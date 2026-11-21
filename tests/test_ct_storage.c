#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_audit.h"
#include "qihse_ct_codec.h"
#include "qihse_ct1_disposition.h"
#include <openssl/sha.h>
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

/* Test-only hand-seeding; production has no marker installation API. */
static void seed_recovery_fence(const char* path, const char* generation,
    uint64_t baseline_seq, const unsigned char baseline_digest[32],
    uint64_t cursor, int variant) {
    unsigned char record[153] = {0};
    assert(strlen(generation) <= 64u);
    memcpy(record, "QCTRF001", 8u);
    memcpy(record + 8u, generation, strlen(generation));
    for (unsigned i = 0; i < 8u; ++i) {
        record[73u + i] = (unsigned char)(baseline_seq >> (8u * i));
        record[113u + i] = (unsigned char)(cursor >> (8u * i));
    }
    memcpy(record + 81u, baseline_digest, 32u);
    unsigned int digest_len = 0u;
    assert(EVP_Digest(record, sizeof(record) - 32u, record + 121u,
                      &digest_len, EVP_sha256(), NULL) == 1 && digest_len == 32u);
    if (variant == 1) record[121u] ^= 1u; /* checksum */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    assert(fd >= 0 && write(fd, record, variant == 2 ? 20u : sizeof(record)) ==
           (ssize_t)(variant == 2 ? 20u : sizeof(record)) &&
           fsync(fd) == 0 && close(fd) == 0);
}

static bool ct_receipt_value(uint64_t seq, char* out, size_t cap, void* context) {
    (void)context;
    int n = snprintf(out, cap, "DONE:%llu", (unsigned long long)seq);
    return n > 0 && (size_t)n < cap;
}

static void ct_wal_fingerprint(int fd, off_t* size, unsigned char digest[32]) {
    struct stat st;
    assert(fstat(fd, &st) == 0 && st.st_size >= 0);
    *size = st.st_size;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    assert(ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    unsigned char bytes[4096];
    for (off_t offset = 0; offset < st.st_size;) {
        size_t count = st.st_size - offset < (off_t)sizeof(bytes)
            ? (size_t)(st.st_size - offset) : sizeof(bytes);
        assert(pread(fd, bytes, count, offset) == (ssize_t)count &&
               EVP_DigestUpdate(ctx, bytes, count) == 1);
        offset += (off_t)count;
    }
    unsigned int digest_len = 0u;
    assert(EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1 && digest_len == 32u);
    EVP_MD_CTX_free(ctx);
}

static void ct_wal_crash_custody_fixture(bool durable, size_t custody_prefix) {
    char dir[] = "./ct_wal_custody_XXXXXX";
    umask(0077);
    assert(mkdtemp(dir) && setenv("QIHSE_DATA_DIR", dir, 1) == 0 &&
           setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
    assert(op);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    if (durable) {
        qihse_user_t* service = qihse_auth_create_user(op, 8302u,
            QIHSE_ROLE_ANALYST, 5u, 2u, "CtStorageService1!", false);
        assert(service && qihse_kv_ct_source_enable(store, op,
            "source:custody", "target:custody", "gen:custody", NULL,
            128u * 1024u * 1024u));
        qihse_kv_store_set_replication_principal_id(store, 8302u);
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], digest[32];
        assert(qihse_kv_ct_owner_token_get(store, op, token));
        qihse_kv_replica_snapshot_t* snapshot = NULL;
        uint64_t baseline_seq = 0u;
        assert(qihse_kv_ct_source_baseline_snapshot_create(store, op,
            &snapshot, &baseline_seq, digest) == 0 && snapshot);
        qihse_kv_replica_snapshot_destroy(snapshot);
        assert(qihse_kv_ct_source_reconcile_peer(store, op, service,
            "target:custody", "gen:custody", digest, 0u));
        qihse_kv_ct_writer_scope_t* scope = NULL;
        assert(qihse_kv_ct_writer_scope_enter(store, op, token, &scope));
        assert(qihse_kv_set_user(store, "commons/custody", "durable-frame",
            0u, 0u, op));
        qihse_kv_ct_source_status_t status = {0};
        assert(qihse_kv_ct_source_status(store, op, &status) &&
            status.durable_lsn == 1u && status.acknowledged_lsn == 0u &&
            status.retained_bytes > 4u);
        qihse_kv_ct_writer_scope_leave(scope);
    } else {
        assert(qihse_kv_set_user(store, "commons/custody", "intact",
            0u, 0u, op));
    }
    qihse_kv_store_destroy(store);
    char wal_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log", dir) > 0);
    int fd = open(wal_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    off_t original_size, damaged_size, after_size;
    unsigned char original_sha[32], damaged_sha[32], after_sha[32];
    ct_wal_fingerprint(fd, &original_size, original_sha);
    assert(original_size > 4);
    if (durable) {
        char magic[4];
        assert(pread(fd, magic, sizeof(magic), 0) == (ssize_t)sizeof(magic) &&
               memcmp(magic, "QKV6", sizeof(magic)) == 0);
    }
    if (custody_prefix) {
        assert(custody_prefix >= 1u && custody_prefix <= 4u);
        pid_t writer = fork();
        assert(writer >= 0);
        if (writer == 0) {
            assert(pwrite(fd, "QCT1", custody_prefix, original_size) ==
                   (ssize_t)custody_prefix && fsync(fd) == 0);
            _exit(86); /* durable partial write, no process cleanup */
        }
        int status = 0;
        assert(waitpid(writer, &status, 0) == writer && WIFEXITED(status) &&
               WEXITSTATUS(status) == 86);
    } else if (durable) {
        assert(ftruncate(fd, original_size - 1) == 0);
    } else {
        assert(pwrite(fd, "QKV3", 4u, original_size) == 4);
    }
    assert(fsync(fd) == 0);
    ct_wal_fingerprint(fd, &damaged_size, damaged_sha);
    assert(damaged_size == original_size + (custody_prefix ?
        (off_t)custody_prefix : (durable ? -1 : 4)));
    assert(close(fd) == 0);
    store = qihse_kv_store_create_user(op);
    if (durable || custody_prefix >= 2u) assert(store == NULL);
    else {
        assert(store);
        char* value = qihse_kv_get_user(store, "commons/custody", op);
        assert(value && strcmp(value, "intact") == 0);
        free(value);
        qihse_kv_store_destroy(store);
    }
    fd = open(wal_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    ct_wal_fingerprint(fd, &after_size, after_sha);
    assert(close(fd) == 0);
    bool preserved = durable || custody_prefix >= 2u;
    assert(after_size == (preserved ? damaged_size : original_size) &&
           memcmp(after_sha, preserved ? damaged_sha : original_sha, 32u) == 0);
    aimem_fixture_cleanup(dir);
}

/* Disposable, fixture-only WAL authoring: no production exceptional writer or
 * QKP command is exposed. The manifest roster is structurally canonical but
 * deliberately not trusted recovery authority. */
static void custody_roster(qihse_ct1_recovery_file_t* files,
    const char* const* names, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const char* s = names[i];
        strcpy(files[i].filename, s);
        files[i].kind = !strcmp(s, "wal.log") ? QIHSE_CT1_FILE_WAL :
            !strcmp(s, "ct-state.bin") ? QIHSE_CT1_FILE_CT_STATE :
            !strcmp(s, "ct-baseline.qfs") ? QIHSE_CT1_FILE_BASELINE :
            !strcmp(s, "restore-highwater.bin") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            !strcmp(s, "slot-ownership.journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            !strcmp(s, "slot-ownership.journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            QIHSE_CT1_FILE_SSTABLE;
        files[i].size = files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK ? 0 : 100 + i;
        if (!files[i].size) assert(SHA256((const unsigned char*)"", 0, files[i].sha256));
        else memset(files[i].sha256, (int)i + 1, 32);
    }
}

static void custody_storage_fixture(qihse_kv_store_t* receiver,
    qihse_user_t* op, qihse_user_t* service,
    qihse_kv_ct_group_t* first, qihse_kv_ct_group_t* second,
    uint64_t baseline_seq, const unsigned char baseline[32],
    const char* baseline_path, int variant) {
    uint64_t cursor = 0;
    assert(first->count == 1 && second->count == 1 &&
        first->records[0].value && first->records[0].change_seq <
        second->records[0].change_seq);
    bool system_original = variant >= 4 && variant <= 11;
    assert(qihse_kv_ct_receiver_apply(receiver, service, first, &cursor) && cursor == 1);
    if (system_original) {
        qihse_kv_ct_group_t extra = *second;
        qihse_kv_ct_record_t record = *second->records;
        extra.records = &record;
        record.key = "commons/custody-prelude";
        extra.stream_position = 2u;
        assert(qihse_kv_ct_receiver_apply(receiver, service, &extra, &cursor) &&
            cursor == 2u);
        second->stream_position = 3u;
        second->records[0].change_seq++;
        second->first_seq = second->last_seq = second->records[0].change_seq;
    }
    qihse_kv_ct_record_t* tomb = second->records;
    free(tomb->key); tomb->key = strdup(first->records[0].key);
    free(tomb->value); tomb->value = NULL;
    assert(tomb->key);
    tomb->classification = first->records[0].classification;
    tomb->sci_compartment = first->records[0].sci_compartment;
    tomb->resource_tenant_id = first->records[0].resource_tenant_id;
    tomb->expire_time_ms = 0;
    tomb->tombstone = true;
    assert(qihse_kv_ct_receiver_apply(receiver, service, second, &cursor) &&
        cursor == (system_original ? 3u : 2u));
    assert(qihse_kv_get_user(receiver, tomb->key, op) == NULL);
    if (system_original) {
        for (uint64_t pos = 4u; pos <= 7u; ++pos) {
            qihse_kv_ct_group_t extra = *second;
            qihse_kv_ct_record_t record = *tomb;
            extra.records = &record;
            extra.stream_position = pos;
            record.key = "commons/custody-padding";
            record.value = "padding";
            record.tombstone = false;
            record.change_seq = tomb->change_seq + pos - 3u;
            extra.first_seq = extra.last_seq = record.change_seq;
            assert(qihse_kv_ct_receiver_apply(receiver, service, &extra, &cursor) &&
                cursor == pos);
        }
    }
    if (variant && !system_original) {
        qihse_kv_ct_group_t later = *second;
        qihse_kv_ct_record_t record = *tomb;
        later.stream_position = 3;
        later.records = &record;
        record.key = strdup(variant == 2 || variant == 12 ? tomb->key :
            "commons/unrelated-custody");
        record.value = variant == 12 ? NULL : strdup("later-set");
        record.tombstone = variant == 12;
        record.change_seq = tomb->change_seq + 1u;
        later.first_seq = later.last_seq = record.change_seq;
        assert(record.key && (record.value || variant == 12) &&
            qihse_kv_ct_receiver_apply(receiver, service, &later, &cursor) && cursor == 3);
        free(record.key); free(record.value);
    }

    qihse_kv_ct_group_t original = *first;
    original.stream_position = system_original ? 8u : variant ? 4u : 3u;
    qihse_kv_ct_record_t row = first->records[0];
    original.records = &row;
    char* padded = malloc(2000);
    assert(padded);
    memset(padded, 'x', 1999); padded[1999] = 0;
    row.value = padded;
    size_t size = 0;
    padded[1] = 0;
    qihse_kv_ct_tenant_policy_t source_policy = system_original ?
        QIHSE_KV_CT_TENANT_SYSTEM_ALL : QIHSE_KV_CT_TENANT_EXACT;
    assert(qihse_ct_codec_encoded_size(op, source_policy, 0,
        QIHSE_CT_CODEC_MODE_SOURCE, &original, 65536, &size));
    size_t payload = QIHSE_CT1_RECOVERY_FRAME_BYTES - size + 1;
    assert(payload > 1 && payload < 1999);
    padded[1] = 'x'; padded[payload] = 0;
    FILE* tmp = tmpfile();
    size_t written = 0;
    assert(tmp && qihse_ct_codec_write(tmp, op, source_policy,
        0, QIHSE_CT_CODEC_MODE_SOURCE, &original, 65536, &written) &&
        written == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        fseek(tmp, 0, SEEK_SET) == 0);
    unsigned char original_frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    assert(fread(original_frame, 1, sizeof(original_frame), tmp) == sizeof(original_frame));
    fclose(tmp); free(padded);

    qihse_ct1_recovery_manifest_t m = {0};
    strcpy(m.issuer_qkp_id, "operator");
    strcpy(m.source_qkp_id, "source"); strcpy(m.target_qkp_id, "target");
    strcpy(m.source_store_id, first->source_id);
    strcpy(m.target_store_id, "target:1");
    strcpy(m.generation, first->generation);
    strcpy(m.replication_principal_id, "replication-service");
    assert(strncmp(row.key, "commons/", 8) == 0);
    strcpy(m.row_key, row.key + 8);
    strcpy(m.source_peer_qkp_id, "source-next");
    strcpy(m.target_peer_qkp_id, "target-next");
    memset(m.issuer_operator_pin, 1, 32);
    memset(m.source_peer_pin, 2, 32);
    memset(m.target_peer_pin, 3, 32);
    assert(SHA256(original_frame, sizeof(original_frame), m.frame_sha256));
    memcpy(m.baseline_sha256, baseline, 32); memset(m.nonce, 6, 32);
    static const char* const src[] = {"ct-baseline.qfs", "ct-state.bin",
        "restore-highwater.bin", "slot-ownership.journal",
        "slot-ownership.journal.lock", "sstable_11321.db",
        "sstable_11322.db", "wal.log"};
    static const char* const dst[] = {"ct-state.bin", "restore-highwater.bin",
        "slot-ownership.journal", "slot-ownership.journal.lock",
        "sstable_6.db", "sstable_7.db", "wal.log"};
    custody_roster(m.source_files, src, 8);
    custody_roster(m.target_files, dst, 7);
    m.epoch = 9; m.issued_ms = 1000; m.expires_ms = 901000;
    m.frame_offset = 400; m.frame_length = sizeof(original_frame);
    m.frame_position = system_original ? 8u : variant ? 4u : 3u;
    m.target_cursor = system_original ? 7u : variant ? 3u : 2u;
    m.target_high_water = system_original ? tomb->change_seq + 4u :
        tomb->change_seq + (variant ? 1u : 0u);
    m.source_high_water = row.change_seq;
    m.row_change_seq = row.change_seq;
    m.tombstone_position = system_original ? 3u : variant == 3 ? 3u : 2u;
    m.tombstone_row_seq = tomb->change_seq;
    if (system_original) {
        assert(first->records[0].change_seq == 3u && tomb->change_seq == 5u &&
            original_frame[9] == QIHSE_KV_CT_TENANT_SYSTEM_ALL);
    }
    m.baseline_row_seq = baseline_seq;
    m.classification = row.classification; m.sci = row.sci_compartment;
    m.principal_classification = row.classification; m.principal_sci = row.sci_compartment;
    m.operation = QIHSE_CT1_RECOVERY_VERIFY;
    /* Independently rehash the outer evidence after each deliberately invalid
     * inner frame: failure must come from policy/codec, not an outer digest. */
    if (variant == 5) original_frame[9] = 3u; /* invalid tenant policy */
    if (variant == 6) m.row_tenant_id = 1u; /* SYSTEM_ALL is never tenant-scoped */
    if (variant == 8) original_frame[8] = 0u; /* malformed SOURCE mode */
    if (variant == 9) original_frame[sizeof(original_frame) - 1u] ^= 1u;
    if (variant == 10) m.sci = 1u; /* row/manifest SCI disagreement */
    if (variant == 11) original_frame[31] = 1u; /* wrong envelope tenant */
    if (system_original && variant != 4 && variant != 7)
        assert(SHA256(original_frame, sizeof(original_frame), m.frame_sha256));
    enum { INNER = QIHSE_CT1_DISPOSITION_SIZE,
        FRAME = QIHSE_CT1_SUPPRESSED_WAL_SIZE };
    unsigned char* frame = calloc(1, FRAME);
    assert(frame);
    memcpy(frame, "QCT1SO02", 8);
    frame[8] = (unsigned char)(FRAME >> 24); frame[9] = (unsigned char)(FRAME >> 16);
    frame[10] = (unsigned char)(FRAME >> 8); frame[11] = (unsigned char)FRAME;
    frame[12] = (unsigned char)(INNER >> 24); frame[13] = (unsigned char)(INNER >> 16);
    frame[14] = (unsigned char)(INNER >> 8); frame[15] = (unsigned char)INNER;
    unsigned char* d = frame + 16;
    memcpy(d, "QCT1SO01", 8);
    d[8] = (unsigned char)(INNER >> 24); d[9] = (unsigned char)(INNER >> 16);
    d[10] = (unsigned char)(INNER >> 8); d[11] = (unsigned char)INNER;
    d[14] = (unsigned char)(sizeof(original_frame) >> 8);
    d[15] = (unsigned char)sizeof(original_frame);
    assert(qihse_ct1_recovery_encode(&m, false, false, d + 16));
    memcpy(d + 16 + QIHSE_CT1_RECOVERY_WIRE_SIZE, original_frame,
        sizeof(original_frame));
    assert(SHA256(d, INNER - 32, d + INNER - 32));
    assert(SHA256(frame, FRAME - 32, frame + FRAME - 32));
    char wal_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
        getenv("QIHSE_DATA_DIR")) > 0);
    if (variant == 0 || variant == 4 || variant == 12) {
        /* PREPARED is durable before any exceptional WAL append. It denies
         * reads, ordinary apply, expiry, and snapshot/compaction at the cut. */
        assert(qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
            m.generation, m.baseline_row_seq, m.baseline_sha256, m.target_cursor));
        assert(qihse_kv_get_user(receiver, tomb->key, op) == NULL &&
            !qihse_kv_ct_receiver_apply(receiver, service, &original, &cursor));
        qihse_kv_sweep_expired(receiver);
    }
    qihse_kv_store_destroy(receiver);
    int fd = open(wal_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    off_t before, after;
    unsigned char old_sha[32], now_sha[32];
    ct_wal_fingerprint(fd, &before, old_sha);
    if (system_original && variant != 4 && variant != 7) {
        assert(pwrite(fd, frame, FRAME, before) == FRAME && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(qihse_kv_store_create_user(op) == NULL);
        off_t preserved; unsigned char digest[32];
        ct_wal_fingerprint(fd, &preserved, digest);
        assert(preserved == after && memcmp(now_sha, digest, 32u) == 0);
        assert(ftruncate(fd, before) == 0 && fsync(fd) == 0);
        close(fd); free(frame);
        return;
    }
    if (system_original && variant == 7) {
        qihse_user_t* low = qihse_auth_create_user(op, 8304u, QIHSE_ROLE_ANALYST,
            0u, 0u, "CtStorageCustodyLow1!", false);
        assert(low && qihse_user_get_tenant_id(low) == QIHSE_TENANT_SYSTEM);
        assert(!qihse_ct1_disposition_encode(low, &m, original_frame,
            sizeof(original_frame), frame + 16));
        assert(pwrite(fd, frame, FRAME, before) == FRAME && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(qihse_kv_store_create_user(low) == NULL);
        /* The denied low-clearance open must leave the custody WAL intact. */
        off_t preserved; unsigned char digest[32];
        ct_wal_fingerprint(fd, &preserved, digest);
        assert(preserved == after && memcmp(now_sha, digest, 32u) == 0);
        assert(ftruncate(fd, before) == 0 && fsync(fd) == 0);
    }
    if (variant == 3 || variant == 2 || variant == 12) {
        assert(pwrite(fd, frame, FRAME, before) == FRAME && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(qihse_kv_store_create_user(op) == NULL);
        off_t preserved; unsigned char digest[32];
        ct_wal_fingerprint(fd, &preserved, digest);
        assert(preserved == after && memcmp(now_sha, digest, 32u) == 0);
        assert(ftruncate(fd, before) == 0 && fsync(fd) == 0);
        close(fd); free(frame);
        return;
    }
    if (variant == 1) {
        unsigned char saved;
        assert(pread(fd, &saved, 1u, 64) == 1);
        unsigned char changed = saved ^ 1u;
        assert(pwrite(fd, &changed, 1u, 64) == 1 && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(qihse_kv_store_create_user(op) == NULL);
        off_t preserved; unsigned char digest[32];
        ct_wal_fingerprint(fd, &preserved, digest);
        assert(preserved == after && !memcmp(now_sha, digest, 32));
        assert(pwrite(fd, &saved, 1u, 64) == 1 && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(after == before && !memcmp(old_sha, now_sha, 32));
        unsigned char* prefix = malloc((size_t)before);
        assert(prefix && pread(fd, prefix, (size_t)before, 0) == before);
        assert(ftruncate(fd, 0) == 0 &&
            pwrite(fd, frame, FRAME, 0) == FRAME && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(qihse_kv_store_create_user(op) == NULL);
        ct_wal_fingerprint(fd, &preserved, digest);
        assert(preserved == after && !memcmp(now_sha, digest, 32));
        assert(ftruncate(fd, 0) == 0 &&
            pwrite(fd, prefix, (size_t)before, 0) == before && fsync(fd) == 0);
        free(prefix);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(after == before && !memcmp(old_sha, now_sha, 32));
    }
    for (size_t cut = 1; cut < FRAME; cut = cut == 4 ? FRAME / 2 :
        cut == FRAME / 2 ? FRAME - 1 : cut + 1) {
        assert(pwrite(fd, frame, cut, before) == (ssize_t)cut && fsync(fd) == 0);
        ct_wal_fingerprint(fd, &after, now_sha);
        assert(!qihse_kv_store_create_user(op));
        off_t preserved; unsigned char digest[32];
        ct_wal_fingerprint(fd, &preserved, digest);
        assert(preserved == after && !memcmp(now_sha, digest, 32));
        assert(ftruncate(fd, before) == 0 && fsync(fd) == 0);
    }
    frame[FRAME - 1] ^= 1u;
    assert(pwrite(fd, frame, FRAME, before) == FRAME && fsync(fd) == 0);
    ct_wal_fingerprint(fd, &after, now_sha);
    assert(!qihse_kv_store_create_user(op));
    off_t corrupt_size; unsigned char corrupt_sha[32];
    ct_wal_fingerprint(fd, &corrupt_size, corrupt_sha);
    assert(corrupt_size == after && !memcmp(corrupt_sha, now_sha, 32));
    assert(ftruncate(fd, before) == 0 && fsync(fd) == 0);
    frame[FRAME - 1] ^= 1u;
    assert(pwrite(fd, frame, FRAME, before) == FRAME && fsync(fd) == 0);
    ct_wal_fingerprint(fd, &after, now_sha);
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-state-before-publish", 1) == 0);
    assert(qihse_kv_store_create_user(op) == NULL);
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    off_t still; unsigned char still_sha[32];
    ct_wal_fingerprint(fd, &still, still_sha);
    assert(still == after && !memcmp(still_sha, now_sha, 32));
    receiver = qihse_kv_store_create_user(op);
    assert(receiver);
    qihse_kv_ct_receiver_status_t state = {0};
    assert(qihse_kv_ct_receiver_status(receiver, op, &state) &&
        state.durable_cursor == m.frame_position && !qihse_kv_sync_store(receiver) &&
        !qihse_kv_ct_receiver_apply(receiver, service, first, &cursor));
    assert(qihse_kv_get_user(receiver, tomb->key, op) == NULL);
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(receiver, op, "*", &snapshot) != 0 &&
        snapshot == NULL);
    assert(qihse_kv_load_user(receiver, baseline_path, op) != 0);
    qihse_kv_sweep_expired(receiver);
    qihse_kv_store_destroy(receiver);
    if (variant == 0 || variant == 4) {
        /* A lost reply permits exact replay, not a second custody unit. */
        assert(pwrite(fd, frame, FRAME, after) == FRAME && fsync(fd) == 0);
        off_t doubled; unsigned char doubled_sha[32], preserved_sha[32];
        ct_wal_fingerprint(fd, &doubled, doubled_sha);
        assert(qihse_kv_store_create_user(op) == NULL);
        off_t preserved;
        ct_wal_fingerprint(fd, &preserved, preserved_sha);
        assert(preserved == doubled && !memcmp(preserved_sha, doubled_sha, 32u));
        assert(ftruncate(fd, after) == 0 && fsync(fd) == 0);
    }
    receiver = qihse_kv_store_create_user(op);
    assert(receiver && qihse_kv_ct_receiver_status(receiver, op, &state) &&
        state.durable_cursor == m.frame_position && !qihse_kv_sync_store(receiver));
    /* The reopened handle must not publish a row-only image or replace the
     * WAL: neither carries the original frame and tombstone-position proof. */
    char export_path[512];
    assert(snprintf(export_path, sizeof(export_path), "%s/custody-export.qfs",
        getenv("QIHSE_DATA_DIR")) > 0);
    assert(qihse_kv_save_user(receiver, export_path, op) != 0 &&
        access(export_path, F_OK) != 0);
    assert(qihse_kv_ct_owner_data_snapshot_create(receiver, op, &snapshot) != 0 &&
        snapshot == NULL);
    assert(qihse_kv_replica_snapshot_create(receiver, op, "*", &snapshot) != 0 &&
        snapshot == NULL);
    assert(qihse_kv_load_user(receiver, baseline_path, op) != 0);
    assert(!qihse_kv_set_user(receiver, tomb->key, "stale-set", 0u, 0u, op) &&
        qihse_kv_get_user(receiver, tomb->key, op) == NULL);
    qihse_user_t* low = qihse_auth_create_user(op, 8317u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "CtStorageCustodyLow2!", false);
    assert(low && qihse_kv_get_user(receiver, tomb->key, low) == NULL &&
        qihse_kv_store_create_user(low) == NULL);
    qihse_kv_sweep_expired(receiver);
    off_t held; unsigned char held_sha[32];
    ct_wal_fingerprint(fd, &held, held_sha);
    assert(held == after && memcmp(held_sha, now_sha, 32u) == 0);
    qihse_kv_store_destroy(receiver);
    off_t final; unsigned char final_sha[32];
    ct_wal_fingerprint(fd, &final, final_sha);
    assert(final == after && !memcmp(final_sha, now_sha, 32));
    /* A later rotation or replacement cannot recover from CT state alone. */
    assert(ftruncate(fd, before) == 0 && fsync(fd) == 0);
    assert(qihse_kv_store_create_user(op) == NULL);
    close(fd); free(frame);
}

static char* ct_large_payload(void) {
    char* value = malloc(32769u);
    assert(value);
    for (size_t i = 0u; i < 32768u; i++) value[i] = (char)('a' + i % 23u);
    value[32768] = '\0';
    return value;
}

static void ct_retained_frame_fixture(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "CtStorageLow1!", false);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
                                                    5u, 2u, "CtStorageService1!", false);
    assert(low && service);
    qihse_kv_store_t* s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_source_enable(s, op, "source:frame", "target:frame",
                                     "gen:frame", NULL, 128u * 1024u * 1024u));
    qihse_kv_store_set_replication_principal_id(s, 8302u);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], baseline[32];
    assert(qihse_kv_ct_owner_token_get(s, op, token));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t baseline_seq = 0u;
    assert(qihse_kv_ct_source_baseline_snapshot_create(s, op, &snapshot,
        &baseline_seq, baseline) == 0 && snapshot);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_source_reconcile_peer(s, op, service, "target:frame",
                                             "gen:frame", baseline, 0u));
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_set_user(s, "commons/frame-high", "retained-secret-unique",
                             6u, 2u, op));
    qihse_kv_ct_source_status_t status = {0};
    assert(qihse_kv_ct_source_status(s, op, &status) &&
           status.durable_lsn == 1u && status.acknowledged_lsn == 0u);
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    assert(qihse_kv_ct_source_read(s, op, "gen:frame", 0u, 1u, 65536u,
                                   &groups, &count, &resume));
    assert(count == 1u && resume == 1u && groups[0].count == 1u &&
           !groups[0].records[0].tombstone &&
           strcmp(groups[0].records[0].value, "retained-secret-unique") == 0);
    qihse_kv_ct_source_retained_frame_request_t req = {
        .version = QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1, .size = sizeof(req),
        .source_id = "source:frame", .successor_id = "target:frame",
        .generation = "gen:frame", .baseline_row_seq = baseline_seq,
        .acknowledged_position = status.acknowledged_lsn,
        .durable_position = status.durable_lsn, .stream_position = 1u,
        .key = groups[0].records[0].key,
        .resource_tenant_id = groups[0].records[0].resource_tenant_id,
        .classification = groups[0].records[0].classification,
        .sci_compartment = groups[0].records[0].sci_compartment,
        .row_change_seq = groups[0].records[0].change_seq};
    memcpy(req.baseline_digest, baseline, sizeof(baseline));
    qihse_kv_ct_source_retained_frame_result_t frame = {0};
#define FRAME_DENIED(principal) do { \
    memset(&frame, 0xa5, sizeof(frame)); \
    assert(!qihse_kv_ct_source_retained_frame_v1(s, principal, &req, &frame)); \
    qihse_kv_ct_source_retained_frame_result_t empty = {0}; \
    assert(memcmp(&frame, &empty, sizeof(frame)) == 0); \
} while (0)
    assert(qihse_kv_ct_source_retained_frame_v1(s, op, &req, &frame));
    char wal_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
                    getenv("QIHSE_DATA_DIR")) > 0);
    int fd = open(wal_path, O_RDWR | O_CLOEXEC);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && st.st_size > 4 &&
           (uint64_t)st.st_size == status.retained_bytes &&
           frame.frame_length == (size_t)st.st_size &&
           memcmp(frame.frame, "QKV6", 4u) == 0);
    unsigned char* original = malloc(frame.frame_length);
    assert(original && pread(fd, original, frame.frame_length, 0) ==
           (ssize_t)frame.frame_length);
    unsigned char digest[32];
    unsigned int digest_length = 0u;
    assert(memcmp(frame.frame, original, frame.frame_length) == 0 &&
           EVP_Digest(original, frame.frame_length, digest, &digest_length,
                      EVP_sha256(), NULL) == 1 && digest_length == 32u &&
           memcmp(frame.frame_sha256, digest, 32u) == 0 &&
           frame.version == QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1 &&
           frame.size == sizeof(frame) &&
           strcmp(frame.key, req.key) == 0 &&
           frame.resource_tenant_id == req.resource_tenant_id &&
           frame.classification == req.classification &&
           frame.sci_compartment == req.sci_compartment &&
           frame.stream_position == req.stream_position &&
           frame.row_change_seq == req.row_change_seq &&
           frame.expire_time_ms == groups[0].records[0].expire_time_ms);
    size_t original_length = frame.frame_length;
    free(frame.frame);
    free(frame.key);
    qihse_kv_store_set_replication_principal_id(s, 8301u);
    FRAME_DENIED(low); /* Authorized replicator, insufficient row clearance. */
    qihse_kv_store_set_replication_principal_id(s, 8302u);
    FRAME_DENIED(service);
    FRAME_DENIED(NULL);
    req.source_id = "source:wrong"; FRAME_DENIED(op); req.source_id = "source:frame";
    req.successor_id = "target:wrong"; FRAME_DENIED(op); req.successor_id = "target:frame";
    req.generation = "gen:wrong"; FRAME_DENIED(op); req.generation = "gen:frame";
    req.baseline_row_seq++; FRAME_DENIED(op); req.baseline_row_seq--;
    req.baseline_digest[0] ^= 1u; FRAME_DENIED(op); req.baseline_digest[0] ^= 1u;
    req.acknowledged_position++; FRAME_DENIED(op); req.acknowledged_position--;
    req.durable_position++; FRAME_DENIED(op); req.durable_position--;
    req.stream_position = 0u; FRAME_DENIED(op); req.stream_position = 1u;
    req.stream_position = 2u; FRAME_DENIED(op); req.stream_position = 1u;
    req.key = "commons/wrong"; FRAME_DENIED(op); req.key = groups[0].records[0].key;
    req.resource_tenant_id++; FRAME_DENIED(op); req.resource_tenant_id--;
    req.classification--; FRAME_DENIED(op); req.classification++;
    req.sci_compartment = 0u; FRAME_DENIED(op); req.sci_compartment = 2u;
    req.row_change_seq++; FRAME_DENIED(op); req.row_change_seq--;
    req.version++; FRAME_DENIED(op); req.version--;
    req.size--; FRAME_DENIED(op); req.size++;
    const char* saved_key = groups[0].records[0].key;
    groups[0].records[0].key = "commons/frame-old!";
    assert(strlen(saved_key) == strlen(groups[0].records[0].key));
    FILE* stale_file = tmpfile();
    size_t stale_length = 0u;
    assert(stale_file && qihse_ct_codec_write(stale_file, op,
           QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 1u, &groups[0], 65536u,
           &stale_length) && stale_length == original_length &&
           fflush(stale_file) == 0 && fseek(stale_file, 0, SEEK_SET) == 0);
    unsigned char* stale_frame = malloc(stale_length);
    assert(stale_frame && fread(stale_frame, 1u, stale_length, stale_file) ==
           stale_length && fclose(stale_file) == 0);
    groups[0].records[0].key = (char*)saved_key;
    assert(pwrite(fd, stale_frame, stale_length, 0) == (ssize_t)stale_length &&
           fsync(fd) == 0);
    FRAME_DENIED(op); /* Valid, same-length frame from a stale row. */
    assert(pwrite(fd, original, original_length, 0) == (ssize_t)original_length &&
           fsync(fd) == 0);
    free(stale_frame);
    assert(pwrite(fd, "X", 1u, 0) == 1 && fsync(fd) == 0);
    FRAME_DENIED(op); /* Bad QKV6 magic, even with the expected file length. */
    assert(pwrite(fd, original, 1u, 0) == 1);
    unsigned char altered = original[original_length - 1u] ^ 1u;
    assert(pwrite(fd, &altered, 1u, (off_t)original_length - 1) == 1 &&
           fsync(fd) == 0);
    FRAME_DENIED(op); /* Frame checksum mismatch. */
    assert(pwrite(fd, original + original_length - 1u, 1u,
                  (off_t)original_length - 1) == 1 && fsync(fd) == 0);
    assert(pwrite(fd, "QKV6", 4u, (off_t)original_length) == 4 &&
           fsync(fd) == 0);
    FRAME_DENIED(op); /* Trailing WAL bytes cannot be ignored. */
    assert(ftruncate(fd, (off_t)original_length - 1) == 0 && fsync(fd) == 0);
    FRAME_DENIED(op); /* Incomplete retained frame. */
    assert(pwrite(fd, original + original_length - 1u, 1u,
                  (off_t)original_length - 1) == 1 && fsync(fd) == 0);
    assert(qihse_kv_ct_source_retained_frame_v1(s, op, &req, &frame));
    free(frame.frame);
    free(frame.key);
    free(original);
    assert(close(fd) == 0);
    qihse_kv_ct_groups_free(groups, count);
    assert(qihse_kv_ct_source_ack(s, op, "target:frame", "gen:frame", 1u));
    FRAME_DENIED(op); /* Stale ACK/durable binding. */
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_del_user(s, "commons/frame-high", op));
    assert(qihse_kv_ct_source_status(s, op, &status) && status.durable_lsn == 2u);
    req.acknowledged_position = 1u; req.durable_position = 2u;
    req.stream_position = 2u; req.row_change_seq++;
    FRAME_DENIED(op); /* The retained DEL is not a single SET. */
    assert(qihse_kv_ct_source_ack(s, op, "target:frame", "gen:frame", 2u));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_set_user(s, "commons/frame-ttl", "ttl-value", 0u, 0u, op));
    assert(qihse_kv_ct_source_ack(s, op, "target:frame", "gen:frame", 3u));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_expire(s, "commons/frame-ttl", 60000u, op));
    assert(qihse_kv_ct_source_status(s, op, &status) && status.durable_lsn == 4u);
    groups = NULL; count = 0u; resume = 0u;
    assert(qihse_kv_ct_source_read(s, op, "gen:frame", 3u, 1u, 65536u,
                                   &groups, &count, &resume) && count == 1u);
    req.acknowledged_position = 3u; req.durable_position = 4u;
    req.stream_position = 4u; req.key = groups[0].records[0].key;
    req.classification = 0u; req.sci_compartment = 0u;
    req.row_change_seq = groups[0].records[0].change_seq;
    assert(qihse_kv_ct_source_retained_frame_v1(s, op, &req, &frame) &&
           frame.expire_time_ms == groups[0].records[0].expire_time_ms &&
           frame.expire_time_ms > 0u);
    free(frame.frame);
    free(frame.key);
    qihse_kv_ct_groups_free(groups, count);
    assert(qihse_kv_ct_source_ack(s, op, "target:frame", "gen:frame", 4u));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_expire(s, "commons/frame-ttl", 0u, op));
    assert(qihse_kv_ct_source_status(s, op, &status) && status.durable_lsn == 5u);
    req.acknowledged_position = 4u; req.durable_position = 5u;
    req.stream_position = 5u; req.row_change_seq++;
    FRAME_DENIED(op); /* A single SET with an expired TTL is not eligible. */
    qihse_kv_ct_writer_scope_leave(scope);
    qihse_kv_store_destroy(s);
#undef FRAME_DENIED
}

static bool ct_stale_receipt_builder(uint64_t seq, char* out, size_t capacity,
                                     void* context) {
    unsigned* calls = context;
    (*calls)++;
    int n = snprintf(out, capacity, "D:%llu", (unsigned long long)seq);
    return n > 0 && (size_t)n < capacity;
}

#ifdef QIHSE_CT_STORAGE_FLOOR_TEST
/* Deliberately local to the fixture binary, absent from the production API. */
extern bool qihse_kv_ct_test_reserve_source_row_floor(qihse_kv_store_t* store,
    qihse_user_t* operator_user, const char* source_id, const char* successor_id,
    const char* generation, uint64_t baseline_seq,
    const unsigned char baseline_digest[32], uint64_t acknowledged_position,
    uint64_t durable_position, uint64_t authenticated_target_highwater);

static void ct_floor_fixture(const char* phase, const char* variant) {
    const uint64_t target_highwater = 5729457u;
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
    assert(op);
    qihse_kv_store_t* source = qihse_kv_store_create_user(op);
    if (strcmp(phase, "denied") == 0) {
        assert(!source);
        _exit(0);
    }
    assert(source);
    bool nonzero_hold = strcmp(variant, "hold-nonzero") == 0;
    if (strcmp(phase, "reopen") == 0 &&
        (strcmp(variant, "hold-only") == 0 || nonzero_hold)) {
        qihse_kv_ct_source_status_t status = {0};
        assert(qihse_kv_ct_source_status(source, op, &status) &&
            !status.admitted && status.durable_lsn == (nonzero_hold ? 3u : 1u) &&
            status.acknowledged_lsn == (nonzero_hold ? 2u : 0u) &&
            status.retained_bytes > 0u);
        qihse_kv_store_set_replication_principal_id(source, 8302u);
        qihse_user_t* service = qihse_auth_create_user(op, 8302u,
            QIHSE_ROLE_ANALYST, 5u, 2u, "CtStorageService1!", false);
        assert(service);
        assert(!qihse_kv_ct_source_ack(source, service,
            "target:floor", "gen:floor", status.durable_lsn));
        assert(!qihse_kv_ct_source_reconcile_peer(source, op, service,
            "target:floor", "gen:floor", status.baseline_digest, status.durable_lsn));
        assert(!qihse_kv_ct_source_reconcile(source, op,
            "target:floor", "gen:floor", status.baseline_digest, status.durable_lsn));
        qihse_kv_ct_group_t* groups = NULL;
        size_t count = 0u;
        uint64_t cursor = 0u;
        assert(qihse_kv_ct_source_read(source, op, "gen:floor",
            nonzero_hold ? 2u : 0u, 1u, 65536u, &groups, &count, &cursor) &&
            count == 1u && cursor == (nonzero_hold ? 3u : 1u) &&
            strcmp(groups[0].records[0].key, "commons/floor-pending") == 0 &&
            strcmp(groups[0].records[0].value, "original-frame") == 0);
        qihse_kv_ct_groups_free(groups, count);
        char wal_path[512], proof_path[512];
        assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
            getenv("QIHSE_DATA_DIR")) > 0 &&
            snprintf(proof_path, sizeof(proof_path), "%s/ct-hold-original.sha",
            getenv("QIHSE_DATA_DIR")) > 0);
        int fd = open(wal_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        off_t size = 0;
        unsigned char digest[32], original[32];
        assert(fd >= 0);
        ct_wal_fingerprint(fd, &size, digest);
        assert(close(fd) == 0);
        fd = open(proof_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && read(fd, original, sizeof(original)) ==
            (ssize_t)sizeof(original) && close(fd) == 0 &&
            memcmp(digest, original, sizeof(original)) == 0 &&
            size == (off_t)status.retained_bytes &&
            qihse_kv_change_seq(source) < target_highwater);
        qihse_kv_store_destroy(source);
        return;
    }
    if (strcmp(phase, "setup") == 0) {
        qihse_user_t* service = qihse_auth_create_user(op, 8302u,
            QIHSE_ROLE_ANALYST, 5u, 2u, "CtStorageService1!", false);
        assert(service);
        assert(qihse_kv_ct_source_enable(source, op, "source:floor",
            "target:floor", "gen:floor", NULL, 128u * 1024u * 1024u));
        qihse_kv_store_set_replication_principal_id(source, 8302u);
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], digest[32];
        assert(qihse_kv_ct_owner_token_get(source, op, token));
        qihse_kv_replica_snapshot_t* snapshot = NULL;
        uint64_t baseline_seq = 0u;
        assert(qihse_kv_ct_source_baseline_snapshot_create(source, op,
            &snapshot, &baseline_seq, digest) == 0 && snapshot);
        qihse_kv_replica_snapshot_destroy(snapshot);
        assert(qihse_kv_ct_source_reconcile_peer(source, op, service,
            "target:floor", "gen:floor", digest, 0u));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 0u, target_highwater)); /* admitted source */
        qihse_kv_ct_writer_scope_t* scope = NULL;
        assert(qihse_kv_ct_writer_scope_enter(source, op, token, &scope));
        assert(qihse_kv_set_user(source, "commons/floor-pending", "original-frame",
            4u, 2u, op));
        if (nonzero_hold) {
            assert(qihse_kv_ct_source_ack(source, service,
                "target:floor", "gen:floor", 1u));
            assert(qihse_kv_set_user(source, "commons/floor-previous", "prior",
                4u, 2u, op));
            assert(qihse_kv_set_user(source, "commons/floor-pending", "original-frame",
                4u, 2u, op));
            assert(qihse_kv_ct_source_ack(source, service,
                "target:floor", "gen:floor", 2u));
        }
        if (strcmp(variant, "hold-only") == 0 || nonzero_hold) {
            char wal_path[512], proof_path[512];
            assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
                getenv("QIHSE_DATA_DIR")) > 0 &&
                snprintf(proof_path, sizeof(proof_path), "%s/ct-hold-original.sha",
                getenv("QIHSE_DATA_DIR")) > 0);
            int fd = open(wal_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            off_t size = 0;
            unsigned char original[32];
            assert(fd >= 0);
            ct_wal_fingerprint(fd, &size, original);
            assert(close(fd) == 0 && size > 0);
            fd = open(proof_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            assert(fd >= 0 && write(fd, original, sizeof(original)) ==
                (ssize_t)sizeof(original) && fsync(fd) == 0 && close(fd) == 0);
            qihse_kv_ct_group_t* quoted_groups = NULL;
            size_t quoted_count = 0u;
            uint64_t quoted_cursor = 0u;
            assert(qihse_kv_ct_source_read(source, op, "gen:floor",
                nonzero_hold ? 2u : 0u, 1u, 65536u,
                &quoted_groups, &quoted_count, &quoted_cursor) &&
                quoted_count == 1u && quoted_cursor == (nonzero_hold ? 3u : 1u) &&
                quoted_groups[0].count == 1u);
            qihse_kv_ct_record_t* quoted_row = &quoted_groups[0].records[0];
            qihse_kv_ct_source_retained_frame_request_t request = {
                .version = QIHSE_KV_CT_SOURCE_RETAINED_FRAME_V1,
                .size = sizeof(request), .source_id = "source:floor",
                .successor_id = "target:floor", .generation = "gen:floor",
                .baseline_row_seq = baseline_seq,
                .acknowledged_position = nonzero_hold ? 2u : 0u,
                .durable_position = nonzero_hold ? 3u : 1u,
                .stream_position = nonzero_hold ? 3u : 1u,
                .key = quoted_row->key,
                .resource_tenant_id = quoted_row->resource_tenant_id,
                .classification = quoted_row->classification,
                .sci_compartment = quoted_row->sci_compartment,
                .row_change_seq = quoted_row->change_seq};
            memcpy(request.baseline_digest, digest, sizeof(digest));
            uint64_t highwater = qihse_kv_change_seq(source);
            qihse_kv_ct_source_quote_snapshot_t quote = {0};
            assert(qihse_kv_ct_source_quote_snapshot_v1(source, op, service,
                &request, highwater, &quote) &&
                quote.row_seq_high_water == highwater &&
                quote.frame_offset + quote.retained.frame_length == (size_t)size &&
                (nonzero_hold ? quote.frame_offset > 0u : quote.frame_offset == 0u));
            size_t frame_length = quote.retained.frame_length;
            qihse_kv_store_t* concurrent = NULL;
            unsigned char frame_digest[32];
            memcpy(frame_digest, quote.retained.frame_sha256, 32u);
            if (nonzero_hold) {
                request.stream_position--;
                assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                    op, service, &request, highwater, frame_length, frame_digest));
                request.stream_position++;
                request.acknowledged_position--;
                assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                    op, service, &request, highwater, frame_length, frame_digest));
                request.acknowledged_position++;
                int wal = open(wal_path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
                unsigned char last = quote.retained.frame[frame_length - 1u];
                off_t last_offset = (off_t)(quote.frame_offset + frame_length - 1u);
                unsigned char changed = last ^ 1u;
                assert(wal >= 0 && pwrite(wal, &changed, 1u, last_offset) == 1 &&
                    fsync(wal) == 0);
                assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                    op, service, &request, highwater, frame_length, frame_digest));
                assert(pwrite(wal, &last, 1u, last_offset) == 1 &&
                    fsync(wal) == 0 &&
                    ftruncate(wal, (off_t)size - 1) == 0 && fsync(wal) == 0);
                assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                    op, service, &request, highwater, frame_length, frame_digest));
                assert(pwrite(wal, &last, 1u, last_offset) == 1 &&
                    fsync(wal) == 0 && close(wal) == 0);
                char moved_dir[512];
                const char* data_dir = getenv("QIHSE_DATA_DIR");
                assert(data_dir && snprintf(moved_dir, sizeof(moved_dir),
                    "%s-detached", data_dir) > 0);
                assert(rename(data_dir, moved_dir) == 0 &&
                    mkdir(data_dir, 0700) == 0);
                assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                    op, service, &request, highwater, frame_length, frame_digest));
                assert(rmdir(data_dir) == 0 && rename(moved_dir, data_dir) == 0);
                concurrent = qihse_kv_store_create_user(op);
                assert(concurrent);
                qihse_kv_store_set_replication_principal_id(concurrent, 8302u);
            }
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, NULL, &request, highwater, frame_length, frame_digest));
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                service, service, &request, highwater, frame_length, frame_digest));
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, service, &request, highwater + 1u, frame_length, frame_digest));
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, service, &request, highwater, frame_length + 1u, frame_digest));
            request.baseline_digest[0] ^= 1u;
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, service, &request, highwater, frame_length, frame_digest));
            request.baseline_digest[0] ^= 1u;
            request.successor_id = "target:wrong";
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, service, &request, highwater, frame_length, frame_digest));
            request.successor_id = "target:floor";
            frame_digest[0] ^= 1u;
            assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, service, &request, highwater, frame_length, frame_digest));
            frame_digest[0] ^= 1u;
            /* A caller-known digest is only a source pin, never root release
             * authority. This hold must outrank an exact service ACK. */
            assert(qihse_kv_ct_source_custody_hold_install_pinned_v1(source,
                op, service, &request, highwater, frame_length, frame_digest));
            free(quote.retained.frame);
            free(quote.retained.key);
            qihse_kv_ct_groups_free(quoted_groups, quoted_count);
            assert(!qihse_kv_ct_source_ack(source, service,
                "target:floor", "gen:floor", request.durable_position));
            assert(!qihse_kv_ct_source_reconcile_peer(source, op, service,
                "target:floor", "gen:floor", digest, request.durable_position));
            if (concurrent) {
                assert(!qihse_kv_ct_source_ack(concurrent, service,
                    "target:floor", "gen:floor", request.durable_position));
                assert(!qihse_kv_ct_source_custody_hold_install_pinned_v1(concurrent,
                    op, service, &request, highwater, frame_length, frame_digest));
                qihse_kv_store_destroy(concurrent);
            }
            _exit(86);
        }
        assert(!qihse_kv_ct_writer_scope_finish(scope, 0u, NULL));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater)); /* de-admitted, not reopened */
        qihse_kv_store_destroy(source);
        source = qihse_kv_store_create_user(op);
        assert(source);
        qihse_kv_ct_source_status_t status = {0};
        assert(qihse_kv_ct_source_status(source, op, &status) &&
            !status.admitted && status.durable_lsn == 1u &&
            status.acknowledged_lsn == 0u && status.retained_bytes > 0u);
        uint64_t before_denials = qihse_kv_change_seq(source);
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, NULL,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, service,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq + 1u,
            digest, 0u, 1u, target_highwater));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, 0u));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater - 1u));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater + 1u));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, UINT64_MAX - 1u));
        assert(qihse_kv_change_seq(source) == before_denials);
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "wrong", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:wrong", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:wrong", baseline_seq,
            digest, 0u, 1u, target_highwater));
        digest[0] ^= 1u;
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater));
        digest[0] ^= 1u;
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 1u, 1u, target_highwater));
        assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, UINT64_MAX));
        char wal_path[512];
        assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
            getenv("QIHSE_DATA_DIR")) > 0);
        int fd = open(wal_path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0);
        off_t original_size, after_size;
        unsigned char original_sha[32], after_sha[32];
        ct_wal_fingerprint(fd, &original_size, original_sha);
        assert(original_size > 0 && status.retained_bytes == (uint64_t)original_size);
        char original_path[512];
        assert(snprintf(original_path, sizeof(original_path), "%s/ct-floor-prefix.bin",
            getenv("QIHSE_DATA_DIR")) > 0);
        int prefix_fd = open(original_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(prefix_fd >= 0 && write(prefix_fd, &original_size, sizeof(original_size)) ==
            (ssize_t)sizeof(original_size) &&
            write(prefix_fd, original_sha, sizeof(original_sha)) ==
            (ssize_t)sizeof(original_sha) && fsync(prefix_fd) == 0 &&
            close(prefix_fd) == 0);
        unsigned char magic[4];
        assert(pread(fd, magic, sizeof(magic), 0) == (ssize_t)sizeof(magic) &&
            memcmp(magic, "QKV6", sizeof(magic)) == 0);
        const char* fault = strcmp(variant, "commit") == 0
            ? "restore-highwater-commit" :
            strcmp(variant, "dir-fsync") == 0
            ? "restore-highwater-dir-fsync" :
            strcmp(variant, "group-fsync") == 0
            ? "ct-after-group-fsync" : NULL;
        if (strcmp(variant, "state-publish") == 0)
            assert(setenv("QIHSE_CT_FLOOR_STATE_FAULT", "1", 1) == 0);
        if (fault) assert(setenv("QIHSE_AIMEM_FAIL_AT", fault, 1) == 0);
        const char* cut = strcmp(variant, "cut-hold") == 0 ? "hold" :
            strcmp(variant, "cut-floor") == 0 ? "floor" :
            strcmp(variant, "cut-group") == 0 ? "group" :
            strcmp(variant, "cut-state") == 0 ? "state" : NULL;
        if (cut) assert(setenv("QIHSE_CT_FLOOR_CRASH_AT", cut, 1) == 0);
        /* An archive-shaped file and caller-known original digest are not
         * root-host release proof; persist the forgery across every crash cut. */
        char forged_path[512];
        assert(snprintf(forged_path, sizeof(forged_path), "%s/ct1-forged.arc",
            getenv("QIHSE_DATA_DIR")) > 0);
        int forged_fd = open(forged_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(forged_fd >= 0 && write(forged_fd, "CT1ARC01", 8u) == 8 &&
            write(forged_fd, original_sha, sizeof(original_sha)) ==
                (ssize_t)sizeof(original_sha) &&
            fsync(forged_fd) == 0 && close(forged_fd) == 0);
        bool reserved = qihse_kv_ct_test_reserve_source_row_floor(source, op,
            "source:floor", "target:floor", "gen:floor", baseline_seq,
            digest, 0u, 1u, target_highwater);
        if (fault) assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        bool failed = fault != NULL || strcmp(variant, "state-publish") == 0;
        assert(reserved == !failed);
        if (failed) {
            /* Clearing the injected fault must not authorize an uncertain retry. */
            assert(!qihse_kv_ct_test_reserve_source_row_floor(source, op,
                "source:floor", "target:floor", "gen:floor", baseline_seq,
                digest, 0u, 1u, target_highwater));
            assert(!qihse_kv_ct_source_ack(source, service,
                "target:floor", "gen:floor", 1u));
            assert(!qihse_kv_ct_source_reconcile_peer(source, op, service,
                "target:floor", "gen:floor", digest, 1u));
        }
        ct_wal_fingerprint(fd, &after_size, after_sha);
        assert(close(fd) == 0 && original_size > 0 && original_size <= 65536 &&
            after_size >= original_size &&
            (fault && strcmp(variant, "commit") == 0 ? after_size == original_size : 1));
        int original_fd = open(wal_path, O_RDONLY | O_CLOEXEC);
        assert(original_fd >= 0);
        unsigned char* current_prefix = malloc((size_t)original_size);
        unsigned char prefix_sha[32];
        assert(current_prefix && pread(original_fd, current_prefix,
            (size_t)original_size, 0) == original_size && close(original_fd) == 0);
        SHA256(current_prefix, (size_t)original_size, prefix_sha);
        free(current_prefix);
        assert(memcmp(original_sha, prefix_sha, 32u) == 0);
        if (failed) assert(!qihse_kv_ct_source_status(source, op, &status));
        else {
            assert(qihse_kv_ct_source_status(source, op, &status) &&
                !status.admitted && status.durable_lsn == 2u &&
                status.acknowledged_lsn == 0u &&
                status.retained_bytes == (uint64_t)after_size);
            assert(!qihse_kv_ct_source_custody_hold_install(source, op,
                "gen:floor", baseline_seq, digest, 2u)); /* already held */
            assert(!qihse_kv_ct_source_ack(source, service,
                "target:floor", "gen:floor", 2u));
            assert(!qihse_kv_ct_source_reconcile_peer(source, op, service,
                "target:floor", "gen:floor", digest, 2u));
            /* Correct configured service UID and correct cursor still cannot
             * convert an untrusted archive file into release authority. */
            assert(status.acknowledged_lsn == 0u && status.retained_bytes > 0u);
        }
        assert(qihse_kv_get_user(source, "commons/floor-pending", op) == NULL);
        assert((qihse_kv_change_seq(source) > target_highwater) == !failed);
        assert(!qihse_kv_ct_writer_scope_enter(source, op, token, &scope));
        _exit(failed ? 87 : 86); /* no destructor: exercise cold crash reopen */
    }
    qihse_kv_ct_source_status_t status = {0};
    bool reopened_status = qihse_kv_ct_source_status(source, op, &status);
    bool before_group = strcmp(variant, "commit") == 0 ||
        strcmp(variant, "dir-fsync") == 0 ||
        strcmp(variant, "cut-hold") == 0 ||
        strcmp(variant, "cut-floor") == 0;
    assert(reopened_status && !status.admitted &&
        status.durable_lsn == (before_group ? 1u : 2u) &&
        status.acknowledged_lsn == 0u && status.retained_bytes > 0u);
    assert(qihse_kv_get_user(source, "commons/floor-pending", op) == NULL);
    assert(!qihse_kv_set_user(source, "commons/floor-pending", "late", 4u, 2u, op));
    assert(!qihse_kv_ct_source_ack(source, op, "target:floor", "gen:floor",
        status.durable_lsn));
    assert(!qihse_kv_ct_source_reconcile(source, op, "target:floor", "gen:floor",
        status.baseline_digest, status.durable_lsn));
    assert(!qihse_kv_ct_source_reconcile_peer(source, op, op,
        "target:floor", "gen:floor", status.baseline_digest, status.durable_lsn));
    /* Auth bootstrap in this process has no inherited setup-process user
     * object. Recreate the same configured UID to test non-transferability. */
    qihse_user_t* service = qihse_auth_create_user(op, 8302u,
        QIHSE_ROLE_ANALYST, 5u, 2u, "CtStorageService1!", false);
    assert(service);
    assert(!qihse_kv_ct_source_ack(source, service,
        "target:floor", "gen:floor", status.durable_lsn));
    assert(!qihse_kv_ct_source_reconcile_peer(source, op, service,
        "target:floor", "gen:floor", status.baseline_digest, status.durable_lsn));
    unsigned char forged_digest[32];
    memcpy(forged_digest, status.baseline_digest, sizeof(forged_digest));
    forged_digest[0] ^= 1u;
    assert(!qihse_kv_ct_source_reconcile_peer(source, op, service,
        "target:floor", "gen:floor", forged_digest, status.durable_lsn));
    assert(qihse_kv_ct_source_status(source, op, &status) &&
        status.acknowledged_lsn == 0u && status.retained_bytes > 0u);
    char forged_path[512];
    assert(snprintf(forged_path, sizeof(forged_path), "%s/ct1-forged.arc",
        getenv("QIHSE_DATA_DIR")) > 0);
    int forged_fd = open(forged_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char forged_magic[8];
    assert(forged_fd >= 0 && read(forged_fd, forged_magic, sizeof(forged_magic)) ==
        (ssize_t)sizeof(forged_magic) && !memcmp(forged_magic, "CT1ARC01", 8) &&
        close(forged_fd) == 0);
    char wal_path[512], original_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
        getenv("QIHSE_DATA_DIR")) > 0 &&
        snprintf(original_path, sizeof(original_path), "%s/ct-floor-prefix.bin",
        getenv("QIHSE_DATA_DIR")) > 0);
    int prefix_fd = open(original_path, O_RDONLY | O_CLOEXEC);
    off_t original_size = 0;
    unsigned char original_sha[32], prefix_sha[32];
    assert(prefix_fd >= 0 && read(prefix_fd, &original_size, sizeof(original_size)) ==
        (ssize_t)sizeof(original_size) &&
        read(prefix_fd, original_sha, sizeof(original_sha)) ==
        (ssize_t)sizeof(original_sha) && close(prefix_fd) == 0 &&
        original_size > 0 && original_size <= 65536);
    int wal_fd = open(wal_path, O_RDONLY | O_CLOEXEC);
    unsigned char* original_prefix = malloc((size_t)original_size);
    assert(wal_fd >= 0 && original_prefix &&
        pread(wal_fd, original_prefix, (size_t)original_size, 0) == original_size &&
        close(wal_fd) == 0);
    SHA256(original_prefix, (size_t)original_size, prefix_sha);
    free(original_prefix);
    assert(memcmp(original_sha, prefix_sha, sizeof(prefix_sha)) == 0);
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t cursor = 0u;
    assert(qihse_kv_ct_source_read(source, op, "gen:floor", 0u, 1u, 65536u,
        &groups, &count, &cursor) && count == 1u && cursor == 1u &&
        groups[0].count == 1u &&
        groups[0].first_seq == groups[0].last_seq &&
        groups[0].first_seq == groups[0].records[0].change_seq &&
        groups[0].first_seq < target_highwater &&
        strcmp(groups[0].records[0].key, "commons/floor-pending") == 0 &&
        strcmp(groups[0].records[0].value, "original-frame") == 0 &&
        !groups[0].records[0].tombstone);
    qihse_kv_ct_groups_free(groups, count);
    if (!before_group) {
        assert(qihse_kv_ct_source_read(source, op, "gen:floor", 1u, 1u, 65536u,
            &groups, &count, &cursor) && count == 1u && cursor == 2u &&
            groups[0].stream_position == 2u && groups[0].count == 1u &&
            groups[0].records[0].tombstone &&
            groups[0].records[0].change_seq > target_highwater &&
            strcmp(groups[0].records[0].key, "commons/floor-pending") == 0 &&
            groups[0].records[0].classification == 4u &&
            groups[0].records[0].sci_compartment == 2u);
        qihse_kv_ct_groups_free(groups, count);
    }
    assert((qihse_kv_change_seq(source) > target_highwater) ==
        (strcmp(variant, "commit") != 0 && strcmp(variant, "cut-hold") != 0));
    if (strcmp(variant, "marker-rollback") == 0 ||
        strcmp(variant, "marker-advance") == 0) {
        char path[512];
        assert(snprintf(path, sizeof(path), "%s/ct1-recovery-fence.bin",
            getenv("QIHSE_DATA_DIR")) > 0);
        seed_recovery_fence(path, "gen:floor", status.baseline_row_seq,
            status.baseline_digest, strcmp(variant, "marker-rollback") == 0 ?
            0u : 3u, 0);
        qihse_kv_store_destroy(source);
        assert(qihse_kv_store_create_user(op) == NULL);
    } else if (strcmp(variant, "corrupt") == 0) {
        char path[512];
        assert(snprintf(path, sizeof(path), "%s/restore-highwater.bin",
            getenv("QIHSE_DATA_DIR")) > 0);
        int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        assert(fd >= 0 && pwrite(fd, "X", 1u, 0) == 1 &&
            fsync(fd) == 0 && close(fd) == 0);
        qihse_kv_store_destroy(source);
        assert(qihse_kv_store_create_user(op) == NULL);
    } else qihse_kv_store_destroy(source);
}
#endif

int main(int argc, char** argv) {
#ifdef QIHSE_CT_STORAGE_FLOOR_TEST
    if (argc == 3 && strcmp(argv[1], "floor-setup") == 0) {
        ct_floor_fixture("setup", argv[2]);
        return 99;
    }
    if (argc == 3 && strcmp(argv[1], "floor-reopen") == 0) {
        ct_floor_fixture("reopen", argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "floor-denied") == 0) {
        ct_floor_fixture("denied", argv[2]);
        return 0;
    }
#endif
    if (argc == 2 && (strcmp(argv[1], "prebind-delete-receipt") == 0 ||
                      strcmp(argv[1], "lane-prebind-delete-receipt") == 0)) {
        bool lane = strcmp(argv[1], "lane-prebind-delete-receipt") == 0;
        char dir[] = "./ct_prebind_delete_receipt_XXXXXX";
        umask(0077);
        assert(mkdtemp(dir));
        assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
        assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_kv_store_t* stale = qihse_kv_store_create_user(op);
        assert(stale);
        const char* source_key = "commons/prebind-source";
        const char* receipt_key = "commons/prebind-receipt";
        uint64_t source_seq = 0u, receipt_seq = 0u;
        assert(qihse_kv_set_user_with_seq(stale, source_key, "protected", 4u, 2u,
                                         op, &source_seq) && source_seq != 0u);
        assert(qihse_kv_set_user_with_seq(stale, receipt_key, "P", 4u, 2u,
                                         op, &receipt_seq) && receipt_seq != 0u);
        assert(qihse_kv_sync_store(stale));
        qihse_kv_ct_transfer_status_t initial = {0};
        assert(qihse_kv_ct_transfer_status(stale, op, &initial) && initial.mode == 0u);
        char wal_path[512];
        assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log", dir) > 0);
        int old_wal = open(wal_path, O_RDONLY | O_CLOEXEC);
        assert(old_wal >= 0);
        qihse_kv_store_t* peer = qihse_kv_store_create_user(op);
        assert(peer);
        char lane_id[QIHSE_KV_CT_LANE_ID_MAX + 1u];
        memset(lane_id, 'a', sizeof(lane_id) - 1u);
        lane_id[sizeof(lane_id) - 1u] = '\0';
        if (lane) {
            uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES];
            memset(slots, 0xff, sizeof(slots));
            unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
            assert(qihse_kv_ct_lane_source_enable(peer, op, lane_id, slots,
                "source:receipt", "target:receipt", "gen:receipt", token,
                128u * 1024u * 1024u));
        } else {
            assert(qihse_kv_ct_source_enable(peer, op, "source:receipt",
                "target:receipt", "gen:receipt", NULL, 128u * 1024u * 1024u));
        }
        /* The pre-bind handle may still reference a rotated WAL inode. */
        int active_wal = open(wal_path, O_RDONLY | O_CLOEXEC);
        assert(active_wal >= 0);
        off_t old_size, active_size, after_size;
        unsigned char old_digest[32], active_digest[32], after_digest[32];
        ct_wal_fingerprint(old_wal, &old_size, old_digest);
        ct_wal_fingerprint(active_wal, &active_size, active_digest);
        unsigned calls = 0u;
        uint64_t delete_seq = 99u;
        assert(!qihse_kv_del_with_receipt_user(stale, source_key, source_seq,
            receipt_key, "P", 4u, 2u, ct_stale_receipt_builder, &calls, op,
            &delete_seq));
        assert(delete_seq == 0u && calls == 0u);
        ct_wal_fingerprint(old_wal, &after_size, after_digest);
        assert(old_size == after_size && memcmp(old_digest, after_digest, 32u) == 0);
        ct_wal_fingerprint(active_wal, &after_size, after_digest);
        assert(active_size == after_size && memcmp(active_digest, after_digest, 32u) == 0);
        qihse_kv_store_destroy(stale);
        ct_wal_fingerprint(old_wal, &after_size, after_digest);
        assert(old_size == after_size && memcmp(old_digest, after_digest, 32u) == 0);
        ct_wal_fingerprint(active_wal, &after_size, after_digest);
        assert(active_size == after_size && memcmp(active_digest, after_digest, 32u) == 0);
        assert(close(old_wal) == 0 && close(active_wal) == 0);
        qihse_kv_store_destroy(peer);
        peer = qihse_kv_store_create_user(op);
        assert(peer);
        qihse_user_t* service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
            5u, 2u, "CtStorageService1!", false);
        assert(service);
        qihse_kv_store_set_replication_principal_id(peer, 8302u);
        qihse_kv_replica_snapshot_t* snapshot = NULL;
        uint64_t baseline_seq = 0u;
        unsigned char baseline[32];
        if (lane) {
            assert(qihse_kv_ct_lane_source_baseline_snapshot_create(peer, op,
                lane_id, &snapshot, &baseline_seq, baseline) == 0 && snapshot);
            assert(qihse_kv_ct_lane_source_reconcile_peer(peer, op, service, lane_id,
                "target:receipt", "gen:receipt", baseline, 0u));
        } else {
            assert(qihse_kv_ct_source_baseline_snapshot_create(peer, op, &snapshot,
                &baseline_seq, baseline) == 0 && snapshot);
            assert(qihse_kv_ct_source_reconcile_peer(peer, op, service, "target:receipt",
                "gen:receipt", baseline, 0u));
        }
        qihse_kv_replica_snapshot_destroy(snapshot);
        char* value = qihse_kv_get_user(peer, source_key, op);
        assert(value && strcmp(value, "protected") == 0);
        free(value);
        value = qihse_kv_get_user(peer, receipt_key, op);
        assert(value && strcmp(value, "P") == 0);
        free(value);
        qihse_kv_record_meta_t meta = {0};
        assert(qihse_kv_meta_user(peer, source_key, op, &meta) &&
               meta.change_seq == source_seq);
        assert(qihse_kv_meta_user(peer, receipt_key, op, &meta) &&
               meta.change_seq == receipt_seq);
        qihse_kv_store_destroy(peer);
        qihse_audit_shutdown();
        aimem_fixture_cleanup(dir);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "source-stale") == 0) {
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_kv_store_t* source = qihse_kv_store_create_user(op);
        assert(source && qihse_kv_ct_source_enable(source, op, "source:1",
            "target:1", "gen:1", NULL, 128u * 1024u * 1024u));
        qihse_kv_store_t* peer = qihse_kv_store_create_user(op);
        assert(peer);
        qihse_kv_replica_snapshot_t* snapshot = NULL;
        uint64_t row_seq = 0u;
        unsigned char digest[32];
        assert(qihse_kv_ct_source_baseline_snapshot_create(source, op,
            &snapshot, &row_seq, digest) == 0 && snapshot);
        qihse_kv_replica_snapshot_destroy(snapshot);
        char path[512];
        assert(snprintf(path, sizeof(path), "%s/ct-baseline.qfs",
            getenv("QIHSE_DATA_DIR")) > 0);
        struct stat before, after;
        assert(stat(path, &before) == 0);
        snapshot = NULL;
        assert(qihse_kv_ct_source_baseline_snapshot_create(peer, op,
            &snapshot, &row_seq, digest) != 0 && snapshot == NULL);
        assert(stat(path, &after) == 0 && before.st_dev == after.st_dev &&
               before.st_ino == after.st_ino && before.st_size == after.st_size);
        /* Even an unchanged ACK cut cannot succeed on a handle whose CT
         * state revision predates the sealed baseline. */
        assert(!qihse_kv_ct_source_ack(peer, op, "target:1", "gen:1", 0u));
        qihse_kv_store_destroy(peer);
        qihse_kv_store_destroy(source);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "lane-stale") == 0) {
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_kv_store_t* first = qihse_kv_store_create_user(op);
        assert(first);
        uint8_t a[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
        uint8_t b[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
        uint8_t c[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
        a[0] = 1u; b[0] = 2u; c[0] = 4u;
        char lane_a[QIHSE_KV_CT_LANE_ID_MAX + 1u];
        char lane_b[QIHSE_KV_CT_LANE_ID_MAX + 1u];
        char lane_c[QIHSE_KV_CT_LANE_ID_MAX + 1u];
        memset(lane_a, 'a', sizeof(lane_a) - 1u); lane_a[sizeof(lane_a) - 1u] = '\0';
        memset(lane_b, 'b', sizeof(lane_b) - 1u); lane_b[sizeof(lane_b) - 1u] = '\0';
        memset(lane_c, 'c', sizeof(lane_c) - 1u); lane_c[sizeof(lane_c) - 1u] = '\0';
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
        assert(qihse_kv_ct_lane_source_enable(first, op, lane_a, a,
            "source:a", "target:a", "gen:a", token, 16u * 1024u * 1024u));
        qihse_kv_store_t* peer = qihse_kv_store_create_user(op);
        assert(peer);
        assert(qihse_kv_ct_lane_source_enable(first, op, lane_b, b,
            "source:b", "target:b", "gen:b", token, 16u * 1024u * 1024u));
        char baseline_path[512];
        assert(snprintf(baseline_path, sizeof(baseline_path), "%s/ct-baseline-%s.bin",
            getenv("QIHSE_DATA_DIR"), lane_a) > 0);
        assert(access(baseline_path, F_OK) != 0);
        qihse_kv_replica_snapshot_t* snapshot = NULL;
        uint64_t row_seq = 0u;
        unsigned char digest[32];
        assert(qihse_kv_ct_lane_source_baseline_snapshot_create(peer, op, lane_a,
            &snapshot, &row_seq, digest) != 0 && snapshot == NULL);
        assert(access(baseline_path, F_OK) != 0);
        assert(!qihse_kv_ct_lane_source_enable(peer, op, lane_c, c,
            "source:c", "target:c", "gen:c", token, 16u * 1024u * 1024u));
        qihse_kv_store_destroy(peer);
        qihse_kv_store_destroy(first);
        return 0;
    }
    if (argc == 2 && (strcmp(argv[1], "recovery-fence-crash") == 0 ||
                      strcmp(argv[1], "recovery-fence-reopen") == 0)) {
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_kv_store_t* receiver = qihse_kv_store_create_user(op);
        assert(receiver);
        qihse_kv_ct_receiver_status_t status = {0};
        assert(qihse_kv_ct_receiver_status(receiver, op, &status) &&
               status.durable_cursor == 1u && status.baseline_sealed &&
               strcmp(status.generation, "gen:1") == 0);
        assert(!qihse_kv_sync_store(receiver));
        if (strcmp(argv[1], "recovery-fence-crash") == 0)
            _exit(86); /* no clean shutdown of the fenced handle */
        qihse_kv_store_destroy(receiver);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "retained-frame") == 0) {
        ct_retained_frame_fixture();
        return 0;
    }
    if (argc == 2 && (strcmp(argv[1], "durable-wal-custody") == 0 ||
                      strcmp(argv[1], "ordinary-wal-tail") == 0)) {
        ct_wal_crash_custody_fixture(strcmp(argv[1], "durable-wal-custody") == 0,
                                     0u);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "disposition-tail") == 0 &&
        (strcmp(argv[2], "durable") == 0 || strcmp(argv[2], "ordinary") == 0) &&
        argv[3][0] >= '1' && argv[3][0] <= '4' && argv[3][1] == '\0') {
        ct_wal_crash_custody_fixture(strcmp(argv[2], "durable") == 0,
                                     (size_t)(argv[3][0] - '0'));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "source-highwater") == 0) {
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_user_t* service = qihse_auth_create_user(op, 8302u,
            QIHSE_ROLE_ANALYST, 5u, 2u, "CtStorageService1!", false);
        assert(service);
        qihse_kv_store_t* source = qihse_kv_store_create_user(op);
        assert(source);
        assert(qihse_kv_ct_source_enable(source, op, "source:1", "target:1",
                                         "gen:1", NULL, 128u * 1024u * 1024u));
        qihse_kv_store_set_replication_principal_id(source, 8302u);
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], digest[32];
        assert(qihse_kv_ct_owner_token_get(source, op, token));
        qihse_kv_replica_snapshot_t* snapshot = NULL;
        uint64_t baseline_seq = 0u;
        assert(qihse_kv_ct_source_baseline_snapshot_create(source, op,
            &snapshot, &baseline_seq, digest) == 0 && snapshot);
        qihse_kv_replica_snapshot_destroy(snapshot);
        assert(qihse_kv_ct_source_reconcile_peer(source, op, service,
            "target:1", "gen:1", digest, 0u));
        for (unsigned phase = 0u; phase < 2u; phase++) {
            for (unsigned i = 0u; i < 16u; i++) {
                char key[48];
                assert(snprintf(key, sizeof(key), "commons/highwater-%u", i) > 0);
                qihse_kv_ct_writer_scope_t* scope = NULL;
                assert(qihse_kv_ct_writer_scope_enter(source, op, token, &scope));
                assert(phase ? qihse_kv_del_user(source, key, op) :
                    qihse_kv_set_user(source, key, "value", 0u, 0u, op));
                qihse_kv_ct_source_status_t status = {0};
                assert(qihse_kv_ct_source_status(source, op, &status) &&
                       status.durable_lsn == (uint64_t)phase * 16u + i + 1u);
                assert(qihse_kv_ct_source_ack(source, op, "target:1", "gen:1",
                                              status.durable_lsn));
                assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
            }
        }
        uint64_t floor = qihse_kv_change_seq(source);
        qihse_kv_ct_source_status_t before = {0}, after = {0};
        assert(qihse_kv_ct_source_status(source, op, &before) &&
               before.durable_lsn == 32u && before.acknowledged_lsn == 32u &&
               before.retained_bytes == 0u);
        qihse_kv_sweep_expired(source);
        qihse_kv_sstable_stats_t stats = {0};
        assert(qihse_kv_sstable_stats(source, &stats) &&
               stats.live_sstable_files == 0u && !stats.index_degraded);
        qihse_kv_store_destroy(source);
        source = qihse_kv_store_create_user(op);
        assert(source && qihse_kv_change_seq(source) >= floor);
        assert(qihse_kv_ct_source_status(source, op, &after) &&
               after.durable_lsn == before.durable_lsn &&
               after.acknowledged_lsn == before.acknowledged_lsn &&
               after.retained_bytes == 0u && !after.admitted);
        qihse_kv_store_destroy(source);
        return 0;
    }
    if (argc == 7 && (strcmp(argv[1], "receiver") == 0 ||
                      strcmp(argv[1], "receiver-mismatch") == 0 ||
                      strcmp(argv[1], "receiver-expired") == 0 ||
                      strcmp(argv[1], "receiver-stale") == 0 ||
                      strcmp(argv[1], "receiver-stale-expired") == 0 ||
                      strcmp(argv[1], "prebind-stale") == 0 ||
                      strcmp(argv[1], "prebind-buffered") == 0 ||
                      strcmp(argv[1], "receiver-history") == 0 ||
                      strcmp(argv[1], "receiver-history-set") == 0 ||
                      strcmp(argv[1], "target-quote") == 0 ||
                      strcmp(argv[1], "target-quote-fence") == 0 ||
                      strcmp(argv[1], "recovery-fence") == 0 ||
                      strcmp(argv[1], "custody-replay") == 0 ||
                      strcmp(argv[1], "custody-replay-separated") == 0 ||
                      strcmp(argv[1], "custody-replay-later-set") == 0 ||
                      strcmp(argv[1], "custody-replay-later-tombstone") == 0 ||
                      strcmp(argv[1], "custody-replay-false-position") == 0 ||
                      strcmp(argv[1], "custody-system") == 0 ||
                      strcmp(argv[1], "custody-system-policy") == 0 ||
                      strcmp(argv[1], "custody-system-tenant") == 0 ||
                      strcmp(argv[1], "custody-system-low") == 0 ||
                      strcmp(argv[1], "custody-system-header") == 0 ||
                      strcmp(argv[1], "custody-system-corrupt") == 0 ||
                      strcmp(argv[1], "custody-system-sci") == 0 ||
                      strcmp(argv[1], "custody-system-frame-tenant") == 0)) {
        bool mismatch = strcmp(argv[1], "receiver-mismatch") == 0;
        bool expired = strcmp(argv[1], "receiver-expired") == 0;
        bool stale_expired = strcmp(argv[1], "receiver-stale-expired") == 0;
        bool stale = stale_expired || strcmp(argv[1], "receiver-stale") == 0;
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_user_t* low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
                                                    0u, 0u, "CtStorageLow1!", false);
        assert(low);
        qihse_user_t* service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
                                                        5u, 2u, "CtStorageService1!", false);
        assert(service);
        qihse_kv_store_t* receiver = qihse_kv_store_create_user(op);
        assert(receiver);
        qihse_kv_store_t* prebind_peer = strcmp(argv[1], "prebind-stale") == 0
            ? qihse_kv_store_create_user(op) : NULL;
        qihse_kv_store_t* fence_peer = strcmp(argv[1], "recovery-fence") == 0
            ? qihse_kv_store_create_user(op) : NULL;
        if (strcmp(argv[1], "recovery-fence") == 0) assert(fence_peer);
        uint64_t receipt_source_seq = 0u;
        int prebind_wal = -1;
        if (strcmp(argv[1], "prebind-stale") == 0) assert(prebind_peer);
        if (prebind_peer) {
            char path[512];
            assert(snprintf(path, sizeof(path), "%s/wal.log", getenv("QIHSE_DATA_DIR")) > 0);
            prebind_wal = open(path, O_RDONLY | O_CLOEXEC);
            assert(prebind_wal >= 0);
            assert(qihse_kv_set_user_with_seq(prebind_peer, "commons/receipt-source",
                "source", 0u, 0u, op, &receipt_source_seq));
            assert(qihse_kv_set_user(prebind_peer, "commons/receipt-prepared", "P",
                0u, 0u, op));
        }
        bool buffered = strcmp(argv[1], "prebind-buffered") == 0;
        qihse_kv_store_t* pending = buffered ? qihse_kv_store_create_user(op) : NULL;
        int old_wal = -1;
        char buffered_wal_path[512];
        off_t old_size = 0, old_after = 0, active_size = 0, active_after = 0;
        unsigned char old_digest[32], old_after_digest[32];
        unsigned char active_digest[32], active_after_digest[32];
        if (buffered) {
            assert(pending);
            assert(snprintf(buffered_wal_path, sizeof(buffered_wal_path), "%s/wal.log",
                getenv("QIHSE_DATA_DIR")) > 0);
            old_wal = open(buffered_wal_path, O_RDONLY | O_CLOEXEC);
            assert(old_wal >= 0);
            ct_wal_fingerprint(old_wal, &old_size, old_digest);
            assert(qihse_kv_set_user(pending, "commons/buffered", "prebind", 0u, 0u, op));
            ct_wal_fingerprint(old_wal, &old_after, old_after_digest);
            assert(old_size == old_after && memcmp(old_digest, old_after_digest, 32u) == 0);
        }
        qihse_kv_store_set_replication_principal_id(receiver, 8302u);
        qihse_kv_ct_receiver_status_t denied_status = {0};
        assert(!qihse_kv_ct_receiver_status(receiver, low, &denied_status));
        uint64_t baseline_seq = strtoull(argv[4], NULL, 10);
        unsigned char digest[32];
        for (size_t i = 0u; i < 32u; i++) {
            unsigned value = 0u;
            assert(sscanf(argv[5] + i * 2u, "%2x", &value) == 1);
            digest[i] = (unsigned char)value;
        }
        assert(qihse_kv_ct_receiver_bind(receiver, op, "source:1", "target:1",
                                          "gen:1", QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                          0u, baseline_seq, NULL));
        if (prebind_peer) {
            /* The pre-bind mode-0 handle still holds a valid local pair. No
             * delete/receipt frame may reach either WAL inode after binding. */
            char path[512];
            assert(snprintf(path, sizeof(path), "%s/wal.log", getenv("QIHSE_DATA_DIR")) > 0);
            int active_wal = open(path, O_RDONLY | O_CLOEXEC);
            assert(active_wal >= 0);
            off_t old_size, active_size, after_size;
            unsigned char old_digest[32], active_digest[32], after_digest[32];
            ct_wal_fingerprint(prebind_wal, &old_size, old_digest);
            ct_wal_fingerprint(active_wal, &active_size, active_digest);
            uint64_t denied_seq = 99u;
            assert(!qihse_kv_del_with_receipt_user(prebind_peer,
                "commons/receipt-source", receipt_source_seq,
                "commons/receipt-prepared", "P", 0u, 0u,
                ct_receipt_value, NULL, op, &denied_seq) && denied_seq == 0u);
            ct_wal_fingerprint(prebind_wal, &after_size, after_digest);
            assert(old_size == after_size && memcmp(old_digest, after_digest, 32u) == 0);
            ct_wal_fingerprint(active_wal, &after_size, after_digest);
            assert(active_size == after_size && memcmp(active_digest, after_digest, 32u) == 0);
            assert(close(prebind_wal) == 0 && close(active_wal) == 0);
            /* This must fail even before a recovery intent exists on disk. */
            assert(!qihse_kv_set_user(prebind_peer, "commons/prebind", "bad", 0u, 0u, op));
            assert(!qihse_kv_ct_receiver_bind(prebind_peer, op, "source:2", "target:2",
                "gen:2", QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, baseline_seq, NULL));
            assert(!qihse_kv_ct_source_enable(prebind_peer, op, "source:2", "target:2",
                "gen:2", NULL, 128u * 1024u * 1024u));
        }
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
        assert(qihse_kv_ct_owner_token_get(receiver, op, token));
        assert(!qihse_kv_ct_receiver_install_baseline(receiver, low, service, "source:1",
            "gen:1", argv[2], baseline_seq, digest, token));
        assert(!qihse_kv_ct_receiver_install_baseline(receiver, op, low, "source:1",
            "gen:1", argv[2], baseline_seq, digest, token));
        if (strcmp(argv[1], "recovery-fence") == 0) {
            char unsealed_path[512];
            assert(snprintf(unsealed_path, sizeof(unsealed_path),
                "%s/ct1-recovery-fence.bin", getenv("QIHSE_DATA_DIR")) > 0);
            seed_recovery_fence(unsealed_path, "gen:1", baseline_seq, digest, 0u, 0);
            assert(!qihse_kv_ct_receiver_install_baseline(receiver, op, service,
                "source:1", "gen:1", argv[2], baseline_seq, digest, token));
            qihse_kv_ct_receiver_status_t unsealed = {0};
            assert(qihse_kv_ct_receiver_status(receiver, op, &unsealed) &&
                   !unsealed.baseline_sealed && unsealed.durable_cursor == 0u);
            assert(qihse_kv_store_create_user(op) == NULL);
            qihse_kv_store_destroy(receiver);
            assert(unlink(unsealed_path) == 0);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(qihse_kv_ct_owner_token_get(receiver, op, token));
        }
        assert(qihse_kv_ct_receiver_install_baseline(receiver, op, service, "source:1",
            "gen:1", argv[2], baseline_seq, digest, token));
        if (buffered) {
            char marker_path[512];
            assert(snprintf(marker_path, sizeof(marker_path),
                "%s/ct1-recovery-fence.bin", getenv("QIHSE_DATA_DIR")) > 0);
            assert(qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:1", baseline_seq, digest, 0u));
            int active_wal = open(buffered_wal_path, O_RDONLY | O_CLOEXEC);
            assert(active_wal >= 0);
            ct_wal_fingerprint(active_wal, &active_size, active_digest);
            qihse_kv_store_destroy(pending);
            ct_wal_fingerprint(old_wal, &old_after, old_after_digest);
            ct_wal_fingerprint(active_wal, &active_after, active_after_digest);
            assert(old_size == old_after && memcmp(old_digest, old_after_digest, 32u) == 0);
            assert(active_size == active_after &&
                   memcmp(active_digest, active_after_digest, 32u) == 0);
            assert(close(old_wal) == 0 && close(active_wal) == 0);
            assert(unlink(marker_path) == 0);
            assert(qihse_kv_store_create_user(op) == NULL);
            assert(!qihse_kv_set_user(receiver, "commons/buffered", "late", 0u, 0u, op));
            qihse_kv_store_destroy(receiver);
            return 0;
        }
        if (prebind_peer) {
            char state_path[512], marker_path[512], wal_path[512], export_path[512];
            assert(snprintf(state_path, sizeof(state_path), "%s/ct-state.bin",
                getenv("QIHSE_DATA_DIR")) > 0);
            assert(snprintf(export_path, sizeof(export_path), "%s/stale-export.bin",
                getenv("QIHSE_DATA_DIR")) > 0);
            assert(snprintf(marker_path, sizeof(marker_path), "%s/ct1-recovery-fence.bin",
                getenv("QIHSE_DATA_DIR")) > 0);
            assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
                getenv("QIHSE_DATA_DIR")) > 0);
            assert(qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:1", baseline_seq, digest, 0u));
            FILE* state = fopen(state_path, "rb");
            assert(state && fseek(state, 0, SEEK_END) == 0);
            long length = ftell(state);
            assert(length > 0 && fseek(state, 0, SEEK_SET) == 0);
            unsigned char* before = malloc((size_t)length);
            unsigned char* after = malloc((size_t)length);
            assert(before && after && fread(before, 1u, (size_t)length, state) == (size_t)length);
            struct stat wal_before, wal_after;
            assert(stat(wal_path, &wal_before) == 0);
            assert(qihse_kv_save_user(prebind_peer, export_path, op) != 0 &&
                   access(export_path, F_OK) != 0);
            assert(qihse_kv_save_user(prebind_peer, state_path, op) != 0);
            assert(!qihse_kv_set_user(prebind_peer, "commons/unauthorized", "bad", 0u, 0u, op));
            assert(!qihse_kv_del_user(prebind_peer, "commons/unauthorized", op));
            assert(!qihse_kv_ct_receiver_bind(prebind_peer, op, "source:2", "target:2",
                "gen:2", QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, baseline_seq, NULL));
            assert(!qihse_kv_ct_source_enable(prebind_peer, op, "source:2", "target:2",
                "gen:2", NULL, 128u * 1024u * 1024u));
            assert(unlink(marker_path) == 0);
            assert(qihse_kv_save_user(prebind_peer, export_path, op) != 0 &&
                   access(export_path, F_OK) != 0);
            assert(qihse_kv_save_user(prebind_peer, state_path, op) != 0);
            assert(!qihse_kv_set_user(prebind_peer, "commons/unauthorized", "bad", 0u, 0u, op));
            assert(!qihse_kv_del_user(prebind_peer, "commons/unauthorized", op));
            assert(!qihse_kv_ct_receiver_bind(prebind_peer, op, "source:2", "target:2",
                "gen:2", QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, baseline_seq, NULL));
            assert(!qihse_kv_ct_source_enable(prebind_peer, op, "source:2", "target:2",
                "gen:2", NULL, 128u * 1024u * 1024u));
            assert(stat(wal_path, &wal_after) == 0 && wal_before.st_size == wal_after.st_size);
            assert(fclose(state) == 0);
            state = fopen(state_path, "rb");
            assert(state && fread(after, 1u, (size_t)length, state) == (size_t)length &&
                memcmp(before, after, (size_t)length) == 0 &&
                fgetc(state) == EOF && fclose(state) == 0);
            free(after); free(before);
            qihse_kv_store_destroy(prebind_peer);
            qihse_kv_store_destroy(receiver);
            return 0;
        }
        FILE* f = fopen(argv[3], "rb");
        assert(f);
        qihse_kv_ct_group_t group = {0};
        uint8_t mode = 0u;
        size_t bytes = 0u;
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                                   65536u, &group, &mode, &bytes) == 1);
        qihse_kv_ct_group_t group2 = {0};
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                                   65536u, &group2, &mode, &bytes) == 1);
        fclose(f);
        assert(group2.count == 1u && group2.records[0].value &&
               strlen(group2.records[0].value) == 32768u);
        if (strncmp(argv[1], "custody-replay", sizeof("custody-replay") - 1u) == 0 ||
            strncmp(argv[1], "custody-system", sizeof("custody-system") - 1u) == 0) {
            int variant = !strcmp(argv[1], "custody-replay-separated") ? 1 :
                !strcmp(argv[1], "custody-replay-later-set") ? 2 :
                !strcmp(argv[1], "custody-replay-later-tombstone") ? 12 :
                !strcmp(argv[1], "custody-replay-false-position") ? 3 :
                !strcmp(argv[1], "custody-system-policy") ? 5 :
                !strcmp(argv[1], "custody-system-tenant") ? 6 :
                !strcmp(argv[1], "custody-system-low") ? 7 :
                !strcmp(argv[1], "custody-system-header") ? 8 :
                !strcmp(argv[1], "custody-system-corrupt") ? 9 :
                !strcmp(argv[1], "custody-system-sci") ? 10 :
                !strcmp(argv[1], "custody-system-frame-tenant") ? 11 :
                !strcmp(argv[1], "custody-system") ? 4 : 0;
            custody_storage_fixture(receiver, op, service, &group, &group2,
                baseline_seq, digest, argv[2], variant);
            qihse_ct_codec_clear(&group);
            qihse_ct_codec_clear(&group2);
            /* Cleanup stops the audit writer, so keep it in the fixture child. */
            aimem_fixture_cleanup(getenv("QIHSE_DATA_DIR"));
            return 0;
        }
        if (strcmp(argv[1], "recovery-fence") == 0) {
            uint64_t cursor = 0u;
            assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) &&
                   cursor == 1u && qihse_kv_sync_store(receiver));
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver); /* an unmarked receiver retains its old admission */
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            qihse_kv_replica_snapshot_t* ordinary = NULL;
            assert(qihse_kv_replica_snapshot_create(receiver, op, "*", &ordinary) == 0 &&
                   ordinary);
            qihse_kv_replica_snapshot_destroy(ordinary);
            qihse_kv_store_destroy(receiver);
            char marker_path[512], held_path[512];
            assert(snprintf(marker_path, sizeof(marker_path), "%s/ct1-recovery-fence.bin",
                            getenv("QIHSE_DATA_DIR")) > 0);
            assert(snprintf(held_path, sizeof(held_path), "%s/invalid-marker",
                            getenv("QIHSE_DATA_DIR")) > 0);
            assert(mkfifo(marker_path, 0600) == 0);
            alarm(3); /* A blocking marker open must terminate this fixture. */
            assert(qihse_kv_store_create_user(op) == NULL);
            alarm(0);
            assert(rename(marker_path, held_path) == 0);
            assert(symlink("ct-state.bin", marker_path) == 0);
            assert(qihse_kv_store_create_user(op) == NULL);
            assert(snprintf(held_path, sizeof(held_path), "%s/invalid-symlink",
                            getenv("QIHSE_DATA_DIR")) > 0);
            assert(rename(marker_path, held_path) == 0);
            receiver = qihse_kv_store_create_user(op);
            qihse_kv_store_t* peer = fence_peer;
            assert(receiver && peer); /* stale peer predates CT binding */
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            qihse_kv_store_set_replication_principal_id(peer, 8302u);
            uint64_t blocked_cut = 99u;
            assert(!qihse_kv_ct_receiver_recovery_fence_install(receiver, low,
                "gen:1", baseline_seq, digest, 1u));
            assert(!qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:wrong", baseline_seq, digest, 1u));
            assert(!qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:1", baseline_seq, digest, 0u));
            assert(qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:1", baseline_seq, digest, 1u));
            assert(!qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:1", baseline_seq, digest, 1u));
            assert(!qihse_kv_ct_receiver_apply(peer, service, &group2, &cursor) &&
                   cursor == 0u);
            assert(!qihse_kv_ct_fence_range(peer, op, "transfer:peer", 1u, 1u,
                                             token, &blocked_cut) && blocked_cut == 0u);
            assert(!qihse_kv_replica_cursor_advance(peer, "source:1", "*", 2u, op));
            qihse_kv_replica_snapshot_t* denied_peer_snapshot = NULL;
            assert(qihse_kv_replica_snapshot_create(peer, op, "*",
                &denied_peer_snapshot) != 0 && denied_peer_snapshot == NULL);
            assert(unlink(marker_path) == 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* CT-state denial survives removal */
            assert(!qihse_kv_ct_receiver_apply(peer, service, &group2, &cursor));
            assert(qihse_kv_replica_snapshot_create(peer, op, "*",
                &denied_peer_snapshot) != 0 && denied_peer_snapshot == NULL);
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 1u, 0);
            qihse_kv_store_destroy(peer);
            qihse_kv_ct_receiver_status_t fenced = {0};
            assert(qihse_kv_ct_receiver_status(receiver, op, &fenced) &&
                   fenced.durable_cursor == 1u && fenced.baseline_sealed &&
                   strcmp(fenced.generation, "gen:1") == 0 &&
                   memcmp(fenced.baseline_digest, digest, 32u) == 0);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            qihse_kv_ct_proof_t* promotion = qihse_kv_ct_promotion_proof_create(
                receiver, op, "source:1", "target:1", "gen:1", 1u);
            assert(promotion);
            assert(!qihse_kv_ct_receiver_promote(receiver, op, promotion,
                "gen:2", "successor:2", token));
            qihse_kv_ct_proof_destroy(promotion);
            assert(!qihse_kv_ct_source_reconcile(receiver, op,
                "target:1", "gen:1", digest, 1u));
            assert(qihse_kv_replica_snapshot_create(receiver, op, "*", &ordinary) != 0 &&
                   ordinary == NULL);
            assert(qihse_kv_get_user(receiver, group.records[0].key, op) == NULL);
            uint64_t fenced_seq = qihse_kv_change_seq(receiver);
            assert(group.records[0].value);
            assert(qihse_kv_compare_set_user(receiver, group.records[0].key,
                "wrong-expected", "forbidden", 0u, 0u, op) == QIHSE_KV_CAS_FAILED);
            assert(qihse_kv_compare_set_user(receiver, group.records[0].key,
                group.records[0].value, "forbidden", 0u, 0u, op) == QIHSE_KV_CAS_FAILED);
            assert(qihse_kv_compare_set_user(receiver, group.records[0].key,
                NULL, "forbidden", 0u, 0u, op) == QIHSE_KV_CAS_FAILED);
            assert(qihse_kv_change_seq(receiver) == fenced_seq);
            assert(!qihse_kv_sync_store(receiver));
            assert(qihse_kv_clear_user(receiver, op) == 0u);
            qihse_kv_sweep_expired(receiver);
            assert(qihse_kv_ct_receiver_status(receiver, op, &fenced) &&
                   fenced.durable_cursor == 1u);
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver); /* crash/cold reopen preserves the denial */
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor));
            qihse_kv_store_destroy(receiver);
            assert(chmod(marker_path, 0644) == 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* insecure permissions */
            assert(chmod(marker_path, 0600) == 0);
            if (geteuid() == 0) {
                assert(chown(marker_path, 1, (gid_t)-1) == 0);
                assert(qihse_kv_store_create_user(op) == NULL); /* incorrect owner */
                assert(chown(marker_path, 0, (gid_t)-1) == 0);
            }
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 1u, 1);
#ifdef QIHSE_AIMEM_DURABILITY_TEST
            assert(setenv("QIHSE_AIMEM_FAIL_AT", "sst-index-load", 1) == 0);
#endif
            assert(qihse_kv_store_create_user(op) == NULL); /* corrupt checksum */
#ifdef QIHSE_AIMEM_DURABILITY_TEST
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 1u, 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* SST fault was not consumed */
            assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
#endif
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 1u, 2);
            assert(qihse_kv_store_create_user(op) == NULL); /* torn sidecar */
            seed_recovery_fence(marker_path, "gen:wrong", baseline_seq, digest, 1u, 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* generation */
            seed_recovery_fence(marker_path, "gen:1", baseline_seq + 1u, digest, 1u, 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* baseline sequence */
            digest[0] ^= 1u;
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 1u, 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* baseline digest */
            digest[0] ^= 1u;
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 0u, 0);
            assert(qihse_kv_store_create_user(op) == NULL); /* durable cursor */
            seed_recovery_fence(marker_path, "gen:1", baseline_seq, digest, 1u, 0);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver && !qihse_kv_ct_receiver_apply(receiver, service, &group2,
                                                              &cursor));
            qihse_ct_codec_clear(&group);
            qihse_ct_codec_clear(&group2);
            qihse_kv_store_destroy(receiver);
            return 0;
        }
        if (strcmp(argv[1], "receiver-history") == 0 ||
            strcmp(argv[1], "receiver-history-set") == 0 ||
            strcmp(argv[1], "target-quote") == 0 ||
            strcmp(argv[1], "target-quote-fence") == 0) {
            assert(group.count == 1u && group.records[0].classification == 4u &&
                   group.records[0].sci_compartment == 2u);
            char* key = group.records[0].key;
            free(group.records[0].value);
            group.records[0].value = NULL;
            group.records[0].tombstone = true;
            group.records[0].expire_time_ms = 0u;
            uint64_t cursor = 0u;
            assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) &&
                   cursor == 1u);
            qihse_kv_ct_receiver_history_request_t req = {
                .version = QIHSE_KV_CT_RECEIVER_HISTORY_V1,
                .size = sizeof(req), .source_id = "source:1", .target_id = "target:1",
                .generation = "gen:1", .baseline_row_seq = baseline_seq,
                .durable_cursor = 1u, .key = key, .resource_tenant_id = 0u,
                .classification = 4u, .sci_compartment = 2u};
            memcpy(req.baseline_digest, digest, 32u);
            qihse_kv_ct_receiver_history_result_t proof = {0};
            assert(qihse_kv_ct_receiver_history_v1(receiver, op, &req, &proof) &&
                   proof.stream_position == 1u &&
                   proof.row_change_seq == group.records[0].change_seq &&
                   proof.durable_cursor == 1u &&
                   proof.row_seq_high_water >= proof.row_change_seq);
            if (strcmp(argv[1], "target-quote-fence") == 0) {
                uint64_t expected = qihse_kv_change_seq(receiver), cut = 0u;
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
                assert(qihse_kv_ct_fence_range(receiver, op, "move:quote", 0u, 0u,
                    token, &cut) && cut == 1u);
                memset(&proof, 0xa5, sizeof(proof));
                assert(!qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
                qihse_kv_ct_receiver_history_result_t empty = {0};
                assert(memcmp(&proof, &empty, sizeof(proof)) == 0);
                qihse_ct_codec_clear(&group);
                qihse_ct_codec_clear(&group2);
                qihse_kv_store_destroy(receiver);
                return 0;
            }
            if (strcmp(argv[1], "target-quote") == 0) {
                uint64_t expected = qihse_kv_change_seq(receiver);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof) && proof.row_seq_high_water == expected &&
                    proof.row_change_seq == group.records[0].change_seq);
                qihse_kv_sstable_stats_t before_sst = {0}, after_sst = {0};
                assert(qihse_kv_sstable_stats(receiver, &before_sst) &&
                    qihse_kv_sync_store(receiver) &&
                    qihse_kv_sstable_stats(receiver, &after_sst) &&
                    after_sst.sstable_counter == before_sst.sstable_counter + 1u &&
                    !after_sst.index_degraded);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof) &&
                    proof.row_change_seq == group.records[0].change_seq);
                char sst_path[512], moved_sst[512];
                const char* quote_dir = getenv("QIHSE_DATA_DIR");
                assert(snprintf(sst_path, sizeof(sst_path), "%s/sstable_%zu.db",
                    quote_dir, before_sst.sstable_counter) > 0);
                assert(snprintf(moved_sst, sizeof(moved_sst), "%s/sstable_%zu.db.replaced",
                    quote_dir, before_sst.sstable_counter) > 0);
                assert(rename(sst_path, moved_sst) == 0 &&
                    symlink(strrchr(moved_sst, '/') + 1, sst_path) == 0);
                memset(&proof, 0xa5, sizeof(proof));
                assert(!qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
                qihse_kv_ct_receiver_history_result_t empty_sst = {0};
                assert(memcmp(&proof, &empty_sst, sizeof(proof)) == 0);
                assert(unlink(sst_path) == 0 && rename(moved_sst, sst_path) == 0);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof) &&
                    proof.row_change_seq == group.records[0].change_seq);
#define QUOTE_DENIED(operator_user, data_user) do { \
    memset(&proof, 0xa5, sizeof(proof)); \
    assert(!qihse_kv_ct_target_quote_snapshot_v1(receiver, operator_user, \
        data_user, &req, expected, &proof)); \
    qihse_kv_ct_receiver_history_result_t empty = {0}; \
    assert(memcmp(&proof, &empty, sizeof(proof)) == 0); \
} while (0)
                QUOTE_DENIED(low, service);
                QUOTE_DENIED(NULL, service);
                QUOTE_DENIED(op, NULL);
                QUOTE_DENIED(op, op); /* Operator cannot be the replicator. */
                QUOTE_DENIED(op, low); /* Wrong identity and low clearance. */
                expected++; QUOTE_DENIED(op, service); expected--;
                req.resource_tenant_id++; QUOTE_DENIED(op, service);
                req.resource_tenant_id--;
                req.classification++; QUOTE_DENIED(op, service);
                req.classification--;
                req.sci_compartment = 0u; QUOTE_DENIED(op, service);
                req.sci_compartment = 2u;
                req.generation = "gen:wrong"; QUOTE_DENIED(op, service);
                req.generation = "gen:1";
                qihse_kv_store_set_replication_principal_id(receiver, 8301u);
                QUOTE_DENIED(op, service);
                QUOTE_DENIED(op, low); /* Configured but below protected row. */
                qihse_user_t* tenant_service = qihse_auth_create_tenant_user(op,
                    12u, 8303u, QIHSE_ROLE_ANALYST, 5u, 2u,
                    "CtStorageTenantService1!", false);
                assert(tenant_service);
                qihse_kv_store_set_replication_principal_id(receiver, 8303u);
                QUOTE_DENIED(op, tenant_service); /* Configured, wrong tenant. */
                qihse_kv_store_set_replication_principal_id(receiver, 8302u);
                assert(qihse_auth_modify_user(op, 8302u, NULL, NULL, -1, -1, 0, 0));
                QUOTE_DENIED(op, service);
                assert(qihse_auth_modify_user(op, 8302u, NULL, NULL, -1, -1, 5, 2));
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
                char state_path[512];
                assert(snprintf(state_path, sizeof(state_path), "%s/ct-state.bin",
                    getenv("QIHSE_DATA_DIR")) > 0);
                int state_fd = open(state_path, O_RDWR | O_CLOEXEC);
                assert(state_fd >= 0);
                unsigned char original, altered;
                assert(pread(state_fd, &original, 1u, 0u) == 1);
                altered = original ^ 1u;
                assert(pwrite(state_fd, &altered, 1u, 0u) == 1);
                QUOTE_DENIED(op, service); /* Persisted state, not live status. */
                assert(pwrite(state_fd, &original, 1u, 0u) == 1 &&
                    close(state_fd) == 0);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
#undef QUOTE_DENIED
            }
#define DENIED(principal) do { \
    memset(&proof, 0xa5, sizeof(proof)); \
    assert(!qihse_kv_ct_receiver_history_v1(receiver, principal, &req, &proof)); \
    qihse_kv_ct_receiver_history_result_t zero = {0}; \
    assert(memcmp(&proof, &zero, sizeof(proof)) == 0); \
} while (0)
            DENIED(low);
            DENIED(NULL);
            if (strcmp(argv[1], "receiver-history-set") == 0) {
                free(group2.records[0].key);
                group2.records[0].key = strdup(key);
                assert(group2.records[0].key);
                group2.first_seq = group2.last_seq =
                    group2.records[0].change_seq = group.records[0].change_seq + 1u;
                group2.records[0].classification = 6u;
                assert(qihse_kv_ct_receiver_apply(receiver, op, &group2, &cursor) &&
                       cursor == 2u);
                req.durable_cursor = 2u;
                DENIED(service);
                DENIED(op);
                assert(qihse_kv_sync_store(receiver));
                qihse_kv_store_destroy(receiver);
                receiver = qihse_kv_store_create_user(op);
                assert(receiver);
                qihse_kv_store_set_replication_principal_id(receiver, 8302u);
                DENIED(service);
                DENIED(op);
                qihse_ct_codec_clear(&group);
                qihse_ct_codec_clear(&group2);
                qihse_kv_store_destroy(receiver);
                return 0;
            }
            req.classification = 0u; DENIED(op); req.classification = 4u;
            req.sci_compartment = 0u; DENIED(op); req.sci_compartment = 2u;
            req.resource_tenant_id = 12u; DENIED(op); req.resource_tenant_id = 0u;
            req.baseline_row_seq++; DENIED(op); req.baseline_row_seq--;
            req.baseline_digest[0] ^= 1u; DENIED(op); req.baseline_digest[0] ^= 1u;
            req.durable_cursor++; DENIED(op); req.durable_cursor--;
            req.generation = "gen:wrong"; DENIED(op); req.generation = "gen:1";
            req.source_id = "source:wrong"; DENIED(op); req.source_id = "source:1";
            req.target_id = "target:wrong"; DENIED(op); req.target_id = "target:1";
            req.version++; DENIED(op); req.version--;
            /* The protected unrelated frame must fail for a lower-clearance
             * replication principal, even though the requested key is readable. */
            free(group2.records[0].key);
            group2.records[0].key = strdup("commons/history-other");
            assert(group2.records[0].key);
            group2.records[0].classification = 6u;
            group2.records[0].sci_compartment = 2u;
            assert(qihse_kv_ct_receiver_apply(receiver, op, &group2, &cursor) &&
                   cursor == 2u);
            req.durable_cursor = 2u;
            assert(qihse_kv_ct_receiver_history_v1(receiver, op, &req, &proof) &&
                   proof.stream_position == 1u && proof.durable_cursor == 2u &&
                   proof.row_seq_high_water >= group2.records[0].change_seq);
            if (strcmp(argv[1], "target-quote") == 0) {
                uint64_t expected = qihse_kv_change_seq(receiver);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, op,
                    &req, expected, &proof) == false);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof) == false); /* unreadable high frame */
            }
            DENIED(service);
            assert(qihse_kv_sync_store(receiver));
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(qihse_kv_ct_receiver_history_v1(receiver, op, &req, &proof) &&
                   proof.stream_position == 1u && proof.durable_cursor == 2u);
            DENIED(service);
            for (unsigned i = 0u; i < 32u; ++i) {
                char padding_key[64];
                assert(snprintf(padding_key, sizeof(padding_key),
                                "commons/history-padding-%u", i) > 0);
                qihse_kv_ct_record_t row = group.records[0];
                row.key = padding_key;
                row.tombstone = false;
                row.value = "padding";
                row.change_seq = group2.records[0].change_seq + 1u + i;
                qihse_kv_ct_group_t padding = group;
                padding.records = &row;
                padding.stream_position = 3u + i;
                padding.first_seq = padding.last_seq = row.change_seq;
                assert(qihse_kv_ct_receiver_apply(receiver, op, &padding, &cursor) &&
                       cursor == padding.stream_position);
                assert(qihse_kv_sync_store(receiver));
            }
            qihse_kv_sweep_expired(receiver);
            req.durable_cursor = 34u;
            assert(qihse_kv_ct_receiver_history_v1(receiver, op, &req, &proof) &&
                   proof.stream_position == 1u && proof.durable_cursor == 34u &&
                   proof.row_seq_high_water >= group2.records[0].change_seq + 32u);
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(qihse_kv_ct_receiver_history_v1(receiver, op, &req, &proof) &&
                   proof.stream_position == 1u && proof.durable_cursor == 34u);
            DENIED(service);
            if (strcmp(argv[1], "target-quote") == 0) {
                assert(qihse_auth_modify_user(op, 8302u, NULL, NULL, -1, -1, 6, 2));
                uint64_t expected = qihse_kv_change_seq(receiver);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof) && proof.row_seq_high_water == expected);
                char quote_state_path[512], moved[512];
                const char* dir = getenv("QIHSE_DATA_DIR");
                assert(snprintf(quote_state_path, sizeof(quote_state_path),
                    "%s/ct-state.bin", dir) > 0);
                assert(snprintf(moved, sizeof(moved),
                    "%s/ct-state.bin.replaced", dir) > 0);
                assert(rename(quote_state_path, moved) == 0 &&
                    symlink("ct-state.bin.replaced", quote_state_path) == 0);
                memset(&proof, 0xa5, sizeof(proof));
                assert(!qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
                qihse_kv_ct_receiver_history_result_t empty = {0};
                assert(memcmp(&proof, &empty, sizeof(proof)) == 0);
                assert(unlink(quote_state_path) == 0 &&
                    rename(moved, quote_state_path) == 0);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, expected, &proof));
            }
            char wal_path[512];
            assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
                            getenv("QIHSE_DATA_DIR")) > 0);
            if (strcmp(argv[1], "target-quote") == 0) {
                char moved_wal[512];
                assert(snprintf(moved_wal, sizeof(moved_wal), "%s/wal.log.replaced",
                    getenv("QIHSE_DATA_DIR")) > 0);
                assert(rename(wal_path, moved_wal) == 0 &&
                    symlink("wal.log.replaced", wal_path) == 0);
                memset(&proof, 0xa5, sizeof(proof));
                assert(!qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, qihse_kv_change_seq(receiver), &proof));
                qihse_kv_ct_receiver_history_result_t empty = {0};
                assert(memcmp(&proof, &empty, sizeof(proof)) == 0);
                assert(unlink(wal_path) == 0 && rename(moved_wal, wal_path) == 0);
                assert(qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, qihse_kv_change_seq(receiver), &proof));
            }
            int wal_fd = open(wal_path, O_RDWR | O_CLOEXEC);
            assert(wal_fd >= 0);
            struct stat wal_st;
            assert(fstat(wal_fd, &wal_st) == 0 && wal_st.st_size > 64);
            unsigned char saved = 0u, flipped;
            assert(pread(wal_fd, &saved, 1u, 64u) == 1);
            flipped = saved ^ 1u;
            assert(pwrite(wal_fd, &flipped, 1u, 64u) == 1); /* checksum */
            DENIED(op);
            if (strcmp(argv[1], "target-quote") == 0) {
                qihse_kv_ct_receiver_history_result_t denied = {0};
                assert(!qihse_kv_ct_target_quote_snapshot_v1(receiver, op, service,
                    &req, qihse_kv_change_seq(receiver), &denied));
                assert(denied.version == 0u && denied.row_change_seq == 0u);
            }
            assert(pwrite(wal_fd, &saved, 1u, 64u) == 1);
            assert(pread(wal_fd, &saved, 1u, 8u) == 1);
            flipped = saved ^ 1u;
            assert(pwrite(wal_fd, &flipped, 1u, 8u) == 1); /* mode */
            DENIED(op);
            assert(pwrite(wal_fd, &saved, 1u, 8u) == 1);
            assert(pwrite(wal_fd, "x", 1u, wal_st.st_size) == 1);
            DENIED(op);
            assert(ftruncate(wal_fd, wal_st.st_size) == 0);
            assert(ftruncate(wal_fd, wal_st.st_size - 1) == 0);
            DENIED(op);
            assert(close(wal_fd) == 0);
            qihse_ct_codec_clear(&group);
            qihse_ct_codec_clear(&group2);
            qihse_kv_store_destroy(receiver);
#undef DENIED
            return 0;
        }
        if (stale) {
            /* A later stream position cannot revive a lower-version SET
             * over an earlier source-authored deletion. */
            assert(group.count == 1u && group2.count == 1u &&
                   !group.records[0].tombstone && !group2.records[0].tombstone);
            if (stale_expired) {
                group.records[0].expire_time_ms = 1u;
            } else {
                free(group.records[0].value);
                group.records[0].value = NULL;
                group.records[0].tombstone = true;
                group.records[0].expire_time_ms = 0u;
            }
            group.first_seq = group.last_seq =
                group.records[0].change_seq = baseline_seq + 3u;
            free(group2.records[0].key);
            group2.records[0].key = strdup(group.records[0].key);
            assert(group2.records[0].key);
            group2.first_seq = group2.last_seq =
                group2.records[0].change_seq = baseline_seq + 2u;
            uint64_t cursor = 0u;
            assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) &&
                   cursor == 1u);
            char stale_wal_path[512];
            assert(snprintf(stale_wal_path, sizeof(stale_wal_path), "%s/wal.log",
                            getenv("QIHSE_DATA_DIR")) > 0);
            int stale_wal = open(stale_wal_path, O_RDONLY | O_CLOEXEC);
            assert(stale_wal >= 0);
            off_t wal_before, wal_after;
            unsigned char sha_before[32], sha_after[32];
            ct_wal_fingerprint(stale_wal, &wal_before, sha_before);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            ct_wal_fingerprint(stale_wal, &wal_after, sha_after);
            assert(wal_before == wal_after && memcmp(sha_before, sha_after, 32u) == 0);
            assert(close(stale_wal) == 0);
            qihse_kv_ct_receiver_status_t denied = {0};
            assert(qihse_kv_ct_receiver_status(receiver, service, &denied) &&
                   denied.durable_cursor == 1u);
            assert(qihse_kv_sync_store(receiver));
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            qihse_kv_ct_receiver_status_t status = {0};
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 1u && status.baseline_sealed);
            assert(qihse_kv_get_user(receiver, group.records[0].key, op) == NULL);
            stale_wal = open(stale_wal_path, O_RDONLY | O_CLOEXEC);
            assert(stale_wal >= 0);
            ct_wal_fingerprint(stale_wal, &wal_before, sha_before);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            ct_wal_fingerprint(stale_wal, &wal_after, sha_after);
            assert(wal_before == wal_after && memcmp(sha_before, sha_after, 32u) == 0);
            assert(close(stale_wal) == 0);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 1u);
            for (unsigned i = 0u; i < 32u; i++) {
                char key[64];
                assert(snprintf(key, sizeof(key), "commons/ct-stale-padding-%u", i) > 0);
                qihse_kv_ct_record_t row = group.records[0];
                row.key = key;
                row.value = "padding";
                row.tombstone = false;
                row.change_seq = baseline_seq + 4u + i;
                qihse_kv_ct_group_t padding = group;
                padding.stream_position = 2u + i;
                padding.first_seq = padding.last_seq = row.change_seq;
                padding.records = &row;
                assert(qihse_kv_ct_receiver_apply(receiver, service, &padding, &cursor) &&
                       cursor == padding.stream_position);
                assert(qihse_kv_sync_store(receiver));
            }
            qihse_kv_sweep_expired(receiver);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 33u);
            group2.stream_position = 34u;
            stale_wal = open(stale_wal_path, O_RDONLY | O_CLOEXEC);
            assert(stale_wal >= 0);
            ct_wal_fingerprint(stale_wal, &wal_before, sha_before);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            ct_wal_fingerprint(stale_wal, &wal_after, sha_after);
            assert(wal_before == wal_after && memcmp(sha_before, sha_after, 32u) == 0);
            assert(close(stale_wal) == 0);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 33u);
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 33u && status.baseline_sealed);
            stale_wal = open(stale_wal_path, O_RDONLY | O_CLOEXEC);
            assert(stale_wal >= 0);
            ct_wal_fingerprint(stale_wal, &wal_before, sha_before);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            ct_wal_fingerprint(stale_wal, &wal_after, sha_after);
            assert(wal_before == wal_after && memcmp(sha_before, sha_after, 32u) == 0);
            assert(close(stale_wal) == 0);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 33u);
            assert(qihse_kv_get_user(receiver, group.records[0].key, op) == NULL);
            qihse_ct_codec_clear(&group);
            qihse_ct_codec_clear(&group2);
            qihse_kv_store_destroy(receiver);
            return 0;
        }
        if (expired) {
            assert(group.count == 1u && !group.records[0].tombstone &&
                   group.records[0].value && group.stream_position == 1u &&
                   group.records[0].classification == 4u &&
                   group.records[0].sci_compartment == 2u &&
                   group.records[0].change_seq == baseline_seq + 1u);
            group.records[0].expire_time_ms = 1u;
            const char* key = group.records[0].key;
            uint64_t cursor = 0u;
            qihse_kv_ct_receiver_status_t before = {0}, after = {0};
            qihse_kv_sstable_stats_t sst_before = {0}, sst_after = {0};
            assert(!qihse_kv_ct_receiver_apply(receiver, low, &group, &cursor));
            assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) &&
                   cursor == 1u);
            assert(qihse_kv_ct_receiver_status(receiver, op, &before) &&
                   before.baseline_sealed && before.durable_cursor == 1u &&
                   strcmp(before.source_id, "source:1") == 0 &&
                   strcmp(before.generation, "gen:1") == 0);
            assert(qihse_kv_get_user(receiver, key, op) == NULL);
            assert(qihse_kv_get_user(receiver, key, low) == NULL);
            assert(qihse_kv_sstable_stats(receiver, &sst_before));
            assert(qihse_kv_sync_store(receiver));
            assert(qihse_kv_sstable_stats(receiver, &sst_after) &&
                   sst_after.sstable_counter > sst_before.sstable_counter &&
                   sst_after.live_sstable_files > sst_before.live_sstable_files &&
                   !sst_after.index_degraded);
            char wal_path[512];
            assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
                            getenv("QIHSE_DATA_DIR")) > 0);
            struct stat wal_before, wal_after;
            assert(stat(wal_path, &wal_before) == 0 && wal_before.st_size > 0);
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver); /* exact expired SET in retained WAL vs SST */
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(stat(wal_path, &wal_after) == 0 &&
                   wal_after.st_size == wal_before.st_size);
            assert(qihse_kv_ct_receiver_status(receiver, op, &after) &&
                   after.baseline_sealed == before.baseline_sealed &&
                   after.durable_cursor == before.durable_cursor &&
                   after.tenant_policy == before.tenant_policy &&
                   after.tenant_id == before.tenant_id &&
                   strcmp(after.source_id, before.source_id) == 0 &&
                   strcmp(after.generation, before.generation) == 0 &&
                   memcmp(after.baseline_digest, before.baseline_digest, 32u) == 0);
            assert(qihse_kv_get_user(receiver, key, op) == NULL);
            assert(!qihse_kv_ct_receiver_status(receiver, low, &after));
            assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) &&
                   cursor == 1u);
            group.records[0].value[0] ^= 1;
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor));
            group.records[0].value[0] ^= 1;
            assert(qihse_kv_ct_receiver_status(receiver, op, &after) &&
                   after.durable_cursor == 1u);
            qihse_ct_codec_clear(&group);
            qihse_ct_codec_clear(&group2);
            qihse_kv_store_destroy(receiver);
            return 0;
        }
        if (mismatch) {
            assert(group2.count == 1u && group2.records[0].value);
            group2.records[0].value[0] ^= 1;
        }
        uint64_t cursor = 0u;
        assert(!qihse_kv_ct_receiver_apply(receiver, low, &group, &cursor));
#ifdef QIHSE_AIMEM_DURABILITY_TEST
        assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-after-group-fsync", 1) == 0);
        assert(!qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor));
        assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        qihse_kv_store_destroy(receiver);
        receiver = qihse_kv_store_create_user(op);
        if (!receiver) perror("CT receiver reopen");
        assert(receiver);
        qihse_kv_ct_receiver_status_t status = {0};
        assert(qihse_kv_ct_receiver_status(receiver, op, &status) &&
               status.durable_cursor == 1u);
#endif
        qihse_kv_store_set_replication_principal_id(receiver, 8302u);
        assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) && cursor == 1u);
        assert(qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor) && cursor == 1u);
        group.stream_position = 3u;
        assert(!qihse_kv_ct_receiver_apply(receiver, service, &group, &cursor));
        qihse_ct_codec_clear(&group);
        assert(qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) && cursor == 2u);
        qihse_ct_codec_clear(&group2);
        uint64_t target_cut = 0u;
        assert(qihse_kv_ct_fence_range(receiver, op, "move:1", 0u, 16383u,
                                        token, &target_cut) && target_cut == 2u);
        qihse_kv_store_destroy(receiver);
        receiver = qihse_kv_store_create_user(op);
        assert(receiver);
        assert(qihse_kv_ct_fence_range(receiver, op, "move:1", 0u, 16383u,
                                        token, &target_cut) && target_cut == 2u);
        assert(!qihse_kv_ct_target_seal_create(receiver, low, op, "move:1",
            "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
        assert(!qihse_kv_ct_target_seal_create(receiver, op, low, "move:1",
            "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
        qihse_kv_ct_proof_t* seal = qihse_kv_ct_target_seal_create(receiver,
            op, op, "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
        assert(seal && qihse_kv_ct_proof_validate(receiver, op, op, seal));
        unsigned char range_digest[32];
        assert(!qihse_kv_ct_proof_validate(receiver, op, low, seal));
        assert(!qihse_kv_ct_proof_fields(receiver, low, op, seal, NULL, NULL, NULL,
                                        NULL, NULL, NULL, NULL, NULL,
                                        range_digest));
        assert(!qihse_kv_ct_proof_fields(receiver, op, low, seal, NULL, NULL, NULL,
                                        NULL, NULL, NULL, NULL, NULL,
                                        range_digest));
        assert(qihse_kv_ct_proof_fields(receiver, op, op, seal, NULL, NULL, NULL,
                                       NULL, NULL, NULL, NULL, NULL,
                                       range_digest));
        char range_hex[65];
        for (size_t i = 0u; i < 32u; i++)
            assert(snprintf(range_hex + i * 2u, 3u, "%02x", range_digest[i]) == 2);
        assert((strcmp(range_hex, argv[6]) != 0) == mismatch);
        qihse_kv_ct_proof_destroy(seal);
        qihse_kv_store_destroy(receiver);
        return 0;
    }
    assert(argc == 1);
    for (unsigned i = 0u; i < 2u; i++) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            execl(argv[0], argv[0], i ? "ordinary-wal-tail" :
                  "durable-wal-custody", (char*)NULL);
            _exit(99);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
    }
    for (unsigned durable = 0u; durable < 2u; durable++) {
        for (unsigned prefix = 1u; prefix <= 4u; prefix++) {
            char length[] = "2";
            length[0] = (char)('0' + prefix);
            pid_t child = fork();
            assert(child >= 0);
            if (!child) {
                execl(argv[0], argv[0], "disposition-tail",
                      durable ? "durable" : "ordinary", length, (char*)NULL);
                _exit(99);
            }
            int status = 0;
            assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0);
        }
    }
    for (unsigned i = 0u; i < 2u; i++) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            execl(argv[0], argv[0], i ? "lane-prebind-delete-receipt" :
                  "prebind-delete-receipt", (char*)NULL);
            _exit(99);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
    }
#ifdef QIHSE_CT_STORAGE_FLOOR_TEST
    const char* floor_variants[] = { "success", "commit", "dir-fsync", "corrupt",
        "hold-only", "hold-nonzero",
        "group-fsync", "state-publish", "cut-hold", "cut-floor", "cut-group",
        "cut-state", "marker-rollback", "marker-advance" };
    for (size_t i = 0u; i < sizeof(floor_variants) / sizeof(floor_variants[0]); i++) {
        char fixture_dir[] = "./ct_floor_XXXXXX";
        umask(0077);
        assert(mkdtemp(fixture_dir));
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            assert(setenv("QIHSE_DATA_DIR", fixture_dir, 1) == 0 &&
                   setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
            execl(argv[0], argv[0], "floor-setup", floor_variants[i], (char*)NULL);
            _exit(99);
        }
        int result = 0;
        assert(waitpid(child, &result, 0) == child && WIFEXITED(result) &&
               WEXITSTATUS(result) == ((!strcmp(floor_variants[i], "commit") ||
                   !strcmp(floor_variants[i], "dir-fsync") ||
                   !strcmp(floor_variants[i], "group-fsync") ||
                   !strcmp(floor_variants[i], "state-publish")) ? 87 : 86));
        child = fork();
        assert(child >= 0);
        if (child == 0) {
            assert(setenv("QIHSE_DATA_DIR", fixture_dir, 1) == 0 &&
                   setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
            execl(argv[0], argv[0], "floor-reopen", floor_variants[i], (char*)NULL);
            _exit(99);
        }
        assert(waitpid(child, &result, 0) == child && WIFEXITED(result) &&
               WEXITSTATUS(result) == 0);
        aimem_fixture_cleanup(fixture_dir);
    }
    /* Correctly checksummed offset, digest, high-water and format changes
     * must each deny reopening the disposable source after a crash. */
    for (unsigned which = 0u; which < 4u; ++which) {
        char fixture_dir[] = "./ct_hold_pin_XXXXXX";
        umask(0077);
        assert(mkdtemp(fixture_dir));
        pid_t child = fork();
        assert(child >= 0);
        if (!child) {
            assert(!setenv("QIHSE_DATA_DIR", fixture_dir, 1) &&
                   !setenv("QIHSE_FIPS_MODE", "disabled", 1));
            execl(argv[0], argv[0], "floor-setup", "hold-only", (char*)NULL);
            _exit(99);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 86);
        char path[512];
        assert(snprintf(path, sizeof(path), "%s/ct1-recovery-fence.bin",
                        fixture_dir) > 0);
        int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
        unsigned char marker[209];
        struct stat st;
        assert(fd >= 0 && !fstat(fd, &st) && st.st_size == (off_t)sizeof(marker) &&
               pread(fd, marker, sizeof(marker), 0) == (ssize_t)sizeof(marker) &&
               !memcmp(marker, "QCTRF002", 8u));
        size_t length = sizeof(marker);
        if (which == 2u) {
            /* Downgrade to a correctly checksummed legacy marker. CT state
             * still requires the pinned V2 extent and must refuse reopen. */
            memcpy(marker, "QCTRF001", 8u);
            length = 153u;
            assert(!ftruncate(fd, (off_t)length));
        } else marker[which == 3u ? 138u : (which ? 145u : 121u)] ^= 1u;
        assert(SHA256(marker, length - 32u, marker + length - 32u));
        assert(pwrite(fd, marker, length, 0) == (ssize_t)length &&
               !fsync(fd) && !close(fd));
        child = fork();
        assert(child >= 0);
        if (!child) {
            assert(!setenv("QIHSE_DATA_DIR", fixture_dir, 1) &&
                   !setenv("QIHSE_FIPS_MODE", "disabled", 1));
            execl(argv[0], argv[0], "floor-denied", "hold-only", (char*)NULL);
            _exit(99);
        }
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
        aimem_fixture_cleanup(fixture_dir);
    }
#endif
    char dir[] = "./ct_storage_XXXXXX";
    umask(0077);
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 8301u, QIHSE_ROLE_ANALYST,
                                                0u, 0u, "CtStorageLow1!", false);
    assert(low);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u, QIHSE_ROLE_ANALYST,
                                                     5u, 2u, "CtStorageService1!", false);
    assert(service);
    qihse_kv_store_t* s = qihse_kv_store_create_user(op);
    assert(s);
    qihse_kv_ct_transfer_status_detail_t initial_fence = {0};
    assert(qihse_kv_ct_transfer_status_detail(s, op, &initial_fence));
    assert(initial_fence.base.mode == 0u && initial_fence.base.fence_state == 0u);
    assert(!qihse_kv_ct_transfer_status_detail(s, low, &initial_fence));
    assert(!qihse_kv_ct_transfer_status_detail(s, NULL, &initial_fence));
    qihse_kv_store_set_replication_principal_id(s, 8302u);
    assert(qihse_kv_set_user(s, "commons/preexisting", "secret", 4u, 2u, op));
    assert(qihse_kv_get_user(s, "commons/preexisting", low) == NULL);
    qihse_kv_replica_snapshot_t* denied_snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(s, low, "*", &denied_snapshot) == -2);
    assert(denied_snapshot == NULL);
    qihse_user_t* high = qihse_auth_create_user(op, 8303u, QIHSE_ROLE_ANALYST,
                                                 4u, 2u, "CtStorageHigh1!", false);
    assert(high);
    qihse_kv_replica_snapshot_t* high_snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(s, high, "*", &high_snapshot) == 0);
    assert(high_snapshot);
    uint64_t high_size = 0u;
    uint64_t high_snapshot_seq = 0u;
    uint64_t expected_snapshot_seq = qihse_kv_change_seq(s);
    assert(qihse_kv_replica_snapshot_size(high_snapshot, high, &high_size));
    assert(qihse_kv_replica_snapshot_change_seq(high_snapshot, high,
                                                &high_snapshot_seq));
    assert(high_snapshot_seq == expected_snapshot_seq);
    assert(qihse_kv_set_user(s, "commons/after-snapshot", "later", 0u, 0u, op));
    uint64_t still_snapshot_seq = 0u;
    assert(qihse_kv_replica_snapshot_change_seq(high_snapshot, high,
                                                &still_snapshot_seq));
    assert(still_snapshot_seq == high_snapshot_seq &&
           qihse_kv_change_seq(s) > high_snapshot_seq);
    size_t denied_bytes = 99u;
    unsigned char denied_data[16] = {0};
    uint64_t denied_seq = 99u;
    assert(!qihse_kv_replica_snapshot_change_seq(high_snapshot, low, &denied_seq));
    assert(denied_seq == 0u);
    assert(!qihse_kv_replica_snapshot_read(high_snapshot, low, 0u,
                                            denied_data, sizeof(denied_data),
                                            &denied_bytes));
    assert(denied_bytes == 0u);
    assert(qihse_auth_modify_user(op, 8303u, NULL, NULL, -1, -1, 0, 0));
    assert(!qihse_kv_replica_snapshot_size(high_snapshot, high, &high_size));
    assert(high_size == 0u);
    denied_bytes = 99u;
    assert(!qihse_kv_replica_snapshot_read(high_snapshot, high, 0u,
                                            denied_data, sizeof(denied_data),
                                            &denied_bytes));
    assert(denied_bytes == 0u);
    qihse_kv_replica_snapshot_destroy(high_snapshot);
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-state-before-publish", 1) == 0);
    assert(!qihse_kv_ct_source_enable(s, op, "source:1", "target:1",
                                       "gen:1", NULL, 128u * 1024u * 1024u));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_store_destroy(s);
    s = qihse_kv_store_create_user(op);
    assert(s);
    char* retained = qihse_kv_get_user(s, "commons/preexisting", op);
    assert(retained && strcmp(retained, "secret") == 0);
    free(retained);
#endif
    assert(qihse_kv_ct_source_enable(s, op, "source:1", "target:1", "gen:1", NULL,
                                     128u * 1024u * 1024u));
    qihse_kv_store_set_replication_principal_id(s, 8302u);
    qihse_kv_ct_source_status_t denied_source = {0};
    assert(!qihse_kv_ct_source_status(s, low, &denied_source));
    qihse_kv_ct_source_status_t admission = {0};
    assert(qihse_kv_ct_source_status(s, op, &admission) && !admission.admitted);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], baseline[32];
    assert(!qihse_kv_ct_owner_token_get(s, low, token));
    assert(qihse_kv_ct_owner_token_get(s, op, token));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t baseline_seq = 0u;
    assert(qihse_kv_ct_source_baseline_snapshot_create(s, op, &snapshot,
                                                       &baseline_seq, baseline) == 0);
    assert(snapshot);
    assert(baseline_seq != 0u);
    assert(!qihse_kv_ct_source_reconcile(s, low, "target:1", "gen:1", baseline, 0u));
    unsigned char wrong[32] = {0};
    assert(!qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", wrong, 0u));
    assert(!qihse_kv_ct_source_reconcile_peer(s, op, low, "target:1", "gen:1", baseline, 0u));
    assert(qihse_kv_ct_source_reconcile_peer(s, op, service, "target:1", "gen:1", baseline, 0u));
    assert(qihse_kv_ct_source_status(s, op, &admission) && admission.admitted);
    qihse_kv_ct_writer_scope_t* scope = NULL;
    assert(!qihse_kv_ct_writer_scope_enter(s, low, wrong, &scope));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_set_user(s, "commons/new", "classified", 4u, 2u, op));
    assert(qihse_kv_get_user(s, "commons/new", op) == NULL); /* pending ACK */
    qihse_kv_ct_group_t* groups = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    assert(!qihse_kv_ct_source_read(s, low, "gen:1", 0u, 1u, 65536u,
                                    &groups, &count, &resume));
    assert(qihse_kv_ct_source_read(s, op, "gen:1", 0u, 1u, 65536u,
                                   &groups, &count, &resume));
    assert(count == 1u && resume == 1u && groups[0].stream_position == 1u);
    assert(groups[0].count == 1u && strcmp(groups[0].records[0].value, "classified") == 0);
    char snapshot_path[] = "./ct_baseline_XXXXXX";
    int snapshot_fd = mkstemp(snapshot_path);
    assert(snapshot_fd >= 0);
    uint64_t snapshot_size = 0u;
    assert(qihse_kv_replica_snapshot_size(snapshot, op, &snapshot_size));
    for (uint64_t off = 0u; off < snapshot_size;) {
        unsigned char chunk[4096];
        size_t got = 0u;
        assert(qihse_kv_replica_snapshot_read(snapshot, op, off, chunk,
                                              sizeof(chunk), &got));
        assert(got > 0u && write(snapshot_fd, chunk, got) == (ssize_t)got);
        off += got;
    }
    assert(fsync(snapshot_fd) == 0 && close(snapshot_fd) == 0);
    char group_path[] = "./ct_group_XXXXXX";
    int group_fd = mkstemp(group_path);
    assert(group_fd >= 0);
    FILE* group_file = fdopen(group_fd, "wb");
    assert(group_file);
    size_t group_bytes = 0u;
    assert(qihse_ct_codec_write(group_file, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                0u, 1u, &groups[0], 65536u, &group_bytes));
    assert(fclose(group_file) == 0);
    /* A periodic successor reconcile can race a newly durable source group.
     * It may confirm its older durable cursor after initial admission, but it
     * must not advance ACK or expose the pending value. */
    assert(qihse_kv_ct_source_reconcile_peer(s, op, service, "target:1", "gen:1",
                                             baseline, 0u));
    qihse_kv_ct_source_status_t stale_reconcile_status = {0};
    assert(qihse_kv_ct_source_status(s, op, &stale_reconcile_status));
    assert(stale_reconcile_status.durable_lsn == 1u &&
           stale_reconcile_status.acknowledged_lsn == 0u);
    assert(qihse_kv_get_user(s, "commons/new", op) == NULL);
    assert(!qihse_kv_ct_source_ack(s, low, "target:1", "gen:1", 1u));
    assert(!qihse_kv_ct_source_ack(s, op, "wrong", "gen:1", 1u));
    uint64_t ack_floor = qihse_kv_change_seq(s);
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "restore-highwater-commit", 1) == 0);
    assert(!qihse_kv_ct_source_ack(s, op, "target:1", "gen:1", 1u));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_ct_source_status_t failed_gc = {0};
    assert(qihse_kv_ct_source_status(s, op, &failed_gc) &&
           failed_gc.durable_lsn == 1u && failed_gc.acknowledged_lsn == 1u &&
           failed_gc.retained_bytes > 0u);
#endif
    assert(qihse_kv_ct_source_ack(s, op, "target:1", "gen:1", 1u));
    char highwater_path[512];
    assert(snprintf(highwater_path, sizeof(highwater_path),
                    "%s/restore-highwater.bin", getenv("QIHSE_DATA_DIR")) > 0);
    FILE* highwater = fopen(highwater_path, "rb");
    assert(highwater);
    unsigned char marker[5];
    uint64_t persisted_floor = 0u;
    assert(fread(marker, 1u, sizeof(marker), highwater) == sizeof(marker) &&
           memcmp(marker, "QRHW1", sizeof(marker)) == 0 &&
           fread(&persisted_floor, sizeof(persisted_floor), 1u, highwater) == 1u &&
           persisted_floor >= ack_floor && fclose(highwater) == 0);
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_ct_source_status_t post_gc = {0};
    assert(qihse_kv_ct_source_status(s, op, &post_gc) &&
           post_gc.durable_lsn == 1u && post_gc.acknowledged_lsn == 1u &&
           post_gc.retained_bytes == 0u);
    char* value = qihse_kv_get_user(s, "commons/new", op);
    assert(value && strcmp(value, "classified") == 0);
    free(value);
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    char* large = ct_large_payload();
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "ct-after-group-fsync", 1) == 0);
    assert(!qihse_kv_set_user(s, "commons/pending", large, 4u, 2u, op));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_ct_writer_scope_leave(scope);
#else
    assert(qihse_kv_set_user(s, "commons/pending", large, 4u, 2u, op));
    assert(!qihse_kv_ct_writer_scope_finish(scope, 0u, NULL)); /* lost ACK */
#endif
    qihse_kv_store_destroy(s);
    s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_source_status(s, op, &admission) && !admission.admitted);
    qihse_kv_replica_snapshot_t* reopened_baseline = NULL;
    uint64_t reopened_seq = 0u;
    unsigned char reopened_digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(s, op,
        &reopened_baseline, &reopened_seq, reopened_digest) == 0);
    assert(reopened_baseline && reopened_seq == baseline_seq &&
           memcmp(reopened_digest, baseline, 32u) == 0);
    uint64_t reopened_size = 0u;
    assert(qihse_kv_replica_snapshot_size(reopened_baseline, op,
                                          &reopened_size) && reopened_size == snapshot_size);
    qihse_kv_replica_snapshot_destroy(reopened_baseline);
    assert(!qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_get_user(s, "commons/pending", op) == NULL);
    qihse_kv_ct_group_t* recovered = NULL;
    size_t recovered_count = 0u;
    uint64_t recovered_resume = 0u;
    assert(qihse_kv_ct_source_read(s, op, "gen:1", 1u, 1u, 65536u,
                                   &recovered, &recovered_count, &recovered_resume));
    assert(recovered_count == 1u && recovered_resume == 2u &&
           strcmp(recovered[0].records[0].value, large) == 0);
    FILE* append_group = fopen(group_path, "ab");
    assert(append_group);
    assert(qihse_ct_codec_write(append_group, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                                0u, 1u, &recovered[0], 65536u, &group_bytes));
    assert(fclose(append_group) == 0);
    qihse_kv_ct_groups_free(recovered, recovered_count);
    assert(qihse_kv_ct_source_ack(s, op, "target:1", "gen:1", 2u));
    assert(qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", baseline, 2u));
    value = qihse_kv_get_user(s, "commons/pending", op);
    assert(value && strcmp(value, large) == 0);
    free(value);
    free(large);
    uint64_t cut = 999u;
    assert(qihse_kv_ct_fence_range(s, op, "move:1", 0u, 16383u, token, &cut));
    assert(cut == 2u);
    qihse_kv_ct_transfer_status_t fence = {0};
    assert(!qihse_kv_ct_transfer_status(s, low, &fence));
    assert(fence.transfer_id[0] == '\0');
    assert(qihse_kv_ct_transfer_status(s, op, &fence));
    assert(fence.fence_state == 1u && fence.cut_position == cut &&
           strcmp(fence.transfer_id, "move:1") == 0);
    qihse_kv_ct_range_snapshot_t* range_image = NULL;
    uint64_t export_cut = 0u, export_size = 0u;
    unsigned char export_sha[32];
    assert(qihse_kv_ct_range_export(s, op, low, "move:1", "target:1",
        "gen:1", 0u, 16383u, token, &range_image, &export_cut,
        export_sha) == -2 && !range_image);
    assert(qihse_kv_ct_range_export(s, op, op, "move:1", "target:1",
        "gen:1", 0u, 16383u, token, &range_image, &export_cut,
        export_sha) == 0 && range_image && export_cut == cut);
    assert(!qihse_kv_ct_range_snapshot_size(range_image, low, &export_size));
    assert(qihse_kv_ct_range_snapshot_size(range_image, op, &export_size) &&
           export_size > 0u);
    qihse_kv_ct_range_snapshot_destroy(range_image);
    assert(!qihse_kv_ct_source_transfer_proof_create(s, low, op, "move:1",
        "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
    assert(!qihse_kv_ct_source_transfer_proof_create(s, op, low, "move:1",
        "source:1", "target:1", "gen:1", 0u, 16383u, 2u));
    qihse_kv_ct_proof_t* source_seal = qihse_kv_ct_source_transfer_proof_create(
        s, op, op, "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
    assert(source_seal && qihse_kv_ct_proof_validate(s, op, op, source_seal));
    unsigned char range_digest[32];
    assert(!qihse_kv_ct_proof_validate(s, op, low, source_seal));
    assert(!qihse_kv_ct_proof_fields(s, op, low, source_seal, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL,
                                   range_digest));
    assert(qihse_kv_ct_proof_fields(s, op, op, source_seal, NULL, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL,
                                   range_digest));
    qihse_kv_ct_proof_destroy(source_seal);
    qihse_user_t* data = qihse_auth_create_user(op, 8390u,
        QIHSE_ROLE_ANALYST, 4u, 2u, "CtProofData1!", false);
    assert(data);
    source_seal = qihse_kv_ct_source_transfer_proof_create(s, op, data,
        "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
    assert(source_seal && qihse_kv_ct_proof_validate(s, op, data, source_seal));
    assert(qihse_auth_modify_user(op, 8390u, NULL, NULL, -1, -1, 0, 0));
    assert(!qihse_kv_ct_proof_validate(s, op, data, source_seal));
    assert(!qihse_kv_ct_proof_fields(s, op, data, source_seal,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, range_digest));
    qihse_kv_ct_proof_destroy(source_seal);
    assert(qihse_auth_modify_user(op, 8390u, NULL, NULL, -1, -1, 4, 2));
    source_seal = qihse_kv_ct_source_transfer_proof_create(s, op, data,
        "move:1", "source:1", "target:1", "gen:1", 0u, 16383u, 2u);
    assert(source_seal);
    assert(qihse_auth_destroy_user(op, 8390u));
    assert(!qihse_kv_ct_proof_validate(s, op, data, source_seal));
    qihse_kv_ct_proof_destroy(source_seal);
    assert(!qihse_kv_ct_fence_finish(s, op, "move:1", true, token));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(!qihse_kv_set_user(s, "commons/new", "denied", 4u, 2u, op));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_replica_snapshot_destroy(snapshot);
    qihse_kv_store_destroy(s);
    s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_transfer_status(s, op, &fence) &&
           fence.fence_state == 1u &&
           strcmp(fence.transfer_id, "move:1") == 0);
    assert(!qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", baseline, 2u));
    assert(qihse_kv_ct_fence_range(s, op, "move:1", 0u, 16383u,
                                   token, &cut) && cut == 2u);
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(!qihse_kv_set_user(s, "commons/new", "still-denied", 4u, 2u, op));
    assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
    qihse_kv_store_destroy(s);
    char receiver_dir[] = "./ct_receiver_XXXXXX";
    assert(mkdtemp(receiver_dir));
    char seq_text[32], digest_hex[65], range_hex[65];
    assert(snprintf(seq_text, sizeof(seq_text), "%llu",
                    (unsigned long long)baseline_seq) > 0);
    for (size_t i = 0u; i < 32u; i++)
        assert(snprintf(digest_hex + i * 2u, 3u, "%02x", baseline[i]) == 2);
    for (size_t i = 0u; i < 32u; i++)
        assert(snprintf(range_hex + i * 2u, 3u, "%02x", range_digest[i]) == 2);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", receiver_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char history_dir[] = "./ct_receiver_history_XXXXXX";
    assert(mkdtemp(history_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", history_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-history", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char quote_dir[] = "./ct_target_quote_XXXXXX";
    assert(mkdtemp(quote_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", quote_dir, 1) == 0);
        execl(argv[0], argv[0], "target-quote", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char quote_fence_dir[] = "./ct_target_quote_fence_XXXXXX";
    assert(mkdtemp(quote_fence_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", quote_fence_dir, 1) == 0);
        execl(argv[0], argv[0], "target-quote-fence", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char history_set_dir[] = "./ct_receiver_history_set_XXXXXX";
    assert(mkdtemp(history_set_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", history_set_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-history-set", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char prebind_dir[] = "./ct_prebind_stale_XXXXXX";
    assert(mkdtemp(prebind_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", prebind_dir, 1) == 0);
        execl(argv[0], argv[0], "prebind-stale", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char buffered_dir[] = "./ct_prebind_buffered_XXXXXX";
    assert(mkdtemp(buffered_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", buffered_dir, 1) == 0);
        execl(argv[0], argv[0], "prebind-buffered", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char source_stale_dir[] = "./ct_source_stale_XXXXXX";
    assert(mkdtemp(source_stale_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", source_stale_dir, 1) == 0);
        execl(argv[0], argv[0], "source-stale", (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char lane_stale_dir[] = "./ct_lane_stale_XXXXXX";
    assert(mkdtemp(lane_stale_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", lane_stale_dir, 1) == 0);
        execl(argv[0], argv[0], "lane-stale", (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char fence_dir[] = "./ct_recovery_fence_XXXXXX";
    assert(mkdtemp(fence_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", fence_dir, 1) == 0);
        execl(argv[0], argv[0], "recovery-fence", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", fence_dir, 1) == 0);
        execl(argv[0], argv[0], "recovery-fence-crash", (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 86);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", fence_dir, 1) == 0);
        execl(argv[0], argv[0], "recovery-fence-reopen", (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char custody_dir[] = "./ct_custody_replay_XXXXXX";
    assert(mkdtemp(custody_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", custody_dir, 1) == 0);
        execl(argv[0], argv[0], "custody-replay", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    const char* custody_cases[] = {"custody-replay-separated",
        "custody-replay-false-position", "custody-replay-later-set",
        "custody-replay-later-tombstone",
        "custody-system-policy", "custody-system-tenant",
        "custody-system-header", "custody-system-corrupt", "custody-system-sci",
        "custody-system-frame-tenant"};
    for (size_t i = 0u; i < sizeof(custody_cases) / sizeof(custody_cases[0]); i++) {
        char separated_dir[] = "./ct_custody_history_XXXXXX";
        assert(mkdtemp(separated_dir));
        child = fork();
        assert(child >= 0);
        if (child == 0) {
            assert(setenv("QIHSE_DATA_DIR", separated_dir, 1) == 0);
            execl(argv[0], argv[0], custody_cases[i], snapshot_path, group_path,
                seq_text, digest_hex, range_hex, (char*)NULL);
            _exit(99);
        }
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
        assert(access(separated_dir, F_OK) == -1);
    }
    const char* system_cases[] = {"custody-system", "custody-system-low"};
    for (size_t i = 0u; i < sizeof(system_cases) / sizeof(system_cases[0]); ++i) {
        char system_dir[] = "./ct_custody_system_XXXXXX";
        assert(mkdtemp(system_dir));
        child = fork();
        assert(child >= 0);
        if (child == 0) {
            assert(setenv("QIHSE_DATA_DIR", system_dir, 1) == 0);
            execl(argv[0], argv[0], system_cases[i], snapshot_path, group_path,
                seq_text, digest_hex, range_hex, (char*)NULL);
            _exit(99);
        }
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0);
        assert(access(system_dir, F_OK) == -1);
    }
    char mismatch_dir[] = "./ct_receiver_mismatch_XXXXXX";
    assert(mkdtemp(mismatch_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", mismatch_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-mismatch", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char expired_dir[] = "./ct_receiver_expired_XXXXXX";
    assert(mkdtemp(expired_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", expired_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-expired", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char retained_dir[] = "./ct_source_retained_XXXXXX";
    assert(mkdtemp(retained_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", retained_dir, 1) == 0);
        execl(argv[0], argv[0], "retained-frame", (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char highwater_dir[] = "./ct_source_highwater_XXXXXX";
    assert(mkdtemp(highwater_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", highwater_dir, 1) == 0);
        execl(argv[0], argv[0], "source-highwater", (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char stale_dir[] = "./ct_receiver_stale_XXXXXX";
    assert(mkdtemp(stale_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", stale_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-stale", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    char stale_expired_dir[] = "./ct_receiver_stale_expired_XXXXXX";
    assert(mkdtemp(stale_expired_dir));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(setenv("QIHSE_DATA_DIR", stale_expired_dir, 1) == 0);
        execl(argv[0], argv[0], "receiver-stale-expired", snapshot_path, group_path,
              seq_text, digest_hex, range_hex, (char*)NULL);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
           WEXITSTATUS(status) == 0);
    s = qihse_kv_store_create_user(op);
    assert(s);
    assert(qihse_kv_ct_fence_finish(s, op, "move:1", false, token));
    assert(qihse_kv_ct_source_reconcile(s, op, "target:1", "gen:1", baseline, 2u));
    assert(qihse_kv_ct_writer_scope_enter(s, op, token, &scope));
    assert(qihse_kv_set_user(s, "commons/new", "after-abort", 4u, 2u, op));
    assert(!qihse_kv_ct_writer_scope_finish(scope, 0u, NULL));
    qihse_kv_store_destroy(s);
    char wal_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log", dir) > 0);
    int wal_fd = open(wal_path, O_WRONLY | O_APPEND | O_CLOEXEC);
    assert(wal_fd >= 0);
    assert(write(wal_fd, "QKV3", 4u) == 4 && fsync(wal_fd) == 0);
    assert(close(wal_fd) == 0);
    assert(qihse_kv_store_create_user(op) == NULL); /* legacy WAL bypass denied */
    qihse_kv_ct_groups_free(groups, count);
    assert(unlink(snapshot_path) == 0);
    assert(unlink(group_path) == 0);
    aimem_fixture_cleanup(receiver_dir);
    aimem_fixture_cleanup(history_dir);
    aimem_fixture_cleanup(quote_dir);
    aimem_fixture_cleanup(quote_fence_dir);
    aimem_fixture_cleanup(history_set_dir);
    aimem_fixture_cleanup(fence_dir);
    assert(access(custody_dir, F_OK) == -1);
    aimem_fixture_cleanup(prebind_dir);
    aimem_fixture_cleanup(buffered_dir);
    aimem_fixture_cleanup(source_stale_dir);
    aimem_fixture_cleanup(lane_stale_dir);
    aimem_fixture_cleanup(mismatch_dir);
    aimem_fixture_cleanup(expired_dir);
    aimem_fixture_cleanup(highwater_dir);
    aimem_fixture_cleanup(retained_dir);
    aimem_fixture_cleanup(stale_dir);
    aimem_fixture_cleanup(dir);
    puts("ct storage: PASS");
    return 0;
}
