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
#include "qihse_audit.h"
#include "qihse_ct_codec.h"
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

int main(int argc, char** argv) {
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
    if (argc == 5 && strcmp(argv[1], "recovery-fence-held") == 0) {
        assert(qihse_auth_init());
        assert(qihse_auth_bootstrap_operator("CtStorageOperator1!"));
        qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtStorageOperator1!");
        assert(op);
        qihse_user_t* service = qihse_auth_create_user(op, 8302u,
            QIHSE_ROLE_ANALYST, 5u, 2u, "CtStorageService1!", false);
        assert(service);
        qihse_kv_store_t* existing = qihse_kv_store_create_user(op);
        assert(existing);
        qihse_kv_store_set_replication_principal_id(existing, 8302u);
        FILE* f = fopen(argv[2], "rb");
        assert(f);
        qihse_kv_ct_group_t group = {0}, next = {0};
        uint8_t mode = 0u;
        size_t bytes = 0u;
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
            65536u, &group, &mode, &bytes) == 1);
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
            65536u, &next, &mode, &bytes) == 1);
        fclose(f);
        int ready = atoi(argv[3]), proceed = atoi(argv[4]);
        int dirfd = open(getenv("QIHSE_DATA_DIR"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        assert(dirfd >= 0 && flock(dirfd, LOCK_EX | LOCK_NB) == 0);
        assert(write(ready, "l", 1u) == 1);
        char signal;
        assert(read(proceed, &signal, 1u) == 1 && signal == 'u');
        assert(flock(dirfd, LOCK_UN) == 0 && close(dirfd) == 0);
        assert(write(ready, "r", 1u) == 1);
        assert(read(proceed, &signal, 1u) == 1 && signal == 'g');
        uint64_t denied_cursor = 99u, cut = 99u;
        unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
        assert(qihse_kv_ct_owner_token_get(existing, op, token));
        assert(!qihse_kv_ct_receiver_apply(existing, service, &next,
                                            &denied_cursor) && denied_cursor == 0u);
        assert(!qihse_kv_ct_fence_range(existing, op, "transfer:held", 1u, 1u,
                                         token, &cut) && cut == 0u);
        assert(!qihse_kv_replica_cursor_advance(existing, "source:1", "*", 2u, op));
        assert(!qihse_kv_sync_store(existing));
        qihse_kv_sweep_expired(existing);
        qihse_audit_shutdown();
        _exit(0); /* crash with an already-open store handle */
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
                      strcmp(argv[1], "recovery-fence") == 0)) {
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
            qihse_kv_store_t* peer = qihse_kv_store_create_user(op);
            assert(receiver && peer); /* both handles predate the intent */
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            qihse_kv_store_set_replication_principal_id(peer, 8302u);
            /* Audit grants one writer per directory: hand off its lock while
             * the child independently opens the same receiver directory. */
            qihse_audit_shutdown();
            int ready[2], proceed[2];
            assert(pipe(ready) == 0 && pipe(proceed) == 0);
            pid_t child = fork();
            assert(child >= 0);
            if (child == 0) {
                close(ready[0]); close(proceed[1]);
                char ready_text[24], proceed_text[24];
                assert(snprintf(ready_text, sizeof(ready_text), "%d", ready[1]) > 0);
                assert(snprintf(proceed_text, sizeof(proceed_text), "%d", proceed[0]) > 0);
                execl(argv[0], argv[0], "recovery-fence-held", argv[3],
                      ready_text, proceed_text, (char*)NULL);
                _exit(99);
            }
            close(ready[1]); close(proceed[0]);
            char signal;
            assert(read(ready[0], &signal, 1u) == 1 && signal == 'l');
            assert(qihse_kv_store_create_user(op) == NULL); /* open cannot replay under peer lock */
            assert(!qihse_kv_ct_receiver_recovery_fence_install(receiver, op,
                "gen:1", baseline_seq, digest, 1u)); /* bounded lock refusal */
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            uint64_t blocked_cut = 99u;
            assert(!qihse_kv_ct_fence_range(receiver, op, "transfer:held", 1u, 1u,
                                             token, &blocked_cut) && blocked_cut == 0u);
            assert(!qihse_kv_replica_cursor_advance(receiver,
                "source:1", "*", 2u, op));
            assert(write(proceed[1], "u", 1u) == 1);
            assert(read(ready[0], &signal, 1u) == 1 && signal == 'r');
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
            assert(write(proceed[1], "g", 1u) == 1);
            close(proceed[1]); close(ready[0]);
            int child_status = 0;
            assert(waitpid(child, &child_status, 0) == child &&
                   WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
            qihse_audit_init();
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
            strcmp(argv[1], "receiver-history-set") == 0) {
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
            char wal_path[512];
            assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log",
                            getenv("QIHSE_DATA_DIR")) > 0);
            int wal_fd = open(wal_path, O_RDWR | O_CLOEXEC);
            assert(wal_fd >= 0);
            struct stat wal_st;
            assert(fstat(wal_fd, &wal_st) == 0 && wal_st.st_size > 64);
            unsigned char saved = 0u, flipped;
            assert(pread(wal_fd, &saved, 1u, 64u) == 1);
            flipped = saved ^ 1u;
            assert(pwrite(wal_fd, &flipped, 1u, 64u) == 1); /* checksum */
            DENIED(op);
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
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            assert(qihse_kv_sync_store(receiver));
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            qihse_kv_ct_receiver_status_t status = {0};
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 1u && status.baseline_sealed);
            assert(qihse_kv_get_user(receiver, group.records[0].key, op) == NULL);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
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
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 33u);
            qihse_kv_store_destroy(receiver);
            receiver = qihse_kv_store_create_user(op);
            assert(receiver);
            qihse_kv_store_set_replication_principal_id(receiver, 8302u);
            assert(qihse_kv_ct_receiver_status(receiver, service, &status) &&
                   status.durable_cursor == 33u && status.baseline_sealed);
            assert(!qihse_kv_ct_receiver_apply(receiver, service, &group2, &cursor) &&
                   cursor == 0u);
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
            execl(argv[0], argv[0], i ? "lane-prebind-delete-receipt" :
                  "prebind-delete-receipt", (char*)NULL);
            _exit(99);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
    }
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
    aimem_fixture_cleanup(history_set_dir);
    aimem_fixture_cleanup(fence_dir);
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
