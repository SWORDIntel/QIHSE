/* test_ct1_target_disposition.c - protected disposition writer.
 * A disposable CT1 receiver with an installed target epoch fence receives
 * the archive-before-commit SUPPRESSED_ORIGINAL disposition for an exact
 * 1644-byte SOURCE frame. The commit advances the cursor without applying
 * the old SET, survives cold reopen with the archive mandatory, retries
 * idempotently, rolls forward after a torn pre-commit crash cut, and every
 * mismatched tuple is refused before anything is touched.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_ct_codec.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_kv_store.h"

#define GEN       "0123456789abcdef0123456789abcdef"
#define SOURCE_ID "hold-primary"
#define TARGET_ID "hold-successor"
#define FULL_KEY  "commons/ct1.hold-pending"
#define ROW_KEY   "ct1.hold-pending"
#define CURSOR    7u
#define PENDING   8u

static int remove_entry(const char* path, const struct stat* st, int flag,
    struct FTW* buffer) {
    (void)st; (void)flag; (void)buffer;
    return remove(path);
}

/* Mint the sealed baseline file in its own process. */
static int mint_baseline_process(const char* src_dir) {
    char data_dir[PATH_MAX];
    assert(snprintf(data_dir, PATH_MAX, "%s/data", src_dir) > 0);
    assert(mkdir(src_dir, 0700) == 0 && mkdir(data_dir, 0700) == 0 &&
        setenv("QIHSE_DATA_DIR", data_dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DispositionOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "DispositionOperator1!");
    assert(op);
    qihse_kv_store_t* source = qihse_kv_store_create_user(op);
    assert(source && qihse_kv_set_user(source, "ct1.preexisting",
        "baseline-history", 2u, 1u, op) && qihse_kv_sync_store(source));
    assert(qihse_kv_ct_source_enable(source, op, SOURCE_ID, TARGET_ID, GEN,
        NULL, 128u * 1024u * 1024u));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t seq = 0u;
    unsigned char digest[32];
    assert(qihse_kv_ct_source_baseline_snapshot_create(source, op, &snapshot,
        &seq, digest) == 0 && snapshot && seq > 0u);
    qihse_kv_replica_snapshot_destroy(snapshot);
    qihse_kv_store_destroy(source);
    char baseline_path[PATH_MAX], meta_path[PATH_MAX];
    assert(snprintf(baseline_path, PATH_MAX, "%s/ct-baseline.qfs",
        data_dir) > 0 && snprintf(meta_path, PATH_MAX, "%s/baseline.meta",
        data_dir) > 0);
    int fd = open(baseline_path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && st.st_size > 0);
    close(fd);
    unsigned char meta[40];
    for (unsigned i = 0u; i < 8u; ++i)
        meta[i] = (unsigned char)(seq >> (8u * i));
    memcpy(meta + 8u, digest, 32u);
    fd = open(meta_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, meta, sizeof(meta)) == (ssize_t)sizeof(meta) &&
        fsync(fd) == 0 && close(fd) == 0);
    qihse_audit_shutdown();
    return 0;
}

/* Receiver at cursor CURSOR: SET at 1, retained tombstone at 3. */
static qihse_kv_store_t* build_receiver(const char* self, const char* dir,
    qihse_user_t* op, qihse_user_t* service, uint64_t* out_seq,
    unsigned char out_digest[32], uint64_t* out_high_water,
    uint64_t* out_tombstone_seq) {
    char src_dir[PATH_MAX];
    assert(snprintf(src_dir, PATH_MAX, "%s/src", dir) > 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl(self, self, "mint", src_dir, (char*)NULL);
        _exit(127);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    char baseline_path[PATH_MAX], meta_path[PATH_MAX];
    assert(snprintf(baseline_path, PATH_MAX, "%s/src/data/ct-baseline.qfs",
        dir) > 0 && snprintf(meta_path, PATH_MAX, "%s/src/data/baseline.meta",
        dir) > 0);
    unsigned char meta[40];
    int fd = open(meta_path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0 && read(fd, meta, sizeof(meta)) == (ssize_t)sizeof(meta));
    close(fd);
    *out_seq = 0u;
    for (unsigned i = 0u; i < 8u; ++i)
        *out_seq |= (uint64_t)meta[i] << (8u * i);
    memcpy(out_digest, meta + 8u, 32u);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, 8302u);
    assert(qihse_kv_ct_receiver_bind(store, op, SOURCE_ID, TARGET_ID, GEN,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, *out_seq, NULL));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_owner_token_get(store, op, token) &&
        qihse_kv_ct_receiver_install_baseline(store, op, service, SOURCE_ID,
            GEN, baseline_path, *out_seq, out_digest, token));
    uint64_t cursor = 0u;
    for (unsigned pos = 1u; pos <= CURSOR; ++pos) {
        bool tomb = pos == 3u;
        const char* key = (pos == 1u || tomb) ? FULL_KEY : "commons/unrelated";
        qihse_kv_ct_record_t row = {
            .key = (char*)key, .value = tomb ? NULL : "fixture-value",
            .change_seq = *out_seq + pos, .actor_id = 0u,
            .actor_tenant_id = 0u, .resource_tenant_id = 0u,
            .classification = 4u, .sci_compartment = 2u,
            .actor_kind = QIHSE_KV_CT_ACTOR_USER, .tombstone = tomb};
        qihse_kv_ct_group_t group = {
            .stream_position = pos, .first_seq = row.change_seq,
            .last_seq = row.change_seq, .records = &row, .count = 1u};
        strcpy(group.source_id, SOURCE_ID);
        strcpy(group.generation, GEN);
        assert(qihse_kv_ct_receiver_apply(store, service, &group, &cursor) &&
            cursor == pos);
        if (tomb) *out_tombstone_seq = row.change_seq;
    }
    *out_high_water = qihse_kv_change_seq(store);
    return store;
}

/* Exact 1644-byte SOURCE frame for the pending position via the codec. */
static void build_source_frame(qihse_user_t* op, uint64_t seq,
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES]) {
    char* padded = malloc(2000);
    assert(padded);
    memset(padded, 'x', 1999);
    padded[1999] = 0;
    padded[1] = 0;
    qihse_kv_ct_record_t row = {
        .key = (char*)FULL_KEY, .value = padded, .change_seq = seq + 1u,
        .actor_id = 0u, .actor_tenant_id = 0u, .resource_tenant_id = 0u,
        .classification = 4u, .sci_compartment = 2u,
        .actor_kind = QIHSE_KV_CT_ACTOR_USER};
    qihse_kv_ct_group_t group = {
        .stream_position = PENDING, .first_seq = row.change_seq,
        .last_seq = row.change_seq, .records = &row, .count = 1u};
    strcpy(group.source_id, SOURCE_ID);
    strcpy(group.generation, GEN);
    size_t size = 0u;
    assert(qihse_ct_codec_encoded_size(op, QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
        QIHSE_CT_CODEC_MODE_SOURCE, &group, 65536u, &size));
    size_t payload = QIHSE_CT1_RECOVERY_FRAME_BYTES - size + 1u;
    assert(payload > 1u && payload < 1999u);
    padded[1] = 'x';
    padded[payload] = 0;
    FILE* tmp = tmpfile();
    size_t written = 0u;
    assert(tmp && qihse_ct_codec_write(tmp, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, QIHSE_CT_CODEC_MODE_SOURCE, &group, 65536u, &written) &&
        written == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        fseek(tmp, 0, SEEK_SET) == 0 &&
        fread(frame, 1u, QIHSE_CT1_RECOVERY_FRAME_BYTES, tmp) ==
            QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        frame[9] == QIHSE_KV_CT_TENANT_SYSTEM_ALL);
    fclose(tmp);
    free(padded);
}

static void custody_roster(qihse_ct1_recovery_file_t* files,
    const char* const* names, size_t count) {
    for (size_t i = 0u; i < count; ++i) {
        files[i].kind = strstr(names[i], "baseline") ?
            QIHSE_CT1_FILE_BASELINE :
            strstr(names[i], "ct-state") ? QIHSE_CT1_FILE_CT_STATE :
            strstr(names[i], "restore") ? QIHSE_CT1_FILE_RESTORE_HIGHWATER :
            strstr(names[i], "journal.lock") ? QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK :
            strstr(names[i], "journal") ? QIHSE_CT1_FILE_SLOT_JOURNAL :
            strstr(names[i], "sstable") ? QIHSE_CT1_FILE_SSTABLE :
            QIHSE_CT1_FILE_WAL;
        strcpy(files[i].filename, names[i]);
        if (files[i].kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK) {
            files[i].size = 0u;
            assert(SHA256((const unsigned char*)"", 0u, files[i].sha256));
        } else {
            files[i].size = 64u + i * 16u;
            memset(files[i].sha256, (int)(i + 1u), 32u);
        }
    }
}

static void build_manifest(qihse_ct1_recovery_manifest_t* m, uint64_t seq,
    const unsigned char digest[32], uint64_t high_water,
    uint64_t tombstone_seq, const unsigned char frame_sha[32],
    unsigned char manifest_sha[32]) {
    memset(m, 0, sizeof(*m));
    strcpy(m->issuer_qkp_id, "operator");
    strcpy(m->source_qkp_id, SOURCE_ID);
    strcpy(m->target_qkp_id, TARGET_ID);
    strcpy(m->source_store_id, SOURCE_ID);
    strcpy(m->target_store_id, TARGET_ID);
    strcpy(m->generation, GEN);
    strcpy(m->replication_principal_id, "8302");
    strcpy(m->row_key, ROW_KEY);
    strcpy(m->source_peer_qkp_id, TARGET_ID);
    strcpy(m->target_peer_qkp_id, SOURCE_ID);
    memset(m->issuer_operator_pin, 1, 32);
    memset(m->source_peer_pin, 2, 32);
    memset(m->target_peer_pin, 3, 32);
    memcpy(m->frame_sha256, frame_sha, 32);
    memcpy(m->baseline_sha256, digest, 32);
    memset(m->nonce, 6, 32);
    static const char* const src[] = {"ct-baseline.qfs", "ct-state.bin",
        "restore-highwater.bin", "slot-ownership.journal",
        "slot-ownership.journal.lock", "sstable_11321.db",
        "sstable_11322.db", "wal.log"};
    static const char* const dst[] = {"ct-state.bin",
        "restore-highwater.bin", "slot-ownership.journal",
        "slot-ownership.journal.lock", "sstable_11321.db",
        "sstable_11322.db", "wal.log"};
    custody_roster(m->source_files, src, 8u);
    custody_roster(m->target_files, dst, 7u);
    m->epoch = 9u;
    m->issued_ms = 1000u;
    m->expires_ms = 901000u;
    m->frame_offset = 400u;
    m->frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    m->frame_position = PENDING;
    m->target_cursor = CURSOR;
    m->target_high_water = high_water;
    m->source_high_water = seq + 1u;
    m->row_change_seq = seq + 1u;
    m->tombstone_position = 3u;
    m->tombstone_row_seq = tombstone_seq;
    m->baseline_row_seq = seq;
    m->row_tenant_id = 0u;
    m->principal_tenant_id = 0u;
    m->classification = 4u;
    m->sci = 2u;
    m->principal_classification = 4u;
    m->principal_sci = 2u;
    m->operation = QIHSE_CT1_RECOVERY_VERIFY;
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    assert(qihse_ct1_recovery_encode(m, false, false, wire) &&
        SHA256(wire, sizeof(wire), manifest_sha));
}

static void install_fence(qihse_kv_store_t* store, qihse_user_t* op,
    qihse_user_t* service, uint64_t seq, const unsigned char digest[32],
    uint64_t high_water, uint64_t tombstone_seq,
    const unsigned char frame_sha[32], const unsigned char manifest_sha[32]) {
    qihse_kv_ct_target_epoch_fence_request_t request;
    memset(&request, 0, sizeof(request));
    request.version = QIHSE_KV_CT_TARGET_EPOCH_FENCE_V1;
    request.size = sizeof(request);
    request.key = FULL_KEY;
    strcpy(request.source_id, SOURCE_ID);
    strcpy(request.target_id, TARGET_ID);
    strcpy(request.generation, GEN);
    memcpy(request.baseline_digest, digest, 32u);
    memcpy(request.manifest_sha256, manifest_sha, 32u);
    memcpy(request.frame_sha256, frame_sha, 32u);
    request.baseline_row_seq = seq;
    request.frame_length = QIHSE_CT1_RECOVERY_FRAME_BYTES;
    request.pending_position = PENDING;
    request.durable_cursor = CURSOR;
    request.target_high_water = high_water;
    request.tombstone_row_seq = tombstone_seq;
    request.tombstone_position = 3u;
    request.resource_tenant_id = 0u;
    request.classification = 4u;
    request.sci_compartment = 2u;
    uint64_t epoch = 0u;
    assert(qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
        service, &request, &epoch) && epoch == 1u);
}

static void expect_archive(const char* dir, int mode) {
    char path[PATH_MAX];
    struct stat st;
    assert(snprintf(path, PATH_MAX,
        "%s/dispositions/%s/%u.frame", dir, GEN, PENDING) > 0);
    if (mode == 0) { /* absent */
        assert(stat(path, &st) != 0 && errno == ENOENT);
        return;
    }
    assert(stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_mode == (S_IFREG | 0600) && st.st_nlink == 1u &&
        st.st_size == (off_t)(161u + QIHSE_CT1_RECOVERY_FRAME_BYTES + 32u));
    if (mode == 2) { /* flip one archive byte */
        int fd = open(path, O_RDWR | O_CLOEXEC);
        unsigned char byte;
        assert(fd >= 0 && pread(fd, &byte, 1u, 40u) == 1);
        byte ^= 1u;
        assert(pwrite(fd, &byte, 1u, 40u) == 1 && fsync(fd) == 0 &&
            close(fd) == 0);
    } else if (mode == 3) {
        assert(unlink(path) == 0);
    }
}

static int run_case(const char* self, const char* case_id) {
    char root[] = "build/ct1-target-disposition-XXXXXX";
    assert(mkdtemp(root));
    char dir[PATH_MAX];
    assert(snprintf(dir, PATH_MAX, "%s/rx", root) > 0 &&
        mkdir(dir, 0700) == 0 &&
        setenv("QIHSE_DATA_DIR", dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DispositionOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "DispositionOperator1!");
    assert(op);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX, "DispositionService1!",
        false);
    assert(service);
    uint64_t seq = 0u, high_water = 0u, tombstone_seq = 0u;
    unsigned char digest[32], frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    unsigned char frame_sha[32], manifest_sha[32];
    qihse_ct1_recovery_manifest_t m;
    qihse_kv_store_t* store = build_receiver(self, dir, op, service, &seq,
        digest, &high_water, &tombstone_seq);
    build_source_frame(op, seq, frame);
    assert(SHA256(frame, sizeof(frame), frame_sha));
    build_manifest(&m, seq, digest, high_water, tombstone_seq, frame_sha,
        manifest_sha);
    qihse_kv_ct_receiver_status_t status = {0};

    if (strcmp(case_id, "no-fence") == 0) {
        assert(!qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == CURSOR);
        expect_archive(dir, 0);
    } else if (strcmp(case_id, "wrong-frame") == 0) {
        install_fence(store, op, service, seq, digest, high_water,
            tombstone_seq, frame_sha, manifest_sha);
        unsigned char wrong[QIHSE_CT1_RECOVERY_FRAME_BYTES];
        memcpy(wrong, frame, sizeof(wrong));
        wrong[100] ^= 1u; /* sha no longer matches the pinned manifest */
        assert(!qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, wrong, sizeof(wrong)));
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == CURSOR);
        expect_archive(dir, 0);
    } else if (strcmp(case_id, "wrong-highwater") == 0) {
        install_fence(store, op, service, seq, digest, high_water,
            tombstone_seq, frame_sha, manifest_sha);
        m.target_high_water = high_water + 1u;
        assert(!qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
        expect_archive(dir, 0);
    } else if (strcmp(case_id, "crash-cut") == 0) {
        install_fence(store, op, service, seq, digest, high_water,
            tombstone_seq, frame_sha, manifest_sha);
        assert(setenv("QIHSE_AIMEM_FAIL_AT", "disposition-after-archive",
            1) == 0);
        assert(!qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
        expect_archive(dir, 1); /* torn archive intact */
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == CURSOR);
        qihse_kv_store_destroy(store);
        assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        /* Cold reopen at the fence cursor stays admissible and fenced. */
        store = qihse_kv_store_create_user(op);
        assert(store);
        qihse_kv_store_set_replication_principal_id(store, 8302u);
        assert(!qihse_kv_set_user(store, "commons/unrelated", "x",
            4u, 2u, op));
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == CURSOR);
        /* The retry rolls the same transaction forward idempotently. */
        assert(qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == PENDING);
        qihse_kv_store_destroy(store);
        store = qihse_kv_store_create_user(op);
        assert(store);
        qihse_kv_store_set_replication_principal_id(store, 8302u);
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == PENDING);
    } else if (strcmp(case_id, "positive") == 0) {
        install_fence(store, op, service, seq, digest, high_water,
            tombstone_seq, frame_sha, manifest_sha);
        assert(qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
        assert(qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == PENDING);
        assert(qihse_kv_get_user(store, FULL_KEY, op) == NULL);
        expect_archive(dir, 1);
        qihse_kv_store_destroy(store);
        /* Cold reopen replays the custody unit and requires the archive. */
        store = qihse_kv_store_create_user(op);
        assert(store);
        qihse_kv_store_set_replication_principal_id(store, 8302u);
        assert(!qihse_kv_set_user(store, "commons/unrelated", "x",
            4u, 2u, op) && qihse_kv_get_user(store, FULL_KEY, op) == NULL &&
            qihse_kv_ct_receiver_status(store, service, &status) &&
            status.durable_cursor == PENDING);
        /* Idempotent re-commit on the reopened handle. */
        assert(qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
    } else if (strncmp(case_id, "harm:", 5u) == 0) {
        install_fence(store, op, service, seq, digest, high_water,
            tombstone_seq, frame_sha, manifest_sha);
        assert(qihse_kv_ct_target_suppression_commit_pinned_v1(store, op,
            service, &m, frame, sizeof(frame)));
        qihse_kv_store_destroy(store);
        store = NULL;
        expect_archive(dir, strcmp(case_id + 5u, "tamper") == 0 ? 2 :
            strcmp(case_id + 5u, "delete") == 0 ? 3 : 1);
        assert(qihse_kv_store_create_user(op) == NULL); /* fail closed */
    } else assert(!"unknown case");

    if (store) qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    static const char* const cases[] = {
        "no-fence", "wrong-frame", "wrong-highwater", "crash-cut",
        "positive", "harm:tamper", "harm:delete"};
    if (argc == 3 && strcmp(argv[1], "mint") == 0)
        return mint_baseline_process(argv[2]);
    if (argc == 3 && strcmp(argv[1], "case") == 0)
        return run_case(argv[0], argv[2]);
    assert(argc == 1);
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            execl(argv[0], argv[0], "case", cases[i], (char*)NULL);
            _exit(127);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0);
        printf("  case ok: %s\n", cases[i]);
    }
    puts("CT1 target disposition writer: OK");
    return 0;
}
