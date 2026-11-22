/* test_ct_target_epoch_fence.c - receiver-side recovery epoch fence.
 * A disposable CT1 receiver built through the public API receives the
 * QCTTF001/QCTRX001 pinned epoch fence; every admission mismatch is
 * refused before persistence, the fence survives cold reopen, denies
 * writes/apply, and any artifact loss, damage or downgrade fails closed.
 * Each case runs in its own re-executed process, mirroring the CT storage
 * fixture pattern, so auth/audit state never spans fixture directories.
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

#include "qihse_auth.h"
#include "core/qihse_audit.h"
#include "qihse_kv_store.h"

#define GEN       "0123456789abcdef0123456789abcdef"
#define SOURCE_ID "hold-primary"
#define TARGET_ID "hold-successor"
#define ROW_KEY   "ct1.hold-pending"
#define CURSOR    7u
#define PENDING   8u

static int remove_entry(const char* path, const struct stat* st, int flag,
    struct FTW* buffer) {
    (void)st; (void)flag; (void)buffer;
    return remove(path);
}

/* Minimal source store used only to mint a sealed baseline file. Runs in
 * its own process so the audit writer never sees QIHSE_DATA_DIR change. */
static int mint_baseline_process(const char* src_dir) {
    char data_dir[PATH_MAX];
    assert(snprintf(data_dir, PATH_MAX, "%s/data", src_dir) > 0);
    assert(mkdir(src_dir, 0700) == 0 && mkdir(data_dir, 0700) == 0 &&
        setenv("QIHSE_DATA_DIR", data_dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("EpochFenceOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "EpochFenceOperator1!");
    assert(op);
    char baseline_path[PATH_MAX], meta_path[PATH_MAX];
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
    assert(snprintf(baseline_path, PATH_MAX, "%s/ct-baseline.qfs",
        data_dir) > 0);
    int fd = open(baseline_path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && st.st_size > 0);
    close(fd);
    /* Hand the exact facts back through a sidecar next to the baseline. */
    assert(snprintf(meta_path, PATH_MAX, "%s/baseline.meta", data_dir) > 0);
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

/* Build one disposable receiver at cursor CURSOR with a retained same-key
 * tombstone at position 3. The sealed baseline is minted by a child
 * process; the receiver shares this process's audit-bound data dir. */
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
    char baseline_path[PATH_MAX], meta_path[PATH_MAX], data_dir[PATH_MAX];
    assert(snprintf(data_dir, PATH_MAX, "%s/src/data", dir) > 0 &&
        snprintf(baseline_path, PATH_MAX, "%s/ct-baseline.qfs",
            data_dir) > 0 &&
        snprintf(meta_path, PATH_MAX, "%s/baseline.meta", data_dir) > 0);
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
        const char* key = (pos == 1u || tomb) ? ROW_KEY : "ct1.unrelated";
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

static void base_request(qihse_kv_ct_target_epoch_fence_request_t* request,
    uint64_t seq, const unsigned char digest[32], uint64_t high_water,
    uint64_t tombstone_seq) {
    memset(request, 0, sizeof(*request));
    request->version = QIHSE_KV_CT_TARGET_EPOCH_FENCE_V1;
    request->size = sizeof(*request);
    request->key = ROW_KEY;
    strcpy(request->source_id, SOURCE_ID);
    strcpy(request->target_id, TARGET_ID);
    strcpy(request->generation, GEN);
    memcpy(request->baseline_digest, digest, 32u);
    for (size_t i = 0u; i < 32u; ++i) {
        request->manifest_sha256[i] = (unsigned char)(i + 1u);
        request->frame_sha256[i] = (unsigned char)(0xA5u ^ i);
    }
    request->baseline_row_seq = seq;
    request->frame_length = 1644u;
    request->pending_position = PENDING;
    request->durable_cursor = CURSOR;
    request->target_high_water = high_water;
    request->tombstone_row_seq = tombstone_seq;
    request->tombstone_position = 3u;
    request->resource_tenant_id = 0u;
    request->classification = 4u;
    request->sci_compartment = 2u;
}

static void next_group(qihse_kv_ct_record_t* row, qihse_kv_ct_group_t* group,
    uint64_t seq, bool tomb) {
    row->key = (char*)ROW_KEY;
    row->value = tomb ? NULL : "late-value";
    row->change_seq = seq + PENDING;
    row->actor_id = 0u; row->actor_tenant_id = 0u;
    row->resource_tenant_id = 0u;
    row->classification = 4u; row->sci_compartment = 2u;
    row->actor_kind = QIHSE_KV_CT_ACTOR_USER; row->tombstone = tomb;
    group->stream_position = PENDING;
    group->first_seq = row->change_seq;
    group->last_seq = row->change_seq;
    group->records = row; group->count = 1u;
    strcpy(group->source_id, SOURCE_ID);
    strcpy(group->generation, GEN);
}

static void expect_artifact(const char* dir, const char* name, size_t size,
    const char magic[8]) {
    char path[PATH_MAX];
    unsigned char body[512];
    assert(snprintf(path, PATH_MAX, "%s/%s", dir, name) > 0);
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_mode == (S_IFREG | 0600) && st.st_nlink == 1u &&
        st.st_size == (off_t)size &&
        read(fd, body, size) == (ssize_t)size &&
        memcmp(body, magic, 8u) == 0);
    close(fd);
}

/* One isolated case: fresh fixture tree, auth, and teardown per process.
 * Auth and audit bind to the receiver's data dir and never move. */
static int run_case(const char* self, const char* case_id) {
    char root[] = "build/ct-target-epoch-fence-XXXXXX";
    assert(mkdtemp(root));
    char dir[PATH_MAX];
    assert(snprintf(dir, PATH_MAX, "%s/rx", root) > 0 &&
        mkdir(dir, 0700) == 0 &&
        setenv("QIHSE_DATA_DIR", dir, 1) == 0 &&
        setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("EpochFenceOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "EpochFenceOperator1!");
    assert(op);
    qihse_user_t* service = qihse_auth_create_user(op, 8302u,
        QIHSE_ROLE_ANALYST, UINT16_MAX, UINT16_MAX, "EpochFenceService1!", false);
    assert(service);

    uint64_t seq = 0u, high_water = 0u, tombstone_seq = 0u, epoch = 0u;
    unsigned char digest[32];
    qihse_kv_ct_target_epoch_fence_request_t request;
    qihse_kv_ct_record_t row;
    qihse_kv_ct_group_t group;
    uint64_t cursor = 0u;
    qihse_kv_store_t* store = build_receiver(self, dir, op, service, &seq,
        digest, &high_water, &tombstone_seq);
    base_request(&request, seq, digest, high_water, tombstone_seq);

    if (strncmp(case_id, "neg:", 4u) == 0) {
        if (strcmp(case_id + 4u, "cursor") == 0)
            request.durable_cursor = CURSOR + 1u;
        else if (strcmp(case_id + 4u, "highwater") == 0)
            request.target_high_water = high_water + 1u;
        else if (strcmp(case_id + 4u, "generation") == 0)
            strcpy(request.generation, "ffffffffffffffffffffffffffffffff");
        else if (strcmp(case_id + 4u, "baseline") == 0)
            request.baseline_digest[0] ^= 1u;
        else if (strcmp(case_id + 4u, "pending") == 0)
            request.pending_position = PENDING + 1u;
        else if (strcmp(case_id + 4u, "tombstone") == 0)
            request.tombstone_row_seq = 0u;
        else if (strcmp(case_id + 4u, "key") == 0)
            request.key = "ct1.hold-pending-key-longer-than-sixty-four-bytes"
                "-in-total-length-padded";
        else if (strcmp(case_id + 4u, "framelen") == 0)
            request.frame_length = 65537u;
        else assert(!"unknown neg case");
        assert(!qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
            service, &request, &epoch));
        next_group(&row, &group, seq, false);
        /* The refused request left the receiver fully operational. */
        assert(qihse_kv_ct_receiver_apply(store, service, &group, &cursor));
    } else if (strcmp(case_id, "principal") == 0) {
        assert(!qihse_kv_ct_target_epoch_fence_install_pinned_v1(store,
            service, service, &request, &epoch));
        assert(!qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
            op, &request, &epoch));
        /* An ordinary receiver recovery fence already blocks the epoch
         * install: layering on top is the only admission path. */
        assert(qihse_kv_ct_receiver_recovery_fence_install(store, op, GEN,
            seq, digest, CURSOR));
        assert(!qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
            service, &request, &epoch));
    } else if (strcmp(case_id, "positive") == 0) {
        assert(qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
            service, &request, &epoch) && epoch == 1u);
        assert(!qihse_kv_set_user(store, "ct1.unrelated", "denied", 4u, 2u, op));
        next_group(&row, &group, seq, false);
        assert(!qihse_kv_ct_receiver_apply(store, service, &group, &cursor));
        assert(qihse_kv_get_user(store, ROW_KEY, op) == NULL);
        assert(!qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
            service, &request, &epoch)); /* once-only */
        expect_artifact(dir, "ct1-recovery-fence.bin", 153u, "QCTRF001");
        expect_artifact(dir, "ct-recovery-ext.bin", 480u, "QCTRX001");
        expect_artifact(dir, "ct1-target-recovery-fence.bin", 299u, "QCTTF001");
        char path[PATH_MAX];
        unsigned char marker[299];
        assert(snprintf(path, PATH_MAX, "%s/ct1-target-recovery-fence.bin",
            dir) > 0);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        assert(fd >= 0 && read(fd, marker, sizeof(marker)) ==
            (ssize_t)sizeof(marker));
        close(fd);
        uint64_t v = 0u;
        for (unsigned b = 0u; b < 8u; ++b)
            v |= (uint64_t)marker[235u + b] << (8u * b);
        assert(v == 1u); /* strictly monotone epoch starts at one */
        qihse_kv_store_destroy(store);
        /* The fence survives cold reopen and still denies everything. */
        store = qihse_kv_store_create_user(op);
        assert(store && !qihse_kv_set_user(store, "ct1.unrelated", "denied",
            4u, 2u, op));
        next_group(&row, &group, seq, true);
        assert(!qihse_kv_ct_receiver_apply(store, service, &group, &cursor));
    } else if (strncmp(case_id, "harm:", 5u) == 0) {
        assert(qihse_kv_ct_target_epoch_fence_install_pinned_v1(store, op,
            service, &request, &epoch));
        qihse_kv_store_destroy(store);
        store = NULL;
        char path[PATH_MAX];
        const char* target = case_id + 5u;
        if (strcmp(target, "tamper-ext") == 0 ||
            strcmp(target, "tamper-marker") == 0) {
            const char* name = strcmp(target, "tamper-ext") == 0 ?
                "ct-recovery-ext.bin" : "ct1-target-recovery-fence.bin";
            assert(snprintf(path, PATH_MAX, "%s/%s", dir, name) > 0);
            int fd = open(path, O_RDWR | O_CLOEXEC);
            unsigned char byte;
            assert(fd >= 0 && pread(fd, &byte, 1u, 40u) == 1);
            byte ^= 1u;
            assert(pwrite(fd, &byte, 1u, 40u) == 1 && fsync(fd) == 0 &&
                close(fd) == 0);
        } else if (strcmp(target, "missing-ext") == 0 ||
            strcmp(target, "missing-marker") == 0 ||
            strcmp(target, "missing-base") == 0) {
            const char* name = strcmp(target, "missing-ext") == 0 ?
                "ct-recovery-ext.bin" :
                strcmp(target, "missing-marker") == 0 ?
                "ct1-target-recovery-fence.bin" : "ct1-recovery-fence.bin";
            assert(snprintf(path, PATH_MAX, "%s/%s", dir, name) > 0);
            assert(unlink(path) == 0);
        } else if (strcmp(target, "substitute") == 0) {
            /* Substitution: a fresh valid-looking file of the wrong length. */
            assert(snprintf(path, PATH_MAX, "%s/ct-recovery-ext.bin",
                dir) > 0);
            assert(unlink(path) == 0);
            int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                0600);
            unsigned char zero[479] = {0};
            assert(fd >= 0 && write(fd, zero, sizeof(zero)) ==
                (ssize_t)sizeof(zero) && fsync(fd) == 0 && close(fd) == 0);
        } else assert(!"unknown harm case");
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
        "neg:cursor", "neg:highwater", "neg:generation", "neg:baseline",
        "neg:pending", "neg:tombstone", "neg:key", "neg:framelen",
        "principal", "positive",
        "harm:tamper-ext", "harm:tamper-marker", "harm:missing-ext",
        "harm:missing-marker", "harm:missing-base", "harm:substitute"};
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
    puts("CT1 target recovery epoch fence: OK");
    return 0;
}
