#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ftw.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_ct_codec.h"

#define RETAINED_LIMIT (2u * 1024u * 1024u)

static const char LANE_A[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char LANE_B[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char GEN_A[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char GEN_B[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static int remove_entry(const char *path, const struct stat *st, int flag,
                        struct FTW *walk) {
    (void)st;
    (void)walk;
    return flag == FTW_D || flag == FTW_DP ? rmdir(path) : unlink(path);
}

static void cleanup(const char *path) {
    qihse_audit_shutdown();
    assert(nftw(path, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
}

static void set_slot(uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
                     uint16_t slot) {
    bitmap[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
}

static char *key_for_slot(const char *prefix, uint16_t slot) {
    char candidate[128];
    for (unsigned i = 0; i < 1000000u; ++i) {
        int n = snprintf(candidate, sizeof(candidate), "%s%u", prefix, i);
        assert(n > 0 && (size_t)n < sizeof(candidate));
        if (qihse_cluster_key_slot(candidate, (size_t)n) == slot)
            return strdup(candidate);
    }
    assert(!"could not find key for slot");
    return NULL;
}

static void admit_source(qihse_kv_store_t *store, qihse_user_t *op,
                         qihse_user_t *peer, const char *lane,
                         const char *generation) {
    qihse_kv_ct_lane_status_t status = {0};
    assert(qihse_kv_ct_lane_status(store, op, lane, &status));
    unsigned char digest[32];
    qihse_kv_replica_snapshot_t *snapshot = NULL;
    if (status.baseline_sealed) {
        memcpy(digest, status.baseline_digest, sizeof(digest));
    } else {
        uint64_t row_seq = UINT64_MAX;
        assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, lane,
            &snapshot, &row_seq, digest) == 0);
        assert(snapshot && row_seq == 0u);
    }
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, lane,
        !strcmp(lane, LANE_A) ? "peer-a" : "peer-b", generation,
        digest, status.acknowledged_position));
    if (snapshot) qihse_kv_replica_snapshot_destroy(snapshot);
}

static qihse_kv_ct_writer_scope_t *write_lane(qihse_kv_store_t *store,
                       qihse_user_t *op, const char *lane,
                       const unsigned char *token, const char *key,
                       const char *value) {
    qihse_kv_ct_writer_scope_t *scope = NULL;
    if (!qihse_kv_ct_writer_scope_enter_lane(store, op, lane, token, &scope)) {
        fprintf(stderr, "writer scope failed lane=%s errno=%d\n", lane, errno);
        abort();
    }
    assert(qihse_kv_set_user(store, key, value, 4u, 1u, op));
    return scope;
}

static void assert_source_read(qihse_kv_store_t *store, qihse_user_t *peer,
                               const char *lane, const char *generation,
                               uint64_t after, uint64_t expected_position) {
    qihse_kv_ct_group_t *groups = NULL;
    size_t count = 0u;
    uint64_t resume = UINT64_MAX;
    assert(qihse_kv_ct_lane_source_read(store, peer, lane, generation, after,
        16u, 1u << 20, &groups, &count, &resume));
    if (expected_position == after) {
        assert(count == 0u && resume == after);
    } else {
        assert(count == 1u && groups[0].stream_position == expected_position &&
               resume == expected_position && groups[0].count == 1u);
    }
    qihse_kv_ct_groups_free(groups, count);
}

static void assert_value(qihse_kv_store_t *store, qihse_user_t *user,
                         const char *key, const char *expected) {
    char *value = qihse_kv_get_user(store, key, user);
    assert(value && strcmp(value, expected) == 0);
    free(value);
}

typedef struct {
    qihse_kv_store_t *store;
    qihse_user_t *op;
    qihse_user_t *peer;
    const unsigned char *token;
    const char *key;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool ready;
    bool finish;
    bool ok;
} pending_lane_write_t;

static void *pending_lane_write(void *opaque) {
    pending_lane_write_t *work = opaque;
    qihse_kv_ct_writer_scope_t *scope = NULL;
    bool ok = qihse_kv_ct_writer_scope_enter_lane(work->store, work->op,
        LANE_B, work->token, &scope) &&
        qihse_kv_set_user(work->store, work->key, "b1", 4u, 1u, work->op);
    pthread_mutex_lock(&work->mutex);
    work->ready = true;
    work->ok = ok;
    pthread_cond_broadcast(&work->condition);
    while (ok && !work->finish)
        pthread_cond_wait(&work->condition, &work->mutex);
    pthread_mutex_unlock(&work->mutex);
    if (ok) {
        ok = qihse_kv_ct_lane_source_ack(work->store, work->peer, LANE_B,
            "peer-b", GEN_B, 1u) &&
            qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL);
    } else if (scope) {
        qihse_kv_ct_writer_scope_leave(scope);
    }
    work->ok = ok;
    return NULL;
}

static _Thread_local bool ack_armed, ack_file_synced, ack_published;
static _Thread_local int ack_witness_fd;
static _Thread_local char ack_lanes_path[512];
static _Thread_local struct stat ack_file_inode, ack_parent_inode;
static const char ack_witness[] = "ACK2:file-and-parent-synced:before-data-sync";

static bool ack_same_inode(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
int rename(const char* oldpath, const char* newpath) {
    int rc = (int)syscall(SYS_rename, oldpath, newpath);
    int saved = errno;
    if (rc == 0 && ack_armed && !strcmp(newpath, ack_lanes_path)) {
        struct stat st;
        assert(ack_file_synced && !ack_published && stat(newpath, &st) == 0);
        assert(ack_same_inode(&st, &ack_file_inode));
        ack_published = true;
    }
    errno = saved; return rc;
}
int fsync(int fd) {
    int rc = (int)syscall(SYS_fsync, fd);
    int saved = errno;
    if (rc == 0 && ack_armed) {
        struct stat st; assert(fstat(fd, &st) == 0);
        if (S_ISREG(st.st_mode)) {
            ack_file_inode = st; ack_file_synced = true;
        } else if (S_ISDIR(st.st_mode) && ack_published &&
                   ack_same_inode(&st, &ack_parent_inode)) {
            ack_armed = false;
            ssize_t n;
            do { n = write(ack_witness_fd, ack_witness, sizeof ack_witness - 1u); }
            while (n < 0 && errno == EINTR);
            if (n != (ssize_t)(sizeof ack_witness - 1u)) _exit(121);
            kill(getpid(), SIGKILL); _exit(122);
        }
    }
    errno = saved; return rc;
}
static uint64_t ack_get64(const unsigned char* b) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8u; ++i) v = (v << 8) | b[i];
    return v;
}
static void ack_check_sidecar(const char* dir, const char* lane,
    const char* generation, uint64_t ack, uint64_t last) {
    char path[512];
    int n = snprintf(path, sizeof path, "%s/ct-lane-log-%s-%s.qcl", dir, lane, generation);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE* f = fopen(path, "rb"); assert(f);
    unsigned char slots[2][320], digest[32]; unsigned len = 0;
    assert(fread(slots, 1u, sizeof slots, f) == sizeof slots);
    for (size_t i = 0; i < 2u; ++i) {
        unsigned char copy[320]; memcpy(copy, slots[i], sizeof copy);
        memset(copy + 288u, 0, 32u);
        assert(!memcmp(copy, "QCLG0001", 8u));
        assert(EVP_Digest(copy, sizeof copy, digest, &len, EVP_sha256(), NULL) && len == 32u);
        assert(!memcmp(digest, slots[i] + 288u, 32u));
    }
    unsigned char* h = ack_get64(slots[0] + 8u) > ack_get64(slots[1] + 8u) ? slots[0] : slots[1];
    assert(ack_get64(h + 16u) == ack && ack_get64(h + 24u) == last);
    assert(h[41] == strlen(lane) && !memcmp(h + 48u, lane, strlen(lane)));
    assert(h[43] == strlen("node-a") && !memcmp(h + 113u, "node-a", strlen("node-a")));
    assert(h[45] == strlen(generation) && !memcmp(h + 178u, generation, strlen(generation)));
    struct stat st; assert(fstat(fileno(f), &st) == 0);
    assert((uint64_t)st.st_size == 640u + ack_get64(h + 32u));
    if (ack == last) assert(st.st_size == 640);
    assert(fclose(f) == 0);
}
static void ack_check_wal(const char* dir, qihse_user_t* op, const char* key) {
    char path[512]; int n = snprintf(path, sizeof path, "%s/wal.log", dir);
    assert(n > 0 && (size_t)n < sizeof path);
    FILE* f = fopen(path, "rb"); assert(f);
    qihse_kv_ct_group_t* group = calloc(1u, sizeof *group); assert(group);
    uint8_t mode = 0; size_t consumed = 0;
    assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, RETAINED_LIMIT, group, &mode, &consumed) == 1);
    assert(mode == QIHSE_CT_CODEC_MODE_SOURCE && group->stream_position == 2u &&
        group->count == 1u && !strcmp(group->source_id, "node-a") &&
        !strcmp(group->generation, GEN_A));
    assert(!strcmp(group->records[0].key, key) && !strcmp(group->records[0].value, "a2") &&
        group->records[0].classification == 4u && group->records[0].sci_compartment == 1u);
    assert(fgetc(f) == EOF && !ferror(f) && fclose(f) == 0);
    qihse_ct_codec_clear(group); free(group);
}
static void ack_mutate(const char* mode, const char* dir, qihse_user_t* op) {
    bool ahead = !strcmp(mode, "--ack-ahead");
    bool different = !strcmp(mode, "--ack-different");
    bool gap = !strcmp(mode, "--ack-gap");
    assert(ahead || different || gap || !strcmp(mode, "--ack-reconstruct"));
    char path[512], saved[544];
    if (!different) {
        int n = snprintf(path, sizeof path, "%s/ct-lane-log-%s-%s.qcl", dir, LANE_A, GEN_A);
        assert(n > 0 && (size_t)n < sizeof path);
        ack_check_sidecar(dir, LANE_A, GEN_A, 1u, 2u);
        FILE* f = fopen(path, "rb"); unsigned char slots[2][320];
        assert(f && fread(slots, 1u, sizeof slots, f) == sizeof slots && fclose(f) == 0);
        for (size_t i = 0; i < 2u; ++i) {
            uint64_t fields[] = {ahead ? 3u : 1u, ahead ? 3u : 1u, 0u};
            for (size_t k = 0; k < 3u; ++k)
                for (size_t j = 0; j < 8u; ++j)
                    slots[i][16u + k * 8u + j] = (unsigned char)(fields[k] >> (56u - j * 8u));
            unsigned len = 0; unsigned char digest[32];
            memset(slots[i] + 288u, 0, 32u);
            assert(EVP_Digest(slots[i], 320u, digest, &len, EVP_sha256(), NULL) && len == 32u);
            memcpy(slots[i] + 288u, digest, 32u);
        }
        assert(snprintf(saved, sizeof saved, "%s.native-saved", path) > 0 &&
            access(saved, F_OK) != 0 && errno == ENOENT && rename(path, saved) == 0);
        f = fopen(path, "wbx"); assert(f);
        assert(fwrite(slots, 1u, sizeof slots, f) == sizeof slots && fflush(f) == 0 &&
            fsync(fileno(f)) == 0 && fclose(f) == 0);
        ack_check_sidecar(dir, LANE_A, GEN_A, ahead ? 3u : 1u, ahead ? 3u : 1u);
    }
    if (different || gap) {
        int n = snprintf(path, sizeof path, "%s/wal.log", dir);
        assert(n > 0 && (size_t)n < sizeof path);
        FILE* f = fopen(path, "rb"); assert(f);
        qihse_kv_ct_group_t* group = calloc(1u, sizeof *group); assert(group);
        uint8_t mode_byte; size_t count;
        assert(qihse_ct_codec_read(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
            0u, RETAINED_LIMIT, group, &mode_byte, &count) == 1 && fclose(f) == 0);
        assert(group->count == 1u && group->stream_position == 2u);
        if (different) {
            free(group->records[0].value);
            group->records[0].value = strdup("changed"); assert(group->records[0].value);
        } else group->stream_position = 3u;
        assert(snprintf(saved, sizeof saved, "%s.native-saved", path) > 0 &&
            access(saved, F_OK) != 0 && errno == ENOENT && rename(path, saved) == 0);
        f = fopen(path, "wbx"); assert(f);
        assert(qihse_ct_codec_write(f, op, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
            0u, mode_byte, group, RETAINED_LIMIT, &count));
        assert(fflush(f) == 0 && fsync(fileno(f)) == 0 && fclose(f) == 0);
        qihse_ct_codec_clear(group); free(group);
    }
    int parent = open(dir, O_RDONLY | O_DIRECTORY); assert(parent >= 0);
    assert(fsync(parent) == 0 && close(parent) == 0);
}
static int ack_child(const char* mode, const char* dir, int fd) {
    bool writer = !strcmp(mode, "--ack-crash");
    bool first = !strcmp(mode, "--ack-first-open");
    bool reject = !strcmp(mode, "--ack-reject");
    bool mutate = !strcmp(mode, "--ack-ahead") || !strcmp(mode, "--ack-different") ||
        !strcmp(mode, "--ack-gap") || !strcmp(mode, "--ack-reconstruct");
    assert(writer || first || reject || mutate || !strcmp(mode, "--ack-open"));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0 && setenv("QIHSE_LOG_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0 && qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtLaneLogOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtLaneLogOperator1!"); assert(op);
    qihse_user_t* peer = qihse_auth_create_user(op, 8602u, QIHSE_ROLE_ANALYST,
        5u, 3u, "CtLaneLogPeerPass1!", false);
    qihse_user_t* low = qihse_auth_create_user(op, 8601u, QIHSE_ROLE_ANALYST,
        0u, 0u, "CtLaneLogLowPass1!", false);
    assert(peer && low);
    if (mutate) { ack_mutate(mode, dir, op); qihse_audit_shutdown(); return 0; }
    if (reject) {
        assert(!qihse_kv_store_create_user(op));
        qihse_audit_shutdown(); return 0;
    }
    char* keys[] = {key_for_slot("ct-log-a1-", 101u), key_for_slot("ct-log-a2-", 101u),
        key_for_slot("ct-log-b1-", 14000u)};
    struct ack_state {
        uint8_t slots[2][QIHSE_KV_CT_SLOT_BITMAP_BYTES];
        unsigned char tokens[2][QIHSE_KV_CT_TOKEN_BYTES];
        qihse_kv_ct_lane_status_t status[2];
    } *s = calloc(1u, sizeof *s); assert(s);
    set_slot(s->slots[0], 101u); set_slot(s->slots[1], 14000u);
    const char* lanes[] = {LANE_A, LANE_B};
    const char* generations[] = {GEN_A, GEN_B};
    const char* peers[] = {"peer-a", "peer-b"};
    if (first) {
        ack_check_sidecar(dir, LANE_A, GEN_A, 1u, 2u);
        ack_check_wal(dir, op, keys[1]);
    }
    qihse_kv_store_t* store = qihse_kv_store_create_user(op); assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    if (writer) {
        for (size_t i = 0; i < 2u; ++i) {
            assert(qihse_kv_ct_lane_source_enable(store, op, lanes[i], s->slots[i],
                "node-a", peers[i], generations[i], s->tokens[i], RETAINED_LIMIT));
            admit_source(store, op, peer, lanes[i], generations[i]);
        }
        qihse_kv_ct_writer_scope_t* scope = write_lane(store, op, LANE_B, s->tokens[1], keys[2], "b1");
        assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_B, peers[1], GEN_B, 1u));
        assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
        char before_path[512], b_path[512]; unsigned char before[640];
        int n = snprintf(b_path, sizeof b_path, "%s/ct-lane-log-%s-%s.qcl", dir, LANE_B, GEN_B);
        assert(n > 0 && (size_t)n < sizeof b_path);
        FILE* saved_b = fopen(b_path, "rb");
        assert(saved_b && fread(before, 1u, sizeof before, saved_b) == sizeof before &&
            fgetc(saved_b) == EOF && fclose(saved_b) == 0);
        n = snprintf(before_path, sizeof before_path, "%s/b-sidecar-before-source-acks", dir);
        assert(n > 0 && (size_t)n < sizeof before_path);
        saved_b = fopen(before_path, "wbx"); assert(saved_b);
        assert(fwrite(before, 1u, sizeof before, saved_b) == sizeof before &&
            fflush(saved_b) == 0 && fsync(fileno(saved_b)) == 0 && fclose(saved_b) == 0);
        int parent = open(dir, O_RDONLY | O_DIRECTORY); assert(parent >= 0);
        assert(fsync(parent) == 0 && close(parent) == 0);
        scope = write_lane(store, op, LANE_A, s->tokens[0], keys[0], "a1");
        assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A, peers[0], GEN_A, 1u));
        assert(qihse_kv_ct_writer_scope_finish(scope, 1000u, NULL));
        scope = write_lane(store, op, LANE_A, s->tokens[0], keys[1], "a2");
        ack_check_sidecar(dir, LANE_A, GEN_A, 1u, 2u);
        ack_check_wal(dir, op, keys[1]);
        assert(stat(dir, &ack_parent_inode) == 0);
        n = snprintf(ack_lanes_path, sizeof ack_lanes_path, "%s/ct-lanes.bin", dir);
        assert(n > 0 && (size_t)n < sizeof ack_lanes_path);
        ack_witness_fd = fd; ack_armed = true;
        (void)qihse_kv_ct_lane_source_ack(store, peer, LANE_A, peers[0], GEN_A, 2u);
        abort();
    }
    for (size_t i = 0; i < 2u; ++i) {
        uint64_t position = i ? 1u : 2u;
        assert(qihse_kv_ct_lane_status(store, op, lanes[i], &s->status[i]));
        assert(s->status[i].mode == QIHSE_KV_CT_LANE_SOURCE && !s->status[i].admitted &&
            s->status[i].durable_position == position && s->status[i].acknowledged_position == position &&
            s->status[i].retained_bytes == 0u && s->status[i].baseline_sealed);
        assert(!memcmp(s->slots[i], s->status[i].slot_bitmap, sizeof s->slots[i]));
        assert(qihse_kv_ct_lane_owner_token_get(store, op, lanes[i], s->tokens[i]));
        qihse_kv_ct_writer_scope_t* scope = NULL;
        assert(!qihse_kv_ct_writer_scope_enter_lane(store, op, lanes[i], s->tokens[i], &scope) && !scope);
        assert(!qihse_kv_ct_lane_source_ack(store, peer, lanes[i], peers[i], generations[i], position));
        qihse_kv_ct_group_t* groups = NULL; size_t count = 0u; uint64_t resume = UINT64_MAX;
        assert(!qihse_kv_ct_lane_source_read(store, peer, lanes[i], generations[i], position,
            8u, 1u << 20, &groups, &count, &resume));
        assert(!groups && !count && resume == position);
        admit_source(store, op, peer, lanes[i], generations[i]);
        assert_source_read(store, peer, lanes[i], generations[i], position, position);
        ack_check_sidecar(dir, lanes[i], generations[i], position, position);
    }
    const char* values[] = {"a1", "a2", "b1"};
    for (size_t i = 0; i < 3u; ++i) {
        assert_value(store, op, keys[i], values[i]);
        qihse_kv_record_meta_t meta = {0};
        assert(qihse_kv_meta_user(store, keys[i], op, &meta) && meta.classification == 4u && meta.sci_compartment == 1u);
        assert(!qihse_kv_get_user(store, keys[i], low) && !qihse_kv_meta_user(store, keys[i], low, &meta));
        free(keys[i]);
    }
    qihse_kv_store_destroy(store); free(s); qihse_audit_shutdown(); return 0;
}
static void ack_wait(pid_t child, bool killed) {
    int status; pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    assert(got == child);
    if (killed) assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static pid_t ack_exec(const char* mode, const char* dir, int fd) {
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        char number[32]; assert(snprintf(number, sizeof number, "%d", fd) > 0);
        execl("/proc/self/exe", "test_ct_lane_log", mode, dir, number, (char*)NULL);
        _exit(127);
    }
    return child;
}
static void ack_regression(const char* mutation) {
    char dir[] = "./ct_lane_ack_crash_XXXXXX"; assert(mkdtemp(dir));
    fprintf(stderr, "ACK crash fixture: %s mode=%s (preserved)\n", dir,
        mutation ? mutation : "native");
    int pipefd[2]; assert(pipe(pipefd) == 0);
    pid_t child = ack_exec("--ack-crash", dir, pipefd[1]); assert(close(pipefd[1]) == 0);
    char bytes[sizeof ack_witness]; size_t used = 0;
    while (used < sizeof bytes) {
        ssize_t n = read(pipefd[0], bytes + used, sizeof bytes - used);
        if (n < 0 && errno == EINTR) continue;
        assert(n >= 0); if (!n) break; used += (size_t)n;
    }
    assert(close(pipefd[0]) == 0); ack_wait(child, true);
    assert(used == sizeof ack_witness - 1u && !memcmp(bytes, ack_witness, used));
    char path[512];
    int n = snprintf(path, sizeof path, "%s/ct-lane-log-%s-%s.qcl", dir, LANE_B, GEN_B);
    assert(n > 0 && (size_t)n < sizeof path);
    char before_path[512];
    n = snprintf(before_path, sizeof before_path, "%s/b-sidecar-before-source-acks", dir);
    assert(n > 0 && (size_t)n < sizeof before_path);
    FILE* f = fopen(before_path, "rb"); unsigned char before[640], after[640];
    assert(f && fread(before, 1u, sizeof before, f) == sizeof before && fgetc(f) == EOF && fclose(f) == 0);
    f = fopen(path, "rb");
    assert(f && fread(after, 1u, sizeof after, f) == sizeof after && fgetc(f) == EOF && fclose(f) == 0);
    assert(!memcmp(before, after, sizeof before));
    if (mutation) ack_wait(ack_exec(mutation, dir, -1), false);
    if (mutation && strcmp(mutation, "--ack-reconstruct")) {
        ack_wait(ack_exec("--ack-reject", dir, -1), false);
        printf("PASS ACK recovery rejects %s\n", mutation);
    } else {
        ack_wait(ack_exec(mutation ? "--ack-open" : "--ack-first-open", dir, -1), false);
        ack_wait(ack_exec("--ack-open", dir, -1), false);
        puts("PASS witnessed ACK metadata before sidecar GC: exact WAL replay and repeated reopen");
    }
    f = fopen(path, "rb");
    assert(f && fread(after, 1u, sizeof after, f) == sizeof after && fgetc(f) == EOF && fclose(f) == 0);
    assert(!memcmp(before, after, sizeof before));
}

static int stale_receiver_admission(const char* dir) {
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0 && qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtLaneLogOperator1!"));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CtLaneLogOperator1!");
    assert(op);
    qihse_user_t* peer = qihse_auth_create_user(op, 8602u, QIHSE_ROLE_ANALYST,
        5u, 3u, "CtLaneLogPeerPass1!", false);
    assert(peer);
    qihse_kv_store_t* first = qihse_kv_store_create_user(op);
    assert(first);
    uint8_t slots_a[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t slots_b[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    set_slot(slots_a, 101u);
    set_slot(slots_b, 14000u);
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES], digest[32];
    assert(qihse_kv_ct_lane_receiver_bind(first, op, LANE_A, slots_a,
        "peer-a", "node-a", GEN_A, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, 0u, token));
    assert(qihse_kv_ct_lane_receiver_empty_baseline_seal(first, op, LANE_A,
        token, digest));
    qihse_kv_store_t* stale = qihse_kv_store_create_user(op);
    assert(stale);
    qihse_kv_store_set_replication_principal_id(stale, qihse_user_get_id(peer));
    assert(qihse_kv_ct_lane_receiver_bind(first, op, LANE_B, slots_b,
        "peer-b", "node-a", GEN_B, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0u, 0u, token));
    char wal_path[512];
    assert(snprintf(wal_path, sizeof(wal_path), "%s/wal.log", dir) > 0);
    struct stat before, after;
    assert(stat(wal_path, &before) == 0);
    char* key = key_for_slot("ct-stale-receiver-", 101u);
    qihse_kv_ct_record_t row = {
        .key = key, .value = "stale", .change_seq = 1u,
        .actor_id = qihse_user_get_id(peer), .classification = 4u,
        .sci_compartment = 1u, .actor_kind = QIHSE_KV_CT_ACTOR_USER
    };
    qihse_kv_ct_group_t group = {0};
    snprintf(group.source_id, sizeof(group.source_id), "peer-a");
    snprintf(group.generation, sizeof(group.generation), "%s", GEN_A);
    group.stream_position = group.first_seq = group.last_seq = 1u;
    group.records = &row;
    group.count = 1u;
    uint64_t cursor = 99u;
    assert(!qihse_kv_ct_lane_receiver_apply(stale, peer, LANE_A,
        &group, &cursor) && cursor == 0u);
    assert(stat(wal_path, &after) == 0 && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size);
    free(key);
    qihse_kv_store_destroy(stale);
    qihse_kv_store_destroy(first);
    qihse_audit_shutdown();
    return 0;
}

int main(int argc, char** argv) {
    umask(0077); alarm(120);
    if (argc == 4 && strcmp(argv[1], "--receiver-stale") == 0)
        return stale_receiver_admission(argv[2]);
    if (argc == 4) return ack_child(argv[1], argv[2], atoi(argv[3]));
    assert(argc == 1);
    char stale_dir[] = "./ct_lane_receiver_stale_XXXXXX";
    assert(mkdtemp(stale_dir));
    ack_wait(ack_exec("--receiver-stale", stale_dir, -1), false);
    cleanup(stale_dir);
    ack_regression(NULL);
    ack_regression("--ack-ahead");
    ack_regression("--ack-different");
    ack_regression("--ack-gap");
    ack_regression("--ack-reconstruct");
    char data_dir[] = "./ct_lane_log_XXXXXX";
    umask(0077);
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("CtLaneLogOperator1!"));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, "CtLaneLogOperator1!");
    qihse_user_t *low = qihse_auth_create_user(op, 8601u, QIHSE_ROLE_ANALYST,
        0u, 0u, "CtLaneLogLowPass1!", false);
    qihse_user_t *peer = qihse_auth_create_user(op, 8602u, QIHSE_ROLE_ANALYST,
        5u, 3u, "CtLaneLogPeerPass1!", false);
    assert(op && low && peer);

    uint16_t slot_a = 101u, slot_b = 14000u;
    uint8_t slots_a[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    uint8_t slots_b[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    set_slot(slots_a, slot_a);
    set_slot(slots_b, slot_b);
    char *key_a1 = key_for_slot("ct-log-a1-", slot_a);
    char *key_a2 = key_for_slot("ct-log-a2-", slot_a);
    char *key_b1 = key_for_slot("ct-log-b1-", slot_b);
    assert(key_a1 && key_a2 && key_b1);

    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    unsigned char token_a[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char token_b[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_A, slots_a,
        "node-a", "peer-a", GEN_A, token_a, RETAINED_LIMIT));
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE_B, slots_b,
        "node-a", "peer-b", GEN_B, token_b, RETAINED_LIMIT));
    admit_source(store, op, peer, LANE_A, GEN_A);
    admit_source(store, op, peer, LANE_B, GEN_B);

    pending_lane_write_t work_b = {.store = store, .op = op, .peer = peer,
        .token = token_b, .key = key_b1, .mutex = PTHREAD_MUTEX_INITIALIZER,
        .condition = PTHREAD_COND_INITIALIZER};
    pthread_t writer_b;
    assert(pthread_create(&writer_b, NULL, pending_lane_write, &work_b) == 0);
    pthread_mutex_lock(&work_b.mutex);
    while (!work_b.ready) pthread_cond_wait(&work_b.condition, &work_b.mutex);
    pthread_mutex_unlock(&work_b.mutex);
    assert(work_b.ok);
    qihse_kv_ct_writer_scope_t *scope_a =
        write_lane(store, op, LANE_A, token_a, key_a1, "a1");
    assert_source_read(store, peer, LANE_A, GEN_A, 0u, 1u);
    assert_source_read(store, peer, LANE_B, GEN_B, 0u, 1u);
    qihse_kv_ct_group_t *groups = NULL;
    size_t group_count = 0u;
    uint64_t resume = 0u;
    assert(!qihse_kv_ct_lane_source_read(store, low, LANE_A, GEN_A, 0u,
        8u, 1u << 20, &groups, &group_count, &resume));
    assert(groups == NULL && group_count == 0u);

    char log_a[512], log_b[512];
    assert(snprintf(log_a, sizeof(log_a), "%s/ct-lane-log-%s-%s.qcl",
                    data_dir, LANE_A, GEN_A) > 0);
    assert(snprintf(log_b, sizeof(log_b), "%s/ct-lane-log-%s-%s.qcl",
                    data_dir, LANE_B, GEN_B) > 0);
    struct stat before_a, before_b, after_a, after_b;
    assert(stat(log_a, &before_a) == 0 && stat(log_b, &before_b) == 0);
    assert(before_a.st_size > 640 && before_b.st_size > 640);

    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A, "peer-a", GEN_A, 1u));
    assert(qihse_kv_ct_writer_scope_finish(scope_a, 1000u, NULL));
    assert(stat(log_a, &after_a) == 0 && stat(log_b, &after_b) == 0);
    assert(after_a.st_size == 640 && after_b.st_size == before_b.st_size);
    assert_source_read(store, peer, LANE_A, GEN_A, 1u, 1u);
    assert_source_read(store, peer, LANE_B, GEN_B, 0u, 1u);
    pthread_mutex_lock(&work_b.mutex);
    work_b.finish = true;
    pthread_cond_broadcast(&work_b.condition);
    pthread_mutex_unlock(&work_b.mutex);
    assert(pthread_join(writer_b, NULL) == 0 && work_b.ok);
    pthread_cond_destroy(&work_b.condition);
    pthread_mutex_destroy(&work_b.mutex);

    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    qihse_kv_ct_lane_status_t status_a = {0}, status_b = {0};
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(qihse_kv_ct_lane_status(store, op, LANE_B, &status_b));
    assert(status_a.acknowledged_position == 1u && status_a.durable_position == 1u);
    assert(status_b.acknowledged_position == 1u && status_b.durable_position == 1u);
    admit_source(store, op, peer, LANE_A, GEN_A);
    admit_source(store, op, peer, LANE_B, GEN_B);

    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, token_a));
    scope_a = write_lane(store, op, LANE_A, token_a, key_a2, "a2");
    assert_source_read(store, peer, LANE_A, GEN_A, 1u, 2u);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A,
        "peer-a", GEN_A, 2u));
    assert(qihse_kv_ct_writer_scope_finish(scope_a, 1000u, NULL));
    assert(stat(log_a, &after_a) == 0 && after_a.st_size == 640);

    qihse_kv_store_destroy(store);
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    /* Fail after the lane frame itself is durable but before its checked
     * sidecar header publishes it. The global WAL must let open reconstruct
     * that suffix, and the recovered ACK cursor must remain monotonic. */
    store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(status_a.acknowledged_position == 2u &&
           status_a.durable_position == 2u);
    admit_source(store, op, peer, LANE_A, GEN_A);
    assert(qihse_kv_ct_lane_owner_token_get(store, op, LANE_A, token_a));
    scope_a = NULL;
    assert(qihse_kv_ct_writer_scope_enter_lane(store, op, LANE_A,
        token_a, &scope_a));
    assert(setenv("QIHSE_AIMEM_FAIL_AT",
                  "ct-lane-log-after-frame-fsync", 1) == 0);
    assert(!qihse_kv_set_user(store, key_a2, "a3", 4u, 1u, op));
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    qihse_kv_store_destroy(store);

    store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    assert(qihse_kv_ct_lane_status(store, op, LANE_A, &status_a));
    assert(status_a.acknowledged_position == 2u &&
           status_a.durable_position == 3u);
    admit_source(store, op, peer, LANE_A, GEN_A);
    assert_source_read(store, peer, LANE_A, GEN_A, 2u, 3u);
    assert(qihse_kv_ct_lane_source_ack(store, peer, LANE_A,
        "peer-a", GEN_A, 3u));
    assert_value(store, op, key_a2, "a3");
    assert(stat(log_a, &after_a) == 0 && after_a.st_size == 640);
    qihse_kv_store_destroy(store);
#endif
    free(key_a1); free(key_a2); free(key_b1);
    cleanup(data_dir);
    return 0;
}
