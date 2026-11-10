#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
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

int main(void) {
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
