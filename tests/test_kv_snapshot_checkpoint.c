#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static qihse_kv_store_t* probed_store;
static qihse_user_t* probed_user;
static bool probe_batch;
static unsigned batch_probes;

static bool same(qihse_kv_snapshot_checkpoint_t a, qihse_kv_snapshot_checkpoint_t b) {
    return a.instance_id == b.instance_id && a.change_seq == b.change_seq &&
        a.projection_epoch == b.projection_epoch;
}

static void denied(qihse_kv_store_t* store, qihse_user_t* user) {
    qihse_kv_snapshot_checkpoint_t before = { UINT64_MAX, UINT64_MAX, UINT64_MAX };
    qihse_kv_snapshot_checkpoint_t after = before;
    assert(!qihse_kv_snapshot_checkpoint_user(store, user, &after));
    assert(same(before, after));
}

/* Interpose only in this executable: inspect while the real durable batch owns
 * its write lock. Checkpoint refusal must not try to reacquire that lock. */
int fdatasync(int fd) {
    static int (*real_fdatasync)(int);
    if (!real_fdatasync) {
        *(void**)(&real_fdatasync) = dlsym(RTLD_NEXT, "fdatasync");
        assert(real_fdatasync);
    }
    if (probe_batch) {
        probe_batch = false;
        denied(probed_store, probed_user);
        batch_probes++;
    }
    return real_fdatasync(fd);
}

static qihse_kv_snapshot_checkpoint_t capture(qihse_kv_store_t* store, qihse_user_t* user) {
    qihse_kv_snapshot_checkpoint_t result;
    assert(qihse_kv_snapshot_checkpoint_user(store, user, &result));
    assert(result.instance_id && result.projection_epoch);
    return result;
}

/* Fresh-process case: a modern admitted SOURCE lane has ct_enabled=true, so the
 * CT-disabled checkpoint must refuse it even though the projection marker
 * (which only needs ct_read_ready) succeeds. A new data dir needs a new process. */
static int lane_source_child(const char* dir) {
    static const char LANE[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char GEN[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const uint16_t slot = 313u;
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_LOG_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_authenticate_id(0u, "CheckpointOperator1!");
    assert(op);
    qihse_user_t* peer = qihse_auth_create_user(op, 8802u, QIHSE_ROLE_ANALYST,
        5u, UINT16_MAX, "CheckpointLanePeer1!", false);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(peer && store);
    qihse_kv_store_set_replication_principal_id(store, qihse_user_get_id(peer));
    char key[128] = "";
    for (unsigned i = 0u; i < 1000000u; ++i) {
        int n = snprintf(key, sizeof key, "commons/source-%u", i);
        assert(n > 0 && (size_t)n < sizeof key);
        if (qihse_cluster_key_slot(key, (size_t)n) == slot) break;
        key[0] = '\0';
    }
    assert(key[0] && qihse_kv_set_user(store, key, "lane-baseline", 4u, 0u, op));
    qihse_kv_snapshot_checkpoint_t bare = capture(store, op);
    uint8_t slots[QIHSE_KV_CT_SLOT_BITMAP_BYTES] = {0};
    slots[slot / 8u] |= (uint8_t)(1u << (slot % 8u));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES];
    assert(qihse_kv_ct_lane_source_enable(store, op, LANE, slots, "source-node",
        "target-node", GEN, token, 16u * 1024u * 1024u));
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    uint64_t row_seq = 0u;
    unsigned char digest[32];
    assert(qihse_kv_ct_lane_source_baseline_snapshot_create(store, op, LANE,
        &snapshot, &row_seq, digest) == 0);
    assert(snapshot && row_seq == bare.change_seq);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_lane_source_reconcile_peer(store, op, peer, LANE,
        "target-node", GEN, digest, 0u));
    qihse_kv_ct_lane_status_t status;
    assert(qihse_kv_ct_lane_status(store, op, LANE, &status) &&
        status.mode == QIHSE_KV_CT_LANE_SOURCE && status.admitted &&
        status.baseline_sealed && !status.promotion_pending &&
        status.baseline_row_seq == row_seq &&
        !memcmp(status.baseline_digest, digest, sizeof digest) &&
        status.durable_position == status.acknowledged_position);
    uint64_t marker_seq = 0u, marker_epoch = 0u;
    assert(qihse_kv_projection_marker(store, &marker_seq, &marker_epoch) &&
        marker_seq == bare.change_seq && marker_epoch);
    assert(qihse_kv_instance_id(store) == bare.instance_id);
    denied(store, op);
    assert(qihse_kv_ct_lane_status(store, op, LANE, &status) && status.admitted);
    qihse_kv_store_destroy(store);
    qihse_auth_release_principal_scoped(peer);
    qihse_auth_release_principal_scoped(op);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && !strcmp(argv[1], "--lane-source"))
        return lane_source_child(argv[2]);
    char root[] = "build/kv-checkpoint-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_LOG_DIR", root, 1) == 0);
    assert(setenv("QIHSE_OPERATOR_PASSWORD", "CheckpointOperator1!", 1) == 0);
    assert(setenv("QIHSE_AUTH_PEPPER", "local-checkpoint-test-only", 1) == 0);
    assert(qihse_auth_init());
    qihse_audit_init();
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 711u, QIHSE_ROLE_GUEST,
        0u, 0u, "CheckpointGuest1!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(op, 7u, 712u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "CheckpointForeign1!", false);
    assert(low && foreign);
    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store && qihse_kv_set_user(store, "checkpoint:protected", "original",
        5u, 1u, op));
    denied(store, NULL);
    denied(NULL, op);
    denied(store, low);
    denied(store, foreign);
    assert(!qihse_kv_snapshot_checkpoint_user(store, op, NULL));
    assert(!qihse_kv_get_user(store, "checkpoint:protected", low));
    qihse_kv_snapshot_checkpoint_t original = capture(store, op);
    assert(same(original, capture(store, op)));
    assert(original.instance_id == qihse_kv_instance_id(store));

    qihse_kv_bulk_load_begin(store);
    denied(store, op);
    qihse_kv_bulk_load_end(store);
    assert(same(original, capture(store, op)));
    qihse_kv_batch_set_record_t record = { .key = "checkpoint:batch",
        .value = "durable", .classification = 5u, .sci_compartment = 1u };
    probed_store = store;
    probed_user = op;
    probe_batch = true;
    assert(qihse_kv_set_batch_durable_user(store, &record, 1u, op));
    assert(batch_probes == 1u && !probe_batch);
    qihse_kv_snapshot_checkpoint_t mutated = capture(store, op);
    assert(mutated.instance_id == original.instance_id && mutated.change_seq > original.change_seq);

    char snapshot_path[256];
    assert(snprintf(snapshot_path, sizeof snapshot_path, "%s/source.qfs", root) > 0);
    assert(qihse_kv_save_user(store, snapshot_path, op) == 0);
    assert(same(mutated, capture(store, op)));
    FILE* input = fopen(snapshot_path, "rb");
    assert(input);
    qihse_kv_store_t* view = qihse_kv_open_snapshot_user(input, op, 1u << 20, 100u);
    assert(view && fclose(input) == 0);
    denied(view, op);
    qihse_kv_store_destroy(view);
    assert(qihse_kv_set_user(store, "checkpoint:protected", "replacement", 5u, 1u, op));
    qihse_kv_snapshot_checkpoint_t replaced = capture(store, op);
    assert(replaced.change_seq > mutated.change_seq);
    assert(qihse_kv_load_user(store, snapshot_path, op) == 0);
    qihse_kv_snapshot_checkpoint_t restored = capture(store, op);
    assert(restored.instance_id == replaced.instance_id &&
        restored.change_seq == replaced.change_seq &&
        restored.projection_epoch > replaced.projection_epoch);
    char* value = qihse_kv_get_user(store, "checkpoint:protected", op);
    assert(value && !strcmp(value, "original"));
    free(value);

    pid_t child = fork();
    assert(child >= 0);
    if (!child) { denied(store, op); _exit(0); }
    int status = 0;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(qihse_kv_sync_store(store));
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_kv_snapshot_checkpoint_t reopened = capture(store, op);
    assert(reopened.instance_id != restored.instance_id);
    assert(qihse_kv_clear_user(store, op) == 2u);
    qihse_kv_snapshot_checkpoint_t cleared = capture(store, op);
    assert(cleared.change_seq > reopened.change_seq);
    assert(qihse_kv_sync_store(store));
    assert(qihse_kv_store_enable_replica_read_only(store));
    denied(store, op);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create_user(op);
    assert(store);
    (void)capture(store, op);
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES];
    memset(owner_token, 0x81, sizeof owner_token);
    assert(qihse_kv_ct_source_enable(store, op, "checkpoint-source",
        "checkpoint-successor",
        "1111111111111111111111111111111111111111111111111111111111111111",
        owner_token, (uint64_t)QIHSE_KV_DURABLE_BATCH_MAX_BYTES + 4096u));
    denied(store, op); /* No distributed ownership snapshot is claimed. */
    qihse_kv_store_destroy(store);
    qihse_audit_shutdown();

    char lane_root[] = "build/kv-checkpoint-lane-XXXXXX";
    assert(mkdtemp(lane_root));
    child = fork();
    assert(child >= 0);
    if (!child) {
        execl("/proc/self/exe", argv[0], "--lane-source", lane_root, (char*)NULL);
        _exit(127);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0);
    puts("PASS authenticated KV checkpoint: protected denial, stable capture, batch refusal, restore epoch, handle identity and admitted SOURCE refusal");
    return 0;
}
