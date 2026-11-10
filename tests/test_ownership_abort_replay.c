/* Regression coverage for idempotent recovery of a completed CT2 abort. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>

#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_cluster_ownership.h"
#include "qihse_cluster_slot.h"

typedef struct {
    char source[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char target[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
} peer_map_t;

static bool peer_id(void* opaque, const char* topology_id,
    char out[QIHSE_KV_CT_ID_MAX + 1u]) {
    const peer_map_t* map = opaque;
    if (!map || !topology_id || !out) return false;
    if (!strcmp(topology_id, map->source)) {
        snprintf(out, QIHSE_KV_CT_ID_MAX + 1u, "%s", "source:1");
        return true;
    }
    if (!strcmp(topology_id, map->target)) {
        snprintf(out, QIHSE_KV_CT_ID_MAX + 1u, "%s", "target:1");
        return true;
    }
    return false;
}

static void remove_fixture(const char* path) {
    DIR* dir = opendir(path);
    assert(dir);
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        assert(unlinkat(dirfd(dir), entry->d_name, 0) == 0);
    }
    assert(closedir(dir) == 0);
    assert(rmdir(path) == 0);
}

static qihse_cluster_node_t node_from_seed(const char* seed, uint16_t port) {
    qihse_cluster_node_t node = {0};
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
    snprintf(node.host, sizeof(node.host), "127.0.0.1");
    node.port = port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = true;
    return node;
}

int main(void) {
    char data_dir[] = "./build/ownership_abort_replay_XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OwnershipAbortReplay-Op-Password-9!"));
    qihse_user_t* operator = qihse_auth_get_user(0u);
    assert(operator && qihse_auth_user_is_active(operator));
    qihse_kv_store_t* store = qihse_kv_store_create_user(operator);
    assert(store);

    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology);
    qihse_cluster_node_t source = node_from_seed("abort-source", 7100u);
    qihse_cluster_node_t target = node_from_seed("abort-target", 7101u);
    uint16_t source_index = QIHSE_CLUSTER_NODE_NONE;
    uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topology, &source, &source_index));
    assert(qihse_cluster_topology_upsert_node(topology, &target, &target_index));
    assert(qihse_cluster_topology_set_local_node(topology, source_index));
    peer_map_t peers = {0};
    snprintf(peers.source, sizeof(peers.source), "%s", source.id);
    snprintf(peers.target, sizeof(peers.target), "%s", target.id);
    qihse_cluster_ownership_context_t ownership = {
        .topology = topology, .store = store, .principal = operator,
        .peer_id = peer_id, .peer_id_context = &peers
    };

    assert(qihse_kv_ct_source_enable(store, operator, "source:1", "target:1",
        "generation-3", NULL, 128u * 1024u * 1024u));
    unsigned char token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    unsigned char baseline_digest[32] = {0};
    uint64_t baseline_seq = 0u, source_cut = 0u;
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    assert(qihse_kv_ct_owner_token_get(store, operator, token));
    assert(qihse_kv_ct_source_baseline_snapshot_create(store, operator,
        &snapshot, &baseline_seq, baseline_digest) == 0);
    assert(snapshot);
    qihse_kv_replica_snapshot_destroy(snapshot);
    assert(qihse_kv_ct_source_reconcile(store, operator, "target:1",
        "generation-3", baseline_digest, baseline_seq));
    assert(qihse_kv_ct_fence_range(store, operator, "abort-replay-test",
        500u, 550u, token, &source_cut));

    qihse_cluster_ownership_txn_t prepared = {0};
    prepared.phase = QIHSE_OWNERSHIP_PREPARED;
    prepared.start = 500u; prepared.end = 550u; prepared.config_epoch = 9u;
    prepared.source_lsn = source_cut;
    snprintf(prepared.transfer_id, sizeof(prepared.transfer_id), "%s", "abort-replay-test");
    snprintf(prepared.source_id, sizeof(prepared.source_id), "%s", source.id);
    snprintf(prepared.target_id, sizeof(prepared.target_id), "%s", target.id);
    snprintf(prepared.source_qkp_id, sizeof(prepared.source_qkp_id), "%s", "source:1");
    snprintf(prepared.target_qkp_id, sizeof(prepared.target_qkp_id), "%s", "target:1");
    snprintf(prepared.generation, sizeof(prepared.generation), "%s", "generation-3");
    snprintf(prepared.owner_id, sizeof(prepared.owner_id), "%s", source.id);
    assert(qihse_cluster_ownership_journal_append_txn(data_dir, &prepared) == 0);
    qihse_cluster_ownership_txn_t aborted = prepared;
    aborted.phase = QIHSE_OWNERSHIP_ABORTED;
    assert(qihse_cluster_ownership_journal_append_txn(data_dir, &aborted) == 0);

    bool unresolved = true;
    char error[256] = {0};
    assert(qihse_cluster_ownership_replay_control(&ownership, &unresolved,
        error, sizeof(error)));
    assert(!unresolved);
    /* Simulates a later daemon restart after the first replay released it. */
    assert(qihse_cluster_ownership_replay_control(&ownership, &unresolved,
        error, sizeof(error)));
    assert(!unresolved);

    /* A terminal transfer ID cannot be restarted for another range. INTENT
     * is rejected before the source can persist a new range fence. */
    qihse_cluster_ownership_txn_t reused_id = aborted;
    reused_id.phase = QIHSE_OWNERSHIP_INTENT;
    reused_id.start++;
    errno = 0;
    assert(qihse_cluster_ownership_journal_append_txn(data_dir,
        &reused_id) == -1 && errno == EEXIST);
    qihse_kv_ct_transfer_status_t after_reuse = {0};
    assert(qihse_kv_ct_transfer_status(store, operator, &after_reuse));
    assert(after_reuse.fence_state == 0u);

    /* A later unfinished transaction may already own the active fence when
     * replay reaches the older ABORTED entry. The old entry must defer to the
     * final journal state, and the later fence must remain active. */
    assert(qihse_kv_ct_fence_range(store, operator, "different-active-transfer",
        600u, 610u, token, &source_cut));
    qihse_cluster_ownership_txn_t later = prepared;
    later.phase = QIHSE_OWNERSHIP_PREPARED;
    later.start = 600u; later.end = 610u; later.source_lsn = source_cut;
    snprintf(later.transfer_id, sizeof(later.transfer_id), "%s", "different-active-transfer");
    assert(qihse_cluster_ownership_journal_append_txn(data_dir, &later) == 0);
    assert(qihse_cluster_ownership_replay_control(&ownership, &unresolved,
        error, sizeof(error)));
    assert(unresolved);
    qihse_kv_ct_transfer_status_t status = {0};
    assert(qihse_kv_ct_transfer_status(store, operator, &status));
    assert(status.fence_state == 1u &&
        !strcmp(status.transfer_id, "different-active-transfer"));

    /* A fence that does not match the journal's final pending transaction
     * remains a hard failure; the deferred historical abort cannot bless it. */
    assert(qihse_kv_ct_fence_finish(store, operator,
        "different-active-transfer", false, token));
    assert(qihse_kv_ct_fence_range(store, operator, "unrelated-active-transfer",
        700u, 710u, token, &source_cut));
    assert(!qihse_cluster_ownership_replay_control(&ownership, &unresolved,
        error, sizeof(error)));
    assert(strstr(error, "active CT fence does not match"));

    OPENSSL_cleanse(token, sizeof(token));
    qihse_cluster_topology_destroy(topology);
    qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    remove_fixture(data_dir);
    puts("ownership abort replay: PASS");
    return 0;
}
