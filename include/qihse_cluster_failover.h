#ifndef QIHSE_CLUSTER_FAILOVER_H
#define QIHSE_CLUSTER_FAILOVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_maintenance.h"
#include "qihse_kv_store.h"
#include "qihse_qkp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QIHSE Cluster Failover Coordinator
 *
 * Monitors cluster node health via the cluster bus heartbeat protocol.
 * When a primary (master) node is detected as failed, the coordinator
 * promotes the highest-priority replica for that primary's slot ranges
 * and broadcasts the ownership change to all peers.
 *
 * The coordinator is driven by callbacks from the cluster bus
 * (on_fail callback) and can also be invoked manually.
 */

typedef struct qihse_cluster_failover qihse_cluster_failover_t;
typedef struct qihse_cluster_ownership_context qihse_cluster_ownership_context_t;

/* Explicit, operator-provisioned mapping. Topology IDs and QKP identities are
 * distinct namespaces; implementations must resolve through a trusted pin
 * registry and must not infer a QKP identity from an address or bus hint. */
typedef bool (*qihse_cluster_topology_qkp_id_fn)(
    void* context, const char* topology_node_id,
    char out_qkp_node_id[QIHSE_QKP_NODE_ID_LEN + 1u]);
/* Trusted embedding adapter to the cluster consensus lease/quorum state.
 * It must validate the current term and election authority for this exact
 * source/target and durable cursor; absence means promotion is denied. */
typedef bool (*qihse_cluster_ct_election_authorized_fn)(
    void* context, const char* topology_source_id, const char* topology_target_id,
    const char* generation, uint64_t durable_cursor);

/* Failback hook: hand slots [first,last] back to `target_index` (the original
 * owner that has returned) INCLUDING the data written while the successor
 * served them. Must be COPY -> PERSIST -> SWITCH (see
 * qihse_cluster_handoff_range) and must NOT change ownership unless the data
 * reached the target. Return 0 on success, non-zero (with `err` filled) to
 * retry later. Runs on the coordinator's worker thread, never the bus thread. */
typedef int (*qihse_cluster_failback_fn)(void* user_data, uint16_t first, uint16_t last,
                                         uint16_t target_index, char* err, size_t err_cap);

/* Completion of a durable promotion is runtime work, not gossip authority.
 * Retry with the same generation until its endpoint and baseline are ready. */
typedef bool (*qihse_cluster_ct_complete_fn)(void* context,
    uint16_t successor_index, const char generation[33]);

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    qihse_cluster_maintenance_t* maintenance_gate; /* borrowed */
    /* CT1 proof path is available only when the embedding supplies the live
     * authenticated KV handle and explicit service principal. Legacy
     * health-only promotion remains fail-closed for data-bearing ranges. */
    qihse_kv_store_t* ct_store; /* borrowed */
    qihse_user_t* ct_principal; /* borrowed; never inferred from NULL */
    /* Optional stable CT lane ID (64 lowercase hex). When supplied, failover
     * promotes this exact replication group and its exact bitmap; legacy
     * single-receiver promotion remains selected only when empty. */
    char ct_lane_id[65];
    char ct_local_qkp_id[QIHSE_QKP_NODE_ID_LEN + 1u];
    qihse_cluster_topology_qkp_id_fn topology_qkp_id;
    void* topology_qkp_id_context;
    qihse_cluster_ct_election_authorized_fn ct_election_authorized;
    void* ct_election_context;
    /* Opt-in automatic mode uses a provisioned, distinct slotless spare.
     * A failed completion leaves the new primary control-only and is retried. */
    const char* ct_auto_successor_id;
    qihse_cluster_ct_complete_fn ct_complete;
    void* ct_complete_context;
    uint16_t local_node_index;
    /* If true, only the local node performs failover (single coordinator
     * mode).  If false, any node may promote replicas (distributed mode,
     * requires deterministic replica ordering to avoid split-brain). */
    bool single_coordinator;
    /* Failback. When failback_fn is set, ranges this node takes over through the
     * sharded fallback are ledgered and handed back once the original owner has
     * been continuously healthy for failback_stable_ms (default 3000), polling
     * every failback_poll_ms (default 1000); failures retry with exponential
     * backoff. Dedicated-replica promotion is NOT failed back: the old primary
     * rejoins as a replica there. */
    qihse_cluster_failback_fn failback_fn;
    void* failback_user_data;
    uint32_t failback_stable_ms;
    uint32_t failback_poll_ms;
} qihse_cluster_failover_config_t;

qihse_cluster_failover_t* qihse_cluster_failover_create(const qihse_cluster_failover_config_t* config);
/* Startup-only ownership hold. create_paused installs it before the worker
 * starts. pause_startup is for a coordinator not yet exposed to bus callbacks
 * or manual promotion; it rejects one that has already received either.
 * This is NOT a live drain, write fence, or gossip/GC fence. */
qihse_cluster_failover_t* qihse_cluster_failover_create_paused(const qihse_cluster_failover_config_t* config);
bool qihse_cluster_failover_pause_startup(qihse_cluster_failover_t* fo);
bool qihse_cluster_failover_is_paused(qihse_cluster_failover_t* fo);
/* Called by the embedding after automatic and takeover callbacks are installed. */
bool qihse_cluster_failover_register_maintenance(qihse_cluster_failover_t* fo);
/* Trusted embedding control: returns true only when a hold was released.
 * Externally reachable callers must authenticate/authorize the release. */
bool qihse_cluster_failover_resume(qihse_cluster_failover_t* fo);
void qihse_cluster_failover_destroy(qihse_cluster_failover_t* fo);

/*
 * Called when a node has been marked as failed.  If the failed node is a
 * primary, this promotes the best replica to primary and reassigns the
 * failed node's slot ranges to the promoted replica.  Returns the node
 * index of the promoted replica, or QIHSE_CLUSTER_NODE_NONE if no
 * failover was performed.
 */
uint16_t qihse_cluster_failover_handle(qihse_cluster_failover_t* fo,
                                       uint16_t failed_node_index);

/* Bus callback adapter — can be used directly as on_fail. */
void qihse_cluster_failover_on_fail_cb(qihse_cluster_topology_t* topology,
                                       uint16_t failed_node_index,
                                       void* user_data);

/* Manually promote a specific replica to primary for a failed primary's
 * slot ranges.  Returns true if the promotion succeeded. */
bool qihse_cluster_failover_promote(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index);

/* CT1 promotion for the local, dedicated replica only. Builds and validates
 * an opaque proof from the receiver's persisted generation/cursor, durably
 * retires that generation before slot ownership changes, and appends v2
 * ownership transitions. The selected successor is a topology index resolved
 * through the configured pin map. Returns the new 32-character generation
 * required to configure the promoted source. Caller-supplied proof fields are
 * not accepted. */
bool qihse_cluster_failover_promote_ct(qihse_cluster_failover_t* fo,
                                       uint16_t failed_primary_index,
                                       uint16_t replica_index,
                                       uint16_t new_successor_index,
                                       char out_new_generation[33],
                                       char* err, size_t err_cap);

/* Promote one explicitly selected replication lane after its source has
 * failed. The ownership context supplies the authenticated store, group
 * authority, local peer pins, bus signer, and successor-preparation adapter.
 * A false return with out_pending=true means durable work was started and the
 * caller should retry this same lane; it must not start a second promotion. */
bool qihse_cluster_failover_promote_lane(
    qihse_cluster_ownership_context_t* ownership,
    const char* lane_id, uint16_t new_successor_index,
    bool* out_pending, char* err, size_t err_cap);

/* Find the best replica for a given primary.  "Best" is the replica with
 * the lowest node index (deterministic).  Returns QIHSE_CLUSTER_NODE_NONE
 * if no replica exists. */
uint16_t qihse_cluster_failover_best_replica(const qihse_cluster_topology_t* topology,
                                             uint16_t primary_index);

/* Read-only eligibility check for a new CT1 successor: it must be a distinct,
 * healthy configured node with no owned slots, so its first full baseline
 * cannot overwrite unrelated primary data. */
bool qihse_cluster_failover_ct_successor_slotless(
    const qihse_cluster_topology_t* topology,
    uint16_t failed_primary_index, uint16_t promoted_local_index,
    uint16_t new_successor_index, char* err, size_t err_cap);

/* Get the number of failover events that have been processed. */
uint64_t qihse_cluster_failover_events(const qihse_cluster_failover_t* fo);

/* Bus takeover callback adapter: ledger a range another node's coordinator
 * handed to THIS node, so it is failed back when the previous owner returns. */
void qihse_cluster_failover_on_takeover_cb(qihse_cluster_topology_t* topology,
                                           uint16_t previous_owner_index,
                                           uint16_t start, uint16_t end,
                                           void* user_data);

/* Completed failbacks (a range handed back to its returned owner). */
uint64_t qihse_cluster_failover_failbacks(const qihse_cluster_failover_t* fo);

/* Ledgered ranges still awaiting failback. */
size_t qihse_cluster_failover_pending_failbacks(const qihse_cluster_failover_t* fo);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_FAILOVER_H */
