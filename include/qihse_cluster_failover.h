#ifndef QIHSE_CLUSTER_FAILOVER_H
#define QIHSE_CLUSTER_FAILOVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"

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

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    uint16_t local_node_index;
    /* If true, only the local node performs failover (single coordinator
     * mode).  If false, any node may promote replicas (distributed mode,
     * requires deterministic replica ordering to avoid split-brain). */
    bool single_coordinator;
} qihse_cluster_failover_config_t;

qihse_cluster_failover_t* qihse_cluster_failover_create(const qihse_cluster_failover_config_t* config);
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

/* Find the best replica for a given primary.  "Best" is the replica with
 * the lowest node index (deterministic).  Returns QIHSE_CLUSTER_NODE_NONE
 * if no replica exists. */
uint16_t qihse_cluster_failover_best_replica(const qihse_cluster_topology_t* topology,
                                             uint16_t primary_index);

/* Get the number of failover events that have been processed. */
uint64_t qihse_cluster_failover_events(const qihse_cluster_failover_t* fo);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_FAILOVER_H */
