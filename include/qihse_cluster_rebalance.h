#ifndef QIHSE_CLUSTER_REBALANCE_H
#define QIHSE_CLUSTER_REBALANCE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_cluster_slot.h"
#include "qihse_cluster_migrate.h"
#include "qihse_cluster_bus.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t slot;
    uint16_t source_node_idx;
    uint16_t target_node_idx;
    bool completed;
    uint64_t keys_migrated;
    uint64_t bytes_migrated;
} qihse_slot_move_t;

typedef struct {
    qihse_slot_move_t* moves;
    size_t num_moves;
    size_t capacity;
    uint16_t node_slot_counts_before[QIHSE_CLUSTER_MAX_NODES];
    uint16_t node_slot_counts_after[QIHSE_CLUSTER_MAX_NODES];
    double imbalance_variance_before;
    double imbalance_variance_after;
} qihse_cluster_rebalance_plan_t;

typedef struct qihse_cluster_rebalancer qihse_cluster_rebalancer_t;

/**
 * @brief Creates an automated zero-downtime cluster rebalancer instance.
 */
qihse_cluster_rebalancer_t* qihse_cluster_rebalancer_create(
    qihse_cluster_topology_t* topo,
    qihse_kv_store_t* kv,
    qihse_vector_db_t vdb,
    qihse_cluster_bus_t* bus
);

/**
 * @brief Destroys the cluster rebalancer instance.
 */
void qihse_cluster_rebalancer_destroy(qihse_cluster_rebalancer_t* rebalancer);

/**
 * @brief Analyzes cluster slot distribution and computes an optimal migration plan.
 * 
 * @param topo Active cluster topology.
 * @param threshold_imbalance Minimum slot variance threshold (e.g. 0.05 for 5%) to trigger moves.
 * @return Allocated rebalance plan, or NULL on failure / if already balanced.
 */
qihse_cluster_rebalance_plan_t* qihse_cluster_plan_rebalance(
    qihse_cluster_topology_t* topo,
    double threshold_imbalance
);

/**
 * @brief Executes a single planned slot migration move with zero downtime (-ASK handoff).
 */
bool qihse_cluster_execute_rebalance_step(
    qihse_cluster_rebalancer_t* rebalancer,
    qihse_cluster_rebalance_plan_t* plan,
    size_t move_idx
);

/**
 * @brief Executes all planned slot migrations sequentially across the cluster.
 */
bool qihse_cluster_rebalance_all(
    qihse_cluster_rebalancer_t* rebalancer,
    qihse_cluster_rebalance_plan_t* plan
);

/**
 * @brief Frees an allocated cluster rebalance plan.
 */
void qihse_cluster_rebalance_plan_free(qihse_cluster_rebalance_plan_t* plan);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_REBALANCE_H */
