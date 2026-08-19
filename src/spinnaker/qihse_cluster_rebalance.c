#include "qihse_cluster_rebalance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct qihse_cluster_rebalancer {
    qihse_cluster_topology_t* topo;
    qihse_kv_store_t* kv;
    qihse_vector_db_t vdb;
    qihse_cluster_bus_t* bus;
};

qihse_cluster_rebalancer_t* qihse_cluster_rebalancer_create(
    qihse_cluster_topology_t* topo,
    qihse_kv_store_t* kv,
    qihse_vector_db_t vdb,
    qihse_cluster_bus_t* bus
) {
    if (!topo) return NULL;
    qihse_cluster_rebalancer_t* reb = (qihse_cluster_rebalancer_t*)calloc(1, sizeof(qihse_cluster_rebalancer_t));
    if (!reb) return NULL;
    reb->topo = topo;
    reb->kv = kv;
    reb->vdb = vdb;
    reb->bus = bus;
    return reb;
}

void qihse_cluster_rebalancer_destroy(qihse_cluster_rebalancer_t* rebalancer) {
    if (rebalancer) {
        free(rebalancer);
    }
}

static void plan_add_move(qihse_cluster_rebalance_plan_t* plan, uint16_t slot, uint16_t src, uint16_t dst) {
    if (plan->num_moves >= plan->capacity) {
        size_t new_cap = plan->capacity ? plan->capacity * 2 : 64;
        qihse_slot_move_t* new_moves = (qihse_slot_move_t*)realloc(plan->moves, new_cap * sizeof(qihse_slot_move_t));
        if (!new_moves) return;
        plan->moves = new_moves;
        plan->capacity = new_cap;
    }
    qihse_slot_move_t* m = &plan->moves[plan->num_moves++];
    m->slot = slot;
    m->source_node_idx = src;
    m->target_node_idx = dst;
    m->completed = false;
    m->keys_migrated = 0;
    m->bytes_migrated = 0;
}

qihse_cluster_rebalance_plan_t* qihse_cluster_plan_rebalance(
    qihse_cluster_topology_t* topo,
    double threshold_imbalance
) {
    if (!topo) return NULL;

    size_t node_count = qihse_cluster_topology_nodes(topo, NULL, 0);
    if (node_count <= 1) return NULL;

    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t active_nodes = qihse_cluster_topology_nodes(topo, nodes, QIHSE_CLUSTER_MAX_NODES);

    // Count primary nodes and slots
    uint16_t primary_indices[QIHSE_CLUSTER_MAX_NODES];
    size_t primary_count = 0;

    for (size_t i = 0; i < active_nodes; i++) {
        if (nodes[i].role == QIHSE_CLUSTER_NODE_PRIMARY && nodes[i].healthy) {
            primary_indices[primary_count++] = (uint16_t)i;
        }
    }

    if (primary_count <= 1) return NULL;

    qihse_cluster_rebalance_plan_t* plan = (qihse_cluster_rebalance_plan_t*)calloc(1, sizeof(qihse_cluster_rebalance_plan_t));
    if (!plan) return NULL;

    // Count slots per node
    for (uint16_t s = 0; s < QIHSE_CLUSTER_SLOT_COUNT; s++) {
        uint16_t owner = 0;
        if (qihse_cluster_topology_get_slot(topo, s, &owner, NULL, NULL)) {
            if (owner < QIHSE_CLUSTER_MAX_NODES) {
                plan->node_slot_counts_before[owner]++;
            }
        }
    }

    memcpy(plan->node_slot_counts_after, plan->node_slot_counts_before, sizeof(plan->node_slot_counts_before));

    uint16_t target_per_node = (uint16_t)(QIHSE_CLUSTER_SLOT_COUNT / primary_count);

    // Calculate initial variance
    double sum_diff = 0.0;
    for (size_t p = 0; p < primary_count; p++) {
        uint16_t idx = primary_indices[p];
        double diff = (double)plan->node_slot_counts_before[idx] - (double)target_per_node;
        sum_diff += fabs(diff);
    }
    plan->imbalance_variance_before = sum_diff / (double)QIHSE_CLUSTER_SLOT_COUNT;

    if (plan->imbalance_variance_before < threshold_imbalance) {
        // Already balanced within threshold
        qihse_cluster_rebalance_plan_free(plan);
        return NULL;
    }

    // Plan slot transfers from donors to receivers
    for (uint16_t s = 0; s < QIHSE_CLUSTER_SLOT_COUNT; s++) {
        uint16_t owner = 0;
        if (!qihse_cluster_topology_get_slot(topo, s, &owner, NULL, NULL)) continue;

        if (plan->node_slot_counts_after[owner] > target_per_node) {
            // Find a receiver node needing slots
            for (size_t p = 0; p < primary_count; p++) {
                uint16_t receiver = primary_indices[p];
                if (plan->node_slot_counts_after[receiver] < target_per_node) {
                    plan_add_move(plan, s, owner, receiver);
                    plan->node_slot_counts_after[owner]--;
                    plan->node_slot_counts_after[receiver]++;
                    break;
                }
            }
        }
    }

    // Calculate final variance
    double final_diff = 0.0;
    for (size_t p = 0; p < primary_count; p++) {
        uint16_t idx = primary_indices[p];
        double diff = (double)plan->node_slot_counts_after[idx] - (double)target_per_node;
        final_diff += fabs(diff);
    }
    plan->imbalance_variance_after = final_diff / (double)QIHSE_CLUSTER_SLOT_COUNT;

    return plan;
}

bool qihse_cluster_execute_rebalance_step(
    qihse_cluster_rebalancer_t* rebalancer,
    qihse_cluster_rebalance_plan_t* plan,
    size_t move_idx
) {
    if (!rebalancer || !plan || move_idx >= plan->num_moves) return false;

    qihse_slot_move_t* move = &plan->moves[move_idx];
    if (move->completed) return true;

    // 1. Begin migration (-ASK state on donor, importing on receiver)
    qihse_cluster_migration_t* mig = qihse_cluster_migration_begin(
        rebalancer->topo, move->slot, move->source_node_idx, move->target_node_idx
    );
    if (!mig) return false;

    // 2. Stream data (simulated chunk transfer of slot keys)
    qihse_cluster_migration_mark_streamed(mig, 256);
    move->keys_migrated = 1;
    move->bytes_migrated = 256;

    // 3. Atomically commit migration to stable target ownership
    if (!qihse_cluster_migration_commit(mig)) {
        qihse_cluster_migration_abort(mig);
        qihse_cluster_migration_destroy(mig);
        return false;
    }

    qihse_cluster_migration_destroy(mig);
    move->completed = true;
    return true;
}

bool qihse_cluster_rebalance_all(
    qihse_cluster_rebalancer_t* rebalancer,
    qihse_cluster_rebalance_plan_t* plan
) {
    if (!rebalancer || !plan) return false;

    for (size_t i = 0; i < plan->num_moves; i++) {
        if (!qihse_cluster_execute_rebalance_step(rebalancer, plan, i)) {
            return false;
        }
    }
    return true;
}

void qihse_cluster_rebalance_plan_free(qihse_cluster_rebalance_plan_t* plan) {
    if (plan) {
        if (plan->moves) free(plan->moves);
        free(plan);
    }
}
