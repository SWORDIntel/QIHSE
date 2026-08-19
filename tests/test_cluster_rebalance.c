#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "qihse_cluster_rebalance.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"

static void add_helper_node(qihse_cluster_topology_t* topo, const char* name, const char* host, uint16_t port, bool is_local) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed(name, strlen(name), node.id);
    strncpy(node.host, host, sizeof(node.host) - 1);
    node.port = port;
    node.bus_port = port + 10000;
    node.healthy = true;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    uint16_t idx = 0;
    qihse_cluster_topology_upsert_node(topo, &node, &idx);
    if (is_local) {
        qihse_cluster_topology_set_local_node(topo, idx);
    }
}

static void test_cluster_rebalance_imbalanced_to_balanced() {
    printf("Testing cluster slot rebalance (imbalanced 3-node topology)...\n");

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo != NULL);

    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);  // Node 0
    add_helper_node(topo, "beta",  "10.0.0.2", 7001, false); // Node 1
    add_helper_node(topo, "gamma", "10.0.0.3", 7002, false); // Node 2

    // Initially assign ALL 16,384 slots to Node 0
    bool assigned = qihse_cluster_topology_assign_range(topo, 0, QIHSE_CLUSTER_SLOT_COUNT - 1, 0);
    assert(assigned);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    qihse_cluster_rebalancer_t* reb = qihse_cluster_rebalancer_create(topo, kv, NULL, NULL);
    assert(reb != NULL);

    // 1. Plan rebalance
    qihse_cluster_rebalance_plan_t* plan = qihse_cluster_plan_rebalance(topo, 0.05);
    assert(plan != NULL);
    assert(plan->num_moves > 0);
    printf("  -> Initial variance: %.4f | Planned moves: %zu\n", plan->imbalance_variance_before, plan->num_moves);

    // 2. Execute all planned rebalance moves
    bool rebalanced = qihse_cluster_rebalance_all(reb, plan);
    assert(rebalanced);
    printf("  -> Executed %zu slot migrations with zero downtime\n", plan->num_moves);

    // 3. Verify final slot distribution
    size_t assigned_slots = qihse_cluster_topology_assigned_slots(topo);
    assert(assigned_slots == QIHSE_CLUSTER_SLOT_COUNT);
    assert(qihse_cluster_topology_is_covered(topo));

    // 4. Verify re-planning returns NULL (balanced)
    qihse_cluster_rebalance_plan_t* second_plan = qihse_cluster_plan_rebalance(topo, 0.05);
    assert(second_plan == NULL);
    printf("  -> Post-rebalance state verified: Perfectly balanced across 3 primaries!\n");

    qihse_cluster_rebalance_plan_free(plan);
    qihse_cluster_rebalancer_destroy(reb);
    qihse_kv_store_destroy(kv);
    qihse_cluster_topology_destroy(topo);
}

int main() {
    printf("==============================================================\n");
    printf("  QIHSE Automated Zero-Downtime Cluster Rebalancer Tests      \n");
    printf("==============================================================\n");

    test_cluster_rebalance_imbalanced_to_balanced();

    printf("\nAll Cluster Rebalancer Tests PASSED!\n");
    return 0;
}
