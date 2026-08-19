#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "qihse_dist_planner.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"

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

static void test_scoped_single_shard_plan() {
    printf("Testing single-shard scoped query planning...\n");

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo != NULL);
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);

    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);
    assert(planner != NULL);

    const char* sql = "SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=10)";
    qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, sql, NULL);

    assert(plan != NULL);
    assert(!plan->is_scatter_gather);
    assert(plan->num_tasks == 1);
    assert(plan->tasks[0].task_type == QIHSE_TASK_VECTOR_SEARCH);
    assert(strcmp(plan->tasks[0].target_entity, "{device_4096}") == 0);
    assert(plan->merge_strategy == QIHSE_MERGE_RRF);

    printf("  -> Scoped query routed to single slot %u (tasks=1, merge=RRF) OK\n", plan->tasks[0].slot);

    qihse_dist_plan_free(plan);
    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

static void test_multi_shard_scatter_gather_plan() {
    printf("Testing multi-shard scatter-gather query planning...\n");

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);
    add_helper_node(topo, "beta", "10.0.0.2", 7001, false);
    add_helper_node(topo, "gamma", "10.0.0.3", 7002, false);

    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);
    assert(planner != NULL);

    const char* qql = "MATCH (n:Sensor) WHERE ts_range(telemetry, 0, 1000000) AND AVG(cpu_temp) > 80.0 RETURN n";
    qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, qql, NULL);

    assert(plan != NULL);
    assert(plan->is_scatter_gather);
    assert(plan->num_tasks == 3); // Dispatched across all 3 nodes in topology
    assert(plan->merge_strategy == QIHSE_MERGE_AGGREGATE_AVG);

    printf("  -> Multi-shard plan created (nodes=3, tasks=3, is_scatter_gather=true) OK\n");

    qihse_dist_plan_free(plan);
    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

static void test_dist_plan_execution() {
    printf("Testing distributed plan execution and result fusion...\n");

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    add_helper_node(topo, "alpha", "10.0.0.1", 7000, true);
    add_helper_node(topo, "beta", "10.0.0.2", 7001, false);

    qihse_dist_planner_t* planner = qihse_dist_planner_create(topo);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    qihse_kv_set(kv, "{device_4096}", "device_active_state", 0, 0);

    const char* sql = "SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=5)";
    qihse_dist_plan_t* plan = qihse_dist_plan_query(planner, sql, NULL);
    assert(plan != NULL);

    qihse_dist_query_result_t* res = qihse_dist_execute_plan(
        planner, plan, kv, NULL, NULL, NULL, NULL, NULL
    );

    assert(res != NULL);
    assert(!res->is_error);
    assert(res->num_rows >= 1);
    printf("  -> Execution completed in %llu ns (rows=%zu)\n", (unsigned long long)res->execution_time_ns, res->num_rows);

    qihse_dist_query_result_free(res);
    qihse_dist_plan_free(plan);
    qihse_kv_store_destroy(kv);
    qihse_dist_planner_destroy(planner);
    qihse_cluster_topology_destroy(topo);
}

int main() {
    printf("========================================================\n");
    printf("  QIHSE Distributed SQL/QQL Multi-Engine Planner Tests  \n");
    printf("========================================================\n");

    test_scoped_single_shard_plan();
    test_multi_shard_scatter_gather_plan();
    test_dist_plan_execution();

    printf("\nAll Distributed Multi-Engine Planner Tests PASSED!\n");
    return 0;
}
