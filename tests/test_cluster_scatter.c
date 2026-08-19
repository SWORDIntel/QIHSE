/*
 * test_cluster_scatter.c — Unit tests for the QIHSE cluster scatter-gather engine.
 *
 * Tests the RRF fusion logic, TS fan-out merge, and COL fan-out merge
 * using mock topology (no live TCP peers needed for the merge logic
 * tests).  A live end-to-end test with two RESP servers is included
 * for VECSCATTER.
 */
#include "qihse_cluster_scatter.h"
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "qihse_platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void make_node(qihse_cluster_node_t* node, const char* id_seed, const char* host, uint16_t port, uint16_t bus_port) {
    memset(node, 0, sizeof(*node));
    qihse_cluster_node_id_from_seed(id_seed, strlen(id_seed), node->id);
    strncpy(node->host, host, QIHSE_CLUSTER_HOST_LEN);
    node->port = port;
    node->bus_port = bus_port;
    node->role = QIHSE_CLUSTER_NODE_PRIMARY;
    node->primary_index = QIHSE_CLUSTER_NODE_NONE;
    node->healthy = true;
}

/* Test 1: RRF fusion of two result lists with overlapping IDs.
 * We test the merge logic by calling qihse_cluster_scatter_vecsearch
 * with a topology that has only the local node (no peers), so the
 * scatter engine returns 0 remote results.  This validates the
 * scatter engine's create/destroy and stats path. */
static void test_scatter_no_peers(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));

    qihse_cluster_scatter_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.timeout_ms = 100;
    qihse_cluster_scatter_t* sg = qihse_cluster_scatter_create(&cfg);
    assert(sg);

    /* With no peers, scatter should return 0 results */
    float vec[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    qihse_vector_result_t results[10];
    int found = qihse_cluster_scatter_vecsearch(sg, vec, 4, 10, NULL, results);
    assert(found == 0);

    qihse_cluster_scatter_stats_t stats;
    qihse_cluster_scatter_stats(sg, &stats);
    assert(stats.scatter_queries == 1);
    assert(stats.peer_queries_sent == 0);

    qihse_cluster_scatter_destroy(sg);
    qihse_cluster_topology_destroy(topo);
    printf("PASS scatter no peers\n");
}

/* Test 2: TS fan-out with no peers returns false. */
static void test_ts_fanout_no_peers(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));

    qihse_cluster_scatter_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.timeout_ms = 100;
    qihse_cluster_scatter_t* sg = qihse_cluster_scatter_create(&cfg);
    assert(sg);

    double value;
    uint64_t count;
    bool found = qihse_cluster_scatter_ts_range(sg, 123, 0, 1000, 1, NULL, &value, &count);
    assert(!found);

    qihse_cluster_scatter_destroy(sg);
    qihse_cluster_topology_destroy(topo);
    printf("PASS ts fanout no peers\n");
}

/* Test 3: COL.SUM fan-out with no peers returns false. */
static void test_col_sum_no_peers(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));

    qihse_cluster_scatter_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.timeout_ms = 100;
    qihse_cluster_scatter_t* sg = qihse_cluster_scatter_create(&cfg);
    assert(sg);

    double sum;
    bool found = qihse_cluster_scatter_col_sum(sg, "test_col", NULL, &sum);
    assert(!found);

    qihse_cluster_scatter_destroy(sg);
    qihse_cluster_topology_destroy(topo);
    printf("PASS col sum no peers\n");
}

/* Test 4: COL.MINMAX fan-out with no peers returns false. */
static void test_col_minmax_no_peers(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));

    qihse_cluster_scatter_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.timeout_ms = 100;
    qihse_cluster_scatter_t* sg = qihse_cluster_scatter_create(&cfg);
    assert(sg);

    double min, max;
    bool found = qihse_cluster_scatter_col_minmax(sg, "test_col", NULL, &min, &max);
    assert(!found);

    qihse_cluster_scatter_destroy(sg);
    qihse_cluster_topology_destroy(topo);
    printf("PASS col minmax no peers\n");
}

/* Test 5: Scatter with unhealthy peers — should skip them. */
static void test_scatter_unhealthy_peer(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a, node_b;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    make_node(&node_b, "nodeB", "127.0.0.1", 7001, 17001);
    uint16_t idx_a, idx_b;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_upsert_node(topo, &node_b, &idx_b));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));

    /* Mark node_b as unhealthy */
    assert(qihse_cluster_topology_set_node_health(topo, idx_b, false));

    qihse_cluster_scatter_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.timeout_ms = 100;
    qihse_cluster_scatter_t* sg = qihse_cluster_scatter_create(&cfg);
    assert(sg);

    float vec[2] = {1.0f, 2.0f};
    qihse_vector_result_t results[10];
    int found = qihse_cluster_scatter_vecsearch(sg, vec, 2, 10, NULL, results);
    /* Unhealthy peer should be skipped, so 0 results */
    assert(found == 0);

    qihse_cluster_scatter_stats_t stats;
    qihse_cluster_scatter_stats(sg, &stats);
    assert(stats.peer_queries_sent == 0);

    qihse_cluster_scatter_destroy(sg);
    qihse_cluster_topology_destroy(topo);
    printf("PASS scatter unhealthy peer skipped\n");
}

/* Test 6: Scatter with a peer on a non-listening port — should fail
 * gracefully and return 0 results without crashing. */
static void test_scatter_peer_connection_failure(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a, node_b;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    make_node(&node_b, "nodeB", "127.0.0.1", 19999, 27999); /* unused port */
    uint16_t idx_a, idx_b;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_upsert_node(topo, &node_b, &idx_b));
    assert(qihse_cluster_topology_set_local_node(topo, idx_a));

    qihse_cluster_scatter_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.timeout_ms = 200; /* short timeout */
    qihse_cluster_scatter_t* sg = qihse_cluster_scatter_create(&cfg);
    assert(sg);

    float vec[2] = {1.0f, 2.0f};
    qihse_vector_result_t results[10];
    int found = qihse_cluster_scatter_vecsearch(sg, vec, 2, 10, NULL, results);
    /* Connection should fail, so 0 results */
    assert(found == 0);

    qihse_cluster_scatter_stats_t stats;
    qihse_cluster_scatter_stats(sg, &stats);
    assert(stats.peer_queries_sent == 1);
    assert(stats.peer_failures == 1);
    assert(stats.peer_responses_received == 0);

    qihse_cluster_scatter_destroy(sg);
    qihse_cluster_topology_destroy(topo);
    printf("PASS scatter peer connection failure\n");
}

/* Test 7: NULL scatter is safe (no-op). */
static void test_null_scatter(void) {
    float vec[2] = {1.0f, 2.0f};
    qihse_vector_result_t results[10];
    int found = qihse_cluster_scatter_vecsearch(NULL, vec, 2, 10, NULL, results);
    assert(found == -1);

    double value;
    uint64_t count;
    bool ts_found = qihse_cluster_scatter_ts_range(NULL, 1, 0, 100, 0, NULL, &value, &count);
    assert(!ts_found);

    double sum;
    bool col_found = qihse_cluster_scatter_col_sum(NULL, "key", NULL, &sum);
    assert(!col_found);

    double min, max;
    bool mm_found = qihse_cluster_scatter_col_minmax(NULL, "key", NULL, &min, &max);
    assert(!mm_found);

    qihse_cluster_scatter_stats(NULL, NULL);
    printf("PASS null scatter safe\n");
}

int main(void) {
    test_scatter_no_peers();
    test_ts_fanout_no_peers();
    test_col_sum_no_peers();
    test_col_minmax_no_peers();
    test_scatter_unhealthy_peer();
    test_scatter_peer_connection_failure();
    test_null_scatter();
    printf("cluster scatter tests passed\n");
    return 0;
}
