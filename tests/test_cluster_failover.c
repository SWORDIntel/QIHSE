/*
 * test_cluster_failover.c — Unit tests for the QIHSE cluster failover coordinator.
 */
#include "qihse_cluster_failover.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void make_node(qihse_cluster_node_t* node, const char* id_seed, const char* host, uint16_t port, uint16_t bus_port,
                      qihse_cluster_node_role_t role, uint16_t primary_index) {
    memset(node, 0, sizeof(*node));
    qihse_cluster_node_id_from_seed(id_seed, strlen(id_seed), node->id);
    strncpy(node->host, host, QIHSE_CLUSTER_HOST_LEN);
    node->port = port;
    node->bus_port = bus_port;
    node->role = role;
    node->primary_index = primary_index;
    node->healthy = true;
}

/* Test 1: Primary fails, replica is promoted and slots are reassigned. */
static void test_primary_failover(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, replica;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&replica, "replica1", "10.0.0.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &idx_r));

    /* Assign slots 0-99 to the primary */
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, idx_p));

    /* Create failover coordinator (local node = replica, so it can be promoted) */
    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.bus = NULL;
    cfg.local_node_index = idx_r;
    cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    /* Mark the primary as failed */
    qihse_cluster_topology_set_node_health(topo, idx_p, false);

    /* Trigger failover */
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_p);
    assert(promoted == idx_r);
    assert(qihse_cluster_failover_events(fo) == 1);

    /* Verify the replica is now a primary */
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_r, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_PRIMARY);
    assert(check.primary_index == QIHSE_CLUSTER_NODE_NONE);

    /* Verify slots 0-99 are now owned by the promoted replica */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 0, &owner, &state, NULL));
    assert(owner == idx_r);
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, &state, NULL));
    assert(owner == idx_r);
    assert(qihse_cluster_topology_get_slot(topo, 99, &owner, &state, NULL));
    assert(owner == idx_r);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS primary failover\n");
}

/* Test 2: No replica available — failover should not occur. */
static void test_no_replica(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    uint16_t idx_p;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, idx_p));

    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_p;
    cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    qihse_cluster_topology_set_node_health(topo, idx_p, false);
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_p);
    assert(promoted == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_events(fo) == 0);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS no replica\n");
}

/* Test 3: Failed node is a replica (not a primary) — no failover needed. */
static void test_replica_failure(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, replica;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&replica, "replica1", "10.0.0.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &idx_r));
    assert(qihse_cluster_topology_assign_range(topo, 0, 99, idx_p));

    qihse_cluster_failover_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_p;
    cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&cfg);
    assert(fo);

    /* Mark the replica as failed */
    qihse_cluster_topology_set_node_health(topo, idx_r, false);
    uint16_t promoted = qihse_cluster_failover_handle(fo, idx_r);
    assert(promoted == QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_failover_events(fo) == 0);

    /* Primary's slots should be unchanged */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, &state, NULL));
    assert(owner == idx_p);

    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS replica failure (no failover)\n");
}

/* Test 4: Best replica selection — multiple replicas, lowest index wins. */
static void test_best_replica_selection(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, r1, r2, r3;
    make_node(&primary, "primary1", "10.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&r1, "replica1", "10.0.0.2", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    make_node(&r2, "replica2", "10.0.0.3", 7002, 17002, QIHSE_CLUSTER_NODE_REPLICA, 0);
    make_node(&r3, "replica3", "10.0.0.4", 7003, 17003, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r1, idx_r2, idx_r3;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &r1, &idx_r1));
    assert(qihse_cluster_topology_upsert_node(topo, &r2, &idx_r2));
    assert(qihse_cluster_topology_upsert_node(topo, &r3, &idx_r3));

    /* Mark r2 as unhealthy — should not be selected */
    qihse_cluster_topology_set_node_health(topo, idx_r2, false);

    uint16_t best = qihse_cluster_failover_best_replica(topo, idx_p);
    /* r1 should be the best (lowest index, healthy) */
    assert(best == idx_r1);

    qihse_cluster_topology_destroy(topo);
    printf("PASS best replica selection\n");
}

/* Test 5: Failover via bus on_fail callback. */
static void test_bus_failover_callback(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t primary, replica;
    make_node(&primary, "primary1", "127.0.0.1", 7000, 17000, QIHSE_CLUSTER_NODE_PRIMARY, QIHSE_CLUSTER_NODE_NONE);
    make_node(&replica, "replica1", "127.0.0.1", 7001, 17001, QIHSE_CLUSTER_NODE_REPLICA, 0);
    uint16_t idx_p, idx_r;
    assert(qihse_cluster_topology_upsert_node(topo, &primary, &idx_p));
    assert(qihse_cluster_topology_upsert_node(topo, &replica, &idx_r));
    assert(qihse_cluster_topology_assign_range(topo, 0, 49, idx_p));

    /* Create failover coordinator first */
    qihse_cluster_failover_config_t fo_cfg;
    memset(&fo_cfg, 0, sizeof(fo_cfg));
    fo_cfg.topology = topo;
    fo_cfg.bus = NULL;
    fo_cfg.local_node_index = idx_r;
    fo_cfg.single_coordinator = false;
    qihse_cluster_failover_t* fo = qihse_cluster_failover_create(&fo_cfg);
    assert(fo);

    /* Create bus with failover callback */
    qihse_cluster_bus_config_t bus_cfg;
    memset(&bus_cfg, 0, sizeof(bus_cfg));
    bus_cfg.topology = topo;
    bus_cfg.local_node_index = idx_r;
    bus_cfg.bus_port = 0;
    bus_cfg.on_fail = qihse_cluster_failover_on_fail_cb;
    bus_cfg.on_fail_user_data = fo;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bus_cfg);
    assert(bus);

    /* Inject a FAIL message for the primary */
    uint8_t datagram[64];
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t type = QIHSE_BUS_MSG_FAIL;
    uint32_t sender = (uint32_t)idx_r;
    uint32_t payload_len = QIHSE_CLUSTER_NODE_ID_LEN + 1;
    memcpy(datagram, &magic, 4);
    memcpy(datagram + 4, &type, 4);
    memcpy(datagram + 8, &sender, 4);
    memcpy(datagram + 12, &payload_len, 4);
    memcpy(datagram + 16, primary.id, QIHSE_CLUSTER_NODE_ID_LEN + 1);

    assert(qihse_cluster_bus_inject(bus, datagram, 16 + payload_len, "127.0.0.1", 17001));

    /* Verify failover occurred */
    assert(qihse_cluster_failover_events(fo) == 1);
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_r, &check));
    assert(check.role == QIHSE_CLUSTER_NODE_PRIMARY);

    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 25, &owner, &state, NULL));
    assert(owner == idx_r);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_failover_destroy(fo);
    qihse_cluster_topology_destroy(topo);
    printf("PASS bus failover callback\n");
}

int main(void) {
    test_primary_failover();
    test_no_replica();
    test_replica_failure();
    test_best_replica_selection();
    test_bus_failover_callback();
    printf("cluster failover tests passed\n");
    return 0;
}
