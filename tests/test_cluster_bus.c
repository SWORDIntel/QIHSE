/*
 * test_cluster_bus.c — Unit tests for the QIHSE cluster gossip bus.
 *
 * Tests use the inject() API to feed datagrams directly into the bus
 * without requiring network I/O, plus a live UDP round-trip test
 * between two in-process bus instances on ephemeral ports.
 */
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_platform.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

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

/* Test 1: Build a datagram manually and inject it; verify topology update. */
static void test_slot_update_inject(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.bus_port = 0; /* will not start the bus */
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);

    /* Build a SLOT_UPDATE datagram for slots 100-200 owned by node A */
    uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(qihse_cluster_bus_slot_update_t)];
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t type = QIHSE_BUS_MSG_SLOT_UPDATE;
    uint32_t sender = 0;
    uint32_t payload_len = sizeof(qihse_cluster_bus_slot_update_t);
    memcpy(datagram, &magic, 4);
    memcpy(datagram + 4, &type, 4);
    memcpy(datagram + 8, &sender, 4);
    memcpy(datagram + 12, &payload_len, 4);
    qihse_cluster_bus_slot_update_t upd;
    memset(&upd, 0, sizeof(upd));
    upd.start = 100;
    upd.end = 200;
    upd.owner_index = idx_a;
    memcpy(upd.owner_id, node_a.id, QIHSE_CLUSTER_NODE_ID_LEN + 1);
    memcpy(datagram + 16, &upd, sizeof(upd));

    assert(qihse_cluster_bus_inject(bus, datagram, 16 + sizeof(upd), "127.0.0.1", 17000));

    /* Verify slots 100-200 are now owned by idx_a */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 100, &owner, &state, NULL));
    assert(owner == idx_a);
    assert(qihse_cluster_topology_get_slot(topo, 150, &owner, &state, NULL));
    assert(owner == idx_a);
    assert(qihse_cluster_topology_get_slot(topo, 200, &owner, &state, NULL));
    assert(owner == idx_a);
    /* Slot 201 should still be unassigned */
    assert(qihse_cluster_topology_get_slot(topo, 201, &owner, &state, NULL));
    assert(owner == QIHSE_CLUSTER_NODE_NONE);

    qihse_cluster_bus_stats_t stats;
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.received == 1);
    assert(stats.slot_updates_received == 1);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS slot update inject\n");
}

/* Test 2: Inject a MEET message and verify the node is added to topology. */
static void test_meet_inject(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);

    /* Build a MEET message with a new node */
    qihse_cluster_node_t node_b;
    make_node(&node_b, "nodeB", "10.0.0.2", 7001, 17001);

    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    /* Serialise node_b manually (same format as qihse_bus_serialise_node) */
    uint8_t* ptr = payload;
    uint16_t port = node_b.port; memcpy(ptr, &port, 2); ptr += 2;
    uint16_t bus_port = node_b.bus_port; memcpy(ptr, &bus_port, 2); ptr += 2;
    uint16_t role = (uint16_t)node_b.role; memcpy(ptr, &role, 2); ptr += 2;
    uint16_t primary = node_b.primary_index; memcpy(ptr, &primary, 2); ptr += 2;
    uint16_t idx = node_b.index; memcpy(ptr, &idx, 2); ptr += 2;
    uint16_t healthy = node_b.healthy ? 1 : 0; memcpy(ptr, &healthy, 2); ptr += 2;
    memcpy(ptr, node_b.id, QIHSE_CLUSTER_NODE_ID_LEN + 1); ptr += QIHSE_CLUSTER_NODE_ID_LEN + 1;
    memcpy(ptr, node_b.host, QIHSE_CLUSTER_HOST_LEN + 1); ptr += QIHSE_CLUSTER_HOST_LEN + 1;
    size_t payload_len = (size_t)(ptr - payload);

    uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t type = QIHSE_BUS_MSG_MEET;
    uint32_t sender = 0;
    uint32_t plen = (uint32_t)payload_len;
    memcpy(datagram, &magic, 4);
    memcpy(datagram + 4, &type, 4);
    memcpy(datagram + 8, &sender, 4);
    memcpy(datagram + 12, &plen, 4);
    memcpy(datagram + 16, payload, payload_len);

    assert(qihse_cluster_bus_inject(bus, datagram, 16 + payload_len, "10.0.0.2", 17001));

    /* Verify node_b was added */
    uint16_t idx_b;
    assert(qihse_cluster_topology_find_node(topo, node_b.id, &idx_b));
    assert(idx_b != idx_a);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS meet inject\n");
}

/* Test 3: Inject a FAIL message and verify node health is set to false. */
static void test_fail_inject(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a, node_b;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    make_node(&node_b, "nodeB", "10.0.0.2", 7001, 17001);
    uint16_t idx_a, idx_b;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_upsert_node(topo, &node_b, &idx_b));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);

    /* Build a FAIL message for node_b */
    uint8_t datagram[64];
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t type = QIHSE_BUS_MSG_FAIL;
    uint32_t sender = (uint32_t)idx_a;
    uint32_t payload_len = QIHSE_CLUSTER_NODE_ID_LEN + 1;
    memcpy(datagram, &magic, 4);
    memcpy(datagram + 4, &type, 4);
    memcpy(datagram + 8, &sender, 4);
    memcpy(datagram + 12, &payload_len, 4);
    memcpy(datagram + 16, node_b.id, QIHSE_CLUSTER_NODE_ID_LEN + 1);

    assert(qihse_cluster_bus_inject(bus, datagram, 16 + payload_len, "127.0.0.1", 17000));

    /* Verify node_b is now unhealthy */
    qihse_cluster_node_t check;
    assert(qihse_cluster_topology_get_node(topo, idx_b, &check));
    assert(!check.healthy);

    qihse_cluster_bus_stats_t stats;
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.fail_notices_received == 1);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS fail inject\n");
}

/* Test 4: Live UDP round-trip between two bus instances. */
static void test_live_udp_roundtrip(void) {
    qihse_cluster_topology_t* topo_a = qihse_cluster_topology_create();
    qihse_cluster_topology_t* topo_b = qihse_cluster_topology_create();
    assert(topo_a && topo_b);

    /* Use ephemeral ports to avoid conflicts */
    uint16_t bus_port_a = 17380;
    uint16_t bus_port_b = 17381;

    qihse_cluster_node_t node_a, node_b;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, bus_port_a);
    make_node(&node_b, "nodeB", "127.0.0.1", 7001, bus_port_b);
    uint16_t idx_a, idx_b;
    assert(qihse_cluster_topology_upsert_node(topo_a, &node_a, &idx_a));
    assert(qihse_cluster_topology_upsert_node(topo_b, &node_b, &idx_b));

    /* Add node_b to topo_a so bus_a knows where to send */
    assert(qihse_cluster_topology_upsert_node(topo_a, &node_b, NULL));
    /* Add node_a to topo_b so bus_b can reply */
    assert(qihse_cluster_topology_upsert_node(topo_b, &node_a, NULL));

    qihse_cluster_bus_config_t cfg_a, cfg_b;
    memset(&cfg_a, 0, sizeof(cfg_a));
    cfg_a.topology = topo_a;
    cfg_a.local_node_index = idx_a;
    cfg_a.bus_port = bus_port_a;
    cfg_a.bind_address = "127.0.0.1";
    cfg_a.heartbeat_ms = 200;
    cfg_a.timeout_ms = 1000;
    qihse_cluster_bus_t* bus_a = qihse_cluster_bus_create(&cfg_a);
    assert(bus_a);

    memset(&cfg_b, 0, sizeof(cfg_b));
    cfg_b.topology = topo_b;
    cfg_b.local_node_index = idx_b;
    cfg_b.bus_port = bus_port_b;
    cfg_b.bind_address = "127.0.0.1";
    cfg_b.heartbeat_ms = 200;
    cfg_b.timeout_ms = 1000;
    qihse_cluster_bus_t* bus_b = qihse_cluster_bus_create(&cfg_b);
    assert(bus_b);

    assert(qihse_cluster_bus_start(bus_a));
    assert(qihse_cluster_bus_start(bus_b));

    /* Give them time to exchange heartbeats */
    sleep_ms(800);

    /* Check that bus_a received at least one PONG from bus_b */
    qihse_cluster_bus_stats_t stats_a;
    qihse_cluster_bus_stats(bus_a, &stats_a);
    assert(stats_a.pings_sent > 0);
    assert(stats_a.received > 0);

    /* Test slot update broadcast from bus_a to bus_b */
    assert(qihse_cluster_bus_broadcast_slot_update(bus_a, 0, 99, idx_a));
    sleep_ms(300);

    /* Verify topo_b received the slot update */
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo_b, 50, &owner, &state, NULL));
    /* The owner_index in topo_b may differ from idx_a in topo_a, but the
     * slot should be assigned (not NONE).  Find node_a's index in topo_b. */
    uint16_t idx_a_in_b;
    assert(qihse_cluster_topology_find_node(topo_b, node_a.id, &idx_a_in_b));
    assert(owner == idx_a_in_b);

    qihse_cluster_bus_stats_t stats_b;
    qihse_cluster_bus_stats(bus_b, &stats_b);
    assert(stats_b.slot_updates_received > 0);

    qihse_cluster_bus_stop(bus_a);
    qihse_cluster_bus_stop(bus_b);
    qihse_cluster_bus_destroy(bus_a);
    qihse_cluster_bus_destroy(bus_b);
    qihse_cluster_topology_destroy(topo_a);
    qihse_cluster_topology_destroy(topo_b);
    printf("PASS live UDP round-trip\n");
}

/* Test 5: Invalid datagram (bad magic) should be rejected. */
static void test_bad_magic(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);

    uint8_t bad[20] = {0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    assert(qihse_cluster_bus_inject(bus, bad, sizeof(bad), "127.0.0.1", 17000));

    qihse_cluster_bus_stats_t stats;
    qihse_cluster_bus_stats(bus, &stats);
    /* Should not have counted as received (bad magic) */
    assert(stats.received == 0);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS bad magic rejected\n");
}

int main(void) {
    test_slot_update_inject();
    test_meet_inject();
    test_fail_inject();
    test_bad_magic();
    test_live_udp_roundtrip();
    printf("cluster bus tests passed\n");
    return 0;
}
