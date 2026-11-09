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
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
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

/* Test 1: A same-owner announcement is observed without changing topology. */
static void test_slot_update_inject(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_assign_range(topo, 100, 200, idx_a));

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

    /* Verify the pre-existing ownership remains unchanged. */
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

    /* A wire ID without an in-field NUL must be discarded before the
     * topology's string lookup can read beyond the fixed payload field. */
    memset(upd.owner_id, 'X', sizeof(upd.owner_id));
    memcpy(datagram + 16, &upd, sizeof(upd));
    assert(qihse_cluster_bus_inject(bus, datagram, 16 + sizeof(upd), "127.0.0.1", 17000));
    assert(qihse_cluster_topology_get_slot(topo, 150, &owner, &state, NULL));
    assert(owner == idx_a);
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.slot_updates_received == 1);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS same-owner slot announcement inject\n");
}

typedef struct { volatile int calls; pthread_t worker; } ct_callback_state_t;
static void on_ct_slot_update(qihse_cluster_bus_t* bus,
        const qihse_cluster_bus_ct_slot_update_t* update, void* opaque) {
    (void)bus;
    ct_callback_state_t* state = opaque;
    assert(update && update->magic == QIHSE_CLUSTER_BUS_CT_UPDATE_MAGIC);
    state->worker = pthread_self();
    __atomic_add_fetch(&state->calls, 1, __ATOMIC_RELEASE);
}

static void test_ct_slot_update_queued_off_rx_thread(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);
    qihse_cluster_node_t source, target;
    make_node(&source, "ct-source", "127.0.0.1", 7000, 17487);
    make_node(&target, "ct-target", "127.0.0.1", 7001, 17488);
    uint16_t source_idx, target_idx;
    assert(qihse_cluster_topology_upsert_node(topo, &source, &source_idx));
    assert(qihse_cluster_topology_upsert_node(topo, &target, &target_idx));
    assert(qihse_cluster_topology_assign_range(topo, 100, 110, source_idx));
    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo; cfg.local_node_index = source_idx;
    cfg.bus_port = 17489; cfg.bind_address = "127.0.0.1";
    ct_callback_state_t state = {0};
    cfg.on_ct_slot_update = on_ct_slot_update;
    cfg.on_ct_slot_update_user_data = &state;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus && qihse_cluster_bus_start(bus));

    qihse_cluster_bus_ct_slot_update_t update;
    memset(&update, 0, sizeof(update));
    update.magic = QIHSE_CLUSTER_BUS_CT_UPDATE_MAGIC;
    update.start = 100; update.end = 110; update.config_epoch = 9;
    /* Source and target use independent durable cursor domains. */
    update.source_lsn = 1000; update.target_lsn = 1;
    strcpy(update.transfer_id, "ct2-queued-test");
    strcpy(update.source_id, source.id); strcpy(update.target_id, target.id);
    strcpy(update.source_qkp_id, "source-pin"); strcpy(update.target_qkp_id, "target-pin");
    strcpy(update.generation, "gen-1"); strcpy(update.owner_id, target.id);
    update.checksum[0] = 1;
    uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(update)];
    uint32_t header[4] = {QIHSE_CLUSTER_BUS_MAGIC, QIHSE_BUS_MSG_SLOT_UPDATE,
                          source_idx, sizeof(update)};
    memcpy(datagram, header, sizeof(header));
    memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, &update, sizeof(update));
    pthread_t receiver_thread = pthread_self();
    assert(qihse_cluster_bus_inject(bus, datagram, sizeof(datagram), "127.0.0.1", 17487));
    for (unsigned i = 0; i < 100 && !__atomic_load_n(&state.calls, __ATOMIC_ACQUIRE); ++i)
        sleep_ms(5);
    assert(__atomic_load_n(&state.calls, __ATOMIC_ACQUIRE) == 1);
    assert(!pthread_equal(receiver_thread, state.worker));
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_get_slot(topo, 105, &owner, NULL, NULL));
    assert(owner == source_idx); /* a claim is never adopted by the bus thread */

    qihse_cluster_bus_stop(bus);
    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS CT slot update is queued to off-receive proof worker\n");
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

    /* An update from bus A cannot publish ownership on B without a durable
     * migration/failover proof, even when the datagram reaches B. */
    assert(qihse_cluster_bus_broadcast_slot_update(bus_a, 0, 99, idx_a));

    /* Wait for the actual asynchronous UDP update, not a fixed delay that
     * depends on host scheduling and makes this assertion race the bus thread. */
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_slot_state_t state;
    uint16_t idx_a_in_b;
    assert(qihse_cluster_topology_find_node(topo_b, node_a.id, &idx_a_in_b));
    qihse_cluster_bus_stats_t stats_b;
    bool refused = false;
    for (unsigned attempt = 0; attempt < 50; ++attempt) {
        qihse_cluster_bus_stats(bus_b, &stats_b);
        if (stats_b.received > 0 &&
            qihse_cluster_topology_get_slot(topo_b, 50, &owner, &state, NULL) &&
            owner == QIHSE_CLUSTER_NODE_NONE) {
            refused = true;
            break;
        }
        sleep_ms(100);
    }
    assert(refused);
    assert(stats_b.slot_updates_received == 0);

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

/* Independent re-implementation of the veiled framing wire format so the test
 * pins the derivation down: [nonce 8B][pad_len u8][padding][xored_frame],
 * keystream = HMAC-SHA384(key, nonce || BE32 block counter) truncated. */
static size_t veil_wrap_test(const char* key, const uint8_t* nonce, uint8_t pad_len,
                             const uint8_t* frame, size_t frame_len,
                             uint8_t* out, size_t cap) {
    size_t total = 8u + 1u + (size_t)pad_len + frame_len;
    if (total > cap) return 0;
    memcpy(out, nonce, 8u);
    out[8] = pad_len;
    for (uint8_t i = 0; i < pad_len; i++) out[9u + i] = (uint8_t)(0xA0u + i);
    uint8_t* body = out + 9u + pad_len;
    memcpy(body, frame, frame_len);
    uint8_t input[12];
    memcpy(input, nonce, 8u);
    size_t done = 0;
    for (uint32_t counter = 0; done < frame_len; counter++) {
        input[8] = (uint8_t)(counter >> 24);
        input[9] = (uint8_t)(counter >> 16);
        input[10] = (uint8_t)(counter >> 8);
        input[11] = (uint8_t)counter;
        uint8_t block[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        HMAC(EVP_sha384(), key, (int)strlen(key), input, sizeof(input), block, &md_len);
        assert(md_len > 0);
        size_t n = frame_len - done < md_len ? frame_len - done : (size_t)md_len;
        for (size_t i = 0; i < n; i++) body[done + i] ^= block[i];
        done += n;
    }
    return total;
}

/* Build a SLOT_UPDATE inner frame for slots `start`-`end` owned by idx. */
static size_t make_slot_update_frame(uint16_t idx, const char* owner_id,
                                     uint16_t start, uint16_t end,
                                     uint8_t* out, size_t cap) {
    assert(cap >= QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(qihse_cluster_bus_slot_update_t));
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t type = QIHSE_BUS_MSG_SLOT_UPDATE;
    uint32_t sender = idx;
    uint32_t payload_len = (uint32_t)sizeof(qihse_cluster_bus_slot_update_t);
    memcpy(out, &magic, 4);
    memcpy(out + 4, &type, 4);
    memcpy(out + 8, &sender, 4);
    memcpy(out + 12, &payload_len, 4);
    qihse_cluster_bus_slot_update_t upd;
    memset(&upd, 0, sizeof(upd));
    upd.start = start;
    upd.end = end;
    upd.owner_index = idx;
    memcpy(upd.owner_id, owner_id, strlen(owner_id) + 1);
    memcpy(out + 16, &upd, sizeof(upd));
    return 16 + sizeof(upd);
}

/* Test 6: veiled framing — correct-key datagram is unwrapped and processed;
 * plain, wrong-key, and malformed wrappers are dropped without disclosure. */
static void test_veiled_framing(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    qihse_cluster_node_t node_a;
    make_node(&node_a, "nodeA", "127.0.0.1", 7000, 17000);
    uint16_t idx_a;
    assert(qihse_cluster_topology_upsert_node(topo, &node_a, &idx_a));
    assert(qihse_cluster_topology_assign_range(topo, 300, 400, idx_a));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = idx_a;
    cfg.veil_key = "cluster-operator-password";
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);

    const uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t frame[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(qihse_cluster_bus_slot_update_t)];
    size_t frame_len = make_slot_update_frame(idx_a, node_a.id, 300, 400, frame, sizeof(frame));
    uint8_t wrapped[8 + 1 + 64 + sizeof(frame)];

    /* Correct key: datagram is unwrapped as a same-owner announcement. */
    size_t wrapped_len = veil_wrap_test(cfg.veil_key, nonce, 17u, frame, frame_len,
                                        wrapped, sizeof(wrapped));
    assert(wrapped_len > 0);
    assert(qihse_cluster_bus_inject(bus, wrapped, wrapped_len, "127.0.0.1", 17000));
    uint16_t owner;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topo, 350, &owner, &state, NULL));
    assert(owner == idx_a);

    qihse_cluster_bus_stats_t stats;
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.received == 1);
    assert(stats.slot_updates_received == 1);

    /* Wrong key: keystream mismatch garbles the frame — must be dropped. */
    uint8_t wrong[8 + 1 + 64 + sizeof(frame)];
    size_t wrong_len = veil_wrap_test("attacker-guess", nonce, 33u, frame, frame_len,
                                      wrong, sizeof(wrong));
    assert(qihse_cluster_bus_inject(bus, wrong, wrong_len, "127.0.0.1", 17000));

    /* Un-veiled plain frame on a veiled bus: also dropped. */
    assert(qihse_cluster_bus_inject(bus, frame, frame_len, "127.0.0.1", 17000));

    /* Malformed pad_len byte (claims more padding than the datagram holds). */
    memcpy(wrapped, nonce, 8u);
    wrapped[8] = 200u;
    assert(qihse_cluster_bus_inject(bus, wrapped, 9u + 16u, "127.0.0.1", 17000));

    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.received == 1); /* no additional frame was accepted */
    assert(stats.slot_updates_received == 1);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS veiled framing\n");
}

static void test_transport_key_derivation(void) {
    static const char credential[] = "CorrectHorseBatteryStaple!";
    static const char expected_bus[] =
        "63252b580ac802b05e4a15d2ee4e00041c67783aaea3bb51cc1a0036bcce2423"
        "b9bc34296733d46b577900a2703e71cd";
    static const char expected_overlay[] =
        "0c31e36be529a7d2418ee03a250b575aea52a47553757e466e324ee98b150db47"
        "aee22dec6ab4d489087b184c7a225a6";
    char bus[QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN + 1u];
    char overlay[QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN + 1u];
    char bus_again[QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN + 1u];

    assert(!qihse_cluster_derive_bus_veil_key(NULL, bus));
    assert(!qihse_cluster_derive_bus_veil_key("", bus));
    assert(!qihse_cluster_derive_bus_veil_key(credential, NULL));
    assert(qihse_cluster_derive_bus_veil_key(credential, bus));
    assert(qihse_cluster_derive_overlay_hmac_key(credential, overlay));
    assert(qihse_cluster_derive_bus_veil_key(credential, bus_again));
    assert(strlen(bus) == QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN);
    assert(strlen(overlay) == QIHSE_CLUSTER_DERIVED_KEY_HEX_LEN);
    assert(strcmp(bus, expected_bus) == 0);
    assert(strcmp(overlay, expected_overlay) == 0);
    assert(strcmp(bus, overlay) != 0);
    assert(strcmp(bus, credential) != 0);
    assert(strcmp(bus, bus_again) == 0);
    printf("PASS transport key derivation\n");
}

static void silent_peer_failed(qihse_cluster_topology_t* topology,
                               uint16_t node_index, void* user_data) {
    (void)topology;
    uint16_t* failed = (uint16_t*)user_data;
    __atomic_store_n(failed, node_index, __ATOMIC_RELEASE);
}

static void test_silent_peer_health(void) {
    assert(qihse_cluster_bus_check_health(NULL) == 0);
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);

    /* Reserve an endpoint that receives UDP but never answers the bus. */
    int silent_fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(silent_fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(silent_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    socklen_t addr_len = sizeof(addr);
    assert(getsockname(silent_fd, (struct sockaddr*)&addr, &addr_len) == 0);

    qihse_cluster_node_t local, peer, check;
    make_node(&local, "silent-local", "127.0.0.1", 7000, 17382);
    make_node(&peer, "silent-peer", "127.0.0.1", 7001, ntohs(addr.sin_port));
    uint16_t local_idx, peer_idx;
    assert(qihse_cluster_topology_upsert_node(topo, &local, &local_idx));
    assert(qihse_cluster_topology_upsert_node(topo, &peer, &peer_idx));
    uint16_t failed = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = topo;
    cfg.local_node_index = local_idx;
    cfg.bind_address = "127.0.0.1";
    cfg.bus_port = local.bus_port;
    cfg.heartbeat_ms = 50;
    cfg.timeout_ms = 100;
    cfg.on_fail = silent_peer_failed;
    cfg.on_fail_user_data = &failed;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);
    assert(qihse_cluster_bus_check_health(bus) == 0);
    assert(qihse_cluster_topology_get_node(topo, peer_idx, &check));
    assert(check.healthy);
    assert(qihse_cluster_bus_start(bus));
    for (unsigned i = 0; i < 100 &&
         __atomic_load_n(&failed, __ATOMIC_ACQUIRE) == QIHSE_CLUSTER_NODE_NONE; i++) {
        sleep_ms(20);
    }
    qihse_cluster_bus_stop(bus);
    assert(__atomic_load_n(&failed, __ATOMIC_ACQUIRE) == peer_idx);
    assert(qihse_cluster_topology_get_node(topo, peer_idx, &check));
    assert(!check.healthy);
    assert(qihse_cluster_topology_get_node(topo, local_idx, &check));
    assert(check.healthy);
    qihse_cluster_bus_stats_t stats;
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.received == 0);
    assert(stats.nodes_marked_unhealthy == 1);

    /* First direct contact must revive even a peer never previously seen. */
    uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint32_t header[] = {QIHSE_CLUSTER_BUS_MAGIC, QIHSE_BUS_MSG_PONG,
                         peer_idx, QIHSE_CLUSTER_NODE_ID_LEN + 1u};
    memcpy(datagram, header, sizeof(header));
    memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, peer.id, sizeof(peer.id));
    assert(qihse_cluster_bus_inject(bus, datagram, sizeof(datagram),
                                  "127.0.0.1", peer.bus_port));
    assert(qihse_cluster_topology_get_node(topo, peer_idx, &check));
    assert(check.healthy);
    assert(qihse_cluster_bus_check_health(bus) == 0);

    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    close(silent_fd);
    printf("PASS silent peer health and first-contact revival\n");
}

static void test_maintenance_defers_slot_update(void) {
    qihse_cluster_maintenance_t* gate = qihse_cluster_maintenance_create();
    assert(gate);
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_RESP, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BGSAVE, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_FAILOVER, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_RECLAIM, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BUS_GROUP, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BUS_FEDERATION, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_REPLICA, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_EXPIRY, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_TASK_WORKER, true));
    assert(qihse_cluster_maintenance_register(gate, QIHSE_MAINT_WRITER_BRAIN, true));
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);
    qihse_cluster_node_t node;
    make_node(&node, "maint-owner", "127.0.0.1", 7000, 17000);
    uint16_t idx;
    assert(qihse_cluster_topology_upsert_node(topo, &node, &idx));
    qihse_cluster_bus_config_t cfg = {0};
    cfg.topology = topo;
    cfg.local_node_index = idx;
    cfg.maintenance_gate = gate;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&cfg);
    assert(bus);
    uint64_t generation;
    uint8_t token[32];
    assert(qihse_cluster_maintenance_begin(gate, 0, 5000, &generation, token));
    uint8_t frame[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(qihse_cluster_bus_slot_update_t)];
    size_t len = make_slot_update_frame(idx, node.id, 50, 50, frame, sizeof(frame));
    assert(qihse_cluster_bus_inject(bus, frame, len, "127.0.0.1", 17000));
    uint16_t owner;
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, NULL, NULL));
    assert(owner == QIHSE_CLUSTER_NODE_NONE);
    qihse_cluster_bus_stats_t stats;
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.maintenance_slot_updates_rejected == 1u);
    assert(qihse_cluster_maintenance_release_trusted(gate, generation, token));
    assert(qihse_cluster_bus_inject(bus, frame, len, "127.0.0.1", 17000));
    assert(qihse_cluster_topology_get_slot(topo, 50, &owner, NULL, NULL));
    assert(owner == QIHSE_CLUSTER_NODE_NONE);
    qihse_cluster_bus_stats(bus, &stats);
    assert(stats.slot_updates_received == 0u);
    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    qihse_cluster_maintenance_destroy(gate);
    printf("PASS maintenance rejects SLOT_UPDATE and reports it\n");
}

int main(void) {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_cluster_bus_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    test_slot_update_inject();
    test_ct_slot_update_queued_off_rx_thread();
    test_meet_inject();
    test_fail_inject();
    test_bad_magic();
    test_transport_key_derivation();
    test_veiled_framing();
    test_live_udp_roundtrip();
    test_silent_peer_health();
    test_maintenance_defers_slot_update();
    printf("cluster bus tests passed\n");
    return 0;
}
