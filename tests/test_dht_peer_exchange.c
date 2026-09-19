/*
 * test_dht_peer_exchange.c — W4.2: overlay layer 3, DHT peer exchange
 * (simplified Kademlia) as bus message types DHT_FIND / DHT_NODES.
 *
 * The roadmap's gate for the overlay is: "a forged/expired IRC record never
 * yields a MEET; a DHT record never yields membership."  The IRC half lives in
 * tests/test_overlay.c.  This file is the DHT half, and the negative cases are
 * the point of it:
 *
 *   1. GATE — a DHT record cannot make anything a member, trusted or
 *      authoritative.  A hostile NODES frame naming an unenrolled node causes
 *      exactly one action (a MEET, i.e. a dial), the cluster topology does not
 *      gain that node, and the federation trust plane holds no identity for
 *      it: its derived UUID resolves to no record and the admissible lookup is
 *      false.  The contrast case is asserted too — a MEET that DOES arrive
 *      (the existing precedent for how far a hint may go) puts the node in the
 *      topology and still does not make it admissible.
 *   2. REJECTED — expired, unknown-version, reserved-flag, truncated,
 *      oversized-count, non-literal-host, unspecified-address, self and
 *      malformed-id records are dropped with no dial and no state.
 *   3. BOUNDED — a flood of NODES frames cannot cause more than
 *      QIHSE_DHT_DIAL_MAX_PER_WINDOW dials per window or grow hint state past
 *      QIHSE_DHT_MAX_HINTS; a flood of FIND frames cannot make us answer more
 *      than QIHSE_DHT_SERVE_MAX_PER_WINDOW times.
 *   4. CLOSER — a FIND is answered with up to k peers ordered by XOR distance
 *      to the target, one hop, never forwarded.
 *   5. REVOKED — with a federation trust context, a hint whose derived UUID is
 *      REVOKED is never dialed, while an unknown id still is.
 *   6. LIVE — the whole exchange over real UDP datagrams to a real bus port.
 *
 * No absolute paths: everything binds to loopback ephemeral ports and a
 * mkdtemp scratch directory.
 */
#include "qihse_auth.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_overlay.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BUS_HDR 16u

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── small helpers ─────────────────────────────────────────────────────── */

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

static void node_id_for(const char* seed, char out[QIHSE_CLUSTER_NODE_ID_LEN + 1u]) {
    qihse_cluster_node_id_from_seed(seed, strlen(seed), out);
}

static uint16_t udp_bind_ephemeral(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static int udp_bind_socket(uint16_t* port_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    *port_out = ntohs(addr.sin_port);
    return fd;
}

/* Read one datagram and report its bus message type, or -1 on timeout. */
static long recv_frame_type(int fd, int timeout_ms, uint8_t* out, size_t cap,
                            size_t* out_len) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, timeout_ms) <= 0) return -1;
    ssize_t n = recv(fd, out, cap, 0);
    if (n < (ssize_t)BUS_HDR) return -1;
    uint32_t magic = 0, type = 0;
    memcpy(&magic, out, 4u);
    memcpy(&type, out + 4u, 4u);
    if (magic != QIHSE_CLUSTER_BUS_MAGIC) return -1;
    if (out_len) *out_len = (size_t)n;
    return (long)type;
}

/* Wait for a frame of `want_type`, skipping other traffic (heartbeats), and
 * return it in a private receive buffer (NULL on timeout).  Receives never
 * share a buffer with a datagram that is still to be injected. */
static uint8_t g_rx[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];

static const uint8_t* expect_frame(int fd, uint32_t want_type, int timeout_ms,
                                   size_t* out_len) {
    uint64_t deadline = now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        uint64_t left = deadline - now_ms();
        if ((int64_t)left <= 0) return NULL;
        long type = recv_frame_type(fd, (int)left, g_rx, sizeof g_rx, out_len);
        if (type < 0) return NULL;
        if ((uint32_t)type == want_type) return g_rx;
    }
}

/* Throw away anything already queued, so a "nothing arrives" assertion cannot
 * pass on a datagram from an earlier case. */
static void drain_fd(int fd) {
    uint8_t buf[2048];
    for (;;) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 0) <= 0) return;
        if (recv(fd, buf, sizeof buf, 0) <= 0) return;
    }
}

static bool send_datagram(int fd, const char* host, uint16_t port,
                          const uint8_t* data, size_t len) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    assert(inet_pton(AF_INET, host, &addr.sin_addr) == 1);
    ssize_t n = sendto(fd, data, len, 0, (struct sockaddr*)&addr, sizeof addr);
    return n == (ssize_t)len;
}

static size_t build_frame(uint8_t* out, size_t cap, uint32_t type,
                          const uint8_t* payload, size_t payload_len) {
    assert(cap >= BUS_HDR + payload_len);
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t plen = (uint32_t)payload_len;
    uint32_t sender = 0;
    memcpy(out, &magic, 4u);
    memcpy(out + 4u, &type, 4u);
    memcpy(out + 8u, &sender, 4u);
    memcpy(out + 12u, &plen, 4u);
    if (payload_len) memcpy(out + BUS_HDR, payload, payload_len);
    return BUS_HDR + payload_len;
}

/* ── DHT frame construction (mirrors the documented layout) ────────────── */

static size_t build_find(uint8_t* out, size_t cap, const char* requester_id,
                         const char* requester_host, uint16_t requester_port,
                         const char* target_id, uint64_t ts) {
    assert(cap >= QIHSE_DHT_FIND_PAYLOAD_SIZE);
    memset(out, 0, QIHSE_DHT_FIND_PAYLOAD_SIZE);
    out[0] = QIHSE_DHT_FRAME_VERSION;
    out[1] = 0u;
    out[2] = (uint8_t)QIHSE_DHT_K;
    out[3] = 0u;
    memcpy(out + 4u, &ts, 8u);
    memcpy(out + 12u, &requester_port, 2u);
    memcpy(out + 14u, requester_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    memcpy(out + 55u, target_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    snprintf((char*)(out + 96u), QIHSE_DHT_HOST_MAX, "%s", requester_host);
    return QIHSE_DHT_FIND_PAYLOAD_SIZE;
}

typedef struct {
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_DHT_HOST_MAX];
    uint16_t port;
} test_entry_t;

static size_t build_nodes(uint8_t* out, size_t cap, const char* responder_id,
                          const test_entry_t* entries, size_t count, uint64_t ts) {
    size_t len = QIHSE_DHT_NODES_HEADER_SIZE + count * QIHSE_DHT_ENTRY_SIZE;
    assert(cap >= len);
    assert(count <= 255u);
    memset(out, 0, len);
    out[0] = QIHSE_DHT_FRAME_VERSION;
    out[1] = 0u;
    out[2] = (uint8_t)count;
    out[3] = 0u;
    memcpy(out + 4u, &ts, 8u);
    memcpy(out + 12u, responder_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    for (size_t i = 0; i < count; i++) {
        uint8_t* e = out + QIHSE_DHT_NODES_HEADER_SIZE + i * QIHSE_DHT_ENTRY_SIZE;
        memcpy(e, entries[i].id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        snprintf((char*)(e + QIHSE_CLUSTER_NODE_ID_LEN + 1u), QIHSE_DHT_HOST_MAX,
                 "%s", entries[i].host);
        memcpy(e + QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_DHT_HOST_MAX,
               &entries[i].port, 2u);
    }
    return len;
}

/* ── fixture ───────────────────────────────────────────────────────────── */

typedef struct {
    qihse_cluster_topology_t* topo;
    qihse_cluster_bus_t* bus;
    uint16_t bus_port;
    uint16_t local_idx;
    char local_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_overlay_dht_config_t dht;
} fixture_t;

/* Peers get ports that are NOT bound by the test, so heartbeat traffic to them
 * goes nowhere and cannot be mistaken for a reply. */
static void fixture_up(fixture_t* f, const char* seed, size_t peer_count) {
    memset(f, 0, sizeof *f);
    f->topo = qihse_cluster_topology_create();
    assert(f->topo);
    f->bus_port = udp_bind_ephemeral();

    qihse_cluster_node_t local;
    memset(&local, 0, sizeof local);
    node_id_for(seed, f->local_id);
    snprintf(local.id, sizeof local.id, "%s", f->local_id);
    snprintf(local.host, sizeof local.host, "%s", "127.0.0.1");
    local.port = 7000u;
    local.bus_port = f->bus_port;
    local.role = QIHSE_CLUSTER_NODE_PRIMARY;
    local.primary_index = QIHSE_CLUSTER_NODE_NONE;
    local.healthy = true;
    assert(qihse_cluster_topology_upsert_node(f->topo, &local, &f->local_idx));
    assert(qihse_cluster_topology_set_local_node(f->topo, f->local_idx));

    for (size_t i = 0; i < peer_count; i++) {
        char peer_seed[64];
        snprintf(peer_seed, sizeof peer_seed, "%s-peer-%zu", seed, i);
        qihse_cluster_node_t peer;
        memset(&peer, 0, sizeof peer);
        node_id_for(peer_seed, peer.id);
        snprintf(peer.host, sizeof peer.host, "%s", "127.0.0.1");
        peer.port = (uint16_t)(17100u + i);
        peer.bus_port = (uint16_t)(17100u + i); /* unbound: nothing answers */
        peer.healthy = true;
        assert(qihse_cluster_topology_upsert_node(f->topo, &peer, NULL));
    }

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.topology = f->topo;
    cfg.local_node_index = f->local_idx;
    cfg.bus_port = f->bus_port;
    cfg.bind_address = "127.0.0.1";
    cfg.heartbeat_ms = 60000u;
    cfg.timeout_ms = 60000u;
    f->bus = qihse_cluster_bus_create(&cfg);
    assert(f->bus);
    assert(qihse_cluster_bus_start(f->bus));

    f->dht.node_id = f->local_id;
    f->dht.advertise_host = "127.0.0.1";
    f->dht.advertise_port = f->bus_port;
    f->dht.bus = f->bus;
}

static void fixture_down(fixture_t* f) {
    qihse_cluster_bus_stop(f->bus);
    qihse_cluster_bus_destroy(f->bus);
    qihse_cluster_topology_destroy(f->topo);
}

/* ── 1: the gate and the fail-closed default ───────────────────────────── */

static void test_gate_and_default(void) {
    /* A DHT frame must never be able to carry authority, and the dial gate
     * depends on MEET not carrying it either. */
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_DHT_FIND));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_DHT_NODES));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_MEET));

    assert(!qihse_overlay_dht_enabled());
    assert(!qihse_overlay_dht_start(NULL));

    fixture_t f;
    fixture_up(&f, "dht-gate", 1u);

    uint16_t endpoint_port = 0;
    int endpoint = udp_bind_socket(&endpoint_port);

    /* Invalid configs fail closed. */
    qihse_overlay_dht_config_t bad = f.dht;
    bad.bus = NULL;
    assert(!qihse_overlay_dht_start(&bad));
    bad = f.dht;
    bad.node_id = "NOT-LOWERCASE-HEX-40-CHARS-000000000000000";
    assert(!qihse_overlay_dht_start(&bad));
    bad = f.dht;
    bad.node_id = "abcd";
    assert(!qihse_overlay_dht_start(&bad));
    bad = f.dht;
    bad.advertise_host = "dht.example.com";
    assert(!qihse_overlay_dht_start(&bad));
    bad = f.dht;
    bad.advertise_port = 0u;
    assert(!qihse_overlay_dht_start(&bad));
    assert(!qihse_overlay_dht_enabled());

    /* While the DHT is disabled every frame is dropped: the hint is not
     * recorded and nothing is dialed. */
    char hostile_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char responder_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-gate-hostile", hostile_id);
    node_id_for("dht-gate-responder", responder_id);
    test_entry_t entry;
    memset(&entry, 0, sizeof entry);
    snprintf(entry.id, sizeof entry.id, "%s", hostile_id);
    snprintf(entry.host, sizeof entry.host, "%s", "127.0.0.1");
    entry.port = endpoint_port;

    uint8_t payload[QIHSE_DHT_NODES_MAX_PAYLOAD];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];
    size_t plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u,
                              now_ms());
    size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES,
                              payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44444));
    drain_fd(endpoint);
    assert(!expect_frame(endpoint, QIHSE_BUS_MSG_MEET, 400, NULL));
    assert(qihse_overlay_dht_hints(NULL, 0) == 0u);
    qihse_overlay_dht_stats_t stats;
    qihse_overlay_dht_stats(&stats);
    assert(stats.hints_dialed == 0u && stats.nodes_accepted == 0u);

    assert(qihse_overlay_dht_start(&f.dht));
    assert(qihse_overlay_dht_enabled());
    assert(!qihse_overlay_dht_start(&f.dht)); /* singleton per process */
    qihse_overlay_dht_stop();
    assert(!qihse_overlay_dht_enabled());
    qihse_overlay_dht_stop(); /* second stop is a no-op */

    close(endpoint);
    fixture_down(&f);
    printf("PASS gate: DHT frames carry no authority, disabled DHT drops every "
           "record\n");
}

/* ── 4: a FIND is answered with the closest peers, one hop ─────────────── */

static void test_find_returns_closer_peers(void) {
    fixture_t f;
    fixture_up(&f, "dht-find", 5u);
    assert(qihse_overlay_dht_start(&f.dht));

    /* The topology peers, in the order the fixture added them. */
    char peer_id[5][QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    for (size_t i = 0; i < 5u; i++) {
        char seed[64];
        snprintf(seed, sizeof seed, "dht-find-peer-%zu", i);
        node_id_for(seed, peer_id[i]);
    }

    uint16_t requester_port = 0;
    int requester = udp_bind_socket(&requester_port);
    char requester_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-find-requester", requester_id);

    uint8_t payload[QIHSE_DHT_FIND_PAYLOAD_SIZE];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];
    size_t plen = build_find(payload, sizeof payload, requester_id, "127.0.0.1",
                             requester_port, peer_id[2], now_ms());
    size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_FIND,
                              payload, plen);
    /* Drain BEFORE the inject: the reply is sent synchronously inside it. */
    drain_fd(requester);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", requester_port));

    size_t reply_len = 0;
    const uint8_t* rx = expect_frame(requester, QIHSE_BUS_MSG_DHT_NODES, 2000,
                                     &reply_len);
    assert(rx);
    assert(reply_len >= BUS_HDR + QIHSE_DHT_NODES_HEADER_SIZE);
    const uint8_t* reply = rx + BUS_HDR;
    assert(reply[0] == QIHSE_DHT_FRAME_VERSION);
    assert(reply[1] == 0u && reply[3] == 0u);
    uint8_t count = reply[2];
    assert(count >= 1u && count <= QIHSE_DHT_K);
    assert(reply_len == BUS_HDR + QIHSE_DHT_NODES_HEADER_SIZE +
                         (size_t)count * QIHSE_DHT_ENTRY_SIZE);

    /* Closest first: the target IS peer[2], so its XOR distance is zero. */
    char first_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(first_id, reply + QIHSE_DHT_NODES_HEADER_SIZE,
           QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    assert(strcmp(first_id, peer_id[2]) == 0);

    /* Independently verify the ordering is ascending XOR distance. */
    uint8_t target[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
    uint8_t prev[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
    for (size_t i = 0; i < count; i++) {
        const uint8_t* e = reply + QIHSE_DHT_NODES_HEADER_SIZE +
                           i * QIHSE_DHT_ENTRY_SIZE;
        char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
        memcpy(id, e, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        uint8_t cur[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
        for (size_t k = 0; k < sizeof cur; k++) {
            int hi = id[k * 2u] <= '9' ? id[k * 2u] - '0' : id[k * 2u] - 'a' + 10;
            int lo = id[k * 2u + 1u] <= '9' ? id[k * 2u + 1u] - '0'
                                            : id[k * 2u + 1u] - 'a' + 10;
            cur[k] = (uint8_t)((hi << 4) | lo);
        }
        if (i == 0u) {
            memcpy(target, cur, sizeof cur); /* distance to itself is zero */
        }
        uint8_t dist[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
        for (size_t k = 0; k < sizeof dist; k++) {
            dist[k] = (uint8_t)(cur[k] ^ target[k]);
        }
        if (i > 0u) assert(memcmp(prev, dist, sizeof dist) <= 0);
        memcpy(prev, dist, sizeof dist);
    }

    /* Every returned id is a peer we actually know, and the reply is a reply:
     * it does not cause a follow-up query (a lookup is one hop). */
    for (size_t i = 0; i < count; i++) {
        const uint8_t* e = reply + QIHSE_DHT_NODES_HEADER_SIZE +
                           i * QIHSE_DHT_ENTRY_SIZE;
        char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
        memcpy(id, e, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        uint16_t idx;
        assert(qihse_cluster_topology_find_node(f.topo, id, &idx));
    }
    assert(!expect_frame(requester, QIHSE_BUS_MSG_DHT_FIND, 400, NULL));

    qihse_overlay_dht_stats_t stats;
    qihse_overlay_dht_stats(&stats);
    assert(stats.finds_served == 1u);
    assert(stats.finds_rejected == 0u);

    /* A query from ourselves is not answered. */
    plen = build_find(payload, sizeof payload, f.local_id, "127.0.0.1",
                      requester_port, peer_id[0], now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_FIND, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", requester_port));
    drain_fd(requester);
    assert(!expect_frame(requester, QIHSE_BUS_MSG_DHT_NODES, 400, NULL));
    qihse_overlay_dht_stats(&stats);
    assert(stats.finds_served == 1u);
    assert(stats.finds_rejected == 1u);

    close(requester);
    qihse_overlay_dht_stop();
    fixture_down(&f);
    printf("PASS find: k closest peers by XOR distance, one hop, self-queries "
           "refused\n");
}

/* ── 2: the roadmap's negative case — a DHT record never yields membership ─ */

static void test_dht_record_never_yields_membership(void) {
    fixture_t f;
    fixture_up(&f, "dht-negative", 2u);
    f.dht.federation_store = g_store;
    f.dht.federation_user = g_op;
    assert(qihse_overlay_dht_start(&f.dht));

    char hostile_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char responder_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-hostile-node", hostile_id);
    node_id_for("dht-hostile-responder", responder_id);

    /* The hostile node is not enrolled: no identity record, and its derived
     * UUID is not admissible.  (The UUID is an INDEX, never a credential.) */
    qihse_uuid_t hostile_uuid;
    assert(qihse_uuid_from_seed(hostile_id, strlen(hostile_id), &hostile_uuid));
    qihse_federation_node_identity_t identity;
    assert(!qihse_federation_node_lookup(g_store, g_op, &hostile_uuid, &identity));
    qihse_federation_node_capability_t cap;
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, g_op,
                                                              &hostile_uuid, &cap));

    uint16_t endpoint_port = 0;
    int endpoint = udp_bind_socket(&endpoint_port);
    test_entry_t entry;
    memset(&entry, 0, sizeof entry);
    snprintf(entry.id, sizeof entry.id, "%s", hostile_id);
    snprintf(entry.host, sizeof entry.host, "%s", "127.0.0.1");
    entry.port = endpoint_port;

    size_t members_before = qihse_cluster_topology_nodes(f.topo, NULL, 0);

    /* A well-formed, fresh, hostile NODES record. */
    uint8_t payload[QIHSE_DHT_NODES_MAX_PAYLOAD];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];
    size_t plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u,
                              now_ms());
    size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES,
                              payload, plen);
    drain_fd(endpoint); /* before the inject: the dial happens inside it */
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44445));

    /* The hint IS acted on — as a dial.  That is the whole of its effect. */
    assert(expect_frame(endpoint, QIHSE_BUS_MSG_MEET, 2000, NULL));

    /* ...and it is NOT a member, NOT trusted, and holds NO authority. */
    uint16_t idx = QIHSE_CLUSTER_NODE_NONE;
    assert(!qihse_cluster_topology_find_node(f.topo, hostile_id, &idx));
    assert(qihse_cluster_topology_nodes(f.topo, NULL, 0) == members_before);
    assert(!qihse_federation_node_lookup(g_store, g_op, &hostile_uuid, &identity));
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, g_op,
                                                              &hostile_uuid, &cap));
    /* Repeat records cannot accumulate anything either. */
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44445));
    assert(!qihse_cluster_topology_find_node(f.topo, hostile_id, &idx));
    assert(qihse_cluster_topology_nodes(f.topo, NULL, 0) == members_before);
    qihse_overlay_dht_stats_t stats;
    qihse_overlay_dht_stats(&stats);
    assert(stats.hints_dialed == 1u);
    assert(stats.hints_duplicate == 1u);

    /* CONTRAST — the existing precedent, unchanged: a MEET datagram (from
     * anyone, unauthenticated) DOES upsert a topology node.  That is how far a
     * hint may go.  Even then the node is not enrolled and not admissible. */
    qihse_cluster_node_t hostile;
    memset(&hostile, 0, sizeof hostile);
    snprintf(hostile.id, sizeof hostile.id, "%s", hostile_id);
    snprintf(hostile.host, sizeof hostile.host, "%s", "127.0.0.1");
    hostile.port = 19191u;
    hostile.bus_port = endpoint_port;
    hostile.healthy = true;
    uint8_t meet_payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    uint8_t* p = meet_payload;
    uint16_t u16 = hostile.port;
    memcpy(p, &u16, 2u); p += 2u;
    u16 = hostile.bus_port;
    memcpy(p, &u16, 2u); p += 2u;
    u16 = (uint16_t)hostile.role;
    memcpy(p, &u16, 2u); p += 2u;
    u16 = hostile.primary_index;
    memcpy(p, &u16, 2u); p += 2u;
    u16 = hostile.index;
    memcpy(p, &u16, 2u); p += 2u;
    u16 = 1u;
    memcpy(p, &u16, 2u); p += 2u;
    memcpy(p, hostile.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    memcpy(p, hostile.host, QIHSE_CLUSTER_HOST_LEN + 1u);
    p += QIHSE_CLUSTER_HOST_LEN + 1u;
    size_t meet_len = (size_t)(p - meet_payload);
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_MEET, meet_payload,
                       meet_len);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44445));
    assert(qihse_cluster_topology_find_node(f.topo, hostile_id, &idx));
    assert(qihse_cluster_topology_nodes(f.topo, NULL, 0) == members_before + 1u);
    assert(!qihse_federation_node_lookup(g_store, g_op, &hostile_uuid, &identity));
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, g_op,
                                                              &hostile_uuid, &cap));

    close(endpoint);
    qihse_overlay_dht_stop();
    fixture_down(&f);
    printf("PASS negative: a DHT record dials at most, never a member, never "
           "admissible\n");
}

/* ── 2 (continued): forged / expired / hostile records are dropped ─────── */

static void test_bad_records_are_dropped(void) {
    fixture_t f;
    fixture_up(&f, "dht-reject", 1u);
    assert(qihse_overlay_dht_start(&f.dht));

    char responder_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char hostile_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-reject-responder", responder_id);
    node_id_for("dht-reject-hostile", hostile_id);

    uint16_t endpoint_port = 0;
    int endpoint = udp_bind_socket(&endpoint_port);
    test_entry_t entry;
    memset(&entry, 0, sizeof entry);
    snprintf(entry.id, sizeof entry.id, "%s", hostile_id);
    snprintf(entry.host, sizeof entry.host, "%s", "127.0.0.1");
    entry.port = endpoint_port;

    uint8_t payload[QIHSE_DHT_NODES_MAX_PAYLOAD];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];
    uint8_t find_payload[QIHSE_DHT_FIND_PAYLOAD_SIZE];
    size_t plen, dlen;

#define EXPECT_NO_DIAL(what)                                                    \
    do {                                                                        \
        drain_fd(endpoint);                                                     \
        assert(!expect_frame(endpoint, QIHSE_BUS_MSG_MEET, 300, NULL));         \
        (void)(what);                                                           \
    } while (0)

    /* Expired (outside the ±5 min replay window). */
    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u,
                       now_ms() - 10u * 60u * 1000u);
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("expired");

    /* Replayed from the future. */
    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u,
                       now_ms() + 10u * 60u * 1000u);
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("future");

    /* Unknown version, reserved flags, reserved byte. */
    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    payload[0] = (uint8_t)(QIHSE_DHT_FRAME_VERSION + 1u);
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("version");

    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    payload[1] = 0x01u;
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("flags");

    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    payload[3] = 0x80u;
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("reserved");

    /* Truncated, and a count that disagrees with the payload size. */
    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload,
                       plen - 1u);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("truncated");

    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    payload[2] = (uint8_t)(QIHSE_DHT_K + 1u); /* count > k, size still 1 entry */
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("count>k");

    /* Malformed ids and undialable hosts/ports. */
    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    payload[QIHSE_DHT_NODES_HEADER_SIZE] = 'Z'; /* not hex */
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("id");

    plen = build_nodes(payload, sizeof payload, responder_id, &entry, 1u, now_ms());
    payload[QIHSE_DHT_NODES_HEADER_SIZE + 1u] = 'A'; /* uppercase spelling */
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("id-case");

    test_entry_t bad_entry = entry;
    snprintf(bad_entry.host, sizeof bad_entry.host, "%s", "host.example.com");
    plen = build_nodes(payload, sizeof payload, responder_id, &bad_entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("hostname");

    bad_entry = entry;
    snprintf(bad_entry.host, sizeof bad_entry.host, "%s", "0.0.0.0");
    plen = build_nodes(payload, sizeof payload, responder_id, &bad_entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("unspecified-address");

    bad_entry = entry;
    bad_entry.port = 0u;
    plen = build_nodes(payload, sizeof payload, responder_id, &bad_entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("port0");

    /* A reply claiming to come from us, and a hint naming ourselves. */
    plen = build_nodes(payload, sizeof payload, f.local_id, &entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("self-responder");

    bad_entry = entry;
    snprintf(bad_entry.id, sizeof bad_entry.id, "%s", f.local_id);
    plen = build_nodes(payload, sizeof payload, responder_id, &bad_entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("self-hint");

    /* A FIND we cannot be answered at, and an expired FIND. */
    char requester_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-reject-requester", requester_id);
    plen = build_find(find_payload, sizeof find_payload, requester_id, "0.0.0.0",
                      endpoint_port, hostile_id, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_FIND, find_payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("find-0.0.0.0");

    plen = build_find(find_payload, sizeof find_payload, requester_id, "127.0.0.1",
                      endpoint_port, hostile_id,
                      now_ms() - 10u * 60u * 1000u);
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_FIND, find_payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44446));
    EXPECT_NO_DIAL("find-expired");

    /* Nothing above was recorded, dialed or served.  The one accepted frame is
     * the well-formed one whose only entry named ourselves: a frame can be
     * fine while the entry in it is refused. */
    qihse_overlay_dht_stats_t stats;
    qihse_overlay_dht_stats(&stats);
    assert(stats.hints_dialed == 0u);
    assert(stats.hints_self == 1u);
    assert(stats.hints_duplicate == 0u);
    assert(stats.nodes_accepted == 1u);
    assert(stats.nodes_rejected == 13u);
    assert(stats.frames_stale == 3u); /* two NODES + one FIND */
    assert(stats.finds_served == 0u);
    assert(stats.finds_rejected == 2u);
    assert(qihse_overlay_dht_hints(NULL, 0) == 0u);

#undef EXPECT_NO_DIAL

    close(endpoint);
    qihse_overlay_dht_stop();
    fixture_down(&f);
    printf("PASS rejected: expired/forged/hostile records are dropped with no "
           "dial\n");
}

/* ── 5: a REVOKED identity is never dialed, an unknown one still is ────── */

static void test_revoked_identity_never_dialed(const char* key_dir) {
    /* An identity whose UUID is the DERIVED uuid of a node id: this is the
     * mapping the DHT uses, so the hint id below resolves to this identity. */
    char revoked_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-revoked-node", revoked_id);
    qihse_federation_node_identity_t id;
    memset(&id, 0, sizeof id);
    assert(qihse_uuid_from_seed(revoked_id, strlen(revoked_id), &id.node_id));
    snprintf(id.hostname, sizeof id.hostname, "%s", "dht-revoked-node");
    snprintf(id.boot_id, sizeof id.boot_id, "%s", "dht-revoked-boot");
    id.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_65, &id));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &id));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &id.node_id, 1u));
    assert(qihse_federation_node_revoke(g_store, g_op, &id.node_id));

    fixture_t f;
    fixture_up(&f, "dht-revoked", 1u);
    f.dht.federation_store = g_store;
    f.dht.federation_user = g_op;
    assert(qihse_overlay_dht_start(&f.dht));

    char responder_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-revoked-responder", responder_id);

    uint16_t revoked_port = 0, unknown_port = 0;
    int revoked_fd = udp_bind_socket(&revoked_port);
    int unknown_fd = udp_bind_socket(&unknown_port);

    test_entry_t entries[2];
    memset(entries, 0, sizeof entries);
    snprintf(entries[0].id, sizeof entries[0].id, "%s", revoked_id);
    snprintf(entries[0].host, sizeof entries[0].host, "%s", "127.0.0.1");
    entries[0].port = revoked_port;
    node_id_for("dht-unknown-node", entries[1].id);
    snprintf(entries[1].host, sizeof entries[1].host, "%s", "127.0.0.1");
    entries[1].port = unknown_port;

    uint8_t payload[QIHSE_DHT_NODES_MAX_PAYLOAD];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];
    size_t plen = build_nodes(payload, sizeof payload, responder_id, entries, 2u,
                              now_ms());
    size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES,
                              payload, plen);
    /* Drain both endpoints before the inject: the dials happen inside it. */
    drain_fd(revoked_fd);
    drain_fd(unknown_fd);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44447));

    /* The revoked hint is never dialed... */
    assert(!expect_frame(revoked_fd, QIHSE_BUS_MSG_MEET, 600, NULL));
    /* ...the unknown one still is (the filter is not vacuous). */
    assert(expect_frame(unknown_fd, QIHSE_BUS_MSG_MEET, 2000, NULL));

    qihse_overlay_dht_stats_t stats;
    qihse_overlay_dht_stats(&stats);
    assert(stats.hints_revoked == 1u);
    assert(stats.hints_dialed == 1u);

    close(revoked_fd);
    close(unknown_fd);
    qihse_overlay_dht_stop();
    fixture_down(&f);
    printf("PASS revoked: a revoked identity is never dialed, an unknown one "
           "is a hint\n");
}

/* ── 3: floods are bounded ─────────────────────────────────────────────── */

static void test_floods_are_bounded(void) {
    fixture_t f;
    fixture_up(&f, "dht-flood", 1u);
    assert(qihse_overlay_dht_start(&f.dht));

    char responder_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-flood-responder", responder_id);

    uint8_t payload[QIHSE_DHT_NODES_MAX_PAYLOAD];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];

    /* 300 NODES frames x 8 distinct endpoints.  Distinct endpoints mean the
     * dedupe table cannot help: only the rate limit bounds the dials. */
    for (size_t round = 0; round < 2u; round++) {
        for (size_t i = 0; i < 300u; i++) {
            test_entry_t entries[QIHSE_DHT_K];
            memset(entries, 0, sizeof entries);
            for (size_t k = 0; k < QIHSE_DHT_K; k++) {
                char seed[64];
                snprintf(seed, sizeof seed, "dht-flood-%zu-%zu", round, i * 8u + k);
                node_id_for(seed, entries[k].id);
                snprintf(entries[k].host, sizeof entries[k].host, "%s",
                         "127.0.0.1");
                entries[k].port = (uint16_t)(20000u + (i * 8u + k) % 20000u);
            }
            size_t plen = build_nodes(payload, sizeof payload, responder_id,
                                      entries, QIHSE_DHT_K, now_ms());
            size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES,
                                      payload, plen);
            assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 44448));
        }
        if (round == 0u) sleep_ms(1100); /* let the dial window refill */
    }

    qihse_overlay_dht_stats_t stats;
    qihse_overlay_dht_stats(&stats);
    assert(stats.nodes_accepted == 600u);
    assert(stats.hints_rate_limited > 0u);
    /* Two windows of the flood, so at most two windows of dials. */
    assert(stats.hints_dialed <= 2u * QIHSE_DHT_DIAL_MAX_PER_WINDOW);
    qihse_overlay_dht_hint_t hints[QIHSE_DHT_MAX_HINTS + 8u];
    size_t hint_count = qihse_overlay_dht_hints(hints, sizeof hints / sizeof hints[0]);
    assert(hint_count == stats.hints_dialed);
    assert(hint_count <= QIHSE_DHT_MAX_HINTS);

    /* A FIND flood cannot make us answer more than the serve budget either. */
    uint16_t requester_port = 0;
    int requester = udp_bind_socket(&requester_port);
    char requester_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-flood-requester", requester_id);
    char target_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-flood-target", target_id);
    uint8_t find_payload[QIHSE_DHT_FIND_PAYLOAD_SIZE];
    size_t plen = build_find(find_payload, sizeof find_payload, requester_id,
                             "127.0.0.1", requester_port, target_id, now_ms());
    for (size_t i = 0; i < 200u; i++) {
        size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_FIND,
                                  find_payload, plen);
        assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1",
                                        requester_port));
    }
    qihse_overlay_dht_stats(&stats);
    assert(stats.finds_served <= QIHSE_DHT_SERVE_MAX_PER_WINDOW);
    assert(stats.finds_rate_limited > 0u);

    close(requester);
    qihse_overlay_dht_stop();
    fixture_down(&f);
    printf("PASS bounded: flood dials <= %u/window, hints <= %u, replies <= %u/"
           "window\n",
           (unsigned)QIHSE_DHT_DIAL_MAX_PER_WINDOW,
           (unsigned)QIHSE_DHT_MAX_HINTS,
           (unsigned)QIHSE_DHT_SERVE_MAX_PER_WINDOW);
}

/* ── 6: the exchange over real UDP ─────────────────────────────────────── */

static void test_live_udp_exchange(void) {
    fixture_t f;
    fixture_up(&f, "dht-live", 3u);
    assert(qihse_overlay_dht_start(&f.dht));

    char peer_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-live-peer-1", peer_id);

    uint16_t raw_port = 0;
    int raw = udp_bind_socket(&raw_port);
    char requester_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-live-requester", requester_id);

    /* (i) A FIND sent to the real bus port is answered to the requester's
     * advertised endpoint, with the target's own id first. */
    uint8_t find_payload[QIHSE_DHT_FIND_PAYLOAD_SIZE];
    uint8_t dgram[QIHSE_DHT_NODES_MAX_PAYLOAD + BUS_HDR];
    size_t plen = build_find(find_payload, sizeof find_payload, requester_id,
                             "127.0.0.1", raw_port, peer_id, now_ms());
    size_t dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_FIND,
                              find_payload, plen);
    assert(send_datagram(raw, "127.0.0.1", f.bus_port, dgram, dlen));
    size_t reply_len = 0;
    const uint8_t* rx = expect_frame(raw, QIHSE_BUS_MSG_DHT_NODES, 3000, &reply_len);
    assert(rx);
    const uint8_t* reply = rx + BUS_HDR;
    assert(reply[2] >= 1u);
    char first_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(first_id, reply + QIHSE_DHT_NODES_HEADER_SIZE,
           QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    assert(strcmp(first_id, peer_id) == 0);

    /* (ii) A NODES record sent to the real bus port causes exactly one dial —
     * to the hinted endpoint — and no membership. */
    char live_hostile_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("dht-live-hostile", live_hostile_id);
    uint16_t hinted_port = 0;
    int hinted = udp_bind_socket(&hinted_port);
    test_entry_t entry;
    memset(&entry, 0, sizeof entry);
    snprintf(entry.id, sizeof entry.id, "%s", live_hostile_id);
    snprintf(entry.host, sizeof entry.host, "%s", "127.0.0.1");
    entry.port = hinted_port;
    plen = build_nodes(find_payload /* big enough buffer reuse */,
                       sizeof find_payload, requester_id, &entry, 1u, now_ms());
    dlen = build_frame(dgram, sizeof dgram, QIHSE_BUS_MSG_DHT_NODES,
                       find_payload, plen);
    drain_fd(hinted); /* before the datagram, so the dial cannot be drained */
    assert(send_datagram(raw, "127.0.0.1", f.bus_port, dgram, dlen));
    assert(expect_frame(hinted, QIHSE_BUS_MSG_MEET, 3000, NULL));
    uint16_t idx = QIHSE_CLUSTER_NODE_NONE;
    assert(!qihse_cluster_topology_find_node(f.topo, live_hostile_id, &idx));

    close(hinted);
    close(raw);
    qihse_overlay_dht_stop();
    fixture_down(&f);
    printf("PASS live: FIND answered over UDP, NODES dials once and yields no "
           "membership\n");
}

/* ── main ──────────────────────────────────────────────────────────────── */

int main(void) {
    char data_root[] = "build/dht_peer_exchange_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[256];
    snprintf(key_dir, sizeof key_dir, "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("DhtPeerPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "DhtPeerPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_store = qihse_kv_store_create();
    assert(g_store);

    test_gate_and_default();
    test_find_returns_closer_peers();
    test_dht_record_never_yields_membership();
    test_bad_records_are_dropped();
    test_revoked_identity_never_dialed(key_dir);
    test_floods_are_bounded();
    test_live_udp_exchange();

    qihse_kv_store_destroy(g_store);

    char cmd[512];
    snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", data_root);
    assert(system(cmd) == 0);

    printf("dht peer exchange tests passed\n");
    return 0;
}
