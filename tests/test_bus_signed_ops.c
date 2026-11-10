/*
 * test_bus_signed_ops.c — hybrid bus upgrade (roadmap improvement 5).
 *
 * The four authority-adjacent ops frame classes (SLOT_UPDATE, NODE_UPDATE,
 * GROUP_UPDATE, GROUP_ACK) carry an ML-DSA-87 signature trailer appended
 * after the payload.  This suite drives qihse_cluster_bus_inject() exactly
 * like tests/test_federation_bus_trust.c and asserts:
 *   a. a correctly signed SLOT_UPDATE is verified against the signer's
 *      ENROLLED identity, but cannot change ownership without data proof;
 *   b. one flipped payload byte after signing -> the whole datagram is
 *      dropped (fail closed, nothing reaches the handler);
 *   c. a signature from an UNENROLLED node id is dropped;
 *   d. require_signed_ops refuses UNSIGNED ops frames;
 *   e. unsigned liveness frames still work on a hardened bus (PING/PONG
 *      must work pre-enrollment and confer no authority).
 */

#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    qihse_federation_node_identity_t peer; /* enrolled signer */
    void* peer_pkey;
    qihse_federation_node_identity_t stranger; /* NOT enrolled */
    void* stranger_pkey;
} fixture_t;

static void fixture_up(fixture_t* f, bool require_signed, const char* tag) {
    memset(f, 0, sizeof(*f));
    f->topology = qihse_cluster_topology_create();
    assert(f->topology);
    for (uint16_t i = 0; i < 3; i++) {
        char seed[32];
        snprintf(seed, sizeof(seed), "signed-ops-node-%u", i);
        qihse_cluster_node_t node;
        memset(&node, 0, sizeof(node));
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(17200u + i);
        node.healthy = true;
        uint16_t idx = 0;
        assert(qihse_cluster_topology_upsert_node(f->topology, &node, &idx));
    }
    assert(qihse_cluster_topology_set_local_node(f->topology, 0));

    char dir[128];
    snprintf(dir, sizeof(dir), "build/bus_signed_ops_XXXXXX");
    assert(mkdtemp(dir));
    setenv("QIHSE_DATA_DIR", dir, 1);
    g_store = qihse_kv_store_create();
    assert(g_store);
    assert(qihse_auth_init());
    if (!qihse_auth_bootstrap_operator("SignedOpsPass1!")) {
        setenv("QIHSE_OPERATOR_PASSWORD", "SignedOpsPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);

    /* Enrolled signer (peer). */
    char useed[48];
    snprintf(useed, sizeof(useed), "signed-ops-peer-%s", tag);
    assert(qihse_uuid_from_seed(useed, strlen(useed), &f->peer.node_id));
    snprintf(f->peer.hostname, sizeof(f->peer.hostname), "signed-peer");
    snprintf(f->peer.boot_id, sizeof(f->peer.boot_id), "signed-boot");
    f->peer.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(dir, QIHSE_SIG_ML_DSA_87,
                                            &f->peer));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &f->peer));
    assert(qihse_federation_node_enroll_approve(g_store, g_op,
                                                &f->peer.node_id, 1));
    f->peer_pkey = qihse_federation_node_key_load(f->peer.key_handle);
    assert(f->peer_pkey);

    /* Unenrolled stranger: keys exist, no enrollment record. */
    char sseed[64];
    snprintf(sseed, sizeof(sseed), "signed-ops-stranger-%s", tag);
    assert(qihse_uuid_from_seed(sseed, strlen(sseed),
                                &f->stranger.node_id));
    snprintf(f->stranger.hostname, sizeof(f->stranger.hostname), "stranger");
    snprintf(f->stranger.boot_id, sizeof(f->stranger.boot_id), "stranger-boot");
    f->stranger.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(dir, QIHSE_SIG_ML_DSA_65,
                                            &f->stranger));
    f->stranger_pkey = qihse_federation_node_key_load(f->stranger.key_handle);
    assert(f->stranger_pkey);

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = f->topology;
    cfg.local_node_index = 0;
    cfg.bus_port = 0;
    cfg.bind_address = "127.0.0.1";
    cfg.federation_store = g_store;
    cfg.federation_user = g_op;
    cfg.require_signed_ops = require_signed;
    f->bus = qihse_cluster_bus_create(&cfg);
    assert(f->bus);
}

static void fixture_down(fixture_t* f) {
    if (f->bus) qihse_cluster_bus_destroy(f->bus);
    if (f->peer_pkey) qihse_federation_node_key_free(f->peer_pkey);
    if (f->stranger_pkey) qihse_federation_node_key_free(f->stranger_pkey);
    if (f->topology) qihse_cluster_topology_destroy(f->topology);
    if (g_store) {
        qihse_kv_store_destroy(g_store);
        g_store = NULL;
    }
    qihse_audit_shutdown();
}

/* Build the 16-byte header + payload frame for an ops update. */
static size_t build_slot_frame(uint8_t* out, size_t cap, uint16_t start,
                               uint16_t end, const char* owner_id,
                               uint64_t epoch) {
    assert(cap > 16u + sizeof(qihse_cluster_bus_slot_update_t));
    memset(out, 0, 16u);
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC, type = QIHSE_BUS_MSG_SLOT_UPDATE;
    uint32_t sender = 1u;
    uint32_t plen = (uint32_t)sizeof(qihse_cluster_bus_slot_update_t);
    memcpy(out, &magic, 4u);
    memcpy(out + 4u, &type, 4u);
    memcpy(out + 8u, &sender, 4u);
    memcpy(out + 12u, &plen, 4u);
    qihse_cluster_bus_slot_update_t upd;
    memset(&upd, 0, sizeof(upd));
    upd.start = start;
    upd.end = end;
    if (owner_id) snprintf(upd.owner_id, sizeof(upd.owner_id), "%s", owner_id);
    upd.config_epoch = epoch;
    memcpy(out + 16u, &upd, sizeof(upd));
    return 16u + plen;
}

/* Sign frame[0..len) as `identity` and append the trailer. */
static size_t append_trailer(uint8_t* out, size_t cap, const uint8_t* frame,
                             size_t len, void* pkey,
                             const qihse_federation_node_identity_t* id) {
    uint8_t sig[4627];
    size_t sig_len = sizeof(sig);
    assert(qihse_federation_sign(pkey, frame, len, sig, &sig_len));
    assert(cap >= len + 4u + 2u + 16u + sig_len + 3u);
    uint8_t* t = out;
    memcpy(t, frame, len);
    t += len;
    *t++ = 1; /* alg advisory */
    *t++ = (uint8_t)(sig_len & 0xFF);
    *t++ = (uint8_t)(sig_len >> 8);
    memcpy(t, id->node_id.bytes, 16u);
    t += 16u;
    memcpy(t, sig, sig_len);
    t += sig_len;
    /* footer mirrors alg+len so the reader locates from the end */
    *t++ = 1;
    *t++ = (uint8_t)(sig_len & 0xFF);
    *t++ = (uint8_t)(sig_len >> 8);
    *t++ = 'Q'; *t++ = 'B'; *t++ = 'S';
    return (size_t)(t - out);
}

static void test_signed_roundtrip(fixture_t* f) {
    uint8_t frame[512], dgram[QIHSE_CLUSTER_BUS_MAX_DATAGRAM];
    qihse_cluster_node_t local_node, remote_node;
    assert(qihse_cluster_topology_get_node(f->topology, 0u, &local_node));
    assert(qihse_cluster_topology_get_node(f->topology, 1u, &remote_node));
    assert(qihse_cluster_topology_assign_range(f->topology, 100u, 149u, 0u));
    assert(qihse_cluster_topology_assign_range(f->topology, 150u, 199u, 2u));

    qihse_user_t* low = qihse_auth_create_user(g_op, 90u, QIHSE_ROLE_GUEST,
                                               0u, 0u, "BusLowPass123!", false);
    assert(low);
    char protected_key[64] = {0};
    for (unsigned i = 0; i < 100000u; i++) {
        snprintf(protected_key, sizeof(protected_key), "bus:protected:%u", i);
        uint16_t slot = qihse_cluster_key_slot(protected_key, strlen(protected_key));
        if (slot >= 100u && slot <= 199u) break;
    }
    uint16_t protected_slot = qihse_cluster_key_slot(protected_key, strlen(protected_key));
    assert(protected_slot >= 100u && protected_slot <= 199u);
    assert(qihse_kv_set_user(g_store, protected_key, "HIGH-SCI-BUS-PAYLOAD", 5u, 9u, g_op));
    assert(qihse_kv_get_user(g_store, protected_key, low) == NULL);

    /* A signed same-owner announcement is observable but changes no map. */
    size_t flen = build_slot_frame(frame, sizeof(frame), 100u, 149u,
                                   local_node.id, local_node.config_epoch);
    size_t dlen = append_trailer(dgram, sizeof(dgram), frame, flen,
                                 f->peer_pkey, &f->peer);
    assert(qihse_cluster_bus_inject(f->bus, dgram, dlen, "127.0.0.1", 17001));
    qihse_cluster_bus_stats_t st;
    qihse_cluster_bus_stats(f->bus, &st);
    assert(st.signed_ops_accepted == 1u);
    assert(st.signed_ops_rejected == 0u);
    assert(st.slot_updates_received == 1u);

    /* Even an enrolled signer and epoch 0 cannot overwrite a mixed range. */
    flen = build_slot_frame(frame, sizeof(frame), 100u, 199u,
                            remote_node.id, 0u);
    dlen = append_trailer(dgram, sizeof(dgram), frame, flen,
                          f->peer_pkey, &f->peer);
    assert(qihse_cluster_bus_inject(f->bus, dgram, dlen, "127.0.0.1", 17001));
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_get_slot(f->topology, 100u, &owner, NULL, NULL));
    assert(owner == 0u);
    assert(qihse_cluster_topology_get_slot(f->topology, 150u, &owner, NULL, NULL));
    assert(owner == 2u);

    /* An unknown/empty owner must not unassign the range either. */
    flen = build_slot_frame(frame, sizeof(frame), 100u, 199u, NULL, 0u);
    dlen = append_trailer(dgram, sizeof(dgram), frame, flen,
                          f->peer_pkey, &f->peer);
    assert(qihse_cluster_bus_inject(f->bus, dgram, dlen, "127.0.0.1", 17001));
    assert(qihse_cluster_topology_get_slot(f->topology, 150u, &owner, NULL, NULL));
    assert(owner == 2u);
    qihse_cluster_bus_stats(f->bus, &st);
    assert(st.signed_ops_accepted == 3u && st.slot_updates_received == 1u);
    assert(qihse_kv_get_user(g_store, protected_key, low) == NULL);
    char* protected_value = qihse_kv_get_user(g_store, protected_key, g_op);
    assert(protected_value && strcmp(protected_value, "HIGH-SCI-BUS-PAYLOAD") == 0);
    free(protected_value);
    char journal_path[512];
    snprintf(journal_path, sizeof(journal_path), "%s/slot-ownership.journal",
             getenv("QIHSE_DATA_DIR"));
    errno = 0;
    assert(access(journal_path, F_OK) == -1 && errno == ENOENT);
    printf("PASS (s1) signed slot gossip verified; ownership, journal, and SCI data preserved\n");
}

static void test_tampered_dropped(fixture_t* f) {
    uint8_t frame[512], dgram[QIHSE_CLUSTER_BUS_MAX_DATAGRAM];
    size_t flen = build_slot_frame(frame, sizeof(frame), 200u, 299u, NULL, 0u);
    size_t dlen = append_trailer(dgram, sizeof(dgram), frame, flen,
                                 f->peer_pkey, &f->peer);
    dgram[17] ^= 0xFF; /* flip one payload byte after signing */
    assert(qihse_cluster_bus_inject(f->bus, dgram, dlen, "127.0.0.1", 17001));
    qihse_cluster_bus_stats_t st;
    qihse_cluster_bus_stats(f->bus, &st);
    assert(st.signed_ops_rejected >= 1u);
    assert(st.slot_updates_received == 1u); /* only s1's update applied */
    printf("PASS (s2) tampered signed frame dropped, handler never ran\n");
}

static void test_unenrolled_signer_dropped(fixture_t* f) {
    uint8_t frame[512], dgram[QIHSE_CLUSTER_BUS_MAX_DATAGRAM];
    size_t flen = build_slot_frame(frame, sizeof(frame), 300u, 399u, NULL, 0u);
    size_t dlen = append_trailer(dgram, sizeof(dgram), frame, flen,
                                 f->stranger_pkey, &f->stranger);
    assert(qihse_cluster_bus_inject(f->bus, dgram, dlen, "127.0.0.1", 17001));
    qihse_cluster_bus_stats_t st;
    qihse_cluster_bus_stats(f->bus, &st);
    assert(st.signed_ops_rejected >= 1u);
    assert(st.slot_updates_received == 1u);
    printf("PASS (s3) unenrolled signer dropped even with a valid signature\n");
}

static void test_require_signed_ops(void) {
    fixture_t f;
    fixture_up(&f, true, "b"); /* hardened mode */

    /* Unsigned SLOT_UPDATE: refused. */
    uint8_t frame[512];
    size_t flen = build_slot_frame(frame, sizeof(frame), 400u, 499u, NULL, 0u);
    assert(qihse_cluster_bus_inject(f.bus, frame, flen, "127.0.0.1", 17001));
    qihse_cluster_bus_stats_t st;
    qihse_cluster_bus_stats(f.bus, &st);
    assert(st.unsigned_ops_refused == 1u);
    assert(st.slot_updates_received == 0u);

    /* Unsigned PONG (liveness): still processed — bootstrap/liveness must
     * work pre-enrollment and confer no authority. */
    uint8_t pong[128];
    memset(pong, 0, sizeof(pong));
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC, type = QIHSE_BUS_MSG_PONG;
    uint32_t sender = 1u, plen = 40u;
    memcpy(pong, &magic, 4u);
    memcpy(pong + 4u, &type, 4u);
    memcpy(pong + 8u, &sender, 4u);
    memcpy(pong + 12u, &plen, 4u);
    assert(qihse_cluster_bus_inject(f.bus, pong, 16u + 40u, "127.0.0.1",
                                    17001));
    qihse_cluster_bus_stats(f.bus, &st);
    assert(st.unsigned_ops_refused == 1u); /* unchanged: PONG is not ops */

    fixture_down(&f);
    printf("PASS (s4) require_signed_ops refuses unsigned ops frames; "
           "liveness unaffected\n");
}

static uint16_t reserve_udp_port(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static void test_real_sender_wire_and_max_payload(void) {
    fixture_t f;
    fixture_up(&f, true, "producer");

    /* Recreate the receiver with a known loopback port and a pinned signer.
     * Sending through send_frame exercises production BE header encoding,
     * signature selection, trailer sizing, UDP emission and receive verify. */
    qihse_cluster_bus_destroy(f.bus);
    f.bus = NULL;
    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = f.topology;
    cfg.local_node_index = 0;
    cfg.bus_port = reserve_udp_port();
    cfg.bind_address = "127.0.0.1";
    cfg.federation_store = g_store;
    cfg.federation_user = g_op;
    cfg.require_signed_ops = true;
    cfg.local_node_uuid = &f.peer.node_id;
    cfg.federation_sign_key = f.peer_pkey;
    f.bus = qihse_cluster_bus_create(&cfg);
    assert(f.bus && qihse_cluster_bus_start(f.bus));

    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    memset(payload, 0x5a, sizeof(payload));
    uint8_t max_sig[4627];
    size_t max_sig_len = sizeof(max_sig);
    assert(qihse_federation_sign(f.peer_pkey, payload, 1u, max_sig,
                                 &max_sig_len));
    assert(max_sig_len == sizeof(max_sig));
    assert(QIHSE_CLUSTER_BUS_SIG_TRAILER_MAX == 25u + 4627u);
    assert(QIHSE_CLUSTER_BUS_MAX_DATAGRAM ==
           QIHSE_CLUSTER_BUS_HEADER_SIZE + QIHSE_CLUSTER_BUS_MAX_PAYLOAD +
               25u + 4627u);
    assert(qihse_cluster_bus_send_frame(f.bus, QIHSE_BUS_MSG_SLOT_UPDATE,
                                       payload, sizeof(payload), "127.0.0.1",
                                       cfg.bus_port));

    qihse_cluster_bus_stats_t st;
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    bool received = false;
    for (unsigned i = 0; i < 2000u; ++i) {
        qihse_cluster_bus_stats(f.bus, &st);
        if (st.signed_ops_accepted == 1u) { received = true; break; }
        nanosleep(&pause, NULL);
    }
    assert(received);
    assert(st.signed_ops_rejected == 0u);
    assert(st.unsigned_ops_refused == 0u);

    /* Unsigned liveness is intentionally still accepted on this hardened
     * receiver; signing the operational class must not gate PONG. */
    uint8_t pong[40] = {0};
    assert(qihse_cluster_bus_send_frame(f.bus, QIHSE_BUS_MSG_PONG, pong,
                                       sizeof(pong), "127.0.0.1", cfg.bus_port));
    received = false;
    for (unsigned i = 0; i < 2000u; ++i) {
        qihse_cluster_bus_stats(f.bus, &st);
        if (st.received >= 2u) { received = true; break; }
        nanosleep(&pause, NULL);
    }
    assert(received);
    assert(st.signed_ops_accepted == 1u);
    assert(st.unsigned_ops_refused == 0u);
    fixture_down(&f);
    printf("PASS (s5) production sender emits pinned signature trailer at max payload; unsigned PONG remains live\n");
}

int main(void) {
    fixture_t f;
    fixture_up(&f, false, "a");
    test_signed_roundtrip(&f);
    test_tampered_dropped(&f);
    test_unenrolled_signer_dropped(&f);
    fixture_down(&f);
    test_require_signed_ops();
    test_real_sender_wire_and_max_payload();

    qihse_kv_store_destroy(g_store);
    printf("bus signed-ops tests passed\n");
    return 0;
}
