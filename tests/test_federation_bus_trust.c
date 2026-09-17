/*
 * test_federation_bus_trust.c — the federation trust plane over the cluster bus.
 *
 * This is the test that matters for the brief's rule: "Never trust a UDP
 * datagram merely because its source IP matches a configured peer."
 *
 * Every case here injects a datagram whose SOURCE is a configured, healthy
 * peer.  The only thing that varies is the CONTENT.  If the bus were still
 * trusting by source, every case would be accepted.
 */
#include "qihse_auth.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

/* ── Callback capture ──────────────────────────────────────────────────── */

/* Two separate captures, mirroring the two callbacks.  A heartbeat must never
 * reach the membership capture, and a statement must never reach the liveness
 * one: the payload types differ, so a consumer cannot mix them up. */
typedef struct {
    uint32_t liveness_calls;
    uint32_t membership_calls;
    qihse_uuid_t last_sender;
    uint32_t last_health;
    qihse_sig_alg_t last_alg;
    qihse_uuid_t last_session;
} fed_capture_t;

static void fed_liveness_cb(qihse_cluster_bus_t* bus,
                            const qihse_federation_liveness_t* obs, void* user_data) {
    (void)bus;
    fed_capture_t* c = (fed_capture_t*)user_data;
    c->liveness_calls++;
    c->last_sender = obs->sender_node;
    c->last_health = obs->health_summary;
}

static void fed_membership_cb(qihse_cluster_bus_t* bus,
                              const qihse_federation_membership_t* member, void* user_data) {
    (void)bus;
    fed_capture_t* c = (fed_capture_t*)user_data;
    c->membership_calls++;
    c->last_sender = member->sender_node;
    c->last_health = member->health_summary;
    c->last_alg = member->sig_alg;
    c->last_session = member->session_id;
}

/* Total callbacks, either tier. */
static uint32_t capture_total(const fed_capture_t* c) {
    return c->liveness_calls + c->membership_calls;
}

/* ── Datagram construction (mirrors the bus wire header) ───────────────── */

#define BUS_HDR 16u

static size_t build_datagram(uint8_t* out, size_t cap, uint32_t type,
                             uint32_t sender_index,
                             const uint8_t* payload, size_t payload_len) {
    assert(cap >= BUS_HDR + payload_len);
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t plen = (uint32_t)payload_len;
    memcpy(out, &magic, 4);
    memcpy(out + 4, &type, 4);
    memcpy(out + 8, &sender_index, 4);
    memcpy(out + 12, &plen, 4);
    if (payload_len) memcpy(out + BUS_HDR, payload, payload_len);
    return BUS_HDR + payload_len;
}

/* ── Fixture ───────────────────────────────────────────────────────────── */

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    fed_capture_t capture;
    qihse_federation_node_identity_t identity;
    void* pkey;
    qihse_uuid_t cluster_id;
    qihse_uuid_t boot_id;
    qihse_uuid_t session_id;
    uint32_t peer_index;
} fixture_t;

static void fixture_up(fixture_t* f, const char* key_dir, bool with_fed_context) {
    memset(f, 0, sizeof(*f));
    /* Each fixture needs a distinct peer identity, since they share one store. */
    static uint32_t fixture_seq = 0;
    char peer_seed[48];
    snprintf(peer_seed, sizeof(peer_seed), "bus-trust-peer-%u", fixture_seq++);

    /* A three-node topology.  Node 1 is the peer we will impersonate: it is
     * configured, healthy, and its index is what a datagram will claim. */
    f->topology = qihse_cluster_topology_create();
    assert(f->topology);
    for (uint16_t i = 0; i < 3; i++) {
        char seed[32];
        snprintf(seed, sizeof(seed), "bus-trust-node-%u", i);
        qihse_cluster_node_t node;
        memset(&node, 0, sizeof(node));
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(17000u + i);
        node.healthy = true;
        uint16_t idx = 0;
        assert(qihse_cluster_topology_upsert_node(f->topology, &node, &idx));
        assert(idx == i);
    }
    assert(qihse_cluster_topology_set_local_node(f->topology, 0));
    f->peer_index = 1;

    /* Enroll node 1's identity so its key is on record. */
    assert(qihse_uuid_from_seed(peer_seed, strlen(peer_seed), &f->identity.node_id));
    snprintf(f->identity.hostname, sizeof(f->identity.hostname), "bus-peer");
    snprintf(f->identity.boot_id, sizeof(f->identity.boot_id), "bus-boot");
    f->identity.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_65, &f->identity));
    assert(qihse_federation_node_enroll_request(g_store, g_op, &f->identity));
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &f->identity.node_id, 1));
    f->pkey = qihse_federation_node_key_load(f->identity.key_handle);
    assert(f->pkey);

    assert(qihse_uuid_from_seed("bus-trust-cluster", strlen("bus-trust-cluster"),
                                &f->cluster_id));
    assert(qihse_uuid_from_seed(peer_seed, strlen(peer_seed), &f->boot_id));
    assert(qihse_uuid_generate(&f->session_id));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = f->topology;
    cfg.local_node_index = 0;
    cfg.bus_port = 0;            /* no real socket: we inject datagrams */
    cfg.bind_address = "127.0.0.1";
    if (with_fed_context) {
        cfg.federation_store = g_store;
        cfg.federation_user = g_op;
        cfg.on_liveness = fed_liveness_cb;
        cfg.on_liveness_user_data = &f->capture;
        cfg.on_membership = fed_membership_cb;
        cfg.on_membership_user_data = &f->capture;
    }
    f->bus = qihse_cluster_bus_create(&cfg);
    assert(f->bus);
}

static void fixture_down(fixture_t* f) {
    if (f->bus) qihse_cluster_bus_destroy(f->bus);
    if (f->pkey) qihse_federation_node_key_free(f->pkey);
    if (f->topology) qihse_cluster_topology_destroy(f->topology);
}

/* ── Tests ─────────────────────────────────────────────────────────────── */

static void test_authority_classification(void) {
    /* The bootstrap and liveness types must never carry authority, because a
     * node cannot verify a peer it has not enrolled yet. */
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_MEET));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_PING));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_PONG));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_FAIL));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_SLOT_UPDATE));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_NODE_UPDATE));
    assert(!qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_GROUP_UPDATE));
    /* Only the verified, signed types may. */
    assert(qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_FED_STATEMENT));
    assert(qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_FED_HEARTBEAT));

    printf("PASS authority classification: bootstrap/liveness types excluded, signed types included\n");
}

static void test_heartbeat_without_statement_is_dropped(const char* key_dir) {
    fixture_t f;
    fixture_up(&f, key_dir, true);

    /* The source is a configured, healthy peer.  Under the old model that was
     * sufficient.  It must not be now. */
    qihse_federation_heartbeat_t hb;
    memset(&hb, 0, sizeof(hb));
    hb.magic = QIHSE_FEDERATION_HEARTBEAT_MAGIC;
    hb.version = QIHSE_FEDERATION_HEARTBEAT_VERSION;
    hb.sender_node = f.identity.node_id;
    hb.boot_id = f.boot_id;
    hb.session_id = f.session_id;
    hb.sequence = 1;

    uint8_t payload[256];
    size_t plen = 0;
    assert(qihse_federation_heartbeat_serialize(&hb, payload, sizeof(payload), &plen));

    uint8_t dgram[512];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_HEARTBEAT,
                                 f.peer_index, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001));

    /* No statement has been signed, so there is no session to match and the
     * frame must not reach a consumer. */
    assert(capture_total(&f.capture) == 0);

    fixture_down(&f);
    printf("PASS heartbeat from a configured peer without a signed statement: dropped\n");
}

static void test_forged_statement_is_dropped(const char* key_dir) {
    fixture_t f;
    fixture_up(&f, key_dir, true);

    /* A statement claiming to be the peer, signed by a key the peer does not
     * own.  The source index is still the peer's. */
    qihse_federation_node_identity_t attacker;
    memset(&attacker, 0, sizeof(attacker));
    assert(qihse_uuid_from_seed("bus-trust-attacker", strlen("bus-trust-attacker"),
                                &attacker.node_id));
    snprintf(attacker.hostname, sizeof(attacker.hostname), "attacker");
    snprintf(attacker.boot_id, sizeof(attacker.boot_id), "attacker-boot");
    attacker.identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_65, &attacker));
    void* bad_key = qihse_federation_node_key_load(attacker.key_handle);
    assert(bad_key);

    qihse_federation_gossip_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    stmt.version = QIHSE_FEDERATION_GOSSIP_VERSION;
    stmt.cluster_id = f.cluster_id;
    stmt.sender_node = f.identity.node_id;   /* claims to be the enrolled peer */
    stmt.boot_id = f.boot_id;
    stmt.session_id = f.session_id;
    stmt.sequence = 1;
    stmt.health_summary = 0xDEADBEEFu;
    assert(qihse_federation_gossip_sign(bad_key, &stmt));

    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t signed_len = 0;
    assert(qihse_federation_gossip_serialize(&stmt, payload, sizeof(payload), &signed_len));
    memcpy(payload + signed_len, stmt.signature, stmt.signature_len);
    size_t plen = signed_len + stmt.signature_len;

    uint8_t dgram[QIHSE_CLUSTER_BUS_MAX_PAYLOAD + 64u];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 f.peer_index, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001));
    assert(capture_total(&f.capture) == 0);

    qihse_federation_node_key_free(bad_key);
    fixture_down(&f);
    printf("PASS forged statement from a configured peer: signature rejected, no callback\n");
}

static void test_valid_statement_then_heartbeat(const char* key_dir) {
    fixture_t f;
    fixture_up(&f, key_dir, true);

    /* A correctly signed statement. */
    qihse_federation_gossip_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    stmt.version = QIHSE_FEDERATION_GOSSIP_VERSION;
    stmt.cluster_id = f.cluster_id;
    stmt.sender_node = f.identity.node_id;
    stmt.boot_id = f.boot_id;
    stmt.session_id = f.session_id;
    stmt.sequence = 1;
    stmt.hlc.physical_ms = 4242;
    stmt.capability_bitmap = 0x1F;
    stmt.health_summary = 7;
    assert(qihse_federation_gossip_sign(f.pkey, &stmt));
    assert(stmt.sig_alg == QIHSE_SIG_ML_DSA_65);

    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t signed_len = 0;
    assert(qihse_federation_gossip_serialize(&stmt, payload, sizeof(payload), &signed_len));
    memcpy(payload + signed_len, stmt.signature, stmt.signature_len);
    size_t plen = signed_len + stmt.signature_len;

    uint8_t dgram[QIHSE_CLUSTER_BUS_MAX_PAYLOAD + 64u];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 f.peer_index, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001));
    assert(f.capture.membership_calls == 1);
    assert(f.capture.liveness_calls == 0);
    assert(f.capture.last_health == 7);
    assert(f.capture.last_alg == QIHSE_SIG_ML_DSA_65);
    assert(qihse_uuid_equal(&f.capture.last_session, &f.session_id));
    assert(qihse_uuid_equal(&f.capture.last_sender, &f.identity.node_id));

    /* Replaying the same statement must not reach the consumer again. */
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001));
    assert(f.capture.membership_calls == 1);

    /* Now the cheap tier works, and is far smaller than the statement. */
    qihse_federation_heartbeat_t hb;
    memset(&hb, 0, sizeof(hb));
    hb.magic = QIHSE_FEDERATION_HEARTBEAT_MAGIC;
    hb.version = QIHSE_FEDERATION_HEARTBEAT_VERSION;
    hb.sender_node = f.identity.node_id;
    hb.boot_id = f.boot_id;
    hb.session_id = f.session_id;
    hb.sequence = 1;
    hb.health_summary = 9;
    uint8_t hb_wire[128];
    size_t hb_len = 0;
    assert(qihse_federation_heartbeat_serialize(&hb, hb_wire, sizeof(hb_wire), &hb_len));
    assert(hb_len == 80u);
    assert(hb_len < plen);   /* the whole point of the two-tier design */

    uint8_t hb_dgram[256];
    size_t hb_dlen = build_datagram(hb_dgram, sizeof(hb_dgram), QIHSE_BUS_MSG_FED_HEARTBEAT,
                                    f.peer_index, hb_wire, hb_len);
    assert(qihse_cluster_bus_inject(f.bus, hb_dgram, hb_dlen, "127.0.0.1", 17001));
    assert(f.capture.liveness_calls == 1);
    /* THE POINT: a heartbeat must never reach the membership capture.  A
     * consumer that needs authority has no liveness input to misuse. */
    assert(f.capture.membership_calls == 1);   /* unchanged */
    assert(f.capture.last_health == 9);

    /* A heartbeat on a retired session is refused even at a higher sequence. */
    qihse_uuid_t new_session;
    assert(qihse_uuid_generate(&new_session));
    qihse_federation_gossip_t stmt2 = stmt;
    stmt2.session_id = new_session;
    stmt2.sequence = 2;
    assert(qihse_federation_gossip_sign(f.pkey, &stmt2));
    size_t s2_len = 0;
    assert(qihse_federation_gossip_serialize(&stmt2, payload, sizeof(payload), &s2_len));
    memcpy(payload + s2_len, stmt2.signature, stmt2.signature_len);
    size_t s2_plen = s2_len + stmt2.signature_len;
    size_t s2_dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                    f.peer_index, payload, s2_plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, s2_dlen, "127.0.0.1", 17001));
    assert(f.capture.membership_calls == 2);

    qihse_federation_heartbeat_t stale = hb;
    stale.sequence = 500;
    size_t stale_len = 0;
    assert(qihse_federation_heartbeat_serialize(&stale, hb_wire, sizeof(hb_wire), &stale_len));
    size_t stale_dlen = build_datagram(hb_dgram, sizeof(hb_dgram), QIHSE_BUS_MSG_FED_HEARTBEAT,
                                       f.peer_index, hb_wire, stale_len);
    assert(qihse_cluster_bus_inject(f.bus, hb_dgram, stale_dlen, "127.0.0.1", 17001));
    assert(f.capture.liveness_calls == 1);   /* unchanged: retired session */
    assert(f.capture.membership_calls == 2);

    fixture_down(&f);
    printf("PASS valid statement accepted, cheap heartbeat accepted, replay and stale session dropped\n");
}

static void test_no_context_fails_closed(const char* key_dir) {
    /* A bus with NO federation context must drop federation frames rather than
     * trust them.  This is the fail-closed default for a misconfigured node. */
    fixture_t f;
    fixture_up(&f, key_dir, false);

    qihse_federation_gossip_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    stmt.version = QIHSE_FEDERATION_GOSSIP_VERSION;
    stmt.cluster_id = f.cluster_id;
    stmt.sender_node = f.identity.node_id;
    stmt.boot_id = f.boot_id;
    stmt.session_id = f.session_id;
    stmt.sequence = 1;
    assert(qihse_federation_gossip_sign(f.pkey, &stmt));

    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t signed_len = 0;
    assert(qihse_federation_gossip_serialize(&stmt, payload, sizeof(payload), &signed_len));
    memcpy(payload + signed_len, stmt.signature, stmt.signature_len);
    size_t plen = signed_len + stmt.signature_len;

    uint8_t dgram[QIHSE_CLUSTER_BUS_MAX_PAYLOAD + 64u];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 f.peer_index, payload, plen);
    /* Injected and accepted by the transport, but no callback is registered so
     * nothing consumes it, and the federation record is not written either. */
    (void)qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001);
    assert(capture_total(&f.capture) == 0);

    /* Prove nothing was recorded: no statement exists for this peer. */
    qihse_federation_gossip_t stored;
    assert(!qihse_federation_gossip_statement_read(g_store, g_op,
                                                  &f.identity.node_id, &f.boot_id, &stored));

    fixture_down(&f);
    printf("PASS no federation context: signed frames dropped, nothing recorded\n");
}

static void test_malformed_frames_are_dropped(const char* key_dir) {
    fixture_t f;
    fixture_up(&f, key_dir, true);

    uint8_t dgram[QIHSE_CLUSTER_BUS_MAX_PAYLOAD + 64u];

    /* A statement payload that is too short to be a statement. */
    uint8_t tiny[8] = { 0 };
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 f.peer_index, tiny, sizeof(tiny));
    (void)qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001);

    /* A heartbeat payload of the wrong length. */
    uint8_t short_hb[40] = { 0 };
    dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_HEARTBEAT,
                          f.peer_index, short_hb, sizeof(short_hb));
    (void)qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001);

    /* An all-zero payload of exactly statement-region size, naming algorithm 0
     * (Ed25519) with a signature length that does not match. */
    uint8_t zeros[512];
    memset(zeros, 0, sizeof(zeros));
    dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                          f.peer_index, zeros, sizeof(zeros));
    (void)qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17001);

    assert(capture_total(&f.capture) == 0);


    fixture_down(&f);
    printf("PASS malformed federation frames: dropped without reaching a consumer\n");
}

static void test_membership_conversion_chokepoint(void) {
    /* A membership record is only ever derived from a well-formed statement.
     * There is deliberately no conversion from a liveness observation, so a
     * consumer that needs authority has no liveness-shaped input to pass. */
    qihse_federation_gossip_t stmt;
    memset(&stmt, 0, sizeof(stmt));
    stmt.magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    stmt.version = QIHSE_FEDERATION_GOSSIP_VERSION;
    stmt.sig_alg = QIHSE_SIG_ML_DSA_65;
    stmt.signature_len = (uint16_t)qihse_sig_alg_signature_bytes(QIHSE_SIG_ML_DSA_65);
    stmt.sequence = 42;
    stmt.capability_bitmap = 0x0F;
    stmt.health_summary = 3;
    assert(qihse_uuid_generate(&stmt.sender_node));
    assert(qihse_uuid_generate(&stmt.session_id));

    qihse_federation_membership_t member;
    assert(qihse_federation_membership_from_statement(&stmt, &member));
    assert(qihse_uuid_equal(&member.sender_node, &stmt.sender_node));
    assert(qihse_uuid_equal(&member.session_id, &stmt.session_id));
    assert(member.sequence == 42);
    assert(member.capability_bitmap == 0x0F);
    assert(member.sig_alg == QIHSE_SIG_ML_DSA_65);

    /* A malformed statement yields no membership record. */
    qihse_federation_gossip_t bad = stmt;
    bad.magic = 0xDEADBEEFu;
    assert(!qihse_federation_membership_from_statement(&bad, &member));
    bad = stmt;
    bad.version = 99;
    assert(!qihse_federation_membership_from_statement(&bad, &member));
    /* A signature length that disagrees with the named algorithm is refused,
     * so a truncated signature cannot become a membership claim. */
    bad = stmt;
    bad.signature_len = 64;
    assert(!qihse_federation_membership_from_statement(&bad, &member));
    assert(!qihse_federation_membership_from_statement(NULL, &member));
    assert(!qihse_federation_membership_from_statement(&stmt, NULL));

    printf("PASS membership chokepoint: only a well-formed statement yields authority input\n");
}

int main(void) {
    char data_root[] = "build/fed_bustrust_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[256];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("BusTrustPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "BusTrustPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_store = qihse_kv_store_create();
    assert(g_store);

    test_authority_classification();
    test_membership_conversion_chokepoint();
    test_heartbeat_without_statement_is_dropped(key_dir);
    test_forged_statement_is_dropped(key_dir);
    test_valid_statement_then_heartbeat(key_dir);
    test_no_context_fails_closed(key_dir);
    test_malformed_frames_are_dropped(key_dir);

    qihse_kv_store_destroy(g_store);
    printf("federation bus trust tests passed\n");
    return 0;
}
