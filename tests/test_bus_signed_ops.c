/*
 * test_bus_signed_ops.c — hybrid bus upgrade (roadmap improvement 5).
 *
 * The four authority-adjacent ops frame classes (SLOT_UPDATE, NODE_UPDATE,
 * GROUP_UPDATE, GROUP_ACK) carry an ML-DSA-87 signature trailer appended
 * after the payload.  This suite drives qihse_cluster_bus_inject() exactly
 * like tests/test_federation_bus_trust.c and asserts:
 *   a. a correctly signed SLOT_UPDATE is verified against the signer's
 *      ENROLLED identity and applied;
 *   b. one flipped payload byte after signing -> the whole datagram is
 *      dropped (fail closed, nothing reaches the handler);
 *   c. a signature from an UNENROLLED node id is dropped;
 *   d. require_signed_ops refuses UNSIGNED ops frames;
 *   e. unsigned liveness frames still work on a hardened bus (PING/PONG
 *      must work pre-enrollment and confer no authority).
 */

#include "qihse_cluster_bus.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

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
    assert(qihse_federation_node_keygen_alg(dir, QIHSE_SIG_ML_DSA_65,
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
}

/* Build the 16-byte header + payload frame for an ops update. */
static size_t build_slot_frame(uint8_t* out, size_t cap, uint16_t start,
                               uint16_t end) {
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
    uint8_t frame[512], dgram[4096];
    size_t flen = build_slot_frame(frame, sizeof(frame), 100u, 199u);
    size_t dlen = append_trailer(dgram, sizeof(dgram), frame, flen,
                                 f->peer_pkey, &f->peer);
    fprintf(stderr,
            "[tdbg] dlen=%zu trailer@64: alg=%02x lo=%02x hi=%02x "
            "uuid=%02x%02x%02x%02x (expect %02x%02x%02x%02x)\n",
            dlen, dgram[64], dgram[65], dgram[66], dgram[67], dgram[68],
            dgram[69], dgram[70], f->peer.node_id.bytes[0],
            f->peer.node_id.bytes[1], f->peer.node_id.bytes[2],
            f->peer.node_id.bytes[3]);
    assert(qihse_cluster_bus_inject(f->bus, dgram, dlen, "127.0.0.1", 17001));
    qihse_cluster_bus_stats_t st;
    qihse_cluster_bus_stats(f->bus, &st);
    assert(st.signed_ops_accepted == 1u);
    assert(st.signed_ops_rejected == 0u);
    assert(st.slot_updates_received == 1u);
    printf("PASS (s1) signed SLOT_UPDATE verified against enrolled identity "
           "and applied\n");
}

static void test_tampered_dropped(fixture_t* f) {
    uint8_t frame[512], dgram[4096];
    size_t flen = build_slot_frame(frame, sizeof(frame), 200u, 299u);
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
    uint8_t frame[512], dgram[4096];
    size_t flen = build_slot_frame(frame, sizeof(frame), 300u, 399u);
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
    size_t flen = build_slot_frame(frame, sizeof(frame), 400u, 499u);
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

int main(void) {
    fixture_t f;
    fixture_up(&f, false, "a");
    test_signed_roundtrip(&f);
    test_tampered_dropped(&f);
    test_unenrolled_signer_dropped(&f);
    fixture_down(&f);
    test_require_signed_ops();

    qihse_kv_store_destroy(g_store);
    printf("bus signed-ops tests passed\n");
    return 0;
}
