/*
 * test_node_cap_records.c — W2.4: NODE_CAP payloads as first-class durable
 * federation node records at "federation/node/<uuid>" with trust state.
 *
 * Item 1 of the fabric spec had NO test at all before this file
 * (`grep QIHSE_BUS_MSG_NODE_CAP tests/` returned nothing).  The properties
 * asserted here:
 *
 *   1. DURABLE   — a capability record survives a simulated restart: the KV
 *                  store is destroyed and re-created from the same data
 *                  directory, so the record must come back from WAL recovery.
 *                  The in-memory cap_* table cannot provide this (it is
 *                  rebuilt only from incoming datagrams).
 *   2. PRODUCER  — a signature-verified v3 membership statement accepted on
 *                  the bus persists the sender's profile (the remote
 *                  producer), and the bus persists the local node's own
 *                  probe when it is given a local federation UUID.
 *   3. TRUST     — a claim is only recorded for an authenticated node; the
 *                  trust state at admission is part of the record; and
 *                  admissibility re-reads the identity record, so a
 *                  revocation invalidates a record admitted earlier.  An
 *                  unauthenticated NODE_CAP frame updates the live hint table
 *                  but writes NO durable record.
 *   4. MALFORMED — truncated, over-long, out-of-range, non-numeric and
 *                  key/body-mismatched records are refused by the decoder.
 *   5. COMPAT    — a v2 signed statement still verifies against its own v2
 *                  signed bytes, so an existing on-disk statement record
 *                  keeps working after the v3 extension.
 */
#include "qihse_auth.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"
#include "qihse_kv_store.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static qihse_kv_store_t* g_store;
static qihse_user_t* g_op;

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

static uint16_t free_udp_port(void) {
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

/* ── Fixture ───────────────────────────────────────────────────────────── */

static void enroll_node(qihse_federation_node_identity_t* id, const char* seed,
                        const char* key_dir, bool approve) {
    memset(id, 0, sizeof(*id));
    assert(qihse_uuid_from_seed(seed, strlen(seed), &id->node_id));
    snprintf(id->hostname, sizeof(id->hostname), "%s", seed);
    snprintf(id->boot_id, sizeof(id->boot_id), "%s-boot", seed);
    id->identity_kind = QIHSE_IDENTITY_HOST_AGENT;
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_65, id));
    assert(qihse_federation_node_enroll_request(g_store, g_op, id));
    if (approve) {
        assert(qihse_federation_node_enroll_approve(g_store, g_op, &id->node_id, 1));
    }
}

static void fill_statement(qihse_federation_gossip_t* s,
                           const qihse_federation_node_identity_t* id,
                           const qihse_uuid_t* cluster, const qihse_uuid_t* boot,
                           const qihse_uuid_t* session, uint64_t sequence,
                           const qihse_federation_capability_values_t* caps,
                           uint16_t version) {
    memset(s, 0, sizeof(*s));
    s->magic = QIHSE_FEDERATION_GOSSIP_MAGIC;
    s->version = version;
    s->cluster_id = *cluster;
    s->sender_node = id->node_id;
    s->boot_id = *boot;
    s->session_id = *session;
    s->sequence = sequence;
    s->hlc.physical_ms = 1000u + sequence;
    s->capability_bitmap = 0x1Fu;
    if (caps) s->caps = *caps;
}

/* Serialise a signed statement into a bus FED_STATEMENT payload. */
static size_t statement_payload(const qihse_federation_gossip_t* stmt,
                                uint8_t* payload, size_t cap) {
    size_t signed_len = 0;
    assert(qihse_federation_gossip_serialize(stmt, payload, cap, &signed_len));
    assert(signed_len + stmt->signature_len <= cap);
    memcpy(payload + signed_len, stmt->signature, stmt->signature_len);
    return signed_len + stmt->signature_len;
}

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    uint32_t membership_calls;
    qihse_federation_capability_values_t last_caps;
} bus_fixture_t;

static void bus_membership_cb(qihse_cluster_bus_t* bus,
                              const qihse_federation_membership_t* member,
                              void* user_data) {
    (void)bus;
    bus_fixture_t* f = (bus_fixture_t*)user_data;
    f->membership_calls++;
    f->last_caps = member->caps;
}

static void bus_fixture_up(bus_fixture_t* f, const qihse_uuid_t* local_uuid) {
    memset(f, 0, sizeof(*f));
    f->topology = qihse_cluster_topology_create();
    assert(f->topology);
    for (uint16_t i = 0; i < 3; i++) {
        char seed[32];
        snprintf(seed, sizeof(seed), "w24-topo-node-%u", i);
        qihse_cluster_node_t node;
        memset(&node, 0, sizeof(node));
        qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
        snprintf(node.host, sizeof(node.host), "127.0.0.1");
        node.port = (uint16_t)(17100u + i);
        node.bus_port = (uint16_t)(17200u + i);
        node.healthy = true;
        uint16_t idx = 0;
        assert(qihse_cluster_topology_upsert_node(f->topology, &node, &idx));
        assert(idx == i);
    }
    assert(qihse_cluster_topology_set_local_node(f->topology, 0));

    qihse_cluster_bus_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.topology = f->topology;
    cfg.local_node_index = 0;
    cfg.bus_port = free_udp_port();
    cfg.bind_address = "127.0.0.1";
    cfg.federation_store = g_store;
    cfg.federation_user = g_op;
    cfg.local_node_uuid = local_uuid;
    cfg.on_membership = bus_membership_cb;
    cfg.on_membership_user_data = f;
    f->bus = qihse_cluster_bus_create(&cfg);
    assert(f->bus);
}

static void bus_fixture_down(bus_fixture_t* f) {
    if (f->bus) qihse_cluster_bus_destroy(f->bus);
    if (f->topology) qihse_cluster_topology_destroy(f->topology);
}

static void store_restart(void) {
    /* Simulated restart: everything in memory is dropped; the new store must
     * recover the records from the data directory's WAL. */
    qihse_kv_store_destroy(g_store);
    g_store = qihse_kv_store_create();
    assert(g_store);
}

/* ── 1 + 3: local probe, durability, revocation ────────────────────────── */

static void test_local_probe_survives_restart(const char* key_dir) {
    qihse_federation_node_identity_t id;
    enroll_node(&id, "w24-local-node", key_dir, true);

    qihse_federation_capability_values_t v;
    memset(&v, 0, sizeof(v));
    v.isa_tier = 3u;
    v.npu = 1u;
    v.gpu = 0u;
    v.free_ram_mb = 4096u;
    v.load_pct = 1234u;
    assert(qihse_federation_node_capability_record_local(g_store, g_op, &id.node_id, &v));

    qihse_federation_node_capability_t rec;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    assert(qihse_uuid_equal(&rec.node_id, &id.node_id));
    assert(rec.source == QIHSE_CAP_SOURCE_LOCAL_PROBE);
    assert(rec.trust == QIHSE_TRUST_APPROVED);
    assert(rec.flags == 0u);            /* self-reported, never attested */
    assert(rec.values.isa_tier == 3u && rec.values.npu == 1u && rec.values.gpu == 0u);
    assert(rec.values.free_ram_mb == 4096u && rec.values.load_pct == 1234u);
    assert(rec.observed.physical_ms > 0u);
    assert(qihse_federation_node_capability_lookup_admissible(g_store, g_op, &id.node_id, &rec));

    /* An out-of-range tuple is refused on write: no record, and the earlier
     * record is left untouched. */
    qihse_federation_capability_values_t bad = v;
    bad.isa_tier = (uint8_t)(QIHSE_FEDERATION_CAP_ISA_TIER_MAX + 1u);
    assert(!qihse_federation_node_capability_record_local(g_store, g_op, &id.node_id, &bad));
    bad = v;
    bad.npu = 2u;
    assert(!qihse_federation_node_capability_record_local(g_store, g_op, &id.node_id, &bad));
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    assert(rec.values.isa_tier == 3u && rec.values.npu == 1u);

    /* RESTART. */
    store_restart();
    qihse_federation_node_capability_t after;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &after));
    assert(after.source == QIHSE_CAP_SOURCE_LOCAL_PROBE);
    assert(after.trust == QIHSE_TRUST_APPROVED);
    assert(after.values.isa_tier == rec.values.isa_tier);
    assert(after.values.npu == rec.values.npu);
    assert(after.values.gpu == rec.values.gpu);
    assert(after.values.free_ram_mb == rec.values.free_ram_mb);
    assert(after.values.load_pct == rec.values.load_pct);
    assert(after.observed.physical_ms == rec.observed.physical_ms);
    assert(qihse_federation_node_capability_lookup_admissible(g_store, g_op, &id.node_id, &after));

    /* Revocation invalidates admissibility but keeps the record for audit:
     * the stored trust snapshot is attribution, not authorization. */
    assert(qihse_federation_node_revoke(g_store, g_op, &id.node_id));
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &after));
    assert(after.trust == QIHSE_TRUST_APPROVED);   /* snapshot at admission */
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, g_op, &id.node_id, &after));
    /* A revoked node cannot re-write its own profile either. */
    assert(!qihse_federation_node_capability_record_local(g_store, g_op, &id.node_id, &v));

    printf("PASS local probe: durable across restart, revocation drops admissibility\n");
}

static void test_unenrolled_local_probe(const char* key_dir) {
    /* A node that is not enrolled at all still gets a durable record — the
     * data must survive a restart — but it is never admissible, and its trust
     * snapshot is UNKNOWN. */
    qihse_federation_node_identity_t id;
    memset(&id, 0, sizeof(id));
    assert(qihse_uuid_from_seed("w24-unenrolled-node", strlen("w24-unenrolled-node"),
                                &id.node_id));
    (void)key_dir;

    qihse_federation_capability_values_t v;
    memset(&v, 0, sizeof(v));
    v.isa_tier = 1u;
    v.free_ram_mb = 128u;
    assert(qihse_federation_node_capability_record_local(g_store, g_op, &id.node_id, &v));

    qihse_federation_node_capability_t rec;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    assert(rec.trust == QIHSE_TRUST_UNKNOWN);
    assert(rec.source == QIHSE_CAP_SOURCE_LOCAL_PROBE);
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, g_op, &id.node_id, &rec));

    /* An all-zero node id has no record and cannot be written. */
    qihse_uuid_t nil;
    memset(&nil, 0, sizeof(nil));
    assert(!qihse_federation_node_capability_record_local(g_store, g_op, &nil, &v));
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &nil, &rec));

    printf("PASS unenrolled local probe: durable but not admissible\n");
}

/* ── 2 + 3: the authenticated producer ─────────────────────────────────── */

static void test_statement_producer(const char* key_dir) {
    qihse_federation_node_identity_t peer;
    enroll_node(&peer, "w24-peer-node", key_dir, true);

    qihse_uuid_t cluster, boot, session;
    assert(qihse_uuid_from_seed("w24-cluster", strlen("w24-cluster"), &cluster));
    assert(qihse_uuid_from_seed("w24-peer-boot", strlen("w24-peer-boot"), &boot));
    assert(qihse_uuid_generate(&session));

    qihse_federation_capability_values_t caps;
    memset(&caps, 0, sizeof(caps));
    caps.isa_tier = 4u;
    caps.npu = 0u;
    caps.gpu = 1u;
    caps.free_ram_mb = 65536u;
    caps.load_pct = 42u;

    qihse_federation_gossip_t stmt;
    fill_statement(&stmt, &peer, &cluster, &boot, &session, 1u, &caps,
                   QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY);
    void* pkey = qihse_federation_node_key_load(peer.key_handle);
    assert(pkey);
    assert(qihse_federation_gossip_sign(pkey, &stmt));
    qihse_federation_node_key_free(pkey);

    /* The capability profile is inside the signed region: editing it breaks
     * the signature, so a claim is attributable to the signing node. */
    qihse_federation_gossip_t tampered = stmt;
    tampered.caps.free_ram_mb = 0u;
    assert(!qihse_federation_gossip_verify(peer.public_key, peer.public_key_len, &tampered));
    tampered = stmt;
    tampered.caps.isa_tier = 0u;
    assert(!qihse_federation_gossip_verify(peer.public_key, peer.public_key_len, &tampered));

    /* Inject it through the bus: the same dispatch production uses. */
    bus_fixture_t f;
    bus_fixture_up(&f, NULL);
    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t plen = statement_payload(&stmt, payload, sizeof(payload));
    uint8_t dgram[QIHSE_CLUSTER_BUS_MAX_PAYLOAD + 64u];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 1u, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));
    assert(f.membership_calls == 1u);
    assert(f.last_caps.isa_tier == 4u && f.last_caps.gpu == 1u);
    assert(f.last_caps.free_ram_mb == 65536u && f.last_caps.load_pct == 42u);

    /* Replay must not reach the consumer again. */
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));
    assert(f.membership_calls == 1u);
    bus_fixture_down(&f);

    /* The durable record exists and is attributed to the signed session. */
    qihse_federation_node_capability_t rec;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &peer.node_id, &rec));
    assert(rec.source == QIHSE_CAP_SOURCE_SIGNED_STATEMENT);
    assert(rec.trust == QIHSE_TRUST_APPROVED);
    assert(qihse_uuid_equal(&rec.boot_id, &boot));
    assert(qihse_uuid_equal(&rec.session_id, &session));
    assert(rec.sequence == 1u);
    assert(rec.flags == 0u);
    assert(rec.values.isa_tier == 4u && rec.values.npu == 0u && rec.values.gpu == 1u);
    assert(rec.values.free_ram_mb == 65536u && rec.values.load_pct == 42u);
    assert(qihse_federation_node_capability_lookup_admissible(g_store, g_op, &peer.node_id, &rec));

    /* And it survives a restart. */
    store_restart();
    qihse_federation_node_capability_t after;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &peer.node_id, &after));
    assert(after.source == QIHSE_CAP_SOURCE_SIGNED_STATEMENT);
    assert(after.values.isa_tier == 4u && after.values.gpu == 1u);
    assert(after.values.free_ram_mb == 65536u && after.values.load_pct == 42u);
    assert(qihse_uuid_equal(&after.session_id, &session));
    assert(qihse_federation_node_capability_lookup_admissible(g_store, g_op, &peer.node_id, &after));

    printf("PASS statement producer: signed profile persisted, replay refused, restart-safe\n");
}

static void test_untrusted_statement_producer(const char* key_dir) {
    qihse_uuid_t cluster, boot, session;
    assert(qihse_uuid_from_seed("w24-cluster", strlen("w24-cluster"), &cluster));
    assert(qihse_uuid_from_seed("w24-pending-boot", strlen("w24-pending-boot"), &boot));
    assert(qihse_uuid_generate(&session));

    /* Enrolled but NOT approved: PENDING. */
    qihse_federation_node_identity_t pending;
    enroll_node(&pending, "w24-pending-node", key_dir, false);
    void* pkey = qihse_federation_node_key_load(pending.key_handle);
    assert(pkey);

    qihse_federation_capability_values_t caps;
    memset(&caps, 0, sizeof(caps));
    caps.isa_tier = 4u;
    caps.free_ram_mb = 999999u;

    qihse_federation_gossip_t stmt;
    fill_statement(&stmt, &pending, &cluster, &boot, &session, 1u, &caps,
                   QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY);
    assert(qihse_federation_gossip_sign(pkey, &stmt));

    bus_fixture_t f;
    bus_fixture_up(&f, NULL);
    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t plen = statement_payload(&stmt, payload, sizeof(payload));
    uint8_t dgram[QIHSE_CLUSTER_BUS_MAX_PAYLOAD + 64u];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 1u, payload, plen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));
    assert(f.membership_calls == 0u);

    /* No durable record for a node that is not APPROVED. */
    qihse_federation_node_capability_t rec;
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &pending.node_id, &rec));

    /* Approve, accept, then revoke: the record stays, admissibility does not,
     * and a new claim from the revoked node is refused. */
    assert(qihse_federation_node_enroll_approve(g_store, g_op, &pending.node_id, 2));
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));
    assert(f.membership_calls == 1u);
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &pending.node_id, &rec));
    assert(qihse_federation_node_capability_lookup_admissible(g_store, g_op,
                                                             &pending.node_id, &rec));

    assert(qihse_federation_node_revoke(g_store, g_op, &pending.node_id));
    qihse_federation_capability_values_t fresh = caps;
    fresh.free_ram_mb = 7u;
    qihse_federation_gossip_t stmt2;
    fill_statement(&stmt2, &pending, &cluster, &boot, &session, 2u, &fresh,
                   QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY);
    assert(qihse_federation_gossip_sign(pkey, &stmt2));
    size_t plen2 = statement_payload(&stmt2, payload, sizeof(payload));
    size_t dlen2 = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                  1u, payload, plen2);
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen2, "127.0.0.1", 17201));
    assert(f.membership_calls == 1u);   /* unchanged */

    qihse_federation_node_capability_t after;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &pending.node_id, &after));
    assert(after.values.free_ram_mb == 999999u);   /* not refreshed by a revoked node */
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, g_op,
                                                              &pending.node_id, &after));

    /* An unknown (unenrolled) sender is refused and records nothing. */
    qihse_federation_node_identity_t ghost;
    memset(&ghost, 0, sizeof(ghost));
    assert(qihse_uuid_from_seed("w24-ghost-node", strlen("w24-ghost-node"), &ghost.node_id));
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_65, &ghost));
    void* gkey = qihse_federation_node_key_load(ghost.key_handle);
    assert(gkey);
    qihse_uuid_t ghost_boot;
    assert(qihse_uuid_from_seed("w24-ghost-boot", strlen("w24-ghost-boot"), &ghost_boot));
    qihse_federation_gossip_t gstmt;
    fill_statement(&gstmt, &ghost, &cluster, &ghost_boot, &session, 1u, &caps,
                   QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY);
    assert(qihse_federation_gossip_sign(gkey, &gstmt));
    size_t gplen = statement_payload(&gstmt, payload, sizeof(payload));
    size_t gdlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                  1u, payload, gplen);
    assert(qihse_cluster_bus_inject(f.bus, dgram, gdlen, "127.0.0.1", 17201));
    assert(f.membership_calls == 1u);
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &ghost.node_id, &rec));

    qihse_federation_node_key_free(gkey);
    qihse_federation_node_key_free(pkey);
    bus_fixture_down(&f);
    printf("PASS untrusted/revoked/unknown senders: no callback, no record, no refresh\n");
}

/* ── 3: an unauthenticated NODE_CAP frame is never durable ─────────────── */

static size_t g_cap_key_count;

static bool count_cap_key_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    (void)user_data;
    if (strncmp(key, QIHSE_FEDERATION_NODE_CAP_PREFIX,
                strlen(QIHSE_FEDERATION_NODE_CAP_PREFIX)) == 0) {
        g_cap_key_count++;
    }
    return true;
}

static size_t durable_record_count(void) {
    g_cap_key_count = 0;
    qihse_kv_foreach_user(g_store, g_op, count_cap_key_cb, NULL);
    return g_cap_key_count;
}

static void test_node_cap_frame_is_hint_only(const char* key_dir) {
    (void)key_dir;
    bus_fixture_t f;
    bus_fixture_up(&f, NULL);

    /* The live table is empty before the frame. */
    uint8_t isa = 0, npu = 0, gpu = 0;
    uint32_t ram = 0;
    uint16_t load = 0;
    assert(!qihse_cluster_bus_node_caps(f.bus, 1u, &isa, &npu, &gpu, &ram, &load));

    /* Build a NODE_CAP frame naming topology node 1, with a profile no real
     * node would report. */
    qihse_cluster_node_t target;
    assert(qihse_cluster_topology_get_node(f.topology, 1u, &target));
    uint8_t capbuf[QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE];
    uint8_t* p = capbuf;
    memcpy(p, target.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u); p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    uint8_t t_isa = 4u, t_npu = 1u, t_gpu = 1u;
    uint32_t t_ram = 777777u;
    uint16_t t_load = 3u;
    memcpy(p, &t_isa, 1u); p += 1u;
    memcpy(p, &t_npu, 1u); p += 1u;
    memcpy(p, &t_gpu, 1u); p += 1u;
    memcpy(p, &t_ram, 4u); p += 4u;
    memcpy(p, &t_load, 2u);

    size_t records_before = durable_record_count();
    /* The earlier tests wrote records, so this counter is not trivially zero
     * (a vacuous 0 == 0 would not prove anything). */
    assert(records_before >= 4u);
    uint8_t dgram[512];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_NODE_CAP,
                                 1u, capbuf, sizeof(capbuf));
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));

    /* The live hint table is updated (existing behaviour preserved)... */
    assert(qihse_cluster_bus_node_caps(f.bus, 1u, &isa, &npu, &gpu, &ram, &load));
    assert(isa == 4u && npu == 1u && gpu == 1u && ram == 777777u && load == 3u);

    /* ...but the frame is unattributable, so it wrote NO durable record:
     * the record table is exactly as it was before the frame. */
    assert(durable_record_count() == records_before);

    /* Repeat frames cannot accumulate records either. */
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));
    assert(durable_record_count() == records_before);

    bus_fixture_down(&f);
    printf("PASS NODE_CAP frame: live hint table updated, no durable record written\n");
}

/* ── 4: malformed and truncated records ────────────────────────────────── */

/* Mirror of the capability record layout (cap_encode in
 * qihse_federation.c): version, node, boot, session, sequence, isa, npu, gpu,
 * free_ram, load, trust, source, flags, observed_ms, observed_logical. */
static void cap_blob(char* out, size_t cap, const char* version, const char* node,
                     const char* boot, const char* session, const char* seq,
                     const char* isa, const char* npu, const char* gpu,
                     const char* ram, const char* load, const char* trust,
                     const char* source, const char* flags, const char* ms,
                     const char* logical) {
    int n = snprintf(out, cap, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
                     version, node, boot, session, seq, isa, npu, gpu, ram, load,
                     trust, source, flags, ms, logical);
    assert(n > 0 && (size_t)n < cap);
}

static void cap_key(const qihse_uuid_t* id, char* out, size_t cap) {
    char str[QIHSE_UUID_STR_LEN + 1u];
    assert(qihse_uuid_format(id, str));
    int n = snprintf(out, cap, QIHSE_FEDERATION_NODE_CAP_PREFIX "%s", str);
    assert(n > 0 && (size_t)n < cap);
}

static void test_malformed_records_refused(const char* key_dir) {
    qihse_federation_node_identity_t id;
    enroll_node(&id, "w24-malformed-node", key_dir, true);

    char node_hex[33];
    const uint8_t* nb = (const uint8_t*)&id.node_id;
    for (int i = 0; i < 16; i++) snprintf(node_hex + i * 2, 3, "%02x", nb[i]);
    node_hex[32] = '\0';
    const char* nil_hex = "00000000000000000000000000000000";

    char key[128];
    cap_key(&id.node_id, key, sizeof(key));

    qihse_uuid_t other;
    assert(qihse_uuid_from_seed("w24-other-node", strlen("w24-other-node"), &other));
    char other_hex[33];
    const uint8_t* ob = (const uint8_t*)&other;
    for (int i = 0; i < 16; i++) snprintf(other_hex + i * 2, 3, "%02x", ob[i]);
    other_hex[32] = '\0';

    qihse_federation_node_capability_t rec;
    char blob[512];

    /* Control: the well-formed shape decodes.  Without this, every refusal
     * below could be a vacuous failure. */
    cap_blob(blob, sizeof(blob), "1", node_hex, node_hex, node_hex, "9", "2", "1", "0",
             "1024", "50", "2", "1", "0", "1234", "0");
    assert(qihse_kv_set_user(g_store, key, blob, 0, 0, g_op));
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    assert(rec.values.isa_tier == 2u && rec.values.npu == 1u && rec.values.free_ram_mb == 1024u);
    assert(rec.trust == QIHSE_TRUST_APPROVED);
    assert(rec.source == QIHSE_CAP_SOURCE_LOCAL_PROBE);

    struct {
        const char* what;
        const char* version; const char* node; const char* boot; const char* session;
        const char* seq; const char* isa; const char* npu; const char* gpu;
        const char* ram; const char* load; const char* trust; const char* source;
        const char* flags; const char* ms; const char* logical;
    } bad_cases[] = {
        /* version 0 / 99 / non-numeric */
        { "unknown version", "99", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        { "version 0", "0", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        { "non-numeric version", "1x", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        /* key/body disagreement */
        { "body node != key", "1", other_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        /* out-of-range values */
        { "isa out of range", "1", node_hex, node_hex, node_hex, "1", "99", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        { "npu out of range", "1", node_hex, node_hex, node_hex, "1", "2", "2", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        { "gpu out of range", "1", node_hex, node_hex, node_hex, "1", "2", "0", "2",
          "1024", "50", "2", "1", "0", "1", "0" },
        { "trust out of range", "1", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "99", "1", "0", "1", "0" },
        { "source out of range", "1", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "99", "0", "1", "0" },
        { "source none", "1", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "0", "0", "1", "0" },
        /* signed-statement attribution without a session/boot */
        { "signed without session", "1", node_hex, node_hex, nil_hex, "1", "2", "1", "0",
          "1024", "50", "2", "2", "0", "1", "0" },
        { "signed without boot", "1", node_hex, nil_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "2", "0", "1", "0" },
        /* trailing junk / partial numbers */
        { "trailing junk", "1", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
        { "numeric with junk", "1", node_hex, node_hex, node_hex, "1", "2", "1", "0",
          "1024", "50", "2", "1", "0", "1x", "0" },
        { "empty isa", "1", node_hex, node_hex, node_hex, "1", "", "1", "0",
          "1024", "50", "2", "1", "0", "1", "0" },
    };
    for (size_t i = 0; i < sizeof(bad_cases) / sizeof(bad_cases[0]); i++) {
        cap_blob(blob, sizeof(blob), bad_cases[i].version, bad_cases[i].node,
                 bad_cases[i].boot, bad_cases[i].session, bad_cases[i].seq,
                 bad_cases[i].isa, bad_cases[i].npu, bad_cases[i].gpu,
                 bad_cases[i].ram, bad_cases[i].load, bad_cases[i].trust,
                 bad_cases[i].source, bad_cases[i].flags, bad_cases[i].ms,
                 bad_cases[i].logical);
        if (strcmp(bad_cases[i].what, "trailing junk") == 0) {
            strncat(blob, "\t99", sizeof(blob) - strlen(blob) - 1u);
        }
        assert(qihse_kv_set_user(g_store, key, blob, 0, 0, g_op));
        bool decoded = qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec);
        if (decoded) {
            fprintf(stderr, "FAIL malformed record accepted: %s\n", bad_cases[i].what);
        }
        assert(!decoded);
    }

    /* Truncated records: every prefix of the valid blob must be refused. */
    cap_blob(blob, sizeof(blob), "1", node_hex, node_hex, node_hex, "9", "2", "1", "0",
             "1024", "50", "2", "1", "0", "1234", "0");
    size_t full = strlen(blob);
    for (size_t cut = 0; cut < full; cut++) {
        char truncated[512];
        memcpy(truncated, blob, cut);
        truncated[cut] = '\0';
        assert(qihse_kv_set_user(g_store, key, truncated, 0, 0, g_op));
        assert(!qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    }

    /* Empty and garbage records. */
    assert(qihse_kv_set_user(g_store, key, "", 0, 0, g_op));
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    assert(qihse_kv_set_user(g_store, key, "not a record at all", 0, 0, g_op));
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));

    /* A truncated statement frame never reaches the producer. */
    bus_fixture_t f;
    bus_fixture_up(&f, NULL);
    uint8_t tiny[16] = { 0 };
    uint8_t dgram[512];
    size_t dlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_FED_STATEMENT,
                                 1u, tiny, sizeof(tiny));
    assert(qihse_cluster_bus_inject(f.bus, dgram, dlen, "127.0.0.1", 17201));
    assert(f.membership_calls == 0u);

    /* A truncated NODE_CAP frame does not even reach the live table. */
    uint8_t short_cap[QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE - 1u];
    memset(short_cap, 0, sizeof(short_cap));
    size_t cdlen = build_datagram(dgram, sizeof(dgram), QIHSE_BUS_MSG_NODE_CAP,
                                  1u, short_cap, sizeof(short_cap));
    assert(qihse_cluster_bus_inject(f.bus, dgram, cdlen, "127.0.0.1", 17201));
    uint8_t isa = 0, npu = 0, gpu = 0;
    uint32_t ram = 0;
    uint16_t load = 0;
    assert(!qihse_cluster_bus_node_caps(f.bus, 1u, &isa, &npu, &gpu, &ram, &load));
    bus_fixture_down(&f);

    printf("PASS malformed records: %zu bad shapes + %zu truncations + frames refused\n",
           sizeof(bad_cases) / sizeof(bad_cases[0]), full);
}

/* ── 5: v2 statements keep working ─────────────────────────────────────── */

static void test_v2_statement_compat(const char* key_dir) {
    qihse_federation_node_identity_t id;
    enroll_node(&id, "w24-v2-node", key_dir, true);

    qihse_uuid_t cluster, boot, session;
    assert(qihse_uuid_from_seed("w24-cluster", strlen("w24-cluster"), &cluster));
    assert(qihse_uuid_from_seed("w24-v2-boot", strlen("w24-v2-boot"), &boot));
    assert(qihse_uuid_generate(&session));

    /* The default version is v2: no capability profile on the wire. */
    qihse_federation_gossip_t v2;
    fill_statement(&v2, &id, &cluster, &boot, &session, 1u, NULL,
                   QIHSE_FEDERATION_GOSSIP_VERSION);
    assert(v2.version == 2u);
    void* pkey = qihse_federation_node_key_load(id.key_handle);
    assert(pkey);
    assert(qihse_federation_gossip_sign(pkey, &v2));

    size_t v2_wire = qihse_federation_gossip_wire_size_v(2u, v2.sig_alg);
    size_t v3_wire = qihse_federation_gossip_wire_size_v(3u, v2.sig_alg);
    assert(v2_wire != 0u && v3_wire == v2_wire + 12u);   /* the v3 cap trailer */
    assert(qihse_federation_gossip_wire_size(v2.sig_alg) == v2_wire);

    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t plen = statement_payload(&v2, payload, sizeof(payload));
    assert(plen == v2_wire);

    /* An old frame round-trips and still verifies against its own v2 bytes. */
    qihse_federation_gossip_t decoded;
    assert(qihse_federation_gossip_deserialize(payload, plen, &decoded));
    assert(decoded.version == 2u);
    assert(decoded.caps.isa_tier == 0u && decoded.caps.free_ram_mb == 0u);
    assert(qihse_federation_gossip_verify(id.public_key, id.public_key_len, &decoded));

    /* Re-labelling it as v3 is refused (the length would not match the v3
     * layout), so a v2 frame cannot be reinterpreted as carrying a profile. */
    uint8_t relabel[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    memcpy(relabel, payload, plen);
    uint16_t v3 = 3u;
    memcpy(relabel + 4, &v3, 2);
    assert(!qihse_federation_gossip_deserialize(relabel, plen, &decoded));

    /* A v2 statement is accepted and writes NO capability record: there is no
     * profile in it, and inventing one would be worse than an absent record. */
    qihse_federation_node_capability_t rec;
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));
    assert(qihse_federation_gossip_accept(g_store, g_op, &v2) == QIHSE_GOSSIP_ACCEPTED);
    assert(!qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));

    /* The stored record reads back as v2 and re-verifies (heartbeat tier
     * depends on exactly this re-verification). */
    qihse_federation_gossip_t stored;
    assert(qihse_federation_gossip_statement_read(g_store, g_op, &id.node_id, &boot, &stored));
    assert(stored.version == 2u);
    assert(qihse_federation_gossip_verify(id.public_key, id.public_key_len, &stored));

    /* A v3 statement with an out-of-range capability is malformed before any
     * crypto: a statement naming an impossible profile never reaches the
     * verifier. */
    qihse_federation_gossip_t v3stmt;
    fill_statement(&v3stmt, &id, &cluster, &boot, &session, 2u, NULL,
                   QIHSE_FEDERATION_GOSSIP_VERSION_CAPABILITY);
    v3stmt.caps.isa_tier = (uint8_t)(QIHSE_FEDERATION_CAP_ISA_TIER_MAX + 1u);
    assert(qihse_federation_gossip_sign(pkey, &v3stmt));
    size_t v3len = statement_payload(&v3stmt, payload, sizeof(payload));
    assert(!qihse_federation_gossip_deserialize(payload, v3len, &decoded));

    qihse_federation_node_key_free(pkey);
    printf("PASS v2 compat: v2 frames verify, v2 accepted without a record, v3 range-checked\n");
}

/* ── 2: the bus local-probe producer ───────────────────────────────────── */

static void test_bus_local_probe_producer(const char* key_dir) {
    qihse_federation_node_identity_t local;
    enroll_node(&local, "w24-bus-local", key_dir, true);

    bus_fixture_t f;
    bus_fixture_up(&f, &local.node_id);
    assert(qihse_cluster_bus_start(f.bus));

    /* start() writes the self-record before the first heartbeat. */
    qihse_federation_node_capability_t rec;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &local.node_id, &rec));
    assert(rec.source == QIHSE_CAP_SOURCE_LOCAL_PROBE);
    assert(rec.trust == QIHSE_TRUST_APPROVED);
    assert(rec.values.isa_tier <= QIHSE_FEDERATION_CAP_ISA_TIER_MAX);
    assert(rec.observed.physical_ms > 0u);
    assert(qihse_federation_node_capability_lookup_admissible(g_store, g_op,
                                                             &local.node_id, &rec));

    qihse_cluster_bus_stop(f.bus);
    bus_fixture_down(&f);
    printf("PASS bus local probe producer: self-record written at start\n");
}

/* ── AGENTS.md invariant 3: no disclosure to a low-clearance principal ──── */

static void test_classified_record_not_disclosed(const char* key_dir) {
    /* Capability records are normally unclassified, but the accessor reads
     * through the classification-aware KV layer.  A record that carries a
     * classification must not be disclosed to a principal that cannot see it,
     * and the denial must not leak any field. */
    qihse_federation_node_identity_t id;
    enroll_node(&id, "w24-classified-node", key_dir, true);

    char node_hex[33];
    const uint8_t* nb = (const uint8_t*)&id.node_id;
    for (int i = 0; i < 16; i++) snprintf(node_hex + i * 2, 3, "%02x", nb[i]);
    node_hex[32] = '\0';

    char key[128];
    cap_key(&id.node_id, key, sizeof(key));
    char blob[512];
    cap_blob(blob, sizeof(blob), "1", node_hex, node_hex, node_hex, "9", "2", "1", "0",
             "4096", "50", "2", "1", "0", "1234", "0");

    /* The operator can store and read it classified. */
    assert(qihse_kv_set_user(g_store, key, blob, 5, 0, g_op));
    qihse_federation_node_capability_t rec;
    assert(qihse_federation_node_capability_lookup(g_store, g_op, &id.node_id, &rec));

    /* A low-clearance guest gets a denial with no payload. */
    qihse_user_t* guest = qihse_auth_create_user(g_op, 77u, QIHSE_ROLE_GUEST, 0u, 0u,
                                                 "W24GuestPass1!", false);
    assert(guest);
    memset(&rec, 0, sizeof(rec));
    assert(!qihse_federation_node_capability_lookup(g_store, guest, &id.node_id, &rec));
    assert(!qihse_federation_node_capability_lookup_admissible(g_store, guest, &id.node_id, &rec));
    assert(rec.values.free_ram_mb == 0u);   /* nothing decoded into the out buffer */
    assert(rec.source == QIHSE_CAP_SOURCE_NONE);

    printf("PASS invariant 3: classified capability record denied to a guest\n");
}

int main(void) {
    char data_root[] = "build/node_cap_records_XXXXXX";
    assert(mkdtemp(data_root));
    char key_dir[256];
    snprintf(key_dir, sizeof(key_dir), "%s/keys", data_root);
    assert(mkdir(key_dir, 0700) == 0);
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    bool bootstrapped = qihse_auth_bootstrap_operator("NodeCapPass1!");
    if (!bootstrapped) {
        setenv("QIHSE_OPERATOR_PASSWORD", "NodeCapPass1!", 1);
        assert(qihse_auth_init());
    }
    g_op = qihse_auth_get_user(0);
    assert(g_op);
    g_store = qihse_kv_store_create();
    assert(g_store);

    test_local_probe_survives_restart(key_dir);
    test_unenrolled_local_probe(key_dir);
    test_statement_producer(key_dir);
    test_untrusted_statement_producer(key_dir);
    test_node_cap_frame_is_hint_only(key_dir);
    test_malformed_records_refused(key_dir);
    test_v2_statement_compat(key_dir);
    test_bus_local_probe_producer(key_dir);
    test_classified_record_not_disclosed(key_dir);

    qihse_kv_store_destroy(g_store);

    /* Self-clean the scratch directory: .gitignore lists per-test prefixes
     * and this test's prefix is not among them. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", data_root);
    assert(system(cmd) == 0);

    printf("node capability record tests passed\n");
    return 0;
}
