/*
 * test_brain_fed_journal.c — W3.4: brain observations and signed decisions on
 * the federation event journal, and the "no action without a journaled
 * pre-condition" gate.
 *
 *   A. observations      brain.observe events carry an HLC stamp, a hash-chain
 *                        link, the structured rule input and the same detail
 *                        JSON the local journal recorded
 *   B. signed decisions  brain.decision envelopes verify against the node key,
 *                        cite the observation they were derived from, and fail
 *                        verification when tampered with; the private key
 *                        never appears in a record
 *   C. pre-condition     the SAME topology and the same act config as (B), but
 *                        with the federation journal unavailable: the action is
 *                        refused and DECISION_REFUSED is journaled, while (B)
 *                        proves the action does happen when it can be journaled
 *   D. determinism       the triage output is byte-identical across worker
 *                        counts; only the scan_us telemetry field varies
 *
 * Everything binds to a synthetic topology with no network; journal dirs are
 * relative (build/) per the repository path policy.
 */
#include "qihse_auth.h"
#include "qihse_cluster_brain.h"
#include "qihse_cluster_slot.h"
#include "qihse_event_stream.h"
#include "qihse_federation.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BRAIN_OBS_MAGIC_LE 0x5148424Fu /* "QHBO" */
#define FED_MAX_EVENTS 128

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

static void sha384(const uint8_t* data, size_t len, uint8_t out[48]) {
    unsigned int olen = 48;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    assert(ctx);
    assert(EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) == 1);
    assert(EVP_DigestUpdate(ctx, data, len) == 1);
    assert(EVP_DigestFinal_ex(ctx, out, &olen) == 1);
    EVP_MD_CTX_free(ctx);
    assert(olen == 48u);
}

/* ── federation journal reader ──────────────────────────────────────────── */

typedef struct {
    char type[64];
    char resource[64];
    uint64_t offset;
    qihse_hlc_t hlc;
    uint8_t hash[48];
    uint8_t prev[48];
    uint8_t* payload;
    size_t payload_len;
} fed_event_t;

typedef struct {
    fed_event_t events[FED_MAX_EVENTS];
    size_t count;
    size_t total;
} fed_log_t;

static bool fed_collect(const qihse_federation_event_t* event, const uint8_t* payload,
                        size_t payload_len, void* user_data) {
    fed_log_t* log = (fed_log_t*)user_data;
    log->total++;
    if (log->count >= FED_MAX_EVENTS) return true;
    fed_event_t* e = &log->events[log->count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->type, sizeof(e->type), "%s", event->event_type);
    snprintf(e->resource, sizeof(e->resource), "%s", event->resource_id);
    e->offset = event->journal_offset;
    e->hlc = event->mutation.hlc;
    memcpy(e->hash, event->hash, 48u);
    memcpy(e->prev, event->previous_hash, 48u);
    if (payload && payload_len) {
        e->payload = malloc(payload_len);
        assert(e->payload);
        memcpy(e->payload, payload, payload_len);
        e->payload_len = payload_len;
    }
    return true;
}

static void fed_scan(const char* dir, fed_log_t* out) {
    memset(out, 0, sizeof(*out));
    qihse_federation_journal_t* journal =
        qihse_federation_journal_open(dir, QIHSE_ES_DURABILITY_NONE);
    assert(journal);
    assert(qihse_federation_journal_replay(journal, 0, fed_collect, out) == out->total);
    qihse_federation_journal_destroy(journal);
}

/* Observation payload header: magic(4) version(2) local(2) seq(8) scan_us(8)
 * workers(4) nodes(4) runs(4) detail_len(4) then the records and the detail. */
static bool obs_detail(const fed_event_t* e, uint64_t* out_seq, const uint8_t** out_detail,
                       size_t* out_detail_len) {
    if (!e->payload || e->payload_len < QIHSE_BRAIN_OBS_HEADER_BYTES) return false;
    uint32_t magic = 0;
    memcpy(&magic, e->payload, 4u);
    if (magic != BRAIN_OBS_MAGIC_LE) return false;
    uint32_t detail_len = 0;
    memcpy(out_seq, e->payload + 8u, 8u);
    memcpy(&detail_len, e->payload + 36u, 4u);
    if (detail_len == 0 || QIHSE_BRAIN_OBS_HEADER_BYTES + detail_len > e->payload_len) return false;
    *out_detail = e->payload + e->payload_len - detail_len;
    *out_detail_len = detail_len;
    return true;
}

/* Replace a JSON number's digits with a single "0", so two records can be
 * compared on everything except that field. */
static void zero_number_field(char* text, const char* key) {
    char* p = strstr(text, key);
    if (!p) return;
    p += strlen(key);
    char* digits = p;
    while (*p >= '0' && *p <= '9') p++;
    if (p == digits) return;
    digits[0] = '0';
    memmove(digits + 1, p, strlen(p) + 1u);
}

/* Copy a detail JSON with the run-dependent telemetry fields removed: scan_us
 * is a wall-clock measurement and workers is the chunk count of the run, and
 * neither is an input to a decision.  Everything else — the node list, the
 * health flags and the slot runs — must be byte-identical. */
static void normalize_detail(const uint8_t* detail, size_t len, char* out, size_t cap) {
    assert(len + 1u < cap);
    memcpy(out, detail, len);
    out[len] = '\0';
    zero_number_field(out, "\"scan_us\":");
    zero_number_field(out, "\"workers\":");
}

/* ── local (cluster.brain) journal reader ───────────────────────────────── */

/* Count records of `kind` whose text also contains `needle` (NULL = any). */
static int local_count(const char* dir, const char* kind, const char* needle) {
    qihse_event_stream_t* stream = qihse_event_stream_open(dir, QIHSE_ES_DURABILITY_NONE, true);
    if (!stream) return 0;
    char kind_tag[64];
    snprintf(kind_tag, sizeof(kind_tag), "\"kind\":\"%s\"", kind);
    uint64_t cursor = 0;
    qihse_es_record_header_t hdr;
    uint8_t* payload = NULL;
    size_t plen = 0;
    char text[8192];
    int found = 0;
    while (qihse_event_stream_iterate(stream, "cluster.brain", &cursor, &hdr, &payload, &plen)) {
        if (payload && plen < sizeof(text)) {
            memcpy(text, payload, plen);
            text[plen] = '\0';
            if (strstr(text, kind_tag) && (!needle || strstr(text, needle))) found++;
        }
        free(payload);
        payload = NULL;
    }
    qihse_event_stream_destroy(stream);
    return found;
}

/* ── synthetic cluster ──────────────────────────────────────────────────── */

typedef struct {
    qihse_resp_server_t* server;
    qihse_cluster_topology_t* topo;
    uint16_t local;
    uint16_t healthy_peer;
    uint16_t dead_peer;
} cluster_t;

static void add_node(qihse_cluster_topology_t* topo, const char* seed, const char* host,
                     uint16_t port, uint16_t bus_port, bool healthy, uint16_t* idx_out) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
    snprintf(node.host, sizeof(node.host), "%s", host);
    node.port = port;
    node.bus_port = bus_port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = healthy;
    uint16_t idx = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topo, &node, &idx));
    if (idx_out) *idx_out = idx;
}

/* Two healthy primaries, each owning half the slot space, plus an unhealthy
 * slotless node when `with_dead_peer` is set. */
static void cluster_create(cluster_t* c, bool with_dead_peer) {
    memset(c, 0, sizeof(*c));
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char local_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("brain-fed-local", strlen("brain-fed-local"), local_id);
    scfg.node_id = local_id;
    scfg.auth_required = false;
    scfg.port = 0; /* never started: the brain only needs the topology */
    c->server = qihse_resp_server_create(&scfg);
    assert(c->server);
    c->topo = qihse_resp_server_topology(c->server);
    assert(c->topo);
    c->local = qihse_cluster_topology_local_node(c->topo);
    assert(c->local != QIHSE_CLUSTER_NODE_NONE);
    add_node(c->topo, "brain-fed-peer", "192.0.2.20", 7101u, 17101u, true, &c->healthy_peer);
    assert(qihse_cluster_topology_assign_range(c->topo, 0u, 8191u, c->local));
    assert(qihse_cluster_topology_assign_range(c->topo, 8192u, 16383u, c->healthy_peer));
    if (with_dead_peer) {
        add_node(c->topo, "brain-fed-dead", "192.0.2.21", 7102u, 17102u, false, &c->dead_peer);
        assert(c->dead_peer != QIHSE_CLUSTER_NODE_NONE);
    }
}

static void cluster_destroy(cluster_t* c) {
    qihse_resp_server_destroy(c->server);
}

static void run_brain(cluster_t* c, const char* dir, uint32_t interval_s, bool act,
                      uint32_t prune_timeout_s, const char* node_key_handle,
                      const char* fed_dir, uint64_t run_ms) {
    qihse_brain_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server = c->server;
    cfg.journal_dir = dir;
    cfg.dsa_key_path = NULL;
    cfg.node_key_handle = node_key_handle;
    cfg.federation_journal_dir = fed_dir;
    cfg.interval_seconds = interval_s;
    cfg.act = act;
    cfg.prune_timeout_seconds = prune_timeout_s;
    assert(qihse_cluster_brain_start(&cfg));
    sleep_ms(run_ms);
    qihse_cluster_brain_stop();
}

static void snapshot_owners(qihse_cluster_topology_t* topo, uint16_t* owners) {
    assert(qihse_cluster_topology_slot_owner_snapshot(topo, owners,
                                                      QIHSE_CLUSTER_SLOT_COUNT) ==
           QIHSE_CLUSTER_SLOT_COUNT);
}

/* ── A: observations on the federation journal ──────────────────────────── */

static void test_observations(const char* dir) {
    cluster_t c;
    cluster_create(&c, false);
    run_brain(&c, dir, 1u, false, 0u, NULL, NULL, 1700u);

    fed_log_t log;
    fed_scan(dir, &log);
    assert(log.count >= 1);
    printf("A: %zu federation records, %zu observations\n", log.total, log.count);

    for (size_t i = 0; i < log.count; i++) {
        const fed_event_t* e = &log.events[i];
        assert(strcmp(e->type, QIHSE_BRAIN_FED_EVENT_OBSERVE) == 0);
        assert(strncmp(e->resource, QIHSE_BRAIN_FED_OBS_PREFIX,
                       strlen(QIHSE_BRAIN_FED_OBS_PREFIX)) == 0);
        /* HLC-stamped by the journal. */
        assert(e->hlc.physical_ms != 0 || e->hlc.logical != 0);
        /* Hash chain: each record links to the one before it. */
        if (i > 0) assert(memcmp(e->prev, log.events[i - 1u].hash, 48u) == 0);

        uint64_t seq = 0;
        const uint8_t* detail = NULL;
        size_t detail_len = 0;
        assert(obs_detail(e, &seq, &detail, &detail_len));
        assert(seq == i + 1u); /* one observation per cycle, in order */

        /* The detail JSON is exactly what the local journal recorded. */
        char prefix[160];
        size_t take = detail_len < sizeof(prefix) - 1u ? detail_len : sizeof(prefix) - 1u;
        memcpy(prefix, detail, take);
        prefix[take] = '\0';
        assert(local_count(dir, "OBSERVE", prefix) >= 1);
        /* ... and it describes the topology the brain read. */
        assert(strstr(prefix, "\"slots\":\"0-8191\""));
    }
    printf("PASS observations are HLC-stamped, hash-chained and match the local record\n");
    cluster_destroy(&c);
}

/* ── B: signed decisions + reproducibility link ─────────────────────────── */

static void test_signed_decisions(const char* dir,
                                 const qihse_federation_node_identity_t* identity) {
    cluster_t c;
    cluster_create(&c, true);
    uint16_t owners_before[QIHSE_CLUSTER_SLOT_COUNT];
    snapshot_owners(c.topo, owners_before);
    run_brain(&c, dir, 1u, true, 1u, identity->key_handle, NULL, 2600u);

    fed_log_t log;
    fed_scan(dir, &log);

    const fed_event_t* prune = NULL;
    const fed_event_t* quarantine = NULL;
    for (size_t i = 0; i < log.count; i++) {
        fed_event_t* e = &log.events[i];
        if (strcmp(e->type, QIHSE_BRAIN_FED_EVENT_DECISION) != 0) continue;
        if (strcmp(e->resource, QIHSE_BRAIN_FED_DECISION_PREFIX "prune") == 0) prune = e;
        if (strcmp(e->resource, QIHSE_BRAIN_FED_DECISION_PREFIX "quarantine") == 0)
            quarantine = e;
    }
    assert(prune);
    assert(quarantine);

    /* The action is legible, the envelope is signed, and it verifies against
     * the node's public key. */
    char action[64];
    qihse_brain_precondition_t pre;
    assert(qihse_cluster_brain_decision_inspect(prune->payload, prune->payload_len,
                                               action, sizeof(action), &pre));
    assert(strcmp(action, "prune") == 0);
    assert(pre.valid);
    assert(qihse_cluster_brain_decision_is_signed(prune->payload, prune->payload_len));
    assert(qihse_cluster_brain_decision_verify(identity->public_key, identity->public_key_len,
                                              prune->payload, prune->payload_len));
    assert(qihse_cluster_brain_decision_is_signed(quarantine->payload, quarantine->payload_len));
    assert(qihse_cluster_brain_decision_verify(identity->public_key, identity->public_key_len,
                                              quarantine->payload, quarantine->payload_len));
    printf("B: prune + quarantine decisions verified against the node key\n");

    /* Tamper-evidence: an edited action, an algorithm downgrade and a flipped
     * signature byte are all refused. */
    uint8_t* tampered = malloc(prune->payload_len);
    assert(tampered);
    memcpy(tampered, prune->payload, prune->payload_len);
    tampered[QIHSE_BRAIN_DECISION_HEADER_BYTES] ^= 0x01u; /* first action byte, inside the region */
    assert(!qihse_cluster_brain_decision_verify(identity->public_key, identity->public_key_len,
                                               tampered, prune->payload_len));
    memcpy(tampered, prune->payload, prune->payload_len);
    tampered[6] = 0u; /* signature algorithm -> ed25519: downgrade attempt */
    tampered[7] = 0u;
    assert(!qihse_cluster_brain_decision_verify(identity->public_key, identity->public_key_len,
                                               tampered, prune->payload_len));
    memcpy(tampered, prune->payload, prune->payload_len);
    tampered[prune->payload_len - 1u] ^= 0x01u; /* last signature byte */
    assert(!qihse_cluster_brain_decision_verify(identity->public_key, identity->public_key_len,
                                               tampered, prune->payload_len));
    free(tampered);
    printf("PASS edited action, algorithm downgrade and flipped signature all fail verification\n");

    /* Reproducibility: the decision cites an observation that PRECEDES it on
     * the journal, with the same offset, chain hash and payload digest. */
    const fed_event_t* cited = NULL;
    for (size_t i = 0; i < log.count; i++) {
        if (strcmp(log.events[i].type, QIHSE_BRAIN_FED_EVENT_OBSERVE) != 0) continue;
        uint64_t seq = 0;
        const uint8_t* detail = NULL;
        size_t detail_len = 0;
        if (!obs_detail(&log.events[i], &seq, &detail, &detail_len)) continue;
        if (seq == pre.observation_seq) cited = &log.events[i];
    }
    assert(cited);
    assert(cited->offset < prune->offset); /* the input precedes the decision */
    assert(pre.journal_offset == cited->offset);
    assert(memcmp(pre.observation_hash, cited->hash, 48u) == 0);
    uint8_t digest[48];
    sha384(cited->payload, cited->payload_len, digest);
    assert(memcmp(pre.payload_digest, digest, 48u) == 0);
    /* The cited pre-condition is the journal's own stamp, not a private one. */
    assert(pre.hlc.physical_ms == cited->hlc.physical_ms);
    assert(pre.hlc.logical == cited->hlc.logical);
    printf("PASS decision cites the recorded observation (seq, offset, hash, digest, HLC)\n");

    /* Attribution: the key handle is carried; the private key never is. */
    bool handle_present = false;
    for (size_t i = 0; i < log.count; i++)
        if (log.events[i].payload && log.events[i].payload_len &&
            memmem(log.events[i].payload, log.events[i].payload_len,
                   identity->key_handle, strlen(identity->key_handle)))
            handle_present = true;
    assert(handle_present);

    /* The private key file's PEM body must not appear anywhere on either
     * journal. */
    FILE* f = fopen(identity->key_handle, "rb");
    assert(f);
    char pem[8192];
    size_t pem_len = fread(pem, 1u, sizeof(pem) - 1u, f);
    fclose(f);
    pem[pem_len] = '\0';
    char* body = pem;
    while (*body && *body != '\n') body++; /* skip "-----BEGIN ...-----" */
    if (*body) body++;
    size_t body_len = strcspn(body, "\r\n");
    assert(body_len >= 64u);
    char probe[65];
    memcpy(probe, body, 64u);
    probe[64] = '\0';
    for (size_t i = 0; i < log.count; i++) {
        if (!log.events[i].payload || !log.events[i].payload_len) continue;
        assert(!memmem(log.events[i].payload, log.events[i].payload_len, probe, 64u));
    }
    assert(local_count(dir, "PRUNE", NULL) == 0 || local_count(dir, "PRUNE", probe) == 0);
    printf("PASS key handle carried, private key material absent from every record\n");

    /* The action really happened: the prune removed the dead node. */
    assert(qihse_cluster_topology_nodes(c.topo, NULL, 0) == 2u);
    cluster_destroy(&c);
}

/* ── C: no action without a journaled pre-condition ─────────────────────── */

static void test_refused_without_precondition(const char* dir, const char* broken_fed_dir) {
    /* A path under a regular file: the federation journal cannot be opened. */
    FILE* f = fopen(broken_fed_dir, "wb");
    assert(f);
    fputs("not a directory\n", f);
    fclose(f);
    char journal_path[700];
    snprintf(journal_path, sizeof(journal_path), "%.600s/federation", broken_fed_dir);

    cluster_t c;
    cluster_create(&c, true);
    size_t nodes_before = qihse_cluster_topology_nodes(c.topo, NULL, 0);
    uint16_t owners_before[QIHSE_CLUSTER_SLOT_COUNT];
    snapshot_owners(c.topo, owners_before);

    /* Same act configuration as (B), where the prune DID happen. */
    run_brain(&c, dir, 1u, true, 1u, NULL, journal_path, 2600u);

    size_t nodes_after = qihse_cluster_topology_nodes(c.topo, NULL, 0);
    uint16_t owners_after[QIHSE_CLUSTER_SLOT_COUNT];
    snapshot_owners(c.topo, owners_after);
    assert(nodes_after == nodes_before);
    assert(memcmp(owners_before, owners_after, sizeof(owners_before)) == 0);
    assert(access(journal_path, F_OK) != 0); /* never created */

    /* The refusal is journaled, names the action, and no PRUNE was taken. */
    assert(local_count(dir, "BRAIN_DEGRADED", "federation-journal-unavailable") == 1);
    assert(local_count(dir, "DECISION_REFUSED", "\"action\":\"prune\"") >= 1);
    assert(local_count(dir, "PRUNE", NULL) == 0);
    printf("PASS no journal -> prune refused, DECISION_REFUSED journaled, topology unchanged\n");

    /* The gate itself is not a formality: NULL, a zeroed struct and a struct
     * that claims `valid` without a record behind it are all refused. */
    assert(!qihse_cluster_brain_precondition_ok(NULL));
    qihse_brain_precondition_t empty;
    memset(&empty, 0, sizeof(empty));
    assert(!qihse_cluster_brain_precondition_ok(&empty));
    empty.valid = true;
    assert(!qihse_cluster_brain_precondition_ok(&empty));
    empty.observation_seq = 1;
    empty.hlc.physical_ms = 1;
    assert(!qihse_cluster_brain_precondition_ok(&empty)); /* no chain hash/digest */
    memset(empty.observation_hash, 0xAB, sizeof(empty.observation_hash));
    memset(empty.payload_digest, 0xCD, sizeof(empty.payload_digest));
    assert(qihse_cluster_brain_precondition_ok(&empty)); /* a complete citation */
    printf("PASS pre-condition gate refuses an absent or incomplete citation\n");
    cluster_destroy(&c);
}

/* ── D: triage output is unchanged across worker counts ─────────────────── */

static void first_observation_detail(const char* dir, char* out, size_t cap) {
    fed_log_t log;
    fed_scan(dir, &log);
    assert(log.count >= 1);
    for (size_t i = 0; i < log.count; i++) {
        uint64_t seq = 0;
        const uint8_t* detail = NULL;
        size_t detail_len = 0;
        if (strcmp(log.events[i].type, QIHSE_BRAIN_FED_EVENT_OBSERVE) != 0) continue;
        assert(obs_detail(&log.events[i], &seq, &detail, &detail_len));
        normalize_detail(detail, detail_len, out, cap);
        return;
    }
    assert(0 && "no observation recorded");
}

static void test_determinism(const char* dir_one, const char* dir_eight) {
    cluster_t c1, c8;
    cluster_create(&c1, true);
    cluster_create(&c8, true);
    assert(setenv("QIHSE_BRAIN_WORKERS", "1", 1) == 0);
    run_brain(&c1, dir_one, 1u, false, 0u, NULL, NULL, 1700u);
    assert(setenv("QIHSE_BRAIN_WORKERS", "8", 1) == 0);
    run_brain(&c8, dir_eight, 1u, false, 0u, NULL, NULL, 1700u);
    unsetenv("QIHSE_BRAIN_WORKERS");

    char one[2048], eight[2048];
    first_observation_detail(dir_one, one, sizeof(one));
    first_observation_detail(dir_eight, eight, sizeof(eight));
    if (strcmp(one, eight) != 0) {
        fprintf(stderr, "1 worker : %s\n8 workers: %s\n", one, eight);
        assert(0 && "triage output differs across worker counts");
    }
    printf("PASS triage output byte-identical at 1 and 8 workers (scan_us normalised)\n");
    cluster_destroy(&c1);
    cluster_destroy(&c8);
}

int main(void) {
    char root[] = "build/brain_fed_XXXXXX";
    assert(mkdtemp(root));
    char dir_a[600], dir_b[600], dir_c[600], dir_d1[600], dir_d8[600], key_dir[600];
    char broken[600];
    snprintf(dir_a, sizeof(dir_a), "%s/obs", root);
    snprintf(dir_b, sizeof(dir_b), "%s/decisions", root);
    snprintf(dir_c, sizeof(dir_c), "%s/refused", root);
    snprintf(dir_d1, sizeof(dir_d1), "%s/det_one", root);
    snprintf(dir_d8, sizeof(dir_d8), "%s/det_eight", root);
    snprintf(key_dir, sizeof(key_dir), "%s/keys", root);
    snprintf(broken, sizeof(broken), "%s/not_a_dir", root);
    assert(mkdir(key_dir, 0700) == 0);

    /* A node identity keypair: ML-DSA-87, private key on disk, public key in
     * the identity record — the same shape the federation trust plane uses. */
    qihse_federation_node_identity_t identity;
    memset(&identity, 0, sizeof(identity));
    assert(qihse_uuid_from_seed("brain-fed-test-node", strlen("brain-fed-test-node"),
                                &identity.node_id));
    snprintf(identity.hostname, sizeof(identity.hostname), "brain-fed-test");
    assert(qihse_federation_node_keygen_alg(key_dir, QIHSE_SIG_ML_DSA_87, &identity));

    test_observations(dir_a);
    test_signed_decisions(dir_b, &identity);
    test_refused_without_precondition(dir_c, broken);
    test_determinism(dir_d1, dir_d8);

    printf("cluster brain federation journal tests passed\n");
    return 0;
}
