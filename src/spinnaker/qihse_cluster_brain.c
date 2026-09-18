#include "qihse_cluster_brain.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_ops.h"
#include "qihse_cluster_slot.h"
#include "qihse_event_stream.h"
#include "qihse_federation.h"
#include "qihse_pqc_crypto.h"
#include "qihse_auth.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BRAIN_TOPIC "cluster.brain"
#define BRAIN_MAX_NODES 64u
#define BRAIN_MAX_HANDOFFS 16u

/* ---- Federation journal records (W3.4) -----------------------------------
 * Observations and decisions are published to the F2 federation event journal
 * (topic "federation") with HLC stamps and a hash-chain link, so a decision
 * can be traced back to the recorded observation it was derived from.  The
 * local journal above is unchanged: it stays the human-readable audit trail
 * and the only durable record when no federation journal is available.
 *
 * Locking: the federation journal handle and its watch are touched ONLY by the
 * brain thread — appends in brain_observe()/brain_decision_record(), reads in
 * brain_consume_observation() — so no lock of our own is needed (the local
 * journal keeps its lock because it predates this work).  Underneath, the
 * event stream serialises writers with flock(LOCK_EX) per append and readers
 * with flock(LOCK_SH), so a second handle in this process or another process
 * cannot interleave a torn record with ours.  Two writers appending to the
 * same topic would still fork the hash chain (each holds its own tip), which
 * is why the brain defaults to its own journal directory rather than sharing
 * one with the resp engine's federation journal.
 */

#define BRAIN_FED_OBS_MAGIC      0x5148424Fu /* "QHBO" */
#define BRAIN_FED_DECISION_MAGIC 0x51484244u /* "QHBD" */
#define BRAIN_FED_FORMAT_VERSION 1u

/* Declared maximums for the variable-length decision fields.  The decoder
 * enforces them, so a malformed record cannot make a reader allocate or copy
 * an unbounded amount. */
#define BRAIN_FED_ACTION_MAX      47u
#define BRAIN_FED_KEY_HANDLE_MAX  159u
#define BRAIN_FED_EVIDENCE_MAX    1024u
#define BRAIN_FED_DETAIL_MAX      4096u
#define BRAIN_FED_OBS_MAX         262144u /* encoder bound for one observation */

/* Decision envelope layout (little-endian; fixed header, then the region the
 * signature covers).  The field-by-field layout lives in
 * include/qihse_cluster_brain.h next to QIHSE_BRAIN_DECISION_HEADER_BYTES, so
 * a consumer does not have to read this file to parse a record. */
#define BRAIN_FED_DECISION_HEADER QIHSE_BRAIN_DECISION_HEADER_BYTES
#define BRAIN_FED_DECISION_F_PRECONDITION 0x0001u
#define BRAIN_FED_MAX_SIGNATURE QIHSE_FEDERATION_SIG_MAX_BYTES

#define BRAIN_OBS_RUN_BYTES 8u
#define BRAIN_OBS_NODE_BYTES (6u * 2u + 4u + (QIHSE_CLUSTER_NODE_ID_LEN + 1u) + \
                              (QIHSE_CLUSTER_HOST_LEN + 1u))
#define BRAIN_OBS_F_HEALTHY 0x1u
#define BRAIN_OBS_F_LOCAL   0x2u

/* A re-home awaiting R4 evaluation: the range, where it went, and when the
 * rollback window closes. `moved < collected` means the transfer stopped
 * partway and ownership must go back. */
typedef struct {
    bool active;
    uint16_t first, last;
    uint16_t target;
    uint64_t deadline_ms;
    uint64_t moved, collected;
} brain_handoff_t;

/* Per-range cooldown so the brain cannot thrash a range it just touched. */
typedef struct {
    bool used;
    uint16_t first, last;
    uint64_t until_ms;
} brain_cooldown_t;

typedef struct brain_pool brain_pool_t; /* persistent scan pool (see below) */

/* One coalesced, owner-contiguous slot run.  Identical to what
 * qihse_cluster_topology_ranges() reports for the same snapshot, so a rule
 * can consume the run list from an observation instead of re-polling the
 * topology. */
typedef struct {
    uint16_t owner;
    uint16_t start;
    uint16_t end;
} brain_obs_run_t;

/* One node as recorded in an observation. */
typedef struct {
    uint16_t index;
    uint16_t role;
    uint16_t primary_index;
    uint16_t port;
    uint16_t bus_port;
    uint32_t flags; /* BRAIN_OBS_F_* */
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_CLUSTER_HOST_LEN + 1u];
} brain_obs_node_t;

/* The rule input: one observation, as recorded on the federation journal and
 * read back through the watch.  Deliberately large (64 nodes, up to one run
 * per slot), so it is only ever held on the heap — never on the brain
 * thread's stack (AGENTS.md, "bounded stack frames"). */
typedef struct {
    bool valid;        /* false = no usable observation this cycle */
    uint64_t seq;      /* per-brain observation sequence, starts at 1 */
    uint64_t scan_us;  /* triage time (telemetry, not a decision input) */
    uint32_t workers;
    uint16_t local_index;
    size_t node_count;
    size_t run_count;
    brain_obs_node_t nodes[BRAIN_MAX_NODES];
    brain_obs_run_t* runs; /* capacity QIHSE_CLUSTER_SLOT_COUNT, allocated once */
} brain_obs_t;

/* Decision envelope inputs.  `fingerprint` is NULL for an unsigned record. */
typedef struct {
    const char* action;
    const char* key_handle;
    const uint8_t* evidence;
    size_t evidence_len;
    qihse_sig_alg_t sig_alg;
    size_t signature_len; /* 0 = unsigned */
    const uint8_t* fingerprint;
    const qihse_brain_precondition_t* pre;
} brain_decision_t;

typedef struct {
    uint16_t sig_alg;
    uint16_t signature_len;
    uint16_t action_len;
    uint16_t key_handle_len;
    uint16_t flags;
    uint32_t evidence_len;
    uint64_t obs_seq;
    uint64_t obs_offset;
    uint64_t hlc_physical;
    uint32_t hlc_logical;
    uint8_t observation_hash[48];
    uint8_t payload_digest[48];
    uint8_t fingerprint[48];
    size_t region_len; /* bytes covered by the signature */
} brain_decision_header_t;

typedef struct {
    qihse_resp_server_t* server;
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    char journal_dir[512];
    char dsa_key_path[576];
    pthread_mutex_t journal_lock;
    uint32_t interval_seconds;
    bool act;
    uint32_t act_cooldown_seconds;
    uint32_t rollback_window_seconds;
    bool running;
    qihse_event_stream_t* journal;
    brain_handoff_t handoffs[BRAIN_MAX_HANDOFFS];
    brain_cooldown_t cooldowns[BRAIN_MAX_HANDOFFS];
    uint64_t unhealthy_since[BRAIN_MAX_NODES]; /* 0 = healthy or not yet observed */
    uint32_t prune_timeout_seconds;
    uint32_t rebalance_min_slots;
    brain_pool_t* pool; /* scan workers, created at start and reused every cycle */
    qihse_cluster_node_t* node_buf; /* topology snapshot (heap: 64 nodes is
                                     * ~36 KB, which must not sit on the brain
                                     * thread's stack); NULL = observe skipped */
    /* Federation journal (W3.4).  `fed` is NULL when the journal could not be
     * opened; the brain then journals locally only and refuses to act. */
    qihse_federation_journal_t* fed;
    qihse_federation_watch_t* watch;
    char fed_dir[512];
    uint64_t obs_seq;                       /* observations published */
    brain_obs_t obs;                        /* rule input (from the watch) */
    brain_obs_t obs_local;                  /* as produced this cycle */
    qihse_brain_precondition_t precondition; /* the citation rules must have */
    uint8_t* obs_payload;                   /* heap scratch, allocated once */
    size_t obs_payload_cap;
    uint8_t* decision_payload;              /* heap scratch, allocated once */
    size_t decision_payload_cap;
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_uuid_t node_uuid;                 /* derived from node_id, stable */
    char obs_resource[64];
    bool identity_set;
    bool roundtrip_reported;                /* OBSERVE_MISMATCH journaled once */
    uint16_t quarantine_peer;               /* peer in the quarantine-policy state */
    /* Decision signing: the key is loaded once at start and never journaled. */
    void* sign_pkey;                        /* EVP_PKEY* */
    qihse_sig_alg_t sign_alg;
    uint8_t sign_fingerprint[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    bool have_signer;
    char sign_key_handle[BRAIN_FED_KEY_HANDLE_MAX + 1u];
    pthread_t thread;
} brain_t;

static brain_t* g_brain = NULL;
static pthread_mutex_t g_brain_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t brain_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t brain_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* Append one record to the durable journal. Decisions/observations carry an
 * ML-DSA-87 signature over the record body when a signing key is configured.
 * `brain` is owned by the calling thread (stop() joins before freeing). */
static void brain_journal(brain_t* brain, const char* kind, const char* detail) {
    if (!brain || !brain->journal) return;
    char body[1024];
    int n = snprintf(body, sizeof(body),
                     "{\"t\":%llu,\"kind\":\"%s\",\"detail\":%s}",
                     (unsigned long long)brain_now_ms(), kind, detail);
    if (n <= 0 || n >= (int)sizeof(body)) return;

    uint8_t sig[QIHSE_MLDSA_SIGNATURE_SIZE];
    char sig_hex[QIHSE_MLDSA_SIGNATURE_SIZE * 2u + 1u];
    size_t sig_hex_len = 0;
    if (brain->dsa_key_path[0] &&
        qihse_pqc_sign_path((const uint8_t*)body, (size_t)n, sig, brain->dsa_key_path)) {
        for (size_t i = 0; i < QIHSE_MLDSA_SIGNATURE_SIZE; i++)
            snprintf(sig_hex + i * 2u, 3u, "%02x", sig[i]);
        sig_hex[16] = '\0'; /* journal the first 16 bytes of the sig: tamper evidence, not bulk */
        sig_hex_len = 32u;
        OPENSSL_cleanse(sig, sizeof(sig));
    }

    uint8_t record[1600];
    size_t len;
    if (sig_hex_len) {
        len = (size_t)snprintf((char*)record, sizeof(record),
                               "{\"rec\":%s,\"sig8\":\"%.32s\"}", body, sig_hex);
    } else {
        len = (size_t)snprintf((char*)record, sizeof(record), "{\"rec\":%s}", body);
    }
    if (len == 0 || len >= sizeof(record)) return;
    pthread_mutex_lock(&brain->journal_lock);
    qihse_event_stream_append(brain->journal, BRAIN_TOPIC, record, len);
    pthread_mutex_unlock(&brain->journal_lock);
}

/* ---- Little-endian record codec ------------------------------------------
 * The same discipline as the federation gossip serializer: an explicit
 * writer with overflow tracking, and a reader that can never walk off the
 * end of a malformed record.  A truncated buffer is never mistaken for a
 * complete record. */

typedef struct {
    uint8_t* buf;
    size_t cap;
    size_t len;
    bool overflow;
} brain_le_writer_t;

static void brain_le_u16(brain_le_writer_t* w, uint16_t v) {
    if (w->len + 2u > w->cap) { w->overflow = true; return; }
    w->buf[w->len++] = (uint8_t)(v & 0xFFu);
    w->buf[w->len++] = (uint8_t)((v >> 8) & 0xFFu);
}

static void brain_le_u32(brain_le_writer_t* w, uint32_t v) {
    for (int i = 0; i < 4; i++) {
        if (w->len + 1u > w->cap) { w->overflow = true; return; }
        w->buf[w->len++] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

static void brain_le_u64(brain_le_writer_t* w, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        if (w->len + 1u > w->cap) { w->overflow = true; return; }
        w->buf[w->len++] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

static void brain_le_bytes(brain_le_writer_t* w, const void* b, size_t n) {
    if (w->len + n > w->cap) { w->overflow = true; return; }
    memcpy(w->buf + w->len, b, n);
    w->len += n;
}

typedef struct {
    const uint8_t* buf;
    size_t len;
    size_t off;
    bool underflow;
} brain_le_reader_t;

static uint16_t brain_le_get_u16(brain_le_reader_t* r) {
    if (r->off + 2u > r->len) { r->underflow = true; return 0; }
    uint16_t v = (uint16_t)r->buf[r->off] | (uint16_t)((uint16_t)r->buf[r->off + 1u] << 8);
    r->off += 2u;
    return v;
}

static uint32_t brain_le_get_u32(brain_le_reader_t* r) {
    uint32_t v = 0;
    if (r->off + 4u > r->len) { r->underflow = true; return 0; }
    for (int i = 0; i < 4; i++) v |= (uint32_t)r->buf[r->off + (size_t)i] << (8 * i);
    r->off += 4u;
    return v;
}

static uint64_t brain_le_get_u64(brain_le_reader_t* r) {
    uint64_t v = 0;
    if (r->off + 8u > r->len) { r->underflow = true; return 0; }
    for (int i = 0; i < 8; i++) v |= (uint64_t)r->buf[r->off + (size_t)i] << (8 * i);
    r->off += 8u;
    return v;
}

static const uint8_t* brain_le_get_bytes(brain_le_reader_t* r, size_t n) {
    if (r->off + n > r->len) { r->underflow = true; return NULL; }
    const uint8_t* p = r->buf + r->off;
    r->off += n;
    return p;
}

static bool brain_all_zero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i]) return false;
    return true;
}

/* SHA-384 of an arbitrary buffer: the digest a decision cites for the
 * observation it was derived from, and the one a replayer recomputes. */
static bool brain_sha384(const uint8_t* data, size_t len, uint8_t out[48]) {
    if (!data && len) return false;
    unsigned int out_len = 0;
    return EVP_Digest(data, len, out, &out_len, EVP_sha384(), NULL) == 1 && out_len == 48u;
}

/* ---- Observations --------------------------------------------------------
 * The recorded observation is the rule input: the rules read the decoded
 * record, never a private copy, which is what makes a decision reproducible
 * from the journal.  The human-readable detail JSON the local journal already
 * carries is embedded verbatim so the federation record is greppable and
 * indexable too (W3.6 dogfooding). */

static size_t brain_obs_encode(const brain_obs_t* obs, const char* detail, size_t detail_len,
                               uint8_t* out, size_t out_cap) {
    if (!obs || !out) return 0;
    if (obs->node_count > BRAIN_MAX_NODES) return 0;
    if (obs->run_count > QIHSE_CLUSTER_SLOT_COUNT) return 0;
    if (detail_len > BRAIN_FED_DETAIL_MAX) return 0;
    size_t need = QIHSE_BRAIN_OBS_HEADER_BYTES +
                  obs->node_count * BRAIN_OBS_NODE_BYTES +
                  obs->run_count * BRAIN_OBS_RUN_BYTES + detail_len;
    if (need > out_cap) return 0;

    brain_le_writer_t w = { out, out_cap, 0, false };
    brain_le_u32(&w, BRAIN_FED_OBS_MAGIC);
    brain_le_u16(&w, BRAIN_FED_FORMAT_VERSION);
    brain_le_u16(&w, obs->local_index);
    brain_le_u64(&w, obs->seq);
    brain_le_u64(&w, obs->scan_us);
    brain_le_u32(&w, obs->workers);
    brain_le_u32(&w, (uint32_t)obs->node_count);
    brain_le_u32(&w, (uint32_t)obs->run_count);
    brain_le_u32(&w, (uint32_t)detail_len);
    for (size_t i = 0; i < obs->node_count; i++) {
        const brain_obs_node_t* n = &obs->nodes[i];
        brain_le_u16(&w, n->index);
        brain_le_u16(&w, n->role);
        brain_le_u16(&w, n->primary_index);
        brain_le_u16(&w, n->port);
        brain_le_u16(&w, n->bus_port);
        brain_le_u16(&w, 0); /* reserved, keeps the node record 4-byte aligned */
        brain_le_u32(&w, n->flags);
        brain_le_bytes(&w, n->id, sizeof(n->id));
        brain_le_bytes(&w, n->host, sizeof(n->host));
    }
    for (size_t i = 0; i < obs->run_count; i++) {
        brain_le_u16(&w, obs->runs[i].owner);
        brain_le_u16(&w, obs->runs[i].start);
        brain_le_u16(&w, obs->runs[i].end);
        brain_le_u16(&w, 0);
    }
    if (detail && detail_len) brain_le_bytes(&w, detail, detail_len);
    if (w.overflow) return 0;
    return w.len;
}

/* Decode into a caller-owned observation (heap; see brain_obs_t).  Every
 * declared count is validated against BOTH the remaining payload and the
 * format's maximum before a byte is copied, so a malformed record cannot
 * overrun the fixed arrays or the buffer. */
static bool brain_obs_decode(const uint8_t* in, size_t in_len, brain_obs_t* out) {
    if (!in || !out || !out->runs) return false;

    brain_le_reader_t r = { in, in_len, 0, false };
    uint32_t magic = brain_le_get_u32(&r);
    uint16_t version = brain_le_get_u16(&r);
    uint16_t local_index = brain_le_get_u16(&r);
    uint64_t seq = brain_le_get_u64(&r);
    uint64_t scan_us = brain_le_get_u64(&r);
    uint32_t workers = brain_le_get_u32(&r);
    uint32_t node_count = brain_le_get_u32(&r);
    uint32_t run_count = brain_le_get_u32(&r);
    uint32_t detail_len = brain_le_get_u32(&r);
    if (r.underflow) return false;
    if (magic != BRAIN_FED_OBS_MAGIC || version != BRAIN_FED_FORMAT_VERSION) return false;
    if (node_count > BRAIN_MAX_NODES) return false;
    if (run_count > QIHSE_CLUSTER_SLOT_COUNT) return false;
    if (detail_len > BRAIN_FED_DETAIL_MAX) return false;
    size_t need = (size_t)node_count * BRAIN_OBS_NODE_BYTES +
                  (size_t)run_count * BRAIN_OBS_RUN_BYTES + (size_t)detail_len;
    if (need > in_len - r.off) return false;

    brain_obs_run_t* runs = out->runs; /* the caller's buffer survives the reset */
    memset(out, 0, sizeof(*out));
    out->runs = runs;
    out->seq = seq;
    out->scan_us = scan_us;
    out->workers = workers;
    out->local_index = local_index;
    out->node_count = node_count;
    out->run_count = run_count;

    for (uint32_t i = 0; i < node_count; i++) {
        brain_obs_node_t* n = &out->nodes[i];
        n->index = brain_le_get_u16(&r);
        n->role = brain_le_get_u16(&r);
        n->primary_index = brain_le_get_u16(&r);
        n->port = brain_le_get_u16(&r);
        n->bus_port = brain_le_get_u16(&r);
        (void)brain_le_get_u16(&r); /* reserved */
        n->flags = brain_le_get_u32(&r);
        const uint8_t* id = brain_le_get_bytes(&r, sizeof(n->id));
        const uint8_t* host = brain_le_get_bytes(&r, sizeof(n->host));
        if (r.underflow || !id || !host) return false;
        memcpy(n->id, id, sizeof(n->id));
        memcpy(n->host, host, sizeof(n->host));
        /* A record without a terminator must not produce an unterminated
         * string in the rule input. */
        n->id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
        n->host[QIHSE_CLUSTER_HOST_LEN] = '\0';
    }
    for (uint32_t i = 0; i < run_count; i++) {
        out->runs[i].owner = brain_le_get_u16(&r);
        out->runs[i].start = brain_le_get_u16(&r);
        out->runs[i].end = brain_le_get_u16(&r);
        (void)brain_le_get_u16(&r); /* reserved */
    }
    if (r.underflow) return false;
    out->valid = true;
    return true;
}

/* Round-trip check: the decoded record must describe exactly the observation
 * the rules are about to act on.  If it does not, the recorded input is not
 * sufficient to reproduce the decision, so the cycle gets no pre-condition
 * and nothing may act.  Padding bytes are deterministic on both sides (both
 * structs are zeroed before their fields are set), so memcmp is exact. */
static bool brain_obs_equal(const brain_obs_t* a, const brain_obs_t* b) {
    if (!a || !b) return false;
    if (a->seq != b->seq || a->scan_us != b->scan_us || a->workers != b->workers ||
        a->local_index != b->local_index || a->node_count != b->node_count ||
        a->run_count != b->run_count) return false;
    if (a->node_count &&
        memcmp(a->nodes, b->nodes, a->node_count * sizeof(a->nodes[0])) != 0) return false;
    if (a->run_count &&
        memcmp(a->runs, b->runs, a->run_count * sizeof(a->runs[0])) != 0) return false;
    return true;
}

static const brain_obs_node_t* brain_obs_find_node(const brain_obs_t* obs, uint16_t index) {
    if (!obs) return NULL;
    for (size_t i = 0; i < obs->node_count; i++)
        if (obs->nodes[i].index == index) return &obs->nodes[i];
    return NULL;
}

/* ── Pre-condition gate ─────────────────────────────────────────────────── */

bool qihse_cluster_brain_precondition_ok(const qihse_brain_precondition_t* pre) {
    if (!pre || !pre->valid) return false;
    if (pre->observation_seq == 0) return false;
    /* The journal stamps every record with an HLC and a chain hash, so a
     * pre-condition with neither is not a record.  The journal offset is
     * deliberately not checked for zero: the first record in a topic file
     * lives at offset 0. */
    if (pre->hlc.physical_ms == 0 && pre->hlc.logical == 0) return false;
    if (brain_all_zero(pre->observation_hash, sizeof(pre->observation_hash))) return false;
    if (brain_all_zero(pre->payload_digest, sizeof(pre->payload_digest))) return false;
    return true;
}

/* ── Decision envelopes ─────────────────────────────────────────────────── */

/* Write the signed region (everything the signature covers).  Returns the
 * region length, or 0 when the record does not fit. */
static size_t brain_decision_region_encode(const brain_decision_t* d, uint8_t* out, size_t out_cap) {
    if (!d || !d->action || !out) return 0;
    size_t action_len = strlen(d->action);
    size_t handle_len = d->key_handle ? strlen(d->key_handle) : 0;
    if (action_len == 0 || action_len > BRAIN_FED_ACTION_MAX) return 0;
    if (handle_len > BRAIN_FED_KEY_HANDLE_MAX) return 0;
    if (d->evidence_len > BRAIN_FED_EVIDENCE_MAX) return 0;
    if (d->signature_len > BRAIN_FED_MAX_SIGNATURE) return 0;
    size_t region = BRAIN_FED_DECISION_HEADER + action_len + handle_len + d->evidence_len;
    if (region + d->signature_len > out_cap) return 0;

    uint16_t flags = 0;
    if (d->pre && qihse_cluster_brain_precondition_ok(d->pre))
        flags |= BRAIN_FED_DECISION_F_PRECONDITION;

    /* A missing hash/digest/fingerprint is written as zeros rather than
     * skipped, so the header is always exactly BRAIN_FED_DECISION_HEADER
     * bytes and the region length can be computed before signing. */
    uint8_t zeros[48];
    memset(zeros, 0, sizeof(zeros));

    brain_le_writer_t w = { out, out_cap, 0, false };
    brain_le_u32(&w, BRAIN_FED_DECISION_MAGIC);
    brain_le_u16(&w, BRAIN_FED_FORMAT_VERSION);
    brain_le_u16(&w, (uint16_t)d->sig_alg);
    brain_le_u16(&w, (uint16_t)d->signature_len);
    brain_le_u16(&w, (uint16_t)action_len);
    brain_le_u16(&w, (uint16_t)handle_len);
    brain_le_u16(&w, flags);
    brain_le_u64(&w, d->pre ? d->pre->observation_seq : 0);
    brain_le_u64(&w, d->pre ? d->pre->journal_offset : 0);
    brain_le_u64(&w, d->pre ? d->pre->hlc.physical_ms : 0);
    brain_le_u32(&w, d->pre ? d->pre->hlc.logical : 0);
    brain_le_u32(&w, (uint32_t)d->evidence_len);
    brain_le_bytes(&w, d->pre ? d->pre->observation_hash : zeros, 48u);
    brain_le_bytes(&w, d->pre ? d->pre->payload_digest : zeros, 48u);
    brain_le_bytes(&w, d->fingerprint ? d->fingerprint : zeros, 48u);
    brain_le_bytes(&w, d->action, action_len);
    if (handle_len) brain_le_bytes(&w, d->key_handle, handle_len);
    if (d->evidence_len) brain_le_bytes(&w, d->evidence, d->evidence_len);
    if (w.overflow || w.len != region) return 0;
    return w.len;
}

static bool brain_decision_header_decode(const uint8_t* in, size_t in_len,
                                         brain_decision_header_t* h) {
    if (!in || !h) return false;
    memset(h, 0, sizeof(*h));
    brain_le_reader_t r = { in, in_len, 0, false };
    uint32_t magic = brain_le_get_u32(&r);
    uint16_t version = brain_le_get_u16(&r);
    uint16_t sig_alg = brain_le_get_u16(&r);
    uint16_t signature_len = brain_le_get_u16(&r);
    uint16_t action_len = brain_le_get_u16(&r);
    uint16_t handle_len = brain_le_get_u16(&r);
    uint16_t flags = brain_le_get_u16(&r);
    uint64_t obs_seq = brain_le_get_u64(&r);
    uint64_t obs_offset = brain_le_get_u64(&r);
    uint64_t hlc_physical = brain_le_get_u64(&r);
    uint32_t hlc_logical = brain_le_get_u32(&r);
    uint32_t evidence_len = brain_le_get_u32(&r);
    const uint8_t* obs_hash = brain_le_get_bytes(&r, 48u);
    const uint8_t* digest = brain_le_get_bytes(&r, 48u);
    const uint8_t* fingerprint = brain_le_get_bytes(&r, 48u);
    if (r.underflow || !obs_hash || !digest || !fingerprint) return false;
    if (magic != BRAIN_FED_DECISION_MAGIC || version != BRAIN_FED_FORMAT_VERSION) return false;
    if (sig_alg > (uint16_t)QIHSE_SIG_ML_DSA_87) return false;
    if (action_len == 0 || action_len > BRAIN_FED_ACTION_MAX) return false;
    if (handle_len > BRAIN_FED_KEY_HANDLE_MAX) return false;
    if (evidence_len > BRAIN_FED_EVIDENCE_MAX) return false;
    /* An unsigned record carries no signature; a signed one carries exactly
     * the algorithm's signature length.  Anything else is malformed. */
    if (signature_len != 0) {
        if (signature_len != qihse_sig_alg_signature_bytes((qihse_sig_alg_t)sig_alg)) return false;
    }
    size_t region = BRAIN_FED_DECISION_HEADER + (size_t)action_len + (size_t)handle_len +
                    (size_t)evidence_len;
    if (region + (size_t)signature_len != in_len) return false;

    h->sig_alg = sig_alg;
    h->signature_len = signature_len;
    h->action_len = action_len;
    h->key_handle_len = handle_len;
    h->flags = flags;
    h->evidence_len = evidence_len;
    h->obs_seq = obs_seq;
    h->obs_offset = obs_offset;
    h->hlc_physical = hlc_physical;
    h->hlc_logical = hlc_logical;
    memcpy(h->observation_hash, obs_hash, 48u);
    memcpy(h->payload_digest, digest, 48u);
    memcpy(h->fingerprint, fingerprint, 48u);
    h->region_len = region;
    return true;
}

bool qihse_cluster_brain_decision_is_signed(const uint8_t* envelope, size_t envelope_len) {
    brain_decision_header_t h;
    if (!brain_decision_header_decode(envelope, envelope_len, &h)) return false;
    if (h.signature_len == 0) return false;
    return !brain_all_zero(h.fingerprint, sizeof(h.fingerprint));
}

bool qihse_cluster_brain_decision_verify(const uint8_t* public_key, size_t public_key_len,
                                         const uint8_t* envelope, size_t envelope_len) {
    if (!public_key || !envelope) return false;
    brain_decision_header_t h;
    if (!brain_decision_header_decode(envelope, envelope_len, &h)) return false;
    if (h.signature_len == 0) return false; /* unsigned: nothing to verify */

    /* Recompute the fingerprint: a stored fingerprint is never trusted to
     * describe the key it is attached to (AGENTS.md, decoder rule 4). */
    uint8_t recomputed[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
    if (!qihse_federation_node_fingerprint(public_key, public_key_len, recomputed)) return false;
    if (memcmp(recomputed, h.fingerprint, sizeof(recomputed)) != 0) return false;

    return qihse_federation_verify((qihse_sig_alg_t)h.sig_alg,
                                   public_key, public_key_len,
                                   envelope, h.region_len,
                                   envelope + h.region_len, h.signature_len);
}

bool qihse_cluster_brain_decision_inspect(const uint8_t* envelope, size_t envelope_len,
                                          char* out_action, size_t action_cap,
                                          qihse_brain_precondition_t* out_precondition) {
    brain_decision_header_t h;
    if (!brain_decision_header_decode(envelope, envelope_len, &h)) return false;
    if (out_action) {
        if (action_cap == 0) return false;
        size_t n = h.action_len < action_cap - 1u ? h.action_len : action_cap - 1u;
        memcpy(out_action, envelope + BRAIN_FED_DECISION_HEADER, n);
        out_action[n] = '\0';
    }
    if (out_precondition) {
        memset(out_precondition, 0, sizeof(*out_precondition));
        out_precondition->valid = (h.flags & BRAIN_FED_DECISION_F_PRECONDITION) != 0;
        out_precondition->journal_offset = h.obs_offset;
        out_precondition->observation_seq = h.obs_seq;
        out_precondition->hlc.physical_ms = h.hlc_physical;
        out_precondition->hlc.logical = h.hlc_logical;
        memcpy(out_precondition->observation_hash, h.observation_hash, 48u);
        memcpy(out_precondition->payload_digest, h.payload_digest, 48u);
    }
    return true;
}

/* Mutation envelope for a brain record.  The HLC is left zero so the journal
 * ticks its own clock and stamps the record; origin_node is derived from the
 * cluster node id, so a replayer can recompute it; principal_id stays nil
 * because a brain record has no authenticated human principal — attribution
 * is the signed node-identity fingerprint. */
static qihse_federation_mutation_t brain_fed_mutation(brain_t* brain, const char* kind,
                                                      uint64_t seq) {
    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    m.origin_node = brain->node_uuid;
    m.consistency = QIHSE_CONSISTENCY_LOCAL;
    /* Deterministic request id: the same (node, kind, sequence) is the same
     * record, so a consumer can dedupe without trusting the HLC. */
    char seed[128];
    int n = snprintf(seed, sizeof(seed), "%s|%s|%llu", brain->node_id, kind,
                     (unsigned long long)seq);
    if (n > 0) (void)qihse_uuid_from_seed(seed, (size_t)n, &m.request_id);
    return m;
}

/* Publish a decision envelope.  `sign` is true only for decisions that commit
 * cluster state (and for the quarantine policy transition), so the signing
 * cost is never on the per-cycle observation path.  Best-effort by design: a
 * record that cannot be published leaves the local journal as the only trace,
 * and the action it describes was already gated on the pre-condition. */
static void brain_decision_record(brain_t* brain, const char* action, const char* evidence,
                                  bool sign) {
    if (!brain || !brain->fed || !brain->decision_payload || !action) return;
    const char* ev = evidence ? evidence : "null";
    size_t ev_len = strlen(ev);
    if (ev_len > BRAIN_FED_EVIDENCE_MAX) ev_len = BRAIN_FED_EVIDENCE_MAX;

    brain_decision_t d;
    memset(&d, 0, sizeof(d));
    d.action = action;
    d.key_handle = brain->have_signer ? brain->sign_key_handle : "";
    d.evidence = (const uint8_t*)ev;
    d.evidence_len = ev_len;
    d.pre = &brain->precondition;
    d.sig_alg = brain->have_signer ? brain->sign_alg : QIHSE_SIG_ALG_DEFAULT;
    d.signature_len = (sign && brain->have_signer)
                          ? qihse_sig_alg_signature_bytes(brain->sign_alg) : 0;
    d.fingerprint = d.signature_len ? brain->sign_fingerprint : NULL;

    uint8_t* buf = brain->decision_payload;
    size_t cap = brain->decision_payload_cap;
    size_t region = brain_decision_region_encode(&d, buf, cap);
    if (region == 0) return;
    size_t total = region;
    if (d.signature_len) {
        if (cap - region < d.signature_len) return;
        size_t sig_len = d.signature_len;
        if (qihse_federation_sign(brain->sign_pkey, buf, region, buf + region, &sig_len) &&
            sig_len == d.signature_len) {
            total = region + sig_len;
        } else {
            /* Cannot sign: publish an honest unsigned envelope rather than a
             * record whose signature field is garbage. */
            brain_decision_t unsigned_d = d;
            unsigned_d.signature_len = 0;
            unsigned_d.fingerprint = NULL;
            total = brain_decision_region_encode(&unsigned_d, buf, cap);
            if (total == 0) return;
        }
    }

    char resource[64];
    snprintf(resource, sizeof(resource), "%s%s", QIHSE_BRAIN_FED_DECISION_PREFIX, action);
    qihse_federation_mutation_t m = brain_fed_mutation(brain, action, brain->obs_seq);
    (void)qihse_federation_journal_append(brain->fed, &m, QIHSE_BRAIN_FED_EVENT_DECISION,
                                          resource, buf, total, NULL);
}

/* The gate every state-committing rule passes through.  A false return means
 * the action MUST NOT be taken: the refusal is journaled so an operator can
 * see that the brain wanted to act and was not allowed to. */
static bool brain_gate(brain_t* brain, const char* action, const char* evidence) {
    if (qihse_cluster_brain_precondition_ok(&brain->precondition)) return true;
    char detail[640];
    snprintf(detail, sizeof(detail),
             "{\"action\":\"%s\",\"reason\":\"no-journaled-precondition\",\"evidence\":%.480s}",
             action, evidence ? evidence : "null");
    brain_journal(brain, "DECISION_REFUSED", detail);
    /* Record the refusal on the federation journal too when it is up, under a
     * distinct resource so "brain/decision/<action>" always means the brain
     * decided that action: an unsigned envelope citing nothing is still an
     * attributable statement that the brain refused. */
    brain_decision_record(brain, "refused", detail, false);
    return false;
}

/* ── Decision signing ───────────────────────────────────────────────────── */

/* The raw public key of a loaded private key.  EVP_PKEY_get_raw_public_key()
 * is not usable for a PEM-loaded ML-DSA key — the provider refuses the raw
 * export even though the size query succeeds — so fall back to the "pub"
 * octet-string parameter, which is the same bytes for every supported
 * algorithm. */
static bool brain_public_key_of(void* pkey, qihse_sig_alg_t alg,
                                uint8_t* out, size_t out_cap, size_t* out_len) {
    size_t want = qihse_sig_alg_public_key_bytes(alg);
    if (!pkey || !out || want == 0 || out_cap < want) return false;
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key((EVP_PKEY*)pkey, out, &len) == 1 && len == want) {
        if (out_len) *out_len = len;
        return true;
    }
    len = 0;
    if (EVP_PKEY_get_octet_string_param((EVP_PKEY*)pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        out, out_cap, &len) == 1 && len == want) {
        if (out_len) *out_len = len;
        return true;
    }
    return false;
}

/* Prove at start that the key handle, the derived public key and the
 * fingerprint agree, by signing and verifying a fixed probe.  A signer whose
 * public half does not match would publish decisions nobody can verify, which
 * is worse than starting degraded. */
static bool brain_signer_selfcheck(void* pkey, qihse_sig_alg_t alg,
                                   const uint8_t* public_key, size_t public_key_len) {
    static const char probe[] = "qihse-brain-decision-signer-selfcheck";
    uint8_t sig[QIHSE_FEDERATION_SIG_MAX_BYTES];
    size_t sig_len = sizeof(sig);
    bool ok = qihse_federation_sign(pkey, (const uint8_t*)probe, sizeof(probe) - 1u,
                                    sig, &sig_len) &&
              qihse_federation_verify(alg, public_key, public_key_len,
                                      (const uint8_t*)probe, sizeof(probe) - 1u,
                                      sig, sig_len);
    OPENSSL_cleanse(sig, sizeof(sig));
    return ok;
}

/* ── Watch consumption ──────────────────────────────────────────────────── */

/* Drain the observation watch and keep the newest record this brain
 * published.  The decoded record becomes the rule input, so the rules act on
 * the bytes that were journaled — not on a private copy of them. */
static bool brain_consume_observation(brain_t* brain) {
    if (!brain || !brain->watch) return false;
    bool consumed = false;
    for (;;) {
        qihse_federation_event_t event;
        uint8_t* payload = NULL;
        size_t payload_len = 0;
        if (!qihse_federation_watch_next(brain->watch, &event, &payload, &payload_len)) break;
        if (payload && payload_len && brain_obs_decode(payload, payload_len, &brain->obs) &&
            brain->obs.seq == brain->obs_seq) {
            memset(&brain->precondition, 0, sizeof(brain->precondition));
            brain->precondition.journal_offset = event.journal_offset;
            brain->precondition.observation_seq = brain->obs.seq;
            brain->precondition.hlc = event.mutation.hlc;
            memcpy(brain->precondition.observation_hash, event.hash, 48u);
            if (!brain_sha384(payload, payload_len, brain->precondition.payload_digest))
                memset(&brain->precondition.payload_digest, 0, 48u);
            brain->precondition.valid = true;
            consumed = true;
        }
        free(payload);
        (void)qihse_federation_watch_ack(brain->watch, event.journal_offset);
    }
    return consumed;
}

/* Publish this cycle's observation and read it back.  Returns true when the
 * cycle has a usable rule input; the pre-condition is valid only when the
 * record was journaled, read back through the watch, and round-tripped to the
 * same values the rules are about to use. */
static bool brain_publish_observation(brain_t* brain, const char* detail, size_t detail_len) {
    brain->obs.valid = false;
    if (!brain->fed || !brain->obs_payload) return false;
    size_t len = brain_obs_encode(&brain->obs_local, detail, detail_len, brain->obs_payload,
                                  brain->obs_payload_cap);
    if (len == 0) return false;
    qihse_federation_mutation_t m = brain_fed_mutation(brain, "observe", brain->obs_seq);
    if (qihse_federation_journal_append(brain->fed, &m, QIHSE_BRAIN_FED_EVENT_OBSERVE,
                                        brain->obs_resource, brain->obs_payload, len,
                                        NULL) == 0)
        return false;
    if (!brain_consume_observation(brain)) return false;
    if (!brain_obs_equal(&brain->obs, &brain->obs_local)) {
        /* The recorded form does not reproduce the rule input.  Treat the
         * cycle as having no pre-condition: nothing may act. */
        if (!brain->roundtrip_reported) {
            brain->roundtrip_reported = true;
            brain_journal(brain, "OBSERVE_MISMATCH",
                          "{\"reason\":\"recorded observation does not round-trip\"}");
        }
        memset(&brain->precondition, 0, sizeof(brain->precondition));
        return false;
    }
    return true;
}

/* ---- Parallel slot triage ------------------------------------------------
 * The observe pass used to walk all 16384 slots serially, taking the
 * topology lock once per slot. Now: ONE bulk snapshot (single lock hold),
 * then the run-coalescing analysis runs lock-free on the private copy,
 * split across worker threads. Deterministic: workers own contiguous slot
 * chunks, results merge in chunk order, identical output at any T. */

typedef struct {
    uint16_t owner;
    uint16_t start;
    uint16_t end;
} brain_run_t;

typedef struct {
    const uint16_t* owners;
    uint32_t start;
    uint32_t end;
    brain_run_t* runs;
    size_t count;
    size_t cap;
} brain_scan_t;

static void scan_push(brain_scan_t* w, uint16_t owner, uint32_t start, uint32_t end) {
    if (w->count && w->runs[w->count - 1u].owner == owner &&
        (uint32_t)w->runs[w->count - 1u].end + 1u == start) {
        w->runs[w->count - 1u].end = (uint16_t)end;
        return;
    }
    if (w->count == w->cap) {
        size_t next = w->cap ? w->cap * 2u : 256u;
        brain_run_t* grown = realloc(w->runs, next * sizeof(*grown));
        if (!grown) return; /* drop runs on OOM: journal stays best-effort */
        w->runs = grown;
        w->cap = next;
    }
    w->runs[w->count].owner = owner;
    w->runs[w->count].start = (uint16_t)start;
    w->runs[w->count].end = (uint16_t)end;
    w->count++;
}

static void* scan_worker(void* argument) {
    brain_scan_t* w = (brain_scan_t*)argument;
    for (uint32_t s = w->start; s < w->end; s++) {
        uint16_t owner = w->owners[s];
        if (owner == QIHSE_CLUSTER_NODE_NONE) continue;
        scan_push(w, owner, s, s);
    }
    return NULL;
}

static uint32_t brain_worker_count(void) {
    const char* env = getenv("QIHSE_BRAIN_WORKERS");
    if (env && *env) {
        long v = strtol(env, NULL, 10);
        if (v >= 1 && v <= 32) return (uint32_t)v;
    }
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    uint32_t t = (uint32_t)cores > 8u ? 8u : (uint32_t)cores;
    return t;
}

/* ---- Persistent scan pool ------------------------------------------------
 * A fresh pthread per chunk per cycle was the dominant cost of the observe
 * pass (thread creation, not slot triage: ~730-780 us/cycle at 8 workers on
 * the 2-node lab). The pool is created once by qihse_cluster_brain_start()
 * and reused by every scan — workers park on a condvar between rounds and
 * wake to triage their own chunk.
 *
 * Determinism is unchanged: a chunk is still a contiguous slice of the slot
 * array, the brain thread still owns chunk 0, and results are merged in chunk
 * order only after every chunk has reported done. No worker can see or
 * reorder another's runs, so output never depends on completion order (or on
 * the chunk count at all).
 *
 * Lifecycle: create at brain start, destroy after the brain thread is joined.
 * Workers are never detached and never cancelled — destroy broadcasts `stop`,
 * a worker caught mid-chunk finishes that chunk and parks, then exits. */

#define BRAIN_MAX_WORKERS 32u /* matches the QIHSE_BRAIN_WORKERS ceiling */

typedef struct {
    brain_pool_t* pool;
    uint32_t index; /* chunk this worker owns (1..chunks-1) */
    uint64_t round; /* last round this worker executed */
} brain_pool_worker_t;

struct brain_pool {
    brain_scan_t scans[BRAIN_MAX_WORKERS]; /* one descriptor per chunk */
    pthread_t threads[BRAIN_MAX_WORKERS];  /* one per chunk 1..chunks-1 */
    brain_pool_worker_t workers[BRAIN_MAX_WORKERS];
    uint32_t chunks;  /* chunks in use; chunk 0 belongs to the owning thread */
    uint32_t want;    /* last requested count (0 = never sized) */
    uint32_t pending; /* worker chunks still running this round */
    uint64_t round;   /* round counter; a worker runs when it lags this */
    bool stop;        /* destroy requested */
    pthread_mutex_t lock;
    pthread_cond_t work; /* owner -> workers: a round is open */
    pthread_cond_t done; /* workers -> owner: the round is complete */
};

/* One pool worker: park until the owner opens a round this worker has not run
 * yet, triage its own chunk, park again. Chunks run lock-free; only the round
 * handshake touches the pool lock, so workers never block each other. */
static void* brain_pool_worker(void* argument) {
    brain_pool_worker_t* w = (brain_pool_worker_t*)argument;
    brain_pool_t* pool = w->pool;
    pthread_mutex_lock(&pool->lock);
    for (;;) {
        while (!pool->stop && pool->round == w->round) pthread_cond_wait(&pool->work, &pool->lock);
        if (pool->stop) break; /* mid-chunk work already finished above */
        uint64_t round = pool->round;
        pthread_mutex_unlock(&pool->lock);
        scan_worker(&pool->scans[w->index]);
        pthread_mutex_lock(&pool->lock);
        w->round = round;
        if (--pool->pending == 0u) pthread_cond_signal(&pool->done);
    }
    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

/* Park the current workers and start `chunks - 1` fresh ones. Called by the
 * owning thread between rounds only, so no chunk is ever half-written. A
 * worker that cannot be spawned shrinks the pool instead of failing the scan:
 * chunk 0 always belongs to the owning thread, so a pool of one chunk is the
 * serial fallback. Failed spawns are not retried until the requested count
 * changes, so an OOM cannot turn into a per-cycle spawn storm. */
static void brain_pool_resize(brain_pool_t* pool, uint32_t chunks) {
    if (chunks > BRAIN_MAX_WORKERS) chunks = BRAIN_MAX_WORKERS;
    if (chunks < 1u) chunks = 1u;
    if (chunks == pool->want) return;

    pthread_mutex_lock(&pool->lock);
    pool->stop = true;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->lock);
    for (uint32_t i = 1; i < pool->chunks; i++) pthread_join(pool->threads[i], NULL);

    pool->stop = false;
    pool->round = 0;
    pool->pending = 0;
    pool->chunks = chunks;
    pool->want = chunks;
    for (uint32_t i = 1; i < chunks; i++) {
        brain_pool_worker_t* w = &pool->workers[i];
        w->pool = pool;
        w->index = i;
        w->round = 0;
        if (pthread_create(&pool->threads[i], NULL, brain_pool_worker, w) != 0) {
            pool->chunks = i; /* owning thread covers chunk 0; threads 1..i-1 started */
            break;
        }
    }
}

/* Create the pool with `chunks` chunks (chunk 0 is the owning thread's).
 * Returns NULL only when the pool itself cannot be allocated or initialised;
 * the caller then scans serially. Thread creation failure is not fatal — the
 * pool simply shrinks to the chunks it could start. */
static brain_pool_t* brain_pool_create(uint32_t chunks) {
    brain_pool_t* pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->work, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->done, NULL) != 0) {
        pthread_cond_destroy(&pool->work);
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }
    brain_pool_resize(pool, chunks);
    return pool;
}

/* Stop and join every worker, then release the pool. A worker mid-chunk is
 * never cancelled: it finishes, parks, sees `stop`, and exits. The owning
 * thread calls this between rounds, so the drain below normally returns
 * immediately; it exists so a round can never be torn down half-written. */
static void brain_pool_destroy(brain_pool_t* pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    while (pool->pending) pthread_cond_wait(&pool->done, &pool->lock);
    pool->stop = true;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->lock);
    for (uint32_t i = 1; i < pool->chunks; i++) pthread_join(pool->threads[i], NULL);
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->work);
    pthread_cond_destroy(&pool->done);
    free(pool);
}

/* Run one triage round over `owners`: the owning thread takes chunk 0, the
 * pool's workers take the rest, and the call returns only once every chunk is
 * written. A worker executes a round only when its own round counter lags the
 * pool's, so no chunk is ever scanned twice. Returns the chunks used. */
static uint32_t brain_pool_scan(brain_pool_t* pool, const uint16_t* owners) {
    uint32_t chunk = (QIHSE_CLUSTER_SLOT_COUNT + pool->chunks - 1u) / pool->chunks;
    for (uint32_t i = 0; i < pool->chunks; i++) {
        brain_scan_t* scan = &pool->scans[i];
        scan->owners = owners;
        scan->start = i * chunk;
        scan->end = scan->start + chunk;
        if (scan->end > QIHSE_CLUSTER_SLOT_COUNT) scan->end = QIHSE_CLUSTER_SLOT_COUNT;
    }

    pthread_mutex_lock(&pool->lock);
    pool->round++;
    pool->pending = pool->chunks - 1u;
    pthread_cond_broadcast(&pool->work);
    pthread_mutex_unlock(&pool->lock);

    scan_worker(&pool->scans[0]); /* the owner takes chunk 0: no idle-core tax */

    if (pool->chunks > 1u) {
        pthread_mutex_lock(&pool->lock);
        while (pool->pending) pthread_cond_wait(&pool->done, &pool->lock);
        pthread_mutex_unlock(&pool->lock);
    }
    return pool->chunks;
}

/* Release a chunk's run list. The pool reuses its descriptors, so a stale run
 * count must never survive into the next round. */
static void brain_scan_clear(brain_scan_t* scan) {
    free(scan->runs);
    scan->runs = NULL;
    scan->count = 0;
    scan->cap = 0;
}

/* One observation per cycle: ONE topology snapshot, one triage round, one
 * local journal record, one federation journal record.  The rules then consume
 * the recorded observation (read back through the watch) instead of polling
 * the topology again — see brain_publish_observation().  The local record's
 * detail JSON is byte-for-byte what it always was; the federation record
 * embeds the same bytes alongside the structured rule input. */
static void brain_observe(brain_t* brain) {
    memset(&brain->precondition, 0, sizeof(brain->precondition));
    brain->obs.valid = false;
    brain->obs_local.valid = false;
    if (!brain->topology || !brain->node_buf) return;

    size_t count = qihse_cluster_topology_nodes(brain->topology, brain->node_buf,
                                                BRAIN_MAX_NODES);
    /* qihse_cluster_topology_nodes() reports the live count and writes at most
     * `capacity`: clamp before indexing the buffer. */
    if (count > BRAIN_MAX_NODES) count = BRAIN_MAX_NODES;
    uint16_t local = qihse_cluster_topology_local_node(brain->topology);

    uint64_t t0 = brain_now_us();
    uint16_t* owners = malloc(QIHSE_CLUSTER_SLOT_COUNT * sizeof(uint16_t));
    if (!owners) return;
    if (qihse_cluster_topology_slot_owner_snapshot(brain->topology, owners,
                                                   QIHSE_CLUSTER_SLOT_COUNT) != QIHSE_CLUSTER_SLOT_COUNT) {
        free(owners);
        return;
    }

    uint32_t workers = brain_worker_count();
    if (workers > QIHSE_CLUSTER_SLOT_COUNT) workers = QIHSE_CLUSTER_SLOT_COUNT;
    brain_scan_t serial; /* used only when the pool could not be created */
    brain_scan_t* scans;
    if (brain->pool) {
        /* Re-size first if the configured count changed since the last cycle:
         * a stale count is never used, and re-sizing happens between rounds. */
        brain_pool_resize(brain->pool, workers);
        scans = brain->pool->scans;
        workers = brain_pool_scan(brain->pool, owners);
    } else {
        /* No pool: triage the whole array on this thread rather than skip the
         * observation (the OBSERVE record then reports workers=1). */
        memset(&serial, 0, sizeof(serial));
        serial.owners = owners;
        serial.end = QIHSE_CLUSTER_SLOT_COUNT;
        scan_worker(&serial);
        scans = &serial;
        workers = 1u;
    }

    /* Merge chunk results in order; coalesce runs across chunk boundaries. */
    size_t total = 0;
    for (uint32_t i = 0; i < workers; i++) total += scans[i].count;
    brain_run_t* merged = malloc((total ? total : 1u) * sizeof(*merged));
    size_t merged_count = 0;
    if (merged) {
        for (uint32_t i = 0; i < workers; i++) {
            for (size_t r = 0; r < scans[i].count; r++) {
                brain_run_t* run = &scans[i].runs[r];
                if (merged_count && merged[merged_count - 1u].owner == run->owner &&
                    (uint32_t)merged[merged_count - 1u].end + 1u == run->start) {
                    merged[merged_count - 1u].end = run->end;
                } else {
                    merged[merged_count++] = *run;
                }
            }
        }
    }

    /* The triage time is measured here, exactly where it always was, so the
     * local record does not change when the federation publish is added. */
    uint64_t scan_us = brain_now_us() - t0;

    char detail[900];
    int off = snprintf(detail, sizeof(detail), "{\"nodes\":[");
    for (size_t i = 0; i < count && off > 0 && off < 800; i++) {
        char runs_buf[240];
        int roff = 0;
        uint32_t runs = 0;
        if (merged) {
            for (size_t r = 0; r < merged_count && roff < (int)(sizeof(runs_buf) - 32u); r++) {
                if (merged[r].owner != brain->node_buf[i].index) continue;
                roff += snprintf(runs_buf + roff, (size_t)(sizeof(runs_buf) - (size_t)roff),
                                 "%s%u-%u", runs ? "," : "", merged[r].start, merged[r].end);
                runs++;
            }
        }
        off += snprintf(detail + off, (size_t)(sizeof(detail) - (size_t)off),
                        "%s{\"id\":\"%.12s\",\"addr\":\"%s:%u\",\"healthy\":%s,\"self\":%s,\"slots\":\"%s\"}",
                        i ? "," : "", brain->node_buf[i].id, brain->node_buf[i].host,
                        brain->node_buf[i].port,
                        brain->node_buf[i].healthy ? "true" : "false",
                        brain->node_buf[i].index == local ? "true" : "false",
                        runs ? runs_buf : "");
    }
    snprintf(detail + off, (size_t)(sizeof(detail) - (size_t)off),
             "],\"scan_us\":%llu,\"workers\":%u}",
             (unsigned long long)scan_us, workers);
    brain_journal(brain, "OBSERVE", detail);

    /* Build this cycle's rule input, then publish it and read it back.  The
     * observation sequence starts at 1 so a pre-condition can never be a
     * zero-initialised struct. */
    if (count > 0 && brain->obs_local.runs) {
        brain->obs_seq++;
        brain->obs_local.seq = brain->obs_seq;
        brain->obs_local.scan_us = scan_us;
        brain->obs_local.workers = workers;
        brain->obs_local.local_index = local;
        brain->obs_local.node_count = count;
        brain->obs_local.run_count = merged ? merged_count : 0;
        for (size_t i = 0; i < count; i++) {
            const qihse_cluster_node_t* src = &brain->node_buf[i];
            brain_obs_node_t* dst = &brain->obs_local.nodes[i];
            memset(dst, 0, sizeof(*dst));
            dst->index = src->index;
            dst->role = (uint16_t)src->role;
            dst->primary_index = src->primary_index;
            dst->port = src->port;
            dst->bus_port = src->bus_port;
            if (src->healthy) dst->flags |= BRAIN_OBS_F_HEALTHY;
            if (src->index == local) dst->flags |= BRAIN_OBS_F_LOCAL;
            snprintf(dst->id, sizeof(dst->id), "%s", src->id);
            snprintf(dst->host, sizeof(dst->host), "%s", src->host);
        }
        for (size_t r = 0; r < brain->obs_local.run_count; r++) {
            brain->obs_local.runs[r].owner = merged[r].owner;
            brain->obs_local.runs[r].start = merged[r].start;
            brain->obs_local.runs[r].end = merged[r].end;
        }
        brain->obs_local.valid = true;

        /* The identity of the journal's resource id is the local node, which
         * is only known once an observation names it. */
        if (!brain->identity_set) {
            const brain_obs_node_t* self = brain_obs_find_node(&brain->obs_local, local);
            if (self && self->id[0]) {
                snprintf(brain->node_id, sizeof(brain->node_id), "%s", self->id);
                (void)qihse_uuid_from_seed(brain->node_id, strlen(brain->node_id),
                                           &brain->node_uuid);
                snprintf(brain->obs_resource, sizeof(brain->obs_resource), "%s%s",
                         QIHSE_BRAIN_FED_OBS_PREFIX, brain->node_id);
                brain->identity_set = true;
            }
        }

        size_t detail_len = strlen(detail);
        (void)brain_publish_observation(brain, detail, detail_len);
        if (!brain->obs.valid) {
            /* No federation journal, or the record could not be published and
             * read back: the rules still get an input so the brain can observe
             * and journal, but the pre-condition stays invalid and every
             * action is refused.  The decoded buffer is kept separate from the
             * local one so neither can alias the other. */
            brain_obs_run_t* runs = brain->obs.runs;
            brain->obs = brain->obs_local;
            brain->obs.runs = runs;
            if (runs && brain->obs.run_count)
                memcpy(runs, brain->obs_local.runs, brain->obs.run_count * sizeof(*runs));
            brain->obs.valid = true;
        }
    }

    for (uint32_t i = 0; i < workers; i++) brain_scan_clear(&scans[i]);
    free(merged);
    free(owners);
}

/* R3: isolated — no healthy peers. Journal once per incident; never act. */
static void brain_check_isolation(brain_t* brain, const brain_obs_t* obs) {
    size_t healthy_peers = 0;
    for (size_t i = 0; i < obs->node_count; i++)
        if (obs->nodes[i].index != obs->local_index &&
            (obs->nodes[i].flags & BRAIN_OBS_F_HEALTHY)) healthy_peers++;
    static bool isolated_reported = false;
    if (healthy_peers == 0 && obs->node_count > 1 && !isolated_reported) {
        brain_journal(brain, "ISOLATED", "{\"reason\":\"no healthy peers reachable\"}");
        brain_decision_record(brain, "isolated", "{\"reason\":\"no healthy peers reachable\"}",
                              false);
        isolated_reported = true;
    } else if (healthy_peers > 0 && isolated_reported) {
        brain_journal(brain, "RECONNECTED", "{\"reason\":\"healthy peer observed\"}");
        brain_decision_record(brain, "reconnected", "{\"reason\":\"healthy peer observed\"}",
                              false);
        isolated_reported = false;
    }
}

/* R2: asymmetry — a peer I consider failed. Quarantine policy only: acting on
 * a possibly-private partition is how clusters split brains, so this records
 * the decision and does not fence anything (ROADMAP W3.7). The policy
 * transition is a decision, so it is signed once per incident; the per-cycle
 * ASYMMETRY record stays unsigned and local-journal-only. */
static void brain_check_asymmetry(brain_t* brain, const brain_obs_t* obs) {
    uint16_t failed = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < obs->node_count; i++) {
        if (!(obs->nodes[i].flags & BRAIN_OBS_F_HEALTHY) && obs->nodes[i].host[0]) {
            failed = obs->nodes[i].index;
            char detail[512];
            snprintf(detail, sizeof(detail), "{\"peer\":\"%s:%u\",\"policy\":\"quarantine-noaction\"}",
                     obs->nodes[i].host, obs->nodes[i].port);
            brain_journal(brain, "ASYMMETRY", detail);
            if (brain->quarantine_peer != failed) {
                brain->quarantine_peer = failed;
                char evidence[320];
                snprintf(evidence, sizeof(evidence),
                         "{\"peer\":\"%.12s\",\"addr\":\"%s:%u\",\"policy\":\"quarantine-noaction\","
                         "\"fence\":false}",
                         obs->nodes[i].id, obs->nodes[i].host, obs->nodes[i].port);
                brain_decision_record(brain, "quarantine", evidence, true);
            }
            return;
        }
    }
    if (brain->quarantine_peer != QIHSE_CLUSTER_NODE_NONE) {
        uint16_t released = brain->quarantine_peer;
        const brain_obs_node_t* node = brain_obs_find_node(obs, released);
        const char* reason = node ? "peer healthy again" : "peer no longer observed";
        brain->quarantine_peer = QIHSE_CLUSTER_NODE_NONE;
        char evidence[160];
        snprintf(evidence, sizeof(evidence),
                 "{\"peer\":%u,\"reason\":\"%s\"}", (unsigned)released, reason);
        brain_decision_record(brain, "quarantine-release", evidence, true);
    }
}

/* ---- Actuation (R1 re-home + R4 rollback) -------------------------------
 * Every action goes through qihse_cluster_handoff_range() — the same audited
 * path CLUSTER MOVESLOTS uses — so the brain adds policy, never data-path
 * code. One action per cycle keeps the journal readable and the state
 * reversible. */

static bool brain_range_cooled(brain_t* brain, uint16_t first, uint16_t last, uint64_t now) {
    for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
        brain_cooldown_t* c = &brain->cooldowns[i];
        if (!c->used || c->first != first || c->last != last) continue;
        return now < c->until_ms;
    }
    return false;
}

static void brain_range_cooldown(brain_t* brain, uint16_t first, uint16_t last, uint64_t now) {
    brain_cooldown_t* slot = &brain->cooldowns[0];
    for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
        brain_cooldown_t* c = &brain->cooldowns[i];
        if (!c->used || (c->first == first && c->last == last)) {
            slot = c;
            break;
        }
    }
    slot->used = true;
    slot->first = first;
    slot->last = last;
    slot->until_ms = now + (uint64_t)brain->act_cooldown_seconds * 1000u;
}

/* Healthy primary to receive a re-homed range. Capability-aware placement
 * (ai_fabric.md §4): prefer nodes that advertise headroom via NODE_CAP
 * (free RAM minus a load penalty); nodes that have not advertised yet stay
 * eligible at the lowest score. Uptime breaks ties, so the choice stays
 * deterministic and journalable. Excludes the failed owner and the local
 * node (we are the actor). */
static uint16_t brain_pick_target(brain_t* brain, const brain_obs_t* obs,
                                  uint16_t failed_owner, uint16_t local) {
    uint64_t now = brain_now_ms();
    int64_t best_score = 0;
    uint64_t best_uptime = 0;
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < obs->node_count; i++) {
        const brain_obs_node_t* node = &obs->nodes[i];
        if (node->index == failed_owner || node->index == local) continue;
        if (!(node->flags & BRAIN_OBS_F_HEALTHY)) continue;
        if (node->role != QIHSE_CLUSTER_NODE_PRIMARY) continue;
        uint64_t first_seen = 0;
        uint64_t uptime = 0;
        if (brain->bus &&
            qihse_cluster_bus_peer_first_seen(brain->bus, node->index, &first_seen) &&
            first_seen > 0) {
            uptime = now > first_seen ? now - first_seen : 0;
        }
        int64_t score = 0;
        uint32_t free_ram = 0;
        uint16_t load = 0;
        if (brain->bus &&
            qihse_cluster_bus_node_caps(brain->bus, node->index, NULL, NULL, NULL,
                                        &free_ram, &load)) {
            score = (int64_t)free_ram - (int64_t)load * 64;
        }
        if (best == QIHSE_CLUSTER_NODE_NONE || score > best_score ||
            (score == best_score && uptime > best_uptime)) {
            best_score = score;
            best_uptime = uptime;
            best = node->index;
        }
    }
    return best;
}

/* Journal evidence for a placement decision: the capability profile the
 * choice was based on (or null when the node has not advertised). */
static void brain_caps_evidence(brain_t* brain, uint16_t index, char* out, size_t cap) {
    uint8_t isa = 0, npu = 0, gpu = 0;
    uint32_t free_ram = 0;
    uint16_t load = 0;
    if (brain->bus &&
        qihse_cluster_bus_node_caps(brain->bus, index, &isa, &npu, &gpu, &free_ram, &load)) {
        snprintf(out, cap,
                 "{\"isa\":%u,\"npu\":%u,\"gpu\":%u,\"free_ram_mb\":%u,\"load_pct\":%u}",
                 (unsigned)isa, (unsigned)npu, (unsigned)gpu, (unsigned)free_ram,
                 (unsigned)load);
    } else {
        snprintf(out, cap, "null");
    }
}

/* R1 — failed-owner re-home. Evidence-gated exactly like the failover
 * coordinator: if ANY peer recently observed the owner healthy this is an
 * asymmetric link, not a dead node, so the brain journals and waits.
 * Returns true when an action was taken. */
static bool brain_check_rehome(brain_t* brain, const brain_obs_t* obs) {
    if (!brain->act || !brain->server) return false;
    uint16_t local = obs->local_index;
    if (obs->node_count == 0 || local == QIHSE_CLUSTER_NODE_NONE) return false;

    const brain_obs_node_t* self = brain_obs_find_node(obs, local);
    if (!self || !(self->flags & BRAIN_OBS_F_HEALTHY)) return false;

    /* R3 guard: with no healthy peer there is nowhere safe to move a range. */
    size_t healthy_peers = 0;
    for (size_t i = 0; i < obs->node_count; i++)
        if (obs->nodes[i].index != local && (obs->nodes[i].flags & BRAIN_OBS_F_HEALTHY))
            healthy_peers++;
    if (healthy_peers == 0) return false;

    bool acted = false;
    uint64_t now = brain_now_ms();
    for (size_t r = 0; r < obs->run_count; r++) {
        const brain_obs_run_t* run = &obs->runs[r];
        uint16_t owner = run->owner;
        if (owner == QIHSE_CLUSTER_NODE_NONE || owner == local) continue;
        const brain_obs_node_t* owner_node = brain_obs_find_node(obs, owner);
        if (!owner_node) continue;
        if (owner_node->flags & BRAIN_OBS_F_HEALTHY) continue;
        if (brain_range_cooled(brain, run->start, run->end, now)) continue;
        /* Evidence gate: same rule the failover coordinator applies. The age
         * of the last healthy sighting is cited in the decision evidence, so
         * a replayed decision can be checked against the recorded input. */
        uint64_t last_healthy = 0;
        if (brain->bus) {
            last_healthy = qihse_cluster_bus_last_observed_healthy(brain->bus, owner);
            if (last_healthy > 0 && now - last_healthy < QIHSE_CLUSTER_BUS_TIMEOUT_MS) continue;
        }
        uint16_t target = brain_pick_target(brain, obs, owner, local);
        if (target == QIHSE_CLUSTER_NODE_NONE) continue;

        bool have_local_keys =
            qihse_cluster_range_has_local_keys(brain->server, run->start, run->end, 4096u);
        char evidence[384];
        snprintf(evidence, sizeof(evidence),
                 "{\"range\":\"%u-%u\",\"owner\":\"%.12s\",\"to\":%u,\"peer_healthy_age_ms\":%llu,"
                 "\"local_keys\":%s}",
                 run->start, run->end, owner_node->id, (unsigned)target,
                 last_healthy ? (unsigned long long)(now - last_healthy) : 0ULL,
                 have_local_keys ? "true" : "false");

        /* Only re-home a range this node can actually serve. */
        if (!have_local_keys) {
            char detail[192];
            snprintf(detail, sizeof(detail),
                     "{\"range\":\"%u-%u\",\"owner\":\"%.12s\",\"reason\":\"no-local-data\"}",
                     run->start, run->end, owner_node->id);
            brain_journal(brain, "REHOME_SKIP", detail);
            brain_decision_record(brain, "rehome-skip", detail, false);
            brain_range_cooldown(brain, run->start, run->end, now);
            continue;
        }

        /* No action without a journaled pre-condition. */
        if (!brain_gate(brain, "rehome", evidence)) return false;

        uint64_t moved = 0, collected = 0;
        char err[160];
        int rc = qihse_cluster_handoff_range(brain->server, run->start, run->end,
                                             target, &moved, &collected, err, sizeof(err));
        char caps[192];
        brain_caps_evidence(brain, target, caps, sizeof(caps));
        char detail[512];
        snprintf(detail, sizeof(detail),
                 "{\"range\":\"%u-%u\",\"from\":\"%.12s\",\"to\":%u,\"moved\":%llu,"
                 "\"collected\":%llu,\"ok\":%s,\"err\":\"%s\",\"target_caps\":%s}",
                 run->start, run->end, owner_node->id, (unsigned)target,
                 (unsigned long long)moved, (unsigned long long)collected,
                 rc == 0 ? "true" : "false", rc == 0 ? "" : err, caps);
        brain_journal(brain, "REHOME", detail);
        brain_decision_record(brain, "rehome", detail, true);
        brain_range_cooldown(brain, run->start, run->end, now);

        /* R4: evaluate this handoff once the rollback window closes. */
        for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
            if (brain->handoffs[i].active) continue;
            brain->handoffs[i].active = true;
            brain->handoffs[i].first = run->start;
            brain->handoffs[i].last = run->end;
            brain->handoffs[i].target = target;
            brain->handoffs[i].deadline_ms =
                now + (uint64_t)brain->rollback_window_seconds * 1000u;
            brain->handoffs[i].moved = moved;
            brain->handoffs[i].collected = collected;
            break;
        }
        acted = true;
        break; /* one action per cycle: predictable, journalable, reversible */
    }
    return acted;
}

/* R4 — rollback. A re-home is kept only if the range arrived completely and
 * the target is still healthy when the window closes; otherwise ownership
 * returns to the local node, which still holds whatever did not transfer. */
static void brain_check_rollback(brain_t* brain, const brain_obs_t* obs) {
    if (!brain->act || !obs->valid) return;
    uint64_t now = brain_now_ms();
    uint16_t local = obs->local_index;
    for (size_t i = 0; i < BRAIN_MAX_HANDOFFS; i++) {
        brain_handoff_t* h = &brain->handoffs[i];
        if (!h->active || now < h->deadline_ms) continue;
        const brain_obs_node_t* target_node = brain_obs_find_node(obs, h->target);
        bool target_ok = target_node && (target_node->flags & BRAIN_OBS_F_HEALTHY);
        const char* reason = NULL;
        if (h->moved < h->collected) reason = "transfer-incomplete";
        else if (!target_ok) reason = "target-unhealthy";
        char evidence[256];
        snprintf(evidence, sizeof(evidence),
                 "{\"range\":\"%u-%u\",\"target\":%u,\"moved\":%llu,\"collected\":%llu,"
                 "\"reason\":\"%s\"}",
                 h->first, h->last, (unsigned)h->target,
                 (unsigned long long)h->moved, (unsigned long long)h->collected,
                 reason ? reason : "complete");
        if (reason) {
            /* No action without a journaled pre-condition: a refused rollback
             * keeps the hand-off pending and is retried next cycle. */
            if (!brain_gate(brain, "rollback", evidence)) continue;
            if (qihse_cluster_set_range_owner(brain->server, h->first, h->last, local)) {
                char detail[256];
                snprintf(detail, sizeof(detail),
                         "{\"range\":\"%u-%u\",\"target\":%u,\"reason\":\"%s\",\"moved\":%llu,"
                         "\"collected\":%llu}",
                         h->first, h->last, (unsigned)h->target, reason,
                         (unsigned long long)h->moved, (unsigned long long)h->collected);
                brain_journal(brain, "ROLLBACK", detail);
                brain_decision_record(brain, "rollback", detail, true);
                brain_range_cooldown(brain, h->first, h->last, now);
            }
        } else {
            if (!brain_gate(brain, "rehome-confirm", evidence)) continue;
            char detail[192];
            snprintf(detail, sizeof(detail), "{\"range\":\"%u-%u\",\"target\":%u,\"moved\":%llu}",
                     h->first, h->last, (unsigned)h->target, (unsigned long long)h->moved);
            brain_journal(brain, "REHOME_CONFIRM", detail);
            brain_decision_record(brain, "rehome-confirm", detail, true);
        }
        h->active = false;
    }
}

/* R6 — stale-node prune. A node that has been unhealthy for the prune timeout
 * with no peer reporting it healthy is removed from this node's view, so
 * CLUSTER NODES stops accumulating corpses. Nodes that still own slots are
 * refused (failover / R1 must re-home them first). */
static void brain_check_prune(brain_t* brain, const brain_obs_t* obs) {
    if (!brain->act || !brain->prune_timeout_seconds) return;
    uint64_t now = brain_now_ms();
    for (size_t i = 0; i < obs->node_count; i++) {
        const brain_obs_node_t* node = &obs->nodes[i];
        uint16_t idx = node->index;
        if (idx >= BRAIN_MAX_NODES || idx == obs->local_index) continue;
        if (node->flags & BRAIN_OBS_F_HEALTHY) {
            brain->unhealthy_since[idx] = 0;
            continue;
        }
        if (brain->unhealthy_since[idx] == 0) {
            brain->unhealthy_since[idx] = now;
            continue;
        }
        if (now - brain->unhealthy_since[idx] <
            (uint64_t)brain->prune_timeout_seconds * 1000u) {
            continue;
        }
        /* Evidence gate: a peer still seeing it healthy means an asymmetric
         * link, not a dead node. */
        uint64_t last_healthy = 0;
        if (brain->bus) {
            last_healthy = qihse_cluster_bus_last_observed_healthy(brain->bus, idx);
            if (last_healthy > 0 && now - last_healthy < QIHSE_CLUSTER_BUS_TIMEOUT_MS) continue;
        }
        char evidence[320];
        snprintf(evidence, sizeof(evidence),
                 "{\"node\":\"%.12s\",\"addr\":\"%s:%u\",\"unhealthy_ms\":%llu,"
                 "\"peer_healthy_age_ms\":%llu}",
                 node->id, node->host, node->port,
                 (unsigned long long)(now - brain->unhealthy_since[idx]),
                 last_healthy ? (unsigned long long)(now - last_healthy) : 0ULL);
        /* No action without a journaled pre-condition. */
        if (!brain_gate(brain, "prune", evidence)) return;
        if (qihse_cluster_topology_remove_node(brain->topology, idx)) {
            char detail[224];
            snprintf(detail, sizeof(detail),
                     "{\"node\":\"%.12s\",\"addr\":\"%s:%u\",\"unhealthy_ms\":%llu}",
                     node->id, node->host, node->port,
                     (unsigned long long)(now - brain->unhealthy_since[idx]));
            brain_journal(brain, "PRUNE", detail);
            brain_decision_record(brain, "prune", detail, true);
            brain->unhealthy_since[idx] = 0;
        }
        /* EBUSY = still owns slots: expected until the range is re-homed. */
    }
}

/* R5 — rebalance on join. A healthy, slotless primary receives a proportional
 * share from the largest owner. Deterministic: only the largest owner acts
 * (tie-break by lowest index), so exactly one node moves the range. */
static void brain_check_rebalance(brain_t* brain, const brain_obs_t* obs) {
    if (!brain->act || !brain->rebalance_min_slots || obs->node_count < 2u) return;
    uint16_t local = obs->local_index;

    size_t healthy = 0;
    for (size_t i = 0; i < obs->node_count; i++)
        if (obs->nodes[i].flags & BRAIN_OBS_F_HEALTHY) healthy++;

    /* Largest owner among healthy nodes (deterministic tie-break by index). */
    size_t best_slots = 0;
    uint16_t best_owner = QIHSE_CLUSTER_NODE_NONE;
    size_t my_slots = 0;
    for (size_t i = 0; i < obs->node_count; i++) {
        if (!(obs->nodes[i].flags & BRAIN_OBS_F_HEALTHY)) continue;
        size_t owned = 0;
        for (size_t r = 0; r < obs->run_count; r++) {
            if (obs->runs[r].owner != obs->nodes[i].index) continue;
            owned += (size_t)(obs->runs[r].end - obs->runs[r].start) + 1u;
        }
        if (obs->nodes[i].index == local) my_slots = owned;
        if (best_owner == QIHSE_CLUSTER_NODE_NONE || owned > best_slots) {
            best_slots = owned;
            best_owner = obs->nodes[i].index;
        }
    }
    if (best_owner != local || my_slots < brain->rebalance_min_slots) return;

    for (size_t i = 0; i < obs->node_count; i++) {
        const brain_obs_node_t* joiner = &obs->nodes[i];
        if (joiner->index == local || !(joiner->flags & BRAIN_OBS_F_HEALTHY)) continue;
        if (joiner->role != QIHSE_CLUSTER_NODE_PRIMARY) continue;
        size_t owned = 0;
        for (size_t r = 0; r < obs->run_count; r++) {
            if (obs->runs[r].owner != joiner->index) continue;
            owned += (size_t)(obs->runs[r].end - obs->runs[r].start) + 1u;
        }
        if (owned != 0) continue; /* not a joiner */

        /* Donate the tail of our largest range; never more than half of it. */
        size_t pick_len = 0;
        uint16_t pick_end = 0;
        for (size_t r = 0; r < obs->run_count; r++) {
            if (obs->runs[r].owner != local) continue;
            size_t len = (size_t)(obs->runs[r].end - obs->runs[r].start) + 1u;
            if (len > pick_len) {
                pick_len = len;
                pick_end = obs->runs[r].end;
            }
        }
        size_t give = my_slots / (healthy ? healthy : 1u);
        if (give > pick_len / 2u) give = pick_len / 2u;
        if (give == 0) return;
        uint16_t first = (uint16_t)(pick_end - give + 1u);
        uint64_t now = brain_now_ms();
        if (brain_range_cooled(brain, first, pick_end, now)) return;

        char evidence[256];
        snprintf(evidence, sizeof(evidence),
                 "{\"range\":\"%u-%u\",\"to\":\"%.12s\",\"my_slots\":%llu,\"joiner_slots\":0}",
                 first, pick_end, joiner->id, (unsigned long long)my_slots);
        /* No action without a journaled pre-condition. */
        if (!brain_gate(brain, "rebalance", evidence)) return;

        uint64_t moved = 0, collected = 0;
        char err[160];
        int rc = qihse_cluster_handoff_range(brain->server, first, pick_end, joiner->index,
                                             &moved, &collected, err, sizeof(err));
        char detail[320];
        snprintf(detail, sizeof(detail),
                 "{\"range\":\"%u-%u\",\"to\":\"%.12s\",\"moved\":%llu,\"collected\":%llu,"
                 "\"ok\":%s,\"err\":\"%s\"}",
                 first, pick_end, joiner->id, (unsigned long long)moved,
                 (unsigned long long)collected, rc == 0 ? "true" : "false",
                 rc == 0 ? "" : err);
        brain_journal(brain, "REBALANCE", detail);
        brain_decision_record(brain, "rebalance", detail, true);
        brain_range_cooldown(brain, first, pick_end, now);
        return; /* one action per cycle */
    }
}

static void* brain_main(void* argument) {
    /* The thread owns its brain struct for its whole lifetime: stop() joins
     * the thread BEFORE freeing, so these accesses need no lock. */
    brain_t* brain = (brain_t*)argument;
    brain_journal(brain, "BRAIN_START", brain->act ? "{\"mode\":\"act\"}" : "{\"mode\":\"observe\"}");
    while (__atomic_load_n(&brain->running, __ATOMIC_ACQUIRE)) {
        /* ONE snapshot per cycle, published as an observation; the rules below
         * consume that record (through the watch) instead of polling the
         * topology again. */
        brain_observe(brain);
        if (brain->obs.valid) {
            brain_check_isolation(brain, &brain->obs);
            brain_check_asymmetry(brain, &brain->obs);
            brain_check_prune(brain, &brain->obs);
            /* R1 and R5 both move data: at most one of them acts per cycle. */
            if (!brain_check_rehome(brain, &brain->obs))
                brain_check_rebalance(brain, &brain->obs);
        }
        brain_check_rollback(brain, &brain->obs);
        uint32_t ms = brain->interval_seconds * 1000u;
        struct timespec ts = { (time_t)(ms / 1000u), (long)((ms % 1000u) * 1000000L) };
        nanosleep(&ts, NULL);
    }
    brain_journal(brain, "BRAIN_STOP", "{}");
    return NULL;
}

bool qihse_cluster_brain_start(const qihse_brain_config_t* config) {
    if (!config || !config->server || !config->journal_dir || !*config->journal_dir) return false;
    pthread_mutex_lock(&g_brain_lock);
    if (g_brain && g_brain->running) {
        pthread_mutex_unlock(&g_brain_lock);
        return true; /* already running */
    }
    brain_t* brain = calloc(1, sizeof(*brain));
    if (!brain) {
        pthread_mutex_unlock(&g_brain_lock);
        return false;
    }
    brain->server = config->server;
    brain->topology = qihse_resp_server_topology(config->server);
    snprintf(brain->journal_dir, sizeof(brain->journal_dir), "%s", config->journal_dir);
    if (config->dsa_key_path && *config->dsa_key_path)
        snprintf(brain->dsa_key_path, sizeof(brain->dsa_key_path), "%s", config->dsa_key_path);
    brain->interval_seconds = config->interval_seconds ? config->interval_seconds : 5u;
    brain->act = config->act;
    brain->act_cooldown_seconds = config->act_cooldown_seconds ? config->act_cooldown_seconds : 30u;
    brain->rollback_window_seconds =
        config->rollback_window_seconds ? config->rollback_window_seconds : 60u;
    brain->prune_timeout_seconds = config->prune_timeout_seconds;
    brain->rebalance_min_slots = config->rebalance_min_slots;
    brain->bus = qihse_resp_server_bus(config->server);
    brain->quarantine_peer = QIHSE_CLUSTER_NODE_NONE; /* no peer quarantined yet */
    brain->running = true;

    brain->journal = qihse_event_stream_create(brain->journal_dir);
    if (!brain->journal) brain->journal = qihse_event_stream_open(brain->journal_dir, QIHSE_ES_DURABILITY_NONE, false);
    if (!brain->journal || pthread_mutex_init(&brain->journal_lock, NULL) != 0) {
        if (brain->journal) qihse_event_stream_destroy(brain->journal);
        free(brain);
        pthread_mutex_unlock(&g_brain_lock);
        return false;
    }
    qihse_pqc_init_providers();

    /* Persistent scan pool: created once here and reused by every cycle, so
     * the observe pass no longer pays a thread spawn per chunk. A pool that
     * cannot be created is NOT fatal — brain_observe() then triages the slot
     * array serially on the brain thread. */
    brain->pool = brain_pool_create(brain_worker_count());

    /* Rule input buffers.  The node snapshot is ~36 KB and each run list is
     * ~96 KB, none of which may sit on the brain thread's stack (AGENTS.md,
     * "bounded stack frames"), so all of them are allocated once here and
     * reused every cycle.  An allocation failure is NOT fatal: the rules then
     * have no input, nothing acts, and the degraded mode is journaled. */
    brain->node_buf = calloc(BRAIN_MAX_NODES, sizeof(*brain->node_buf));
    brain->obs.runs = malloc(QIHSE_CLUSTER_SLOT_COUNT * sizeof(*brain->obs.runs));
    brain->obs_local.runs = malloc(QIHSE_CLUSTER_SLOT_COUNT * sizeof(*brain->obs_local.runs));
    if (!brain->node_buf || !brain->obs.runs || !brain->obs_local.runs)
        brain_journal(brain, "BRAIN_DEGRADED",
                      "{\"reason\":\"observation-buffers-unavailable\",\"act\":\"disabled\"}");

    /* Federation journal (W3.4).  The brain opens its own handle on the
     * configured directory (default: its own journal directory, topic
     * "federation") and watches its own observation prefix.  If it cannot be
     * opened the brain still observes and journals locally — federation is
     * never a prerequisite for local operation — but no rule may act, because
     * there is no journaled pre-condition to cite. */
    const char* fed_dir = (config->federation_journal_dir && *config->federation_journal_dir)
                              ? config->federation_journal_dir
                              : brain->journal_dir;
    snprintf(brain->fed_dir, sizeof(brain->fed_dir), "%s", fed_dir);
    brain->fed = qihse_federation_journal_open(brain->fed_dir, QIHSE_ES_DURABILITY_NONE);
    if (brain->fed) {
        qihse_federation_watch_config_t wcfg;
        memset(&wcfg, 0, sizeof(wcfg));
        snprintf(wcfg.prefix, sizeof(wcfg.prefix), "%s", QIHSE_BRAIN_FED_OBS_PREFIX);
        /* Resume at the end of the journal: only observations published after
         * this brain started are rule inputs. */
        wcfg.cursor = qihse_federation_journal_length(brain->fed);
        wcfg.backlog_limit = 64u;
        brain->watch = qihse_federation_watch_open(brain->fed, &wcfg);
        brain->obs_payload_cap = BRAIN_FED_OBS_MAX;
        brain->obs_payload = malloc(brain->obs_payload_cap);
        brain->decision_payload_cap = BRAIN_FED_DECISION_HEADER + BRAIN_FED_ACTION_MAX +
                                      BRAIN_FED_KEY_HANDLE_MAX + BRAIN_FED_EVIDENCE_MAX +
                                      BRAIN_FED_MAX_SIGNATURE;
        brain->decision_payload = malloc(brain->decision_payload_cap);
        if (!brain->watch || !brain->obs_payload || !brain->decision_payload)
            brain_journal(brain, "BRAIN_DEGRADED",
                          "{\"reason\":\"federation-journal-buffers-unavailable\","
                          "\"act\":\"disabled\"}");
    } else {
        brain_journal(brain, "BRAIN_DEGRADED",
                      "{\"reason\":\"federation-journal-unavailable\",\"act\":\"refused\"}");
    }

    /* Decision signing key: loaded once (a PEM parse per decision would be
     * waste), never journaled.  A key handle that cannot be loaded is not
     * fatal — decisions are then published unsigned — but the degradation is
     * journaled so it is never silent. */
    {
        const char* handle = (config->node_key_handle && *config->node_key_handle)
                                 ? config->node_key_handle
                                 : (config->dsa_key_path && *config->dsa_key_path
                                        ? config->dsa_key_path : NULL);
        if (handle && *handle) {
            void* pkey = qihse_federation_node_key_load(handle);
            uint8_t raw_public[QIHSE_FEDERATION_PUBKEY_MAX_BYTES];
            size_t raw_len = 0;
            if (pkey && qihse_federation_pkey_sig_alg(pkey, &brain->sign_alg) &&
                brain_public_key_of(pkey, brain->sign_alg, raw_public, sizeof(raw_public),
                                    &raw_len) &&
                brain_signer_selfcheck(pkey, brain->sign_alg, raw_public, raw_len) &&
                qihse_federation_node_fingerprint(raw_public, raw_len,
                                                  brain->sign_fingerprint)) {
                brain->sign_pkey = pkey;
                brain->have_signer = true;
                snprintf(brain->sign_key_handle, sizeof(brain->sign_key_handle), "%s", handle);
            } else {
                if (pkey) qihse_federation_node_key_free(pkey);
                brain_journal(brain, "BRAIN_DEGRADED",
                              "{\"reason\":\"decision-signing-key-unavailable\","
                              "\"decisions\":\"unsigned\"}");
            }
            OPENSSL_cleanse(raw_public, sizeof(raw_public));
        }
    }

    if (pthread_create(&brain->thread, NULL, brain_main, brain) != 0) {
        brain_pool_destroy(brain->pool);
        if (brain->sign_pkey) qihse_federation_node_key_free(brain->sign_pkey);
        if (brain->watch) qihse_federation_watch_destroy(brain->watch);
        if (brain->fed) qihse_federation_journal_destroy(brain->fed);
        free(brain->obs_payload);
        free(brain->decision_payload);
        free(brain->obs.runs);
        free(brain->obs_local.runs);
        free(brain->node_buf);
        qihse_event_stream_destroy(brain->journal);
        pthread_mutex_destroy(&brain->journal_lock);
        free(brain);
        pthread_mutex_unlock(&g_brain_lock);
        return false;
    }
    g_brain = brain;
    pthread_mutex_unlock(&g_brain_lock);
    return true;
}

void qihse_cluster_brain_stop(void) {
    pthread_mutex_lock(&g_brain_lock);
    brain_t* brain = g_brain;
    g_brain = NULL;
    pthread_mutex_unlock(&g_brain_lock);
    if (!brain) return;
    __atomic_store_n(&brain->running, false, __ATOMIC_RELEASE);
    pthread_join(brain->thread, NULL); /* thread finishes its cycle on its own struct */
    /* The brain thread is joined, so no round is in flight: this parks the
     * idle workers and joins them before the brain struct goes away. */
    brain_pool_destroy(brain->pool);
    /* The brain thread is joined, so the federation journal handle and its
     * watch are quiescent: safe to release them here. */
    if (brain->watch) qihse_federation_watch_destroy(brain->watch);
    if (brain->fed) qihse_federation_journal_destroy(brain->fed);
    if (brain->sign_pkey) qihse_federation_node_key_free(brain->sign_pkey);
    free(brain->obs_payload);
    free(brain->decision_payload);
    free(brain->obs.runs);
    free(brain->obs_local.runs);
    free(brain->node_buf); /* the rules ran on the joined thread only */
    qihse_event_stream_destroy(brain->journal);
    pthread_mutex_destroy(&brain->journal_lock);
    free(brain);
}
