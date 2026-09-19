/*
 * QIHSE fabric remote job dispatch.
 *
 * See include/qihse_fabric_dispatch.h for the design and for why the three
 * decisions are the ones implemented.  This file is the network-facing half of
 * ai_fabric.md build item 3.
 *
 * Structure:
 *   - bounded little-endian codec for the capability token;
 *   - the replay ledger;
 *   - qihse_fabric_token_check(): the one place a token is accepted;
 *   - the executor (run/fetch/serve over one framed request per connection);
 *   - the accept loop, which is the production caller the federation
 *     listener never had;
 *   - the submitter (mint, frame, send, read, retry policy).
 *
 * Every buffer in this file is either a fixed-size field of a record or a
 * caller-provided buffer whose capacity is a parameter.  No function here
 * copies before validating, and no function here allocates per peer beyond
 * one bounded heap block per request.
 */
#include "qihse_fabric_dispatch.h"

/* The token-derived context below is a deliberate, narrow use of the auth
 * layer's representation: QIHSE resolves a principal by pointer identity
 * against its node-local table, so a context built here is NON-AUTHORITATIVE
 * by construction and can never carry more authority than "unclassified".
 * That is exactly what a clearance-0/SCI-0 token claims, and it is why a
 * token above that is refused rather than mapped onto a local principal. */
#include "qihse_auth_internal.h"

#include "qihse_ai_memory.h"
#include "qihse_fabric_index.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

/* ── Wire constants ─────────────────────────────────────────────────────── */

#define FABRIC_FRAME_MAGIC 0x51464244u   /* "QFBD" */
#define FABRIC_FRAME_VERSION 1u
#define FABRIC_FRAME_RUN 1u
#define FABRIC_FRAME_FETCH 2u
#define FABRIC_FRAME_RESULT 0x81u
#define FABRIC_FRAME_REFUSED 0x82u
#define FABRIC_FRAME_HEADER_BYTES 16u

#define FABRIC_TOKEN_MAGIC 0x5146544Bu   /* "QFTK" */
#define FABRIC_TOKEN_VERSION 1u

#define FABRIC_RESPONSE_PREFIX "fabric-remote v1 "

/* The executor's records.  Deterministic keys: that is what makes a retry of
 * an idempotent job an OVERWRITE of the same record rather than a second one. */
#define FABRIC_REMOTE_RESULT_KEY_PREFIX "fabric:remote-result:"
#define FABRIC_REMOTE_ARTIFACT_KEY_PREFIX "fabric:ingest:r:"
#define FABRIC_REPLAY_KEY_PREFIX "fabric:replay:"

/* ── Bounded little-endian codec ────────────────────────────────────────── */

typedef struct {
    uint8_t* base;
    size_t cap;
    size_t len;
    bool overflow;
} fabric_writer_t;

static void fab_put_u16(fabric_writer_t* w, uint16_t v) {
    if (w->overflow || w->len + 2u > w->cap) { w->overflow = true; return; }
    w->base[w->len] = (uint8_t)(v & 0xFFu);
    w->base[w->len + 1u] = (uint8_t)((v >> 8) & 0xFFu);
    w->len += 2u;
}

static void fab_put_u32(fabric_writer_t* w, uint32_t v) {
    if (w->overflow || w->len + 4u > w->cap) { w->overflow = true; return; }
    for (size_t i = 0; i < 4u; i++) w->base[w->len + i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    w->len += 4u;
}

static void fab_put_u64(fabric_writer_t* w, uint64_t v) {
    if (w->overflow || w->len + 8u > w->cap) { w->overflow = true; return; }
    for (size_t i = 0; i < 8u; i++) w->base[w->len + i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    w->len += 8u;
}

static void fab_put_bytes(fabric_writer_t* w, const uint8_t* src, size_t len) {
    if (w->overflow || w->len + len > w->cap) { w->overflow = true; return; }
    if (len) memcpy(w->base + w->len, src, len);
    w->len += len;
}

typedef struct {
    const uint8_t* base;
    size_t cap;
    size_t off;
    bool underflow;
} fabric_reader_t;

static uint16_t fab_get_u16(fabric_reader_t* r) {
    if (r->underflow || r->off + 2u > r->cap) { r->underflow = true; return 0; }
    uint16_t v = (uint16_t)(r->base[r->off] | ((uint16_t)r->base[r->off + 1u] << 8));
    r->off += 2u;
    return v;
}

static uint32_t fab_get_u32(fabric_reader_t* r) {
    if (r->underflow || r->off + 4u > r->cap) { r->underflow = true; return 0; }
    uint32_t v = 0;
    for (size_t i = 0; i < 4u; i++) v |= (uint32_t)r->base[r->off + i] << (8u * i);
    r->off += 4u;
    return v;
}

static uint64_t fab_get_u64(fabric_reader_t* r) {
    if (r->underflow || r->off + 8u > r->cap) { r->underflow = true; return 0; }
    uint64_t v = 0;
    for (size_t i = 0; i < 8u; i++) v |= (uint64_t)r->base[r->off + i] << (8u * i);
    r->off += 8u;
    return v;
}

static const uint8_t* fab_get_bytes(fabric_reader_t* r, size_t len) {
    if (r->underflow || r->off + len > r->cap) { r->underflow = true; return NULL; }
    const uint8_t* p = r->base + r->off;
    r->off += len;
    return p;
}

static uint64_t fabric_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

/* ── Job types and idempotency declarations (decision 2) ────────────────── */

/*
 * The declarations are per TYPE because the two executors genuinely differ,
 * and the difference is not a guess: it is what the executor code does with
 * its result key.
 *
 *   keystone-ingest writes `fabric:ingest:<job-id>` (here, the remote form of
 *   that key, derived from the submitter node and the job id).  A second run
 *   writes the SAME key, so the observable state after a retry is the state
 *   after one run: idempotent, and a retry is permitted.
 *
 *   embed calls qihse_ai_memory_store(), which generates a NEW id per call.
 *   A retry therefore creates a SECOND memory, and the submitter cannot tell
 *   the difference from the first: NOT idempotent, so a retry is refused
 *   rather than attempted.
 */
static const qihse_fabric_jobtype_decl_t g_fabric_jobtypes[] = {
    { "keystone-ingest", QIHSE_FABRIC_JOB_KEYSTONE_INGEST, true,
      "writes the deterministic artifact key for the job binding; a retry "
      "overwrites it and leaves the same state as one run" },
    { "embed", QIHSE_FABRIC_JOB_EMBED, false,
      "qihse_ai_memory_store() generates a new memory id per call, so a retry "
      "creates a SECOND memory rather than replacing the first" }
};

const qihse_fabric_jobtype_decl_t* qihse_fabric_jobtype_lookup(const char* name) {
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof(g_fabric_jobtypes) / sizeof(g_fabric_jobtypes[0]); i++) {
        if (strcmp(g_fabric_jobtypes[i].name, name) == 0) return &g_fabric_jobtypes[i];
    }
    return NULL;
}

const qihse_fabric_jobtype_decl_t* qihse_fabric_jobtype_decl(qihse_fabric_job_t type) {
    for (size_t i = 0; i < sizeof(g_fabric_jobtypes) / sizeof(g_fabric_jobtypes[0]); i++) {
        if (g_fabric_jobtypes[i].type == type) return &g_fabric_jobtypes[i];
    }
    return NULL;
}

const char* qihse_fabric_jobtype_name(qihse_fabric_job_t type) {
    const qihse_fabric_jobtype_decl_t* d = qihse_fabric_jobtype_decl(type);
    return d ? d->name : "unknown";
}

bool qihse_fabric_jobtype_is_idempotent(qihse_fabric_job_t type) {
    const qihse_fabric_jobtype_decl_t* d = qihse_fabric_jobtype_decl(type);
    /* An unknown type is NOT idempotent: a type with no declaration has not
     * been reasoned about, and "not reasoned about" must not read as "safe to
     * repeat". */
    return d ? d->idempotent : false;
}

/* ── SHA-384 (payload binding and cache coherence) ──────────────────────── */

static bool fabric_sha384_raw(const void* data, size_t len, uint8_t out[48]) {
    if (!data && len > 0) return false;
    unsigned int digest_len = 0;
    if (EVP_Digest(data, len, out, &digest_len, EVP_sha384(), NULL) != 1 ||
        digest_len != 48u) {
        return false;
    }
    return true;
}

static void fabric_hex48(const uint8_t digest[48], char out_hex[97]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 48u; i++) {
        out_hex[i * 2u] = hex[digest[i] >> 4];
        out_hex[i * 2u + 1u] = hex[digest[i] & 0x0Fu];
    }
    out_hex[96] = '\0';
}

/* SHA-384 as 96 lowercase hex characters plus a terminator: 97 bytes.
 *
 * The capacity is an ARGUMENT, not a decoration. The previous signature was
 * `char out_hex[97]`, which in C is a pointer — the 97 was documentation the
 * function could not enforce, so a caller passing a shorter buffer got a
 * SILENT OVERFLOW of 96 bytes plus a terminator. A test asserted the short
 * buffer was rejected, which cannot be true of that signature; the assertion
 * was wrong and the signature was the reason.
 *
 * An insufficient capacity now returns false without writing, so the failure
 * is a refusal rather than memory corruption. */
bool qihse_fabric_sha384_hex(const void* data, size_t len, char* out_hex, size_t out_cap) {
    if (!out_hex || out_cap < 97u) return false;
    uint8_t digest[48];
    if (!fabric_sha384_raw(data, len, digest)) return false;
    fabric_hex48(digest, out_hex);
    return true;
}

/* ── Token codec ────────────────────────────────────────────────────────── */

bool qihse_fabric_token_encode_region(const qihse_fabric_token_t* token,
                                      uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!token || !out || out_cap < QIHSE_FABRIC_TOKEN_REGION_BYTES) return false;
    if (token->signature_len != 0 &&
        token->signature_len != qihse_sig_alg_signature_bytes(token->sig_alg)) return false;

    fabric_writer_t w = { out, out_cap, 0u, false };
    fab_put_u32(&w, FABRIC_TOKEN_MAGIC);
    fab_put_u16(&w, FABRIC_TOKEN_VERSION);
    fab_put_u16(&w, (uint16_t)token->sig_alg);
    fab_put_u16(&w, token->signature_len);
    fab_put_u16(&w, token->purpose);
    fab_put_u16(&w, (uint16_t)token->job_type);
    fab_put_u16(&w, 0u); /* reserved: must be zero, checked on parse */
    fab_put_u32(&w, token->scope);
    fab_put_u32(&w, token->principal_user_id);
    fab_put_u16(&w, token->clearance);
    fab_put_u16(&w, token->sci);
    fab_put_u32(&w, token->principal_tenant);
    fab_put_bytes(&w, token->submitter_node.bytes, QIHSE_UUID_BYTES);
    fab_put_bytes(&w, token->nonce.bytes, QIHSE_UUID_BYTES);
    fab_put_u64(&w, token->job_id);
    fab_put_u64(&w, token->issued_ms);
    fab_put_u64(&w, token->expires_ms);
    fab_put_u32(&w, token->payload_len);
    fab_put_bytes(&w, token->payload_digest, sizeof(token->payload_digest));
    if (w.overflow || w.len != QIHSE_FABRIC_TOKEN_REGION_BYTES) return false;
    if (out_len) *out_len = w.len;
    return true;
}

bool qihse_fabric_token_parse(const uint8_t* blob, size_t blob_len,
                              qihse_fabric_token_t* out,
                              size_t* out_region_len, size_t* out_total_len) {
    if (!blob || !out || blob_len < QIHSE_FABRIC_TOKEN_REGION_BYTES) return false;

    fabric_reader_t r = { blob, blob_len, 0u, false };
    uint32_t magic = fab_get_u32(&r);
    uint16_t version = fab_get_u16(&r);
    uint16_t sig_alg_raw = fab_get_u16(&r);
    uint16_t signature_len = fab_get_u16(&r);
    uint16_t purpose = fab_get_u16(&r);
    uint16_t job_type = fab_get_u16(&r);
    uint16_t reserved = fab_get_u16(&r);
    uint32_t scope = fab_get_u32(&r);
    uint32_t principal_user_id = fab_get_u32(&r);
    uint16_t clearance = fab_get_u16(&r);
    uint16_t sci = fab_get_u16(&r);
    uint32_t tenant = fab_get_u32(&r);
    const uint8_t* submitter = fab_get_bytes(&r, QIHSE_UUID_BYTES);
    const uint8_t* nonce = fab_get_bytes(&r, QIHSE_UUID_BYTES);
    uint64_t job_id = fab_get_u64(&r);
    uint64_t issued_ms = fab_get_u64(&r);
    uint64_t expires_ms = fab_get_u64(&r);
    uint32_t payload_len = fab_get_u32(&r);
    const uint8_t* digest = fab_get_bytes(&r, 48u);
    if (r.underflow || !submitter || !nonce || !digest) return false;
    if (r.off != QIHSE_FABRIC_TOKEN_REGION_BYTES) return false;

    if (magic != FABRIC_TOKEN_MAGIC || version != FABRIC_TOKEN_VERSION) return false;
    if (reserved != 0u) return false;
    if (sig_alg_raw > (uint16_t)QIHSE_SIG_ML_DSA_87) return false;
    qihse_sig_alg_t sig_alg = (qihse_sig_alg_t)sig_alg_raw;
    /* The declared signature length must be exactly the algorithm's fixed
     * size: a truncated or padded signature never reaches the verifier. */
    if (signature_len != qihse_sig_alg_signature_bytes(sig_alg)) return false;
    if (signature_len == 0) return false;
    if (purpose != QIHSE_FABRIC_TOKEN_PURPOSE_RUN &&
        purpose != QIHSE_FABRIC_TOKEN_PURPOSE_FETCH) return false;
    if (job_type != (uint16_t)QIHSE_FABRIC_JOB_EMBED &&
        job_type != (uint16_t)QIHSE_FABRIC_JOB_KEYSTONE_INGEST) return false;
    if (payload_len > QIHSE_FABRIC_MAX_PAYLOAD) return false;
    if (issued_ms == 0u || expires_ms <= issued_ms) return false;
    if (expires_ms - issued_ms > QIHSE_FABRIC_TOKEN_MAX_TTL_MS) return false;

    size_t region = QIHSE_FABRIC_TOKEN_REGION_BYTES;
    if (blob_len < region + (size_t)signature_len) return false;

    memset(out, 0, sizeof(*out));
    out->purpose = purpose;
    out->job_type = (qihse_fabric_job_t)job_type;
    out->scope = scope;
    out->principal_user_id = principal_user_id;
    out->clearance = clearance;
    out->sci = sci;
    out->principal_tenant = tenant;
    memcpy(out->submitter_node.bytes, submitter, QIHSE_UUID_BYTES);
    memcpy(out->nonce.bytes, nonce, QIHSE_UUID_BYTES);
    out->job_id = job_id;
    out->issued_ms = issued_ms;
    out->expires_ms = expires_ms;
    out->payload_len = payload_len;
    memcpy(out->payload_digest, digest, sizeof(out->payload_digest));
    out->sig_alg = sig_alg;
    out->signature_len = signature_len;

    if (out_region_len) *out_region_len = region;
    if (out_total_len) *out_total_len = region + (size_t)signature_len;
    return true;
}

bool qihse_fabric_token_mint(void* pkey, qihse_fabric_token_t* token,
                             uint8_t* out_blob, size_t out_cap, size_t* out_len) {
    if (!pkey || !token || !out_blob) return false;

    qihse_sig_alg_t alg = QIHSE_SIG_ALG_DEFAULT;
    if (!qihse_federation_pkey_sig_alg(pkey, &alg)) return false;
    size_t sig_bytes = qihse_sig_alg_signature_bytes(alg);
    if (sig_bytes == 0) return false;
    if (out_cap < QIHSE_FABRIC_TOKEN_REGION_BYTES + sig_bytes) return false;

    token->sig_alg = alg;
    token->signature_len = (uint16_t)sig_bytes;

    size_t region = 0;
    if (!qihse_fabric_token_encode_region(token, out_blob, out_cap, &region)) return false;

    size_t sig_len = sig_bytes;
    if (!qihse_federation_sign(pkey, out_blob, region, out_blob + region, &sig_len)) {
        /* An unsigned capability must never be emitted: a token whose
         * signature field is absent would have to be accepted unverified,
         * which is the whole thing this design exists to prevent. */
        memset(out_blob, 0, region + sig_bytes);
        return false;
    }
    if (sig_len != sig_bytes) { memset(out_blob, 0, region + sig_bytes); return false; }
    if (out_len) *out_len = region + sig_len;
    return true;
}

/* ── Replay ledger ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t nonce[QIHSE_UUID_BYTES];
    uint16_t purpose;
    uint64_t expires_ms;
} fabric_replay_entry_t;

static pthread_mutex_t g_fabric_replay_lock = PTHREAD_MUTEX_INITIALIZER;
static fabric_replay_entry_t g_fabric_replay[QIHSE_FABRIC_REPLAY_MAX];
static size_t g_fabric_replay_count = 0;

static void fabric_replay_key(const uint8_t nonce[QIHSE_UUID_BYTES], uint16_t purpose,
                              char* out, size_t out_cap) {
    static const char hex[] = "0123456789abcdef";
    size_t off = 0;
    int n = snprintf(out, out_cap, "%s", FABRIC_REPLAY_KEY_PREFIX);
    if (n <= 0 || (size_t)n >= out_cap) { out[0] = '\0'; return; }
    off = (size_t)n;
    for (size_t i = 0; i < QIHSE_UUID_BYTES && off + 2u < out_cap; i++) {
        out[off++] = hex[nonce[i] >> 4];
        out[off++] = hex[nonce[i] & 0x0Fu];
    }
    if (off + 8u < out_cap) {
        int m = snprintf(out + off, out_cap - off, ":%u", (unsigned)purpose);
        if (m <= 0) { out[0] = '\0'; return; }
        off += (size_t)m;
    }
    out[off < out_cap ? off : out_cap - 1u] = '\0';
}

/* Drop entries whose token has expired.  Bounded by the ledger cap, and it
 * runs before every insert, so the ledger holds only live nonces. */
static void fabric_replay_prune_locked(qihse_kv_store_t* store, qihse_user_t* user,
                                      uint64_t now_ms) {
    size_t keep = 0;
    for (size_t i = 0; i < g_fabric_replay_count; i++) {
        if (g_fabric_replay[i].expires_ms > now_ms) {
            if (keep != i) g_fabric_replay[keep] = g_fabric_replay[i];
            keep++;
            continue;
        }
        char key[128];
        fabric_replay_key(g_fabric_replay[i].nonce, g_fabric_replay[i].purpose, key, sizeof(key));
        if (key[0] != '\0' && store) (void)qihse_kv_del_user(store, key, user);
    }
    g_fabric_replay_count = keep;
}

/*
 * Consume a nonce.  Returns false when it was already used (a replay), when
 * the ledger is full of live nonces (fail closed: evicting a live nonce would
 * reopen the window it exists to close), or when the ledger record could not
 * be written durably.
 *
 * The KV record makes the window survive a restart; the in-process table
 * makes the check cheap and gives the prune something to walk.
 */
static bool fabric_replay_consume(void* store_void, qihse_user_t* user,
                                  const uint8_t nonce[QIHSE_UUID_BYTES],
                                  uint16_t purpose, uint64_t expires_ms,
                                  uint64_t now_ms) {
    qihse_kv_store_t* store = (qihse_kv_store_t*)store_void;
    char key[128];
    fabric_replay_key(nonce, purpose, key, sizeof(key));
    if (key[0] == '\0') return false;

    pthread_mutex_lock(&g_fabric_replay_lock);
    fabric_replay_prune_locked(store, user, now_ms);

    bool replay = false;
    for (size_t i = 0; i < g_fabric_replay_count; i++) {
        if (g_fabric_replay[i].purpose == purpose &&
            memcmp(g_fabric_replay[i].nonce, nonce, QIHSE_UUID_BYTES) == 0) {
            replay = true;
            break;
        }
    }
    if (replay) { pthread_mutex_unlock(&g_fabric_replay_lock); return false; }

    /* Durable check: a nonce consumed before a restart must still be refused. */
    char* existing = store ? qihse_kv_get_user(store, key, user) : NULL;
    if (existing) {
        free(existing);
        pthread_mutex_unlock(&g_fabric_replay_lock);
        return false;
    }
    if (g_fabric_replay_count >= QIHSE_FABRIC_REPLAY_MAX) {
        pthread_mutex_unlock(&g_fabric_replay_lock);
        return false;
    }

    char value[32];
    snprintf(value, sizeof(value), "%llu", (unsigned long long)expires_ms);
    /* The ledger record carries no job content and is written unclassified;
     * it is metadata about a token, not data the token protects. */
    bool stored = store ? qihse_kv_set_user(store, key, value, 0, 0, user) : false;
    if (!stored) {
        pthread_mutex_unlock(&g_fabric_replay_lock);
        return false;
    }
    g_fabric_replay[g_fabric_replay_count].purpose = purpose;
    g_fabric_replay[g_fabric_replay_count].expires_ms = expires_ms;
    memcpy(g_fabric_replay[g_fabric_replay_count].nonce, nonce, QIHSE_UUID_BYTES);
    g_fabric_replay_count++;
    pthread_mutex_unlock(&g_fabric_replay_lock);
    return true;
}

/* ── Token verdict names ────────────────────────────────────────────────── */

const char* qihse_fabric_token_verdict_name(qihse_fabric_token_verdict_t v) {
    switch (v) {
        case QIHSE_FABRIC_TOKEN_OK:              return "ok";
        case QIHSE_FABRIC_TOKEN_MALFORMED:       return "malformed-token";
        case QIHSE_FABRIC_TOKEN_BAD_SIGNATURE:   return "bad-signature";
        case QIHSE_FABRIC_TOKEN_UNKNOWN_SUBMITTER: return "unknown-submitter-node";
        case QIHSE_FABRIC_TOKEN_NOT_APPROVED:    return "submitter-not-approved";
        case QIHSE_FABRIC_TOKEN_NODE_MISMATCH:   return "node-not-the-tls-peer";
        case QIHSE_FABRIC_TOKEN_ISSUED_IN_FUTURE:   return "token-issued-in-future";
        case QIHSE_FABRIC_TOKEN_EXPIRED:         return "token-expired";
        case QIHSE_FABRIC_TOKEN_TTL_TOO_LONG:    return "token-lifetime-too-long";
        case QIHSE_FABRIC_TOKEN_SCOPE_REFUSED:   return "scope-refused";
        case QIHSE_FABRIC_TOKEN_WRONG_PURPOSE:   return "wrong-purpose";
        case QIHSE_FABRIC_TOKEN_JOB_MISMATCH:    return "job-binding-mismatch";
        case QIHSE_FABRIC_TOKEN_REPLAY:          return "token-replayed";
        case QIHSE_FABRIC_TOKEN_NO_CONTEXT:      return "no-local-context";
        case QIHSE_FABRIC_TOKEN_STORE_ERROR:     return "token-store-error";
    }
    return "unknown-verdict";
}

/* ── Token verification (the one place a token is accepted) ─────────────── */

qihse_fabric_token_verdict_t qihse_fabric_token_check(
    void* store_void, qihse_user_t* local_user,
    const uint8_t* blob, size_t blob_len,
    const qihse_fabric_token_check_t* check,
    qihse_fabric_token_t* out_claims) {
    if (!check) return QIHSE_FABRIC_TOKEN_MALFORMED;
    /* NULL is never an authorization bypass: every read this performs (the
     * submitter's identity record, the replay ledger) needs an explicit
     * authenticated context, so a caller that has none is refused. */
    if (!store_void || !local_user) return QIHSE_FABRIC_TOKEN_NO_CONTEXT;
    if (!blob || blob_len == 0) return QIHSE_FABRIC_TOKEN_MALFORMED;

    qihse_fabric_token_t claims;
    size_t region = 0, total = 0;
    if (!qihse_fabric_token_parse(blob, blob_len, &claims, &region, &total)) {
        return QIHSE_FABRIC_TOKEN_MALFORMED;
    }
    if (total > blob_len) return QIHSE_FABRIC_TOKEN_MALFORMED;

    /* 2. The submitter must be an enrolled node, APPROVED right now.  The
     * record is re-read here rather than cached: a revocation between the
     * handshake and this call must take effect. */
    qihse_federation_node_identity_t* node =
        (qihse_federation_node_identity_t*)calloc(1u, sizeof(*node));
    if (!node) return QIHSE_FABRIC_TOKEN_STORE_ERROR;
    qihse_fabric_token_verdict_t verdict = QIHSE_FABRIC_TOKEN_OK;

    if (!qihse_federation_node_lookup(store_void, local_user, &claims.submitter_node, node)) {
        verdict = QIHSE_FABRIC_TOKEN_UNKNOWN_SUBMITTER;
        goto done;
    }
    if (node->trust != QIHSE_TRUST_APPROVED) {
        verdict = QIHSE_FABRIC_TOKEN_NOT_APPROVED;
        goto done;
    }

    /* 3. The signature must verify against THAT node's enrolled public key.
     * The token's own key material is never consulted, so a token cannot
     * nominate the key that validates it. */
    if (node->public_key_len == 0 ||
        node->public_key_len != qihse_sig_alg_public_key_bytes(claims.sig_alg)) {
        verdict = QIHSE_FABRIC_TOKEN_BAD_SIGNATURE;
        goto done;
    }
    if (!qihse_federation_verify(claims.sig_alg, node->public_key, node->public_key_len,
                                 blob, region, blob + region, claims.signature_len)) {
        verdict = QIHSE_FABRIC_TOKEN_BAD_SIGNATURE;
        goto done;
    }

    /* 4. The token must name the peer that is holding this channel.  A token
     * captured off the wire is therefore useless without the issuing node's
     * private key, because the capturer cannot present that node's channel. */
    if (!qihse_uuid_equal(&claims.submitter_node, &check->channel_peer)) {
        verdict = QIHSE_FABRIC_TOKEN_NODE_MISMATCH;
        goto done;
    }

    /* 5. Lifetime.  A clock that disagrees is refused rather than tolerated:
     * a token from the future would extend the replay window. */
    uint64_t now = check->now_ms ? check->now_ms : fabric_now_ms();
    /* ISSUED IN THE FUTURE, refused. This is NOT a `not_before`: the token
     * format has no such field. The rule is that a token whose issued time is
     * ahead of us beyond the clock skew is refused, because its expiry
     * (issued + TTL) is ALSO ahead — so accepting it would give it a longer
     * life than the TTL allows, measured from our clock.
     *
     * The name was previously NOT_YET_VALID, which described a concept the
     * format cannot express and invited exactly the wrong reading: a test
     * asserted that a token checked AFTER its issue time should be refused
     * for being "not yet valid", which is not a rule this code has. A name
     * that describes a feature you do not have is how a reviewer tests the
     * wrong contract. */
    if (claims.issued_ms > now + QIHSE_FABRIC_TOKEN_CLOCK_SKEW_MS) {
        verdict = QIHSE_FABRIC_TOKEN_ISSUED_IN_FUTURE;
        goto done;
    }
    if (claims.expires_ms <= now) {
        verdict = QIHSE_FABRIC_TOKEN_EXPIRED;
        goto done;
    }
    if (claims.expires_ms - claims.issued_ms > QIHSE_FABRIC_TOKEN_MAX_TTL_MS) {
        verdict = QIHSE_FABRIC_TOKEN_TTL_TOO_LONG;
        goto done;
    }

    /* 6. Scope: the required scope must be present, and the whole asserted
     * scope must be a subset of what the submitter NODE was enrolled with.  A
     * node cannot mint a token claiming authority it was never granted. */
    if ((claims.scope & check->required_scope) != check->required_scope) {
        verdict = QIHSE_FABRIC_TOKEN_SCOPE_REFUSED;
        goto done;
    }
    if (claims.scope == QIHSE_SCOPE_NONE || (node->scopes & claims.scope) != claims.scope) {
        verdict = QIHSE_FABRIC_TOKEN_SCOPE_REFUSED;
        goto done;
    }

    /* 7. Binding: purpose, job id, job type and payload digest.  A token is a
     * capability for ONE job, not a bearer credential for a node. */
    if (claims.purpose != check->expect_purpose) {
        verdict = QIHSE_FABRIC_TOKEN_WRONG_PURPOSE;
        goto done;
    }
    if (claims.job_type != check->expect_job_type || claims.job_id != check->expect_job_id) {
        verdict = QIHSE_FABRIC_TOKEN_JOB_MISMATCH;
        goto done;
    }
    if (claims.payload_len != check->payload_len) {
        verdict = QIHSE_FABRIC_TOKEN_JOB_MISMATCH;
        goto done;
    }
    {
        char digest[97];
        char declared[97];
        if (!qihse_fabric_sha384_hex(check->payload, check->payload_len, digest, sizeof(digest))) {
            verdict = QIHSE_FABRIC_TOKEN_JOB_MISMATCH;
            goto done;
        }
        fabric_hex48(claims.payload_digest, declared);
        if (strcmp(digest, declared) != 0) {
            verdict = QIHSE_FABRIC_TOKEN_JOB_MISMATCH;
            goto done;
        }
    }

    /* 8. Replay: last, so an unverifiable token never writes to the ledger. */
    if (check->consume) {
        if (!fabric_replay_consume(store_void, local_user, claims.nonce.bytes, claims.purpose,
                                   claims.expires_ms, now)) {
            verdict = QIHSE_FABRIC_TOKEN_REPLAY;
            goto done;
        }
    }

    if (out_claims) *out_claims = claims;

done:
    free(node);
    return verdict;
}

/* ── Response bodies ────────────────────────────────────────────────────── */

/* Format the one-line status header.  `payload` is appended verbatim after a
 * newline, and `digest` always describes exactly those payload bytes (it is
 * SHA-384 of the empty string when there are none).  `record_digest`, when
 * given, is the digest of the RECORD the executor wrote: it lets the
 * submitter check that the record it later pulls is the record it was told
 * about. */
static bool fabric_response_format(const char* status, qihse_fabric_job_t job_type,
                                   uint64_t job_id, uint64_t gen,
                                   uint16_t clearance, uint16_t sci,
                                   const qihse_uuid_t* node, const char* result_ref,
                                   const char* reason,
                                   const char* payload, size_t payload_len,
                                   const char* record_digest,
                                   char* out, size_t out_cap, size_t* out_len) {
    if (out_len) *out_len = 0u;
    char digest[97];
    if (!qihse_fabric_sha384_hex(payload, payload_len, digest, sizeof(digest))) return false;

    char node_str[QIHSE_UUID_STR_LEN + 1u];
    if (node) {
        if (!qihse_uuid_format(node, node_str)) node_str[0] = '\0';
    } else {
        node_str[0] = '\0';
    }

    int n = snprintf(out, out_cap,
                     "%sstatus=%s type=%s job=%llu gen=%llu cls=%u sci=%u node=%s "
                     "result=%s digest=%s bytes=%llu reason=%s record_digest=%s\n",
                     FABRIC_RESPONSE_PREFIX, status, qihse_fabric_jobtype_name(job_type),
                     (unsigned long long)job_id, (unsigned long long)gen,
                     (unsigned)clearance, (unsigned)sci, node_str,
                     result_ref ? result_ref : "-", digest,
                     (unsigned long long)payload_len, reason ? reason : "-",
                     record_digest ? record_digest : "-");
    if (n <= 0 || (size_t)n >= out_cap) return false;
    size_t header = (size_t)n;
    if (header + payload_len >= out_cap) return false;
    if (payload_len) memcpy(out + header, payload, payload_len);
    out[header + payload_len] = '\0';
    if (out_len) *out_len = header + payload_len;
    return true;
}

static bool fabric_response_is_status(const char* status, const char* want) {
    return status && want && strcmp(status, want) == 0;
}

bool qihse_fabric_response_parse(const char* body, size_t body_len,
                                 qihse_fabric_response_t* out) {
    if (!body || !out || body_len == 0) return false;
    if (body_len < strlen(FABRIC_RESPONSE_PREFIX)) return false;
    if (strncmp(body, FABRIC_RESPONSE_PREFIX, strlen(FABRIC_RESPONSE_PREFIX)) != 0) return false;

    /* The header is one line; the payload (if any) follows it.  Find the
     * newline within the body, never beyond it. */
    size_t header_end = body_len;
    for (size_t i = 0; i < body_len; i++) {
        if (body[i] == '\n') { header_end = i; break; }
    }
    if (header_end >= body_len) return false;   /* no newline: not a header line */

    memset(out, 0, sizeof(*out));
    out->payload_offset = header_end + 1u;

    const char* p = body + strlen(FABRIC_RESPONSE_PREFIX);
    const char* end = body + header_end;
    while (p < end) {
        const char* sp = p;
        while (sp < end && *sp != ' ') sp++;
        size_t tok_len = (size_t)(sp - p);
        if (tok_len > 0) {
            const char* eq = memchr(p, '=', tok_len);
            if (!eq) return false;
            size_t key_len = (size_t)(eq - p);
            const char* val = eq + 1;
            size_t val_len = tok_len - key_len - 1u;
            char val_buf[256];
            if (val_len >= sizeof(val_buf)) return false;
            memcpy(val_buf, val, val_len);
            val_buf[val_len] = '\0';

            if (key_len == 6u && strncmp(p, "status", 6u) == 0) {
                if (val_len >= sizeof(out->status)) return false;
                memcpy(out->status, val_buf, val_len + 1u);
            } else if (key_len == 4u && strncmp(p, "type", 4u) == 0) {
                if (val_len >= sizeof(out->type)) return false;
                memcpy(out->type, val_buf, val_len + 1u);
            } else if (key_len == 6u && strncmp(p, "reason", 6u) == 0) {
                if (val_len >= sizeof(out->reason)) return false;
                memcpy(out->reason, val_buf, val_len + 1u);
            } else if (key_len == 6u && strncmp(p, "result", 6u) == 0) {
                if (val_len >= sizeof(out->result)) return false;
                memcpy(out->result, val_buf, val_len + 1u);
            } else if (key_len == 3u && strncmp(p, "job", 3u) == 0) {
                out->job_id = strtoull(val_buf, NULL, 10);
            } else if (key_len == 3u && strncmp(p, "gen", 3u) == 0) {
                out->gen = strtoull(val_buf, NULL, 10);
            } else if (key_len == 3u && strncmp(p, "cls", 3u) == 0) {
                out->clearance = (uint16_t)strtoul(val_buf, NULL, 10);
            } else if (key_len == 3u && strncmp(p, "sci", 3u) == 0) {
                out->sci = (uint16_t)strtoul(val_buf, NULL, 10);
            } else if (key_len == 6u && strncmp(p, "digest", 6u) == 0) {
                if (val_len >= sizeof(out->digest)) return false;
                memcpy(out->digest, val_buf, val_len + 1u);
            } else if (key_len == 13u && strncmp(p, "record_digest", 13u) == 0) {
                if (val_len >= sizeof(out->record_digest)) return false;
                memcpy(out->record_digest, val_buf, val_len + 1u);
            } else if (key_len == 5u && strncmp(p, "bytes", 5u) == 0) {
                out->payload_len = strtoull(val_buf, NULL, 10);
            }
            /* Unknown fields are ignored rather than refused: a newer
             * executor may add one, and refusing would break the older
             * submitter for no security gain. */
        }
        p = (sp < end) ? sp + 1 : end;
    }

    /* The declared payload length must describe the bytes that are actually
     * present.  A record whose header disagrees with its body is refused
     * rather than truncated to fit. */
    size_t available = body_len - out->payload_offset;
    if (out->payload_len != (uint64_t)available) return false;
    if (out->status[0] == '\0') return false;
    return true;
}

/* ── Executor: job execution ────────────────────────────────────────────── */

/* A context that carries the VERIFIED remote claims and nothing else.
 *
 * It is deliberately non-authoritative: QIHSE's authorization resolves a
 * principal by pointer identity against the node-local table, so this
 * structure can never grant more than unclassified access.  It is therefore a
 * faithful representation of a clearance-0/SCI-0 principal and of no other,
 * which is exactly the rule qihse_fabric_executor_run() enforces. */
static void fabric_remote_context(qihse_user_t* out, const qihse_fabric_token_t* claims) {
    memset(out, 0, sizeof(*out));
    out->user_id = claims->principal_user_id;
    out->role = 0;                       /* no role: role is not a claim */
    out->classification_level = claims->clearance;
    out->sci_compartments = claims->sci;
    out->tenant_id = claims->principal_tenant;
    snprintf(out->username, sizeof(out->username), "fabric-remote:%u",
             (unsigned)claims->principal_user_id);
}

static bool fabric_remote_result_key(const qihse_uuid_t* submitter_node,
                                     uint64_t job_id, char* out, size_t out_cap,
                                     const char* prefix) {
    if (!submitter_node || !out || out_cap == 0) return false;
    static const char hex[] = "0123456789abcdef";
    char id[QIHSE_UUID_BYTES * 2u + 1u];
    for (size_t i = 0; i < QIHSE_UUID_BYTES; i++) {
        id[i * 2u] = hex[submitter_node->bytes[i] >> 4];
        id[i * 2u + 1u] = hex[submitter_node->bytes[i] & 0x0Fu];
    }
    id[QIHSE_UUID_BYTES * 2u] = '\0';
    int n = snprintf(out, out_cap, "%s%s:%llu", prefix, id, (unsigned long long)job_id);
    return n > 0 && (size_t)n < out_cap;
}

bool qihse_fabric_remote_result_key(const qihse_uuid_t* submitter_node,
                                    uint64_t job_id, char* out, size_t out_cap) {
    return fabric_remote_result_key(submitter_node, job_id, out, out_cap,
                                    FABRIC_REMOTE_RESULT_KEY_PREFIX);
}

bool qihse_fabric_remote_artifact_key(const qihse_uuid_t* submitter_node,
                                      uint64_t job_id, char* out, size_t out_cap) {
    return fabric_remote_result_key(submitter_node, job_id, out, out_cap,
                                    FABRIC_REMOTE_ARTIFACT_KEY_PREFIX);
}

/* Read the previous record's generation so a retry is observably a new
 * generation of the same job rather than a silent overwrite.  The read uses
 * the executor's explicit context: this is the executor's own store, and the
 * value read is its own record's metadata. */
static uint64_t fabric_previous_generation(qihse_kv_store_t* store, qihse_user_t* user,
                                           const char* key) {
    if (!store || !user || !key) return 0;
    char* v = qihse_kv_get_user(store, key, user);
    if (!v) return 0;
    uint64_t gen = 0;
    qihse_fabric_response_t parsed;
    if (qihse_fabric_response_parse(v, strlen(v), &parsed)) gen = parsed.gen;
    free(v);
    return gen;
}

static void fabric_refusal_body(const char* reason, qihse_fabric_job_t job_type,
                                uint64_t job_id, char* out, size_t out_cap,
                                size_t* out_len) {
    (void)fabric_response_format("denied", job_type, job_id, 0u, 0u, 0u, NULL, "-",
                                 reason, NULL, 0u, NULL, out, out_cap, out_len);
}

/* Execute one verified job.  Returns the executor's response body. */
static bool fabric_execute_job(qihse_fabric_executor_t* ex,
                               const qihse_fabric_token_t* claims,
                               const char* payload, size_t payload_len,
                               char* out, size_t out_cap, size_t* out_len) {
    qihse_kv_store_t* store = qihse_resp_server_store(ex->server);
    if (!store) return false;

    /*
     * THE EXECUTION RULE.
     *
     * The job runs only when the executor can run it as EXACTLY the principal
     * the token names.  QIHSE resolves principals by identity against its
     * node-local authorization table, so a principal from another node has no
     * entry there and the only context the executor can construct carries no
     * authority beyond unclassified.  That is a faithful representation of a
     * clearance-0/SCI-0 principal and of nothing else.
     *
     * Any token above that is REFUSED here.  It is NOT run under the
     * executor's own principal: the executor's clearance is 0xFFFF on a
     * system node, so running there would read data the submitter cannot and
     * return it — the disclosure path this whole design exists to prevent.
     */
    if (claims->clearance != 0u || claims->sci != 0u) {
        fabric_refusal_body("principal-not-representable", claims->job_type,
                            claims->job_id, out, out_cap, out_len);
        return true;
    }

    qihse_user_t remote_ctx;
    fabric_remote_context(&remote_ctx, claims);

    char result_key[128];
    if (!qihse_fabric_remote_result_key(&claims->submitter_node, claims->job_id,
                                        result_key, sizeof(result_key))) {
        return false;
    }
    uint64_t gen = fabric_previous_generation(store, ex->local_user, result_key) + 1u;

    const char* status = "failed";
    const char* reason = "executor-failed";
    char result_ref[192];
    result_ref[0] = '\0';
    const char* record_payload = NULL;
    size_t record_payload_len = 0;

    if (claims->job_type == QIHSE_FABRIC_JOB_KEYSTONE_INGEST) {
        char art_key[192];
        if (!qihse_fabric_remote_artifact_key(&claims->submitter_node, claims->job_id,
                                              art_key, sizeof(art_key))) {
            return false;
        }
        snprintf(result_ref, sizeof(result_ref), "%s", art_key);
        /* The artifact is stored AT THE TOKEN'S CLAIMS.  The classification
         * value in this call comes from the token and from nowhere else; the
         * executor's own clearance is never read here. */
        bool stored = qihse_kv_set_user(store, art_key, payload, claims->clearance,
                                        claims->sci, ex->local_user);
        if (!stored) {
            status = "failed";
            reason = "artifact-store-refused";
        } else {
            int irc = qihse_fabric_index_artifact_user(art_key, payload, payload_len,
                                                       claims->clearance, claims->sci,
                                                       ex->local_user);
            if (irc == 0) {
                status = "done";
                reason = "-";
            } else {
                /* "stored but not indexed" is a real outcome (KEYSTONE is a
                 * soft dependency) and is reported as its own status rather
                 * than as success. */
                status = "stored-unindexed";
                reason = "keystone-index-unavailable";
            }
            record_payload = payload;
            record_payload_len = payload_len;
        }
    } else {
        char mem_id[QIHSE_AIMEM_ID_LEN + 1u];
        mem_id[0] = '\0';
        /* `embed` takes its classification from the context, which is why the
         * context must be exactly the principal's — see the rule above. */
        if (qihse_ai_memory_store(ex->server, &remote_ctx, payload,
                                  QIHSE_AIMEM_SEMANTIC, mem_id)) {
            status = "done";
            reason = "-";
            snprintf(result_ref, sizeof(result_ref), "%s", mem_id);
        } else {
            status = "failed";
            reason = "embed-refused";
        }
    }

    /* The executor writes its OWN record, in its OWN store.  Nothing here
     * writes into the submitter's store: there is no remote-write path.
     *
     * The record buffer is heap-allocated rather than a local array: this
     * runs on the connection thread, and a multi-kilobyte frame per peer is
     * exactly the cheap denial-of-service shape AGENTS.md warns about. */
    char* record = (char*)malloc(QIHSE_FABRIC_MAX_RESPONSE);
    if (!record) return false;
    size_t record_len = 0;
    if (!fabric_response_format(status, claims->job_type, claims->job_id, gen,
                                claims->clearance, claims->sci, &ex->local_node,
                                result_ref, reason, record_payload, record_payload_len,
                                NULL, record, QIHSE_FABRIC_MAX_RESPONSE, &record_len)) {
        free(record);
        return false;
    }
    char record_digest[97];
    if (!qihse_fabric_sha384_hex(record, record_len, record_digest, sizeof(record_digest))) {
        free(record);
        return false;
    }
    bool recorded = qihse_kv_set_user(store, result_key, record, claims->clearance,
                                      claims->sci, ex->local_user);
    free(record);
    if (!recorded) {
        /* A job whose result cannot be recorded must not be reported done: the
         * submitter would pull a record that does not exist. */
        fabric_refusal_body("result-record-failed", claims->job_type, claims->job_id,
                            out, out_cap, out_len);
        return true;
    }

    /* The RUN reply is an ACK, not the result: it carries the status, the
     * generation and the digest of the record that was written, and the
     * submitter pulls the record itself (decision 1). */
    if (!fabric_response_format(status, claims->job_type, claims->job_id, gen,
                                claims->clearance, claims->sci, &ex->local_node,
                                result_ref, reason, NULL, 0u, record_digest,
                                out, out_cap, out_len)) {
        return false;
    }
    return true;
}

bool qihse_fabric_executor_run(qihse_fabric_executor_t* ex,
                               const uint8_t* body, size_t body_len,
                               qihse_uuid_t channel_peer,
                               char* out_body, size_t out_cap, size_t* out_len) {
    if (!ex || !ex->server || !out_body || !out_len) return false;
    if (!body || body_len == 0 || body_len > QIHSE_FABRIC_MAX_FRAME_BODY) return false;
    if (!ex->local_user) {
        /* Fail closed, explicitly.  There is no context-free execution. */
        fabric_refusal_body("no-local-context", QIHSE_FABRIC_JOB_NONE, 0u,
                            out_body, out_cap, out_len);
        return true;
    }

    qihse_fabric_token_t claims;
    size_t region = 0, total = 0;
    if (!qihse_fabric_token_parse(body, body_len, &claims, &region, &total)) {
        fabric_refusal_body("malformed-token", QIHSE_FABRIC_JOB_NONE, 0u,
                            out_body, out_cap, out_len);
        return true;
    }
    if (region != QIHSE_FABRIC_TOKEN_REGION_BYTES || total > body_len) {
        fabric_refusal_body("malformed-token", QIHSE_FABRIC_JOB_NONE, 0u,
                            out_body, out_cap, out_len);
        return true;
    }

    const char* payload = (const char*)body + total;
    size_t payload_len = body_len - total;
    /* The token binds the payload, so a body whose payload is not the bound
     * payload is refused by the digest check inside token_check. */
    if (payload_len > QIHSE_FABRIC_MAX_PAYLOAD) {
        fabric_refusal_body("payload-too-large", claims.job_type, claims.job_id,
                            out_body, out_cap, out_len);
        return true;
    }
    if (payload_len != claims.payload_len) {
        fabric_refusal_body("payload-length-mismatch", claims.job_type, claims.job_id,
                            out_body, out_cap, out_len);
        return true;
    }

    qihse_fabric_token_check_t check;
    memset(&check, 0, sizeof(check));
    check.channel_peer = channel_peer;
    check.expect_purpose = QIHSE_FABRIC_TOKEN_PURPOSE_RUN;
    check.expect_job_type = claims.job_type;
    check.expect_job_id = claims.job_id;
    check.payload = payload;
    check.payload_len = payload_len;
    check.required_scope = QIHSE_FABRIC_SCOPE_RUN;
    check.consume = true;

    qihse_fabric_token_t verified;
    qihse_fabric_token_verdict_t verdict =
        qihse_fabric_token_check(ex->server, ex->local_user, body, body_len, &check, &verified);
    if (verdict != QIHSE_FABRIC_TOKEN_OK) {
        fabric_refusal_body(qihse_fabric_token_verdict_name(verdict), claims.job_type,
                            claims.job_id, out_body, out_cap, out_len);
        return true;
    }

    return fabric_execute_job(ex, &verified, payload, payload_len, out_body, out_cap, out_len);
}

bool qihse_fabric_executor_fetch(qihse_fabric_executor_t* ex,
                                 const uint8_t* body, size_t body_len,
                                 qihse_uuid_t channel_peer,
                                 char* out_body, size_t out_cap, size_t* out_len) {
    if (!ex || !ex->server || !out_body || !out_len) return false;
    if (!body || body_len == 0 || body_len > QIHSE_FABRIC_MAX_FRAME_BODY) return false;
    if (!ex->local_user) {
        fabric_refusal_body("no-local-context", QIHSE_FABRIC_JOB_NONE, 0u,
                            out_body, out_cap, out_len);
        return true;
    }

    qihse_fabric_token_t claims;
    size_t region = 0, total = 0;
    if (!qihse_fabric_token_parse(body, body_len, &claims, &region, &total) ||
        total != body_len) {
        fabric_refusal_body("malformed-token", QIHSE_FABRIC_JOB_NONE, 0u,
                            out_body, out_cap, out_len);
        return true;
    }

    qihse_fabric_token_check_t check;
    memset(&check, 0, sizeof(check));
    check.channel_peer = channel_peer;
    check.expect_purpose = QIHSE_FABRIC_TOKEN_PURPOSE_FETCH;
    check.expect_job_type = claims.job_type;
    check.expect_job_id = claims.job_id;
    check.payload = NULL;
    check.payload_len = 0u;
    check.required_scope = QIHSE_FABRIC_SCOPE_FETCH;
    check.consume = true;

    qihse_fabric_token_t verified;
    qihse_fabric_token_verdict_t verdict =
        qihse_fabric_token_check(ex->server, ex->local_user, body, body_len, &check, &verified);
    if (verdict != QIHSE_FABRIC_TOKEN_OK) {
        fabric_refusal_body(qihse_fabric_token_verdict_name(verdict), claims.job_type,
                            claims.job_id, out_body, out_cap, out_len);
        return true;
    }

    qihse_kv_store_t* store = qihse_resp_server_store(ex->server);
    char key[128];
    if (!store || !qihse_fabric_remote_result_key(&verified.submitter_node, verified.job_id,
                                                  key, sizeof(key))) {
        return false;
    }

    /*
     * THE READ RULE.
     *
     * The record is first read with a NULL context, which the store permits
     * only for UNCLASSIFIED records — so a record that is protected by the
     * store's own classification gate cannot be reached this way at all.
     * Only when that fails is the record read with the executor's explicit
     * context, and then the token's clearance/SCI must dominate the record's
     * declared classification BEFORE any byte is returned.  The two reads are
     * cross-checked in both directions: a record the unclassified read could
     * not fetch may not declare itself unclassified.
     */
    char* value = qihse_kv_get_user(store, key, NULL);
    bool classified = false;
    if (!value) {
        value = qihse_kv_get_user(store, key, ex->local_user);
        classified = true;
    }
    if (!value) {
        fabric_refusal_body("no-result-record", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }

    size_t value_len = strlen(value);
    qihse_fabric_response_t parsed;
    if (!qihse_fabric_response_parse(value, value_len, &parsed)) {
        free(value);
        fabric_refusal_body("result-record-malformed", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }

    bool declares_unclassified = (parsed.clearance == 0u && parsed.sci == 0u);
    if (classified == declares_unclassified) {
        /* Inconsistent: either a store-protected record claims to be
         * unclassified, or an unclassified read failed for a record that
         * claims to be unclassified.  Both are refused rather than served. */
        free(value);
        fabric_refusal_body("result-record-inconsistent", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }
    if (parsed.job_id != verified.job_id) {
        free(value);
        fabric_refusal_body("result-record-mismatch", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }

    /* The authorization decision, made from the VERIFIED token's claims. */
    bool above = verified.clearance < parsed.clearance ||
                 (parsed.sci & verified.sci) != parsed.sci;
    if (above) {
        free(value);
        fabric_refusal_body("above-clearance", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }

    /* Integrity: the payload's digest must match the record's own digest, so a
     * tampered record is refused rather than served as if intact. */
    char digest[97];
    const char* payload = value + parsed.payload_offset;
    if (!qihse_fabric_sha384_hex(payload, (size_t)parsed.payload_len, digest, sizeof(digest)) ||
        strcmp(digest, parsed.digest) != 0) {
        free(value);
        fabric_refusal_body("result-record-corrupt", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }

    if (value_len >= out_cap) {
        free(value);
        fabric_refusal_body("result-too-large", verified.job_type, verified.job_id,
                            out_body, out_cap, out_len);
        return true;
    }
    memcpy(out_body, value, value_len + 1u);
    *out_len = value_len;
    free(value);
    return true;
}

/* ── Framing ────────────────────────────────────────────────────────────── */

static bool fabric_read_exact(const qihse_repl_transport_ops_t* ops, void* ctx,
                              uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        long n = ops->recv(ctx, buf + got, len - got);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

static bool fabric_write_all(const qihse_repl_transport_ops_t* ops, void* ctx,
                             const uint8_t* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        long n = ops->send(ctx, buf + sent, len - sent);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool fabric_frame_write(const qihse_repl_transport_ops_t* ops, void* ctx,
                               uint16_t type, const char* body, size_t body_len) {
    if (body_len > QIHSE_FABRIC_MAX_FRAME_BODY) return false;
    uint8_t header[FABRIC_FRAME_HEADER_BYTES];
    fabric_writer_t w = { header, sizeof(header), 0u, false };
    fab_put_u32(&w, FABRIC_FRAME_MAGIC);
    fab_put_u16(&w, FABRIC_FRAME_VERSION);
    fab_put_u16(&w, type);
    fab_put_u32(&w, 0u);                 /* flags: reserved, must be zero */
    fab_put_u32(&w, (uint32_t)body_len);
    if (w.overflow) return false;
    if (!fabric_write_all(ops, ctx, header, sizeof(header))) return false;
    if (body_len == 0) return true;
    return fabric_write_all(ops, ctx, (const uint8_t*)body, body_len);
}

static bool fabric_frame_read(const qihse_repl_transport_ops_t* ops, void* ctx,
                              uint16_t* out_type, uint8_t* body, size_t body_cap,
                              size_t* out_len) {
    uint8_t header[FABRIC_FRAME_HEADER_BYTES];
    if (!fabric_read_exact(ops, ctx, header, sizeof(header))) return false;
    fabric_reader_t r = { header, sizeof(header), 0u, false };
    uint32_t magic = fab_get_u32(&r);
    uint16_t version = fab_get_u16(&r);
    uint16_t type = fab_get_u16(&r);
    uint32_t flags = fab_get_u32(&r);
    uint32_t length = fab_get_u32(&r);
    if (r.underflow) return false;
    if (magic != FABRIC_FRAME_MAGIC || version != FABRIC_FRAME_VERSION) return false;
    if (flags != 0u) return false;
    /* The declared length is attacker-controlled and is validated against the
     * caller's buffer BEFORE a single byte of the body is read. */
    if (length > QIHSE_FABRIC_MAX_FRAME_BODY || length > body_cap) return false;
    if (length > 0 && !fabric_read_exact(ops, ctx, body, length)) return false;
    if (out_type) *out_type = type;
    if (out_len) *out_len = length;
    return true;
}

/* ── Executor: one connection ───────────────────────────────────────────── */

bool qihse_fabric_executor_serve_session(qihse_fabric_executor_t* ex,
                                         qihse_fed_tls_session_t* session) {
    if (!ex || !session) return false;

    qihse_uuid_t peer;
    qihse_runtime_trust_t trust;
    /* The channel identity, from the handshake.  Never from the wire: the
     * token is bound to it precisely so that a captured token is useless. */
    if (!qihse_federation_tls_peer_identity(session, &peer, &trust)) return false;

    qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(session);
    if (!ops.recv || !ops.send) return false;

    uint8_t* body = (uint8_t*)malloc(QIHSE_FABRIC_MAX_FRAME_BODY);
    char* response = (char*)malloc(QIHSE_FABRIC_MAX_RESPONSE);
    if (!body || !response) { free(body); free(response); return false; }

    uint16_t type = 0;
    size_t body_len = 0;
    bool ok = fabric_frame_read(&ops, session, &type, body, QIHSE_FABRIC_MAX_FRAME_BODY,
                                &body_len);
    if (ok) {
        size_t response_len = 0;
        bool handled = false;
        if (type == FABRIC_FRAME_RUN) {
            handled = qihse_fabric_executor_run(ex, body, body_len, peer, response,
                                               QIHSE_FABRIC_MAX_RESPONSE, &response_len);
        } else if (type == FABRIC_FRAME_FETCH) {
            handled = qihse_fabric_executor_fetch(ex, body, body_len, peer, response,
                                                 QIHSE_FABRIC_MAX_RESPONSE, &response_len);
        } else {
            /* An unknown frame type is refused, not ignored: a peer that is
             * probing for a handler must get a refusal. */
            size_t n = 0;
            fabric_refusal_body("unknown-frame-type", QIHSE_FABRIC_JOB_NONE, 0u,
                                response, QIHSE_FABRIC_MAX_RESPONSE, &n);
            handled = n > 0;
            response_len = n;
        }
        if (handled) {
            uint16_t reply_type = FABRIC_FRAME_RESULT;
            qihse_fabric_response_t parsed;
            if (qihse_fabric_response_parse(response, response_len, &parsed) &&
                fabric_response_is_status(parsed.status, "denied")) {
                reply_type = FABRIC_FRAME_REFUSED;
            }
            ok = fabric_frame_write(&ops, session, reply_type, response, response_len);
        } else {
            ok = false;
        }
    }

    free(body);
    free(response);
    return ok;
}

/* ── Listener loop ──────────────────────────────────────────────────────── */

struct qihse_fabric_listener {
    qihse_fed_listener_t* listener;
    qihse_fabric_executor_t executor;
    pthread_t thread;
    pthread_mutex_t lock;
    bool running;
    bool shutdown;
    uint64_t served;
    uint64_t refused;
};

static void* fabric_listener_main(void* arg) {
    qihse_fabric_listener_t* l = (qihse_fabric_listener_t*)arg;
    int timeout = QIHSE_FABRIC_LISTENER_ACCEPT_TIMEOUT_MS;

    for (;;) {
        pthread_mutex_lock(&l->lock);
        bool stop = l->shutdown;
        pthread_mutex_unlock(&l->lock);
        if (stop) break;

        /* ONE connection at a time.  No thread per peer and no connection
         * table: the loop cannot be turned into a resource bomb.  The
         * handshake has its own fixed bound inside the transport, and the
         * socket keeps the receive timeout it was given there, so a peer that
         * connects and then stalls cannot hold this loop past that bound. */
        qihse_peer_verdict_t verdict = QIHSE_PEER_REJECT_MALFORMED;
        qihse_fed_tls_session_t* session =
            qihse_federation_listener_accept(l->listener, timeout, &verdict);
        if (!session) continue;   /* nobody called, or a refused peer */

        pthread_mutex_lock(&l->lock);
        l->served++;
        pthread_mutex_unlock(&l->lock);

        (void)qihse_fabric_executor_serve_session(&l->executor, session);
        qihse_federation_tls_session_destroy(session);
    }
    return NULL;
}

qihse_fabric_listener_t* qihse_fabric_listener_start(const qihse_fabric_listener_config_t* cfg) {
    if (!cfg || !cfg->tls || !cfg->bind_address) return NULL;
    if (!cfg->executor.server || !cfg->executor.local_user) return NULL;

    qihse_fed_listener_t* inner =
        qihse_federation_listener_open(cfg->tls, cfg->bind_address, cfg->port);
    if (!inner) return NULL;

    qihse_fabric_listener_t* l = (qihse_fabric_listener_t*)calloc(1u, sizeof(*l));
    if (!l) { qihse_federation_listener_close(inner); return NULL; }
    l->listener = inner;
    l->executor = cfg->executor;
    l->running = true;
    if (pthread_mutex_init(&l->lock, NULL) != 0) {
        qihse_federation_listener_close(inner);
        free(l);
        return NULL;
    }
    if (pthread_create(&l->thread, NULL, fabric_listener_main, l) != 0) {
        pthread_mutex_destroy(&l->lock);
        qihse_federation_listener_close(inner);
        free(l);
        return NULL;
    }
    return l;
}

uint16_t qihse_fabric_listener_port(const qihse_fabric_listener_t* listener) {
    return listener ? qihse_federation_listener_port(listener->listener) : 0u;
}

uint64_t qihse_fabric_listener_served(const qihse_fabric_listener_t* listener) {
    if (!listener) return 0u;
    qihse_fabric_listener_t* l = (qihse_fabric_listener_t*)listener;
    pthread_mutex_lock(&l->lock);
    uint64_t n = l->served;
    pthread_mutex_unlock(&l->lock);
    return n;
}

void qihse_fabric_listener_stop(qihse_fabric_listener_t* listener) {
    if (!listener) return;
    pthread_mutex_lock(&listener->lock);
    listener->shutdown = true;
    pthread_mutex_unlock(&listener->lock);
    /* The accept call returns within the accept timeout, so the join is
     * bounded by it. */
    pthread_join(listener->thread, NULL);
    listener->running = false;
    pthread_mutex_destroy(&listener->lock);
    qihse_federation_listener_close(listener->listener);
    free(listener);
}

/* ── TLS context and signer ─────────────────────────────────────────────── */

static bool fabric_read_pem_file(const char* path, char* out, size_t out_cap) {
    if (!path || !out || out_cap < 2u) return false;
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(out, 1u, out_cap - 1u, f);
    bool ok = !ferror(f) && n > 0u;
    fclose(f);
    if (!ok) return false;
    out[n] = '\0';
    /* A PEM file that was truncated to fit is refused rather than used: a
     * partial certificate is not a certificate. */
    if (n == out_cap - 1u) return false;
    return strstr(out, "CERTIFICATE") != NULL;
}

bool qihse_fabric_tls_context_create(const char* ca_cert_path,
                                     const char* node_cert_path,
                                     const char* node_key_handle,
                                     void* store_void, qihse_user_t* user,
                                     qihse_fed_tls_server_t** out) {
    if (!ca_cert_path || !node_cert_path || !node_key_handle || !store_void || !user || !out) {
        return false;
    }
    *out = NULL;

    qihse_federation_ca_t* ca = (qihse_federation_ca_t*)calloc(1u, sizeof(*ca));
    char* node_cert = (char*)malloc(QIHSE_FEDERATION_PEM_MAX);
    if (!ca || !node_cert) { free(ca); free(node_cert); return false; }

    bool ok = false;
    if (fabric_read_pem_file(ca_cert_path, ca->cert_pem, sizeof(ca->cert_pem)) &&
        fabric_read_pem_file(node_cert_path, node_cert, QIHSE_FEDERATION_PEM_MAX)) {
        ca->cert_pem_len = strlen(ca->cert_pem);
        /* The fingerprint is RECOMPUTED from the loaded certificate, never
         * taken from the file: a stored fingerprint must not be trusted to
         * describe the key it is attached to. */
        uint8_t fp[QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES];
        if (qihse_federation_cert_fingerprint(ca->cert_pem, fp)) {
            static const char hex[] = "0123456789abcdef";
            for (size_t i = 0; i < sizeof(fp); i++) {
                ca->fingerprint_hex[i * 2u] = hex[fp[i] >> 4];
                ca->fingerprint_hex[i * 2u + 1u] = hex[fp[i] & 0x0Fu];
            }
            ca->fingerprint_hex[sizeof(fp) * 2u] = '\0';
            *out = qihse_federation_tls_server_create(ca, node_cert, node_key_handle,
                                                     store_void, user);
            ok = (*out != NULL);
        }
    }
    if (!ok && *out) { qihse_federation_tls_server_destroy(*out); *out = NULL; }
    free(node_cert);
    free(ca);
    return ok;
}

bool qihse_fabric_node_signer_load(void* store_void, qihse_user_t* user,
                                   const qihse_uuid_t* node_id,
                                   qihse_federation_node_identity_t* out_identity,
                                   void** out_pkey) {
    if (!store_void || !user || !node_id || !out_identity || !out_pkey) return false;
    *out_pkey = NULL;
    if (!qihse_federation_node_lookup(store_void, user, node_id, out_identity)) return false;
    /* Only an APPROVED node may act.  A pending or revoked identity has no
     * dispatch authority, and this is checked before the key is touched. */
    if (out_identity->trust != QIHSE_TRUST_APPROVED) return false;
    if (out_identity->key_handle[0] == '\0') return false;
    void* pkey = qihse_federation_node_key_load(out_identity->key_handle);
    if (!pkey) return false;
    *out_pkey = pkey;
    return true;
}

/* ── Submitter side ─────────────────────────────────────────────────────── */

static void fabric_fill_claims(qihse_fabric_token_t* claims, uint16_t purpose,
                               const qihse_uuid_t* submitter,
                               qihse_fabric_job_t job_type, uint64_t job_id,
                               const char* payload, size_t payload_len,
                               uint32_t user_id, uint16_t clearance, uint16_t sci,
                               uint32_t tenant, uint32_t scope, uint64_t ttl_ms) {
    memset(claims, 0, sizeof(*claims));
    claims->purpose = purpose;
    claims->job_type = job_type;
    claims->scope = scope;
    claims->principal_user_id = user_id;
    claims->clearance = clearance;
    claims->sci = sci;
    claims->principal_tenant = tenant;
    claims->submitter_node = *submitter;
    claims->job_id = job_id;
    claims->issued_ms = fabric_now_ms();
    if (ttl_ms == 0u || ttl_ms > QIHSE_FABRIC_TOKEN_MAX_TTL_MS) {
        ttl_ms = QIHSE_FABRIC_TOKEN_DEFAULT_TTL_MS;
    }
    claims->expires_ms = claims->issued_ms + ttl_ms;
    claims->payload_len = (uint32_t)payload_len;
    /* Always computed, including for the empty payload a FETCH binds: the
     * verifier recomputes it and compares, so an unset digest would fail
     * every fetch rather than only the ones it should. */
    uint8_t digest[48];
    if (fabric_sha384_raw(payload, payload_len, digest)) {
        memcpy(claims->payload_digest, digest, sizeof(digest));
    }
    /* A fresh nonce per attempt.  A nonce that two callers can collide on is
     * not replay protection, and a nonce reused across retries would make the
     * retry itself look like a replay. */
    if (!qihse_uuid_generate(&claims->nonce)) {
        memset(claims->nonce.bytes, 0, QIHSE_UUID_BYTES);
    }
}

/* One RUN attempt over a fresh connection.  Returns true when the executor
 * answered (the body is then in out->body). */
static bool fabric_attempt_run(const qihse_fabric_run_request_t* req,
                               const qihse_uuid_t* submitter,
                               qihse_fabric_run_outcome_t* out) {
    uint8_t* blob = (uint8_t*)malloc(QIHSE_FABRIC_TOKEN_MAX_BYTES);
    if (!blob) return false;

    qihse_fabric_token_t claims;
    fabric_fill_claims(&claims, QIHSE_FABRIC_TOKEN_PURPOSE_RUN, submitter,
                       req->job_type, req->job_id, req->payload, req->payload_len,
                       req->principal_user_id, req->clearance, req->sci,
                       req->principal_tenant, req->scope, req->ttl_ms);
    size_t blob_len = 0;
    bool ok = false;
    if (qihse_fabric_token_mint(req->pkey, &claims, blob, QIHSE_FABRIC_TOKEN_MAX_BYTES,
                               &blob_len)) {
        qihse_peer_verdict_t verdict = QIHSE_PEER_REJECT_MALFORMED;
        qihse_fed_tls_session_t* session = qihse_federation_tls_connect_to(
            req->tls, req->host, req->port, req->timeout_ms, &verdict);
        out->tls_verdict = verdict;
        if (session) {
            qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(session);
            if (ops.send && ops.recv) {
                uint8_t* body = (uint8_t*)malloc(QIHSE_FABRIC_MAX_FRAME_BODY);
                char* response = (char*)malloc(QIHSE_FABRIC_MAX_RESPONSE);
                if (body && response && blob_len + req->payload_len <= QIHSE_FABRIC_MAX_FRAME_BODY) {
                    memcpy(body, blob, blob_len);
                    if (req->payload_len) {
                        memcpy(body + blob_len, req->payload, req->payload_len);
                    }
                    if (fabric_frame_write(&ops, session, FABRIC_FRAME_RUN,
                                           (const char*)body, blob_len + req->payload_len)) {
                        uint16_t type = 0;
                        size_t len = 0;
                        if (fabric_frame_read(&ops, session, &type, (uint8_t*)response,
                                              QIHSE_FABRIC_MAX_RESPONSE, &len) &&
                            len < out->body_cap) {
                            memcpy(out->body, response, len);
                            out->body[len] = '\0';
                            out->body_len = len;
                            ok = true;
                        }
                    }
                }
                free(body);
                free(response);
            }
            qihse_federation_tls_session_destroy(session);
        }
    }
    memset(blob, 0, QIHSE_FABRIC_TOKEN_MAX_BYTES);
    free(blob);
    return ok;
}

bool qihse_fabric_run(const qihse_fabric_run_request_t* req,
                      qihse_fabric_run_outcome_t* out) {
    if (!req || !out) return false;
    if (!req->tls || !req->pkey || !req->host || !out->body || out->body_cap == 0u) return false;
    if (req->payload_len > QIHSE_FABRIC_MAX_PAYLOAD) return false;
    if (req->payload_len > 0 && !req->payload) return false;
    if (req->job_type == QIHSE_FABRIC_JOB_NONE) return false;

    qihse_uuid_t submitter = req->submitter_node;
    unsigned max_attempts = QIHSE_FABRIC_MAX_ATTEMPTS;
    bool idempotent = qihse_fabric_jobtype_is_idempotent(req->job_type);

    out->attempts = 0;
    out->retried = false;
    out->answered = false;
    out->succeeded = false;
    out->denied = false;
    out->gave_up = false;
    out->terminal_reason[0] = '\0';
    out->remote_status[0] = '\0';
    out->result_ref[0] = '\0';
    out->remote_gen = 0;
    out->remote_digest[0] = '\0';
    out->remote_clearance = 0;
    out->remote_sci = 0;
    out->tls_verdict = QIHSE_PEER_REJECT_MALFORMED;
    out->body[0] = '\0';
    out->body_len = 0;

    for (unsigned attempt = 0; attempt < max_attempts; attempt++) {
        out->attempts = attempt + 1;
        if (attempt > 0) out->retried = true;

        if (fabric_attempt_run(req, &submitter, out)) {
            out->answered = true;
            qihse_fabric_response_t parsed;
            if (!qihse_fabric_response_parse(out->body, out->body_len, &parsed)) {
                /* An answer that cannot be parsed is not an answer. */
                snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                         "unparseable-response");
                continue;
            }
            snprintf(out->remote_status, sizeof(out->remote_status), "%s", parsed.status);
            snprintf(out->result_ref, sizeof(out->result_ref), "%s",
                     strcmp(parsed.result, "-") == 0 ? "" : parsed.result);
            out->remote_gen = parsed.gen;
            out->remote_clearance = parsed.clearance;
            out->remote_sci = parsed.sci;
            /* The ACK's record digest, so the submitter can later check that
             * the record it pulls is the record it was told about. */
            snprintf(out->remote_digest, sizeof(out->remote_digest), "%s",
                     parsed.record_digest);

            if (fabric_response_is_status(parsed.status, "done") ||
                fabric_response_is_status(parsed.status, "stored-unindexed")) {
                out->succeeded = true;
                return true;
            }
            if (fabric_response_is_status(parsed.status, "failed")) {
                /* A definite failure.  It is NOT retried: the executor ran the
                 * job and reported that it failed, so repeating it would be
                 * repeating a known-bad operation. */
                snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                         "executor-reported-failure");
                return true;
            }
            if (fabric_response_is_status(parsed.status, "denied")) {
                /* A refusal is terminal: retrying an authorization decision
                 * cannot change it. */
                out->denied = true;
                snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                         parsed.reason[0] ? parsed.reason : "denied");
                return true;
            }
            snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                     "unexpected-status");
            return true;
        }

        /* No answer.  The request may or may not have reached the executor,
         * which is exactly why the retry decision depends on the type's
         * declared idempotency. */
        if (!idempotent) {
            out->gave_up = true;
            snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                     "gave-up:retry-refused-non-idempotent");
            return true;
        }
        snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                 "gave-up:attempts-exhausted");
    }

    /* Attempts used up with no definite answer.  This is NOT `failed`: the
     * job may have run and the submitter cannot tell, and reporting `failed`
     * would be a claim the submitter cannot support. */
    out->gave_up = true;
    if (out->terminal_reason[0] == '\0') {
        snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                 "gave-up:attempts-exhausted");
    }
    return true;
}

static bool fabric_attempt_fetch(const qihse_fabric_fetch_request_t* req,
                                 const qihse_uuid_t* submitter,
                                 qihse_fabric_fetch_outcome_t* out) {
    uint8_t* blob = (uint8_t*)malloc(QIHSE_FABRIC_TOKEN_MAX_BYTES);
    if (!blob) return false;

    qihse_fabric_token_t claims;
    fabric_fill_claims(&claims, QIHSE_FABRIC_TOKEN_PURPOSE_FETCH, submitter,
                       req->job_type, req->job_id, NULL, 0u,
                       req->principal_user_id, req->clearance, req->sci,
                       req->principal_tenant, req->scope, req->ttl_ms);
    size_t blob_len = 0;
    bool ok = false;
    if (qihse_fabric_token_mint(req->pkey, &claims, blob, QIHSE_FABRIC_TOKEN_MAX_BYTES,
                               &blob_len)) {
        qihse_peer_verdict_t verdict = QIHSE_PEER_REJECT_MALFORMED;
        qihse_fed_tls_session_t* session = qihse_federation_tls_connect_to(
            req->tls, req->host, req->port, req->timeout_ms, &verdict);
        out->tls_verdict = verdict;
        if (session) {
            qihse_repl_transport_ops_t ops = qihse_federation_tls_transport_ops(session);
            if (ops.send && ops.recv &&
                fabric_frame_write(&ops, session, FABRIC_FRAME_FETCH,
                                   (const char*)blob, blob_len)) {
                uint16_t type = 0;
                size_t len = 0;
                char* response = (char*)malloc(QIHSE_FABRIC_MAX_RESPONSE);
                if (response && fabric_frame_read(&ops, session, &type, (uint8_t*)response,
                                                  QIHSE_FABRIC_MAX_RESPONSE, &len) &&
                    len < out->body_cap) {
                    memcpy(out->body, response, len);
                    out->body[len] = '\0';
                    out->body_len = len;
                    ok = true;
                }
                free(response);
            }
            qihse_federation_tls_session_destroy(session);
        }
    }
    memset(blob, 0, QIHSE_FABRIC_TOKEN_MAX_BYTES);
    free(blob);
    return ok;
}

bool qihse_fabric_fetch(const qihse_fabric_fetch_request_t* req,
                        qihse_fabric_fetch_outcome_t* out) {
    if (!req || !out) return false;
    if (!req->tls || !req->pkey || !req->host || !out->body || out->body_cap == 0u) return false;

    out->answered = false;
    out->refused = false;
    out->terminal_reason[0] = '\0';
    out->remote_gen = 0;
    out->remote_status[0] = '\0';
    out->tls_verdict = QIHSE_PEER_REJECT_MALFORMED;
    out->body[0] = '\0';
    out->body_len = 0;

    qihse_uuid_t submitter = req->submitter_node;
    if (!fabric_attempt_fetch(req, &submitter, out)) {
        snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s", "no-answer");
        return true;
    }
    out->answered = true;

    qihse_fabric_response_t parsed;
    if (!qihse_fabric_response_parse(out->body, out->body_len, &parsed)) {
        snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                 "unparseable-response");
        return true;
    }
    snprintf(out->remote_status, sizeof(out->remote_status), "%s", parsed.status);
    out->remote_gen = parsed.gen;

    if (fabric_response_is_status(parsed.status, "denied")) {
        out->refused = true;
        snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                 parsed.reason[0] ? parsed.reason : "denied");
        return true;
    }

    /* Cache coherence, the submitter's half of the rule: a fetch that would
     * move the cached record BACKWARDS is refused.  The executor's record is
     * written once per job generation and is immutable afterwards, so a lower
     * generation means the executor's record was rolled back or tampered
     * with, and replacing a newer cache with it would silently serve older
     * state as current. */
    if (req->have_cached_gen && parsed.gen < req->cached_gen) {
        out->refused = true;
        snprintf(out->terminal_reason, sizeof(out->terminal_reason), "%s",
                 "stale:executor-generation-went-backwards");
        return true;
    }
    return true;
}
