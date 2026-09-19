#ifndef QIHSE_FABRIC_DISPATCH_H
#define QIHSE_FABRIC_DISPATCH_H

/*
 * QIHSE fabric remote job dispatch — the missing remote half of
 * ai_fabric.md build item 3.
 *
 * `FABRIC.SUBMIT` picks a best-fit node and, when that node is not this one,
 * previously recorded the job `queued` and never ran it.  This module is the
 * dispatch: the submitter mints a SIGNED CAPABILITY TOKEN naming the
 * principal, its clearance/SCI and its scope, sends the job over the
 * federation mTLS channel, and the EXECUTOR verifies the token and runs the
 * job as that principal.
 *
 * Three decisions this module implements, and the reasons they are the ones
 * implemented:
 *
 * 1. RESULT LOCATION — the executor writes its OWN result record in its own
 *    store.  It never writes into the submitter's store: there is no
 *    remote-write path here and none may be added.  The submitter PULLS the
 *    record and caches it; `FABRIC.RESULT` reads the local cache and reports
 *    the honest state (`pending-fetch` is not `done`).
 *
 * 2. FAILURE SEMANTICS — retry is permitted ONLY for a job type that
 *    DECLARES idempotency, and the declaration is per type because the two
 *    executors genuinely differ: `keystone-ingest` writes the deterministic
 *    key `fabric:ingest:<job-id>` (a retry overwrites, so it is idempotent)
 *    while `embed` calls qihse_ai_memory_store(), which GENERATES A NEW ID
 *    per call (a retry creates a SECOND memory, so it is not).  A
 *    non-idempotent type is never retried, and the terminal "gave up" state
 *    is distinct from "failed".
 *
 * 3. PRINCIPAL — a signed capability token, because clearance and SCI are
 *    NODE-LOCAL (the federation has no replication hook for them) and because
 *    running the job as the executor's OWN system principal is a disclosure
 *    path: an executor with a higher clearance than the submitter would read
 *    data the submitter cannot and hand it back.  An unverifiable or expired
 *    token REFUSES the job.  There is NO fallback to a local principal, and
 *    no code path in this module derives a job's authority from the
 *    executor's own principal.
 *
 * Bounds: this module is network-facing.  Every length field in a frame is
 * attacker-controlled and is validated before any copy; the frame body, the
 * payload, the token, the replay ledger, the accept loop and the connections
 * it serves are all explicitly bounded.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_auth.h"
#include "qihse_federation.h"
#include "qihse_federation_transport.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Bounds (all attacker-reachable, all explicit) ──────────────────────── */

/* The largest job payload a remote dispatch will carry.  Matches the local
 * FABRIC.SUBMIT limit, so a job that can be submitted locally can be
 * dispatched and vice versa. */
#define QIHSE_FABRIC_MAX_PAYLOAD 4095u

/* The complete token blob: the signed region plus the largest supported
 * signature (an ML-DSA-87 signature is 4627 bytes). */
#define QIHSE_FABRIC_TOKEN_REGION_BYTES 140u
#define QIHSE_FABRIC_TOKEN_MAX_BYTES \
    (QIHSE_FABRIC_TOKEN_REGION_BYTES + QIHSE_FEDERATION_SIG_MAX_BYTES)

/* A frame body is `token || payload`, so the bound is the sum plus framing. */
#define QIHSE_FABRIC_MAX_FRAME_BODY \
    (QIHSE_FABRIC_TOKEN_MAX_BYTES + QIHSE_FABRIC_MAX_PAYLOAD)

/* The executor's response: a one-line status header plus the record payload. */
#define QIHSE_FABRIC_MAX_RESPONSE \
    (512u + QIHSE_FABRIC_MAX_PAYLOAD + 128u)

/* Token lifetime.  A long-lived capability is a long-lived replay window, so
 * the executor refuses anything above the maximum, and refuses a token whose
 * issued/expiry window is inconsistent. */
#define QIHSE_FABRIC_TOKEN_DEFAULT_TTL_MS 120000u
#define QIHSE_FABRIC_TOKEN_MAX_TTL_MS 300000u
#define QIHSE_FABRIC_TOKEN_CLOCK_SKEW_MS 60000u

/* Replay ledger bound: entries live only until their token expires, so this
 * is a ceiling on concurrent live tokens, not a leak.  A full ledger refuses
 * new tokens (fail closed) rather than evicting a live nonce, because
 * evicting one would reopen the replay window it exists to close. */
#define QIHSE_FABRIC_REPLAY_MAX 1024u

/* Retry budget for an idempotent job type.  One initial attempt plus retries. */
#define QIHSE_FABRIC_MAX_ATTEMPTS 3u

/* One request per connection and one connection at a time: no pipelining and
 * no thread-per-peer, so the listener cannot be turned into a thread bomb. */
#define QIHSE_FABRIC_LISTENER_ACCEPT_TIMEOUT_MS 250

/* ── Job types and their idempotency declarations (decision 2) ──────────── */

typedef enum {
    QIHSE_FABRIC_JOB_NONE = 0,
    QIHSE_FABRIC_JOB_EMBED = 1,
    QIHSE_FABRIC_JOB_KEYSTONE_INGEST = 2
} qihse_fabric_job_t;

typedef struct {
    const char* name;
    qihse_fabric_job_t type;
    /* May a FAILED/INCONCLUSIVE dispatch of this type be retried?  True only
     * when re-running the job is observably the same as running it once. */
    bool idempotent;
    /* Why, in the type's own terms.  A declaration without its reason is a
     * comment that will be "fixed" by someone who does not know the executor. */
    const char* idempotency_reason;
} qihse_fabric_jobtype_decl_t;

/* NULL for a name that has no executor (the caller refuses it). */
const qihse_fabric_jobtype_decl_t* qihse_fabric_jobtype_lookup(const char* name);
const qihse_fabric_jobtype_decl_t* qihse_fabric_jobtype_decl(qihse_fabric_job_t type);
const char* qihse_fabric_jobtype_name(qihse_fabric_job_t type);
bool qihse_fabric_jobtype_is_idempotent(qihse_fabric_job_t type);

/* ── Capability token (decision 3) ──────────────────────────────────────── */

/* Purpose is inside the signed region, so a token minted to run a job cannot
 * be presented to fetch a result and vice versa. */
#define QIHSE_FABRIC_TOKEN_PURPOSE_RUN 1u
#define QIHSE_FABRIC_TOKEN_PURPOSE_FETCH 2u

/* The scope a token must carry.  These are the federation infrastructure
 * scopes (qihse_federation.h): a RUN writes on the peer, a FETCH reads.  The
 * executor requires the token's scope to be a SUBSET of the submitter node's
 * enrolled scopes, so a node cannot claim a scope it was never enrolled with. */
#define QIHSE_FABRIC_SCOPE_RUN QIHSE_SCOPE_FEDERATION_WRITE
#define QIHSE_FABRIC_SCOPE_FETCH QIHSE_SCOPE_FEDERATION_READ

typedef struct {
    uint16_t purpose;          /* QIHSE_FABRIC_TOKEN_PURPOSE_* */
    qihse_fabric_job_t job_type;
    uint32_t scope;            /* infra scope bits the submitter asserts */
    uint32_t principal_user_id;
    uint16_t clearance;        /* the principal's clearance AT THE SUBMITTER */
    uint16_t sci;              /* the principal's SCI compartments */
    uint32_t principal_tenant;
    qihse_uuid_t submitter_node;  /* node that issued the token */
    qihse_uuid_t nonce;           /* replay key; one use per purpose */
    uint64_t job_id;              /* bound to ONE job */
    uint64_t issued_ms;
    uint64_t expires_ms;
    uint32_t payload_len;         /* bound to the exact payload */
    uint8_t payload_digest[48];   /* SHA-384 of the payload bytes */
    qihse_sig_alg_t sig_alg;
    uint16_t signature_len;
} qihse_fabric_token_t;

typedef enum {
    QIHSE_FABRIC_TOKEN_OK = 0,
    QIHSE_FABRIC_TOKEN_MALFORMED,
    QIHSE_FABRIC_TOKEN_BAD_SIGNATURE,
    QIHSE_FABRIC_TOKEN_UNKNOWN_SUBMITTER,  /* no enrolled identity record */
    QIHSE_FABRIC_TOKEN_NOT_APPROVED,       /* enrolled but not APPROVED now */
    QIHSE_FABRIC_TOKEN_NODE_MISMATCH,      /* token's node != the TLS peer */
    QIHSE_FABRIC_TOKEN_ISSUED_IN_FUTURE,
    QIHSE_FABRIC_TOKEN_EXPIRED,
    QIHSE_FABRIC_TOKEN_TTL_TOO_LONG,
    QIHSE_FABRIC_TOKEN_SCOPE_REFUSED,
    QIHSE_FABRIC_TOKEN_WRONG_PURPOSE,
    QIHSE_FABRIC_TOKEN_JOB_MISMATCH,
    QIHSE_FABRIC_TOKEN_REPLAY,
    QIHSE_FABRIC_TOKEN_NO_CONTEXT,         /* NULL local context: fail closed */
    QIHSE_FABRIC_TOKEN_STORE_ERROR
} qihse_fabric_token_verdict_t;

const char* qihse_fabric_token_verdict_name(qihse_fabric_token_verdict_t v);

/* Serialize the signed region (no signature) — the bytes the signature covers. */
bool qihse_fabric_token_encode_region(const qihse_fabric_token_t* token,
                                      uint8_t* out, size_t out_cap, size_t* out_len);

/* Parse a token blob.  Validates magic, version, algorithm and every length
 * against the algorithm's fixed sizes BEFORE any copy, and returns the signed
 * region length and the total blob length so the caller can find the payload
 * that follows it.  Does NOT verify the signature: that is
 * qihse_fabric_token_check()'s job. */
bool qihse_fabric_token_parse(const uint8_t* blob, size_t blob_len,
                              qihse_fabric_token_t* out,
                              size_t* out_region_len, size_t* out_total_len);

/* Mint a token: fills the signature field and writes `region || signature`.
 * `pkey` is the submitter's loaded private key
 * (qihse_federation_node_key_load).  `nonce`/`issued_ms`/`expires_ms` must be
 * set by the caller; this function never invents a nonce, because a nonce
 * that two callers can collide on is not replay protection. */
bool qihse_fabric_token_mint(void* pkey, qihse_fabric_token_t* token,
                             uint8_t* out_blob, size_t out_cap, size_t* out_len);

/* What the executor requires of a token it is handed. */
typedef struct {
    qihse_uuid_t channel_peer;   /* from the mTLS handshake, never from the wire */
    uint16_t expect_purpose;
    qihse_fabric_job_t expect_job_type;
    uint64_t expect_job_id;
    const char* payload;         /* RUN: the payload whose digest is bound */
    size_t payload_len;
    uint32_t required_scope;
    uint64_t now_ms;
    bool consume;                /* record the nonce in the replay ledger */
} qihse_fabric_token_check_t;

/*
 * The complete verification the executor performs, in one place so no caller
 * can perform half of it:
 *
 *   1. structural parse (bounds before copies);
 *   2. the submitter node must have an ENROLLED, currently APPROVED identity;
 *   3. the signature must verify against THAT node's enrolled public key —
 *      the token's own key material is never trusted to describe itself;
 *   4. the token's node must equal the mTLS peer identity, so a token
 *      captured off the wire is useless without the node's private key;
 *   5. the lifetime window must be consistent and within the maximum;
 *   6. the token's scope must include the required scope AND be a subset of
 *      the submitter node's enrolled scopes;
 *   7. purpose, job id, job type and payload digest must match this request;
 *   8. the nonce must not have been used before (replay ledger), and if
 *      `consume` is set it is recorded now.
 *
 * `local_user` is the executor's own explicit context for the store reads
 * this performs.  NULL fails closed (QIHSE_FABRIC_TOKEN_NO_CONTEXT): the
 * refusal path has no bypass.
 *
 * `out_claims` receives the verified claims on success and is not written on
 * failure, so a caller cannot accidentally act on unverified claims.
 */
qihse_fabric_token_verdict_t qihse_fabric_token_check(
    void* store_void, qihse_user_t* local_user,
    const uint8_t* blob, size_t blob_len,
    const qihse_fabric_token_check_t* check,
    qihse_fabric_token_t* out_claims);

/* ── Executor side ──────────────────────────────────────────────────────── */

/* The executor's result record key for a job binding.  Deterministic, so a
 * retry of an idempotent job lands on the SAME record (which is what makes
 * the overwrite idempotent) and so a test can place a record directly. */
bool qihse_fabric_remote_result_key(const qihse_uuid_t* submitter_node,
                                    uint64_t job_id,
                                    char* out, size_t out_cap);

/* The executor's store key for a `keystone-ingest` artifact.  Same binding
 * rule: a retry overwrites this key and nothing else. */
bool qihse_fabric_remote_artifact_key(const qihse_uuid_t* submitter_node,
                                      uint64_t job_id,
                                      char* out, size_t out_cap);

typedef struct {
    qihse_resp_server_t* server;   /* store + the local executors */
    qihse_user_t* local_user;      /* explicit; NULL refuses every request */
    qihse_uuid_t local_node;
    const char* node_label;        /* audit attribution only */
} qihse_fabric_executor_t;

/*
 * Handle one RUN request body (`token || payload`).  The token is verified by
 * qihse_fabric_token_check() with purpose RUN; a refusal produces a refusal
 * body and NO job execution.
 *
 * Execution authority: the job's data operations are classified at, and
 * bounded by, the TOKEN's clearance/SCI — never the executor's.  Where an
 * executor cannot be given the classification explicitly (the `embed`
 * executor reads it from a qihse_user_t, and no local principal may stand in
 * for a remote one) a token above clearance 0 / SCI 0 is REFUSED with
 * `principal-not-representable` rather than run under the executor's own
 * principal.  `keystone-ingest` takes the classification as a parameter, so
 * it executes at any clearance the token claims.
 */
bool qihse_fabric_executor_run(qihse_fabric_executor_t* ex,
                               const uint8_t* body, size_t body_len,
                               qihse_uuid_t channel_peer,
                               char* out_body, size_t out_cap, size_t* out_len);

/*
 * Handle one FETCH request body (`token`).  The result record is read with
 * the token's clearance/SCI as the bound: a record above them is REFUSED and
 * no record bytes are returned.  Returns false only on a framing/store error;
 * a refusal is a successful call with a refusal body.
 */
bool qihse_fabric_executor_fetch(qihse_fabric_executor_t* ex,
                                 const uint8_t* body, size_t body_len,
                                 qihse_uuid_t channel_peer,
                                 char* out_body, size_t out_cap, size_t* out_len);

/* Serve one already-accepted, already-handshaked session: read one framed
 * request, dispatch it, write one framed response.  Used by the listener loop
 * and directly by tests. */
bool qihse_fabric_executor_serve_session(qihse_fabric_executor_t* ex,
                                         qihse_fed_tls_session_t* session);

/* ── Listener ───────────────────────────────────────────────────────────── */

typedef struct qihse_fabric_listener qihse_fabric_listener_t;

typedef struct {
    qihse_fed_tls_server_t* tls;   /* built by qihse_fabric_tls_context_create */
    qihse_fabric_executor_t executor;
    const char* bind_address;      /* REQUIRED; a wildcard bind is refused */
    uint16_t port;                 /* 0 = ephemeral */
    int accept_timeout_ms;         /* 0 = default */
} qihse_fabric_listener_config_t;

/*
 * Start the accept loop.  This is the production caller
 * qihse_federation_listener_open()/accept() did not have: without it the
 * transport's listener was dead code.  The loop accepts ONE connection at a
 * time, performs the mTLS handshake (peer refused => that connection only),
 * serves ONE request, closes, and repeats — so a peer cannot make the node
 * allocate a thread or a connection per request.
 */
qihse_fabric_listener_t* qihse_fabric_listener_start(const qihse_fabric_listener_config_t* cfg);
uint16_t qihse_fabric_listener_port(const qihse_fabric_listener_t* listener);
void qihse_fabric_listener_stop(qihse_fabric_listener_t* listener);
/* Connections accepted and served so far (health/telemetry). */
uint64_t qihse_fabric_listener_served(const qihse_fabric_listener_t* listener);

/* ── TLS context from PEM files ─────────────────────────────────────────── */

/*
 * Build the mTLS context fabric dispatch runs on.  The CA certificate is
 * loaded from a PEM file and its fingerprint recomputed from the loaded
 * certificate (a stored fingerprint is never trusted to describe the key it
 * is attached to).  The node's certificate is read from a PEM file; its
 * private key comes from the enrolled identity record's key handle, so the
 * private key never has to be passed around.
 */
bool qihse_fabric_tls_context_create(const char* ca_cert_path,
                                     const char* node_cert_path,
                                     const char* node_key_handle,
                                     void* store_void, qihse_user_t* user,
                                     qihse_fed_tls_server_t** out);

/* Load this node's APPROVED identity record and its private key.  Returns
 * false when the node is not enrolled/approved or the key is unreadable: a
 * node that cannot prove who it is cannot dispatch, and there is no
 * anonymous dispatch path. */
bool qihse_fabric_node_signer_load(void* store_void, qihse_user_t* user,
                                   const qihse_uuid_t* node_id,
                                   qihse_federation_node_identity_t* out_identity,
                                   void** out_pkey);

/* ── Submitter side ─────────────────────────────────────────────────────── */

typedef struct {
    /* Endpoint of the peer's dispatch listener. */
    const char* host;
    uint16_t port;
    int timeout_ms;
    qihse_fed_tls_server_t* tls;      /* the submitter's own mTLS context */
    void* pkey;                        /* the submitter's private key */
    qihse_uuid_t submitter_node;
    /* The job binding.  Retries reuse it; that is what makes an idempotent
     * retry an overwrite rather than a second job. */
    qihse_fabric_job_t job_type;
    uint64_t job_id;
    const char* payload;
    size_t payload_len;
    /* The principal's claims, taken from the authenticated submitter session. */
    uint32_t principal_user_id;
    uint16_t clearance;
    uint16_t sci;
    uint32_t principal_tenant;
    uint32_t scope;
    uint64_t ttl_ms;                   /* 0 = default */
} qihse_fabric_run_request_t;

typedef struct {
    bool answered;          /* the executor replied to at least one attempt */
    bool succeeded;         /* the executor's status was done/stored-unindexed */
    bool denied;            /* a terminal refusal: retrying cannot help */
    bool gave_up;           /* terminal: no definite answer, see reason */
    bool retried;
    unsigned attempts;
    /* Why it ended.  A COPY, not a pointer: the reason may come from the
     * executor's response, and a pointer into that would dangle. */
    char terminal_reason[64];
    char remote_status[32];       /* the executor's status word, verbatim */
    char result_ref[192];         /* the executor's result reference, if any */
    uint64_t remote_gen;
    char remote_digest[97];       /* SHA-384 of the executor's record */
    uint16_t remote_clearance;    /* classification of the record, as executed */
    uint16_t remote_sci;
    qihse_peer_verdict_t tls_verdict;
    /* The executor's response body.  Caller-provided so this struct stays
     * small enough to live on the stack. */
    char* body;
    size_t body_cap;
    size_t body_len;
} qihse_fabric_run_outcome_t;

/*
 * Dispatch one RUN, applying the retry policy:
 *
 *   - the type must DECLARE idempotency before a retry is attempted; a
 *     non-idempotent type is never retried, and an inconclusive attempt is
 *     terminal `gave-up` (retry refused), not `failed`;
 *   - an idempotent type is retried up to QIHSE_FABRIC_MAX_ATTEMPTS, each
 *     attempt with a FRESH nonce (the previous one may have been consumed by
 *     an attempt whose reply was lost, and a replayed nonce must be refused);
 *   - a definite executor answer of `failed` is terminal `failed`; a refusal
 *     (`denied`, `principal-not-representable`) is terminal and never retried.
 *
 * `now_ms` of 0 means "read the clock".  Returns false only on invalid
 * arguments.
 */
bool qihse_fabric_run(const qihse_fabric_run_request_t* req,
                      qihse_fabric_run_outcome_t* out);

/* A FETCH request.  Same binding, purpose FETCH. */
typedef struct {
    const char* host;
    uint16_t port;
    int timeout_ms;
    qihse_fed_tls_server_t* tls;
    void* pkey;
    qihse_uuid_t submitter_node;
    qihse_fabric_job_t job_type;
    uint64_t job_id;
    uint32_t principal_user_id;
    uint16_t clearance;
    uint16_t sci;
    uint32_t principal_tenant;
    uint32_t scope;
    uint64_t ttl_ms;
    /* The generation already cached, so a FETCH that would move the record
     * BACKWARDS can be refused instead of silently overwriting a newer
     * cache (see the coherence rule). */
    uint64_t cached_gen;
    bool have_cached_gen;
} qihse_fabric_fetch_request_t;

typedef struct {
    bool answered;
    bool refused;               /* the executor refused to disclose the record */
    char terminal_reason[64];
    uint64_t remote_gen;
    char remote_status[32];
    qihse_peer_verdict_t tls_verdict;
    char* body;
    size_t body_cap;
    size_t body_len;
} qihse_fabric_fetch_outcome_t;

bool qihse_fabric_fetch(const qihse_fabric_fetch_request_t* req,
                        qihse_fabric_fetch_outcome_t* out);

/* ── Response body parsing (both sides use the same fields) ─────────────── */

/* Parse the one-line status header of an executor response body.  A field
 * that is absent is left untouched, so a caller can pass defaults. */
typedef struct {
    char status[32];
    char type[32];
    char reason[64];
    char result[192];         /* the executor's result reference, or "-" */
    uint64_t job_id;
    uint64_t gen;
    uint16_t clearance;
    uint16_t sci;
    char digest[97];          /* SHA-384 of this body's payload section */
    char record_digest[97];   /* SHA-384 of the record the executor wrote, or "-" */
    uint64_t payload_len;
    size_t payload_offset;   /* where the record payload begins in the body */
} qihse_fabric_response_t;

bool qihse_fabric_response_parse(const char* body, size_t body_len,
                                 qihse_fabric_response_t* out);

/* SHA-384 of `len` bytes, hex-encoded (97 bytes with NUL).  Used for the
 * payload binding and for the cache coherence check. */
/* Writes 96 hex chars + NUL; `out_cap` must be >= 97. Returns false WITHOUT
 * WRITING when the capacity is insufficient, so a short buffer is refused
 * rather than overflowed. */
bool qihse_fabric_sha384_hex(const void* data, size_t len, char* out_hex, size_t out_cap);

/* The state words a job record can carry.  `queued` is placement without
 * dispatch; `pending-fetch` is dispatch without a pulled result; `gave-up` is
 * distinct from `failed` by design. */
#define QIHSE_FABRIC_STATE_QUEUED "queued"
#define QIHSE_FABRIC_STATE_DISPATCHED "dispatched"
#define QIHSE_FABRIC_STATE_PENDING_FETCH "pending-fetch"
#define QIHSE_FABRIC_STATE_DONE "done"
#define QIHSE_FABRIC_STATE_FAILED "failed"
#define QIHSE_FABRIC_STATE_GAVE_UP "gave-up"
#define QIHSE_FABRIC_STATE_DENIED "denied"
#define QIHSE_FABRIC_STATE_STALE "stale"
#define QIHSE_FABRIC_STATE_CACHE_CORRUPT "cache-corrupt"

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FABRIC_DISPATCH_H */
