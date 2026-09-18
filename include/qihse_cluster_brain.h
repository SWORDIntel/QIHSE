#ifndef QIHSE_CLUSTER_BRAIN_H
#define QIHSE_CLUSTER_BRAIN_H

/* Cluster brain — decision making for QIHSE clusters (phase 1 + actuation).
 *
 * Mines MEMSHADOW for the useful parts (persistent decision journal, health
 * monitoring with rollback, deterministic telemetry, signed records) without
 * the bloat. See docs/architecture/cluster_brain.md.
 *
 * Observe + remember + decide always run. Acting (R1 failed-owner re-home via
 * the audited slot-handoff path, with R4 rollback) runs only when `act` is
 * set: a brain that can act is a brain that can misact, so the journal earns
 * trust first. Every observation/decision is appended to a durable
 * qihse_event_stream (topic "cluster.brain") and decisions are signed with
 * the node's ML-DSA-87 key when one is configured.
 *
 * ── Federation journal (W3.4) ─────────────────────────────────────────────
 *
 * On top of that local journal, every observation and every decision is
 * published to the F2 federation event journal (topic "federation") with an
 * HLC stamp and a hash-chain link:
 *
 *   OBSERVATION  event_type "brain.observe", resource_id "brain/obs/<node>".
 *                The payload is the structured rule input (nodes, slot runs,
 *                the human-readable detail JSON, the observation sequence).
 *                Observations are NOT signed: they are one per cycle, and
 *                signing them would put a post-quantum signature on the hot
 *                path.  Their integrity comes from the journal's hash chain.
 *
 *   DECISION     event_type "brain.decision", resource_id
 *                "brain/decision/<action>".  The payload is an authenticated
 *                envelope: a length-prefixed region carrying the action, the
 *                evidence, the cited pre-condition and the signer's algorithm
 *                and key fingerprint, followed by the detached signature over
 *                that region.  The algorithm and signature length are inside
 *                the signed region, so an algorithm-downgrade edit invalidates
 *                the signature.  A decision cites the observation it was
 *                derived from (sequence, journal offset, chain hash and
 *                SHA-384 of the recorded observation bytes), which is what
 *                makes it reproducible from recorded inputs.
 *
 * Decisions that commit cluster state (rehome, rebalance, rollback, prune and
 * the confirmation of a completed hand-off) are signed and are refused
 * outright when there is no journaled pre-condition to cite — see
 * qihse_cluster_brain_precondition_ok().  Policy observations (asymmetry,
 * isolation, reconnection) and refusals are journaled with the same envelope
 * but unsigned, because they do not change cluster state and occur once per
 * cycle.  Quarantine is a policy decision, journaled signed on the transition
 * into and out of the asymmetric state (once per incident, not per cycle);
 * the brain does not fence the node — see ROADMAP W3.7.
 *
 * The private key is NEVER journaled: records carry a key handle and the
 * SHA-384 fingerprint of the public key only.
 *
 * Nothing here is a prerequisite for local operation: a brain without a
 * federation journal still observes, journals locally, and refuses to act.
 */

#include <stdbool.h>
#include <stdint.h>
#include "qihse_resp_wire.h"
#include "qihse_federation.h" /* qihse_hlc_t, qihse_sig_alg_t */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    qihse_resp_server_t* server;
    const char* journal_dir;        /* event-stream directory (created) */
    const char* dsa_key_path;       /* ML-DSA-87 signing key (NULL = unsigned) */
    uint32_t interval_seconds;      /* observation cadence (default 5) */
    bool act;                       /* false = observe/journal/decide only */
    uint32_t act_cooldown_seconds;  /* per-range re-home cooldown (default 30) */
    uint32_t rollback_window_seconds; /* R4 evaluation window (default 60) */
    uint32_t prune_timeout_seconds;   /* prune a node unhealthy this long (0 = never) */
    uint32_t rebalance_min_slots;     /* donate a proportional range to a slotless
                                       * joiner when the largest owner holds at
                                       * least this many slots (0 = disabled) */
    const char* federation_journal_dir; /* federation event journal directory;
                                         * NULL = journal_dir (topic "federation") */
    const char* node_key_handle;        /* federation node identity private key
                                         * handle used to sign decisions; NULL =
                                         * dsa_key_path when that is set.  The
                                         * handle is journaled, the key never is. */
} qihse_brain_config_t;

/* Start the brain thread. Returns false on allocation/startup failure. */
bool qihse_cluster_brain_start(const qihse_brain_config_t* config);

/* Stop the brain thread and flush the journal. MUST be called before the
 * server topology is freed — the brain references it every cycle. */
void qihse_cluster_brain_stop(void);

/* ── Pre-condition gate (W3.4) ─────────────────────────────────────────────
 *
 * "No action without a journaled pre-condition": an observation is a
 * pre-condition only when it is on the federation journal and the brain has
 * consumed it back through the watch stream (so the rules acted on the
 * recorded bytes, not on a private copy).  A cycle in which the observation
 * could not be journaled, could not be read back, or did not round-trip to
 * the same rule input yields `valid = false`.
 *
 * Every rule that commits cluster state passes through
 * qihse_cluster_brain_precondition_ok() before it touches the topology or the
 * data path.  A false return means the action MUST NOT be taken; the brain
 * journals the refusal as "DECISION_REFUSED" on the local journal.
 */
typedef struct {
    bool valid;                    /* false = no journaled observation */
    uint64_t journal_offset;       /* federation journal offset of the observation */
    uint64_t observation_seq;      /* per-brain observation sequence */
    qihse_hlc_t hlc;               /* HLC stamp the journal assigned */
    uint8_t observation_hash[48];  /* journal hash-chain link */
    uint8_t payload_digest[48];    /* SHA-384 of the recorded observation bytes */
} qihse_brain_precondition_t;

/* The gate.  Returns false for NULL, for `valid = false`, and for a
 * pre-condition whose journal offset or hash is unset. */
bool qihse_cluster_brain_precondition_ok(const qihse_brain_precondition_t* pre);

/* ── Decision envelope inspection and verification (W3.4) ──────────────────
 *
 * Both take the payload bytes as recorded on the federation journal (the
 * `payload` handed to a journal replay callback).  They exist so a consumer
 * replaying the journal — a test, an operator tool, a future replayer — does
 * not have to reimplement the record format.
 */

/* Verify a decision envelope against a raw public key.  The fingerprint
 * carried in the envelope is recomputed from `public_key` and must match (a
 * stored fingerprint is never trusted to describe the key it is attached
 * to), and an unsigned envelope is refused. */
bool qihse_cluster_brain_decision_verify(const uint8_t* public_key, size_t public_key_len,
                                         const uint8_t* envelope, size_t envelope_len);

/* Read a decision envelope's action, signature state and cited pre-condition.
 * `out_action` receives the action name; `out_precondition` may be NULL. */
bool qihse_cluster_brain_decision_inspect(const uint8_t* envelope, size_t envelope_len,
                                          char* out_action, size_t action_cap,
                                          qihse_brain_precondition_t* out_precondition);

/* True when the envelope carries a signature (its signature length is the
 * algorithm's, and the key fingerprint is set). */
bool qihse_cluster_brain_decision_is_signed(const uint8_t* envelope, size_t envelope_len);

/* Record kind strings, so a consumer can filter without string literals. */
#define QIHSE_BRAIN_FED_EVENT_OBSERVE  "brain.observe"
#define QIHSE_BRAIN_FED_EVENT_DECISION "brain.decision"
#define QIHSE_BRAIN_FED_OBS_PREFIX     "brain/obs/"
#define QIHSE_BRAIN_FED_DECISION_PREFIX "brain/decision/"

/* ── Record layout (little-endian) ────────────────────────────────────────
 *
 * OBSERVATION payload: 40-byte header, then the node records, the slot runs
 * and the detail JSON.  A consumer that only wants the human-readable part
 * needs the last field (detail_len) and the payload length.
 *
 *   off size  field                off size  field
 *    0   4   magic "QHBO"          24   4   workers
 *    4   2   format version        28   4   node count
 *    6   2   local node index      32   4   run count
 *    8   8   observation sequence  36   4   detail JSON length
 *   16   8   triage time (us)
 *
 *   then node_count x 313-byte node records, run_count x 8-byte runs
 *   (owner, start, end, reserved), then detail_len bytes of JSON.
 *
 * DECISION payload: 192-byte header, then the variable-length fields, then
 * the detached signature over every byte before it.
 *
 *   off size  field                off size  field
 *    0   4   magic "QHBD"          44   4   evidence length
 *    4   2   format version        48  48   cited observation chain hash
 *    6   2   signature algorithm   96  48   SHA-384 of the recorded
 *    8   2   signature length     144  48   observation payload, and the
 *   10   2   action length                 signer public-key fingerprint
 *   12   2   key handle length   192  ..   action, key handle, evidence,
 *   14   2   flags (bit0 = cited            then the signature
 *           pre-condition valid)
 *   16   8   cited observation sequence
 *   24   8   cited observation journal offset
 *   32   8   cited observation HLC physical
 *   40   4   cited observation HLC logical
 *
 * The algorithm and the signature length are INSIDE the signed region, so an
 * algorithm-downgrade edit invalidates the signature. */
#define QIHSE_BRAIN_OBS_HEADER_BYTES      40u
#define QIHSE_BRAIN_DECISION_HEADER_BYTES 192u

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_BRAIN_H */
