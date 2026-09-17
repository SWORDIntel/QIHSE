#ifndef QIHSE_RUNTIME_TRUST_H
#define QIHSE_RUNTIME_TRUST_H

/*
 * QIHSE runtime trust and time integrity — federation stage F7.
 * See v3.md §35 (evidence-aware federation admission) and §38 (time
 * integrity and trusted ordering).
 *
 * A valid node certificate proves identity, not current trustworthiness.
 * Admission therefore evaluates a runtime trust evidence bundle: what image
 * the node booted, which QIHSE artifact it is running, whether that artifact
 * has a verified SBOM and provenance attestation, and how its hardening
 * audit came out.
 *
 * QIHSE STORES this evidence and EVALUATES it against policy.  It does not
 * fabricate evidence and does not self-approve (v3.md §35).
 *
 * Critical principle: a failed provenance or attestation check must not
 * destroy local availability, but it must be able to remove the node from
 * trusted distributed authority.  `local_usable` therefore stays true for
 * every trust state.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Runtime trust states (v3.md §35) ──────────────────────────────────── */

typedef enum {
    QIHSE_RTRUST_UNKNOWN = 0,      /* no evidence evaluated yet */
    QIHSE_RTRUST_TRUSTED,          /* may participate per configured role */
    QIHSE_RTRUST_TRUSTED_DEGRADED, /* reads + selected replication allowed */
    QIHSE_RTRUST_LOCAL_ONLY,       /* local DB usable; no federation authority */
    QIHSE_RTRUST_QUARANTINED,      /* forensic/repair access only */
    QIHSE_RTRUST_REVOKED           /* federation access denied */
} qihse_runtime_trust_t;

const char* qihse_runtime_trust_name(qihse_runtime_trust_t state);
bool qihse_runtime_trust_parse(const char* name, qihse_runtime_trust_t* out);

/* ── Runtime trust evidence bundle (v3.md §35) ─────────────────────────── */

#define QIHSE_RTRUST_DIGEST_MAX 128u
#define QIHSE_RTRUST_ID_MAX 128u

typedef struct {
    qihse_uuid_t node_id;
    qihse_uuid_t boot_id;
    char citadel_release[QIHSE_RTRUST_ID_MAX + 1u];   /* Citadel release/image id */
    char root_image_digest[QIHSE_RTRUST_DIGEST_MAX + 1u];
    char qihse_artifact_digest[QIHSE_RTRUST_DIGEST_MAX + 1u];
    char qihse_sbom_digest[QIHSE_RTRUST_DIGEST_MAX + 1u];
    char qihse_provenance_digest[QIHSE_RTRUST_DIGEST_MAX + 1u];
    char kernel_image[QIHSE_RTRUST_ID_MAX + 1u];
    char xen_image[QIHSE_RTRUST_ID_MAX + 1u];
    char measured_boot_state[QIHSE_RTRUST_ID_MAX + 1u];
    char tpm_attestation_ref[QIHSE_RTRUST_ID_MAX + 1u];
    uint64_t policy_generation;
    uint64_t hardening_audit_generation;
    uint64_t collected_hlc_physical;
} qihse_trust_evidence_t;

#define QIHSE_RTRUST_EVIDENCE_PREFIX "rtrust/evidence:"

/* Store an evidence bundle exactly as the node reported it.  QIHSE does not
 * fabricate or mutate evidence; a repeated bundle for the same
 * (node, boot, policy generation) is refused so the record stays immutable. */
bool qihse_trust_evidence_put(void* store_void, void* user_void,
                              const qihse_trust_evidence_t* evidence);
bool qihse_trust_evidence_get(void* store_void, void* user_void,
                              const qihse_uuid_t* node_id, const qihse_uuid_t* boot_id,
                              qihse_trust_evidence_t* out);

/* ── Verification result (v3.md §35) ───────────────────────────────────── */

typedef struct {
    qihse_uuid_t node_id;
    qihse_runtime_trust_t trust_state;
    uint64_t trust_policy_generation;
    qihse_uuid_t evidence_bundle_id;   /* == boot_id of the evaluated bundle */
    uint64_t evidence_verified_hlc_physical;
    qihse_uuid_t verification_principal;
    char verification_result[64];      /* e.g. "provenance_ok", "sbom_missing" */
} qihse_trust_verification_t;

#define QIHSE_RTRUST_STATE_PREFIX "rtrust/state:"

/* Record the outcome of evaluating evidence against policy.  This is the
 * external verifier's decision (Citadel/attestation), not QIHSE's.
 *
 * Effects on distributed authority are derived from the trust state by
 * qihse_runtime_admission_evaluate(); a change that reduces authority emits
 * an immutable audit event through the F2 journal. */
bool qihse_trust_verification_put(void* store_void, void* user_void,
                                  const qihse_trust_verification_t* verification,
                                  void* journal_void);
bool qihse_trust_verification_get(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id,
                                  qihse_trust_verification_t* out);

/* ── Admission decision (v3.md §35, acceptance criterion 23) ───────────── */

typedef struct {
    qihse_runtime_trust_t trust_state;
    bool local_usable;      /* ALWAYS true — never gated on federation trust */
    bool may_replicate;     /* may exchange federation state at all */
    bool may_read_remote;   /* may read peer state */
    bool may_strong_write;  /* may perform strong/exclusive mutations */
    bool may_vote;          /* eligible to be a consensus voter */
    char reason[96];
} qihse_admission_t;

/* Evaluate what a node is permitted to do given its trust state.
 *
 * The mapping is deliberately total and explicit: every state yields a
 * complete decision, and `local_usable` is true in all of them. */
void qihse_runtime_admission_evaluate(qihse_runtime_trust_t trust, qihse_admission_t* out);

/* Convenience: look up a node's recorded trust state and evaluate it.  A node
 * with no verification record is UNKNOWN. */
bool qihse_runtime_admission_for_node(void* store_void, void* user_void,
                                      const qihse_uuid_t* node_id,
                                      qihse_admission_t* out);

/* ── Time integrity (v3.md §38, acceptance criterion 27) ───────────────── */

typedef enum {
    QIHSE_TIME_OK = 0,
    QIHSE_TIME_BACKWARD_JUMP,       /* wall clock moved backwards */
    QIHSE_TIME_FORWARD_JUMP,        /* large forward wall-clock jump */
    QIHSE_TIME_MONOTONIC_REGRESSION,/* monotonic clock went backwards */
    QIHSE_TIME_WALL_MONO_INCONSISTENT, /* wall moved but monotonic did not */
    QIHSE_TIME_SYNC_LOST
} qihse_time_anomaly_t;

const char* qihse_time_anomaly_name(qihse_time_anomaly_t anomaly);

/* Thresholds for anomaly detection.  Values are in milliseconds. */
typedef struct {
    uint64_t forward_jump_threshold_ms;  /* default 5 minutes */
    uint64_t backward_jump_threshold_ms; /* default 1 second of tolerance */
    uint64_t peer_skew_threshold_ms;     /* default 30 seconds */
} qihse_time_policy_t;

void qihse_time_policy_init(qihse_time_policy_t* policy);

typedef struct {
    uint64_t last_wall_ms;
    uint64_t last_mono_ms;
    uint64_t wall_jumps;
    uint64_t monotonic_regressions;
    uint64_t sync_losses;
    uint64_t observed;
    bool synced;
} qihse_time_monitor_t;

void qihse_time_monitor_init(qihse_time_monitor_t* mon);

/* Feed a (monotonic, wall) sample pair.  Returns the anomaly detected, or
 * QIHSE_TIME_OK.  The monitor NEVER adjusts the HLC — it only reports.  A
 * wall-clock anomaly must not break ordering, so callers keep using the HLC
 * for correctness and treat this purely as diagnostic state. */
qihse_time_anomaly_t qihse_time_monitor_observe(qihse_time_monitor_t* mon,
                                                const qihse_time_policy_t* policy,
                                                uint64_t mono_ms, uint64_t wall_ms);

/* Record loss/restoration of authenticated time sync.  Returns the anomaly
 * to emit (SYNC_LOST on a transition into the lost state, OK otherwise). */
qihse_time_anomaly_t qihse_time_monitor_set_synced(qihse_time_monitor_t* mon, bool synced);

/* Compute peer clock skew and classify it. */
qihse_time_anomaly_t qihse_time_check_peer_skew(const qihse_time_policy_t* policy,
                                                uint64_t local_wall_ms, uint64_t peer_wall_ms);

/* ── HLC monotonicity under anomalies (acceptance criterion 27) ─────────── */

/* Advance an HLC using a wall-clock reading that may be WRONG (backwards or
 * far forwards).  The returned HLC is guaranteed to be strictly greater than
 * the input, so a wall-clock anomaly can never break ordering.  The physical
 * component is still taken from the wall clock when it moves forward, which
 * keeps HLCs meaningful for humans; the logical counter carries the ordering
 * guarantee. */
qihse_hlc_t qihse_hlc_advance_safe(const qihse_hlc_t* prev, uint64_t wall_ms);

/* Merge a remote HLC (as on receive), tolerating skew. */
qihse_hlc_t qihse_hlc_merge_safe(const qihse_hlc_t* local, const qihse_hlc_t* remote,
                                 uint64_t local_wall_ms);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_RUNTIME_TRUST_H */
