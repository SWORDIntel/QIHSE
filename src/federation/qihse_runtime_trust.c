/*
 * QIHSE runtime trust and time integrity — federation stage F7.
 * See v3.md §35 (evidence-aware federation admission) and §38 (time
 * integrity and trusted ordering).
 */
#include "qihse_runtime_trust.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "qihse_event_stream.h"
#include "qihse_kv_store.h"

/* ── Runtime trust states ──────────────────────────────────────────────── */

typedef struct { qihse_runtime_trust_t v; const char* name; } rtrust_entry_t;

static const rtrust_entry_t g_rtrust_states[] = {
    { QIHSE_RTRUST_UNKNOWN,          "UNKNOWN"          },
    { QIHSE_RTRUST_TRUSTED,          "TRUSTED"          },
    { QIHSE_RTRUST_TRUSTED_DEGRADED, "TRUSTED_DEGRADED" },
    { QIHSE_RTRUST_LOCAL_ONLY,       "LOCAL_ONLY"       },
    { QIHSE_RTRUST_QUARANTINED,      "QUARANTINED"      },
    { QIHSE_RTRUST_REVOKED,          "REVOKED"          },
};

const char* qihse_runtime_trust_name(qihse_runtime_trust_t state) {
    for (size_t i = 0; i < sizeof(g_rtrust_states) / sizeof(g_rtrust_states[0]); i++) {
        if (g_rtrust_states[i].v == state) return g_rtrust_states[i].name;
    }
    return "UNKNOWN";
}

bool qihse_runtime_trust_parse(const char* name, qihse_runtime_trust_t* out) {
    if (!name || !out) return false;
    for (size_t i = 0; i < sizeof(g_rtrust_states) / sizeof(g_rtrust_states[0]); i++) {
        if (strcasecmp(g_rtrust_states[i].name, name) == 0) {
            *out = g_rtrust_states[i].v;
            return true;
        }
    }
    return false;
}

/* ── Record encoding helpers ───────────────────────────────────────────── */

/* Records are tab-separated and many fields are legitimately empty (a node
 * with no TPM, a build with no Xen image).  sscanf's "%[^\t]" cannot match an
 * empty field, so decoders walk the record with this splitter.  Returns the
 * start of the next field, or NULL when the record is exhausted. */
static const char* rt_next_field(const char* p, char* out, size_t cap) {
    if (!p) { if (cap) out[0] = '\0'; return NULL; }
    const char* start = p;
    while (*p && *p != '\t') p++;
    size_t len = (size_t)(p - start);
    if (len >= cap) len = cap - 1u;
    if (cap) { memcpy(out, start, len); out[len] = '\0'; }
    return (*p == '\t') ? p + 1 : NULL;
}

static void rt_uuid_hex(const qihse_uuid_t* u, char* out) {
    const uint8_t* b = (const uint8_t*)u;
    for (int i = 0; i < 16; i++) snprintf(out + i * 2, 3, "%02x", b[i]);
    out[32] = '\0';
}

static bool rt_uuid_from_hex(const char* hex, qihse_uuid_t* out) {
    if (!hex || strlen(hex) != 32u) return false;
    uint8_t* b = (uint8_t*)out;
    for (int i = 0; i < 16; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return false;
        b[i] = (uint8_t)byte;
    }
    return true;
}

static pthread_mutex_t g_rtrust_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Evidence bundles ──────────────────────────────────────────────────── */

static void evidence_key(const qihse_uuid_t* node_id, const qihse_uuid_t* boot_id,
                         char* out, size_t cap) {
    char n[33], b[33];
    rt_uuid_hex(node_id, n);
    rt_uuid_hex(boot_id, b);
    snprintf(out, cap, QIHSE_RTRUST_EVIDENCE_PREFIX "%s:%s", n, b);
}

static void evidence_encode(const qihse_trust_evidence_t* e, char* out, size_t cap) {
    char n[33], b[33];
    rt_uuid_hex(&e->node_id, n);
    rt_uuid_hex(&e->boot_id, b);
    snprintf(out, cap, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%llu\t%llu\t%llu",
             n, b, e->citadel_release, e->root_image_digest,
             e->qihse_artifact_digest, e->qihse_sbom_digest, e->qihse_provenance_digest,
             e->kernel_image, e->xen_image, e->measured_boot_state,
             e->tpm_attestation_ref,
             (unsigned long long)e->policy_generation,
             (unsigned long long)e->hardening_audit_generation,
             (unsigned long long)e->collected_hlc_physical);
}

static bool evidence_decode(const char* blob, qihse_trust_evidence_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char f[14][QIHSE_RTRUST_DIGEST_MAX + 1u];
    const char* p = blob;
    for (size_t i = 0; i < 14u; i++) p = rt_next_field(p, f[i], sizeof(f[i]));
    if (!rt_uuid_from_hex(f[0], &out->node_id)) return false;
    if (!rt_uuid_from_hex(f[1], &out->boot_id)) return false;
    snprintf(out->citadel_release, sizeof(out->citadel_release), "%s", f[2]);
    snprintf(out->root_image_digest, sizeof(out->root_image_digest), "%s", f[3]);
    snprintf(out->qihse_artifact_digest, sizeof(out->qihse_artifact_digest), "%s", f[4]);
    snprintf(out->qihse_sbom_digest, sizeof(out->qihse_sbom_digest), "%s", f[5]);
    snprintf(out->qihse_provenance_digest, sizeof(out->qihse_provenance_digest), "%s", f[6]);
    snprintf(out->kernel_image, sizeof(out->kernel_image), "%s", f[7]);
    snprintf(out->xen_image, sizeof(out->xen_image), "%s", f[8]);
    snprintf(out->measured_boot_state, sizeof(out->measured_boot_state), "%s", f[9]);
    snprintf(out->tpm_attestation_ref, sizeof(out->tpm_attestation_ref), "%s", f[10]);
    out->policy_generation = (uint64_t)strtoull(f[11], NULL, 10);
    out->hardening_audit_generation = (uint64_t)strtoull(f[12], NULL, 10);
    out->collected_hlc_physical = (uint64_t)strtoull(f[13], NULL, 10);
    return true;
}

bool qihse_trust_evidence_put(void* store_void, void* user_void,
                              const qihse_trust_evidence_t* evidence) {
    if (!store_void || !user_void || !evidence) return false;
    char key[192];
    evidence_key(&evidence->node_id, &evidence->boot_id, key, sizeof(key));

    pthread_mutex_lock(&g_rtrust_lock);
    /* Evidence is immutable: a node reports a bundle once per boot.  A repeat
     * is refused rather than silently overwriting what was verified. */
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) {
        free(existing);
        pthread_mutex_unlock(&g_rtrust_lock);
        return false;
    }
    char blob[4096];
    evidence_encode(evidence, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_rtrust_lock);
    return ok;
}

bool qihse_trust_evidence_get(void* store_void, void* user_void,
                              const qihse_uuid_t* node_id, const qihse_uuid_t* boot_id,
                              qihse_trust_evidence_t* out) {
    if (!store_void || !user_void || !node_id || !boot_id || !out) return false;
    char key[192];
    evidence_key(node_id, boot_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = evidence_decode(blob, out);
    free(blob);
    return ok;
}

/* ── Verification records ──────────────────────────────────────────────── */

static void state_key(const qihse_uuid_t* node_id, char* out, size_t cap) {
    char n[33];
    rt_uuid_hex(node_id, n);
    snprintf(out, cap, QIHSE_RTRUST_STATE_PREFIX "%s", n);
}

static void verification_encode(const qihse_trust_verification_t* v, char* out, size_t cap) {
    char n[33], e[33], p[33];
    rt_uuid_hex(&v->node_id, n);
    rt_uuid_hex(&v->evidence_bundle_id, e);
    rt_uuid_hex(&v->verification_principal, p);
    snprintf(out, cap, "%s\t%u\t%llu\t%s\t%llu\t%s\t%s",
             n, (unsigned)v->trust_state,
             (unsigned long long)v->trust_policy_generation,
             e, (unsigned long long)v->evidence_verified_hlc_physical,
             p, v->verification_result);
}

static bool verification_decode(const char* blob, qihse_trust_verification_t* out) {
    if (!blob || !out) return false;
    memset(out, 0, sizeof(*out));
    char f[7][160];
    const char* p = blob;
    for (size_t i = 0; i < 7u; i++) p = rt_next_field(p, f[i], sizeof(f[i]));
    if (!rt_uuid_from_hex(f[0], &out->node_id)) return false;
    uint64_t trust_raw = strtoull(f[1], NULL, 10);
    if (trust_raw > (uint64_t)QIHSE_RTRUST_REVOKED) return false;
    out->trust_state = (qihse_runtime_trust_t)trust_raw;
    out->trust_policy_generation = (uint64_t)strtoull(f[2], NULL, 10);
    (void)rt_uuid_from_hex(f[3], &out->evidence_bundle_id);
    out->evidence_verified_hlc_physical = (uint64_t)strtoull(f[4], NULL, 10);
    (void)rt_uuid_from_hex(f[5], &out->verification_principal);
    snprintf(out->verification_result, sizeof(out->verification_result), "%s", f[6]);
    return true;
}

/* Append an audit event to the F2 journal when distributed authority changes.
 * A trust change is exactly the kind of control-plane transition the journal
 * exists to make reconstructable (v3.md §35: "Changes in trust state must
 * emit immutable audit events"). */
static void emit_trust_event(void* journal_void, void* user_void,
                             const qihse_trust_verification_t* v,
                             qihse_runtime_trust_t previous) {
    if (!journal_void) return;
    qihse_federation_journal_t* journal = (qihse_federation_journal_t*)journal_void;
    qihse_federation_mutation_t m;
    memset(&m, 0, sizeof(m));
    m.principal_id = v->verification_principal;
    m.origin_node = v->node_id;
    m.consistency = QIHSE_CONSISTENCY_QUORUM;
    m.fencing_epoch = v->trust_policy_generation;
    m.expected_generation = (uint64_t)previous;

    char payload[256];
    snprintf(payload, sizeof(payload), "{\"from\":\"%s\",\"to\":\"%s\",\"result\":\"%s\"}",
             qihse_runtime_trust_name(previous),
             qihse_runtime_trust_name(v->trust_state),
             v->verification_result);

    char resource[96];
    char n[33];
    rt_uuid_hex(&v->node_id, n);
    snprintf(resource, sizeof(resource), "federation/node/%s", n);

    qihse_federation_event_t ev;
    (void)qihse_federation_journal_append(journal, &m, "trust.state.changed",
                                          resource, (const uint8_t*)payload,
                                          strlen(payload), &ev);
}

bool qihse_trust_verification_put(void* store_void, void* user_void,
                                  const qihse_trust_verification_t* verification,
                                  void* journal_void) {
    if (!store_void || !user_void || !verification) return false;
    char key[160];
    state_key(&verification->node_id, key, sizeof(key));

    pthread_mutex_lock(&g_rtrust_lock);
    qihse_runtime_trust_t previous = QIHSE_RTRUST_UNKNOWN;
    char* existing = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                       (qihse_user_t*)user_void);
    if (existing) {
        qihse_trust_verification_t prev_rec;
        if (verification_decode(existing, &prev_rec)) previous = prev_rec.trust_state;
        free(existing);
    }
    char blob[1024];
    verification_encode(verification, blob, sizeof(blob));
    bool ok = qihse_kv_set_user((qihse_kv_store_t*)store_void, key, blob, 0, 0,
                                (qihse_user_t*)user_void);
    pthread_mutex_unlock(&g_rtrust_lock);

    if (ok && previous != verification->trust_state) {
        emit_trust_event(journal_void, user_void, verification, previous);
    }
    return ok;
}

bool qihse_trust_verification_get(void* store_void, void* user_void,
                                  const qihse_uuid_t* node_id,
                                  qihse_trust_verification_t* out) {
    if (!store_void || !user_void || !node_id || !out) return false;
    char key[160];
    state_key(node_id, key, sizeof(key));
    char* blob = qihse_kv_get_user((qihse_kv_store_t*)store_void, key,
                                   (qihse_user_t*)user_void);
    if (!blob) return false;
    bool ok = verification_decode(blob, out);
    free(blob);
    /* The body's node id must agree with the key. */
    if (ok && !qihse_uuid_equal(&out->node_id, node_id)) return false;
    return ok;
}

/* ── Admission (v3.md §35, criterion 23) ───────────────────────────────── */

void qihse_runtime_admission_evaluate(qihse_runtime_trust_t trust, qihse_admission_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->trust_state = trust;
    /* A node's own database is never gated on federation trust.  This is the
     * governing architectural principle in code form. */
    out->local_usable = true;

    switch (trust) {
        case QIHSE_RTRUST_TRUSTED:
            out->may_replicate = true;
            out->may_read_remote = true;
            out->may_strong_write = true;
            out->may_vote = true;
            snprintf(out->reason, sizeof(out->reason), "trusted");
            break;
        case QIHSE_RTRUST_TRUSTED_DEGRADED:
            out->may_replicate = true;
            out->may_read_remote = true;
            /* Strong-write and voter eligibility are policy-dependent; the
             * conservative default is to withhold them. */
            out->may_strong_write = false;
            out->may_vote = false;
            snprintf(out->reason, sizeof(out->reason), "degraded: no strong-write or vote");
            break;
        case QIHSE_RTRUST_LOCAL_ONLY:
            out->may_replicate = false;
            out->may_read_remote = false;
            out->may_strong_write = false;
            out->may_vote = false;
            snprintf(out->reason, sizeof(out->reason), "local-only: no federation authority");
            break;
        case QIHSE_RTRUST_QUARANTINED:
            /* Forensic/repair access only: the node may not exchange
             * federation state at all. */
            out->may_replicate = false;
            out->may_read_remote = false;
            out->may_strong_write = false;
            out->may_vote = false;
            snprintf(out->reason, sizeof(out->reason), "quarantined: forensic access only");
            break;
        case QIHSE_RTRUST_REVOKED:
            out->may_replicate = false;
            out->may_read_remote = false;
            out->may_strong_write = false;
            out->may_vote = false;
            snprintf(out->reason, sizeof(out->reason), "revoked: federation access denied");
            break;
        case QIHSE_RTRUST_UNKNOWN:
        default:
            out->may_replicate = false;
            out->may_read_remote = false;
            out->may_strong_write = false;
            out->may_vote = false;
            snprintf(out->reason, sizeof(out->reason), "no verified evidence");
            break;
    }
}

bool qihse_runtime_admission_for_node(void* store_void, void* user_void,
                                      const qihse_uuid_t* node_id,
                                      qihse_admission_t* out) {
    if (!store_void || !user_void || !node_id || !out) return false;
    qihse_trust_verification_t v;
    qihse_runtime_trust_t trust = QIHSE_RTRUST_UNKNOWN;
    if (qihse_trust_verification_get(store_void, user_void, node_id, &v)) {
        trust = v.trust_state;
    }
    qihse_runtime_admission_evaluate(trust, out);
    return true;
}

/* ── Time integrity (v3.md §38) ────────────────────────────────────────── */

typedef struct { qihse_time_anomaly_t v; const char* name; } time_anomaly_entry_t;

static const time_anomaly_entry_t g_time_anomalies[] = {
    { QIHSE_TIME_OK,                    "OK"                     },
    { QIHSE_TIME_BACKWARD_JUMP,         "time.wall_jump_backward" },
    { QIHSE_TIME_FORWARD_JUMP,          "time.wall_jump_forward"  },
    { QIHSE_TIME_MONOTONIC_REGRESSION,  "time.monotonic_regression" },
    { QIHSE_TIME_WALL_MONO_INCONSISTENT, "time.wall_mono_inconsistent" },
    { QIHSE_TIME_SYNC_LOST,             "time.sync_lost"          },
};

const char* qihse_time_anomaly_name(qihse_time_anomaly_t anomaly) {
    for (size_t i = 0; i < sizeof(g_time_anomalies) / sizeof(g_time_anomalies[0]); i++) {
        if (g_time_anomalies[i].v == anomaly) return g_time_anomalies[i].name;
    }
    return "time.unknown";
}

void qihse_time_policy_init(qihse_time_policy_t* policy) {
    if (!policy) return;
    policy->forward_jump_threshold_ms = 5u * 60u * 1000u;   /* 5 minutes */
    policy->backward_jump_threshold_ms = 1000u;             /* 1 second */
    policy->peer_skew_threshold_ms = 30u * 1000u;           /* 30 seconds */
}

void qihse_time_monitor_init(qihse_time_monitor_t* mon) {
    if (!mon) return;
    memset(mon, 0, sizeof(*mon));
    mon->synced = true;
}

qihse_time_anomaly_t qihse_time_monitor_observe(qihse_time_monitor_t* mon,
                                                const qihse_time_policy_t* policy,
                                                uint64_t mono_ms, uint64_t wall_ms) {
    if (!mon) return QIHSE_TIME_OK;
    qihse_time_policy_t defaults;
    if (!policy) {
        qihse_time_policy_init(&defaults);
        policy = &defaults;
    }

    mon->observed++;
    qihse_time_anomaly_t anomaly = QIHSE_TIME_OK;

    if (mon->observed > 1u) {
        /* The monotonic clock must never regress.  If it does, something is
         * badly wrong with the platform and ordering guarantees need
         * re-establishing from the HLC's logical component. */
        if (mono_ms < mon->last_mono_ms) {
            anomaly = QIHSE_TIME_MONOTONIC_REGRESSION;
            mon->monotonic_regressions++;
        } else if (wall_ms + policy->backward_jump_threshold_ms < mon->last_wall_ms) {
            anomaly = QIHSE_TIME_BACKWARD_JUMP;
            mon->wall_jumps++;
        } else if (wall_ms > mon->last_wall_ms + policy->forward_jump_threshold_ms) {
            anomaly = QIHSE_TIME_FORWARD_JUMP;
            mon->wall_jumps++;
        } else if (wall_ms != mon->last_wall_ms && mono_ms == mon->last_mono_ms) {
            /* Wall clock moved while the monotonic clock stood still: the wall
             * reading was adjusted by something other than elapsed time. */
            anomaly = QIHSE_TIME_WALL_MONO_INCONSISTENT;
            mon->wall_jumps++;
        }
    }

    /* Only advance the stored baseline when the sample is sane, so a single
     * bad reading cannot poison subsequent comparisons. */
    if (anomaly == QIHSE_TIME_OK) {
        mon->last_wall_ms = wall_ms;
        mon->last_mono_ms = mono_ms;
    } else if (mono_ms > mon->last_mono_ms) {
        mon->last_mono_ms = mono_ms;
        if (wall_ms > mon->last_wall_ms && wall_ms < mon->last_wall_ms + policy->forward_jump_threshold_ms) {
            mon->last_wall_ms = wall_ms;
        }
    }
    return anomaly;
}

qihse_time_anomaly_t qihse_time_monitor_set_synced(qihse_time_monitor_t* mon, bool synced) {
    if (!mon) return QIHSE_TIME_OK;
    bool was = mon->synced;
    mon->synced = synced;
    if (was && !synced) {
        mon->sync_losses++;
        return QIHSE_TIME_SYNC_LOST;
    }
    return QIHSE_TIME_OK;
}

qihse_time_anomaly_t qihse_time_check_peer_skew(const qihse_time_policy_t* policy,
                                                uint64_t local_wall_ms, uint64_t peer_wall_ms) {
    qihse_time_policy_t defaults;
    if (!policy) {
        qihse_time_policy_init(&defaults);
        policy = &defaults;
    }
    uint64_t skew = (local_wall_ms > peer_wall_ms)
                        ? local_wall_ms - peer_wall_ms
                        : peer_wall_ms - local_wall_ms;
    return (skew > policy->peer_skew_threshold_ms) ? QIHSE_TIME_FORWARD_JUMP : QIHSE_TIME_OK;
}

/* ── HLC monotonicity under anomalies (criterion 27) ───────────────────── */

qihse_hlc_t qihse_hlc_advance_safe(const qihse_hlc_t* prev, uint64_t wall_ms) {
    qihse_hlc_t out;
    if (!prev) {
        out.physical_ms = wall_ms;
        out.logical = 0;
        return out;
    }
    if (wall_ms > prev->physical_ms) {
        /* Wall clock moved forward: adopt it and reset the counter. */
        out.physical_ms = wall_ms;
        out.logical = 0;
    } else {
        /* Wall clock stalled or went BACKWARDS.  Keep the previous physical
         * component and carry the ordering guarantee in the logical counter,
         * so the result is still strictly greater than `prev`.  This is what
         * makes a wall-clock anomaly unable to break HLC ordering. */
        out.physical_ms = prev->physical_ms;
        out.logical = prev->logical + 1u;
        if (out.logical == 0u) {
            /* Counter wrapped: borrow a millisecond rather than repeat. */
            out.physical_ms = prev->physical_ms + 1u;
            out.logical = 0u;
        }
    }
    return out;
}

qihse_hlc_t qihse_hlc_merge_safe(const qihse_hlc_t* local, const qihse_hlc_t* remote,
                                 uint64_t local_wall_ms) {
    qihse_hlc_t out;
    if (!local && !remote) {
        out.physical_ms = local_wall_ms;
        out.logical = 0;
        return out;
    }
    if (!local) { out = *remote; return out; }
    if (!remote) {
        return qihse_hlc_advance_safe(local, local_wall_ms);
    }

    uint64_t physical = local_wall_ms;
    if (local->physical_ms > physical) physical = local->physical_ms;
    if (remote->physical_ms > physical) physical = remote->physical_ms;

    /* Take the highest logical counter among the clocks that share the
     * winning physical component, then increment.  A remote clock that is
     * ahead or behind by any amount therefore still yields a strictly
     * greater local clock. */
    uint32_t logical = 0;
    bool local_ties = (local->physical_ms == physical);
    bool remote_ties = (remote->physical_ms == physical);
    if (local_ties && remote_ties) {
        logical = (local->logical > remote->logical ? local->logical : remote->logical) + 1u;
    } else if (local_ties) {
        logical = local->logical + 1u;
    } else if (remote_ties) {
        logical = remote->logical + 1u;
    }
    out.physical_ms = physical;
    out.logical = logical;
    return out;
}
