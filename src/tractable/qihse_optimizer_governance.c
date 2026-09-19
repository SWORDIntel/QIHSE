#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * QIHSE optimizer governance (W5.1) — shadow evaluation, explicit safety
 * constraints, automatic rollback, persisted decisions.
 *
 * See include/qihse_optimizer_governance.h for the design and the declared
 * rules.  The three properties this file must not lose:
 *
 *   1. FAIL CLOSED.  Every path that cannot evaluate — no journal, no
 *      evidence, a full key table, a key that does not match the recorded
 *      incumbent, a cost that is not a number — returns KEEP and leaves the
 *      served plan exactly where it was.  "No evidence" is never read as
 *      "evidence of absence": the probation rule below keeps a switch whose
 *      window closed unmeasured, because an unmeasured plan has not been
 *      shown to regress, and reverting on silence would be the same mistake
 *      in the other direction.
 *
 *   2. THE SWITCH IS THE HARD DIRECTION.  A switch needs a committed journal
 *      record, min_samples on BOTH arms, a candidate that is better than the
 *      incumbent by more than improvement_margin, and a candidate that is not
 *      worse than the incumbent by more than regression_bound.  The rollback
 *      is the easy direction: it needs only a violated bound, and it happens
 *      inside observe() with no operator input.
 *
 *   3. BOUNDED.  Every structure is fixed-size: QIHSE_OPT_GOV_MAX_KEYS keys,
 *      QIHSE_OPT_GOV_SAMPLE_WINDOW samples per arm, a 16-entry history ring,
 *      one 1 KiB record buffer allocated once.  A long-running process cannot
 *      grow this, and no stack frame here is sized by anything but those
 *      constants.  The journal grows one record per STATE CHANGE (or per
 *      change of the reason a key is being kept), not one per query, so a
 *      per-query evaluate() cannot grow it either.
 *
 * The journal is the cluster brain's store (qihse_event_stream, topic
 * "optimizer.governance"), so a governance decision has the same shape as an
 * R1/R4 decision: hash-chained, SHA-384 event id, and evidence in the record.
 */
#include "qihse_optimizer_governance.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Declared metric vocabularies ────────────────────────────────────────
 *
 * These tables ARE the declared value sets.  Registration and lookup both use
 * them, so no caller-supplied string can become a label value (the W5.2 rule)
 * and the two cannot drift apart. */
static const char* const GOV_OUTCOME_NAMES[QIHSE_OPT_GOV_OUTCOME_COUNT] = {
    "keep",     /* QIHSE_OPT_GOV_OUTCOME_KEEP */
    "switch",   /* QIHSE_OPT_GOV_OUTCOME_SWITCH */
    "rollback", /* QIHSE_OPT_GOV_OUTCOME_ROLLBACK */
    "observe"   /* QIHSE_OPT_GOV_OUTCOME_OBSERVE */
};

static const char* const GOV_ROLLBACK_NAMES[QIHSE_OPT_GOV_ROLLBACK_REASON_COUNT] = {
    "regression",      /* QIHSE_OPT_GOV_ROLLBACK_REGRESSION */
    "result_mismatch"  /* QIHSE_OPT_GOV_ROLLBACK_MISMATCH */
};

const char* qihse_opt_gov_outcome_name(qihse_opt_gov_outcome_t outcome) {
    if ((int)outcome < 0 || outcome >= QIHSE_OPT_GOV_OUTCOME_COUNT) return "keep";
    return GOV_OUTCOME_NAMES[outcome];
}

const char* qihse_opt_gov_rollback_reason_name(qihse_opt_gov_rollback_reason_t reason) {
    if ((int)reason < 0 || reason >= QIHSE_OPT_GOV_ROLLBACK_REASON_COUNT) return "regression";
    return GOV_ROLLBACK_NAMES[reason];
}

const char* qihse_opt_gov_reason_name(qihse_opt_gov_reason_t reason) {
    switch (reason) {
        case QIHSE_OPT_GOV_REASON_NONE:                 return "none";
        case QIHSE_OPT_GOV_REASON_BASELINE:             return "baseline";
        case QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT:       return "no_improvement";
        case QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES: return "insufficient_samples";
        case QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER:     return "candidate_better";
        case QIHSE_OPT_GOV_REASON_REGRESSION_BOUND:     return "regression_bound";
        case QIHSE_OPT_GOV_REASON_RESULT_MISMATCH:      return "result_mismatch";
        case QIHSE_OPT_GOV_REASON_NO_JOURNAL:           return "no_journal";
        case QIHSE_OPT_GOV_REASON_COOLDOWN:             return "cooldown";
        case QIHSE_OPT_GOV_REASON_PROBATION:            return "probation";
        case QIHSE_OPT_GOV_REASON_PROBATION_PASSED:     return "probation_passed";
        case QIHSE_OPT_GOV_REASON_ROLLBACK_REGRESSION:  return "rollback_regression";
        case QIHSE_OPT_GOV_REASON_ROLLBACK_MISMATCH:    return "rollback_mismatch";
        case QIHSE_OPT_GOV_REASON_UNKNOWN_SHAPE:        return "unknown_shape";
        case QIHSE_OPT_GOV_REASON_KEY_INVALID:          return "key_invalid";
        case QIHSE_OPT_GOV_REASON_TABLE_FULL:           return "table_full";
        case QIHSE_OPT_GOV_REASON_INCUMBENT_MISMATCH:   return "incumbent_mismatch";
        case QIHSE_OPT_GOV_REASON_DISQUALIFIED:         return "disqualified";
        default:                                        return "none";
    }
}

/* ── Time ────────────────────────────────────────────────────────────────
 *
 * Windows are measured on the monotonic clock (a wall-clock step must not
 * open or close a probation), while the journal stamps records with wall time
 * so an operator can line a decision up with everything else that happened. */
static uint64_t gov_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static uint64_t gov_wall_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static uint64_t gov_wall_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)(ts.tv_nsec / 1000L);
}

/* ── One arm's evidence ──────────────────────────────────────────────────
 *
 * A bounded ring of the most recent QIHSE_OPT_GOV_SAMPLE_WINDOW observations.
 * The mean is computed from the ring on demand rather than carried as a
 * running sum: a sum that is added to and subtracted from forever drifts, and
 * a decision must not rest on a drifting number. */
typedef struct {
    double   samples[QIHSE_OPT_GOV_SAMPLE_WINDOW];
    size_t   head;   /* next slot to write */
    size_t   count;  /* valid entries, <= QIHSE_OPT_GOV_SAMPLE_WINDOW */
    uint64_t total;  /* observations ever recorded for this plan */
    uint64_t shadow; /* of which were shadow measurements */
} gov_arm_t;

static void gov_arm_add(gov_arm_t* a, double cost, bool shadow) {
    /* A cost that is negative or not a number is refused rather than
     * recorded: it would poison every mean computed from this arm. */
    if (!(cost >= 0.0)) return;
    a->samples[a->head] = cost;
    a->head = (a->head + 1u) % QIHSE_OPT_GOV_SAMPLE_WINDOW;
    if (a->count < QIHSE_OPT_GOV_SAMPLE_WINDOW) a->count++;
    a->total++;
    if (shadow) a->shadow++;
}

static double gov_arm_mean(const gov_arm_t* a) {
    if (a->count == 0) return 0.0;
    double sum = 0.0;
    for (size_t i = 0; i < a->count; i++) sum += a->samples[i];
    return sum / (double)a->count;
}

static void gov_arm_reset(gov_arm_t* a) { memset(a, 0, sizeof(*a)); }

static void gov_arm_swap(gov_arm_t* a, gov_arm_t* b) {
    gov_arm_t t = *a;
    *a = *b;
    *b = t;
}

/* ── Per-key state ───────────────────────────────────────────────────────
 *
 * `served` is the plan in service; `challenger` is the plan under evaluation
 * (before a switch) or the plan a rollback would restore (during probation).
 * The evidence follows the plan: a switch or a rollback swaps the arms. */
typedef struct {
    bool     used;
    char     key[QIHSE_OPT_GOV_KEY_MAX];
    uint64_t served_shape;
    uint64_t challenger_shape;
    gov_arm_t served;
    gov_arm_t challenger;
    /* C3: false once a shadow result disagreed with the incumbent's. */
    bool     challenger_valid;
    /* The plan that failed its probation on this key.  It is not re-proposed:
     * that is what keeps a rollback from becoming an oscillation. */
    uint64_t disqualified_shape;
    /* Probation: the window a switch is judged in. */
    bool     probation;
    uint64_t probation_start_ms;
    uint64_t probation_deadline_ms;
    /* The mean of the plan a rollback would restore, frozen at the switch:
     * later observations of that plan must not move the bound the served plan
     * is being judged against. */
    double   reference_mean;
    /* C5: no new switch on this key before this deadline. */
    uint64_t cooldown_until_ms;
    /* C1 by workload: this key's own regression budget, or < 0 to use the
     * harness default.  Set by
     * qihse_optimizer_governance_set_regression_budget(). */
    double   regression_bound;
    /* The last reason this key was kept/decided for, so the journal records
     * the first occurrence of a reason rather than one record per query. */
    qihse_opt_gov_reason_t last_reason;
} gov_key_t;

struct qihse_opt_governance {
    qihse_optimizer_t* opt;
    qihse_opt_gov_config_t cfg;
    gov_key_t keys[QIHSE_OPT_GOV_MAX_KEYS];
    qihse_event_stream_t* journal;
    /* Bounded in-memory decision history, newest at head-1. */
    qihse_opt_gov_decision_t history[QIHSE_OPT_GOV_HISTORY_MAX];
    size_t history_head;
    size_t history_count;
    uint64_t seq;
    /* W5.2 registry handles; NULL when no registry is attached. */
    qihse_metrics_registry_t* metrics;
    qihse_metric_series_t* decisions_series[QIHSE_OPT_GOV_OUTCOME_COUNT];
    qihse_metric_series_t* rollbacks_series[QIHSE_OPT_GOV_ROLLBACK_REASON_COUNT];
    qihse_metric_series_t* active_switches_series;
    /* ONE reusable record buffer, allocated once (AGENTS.md: a decoder keeps
     * one buffer sized for the largest record, not one array per field). */
    char* record;
};

/* The budget a decision about this key is judged against.  A key that has not
 * been given one inherits the harness default, so a workload-specific budget
 * is an override and never a requirement. */
static double gov_effective_bound(const qihse_opt_governance_t* gov, const gov_key_t* k) {
    if (k && k->regression_bound >= 0.0) return k->regression_bound;
    return gov->cfg.regression_bound;
}

/* ── Config ────────────────────────────────────────────────────────────── */

void qihse_opt_gov_config_default(qihse_opt_gov_config_t* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->regression_bound = 0.20;      /* C1: tolerate 20% worse, no more */
    out->improvement_margin = 0.05;    /* C6: 5% better or it is churn */
    out->min_samples = 8;              /* C2 */
    out->rollback_min_samples = 3;     /* C2, post-switch */
    out->rollback_window_ms = 60000u;  /* one minute of probation */
    out->cooldown_ms = 300000u;        /* C5: five minutes after a rollback */
    out->require_result_match = true;  /* C3 */
    out->journal_dir = NULL;           /* C4: set this or no switch happens */
    out->journal_durability = QIHSE_ES_DURABILITY_FDATASYNC;
}

/* Normalise a caller's config so the constraints cannot be configured away.
 * Each clamp is a constraint that would otherwise be silenceable. */
static void gov_config_normalize(qihse_opt_gov_config_t* cfg) {
    if (cfg->min_samples < 2u) cfg->min_samples = 2u;
    if (cfg->min_samples > QIHSE_OPT_GOV_SAMPLE_WINDOW) cfg->min_samples = QIHSE_OPT_GOV_SAMPLE_WINDOW;
    if (cfg->rollback_min_samples < 1u) cfg->rollback_min_samples = 1u;
    if (cfg->rollback_min_samples > QIHSE_OPT_GOV_SAMPLE_WINDOW)
        cfg->rollback_min_samples = QIHSE_OPT_GOV_SAMPLE_WINDOW;
    if (!(cfg->regression_bound >= 0.0)) cfg->regression_bound = 0.20;
    if (!(cfg->improvement_margin >= 0.0)) cfg->improvement_margin = 0.05;
    if (cfg->improvement_margin > 1.0) cfg->improvement_margin = 1.0;
}

/* ── Keys ──────────────────────────────────────────────────────────────── */

static bool gov_key_ok(const char* key) {
    if (!key) return false;
    size_t n = strnlen(key, QIHSE_OPT_GOV_KEY_MAX);
    return n > 0 && n < QIHSE_OPT_GOV_KEY_MAX;
}

static gov_key_t* gov_find_key(qihse_opt_governance_t* gov, const char* key, bool create) {
    for (size_t i = 0; i < QIHSE_OPT_GOV_MAX_KEYS; i++) {
        gov_key_t* k = &gov->keys[i];
        if (k->used && strcmp(k->key, key) == 0) return k;
    }
    if (!create) return NULL;
    for (size_t i = 0; i < QIHSE_OPT_GOV_MAX_KEYS; i++) {
        gov_key_t* k = &gov->keys[i];
        if (k->used) continue;
        memset(k, 0, sizeof(*k));
        k->used = true;
        /* Bounded copy: gov_key_ok() already proved the key fits. */
        memcpy(k->key, key, strlen(key) + 1u);
        k->challenger_valid = true;
        k->regression_bound = -1.0; /* no per-workload budget: inherit */
        return k;
    }
    return NULL; /* C7: the table is full; the caller's key is refused */
}

/* The key as a journal field: bounded, and stripped of anything that could
 * rewrite the record it is embedded in.  A key is caller data, so it is
 * sanitised rather than trusted. */
static void gov_json_key(char* out, size_t cap, const char* key) {
    if (cap == 0) return;
    size_t i = 0;
    for (; key && key[i] && i + 1u < cap; i++) {
        unsigned char c = (unsigned char)key[i];
        bool plain = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':' || c == '-';
        out[i] = plain ? (char)c : '_';
    }
    out[i] = '\0';
}

/* ── Journal ───────────────────────────────────────────────────────────── */

static const char* gov_kind(const qihse_opt_gov_decision_t* d) {
    switch (d->outcome) {
        case QIHSE_OPT_GOV_OUTCOME_SWITCH:   return "SWITCH";
        case QIHSE_OPT_GOV_OUTCOME_ROLLBACK: return "ROLLBACK";
        case QIHSE_OPT_GOV_OUTCOME_OBSERVE:  return "OBSERVE";
        default: break;
    }
    if (d->reason == QIHSE_OPT_GOV_REASON_BASELINE) return "BASELINE";
    if (d->reason == QIHSE_OPT_GOV_REASON_PROBATION_PASSED) return "PROBATION_PASSED";
    if (d->reason == QIHSE_OPT_GOV_REASON_PROBATION) return "PROBATION_OPEN";
    return "KEEP";
}

/* Append one decision to the durable journal.  Returns true when the record
 * is committed, with its frame offset in *offset_out.  A false return is what
 * a switch reads as a refusal (C4); note that a committed record can sit at
 * frame offset 0 (the first record in a topic), which is why the answer is a
 * bool and not the offset. */
static bool gov_journal_append(qihse_opt_governance_t* gov, const char* key,
                               const qihse_opt_gov_decision_t* d, uint64_t* offset_out) {
    if (offset_out) *offset_out = 0;
    if (!gov->journal || !gov->record) return false;
    char kbuf[QIHSE_OPT_GOV_KEY_MAX];
    gov_json_key(kbuf, sizeof(kbuf), key);

    /* The record carries the constraint values IN FORCE at this moment, so
     * the arithmetic behind the decision can be re-checked from the record
     * alone, even after the configuration has changed.
     *
     * `ts_us` is there because the store refuses a byte-identical record (its
     * event id is SHA-384 of the payload): a decision that repeats exactly —
     * same key, same sequence, same evidence, same millisecond, from a second
     * harness sharing this journal — is the same decision, and the refusal
     * fails closed rather than corrupting the chain.  Microsecond resolution
     * keeps that from happening to two decisions that are merely similar. */
    int n = snprintf(gov->record, QIHSE_OPT_GOV_RECORD_MAX,
                     "{\"schema\":%u,\"seq\":%llu,\"ts_ms\":%llu,\"ts_us\":%llu,"
                     "\"kind\":\"%s\",\"key\":\"%s\","
                     "\"outcome\":\"%s\",\"reason\":\"%s\",\"serve_shape\":\"%016llx\","
                     "\"previous_shape\":\"%016llx\",\"challenger_shape\":\"%016llx\","
                     "\"previous_mean\":%.6g,\"challenger_mean\":%.6g,"
                     "\"previous_samples\":%llu,\"challenger_samples\":%llu,"
                     "\"probation_elapsed_ms\":%llu,"
                     "\"constraints\":{\"regression_bound\":%.6g,\"improvement_margin\":%.6g,"
                     "\"min_samples\":%llu,\"rollback_min_samples\":%llu,"
                     "\"rollback_window_ms\":%u,\"cooldown_ms\":%u,\"require_result_match\":%s}}",
                     (unsigned)QIHSE_OPT_GOV_RECORD_SCHEMA,
                     (unsigned long long)d->seq, (unsigned long long)d->ts_ms,
                     (unsigned long long)gov_wall_us(), gov_kind(d), kbuf,
                     qihse_opt_gov_outcome_name(d->outcome), qihse_opt_gov_reason_name(d->reason),
                     (unsigned long long)d->serve_shape,
                     (unsigned long long)d->previous_shape,
                     (unsigned long long)d->challenger_shape,
                     d->previous_mean, d->challenger_mean,
                     (unsigned long long)d->previous_samples,
                     (unsigned long long)d->challenger_samples,
                     (unsigned long long)d->probation_elapsed_ms,
                     d->regression_bound, gov->cfg.improvement_margin,
                     (unsigned long long)gov->cfg.min_samples,
                     (unsigned long long)gov->cfg.rollback_min_samples,
                     (unsigned)gov->cfg.rollback_window_ms, (unsigned)gov->cfg.cooldown_ms,
                     gov->cfg.require_result_match ? "true" : "false");
    /* A truncated record is not a record: refuse rather than commit evidence
     * that cannot be read back.  (The worst case is bounded by the declared
     * key size plus the fixed field list, so this is a guard, not a path.) */
    if (n < 0 || (size_t)n >= QIHSE_OPT_GOV_RECORD_MAX) return false;

    uint64_t offset = qihse_event_stream_length(gov->journal, QIHSE_OPT_GOV_TOPIC);
    if (!qihse_event_stream_append(gov->journal, QIHSE_OPT_GOV_TOPIC,
                                   (const uint8_t*)gov->record, (size_t)n))
        return false;
    if (offset_out) *offset_out = offset;
    return true;
}

/* ── Metrics (W5.2 registry, declared labels only) ─────────────────────── */

static void gov_metrics_decision(qihse_opt_governance_t* gov,
                                 const qihse_opt_gov_decision_t* d) {
    if (!gov->metrics) return;
    if (d->outcome < QIHSE_OPT_GOV_OUTCOME_COUNT && gov->decisions_series[d->outcome])
        qihse_metrics_series_increment(gov->decisions_series[d->outcome], 1u);
    if (d->outcome == QIHSE_OPT_GOV_OUTCOME_ROLLBACK) {
        qihse_opt_gov_rollback_reason_t r =
            (d->reason == QIHSE_OPT_GOV_REASON_ROLLBACK_MISMATCH)
                ? QIHSE_OPT_GOV_ROLLBACK_MISMATCH : QIHSE_OPT_GOV_ROLLBACK_REGRESSION;
        if (gov->rollbacks_series[r]) qihse_metrics_series_increment(gov->rollbacks_series[r], 1u);
    }
}

static void gov_metrics_probation(qihse_opt_governance_t* gov) {
    if (!gov->metrics || !gov->active_switches_series) return;
    size_t n = qihse_optimizer_governance_probation_count(gov);
    qihse_metrics_series_set(gov->active_switches_series, (double)n);
}

/* ── Decision finalisation ───────────────────────────────────────────────
 *
 * The pending state change travels with the decision so that the journal
 * write, the state change and the history entry cannot get out of order:
 * a switch whose record cannot be committed is DOWNGRADED to a keep before
 * anything is applied. */
typedef enum {
    GOV_ACT_NONE = 0,
    GOV_ACT_BASELINE,      /* adopt the first plan for a key */
    GOV_ACT_SWITCH,        /* candidate becomes the served plan, on probation */
    GOV_ACT_ROLLBACK,      /* the pre-switch plan is restored */
    GOV_ACT_PROBATION_PASS /* the window closed with no violation: switch kept */
} gov_action_t;

static qihse_opt_gov_decision_t gov_finish(qihse_opt_governance_t* gov, gov_key_t* k,
                                           const char* key, qihse_opt_gov_decision_t d,
                                           gov_action_t action, uint64_t now) {
    bool state_change = (action != GOV_ACT_NONE);
    /* Journal a state change, and the first occurrence of a keep-reason for a
     * key.  Repeats are not journaled: a per-query evaluate() must not be able
     * to grow the journal. */
    bool want_record = state_change || (d.reason != k->last_reason);

    uint64_t offset = 0;
    bool recorded = false;
    d.ts_ms = gov_wall_ms();
    if (want_record) {
        d.seq = gov->seq + 1u;
        recorded = gov_journal_append(gov, key, &d, &offset);
    }

    if (action == GOV_ACT_SWITCH && !recorded) {
        /* C4: no committed record, no switch.  The candidate keeps its
         * evidence — the caller can retry once the journal is available. */
        d.outcome = QIHSE_OPT_GOV_OUTCOME_KEEP;
        d.reason = QIHSE_OPT_GOV_REASON_NO_JOURNAL;
        d.serve_shape = k->served_shape;
        d.probation = k->probation;
        d.probation_elapsed_ms = 0;
        state_change = false;
        action = GOV_ACT_NONE;
    }

    /* Apply the state change.  A rollback is applied even when the record
     * could not be committed: reverting a regressing plan is the safety
     * action, and refusing it to protect the audit trail would trade safety
     * for bookkeeping.  Switches are the reverse (above) because keeping the
     * incumbent costs nothing. */
    switch (action) {
        case GOV_ACT_BASELINE:
            k->served_shape = d.serve_shape;
            break;
        case GOV_ACT_SWITCH: {
            uint64_t was_served = k->served_shape;
            gov_arm_swap(&k->served, &k->challenger);
            k->served_shape = k->challenger_shape;
            k->challenger_shape = was_served;
            k->reference_mean = gov_arm_mean(&k->challenger);
            /* The probation judges the plan's behaviour IN SERVICE, so the
             * served arm starts empty here: shadow measurements taken before
             * the plan was in service cannot show how it behaves in service,
             * and leaving them in would dilute exactly the regression the
             * window exists to catch.  The evidence that justified the switch
             * is not lost — it is in this decision's record. */
            gov_arm_reset(&k->served);
            k->probation = true;
            k->probation_start_ms = now;
            k->probation_deadline_ms = now + (uint64_t)gov->cfg.rollback_window_ms;
            k->disqualified_shape = 0;
            break;
        }
        case GOV_ACT_ROLLBACK: {
            uint64_t regressed = k->served_shape;
            gov_arm_swap(&k->served, &k->challenger);
            k->served_shape = k->challenger_shape;
            k->challenger_shape = regressed;
            k->probation = false;
            k->probation_start_ms = 0;
            k->probation_deadline_ms = 0;
            k->cooldown_until_ms = now + (uint64_t)gov->cfg.cooldown_ms;
            k->disqualified_shape = regressed;
            break;
        }
        case GOV_ACT_PROBATION_PASS:
            k->probation = false;
            k->probation_start_ms = 0;
            k->probation_deadline_ms = 0;
            break;
        case GOV_ACT_NONE:
        default:
            break;
    }

    /* The returned decision describes the state AFTER the decision, which is
     * what the caller has to act on: a switch is on probation from here, a
     * rollback is not.  (The journal record above was built from the state
     * before the change, which is the evidence the decision rested on.) */
    d.probation = k->probation;
    d.probation_elapsed_ms = (k->probation && now >= k->probation_start_ms)
                                 ? now - k->probation_start_ms : 0u;

    d.recorded = recorded;
    d.journal_offset = recorded ? offset : 0;
    if (recorded) gov->seq = d.seq;
    k->last_reason = d.reason;

    /* The history and the counters describe plan decisions; an observation is
     * not a decision and is not counted as one. */
    if (d.outcome != QIHSE_OPT_GOV_OUTCOME_OBSERVE) {
        gov->history[gov->history_head] = d;
        gov->history_head = (gov->history_head + 1u) % QIHSE_OPT_GOV_HISTORY_MAX;
        if (gov->history_count < QIHSE_OPT_GOV_HISTORY_MAX) gov->history_count++;
        gov_metrics_decision(gov, &d);
    }
    if (state_change || d.outcome == QIHSE_OPT_GOV_OUTCOME_ROLLBACK) gov_metrics_probation(gov);
    return d;
}

/* A decision with the current key state filled in. */
static qihse_opt_gov_decision_t gov_decision(const qihse_opt_governance_t* gov,
                                             const gov_key_t* k,
                                             qihse_opt_gov_outcome_t outcome,
                                             qihse_opt_gov_reason_t reason,
                                             uint64_t now) {
    qihse_opt_gov_decision_t d;
    memset(&d, 0, sizeof(d));
    d.outcome = outcome;
    d.reason = reason;
    d.serve_shape = k ? k->served_shape : 0;
    d.previous_shape = k ? k->served_shape : 0;
    d.challenger_shape = k ? k->challenger_shape : 0;
    d.previous_mean = k ? gov_arm_mean(&k->served) : 0.0;
    d.challenger_mean = k ? gov_arm_mean(&k->challenger) : 0.0;
    d.previous_samples = k ? k->served.count : 0u;
    d.challenger_samples = k ? k->challenger.count : 0u;
    d.regression_bound = gov_effective_bound(gov, k);
    d.probation = k ? k->probation : false;
    d.probation_elapsed_ms = (k && k->probation && now >= k->probation_start_ms)
                                 ? now - k->probation_start_ms : 0u;
    return d;
}

/* ── Probation (the automatic rollback) ──────────────────────────────────
 *
 * Called from observe() after the sample is recorded and from evaluate().
 * Returns true when the probation ended (either way), with `out` filled in. */
static bool gov_check_probation(qihse_opt_governance_t* gov, gov_key_t* k,
                                const char* key, uint64_t now,
                                qihse_opt_gov_decision_t* out) {
    if (!k->probation) return false;
    if (now < k->probation_deadline_ms) return false;
    if (k->served.count < gov->cfg.rollback_min_samples) return false;

    double served_mean = gov_arm_mean(&k->served);
    double bound = k->reference_mean * (1.0 + gov_effective_bound(gov, k));
    if (served_mean > bound) {
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_ROLLBACK,
                                                 QIHSE_OPT_GOV_REASON_ROLLBACK_REGRESSION, now);
        /* The evidence is the served (regressed) plan against the plan a
         * rollback restores, with the bound it violated. */
        d.previous_mean = served_mean;
        d.challenger_mean = k->reference_mean;
        d.serve_shape = k->challenger_shape; /* the restored plan */
        d = gov_finish(gov, k, key, d, GOV_ACT_ROLLBACK, now);
        d.serve_shape = k->served_shape;
        d.previous_shape = k->challenger_shape;
        *out = d;
        return true;
    }
    /* The window closed with enough samples and no violation: the switch
     * survived.  This is a decision worth journaling. */
    qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                              QIHSE_OPT_GOV_REASON_PROBATION_PASSED, now);
    d = gov_finish(gov, k, key, d, GOV_ACT_PROBATION_PASS, now);
    *out = d;
    return true;
}

/* The rollback that does not wait for the window: the served plan returned a
 * different result, which is a correctness violation, not a cost question. */
static qihse_opt_gov_decision_t gov_rollback_mismatch(qihse_opt_governance_t* gov, gov_key_t* k,
                                                      const char* key, uint64_t now) {
    qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_ROLLBACK,
                                              QIHSE_OPT_GOV_REASON_ROLLBACK_MISMATCH, now);
    d.serve_shape = k->challenger_shape;
    d = gov_finish(gov, k, key, d, GOV_ACT_ROLLBACK, now);
    d.serve_shape = k->served_shape;
    d.previous_shape = k->challenger_shape;
    return d;
}

/* ── Lifecycle ─────────────────────────────────────────────────────────── */

qihse_opt_governance_t* qihse_optimizer_governance_create(
        qihse_optimizer_t* opt, const qihse_opt_gov_config_t* config) {
    qihse_opt_governance_t* gov = (qihse_opt_governance_t*)calloc(1, sizeof(*gov));
    if (!gov) return NULL;
    gov->opt = opt;
    if (config) gov->cfg = *config;
    else qihse_opt_gov_config_default(&gov->cfg);
    gov_config_normalize(&gov->cfg);
    /* The record buffer is sized by a constant and allocated once: no stack
     * frame in this file is sized by caller input. */
    gov->record = (char*)malloc(QIHSE_OPT_GOV_RECORD_MAX);
    if (gov->cfg.journal_dir && gov->cfg.journal_dir[0]) {
        gov->journal = qihse_event_stream_open(gov->cfg.journal_dir,
                                               gov->cfg.journal_durability, false);
    }
    /* A journal that could not be opened is not a creation failure: the
     * harness observes, reports and refuses to switch, which is exactly the
     * fail-closed behaviour.  Callers are told on every decision (NO_JOURNAL).
     */
    return gov;
}

void qihse_optimizer_governance_destroy(qihse_opt_governance_t* gov) {
    if (!gov) return;
    if (gov->journal) qihse_event_stream_destroy(gov->journal);
    free(gov->record);
    free(gov);
}

/* ── observe ───────────────────────────────────────────────────────────── */

qihse_opt_gov_decision_t qihse_optimizer_governance_observe(
        qihse_opt_governance_t* gov, const char* key, const qihse_opt_gov_obs_t* obs) {
    qihse_opt_gov_decision_t none;
    memset(&none, 0, sizeof(none));
    none.outcome = QIHSE_OPT_GOV_OUTCOME_OBSERVE;
    none.reason = QIHSE_OPT_GOV_REASON_KEY_INVALID;
    /* C8: an observation the harness cannot attribute changes nothing. */
    if (!gov || !gov_key_ok(key) || !obs) return none;

    uint64_t now = gov_mono_ms();
    gov_key_t* k = gov_find_key(gov, key, false);
    if (!k) {
        none.reason = QIHSE_OPT_GOV_REASON_UNKNOWN_SHAPE; /* no plan tracked yet */
        return none;
    }
    /* While a switch is on probation only the served plan is being measured;
     * an observation for anything else is not evidence about the decision the
     * probation is judging, so it is refused rather than filed. */
    if (k->probation && obs->shape != k->served_shape) {
        none.reason = QIHSE_OPT_GOV_REASON_PROBATION;
        return none;
    }
    if (obs->shape == k->served_shape) {
        gov_arm_add(&k->served, obs->cost, obs->shadow);
    } else if (obs->shape == k->challenger_shape) {
        gov_arm_add(&k->challenger, obs->cost, obs->shadow);
        if (obs->shadow && !obs->result_matched && gov->cfg.require_result_match) {
            /* C3: a faster plan that returns a different answer is not a
             * faster plan.  It is disqualified on the spot. */
            k->challenger_valid = false;
        }
    } else {
        none.reason = QIHSE_OPT_GOV_REASON_UNKNOWN_SHAPE;
        return none;
    }

    /* A served plan whose result changed is a correctness violation and does
     * not wait for the rollback window. */
    if (k->probation && obs->shape == k->served_shape && !obs->result_matched &&
        gov->cfg.require_result_match) {
        return gov_rollback_mismatch(gov, k, key, now);
    }

    qihse_opt_gov_decision_t ended;
    if (gov_check_probation(gov, k, key, now, &ended)) return ended;

    qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_OBSERVE,
                                             QIHSE_OPT_GOV_REASON_NONE, now);
    /* Journal the first time a key is seen inside its probation window, so the
     * audit trail shows the window opening without one record per sample. */
    if (k->probation && k->last_reason != QIHSE_OPT_GOV_REASON_PROBATION) {
        d = gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
        d.outcome = QIHSE_OPT_GOV_OUTCOME_OBSERVE; /* an observation is not a plan decision */
        return d;
    }
    return d;
}

/* ── evaluate ──────────────────────────────────────────────────────────── */

qihse_opt_gov_decision_t qihse_optimizer_governance_evaluate_shapes(
        qihse_opt_governance_t* gov, const char* key,
        uint64_t incumbent_shape, uint64_t candidate_shape) {
    qihse_opt_gov_decision_t none;
    memset(&none, 0, sizeof(none));
    none.outcome = QIHSE_OPT_GOV_OUTCOME_KEEP;
    none.reason = QIHSE_OPT_GOV_REASON_KEY_INVALID;
    /* C8: every refusal below is a keep.  An argument the harness cannot
     * understand is not a reason to change what is serving. */
    if (!gov || !gov_key_ok(key)) return none;

    uint64_t now = gov_mono_ms();
    if (incumbent_shape == 0) return none; /* no plan to be the baseline */

    gov_key_t* k = gov_find_key(gov, key, true);
    if (!k) {
        none.reason = QIHSE_OPT_GOV_REASON_TABLE_FULL;
        return none;
    }

    if (k->served_shape == 0) {
        /* First sighting: the caller's own plan becomes the baseline.  This
         * is not a switch — the caller would have served this plan with no
         * harness at all — and it is journaled so the baseline is auditable. */
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                                 QIHSE_OPT_GOV_REASON_BASELINE, now);
        d.serve_shape = incumbent_shape;
        d.challenger_shape = candidate_shape;
        d.previous_shape = 0;
        d.previous_samples = 0;
        d.previous_mean = 0.0;
        if (candidate_shape != 0 && candidate_shape != incumbent_shape) {
            k->challenger_shape = candidate_shape;
            gov_arm_reset(&k->challenger);
            k->challenger_valid = true;
            d.challenger_samples = 0;
            d.challenger_mean = 0.0;
        } else {
            k->challenger_shape = 0;
        }
        return gov_finish(gov, k, key, d, GOV_ACT_BASELINE, now);
    }

    /* The caller is serving something other than what the harness recorded.
     * The harness cannot stop that, but it will not evaluate under a baseline
     * it did not approve either: the change is refused and journaled, so it
     * appears in the audit trail instead of quietly becoming the baseline. */
    if (incumbent_shape != k->served_shape) {
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                                 QIHSE_OPT_GOV_REASON_INCUMBENT_MISMATCH, now);
        d.challenger_shape = candidate_shape;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }

    /* A probation whose window has closed is evaluated here as well as in
     * observe(), so a caller that only ever calls evaluate() still gets its
     * automatic rollback. */
    qihse_opt_gov_decision_t ended;
    if (gov_check_probation(gov, k, key, now, &ended)) return ended;

    if (k->probation) {
        /* One plan change in flight per key.  While the probation is open the
         * rollback target and its evidence must stay intact, so a new
         * candidate waits — the brain's "one action per cycle" rule. */
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                                 QIHSE_OPT_GOV_REASON_PROBATION, now);
        d.challenger_shape = candidate_shape;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }

    if (candidate_shape == 0 || candidate_shape == k->served_shape) {
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                                 QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT, now);
        d.challenger_shape = candidate_shape;
        d.challenger_samples = 0;
        d.challenger_mean = 0.0;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }

    if (now < k->cooldown_until_ms) {
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                                 QIHSE_OPT_GOV_REASON_COOLDOWN, now);
        d.challenger_shape = candidate_shape;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }
    if (candidate_shape == k->disqualified_shape) {
        /* A plan that failed its probation on this key is not re-proposed by
         * this harness; that is what stops a rollback from oscillating. */
        qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                                 QIHSE_OPT_GOV_REASON_DISQUALIFIED, now);
        d.challenger_shape = candidate_shape;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }

    if (candidate_shape != k->challenger_shape) {
        /* A different candidate: its predecessor's evidence does not transfer
         * to it, so the arm starts empty and the minimum sample size applies
         * again.  Fail closed on a new candidate. */
        k->challenger_shape = candidate_shape;
        gov_arm_reset(&k->challenger);
        k->challenger_valid = true;
    }

    /* ── THE SWITCH RULE (see the header for the declared form) ───────────
     * Each clause below is one named constraint.  The default is the keep. */
    qihse_opt_gov_decision_t d = gov_decision(gov, k, QIHSE_OPT_GOV_OUTCOME_KEEP,
                                             QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES, now);
    d.challenger_shape = candidate_shape;

    if (gov->cfg.require_result_match && !k->challenger_valid) {
        /* C3 */
        d.reason = QIHSE_OPT_GOV_REASON_RESULT_MISMATCH;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }
    if (k->served.count < gov->cfg.min_samples ||
        k->challenger.count < gov->cfg.min_samples) {
        /* C2 — not enough data: the incumbent keeps serving. */
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }

    double incumbent_mean = gov_arm_mean(&k->served);
    double candidate_mean = gov_arm_mean(&k->challenger);
    d.previous_mean = incumbent_mean;
    d.challenger_mean = candidate_mean;

    if (candidate_mean > incumbent_mean * (1.0 + gov_effective_bound(gov, k))) {
        /* C1 — the regression bound. */
        d.reason = QIHSE_OPT_GOV_REASON_REGRESSION_BOUND;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }
    if (candidate_mean > incumbent_mean * (1.0 - gov->cfg.improvement_margin)) {
        /* C6 — "not worse" is not a reason to change a production plan. */
        d.reason = QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT;
        return gov_finish(gov, k, key, d, GOV_ACT_NONE, now);
    }

    d.outcome = QIHSE_OPT_GOV_OUTCOME_SWITCH;
    d.reason = QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER;
    d.serve_shape = candidate_shape;
    d.probation = true;
    d.probation_elapsed_ms = 0;
    return gov_finish(gov, k, key, d, GOV_ACT_SWITCH, now);
}

qihse_opt_gov_decision_t qihse_optimizer_governance_evaluate(
        qihse_opt_governance_t* gov, const char* key,
        const qihse_plan_node_t* incumbent, const qihse_plan_node_t* candidate) {
    return qihse_optimizer_governance_evaluate_shapes(
        gov, key,
        qihse_optimizer_plan_shape_digest(incumbent),
        qihse_optimizer_plan_shape_digest(candidate));
}

qihse_opt_gov_decision_t qihse_optimizer_governance_consider(
        qihse_opt_governance_t* gov, const char* key, const qihse_sql_ast_t* ast) {
    qihse_opt_gov_decision_t d;
    memset(&d, 0, sizeof(d));
    d.outcome = QIHSE_OPT_GOV_OUTCOME_KEEP;
    d.reason = QIHSE_OPT_GOV_REASON_NONE;
    if (!gov || !gov_key_ok(key) || !ast) {
        d.reason = QIHSE_OPT_GOV_REASON_KEY_INVALID;
        return d;
    }
    /* Without an optimizer there is nothing to rebuild: a no-op, and a no-op
     * keeps the incumbent. */
    if (!gov->opt) return d;

    qihse_plan_node_t* plan = qihse_optimizer_build_plan(gov->opt, ast);
    if (!plan) return d; /* no plan for this statement: nothing to consider */
    uint64_t shape = qihse_optimizer_plan_shape_digest(plan);
    qihse_plan_node_free(plan);
    if (shape == 0) return d;

    gov_key_t* k = gov_find_key(gov, key, false);
    /* On a key the harness has not seen, the rebuilt plan IS the baseline. */
    uint64_t incumbent = k ? k->served_shape : shape;
    return qihse_optimizer_governance_evaluate_shapes(gov, key, incumbent, shape);
}

bool qihse_optimizer_governance_shadow_wanted(qihse_opt_governance_t* gov, const char* key) {
    if (!gov || !gov_key_ok(key)) return false;
    /* C4 — the harness does not spend the caller's cycles on an experiment it
     * could not act on. */
    if (!gov->journal) return false;
    gov_key_t* k = gov_find_key(gov, key, false);
    if (!k || k->probation) return false;
    if (gov_mono_ms() < k->cooldown_until_ms) return false;
    if (k->challenger_shape == 0 || k->challenger_shape == k->served_shape) return false;
    if (gov->cfg.require_result_match && !k->challenger_valid) return false;
    return k->challenger.count < gov->cfg.min_samples;
}

size_t qihse_optimizer_governance_history(const qihse_opt_governance_t* gov,
                                          qihse_opt_gov_decision_t* out, size_t max) {
    if (!gov || !out || max == 0) return 0;
    size_t n = gov->history_count;
    if (n > max) n = max;
    for (size_t i = 0; i < n; i++) {
        size_t idx = (gov->history_head + QIHSE_OPT_GOV_HISTORY_MAX - 1u - i)
                     % QIHSE_OPT_GOV_HISTORY_MAX;
        out[i] = gov->history[idx];
    }
    return n;
}

size_t qihse_optimizer_governance_probation_count(const qihse_opt_governance_t* gov) {
    if (!gov) return 0;
    size_t n = 0;
    for (size_t i = 0; i < QIHSE_OPT_GOV_MAX_KEYS; i++) {
        if (gov->keys[i].used && gov->keys[i].probation) n++;
    }
    return n;
}

int qihse_optimizer_governance_set_regression_budget(qihse_opt_governance_t* gov,
                                                     const char* key, double bound) {
    if (!gov || !gov_key_ok(key)) return -1;
    /* A budget that is negative or not a number would disable the constraint
     * it is supposed to tighten, so it is refused rather than clamped: the
     * caller has to say what it means. */
    if (!(bound >= 0.0) || bound > 1.0) return -1;
    gov_key_t* k = gov_find_key(gov, key, false);
    if (!k) return -1; /* nothing governed under that key yet */
    k->regression_bound = bound;
    return 0;
}

/* ── Metrics registration ──────────────────────────────────────────────── */

int qihse_optimizer_governance_attach_metrics(qihse_opt_governance_t* gov,
                                             qihse_metrics_registry_t* reg) {
    if (!gov || !reg) return -1;

    /* Registration is refused when the family already exists, which is the
     * correct outcome for a second harness sharing one registry: the series
     * are then resolved instead of duplicated. */
    (void)qihse_metrics_register_bounded(
        reg, "qihse_optimizer_plan_decisions_total",
        "Optimizer plan decisions by outcome (W5.1 governance).",
        METRIC_COUNTER, "outcome", GOV_OUTCOME_NAMES, QIHSE_OPT_GOV_OUTCOME_COUNT);
    (void)qihse_metrics_register_bounded(
        reg, "qihse_optimizer_plan_rollbacks_total",
        "Optimizer plan rollbacks by cause (W5.1 governance).",
        METRIC_COUNTER, "reason", GOV_ROLLBACK_NAMES, QIHSE_OPT_GOV_ROLLBACK_REASON_COUNT);
    (void)qihse_metrics_register(
        reg, "qihse_optimizer_plan_active_switches",
        "Governed plans currently inside their rollback window.", METRIC_GAUGE);

    bool ok = true;
    for (size_t i = 0; i < QIHSE_OPT_GOV_OUTCOME_COUNT; i++) {
        gov->decisions_series[i] = qihse_metrics_series(
            reg, "qihse_optimizer_plan_decisions_total", GOV_OUTCOME_NAMES[i]);
        if (!gov->decisions_series[i]) ok = false;
    }
    for (size_t i = 0; i < QIHSE_OPT_GOV_ROLLBACK_REASON_COUNT; i++) {
        gov->rollbacks_series[i] = qihse_metrics_series(
            reg, "qihse_optimizer_plan_rollbacks_total", GOV_ROLLBACK_NAMES[i]);
        if (!gov->rollbacks_series[i]) ok = false;
    }
    gov->active_switches_series =
        qihse_metrics_series(reg, "qihse_optimizer_plan_active_switches", NULL);
    if (!gov->active_switches_series) ok = false;

    gov->metrics = reg;
    gov_metrics_probation(gov);
    return ok ? 0 : -1;
}
