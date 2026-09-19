#ifndef QIHSE_OPTIMIZER_GOVERNANCE_H
#define QIHSE_OPTIMIZER_GOVERNANCE_H

/* ── W5.1 Optimizer governance ─────────────────────────────────────────────
 *
 * A harness that lets a plan change be evaluated, DETECTS when the change was
 * wrong, and UNDOES it automatically — with the evidence persisted so the
 * decision can be audited afterwards.  A harness that can silently make a
 * query slower is worse than no harness, so the design is deliberately
 * asymmetric: changing a plan is hard (it needs a durable journal, enough
 * samples on both arms, a proven improvement and a satisfied regression
 * bound), while keeping or reverting to the plan already in service is the
 * default in every situation the harness cannot evaluate.
 *
 * ── What is governed
 *
 * The unit is a (workload key, plan shape) pair.  A "plan shape" is the
 * 64-bit digest qihse_optimizer_plan_shape_digest() computes from a plan tree
 * — node types, scan/index choice, join algorithm, the columns each node
 * touches — and NOT the table names, so the shape is a structural identity
 * and the workload key carries the rest.  A digest is a hash: it is never
 * used as a metrics label.
 *
 * ── The two arms (shadow / A-B)
 *
 *   INCUMBENT (control)   the plan the caller is serving right now.  Its cost
 *                         samples come from real traffic: the caller reports
 *                         what each served query cost.
 *   CANDIDATE (treatment) the plan being considered.  Its samples come from
 *                         SHADOW runs: the caller executes the candidate,
 *                         compares its result with the incumbent's, and throws
 *                         the candidate's result away.  Nothing a user sees
 *                         comes from the candidate until a switch is proven.
 *
 * qihse_optimizer_governance_shadow_wanted() is how the harness DIRECTS that
 * experiment: it answers true while the candidate still needs samples, and
 * the caller then runs one shadow measurement.  After at most min_samples
 * shadow runs the harness stops asking and the next evaluate() decides.
 *
 * ── The switch rule (the declared rule; the only way a plan changes)
 *
 *   switch(key) iff
 *        the decision record was committed to the journal   [C4: no journal,
 *                                                            no switch]
 *     && !cooldown_active(key)                              [C5: a rolled-back
 *                                                            key waits]
 *     && candidate_valid                                    [C3: every shadow
 *                                                            result matched]
 *     && incumbent.samples >= min_samples                   [C2: minimum
 *     && candidate.samples >= min_samples                     sample size]
 *     && candidate.mean <= incumbent.mean * (1 + regression_bound)  [C1]
 *     && candidate.mean <= incumbent.mean * (1 - improvement_margin) [C6]
 *
 *   Anything else keeps the incumbent and is recorded with the reason it was
 *   kept.  min_samples is forced to at least 2, so "switch on one
 *   observation" is not reachable through configuration either.
 *
 * ── Safety constraints, named (each is enforced, and tagged C1..C8 in
 *    src/tractable/qihse_optimizer_governance.c at the line that enforces it)
 *
 *   C1 regression bound      candidate.mean <= incumbent.mean*(1+bound)
 *                            — per workload when one was set, else the default
 *   C2 minimum sample size   both arms, before any switch
 *   C3 result equivalence    a shadow run that returned a different result
 *                            disqualifies the candidate however fast it is
 *   C4 journal required      no committed decision record, no switch
 *   C5 anti-oscillation      a key that just rolled back is not switched again
 *                            until its cooldown expires
 *   C6 proven improvement    "not worse" is not enough to justify a change
 *   C7 bounded everything    keys, sample windows, decision history, records
 *   C8 fail closed           every path that cannot evaluate keeps the
 *                            incumbent; no evidence is never evidence
 *
 * ── The rollback rule
 *
 * A switched plan is on PROBATION until the rollback window closes.  The
 * switch is reverted — the incumbent plan is restored, with no operator
 * involvement — as soon as either is true:
 *
 *   (a) a post-switch observation of the served plan reports a result that
 *       differs from the incumbent's  (correctness: no waiting for the
 *       window), or
 *   (b) elapsed >= rollback_window_ms AND served.samples >=
 *       rollback_min_samples AND served.mean > reference_mean *
 *       (1 + regression_bound), where reference_mean is the mean of the plan
 *       a rollback would restore, FROZEN at the moment of the switch.
 *
 * `served` counts the plan's observations IN SERVICE: the arm is reset when
 * the switch happens, because shadow measurements taken before the plan was
 * in service cannot show how it behaves in service, and leaving them in would
 * dilute the regression the window exists to catch.  The evidence that
 * justified the switch is in the switch's own record.
 *
 * When the window closes with too few post-switch samples the switch is KEPT
 * and the probation stays open: the bound has not been violated by evidence,
 * it has not been tested.  Reverting there would be treating "no evidence" as
 * "evidence of a regression", which is the failure mode this repository keeps
 * re-learning.  The open probation is visible in the decision record, in the
 * history, and in the active-switch gauge.
 *
 * ── Delayed detection
 *
 * Detection is observation-driven: the check runs inside every observe() and
 * every evaluate().  A key that receives no further observations keeps the
 * switched plan — the risk window is longer, and that is the cost of having
 * no measurement at all.  Nothing is lost when the first post-window
 * observation finally arrives: the decision is taken then, with the elapsed
 * time and both means in the evidence, and the cooldown prevents the revert
 * and the switch from chasing each other.
 *
 * ── Persistence
 *
 * Every switch, rollback, refusal and probation outcome is appended to a
 * qihse_event_stream journal (topic "optimizer.governance"), the same store
 * the cluster brain journals its R1/R4 decisions to.  The record carries the
 * evidence the decision rested on — both means, both sample counts, the
 * constraint values IN FORCE at that moment — so the arithmetic can be
 * re-checked from the record alone; the store adds the hash chain and the
 * SHA-384 event id.  A switch is refused when its record cannot be committed.
 * A rollback is NOT refused when the journal write fails: reverting a
 * regressing plan is the safety action, and it is recorded best-effort plus
 * in the bounded in-memory history.
 *
 * State is in memory, the decisions are on disk.  On restart the caller's own
 * plan is re-adopted as the baseline and journaled as BASELINE, so a restart
 * shows up in the audit trail instead of silently resetting it.
 *
 * ── What the harness deliberately does NOT do
 *
 * It never decides from the optimizer's own cost estimates.  The estimates
 * are the thing under governance; a harness that switched plans because the
 * estimator said the new plan was cheaper would be governing the model with
 * the model.  Every decision rests on caller-supplied OBSERVED costs.  The
 * consequence is the statistics contract: this optimizer has no ANALYZE pass,
 * statistics and histograms are caller-supplied, and with no statistics the
 * plans for a query do not differ at all (both arms digest the same shape and
 * the harness reports NO_IMPROVEMENT).  That is the honest outcome — a
 * governance harness over empty statistics has nothing to compare — and it is
 * asserted in tests/test_optimizer_governance.c rather than papered over.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_event_stream.h" /* the decision journal + durability modes */
#include "qihse_metrics.h"      /* W5.2 registry: the only metrics surface */
#include "qihse_optimizer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Declared bounds (C7) ────────────────────────────────────────────────
 *
 * Every one is compile-time, so the worst-case memory of a harness is a
 * constant: MAX_KEYS x (2 sample windows) + a decision history.  A
 * long-running process cannot grow it. */
#define QIHSE_OPT_GOV_KEY_MAX       64u  /* workload key, incl. NUL         */
#define QIHSE_OPT_GOV_SAMPLE_WINDOW 64u  /* observations per arm            */
#define QIHSE_OPT_GOV_MAX_KEYS      32u  /* governed workloads              */
#define QIHSE_OPT_GOV_HISTORY_MAX   16u  /* in-memory decisions, newest first */
#define QIHSE_OPT_GOV_RECORD_MAX    1024u /* one journal record, incl. NUL  */

/* The journal topic.  Dotted, like the cluster brain's "cluster.brain". */
#define QIHSE_OPT_GOV_TOPIC "optimizer.governance"
/* Record schema version, so a later field change is readable by version. */
#define QIHSE_OPT_GOV_RECORD_SCHEMA 1u

/* ── Outcome: what the caller must serve ─────────────────────────────────
 *
 * Four values, and the default is KEEP.  The reason a decision was taken is
 * the second axis (below); the outcome is the instruction. */
typedef enum {
    QIHSE_OPT_GOV_OUTCOME_KEEP = 0,  /* serve the incumbent; nothing changed */
    QIHSE_OPT_GOV_OUTCOME_SWITCH,    /* serve the candidate: it is now the incumbent */
    QIHSE_OPT_GOV_OUTCOME_ROLLBACK,  /* serve the incumbent again: the switch was reverted */
    QIHSE_OPT_GOV_OUTCOME_OBSERVE,   /* an observation was recorded; no plan decision */
    QIHSE_OPT_GOV_OUTCOME_COUNT
} qihse_opt_gov_outcome_t;

/* The complete, declared value set of the `outcome` label of
 * qihse_optimizer_plan_decisions_total.  Registration uses this table, so the
 * family can never grow a series from data. */
const char* qihse_opt_gov_outcome_name(qihse_opt_gov_outcome_t outcome);

typedef enum {
    QIHSE_OPT_GOV_REASON_NONE = 0,
    QIHSE_OPT_GOV_REASON_BASELINE,            /* first plan for a key: adopted, not switched */
    QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT,      /* identical shape, or within the margin */
    QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES,/* fewer than min_samples on an arm */
    QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER,    /* the switch rule was satisfied */
    QIHSE_OPT_GOV_REASON_REGRESSION_BOUND,    /* C1: candidate exceeds the bound */
    QIHSE_OPT_GOV_REASON_RESULT_MISMATCH,     /* C3: a shadow result differed */
    QIHSE_OPT_GOV_REASON_NO_JOURNAL,          /* C4: no committed record, no switch */
    QIHSE_OPT_GOV_REASON_COOLDOWN,            /* C5: post-rollback cooldown in force */
    QIHSE_OPT_GOV_REASON_PROBATION,           /* inside the rollback window */
    QIHSE_OPT_GOV_REASON_PROBATION_PASSED,    /* window closed with no violation: kept */
    QIHSE_OPT_GOV_REASON_ROLLBACK_REGRESSION, /* the served plan regressed: reverted */
    QIHSE_OPT_GOV_REASON_ROLLBACK_MISMATCH,   /* the served plan's result differed: reverted */
    QIHSE_OPT_GOV_REASON_UNKNOWN_SHAPE,       /* observation for an untracked shape */
    QIHSE_OPT_GOV_REASON_KEY_INVALID,         /* key missing, empty or too long */
    QIHSE_OPT_GOV_REASON_TABLE_FULL,          /* the bounded key table is full */
    QIHSE_OPT_GOV_REASON_INCUMBENT_MISMATCH,  /* the served plan changed out of band */
    QIHSE_OPT_GOV_REASON_DISQUALIFIED,        /* this candidate already failed its probation */
    QIHSE_OPT_GOV_REASON_COUNT
} qihse_opt_gov_reason_t;

const char* qihse_opt_gov_reason_name(qihse_opt_gov_reason_t reason);

/* The complete, declared value set of the `reason` label of
 * qihse_optimizer_plan_rollbacks_total: the only two reasons a rollback can
 * have.  Kept separate from the reason enum above so the rollback family
 * declares a set that is exactly the set of rollback causes. */
typedef enum {
    QIHSE_OPT_GOV_ROLLBACK_REGRESSION = 0, /* (b) the bound was exceeded */
    QIHSE_OPT_GOV_ROLLBACK_MISMATCH,       /* (a) the result changed */
    QIHSE_OPT_GOV_ROLLBACK_REASON_COUNT
} qihse_opt_gov_rollback_reason_t;

const char* qihse_opt_gov_rollback_reason_name(qihse_opt_gov_rollback_reason_t reason);

/* ── The safety constraints, as configuration ────────────────────────────
 *
 * The struct is the declaration: each field is one of C1..C6. */
typedef struct {
    /* C1 — a candidate may not exceed the incumbent's mean cost by more than
     * this fraction.  0.20 = "up to 20% worse is tolerated", and the same
     * bound is what a post-switch probation is judged against. */
    double regression_bound;
    /* C6 — how much better the candidate must be before a change is worth
     * making.  A switch on a 0.1% difference is churn, not improvement. */
    double improvement_margin;
    /* C2 — observations of EACH arm required before any switch.  Values
     * below 2 are raised to 2: a switch on one observation is not a rule. */
    size_t min_samples;
    /* C2 — post-switch observations of the served plan required before a
     * regression can be declared. */
    size_t rollback_min_samples;
    /* How long a switched plan is on probation, in milliseconds. */
    uint32_t rollback_window_ms;
    /* C5 — how long a key that rolled back is held off from another switch. */
    uint32_t cooldown_ms;
    /* C3 — when true, a shadow observation whose result differed from the
     * incumbent's disqualifies the candidate, and a post-switch result
     * difference rolls the switch back immediately.  A caller whose workload
     * cannot compare results must set this to false DELIBERATELY: the flag is
     * journaled with every decision, so a weakened correctness constraint is
     * visible in the audit trail instead of being silent. */
    bool require_result_match;
    /* Where the decision journal lives.  NULL or "" means no durable journal,
     * which under C4 means no switch is ever permitted: the harness still
     * observes, counts and reports, it just cannot change a plan. */
    const char* journal_dir;
    qihse_es_durability_t journal_durability;
} qihse_opt_gov_config_t;

/* Defaults: regression_bound 0.20, improvement_margin 0.05, min_samples 8,
 * rollback_min_samples 3, rollback_window_ms 60000, cooldown_ms 300000,
 * require_result_match true, no journal_dir. */
void qihse_opt_gov_config_default(qihse_opt_gov_config_t* out);

/* ── Observations (the caller's evidence) ────────────────────────────────
 *
 * `cost` is in whatever monotone unit the caller measures with (microseconds
 * are the natural one); both arms must use the SAME unit, and the harness
 * only ever compares means of the two arms. */
typedef struct {
    /* Which plan was measured: the digest of the plan tree that ran. */
    uint64_t shape;
    double   cost;
    /* True for a measurement whose result the caller discarded (a shadow run
     * of the candidate).  False for a real served query.  This is what makes
     * "the caller's answer never came from an unproven plan" checkable. */
    bool     shadow;
    /* Did the result equal the incumbent's?  C3.  A caller that cannot
     * compare must leave require_result_match false rather than pass true
     * here, so the audit trail shows the constraint was not in force. */
    bool     result_matched;
} qihse_opt_gov_obs_t;

/* ── Decisions ───────────────────────────────────────────────────────────
 *
 * The evidence a decision rested on, returned to the caller and recorded in
 * the in-memory history and (for every state change) in the journal. */
typedef struct {
    qihse_opt_gov_outcome_t outcome;
    qihse_opt_gov_reason_t  reason;
    /* The shape the caller must serve now.  0 = the harness has no
     * instruction (only reachable on an invalid key, where it also has no
     * opinion to offer). */
    uint64_t serve_shape;
    /* The plan that was being served when the decision was taken, and the
     * plan the decision was about (0 when there was none).  On a ROLLBACK,
     * `previous_shape` is the plan that regressed and `serve_shape` is the
     * restored one. */
    uint64_t previous_shape;
    uint64_t challenger_shape;
    /* The evidence: the mean cost and sample count behind each of the two
     * shapes above, as the harness held them at decision time. */
    double   previous_mean;
    double   challenger_mean;
    size_t   previous_samples;
    size_t   challenger_samples;
    /* The regression budget the decision was actually judged against: the
     * key's own budget when one was set, otherwise the harness default.  It
     * is in the journal record too, so the arithmetic can be re-checked. */
    double   regression_bound;
    /* True while the served plan is inside its rollback window. */
    bool     probation;
    /* Milliseconds elapsed since the switch that opened the current
     * probation (0 when there is none). */
    uint64_t probation_elapsed_ms;
    /* Monotonic sequence over everything the harness records, including the
     * notice that a probation window opened.  `recorded` says whether this
     * decision is in the durable journal, and `journal_offset` is the byte
     * offset of its record frame when it is. */
    uint64_t seq;
    bool     recorded;
    uint64_t journal_offset;
    uint64_t ts_ms;
} qihse_opt_gov_decision_t;

typedef struct qihse_opt_governance qihse_opt_governance_t;

/* Create a harness.  `opt` may be NULL (the harness never decides from the
 * optimizer's estimates, so it does not need one; it is kept so that
 * qihse_optimizer_governance_consider() can rebuild a plan from an AST).  A
 * journal that cannot be opened does not fail creation: it disables switches
 * and is reported on every decision as NO_JOURNAL.  Returns NULL only when
 * out of memory. */
qihse_opt_governance_t* qihse_optimizer_governance_create(
    qihse_optimizer_t* opt, const qihse_opt_gov_config_t* config);
void qihse_optimizer_governance_destroy(qihse_opt_governance_t* gov);

/* Report one measurement.  This is also where a pending probation is
 * evaluated, so an automatic rollback happens inside this call: there is no
 * separate "check" step an operator has to perform. */
qihse_opt_gov_decision_t qihse_optimizer_governance_observe(
    qihse_opt_governance_t* gov, const char* key, const qihse_opt_gov_obs_t* obs);

/* Compare a candidate plan against the incumbent for `key`.  `incumbent` is
 * the plan the caller is serving, `candidate` the plan it is considering;
 * either may be NULL only when the corresponding digest is 0, which is
 * refused.  On the first call for a key the incumbent is adopted as the
 * baseline (reason BASELINE) — that is not a switch: the caller would have
 * served that plan without the harness. */
qihse_opt_gov_decision_t qihse_optimizer_governance_evaluate(
    qihse_opt_governance_t* gov, const char* key,
    const qihse_plan_node_t* incumbent, const qihse_plan_node_t* candidate);

/* Same decision, for callers that identify plans by digest already. */
qihse_opt_gov_decision_t qihse_optimizer_governance_evaluate_shapes(
    qihse_opt_governance_t* gov, const char* key,
    uint64_t incumbent_shape, uint64_t candidate_shape);

/* Rebuild the plan for `ast` from the optimizer's current statistics and
 * evaluate it as a candidate against the recorded incumbent.  This is the
 * integration point for a database: statistics changed, so the plan the
 * optimizer would choose now may differ from the one in service.  The
 * candidate is digested and freed; the caller serves what the decision says.
 * Returns KEEP/NO_IMPROVEMENT when the rebuilt plan has the same shape as the
 * incumbent, which is what happens when no statistics were ever collected. */
qihse_opt_gov_decision_t qihse_optimizer_governance_consider(
    qihse_opt_governance_t* gov, const char* key, const qihse_sql_ast_t* ast);

/* The A/B direction: true while the harness wants one shadow measurement of
 * the candidate for `key`.  False when there is no candidate, when the
 * candidate already has min_samples, when a probation or cooldown is in
 * force, or when the journal that a switch would need is not available — the
 * harness does not spend the caller's cycles on an experiment it could not
 * act on. */
bool qihse_optimizer_governance_shadow_wanted(qihse_opt_governance_t* gov,
                                              const char* key);

/* Give one governed key its own regression budget, overriding the harness
 * default for that workload (C1 "regression budgets by workload").  0.0 is a
 * legal, strict budget — no regression is tolerated at all — so the argument
 * is validated as a finite, non-negative fraction.  The key must already be
 * governed (it has to have a baseline to judge against); returns 0 on
 * success, -1 for an unknown key or an invalid bound.  The effective budget
 * travels with every decision and every journal record for that key, so a
 * budget that changed under an operator's feet is visible in the audit trail.
 */
int qihse_optimizer_governance_set_regression_budget(qihse_opt_governance_t* gov,
                                                     const char* key, double bound);

/* The bounded in-memory decision history, newest first.  Returns how many
 * entries were written (at most `max`, at most QIHSE_OPT_GOV_HISTORY_MAX).
 * The durable record is the journal; this is for in-process inspection and
 * for tests. */
size_t qihse_optimizer_governance_history(const qihse_opt_governance_t* gov,
                                          qihse_opt_gov_decision_t* out,
                                          size_t max);

/* How many governed keys are currently on probation. */
size_t qihse_optimizer_governance_probation_count(const qihse_opt_governance_t* gov);

/* Emit governance metrics into the W5.2 registry — the only metrics surface
 * in this tree.  Families registered (all labels declared, none derived from
 * caller data):
 *
 *   qihse_optimizer_plan_decisions_total{outcome}  counter, 4 declared values
 *   qihse_optimizer_plan_rollbacks_total{reason}   counter, 2 declared values
 *   qihse_optimizer_plan_active_switches           gauge, unlabelled
 *
 * Safe to call on a registry that already has the families (a second harness
 * sharing one registry resolves the existing series).  Metrics are never
 * required for a decision: attach failing leaves governance fully functional.
 * Returns 0 when the metrics are available, -1 otherwise. */
int qihse_optimizer_governance_attach_metrics(qihse_opt_governance_t* gov,
                                              qihse_metrics_registry_t* reg);

#ifdef __cplusplus
}
#endif

#endif
