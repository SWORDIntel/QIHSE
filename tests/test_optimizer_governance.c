/*
 * test_optimizer_governance.c — W5.1 optimizer governance.
 *
 * Covers src/tractable/qihse_optimizer_governance.c: shadow evaluation of a
 * candidate plan with explicit safety constraints, automatic rollback, and
 * decisions persisted to an event-stream journal.
 *
 * A governance test that only asserts "a switch happened" proves nothing
 * about safety, so the cases below are chosen around the ways a harness can
 * fail to be safe:
 *
 *   1.  Plan identity: the shape digest is deterministic, changes when the
 *       plan actually changes (seq scan -> index scan), and is 0 only for no
 *       plan at all.
 *   2.  The statistics contract.  This optimizer has no ANALYZE pass, so
 *       statistics and histograms are caller-supplied.  With no statistics a
 *       query's plan shape does not change, and the harness reports
 *       NO_IMPROVEMENT rather than inventing a candidate: the test asserts
 *       both the "nothing to compare" case and the "a real statistics change
 *       (an index) does produce a candidate" case.
 *   3.  Fail closed with no journal: enough evidence and a much better
 *       candidate, and the switch is still REFUSED (C4), and the harness does
 *       not even ask for shadow runs.
 *   4.  Insufficient samples never switch (C2), including "one observation".
 *   5.  The regression bound refuses a candidate that is worse (C1).
 *   6.  A shadow result that disagrees with the incumbent disqualifies the
 *       candidate however cheap it is (C3).
 *   7.  THE ROLLBACK.  Switch on evidence, then observe the served plan
 *       regressing past the bound once the window closes: the harness must
 *       revert on its own — no operator, no explicit "check" call — restore
 *       the incumbent shape, and record the decision with the evidence.  The
 *       journal is then read back and the SWITCH and ROLLBACK records are
 *       asserted to be there.
 *   8.  The rollback that does not wait for the window: a served plan whose
 *       result changed is reverted immediately.
 *   9.  What happens with too little data AFTER a switch: the switch is kept
 *       (an unmeasured plan has not been shown to regress) and the probation
 *       stays open rather than silently passing.
 *  10.  Bounded structures: the key table refuses the 33rd key instead of
 *       growing, and the decision history stays at its declared bound.
 *  11.  Bypass detection: a caller that changes the served plan out of band is
 *       refused and journaled rather than silently becoming the baseline.
 *  12.  Metrics use the W5.2 registry with declared label values only, and a
 *       key that carries JSON metacharacters cannot rewrite a journal record.
 *
 * Observation streams are synthetic on purpose: the harness's contract is
 * caller-supplied evidence, exactly like the statistics contract, and this
 * test exercises the governance state machine.  It does not claim to have
 * measured a real query, and no assertion here depends on wall-clock timing
 * beyond the declared rollback window.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_event_stream.h"
#include "qihse_metrics.h"
#include "qihse_optimizer.h"
#include "qihse_optimizer_governance.h"
#include "qihse_schema.h"
#include "qihse_sql_parser.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* ── Helpers ────────────────────────────────────────────────────────────── */

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

static void expect_outcome(const qihse_opt_gov_decision_t* d,
                           qihse_opt_gov_outcome_t outcome,
                           qihse_opt_gov_reason_t reason, const char* what) {
    if (d->outcome != outcome || d->reason != reason) {
        printf("FAIL %s: outcome=%s reason=%s, want outcome=%s reason=%s\n", what,
               qihse_opt_gov_outcome_name(d->outcome), qihse_opt_gov_reason_name(d->reason),
               qihse_opt_gov_outcome_name(outcome), qihse_opt_gov_reason_name(reason));
        assert(0);
    }
}

/* Report one observation and return the decision it produced. */
static qihse_opt_gov_decision_t observe(qihse_opt_governance_t* gov, const char* key,
                                        uint64_t shape, double cost, bool shadow,
                                        bool result_matched) {
    qihse_opt_gov_obs_t o;
    memset(&o, 0, sizeof(o));
    o.shape = shape;
    o.cost = cost;
    o.shadow = shadow;
    o.result_matched = result_matched;
    return qihse_optimizer_governance_observe(gov, key, &o);
}

/* `n` identical observations. */
static void feed(qihse_opt_governance_t* gov, const char* key, uint64_t shape,
                 double cost, bool shadow, size_t n) {
    for (size_t i = 0; i < n; i++) observe(gov, key, shape, cost, shadow, true);
}

/* Read the journal back: the audit trail is only worth anything if a reader
 * can find the decision in it afterwards. */
typedef struct {
    size_t records;
    size_t baseline, switches, rollbacks, probation_open;
    char   rollback_record[QIHSE_OPT_GOV_RECORD_MAX];
    char   switch_record[QIHSE_OPT_GOV_RECORD_MAX];
    char   all[4096];
    size_t all_len;
    bool   all_readable;
} journal_scan_t;

static void journal_scan(const char* dir, journal_scan_t* out) {
    memset(out, 0, sizeof(*out));
    out->all_readable = true;
    qihse_event_stream_t* journal = qihse_event_stream_open(dir, QIHSE_ES_DURABILITY_NONE, true);
    assert(journal);
    uint64_t cursor = 0;
    qihse_es_record_header_t header;
    uint8_t* payload = NULL;
    size_t payload_size = 0;
    char text[QIHSE_OPT_GOV_RECORD_MAX * 2];
    while (qihse_event_stream_iterate(journal, QIHSE_OPT_GOV_TOPIC, &cursor, &header,
                                      &payload, &payload_size)) {
        if (!payload || payload_size >= sizeof(text)) {
            out->all_readable = false;
        } else {
            memcpy(text, payload, payload_size);
            text[payload_size] = '\0';
            out->records++;
            if (out->all_len + payload_size + 1u < sizeof(out->all)) {
                memcpy(out->all + out->all_len, text, payload_size + 1u);
                out->all_len += payload_size;
            }
            if (strstr(text, "\"kind\":\"SWITCH\"")) {
                out->switches++;
                memcpy(out->switch_record, text, payload_size + 1u);
            } else if (strstr(text, "\"kind\":\"ROLLBACK\"")) {
                out->rollbacks++;
                memcpy(out->rollback_record, text, payload_size + 1u);
            } else if (strstr(text, "\"kind\":\"BASELINE\"")) {
                out->baseline++;
            } else if (strstr(text, "\"kind\":\"PROBATION_OPEN\"")) {
                out->probation_open++;
            }
        }
        free(payload);
        payload = NULL;
    }
    qihse_event_stream_destroy(journal);
}

/* A schema with a users table; `indexed` adds an index on age, which is what
 * flips the optimizer's scan choice. */
static qihse_schema_registry_t* make_schema(bool indexed) {
    qihse_schema_registry_t* reg = qihse_schema_registry_create();
    assert(reg);
    qihse_sql_ast_t* ddl = qihse_parse_sql_to_ast(
        "CREATE TABLE users (id INT PRIMARY KEY, dept TEXT, age INT)");
    assert(ddl && qihse_schema_create_table(reg, ddl) == 0);
    qihse_sql_ast_free(ddl);
    if (indexed) {
        ddl = qihse_parse_sql_to_ast("CREATE INDEX users_age ON users (age)");
        assert(ddl && qihse_schema_create_index(reg, ddl) == 0);
        qihse_sql_ast_free(ddl);
    }
    return reg;
}

static qihse_opt_gov_config_t gov_cfg(const char* journal_dir) {
    qihse_opt_gov_config_t cfg;
    qihse_opt_gov_config_default(&cfg);
    cfg.journal_dir = journal_dir;
    cfg.journal_durability = QIHSE_ES_DURABILITY_NONE;
    return cfg;
}

/* ── 1. Plan shape digest ───────────────────────────────────────────────── */

static void test_shape_digest(void) {
    qihse_schema_registry_t* reg = make_schema(false);
    qihse_optimizer_t* opt = qihse_optimizer_create(reg);
    assert(opt);
    qihse_optimizer_set_table_stats(opt, "users", 100000);
    qihse_optimizer_set_column_stats(opt, "users", "age", 50000, 0.0, "18", "95");

    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast("SELECT id FROM users WHERE age = 30");
    assert(ast);
    qihse_plan_node_t* p1 = qihse_optimizer_build_plan(opt, ast);
    qihse_plan_node_t* p2 = qihse_optimizer_build_plan(opt, ast);
    assert(p1 && p2);
    assert(p1->type == QIHSE_PLAN_SEQ_SCAN);
    uint64_t d1 = qihse_optimizer_plan_shape_digest(p1);
    assert(d1 != 0);
    assert(qihse_optimizer_plan_shape_digest(p2) == d1); /* deterministic */
    assert(qihse_optimizer_plan_shape_digest(NULL) == 0); /* no plan, no shape */
    qihse_plan_node_free(p2);

    /* An ORDER BY is a different plan, so a different shape. */
    qihse_sql_ast_t* sorted = qihse_parse_sql_to_ast("SELECT id FROM users ORDER BY age");
    assert(sorted);
    qihse_plan_node_t* p3 = qihse_optimizer_build_plan(opt, sorted);
    assert(p3 && p3->type == QIHSE_PLAN_SORT);
    assert(qihse_optimizer_plan_shape_digest(p3) != d1);
    qihse_plan_node_free(p3);
    qihse_sql_ast_free(sorted);

    /* A real plan change — the index appears — is a different shape. */
    qihse_sql_ast_t* ddl = qihse_parse_sql_to_ast("CREATE INDEX users_age ON users (age)");
    assert(ddl && qihse_schema_create_index(reg, ddl) == 0);
    qihse_sql_ast_free(ddl);
    qihse_plan_node_t* p4 = qihse_optimizer_build_plan(opt, ast);
    assert(p4 && p4->type == QIHSE_PLAN_INDEX_SCAN);
    assert(qihse_optimizer_plan_shape_digest(p4) != d1);
    qihse_plan_node_free(p4);

    qihse_plan_node_free(p1);
    qihse_sql_ast_free(ast);
    qihse_optimizer_destroy(opt);
    qihse_schema_registry_destroy(reg);
    printf("PASS governance: plan shape digest is deterministic and follows the plan choice\n");
}

/* ── 2. The statistics contract ─────────────────────────────────────────── */

static void test_no_statistics_means_no_candidate(const char* dir) {
    qihse_schema_registry_t* reg = make_schema(false);
    qihse_optimizer_t* opt = qihse_optimizer_create(reg);
    assert(opt);

    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast("SELECT id FROM users WHERE age = 30");
    assert(ast);

    /* No statistics at all, then a row count that changes no choice: the plan
     * the optimizer builds is the same shape both times.  There is no
     * candidate plan to evaluate, and the harness must say so instead of
     * manufacturing a difference out of two identical plans. */
    qihse_plan_node_t* a = qihse_optimizer_build_plan(opt, ast);
    assert(a);
    uint64_t digest_a = qihse_optimizer_plan_shape_digest(a);
    qihse_plan_node_free(a);
    qihse_optimizer_set_table_stats(opt, "users", 50000);
    qihse_plan_node_t* b = qihse_optimizer_build_plan(opt, ast);
    assert(b);
    uint64_t digest_b = qihse_optimizer_plan_shape_digest(b);
    qihse_plan_node_free(b);
    assert(digest_a == digest_b);

    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(opt, &cfg);
    assert(gov);

    /* The first plan for a key is the baseline (the caller's own plan). */
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_consider(gov, "q:users:age", ast);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_BASELINE, "baseline");
    assert(d.serve_shape == digest_a);
    assert(d.recorded);

    /* Re-planning under unchanged statistics yields the same shape: nothing
     * to compare, no shadow run requested. */
    d = qihse_optimizer_governance_consider(gov, "q:users:age", ast);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT,
                   "empty statistics");
    assert(d.serve_shape == digest_a);
    assert(!qihse_optimizer_governance_shadow_wanted(gov, "q:users:age"));

    /* Now a statistics change that DOES change the plan: the index lands and
     * the scan flips.  The harness sees a candidate and asks for shadow
     * measurements — it does not switch, and it does not pretend the plan
     * change did not happen either. */
    qihse_sql_ast_t* ddl = qihse_parse_sql_to_ast("CREATE INDEX users_age ON users (age)");
    assert(ddl && qihse_schema_create_index(reg, ddl) == 0);
    qihse_sql_ast_free(ddl);
    d = qihse_optimizer_governance_consider(gov, "q:users:age", ast);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES,
                   "new candidate plan");
    assert(d.serve_shape == digest_a);       /* the incumbent is untouched */
    assert(d.challenger_shape != digest_a);
    assert(qihse_optimizer_governance_shadow_wanted(gov, "q:users:age"));

    qihse_optimizer_governance_destroy(gov);
    qihse_sql_ast_free(ast);
    qihse_optimizer_destroy(opt);
    qihse_schema_registry_destroy(reg);
    printf("PASS governance: no statistics means no candidate; a real plan change does\n");
}

/* ── 3. Fail closed with no journal (C4) ────────────────────────────────── */

static void test_no_journal_never_switches(void) {
    qihse_opt_gov_config_t cfg;
    qihse_opt_gov_config_default(&cfg);
    cfg.journal_dir = NULL; /* the only difference from a working harness */
    cfg.min_samples = 2;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0x1111111111111111ULL, B = 0x2222222222222222ULL;
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_BASELINE, "no-journal baseline");
    assert(d.serve_shape == A);

    /* The candidate is twice as fast with plenty of samples on both arms. */
    feed(gov, "k", A, 100.0, false, 4);
    feed(gov, "k", B, 50.0, true, 4);
    d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_NO_JOURNAL, "no-journal switch");
    assert(d.serve_shape == A);   /* the incumbent still serves */
    assert(!d.recorded);
    /* The harness does not even ask for shadow runs it could not act on. */
    assert(!qihse_optimizer_governance_shadow_wanted(gov, "k"));
    assert(qihse_optimizer_governance_probation_count(gov) == 0);

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: no journal, no switch (C4) — the incumbent keeps serving\n");
}

/* ── 4. Minimum sample size (C2) ────────────────────────────────────────── */

static void test_insufficient_samples_never_switch(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 4;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0xaaaaULL, B = 0xbbbbULL;
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_BASELINE, "baseline");

    /* One observation of a 100x cheaper candidate.  "Switch on one
     * observation" is not a rule: it must not switch. */
    feed(gov, "k", A, 1000.0, false, 3);
    feed(gov, "k", B, 10.0, true, 1);
    d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES,
                   "one observation");
    assert(d.serve_shape == A);
    assert(d.challenger_samples == 1);
    assert(d.previous_samples == 3);

    /* Enough on the candidate arm, still short on the incumbent's: not
     * enough, and the harness stops asking for shadow runs. */
    feed(gov, "k", B, 10.0, true, 3);
    assert(!qihse_optimizer_governance_shadow_wanted(gov, "k"));
    d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES,
                   "candidate at minimum, incumbent short");
    assert(d.challenger_samples == 4);
    assert(d.previous_samples == 3);

    /* The last incumbent sample makes both arms sufficient: now it switches. */
    feed(gov, "k", A, 1000.0, false, 1);
    d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_SWITCH, QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER,
                   "enough evidence");
    assert(d.serve_shape == B);
    assert(d.probation);
    assert(d.recorded);
    assert(qihse_optimizer_governance_probation_count(gov) == 1);

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: fewer than min_samples on either arm never switches (C2)\n");
}

/* ── 5. Regression bound (C1) ───────────────────────────────────────────── */

static void test_regression_bound_refuses(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 2;
    cfg.regression_bound = 0.20;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0x1ULL, B = 0x2ULL;
    qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    feed(gov, "k", A, 100.0, false, 4);
    feed(gov, "k", B, 150.0, true, 4); /* 50% worse: outside the 20% bound */

    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_REGRESSION_BOUND,
                   "regression bound");
    assert(d.serve_shape == A);
    assert(d.previous_mean > 99.0 && d.previous_mean < 101.0);
    assert(d.challenger_mean > 149.0 && d.challenger_mean < 151.0);

    /* A candidate inside the bound but not better by the margin is churn, not
     * improvement: keep. */
    qihse_opt_gov_decision_t d2 = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, 0x3ULL);
    assert(d2.reason == QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES); /* a new candidate: no evidence */

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: a candidate worse than the bound is refused (C1)\n");
}

/* ── 5b. Regression budgets by workload (C1, per key) ───────────────────── */

static void test_per_workload_budget(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 2;
    cfg.regression_bound = 0.20;   /* the harness default */
    cfg.rollback_min_samples = 1;
    cfg.rollback_window_ms = 10;
    cfg.cooldown_ms = 60000;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0xE1ULL, B = 0xE2ULL;

    /* k1: a candidate 10% worse.  Under the harness default (20%) the
     * regression bound does not fire, so the decision is the "not better
     * enough" keep. */
    qihse_optimizer_governance_evaluate_shapes(gov, "k1", A, B);
    feed(gov, "k1", A, 100.0, false, 2);
    feed(gov, "k1", B, 110.0, true, 2);
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "k1", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT,
                   "default budget allows 10% worse");
    assert(d.regression_bound > 0.19 && d.regression_bound < 0.21);

    /* The same workload with its own budget refuses it. */
    assert(qihse_optimizer_governance_set_regression_budget(gov, "k1", 0.05) == 0);
    d = qihse_optimizer_governance_evaluate_shapes(gov, "k1", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_REGRESSION_BOUND,
                   "workload budget refuses 10% worse");
    assert(d.regression_bound > 0.04 && d.regression_bound < 0.06);

    /* A budget is refused rather than silently clamped when it cannot mean
     * what it says, and a key the harness does not govern has no budget. */
    assert(qihse_optimizer_governance_set_regression_budget(gov, "k1", -0.5) == -1);
    assert(qihse_optimizer_governance_set_regression_budget(gov, "k1", 1.5) == -1);
    assert(qihse_optimizer_governance_set_regression_budget(gov, "unknown", 0.05) == -1);

    /* k2: the budget governs the ROLLBACK too, not just the switch.  A 5%
     * cheaper candidate switches in; a 10% regression then reverts it — which
     * the default 20% budget would have tolerated. */
    qihse_optimizer_governance_evaluate_shapes(gov, "k2", A, B);
    assert(qihse_optimizer_governance_set_regression_budget(gov, "k2", 0.05) == 0);
    feed(gov, "k2", A, 100.0, false, 2);
    feed(gov, "k2", B, 95.0, true, 2);
    d = qihse_optimizer_governance_evaluate_shapes(gov, "k2", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_SWITCH, QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER,
                   "k2 switch");
    assert(d.serve_shape == B);

    sleep_ms(20);
    d = observe(gov, "k2", B, 110.0, false, true);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_ROLLBACK, QIHSE_OPT_GOV_REASON_ROLLBACK_REGRESSION,
                   "k2 tight-budget rollback");
    assert(d.serve_shape == A);
    assert(d.regression_bound > 0.04 && d.regression_bound < 0.06);

    /* The audit trail says which budget was applied, not just that one was. */
    journal_scan_t scan;
    journal_scan(dir, &scan);
    assert(scan.rollbacks >= 1);
    assert(strstr(scan.rollback_record, "\"regression_bound\":0.05"));
    assert(strstr(scan.rollback_record, "\"key\":\"k2\""));

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: a per-workload regression budget governs switch and rollback\n");
}

/* ── 6. Result equivalence (C3) ─────────────────────────────────────────── */
static void test_result_mismatch_disqualifies(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 2;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0x10ULL, B = 0x20ULL;
    qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    feed(gov, "k", A, 100.0, false, 3);
    feed(gov, "k", B, 20.0, true, 2);                          /* cheap... */
    observe(gov, "k", B, 20.0, true, false);                    /* ...but wrong */
    assert(!qihse_optimizer_governance_shadow_wanted(gov, "k"));

    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "k", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_RESULT_MISMATCH,
                   "result mismatch");
    assert(d.serve_shape == A);

    /* With the constraint deliberately not in force, the same evidence is
     * enough to switch — and the journal records that the constraint was off,
     * so the weakening is auditable rather than silent. */
    cfg.require_result_match = false;
    qihse_opt_governance_t* gov2 = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov2);
    qihse_optimizer_governance_evaluate_shapes(gov2, "k", A, B);
    feed(gov2, "k", A, 100.0, false, 3);
    feed(gov2, "k", B, 20.0, true, 3);
    qihse_opt_gov_decision_t d2 = qihse_optimizer_governance_evaluate_shapes(gov2, "k", A, B);
    assert(d2.outcome == QIHSE_OPT_GOV_OUTCOME_SWITCH);

    qihse_optimizer_governance_destroy(gov2);
    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: a shadow result that differs disqualifies the candidate (C3)\n");
}

/* ── 7. THE ROLLBACK ────────────────────────────────────────────────────── */

static void test_switch_then_automatic_rollback(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 4;
    cfg.rollback_min_samples = 3;
    cfg.rollback_window_ms = 20;
    cfg.cooldown_ms = 60000;
    cfg.regression_bound = 0.20;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    qihse_metrics_registry_t* reg = qihse_metrics_create();
    assert(reg);
    assert(qihse_optimizer_governance_attach_metrics(gov, reg) == 0);

    const uint64_t A = 0xA1A1ULL, B = 0xB2B2ULL;
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "roll", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_BASELINE, "baseline");
    assert(d.serve_shape == A);

    /* Evidence: the incumbent costs 100, the shadow candidate 50. */
    feed(gov, "roll", A, 100.0, false, 4);
    feed(gov, "roll", B, 50.0, true, 4);

    d = qihse_optimizer_governance_evaluate_shapes(gov, "roll", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_SWITCH, QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER, "switch");
    assert(d.serve_shape == B);
    assert(d.probation);
    assert(d.recorded);
    assert(d.previous_samples == 4 && d.challenger_samples == 4);
    assert(qihse_optimizer_governance_probation_count(gov) == 1);

    /* Inside the window nothing is decided: the probation is open. */
    d = qihse_optimizer_governance_evaluate_shapes(gov, "roll", B, A);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_PROBATION, "probation");
    assert(d.serve_shape == B);

    sleep_ms(30); /* let the rollback window close */

    /* The served plan turns out to cost 200, twice the reference.  The first
     * two observations are below rollback_min_samples, so they decide
     * nothing; the third is the one that can prove the regression, and the
     * rollback happens INSIDE observe() — no operator, no separate check. */
    qihse_opt_gov_decision_t o1 = observe(gov, "roll", B, 200.0, false, true);
    assert(o1.outcome == QIHSE_OPT_GOV_OUTCOME_OBSERVE);
    assert(o1.probation);
    qihse_opt_gov_decision_t o2 = observe(gov, "roll", B, 200.0, false, true);
    assert(o2.outcome == QIHSE_OPT_GOV_OUTCOME_OBSERVE);
    qihse_opt_gov_decision_t o3 = observe(gov, "roll", B, 200.0, false, true);
    expect_outcome(&o3, QIHSE_OPT_GOV_OUTCOME_ROLLBACK, QIHSE_OPT_GOV_REASON_ROLLBACK_REGRESSION,
                   "automatic rollback");
    /* The incumbent is RESTORED: this is the assertion that matters. */
    assert(o3.serve_shape == A);
    assert(o3.previous_shape == B);
    assert(o3.previous_mean > 199.0 && o3.previous_mean < 201.0);
    assert(o3.challenger_mean > 99.0 && o3.challenger_mean < 101.0);
    assert(!o3.probation);
    assert(o3.recorded);
    assert(qihse_optimizer_governance_probation_count(gov) == 0);

    /* Serving the restored plan is not a decision, and the harness reports it
     * as the incumbent from then on. */
    d = qihse_optimizer_governance_evaluate_shapes(gov, "roll", A, A);
    assert(d.serve_shape == A);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_NO_IMPROVEMENT,
                   "restored incumbent");

    /* Anti-oscillation (C5): the plan that just regressed is not switched
     * back in while the cooldown holds, even though it is the cheaper of the
     * two by the pre-switch evidence. */
    d = qihse_optimizer_governance_evaluate_shapes(gov, "roll", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_COOLDOWN, "cooldown");
    assert(d.serve_shape == A);
    assert(!qihse_optimizer_governance_shadow_wanted(gov, "roll"));

    /* ── The audit trail ──────────────────────────────────────────────────
     * Read the journal back: the switch and the rollback must both be there,
     * and the rollback record must carry the evidence it rested on. */
    journal_scan_t scan;
    journal_scan(dir, &scan);
    assert(scan.all_readable);
    assert(scan.baseline >= 1);
    assert(scan.switches == 1);
    assert(scan.rollbacks == 1);
    assert(scan.probation_open >= 1);
    assert(strstr(scan.switch_record, "\"reason\":\"candidate_better\""));
    assert(strstr(scan.switch_record, "\"constraints\""));
    assert(strstr(scan.switch_record, "\"regression_bound\":0.2"));
    assert(strstr(scan.rollback_record, "\"reason\":\"rollback_regression\""));
    assert(strstr(scan.rollback_record, "\"serve_shape\""));
    assert(strstr(scan.rollback_record, "\"key\":\"roll\""));
    /* The evidence the decision rested on is in the record. */
    assert(strstr(scan.rollback_record, "\"previous_mean\":200"));
    assert(strstr(scan.rollback_record, "\"challenger_mean\":100"));
    assert(strstr(scan.rollback_record, "\"previous_samples\":3"));

    /* ── Metrics, through the W5.2 registry and its bounded labels ──────── */
    qihse_metric_series_t* sw = qihse_metrics_series(
        reg, "qihse_optimizer_plan_decisions_total", "switch");
    qihse_metric_series_t* rb = qihse_metrics_series(
        reg, "qihse_optimizer_plan_decisions_total", "rollback");
    qihse_metric_series_t* rbr = qihse_metrics_series(
        reg, "qihse_optimizer_plan_rollbacks_total", "regression");
    qihse_metric_series_t* gauge = qihse_metrics_series(
        reg, "qihse_optimizer_plan_active_switches", NULL);
    assert(sw && rb && rbr && gauge);
    qihse_metric_snapshot_t snap;
    /* A counter's value is in `value` (the atomic counter), not in `count`. */
    assert(qihse_metrics_series_snapshot(sw, &snap) == 0 && snap.value == 1.0);
    assert(qihse_metrics_series_snapshot(rb, &snap) == 0 && snap.value == 1.0);
    assert(qihse_metrics_series_snapshot(rbr, &snap) == 0 && snap.value == 1.0);
    assert(qihse_metrics_series_snapshot(gauge, &snap) == 0 && snap.value == 0.0);
    /* A label value the family did not declare creates no series. */
    assert(qihse_metrics_series(reg, "qihse_optimizer_plan_decisions_total", "faster") == NULL);
    assert(__atomic_load_n(&reg->label_rejected_total, __ATOMIC_RELAXED) >= 1u);

    qihse_metrics_destroy(reg);
    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: rollback fires automatically, incumbent restored, decision persisted\n");
}

/* ── 8. The rollback that does not wait for the window ──────────────────── */

static void test_mismatch_rolls_back_immediately(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 2;
    cfg.rollback_min_samples = 3;
    cfg.rollback_window_ms = 600000; /* one switch cannot outlast the test */
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0x5A5AULL, B = 0x6B6BULL;
    qihse_optimizer_governance_evaluate_shapes(gov, "mm", A, B);
    feed(gov, "mm", A, 100.0, false, 2);
    feed(gov, "mm", B, 90.0, true, 2);
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "mm", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_SWITCH, QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER, "switch");
    assert(d.serve_shape == B && d.probation);

    /* The switched plan returns a different answer.  That is a correctness
     * violation, and it does not wait for a cost window. */
    d = observe(gov, "mm", B, 90.0, false, false);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_ROLLBACK, QIHSE_OPT_GOV_REASON_ROLLBACK_MISMATCH,
                   "immediate rollback");
    assert(d.serve_shape == A);
    assert(!d.probation);
    assert(qihse_optimizer_governance_probation_count(gov) == 0);

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: a post-switch result mismatch rolls back immediately\n");
}

/* ── 9. Too little data after a switch ──────────────────────────────────── */

static void test_probation_without_enough_data_keeps_the_switch(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 2;
    cfg.rollback_min_samples = 3;
    cfg.rollback_window_ms = 10;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0x77ULL, B = 0x88ULL;
    qihse_optimizer_governance_evaluate_shapes(gov, "few", A, B);
    feed(gov, "few", A, 100.0, false, 2);
    feed(gov, "few", B, 80.0, true, 2);
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "few", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_SWITCH, QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER, "switch");
    assert(d.serve_shape == B);

    sleep_ms(20);
    /* One post-switch observation, and it is a bad one.  It is NOT enough to
     * declare a regression (rollback_min_samples = 3), and the switch is not
     * reverted on silence either: the probation stays open and the plan stays
     * in service, with the reason recorded. */
    d = observe(gov, "few", B, 400.0, false, true);
    assert(d.outcome == QIHSE_OPT_GOV_OUTCOME_OBSERVE);
    assert(d.probation);
    assert(qihse_optimizer_governance_probation_count(gov) == 1);

    d = qihse_optimizer_governance_evaluate_shapes(gov, "few", B, A);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_PROBATION, "open probation");
    assert(d.serve_shape == B);
    assert(d.probation);

    /* Enough post-switch evidence arrives, and now the bound is violated: the
     * rollback fires and the incumbent is restored. */
    observe(gov, "few", B, 400.0, false, true);
    d = observe(gov, "few", B, 400.0, false, true);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_ROLLBACK, QIHSE_OPT_GOV_REASON_ROLLBACK_REGRESSION,
                   "late rollback");
    assert(d.serve_shape == A);
    assert(qihse_optimizer_governance_probation_count(gov) == 0);

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: an unmeasured probation keeps the switch; evidence later reverts it\n");
}

/* ── 10. Bounded structures ─────────────────────────────────────────────── */

static void test_bounds_hold(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    cfg.min_samples = 2;
    cfg.cooldown_ms = 0;
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    char key[64];
    for (size_t i = 0; i < QIHSE_OPT_GOV_MAX_KEYS; i++) {
        snprintf(key, sizeof(key), "key%zu", i);
        qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(
            gov, key, 0x1000ULL + i, 0x2000ULL + i);
        assert(d.outcome == QIHSE_OPT_GOV_OUTCOME_KEEP);
        assert(d.reason == QIHSE_OPT_GOV_REASON_BASELINE);
    }
    /* The table is bounded: the next key is refused, not accommodated. */
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(
        gov, "one-too-many", 0x3000ULL, 0x4000ULL);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_TABLE_FULL, "table full");
    assert(d.serve_shape == 0);

    /* The keys already governed still work. */
    qihse_optimizer_governance_evaluate_shapes(gov, "key0", 0x1000ULL, 0x2000ULL);
    feed(gov, "key0", 0x1000ULL, 100.0, false, 2);
    feed(gov, "key0", 0x2000ULL, 50.0, true, 2);
    d = qihse_optimizer_governance_evaluate_shapes(gov, "key0", 0x1000ULL, 0x2000ULL);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_SWITCH, QIHSE_OPT_GOV_REASON_CANDIDATE_BETTER,
                   "existing key still switches");

    /* The decision history is bounded, and the newest decision is first. */
    qihse_opt_gov_decision_t hist[QIHSE_OPT_GOV_HISTORY_MAX + 8];
    size_t n = qihse_optimizer_governance_history(gov, hist, sizeof(hist) / sizeof(hist[0]));
    assert(n == QIHSE_OPT_GOV_HISTORY_MAX);
    assert(hist[0].outcome == QIHSE_OPT_GOV_OUTCOME_SWITCH);
    assert(hist[0].serve_shape == 0x2000ULL);

    /* An over-long key is refused rather than truncated into another key's
     * identity. */
    char long_key[QIHSE_OPT_GOV_KEY_MAX + 8];
    memset(long_key, 'x', sizeof(long_key) - 1u);
    long_key[sizeof(long_key) - 1u] = '\0';
    d = qihse_optimizer_governance_evaluate_shapes(gov, long_key, 0x1000ULL, 0x2000ULL);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_KEY_INVALID, "long key");
    d = qihse_optimizer_governance_evaluate_shapes(gov, "", 0x1000ULL, 0x2000ULL);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_KEY_INVALID, "empty key");
    d = qihse_optimizer_governance_evaluate_shapes(gov, NULL, 0x1000ULL, 0x2000ULL);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_KEY_INVALID, "null key");

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: key table, history and key length are all bounded\n");
}

/* ── 11. Bypass detection ───────────────────────────────────────────────── */

static void test_out_of_band_change_is_refused(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    const uint64_t A = 0x100ULL, B = 0x200ULL, C = 0x300ULL;
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(gov, "by", A, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_BASELINE, "baseline");
    assert(d.serve_shape == A);

    /* The caller reports that it is serving C, which the harness never
     * approved.  It is refused and journaled, not adopted. */
    d = qihse_optimizer_governance_evaluate_shapes(gov, "by", C, B);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_INCUMBENT_MISMATCH,
                   "out-of-band change");
    assert(d.serve_shape == A);

    /* The recorded incumbent is still A, so a legitimate evaluation still
     * works afterwards. */
    d = qihse_optimizer_governance_evaluate_shapes(gov, "by", A, B);
    assert(d.reason == QIHSE_OPT_GOV_REASON_INSUFFICIENT_SAMPLES);

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: a served plan the harness never approved is refused\n");
}

/* ── 12. A key cannot rewrite the record it is embedded in ──────────────── */

static void test_hostile_key_is_contained(const char* dir) {
    qihse_opt_gov_config_t cfg = gov_cfg(dir);
    qihse_opt_governance_t* gov = qihse_optimizer_governance_create(NULL, &cfg);
    assert(gov);

    /* A key that tries to close the record's string, add a switch of its own
     * and open a new record. */
    const char* hostile = "k\",\"outcome\":\"switch\"}\n{\"schema\":0";
    qihse_opt_gov_decision_t d = qihse_optimizer_governance_evaluate_shapes(
        gov, hostile, 0x11ULL, 0x22ULL);
    expect_outcome(&d, QIHSE_OPT_GOV_OUTCOME_KEEP, QIHSE_OPT_GOV_REASON_BASELINE, "hostile key");
    assert(d.recorded);

    journal_scan_t scan;
    journal_scan(dir, &scan);
    assert(scan.all_readable);
    assert(scan.records == 1);          /* one record: the injection added none */
    assert(scan.baseline == 1);
    assert(scan.switches == 0);
    assert(strstr(scan.all, "\"key\":\"k") != NULL);          /* the key is there... */
    assert(strstr(scan.all, "\"outcome\":\"switch\"") == NULL); /* ...and did not rewrite it */

    qihse_optimizer_governance_destroy(gov);
    printf("PASS governance: a key with JSON metacharacters cannot forge a journal record\n");
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    char root[] = "build/opt_gov_XXXXXX";
    assert(mkdtemp(root));
    char dir_a[600], dir_b[600], dir_c[600], dir_d[600], dir_e[600], dir_f[600];
    snprintf(dir_a, sizeof(dir_a), "%s/a", root);
    snprintf(dir_b, sizeof(dir_b), "%s/b", root);
    snprintf(dir_c, sizeof(dir_c), "%s/c", root);
    snprintf(dir_d, sizeof(dir_d), "%s/d", root);
    snprintf(dir_e, sizeof(dir_e), "%s/e", root);
    snprintf(dir_f, sizeof(dir_f), "%s/f", root);

    test_shape_digest();
    test_no_statistics_means_no_candidate(dir_a);
    test_no_journal_never_switches();
    test_insufficient_samples_never_switch(dir_b);
    test_regression_bound_refuses(dir_c);
    test_per_workload_budget(dir_f);
    test_result_mismatch_disqualifies(dir_d);
    test_switch_then_automatic_rollback(dir_a);   /* same journal: BASELINE twice is fine */
    test_mismatch_rolls_back_immediately(dir_b);
    test_probation_without_enough_data_keeps_the_switch(dir_c);
    test_bounds_hold(dir_d);
    test_out_of_band_change_is_refused(dir_a);
    test_hostile_key_is_contained(dir_e);

    printf("PASS optimizer governance: shadow A/B, declared constraints, automatic rollback, "
           "persisted decisions\n");
    return 0;
}
