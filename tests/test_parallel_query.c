/*
 * test_parallel_query.c — parallel scan, aggregate and hash join.
 *
 * Exercises src/tractable/qihse_parallel_query.c, which used to be a stub
 * that reported success while doing nothing:
 *
 *   - scan_worker() counted nothing ("TODO: actual KV store iteration with
 *     partitioning"), so every scan returned total_rows = 0;
 *   - agg_worker() aggregated nothing, so every aggregate returned 0;
 *   - qihse_parallel_join() was a TODO that returned 0 — SUCCESS — while
 *     doing nothing, and had no result parameter through which a join could
 *     have been reported at all;
 *   - pthread_create() failures were ignored and the threads joined anyway;
 *   - qihse_parallel_init() ignored calloc()/pthread_mutex_init() failures.
 *
 * The cases below therefore check, in order:
 *
 *   1. the scan really partitions and iterates: every key under the prefix is
 *      returned exactly once, whatever the worker count, and the total agrees
 *      with the KV layer's own count;
 *   2. the aggregate really aggregates: count/sum/avg/min/max over a column,
 *      with a value that is not a number refused instead of silently skipped;
 *   3. the join really joins, and a join that CANNOT have matched anything
 *      (either table has no row carrying the join column) is refused rather
 *      than reported as "0 rows matched";
 *   4. a context with no user bound sees unclassified rows only, and the
 *      operator sees the classified row — the security context is inherited
 *      by the workers;
 *   5. the thread lifecycle: a real pthread_create() failure (RLIMIT_NPROC 0,
 *      an EAGAIN from the kernel, not a mock) fails the operation with
 *      QIHSE_PARALLEL_ERR_THREAD and exposes no partial result, and the
 *      context works again once threads can be created;
 *   6. what the parallelism actually buys, measured, printed and not
 *      asserted: the keyspace traversal is serial because the KV API has no
 *      range iterator, so only the per-row work is parallel.
 *
 * Test data uses the module's documented row model: key
 * <table><sep><row_id>[<sep><column>].
 */
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_parallel_query.h"

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── Assertions that say which case failed ──────────────────────────────── */

static void expect_rc(int got, int want, const char* what) {
    if (got != want) {
        printf("FAIL %s: rc=%d want=%d\n", what, got, want);
        assert(0);
    }
}

static void expect_size(size_t got, size_t want, const char* what) {
    if (got != want) {
        printf("FAIL %s: got %zu want %zu\n", what, got, want);
        assert(0);
    }
}

static void expect_double(double got, double want, const char* what) {
    double d = got - want;
    if (d < 0.0) d = -d;
    if (!(d <= 1e-9)) {
        printf("FAIL %s: got %.17g want %.17g\n", what, got, want);
        assert(0);
    }
}

/* ── Fixture ───────────────────────────────────────────────────────────── */

static qihse_kv_store_t* g_kv = NULL;
static qihse_user_t* g_operator = NULL;
static qihse_user_t* g_guest = NULL;
static char g_data_dir[] = "/tmp/qihse-parallel-XXXXXX";

static void put(const char* key, const char* value) {
    assert(qihse_kv_set(g_kv, key, value, 0, 0));
}

static void build_fixture(void) {
    /* users: four visible keys, one of which is not a number. */
    put("users/1/age", "30");
    put("users/2/age", "40");
    put("users/3/age", "not-a-number");
    put("users/1/name", "alice");
    /* A prefix must match a whole component: this is NOT in table "users". */
    put("users_archive/1/age", "999");
    put("commons/notice", "hello");
    /* Numeric column for the numeric aggregates. */
    put("metrics/a/v", "1.5");
    put("metrics/b/v", "2.5");
    put("metrics/c/v", "6");
    /* Join fixture: "cust_id" is carried by four left rows and three right
     * rows, with one value carried by two left rows (one-to-many). */
    put("orders/o1/cust_id", "1");
    put("orders/o2/cust_id", "2");
    put("orders/o3/cust_id", "9");
    put("orders/o5/cust_id", "1");
    put("orders/o1/total", "100");
    put("orders/o4/note", "x");
    put("customers/c1/cust_id", "1");
    put("customers/c2/cust_id", "2");
    put("customers/c3/cust_id", "3");
    put("customers/c4/name", "dave");
    /* Both sides carry the column, no value matches. */
    put("l2/a/k", "7");
    put("r2/b/k", "8");
    /* Classified row: only the operator may see it. */
    assert(qihse_kv_set_user(g_kv, "users/9/age", "50", 5, 0, g_operator));
}

/* ── Scan ──────────────────────────────────────────────────────────────── */

#define MAX_KEYS 64

typedef struct {
    const char* keys[MAX_KEYS];
    size_t n;
} key_set_t;

/* An independent count of the keys under a prefix, using the KV layer's own
 * enumeration with the same prefix rule.  This is the cross-check that the
 * module's traversal misses nothing and counts nothing twice. */
typedef struct {
    const char* prefix;
    size_t n;
} count_prefix_ctx_t;

static bool count_prefix_cb(const char* key, const char* value, void* ud) {
    (void)value;
    count_prefix_ctx_t* c = (count_prefix_ctx_t*)ud;
    const size_t plen = strlen(c->prefix);
    if (strncmp(key, c->prefix, plen) == 0) {
        const char ch = key[plen];
        if (ch == '\0' || ch == '/' || ch == ':') c->n++;
    }
    return true;
}

static size_t count_prefix(const char* prefix) {
    count_prefix_ctx_t c;
    c.prefix = prefix;
    c.n = 0;
    assert(qihse_kv_foreach_user(g_kv, NULL, count_prefix_cb, &c));
    return c.n;
}

static void collect_scan_keys(const qihse_parallel_scan_t* scan,
                              key_set_t* set) {
    set->n = 0;
    for (int i = 0; i < scan->num_workers; i++) {
        const qihse_parallel_row_t* rows =
            (const qihse_parallel_row_t*)scan->results[i];
        if (scan->result_counts[i] == 0) {
            assert(rows == NULL); /* no rows means no array, not an empty one */
            continue;
        }
        assert(rows != NULL);
        for (size_t k = 0; k < scan->result_counts[i]; k++) {
            assert(set->n < MAX_KEYS);
            set->keys[set->n++] = rows[k].key;
        }
    }
}

/* Each expected key must appear exactly once, so this catches both a missed
 * key and a key that two partitions both claim. */
static void expect_keys(const key_set_t* set, const char* const* want,
                        size_t want_n, const char* what) {
    expect_size(set->n, want_n, what);
    for (size_t i = 0; i < want_n; i++) {
        size_t hits = 0;
        for (size_t j = 0; j < set->n; j++) {
            if (strcmp(set->keys[j], want[i]) == 0) hits++;
        }
        if (hits != 1) {
            printf("FAIL %s: key %s appears %zu times\n", what, want[i], hits);
            assert(0);
        }
    }
}

static void test_scan(void) {
    static const char* const users[] = {
        "users/1/age", "users/2/age", "users/3/age", "users/1/name"
    };
    static const char* const users_op[] = {
        "users/1/age", "users/2/age", "users/3/age", "users/1/name",
        "users/9/age"
    };
    static const char* const archive[] = { "users_archive/1/age" };

    /* The same scan at 1, 2, 4 and 8 workers must see the same key set. */
    for (int workers = 1; workers <= 8; workers *= 2) {
        qihse_parallel_ctx_t* ctx = qihse_parallel_init(workers);
        assert(ctx != NULL);
        qihse_parallel_scan_t scan;
        expect_rc(qihse_parallel_scan(ctx, g_kv, "users", &scan),
                  QIHSE_PARALLEL_OK, "scan users");
        expect_size(scan.total_rows, 4u, "scan users total_rows");
        expect_size(scan.rows_per_worker, (4u + (size_t)workers - 1u) /
                                              (size_t)workers,
                    "scan users rows_per_worker");
        assert(scan.num_workers == workers);
        assert(scan.table_name && strcmp(scan.table_name, "users") == 0);
        key_set_t set;
        collect_scan_keys(&scan, &set);
        expect_keys(&set, users, 4u, "scan users keys");
        /* The KV layer's own count is the cross-check on the traversal: a
         * missed key or a key two partitions both claim would show here. */
        expect_size(scan.total_rows, count_prefix("users"),
                    "scan users vs qihse_kv_foreach");

        /* Values travel with their keys. */
        for (int i = 0; i < scan.num_workers; i++) {
            const qihse_parallel_row_t* rows =
                (const qihse_parallel_row_t*)scan.results[i];
            for (size_t k = 0; k < scan.result_counts[i]; k++) {
                assert(rows[k].value != NULL);
                if (strcmp(rows[k].key, "users/1/age") == 0)
                    assert(strcmp(rows[k].value, "30") == 0);
                if (strcmp(rows[k].key, "users/1/name") == 0)
                    assert(strcmp(rows[k].value, "alice") == 0);
            }
        }
        qihse_parallel_scan_free(&scan);
        assert(scan.results == NULL && scan.table_name == NULL);

        /* A prefix that matches a whole component only. */
        expect_rc(qihse_parallel_scan(ctx, g_kv, "users_archive", &scan),
                  QIHSE_PARALLEL_OK, "scan users_archive");
        expect_size(scan.total_rows, 1u, "scan users_archive total_rows");
        collect_scan_keys(&scan, &set);
        expect_keys(&set, archive, 1u, "scan users_archive keys");
        qihse_parallel_scan_free(&scan);

        /* "users_archive" must not be reachable through "users". */
        expect_rc(qihse_parallel_scan(ctx, g_kv, "users_", &scan),
                  QIHSE_PARALLEL_OK, "scan users_");
        expect_size(scan.total_rows, 0u, "scan users_ total_rows");
        qihse_parallel_scan_free(&scan);

        /* The operator sees the classified row as well. */
        expect_rc(qihse_parallel_set_user(ctx, g_operator), QIHSE_PARALLEL_OK,
                  "set_user operator");
        assert(qihse_parallel_get_user(ctx) == g_operator);
        expect_rc(qihse_parallel_scan(ctx, g_kv, "users", &scan),
                  QIHSE_PARALLEL_OK, "scan users as operator");
        expect_size(scan.total_rows, 5u, "scan users as operator total_rows");
        collect_scan_keys(&scan, &set);
        expect_keys(&set, users_op, 5u, "scan users as operator keys");
        qihse_parallel_scan_free(&scan);
        qihse_parallel_cleanup(ctx);
    }

    /* An empty result is a real answer: the traversal ran and found nothing.
     * (A KV store has no schema, so an absent table and an empty one are the
     * same thing — the header says so.) */
    qihse_parallel_ctx_t* ctx = qihse_parallel_init(4);
    assert(ctx != NULL);

    /* The classified row is invisible without a user and visible with the
     * operator: 21 unclassified keys in the fixture, 22 in total. */
    expect_size(qihse_kv_count_user(g_kv, NULL), 21u,
                "keyspace count without a user");
    expect_size(qihse_kv_count_user(g_kv, g_operator), 22u,
                "keyspace count as operator");
    qihse_parallel_scan_t scan;
    expect_rc(qihse_parallel_scan(ctx, g_kv, "absent_table", &scan),
              QIHSE_PARALLEL_OK, "scan absent table");
    expect_size(scan.total_rows, 0u, "scan absent table total_rows");
    assert(scan.results != NULL && scan.result_counts != NULL);
    qihse_parallel_scan_free(&scan);

    /* Refusals: no NULL argument is quietly accepted. */
    expect_rc(qihse_parallel_scan(NULL, g_kv, "users", &scan),
              QIHSE_PARALLEL_ERR_ARGS, "scan NULL ctx");
    expect_rc(qihse_parallel_scan(ctx, NULL, "users", &scan),
              QIHSE_PARALLEL_ERR_ARGS, "scan NULL kv");
    expect_rc(qihse_parallel_scan(ctx, g_kv, NULL, &scan),
              QIHSE_PARALLEL_ERR_ARGS, "scan NULL prefix");
    expect_rc(qihse_parallel_scan(ctx, g_kv, "", &scan),
              QIHSE_PARALLEL_ERR_ARGS, "scan empty prefix");
    expect_rc(qihse_parallel_scan(ctx, g_kv, "users", NULL),
              QIHSE_PARALLEL_ERR_ARGS, "scan NULL out");
    qihse_parallel_cleanup(ctx);
    printf("PASS scan: partitions cover the prefix exactly once at 1/2/4/8 "
           "workers, empty and absent prefixes are real answers, NULL and "
           "empty arguments are refused\n");
}

/* ── Aggregate ─────────────────────────────────────────────────────────── */

static void agg(int workers, const char* table, const char* column,
                const char* func, int want_rc, double want) {
    qihse_parallel_ctx_t* ctx = qihse_parallel_init(workers);
    assert(ctx != NULL);
    double got = -12345.0; /* a refusal must overwrite this with 0.0 */
    int rc = qihse_parallel_aggregate(ctx, g_kv, table, column, func, &got);
    char what[160];
    snprintf(what, sizeof(what), "aggregate %s(%s.%s) with %d workers", func,
             table, column ? column : "-", workers);
    expect_rc(rc, want_rc, what);
    if (want_rc == QIHSE_PARALLEL_OK) {
        expect_double(got, want, what);
    } else {
        expect_double(got, 0.0, what);
    }
    qihse_parallel_cleanup(ctx);
}

static void test_aggregate(void) {
    const int worker_counts[] = { 1, 2, 4, 8 };

    for (size_t i = 0; i < sizeof(worker_counts) / sizeof(worker_counts[0]);
         i++) {
        const int w = worker_counts[i];
        agg(w, "users", NULL, "count", QIHSE_PARALLEL_OK, 4.0);
        agg(w, "users", "age", "count", QIHSE_PARALLEL_OK, 3.0);
        agg(w, "users", "name", "count", QIHSE_PARALLEL_OK, 1.0);
        agg(w, "metrics", "v", "count", QIHSE_PARALLEL_OK, 3.0);
        agg(w, "metrics", "v", "sum", QIHSE_PARALLEL_OK, 10.0);
        agg(w, "metrics", "v", "avg", QIHSE_PARALLEL_OK, 10.0 / 3.0);
        agg(w, "metrics", "v", "min", QIHSE_PARALLEL_OK, 1.5);
        agg(w, "metrics", "v", "max", QIHSE_PARALLEL_OK, 6.0);
        agg(w, "metrics", "v", "SUM", QIHSE_PARALLEL_OK, 10.0);
        agg(w, "metrics", "v", "Average", QIHSE_PARALLEL_ERR_UNSUPPORTED, 0.0);
        /* "not-a-number" is refused, not skipped: a sum that silently omits
         * a row is the failure mode this module exists to remove. */
        agg(w, "users", "age", "sum", QIHSE_PARALLEL_ERR_DATA, 0.0);
        agg(w, "users", "age", "avg", QIHSE_PARALLEL_ERR_DATA, 0.0);
        /* A column no key in the table carries is not "count = 0". */
        agg(w, "users", "nope", "count", QIHSE_PARALLEL_ERR_NO_RESULT, 0.0);
        agg(w, "users", "nope", "min", QIHSE_PARALLEL_ERR_NO_RESULT, 0.0);
        agg(w, "absent_table", NULL, "count", QIHSE_PARALLEL_OK, 0.0);
        agg(w, "absent_table", NULL, "sum", QIHSE_PARALLEL_OK, 0.0);
        agg(w, "absent_table", "v", "avg", QIHSE_PARALLEL_ERR_NO_RESULT, 0.0);
        agg(w, "absent_table", "v", "min", QIHSE_PARALLEL_ERR_NO_RESULT, 0.0);
        agg(w, "absent_table", "v", "max", QIHSE_PARALLEL_ERR_NO_RESULT, 0.0);
    }

    /* A sum that overflows to infinity is not an answer: it is refused like
     * any other value the aggregate cannot represent. */
    put("big/a/v", "1e308");
    put("big/b/v", "1e308");
    agg(1, "big", "v", "sum", QIHSE_PARALLEL_ERR_DATA, 0.0);
    agg(4, "big", "v", "sum", QIHSE_PARALLEL_ERR_DATA, 0.0);
    agg(4, "big", "v", "max", QIHSE_PARALLEL_OK, 1e308);

    /* The operator's context sees the classified row and therefore refuses a
     * sum over "age" for the same reason as an unprivileged one, but counts
     * one more row: the security context reaches the workers. */
    qihse_parallel_ctx_t* ctx = qihse_parallel_init(4);
    assert(ctx != NULL);
    assert(qihse_parallel_set_user(ctx, g_operator) == QIHSE_PARALLEL_OK);
    double got = -1.0;
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, "users", NULL, "count", &got),
              QIHSE_PARALLEL_OK, "operator count users");
    expect_double(got, 5.0, "operator count users");
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, "users", "age", "count", &got),
              QIHSE_PARALLEL_OK, "operator count users.age");
    expect_double(got, 4.0, "operator count users.age");
    assert(qihse_parallel_set_user(ctx, g_guest) == QIHSE_PARALLEL_OK);
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, "users", NULL, "count", &got),
              QIHSE_PARALLEL_OK, "guest count users");
    expect_double(got, 4.0, "guest count users");

    /* Refusals. */
    expect_rc(qihse_parallel_aggregate(NULL, g_kv, "users", NULL, "count", &got),
              QIHSE_PARALLEL_ERR_ARGS, "aggregate NULL ctx");
    expect_rc(qihse_parallel_aggregate(ctx, NULL, "users", NULL, "count", &got),
              QIHSE_PARALLEL_ERR_ARGS, "aggregate NULL kv");
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, NULL, NULL, "count", &got),
              QIHSE_PARALLEL_ERR_ARGS, "aggregate NULL table");
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, "users", NULL, NULL, &got),
              QIHSE_PARALLEL_ERR_ARGS, "aggregate NULL func");
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, "users", NULL, "count", NULL),
              QIHSE_PARALLEL_ERR_ARGS, "aggregate NULL out");
    qihse_parallel_cleanup(ctx);
    printf("PASS aggregate: count/sum/avg/min/max really aggregate at 1/2/4/8 "
           "workers, an unknown function is ERR_UNSUPPORTED, a non-numeric "
           "value is ERR_DATA, and a missing column is ERR_NO_RESULT\n");
}

/* ── Join ──────────────────────────────────────────────────────────────── */

static size_t pair_hits(const qihse_parallel_join_t* join, const char* lk,
                        const char* rk) {
    size_t hits = 0;
    for (size_t i = 0; i < join->matched_rows; i++) {
        if (strcmp(join->pairs[i].left_key, lk) == 0 &&
            strcmp(join->pairs[i].right_key, rk) == 0)
            hits++;
    }
    return hits;
}

static void test_join(void) {
    for (int workers = 1; workers <= 8; workers *= 2) {
        qihse_parallel_ctx_t* ctx = qihse_parallel_init(workers);
        assert(ctx != NULL);
        qihse_parallel_join_t join;
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers",
                                      "cust_id", &join),
                  QIHSE_PARALLEL_OK, "join orders/customers");
        expect_size(join.left_keys, 6u, "join left_keys");
        expect_size(join.right_keys, 4u, "join right_keys");
        expect_size(join.left_join_rows, 4u, "join left_join_rows");
        expect_size(join.right_join_rows, 3u, "join right_join_rows");
        expect_size(join.matched_rows, 3u, "join matched_rows");
        assert(join.pairs != NULL);
        expect_size(pair_hits(&join, "orders/o1/cust_id",
                              "customers/c1/cust_id"),
                    1u, "join pair o1/c1");
        expect_size(pair_hits(&join, "orders/o2/cust_id",
                              "customers/c2/cust_id"),
                    1u, "join pair o2/c2");
        /* One value on two left rows: both pair with the one right row. */
        expect_size(pair_hits(&join, "orders/o5/cust_id",
                              "customers/c1/cust_id"),
                    1u, "join pair o5/c1");
        qihse_parallel_join_free(&join);
        assert(join.pairs == NULL && join.matched_rows == 0);

        /* Zero matches is a real answer when the join really ran: both sides
         * carry the column and no value matches. */
        expect_rc(qihse_parallel_join(ctx, g_kv, "l2", "r2", "k", &join),
                  QIHSE_PARALLEL_OK, "join l2/r2");
        expect_size(join.matched_rows, 0u, "join l2/r2 matched_rows");
        assert(join.pairs == NULL);
        expect_size(join.left_join_rows, 1u, "join l2/r2 left_join_rows");
        expect_size(join.right_join_rows, 1u, "join l2/r2 right_join_rows");
        qihse_parallel_join_free(&join);

        /* THE REGRESSION: a join that cannot have matched anything must be
         * refused.  The stub returned 0 here, so a caller could not tell
         * "no rows matched" from "nothing ran". */
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers",
                                      "missing_column", &join),
                  QIHSE_PARALLEL_ERR_NO_RESULT, "join missing column");
        assert(join.pairs == NULL && join.matched_rows == 0 &&
               join.left_keys == 0 && join.right_keys == 0);
        /* The column exists on the left but not on the right. */
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers", "note",
                                      &join),
                  QIHSE_PARALLEL_ERR_NO_RESULT, "join column on one side only");
        assert(join.pairs == NULL);
        /* Neither table exists. */
        expect_rc(qihse_parallel_join(ctx, g_kv, "ghost", "customers",
                                      "cust_id", &join),
                  QIHSE_PARALLEL_ERR_NO_RESULT, "join absent left table");
        assert(join.pairs == NULL);

        /* Refusals. */
        expect_rc(qihse_parallel_join(NULL, g_kv, "orders", "customers",
                                      "cust_id", &join),
                  QIHSE_PARALLEL_ERR_ARGS, "join NULL ctx");
        expect_rc(qihse_parallel_join(ctx, NULL, "orders", "customers",
                                      "cust_id", &join),
                  QIHSE_PARALLEL_ERR_ARGS, "join NULL kv");
        expect_rc(qihse_parallel_join(ctx, g_kv, NULL, "customers", "cust_id",
                                      &join),
                  QIHSE_PARALLEL_ERR_ARGS, "join NULL left table");
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", NULL, "cust_id",
                                      &join),
                  QIHSE_PARALLEL_ERR_ARGS, "join NULL right table");
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers", NULL,
                                      &join),
                  QIHSE_PARALLEL_ERR_ARGS, "join NULL key");
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers", "",
                                      &join),
                  QIHSE_PARALLEL_ERR_ARGS, "join empty key");
        expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers",
                                      "cust_id", NULL),
                  QIHSE_PARALLEL_ERR_ARGS, "join NULL out");
        qihse_parallel_cleanup(ctx);
    }
    printf("PASS join: the hash join really matches (and reports what it "
           "examined) at 1/2/4/8 workers, and a join that cannot match "
           "anything is refused instead of reporting 0 rows\n");
}

/* ── Thread lifecycle ──────────────────────────────────────────────────── */

static void* noop_worker(void* arg) {
    (void)arg;
    return NULL;
}

static void test_thread_lifecycle(void) {
    /* An out-of-range worker count is refused, not silently defaulted: the
     * old init turned 0 into 4 and hid the caller's mistake. */
    assert(qihse_parallel_init(0) == NULL);
    assert(qihse_parallel_init(-3) == NULL);
    assert(qihse_parallel_init(QIHSE_PARALLEL_MAX_WORKERS + 1) == NULL);
    qihse_parallel_ctx_t* max_ctx =
        qihse_parallel_init(QIHSE_PARALLEL_MAX_WORKERS);
    assert(max_ctx != NULL);
    qihse_parallel_cleanup(max_ctx);

    qihse_parallel_ctx_t* ctx = qihse_parallel_init(8);
    assert(ctx != NULL);
    qihse_parallel_scan_t scan;
    expect_rc(qihse_parallel_scan(ctx, g_kv, "users", &scan),
              QIHSE_PARALLEL_OK, "8-worker scan");
    expect_size(scan.total_rows, 4u, "8-worker scan total_rows");
    assert(scan.num_workers == 8);
    qihse_parallel_scan_free(&scan);
    qihse_parallel_cleanup(ctx);

    /* A real pthread_create() failure: RLIMIT_NPROC 0 makes the kernel
     * refuse the clone with EAGAIN, exactly as a resource-exhausted host
     * would.  Nothing is mocked.  If the limit is not enforced for this user
     * (root bypasses it) the probe below says so and the case is skipped. */
    struct rlimit original;
    assert(getrlimit(RLIMIT_NPROC, &original) == 0);
    struct rlimit zero;
    zero.rlim_cur = 0;
    zero.rlim_max = original.rlim_max;
    bool injected = (setrlimit(RLIMIT_NPROC, &zero) == 0);
    if (injected) {
        pthread_t probe;
        int probe_rc = pthread_create(&probe, NULL, noop_worker, NULL);
        if (probe_rc == 0) {
            pthread_join(probe, NULL);
            injected = false;
        }
    }
    if (!injected) {
        assert(setrlimit(RLIMIT_NPROC, &original) == 0);
        printf("NOTE thread-create injection unavailable (RLIMIT_NPROC is "
               "not enforced for this user); that case was skipped\n");
        return;
    }

    ctx = qihse_parallel_init(4); /* init creates no threads: it still works */
    assert(ctx != NULL);
    double got = -12345.0;
    qihse_parallel_join_t join;
    expect_rc(qihse_parallel_scan(ctx, g_kv, "users", &scan),
              QIHSE_PARALLEL_ERR_THREAD, "scan with no threads");
    /* Nothing partial is published, and no thread was joined that was never
     * created (which would be undefined behaviour). */
    expect_size(scan.total_rows, 0u, "refused scan total_rows");
    assert(scan.results == NULL && scan.result_counts == NULL &&
           scan.table_name == NULL);
    expect_rc(qihse_parallel_aggregate(ctx, g_kv, "users", NULL, "count", &got),
              QIHSE_PARALLEL_ERR_THREAD, "aggregate with no threads");
    expect_double(got, 0.0, "refused aggregate out");
    expect_rc(qihse_parallel_join(ctx, g_kv, "orders", "customers", "cust_id",
                                  &join),
              QIHSE_PARALLEL_ERR_THREAD, "join with no threads");
    assert(join.pairs == NULL && join.matched_rows == 0);
    qihse_parallel_cleanup(ctx);

    assert(setrlimit(RLIMIT_NPROC, &original) == 0);
    ctx = qihse_parallel_init(4);
    assert(ctx != NULL);
    expect_rc(qihse_parallel_scan(ctx, g_kv, "users", &scan),
              QIHSE_PARALLEL_OK, "scan after the limit is restored");
    expect_size(scan.total_rows, 4u, "scan after restore total_rows");
    qihse_parallel_scan_free(&scan);
    qihse_parallel_cleanup(ctx);
    printf("PASS thread lifecycle: init refuses an out-of-range worker count, "
           "a refused pthread_create fails the operation with "
           "ERR_THREAD and exposes nothing, and the context recovers\n");
}

/* ── What the parallelism buys (measured, not asserted) ────────────────── */

typedef struct {
    double scan_ms;
    double agg_ms;
    double join_ms;
} timing_t;

#define BENCH_ROWS 20000
#define BENCH_JOIN_ROWS 2000
#define REPS 3

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static timing_t measure(int workers) {
    timing_t best = { 0.0, 0.0, 0.0 };
    qihse_parallel_ctx_t* ctx = qihse_parallel_init(workers);
    assert(ctx != NULL);
    for (int rep = 0; rep < REPS; rep++) {
        double t0 = now_ms();
        qihse_parallel_scan_t scan;
        expect_rc(qihse_parallel_scan(ctx, g_kv, "bench", &scan),
                  QIHSE_PARALLEL_OK, "bench scan");
        double t1 = now_ms();
        expect_size(scan.total_rows, (size_t)BENCH_ROWS,
                    "bench scan total_rows");
        expect_size(scan.total_rows, count_prefix("bench"),
                    "bench scan vs qihse_kv_foreach");
        qihse_parallel_scan_free(&scan);
        if (rep == 0 || t1 - t0 < best.scan_ms) best.scan_ms = t1 - t0;

        double got = 0.0;
        t0 = now_ms();
        expect_rc(qihse_parallel_aggregate(ctx, g_kv, "bench", "v", "sum",
                                           &got),
                  QIHSE_PARALLEL_OK, "bench sum");
        t1 = now_ms();
        expect_double(got, (double)BENCH_ROWS * (BENCH_ROWS - 1) / 2.0,
                      "bench sum value");
        if (rep == 0 || t1 - t0 < best.agg_ms) best.agg_ms = t1 - t0;

        qihse_parallel_join_t join;
        t0 = now_ms();
        expect_rc(qihse_parallel_join(ctx, g_kv, "bl", "br", "k", &join),
                  QIHSE_PARALLEL_OK, "bench join");
        t1 = now_ms();
        expect_size(join.matched_rows, (size_t)BENCH_JOIN_ROWS,
                    "bench join matched_rows");
        qihse_parallel_join_free(&join);
        if (rep == 0 || t1 - t0 < best.join_ms) best.join_ms = t1 - t0;
    }
    qihse_parallel_cleanup(ctx);
    return best;
}

static void test_measurement(void) {
    for (int i = 0; i < BENCH_ROWS; i++) {
        char key[64];
        char val[32];
        snprintf(key, sizeof(key), "bench/r%d/v", i);
        snprintf(val, sizeof(val), "%d", i);
        put(key, val);
    }
    for (int i = 0; i < BENCH_JOIN_ROWS; i++) {
        char key[64];
        char val[32];
        snprintf(val, sizeof(val), "%d", i);
        snprintf(key, sizeof(key), "bl/r%d/k", i);
        put(key, val);
        snprintf(key, sizeof(key), "br/r%d/k", i);
        put(key, val);
    }
    const timing_t one = measure(1);
    const timing_t four = measure(4);
    /* The reference: one serial keyspace traversal with no per-row work, so
     * the reader can see how much of the numbers above is the traversal
     * (which the KV API cannot partition) rather than the workers. */
    double trav = 0.0;
    for (int rep = 0; rep < REPS; rep++) {
        const double t0 = now_ms();
        const size_t n = count_prefix("bench");
        const double t1 = now_ms();
        expect_size(n, (size_t)BENCH_ROWS, "traversal-only count");
        if (rep == 0 || t1 - t0 < trav) trav = t1 - t0;
    }
    printf("parallel query measurement (%d scan rows, %d+%d join rows, best "
           "of %d):\n", BENCH_ROWS, BENCH_JOIN_ROWS, BENCH_JOIN_ROWS, REPS);
    printf("  workers   scan ms   sum ms   join ms\n");
    printf("        1   %7.2f  %7.2f  %7.2f\n", one.scan_ms, one.agg_ms,
           one.join_ms);
    printf("        4   %7.2f  %7.2f  %7.2f\n", four.scan_ms, four.agg_ms,
           four.join_ms);
    printf("  reference: the keyspace traversal alone (no per-row work, "
           "nothing parallel) is %.2f ms, and it is serial because the KV API "
           "has no prefix/range iterator.  These numbers are not a claim "
           "about scaling.\n", trav);
}

int main(void) {
    /* Unbuffered: a failed case prints which one before the assertion aborts. */
    setvbuf(stdout, NULL, _IONBF, 0);
    assert(mkdtemp(g_data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", g_data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ParallelQueryPass1!"));
    g_operator = qihse_auth_get_user(0);
    assert(g_operator != NULL);
    g_guest = qihse_auth_create_user(g_operator, 92, QIHSE_ROLE_GUEST, 0, 0,
                                     "GuestParallel1!", false);
    assert(g_guest != NULL);

    g_kv = qihse_kv_store_create();
    assert(g_kv != NULL);
    build_fixture();

    test_scan();
    test_aggregate();
    test_join();
    test_thread_lifecycle();
    test_measurement();

    qihse_kv_store_destroy(g_kv);
    char command[768];
    snprintf(command, sizeof(command), "rm -rf -- '%s'", g_data_dir);
    assert(system(command) == 0);
    printf("test_parallel_query: all parallel query tests passed\n");
    return 0;
}
