#ifndef QIHSE_PARALLEL_QUERY_H
#define QIHSE_PARALLEL_QUERY_H

#include "qihse_kv_store.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QIHSE Parallel Query — worker-threaded scan, aggregate and hash join.
 *
 * ROW MODEL
 * ---------
 * The KV layer has no schema, so this module fixes the smallest convention
 * that lets the operations be defined at all:
 *
 *     key   = <table><sep><row_id>[<sep><column>]
 *     value = the column's value
 *
 * <sep> is '/' or ':'.  A key belongs to a table when the table name is a
 * whole prefix component of the key: "users/1/age" and "users:1:age" belong
 * to the table "users", while "users_archive/1/age" does not.  A key's
 * COLUMN is its final component, so "users/1/age" carries the column "age"
 * for the row "users/1".  A row is one key/value pair.
 *
 * PARTITIONING — what is parallel and what cannot be
 * --------------------------------------------------
 * qihse_kv_foreach_user() is the only enumeration the KV layer exposes: it
 * walks the entire keyspace and has no prefix, range or resume form.  The
 * traversal therefore runs once, on the calling thread, materialising the
 * rows under the table prefix; the resulting row array is then partitioned
 * across the workers (worker i takes rows i, i+num_workers, ...).  Every row
 * is visited once and lands in exactly one partition, so no key is missed
 * and no key is counted twice.
 *
 * Parallelised per-row work: the row copies a scan returns, the numeric
 * parse an aggregate needs, and the hash build/probe a join needs.  A
 * prefix/range iterator in the KV API would let the traversal itself be
 * partitioned and would remove the materialisation; until one exists this
 * module cannot do better, and it does not claim to.
 *
 * SECURITY CONTEXT (AGENTS.md invariant 1)
 * ----------------------------------------
 * Rows are read through qihse_kv_foreach_user() with the user bound to the
 * context, so enumeration is authorization-aware.  A context with no user
 * bound is unclassified-only — the same deliberate mode as the context-free
 * qihse_kv_foreach()/qihse_kv_get() — and is NOT an authorization bypass:
 * the KV layer denies classified records to a NULL user.  Bind the caller's
 * identity with qihse_parallel_set_user() before querying a store that may
 * hold classified data.
 *
 * FAILURES ARE REPORTED, NEVER FOLDED INTO A RESULT
 * -------------------------------------------------
 * Every entry point returns 0 on success or one of the negative codes below.
 * A refusal exposes no partial result: the out parameter is zeroed/freed and
 * the caller can tell "the query ran and matched nothing" (success with zero
 * counts, alongside the examined-row counts that prove the work ran) from
 * "the query could not run" (a negative code).
 */

#define QIHSE_PARALLEL_OK                 0
#define QIHSE_PARALLEL_ERR_ARGS          -1  /* NULL/malformed argument */
#define QIHSE_PARALLEL_ERR_UNSUPPORTED   -2  /* unknown aggregate function */
#define QIHSE_PARALLEL_ERR_THREAD        -3  /* a worker thread was not created */
#define QIHSE_PARALLEL_ERR_NOMEM         -4  /* allocation failure */
#define QIHSE_PARALLEL_ERR_STORE         -5  /* KV enumeration/read failure */
#define QIHSE_PARALLEL_ERR_DATA          -6  /* a value is not a finite number */
#define QIHSE_PARALLEL_ERR_NO_RESULT     -7  /* the query has no answer at all */
#define QIHSE_PARALLEL_ERR_LIMIT         -8  /* result exceeds the row/pair cap */

/* qihse_parallel_init() refuses anything outside this range. */
#define QIHSE_PARALLEL_MAX_WORKERS 64

/* Cap on qihse_parallel_join() output pairs.  Exceeding it is
 * QIHSE_PARALLEL_ERR_LIMIT: truncating the pair list while still reporting
 * matched_rows would be a silent lie about the join's output. */
#define QIHSE_PARALLEL_JOIN_MAX_PAIRS (1u << 20)

typedef struct {
    int num_workers;
    pthread_t* worker_threads;
    volatile int shutdown;
    pthread_mutex_t lock;      /* serialises operations on this context */
    qihse_user_t* user;        /* borrowed, never owned; NULL == unclassified only */
} qihse_parallel_ctx_t;

/* One materialised KV row.  Both members are owned by the structure that
 * holds them and are released by the matching *_free() call. */
typedef struct {
    char* key;
    char* value;
} qihse_parallel_row_t;

typedef struct {
    char* table_name;          /* owned */
    size_t total_rows;         /* sum of result_counts[] */
    size_t rows_per_worker;    /* largest row count handed to one worker */
    int num_workers;           /* entries in results[] / result_counts[] */
    void** results;            /* results[i] is a qihse_parallel_row_t* */
    size_t* result_counts;     /* rows in results[i]; NULL array if 0 rows */
} qihse_parallel_scan_t;

/* A matched pair: the left and right keys that carried the same join value. */
typedef struct {
    char* left_key;            /* owned */
    char* right_key;           /* owned */
} qihse_parallel_join_pair_t;

typedef struct {
    size_t left_keys;          /* keys under the left table prefix */
    size_t right_keys;         /* keys under the right table prefix */
    size_t left_join_rows;     /* left keys carrying the join column */
    size_t right_join_rows;    /* right keys carrying the join column */
    size_t matched_rows;       /* entries in pairs[] */
    qihse_parallel_join_pair_t* pairs;   /* owned */
} qihse_parallel_join_t;

/*
 * Create a context with `num_workers` workers (1..QIHSE_PARALLEL_MAX_WORKERS).
 * Returns NULL for an out-of-range worker count or on allocation/mutex
 * failure — an unchecked failure here is how a "parallel" path silently
 * becomes a serial or empty one.  A new context has no user bound, i.e. it
 * sees unclassified data only.
 */
qihse_parallel_ctx_t* qihse_parallel_init(int num_workers);

/* Bind (or clear, with NULL) the security context inherited by every
 * operation on this context.  Borrowed: the caller keeps ownership. */
int qihse_parallel_set_user(qihse_parallel_ctx_t* ctx, qihse_user_t* user);
qihse_user_t* qihse_parallel_get_user(qihse_parallel_ctx_t* ctx);

/*
 * Scan every key under `table_prefix` and partition the rows across the
 * workers.  Success with total_rows == 0 means the traversal really ran and
 * found no key under that prefix — a KV store has no schema, so an empty
 * table and an absent one are the same thing here.  On failure out_scan is
 * zeroed.
 */
int qihse_parallel_scan(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* table_prefix,
                        qihse_parallel_scan_t* out_scan);

/* Release the rows and arrays owned by a scan.  Safe on a zeroed struct. */
void qihse_parallel_scan_free(qihse_parallel_scan_t* scan);

void qihse_parallel_cleanup(qihse_parallel_ctx_t* ctx);

/*
 * Parallel hash join of two tables on a shared column name.
 *
 * A row participates when its key is under the table prefix AND its final
 * component equals join_key; its join value is that key's value.  Two rows
 * match when their join values are byte-equal.  pairs[] reports the matched
 * keys, and left_keys/right_keys/left_join_rows/right_join_rows report what
 * was examined, so success with matched_rows == 0 is evidence that the join
 * ran and nothing matched.
 *
 * QIHSE_PARALLEL_ERR_NO_RESULT is returned when either table has no key
 * carrying the join column: nothing could ever have matched, and reporting
 * that as "0 rows matched" is the false success this module exists to
 * remove.
 *
 * (The previous form of this function took no result parameter at all and
 * returned 0 while doing nothing.)
 */
int qihse_parallel_join(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* left_table, const char* right_table,
                        const char* join_key,
                        qihse_parallel_join_t* out_join);

/* Release the pairs owned by a join result.  Safe on a zeroed struct. */
void qihse_parallel_join_free(qihse_parallel_join_t* join);

/*
 * Aggregate the rows under `table_name`.  `agg_column` selects the column
 * (final key component) to aggregate; NULL aggregates each row's own value.
 * `agg_func` is one of count/sum/avg/min/max, matched case-insensitively.
 *
 * count and sum have a defined answer for an empty table (0); avg, min and
 * max do not, and return QIHSE_PARALLEL_ERR_NO_RESULT rather than 0.  A
 * non-numeric value in a numeric aggregate is QIHSE_PARALLEL_ERR_DATA, and
 * an agg_column that no key in the table carries is
 * QIHSE_PARALLEL_ERR_NO_RESULT for every function.
 */
int qihse_parallel_aggregate(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                             const char* table_name, const char* agg_column,
                             const char* agg_func,
                             double* out_result);

#ifdef __cplusplus
}
#endif
#endif
