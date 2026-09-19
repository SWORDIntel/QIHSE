/*
 * QIHSE Parallel Query — worker-threaded scan, aggregate and hash join over
 * the KV keyspace.
 *
 * The row model, the partitioning contract and the security-context rules
 * live in include/qihse_parallel_query.h; this file implements them.
 *
 * Thread lifecycle: every worker that is created is joined, and a worker that
 * pthread_create() refused is never joined (joining a thread that was never
 * created is undefined behaviour).  A refused create fails the whole
 * operation with QIHSE_PARALLEL_ERR_THREAD: running the remaining partitions
 * on the calling thread would complete the work but hide that the caller did
 * not get the parallelism it asked for, and a caller that is told "no" can
 * retry with a smaller context.
 *
 * Every allocation that can fail is checked, because an unchecked failure on
 * this path is how a "parallel" query quietly becomes an empty one.
 */
#include "qihse_parallel_query.h"

#include <errno.h>
#include <float.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Key-shape helpers
 * ------------------------------------------------------------------------- */

/* A key belongs to a table only when the table name is a whole prefix
 * component: "users/1/age" belongs to "users", "users_archive/1/age" does
 * not. */
static bool key_under_prefix(const char* key, const char* prefix,
                             size_t prefix_len) {
    if (strncmp(key, prefix, prefix_len) != 0) return false;
    char c = key[prefix_len];
    return c == '\0' || c == '/' || c == ':';
}

/* The final component of a key: the column name in the row model. */
static const char* key_column(const char* key) {
    const char* slash = strrchr(key, '/');
    const char* colon = strrchr(key, ':');
    const char* sep = (slash > colon) ? slash : colon;
    return sep ? sep + 1 : key;
}

/* Does this key carry `column`?  A NULL column means "any row". */
static bool column_is(const char* key, const char* column, size_t column_len) {
    if (!column) return true;
    const char* c = key_column(key);
    return strncmp(c, column, column_len) == 0 && c[column_len] == '\0';
}

/* Aggregate names are SQL keywords, so they are matched case-insensitively;
 * column names are data (key components) and are matched byte-exactly. */
static bool ci_eq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == *b;
}

/* A value is numeric only if the WHOLE value is a finite number.  A value
 * that is not a number is refused by the caller rather than skipped:
 * skipping would report a sum that silently omits rows, which is the failure
 * mode this module exists to remove. */
static bool value_to_double(const char* value, double* out) {
    if (!value || value[0] == '\0') return false;
    errno = 0;
    char* end = NULL;
    double v = strtod(value, &end);
    if (end == value) return false;
    while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r') end++;
    if (*end != '\0') return false;
    if (errno == ERANGE) return false;
    /* Rejects NaN (all comparisons false) and +/-infinity in one test. */
    if (!(v >= -DBL_MAX && v <= DBL_MAX)) return false;
    *out = v;
    return true;
}

/* -------------------------------------------------------------------------
 * One authorized pass over the keyspace
 *
 * qihse_kv_foreach_user() is the KV layer's only enumeration primitive: it
 * has no prefix, range or resume form, so the traversal cannot be split
 * between workers (see the header).  It is also not safe to run twice
 * concurrently: a store whose SSTable metadata index is degraded compacts
 * back into the memtable inside this call, so two concurrent traversals
 * would be two concurrent writers.
 * ------------------------------------------------------------------------- */

typedef struct {
    const char* prefix;
    size_t prefix_len;
    qihse_parallel_row_t* rows;
    size_t count;
    size_t cap;
    bool oom;
} kv_rows_t;

static bool collect_row_cb(const char* key, const char* value,
                           void* user_data) {
    kv_rows_t* c = (kv_rows_t*)user_data;
    if (!c || !key) return false;
    if (!key_under_prefix(key, c->prefix, c->prefix_len)) return true;
    if (c->count == c->cap) {
        size_t cap = c->cap ? c->cap * 2u : 64u;
        if (cap <= c->cap) {
            c->oom = true;
            return false;
        }
        qihse_parallel_row_t* rows =
            (qihse_parallel_row_t*)realloc(c->rows, cap * sizeof(*rows));
        if (!rows) {
            c->oom = true;
            return false;
        }
        c->rows = rows;
        c->cap = cap;
    }
    qihse_parallel_row_t* row = &c->rows[c->count];
    row->key = strdup(key);
    row->value = strdup(value ? value : "");
    if (!row->key || !row->value) {
        free(row->key);
        row->key = NULL;
        row->value = NULL;
        c->oom = true;
        return false;
    }
    c->count++;
    return true;
}

/* A failed enumeration is QIHSE_PARALLEL_ERR_STORE, never an empty table. */
static int collect_rows(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* prefix, kv_rows_t* out) {
    memset(out, 0, sizeof(*out));
    out->prefix = prefix;
    out->prefix_len = strlen(prefix);
    if (!qihse_kv_foreach_user(kv, ctx->user, collect_row_cb, out))
        return QIHSE_PARALLEL_ERR_STORE;
    if (out->oom) return QIHSE_PARALLEL_ERR_NOMEM;
    return QIHSE_PARALLEL_OK;
}

static void rows_free(qihse_parallel_row_t* rows, size_t count) {
    if (!rows) return;
    for (size_t i = 0; i < count; i++) {
        free(rows[i].key);
        free(rows[i].value);
    }
    free(rows);
}

/* -------------------------------------------------------------------------
 * Worker launch
 * ------------------------------------------------------------------------- */

/* Start `num_workers` workers and join exactly the ones that started.  The
 * caller refuses with the returned code instead of publishing a partial
 * result as a whole one. */
static int launch_and_join(pthread_t* threads, int num_workers,
                           void* (*worker_fn)(void*), void* args,
                           size_t arg_size) {
    bool* started = (bool*)calloc((size_t)num_workers, sizeof(bool));
    if (!started) return QIHSE_PARALLEL_ERR_NOMEM;
    int rc = QIHSE_PARALLEL_OK;
    for (int i = 0; i < num_workers; i++) {
        if (pthread_create(&threads[i], NULL, worker_fn,
                           (char*)args + (size_t)i * arg_size) != 0) {
            rc = QIHSE_PARALLEL_ERR_THREAD;
            break;
        }
        started[i] = true;
    }
    for (int i = 0; i < num_workers; i++) {
        if (started[i]) pthread_join(threads[i], NULL);
    }
    free(started);
    return rc;
}

/* -------------------------------------------------------------------------
 * Context
 * ------------------------------------------------------------------------- */

qihse_parallel_ctx_t* qihse_parallel_init(int num_workers) {
    if (num_workers <= 0 || num_workers > QIHSE_PARALLEL_MAX_WORKERS)
        return NULL;
    qihse_parallel_ctx_t* ctx =
        (qihse_parallel_ctx_t*)calloc(1, sizeof(qihse_parallel_ctx_t));
    if (!ctx) return NULL;
    ctx->worker_threads =
        (pthread_t*)calloc((size_t)num_workers, sizeof(pthread_t));
    if (!ctx->worker_threads) {
        free(ctx);
        return NULL;
    }
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        free(ctx->worker_threads);
        free(ctx);
        return NULL;
    }
    ctx->num_workers = num_workers;
    ctx->shutdown = 0;
    ctx->user = NULL; /* unclassified-only until qihse_parallel_set_user() */
    return ctx;
}

int qihse_parallel_set_user(qihse_parallel_ctx_t* ctx, qihse_user_t* user) {
    if (!ctx) return QIHSE_PARALLEL_ERR_ARGS;
    pthread_mutex_lock(&ctx->lock);
    ctx->user = user; /* borrowed, never owned */
    pthread_mutex_unlock(&ctx->lock);
    return QIHSE_PARALLEL_OK;
}

qihse_user_t* qihse_parallel_get_user(qihse_parallel_ctx_t* ctx) {
    if (!ctx) return NULL;
    pthread_mutex_lock(&ctx->lock);
    qihse_user_t* user = ctx->user;
    pthread_mutex_unlock(&ctx->lock);
    return user;
}

void qihse_parallel_cleanup(qihse_parallel_ctx_t* ctx) {
    if (!ctx) return;
    /* The caller must not race this with an operation on the same context. */
    ctx->shutdown = 1;
    pthread_mutex_destroy(&ctx->lock);
    free(ctx->worker_threads);
    free(ctx);
}

/* -------------------------------------------------------------------------
 * Parallel scan
 * ------------------------------------------------------------------------- */

typedef struct {
    const qihse_parallel_row_t* rows; /* shared, read-only */
    size_t row_count;
    size_t start;                     /* first index owned by this worker */
    size_t stride;                    /* == num_workers */
    qihse_parallel_row_t* out;        /* owned by this worker */
    size_t out_count;
    bool oom;
} scan_worker_arg_t;

static void* scan_worker(void* arg) {
    scan_worker_arg_t* a = (scan_worker_arg_t*)arg;
    for (size_t i = a->start; i < a->row_count; i += a->stride) {
        const qihse_parallel_row_t* src = &a->rows[i];
        qihse_parallel_row_t* dst = &a->out[a->out_count];
        dst->key = strdup(src->key);
        dst->value = strdup(src->value);
        if (!dst->key || !dst->value) {
            free(dst->key);
            dst->key = NULL;
            dst->value = NULL;
            a->oom = true;
            return NULL;
        }
        a->out_count++;
    }
    return NULL;
}

void qihse_parallel_scan_free(qihse_parallel_scan_t* scan) {
    if (!scan) return;
    if (scan->results && scan->result_counts) {
        for (int i = 0; i < scan->num_workers; i++) {
            rows_free((qihse_parallel_row_t*)scan->results[i],
                      scan->result_counts[i]);
        }
    }
    free(scan->table_name);
    free(scan->results);
    free(scan->result_counts);
    memset(scan, 0, sizeof(*scan));
}

int qihse_parallel_scan(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* table_prefix,
                        qihse_parallel_scan_t* out_scan) {
    if (!out_scan) return QIHSE_PARALLEL_ERR_ARGS;
    /* A refusal never leaves a stale result looking like an answer. */
    memset(out_scan, 0, sizeof(*out_scan));
    if (!ctx || !kv || !table_prefix || table_prefix[0] == '\0')
        return QIHSE_PARALLEL_ERR_ARGS;

    const int num_workers = ctx->num_workers;
    out_scan->num_workers = num_workers;
    pthread_mutex_lock(&ctx->lock);

    kv_rows_t rows;
    scan_worker_arg_t* args = NULL;
    int rc = collect_rows(ctx, kv, table_prefix, &rows);

    if (rc != QIHSE_PARALLEL_OK) goto done;

    out_scan->table_name = strdup(table_prefix);
    out_scan->results = (void**)calloc((size_t)num_workers, sizeof(void*));
    out_scan->result_counts =
        (size_t*)calloc((size_t)num_workers, sizeof(size_t));
    args = (scan_worker_arg_t*)calloc((size_t)num_workers, sizeof(*args));
    if (!out_scan->table_name || !out_scan->results ||
        !out_scan->result_counts || !args) {
        rc = QIHSE_PARALLEL_ERR_NOMEM;
        goto done;
    }

    for (int i = 0; i < num_workers; i++) {
        const size_t start = (size_t)i;
        const size_t stride = (size_t)num_workers;
        const size_t part =
            (rows.count > start) ? (rows.count - start + stride - 1u) / stride
                                 : 0u;
        args[i].rows = rows.rows;
        args[i].row_count = rows.count;
        args[i].start = start;
        args[i].stride = stride;
        args[i].out = part
            ? (qihse_parallel_row_t*)calloc(part, sizeof(qihse_parallel_row_t))
            : NULL;
        args[i].out_count = 0;
        args[i].oom = (part > 0u && !args[i].out);
    }
    for (int i = 0; i < num_workers; i++) {
        if (args[i].oom) {
            rc = QIHSE_PARALLEL_ERR_NOMEM;
            goto done;
        }
    }

    rc = launch_and_join(ctx->worker_threads, num_workers, scan_worker, args,
                         sizeof(*args));
    if (rc != QIHSE_PARALLEL_OK) goto done;

    size_t total = 0;
    size_t largest = 0;
    for (int i = 0; i < num_workers; i++) {
        if (args[i].oom) {
            rc = QIHSE_PARALLEL_ERR_NOMEM;
            goto done;
        }
        out_scan->results[i] = args[i].out;
        out_scan->result_counts[i] = args[i].out_count;
        total += args[i].out_count;
        if (args[i].out_count > largest) largest = args[i].out_count;
        args[i].out = NULL; /* ownership moved to out_scan */
    }
    out_scan->total_rows = total;
    out_scan->rows_per_worker = largest;
    rc = QIHSE_PARALLEL_OK;

done:
    if (args) {
        for (int i = 0; i < num_workers; i++)
            rows_free(args[i].out, args[i].out_count);
    }
    free(args);
    rows_free(rows.rows, rows.count);
    if (rc != QIHSE_PARALLEL_OK) qihse_parallel_scan_free(out_scan);
    pthread_mutex_unlock(&ctx->lock);
    return rc;
}

/* -------------------------------------------------------------------------
 * Parallel aggregate
 * ------------------------------------------------------------------------- */

typedef enum {
    AGG_COUNT = 0,
    AGG_SUM,
    AGG_AVG,
    AGG_MIN,
    AGG_MAX
} agg_func_t;

static int agg_func_parse(const char* name) {
    if (ci_eq(name, "count")) return AGG_COUNT;
    if (ci_eq(name, "sum")) return AGG_SUM;
    if (ci_eq(name, "avg")) return AGG_AVG;
    if (ci_eq(name, "min")) return AGG_MIN;
    if (ci_eq(name, "max")) return AGG_MAX;
    return -1;
}

typedef struct {
    const qihse_parallel_row_t* rows; /* shared, read-only */
    size_t row_count;
    size_t start;
    size_t stride;
    const char* column;               /* NULL == every row */
    size_t column_len;
    agg_func_t func;
    double agg;                       /* sum for sum/avg; min or max otherwise */
    size_t count;                     /* rows that contributed a value */
    bool have;                        /* agg is meaningful */
    int err;                          /* QIHSE_PARALLEL_ERR_DATA on bad value */
} agg_worker_arg_t;

static void* agg_worker(void* arg) {
    agg_worker_arg_t* a = (agg_worker_arg_t*)arg;
    for (size_t i = a->start; i < a->row_count; i += a->stride) {
        const qihse_parallel_row_t* row = &a->rows[i];
        if (!column_is(row->key, a->column, a->column_len)) continue;
        if (a->func == AGG_COUNT) {
            a->count++;
            continue;
        }
        double v = 0.0;
        if (!value_to_double(row->value, &v)) {
            a->err = QIHSE_PARALLEL_ERR_DATA;
            return NULL;
        }
        a->count++;
        switch (a->func) {
        case AGG_SUM:
        case AGG_AVG:
            a->agg += v;
            break;
        case AGG_MIN:
            if (!a->have || v < a->agg) a->agg = v;
            break;
        case AGG_MAX:
            if (!a->have || v > a->agg) a->agg = v;
            break;
        case AGG_COUNT:
            break;
        }
        a->have = true;
    }
    return NULL;
}

int qihse_parallel_aggregate(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                             const char* table_name, const char* agg_column,
                             const char* agg_func, double* out_result) {
    if (!out_result) return QIHSE_PARALLEL_ERR_ARGS;
    /* A refusal never leaves a stale result looking like an answer. */
    *out_result = 0.0;
    if (!ctx || !kv || !table_name || !table_name[0] || !agg_func)
        return QIHSE_PARALLEL_ERR_ARGS;
    const int parsed = agg_func_parse(agg_func);
    if (parsed < 0) return QIHSE_PARALLEL_ERR_UNSUPPORTED;
    const agg_func_t func = (agg_func_t)parsed;
    if (agg_column && agg_column[0] == '\0') agg_column = NULL;

    pthread_mutex_lock(&ctx->lock);

    kv_rows_t rows;
    agg_worker_arg_t* args = NULL;
    const int num_workers = ctx->num_workers;
    int rc = collect_rows(ctx, kv, table_name, &rows);

    if (rc != QIHSE_PARALLEL_OK) goto done;

    /* An empty table has a defined count and sum (0).  It has no average,
     * minimum or maximum, and reporting 0 for those is exactly the false
     * answer this module exists to remove. */
    if (rows.count == 0u) {
        rc = (func == AGG_COUNT || func == AGG_SUM)
            ? QIHSE_PARALLEL_OK
            : QIHSE_PARALLEL_ERR_NO_RESULT;
        goto done;
    }

    args = (agg_worker_arg_t*)calloc((size_t)num_workers, sizeof(*args));
    if (!args) {
        rc = QIHSE_PARALLEL_ERR_NOMEM;
        goto done;
    }
    for (int i = 0; i < num_workers; i++) {
        args[i].rows = rows.rows;
        args[i].row_count = rows.count;
        args[i].start = (size_t)i;
        args[i].stride = (size_t)num_workers;
        args[i].column = agg_column;
        args[i].column_len = agg_column ? strlen(agg_column) : 0u;
        args[i].func = func;
    }

    rc = launch_and_join(ctx->worker_threads, num_workers, agg_worker, args,
                         sizeof(*args));
    if (rc != QIHSE_PARALLEL_OK) goto done;

    double total = 0.0;
    size_t total_count = 0;
    bool have = false;
    for (int i = 0; i < num_workers; i++) {
        if (args[i].err != QIHSE_PARALLEL_OK) {
            rc = args[i].err;
            goto done;
        }
        total_count += args[i].count;
        switch (func) {
        case AGG_COUNT:
            break; /* total_count is the answer */
        case AGG_SUM:
        case AGG_AVG:
            total += args[i].agg;
            break;
        case AGG_MIN:
            if (args[i].have && (!have || args[i].agg < total)) {
                total = args[i].agg;
                have = true;
            }
            break;
        case AGG_MAX:
            if (args[i].have && (!have || args[i].agg > total)) {
                total = args[i].agg;
                have = true;
            }
            break;
        }
    }

    /* No row carried the column: it does not exist in this table, and
     * "count = 0" for a column that is not there is not an answer. */
    if (total_count == 0u) {
        rc = QIHSE_PARALLEL_ERR_NO_RESULT;
        goto done;
    }
    if (func == AGG_COUNT) {
        *out_result = (double)total_count;
    } else {
        const double result =
            (func == AGG_AVG) ? total / (double)total_count : total;
        /* A sum that overflowed to infinity is not an answer. */
        if (!(result >= -DBL_MAX && result <= DBL_MAX)) {
            rc = QIHSE_PARALLEL_ERR_DATA;
            goto done;
        }
        *out_result = result;
    }
    rc = QIHSE_PARALLEL_OK;

done:
    free(args);
    rows_free(rows.rows, rows.count);
    if (rc != QIHSE_PARALLEL_OK) *out_result = 0.0;
    pthread_mutex_unlock(&ctx->lock);
    return rc;
}

/* -------------------------------------------------------------------------
 * Parallel hash join
 * ------------------------------------------------------------------------- */

typedef struct {
    const char* value; /* borrowed from the row array */
    const char* key;   /* borrowed; NULL marks a free slot */
} join_slot_t;

typedef struct {
    const qihse_parallel_row_t* left;
    size_t left_count;
    const qihse_parallel_row_t* right;
    size_t right_count;
    const char* column;
    size_t column_len;
    unsigned bucket;   /* the hash buckets this worker owns */
    unsigned buckets;  /* == num_workers */
    size_t max_pairs;  /* this worker's share of the pair cap */
    size_t left_join_rows;
    size_t right_join_rows;
    size_t matched;
    qihse_parallel_join_pair_t* pairs;
    size_t pair_cap;
    bool oom;
    bool over_limit;
} join_worker_arg_t;

static uint64_t join_hash(const char* value) {
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char* p = (const unsigned char*)value; *p; p++) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL;
    }
    return h;
}

static unsigned join_bucket(const char* value, unsigned buckets) {
    return (unsigned)(join_hash(value) % (uint64_t)buckets);
}

static bool join_pair_append(join_worker_arg_t* a, const char* left_key,
                             const char* right_key) {
    if (a->matched >= a->max_pairs) {
        a->over_limit = true;
        return false;
    }
    if (a->matched == a->pair_cap) {
        size_t cap = a->pair_cap ? a->pair_cap * 2u : 16u;
        qihse_parallel_join_pair_t* pairs = (qihse_parallel_join_pair_t*)
            realloc(a->pairs, cap * sizeof(*pairs));
        if (!pairs) {
            a->oom = true;
            return false;
        }
        a->pairs = pairs;
        a->pair_cap = cap;
    }
    char* l = strdup(left_key);
    char* r = strdup(right_key);
    if (!l || !r) {
        free(l);
        free(r);
        a->oom = true;
        return false;
    }
    a->pairs[a->matched].left_key = l;
    a->pairs[a->matched].right_key = r;
    a->matched++;
    return true;
}

static void* join_worker(void* arg) {
    join_worker_arg_t* a = (join_worker_arg_t*)arg;
    join_slot_t* table = NULL;
    size_t cap = 0;
    size_t n = 0;

    /* Build: count this worker's share of the left rows first, so the probe
     * table is allocated once, at its final size.  Both sides are partitioned
     * by the same hash of the join value, so every pair is found by exactly
     * one worker and no pair is emitted twice. */
    for (size_t i = 0; i < a->left_count; i++) {
        const qihse_parallel_row_t* r = &a->left[i];
        if (!column_is(r->key, a->column, a->column_len)) continue;
        if (join_bucket(r->value, a->buckets) != a->bucket) continue;
        n++;
    }
    a->left_join_rows = n;
    if (n > 0u) {
        if (n > (SIZE_MAX / 2u)) {
            a->oom = true;
            return NULL;
        }
        cap = 16u;
        while (cap < n * 2u) cap *= 2u;
        table = (join_slot_t*)calloc(cap, sizeof(*table));
        if (!table) {
            a->oom = true;
            return NULL;
        }
        for (size_t i = 0; i < a->left_count; i++) {
            const qihse_parallel_row_t* r = &a->left[i];
            if (!column_is(r->key, a->column, a->column_len)) continue;
            if (join_bucket(r->value, a->buckets) != a->bucket) continue;
            size_t j = (size_t)(join_hash(r->value) & (uint64_t)(cap - 1u));
            while (table[j].key) j = (j + 1u) & (cap - 1u);
            table[j].value = r->value;
            table[j].key = r->key;
        }
    }

    /* Probe: this worker's share of the right rows. */
    for (size_t i = 0; i < a->right_count; i++) {
        const qihse_parallel_row_t* r = &a->right[i];
        if (!column_is(r->key, a->column, a->column_len)) continue;
        if (join_bucket(r->value, a->buckets) != a->bucket) continue;
        a->right_join_rows++;
        if (!table) continue;
        size_t j = (size_t)(join_hash(r->value) & (uint64_t)(cap - 1u));
        while (table[j].key) {
            if (strcmp(table[j].value, r->value) == 0) {
                if (!join_pair_append(a, table[j].key, r->key)) {
                    free(table);
                    return NULL;
                }
            }
            j = (j + 1u) & (cap - 1u);
        }
    }
    free(table);
    return NULL;
}

void qihse_parallel_join_free(qihse_parallel_join_t* join) {
    if (!join) return;
    if (join->pairs) {
        for (size_t i = 0; i < join->matched_rows; i++) {
            free(join->pairs[i].left_key);
            free(join->pairs[i].right_key);
        }
        free(join->pairs);
    }
    memset(join, 0, sizeof(*join));
}

int qihse_parallel_join(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* left_table, const char* right_table,
                        const char* join_key, qihse_parallel_join_t* out_join) {
    if (!out_join) return QIHSE_PARALLEL_ERR_ARGS;
    /* A refusal never leaves a stale result looking like an answer. */
    memset(out_join, 0, sizeof(*out_join));
    if (!ctx || !kv || !left_table || !left_table[0] || !right_table ||
        !right_table[0] || !join_key || !join_key[0])
        return QIHSE_PARALLEL_ERR_ARGS;

    pthread_mutex_lock(&ctx->lock);

    kv_rows_t left;
    kv_rows_t right;
    memset(&left, 0, sizeof(left));
    memset(&right, 0, sizeof(right));
    join_worker_arg_t* args = NULL;
    const int num_workers = ctx->num_workers;
    const size_t join_len = strlen(join_key);
    int rc = collect_rows(ctx, kv, left_table, &left);

    if (rc != QIHSE_PARALLEL_OK) goto done;
    rc = collect_rows(ctx, kv, right_table, &right);
    if (rc != QIHSE_PARALLEL_OK) goto done;

    args = (join_worker_arg_t*)calloc((size_t)num_workers, sizeof(*args));
    if (!args) {
        rc = QIHSE_PARALLEL_ERR_NOMEM;
        goto done;
    }
    const size_t per_worker_cap =
        (size_t)QIHSE_PARALLEL_JOIN_MAX_PAIRS / (size_t)num_workers + 1u;
    for (int i = 0; i < num_workers; i++) {
        args[i].left = left.rows;
        args[i].left_count = left.count;
        args[i].right = right.rows;
        args[i].right_count = right.count;
        args[i].column = join_key;
        args[i].column_len = join_len;
        args[i].bucket = (unsigned)i;
        args[i].buckets = (unsigned)num_workers;
        args[i].max_pairs = per_worker_cap;
    }

    rc = launch_and_join(ctx->worker_threads, num_workers, join_worker, args,
                         sizeof(*args));
    if (rc != QIHSE_PARALLEL_OK) goto done;

    size_t matched = 0;
    size_t left_join_rows = 0;
    size_t right_join_rows = 0;
    for (int i = 0; i < num_workers; i++) {
        if (args[i].oom) {
            rc = QIHSE_PARALLEL_ERR_NOMEM;
            goto done;
        }
        if (args[i].over_limit) {
            rc = QIHSE_PARALLEL_ERR_LIMIT;
            goto done;
        }
        matched += args[i].matched;
        left_join_rows += args[i].left_join_rows;
        right_join_rows += args[i].right_join_rows;
    }

    /* Nothing could have matched: one side has no row carrying the join
     * column at all.  Reporting that as "0 rows matched" is the false
     * success this module exists to remove, so it is a refusal. */
    if (left_join_rows == 0u || right_join_rows == 0u) {
        rc = QIHSE_PARALLEL_ERR_NO_RESULT;
        goto done;
    }

    if (matched > 0u) {
        out_join->pairs = (qihse_parallel_join_pair_t*)
            calloc(matched, sizeof(qihse_parallel_join_pair_t));
        if (!out_join->pairs) {
            rc = QIHSE_PARALLEL_ERR_NOMEM;
            goto done;
        }
        size_t w = 0;
        for (int i = 0; i < num_workers; i++) {
            for (size_t k = 0; k < args[i].matched; k++) {
                out_join->pairs[w++] = args[i].pairs[k];
                args[i].pairs[k].left_key = NULL; /* ownership moved */
                args[i].pairs[k].right_key = NULL;
            }
        }
    }
    out_join->left_keys = left.count;
    out_join->right_keys = right.count;
    out_join->left_join_rows = left_join_rows;
    out_join->right_join_rows = right_join_rows;
    out_join->matched_rows = matched;
    rc = QIHSE_PARALLEL_OK;

done:
    if (args) {
        for (int i = 0; i < num_workers; i++) {
            for (size_t k = 0; k < args[i].matched; k++) {
                free(args[i].pairs[k].left_key);
                free(args[i].pairs[k].right_key);
            }
            free(args[i].pairs);
        }
    }
    free(args);
    rows_free(left.rows, left.count);
    rows_free(right.rows, right.count);
    if (rc != QIHSE_PARALLEL_OK) qihse_parallel_join_free(out_join);
    pthread_mutex_unlock(&ctx->lock);
    return rc;
}
