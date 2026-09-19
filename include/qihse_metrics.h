#ifndef QIHSE_METRICS_H
#define QIHSE_METRICS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    METRIC_COUNTER = 0,
    METRIC_GAUGE = 1,
    METRIC_HISTOGRAM = 2,
    METRIC_SUMMARY = 3
} metric_type_t;

/* ── Bounds (W5.2) ───────────────────────────────────────────────────────
 *
 * The registry began as one unlabelled series per name.  W5.2 needs
 * dimensions (query type, engine backend, index kind), and the F8
 * observability work established the rule this file now enforces: a label
 * whose value set is decided by the DATA — a key, a query string, a node id —
 * is a memory leak with a metric attached.  So a labelled family declares its
 * COMPLETE value set at registration and the registry refuses any other
 * value; an unknown value is counted as `label_rejected_total` rather than
 * silently creating a series.
 *
 * Every bound below is compile-time, so the worst-case memory of the registry
 * is a constant: families x (values x (bucket array + label copies)).
 */
#define QIHSE_METRICS_MAX_LABEL_VALUES 32u /* series in one labelled family */
#define QIHSE_METRICS_MAX_BUCKETS      16u /* histogram upper bounds/series  */
#define QIHSE_METRICS_LABEL_NAME_MAX   32u /* incl. NUL                      */
#define QIHSE_METRICS_LABEL_VALUE_MAX  48u /* incl. NUL                      */

/* ── Query-type vocabulary (W5.2) ────────────────────────────────────────
 *
 * The `type` dimension of qihse_queries_total / qihse_query_latency_seconds /
 * qihse_query_errors_total.  This enum IS the bound: a command name is mapped
 * to one of these by a fixed table, and anything unrecognised lands in OTHER.
 * User data (a key, a statement, a node id) can never become a label value.
 */
typedef enum {
    QIHSE_QUERY_TYPE_GET = 0,
    QIHSE_QUERY_TYPE_SET,
    QIHSE_QUERY_TYPE_DELETE,
    QIHSE_QUERY_TYPE_SCAN,       /* MGET / KEYS / SCAN / TYPE / EXISTS / OBJECT */
    QIHSE_QUERY_TYPE_EXPIRE,     /* EXPIRE* / PEXPIRE* / PERSIST / TTL / PTTL */
    QIHSE_QUERY_TYPE_VECTOR,     /* VECSET / VECGET / VECSEARCH               */
    QIHSE_QUERY_TYPE_TIMESERIES, /* TS.ADD / TS.RANGE                         */
    QIHSE_QUERY_TYPE_COLUMN,     /* COL.*                                     */
    QIHSE_QUERY_TYPE_DOCUMENT,   /* DOC.*                                     */
    QIHSE_QUERY_TYPE_GRAPH,      /* GRAPH.* / Cypher surface                  */
    QIHSE_QUERY_TYPE_FTS,        /* SEARCH.* / FTS.*                          */
    QIHSE_QUERY_TYPE_SQL,        /* SQL / QQL surface                         */
    QIHSE_QUERY_TYPE_KEYSTONE,   /* KEYSTONE.*                                */
    QIHSE_QUERY_TYPE_FABRIC,     /* FABRIC.* / TASK.* / SCHEDULE.*            */
    QIHSE_QUERY_TYPE_CLUSTER,    /* CLUSTER.* / GROUP.* / MIGRATE / ASKING    */
    QIHSE_QUERY_TYPE_FEDERATION, /* FEDERATION.*                              */
    QIHSE_QUERY_TYPE_PUBSUB,     /* PUBLISH / SUBSCRIBE / PUBSUB              */
    QIHSE_QUERY_TYPE_ADMIN,      /* CONFIG / DEBUG / MEMORY / METRICS.RENDER   */
    QIHSE_QUERY_TYPE_SESSION,    /* AUTH / HELLO / PING / SELECT / MULTI ...   */
    QIHSE_QUERY_TYPE_OTHER,      /* anything not classified above             */
    QIHSE_QUERY_TYPE_COUNT
} qihse_query_type_t;

const char* qihse_query_type_name(qihse_query_type_t type);

/* ── Engine-backend vocabulary (W5.2) ────────────────────────────────────
 *
 * The `backend` dimension of qihse_backend_queries_total and
 * qihse_backend_available.  Backend identity is the ENGINE that serves the
 * request in this multi-model database, not a caller-supplied name: the value
 * set is this enum, so a client cannot mint a new backend label.
 */
typedef enum {
    QIHSE_ENGINE_BACKEND_KV = 0,
    QIHSE_ENGINE_BACKEND_VECTOR,
    QIHSE_ENGINE_BACKEND_TIMESERIES,
    QIHSE_ENGINE_BACKEND_COLUMN,
    QIHSE_ENGINE_BACKEND_DOCUMENT,
    QIHSE_ENGINE_BACKEND_GRAPH,
    QIHSE_ENGINE_BACKEND_FTS,
    QIHSE_ENGINE_BACKEND_CONTROL, /* session/administrative/cluster control plane */
    QIHSE_ENGINE_BACKEND_COUNT
} qihse_engine_backend_t;

const char* qihse_engine_backend_name(qihse_engine_backend_t backend);

typedef struct {
    char* name;
    char* help;
    metric_type_t type;
    /* Gauge/summary value.  Mutex-protected; a counter's value lives in
     * `counter` instead so that incrementing one is a single lock-free add. */
    double value;
    /* Counter value (METRIC_COUNTER) and observation count (histogram,
     * summary).  Written with __atomic_* so a request path never takes a
     * lock to count something. */
    uint64_t counter;
    uint64_t count;
    double sum;
    /* W5.2: label-bounded series identity.  Both fields are fixed-size
     * copies, never pointers to caller memory, so a caller cannot free a
     * value out from under the registry.  An empty label_value marks the
     * unlabelled series that the original (name-only) API addresses. */
    char label_name[QIHSE_METRICS_LABEL_NAME_MAX];
    char label_value[QIHSE_METRICS_LABEL_VALUE_MAX];
    /* Histogram upper bounds, strictly increasing, and per-bucket counts.
     * Stored NON-cumulative so an observation is one atomic add rather than
     * one per bucket; the export and the snapshot accumulate them, which is
     * what the Prometheus `_bucket` format requires.  The +Inf bucket is
     * `count` and needs no storage of its own. */
    double bounds[QIHSE_METRICS_MAX_BUCKETS];
    uint64_t buckets[QIHSE_METRICS_MAX_BUCKETS];
    size_t num_bounds;
    pthread_mutex_t lock;
} qihse_metric_t;

/* A stable handle to ONE series.  Unlike the name-based API it needs no
 * registry lock and no string comparison, which is what makes it usable on a
 * request path.  The handle is a pointer into the registry's own series
 * storage: it stays valid until the registry is destroyed and the caller must
 * never free it. */
typedef qihse_metric_t qihse_metric_series_t;

typedef struct {
    qihse_metric_t** metrics;
    size_t num_metrics;
    size_t cap;
    /* Value of a label that is not in a family's declared value set.  Non-zero
     * means a caller is trying to create a series the bound forbids. */
    uint64_t label_rejected_total;
    pthread_mutex_t lock;
} qihse_metrics_registry_t;

qihse_metrics_registry_t* qihse_metrics_create(void);
void qihse_metrics_destroy(qihse_metrics_registry_t* reg);

int qihse_metrics_register(qihse_metrics_registry_t* reg, const char* name,
                           const char* help, metric_type_t type);
int qihse_metrics_increment(qihse_metrics_registry_t* reg, const char* name, double val);
int qihse_metrics_set(qihse_metrics_registry_t* reg, const char* name, double val);
int qihse_metrics_observe(qihse_metrics_registry_t* reg, const char* name, double val);

/* Register a family of series that share ONE label whose complete value set
 * is declared here.  `label_values` must contain value_count distinct,
 * non-empty strings; value_count is bounded by
 * QIHSE_METRICS_MAX_LABEL_VALUES.  Returns 0 on success.  Registration
 * happens before the first request is served, so a failure is a startup
 * failure: on allocation failure a family may be left partially registered
 * and a retry under the same name is refused by the family-name check. */
int qihse_metrics_register_bounded(qihse_metrics_registry_t* reg, const char* name,
                                   const char* help, metric_type_t type,
                                   const char* label_name,
                                   const char* const* label_values, size_t value_count);

/* Give an existing series an explicit histogram bucket ladder.  `bounds` must
 * be strictly increasing and positive; num_bounds is bounded by
 * QIHSE_METRICS_MAX_BUCKETS.  Observations land in every bucket whose bound
 * they do not exceed, and the overflow is `count` (the +Inf bucket). */
int qihse_metrics_set_buckets(qihse_metrics_registry_t* reg, const char* name,
                              const char* label_value,
                              const double* bounds, size_t num_bounds);

/* Resolve a series handle.  `label_value` is NULL or "" for an unlabelled
 * series.  Returns NULL when no series matches — a bounded label never
 * creates one on demand. */
qihse_metric_series_t* qihse_metrics_series(qihse_metrics_registry_t* reg,
                                            const char* name,
                                            const char* label_value);

/* Hot-path operations: no registry lock, no name lookup.  Counters use one
 * lock-free 64-bit add; gauges and histogram sums take the series lock.
 *
 * Measured on the reference machine (x86-64, -O3, shared library):
 * qihse_metrics_series_increment 8 ns, qihse_metrics_series_observe 23 ns.
 * A counter therefore costs a small fraction of the request it counts; a
 * histogram observation is ~3x a counter and is still 1% of a ~2 us point
 * operation.  Anything that could not be maintained for that price (cluster
 * status, engine occupancy, datapath totals) is sampled at scrape time
 * instead of counted per request. */
int qihse_metrics_series_increment(qihse_metric_series_t* series, uint64_t value);
int qihse_metrics_series_set(qihse_metric_series_t* series, double value);
int qihse_metrics_series_observe(qihse_metric_series_t* series, double value);

typedef struct {
    double value;
    uint64_t count;
    double sum;
    /* Cumulative bucket counts in bounds order; buckets[num_bounds] is the
     * +Inf bucket, i.e. `count`. */
    uint64_t buckets[QIHSE_METRICS_MAX_BUCKETS + 1u];
    size_t num_bounds;
} qihse_metric_snapshot_t;

/* Read one series without going through the text export (used by tests and
 * by any in-process consumer).  Returns 0 on success. */
int qihse_metrics_series_snapshot(const qihse_metric_series_t* series,
                                  qihse_metric_snapshot_t* out);

char* qihse_metrics_export(qihse_metrics_registry_t* reg);
size_t qihse_metrics_count(qihse_metrics_registry_t* reg);

#ifdef __cplusplus
}
#endif
#endif
