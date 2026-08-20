#ifndef QIHSE_SQL_EXTENSIONS_H
#define QIHSE_SQL_EXTENSIONS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Vector SQL Extensions ---- */

/* VECTOR_SEARCH(table, query_vec, k) table function */
typedef struct {
    char* table_name;
    float* query_vector;
    size_t vector_dims;
    size_t k;
    char* distance_metric;  /* "euclidean", "cosine", "dot" */
} qihse_vector_search_spec_t;

/* Parse VECTOR_SEARCH(...) from SQL */
int qihse_sql_parse_vector_search(const char* sql, qihse_vector_search_spec_t* out);
void qihse_vector_search_spec_free(qihse_vector_search_spec_t* spec);

/* Execute vector search and return results as rows */
typedef struct {
    uint64_t id;
    float distance;
} qihse_vector_search_result_t;

int qihse_sql_execute_vector_search(const qihse_vector_search_spec_t* spec,
                                    qihse_vector_search_result_t** out_results, size_t* out_count);

/* ---- Time-Series SQL Extensions ---- */

/* TIME_BUCKET(bucket_width, time_column) function */
typedef struct {
    int64_t bucket_width_ms;
    char* time_column;
    char* agg_func;     /* "avg", "sum", "min", "max", "count" */
    char* value_column;
} qihse_time_bucket_spec_t;

/* Parse TIME_BUCKET(...) from SQL */
int qihse_sql_parse_time_bucket(const char* sql, qihse_time_bucket_spec_t* out);
void qihse_time_bucket_spec_free(qihse_time_bucket_spec_t* spec);

/* Execute time bucket aggregation */
typedef struct {
    int64_t bucket_start;
    double agg_value;
    size_t count;
} qihse_time_bucket_result_t;

int qihse_sql_execute_time_bucket(const qihse_time_bucket_spec_t* spec,
                                  qihse_time_bucket_result_t** out_results, size_t* out_count);

/* Gap filling: fill missing buckets with NULL or interpolation */
int qihse_time_bucket_fill_gaps(qihse_time_bucket_result_t* results, size_t* count,
                                int64_t start_time, int64_t end_time, int64_t bucket_width,
                                int fill_mode);  /* 0=NULL, 1=linear, 2=carry */

/* ---- Full-Text SQL Extensions ---- */

/* MATCH(field, query) function */
typedef struct {
    char* field;
    char* query;
    int highlight;      /* 0=no, 1=yes */
    int snippet_size;   /* characters */
} qihse_fts_match_spec_t;

/* Parse MATCH(...) from SQL */
int qihse_sql_parse_fts_match(const char* sql, qihse_fts_match_spec_t* out);
void qihse_fts_match_spec_free(qihse_fts_match_spec_t* spec);

/* Execute FTS match */
typedef struct {
    uint64_t doc_id;
    double score;
    char* highlight_snippet;
} qihse_fts_match_result_t;

int qihse_sql_execute_fts_match(const qihse_fts_match_spec_t* spec,
                                qihse_fts_match_result_t** out_results, size_t* out_count);
void qihse_fts_match_result_free(qihse_fts_match_result_t* results, size_t count);

/* ---- ClickHouse SQL Extensions ---- */

/* MergeTree engine family */
typedef enum {
    QIHSE_CH_ENGINE_NONE             = 0,
    QIHSE_CH_ENGINE_MERGETREE        = 1,
    QIHSE_CH_ENGINE_REPLACING_MERGETREE  = 2,
    QIHSE_CH_ENGINE_SUMMING_MERGETREE    = 3,
    QIHSE_CH_ENGINE_AGGREGATING_MERGETREE = 4,
    QIHSE_CH_ENGINE_COLLAPSING_MERGETREE  = 5,
    QIHSE_CH_ENGINE_VERSIONED_MERGETREE   = 6
} qihse_ch_engine_kind_t;

/* MergeTree engine parameters */
typedef struct {
    qihse_ch_engine_kind_t engine_kind;
    char*  engine_params;       /* raw params string (e.g. version column) */
    char*  order_by_expr;       /* ORDER BY expression for the engine */
    char*  partition_by_expr;   /* PARTITION BY expression (optional) */
    char*  primary_key_expr;    /* PRIMARY KEY expression (optional) */
    char*  sample_by_expr;      /* SAMPLE BY expression (optional) */
    char*  ttl_expr;            /* TTL expression (optional) */
    char*  settings_expr;       /* SETTINGS clause (optional) */
} qihse_ch_mergetree_spec_t;

/* Parse MergeTree engine clause from CREATE TABLE SQL */
int qihse_sql_parse_mergetree(const char* sql, qihse_ch_mergetree_spec_t* out);
void qihse_ch_mergetree_spec_free(qihse_ch_mergetree_spec_t* spec);

/* Materialized view definition */
typedef struct {
    char*  view_name;
    char*  target_table;        /* TO table (optional) */
    char*  database;
    int    if_not_exists;       /* IF NOT EXISTS flag */
    char*  select_query;        /* raw AS SELECT ... text */
    char*  engine;              /* engine string (optional) */
} qihse_ch_matview_spec_t;

/* Parse CREATE MATERIALIZED VIEW ... AS SELECT ... from SQL */
int qihse_sql_parse_materialized_view(const char* sql, qihse_ch_matview_spec_t* out);
void qihse_ch_matview_spec_free(qihse_ch_matview_spec_t* spec);

/* Dictionary definition */
typedef struct {
    char*  dict_name;
    char*  source;              /* data source (e.g. mysql, clickhouse, file) */
    char*  layout;              /* layout type (flat, hashed, cache, etc.) */
    int    lifetime;            /* LIFETIME in seconds */
    char** columns;             /* attribute columns */
    size_t num_columns;
    char** column_types;
    size_t num_column_types;
} qihse_ch_dictionary_spec_t;

/* Parse CREATE DICTIONARY ... from SQL */
int qihse_sql_parse_dictionary(const char* sql, qihse_ch_dictionary_spec_t* out);
void qihse_ch_dictionary_spec_free(qihse_ch_dictionary_spec_t* spec);

/* ClickHouse-specific function detection */
typedef enum {
    QIHSE_CH_FUNC_NONE            = 0,
    QIHSE_CH_FUNC_NOW             = 1,
    QIHSE_CH_FUNC_TODAY           = 2,
    QIHSE_CH_FUNC_YESTERDAY       = 3,
    QIHSE_CH_FUNC_TOSTARTOFMONTH  = 4,
    QIHSE_CH_FUNC_TOSTARTOFDAY    = 5,
    QIHSE_CH_FUNC_COUNTIF         = 6,
    QIHSE_CH_FUNC_SUMIF           = 7,
    QIHSE_CH_FUNC_AVGIF           = 8,
    QIHSE_CH_FUNC_GROUPARRAY      = 9,
    QIHSE_CH_FUNC_GROUPUNIQARRAY  = 10
} qihse_ch_func_kind_t;

/* Detect a ClickHouse-specific function from a function name */
qihse_ch_func_kind_t qihse_ch_detect_function(const char* func_name);

/* ARRAY JOIN clause */
typedef struct {
    char*  array_expr;          /* the array column/expression to join on */
    int    is_left;             /* LEFT ARRAY JOIN vs ARRAY JOIN */
} qihse_ch_array_join_t;

/* Parse ARRAY JOIN clause from SELECT SQL */
int qihse_sql_parse_array_join(const char* sql, qihse_ch_array_join_t* out);
void qihse_ch_array_join_free(qihse_ch_array_join_t* spec);

/* FINAL modifier detection */
int qihse_sql_has_final_modifier(const char* sql);

/* PREWHERE clause extraction */
char* qihse_sql_extract_prewhere(const char* sql);

/* SAMPLE clause extraction */
typedef struct {
    char*  sample_expr;         /* e.g. "0.1" or "10000" or "1/10" */
    int    is_offset;           /* 1 if OFFSET is present */
    char*  offset_expr;         /* OFFSET expression (optional) */
} qihse_ch_sample_spec_t;

int qihse_sql_parse_sample(const char* sql, qihse_ch_sample_spec_t* out);
void qihse_ch_sample_spec_free(qihse_ch_sample_spec_t* spec);

/* SETTINGS clause in a query (SELECT ... SETTINGS max_threads=4) */
typedef struct {
    char** names;
    char** values;
    size_t num_settings;
} qihse_ch_query_settings_t;

/* Extract SETTINGS from a query string (removes SETTINGS from the query) */
int qihse_sql_extract_settings(const char* sql, qihse_ch_query_settings_t* out);
void qihse_ch_query_settings_free(qihse_ch_query_settings_t* settings);

/* Get the string name of a ClickHouse engine kind */
const char* qihse_ch_engine_name(qihse_ch_engine_kind_t kind);

/* Get the string name of a ClickHouse function kind */
const char* qihse_ch_func_name(qihse_ch_func_kind_t kind);

#ifdef __cplusplus
}
#endif
#endif
