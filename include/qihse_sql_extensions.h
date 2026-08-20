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

#ifdef __cplusplus
}
#endif
#endif
