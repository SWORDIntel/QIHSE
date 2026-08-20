#ifndef QIHSE_OPTIMIZER_H
#define QIHSE_OPTIMIZER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_sql_parser.h"
#include "qihse_schema.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Cost-based optimizer — Phase 1 Relational Completeness
 *
 * Maintains basic statistics (row count estimates, column histograms),
 * estimates cardinality for filter conditions, and enumerates plans
 * choosing between seq scan, index scan, hash join vs nested loop.
 * ------------------------------------------------------------------------- */

typedef enum {
    QIHSE_PLAN_SEQ_SCAN    = 1,
    QIHSE_PLAN_INDEX_SCAN  = 2,
    QIHSE_PLAN_HASH_JOIN   = 3,
    QIHSE_PLAN_NESTED_LOOP = 4,
    QIHSE_PLAN_AGGREGATE   = 5,
    QIHSE_PLAN_SORT        = 6,
    QIHSE_PLAN_LIMIT       = 7,
    QIHSE_PLAN_SUBQUERY    = 8
} qihse_plan_node_type_t;

typedef struct qihse_plan_node {
    qihse_plan_node_type_t type;
    char*  table_name;          /* for scan nodes */
    char*  index_name;          /* for index scan */
    char*  filter_column;       /* filter column */
    double estimated_rows;
    double estimated_cost;
    struct qihse_plan_node* left;
    struct qihse_plan_node* right;
    /* join-specific */
    char*  join_key_left;
    char*  join_key_right;
    qihse_sql_join_type_t join_type;
    /* aggregate / sort specific */
    char** group_cols;
    size_t num_group_cols;
    char** sort_cols;
    int*   sort_asc;
    size_t num_sort_cols;
    int    limit;
} qihse_plan_node_t;

/* Column statistics: distinct count, min, max (as strings), null fraction */
typedef struct {
    char*  column_name;
    int64_t distinct_count;
    double  null_fraction;
    char*  min_value;
    char*  max_value;
    /* simple histogram: up to 16 buckets */
    char*  hist_lo[16];
    char*  hist_hi[16];
    int64_t hist_freq[16];
    int    num_buckets;
} qihse_column_stat_t;

/* Table statistics */
typedef struct {
    char*  table_name;
    int64_t row_count;
    qihse_column_stat_t* columns;
    size_t num_columns;
} qihse_table_stat_t;

typedef struct qihse_optimizer qihse_optimizer_t;

/* Create / destroy */
qihse_optimizer_t* qihse_optimizer_create(qihse_schema_registry_t* schema);
void qihse_optimizer_destroy(qihse_optimizer_t* opt);

/* Statistics management */
void qihse_optimizer_set_table_stats(qihse_optimizer_t* opt, const char* table, int64_t row_count);
void qihse_optimizer_set_column_stats(qihse_optimizer_t* opt, const char* table,
                                       const char* column, int64_t distinct_count,
                                       double null_fraction, const char* min_val, const char* max_val);
const qihse_table_stat_t* qihse_optimizer_get_table_stats(const qihse_optimizer_t* opt, const char* table);

/* Cardinality estimation for a filter condition */
double qihse_optimizer_estimate_selectivity(const qihse_optimizer_t* opt,
                                             const char* table,
                                             const qihse_sql_condition_t* cond);

/* Plan enumeration: build a plan tree from an AST */
qihse_plan_node_t* qihse_optimizer_build_plan(qihse_optimizer_t* opt, const qihse_sql_ast_t* ast);

/* Free a plan tree */
void qihse_plan_node_free(qihse_plan_node_t* node);

/* Get a human-readable name for a plan node type */
const char* qihse_plan_node_type_name(qihse_plan_node_type_t t);

#ifdef __cplusplus
}
#endif

#endif
