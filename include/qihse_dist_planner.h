#ifndef QIHSE_DIST_PLANNER_H
#define QIHSE_DIST_PLANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include "qihse_document.h"
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_TASK_KV_POINT = 1,
    QIHSE_TASK_VECTOR_SEARCH = 2,
    QIHSE_TASK_TS_RANGE = 3,
    QIHSE_TASK_COL_SCAN = 4,
    QIHSE_TASK_DOC_FILTER = 5
} qihse_dist_task_type_t;

typedef enum {
    QIHSE_MERGE_NONE = 0,
    QIHSE_MERGE_RRF = 1,              /* Reciprocal Rank Fusion for vector ranking */
    QIHSE_MERGE_SORT_LIMIT = 2,       /* Top-K score sort with limit */
    QIHSE_MERGE_CONCAT = 3,           /* Unordered row concatenation */
    QIHSE_MERGE_AGGREGATE_SUM = 4,    /* Metric summation */
    QIHSE_MERGE_AGGREGATE_AVG = 5     /* Metric averaging */
} qihse_dist_merge_type_t;

typedef struct {
    uint16_t node_index;
    uint16_t slot;
    qihse_dist_task_type_t task_type;
    char target_entity[128];
    float vector_query[128];
    size_t vector_dims;
    size_t top_k;
    int64_t time_start;
    int64_t time_end;
    char filter_column[64];
    char filter_op[8];
    double filter_threshold;
} qihse_shard_task_t;

typedef struct {
    char raw_query[512];
    bool is_scatter_gather;
    qihse_dist_merge_type_t merge_strategy;
    qihse_shard_task_t* tasks;
    size_t num_tasks;
    size_t capacity;
    int limit;
} qihse_dist_plan_t;

typedef struct {
    uint64_t id;
    float score;
    double metric_val;
    int64_t timestamp;
    char payload[256];
} qihse_dist_row_t;

typedef struct {
    qihse_dist_row_t* rows;
    size_t num_rows;
    double aggregate_scalar;
    uint64_t execution_time_ns;
    bool is_error;
    char error_msg[128];
} qihse_dist_query_result_t;

typedef struct qihse_dist_planner qihse_dist_planner_t;

/**
 * @brief Creates a distributed query planner backed by the cluster topology.
 */
qihse_dist_planner_t* qihse_dist_planner_create(qihse_cluster_topology_t* topo);

/**
 * @brief Destroys the distributed query planner.
 */
void qihse_dist_planner_destroy(qihse_dist_planner_t* planner);

/**
 * @brief Deconstructs and plans a composite SQL/QQL multi-model statement.
 */
qihse_dist_plan_t* qihse_dist_plan_query(qihse_dist_planner_t* planner, const char* query_str, qihse_user_t* user);

/**
 * @brief Frees an allocated distributed query plan.
 */
void qihse_dist_plan_free(qihse_dist_plan_t* plan);

/**
 * @brief Executes a planned distributed query across local engines and merged shard outputs.
 */
qihse_dist_query_result_t* qihse_dist_execute_plan(
    qihse_dist_planner_t* planner,
    const qihse_dist_plan_t* plan,
    qihse_kv_store_t* local_kv,
    qihse_vector_db_t local_vdb,
    qihse_tsdb_t* local_tsdb,
    qihse_column_store_t* local_col,
    qihse_document_store_t* local_doc,
    qihse_user_t* user
);

/**
 * @brief Frees a distributed query result.
 */
void qihse_dist_query_result_free(qihse_dist_query_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_DIST_PLANNER_H */
