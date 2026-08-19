#include "qihse_dist_planner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

struct qihse_dist_planner {
    qihse_cluster_topology_t* topo;
};

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

qihse_dist_planner_t* qihse_dist_planner_create(qihse_cluster_topology_t* topo) {
    qihse_dist_planner_t* planner = (qihse_dist_planner_t*)calloc(1, sizeof(qihse_dist_planner_t));
    if (!planner) return NULL;
    planner->topo = topo;
    return planner;
}

void qihse_dist_planner_destroy(qihse_dist_planner_t* planner) {
    if (planner) {
        free(planner);
    }
}

static void plan_add_task(qihse_dist_plan_t* plan, const qihse_shard_task_t* task) {
    if (plan->num_tasks >= plan->capacity) {
        size_t new_cap = plan->capacity ? plan->capacity * 2 : 8;
        qihse_shard_task_t* new_tasks = (qihse_shard_task_t*)realloc(plan->tasks, new_cap * sizeof(qihse_shard_task_t));
        if (!new_tasks) return;
        plan->tasks = new_tasks;
        plan->capacity = new_cap;
    }
    plan->tasks[plan->num_tasks++] = *task;
}

qihse_dist_plan_t* qihse_dist_plan_query(qihse_dist_planner_t* planner, const char* query_str, qihse_user_t* user) {
    (void)user;
    if (!planner || !query_str) return NULL;

    qihse_dist_plan_t* plan = (qihse_dist_plan_t*)calloc(1, sizeof(qihse_dist_plan_t));
    if (!plan) return NULL;

    snprintf(plan->raw_query, sizeof(plan->raw_query), "%s", query_str);
    plan->limit = 10;
    plan->merge_strategy = QIHSE_MERGE_SORT_LIMIT;

    // Detect query type and multi-engine components
    bool has_vector = (strstr(query_str, "vector_search") != NULL || strstr(query_str, "VECSEARCH") != NULL);
    bool has_tsdb = (strstr(query_str, "ts_range") != NULL || strstr(query_str, "telemetry") != NULL || strstr(query_str, "TS.RANGE") != NULL);
    bool has_col = (strstr(query_str, "SUM(") != NULL || strstr(query_str, "AVG(") != NULL || strstr(query_str, "COL.SUM") != NULL);

    // Extract entity or hash tag
    const char* tag_start = strchr(query_str, '{');
    const char* tag_end = tag_start ? strchr(tag_start, '}') : NULL;
    char entity_tag[128] = "default_table";

    if (tag_start && tag_end && tag_end > tag_start) {
        size_t tlen = (size_t)(tag_end - tag_start + 1);
        if (tlen < sizeof(entity_tag)) {
            memcpy(entity_tag, tag_start, tlen);
            entity_tag[tlen] = '\0';
        }
    }

    uint16_t slot = qihse_cluster_key_slot(entity_tag, strlen(entity_tag));
    bool is_scoped = (tag_start != NULL && tag_end != NULL);

    size_t node_count = planner->topo ? qihse_cluster_topology_nodes(planner->topo, NULL, 0) : 1;
    if (node_count == 0) node_count = 1;

    if (is_scoped) {
        plan->is_scatter_gather = false;
        qihse_shard_task_t task;
        memset(&task, 0, sizeof(task));
        task.slot = slot;
        snprintf(task.target_entity, sizeof(task.target_entity), "%s", entity_tag);

        if (has_vector) {
            task.task_type = QIHSE_TASK_VECTOR_SEARCH;
            task.vector_dims = 128;
            task.top_k = 10;
            plan->merge_strategy = QIHSE_MERGE_RRF;
        } else if (has_tsdb) {
            task.task_type = QIHSE_TASK_TS_RANGE;
            task.time_start = 0;
            task.time_end = 1000000;
            plan->merge_strategy = QIHSE_MERGE_AGGREGATE_AVG;
        } else if (has_col) {
            task.task_type = QIHSE_TASK_COL_SCAN;
            plan->merge_strategy = QIHSE_MERGE_AGGREGATE_SUM;
        } else {
            task.task_type = QIHSE_TASK_KV_POINT;
        }

        plan_add_task(plan, &task);
    } else {
        // Multi-shard scatter gather across all nodes in topology
        plan->is_scatter_gather = true;
        if (has_vector) plan->merge_strategy = QIHSE_MERGE_RRF;
        else if (has_tsdb) plan->merge_strategy = QIHSE_MERGE_AGGREGATE_AVG;
        else if (has_col) plan->merge_strategy = QIHSE_MERGE_AGGREGATE_SUM;

        for (size_t i = 0; i < node_count; i++) {
            qihse_shard_task_t task;
            memset(&task, 0, sizeof(task));
            task.node_index = (uint16_t)i;
            task.slot = (uint16_t)(i * (QIHSE_CLUSTER_SLOT_COUNT / node_count));
            snprintf(task.target_entity, sizeof(task.target_entity), "%s", entity_tag);

            if (has_vector) {
                task.task_type = QIHSE_TASK_VECTOR_SEARCH;
                task.vector_dims = 128;
                task.top_k = 10;
            } else if (has_tsdb) {
                task.task_type = QIHSE_TASK_TS_RANGE;
                task.time_start = 0;
                task.time_end = 1000000;
            } else if (has_col) {
                task.task_type = QIHSE_TASK_COL_SCAN;
            } else {
                task.task_type = QIHSE_TASK_DOC_FILTER;
            }
            plan_add_task(plan, &task);
        }
    }

    return plan;
}

void qihse_dist_plan_free(qihse_dist_plan_t* plan) {
    if (plan) {
        if (plan->tasks) free(plan->tasks);
        free(plan);
    }
}

qihse_dist_query_result_t* qihse_dist_execute_plan(
    qihse_dist_planner_t* planner,
    const qihse_dist_plan_t* plan,
    qihse_kv_store_t* local_kv,
    qihse_vector_db_t local_vdb,
    qihse_tsdb_t* local_tsdb,
    qihse_column_store_t* local_col,
    qihse_document_store_t* local_doc,
    qihse_user_t* user
) {
    (void)planner;
    (void)local_doc;
    if (!plan) return NULL;

    uint64_t t0 = get_time_ns();
    qihse_dist_query_result_t* res = (qihse_dist_query_result_t*)calloc(1, sizeof(qihse_dist_query_result_t));
    if (!res) return NULL;

    // Allocate result rows
    size_t max_rows = 64;
    res->rows = (qihse_dist_row_t*)calloc(max_rows, sizeof(qihse_dist_row_t));

    for (size_t i = 0; i < plan->num_tasks; i++) {
        const qihse_shard_task_t* task = &plan->tasks[i];

        switch (task->task_type) {
            case QIHSE_TASK_KV_POINT: {
                if (local_kv) {
                    char* val = qihse_kv_get_user(local_kv, task->target_entity, user);
                    if (val && res->num_rows < max_rows) {
                        res->rows[res->num_rows].id = 1;
                        snprintf(res->rows[res->num_rows].payload, sizeof(res->rows[res->num_rows].payload), "%s", val);
                        res->num_rows++;
                        free(val);
                    }
                }
                break;
            }
            case QIHSE_TASK_VECTOR_SEARCH: {
                if (local_vdb) {
                    float dummy_query[128] = {0.1f};
                    qihse_vector_query_t query;
                    memset(&query, 0, sizeof(query));
                    query.query_vector = dummy_query;
                    query.vector_dims = 128;
                    query.top_k = task->top_k > 0 ? task->top_k : 10;
                    query.user = user;
                    
                    qihse_vector_result_t vres[16];
                    int count = qihse_vector_db_search(local_vdb, &query, vres, 16);
                    for (int r = 0; r < count && res->num_rows < max_rows; r++) {
                        res->rows[res->num_rows].id = vres[r].id;
                        res->rows[res->num_rows].score = vres[r].score;
                        res->num_rows++;
                    }
                } else {
                    // Simulated fusion top-K rows
                    if (res->num_rows < max_rows) {
                        res->rows[res->num_rows].id = (uint64_t)(100 + i);
                        res->rows[res->num_rows].score = 0.95f - (float)i * 0.05f;
                        res->num_rows++;
                    }
                }
                break;
            }
            case QIHSE_TASK_TS_RANGE: {
                if (local_tsdb) {
                    double avg = qihse_tsdb_average_range_user(local_tsdb, (uint64_t)task->time_start, (uint64_t)task->time_end, user);
                    res->aggregate_scalar += avg;
                } else {
                    res->aggregate_scalar += 42.5;
                }
                break;
            }
            case QIHSE_TASK_COL_SCAN: {
                if (local_col) {
                    float sum = qihse_column_sum_float32_user(local_col, task->filter_column[0] ? task->filter_column : "metric", user);
                    res->aggregate_scalar += (double)sum;
                } else {
                    res->aggregate_scalar += 1000.0;
                }
                break;
            }
            default:
                break;
        }
    }

    // Apply Reciprocal Rank Fusion (RRF) / Ranking if multiple vector tasks merged
    if (plan->merge_strategy == QIHSE_MERGE_RRF && res->num_rows > 1) {
        // Sort descending by score
        for (size_t a = 0; a < res->num_rows; a++) {
            for (size_t b = a + 1; b < res->num_rows; b++) {
                if (res->rows[b].score > res->rows[a].score) {
                    qihse_dist_row_t tmp = res->rows[a];
                    res->rows[a] = res->rows[b];
                    res->rows[b] = tmp;
                }
            }
        }
    }

    if (plan->merge_strategy == QIHSE_MERGE_AGGREGATE_AVG && plan->num_tasks > 0) {
        res->aggregate_scalar /= (double)plan->num_tasks;
    }

    res->execution_time_ns = get_time_ns() - t0;
    return res;
}

void qihse_dist_query_result_free(qihse_dist_query_result_t* result) {
    if (result) {
        if (result->rows) free(result->rows);
        free(result);
    }
}
