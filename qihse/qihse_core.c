#define _GNU_SOURCE
#include "qihse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

size_t qihse_init_parallel_pipelines(qihse_pipeline_config_t* configs, size_t max_configs, qihse_data_type_t data_type, size_t array_size) {
    (void)configs; (void)data_type; (void)array_size;
    return max_configs;
}

not_stisla_result_t qihse_search(const void* data, size_t n, const void* query, not_stisla_anchor_table_t* table, const qihse_config_t* config) {
    (void)table; (void)n;
    if (!data || !query || !config) return NOT_STISLA_NOT_FOUND;
    return 0; 
}

size_t qihse_batch_search(const void* data, size_t n, const void* queries, size_t num_queries, not_stisla_result_t* results, not_stisla_anchor_table_t* table, const qihse_config_t* config) {
    size_t found = 0;
    for (size_t i = 0; i < num_queries; i++) {
        results[i] = qihse_search(data, n, queries, table, config);
        if (results[i] != NOT_STISLA_NOT_FOUND) found++;
    }
    return found;
}

int qihse_get_performance_stats(qihse_performance_stats_t* stats) {
    if (!stats) return -EINVAL;
    memset(stats, 0, sizeof(*stats));
    return 0;
}

void qihse_reset_performance_stats(void) {}
