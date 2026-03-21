#define _GNU_SOURCE
#include "qihse.h"
#include "qihse_search.h"
#include "qihse_math.h"
#include "qihse_instr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <math.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ============================================================================
 * CONFIGURATION AND INITIALIZATION
 * ============================================================================ */

int qihse_config_init(
    qihse_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size
) {
    if (!config) return -1;
    memset(config, 0, sizeof(qihse_config_t));
    config->data_type = data_type;
    config->anchor_config.max_anchors = NOT_STISLA_MAX_ANCHORS;
    config->anchor_config.min_anchors = NOT_STISLA_MIN_ANCHORS;
    config->anchor_config.anchor_prune_threshold = NOT_STISLA_ANCHOR_PRUNE_THRESHOLD;
    config->anchor_config.memory_budget_mb = NOT_STISLA_MEMORY_BUDGET_MB;
    config->anchor_config.enable_anchor_learning = true;
    config->anchor_config.enable_anchor_simd = true;
    config->anchor_config.workload_type = 0; /* Default */

    config->auto_dimensions = true;
    config->fixed_dimensions = 256;
    config->max_dimensions = QIHSE_MAX_DIMENSIONS;
    config->min_dimensions = QIHSE_MIN_DIMENSIONS;
    config->type_descriptor.type = data_type;
    config->type_descriptor.element_size = 8;
    config->rff_gamma = 1.0 / array_size;
    config->random_seed = 42;
    qihse_amplification_config_init(&config->amplification, array_size);
    qihse_verify_config_init(&config->verification, 0.9999);
    config->use_heterogeneous = true;
    config->max_batch_size = 65536;
    config->timeout_ms = QIHSE_DEFAULT_TIMEOUT_MS;
    return 0;
}

/* ============================================================================
 * VERSION INFORMATION
 * ============================================================================ */

const char* qihse_version(void) {
    return "QIHSE 1.0.0";
}

const char* qihse_build_info(void) {
    return "QIHSE Build: Modularized Heterogeneous Compute";
}

bool qihse_available(void) {
    return qihse_detect_avx2() || qihse_detect_avx512();
}

/* ============================================================================
 * PARALLEL PIPELINE ORCHESTRATION
 * ============================================================================ */

static void* qihse_pipeline_worker(void* arg) {
    qihse_pipeline_worker_arg_t* worker_arg = (qihse_pipeline_worker_arg_t*)arg;
    uint64_t start = ns_now();
    qihse_config_t config;
    if (qihse_config_init(&config, worker_arg->data_type, worker_arg->n) == 0) {
        config.fixed_dimensions = worker_arg->pipeline_config->dimensions;
        config.auto_dimensions = false;
        config.verification.mode = (worker_arg->pipeline_config->type == QIHSE_PIPELINE_FAST) ? QIHSE_VERIFY_FAST : QIHSE_VERIFY_FALLBACK;
        not_stisla_result_t result = qihse_search(worker_arg->data, worker_arg->n, worker_arg->query, worker_arg->table, &config);
        worker_arg->pipeline_result->completed = true;
        worker_arg->pipeline_result->success = (result != NOT_STISLA_NOT_FOUND);
        if (worker_arg->pipeline_result->success) {
            worker_arg->pipeline_result->result.predicted_index = result;
            worker_arg->pipeline_result->result.confidence = 0.9;
        }
    }
    worker_arg->pipeline_result->execution_time_ns = ns_now() - start;
    return NULL;
}

int qihse_execute_parallel_pipelines(const void* data, size_t n, const void* query, not_stisla_anchor_table_t* table, const qihse_pipeline_config_t* configs, size_t num_configs, qihse_parallel_result_t* result) {
    if (!data || !query || !configs || !result || num_configs == 0) return -EINVAL;
    memset(result, 0, sizeof(qihse_parallel_result_t));
    result->num_pipelines = num_configs;
    result->pipelines = calloc(num_configs, sizeof(qihse_pipeline_result_t));
    if (!result->pipelines) return -ENOMEM;

    uint64_t total_start = ns_now();
    for (size_t i = 0; i < num_configs; i++) {
        qihse_pipeline_worker_arg_t arg = {data, n, query, table, QIHSE_TYPE_INT64, &configs[i], &result->pipelines[i]};
        qihse_pipeline_worker(&arg);
        if (result->pipelines[i].success && configs[i].early_exit && result->pipelines[i].result.confidence >= configs[i].confidence_threshold) break;
    }
    result->total_time_ns = ns_now() - total_start;
    return num_configs; /* Return the number of pipelines processed */
}


/* ============================================================================
 * PARALLEL PIPELINE INITIALIZATION
 * ============================================================================ */

size_t qihse_init_parallel_pipelines(qihse_pipeline_config_t* configs, size_t max_configs, qihse_data_type_t data_type, size_t array_size) {
    if (!configs || max_configs == 0) { return 0; }
    size_t num = 0;
    for (size_t i = 0; i < max_configs; ++i) {
        configs[i].type = QIHSE_PIPELINE_BALANCED; // Default to balanced pipeline
        configs[i].dimensions = 256; // Default dimensions
        configs[i].confidence_threshold = 0.9;
        configs[i].early_exit = false;
        configs[i].priority = 100;
        configs[i].timeout_ms = QIHSE_DEFAULT_TIMEOUT_MS;
        configs[i].pipeline_data = NULL;
        num++;
    }
    return num; // Return the number of initialized configurations
}

/* ============================================================================
 * MAIN QIHSE SEARCH ORCHESTRATION
 * ============================================================================ */

not_stisla_result_t qihse_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
) {
    if (!data || !query || !config || n == 0) return NOT_STISLA_NOT_FOUND;

    qihse_init_global_optimization();
    static bool hw_detected = false;
    if (!hw_detected) {
        qihse_intel_hw_info_t info;
        if (qihse_intel_detect_hardware(&info) == 0) {
            uint32_t f = 0;
            if (info.available_features & QIHSE_INTEL_HW_AVX512) f |= QIHSE_INTEL_HW_AVX512;
            if (info.available_features & QIHSE_INTEL_HW_AMX) f |= QIHSE_INTEL_HW_AMX;
            qihse_intel_enable_features(f);
        }
        qihse_power_config_t pc = {QIHSE_FREQ_MODE_ADAPTIVE, 0, 1000, 4500, 125, true, false, 50};
        qihse_power_init(&pc);
        qihse_math_config_t mc = {QIHSE_MATH_PRECISION_MEDIUM, true, true, true, 64, true};
        qihse_math_init(&mc);
        hw_detected = true;
    }

    qihse_workload_characteristics_t w;
    qihse_power_analyze_workload(&w);
    qihse_power_adaptive_scaling(&w);

    qihse_data_signature_t ds = {0, n, config->data_type, 0.5, 1.0};
    qihse_config_t opt_config = *config;
    qihse_get_optimized_config(&g_optimization_db, &ds, &opt_config);
    qihse_get_anchor_optimized_config(&g_optimization_db, &ds, &opt_config);

    qihse_optimization_entry_t* entry = qihse_get_entry(&g_optimization_db, &ds);
    qihse_algorithm_selection_t algo = qihse_select_algorithm(&ds, entry, n, opt_config.anchor_config.workload_type);

    if (algo == QIHSE_ALGO_HYBRID_BALANCED) {
        qihse_hybrid_result_t hr = qihse_execute_hybrid_search(data, n, query, table, &opt_config);
        return hr.final_result;
    } else if (algo == QIHSE_ALGO_ANCHOR_ONLY && table) {
        return not_stisla_search((const int64_t*)data, n, *(const int64_t*)query, table, 8);
    }

    /* Core QIHSE algorithm logic */
    uint64_t start = ns_now();
    double* h_data = malloc(n * sizeof(double));
    if (!h_data) return NOT_STISLA_NOT_FOUND;
    double qv = 0;
    if (config->data_type == QIHSE_TYPE_INT64) {
        qv = (double)*(const int64_t*)query;
        for (size_t i = 0; i < n; i++) h_data[i] = (double)((const int64_t*)data)[i];
    } else if (config->data_type == QIHSE_TYPE_DOUBLE) {
        qv = *(const double*)query;
        memcpy(h_data, data, n * sizeof(double));
    }

    size_t h_dims = opt_config.auto_dimensions ? (size_t)(log2((double)n) * 4.0) : opt_config.fixed_dimensions;
    if (h_dims < 64) h_dims = 64;
    if (h_dims > 2048) h_dims = 2048;

    qihse_rff_kernel_t* kernel = qihse_rff_create(1, h_dims, opt_config.rff_gamma, opt_config.random_seed);
    double* h_expanded = malloc(n * h_dims * sizeof(double));
    for (size_t i = 0; i < n; i++) qihse_rff_project(kernel, &h_data[i], &h_expanded[i * h_dims]);

    qihse_superposition_t sup;
    qihse_create_superposition(h_expanded, n, h_dims, &sup);

    qihse_amplification_config_t ac;
    qihse_amplification_config_init(&ac, n);
    qihse_adaptive_amplify(&sup, &qv, QIHSE_TYPE_DOUBLE, &ac);

    qihse_collapse_result_t cr = qihse_dimensional_collapse_l2_norm(&sup);
    not_stisla_result_t res = qihse_verify_result(data, n, query, config->data_type, &cr, &config->verification);

    qihse_record_performance(&g_optimization_db, &ds, QIHSE_PIPELINE_ACCURATE, h_dims, 1.0, cr.confidence);

    qihse_destroy_superposition(&sup);
    free(h_expanded);
    qihse_rff_destroy(kernel);
    free(h_data);

    return res;
}

size_t qihse_batch_search(const void* data, size_t n, const void* queries, size_t num_queries, not_stisla_result_t* results, not_stisla_anchor_table_t* table, const qihse_config_t* config) {
    size_t found = 0;
    for (size_t i = 0; i < num_queries; i++) {
        void* qp = (config->data_type == QIHSE_TYPE_INT64) ? (void*)&((int64_t*)queries)[i] : (void*)&((double*)queries)[i];
        results[i] = qihse_search(data, n, qp, table, config);
        if (results[i] != NOT_STISLA_NOT_FOUND) found++;
    }
    return found;
}

int qihse_get_performance_stats(qihse_performance_stats_t* stats) {
    if (!stats) return -EINVAL;
    memset(stats, 0, sizeof(*stats));
    qihse_record_anchor_search(false, 0, 0); /* Trick to update stats if needed */
    return 0;
}

void qihse_reset_performance_stats(void) {}
