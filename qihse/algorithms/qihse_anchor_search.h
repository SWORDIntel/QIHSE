/**
 * QIHSE native anchor search.
 *
 * This module integrates the upstream NOT_STISLA interpolation/anchor-search
 * engine directly into QIHSE. The not_stisla_* symbols remain as compatibility
 * names for existing QIHSE call sites.
 */

#ifndef QIHSE_ANCHOR_SEARCH_H
#define QIHSE_ANCHOR_SEARCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Anchor and search tuning limits. */
#define NOT_STISLA_MAX_ANCHORS 1048576
#define NOT_STISLA_CHUNK_SIZE 4
#define NOT_STISLA_MIN_ANCHORS 2
#define NOT_STISLA_ANCHOR_PRUNE_THRESHOLD 0.8f
#define NOT_STISLA_MEMORY_BUDGET_MB 8

/* DSMIL workload types for optimization. */
enum not_stisla_workload_type {
    NOT_STISLA_WORKLOAD_TELEMETRY = 0,
    NOT_STISLA_WORKLOAD_IDS = 1,
    NOT_STISLA_WORKLOAD_OFFSETS = 2,
    NOT_STISLA_WORKLOAD_EVENTS = 3
};

typedef enum not_stisla_cpu_feature {
    NOT_STISLA_CPU_AVX2 = (1 << 0),
    NOT_STISLA_CPU_AVX512 = (1 << 1),
    NOT_STISLA_CPU_AMX = (1 << 2),
    NOT_STISLA_CPU_VNNI = (1 << 3),
    NOT_STISLA_CPU_NEON = (1 << 4),
    NOT_STISLA_CPU_SVE = (1 << 5),
    NOT_STISLA_CPU_SVE2 = (1 << 6),
    NOT_STISLA_CPU_I8MM = (1 << 7),
    NOT_STISLA_CPU_GRAVITON4 = (1 << 8)
} not_stisla_cpu_feature_t;

typedef struct {
    int64_t v;
    size_t i;
    uint32_t use_count;
    uint64_t last_used;
} not_stisla_anchor_t;

typedef struct not_stisla_stats {
    uint64_t searches_total;
    uint64_t searches_successful;
    uint64_t anchors_learned;
    uint64_t anchors_pruned;
    uint64_t memory_reallocations;
    double avg_search_time_ns;
    double avg_interpolation_error;
    uint32_t cpu_features_detected;
} not_stisla_stats_t;

typedef struct not_stisla_anchor_table {
    not_stisla_anchor_t* anchors;
    size_t capacity;
    size_t size;
    size_t max_capacity;
    size_t searches_performed;
    int workload_type;
    not_stisla_stats_t stats;
    uint64_t creation_time;
} not_stisla_anchor_table_t;

typedef size_t not_stisla_result_t;
#define NOT_STISLA_NOT_FOUND ((not_stisla_result_t)-1)

typedef struct not_stisla_batch_item {
    int64_t key;
    not_stisla_result_t result;
    size_t ordinal;
} not_stisla_batch_item_t;

typedef struct not_stisla_parallel_config {
    int num_threads;
    int use_thread_pool;
    size_t batch_chunk;
} not_stisla_parallel_config_t;

typedef enum not_stisla_backend {
    NOT_STISLA_BACKEND_AUTO = 0,
    NOT_STISLA_BACKEND_SCALAR,
    NOT_STISLA_BACKEND_C_BATCH,
    NOT_STISLA_BACKEND_C_OPENMP,
    NOT_STISLA_BACKEND_C_AVX2,
    NOT_STISLA_BACKEND_C_AVX512,
    NOT_STISLA_BACKEND_C_AMX,
    NOT_STISLA_BACKEND_FORTRAN
} not_stisla_backend_t;

typedef struct not_stisla_backend_decision {
    not_stisla_backend_t backend;
    uint32_t cpu_features;
    size_t array_size_bucket;
    size_t query_count_bucket;
    int thread_count;
    double estimated_ns_per_key;
    double p95_ns_per_key;
} not_stisla_backend_decision_t;

typedef struct not_stisla_performance_stats {
    uint64_t total_time_ns;
    uint64_t search_time_ns;
    uint64_t total_searches;
    uint64_t successful_searches;
    double avg_search_time_ns;
    double search_success_rate;
    double speedup_vs_binary;
    size_t peak_memory_usage;
    size_t avg_memory_usage;
    uint64_t anchors_learned;
    uint64_t anchors_pruned;
    uint32_t cpu_features_used;
    double vectorization_efficiency;
    uint64_t memory_allocation_failures;
} not_stisla_performance_stats_t;

typedef enum not_stisla_error {
    NOT_STISLA_SUCCESS = 0,
    NOT_STISLA_ERROR_INVALID_PARAM = -1,
    NOT_STISLA_ERROR_MEMORY = -2,
    NOT_STISLA_ERROR_NOT_FOUND = -3,
    NOT_STISLA_ERROR_CONFIG = -7,
    NOT_STISLA_ERROR_CPU_FEATURE = -8
} not_stisla_error_t;

typedef struct not_stisla_config {
    size_t tol;
    int enable_anchor_learning;
    size_t max_anchors;
    int workload_type;
    int enable_simd;
    uint32_t force_cpu_features;
    int enable_profiling;
    int strict_mode;
} not_stisla_config_t;

not_stisla_anchor_table_t* not_stisla_anchor_table_create(void);
void not_stisla_anchor_table_destroy(not_stisla_anchor_table_t* table);
size_t not_stisla_anchor_table_size(const not_stisla_anchor_table_t* table);
void not_stisla_anchor_table_reset(not_stisla_anchor_table_t* table);
const not_stisla_stats_t* not_stisla_anchor_table_get_stats(const not_stisla_anchor_table_t* table);
int not_stisla_anchor_table_set_memory_limit(not_stisla_anchor_table_t* table, size_t max_anchors);
int not_stisla_anchor_table_optimize_for_workload(not_stisla_anchor_table_t* table, int workload_type);

uint32_t not_stisla_detect_cpu_features(void);

int not_stisla_get_performance_stats(not_stisla_performance_stats_t* stats);
void not_stisla_reset_performance_stats(void);
void not_stisla_set_performance_tracking(int enabled);
int not_stisla_is_performance_tracking_enabled(void);

const char* not_stisla_error_message(not_stisla_error_t error);

void not_stisla_config_init(not_stisla_config_t* config, int workload_type);
int not_stisla_config_validate(const not_stisla_config_t* config);
void not_stisla_config_optimize_for_workload(not_stisla_config_t* config, int workload_type);
void not_stisla_get_tuned_config(size_t array_size, not_stisla_config_t* config);

not_stisla_result_t not_stisla_search(
    const int64_t* arr,
    size_t n,
    int64_t key,
    not_stisla_anchor_table_t* table,
    size_t tol
);

not_stisla_result_t not_stisla_search_enhanced(
    const int64_t* arr,
    size_t n,
    int64_t key,
    not_stisla_anchor_table_t* table,
    const not_stisla_config_t* config
);

size_t not_stisla_search_batch(
    const int64_t* arr,
    size_t n,
    not_stisla_batch_item_t* items,
    size_t num_items,
    not_stisla_anchor_table_t* table,
    size_t tol
);

size_t not_stisla_search_parallel(
    const int64_t* arr,
    size_t n,
    not_stisla_batch_item_t* items,
    size_t num_items,
    not_stisla_anchor_table_t* table,
    size_t tol,
    const not_stisla_parallel_config_t* config
);

size_t not_stisla_search_batch_auto(
    const int64_t* arr,
    size_t n,
    not_stisla_batch_item_t* items,
    size_t num_items,
    not_stisla_anchor_table_t* table,
    size_t tol,
    const not_stisla_parallel_config_t* config
);

int not_stisla_get_last_backend_decision(not_stisla_backend_decision_t* decision);

int not_stisla_fortran_backend_available(void);

size_t not_stisla_search_batch_fortran(
    const int64_t* arr,
    size_t n,
    not_stisla_batch_item_t* items,
    size_t num_items
);

size_t not_stisla_search_batch_c_optimized(
    const int64_t* arr,
    size_t n,
    not_stisla_batch_item_t* items,
    size_t num_items,
    not_stisla_anchor_table_t* table,
    size_t tol
);

void not_stisla_get_stats(
    const not_stisla_anchor_table_t* table,
    size_t* searches_total,
    size_t* anchors_learned,
    size_t* memory_used_bytes
);

not_stisla_result_t not_stisla_search_telemetry(
    const int64_t* timestamps,
    size_t n,
    int64_t target_time,
    not_stisla_anchor_table_t* table
);

not_stisla_result_t not_stisla_search_ids(
    const int64_t* ids,
    size_t n,
    int64_t target_id,
    not_stisla_anchor_table_t* table
);

not_stisla_result_t not_stisla_search_offsets(
    const int64_t* offsets,
    size_t n,
    int64_t target_offset,
    not_stisla_anchor_table_t* table
);

not_stisla_result_t not_stisla_search_events(
    const int64_t* events,
    size_t n,
    int64_t target_time,
    not_stisla_anchor_table_t* table
);

bool not_stisla_init_for_dsmil(not_stisla_anchor_table_t* table, int workload_type);
int not_stisla_optimize_array_memory(const int64_t* arr, size_t n);

#define NOT_STISLA_VERSION_MAJOR 1
#define NOT_STISLA_VERSION_MINOR 0
#define NOT_STISLA_VERSION_PATCH 0

const char* not_stisla_version(void);
const char* not_stisla_build_info(void);
bool enhanced_available(void);
const char* enhanced_build_info(void);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_ANCHOR_SEARCH_H */
