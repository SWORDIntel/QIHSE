/**
 * QIHSE Anchor-Based Interpolation Search Algorithm
 *
 * Integrates native anchor-based interpolation search into QIHSE
 * for optimal performance on sorted data with learned interpolation points.
 *
 * Features:
 * - Smart anchor learning with usage tracking
 * - Memory-bounded anchor tables with LRU pruning
 * - Runtime CPU feature detection (AVX2/AVX512/AMX)
 * - Workload-specific optimization parameters
 * - SIMD-accelerated operations with graceful fallbacks
 */

#ifndef QIHSE_ANCHOR_H
#define QIHSE_ANCHOR_H

#include "../qihse.h"
#include "qihse_anchor_search.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * QIHSE ANCHOR SEARCH CONFIGURATION
 * ============================================================================ */

typedef struct {
    size_t max_anchors;         /* Maximum anchors to maintain (default: 16) */
    size_t min_anchors;         /* Minimum anchors before learning (default: 2) */
    double anchor_prune_threshold; /* Memory usage threshold for pruning (default: 0.8) */
    size_t memory_budget_mb;    /* Memory budget in MB (default: 8) */
    bool enable_learning;       /* Enable adaptive anchor learning (default: true) */
    size_t chunk_size;          /* SIMD chunk size (default: 4 for AVX2) */
    bool enable_simd;           /* Enable SIMD acceleration (default: true) */
    int workload_type;          /* DSMIL workload type (default: auto-detect) */
} qihse_anchor_config_t;

/* ============================================================================
 * QIHSE ANCHOR SEARCH STATISTICS
 * ============================================================================ */

typedef struct {
    /* Performance metrics */
    uint64_t searches_total;    /* Total searches performed */
    uint64_t searches_successful; /* Successful anchor-based searches */
    uint64_t classical_fallbacks; /* Times classical search was used */

    /* Anchor management */
    size_t anchors_current;     /* Current number of anchors */
    size_t anchors_learned;     /* Total anchors learned */
    size_t anchors_pruned;      /* Anchors pruned due to memory limits */

    /* Learning metrics */
    double avg_interpolation_error; /* Average interpolation prediction error */
    double anchor_hit_rate;     /* Percentage of searches using anchors */
    double speedup_vs_classical; /* Speedup over pure classical search */

    /* SIMD and hardware metrics */
    uint32_t cpu_features_detected; /* Bitmask of detected CPU features */
    double avg_search_time_ns;  /* Average search time in nanoseconds */
    size_t memory_used_bytes;   /* Current memory usage */

    /* Workload adaptation */
    int detected_workload_type; /* Auto-detected workload type */
    uint64_t workload_adaptations; /* Number of workload-specific optimizations */
} qihse_anchor_stats_t;

/* ============================================================================
 * QIHSE ANCHOR SEARCH API
 * ============================================================================ */

/**
 * @brief Initialize anchor search configuration with smart defaults
 *
 * @param config Configuration structure to initialize
 * @param array_size Size of the array to be searched
 * @return 0 on success, negative on error
 */
int qihse_anchor_config_init(
    qihse_anchor_config_t* config,
    size_t array_size
);

/**
 * @brief Create and initialize anchor search context
 *
 * @param config Anchor search configuration
 * @return Pointer to anchor search context, NULL on allocation failure
 */
void* qihse_anchor_create(const qihse_anchor_config_t* config);

/**
 * @brief Destroy anchor search context
 *
 * @param ctx Anchor search context to destroy
 */
void qihse_anchor_destroy(void* ctx);

/**
 * @brief Perform anchor-based interpolation search
 *
 * Searches for 'query' in the sorted array 'data' using learned anchor points
 * for optimal interpolation prediction. Falls back to classical search if
 * anchors cannot provide better performance.
 *
 * @param ctx Anchor search context
 * @param data Sorted array to search in
 * @param n Number of elements in array
 * @param query Value to search for
 * @param table Anchor table for learning (can be NULL)
 * @return Index of found element, or NOT_STISLA_NOT_FOUND if not found
 */
not_stisla_result_t qihse_anchor_search(
    void* ctx,
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table
);

/**
 * @brief Batch anchor-based search for multiple queries
 *
 * @param ctx Anchor search context
 * @param data Sorted array to search in
 * @param n Number of elements in array
 * @param queries Array of query values
 * @param num_queries Number of queries
 * @param results Output array for results
 * @param table Anchor table for learning
 * @return Number of queries found
 */
size_t qihse_anchor_batch_search(
    void* ctx,
    const void* data,
    size_t n,
    const void* queries,
    size_t num_queries,
    not_stisla_result_t* results,
    not_stisla_anchor_table_t* table
);

/**
 * @brief Get anchor search statistics
 *
 * @param ctx Anchor search context
 * @param stats Statistics structure to fill
 * @return 0 on success, negative if no stats available
 */
int qihse_anchor_get_stats(
    const void* ctx,
    qihse_anchor_stats_t* stats
);

/**
 * @brief Reset anchor search statistics
 *
 * @param ctx Anchor search context
 */
void qihse_anchor_reset_stats(void* ctx);

/**
 * @brief Detect optimal workload type for anchor search
 *
 * Analyzes data patterns to determine the best anchor search strategy.
 *
 * @param data Sample data array
 * @param n Number of elements in sample
 * @param data_type QIHSE data type
 * @return Recommended workload type (NOT_STISLA_WORKLOAD_*)
 */
int qihse_anchor_detect_workload(
    const void* data,
    size_t n,
    qihse_data_type_t data_type
);

/**
 * @brief Optimize anchor configuration for specific workload
 *
 * @param config Configuration to optimize
 * @param workload_type Workload type (NOT_STISLA_WORKLOAD_*)
 * @return 0 on success, negative on error
 */
int qihse_anchor_optimize_for_workload(
    qihse_anchor_config_t* config,
    int workload_type
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_ANCHOR_H */
