/**
 * QIHSE True Parallel Processing
 *
 * Beyond first-past-the-post: Process ALL candidate results in parallel
 * and optimally combine them using advanced mathematical techniques.
 */

#ifndef QIHSE_PARALLEL_H
#define QIHSE_PARALLEL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse.h"

/* ============================================================================
 * PARALLEL RESULT PROCESSING
 * ============================================================================ */

/**
 * Parallel result candidate from any processing unit
 */
typedef struct {
    size_t candidate_index;         /* Index in original data array */
    double confidence_score;        /* Confidence/probability (0.0-1.0) */
    double phase_angle;             /* Quantum phase information */
    uint32_t processing_unit_id;    /* Which unit produced this result */
    uint64_t timestamp_ns;          /* When result was produced */
    void* auxiliary_data;           /* Unit-specific additional data */
} qihse_parallel_result_t;

/**
 * Parallel result set from all processing units
 */
typedef struct {
    qihse_parallel_result_t* results;
    size_t num_results;
    size_t max_results;
    bool sorted_by_confidence;      /* True if sorted by confidence descending */

    /* Aggregation metadata */
    double total_confidence_sum;    /* Sum of all confidence scores */
    double max_confidence;          /* Highest confidence score */
    double mean_confidence;         /* Average confidence score */
    double confidence_stddev;       /* Standard deviation of confidence */

    /* Timing information */
    uint64_t earliest_timestamp;
    uint64_t latest_timestamp;
    uint64_t aggregation_time_ns;
} qihse_parallel_result_set_t;

/* ============================================================================
 * ADVANCED RESULT AGGREGATION METHODS
 * ============================================================================ */

typedef enum {
    QIHSE_AGGREGATE_FIRST_PAST_POST,    /* Winner takes all (current) */
    QIHSE_AGGREGATE_WEIGHTED_VOTING,    /* Weighted by confidence */
    QIHSE_AGGREGATE_PHASE_INTERFERENCE, /* Quantum interference model */
    QIHSE_AGGREGATE_BAYESIAN_FUSION,    /* Bayesian probability fusion */
    QIHSE_AGGREGATE_NEURAL_COMBINATION, /* Neural network combination */
    QIHSE_AGGREGATE_ADAPTIVE_ENSEMBLE,  /* Adaptive ensemble method */
} qihse_aggregation_method_t;

/**
 * Aggregation configuration
 */
typedef struct {
    qihse_aggregation_method_t method;
    size_t max_candidates;          /* Maximum candidates to consider */
    double confidence_threshold;    /* Minimum confidence to include */
    bool use_phase_information;     /* Include quantum phase in aggregation */
    bool normalize_confidence;      /* Normalize confidence scores */
    bool apply_temporal_weighting;  /* Weight by result timestamp */

    /* Method-specific parameters */
    union {
        struct {
            double phase_decay;     /* Phase interference decay factor */
            double interference_strength; /* Interference coupling strength */
        } phase_interference;

        struct {
            double prior_strength;  /* Bayesian prior strength */
            double evidence_weight; /* Evidence weighting factor */
        } bayesian_fusion;

        struct {
            size_t ensemble_size;   /* Number of models in ensemble */
            double learning_rate;   /* Neural adaptation rate */
        } neural_combination;
    } params;
} qihse_aggregation_config_t;

/* ============================================================================
 * PARALLEL PROCESSING PIPELINE
 * ============================================================================ */

/**
 * Parallel processing pipeline stage
 */
typedef struct qihse_pipeline_stage_t qihse_pipeline_stage_t;

typedef int (*qihse_stage_processor_t)(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    void* stage_context
);

struct qihse_pipeline_stage_t {
    char stage_name[64];
    qihse_stage_processor_t processor;
    void* context;
    qihse_pipeline_stage_t* next_stage;
};

/**
 * Complete parallel processing pipeline
 */
typedef struct {
    qihse_pipeline_stage_t* first_stage;
    qihse_pipeline_stage_t* last_stage;
    size_t num_stages;

    /* Pipeline configuration */
    bool parallel_execution;        /* Execute stages in parallel when possible */
    size_t max_concurrent_stages;   /* Maximum parallel stages */
    uint64_t pipeline_timeout_ns;   /* Maximum pipeline execution time */

    /* Performance monitoring */
    uint64_t total_executions;
    uint64_t total_time_ns;
    double avg_stage_time_ns;
} qihse_parallel_pipeline_t;

/* ============================================================================
 * TRUE PARALLEL RESULT MERGER
 * ============================================================================ */

/**
 * Advanced result merger that processes all candidates simultaneously
 */
typedef struct {
    qihse_parallel_result_set_t* input_results;
    qihse_aggregation_config_t config;

    /* Processing state */
    void* intermediate_buffer;      /* For complex aggregations */
    size_t buffer_size;

    /* Hardware acceleration */
    bool use_npu_acceleration;      /* Use NPU for aggregation */
    bool use_gpu_acceleration;      /* Use GPU for aggregation */
    void* accelerator_context;

    /* Result caching */
    qihse_parallel_result_t* cached_results;
    size_t cache_size;
    uint64_t cache_timestamp;
} qihse_parallel_merger_t;

/* ============================================================================
 * PARALLEL PROCESSING API
 * ============================================================================ */

/**
 * Initialize parallel result set
 */
qihse_parallel_result_set_t* qihse_parallel_result_set_init(size_t max_results);

/**
 * Destroy parallel result set
 */
void qihse_parallel_result_set_destroy(qihse_parallel_result_set_t* set);

/**
 * Add result to parallel result set
 */
int qihse_parallel_result_set_add(
    qihse_parallel_result_set_t* set,
    size_t candidate_index,
    double confidence_score,
    double phase_angle,
    uint32_t processing_unit_id
);

/**
 * Sort result set by confidence (descending)
 */
void qihse_parallel_result_set_sort(qihse_parallel_result_set_t* set);

/**
 * Initialize result merger with aggregation method
 */
qihse_parallel_merger_t* qihse_parallel_merger_init(
    const qihse_aggregation_config_t* config
);

/**
 * Destroy result merger
 */
void qihse_parallel_merger_destroy(qihse_parallel_merger_t* merger);

/**
 * Merge parallel results using advanced aggregation
 */
int qihse_parallel_merger_combine(
    qihse_parallel_merger_t* merger,
    const qihse_parallel_result_set_t* input_results,
    qihse_parallel_result_set_t* output_results
);

/* ============================================================================
 * ADVANCED AGGREGATION METHODS
 * ============================================================================ */

/**
 * Weighted voting aggregation (improved first-past-the-post)
 */
int qihse_aggregate_weighted_voting(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/**
 * Quantum phase interference model aggregation
 */
int qihse_aggregate_phase_interference(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/**
 * Bayesian probability fusion aggregation
 */
int qihse_aggregate_bayesian_fusion(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/**
 * Neural network combination aggregation
 */
int qihse_aggregate_neural_combination(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/**
 * Adaptive ensemble method aggregation
 */
int qihse_aggregate_adaptive_ensemble(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/* ============================================================================
 * PIPELINE PROCESSING
 * ============================================================================ */

/**
 * Create parallel processing pipeline
 */
qihse_parallel_pipeline_t* qihse_parallel_pipeline_create(void);

/**
 * Destroy parallel processing pipeline
 */
void qihse_parallel_pipeline_destroy(qihse_parallel_pipeline_t* pipeline);

/**
 * Add processing stage to pipeline
 */
int qihse_parallel_pipeline_add_stage(
    qihse_parallel_pipeline_t* pipeline,
    const char* stage_name,
    qihse_stage_processor_t processor,
    void* context
);

/**
 * Execute parallel processing pipeline
 */
int qihse_parallel_pipeline_execute(
    qihse_parallel_pipeline_t* pipeline,
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output
);

/* ============================================================================
 * HARDWARE-ACCELERATED AGGREGATION
 * ============================================================================ */

/**
 * Initialize NPU-accelerated aggregation
 */
int qihse_npu_aggregation_init(qihse_parallel_merger_t* merger);

/**
 * Perform NPU-accelerated result aggregation
 */
int qihse_npu_aggregate_results(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/**
 * Initialize GPU-accelerated aggregation
 */
int qihse_gpu_aggregation_init(qihse_parallel_merger_t* merger);

/**
 * Perform GPU-accelerated result aggregation
 */
int qihse_gpu_aggregate_results(
    const qihse_parallel_result_set_t* input,
    qihse_parallel_result_set_t* output,
    const qihse_aggregation_config_t* config
);

/* ============================================================================
 * PERFORMANCE MONITORING
 * ============================================================================ */

/**
 * Parallel processing performance statistics
 */
typedef struct {
    uint64_t total_aggregation_time_ns;
    uint64_t num_aggregations;
    double avg_aggregation_time_ns;
    double min_aggregation_time_ns;
    double max_aggregation_time_ns;

    /* Per-method statistics */
    struct {
        uint64_t calls;
        uint64_t total_time_ns;
        double avg_time_ns;
        double success_rate;
    } method_stats[QIHSE_AGGREGATE_ADAPTIVE_ENSEMBLE + 1];

    /* Hardware acceleration stats */
    uint64_t npu_accelerated_calls;
    uint64_t gpu_accelerated_calls;
    uint64_t cpu_fallback_calls;
} qihse_parallel_stats_t;

/**
 * Get parallel processing performance statistics
 */
int qihse_parallel_get_stats(qihse_parallel_stats_t* stats);

/**
 * Reset parallel processing performance statistics
 */
void qihse_parallel_reset_stats(void);

/* ============================================================================
 * INTEGRATION WITH QIHSE MAIN API
 * ============================================================================ */

/**
 * Enhanced QIHSE search with true parallel processing
 */
not_stisla_result_t qihse_parallel_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config,
    qihse_parallel_merger_t* merger
);

/**
 * Enhanced QIHSE batch search with true parallel processing
 */
size_t qihse_parallel_batch_search(
    const void* data,
    size_t n,
    const void* queries,
    size_t num_queries,
    not_stisla_result_t* results,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config,
    qihse_parallel_merger_t* merger
);

#endif /* QIHSE_PARALLEL_H */
