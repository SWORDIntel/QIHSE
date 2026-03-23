/*
 * QIHSE - Verification and Accuracy Modes
 *
 * Multi-level verification system for approximate/probabilistic search.
 * Provides configurable accuracy guarantees with performance trade-offs.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_VERIFICATION_H
#define QIHSE_VERIFICATION_H

#include <stddef.h>
#include <stdint.h>
#include "qihse_rff.h"
#include "../backends/cpu/qihse_cpu_detect.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VERIFICATION MODES
 * ============================================================================ */

/**
 * Verification modes for different accuracy/performance trade-offs.
 */
typedef enum qihse_verification_mode_e {
    QIHSE_VERIFY_NONE = 0,      /* No verification - maximum performance */
    QIHSE_VERIFY_FAST = 1,      /* Fast verification with consistency checks */
    QIHSE_VERIFY_WINDOW = 2,    /* Window-based verification with rolling checks */
    QIHSE_VERIFY_FALLBACK = 3,  /* Fallback verification with retry logic */
    QIHSE_VERIFY_EXACT = 4,     /* Exact verification - maximum accuracy */
    QIHSE_VERIFY_PRECISION = 5  /* NEW: Precision search mode (90%+ required) */
} qihse_verification_mode_t;

/* ============================================================================
 * VERIFICATION CONFIGURATION
 * ============================================================================ */

/**
 * Verification configuration structure.
 */
typedef struct qihse_verification_config_s {
    qihse_verification_mode_t mode;      /* Verification mode */
    double confidence_threshold;         /* Minimum confidence required (0.0-1.0) */
    size_t max_retries;                  /* Maximum verification retries */
    double tolerance;                    /* Numerical tolerance for comparisons */
    int enable_fallback;                 /* Enable fallback to higher verification */
    double performance_budget;           /* Performance budget for verification (%) */
    size_t window_size;                  /* Window size for rolling verification */
    int adaptive_verification;           /* Enable adaptive verification level */
} qihse_verification_config_t;

/**
 * Initialize verification config with defaults for given mode.
 *
 * @param config Config to initialize
 * @param mode Verification mode
 */
void qihse_verification_config_init(
    qihse_verification_config_t* config,
    qihse_verification_mode_t mode
);

/* ============================================================================
 * VERIFICATION RESULTS
 * ============================================================================ */

/**
 * Verification result structure.
 */
typedef struct qihse_verification_result_s {
    int is_valid;               /* 1 if verification passed, 0 if failed */
    double confidence;          /* Confidence score (0.0-1.0) */
    double accuracy;            /* Measured accuracy (0.0-1.0) */
    size_t verification_time_us; /* Time spent on verification */
    size_t retries_used;        /* Number of retries performed */
    qihse_verification_mode_t mode_used; /* Verification mode actually used */
    char* error_message;        /* Error message if verification failed */
    void* detailed_metrics;     /* Backend-specific metrics */
} qihse_verification_result_t;

/**
 * Initialize verification result.
 *
 * @param result Result to initialize
 */
void qihse_verification_result_init(qihse_verification_result_t* result);

/**
 * Destroy verification result and free resources.
 *
 * @param result Result to destroy
 */
void qihse_verification_result_destroy(qihse_verification_result_t* result);

/* ============================================================================
 * VERIFICATION OPERATIONS
 * ============================================================================ */

/**
 * Verify search result accuracy.
 *
 * Performs verification according to the configured mode.
 *
 * @param query Original query data
 * @param result Search result to verify
 * @param ground_truth Ground truth for verification (if available)
 * @param config Verification configuration
 * @param verification_result Output verification result
 * @return 0 on successful verification, negative error code on failure
 */
int qihse_verify_result_advanced(
    const void* query,
    const void* result,
    const void* ground_truth,
    const qihse_verification_config_t* config,
    qihse_verification_result_t* verification_result
);

/**
 * Verify batch of search results.
 *
 * @param queries Array of query data
 * @param results Array of search results
 * @param ground_truths Array of ground truths (can be NULL)
 * @param batch_size Number of items to verify
 * @param config Verification configuration
 * @param verification_results Output verification results [batch_size]
 * @return 0 on success, negative error code on failure
 */
int qihse_verify_batch(
    const void* const* queries,
    const void* const* results,
    const void* const* ground_truths,
    size_t batch_size,
    const qihse_verification_config_t* config,
    qihse_verification_result_t* verification_results
);

/* ============================================================================
 * ADAPTIVE VERIFICATION
 * ============================================================================ */

/**
 * Adaptive verification controller.
 */
typedef struct qihse_adaptive_verifier_s {
    qihse_verification_mode_t current_mode; /* Current verification mode */
    double target_confidence;    /* Target confidence level */
    double performance_budget;   /* Available performance budget */
    size_t window_size;          /* Rolling window size for adaptation */
    double adaptation_rate;      /* How quickly to adapt verification level */

    /* Internal state for adaptation */
    double recent_confidence;    /* Recent confidence measurements */
    double recent_performance;   /* Recent performance measurements */
    size_t samples_collected;    /* Number of samples collected */
    void* internal_state;        /* Backend-specific state */
} qihse_adaptive_verifier_t;

/**
 * Initialize adaptive verifier.
 *
 * @param verifier Verifier to initialize
 * @param initial_mode Initial verification mode
 * @param target_confidence Target confidence level
 * @param performance_budget Performance budget as fraction (0.0-1.0)
 * @return 0 on success, negative error code on failure
 */
int qihse_adaptive_verifier_init(
    qihse_adaptive_verifier_t* verifier,
    qihse_verification_mode_t initial_mode,
    double target_confidence,
    double performance_budget
);

/**
 * Destroy adaptive verifier.
 *
 * @param verifier Verifier to destroy
 */
void qihse_adaptive_verifier_destroy(qihse_adaptive_verifier_t* verifier);

/**
 * Adapt verification level based on performance feedback.
 *
 * @param verifier Adaptive verifier
 * @param verification_result Recent verification result
 * @param query_time_us Time spent on query (excluding verification)
 * @return Recommended verification mode for next operation
 */
qihse_verification_mode_t qihse_adaptive_verifier_adapt(
    qihse_adaptive_verifier_t* verifier,
    const qihse_verification_result_t* verification_result,
    size_t query_time_us
);

/**
 * Get current verification statistics.
 *
 * @param verifier Adaptive verifier
 * @param avg_confidence Output average confidence
 * @param avg_performance Output average performance
 * @param mode_distribution Output mode usage distribution
 */
void qihse_adaptive_verifier_get_stats(
    const qihse_adaptive_verifier_t* verifier,
    double* avg_confidence,
    double* avg_performance,
    double mode_distribution[5] /* One for each verification mode */
);

/* ============================================================================
 * VERIFICATION UTILITIES
 * ============================================================================ */

/**
 * Calculate verification overhead for given mode.
 *
 * @param mode Verification mode
 * @param problem_size Size of search problem
 * @return Estimated overhead as fraction of total query time (0.0-1.0)
 */
double qihse_estimate_verification_overhead(
    qihse_verification_mode_t mode,
    size_t problem_size
);

/**
 * Get human-readable verification mode name.
 *
 * @param mode Verification mode
 * @return Mode name string
 */
const char* qihse_verification_mode_name(qihse_verification_mode_t mode);

/**
 * Validate verification configuration.
 *
 * @param config Configuration to validate
 * @return 1 if valid, 0 if invalid
 */
int qihse_verification_config_validate(const qihse_verification_config_t* config);

/* ============================================================================
 * ENHANCED SIMILARITY CALCULATIONS - HARDWARE ACCELERATED & QUANTUM-INSPIRED
 * ============================================================================ */

/**
 * AVX512-accelerated cosine similarity for full dataset.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @return Cosine similarity (0.0-1.0)
 */
double qihse_cosine_similarity_avx512(const float* result, const float* ground_truth, size_t data_size);

/**
 * AVX2-accelerated cosine similarity for full dataset.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @return Cosine similarity (0.0-1.0)
 */
double qihse_cosine_similarity_avx2(const float* result, const float* ground_truth, size_t data_size);

/**
 * Scalar cosine similarity fallback.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @return Cosine similarity (0.0-1.0)
 */
double qihse_cosine_similarity_scalar(const float* result, const float* ground_truth, size_t data_size);

/**
 * RFF-based Hilbert space similarity.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @param rff_kernel Initialized RFF kernel
 * @return RFF similarity (0.0-1.0)
 */
double qihse_rff_similarity(const float* result, const float* ground_truth, size_t data_size, qihse_rff_kernel_t* rff_kernel);

/**
 * Superposition fidelity similarity.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @return Superposition fidelity (0.0-1.0)
 */
double qihse_superposition_fidelity_similarity(const float* result, const float* ground_truth, size_t data_size);

/**
 * AMX tile-based matrix similarity.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @return AMX similarity (0.0-1.0)
 */
double qihse_amx_matrix_similarity(const float* result, const float* ground_truth, size_t data_size);

/**
 * Grover amplification similarity.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @param target_threshold Similarity threshold for target identification
 * @return Grover amplified similarity (0.0-1.0)
 */
double qihse_grover_amplified_similarity(const float* result, const float* ground_truth, size_t data_size, double target_threshold);

/**
 * Statistical distribution similarity.
 *
 * @param result Result vector
 * @param ground_truth Ground truth vector
 * @param data_size Number of elements
 * @return Statistical similarity (0.0-1.0)
 */
double qihse_statistical_similarity(const float* result, const float* ground_truth, size_t data_size);

/**
 * Comprehensive precision similarity using all available methods.
 *
 * @param result Result data
 * @param ground_truth Ground truth data
 * @param data_size Number of elements
 * @param cpu_features Available CPU features for method selection
 * @return Precision similarity (0.0-1.0)
 */
double qihse_calculate_precision_similarity(const void* result, const void* ground_truth, size_t data_size, qihse_cpu_feature_t cpu_features);

/**
 * Create ground truth for verification testing.
 *
 * Generates synthetic ground truth data for testing verification modes.
 *
 * @param query Query data
 * @param ground_truth Output ground truth buffer
 * @param buffer_size Size of ground truth buffer
 * @return 0 on success, negative error code on failure
 */
int qihse_generate_ground_truth(
    const void* query,
    void* ground_truth,
    size_t buffer_size
);

/* ============================================================================
 * VERIFICATION METRICS AND MONITORING
 * ============================================================================ */

/**
 * Verification metrics structure.
 */
typedef struct qihse_verification_metrics_s {
    size_t total_verifications;     /* Total verification operations */
    size_t passed_verifications;    /* Number of passed verifications */
    size_t failed_verifications;    /* Number of failed verifications */
    double average_confidence;      /* Average confidence across all verifications */
    double average_accuracy;        /* Average accuracy across all verifications */
    size_t average_time_us;         /* Average verification time */
    size_t max_time_us;             /* Maximum verification time */
    size_t min_time_us;             /* Minimum verification time */
} qihse_verification_metrics_t;

/**
 * Get global verification metrics.
 *
 * @param metrics Output metrics structure
 */
void qihse_get_verification_metrics(qihse_verification_metrics_t* metrics);

/**
 * Reset verification metrics.
 */
void qihse_reset_verification_metrics(void);

/**
 * Export verification metrics to JSON string.
 *
 * @return JSON string (caller must free), or NULL on failure
 */
char* qihse_export_verification_metrics_json(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_VERIFICATION_H */

