/*
 * QIHSE - Dynamic Dimension Calculation
 *
 * Intelligent dimension calculation based on problem characteristics,
 * entropy analysis, and performance optimization.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_DIMENSIONS_H
#define QIHSE_DIMENSIONS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DIMENSION CALCULATION CONFIGURATION
 * ============================================================================ */

/**
 * Dimension calculation configuration.
 */
typedef struct qihse_dimension_config_s {
    size_t min_dims;            /* Minimum allowed dimensions */
    size_t max_dims;            /* Maximum allowed dimensions */
    double entropy_threshold;   /* Minimum entropy threshold */
    double complexity_weight;   /* Weight for problem complexity */
    double memory_weight;       /* Weight for memory constraints */
    double performance_weight;  /* Weight for performance requirements */
    int adaptive_scaling;       /* Enable adaptive dimension scaling */
    double target_accuracy;     /* Target accuracy for dimension selection */
} qihse_dimension_config_t;

/**
 * Initialize dimension config with defaults.
 *
 * @param config Config to initialize
 */
void qihse_dimension_config_init(qihse_dimension_config_t* config);

/* ============================================================================
 * PROBLEM CHARACTERIZATION
 * ============================================================================ */

/**
 * Problem characteristics structure.
 */
typedef struct qihse_problem_characteristics_s {
    size_t input_size;          /* Size of input data */
    size_t output_size;         /* Expected output size */
    double data_entropy;        /* Shannon entropy of input data */
    double data_complexity;     /* Kolmogorov complexity estimate */
    double sparsity;            /* Data sparsity (0.0 = dense, 1.0 = sparse) */
    double correlation;         /* Data correlation coefficient */
    size_t memory_budget;       /* Available memory in bytes */
    double performance_target;  /* Target performance (queries/sec) */
} qihse_problem_characteristics_t;

/**
 * Analyze problem characteristics from sample data.
 *
 * @param data Sample data array
 * @param data_size Size of data array
 * @param characteristics Output characteristics structure
 * @return 0 on success, negative error code on failure
 */
int qihse_analyze_problem_characteristics(
    const double* data,
    size_t data_size,
    qihse_problem_characteristics_t* characteristics
);

/* ============================================================================
 * DIMENSION CALCULATION
 * ============================================================================ */

/**
 * Calculate optimal Hilbert space dimensions.
 *
 * Uses problem characteristics to determine optimal expansion dimensions.
 *
 * @param characteristics Problem characteristics
 * @param config Dimension calculation config
 * @return Recommended Hilbert space dimensions
 */
size_t qihse_calculate_optimal_dimensions(
    const qihse_problem_characteristics_t* characteristics,
    const qihse_dimension_config_t* config
);

/**
 * Calculate dimensions for specific accuracy target.
 *
 * @param characteristics Problem characteristics
 * @param target_accuracy Desired accuracy (0.0-1.0)
 * @param config Dimension config
 * @return Dimensions needed for target accuracy
 */
size_t qihse_calculate_dimensions_for_accuracy(
    const qihse_problem_characteristics_t* characteristics,
    double target_accuracy,
    const qihse_dimension_config_t* config
);

/**
 * Calculate dimensions with memory constraints.
 *
 * @param characteristics Problem characteristics
 * @param memory_budget Available memory in bytes
 * @param config Dimension config
 * @return Dimensions fitting memory budget
 */
size_t qihse_calculate_dimensions_with_memory(
    const qihse_problem_characteristics_t* characteristics,
    size_t memory_budget,
    const qihse_dimension_config_t* config
);

/* ============================================================================
 * DIMENSION ANALYSIS AND VALIDATION
 * ============================================================================ */

/**
 * Validate calculated dimensions against constraints.
 *
 * @param dims Proposed dimensions
 * @param characteristics Problem characteristics
 * @param config Dimension config
 * @return 1 if valid, 0 if invalid
 */
int qihse_validate_dimensions(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics,
    const qihse_dimension_config_t* config
);

/**
 * Estimate memory usage for given dimensions.
 *
 * @param dims Hilbert space dimensions
 * @param characteristics Problem characteristics
 * @return Estimated memory usage in bytes
 */
size_t qihse_estimate_memory_usage(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics
);

/**
 * Estimate performance for given dimensions.
 *
 * @param dims Hilbert space dimensions
 * @param characteristics Problem characteristics
 * @return Estimated queries per second
 */
double qihse_estimate_performance(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics
);

/**
 * Calculate dimension efficiency metric.
 *
 * Higher values indicate better dimension utilization.
 *
 * @param dims Hilbert space dimensions
 * @param characteristics Problem characteristics
 * @return Efficiency metric (0.0-1.0)
 */
double qihse_calculate_dimension_efficiency(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics
);

/* ============================================================================
 * ADAPTIVE DIMENSION SCALING
 * ============================================================================ */

/**
 * Adaptive dimension scaler state.
 */
typedef struct qihse_dimension_scaler_s {
    size_t current_dims;        /* Current Hilbert space dimensions */
    double current_accuracy;    /* Current accuracy level */
    double target_accuracy;     /* Target accuracy level */
    size_t min_dims;            /* Minimum allowed dimensions */
    size_t max_dims;            /* Maximum allowed dimensions */
    double adaptation_rate;     /* How quickly to adapt dimensions */
    void* internal_state;       /* Internal adaptation state */
} qihse_dimension_scaler_t;

/**
 * Initialize adaptive dimension scaler.
 *
 * @param scaler Scaler to initialize
 * @param initial_dims Initial dimensions
 * @param target_accuracy Target accuracy level
 * @param min_dims Minimum dimensions
 * @param max_dims Maximum dimensions
 * @return 0 on success, negative error code on failure
 */
int qihse_dimension_scaler_init(
    qihse_dimension_scaler_t* scaler,
    size_t initial_dims,
    double target_accuracy,
    size_t min_dims,
    size_t max_dims
);

/**
 * Destroy dimension scaler.
 *
 * @param scaler Scaler to destroy
 */
void qihse_dimension_scaler_destroy(qihse_dimension_scaler_t* scaler);

/**
 * Adapt dimensions based on performance feedback.
 *
 * @param scaler Dimension scaler
 * @param measured_accuracy Current measured accuracy
 * @param performance_metric Current performance metric
 * @return New recommended dimensions
 */
size_t qihse_dimension_scaler_adapt(
    qihse_dimension_scaler_t* scaler,
    double measured_accuracy,
    double performance_metric
);

/**
 * Reset scaler to initial state.
 *
 * @param scaler Scaler to reset
 */
void qihse_dimension_scaler_reset(qihse_dimension_scaler_t* scaler);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Clamp dimensions to valid range.
 *
 * @param dims Input dimensions
 * @param config Dimension config
 * @return Clamped dimensions
 */
size_t qihse_clamp_dimensions(
    size_t dims,
    const qihse_dimension_config_t* config
);

/**
 * Suggest dimension scaling factors for multi-resolution.
 *
 * @param base_dims Base dimensions
 * @param num_levels Number of resolution levels
 * @param scaling_factors Output scaling factors [num_levels]
 * @return 0 on success, negative error code on failure
 */
int qihse_suggest_scaling_factors(
    size_t base_dims,
    size_t num_levels,
    double* scaling_factors
);

/**
 * Calculate information-theoretic dimension bound.
 *
 * Based on data entropy and complexity.
 *
 * @param characteristics Problem characteristics
 * @return Theoretical dimension bound
 */
size_t qihse_calculate_entropy_dimension_bound(
    const qihse_problem_characteristics_t* characteristics
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_DIMENSIONS_H */

