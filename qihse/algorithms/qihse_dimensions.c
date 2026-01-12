/*
 * QIHSE - Dynamic Dimension Calculation Implementation
 *
 * Implements intelligent dimension calculation based on problem characteristics.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_dimensions.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>

/* ============================================================================
 * DIMENSION CALCULATION CONFIGURATION
 * ============================================================================ */

void qihse_dimension_config_init(qihse_dimension_config_t* config) {
    if (!config) return;

    config->min_dims = 8;
    config->max_dims = 16384;
    config->entropy_threshold = 0.1;
    config->complexity_weight = 0.3;
    config->memory_weight = 0.4;
    config->performance_weight = 0.3;
    config->adaptive_scaling = 1;
    config->target_accuracy = 0.95;
}

/* ============================================================================
 * PROBLEM CHARACTERIZATION
 * ============================================================================ */

int qihse_analyze_problem_characteristics(
    const double* data,
    size_t data_size,
    qihse_problem_characteristics_t* characteristics
) {
    if (!data || data_size == 0 || !characteristics) {
        errno = EINVAL;
        return -1;
    }

    memset(characteristics, 0, sizeof(qihse_problem_characteristics_t));

    characteristics->input_size = data_size;

    /* Calculate statistical properties */
    double sum = 0.0, sum_sq = 0.0, min_val = data[0], max_val = data[0];
    size_t non_zero_count = 0;

    for (size_t i = 0; i < data_size; i++) {
        double val = data[i];
        sum += val;
        sum_sq += val * val;

        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
        if (val != 0.0) non_zero_count++;
    }

    double mean = sum / data_size;
    double variance = (sum_sq / data_size) - (mean * mean);
    double std_dev = sqrt(variance > 0 ? variance : 0);

    /* Estimate entropy using Shannon entropy calculation */
    characteristics->data_entropy = 0.0;
    if (std_dev > 0) {
        /* Discretize into 10 bins for entropy calculation */
        int bins[10] = {0};
        for (size_t i = 0; i < data_size; i++) {
            double normalized = (data[i] - min_val) / (max_val - min_val);
            int bin = (int)(normalized * 9.999);
            if (bin >= 0 && bin < 10) bins[bin]++;
        }

        for (int i = 0; i < 10; i++) {
            if (bins[i] > 0) {
                double p = (double)bins[i] / data_size;
                characteristics->data_entropy -= p * log2(p);
            }
        }
    }

    /* Estimate complexity (Kolmogorov-like) */
    characteristics->data_complexity = 0.0;
    for (size_t i = 1; i < data_size; i++) {
        double diff = fabs(data[i] - data[i-1]);
        characteristics->data_complexity += diff;
    }
    characteristics->data_complexity /= data_size;

    /* Calculate sparsity */
    characteristics->sparsity = 1.0 - (double)non_zero_count / data_size;

    /* Estimate correlation */
    characteristics->correlation = 0.0;
    if (data_size > 1) {
        double sum_xy = 0.0, sum_x_sq = 0.0, sum_y_sq = 0.0;
        for (size_t i = 1; i < data_size; i++) {
            double x = data[i-1] - mean;
            double y = data[i] - mean;
            sum_xy += x * y;
            sum_x_sq += x * x;
            sum_y_sq += y * y;
        }
        if (sum_x_sq > 0 && sum_y_sq > 0) {
            characteristics->correlation = sum_xy / sqrt(sum_x_sq * sum_y_sq);
        }
    }

    /* Set default memory and performance targets */
    characteristics->memory_budget = 1024 * 1024 * 1024; /* 1GB default */
    characteristics->performance_target = 1000.0; /* 1000 queries/sec default */

    return 0;
}

/* ============================================================================
 * DIMENSION CALCULATION
 * ============================================================================ */

size_t qihse_calculate_optimal_dimensions(
    const qihse_problem_characteristics_t* characteristics,
    const qihse_dimension_config_t* config
) {
    if (!characteristics || !config) return config ? config->min_dims : 8;

    /* Base calculation from entropy */
    double entropy_factor = characteristics->data_entropy / 4.0; /* Normalize entropy */
    double complexity_factor = characteristics->data_complexity * 100.0; /* Amplify complexity */

    /* Size-based scaling */
    double size_factor = log2((double)characteristics->input_size) / 10.0;

    /* Combine factors with weights */
    double dimension_score = (
        entropy_factor * config->complexity_weight +
        complexity_factor * config->complexity_weight +
        size_factor * config->performance_weight
    );

    /* Convert to dimension count */
    size_t dims = (size_t)exp(dimension_score) * 8; /* Base of 8 */

    /* Apply memory constraint */
    size_t memory_dims = characteristics->memory_budget / (sizeof(double) * 8); /* Conservative */
    if (dims > memory_dims) dims = memory_dims;

    /* Clamp to configured range */
    return qihse_clamp_dimensions(dims, config);
}

size_t qihse_calculate_dimensions_for_accuracy(
    const qihse_problem_characteristics_t* characteristics,
    double target_accuracy,
    const qihse_dimension_config_t* config
) {
    if (!characteristics || !config || target_accuracy <= 0.0 || target_accuracy > 1.0) {
        return config->min_dims;
    }

    /* Accuracy-based dimension calculation */
    /* Higher accuracy requires more dimensions */
    double accuracy_factor = -log(1.0 - target_accuracy) * 2.0;
    size_t base_dims = qihse_calculate_optimal_dimensions(characteristics, config);

    size_t accuracy_dims = (size_t)(base_dims * accuracy_factor);

    /* Clamp to configured range */
    return qihse_clamp_dimensions(accuracy_dims, config);
}

size_t qihse_calculate_dimensions_with_memory(
    const qihse_problem_characteristics_t* characteristics,
    size_t memory_budget,
    const qihse_dimension_config_t* config
) {
    if (!characteristics || !config) return config->min_dims;

    /* Calculate maximum dimensions that fit in memory */
    /* Assume each dimension stores: input_size * sizeof(double) for projections */
    size_t max_dims = memory_budget / (characteristics->input_size * sizeof(double));

    /* Take minimum of calculated optimal and memory-limited */
    size_t optimal_dims = qihse_calculate_optimal_dimensions(characteristics, config);

    return qihse_clamp_dimensions(max_dims < optimal_dims ? max_dims : optimal_dims, config);
}

/* ============================================================================
 * DIMENSION ANALYSIS AND VALIDATION
 * ============================================================================ */

int qihse_validate_dimensions(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics,
    const qihse_dimension_config_t* config
) {
    if (!config) return 0;

    if (dims < config->min_dims || dims > config->max_dims) return 0;

    if (characteristics) {
        size_t memory_usage = qihse_estimate_memory_usage(dims, characteristics);
        if (memory_usage > characteristics->memory_budget) return 0;
    }

    return 1;
}

size_t qihse_estimate_memory_usage(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics
) {
    if (!characteristics) return 0;

    /* Estimate memory for RFF kernel */
    size_t rff_memory = dims * characteristics->input_size * sizeof(double) * 2; /* omega + bias */

    /* Estimate memory for superposition */
    size_t superposition_memory = dims * characteristics->input_size * sizeof(double) * 2; /* real + imag */

    return rff_memory + superposition_memory;
}

double qihse_estimate_performance(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics
) {
    if (!characteristics || dims == 0) return 0.0;

    /* Use performance scaling model */
    /* Performance decreases with dimension count and input size */
    double complexity_factor = (double)dims * characteristics->input_size / 1000000.0;
    double performance = characteristics->performance_target / (1.0 + complexity_factor);

    return performance > 0 ? performance : 1.0; /* Minimum 1 query/sec */
}

double qihse_calculate_dimension_efficiency(
    size_t dims,
    const qihse_problem_characteristics_t* characteristics
) {
    if (!characteristics || dims == 0) return 0.0;

    double memory_efficiency = (double)qihse_estimate_memory_usage(dims, characteristics) /
                              characteristics->memory_budget;

    double performance_efficiency = qihse_estimate_performance(dims, characteristics) /
                                   characteristics->performance_target;

    /* Combined efficiency metric */
    return (memory_efficiency + performance_efficiency) / 2.0;
}

/* ============================================================================
 * ADAPTIVE DIMENSION SCALING
 * ============================================================================ */

int qihse_dimension_scaler_init(
    qihse_dimension_scaler_t* scaler,
    size_t initial_dims,
    double target_accuracy,
    size_t min_dims,
    size_t max_dims
) {
    if (!scaler) {
        errno = EINVAL;
        return -1;
    }

    scaler->current_dims = initial_dims;
    scaler->current_accuracy = 0.5; /* Initial guess */
    scaler->target_accuracy = target_accuracy;
    scaler->min_dims = min_dims;
    scaler->max_dims = max_dims;
    scaler->adaptation_rate = 0.1; /* 10% adaptation rate */
    scaler->internal_state = NULL;

    return 0;
}

void qihse_dimension_scaler_destroy(qihse_dimension_scaler_t* scaler) {
    if (!scaler) return;
    free(scaler->internal_state);
    memset(scaler, 0, sizeof(qihse_dimension_scaler_t));
}

size_t qihse_dimension_scaler_adapt(
    qihse_dimension_scaler_t* scaler,
    double measured_accuracy,
    double performance_metric
) {
    if (!scaler) return scaler->current_dims;

    scaler->current_accuracy = measured_accuracy;

    /* Adaptive scaling based on accuracy and performance */
    double accuracy_error = scaler->target_accuracy - measured_accuracy;
    double performance_factor = performance_metric / 1000.0; /* Normalize */

    /* Adjust dimensions based on error and performance */
    double adjustment = accuracy_error * scaler->adaptation_rate;
    if (performance_factor < 0.5) {
        adjustment *= 0.5; /* Reduce adjustment if performance is poor */
    }

    double new_dims_d = (double)scaler->current_dims * (1.0 + adjustment);
    size_t new_dims = (size_t)new_dims_d;

    /* Clamp to bounds */
    if (new_dims < scaler->min_dims) new_dims = scaler->min_dims;
    if (new_dims > scaler->max_dims) new_dims = scaler->max_dims;

    scaler->current_dims = new_dims;
    return new_dims;
}

void qihse_dimension_scaler_reset(qihse_dimension_scaler_t* scaler) {
    if (!scaler) return;
    scaler->current_accuracy = 0.5;
    scaler->current_dims = (scaler->min_dims + scaler->max_dims) / 2;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

size_t qihse_clamp_dimensions(
    size_t dims,
    const qihse_dimension_config_t* config
) {
    if (!config) return dims;

    if (dims < config->min_dims) return config->min_dims;
    if (dims > config->max_dims) return config->max_dims;
    return dims;
}

int qihse_suggest_scaling_factors(
    size_t base_dims,
    size_t num_levels,
    double* scaling_factors
) {
    if (!scaling_factors || num_levels == 0) {
        errno = EINVAL;
        return -1;
    }
    (void)base_dims;  /* Reserved for future base-dimension-aware scaling */

    /* Suggest geometric scaling for multi-resolution */
    double ratio = 2.0; /* Double dimensions each level */

    for (size_t i = 0; i < num_levels; i++) {
        scaling_factors[i] = pow(ratio, (double)i);
    }

    return 0;
}

size_t qihse_calculate_entropy_dimension_bound(
    const qihse_problem_characteristics_t* characteristics
) {
    if (!characteristics) return 8;

    /* Information-theoretic bound based on entropy */
    double entropy_bits = characteristics->data_entropy * characteristics->input_size;
    size_t bound = (size_t)exp(entropy_bits / 10.0); /* Conservative scaling */

    return bound > 0 ? bound : 8;
}
