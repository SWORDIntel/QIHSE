/**
 * QIHSE Dynamic Dimension Calculator
 *
 * Analyzes data characteristics to compute optimal Hilbert space dimensions
 * for quantum-inspired search based on entropy, gap variance, and array size.
 */

#include "qihse.h"
#include <math.h>
#include <float.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846264338327950288
#endif

/* ============================================================================
 * ENTROPY CALCULATION
 * ============================================================================ */

/**
 * @brief Calculate Shannon entropy of data gaps
 *
 * Entropy measures the unpredictability/information content of gaps between
 * consecutive elements. Higher entropy indicates more complex patterns
 * requiring larger Hilbert spaces.
 */
static double calculate_gap_entropy(const void* data, size_t n, qihse_data_type_t type) {
    if (n < 2) return 0.0;

    /* Calculate gaps between consecutive elements */
    double* gaps = malloc((n - 1) * sizeof(double));
    if (!gaps) return 0.0;

    size_t gap_count = 0;

    /* Extract values based on type */
    for (size_t i = 1; i < n; i++) {
        double val1, val2;

        switch (type) {
            case QIHSE_TYPE_INT64: {
                const int64_t* arr = data;
                val1 = (double)arr[i - 1];
                val2 = (double)arr[i];
                break;
            }
            case QIHSE_TYPE_UINT64: {
                const uint64_t* arr = data;
                val1 = (double)arr[i - 1];
                val2 = (double)arr[i];
                break;
            }
            case QIHSE_TYPE_DOUBLE: {
                const double* arr = data;
                val1 = arr[i - 1];
                val2 = arr[i];
                break;
            }
            default:
                /* For other types, use hash-based approximation */
                val1 = (double)(i - 1); /* Fallback to index-based */
                val2 = (double)i;
                break;
        }

        gaps[gap_count++] = fabs(val2 - val1);
    }

    if (gap_count == 0) {
        free(gaps);
        return 0.0;
    }

    /* Calculate entropy using histogram */
    const size_t bins = 64; /* Number of histogram bins */
    size_t* histogram = calloc(bins, sizeof(size_t));
    if (!histogram) {
        free(gaps);
        return 0.0;
    }

    /* Find min/max for binning */
    double min_gap = DBL_MAX;
    double max_gap = -DBL_MAX;

    for (size_t i = 0; i < gap_count; i++) {
        if (gaps[i] < min_gap) min_gap = gaps[i];
        if (gaps[i] > max_gap) max_gap = gaps[i];
    }

    if (max_gap <= min_gap) {
        free(histogram);
        free(gaps);
        return 0.0; /* All gaps equal */
    }

    /* Build histogram */
    double bin_width = (max_gap - min_gap) / bins;
    for (size_t i = 0; i < gap_count; i++) {
        size_t bin = (size_t)((gaps[i] - min_gap) / bin_width);
        if (bin >= bins) bin = bins - 1;
        histogram[bin]++;
    }

    /* Calculate Shannon entropy */
    double entropy = 0.0;
    double total = (double)gap_count;

    for (size_t i = 0; i < bins; i++) {
        if (histogram[i] > 0) {
            double p = (double)histogram[i] / total;
            entropy -= p * log2(p);
        }
    }

    free(histogram);
    free(gaps);

    /* Normalize to 0-1 range */
    return entropy / log2(bins);
}

/* ============================================================================
 * GAP VARIANCE ANALYSIS
 * ============================================================================ */

/**
 * @brief Calculate coefficient of variation for gaps
 *
 * Measures relative variability of gaps. Higher values indicate
 * irregular spacing requiring more dimensions to capture patterns.
 */
static double calculate_gap_coefficient_of_variation(const void* data, size_t n, qihse_data_type_t type) {
    if (n < 2) return 0.0;

    /* Calculate gaps */
    double* gaps = malloc((n - 1) * sizeof(double));
    if (!gaps) return 0.0;

    size_t gap_count = 0;
    double sum = 0.0;

    for (size_t i = 1; i < n; i++) {
        double gap;

        switch (type) {
            case QIHSE_TYPE_INT64: {
                const int64_t* arr = data;
                gap = fabs((double)arr[i] - (double)arr[i - 1]);
                break;
            }
            case QIHSE_TYPE_UINT64: {
                const uint64_t* arr = data;
                gap = fabs((double)arr[i] - (double)arr[i - 1]);
                break;
            }
            case QIHSE_TYPE_DOUBLE: {
                const double* arr = data;
                gap = fabs(arr[i] - arr[i - 1]);
                break;
            }
            default:
                gap = 1.0; /* Assume unit gaps for other types */
                break;
        }

        gaps[gap_count++] = gap;
        sum += gap;
    }

    if (gap_count == 0 || sum == 0.0) {
        free(gaps);
        return 0.0;
    }

    /* Calculate mean */
    double mean = sum / gap_count;

    /* Calculate variance */
    double variance = 0.0;
    for (size_t i = 0; i < gap_count; i++) {
        double diff = gaps[i] - mean;
        variance += diff * diff;
    }
    variance /= gap_count;

    /* Calculate coefficient of variation (CV) */
    double cv = (variance > 0.0) ? sqrt(variance) / mean : 0.0;

    free(gaps);
    return cv;
}

/* ============================================================================
 * ARRAY SIZE SCALING FACTORS
 * ============================================================================ */

/**
 * @brief Calculate size-based scaling factor
 *
 * Larger arrays benefit from higher-dimensional expansions due to
 * increased parallelism and better pattern capture.
 */
static double calculate_size_scaling_factor(size_t n) {
    if (n < 1000) return 1.0;           /* Tiny: no expansion needed */
    if (n < 10000) return 1.5;          /* Small: minimal expansion */
    if (n < 100000) return 2.0;         /* Medium: moderate expansion */
    if (n < 1000000) return 3.0;        /* Large: significant expansion */
    if (n < 10000000) return 4.0;       /* Huge: major expansion */
    return 5.0;                         /* Massive: maximum expansion */
}

/* ============================================================================
 * DEVICE CAPABILITY CONSTRAINTS
 * ============================================================================ */

/**
 * @brief Apply device-specific dimension constraints
 *
 * Different compute devices have different optimal dimension ranges
 * based on their architecture and memory characteristics.
 */
static size_t apply_device_constraints(
    size_t raw_dims,
    const qihse_compute_pool_t* pool,
    qihse_data_type_t data_type
) {
    if (!pool || raw_dims == 0) return raw_dims;

    size_t constrained_dims = raw_dims;
    size_t max_dims = QIHSE_MAX_DIMENSIONS;

    /* Apply per-device constraints */
    for (int i = 0; i < QIHSE_DEV_COUNT; i++) {
        if (!pool->devices[i].available) continue;

        size_t device_max;
        switch (pool->devices[i].type) {
            case QIHSE_DEV_CPU_AMX:
                device_max = 512; /* AMX tiles are 16x16, efficient for powers of 2 */
                break;
            case QIHSE_DEV_CPU_VNNI:
                device_max = 1024; /* VNNI prefers larger batches */
                break;
            case QIHSE_DEV_CPU_AVX512:
                device_max = 2048; /* AVX-512 wide vectors */
                break;
            case QIHSE_DEV_CPU_AVX2:
                device_max = 4096; /* AVX2 baseline */
                break;
            case QIHSE_DEV_NPU:
                device_max = 8192; /* NPU tensor cores */
                break;
            case QIHSE_DEV_INTEL_GPU:
                device_max = 16384; /* Intel Arc GPU */
                break;
            case QIHSE_DEV_NVIDIA_GPU:
                device_max = QIHSE_MAX_DIMENSIONS; /* Maximum for NVIDIA */
                break;
            default:
                device_max = 1024;
                break;
        }

        if (device_max < max_dims) {
            max_dims = device_max;
        }
    }

    /* Apply memory constraints */
    size_t memory_budget_dims = max_dims;
    const size_t memory_per_dim = 256; /* Rough estimate: 256 bytes per dimension */
    const size_t max_memory_mb = 1024; /* 1GB memory budget */

    if (memory_per_dim * constrained_dims > max_memory_mb * 1024 * 1024) {
        memory_budget_dims = (max_memory_mb * 1024 * 1024) / memory_per_dim;
    }

    /* Take minimum of all constraints */
    constrained_dims = constrained_dims < memory_budget_dims ?
                      constrained_dims : memory_budget_dims;
    constrained_dims = constrained_dims < max_dims ? constrained_dims : max_dims;

    /* Ensure minimum and alignment */
    if (constrained_dims < QIHSE_MIN_DIMENSIONS) {
        constrained_dims = QIHSE_MIN_DIMENSIONS;
    }

    /* Align to SIMD-friendly boundaries */
    const size_t alignment = 16; /* AVX2/AVX512 alignment */
    constrained_dims = ((constrained_dims + alignment - 1) / alignment) * alignment;

    return constrained_dims;
}

/* ============================================================================
 * MAIN DIMENSION CALCULATION
 * ============================================================================ */

int qihse_compute_optimal_dimensions(
    const void* data,
    size_t n,
    size_t element_size,
    qihse_data_type_t type,
    const qihse_compute_pool_t* pool,
    qihse_dimension_params_t* params
) {
    if (!data || !params || n == 0) return -EINVAL;

    memset(params, 0, sizeof(*params));
    params->array_size = n;
    params->data_type = type;

    /* Calculate data characteristics */
    params->data_entropy = calculate_gap_entropy(data, n, type);
    params->gap_coefficient = calculate_gap_coefficient_of_variation(data, n, type);

    /* Calculate base dimensions from array size */
    double log_n = log2((double)n);
    if (log_n < 1.0) log_n = 1.0;

    params->effective_rank = (size_t)log_n;

    /* Apply scaling factors */
    double entropy_multiplier = 1.0 + (params->data_entropy * 1.5);  /* 1.0 to 2.5 */
    double gap_multiplier = 1.0 + (params->gap_coefficient * 2.0);    /* 1.0 to 3.0+ */
    double size_multiplier = calculate_size_scaling_factor(n);       /* 1.0 to 5.0 */

    /* Calculate raw dimensions */
    double raw_dims_dbl = log_n * entropy_multiplier * gap_multiplier * size_multiplier;
    size_t raw_dims = (size_t)raw_dims_dbl;

    /* Apply constraints */
    params->optimal_dims = apply_device_constraints(raw_dims, pool, type);

    /* Calculate expansion factor */
    params->expansion_factor = params->optimal_dims / log_n;
    if (params->expansion_factor < 1.0) params->expansion_factor = 1.0;

    return 0;
}

/* ============================================================================
 * RFF KERNEL EMBEDDING
 * ============================================================================ */


/* ============================================================================
 * SUPERPOSITION CREATION
 * ============================================================================ */

