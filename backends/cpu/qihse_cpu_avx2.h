/*
 * QIHSE - AVX2 SIMD Backend for RFF and Superposition
 *
 * AVX2-accelerated implementations of Random Fourier Features and
 * superposition operations using 256-bit SIMD vectors.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_CPU_AVX2_H
#define QIHSE_CPU_AVX2_H

#include "../algorithms/qihse_rff.h"
#include "../algorithms/qihse_superposition.h"
#include <immintrin.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * AVX2-SPECIFIC RFF KERNEL
 * ============================================================================ */

/**
 * AVX2-optimized RFF kernel.
 * Uses SoA (Struct of Arrays) layout for better cache performance.
 */
typedef struct qihse_rff_kernel_avx2_s {
    size_t input_dims;         /* Input dimensionality */
    size_t output_dims;        /* Output dimensionality (D) */
    double gamma;              /* RBF kernel parameter */
    uint64_t seed;             /* Random seed for reproducibility */

    /* SoA layout: separate arrays for better SIMD access */
    float* omega_real;         /* Real part of frequencies [output_dims * input_dims] */
    float* omega_imag;         /* Imaginary part of frequencies [output_dims * input_dims] */
    float* bias;               /* Random biases [output_dims] */

    /* SIMD working buffers */
    float* temp_buffer;        /* Temporary buffer for SIMD operations */
    size_t buffer_size;        /* Size of temporary buffer */

    /* Cache-aware blocking parameters */
    size_t block_size;         /* Optimal block size for cache */
    size_t num_blocks;         /* Number of blocks for processing */
} qihse_rff_kernel_avx2_t;

/* ============================================================================
 * AVX2 RFF OPERATIONS
 * ============================================================================ */

/**
 * Create AVX2-optimized RFF kernel.
 *
 * @param input_dims Input dimensionality
 * @param output_dims Output dimensionality (must be multiple of 8 for AVX2)
 * @param gamma RBF kernel bandwidth parameter
 * @param seed Random seed for reproducible results
 * @return AVX2 RFF kernel, or NULL on failure
 */
qihse_rff_kernel_avx2_t* qihse_rff_avx2_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
);

/**
 * Destroy AVX2 RFF kernel.
 *
 * @param kernel AVX2 kernel to destroy
 */
void qihse_rff_avx2_destroy(qihse_rff_kernel_avx2_t* kernel);

/**
 * AVX2-accelerated RFF projection.
 *
 * z(x) = sqrt(2/D) * cos(ω·x + b)
 *
 * @param kernel AVX2 RFF kernel
 * @param input Input vector [input_dims]
 * @param output Output Hilbert space projection [output_dims]
 */
void qihse_rff_avx2_project(
    const qihse_rff_kernel_avx2_t* kernel,
    const float* input,
    float* output
);

/**
 * AVX2 batch RFF projection.
 *
 * @param kernel AVX2 RFF kernel
 * @param inputs Input vectors [batch_size * input_dims]
 * @param outputs Output projections [batch_size * output_dims]
 * @param batch_size Number of vectors to project
 */
void qihse_rff_avx2_project_batch(
    const qihse_rff_kernel_avx2_t* kernel,
    const float* inputs,
    float* outputs,
    size_t batch_size
);

/* ============================================================================
 * AVX2 SUPERPOSITION OPERATIONS
 * ============================================================================ */

/**
 * AVX2-optimized superposition structure.
 * Uses SoA layout for SIMD operations.
 */
typedef struct qihse_superposition_avx2_s {
    size_t num_states;          /* Number of superposition states */
    size_t dims_per_state;      /* Dimensions per quantum state */
    float global_phase;         /* Global quantum phase offset */
    float measurement_confidence; /* Confidence in quantum measurement */

    /* SoA layout for SIMD */
    float* real;                /* Real amplitude components [num_states * dims_per_state] */
    float* imag;                /* Imaginary amplitude components [num_states * dims_per_state] */
    float* phase;               /* Per-element phase angles [num_states] */

    /* AVX2 working buffers */
    float* temp_real;           /* Temporary real buffer */
    float* temp_imag;           /* Temporary imaginary buffer */
    size_t temp_size;           /* Size of temporary buffers */
} qihse_superposition_avx2_t;

/**
 * Create AVX2 superposition from RFF data.
 *
 * @param rff_data RFF-projected array [n * rff_dims]
 * @param n Number of elements in original array
 * @param rff_dims RFF output dimensions
 * @param superposition Output AVX2 superposition structure
 * @return 0 on success, negative error code on failure
 */
int qihse_superposition_avx2_create(
    const float* rff_data,
    size_t n,
    size_t rff_dims,
    qihse_superposition_avx2_t* superposition
);

/**
 * Destroy AVX2 superposition.
 *
 * @param superposition AVX2 superposition to destroy
 */
void qihse_superposition_avx2_destroy(qihse_superposition_avx2_t* superposition);

/**
 * AVX2-accelerated superposition normalization.
 *
 * @param superposition Superposition to normalize
 * @return 0 on success, negative error code on failure
 */
int qihse_superposition_avx2_normalize(qihse_superposition_avx2_t* superposition);

/**
 * AVX2-accelerated phase application.
 *
 * @param superposition Superposition to modify
 * @param phase_shift Phase shift in radians
 */
void qihse_superposition_avx2_apply_phase(
    qihse_superposition_avx2_t* superposition,
    float phase_shift
);

/**
 * AVX2-accelerated Grover oracle operation.
 *
 * @param superposition Superposition to modify
 * @param target_indices Array of target state indices
 * @param num_targets Number of target states
 * @param selectivity How strictly to mark targets (0.0-1.0)
 */
void qihse_superposition_avx2_oracle_mark(
    qihse_superposition_avx2_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    float selectivity
);

/**
 * AVX2-accelerated Grover diffusion operator.
 *
 * @param superposition Superposition to modify
 */
void qihse_superposition_avx2_diffusion(qihse_superposition_avx2_t* superposition);

/* ============================================================================
 * AVX2 UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Convert double precision to single precision for AVX2.
 *
 * @param input Double precision input
 * @param output Single precision output
 * @param size Number of elements
 */
void qihse_avx2_double_to_float(const double* input, float* output, size_t size);

/**
 * Convert single precision to double precision.
 *
 * @param input Single precision input
 * @param output Double precision output
 * @param size Number of elements
 */
void qihse_avx2_float_to_double(const float* input, double* output, size_t size);

/**
 * Get optimal AVX2 block size for cache efficiency.
 *
 * @param cache_line_size Cache line size in bytes
 * @param l2_cache_size L2 cache size in bytes
 * @return Optimal block size for AVX2 operations
 */
size_t qihse_avx2_optimal_block_size(size_t cache_line_size, size_t l2_cache_size);

/**
 * Check if dimensions are optimal for AVX2.
 *
 * @param dims Dimensions to check
 * @return true if optimal, false otherwise
 */
bool qihse_avx2_is_optimal_dims(size_t dims);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_CPU_AVX2_H */
