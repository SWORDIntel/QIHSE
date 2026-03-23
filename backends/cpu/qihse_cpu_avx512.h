/*
 * QIHSE - AVX-512 SIMD Backend for RFF and Superposition
 *
 * AVX-512-accelerated implementations of Random Fourier Features and
 * superposition operations using 512-bit SIMD vectors.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_CPU_AVX512_H
#define QIHSE_CPU_AVX512_H

#include "../../algorithms/qihse_rff.h"
#include "../../algorithms/qihse_superposition.h"
#include <immintrin.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * AVX-512-SPECIFIC RFF KERNEL
 * ============================================================================ */

/**
 * AVX-512-optimized RFF kernel.
 * Uses SoA (Struct of Arrays) layout for better cache performance.
 */
typedef struct qihse_rff_kernel_avx512_s {
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
} qihse_rff_kernel_avx512_t;

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



/* ============================================================================
 * PROCESSING-IN-MEMORY (PIM) OPERATIONS WITH AMX TILES
 * ============================================================================
 *
 * PIM operations using Intel Advanced Matrix Extensions (AMX) for
 * memory-compute co-location and blocked GEMM operations.
 * ============================================================================ */

/**
 * AMX tile configuration for PIM operations.
 */
typedef struct qihse_amx_tile_config_s {
    uint8_t palette_id;              /* Tile palette configuration */
    uint16_t tile_bytes[8];          /* Size of each tile in bytes */
    uint8_t tile_rows[8];            /* Rows per tile */
    uint8_t tile_cols[8];            /* Columns per tile */
} qihse_amx_tile_config_t;

/**
 * AMX PIM GEMM operation.
 */
typedef struct qihse_amx_pim_gemm_s {
    size_t M;                        /* Matrix A rows, Matrix C rows */
    size_t N;                        /* Matrix B columns, Matrix C columns */
    size_t K;                        /* Matrix A columns, Matrix B rows */
    size_t tile_size;                /* Tile size for blocked operations */
    uint8_t tile_config_valid;       /* Whether AMX tiles are configured */
    qihse_amx_tile_config_t tile_config; /* AMX tile configuration */
    float* matrix_a;                 /* Matrix A data [M*K] */
    float* matrix_b;                 /* Matrix B data [K*N] */
    float* matrix_c;                 /* Matrix C data [M*N] - result */
} qihse_amx_pim_gemm_t;

/**
 * Initialize AMX PIM GEMM operation.
 *
 * @param gemm AMX PIM GEMM operation to initialize
 * @param M Matrix A rows / Matrix C rows
 * @param N Matrix B columns / Matrix C columns
 * @param K Matrix A columns / Matrix B rows
 * @param matrix_a Matrix A data [M*K]
 * @param matrix_b Matrix B data [K*N]
 * @param tile_size Tile size for blocked operations
 * @return 0 on success, negative error code on failure
 */
int qihse_amx_pim_gemm_init(
    qihse_amx_pim_gemm_t* gemm,
    size_t M, size_t N, size_t K,
    const float* matrix_a,
    const float* matrix_b,
    size_t tile_size
);

/**
 * Execute AMX PIM GEMM operation.
 *
 * @param gemm AMX PIM GEMM operation instance
 * @param result Output result matrix [M*N]
 * @return 0 on success, negative error code on failure
 */
int qihse_amx_pim_gemm_execute(
    qihse_amx_pim_gemm_t* gemm,
    float* result
);

/**
 * Destroy AMX PIM GEMM operation.
 *
 * @param gemm AMX PIM GEMM operation to destroy
 */
void qihse_amx_pim_gemm_destroy(qihse_amx_pim_gemm_t* gemm);

/**
 * AMX PIM matrix-vector operation.
 */
typedef struct qihse_amx_pim_mv_s {
    size_t matrix_rows;              /* Matrix rows (M) */
    size_t matrix_cols;              /* Matrix columns (N) */
    size_t tile_size;                /* Tile size for blocked operations */
    uint8_t tile_config_valid;       /* Whether AMX tiles are configured */
    qihse_amx_tile_config_t tile_config; /* AMX tile configuration */
    float* matrix_data;              /* Matrix data [M*N] */
    float* result_data;              /* Result buffer [M] */
} qihse_amx_pim_mv_t;

/**
 * Initialize AMX PIM matrix-vector operation.
 *
 * @param mv AMX PIM MV operation to initialize
 * @param matrix_rows Matrix rows
 * @param matrix_cols Matrix columns
 * @param matrix_data Matrix data [matrix_rows * matrix_cols]
 * @param tile_size Tile size for blocked operations
 * @return 0 on success, negative error code on failure
 */
int qihse_amx_pim_mv_init(
    qihse_amx_pim_mv_t* mv,
    size_t matrix_rows,
    size_t matrix_cols,
    const float* matrix_data,
    size_t tile_size
);

/**
 * Execute AMX PIM matrix-vector multiplication.
 *
 * @param mv AMX PIM MV operation instance
 * @param vector Input vector [matrix_cols]
 * @param result Output result vector [matrix_rows]
 * @return 0 on success, negative error code on failure
 */
int qihse_amx_pim_mv_execute(
    qihse_amx_pim_mv_t* mv,
    const float* vector,
    float* result
);

/**
 * Destroy AMX PIM matrix-vector operation.
 *
 * @param mv AMX PIM MV operation to destroy
 */
void qihse_amx_pim_mv_destroy(qihse_amx_pim_mv_t* mv);

/**
 * Get AMX tile information.
 *
 * @param tile_count Output number of available tiles
 * @param max_tile_rows Output maximum rows per tile
 * @param max_tile_cols Output maximum columns per tile
 */
void qihse_amx_get_tile_info(size_t* tile_count, size_t* max_tile_rows, size_t* max_tile_cols);

/**
 * Check if AMX PIM operations are supported.
 *
 * @return true if AMX PIM operations are available
 */
bool qihse_amx_pim_supported(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_CPU_AVX512_H */
