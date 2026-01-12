/*
 * QIHSE - Random Fourier Features (RFF) Implementation
 *
 * Random Fourier Features for approximating RBF kernels in higher-dimensional
 * Hilbert space. Provides the foundation for quantum-inspired search.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_RFF_H
#define QIHSE_RFF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * RFF KERNEL STRUCTURE
 * ============================================================================ */

/**
 * RFF kernel for approximating RBF kernels.
 *
 * Approximates K(x,y) = exp(-γ||x-y||²) using random Fourier features:
 * z(x) = sqrt(2/D) * cos(ω·x + b)
 *
 * Where:
 * - ω are random frequencies drawn from N(0, 2γ)
 * - b are random biases drawn from U[0, 2π]
 * - D is the output dimension (number of features)
 */
typedef struct qihse_rff_kernel_s {
    size_t input_dims;         /* Input dimensionality */
    size_t output_dims;        /* Output dimensionality (D) */
    double gamma;              /* RBF kernel parameter */
    uint64_t seed;             /* Random seed for reproducibility */

    /* Random parameters - allocated dynamically */
    double* omega;             /* Random frequencies [input_dims * output_dims] */
    double* bias;              /* Random biases [output_dims] */

    /* Internal state */
    void* internal_state;      /* Backend-specific state (if needed) */
} qihse_rff_kernel_t;

/* ============================================================================
 * RFF KERNEL MANAGEMENT
 * ============================================================================ */

/**
 * Create RFF kernel with specified parameters.
 *
 * @param input_dims Input dimensionality
 * @param output_dims Output dimensionality (Hilbert space size)
 * @param gamma RBF kernel bandwidth parameter
 * @param seed Random seed for reproducible results
 * @return Initialized RFF kernel, or NULL on allocation failure
 */
qihse_rff_kernel_t* qihse_rff_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
);

/**
 * Destroy RFF kernel and free resources.
 *
 * @param kernel Kernel to destroy
 */
void qihse_rff_destroy(qihse_rff_kernel_t* kernel);

/* ============================================================================
 * RFF PROJECTION OPERATIONS
 * ============================================================================ */

/**
 * Project input vector to Hilbert space using RFF.
 *
 * z(x) = sqrt(2/D) * cos(ω·x + b)
 *
 * @param kernel Initialized RFF kernel
 * @param input Input vector [input_dims]
 * @param output Output Hilbert space projection [output_dims]
 */
void qihse_rff_project(
    const qihse_rff_kernel_t* kernel,
    const double* input,
    double* output
);

/**
 * Project batch of input vectors to Hilbert space.
 *
 * @param kernel Initialized RFF kernel
 * @param inputs Input vectors [batch_size * input_dims]
 * @param outputs Output projections [batch_size * output_dims]
 * @param batch_size Number of vectors to project
 */
void qihse_rff_project_batch(
    const qihse_rff_kernel_t* kernel,
    const double* inputs,
    double* outputs,
    size_t batch_size
);

/* ============================================================================
 * RFF KERNEL PROPERTIES
 * ============================================================================ */

/**
 * Get input dimensionality of RFF kernel.
 *
 * @param kernel RFF kernel
 * @return Input dimensions
 */
size_t qihse_rff_get_input_dims(const qihse_rff_kernel_t* kernel);

/**
 * Get output dimensionality of RFF kernel.
 *
 * @param kernel RFF kernel
 * @return Output dimensions
 */
size_t qihse_rff_get_output_dims(const qihse_rff_kernel_t* kernel);

/**
 * Get RBF gamma parameter.
 *
 * @param kernel RFF kernel
 * @return Gamma parameter
 */
double qihse_rff_get_gamma(const qihse_rff_kernel_t* kernel);

/**
 * Get random seed used for kernel initialization.
 *
 * @param kernel RFF kernel
 * @return Random seed
 */
uint64_t qihse_rff_get_seed(const qihse_rff_kernel_t* kernel);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_RFF_H */

