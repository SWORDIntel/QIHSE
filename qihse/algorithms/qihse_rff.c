/*
 * QIHSE - Random Fourier Features Implementation
 *
 * Implements RFF kernel embedding for quantum-inspired search.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_rff.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

/* ============================================================================
 * INTERNAL UTILITIES
 * ============================================================================ */

/* Box-Muller transform for Gaussian random variables */
static double generate_gaussian(double mu, double sigma, uint64_t* seed) {
    /* Simple implementation - in production, use better PRNG */
    static int has_spare = 0;
    static double spare;

    if (has_spare) {
        has_spare = 0;
        return spare * sigma + mu;
    }

    has_spare = 1;
    double u, v, s;
    do {
        /* Simple LCG for demo - replace with proper PRNG */
        *seed = (*seed * 1103515245 + 12345) & 0x7fffffff;
        u = (double)*seed / 0x7fffffff * 2.0 - 1.0;

        *seed = (*seed * 1103515245 + 12345) & 0x7fffffff;
        v = (double)*seed / 0x7fffffff * 2.0 - 1.0;

        s = u * u + v * v;
    } while (s >= 1.0 || s == 0.0);

    s = sqrt(-2.0 * log(s) / s);
    spare = v * s;
    return (u * s) * sigma + mu;
}

/* ============================================================================
 * RFF KERNEL MANAGEMENT
 * ============================================================================ */

qihse_rff_kernel_t* qihse_rff_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
) {
    if (input_dims == 0 || output_dims == 0 || gamma <= 0.0) {
        errno = EINVAL;
        return NULL;
    }

    qihse_rff_kernel_t* kernel = calloc(1, sizeof(qihse_rff_kernel_t));
    if (!kernel) {
        errno = ENOMEM;
        return NULL;
    }

    kernel->input_dims = input_dims;
    kernel->output_dims = output_dims;
    kernel->gamma = gamma;
    kernel->seed = seed;

    /* Allocate parameter arrays */
    kernel->omega = malloc(output_dims * input_dims * sizeof(double));
    kernel->bias = malloc(output_dims * sizeof(double));

    if (!kernel->omega || !kernel->bias) {
        qihse_rff_destroy(kernel);
        errno = ENOMEM;
        return NULL;
    }

    /* Initialize random parameters */
    uint64_t current_seed = seed;
    double sigma = sqrt(2.0 * gamma);

    /* Generate Gaussian random frequencies ω ~ N(0, 2γ) */
    for (size_t i = 0; i < output_dims * input_dims; i++) {
        kernel->omega[i] = generate_gaussian(0.0, sigma, &current_seed);
    }

    /* Generate uniform random biases b ~ U[0, 2π] */
    for (size_t i = 0; i < output_dims; i++) {
        current_seed = (current_seed * 1103515245 + 12345) & 0x7fffffff;
        kernel->bias[i] = (double)current_seed / 0x7fffffff * 2.0 * M_PI;
    }

    return kernel;
}

void qihse_rff_destroy(qihse_rff_kernel_t* kernel) {
    if (!kernel) return;

    free(kernel->omega);
    free(kernel->bias);
    free(kernel);
}

/* ============================================================================
 * RFF PROJECTION OPERATIONS
 * ============================================================================ */

void qihse_rff_project(
    const qihse_rff_kernel_t* kernel,
    const double* input,
    double* output
) {
    if (!kernel || !input || !output) return;

    const double scale = sqrt(2.0 / kernel->output_dims);

    for (size_t d = 0; d < kernel->output_dims; d++) {
        double dot_product = kernel->bias[d];

        /* Compute ω·x + b */
        for (size_t i = 0; i < kernel->input_dims; i++) {
            dot_product += kernel->omega[d * kernel->input_dims + i] * input[i];
        }

        /* Apply random Fourier transform: z(x) = sqrt(2/D) * cos(ω·x + b) */
        output[d] = scale * cos(dot_product);
    }
}

void qihse_rff_project_batch(
    const qihse_rff_kernel_t* kernel,
    const double* inputs,
    double* outputs,
    size_t batch_size
) {
    if (!kernel || !inputs || !outputs || batch_size == 0) return;

    for (size_t b = 0; b < batch_size; b++) {
        const double* input = &inputs[b * kernel->input_dims];
        double* output = &outputs[b * kernel->output_dims];
        qihse_rff_project(kernel, input, output);
    }
}

/* ============================================================================
 * RFF KERNEL PROPERTIES
 * ============================================================================ */

size_t qihse_rff_get_input_dims(const qihse_rff_kernel_t* kernel) {
    return kernel ? kernel->input_dims : 0;
}

size_t qihse_rff_get_output_dims(const qihse_rff_kernel_t* kernel) {
    return kernel ? kernel->output_dims : 0;
}

double qihse_rff_get_gamma(const qihse_rff_kernel_t* kernel) {
    return kernel ? kernel->gamma : 0.0;
}

uint64_t qihse_rff_get_seed(const qihse_rff_kernel_t* kernel) {
    return kernel ? kernel->seed : 0;
}

