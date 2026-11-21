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

/* Per-construction state: odd-sized kernels and concurrent callers cannot
 * share the Box-Muller spare sample. */
typedef struct { uint64_t seed; int has_spare; double spare; } rff_rng_t;
static uint64_t random_word(rff_rng_t *rng) {
    uint64_t z = (rng->seed += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}
static double uniform(rff_rng_t *rng) { return (double)(random_word(rng) >> 11) * 0x1.0p-53; }
static double generate_gaussian(double mu, double sigma, rff_rng_t* rng) {

    if (rng->has_spare) {
        rng->has_spare = 0;
        return rng->spare * sigma + mu;
    }

    rng->has_spare = 1;
    double u, v, s;
    do {
        u = uniform(rng) * 2.0 - 1.0;
        v = uniform(rng) * 2.0 - 1.0;

        s = u * u + v * v;
    } while (s >= 1.0 || s == 0.0);

    s = sqrt(-2.0 * log(s) / s);
    rng->spare = v * s;
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
    if (input_dims == 0 || output_dims == 0 || !isfinite(gamma) || gamma <= 0.0) {
        errno = EINVAL;
        return NULL;
    }

    if (output_dims > SIZE_MAX / input_dims ||
        output_dims * input_dims > SIZE_MAX / sizeof(double)) {
        errno = EOVERFLOW;
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
    rff_rng_t rng = {seed, 0, 0.0};
    double sigma = sqrt(gamma) * sqrt(2.0);

    /* Generate Gaussian random frequencies ω ~ N(0, 2γ) */
    for (size_t i = 0; i < output_dims * input_dims; i++) {
        kernel->omega[i] = generate_gaussian(0.0, sigma, &rng);
    }

    /* Generate uniform random biases b ~ U[0, 2π] */
    for (size_t i = 0; i < output_dims; i++) {
        kernel->bias[i] = uniform(&rng) * 2.0 * M_PI;
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

