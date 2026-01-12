/*
 * QIHSE - Superposition State Encoding Implementation
 *
 * Implements quantum-inspired superposition encoding with phase entanglement.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_superposition.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

/* ============================================================================
 * SUPERPOSITION CREATION AND MANAGEMENT
 * ============================================================================ */

int qihse_create_superposition(
    const double* rff_data,
    size_t n,
    size_t rff_dims,
    qihse_superposition_t* superposition
) {
    if (!rff_data || n == 0 || rff_dims == 0 || !superposition) {
        errno = EINVAL;
        return -1;
    }

    /* Initialize superposition structure */
    memset(superposition, 0, sizeof(qihse_superposition_t));
    superposition->num_states = n;
    superposition->dims_per_state = rff_dims;
    superposition->global_phase = 0.0;
    superposition->measurement_confidence = 0.0;

    /* Allocate superposition arrays */
    size_t total_elements = n * rff_dims;
    superposition->real = malloc(total_elements * sizeof(double));
    superposition->imag = malloc(total_elements * sizeof(double));
    superposition->phase = malloc(n * sizeof(double));

    if (!superposition->real || !superposition->imag || !superposition->phase) {
        qihse_destroy_superposition(superposition);
        errno = ENOMEM;
        return -1;
    }

    /* Encode RFF data into quantum superposition states */
    for (size_t state = 0; state < n; state++) {
        const double* rff_vector = &rff_data[state * rff_dims];
        superposition->phase[state] = 0.0;

        /* Phase encoding with entanglement */
        for (size_t dim = 0; dim < rff_dims; dim++) {
            size_t idx = state * rff_dims + dim;
            double amplitude = rff_vector[dim];

            /* Create phase entanglement between dimensions */
            double state_phase = 2.0 * M_PI * (double)state / n;
            double dim_phase = 2.0 * M_PI * (double)dim / rff_dims;
            double entanglement_phase = state_phase + dim_phase;

            /* Encode as complex amplitude */
            superposition->real[idx] = amplitude * cos(entanglement_phase);
            superposition->imag[idx] = amplitude * sin(entanglement_phase);
        }
    }

    return 0;
}

int qihse_create_superposition_from_amplitudes(
    const double* real,
    const double* imag,
    size_t num_states,
    qihse_superposition_t* superposition
) {
    if (!real || !imag || num_states == 0 || !superposition) {
        errno = EINVAL;
        return -1;
    }

    /* Initialize superposition structure */
    memset(superposition, 0, sizeof(qihse_superposition_t));
    superposition->num_states = num_states;
    superposition->dims_per_state = 1; /* Single amplitude per state */
    superposition->global_phase = 0.0;
    superposition->measurement_confidence = 0.0;

    /* Allocate superposition arrays */
    superposition->real = malloc(num_states * sizeof(double));
    superposition->imag = malloc(num_states * sizeof(double));
    superposition->phase = malloc(num_states * sizeof(double));

    if (!superposition->real || !superposition->imag || !superposition->phase) {
        qihse_destroy_superposition(superposition);
        errno = ENOMEM;
        return -1;
    }

    /* Copy amplitudes and compute phases */
    for (size_t i = 0; i < num_states; i++) {
        superposition->real[i] = real[i];
        superposition->imag[i] = imag[i];
        superposition->phase[i] = atan2(imag[i], real[i]);
    }

    return 0;
}

void qihse_destroy_superposition(qihse_superposition_t* superposition) {
    if (!superposition) return;

    free(superposition->real);
    free(superposition->imag);
    free(superposition->phase);

    memset(superposition, 0, sizeof(qihse_superposition_t));
}

/* ============================================================================
 * SUPERPOSITION OPERATIONS
 * ============================================================================ */

int qihse_superposition_normalize(qihse_superposition_t* superposition) {
    if (!superposition || superposition->num_states == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t total_elements = superposition->num_states * superposition->dims_per_state;

    /* Calculate normalization factor */
    double norm_squared = 0.0;
    for (size_t i = 0; i < total_elements; i++) {
        double real = superposition->real[i];
        double imag = superposition->imag[i];
        norm_squared += real * real + imag * imag;
    }

    if (norm_squared == 0.0) {
        errno = EDOM; /* Division by zero */
        return -1;
    }

    double norm_factor = 1.0 / sqrt(norm_squared);

    /* Normalize amplitudes */
    for (size_t i = 0; i < total_elements; i++) {
        superposition->real[i] *= norm_factor;
        superposition->imag[i] *= norm_factor;
    }

    /* Update measurement confidence */
    superposition->measurement_confidence = 1.0 / sqrt(norm_squared);

    return 0;
}

void qihse_superposition_apply_phase(
    qihse_superposition_t* superposition,
    double phase_shift
) {
    if (!superposition) return;

    superposition->global_phase += phase_shift;

    /* Apply phase shift to all elements */
    size_t total_elements = superposition->num_states * superposition->dims_per_state;
    for (size_t i = 0; i < total_elements; i++) {
        double real = superposition->real[i];
        double imag = superposition->imag[i];
        double cos_phase = cos(phase_shift);
        double sin_phase = sin(phase_shift);

        superposition->real[i] = real * cos_phase - imag * sin_phase;
        superposition->imag[i] = real * sin_phase + imag * cos_phase;
    }
}

double qihse_superposition_fidelity(
    const qihse_superposition_t* a,
    const qihse_superposition_t* b
) {
    if (!a || !b || a->num_states != b->num_states ||
        a->dims_per_state != b->dims_per_state) {
        return 0.0;
    }

    size_t total_elements = a->num_states * a->dims_per_state;
    double fidelity = 0.0;

    /* Compute |⟨ψ|φ⟩|² */
    for (size_t i = 0; i < total_elements; i++) {
        double real_overlap = a->real[i] * b->real[i] + a->imag[i] * b->imag[i];
        double imag_overlap = a->real[i] * b->imag[i] - a->imag[i] * b->real[i];
        fidelity += real_overlap * real_overlap + imag_overlap * imag_overlap;
    }

    return fidelity;
}

void qihse_superposition_get_probabilities(
    const qihse_superposition_t* superposition,
    double* probabilities
) {
    if (!superposition || !probabilities) return;

    for (size_t state = 0; state < superposition->num_states; state++) {
        double prob = 0.0;
        for (size_t dim = 0; dim < superposition->dims_per_state; dim++) {
            size_t idx = state * superposition->dims_per_state + dim;
            double real = superposition->real[idx];
            double imag = superposition->imag[idx];
            prob += real * real + imag * imag;
        }
        probabilities[state] = prob;
    }
}

/* ============================================================================
 * SUPERPOSITION MEASUREMENT
 * ============================================================================ */

size_t qihse_superposition_measure(
    const qihse_superposition_t* superposition,
    uint64_t random_seed
) {
    if (!superposition || superposition->num_states == 0) {
        return 0;
    }

    /* Get probability distribution */
    double* probabilities = malloc(superposition->num_states * sizeof(double));
    if (!probabilities) return 0;

    qihse_superposition_get_probabilities(superposition, probabilities);

    /* Normalize probabilities to ensure they sum to 1 */
    double total_prob = 0.0;
    for (size_t i = 0; i < superposition->num_states; i++) {
        total_prob += probabilities[i];
    }

    if (total_prob == 0.0) {
        free(probabilities);
        return 0; /* All zero probabilities */
    }

    /* Perform measurement using random seed */
    double rand_val = (double)(random_seed % 1000000) / 1000000.0;
    double cumulative = 0.0;

    for (size_t i = 0; i < superposition->num_states; i++) {
        cumulative += probabilities[i] / total_prob;
        if (rand_val <= cumulative) {
            free(probabilities);
            return i;
        }
    }

    free(probabilities);
    return superposition->num_states - 1; /* Fallback */
}

void qihse_superposition_measure_multiple(
    const qihse_superposition_t* superposition,
    size_t* measurements,
    size_t num_measurements,
    uint64_t random_seed
) {
    if (!superposition || !measurements || num_measurements == 0) return;

    for (size_t i = 0; i < num_measurements; i++) {
        uint64_t measurement_seed = random_seed + i;
        measurements[i] = qihse_superposition_measure(superposition, measurement_seed);
    }
}

/* ============================================================================
 * SUPERPOSITION PROPERTIES
 * ============================================================================ */

size_t qihse_superposition_get_num_states(const qihse_superposition_t* superposition) {
    return superposition ? superposition->num_states : 0;
}

size_t qihse_superposition_get_dims_per_state(const qihse_superposition_t* superposition) {
    return superposition ? superposition->dims_per_state : 0;
}

double qihse_superposition_get_global_phase(const qihse_superposition_t* superposition) {
    return superposition ? superposition->global_phase : 0.0;
}

double qihse_superposition_get_measurement_confidence(const qihse_superposition_t* superposition) {
    return superposition ? superposition->measurement_confidence : 0.0;
}

int qihse_superposition_is_normalized(const qihse_superposition_t* superposition) {
    if (!superposition) return 0;

    size_t total_elements = superposition->num_states * superposition->dims_per_state;
    double norm_squared = 0.0;

    for (size_t i = 0; i < total_elements; i++) {
        double real = superposition->real[i];
        double imag = superposition->imag[i];
        norm_squared += real * real + imag * imag;
    }

    /* Check if norm is close to 1.0 */
    return fabs(norm_squared - 1.0) < 1e-6;
}

