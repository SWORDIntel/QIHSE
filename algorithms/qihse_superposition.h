/*
 * QIHSE - Superposition State Encoding
 *
 * Quantum-inspired superposition encoding with phase entanglement.
 * Encodes search problems into higher-dimensional Hilbert space.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_SUPERPOSITION_H
#define QIHSE_SUPERPOSITION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * SUPERPOSITION STRUCTURE
 * ============================================================================ */

/**
 * Quantum superposition state representation.
 *
 * Represents a quantum state |ψ⟩ = Σᵢ αᵢ |i⟩ where αᵢ are complex amplitudes.
 * In classical terms, this is stored as real/imaginary components with phases.
 */
typedef struct qihse_superposition_s {
    double* real;               /* Real amplitude components [num_states] */
    double* imag;               /* Imaginary amplitude components [num_states] */
    double* phase;              /* Per-element phase angles [num_states] in radians */
    size_t num_states;          /* Number of superposition states */
    size_t dims_per_state;      /* Dimensions per quantum state */
    double global_phase;        /* Global quantum phase offset */
    double measurement_confidence; /* Confidence in quantum measurement */

    /* Internal state */
    void* internal_state;       /* Backend-specific state (if needed) */
} qihse_superposition_t;

/* ============================================================================
 * SUPERPOSITION CREATION AND MANAGEMENT
 * ============================================================================ */

/**
 * Create quantum superposition from RFF-projected data.
 *
 * Encodes search problem into higher-dimensional Hilbert space with
 * phase entanglement between dimensions.
 *
 * @param rff_data RFF-projected array [n * rff_dims]
 * @param n Number of elements in original array
 * @param rff_dims RFF output dimensions
 * @param superposition Output superposition structure (must be allocated)
 * @return 0 on success, negative error code on failure
 */
int qihse_create_superposition(
    const double* rff_data,
    size_t n,
    size_t rff_dims,
    qihse_superposition_t* superposition
);

/**
 * Create superposition from raw complex amplitudes.
 *
 * @param real Real amplitudes [num_states]
 * @param imag Imaginary amplitudes [num_states]
 * @param num_states Number of states
 * @param superposition Output superposition structure
 * @return 0 on success, negative error code on failure
 */
int qihse_create_superposition_from_amplitudes(
    const double* real,
    const double* imag,
    size_t num_states,
    qihse_superposition_t* superposition
);

/**
 * Destroy superposition structure and free resources.
 *
 * @param superposition Structure to destroy
 */
void qihse_destroy_superposition(qihse_superposition_t* superposition);

/* ============================================================================
 * SUPERPOSITION OPERATIONS
 * ============================================================================ */

/**
 * Normalize superposition amplitudes.
 *
 * Ensures Σᵢ |αᵢ|² = 1 (quantum state normalization).
 *
 * @param superposition Superposition to normalize
 * @return 0 on success, negative error code on failure
 */
int qihse_superposition_normalize(qihse_superposition_t* superposition);

/**
 * Apply global phase shift to superposition.
 *
 * |ψ⟩ → e^(iθ) |ψ⟩
 *
 * @param superposition Superposition to modify
 * @param phase_shift Phase shift in radians
 */
void qihse_superposition_apply_phase(
    qihse_superposition_t* superposition,
    double phase_shift
);

/**
 * Compute superposition fidelity with another state.
 *
 * Fidelity F = |⟨ψ|φ⟩|²
 *
 * @param a First superposition
 * @param b Second superposition
 * @return Fidelity value between 0.0 and 1.0
 */
double qihse_superposition_fidelity(
    const qihse_superposition_t* a,
    const qihse_superposition_t* b
);

/**
 * Extract probability amplitudes from superposition.
 *
 * Pᵢ = |αᵢ|²
 *
 * @param superposition Input superposition
 * @param probabilities Output probabilities [num_states]
 */
void qihse_superposition_get_probabilities(
    const qihse_superposition_t* superposition,
    double* probabilities
);

/* ============================================================================
 * SUPERPOSITION MEASUREMENT
 * ============================================================================ */

/**
 * Perform quantum measurement on superposition.
 *
 * Collapses superposition to a single state based on probability amplitudes.
 *
 * @param superposition Superposition to measure
 * @param random_seed Random seed for reproducible measurements
 * @return Index of measured state (0 to num_states-1)
 */
size_t qihse_superposition_measure(
    const qihse_superposition_t* superposition,
    uint64_t random_seed
);

/**
 * Perform multiple measurements on superposition.
 *
 * @param superposition Superposition to measure
 * @param measurements Output measurement results [num_measurements]
 * @param num_measurements Number of measurements to perform
 * @param random_seed Random seed for reproducible results
 */
void qihse_superposition_measure_multiple(
    const qihse_superposition_t* superposition,
    size_t* measurements,
    size_t num_measurements,
    uint64_t random_seed
);

/* ============================================================================
 * SUPERPOSITION PROPERTIES
 * ============================================================================ */

/**
 * Get number of states in superposition.
 *
 * @param superposition Superposition
 * @return Number of states
 */
size_t qihse_superposition_get_num_states(const qihse_superposition_t* superposition);

/**
 * Get dimensions per state.
 *
 * @param superposition Superposition
 * @return Dimensions per state
 */
size_t qihse_superposition_get_dims_per_state(const qihse_superposition_t* superposition);

/**
 * Get global phase of superposition.
 *
 * @param superposition Superposition
 * @return Global phase in radians
 */
double qihse_superposition_get_global_phase(const qihse_superposition_t* superposition);

/**
 * Get measurement confidence.
 *
 * @param superposition Superposition
 * @return Confidence value (0.0 to 1.0)
 */
double qihse_superposition_get_measurement_confidence(const qihse_superposition_t* superposition);

/**
 * Check if superposition is properly normalized.
 *
 * @param superposition Superposition to check
 * @return 1 if normalized, 0 if not
 */
int qihse_superposition_is_normalized(const qihse_superposition_t* superposition);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_SUPERPOSITION_H */

