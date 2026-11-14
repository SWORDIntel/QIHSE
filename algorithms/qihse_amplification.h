/*
 * QIHSE - Grover Amplification Implementation
 *
 * Quantum-inspired amplitude amplification using Grover's algorithm.
 * Amplifies target state amplitudes through iterative phase rotations.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_AMPLIFICATION_H
#define QIHSE_AMPLIFICATION_H

#include "../include/qihse_math_types.h"

#include "qihse_superposition.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * AMPLIFICATION CONFIGURATION
 * ============================================================================ */

/**
 * Grover amplification configuration.
 * Controls the amplitude amplification process.
 */
/* ABI-stable definitions are shared with the installed public headers. */

/**
 * Initialize amplification config with smart defaults.
 *
 * @param config Config structure to initialize
 * @param problem_size Size of search problem (affects round count)
 */
void qihse_amplification_config_init(
    qihse_amplification_config_t* config,
    size_t problem_size
);

/* ============================================================================
 * AMPLIFICATION OPERATIONS
 * ============================================================================ */

/**
 * Perform Grover amplitude amplification on superposition.
 *
 * Amplifies target state amplitudes through iterative phase rotations.
 * Implements the core Grover iteration: Oracle → Diffusion → Measure
 *
 * @param superposition Superposition to amplify (modified in-place)
 * @param target_indices Array of target state indices to amplify
 * @param num_targets Number of target states
 * @param config Amplification configuration
 * @return Number of rounds performed, or negative error code
 */
int qihse_amplify(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    const qihse_amplification_config_t* config
);

/**
 * Apply oracle operator to mark target states.
 *
 * Flips the phase of target states: |ψ⟩ → Oracle|ψ⟩
 *
 * @param superposition Superposition to modify
 * @param target_indices Array of target state indices
 * @param num_targets Number of target states
 * @param selectivity How strictly to mark targets (0.0 = mark all, 1.0 = mark exact)
 */
void qihse_oracle_mark(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    double selectivity
);

/**
 * Apply diffusion operator (Grover diffusion).
 *
 * Implements the inversion about the mean: |ψ⟩ → 2|s⟩⟨s| - I|ψ⟩
 * where |s⟩ is the uniform superposition state.
 *
 * @param superposition Superposition to modify
 */
void qihse_diffusion_operator(qihse_superposition_t* superposition);

/**
 * Compute optimal number of Grover rounds.
 *
 * Based on problem size N and number of solutions M:
 * Uniform-state optimum uses theta=asin(sqrt(M/N)); the materialized
 * simulator caps the returned count at 50. Invalid counts return -1.
 *
 * @param problem_size Total search space size (N)
 * @param num_solutions Expected number of solutions (M)
 * @return Optimal number of rounds
 */
int qihse_compute_optimal_rounds(size_t problem_size, size_t num_solutions);

/**
 * Check if amplification has converged.
 *
 * @param superposition Current superposition state
 * @param prev_superposition Previous iteration state (can be NULL)
 * @param threshold Convergence threshold
 * @return 1 if converged, 0 if not
 */
int qihse_amplification_converged(
    const qihse_superposition_t* superposition,
    const qihse_superposition_t* prev_superposition,
    double threshold
);

/* ============================================================================
 * ADVANCED AMPLIFICATION TECHNIQUES
 * ============================================================================ */

/**
 * Fixed-point amplitude amplification.
 *
 * Reserved API: returns -1 with errno=ENOTSUP. Ordinary Grover rotations
 * are not a fixed-point amplification algorithm.
 *
 * @param superposition Superposition to amplify
 * @param target_indices Target state indices
 * @param num_targets Number of targets
 * @param config Amplification config
 * @return Number of rounds performed
 */
int qihse_amplify_fixed_point(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    const qihse_amplification_config_t* config
);

/**
 * Quantum-inspired maximum finding.
 *
 * Finds the state with maximum amplitude using amplitude estimation.
 *
 * @param superposition Superposition to analyze
 * @param config Amplification config
 * @return Index of state with maximum amplitude
 */
size_t qihse_find_maximum_amplitude(
    const qihse_superposition_t* superposition,
    const qihse_amplification_config_t* config
);

/**
 * Adaptive amplification with confidence bounds.
 *
 * Adjusts amplification rounds based on measurement confidence.
 *
 * @param superposition Superposition to amplify
 * @param target_indices Target state indices
 * @param num_targets Number of targets
 * @param config Amplification config
 * @param confidence_target Target confidence level (0.0-1.0)
 * @return Number of rounds performed
 */
int qihse_amplify_adaptive(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    const qihse_amplification_config_t* config,
    double confidence_target
);

/* ============================================================================
 * AMPLIFICATION MONITORING AND DEBUGGING
 * ============================================================================ */

/**
 * Amplification statistics structure.
 */
typedef struct qihse_amplification_stats_s {
    int rounds_performed;       /* Actual rounds executed */
    int rounds_optimal;         /* Theoretically optimal rounds */
    double convergence_rate;    /* How quickly it converged */
    double final_amplitude;     /* Final target amplitude */
    double success_probability; /* Probability of measuring target */
    int oracle_calls;           /* Number of oracle applications */
    int diffusion_calls;        /* Number of diffusion applications */
} qihse_amplification_stats_t;

/**
 * Get statistics from last amplification operation.
 *
 * @param stats Output statistics structure
 * @return 0 on success, negative error code on failure
 */
int qihse_amplification_get_stats(qihse_amplification_stats_t* stats);

/**
 * Reset amplification statistics.
 */
void qihse_amplification_reset_stats(void);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Estimate amplification success probability.
 *
 * @param problem_size Total search space size
 * @param num_targets Number of target states
 * @param rounds Number of amplification rounds
 * @return Estimated success probability
 */
double qihse_estimate_success_probability(
    size_t problem_size,
    size_t num_targets,
    int rounds
);

/**
 * Validate amplification configuration.
 *
 * @param config Configuration to validate
 * @return 1 if valid, 0 if invalid
 */
int qihse_amplification_config_validate(const qihse_amplification_config_t* config);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_AMPLIFICATION_H */

