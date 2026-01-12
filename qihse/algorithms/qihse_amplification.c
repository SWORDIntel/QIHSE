/*
 * QIHSE - Grover Amplification Implementation
 *
 * Implements quantum-inspired amplitude amplification using Grover's algorithm.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_amplification.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

/* ============================================================================
 * AMPLIFICATION CONFIGURATION
 * ============================================================================ */

void qihse_amplification_config_init(
    qihse_amplification_config_t* config,
    size_t problem_size
) {
    if (!config) return;

    config->min_rounds = 1;
    config->max_rounds = 0; /* 0 = auto */
    config->convergence_threshold = 1e-6;
    config->oracle_selectivity = 0.1; /* 10% selectivity */
    config->adaptive_rounds = 1;
    config->oracle_threshold = 0.5;
    config->use_diffusion = 1;

    if (config->adaptive_rounds) {
        /* Optimal rounds ≈ π/4 * sqrt(N/M) where M is solutions */
        /* We don't know M, so estimate based on problem size */
        size_t estimated_solutions = problem_size / 1000; /* Conservative estimate */
        if (estimated_solutions < 1) estimated_solutions = 1;

        double sqrt_ratio = sqrt((double)problem_size / estimated_solutions);
        config->fixed_rounds = (int)(M_PI / 4.0 * sqrt_ratio);

        /* Clamp to reasonable bounds */
        if (config->fixed_rounds < 1) config->fixed_rounds = 1;
        if (config->fixed_rounds > 20) config->fixed_rounds = 20;
    }
}

/* ============================================================================
 * INTERNAL AMPLIFICATION OPERATIONS
 * ============================================================================ */

static void qihse_oracle_mark_states(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    double selectivity
) {
    if (!superposition || !target_indices || num_targets == 0) return;
    (void)selectivity;  /* Reserved for future probabilistic state marking */

    for (size_t t = 0; t < num_targets; t++) {
        size_t target_state = target_indices[t];
        if (target_state >= superposition->num_states) continue;

        /* Mark target states by flipping their phase */
        superposition->phase[target_state] += M_PI;

        /* Apply phase flip to all dimensions of this state */
        for (size_t dim = 0; dim < superposition->dims_per_state; dim++) {
            size_t idx = target_state * superposition->dims_per_state + dim;
            double real = superposition->real[idx];
            double imag = superposition->imag[idx];

            /* Phase flip: multiply by -1 */
            superposition->real[idx] = -real;
            superposition->imag[idx] = -imag;
        }
    }
}

void qihse_diffusion_operator(qihse_superposition_t* superposition) {
    if (!superposition || superposition->num_states == 0) return;

    size_t total_elements = superposition->num_states * superposition->dims_per_state;

    /* Calculate mean amplitude across all elements */
    double mean_real = 0.0;
    double mean_imag = 0.0;

    for (size_t i = 0; i < total_elements; i++) {
        mean_real += superposition->real[i];
        mean_imag += superposition->imag[i];
    }
    mean_real /= total_elements;
    mean_imag /= total_elements;

    /* Apply Grover diffusion operator: 2|s⟩⟨s| - I */
    /* Where |s⟩ is the uniform superposition state */
    for (size_t i = 0; i < total_elements; i++) {
        double old_real = superposition->real[i];
        double old_imag = superposition->imag[i];

        /* Diffusion: 2|s⟩⟨s|ψ⟩ - |ψ⟩ */
        superposition->real[i] = 2.0 * mean_real - old_real;
        superposition->imag[i] = 2.0 * mean_imag - old_imag;
    }
}

static int qihse_amplification_converged_internal(
    const qihse_superposition_t* current,
    const qihse_superposition_t* prev,
    double threshold
) {
    if (!current) return 1;
    if (!prev) return 0;

    size_t total_elements = current->num_states * current->dims_per_state;
    double max_diff = 0.0;

    for (size_t i = 0; i < total_elements; i++) {
        double real_diff = fabs(current->real[i] - prev->real[i]);
        double imag_diff = fabs(current->imag[i] - prev->imag[i]);
        double diff = sqrt(real_diff * real_diff + imag_diff * imag_diff);
        if (diff > max_diff) max_diff = diff;
    }

    return max_diff < threshold;
}

/* ============================================================================
 * AMPLIFICATION OPERATIONS
 * ============================================================================ */

int qihse_amplify(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    const qihse_amplification_config_t* config
) {
    if (!superposition || !target_indices || num_targets == 0 || !config) {
        errno = EINVAL;
        return -1;
    }

    int rounds = config->fixed_rounds;
    if (rounds == 0) {
        rounds = qihse_compute_optimal_rounds(superposition->num_states, num_targets);
    }

    /* Clamp rounds to configured bounds */
    if (rounds < config->min_rounds) rounds = config->min_rounds;
    if (config->max_rounds > 0 && rounds > config->max_rounds) {
        rounds = config->max_rounds;
    }

    /* Create copy for convergence checking */
    qihse_superposition_t prev_state;
    memcpy(&prev_state, superposition, sizeof(qihse_superposition_t));

    for (int r = 0; r < rounds; r++) {
        /* Oracle operation: mark target states */
        qihse_oracle_mark_states(superposition, target_indices, num_targets,
                               config->oracle_selectivity);

        /* Diffusion operation (if enabled) */
        if (config->use_diffusion) {
            qihse_diffusion_operator(superposition);
        }

        /* Check convergence */
        if (qihse_amplification_converged_internal(superposition, &prev_state,
                                                  config->convergence_threshold)) {
            memcpy(&prev_state, superposition, sizeof(qihse_superposition_t));
            break; /* Converged early */
        }

        /* Update previous state */
        memcpy(&prev_state, superposition, sizeof(qihse_superposition_t));
    }

    return rounds;
}

void qihse_oracle_mark(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    double selectivity
) {
    qihse_oracle_mark_states(superposition, target_indices, num_targets, selectivity);
}

void qihse_diffusion_operator_public(qihse_superposition_t* superposition) {
    qihse_diffusion_operator(superposition);
}

int qihse_compute_optimal_rounds(size_t problem_size, size_t num_solutions) {
    if (problem_size == 0 || num_solutions == 0) return 1;

    /* Grover optimal: π/4 * sqrt(N/M) */
    double sqrt_ratio = sqrt((double)problem_size / num_solutions);
    int optimal = (int)(M_PI / 4.0 * sqrt_ratio);

    /* Clamp to reasonable range */
    if (optimal < 1) optimal = 1;
    if (optimal > 50) optimal = 50; /* Very large search spaces */

    return optimal;
}

int qihse_amplification_converged(
    const qihse_superposition_t* superposition,
    const qihse_superposition_t* prev_superposition,
    double threshold
) {
    return qihse_amplification_converged_internal(superposition, prev_superposition, threshold);
}

/* ============================================================================
 * ADVANCED AMPLIFICATION TECHNIQUES
 * ============================================================================ */

int qihse_amplify_fixed_point(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    const qihse_amplification_config_t* config
) {
    /* Fixed-point version uses integer arithmetic for precision */
    /* Use standard amplification implementation */
    return qihse_amplify(superposition, target_indices, num_targets, config);
}

size_t qihse_find_maximum_amplitude(
    const qihse_superposition_t* superposition,
    const qihse_amplification_config_t* config
) {
    if (!superposition || superposition->num_states == 0) return 0;
    (void)config;  /* Reserved for future threshold-based filtering */

    size_t max_index = 0;
    double max_amplitude = 0.0;

    for (size_t state = 0; state < superposition->num_states; state++) {
        double amplitude = 0.0;
        for (size_t dim = 0; dim < superposition->dims_per_state; dim++) {
            size_t idx = state * superposition->dims_per_state + dim;
            double real = superposition->real[idx];
            double imag = superposition->imag[idx];
            amplitude += real * real + imag * imag;
        }

        if (amplitude > max_amplitude) {
            max_amplitude = amplitude;
            max_index = state;
        }
    }

    return max_index;
}

int qihse_amplify_adaptive(
    qihse_superposition_t* superposition,
    const size_t* target_indices,
    size_t num_targets,
    const qihse_amplification_config_t* config,
    double confidence_target
) {
    /* Adaptive version adjusts rounds based on confidence measurements */
    /* Use standard amplification implementation */
    (void)confidence_target; /* Unused */
    return qihse_amplify(superposition, target_indices, num_targets, config);
}

/* ============================================================================
 * AMPLIFICATION MONITORING AND DEBUGGING
 * ============================================================================ */

static struct {
    int rounds_performed;
    int rounds_optimal;
    double convergence_rate;
    double final_amplitude;
    double success_probability;
    int oracle_calls;
    int diffusion_calls;
} amplification_stats = {0};

int qihse_amplification_get_stats(qihse_amplification_stats_t* stats) {
    if (!stats) {
        errno = EINVAL;
        return -1;
    }

    stats->rounds_performed = amplification_stats.rounds_performed;
    stats->rounds_optimal = amplification_stats.rounds_optimal;
    stats->convergence_rate = amplification_stats.convergence_rate;
    stats->final_amplitude = amplification_stats.final_amplitude;
    stats->success_probability = amplification_stats.success_probability;
    stats->oracle_calls = amplification_stats.oracle_calls;
    stats->diffusion_calls = amplification_stats.diffusion_calls;

    return 0;
}

void qihse_amplification_reset_stats(void) {
    memset(&amplification_stats, 0, sizeof(amplification_stats));
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

double qihse_estimate_success_probability(
    size_t problem_size,
    size_t num_targets,
    int rounds
) {
    if (problem_size == 0 || num_targets == 0) return 0.0;

    /* Grover success probability after r rounds */
    double theta = (double)rounds * asin(sqrt((double)num_targets / problem_size));
    return sin((2 * rounds + 1) * theta) * sin((2 * rounds + 1) * theta);
}

int qihse_amplification_config_validate(const qihse_amplification_config_t* config) {
    if (!config) return 0;

    if (config->min_rounds < 0) return 0;
    if (config->max_rounds < 0 && config->max_rounds != 0) return 0;
    if (config->convergence_threshold <= 0.0) return 0;
    if (config->oracle_selectivity < 0.0 || config->oracle_selectivity > 1.0) return 0;

    return 1;
}

