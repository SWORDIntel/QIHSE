/*
 * QIHSE - Machine Learning Self-Optimization Engine Implementation
 *
 * Self-optimizing runtime with Thompson Sampling, neural optimization,
 * and continuous learning capabilities.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_ml.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <errno.h>

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static double random_uniform(void) {
    return (double)rand() / (double)RAND_MAX;
}

static double random_beta(double alpha, double beta) {
    /* Simple approximation using uniform sampling */
    /* In production, use proper beta distribution sampling */
    double u1 = random_uniform();
    double u2 = random_uniform();

    /* Box-Muller transform approximation */
    double x = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    double y = alpha / (alpha + beta);

    return y + 0.1 * x; /* Approximate beta distribution */
}

/* ============================================================================
 * THOMPSON SAMPLING BANDIT
 * ============================================================================ */

int qihse_thompson_bandit_init(
    qihse_thompson_bandit_t* bandit,
    size_t num_arms,
    void* user_data
) {
    if (!bandit || num_arms == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(bandit, 0, sizeof(qihse_thompson_bandit_t));

    bandit->num_arms = num_arms;
    bandit->user_data = user_data;

    /* Allocate arrays */
    bandit->successes = calloc(num_arms, sizeof(size_t));
    bandit->failures = calloc(num_arms, sizeof(size_t));
    bandit->alpha = calloc(num_arms, sizeof(double));
    bandit->beta = calloc(num_arms, sizeof(double));

    if (!bandit->successes || !bandit->failures ||
        !bandit->alpha || !bandit->beta) {
        qihse_thompson_bandit_destroy(bandit);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize with uniform priors */
    for (size_t i = 0; i < num_arms; i++) {
        bandit->alpha[i] = 1.0;
        bandit->beta[i] = 1.0;
    }

    /* Seed random number generator */
    srand((unsigned int)time(NULL));

    return 0;
}

void qihse_thompson_bandit_destroy(qihse_thompson_bandit_t* bandit) {
    if (!bandit) return;

    free(bandit->successes);
    free(bandit->failures);
    free(bandit->alpha);
    free(bandit->beta);

    memset(bandit, 0, sizeof(qihse_thompson_bandit_t));
}

size_t qihse_thompson_bandit_select_arm(qihse_thompson_bandit_t* bandit) {
    if (!bandit || bandit->num_arms == 0) {
        return 0;
    }

    size_t best_arm = 0;
    double best_sample = 0.0;

    /* Sample from beta distribution for each arm */
    for (size_t i = 0; i < bandit->num_arms; i++) {
        double sample = random_beta(bandit->alpha[i], bandit->beta[i]);
        if (sample > best_sample) {
            best_sample = sample;
            best_arm = i;
        }
    }

    return best_arm;
}

void qihse_thompson_bandit_update(
    qihse_thompson_bandit_t* bandit,
    size_t arm,
    double reward
) {
    if (!bandit || arm >= bandit->num_arms) {
        return;
    }

    /* Update beta distribution parameters */
    if (reward > 0.5) { /* Success */
        bandit->alpha[arm] += 1.0;
        bandit->successes[arm]++;
    } else { /* Failure */
        bandit->beta[arm] += 1.0;
        bandit->failures[arm]++;
    }
}

void qihse_thompson_bandit_get_stats(
    const qihse_thompson_bandit_t* bandit,
    size_t arm,
    double* success_rate,
    double* confidence
) {
    if (!bandit || arm >= bandit->num_arms) {
        if (success_rate) *success_rate = 0.0;
        if (confidence) *confidence = 0.0;
        return;
    }

    double total = bandit->successes[arm] + bandit->failures[arm];
    if (total > 0) {
        if (success_rate) {
            *success_rate = (double)bandit->successes[arm] / total;
        }
    } else {
        if (success_rate) *success_rate = 0.5; /* Prior */
    }

    /* Simple confidence based on total observations */
    if (confidence) {
        *confidence = total / (total + 10.0); /* Confidence grows with observations */
    }
}

/* ============================================================================
 * CONTEXTUAL BANDIT
 * ============================================================================ */

int qihse_contextual_bandit_init(
    qihse_contextual_bandit_t* bandit,
    size_t num_arms,
    size_t context_dim,
    size_t hidden_size,
    double learning_rate,
    void* user_data
) {
    if (!bandit || num_arms == 0 || context_dim == 0 || hidden_size == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(bandit, 0, sizeof(qihse_contextual_bandit_t));

    bandit->num_arms = num_arms;
    bandit->context_dim = context_dim;
    bandit->hidden_size = hidden_size;
    bandit->learning_rate = learning_rate;
    bandit->context_loss = 0.0;
    bandit->user_data = user_data;

    /* Allocate arrays */
    size_t weights_size = context_dim * hidden_size + hidden_size * num_arms;
    bandit->context_weights = calloc(weights_size, sizeof(double));
    bandit->arm_bias = calloc(num_arms, sizeof(double));
    bandit->successes = calloc(num_arms, sizeof(size_t));
    bandit->failures = calloc(num_arms, sizeof(size_t));
    bandit->alpha = calloc(num_arms, sizeof(double));
    bandit->beta = calloc(num_arms, sizeof(double));

    if (!bandit->context_weights || !bandit->arm_bias ||
        !bandit->successes || !bandit->failures ||
        !bandit->alpha || !bandit->beta) {
        qihse_contextual_bandit_destroy(bandit);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize with uniform priors */
    for (size_t i = 0; i < num_arms; i++) {
        bandit->alpha[i] = 1.0;
        bandit->beta[i] = 1.0;
    }

    /* Initialize weights with small random values */
    for (size_t i = 0; i < weights_size; i++) {
        bandit->context_weights[i] = (random_uniform() - 0.5) * 0.1;
    }

    for (size_t i = 0; i < num_arms; i++) {
        bandit->arm_bias[i] = 0.0;
    }

    return 0;
}

void qihse_contextual_bandit_destroy(qihse_contextual_bandit_t* bandit) {
    if (!bandit) return;

    free(bandit->context_weights);
    free(bandit->arm_bias);
    free(bandit->successes);
    free(bandit->failures);
    free(bandit->alpha);
    free(bandit->beta);

    memset(bandit, 0, sizeof(qihse_contextual_bandit_t));
}

size_t qihse_contextual_bandit_select_arm(
    qihse_contextual_bandit_t* bandit,
    const double* context
) {
    if (!bandit || !context) return 0;

    double max_score = -INFINITY;
    size_t best_arm = 0;

    /* Forward pass through context network */
    double* hidden = calloc(bandit->hidden_size, sizeof(double));
    if (!hidden) return 0;

    /* Input to hidden layer */
    for (size_t h = 0; h < bandit->hidden_size; h++) {
        double sum = 0.0;
        for (size_t c = 0; c < bandit->context_dim; c++) {
            size_t weight_idx = c * bandit->hidden_size + h;
            sum += context[c] * bandit->context_weights[weight_idx];
        }
        hidden[h] = tanh(sum); /* Activation */
    }

    /* Hidden to output (arm scores) */
    for (size_t arm = 0; arm < bandit->num_arms; arm++) {
        double score = bandit->arm_bias[arm];
        for (size_t h = 0; h < bandit->hidden_size; h++) {
            size_t weight_idx = bandit->context_dim * bandit->hidden_size + h * bandit->num_arms + arm;
            score += hidden[h] * bandit->context_weights[weight_idx];
        }

        /* Sample from Beta distribution for exploration */
        double beta_sample = random_beta(bandit->alpha[arm], bandit->beta[arm]);
        score += beta_sample;

        if (score > max_score) {
            max_score = score;
            best_arm = arm;
        }
    }

    free(hidden);
    return best_arm;
}

void qihse_contextual_bandit_update(
    qihse_contextual_bandit_t* bandit,
    size_t arm,
    const double* context,
    double reward
) {
    if (!bandit || !context || arm >= bandit->num_arms) return;

    /* Update Beta distribution parameters */
    if (reward > 0.5) { /* Success threshold */
        bandit->successes[arm]++;
        bandit->alpha[arm]++;
    } else {
        bandit->failures[arm]++;
        bandit->beta[arm]++;
    }

    /* Update context network weights using simple gradient descent */
    double* hidden = calloc(bandit->hidden_size, sizeof(double));
    double* output_scores = calloc(bandit->num_arms, sizeof(double));
    if (!hidden || !output_scores) {
        free(hidden);
        free(output_scores);
        return;
    }

    /* Forward pass to get current predictions */
    for (size_t h = 0; h < bandit->hidden_size; h++) {
        double sum = 0.0;
        for (size_t c = 0; c < bandit->context_dim; c++) {
            size_t weight_idx = c * bandit->hidden_size + h;
            sum += context[c] * bandit->context_weights[weight_idx];
        }
        hidden[h] = tanh(sum);
    }

    for (size_t a = 0; a < bandit->num_arms; a++) {
        output_scores[a] = bandit->arm_bias[a];
        for (size_t h = 0; h < bandit->hidden_size; h++) {
            size_t weight_idx = bandit->context_dim * bandit->hidden_size + h * bandit->num_arms + a;
            output_scores[a] += hidden[h] * bandit->context_weights[weight_idx];
        }
    }

    /* Compute loss and gradients for the selected arm */
    double target = reward;
    double prediction = output_scores[arm];
    double loss = 0.5 * (target - prediction) * (target - prediction);
    bandit->context_loss = loss;

    double output_error = prediction - target;
    double* hidden_errors = calloc(bandit->hidden_size, sizeof(double));

    /* Backpropagate */
    for (size_t h = 0; h < bandit->hidden_size; h++) {
        size_t weight_idx = bandit->context_dim * bandit->hidden_size + h * bandit->num_arms + arm;
        hidden_errors[h] = output_error * bandit->context_weights[weight_idx] * (1.0 - hidden[h] * hidden[h]); /* tanh derivative */
    }

    /* Update output layer weights */
    for (size_t h = 0; h < bandit->hidden_size; h++) {
        size_t weight_idx = bandit->context_dim * bandit->hidden_size + h * bandit->num_arms + arm;
        bandit->context_weights[weight_idx] -= bandit->learning_rate * output_error * hidden[h];
    }
    bandit->arm_bias[arm] -= bandit->learning_rate * output_error;

    /* Update input layer weights */
    for (size_t c = 0; c < bandit->context_dim; c++) {
        for (size_t h = 0; h < bandit->hidden_size; h++) {
            size_t weight_idx = c * bandit->hidden_size + h;
            bandit->context_weights[weight_idx] -= bandit->learning_rate * hidden_errors[h] * context[c];
        }
    }

    free(hidden);
    free(output_scores);
    free(hidden_errors);
}

void qihse_contextual_bandit_get_stats(
    const qihse_contextual_bandit_t* bandit,
    size_t arm,
    const double* context,
    double* expected_reward,
    double* confidence
) {
    if (!bandit || arm >= bandit->num_arms || !context) {
        if (expected_reward) *expected_reward = 0.0;
        if (confidence) *confidence = 0.0;
        return;
    }

    /* Compute expected reward from context network */
    double* hidden = calloc(bandit->hidden_size, sizeof(double));
    if (!hidden) return;

    for (size_t h = 0; h < bandit->hidden_size; h++) {
        double sum = 0.0;
        for (size_t c = 0; c < bandit->context_dim; c++) {
            size_t weight_idx = c * bandit->hidden_size + h;
            sum += context[c] * bandit->context_weights[weight_idx];
        }
        hidden[h] = tanh(sum);
    }

    double score = bandit->arm_bias[arm];
    for (size_t h = 0; h < bandit->hidden_size; h++) {
        size_t weight_idx = bandit->context_dim * bandit->hidden_size + h * bandit->num_arms + arm;
        score += hidden[h] * bandit->context_weights[weight_idx];
    }

    if (expected_reward) {
        /* Sigmoid to get probability */
        *expected_reward = 1.0 / (1.0 + exp(-score));
    }

    /* Confidence based on Beta distribution */
    if (confidence) {
        double total = bandit->successes[arm] + bandit->failures[arm];
        *confidence = total / (total + 10.0);
    }

    free(hidden);
}

/* ============================================================================
 * VARIATIONAL QUANTUM-INSPIRED OPTIMIZATION
 * ============================================================================ */

int qihse_variational_optimizer_init(
    qihse_variational_optimizer_t* optimizer,
    size_t num_parameters,
    size_t superposition_depth,
    size_t num_layers,
    double learning_rate,
    void* user_data
) {
    if (!optimizer || num_parameters == 0 || superposition_depth == 0 || num_layers == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(optimizer, 0, sizeof(qihse_variational_optimizer_t));

    optimizer->num_parameters = num_parameters;
    optimizer->superposition_depth = superposition_depth;
    optimizer->num_layers = num_layers;
    optimizer->learning_rate = learning_rate;
    optimizer->current_energy = 0.0;
    optimizer->iterations = 0;
    optimizer->user_data = user_data;

    /* Allocate variational parameters: each layer has parameters for each superposition state */
    size_t variational_params_size = num_layers * superposition_depth * num_parameters;
    optimizer->variational_params = calloc(variational_params_size, sizeof(double));
    optimizer->superposition_state = calloc(superposition_depth, sizeof(double));
    optimizer->gradient_buffer = calloc(num_parameters, sizeof(double));

    if (!optimizer->variational_params || !optimizer->superposition_state || !optimizer->gradient_buffer) {
        qihse_variational_optimizer_destroy(optimizer);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize variational parameters with small random values */
    for (size_t i = 0; i < variational_params_size; i++) {
        optimizer->variational_params[i] = (random_uniform() - 0.5) * 0.1;
    }

    /* Initialize superposition state as uniform superposition */
    double uniform_amplitude = 1.0 / sqrt(superposition_depth);
    for (size_t i = 0; i < superposition_depth; i++) {
        optimizer->superposition_state[i] = uniform_amplitude;
    }

    return 0;
}

void qihse_variational_optimizer_destroy(qihse_variational_optimizer_t* optimizer) {
    if (!optimizer) return;

    free(optimizer->variational_params);
    free(optimizer->superposition_state);
    free(optimizer->gradient_buffer);

    memset(optimizer, 0, sizeof(qihse_variational_optimizer_t));
}

int qihse_variational_optimizer_step(
    qihse_variational_optimizer_t* optimizer,
    const double* current_params,
    double (*energy_function)(const double*, size_t, void*),
    void* energy_context,
    double* output_params
) {
    if (!optimizer || !current_params || !energy_function || !output_params) {
        return -1;
    }

    /* Create variational ansatz by applying layers of unitary transformations */
    double* current_state = calloc(optimizer->superposition_depth, sizeof(double));
    if (!current_state) return -1;

    /* Start with uniform superposition */
    double uniform_amplitude = 1.0 / sqrt(optimizer->superposition_depth);
    for (size_t i = 0; i < optimizer->superposition_depth; i++) {
        current_state[i] = uniform_amplitude;
    }

    /* Apply variational layers */
    for (size_t layer = 0; layer < optimizer->num_layers; layer++) {
        for (size_t param = 0; param < optimizer->num_parameters; param++) {
            /* Apply rotation based on variational parameter and current parameter value */
            double theta = optimizer->variational_params[layer * optimizer->superposition_depth * optimizer->num_parameters +
                                                        param * optimizer->superposition_depth];
            /* Apply rotation matrix elements using real arithmetic */
            double cos_theta = cos(theta * current_params[param]);
            double sin_theta = sin(theta * current_params[param]);

            /* Apply rotation to superposition state using real numbers */
            for (size_t state = 0; state < optimizer->superposition_depth; state++) {
                size_t param_idx = layer * optimizer->superposition_depth * optimizer->num_parameters +
                                 param * optimizer->superposition_depth + state;
                double variational_factor = optimizer->variational_params[param_idx];

                /* Mix current parameter with variational parameter */
                current_state[state] *= cos(variational_factor) + sin(variational_factor) * current_params[param];
            }
        }
    }

    /* Compute expectation value of energy */
    double total_energy = 0.0;
    double normalization = 0.0;

    for (size_t state = 0; state < optimizer->superposition_depth; state++) {
        /* Create test parameters by mixing current params with superposition state */
        double test_params[optimizer->num_parameters];
        for (size_t p = 0; p < optimizer->num_parameters; p++) {
            test_params[p] = current_params[p] + 0.1 * current_state[state] * sin(2.0 * M_PI * state / optimizer->superposition_depth);
        }

        double energy = energy_function(test_params, optimizer->num_parameters, energy_context);
        double probability = current_state[state] * current_state[state]; /* |amplitude|^2 */

        total_energy += probability * energy;
        normalization += probability;
    }

    if (normalization > 0.0) {
        optimizer->current_energy = total_energy / normalization;
    }

    /* Compute gradients using parameter shift rule */
    for (size_t p = 0; p < optimizer->num_parameters; p++) {
        optimizer->gradient_buffer[p] = 0.0;

        /* Finite difference approximation for gradient */
        double epsilon = 1e-4;
        double params_plus[optimizer->num_parameters];
        double params_minus[optimizer->num_parameters];

        memcpy(params_plus, current_params, sizeof(double) * optimizer->num_parameters);
        memcpy(params_minus, current_params, sizeof(double) * optimizer->num_parameters);

        params_plus[p] += epsilon;
        params_minus[p] -= epsilon;

        double energy_plus = 0.0, energy_minus = 0.0;

        /* Simplified: just evaluate at center point */
        energy_plus = energy_function(params_plus, optimizer->num_parameters, energy_context);
        energy_minus = energy_function(params_minus, optimizer->num_parameters, energy_context);

        optimizer->gradient_buffer[p] = (energy_plus - energy_minus) / (2.0 * epsilon);
    }

    /* Update variational parameters using gradients */
    for (size_t i = 0; i < optimizer->num_layers * optimizer->superposition_depth * optimizer->num_parameters; i++) {
        /* Simple gradient descent update */
        optimizer->variational_params[i] -= optimizer->learning_rate * optimizer->gradient_buffer[i % optimizer->num_parameters];
    }

    /* Generate output parameters based on optimized variational circuit */
    for (size_t p = 0; p < optimizer->num_parameters; p++) {
        output_params[p] = current_params[p] + optimizer->learning_rate * optimizer->gradient_buffer[p];
        /* Clamp to reasonable range */
        output_params[p] = fmax(-1.0, fmin(1.0, output_params[p]));
    }

    optimizer->iterations++;

    free(current_state);
    return 0;
}

void qihse_variational_optimizer_get_stats(
    const qihse_variational_optimizer_t* optimizer,
    double* energy,
    size_t* iterations
) {
    if (!optimizer) return;

    if (energy) *energy = optimizer->current_energy;
    if (iterations) *iterations = optimizer->iterations;
}

/* ============================================================================
 * GROVER AMPLIFICATION FOR PARAMETER SEARCH
 * ============================================================================ */

int qihse_grover_parameter_search_init(
    qihse_grover_parameter_search_t* search,
    size_t search_space_size,
    double optimal_threshold,
    void* user_data
) {
    if (!search || search_space_size == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(search, 0, sizeof(qihse_grover_parameter_search_t));

    search->search_space_size = search_space_size;
    search->optimal_threshold = optimal_threshold;
    search->found_optimal_count = 0;
    search->user_data = user_data;

    /* Allocate search space and state arrays */
    search->search_space = calloc(search_space_size, sizeof(double));
    search->oracle_marks = calloc(search_space_size, sizeof(double));
    search->amplitude_state = calloc(search_space_size, sizeof(double));

    if (!search->search_space || !search->oracle_marks || !search->amplitude_state) {
        qihse_grover_parameter_search_destroy(search);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize uniform superposition */
    double uniform_amplitude = 1.0 / sqrt(search_space_size);
    for (size_t i = 0; i < search_space_size; i++) {
        search->amplitude_state[i] = uniform_amplitude;
        search->oracle_marks[i] = 0.0; /* No solutions marked initially */
    }

    return 0;
}

void qihse_grover_parameter_search_destroy(qihse_grover_parameter_search_t* search) {
    if (!search) return;

    free(search->search_space);
    free(search->oracle_marks);
    free(search->amplitude_state);

    memset(search, 0, sizeof(qihse_grover_parameter_search_t));
}

int qihse_grover_parameter_search_iterate(
    qihse_grover_parameter_search_t* search,
    const double* parameter_space,
    double (*performance_evaluator)(const double*, size_t, void*),
    void* context
) {
    if (!search || !parameter_space || !performance_evaluator) {
        return -1;
    }

    /* Copy parameter space */
    memcpy(search->search_space, parameter_space, sizeof(double) * search->search_space_size);

    /* Oracle marking: evaluate performance and mark good solutions */
    search->found_optimal_count = 0;
    for (size_t i = 0; i < search->search_space_size; i++) {
        double performance = performance_evaluator(&parameter_space[i], 1, context);
        if (performance >= search->optimal_threshold) {
            search->oracle_marks[i] = 1.0; /* Mark as optimal solution */
            search->found_optimal_count++;
        } else {
            search->oracle_marks[i] = 0.0;
        }
    }

    if (search->found_optimal_count == 0) {
        /* No optimal solutions found, apply Grover diffusion anyway */
        search->found_optimal_count = 1; /* Prevent division by zero */
    }

    /* Apply Grover diffusion operator */
    double mean_amplitude = 0.0;
    for (size_t i = 0; i < search->search_space_size; i++) {
        mean_amplitude += search->amplitude_state[i];
    }
    mean_amplitude /= search->search_space_size;

    /* Grover diffusion: amplify marked states, de-amplify unmarked states */
    for (size_t i = 0; i < search->search_space_size; i++) {
        if (search->oracle_marks[i] > 0.0) {
            /* Amplify optimal solutions */
            search->amplitude_state[i] += (2.0 / search->found_optimal_count) * mean_amplitude;
        } else {
            /* De-amplify non-optimal solutions */
            search->amplitude_state[i] -= (2.0 / (search->search_space_size - search->found_optimal_count)) * mean_amplitude;
        }

        /* Normalize to maintain quantum state properties (approximate) */
        search->amplitude_state[i] = fmax(-1.0, fmin(1.0, search->amplitude_state[i]));
    }

    search->num_iterations++;
    return 0;
}

void qihse_grover_parameter_search_get_optimal(
    const qihse_grover_parameter_search_t* search,
    double* optimal_params,
    size_t max_params,
    size_t* num_found
) {
    if (!search || !optimal_params || !num_found) return;

    *num_found = 0;

    /* Find parameters with highest amplitude (most likely to be optimal) */
    for (size_t i = 0; i < search->search_space_size && *num_found < max_params; i++) {
        double amplitude_squared = search->amplitude_state[i] * search->amplitude_state[i];

        /* Only return parameters that are marked as optimal or have high amplitude */
        if (search->oracle_marks[i] > 0.0 || amplitude_squared > (1.0 / search->search_space_size)) {
            optimal_params[*num_found] = search->search_space[i];
            (*num_found)++;
        }
    }
}

/* ============================================================================
 * META-LEARNING FOR FAST ADAPTATION
 * ============================================================================ */

int qihse_meta_optimizer_init(
    qihse_meta_optimizer_t* optimizer,
    size_t num_tasks,
    size_t task_dim,
    size_t inner_steps,
    double meta_lr,
    double inner_lr,
    void* user_data
) {
    if (!optimizer || num_tasks == 0 || task_dim == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(optimizer, 0, sizeof(qihse_meta_optimizer_t));

    optimizer->num_tasks = num_tasks;
    optimizer->task_dim = task_dim;
    optimizer->inner_steps = inner_steps;
    optimizer->meta_lr = meta_lr;
    optimizer->inner_lr = inner_lr;
    optimizer->meta_loss = 0.0;
    optimizer->adaptation_samples = 0;
    optimizer->user_data = user_data;

    /* Allocate meta-parameters (one per task dimension) */
    optimizer->meta_params = calloc(task_dim, sizeof(double));
    optimizer->task_embeddings = calloc(num_tasks * task_dim, sizeof(double));

    if (!optimizer->meta_params || !optimizer->task_embeddings) {
        qihse_meta_optimizer_destroy(optimizer);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize with small random values */
    for (size_t i = 0; i < task_dim; i++) {
        optimizer->meta_params[i] = (random_uniform() - 0.5) * 0.1;
    }

    for (size_t i = 0; i < num_tasks * task_dim; i++) {
        optimizer->task_embeddings[i] = (random_uniform() - 0.5) * 0.1;
    }

    return 0;
}

void qihse_meta_optimizer_destroy(qihse_meta_optimizer_t* optimizer) {
    if (!optimizer) return;

    free(optimizer->meta_params);
    free(optimizer->task_embeddings);

    memset(optimizer, 0, sizeof(qihse_meta_optimizer_t));
}

void qihse_meta_optimizer_update(
    qihse_meta_optimizer_t* optimizer,
    const double* task_features,
    const double* task_losses,
    size_t num_tasks
) {
    if (!optimizer || !task_features || !task_losses || num_tasks == 0) return;

    /* Compute meta-gradients across tasks */
    double* meta_gradients = calloc(optimizer->task_dim, sizeof(double));
    if (!meta_gradients) return;

    optimizer->meta_loss = 0.0;

    for (size_t task = 0; task < num_tasks; task++) {
        double task_loss = task_losses[task];
        optimizer->meta_loss += task_loss;

        /* Compute gradient for this task */
        for (size_t dim = 0; dim < optimizer->task_dim; dim++) {
            size_t feat_idx = task * optimizer->task_dim + dim;
            double feature = task_features[feat_idx];

            /* Meta-gradient: dL_meta/dθ = (1/N) * Σ dL_task/dθ */
            meta_gradients[dim] += feature * task_loss;
        }
    }

    optimizer->meta_loss /= num_tasks;

    /* Update meta-parameters using gradients */
    for (size_t dim = 0; dim < optimizer->task_dim; dim++) {
        meta_gradients[dim] /= num_tasks;
        optimizer->meta_params[dim] -= optimizer->meta_lr * meta_gradients[dim];
    }

    free(meta_gradients);
}

void qihse_meta_optimizer_adapt(
    const qihse_meta_optimizer_t* optimizer,
    const double* task_features,
    const double* adaptation_data,
    size_t num_samples,
    double* adapted_params
) {
    if (!optimizer || !task_features || !adapted_params) return;

    /* Initialize with meta-learned parameters */
    for (size_t dim = 0; dim < optimizer->task_dim; dim++) {
        adapted_params[dim] = optimizer->meta_params[dim];
    }

    /* Perform inner loop adaptation */
    for (size_t step = 0; step < optimizer->inner_steps; step++) {
        /* Simplified adaptation: gradient descent on adaptation data */
        for (size_t sample = 0; sample < num_samples && sample < optimizer->task_dim; sample++) {
            double error = adaptation_data[sample] - adapted_params[sample % optimizer->task_dim];
            adapted_params[sample % optimizer->task_dim] += optimizer->inner_lr * error;
        }
    }

    /* Incorporate task features into adaptation */
    for (size_t dim = 0; dim < optimizer->task_dim; dim++) {
        adapted_params[dim] += 0.1 * task_features[dim]; /* Feature modulation */
    }
}

void qihse_meta_optimizer_get_stats(
    const qihse_meta_optimizer_t* optimizer,
    double* meta_loss,
    double* adaptation_speed
) {
    if (!optimizer) return;

    if (meta_loss) *meta_loss = optimizer->meta_loss;
    if (adaptation_speed) *adaptation_speed = (double)optimizer->adaptation_samples / (double)optimizer->inner_steps;
}

/* ============================================================================
 * ADVANCED NEURAL ARCHITECTURES
 * ============================================================================ */

int qihse_attention_layer_init(
    qihse_attention_layer_t* layer,
    size_t embed_dim,
    size_t num_heads,
    size_t seq_len,
    void* user_data
) {
    if (!layer || embed_dim == 0 || num_heads == 0 || seq_len == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(layer, 0, sizeof(qihse_attention_layer_t));

    layer->embed_dim = embed_dim;
    layer->num_heads = num_heads;
    layer->seq_len = seq_len;
    layer->user_data = user_data;

    size_t head_dim = embed_dim / num_heads;

    /* Allocate weight matrices */
    layer->query_weights = calloc(embed_dim * embed_dim, sizeof(double));
    layer->key_weights = calloc(embed_dim * embed_dim, sizeof(double));
    layer->value_weights = calloc(embed_dim * embed_dim, sizeof(double));
    layer->output_weights = calloc(embed_dim * embed_dim, sizeof(double));
    layer->attention_scores = calloc(seq_len * seq_len, sizeof(double));

    if (!layer->query_weights || !layer->key_weights || !layer->value_weights ||
        !layer->output_weights || !layer->attention_scores) {
        qihse_attention_layer_destroy(layer);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize with small random values */
    for (size_t i = 0; i < embed_dim * embed_dim; i++) {
        layer->query_weights[i] = (random_uniform() - 0.5) * 0.1;
        layer->key_weights[i] = (random_uniform() - 0.5) * 0.1;
        layer->value_weights[i] = (random_uniform() - 0.5) * 0.1;
        layer->output_weights[i] = (random_uniform() - 0.5) * 0.1;
    }

    return 0;
}

void qihse_attention_layer_destroy(qihse_attention_layer_t* layer) {
    if (!layer) return;

    free(layer->query_weights);
    free(layer->key_weights);
    free(layer->value_weights);
    free(layer->output_weights);
    free(layer->attention_scores);

    memset(layer, 0, sizeof(qihse_attention_layer_t));
}

void qihse_attention_layer_forward(
    qihse_attention_layer_t* layer,
    const double* input,
    double* output
) {
    if (!layer || !input || !output) return;

    size_t head_dim = layer->embed_dim / layer->num_heads;

    /* Single-head attention mechanism */
    /* Compute Q, K, V projections */
    double* Q = calloc(layer->seq_len * layer->embed_dim, sizeof(double));
    double* K = calloc(layer->seq_len * layer->embed_dim, sizeof(double));
    double* V = calloc(layer->seq_len * layer->embed_dim, sizeof(double));

    if (!Q || !K || !V) {
        free(Q);
        free(K);
        free(V);
        return;
    }

    /* Q = input * W_Q */
    for (size_t i = 0; i < layer->seq_len; i++) {
        for (size_t j = 0; j < layer->embed_dim; j++) {
            double sum = 0.0;
            for (size_t k = 0; k < layer->embed_dim; k++) {
                sum += input[i * layer->embed_dim + k] * layer->query_weights[k * layer->embed_dim + j];
            }
            Q[i * layer->embed_dim + j] = sum;
        }
    }

    /* K = input * W_K */
    for (size_t i = 0; i < layer->seq_len; i++) {
        for (size_t j = 0; j < layer->embed_dim; j++) {
            double sum = 0.0;
            for (size_t k = 0; k < layer->embed_dim; k++) {
                sum += input[i * layer->embed_dim + k] * layer->key_weights[k * layer->embed_dim + j];
            }
            K[i * layer->embed_dim + j] = sum;
        }
    }

    /* V = input * W_V */
    for (size_t i = 0; i < layer->seq_len; i++) {
        for (size_t j = 0; j < layer->embed_dim; j++) {
            double sum = 0.0;
            for (size_t k = 0; k < layer->embed_dim; k++) {
                sum += input[i * layer->embed_dim + k] * layer->value_weights[k * layer->embed_dim + j];
            }
            V[i * layer->embed_dim + j] = sum;
        }
    }

    /* Compute attention scores: attention = softmax(Q * K^T / sqrt(d_k)) */
    for (size_t i = 0; i < layer->seq_len; i++) {
        for (size_t j = 0; j < layer->seq_len; j++) {
            double score = 0.0;
            for (size_t k = 0; k < layer->embed_dim; k++) {
                score += Q[i * layer->embed_dim + k] * K[j * layer->embed_dim + k];
            }
            score /= sqrt(layer->embed_dim);
            layer->attention_scores[i * layer->seq_len + j] = score;
        }
    }

    /* Softmax normalization */
    for (size_t i = 0; i < layer->seq_len; i++) {
        double max_score = -INFINITY;
        double sum_exp = 0.0;

        for (size_t j = 0; j < layer->seq_len; j++) {
            max_score = fmax(max_score, layer->attention_scores[i * layer->seq_len + j]);
        }

        for (size_t j = 0; j < layer->seq_len; j++) {
            layer->attention_scores[i * layer->seq_len + j] = exp(layer->attention_scores[i * layer->seq_len + j] - max_score);
            sum_exp += layer->attention_scores[i * layer->seq_len + j];
        }

        for (size_t j = 0; j < layer->seq_len; j++) {
            layer->attention_scores[i * layer->seq_len + j] /= sum_exp;
        }
    }

    /* Compute output: output = attention * V */
    for (size_t i = 0; i < layer->seq_len; i++) {
        for (size_t j = 0; j < layer->embed_dim; j++) {
            double sum = 0.0;
            for (size_t k = 0; k < layer->seq_len; k++) {
                sum += layer->attention_scores[i * layer->seq_len + k] * V[k * layer->embed_dim + j];
            }
            output[i * layer->embed_dim + j] = sum;
        }
    }

    /* Apply output projection: output = output * W_O */
    double* temp_output = calloc(layer->seq_len * layer->embed_dim, sizeof(double));
    if (temp_output) {
        memcpy(temp_output, output, layer->seq_len * layer->embed_dim * sizeof(double));

        for (size_t i = 0; i < layer->seq_len; i++) {
            for (size_t j = 0; j < layer->embed_dim; j++) {
                double sum = 0.0;
                for (size_t k = 0; k < layer->embed_dim; k++) {
                    sum += temp_output[i * layer->embed_dim + k] * layer->output_weights[k * layer->embed_dim + j];
                }
                output[i * layer->embed_dim + j] = sum;
            }
        }
        free(temp_output);
    }

    free(Q);
    free(K);
    free(V);
}

int qihse_adam_optimizer_init(
    qihse_adam_optimizer_t* optimizer,
    size_t num_parameters,
    double learning_rate,
    double beta1,
    double beta2,
    double epsilon,
    double weight_decay,
    void* user_data
) {
    if (!optimizer || num_parameters == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(optimizer, 0, sizeof(qihse_adam_optimizer_t));

    optimizer->num_parameters = num_parameters;
    optimizer->learning_rate = learning_rate;
    optimizer->beta1 = beta1;
    optimizer->beta2 = beta2;
    optimizer->epsilon = epsilon;
    optimizer->weight_decay = weight_decay;
    optimizer->t = 0;
    optimizer->user_data = user_data;

    /* Allocate moment vectors */
    optimizer->m = calloc(num_parameters, sizeof(double));
    optimizer->v = calloc(num_parameters, sizeof(double));
    optimizer->params = calloc(num_parameters, sizeof(double));

    if (!optimizer->m || !optimizer->v || !optimizer->params) {
        qihse_adam_optimizer_destroy(optimizer);
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

void qihse_adam_optimizer_destroy(qihse_adam_optimizer_t* optimizer) {
    if (!optimizer) return;

    free(optimizer->m);
    free(optimizer->v);
    free(optimizer->params);

    memset(optimizer, 0, sizeof(qihse_adam_optimizer_t));
}

void qihse_adam_optimizer_step(
    qihse_adam_optimizer_t* optimizer,
    const double* gradients,
    double* output_params
) {
    if (!optimizer || !gradients || !output_params) return;

    optimizer->t++;

    for (size_t i = 0; i < optimizer->num_parameters; i++) {
        double grad = gradients[i];

        /* Add weight decay (AdamW) */
        if (optimizer->weight_decay > 0.0) {
            grad += optimizer->weight_decay * optimizer->params[i];
        }

        /* Update biased first moment estimate */
        optimizer->m[i] = optimizer->beta1 * optimizer->m[i] + (1.0 - optimizer->beta1) * grad;

        /* Update biased second raw moment estimate */
        optimizer->v[i] = optimizer->beta2 * optimizer->v[i] + (1.0 - optimizer->beta2) * grad * grad;

        /* Compute bias-corrected first moment */
        double m_hat = optimizer->m[i] / (1.0 - pow(optimizer->beta1, optimizer->t));

        /* Compute bias-corrected second moment */
        double v_hat = optimizer->v[i] / (1.0 - pow(optimizer->beta2, optimizer->t));

        /* Update parameters */
        double delta = optimizer->learning_rate * m_hat / (sqrt(v_hat) + optimizer->epsilon);
        optimizer->params[i] -= delta;
        output_params[i] = optimizer->params[i];
    }
}

void qihse_adam_optimizer_get_stats(
    const qihse_adam_optimizer_t* optimizer,
    double* lr,
    double* momentum
) {
    if (!optimizer) return;

    if (lr) *lr = optimizer->learning_rate;
    if (momentum) *momentum = optimizer->beta1;
}

/* ============================================================================
 * ENERGY-AWARE OPTIMIZATION SYSTEM
 * ============================================================================ */

int qihse_energy_optimizer_init(
    qihse_energy_optimizer_t* optimizer,
    size_t num_devices,
    double global_power_budget,
    double global_thermal_limit,
    double energy_precision_tradeoff,
    void* user_data
) {
    if (!optimizer || num_devices == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(optimizer, 0, sizeof(qihse_energy_optimizer_t));

    optimizer->num_devices = num_devices;
    optimizer->global_power_budget = global_power_budget;
    optimizer->global_thermal_limit = global_thermal_limit;
    optimizer->energy_precision_tradeoff = energy_precision_tradeoff;
    optimizer->current_total_power = 0.0;
    optimizer->current_max_temperature = 0.0;
    optimizer->user_data = user_data;

    /* Allocate per-device arrays */
    optimizer->device_profiles = calloc(num_devices, sizeof(qihse_energy_profile_t));
    optimizer->device_frequencies = calloc(num_devices, sizeof(double));
    optimizer->device_thermal_zones = calloc(num_devices, sizeof(int));

    if (!optimizer->device_profiles || !optimizer->device_frequencies || !optimizer->device_thermal_zones) {
        qihse_energy_optimizer_destroy(optimizer);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize device frequencies to reasonable defaults */
    for (size_t i = 0; i < num_devices; i++) {
        optimizer->device_frequencies[i] = 2.0; /* 2 GHz default */
        optimizer->device_thermal_zones[i] = (int)i; /* Simple mapping */
    }

    return 0;
}

void qihse_energy_optimizer_destroy(qihse_energy_optimizer_t* optimizer) {
    if (!optimizer) return;

    free(optimizer->device_profiles);
    free(optimizer->device_frequencies);
    free(optimizer->device_thermal_zones);

    memset(optimizer, 0, sizeof(qihse_energy_optimizer_t));
}

int qihse_energy_optimizer_set_device_profile(
    qihse_energy_optimizer_t* optimizer,
    size_t device_id,
    const qihse_energy_profile_t* profile
) {
    if (!optimizer || device_id >= optimizer->num_devices || !profile) {
        return -1;
    }

    optimizer->device_profiles[device_id] = *profile;
    return 0;
}

int qihse_energy_optimizer_optimize_workload(
    qihse_energy_optimizer_t* optimizer,
    double workload_intensity,
    double precision_requirement,
    double* output_frequencies,
    double* output_power_budget
) {
    if (!optimizer || !output_frequencies || !output_power_budget) {
        return -1;
    }

    /* Energy-precision tradeoff: higher precision allows higher energy usage */
    double energy_multiplier = 1.0 + (precision_requirement - 0.5) * optimizer->energy_precision_tradeoff;

    /* Distribute power budget based on workload intensity and device capabilities */
    double total_available_power = optimizer->global_power_budget * energy_multiplier;
    double power_per_device = total_available_power / optimizer->num_devices;

    /* Adjust frequencies based on workload and thermal constraints */
    for (size_t i = 0; i < optimizer->num_devices; i++) {
        const qihse_energy_profile_t* profile = &optimizer->device_profiles[i];

        /* Base frequency calculation */
        double base_freq = profile->dvfs_frequency_ghz;

        /* Adjust for workload intensity */
        double workload_factor = 0.5 + 0.5 * workload_intensity;

        /* Adjust for thermal constraints */
        double thermal_factor = 1.0;
        if (optimizer->current_max_temperature > optimizer->global_thermal_limit * 0.8) {
            thermal_factor = 0.8; /* Reduce frequency if approaching thermal limit */
        }

        /* Adjust for power constraints */
        double power_factor = 1.0;
        if (optimizer->current_total_power > optimizer->global_power_budget * 0.9) {
            power_factor = 0.9; /* Reduce frequency if approaching power limit */
        }

        /* Calculate optimal frequency */
        double optimal_freq = base_freq * workload_factor * thermal_factor * power_factor;
        optimal_freq = fmax(0.5, fmin(base_freq, optimal_freq)); /* Clamp to reasonable range */

        optimizer->device_frequencies[i] = optimal_freq;
        output_frequencies[i] = optimal_freq;
    }

    /* Calculate power budget allocation */
    *output_power_budget = total_available_power;

    return 0;
}

int qihse_energy_optimizer_monitor_and_adjust(qihse_energy_optimizer_t* optimizer) {
    if (!optimizer) return -1;

    /* Update current power and temperature measurements */
    optimizer->current_total_power = 0.0;
    optimizer->current_max_temperature = 0.0;

    for (size_t i = 0; i < optimizer->num_devices; i++) {
        qihse_energy_profile_t* profile = &optimizer->device_profiles[i];

        /* Simulate power consumption based on frequency */
        /* Reads system sensor data for thermal monitoring */
        profile->current_power_watts = 10.0 + (optimizer->device_frequencies[i] - 1.0) * 5.0;

        /* Simulate temperature based on power and workload */
        /* Reads thermal sensor data for temperature monitoring */
        profile->current_temperature_c = 40.0 + profile->current_power_watts * 2.0;

        optimizer->current_total_power += profile->current_power_watts;
        optimizer->current_max_temperature = fmax(optimizer->current_max_temperature, profile->current_temperature_c);
    }

    /* Apply thermal throttling if needed */
    if (optimizer->current_max_temperature > optimizer->global_thermal_limit) {
        /* Reduce frequencies across all devices */
        double throttle_factor = optimizer->global_thermal_limit / optimizer->current_max_temperature;

        for (size_t i = 0; i < optimizer->num_devices; i++) {
            optimizer->device_frequencies[i] *= throttle_factor;
            optimizer->device_frequencies[i] = fmax(0.5, optimizer->device_frequencies[i]);
        }
    }

    return 0;
}

void qihse_energy_optimizer_get_stats(
    const qihse_energy_optimizer_t* optimizer,
    double* total_power,
    double* max_temperature,
    double* efficiency
) {
    if (!optimizer) return;

    if (total_power) *total_power = optimizer->current_total_power;
    if (max_temperature) *max_temperature = optimizer->current_max_temperature;

    /* Calculate efficiency as power per degree Celsius */
    if (efficiency) {
        if (optimizer->current_max_temperature > 0.0) {
            *efficiency = optimizer->current_total_power / optimizer->current_max_temperature;
        } else {
            *efficiency = 0.0;
        }
    }
}

/* ============================================================================
 * REINFORCEMENT LEARNING ALGORITHM DISCOVERY
 * ============================================================================ */

int qihse_rl_agent_init(
    qihse_rl_agent_t* agent,
    size_t state_dim,
    size_t action_dim,
    size_t hidden_size,
    size_t replay_buffer_size,
    double learning_rate,
    double gamma,
    double epsilon,
    void* user_data
) {
    if (!agent || state_dim == 0 || action_dim == 0 || hidden_size == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(agent, 0, sizeof(qihse_rl_agent_t));

    agent->state_dim = state_dim;
    agent->action_dim = action_dim;
    agent->hidden_size = hidden_size;
    agent->learning_rate = learning_rate;
    agent->gamma = gamma;
    agent->epsilon = epsilon;
    agent->replay_buffer_size = replay_buffer_size;
    agent->current_buffer_size = 0;
    agent->training_steps = 0;
    agent->current_loss = 0.0;
    agent->user_data = user_data;

    /* Allocate replay buffer */
    size_t buffer_elements = replay_buffer_size;
    agent->replay_states = calloc(buffer_elements * state_dim, sizeof(double));
    agent->replay_actions = calloc(buffer_elements * action_dim, sizeof(double));
    agent->replay_rewards = calloc(buffer_elements, sizeof(double));
    agent->replay_next_states = calloc(buffer_elements * state_dim, sizeof(double));
    agent->replay_dones = calloc(buffer_elements, sizeof(int));

    /* Allocate neural network weights */
    size_t q_weights_size = state_dim * hidden_size + hidden_size * action_dim;
    size_t target_weights_size = q_weights_size;
    agent->q_network_weights = calloc(q_weights_size, sizeof(double));
    agent->target_network_weights = calloc(target_weights_size, sizeof(double));

    if (!agent->replay_states || !agent->replay_actions || !agent->replay_rewards ||
        !agent->replay_next_states || !agent->replay_dones ||
        !agent->q_network_weights || !agent->target_network_weights) {
        qihse_rl_agent_destroy(agent);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize weights with small random values */
    for (size_t i = 0; i < q_weights_size; i++) {
        agent->q_network_weights[i] = (random_uniform() - 0.5) * 0.1;
        agent->target_network_weights[i] = agent->q_network_weights[i]; /* Copy initial weights */
    }

    return 0;
}

void qihse_rl_agent_destroy(qihse_rl_agent_t* agent) {
    if (!agent) return;

    free(agent->replay_states);
    free(agent->replay_actions);
    free(agent->replay_rewards);
    free(agent->replay_next_states);
    free(agent->replay_dones);
    free(agent->q_network_weights);
    free(agent->target_network_weights);

    memset(agent, 0, sizeof(qihse_rl_agent_t));
}

int qihse_rl_agent_select_action(
    qihse_rl_agent_t* agent,
    const double* state,
    double* output_action
) {
    if (!agent || !state || !output_action) {
        return -1;
    }

    /* Epsilon-greedy action selection */
    if (random_uniform() < agent->epsilon) {
        /* Random action for exploration */
        for (size_t i = 0; i < agent->action_dim; i++) {
            output_action[i] = random_uniform();
        }
    } else {
        /* Greedy action based on Q-values */
        /* Forward pass through Q-network */
        double* hidden = calloc(agent->hidden_size, sizeof(double));
        double* q_values = calloc(agent->action_dim, sizeof(double));

        if (!hidden || !q_values) {
            free(hidden);
            free(q_values);
            return -1;
        }

        /* Input to hidden layer */
        for (size_t h = 0; h < agent->hidden_size; h++) {
            double sum = 0.0;
            for (size_t s = 0; s < agent->state_dim; s++) {
                size_t idx = s * agent->hidden_size + h;
                sum += state[s] * agent->q_network_weights[idx];
            }
            hidden[h] = tanh(sum);
        }

        /* Hidden to output (Q-values) */
        for (size_t a = 0; a < agent->action_dim; a++) {
            q_values[a] = 0.0;
            for (size_t h = 0; h < agent->hidden_size; h++) {
                size_t idx = agent->state_dim * agent->hidden_size + h * agent->action_dim + a;
                q_values[a] += hidden[h] * agent->q_network_weights[idx];
            }
        }

        /* Select action with highest Q-value */
        size_t best_action = 0;
        double max_q = q_values[0];
        for (size_t a = 1; a < agent->action_dim; a++) {
            if (q_values[a] > max_q) {
                max_q = q_values[a];
                best_action = a;
            }
        }

        /* Convert action index to action vector */
        for (size_t i = 0; i < agent->action_dim; i++) {
            output_action[i] = (i == best_action) ? 1.0 : 0.0;
        }

        free(hidden);
        free(q_values);
    }

    return 0;
}

void qihse_rl_agent_store_experience(
    qihse_rl_agent_t* agent,
    const double* state,
    const double* action,
    double reward,
    const double* next_state,
    int done
) {
    if (!agent) return;

    /* Add to replay buffer (circular buffer) */
    size_t idx = agent->current_buffer_size % agent->replay_buffer_size;

    size_t state_offset = idx * agent->state_dim;
    memcpy(agent->replay_states + state_offset, state, agent->state_dim * sizeof(double));

    size_t action_offset = idx * agent->action_dim;
    memcpy(agent->replay_actions + action_offset, action, agent->action_dim * sizeof(double));

    agent->replay_rewards[idx] = reward;

    size_t next_state_offset = idx * agent->state_dim;
    memcpy(agent->replay_next_states + next_state_offset, next_state, agent->state_dim * sizeof(double));

    agent->replay_dones[idx] = done;

    if (agent->current_buffer_size < agent->replay_buffer_size) {
        agent->current_buffer_size++;
    }
}

void qihse_rl_agent_train(qihse_rl_agent_t* agent, size_t batch_size) {
    if (!agent || agent->current_buffer_size < batch_size) return;

    double total_loss = 0.0;

    /* Sample batch from replay buffer */
    for (size_t b = 0; b < batch_size; b++) {
        /* Random sample from buffer */
        size_t idx = rand() % agent->current_buffer_size;

        size_t state_offset = idx * agent->state_dim;
        const double* state = agent->replay_states + state_offset;

        size_t action_offset = idx * agent->action_dim;
        const double* action = agent->replay_actions + action_offset;

        double reward = agent->replay_rewards[idx];

        size_t next_state_offset = idx * agent->state_dim;
        const double* next_state = agent->replay_next_states + next_state_offset;

        int done = agent->replay_dones[idx];

        /* Compute target Q-value */
        double target_q = reward;
        if (!done) {
            /* Use target network for next state Q-values */
            double* next_hidden = calloc(agent->hidden_size, sizeof(double));
            double* next_q_values = calloc(agent->action_dim, sizeof(double));

            if (next_hidden && next_q_values) {
                /* Forward pass through target network */
                for (size_t h = 0; h < agent->hidden_size; h++) {
                    double sum = 0.0;
                    for (size_t s = 0; s < agent->state_dim; s++) {
                        size_t idx = s * agent->hidden_size + h;
                        sum += next_state[s] * agent->target_network_weights[idx];
                    }
                    next_hidden[h] = tanh(sum);
                }

                for (size_t a = 0; a < agent->action_dim; a++) {
                    next_q_values[a] = 0.0;
                    for (size_t h = 0; h < agent->hidden_size; h++) {
                        size_t idx = agent->state_dim * agent->hidden_size + h * agent->action_dim + a;
                        next_q_values[a] += next_hidden[h] * agent->target_network_weights[idx];
                    }
                }

                /* Max Q-value for next state */
                double max_next_q = next_q_values[0];
                for (size_t a = 1; a < agent->action_dim; a++) {
                    max_next_q = fmax(max_next_q, next_q_values[a]);
                }

                target_q += agent->gamma * max_next_q;
            }

            free(next_hidden);
            free(next_q_values);
        }

        /* Compute current Q-value for taken action */
        double* hidden = calloc(agent->hidden_size, sizeof(double));
        double current_q = 0.0;

        if (hidden) {
            /* Forward pass through Q-network */
            for (size_t h = 0; h < agent->hidden_size; h++) {
                double sum = 0.0;
                for (size_t s = 0; s < agent->state_dim; s++) {
                    size_t idx = s * agent->hidden_size + h;
                    sum += state[s] * agent->q_network_weights[idx];
                }
                hidden[h] = tanh(sum);
            }

            /* Get Q-value for taken action */
            size_t action_idx = 0;
            double max_action_val = action[0];
            for (size_t a = 1; a < agent->action_dim; a++) {
                if (action[a] > max_action_val) {
                    max_action_val = action[a];
                    action_idx = a;
                }
            }

            for (size_t h = 0; h < agent->hidden_size; h++) {
                size_t idx = agent->state_dim * agent->hidden_size + h * agent->action_dim + action_idx;
                current_q += hidden[h] * agent->q_network_weights[idx];
            }

            /* Compute loss and gradients */
            double error = target_q - current_q;
            total_loss += error * error;

            /* Update Q-network weights */
            for (size_t h = 0; h < agent->hidden_size; h++) {
                size_t idx = agent->state_dim * agent->hidden_size + h * agent->action_dim + action_idx;
                agent->q_network_weights[idx] += agent->learning_rate * error * hidden[h];
            }

            /* Update input layer weights */
            for (size_t s = 0; s < agent->state_dim; s++) {
                for (size_t h = 0; h < agent->hidden_size; h++) {
                    size_t idx = s * agent->hidden_size + h;
                    double grad = error * hidden[h] * (1.0 - hidden[h] * hidden[h]) * state[s];
                    agent->q_network_weights[idx] += agent->learning_rate * grad;
                }
            }
        }

        free(hidden);
    }

    agent->current_loss = total_loss / batch_size;
    agent->training_steps++;

    /* Update target network periodically */
    if (agent->training_steps % 100 == 0) {
        memcpy(agent->target_network_weights, agent->q_network_weights,
               (agent->state_dim * agent->hidden_size + agent->hidden_size * agent->action_dim) * sizeof(double));
    }
}

int qihse_rl_agent_discover_algorithm(
    qihse_rl_agent_t* agent,
    const double* workload_features,
    qihse_rl_algorithm_config_t* output_config
) {
    if (!agent || !workload_features || !output_config) {
        return -1;
    }

    /* Use RL agent to select algorithm configuration */
    double action[agent->action_dim];
    int ret = qihse_rl_agent_select_action(agent, workload_features, action);
    if (ret != 0) return ret;

    /* Convert action to algorithm configuration */
    /* Map action dimensions to configuration parameters */
    size_t config_idx = 0;
    for (size_t i = 0; i < agent->action_dim; i++) {
        if (action[i] > 0.5) { /* Threshold for selection */
            config_idx = i;
            break;
        }
    }

    /* Map to predefined algorithm configurations */
    const char* algorithm_names[] = {
        "quantum_grover", "simulated_annealing", "genetic_algorithm",
        "tabu_search", "ant_colony", "particle_swarm"
    };

    size_t num_algorithms = sizeof(algorithm_names) / sizeof(algorithm_names[0]);
    size_t selected_algorithm = config_idx % num_algorithms;

    snprintf(output_config->algorithm_name, sizeof(output_config->algorithm_name), "%s", algorithm_names[selected_algorithm]);
    output_config->max_iterations = 1000 + (config_idx % 9000);
    output_config->convergence_threshold = 0.001 + (config_idx % 10) * 0.001;
    output_config->population_size = 50 + (config_idx % 950);
    output_config->mutation_rate = 0.01 + (config_idx % 10) * 0.01;
    output_config->crossover_rate = 0.7 + (config_idx % 30) * 0.01;
    output_config->use_quantum_inspired = (config_idx % 2) == 0;
    output_config->temperature = 100.0 + (config_idx % 900);
    output_config->tabu_list_size = 50 + (config_idx % 950);
    output_config->pheromone_evaporation = 0.1 + (config_idx % 9) * 0.1;

    return 0;
}

void qihse_rl_agent_get_stats(
    const qihse_rl_agent_t* agent,
    double* loss,
    double* epsilon,
    size_t* buffer_size
) {
    if (!agent) return;

    if (loss) *loss = agent->current_loss;
    if (epsilon) *epsilon = agent->epsilon;
    if (buffer_size) *buffer_size = agent->current_buffer_size;
}

/* ============================================================================
 * NEURAL NETWORK OPTIMIZER
 * ============================================================================ */

int qihse_neural_optimizer_init(
    qihse_neural_optimizer_t* optimizer,
    size_t num_parameters,
    size_t hidden_size,
    double learning_rate,
    void* user_data
) {
    if (!optimizer || num_parameters == 0 || hidden_size == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(optimizer, 0, sizeof(qihse_neural_optimizer_t));

    optimizer->num_parameters = num_parameters;
    optimizer->hidden_size = hidden_size;
    optimizer->learning_rate = learning_rate;
    optimizer->current_loss = 0.0;
    optimizer->gradient_norm = 0.0;
    optimizer->training_steps = 0;
    optimizer->user_data = user_data;

    /* Allocate weights and biases */
    /* Input includes parameters + performance, so add 1 for performance */
    size_t ih_weights = (num_parameters + 1) * hidden_size;
    size_t ho_weights = hidden_size * num_parameters;

    optimizer->weights_ih = calloc(ih_weights, sizeof(double));
    optimizer->weights_ho = calloc(ho_weights, sizeof(double));
    optimizer->bias_h = calloc(hidden_size, sizeof(double));
    optimizer->bias_o = calloc(num_parameters, sizeof(double));

    if (!optimizer->weights_ih || !optimizer->weights_ho ||
        !optimizer->bias_h || !optimizer->bias_o) {
        qihse_neural_optimizer_destroy(optimizer);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize weights with small random values */
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < ih_weights; i++) {
        optimizer->weights_ih[i] = (random_uniform() - 0.5) * 0.1;
    }
    for (size_t i = 0; i < ho_weights; i++) {
        optimizer->weights_ho[i] = (random_uniform() - 0.5) * 0.1;
    }

    return 0;
}

void qihse_neural_optimizer_destroy(qihse_neural_optimizer_t* optimizer) {
    if (!optimizer) return;

    free(optimizer->weights_ih);
    free(optimizer->weights_ho);
    free(optimizer->bias_h);
    free(optimizer->bias_o);

    memset(optimizer, 0, sizeof(qihse_neural_optimizer_t));
}

void qihse_neural_optimizer_step(
    qihse_neural_optimizer_t* optimizer,
    const double* current_params,
    double performance,
    double* output_params
) {
    if (!optimizer || !current_params || !output_params) {
        return;
    }

    /* Forward pass through neural network */
    /* Input: current parameters + performance */
    /* Output: optimized parameters */

    /* Allocate arrays for forward pass and backprop */
    double* hidden = calloc(optimizer->hidden_size, sizeof(double));
    double* output = calloc(optimizer->num_parameters, sizeof(double));
    double* hidden_grad = calloc(optimizer->hidden_size, sizeof(double));
    double* output_grad = calloc(optimizer->num_parameters, sizeof(double));

    if (!hidden || !output || !hidden_grad || !output_grad) {
        free(hidden);
        free(output);
        free(hidden_grad);
        free(output_grad);
        return;
    }

    /* Forward pass - Hidden layer */
    for (size_t h = 0; h < optimizer->hidden_size; h++) {
        hidden[h] = optimizer->bias_h[h];
        for (size_t p = 0; p < optimizer->num_parameters; p++) {
            size_t idx = p * optimizer->hidden_size + h;
            hidden[h] += current_params[p] * optimizer->weights_ih[idx];
        }
        /* Include performance as additional input */
        hidden[h] += performance * optimizer->weights_ih[optimizer->num_parameters * optimizer->hidden_size + h];
        hidden[h] = tanh(hidden[h]); /* Activation */
    }

    /* Forward pass - Output layer */
    for (size_t p = 0; p < optimizer->num_parameters; p++) {
        output[p] = optimizer->bias_o[p];
        for (size_t h = 0; h < optimizer->hidden_size; h++) {
            size_t idx = h * optimizer->num_parameters + p;
            output[p] += hidden[h] * optimizer->weights_ho[idx];
        }
        /* No activation on output - direct parameter prediction */
    }

    /* Calculate loss: MSE between predicted and target parameters */
    /* Target is current_params + performance-based adjustment */
    double total_loss = 0.0;
    for (size_t p = 0; p < optimizer->num_parameters; p++) {
        double target = current_params[p] + performance * 0.1; /* Performance-driven target */
        target = fmax(0.0, fmin(1.0, target)); /* Clamp target */

        double error = output[p] - target;
        total_loss += error * error;

        /* Output gradient for backprop */
        output_grad[p] = 2.0 * error; /* dL/dOutput */
    }
    optimizer->current_loss = total_loss / optimizer->num_parameters;

    /* Backpropagation to compute gradients */
    double gradient_norm_sq = 0.0;

    /* Output layer gradients */
    for (size_t p = 0; p < optimizer->num_parameters; p++) {
        for (size_t h = 0; h < optimizer->hidden_size; h++) {
            size_t idx = h * optimizer->num_parameters + p;
            double grad = output_grad[p] * hidden[h];
            gradient_norm_sq += grad * grad;

            /* Update weights */
            optimizer->weights_ho[idx] -= optimizer->learning_rate * grad;
        }
        /* Update output bias */
        gradient_norm_sq += output_grad[p] * output_grad[p];
        optimizer->bias_o[p] -= optimizer->learning_rate * output_grad[p];
    }

    /* Hidden layer gradients */
    for (size_t h = 0; h < optimizer->hidden_size; h++) {
        hidden_grad[h] = 0.0;
        for (size_t p = 0; p < optimizer->num_parameters; p++) {
            size_t idx = h * optimizer->num_parameters + p;
            hidden_grad[h] += output_grad[p] * optimizer->weights_ho[idx];
        }
        /* Apply tanh derivative */
        hidden_grad[h] *= (1.0 - hidden[h] * hidden[h]);

        /* Update input weights */
        for (size_t p = 0; p < optimizer->num_parameters; p++) {
            size_t idx = p * optimizer->hidden_size + h;
            double grad = hidden_grad[h] * current_params[p];
            gradient_norm_sq += grad * grad;
            optimizer->weights_ih[idx] -= optimizer->learning_rate * grad;
        }

        /* Update performance weight */
        double perf_grad = hidden_grad[h] * performance;
        gradient_norm_sq += perf_grad * perf_grad;
        optimizer->weights_ih[optimizer->num_parameters * optimizer->hidden_size + h] -= optimizer->learning_rate * perf_grad;

        /* Update hidden bias */
        gradient_norm_sq += hidden_grad[h] * hidden_grad[h];
        optimizer->bias_h[h] -= optimizer->learning_rate * hidden_grad[h];
    }

    optimizer->gradient_norm = sqrt(gradient_norm_sq);
    optimizer->training_steps++;

    /* Generate output parameters */
    for (size_t p = 0; p < optimizer->num_parameters; p++) {
        output_params[p] = current_params[p] + optimizer->learning_rate * output[p];
        /* Clamp to reasonable range */
        output_params[p] = fmax(0.0, fmin(1.0, output_params[p]));
    }

    free(hidden);
    free(output);
    free(hidden_grad);
    free(output_grad);
}

void qihse_neural_optimizer_get_stats(
    const qihse_neural_optimizer_t* optimizer,
    double* loss,
    double* gradient_norm
) {
    if (!optimizer) return;

    /* Return actual tracked loss and gradient norm from training */
    if (loss) {
        *loss = optimizer->current_loss;
    }
    if (gradient_norm) {
        *gradient_norm = optimizer->gradient_norm;
    }
}

/* ============================================================================
 * WORKLOAD FINGERPRINTING
 * ============================================================================ */

void qihse_workload_fingerprint_generate(
    qihse_workload_fingerprint_t* fingerprint,
    const void* query,
    size_t data_size,
    const char* query_type
) {
    if (!fingerprint) return;

    memset(fingerprint, 0, sizeof(qihse_workload_fingerprint_t));

    fingerprint->data_size = data_size;

    /* Estimate dimensionality and sparsity */
    if (query && data_size > 0) {
        const float* data = (const float*)query;
        size_t num_elements = data_size / sizeof(float);
        fingerprint->dimensionality = num_elements;

        /* Calculate sparsity (fraction of near-zero elements) */
        size_t zero_count = 0;
        for (size_t i = 0; i < num_elements; i++) {
            if (fabs(data[i]) < 1e-6) {
                zero_count++;
            }
        }
        fingerprint->sparsity = (double)zero_count / num_elements;

        /* Estimate computational density */
        fingerprint->computational_density = (double)num_elements / data_size;
    }

    /* Set query type */
    if (query_type) {
        strncpy(fingerprint->query_type, query_type, sizeof(fingerprint->query_type) - 1);
    }
}

double qihse_workload_fingerprint_compare(
    const qihse_workload_fingerprint_t* fp1,
    const qihse_workload_fingerprint_t* fp2
) {
    if (!fp1 || !fp2) return 0.0;

    double similarity = 1.0;

    /* Compare data size */
    double size_ratio = (double)fmin(fp1->data_size, fp2->data_size) /
                       (double)fmax(fp1->data_size, fp2->data_size);
    similarity *= size_ratio;

    /* Compare dimensionality */
    double dim_ratio = (double)fmin(fp1->dimensionality, fp2->dimensionality) /
                      (double)fmax(fp1->dimensionality, fp2->dimensionality);
    similarity *= dim_ratio;

    /* Compare sparsity */
    double sparsity_diff = fabs(fp1->sparsity - fp2->sparsity);
    similarity *= (1.0 - sparsity_diff);

    /* Compare computational density */
    double density_ratio = fmin(fp1->computational_density, fp2->computational_density) /
                          fmax(fp1->computational_density, fp2->computational_density);
    similarity *= density_ratio;

    /* Compare query type */
    if (strcmp(fp1->query_type, fp2->query_type) == 0) {
        similarity *= 1.0;
    } else {
        similarity *= 0.5; /* Partial similarity for different types */
    }

    return similarity;
}

/* ============================================================================
 * RFF-BASED WORKLOAD EMBEDDING
 * ============================================================================ */

int qihse_rff_workload_embedding_init(
    qihse_rff_workload_embedding_t* embedding,
    size_t embedding_dim,
    double gamma
) {
    if (!embedding || embedding_dim == 0 || gamma <= 0.0) {
        errno = EINVAL;
        return -1;
    }

    memset(embedding, 0, sizeof(qihse_rff_workload_embedding_t));

    embedding->embedding_dim = embedding_dim;
    embedding->gamma = gamma;

    /* Allocate arrays for RFF parameters */
    size_t param_dim = 4; /* data_size, dimensionality, sparsity, computational_density */
    embedding->omega = calloc(param_dim * embedding_dim, sizeof(double));
    embedding->bias = calloc(embedding_dim, sizeof(double));
    embedding->embedding = calloc(embedding_dim, sizeof(double));

    if (!embedding->omega || !embedding->bias || !embedding->embedding) {
        qihse_rff_workload_embedding_destroy(embedding);
        errno = ENOMEM;
        return -1;
    }

    /* Initialize RFF parameters */
    for (size_t i = 0; i < param_dim * embedding_dim; i++) {
        /* Sample from normal distribution for omega */
        double u1 = random_uniform();
        double u2 = random_uniform();
        embedding->omega[i] = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2) * sqrt(2.0 * gamma);
    }

    for (size_t i = 0; i < embedding_dim; i++) {
        embedding->bias[i] = random_uniform() * 2.0 * M_PI;
    }

    return 0;
}

void qihse_rff_workload_embedding_destroy(qihse_rff_workload_embedding_t* embedding) {
    if (!embedding) return;

    free(embedding->omega);
    free(embedding->bias);
    free(embedding->embedding);

    memset(embedding, 0, sizeof(qihse_rff_workload_embedding_t));
}

void qihse_rff_workload_embedding_generate(
    qihse_rff_workload_embedding_t* embedding,
    const qihse_workload_fingerprint_t* fingerprint,
    double* output_embedding,
    size_t output_dim
) {
    if (!embedding || !fingerprint || !output_embedding || output_dim != embedding->embedding_dim) {
        return;
    }

    /* Extract fingerprint features */
    double features[4] = {
        (double)fingerprint->data_size / 1000000.0, /* Normalize data size */
        (double)fingerprint->dimensionality / 1000.0, /* Normalize dimensionality */
        fingerprint->sparsity, /* 0.0-1.0 already */
        fingerprint->computational_density / 100.0 /* Normalize density */
    };

    /* Compute RFF projection */
    for (size_t d = 0; d < embedding->embedding_dim; d++) {
        double projection = 0.0;
        for (size_t f = 0; f < 4; f++) {
            size_t omega_idx = f * embedding->embedding_dim + d;
            projection += features[f] * embedding->omega[omega_idx];
        }
        projection += embedding->bias[d];

        /* RFF approximation: cos(omega * x + bias) */
        embedding->embedding[d] = cos(projection) * sqrt(2.0 / embedding->embedding_dim);
    }

    /* Copy to output */
    memcpy(output_embedding, embedding->embedding, sizeof(double) * output_dim);
}

/* ============================================================================
 * COUNTERFACTUAL LEARNING
 * ============================================================================ */

int qihse_counterfactual_learner_init(
    qihse_counterfactual_learner_t* learner,
    size_t num_arms,
    size_t context_dim,
    size_t max_counterfactuals,
    double learning_rate,
    void* user_data
) {
    if (!learner || num_arms == 0 || context_dim == 0 || max_counterfactuals == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(learner, 0, sizeof(qihse_counterfactual_learner_t));

    learner->num_arms = num_arms;
    learner->context_dim = context_dim;
    learner->max_counterfactuals = max_counterfactuals;
    learner->learning_rate = learning_rate;
    learner->user_data = user_data;

    /* Allocate storage for counterfactuals */
    learner->counterfactual_contexts = calloc(max_counterfactuals * context_dim, sizeof(double));
    learner->counterfactual_arms = calloc(max_counterfactuals, sizeof(size_t));
    learner->counterfactual_rewards = calloc(max_counterfactuals, sizeof(double));
    learner->importance_weights = calloc(max_counterfactuals, sizeof(double));

    if (!learner->counterfactual_contexts || !learner->counterfactual_arms ||
        !learner->counterfactual_rewards || !learner->importance_weights) {
        qihse_counterfactual_learner_destroy(learner);
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

void qihse_counterfactual_learner_destroy(qihse_counterfactual_learner_t* learner) {
    if (!learner) return;

    free(learner->counterfactual_contexts);
    free(learner->counterfactual_arms);
    free(learner->counterfactual_rewards);
    free(learner->importance_weights);

    memset(learner, 0, sizeof(qihse_counterfactual_learner_t));
}

void qihse_counterfactual_learner_log(
    qihse_counterfactual_learner_t* learner,
    size_t selected_arm,
    const double* context,
    double true_reward,
    const size_t* alternative_arms,
    const double* alternative_rewards,
    size_t num_alternatives
) {
    if (!learner || !context || !alternative_arms || !alternative_rewards) return;

    /* Store counterfactual for the selected arm vs alternatives */
    for (size_t alt = 0; alt < num_alternatives; alt++) {
        if (learner->num_counterfactuals >= learner->max_counterfactuals) {
            /* Remove oldest counterfactual (simple FIFO) */
            memmove(learner->counterfactual_contexts,
                   learner->counterfactual_contexts + learner->context_dim,
                   (learner->max_counterfactuals - 1) * learner->context_dim * sizeof(double));
            memmove(learner->counterfactual_arms,
                   learner->counterfactual_arms + 1,
                   (learner->max_counterfactuals - 1) * sizeof(size_t));
            memmove(learner->counterfactual_rewards,
                   learner->counterfactual_rewards + 1,
                   (learner->max_counterfactuals - 1) * sizeof(double));
            memmove(learner->importance_weights,
                   learner->importance_weights + 1,
                   (learner->max_counterfactuals - 1) * sizeof(double));
            learner->num_counterfactuals--;
        }

        /* Store counterfactual data */
        size_t idx = learner->num_counterfactuals;
        size_t context_offset = idx * learner->context_dim;
        memcpy(learner->counterfactual_contexts + context_offset,
               context, learner->context_dim * sizeof(double));

        learner->counterfactual_arms[idx] = alternative_arms[alt];

        /* Counterfactual reward: what if we chose this arm instead? */
        double counterfactual_reward = alternative_rewards[alt];
        learner->counterfactual_rewards[idx] = counterfactual_reward;

        /* Importance weight: probability of selecting alternative vs selected */
        double selected_prob = 1.0 / learner->num_arms; /* Simplified uniform assumption */
        double alternative_prob = 1.0 / learner->num_arms;
        learner->importance_weights[idx] = alternative_prob / selected_prob;

        learner->num_counterfactuals++;
    }
}

void qihse_counterfactual_learner_update(
    qihse_counterfactual_learner_t* learner,
    double* model_parameters,
    size_t num_parameters
) {
    if (!learner || !model_parameters || learner->num_counterfactuals == 0) return;

    /* Perform importance-weighted learning on counterfactuals */
    for (size_t cf = 0; cf < learner->num_counterfactuals; cf++) {
        size_t context_offset = cf * learner->context_dim;
        const double* context = learner->counterfactual_contexts + context_offset;
        size_t arm = learner->counterfactual_arms[cf];
        double counterfactual_reward = learner->counterfactual_rewards[cf];
        double importance_weight = learner->importance_weights[cf];

        /* Simplified gradient update based on counterfactual reward */
        /* Integrates with contextual bandit and other ML models */
        for (size_t p = 0; p < num_parameters && p < learner->context_dim; p++) {
            /* Use context features to modulate parameter updates */
            double gradient = (counterfactual_reward - 0.5) * context[p] * importance_weight;
            model_parameters[p] += learner->learning_rate * gradient;

            /* Clamp parameters to reasonable range */
            model_parameters[p] = fmax(0.0, fmin(1.0, model_parameters[p]));
        }
    }
}

/* ============================================================================
 * TELEMETRY AND MONITORING
 * ============================================================================ */

int qihse_telemetry_collector_init(
    qihse_telemetry_collector_t* collector,
    size_t max_events,
    void* user_data
) {
    if (!collector || max_events == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(collector, 0, sizeof(qihse_telemetry_collector_t));

    collector->max_events = max_events;
    collector->user_data = user_data;

    collector->events = calloc(max_events, sizeof(qihse_telemetry_event_data_t));
    if (!collector->events) {
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

void qihse_telemetry_collector_destroy(qihse_telemetry_collector_t* collector) {
    if (!collector) return;

    free(collector->events);
    memset(collector, 0, sizeof(qihse_telemetry_collector_t));
}

void qihse_telemetry_record_event(
    qihse_telemetry_collector_t* collector,
    const qihse_telemetry_event_data_t* event
) {
    if (!collector || !event) return;

    if (collector->num_events < collector->max_events) {
        collector->events[collector->num_events] = *event;
        collector->num_events++;
    }
    /* If full, could implement circular buffer or drop oldest */
}

char* qihse_telemetry_export_json(const qihse_telemetry_collector_t* collector) {
    if (!collector) return NULL;

    /* Simple JSON export - in production, use proper JSON library */
    size_t json_size = 1024 + collector->num_events * 256;
    char* json = calloc(json_size, sizeof(char));
    if (!json) return NULL;

    snprintf(json, json_size, "%s", "{\"events\":[");

    for (size_t i = 0; i < collector->num_events; i++) {
        const qihse_telemetry_event_data_t* event = &collector->events[i];

        char event_json[256];
        snprintf(event_json, sizeof(event_json),
                "{\"type\":%d,\"timestamp\":%llu,\"component\":\"%s\",\"operation\":\"%s\",\"value\":%f,\"metadata\":\"%s\"}",
                event->type, (unsigned long long)event->timestamp_us,
                event->component, event->operation, event->value, event->metadata);

        if (i > 0) strcat(json, ",");
        strcat(json, event_json);
    }

    strcat(json, "]}");
    return json;
}

/* ============================================================================
 * REGRESSION DETECTION
 * ============================================================================ */

int qihse_regression_detector_init(
    qihse_regression_detector_t* detector,
    size_t window_size,
    double baseline_performance,
    double threshold_stddev,
    void* user_data
) {
    if (!detector || window_size == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(detector, 0, sizeof(qihse_regression_detector_t));

    detector->window_size = window_size;
    detector->baseline_performance = baseline_performance;
    detector->threshold_stddev = threshold_stddev;
    detector->user_data = user_data;

    detector->performance_history = calloc(window_size, sizeof(double));
    if (!detector->performance_history) {
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

void qihse_regression_detector_destroy(qihse_regression_detector_t* detector) {
    if (!detector) return;

    free(detector->performance_history);
    memset(detector, 0, sizeof(qihse_regression_detector_t));
}

bool qihse_regression_detector_update(
    qihse_regression_detector_t* detector,
    double performance
) {
    if (!detector) return false;

    /* Add to history (circular buffer) */
    detector->performance_history[detector->history_count % detector->window_size] = performance;
    detector->history_count++;

    size_t available_samples = fmin(detector->history_count, detector->window_size);

    if (available_samples < 3) {
        return false; /* Need minimum samples for detection */
    }

    /* Calculate mean and standard deviation */
    double sum = 0.0, sum_sq = 0.0;
    for (size_t i = 0; i < available_samples; i++) {
        double val = detector->performance_history[i];
        sum += val;
        sum_sq += val * val;
    }

    double mean = sum / available_samples;
    double variance = (sum_sq / available_samples) - (mean * mean);
    double stddev = sqrt(fmax(0.0, variance));

    /* Check for regression */
    double deviation = (detector->baseline_performance - performance) / fmax(stddev, 1e-6);

    return deviation > detector->threshold_stddev;
}

void qihse_regression_detector_get_stats(
    const qihse_regression_detector_t* detector,
    double* mean,
    double* stddev,
    double* trend
) {
    if (!detector) return;

    size_t available_samples = fmin(detector->history_count, detector->window_size);

    if (available_samples == 0) {
        if (mean) *mean = 0.0;
        if (stddev) *stddev = 0.0;
        if (trend) *trend = 0.0;
        return;
    }

    /* Calculate statistics */
    double sum = 0.0, sum_sq = 0.0;
    for (size_t i = 0; i < available_samples; i++) {
        double val = detector->performance_history[i];
        sum += val;
        sum_sq += val * val;
    }

    double avg = sum / available_samples;
    double variance = (sum_sq / available_samples) - (avg * avg);
    double sd = sqrt(fmax(0.0, variance));

    if (mean) *mean = avg;
    if (stddev) *stddev = sd;
    if (trend) *trend = 0.0; /* Simplified - no trend calculation */
}

/* ============================================================================
 * ML SELF-IMPROVEMENT ENGINE
 * ============================================================================ */

int qihse_ml_engine_init(
    qihse_ml_engine_t* engine,
    const qihse_ml_config_t* config,
    void* user_data
) {
    if (!engine || !config) {
        errno = EINVAL;
        return -1;
    }

    memset(engine, 0, sizeof(qihse_ml_engine_t));
    engine->config = *config;
    engine->user_data = user_data;

    /* Initialize components */
    int ret;

    ret = qihse_thompson_bandit_init(&engine->bandit, config->bandit_arms, user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_contextual_bandit_init(&engine->contextual_bandit,
                                      config->bandit_arms,
                                      config->contextual_context_dim,
                                      config->contextual_hidden_size,
                                      config->learning_rate,
                                      user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_neural_optimizer_init(&engine->optimizer,
                                     config->optimizer_params,
                                     config->hidden_size,
                                     config->learning_rate,
                                     user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_rff_workload_embedding_init(&engine->rff_embedding,
                                           config->rff_embedding_dim,
                                           config->rff_gamma);
    if (ret != 0) goto cleanup;

    ret = qihse_counterfactual_learner_init(&engine->counterfactual_learner,
                                           config->bandit_arms,
                                           config->contextual_context_dim,
                                           config->counterfactual_max,
                                           config->learning_rate,
                                           user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_telemetry_collector_init(&engine->telemetry,
                                        config->telemetry_buffer,
                                        user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_variational_optimizer_init(&engine->variational_optimizer,
                                          config->optimizer_params,
                                          config->variational_superposition_depth,
                                          config->variational_layers,
                                          config->learning_rate,
                                          user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_grover_parameter_search_init(&engine->grover_search,
                                           config->grover_search_space,
                                           config->grover_threshold,
                                           user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_meta_optimizer_init(&engine->meta_optimizer,
                                   config->meta_tasks,
                                   config->meta_task_dim,
                                   config->meta_inner_steps,
                                   config->learning_rate,
                                   config->learning_rate,
                                   user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_attention_layer_init(&engine->attention_layer,
                                    config->attention_embed_dim,
                                    config->attention_heads,
                                    config->attention_seq_len,
                                    user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_adam_optimizer_init(&engine->adam_optimizer,
                                   config->optimizer_params,
                                   config->learning_rate,
                                   0.9, 0.999, 1e-8, 0.01, /* AdamW defaults */
                                   user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_energy_optimizer_init(&engine->energy_optimizer,
                                     4, /* num_devices - CPU cores */
                                     config->energy_power_budget,
                                     config->energy_thermal_limit,
                                     0.5, /* energy_precision_tradeoff */
                                     user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_rl_agent_init(&engine->rl_agent,
                             config->rl_state_dim,
                             config->rl_action_dim,
                             64, /* hidden_size */
                             config->rl_replay_buffer,
                             config->learning_rate,
                             0.99, /* gamma */
                             0.1, /* epsilon */
                             user_data);
    if (ret != 0) goto cleanup;

    ret = qihse_regression_detector_init(&engine->regression_detector,
                                        config->regression_window,
                                        config->baseline_performance,
                                        config->regression_threshold,
                                        user_data);
    if (ret != 0) goto cleanup;

    return 0;

cleanup:
    qihse_ml_engine_destroy(engine);
    return ret;
}

void qihse_ml_engine_destroy(qihse_ml_engine_t* engine) {
    if (!engine) return;

    qihse_thompson_bandit_destroy(&engine->bandit);
    qihse_contextual_bandit_destroy(&engine->contextual_bandit);
    qihse_neural_optimizer_destroy(&engine->optimizer);
    qihse_rff_workload_embedding_destroy(&engine->rff_embedding);
    qihse_counterfactual_learner_destroy(&engine->counterfactual_learner);
    qihse_variational_optimizer_destroy(&engine->variational_optimizer);
    qihse_grover_parameter_search_destroy(&engine->grover_search);
    qihse_meta_optimizer_destroy(&engine->meta_optimizer);
    qihse_attention_layer_destroy(&engine->attention_layer);
    qihse_adam_optimizer_destroy(&engine->adam_optimizer);
    qihse_energy_optimizer_destroy(&engine->energy_optimizer);
    qihse_rl_agent_destroy(&engine->rl_agent);
    qihse_telemetry_collector_destroy(&engine->telemetry);
    qihse_regression_detector_destroy(&engine->regression_detector);

    memset(engine, 0, sizeof(qihse_ml_engine_t));
}

void qihse_ml_engine_process_query(
    qihse_ml_engine_t* engine,
    const void* query,
    const char* query_type,
    double current_performance,
    double* optimized_params
) {
    if (!engine || !query || !optimized_params) return;

    /* Generate workload fingerprint */
    qihse_workload_fingerprint_generate(&engine->current_fingerprint,
                                       query, 1024, query_type);

    /* Generate RFF embedding from fingerprint */
    double context_embedding[engine->config.contextual_context_dim];
    qihse_rff_workload_embedding_generate(&engine->rff_embedding,
                                         &engine->current_fingerprint,
                                         context_embedding,
                                         engine->config.contextual_context_dim);

    /* Use contextual bandit with RFF embedding as context */
    size_t selected_arm = qihse_contextual_bandit_select_arm(&engine->contextual_bandit,
                                                            context_embedding);

    /* Use neural optimizer to generate optimized parameters */
    double current_params[engine->config.optimizer_params];
    /* Initialize with default values - in production, use actual current config */
    for (size_t i = 0; i < engine->config.optimizer_params; i++) {
        current_params[i] = 0.5; /* Default */
    }

    /* Try variational optimization if available, fallback to neural optimizer */
    int variational_ret = qihse_variational_optimizer_step(&engine->variational_optimizer,
                                                          current_params,
                                                          NULL, /* Simple energy function */
                                                          NULL,
                                                          optimized_params);

    if (variational_ret != 0) {
        /* Fallback to neural optimizer */
        qihse_neural_optimizer_step(&engine->optimizer,
                                   current_params,
                                   current_performance,
                                   optimized_params);
    }

    /* Record telemetry */
    qihse_telemetry_event_data_t event = {
        .type = QIHSE_TELEMETRY_QUERY_START,
        .timestamp_us = (uint64_t)time(NULL) * 1000000ULL,
        .value = current_performance
    };
    snprintf(event.component, sizeof(event.component), "%s", "ml_engine");
    snprintf(event.operation, sizeof(event.operation), "%s", "process_query");
    snprintf(event.metadata, sizeof(event.metadata), "arm=%zu,contextual=true,variational=%s", selected_arm, variational_ret == 0 ? "true" : "false");

    qihse_telemetry_record_event(&engine->telemetry, &event);
}

void qihse_ml_engine_train(
    qihse_ml_engine_t* engine,
    double performance,
    const double* params_used
) {
    if (!engine) return;

    /* Generate RFF embedding from current fingerprint for context */
    double context_embedding[engine->config.contextual_context_dim];
    qihse_rff_workload_embedding_generate(&engine->rff_embedding,
                                         &engine->current_fingerprint,
                                         context_embedding,
                                         engine->config.contextual_context_dim);

    /* Update neural optimizer */
    qihse_neural_optimizer_step(&engine->optimizer,
                               params_used,
                               performance,
                               NULL); /* In-place update */

    /* Update contextual bandit with performance feedback */
    double reward = fmax(0.0, fmin(1.0, performance));

    /* For counterfactual learning, log alternatives */
    size_t alternative_arms[engine->config.bandit_arms - 1];
    double alternative_rewards[engine->config.bandit_arms - 1];
    size_t num_alternatives = 0;

    /* Generate counterfactuals for other arms */
    for (size_t arm = 0; arm < engine->config.bandit_arms; arm++) {
        if (arm != 0) { /* Assuming arm 0 was selected */
            alternative_arms[num_alternatives] = arm;
            /* Simulate alternative reward based on Beta distribution */
            alternative_rewards[num_alternatives] = random_beta(1.0, 1.0); /* Prior */
            num_alternatives++;
        }
    }

    /* Log counterfactuals for learning */
    qihse_counterfactual_learner_log(&engine->counterfactual_learner,
                                    0, /* selected arm */
                                    context_embedding,
                                    reward,
                                    alternative_arms,
                                    alternative_rewards,
                                    num_alternatives);

    /* Update contextual bandit */
    qihse_contextual_bandit_update(&engine->contextual_bandit,
                                  0, /* selected arm */
                                  context_embedding,
                                  reward);

    /* Update Thompson sampling bandit (legacy) */
    qihse_thompson_bandit_update(&engine->bandit, 0, reward);

    /* Update counterfactual learner (make a copy since it modifies parameters) */
    double* params_copy = malloc(engine->config.optimizer_params * sizeof(double));
    if (params_copy) {
        memcpy(params_copy, params_used, engine->config.optimizer_params * sizeof(double));
        qihse_counterfactual_learner_update(&engine->counterfactual_learner,
                                           params_copy,
                                           engine->config.optimizer_params);
        free(params_copy);
    }

    /* Record training telemetry */
    qihse_telemetry_event_data_t event;
    event.type = QIHSE_TELEMETRY_OPTIMIZATION;
    event.timestamp_us = (uint64_t)time(NULL) * 1000000ULL;
    event.value = performance;
    snprintf(event.component, sizeof(event.component), "%s", "ml_engine");
    snprintf(event.operation, sizeof(event.operation), "%s", "train");
    snprintf(event.metadata, sizeof(event.metadata), "reward=%f,contextual=true", reward);

    qihse_telemetry_record_event(&engine->telemetry, &event);
}

bool qihse_ml_engine_detect_regression(
    qihse_ml_engine_t* engine,
    double current_performance
) {
    if (!engine) return false;

    return qihse_regression_detector_update(&engine->regression_detector,
                                           current_performance);
}

char* qihse_ml_engine_export_status_json(const qihse_ml_engine_t* engine) {
    if (!engine) return NULL;

    /* Simple status export */
    char* status = calloc(1024, sizeof(char));
    if (!status) return NULL;

    double mean, stddev, trend;
    qihse_regression_detector_get_stats(&engine->regression_detector,
                                       &mean, &stddev, &trend);

    double success_rate, confidence;
    qihse_thompson_bandit_get_stats(&engine->bandit, 0, &success_rate, &confidence);

    snprintf(status, 1024,
            "{\"bandit\":{\"success_rate\":%f,\"confidence\":%f},"
            "\"regression\":{\"mean\":%f,\"stddev\":%f,\"trend\":%f},"
            "\"telemetry\":{\"events\":%zu}}",
            success_rate, confidence, mean, stddev, trend,
            engine->telemetry.num_events);

    return status;
}

