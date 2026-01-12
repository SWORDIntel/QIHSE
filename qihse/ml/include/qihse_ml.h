/*
 * QIHSE - Machine Learning Self-Optimization Engine
 *
 * Self-optimizing runtime with Thompson Sampling, neural optimization,
 * and continuous learning capabilities.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_ML_H
#define QIHSE_ML_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONTEXTUAL BANDITS
 * ============================================================================ */

/**
 * Contextual bandit with neural context model.
 */
typedef struct qihse_contextual_bandit_s {
    size_t num_arms;           /* Number of parameter choices */
    size_t context_dim;        /* Context feature dimension */
    size_t hidden_size;        /* Neural network hidden size */
    double learning_rate;      /* Learning rate for context model */
    double* context_weights;   /* Neural network weights for context */
    double* arm_bias;          /* Bias terms for each arm */
    size_t* successes;         /* Success counts for each arm */
    size_t* failures;          /* Failure counts for each arm */
    double* alpha;             /* Beta distribution alpha parameters */
    double* beta;              /* Beta distribution beta parameters */
    double context_loss;       /* Current context model loss */
    void* user_data;           /* User context */
} qihse_contextual_bandit_t;

/**
 * Initialize contextual bandit.
 *
 * @param bandit Bandit to initialize
 * @param num_arms Number of parameter choices
 * @param context_dim Context feature dimension
 * @param hidden_size Hidden layer size for context model
 * @param learning_rate Learning rate
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_contextual_bandit_init(
    qihse_contextual_bandit_t* bandit,
    size_t num_arms,
    size_t context_dim,
    size_t hidden_size,
    double learning_rate,
    void* user_data
);

/**
 * Destroy contextual bandit.
 *
 * @param bandit Bandit to destroy
 */
void qihse_contextual_bandit_destroy(qihse_contextual_bandit_t* bandit);

/**
 * Select arm using contextual bandit with neural context model.
 *
 * @param bandit Bandit instance
 * @param context Context features
 * @return Selected arm index
 */
size_t qihse_contextual_bandit_select_arm(
    qihse_contextual_bandit_t* bandit,
    const double* context
);

/**
 * Update bandit with reward and context.
 *
 * @param bandit Bandit instance
 * @param arm Selected arm
 * @param context Context features used for selection
 * @param reward Reward value (0.0 to 1.0)
 */
void qihse_contextual_bandit_update(
    qihse_contextual_bandit_t* bandit,
    size_t arm,
    const double* context,
    double reward
);

/**
 * Get arm statistics with context.
 *
 * @param bandit Bandit instance
 * @param arm Arm index
 * @param context Context features
 * @param expected_reward Output expected reward for this arm-context
 * @param confidence Output confidence interval
 */
void qihse_contextual_bandit_get_stats(
    const qihse_contextual_bandit_t* bandit,
    size_t arm,
    const double* context,
    double* expected_reward,
    double* confidence
);

/* ============================================================================
 * THOMPSON SAMPLING BANDIT
 * ============================================================================ */

/**
 * Thompson Sampling bandit for parameter optimization.
 */
typedef struct qihse_thompson_bandit_s {
    size_t num_arms;           /* Number of parameter choices */
    size_t* successes;         /* Success counts for each arm */
    size_t* failures;          /* Failure counts for each arm */
    double* alpha;             /* Beta distribution alpha parameters */
    double* beta;              /* Beta distribution beta parameters */
    void* user_data;           /* User context */
} qihse_thompson_bandit_t;

/**
 * Initialize Thompson Sampling bandit.
 *
 * @param bandit Bandit to initialize
 * @param num_arms Number of parameter choices
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_thompson_bandit_init(
    qihse_thompson_bandit_t* bandit,
    size_t num_arms,
    void* user_data
);

/**
 * Destroy Thompson Sampling bandit.
 *
 * @param bandit Bandit to destroy
 */
void qihse_thompson_bandit_destroy(qihse_thompson_bandit_t* bandit);

/**
 * Select arm using Thompson Sampling.
 *
 * @param bandit Bandit instance
 * @return Selected arm index
 */
size_t qihse_thompson_bandit_select_arm(qihse_thompson_bandit_t* bandit);

/**
 * Update bandit with reward observation.
 *
 * @param bandit Bandit instance
 * @param arm Selected arm
 * @param reward Reward value (0.0 to 1.0)
 */
void qihse_thompson_bandit_update(
    qihse_thompson_bandit_t* bandit,
    size_t arm,
    double reward
);

/**
 * Get arm statistics.
 *
 * @param bandit Bandit instance
 * @param arm Arm index
 * @param success_rate Output success rate
 * @param confidence Output confidence interval
 */
void qihse_thompson_bandit_get_stats(
    const qihse_thompson_bandit_t* bandit,
    size_t arm,
    double* success_rate,
    double* confidence
);

/* ============================================================================
 * NEURAL NETWORK OPTIMIZER
 * ============================================================================ */

/**
 * Neural network optimizer for parameter tuning.
 */
typedef struct qihse_neural_optimizer_s {
    size_t num_parameters;     /* Number of parameters to optimize */
    size_t hidden_size;        /* Hidden layer size */
    double learning_rate;      /* Learning rate */
    double* weights_ih;        /* Input to hidden weights */
    double* weights_ho;        /* Hidden to output weights */
    double* bias_h;            /* Hidden layer biases */
    double* bias_o;            /* Output layer biases */
    double current_loss;       /* Current training loss */
    double gradient_norm;      /* Current gradient norm */
    size_t training_steps;     /* Number of training steps performed */
    void* user_data;           /* User context */
} qihse_neural_optimizer_t;

/**
 * Initialize neural network optimizer.
 *
 * @param optimizer Optimizer to initialize
 * @param num_parameters Number of parameters
 * @param hidden_size Hidden layer size
 * @param learning_rate Learning rate
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_neural_optimizer_init(
    qihse_neural_optimizer_t* optimizer,
    size_t num_parameters,
    size_t hidden_size,
    double learning_rate,
    void* user_data
);

/**
 * Destroy neural network optimizer.
 *
 * @param optimizer Optimizer to destroy
 */
void qihse_neural_optimizer_destroy(qihse_neural_optimizer_t* optimizer);

/**
 * Optimize parameters using neural network.
 *
 * @param optimizer Optimizer instance
 * @param current_params Current parameter values
 * @param performance Performance metric
 * @param output_params Output optimized parameters
 */
void qihse_neural_optimizer_step(
    qihse_neural_optimizer_t* optimizer,
    const double* current_params,
    double performance,
    double* output_params
);

/**
 * Get optimizer statistics.
 *
 * @param optimizer Optimizer instance
 * @param loss Output current loss
 * @param gradient_norm Output gradient norm
 */
void qihse_neural_optimizer_get_stats(
    const qihse_neural_optimizer_t* optimizer,
    double* loss,
    double* gradient_norm
);

/* ============================================================================
 * WORKLOAD FINGERPRINTING
 * ============================================================================ */

/**
 * Workload fingerprint for optimization.
 */
typedef struct qihse_workload_fingerprint_s {
    size_t data_size;          /* Input data size */
    size_t dimensionality;     /* Data dimensionality */
    double sparsity;           /* Data sparsity (0.0-1.0) */
    double computational_density; /* FLOPs per byte */
    char query_type[64];       /* Query type string */
    void* custom_features;     /* Custom workload features */
} qihse_workload_fingerprint_t;

/**
 * Generate workload fingerprint.
 *
 * @param fingerprint Output fingerprint
 * @param query Query data
 * @param data_size Data size in bytes
 * @param query_type Query type string
 */
void qihse_workload_fingerprint_generate(
    qihse_workload_fingerprint_t* fingerprint,
    const void* query,
    size_t data_size,
    const char* query_type
);

/**
 * Compare workload fingerprints.
 *
 * @param fp1 First fingerprint
 * @param fp2 Second fingerprint
 * @return Similarity score (0.0-1.0)
 */
double qihse_workload_fingerprint_compare(
    const qihse_workload_fingerprint_t* fp1,
    const qihse_workload_fingerprint_t* fp2
);

/* ============================================================================
 * RFF-BASED WORKLOAD EMBEDDING
 * ============================================================================ */

/**
 * RFF-based workload embedding.
 */
typedef struct qihse_rff_workload_embedding_s {
    size_t embedding_dim;      /* RFF embedding dimension */
    double gamma;              /* RFF kernel parameter */
    double* omega;             /* Random frequencies */
    double* bias;              /* Random biases */
    double* embedding;         /* Current embedding */
    void* rff_kernel;          /* RFF kernel instance */
} qihse_rff_workload_embedding_t;

/**
 * Initialize RFF-based workload embedding.
 *
 * @param embedding Embedding to initialize
 * @param embedding_dim RFF embedding dimension
 * @param gamma RFF kernel parameter
 * @return 0 on success, negative error code on failure
 */
int qihse_rff_workload_embedding_init(
    qihse_rff_workload_embedding_t* embedding,
    size_t embedding_dim,
    double gamma
);

/**
 * Destroy RFF-based workload embedding.
 *
 * @param embedding Embedding to destroy
 */
void qihse_rff_workload_embedding_destroy(qihse_rff_workload_embedding_t* embedding);

/**
 * Generate RFF embedding from workload fingerprint.
 *
 * @param embedding Embedding instance
 * @param fingerprint Workload fingerprint
 * @param output_embedding Output embedding vector
 * @param output_dim Output dimension
 */
void qihse_rff_workload_embedding_generate(
    qihse_rff_workload_embedding_t* embedding,
    const qihse_workload_fingerprint_t* fingerprint,
    double* output_embedding,
    size_t output_dim
);

/* ============================================================================
 * COUNTERFACTUAL LEARNING
 * ============================================================================ */

/**
 * Counterfactual learning framework.
 */
typedef struct qihse_counterfactual_learner_s {
    size_t num_arms;           /* Number of arms */
    size_t context_dim;        /* Context dimension */
    size_t max_counterfactuals; /* Maximum counterfactuals to store */
    size_t num_counterfactuals; /* Current counterfactual count */
    double* counterfactual_contexts; /* Stored counterfactual contexts */
    size_t* counterfactual_arms; /* Stored counterfactual arms */
    double* counterfactual_rewards; /* Stored counterfactual rewards */
    double* importance_weights; /* Importance sampling weights */
    double learning_rate;      /* Learning rate for counterfactual updates */
    void* user_data;           /* User context */
} qihse_counterfactual_learner_t;

/**
 * Initialize counterfactual learner.
 *
 * @param learner Learner to initialize
 * @param num_arms Number of arms
 * @param context_dim Context dimension
 * @param max_counterfactuals Maximum counterfactuals to store
 * @param learning_rate Learning rate
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_counterfactual_learner_init(
    qihse_counterfactual_learner_t* learner,
    size_t num_arms,
    size_t context_dim,
    size_t max_counterfactuals,
    double learning_rate,
    void* user_data
);

/**
 * Destroy counterfactual learner.
 *
 * @param learner Learner to destroy
 */
void qihse_counterfactual_learner_destroy(qihse_counterfactual_learner_t* learner);

/**
 * Log counterfactual for learning.
 *
 * @param learner Learner instance
 * @param selected_arm Arm that was actually selected
 * @param context Context that was used
 * @param true_reward True reward for selected arm
 * @param alternative_arms Alternative arms that could have been selected
 * @param alternative_rewards Rewards for alternative arms
 * @param num_alternatives Number of alternative arms
 */
void qihse_counterfactual_learner_log(
    qihse_counterfactual_learner_t* learner,
    size_t selected_arm,
    const double* context,
    double true_reward,
    const size_t* alternative_arms,
    const double* alternative_rewards,
    size_t num_alternatives
);

/**
 * Learn from counterfactuals using importance sampling.
 *
 * @param learner Learner instance
 * @param model_parameters Model parameters to update
 * @param num_parameters Number of parameters
 */
void qihse_counterfactual_learner_update(
    qihse_counterfactual_learner_t* learner,
    double* model_parameters,
    size_t num_parameters
);

/* ============================================================================
 * VARIATIONAL QUANTUM-INSPIRED OPTIMIZATION
 * ============================================================================ */

/**
 * Variational quantum-inspired optimizer using superposition states.
 */
typedef struct qihse_variational_optimizer_s {
    size_t num_parameters;      /* Number of parameters to optimize */
    size_t superposition_depth; /* Depth of superposition representation */
    size_t num_layers;          /* Number of variational layers */
    double learning_rate;      /* Learning rate for parameter updates */
    double* variational_params; /* Variational circuit parameters */
    double* superposition_state; /* Current superposition representation */
    double* gradient_buffer;    /* Gradient computation buffer */
    size_t iterations;          /* Training iterations performed */
    double current_energy;      /* Current energy expectation value */
    void* user_data;           /* User context */
} qihse_variational_optimizer_t;

/**
 * Initialize variational optimizer.
 *
 * @param optimizer Optimizer to initialize
 * @param num_parameters Number of parameters
 * @param superposition_depth Superposition state depth
 * @param num_layers Number of variational layers
 * @param learning_rate Learning rate
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_variational_optimizer_init(
    qihse_variational_optimizer_t* optimizer,
    size_t num_parameters,
    size_t superposition_depth,
    size_t num_layers,
    double learning_rate,
    void* user_data
);

/**
 * Destroy variational optimizer.
 *
 * @param optimizer Optimizer to destroy
 */
void qihse_variational_optimizer_destroy(qihse_variational_optimizer_t* optimizer);

/**
 * Execute variational optimization step.
 *
 * @param optimizer Optimizer instance
 * @param current_params Current parameter values
 * @param energy_function Energy/cost function to minimize
 * @param output_params Output optimized parameters
 * @return 0 on success, negative error code on failure
 */
int qihse_variational_optimizer_step(
    qihse_variational_optimizer_t* optimizer,
    const double* current_params,
    double (*energy_function)(const double*, size_t, void*),
    void* energy_context,
    double* output_params
);

/**
 * Get optimizer statistics.
 *
 * @param optimizer Optimizer instance
 * @param energy Output current energy
 * @param iterations Output iterations performed
 */
void qihse_variational_optimizer_get_stats(
    const qihse_variational_optimizer_t* optimizer,
    double* energy,
    size_t* iterations
);

/* ============================================================================
 * GROVER AMPLIFICATION FOR PARAMETER SEARCH
 * ============================================================================ */

/**
 * Grover amplification parameter search.
 */
typedef struct qihse_grover_parameter_search_s {
    size_t search_space_size;   /* Size of parameter search space */
    size_t num_iterations;      /* Number of Grover iterations */
    double* search_space;       /* Parameter search space */
    double* oracle_marks;       /* Oracle marking of good solutions */
    double* amplitude_state;    /* Quantum amplitude state */
    double optimal_threshold;   /* Threshold for optimal solutions */
    size_t found_optimal_count; /* Number of optimal solutions found */
    void* user_data;           /* User context */
} qihse_grover_parameter_search_t;

/**
 * Initialize Grover parameter search.
 *
 * @param search Search to initialize
 * @param search_space_size Size of search space
 * @param optimal_threshold Threshold for optimal solutions
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_grover_parameter_search_init(
    qihse_grover_parameter_search_t* search,
    size_t search_space_size,
    double optimal_threshold,
    void* user_data
);

/**
 * Destroy Grover parameter search.
 *
 * @param search Search to destroy
 */
void qihse_grover_parameter_search_destroy(qihse_grover_parameter_search_t* search);

/**
 * Execute Grover search iteration.
 *
 * @param search Search instance
 * @param parameter_space Current parameter space
 * @param performance_evaluator Function to evaluate parameter performance
 * @param context Context for performance evaluation
 * @return 0 on success, negative error code on failure
 */
int qihse_grover_parameter_search_iterate(
    qihse_grover_parameter_search_t* search,
    const double* parameter_space,
    double (*performance_evaluator)(const double*, size_t, void*),
    void* context
);

/**
 * Get optimal parameters from Grover search.
 *
 * @param search Search instance
 * @param optimal_params Output buffer for optimal parameters
 * @param max_params Maximum number of parameters to return
 * @param num_found Output number of optimal parameters found
 */
void qihse_grover_parameter_search_get_optimal(
    const qihse_grover_parameter_search_t* search,
    double* optimal_params,
    size_t max_params,
    size_t* num_found
);

/* ============================================================================
 * META-LEARNING FOR FAST ADAPTATION
 * ============================================================================ */

/**
 * Meta-learning optimizer for fast adaptation.
 */
typedef struct qihse_meta_optimizer_s {
    size_t num_tasks;              /* Number of meta-learning tasks */
    size_t task_dim;               /* Task feature dimension */
    size_t inner_steps;            /* Inner loop adaptation steps */
    double meta_lr;                /* Meta-learning rate */
    double inner_lr;               /* Inner adaptation learning rate */
    double* meta_params;           /* Meta-parameters (theta) */
    double* task_embeddings;       /* Task embedding vectors */
    size_t adaptation_samples;     /* Samples used for adaptation */
    double meta_loss;              /* Current meta-loss */
    void* user_data;              /* User context */
} qihse_meta_optimizer_t;

/**
 * Initialize meta-learning optimizer.
 *
 * @param optimizer Optimizer to initialize
 * @param num_tasks Number of meta-learning tasks
 * @param task_dim Task feature dimension
 * @param inner_steps Inner loop adaptation steps
 * @param meta_lr Meta-learning rate
 * @param inner_lr Inner adaptation learning rate
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_meta_optimizer_init(
    qihse_meta_optimizer_t* optimizer,
    size_t num_tasks,
    size_t task_dim,
    size_t inner_steps,
    double meta_lr,
    double inner_lr,
    void* user_data
);

/**
 * Destroy meta-learning optimizer.
 *
 * @param optimizer Optimizer to destroy
 */
void qihse_meta_optimizer_destroy(qihse_meta_optimizer_t* optimizer);

/**
 * Perform meta-learning update across tasks.
 *
 * @param optimizer Optimizer instance
 * @param task_features Array of task feature vectors
 * @param task_losses Array of task losses
 * @param num_tasks Number of tasks in this meta-batch
 */
void qihse_meta_optimizer_update(
    qihse_meta_optimizer_t* optimizer,
    const double* task_features,
    const double* task_losses,
    size_t num_tasks
);

/**
 * Adapt to new task using meta-learned initialization.
 *
 * @param optimizer Optimizer instance
 * @param task_features Task feature vector
 * @param adaptation_data Adaptation data (inputs, targets)
 * @param num_samples Number of adaptation samples
 * @param adapted_params Output adapted parameters
 */
void qihse_meta_optimizer_adapt(
    const qihse_meta_optimizer_t* optimizer,
    const double* task_features,
    const double* adaptation_data,
    size_t num_samples,
    double* adapted_params
);

/**
 * Get meta-optimizer statistics.
 *
 * @param optimizer Optimizer instance
 * @param meta_loss Output current meta-loss
 * @param adaptation_speed Output adaptation speed metric
 */
void qihse_meta_optimizer_get_stats(
    const qihse_meta_optimizer_t* optimizer,
    double* meta_loss,
    double* adaptation_speed
);

/* ============================================================================
 * ADVANCED NEURAL ARCHITECTURES
 * ============================================================================ */

/**
 * Attention mechanism for context modeling.
 */
typedef struct qihse_attention_layer_s {
    size_t embed_dim;              /* Embedding dimension */
    size_t num_heads;              /* Number of attention heads */
    size_t seq_len;                /* Sequence length */
    double* query_weights;         /* Query projection weights */
    double* key_weights;           /* Key projection weights */
    double* value_weights;         /* Value projection weights */
    double* output_weights;        /* Output projection weights */
    double* attention_scores;      /* Attention score matrix */
    void* user_data;              /* User context */
} qihse_attention_layer_t;

/**
 * Initialize attention layer.
 *
 * @param layer Layer to initialize
 * @param embed_dim Embedding dimension
 * @param num_heads Number of attention heads
 * @param seq_len Sequence length
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_attention_layer_init(
    qihse_attention_layer_t* layer,
    size_t embed_dim,
    size_t num_heads,
    size_t seq_len,
    void* user_data
);

/**
 * Destroy attention layer.
 *
 * @param layer Layer to destroy
 */
void qihse_attention_layer_destroy(qihse_attention_layer_t* layer);

/**
 * Apply attention mechanism.
 *
 * @param layer Layer instance
 * @param input Input sequence [seq_len * embed_dim]
 * @param output Output sequence [seq_len * embed_dim]
 */
void qihse_attention_layer_forward(
    qihse_attention_layer_t* layer,
    const double* input,
    double* output
);

/**
 * Advanced neural optimizer with Adam/AdamW.
 */
typedef struct qihse_adam_optimizer_s {
    size_t num_parameters;         /* Number of parameters */
    double learning_rate;          /* Learning rate */
    double beta1;                  /* Beta1 parameter (momentum) */
    double beta2;                  /* Beta2 parameter (RMSProp) */
    double epsilon;                 /* Numerical stability epsilon */
    double weight_decay;           /* Weight decay (AdamW) */
    size_t t;                      /* Timestep counter */
    double* m;                     /* First moment vector */
    double* v;                     /* Second moment vector */
    double* params;                /* Parameter storage */
    void* user_data;              /* User context */
} qihse_adam_optimizer_t;

/**
 * Initialize Adam optimizer.
 *
 * @param optimizer Optimizer to initialize
 * @param num_parameters Number of parameters
 * @param learning_rate Learning rate
 * @param beta1 Beta1 parameter
 * @param beta2 Beta2 parameter
 * @param epsilon Epsilon for numerical stability
 * @param weight_decay Weight decay (0 for Adam, >0 for AdamW)
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_adam_optimizer_init(
    qihse_adam_optimizer_t* optimizer,
    size_t num_parameters,
    double learning_rate,
    double beta1,
    double beta2,
    double epsilon,
    double weight_decay,
    void* user_data
);

/**
 * Destroy Adam optimizer.
 *
 * @param optimizer Optimizer to destroy
 */
void qihse_adam_optimizer_destroy(qihse_adam_optimizer_t* optimizer);

/**
 * Perform Adam optimization step.
 *
 * @param optimizer Optimizer instance
 * @param gradients Gradient vector
 * @param output_params Output updated parameters
 */
void qihse_adam_optimizer_step(
    qihse_adam_optimizer_t* optimizer,
    const double* gradients,
    double* output_params
);

/**
 * Get Adam optimizer statistics.
 *
 * @param optimizer Optimizer instance
 * @param lr Output effective learning rate
 * @param momentum Output momentum term
 */
void qihse_adam_optimizer_get_stats(
    const qihse_adam_optimizer_t* optimizer,
    double* lr,
    double* momentum
);

/* ============================================================================
 * ENERGY-AWARE OPTIMIZATION SYSTEM
 * ============================================================================ */

/**
 * Energy profile for device power management.
 */
typedef struct qihse_energy_profile_s {
    double power_budget_watts;      /* Maximum power consumption in watts */
    double thermal_limit_celsius;  /* Maximum temperature in Celsius */
    double energy_per_query_joules; /* Target energy per query in joules */
    double dvfs_frequency_ghz;     /* Target CPU frequency in GHz */
    int thermal_zone_id;           /* Thermal zone identifier */
    double current_power_watts;    /* Current power consumption */
    double current_temperature_c;  /* Current temperature */
    uint64_t last_measurement_us;  /* Last measurement timestamp */
} qihse_energy_profile_t;

/**
 * Energy-aware optimizer.
 */
typedef struct qihse_energy_optimizer_s {
    size_t num_devices;             /* Number of managed devices */
    qihse_energy_profile_t* device_profiles; /* Per-device energy profiles */
    double global_power_budget;     /* Total system power budget */
    double global_thermal_limit;    /* Global thermal limit */
    double energy_precision_tradeoff; /* Energy vs accuracy tradeoff factor */
    double current_total_power;     /* Current total power consumption */
    double current_max_temperature; /* Current maximum temperature */
    double* device_frequencies;     /* Current device frequencies */
    int* device_thermal_zones;      /* Device thermal zone mappings */
    void* user_data;               /* User context */
} qihse_energy_optimizer_t;

/**
 * Initialize energy-aware optimizer.
 *
 * @param optimizer Optimizer to initialize
 * @param num_devices Number of devices to manage
 * @param global_power_budget Total power budget in watts
 * @param global_thermal_limit Global thermal limit in Celsius
 * @param energy_precision_tradeoff Energy-precision tradeoff factor
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_energy_optimizer_init(
    qihse_energy_optimizer_t* optimizer,
    size_t num_devices,
    double global_power_budget,
    double global_thermal_limit,
    double energy_precision_tradeoff,
    void* user_data
);

/**
 * Destroy energy-aware optimizer.
 *
 * @param optimizer Optimizer to destroy
 */
void qihse_energy_optimizer_destroy(qihse_energy_optimizer_t* optimizer);

/**
 * Set device energy profile.
 *
 * @param optimizer Optimizer instance
 * @param device_id Device identifier
 * @param profile Energy profile for the device
 * @return 0 on success, negative error code on failure
 */
int qihse_energy_optimizer_set_device_profile(
    qihse_energy_optimizer_t* optimizer,
    size_t device_id,
    const qihse_energy_profile_t* profile
);

/**
 * Optimize energy consumption for workload.
 *
 * @param optimizer Optimizer instance
 * @param workload_intensity Workload intensity (0.0-1.0)
 * @param precision_requirement Required precision level
 * @param output_frequencies Output optimal frequencies for each device
 * @param output_power_budget Output power allocation
 * @return 0 on success, negative error code on failure
 */
int qihse_energy_optimizer_optimize_workload(
    qihse_energy_optimizer_t* optimizer,
    double workload_intensity,
    double precision_requirement,
    double* output_frequencies,
    double* output_power_budget
);

/**
 * Monitor and adjust energy consumption.
 *
 * @param optimizer Optimizer instance
 * @return 0 on success, negative error code on failure
 */
int qihse_energy_optimizer_monitor_and_adjust(qihse_energy_optimizer_t* optimizer);

/**
 * Get energy statistics.
 *
 * @param optimizer Optimizer instance
 * @param total_power Output total power consumption
 * @param max_temperature Output maximum temperature
 * @param efficiency Output energy efficiency metric
 */
void qihse_energy_optimizer_get_stats(
    const qihse_energy_optimizer_t* optimizer,
    double* total_power,
    double* max_temperature,
    double* efficiency
);

/* ============================================================================
 * REINFORCEMENT LEARNING ALGORITHM DISCOVERY
 * ============================================================================ */

/**
 * RL algorithm configuration space.
 */
typedef struct qihse_rl_algorithm_config_s {
    char algorithm_name[64];       /* Algorithm name */
    size_t max_iterations;         /* Maximum iterations */
    double convergence_threshold;  /* Convergence threshold */
    size_t population_size;        /* Population size for genetic algorithms */
    double mutation_rate;          /* Mutation rate for genetic algorithms */
    double crossover_rate;         /* Crossover rate for genetic algorithms */
    int use_quantum_inspired;      /* Whether to use quantum-inspired variants */
    double temperature;            /* Temperature for simulated annealing */
    size_t tabu_list_size;         /* Tabu list size for tabu search */
    double pheromone_evaporation;  /* Pheromone evaporation for ACO */
} qihse_rl_algorithm_config_t;

/**
 * RL agent for algorithm discovery.
 */
typedef struct qihse_rl_agent_s {
    size_t state_dim;              /* State space dimension */
    size_t action_dim;             /* Action space dimension */
    size_t hidden_size;            /* Neural network hidden size */
    double learning_rate;          /* Learning rate */
    double gamma;                  /* Discount factor */
    double epsilon;                /* Exploration rate */
    size_t replay_buffer_size;     /* Experience replay buffer size */
    size_t current_buffer_size;    /* Current buffer size */
    double* replay_states;         /* Replay state buffer */
    double* replay_actions;        /* Replay action buffer */
    double* replay_rewards;        /* Replay reward buffer */
    double* replay_next_states;    /* Replay next state buffer */
    int* replay_dones;             /* Replay done flags */
    double* q_network_weights;     /* Q-network weights */
    double* target_network_weights; /* Target network weights */
    size_t training_steps;         /* Training steps performed */
    double current_loss;           /* Current training loss */
    void* user_data;              /* User context */
} qihse_rl_agent_t;

/**
 * Initialize RL agent.
 *
 * @param agent Agent to initialize
 * @param state_dim State space dimension
 * @param action_dim Action space dimension
 * @param hidden_size Neural network hidden size
 * @param replay_buffer_size Experience replay buffer size
 * @param learning_rate Learning rate
 * @param gamma Discount factor
 * @param epsilon Exploration rate
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
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
);

/**
 * Destroy RL agent.
 *
 * @param agent Agent to destroy
 */
void qihse_rl_agent_destroy(qihse_rl_agent_t* agent);

/**
 * Select action using epsilon-greedy policy.
 *
 * @param agent Agent instance
 * @param state Current state
 * @param output_action Output selected action
 * @return 0 on success, negative error code on failure
 */
int qihse_rl_agent_select_action(
    qihse_rl_agent_t* agent,
    const double* state,
    double* output_action
);

/**
 * Store experience in replay buffer.
 *
 * @param agent Agent instance
 * @param state Current state
 * @param action Taken action
 * @param reward Received reward
 * @param next_state Next state
 * @param done Episode termination flag
 */
void qihse_rl_agent_store_experience(
    qihse_rl_agent_t* agent,
    const double* state,
    const double* action,
    double reward,
    const double* next_state,
    int done
);

/**
 * Train RL agent using experience replay.
 *
 * @param agent Agent instance
 * @param batch_size Training batch size
 */
void qihse_rl_agent_train(qihse_rl_agent_t* agent, size_t batch_size);

/**
 * Discover optimal algorithm configuration.
 *
 * @param agent Agent instance
 * @param workload_features Workload feature vector
 * @param output_config Output optimal algorithm configuration
 * @return 0 on success, negative error code on failure
 */
int qihse_rl_agent_discover_algorithm(
    qihse_rl_agent_t* agent,
    const double* workload_features,
    qihse_rl_algorithm_config_t* output_config
);

/**
 * Get RL agent statistics.
 *
 * @param agent Agent instance
 * @param loss Output current loss
 * @param epsilon Output current exploration rate
 * @param buffer_size Output replay buffer size
 */
void qihse_rl_agent_get_stats(
    const qihse_rl_agent_t* agent,
    double* loss,
    double* epsilon,
    size_t* buffer_size
);

/* ============================================================================
 * TELEMETRY AND MONITORING
 * ============================================================================ */

/**
 * Telemetry event types.
 */
typedef enum qihse_telemetry_event_e {
    QIHSE_TELEMETRY_QUERY_START = 0,
    QIHSE_TELEMETRY_QUERY_END = 1,
    QIHSE_TELEMETRY_OPTIMIZATION = 2,
    QIHSE_TELEMETRY_REGRESSION = 3,
    QIHSE_TELEMETRY_ERROR = 4
} qihse_telemetry_event_t;

/**
 * Telemetry event data.
 */
typedef struct qihse_telemetry_event_s {
    qihse_telemetry_event_t type;
    uint64_t timestamp_us;
    char component[64];
    char operation[64];
    double value;
    char metadata[256];
} qihse_telemetry_event_data_t;

/**
 * Telemetry collector.
 */
typedef struct qihse_telemetry_collector_s {
    size_t max_events;
    size_t num_events;
    qihse_telemetry_event_data_t* events;
    void* user_data;
} qihse_telemetry_collector_t;

/**
 * Initialize telemetry collector.
 *
 * @param collector Collector to initialize
 * @param max_events Maximum events to store
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_telemetry_collector_init(
    qihse_telemetry_collector_t* collector,
    size_t max_events,
    void* user_data
);

/**
 * Destroy telemetry collector.
 *
 * @param collector Collector to destroy
 */
void qihse_telemetry_collector_destroy(qihse_telemetry_collector_t* collector);

/**
 * Record telemetry event.
 *
 * @param collector Collector instance
 * @param event Event to record
 */
void qihse_telemetry_record_event(
    qihse_telemetry_collector_t* collector,
    const qihse_telemetry_event_data_t* event
);

/**
 * Export telemetry data to JSON.
 *
 * @param collector Collector instance
 * @return JSON string (caller must free), or NULL on failure
 */
char* qihse_telemetry_export_json(const qihse_telemetry_collector_t* collector);

/* ============================================================================
 * REGRESSION DETECTION
 * ============================================================================ */

/**
 * Regression detector using statistical analysis.
 */
typedef struct qihse_regression_detector_s {
    size_t window_size;        /* Rolling window size */
    double* performance_history; /* Performance history */
    size_t history_count;      /* Current history count */
    double baseline_performance; /* Expected performance */
    double threshold_stddev;   /* Regression threshold in standard deviations */
    void* user_data;           /* User context */
} qihse_regression_detector_t;

/**
 * Initialize regression detector.
 *
 * @param detector Detector to initialize
 * @param window_size Rolling window size
 * @param baseline_performance Expected performance level
 * @param threshold_stddev Regression threshold
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_regression_detector_init(
    qihse_regression_detector_t* detector,
    size_t window_size,
    double baseline_performance,
    double threshold_stddev,
    void* user_data
);

/**
 * Destroy regression detector.
 *
 * @param detector Detector to destroy
 */
void qihse_regression_detector_destroy(qihse_regression_detector_t* detector);

/**
 * Update regression detector with new performance measurement.
 *
 * @param detector Detector instance
 * @param performance Current performance measurement
 * @return true if regression detected, false otherwise
 */
bool qihse_regression_detector_update(
    qihse_regression_detector_t* detector,
    double performance
);

/**
 * Get regression statistics.
 *
 * @param detector Detector instance
 * @param mean Output mean performance
 * @param stddev Output standard deviation
 * @param trend Output performance trend
 */
void qihse_regression_detector_get_stats(
    const qihse_regression_detector_t* detector,
    double* mean,
    double* stddev,
    double* trend
);

/* ============================================================================
 * ML SELF-IMPROVEMENT ENGINE
 * ============================================================================ */

/**
 * ML self-improvement engine configuration.
 */
typedef struct qihse_ml_config_s {
    size_t bandit_arms;        /* Number of bandit arms */
    size_t contextual_context_dim; /* Contextual bandit context dimension */
    size_t contextual_hidden_size; /* Contextual bandit hidden size */
    size_t rff_embedding_dim;  /* RFF embedding dimension */
    double rff_gamma;          /* RFF kernel parameter */
    size_t counterfactual_max; /* Maximum counterfactuals to store */
    size_t optimizer_params;   /* Number of optimizer parameters */
    size_t hidden_size;        /* Neural network hidden size */
    double learning_rate;      /* Learning rate */
    size_t variational_superposition_depth; /* Variational optimizer superposition depth */
    size_t variational_layers; /* Variational optimizer layers */
    size_t grover_search_space; /* Grover search space size */
    double grover_threshold;   /* Grover optimal threshold */
    size_t meta_tasks;         /* Meta-learning number of tasks */
    size_t meta_task_dim;      /* Meta-learning task dimension */
    size_t meta_inner_steps;   /* Meta-learning inner adaptation steps */
    size_t attention_embed_dim; /* Attention embedding dimension */
    size_t attention_heads;    /* Attention number of heads */
    size_t attention_seq_len;  /* Attention sequence length */
    double energy_power_budget; /* Energy-aware power budget in watts */
    double energy_thermal_limit; /* Energy-aware thermal limit in Celsius */
    size_t rl_state_dim;       /* RL state dimension */
    size_t rl_action_dim;      /* RL action dimension */
    size_t rl_replay_buffer;   /* RL replay buffer size */
    size_t telemetry_buffer;   /* Telemetry buffer size */
    size_t regression_window;  /* Regression detection window */
    double baseline_performance; /* Baseline performance */
    double regression_threshold; /* Regression threshold */
} qihse_ml_config_t;

/**
 * ML self-improvement engine.
 */
typedef struct qihse_ml_engine_s {
    qihse_ml_config_t config;
    qihse_thompson_bandit_t bandit;
    qihse_contextual_bandit_t contextual_bandit;
    qihse_neural_optimizer_t optimizer;
    qihse_rff_workload_embedding_t rff_embedding;
    qihse_counterfactual_learner_t counterfactual_learner;
    qihse_variational_optimizer_t variational_optimizer;
    qihse_grover_parameter_search_t grover_search;
    qihse_meta_optimizer_t meta_optimizer;
    qihse_attention_layer_t attention_layer;
    qihse_adam_optimizer_t adam_optimizer;
    qihse_energy_optimizer_t energy_optimizer;
    qihse_rl_agent_t rl_agent;
    qihse_telemetry_collector_t telemetry;
    qihse_regression_detector_t regression_detector;
    qihse_workload_fingerprint_t current_fingerprint;
    void* user_data;
} qihse_ml_engine_t;

/**
 * Initialize ML self-improvement engine.
 *
 * @param engine Engine to initialize
 * @param config Engine configuration
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_ml_engine_init(
    qihse_ml_engine_t* engine,
    const qihse_ml_config_t* config,
    void* user_data
);

/**
 * Destroy ML self-improvement engine.
 *
 * @param engine Engine to destroy
 */
void qihse_ml_engine_destroy(qihse_ml_engine_t* engine);

/**
 * Process query with ML optimization.
 *
 * @param engine Engine instance
 * @param query Query data
 * @param query_type Query type
 * @param current_performance Current performance metric
 * @param optimized_params Output optimized parameters
 */
void qihse_ml_engine_process_query(
    qihse_ml_engine_t* engine,
    const void* query,
    const char* query_type,
    double current_performance,
    double* optimized_params
);

/**
 * Train ML engine with performance feedback.
 *
 * @param engine Engine instance
 * @param performance Performance measurement
 * @param params_used Parameters that were used
 */
void qihse_ml_engine_train(
    qihse_ml_engine_t* engine,
    double performance,
    const double* params_used
);

/**
 * Check for performance regression.
 *
 * @param engine Engine instance
 * @param current_performance Current performance
 * @return true if regression detected, false otherwise
 */
bool qihse_ml_engine_detect_regression(
    qihse_ml_engine_t* engine,
    double current_performance
);

/**
 * Export ML engine status to JSON.
 *
 * @param engine Engine instance
 * @return JSON string (caller must free), or NULL on failure
 */
char* qihse_ml_engine_export_status_json(const qihse_ml_engine_t* engine);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_ML_H */
