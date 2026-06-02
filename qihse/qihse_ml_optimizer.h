/**
 * QIHSE ML Optimizer - Self-Improving Search System
 *
 * ML model trained on simulated data for continuous optimization of:
 * - Dimension calculation parameters
 * - Quantization strategies
 * - Hardware-specific tuning
 * - Search algorithm parameters
 */

#ifndef QIHSE_ML_OPTIMIZER_H
#define QIHSE_ML_OPTIMIZER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse.h"

/* ============================================================================
 * TRAINING DATA GENERATION
 * ============================================================================ */

/**
 * Simulated dataset characteristics for training
 */
typedef struct {
    size_t array_size;
    double entropy;
    double gap_variance;
    qihse_data_type_t data_type;
    qihse_memory_tier_t memory_tier;
    bool has_npu;
    bool has_gpu;
    bool has_amx;
    bool has_vnni;
} qihse_simulation_params_t;

/**
 * Training sample with input features and optimal parameters
 */
typedef struct {
    /* Input features */
    double array_size_log;          /* log10(array_size) */
    double entropy;                 /* Data entropy (0-1) */
    double gap_variance;            /* Gap coefficient of variation */
    double data_type_encoded;       /* One-hot encoded data type */
    double memory_tier_encoded;     /* Memory tier encoding */
    double hw_npu;                  /* NPU presence (0/1) */
    double hw_gpu;                  /* GPU presence (0/1) */
    double hw_amx;                  /* AMX presence (0/1) */
    double hw_vnni;                 /* VNNI presence (0/1) */

    /* Optimal output parameters */
    double optimal_dims;            /* Optimal Hilbert dimensions */
    double rff_gamma;               /* Optimal RFF gamma */
    double amplification_rounds;    /* Optimal Grover rounds */
    double verification_threshold;  /* Optimal verification confidence */
    double quantization_bits;       /* Optimal quantization (2/4/8/16/32) */
    double batch_size;              /* Optimal batch size */
} qihse_training_sample_t;

/* ============================================================================
 * ML MODEL ARCHITECTURE
 * ============================================================================ */

/**
 * Neural network layer configuration
 */
typedef struct {
    size_t input_size;
    size_t output_size;
    size_t num_layers;
    size_t* layer_sizes;
    double learning_rate;
    double momentum;
    char activation[32];            /* "relu", "tanh", "sigmoid" */
} qihse_nn_config_t;

/**
 * Self-improving ML optimizer
 */
typedef struct {
    /* Model architecture */
    qihse_nn_config_t nn_config;

    /* Model parameters (flattened) */
    double* weights;
    double* biases;
    double* gradients;
    size_t total_parameters;

    /* Training state */
    size_t training_samples;
    size_t epochs_completed;
    double current_loss;
    double best_loss;
    double* best_weights;           /* Best model parameters */

    /* Feature scaling */
    double* feature_mean;
    double* feature_std;
    double* target_mean;
    double* target_std;

    /* Continuous learning */
    bool online_learning;           /* Enable continuous adaptation */
    size_t adaptation_window;       /* Rolling window size */
    double adaptation_rate;         /* How fast to adapt */

    /* Hardware acceleration */
    bool use_npu;                   /* Use NPU for inference/training */
    bool use_gpu;                   /* Use GPU for inference/training */
    void* accelerator_context;      /* Hardware acceleration context */
} qihse_ml_optimizer_t;

/* ============================================================================
 * SIMULATED DATA GENERATION
 * ============================================================================ */

/**
 * Generate training data from simulation
 */
qihse_training_sample_t* qihse_generate_training_data(
    size_t num_samples,
    const qihse_simulation_params_t* sim_params,
    size_t* generated_samples
);

/**
 * Generate single training sample by running QIHSE simulation
 */
int qihse_generate_sample(
    const qihse_simulation_params_t* params,
    qihse_training_sample_t* sample
);

/**
 * Simulate QIHSE performance for different parameter combinations
 */
int qihse_simulate_performance(
    const qihse_simulation_params_t* data_params,
    double dims, double gamma, double rounds,
    double* predicted_speedup,
    double* predicted_accuracy
);

/* ============================================================================
 * ML OPTIMIZER API
 * ============================================================================ */

/**
 * Initialize ML optimizer with training data
 */
qihse_ml_optimizer_t* qihse_ml_optimizer_init(
    const qihse_nn_config_t* config,
    const qihse_training_sample_t* training_data,
    size_t num_samples
);

/**
 * Destroy ML optimizer
 */
void qihse_ml_optimizer_destroy(qihse_ml_optimizer_t* optimizer);

/**
 * Train ML optimizer on generated/simulated data
 */
int qihse_ml_optimizer_train(
    qihse_ml_optimizer_t* optimizer,
    size_t epochs,
    double validation_split
);

/**
 * Get optimal QIHSE parameters for current hardware/data
 */
int qihse_ml_optimizer_predict(
    qihse_ml_optimizer_t* optimizer,
    const qihse_simulation_params_t* current_params,
    qihse_config_t* optimal_config
);

/**
 * Update optimizer with new performance data (online learning)
 */
int qihse_ml_optimizer_update(
    qihse_ml_optimizer_t* optimizer,
    const qihse_simulation_params_t* params,
    const qihse_config_t* config_used,
    double actual_speedup,
    double actual_accuracy
);

/**
 * Save trained optimizer to file
 */
int qihse_ml_optimizer_save(const qihse_ml_optimizer_t* optimizer, const char* path);

/**
 * Load trained optimizer from file
 */
qihse_ml_optimizer_t* qihse_ml_optimizer_load(const char* path);

/* ============================================================================
 * QUANTIZATION OPTIMIZATION
 * ============================================================================ */

/**
 * Quantization-aware training for optimal precision
 */
typedef struct {
    size_t bits;                    /* Quantization bits (2,4,8,16,32) */
    double scale;                   /* Quantization scale factor */
    int64_t zero_point;             /* Quantization zero point */
    double mse_error;               /* Mean squared error from quantization */
} qihse_quantization_config_t;

/**
 * Find optimal quantization for current data/hardware
 */
int qihse_ml_optimize_quantization(
    qihse_ml_optimizer_t* optimizer,
    const void* data,
    size_t n,
    qihse_data_type_t type,
    qihse_quantization_config_t* optimal_config
);

/**
 * Apply quantization to data
 */
int qihse_apply_quantization(
    const void* input_data,
    size_t n,
    qihse_data_type_t type,
    const qihse_quantization_config_t* config,
    void** output_data
);

/**
 * Dequantize data back to original precision
 */
int qihse_dequantize_data(
    const void* quantized_data,
    size_t n,
    const qihse_quantization_config_t* config,
    void** output_data
);

/* ============================================================================
 * CONTINUOUS SELF-IMPROVEMENT
 * ============================================================================ */

/**
 * Self-improvement system that learns from real usage
 */
typedef struct {
    qihse_ml_optimizer_t* optimizer;
    char data_dir[256];             /* Directory for storing experience */
    size_t max_experience_samples;  /* Maximum experience to keep */
    double improvement_threshold;   /* Minimum improvement to retrain */

    /* Performance tracking */
    double baseline_speedup;        /* Initial baseline performance */
    double baseline_accuracy;
    double current_speedup;
    double current_accuracy;

    /* Retraining triggers */
    size_t samples_since_retrain;
    size_t min_samples_for_retrain;
    bool pending_retrain;
} qihse_self_improvement_t;

/**
 * Initialize self-improvement system
 */
qihse_self_improvement_t* qihse_self_improvement_init(
    const char* data_dir,
    size_t max_samples
);

/**
 * Record QIHSE usage for learning
 */
int qihse_self_improvement_record(
    qihse_self_improvement_t* si,
    const qihse_simulation_params_t* params,
    const qihse_config_t* config_used,
    double actual_speedup,
    double actual_accuracy
);

/**
 * Check if retraining is needed and perform if so
 */
int qihse_self_improvement_check_retrain(qihse_self_improvement_t* si);

/**
 * Get improved configuration based on learning
 */
int qihse_self_improvement_get_config(
    qihse_self_improvement_t* si,
    const qihse_simulation_params_t* current_params,
    qihse_config_t* improved_config
);

/**
 * Export learning data for analysis
 */
int qihse_self_improvement_export_data(
    const qihse_self_improvement_t* si,
    const char* output_path
);

#endif /* QIHSE_ML_OPTIMIZER_H */
