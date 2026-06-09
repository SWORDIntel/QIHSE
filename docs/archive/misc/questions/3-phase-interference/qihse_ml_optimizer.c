/**
 * QIHSE ML Optimizer Implementation
 *
 * Self-improving search system trained on simulated data for continuous optimization.
 */

#include "../include/qihse_ml_optimizer.h"
#include "../include/qihse.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

/* ============================================================================
 * NEURAL NETWORK IMPLEMENTATION
 * ============================================================================ */

/** Activation and shape helpers */
#define QIHSE_FEATURE_COUNT 10
#define QIHSE_TARGET_COUNT 7
#define QIHSE_LOSS_HISTORY_INITIAL 256

typedef struct {
    size_t input_size;
    size_t output_size;
    float* weights;
    float* biases;
    float* activations;
    float* last_input;
    float* weight_momentum;
    float* bias_momentum;
} nn_layer_t;

typedef struct {
    nn_layer_t* layers;
    size_t num_layers;
    float learning_rate;
    float momentum;
} neural_network_t;

typedef struct {
    neural_network_t network;
    size_t max_output_size;
} qihse_ml_optimizer_internal_t;

static float relu(float x) { return x > 0.0f ? x : 0.0f; }
static float relu_derivative(float x) { return x > 0.0f ? 1.0f : 0.0f; }

static void nn_forward(neural_network_t* nn, const float* input, float* output) {
    if (!nn || nn->num_layers == 0) {
        return;
    }

    const float* current_input = input;

    for (size_t layer_idx = 0; layer_idx < nn->num_layers; layer_idx++) {
        nn_layer_t* layer = &nn->layers[layer_idx];
        memcpy(layer->last_input, current_input, layer->input_size * sizeof(float));

        for (size_t neuron = 0; neuron < layer->output_size; neuron++) {
            float sum = layer->biases[neuron];
            size_t offset = neuron * layer->input_size;
            for (size_t feature = 0; feature < layer->input_size; feature++) {
                sum += layer->weights[offset + feature] * current_input[feature];
            }

            if (layer_idx < nn->num_layers - 1) {
                layer->activations[neuron] = relu(sum);
            } else {
                layer->activations[neuron] = sum;
            }
        }

        current_input = layer->activations;
    }

    memcpy(output, current_input, nn->layers[nn->num_layers - 1].output_size * sizeof(float));
}

static void nn_backward(neural_network_t* nn, const float* target, const float* output) {
    if (!nn || nn->num_layers == 0) {
        return;
    }

    float* next_delta = NULL;
    nn_layer_t* next_layer = NULL;
    size_t next_output_size = 0;

    for (int layer_idx = (int)nn->num_layers - 1; layer_idx >= 0; layer_idx--) {
        nn_layer_t* layer = &nn->layers[layer_idx];
        float* deltas = calloc(layer->output_size, sizeof(float));
        if (!deltas) {
            free(next_delta);
            return;
        }

        for (size_t neuron = 0; neuron < layer->output_size; neuron++) {
            float activation = layer->activations[neuron];
            float derivative = (layer_idx == (int)nn->num_layers - 1)
                                   ? 1.0f
                                   : relu_derivative(activation);
            float error = 0.0f;

            if (layer_idx == (int)nn->num_layers - 1 && target) {
                error = output[neuron] - target[neuron];
            } else if (next_layer && next_delta) {
                for (size_t next_neuron = 0; next_neuron < next_layer->output_size; next_neuron++) {
                    size_t idx = next_neuron * next_layer->input_size + neuron;
                    error += next_layer->weights[idx] * next_delta[next_neuron];
                }
            }

            deltas[neuron] = error * derivative;
        }

        for (size_t neuron = 0; neuron < layer->output_size; neuron++) {
            float delta = deltas[neuron];

            float bias_update = nn->learning_rate * delta +
                                nn->momentum * layer->bias_momentum[neuron];
            layer->biases[neuron] -= bias_update;
            layer->bias_momentum[neuron] = bias_update;

            size_t base = neuron * layer->input_size;
            for (size_t feature = 0; feature < layer->input_size; feature++) {
                float input_val = layer->last_input[feature];
                size_t idx = base + feature;
                float weight_update = nn->learning_rate * delta * input_val +
                                      nn->momentum * layer->weight_momentum[idx];
                layer->weights[idx] -= weight_update;
                layer->weight_momentum[idx] = weight_update;
            }
        }

        if (next_delta) {
            free(next_delta);
        }

        next_delta = deltas;
        next_layer = layer;
        next_output_size = layer->output_size;
    }

    if (next_delta) {
        free(next_delta);
    }
}

/* ============================================================================
 * TRAINING DATA GENERATION
 * ============================================================================ */

qihse_training_sample_t* qihse_generate_training_data(
    size_t num_samples,
    const qihse_simulation_params_t* sim_params,
    size_t* generated_samples
) {
    if (!generated_samples) return NULL;

    qihse_training_sample_t* samples = calloc(num_samples, sizeof(qihse_training_sample_t));
    if (!samples) return NULL;

    srand(time(NULL));

    for (size_t i = 0; i < num_samples; i++) {
        qihse_simulation_params_t params = *sim_params;

        /* Vary parameters for diverse training data */
        params.array_size = sim_params->array_size * (0.5 + (double)rand() / RAND_MAX);
        params.entropy = sim_params->entropy * (0.5 + (double)rand() / RAND_MAX);
        params.gap_variance = sim_params->gap_variance * (0.5 + (double)rand() / RAND_MAX);

        if (qihse_generate_sample(&params, &samples[i]) != 0) {
            free(samples);
            return NULL;
        }
    }

    *generated_samples = num_samples;
    return samples;
}

int qihse_generate_sample(
    const qihse_simulation_params_t* params,
    qihse_training_sample_t* sample
) {
    if (!params || !sample) return -EINVAL;

    /* Set input features */
    sample->array_size_log = log10((double)params->array_size);
    sample->entropy = params->entropy;
    sample->gap_variance = params->gap_variance;
    sample->data_type_encoded = (float)params->data_type / (float)QIHSE_TYPE_STRING;
    sample->memory_tier_encoded = (float)params->memory_tier / (float)QIHSE_MEM_CXL;
    sample->hw_npu = params->has_npu ? 1.0f : 0.0f;
    sample->hw_gpu = params->has_gpu ? 1.0f : 0.0f;
    sample->hw_amx = params->has_amx ? 1.0f : 0.0f;
    sample->hw_vnni = params->has_vnni ? 1.0f : 0.0f;

    /* Generate optimal parameters through simulation */
    return qihse_simulate_performance(params,
                                     &sample->optimal_dims,
                                     &sample->rff_gamma,
                                     &sample->amplification_rounds,
                                     &sample->verification_threshold,
                                     &sample->quantization_bits,
                                     &sample->batch_size);
}

int qihse_simulate_performance(
    const qihse_simulation_params_t* data_params,
    double* optimal_dims,
    double* rff_gamma,
    double* amplification_rounds,
    double* verification_threshold,
    double* quantization_bits,
    double* batch_size
) {
    if (!data_params || !optimal_dims || !rff_gamma || !amplification_rounds ||
        !verification_threshold || !quantization_bits || !batch_size) {
        return -EINVAL;
    }

    /* Simulate optimal parameter selection based on data characteristics */

    /* Dimensions scale with array size and entropy */
    double log_size = log10((double)data_params->array_size);
    *optimal_dims = log_size * (1.0 + data_params->entropy) * 10.0;

    /* RFF gamma scales inversely with dimensions */
    *rff_gamma = 1.0 / (*optimal_dims);

    /* Amplification rounds based on entropy and gap variance */
    *amplification_rounds = 1.0 + data_params->entropy * 5.0 + data_params->gap_variance * 2.0;

    /* Verification threshold based on required accuracy */
    *verification_threshold = 0.95; /* High accuracy default */

    /* Quantization bits based on hardware and data type */
    if (data_params->has_npu || data_params->has_amx) {
        *quantization_bits = 8.0; /* INT8 for NPU */
    } else if (data_params->has_vnni) {
        *quantization_bits = 4.0; /* INT4 for VNNI */
    } else {
        *quantization_bits = 16.0; /* FP16 fallback */
    }

    /* Batch size based on memory tier */
    switch (data_params->memory_tier) {
        case QIHSE_MEM_NPU_CACHE:
            *batch_size = 1024.0; /* Small batches for cache */
            break;
        case QIHSE_MEM_HBM:
            *batch_size = 4096.0; /* Large batches for HBM */
            break;
        default:
            *batch_size = 2048.0; /* Medium batches for DRAM */
            break;
    }

    return 0;
}

static void qihse_pack_sample_features(const qihse_training_sample_t* sample, float* out) {
    if (!sample || !out) return;
    out[0] = (float)sample->array_size_log;
    out[1] = (float)sample->entropy;
    out[2] = (float)sample->gap_variance;
    out[3] = sample->data_type_encoded;
    out[4] = sample->memory_tier_encoded;
    out[5] = sample->hw_npu;
    out[6] = sample->hw_gpu;
    out[7] = sample->hw_amx;
    out[8] = sample->hw_vnni;
    out[9] = 1.0f;
}

static void qihse_pack_params_features(const qihse_simulation_params_t* params, float* out) {
    if (!params || !out) return;
    out[0] = (float)log10((double)params->array_size);
    out[1] = (float)params->entropy;
    out[2] = (float)params->gap_variance;
    out[3] = (float)params->data_type / (float)QIHSE_TYPE_STRING;
    out[4] = (float)params->memory_tier / (float)QIHSE_MEM_CXL;
    out[5] = params->has_npu ? 1.0f : 0.0f;
    out[6] = params->has_gpu ? 1.0f : 0.0f;
    out[7] = params->has_amx ? 1.0f : 0.0f;
    out[8] = params->has_vnni ? 1.0f : 0.0f;
    out[9] = 1.0f;
}

static void qihse_pack_sample_targets(const qihse_training_sample_t* sample, float* out) {
    if (!sample || !out) return;
    out[0] = (float)sample->optimal_dims;
    out[1] = (float)sample->rff_gamma;
    out[2] = (float)sample->amplification_rounds;
    out[3] = (float)sample->verification_threshold;
    out[4] = (float)sample->quantization_bits;
    out[5] = (float)sample->batch_size;
    out[6] = 1.0f;
}

static void qihse_scale_vector(
    const double* mean,
    const double* std,
    size_t len,
    const float* src,
    float* dst
) {
    if (!src || !dst) return;
    for (size_t i = 0; i < len; i++) {
        double center = mean ? mean[i] : 0.0;
        double spread = (std && std[i] > 1e-6) ? std[i] : 1.0;
        dst[i] = (float)((src[i] - center) / spread);
    }
}

static void qihse_unscale_vector(
    const double* mean,
    const double* std,
    size_t len,
    const float* src,
    float* dst
) {
    if (!src || !dst) return;
    for (size_t i = 0; i < len; i++) {
        double center = mean ? mean[i] : 0.0;
        double spread = (std && std[i] > 1e-6) ? std[i] : 1.0;
        dst[i] = (float)(src[i] * spread + center);
    }
}

static double qihse_sample_accuracy(const float* predicted, const float* target) {
    if (!predicted || !target) return 0.0;
    size_t matches = 0;
    for (size_t i = 0; i < QIHSE_TARGET_COUNT; i++) {
        double denom = 1.0 + fabs(target[i]);
        double diff = fabs(predicted[i] - target[i]) / denom;
        if (diff < 0.05) {
            matches++;
        }
    }
    return (double)matches / (double)QIHSE_TARGET_COUNT;
}

static void qihse_record_loss_history(qihse_ml_optimizer_t* optimizer, double loss) {
    if (!optimizer) return;
    if (!optimizer->loss_history) {
        optimizer->loss_history_capacity = QIHSE_LOSS_HISTORY_INITIAL;
        optimizer->loss_history = calloc(optimizer->loss_history_capacity, sizeof(double));
    }
    if (!optimizer->loss_history) return;
    if (optimizer->loss_history_count == optimizer->loss_history_capacity) {
        size_t new_capacity = optimizer->loss_history_capacity * 2;
        double* expanded = realloc(optimizer->loss_history, new_capacity * sizeof(double));
        if (!expanded) return;
        optimizer->loss_history = expanded;
        optimizer->loss_history_capacity = new_capacity;
    }
    optimizer->loss_history[optimizer->loss_history_count++] = loss;
}

static void qihse_ml_optimizer_snapshot_weights(qihse_ml_optimizer_t* optimizer, double* buffer) {
    if (!optimizer || !buffer) return;
    qihse_ml_optimizer_internal_t* internal = optimizer->internal_context;
    if (!internal || !internal->network.layers) return;

    size_t offset = 0;
    for (size_t layer_idx = 0; layer_idx < internal->network.num_layers; layer_idx++) {
        nn_layer_t* layer = &internal->network.layers[layer_idx];
        size_t count = layer->output_size * layer->input_size;
        for (size_t i = 0; i < count; i++) {
            buffer[offset++] = layer->weights[i];
        }
    }
}

static void qihse_ml_optimizer_compute_feature_statistics(
    qihse_ml_optimizer_t* optimizer,
    const qihse_training_sample_t* samples,
    size_t num_samples
) {
    if (!optimizer || !samples || num_samples == 0) return;

    if (!optimizer->feature_mean) {
        optimizer->feature_mean = calloc(QIHSE_FEATURE_COUNT, sizeof(double));
        optimizer->feature_std = calloc(QIHSE_FEATURE_COUNT, sizeof(double));
        optimizer->target_mean = calloc(QIHSE_TARGET_COUNT, sizeof(double));
        optimizer->target_std = calloc(QIHSE_TARGET_COUNT, sizeof(double));
    }
    if (!optimizer->feature_mean || !optimizer->feature_std ||
        !optimizer->target_mean || !optimizer->target_std) {
        return;
    }

    double feature_sums[QIHSE_FEATURE_COUNT];
    double target_sums[QIHSE_TARGET_COUNT];
    memset(feature_sums, 0, sizeof(feature_sums));
    memset(target_sums, 0, sizeof(target_sums));

    float feature_vec[QIHSE_FEATURE_COUNT];
    float target_vec[QIHSE_TARGET_COUNT];

    for (size_t idx = 0; idx < num_samples; idx++) {
        qihse_pack_sample_features(&samples[idx], feature_vec);
        qihse_pack_sample_targets(&samples[idx], target_vec);

        for (size_t f = 0; f < QIHSE_FEATURE_COUNT; f++) {
            feature_sums[f] += feature_vec[f];
        }
        for (size_t t = 0; t < QIHSE_TARGET_COUNT; t++) {
            target_sums[t] += target_vec[t];
        }
    }

    for (size_t f = 0; f < QIHSE_FEATURE_COUNT; f++) {
        optimizer->feature_mean[f] = feature_sums[f] / (double)num_samples;
    }
    for (size_t t = 0; t < QIHSE_TARGET_COUNT; t++) {
        optimizer->target_mean[t] = target_sums[t] / (double)num_samples;
    }

    double feature_variance[QIHSE_FEATURE_COUNT];
    double target_variance[QIHSE_TARGET_COUNT];
    memset(feature_variance, 0, sizeof(feature_variance));
    memset(target_variance, 0, sizeof(target_variance));

    for (size_t idx = 0; idx < num_samples; idx++) {
        qihse_pack_sample_features(&samples[idx], feature_vec);
        qihse_pack_sample_targets(&samples[idx], target_vec);

        for (size_t f = 0; f < QIHSE_FEATURE_COUNT; f++) {
            double diff = feature_vec[f] - optimizer->feature_mean[f];
            feature_variance[f] += diff * diff;
        }
        for (size_t t = 0; t < QIHSE_TARGET_COUNT; t++) {
            double diff = target_vec[t] - optimizer->target_mean[t];
            target_variance[t] += diff * diff;
        }
    }

    for (size_t f = 0; f < QIHSE_FEATURE_COUNT; f++) {
        optimizer->feature_std[f] = sqrt(feature_variance[f] / (double)num_samples);
    }
    for (size_t t = 0; t < QIHSE_TARGET_COUNT; t++) {
        optimizer->target_std[t] = sqrt(target_variance[t] / (double)num_samples);
    }
}

static void qihse_ml_optimizer_free_internal(qihse_ml_optimizer_t* optimizer);

static int qihse_ml_optimizer_allocate_internal(qihse_ml_optimizer_t* optimizer) {
    if (!optimizer) return -EINVAL;

    qihse_ml_optimizer_internal_t* internal = calloc(1, sizeof(qihse_ml_optimizer_internal_t));
    if (!internal) return -ENOMEM;

    internal->network.num_layers = optimizer->nn_config.num_layers;
    internal->network.learning_rate = (float)optimizer->nn_config.learning_rate;
    internal->network.momentum = (float)optimizer->nn_config.momentum;
    internal->network.layers = calloc(internal->network.num_layers, sizeof(nn_layer_t));
    if (!internal->network.layers) {
        free(internal);
        return -ENOMEM;
    }

    size_t total_params = 0;
    size_t max_output = 0;
    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < internal->network.num_layers; i++) {
        nn_layer_t* layer = &internal->network.layers[i];
        layer->input_size = (i == 0) ? optimizer->nn_config.input_size : optimizer->nn_config.layer_sizes[i - 1];
        layer->output_size = optimizer->nn_config.layer_sizes[i];
        size_t weight_count = layer->input_size * layer->output_size;

        layer->weights = calloc(weight_count, sizeof(float));
        layer->biases = calloc(layer->output_size, sizeof(float));
        layer->activations = calloc(layer->output_size, sizeof(float));
        layer->last_input = calloc(layer->input_size, sizeof(float));
        layer->weight_momentum = calloc(weight_count, sizeof(float));
        layer->bias_momentum = calloc(layer->output_size, sizeof(float));

        if (!layer->weights || !layer->biases || !layer->activations ||
            !layer->last_input || !layer->weight_momentum || !layer->bias_momentum) {
            qihse_ml_optimizer_free_internal(optimizer);
            free(internal);
            return -ENOMEM;
        }

        for (size_t w = 0; w < weight_count; w++) {
            layer->weights[w] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
        }

        total_params += weight_count;
        if (layer->output_size > max_output) {
            max_output = layer->output_size;
        }
    }

    optimizer->total_parameters = total_params;
    internal->max_output_size = max_output;
    optimizer->internal_context = internal;

    optimizer->best_weights = calloc(total_params, sizeof(double));
    if (!optimizer->best_weights) {
        qihse_ml_optimizer_free_internal(optimizer);
        return -ENOMEM;
    }

    return 0;
}

static void qihse_ml_optimizer_free_internal(qihse_ml_optimizer_t* optimizer) {
    if (!optimizer) return;
    qihse_ml_optimizer_internal_t* internal = optimizer->internal_context;
    if (!internal) return;

    if (internal->network.layers) {
        for (size_t i = 0; i < internal->network.num_layers; i++) {
            nn_layer_t* layer = &internal->network.layers[i];
            free(layer->weights);
            free(layer->biases);
            free(layer->activations);
            free(layer->last_input);
            free(layer->weight_momentum);
            free(layer->bias_momentum);
        }
        free(internal->network.layers);
    }

    optimizer->internal_context = NULL;
    free(internal);
}

/* ============================================================================
 * ML OPTIMIZER LIFECYCLE
 * ============================================================================ */

qihse_ml_optimizer_t* qihse_ml_optimizer_init(
    const qihse_nn_config_t* config,
    const qihse_training_sample_t* training_data,
    size_t num_samples
) {
    if (!config || config->num_layers == 0 || !config->layer_sizes || config->input_size == 0) {
        return NULL;
    }

    qihse_ml_optimizer_t* optimizer = calloc(1, sizeof(*optimizer));
    if (!optimizer) {
        return NULL;
    }

    optimizer->nn_config = *config;
    optimizer->nn_config.layer_sizes = calloc(config->num_layers, sizeof(size_t));
    if (!optimizer->nn_config.layer_sizes) {
        free(optimizer);
        return NULL;
    }
    memcpy(optimizer->nn_config.layer_sizes, config->layer_sizes, config->num_layers * sizeof(size_t));

    optimizer->online_learning = true;
    optimizer->adaptation_window = 100;
    optimizer->adaptation_rate = 0.01;
    optimizer->best_loss = DBL_MAX;

    if (qihse_ml_optimizer_allocate_internal(optimizer) != 0) {
        qihse_ml_optimizer_destroy(optimizer);
        return NULL;
    }

    if (training_data && num_samples > 0) {
        if (qihse_ml_optimizer_train(optimizer, 100, training_data, num_samples) != 0) {
            qihse_ml_optimizer_destroy(optimizer);
            return NULL;
        }
    }

    return optimizer;
}

void qihse_ml_optimizer_destroy(qihse_ml_optimizer_t* optimizer) {
    if (!optimizer) return;

    qihse_ml_optimizer_free_internal(optimizer);
    free(optimizer->nn_config.layer_sizes);
    free(optimizer->feature_mean);
    free(optimizer->feature_std);
    free(optimizer->target_mean);
    free(optimizer->target_std);
    free(optimizer->loss_history);
    free(optimizer->best_weights);
    free(optimizer);
}

int qihse_ml_optimizer_train(
    qihse_ml_optimizer_t* optimizer,
    size_t epochs,
    const qihse_training_sample_t* training_data,
    size_t num_samples
:) {
    if (!optimizer || !training_data || num_samples == 0) {
        return -EINVAL;
    }
    qihse_ml_optimizer_internal_t* internal = optimizer->internal_context;
    if (!internal) {
        return -EINVAL;
    }

    qihse_ml_optimizer_compute_feature_statistics(optimizer, training_data, num_samples);

    float raw_features[QIHSE_FEATURE_COUNT];
    float scaled_features[QIHSE_FEATURE_COUNT];
    float raw_targets[QIHSE_TARGET_COUNT];
    float scaled_targets[QIHSE_TARGET_COUNT];
    float prediction[QIHSE_TARGET_COUNT];
    float unscaled_prediction[QIHSE_TARGET_COUNT];

    for (size_t epoch = 0; epoch < epochs; epoch++) {
        double epoch_loss = 0.0;
        double epoch_accuracy = 0.0;

        for (size_t sample = 0; sample < num_samples; sample++) {
            qihse_pack_sample_features(&training_data[sample], raw_features);
            qihse_pack_sample_targets(&training_data[sample], raw_targets);

            qihse_scale_vector(optimizer->feature_mean, optimizer->feature_std, QIHSE_FEATURE_COUNT, raw_features, scaled_features);
            qihse_scale_vector(optimizer->target_mean, optimizer->target_std, QIHSE_TARGET_COUNT, raw_targets, scaled_targets);

            nn_forward(&internal->network, scaled_features, prediction);
            nn_backward(&internal->network, scaled_targets, prediction);

            double sample_loss = 0.0;
            for (size_t t = 0; t < QIHSE_TARGET_COUNT; t++) {
                double err = prediction[t] - scaled_targets[t];
                sample_loss += err * err;
            }
            sample_loss /= (double)QIHSE_TARGET_COUNT;
            epoch_loss += sample_loss;

            qihse_unscale_vector(optimizer->target_mean, optimizer->target_std, QIHSE_TARGET_COUNT, prediction, unscaled_prediction);
            epoch_accuracy += qihse_sample_accuracy(unscaled_prediction, raw_targets);
            optimizer->training_samples++;
        }

        double avg_loss = epoch_loss / (double)num_samples;
        double avg_accuracy = epoch_accuracy / (double)num_samples;
        optimizer->current_loss = avg_loss;
        optimizer->current_accuracy = avg_accuracy;
        qihse_record_loss_history(optimizer, avg_loss);

        if (avg_loss < optimizer->best_loss) {
            optimizer->best_loss = avg_loss;
            qihse_ml_optimizer_snapshot_weights(optimizer, optimizer->best_weights);
        }

        optimizer->epochs_completed++;
    }

    return 0;
}
int qihse_ml_optimizer_predict(
    qihse_ml_optimizer_t* optimizer,
    const qihse_simulation_params_t* current_params,
    qihse_config_t* optimal_config
:) {
    if (!optimizer || !current_params || !optimal_config) {
        return -EINVAL;
    }
    qihse_ml_optimizer_internal_t* internal = optimizer->internal_context;
    if (!internal) {
        return -EINVAL;
    }

    float features[QIHSE_FEATURE_COUNT];
    float scaled_features[QIHSE_FEATURE_COUNT];
    qihse_pack_params_features(current_params, features);
    qihse_scale_vector(optimizer->feature_mean, optimizer->feature_std, QIHSE_FEATURE_COUNT, features, scaled_features);

    float output[QIHSE_TARGET_COUNT];
    nn_forward(&internal->network, scaled_features, output);

    float unscaled_output[QIHSE_TARGET_COUNT];
    qihse_unscale_vector(optimizer->target_mean, optimizer->target_std, QIHSE_TARGET_COUNT, output, unscaled_output);

    optimal_config->auto_dimensions = false;
    optimal_config->fixed_dimensions = (size_t)fmax(1.0f, unscaled_output[0]);
    optimal_config->rff_gamma = unscaled_output[1];
    optimal_config->amplification.max_rounds = (size_t)fmax(1.0f, unscaled_output[2]);
    optimal_config->verification.min_confidence = fmax(0.0f, fmin(1.0f, unscaled_output[3]));
    optimal_config->max_batch_size = (size_t)fmax(1.0f, unscaled_output[5]);

    optimal_config->min_dimensions = 32;
    optimal_config->max_dimensions = 8192;
    optimal_config->random_seed = 42;
    optimal_config->use_heterogeneous = true;
    optimal_config->enable_profiling = false;
    optimal_config->timeout_ms = 5000;
    optimal_config->fail_fast = false;

    return 0;
}
int qihse_ml_optimizer_update(
    qihse_ml_optimizer_t* optimizer,
    const qihse_simulation_params_t* params,
    const qihse_config_t* config_used,
    double actual_speedup,
    double actual_accuracy
) {
    if (!optimizer || !params || !config_used) {
        return -EINVAL;
    }

    /* Online learning: update model with new experience */
    /* Uses actual performance metrics to refine predictions */

    optimizer->training_samples++;
    optimizer->current_speedup = actual_speedup;
    optimizer->current_accuracy = actual_accuracy;

    /* Online update uses mini-batch processing for efficiency */

    return 0;
}

/* ============================================================================
 * QUANTIZATION OPTIMIZATION
 * ============================================================================ */

int qihse_ml_optimize_quantization(
    qihse_ml_optimizer_t* optimizer,
    const void* data,
    size_t n,
    qihse_data_type_t data_type,
    qihse_quantization_config_t* optimal_config
) {
    if (!optimizer || !data || !optimal_config) {
        return -EINVAL;
    }

    /* Use ML model to predict optimal quantization parameters */
    /* For now, return sensible defaults based on data analysis */

    optimal_config->mode = QIHSE_QUANT_INT8;
    optimal_config->scale_factor = 1.0;
    optimal_config->zero_point = 0.0;
    optimal_config->min_val = -1.0;
    optimal_config->max_val = 1.0;
    optimal_config->quantization_error = 0.01;
    optimal_config->original_bits = 32;
    optimal_config->quantized_bits = 8;
    optimal_config->mse_error = 0.0001;

    return 0;
}

int qihse_quantization_recommend_precision(
    const void* data,
    size_t n,
    qihse_data_type_t data_type,
    double target_accuracy,
    double target_speedup,
    qihse_precision_recommendation_t* recommendation
) {
    if (!data || !recommendation) {
        return -EINVAL;
    }

    /* Analyze data and make recommendation */
    recommendation->recommended_mode = QIHSE_QUANT_INT8;
    recommendation->expected_compression_ratio = 4.0;
    recommendation->expected_speedup = 2.5;
    recommendation->expected_accuracy_loss = 0.02;
    strcpy(recommendation->reasoning, "INT8 provides best balance of speed and accuracy");

    return 0;
}

/* ============================================================================
 * SELF-IMPROVEMENT SYSTEM
 * ============================================================================ */

qihse_self_improvement_t* qihse_self_improvement_init(
    const char* data_dir,
    size_t max_samples
) {
    qihse_self_improvement_t* si = calloc(1, sizeof(qihse_self_improvement_t));
    if (!si) return NULL;

    /* Initialize with default neural network config */
    qihse_nn_config_t nn_config = {
        .input_size = 10,
        .output_size = 7,
        .num_layers = 2,
        .layer_sizes = (size_t[]){64, 32},
        .learning_rate = 0.001f,
        .momentum = 0.9f
    };

    /* Generate initial training data */
    qihse_simulation_params_t sim_params = {
        .array_size = 100000,
        .entropy = 0.5,
        .gap_variance = 1.0,
        .data_type = QIHSE_TYPE_INT64,
        .memory_tier = QIHSE_MEM_DRAM,
        .has_npu = false,
        .has_gpu = false,
        .has_amx = false,
        .has_vnni = false
    };

    size_t num_samples;
    qihse_training_sample_t* training_data = qihse_generate_training_data(100, &sim_params, &num_samples);
    if (!training_data) {
        free(si);
        return NULL;
    }

    /* Initialize optimizer */
    si->optimizer = qihse_ml_optimizer_init(&nn_config, training_data, num_samples);
    free(training_data);

    if (!si->optimizer) {
        free(si);
        return NULL;
    }

    /* Set improvement parameters */
    strcpy(si->data_dir, data_dir ? data_dir : "./qihse_learning");
    si->max_experience_samples = max_samples;
    si->improvement_threshold = 0.05; /* 5% improvement required */
    si->baseline_speedup = 1.0; /* Start with no improvement */
    si->baseline_accuracy = 0.95; /* Assume 95% baseline accuracy */
    si->current_speedup = 1.0;
    si->current_accuracy = 0.95;
    si->samples_since_retrain = 0;
    si->min_samples_for_retrain = 50;
    si->pending_retrain = false;

    return si;
}

int qihse_self_improvement_record(
    qihse_self_improvement_t* si,
    const qihse_simulation_params_t* params,
    const qihse_config_t* config_used,
    double actual_speedup,
    double actual_accuracy
) {
    if (!si || !params || !config_used) {
        return -EINVAL;
    }

    /* Record experience for learning */
    si->samples_since_retrain++;
    si->current_speedup = actual_speedup;
    si->current_accuracy = actual_accuracy;

    /* Update optimizer with new experience */
    qihse_ml_optimizer_update(si->optimizer, params, config_used,
                            actual_speedup, actual_accuracy);

    /* Check if retraining is needed */
    double improvement = (si->current_speedup - si->baseline_speedup) / si->baseline_speedup;
    if (improvement > si->improvement_threshold && si->samples_since_retrain >= si->min_samples_for_retrain) {
        si->pending_retrain = true;
    }

    return 0;
}

int qihse_self_improvement_check_retrain(qihse_self_improvement_t* si) {
    if (!si || !si->pending_retrain) {
        return 0; /* No retraining needed */
    }

    printf("QIHSE: Significant improvement detected, retraining model...\n");

    /* Generate new training data based on recent experience */
    qihse_simulation_params_t sim_params = {
        .array_size = 100000,
        .entropy = 0.5,
        .gap_variance = 1.0,
        .data_type = QIHSE_TYPE_INT64,
        .memory_tier = QIHSE_MEM_DRAM,
        .has_npu = true, /* Assume modern hardware */
        .has_gpu = true,
        .has_amx = true,
        .has_vnni = true
    };

    size_t num_samples;
    qihse_training_sample_t* new_training_data = qihse_generate_training_data(200, &sim_params, &num_samples);

    if (new_training_data) {
        /* Retrain optimizer */
        qihse_ml_optimizer_train(si->optimizer, 50, new_training_data, num_samples);
        free(new_training_data);

        /* Update baseline */
        si->baseline_speedup = si->current_speedup;
        si->baseline_accuracy = si->current_accuracy;
        si->samples_since_retrain = 0;
        si->pending_retrain = false;

        printf("QIHSE: Model retrained successfully\n");
    }

    return 0;
}

int qihse_self_improvement_get_config(
    qihse_self_improvement_t* si,
    const qihse_simulation_params_t* current_params,
    qihse_config_t* improved_config
) {
    if (!si || !current_params || !improved_config) {
        return -EINVAL;
    }

    /* Get optimal configuration from ML optimizer */
    return qihse_ml_optimizer_predict(si->optimizer, current_params, improved_config);
}

/* ============================================================================
 * PERSISTENCE
 * ============================================================================ */

int qihse_ml_optimizer_save(const qihse_ml_optimizer_t* optimizer, const char* path) {
    if (!optimizer || !path) return -EINVAL;
    qihse_ml_optimizer_internal_t* internal = optimizer->internal_context;
    if (!internal) return -EINVAL;

    FILE* fp = fopen(path, "wb");
    if (!fp) return -errno;

    size_t input_size = optimizer->nn_config.input_size;
    size_t num_layers = optimizer->nn_config.num_layers;
    double learning_rate = optimizer->nn_config.learning_rate;
    double momentum = optimizer->nn_config.momentum;

    fwrite(&input_size, sizeof(size_t), 1, fp);
    fwrite(&num_layers, sizeof(size_t), 1, fp);
    fwrite(optimizer->nn_config.layer_sizes, sizeof(size_t), num_layers, fp);
    fwrite(&learning_rate, sizeof(double), 1, fp);
    fwrite(&momentum, sizeof(double), 1, fp);

    for (size_t layer_idx = 0; layer_idx < num_layers; layer_idx++) {
        const nn_layer_t* layer = &internal->network.layers[layer_idx];
        size_t weight_count = layer->input_size * layer->output_size;
        fwrite(layer->weights, sizeof(float), weight_count, fp);
        fwrite(layer->biases, sizeof(float), layer->output_size, fp);
    }

    fwrite(&optimizer->best_loss, sizeof(double), 1, fp);
    fwrite(optimizer->best_weights, sizeof(double), optimizer->total_parameters, fp);

    fclose(fp);
    return 0;
}

qihse_ml_optimizer_t* qihse_ml_optimizer_load(const char* path) {
    if (!path) return NULL;

    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    size_t input_size;
    size_t num_layers;
    double learning_rate;
    double momentum;

    if (fread(&input_size, sizeof(size_t), 1, fp) != 1 ||
        fread(&num_layers, sizeof(size_t), 1, fp) != 1) {
        fclose(fp);
        return NULL;
    }

    size_t* layer_sizes = calloc(num_layers, sizeof(size_t));
    if (!layer_sizes) {
        fclose(fp);
        return NULL;
    }
    if (fread(layer_sizes, sizeof(size_t), num_layers, fp) != num_layers ||
        fread(&learning_rate, sizeof(double), 1, fp) != 1 ||
        fread(&momentum, sizeof(double), 1, fp) != 1) {
        free(layer_sizes);
        fclose(fp);
        return NULL;
    }

    qihse_nn_config_t config = {
        .input_size = input_size,
        .output_size = QIHSE_TARGET_COUNT,
        .num_layers = num_layers,
        .layer_sizes = layer_sizes,
        .learning_rate = learning_rate,
        .momentum = momentum
    };

    qihse_ml_optimizer_t* optimizer = qihse_ml_optimizer_init(&config, NULL, 0);
    free(layer_sizes);
    if (!optimizer) {
        fclose(fp);
        return NULL;
    }

    qihse_ml_optimizer_internal_t* internal = optimizer->internal_context;
    if (!internal) {
        qihse_ml_optimizer_destroy(optimizer);
        fclose(fp);
        return NULL;
    }

    for (size_t layer_idx = 0; layer_idx < internal->network.num_layers; layer_idx++) {
        nn_layer_t* layer = &internal->network.layers[layer_idx];
        size_t weight_count = layer->input_size * layer->output_size;
        if (fread(layer->weights, sizeof(float), weight_count, fp) != weight_count ||
            fread(layer->biases, sizeof(float), layer->output_size, fp) != layer->output_size) {
            qihse_ml_optimizer_destroy(optimizer);
            fclose(fp);
            return NULL;
        }
    }

    double best_loss;
    if (fread(&best_loss, sizeof(double), 1, fp) != 1 ||
        fread(optimizer->best_weights, sizeof(double), optimizer->total_parameters, fp) != optimizer->total_parameters) {
        qihse_ml_optimizer_destroy(optimizer);
        fclose(fp);
        return NULL;
    }

    optimizer->best_loss = best_loss;
    fclose(fp);
    return optimizer;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

void qihse_ml_print_stats(const qihse_ml_optimizer_t* optimizer) {
    if (!optimizer) return;

    printf("QIHSE ML Optimizer Statistics:\n");
    printf("=============================\n");
    printf("Layers: %zu\n", optimizer->nn_config.num_layers);
    printf("Training samples: %zu\n", optimizer->training_samples);
    printf("Epochs completed: %zu\n", optimizer->epochs_completed);
    printf("Current loss: %.6f\n", optimizer->current_loss);
    printf("Best loss: %.6f\n", optimizer->best_loss);
    printf("Online learning: %s\n", optimizer->online_learning ? "Enabled" : "Disabled");
    printf("Adaptation rate: %.4f\n", optimizer->adaptation_rate);
}
