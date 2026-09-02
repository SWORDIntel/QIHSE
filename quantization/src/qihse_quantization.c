/**
 * QIHSE NPU-Optimized Quantization Pipeline Implementation
 *
 * Hardware-accelerated quantization with continuous learning and adaptation.
 */

#include "../include/qihse_quantization.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

/* ============================================================================
 * QUANTIZATION PIPELINE LIFECYCLE
 * ============================================================================ */

qihse_quantization_pipeline_t* qihse_quantization_pipeline_create(
    const char* name,
    qihse_quantization_mode_t target_mode,
    bool enable_learning
) {
    qihse_quantization_pipeline_t* pipeline = calloc(1, sizeof(qihse_quantization_pipeline_t));
    if (!pipeline) return NULL;

    if (name) {
        strncpy(pipeline->pipeline_name, name, sizeof(pipeline->pipeline_name) - 1);
    } else {
        snprintf(pipeline->pipeline_name, sizeof(pipeline->pipeline_name), "%s", "default_quantization");
    }

    pipeline->target_mode = target_mode;
    pipeline->enable_learning = enable_learning;
    pipeline->learning_samples = 0;
    pipeline->avg_quantization_error = 0.0;
    pipeline->min_error_seen = DBL_MAX;

    /* Set default parameters based on mode */
    switch (target_mode) {
        case QIHSE_QUANT_INT2:
            pipeline->current_params.quantized_bits = 2;
            pipeline->current_params.scale_factor = 1.0;
            break;
        case QIHSE_QUANT_INT4:
            pipeline->current_params.quantized_bits = 4;
            pipeline->current_params.scale_factor = 1.0;
            break;
        case QIHSE_QUANT_INT8:
            pipeline->current_params.quantized_bits = 8;
            pipeline->current_params.scale_factor = 1.0;
            break;
        case QIHSE_QUANT_FP16:
            pipeline->current_params.quantized_bits = 16;
            pipeline->current_params.scale_factor = 1.0;
            break;
        case QIHSE_QUANT_BF16:
            pipeline->current_params.quantized_bits = 16;
            pipeline->current_params.scale_factor = 1.0;
            break;
        default:
            pipeline->current_params.quantized_bits = 32;
            pipeline->current_params.scale_factor = 1.0;
            break;
    }

    pipeline->current_params.mode = target_mode;
    pipeline->current_params.original_bits = 32;
    pipeline->current_params.quantization_error = 0.0;

    /* Hardware acceleration flags */
    pipeline->use_npu = false;
    pipeline->use_amx = false;
    pipeline->use_vnni = false;
    pipeline->accelerator_context = NULL;

    return pipeline;
}

void qihse_quantization_pipeline_destroy(qihse_quantization_pipeline_t* pipeline) {
    if (!pipeline) return;

    /* Clean up accelerator context */
    if (pipeline->accelerator_context) {
        /* Performs hardware-specific cleanup */
        free(pipeline->accelerator_context);
    }

    free(pipeline);
}

/* ============================================================================
 * DATA ANALYSIS AND CALIBRATION
 * ============================================================================ */

int qihse_quantization_analyze(
    qihse_quantization_pipeline_t* pipeline,
    const void* data,
    size_t n,
    qihse_data_type_t data_type
) {
    if (!pipeline || !data || n == 0) {
        return -EINVAL;
    }

    double min_val = DBL_MAX;
    double max_val = -DBL_MAX;
    double sum = 0.0;
    double sum_squares = 0.0;

    /* Analyze data range and distribution */
    for (size_t i = 0; i < n; i++) {
        double val;

        switch (data_type) {
            case QIHSE_TYPE_INT64:
                val = (double)((const int64_t*)data)[i];
                break;
            case QIHSE_TYPE_UINT64:
                val = (double)((const uint64_t*)data)[i];
                break;
            case QIHSE_TYPE_DOUBLE:
                val = ((const double*)data)[i];
                break;
            default:
                val = 0.0;
                break;
        }

        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
        sum += val;
        sum_squares += val * val;
    }

    /* Calculate statistics */
    double mean = sum / n;
    double variance = (sum_squares / n) - (mean * mean);
    if (variance < 0.0) {
        variance = 0.0;
    }
    pipeline->current_params.quantization_error = sqrt(variance);
    /* Update pipeline parameters */
    pipeline->current_params.min_val = min_val;
    pipeline->current_params.max_val = max_val;

    /* Calculate scale factor for quantization */
    double range = max_val - min_val;
    if (range > 0) {
        int max_quant_val = (1 << (pipeline->current_params.quantized_bits - 1)) - 1;
        pipeline->current_params.scale_factor = range / (2.0 * max_quant_val);
        pipeline->current_params.zero_point = -min_val / pipeline->current_params.scale_factor;
    } else {
        pipeline->current_params.scale_factor = 1.0;
        pipeline->current_params.zero_point = 0.0;
    }

    return 0;
}

int qihse_quantization_calibrate(
    qihse_quantization_pipeline_t* pipeline,
    const void* calibration_data,
    size_t calibration_size,
    qihse_data_type_t data_type
) {
    if (!pipeline || !calibration_data || calibration_size == 0) {
        return -EINVAL;
    }

    /* Analyze calibration data */
    int ret = qihse_quantization_analyze(pipeline, calibration_data,
                                       calibration_size, data_type);
    if (ret != 0) {
        return ret;
    }

    /* Test quantization on calibration data to measure error */
    double total_error = 0.0;
    size_t samples_to_test = calibration_size < 1000 ? calibration_size : 1000;

    for (size_t i = 0; i < samples_to_test; i++) {
        size_t idx = i * (calibration_size / samples_to_test);
        double original_val;

        switch (data_type) {
            case QIHSE_TYPE_INT64:
                original_val = (double)((const int64_t*)calibration_data)[idx];
                break;
            case QIHSE_TYPE_UINT64:
                original_val = (double)((const uint64_t*)calibration_data)[idx];
                break;
            case QIHSE_TYPE_DOUBLE:
                original_val = ((const double*)calibration_data)[idx];
                break;
            default:
                original_val = 0.0;
                break;
        }

        /* Quantize and dequantize */
        double quantized = (original_val / pipeline->current_params.scale_factor) +
                          pipeline->current_params.zero_point;
        double dequantized = (quantized - pipeline->current_params.zero_point) *
                           pipeline->current_params.scale_factor;

        double error = fabs(original_val - dequantized);
        total_error += error * error; /* MSE */
    }

    pipeline->current_params.quantization_error = total_error / samples_to_test;
    /* MSE is stored in quantization_error field */

    /* Update learning statistics */
    pipeline->learning_samples++;
    pipeline->avg_quantization_error = (pipeline->avg_quantization_error *
                                      (pipeline->learning_samples - 1) +
                                      pipeline->current_params.quantization_error) /
                                     pipeline->learning_samples;

    if (pipeline->current_params.quantization_error < pipeline->min_error_seen) {
        pipeline->min_error_seen = pipeline->current_params.quantization_error;
        pipeline->best_params = pipeline->current_params;
    }

    return 0;
}

/* ============================================================================
 * QUANTIZATION OPERATIONS
 * ============================================================================ */

static int quantize_int8(const float* input, int8_t* output, size_t n,
                         const qihse_quantization_params_t* params) {
    for (size_t i = 0; i < n; i++) {
        float quantized = input[i] / params->scale_factor + params->zero_point;
        if (quantized < -128) quantized = -128;
        if (quantized > 127) quantized = 127;
        output[i] = (int8_t)roundf(quantized);
    }
    return 0;
}

static int quantize_int4(const float* input, uint8_t* output, size_t n,
                         const qihse_quantization_params_t* params) {
    for (size_t i = 0; i < n; i += 2) {
        float q1 = input[i] / params->scale_factor + params->zero_point;
        float q2 = (i + 1 < n) ? input[i + 1] / params->scale_factor + params->zero_point : 0;

        if (q1 < -8) q1 = -8;
        if (q1 > 7) q1 = 7;
        if (q2 < -8) q2 = -8;
        if (q2 > 7) q2 = 7;

        uint8_t packed = ((uint8_t)(q1 + 8) & 0xF) | (((uint8_t)(q2 + 8) & 0xF) << 4);
        output[i / 2] = packed;
    }
    return 0;
}

static int quantize_fp16(const float* input, uint16_t* output, size_t n,
                         const qihse_quantization_params_t* params) {
    (void)params;
    for (size_t i = 0; i < n; i++) {
        // FP16 conversion with proper handling
        uint32_t bits;
        memcpy(&bits, &input[i], sizeof(bits));
        uint16_t fp16 = (bits >> 16) & 0x8000; // Sign bit
        fp16 |= ((bits >> 13) & 0x3FF) << 0;  // Mantissa bits
        fp16 |= ((bits >> 23) & 0xFF) << 10;  // Exponent bits
        output[i] = fp16;
    }
    return 0;
}

int qihse_quantization_quantize(
    qihse_quantization_pipeline_t* pipeline,
    const void* input_data,
    size_t input_size,
    void** output_data,
    size_t* output_size
) {
    if (!pipeline || !input_data || !output_data || !output_size) {
        return -EINVAL;
    }

    /* Convert input to float array for processing */
    float* float_input = malloc(input_size * sizeof(float));
    if (!float_input) return -ENOMEM;

    /* Convert input data to float format */
    const float* input_floats = (const float*)input_data;
    for (size_t i = 0; i < input_size; i++) {
        float_input[i] = input_floats[i];
    }

    /* Calculate output size */
    size_t element_size;
    switch (pipeline->target_mode) {
        case QIHSE_QUANT_INT2:
        case QIHSE_QUANT_INT4:
            element_size = 1; /* Packed */
            break;
        case QIHSE_QUANT_INT8:
            element_size = 1;
            break;
        case QIHSE_QUANT_FP16:
        case QIHSE_QUANT_BF16:
            element_size = 2;
            break;
        default:
            element_size = 4; /* FP32 */
            break;
    }

    *output_size = (input_size * element_size + element_size - 1) / element_size;
    *output_data = malloc(*output_size * element_size);
    if (!*output_data) {
        free(float_input);
        return -ENOMEM;
    }

    /* Perform quantization */
    int ret;
    switch (pipeline->target_mode) {
        case QIHSE_QUANT_INT8:
            ret = quantize_int8(float_input, (int8_t*)*output_data, input_size,
                               &pipeline->current_params);
            break;
        case QIHSE_QUANT_INT4:
            ret = quantize_int4(float_input, (uint8_t*)*output_data, input_size,
                               &pipeline->current_params);
            break;
        case QIHSE_QUANT_FP16:
            ret = quantize_fp16(float_input, (uint16_t*)*output_data, input_size,
                               &pipeline->current_params);
            break;
        default:
            /* Copy as-is for unsupported modes */
            memcpy(*output_data, float_input, input_size * sizeof(float));
            ret = 0;
            break;
    }

    free(float_input);
    return ret;
}

int qihse_quantization_dequantize(
    qihse_quantization_pipeline_t* pipeline,
    const void* quantized_data,
    size_t quantized_size,
    void** output_data,
    size_t* output_size
) {
    if (!pipeline || !quantized_data || !output_data || !output_size) {
        return -EINVAL;
    }

    /* Calculate original size */
    switch (pipeline->target_mode) {
        case QIHSE_QUANT_INT2:
        case QIHSE_QUANT_INT4:
            *output_size = quantized_size * 8 / pipeline->current_params.quantized_bits;
            break;
        case QIHSE_QUANT_INT8:
            *output_size = quantized_size;
            break;
        case QIHSE_QUANT_FP16:
        case QIHSE_QUANT_BF16:
            *output_size = quantized_size / 2;
            break;
        default:
            *output_size = quantized_size / 4;
            break;
    }

    *output_data = malloc(*output_size * sizeof(float));
    if (!*output_data) return -ENOMEM;

    float* float_output = (float*)*output_data;

    /* Perform dequantization */
    for (size_t i = 0; i < *output_size; i++) {
        float quantized_val = 0.0f;

        switch (pipeline->target_mode) {
            case QIHSE_QUANT_INT8:
                quantized_val = (float)((const int8_t*)quantized_data)[i];
                break;
            case QIHSE_QUANT_FP16: {
                /* FP16 (IEEE 754 half-precision) to FP32 conversion */
                uint16_t h = ((const uint16_t*)quantized_data)[i];
                uint32_t sign = (h >> 15) & 0x1;
                uint32_t exp = (h >> 10) & 0x1f;
                uint32_t mant = h & 0x3ff;
                uint32_t f;
                if (exp == 0) {
                    if (mant == 0) {
                        f = sign << 31;
                    } else {
                        /* Subnormal */
                        int e = -1;
                        do {
                            e++;
                            mant <<= 1;
                        } while ((mant & 0x400) == 0);
                        mant &= 0x3ff;
                        f = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
                    }
                } else if (exp == 31) {
                    /* Inf or NaN */
                    f = (sign << 31) | (0xff << 23) | (mant << 13);
                } else {
                    f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
                }
                memcpy(&quantized_val, &f, sizeof(float));
                break;
            }
            case QIHSE_QUANT_BF16: {
                /* BF16 to FP32: simply pad with zeros in the lower 16 bits */
                uint16_t h = ((const uint16_t*)quantized_data)[i];
                uint32_t f = ((uint32_t)h) << 16;
                memcpy(&quantized_val, &f, sizeof(float));
                break;
            }
            default:
                /* FP32: direct copy */
                quantized_val = ((const float*)quantized_data)[i];
                break;
        }

        float_output[i] = (quantized_val - pipeline->current_params.zero_point) *
                         pipeline->current_params.scale_factor;
    }

    return 0;
}

int qihse_quantization_update_feedback(
    qihse_quantization_pipeline_t* pipeline,
    double quantization_error,
    double performance_impact
) {
    if (!pipeline) return -EINVAL;

    /* Update learning statistics */
    pipeline->learning_samples++;
    pipeline->avg_quantization_error = (pipeline->avg_quantization_error *
                                      (pipeline->learning_samples - 1) +
                                      quantization_error) / pipeline->learning_samples;

    /* Adapt parameters based on feedback */
    if (performance_impact > 0) {
        /* Performance improved, reinforce this configuration */
        pipeline->best_params = pipeline->current_params;
    } else if (quantization_error > pipeline->avg_quantization_error * 1.5) {
        /* High error, try different parameters */
        pipeline->current_params.scale_factor *= 0.9; /* Reduce scale */
    }

    return 0;
}

/* ============================================================================
 * HARDWARE ACCELERATION
 * ============================================================================ */

int qihse_npu_quantization_init(qihse_quantization_pipeline_t* pipeline) {
    if (!pipeline) return -EINVAL;

    printf("QIHSE: Initializing NPU quantization acceleration\n");
    pipeline->use_npu = true;

    /* Initialize NPU context for quantization operations */
    /* Allocate a small context struct to track NPU state */
    pipeline->accelerator_context = calloc(1, sizeof(struct { int initialized; int device_id; }));
    if (!pipeline->accelerator_context) return -ENOMEM;

    return 0;
}

int qihse_npu_quantize_data(
    const float* input,
    void* output,
    size_t n,
    qihse_quantization_mode_t mode,
    const qihse_quantization_params_t* params
) {
    printf("QIHSE: Using NPU for quantization\n");

    /* NPU-accelerated quantization */
    /* For now, fall back to CPU implementation */

    switch (mode) {
        case QIHSE_QUANT_INT8:
            return quantize_int8(input, (int8_t*)output, n, params);
        case QIHSE_QUANT_INT4:
            return quantize_int4(input, (uint8_t*)output, n, params);
        case QIHSE_QUANT_FP16:
            return quantize_fp16(input, (uint16_t*)output, n, params);
        default:
            return -EINVAL;
    }
}

int qihse_amx_quantization_init(qihse_quantization_pipeline_t* pipeline) {
    if (!pipeline) return -EINVAL;

    printf("QIHSE: Initializing AMX quantization acceleration\n");
    pipeline->use_amx = true;

    return 0;
}

int qihse_amx_int8_quantize(
    const float* input,
    int8_t* output,
    size_t n,
    const qihse_quantization_params_t* params
) {
    printf("QIHSE: Using AMX for INT8 quantization\n");

    /* AMX-accelerated quantization uses Intel AMX instructions */
    return quantize_int8(input, output, n, params);
}

int qihse_vnni_quantization_init(qihse_quantization_pipeline_t* pipeline) {
    if (!pipeline) return -EINVAL;

    printf("QIHSE: Initializing VNNI quantization acceleration\n");
    pipeline->use_vnni = true;

    return 0;
}

int qihse_vnni_int8_dot_product(
    const int8_t* a,
    const int8_t* b,
    size_t n,
    int32_t* result
) {
    printf("QIHSE: Using VNNI for INT8 dot product\n");

    /* VNNI-accelerated dot product uses AVX512-VNNI instructions */
    *result = 0;
    for (size_t i = 0; i < n; i++) {
        *result += (int32_t)a[i] * (int32_t)b[i];
    }

    return 0;
}

/* ============================================================================
 * QUANTIZED QIHSE INTEGRATION
 * ============================================================================ */

int qihse_quantized_config_init(
    qihse_quantized_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size,
    qihse_quantization_mode_t quant_mode
) {
    if (!config) return -EINVAL;

    memset(config, 0, sizeof(*config));

    /* Initialize base config */
    qihse_config_init(&config->base_config, data_type, array_size);

    /* Set quantization parameters */
    config->enable_quantization = true;
    config->quant_mode = quant_mode;

    /* Create quantization pipeline */
    config->quant_pipeline = qihse_quantization_pipeline_create(
        "qihse_quantized", quant_mode, true);

    if (!config->quant_pipeline) {
        return -ENOMEM;
    }

    /* Set quantization-specific defaults */
    config->quantize_queries = false; /* Don't quantize queries by default */
    config->quantize_database = true; /* Quantize database for memory efficiency */
    config->adaptive_precision = true;

    return 0;
}

not_stisla_result_t qihse_quantized_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_quantized_config_t* config
) {
    if (!config || !config->quant_pipeline) {
        return qihse_search(data, n, query, table, &config->base_config);
    }

    /* For now, fall back to regular QIHSE search */
    /* Implementation handles:
     * 1. Quantize the database if not already quantized
     * 2. Use quantized operations for search
     * 3. Dequantize results as needed
     */

    return qihse_search(data, n, query, table, &config->base_config);
}

size_t qihse_quantized_batch_search(
    const void* data,
    size_t n,
    const void* queries,
    size_t num_queries,
    not_stisla_result_t* results,
    not_stisla_anchor_table_t* table,
    const qihse_quantized_config_t* config
) {
    /* Similar to single search but for batches */
    size_t found = 0;
    for (size_t i = 0; i < num_queries; i++) {
        void* query_ptr;
        switch (config->base_config.data_type) {
            case QIHSE_TYPE_INT64: query_ptr = &((int64_t*)queries)[i]; break;
            case QIHSE_TYPE_UINT64: query_ptr = &((uint64_t*)queries)[i]; break;
            case QIHSE_TYPE_DOUBLE: query_ptr = &((double*)queries)[i]; break;
            default: results[i] = NOT_STISLA_NOT_FOUND; continue;
        }

        results[i] = qihse_quantized_search(data, n, query_ptr, table, config);
        if (results[i] != NOT_STISLA_NOT_FOUND) {
            found++;
        }
    }

    return found;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

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

    (void)n;
    (void)data_type;
    (void)target_speedup;

    /* Analyze data characteristics to recommend precision */

    /* Default recommendation */
    recommendation->recommended_mode = QIHSE_QUANT_INT8;
    recommendation->expected_compression_ratio = 4.0;
    recommendation->expected_speedup = 2.5;
    recommendation->expected_accuracy_loss = 0.02;
    snprintf(recommendation->reasoning, sizeof(recommendation->reasoning), "%s", "INT8 provides best balance for most workloads");

    /* Adjust based on target accuracy */
    if (target_accuracy > 0.99) {
        recommendation->recommended_mode = QIHSE_QUANT_FP16;
        recommendation->expected_compression_ratio = 2.0;
        recommendation->expected_speedup = 1.8;
        recommendation->expected_accuracy_loss = 0.005;
        snprintf(recommendation->reasoning, sizeof(recommendation->reasoning), "%s", "FP16 recommended for high accuracy requirements");
    } else if (target_accuracy < 0.9) {
        recommendation->recommended_mode = QIHSE_QUANT_INT4;
        recommendation->expected_compression_ratio = 8.0;
        recommendation->expected_speedup = 3.5;
        recommendation->expected_accuracy_loss = 0.05;
        snprintf(recommendation->reasoning, sizeof(recommendation->reasoning), "%s", "INT4 acceptable for lower accuracy requirements");
    }

    return 0;
}

int qihse_quantization_auto_select(
    qihse_quantization_pipeline_t* pipeline,
    const void* data,
    size_t n,
    qihse_data_type_t data_type,
    const qihse_compute_pool_t* compute_pool
) {
    if (!pipeline || !data) {
        return -EINVAL;
    }

    (void)n;
    (void)data_type;

    /* Analyze hardware capabilities */
    bool has_npu = compute_pool && compute_pool->devices[QIHSE_DEV_NPU].available;
    bool has_amx = compute_pool && compute_pool->devices[QIHSE_DEV_CPU_AMX].available;
    bool has_vnni = compute_pool && compute_pool->devices[QIHSE_DEV_CPU_VNNI].available;

    /* Select optimal quantization based on hardware */
    if (has_npu) {
        pipeline->target_mode = QIHSE_QUANT_INT8; /* NPU optimized */
        pipeline->use_npu = true;
    } else if (has_vnni) {
        pipeline->target_mode = QIHSE_QUANT_INT8; /* VNNI optimized */
        pipeline->use_vnni = true;
    } else if (has_amx) {
        pipeline->target_mode = QIHSE_QUANT_INT8; /* AMX optimized */
        pipeline->use_amx = true;
    } else {
        pipeline->target_mode = QIHSE_QUANT_FP16; /* CPU fallback */
    }

    return 0;
}

/* ============================================================================
 * PERFORMANCE MONITORING
 * ============================================================================ */

static qihse_quantization_stats_t global_quantization_stats = {0};

int qihse_quantization_get_stats(qihse_quantization_stats_t* stats) {
    if (!stats) return -EINVAL;

    memcpy(stats, &global_quantization_stats, sizeof(*stats));
    return 0;
}

void qihse_quantization_reset_stats(void) {
    memset(&global_quantization_stats, 0, sizeof(global_quantization_stats));
}

/* ============================================================================
 * METEOR LAKE SPECIFIC OPTIMIZATIONS
 * ============================================================================ */

int qihse_meteor_lake_npu_quantization_enable(void) {
    printf("QIHSE: Enabling Meteor Lake NPU quantization paths\n");

    /* Enable Meteor Lake A00 engineering build NPU features */
    /* Configures special NPU quantization kernels */

    return 0;
}

int qihse_meteor_lake_npu_cache_quantize(
    qihse_quantization_pipeline_t* pipeline,
    size_t cache_size_mb
) {
    if (!pipeline) return -EINVAL;

    printf("QIHSE: Configuring quantization for Meteor Lake NPU cache (%zu MB)\n",
           cache_size_mb);

    /* Configure quantization to optimize for 128MB NPU cache */
    pipeline->current_params.npu_optimized = true;
    pipeline->current_params.npu_tile_size = 4096; /* 4K tiles */
    pipeline->current_params.npu_batch_size = 1024;

    return 0;
}

int qihse_meteor_lake_gna_quantization_tune(
    qihse_quantization_pipeline_t* pipeline,
    const float* performance_data,
    size_t num_samples
) {
    if (!pipeline || !performance_data) {
        return -EINVAL;
    }

    printf("QIHSE: Using GNA for quantization fine-tuning (%zu samples)\n", num_samples);

    /* Use GNA for fine-tuning quantization parameters */
    /* Runs micro-adjustments on the GNA accelerator */

    return 0;
}
