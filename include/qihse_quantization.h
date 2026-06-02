/**
 * QIHSE NPU-Optimized Quantization Pipeline
 *
 * Hardware-accelerated quantization with continuous learning and adaptation.
 * Supports INT2, INT4, INT8, FP16, BF16 precision with NPU optimization.
 */

#ifndef QIHSE_QUANTIZATION_H
#define QIHSE_QUANTIZATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse.h"

/* ============================================================================
 * QUANTIZATION PRECISION MODES
 * ============================================================================ */

typedef enum {
    QIHSE_QUANT_INT2,       /* 2-bit integer quantization */
    QIHSE_QUANT_INT4,       /* 4-bit integer quantization */
    QIHSE_QUANT_INT8,       /* 8-bit integer quantization */
    QIHSE_QUANT_FP16,       /* 16-bit floating point */
    QIHSE_QUANT_BF16,       /* 16-bit bfloat16 */
    QIHSE_QUANT_FP32,       /* 32-bit floating point (no quantization) */
} qihse_quantization_mode_t;

/**
 * Quantization parameters for a data block
 */
typedef struct {
    qihse_quantization_mode_t mode;
    double scale_factor;           /* Scale factor for quantization */
    double zero_point;             /* Zero point for asymmetric quantization */
    double min_val;                /* Minimum value in original data */
    double max_val;                /* Maximum value in original data */
    double quantization_error;     /* RMS quantization error */
    size_t original_bits;          /* Original precision (32 for float, etc.) */
    size_t quantized_bits;         /* Quantized precision */

    /* NPU-specific optimizations */
    bool npu_optimized;            /* True if optimized for NPU */
    uint32_t npu_tile_size;        /* Optimal tile size for NPU processing */
    uint32_t npu_batch_size;       /* Optimal batch size for NPU */
} qihse_quantization_params_t;

/* ============================================================================
 * ADAPTIVE QUANTIZATION PIPELINE
 * ============================================================================ */

/**
 * Quantization pipeline stage
 */
typedef enum {
    QIHSE_QUANT_STAGE_ANALYZE,     /* Data analysis stage */
    QIHSE_QUANT_STAGE_CALIBRATE,   /* Calibration stage */
    QIHSE_QUANT_STAGE_QUANTIZE,    /* Quantization stage */
    QIHSE_QUANT_STAGE_OPTIMIZE,    /* NPU optimization stage */
    QIHSE_QUANT_STAGE_VERIFY,      /* Verification stage */
} qihse_quantization_stage_t;

/**
 * Adaptive quantization pipeline with learning
 */
typedef struct {
    char pipeline_name[64];
    qihse_quantization_mode_t target_mode;
    bool enable_learning;          /* Enable continuous adaptation */

    /* Pipeline stages */
    qihse_quantization_params_t current_params;

    /* Learning state */
    size_t learning_samples;       /* Number of samples processed */
    double avg_quantization_error; /* Running average error */
    double min_error_seen;         /* Best error achieved */
    qihse_quantization_params_t best_params; /* Best parameters found */

    /* Hardware acceleration */
    bool use_npu;                  /* Use NPU for quantization */
    bool use_amx;                  /* Use AMX for int8 operations */
    bool use_vnni;                 /* Use VNNI for int8 dot products */
    void* accelerator_context;     /* Hardware context */

    /* Performance tracking */
    uint64_t total_quantize_time_ns;
    uint64_t total_dequantize_time_ns;
    size_t total_bytes_processed;
} qihse_quantization_pipeline_t;

/* ============================================================================
 * NPU QUANTIZATION KERNELS
 * ============================================================================ */

/**
 * NPU-optimized quantization functions
 */
typedef struct {
    /* INT8 quantization */
    int (*quantize_int8)(const float* input, int8_t* output, size_t n,
                         const qihse_quantization_params_t* params);

    /* INT4 quantization */
    int (*quantize_int4)(const float* input, uint8_t* output, size_t n,
                         const qihse_quantization_params_t* params);

    /* FP16 quantization */
    int (*quantize_fp16)(const float* input, uint16_t* output, size_t n,
                         const qihse_quantization_params_t* params);

    /* BF16 quantization */
    int (*quantize_bf16)(const float* input, uint16_t* output, size_t n,
                         const qihse_quantization_params_t* params);

    /* Batch processing */
    int (*quantize_batch)(const float* input, void* output, size_t batch_size,
                          size_t vector_size, qihse_quantization_mode_t mode,
                          const qihse_quantization_params_t* params);

} qihse_npu_quantization_ops_t;

/* ============================================================================
 * QUANTIZATION PIPELINE API
 * ============================================================================ */

/**
 * Create quantization pipeline
 */
qihse_quantization_pipeline_t* qihse_quantization_pipeline_create(
    const char* name,
    qihse_quantization_mode_t mode,
    bool enable_learning
);

/**
 * Destroy quantization pipeline
 */
void qihse_quantization_pipeline_destroy(qihse_quantization_pipeline_t* pipeline);

/**
 * Analyze data for optimal quantization parameters
 */
int qihse_quantization_analyze(
    qihse_quantization_pipeline_t* pipeline,
    const void* data,
    size_t n,
    qihse_data_type_t data_type
);

/**
 * Calibrate quantization parameters using sample data
 */
int qihse_quantization_calibrate(
    qihse_quantization_pipeline_t* pipeline,
    const void* calibration_data,
    size_t calibration_size,
    qihse_data_type_t data_type
);

/**
 * Quantize data using optimized pipeline
 */
int qihse_quantization_quantize(
    qihse_quantization_pipeline_t* pipeline,
    const void* input_data,
    size_t input_size,
    void** output_data,
    size_t* output_size
);

/**
 * Dequantize data back to original precision
 */
int qihse_quantization_dequantize(
    qihse_quantization_pipeline_t* pipeline,
    const void* quantized_data,
    size_t quantized_size,
    void** output_data,
    size_t* output_size
);

/**
 * Update pipeline with performance feedback (learning)
 */
int qihse_quantization_update_feedback(
    qihse_quantization_pipeline_t* pipeline,
    double quantization_error,
    double performance_impact
);

/* ============================================================================
 * HARDWARE-ACCELERATED QUANTIZATION
 * ============================================================================ */

/**
 * Initialize NPU quantization acceleration
 */
int qihse_npu_quantization_init(qihse_quantization_pipeline_t* pipeline);

/**
 * Perform NPU-accelerated quantization
 */
int qihse_npu_quantize_data(
    const float* input,
    void* output,
    size_t n,
    qihse_quantization_mode_t mode,
    const qihse_quantization_params_t* params
);

/**
 * Initialize AMX-accelerated INT8 quantization
 */
int qihse_amx_quantization_init(qihse_quantization_pipeline_t* pipeline);

/**
 * Perform AMX-accelerated INT8 operations
 */
int qihse_amx_int8_quantize(
    const float* input,
    int8_t* output,
    size_t n,
    const qihse_quantization_params_t* params
);

/**
 * Initialize VNNI-accelerated INT8 dot products
 */
int qihse_vnni_quantization_init(qihse_quantization_pipeline_t* pipeline);

/**
 * Perform VNNI-accelerated quantized operations
 */
int qihse_vnni_int8_dot_product(
    const int8_t* a,
    const int8_t* b,
    size_t n,
    int32_t* result
);

/* ============================================================================
 * ADAPTIVE PRECISION SELECTION
 * ============================================================================ */

/**
 * Precision recommendation based on data characteristics
 */
typedef struct {
    qihse_quantization_mode_t recommended_mode;
    double expected_compression_ratio;
    double expected_speedup;
    double expected_accuracy_loss;
    char reasoning[256];           /* Explanation for recommendation */
} qihse_precision_recommendation_t;

/**
 * Get precision recommendation for data
 */
int qihse_quantization_recommend_precision(
    const void* data,
    size_t n,
    qihse_data_type_t data_type,
    double target_accuracy,
    double target_speedup,
    qihse_precision_recommendation_t* recommendation
);

/**
 * Automatically select optimal quantization for QIHSE
 */
int qihse_quantization_auto_select(
    qihse_quantization_pipeline_t* pipeline,
    const void* data,
    size_t n,
    qihse_data_type_t data_type,
    const qihse_compute_pool_t* compute_pool
);

/* ============================================================================
 * QUANTIZATION-AWARE QIHSE INTEGRATION
 * ============================================================================ */

/**
 * QIHSE configuration with quantization
 */
typedef struct {
    qihse_config_t base_config;                    /* Base QIHSE config */
    qihse_quantization_pipeline_t* quant_pipeline; /* Quantization pipeline */
    bool enable_quantization;                      /* Enable quantization */
    qihse_quantization_mode_t quant_mode;          /* Quantization mode */

    /* Quantization-specific settings */
    bool quantize_queries;                         /* Quantize query vectors */
    bool quantize_database;                        /* Quantize database vectors */
    bool adaptive_precision;                       /* Adapt precision dynamically */
    double accuracy_threshold;                     /* Minimum accuracy to maintain */
} qihse_quantized_config_t;

/**
 * Initialize quantized QIHSE configuration
 */
int qihse_quantized_config_init(
    qihse_quantized_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size,
    qihse_quantization_mode_t quant_mode
);

/**
 * Quantized QIHSE search
 */
not_stisla_result_t qihse_quantized_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_quantized_config_t* config
);

/**
 * Quantized QIHSE batch search
 */
size_t qihse_quantized_batch_search(
    const void* data,
    size_t n,
    const void* queries,
    size_t num_queries,
    not_stisla_result_t* results,
    not_stisla_anchor_table_t* table,
    const qihse_quantized_config_t* config
);

/* ============================================================================
 * PERFORMANCE MONITORING & TUNING
 * ============================================================================ */

/**
 * Quantization performance statistics
 */
typedef struct {
    uint64_t total_quantize_time_ns;
    uint64_t total_dequantize_time_ns;
    size_t total_bytes_processed;
    size_t total_bytes_saved;

    /* Per-precision statistics */
    struct {
        uint64_t quantize_calls;
        uint64_t dequantize_calls;
        double avg_error;
        double compression_ratio;
        double speedup_factor;
    } precision_stats[QIHSE_QUANT_FP32 + 1];

    /* Learning statistics */
    size_t parameters_learned;
    double avg_learning_improvement;
    uint64_t last_recalibration;
} qihse_quantization_stats_t;

/**
 * Get quantization performance statistics
 */
int qihse_quantization_get_stats(qihse_quantization_stats_t* stats);

/**
 * Reset quantization performance statistics
 */
void qihse_quantization_reset_stats(void);

/**
 * Export quantization learning data
 */
int qihse_quantization_export_learning_data(
    const qihse_quantization_pipeline_t* pipeline,
    const char* output_path
);

/* ============================================================================
 * METEOR LAKE NPU SPECIFIC OPTIMIZATIONS
 * ============================================================================ */

/**
 * Enable Meteor Lake NPU quantization paths
 */
int qihse_meteor_lake_npu_quantization_enable(void);

/**
 * Configure quantization for Meteor Lake NPU cache (128MB)
 */
int qihse_meteor_lake_npu_cache_quantize(
    qihse_quantization_pipeline_t* pipeline,
    size_t cache_size_mb
);

/**
 * Use Meteor Lake GNA for quantization fine-tuning
 */
int qihse_meteor_lake_gna_quantization_tune(
    qihse_quantization_pipeline_t* pipeline,
    const float* performance_data,
    size_t num_samples
);

#endif /* QIHSE_QUANTIZATION_H */
