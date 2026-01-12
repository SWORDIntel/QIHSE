/*
 * QIHSE - Intel NPU Backend (OpenVINO)
 *
 * Neural Processing Unit backend using Intel OpenVINO for inference acceleration.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_NPU_OPENVINO_H
#define QIHSE_NPU_OPENVINO_H

#include "../../core/qihse_abi.h"
#include "../../memory/include/qihse_memory.h"
#include "../../memory/include/qihse_uma.h"
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * NPU DEVICE CONFIGURATION
 * ============================================================================ */

/**
 * Intel NPU device capabilities and configuration.
 */
typedef struct qihse_npu_config_s {
    /* Hardware capabilities */
    size_t total_memory_mb;          /* Total NPU memory (e.g., 128MB for Meteor Lake) */
    size_t available_memory_mb;      /* Available memory */
    bool supports_fp16;              /* FP16 support */
    bool supports_int8;              /* INT8 quantization support */
    bool supports_gna;               /* Gaussian Neural Accelerator support */
    size_t max_batch_size;           /* Maximum batch size */
    size_t max_input_channels;       /* Maximum input channels */
    size_t max_output_channels;      /* Maximum output channels */

    /* Performance characteristics */
    double peak_tops;                /* Peak TOPS performance */
    double memory_bandwidth_gbps;    /* Memory bandwidth */
    double power_consumption_watts;  /* Power consumption */

    /* OpenVINO configuration */
    const char* device_name;         /* OpenVINO device name ("NPU", "GNA", etc.) */
    const char* model_precision;     /* Preferred model precision ("FP16", "INT8") */
    size_t inference_threads;        /* Number of inference threads */

    /* Cache and optimization */
    bool enable_caching;             /* Enable model caching */
    bool enable_profiling;           /* Enable performance profiling */
    size_t cache_size_mb;            /* Model cache size */
} qihse_npu_config_t;

/* ============================================================================
 * NPU CONTEXT AND MODELS
 * ============================================================================ */

/**
 * Compiled NPU model for inference.
 */
typedef struct qihse_npu_model_s* qihse_npu_model_t;

/**
 * NPU inference request handle.
 */
typedef struct qihse_npu_request_s* qihse_npu_request_t;

/**
 * NPU backend context.
 */
typedef struct qihse_npu_context_s {
    /* OpenVINO integration */
    void* ov_core;                   /* OpenVINO Core object */
    void* ov_compiled_model;         /* Compiled model */
    qihse_npu_config_t config;       /* Device configuration */

    /* Memory management */
    qihse_memory_manager_t memory_manager; /* Memory manager */
    qihse_uma_manager_t uma_manager; /* Unified memory manager */

    /* Model registry */
    qihse_npu_model_t* models;       /* Loaded models */
    size_t num_models;               /* Number of models */
    size_t max_models;               /* Maximum models */

    /* Performance tracking */
    uint64_t total_inferences;       /* Total inference operations */
    double avg_inference_time_ms;    /* Average inference time */
    double total_energy_consumed_j;  /* Total energy consumption */
    char gna_power_profile[32];      /* Current GNA power profile */

    /* Error tracking */
    char last_error[256];
    int last_error_code;
    bool error_occurred;

    /* Thread safety */
    pthread_mutex_t mutex;           /* Context protection */
} qihse_npu_context_t;

/* ============================================================================
 * NPU LIFECYCLE MANAGEMENT
 * ============================================================================ */

/**
 * Initialize NPU backend with OpenVINO.
 *
 * @param config NPU configuration
 * @param memory_manager Memory manager for allocations
 * @return NPU context, or NULL on failure
 */
qihse_npu_context_t* qihse_npu_init(
    const qihse_npu_config_t* config,
    qihse_memory_manager_t memory_manager
);

/**
 * Shutdown NPU backend and release resources.
 *
 * @param context NPU context to shutdown
 */
void qihse_npu_shutdown(qihse_npu_context_t* context);

/* ============================================================================
 * MODEL MANAGEMENT
 * ============================================================================ */

/**
 * Load and compile a model for NPU inference.
 *
 * @param context NPU context
 * @param model_path Path to OpenVINO model file (.xml/.bin or .onnx)
 * @param model_name Unique model identifier
 * @return Model handle, or NULL on failure
 */
qihse_npu_model_t qihse_npu_load_model(
    qihse_npu_context_t* context,
    const char* model_path,
    const char* model_name
);

/**
 * Unload a model from NPU.
 *
 * @param context NPU context
 * @param model Model to unload
 */
void qihse_npu_unload_model(
    qihse_npu_context_t* context,
    qihse_npu_model_t model
);

/* ============================================================================
 * INFERENCE OPERATIONS
 * ============================================================================ */

/**
 * Create an inference request for a model.
 *
 * @param context NPU context
 * @param model Model to create request for
 * @return Inference request handle, or NULL on failure
 */
qihse_npu_request_t qihse_npu_create_request(
    qihse_npu_context_t* context,
    qihse_npu_model_t model
);

/**
 * Set input tensor for inference.
 *
 * @param request Inference request
 * @param input_name Input tensor name
 * @param data Input data buffer
 * @param size Data size in bytes
 * @return true on success, false on failure
 */
bool qihse_npu_set_input(
    qihse_npu_request_t request,
    const char* input_name,
    const void* data,
    size_t size
);

/**
 * Set input tensor using unified memory.
 *
 * @param request Inference request
 * @param input_name Input tensor name
 * @param uma_address Unified memory address
 * @return true on success, false on failure
 */
bool qihse_npu_set_input_uma(
    qihse_npu_request_t request,
    const char* input_name,
    qihse_uma_address_t* uma_address
);

/**
 * Execute inference synchronously.
 *
 * @param request Inference request
 * @return true on success, false on failure
 */
bool qihse_npu_infer(qihse_npu_request_t request);

/**
 * Execute inference asynchronously.
 *
 * @param request Inference request
 * @return true on success, false on failure (inference continues in background)
 */
bool qihse_npu_infer_async(qihse_npu_request_t request);

/**
 * Wait for asynchronous inference to complete.
 *
 * @param request Inference request
 * @param timeout_ms Timeout in milliseconds (0 = infinite)
 * @return true on success, false on timeout/failure
 */
bool qihse_npu_wait(qihse_npu_request_t request, uint32_t timeout_ms);

/**
 * Get output tensor from inference results.
 *
 * @param request Inference request
 * @param output_name Output tensor name
 * @param data Output data buffer
 * @param size Buffer size in bytes
 * @return true on success, false on failure
 */
bool qihse_npu_get_output(
    qihse_npu_request_t request,
    const char* output_name,
    void* data,
    size_t size
);

/**
 * Get output tensor using unified memory.
 *
 * @param request Inference request
 * @param output_name Output tensor name
 * @param uma_address Unified memory address for output
 * @return true on success, false on failure
 */
bool qihse_npu_get_output_uma(
    qihse_npu_request_t request,
    const char* output_name,
    qihse_uma_address_t* uma_address
);

/**
 * Destroy inference request.
 *
 * @param request Request to destroy
 */
void qihse_npu_destroy_request(qihse_npu_request_t request);

/* ============================================================================
 * BATCH PROCESSING
 * ============================================================================ */

/**
 * Set batch size for model inference.
 *
 * @param context NPU context
 * @param model Model to configure
 * @param batch_size Batch size (1 = no batching)
 * @return true on success, false on failure
 */
bool qihse_npu_set_batch_size(
    qihse_npu_context_t* context,
    qihse_npu_model_t model,
    size_t batch_size
);

/**
 * Process a batch of inputs.
 *
 * @param request Inference request (configured for batching)
 * @param inputs Array of input data pointers
 * @param outputs Array of output data pointers
 * @param batch_size Number of items in batch
 * @return true on success, false on failure
 */
bool qihse_npu_infer_batch(
    qihse_npu_request_t request,
    const void** inputs,
    void** outputs,
    size_t batch_size
);

/* ============================================================================
 * PERFORMANCE MONITORING
 * ============================================================================ */

/**
 * NPU performance statistics.
 */
typedef struct qihse_npu_stats_s {
    uint64_t total_inferences;       /* Total inference operations */
    double avg_inference_time_ms;    /* Average inference time */
    double throughput_inferences_sec; /* Inference throughput */
    double total_energy_consumed_j;  /* Total energy consumption */
    double avg_power_consumption_w;  /* Average power consumption */
    size_t peak_memory_usage_mb;     /* Peak memory usage */
    double cache_hit_rate;           /* Model cache hit rate */
} qihse_npu_stats_t;

/**
 * Get NPU performance statistics.
 *
 * @param context NPU context
 * @param stats Output statistics
 * @return true on success, false on failure
 */
bool qihse_npu_get_stats(
    qihse_npu_context_t* context,
    qihse_npu_stats_t* stats
);

/**
 * Reset performance statistics.
 *
 * @param context NPU context
 */
void qihse_npu_reset_stats(qihse_npu_context_t* context);

/* ============================================================================
 * GNA-SPECIFIC OPERATIONS (Intel Gaussian Neural Accelerator)
 * ============================================================================ */

/**
 * Configure GNA for low-power inference.
 *
 * @param context NPU context
 * @param enable_gna Enable GNA acceleration
 * @param power_profile Power profile ("LOW_POWER", "BALANCED", "HIGH_PERF")
 * @return true on success, false on failure
 */
bool qihse_npu_configure_gna(
    qihse_npu_context_t* context,
    bool enable_gna,
    const char* power_profile
);

/**
 * Fine-tune GNA model for specific workload.
 *
 * @param context NPU context
 * @param model Model to fine-tune
 * @param calibration_data Calibration dataset
 * @param num_samples Number of calibration samples
 * @return true on success, false on failure
 */
bool qihse_npu_finetune_gna(
    qihse_npu_context_t* context,
    qihse_npu_model_t model,
    const float** calibration_data,
    size_t num_samples
);

/* ============================================================================
 * ERROR HANDLING
 * ============================================================================ */

/**
 * Get last error message from NPU operations.
 *
 * @param context NPU context
 * @return Error message string, or NULL if no error
 */
const char* qihse_npu_get_last_error(qihse_npu_context_t* context);

/**
 * Clear last error state.
 *
 * @param context NPU context
 */
void qihse_npu_clear_error(qihse_npu_context_t* context);

/* ============================================================================
 * PROCESSING-IN-MEMORY (PIM) OPERATIONS
 * ============================================================================
 *
 * PIM operations for memory-compute co-location using NPU tensor cores.
 * ============================================================================ */

/**
 * PIM matrix-vector multiplication operation.
 */
typedef struct qihse_npu_pim_mv_s {
    size_t matrix_rows;              /* Matrix rows (M) */
    size_t matrix_cols;              /* Matrix columns (N) */
    size_t vector_size;              /* Vector size (must equal N) */
    float* matrix_data;              /* Matrix data [M*N] */
    float* vector_data;              /* Vector data [N] */
    float* result_data;              /* Result data [M] */
    void* pim_kernel;                /* PIM-optimized kernel handle */
    size_t tile_size;                /* Tile size for blocked operations */
} qihse_npu_pim_mv_t;

/**
 * Initialize PIM matrix-vector operation.
 *
 * @param mv PIM operation to initialize
 * @param matrix_rows Matrix rows
 * @param matrix_cols Matrix columns (must equal vector size)
 * @param matrix_data Matrix data (will be transferred to NPU memory)
 * @param tile_size Tile size for blocked operations
 * @return 0 on success, negative error code on failure
 */
int qihse_npu_pim_mv_init(
    qihse_npu_pim_mv_t* mv,
    size_t matrix_rows,
    size_t matrix_cols,
    const float* matrix_data,
    size_t tile_size
);

/**
 * Execute PIM matrix-vector multiplication.
 *
 * @param mv PIM operation instance
 * @param vector Input vector data [matrix_cols]
 * @param result Output result vector [matrix_rows]
 * @return 0 on success, negative error code on failure
 */
int qihse_npu_pim_mv_execute(
    qihse_npu_pim_mv_t* mv,
    const float* vector,
    float* result
);

/**
 * Destroy PIM matrix-vector operation.
 *
 * @param mv PIM operation to destroy
 */
void qihse_npu_pim_mv_destroy(qihse_npu_pim_mv_t* mv);

/**
 * PIM blocked GEMM operation.
 */
typedef struct qihse_npu_pim_gemm_s {
    size_t M;                        /* Matrix A rows, Matrix C rows */
    size_t N;                        /* Matrix B columns, Matrix C columns */
    size_t K;                        /* Matrix A columns, Matrix B rows */
    float* matrix_a;                 /* Matrix A data [M*K] */
    float* matrix_b;                 /* Matrix B data [K*N] */
    float* matrix_c;                 /* Matrix C data [M*N] - result */
    size_t block_size;               /* Block size for tiled operations */
    void* gemm_kernel;               /* PIM GEMM kernel handle */
} qihse_npu_pim_gemm_t;

/**
 * Initialize PIM GEMM operation.
 *
 * @param gemm PIM GEMM operation to initialize
 * @param M Matrix A rows / Matrix C rows
 * @param N Matrix B columns / Matrix C columns
 * @param K Matrix A columns / Matrix B rows
 * @param matrix_a Matrix A data [M*K]
 * @param matrix_b Matrix B data [K*N]
 * @param block_size Block size for tiled operations
 * @return 0 on success, negative error code on failure
 */
int qihse_npu_pim_gemm_init(
    qihse_npu_pim_gemm_t* gemm,
    size_t M, size_t N, size_t K,
    const float* matrix_a,
    const float* matrix_b,
    size_t block_size
);

/**
 * Execute PIM blocked GEMM operation.
 *
 * @param gemm PIM GEMM operation instance
 * @param result Output result matrix [M*N]
 * @return 0 on success, negative error code on failure
 */
int qihse_npu_pim_gemm_execute(
    qihse_npu_pim_gemm_t* gemm,
    float* result
);

/**
 * Destroy PIM GEMM operation.
 *
 * @param gemm PIM GEMM operation to destroy
 */
void qihse_npu_pim_gemm_destroy(qihse_npu_pim_gemm_t* gemm);

/**
 * Allocate PIM-optimized memory buffer.
 *
 * @param size Size in bytes
 * @param alignment Memory alignment (for SIMD operations)
 * @return Allocated buffer, or NULL on failure
 */
void* qihse_npu_pim_alloc(size_t size, size_t alignment);

/**
 * Free PIM-optimized memory buffer.
 *
 * @param ptr Buffer to free
 */
void qihse_npu_pim_free(void* ptr);

/**
 * Prefetch data for PIM operations.
 *
 * @param data Data buffer to prefetch
 * @param size Size of data in bytes
 * @param direction Prefetch direction (read/write)
 */
void qihse_npu_pim_prefetch(const void* data, size_t size, int direction);

/**
 * Synchronize PIM operations.
 *
 * Ensures all pending PIM operations are complete before proceeding.
 */
void qihse_npu_pim_sync(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_NPU_OPENVINO_H */
