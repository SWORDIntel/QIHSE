/*
 * QIHSE - Quantum-Inspired Hilbert Space Expansion
 * Core ABI Header (ABI-STABLE)
 *
 * This header defines the stable C ABI for QIHSE that survives major version changes.
 * Once published, this ABI cannot be broken without a major version bump.
 *
 * Version: 1.0.0 (ABI Version 100)
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_ABI_H
#define QIHSE_ABI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ============================================================================
 * ABI VERSIONING
 * ============================================================================ */

#define QIHSE_ABI_VERSION 100  /* v1.0.0 */
#define QIHSE_ABI_VERSION_MAJOR 1
#define QIHSE_ABI_VERSION_MINOR 0
#define QIHSE_ABI_VERSION_PATCH 0

/* ============================================================================
 * ERROR CODES (ABI-STABLE)
 * ============================================================================ */

typedef enum qihse_error_e {
    QIHSE_OK = 0,

    /* General errors */
    QIHSE_ERROR_INVALID_ARGUMENT = -1,
    QIHSE_ERROR_OUT_OF_MEMORY = -2,
    QIHSE_ERROR_TIMEOUT = -4,
    QIHSE_ERROR_NOT_IMPLEMENTED = -5,
    QIHSE_ERROR_VERSION_MISMATCH = -6,

    /* Backend errors */
    QIHSE_ERROR_BACKEND_UNAVAILABLE = -10,
    QIHSE_ERROR_BACKEND_BUSY = -11,
    QIHSE_ERROR_BACKEND_INCOMPATIBLE = -12,

    /* Operation errors */
    QIHSE_ERROR_OPERATION_INVALID = -20,
    QIHSE_ERROR_OPERATION_UNSUPPORTED = -21,
    QIHSE_ERROR_OPERATION_FAILED = -22,

    /* Memory errors */
    QIHSE_ERROR_MEMORY_INVALID = -30,
    QIHSE_ERROR_MEMORY_INSUFFICIENT = -31,

    /* Verification errors */
    QIHSE_ERROR_VERIFICATION_FAILED = -40,
    QIHSE_ERROR_INTEGRITY_CHECK_FAILED = -41
} qihse_error_t;

/* ============================================================================
 * OPAQUE HANDLES (ABI-STABLE)
 * ============================================================================ */

typedef struct qihse_context* qihse_context_t;
typedef struct qihse_backend* qihse_backend_t;
typedef struct qihse_search_op* qihse_search_op_t;

/* ============================================================================
 * DATA TYPES (ABI-STABLE)
 * ============================================================================ */

typedef enum qihse_data_type_e {
    QIHSE_DATA_TYPE_FLOAT32 = 1,
    QIHSE_DATA_TYPE_FLOAT16 = 2,
    QIHSE_DATA_TYPE_INT32 = 3,
    QIHSE_DATA_TYPE_INT16 = 4,
    QIHSE_DATA_TYPE_INT8 = 5,
    QIHSE_DATA_TYPE_UINT32 = 6,
    QIHSE_DATA_TYPE_UINT16 = 7,
    QIHSE_DATA_TYPE_UINT8 = 8,
    QIHSE_DATA_TYPE_COMPLEX64 = 9,
    QIHSE_DATA_TYPE_COMPLEX32 = 10
} qihse_data_type_t;

typedef enum qihse_backend_type_e {
    QIHSE_BACKEND_CPU = 1,
    QIHSE_BACKEND_GPU_NVIDIA = 2,
    QIHSE_BACKEND_GPU_INTEL = 3,
    QIHSE_BACKEND_NPU = 4,
    QIHSE_BACKEND_HETEROGENEOUS = 5
} qihse_backend_type_t;

typedef enum qihse_memory_flags_e {
    QIHSE_MEMORY_HOST = (1 << 0),
    QIHSE_MEMORY_DEVICE = (1 << 1),
    QIHSE_MEMORY_PINNED = (1 << 2),
    QIHSE_MEMORY_ZERO_COPY = (1 << 3),
    QIHSE_MEMORY_READ_ONLY = (1 << 4),
    QIHSE_MEMORY_WRITE_ONLY = (1 << 5)
} qihse_memory_flags_t;

/* ============================================================================
 * BUFFER MANAGEMENT ABI (ABI-STABLE)
 * ============================================================================ */

typedef struct qihse_buffer_s {
    void* data;
    size_t size;
    qihse_data_type_t type;
    qihse_memory_flags_t flags;
    void* internal_handle;
} qihse_buffer_t;

qihse_error_t qihse_buffer_create(
    qihse_context_t ctx,
    size_t size,
    qihse_data_type_t type,
    qihse_memory_flags_t flags,
    qihse_buffer_t* buffer
);

void qihse_buffer_destroy(qihse_buffer_t* buffer);

qihse_error_t qihse_buffer_copy(
    qihse_buffer_t* dst,
    const qihse_buffer_t* src
);

/* ============================================================================
 * CONTEXT MANAGEMENT ABI (ABI-STABLE)
 * ============================================================================ */

qihse_error_t qihse_context_create(
    const char* config_path,
    qihse_context_t* ctx
);

void qihse_context_destroy(qihse_context_t ctx);



/* ============================================================================
 * SEARCH OPERATION ABI (ABI-STABLE)
 * ============================================================================ */

typedef enum qihse_search_op_type_e {
    QIHSE_SEARCH_OP_VECTOR_KNN = 1,
    QIHSE_SEARCH_OP_VECTOR_RANGE = 2,
    QIHSE_SEARCH_OP_GRAPH_BFS = 3,
    QIHSE_SEARCH_OP_GRAPH_SHORTEST_PATH = 4,
    QIHSE_SEARCH_OP_CONSTRAINT_OPTIMIZE = 5,
    QIHSE_SEARCH_OP_QUANTUM_ESTIMATE = 6
} qihse_search_op_type_t;

typedef enum qihse_metric_type_e {
    QIHSE_METRIC_L2 = 1,
    QIHSE_METRIC_COSINE = 2,
    QIHSE_METRIC_INNER_PRODUCT = 3,
    QIHSE_METRIC_HAMMING = 4
} qihse_metric_type_t;

typedef struct qihse_search_config_s {
    qihse_search_op_type_t op_type;
    qihse_metric_type_t metric;
    uint32_t k;
    float radius;
    uint32_t max_results;
    uint32_t timeout_ms;
    void* op_specific_config;
} qihse_search_config_t;

/**
 * Search result.
 */
typedef struct qihse_search_result_s {
    double confidence;                 /* Result confidence (0.0 to 1.0) */
    size_t data_size;                  /* Size of result data in bytes */
    void* data;                        /* Result data (owned by caller) */
} qihse_search_result_t;

typedef struct qihse_search_op_info_s {
    const char* name;
    qihse_search_op_type_t type;
    qihse_data_type_t input_type;
    qihse_data_type_t output_type;
    int supports_batching;
    int supports_quantization;
    uint32_t min_abi_version;
    uint32_t estimated_complexity;
} qihse_search_op_info_t;


/* ============================================================================
 * CONTEXT MANAGEMENT ABI (ABI-STABLE)
 * ============================================================================ */

qihse_error_t qihse_context_create(
    const char* config_path,
    qihse_context_t* ctx
);

void qihse_context_destroy(qihse_context_t ctx);

uint32_t qihse_get_abi_version(qihse_context_t ctx);


/* ============================================================================
 * VERSION COMPATIBILITY (ABI-STABLE)
 * ============================================================================ */

int qihse_check_abi_compatibility(uint32_t requested_version);

/* ============================================================================
 * UTILITY FUNCTIONS (ABI-STABLE)
 * ============================================================================ */

const char* qihse_error_string(qihse_error_t error);
const char* qihse_get_version_string(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_ABI_H */