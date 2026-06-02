/*
 * QIHSE - Heterogeneous Compute Pool
 *
 * Unified device abstraction and orchestration for heterogeneous computing.
 * Integrates CPU SIMD, NPU, GPU, and other accelerators through Phase 0 ABI.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_HETERO_H
#define QIHSE_HETERO_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "../../core/qihse_abi.h"  /* Phase 0 ABI */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * DEVICE TYPES AND CAPABILITIES
 * ============================================================================ */

/**
 * Device types supported by the heterogeneous pool.
 */
typedef enum qihse_device_type_e {
    QIHSE_DEVICE_CPU_AVX2 = 1,      /* CPU with AVX2 SIMD */
    QIHSE_DEVICE_CPU_AVX512 = 2,    /* CPU with AVX-512 SIMD */
    QIHSE_DEVICE_CPU_AMX = 3,       /* CPU with AMX instructions */
    QIHSE_DEVICE_NPU = 4,           /* Neural Processing Unit */
    QIHSE_DEVICE_GPU = 5,           /* Graphics Processing Unit */
    QIHSE_DEVICE_MAX = 6
} qihse_device_type_t;

/**
 * Device capabilities bitfield.
 */
typedef enum qihse_device_caps_e {
    QIHSE_CAPS_SIMD_AVX2 = (1 << 0),    /* AVX2 SIMD support */
    QIHSE_CAPS_SIMD_AVX512 = (1 << 1),  /* AVX-512 SIMD support */
    QIHSE_CAPS_AMX = (1 << 2),          /* AMX matrix operations */
    QIHSE_CAPS_VNNI = (1 << 3),         /* VNNI instructions */
    QIHSE_CAPS_FP16 = (1 << 4),         /* FP16 support */
    QIHSE_CAPS_INT8 = (1 << 5),         /* INT8 quantization */
    QIHSE_CAPS_TENSOR = (1 << 6),       /* Tensor operations */
    QIHSE_CAPS_ASYNC = (1 << 7),        /* Asynchronous execution */
    QIHSE_CAPS_UNIFIED_MEM = (1 << 8),  /* Unified memory support */
} qihse_device_caps_t;

/* ============================================================================
 * DEVICE ABSTRACTION
 * ============================================================================ */

/**
 * Device information structure.
 */
typedef struct qihse_device_info_s {
    qihse_device_type_t type;        /* Device type */
    const char* name;                /* Human-readable name */
    const char* description;         /* Device description */
    uint64_t capabilities;           /* Bitfield of capabilities */
    size_t max_memory_mb;            /* Maximum memory capacity (MB) */
    size_t compute_units;            /* Number of compute units */
    double peak_performance_gflops;  /* Peak performance in GFLOPS */
    bool supports_async;             /* Asynchronous execution support */
} qihse_device_info_t;

/**
 * Device handle - opaque pointer to device implementation.
 */
typedef struct qihse_device_s* qihse_device_t;

/**
 * Work batch for heterogeneous execution.
 */
typedef struct qihse_work_batch_s {
    size_t num_operations;           /* Number of operations in batch */
    qihse_search_op_t* operations;   /* Array of search operations */
    qihse_buffer_t** inputs;         /* Input buffers for each operation */
    size_t* num_inputs;              /* Number of inputs per operation */
    qihse_buffer_t** outputs;        /* Output buffers for each operation */
    size_t* num_outputs;             /* Number of outputs per operation */
    const qihse_search_config_t* config; /* Search configuration */
} qihse_work_batch_t;

/* ============================================================================
 * HETEROGENEOUS POOL MANAGEMENT
 * ============================================================================ */

/**
 * Heterogeneous compute pool.
 */
typedef struct qihse_hetero_pool_s* qihse_hetero_pool_t;

/**
 * Create heterogeneous compute pool.
 *
 * @param ctx QIHSE context (Phase 0 ABI)
 * @return Pool handle, or NULL on failure
 */
qihse_hetero_pool_t qihse_hetero_pool_create(qihse_context_t ctx);

/**
 * Destroy heterogeneous compute pool.
 *
 * @param pool Pool to destroy
 */
void qihse_hetero_pool_destroy(qihse_hetero_pool_t pool);

/**
 * Register a device backend in the pool.
 *
 * @param pool Heterogeneous pool
 * @param device_type Type of device to register
 * @param device Device handle from backend
 * @param info Device information
 * @return 0 on success, negative error code on failure
 */
int qihse_hetero_pool_register_device(
    qihse_hetero_pool_t pool,
    qihse_device_type_t device_type,
    qihse_backend_t device,
    const qihse_device_info_t* info
);

/**
 * Get number of registered devices.
 *
 * @param pool Heterogeneous pool
 * @return Number of devices
 */
size_t qihse_hetero_pool_get_device_count(qihse_hetero_pool_t pool);

/**
 * Get device information by index.
 *
 * @param pool Heterogeneous pool
 * @param index Device index (0 to count-1)
 * @param info Output device information
 * @return 0 on success, negative error code on failure
 */
int qihse_hetero_pool_get_device_info(
    qihse_hetero_pool_t pool,
    size_t index,
    qihse_device_info_t* info
);

/* ============================================================================
 * WORK PARTITIONING AND ORCHESTRATION
 * ============================================================================ */

/**
 * Partition work across heterogeneous devices.
 *
 * @param pool Heterogeneous pool
 * @param batch Work batch to partition
 * @param partitions Output array of device assignments (size = batch->num_operations)
 * @return 0 on success, negative error code on failure
 */
int qihse_hetero_pool_partition_work(
    qihse_hetero_pool_t pool,
    const qihse_work_batch_t* batch,
    qihse_device_type_t* partitions
);

/**
 * Execute work batch across heterogeneous devices.
 *
 * @param pool Heterogeneous pool
 * @param batch Work batch to execute
 * @return 0 on success, negative error code on failure
 */
int qihse_hetero_pool_execute_batch(
    qihse_hetero_pool_t pool,
    qihse_work_batch_t* batch
);

/**
 * Calibrate device performance for optimal partitioning.
 *
 * @param pool Heterogeneous pool
 * @return 0 on success, negative error code on failure
 */
int qihse_hetero_pool_calibrate_devices(qihse_hetero_pool_t pool);

/* ============================================================================
 * PERFORMANCE MONITORING
 * ============================================================================ */

/**
 * Device performance metrics.
 */
typedef struct qihse_device_metrics_s {
    double throughput_gops;          /* Operations per second */
    double latency_ms;               /* Average latency in milliseconds */
    double memory_bandwidth_gbps;    /* Memory bandwidth in GB/s */
    size_t memory_used_mb;           /* Current memory usage */
    double utilization_percent;      /* Device utilization percentage */
    size_t operations_completed;     /* Total operations completed */
} qihse_device_metrics_t;

/**
 * Get performance metrics for a device.
 *
 * @param pool Heterogeneous pool
 * @param device_type Device type
 * @param metrics Output performance metrics
 * @return 0 on success, negative error code on failure
 */
int qihse_hetero_pool_get_device_metrics(
    qihse_hetero_pool_t pool,
    qihse_device_type_t device_type,
    qihse_device_metrics_t* metrics
);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Get string representation of device type.
 *
 * @param type Device type
 * @return String representation
 */
const char* qihse_device_type_string(qihse_device_type_t type);

/**
 * Check if device type supports specific capability.
 *
 * @param type Device type
 * @param cap Capability to check
 * @return true if supported, false otherwise
 */
bool qihse_device_type_supports_cap(qihse_device_type_t type, qihse_device_caps_t cap);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_HETERO_H */
