/*
 * QIHSE - Plugin Architecture Interface
 *
 * This header defines the plugin interface for backend loading and management.
 * Plugins allow QIHSE to dynamically load compute backends at runtime.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_PLUGIN_H
#define QIHSE_PLUGIN_H

#include "qihse_abi.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * PLUGIN INFORMATION (ABI-STABLE)
 * ============================================================================ */

/**
 * Plugin information structure.
 * Describes plugin capabilities and requirements.
 */
typedef struct qihse_plugin_info_s {
    uint32_t abi_version;                /* Required ABI version */
    const char* name;                    /* Plugin name (unique identifier) */
    const char* description;             /* Human-readable description */
    const char* version;                 /* Plugin version string */
    qihse_backend_type_t backend_type;   /* Type of backend provided */
    uint32_t priority;                   /* Priority (0-100, higher = preferred) */
    uint64_t capability_flags;           /* Backend capability flags */
    const char* author;                  /* Plugin author */
    const char* license;                 /* Plugin license */
} qihse_plugin_info_t;

/* ============================================================================
 * PLUGIN LIFECYCLE FUNCTIONS (ABI-STABLE)
 * ============================================================================ */

/**
 * Plugin initialization function.
 * Called when plugin is loaded. Plugin should allocate and initialize backend.
 *
 * @param info Plugin information (from plugin)
 * @param backend Output backend handle
 * @return QIHSE_OK on success, error code otherwise
 */
typedef qihse_error_t (*qihse_plugin_init_fn)(
    const qihse_plugin_info_t* info,
    qihse_backend_t* backend
);

/**
 * Plugin shutdown function.
 * Called when plugin is unloaded. Plugin should clean up all resources.
 *
 * @param backend Backend to shut down
 */
typedef void (*qihse_plugin_shutdown_fn)(qihse_backend_t backend);

/* ============================================================================
 * PLUGIN CAPABILITY FUNCTIONS (ABI-STABLE)
 * ============================================================================ */

/**
 * Check if plugin supports a specific operation.
 *
 * @param backend Backend instance
 * @param op Operation to check
 * @return 1 if supported, 0 if not supported
 */
typedef int (*qihse_plugin_supports_op_fn)(
    qihse_backend_t backend,
    qihse_search_op_t op
);

/**
 * Get backend memory capacity.
 *
 * @param backend Backend instance
 * @param capacity_mb Output capacity in MB
 * @return QIHSE_OK on success, error code otherwise
 */
typedef qihse_error_t (*qihse_plugin_get_memory_capacity_fn)(
    qihse_backend_t backend,
    size_t* capacity_mb
);

/**
 * Get backend performance estimate.
 *
 * @param backend Backend instance
 * @param op Operation to estimate
 * @param input_size Input data size
 * @param throughput_ops_per_sec Output throughput estimate
 * @return QIHSE_OK on success, error code otherwise
 */
typedef qihse_error_t (*qihse_plugin_estimate_performance_fn)(
    qihse_backend_t backend,
    qihse_search_op_t op,
    size_t input_size,
    double* throughput_ops_per_sec
);

/* ============================================================================
 * PLUGIN REGISTRY (ABI-STABLE)
 * ============================================================================ */

/**
 * Plugin function table.
 * Contains all plugin entry points.
 */
typedef struct qihse_plugin_functions_s {
    qihse_plugin_init_fn init;
    qihse_plugin_shutdown_fn shutdown;
    qihse_plugin_supports_op_fn supports_op;
    qihse_plugin_get_memory_capacity_fn get_memory_capacity;
    qihse_plugin_estimate_performance_fn estimate_performance;
} qihse_plugin_functions_t;

/**
 * Complete plugin descriptor.
 * This is the main structure plugins export.
 */
typedef struct qihse_plugin_descriptor_s {
    qihse_plugin_info_t info;            /* Plugin information */
    qihse_plugin_functions_t functions;  /* Plugin functions */
} qihse_plugin_descriptor_t;

/* Alias for backward compatibility */
typedef qihse_plugin_descriptor_t qihse_plugin_t;

/* ============================================================================
 * PLUGIN LOADING API (ABI-STABLE)
 * ============================================================================ */

/**
 * Load a plugin from a shared library file.
 *
 * @param ctx QIHSE context
 * @param plugin_path Path to plugin shared library
 * @param backend Output backend handle
 * @return QIHSE_OK on success, error code otherwise
 */
qihse_error_t qihse_plugin_load_file(
    qihse_context_t ctx,
    const char* plugin_path,
    qihse_backend_t* backend
);

/**
 * Load all plugins from a directory.
 *
 * @param ctx QIHSE context
 * @param plugin_dir Directory containing plugin files
 * @return QIHSE_OK on success, error code otherwise
 */
qihse_error_t qihse_plugin_load_directory(
    qihse_context_t ctx,
    const char* plugin_dir
);

/**
 * Unload a plugin backend.
 *
 * @param backend Backend to unload
 * @return QIHSE_OK on success, error code otherwise
 */
qihse_error_t qihse_plugin_unload(qihse_backend_t backend);

/* ============================================================================
 * PLUGIN DISCOVERY API (ABI-STABLE)
 * ============================================================================ */

/**
 * Get plugin information without loading.
 *
 * @param plugin_path Path to plugin file
 * @param info Output plugin information
 * @return QIHSE_OK on success, error code otherwise
 */
qihse_error_t qihse_plugin_get_info(
    const char* plugin_path,
    qihse_plugin_info_t* info
);

/**
 * List available plugins in directory.
 *
 * @param plugin_dir Directory to scan
 * @param plugins Array to fill with plugin info
 * @param num_plugins Input: max plugins, Output: actual plugins
 * @return QIHSE_OK on success, error code otherwise
 */
qihse_error_t qihse_plugin_list_directory(
    const char* plugin_dir,
    qihse_plugin_info_t* plugins,
    size_t* num_plugins
);

/* ============================================================================
 * PLUGIN DEVELOPMENT HELPERS (ABI-STABLE)
 * ============================================================================ */

/**
 * Plugin export macro.
 * Use this to export plugin descriptor from shared library.
 */
#define QIHSE_PLUGIN_EXPORT(plugin_name) \
    QIHSE_PLUGIN_EXPORT_SYMBOL(qihse_plugin_descriptor_ ## plugin_name)

#define QIHSE_PLUGIN_EXPORT_SYMBOL(symbol) \
    extern qihse_plugin_descriptor_t symbol; \
    __attribute__((visibility("default"))) \
    qihse_plugin_descriptor_t* qihse_plugin_descriptor = &symbol;

/**
 * Plugin version compatibility check.
 */
#define QIHSE_PLUGIN_CHECK_ABI_VERSION(required_version) \
    if (QIHSE_ABI_VERSION < (required_version)) { \
        return QIHSE_ERROR_VERSION_MISMATCH; \
    }

/* ============================================================================
 * PLUGIN CAPABILITY FLAGS (ABI-STABLE)
 * ============================================================================ */

#define QIHSE_PLUGIN_CAP_FLOAT32     (1ULL << 0)
#define QIHSE_PLUGIN_CAP_FLOAT16     (1ULL << 1)
#define QIHSE_PLUGIN_CAP_INT32       (1ULL << 2)
#define QIHSE_PLUGIN_CAP_INT16       (1ULL << 3)
#define QIHSE_PLUGIN_CAP_INT8        (1ULL << 4)
#define QIHSE_PLUGIN_CAP_VECTOR_OPS  (1ULL << 5)
#define QIHSE_PLUGIN_CAP_MATRIX_OPS  (1ULL << 6)
#define QIHSE_PLUGIN_CAP_ASYNC_OPS   (1ULL << 7)
#define QIHSE_PLUGIN_CAP_QUANTIZATION (1ULL << 8)
#define QIHSE_PLUGIN_CAP_RFF         (1ULL << 9)
#define QIHSE_PLUGIN_CAP_SUPERPOSITION (1ULL << 10)
#define QIHSE_PLUGIN_CAP_AMPLIFICATION (1ULL << 11)
#define QIHSE_PLUGIN_CAP_SIMD_AVX2   (1ULL << 12)
#define QIHSE_PLUGIN_CAP_SIMD_AVX512 (1ULL << 13)
#define QIHSE_PLUGIN_CAP_SIMD_AMX    (1ULL << 14)
#define QIHSE_PLUGIN_CAP_SIMD_VNNI   (1ULL << 15)
#define QIHSE_PLUGIN_CAP_GPU_CUDA    (1ULL << 16)
#define QIHSE_PLUGIN_CAP_GPU_SYCL    (1ULL << 17)
#define QIHSE_PLUGIN_CAP_NPU_OPENVINO (1ULL << 18)

/* ============================================================================
 * PLUGIN DEVELOPMENT TEMPLATE
 * ============================================================================ */

/**
 * Template for implementing a QIHSE plugin.
 *
 * To create a plugin:
 * 1. Implement the plugin descriptor
 * 2. Implement the required functions
 * 3. Export using QIHSE_PLUGIN_EXPORT
 *
 * Example:
 *
 * static qihse_plugin_descriptor_t my_plugin = {
 *     .info = {
 *         .abi_version = QIHSE_ABI_VERSION,
 *         .name = "my_backend",
 *         .description = "My custom backend",
 *         .version = "1.0.0",
 *         .backend_type = QIHSE_BACKEND_CPU,
 *         .priority = 50,
 *         .capability_flags = QIHSE_PLUGIN_CAP_FLOAT32 | QIHSE_PLUGIN_CAP_VECTOR_OPS,
 *         .author = "My Organization",
 *         .license = "MIT"
 *     },
 *     .functions = {
 *         .init = my_plugin_init,
 *         .shutdown = my_plugin_shutdown,
 *         .supports_op = my_plugin_supports_op,
 *         .get_memory_capacity = my_plugin_get_memory_capacity,
 *         .estimate_performance = my_plugin_estimate_performance
 *     }
 * };
 *
 * QIHSE_PLUGIN_EXPORT(my_plugin)
 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_PLUGIN_H */
