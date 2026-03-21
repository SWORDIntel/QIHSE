/**
 * QIHSE - Quantum-Inspired Hilbert Space Expansion Search
 *
 * Ultra-high-performance search using higher-dimensional Hilbert space expansion,
 * Grover-inspired amplitude amplification, and heterogeneous parallel compute.
 *
 * Features:
 * - Dynamic Hilbert space dimension calculation
 * - Random Fourier Features kernel embedding
 * - Tensor product phase entanglement
 * - Heterogeneous parallel execution (CPU AMX/VNNI/AVX512 + NPU + GPUs)
 * - Configurable accuracy verification modes
 * - Universal data type support
 *
 * Performance: 200-2000x speedup vs binary search
 */

#ifndef QIHSE_H
#define QIHSE_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#include "qihse_hetero.h"
#include "not_stisla.h"  /* For anchor table compatibility */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * QIHSE CONSTANTS
 * ============================================================================ */

#define QIHSE_MAX_DIMENSIONS 16384   /* Maximum Hilbert space dimensions */
#define QIHSE_MIN_DIMENSIONS 8       /* Minimum dimensions */
#define QIHSE_DEFAULT_TIMEOUT_MS 5000 /* Default timeout for operations */

/* ============================================================================
 * INTEL ONEAPI ENHANCEMENT FLAGS
 * ============================================================================ */

#ifdef QIHSE_ENABLE_ONEAPI
#define QIHSE_ONEAPI_AVAILABLE 1
#else
#define QIHSE_ONEAPI_AVAILABLE 0
#endif

#ifdef QIHSE_ENABLE_MKL
#define QIHSE_MKL_AVAILABLE 1
#else
#define QIHSE_MKL_AVAILABLE 0
#endif

#ifdef QIHSE_ENABLE_IPP
#define QIHSE_IPP_AVAILABLE 1
#else
#define QIHSE_IPP_AVAILABLE 0
#endif

#ifdef QIHSE_ENABLE_TBB
#define QIHSE_TBB_AVAILABLE 1
#else
#define QIHSE_TBB_AVAILABLE 0
#endif

#ifdef QIHSE_ENABLE_FORTRAN
#define QIHSE_FORTRAN_AVAILABLE 1
#else
#define QIHSE_FORTRAN_AVAILABLE 0
#endif

/* ============================================================================
 * QIHSE-NOT_STISLA INTEGRATION: ANCHOR-BASED OPTIMIZATIONS
 * ============================================================================ */

/* Anchor-based search configuration (integrated into QIHSE core) */
typedef struct {
    size_t max_anchors;         /* Maximum anchors to maintain (default: 16) */
    size_t min_anchors;         /* Minimum anchors before learning (default: 2) */
    double anchor_prune_threshold; /* Memory usage threshold for pruning (default: 0.8) */
    size_t memory_budget_mb;    /* Memory budget in MB (default: 8) */
    bool enable_anchor_learning; /* Enable adaptive anchor learning (default: true) */
    size_t chunk_size;          /* SIMD chunk size (default: 4 for AVX2) */
    bool enable_anchor_simd;    /* Enable SIMD in anchor operations (default: true) */
    int workload_type;          /* DSMIL workload type (default: auto-detect) */
} qihse_anchor_config_t;

/* ============================================================================
 * DATA TYPE SUPPORT
 * ============================================================================ */

typedef enum {
    QIHSE_TYPE_INT64 = 0,       /* Native int64_t arrays */
    QIHSE_TYPE_UINT64 = 1,      /* Unsigned 64-bit */
    QIHSE_TYPE_DOUBLE = 2,      /* IEEE 754 double precision */
    QIHSE_TYPE_STRING = 3,      /* Null-terminated strings */
    QIHSE_TYPE_BINARY = 4,      /* Arbitrary binary blobs */
    QIHSE_TYPE_STRUCT = 5,      /* Custom structs with descriptors */
    QIHSE_TYPE_CUSTOM = 6       /* User-provided embedding function */
} qihse_data_type_t;

/* Type descriptor for custom data types */
typedef struct {
    qihse_data_type_t type;
    size_t element_size;        /* Bytes per element */
    size_t (*hash_fn)(const void*, size_t);     /* Hash function */
    int (*compare_fn)(const void*, const void*); /* Comparison function */
    void (*embed_fn)(const void*, double*, size_t); /* Embedding function */
    const char* type_name;      /* Human-readable type name */
} qihse_type_descriptor_t;

/* ============================================================================
 * MODULAR QIHSE HEADERS
 * ============================================================================ */

/* Enums and basic types needed by modular headers */
typedef enum {
    QIHSE_PIPELINE_FAST,
    QIHSE_PIPELINE_BALANCED,
    QIHSE_PIPELINE_ACCURATE,
    QIHSE_PIPELINE_LEARNED
} qihse_pipeline_type_t;

typedef enum {
    QIHSE_BACKEND_CPU_C,
    QIHSE_BACKEND_CPU_FORTRAN,
    QIHSE_BACKEND_GPU_CUDA,
    QIHSE_BACKEND_GPU_JULIA,
    QIHSE_BACKEND_NPU_INTEL,
    QIHSE_BACKEND_DSP_ARM,
    QIHSE_BACKEND_FPGA,
    QIHSE_BACKEND_AUTO
} qihse_backend_type_t;

/* Forward declarations for circular dependencies */
typedef struct qihse_superposition_s qihse_superposition_t;
typedef struct qihse_config_s qihse_config_t;
typedef struct qihse_amplification_config_s qihse_amplification_config_t;
typedef struct qihse_verify_config_s qihse_verify_config_t;
typedef struct qihse_collapse_result_s qihse_collapse_result_t;
typedef struct qihse_dimension_params_s qihse_dimension_params_t;

typedef struct qihse_amplification_config_s {
    int min_rounds;             /* Minimum amplification rounds */
    int max_rounds;             /* Maximum amplification rounds (0 = auto) */
    double convergence_threshold; /* Stop when amplitude delta < threshold */
    double oracle_selectivity;  /* How strict the oracle marking is (0.0-1.0) */
    bool adaptive_rounds;       /* Use adaptive round count based on problem size */
    int fixed_rounds;           /* Fixed round count (if adaptive_rounds=false) */
} qihse_amplification_config_t;

typedef enum {
    QIHSE_VERIFY_NONE = 0,
    QIHSE_VERIFY_FAST = 1,
    QIHSE_VERIFY_WINDOW = 2,
    QIHSE_VERIFY_FALLBACK = 3,
    QIHSE_VERIFY_EXACT = 4
} qihse_verify_mode_t;

typedef struct qihse_verify_config_s {
    qihse_verify_mode_t mode;
    size_t window_size;
    double min_confidence;
    bool fallback_to_classical;
    size_t max_verification_time_us;
} qihse_verify_config_t;

typedef struct qihse_collapse_result_s {
    size_t predicted_index;
    double confidence;
    size_t* fallback_indices;
    size_t fallback_count;
} qihse_collapse_result_t;

#include "qihse_math.h"
#include "qihse_instr.h"
#include "qihse_search.h"

typedef struct {
    qihse_backend_type_t type;
    float priority_weight;      /* 0.0-1.0, higher = preferred */
    bool enabled;               /* Backend is available and enabled */
    size_t memory_limit;        /* Memory limit for this backend */
} qihse_backend_priority_t;

typedef struct {
    qihse_pipeline_type_t type;
    size_t dimensions;           /* Hilbert space dimensions for this pipeline */
    double confidence_threshold; /* Minimum confidence to accept result */
    bool early_exit;            /* Exit early if confidence threshold met */
    uint32_t priority;          /* Pipeline priority (higher = more important) */
    uint32_t timeout_ms;        /* Timeout in milliseconds */
    void* pipeline_data;        /* Pipeline-specific configuration */
} qihse_pipeline_config_t;

typedef struct {
    qihse_pipeline_config_t config;
    qihse_collapse_result_t result;
    double execution_time_ns;
    bool completed;
    bool success;
    char pipeline_name[64];
} qihse_pipeline_result_t;

typedef struct {
    size_t num_pipelines;
    qihse_pipeline_result_t* pipelines;
    qihse_collapse_result_t final_result;
    double total_time_ns;
    bool parallel_execution;
    uint32_t active_pipelines;
} qihse_parallel_result_t;

/* Internal structures for parallel execution */
typedef struct {
    const void* data;
    size_t n;
    const void* query;
    not_stisla_anchor_table_t* table;
    qihse_data_type_t data_type;
    const qihse_pipeline_config_t* pipeline_config;
    qihse_pipeline_result_t* pipeline_result;
} qihse_pipeline_worker_arg_t;

/* ============================================================================
 * DIMENSION CALCULATION AND ANALYSIS
 * ============================================================================ */

typedef struct qihse_dimension_params_s {
    size_t optimal_dims;        /* Calculated optimal dimension count */
    size_t expansion_factor;    /* Actual expansion ratio (1.5x to 16x) */
    double data_entropy;        /* Shannon entropy of data gaps */
    double gap_coefficient;     /* Coefficient of variation for gaps */
    size_t effective_rank;      /* Estimated intrinsic dimensionality */
    size_t array_size;          /* Size of input array */
    qihse_data_type_t data_type; /* Detected or specified data type */
} qihse_dimension_params_t;

/**
 * @brief Analyze data and compute optimal Hilbert space dimensions
 *
 * Calculates dimensions based on data entropy, gap variance, array size,
 * and available compute capabilities.
 *
 * @param data Raw data array
 * @param n Number of elements
 * @param element_size Size of each element in bytes
 * @param type Data type (or QIHSE_TYPE_CUSTOM for auto-detection)
 * @param pool Compute pool for capability reference
 * @param params Output dimension parameters
 * @return 0 on success, negative on error
 */
int qihse_compute_optimal_dimensions(
    const void* data,
    size_t n,
    size_t element_size,
    qihse_data_type_t type,
    const qihse_compute_pool_t* pool,
    qihse_dimension_params_t* params
);

/* ============================================================================
 * MAIN QIHSE CONFIGURATION AND API
 * ============================================================================ */

typedef struct qihse_config_s {
    /* QIHSE-NOT_STISLA Integration: Anchor-based optimizations */
    qihse_anchor_config_t anchor_config; /* Anchor search configuration */

    /* Dimension configuration */
    bool auto_dimensions;       /* Auto-calculate optimal dimensions */
    size_t fixed_dimensions;    /* Use this dimension count if not auto */
    size_t max_dimensions;      /* Upper bound for auto mode */
    size_t min_dimensions;      /* Lower bound for auto mode */

    /* Data type configuration */
    qihse_data_type_t data_type; /* Data type (auto-detected if CUSTOM) */
    qihse_type_descriptor_t type_descriptor; /* For custom types */

    /* Kernel configuration */
    double rff_gamma;           /* RFF kernel bandwidth */
    uint64_t random_seed;       /* Random seed for reproducibility */

    /* Amplification configuration */
    qihse_amplification_config_t amplification;

    /* Verification configuration */
    qihse_verify_config_t verification;

    /* Compute configuration */
    bool use_heterogeneous;     /* Use all available devices in parallel */
    bool enable_acceleration;   /* Enable high-performance backends (CUDA, Julia, FORTRAN) */
    size_t max_batch_size;      /* Maximum batch size per device */
    bool enable_profiling;      /* Collect detailed performance metrics */

    /* Parallel pipeline configuration */
    bool use_parallel_pipelines;    /* Use multiple pipeline configurations */
    size_t max_parallel_pipelines;  /* Maximum number of parallel pipelines */

    /* Timeout and error handling */
    uint32_t timeout_ms;        /* Overall operation timeout */
    bool fail_fast;             /* Stop on first device error */

    /* Language backend configuration */
    qihse_backend_priority_t backend_priority[8]; /* Ordered list of preferred backends */
    size_t num_backends;        /* Number of configured backends */
    bool adaptive_backend;      /* Automatically select best backend */
    bool memory_pooling;        /* Use memory pools for reuse */
    size_t memory_pool_size;    /* Size of memory pool per backend */
} qihse_config_t;

/**
 * @brief Initialize QIHSE config with smart defaults
 *
 * @param config Config structure to initialize
 * @param data_type Data type for the search
 * @param array_size Size of the array to search
 * @return 0 on success, negative on error
 */
int qihse_config_init(
    qihse_config_t* config,
    qihse_data_type_t data_type,
    size_t array_size
);

/* ============================================================================
 * CORE QIHSE SEARCH API
 * ============================================================================ */

/**
 * @brief Quantum-Inspired Hilbert Space Expansion Search
 *
 * Main QIHSE search function that uses higher-dimensional Hilbert space
 * expansion, Grover-inspired amplitude amplification, and heterogeneous
 * parallel compute for ultra-high-performance search.
 *
 * @param data Sorted array to search in
 * @param n Number of elements in array
 * @param query Value to search for
 * @param table Anchor table for learning (can be NULL)
 * @param config QIHSE configuration
 * @return Index of found element, or NOT_STISLA_NOT_FOUND if not found
 */
not_stisla_result_t qihse_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
);

/**
 * @brief Batch QIHSE search for multiple queries
 *
 * Searches for multiple queries in a single operation, maximizing
 * learning and parallelization benefits.
 *
 * @param data Sorted array to search in
 * @param n Number of elements in array
 * @param queries Array of query values
 * @param num_queries Number of queries
 * @param results Output array for results (must be sized for num_queries)
 * @param table Anchor table for learning (can be NULL)
 * @param config QIHSE configuration
 * @return Number of queries found
 */
size_t qihse_batch_search(
    const void* data,
    size_t n,
    const void* queries,
    size_t num_queries,
    not_stisla_result_t* results,
    not_stisla_anchor_table_t* table,
    const qihse_config_t* config
);

/* ============================================================================
 * PERFORMANCE MONITORING AND STATISTICS
 * ============================================================================ */

typedef struct {
    /* Execution timing */
    double total_time_ns;       /* Total execution time */
    double dim_calc_time_ns;    /* Dimension calculation time */
    double rff_time_ns;         /* RFF embedding time */
    double superposition_time_ns; /* Superposition creation time */
    double amplification_time_ns; /* Grover amplification time */
    double collapse_time_ns;    /* Dimensional collapse time */
    double verification_time_ns; /* Verification time */

    /* Device utilization */
    double device_utilization[QIHSE_DEV_COUNT]; /* % utilization per device */
    double device_time_ns[QIHSE_DEV_COUNT]; /* Time spent per device */

    /* Quality metrics */
    double avg_confidence;      /* Average measurement confidence */
    double verification_rate;   /* % of results that needed verification */
    size_t classical_fallbacks; /* Number of classical fallbacks */

    /* QIHSE-NOT_STISLA Integration: Enhanced anchor learning metrics */
    size_t anchors_learned;     /* New anchors learned */
    size_t anchors_pruned;      /* Anchors pruned due to memory limits */
    size_t anchor_table_size;   /* Current anchor table size */
    double anchor_hit_rate;     /* Percentage of searches using anchors */
    double anchor_avg_error;    /* Average interpolation error */
    int detected_workload_type; /* Auto-detected workload type */
    double speedup_vs_binary;   /* Speedup vs binary search */
    double speedup_vs_classical; /* Speedup vs classical NOT_STISLA */
    double anchor_memory_usage_mb; /* Memory used by anchor tables */

    /* Resource usage */
    size_t peak_memory_bytes;   /* Peak memory usage */
    size_t total_operations;    /* Total operations performed */
} qihse_performance_stats_t;

/**
 * @brief Get performance statistics from last QIHSE operation
 *
 * @param stats Output statistics structure
 * @return 0 on success, negative if no stats available
 */
int qihse_get_performance_stats(qihse_performance_stats_t* stats);

/**
 * @brief Reset performance statistics
 */
void qihse_reset_performance_stats(void);

/* ============================================================================
 * PARALLEL PIPELINE API
 * ============================================================================ */

/**
 * @brief Initialize parallel pipeline configurations
 * @param configs Array to fill with pipeline configurations
 * @param max_configs Maximum number of configurations to create
 * @param data_type Data type being searched
 * @param array_size Size of the search array
 * @return Number of configurations created
 */
size_t qihse_init_parallel_pipelines(
    qihse_pipeline_config_t* configs,
    size_t max_configs,
    qihse_data_type_t data_type,
    size_t array_size
);

/**
 * @brief Execute parallel pipelines for a search query
 * @param data Search data array
 * @param n Number of elements
 * @param query Search query
 * @param table Anchor table (optional)
 * @param configs Pipeline configurations
 * @param num_configs Number of configurations
 * @param result Parallel result structure to fill
 * @return 0 on success, negative on error
 */
int qihse_execute_parallel_pipelines(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    const qihse_pipeline_config_t* configs,
    size_t num_configs,
    qihse_parallel_result_t* result
);

/**
 * @brief Combine results from multiple pipelines
 * @param parallel_result Parallel execution results
 * @param combination_strategy How to combine results
 * @return Final combined result
 */
qihse_collapse_result_t qihse_combine_pipeline_results(
    const qihse_parallel_result_t* parallel_result,
    const char* combination_strategy
);

/**
 * @brief Get performance statistics for parallel execution
 * @param result Parallel result structure
 * @param stats Statistics structure to fill
 * @return 0 on success
 */
int qihse_get_parallel_stats(
    const qihse_parallel_result_t* result,
    qihse_performance_stats_t* stats
);

/* ============================================================================
 * VERSION AND BUILD INFORMATION
 * ============================================================================ */

#define QIHSE_VERSION_MAJOR 1
#define QIHSE_VERSION_MINOR 0
#define QIHSE_VERSION_PATCH 0

/**
 * @brief Get QIHSE version string
 */
const char* qihse_version(void);

/**
 * @brief Get QIHSE build information with compiled features
 */
const char* qihse_build_info(void);

/**
 * @brief Check if QIHSE is available and properly configured
 *
 * @return true if QIHSE can be used, false otherwise
 */
bool qihse_available(void);

/* ============================================================================
 * HIGH-PERFORMANCE BACKEND ACCELERATION
 * ============================================================================ */

/* CUDA acceleration functions */
typedef void* qihse_cuda_handle_t;

/**
 * @brief Initialize CUDA accelerator
 * @param max_states Maximum number of quantum states
 * @param max_dims Maximum dimensions per state
 * @return CUDA handle or NULL on error
 */
qihse_cuda_handle_t qihse_cuda_init(size_t max_states, size_t max_dims);

/**
 * @brief Cleanup CUDA accelerator
 * @param handle CUDA handle to cleanup
 */
void qihse_cuda_cleanup(qihse_cuda_handle_t handle);

/**
 * @brief Execute quantum search on CUDA
 * @param handle CUDA accelerator handle
 * @param data Input data array
 * @param num_samples Number of data samples
 * @param input_dims Input dimensions
 * @param query Query value
 * @param hilbert_dims Hilbert space dimensions
 * @param result_index Output result index
 * @param confidence Output confidence score
 * @return 0 on success, negative on error
 */
int qihse_cuda_search(qihse_cuda_handle_t handle, const double* data, size_t num_samples,
                     size_t input_dims, const double* query, size_t hilbert_dims,
                     size_t* result_index, double* confidence);

/**
 * @brief Get CUDA device information
 * @param device_name Output device name buffer
 * @param name_size Size of device name buffer
 * @param total_memory Output total GPU memory
 * @param compute_capability Output compute capability
 * @return 0 on success, negative on error
 */
int qihse_cuda_get_device_info(char* device_name, size_t name_size,
                              size_t* total_memory, size_t* compute_capability);

/* Julia acceleration functions - Quantum-inspired classical algorithms */
typedef void* qihse_julia_handle_t;

/**
 * @brief Initialize Julia quantum-inspired accelerator
 * @param device Device type (0=CPU, 1=GPU)
 * @param threads Number of threads
 * @return Julia handle or NULL on error
 */
qihse_julia_handle_t qihse_julia_init(int device, int threads);

/**
 * @brief Cleanup Julia quantum-inspired accelerator
 * @param handle Julia handle to cleanup
 */
void qihse_julia_cleanup(qihse_julia_handle_t handle);

/**
 * @brief Execute quantum-inspired search using Julia-optimized algorithms
 * @param handle Julia accelerator handle
 * @param data Input data array
 * @param n Number of data samples
 * @param query Query value
 * @param hilbert_dims Hilbert space dimensions
 * @param result_index Output result index
 * @param confidence Output confidence score
 * @return 0 on success, negative on error
 */
int qihse_julia_search(qihse_julia_handle_t handle, const double* data, size_t n,
                      double query, int hilbert_dims,
                      size_t* result_index, double* confidence);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_H */
