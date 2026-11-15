/**
 * QIHSE - Quantum-Inspired Hilbert Space Expansion Search
 *
 * Scalar exact lookup with Random Fourier Feature candidate scoring, plus
 * experimental mathematical and heterogeneous-compute interfaces.
 *
 * Features:
 * - Dynamic Hilbert space dimension calculation
 * - Random Fourier Features kernel embedding
 * - Bounded-memory, query-dependent candidate scoring
 * - Configurable accuracy verification modes
 * - Descriptor-based equality for fixed-width records
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
#include "qihse_math_types.h"
#include "qihse_hetero.h"
#include "qihse_anchor_search.h"  /* Native QIHSE anchor-search compatibility */

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
 * QIHSE NATIVE ANCHOR-BASED OPTIMIZATIONS
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

typedef struct qihse_verify_config_s {
    qihse_verify_mode_t mode;
    size_t window_size;
    double min_confidence;
    bool fallback_to_classical;
    size_t max_verification_time_us; /* Reserved; exact verification is not truncated */
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
    size_t expansion_factor;    /* Output dimensions per scalar input */
    double data_entropy;        /* NAN when the selector has not measured it */
    double gap_coefficient;     /* NAN when the selector has not measured it */
    size_t effective_rank;      /* 0 when intrinsic rank has not been measured */
    size_t array_size;          /* Size of input array */
    qihse_data_type_t data_type; /* Detected or specified data type */
} qihse_dimension_params_t;

/**
 * @brief Analyze data and compute optimal Hilbert space dimensions
 *
 * Uses a bounded size-based heuristic. Unmeasured distribution statistics are
 * reported as NAN (rank as 0), rather than inferred from the element count.
 *
 * @param data Raw data array
 * @param n Number of elements
 * @param element_size Size of each element in bytes
 * @param type Data type (or QIHSE_TYPE_CUSTOM for auto-detection)
 * @param pool Optional reserved compute-capability hint
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
    /* QIHSE native anchor-based optimizations */
    qihse_anchor_config_t anchor_config; /* Anchor search configuration */

    /* Dimension configuration */
    bool auto_dimensions;       /* Auto-calculate optimal dimensions */
    size_t fixed_dimensions;    /* Use this dimension count if not auto */
    size_t max_dimensions;      /* Upper bound for auto mode */
    size_t min_dimensions;      /* Lower bound for auto mode */

    /* Data type configuration */
    qihse_data_type_t data_type; /* CUSTOM requires an explicit comparator */
    qihse_type_descriptor_t type_descriptor; /* For custom types */

    /* Kernel configuration */
    double rff_gamma;           /* RFF kernel bandwidth */
    uint64_t random_seed;       /* Random seed for reproducibility */

    /* Amplification configuration */
    qihse_amplification_config_t amplification;

    /* Verification configuration */
    qihse_verify_config_t verification;

    /* Compute configuration */
    bool use_heterogeneous;     /* Reserved by scalar qihse_search; separate orchestration APIs */
    bool enable_acceleration;   /* Reserved by scalar qihse_search; explicit backend APIs */
    size_t max_batch_size;      /* Maximum batch size per device */
    bool enable_profiling;      /* Collect detailed performance metrics */

    /* Parallel pipeline configuration */
    bool use_parallel_pipelines;    /* Use multiple pipeline configurations */
    size_t max_parallel_pipelines;  /* Maximum number of parallel pipelines */

    /* Timeout and error handling */
    uint32_t timeout_ms;        /* Reserved by scalar qihse_search; no deadline enforcement */
    bool fail_fast;             /* Reserved by scalar qihse_search */

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

#define QIHSE_SEARCH_OPTIONS_VERSION 1u
#define QIHSE_SEARCH_MAX_TILE_SIZE 64u

typedef enum {
    QIHSE_SEARCH_EXACT = 0,
    QIHSE_SEARCH_RFF_COSINE = 1,
    QIHSE_SEARCH_RFF_PAIRED = 2
} qihse_search_method_t;

/* Additive options: existing qihse_config_t and kernel layouts are unchanged. */
typedef struct {
    size_t struct_size;
    uint32_t version;
    qihse_search_method_t method;
    size_t tile_size; /* 1..64 queries sharing each streamed row projection */
} qihse_search_options_t;

/* Per-call measurements, independent of the legacy global last-operation stats.
 * Projection counts include successful projections only; failures are separate.
 * Scratch counts owned heap allocations, excluding inputs, outputs and stack.
 * Timings include instrumentation overhead; intervals with failed clock reads
 * contribute zero. Counters saturate at SIZE_MAX when necessary. */
typedef struct {
    size_t struct_size;
    uint32_t version;
    qihse_search_method_t method;
    size_t dimensions;
    size_t tile_size;
    size_t queries;
    size_t matches;
    size_t candidate_hits;
    size_t fallback_queries; /* Window/full scans after a candidate did not match */
    size_t fallback_hits;
    size_t direct_queries; /* Explicit EXACT method */
    size_t unprojected_queries; /* RFF query had no usable numeric features */
    size_t query_projections;
    size_t row_projections;
    size_t projection_failures;
    size_t comparisons; /* Actual original-record equality comparisons */
    size_t kernel_builds;
    size_t tiles; /* Tiles containing at least one successfully projected query */
    size_t peak_scratch_bytes;
    double setup_time_ns;
    double scoring_time_ns;
    double verification_time_ns;
    double total_time_ns;
} qihse_search_metrics_t;

/* Initialize with the caller's sizeof(object). Undersized buffers are rejected
 * without writes. Defaults are cosine RFF and tile_size=16. */
int qihse_search_options_init(qihse_search_options_t* options, size_t bytes);
int qihse_search_metrics_init(qihse_search_metrics_t* metrics, size_t bytes);

/* Status-returning variants: 0 includes an ordinary absent result; -1 sets errno
 * for invalid arguments/resources. NULL options selects defaults; NULL metrics
 * disables per-call reporting. Initialize supplied metrics before first use.
 * EXACT ignores projection settings and always performs typed equality lookup.
 * PAIRED requires an even resolved output dimension. A batch constructs one
 * basis and shares each row projection within a tile; tile_size=1 is streaming.
 * Valid output arrays are filled with NOT_FOUND before resource allocation, so
 * allocation failure cannot leave a partially completed batch. Argument errors
 * need not modify outputs. Input and output buffers must not overlap. */
int qihse_search_ex(const void* data, size_t n, const void* query,
    not_stisla_anchor_table_t* table, const qihse_config_t* config,
    const qihse_search_options_t* options, not_stisla_result_t* result,
    qihse_search_metrics_t* metrics);
int qihse_batch_search_ex(const void* data, size_t n, const void* queries,
    size_t num_queries, not_stisla_result_t* results,
    not_stisla_anchor_table_t* table, const qihse_config_t* config,
    const qihse_search_options_t* options, qihse_search_metrics_t* metrics);

/**
 * @brief Quantum-Inspired Hilbert Space Expansion Search
 *
 * Score scalar numeric candidates with a signed RFF inner product, then verify
 * equality against original data. Scratch storage is O(dimensions), independent
 * of n. Exact/fallback mode searches all records if the candidate does not match.
 * Non-numeric records use descriptor-based verification directly. The CPU
 * streaming path does not dispatch the experimental amplification/device APIs.
 *
 * @param data Array of fixed-width records; need not be sorted
 * @param n Number of elements in array
 * @param query Value to search for
 * @param table Reserved on this streaming path (can be NULL)
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
 * Uses one cosine-RFF basis and tiles of up to 16 queries, sharing streamed row
 * projections. Use qihse_batch_search_ex to select a method and tile size.
 *
 * @param data Array of fixed-width records; need not be sorted
 * @param n Number of elements in array
 * @param queries Array of query values
 * @param num_queries Number of queries
 * @param results Output array for results (must be sized for num_queries)
 * @param table Reserved on this path (can be NULL)
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
    double dim_calc_time_ns;    /* Core setup: dimensions, basis and scratch allocation */
    double rff_time_ns;         /* RFF embedding time */
    double superposition_time_ns; /* Superposition creation time */
    double amplification_time_ns; /* Grover amplification time */
    double collapse_time_ns;    /* Dimensional collapse time */
    double verification_time_ns; /* Verification time */

    /* Device utilization */
    double device_utilization[QIHSE_DEV_COUNT]; /* % utilization per device */
    double device_time_ns[QIHSE_DEV_COUNT]; /* Time spent per device */

    /* Quality metrics */
    double avg_confidence;      /* Fraction of queries with verified hits */
    double verification_rate;   /* Scalar search: 1, every candidate is checked */
    size_t classical_fallbacks; /* Queries scanned beyond the RFF candidate */

    /* QIHSE native anchor learning metrics */
    size_t anchors_learned;     /* New anchors learned */
    size_t anchors_pruned;      /* Anchors pruned due to memory limits */
    size_t anchor_table_size;   /* Current anchor table size */
    double anchor_hit_rate;     /* Percentage of searches using anchors */
    double anchor_avg_error;    /* Average interpolation error */
    int detected_workload_type; /* Auto-detected workload type */
    double speedup_vs_binary;   /* Speedup vs binary search */
    double speedup_vs_classical; /* Speedup vs classical anchor search */
    double anchor_memory_usage_mb; /* Memory used by anchor tables */

    /* Resource usage */
    size_t peak_memory_bytes;   /* Scalar search: kernel + feature scratch bytes */
    size_t total_operations;    /* Reserved/uninstrumented by scalar search */
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
