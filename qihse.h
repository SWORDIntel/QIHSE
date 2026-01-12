/**
 * QIHSE - Quantum-Inspired Hilbert Space Expansion Search Algorithm
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
 * DIMENSION CALCULATION AND ANALYSIS
 * ============================================================================ */

typedef struct {
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
 * RANDOM FOURIER FEATURES KERNEL EMBEDDING
 * ============================================================================ */

typedef struct {
    double* omega;              /* Random frequency matrix [dims x input_dims] */
    double* bias;               /* Random phase offsets [dims] */
    size_t input_dims;          /* Input dimension count */
    size_t output_dims;         /* Output dimension count (Hilbert space) */
    double gamma;               /* RBF kernel bandwidth parameter */
    uint64_t seed;              /* Random seed for reproducibility */
} qihse_rff_kernel_t;

/**
 * @brief Create Random Fourier Features kernel
 *
 * Initializes RFF kernel with random frequencies and biases for
 * approximating RBF kernel in higher-dimensional space.
 *
 * @param input_dims Input dimension count
 * @param output_dims Output dimension count (Hilbert space size)
 * @param gamma RBF kernel bandwidth (smaller = more localized)
 * @param seed Random seed for reproducible results
 * @return Initialized RFF kernel, or NULL on allocation failure
 */
qihse_rff_kernel_t* qihse_rff_create(
    size_t input_dims,
    size_t output_dims,
    double gamma,
    uint64_t seed
);

/**
 * @brief Destroy RFF kernel
 *
 * @param kernel Kernel to destroy
 */
void qihse_rff_destroy(qihse_rff_kernel_t* kernel);

/**
 * @brief Project data to Hilbert space using RFF
 *
 * z(x) = sqrt(2/D) * cos(ω·x + b)
 *
 * @param kernel Initialized RFF kernel
 * @param input Input vector [input_dims]
 * @param output Output Hilbert space projection [output_dims]
 */
void qihse_rff_project(
    const qihse_rff_kernel_t* kernel,
    const double* input,
    double* output
);

/* ============================================================================
 * SUPERPOSITION STATE ENCODING
 * ============================================================================ */

typedef struct {
    double* real;               /* Real amplitude components */
    double* imag;               /* Imaginary amplitude components */
    double* phase;              /* Per-element phase angles */
    size_t num_states;          /* Number of superposition states */
    size_t dims_per_state;      /* Dimensions per quantum state */
    double global_phase;        /* Global quantum phase */
    double measurement_confidence; /* Confidence in quantum measurement */
} qihse_superposition_t;

/**
 * @brief Create quantum superposition from RFF-projected data
 *
 * Encodes search problem into higher-dimensional Hilbert space with
 * phase entanglement between dimensions.
 *
 * @param rff_data RFF-projected array [n x rff_dims]
 * @param n Number of elements in original array
 * @param rff_dims RFF output dimensions
 * @param superposition Output superposition structure
 * @return 0 on success, negative on allocation failure
 */
int qihse_create_superposition(
    const double* rff_data,
    size_t n,
    size_t rff_dims,
    qihse_superposition_t* superposition
);

/**
 * @brief Destroy superposition structure
 *
 * @param superposition Structure to destroy
 */
void qihse_destroy_superposition(qihse_superposition_t* superposition);

/* ============================================================================
 * GROVER AMPLIFICATION CONFIGURATION
 * ============================================================================ */

typedef struct {
    int min_rounds;             /* Minimum amplification rounds */
    int max_rounds;             /* Maximum amplification rounds (0 = auto) */
    double convergence_threshold; /* Stop when amplitude delta < threshold */
    double oracle_selectivity;  /* How strict the oracle marking is (0.0-1.0) */
    bool adaptive_rounds;       /* Use adaptive round count based on problem size */
    int fixed_rounds;           /* Fixed round count (if adaptive_rounds=false) */
} qihse_amplification_config_t;

/**
 * @brief Initialize amplification config with smart defaults
 *
 * @param config Config structure to initialize
 * @param problem_size Size of search problem (affects round count)
 */
void qihse_amplification_config_init(
    qihse_amplification_config_t* config,
    size_t problem_size
);

/* ============================================================================
 * VERIFICATION AND ACCURACY MODES
 * ============================================================================ */

typedef enum {
    QIHSE_VERIFY_NONE = 0,      /* No verification (fastest, ~95% accuracy) */
    QIHSE_VERIFY_FAST = 1,      /* Check predicted index only (~99.9% accuracy) */
    QIHSE_VERIFY_WINDOW = 2,    /* Check small window around prediction (~99.99%) */
    QIHSE_VERIFY_FALLBACK = 3,  /* Check prediction + fallbacks (99.999%) */
    QIHSE_VERIFY_EXACT = 4      /* Guarantee 100% via classical fallback */
} qihse_verify_mode_t;

typedef struct {
    qihse_verify_mode_t mode;   /* Verification mode */
    size_t window_size;         /* Window size for VERIFY_WINDOW mode */
    double min_confidence;      /* Skip verification if confidence > threshold */
    bool fallback_to_classical; /* Use classical search if QIHSE fails */
    size_t max_verification_time_us; /* Timeout for verification operations */
} qihse_verify_config_t;

/* ============================================================================
 * COLLAPSE AND VERIFICATION RESULTS
 * ============================================================================ */

typedef struct {
    size_t predicted_index;     /* Best guess index */
    double confidence;          /* 0.0 to 1.0 confidence score */
    size_t* fallback_indices;   /* Backup candidates if verification fails */
    size_t fallback_count;      /* Number of fallback indices */
} qihse_collapse_result_t;

/* ============================================================================
 * PARALLEL PIPELINE PROCESSING
 * ============================================================================ */

typedef enum {
    QIHSE_PIPELINE_FAST,        /* Quick approximate results */
    QIHSE_PIPELINE_BALANCED,    /* Balanced speed/accuracy */
    QIHSE_PIPELINE_ACCURATE,    /* Maximum accuracy */
    QIHSE_PIPELINE_LEARNED      /* ML-optimized configuration */
} qihse_pipeline_type_t;

/* ============================================================================
 * LANGUAGE BACKEND SYSTEM
 * ============================================================================ */

typedef enum {
    QIHSE_BACKEND_CPU_C,        /* Primary C implementation */
    QIHSE_BACKEND_CPU_FORTRAN,  /* FORTRAN BLAS/LAPACK */
    QIHSE_BACKEND_GPU_CUDA,     /* NVIDIA CUDA */
    QIHSE_BACKEND_GPU_JULIA,    /* Julia with CUDA.jl */
    QIHSE_BACKEND_NPU_INTEL,    /* Intel NPU/OpenVINO */
    QIHSE_BACKEND_DSP_ARM,      /* ARM DSP acceleration */
    QIHSE_BACKEND_FPGA,         /* FPGA acceleration */
    QIHSE_BACKEND_AUTO          /* Automatic selection */
} qihse_backend_type_t;

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

/**
 * @brief Initialize verification config with smart defaults
 *
 * @param config Config structure to initialize
 * @param target_accuracy Target accuracy level (0.0 = fast, 1.0 = exact)
 */
void qihse_verify_config_init(
    qihse_verify_config_t* config,
    double target_accuracy
);

/* ============================================================================
 * MAIN QIHSE CONFIGURATION AND API
 * ============================================================================ */

typedef struct {
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
 * INTERNAL QIHSE FUNCTIONS (used by qihse.c)
 * ============================================================================ */

int qihse_adaptive_amplify(qihse_superposition_t* superposition,
                           const void* query, qihse_data_type_t type,
                           const qihse_amplification_config_t* config);

qihse_collapse_result_t qihse_dimensional_collapse_l2_norm(
    const qihse_superposition_t* superposition);

not_stisla_result_t qihse_verify_result(
    const void* data, size_t n, const void* query, qihse_data_type_t type,
    const qihse_collapse_result_t* collapse, const qihse_verify_config_t* config);

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
 * INTEL ONEAPI INTEGRATION API
 * ============================================================================ */

typedef enum {
    QIHSE_INTEL_BACKEND_NONE = 0,    /* No Intel acceleration */
    QIHSE_INTEL_BACKEND_MKL = 1,     /* Intel MKL for BLAS operations */
    QIHSE_INTEL_BACKEND_IPP = 2,     /* Intel IPP for signal processing */
    QIHSE_INTEL_BACKEND_TBB = 3,     /* Intel TBB for threading */
    QIHSE_INTEL_BACKEND_DPCPP = 4,   /* Intel oneAPI DPC++ */
    QIHSE_INTEL_BACKEND_FORTRAN = 5  /* FORTRAN kernels */
} qihse_intel_backend_t;

typedef struct {
    qihse_intel_backend_t backend;
    int mkl_threads;                 /* MKL thread count */
    int tbb_threads;                 /* TBB thread count */
    bool enable_amx;                 /* Use AMX instructions */
    bool enable_avx512;              /* Use AVX-512 */
    bool enable_vnni;                /* Use VNNI instructions */
    size_t mkl_block_size;           /* MKL block size for GEMM */
    int fortran_precision;           /* FORTRAN precision mode */
    void* backend_context;           /* Backend-specific context */
} qihse_intel_config_t;

typedef struct {
    double mkl_gemm_time;            /* MKL GEMM operation time */
    double ipp_fft_time;             /* IPP FFT time */
    double tbb_parallel_time;        /* TBB parallel execution time */
    double fortran_compute_time;     /* FORTRAN computation time */
    size_t amx_tiles_used;           /* AMX tiles utilized */
    size_t avx512_vectors;           /* AVX-512 vector operations */
    double frequency_mhz;            /* CPU frequency during execution */
    double power_watts;              /* Power consumption estimate */
} qihse_intel_performance_t;

/**
 * @brief Initialize Intel oneAPI backends
 * @param config Intel backend configuration
 * @return 0 on success, negative on error
 */
int qihse_intel_init(const qihse_intel_config_t* config);

/**
 * @brief Shutdown Intel oneAPI backends
 */
void qihse_intel_shutdown(void);

/**
 * @brief Check if Intel backend is available
 * @param backend Backend to check
 * @return true if available
 */
bool qihse_intel_backend_available(qihse_intel_backend_t backend);

/**
 * @brief Get Intel backend performance statistics
 * @param stats Performance statistics structure to fill
 * @return 0 on success
 */
int qihse_intel_get_performance_stats(qihse_intel_performance_t* stats);

/**
 * @brief Set CPU frequency scaling for optimal performance
 * @param target_frequency_mhz Target frequency in MHz (0 = auto)
 * @return 0 on success
 */
int qihse_intel_set_frequency_scaling(double target_frequency_mhz);

/**
 * @brief Optimize memory layout for Intel architectures
 * @param data Data buffer to optimize
 * @param size Size of data in bytes
 * @param alignment Required alignment (cache line, page, etc.)
 * @return Pointer to optimized buffer (may be same as input)
 */
void* qihse_intel_optimize_memory_layout(void* data, size_t size, size_t alignment);

/* ============================================================================
 * FORTRAN INTEGRATION API
 * ============================================================================ */

typedef enum {
    QIHSE_FORTRAN_PRECISION_SINGLE = 1,   /* Single precision (float32) */
    QIHSE_FORTRAN_PRECISION_DOUBLE = 2,   /* Double precision (float64) */
    QIHSE_FORTRAN_PRECISION_QUAD = 3      /* Quad precision */
} qihse_fortran_precision_t;

typedef struct {
    qihse_fortran_precision_t precision;
    bool enable_openmp;               /* Use OpenMP in FORTRAN code */
    int openmp_threads;               /* OpenMP thread count */
    bool enable_simd;                 /* Enable SIMD directives */
    bool enable_vectorization;        /* Enable vectorization */
    char* library_path;               /* Path to FORTRAN libraries */
    void* fortran_context;            /* FORTRAN runtime context */
} qihse_fortran_config_t;

typedef struct {
    double matrix_multiply_time;      /* BLAS-like operations */
    double eigenvalue_time;           /* Eigenvalue computations */
    double svd_time;                  /* SVD decompositions */
    double fft_time;                  /* FFT operations */
    size_t flops_performed;           /* Floating point operations */
    double gflops_achieved;           /* GFLOPS achieved */
} qihse_fortran_performance_t;

/**
 * @brief Initialize FORTRAN runtime environment
 * @param config FORTRAN configuration
 * @return 0 on success, negative on error
 */
int qihse_fortran_init(const qihse_fortran_config_t* config);

/**
 * @brief Shutdown FORTRAN runtime
 */
void qihse_fortran_shutdown(void);

/**
 * @brief Check if FORTRAN backend is available
 * @return true if available
 */
bool qihse_fortran_available(void);

/**
 * @brief High-performance matrix multiplication using FORTRAN BLAS
 * @param a Matrix A (m x k)
 * @param b Matrix B (k x n)
 * @param c Result matrix C (m x n)
 * @param m Rows in A/C
 * @param n Columns in B/C
 * @param k Columns in A/Rows in B
 * @return 0 on success
 */
int qihse_fortran_gemm(const double* a, const double* b, double* c,
                      size_t m, size_t n, size_t k);

/**
 * @brief FORTRAN-accelerated eigenvalue computation
 * @param matrix Input matrix (n x n)
 * @param eigenvalues Output eigenvalues array
 * @param eigenvectors Output eigenvectors matrix (optional)
 * @param n Matrix dimension
 * @return 0 on success
 */
int qihse_fortran_eigenvalues(const double* matrix, double* eigenvalues,
                             double* eigenvectors, size_t n);

/**
 * @brief FORTRAN FFT computation
 * @param input Input array
 * @param output Output array (can be same as input)
 * @param size Size of arrays (must be power of 2)
 * @param direction 1 for forward, -1 for inverse
 * @return 0 on success
 */
int qihse_fortran_fft(const double* input, double* output,
                     size_t size, int direction);

/**
 * @brief Get FORTRAN performance statistics
 * @param stats Performance statistics to fill
 * @return 0 on success
 */
int qihse_fortran_get_performance_stats(qihse_fortran_performance_t* stats);

/* ============================================================================
 * ADVANCED MATHEMATICAL OPTIMIZATIONS
 * ============================================================================ */

typedef enum {
    QIHSE_MATH_PRECISION_FULL = 0,    /* Full IEEE 754 precision */
    QIHSE_MATH_PRECISION_HIGH = 1,    /* High precision (1e-12 relative) */
    QIHSE_MATH_PRECISION_MEDIUM = 2,  /* Medium precision (1e-8 relative) */
    QIHSE_MATH_PRECISION_LOW = 3,     /* Low precision (1e-4 relative) */
    QIHSE_MATH_PRECISION_FAST = 4     /* Fast approximations */
} qihse_math_precision_t;

typedef struct {
    qihse_math_precision_t precision;
    bool enable_fma;                  /* Use fused multiply-add */
    bool enable_fast_math;            /* Use fast math approximations */
    bool enable_vectorization;        /* Enable SIMD vectorization */
    size_t cache_line_size;           /* Cache line size for alignment */
    bool enable_prefetching;          /* Enable software prefetching */
} qihse_math_config_t;

typedef struct {
    double exp_approximation_error;    /* Max error in exp() approximation */
    double log_approximation_error;    /* Max error in log() approximation */
    double sqrt_approximation_error;   /* Max error in sqrt() approximation */
    double trig_approximation_error;   /* Max error in trig approximations */
    size_t vector_operations;          /* SIMD vector operations performed */
    size_t cache_misses;               /* Estimated cache misses */
    double computation_time;           /* Total computation time */
} qihse_math_performance_t;

/**
 * @brief Initialize mathematical optimization library
 * @param config Mathematical optimization configuration
 * @return 0 on success
 */
int qihse_math_init(const qihse_math_config_t* config);

/**
 * @brief Fast exponential function approximation
 * @param x Input value
 * @param precision Precision level
 * @return exp(x) approximation
 */
double qihse_math_fast_exp(double x, qihse_math_precision_t precision);

/**
 * @brief Fast logarithm function approximation
 * @param x Input value (> 0)
 * @param precision Precision level
 * @return log(x) approximation
 */
double qihse_math_fast_log(double x, qihse_math_precision_t precision);

/**
 * @brief Fast square root using Intel-optimized algorithm
 * @param x Input value (>= 0)
 * @param precision Precision level
 * @return sqrt(x) approximation
 */
double qihse_math_fast_sqrt(double x, qihse_math_precision_t precision);

/**
 * @brief Fast sine/cosine computation using Intel algorithms
 * @param x Input angle in radians
 * @param sin_out Output sine value (optional)
 * @param cos_out Output cosine value (optional)
 * @param precision Precision level
 */
void qihse_math_fast_sincos(double x, double* sin_out, double* cos_out,
                           qihse_math_precision_t precision);

/**
 * @brief Vectorized dot product with Intel optimizations
 * @param a First vector
 * @param b Second vector
 * @param n Vector length
 * @return Dot product result
 */
double qihse_math_vector_dot(const double* a, const double* b, size_t n);

/**
 * @brief Optimized matrix-vector multiplication
 * @param matrix Input matrix (m x n)
 * @param vector Input vector (n)
 * @param result Output vector (m)
 * @param m Matrix rows
 * @param n Matrix columns
 */
void qihse_math_matrix_vector_mul(const double* matrix, const double* vector,
                                 double* result, size_t m, size_t n);

/**
 * @brief Fast random number generation using Intel-optimized PRNG
 * @param seed Random seed
 * @return Random double in [0,1)
 */
double qihse_math_fast_random(uint64_t* seed);

/**
 * @brief Cache-efficient matrix transpose
 * @param input Input matrix
 * @param output Output transposed matrix
 * @param rows Input rows
 * @param cols Input columns
 */
void qihse_math_cache_efficient_transpose(const double* input, double* output,
                                        size_t rows, size_t cols);

/**
 * @brief Get mathematical performance statistics
 * @param stats Performance statistics to fill
 * @return 0 on success
 */
int qihse_math_get_performance_stats(qihse_math_performance_t* stats);

/* ============================================================================
 * INTEL-SPECIFIC HARDWARE OPTIMIZATIONS
 * ============================================================================ */

typedef enum {
    QIHSE_INTEL_HW_AMX = (1 << 0),       /* Advanced Matrix Extensions */
    QIHSE_INTEL_HW_AVX512 = (1 << 1),    /* AVX-512 instructions */
    QIHSE_INTEL_HW_AVX_VNNI = (1 << 2),  /* VNNI for neural networks */
    QIHSE_INTEL_HW_AVX2 = (1 << 3),      /* AVX2 instructions */
    QIHSE_INTEL_HW_FMA = (1 << 4),       /* Fused multiply-add */
    QIHSE_INTEL_HW_SSE4_2 = (1 << 5),    /* SSE4.2 instructions */
    QIHSE_INTEL_HW_PREFETCH = (1 << 6),  /* Hardware prefetching */
    QIHSE_INTEL_HW_TSX = (1 << 7),       /* Transactional memory */
    QIHSE_INTEL_HW_SHA = (1 << 8),       /* SHA acceleration */
    QIHSE_INTEL_HW_AES = (1 << 9)        /* AES acceleration */
} qihse_intel_hw_features_t;

typedef struct {
    uint32_t available_features;         /* Bitmask of available features */
    uint32_t enabled_features;           /* Bitmask of enabled features */
    size_t amx_tile_size;                /* AMX tile size in bytes */
    size_t avx512_vector_size;           /* AVX-512 vector register size */
    size_t cache_line_size;              /* L1 cache line size */
    size_t l2_cache_size;                /* L2 cache size in bytes */
    size_t l3_cache_size;                /* L3 cache size in bytes */
    double base_frequency_mhz;           /* Base CPU frequency */
    double max_frequency_mhz;            /* Maximum turbo frequency */
    uint32_t physical_cores;             /* Physical CPU cores */
    uint32_t logical_cores;              /* Logical CPU cores (with HT) */
} qihse_intel_hw_info_t;

typedef struct {
    size_t amx_operations;               /* AMX tile operations performed */
    size_t avx512_operations;            /* AVX-512 vector operations */
    size_t cache_hits;                   /* Estimated cache hits */
    size_t cache_misses;                 /* Estimated cache misses */
    double avg_frequency_mhz;            /* Average CPU frequency during execution */
    double power_consumption_watts;      /* Estimated power consumption */
    size_t prefetch_requests;            /* Software prefetch requests issued */
    size_t tlb_misses;                   /* TLB misses (estimated) */
} qihse_intel_hw_performance_t;

/**
 * @brief Detect available Intel hardware features
 * @param info Hardware information structure to fill
 * @return 0 on success
 */
int qihse_intel_detect_hardware(qihse_intel_hw_info_t* info);

/**
 * @brief Enable specific Intel hardware optimizations
 * @param features Bitmask of features to enable
 * @return 0 on success, negative on error
 */
int qihse_intel_enable_features(uint32_t features);

/**
 * @brief AMX tile matrix multiplication
 * @param a Tile A data (16x16 or 16x32 FP16/BF16)
 * @param b Tile B data
 * @param c Tile C accumulator
 * @param m Matrix dimension M
 * @param n Matrix dimension N
 * @param k Matrix dimension K
 * @return 0 on success
 */
int qihse_intel_amx_gemm(const void* a, const void* b, void* c,
                        size_t m, size_t n, size_t k);

/**
 * @brief AVX-512 optimized vector operations
 * @param a First vector
 * @param b Second vector
 * @param result Output vector
 * @param n Vector length (must be multiple of 8 for double, 16 for float)
 * @param operation Operation: 0=add, 1=sub, 2=mul, 3=div, 4=dot
 * @return 0 on success
 */
int qihse_intel_avx512_vector_op(const double* a, const double* b, double* result,
                                size_t n, int operation);

/**
 * @brief Hardware-accelerated hash computation using Intel SHA
 * @param data Input data
 * @param size Data size in bytes
 * @param hash Output hash (32 bytes for SHA-256)
 * @param hash_type 0=SHA-256, 1=SHA-1
 * @return 0 on success
 */
int qihse_intel_hw_hash(const void* data, size_t size, void* hash, int hash_type);

/**
 * @brief Prefetch data into cache
 * @param addr Memory address to prefetch
 * @param size Size to prefetch in bytes
 * @param locality Temporal locality hint (0=none, 1=low, 2=moderate, 3=high)
 */
void qihse_intel_prefetch(const void* addr, size_t size, int locality);

/**
 * @brief Memory copy optimized for Intel architecture
 * @param dest Destination buffer
 * @param src Source buffer
 * @param size Size to copy in bytes
 */
void qihse_intel_memcpy(void* dest, const void* src, size_t size);

/**
 * @brief Get Intel hardware performance counters
 * @param perf Performance statistics to fill
 * @return 0 on success
 */
int qihse_intel_get_hw_performance(qihse_intel_hw_performance_t* perf);

/* ============================================================================
 * FREQUENCY MATCHING AND POWER MANAGEMENT
 * ============================================================================ */

typedef enum {
    QIHSE_FREQ_MODE_FIXED = 0,       /* Fixed frequency */
    QIHSE_FREQ_MODE_ADAPTIVE = 1,    /* Adaptive based on workload */
    QIHSE_FREQ_MODE_PERFORMANCE = 2, /* Maximum performance */
    QIHSE_FREQ_MODE_BALANCED = 3,    /* Balanced power/performance */
    QIHSE_FREQ_MODE_POWERSAVE = 4    /* Power saving */
} qihse_frequency_mode_t;

typedef struct {
    qihse_frequency_mode_t mode;
    double target_frequency_mhz;      /* Target CPU frequency */
    double min_frequency_mhz;         /* Minimum allowed frequency */
    double max_frequency_mhz;         /* Maximum allowed frequency */
    double power_budget_watts;        /* Power consumption limit */
    bool enable_turbo;                /* Allow turbo boost */
    bool enable_c_states;             /* Allow C-states for power saving */
    size_t monitoring_interval_ms;    /* Performance monitoring interval */
} qihse_power_config_t;

typedef struct {
    double current_frequency_mhz;     /* Current CPU frequency */
    double average_frequency_mhz;     /* Average frequency over time */
    double power_consumption_watts;   /* Current power consumption */
    double temperature_celsius;       /* CPU temperature */
    size_t throttling_events;         /* Number of thermal throttling events */
    double efficiency_score;          /* Performance per watt score */
    uint64_t last_adjustment_time;    /* Last frequency adjustment timestamp */
} qihse_power_status_t;

typedef struct {
    double workload_intensity;        /* 0.0 to 1.0 workload intensity */
    double memory_pressure;           /* Memory usage pressure */
    double cache_hit_rate;            /* L1/L2 cache hit rate */
    double branch_mispredict_rate;    /* Branch misprediction rate */
    size_t active_threads;            /* Number of active threads */
    double ipc;                       /* Instructions per cycle */
} qihse_workload_characteristics_t;

/**
 * @brief Initialize frequency and power management
 * @param config Power and frequency configuration
 * @return 0 on success
 */
int qihse_power_init(const qihse_power_config_t* config);

/**
 * @brief Set frequency scaling mode
 * @param mode Frequency scaling mode
 * @param target_freq_mhz Target frequency (0 = auto)
 * @return 0 on success
 */
int qihse_power_set_mode(qihse_frequency_mode_t mode, double target_freq_mhz);

/**
 * @brief Analyze workload characteristics for optimal frequency
 * @param chars Workload characteristics structure to fill
 * @return 0 on success
 */
int qihse_power_analyze_workload(qihse_workload_characteristics_t* chars);

/**
 * @brief Adjust frequency based on workload analysis
 * @param chars Current workload characteristics
 * @return 0 on success
 */
int qihse_power_adaptive_scaling(const qihse_workload_characteristics_t* chars);

/**
 * @brief Get current power and frequency status
 * @param status Status structure to fill
 * @return 0 on success
 */
int qihse_power_get_status(qihse_power_status_t* status);

/**
 * @brief Set power consumption budget
 * @param budget_watts Maximum power consumption in watts
 * @return 0 on success
 */
int qihse_power_set_budget(double budget_watts);

/**
 * @brief Enable/disable turbo boost
 * @param enable True to enable turbo boost
 * @return 0 on success
 */
int qihse_power_set_turbo(bool enable);

/**
 * @brief Monitor and adjust frequency for optimal performance
 * @param duration_ms Monitoring duration in milliseconds
 * @return 0 on success
 */
int qihse_power_monitor_and_adjust(size_t duration_ms);

/* ============================================================================
 * MULTI-RESOLUTION SEARCH API
 * ============================================================================ */

typedef enum {
    QIHSE_RESOLUTION_LOW,      /* 8-64 dimensions: Fast but approximate */
    QIHSE_RESOLUTION_MEDIUM,   /* 128-512 dimensions: Balanced */
    QIHSE_RESOLUTION_HIGH,     /* 1024+ dimensions: Slow but accurate */
    QIHSE_RESOLUTION_ADAPTIVE  /* Adaptive based on data and requirements */
} qihse_resolution_level_t;

typedef struct {
    qihse_resolution_level_t level;
    size_t target_dimensions;
    double confidence_threshold;
    bool use_previous_results;  /* Use results from lower resolutions */
    size_t max_candidates;      /* Limit search space for efficiency */
    qihse_collapse_result_t* previous_result; /* Guide from lower resolution */
} qihse_resolution_config_t;

typedef struct {
    size_t num_resolutions;
    qihse_resolution_config_t* resolutions;
    qihse_collapse_result_t final_result;
    double total_time_ns;
    size_t resolutions_completed;
    bool early_termination;     /* Stopped early due to high confidence */
} qihse_multires_result_t;

/**
 * @brief Initialize multi-resolution search configurations
 * @param configs Array to fill with resolution configurations
 * @param max_configs Maximum number of configurations
 * @param data_type Data type being searched
 * @param array_size Size of the search array
 * @return Number of configurations created
 */
size_t qihse_init_multires_search(
    qihse_resolution_config_t* configs,
    size_t max_configs,
    qihse_data_type_t data_type,
    size_t array_size
);

/**
 * @brief Execute multi-resolution search
 * @param data Search data array
 * @param n Number of elements
 * @param query Search query
 * @param table Anchor table (optional)
 * @param configs Resolution configurations
 * @param num_configs Number of configurations
 * @param result Multi-resolution result structure
 * @return 0 on success, negative on error
 */
int qihse_execute_multires_search(
    const void* data,
    size_t n,
    const void* query,
    not_stisla_anchor_table_t* table,
    qihse_resolution_config_t* configs,
    size_t num_configs,
    qihse_multires_result_t* result
);

/**
 * @brief Get final result from multi-resolution search
 * @param result Multi-resolution result structure
 * @return Best result found
 */
qihse_collapse_result_t qihse_get_multires_final_result(
    const qihse_multires_result_t* result
);

/* ============================================================================
 * SELF-OPTIMIZATION API
 * ============================================================================ */

typedef struct {
    uint64_t data_hash;         /* Hash of data characteristics */
    size_t array_size;          /* Size of array searched */
    qihse_data_type_t data_type; /* Type of data */
    double entropy;             /* Data entropy measure */
    double gap_variance;        /* Gap variance measure */
} qihse_data_signature_t;

typedef struct {
    qihse_data_signature_t signature;
    qihse_pipeline_type_t best_pipeline;  /* Best performing pipeline type */
    size_t optimal_dimensions;  /* Optimal Hilbert dimensions */
    double avg_speedup;         /* Average speedup vs classical */
    double avg_confidence;      /* Average result confidence */
    size_t samples;             /* Number of measurements */
    uint64_t last_updated;      /* Timestamp of last update */

    /* QIHSE-NOT_STISLA Integration: Anchor learning data */
    bool use_anchor_search;     /* Whether anchor search improves performance */
    size_t optimal_anchor_count; /* Optimal number of anchors for this workload */
    double anchor_hit_rate;     /* Average anchor hit rate */
    double anchor_speedup;      /* Speedup from anchor optimization */
    int workload_type;          /* Detected workload type (NOT_STISLA_WORKLOAD_*) */
} qihse_optimization_entry_t;

typedef struct {
    qihse_optimization_entry_t* entries;
    size_t num_entries;
    size_t max_entries;
    char* storage_path;         /* Path to persistent storage */
    bool enable_learning;       /* Enable self-optimization */
} qihse_optimization_db_t;

/**
 * @brief Initialize optimization database
 * @param db Database structure to initialize
 * @param max_entries Maximum number of optimization entries
 * @param storage_path Path for persistent storage (optional)
 * @return 0 on success, negative on error
 */
int qihse_optimization_init(
    qihse_optimization_db_t* db,
    size_t max_entries,
    const char* storage_path
);

/**
 * @brief Destroy optimization database
 * @param db Database to destroy
 */
void qihse_optimization_destroy(qihse_optimization_db_t* db);

/**
 * @brief Record performance measurement for learning
 * @param db Optimization database
 * @param data_signature Characteristics of the data searched
 * @param pipeline_type Pipeline type used
 * @param dimensions Hilbert dimensions used
 * @param speedup Speedup achieved vs classical search
 * @param confidence Result confidence achieved
 */
void qihse_record_performance(
    qihse_optimization_db_t* db,
    const qihse_data_signature_t* data_signature,
    qihse_pipeline_type_t pipeline_type,
    size_t dimensions,
    double speedup,
    double confidence
);

/**
 * @brief Get optimized configuration for data signature
 * @param db Optimization database
 * @param data_signature Data characteristics
 * @param config Configuration to optimize
 */
void qihse_get_optimized_config(
    const qihse_optimization_db_t* db,
    const qihse_data_signature_t* data_signature,
    qihse_config_t* config
);

/* ============================================================================
 * QIHSE-NOT_STISLA INTEGRATION: ANCHOR LEARNING API
 * ============================================================================ */

/**
 * @brief Record anchor learning performance for optimization
 * @param db Optimization database
 * @param data_signature Data characteristics
 * @param anchor_count Number of anchors used
 * @param hit_rate Anchor hit rate achieved
 * @param speedup Speedup from anchor optimization
 * @param workload_type Workload type (NOT_STISLA_WORKLOAD_*)
 */
void qihse_record_anchor_performance(
    qihse_optimization_db_t* db,
    const qihse_data_signature_t* data_signature,
    size_t anchor_count,
    double hit_rate,
    double speedup,
    int workload_type
);

/**
 * @brief Get anchor-optimized configuration for data signature
 * @param db Optimization database
 * @param data_signature Data characteristics
 * @param config Configuration to optimize with anchor settings
 * @return true if anchor optimization data was found and applied
 */
bool qihse_get_anchor_optimized_config(
    const qihse_optimization_db_t* db,
    const qihse_data_signature_t* data_signature,
    qihse_config_t* config
);

/**
 * @brief Detect workload type from actual data patterns
 * @param data Data array to analyze
 * @param n Number of elements
 * @param data_type QIHSE data type
 * @return Detected workload type (NOT_STISLA_WORKLOAD_*)
 */
int qihse_detect_workload_from_data(
    const void* data,
    size_t n,
    qihse_data_type_t data_type
);

/**
 * @brief Save optimization database to disk
 * @param db Database to save
 * @return 0 on success, negative on error
 */
int qihse_save_optimization_db(const qihse_optimization_db_t* db);

/**
 * @brief Load optimization database from disk
 * @param db Database to load into
 * @return 0 on success, negative on error
 */
int qihse_load_optimization_db(qihse_optimization_db_t* db);

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

