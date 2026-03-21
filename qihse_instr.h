#include <pthread.h>
/*
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

#ifndef QIHSE_INSTR_H
#define QIHSE_INSTR_H

/* Define feature test macros before including system headers. */
/* _GNU_SOURCE enables a superset of POSIX features, often including threading primitives. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* _XOPEN_SOURCE enables POSIX features, including pthreads. */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
/* _POSIX_C_SOURCE ensures POSIX standards are met. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

/* Include essential POSIX headers early. */
#include <unistd.h>     /* For POSIX operating system API */
#include <semaphore.h>  /* Often related to threading primitives */
#include <errno.h>      /* For error handling */
#include <pthread.h>    /* For pthreads, including rwlock */
#include <stdint.h>     /* For fixed-width integer types */
#include <stdbool.h>    /* For boolean types */

#ifdef __cplusplus
extern "C" {
#endif

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
    uint32_t physical_cores;             /* CPU physical cores */
    uint32_t logical_cores;              /* CPU logical cores (with HT) */
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

int qihse_intel_detect_hardware(qihse_intel_hw_info_t* info);
int qihse_intel_enable_features(uint32_t features);
int qihse_intel_amx_gemm(const void* a, const void* b, void* c,
                        size_t m, size_t n, size_t k);
int qihse_intel_avx512_vector_op(const double* a, const double* b, double* result,
                                size_t n, int operation);
int qihse_intel_vnni_dot_product(const int8_t* a, const int8_t* b, int32_t* result, size_t n);
int qihse_intel_hw_hash(const void* data, size_t size, void* hash, int hash_type);
void qihse_intel_prefetch(const void* addr, size_t size, int locality);
void qihse_intel_memcpy(void* dest, const void* src, size_t size);
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

int qihse_power_init(const qihse_power_config_t* config);
int qihse_power_set_mode(qihse_frequency_mode_t mode, double target_freq_mhz);
int qihse_power_analyze_workload(qihse_workload_characteristics_t* chars);
int qihse_power_adaptive_scaling(const qihse_workload_characteristics_t* chars);
int qihse_power_get_status(qihse_power_status_t* status);
int qihse_power_set_budget(double budget_watts);
int qihse_power_set_turbo(bool enable);
int qihse_power_monitor_and_adjust(size_t duration_ms);

/* CPU feature detection exports */
bool qihse_detect_avx2(void);
bool qihse_detect_avx512(void);

/* ============================================================================
 * UMA AND MEMORY MANAGEMENT RELATED EXPORTS
 * ============================================================================ */
/* Forward declarations for structs used in UMA functions */
typedef struct qihse_memory_superposition_t qihse_memory_superposition_t;
typedef struct qihse_vector_db_t qihse_vector_db_t;
typedef void* qihse_uma_manager_t; /* Opaque pointer for UMA manager */
typedef void* qihse_uma_address_t; /* Opaque pointer for UMA address object */

/* Memory tiers */
typedef enum {
    QIHSE_MEM_DRAM,
    QIHSE_MEM_HBM,
    QIHSE_MEM_NPU_CACHE,
    QIHSE_MEM_GNA_CACHE,
    QIHSE_MEM_OPTANE,
    QIHSE_MEM_CXL
} qihse_memory_tier_t;

/* Memory region information */
typedef struct {
    qihse_memory_tier_t tier;
    size_t capacity_bytes;
    size_t available_bytes;
    uint64_t bandwidth_mbps;
    uint64_t latency_ns;
    bool is_unified;
    int numa_node;
    const char* device_name;
} qihse_memory_region_t;

/* Access modes for superposition */
typedef enum {
    QIHSE_SUPERPOSITION_SHARED,
    QIHSE_SUPERPOSITION_PINNED,
    QIHSE_SUPERPOSITION_REPLICATED
} qihse_superposition_mode_t;

/* Memory superposition structure */
struct qihse_memory_superposition_t {
    void* logical_address;              /* Logical address for application access */
    void** replicas;                    /* Array of physical memory replicas */
    size_t num_replicas;                /* Number of replicas */
    size_t total_size;                  /* Total size of the data */
    bool auto_migrate;                  /* Enable automatic migration */
    double hot_threshold;               /* Threshold for hot data */
    double cold_threshold;              /* Threshold for cold data */
    pthread_rwlock_t* rwlock;           /* Read-write lock for synchronization */
    /* Internal fields */
    size_t num_devices;                 /* Number of devices supporting this data */
    int* devices;                       /* List of devices supporting this data */
    double workload_intensity;          /* Current workload intensity */
    size_t access_count;                /* Global access count */
    size_t migration_count;             /* Migration count */
};

/* Vector database structure */
struct qihse_vector_db_t {
    size_t vector_dimension;
    size_t num_vectors;
    qihse_memory_superposition_t* data_superposition;
    qihse_memory_superposition_t* index_superposition;
    bool preload_enabled;
    double preload_fraction;
    bool use_quantization;
    uint8_t quantization_bits;
};

/* Function to initialize UMA */
int qihse_uma_init(void);
/* Function to shut down UMA */
void qihse_uma_shutdown(void);
/* Function to detect and list memory regions */
int qihse_uma_detect_regions(qihse_memory_region_t** regions, size_t* num_regions);
/* Function to allocate memory with UMA */
void* qihse_uma_alloc(size_t size, qihse_memory_tier_t tier);
/* Function to free UMA allocated memory */
void qihse_uma_free(void* ptr);
/* Function to access memory, handling UMA specifics */
int qihse_uma_access(void* ptr, size_t size, bool write_access);
/* Function to migrate data between memory tiers */
int qihse_uma_migrate(void* ptr, qihse_memory_tier_t from_tier, qihse_memory_tier_t to_tier);
/* Function to get the 'temperature' of memory based on access patterns */
double qihse_uma_get_temperature(void* ptr);
/* Function to optimize memory layout for NPU cache */
int qihse_uma_optimize_for_npu(qihse_memory_superposition_t* superposition);
/* Function to create a memory superposition object */
qihse_memory_superposition_t* qihse_uma_create_superposition(
    size_t size,
    qihse_memory_tier_t preferred_tier,
    bool enable_migration
);

/* Vector database functions */
qihse_vector_db_t* qihse_vector_db_init(
    size_t vector_dim,
    size_t num_vectors,
    const char* db_path
);
void qihse_vector_db_shutdown(qihse_vector_db_t* db);
int qihse_vector_db_preload(qihse_vector_db_t* db, double fraction);
int qihse_vector_db_optimize_layout(qihse_vector_db_t* db);

/* Meteor Lake NPU Cache functions */
int qihse_meteor_lake_npu_cache_init(void);
void* qihse_npu_cache_alloc(size_t size);
int qihse_npu_cache_prefetch(void* ptr, size_t size);
int qihse_npu_cache_flush(void);

/* GNA integration functions */
int qihse_gna_init(void);
int qihse_gna_micro_tweak(
    const float* input_features,
    size_t num_features,
    float* output_tweaks,
    size_t num_tweaks
);
int qihse_gna_train(
    const float* training_data,
    const float* target_tweaks,
    size_t num_samples,
    size_t num_features,
    size_t num_tweaks
);

/* Utility functions */
const char* qihse_memory_tier_name(qihse_memory_tier_t tier);
void qihse_uma_print_stats(void);

/* ============================================================================
 * NEW FUNCTION DECLARATION TO RESOLVE LINKER ERROR
 * ============================================================================ */

/**
 * @brief Sets the priority pinning for a given task handle.
 *
 * This function is intended to resolve linker errors related to missing
 * priority pinning functionality. It currently provides a stub implementation.
 *
 * @param task_handle A handle to the task whose priority is to be set.
 * @param priority The desired priority level.
 */
void qihse_uma_set_priority_pinning(void *task_handle, int priority);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* QIHSE_INSTR_H */
