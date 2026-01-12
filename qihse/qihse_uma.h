/**
 * QIHSE UMA (Unified Memory Architecture) Memory Management
 *
 * Enables superposition of data availability across RAM/GPU/NPU with
 * intelligent memory placement and migration for optimal performance.
 */

#ifndef QIHSE_UMA_H
#define QIHSE_UMA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * UMA MEMORY HIERARCHY
 * ============================================================================ */

typedef enum {
    QIHSE_MEM_DRAM,          /* Main system RAM */
    QIHSE_MEM_HBM,           /* High Bandwidth Memory (GPU) */
    QIHSE_MEM_NPU_CACHE,     /* NPU cache (128MB on Meteor Lake) */
    QIHSE_MEM_GNA_CACHE,     /* GNA cache for fine-tuning */
    QIHSE_MEM_OPTANE,        /* Intel Optane persistent memory */
    QIHSE_MEM_CXL,           /* CXL-attached memory */
} qihse_memory_tier_t;

typedef struct {
    qihse_memory_tier_t tier;
    size_t capacity_bytes;   /* Total capacity */
    size_t available_bytes;  /* Currently available */
    size_t bandwidth_mbps;   /* Theoretical bandwidth */
    size_t latency_ns;       /* Typical access latency */
    bool is_unified;         /* True if UMA-capable */
    int numa_node;           /* NUMA node (-1 if not applicable) */
    char device_name[64];    /* Device identifier */
} qihse_memory_region_t;

/* ============================================================================
 * MEMORY SUPERPOSITION
 * ============================================================================ */

/**
 * Memory superposition state - tracks data distribution across memory hierarchy
 */
typedef struct {
    void* logical_address;           /* Virtual address in user space */
    size_t total_size;               /* Total data size */
    size_t num_replicas;             /* Number of physical copies */

    /* Physical memory mappings */
    struct {
        qihse_memory_tier_t tier;
        void* physical_address;      /* Physical/virtual address in this tier */
        size_t offset;               /* Offset within this replica */
        size_t size;                 /* Size in this tier */
        uint64_t access_timestamp;   /* Last access time */
        uint64_t access_count;       /* Access frequency */
        double temperature;          /* "Hotness" metric (0.0=cold, 1.0=hot) */
    }* replicas;

    /* Migration policies */
    bool auto_migrate;               /* Enable automatic migration */
    double hot_threshold;            /* Temperature threshold for promotion */
    double cold_threshold;           /* Temperature threshold for demotion */

    /* Synchronization */
    pthread_rwlock_t* rwlock;        /* Read-write lock for concurrent access */
} qihse_memory_superposition_t;

/* ============================================================================
 * VECTOR DATABASE INTEGRATION
 * ============================================================================ */

/**
 * Vector database interface for QIHSE optimization
 */
typedef struct {
    /* Database metadata */
    size_t vector_dimension;         /* Vector dimensionality */
    size_t num_vectors;             /* Total vectors in database */
    size_t index_type;              /* Index type (HNSW, IVF, etc.) */

    /* Memory mapping */
    qihse_memory_superposition_t* data_superposition;
    qihse_memory_superposition_t* index_superposition;

    /* Pre-loading configuration */
    bool preload_enabled;           /* Enable pre-loading */
    double preload_fraction;        /* Fraction of DB to preload (0.0-1.0) */
    qihse_memory_tier_t preload_tier; /* Preferred preload tier */

    /* Query optimization */
    size_t batch_size;              /* Optimal batch size for queries */
    bool use_quantization;          /* Use quantization for memory efficiency */
    size_t quantization_bits;       /* Quantization precision (8, 4, 2 bits) */
} qihse_vector_db_t;

/* ============================================================================
 * UMA-AWARE MEMORY MANAGEMENT API
 * ============================================================================ */

/**
 * Initialize UMA memory management system
 */
int qihse_uma_init(void);

/**
 * Shutdown UMA memory management system
 */
void qihse_uma_shutdown(void);

/**
 * Detect available memory regions and their properties
 */
int qihse_uma_detect_regions(qihse_memory_region_t** regions, size_t* num_regions);

/**
 * Create memory superposition for optimal data placement
 */
qihse_memory_superposition_t* qihse_uma_create_superposition(
    size_t size,
    qihse_memory_tier_t preferred_tier,
    bool enable_migration
);

/**
 * Allocate memory with UMA-aware placement
 */
void* qihse_uma_alloc(size_t size, qihse_memory_tier_t tier);

/**
 * Free UMA-managed memory
 */
void qihse_uma_free(void* ptr);

/**
 * Access memory with automatic migration if needed
 */
int qihse_uma_access(void* ptr, size_t size, bool write_access);

/**
 * Migrate data between memory tiers
 */
int qihse_uma_migrate(
    void* ptr,
    qihse_memory_tier_t from_tier,
    qihse_memory_tier_t to_tier
);

/**
 * Get memory temperature (access frequency) for optimization
 */
double qihse_uma_get_temperature(void* ptr);

/**
 * Optimize memory layout for NPU cache (128MB on Meteor Lake)
 */
int qihse_uma_optimize_for_npu(qihse_memory_superposition_t* superposition);

/* ============================================================================
 * VECTOR DATABASE INTEGRATION API
 * ============================================================================ */

/**
 * Initialize vector database integration
 */
qihse_vector_db_t* qihse_vector_db_init(
    size_t vector_dim,
    size_t num_vectors,
    const char* db_path
);

/**
 * Shutdown vector database integration
 */
void qihse_vector_db_shutdown(qihse_vector_db_t* db);

/**
 * Pre-load vector database into optimal memory tier
 */
int qihse_vector_db_preload(qihse_vector_db_t* db, double fraction);

/**
 * Query vector database with UMA optimization
 */
int qihse_vector_db_query(
    qihse_vector_db_t* db,
    const float* query_vector,
    size_t k,
    size_t* indices,
    float* distances
);

/**
 * Optimize vector database layout for QIHSE access patterns
 */
int qihse_vector_db_optimize_layout(qihse_vector_db_t* db);

/* ============================================================================
 * METEOR LAKE NPU CACHE OPTIMIZATION
 * ============================================================================ */

/**
 * Configure memory for Meteor Lake NPU cache (128MB)
 */
int qihse_meteor_lake_npu_cache_init(void);

/**
 * Allocate memory optimized for NPU cache access patterns
 */
void* qihse_npu_cache_alloc(size_t size);

/**
 * Prefetch data into NPU cache for upcoming operations
 */
int qihse_npu_cache_prefetch(void* ptr, size_t size);

/**
 * Flush NPU cache to main memory
 */
int qihse_npu_cache_flush(void);

/* ============================================================================
 * GNA INTEGRATION FOR MICRO-TWEAKING
 * ============================================================================ */

/**
 * Initialize GNA (Gaussian Neural Accelerator) for fine-tuning
 */
int qihse_gna_init(void);

/**
 * Use GNA for micro-tweaking of search parameters
 */
int qihse_gna_micro_tweak(
    const float* input_features,
    size_t num_features,
    float* output_tweaks,
    size_t num_tweaks
);

/**
 * Train GNA model for parameter optimization
 */
int qihse_gna_train(
    const float* training_data,
    const float* target_tweaks,
    size_t num_samples,
    size_t num_features,
    size_t num_tweaks
);

#endif /* QIHSE_UMA_H */
