/*
 * QIHSE - Unified Memory Architecture (UMA)
 *
 * Unified memory abstraction layer for seamless data movement across devices.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_UMA_H
#define QIHSE_UMA_H

#include "qihse_memory.h"
#include "../../orchestration/include/qihse_hetero.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * MEMORY TIER HIERARCHY
 * ============================================================================ */

typedef enum {
    QIHSE_MEM_DRAM,          /* Main system RAM */
    QIHSE_MEM_HBM,           /* High Bandwidth Memory (GPU) */
    QIHSE_MEM_NPU_CACHE,     /* NPU cache */
    QIHSE_MEM_GNA_CACHE,     /* GNA cache */
    QIHSE_MEM_OPTANE,        /* Intel Optane persistent memory */
    QIHSE_MEM_CXL,           /* CXL-attached memory */
} qihse_memory_tier_t;

/* ============================================================================
 * UMA ABSTRACTIONS
 * ============================================================================ */

/**
 * Unified memory address space.
 */
typedef struct qihse_uma_address_s {
    void* ptr;                       /* Pointer in unified address space */
    size_t size;                     /* Size of allocation */
    qihse_device_type_t current_device; /* Current resident device */
    uint64_t residency_mask;         /* Bitmask of devices that can access */
} qihse_uma_address_t;

/**
 * Memory migration policy.
 */
typedef enum qihse_uma_migration_policy_e {
    QIHSE_UMA_MIGRATE_ON_ACCESS = 0, /* Migrate on first access */
    QIHSE_UMA_MIGRATE_PREFETCH = 1,  /* Prefetch to target device */
    QIHSE_UMA_MIGRATE_EXPLICIT = 2,  /* Explicit migration only */
    QIHSE_UMA_MIGRATE_LAZY = 3,      /* Migrate when needed */
} qihse_uma_migration_policy_t;

/**
 * UMA manager for unified memory operations.
 */
typedef struct qihse_uma_manager_s* qihse_uma_manager_t;

/* ============================================================================
 * PHASE 2 ENHANCEMENTS: MEMORY SUPERPOSITION & VECTOR DB INTEGRATION
 * ============================================================================ */

/**
 * Memory superposition state for quantum-inspired data placement.
 */
typedef enum qihse_memory_superposition_state_e {
    QIHSE_SUPERPOSITION_READY = 0,      /* Data ready for access */
    QIHSE_SUPERPOSITION_MIGRATING = 1,  /* Data migrating between tiers */
    QIHSE_SUPERPOSITION_PINNED = 2,     /* Data pinned to specific tier */
    QIHSE_SUPERPOSITION_EVICTED = 3,    /* Data evicted from fast memory */
    QIHSE_SUPERPOSITION_HYBRID = 4,     /* Data exists in multiple tiers */
} qihse_memory_superposition_state_t;

/**
 * Temperature-aware migration trigger.
 */
typedef enum qihse_temperature_trigger_e {
    QIHSE_TEMP_CRITICAL = 0,    /* > 90°C - force migration to cooler memory */
    QIHSE_TEMP_HIGH = 1,        /* > 75°C - consider migration */
    QIHSE_TEMP_NORMAL = 2,      /* 50-75°C - normal operation */
    QIHSE_TEMP_LOW = 3,         /* < 50°C - prefer fast memory */
} qihse_temperature_trigger_t;

/**
 * Meteor Lake NPU cache configuration.
 */
typedef struct qihse_meteor_lake_npu_cache_s {
    size_t cache_size_mb;           /* 128MB NPU cache size */
    size_t line_size_bytes;         /* Cache line size */
    size_t associativity;           /* Cache associativity */
    double hit_latency_ns;         /* Cache hit latency */
    double miss_penalty_ns;         /* Cache miss penalty */
    bool gna_enabled;              /* GNA acceleration enabled */
    size_t gna_workgroup_size;     /* GNA workgroup size */
} qihse_meteor_lake_npu_cache_t;

/**
 * Vector database preload configuration.
 */
typedef struct qihse_vector_db_preload_s {
    char* db_path;                 /* Path to vector database */
    size_t preload_batch_size;     /* Batch size for preloading */
    double preload_threshold;      /* Similarity threshold for preloading */
    size_t max_preload_vectors;    /* Maximum vectors to preload */
    bool enable_incremental_load;  /* Enable incremental loading */
    size_t preload_window_mb;      /* Memory window for preloading */
} qihse_vector_db_preload_t;

/* ============================================================================
 * UMA MANAGER LIFECYCLE
 * ============================================================================ */

/**
 * Create UMA manager.
 *
 * @param memory_manager Underlying memory manager
 * @param migration_policy Default migration policy
 * @return UMA manager, or NULL on failure
 */
qihse_uma_manager_t qihse_uma_create(
    qihse_memory_manager_t memory_manager,
    qihse_uma_migration_policy_t migration_policy
);

/**
 * Destroy UMA manager.
 *
 * @param uma UMA manager to destroy
 */
void qihse_uma_destroy(qihse_uma_manager_t uma);

/* ============================================================================
 * UNIFIED MEMORY OPERATIONS
 * ============================================================================ */

/**
 * Allocate unified memory accessible by multiple devices.
 *
 * @param uma UMA manager
 * @param size Size in bytes
 * @param devices Array of devices that need access
 * @param num_devices Number of devices in array
 * @return Unified address, or NULL on failure
 */
qihse_uma_address_t* qihse_uma_allocate(
    qihse_uma_manager_t uma,
    size_t size,
    const int* devices,
    size_t num_devices
);

/**
 * Free unified memory.
 *
 * @param uma UMA manager
 * @param address Unified address to free
 */
void qihse_uma_free(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address
);

/**
 * Access unified memory from specific device (may trigger migration).
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param device Accessing device
 * @return Device-local pointer, or NULL on failure
 */
void* qihse_uma_access(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    int device
);

/**
 * Release access to unified memory.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param device Device releasing access
 */
void qihse_uma_release(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    int device
);

/* ============================================================================
 * MIGRATION CONTROL
 * ============================================================================ */

/**
 * Explicitly migrate unified memory to target device.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param target_device Target device
 * @return true on success, false on failure
 */
bool qihse_uma_migrate(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    qihse_device_type_t target_device
);

/**
 * Set migration policy for unified address.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param policy New migration policy
 */
void qihse_uma_set_migration_policy(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    qihse_uma_migration_policy_t policy
);

/**
 * Get current migration policy.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @return Current migration policy
 */
qihse_uma_migration_policy_t qihse_uma_get_migration_policy(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address
);

/* ============================================================================
 * MEMORY COHERENCE
 * ============================================================================ */

/**
 * Ensure memory coherence across all devices.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @return true on success, false on failure
 */
bool qihse_uma_synchronize(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address
);

/**
 * Flush modifications from device cache.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param device Device to flush from
 * @return true on success, false on failure
 */
bool qihse_uma_flush(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    int device
);

/* ============================================================================
 * PERFORMANCE MONITORING
 * ============================================================================ */

/**
 * UMA performance statistics.
 */
typedef struct qihse_uma_stats_s {
    uint64_t total_migrations;       /* Total migration operations */
    uint64_t total_accesses;         /* Total access operations */
    uint64_t cache_hits;             /* Unified memory cache hits */
    uint64_t cache_misses;           /* Unified memory cache misses */
    double avg_migration_time;       /* Average migration time (microseconds) */
    double coherence_overhead;       /* Coherence maintenance overhead */
} qihse_uma_stats_t;

/**
 * Get UMA performance statistics.
 *
 * @param uma UMA manager
 * @param stats Output statistics
 * @return true on success, false on failure
 */
bool qihse_uma_get_stats(
    qihse_uma_manager_t uma,
    qihse_uma_stats_t* stats
);

/**
 * Reset UMA statistics counters.
 *
 * @param uma UMA manager
 */
void qihse_uma_reset_stats(qihse_uma_manager_t uma);

/* ============================================================================
 * PHASE 2: MEMORY SUPERPOSITION ENHANCEMENTS
 * ============================================================================ */

/**
 * Initialize Meteor Lake NPU cache for QIHSE operations.
 * Automatically detects and optimizes for actual HPU cache size.
 *
 * @param cache Cache configuration to initialize
 * @return true on success, false on failure
 */
bool qihse_uma_init_meteor_lake_npu_cache(qihse_meteor_lake_npu_cache_t* cache);

/**
 * Get the detected HPU cache size in MB.
 *
 * @param cache Initialized cache configuration
 * @return Cache size in MB
 */
size_t qihse_uma_get_detected_cache_size(const qihse_meteor_lake_npu_cache_t* cache);

/**
 * Optimize UMA policies based on detected cache size.
 *
 * @param uma UMA manager to optimize
 * @param cache Detected cache configuration
 * @return true on success, false on failure
 */
bool qihse_uma_optimize_for_cache_size(qihse_uma_manager_t uma,
                                       const qihse_meteor_lake_npu_cache_t* cache);

/**
 * Create memory superposition across RAM/GPU/NPU with intelligent placement.
 *
 * @param uma UMA manager
 * @param size Size in bytes
 * @param devices Array of devices that need access
 * @param num_devices Number of devices in array
 * @param superposition_state Initial superposition state
 * @return Unified address with superposition, or NULL on failure
 */
qihse_uma_address_t* qihse_uma_allocate_superposition(
    qihse_uma_manager_t uma,
    size_t size,
    const int* devices,
    size_t num_devices,
    qihse_memory_superposition_state_t superposition_state
);

/**
 * Access unified memory with temperature-aware migration.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param device Accessing device
 * @param temperature Current system temperature in Celsius
 * @return Device-local pointer, or NULL on failure
 */
void* qihse_uma_access_temperature_aware(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    int device,
    double temperature
);

/**
 * Enable vector database pre-loading for instant access.
 *
 * @param uma UMA manager
 * @param preload Preload configuration
 * @return true on success, false on failure
 */
bool qihse_uma_enable_vector_db_preload(
    qihse_uma_manager_t uma,
    const qihse_vector_db_preload_t* preload
);

/**
 * Preload vector database entries into fast memory tiers.
 *
 * @param uma UMA manager
 * @param query_vector Query vector for similarity preloading
 * @param vector_dims Dimension count of vectors
 * @return true on success, false on failure
 */
bool qihse_uma_preload_similar_vectors(
    qihse_uma_manager_t uma,
    const float* query_vector,
    size_t vector_dims
);

/**
 * Get current memory superposition state.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @return Current superposition state
 */
qihse_memory_superposition_state_t qihse_uma_get_superposition_state(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address
);

/**
 * Set memory superposition state with policy.
 *
 * @param uma UMA manager
 * @param address Unified address
 * @param state New superposition state
 * @param temperature_trigger Temperature trigger for state changes
 */
void qihse_uma_set_superposition_state(
    qihse_uma_manager_t uma,
    qihse_uma_address_t* address,
    qihse_memory_superposition_state_t state,
    qihse_temperature_trigger_t temperature_trigger
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_UMA_H */
