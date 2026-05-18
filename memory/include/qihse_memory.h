/*
 * QIHSE - Unified Memory Management
 *
 * Core memory management API for quantum-inspired search operations.
 * Provides unified buffer allocation, tracking, and lifecycle management.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_MEMORY_H
#define QIHSE_MEMORY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../core/qihse_abi.h"  /* Phase 0 ABI integration */

/* Forward declarations */
typedef enum qihse_device_type_e qihse_device_type_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * MEMORY TYPES AND FLAGS
 * ============================================================================ */

/**
 * Memory allocation types for different use cases.
 */
typedef enum qihse_memory_type_e {
    QIHSE_MEM_HOST = 0,           /* Standard host memory (malloc) */
    QIHSE_MEM_PINNED = 1,         /* Pinned host memory for DMA */
    QIHSE_MEM_DEVICE = 2,         /* Device-specific memory (GPU/NPU) */
    QIHSE_MEM_UNIFIED = 3,        /* Unified memory (accessible by all devices) */
    QIHSE_MEM_HMA_SUPERPOSITION = 4, /* HMA superposition buffer */
    QIHSE_MEM_HMA_INTERACTION = 5,   /* HMA interaction cache */
    QIHSE_MEM_HMA_ENTANGLEMENT = 6,  /* HMA entanglement fabric */
    /* QIHSE-NOT_STISLA Integration: Anchor table memory */
    QIHSE_MEM_ANCHOR_TABLE = 7,   /* Memory-bounded anchor tables */
    QIHSE_MEM_ANCHOR_WORKSPACE = 8, /* Anchor learning workspace */
} qihse_memory_type_t;

/**
 * Memory access patterns for optimization.
 */
typedef enum qihse_memory_access_e {
    QIHSE_ACCESS_RANDOM = 0,      /* Random access pattern */
    QIHSE_ACCESS_SEQUENTIAL = 1,  /* Sequential access pattern */
    QIHSE_ACCESS_STRIDED = 2,     /* Strided access pattern */
    QIHSE_ACCESS_BLOCKED = 3,     /* Block-wise access pattern */
    QIHSE_ACCESS_SIMD = 4,        /* SIMD-optimized access */
} qihse_memory_access_t;

/**
 * Quantum-inspired workload phase for tier placement.
 */
typedef enum qihse_memory_phase_e {
    QIHSE_MEMORY_PHASE_INIT = 0,          /* Initialization / bulk ingest */
    QIHSE_MEMORY_PHASE_SUPERPOSITION = 1, /* Active state-vector work */
    QIHSE_MEMORY_PHASE_INTERACTION = 2,   /* Coupling / interaction matrix work */
    QIHSE_MEMORY_PHASE_AMPLIFICATION = 3, /* Iterative amplification */
    QIHSE_MEMORY_PHASE_MEASUREMENT = 4,   /* Readout / result materialization */
} qihse_memory_phase_t;

/**
 * Workload description used by the UMA/HMA placement planner.
 */
typedef struct qihse_memory_workload_analysis_s {
    qihse_memory_access_t access_pattern; /* Dominant access pattern */
    double read_write_ratio;              /* Reads per write; 0 means unknown */
    size_t working_set_size;              /* Active bytes */
    double temporal_locality;             /* 0..1 reuse score */
    double spatial_locality;              /* 0..1 adjacency score */
    size_t superposition_dims;            /* Active state dimensions */
    double entanglement_density;          /* 0..1 correlation density */
    qihse_memory_phase_t phase;           /* Current algorithm phase */
} qihse_memory_workload_analysis_t;

/**
 * Capacity/latency model for HMA placement. Values may be approximate.
 */
typedef struct qihse_memory_tier_topology_s {
    size_t capacity;             /* Tier capacity in bytes */
    double bandwidth_gbps;       /* Estimated bandwidth */
    double latency_ns;           /* Estimated latency */
    bool coherent;               /* Hardware/software coherence available */
} qihse_memory_tier_topology_t;

typedef struct qihse_memory_topology_s {
    qihse_memory_tier_topology_t superposition_buffer;
    qihse_memory_tier_topology_t interaction_cache;
    qihse_memory_tier_topology_t entanglement_fabric;
    double inter_tier_bandwidth_gbps;
    size_t numa_nodes;
} qihse_memory_topology_t;

/**
 * Memory allocation flags.
 */
#define QIHSE_MEM_ZERO     (1u << 0)  /* Zero-initialize allocation */
#define QIHSE_MEM_TRACKED  (1u << 1)  /* Track buffer in manager registry */
#define QIHSE_MEM_SHARED   (1u << 2)  /* Shared across devices */

/* ============================================================================
 * MEMORY BUFFER MANAGEMENT
 * ============================================================================ */

/**
 * Extended memory buffer with metadata for UMA/HMA operations.
 */
typedef struct qihse_memory_buffer_s {
    qihse_buffer_t abi_buffer;    /* Phase 0 ABI compatibility */

    /* Extended metadata */
    qihse_memory_type_t mem_type; /* Memory type */
    qihse_memory_access_t access_pattern; /* Access pattern hint */
    uint32_t flags;               /* Allocation flags */

    /* Usage tracking */
    size_t logical_size;          /* Logical data size */
    size_t allocated_size;        /* Actually allocated size */
    size_t alignment;             /* Memory alignment */

    /* Device placement */
    int preferred_device;         /* Preferred device placement (as int) */
    bool is_migratable;           /* Can migrate between devices */

    /* Performance tracking */
    uint64_t access_count;       /* Number of accesses */
    uint64_t last_access_time;    /* Last access timestamp */
    double residency_score;       /* Migration priority score */

    /* Coherence tracking */
    uint64_t coherence_version;           /* Current coherence version */
    uint64_t coherence_last_read_version; /* Last read-observed version */
    uint64_t coherence_last_write_version; /* Last write-produced version */
    uint32_t coherence_state;             /* qihse_memory_coherence_state_t */
    bool coherence_shared;                /* Shared clean residency */

    /* HMA integration */
    void* hma_metadata;           /* HMA-specific metadata */
} qihse_memory_buffer_t;

/* ============================================================================
 * MEMORY MANAGER INTERFACE
 * ============================================================================ */

/**
 * Memory manager context.
 */
typedef struct qihse_memory_manager_s* qihse_memory_manager_t;

/**
 * Create memory manager with specified backend.
 *
 * @param ctx QIHSE context (Phase 0 ABI)
 * @param backend_type Memory backend type (UMA, HMA, etc.)
 * @return Memory manager handle, or NULL on failure
 */
qihse_memory_manager_t qihse_memory_manager_create(
    qihse_context_t ctx,
    const char* backend_type
);

/**
 * Destroy memory manager.
 *
 * @param manager Memory manager to destroy
 */
void qihse_memory_manager_destroy(qihse_memory_manager_t manager);

/* ============================================================================
 * BUFFER ALLOCATION AND MANAGEMENT
 * ============================================================================ */

/**
 * Allocate memory buffer with specified characteristics.
 *
 * @param manager Memory manager
 * @param size Size in bytes
 * @param mem_type Memory type
 * @param access_pattern Expected access pattern
 * @param flags Allocation flags
 * @return Allocated buffer, or NULL on failure
 */
qihse_memory_buffer_t* qihse_memory_allocate(
    qihse_memory_manager_t manager,
    size_t size,
    qihse_memory_type_t mem_type,
    qihse_memory_access_t access_pattern,
    uint32_t flags
);

/**
 * Free memory buffer.
 *
 * @param manager Memory manager
 * @param buffer Buffer to free
 */
void qihse_memory_free(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer
);

/**
 * Resize existing buffer.
 *
 * @param manager Memory manager
 * @param buffer Buffer to resize
 * @param new_size New size in bytes
 * @return true on success, false on failure
 */
bool qihse_memory_resize(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    size_t new_size
);

/* ============================================================================
 * DATA TRANSFER AND MIGRATION
 * ============================================================================ */

/**
 * Copy data between buffers.
 *
 * @param manager Memory manager
 * @param dst Destination buffer
 * @param dst_offset Offset in destination
 * @param src Source buffer
 * @param src_offset Offset in source
 * @param size Size to copy
 * @return true on success, false on failure
 */
bool qihse_memory_copy(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* dst,
    size_t dst_offset,
    const qihse_memory_buffer_t* src,
    size_t src_offset,
    size_t size
);

/**
 * Migrate buffer to different device/memory type.
 *
 * @param manager Memory manager
 * @param buffer Buffer to migrate
 * @param target_device Target device
 * @param target_type Target memory type
 * @return true on success, false on failure
 */
bool qihse_memory_migrate(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type
);

/**
 * Prefetch buffer to specific device.
 *
 * @param manager Memory manager
 * @param buffer Buffer to prefetch
 * @param device Target device
 * @return true on success, false on failure
 */
bool qihse_memory_prefetch(
    qihse_memory_manager_t manager,
    qihse_memory_buffer_t* buffer,
    int device
);

/* ============================================================================
 * MEMORY STATISTICS AND MONITORING
 * ============================================================================ */

/**
 * Memory usage statistics.
 */
typedef struct qihse_memory_stats_s {
    size_t total_allocated;       /* Total bytes allocated */
    size_t total_used;            /* Total bytes in use */
    size_t peak_usage;            /* Peak memory usage */
    size_t num_buffers;           /* Number of active buffers */

    /* Per-type statistics */
    size_t host_memory;           /* Host memory usage */
    size_t device_memory;         /* Device memory usage */
    size_t unified_memory;        /* Unified memory usage */

    /* Performance metrics */
    uint64_t total_allocations;   /* Total allocation operations */
    uint64_t total_frees;         /* Total free operations */
    uint64_t total_migrations;    /* Total migration operations */
    double avg_allocation_time;   /* Average allocation time (microseconds) */
} qihse_memory_stats_t;

/**
 * Get memory usage statistics.
 *
 * @param manager Memory manager
 * @param stats Output statistics
 * @return true on success, false on failure
 */
bool qihse_memory_get_stats(
    qihse_memory_manager_t manager,
    qihse_memory_stats_t* stats
);

/**
 * Reset memory statistics counters.
 *
 * @param manager Memory manager
 */
void qihse_memory_reset_stats(qihse_memory_manager_t manager);

/* ============================================================================
 * MEMORY POLICY AND OPTIMIZATION
 * ============================================================================ */

/**
 * Memory placement policy.
 */
typedef enum qihse_memory_policy_e {
    QIHSE_POLICY_FIRST_FIT = 0,   /* Allocate in first available location */
    QIHSE_POLICY_BEST_FIT = 1,    /* Choose best location for access pattern */
    QIHSE_POLICY_DEVICE_LOCAL = 2, /* Prefer device-local memory */
    QIHSE_POLICY_LOW_LATENCY = 3, /* Optimize for low latency */
    QIHSE_POLICY_HIGH_BANDWIDTH = 4, /* Optimize for high bandwidth */
    QIHSE_POLICY_ENERGY_EFFICIENT = 5, /* Optimize for energy efficiency */
} qihse_memory_policy_t;

/**
 * Set memory placement policy.
 *
 * @param manager Memory manager
 * @param policy New placement policy
 */
void qihse_memory_set_policy(
    qihse_memory_manager_t manager,
    qihse_memory_policy_t policy
);

/**
 * Get current memory placement policy.
 *
 * @param manager Memory manager
 * @return Current policy
 */
qihse_memory_policy_t qihse_memory_get_policy(qihse_memory_manager_t manager);

/**
 * Fill a conservative default HMA topology used when no hardware probe is
 * available.
 *
 * @param topology Output topology
 * @return true on success, false on invalid arguments
 */
bool qihse_memory_default_topology(qihse_memory_topology_t* topology);

/**
 * Recommend an HMA/UMA memory type for a workload. If topology is NULL, a
 * conservative default topology is used.
 *
 * @param analysis Workload characteristics
 * @param topology Optional hardware topology
 * @param out_type Recommended memory type
 * @return true on success, false on invalid arguments
 */
bool qihse_memory_recommend_type(
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    qihse_memory_type_t* out_type
);

/**
 * Allocate a buffer using the workload-aware HMA placement planner.
 *
 * @param manager Memory manager
 * @param analysis Workload characteristics used for placement
 * @param topology Optional hardware topology; NULL uses defaults
 * @param flags Allocation flags
 * @return Allocated buffer, or NULL on failure
 */
qihse_memory_buffer_t* qihse_memory_allocate_for_workload(
    qihse_memory_manager_t manager,
    const qihse_memory_workload_analysis_t* analysis,
    const qihse_memory_topology_t* topology,
    uint32_t flags
);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * Get recommended alignment for memory type.
 *
 * @param mem_type Memory type
 * @return Recommended alignment in bytes
 */
size_t qihse_memory_get_alignment(qihse_memory_type_t mem_type);

/**
 * Check if memory type is accessible by device.
 *
 * @param mem_type Memory type
 * @param device Device type
 * @return true if accessible, false otherwise
 */
bool qihse_memory_is_accessible(
    qihse_memory_type_t mem_type,
    qihse_device_type_t device
);

/**
 * Get string representation of memory type.
 *
 * @param mem_type Memory type
 * @return String representation
 */
const char* qihse_memory_type_string(qihse_memory_type_t mem_type);

/* ============================================================================
 * QIHSE-NOT_STISLA INTEGRATION: ANCHOR TABLE MEMORY MANAGEMENT
 * ============================================================================ */

/**
 * Anchor table memory manager - integrates NOT_STISLA bounded memory management.
 */
typedef struct qihse_anchor_memory_manager_s* qihse_anchor_memory_manager_t;

/**
 * Create anchor memory manager with bounded memory limits.
 *
 * @param manager Parent memory manager
 * @param max_memory_mb Maximum memory budget in MB
 * @param enable_lru Enable LRU pruning when limits exceeded
 * @return Anchor memory manager, or NULL on failure
 */
qihse_anchor_memory_manager_t qihse_anchor_memory_manager_create(
    qihse_memory_manager_t manager,
    size_t max_memory_mb,
    bool enable_lru
);

/**
 * Destroy anchor memory manager.
 *
 * @param anchor_manager Anchor memory manager to destroy
 */
void qihse_anchor_memory_manager_destroy(qihse_anchor_memory_manager_t anchor_manager);

/**
 * Allocate anchor table with memory bounds checking.
 *
 * @param anchor_manager Anchor memory manager
 * @param max_anchors Maximum number of anchors
 * @param workload_type Workload type for optimization
 * @return Anchor table buffer, or NULL on failure/out of memory
 */
qihse_memory_buffer_t* qihse_anchor_memory_allocate_table(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t max_anchors,
    int workload_type
);

/**
 * Allocate anchor learning workspace.
 *
 * @param anchor_manager Anchor memory manager
 * @param workspace_size Required workspace size
 * @return Workspace buffer, or NULL on failure
 */
qihse_memory_buffer_t* qihse_anchor_memory_allocate_workspace(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t workspace_size
);

/**
 * Check if anchor table allocation exceeds memory limits.
 *
 * @param anchor_manager Anchor memory manager
 * @param requested_size Size to check
 * @return true if allocation fits, false if it exceeds limits
 */
bool qihse_anchor_memory_check_limits(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t requested_size
);

/**
 * Perform LRU pruning to free memory for new allocations.
 *
 * @param anchor_manager Anchor memory manager
 * @param target_free_bytes Amount of memory to free
 * @return Number of anchors pruned
 */
size_t qihse_anchor_memory_prune_lru(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t target_free_bytes
);

/**
 * Get anchor memory usage statistics.
 *
 * @param anchor_manager Anchor memory manager
 * @param current_usage_bytes Current memory usage
 * @param max_usage_bytes Maximum allowed usage
 * @param num_tables Current number of active tables
 * @param pruned_count Total anchors pruned due to memory limits
 */
void qihse_anchor_memory_get_stats(
    qihse_anchor_memory_manager_t anchor_manager,
    size_t* current_usage_bytes,
    size_t* max_usage_bytes,
    size_t* num_tables,
    size_t* pruned_count
);

/**
 * Optimize anchor table memory layout for workload.
 *
 * @param anchor_manager Anchor memory manager
 * @param table Anchor table to optimize
 * @param workload_type Workload type
 * @return true on success, false on failure
 */
bool qihse_anchor_memory_optimize_for_workload(
    qihse_anchor_memory_manager_t anchor_manager,
    qihse_memory_buffer_t* table,
    int workload_type
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_MEMORY_H */
