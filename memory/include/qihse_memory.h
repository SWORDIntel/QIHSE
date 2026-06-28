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
#include "../../orchestration/include/qihse_hetero.h"  /* qihse_device_type_t */

/* Forward declarations */

struct qihse_memory_migration_scheduler_s;

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
#define QIHSE_MEMORY_MIGRATION_DECISION_REASON_SIZE 128u

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

/**
 * Migration decision outcome used by planner/scheduler visibility APIs.
 */
typedef enum qihse_memory_migration_decision_reason_e {
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_UNKNOWN = 0,
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_ACCEPTED = 1,
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_INVALID_ARGUMENTS = 2,
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_NOT_MIGRATABLE = 3,
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_ALREADY_PLACED = 4,
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_POLICY_REJECT = 5,
    QIHSE_MEMORY_MIGRATION_DECISION_REASON_BELOW_SCORE_THRESHOLD = 6
} qihse_memory_migration_decision_reason_t;

/**
 * Internal scoring pieces used by migration scheduling.
 */
typedef struct qihse_memory_migration_scoring_breakdown_s {
    double residency_component;
    double access_component;
    double coherence_component;
    double target_component;
    double policy_component;
    double minimum_score;
    uint64_t hot_access_threshold;
} qihse_memory_migration_scoring_breakdown_t;

/**
 * Planner-facing migration decision detail for scheduler/policy debugging.
 */
typedef struct qihse_memory_migration_decision_s {
    qihse_memory_buffer_t* buffer;
    int target_device;
    qihse_memory_type_t source_type;
    qihse_memory_type_t target_type;

    qihse_memory_migration_decision_reason_t reason;
    bool accepted;
    bool zero_copy;
    bool copy_required;
    bool preserves_coherence;

    qihse_memory_migration_scoring_breakdown_t scoring;
    double score;
    char plan_reason[QIHSE_MEMORY_MIGRATION_DECISION_REASON_SIZE];
} qihse_memory_migration_decision_t;

/**
 * Convert reason code to string.
 */
const char* qihse_memory_migration_decision_reason_name(
    qihse_memory_migration_decision_reason_t reason
);

/**
 * Inspect a migration candidate's scheduler/policy score and reason without
 * enqueuing it.
 *
 * @param buffer Migration candidate
 * @param target_device Target device
 * @param target_type Target memory type
 * @param out_decision Output decision trace
 * @return true on successful inspection, false on invalid arguments
 */
bool qihse_memory_migration_decision_inspect(
    const qihse_memory_buffer_t* buffer,
    int target_device,
    qihse_memory_type_t target_type,
    qihse_memory_migration_decision_t* out_decision
);

/**
 * Format a migration decision for structured logs and external diagnostics.
 *
 * @param buffer Output buffer
 * @param buffer_size Output capacity
 * @param decision Decision created by qihse_memory_migration_decision_inspect
 * @return Number of characters written (excluding terminator)
 */
size_t qihse_memory_migration_decision_format(
    char* buffer,
    size_t buffer_size,
    const qihse_memory_migration_decision_t* decision
);

/**
 * Start (reset) a caller-owned maintenance pass over a migration scheduler.
 *
 * The maintenance surface remains caller-owned and explicit: no background
 * worker threads are spawned by the core library.
 *
 * @param manager Memory manager
 * @param scheduler Scheduler instance created by the caller
 * @return true on successful start/reset, false on invalid arguments
 */
bool qihse_memory_maintenance_start(
    qihse_memory_manager_t manager,
    struct qihse_memory_migration_scheduler_s* scheduler
);

/**
 * Build a deterministic maintenance candidate set from currently tracked buffers
 * and enqueue them into the provided scheduler.
 *
 * Deterministic selection is based on tracked-buffer state: access_count,
 * residency_score, and memory-type delta heuristics.
 *
 * @param manager Memory manager
 * @param scheduler Scheduler to populate with migration candidates
 * @param target_device Preferred target device for maintenance migrations
 * @param max_candidates Maximum number of candidates to enqueue (0 means no explicit
 * limit; scheduler capacity controls final stop)
 * @return Number of candidates enqueued
 */
size_t qihse_memory_maintenance_snapshot(
    qihse_memory_manager_t manager,
    struct qihse_memory_migration_scheduler_s* scheduler,
    int target_device,
    size_t max_candidates
);

/**
 * Execute one explicit maintenance step by draining up to max_tasks tasks from
 * the populated migration scheduler.
 *
 * @param manager Memory manager
 * @param scheduler Scheduler containing migration work
 * @param max_tasks Max tasks to execute in this step
 * @return Number of tasks successfully executed
 */
size_t qihse_memory_maintenance_step(
    qihse_memory_manager_t manager,
    struct qihse_memory_migration_scheduler_s* scheduler,
    size_t max_tasks
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
