/*
 * QIHSE - Holographic Memory Architecture (HMA)
 *
 * Three-tier quantum-inspired memory hierarchy for optimal search performance.
 * Implements superposition buffers, interaction caches, and entanglement fabrics.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_HMA_H
#define QIHSE_HMA_H

#include <stdatomic.h>
#include "qihse_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * HMA TIERS AND COMPONENTS
 * ============================================================================ */

/**
 * HMA tier enumeration.
 */
typedef enum qihse_hma_tier_e {
    QIHSE_HMA_TIER_SUPERPOSITION = 0,  /* Fast superposition state storage */
    QIHSE_HMA_TIER_INTERACTION = 1,    /* Medium-term interaction caching */
    QIHSE_HMA_TIER_ENTANGLEMENT = 2,   /* Long-term entanglement fabric */
    QIHSE_HMA_TIER_MAX = 3
} qihse_hma_tier_t;

/**
 * HMA component types within each tier.
 */
typedef enum qihse_hma_component_e {
    QIHSE_HMA_COMP_BUFFER = 0,     /* Raw data buffer */
    QIHSE_HMA_COMP_INDEX = 1,      /* Index/metadata storage */
    QIHSE_HMA_COMP_TEMP = 2,       /* Temporary computation space */
    QIHSE_HMA_COMP_CACHE = 3,      /* Cached results */
    QIHSE_HMA_COMP_MAX = 4
} qihse_hma_component_t;

/* ============================================================================
 * SUPERPOSITION BUFFER (TIER 0)
 * ============================================================================ */

/**
 * Superposition buffer for storing quantum-inspired state vectors.
 * Optimized for high-frequency access patterns in RFF and superposition operations.
 */
typedef struct qihse_superposition_buffer_s {
    qihse_memory_buffer_t* state_vectors;    /* State vector storage */
    qihse_memory_buffer_t* amplitude_cache;  /* Amplitude lookup cache */
    qihse_memory_buffer_t* phase_tracking;   /* Phase coherence tracking */

    /* Buffer metadata */
    size_t max_states;               /* Maximum number of states */
    size_t vector_dims;              /* Dimensions per state vector */
    size_t active_states;            /* Currently active states */

    /* Performance tracking */
    uint64_t coherence_operations;   /* Coherence maintenance operations */
    uint64_t superposition_updates;  /* State update operations */
    double coherence_score;          /* Current coherence quality */

    /* Quantum-inspired parameters */
    double decoherence_rate;         /* Natural decoherence rate */
    double measurement_threshold;    /* Measurement confidence threshold */
    float global_phase;              /* Global quantum phase offset */
    float measurement_confidence;    /* Confidence in quantum measurement */
} qihse_superposition_buffer_t;

/* ============================================================================
 * INTERACTION CACHE (TIER 1)
 * ============================================================================ */

/**
 * Interaction cache for storing frequently accessed data relationships.
 * Implements associative memory patterns for search optimization.
 */
typedef struct qihse_interaction_cache_s {
    qihse_memory_buffer_t* interaction_matrix;  /* Interaction strength matrix */
    qihse_memory_buffer_t* relationship_index;  /* Relationship lookup index */
    qihse_memory_buffer_t* temporal_weights;    /* Time-decay weights */

    /* Cache configuration */
    size_t cache_lines;              /* Number of cache lines */
    size_t associativity;            /* Cache associativity */
    size_t line_size;                /* Bytes per cache line */

    /* Replacement policy */
    qihse_memory_buffer_t* access_history;     /* LRU/access tracking */
    qihse_memory_buffer_t* frequency_counts;  /* Access frequency tracking */

    /* Performance metrics */
    atomic_uint_fast64_t cache_hits;           /* Cache hit count (atomic) */
    atomic_uint_fast64_t cache_misses;         /* Cache miss count (atomic) */
    double hit_ratio;                /* Current hit ratio */

    /* Adaptive parameters */
    double learning_rate;            /* Adaptation learning rate */
    size_t temporal_window;          /* Temporal analysis window */
} qihse_interaction_cache_t;

/* ============================================================================
 * ENTANGLEMENT FABRIC (TIER 2)
 * ============================================================================ */

/**
 * Entanglement fabric for long-term storage of complex data relationships.
 * Implements distributed storage with quantum-inspired coherence properties.
 */
typedef struct qihse_entanglement_fabric_s {
    qihse_memory_buffer_t* fabric_nodes;       /* Storage nodes */
    qihse_memory_buffer_t* coherence_matrix;   /* Inter-node coherence */
    qihse_memory_buffer_t* entanglement_graph; /* Relationship graph */

    /* Fabric topology */
    size_t num_nodes;                /* Number of storage nodes */
    size_t connections_per_node;     /* Connectivity degree */
    size_t replication_factor;       /* Data replication factor */

    /* Coherence management */
    qihse_memory_buffer_t* coherence_states;   /* Node coherence states */
    qihse_memory_buffer_t* migration_paths;    /* Data migration paths */

    /* Distributed operations */
    uint64_t entanglement_operations; /* Entanglement maintenance ops */
    uint64_t coherence_checks;        /* Coherence verification ops */
    double fabric_stability;          /* Overall fabric stability */

    /* Quantum parameters */
    double entanglement_strength;     /* Base entanglement strength */
    double decoherence_threshold;     /* Critical decoherence level */
    size_t max_entanglement_distance; /* Maximum entanglement range */
} qihse_entanglement_fabric_t;

/* ============================================================================
 * HMA MANAGER AND INTEGRATION
 * ============================================================================ */

/**
 * Complete HMA hierarchy manager.
 */
typedef struct qihse_hma_manager_s {
    /* Memory manager integration */
    qihse_memory_manager_t memory_manager;

    /* HMA tier components */
    qihse_superposition_buffer_t* superposition;
    qihse_interaction_cache_t* interaction_cache;
    qihse_entanglement_fabric_t* entanglement_fabric;

    /* Configuration */
    size_t superposition_size_mb;    /* Superposition buffer size */
    size_t interaction_cache_size_mb; /* Interaction cache size */
    size_t entanglement_fabric_size_mb; /* Entanglement fabric size */

    /* Performance tracking */
    uint64_t total_operations;       /* Total HMA operations */
    uint64_t cache_operations;       /* Cache-related operations */
    double avg_access_latency;       /* Average access latency */

    /* Adaptation state */
    bool adaptive_enabled;           /* Adaptive optimization enabled */
    uint64_t adaptation_cycles;      /* Number of adaptation cycles */
} *qihse_hma_manager_t;

/**
 * Create HMA hierarchy manager.
 *
 * @param memory_manager Underlying memory manager
 * @param superposition_mb Size of superposition buffer (MB)
 * @param interaction_mb Size of interaction cache (MB)
 * @param entanglement_mb Size of entanglement fabric (MB)
 * @return HMA manager, or NULL on failure
 */
qihse_hma_manager_t qihse_hma_create(
    qihse_memory_manager_t memory_manager,
    size_t superposition_mb,
    size_t interaction_mb,
    size_t entanglement_mb
);

/**
 * Destroy HMA hierarchy manager.
 *
 * @param hma HMA manager to destroy
 */
void qihse_hma_destroy(qihse_hma_manager_t hma);

/* ============================================================================
 * SUPERPOSITION BUFFER OPERATIONS
 * ============================================================================ */

/**
 * Store state vector in superposition buffer.
 *
 * @param hma HMA manager
 * @param state_id State identifier
 * @param vector State vector data
 * @param dims Vector dimensions
 * @return true on success, false on failure
 */
bool qihse_hma_superposition_store(
    qihse_hma_manager_t hma,
    uint64_t state_id,
    const float* vector,
    size_t dims
);

/**
 * Retrieve state vector from superposition buffer.
 *
 * @param hma HMA manager
 * @param state_id State identifier
 * @param vector Output vector buffer
 * @param dims Vector dimensions
 * @return true on success, false on failure
 */
bool qihse_hma_superposition_retrieve(
    qihse_hma_manager_t hma,
    uint64_t state_id,
    float* vector,
    size_t dims
);

/**
 * Update superposition state with quantum-inspired coherence.
 *
 * @param hma HMA manager
 * @param state_id State identifier
 * @param phase_shift Phase shift in radians
 * @param amplitude_scale Amplitude scaling factor
 * @return true on success, false on failure
 */
bool qihse_hma_superposition_update(
    qihse_hma_manager_t hma,
    uint64_t state_id,
    double phase_shift,
    double amplitude_scale
);

/* ============================================================================
 * INTERACTION CACHE OPERATIONS
 * ============================================================================ */

/**
 * Cache interaction data with temporal weighting.
 *
 * @param hma HMA manager
 * @param key Interaction key
 * @param data Interaction data
 * @param size Data size in bytes
 * @param weight Temporal weight (importance)
 * @return true on success, false on failure
 */
bool qihse_hma_cache_store(
    qihse_hma_manager_t hma,
    uint64_t key,
    const void* data,
    size_t size,
    double weight
);

/**
 * Retrieve cached interaction data.
 *
 * @param hma HMA manager
 * @param key Interaction key
 * @param data Output data buffer
 * @param size Data size in bytes
 * @return true on success, false on failure
 */
bool qihse_hma_cache_retrieve(
    qihse_hma_manager_t hma,
    uint64_t key,
    void* data,
    size_t size
);

/**
 * Update cache with new access patterns.
 *
 * @param hma HMA manager
 * @param access_pattern Array of recently accessed keys
 * @param num_accesses Number of accesses
 */
void qihse_hma_cache_update_access(
    qihse_hma_manager_t hma,
    const uint64_t* access_pattern,
    size_t num_accesses
);

/* ============================================================================
 * ENTANGLEMENT FABRIC OPERATIONS
 * ============================================================================ */

/**
 * Store data in entanglement fabric with replication.
 *
 * @param hma HMA manager
 * @param key Data key
 * @param data Data to store
 * @param size Data size in bytes
 * @return true on success, false on failure
 */
bool qihse_hma_fabric_store(
    qihse_hma_manager_t hma,
    uint64_t key,
    const void* data,
    size_t size
);

/**
 * Retrieve data from entanglement fabric.
 *
 * @param hma HMA manager
 * @param key Data key
 * @param data Output data buffer
 * @param size Data size in bytes
 * @return true on success, false on failure
 */
bool qihse_hma_fabric_retrieve(
    qihse_hma_manager_t hma,
    uint64_t key,
    void* data,
    size_t size
);

/**
 * Perform coherence maintenance on entanglement fabric.
 *
 * @param hma HMA manager
 * @return true on success, false on failure
 */
bool qihse_hma_fabric_maintain_coherence(qihse_hma_manager_t hma);

/* ============================================================================
 * HMA OPTIMIZATION AND ADAPTATION
 * ============================================================================ */

/**
 * Optimize HMA configuration based on access patterns.
 *
 * @param hma HMA manager
 * @param access_history Array of recent access patterns
 * @param history_length Length of access history
 */
void qihse_hma_optimize_configuration(
    qihse_hma_manager_t hma,
    const uint64_t* access_history,
    size_t history_length
);

/**
 * Get HMA performance statistics.
 *
 * @param hma HMA manager
 * @param tier_stats Output statistics for each tier
 * @return true on success, false on failure
 */
bool qihse_hma_get_statistics(
    qihse_hma_manager_t hma,
    qihse_memory_stats_t tier_stats[QIHSE_HMA_TIER_MAX]
);

/**
 * Reset HMA statistics and counters.
 *
 * @param hma HMA manager
 */
void qihse_hma_reset_statistics(qihse_hma_manager_t hma);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_HMA_H */
