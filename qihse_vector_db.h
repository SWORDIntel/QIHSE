/*
 * QIHSE - Vector Database Integration
 *
 * Integration between QIHSE search algorithms and vector databases
 * for instant access and pre-loading capabilities.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_VECTOR_DB_H
#define QIHSE_VECTOR_DB_H

#include "memory/include/qihse_uma.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * VECTOR DATABASE INTEGRATION TYPES
 * ============================================================================ */

/**
 * Vector database backend types.
 */
typedef enum qihse_vector_db_backend_e {
    QIHSE_VECTOR_DB_FAISS = 0,      /* Facebook AI Similarity Search */
    QIHSE_VECTOR_DB_CHROMA = 1,     /* ChromaDB */
    QIHSE_VECTOR_DB_QDRANT = 2,     /* Qdrant */
    QIHSE_VECTOR_DB_INMEMORY = 3,   /* In-memory vector store */
    QIHSE_VECTOR_DB_AUTO = 4,       /* Auto-detect available backend */
} qihse_vector_db_backend_t;

/**
 * Vector database search result.
 */
typedef struct qihse_vector_result_s {
    uint64_t id;                    /* Vector ID */
    float score;                    /* Similarity score */
    float* vector;                  /* Vector data */
    size_t vector_dims;             /* Vector dimensions */
    void* metadata;                 /* Associated metadata */
    size_t metadata_size;           /* Metadata size */
} qihse_vector_result_t;

/**
 * Vector database query parameters.
 */
typedef struct qihse_vector_query_s {
    const float* query_vector;      /* Query vector */
    size_t vector_dims;             /* Vector dimensions */
    size_t top_k;                   /* Number of results to return */
    float similarity_threshold;     /* Minimum similarity threshold */
    bool include_vectors;           /* Include vector data in results */
    bool include_metadata;          /* Include metadata in results */
} qihse_vector_query_t;

/**
 * Vector database integration handle.
 */
typedef struct qihse_vector_db_s* qihse_vector_db_t;

/* ============================================================================
 * VECTOR DATABASE LIFECYCLE
 * ============================================================================ */

/**
 * Create vector database integration with QIHSE UMA.
 *
 * @param backend Vector database backend to use
 * @param uma UMA manager for memory management
 * @param db_path Path to vector database (NULL for in-memory)
 * @return Vector database handle, or NULL on failure
 */
qihse_vector_db_t qihse_vector_db_create(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path
);

/**
 * Destroy vector database integration.
 *
 * @param vdb Vector database handle to destroy
 */
void qihse_vector_db_destroy(qihse_vector_db_t vdb);

/* ============================================================================
 * VECTOR DATABASE OPERATIONS
 * ============================================================================ */

/**
 * Add vectors to the database with QIHSE-optimized placement.
 *
 * @param vdb Vector database handle
 * @param vectors Array of vectors to add
 * @param num_vectors Number of vectors
 * @param vector_dims Dimension count per vector
 * @param ids Array of vector IDs (NULL for auto-generated)
 * @param metadata Array of metadata pointers (NULL if no metadata)
 * @param metadata_sizes Array of metadata sizes
 * @return true on success, false on failure
 */
bool qihse_vector_db_add_vectors(
    qihse_vector_db_t vdb,
    const float* vectors,
    size_t num_vectors,
    size_t vector_dims,
    const uint64_t* ids,
    const void* const* metadata,
    const size_t* metadata_sizes
);

/**
 * Search vectors with QIHSE acceleration and instant access.
 *
 * @param vdb Vector database handle
 * @param query Query parameters
 * @param results Output array for results
 * @param max_results Maximum number of results to return
 * @return Number of results found, or negative on error
 */
int qihse_vector_db_search(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results
);

/**
 * Pre-load vectors for instant access based on query pattern.
 *
 * @param vdb Vector database handle
 * @param query_vector Query vector for preloading similar vectors
 * @param vector_dims Vector dimensions
 * @param preload_radius Similarity radius for preloading
 * @return true on success, false on failure
 */
bool qihse_vector_db_preload_similar(
    qihse_vector_db_t vdb,
    const float* query_vector,
    size_t vector_dims,
    float preload_radius
);

/* ============================================================================
 * QIHSE INTEGRATION FEATURES
 * ============================================================================ */

/**
 * Enable QIHSE-accelerated search with vector database.
 *
 * @param vdb Vector database handle
 * @param enable_hilbert Enable Hilbert space expansion
 * @param enable_quantization Enable quantization optimization
 * @param enable_parallel Enable parallel search
 * @return true on success, false on failure
 */
bool qihse_vector_db_enable_acceleration(
    qihse_vector_db_t vdb,
    bool enable_hilbert,
    bool enable_quantization,
    bool enable_parallel
);

/**
 * Get performance statistics for QIHSE-vector DB integration.
 *
 * @param vdb Vector database handle
 * @param search_time_ms Average search time in milliseconds
 * @param preload_hit_rate Preload cache hit rate (0.0-1.0)
 * @param memory_efficiency Memory efficiency ratio
 * @return true on success, false on failure
 */
bool qihse_vector_db_get_stats(
    qihse_vector_db_t vdb,
    double* search_time_ms,
    double* preload_hit_rate,
    double* memory_efficiency
);

/**
 * Optimize vector database layout for QIHSE access patterns.
 *
 * @param vdb Vector database handle
 * @param target_workload Expected workload characteristics
 * @return true on success, false on failure
 */
bool qihse_vector_db_optimize_layout(
    qihse_vector_db_t vdb,
    const char* target_workload
);

/* ============================================================================
 * MEMORY SUPERPOSITION INTEGRATION
 * ============================================================================ */

/**
 * Enable memory superposition for vector data.
 *
 * @param vdb Vector database handle
 * @param superposition_state Initial superposition state
 * @param temperature_aware Enable temperature-aware placement
 * @return true on success, false on failure
 */
bool qihse_vector_db_enable_superposition(
    qihse_vector_db_t vdb,
    qihse_memory_superposition_state_t superposition_state,
    bool temperature_aware
);

/**
 * Get current memory superposition status for vectors.
 *
 * @param vdb Vector database handle
 * @param ready_percentage Percentage of vectors in ready state (0.0-1.0)
 * @param migrating_count Number of vectors currently migrating
 * @param pinned_count Number of vectors pinned to fast memory
 * @return true on success, false on failure
 */
bool qihse_vector_db_get_superposition_status(
    qihse_vector_db_t vdb,
    double* ready_percentage,
    size_t* migrating_count,
    size_t* pinned_count
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_VECTOR_DB_H */
