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
 * Native vector database storage mode.
 *
 * QIHSE persistence is a storage concern, not an external vector DB backend.
 */
typedef enum qihse_vector_db_storage_mode_e {
    QIHSE_VDB_STORAGE_EPHEMERAL = 0,
    QIHSE_VDB_STORAGE_FILE_COPY = 1,
    QIHSE_VDB_STORAGE_FILE_MMAP = 2
} qihse_vector_db_storage_mode_t;

/**
 * Native vector database open flags.
 */
typedef enum qihse_vector_db_open_flags_e {
    QIHSE_VDB_OPEN_CREATE      = 1u << 0,
    QIHSE_VDB_OPEN_READ_ONLY   = 1u << 1,
    QIHSE_VDB_OPEN_TRUNCATE    = 1u << 2,
    QIHSE_VDB_OPEN_FILE_BACKED = 1u << 3,
    QIHSE_VDB_OPEN_MMAP        = 1u << 4
} qihse_vector_db_open_flags_t;

/**
 * Native vector encoding identifiers reserved by the QIHSE file format.
 */
typedef enum qihse_vector_encoding_e {
    QIHSE_ENCODING_FLOAT32 = 0x00000001u,
    QIHSE_ENCODING_FLOAT32_TRINARY_2BIT = 0x00010001u,
    QIHSE_ENCODING_FLOAT32_TRINARY_TRYTE = 0x00010002u,
    QIHSE_ENCODING_TRINARY_TRYTE = 0x00010003u
} qihse_vector_encoding_t;

/**
 * Status of the optional vectors.qtri sidecar.
 */
typedef enum qihse_vector_db_trinary_status_e {
    QIHSE_VDB_TRINARY_ABSENT = 0,
    QIHSE_VDB_TRINARY_VALID = 1,
    QIHSE_VDB_TRINARY_STALE = 2,
    QIHSE_VDB_TRINARY_CORRUPT = 3
} qihse_vector_db_trinary_status_t;

/**
 * Native file-backed persistence diagnostics.
 */
typedef struct qihse_vector_db_persistence_stats_s {
    qihse_vector_db_storage_mode_t storage_mode;
    qihse_vector_encoding_t encoding_id;
    uint32_t encoding_version;
    bool read_only;
    bool needs_flush;
    uint64_t committed_generation;
    uint64_t total_vectors;
    uint64_t live_vectors;
    uint64_t vector_dims;
    uint64_t vector_bytes;
    uint64_t metadata_bytes;
    uint64_t index_rows;
    bool idmap_valid;
    bool idmap_dirty;
    uint64_t idmap_rows;
    uint64_t wal_bytes_pending;
    uint64_t wal_records_replayed;
    qihse_vector_db_trinary_status_t trinary_status;
    uint64_t trinary_row_bytes;
    uint64_t trinary_rows;
} qihse_vector_db_persistence_stats_t;

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
 * Open a native QIHSE vector database.
 *
 * @param backend Vector database backend to use for compatibility
 * @param uma UMA manager for vector and metadata buffers
 * @param db_path Path to QIHSE database directory (NULL for ephemeral)
 * @param flags Open flags
 * @return Vector database handle, or NULL on failure
 */
qihse_vector_db_t qihse_vector_db_open(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags
);

/**
 * Flush accepted writes to durable storage.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_flush(qihse_vector_db_t vdb);

/**
 * Checkpoint durable state by flushing the current snapshot and clearing WAL
 * records at or before the committed generation.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure or unsupported mode
 */
bool qihse_vector_db_checkpoint(qihse_vector_db_t vdb);

/**
 * Compact durable state. The current implementation rewrites the snapshot and
 * derived sidecars; row-level tombstone compaction is reserved for a later
 * storage-maintenance pass.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure or unsupported mode
 */
bool qihse_vector_db_compact(qihse_vector_db_t vdb);

/**
 * Flush and close a vector database handle.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_close(qihse_vector_db_t vdb);

/**
 * Get native file-backed persistence diagnostics.
 *
 * @param vdb Vector database handle
 * @param stats Output persistence statistics
 * @return true on success, false on failure
 */
bool qihse_vector_db_get_persistence_stats(
    qihse_vector_db_t vdb,
    qihse_vector_db_persistence_stats_t* stats
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
 * Delete one live vector by external ID.
 *
 * PR-4 API surface only: implementations must reject read-only handles, mark
 * the latest live row tombstoned, and preserve crash recovery through WAL.
 *
 * @param vdb Vector database handle
 * @param vector_id External vector ID to delete
 * @return true if a live vector was deleted, false on failure or missing ID
 */
bool qihse_vector_db_delete_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id
);

/**
 * Delete multiple live vectors by external ID in one batch.
 *
 * @param vdb Vector database handle
 * @param vector_ids External vector IDs to delete
 * @param count Number of IDs
 * @param deleted_count Optional output count of deleted live rows
 * @return true if the batch completed, false on validation or storage failure
 */
bool qihse_vector_db_delete_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    size_t count,
    size_t* deleted_count
);

/**
 * Replace one live vector by external ID.
 *
 * PR-4 semantics are append-only: tombstone the previous live row and append a
 * new live row with the same external ID.
 *
 * @param vdb Vector database handle
 * @param vector_id External vector ID to update
 * @param vector Replacement vector
 * @param dims Replacement vector dimensions
 * @param metadata Optional replacement metadata bytes
 * @param metadata_size Replacement metadata size
 * @return true if the vector was updated, false on failure or missing ID
 */
bool qihse_vector_db_update_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    const float* vector,
    size_t dims,
    const void* metadata,
    size_t metadata_size
);

/**
 * Replace multiple live vectors by external ID in one batch.
 *
 * @param vdb Vector database handle
 * @param vector_ids External vector IDs to update
 * @param vectors Contiguous replacement vectors
 * @param count Number of vectors
 * @param dims Dimension count per replacement vector
 * @param metadata Optional replacement metadata pointers
 * @param metadata_sizes Optional replacement metadata sizes
 * @param updated_count Optional output count of updated live rows
 * @return true if the batch completed, false on validation or storage failure
 */
bool qihse_vector_db_update_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* updated_count
);

/**
 * Insert missing IDs and replace existing IDs in one committed batch.
 *
 * @param vdb Vector database handle
 * @param vector_ids External vector IDs to insert or update
 * @param vectors Contiguous source vectors
 * @param count Number of vectors
 * @param dims Dimension count per vector
 * @param metadata Optional metadata pointers
 * @param metadata_sizes Optional metadata sizes
 * @param inserted_count Optional output count of inserted rows
 * @param updated_count Optional output count of updated rows
 * @return true if the batch completed, false on validation or storage failure
 */
bool qihse_vector_db_upsert_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* inserted_count,
    size_t* updated_count
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
