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

#define QIHSE_VECTOR_DB_PR5_TRINARY_SEARCH_API 1

#include "../memory/include/qihse_uma.h"
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
 * Status of the optional vectors.qmag magnitude sidecar.
 */
typedef enum qihse_vector_db_magnitude_status_e {
    QIHSE_VDB_MAGNITUDE_ABSENT = 0,
    QIHSE_VDB_MAGNITUDE_VALID = 1,
    QIHSE_VDB_MAGNITUDE_STALE = 2,
    QIHSE_VDB_MAGNITUDE_CORRUPT = 3
} qihse_vector_db_magnitude_status_t;

/**
 * Status of the optional graph index sidecar.
 */
typedef enum qihse_vector_db_graph_status_e {
    QIHSE_VDB_GRAPH_ABSENT = 0,
    QIHSE_VDB_GRAPH_VALID = 1,
    QIHSE_VDB_GRAPH_STALE = 2,
    QIHSE_VDB_GRAPH_CORRUPT = 3
} qihse_vector_db_graph_status_t;

/**
 * Status of the optional INT8 scalar quantization sidecar.
 */
typedef enum qihse_vector_db_int8_status_e {
    QIHSE_VDB_INT8_ABSENT = 0,
    QIHSE_VDB_INT8_VALID = 1,
    QIHSE_VDB_INT8_STALE = 2,
    QIHSE_VDB_INT8_CORRUPT = 3
} qihse_vector_db_int8_status_t;

/**
 * Status of the optional FP16 quantization sidecar.
 */
typedef enum qihse_vector_db_fp16_status_e {
    QIHSE_VDB_FP16_ABSENT = 0,
    QIHSE_VDB_FP16_VALID = 1,
    QIHSE_VDB_FP16_STALE = 2,
    QIHSE_VDB_FP16_CORRUPT = 3
} qihse_vector_db_fp16_status_t;

/**
 * Status of the optional explicit FP32 sidecar.
 */
typedef enum qihse_vector_db_fp32_status_e {
    QIHSE_VDB_FP32_ABSENT = 0,
    QIHSE_VDB_FP32_VALID = 1,
    QIHSE_VDB_FP32_STALE = 2,
    QIHSE_VDB_FP32_CORRUPT = 3
} qihse_vector_db_fp32_status_t;

/**
 * Status of the optional FP8 quantization sidecar.
 */
typedef enum qihse_vector_db_fp8_status_e {
    QIHSE_VDB_FP8_ABSENT = 0,
    QIHSE_VDB_FP8_VALID = 1,
    QIHSE_VDB_FP8_STALE = 2,
    QIHSE_VDB_FP8_CORRUPT = 3
} qihse_vector_db_fp8_status_t;

/**
 * Status of the optional FP4 quantization sidecar.
 */
typedef enum qihse_vector_db_fp4_status_e {
    QIHSE_VDB_FP4_ABSENT = 0,
    QIHSE_VDB_FP4_VALID = 1,
    QIHSE_VDB_FP4_STALE = 2,
    QIHSE_VDB_FP4_CORRUPT = 3
} qihse_vector_db_fp4_status_t;

/**
 * Status of the optional INT4 quantization sidecar.
 */
typedef enum qihse_vector_db_int4_status_e {
    QIHSE_VDB_INT4_ABSENT = 0,
    QIHSE_VDB_INT4_VALID = 1,
    QIHSE_VDB_INT4_STALE = 2,
    QIHSE_VDB_INT4_CORRUPT = 3
} qihse_vector_db_int4_status_t;

/**
 * Status of the optional binary quantization sidecar (1 bit per dimension).
 */
typedef enum qihse_vector_db_binary_status_e {
    QIHSE_VDB_BINARY_ABSENT = 0,
    QIHSE_VDB_BINARY_VALID = 1,
    QIHSE_VDB_BINARY_STALE = 2,
    QIHSE_VDB_BINARY_CORRUPT = 3
} qihse_vector_db_binary_status_t;

/**
 * Native search mode selector for qihse_vector_db_search().
 *
 * QIHSE_VDB_QUERY_FLOAT32 is the default and ignores optional trinary sidecars.
 * QIHSE_VDB_QUERY_TRINARY_SCALAR uses vectors.qtri for sign-only candidate
 * selection, then reranks the candidate rows against authoritative float32
 * storage. QIHSE_VDB_QUERY_TRINARY_MAGNITUDE uses both vectors.qtri and
 * vectors.qmag for magnitude-aware candidate selection before the same exact
 * float32 rerank. QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS skips float32
 * rerank and returns qmag-ranked candidates directly.
 *
 * Trinary modes are explicit caller opt-ins. They fail rather than falling back
 * when required sidecars are absent, corrupt, stale, or internally inconsistent
 * with the live float32 row count/dimensions.
 */
typedef enum qihse_vector_db_query_mode_e {
    QIHSE_VDB_QUERY_FLOAT32 = 0,
    QIHSE_VDB_QUERY_TRINARY_SCALAR = 1,
    QIHSE_VDB_QUERY_TRINARY_MAGNITUDE = 2,
    QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS = 3,
    QIHSE_VDB_QUERY_GRAPH = 4,           /* Graph index candidate selection */
    QIHSE_VDB_QUERY_INT8 = 5,            /* INT8 scalar quantization candidate selection */
    QIHSE_VDB_QUERY_SPARSE = 6,          /* Sparse inverted index (BM25) candidate selection */
    QIHSE_VDB_QUERY_FP16 = 7,            /* FP16 candidate selection */
    QIHSE_VDB_QUERY_FP32 = 8,            /* Explicit FP32 candidate selection */
    QIHSE_VDB_QUERY_FP8 = 9,             /* FP8 candidate selection */
    QIHSE_VDB_QUERY_FP4 = 10,            /* FP4 candidate selection */
    QIHSE_VDB_QUERY_INT4 = 11            /* INT4 candidate selection */
} qihse_vector_db_query_mode_t;

/**
 * Distance metric for exact reranking and score computation.
 *
 * QIHSE_DISTANCE_COSINE is the default. All metrics produce a similarity score
 * where higher is more similar. Euclidean distance is converted to a similarity
 * score as 1.0 / (1.0 + distance).
 */
typedef enum qihse_distance_metric_e {
    QIHSE_DISTANCE_COSINE = 0,
    QIHSE_DISTANCE_DOT_PRODUCT = 1,
    QIHSE_DISTANCE_EUCLIDEAN = 2
} qihse_distance_metric_t;

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
    qihse_vector_db_magnitude_status_t magnitude_status;
    uint64_t magnitude_row_bytes;
    uint64_t magnitude_rows;
    qihse_vector_db_graph_status_t graph_status;
    uint64_t graph_nodes;
    uint64_t graph_edges;
    qihse_vector_db_int8_status_t int8_status;
    uint64_t int8_rows;
    uint64_t int8_dims;
    qihse_vector_db_fp16_status_t fp16_status;
    uint64_t fp16_rows;
    uint64_t fp16_dims;
    qihse_vector_db_fp32_status_t fp32_status;
    uint64_t fp32_rows;
    uint64_t fp32_dims;
    qihse_vector_db_fp8_status_t fp8_status;
    uint64_t fp8_rows;
    uint64_t fp8_dims;
    qihse_vector_db_fp4_status_t fp4_status;
    uint64_t fp4_rows;
    uint64_t fp4_dims;
    qihse_vector_db_int4_status_t int4_status;
    uint64_t int4_rows;
    uint64_t int4_dims;
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
 *
 * Contract for qihse_vector_db_search():
 *
 * - `query_mode == QIHSE_VDB_QUERY_FLOAT32`, including zero-initialized queries,
 *   performs exact float32 search and tolerates missing/corrupt/stale qtri or
 *   qmag sidecars.
 * - use_trinary_candidates is the legacy scalar opt-in. When true and
 *   query_mode remains FLOAT32, candidate_count is used as-is and must be at
 *   least top_k; there is no automatic pool default on this legacy path.
 * - Explicit trinary modes use candidate_pool_size when non-zero, otherwise
 *   candidate_count. When both are zero, scalar qtri searches all physical
 *   rows for correctness; qmag uses an internal conservative default based on
 *   top_k, active query dimensions, and live rows.
 * - Explicit trinary candidate pools are capped after default resolution
 *   (scalar to total_vectors, qmag to live rows). The effective pool must
 *   still be at least top_k.
 * - Default-pool qmag (TRINARY_MAGNITUDE) is opportunistic: when its
 *   conservative policy gate rejects the query shape, including high
 *   active-dimension ratios, high top_k/live-row ratios, or high exact-rerank
 *   pool pressure, qihse_vector_db_search() falls back to exact float32 search.
 *   Default-policy gates are dimension-aware and pressure-aware:
 *   - sparse (<=1/32 active dims): top_k/live_rows <= 1/16 and
 *     effective_candidate_pool/live_rows <= 1/4, qmag pool = top_k*4;
 *   - light/medium (<=1/16 active dims): top_k/live_rows <= 3/128 and
 *     effective_candidate_pool/live_rows <= 9/32, qmag pool = top_k*6;
 *   - denser (<=1/8 active dims): top_k/live_rows <= 1/64 and
 *     effective_candidate_pool/live_rows <= 1/8, qmag pool = top_k*8;
 *   - >1/8 and <=1/4 active dims: denied by the 1/4 global sparsity gate.
 *   These thresholds are chosen so fewer active dimensions route to a faster,
 *   tighter default pool while preserving fallback to exact for denser cases.
 *   Caller-provided qmag pools remain explicit opt-ins and execute qmag
 *   search directly after normal pool and sidecar validation.
 * - Explicit trinary modes require top_k > 0 and top_k <= max_results. The
 *   effective candidate pool must still be at least top_k after validation.
 * - QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS returns approximate qmag
 *   ordering and writes qmag score (not cosine) into query results.
 * - Missing qtri reports ENOENT; stale qtri reports ESTALE when available or
 *   EINVAL otherwise; corrupt qtri reports EINVAL.
 * - Missing qmag reports ENODATA when available or ENOENT otherwise; stale
 *   qmag reports ESTALE when available or EINVAL otherwise; corrupt qmag
 *   reports EINVAL. The current internal consistency check reports stale via
 *   the trinary stale path when either qtri or qmag row/byte metadata no
 *   longer matches the float32 store.
 * - For explicit `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE`, candidate-pool defaults
 *   are policy-gated; if policy denies the workload shape, the implementation
 *   falls back to exact float32 search. `QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS`
 *   never auto-falls back.
 */
/**
 * Metadata filter callback. Return true if the row should be included in results.
 * opaque is caller-provided context (e.g., parsed filter struct pointer).
 */
typedef bool (*qihse_metadata_filter_fn_t)(const void* metadata,
                                            size_t metadata_size,
                                            void* opaque);

typedef struct qihse_vector_query_s {
    const float* query_vector;      /* Query vector */
    size_t vector_dims;             /* Vector dimensions */
    size_t top_k;                   /* Number of results to return */
    float similarity_threshold;     /* Minimum similarity threshold */
    bool include_vectors;           /* Include vector data in results */
    bool include_metadata;          /* Include metadata in results */
    bool use_trinary_candidates;    /* Legacy scalar opt-in candidate path */
    size_t candidate_count;         /* Trinary candidate count before rerank */
    qihse_vector_db_query_mode_t query_mode; /* Preferred search mode selector */
    size_t candidate_pool_size;     /* Trinary/qmag pool override for explicit modes */
    qihse_distance_metric_t distance_metric; /* Distance metric for exact rerank */
    qihse_metadata_filter_fn_t metadata_filter; /* Optional pre-filter callback */
    void* metadata_filter_opaque;   /* Opaque context for metadata_filter */
    struct qihse_user_s* user;      /* The user performing the query */
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
 * @param db_path Path to the .qdb container file (NULL for ephemeral in-memory)
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
 * @param db_path Path to the .qdb single-file container (NULL for ephemeral)
 * @param flags Open flags (QIHSE_VDB_OPEN_* bitmask)
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
 * Enable query result cache with specified capacity.
 *
 * @param vdb Vector database handle
 * @param max_entries Maximum cached query results
 * @return true on success, false on failure
 */
bool qihse_vector_db_enable_cache(
    qihse_vector_db_t vdb,
    size_t max_entries
);

/**
 * Clear all cached query results.
 *
 * @param vdb Vector database handle
 */
void qihse_vector_db_clear_cache(
    qihse_vector_db_t vdb
);

/**
 * Run hierarchical storage maintenance: evaluate per-vector access temperatures
 * and promote/demote vectors across memory tiers (SRAM -> HBM -> DRAM).
 *
 * @param vdb Vector database handle
 * @return true if maintenance ran, false if vdb is NULL
 */
bool qihse_vector_db_run_memory_maintenance(
    qihse_vector_db_t vdb
);

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
 * Add model storage weights directly into the specified quantization category (e.g. FP16, INT8, FP8, FP4, INT4).
 * This API is optimized for ML model storage: it directly populates the corresponding sidecar
 * memory buffers to avoid wasting time and memory, and auto-expands to the core FP32 representation
 * for authoritative query routing.
 *
 * @param vdb Vector database handle
 * @param category The quantization category (e.g., QIHSE_VDB_QUERY_FP8, QIHSE_VDB_QUERY_INT4)
 * @param weights Raw byte array containing the weights in the specified format
 * @param num_vectors Number of weight vectors
 * @param vector_dims Dimension count per vector
 * @param ids Array of vector IDs (NULL for auto-generated)
 * @return true on success, false on failure
 */
bool qihse_vector_db_add_model_weights(
    qihse_vector_db_t vdb,
    qihse_vector_db_query_mode_t category,
    const void* weights,
    size_t num_vectors,
    size_t vector_dims,
    const uint64_t* ids
);

/**
 * Delete one live vector by external ID.
 *
 * PR-4 API surface only: implementations must reject read-only handles, mark
 * the latest live row tombstoned, and preserve crash recovery through WAL.
 *
 * @param vdb Vector database handle
 * @param vector_id External vector ID to delete
 * Deletion fails with EBUSY while explicit edges reference the vector; remove
 * those relationships first so every persisted edge retains valid endpoints.
 *
 * @return true if a live vector was deleted, false on failure or missing ID
 */
bool qihse_vector_db_delete_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id
);

/**
 * Retrieve a single vector by external ID.
 *
 * @param vdb Vector database handle
 * @param vector_id External vector ID to retrieve
 * @param out_vector Output buffer for vector data (must be at least dims * sizeof(float))
 * @param out_dims Optional output for vector dimensions
 * @return true if found, false on failure or missing ID
 */
bool qihse_vector_db_get_vector_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    float* out_vector,
    size_t* out_dims
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
 * Default queries search authoritative float32 vectors. Trinary query modes use
 * qtri/qmag as candidate selectors and normally return exact float32 reranked
 * results, except for QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS which returns
 * approximate qmag-only ordering for lowest-latency execution.
 *
 * @param vdb Vector database handle
 * @param query Query parameters; see qihse_vector_query_t for trinary contract
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
 * Explicit opt-in legacy scalar trinary candidate search.
 *
 * This path uses a valid vectors.qtri sidecar only to choose candidate rows,
 * then reranks those candidates against the authoritative float32 vectors. It
 * does not consult query->candidate_pool_size and does not synthesize a default
 * candidate count; callers must pass candidate_count >= query->top_k.
 *
 * It fails instead of falling back when qtri is absent, corrupt, stale,
 * internally inconsistent with float32 storage, or when candidate_count is
 * smaller than query->top_k.
 *
 * @param vdb Vector database handle
 * @param query Query parameters; query->top_k is the required result count
 * @param candidate_count Number of trinary candidates to generate before rerank
 * @param results Output array for exact-reranked float32 results
 * @param max_results Capacity of results; must be at least query->top_k
 * @return Number of results found, or negative on error
 */
int qihse_vector_db_search_trinary_candidates(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    size_t candidate_count,
    qihse_vector_result_t* results,
    size_t max_results
);

/**
 * Batch search vectors with QIHSE acceleration.
 *
 * Executes multiple queries against the same vector database, amortizing
 * index and sidecar lookup overhead. Each query is independent and produces
 * its own result set. The caller must provide a results array large enough
 * to hold max_results per query, and an out_counts array of length num_queries.
 *
 * @param vdb Vector database handle
 * @param queries Array of query parameters
 * @param num_queries Number of queries
 * @param results Flat output array: num_queries * max_results entries
 * @param max_results Maximum results per query
 * @param out_counts Output array of actual result counts per query
 * @return true on success, false on error
 */
bool qihse_vector_db_search_batch(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* queries,
    size_t num_queries,
    qihse_vector_result_t* results,
    size_t max_results,
    int* out_counts
);

/* ============================================================================
 * EXPLICIT GRAPH EDGE MANAGEMENT (QQL/Graph DB)
 * ============================================================================ */

#define QIHSE_EDGE_TYPE_MAX 31u

typedef enum qihse_edge_direction_e {
    QIHSE_EDGE_OUTGOING = 0,
    QIHSE_EDGE_INCOMING = 1,
    QIHSE_EDGE_BOTH = 2
} qihse_edge_direction_t;

typedef struct qihse_edge_input_s {
    uint64_t from_id;
    uint64_t to_id;
    const char* edge_type;
    const void* metadata;
    size_t metadata_size;
} qihse_edge_input_t;

typedef struct qihse_edge_result_s {
    uint64_t from_id;
    uint64_t to_id;
    char edge_type[QIHSE_EDGE_TYPE_MAX + 1u];
    void* metadata;
    size_t metadata_size;
} qihse_edge_result_t;

/**
 * Add an explicit edge between two vector nodes.
 *
 * @param vdb Vector database handle
 * @param from_id Source vector ID
 * @param to_id Destination vector ID
 * @param edge_type String literal defining relationship (e.g., "RELATES_TO")
 * @param metadata Optional metadata for the edge
 * @param metadata_size Size of edge metadata
 * @return true on success, false on failure
 */
bool qihse_vector_db_add_edge(
    qihse_vector_db_t vdb,
    uint64_t from_id,
    uint64_t to_id,
    const char* edge_type,
    const void* metadata,
    size_t metadata_size
);

/**
 * Get outgoing edges for a given vector node.
 * 
 * @param vdb Vector database handle
 * @param from_id Source vector ID
 * @param edge_type Filter by type (NULL for all)
 * @param out_ids Array to store destination IDs
 * @param max_edges Maximum edges to retrieve
 * @return Number of edges found, or negative on error
 */
int qihse_vector_db_get_edges(
    qihse_vector_db_t vdb,
    uint64_t from_id,
    const char* edge_type,
    uint64_t* out_ids,
    size_t max_edges
);

/** Add or idempotently retain a batch of typed edges. */
bool qihse_vector_db_add_edges(
    qihse_vector_db_t vdb,
    const qihse_edge_input_t* edges,
    size_t edge_count,
    size_t* changed_count
);

/** Replace metadata on an existing typed edge. */
bool qihse_vector_db_replace_edge(
    qihse_vector_db_t vdb,
    uint64_t from_id,
    uint64_t to_id,
    const char* edge_type,
    const void* metadata,
    size_t metadata_size
);

/** Remove an existing typed edge. Missing edges are idempotent success. */
bool qihse_vector_db_remove_edge(
    qihse_vector_db_t vdb,
    uint64_t from_id,
    uint64_t to_id,
    const char* edge_type
);

/** Retrieve typed neighbors in the requested direction. */
int qihse_vector_db_get_typed_neighbors(
    qihse_vector_db_t vdb,
    uint64_t node_id,
    const char* edge_type,
    qihse_edge_direction_t direction,
    uint64_t* out_ids,
    size_t max_edges
);

/** Retrieve edge records including owned metadata copies. */
int qihse_vector_db_get_edge_records(
    qihse_vector_db_t vdb,
    uint64_t node_id,
    const char* edge_type,
    qihse_edge_direction_t direction,
    qihse_edge_result_t* results,
    size_t max_edges
);

/** Release metadata allocated by qihse_vector_db_get_edge_records. */
void qihse_vector_db_free_edge_records(qihse_edge_result_t* results, size_t count);

/* ============================================================================
 * EMBEDDED QUERY EXECUTION (QQL & SQL)
 * ============================================================================ */

/**
 * Result set returned from embedded string-based query execution.
 */
typedef struct qihse_result_set_s {
    qihse_vector_result_t* results;
    size_t count;
} qihse_result_set_t;

/**
 * Execute a native QIHSE Query Language (QQL) string entirely in memory.
 * Parses the string, compiles WHERE clauses to native bytecode, performs the 
 * underlying vector search, and returns the results.
 * 
 * @param vdb Vector database handle
 * @param qql_query_string Raw QQL query (e.g., "MATCH (d) SEARCH d.vec WITH VEC(...)")
 * @return Allocated result set, or NULL on parsing/execution error. 
 *         Caller must free via qihse_free_result_set().
 */
qihse_result_set_t* qihse_execute_qql(
    qihse_vector_db_t vdb, 
    const char* qql_query_string
);

/**
 * Execute a legacy SQL string by dynamically translating it into QIHSE graph operations.
 * Requires the native SQL parser module to be linked into the framework.
 * 
 * @param vdb Vector database handle
 * @param sql_query_string Raw SQL query
 * @return Allocated result set, or NULL on parsing/execution error.
 */
qihse_result_set_t* qihse_execute_sql(
    qihse_vector_db_t vdb, 
    const char* sql_query_string
);

/**
 * Free a result set allocated by qihse_execute_qql or qihse_execute_sql.
 */
void qihse_free_result_set(qihse_result_set_t* rs);

/**
 * Get the vector dimensions of the database.
 *
 * @param vdb Vector database handle
 * @return Vector dimensions, or 0 on error
 */
size_t qihse_vector_db_get_dims(qihse_vector_db_t vdb);

/**
 * Hybrid search request combining two independent query paths.
 *
 * query_a and query_b are executed independently against the same collection.
 * Results are fused with Reciprocal Rank Fusion (RRF):
 *   score = sum(1.0 / (rank + k))
 * where k is fusion_constant_k (caller-tunable; 60.0 is a common default).
 *
 * The fused result score is written into the result score field.  Each path
 * preserves its own exactness contract; this is purely an orchestration layer.
 */
typedef struct qihse_hybrid_request_s {
    qihse_vector_query_t query_a;
    qihse_vector_query_t query_b;
    float fusion_constant_k;
} qihse_hybrid_request_t;

/**
 * Hybrid search with RRF fusion of two query paths.
 *
 * @param vdb Vector database handle
 * @param request Hybrid request with two queries and fusion parameters
 * @param results Output array for fused results
 * @param max_results Maximum results to return
 * @return Number of fused results, or negative on error
 */
int qihse_vector_db_hybrid_search(
    qihse_vector_db_t vdb,
    const qihse_hybrid_request_t* request,
    qihse_vector_result_t* results,
    size_t max_results
);

/**
 * Build or rebuild the optional graph index sidecar.
 *
 * @param vdb Vector database handle
 * @param M Max neighbors per node (0 for default 16)
 * @param ef_construction Beam width during build (0 for default 200)
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_graph(
    qihse_vector_db_t vdb,
    size_t M,
    size_t ef_construction
);

/**
 * Build or rebuild the optional INT8 scalar quantization sidecar.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_int8(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the optional FP16 quantization sidecar.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_fp16(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the optional explicit FP32 sidecar.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_fp32(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the optional FP8 sidecar.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_fp8(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the optional FP4 sidecar.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_fp4(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the optional INT4 sidecar.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_int4(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the optional binary quantization sidecar (1 bit / dim).
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_binary(
    qihse_vector_db_t vdb
);

/**
 * Build or rebuild the sparse inverted index for sparse vector search.
 *
 * @param vdb Vector database handle
 * @return true on success, false on failure
 */
bool qihse_vector_db_build_sparse(
    qihse_vector_db_t vdb
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
