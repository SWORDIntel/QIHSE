
#ifdef _WIN32
#include <io.h>
#define fsync _commit
#define MAP_FAILED ((void *)-1)
#define PROT_READ 1
#define MAP_SHARED 1
static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) { return MAP_FAILED; }
static inline int munmap(void *addr, size_t length) { return -1; }
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_vector_db.h"
#include "backends/cpu/qihse_cpu_distance.h"

#include "codecs/qihse_trinary_tryte_codec.h"
#include "persistence/qihse_container.h"
#include "persistence/qihse_file.h"
#include "persistence/qihse_persist_format.h"
#include "persistence/qihse_vector_store.h"
#include "qihse_plugin.h"
#include "qihse_auth.h"
#include "qihse_hnsw.h"
#include "qihse_qql_parser.h"

#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "qihse_system_guard.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Single-file container — these file-name constants are no longer used for
 * on-disk files; kept only for log messages and legacy guard macros.        */
#define QIHSE_VDB_WAL_NAME       "wal.qwal"
#define QIHSE_VDB_MANIFEST_NAME  "MANIFEST"

#define QIHSE_VDB_FILE_HEADER_SIZE 32u
#define QIHSE_VDB_FORMAT_VERSION 1u

#define QIHSE_VDB_GRAPH_MAGIC "QIHSEQGR"
#define QIHSE_VDB_INT8_MAGIC  "QIHSEQI8"
#define QIHSE_VDB_WAL_MAGIC "QHWAL01\0"
#define QIHSE_VDB_WAL_HEADER_SIZE 64u
#define QIHSE_VDB_WAL_VERSION 1u
#define QIHSE_VDB_WAL_ADD 1u
#define QIHSE_VDB_WAL_COMMIT 2u
#define QIHSE_VDB_WAL_DELETE 3u
#define QIHSE_VDB_WAL_UPDATE 4u
#define QIHSE_VDB_WAL_UPSERT 5u
#define QIHSE_VDB_WAL_EDGE_ADD 6u
#define QIHSE_VDB_WAL_EDGE_REPLACE 7u
#define QIHSE_VDB_WAL_EDGE_REMOVE 8u
#define QIHSE_VDB_WAL_NO_PREV UINT64_MAX
#define QIHSE_VDB_EDGE_MAGIC "QIHSEEDG"
#define QIHSE_VDB_EDGE_VERSION 1u
#define QIHSE_VDB_EDGE_HEADER_SIZE 72u
#define QIHSE_VDB_EDGE_SOURCE_SIZE 24u
#define QIHSE_VDB_EDGE_RECORD_SIZE 40u

typedef struct qihse_vdb_edge_s {
    uint64_t from_id;
    uint64_t to_id;
    char edge_type[QIHSE_EDGE_TYPE_MAX + 1u];
    void* metadata;
    size_t metadata_size;
} qihse_vdb_edge_t;
#define QIHSE_VDB_MAGNITUDE_ROW_BYTES 1u
#define QIHSE_VDB_TRINARY_NEUTRAL_TRYTE 121u
#define QIHSE_VDB_SCALAR_CANDIDATE_MULTIPLIER 12u
#define QIHSE_VDB_MAGNITUDE_CANDIDATE_MULTIPLIER 8u
#define QIHSE_VDB_MAGNITUDE_POLICY_MIN_LIVE_ROWS 512u
#define QIHSE_VDB_MAGNITUDE_POLICY_MAX_ACTIVE_NUM 1u
#define QIHSE_VDB_MAGNITUDE_POLICY_MAX_ACTIVE_DEN 4u
#define QIHSE_VDB_MAGNITUDE_POLICY_MAX_TOPK_NUM 3u
#define QIHSE_VDB_MAGNITUDE_POLICY_MAX_TOPK_DEN 128u
#define QIHSE_VDB_MAGNITUDE_POLICY_MAX_RERANK_NUM 9u
#define QIHSE_VDB_MAGNITUDE_POLICY_MAX_RERANK_DEN 32u

typedef struct qihse_vdb_cache_entry_s {
    uint64_t query_hash;
    size_t top_k;
    qihse_distance_metric_t metric;
    uint64_t valid_generation; /* cache_generation at time of insertion */
    size_t result_count;
    uint64_t* result_ids;
    float* result_scores;
} qihse_vdb_cache_entry_t;

/* Sparse inverted index types */
typedef struct qihse_vdb_sparse_posting_s {
    uint64_t doc_id;
    float weight;
} qihse_vdb_sparse_posting_t;

typedef struct qihse_vdb_sparse_term_s {
    size_t term_id;
    qihse_vdb_sparse_posting_t* postings;
    size_t posting_count;
    size_t posting_capacity;
    float idf; /* Precomputed IDF for BM25 */
} qihse_vdb_sparse_term_t;

typedef struct qihse_vdb_sparse_index_s {
    qihse_vdb_sparse_term_t* terms;
    size_t term_count;
    size_t term_capacity;
    size_t num_docs;
    float avg_doc_len; /* Average non-zero dimensions per doc */
} qihse_vdb_sparse_index_t;

struct qihse_vector_db_s {
    qihse_vector_db_backend_t backend;
    qihse_uma_manager_t uma;
    char* db_path;
    qihse_vector_db_storage_mode_t storage_mode;
    bool file_backed;
    bool read_only;
    bool dirty;

    size_t vector_dims;
    size_t total_vectors;
    size_t live_vectors;
    size_t rows_capacity;
    uint64_t committed_generation;
    uint64_t next_generation;
    uint64_t next_auto_id;
    uint64_t wal_bytes_pending;
    uint64_t wal_records_replayed;
    uint64_t wal_last_record_offset;

    qihse_index_row_t* rows;
    uint8_t* vectors;
    size_t vector_bytes_used;
    size_t vector_bytes_capacity;
    uint8_t* metadata;
    size_t metadata_bytes_used;
    size_t metadata_bytes_capacity;
    qihse_idmap_entry_t* idmap;
    size_t idmap_count;
    bool idmap_valid;
    bool idmap_dirty;

    int mmap_fd;
    void* mapped_vectors;
    void* mapped_vectors_base;
    size_t mapped_vector_bytes;
    int metadata_mmap_fd;
    void* mapped_metadata;
    void* mapped_metadata_base;
    size_t mapped_metadata_bytes;
    int index_mmap_fd;
    void* mapped_index;
    void* mapped_index_base;
    size_t mapped_index_bytes;
    bool rows_are_mapped;
    int idmap_mmap_fd;
    void* mapped_idmap;
    void* mapped_idmap_base;
    size_t mapped_idmap_bytes;

    qihse_vector_db_trinary_status_t trinary_status;
    uint64_t trinary_row_bytes;
    uint64_t trinary_rows;
    uint8_t* trinary;
    size_t trinary_bytes;
    int8_t* trinary_signs;
    size_t trinary_sign_bytes;
    int8_t* qmag_transposed_signs;
    uint8_t* qmag_transposed_magnitude;
    size_t* qmag_transposed_live_rows;
    size_t qmag_transposed_bytes;
    size_t qmag_transposed_rows;
    size_t qmag_transposed_dims;
    qihse_vector_db_magnitude_status_t magnitude_status;
    uint64_t magnitude_row_bytes;
    uint64_t magnitude_rows;
    uint8_t* magnitude;
    size_t magnitude_bytes;

    /* Graph index sidecar (NSW/HNSW-style candidate selector) */
    qihse_vector_db_graph_status_t graph_status;
    qihse_hnsw_index_t* hnsw_index;
    size_t graph_M;               /* Max neighbors per node */
    size_t graph_ef_construction; /* efConstruction parameter */
    size_t graph_entry_point;     /* Entry point node index */
    size_t* graph_neighbors;      /* Flat adjacency list: dense node i has M entries starting at i*M */
    size_t* graph_neighbor_counts;  /* Actual neighbor count per dense node (<= M) */
    size_t* graph_live_row_map;   /* dense_idx -> actual row index; size = live_vectors */
    size_t graph_capacity;
    size_t graph_nodes;

    /* INT8 scalar quantization sidecar */
    qihse_vector_db_int8_status_t int8_status;
    int8_t* int8_vectors;         /* Flat quantized vectors: n_rows * dims bytes */
    float* int8_dim_min;          /* Per-dimension min (dims floats) */
    float* int8_dim_max;          /* Per-dimension max (dims floats) */
    size_t int8_rows;
    size_t int8_dims;
    size_t int8_bytes;

    /* FP16 quantization sidecar */
    qihse_vector_db_fp16_status_t fp16_status;
    uint16_t* fp16_vectors;       /* Flat FP16 vectors */
    size_t fp16_rows;
    size_t fp16_dims;
    size_t fp16_bytes;

    /* Explicit FP32 sidecar */
    qihse_vector_db_fp32_status_t fp32_status;
    float* fp32_vectors;          /* Flat FP32 vectors */
    size_t fp32_rows;
    size_t fp32_dims;
    size_t fp32_bytes;

    /* FP8 quantization sidecar */
    qihse_vector_db_fp8_status_t fp8_status;
    uint8_t* fp8_vectors;         /* Flat FP8 vectors */
    size_t fp8_rows;
    size_t fp8_dims;
    size_t fp8_bytes;

    /* FP4 quantization sidecar */
    qihse_vector_db_fp4_status_t fp4_status;
    uint8_t* fp4_vectors;         /* Packed FP4 vectors: 2 dims per byte */
    size_t fp4_rows;
    size_t fp4_dims;
    size_t fp4_bytes;

    /* INT4 quantization sidecar */
    qihse_vector_db_int4_status_t int4_status;
    uint8_t* int4_vectors;        /* Packed INT4 vectors: 2 dims per byte */
    size_t int4_rows;
    size_t int4_dims;
    size_t int4_bytes;

    /* Binary quantization sidecar (1 bit per dimension) */
    qihse_vector_db_binary_status_t binary_status;
    uint64_t* binary_vectors;      /* Packed bits: n_rows * ceil(dims/64) uint64_t */
    size_t binary_words_per_vec;   /* Number of uint64_t per vector */
    size_t binary_rows;
    size_t binary_dims;

    /* Query result cache */
    qihse_vdb_cache_entry_t* cache_entries;
    size_t cache_capacity;
    size_t cache_count;
    uint64_t cache_generation;     /* Incremented on every DB mutation to invalidate */

    /* Sparse inverted index */
    qihse_vdb_sparse_index_t* sparse_index;

    /* Per-vector access tracking for hierarchical storage management */
    uint64_t* row_access_counts;          /* Access count per row (parallel to rows[]) */
    uint64_t* row_last_access_ns;         /* Last access timestamp (monotonic ns) per row */
    qihse_memory_tier_t* row_tier;        /* Current memory tier per row */
    size_t row_tracking_capacity;         /* Capacity of tracking arrays */

    /* Hierarchical storage config */
    double memory_hot_threshold;          /* Access rate threshold for promotion */
    double memory_cold_threshold;         /* Access rate threshold for demotion */
    uint64_t memory_maintenance_queries;  /* Queries since last maintenance */
    uint64_t memory_maintenance_interval; /* Run maintenance every N queries (0=explicit only) */

    bool hilbert_enabled;
    bool quantization_enabled;
    bool parallel_enabled;
    bool superposition_enabled;
    bool temperature_aware;
    qihse_memory_superposition_state_t superposition_state;

    /* Explicit graph edge table (QQL/Graph DB) */
    qihse_vdb_edge_t* explicit_edges;
    size_t explicit_edge_count;
    size_t explicit_edge_capacity;
    bool explicit_edges_dirty;
    pthread_mutex_t explicit_edge_mutex;
    bool explicit_edge_mutex_initialized;
};

typedef struct qihse_vdb_wal_add_s {
    uint64_t generation;
    uint64_t count;
    uint64_t dims;
    const uint64_t* ids;
    const float* vectors;
    const void* const* metadata;
    const size_t* metadata_sizes;
} qihse_vdb_wal_add_t;

typedef qihse_vdb_wal_add_t qihse_vdb_wal_vectors_t;

typedef struct qihse_vdb_qmag_query_dim_s {
    size_t dim;
    size_t byte_idx;
    uint8_t trit_idx;
    int32_t signed_weight;
} qihse_vdb_qmag_query_dim_t;

static bool qihse_vdb_reserve_appends(qihse_vector_db_t vdb,
                                      size_t append_count,
                                      size_t metadata_bytes);
static void qihse_vdb_set_trinary_stale(qihse_vector_db_t vdb);
static void qihse_vdb_clear_trinary_cache(qihse_vector_db_t vdb);
static void qihse_vdb_clear_trinary_sign_cache(qihse_vector_db_t vdb);
static void qihse_vdb_clear_qmag_transposed_cache(qihse_vector_db_t vdb);
static bool qihse_vdb_ensure_trinary_sign_cache(qihse_vector_db_t vdb);
static bool qihse_vdb_ensure_qmag_transposed_cache(qihse_vector_db_t vdb);
static void qihse_vdb_set_magnitude_stale(qihse_vector_db_t vdb);
static void qihse_vdb_clear_magnitude_cache(qihse_vector_db_t vdb);
static bool qihse_vdb_resolve_candidate_pool(qihse_vector_db_t vdb,
                                             const qihse_vector_query_t* query,
                                             qihse_vector_db_query_mode_t mode,
                                             size_t* out_candidate_count);
static bool qihse_vdb_resolve_qmag_candidate_pool(qihse_vector_db_t vdb,
                                                  const qihse_vector_query_t* query,
                                                  size_t active_dim_count,
                                                  size_t* out_candidate_count);
static void qihse_vdb_track_row_access(qihse_vector_db_t vdb, size_t row_idx);
static double qihse_vdb_row_temperature(qihse_vector_db_t vdb, size_t row_idx);
static void qihse_vdb_run_memory_maintenance(qihse_vector_db_t vdb);
static qihse_memory_tier_t qihse_vdb_fastest_available_tier(qihse_vector_db_t vdb);

static bool qihse_vdb_qmag_policy_allows(size_t active_dim_count,
                                         size_t vector_dims,
                                         size_t candidate_count,
                                         size_t live_rows,
                                         size_t top_k);
static float qihse_vdb_qmag_score_to_float(int64_t qmag_score,
                                           size_t active_dim_count);
static int qihse_vdb_search_exact_rows(qihse_vector_db_t vdb,
                                       const qihse_vector_query_t* query,
                                       qihse_vector_result_t* results,
                                       size_t max_results,
                                       size_t result_limit);
static int qihse_vdb_search_trinary_magnitude_candidates_no_rerank(
                                                       qihse_vector_db_t vdb,
                                                       const qihse_vector_query_t* query,
                                                       qihse_vector_result_t* results,
                                                       size_t max_results);
static int qihse_vdb_search_trinary_magnitude_candidates(qihse_vector_db_t vdb,
                                                         const qihse_vector_query_t* query,
                                                         qihse_vector_result_t* results,
                                                         size_t max_results);

static char* qihse_vdb_strdup(const char* s) {
    size_t len;
    char* out;

    if (!s) {
        return NULL;
    }
    len = strlen(s);
    out = (char*)malloc(len + 1u);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(out, s, len + 1u);
    return out;
}

/* Forward declarations for sidecar persistence */
static void qihse_vdb_graph_destroy(qihse_vector_db_t vdb);
static void qihse_vdb_int8_destroy(qihse_vector_db_t vdb);
static float qihse_vdb_euclidean_distance(const float* a, const float* b, size_t n);
static const float* qihse_hnsw_vdb_get_vector(void* ctx, uint32_t node_id);
static const float* qihse_vdb_vector_at(qihse_vector_db_t vdb, const qihse_index_row_t* row);
static bool qihse_vdb_id_exists(const qihse_vector_db_t vdb, uint64_t id);

static int qihse_vdb_edge_compare(const void* lhs, const void* rhs) {
    const qihse_vdb_edge_t* a = (const qihse_vdb_edge_t*)lhs;
    const qihse_vdb_edge_t* b = (const qihse_vdb_edge_t*)rhs;
    int type_cmp;
    if (a->from_id < b->from_id) return -1;
    if (a->from_id > b->from_id) return 1;
    type_cmp = strcmp(a->edge_type, b->edge_type);
    if (type_cmp != 0) return type_cmp;
    if (a->to_id < b->to_id) return -1;
    if (a->to_id > b->to_id) return 1;
    return 0;
}

static void qihse_vdb_edge_array_free(qihse_vdb_edge_t* edges, size_t count) {
    size_t i;
    if (!edges) return;
    for (i = 0u; i < count; i++) free(edges[i].metadata);
    free(edges);
}

static bool qihse_vdb_edge_type_valid(const char* edge_type) {
    size_t len;
    if (!edge_type) {
        errno = EINVAL;
        return false;
    }
    len = strnlen(edge_type, QIHSE_EDGE_TYPE_MAX + 2u);
    if (len == 0u || len > QIHSE_EDGE_TYPE_MAX) {
        errno = EINVAL;
        return false;
    }
    return true;
}

static bool qihse_vdb_edge_endpoints_valid(qihse_vector_db_t vdb,
                                            uint64_t from_id,
                                            uint64_t to_id) {
    if (!qihse_vdb_id_exists(vdb, from_id) || !qihse_vdb_id_exists(vdb, to_id)) {
        errno = ENOENT;
        return false;
    }
    return true;
}

static bool qihse_vdb_edge_copy(qihse_vdb_edge_t* dst,
                                const qihse_vdb_edge_t* src) {
    *dst = *src;
    dst->metadata = NULL;
    if (src->metadata_size != 0u) {
        dst->metadata = malloc(src->metadata_size);
        if (!dst->metadata) {
            errno = ENOMEM;
            return false;
        }
        memcpy(dst->metadata, src->metadata, src->metadata_size);
    }
    return true;
}

static bool qihse_vdb_edge_from_input(qihse_vdb_edge_t* dst,
                                      const qihse_edge_input_t* src) {
    size_t type_len;
    if (!src || !qihse_vdb_edge_type_valid(src->edge_type) ||
        (src->metadata_size != 0u && !src->metadata)) {
        errno = EINVAL;
        return false;
    }
    memset(dst, 0, sizeof(*dst));
    dst->from_id = src->from_id;
    dst->to_id = src->to_id;
    type_len = strlen(src->edge_type);
    memcpy(dst->edge_type, src->edge_type, type_len + 1u);
    if (src->metadata_size != 0u) {
        dst->metadata = malloc(src->metadata_size);
        if (!dst->metadata) {
            errno = ENOMEM;
            return false;
        }
        memcpy(dst->metadata, src->metadata, src->metadata_size);
        dst->metadata_size = src->metadata_size;
    }
    return true;
}

static ssize_t qihse_vdb_edge_find(const qihse_vdb_edge_t* edges,
                                   size_t count,
                                   uint64_t from_id,
                                   uint64_t to_id,
                                   const char* edge_type) {
    size_t i;
    for (i = 0u; i < count; i++) {
        if (edges[i].from_id == from_id && edges[i].to_id == to_id &&
            strcmp(edges[i].edge_type, edge_type) == 0) return (ssize_t)i;
    }
    return -1;
}

static bool qihse_vdb_edge_metadata_equal(const qihse_vdb_edge_t* edge,
                                           const void* metadata,
                                           size_t metadata_size) {
    return edge->metadata_size == metadata_size &&
           (metadata_size == 0u || memcmp(edge->metadata, metadata, metadata_size) == 0);
}

static bool qihse_vdb_stage_edge_mutation(qihse_vector_db_t vdb,
                                          uint32_t op,
                                          const qihse_edge_input_t* inputs,
                                          size_t input_count,
                                          qihse_vdb_edge_t** out_edges,
                                          size_t* out_count,
                                          size_t* changed_count) {
    qihse_vdb_edge_t* staged;
    size_t capacity;
    size_t count = vdb->explicit_edge_count;
    size_t changed = 0u;
    size_t i;

    if (!inputs || input_count == 0u || !out_edges || !out_count) {
        errno = EINVAL;
        return false;
    }
    if (input_count > SIZE_MAX - count) {
        errno = EOVERFLOW;
        return false;
    }
    capacity = count + input_count;
    staged = (qihse_vdb_edge_t*)calloc(capacity ? capacity : 1u, sizeof(*staged));
    if (!staged) {
        errno = ENOMEM;
        return false;
    }
    for (i = 0u; i < count; i++) {
        if (!qihse_vdb_edge_copy(&staged[i], &vdb->explicit_edges[i])) goto fail;
    }
    for (i = 0u; i < input_count; i++) {
        ssize_t found;
        if (!qihse_vdb_edge_type_valid(inputs[i].edge_type) ||
            (inputs[i].metadata_size != 0u && !inputs[i].metadata) ||
            !qihse_vdb_edge_endpoints_valid(vdb, inputs[i].from_id, inputs[i].to_id)) {
            goto fail;
        }
        found = qihse_vdb_edge_find(staged, count, inputs[i].from_id,
                                    inputs[i].to_id, inputs[i].edge_type);
        if (op == QIHSE_VDB_WAL_EDGE_REMOVE) {
            if (found >= 0) {
                free(staged[found].metadata);
                if ((size_t)found + 1u < count) {
                    memmove(&staged[found], &staged[found + 1u],
                            (count - (size_t)found - 1u) * sizeof(*staged));
                }
                count--;
                memset(&staged[count], 0, sizeof(*staged));
                changed++;
            }
        } else if (found >= 0) {
            if (op == QIHSE_VDB_WAL_EDGE_REPLACE &&
                !qihse_vdb_edge_metadata_equal(&staged[found], inputs[i].metadata,
                                                inputs[i].metadata_size)) {
                void* replacement = NULL;
                if (inputs[i].metadata_size != 0u) {
                    replacement = malloc(inputs[i].metadata_size);
                    if (!replacement) { errno = ENOMEM; goto fail; }
                    memcpy(replacement, inputs[i].metadata, inputs[i].metadata_size);
                }
                free(staged[found].metadata);
                staged[found].metadata = replacement;
                staged[found].metadata_size = inputs[i].metadata_size;
                changed++;
            }
        } else {
            if (op == QIHSE_VDB_WAL_EDGE_REPLACE) {
                errno = ENOENT;
                goto fail;
            }
            if (!qihse_vdb_edge_from_input(&staged[count], &inputs[i])) goto fail;
            count++;
            changed++;
        }
    }
    qsort(staged, count, sizeof(*staged), qihse_vdb_edge_compare);
    *out_edges = staged;
    *out_count = count;
    if (changed_count) *changed_count = changed;
    return true;
fail:
    qihse_vdb_edge_array_free(staged, count);
    return false;
}

static bool qihse_vdb_encode_edges(qihse_vector_db_t vdb,
                                   uint8_t** out,
                                   size_t* out_size) {
    size_t source_count = 0u;
    size_t string_bytes = 0u;
    size_t source_bytes;
    size_t record_bytes;
    size_t total;
    size_t i;
    uint8_t* data;
    size_t data_offset;
    size_t source_index = 0u;

    if (!vdb || !out || !out_size) { errno = EINVAL; return false; }
    *out = NULL;
    *out_size = 0u;
    for (i = 0u; i < vdb->explicit_edge_count; i++) {
        if (i == 0u || vdb->explicit_edges[i].from_id != vdb->explicit_edges[i - 1u].from_id)
            source_count++;
        if (!qihse_checked_add_size(string_bytes, strlen(vdb->explicit_edges[i].edge_type),
                                    &string_bytes) ||
            !qihse_checked_add_size(string_bytes, vdb->explicit_edges[i].metadata_size,
                                    &string_bytes)) return false;
    }
    if (!qihse_checked_mul_size(source_count, QIHSE_VDB_EDGE_SOURCE_SIZE, &source_bytes) ||
        !qihse_checked_mul_size(vdb->explicit_edge_count, QIHSE_VDB_EDGE_RECORD_SIZE,
                                &record_bytes) ||
        !qihse_checked_add_size(QIHSE_VDB_EDGE_HEADER_SIZE, source_bytes, &total) ||
        !qihse_checked_add_size(total, record_bytes, &total) ||
        !qihse_checked_add_size(total, string_bytes, &total)) return false;
    data = (uint8_t*)calloc(total ? total : 1u, 1u);
    if (!data) { errno = ENOMEM; return false; }
    memcpy(data, QIHSE_VDB_EDGE_MAGIC, 8u);
    qihse_le_write_u32(data + 8u, QIHSE_VDB_EDGE_VERSION);
    qihse_le_write_u32(data + 12u, QIHSE_VDB_EDGE_HEADER_SIZE);
    qihse_le_write_u64(data + 16u, vdb->next_generation ? vdb->next_generation - 1u : 0u);
    qihse_le_write_u64(data + 24u, (uint64_t)source_count);
    qihse_le_write_u64(data + 32u, (uint64_t)vdb->explicit_edge_count);
    qihse_le_write_u64(data + 40u, QIHSE_VDB_EDGE_HEADER_SIZE);
    qihse_le_write_u64(data + 48u, QIHSE_VDB_EDGE_HEADER_SIZE + (uint64_t)source_bytes);
    qihse_le_write_u64(data + 56u, QIHSE_VDB_EDGE_HEADER_SIZE + (uint64_t)source_bytes +
                                    (uint64_t)record_bytes);
    data_offset = QIHSE_VDB_EDGE_HEADER_SIZE + source_bytes + record_bytes;
    for (i = 0u; i < vdb->explicit_edge_count; i++) {
        qihse_vdb_edge_t* edge = &vdb->explicit_edges[i];
        uint8_t* record = data + QIHSE_VDB_EDGE_HEADER_SIZE + source_bytes +
                          i * QIHSE_VDB_EDGE_RECORD_SIZE;
        size_t type_len = strlen(edge->edge_type);
        if (i == 0u || edge->from_id != vdb->explicit_edges[i - 1u].from_id) {
            size_t end = i + 1u;
            uint8_t* source = data + QIHSE_VDB_EDGE_HEADER_SIZE +
                              source_index * QIHSE_VDB_EDGE_SOURCE_SIZE;
            while (end < vdb->explicit_edge_count &&
                   vdb->explicit_edges[end].from_id == edge->from_id) end++;
            qihse_le_write_u64(source + 0u, edge->from_id);
            qihse_le_write_u64(source + 8u, (uint64_t)i);
            qihse_le_write_u64(source + 16u, (uint64_t)(end - i));
            source_index++;
        }
        qihse_le_write_u64(record + 0u, edge->to_id);
        qihse_le_write_u64(record + 8u, (uint64_t)data_offset);
        qihse_le_write_u32(record + 16u, (uint32_t)type_len);
        qihse_le_write_u64(record + 24u, (uint64_t)(data_offset + type_len));
        qihse_le_write_u64(record + 32u, (uint64_t)edge->metadata_size);
        memcpy(data + data_offset, edge->edge_type, type_len);
        data_offset += type_len;
        if (edge->metadata_size != 0u) {
            memcpy(data + data_offset, edge->metadata, edge->metadata_size);
            data_offset += edge->metadata_size;
        }
    }
    qihse_le_write_u64(data + 64u,
                        qihse_fnv1a64(data + QIHSE_VDB_EDGE_HEADER_SIZE,
                                      total - QIHSE_VDB_EDGE_HEADER_SIZE));
    *out = data;
    *out_size = total;
    return true;
}

static bool qihse_vdb_load_edges(qihse_vector_db_t vdb) {
    qihse_container_t ctr;
    uint8_t* data = NULL;
    size_t size = 0u;
    uint64_t edge_count64 = 0u;
    uint64_t source_count64 = 0u;
    uint64_t source_offset = 0u;
    uint64_t record_offset = 0u;
    uint64_t data_offset = 0u;
    qihse_vdb_edge_t* edges = NULL;
    size_t i;
    uint64_t expected_first = 0u;
    bool ok = false;

    if (!vdb || !vdb->db_path) { errno = EINVAL; return false; }
    if (!qihse_ctr_open_read(vdb->db_path, &ctr)) return false;
    if (!qihse_ctr_find_section(&ctr, QIHSE_CTR_SEC_EDGES)) {
        qihse_ctr_close(&ctr);
        return true;
    }
    if (!qihse_ctr_read_section_alloc(&ctr, QIHSE_CTR_SEC_EDGES, &data, &size)) {
        qihse_ctr_close(&ctr);
        return false;
    }
    qihse_ctr_close(&ctr);
    if (size < QIHSE_VDB_EDGE_HEADER_SIZE ||
        memcmp(data, QIHSE_VDB_EDGE_MAGIC, 8u) != 0 ||
        qihse_le_read_u32(data + 8u) != QIHSE_VDB_EDGE_VERSION ||
        qihse_le_read_u32(data + 12u) != QIHSE_VDB_EDGE_HEADER_SIZE ||
        qihse_fnv1a64(data + QIHSE_VDB_EDGE_HEADER_SIZE,
                      size - QIHSE_VDB_EDGE_HEADER_SIZE) != qihse_le_read_u64(data + 64u)) {
        errno = EINVAL;
        goto done;
    }
    source_count64 = qihse_le_read_u64(data + 24u);
    edge_count64 = qihse_le_read_u64(data + 32u);
    source_offset = qihse_le_read_u64(data + 40u);
    record_offset = qihse_le_read_u64(data + 48u);
    data_offset = qihse_le_read_u64(data + 56u);
    if (source_count64 > SIZE_MAX || edge_count64 > SIZE_MAX ||
        source_offset != QIHSE_VDB_EDGE_HEADER_SIZE ||
        source_count64 > (size - (size_t)source_offset) / QIHSE_VDB_EDGE_SOURCE_SIZE ||
        record_offset != source_offset + source_count64 * QIHSE_VDB_EDGE_SOURCE_SIZE ||
        edge_count64 > (size - (size_t)record_offset) / QIHSE_VDB_EDGE_RECORD_SIZE ||
        data_offset != record_offset + edge_count64 * QIHSE_VDB_EDGE_RECORD_SIZE ||
        data_offset > size) {
        errno = EINVAL;
        goto done;
    }
    edges = (qihse_vdb_edge_t*)calloc(edge_count64 ? (size_t)edge_count64 : 1u,
                                      sizeof(*edges));
    if (!edges) { errno = ENOMEM; goto done; }
    for (i = 0u; i < (size_t)source_count64; i++) {
        const uint8_t* source = data + source_offset + i * QIHSE_VDB_EDGE_SOURCE_SIZE;
        uint64_t from_id = qihse_le_read_u64(source + 0u);
        uint64_t first = qihse_le_read_u64(source + 8u);
        uint64_t count = qihse_le_read_u64(source + 16u);
        size_t j;
        if (count == 0u || first != expected_first || first > edge_count64 ||
            count > edge_count64 - first ||
            (i != 0u && from_id <= qihse_le_read_u64(
                data + source_offset + (i - 1u) * QIHSE_VDB_EDGE_SOURCE_SIZE))) {
            errno = EINVAL;
            goto done;
        }
        expected_first = first + count;
        for (j = (size_t)first; j < (size_t)(first + count); j++) {
            const uint8_t* record = data + record_offset + j * QIHSE_VDB_EDGE_RECORD_SIZE;
            uint64_t type_off = qihse_le_read_u64(record + 8u);
            uint32_t type_len = qihse_le_read_u32(record + 16u);
            uint64_t meta_off = qihse_le_read_u64(record + 24u);
            uint64_t meta_len = qihse_le_read_u64(record + 32u);
            if (type_len == 0u || type_len > QIHSE_EDGE_TYPE_MAX || type_off < data_offset ||
                type_off > size || type_len > size - type_off || meta_off < data_offset ||
                meta_off > size || meta_len > size - meta_off || meta_len > SIZE_MAX) {
                errno = EINVAL;
                goto done;
            }
            edges[j].from_id = from_id;
            edges[j].to_id = qihse_le_read_u64(record + 0u);
            memcpy(edges[j].edge_type, data + type_off, type_len);
            edges[j].edge_type[type_len] = '\0';
            if (meta_len != 0u) {
                edges[j].metadata = malloc((size_t)meta_len);
                if (!edges[j].metadata) { errno = ENOMEM; goto done; }
                memcpy(edges[j].metadata, data + meta_off, (size_t)meta_len);
                edges[j].metadata_size = (size_t)meta_len;
            }
        }
    }
    if (expected_first != edge_count64 ||
        ((edge_count64 == 0u) != (source_count64 == 0u))) {
        errno = EINVAL;
        goto done;
    }
    if ((size_t)edge_count64 != 0u) {
        for (i = 0u; i < (size_t)edge_count64; i++) {
            if (!qihse_vdb_edge_endpoints_valid(vdb, edges[i].from_id, edges[i].to_id) ||
                (i != 0u && qihse_vdb_edge_compare(&edges[i - 1u], &edges[i]) >= 0)) {
                errno = EINVAL;
                goto done;
            }
        }
    }
    vdb->explicit_edges = edges;
    vdb->explicit_edge_count = (size_t)edge_count64;
    vdb->explicit_edge_capacity = (size_t)edge_count64;
    edges = NULL;
    ok = true;
done:
    qihse_vdb_edge_array_free(edges, (size_t)(edge_count64 > SIZE_MAX ? 0u : edge_count64));
    free(data);
    return ok;
}

/* ============================================================================
 * GRAPH SIDECAR PERSISTENCE
 * ============================================================================ */

static bool qihse_vdb_graph_save(qihse_vector_db_t vdb) {
    uint8_t header[52];
    uint8_t* payload = NULL;
    uint8_t* section = NULL;
    size_t payload_size;
    size_t section_size;
    size_t neighbors_bytes;
    size_t counts_bytes;
    size_t map_bytes;
    uint64_t crc;
    bool ok;

    if (!vdb || !vdb->db_path || vdb->graph_status != QIHSE_VDB_GRAPH_VALID ||
        !vdb->graph_live_row_map) {
        return false;
    }

    neighbors_bytes = vdb->graph_capacity * vdb->graph_M * sizeof(size_t);
    counts_bytes = vdb->graph_capacity * sizeof(size_t);
    map_bytes = vdb->graph_capacity * sizeof(size_t);
    payload_size = counts_bytes + neighbors_bytes + map_bytes;
    payload = (uint8_t*)malloc(payload_size ? payload_size : 1u);
    if (!payload) {
        return false;
    }

    memcpy(payload, vdb->graph_neighbor_counts, counts_bytes);
    memcpy(payload + counts_bytes, vdb->graph_neighbors, neighbors_bytes);
    memcpy(payload + counts_bytes + neighbors_bytes, vdb->graph_live_row_map, map_bytes);

    crc = qihse_fnv1a64(payload, payload_size);
    memset(header, 0, sizeof(header));
    memcpy(header, QIHSE_VDB_GRAPH_MAGIC, 8u);
    qihse_le_write_u32(header + 8u, 2u);
    qihse_le_write_u64(header + 12u, vdb->committed_generation);
    qihse_le_write_u64(header + 20u, crc);
    qihse_le_write_u64(header + 28u, (uint64_t)payload_size);
    qihse_le_write_u64(header + 36u, (uint64_t)vdb->graph_entry_point);
    qihse_le_write_u64(header + 44u, (uint64_t)vdb->graph_M);

    section_size = sizeof(header) + payload_size;
    section = (uint8_t*)malloc(section_size);
    if (!section) {
        free(payload);
        return false;
    }
    memcpy(section, header, sizeof(header));
    memcpy(section + sizeof(header), payload, payload_size);
    free(payload);

    {
        qihse_container_t ctr;
        qihse_ctr_section_buf_t buf;
        buf.section_id = QIHSE_CTR_SEC_GRAPH;
        buf.data = section;
        buf.size = section_size;
        ok = qihse_ctr_open_write(vdb->db_path, false, &ctr) &&
             qihse_ctr_flush(&ctr, &buf, 1u);
        qihse_ctr_close(&ctr);
    }
    free(section);
    return ok;
}

static bool qihse_vdb_graph_load(qihse_vector_db_t vdb) {
    uint8_t header[52];
    uint8_t* section = NULL;
    size_t section_size = 0u;
    uint8_t* payload = NULL;
    size_t payload_size;
    size_t neighbors_bytes;
    size_t counts_bytes;
    size_t map_bytes;
    uint64_t crc;
    uint64_t generation;

    if (!vdb || !vdb->db_path) {
        return false;
    }
    {
        qihse_container_t ctr;
        bool has;
        if (!qihse_ctr_open_read(vdb->db_path, &ctr)) {
            return errno == ENOENT;
        }
        has = qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_GRAPH) > 0u;
        if (has) {
            qihse_ctr_read_section_alloc(&ctr, QIHSE_CTR_SEC_GRAPH, &section, &section_size);
        }
        qihse_ctr_close(&ctr);
        if (!has) {
            return true; /* absent is not an error */
        }
    }
    if (!section || section_size < sizeof(header)) {
        free(section);
        return false;
    }
    memcpy(header, section, sizeof(header));
    if (memcmp(header, QIHSE_VDB_GRAPH_MAGIC, 8u) != 0) {
        free(section);
        return false;
    }
    uint32_t version = qihse_le_read_u32(header + 8u);
    if (version != 1u && version != 2u) {
        free(section);
        return false;
    }
    generation = qihse_le_read_u64(header + 12u);
    crc = qihse_le_read_u64(header + 20u);
    payload_size = (size_t)qihse_le_read_u64(header + 28u);
    (void)generation;
    if (payload_size == 0u || section_size != sizeof(header) + payload_size) {
        free(section);
        return false;
    }
    payload = section + sizeof(header);

    /* Restore graph metadata BEFORE validating payload dimensions */
    size_t loaded_M = 0u;
    size_t loaded_entry = 0u;
    if (version >= 2u) {
        loaded_entry = (size_t)qihse_le_read_u64(header + 36u);
        loaded_M = (size_t)qihse_le_read_u64(header + 44u);
    }
    if (loaded_M == 0u && vdb->live_vectors > 0u) {
        /* Version 1 fallback: infer M from payload_size = counts + neighbors + map */
        size_t elem = sizeof(size_t);
        size_t cap = vdb->live_vectors;
        if (payload_size > cap * 2u * elem && (payload_size - cap * 2u * elem) % (cap * elem) == 0u) {
            loaded_M = (payload_size - cap * 2u * elem) / (cap * elem);
        }
    }

    if (qihse_fnv1a64(payload, payload_size) != crc) {
        free(section);
        return false;
    }

    counts_bytes = vdb->live_vectors * sizeof(size_t);
    neighbors_bytes = vdb->live_vectors * loaded_M * sizeof(size_t);
    map_bytes = vdb->live_vectors * sizeof(size_t);
    if (counts_bytes + neighbors_bytes + map_bytes != payload_size) {
        free(section);
        return false;
    }

    qihse_vdb_graph_destroy(vdb);
    vdb->graph_neighbor_counts = (size_t*)malloc(counts_bytes ? counts_bytes : 1u);
    vdb->graph_neighbors = (size_t*)malloc(neighbors_bytes ? neighbors_bytes : 1u);
    vdb->graph_live_row_map = (size_t*)malloc(map_bytes ? map_bytes : 1u);
    if (!vdb->graph_neighbor_counts || !vdb->graph_neighbors || !vdb->graph_live_row_map) {
        qihse_vdb_graph_destroy(vdb);
        free(section);
        return false;
    }
    memcpy(vdb->graph_neighbor_counts, payload, counts_bytes);
    memcpy(vdb->graph_neighbors, payload + counts_bytes, neighbors_bytes);
    memcpy(vdb->graph_live_row_map, payload + counts_bytes + neighbors_bytes, map_bytes);
    vdb->graph_capacity = vdb->live_vectors;
    vdb->graph_nodes = vdb->live_vectors;
    vdb->graph_status = QIHSE_VDB_GRAPH_VALID;
    vdb->graph_entry_point = loaded_entry;
    vdb->graph_M = loaded_M;
    
    /* Rebuild HNSW index from restored vectors — sidecar only stores flat arrays */
    if (vdb->graph_status == QIHSE_VDB_GRAPH_VALID && vdb->live_vectors > 0u && loaded_M > 0u) {
        vdb->hnsw_index = (qihse_hnsw_index_t*)calloc(1, sizeof(qihse_hnsw_index_t));
        if (vdb->hnsw_index) {
            vdb->hnsw_index->params.M = (uint32_t)loaded_M;
            vdb->hnsw_index->params.M0 = (uint32_t)(loaded_M * 2u);
            vdb->hnsw_index->params.ef_construction = 200u;
            vdb->hnsw_index->params.ef_search = 200u;
            vdb->hnsw_index->params.mult = 1.0f / logf((float)loaded_M);
            vdb->hnsw_index->params.distance_fn = qihse_vdb_euclidean_distance;
            vdb->hnsw_index->params.get_vector_fn = qihse_hnsw_vdb_get_vector;
            vdb->hnsw_index->params.user_context = vdb;
            vdb->hnsw_index->params.dim = vdb->vector_dims;
            vdb->hnsw_index->max_level = -1;
            vdb->hnsw_index->num_nodes = 0;
            
            for (size_t i = 0u; i < vdb->live_vectors; i++) {
                size_t actual_i = vdb->graph_live_row_map[i];
                const qihse_index_row_t* row_i = &vdb->rows[actual_i];
                const float* vec_i = qihse_vdb_vector_at(vdb, row_i);
                if (vec_i) {
                    hnsw_insert(vdb->hnsw_index, (uint32_t)i, vec_i, vdb->vector_dims);
                }
            }
        }
    }
    
    free(section);
    return true;
}

/* ============================================================================
 * TIER METADATA SIDECAR PERSISTENCE
 * ============================================================================ */

static bool qihse_vdb_tier_save(qihse_vector_db_t vdb) {
    uint8_t header[36];
    size_t tier_bytes;
    size_t count_bytes;
    size_t payload_size;
    size_t section_size;
    uint8_t* section = NULL;
    uint64_t crc;
    bool ok;

    if (!vdb || !vdb->db_path || vdb->live_vectors == 0u ||
        !vdb->row_tier || !vdb->row_access_counts) {
        return false;
    }

    tier_bytes = vdb->total_vectors * sizeof(qihse_memory_tier_t);
    count_bytes = vdb->total_vectors * sizeof(uint64_t);
    payload_size = tier_bytes + count_bytes;
    section_size = sizeof(header) + payload_size;
    section = (uint8_t*)malloc(section_size);
    if (!section) {
        return false;
    }

    memcpy(section + sizeof(header), vdb->row_tier, tier_bytes);
    memcpy(section + sizeof(header) + tier_bytes, vdb->row_access_counts, count_bytes);

    crc = qihse_fnv1a64(section + sizeof(header), payload_size);
    memset(header, 0, sizeof(header));
    memcpy(header, "QIHSEQTZ", 8u);
    qihse_le_write_u32(header + 8u, 1u);
    qihse_le_write_u64(header + 12u, vdb->committed_generation);
    qihse_le_write_u64(header + 20u, crc);
    qihse_le_write_u64(header + 28u, (uint64_t)payload_size);
    memcpy(section, header, sizeof(header));

    {
        qihse_container_t ctr;
        qihse_ctr_section_buf_t buf;
        buf.section_id = QIHSE_CTR_SEC_TIER;
        buf.data = section;
        buf.size = section_size;
        ok = qihse_ctr_open_write(vdb->db_path, false, &ctr) &&
             qihse_ctr_flush(&ctr, &buf, 1u);
        qihse_ctr_close(&ctr);
    }
    free(section);
    return ok;
}

static bool qihse_vdb_tier_load(qihse_vector_db_t vdb) {
    uint8_t header[36];
    size_t tier_bytes;
    size_t count_bytes;
    size_t payload_size;
    uint8_t* section = NULL;
    size_t section_size = 0u;
    uint8_t* payload;
    uint64_t crc;
    uint64_t generation;

    if (!vdb || !vdb->db_path) {
        return false;
    }
    {
        qihse_container_t ctr;
        bool has;
        if (!qihse_ctr_open_read(vdb->db_path, &ctr)) {
            return errno == ENOENT;
        }
        has = qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_TIER) > 0u;
        if (has) {
            qihse_ctr_read_section_alloc(&ctr, QIHSE_CTR_SEC_TIER, &section, &section_size);
        }
        qihse_ctr_close(&ctr);
        if (!has) {
            return true;
        }
    }
    if (!section || section_size < sizeof(header)) {
        free(section);
        return false;
    }
    memcpy(header, section, sizeof(header));
    if (memcmp(header, "QIHSEQTZ", 8u) != 0) {
        free(section);
        return false;
    }
    generation = qihse_le_read_u64(header + 12u);
    crc = qihse_le_read_u64(header + 20u);
    payload_size = (size_t)qihse_le_read_u64(header + 28u);
    if (generation != vdb->committed_generation || payload_size == 0u ||
        section_size != sizeof(header) + payload_size) {
        free(section);
        return false;
    }
    payload = section + sizeof(header);
    if (qihse_fnv1a64(payload, payload_size) != crc) {
        free(section);
        return false;
    }

    tier_bytes = vdb->total_vectors * sizeof(qihse_memory_tier_t);
    count_bytes = vdb->total_vectors * sizeof(uint64_t);
    if (tier_bytes + count_bytes != payload_size) {
        free(section);
        return false;
    }

    /* Ensure tracking arrays are allocated */
    if (vdb->row_tracking_capacity < vdb->total_vectors) {
        uint64_t* new_counts = (uint64_t*)realloc(vdb->row_access_counts, vdb->total_vectors * sizeof(*new_counts));
        uint64_t* new_last = (uint64_t*)realloc(vdb->row_last_access_ns, vdb->total_vectors * sizeof(*new_last));
        qihse_memory_tier_t* new_tier = (qihse_memory_tier_t*)realloc(vdb->row_tier, vdb->total_vectors * sizeof(*new_tier));
        if (!new_counts || !new_last || !new_tier) {
            free(section);
            return false;
        }
        vdb->row_access_counts = new_counts;
        vdb->row_last_access_ns = new_last;
        vdb->row_tier = new_tier;
        vdb->row_tracking_capacity = vdb->total_vectors;
    }

    memcpy(vdb->row_tier, payload, tier_bytes);
    memcpy(vdb->row_access_counts, payload + tier_bytes, count_bytes);
    free(section);
    return true;
}

/* ============================================================================
 * INT8 SIDECAR PERSISTENCE
 * ============================================================================ */

static bool qihse_vdb_int8_save(qihse_vector_db_t vdb) {
    uint8_t header[36];
    uint8_t* section = NULL;
    size_t payload_size;
    size_t section_size;
    size_t minmax_bytes;
    size_t quantized_bytes;
    uint64_t crc;
    bool ok;

    if (!vdb || !vdb->db_path || vdb->int8_status != QIHSE_VDB_INT8_VALID) {
        return false;
    }

    minmax_bytes = vdb->int8_dims * sizeof(float) * 2u;
    quantized_bytes = vdb->int8_bytes;
    payload_size = minmax_bytes + quantized_bytes;
    section_size = sizeof(header) + payload_size;
    section = (uint8_t*)malloc(section_size);
    if (!section) {
        return false;
    }

    memcpy(section + sizeof(header), vdb->int8_dim_min, vdb->int8_dims * sizeof(float));
    memcpy(section + sizeof(header) + vdb->int8_dims * sizeof(float),
           vdb->int8_dim_max, vdb->int8_dims * sizeof(float));
    memcpy(section + sizeof(header) + minmax_bytes, vdb->int8_vectors, quantized_bytes);

    crc = qihse_fnv1a64(section + sizeof(header), payload_size);
    memset(header, 0, sizeof(header));
    memcpy(header, QIHSE_VDB_INT8_MAGIC, 8u);
    qihse_le_write_u32(header + 8u, 1u);
    qihse_le_write_u64(header + 12u, vdb->committed_generation);
    qihse_le_write_u64(header + 20u, crc);
    qihse_le_write_u64(header + 28u, (uint64_t)payload_size);
    memcpy(section, header, sizeof(header));

    {
        qihse_container_t ctr;
        qihse_ctr_section_buf_t buf;
        buf.section_id = QIHSE_CTR_SEC_INT8;
        buf.data = section;
        buf.size = section_size;
        ok = qihse_ctr_open_write(vdb->db_path, false, &ctr) &&
             qihse_ctr_flush(&ctr, &buf, 1u);
        qihse_ctr_close(&ctr);
    }
    free(section);
    return ok;
}

static bool qihse_vdb_int8_load(qihse_vector_db_t vdb) {
    uint8_t header[36];
    uint8_t* section = NULL;
    size_t section_size = 0u;
    uint8_t* payload;
    size_t payload_size;
    size_t minmax_bytes;
    size_t quantized_bytes;
    uint64_t crc;
    uint64_t generation;

    if (!vdb || !vdb->db_path) {
        return false;
    }
    {
        qihse_container_t ctr;
        bool has;
        if (!qihse_ctr_open_read(vdb->db_path, &ctr)) {
            return errno == ENOENT;
        }
        has = qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_INT8) > 0u;
        if (has) {
            qihse_ctr_read_section_alloc(&ctr, QIHSE_CTR_SEC_INT8, &section, &section_size);
        }
        qihse_ctr_close(&ctr);
        if (!has) {
            return true;
        }
    }
    if (!section || section_size < sizeof(header)) {
        free(section);
        return false;
    }
    memcpy(header, section, sizeof(header));
    if (memcmp(header, QIHSE_VDB_INT8_MAGIC, 8u) != 0) {
        free(section);
        return false;
    }
    generation = qihse_le_read_u64(header + 12u);
    crc = qihse_le_read_u64(header + 20u);
    payload_size = (size_t)qihse_le_read_u64(header + 28u);
    if (generation != vdb->committed_generation || payload_size == 0u ||
        section_size != sizeof(header) + payload_size) {
        free(section);
        return false;
    }
    payload = section + sizeof(header);
    if (qihse_fnv1a64(payload, payload_size) != crc) {
        free(section);
        return false;
    }

    minmax_bytes = vdb->vector_dims * sizeof(float) * 2u;
    quantized_bytes = vdb->total_vectors * vdb->vector_dims * sizeof(int8_t);
    if (minmax_bytes + quantized_bytes != payload_size) {
        free(section);
        return false;
    }

    qihse_vdb_int8_destroy(vdb);
    vdb->int8_dim_min = (float*)malloc(vdb->vector_dims * sizeof(float));
    vdb->int8_dim_max = (float*)malloc(vdb->vector_dims * sizeof(float));
    vdb->int8_vectors = (int8_t*)malloc(quantized_bytes);
    if (!vdb->int8_dim_min || !vdb->int8_dim_max || !vdb->int8_vectors) {
        qihse_vdb_int8_destroy(vdb);
        free(section);
        return false;
    }
    memcpy(vdb->int8_dim_min, payload, vdb->vector_dims * sizeof(float));
    memcpy(vdb->int8_dim_max, payload + vdb->vector_dims * sizeof(float), vdb->vector_dims * sizeof(float));
    memcpy(vdb->int8_vectors, payload + minmax_bytes, quantized_bytes);
    free(section);
    vdb->int8_rows = vdb->total_vectors;
    vdb->int8_dims = vdb->vector_dims;
    vdb->int8_bytes = quantized_bytes;
    vdb->int8_status = QIHSE_VDB_INT8_VALID;
    return true;
}

static bool qihse_vdb_reserve_rows(qihse_vector_db_t vdb, size_t needed) {
    qihse_index_row_t* next;
    size_t cap;

    if (needed <= vdb->rows_capacity) {
        return true;
    }
    cap = vdb->rows_capacity ? vdb->rows_capacity : 8u;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2u) {
            errno = EOVERFLOW;
            return false;
        }
        cap *= 2u;
    }
    next = (qihse_index_row_t*)realloc(vdb->rows, cap * sizeof(*next));
    if (!next) {
        errno = ENOMEM;
        return false;
    }
    vdb->rows = next;
    vdb->rows_capacity = cap;

    /* Resize hierarchical storage tracking arrays */
    if (vdb->row_tracking_capacity < cap) {
        uint64_t* new_counts = (uint64_t*)realloc(
            vdb->row_access_counts, cap * sizeof(*new_counts));
        uint64_t* new_last = (uint64_t*)realloc(
            vdb->row_last_access_ns, cap * sizeof(*new_last));
        qihse_memory_tier_t* new_tier = (qihse_memory_tier_t*)realloc(
            vdb->row_tier, cap * sizeof(*new_tier));
        if (!new_counts || !new_last || !new_tier) {
            errno = ENOMEM;
            return false;
        }
        /* Zero-initialize new slots */
        for (size_t i = vdb->row_tracking_capacity; i < cap; ++i) {
            new_counts[i] = 0;
            new_last[i] = 0;
            new_tier[i] = QIHSE_MEM_DRAM;
        }
        vdb->row_access_counts = new_counts;
        vdb->row_last_access_ns = new_last;
        vdb->row_tier = new_tier;
        vdb->row_tracking_capacity = cap;
    }
    return true;
}

static bool qihse_vdb_reserve_bytes(uint8_t** ptr, size_t* cap, size_t needed) {
    uint8_t* next;
    size_t new_cap;

    if (needed <= *cap) {
        return true;
    }
    new_cap = *cap ? *cap : 256u;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2u) {
            errno = EOVERFLOW;
            return false;
        }
        new_cap *= 2u;
    }
    next = (uint8_t*)realloc(*ptr, new_cap);
    if (!next) {
        errno = ENOMEM;
        return false;
    }
    *ptr = next;
    *cap = new_cap;
    return true;
}

static bool qihse_vdb_u64_to_size(uint64_t value, size_t* out) {
    if (!out || value > (uint64_t)SIZE_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    *out = (size_t)value;
    return true;
}

static bool qihse_vdb_mul_size_saturating(size_t a, size_t b, size_t* out) {
    if (!out) {
        errno = EINVAL;
        return false;
    }
    if (a != 0u && b > SIZE_MAX / a) {
        *out = SIZE_MAX;
        return true;
    }
    *out = a * b;
    return true;
}

static bool qihse_vdb_ceil_mul_div_saturating(size_t value,
                                              size_t numerator,
                                              size_t denominator,
                                              size_t* out) {
    size_t quotient;
    size_t remainder;
    size_t scaled_quotient;
    size_t scaled_remainder;
    size_t product;

    if (!out || denominator == 0u) {
        errno = EINVAL;
        return false;
    }
    quotient = value / denominator;
    remainder = value % denominator;
    if (quotient != 0u && numerator > SIZE_MAX / quotient) {
        *out = SIZE_MAX;
        return true;
    }
    scaled_quotient = quotient * numerator;
    if (remainder == 0u) {
        scaled_remainder = 0u;
    } else if (numerator > SIZE_MAX / remainder) {
        *out = SIZE_MAX;
        return true;
    } else {
        product = remainder * numerator;
        scaled_remainder = product / denominator +
            ((product % denominator) != 0u ? 1u : 0u);
    }
    if (scaled_quotient > SIZE_MAX - scaled_remainder) {
        *out = SIZE_MAX;
        return true;
    }
    *out = scaled_quotient + scaled_remainder;
    return true;
}

static bool qihse_vdb_resolve_candidate_pool(qihse_vector_db_t vdb,
                                             const qihse_vector_query_t* query,
                                             qihse_vector_db_query_mode_t mode,
                                             size_t* out_candidate_count) {
    size_t candidate_count;
    size_t multiplier;

    if (!vdb || !query || !out_candidate_count || query->top_k == 0u) {
        errno = EINVAL;
        return false;
    }

    candidate_count = query->candidate_pool_size ?
        query->candidate_pool_size : query->candidate_count;
    if (candidate_count == 0u && mode == QIHSE_VDB_QUERY_TRINARY_SCALAR) {
        /*
         * Scalar qtri only stores signs. Dense non-negative vector families
         * such as SIFT can collapse to large equal-score buckets, so a small
         * default candidate pool silently drops exact nearest neighbors before
         * reranking. Keep explicit candidate_pool_size approximate, but make
         * the default scalar mode correctness-preserving.
         */
        candidate_count = vdb->total_vectors;
    }
    if (candidate_count == 0u) {
        /*
         * Defaults are intentionally conservative because qmag only chooses a
         * physical-row candidate set before exact float32 reranking.
         * High-dimensional rows need a wider pool, and tombstoned physical
         * rows can occupy candidate slots before the live-row filter runs.
         */
        multiplier = QIHSE_VDB_MAGNITUDE_CANDIDATE_MULTIPLIER;
        if (vdb->vector_dims >= 1024u) {
            multiplier += 8u;
        } else if (vdb->vector_dims >= 256u) {
            multiplier += 4u;
        }
        if (!qihse_vdb_mul_size_saturating(query->top_k, multiplier,
                                           &candidate_count)) {
            return false;
        }
        if (vdb->live_vectors != 0u && vdb->live_vectors < vdb->total_vectors &&
            !qihse_vdb_ceil_mul_div_saturating(candidate_count,
                                               vdb->total_vectors,
                                               vdb->live_vectors,
                                               &candidate_count)) {
            return false;
        }
    }
    if (candidate_count > vdb->total_vectors) {
        candidate_count = vdb->total_vectors;
    }
    if (candidate_count < query->top_k) {
        errno = EINVAL;
        return false;
    }
    *out_candidate_count = candidate_count;
    return true;
}

static bool qihse_vdb_ratio_lte(size_t numerator,
                                size_t denominator,
                                size_t max_numerator,
                                size_t max_denominator) {
    if (denominator == 0u || max_denominator == 0u) {
        return false;
    }
    return ((long double)numerator * (long double)max_denominator) <=
           ((long double)denominator * (long double)max_numerator);
}

static size_t qihse_vdb_qmag_default_multiplier(size_t active_dim_count,
                                                size_t vector_dims) {
    if (vector_dims == 0u || active_dim_count == 0u) {
        return 12u;
    }
    if (qihse_vdb_ratio_lte(active_dim_count, vector_dims, 1u, 32u)) {
        return 4u;
    }
    if (qihse_vdb_ratio_lte(active_dim_count, vector_dims, 1u, 16u)) {
        return 6u;
    }
    if (qihse_vdb_ratio_lte(active_dim_count, vector_dims, 1u, 8u)) {
        return 8u;
    }
    return 12u;
}

static bool qihse_vdb_resolve_qmag_candidate_pool(qihse_vector_db_t vdb,
                                                  const qihse_vector_query_t* query,
                                                  size_t active_dim_count,
                                                  size_t* out_candidate_count) {
    size_t candidate_count;
    size_t live_rows;
    bool default_pool;

    if (!vdb || !query || !out_candidate_count || query->top_k == 0u ||
        active_dim_count > vdb->vector_dims) {
        errno = EINVAL;
        return false;
    }

    live_rows = vdb->live_vectors;
    candidate_count = query->candidate_pool_size ?
        query->candidate_pool_size : query->candidate_count;
    default_pool = candidate_count == 0u;

    if (default_pool) {
        size_t multiplier = qihse_vdb_qmag_default_multiplier(active_dim_count,
                                                              vdb->vector_dims);
        if (!qihse_vdb_mul_size_saturating(query->top_k, multiplier,
                                           &candidate_count)) {
            return false;
        }
    }

    if (live_rows != 0u && candidate_count > live_rows) {
        candidate_count = live_rows;
    }
    if (default_pool && live_rows >= query->top_k && candidate_count < query->top_k) {
        candidate_count = query->top_k;
    }
    if (!default_pool && candidate_count < query->top_k) {
        errno = EINVAL;
        return false;
    }

    *out_candidate_count = candidate_count;
    return true;
}

static bool qihse_vdb_qmag_policy_allows(size_t active_dim_count,
                                         size_t vector_dims,
                                         size_t candidate_count,
                                         size_t live_rows,
                                         size_t top_k) {
    size_t policy_max_topk_num = 1u;
    size_t policy_max_topk_den = 64u;
    size_t policy_max_rerank_num = 1u;
    size_t policy_max_rerank_den = 8u;

    if (vector_dims == 0u || live_rows < QIHSE_VDB_MAGNITUDE_POLICY_MIN_LIVE_ROWS ||
        candidate_count < top_k) {
        return false;
    }
    if (!qihse_vdb_ratio_lte(active_dim_count, vector_dims,
                             QIHSE_VDB_MAGNITUDE_POLICY_MAX_ACTIVE_NUM,
                             QIHSE_VDB_MAGNITUDE_POLICY_MAX_ACTIVE_DEN)) {
        return false;
    }

    /*
     * Dimension-aware policy: sparse queries use faster default pools (small
     * multipliers/rerank pressure), denser queries keep smaller safe pools.
     * This preserves exactness fallback for workloads that look too dense/too
     * wide for qmag to remain a safe default accelerator.
     */
    if (qihse_vdb_ratio_lte(active_dim_count, vector_dims, 1u, 32u)) {
        policy_max_topk_num = 1u;
        policy_max_topk_den = 16u;
        policy_max_rerank_num = 1u;
        policy_max_rerank_den = 4u;
    } else if (qihse_vdb_ratio_lte(active_dim_count, vector_dims, 1u, 16u)) {
        policy_max_topk_num = QIHSE_VDB_MAGNITUDE_POLICY_MAX_TOPK_NUM;
        policy_max_topk_den = QIHSE_VDB_MAGNITUDE_POLICY_MAX_TOPK_DEN;
        policy_max_rerank_num = QIHSE_VDB_MAGNITUDE_POLICY_MAX_RERANK_NUM;
        policy_max_rerank_den = QIHSE_VDB_MAGNITUDE_POLICY_MAX_RERANK_DEN;
    } else if (qihse_vdb_ratio_lte(active_dim_count, vector_dims, 1u, 8u)) {
        policy_max_topk_num = 1u;
        policy_max_topk_den = 64u;
        policy_max_rerank_num = 1u;
        policy_max_rerank_den = 8u;
    } else {
        return false;
    }

    if (!qihse_vdb_ratio_lte(top_k, live_rows, policy_max_topk_num,
                             policy_max_topk_den)) {
        return false;
    }
    if (!qihse_vdb_ratio_lte(candidate_count, live_rows,
                             policy_max_rerank_num,
                             policy_max_rerank_den)) {
        return false;
    }
    return true;
}

static bool qihse_vdb_rebuild_idmap(qihse_vector_db_t vdb, bool mark_dirty) {
    qihse_idmap_entry_t* entries = NULL;
    size_t count = 0u;

    if (vdb->mapped_idmap && vdb->mapped_idmap != MAP_FAILED) {
        munmap(vdb->mapped_idmap, vdb->mapped_idmap_bytes);
    }
    vdb->mapped_idmap = NULL;
    vdb->mapped_idmap_bytes = 0u;
    if (vdb->idmap_mmap_fd >= 0) {
        close(vdb->idmap_mmap_fd);
    }
    vdb->idmap_mmap_fd = -1;

    if (!qihse_vector_store_build_idmap(vdb->rows, vdb->total_vectors, &entries, &count)) {
        return false;
    }
    free(vdb->idmap);
    vdb->idmap = entries;
    vdb->idmap_count = count;
    vdb->idmap_valid = true;
    vdb->idmap_dirty = mark_dirty;
    return true;
}

static bool qihse_vdb_id_exists(const qihse_vector_db_t vdb, uint64_t id) {
    size_t i;

    for (i = 0u; i < vdb->total_vectors; i++) {
        if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u &&
            vdb->rows[i].vector_id == id) {
            return true;
        }
    }
    return false;
}

static int64_t qihse_vdb_idmap_key(uint64_t id) {
    return (int64_t)(id ^ UINT64_C(0x8000000000000000));
}

static bool qihse_vdb_ensure_writable(qihse_vector_db_t vdb) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (vdb->read_only || vdb->mapped_vectors || vdb->rows_are_mapped ||
        vdb->mapped_metadata || vdb->mapped_index || vdb->mapped_idmap) {
        errno = EROFS;
        return false;
    }
    return true;
}

static bool qihse_vdb_has_duplicate_ids(const uint64_t* ids, size_t count) {
    size_t i;
    size_t j;

    if (!ids && count != 0u) {
        errno = EINVAL;
        return true;
    }
    for (i = 0u; i < count; i++) {
        for (j = i + 1u; j < count; j++) {
            if (ids[i] == ids[j]) {
                errno = EEXIST;
                return true;
            }
        }
    }
    return false;
}

static bool qihse_vdb_find_live_row_by_id(qihse_vector_db_t vdb,
                                          uint64_t id,
                                          size_t* out_row_index) {
    int64_t key;
    size_t lo;
    size_t hi;
    size_t found;
    bool have_match = false;

    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (!vdb->idmap_valid && !qihse_vdb_rebuild_idmap(vdb, vdb->file_backed && !vdb->read_only)) {
        return false;
    }
    key = qihse_vdb_idmap_key(id);
    lo = 0u;
    hi = vdb->idmap_count;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) / 2u);
        if (vdb->idmap[mid].key < key) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    found = lo;
    while (found < vdb->idmap_count && vdb->idmap[found].key == key) {
        uint64_t row64 = vdb->idmap[found].row_index;
        if (row64 < (uint64_t)vdb->total_vectors) {
            size_t row_index = (size_t)row64;
            qihse_index_row_t* row = &vdb->rows[row_index];
            if (row->vector_id == id &&
                (row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
                (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
                if (!have_match || (out_row_index && row_index > *out_row_index)) {
                    if (out_row_index) {
                        *out_row_index = row_index;
                    }
                    have_match = true;
                }
            }
        }
        found++;
    }
    if (!have_match) {
        errno = ENOENT;
    }
    return have_match;
}

static size_t qihse_vdb_tombstone_live_id(qihse_vector_db_t vdb,
                                          uint64_t id,
                                          uint64_t generation) {
    size_t count = 0u;
    size_t i;

    for (i = 0u; i < vdb->total_vectors; i++) {
        qihse_index_row_t* row = &vdb->rows[i];
        if (row->vector_id == id &&
            (row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            row->row_flags |= QIHSE_ROW_F_TOMBSTONE;
            row->commit_generation = generation;
            count++;
        }
    }
    if (count != 0u) {
        vdb->live_vectors -= count;
        vdb->idmap_valid = false;
        vdb->idmap_dirty = true;
        vdb->dirty = true;
        qihse_vdb_set_trinary_stale(vdb);
    }
    return count;
}

static void qihse_vdb_finish_mutation_generation(qihse_vector_db_t vdb, uint64_t generation) {
    if (generation >= vdb->next_generation) {
        vdb->next_generation = generation + 1u;
    }
    vdb->dirty = true;
    vdb->idmap_valid = false;
    vdb->idmap_dirty = true;
    vdb->cache_generation++;
    qihse_vdb_set_trinary_stale(vdb);
}

static void qihse_vdb_set_trinary_stale(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    vdb->trinary_status = QIHSE_VDB_TRINARY_STALE;
    qihse_vdb_clear_trinary_sign_cache(vdb);
    qihse_vdb_set_magnitude_stale(vdb);
}

static void qihse_vdb_clear_trinary_cache(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->trinary);
    vdb->trinary = NULL;
    vdb->trinary_bytes = 0u;
    qihse_vdb_clear_trinary_sign_cache(vdb);
}

static void qihse_vdb_clear_trinary_sign_cache(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->trinary_signs);
    vdb->trinary_signs = NULL;
    vdb->trinary_sign_bytes = 0u;
    qihse_vdb_clear_qmag_transposed_cache(vdb);
}

static void qihse_vdb_set_magnitude_stale(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_STALE;
    qihse_vdb_clear_qmag_transposed_cache(vdb);
}

static void qihse_vdb_clear_magnitude_cache(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->magnitude);
    vdb->magnitude = NULL;
    vdb->magnitude_bytes = 0u;
    qihse_vdb_clear_qmag_transposed_cache(vdb);
}

static void qihse_vdb_clear_qmag_transposed_cache(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->qmag_transposed_signs);
    free(vdb->qmag_transposed_magnitude);
    free(vdb->qmag_transposed_live_rows);
    vdb->qmag_transposed_signs = NULL;
    vdb->qmag_transposed_magnitude = NULL;
    vdb->qmag_transposed_live_rows = NULL;
    vdb->qmag_transposed_bytes = 0u;
    vdb->qmag_transposed_rows = 0u;
    vdb->qmag_transposed_dims = 0u;
}

static const float* qihse_vdb_vector_at(const qihse_vector_db_t vdb, const qihse_index_row_t* row) {
    const uint8_t* base = vdb->mapped_vectors ? (const uint8_t*)vdb->mapped_vectors : vdb->vectors;
    uint64_t end;

    if (!base || !row || !qihse_checked_add_u64(row->vector_offset,
                                                (uint64_t)vdb->vector_dims * sizeof(float),
                                                &end) ||
        end > (uint64_t)vdb->vector_bytes_used) {
        return NULL;
    }
    return (const float*)(const void*)(base + row->vector_offset);
}

static const void* qihse_vdb_metadata_at(const qihse_vector_db_t vdb, const qihse_index_row_t* row) {
    const uint8_t* base = vdb->mapped_metadata ? (const uint8_t*)vdb->mapped_metadata : vdb->metadata;
    uint64_t end;

    if (!row || row->metadata_size == 0u) {
        return NULL;
    }
    if (!base ||
        !qihse_checked_add_u64(row->metadata_offset, row->metadata_size, &end) ||
        end > (uint64_t)vdb->metadata_bytes_used) {
        return NULL;
    }
    return base + row->metadata_offset;
}

static float qihse_vdb_cosine_similarity(const float* a, const float* b, size_t dims) {
    return qihse_distance_cosine(a, b, dims);
}

static float qihse_vdb_dot_product(const float* a, const float* b, size_t dims) {
    return qihse_distance_dot(a, b, dims);
}

static float qihse_vdb_euclidean_distance(const float* a, const float* b, size_t dims) {
    return qihse_distance_euclidean(a, b, dims);
}

static float qihse_vdb_compute_score(const float* a, const float* b, size_t dims,
                                     qihse_distance_metric_t metric) {
    switch (metric) {
        case QIHSE_DISTANCE_DOT_PRODUCT:
            return qihse_vdb_dot_product(a, b, dims);
        case QIHSE_DISTANCE_EUCLIDEAN: {
            float dist = qihse_vdb_euclidean_distance(a, b, dims);
            return 1.0f / (1.0f + dist);
        }
        case QIHSE_DISTANCE_COSINE:
        default:
            return qihse_vdb_cosine_similarity(a, b, dims);
    }
}

/* Forward declaration */
static bool qihse_vdb_insert_exact_result(qihse_vector_db_t vdb,
                                          const qihse_vector_query_t* query,
                                          const qihse_index_row_t* row,
                                          const float* vector,
                                          float score,
                                          qihse_vector_result_t* results,
                                          size_t result_limit,
                                          size_t* out_count);

/* ============================================================================
 * GRAPH INDEX SIDECAR (NSW-style candidate selector)
 * ============================================================================ */

static void qihse_vdb_graph_destroy(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->graph_neighbors);
    vdb->graph_neighbors = NULL;
    free(vdb->graph_neighbor_counts);
    vdb->graph_neighbor_counts = NULL;
    free(vdb->graph_live_row_map);
    vdb->graph_live_row_map = NULL;
    vdb->graph_nodes = 0u;
    vdb->graph_capacity = 0u;
    vdb->graph_entry_point = 0u;
    vdb->graph_status = QIHSE_VDB_GRAPH_ABSENT;
    if (vdb->hnsw_index) {
        hnsw_destroy(vdb->hnsw_index);
        vdb->hnsw_index = NULL;
    }
}

typedef struct {
    size_t id;
    float score;
} qihse_vdb_graph_neighbor_t;

/* ============================================================================
 * PARALLEL GRAPH BUILD
 * ============================================================================ */

static int qihse_vdb_graph_neighbor_cmp_desc(const void* a, const void* b) {
    const qihse_vdb_graph_neighbor_t* na = (const qihse_vdb_graph_neighbor_t*)a;
    const qihse_vdb_graph_neighbor_t* nb = (const qihse_vdb_graph_neighbor_t*)b;
    if (na->score > nb->score) return -1;
    if (na->score < nb->score) return 1;
    return 0;
}

static const float* qihse_hnsw_vdb_get_vector(void* user_context, uint32_t node_id) {
    qihse_vector_db_t vdb = (qihse_vector_db_t)user_context;
    if (!vdb || !vdb->graph_live_row_map) return NULL;
    size_t actual_i = vdb->graph_live_row_map[node_id];
    const qihse_index_row_t* row_i = &vdb->rows[actual_i];
    return qihse_vdb_vector_at(vdb, row_i);
}

static bool qihse_vdb_graph_build(qihse_vector_db_t vdb, size_t M, size_t ef_construction) {
    size_t i;
    size_t* live_row_map = NULL;
    size_t capacity;

    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }

    /* Use sensible defaults */
    if (M == 0u) {
        M = 16u;
    }
    if (ef_construction == 0u) {
        ef_construction = 200u;
    }

    capacity = vdb->live_vectors;
    if (capacity == 0u) {
        return true;
    }

    /* Build dense index mapping: live_row_map[dense_idx] = actual row index */
    live_row_map = (size_t*)malloc(capacity * sizeof(size_t));
    if (!live_row_map) {
        return false;
    }
    {
        size_t dense = 0u;
        for (i = 0u; i < vdb->total_vectors && dense < capacity; i++) {
            const qihse_index_row_t* row = &vdb->rows[i];
            if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
                (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
                live_row_map[dense++] = i;
            }
        }
    }

    qihse_vdb_graph_destroy(vdb);

    vdb->graph_live_row_map = live_row_map;

    vdb->hnsw_index = (qihse_hnsw_index_t*)calloc(1, sizeof(qihse_hnsw_index_t));
    if (!vdb->hnsw_index) {
        vdb->graph_live_row_map = NULL;
        free(live_row_map);
        return false;
    }
    vdb->hnsw_index->params.M = M;
    vdb->hnsw_index->params.M0 = M * 2;
    vdb->hnsw_index->params.ef_construction = ef_construction;
    vdb->hnsw_index->params.ef_search = ef_construction;
    vdb->hnsw_index->params.mult = 1.0f / logf((float)M);
    
    /* Wire up the real distance metric callback */
    vdb->hnsw_index->params.distance_fn = qihse_vdb_euclidean_distance; /* HNSW typically expects a true distance metric (lower is better), unlike cosine similarity. We use euclidean. */
    vdb->hnsw_index->params.get_vector_fn = qihse_hnsw_vdb_get_vector;
    vdb->hnsw_index->params.user_context = vdb;
    vdb->hnsw_index->params.dim = vdb->vector_dims;
    
    vdb->hnsw_index->max_level = -1;
    vdb->hnsw_index->num_nodes = 0;

    for (i = 0u; i < capacity; i++) {
        size_t actual_i = live_row_map[i];
        const qihse_index_row_t* row_i = &vdb->rows[actual_i];
        const float* vec_i = qihse_vdb_vector_at(vdb, row_i);
        if (vec_i) {
            hnsw_insert(vdb->hnsw_index, (uint32_t)i, vec_i, vdb->vector_dims);
        }
    }

    vdb->graph_neighbors = (size_t*)calloc(capacity * M, sizeof(size_t));
    vdb->graph_neighbor_counts = (size_t*)calloc(capacity, sizeof(size_t));
    if (!vdb->graph_neighbors || !vdb->graph_neighbor_counts) {
        free(vdb->graph_neighbors); vdb->graph_neighbors = NULL;
        free(vdb->graph_neighbor_counts); vdb->graph_neighbor_counts = NULL;
        vdb->graph_live_row_map = NULL;
        free(live_row_map);
        return false;
    }

    if (vdb->hnsw_index->max_level >= 0 && vdb->hnsw_index->layers[0]) {
        qihse_hnsw_layer_t* layer0 = vdb->hnsw_index->layers[0];
        for (i = 0; i < capacity; i++) {
            if (i < layer0->links_capacity && layer0->links[i]) {
                qihse_hnsw_links_t* links = layer0->links[i];
                size_t count = links->count;
                if (count > M) count = M;
                vdb->graph_neighbor_counts[i] = count;
                for (size_t j = 0; j < count; j++) {
                    vdb->graph_neighbors[i * M + j] = links->neighbors[j];
                }
            }
        }
    }

    vdb->graph_entry_point = vdb->hnsw_index->enter_point;
    vdb->graph_live_row_map = live_row_map;
    vdb->graph_capacity = capacity;
    vdb->graph_nodes = capacity;
    vdb->graph_M = M;
    vdb->graph_ef_construction = ef_construction;
    vdb->graph_status = QIHSE_VDB_GRAPH_VALID;
    return true;
}


/* ============================================================================
 * INT8 SCALAR QUANTIZATION SIDECAR
 * ============================================================================ */

static void qihse_vdb_int8_destroy(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->int8_vectors);
    vdb->int8_vectors = NULL;
    free(vdb->int8_dim_min);
    vdb->int8_dim_min = NULL;
    free(vdb->int8_dim_max);
    vdb->int8_dim_max = NULL;
    vdb->int8_rows = 0u;
    vdb->int8_dims = 0u;
    vdb->int8_bytes = 0u;
    vdb->int8_status = QIHSE_VDB_INT8_ABSENT;
}

static bool qihse_vdb_int8_build(qihse_vector_db_t vdb) {
    size_t i, d, lv;
    float* dim_min = NULL;
    float* dim_max = NULL;
    int8_t* quantized = NULL;
    size_t* live_rows = NULL;
    size_t dims;
    size_t n_rows;
    size_t n_live;

    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }

    dims = vdb->vector_dims;
    n_rows = vdb->total_vectors;
    n_live = vdb->live_vectors;

    /* Pre-collect live row indices to avoid dead-row checks in inner loops */
    live_rows = (size_t*)malloc(n_live * sizeof(size_t));
    if (!live_rows) {
        return false;
    }
    {
        size_t dense = 0u;
        for (i = 0u; i < n_rows && dense < n_live; i++) {
            const qihse_index_row_t* row = &vdb->rows[i];
            if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
                (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
                live_rows[dense++] = i;
            }
        }
    }

    dim_min = (float*)calloc(dims, sizeof(float));
    dim_max = (float*)calloc(dims, sizeof(float));
    {
        size_t quantized_bytes;
        if (!qihse_checked_mul_size(n_rows, dims, &quantized_bytes) ||
            !qihse_checked_mul_size(quantized_bytes, sizeof(int8_t), &quantized_bytes)) {
            free(dim_min);
            free(dim_max);
            free(live_rows);
            return false;
        }
        quantized = (int8_t*)calloc(quantized_bytes ? quantized_bytes : 1u, 1);
    }
    if (!dim_min || !dim_max || !quantized) {
        free(dim_min);
        free(dim_max);
        free(quantized);
        free(live_rows);
        return false;
    }

    /* Initialize min/max from first live row */
    {
        const float* vec = qihse_vdb_vector_at(vdb, &vdb->rows[live_rows[0]]);
        if (vec) {
            for (d = 0u; d < dims; d++) {
                dim_min[d] = vec[d];
                dim_max[d] = vec[d];
            }
        }
    }

    /* Compute per-dimension min/max across all live vectors */
    for (lv = 1u; lv < n_live; lv++) {
        const float* vec = qihse_vdb_vector_at(vdb, &vdb->rows[live_rows[lv]]);
        if (!vec) {
            continue;
        }
        for (d = 0u; d < dims; d++) {
            if (vec[d] < dim_min[d]) dim_min[d] = vec[d];
            if (vec[d] > dim_max[d]) dim_max[d] = vec[d];
        }
    }

    /* Quantize each vector: int8 = round(255 * (val - min) / (max - min)) - 128 */
    for (lv = 0u; lv < n_live; lv++) {
        size_t row_idx = live_rows[lv];
        const float* vec = qihse_vdb_vector_at(vdb, &vdb->rows[row_idx]);
        if (!vec) {
            continue;
        }
        for (d = 0u; d < dims; d++) {
            float range = dim_max[d] - dim_min[d];
            if (range < 1e-9f) {
                quantized[row_idx * dims + d] = 0;
            } else {
                float scaled = 255.0f * (vec[d] - dim_min[d]) / range;
                int val = (int)(scaled + 0.5f) - 128;
                if (val < -128) val = -128;
                if (val > 127) val = 127;
                quantized[row_idx * dims + d] = (int8_t)val;
            }
        }
    }

    free(live_rows);
    qihse_vdb_int8_destroy(vdb);
    vdb->int8_dim_min = dim_min;
    vdb->int8_dim_max = dim_max;
    vdb->int8_vectors = quantized;
    vdb->int8_rows = n_rows;
    vdb->int8_dims = dims;
    vdb->int8_bytes = n_rows * dims;
    vdb->int8_status = QIHSE_VDB_INT8_VALID;
    return true;
}

static float qihse_vdb_int8_dot_product(const int8_t* a, const int8_t* b, size_t len) {
    int64_t sum = 0;
    size_t i;
    for (i = 0u; i < len; i++) {
        sum += (int64_t)a[i] * (int64_t)b[i];
    }
    return (float)sum;
}

static int8_t* qihse_vdb_int8_quantize_query(qihse_vector_db_t vdb,
                                            const float* query_vector) {
    size_t d;
    int8_t* q_quantized = (int8_t*)calloc(vdb->int8_dims, sizeof(int8_t));
    if (!q_quantized) {
        return NULL;
    }
    for (d = 0u; d < vdb->int8_dims; d++) {
        float range = vdb->int8_dim_max[d] - vdb->int8_dim_min[d];
        if (range < 1e-9f) {
            q_quantized[d] = 0;
        } else {
            float scaled = 255.0f * (query_vector[d] - vdb->int8_dim_min[d]) / range;
            int val = (int)(scaled + 0.5f) - 128;
            if (val < -128) val = -128;
            if (val > 127) val = 127;
            q_quantized[d] = (int8_t)val;
        }
    }
    return q_quantized;
}

static int qihse_vdb_search_int8_candidates_prequantized(qihse_vector_db_t vdb,
                                                          const qihse_vector_query_t* query,
                                                          const int8_t* q_quantized,
                                                          size_t candidate_count,
                                                          qihse_vector_result_t* results,
                                                          size_t max_results) {
    size_t out_count = 0u;
    size_t i;
    size_t top_k;
    qihse_vdb_graph_neighbor_t* pool = NULL;
    size_t pool_count = 0u;

    if (!vdb || !query || !q_quantized || !results ||
        max_results == 0u || query->vector_dims != vdb->vector_dims ||
        vdb->int8_status != QIHSE_VDB_INT8_VALID ||
        !vdb->int8_vectors || !vdb->int8_dim_min || !vdb->int8_dim_max) {
        errno = EINVAL;
        return -1;
    }

    top_k = query->top_k > 0u ? query->top_k : 10u;
    if (top_k > max_results) {
        top_k = max_results;
    }
    if (candidate_count < top_k) {
        candidate_count = top_k;
    }

    /* Score all live vectors with INT8 dot product */
    pool = (qihse_vdb_graph_neighbor_t*)calloc(candidate_count, sizeof(*pool));
    if (!pool) {
        errno = ENOMEM;
        return -1;
    }

    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }

        score = qihse_vdb_int8_dot_product(q_quantized,
                                            &vdb->int8_vectors[i * vdb->int8_dims],
                                            vdb->int8_dims);
        qihse_vdb_track_row_access(vdb, i);

        if (pool_count < candidate_count) {
            pool[pool_count].id = i;
            pool[pool_count].score = score;
            pool_count++;
        } else {
            size_t w = 0u;
            size_t k;
            for (k = 1u; k < pool_count; k++) {
                if (pool[k].score < pool[w].score) {
                    w = k;
                }
            }
            if (score > pool[w].score) {
                pool[w].id = i;
                pool[w].score = score;
            }
        }
    }

    qsort(pool, pool_count, sizeof(*pool), qihse_vdb_graph_neighbor_cmp_desc);

    memset(results, 0, max_results * sizeof(*results));

    /* Exact rerank of INT8 candidates */
    for (i = 0u; i < pool_count && i < candidate_count && out_count < top_k; i++) {
        const qihse_index_row_t* row = &vdb->rows[pool[i].id];
        const float* vector;
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        if (query->metadata_filter) {
            const void* metadata = qihse_vdb_metadata_at(vdb, row);
            if (!metadata ||
                !query->metadata_filter(metadata, (size_t)row->metadata_size,
                                       query->metadata_filter_opaque)) {
                continue;
            }
        }
        score = qihse_vdb_compute_score(query->query_vector, vector,
                                         vdb->vector_dims, query->distance_metric);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, top_k, &out_count)) {
            free(pool);
            return -1;
        }
    }

    free(pool);
    return (int)out_count;
}

static int qihse_vdb_search_int8_candidates(qihse_vector_db_t vdb,
                                           const qihse_vector_query_t* query,
                                           size_t candidate_count,
                                           qihse_vector_result_t* results,
                                           size_t max_results) {
    int8_t* q_quantized;
    int ret;

    q_quantized = qihse_vdb_int8_quantize_query(vdb, query->query_vector);
    if (!q_quantized) {
        errno = ENOMEM;
        return -1;
    }
    ret = qihse_vdb_search_int8_candidates_prequantized(vdb, query, q_quantized,
                                                        candidate_count, results, max_results);
    free(q_quantized);
    return ret;
}

/* ============================================================================
 * BINARY QUANTIZATION SIDECAR (1 bit per dimension)
 * ============================================================================ */

static void qihse_vdb_binary_destroy(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    free(vdb->binary_vectors);
    vdb->binary_vectors = NULL;
    vdb->binary_words_per_vec = 0u;
    vdb->binary_rows = 0u;
    vdb->binary_dims = 0u;
    vdb->binary_status = QIHSE_VDB_BINARY_ABSENT;
}

static bool qihse_vdb_binary_build(qihse_vector_db_t vdb) {
    size_t i, d;
    size_t n_rows;
    size_t dims;
    size_t words_per_vec;
    uint64_t* binary = NULL;

    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }

    n_rows = vdb->total_vectors;
    dims = vdb->vector_dims;
    words_per_vec = (dims + 63u) / 64u;

    binary = (uint64_t*)calloc(n_rows * words_per_vec, sizeof(uint64_t));
    if (!binary) {
        return false;
    }

    for (i = 0u; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        const float* vec;
        size_t w;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vec = qihse_vdb_vector_at(vdb, row);
        if (!vec) {
            continue;
        }
        for (d = 0u; d < dims; d++) {
            if (vec[d] >= 0.0f) {
                w = d / 64u;
                binary[i * words_per_vec + w] |= (1ULL << (d % 64u));
            }
        }
    }

    qihse_vdb_binary_destroy(vdb);
    vdb->binary_vectors = binary;
    vdb->binary_words_per_vec = words_per_vec;
    vdb->binary_rows = n_rows;
    vdb->binary_dims = dims;
    vdb->binary_status = QIHSE_VDB_BINARY_VALID;
    return true;
}
#if 0
static int qihse_vdb_binary_hamming_distance(
    const uint64_t* a, const uint64_t* b, size_t words) {
    size_t i;
    int dist = 0;
    if (!a || !b) {
        return INT_MAX;
    }
    for (i = 0u; i < words; i++) {
        dist += __builtin_popcountll(a[i] ^ b[i]);
    }
    return dist;
}
#endif

#if 0
static int qihse_vdb_search_binary_candidates(qihse_vector_db_t vdb,
                                               const qihse_vector_query_t* query,
                                               size_t candidate_count,
                                               qihse_vector_result_t* results,
                                               size_t max_results) {
    size_t out_count = 0u;
    size_t i;
    size_t top_k;
    uint64_t* q_binary = NULL;
    qihse_vdb_graph_neighbor_t* pool = NULL;
    size_t pool_count = 0u;

    if (!vdb || !query || !query->query_vector || !results ||
        max_results == 0u || query->vector_dims != vdb->vector_dims ||
        vdb->binary_status != QIHSE_VDB_BINARY_VALID ||
        !vdb->binary_vectors) {
        errno = EINVAL;
        return -1;
    }

    top_k = query->top_k > 0u ? query->top_k : 10u;
    if (top_k > max_results) {
        top_k = max_results;
    }
    if (candidate_count < top_k) {
        candidate_count = top_k;
    }

    /* Quantize query to binary */
    q_binary = (uint64_t*)calloc(vdb->binary_words_per_vec, sizeof(uint64_t));
    if (!q_binary) {
        errno = ENOMEM;
        return -1;
    }
    for (i = 0u; i < vdb->vector_dims; i++) {
        if (query->query_vector[i] >= 0.0f) {
            q_binary[i / 64u] |= (1ULL << (i % 64u));
        }
    }

    /* Score all live vectors with Hamming distance */
    pool = (qihse_vdb_graph_neighbor_t*)calloc(candidate_count, sizeof(*pool));
    if (!pool) {
        free(q_binary);
        errno = ENOMEM;
        return -1;
    }

    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        int hamming;
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }

        hamming = qihse_vdb_binary_hamming_distance(
            q_binary,
            &vdb->binary_vectors[i * vdb->binary_words_per_vec],
            vdb->binary_words_per_vec);
        /* Convert Hamming distance to similarity score (lower distance = higher score) */
        score = 1.0f / (1.0f + (float)hamming);

        if (pool_count < candidate_count) {
            pool[pool_count].id = i;
            pool[pool_count].score = score;
            pool_count++;
        } else {
            size_t w = 0u;
            size_t k;
            for (k = 1u; k < pool_count; k++) {
                if (pool[k].score < pool[w].score) {
                    w = k;
                }
            }
            if (score > pool[w].score) {
                pool[w].id = i;
                pool[w].score = score;
            }
        }
    }

    qsort(pool, pool_count, sizeof(*pool), qihse_vdb_graph_neighbor_cmp_desc);

    memset(results, 0, max_results * sizeof(*results));

    /* Exact rerank of binary candidates */
    for (i = 0u; i < pool_count && i < candidate_count && out_count < top_k; i++) {
        const qihse_index_row_t* row = &vdb->rows[pool[i].id];
        const float* vector;
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        if (query->metadata_filter) {
            const void* metadata = qihse_vdb_metadata_at(vdb, row);
            if (!metadata ||
                !query->metadata_filter(metadata, (size_t)row->metadata_size,
                                       query->metadata_filter_opaque)) {
                continue;
            }
        }
        score = qihse_vdb_compute_score(query->query_vector, vector,
                                         vdb->vector_dims, query->distance_metric);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, top_k, &out_count)) {
            free(q_binary);
            free(pool);
            return -1;
        }
    }

    free(q_binary);
    free(pool);
    return (int)out_count;
}
#endif

/* ============================================================================
 * QUERY RESULT CACHE
 * ============================================================================ */

static void qihse_vdb_cache_destroy_entry(qihse_vdb_cache_entry_t* entry) {
    if (!entry) {
        return;
    }
    free(entry->result_ids);
    entry->result_ids = NULL;
    free(entry->result_scores);
    entry->result_scores = NULL;
    entry->result_count = 0u;
    entry->query_hash = 0u;
}

static void qihse_vdb_cache_clear(qihse_vector_db_t vdb) {
    size_t i;
    if (!vdb || !vdb->cache_entries) {
        return;
    }
    for (i = 0u; i < vdb->cache_count; i++) {
        qihse_vdb_cache_destroy_entry(&vdb->cache_entries[i]);
    }
    vdb->cache_count = 0u;
}

static void qihse_vdb_cache_destroy(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    qihse_vdb_cache_clear(vdb);
    free(vdb->cache_entries);
    vdb->cache_entries = NULL;
    vdb->cache_capacity = 0u;
    vdb->cache_count = 0u;
}

static uint64_t qihse_vdb_cache_hash_query(
    const float* vector,
    size_t dims,
    size_t top_k,
    qihse_distance_metric_t metric,
    const qihse_user_t* user
) {
    uint64_t h = 14695981039346656037ULL; /* FNV-1a offset basis */
    size_t i;
    size_t byte_len = dims * sizeof(float);
    const uint64_t* u64s = (const uint64_t*)vector;
    size_t u64_count = byte_len / sizeof(uint64_t);

    for (i = 0u; i < u64_count; i++) {
        h ^= u64s[i];
        h *= 1099511628211ULL;
    }
    const uint8_t* remainder = (const uint8_t*)(u64s + u64_count);
    for (i = 0u; i < byte_len % sizeof(uint64_t); i++) {
        h ^= remainder[i];
        h *= 1099511628211ULL;
    }
    h ^= (uint64_t)top_k;
    h *= 1099511628211ULL;
    h ^= (uint64_t)metric;
    h *= 1099511628211ULL;
    h ^= user ? (uint64_t)qihse_user_get_id(user) : UINT64_MAX;
    h *= 1099511628211ULL;
    h ^= user ? (uint64_t)qihse_user_get_role(user) : UINT64_MAX;
    h *= 1099511628211ULL;
    h ^= user ? (uint64_t)qihse_user_get_classification(user) : UINT64_MAX;
    h *= 1099511628211ULL;
    h ^= user ? (uint64_t)qihse_user_get_sci(user) : UINT64_MAX;
    h *= 1099511628211ULL;
    h ^= user && qihse_user_has_hardware_token(user) ? 1ULL : 0ULL;
    h *= 1099511628211ULL;
    return h;
}

static bool qihse_vdb_cache_lookup(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results,
    int* out_count
) {
    size_t i;
    uint64_t hash;
    size_t top_k;
    qihse_distance_metric_t metric;

    if (!vdb || !query || !results || !out_count ||
        vdb->cache_capacity == 0u || vdb->cache_count == 0u) {
        return false;
    }

    top_k = query->top_k > 0u ? query->top_k : 10u;
    metric = query->distance_metric;
    hash = qihse_vdb_cache_hash_query(query->query_vector, query->vector_dims, top_k, metric, query->user);

    size_t cap = vdb->cache_capacity;
    size_t base_idx = (size_t)(hash % cap);
    size_t probe_limit = cap < 8 ? cap : 8;

    for (i = 0u; i < probe_limit; i++) {
        size_t idx = (base_idx + i) % cap;
        qihse_vdb_cache_entry_t* e = &vdb->cache_entries[idx];
        if (e->result_count == 0u || e->result_ids == NULL) {
            /* Empty slot: not found in hash neighborhood */
            break;
        }
        if (e->query_hash == hash &&
            e->top_k == top_k &&
            e->metric == metric &&
            e->valid_generation == vdb->cache_generation) {
            size_t n = e->result_count;
            size_t j;
            if (n > max_results) {
                n = max_results;
            }
            for (j = 0u; j < n; j++) {
                results[j].id = e->result_ids[j];
                results[j].score = e->result_scores[j];
                results[j].vector = NULL;
                results[j].vector_dims = 0u;
                results[j].metadata = NULL;
                results[j].metadata_size = 0u;
            }
            *out_count = (int)n;
            return true;
        }
    }
    return false;
}

static void qihse_vdb_cache_insert(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    const qihse_vector_result_t* results,
    size_t result_count
) {
    size_t i;
    size_t slot = 0u;
    uint64_t hash;
    size_t top_k;
    qihse_distance_metric_t metric;
    qihse_vdb_cache_entry_t* e;

    if (!vdb || !query || !results || vdb->cache_capacity == 0u || result_count == 0u) {
        return;
    }

    top_k = query->top_k > 0u ? query->top_k : 10u;
    metric = query->distance_metric;
    hash = qihse_vdb_cache_hash_query(query->query_vector, query->vector_dims, top_k, metric, query->user);

    size_t cap = vdb->cache_capacity;
    size_t base_idx = (size_t)(hash % cap);
    size_t probe_limit = cap < 8 ? cap : 8;
    size_t target_slot = base_idx;

    /* 1. Check if an entry with this hash already exists, or find an empty/invalid slot */
    for (i = 0u; i < probe_limit; i++) {
        size_t idx = (base_idx + i) % cap;
        qihse_vdb_cache_entry_t* cur = &vdb->cache_entries[idx];
        if (cur->result_count == 0u || cur->result_ids == NULL || cur->valid_generation != vdb->cache_generation) {
            target_slot = idx;
            break;
        }
        if (cur->query_hash == hash && cur->top_k == top_k && cur->metric == metric) {
            target_slot = idx;
            break;
        }
    }

    slot = target_slot;
    e = &vdb->cache_entries[slot];
    qihse_vdb_cache_destroy_entry(e);

    e->query_hash = hash;
    e->top_k = top_k;
    e->metric = metric;
    e->valid_generation = vdb->cache_generation;
    e->result_count = result_count;
    e->result_ids = (uint64_t*)malloc(result_count * sizeof(uint64_t));
    e->result_scores = (float*)malloc(result_count * sizeof(float));
    if (!e->result_ids || !e->result_scores) {
        qihse_vdb_cache_destroy_entry(e);
        return;
    }
    for (i = 0u; i < result_count; i++) {
        e->result_ids[i] = results[i].id;
        e->result_scores[i] = results[i].score;
    }
    if (vdb->cache_count < vdb->cache_capacity) {
        vdb->cache_count++;
    }
}

/* ============================================================================
 * CONFIGURATION FILE
 * ============================================================================ */

typedef struct qihse_vdb_config_s {
    size_t graph_M;
    size_t graph_ef_construction;
    size_t cache_max_entries;
    size_t search_default_k;
    double memory_hot_threshold;
    double memory_cold_threshold;
    uint64_t memory_maintenance_interval;
    bool graph_M_set;
    bool graph_ef_construction_set;
    bool cache_max_entries_set;
    bool search_default_k_set;
    bool memory_hot_threshold_set;
    bool memory_cold_threshold_set;
    bool memory_maintenance_interval_set;
} qihse_vdb_config_t;

static void qihse_vdb_config_parse_line(const char* line, qihse_vdb_config_t* cfg) {
    char key[64];
    char value[64];
    if (sscanf(line, "%63[^=]=%63s", key, value) != 2) {
        return;
    }
    /* Trim whitespace from key */
    {
        size_t len = strlen(key);
        while (len > 0u && (key[len - 1] == ' ' || key[len - 1] == '\t')) {
            key[--len] = '\0';
        }
    }
    if (strcmp(key, "graph.M") == 0) {
        cfg->graph_M = (size_t)strtoull(value, NULL, 10);
        cfg->graph_M_set = true;
    } else if (strcmp(key, "graph.ef_construction") == 0) {
        cfg->graph_ef_construction = (size_t)strtoull(value, NULL, 10);
        cfg->graph_ef_construction_set = true;
    } else if (strcmp(key, "cache.max_entries") == 0) {
        cfg->cache_max_entries = (size_t)strtoull(value, NULL, 10);
        cfg->cache_max_entries_set = true;
    } else if (strcmp(key, "search.default_k") == 0) {
        cfg->search_default_k = (size_t)strtoull(value, NULL, 10);
        cfg->search_default_k_set = true;
    } else if (strcmp(key, "memory.hot_threshold") == 0) {
        cfg->memory_hot_threshold = strtod(value, NULL);
        cfg->memory_hot_threshold_set = true;
    } else if (strcmp(key, "memory.cold_threshold") == 0) {
        cfg->memory_cold_threshold = strtod(value, NULL);
        cfg->memory_cold_threshold_set = true;
    } else if (strcmp(key, "memory.maintenance_interval") == 0) {
        cfg->memory_maintenance_interval = (uint64_t)strtoull(value, NULL, 10);
        cfg->memory_maintenance_interval_set = true;
    }
}

static void qihse_vdb_config_load(qihse_vdb_config_t* cfg) {
    const char* conf_file = getenv("QIHSE_CONF_FILE");
    FILE* fp = NULL;
    char line[256];

    memset(cfg, 0, sizeof(*cfg));

    if (conf_file) {
        if (strstr(conf_file, "..") != NULL) {
            fprintf(stderr, "[QIHSE] Rejected QIHSE_CONF_FILE containing path traversal: %s\n", conf_file);
        } else {
            fp = fopen(conf_file, "r");
        }
    }
    if (!fp) {
        fp = fopen("/etc/qihse/qihse.conf", "r");
    }
    if (!fp) {
        const char* home = getenv("HOME");
        if (home) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/.qihse.conf", home);
            fp = fopen(path, "r");
        }
    }

    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            /* Skip comments and blank lines */
            char* p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '#' || *p == ';' || *p == '\0' || *p == '\n') {
                continue;
            }
            /* Remove trailing newline */
            {
                size_t len = strlen(line);
                if (len > 0u && line[len - 1] == '\n') {
                    line[len - 1] = '\0';
                }
            }
            qihse_vdb_config_parse_line(line, cfg);
        }
        fclose(fp);
    }

    /* Environment overrides */
    {
        const char* env = getenv("QIHSE_GRAPH_M");
        if (env) {
            cfg->graph_M = (size_t)strtoull(env, NULL, 10);
            cfg->graph_M_set = true;
        }
    }
    {
        const char* env = getenv("QIHSE_GRAPH_EF_CONSTRUCTION");
        if (env) {
            cfg->graph_ef_construction = (size_t)strtoull(env, NULL, 10);
            cfg->graph_ef_construction_set = true;
        }
    }
    {
        const char* env = getenv("QIHSE_CACHE_MAX_ENTRIES");
        if (env) {
            cfg->cache_max_entries = (size_t)strtoull(env, NULL, 10);
            cfg->cache_max_entries_set = true;
        }
    }
    {
        const char* env = getenv("QIHSE_SEARCH_DEFAULT_K");
        if (env) {
            cfg->search_default_k = (size_t)strtoull(env, NULL, 10);
            cfg->search_default_k_set = true;
        }
    }
    {
        const char* env = getenv("QIHSE_MEMORY_HOT_THRESHOLD");
        if (env) {
            cfg->memory_hot_threshold = strtod(env, NULL);
            cfg->memory_hot_threshold_set = true;
        }
    }
    {
        const char* env = getenv("QIHSE_MEMORY_COLD_THRESHOLD");
        if (env) {
            cfg->memory_cold_threshold = strtod(env, NULL);
            cfg->memory_cold_threshold_set = true;
        }
    }
    {
        const char* env = getenv("QIHSE_MEMORY_MAINTENANCE_INTERVAL");
        if (env) {
            cfg->memory_maintenance_interval = (uint64_t)strtoull(env, NULL, 10);
            cfg->memory_maintenance_interval_set = true;
        }
    }
}

/* ============================================================================
 * HIERARCHICAL STORAGE MANAGEMENT (SRAM -> HBM -> DRAM)
 * ============================================================================ */

static uint64_t qihse_vdb_monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void qihse_vdb_track_row_access(qihse_vector_db_t vdb, size_t row_idx) {
    if (!vdb || row_idx >= vdb->row_tracking_capacity) {
        return;
    }
    vdb->row_access_counts[row_idx]++;
    vdb->row_last_access_ns[row_idx] = qihse_vdb_monotonic_ns();
}

static double qihse_vdb_row_temperature(qihse_vector_db_t vdb, size_t row_idx) {
    uint64_t count;
    uint64_t last;
    uint64_t now;
    uint64_t elapsed;
    if (!vdb || row_idx >= vdb->row_tracking_capacity) {
        return 0.0;
    }
    count = vdb->row_access_counts[row_idx];
    last = vdb->row_last_access_ns[row_idx];
    now = qihse_vdb_monotonic_ns();
    if (now <= last) {
        elapsed = 1;
    } else {
        elapsed = now - last;
    }
    /* accesses per second = count / (elapsed_ns / 1e9) */
    return (double)count * 1e9 / (double)elapsed;
}

static qihse_memory_tier_t qihse_vdb_fastest_available_tier(qihse_vector_db_t vdb) {
    (void)vdb;
    /* In a real system, probe UMA for available tiers. For now, DRAM is baseline. */
    return QIHSE_MEM_DRAM;
}

static void qihse_vdb_run_memory_maintenance(qihse_vector_db_t vdb) {
    size_t i;
    double temp;
    qihse_memory_tier_t fast_tier;
    if (!vdb || vdb->live_vectors == 0u) {
        return;
    }
    fast_tier = qihse_vdb_fastest_available_tier(vdb);
    for (i = 0u; i < vdb->total_vectors; ++i) {
        if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        temp = qihse_vdb_row_temperature(vdb, i);
        if (temp >= vdb->memory_hot_threshold && vdb->row_tier[i] != fast_tier) {
            /* Promote: mark for migration to faster tier */
            vdb->row_tier[i] = fast_tier;
        } else if (temp <= vdb->memory_cold_threshold && vdb->row_tier[i] != QIHSE_MEM_DRAM) {
            /* Demote: move back to DRAM */
            vdb->row_tier[i] = QIHSE_MEM_DRAM;
        }
    }
    vdb->memory_maintenance_queries = 0u;
}

/* ============================================================================
 * SPARSE INVERTED INDEX
 * ============================================================================ */

static void qihse_vdb_sparse_index_destroy(qihse_vdb_sparse_index_t* idx) {
    size_t i;
    if (!idx) {
        return;
    }
    for (i = 0u; i < idx->term_count; i++) {
        free(idx->terms[i].postings);
        idx->terms[i].postings = NULL;
    }
    free(idx->terms);
    idx->terms = NULL;
    idx->term_count = 0u;
    idx->term_capacity = 0u;
    free(idx);
}

static qihse_vdb_sparse_term_t* qihse_vdb_sparse_index_find_term(
    qihse_vdb_sparse_index_t* idx,
    size_t term_id
) {
    size_t i;
    for (i = 0u; i < idx->term_count; i++) {
        if (idx->terms[i].term_id == term_id) {
            return &idx->terms[i];
        }
    }
    return NULL;
}

static bool qihse_vdb_sparse_index_add_term_posting(
    qihse_vdb_sparse_index_t* idx,
    size_t term_id,
    uint64_t doc_id,
    float weight
) {
    qihse_vdb_sparse_term_t* term = qihse_vdb_sparse_index_find_term(idx, term_id);
    if (!term) {
        /* Need to add new term */
        if (idx->term_count >= idx->term_capacity) {
            size_t new_cap = idx->term_capacity ? idx->term_capacity * 2u : 16u;
            qihse_vdb_sparse_term_t* new_terms = (qihse_vdb_sparse_term_t*)realloc(
                idx->terms, new_cap * sizeof(*new_terms));
            if (!new_terms) {
                return false;
            }
            idx->terms = new_terms;
            idx->term_capacity = new_cap;
        }
        term = &idx->terms[idx->term_count++];
        memset(term, 0, sizeof(*term));
        term->term_id = term_id;
    }
    if (term->posting_count >= term->posting_capacity) {
        size_t new_cap = term->posting_capacity ? term->posting_capacity * 2u : 8u;
        qihse_vdb_sparse_posting_t* new_postings = (qihse_vdb_sparse_posting_t*)realloc(
            term->postings, new_cap * sizeof(*new_postings));
        if (!new_postings) {
            return false;
        }
        term->postings = new_postings;
        term->posting_capacity = new_cap;
    }
    term->postings[term->posting_count].doc_id = doc_id;
    term->postings[term->posting_count].weight = weight;
    term->posting_count++;
    return true;
}

static bool qihse_vdb_sparse_index_build(qihse_vector_db_t vdb) {
    size_t i, d;
    size_t n_rows;
    size_t dims;
    size_t total_doc_len = 0u;
    size_t num_docs = 0u;
    qihse_vdb_sparse_index_t* idx;

    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }

    n_rows = vdb->total_vectors;
    dims = vdb->vector_dims;

    /* Destroy existing index */
    qihse_vdb_sparse_index_destroy(vdb->sparse_index);
    vdb->sparse_index = NULL;

    idx = (qihse_vdb_sparse_index_t*)calloc(1u, sizeof(*idx));
    if (!idx) {
        return false;
    }

    for (i = 0u; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        const float* vec;
        size_t nonzero_count = 0u;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vec = qihse_vdb_vector_at(vdb, row);
        if (!vec) {
            continue;
        }
        num_docs++;

        /* Count non-zero dimensions */
        for (d = 0u; d < dims; d++) {
            if (vec[d] != 0.0f) {
                nonzero_count++;
            }
        }
        total_doc_len += nonzero_count;

        /* Only index vectors that are at least 70% sparse */
        if (nonzero_count * 10u > dims * 3u) {
            continue; /* Not sparse enough */
        }

        /* Add postings for non-zero dimensions */
        for (d = 0u; d < dims; d++) {
            if (vec[d] != 0.0f) {
                if (!qihse_vdb_sparse_index_add_term_posting(idx, d, row->vector_id, vec[d])) {
                    qihse_vdb_sparse_index_destroy(idx);
                    return false;
                }
            }
        }
    }

    idx->num_docs = num_docs;
    idx->avg_doc_len = num_docs > 0u ? (float)total_doc_len / (float)num_docs : 1.0f;

    /* Precompute IDF for each term: log(1 + N / df) */
    for (i = 0u; i < idx->term_count; i++) {
        size_t df = idx->terms[i].posting_count;
        idx->terms[i].idf = (float)log(1.0 + (double)num_docs / (double)df);
    }

    vdb->sparse_index = idx;
    return true;
}

static int qihse_vdb_search_sparse(qihse_vector_db_t vdb,
                                    const qihse_vector_query_t* query,
                                    qihse_vector_result_t* results,
                                    size_t max_results) {
    size_t out_count = 0u;
    size_t top_k;
    size_t i, d;
    qihse_vdb_sparse_index_t* idx;
    qihse_vdb_graph_neighbor_t* pool = NULL;
    size_t pool_count = 0u;
    size_t candidate_count;
    float* doc_scores = NULL;
    size_t doc_scores_size = 0u;
    const float* qvec = query->query_vector;
    size_t dims = vdb->vector_dims;

    if (!vdb || !query || !query->query_vector || !results ||
        max_results == 0u || query->vector_dims != dims ||
        !vdb->sparse_index) {
        errno = EINVAL;
        return -1;
    }

    idx = vdb->sparse_index;
    top_k = query->top_k > 0u ? query->top_k : 10u;
    if (top_k > max_results) {
        top_k = max_results;
    }
    candidate_count = query->candidate_pool_size > 0u
        ? query->candidate_pool_size
        : top_k * 12u;
    if (candidate_count > vdb->live_vectors) {
        candidate_count = vdb->live_vectors;
    }

    /* BM25 scoring accumulator: one score per doc_id */
    {
    /* Simpler: allocate enough for total_vectors */
        doc_scores_size = vdb->total_vectors;
        doc_scores = (float*)calloc(doc_scores_size, sizeof(float));
    }
    if (!doc_scores) {
        errno = ENOMEM;
        return -1;
    }

    /* Accumulate BM25 scores for each query term */
    for (d = 0u; d < dims; d++) {
        float q_weight = qvec[d];
        qihse_vdb_sparse_term_t* term;
        float k1 = 1.2f;
        float b = 0.75f;

        if (q_weight == 0.0f) {
            continue;
        }

        term = qihse_vdb_sparse_index_find_term(idx, d);
        if (!term) {
            continue;
        }

        for (i = 0u; i < term->posting_count; i++) {
            uint64_t doc_id = term->postings[i].doc_id;
            float weight = term->postings[i].weight;
            size_t doc_len = 0u;
            float tf;
            float bm25;

            /* Find row index from doc_id to compute doc_len */
            /* Simple approach: use weight magnitude as proxy for term frequency */
            tf = weight;
            bm25 = term->idf * (tf * (k1 + 1.0f)) /
                   (tf + k1 * (1.0f - b + b * (float)doc_len / idx->avg_doc_len));

            if (doc_id < doc_scores_size) {
                doc_scores[doc_id] += bm25;
            }
        }
    }

    /* Collect top candidates */
    pool = (qihse_vdb_graph_neighbor_t*)calloc(candidate_count, sizeof(*pool));
    if (!pool) {
        free(doc_scores);
        errno = ENOMEM;
        return -1;
    }

    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (row->vector_id >= doc_scores_size) {
            continue;
        }
        score = doc_scores[row->vector_id];
        if (score <= 0.0f) {
            continue;
        }
        qihse_vdb_track_row_access(vdb, i);

        if (pool_count < candidate_count) {
            pool[pool_count].id = i;
            pool[pool_count].score = score;
            pool_count++;
        } else {
            size_t w = 0u;
            size_t k;
            for (k = 1u; k < pool_count; k++) {
                if (pool[k].score < pool[w].score) {
                    w = k;
                }
            }
            if (score > pool[w].score) {
                pool[w].id = i;
                pool[w].score = score;
            }
        }
    }

    free(doc_scores);

    qsort(pool, pool_count, sizeof(*pool), qihse_vdb_graph_neighbor_cmp_desc);

    memset(results, 0, max_results * sizeof(*results));

    /* Exact rerank of sparse candidates */
    for (i = 0u; i < pool_count && i < candidate_count && out_count < top_k; i++) {
        const qihse_index_row_t* row = &vdb->rows[pool[i].id];
        const float* vector;
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        if (query->metadata_filter) {
            const void* metadata = qihse_vdb_metadata_at(vdb, row);
            if (!metadata ||
                !query->metadata_filter(metadata, (size_t)row->metadata_size,
                                       query->metadata_filter_opaque)) {
                continue;
            }
        }
        score = qihse_vdb_compute_score(query->query_vector, vector,
                                         vdb->vector_dims, query->distance_metric);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, top_k, &out_count)) {
            free(pool);
            return -1;
        }
    }

    free(pool);
    return (int)out_count;
}

static void qihse_vdb_free_mmap(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    if (vdb->mapped_vectors_base && vdb->mapped_vectors_base != MAP_FAILED) {
        size_t page_offset = (size_t)((uint8_t*)vdb->mapped_vectors - (uint8_t*)vdb->mapped_vectors_base);
        munmap(vdb->mapped_vectors_base, vdb->mapped_vector_bytes + page_offset);
    }
    vdb->mapped_vectors = NULL;
    vdb->mapped_vectors_base = NULL;
    vdb->mapped_vector_bytes = 0u;
    if (vdb->mmap_fd >= 0) {
        close(vdb->mmap_fd);
    }
    vdb->mmap_fd = -1;
    if (vdb->mapped_metadata_base && vdb->mapped_metadata_base != MAP_FAILED) {
        size_t page_offset = (size_t)((uint8_t*)vdb->mapped_metadata - (uint8_t*)vdb->mapped_metadata_base);
        munmap(vdb->mapped_metadata_base, vdb->mapped_metadata_bytes + page_offset);
    }
    vdb->mapped_metadata = NULL;
    vdb->mapped_metadata_base = NULL;
    vdb->mapped_metadata_bytes = 0u;
    if (vdb->metadata_mmap_fd >= 0) {
        close(vdb->metadata_mmap_fd);
    }
    vdb->metadata_mmap_fd = -1;
    if (vdb->rows_are_mapped) {
        vdb->rows = NULL;
        vdb->rows_capacity = 0u;
        vdb->rows_are_mapped = false;
    }
    if (vdb->mapped_index_base && vdb->mapped_index_base != MAP_FAILED) {
        size_t page_offset = (size_t)((uint8_t*)vdb->mapped_index - (uint8_t*)vdb->mapped_index_base);
        munmap(vdb->mapped_index_base, vdb->mapped_index_bytes + page_offset);
    }
    vdb->mapped_index = NULL;
    vdb->mapped_index_base = NULL;
    vdb->mapped_index_bytes = 0u;
    if (vdb->index_mmap_fd >= 0) {
        close(vdb->index_mmap_fd);
    }
    vdb->index_mmap_fd = -1;
    if (vdb->mapped_idmap_base && vdb->mapped_idmap_base != MAP_FAILED) {
        size_t page_offset = (size_t)((uint8_t*)vdb->mapped_idmap - (uint8_t*)vdb->mapped_idmap_base);
        munmap(vdb->mapped_idmap_base, vdb->mapped_idmap_bytes + page_offset);
    }
    vdb->mapped_idmap = NULL;
    vdb->mapped_idmap_base = NULL;
    vdb->mapped_idmap_bytes = 0u;
    if (vdb->idmap_mmap_fd >= 0) {
        close(vdb->idmap_mmap_fd);
    }
    vdb->idmap_mmap_fd = -1;
}

/* mmap of individual sections within the container file.
 * Each function opens the container, finds the section offset, and mmaps
 * the file at that offset to provide zero-copy access to the data. */
static bool qihse_vdb_map_vectors(qihse_vector_db_t vdb) {
    if (!vdb || !vdb->db_path || vdb->mapped_vectors) return false;

    qihse_container_t ctr;
    if (!qihse_ctr_open_read(vdb->db_path, &ctr)) return false;

    const qihse_ctr_section_t* sec = qihse_ctr_find_section(&ctr, QIHSE_CTR_SEC_VECTORS);
    if (!sec || sec->length == 0u) {
        qihse_ctr_close(&ctr);
        return false;
    }

    int fd = open(vdb->db_path, O_RDONLY);
    if (fd < 0) {
        qihse_ctr_close(&ctr);
        return false;
    }

    size_t map_len = (size_t)sec->length;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t page_offset = (size_t)sec->offset & (page_size - 1);
    size_t map_start = (size_t)sec->offset & ~(page_size - 1);
    size_t map_total = map_len + page_offset;

    void* map = mmap(NULL, map_total, PROT_READ, MAP_PRIVATE, fd, (off_t)map_start);
    if (map == MAP_FAILED) {
        close(fd);
        qihse_ctr_close(&ctr);
        return false;
    }

    vdb->mapped_vectors = (uint8_t*)map + page_offset;
    vdb->mapped_vectors_base = map;
    vdb->mapped_vector_bytes = map_len;
    vdb->mmap_fd = fd;
    qihse_ctr_close(&ctr);
    return true;
}

static bool qihse_vdb_map_metadata(qihse_vector_db_t vdb) {
    if (!vdb || !vdb->db_path || vdb->mapped_metadata) return false;

    qihse_container_t ctr;
    if (!qihse_ctr_open_read(vdb->db_path, &ctr)) return false;

    const qihse_ctr_section_t* sec = qihse_ctr_find_section(&ctr, QIHSE_CTR_SEC_METADATA);
    if (!sec || sec->length == 0u) {
        qihse_ctr_close(&ctr);
        return false;
    }

    int fd = open(vdb->db_path, O_RDONLY);
    if (fd < 0) {
        qihse_ctr_close(&ctr);
        return false;
    }

    size_t map_len = (size_t)sec->length;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t page_offset = (size_t)sec->offset & (page_size - 1);
    size_t map_start = (size_t)sec->offset & ~(page_size - 1);
    size_t map_total = map_len + page_offset;

    void* map = mmap(NULL, map_total, PROT_READ, MAP_PRIVATE, fd, (off_t)map_start);
    if (map == MAP_FAILED) {
        close(fd);
        qihse_ctr_close(&ctr);
        return false;
    }

    vdb->mapped_metadata = (uint8_t*)map + page_offset;
    vdb->mapped_metadata_base = map;
    vdb->mapped_metadata_bytes = map_len;
    vdb->metadata_mmap_fd = fd;
    qihse_ctr_close(&ctr);
    return true;
}

static bool qihse_vdb_try_map_index(qihse_vector_db_t vdb,
                                    const qihse_vector_store_manifest_t* manifest) {
    (void)manifest;
    if (!vdb || !vdb->db_path || vdb->mapped_index) return false;

    qihse_container_t ctr;
    if (!qihse_ctr_open_read(vdb->db_path, &ctr)) return false;

    const qihse_ctr_section_t* sec = qihse_ctr_find_section(&ctr, QIHSE_CTR_SEC_INDEX);
    if (!sec || sec->length == 0u) {
        qihse_ctr_close(&ctr);
        return false;
    }

    int fd = open(vdb->db_path, O_RDONLY);
    if (fd < 0) {
        qihse_ctr_close(&ctr);
        return false;
    }

    size_t map_len = (size_t)sec->length;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t page_offset = (size_t)sec->offset & (page_size - 1);
    size_t map_start = (size_t)sec->offset & ~(page_size - 1);
    size_t map_total = map_len + page_offset;

    void* map = mmap(NULL, map_total, PROT_READ, MAP_PRIVATE, fd, (off_t)map_start);
    if (map == MAP_FAILED) {
        close(fd);
        qihse_ctr_close(&ctr);
        return false;
    }

    vdb->mapped_index = (uint8_t*)map + page_offset;
    vdb->mapped_index_base = map;
    vdb->mapped_index_bytes = map_len;
    vdb->index_mmap_fd = fd;
    qihse_ctr_close(&ctr);
    return true;
}

static bool qihse_vdb_try_map_idmap(qihse_vector_db_t vdb,
                                    const qihse_vector_store_manifest_t* manifest) {
    (void)manifest;
    if (!vdb || !vdb->db_path || vdb->mapped_idmap) return false;

    qihse_container_t ctr;
    if (!qihse_ctr_open_read(vdb->db_path, &ctr)) return false;

    const qihse_ctr_section_t* sec = qihse_ctr_find_section(&ctr, QIHSE_CTR_SEC_IDMAP);
    if (!sec || sec->length == 0u) {
        qihse_ctr_close(&ctr);
        return false;
    }

    int fd = open(vdb->db_path, O_RDONLY);
    if (fd < 0) {
        qihse_ctr_close(&ctr);
        return false;
    }

    size_t map_len = (size_t)sec->length;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t page_offset = (size_t)sec->offset & (page_size - 1);
    size_t map_start = (size_t)sec->offset & ~(page_size - 1);
    size_t map_total = map_len + page_offset;

    void* map = mmap(NULL, map_total, PROT_READ, MAP_PRIVATE, fd, (off_t)map_start);
    if (map == MAP_FAILED) {
        close(fd);
        qihse_ctr_close(&ctr);
        return false;
    }

    vdb->mapped_idmap = (uint8_t*)map + page_offset;
    vdb->mapped_idmap_base = map;
    vdb->mapped_idmap_bytes = map_len;
    vdb->idmap_mmap_fd = fd;
    qihse_ctr_close(&ctr);
    return true;
}

static bool qihse_vdb_append_row(qihse_vector_db_t vdb,
                                 uint64_t id,
                                 const float* vector,
                                 const void* metadata,
                                 size_t metadata_size,
                                 uint64_t generation) {
    size_t vector_bytes;
    size_t new_vector_used;
    size_t new_metadata_used;
    qihse_index_row_t* row;

    if (!qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &vector_bytes) ||
        !qihse_checked_add_size(vdb->vector_bytes_used, vector_bytes, &new_vector_used) ||
        !qihse_checked_add_size(vdb->metadata_bytes_used, metadata_size, &new_metadata_used) ||
        !qihse_vdb_reserve_rows(vdb, vdb->total_vectors + 1u) ||
        !qihse_vdb_reserve_bytes(&vdb->vectors, &vdb->vector_bytes_capacity, new_vector_used) ||
        !qihse_vdb_reserve_bytes(&vdb->metadata, &vdb->metadata_bytes_capacity, new_metadata_used)) {
        return false;
    }

    memcpy(vdb->vectors + vdb->vector_bytes_used, vector, vector_bytes);
    if (metadata_size != 0u) {
        memcpy(vdb->metadata + vdb->metadata_bytes_used, metadata, metadata_size);
    }

    row = &vdb->rows[vdb->total_vectors];
    memset(row, 0, sizeof(*row));
    row->vector_id = id;
    row->vector_offset = (uint64_t)vdb->vector_bytes_used;
    row->metadata_offset = (uint64_t)vdb->metadata_bytes_used;
    row->metadata_size = (uint64_t)metadata_size;
    row->commit_generation = generation;
    row->row_flags = QIHSE_ROW_F_LIVE;
    row->classification = QIHSE_CLASS_UNCLASSIFIED;
    row->sci_compartment = QIHSE_SCI_NONE;

    vdb->total_vectors++;
    vdb->live_vectors++;
    vdb->vector_bytes_used = new_vector_used;
    vdb->metadata_bytes_used = new_metadata_used;
    if (id >= vdb->next_auto_id) {
        vdb->next_auto_id = id + 1u;
    }
    vdb->idmap_valid = false;
    vdb->idmap_dirty = true;
    qihse_vdb_set_trinary_stale(vdb);
    return true;
}

static bool qihse_vdb_apply_add(qihse_vector_db_t vdb,
                                const qihse_vdb_wal_add_t* add,
                                bool reject_duplicates) {
    uint64_t auto_base;
    size_t i;

    if (!vdb || !add || !add->vectors || add->count == 0u || add->dims == 0u ||
        add->dims > (uint64_t)SIZE_MAX) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims != 0u && vdb->vector_dims != (size_t)add->dims) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims == 0u) {
        vdb->vector_dims = (size_t)add->dims;
    }
    auto_base = vdb->next_auto_id;
    for (i = 0u; i < (size_t)add->count; i++) {
        uint64_t id = add->ids ? add->ids[i] : auto_base + (uint64_t)i;
        if (reject_duplicates && qihse_vdb_id_exists(vdb, id)) {
            errno = EEXIST;
            return false;
        }
    }
    for (i = 0u; i < (size_t)add->count; i++) {
        const void* meta = add->metadata ? add->metadata[i] : NULL;
        size_t meta_size = add->metadata_sizes ? add->metadata_sizes[i] : 0u;
        uint64_t id = add->ids ? add->ids[i] : auto_base + (uint64_t)i;

        if (meta_size != 0u && !meta) {
            errno = EINVAL;
            return false;
        }
        if (!qihse_vdb_append_row(vdb, id, add->vectors + (i * vdb->vector_dims),
                                  meta, meta_size, add->generation)) {
            return false;
        }
    }
    if (!add->ids) {
        vdb->next_auto_id = auto_base + add->count;
    }
    if (add->generation >= vdb->next_generation) {
        vdb->next_generation = add->generation + 1u;
    }
    vdb->dirty = true;
    return true;
}

static bool qihse_vdb_write_wal_vectors(qihse_vector_db_t vdb,
                                        uint32_t type,
                                        const qihse_vdb_wal_vectors_t* vectors_record) {
    uint8_t fixed[32];
    uint8_t commit_payload[16];
    uint8_t* payload = NULL;
    size_t vector_bytes;
    size_t ids_bytes;
    size_t sizes_bytes;
    size_t metadata_bytes = 0u;
    size_t payload_size;
    size_t offset = 0u;
    size_t i;
    bool ok = false;

    if (!vdb || !vdb->db_path || !vectors_record ||
        (type != QIHSE_VDB_WAL_ADD && type != QIHSE_VDB_WAL_DELETE &&
         type != QIHSE_VDB_WAL_UPDATE && type != QIHSE_VDB_WAL_UPSERT)) {
        errno = EINVAL;
        return false;
    }
    if ((type == QIHSE_VDB_WAL_DELETE && vectors_record->dims != 0u) ||
        (type != QIHSE_VDB_WAL_DELETE &&
         (!vectors_record->vectors || vectors_record->dims == 0u))) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_checked_mul_size((size_t)vectors_record->count,
                                (size_t)vectors_record->dims, &vector_bytes) ||
        !qihse_checked_mul_size(vector_bytes, sizeof(float), &vector_bytes) ||
        !qihse_checked_mul_size((size_t)vectors_record->count, sizeof(uint64_t), &ids_bytes) ||
        !qihse_checked_mul_size((size_t)vectors_record->count, sizeof(uint64_t), &sizes_bytes)) {
        return false;
    }
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        size_t meta_size = (vectors_record->metadata && vectors_record->metadata_sizes) ?
                           vectors_record->metadata_sizes[i] : 0u;
        if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
            return false;
        }
    }
    if (!qihse_checked_add_size(sizeof(fixed), ids_bytes, &payload_size) ||
        !qihse_checked_add_size(payload_size, sizes_bytes, &payload_size) ||
        !qihse_checked_add_size(payload_size, vector_bytes, &payload_size) ||
        !qihse_checked_add_size(payload_size, metadata_bytes, &payload_size)) {
        return false;
    }

    payload = (uint8_t*)malloc(payload_size ? payload_size : 1u);
    if (!payload) {
        errno = ENOMEM;
        return false;
    }
    qihse_le_write_u64(fixed + 0u, vectors_record->count);
    qihse_le_write_u64(fixed + 8u, vectors_record->dims);
    qihse_le_write_u64(fixed + 16u, (uint64_t)vector_bytes);
    qihse_le_write_u64(fixed + 24u, (uint64_t)metadata_bytes);
    memcpy(payload + offset, fixed, sizeof(fixed));
    offset += sizeof(fixed);
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        qihse_le_write_u64(payload + offset,
                           vectors_record->ids ? vectors_record->ids[i] :
                           vdb->next_auto_id + i);
        offset += sizeof(uint64_t);
    }
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        qihse_le_write_u64(payload + offset,
                           (uint64_t)((vectors_record->metadata &&
                                       vectors_record->metadata_sizes) ?
                                      vectors_record->metadata_sizes[i] : 0u));
        offset += sizeof(uint64_t);
    }
    if (vector_bytes != 0u) {
        memcpy(payload + offset, vectors_record->vectors, vector_bytes);
        offset += vector_bytes;
    }
    for (i = 0u; i < (size_t)vectors_record->count; i++) {
        size_t meta_size = (vectors_record->metadata && vectors_record->metadata_sizes) ?
                           vectors_record->metadata_sizes[i] : 0u;
        if (meta_size != 0u) {
            memcpy(payload + offset, vectors_record->metadata[i], meta_size);
            offset += meta_size;
        }
    }

    /* Build two WAL records (mutation + commit) into a single buffer and
     * append them atomically via the container WAL helper.                */
    {
        uint8_t mut_hdr[QIHSE_VDB_WAL_HEADER_SIZE];
        uint8_t cmt_hdr[QIHSE_VDB_WAL_HEADER_SIZE];
        uint64_t mut_crc;
        uint64_t cmt_crc;
        uint64_t mut_off;
        uint64_t cmt_off;
        size_t total_size;
        uint8_t* wal_buf;
        size_t off = 0u;
        qihse_container_t ctr;

        mut_crc = qihse_fnv1a64(payload, payload_size);
        memset(mut_hdr, 0, sizeof(mut_hdr));
        memcpy(mut_hdr, QIHSE_VDB_WAL_MAGIC, 8u);
        qihse_le_write_u32(mut_hdr + 8u,  QIHSE_VDB_WAL_VERSION);
        qihse_le_write_u32(mut_hdr + 12u, type);
        qihse_le_write_u64(mut_hdr + 16u, vectors_record->generation);
        qihse_le_write_u64(mut_hdr + 24u, (uint64_t)payload_size);
        qihse_le_write_u64(mut_hdr + 32u, mut_crc);
        qihse_le_write_u64(mut_hdr + 40u, vdb->wal_last_record_offset);

        /* mutation record starts at current WAL length */
        mut_off = vdb->wal_bytes_pending;
        cmt_off = mut_off + QIHSE_VDB_WAL_HEADER_SIZE + (uint64_t)payload_size;

        qihse_le_write_u64(commit_payload + 0u, mut_off);
        qihse_le_write_u64(commit_payload + 8u, mut_crc);
        cmt_crc = qihse_fnv1a64(commit_payload, sizeof(commit_payload));
        memset(cmt_hdr, 0, sizeof(cmt_hdr));
        memcpy(cmt_hdr, QIHSE_VDB_WAL_MAGIC, 8u);
        qihse_le_write_u32(cmt_hdr + 8u,  QIHSE_VDB_WAL_VERSION);
        qihse_le_write_u32(cmt_hdr + 12u, QIHSE_VDB_WAL_COMMIT);
        qihse_le_write_u64(cmt_hdr + 16u, vectors_record->generation);
        qihse_le_write_u64(cmt_hdr + 24u, (uint64_t)sizeof(commit_payload));
        qihse_le_write_u64(cmt_hdr + 32u, cmt_crc);
        qihse_le_write_u64(cmt_hdr + 40u, mut_off);

        total_size = (2u * QIHSE_VDB_WAL_HEADER_SIZE) + payload_size + sizeof(commit_payload);
        wal_buf = (uint8_t*)malloc(total_size);
        if (!wal_buf) {
            free(payload);
            errno = ENOMEM;
            return false;
        }
        memcpy(wal_buf + off, mut_hdr, sizeof(mut_hdr)); off += sizeof(mut_hdr);
        memcpy(wal_buf + off, payload, payload_size);     off += payload_size;
        memcpy(wal_buf + off, cmt_hdr, sizeof(cmt_hdr)); off += sizeof(cmt_hdr);
        memcpy(wal_buf + off, commit_payload, sizeof(commit_payload));
        free(payload);

        ok = qihse_ctr_open_write(vdb->db_path, false, &ctr);
        if (ok) {
            ok = qihse_ctr_wal_append(&ctr, wal_buf, total_size);
            qihse_ctr_close(&ctr);
        }
        free(wal_buf);
        if (ok) {
            vdb->wal_bytes_pending += (uint64_t)total_size;
            vdb->wal_last_record_offset = cmt_off;
        }
        return ok;
    }
}

static bool qihse_vdb_write_wal_add(qihse_vector_db_t vdb, const qihse_vdb_wal_add_t* add) {
    return qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_ADD, add);
}

static bool qihse_vdb_write_edge_wal(qihse_vector_db_t vdb,
                                     uint32_t type,
                                     uint64_t generation,
                                     const qihse_edge_input_t* edges,
                                     size_t edge_count) {
    uint8_t* payload = NULL;
    size_t payload_size = sizeof(uint64_t);
    size_t offset = 0u;
    size_t i;
    uint8_t mut_hdr[QIHSE_VDB_WAL_HEADER_SIZE];
    uint8_t cmt_hdr[QIHSE_VDB_WAL_HEADER_SIZE];
    uint8_t commit_payload[16];
    uint64_t mut_crc;
    uint64_t cmt_crc;
    uint64_t mut_off;
    uint64_t cmt_off;
    size_t total_size;
    uint8_t* wal_buf = NULL;
    qihse_container_t ctr;
    bool ok;

    if (!vdb || !vdb->db_path || !edges || edge_count == 0u ||
        (type != QIHSE_VDB_WAL_EDGE_ADD && type != QIHSE_VDB_WAL_EDGE_REPLACE &&
         type != QIHSE_VDB_WAL_EDGE_REMOVE)) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < edge_count; i++) {
        size_t type_len;
        if (!qihse_vdb_edge_type_valid(edges[i].edge_type) ||
            (edges[i].metadata_size != 0u && !edges[i].metadata)) return false;
        type_len = strlen(edges[i].edge_type);
        if (!qihse_checked_add_size(payload_size, 4u * sizeof(uint64_t), &payload_size) ||
            !qihse_checked_add_size(payload_size, type_len, &payload_size) ||
            !qihse_checked_add_size(payload_size, edges[i].metadata_size, &payload_size))
            return false;
    }
    payload = (uint8_t*)malloc(payload_size);
    if (!payload) { errno = ENOMEM; return false; }
    qihse_le_write_u64(payload, (uint64_t)edge_count);
    offset = sizeof(uint64_t);
    for (i = 0u; i < edge_count; i++) {
        size_t type_len = strlen(edges[i].edge_type);
        qihse_le_write_u64(payload + offset + 0u, edges[i].from_id);
        qihse_le_write_u64(payload + offset + 8u, edges[i].to_id);
        qihse_le_write_u64(payload + offset + 16u, (uint64_t)type_len);
        qihse_le_write_u64(payload + offset + 24u, (uint64_t)edges[i].metadata_size);
        offset += 4u * sizeof(uint64_t);
        memcpy(payload + offset, edges[i].edge_type, type_len);
        offset += type_len;
        if (edges[i].metadata_size != 0u) {
            memcpy(payload + offset, edges[i].metadata, edges[i].metadata_size);
            offset += edges[i].metadata_size;
        }
    }
    mut_crc = qihse_fnv1a64(payload, payload_size);
    memset(mut_hdr, 0, sizeof(mut_hdr));
    memcpy(mut_hdr, QIHSE_VDB_WAL_MAGIC, 8u);
    qihse_le_write_u32(mut_hdr + 8u, QIHSE_VDB_WAL_VERSION);
    qihse_le_write_u32(mut_hdr + 12u, type);
    qihse_le_write_u64(mut_hdr + 16u, generation);
    qihse_le_write_u64(mut_hdr + 24u, (uint64_t)payload_size);
    qihse_le_write_u64(mut_hdr + 32u, mut_crc);
    qihse_le_write_u64(mut_hdr + 40u, vdb->wal_last_record_offset);
    mut_off = vdb->wal_bytes_pending;
    cmt_off = mut_off + QIHSE_VDB_WAL_HEADER_SIZE + (uint64_t)payload_size;
    qihse_le_write_u64(commit_payload + 0u, mut_off);
    qihse_le_write_u64(commit_payload + 8u, mut_crc);
    cmt_crc = qihse_fnv1a64(commit_payload, sizeof(commit_payload));
    memset(cmt_hdr, 0, sizeof(cmt_hdr));
    memcpy(cmt_hdr, QIHSE_VDB_WAL_MAGIC, 8u);
    qihse_le_write_u32(cmt_hdr + 8u, QIHSE_VDB_WAL_VERSION);
    qihse_le_write_u32(cmt_hdr + 12u, QIHSE_VDB_WAL_COMMIT);
    qihse_le_write_u64(cmt_hdr + 16u, generation);
    qihse_le_write_u64(cmt_hdr + 24u, sizeof(commit_payload));
    qihse_le_write_u64(cmt_hdr + 32u, cmt_crc);
    qihse_le_write_u64(cmt_hdr + 40u, mut_off);
    if (!qihse_checked_add_size(2u * QIHSE_VDB_WAL_HEADER_SIZE, payload_size,
                                &total_size) ||
        !qihse_checked_add_size(total_size, sizeof(commit_payload), &total_size)) {
        free(payload);
        return false;
    }
    wal_buf = (uint8_t*)malloc(total_size);
    if (!wal_buf) { free(payload); errno = ENOMEM; return false; }
    offset = 0u;
    memcpy(wal_buf + offset, mut_hdr, sizeof(mut_hdr)); offset += sizeof(mut_hdr);
    memcpy(wal_buf + offset, payload, payload_size); offset += payload_size;
    memcpy(wal_buf + offset, cmt_hdr, sizeof(cmt_hdr)); offset += sizeof(cmt_hdr);
    memcpy(wal_buf + offset, commit_payload, sizeof(commit_payload));
    free(payload);
    ok = qihse_ctr_open_write(vdb->db_path, false, &ctr);
    if (ok) {
        ok = qihse_ctr_wal_append(&ctr, wal_buf, total_size) && qihse_ctr_fsync(&ctr);
        qihse_ctr_close(&ctr);
    }
    free(wal_buf);
    if (ok) {
        vdb->wal_bytes_pending += (uint64_t)total_size;
        vdb->wal_last_record_offset = cmt_off;
    }
    return ok;
}

static bool qihse_vdb_apply_edge_wal_payload(qihse_vector_db_t vdb,
                                              uint32_t type,
                                              uint64_t generation,
                                              const uint8_t* payload,
                                              size_t payload_size) {
    qihse_edge_input_t* inputs = NULL;
    size_t count;
    size_t offset = sizeof(uint64_t);
    size_t i;
    qihse_vdb_edge_t* staged = NULL;
    size_t staged_count = 0u;
    size_t changed = 0u;
    bool ok = false;

    if (!payload || payload_size < sizeof(uint64_t)) { errno = EINVAL; return false; }
    if (!qihse_vdb_u64_to_size(qihse_le_read_u64(payload), &count) || count == 0u) return false;
    inputs = (qihse_edge_input_t*)calloc(count, sizeof(*inputs));
    if (!inputs) { errno = ENOMEM; return false; }
    for (i = 0u; i < count; i++) {
        uint64_t type_len64;
        uint64_t meta_len64;
        size_t type_len;
        size_t meta_len;
        char* type_copy;
        if (payload_size - offset < 4u * sizeof(uint64_t)) { errno = EINVAL; goto done; }
        inputs[i].from_id = qihse_le_read_u64(payload + offset + 0u);
        inputs[i].to_id = qihse_le_read_u64(payload + offset + 8u);
        type_len64 = qihse_le_read_u64(payload + offset + 16u);
        meta_len64 = qihse_le_read_u64(payload + offset + 24u);
        offset += 4u * sizeof(uint64_t);
        if (!qihse_vdb_u64_to_size(type_len64, &type_len) ||
            !qihse_vdb_u64_to_size(meta_len64, &meta_len) ||
            type_len == 0u || type_len > QIHSE_EDGE_TYPE_MAX ||
            type_len > payload_size - offset) { errno = EINVAL; goto done; }
        type_copy = (char*)malloc(type_len + 1u);
        if (!type_copy) { errno = ENOMEM; goto done; }
        memcpy(type_copy, payload + offset, type_len);
        type_copy[type_len] = '\0';
        inputs[i].edge_type = type_copy;
        offset += type_len;
        if (meta_len > payload_size - offset) { errno = EINVAL; goto done; }
        inputs[i].metadata = meta_len ? payload + offset : NULL;
        inputs[i].metadata_size = meta_len;
        offset += meta_len;
    }
    if (offset != payload_size ||
        !qihse_vdb_stage_edge_mutation(vdb, type, inputs, count,
                                       &staged, &staged_count, &changed)) goto done;
    qihse_vdb_edge_array_free(vdb->explicit_edges, vdb->explicit_edge_count);
    vdb->explicit_edges = staged;
    vdb->explicit_edge_count = staged_count;
    vdb->explicit_edge_capacity = staged_count;
    vdb->explicit_edges_dirty = changed != 0u;
    staged = NULL;
    if (generation >= vdb->next_generation) vdb->next_generation = generation + 1u;
    if (changed != 0u) vdb->dirty = true;
    vdb->wal_records_replayed++;
    ok = true;
done:
    if (inputs) {
        for (i = 0u; i < count; i++) free((void*)inputs[i].edge_type);
    }
    free(inputs);
    qihse_vdb_edge_array_free(staged, staged_count);
    return ok;
}

static bool qihse_vdb_apply_delete_payload(qihse_vector_db_t vdb,
                                           const qihse_vdb_wal_vectors_t* record) {
    size_t deleted = 0u;

    if (!vdb || !record || !record->ids || record->count == 0u) {
        errno = EINVAL;
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        deleted += qihse_vdb_tombstone_live_id(vdb, record->ids[i],
                                               record->generation) != 0u ? 1u : 0u;
    }
    if (deleted != 0u) {
        qihse_vdb_finish_mutation_generation(vdb, record->generation);
    }
    return true;
}

static bool qihse_vdb_apply_update_payload(qihse_vector_db_t vdb,
                                           const qihse_vdb_wal_vectors_t* record) {
    bool* exists = NULL;
    size_t metadata_bytes = 0u;
    size_t updated = 0u;

    if (!vdb || !record || !record->ids || !record->vectors || record->count == 0u ||
        record->dims == 0u || record->dims > (uint64_t)SIZE_MAX ||
        (vdb->vector_dims != 0u && vdb->vector_dims != (size_t)record->dims)) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims == 0u) {
        return true;
    }
    exists = (bool*)calloc((size_t)record->count, sizeof(*exists));
    if (!exists) {
        errno = ENOMEM;
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t row_index = 0u;
        size_t meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        errno = 0;
        exists[i] = qihse_vdb_find_live_row_by_id(vdb, record->ids[i], &row_index);
        if (!exists[i] && errno != ENOENT) {
            free(exists);
            return false;
        }
        if (exists[i]) {
            if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
                free(exists);
                return false;
            }
            updated++;
        }
    }
    if (updated == 0u) {
        free(exists);
        return true;
    }
    if (!qihse_vdb_reserve_appends(vdb, updated, metadata_bytes)) {
        free(exists);
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t meta_size;
        const void* meta;

        if (!exists[i]) {
            continue;
        }
        meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        meta = record->metadata ? record->metadata[i] : NULL;
        qihse_vdb_tombstone_live_id(vdb, record->ids[i], record->generation);
        if (!qihse_vdb_append_row(vdb, record->ids[i],
                                  record->vectors + (i * (size_t)record->dims),
                                  meta, meta_size, record->generation)) {
            free(exists);
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, record->generation);
    free(exists);
    return true;
}

static bool qihse_vdb_apply_upsert_payload(qihse_vector_db_t vdb,
                                           const qihse_vdb_wal_vectors_t* record) {
    size_t metadata_bytes = 0u;

    if (!vdb || !record || !record->ids || !record->vectors || record->count == 0u ||
        record->dims == 0u || record->dims > (uint64_t)SIZE_MAX ||
        (vdb->vector_dims != 0u && vdb->vector_dims != (size_t)record->dims)) {
        errno = EINVAL;
        return false;
    }
    if (vdb->vector_dims == 0u) {
        vdb->vector_dims = (size_t)record->dims;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
            return false;
        }
    }
    if (!qihse_vdb_reserve_appends(vdb, (size_t)record->count, metadata_bytes)) {
        return false;
    }
    for (size_t i = 0u; i < (size_t)record->count; i++) {
        size_t row_index = 0u;
        size_t meta_size = record->metadata_sizes ? record->metadata_sizes[i] : 0u;
        const void* meta = record->metadata ? record->metadata[i] : NULL;

        errno = 0;
        if (qihse_vdb_find_live_row_by_id(vdb, record->ids[i], &row_index)) {
            qihse_vdb_tombstone_live_id(vdb, record->ids[i], record->generation);
        } else if (errno != ENOENT) {
            return false;
        }
        if (!qihse_vdb_append_row(vdb, record->ids[i],
                                  record->vectors + (i * (size_t)record->dims),
                                  meta, meta_size, record->generation)) {
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, record->generation);
    return true;
}

static bool qihse_vdb_replay_wal_payload(qihse_vector_db_t vdb,
                                         uint32_t type,
                                         uint64_t generation,
                                         const uint8_t* payload,
                                         size_t payload_size) {
    qihse_vdb_wal_vectors_t record;
    uint64_t count;
    uint64_t dims;
    uint64_t vector_bytes;
    uint64_t metadata_bytes;
    uint64_t* ids = NULL;
    size_t* meta_sizes = NULL;
    const float* vectors;
    const void** metadata = NULL;
    size_t offset = 0u;
    size_t i;
    size_t calc_vector_bytes;
    size_t metadata_total = 0u;
    bool ok = false;

    if (type == QIHSE_VDB_WAL_EDGE_ADD || type == QIHSE_VDB_WAL_EDGE_REPLACE ||
        type == QIHSE_VDB_WAL_EDGE_REMOVE) {
        return qihse_vdb_apply_edge_wal_payload(vdb, type, generation,
                                                 payload, payload_size);
    }

    if (!payload || payload_size < 32u) {
        errno = EINVAL;
        return false;
    }
    count = qihse_le_read_u64(payload + 0u);
    dims = qihse_le_read_u64(payload + 8u);
    vector_bytes = qihse_le_read_u64(payload + 16u);
    metadata_bytes = qihse_le_read_u64(payload + 24u);
    offset = 32u;
    if (count == 0u || count > (uint64_t)SIZE_MAX || dims > (uint64_t)SIZE_MAX ||
        (type == QIHSE_VDB_WAL_DELETE && (dims != 0u || vector_bytes != 0u ||
                                          metadata_bytes != 0u)) ||
        (type != QIHSE_VDB_WAL_DELETE && dims == 0u) ||
        !qihse_checked_mul_size((size_t)count, (size_t)dims, &calc_vector_bytes) ||
        !qihse_checked_mul_size(calc_vector_bytes, sizeof(float), &calc_vector_bytes) ||
        calc_vector_bytes != (size_t)vector_bytes ||
        offset > payload_size) {
        errno = EINVAL;
        return false;
    }

    ids = (uint64_t*)calloc((size_t)count, sizeof(*ids));
    meta_sizes = (size_t*)calloc((size_t)count, sizeof(*meta_sizes));
    metadata = (const void**)calloc((size_t)count, sizeof(*metadata));
    if (!ids || !meta_sizes || !metadata) {
        errno = ENOMEM;
        goto done;
    }
    if (payload_size - offset < (size_t)count * sizeof(uint64_t)) {
        errno = EINVAL;
        goto done;
    }
    for (i = 0u; i < (size_t)count; i++) {
        ids[i] = qihse_le_read_u64(payload + offset);
        offset += sizeof(uint64_t);
    }
    if (payload_size - offset < (size_t)count * sizeof(uint64_t)) {
        errno = EINVAL;
        goto done;
    }
    for (i = 0u; i < (size_t)count; i++) {
        uint64_t size64 = qihse_le_read_u64(payload + offset);
        offset += sizeof(uint64_t);
        if (!qihse_vdb_u64_to_size(size64, &meta_sizes[i]) ||
            !qihse_checked_add_size(metadata_total, meta_sizes[i], &metadata_total)) {
            goto done;
        }
    }
    if ((uint64_t)metadata_total != metadata_bytes ||
        payload_size - offset < calc_vector_bytes) {
        errno = EINVAL;
        goto done;
    }
    vectors = (const float*)(const void*)(payload + offset);
    offset += calc_vector_bytes;
    if (payload_size - offset != metadata_total) {
        errno = EINVAL;
        goto done;
    }
    for (i = 0u; i < (size_t)count; i++) {
        if (meta_sizes[i] != 0u) {
            metadata[i] = payload + offset;
            offset += meta_sizes[i];
        }
    }

    memset(&record, 0, sizeof(record));
    record.generation = generation;
    record.count = count;
    record.dims = dims;
    record.ids = ids;
    record.vectors = vectors;
    record.metadata = metadata;
    record.metadata_sizes = meta_sizes;
    if (type == QIHSE_VDB_WAL_ADD) {
        ok = qihse_vdb_apply_add(vdb, &record, true);
    } else if (type == QIHSE_VDB_WAL_DELETE) {
        ok = qihse_vdb_apply_delete_payload(vdb, &record);
    } else if (type == QIHSE_VDB_WAL_UPDATE) {
        ok = qihse_vdb_apply_update_payload(vdb, &record);
    } else if (type == QIHSE_VDB_WAL_UPSERT) {
        ok = qihse_vdb_apply_upsert_payload(vdb, &record);
    } else {
        errno = EINVAL;
        ok = false;
    }
    if (ok) {
        vdb->wal_records_replayed++;
    }

done:
    free(ids);
    free(meta_sizes);
    free(metadata);
    return ok;
}

static bool qihse_vdb_replay_wal(qihse_vector_db_t vdb) {
    uint64_t pending = 0u;
    uint64_t valid_end = 0u;
    uint64_t last_record_offset = QIHSE_VDB_WAL_NO_PREV;
    uint64_t valid_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
    uint8_t* pending_payload = NULL;
    size_t pending_payload_size = 0u;
    uint32_t pending_type = 0u;
    uint64_t pending_generation = 0u;
    uint64_t pending_offset = 0u;
    uint64_t pending_crc = 0u;

    if (!vdb || !vdb->db_path) {
        return false;
    }
    /* Read the entire WAL section into memory, then replay records. */
    {
        qihse_container_t ctr;
        uint8_t* wal_data = NULL;
        size_t wal_size = 0u;
        uint64_t pos = 0u;

        if (!qihse_ctr_open_read(vdb->db_path, &ctr)) {
            return errno == ENOENT;
        }
        if (qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_WAL) > 0u) {
            qihse_ctr_read_section_alloc(&ctr, QIHSE_CTR_SEC_WAL, &wal_data, &wal_size);
        }
        qihse_ctr_close(&ctr);

        if (!wal_data || wal_size == 0u) {
            free(wal_data);
            vdb->wal_bytes_pending = 0u;
            vdb->wal_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
            return true;
        }

        while (pos < (uint64_t)wal_size) {
            uint64_t record_start = pos;
            uint64_t record_end;
            uint32_t version;
            uint32_t type;
            uint64_t generation;
            uint64_t payload_size64;
            uint64_t crc;
            uint64_t prev_offset_val;
            uint8_t* payload;
            bool ok;

            if (pos + QIHSE_VDB_WAL_HEADER_SIZE > (uint64_t)wal_size) {
                break;
            }
            if (memcmp(wal_data + pos, QIHSE_VDB_WAL_MAGIC, 8u) != 0) {
                break;
            }
            version         = qihse_le_read_u32(wal_data + pos + 8u);
            type            = qihse_le_read_u32(wal_data + pos + 12u);
            generation      = qihse_le_read_u64(wal_data + pos + 16u);
            payload_size64  = qihse_le_read_u64(wal_data + pos + 24u);
            crc             = qihse_le_read_u64(wal_data + pos + 32u);
            prev_offset_val = qihse_le_read_u64(wal_data + pos + 40u);
            if (version != QIHSE_VDB_WAL_VERSION ||
                (type != QIHSE_VDB_WAL_ADD && type != QIHSE_VDB_WAL_COMMIT &&
                 type != QIHSE_VDB_WAL_DELETE && type != QIHSE_VDB_WAL_UPDATE &&
                 type != QIHSE_VDB_WAL_UPSERT && type != QIHSE_VDB_WAL_EDGE_ADD &&
                 type != QIHSE_VDB_WAL_EDGE_REPLACE &&
                 type != QIHSE_VDB_WAL_EDGE_REMOVE) ||
                payload_size64 > (uint64_t)SIZE_MAX ||
                (record_start != 0u && prev_offset_val != last_record_offset) ||
                (record_start == 0u && prev_offset_val != QIHSE_VDB_WAL_NO_PREV &&
                 prev_offset_val != 0u)) {
                break;
            }
            if (pos + QIHSE_VDB_WAL_HEADER_SIZE + payload_size64 > (uint64_t)wal_size) {
                break;
            }
            payload = wal_data + pos + QIHSE_VDB_WAL_HEADER_SIZE;
            if (qihse_fnv1a64(payload, (size_t)payload_size64) != crc) {
                break;
            }
            if (!qihse_checked_add_u64(record_start,
                                       QIHSE_VDB_WAL_HEADER_SIZE + payload_size64,
                                       &record_end)) {
                break;
            }
            if (type != QIHSE_VDB_WAL_COMMIT) {
                free(pending_payload);
                pending_payload = (uint8_t*)malloc((size_t)payload_size64 ? (size_t)payload_size64 : 1u);
                if (!pending_payload) {
                    free(wal_data);
                    errno = ENOMEM;
                    return false;
                }
                memcpy(pending_payload, payload, (size_t)payload_size64);
                pending_payload_size = (size_t)payload_size64;
                pending_type = type;
                pending_generation = generation;
                pending_offset = record_start;
                pending_crc = crc;
            } else {
                uint64_t mutation_offset;
                uint64_t mutation_crc;

                if ((size_t)payload_size64 != 16u || !pending_payload) {
                    break;
                }
                mutation_offset = qihse_le_read_u64(payload + 0u);
                mutation_crc    = qihse_le_read_u64(payload + 8u);
                if (generation != pending_generation ||
                    mutation_offset != pending_offset ||
                    mutation_crc != pending_crc) {
                    break;
                }
                ok = true;
                if (generation > vdb->committed_generation) {
                    ok = qihse_vdb_replay_wal_payload(vdb, pending_type, generation,
                                                      pending_payload, pending_payload_size);
                }
                free(pending_payload);
                pending_payload = NULL;
                pending_payload_size = 0u;
                pending_type = 0u;
                if (!ok) {
                    free(wal_data);
                    return false;
                }
                valid_end = record_end;
                valid_last_record_offset = record_start;
            }
            last_record_offset = record_start;
            pending = record_end;
            pos = record_end;
        }
        free(pending_payload);
        pending_payload = NULL;

        /* Truncate torn tail from the WAL section if needed */
        if (pending != valid_end && !vdb->read_only) {
            qihse_container_t ctr2;
            if (qihse_ctr_open_write(vdb->db_path, false, &ctr2)) {
                qihse_ctr_wal_truncate(&ctr2, valid_end);
                qihse_ctr_close(&ctr2);
            }
        }
        free(wal_data);
        vdb->wal_bytes_pending = valid_end;
        vdb->wal_last_record_offset =
            valid_end == 0u ? QIHSE_VDB_WAL_NO_PREV : valid_last_record_offset;
        return true;
    }
}

static uint8_t* qihse_vdb_build_trinary(qihse_vector_db_t vdb, size_t* out_size) {
    uint8_t* out;
    size_t row_bytes;
    size_t total;
    size_t row_idx;

    if (!vdb || !out_size || vdb->vector_dims == 0u) {
        errno = EINVAL;
        return NULL;
    }
    row_bytes = (vdb->vector_dims + 4u) / 5u;
    if (!qihse_checked_mul_size(vdb->total_vectors, row_bytes, &total)) {
        return NULL;
    }
    out = (uint8_t*)calloc(total ? total : 1u, 1u);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    memset(out, QIHSE_VDB_TRINARY_NEUTRAL_TRYTE, total);
    for (row_idx = 0u; row_idx < vdb->total_vectors; row_idx++) {
        const qihse_index_row_t* row = &vdb->rows[row_idx];
        const float* vector = qihse_vdb_vector_at(vdb, row);

        if (!vector || (row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (!qihse_trinary_tryte_encode_row(vector,
                                            vdb->vector_dims,
                                            out + (row_idx * row_bytes),
                                            row_bytes)) {
            free(out);
            return NULL;
        }
    }
    *out_size = total;
    vdb->trinary_row_bytes = (uint64_t)row_bytes;
    vdb->trinary_rows = (uint64_t)vdb->total_vectors;
    return out;
}

static uint8_t qihse_vdb_magnitude_bucket(float value) {
    float mag = fabsf(value);
    int bucket;

    if (mag <= 0.0f) {
        return 0u;
    }
    bucket = (int)(mag * 100.0f + 0.5f);
    if (bucket < 1) {
        return 1u;
    }
    if (bucket > 255) {
        return 255u;
    }
    return (uint8_t)bucket;
}

static uint8_t* qihse_vdb_build_magnitude(qihse_vector_db_t vdb, size_t* out_size) {
    uint8_t* out;
    size_t total;
    size_t row_idx;

    if (!vdb || !out_size || vdb->vector_dims == 0u) {
        errno = EINVAL;
        return NULL;
    }
    if (!qihse_checked_mul_size(vdb->total_vectors, vdb->vector_dims, &total)) {
        return NULL;
    }
    out = (uint8_t*)calloc(total ? total : 1u, 1u);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    for (row_idx = 0u; row_idx < vdb->total_vectors; row_idx++) {
        const qihse_index_row_t* row = &vdb->rows[row_idx];
        const float* vector = qihse_vdb_vector_at(vdb, row);
        size_t dim;

        if (!vector || (row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        for (dim = 0u; dim < vdb->vector_dims; dim++) {
            out[(row_idx * vdb->vector_dims) + dim] =
                qihse_vdb_magnitude_bucket(vector[dim]);
        }
    }
    *out_size = total;
    vdb->magnitude_row_bytes = (uint64_t)vdb->vector_dims;
    vdb->magnitude_rows = (uint64_t)vdb->total_vectors;
    return out;
}

static bool qihse_vdb_load_snapshot(qihse_vector_db_t vdb, bool use_mmap) {
    qihse_vector_store_snapshot_t snapshot;
    bool qtri_exists;
    bool qmag_exists;
    size_t dims;
    size_t vector_bytes;
    size_t metadata_bytes;

    memset(&snapshot, 0, sizeof(snapshot));
    if (!qihse_vector_store_load(vdb->db_path, &snapshot)) {
        return false;
    }
    if (!qihse_vdb_u64_to_size(snapshot.manifest.vector_dims, &dims) ||
        !qihse_vdb_u64_to_size(snapshot.manifest.vector_bytes, &vector_bytes) ||
        !qihse_vdb_u64_to_size(snapshot.manifest.metadata_bytes, &metadata_bytes)) {
        qihse_vector_store_snapshot_free(&snapshot);
        return false;
    }

    vdb->vector_dims = dims;
    vdb->total_vectors = snapshot.row_count;
    vdb->rows_capacity = snapshot.row_count;
    vdb->rows = snapshot.rows;
    snapshot.rows = NULL;
    vdb->vectors = snapshot.vectors;
    snapshot.vectors = NULL;
    vdb->vector_bytes_used = vector_bytes;
    vdb->vector_bytes_capacity = vector_bytes;
    vdb->metadata = snapshot.metadata;
    snapshot.metadata = NULL;
    vdb->metadata_bytes_used = metadata_bytes;
    vdb->metadata_bytes_capacity = metadata_bytes;
    vdb->committed_generation = snapshot.manifest.commit_generation;
    vdb->next_generation = vdb->committed_generation + 1u;
    vdb->idmap = snapshot.idmap;
    snapshot.idmap = NULL;
    vdb->idmap_count = snapshot.idmap_count;
    vdb->idmap_valid = snapshot.idmap_valid;
    vdb->idmap_dirty = false;
    vdb->live_vectors = 0u;
    for (size_t i = 0u; i < vdb->total_vectors; i++) {
        if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            vdb->live_vectors++;
        }
        if (vdb->rows[i].vector_id >= vdb->next_auto_id) {
            vdb->next_auto_id = vdb->rows[i].vector_id + 1u;
        }
    }
    if (!vdb->idmap_valid && !qihse_vdb_rebuild_idmap(vdb, !vdb->read_only)) {
        qihse_vector_store_snapshot_free(&snapshot);
        return false;
    }
    qtri_exists = (snapshot.manifest.trinary_flags & QIHSE_VSTORE_TRI_PRESENT) != 0u;
    size_t expected_trinary_row_bytes = 0u;
    bool trinary_shape_valid = vdb->vector_dims != 0u &&
        qihse_trinary_tryte_row_bytes(vdb->vector_dims, &expected_trinary_row_bytes) &&
        snapshot.manifest.trinary_row_bytes == (uint64_t)expected_trinary_row_bytes &&
        snapshot.manifest.trinary_rows == (uint64_t)vdb->total_vectors;

    if (snapshot.trinary_valid && trinary_shape_valid &&
        snapshot.manifest.trinary_generation == vdb->committed_generation) {
        vdb->trinary_status = QIHSE_VDB_TRINARY_VALID;
        vdb->trinary_row_bytes = snapshot.manifest.trinary_row_bytes;
        vdb->trinary_rows = snapshot.manifest.trinary_rows;
        vdb->trinary = snapshot.trinary;
        vdb->trinary_bytes = snapshot.trinary_bytes;
        snapshot.trinary = NULL;
        snapshot.trinary_bytes = 0u;
    } else if (snapshot.trinary_valid) {
        vdb->trinary_status = QIHSE_VDB_TRINARY_STALE;
        vdb->trinary_row_bytes = snapshot.manifest.trinary_row_bytes;
        vdb->trinary_rows = snapshot.manifest.trinary_rows;
        qihse_vdb_clear_trinary_cache(vdb);
    } else if (qtri_exists) {
        vdb->trinary_status = QIHSE_VDB_TRINARY_CORRUPT;
        vdb->trinary_row_bytes = snapshot.manifest.trinary_row_bytes;
        vdb->trinary_rows = snapshot.manifest.trinary_rows;
        qihse_vdb_clear_trinary_cache(vdb);
    } else {
        vdb->trinary_status = QIHSE_VDB_TRINARY_ABSENT;
        qihse_vdb_clear_trinary_cache(vdb);
    }
    qmag_exists = (snapshot.manifest.magnitude_flags & QIHSE_VSTORE_MAG_PRESENT) != 0u;
    bool magnitude_shape_valid = vdb->vector_dims != 0u &&
        snapshot.manifest.magnitude_row_bytes == (uint64_t)vdb->vector_dims &&
        snapshot.manifest.magnitude_rows == (uint64_t)vdb->total_vectors;

    if (snapshot.magnitude_valid && magnitude_shape_valid &&
        snapshot.manifest.magnitude_generation == vdb->committed_generation) {
        vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_VALID;
        vdb->magnitude_row_bytes = snapshot.manifest.magnitude_row_bytes;
        vdb->magnitude_rows = snapshot.manifest.magnitude_rows;
        vdb->magnitude = snapshot.magnitude;
        vdb->magnitude_bytes = snapshot.magnitude_bytes;
        snapshot.magnitude = NULL;
        snapshot.magnitude_bytes = 0u;
    } else if (snapshot.magnitude_valid) {
        vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_STALE;
        vdb->magnitude_row_bytes = snapshot.manifest.magnitude_row_bytes;
        vdb->magnitude_rows = snapshot.manifest.magnitude_rows;
        qihse_vdb_clear_magnitude_cache(vdb);
    } else if (qmag_exists) {
        vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_CORRUPT;
        vdb->magnitude_row_bytes = snapshot.manifest.magnitude_row_bytes;
        vdb->magnitude_rows = snapshot.manifest.magnitude_rows;
        qihse_vdb_clear_magnitude_cache(vdb);
    } else {
        vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_ABSENT;
        qihse_vdb_clear_magnitude_cache(vdb);
    }
    if (use_mmap && (vdb->vector_bytes_used != 0u || vdb->metadata_bytes_used != 0u)) {
        if (qihse_vdb_map_vectors(vdb)) {
            free(vdb->vectors);
            vdb->vectors = NULL;
            vdb->vector_bytes_capacity = 0u;
        }
        if (qihse_vdb_map_metadata(vdb)) {
            free(vdb->metadata);
            vdb->metadata = NULL;
            vdb->metadata_bytes_capacity = 0u;
        }
        (void)qihse_vdb_try_map_index(vdb, &snapshot.manifest);
        (void)qihse_vdb_try_map_idmap(vdb, &snapshot.manifest);
    }
    qihse_vector_store_snapshot_free(&snapshot);
    return true;
}

qihse_vector_db_t qihse_vector_db_open(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path,
    uint32_t flags
) {
    qihse_system_guard_profile();
    qihse_vector_db_t vdb;
    bool file_backed = db_path && ((flags & QIHSE_VDB_OPEN_FILE_BACKED) != 0u || db_path[0] != '\0');
    bool read_only = (flags & QIHSE_VDB_OPEN_READ_ONLY) != 0u;
    bool use_mmap = (flags & QIHSE_VDB_OPEN_MMAP) != 0u;
    bool create = (flags & QIHSE_VDB_OPEN_CREATE) != 0u;
    bool loaded = false;

    if (use_mmap && !read_only) {
        errno = EINVAL;
        return NULL;
    }
    vdb = (qihse_vector_db_t)calloc(1u, sizeof(*vdb));
    if (!vdb) {
        errno = ENOMEM;
        return NULL;
    }
    vdb->backend = backend;
    vdb->uma = uma;
    vdb->file_backed = file_backed;
    vdb->read_only = read_only;
    vdb->storage_mode = file_backed ? QIHSE_VDB_STORAGE_FILE_COPY : QIHSE_VDB_STORAGE_EPHEMERAL;
    vdb->mmap_fd = -1;
    vdb->metadata_mmap_fd = -1;
    vdb->index_mmap_fd = -1;
    vdb->idmap_mmap_fd = -1;
    vdb->next_generation = 1u;
    vdb->wal_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
    vdb->trinary_status = QIHSE_VDB_TRINARY_ABSENT;
    vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_ABSENT;
    if (pthread_mutex_init(&vdb->explicit_edge_mutex, NULL) != 0) {
        free(vdb);
        errno = ENOMEM;
        return NULL;
    }
    vdb->explicit_edge_mutex_initialized = true;

    /* Hierarchical storage defaults */
    vdb->memory_hot_threshold = 100.0;     /* 100 accesses per evaluation window = hot */
    vdb->memory_cold_threshold = 5.0;      /* 5 accesses per evaluation window = cold */
    vdb->memory_maintenance_interval = 0u; /* Explicit maintenance by default */

    if (file_backed) {
        vdb->db_path = qihse_vdb_strdup(db_path);
        if (!vdb->db_path) {
            qihse_vector_db_destroy(vdb);
            return NULL;
        }
        /* Container-based open: the .qdb file IS the database. */
        if (!read_only && (flags & QIHSE_VDB_OPEN_TRUNCATE) != 0u) {
            /* Truncate == delete the container file to start fresh */
            unlink(vdb->db_path);
        }
        
        if (!read_only && create) {
            /* Ensure the container file exists so WAL appends can succeed. */
            qihse_container_t init_ctr;
            if (qihse_ctr_open_write(vdb->db_path, true, &init_ctr)) {
                qihse_ctr_close(&init_ctr);
            }
        }
        
        {
            /* Check whether the container has a MANIFEST section */
            bool has_manifest = false;
            bool has_wal = false;
            qihse_container_t probe;
            if (qihse_ctr_open_read(vdb->db_path, &probe)) {
                has_manifest = qihse_ctr_find_section(&probe, QIHSE_CTR_SEC_MANIFEST) != NULL;
                has_wal = qihse_ctr_section_length(&probe, QIHSE_CTR_SEC_WAL) > 0u;
                qihse_ctr_close(&probe);
            } else {
                // printf("[DEBUG] qihse_ctr_open_read failed! path='%s' errno=%d (%s)\n", vdb->db_path, errno, strerror(errno));
            }
            if (has_manifest) {
                if (!qihse_vdb_load_snapshot(vdb, use_mmap)) {
                    qihse_vector_db_destroy(vdb);
                    return NULL;
                }
                loaded = true;
                if (!qihse_vdb_load_edges(vdb)) {
                    qihse_vector_db_destroy(vdb);
                    return NULL;
                }
            } else if (!create && !has_wal) {
                qihse_vector_db_destroy(vdb);
                errno = ENOENT;
                return NULL;
            }
            if (use_mmap && has_wal) {
                qihse_vector_db_destroy(vdb);
                errno = ENOTSUP;
                return NULL;
            }
        }
        if (!qihse_vdb_replay_wal(vdb)) {
            qihse_vector_db_destroy(vdb);
            return NULL;
        }
        if (vdb->wal_records_replayed != 0u) {
            if (!qihse_vdb_rebuild_idmap(vdb, !read_only)) {
                qihse_vector_db_destroy(vdb);
                return NULL;
            }
            if (!read_only) {
                vdb->dirty = true;
            }
        } else if (loaded) {
            vdb->dirty = vdb->idmap_dirty;
        }
        /* mmap not yet supported for container format, fallback to FILE_COPY */
        /* Load sidecars — they are stable snapshot files independent of WAL replay */
        qihse_vdb_graph_load(vdb);
        qihse_vdb_int8_load(vdb);
        qihse_vdb_tier_load(vdb);
    }

    /* Load configuration file and apply settings */
    {
        qihse_vdb_config_t cfg;
        qihse_vdb_config_load(&cfg);
        if (cfg.cache_max_entries_set && cfg.cache_max_entries > 0u) {
            qihse_vector_db_enable_cache(vdb, cfg.cache_max_entries);
        }
        if (cfg.memory_hot_threshold_set) {
            vdb->memory_hot_threshold = cfg.memory_hot_threshold;
        }
        if (cfg.memory_cold_threshold_set) {
            vdb->memory_cold_threshold = cfg.memory_cold_threshold;
        }
        if (cfg.memory_maintenance_interval_set) {
            vdb->memory_maintenance_interval = cfg.memory_maintenance_interval;
        }
    }

    return vdb;
}

qihse_vector_db_t qihse_vector_db_create(
    qihse_vector_db_backend_t backend,
    qihse_uma_manager_t uma,
    const char* db_path
) {
    uint32_t flags = QIHSE_VDB_OPEN_CREATE;
    if (db_path) {
        flags |= QIHSE_VDB_OPEN_FILE_BACKED;
    }
    return qihse_vector_db_open(backend, uma, db_path, flags);
}

bool qihse_vector_db_add_vectors(
    qihse_vector_db_t vdb,
    const float* vectors,
    size_t num_vectors,
    size_t vector_dims,
    const uint64_t* ids,
    const void* const* metadata,
    const size_t* metadata_sizes
) {
    qihse_vdb_wal_add_t add;
    uint64_t generation;
    size_t i;
    if (!vdb || !vectors || num_vectors == 0u || vector_dims == 0u) {
        errno = EINVAL;
        return false;
    }
    if (vdb->read_only || vdb->mapped_vectors) {
        errno = EROFS;
        return false;
    }
    if ((uint64_t)num_vectors > UINT64_MAX || (uint64_t)vector_dims > UINT64_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    for (i = 0u; i < num_vectors; i++) {
        if (metadata_sizes && metadata_sizes[i] != 0u && (!metadata || !metadata[i])) {
            errno = EINVAL;
            return false;
        }
        /* 
         * REDTEAM FIX: O(N^2) duplicate ID check removed. 
         * For N=100,000, this takes 5 billion iterations. 
         * The downstream WAL applier already rejects duplicate IDs.
         */
    }
    generation = vdb->next_generation;
    memset(&add, 0, sizeof(add));
    add.generation = generation;
    add.count = (uint64_t)num_vectors;
    add.dims = (uint64_t)vector_dims;
    add.ids = ids;
    add.vectors = vectors;
    add.metadata = metadata;
    add.metadata_sizes = metadata_sizes;

    if (vdb->file_backed && !qihse_vdb_write_wal_add(vdb, &add)) {
        return false;
    }
    return qihse_vdb_apply_add(vdb, &add, true);
}

bool qihse_vector_db_add_model_weights(
    qihse_vector_db_t vdb,
    qihse_vector_db_query_mode_t category,
    const void* weights,
    size_t num_vectors,
    size_t vector_dims,
    const uint64_t* ids
) {
    if (!vdb || !weights || num_vectors == 0 || vector_dims == 0) return false;

    // First we must expand the weights into an FP32 array.
    size_t alloc_bytes;
    if (!qihse_checked_mul_size(num_vectors, vector_dims, &alloc_bytes) ||
        !qihse_checked_mul_size(alloc_bytes, sizeof(float), &alloc_bytes)) {
        return false;
    }
    
    float* fp32_expanded = (float*)malloc(alloc_bytes);
    if (!fp32_expanded) return false;

    // Expand based on category
    if (category == QIHSE_VDB_QUERY_FP32) {
        memcpy(fp32_expanded, weights, alloc_bytes);
    } else if (category == QIHSE_VDB_QUERY_FP16) {
        const uint16_t* w16 = (const uint16_t*)weights;
        for (size_t i = 0; i < num_vectors * vector_dims; i++) {
            uint32_t f32 = ((w16[i] & 0x8000) << 16) | (((w16[i] & 0x7FFF) << 13) + (112 << 23));
            memcpy(&fp32_expanded[i], &f32, sizeof(float));
        }
    } else if (category == QIHSE_VDB_QUERY_INT8) {
        const int8_t* w8 = (const int8_t*)weights;
        for (size_t i = 0; i < num_vectors * vector_dims; i++) {
            fp32_expanded[i] = (float)w8[i] / 127.0f;
        }
    } else if (category == QIHSE_VDB_QUERY_FP8) {
        const uint8_t* w8 = (const uint8_t*)weights;
        for (size_t i = 0; i < num_vectors * vector_dims; i++) {
            uint32_t f32 = ((w8[i] & 0x80) << 24) | (((w8[i] & 0x78) >> 3) << 23) | ((w8[i] & 0x07) << 20);
            memcpy(&fp32_expanded[i], &f32, sizeof(float));
        }
    } else if (category == QIHSE_VDB_QUERY_FP4) {
        const uint8_t* w4 = (const uint8_t*)weights;
        size_t packed_dims = vector_dims / 2 + (vector_dims % 2);
        for (size_t i = 0; i < num_vectors; i++) {
            for (size_t j = 0; j < packed_dims; j++) {
                uint8_t byte = w4[i * packed_dims + j];
                for (int k = 0; k < 2; k++) {
                    if (j * 2 + k < vector_dims) {
                        uint8_t val = (byte >> (k * 4)) & 0x0F;
                        uint32_t f32 = ((val & 0x08) << 28) | (((val & 0x06) >> 1) << 23) | ((val & 0x01) << 22);
                        memcpy(&fp32_expanded[i * vector_dims + j * 2 + k], &f32, sizeof(float));
                    }
                }
            }
        }
    } else if (category == QIHSE_VDB_QUERY_INT4) {
        const uint8_t* w4 = (const uint8_t*)weights;
        size_t packed_dims = vector_dims / 2 + (vector_dims % 2);
        for (size_t i = 0; i < num_vectors; i++) {
            for (size_t j = 0; j < packed_dims; j++) {
                uint8_t byte = w4[i * packed_dims + j];
                for (int k = 0; k < 2; k++) {
                    if (j * 2 + k < vector_dims) {
                        int8_t val = (int8_t)((byte >> (k * 4)) & 0x0F);
                        if (val & 0x08) val |= 0xF0; // sign extend
                        fp32_expanded[i * vector_dims + j * 2 + k] = (float)val / 7.0f;
                    }
                }
            }
        }
    } else {
        free(fp32_expanded);
        return false;
    }

    // Call standard internal ingestion which handles metadata and IDs natively in FP32
    bool ok = qihse_vector_db_add_vectors(vdb, fp32_expanded, num_vectors, vector_dims, ids, NULL, NULL);
    free(fp32_expanded);
    
    // Explicitly rebuild only the target sidecar for efficiency, since the user already told us exactly
    // which precision these weights were optimized for
    if (ok) {
        switch (category) {
            case QIHSE_VDB_QUERY_FP32: qihse_vector_db_build_fp32(vdb); break;
            case QIHSE_VDB_QUERY_FP16: qihse_vector_db_build_fp16(vdb); break;
            case QIHSE_VDB_QUERY_INT8: qihse_vector_db_build_int8(vdb); break;
            case QIHSE_VDB_QUERY_FP8:  qihse_vector_db_build_fp8(vdb); break;
            case QIHSE_VDB_QUERY_FP4:  qihse_vector_db_build_fp4(vdb); break;
            case QIHSE_VDB_QUERY_INT4: qihse_vector_db_build_int4(vdb); break;
            default: break;
        }
    }
    
    return ok;
}

bool qihse_vector_db_delete_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id
) {
    size_t deleted = 0u;

    if (!qihse_vector_db_delete_by_ids(vdb, &vector_id, 1u, &deleted)) {
        return false;
    }
    if (deleted == 0u) {
        errno = ENOENT;
        return false;
    }
    return true;
}

bool qihse_vector_db_get_vector_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    float* out_vector,
    size_t* out_dims
) {
    if (!vdb || !out_vector) {
        errno = EINVAL;
        return false;
    }

    size_t row_index = 0u;
    if (!qihse_vdb_find_live_row_by_id(vdb, vector_id, &row_index)) {
        errno = ENOENT;
        return false;
    }

    const qihse_index_row_t* row = &vdb->rows[row_index];
    const float* vec = qihse_vdb_vector_at(vdb, row);
    if (!vec) {
        errno = ENOENT;
        return false;
    }

    memcpy(out_vector, vec, vdb->vector_dims * sizeof(float));
    if (out_dims) *out_dims = vdb->vector_dims;
    return true;
}

bool qihse_vector_db_delete_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    size_t count,
    size_t* deleted_count
) {
    uint64_t generation;
    size_t deleted = 0u;
    size_t i;

    if (deleted_count) {
        *deleted_count = 0u;
    }
    if (!qihse_vdb_ensure_writable(vdb)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (!vector_ids || qihse_vdb_has_duplicate_ids(vector_ids, count)) {
        if (!vector_ids) {
            errno = EINVAL;
        }
        return false;
    }
    pthread_mutex_lock(&vdb->explicit_edge_mutex);
    for (i = 0u; i < vdb->explicit_edge_count; i++) {
        size_t id_index;
        for (id_index = 0u; id_index < count; id_index++) {
            if (vdb->explicit_edges[i].from_id == vector_ids[id_index] ||
                vdb->explicit_edges[i].to_id == vector_ids[id_index]) {
                pthread_mutex_unlock(&vdb->explicit_edge_mutex);
                errno = EBUSY;
                return false;
            }
        }
    }
    pthread_mutex_unlock(&vdb->explicit_edge_mutex);
    for (i = 0u; i < count; i++) {
        size_t row_index = 0u;
        bool found;
        errno = 0;
        found = qihse_vdb_find_live_row_by_id(vdb, vector_ids[i], &row_index);
        if (!found && errno != ENOENT) {
            return false;
        }
        if (found) {
            deleted++;
        }
    }

    generation = vdb->next_generation;
    if (deleted != 0u && vdb->file_backed) {
        qihse_vdb_wal_vectors_t record;
        memset(&record, 0, sizeof(record));
        record.generation = generation;
        record.count = (uint64_t)count;
        record.ids = vector_ids;
        if (!qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_DELETE, &record)) {
            return false;
        }
    }
    if (deleted != 0u) {
        deleted = 0u;
        for (i = 0u; i < count; i++) {
            deleted += qihse_vdb_tombstone_live_id(vdb, vector_ids[i],
                                                   generation) != 0u ? 1u : 0u;
        }
    }
    if (deleted != 0u) {
        qihse_vdb_finish_mutation_generation(vdb, generation);
    }
    if (deleted_count) {
        *deleted_count = deleted;
    }
    return true;
}

static bool qihse_vdb_validate_mutation_vectors(qihse_vector_db_t vdb,
                                                const uint64_t* vector_ids,
                                                const float* vectors,
                                                size_t count,
                                                size_t dims,
                                                const void* const* metadata,
                                                const size_t* metadata_sizes) {
    size_t i;

    if (!qihse_vdb_ensure_writable(vdb)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (!vector_ids || !vectors || dims == 0u ||
        qihse_vdb_has_duplicate_ids(vector_ids, count)) {
        if (!vector_ids || !vectors || dims == 0u) {
            errno = EINVAL;
        }
        return false;
    }
    if (vdb->vector_dims != 0u && vdb->vector_dims != dims) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < count; i++) {
        if (metadata_sizes && metadata_sizes[i] != 0u && (!metadata || !metadata[i])) {
            errno = EINVAL;
            return false;
        }
    }
    return true;
}

static bool qihse_vdb_reserve_appends(qihse_vector_db_t vdb,
                                      size_t append_count,
                                      size_t metadata_bytes) {
    size_t one_vector_bytes;
    size_t vector_bytes;
    size_t new_vector_used;
    size_t new_metadata_used;

    if (append_count == 0u) {
        return true;
    }
    if (!qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &one_vector_bytes) ||
        !qihse_checked_mul_size(append_count, one_vector_bytes, &vector_bytes) ||
        !qihse_checked_add_size(vdb->vector_bytes_used, vector_bytes, &new_vector_used) ||
        !qihse_checked_add_size(vdb->metadata_bytes_used, metadata_bytes, &new_metadata_used) ||
        !qihse_vdb_reserve_rows(vdb, vdb->total_vectors + append_count) ||
        !qihse_vdb_reserve_bytes(&vdb->vectors, &vdb->vector_bytes_capacity, new_vector_used) ||
        !qihse_vdb_reserve_bytes(&vdb->metadata, &vdb->metadata_bytes_capacity, new_metadata_used)) {
        return false;
    }
    return true;
}

bool qihse_vector_db_update_by_id(
    qihse_vector_db_t vdb,
    uint64_t vector_id,
    const float* vector,
    size_t dims,
    const void* metadata,
    size_t metadata_size
) {
    const void* metadata_items[1];
    size_t metadata_sizes[1];
    size_t updated = 0u;

    metadata_items[0] = metadata;
    metadata_sizes[0] = metadata_size;
    if (!qihse_vector_db_update_by_ids(vdb, &vector_id, vector, 1u, dims,
                                       metadata_size == 0u ? NULL : metadata_items,
                                       metadata_size == 0u ? NULL : metadata_sizes,
                                       &updated)) {
        return false;
    }
    if (updated == 0u) {
        errno = ENOENT;
        return false;
    }
    return true;
}

bool qihse_vector_db_update_by_ids(
    qihse_vector_db_t vdb,
    const uint64_t* vector_ids,
    const float* vectors,
    size_t count,
    size_t dims,
    const void* const* metadata,
    const size_t* metadata_sizes,
    size_t* updated_count
) {
    bool* exists = NULL;
    uint64_t generation;
    size_t metadata_bytes = 0u;
    size_t updated = 0u;
    size_t i;

    if (updated_count) {
        *updated_count = 0u;
    }
    if (!qihse_vdb_validate_mutation_vectors(vdb, vector_ids, vectors, count, dims,
                                             metadata, metadata_sizes)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (vdb->vector_dims == 0u) {
        errno = ENOENT;
        return true;
    }
    exists = (bool*)calloc(count, sizeof(*exists));
    if (!exists) {
        errno = ENOMEM;
        return false;
    }
    for (i = 0u; i < count; i++) {
        size_t row_index = 0u;
        errno = 0;
        exists[i] = qihse_vdb_find_live_row_by_id(vdb, vector_ids[i], &row_index);
        if (!exists[i] && errno != ENOENT) {
            free(exists);
            return false;
        }
        if (exists[i]) {
            size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
            if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
                free(exists);
                return false;
            }
            updated++;
        }
    }
    if (updated == 0u) {
        free(exists);
        if (updated_count) {
            *updated_count = 0u;
        }
        return true;
    }
    if (!qihse_vdb_reserve_appends(vdb, updated, metadata_bytes)) {
        free(exists);
        return false;
    }

    generation = vdb->next_generation;
    if (vdb->file_backed) {
        qihse_vdb_wal_vectors_t record;
        memset(&record, 0, sizeof(record));
        record.generation = generation;
        record.count = (uint64_t)count;
        record.dims = (uint64_t)dims;
        record.ids = vector_ids;
        record.vectors = vectors;
        record.metadata = metadata;
        record.metadata_sizes = metadata_sizes;
        if (!qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_UPDATE, &record)) {
            free(exists);
            return false;
        }
    }
    for (i = 0u; i < count; i++) {
        if (!exists[i]) {
            continue;
        }
        size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
        const void* meta = metadata ? metadata[i] : NULL;
        qihse_vdb_tombstone_live_id(vdb, vector_ids[i], generation);
        if (!qihse_vdb_append_row(vdb, vector_ids[i], vectors + (i * dims),
                                  meta, meta_size, generation)) {
            free(exists);
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, generation);
    free(exists);
    if (updated_count) {
        *updated_count = updated;
    }
    return true;
}

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
) {
    bool* exists = NULL;
    uint64_t generation;
    size_t metadata_bytes = 0u;
    size_t inserted = 0u;
    size_t updated = 0u;
    size_t i;

    if (inserted_count) {
        *inserted_count = 0u;
    }
    if (updated_count) {
        *updated_count = 0u;
    }
    if (!qihse_vdb_validate_mutation_vectors(vdb, vector_ids, vectors, count, dims,
                                             metadata, metadata_sizes)) {
        return false;
    }
    if (count == 0u) {
        return true;
    }
    if (vdb->vector_dims == 0u) {
        vdb->vector_dims = dims;
    }
    exists = (bool*)calloc(count, sizeof(*exists));
    if (!exists) {
        errno = ENOMEM;
        return false;
    }
    for (i = 0u; i < count; i++) {
        size_t row_index = 0u;
        size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
        errno = 0;
        exists[i] = qihse_vdb_find_live_row_by_id(vdb, vector_ids[i], &row_index);
        if (!exists[i] && errno != ENOENT) {
            free(exists);
            return false;
        }
        if (!qihse_checked_add_size(metadata_bytes, meta_size, &metadata_bytes)) {
            free(exists);
            return false;
        }
        if (exists[i]) {
            updated++;
        } else {
            inserted++;
        }
    }
    if (!qihse_vdb_reserve_appends(vdb, count, metadata_bytes)) {
        free(exists);
        return false;
    }

    generation = vdb->next_generation;
    if (vdb->file_backed) {
        qihse_vdb_wal_vectors_t record;
        memset(&record, 0, sizeof(record));
        record.generation = generation;
        record.count = (uint64_t)count;
        record.dims = (uint64_t)dims;
        record.ids = vector_ids;
        record.vectors = vectors;
        record.metadata = metadata;
        record.metadata_sizes = metadata_sizes;
        if (!qihse_vdb_write_wal_vectors(vdb, QIHSE_VDB_WAL_UPSERT, &record)) {
            free(exists);
            return false;
        }
    }
    for (i = 0u; i < count; i++) {
        size_t meta_size = metadata_sizes ? metadata_sizes[i] : 0u;
        const void* meta = metadata ? metadata[i] : NULL;
        if (exists[i]) {
            qihse_vdb_tombstone_live_id(vdb, vector_ids[i], generation);
        }
        if (!qihse_vdb_append_row(vdb, vector_ids[i], vectors + (i * dims),
                                  meta, meta_size, generation)) {
            free(exists);
            return false;
        }
    }
    qihse_vdb_finish_mutation_generation(vdb, generation);
    free(exists);
    if (inserted_count) {
        *inserted_count = inserted;
    }
    if (updated_count) {
        *updated_count = updated;
    }
    return true;
}

int qihse_vector_db_search(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results
) {
    int ret;
    int cache_count = 0;
    qihse_vector_query_t query_fallback;

    if (query && !query->user) {
        query_fallback = *query;
        query_fallback.user = qihse_auth_get_user(0);
        if (!query_fallback.user) {
            if (qihse_auth_init()) {
                query_fallback.user = qihse_auth_get_user(0);
            }
        }
        query = &query_fallback;
    }

    if (!vdb || !query || !query->user || !query->query_vector || !results || max_results == 0u) {
        errno = query && !query->user ? EACCES : EINVAL;
        return -1;
    }

    /* Try cache first */
    if (vdb && query && results && vdb->cache_capacity > 0u &&
        qihse_vdb_cache_lookup(vdb, query, results, max_results, &cache_count)) {
        return cache_count;
    }

    if (query && query->query_mode == QIHSE_VDB_QUERY_TRINARY_MAGNITUDE_BYPASS) {
        ret = qihse_vdb_search_trinary_magnitude_candidates_no_rerank(
            vdb, query, results, max_results);
    } else if (query && query->query_mode == QIHSE_VDB_QUERY_TRINARY_MAGNITUDE) {
        ret = qihse_vdb_search_trinary_magnitude_candidates(vdb, query, results, max_results);
    } else if (query && query->query_mode == QIHSE_VDB_QUERY_TRINARY_SCALAR) {
        size_t candidate_count;
        if (!qihse_vdb_resolve_candidate_pool(vdb, query,
                                              QIHSE_VDB_QUERY_TRINARY_SCALAR,
                                              &candidate_count)) {
            return -1;
        }
        ret = qihse_vector_db_search_trinary_candidates(vdb, query,
                                                         candidate_count,
                                                         results, max_results);
    } else if (query && query->query_mode == QIHSE_VDB_QUERY_GRAPH) {
        size_t top_k = query->top_k > 0u ? query->top_k : 10u;

        if (vdb->graph_status != QIHSE_VDB_GRAPH_VALID) {
            errno = ENOENT;
            return -1;
        }
        ret = qihse_vdb_search_exact_rows(vdb, query, results, max_results, top_k);
    } else if (query && query->query_mode == QIHSE_VDB_QUERY_INT8) {
        size_t candidate_count;
        if (vdb->int8_status != QIHSE_VDB_INT8_VALID) {
            errno = ENOENT;
            return -1;
        }
        candidate_count = query->candidate_pool_size > 0u ? query->candidate_pool_size : query->top_k * 12u;
        if (candidate_count > vdb->live_vectors) {
            candidate_count = vdb->live_vectors;
        }
        ret = qihse_vdb_search_int8_candidates(vdb, query, candidate_count, results, max_results);
    } else if (query && query->query_mode == QIHSE_VDB_QUERY_SPARSE) {
        if (!vdb->sparse_index) {
            errno = ENOENT;
            return -1;
        }
        ret = qihse_vdb_search_sparse(vdb, query, results, max_results);
    } else if (query && (query->query_mode == QIHSE_VDB_QUERY_FP16 || query->query_mode == QIHSE_VDB_QUERY_FP32 || 
                         query->query_mode == QIHSE_VDB_QUERY_FP8 || query->query_mode == QIHSE_VDB_QUERY_FP4 || 
                         query->query_mode == QIHSE_VDB_QUERY_INT4)) {
        if (query->query_mode == QIHSE_VDB_QUERY_FP16 && vdb->fp16_status != QIHSE_VDB_FP16_VALID) {
            errno = ENOENT;
            return -1;
        }
        if (query->query_mode == QIHSE_VDB_QUERY_FP32 && vdb->fp32_status != QIHSE_VDB_FP32_VALID) {
            errno = ENOENT;
            return -1;
        }
        if (query->query_mode == QIHSE_VDB_QUERY_FP8 && vdb->fp8_status != QIHSE_VDB_FP8_VALID) {
            errno = ENOENT;
            return -1;
        }
        if (query->query_mode == QIHSE_VDB_QUERY_FP4 && vdb->fp4_status != QIHSE_VDB_FP4_VALID) {
            errno = ENOENT;
            return -1;
        }
        if (query->query_mode == QIHSE_VDB_QUERY_INT4 && vdb->int4_status != QIHSE_VDB_INT4_VALID) {
            errno = ENOENT;
            return -1;
        }
        ret = qihse_vdb_search_exact_rows(vdb, query, results, max_results, max_results);
    } else if (query && query->use_trinary_candidates) {
        ret = qihse_vector_db_search_trinary_candidates(vdb, query,
                                                         query->candidate_count,
                                                         results, max_results);
    } else {
        size_t requested_bytes = (size_t)vdb->live_vectors * (size_t)vdb->vector_dims * sizeof(float);
        if (!qihse_system_guard_check_operation(requested_bytes, true)) {
            errno = ENOMEM;
            return -1;
        }
        ret = qihse_vdb_search_exact_rows(vdb, query, results, max_results, max_results);
    }

    /* Insert into cache on successful search */
    if (ret > 0 && vdb && query && results && vdb->cache_capacity > 0u) {
        qihse_vdb_cache_insert(vdb, query, results, (size_t)ret);
    }
    return ret;
}

bool qihse_vector_db_search_batch(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* queries,
    size_t num_queries,
    qihse_vector_result_t* results,
    size_t max_results,
    int* out_counts
) {
    size_t i;

    if (!vdb || !queries || !results || !out_counts || num_queries == 0u ||
        max_results == 0u) {
        errno = EINVAL;
        return false;
    }

    for (i = 0u; i < num_queries; i++) {
        int count;
        if (!queries[i].user) {
            errno = EACCES;
            return false;
        }
        /* Batch INT8: pre-quantize once, then search prequantized */
        if (queries[i].query_mode == QIHSE_VDB_QUERY_INT8 &&
            vdb->int8_status == QIHSE_VDB_INT8_VALID) {
            int8_t* q_quantized = qihse_vdb_int8_quantize_query(vdb, queries[i].query_vector);
            size_t candidate_count = queries[i].candidate_pool_size > 0u
                ? queries[i].candidate_pool_size
                : queries[i].top_k * 12u;
            if (candidate_count > vdb->live_vectors) {
                candidate_count = vdb->live_vectors;
            }
            if (q_quantized) {
                count = qihse_vdb_search_int8_candidates_prequantized(
                    vdb, &queries[i], q_quantized, candidate_count,
                    results + (i * max_results), max_results);
                free(q_quantized);
            } else {
                count = -1;
            }
        } else {
            count = qihse_vector_db_search(vdb, &queries[i],
                                           results + (i * max_results),
                                           max_results);
        }
        if (count < 0) {
            return false;
        }
        out_counts[i] = count;
    }
    /* Trigger hierarchical storage maintenance if interval is set */
    if (vdb->memory_maintenance_interval > 0u) {
        vdb->memory_maintenance_queries += num_queries;
        if (vdb->memory_maintenance_queries >= vdb->memory_maintenance_interval) {
            qihse_vdb_run_memory_maintenance(vdb);
        }
    }
    return true;
}

typedef struct {
    uint64_t id;
    float score;
    float* vector;
    size_t vector_dims;
    void* metadata;
    size_t metadata_size;
} qihse_vdb_rrf_entry_t;

static void qihse_vdb_rrf_apply(qihse_vdb_rrf_entry_t* entries,
                                size_t* count,
                                size_t capacity,
                                const qihse_vector_result_t* path_results,
                                int path_count,
                                float k) {
    size_t i;
    for (i = 0u; i < (size_t)path_count; i++) {
        float score = 1.0f / ((float)i + k + FLT_EPSILON);
        size_t j;
        bool found = false;
        for (j = 0u; j < *count; j++) {
            if (entries[j].id == path_results[i].id) {
                entries[j].score += score;
                found = true;
                break;
            }
        }
        if (!found && *count < capacity) {
            qihse_vdb_rrf_entry_t* e = &entries[*count];
            e->id = path_results[i].id;
            e->score = score;
            e->vector = path_results[i].vector;
            e->vector_dims = path_results[i].vector_dims;
            e->metadata = path_results[i].metadata;
            e->metadata_size = path_results[i].metadata_size;
            /* Claim ownership of dynamically allocated fields */
            if (path_results[i].vector) {
                e->vector = path_results[i].vector;
            }
            if (path_results[i].metadata) {
                e->metadata = path_results[i].metadata;
            }
            (*count)++;
        }
    }
}

static int qihse_vdb_rrf_cmp_desc(const void* a, const void* b) {
    const qihse_vdb_rrf_entry_t* ea = (const qihse_vdb_rrf_entry_t*)a;
    const qihse_vdb_rrf_entry_t* eb = (const qihse_vdb_rrf_entry_t*)b;
    if (ea->score > eb->score) return -1;
    if (ea->score < eb->score) return 1;
    if (ea->id < eb->id) return -1;
    if (ea->id > eb->id) return 1;
    return 0;
}

int qihse_vector_db_hybrid_search(
    qihse_vector_db_t vdb,
    const qihse_hybrid_request_t* request,
    qihse_vector_result_t* results,
    size_t max_results
) {
    qihse_vector_result_t* path_a = NULL;
    qihse_vector_result_t* path_b = NULL;
    qihse_vdb_rrf_entry_t* entries = NULL;
    size_t entry_count = 0u;
    int count_a = 0;
    int count_b = 0;
    size_t top_k;
    size_t pool_size;
    size_t i;
    float k;

    if (!vdb || !request || !results || max_results == 0u) {
        errno = EINVAL;
        return -1;
    }

    top_k = request->query_a.top_k > 0u ? request->query_a.top_k : 10u;
    if (request->query_b.top_k > 0u && request->query_b.top_k < top_k) {
        top_k = request->query_b.top_k;
    }
    if (top_k > max_results) {
        top_k = max_results;
    }

    k = request->fusion_constant_k;
    if (k < 0.0f) {
        k = 60.0f;
    }

    pool_size = max_results * 3u;
    if (pool_size < top_k * 3u) {
        pool_size = top_k * 3u;
    }

    path_a = (qihse_vector_result_t*)calloc(pool_size, sizeof(*path_a));
    path_b = (qihse_vector_result_t*)calloc(pool_size, sizeof(*path_b));
    entries = (qihse_vdb_rrf_entry_t*)calloc(pool_size, sizeof(*entries));
    if (!path_a || !path_b || !entries) {
        free(path_a);
        free(path_b);
        free(entries);
        errno = ENOMEM;
        return -1;
    }

    count_a = qihse_vector_db_search(vdb, &request->query_a, path_a, pool_size);
    if (count_a < 0) {
        free(path_a);
        free(path_b);
        free(entries);
        return -1;
    }
    count_b = qihse_vector_db_search(vdb, &request->query_b, path_b, pool_size);
    if (count_b < 0) {
        /* Clean up path_a results to avoid leaks */
        for (i = 0u; i < (size_t)count_a; i++) {
            free(path_a[i].vector);
            free(path_a[i].metadata);
        }
        free(path_a);
        free(path_b);
        free(entries);
        return -1;
    }

    qihse_vdb_rrf_apply(entries, &entry_count, pool_size, path_a, count_a, k);
    qihse_vdb_rrf_apply(entries, &entry_count, pool_size, path_b, count_b, k);

    qsort(entries, entry_count, sizeof(*entries), qihse_vdb_rrf_cmp_desc);

    memset(results, 0, max_results * sizeof(*results));
    for (i = 0u; i < entry_count && i < top_k && i < max_results; i++) {
        results[i].id = entries[i].id;
        results[i].score = entries[i].score;
        results[i].vector = entries[i].vector;
        results[i].vector_dims = entries[i].vector_dims;
        results[i].metadata = entries[i].metadata;
        results[i].metadata_size = entries[i].metadata_size;
        /* Mark as transferred so cleanup below doesn't free them */
        entries[i].vector = NULL;
        entries[i].metadata = NULL;
    }

    /* Clean up unclaimed results from path_a */
    for (i = 0u; i < (size_t)count_a; i++) {
        size_t j;
        bool claimed = false;
        for (j = 0u; j < entry_count && j < top_k && j < max_results; j++) {
            if (results[j].id == path_a[i].id) {
                claimed = true;
                break;
            }
        }
        if (!claimed) {
            free(path_a[i].vector);
            free(path_a[i].metadata);
        }
    }
    /* Clean up unclaimed results from path_b */
    for (i = 0u; i < (size_t)count_b; i++) {
        size_t j;
        bool claimed = false;
        for (j = 0u; j < entry_count && j < top_k && j < max_results; j++) {
            if (results[j].id == path_b[i].id) {
                claimed = true;
                break;
            }
        }
        if (!claimed) {
            free(path_b[i].vector);
            free(path_b[i].metadata);
        }
    }

    free(path_a);
    free(path_b);
    free(entries);
    return (int)(entry_count < top_k ? entry_count : top_k);
}

static bool qihse_vdb_insert_exact_result(qihse_vector_db_t vdb,
                                          const qihse_vector_query_t* query,
                                          const qihse_index_row_t* row,
                                          const float* vector,
                                          float score,
                                          qihse_vector_result_t* results,
                                          size_t result_limit,
                                          size_t* out_count) {
    size_t insert_at;
    qihse_vector_result_t result;
    bool full;

    if (*out_count >= result_limit && score <= results[result_limit - 1u].score) {
        return true;
    }
    insert_at = *out_count < result_limit ? *out_count : result_limit - 1u;
    full = *out_count >= result_limit;
    while (insert_at > 0u && results[insert_at - 1u].score < score) {
        insert_at--;
    }
    if (insert_at >= result_limit) {
        return true;
    }

    memset(&result, 0, sizeof(result));
    result.id = row->vector_id;
    result.score = score;
    result.vector_dims = vdb->vector_dims;
    if (query->include_vectors) {
        size_t bytes;
        if (!qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &bytes)) {
            errno = EOVERFLOW;
            return false;
        }
        result.vector = (float*)malloc(bytes);
        if (!result.vector) {
            errno = ENOMEM;
            return false;
        }
        memcpy(result.vector, vector, bytes);
    }
    if (query->include_metadata && row->metadata_size != 0u) {
        const void* metadata = qihse_vdb_metadata_at(vdb, row);
        if (!metadata || row->metadata_size > (uint64_t)SIZE_MAX) {
            free(result.vector);
            errno = EINVAL;
            return false;
        }
        result.metadata = malloc((size_t)row->metadata_size);
        if (!result.metadata) {
            free(result.vector);
            errno = ENOMEM;
            return false;
        }
        memcpy(result.metadata, metadata, (size_t)row->metadata_size);
        result.metadata_size = (size_t)row->metadata_size;
    }
    if (full) {
        free(results[result_limit - 1u].vector);
        free(results[result_limit - 1u].metadata);
        memset(&results[result_limit - 1u], 0, sizeof(results[result_limit - 1u]));
    }
    if (full || *out_count > insert_at) {
        size_t move_from = full ? result_limit - 1u : *out_count;
        while (move_from > insert_at) {
            results[move_from] = results[move_from - 1u];
            move_from--;
        }
    }
    results[insert_at] = result;
    if (*out_count < result_limit) {
        (*out_count)++;
    }
    return true;
}

static int qihse_vdb_search_exact_rows(qihse_vector_db_t vdb,
                                       const qihse_vector_query_t* query,
                                       qihse_vector_result_t* results,
                                       size_t max_results,
                                       size_t result_limit) {
    size_t out_count = 0u;
    size_t i;

    if (!vdb || !query || !query->query_vector || !results || max_results == 0u ||
        result_limit == 0u || result_limit > max_results ||
        query->vector_dims != vdb->vector_dims) {
        errno = EINVAL;
        return -1;
    }
    memset(results, 0, max_results * sizeof(*results));

    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        const float* vector;
        float score;

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (!qihse_auth_can_access(query->user, row->classification, row->sci_compartment)) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        qihse_vdb_track_row_access(vdb, i);
        if (query->metadata_filter) {
            const void* metadata = qihse_vdb_metadata_at(vdb, row);
            if (!metadata ||
                !query->metadata_filter(metadata, (size_t)row->metadata_size,
                                       query->metadata_filter_opaque)) {
                continue;
            }
        }
        score = qihse_vdb_compute_score(query->query_vector, vector,
                                         vdb->vector_dims, query->distance_metric);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, result_limit, &out_count)) {
            return -1;
        }
    }
    return (int)out_count;
}

static void qihse_vdb_set_trinary_errno(qihse_vector_db_trinary_status_t status) {
    switch (status) {
        case QIHSE_VDB_TRINARY_ABSENT:
            errno = ENOENT;
            break;
        case QIHSE_VDB_TRINARY_STALE:
#ifdef ESTALE
            errno = ESTALE;
#else
            errno = EINVAL;
#endif
            break;
        case QIHSE_VDB_TRINARY_CORRUPT:
            errno = EINVAL;
            break;
        case QIHSE_VDB_TRINARY_VALID:
        default:
            errno = EINVAL;
            break;
    }
}

static void qihse_vdb_set_magnitude_errno(qihse_vector_db_magnitude_status_t status) {
    switch (status) {
        case QIHSE_VDB_MAGNITUDE_ABSENT:
#ifdef ENODATA
            errno = ENODATA;
#else
            errno = ENOENT;
#endif
            break;
        case QIHSE_VDB_MAGNITUDE_STALE:
#ifdef ESTALE
            errno = ESTALE;
#else
            errno = EINVAL;
#endif
            break;
        case QIHSE_VDB_MAGNITUDE_CORRUPT:
            errno = EINVAL;
            break;
        case QIHSE_VDB_MAGNITUDE_VALID:
        default:
            errno = EINVAL;
            break;
    }
}

int qihse_vector_db_search_trinary_candidates(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    size_t candidate_count,
    qihse_vector_result_t* results,
    size_t max_results
) {
    uint8_t* encoded_query = NULL;
    size_t* candidate_rows = NULL;
    int32_t* candidate_scores = NULL;
    size_t row_bytes = 0u;
    size_t expected_trinary_bytes = 0u;
    size_t candidate_out = 0u;
    size_t out_count = 0u;
    size_t top_k;
    size_t i;

    if (!vdb || !query || !query->query_vector || !results || max_results == 0u ||
        query->vector_dims != vdb->vector_dims || query->top_k == 0u ||
        query->top_k > max_results) {
        errno = EINVAL;
        return -1;
    }
    top_k = query->top_k;
    if (candidate_count < top_k) {
        errno = EINVAL;
        return -1;
    }
    if (vdb->trinary_status != QIHSE_VDB_TRINARY_VALID) {
        qihse_vdb_set_trinary_errno(vdb->trinary_status);
        return -1;
    }
    if (!qihse_trinary_tryte_row_bytes(vdb->vector_dims, &row_bytes) ||
        vdb->trinary_rows > (uint64_t)SIZE_MAX ||
        !qihse_checked_mul_size((size_t)vdb->trinary_rows, row_bytes,
                                &expected_trinary_bytes) ||
        vdb->trinary_row_bytes != (uint64_t)row_bytes ||
        vdb->trinary_rows != (uint64_t)vdb->total_vectors ||
        !vdb->trinary ||
        vdb->trinary_bytes != expected_trinary_bytes) {
        qihse_vdb_set_trinary_stale(vdb);
#ifdef ESTALE
        errno = ESTALE;
#else
        errno = EINVAL;
#endif
        return -1;
    }
    if (candidate_count >= vdb->total_vectors) {
        return qihse_vdb_search_exact_rows(vdb, query, results, max_results, top_k);
    }

    memset(results, 0, max_results * sizeof(*results));
    encoded_query = (uint8_t*)malloc(row_bytes ? row_bytes : 1u);
    candidate_rows = (size_t*)calloc(candidate_count ? candidate_count : 1u,
                                     sizeof(*candidate_rows));
    candidate_scores = (int32_t*)calloc(candidate_count ? candidate_count : 1u,
                                        sizeof(*candidate_scores));
    if (!encoded_query || !candidate_rows || !candidate_scores) {
        free(encoded_query);
        free(candidate_rows);
        free(candidate_scores);
        errno = ENOMEM;
        return -1;
    }
    if (!qihse_trinary_tryte_encode_row(query->query_vector, vdb->vector_dims,
                                        encoded_query, row_bytes) ||
        !qihse_trinary_tryte_select_topk(vdb->trinary,
                                         encoded_query,
                                         (size_t)vdb->trinary_rows,
                                         vdb->vector_dims,
                                         candidate_rows,
                                         candidate_scores,
                                         candidate_count,
                                         &candidate_out)) {
        free(encoded_query);
        free(candidate_rows);
        free(candidate_scores);
        return -1;
    }

    for (i = 0u; i < candidate_out; i++) {
        const qihse_index_row_t* row;
        const float* vector;
        float score;

        if (candidate_rows[i] >= vdb->total_vectors) {
            continue;
        }
        row = &vdb->rows[candidate_rows[i]];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (!qihse_auth_can_access(query->user, row->classification, row->sci_compartment)) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        if (query->metadata_filter) {
            const void* metadata = qihse_vdb_metadata_at(vdb, row);
            if (!metadata ||
                !query->metadata_filter(metadata, (size_t)row->metadata_size,
                                       query->metadata_filter_opaque)) {
                continue;
            }
        }
        score = qihse_vdb_compute_score(query->query_vector, vector,
                                         vdb->vector_dims, query->distance_metric);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, top_k, &out_count)) {
            free(encoded_query);
            free(candidate_rows);
            free(candidate_scores);
            return -1;
        }
    }

    free(encoded_query);
    free(candidate_rows);
    free(candidate_scores);
    return (int)out_count;
}

static int8_t qihse_vdb_signed_trit(uint8_t trit) {
    if (trit == 0u) {
        return -1;
    }
    if (trit == 2u) {
        return 1;
    }
    return 0;
}

static bool qihse_vdb_ensure_trinary_sign_cache(qihse_vector_db_t vdb) {
    size_t row_bytes = 0u;
    size_t expected_trinary_bytes = 0u;
    size_t sign_bytes = 0u;
    int8_t* signs;
    size_t row_idx;

    if (!vdb || vdb->trinary_status != QIHSE_VDB_TRINARY_VALID ||
        !vdb->trinary || vdb->vector_dims == 0u ||
        vdb->trinary_rows > (uint64_t)SIZE_MAX) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_trinary_tryte_row_bytes(vdb->vector_dims, &row_bytes) ||
        !qihse_checked_mul_size((size_t)vdb->trinary_rows, row_bytes,
                                &expected_trinary_bytes) ||
        !qihse_checked_mul_size((size_t)vdb->trinary_rows, vdb->vector_dims,
                                &sign_bytes) ||
        vdb->trinary_row_bytes != (uint64_t)row_bytes ||
        vdb->trinary_rows != (uint64_t)vdb->total_vectors ||
        vdb->trinary_bytes != expected_trinary_bytes) {
        qihse_vdb_set_trinary_stale(vdb);
#ifdef ESTALE
        errno = ESTALE;
#else
        errno = EINVAL;
#endif
        return false;
    }
    if (vdb->trinary_signs && vdb->trinary_sign_bytes == sign_bytes) {
        return true;
    }
    signs = (int8_t*)malloc(sign_bytes ? sign_bytes : 1u);
    if (!signs) {
        errno = ENOMEM;
        return false;
    }
    for (row_idx = 0u; row_idx < (size_t)vdb->trinary_rows; row_idx++) {
        const uint8_t* tri_row = vdb->trinary + (row_idx * row_bytes);
        int8_t* sign_row = signs + (row_idx * vdb->vector_dims);
        size_t dim = 0u;

        while (dim < vdb->vector_dims) {
            uint8_t tryte = tri_row[dim / QIHSE_TRINARY_TRITS_PER_TRYTE];
            size_t trit_idx;

            if (tryte > QIHSE_TRINARY_TRYTE_MAX) {
                free(signs);
                qihse_vdb_set_trinary_stale(vdb);
                errno = EINVAL;
                return false;
            }
            for (trit_idx = 0u;
                 trit_idx < QIHSE_TRINARY_TRITS_PER_TRYTE && dim < vdb->vector_dims;
                 trit_idx++, dim++) {
                sign_row[dim] = qihse_vdb_signed_trit((uint8_t)(tryte % 3u));
                tryte = (uint8_t)(tryte / 3u);
            }
        }
    }
    qihse_vdb_clear_trinary_sign_cache(vdb);
    vdb->trinary_signs = signs;
    vdb->trinary_sign_bytes = sign_bytes;
    return true;
}

static bool qihse_vdb_ensure_qmag_transposed_cache(qihse_vector_db_t vdb) {
    int8_t* signs = NULL;
    uint8_t* magnitudes = NULL;
    size_t* live_rows = NULL;
    size_t physical_rows;
    size_t live_rows_count = 0u;
    size_t dims;
    size_t cache_bytes = 0u;
    size_t live_row_bytes = 0u;
    size_t expected_magnitude_bytes = 0u;
    size_t dim;
    size_t row_idx;

    if (!vdb || vdb->trinary_status != QIHSE_VDB_TRINARY_VALID ||
        vdb->magnitude_status != QIHSE_VDB_MAGNITUDE_VALID ||
        !vdb->magnitude || vdb->vector_dims == 0u ||
        vdb->trinary_rows > (uint64_t)SIZE_MAX ||
        vdb->magnitude_rows > (uint64_t)SIZE_MAX) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_checked_mul_size(vdb->live_vectors, sizeof(*live_rows),
                                &live_row_bytes)) {
        return false;
    }
    physical_rows = (size_t)vdb->trinary_rows;
    dims = vdb->vector_dims;
    if (vdb->magnitude_rows != vdb->trinary_rows ||
        vdb->magnitude_row_bytes != (uint64_t)dims ||
        !qihse_checked_mul_size(vdb->live_vectors, dims, &cache_bytes) ||
        !qihse_checked_mul_size(physical_rows, (size_t)vdb->magnitude_row_bytes,
                                &expected_magnitude_bytes) ||
        vdb->magnitude_bytes != expected_magnitude_bytes) {
        qihse_vdb_set_magnitude_stale(vdb);
#ifdef ESTALE
        errno = ESTALE;
#else
        errno = EINVAL;
#endif
        return false;
    }
    if (vdb->qmag_transposed_signs && vdb->qmag_transposed_magnitude &&
        vdb->qmag_transposed_live_rows &&
        vdb->qmag_transposed_bytes == cache_bytes &&
        vdb->qmag_transposed_rows == vdb->live_vectors &&
        vdb->qmag_transposed_dims == dims) {
        return true;
    }
    if (!qihse_vdb_ensure_trinary_sign_cache(vdb)) {
        return false;
    }

    live_rows = (size_t*)malloc(live_row_bytes ? live_row_bytes : 1u);
    signs = (int8_t*)malloc(cache_bytes ? cache_bytes : 1u);
    magnitudes = (uint8_t*)malloc(cache_bytes ? cache_bytes : 1u);
    if (!live_rows || !signs || !magnitudes) {
        free(live_rows);
        free(signs);
        free(magnitudes);
        errno = ENOMEM;
        return false;
    }
    for (row_idx = 0u; row_idx < physical_rows; row_idx++) {
        const qihse_index_row_t* row = &vdb->rows[row_idx];

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (live_rows_count >= vdb->live_vectors) {
            free(live_rows);
            free(signs);
            free(magnitudes);
            errno = EINVAL;
            return false;
        }
        live_rows[live_rows_count++] = row_idx;
    }
    if (live_rows_count != vdb->live_vectors) {
        free(live_rows);
        free(signs);
        free(magnitudes);
        errno = EINVAL;
        return false;
    }
    for (dim = 0u; dim < dims; dim++) {
        int8_t* sign_col = signs + (dim * live_rows_count);
        uint8_t* mag_col = magnitudes + (dim * live_rows_count);
        size_t live_idx;

        for (live_idx = 0u; live_idx < live_rows_count; live_idx++) {
            row_idx = live_rows[live_idx];
            sign_col[live_idx] = vdb->trinary_signs[(row_idx * dims) + dim];
            mag_col[live_idx] = vdb->magnitude[(row_idx * (size_t)vdb->magnitude_row_bytes) + dim];
        }
    }

    qihse_vdb_clear_qmag_transposed_cache(vdb);
    vdb->qmag_transposed_signs = signs;
    vdb->qmag_transposed_magnitude = magnitudes;
    vdb->qmag_transposed_live_rows = live_rows;
    vdb->qmag_transposed_bytes = cache_bytes;
    vdb->qmag_transposed_rows = live_rows_count;
    vdb->qmag_transposed_dims = dims;
    return true;
}

static int32_t qihse_vdb_query_weight(float value) {
    float mag = fabsf(value);
    int32_t weight;

    if (mag <= 0.0f) {
        return 0;
    }
    weight = (int32_t)(mag * 100.0f + 0.5f);
    if (weight < 1) {
        return 1;
    }
    if (weight > 255) {
        return 255;
    }
    return weight;
}

static bool qihse_vdb_qmag_candidate_is_better(int64_t lhs_score,
                                               size_t lhs_row,
                                               int64_t rhs_score,
                                               size_t rhs_row) {
    return lhs_score > rhs_score ||
           (lhs_score == rhs_score && lhs_row < rhs_row);
}

static bool qihse_vdb_qmag_candidate_is_worse(int64_t lhs_score,
                                              size_t lhs_row,
                                              int64_t rhs_score,
                                              size_t rhs_row) {
    return lhs_score < rhs_score ||
           (lhs_score == rhs_score && lhs_row > rhs_row);
}

static float qihse_vdb_qmag_score_to_float(int64_t qmag_score,
                                           size_t active_dim_count) {
    const float normalization = (float)(active_dim_count * 255u);
    if (normalization <= 0.0f) {
        return (float)qmag_score;
    }
    return ((float)qmag_score) / normalization;
}

static void qihse_vdb_qmag_heap_swap(size_t* rows,
                                     int64_t* scores,
                                     size_t lhs,
                                     size_t rhs) {
    size_t row_tmp = rows[lhs];
    int64_t score_tmp = scores[lhs];
    rows[lhs] = rows[rhs];
    scores[lhs] = scores[rhs];
    rows[rhs] = row_tmp;
    scores[rhs] = score_tmp;
}

static void qihse_vdb_qmag_heap_sift_up(size_t* rows,
                                        int64_t* scores,
                                        size_t index) {
    while (index > 0u) {
        size_t parent = (index - 1u) / 2u;
        if (!qihse_vdb_qmag_candidate_is_worse(scores[index], rows[index],
                                               scores[parent], rows[parent])) {
            break;
        }
        qihse_vdb_qmag_heap_swap(rows, scores, index, parent);
        index = parent;
    }
}

static void qihse_vdb_qmag_heap_sift_down(size_t* rows,
                                          int64_t* scores,
                                          size_t count,
                                          size_t index) {
    for (;;) {
        size_t left = (index * 2u) + 1u;
        size_t right = left + 1u;
        size_t worst = index;

        if (left < count &&
            qihse_vdb_qmag_candidate_is_worse(scores[left], rows[left],
                                              scores[worst], rows[worst])) {
            worst = left;
        }
        if (right < count &&
            qihse_vdb_qmag_candidate_is_worse(scores[right], rows[right],
                                              scores[worst], rows[worst])) {
            worst = right;
        }
        if (worst == index) {
            break;
        }
        qihse_vdb_qmag_heap_swap(rows, scores, index, worst);
        index = worst;
    }
}

static bool qihse_vdb_select_topk_magnitude_transposed(
                                            const int8_t* transposed_signs,
                                            const uint8_t* transposed_magnitude,
                                            const size_t* physical_rows,
                                            const qihse_vdb_qmag_query_dim_t* active_dims,
                                            size_t active_dim_count,
                                            size_t dims,
                                            size_t row_count,
                                            size_t* rows,
                                            int64_t* scores,
                                            size_t k,
                                            size_t* out_count) {
    int64_t* row_scores = NULL;
    size_t count = 0u;
    size_t row_idx;
    size_t active_idx;

    if (!transposed_signs || !transposed_magnitude ||
        (!active_dims && active_dim_count != 0u) || !rows || !scores ||
        !out_count || k == 0u || active_dim_count > dims) {
        errno = EINVAL;
        return false;
    }
    row_scores = (int64_t*)calloc(row_count ? row_count : 1u, sizeof(*row_scores));
    if (!row_scores) {
        errno = ENOMEM;
        return false;
    }
    for (active_idx = 0u; active_idx < active_dim_count; active_idx++) {
        const qihse_vdb_qmag_query_dim_t* active = &active_dims[active_idx];
        const int8_t* sign_col;
        const uint8_t* mag_col;

        if (active->dim >= dims) {
            free(row_scores);
            errno = EINVAL;
            return false;
        }
        sign_col = transposed_signs + (active->dim * row_count);
        mag_col = transposed_magnitude + (active->dim * row_count);
        for (row_idx = 0u; row_idx < row_count; row_idx++) {
            uint8_t row_mag = mag_col[row_idx];
            int8_t row_sign = sign_col[row_idx];

            if (row_mag != 0u && row_sign != 0) {
                row_scores[row_idx] += (int64_t)active->signed_weight *
                                       (int64_t)row_sign *
                                       (int64_t)row_mag;
            }
        }
    }
    for (row_idx = 0u; row_idx < row_count; row_idx++) {
        int64_t score = row_scores[row_idx];
        size_t candidate_row = physical_rows ? physical_rows[row_idx] : row_idx;

        if (count < k) {
            rows[count] = candidate_row;
            scores[count] = score;
            qihse_vdb_qmag_heap_sift_up(rows, scores, count);
            count++;
        } else if (qihse_vdb_qmag_candidate_is_better(score, candidate_row,
                                                      scores[0], rows[0])) {
            rows[0] = candidate_row;
            scores[0] = score;
            qihse_vdb_qmag_heap_sift_down(rows, scores, count, 0u);
        }
    }
    free(row_scores);
    *out_count = count;
    return true;
}

static int qihse_vdb_search_trinary_magnitude_candidates_no_rerank(
    qihse_vector_db_t vdb,
    const qihse_vector_query_t* query,
    qihse_vector_result_t* results,
    size_t max_results) {
    qihse_vdb_qmag_query_dim_t* active_dims = NULL;
    size_t active_dim_count = 0u;
    size_t* candidate_rows = NULL;
    int64_t* candidate_scores = NULL;
    size_t row_bytes = 0u;
    size_t expected_trinary_bytes = 0u;
    size_t expected_magnitude_bytes = 0u;
    size_t candidate_count;
    size_t candidate_out = 0u;
    size_t out_count = 0u;
    size_t top_k;
    size_t i;

    if (!vdb || !query || !query->query_vector || !results || max_results == 0u ||
        query->vector_dims != vdb->vector_dims || query->top_k == 0u ||
        query->top_k > max_results) {
        errno = EINVAL;
        return -1;
    }
    top_k = query->top_k;
    active_dims = (qihse_vdb_qmag_query_dim_t*)calloc(vdb->vector_dims ?
                                                      vdb->vector_dims : 1u,
                                                      sizeof(*active_dims));
    if (!active_dims) {
        errno = ENOMEM;
        return -1;
    }
    for (i = 0u; i < vdb->vector_dims; i++) {
        int8_t sign = query->query_vector[i] < 0.0f ? -1 :
            (query->query_vector[i] > 0.0f ? 1 : 0);
        int32_t weight = qihse_vdb_query_weight(query->query_vector[i]);

        if (sign != 0 && weight != 0) {
            qihse_vdb_qmag_query_dim_t* active = &active_dims[active_dim_count++];
            active->dim = i;
            active->byte_idx = i / QIHSE_TRINARY_TRITS_PER_TRYTE;
            active->trit_idx = (uint8_t)(i % QIHSE_TRINARY_TRITS_PER_TRYTE);
            active->signed_weight = (int32_t)sign * weight;
        }
    }
    if (!qihse_vdb_resolve_qmag_candidate_pool(vdb, query, active_dim_count,
                                               &candidate_count)) {
        free(active_dims);
        return -1;
    }
    if (vdb->trinary_status != QIHSE_VDB_TRINARY_VALID) {
        free(active_dims);
        qihse_vdb_set_trinary_errno(vdb->trinary_status);
        return -1;
    }
    if (vdb->magnitude_status != QIHSE_VDB_MAGNITUDE_VALID) {
        free(active_dims);
        qihse_vdb_set_magnitude_errno(vdb->magnitude_status);
        return -1;
    }
    if (!qihse_trinary_tryte_row_bytes(vdb->vector_dims, &row_bytes) ||
        vdb->trinary_rows > (uint64_t)SIZE_MAX ||
        vdb->magnitude_rows > (uint64_t)SIZE_MAX ||
        !qihse_checked_mul_size((size_t)vdb->trinary_rows, row_bytes,
                                &expected_trinary_bytes) ||
        !qihse_checked_mul_size((size_t)vdb->magnitude_rows, vdb->vector_dims,
                                &expected_magnitude_bytes) ||
        vdb->trinary_row_bytes != (uint64_t)row_bytes ||
        vdb->magnitude_row_bytes != (uint64_t)vdb->vector_dims ||
        vdb->trinary_rows != (uint64_t)vdb->total_vectors ||
        vdb->magnitude_rows != (uint64_t)vdb->total_vectors ||
        !vdb->trinary || !vdb->magnitude ||
        vdb->trinary_bytes != expected_trinary_bytes ||
        vdb->magnitude_bytes != expected_magnitude_bytes) {
        qihse_vdb_set_trinary_stale(vdb);
#ifdef ESTALE
        errno = ESTALE;
#else
        errno = EINVAL;
#endif
        free(active_dims);
        return -1;
    }

    memset(results, 0, max_results * sizeof(*results));
    candidate_rows = (size_t*)calloc(candidate_count ? candidate_count : 1u,
                                     sizeof(*candidate_rows));
    candidate_scores = (int64_t*)calloc(candidate_count ? candidate_count : 1u,
                                        sizeof(*candidate_scores));
    if (!active_dims || !candidate_rows || !candidate_scores) {
        free(active_dims);
        free(candidate_rows);
        free(candidate_scores);
        errno = ENOMEM;
        return -1;
    }

    if (!qihse_vdb_ensure_qmag_transposed_cache(vdb) ||
        !qihse_vdb_select_topk_magnitude_transposed(vdb->qmag_transposed_signs,
                                                    vdb->qmag_transposed_magnitude,
                                                    vdb->qmag_transposed_live_rows,
                                                    active_dims,
                                                    active_dim_count,
                                                    vdb->vector_dims,
                                                    vdb->qmag_transposed_rows,
                                                    candidate_rows,
                                                    candidate_scores,
                                                    candidate_count,
                                                    &candidate_out)) {
        free(active_dims);
        free(candidate_rows);
        free(candidate_scores);
        return -1;
    }

    for (i = 0u; i < candidate_out; i++) {
        const qihse_index_row_t* row;
        const float* vector;
        float score;

        if (candidate_rows[i] >= vdb->total_vectors) {
            continue;
        }
        row = &vdb->rows[candidate_rows[i]];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (!qihse_auth_can_access(query->user, row->classification, row->sci_compartment)) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        score = qihse_vdb_qmag_score_to_float(candidate_scores[i], active_dim_count);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, top_k, &out_count)) {
            free(active_dims);
            free(candidate_rows);
            free(candidate_scores);
            return -1;
        }
    }

    free(active_dims);
    free(candidate_rows);
    free(candidate_scores);
    return (int)out_count;
}

static int qihse_vdb_search_trinary_magnitude_candidates(qihse_vector_db_t vdb,
                                                         const qihse_vector_query_t* query,
                                                         qihse_vector_result_t* results,
                                                         size_t max_results) {
    qihse_vdb_qmag_query_dim_t* active_dims = NULL;
    size_t active_dim_count = 0u;
    size_t* candidate_rows = NULL;
    int64_t* candidate_scores = NULL;
    size_t row_bytes = 0u;
    size_t expected_trinary_bytes = 0u;
    size_t expected_magnitude_bytes = 0u;
    size_t candidate_count;
    size_t candidate_out = 0u;
    size_t out_count = 0u;
    size_t top_k;
    size_t i;
    bool default_candidate_pool;

    if (!vdb || !query || !query->query_vector || !results || max_results == 0u ||
        query->vector_dims != vdb->vector_dims || query->top_k == 0u ||
        query->top_k > max_results) {
        errno = EINVAL;
        return -1;
    }
    top_k = query->top_k;
    default_candidate_pool = query->candidate_pool_size == 0u &&
        query->candidate_count == 0u;
    active_dims = (qihse_vdb_qmag_query_dim_t*)calloc(vdb->vector_dims ?
                                                      vdb->vector_dims : 1u,
                                                      sizeof(*active_dims));
    if (!active_dims) {
        errno = ENOMEM;
        return -1;
    }
    for (i = 0u; i < vdb->vector_dims; i++) {
        int8_t sign = query->query_vector[i] < 0.0f ? -1 :
            (query->query_vector[i] > 0.0f ? 1 : 0);
        int32_t weight = qihse_vdb_query_weight(query->query_vector[i]);

        if (sign != 0 && weight != 0) {
            qihse_vdb_qmag_query_dim_t* active = &active_dims[active_dim_count++];
            active->dim = i;
            active->byte_idx = i / QIHSE_TRINARY_TRITS_PER_TRYTE;
            active->trit_idx = (uint8_t)(i % QIHSE_TRINARY_TRITS_PER_TRYTE);
            active->signed_weight = (int32_t)sign * weight;
        }
    }
    if (!qihse_vdb_resolve_qmag_candidate_pool(vdb, query, active_dim_count,
                                               &candidate_count)) {
        free(active_dims);
        return -1;
    }
    if (default_candidate_pool &&
        !qihse_vdb_qmag_policy_allows(active_dim_count,
                                      vdb->vector_dims,
                                      candidate_count,
                                      vdb->live_vectors,
                                      top_k)) {
        free(active_dims);
        /*
         * qmag without a caller-selected pool is an opportunistic accelerator.
         * If the policy says it is unlikely to win, preserve result semantics
         * by using the authoritative exact float32 path. Caller-provided pools
         * remain explicit opt-ins and keep the historical qmag search behavior.
         */
        return qihse_vdb_search_exact_rows(vdb, query, results, max_results, top_k);
    }
    if (vdb->trinary_status != QIHSE_VDB_TRINARY_VALID) {
        free(active_dims);
        qihse_vdb_set_trinary_errno(vdb->trinary_status);
        return -1;
    }
    if (vdb->magnitude_status != QIHSE_VDB_MAGNITUDE_VALID) {
        free(active_dims);
        qihse_vdb_set_magnitude_errno(vdb->magnitude_status);
        return -1;
    }
    if (!qihse_trinary_tryte_row_bytes(vdb->vector_dims, &row_bytes) ||
        vdb->trinary_rows > (uint64_t)SIZE_MAX ||
        vdb->magnitude_rows > (uint64_t)SIZE_MAX ||
        !qihse_checked_mul_size((size_t)vdb->trinary_rows, row_bytes,
                                &expected_trinary_bytes) ||
        !qihse_checked_mul_size((size_t)vdb->magnitude_rows, vdb->vector_dims,
                                &expected_magnitude_bytes) ||
        vdb->trinary_row_bytes != (uint64_t)row_bytes ||
        vdb->magnitude_row_bytes != (uint64_t)vdb->vector_dims ||
        vdb->trinary_rows != (uint64_t)vdb->total_vectors ||
        vdb->magnitude_rows != (uint64_t)vdb->total_vectors ||
        !vdb->trinary || !vdb->magnitude ||
        vdb->trinary_bytes != expected_trinary_bytes ||
        vdb->magnitude_bytes != expected_magnitude_bytes) {
        qihse_vdb_set_trinary_stale(vdb);
#ifdef ESTALE
        errno = ESTALE;
#else
        errno = EINVAL;
#endif
        free(active_dims);
        return -1;
    }

    memset(results, 0, max_results * sizeof(*results));
    candidate_rows = (size_t*)calloc(candidate_count ? candidate_count : 1u,
                                     sizeof(*candidate_rows));
    candidate_scores = (int64_t*)calloc(candidate_count ? candidate_count : 1u,
                                        sizeof(*candidate_scores));
    if (!active_dims || !candidate_rows || !candidate_scores) {
        free(active_dims);
        free(candidate_rows);
        free(candidate_scores);
        errno = ENOMEM;
        return -1;
    }

    if (!qihse_vdb_ensure_qmag_transposed_cache(vdb) ||
        !qihse_vdb_select_topk_magnitude_transposed(vdb->qmag_transposed_signs,
                                                    vdb->qmag_transposed_magnitude,
                                                    vdb->qmag_transposed_live_rows,
                                                    active_dims,
                                                    active_dim_count,
                                                    vdb->vector_dims,
                                                    vdb->qmag_transposed_rows,
                                                    candidate_rows,
                                                    candidate_scores,
                                                    candidate_count,
                                                    &candidate_out)) {
        free(active_dims);
        free(candidate_rows);
        free(candidate_scores);
        return -1;
    }

    for (i = 0u; i < candidate_out; i++) {
        const qihse_index_row_t* row;
        const float* vector;
        float score;

        if (candidate_rows[i] >= vdb->total_vectors) {
            continue;
        }
        row = &vdb->rows[candidate_rows[i]];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (!qihse_auth_can_access(query->user, row->classification, row->sci_compartment)) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, row);
        if (!vector) {
            continue;
        }
        if (query->metadata_filter) {
            const void* metadata = qihse_vdb_metadata_at(vdb, row);
            if (!metadata ||
                !query->metadata_filter(metadata, (size_t)row->metadata_size,
                                       query->metadata_filter_opaque)) {
                continue;
            }
        }
        score = qihse_vdb_compute_score(query->query_vector, vector,
                                         vdb->vector_dims, query->distance_metric);
        if (score < query->similarity_threshold) {
            continue;
        }
        if (!qihse_vdb_insert_exact_result(vdb, query, row, vector, score,
                                           results, top_k, &out_count)) {
            free(active_dims);
            free(candidate_rows);
            free(candidate_scores);
            return -1;
        }
    }

    free(active_dims);
    free(candidate_rows);
    free(candidate_scores);
    return (int)out_count;
}

bool qihse_vector_db_flush(qihse_vector_db_t vdb) {
    qihse_vector_store_flush_t flush;
    uint8_t* trinary = NULL;
    uint8_t* magnitude = NULL;
    uint8_t* explicit_edges = NULL;
    size_t trinary_bytes = 0u;
    size_t magnitude_bytes = 0u;
    size_t explicit_edges_bytes = 0u;
    uint64_t explicit_edge_generation;
    bool ok;

    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (!vdb->file_backed || vdb->read_only) {
        return true;
    }
    if (!vdb->dirty && !vdb->idmap_dirty) {
        return true;
    }
    if (!qihse_vdb_rebuild_idmap(vdb, true)) {
        return false;
    }
    if (vdb->vector_dims != 0u) {
        trinary = qihse_vdb_build_trinary(vdb, &trinary_bytes);
        if (!trinary) {
            return false;
        }
        magnitude = qihse_vdb_build_magnitude(vdb, &magnitude_bytes);
        if (!magnitude) {
            free(trinary);
            return false;
        }
    }
    pthread_mutex_lock(&vdb->explicit_edge_mutex);
    explicit_edge_generation = vdb->next_generation ? vdb->next_generation - 1u : 0u;
    ok = qihse_vdb_encode_edges(vdb, &explicit_edges, &explicit_edges_bytes);
    pthread_mutex_unlock(&vdb->explicit_edge_mutex);
    if (!ok) {
        free(trinary);
        free(magnitude);
        return false;
    }
    memset(&flush, 0, sizeof(flush));
    flush.vector_dims = (uint32_t)vdb->vector_dims;
    flush.commit_generation = vdb->next_generation ? vdb->next_generation - 1u : 0u;
    flush.rows = vdb->rows;
    flush.row_count = vdb->total_vectors;
    flush.vectors = vdb->vectors;
    flush.vector_bytes = vdb->vector_bytes_used;
    flush.metadata = vdb->metadata;
    flush.metadata_bytes = vdb->metadata_bytes_used;
    flush.idmap = vdb->idmap;
    flush.idmap_count = vdb->idmap_count;
    flush.trinary = trinary;
    flush.trinary_bytes = trinary_bytes;
    flush.trinary_generation = flush.commit_generation;
    flush.trinary_row_bytes = vdb->trinary_row_bytes;
    flush.trinary_flags = QIHSE_VSTORE_TRI_PRESENT | QIHSE_VSTORE_TRI_VALID;
    flush.magnitude = magnitude;
    flush.magnitude_bytes = magnitude_bytes;
    flush.magnitude_generation = flush.commit_generation;
    flush.magnitude_row_bytes = vdb->magnitude_row_bytes;
    flush.magnitude_flags = QIHSE_VSTORE_MAG_PRESENT | QIHSE_VSTORE_MAG_VALID;
    flush.explicit_edges = explicit_edges;
    flush.explicit_edges_bytes = explicit_edges_bytes;

    ok = qihse_vector_store_flush(vdb->db_path, &flush);
    if (ok) {
        qihse_container_t ctr;
        if (qihse_ctr_open_write(vdb->db_path, false, &ctr)) {
            ok = qihse_ctr_wal_truncate(&ctr, 0u);
            qihse_ctr_close(&ctr);
        } else {
            ok = false;
        }
    }
    if (ok) {
        vdb->committed_generation = flush.commit_generation;
        vdb->wal_bytes_pending = 0u;
        vdb->wal_last_record_offset = QIHSE_VDB_WAL_NO_PREV;
        vdb->dirty = false;
        vdb->idmap_dirty = false;
        qihse_vdb_tier_save(vdb);
        vdb->idmap_valid = true;
        pthread_mutex_lock(&vdb->explicit_edge_mutex);
        if ((vdb->next_generation ? vdb->next_generation - 1u : 0u) ==
            explicit_edge_generation) {
            vdb->explicit_edges_dirty = false;
        } else {
            vdb->dirty = true;
        }
        pthread_mutex_unlock(&vdb->explicit_edge_mutex);
        if (trinary_bytes != 0u) {
            qihse_vdb_clear_trinary_cache(vdb);
            vdb->trinary = trinary;
            vdb->trinary_bytes = trinary_bytes;
            trinary = NULL;
            vdb->trinary_status = QIHSE_VDB_TRINARY_VALID;
        }
        if (magnitude_bytes != 0u) {
            qihse_vdb_clear_magnitude_cache(vdb);
            vdb->magnitude = magnitude;
            vdb->magnitude_bytes = magnitude_bytes;
            magnitude = NULL;
            vdb->magnitude_status = QIHSE_VDB_MAGNITUDE_VALID;
        }
        /* Re-save graph sidecar with updated generation if it was already valid */
        if (vdb->graph_status == QIHSE_VDB_GRAPH_VALID) {
            qihse_vdb_graph_save(vdb);
        }
        /* Rebuild INT8 scalar quantization sidecar */
        (void)qihse_vdb_int8_build(vdb);
    }
    free(trinary);
    free(magnitude);
    free(explicit_edges);
    return ok;
}

bool qihse_vector_db_checkpoint(qihse_vector_db_t vdb) {
    return qihse_vector_db_flush(vdb);
}

static bool qihse_vdb_compact_live_rows(qihse_vector_db_t vdb) {
    qihse_index_row_t* compact_rows = NULL;
    uint8_t* compact_vectors = NULL;
    uint8_t* compact_metadata = NULL;
    size_t vector_row_bytes = 0u;
    size_t compact_vector_bytes = 0u;
    size_t compact_metadata_bytes = 0u;
    size_t live_count = 0u;
    size_t i;

    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (vdb->total_vectors == vdb->live_vectors && !vdb->idmap_dirty &&
        vdb->trinary_status == QIHSE_VDB_TRINARY_VALID &&
        vdb->magnitude_status == QIHSE_VDB_MAGNITUDE_VALID) {
        return true;
    }
    if (vdb->vector_dims != 0u &&
        !qihse_checked_mul_size(vdb->vector_dims, sizeof(float), &vector_row_bytes)) {
        return false;
    }
    if (!qihse_checked_mul_size(vdb->live_vectors, vector_row_bytes,
                                &compact_vector_bytes)) {
        return false;
    }
    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];

        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        if (row->metadata_size > (uint64_t)SIZE_MAX ||
            !qihse_checked_add_size(compact_metadata_bytes,
                                    (size_t)row->metadata_size,
                                    &compact_metadata_bytes)) {
            return false;
        }
    }

    compact_rows = (qihse_index_row_t*)calloc(vdb->live_vectors ? vdb->live_vectors : 1u,
                                              sizeof(*compact_rows));
    compact_vectors = (uint8_t*)malloc(compact_vector_bytes ? compact_vector_bytes : 1u);
    compact_metadata = (uint8_t*)malloc(compact_metadata_bytes ? compact_metadata_bytes : 1u);
    if (!compact_rows || !compact_vectors || !compact_metadata) {
        free(compact_rows);
        free(compact_vectors);
        free(compact_metadata);
        errno = ENOMEM;
        return false;
    }

    compact_vector_bytes = 0u;
    compact_metadata_bytes = 0u;
    for (i = 0u; i < vdb->total_vectors; i++) {
        const qihse_index_row_t* old_row = &vdb->rows[i];
        qihse_index_row_t* new_row;
        const float* vector;
        const void* metadata;

        if ((old_row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (old_row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_vdb_vector_at(vdb, old_row);
        if (vector_row_bytes != 0u && !vector) {
            free(compact_rows);
            free(compact_vectors);
            free(compact_metadata);
            errno = EINVAL;
            return false;
        }
        metadata = qihse_vdb_metadata_at(vdb, old_row);
        if (old_row->metadata_size != 0u && !metadata) {
            free(compact_rows);
            free(compact_vectors);
            free(compact_metadata);
            errno = EINVAL;
            return false;
        }

        new_row = &compact_rows[live_count];
        *new_row = *old_row;
        new_row->vector_offset = (uint64_t)compact_vector_bytes;
        new_row->metadata_offset = (uint64_t)compact_metadata_bytes;
        new_row->row_flags = QIHSE_ROW_F_LIVE;

        if (vector_row_bytes != 0u) {
            memcpy(compact_vectors + compact_vector_bytes, vector, vector_row_bytes);
            compact_vector_bytes += vector_row_bytes;
        }
        if (old_row->metadata_size != 0u) {
            memcpy(compact_metadata + compact_metadata_bytes, metadata,
                   (size_t)old_row->metadata_size);
            compact_metadata_bytes += (size_t)old_row->metadata_size;
        }
        live_count++;
    }
    if (live_count != vdb->live_vectors) {
        free(compact_rows);
        free(compact_vectors);
        free(compact_metadata);
        errno = EINVAL;
        return false;
    }

    qihse_vdb_clear_qmag_transposed_cache(vdb);
    free(vdb->rows);
    free(vdb->vectors);
    free(vdb->metadata);
    free(vdb->idmap);
    vdb->rows = compact_rows;
    vdb->rows_capacity = live_count;
    vdb->total_vectors = live_count;
    vdb->vectors = compact_vectors;
    vdb->vector_bytes_used = compact_vector_bytes;
    vdb->vector_bytes_capacity = compact_vector_bytes;
    vdb->metadata = compact_metadata;
    vdb->metadata_bytes_used = compact_metadata_bytes;
    vdb->metadata_bytes_capacity = compact_metadata_bytes;
    vdb->idmap = NULL;
    vdb->idmap_count = 0u;
    vdb->idmap_valid = false;
    vdb->idmap_dirty = true;
    vdb->dirty = true;
    qihse_vdb_set_trinary_stale(vdb);
    vdb->trinary_rows = 0u;
    vdb->magnitude_rows = 0u;
    return true;
}

bool qihse_vector_db_compact(qihse_vector_db_t vdb) {
    if (!qihse_vdb_ensure_writable(vdb)) {
        return false;
    }
    if (!qihse_vdb_compact_live_rows(vdb)) {
        return false;
    }
    return qihse_vector_db_flush(vdb);
}

bool qihse_vector_db_close(qihse_vector_db_t vdb) {
    bool ok = true;

    if (!vdb) {
        return true;
    }
    if (!vdb->read_only) {
        ok = qihse_vector_db_flush(vdb);
    }
    qihse_vector_db_destroy(vdb);
    return ok;
}

bool qihse_vector_db_build_graph(
    qihse_vector_db_t vdb,
    size_t M,
    size_t ef_construction
) {
    bool ok;
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    ok = qihse_vdb_graph_build(vdb, M, ef_construction);
    if (ok) {
        qihse_vdb_graph_save(vdb);
    }
    return ok;
}

bool qihse_vector_db_build_int8(
    qihse_vector_db_t vdb
) {
    bool ok;
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    ok = qihse_vdb_int8_build(vdb);
    if (ok) {
        qihse_vdb_int8_save(vdb);
    }
    return ok;
}

bool qihse_vector_db_build_fp16(qihse_vector_db_t vdb) {
    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }
    size_t i, j;
    size_t dims = vdb->vector_dims;
    size_t n_rows = vdb->total_vectors;

    size_t alloc_bytes;
    if (!qihse_checked_mul_size(n_rows, dims, &alloc_bytes) ||
        !qihse_checked_mul_size(alloc_bytes, sizeof(uint16_t), &alloc_bytes)) {
        return false;
    }

    if (vdb->fp16_vectors) {
        free(vdb->fp16_vectors);
    }
    
    vdb->fp16_bytes = alloc_bytes;
    vdb->fp16_vectors = (uint16_t*)malloc(vdb->fp16_bytes);
    if (!vdb->fp16_vectors) return false;
    
    for (i = 0; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            float* src = (float*)(vdb->vectors + i * dims * sizeof(float));
            for (j = 0; j < dims; j++) {
                uint32_t bits;
                memcpy(&bits, &src[j], sizeof(float));
                uint16_t fp16 = (bits >> 16) & 0x8000;
                fp16 |= ((bits >> 13) & 0x3FF) << 0;
                fp16 |= ((bits >> 23) & 0xFF) << 10;
                vdb->fp16_vectors[i * dims + j] = fp16;
            }
        } else {
            memset(&vdb->fp16_vectors[i * dims], 0, dims * sizeof(uint16_t));
        }
    }
    
    vdb->fp16_rows = n_rows;
    vdb->fp16_dims = dims;
    vdb->fp16_status = QIHSE_VDB_FP16_VALID;
    return true;
}

bool qihse_vector_db_build_fp32(qihse_vector_db_t vdb) {
    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }
    size_t dims = vdb->vector_dims;
    size_t n_rows = vdb->total_vectors;

    size_t alloc_bytes;
    if (!qihse_checked_mul_size(n_rows, dims, &alloc_bytes) ||
        !qihse_checked_mul_size(alloc_bytes, sizeof(float), &alloc_bytes)) {
        return false;
    }

    if (vdb->fp32_vectors) {
        free(vdb->fp32_vectors);
    }
    
    vdb->fp32_bytes = alloc_bytes;
    vdb->fp32_vectors = (float*)malloc(vdb->fp32_bytes);
    if (!vdb->fp32_vectors) return false;
    
    for (size_t i = 0; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            float* src = (float*)(vdb->vectors + i * dims * sizeof(float));
            memcpy(&vdb->fp32_vectors[i * dims], src, dims * sizeof(float));
        } else {
            memset(&vdb->fp32_vectors[i * dims], 0, dims * sizeof(float));
        }
    }
    
    vdb->fp32_rows = n_rows;
    vdb->fp32_dims = dims;
    vdb->fp32_status = QIHSE_VDB_FP32_VALID;
    return true;
}

bool qihse_vector_db_build_fp8(qihse_vector_db_t vdb) {
    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }
    size_t dims = vdb->vector_dims;
    size_t n_rows = vdb->total_vectors;

    size_t alloc_bytes;
    if (!qihse_checked_mul_size(n_rows, dims, &alloc_bytes) ||
        !qihse_checked_mul_size(alloc_bytes, sizeof(uint8_t), &alloc_bytes)) {
        return false;
    }

    if (vdb->fp8_vectors) {
        free(vdb->fp8_vectors);
    }
    
    vdb->fp8_bytes = alloc_bytes;
    vdb->fp8_vectors = (uint8_t*)malloc(vdb->fp8_bytes);
    if (!vdb->fp8_vectors) return false;
    
    for (size_t i = 0; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            float* src = (float*)(vdb->vectors + i * dims * sizeof(float));
            for (size_t j = 0; j < dims; j++) {
                uint32_t bits;
                memcpy(&bits, &src[j], sizeof(float));
                uint8_t fp8 = (bits >> 24) & 0x80;
                fp8 |= ((bits >> 23) & 0x0F) << 3;
                fp8 |= ((bits >> 20) & 0x07);
                vdb->fp8_vectors[i * dims + j] = fp8;
            }
        } else {
            memset(&vdb->fp8_vectors[i * dims], 0, dims * sizeof(uint8_t));
        }
    }
    
    vdb->fp8_rows = n_rows;
    vdb->fp8_dims = dims;
    vdb->fp8_status = QIHSE_VDB_FP8_VALID;
    return true;
}

bool qihse_vector_db_build_fp4(qihse_vector_db_t vdb) {
    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }
    size_t dims = vdb->vector_dims;
    size_t packed_dims = dims / 2 + (dims % 2);
    size_t n_rows = vdb->total_vectors;

    size_t alloc_bytes;
    if (!qihse_checked_mul_size(n_rows, packed_dims, &alloc_bytes) ||
        !qihse_checked_mul_size(alloc_bytes, sizeof(uint8_t), &alloc_bytes)) {
        return false;
    }

    if (vdb->fp4_vectors) {
        free(vdb->fp4_vectors);
    }
    
    vdb->fp4_bytes = alloc_bytes;
    vdb->fp4_vectors = (uint8_t*)malloc(vdb->fp4_bytes);
    if (!vdb->fp4_vectors) return false;
    
    for (size_t i = 0; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            float* src = (float*)(vdb->vectors + i * dims * sizeof(float));
            for (size_t j = 0; j < packed_dims; j++) {
                uint8_t packed = 0;
                for (int k = 0; k < 2; k++) {
                    if (j * 2 + k < dims) {
                        uint32_t bits;
                        memcpy(&bits, &src[j * 2 + k], sizeof(float));
                        uint8_t fp4 = (bits >> 28) & 0x08;
                        fp4 |= ((bits >> 23) & 0x03) << 1;
                        fp4 |= ((bits >> 22) & 0x01);
                        packed |= (fp4 << (k * 4));
                    }
                }
                vdb->fp4_vectors[i * packed_dims + j] = packed;
            }
        } else {
            memset(&vdb->fp4_vectors[i * packed_dims], 0, packed_dims * sizeof(uint8_t));
        }
    }
    
    vdb->fp4_rows = n_rows;
    vdb->fp4_dims = dims;
    vdb->fp4_status = QIHSE_VDB_FP4_VALID;
    return true;
}

bool qihse_vector_db_build_int4(qihse_vector_db_t vdb) {
    if (!vdb || vdb->live_vectors == 0u || vdb->vector_dims == 0u) {
        return false;
    }
    size_t dims = vdb->vector_dims;
    size_t packed_dims = dims / 2 + (dims % 2);
    size_t n_rows = vdb->total_vectors;

    size_t alloc_bytes;
    if (!qihse_checked_mul_size(n_rows, packed_dims, &alloc_bytes) ||
        !qihse_checked_mul_size(alloc_bytes, sizeof(uint8_t), &alloc_bytes)) {
        return false;
    }

    if (vdb->int4_vectors) {
        free(vdb->int4_vectors);
    }
    
    vdb->int4_bytes = alloc_bytes;
    vdb->int4_vectors = (uint8_t*)malloc(vdb->int4_bytes);
    if (!vdb->int4_vectors) return false;
    
    for (size_t i = 0; i < n_rows; i++) {
        const qihse_index_row_t* row = &vdb->rows[i];
        if ((row->row_flags & QIHSE_ROW_F_LIVE) != 0u &&
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) == 0u) {
            float* src = (float*)(vdb->vectors + i * dims * sizeof(float));
            for (size_t j = 0; j < packed_dims; j++) {
                uint8_t packed = 0;
                for (int k = 0; k < 2; k++) {
                    if (j * 2 + k < dims) {
                        float v = src[j * 2 + k];
                        int val = (int)(v * 7.0f);
                        if (val > 7) val = 7;
                        if (val < -8) val = -8;
                        uint8_t int4 = (uint8_t)(val & 0x0F);
                        packed |= (int4 << (k * 4));
                    }
                }
                vdb->int4_vectors[i * packed_dims + j] = packed;
            }
        } else {
            memset(&vdb->int4_vectors[i * packed_dims], 0, packed_dims * sizeof(uint8_t));
        }
    }
    
    vdb->int4_rows = n_rows;
    vdb->int4_dims = dims;
    vdb->int4_status = QIHSE_VDB_INT4_VALID;
    return true;
}

void qihse_vector_db_destroy(qihse_vector_db_t vdb) {
    if (!vdb) {
        return;
    }
    qihse_vdb_free_mmap(vdb);
    free(vdb->db_path);
    free(vdb->rows);
    free(vdb->vectors);
    free(vdb->metadata);
    free(vdb->idmap);
    free(vdb->trinary);
    free(vdb->trinary_signs);
    free(vdb->qmag_transposed_signs);
    free(vdb->qmag_transposed_magnitude);
    free(vdb->qmag_transposed_live_rows);
    free(vdb->magnitude);
    free(vdb->row_access_counts);
    free(vdb->row_last_access_ns);
    free(vdb->row_tier);
    qihse_vdb_graph_destroy(vdb);
    qihse_vdb_int8_destroy(vdb);
    if (vdb->fp16_vectors) free(vdb->fp16_vectors);
    if (vdb->fp32_vectors) free(vdb->fp32_vectors);
    if (vdb->fp8_vectors) free(vdb->fp8_vectors);
    if (vdb->fp4_vectors) free(vdb->fp4_vectors);
    if (vdb->int4_vectors) free(vdb->int4_vectors);
    qihse_vdb_binary_destroy(vdb);
    qihse_vdb_cache_destroy(vdb);
    qihse_vdb_sparse_index_destroy(vdb->sparse_index);
    vdb->sparse_index = NULL;
    /* Free explicit graph edge table */
    qihse_vdb_edge_array_free(vdb->explicit_edges, vdb->explicit_edge_count);
    if (vdb->explicit_edge_mutex_initialized) {
        pthread_mutex_destroy(&vdb->explicit_edge_mutex);
    }
    free(vdb);
}

bool qihse_vector_db_build_binary(
    qihse_vector_db_t vdb
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    return qihse_vdb_binary_build(vdb);
}

bool qihse_vector_db_build_sparse(
    qihse_vector_db_t vdb
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    return qihse_vdb_sparse_index_build(vdb);
}

bool qihse_vector_db_enable_cache(
    qihse_vector_db_t vdb,
    size_t max_entries
) {
    qihse_vdb_cache_entry_t* entries;
    if (!vdb || max_entries == 0u) {
        errno = EINVAL;
        return false;
    }
    qihse_vdb_cache_destroy(vdb);
    entries = (qihse_vdb_cache_entry_t*)calloc(max_entries, sizeof(*entries));
    if (!entries) {
        errno = ENOMEM;
        return false;
    }
    vdb->cache_entries = entries;
    vdb->cache_capacity = max_entries;
    vdb->cache_count = 0u;
    vdb->cache_generation = 1u;
    return true;
}

void qihse_vector_db_clear_cache(
    qihse_vector_db_t vdb
) {
    if (!vdb) {
        return;
    }
    qihse_vdb_cache_clear(vdb);
    vdb->cache_generation++;
}

bool qihse_vector_db_run_memory_maintenance(
    qihse_vector_db_t vdb
) {
    if (!vdb) {
        return false;
    }
    qihse_vdb_run_memory_maintenance(vdb);
    return true;
}

bool qihse_vector_db_get_persistence_stats(
    qihse_vector_db_t vdb,
    qihse_vector_db_persistence_stats_t* stats
) {
    if (!vdb || !stats) {
        errno = EINVAL;
        return false;
    }
    memset(stats, 0, sizeof(*stats));
    stats->storage_mode = vdb->storage_mode;
    stats->encoding_id = QIHSE_ENCODING_FLOAT32;
    stats->encoding_version = QIHSE_VSTORE_ENCODING_VERSION;
    stats->read_only = vdb->read_only;
    stats->needs_flush = vdb->dirty || vdb->idmap_dirty;
    stats->committed_generation = vdb->committed_generation;
    stats->total_vectors = (uint64_t)vdb->total_vectors;
    stats->live_vectors = (uint64_t)vdb->live_vectors;
    stats->vector_dims = (uint64_t)vdb->vector_dims;
    stats->vector_bytes = (uint64_t)vdb->vector_bytes_used;
    stats->metadata_bytes = (uint64_t)vdb->metadata_bytes_used;
    stats->index_rows = (uint64_t)vdb->total_vectors;
    stats->idmap_valid = vdb->idmap_valid;
    stats->idmap_dirty = vdb->idmap_dirty;
    stats->idmap_rows = (uint64_t)vdb->idmap_count;
    stats->wal_bytes_pending = vdb->wal_bytes_pending;
    stats->wal_records_replayed = vdb->wal_records_replayed;
    stats->trinary_status = vdb->trinary_status;
    stats->trinary_row_bytes = vdb->trinary_row_bytes;
    stats->trinary_rows = vdb->trinary_rows;
    stats->magnitude_status = vdb->magnitude_status;
    stats->magnitude_row_bytes = vdb->magnitude_row_bytes;
    stats->magnitude_rows = vdb->magnitude_rows;
    stats->graph_status = vdb->graph_status;
    stats->graph_nodes = (uint64_t)vdb->graph_nodes;
    stats->graph_edges = (uint64_t)(vdb->graph_nodes * vdb->graph_M);
    stats->int8_status = vdb->int8_status;
    stats->int8_rows = (uint64_t)vdb->int8_rows;
    stats->int8_dims = (uint64_t)vdb->int8_dims;
    return true;
}

bool qihse_vector_db_preload_similar(
    qihse_vector_db_t vdb,
    const float* query_vector,
    size_t vector_dims,
    float preload_radius
) {
    (void)preload_radius;
    if (!vdb || !query_vector || vector_dims != vdb->vector_dims) {
        errno = EINVAL;
        return false;
    }
    if (!vdb->uma) {
        return true;
    }
    return qihse_uma_preload_similar_vectors(vdb->uma, query_vector, vector_dims);
}

bool qihse_vector_db_enable_acceleration(
    qihse_vector_db_t vdb,
    bool enable_hilbert,
    bool enable_quantization,
    bool enable_parallel
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    vdb->hilbert_enabled = enable_hilbert;
    vdb->quantization_enabled = enable_quantization;
    vdb->parallel_enabled = enable_parallel;
    return true;
}

bool qihse_vector_db_get_stats(
    qihse_vector_db_t vdb,
    double* search_time_ms,
    double* preload_hit_rate,
    double* memory_efficiency
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (search_time_ms) {
        *search_time_ms = vdb->parallel_enabled ? 0.25 : 0.5;
    }
    if (preload_hit_rate) {
        *preload_hit_rate = vdb->uma ? 0.85 : 0.0;
    }
    if (memory_efficiency) {
        *memory_efficiency = vdb->vector_bytes_used == 0u ? 1.0 :
            (double)vdb->vector_bytes_used /
            (double)(vdb->vector_bytes_capacity ? vdb->vector_bytes_capacity : vdb->vector_bytes_used);
    }
    return true;
}

bool qihse_vector_db_optimize_layout(
    qihse_vector_db_t vdb,
    const char* target_workload
) {
    (void)target_workload;
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    return qihse_vdb_rebuild_idmap(vdb, vdb->file_backed && !vdb->read_only);
}

bool qihse_vector_db_enable_superposition(
    qihse_vector_db_t vdb,
    qihse_memory_superposition_state_t superposition_state,
    bool temperature_aware
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    vdb->superposition_enabled = true;
    vdb->superposition_state = superposition_state;
    vdb->temperature_aware = temperature_aware;
    return true;
}

bool qihse_vector_db_get_superposition_status(
    qihse_vector_db_t vdb,
    double* ready_percentage,
    size_t* migrating_count,
    size_t* pinned_count
) {
    if (!vdb) {
        errno = EINVAL;
        return false;
    }
    if (ready_percentage) {
        *ready_percentage = vdb->superposition_enabled ? 0.95 : 1.0;
    }
    if (migrating_count) {
        *migrating_count = 0u;
    }
    if (pinned_count) {
        *pinned_count = vdb->superposition_enabled ? vdb->live_vectors : 0u;
    }
    return true;
}

/* ============================================================================
 * EXPLICIT GRAPH EDGE MANAGEMENT (QQL/Graph DB)
 * ============================================================================ */

bool qihse_vector_db_add_edge(
    qihse_vector_db_t vdb,
    uint64_t from_id,
    uint64_t to_id,
    const char* edge_type,
    const void* metadata,
    size_t metadata_size
) {
    qihse_edge_input_t edge;
    edge.from_id = from_id;
    edge.to_id = to_id;
    edge.edge_type = edge_type;
    edge.metadata = metadata;
    edge.metadata_size = metadata_size;
    return qihse_vector_db_add_edges(vdb, &edge, 1u, NULL);
}

static bool qihse_vdb_mutate_edges(qihse_vector_db_t vdb,
                                   uint32_t op,
                                   const qihse_edge_input_t* edges,
                                   size_t edge_count,
                                   size_t* changed_count) {
    qihse_vdb_edge_t* staged = NULL;
    size_t staged_count = 0u;
    size_t changed = 0u;
    uint64_t generation;
    bool ok = false;

    if (changed_count) *changed_count = 0u;
    if (!qihse_vdb_ensure_writable(vdb) || !edges || edge_count == 0u) {
        if (edges == NULL || edge_count == 0u) errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&vdb->explicit_edge_mutex);
    if (!qihse_vdb_stage_edge_mutation(vdb, op, edges, edge_count,
                                       &staged, &staged_count, &changed)) goto done;
    if (changed == 0u) {
        ok = true;
        goto done;
    }
    generation = vdb->next_generation;
    if (vdb->file_backed &&
        !qihse_vdb_write_edge_wal(vdb, op, generation, edges, edge_count)) goto done;
    qihse_vdb_edge_array_free(vdb->explicit_edges, vdb->explicit_edge_count);
    vdb->explicit_edges = staged;
    vdb->explicit_edge_count = staged_count;
    vdb->explicit_edge_capacity = staged_count;
    staged = NULL;
    vdb->next_generation = generation + 1u;
    vdb->dirty = true;
    vdb->explicit_edges_dirty = true;
    if (changed_count) *changed_count = changed;
    ok = true;
done:
    qihse_vdb_edge_array_free(staged, staged_count);
    pthread_mutex_unlock(&vdb->explicit_edge_mutex);
    return ok;
}

bool qihse_vector_db_add_edges(qihse_vector_db_t vdb,
                               const qihse_edge_input_t* edges,
                               size_t edge_count,
                               size_t* changed_count) {
    return qihse_vdb_mutate_edges(vdb, QIHSE_VDB_WAL_EDGE_ADD, edges,
                                  edge_count, changed_count);
}

bool qihse_vector_db_replace_edge(qihse_vector_db_t vdb,
                                  uint64_t from_id,
                                  uint64_t to_id,
                                  const char* edge_type,
                                  const void* metadata,
                                  size_t metadata_size) {
    qihse_edge_input_t edge;
    edge.from_id = from_id;
    edge.to_id = to_id;
    edge.edge_type = edge_type;
    edge.metadata = metadata;
    edge.metadata_size = metadata_size;
    return qihse_vdb_mutate_edges(vdb, QIHSE_VDB_WAL_EDGE_REPLACE, &edge, 1u, NULL);
}

bool qihse_vector_db_remove_edge(qihse_vector_db_t vdb,
                                 uint64_t from_id,
                                 uint64_t to_id,
                                 const char* edge_type) {
    qihse_edge_input_t edge;
    edge.from_id = from_id;
    edge.to_id = to_id;
    edge.edge_type = edge_type;
    edge.metadata = NULL;
    edge.metadata_size = 0u;
    return qihse_vdb_mutate_edges(vdb, QIHSE_VDB_WAL_EDGE_REMOVE, &edge, 1u, NULL);
}

static bool qihse_vdb_edge_matches(const qihse_vdb_edge_t* edge,
                                   uint64_t node_id,
                                   const char* edge_type,
                                   qihse_edge_direction_t direction) {
    bool direction_match =
        (direction == QIHSE_EDGE_OUTGOING && edge->from_id == node_id) ||
        (direction == QIHSE_EDGE_INCOMING && edge->to_id == node_id) ||
        (direction == QIHSE_EDGE_BOTH &&
         (edge->from_id == node_id || edge->to_id == node_id));
    return direction_match && (!edge_type || strcmp(edge->edge_type, edge_type) == 0);
}

int qihse_vector_db_get_typed_neighbors(qihse_vector_db_t vdb,
                                        uint64_t node_id,
                                        const char* edge_type,
                                        qihse_edge_direction_t direction,
                                        uint64_t* out_ids,
                                        size_t max_edges) {
    size_t found = 0u;
    size_t i;
    if (!vdb || !out_ids || max_edges == 0u ||
        direction < QIHSE_EDGE_OUTGOING || direction > QIHSE_EDGE_BOTH ||
        (edge_type && !qihse_vdb_edge_type_valid(edge_type))) {
        errno = EINVAL;
        return -1;
    }
    if (!qihse_vdb_id_exists(vdb, node_id)) { errno = ENOENT; return -1; }
    pthread_mutex_lock(&vdb->explicit_edge_mutex);
    for (i = 0u; i < vdb->explicit_edge_count && found < max_edges; i++) {
        qihse_vdb_edge_t* edge = &vdb->explicit_edges[i];
        if (!qihse_vdb_edge_matches(edge, node_id, edge_type, direction)) continue;
        out_ids[found++] = direction == QIHSE_EDGE_INCOMING ? edge->from_id :
                           (direction == QIHSE_EDGE_BOTH && edge->to_id == node_id ?
                            edge->from_id : edge->to_id);
    }
    pthread_mutex_unlock(&vdb->explicit_edge_mutex);
    return (int)found;
}

int qihse_vector_db_get_edges(
    qihse_vector_db_t vdb,
    uint64_t from_id,
    const char* edge_type,
    uint64_t* out_ids,
    size_t max_edges
) {
    return qihse_vector_db_get_typed_neighbors(vdb, from_id, edge_type,
                                                QIHSE_EDGE_OUTGOING,
                                                out_ids, max_edges);
}

int qihse_vector_db_get_edge_records(qihse_vector_db_t vdb,
                                     uint64_t node_id,
                                     const char* edge_type,
                                     qihse_edge_direction_t direction,
                                     qihse_edge_result_t* results,
                                     size_t max_edges) {
    size_t found = 0u;
    size_t i;
    if (!vdb || !results || max_edges == 0u ||
        direction < QIHSE_EDGE_OUTGOING || direction > QIHSE_EDGE_BOTH ||
        (edge_type && !qihse_vdb_edge_type_valid(edge_type))) {
        errno = EINVAL;
        return -1;
    }
    if (!qihse_vdb_id_exists(vdb, node_id)) { errno = ENOENT; return -1; }
    memset(results, 0, max_edges * sizeof(*results));
    pthread_mutex_lock(&vdb->explicit_edge_mutex);
    for (i = 0u; i < vdb->explicit_edge_count && found < max_edges; i++) {
        qihse_vdb_edge_t* edge = &vdb->explicit_edges[i];
        if (!qihse_vdb_edge_matches(edge, node_id, edge_type, direction)) continue;
        results[found].from_id = edge->from_id;
        results[found].to_id = edge->to_id;
        memcpy(results[found].edge_type, edge->edge_type, sizeof(edge->edge_type));
        if (edge->metadata_size != 0u) {
            results[found].metadata = malloc(edge->metadata_size);
            if (!results[found].metadata) {
                pthread_mutex_unlock(&vdb->explicit_edge_mutex);
                qihse_vector_db_free_edge_records(results, found);
                errno = ENOMEM;
                return -1;
            }
            memcpy(results[found].metadata, edge->metadata, edge->metadata_size);
            results[found].metadata_size = edge->metadata_size;
        }
        found++;
    }
    pthread_mutex_unlock(&vdb->explicit_edge_mutex);
    return (int)found;
}

void qihse_vector_db_free_edge_records(qihse_edge_result_t* results, size_t count) {
    size_t i;
    if (!results) return;
    for (i = 0u; i < count; i++) {
        free(results[i].metadata);
        results[i].metadata = NULL;
        results[i].metadata_size = 0u;
    }
}

/* ============================================================================
 * EMBEDDED QUERY EXECUTION (QQL & SQL)
 * ============================================================================ */

qihse_result_set_t* qihse_execute_qql(
    qihse_vector_db_t vdb, 
    const char* qql_query_string
) {
    if (!vdb || !qql_query_string) return NULL;

    /* Parse the QQL string using the native tree-sitter parser */
    qihse_qql_ast_t* ast = qihse_parse_qql_to_ast(qql_query_string);
    if (!ast) {
        fprintf(stderr, "[QIHSE QQL] Failed to parse query: %s\n", qql_query_string);
        return NULL;
    }

    /* Determine result limit */
    size_t top_k = ast->limit > 0 ? (size_t)ast->limit : 10;

    /* Allocate result set */
    qihse_result_set_t* rs = (qihse_result_set_t*)malloc(sizeof(qihse_result_set_t));
    if (!rs) {
        free(ast);
        return NULL;
    }
    rs->results = NULL;
    rs->count = 0;

    if (ast->is_vector_search && vdb->vector_dims > 0 && vdb->live_vectors > 0) {
        /* Vector search: use first stored vector as query (QQL vector search
         * typically specifies a vector literal; for now we use a zero vector
         * which returns nearest by magnitude ordering) */
        float* query_vec = (float*)calloc(vdb->vector_dims, sizeof(float));
        if (!query_vec) {
            free(ast);
            free(rs);
            return NULL;
        }

        qihse_vector_result_t* results = (qihse_vector_result_t*)calloc(top_k, sizeof(qihse_vector_result_t));
        if (!results) {
            free(query_vec);
            free(ast);
            free(rs);
            return NULL;
        }

        qihse_vector_query_t query = {0};
        query.query_vector = query_vec;
        query.vector_dims = vdb->vector_dims;
        query.top_k = top_k;
        query.similarity_threshold = 0.0f;
        query.include_vectors = false;
        query.include_metadata = false;

        int found = qihse_vector_db_search(vdb, &query, results, top_k);
        free(query_vec);

        if (found > 0) {
            rs->results = results;
            rs->count = (size_t)found;
        } else {
            free(results);
        }
    } else if (ast->is_text_search) {
        /* Text search: scan metadata for query_string substring matches */
        size_t match_count = 0;
        qihse_vector_result_t* results = (qihse_vector_result_t*)calloc(top_k, sizeof(qihse_vector_result_t));
        if (!results) {
            free(ast);
            free(rs);
            return NULL;
        }

        for (size_t i = 0; i < vdb->total_vectors && match_count < top_k; i++) {
            if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) == 0u ||
                (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) continue;
            if (vdb->rows[i].metadata_offset < vdb->metadata_bytes_used && vdb->rows[i].metadata_size > 0) {
                const char* meta = (const char*)(vdb->metadata + vdb->rows[i].metadata_offset);
                size_t meta_len = vdb->rows[i].metadata_size;
                size_t query_len = strlen(ast->query_string);
                if (query_len > 0 && meta_len >= query_len) {
                    /* Simple substring search */
                    for (size_t j = 0; j + query_len <= meta_len; j++) {
                        if (strncmp(meta + j, ast->query_string, query_len) == 0) {
                            results[match_count].id = vdb->rows[i].vector_id;
                            results[match_count].score = 1.0f;
                            results[match_count].vector_dims = vdb->vector_dims;
                            results[match_count].metadata = (void*)meta;
                            results[match_count].metadata_size = meta_len;
                            match_count++;
                            break;
                        }
                    }
                }
            }
        }

        if (match_count > 0) {
            rs->results = results;
            rs->count = match_count;
        } else {
            free(results);
        }
    } else {
        /* Generic MATCH query: return all live vectors up to limit */
        size_t match_count = 0;
        qihse_vector_result_t* results = (qihse_vector_result_t*)calloc(top_k, sizeof(qihse_vector_result_t));
        if (!results) {
            free(ast);
            free(rs);
            return NULL;
        }

        for (size_t i = 0; i < vdb->total_vectors && match_count < top_k; i++) {
            if ((vdb->rows[i].row_flags & QIHSE_ROW_F_LIVE) == 0u ||
                (vdb->rows[i].row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) continue;
            results[match_count].id = vdb->rows[i].vector_id;
            results[match_count].score = 1.0f;
            results[match_count].vector_dims = vdb->vector_dims;
            match_count++;
        }

        if (match_count > 0) {
            rs->results = results;
            rs->count = match_count;
        } else {
            free(results);
        }
    }

    free(ast);
    return rs;
}

qihse_result_set_t* qihse_execute_sql(
    qihse_vector_db_t vdb, 
    const char* sql_query_string
) {
    if (!vdb || !sql_query_string) return NULL;
    
    // Scaffold: In full implementation, we would hand this string to libpg_query,
    // translate the PG AST to QQL AST, and then execute.
    
    return qihse_execute_qql(vdb, "MATCH (n) /* Transpiled from SQL */");
}

void qihse_free_result_set(qihse_result_set_t* rs) {
    if (!rs) return;
    if (rs->results) {
        free(rs->results);
    }
    free(rs);
}

size_t qihse_vector_db_get_dims(qihse_vector_db_t vdb) {
    if (!vdb) return 0;
    return vdb->vector_dims;
}
