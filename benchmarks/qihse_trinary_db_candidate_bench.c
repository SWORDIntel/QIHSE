#include "codecs/qihse_trinary_tryte_codec.h"
#include "persistence/qihse_vector_store.h"
#include "qihse_vector_db.h"

#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define QIHSE_BENCH_ROWS 2048u
#define QIHSE_BENCH_DIMS 64u
#define QIHSE_BENCH_CANDIDATES 64u
#define QIHSE_BENCH_TOPK 8u
#define QIHSE_BENCH_ITERS 32u

typedef struct qihse_bench_ranked_s {
    size_t row_index;
    uint64_t id;
    float score;
} qihse_bench_ranked_t;

static double qihse_bench_seconds(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static uint32_t qihse_bench_mix32(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7feb352du;
    value ^= value >> 15;
    value *= 0x846ca68bu;
    value ^= value >> 16;
    return value;
}

static float qihse_bench_query_value(size_t dim) {
    return (dim % 3u == 0u) ? 1.0f : -1.0f;
}

static void qihse_bench_fill_data(float* rows, float* query, uint64_t* ids) {
    size_t row;
    size_t dim;

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        query[dim] = qihse_bench_query_value(dim);
    }

    for (row = 0u; row < QIHSE_BENCH_ROWS; row++) {
        ids[row] = 100000u + (uint64_t)row;
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            uint32_t mixed = qihse_bench_mix32((uint32_t)((row + 17u) * 131u +
                                                          (dim + 5u) * 977u));
            uint32_t bucket = mixed % 5u;
            float value = 0.0f;

            if (bucket == 0u || bucket == 1u) {
                value = query[dim];
            } else if (bucket == 2u || bucket == 3u) {
                value = -query[dim];
            }
            rows[(row * QIHSE_BENCH_DIMS) + dim] = value;
        }
    }

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        rows[dim] = query[dim];
        rows[QIHSE_BENCH_DIMS + dim] = dim == 7u ? 0.0f : query[dim];
        rows[(2u * QIHSE_BENCH_DIMS) + dim] = dim == 11u ? -query[dim] : query[dim];
        rows[(3u * QIHSE_BENCH_DIMS) + dim] =
            (dim == 13u || dim == 17u) ? -query[dim] : query[dim];
    }
}

static void qihse_bench_remove_tree(const char* path) {
    DIR* dir;
    struct dirent* entry;

    if (!path) {
        return;
    }
    dir = opendir(path);
    if (!dir) {
        (void)unlink(path);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char child[512];

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
            (int)sizeof(child)) {
            continue;
        }
        qihse_bench_remove_tree(child);
    }
    (void)closedir(dir);
    (void)rmdir(path);
}

static char* qihse_bench_make_temp_db_path(void) {
    char template_path[] = "/tmp/qihse_trinary_db_candidate_XXXXXX";
    char* path = strdup(template_path);

    if (!path) {
        return NULL;
    }
    if (!mkdtemp(path)) {
        free(path);
        return NULL;
    }
    qihse_bench_remove_tree(path);
    return path;
}

static int qihse_bench_create_persisted_db(const char* db_path,
                                           const float* rows,
                                           const uint64_t* ids) {
    qihse_vector_db_t db =
        qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, db_path);

    if (!db) {
        perror("qihse_vector_db_create");
        return 0;
    }
    if (!qihse_vector_db_add_vectors(db,
                                     rows,
                                     QIHSE_BENCH_ROWS,
                                     QIHSE_BENCH_DIMS,
                                     ids,
                                     NULL,
                                     NULL)) {
        perror("qihse_vector_db_add_vectors");
        qihse_vector_db_destroy(db);
        return 0;
    }
    if (!qihse_vector_db_flush(db)) {
        perror("qihse_vector_db_flush");
        qihse_vector_db_destroy(db);
        return 0;
    }
    if (!qihse_vector_db_close(db)) {
        perror("qihse_vector_db_close");
        return 0;
    }
    return 1;
}

static int qihse_bench_verify_reopen_stats(const char* db_path) {
    qihse_vector_db_t db;
    qihse_vector_db_persistence_stats_t stats;

    db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,
                              NULL,
                              db_path,
                              QIHSE_VDB_OPEN_FILE_BACKED |
                                  QIHSE_VDB_OPEN_READ_ONLY |
                                  QIHSE_VDB_OPEN_MMAP);
    if (!db) {
        perror("qihse_vector_db_open read-only mmap");
        return 0;
    }
    memset(&stats, 0, sizeof(stats));
    if (!qihse_vector_db_get_persistence_stats(db, &stats)) {
        perror("qihse_vector_db_get_persistence_stats");
        qihse_vector_db_destroy(db);
        return 0;
    }
    if (stats.encoding_id != QIHSE_ENCODING_FLOAT32 ||
        stats.trinary_status != QIHSE_VDB_TRINARY_VALID ||
        stats.trinary_rows != QIHSE_BENCH_ROWS) {
        fprintf(stderr,
                "unexpected persistence stats: encoding=%u trinary_status=%d "
                "trinary_rows=%llu\n",
                (unsigned)stats.encoding_id,
                (int)stats.trinary_status,
                (unsigned long long)stats.trinary_rows);
        qihse_vector_db_destroy(db);
        return 0;
    }
    if (!qihse_vector_db_close(db)) {
        perror("qihse_vector_db_close read-only");
        return 0;
    }
    return 1;
}

static const float* qihse_bench_snapshot_vector_at(
    const qihse_vector_store_snapshot_t* snapshot,
    const qihse_index_row_t* row,
    size_t dims) {
    size_t bytes = dims * sizeof(float);

    if (!snapshot || !row ||
        row->vector_offset > (uint64_t)SIZE_MAX ||
        (size_t)row->vector_offset > snapshot->vector_bytes ||
        bytes > snapshot->vector_bytes - (size_t)row->vector_offset) {
        return NULL;
    }
    return (const float*)(const void*)(snapshot->vectors + (size_t)row->vector_offset);
}

static float qihse_bench_cosine(const float* lhs, const float* rhs, size_t dims) {
    double dot = 0.0;
    double lhs_norm = 0.0;
    double rhs_norm = 0.0;
    size_t dim;

    for (dim = 0u; dim < dims; dim++) {
        dot += (double)lhs[dim] * (double)rhs[dim];
        lhs_norm += (double)lhs[dim] * (double)lhs[dim];
        rhs_norm += (double)rhs[dim] * (double)rhs[dim];
    }
    if (lhs_norm == 0.0 || rhs_norm == 0.0) {
        return 0.0f;
    }
    return (float)(dot / (sqrt(lhs_norm) * sqrt(rhs_norm)));
}

static int qihse_bench_exact_is_better(float lhs_score,
                                       size_t lhs_row,
                                       float rhs_score,
                                       size_t rhs_row) {
    return lhs_score > rhs_score ||
           (lhs_score == rhs_score && lhs_row < rhs_row);
}

static int qihse_bench_exact_rank(
    const qihse_vector_store_snapshot_t* snapshot,
    const float* query,
    const size_t* candidate_rows,
    size_t candidate_count,
    qihse_bench_ranked_t* out,
    size_t max_results,
    size_t* out_count) {
    size_t selected = 0u;
    size_t i;

    if (!snapshot || !query || !out || !out_count || max_results == 0u) {
        errno = EINVAL;
        return 0;
    }
    *out_count = 0u;
    memset(out, 0, max_results * sizeof(*out));

    for (i = 0u; i < candidate_count; i++) {
        size_t row_index = candidate_rows ? candidate_rows[i] : i;
        const qihse_index_row_t* row;
        const float* vector;
        float score;
        size_t insert_at;

        if (row_index >= snapshot->row_count) {
            errno = EINVAL;
            return 0;
        }
        row = snapshot->rows + row_index;
        if ((row->row_flags & QIHSE_ROW_F_LIVE) == 0u ||
            (row->row_flags & QIHSE_ROW_F_TOMBSTONE) != 0u) {
            continue;
        }
        vector = qihse_bench_snapshot_vector_at(snapshot, row, QIHSE_BENCH_DIMS);
        if (!vector) {
            errno = EINVAL;
            return 0;
        }
        score = qihse_bench_cosine(query, vector, QIHSE_BENCH_DIMS);
        insert_at = selected;
        while (insert_at > 0u &&
               qihse_bench_exact_is_better(score,
                                           row_index,
                                           out[insert_at - 1u].score,
                                           out[insert_at - 1u].row_index)) {
            insert_at--;
        }
        if (insert_at >= max_results) {
            continue;
        }
        if (selected < max_results) {
            selected++;
        }
        if (selected > insert_at + 1u) {
            size_t move;
            for (move = selected - 1u; move > insert_at; move--) {
                out[move] = out[move - 1u];
            }
        }
        out[insert_at].row_index = row_index;
        out[insert_at].id = row->vector_id;
        out[insert_at].score = score;
    }

    *out_count = selected;
    return 1;
}

static int qihse_bench_verify_rerank(const qihse_bench_ranked_t* reranked,
                                     size_t reranked_count,
                                     const qihse_bench_ranked_t* oracle,
                                     size_t oracle_count) {
    size_t i;

    if (reranked_count != QIHSE_BENCH_TOPK || oracle_count != QIHSE_BENCH_TOPK) {
        fprintf(stderr,
                "expected %u reranked/oracle rows, got %zu/%zu\n",
                (unsigned)QIHSE_BENCH_TOPK,
                reranked_count,
                oracle_count);
        return 0;
    }
    for (i = 0u; i < QIHSE_BENCH_TOPK; i++) {
        if (reranked[i].row_index != oracle[i].row_index ||
            reranked[i].id != oracle[i].id) {
            fprintf(stderr,
                    "exact rerank mismatch at %zu: got row=%zu id=%llu, "
                    "expected row=%zu id=%llu\n",
                    i,
                    reranked[i].row_index,
                    (unsigned long long)reranked[i].id,
                    oracle[i].row_index,
                    (unsigned long long)oracle[i].id);
            return 0;
        }
    }
    return 1;
}

static int qihse_bench_verify_full_search(const qihse_vector_result_t* results,
                                          size_t result_count,
                                          const qihse_bench_ranked_t* oracle,
                                          size_t oracle_count) {
    size_t i;

    if (result_count < QIHSE_BENCH_TOPK || oracle_count != QIHSE_BENCH_TOPK) {
        fprintf(stderr,
                "expected at least %u full-search rows and %u oracle rows, got %zu/%zu\n",
                (unsigned)QIHSE_BENCH_TOPK,
                (unsigned)QIHSE_BENCH_TOPK,
                result_count,
                oracle_count);
        return 0;
    }
    for (i = 0u; i < QIHSE_BENCH_TOPK; i++) {
        if (fabsf(results[i].score - oracle[i].score) > 0.000001f) {
            fprintf(stderr,
                    "full float32 search score mismatch at %zu: got %.6f, "
                    "expected %.6f\n",
                    i,
                    results[i].score,
                    oracle[i].score);
            return 0;
        }
    }
    return 1;
}

static size_t qihse_bench_recall_matches(const qihse_bench_ranked_t* reranked,
                                         size_t reranked_count,
                                         const qihse_vector_result_t* full,
                                         size_t full_count) {
    size_t matches = 0u;
    size_t i;

    for (i = 0u; i < reranked_count; i++) {
        size_t j;
        for (j = 0u; j < full_count; j++) {
            if (reranked[i].id == full[j].id) {
                matches++;
                break;
            }
        }
    }
    return matches;
}

static size_t qihse_bench_ordered_matches(const qihse_bench_ranked_t* reranked,
                                          size_t reranked_count,
                                          const qihse_vector_result_t* full,
                                          size_t full_count) {
    size_t limit = reranked_count < full_count ? reranked_count : full_count;
    size_t matches = 0u;
    size_t i;

    for (i = 0u; i < limit; i++) {
        if (reranked[i].id == full[i].id) {
            matches++;
        }
    }
    return matches;
}

static int32_t qihse_bench_candidate_score_for_row(const size_t* candidate_rows,
                                                   const int32_t* candidate_scores,
                                                   size_t candidate_count,
                                                   size_t row_index) {
    size_t i;

    for (i = 0u; i < candidate_count; i++) {
        if (candidate_rows[i] == row_index) {
            return candidate_scores[i];
        }
    }
    return 0;
}

int main(void) {
    char* db_path = NULL;
    qihse_vector_db_t full_db = NULL;
    float* rows = NULL;
    uint64_t* ids = NULL;
    float query[QIHSE_BENCH_DIMS];
    uint8_t encoded_query[(QIHSE_BENCH_DIMS + 4u) / 5u];
    qihse_vector_query_t full_query;
    qihse_vector_result_t* full_results = NULL;
    qihse_vector_store_snapshot_t snapshot;
    size_t row_bytes = 0u;
    size_t candidate_rows[QIHSE_BENCH_CANDIDATES] = {0u};
    int32_t candidate_scores[QIHSE_BENCH_CANDIDATES] = {0};
    size_t candidate_count = 0u;
    qihse_bench_ranked_t reranked[QIHSE_BENCH_TOPK];
    qihse_bench_ranked_t oracle[QIHSE_BENCH_TOPK];
    size_t full_count = 0u;
    size_t full_topk_count = 0u;
    size_t reranked_count = 0u;
    size_t oracle_count = 0u;
    double load_start;
    double load_seconds;
    double full_start;
    double full_seconds;
    double select_start;
    double select_seconds;
    double rerank_start;
    double rerank_seconds;
    size_t recall_matches;
    size_t ordered_matches;
    volatile int64_t checksum = 0;
    size_t iter;
    size_t i;
    int exit_code = 1;

    memset(&snapshot, 0, sizeof(snapshot));
    rows = (float*)calloc(QIHSE_BENCH_ROWS * QIHSE_BENCH_DIMS, sizeof(float));
    ids = (uint64_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*ids));
    full_results = (qihse_vector_result_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*full_results));
    if (!rows || !ids || !full_results) {
        perror("calloc");
        goto cleanup;
    }
    qihse_bench_fill_data(rows, query, ids);

    db_path = qihse_bench_make_temp_db_path();
    if (!db_path) {
        perror("mkdtemp");
        goto cleanup;
    }
    if (!qihse_bench_create_persisted_db(db_path, rows, ids) ||
        !qihse_bench_verify_reopen_stats(db_path)) {
        goto cleanup;
    }

    full_db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,
                                   NULL,
                                   db_path,
                                   QIHSE_VDB_OPEN_FILE_BACKED |
                                       QIHSE_VDB_OPEN_READ_ONLY |
                                       QIHSE_VDB_OPEN_MMAP);
    if (!full_db) {
        perror("qihse_vector_db_open full-search read-only mmap");
        goto cleanup;
    }

    load_start = qihse_bench_seconds();
    if (!qihse_vector_store_load(db_path, &snapshot)) {
        perror("qihse_vector_store_load");
        goto cleanup;
    }
    load_seconds = qihse_bench_seconds() - load_start;

    if (!snapshot.trinary_valid ||
        snapshot.manifest.encoding_id != QIHSE_VSTORE_ENCODING_FLOAT32 ||
        snapshot.manifest.trinary_rows != QIHSE_BENCH_ROWS ||
        snapshot.manifest.vector_dims != QIHSE_BENCH_DIMS ||
        !qihse_trinary_tryte_row_bytes(QIHSE_BENCH_DIMS, &row_bytes) ||
        snapshot.manifest.trinary_row_bytes != row_bytes) {
        fprintf(stderr, "persisted snapshot is missing a valid qtri/qvec pair\n");
        goto cleanup;
    }
    if (!qihse_trinary_tryte_encode_row(query,
                                        QIHSE_BENCH_DIMS,
                                        encoded_query,
                                        sizeof(encoded_query))) {
        perror("qihse_trinary_tryte_encode_row");
        goto cleanup;
    }

    memset(&full_query, 0, sizeof(full_query));
    full_query.query_vector = query;
    full_query.vector_dims = QIHSE_BENCH_DIMS;
    full_query.top_k = QIHSE_BENCH_ROWS;
    full_query.similarity_threshold = -1.0f;
    full_query.include_vectors = false;
    full_query.include_metadata = false;

    full_start = qihse_bench_seconds();
    for (iter = 0u; iter < QIHSE_BENCH_ITERS; iter++) {
        int found;

        memset(full_results, 0, QIHSE_BENCH_ROWS * sizeof(*full_results));
        found = qihse_vector_db_search(full_db,
                                       &full_query,
                                       full_results,
                                       QIHSE_BENCH_ROWS);
        if (found < 0) {
            perror("qihse_vector_db_search");
            goto cleanup;
        }
        full_count = (size_t)found;
        if (full_count != 0u) {
            checksum += (int64_t)full_results[0].id;
        }
    }
    full_seconds = qihse_bench_seconds() - full_start;
    full_topk_count = full_count < QIHSE_BENCH_TOPK ? full_count : QIHSE_BENCH_TOPK;

    select_start = qihse_bench_seconds();
    for (iter = 0u; iter < QIHSE_BENCH_ITERS; iter++) {
        if (!qihse_trinary_tryte_select_topk(snapshot.trinary,
                                             encoded_query,
                                             snapshot.row_count,
                                             QIHSE_BENCH_DIMS,
                                             candidate_rows,
                                             candidate_scores,
                                             QIHSE_BENCH_CANDIDATES,
                                             &candidate_count)) {
            perror("qihse_trinary_tryte_select_topk");
            goto cleanup;
        }
        checksum += (int64_t)candidate_rows[0] + (int64_t)candidate_scores[0];
    }
    select_seconds = qihse_bench_seconds() - select_start;

    rerank_start = qihse_bench_seconds();
    for (iter = 0u; iter < QIHSE_BENCH_ITERS; iter++) {
        if (!qihse_bench_exact_rank(&snapshot,
                                    query,
                                    candidate_rows,
                                    candidate_count,
                                    reranked,
                                    QIHSE_BENCH_TOPK,
                                    &reranked_count)) {
            perror("candidate exact rerank");
            goto cleanup;
        }
        checksum += (int64_t)reranked[0].row_index;
    }
    rerank_seconds = qihse_bench_seconds() - rerank_start;

    if (!qihse_bench_exact_rank(&snapshot,
                                query,
                                NULL,
                                snapshot.row_count,
                                oracle,
                                QIHSE_BENCH_TOPK,
                                &oracle_count) ||
        !qihse_bench_verify_full_search(full_results, full_count, oracle, oracle_count) ||
        !qihse_bench_verify_rerank(reranked, reranked_count, oracle, oracle_count)) {
        goto cleanup;
    }

    recall_matches = qihse_bench_recall_matches(reranked,
                                                reranked_count,
                                                full_results,
                                                full_topk_count);
    ordered_matches = qihse_bench_ordered_matches(reranked,
                                                  reranked_count,
                                                  full_results,
                                                  full_topk_count);

    printf("trinary_search_path_bench rows=%u dims=%u qtri_row_bytes=%zu "
           "candidates=%u topk=%u iterations=%u\n",
           (unsigned)QIHSE_BENCH_ROWS,
           (unsigned)QIHSE_BENCH_DIMS,
           row_bytes,
           (unsigned)QIHSE_BENCH_CANDIDATES,
           (unsigned)QIHSE_BENCH_TOPK,
           (unsigned)QIHSE_BENCH_ITERS);
    printf("load_ms=%.3f full_float32_avg_us=%.3f trinary_select_avg_us=%.3f "
           "exact_rerank_avg_us=%.3f trinary_rerank_avg_us=%.3f "
           "speedup_vs_full=%.3fx recall_at_%u=%.3f ordered_at_%u=%.3f "
           "checksum=%lld\n",
           load_seconds * 1000.0,
           (full_seconds * 1000000.0) / (double)QIHSE_BENCH_ITERS,
           (select_seconds * 1000000.0) / (double)QIHSE_BENCH_ITERS,
           (rerank_seconds * 1000000.0) / (double)QIHSE_BENCH_ITERS,
           ((select_seconds + rerank_seconds) * 1000000.0) /
               (double)QIHSE_BENCH_ITERS,
           full_seconds > 0.0 && (select_seconds + rerank_seconds) > 0.0
               ? full_seconds / (select_seconds + rerank_seconds)
               : 0.0,
           (unsigned)QIHSE_BENCH_TOPK,
           full_topk_count == 0u ? 0.0
                                 : (double)recall_matches / (double)full_topk_count,
           (unsigned)QIHSE_BENCH_TOPK,
           full_topk_count == 0u ? 0.0
                                 : (double)ordered_matches / (double)full_topk_count,
           (long long)checksum);
    for (i = 0u; i < reranked_count; i++) {
        printf("result[%zu] row=%zu id=%llu tri_score=%d exact_score=%.6f\n",
               i,
               reranked[i].row_index,
               (unsigned long long)reranked[i].id,
               qihse_bench_candidate_score_for_row(candidate_rows,
                                                   candidate_scores,
                                                   candidate_count,
                                                   reranked[i].row_index),
               reranked[i].score);
    }

    exit_code = 0;

cleanup:
    if (full_db) {
        (void)qihse_vector_db_close(full_db);
    }
    qihse_vector_store_snapshot_free(&snapshot);
    if (db_path) {
        qihse_bench_remove_tree(db_path);
        free(db_path);
    }
    free(ids);
    free(full_results);
    free(rows);
    return exit_code;
}
