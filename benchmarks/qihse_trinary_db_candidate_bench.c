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

#ifndef QIHSE_BENCH_ROWS
#define QIHSE_BENCH_ROWS 2048u
#endif
#ifndef QIHSE_BENCH_DIMS
#define QIHSE_BENCH_DIMS 64u
#endif
#ifndef QIHSE_BENCH_CANDIDATES
#define QIHSE_BENCH_CANDIDATES 64u
#endif
#ifndef QIHSE_BENCH_TOPK
#define QIHSE_BENCH_TOPK 8u
#endif
#ifndef QIHSE_BENCH_ITERS
#define QIHSE_BENCH_ITERS 32u
#endif

typedef enum qihse_bench_dataset_e {
    QIHSE_BENCH_DATASET_ALIGNED = 0,
    QIHSE_BENCH_DATASET_BANDED = 1,
    QIHSE_BENCH_DATASET_WEIGHTED = 2,
    QIHSE_BENCH_DATASET_MAGNITUDE_SKEW = 3,
    QIHSE_BENCH_DATASET_NEAR_TIE = 4
} qihse_bench_dataset_t;

typedef struct qihse_bench_ranked_s {
    size_t row_index;
    uint64_t id;
    float score;
} qihse_bench_ranked_t;

typedef enum qihse_bench_score_mode_e {
    QIHSE_BENCH_SCORE_SCALAR = 0,
    QIHSE_BENCH_SCORE_WEIGHTED = 1,
    QIHSE_BENCH_SCORE_MAGNITUDE = 2
} qihse_bench_score_mode_t;

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

static qihse_bench_dataset_t qihse_bench_dataset(void) {
    const char* name = getenv("QIHSE_BENCH_DATASET");

    if (name && strcmp(name, "banded") == 0) {
        return QIHSE_BENCH_DATASET_BANDED;
    }
    if (name && strcmp(name, "weighted") == 0) {
        return QIHSE_BENCH_DATASET_WEIGHTED;
    }
    if (name && strcmp(name, "magnitude_skew") == 0) {
        return QIHSE_BENCH_DATASET_MAGNITUDE_SKEW;
    }
    if (name && strcmp(name, "near_tie") == 0) {
        return QIHSE_BENCH_DATASET_NEAR_TIE;
    }
    return QIHSE_BENCH_DATASET_ALIGNED;
}

static const char* qihse_bench_dataset_name(qihse_bench_dataset_t dataset) {
    switch (dataset) {
        case QIHSE_BENCH_DATASET_BANDED:
            return "banded";
        case QIHSE_BENCH_DATASET_WEIGHTED:
            return "weighted";
        case QIHSE_BENCH_DATASET_MAGNITUDE_SKEW:
            return "magnitude_skew";
        case QIHSE_BENCH_DATASET_NEAR_TIE:
            return "near_tie";
        case QIHSE_BENCH_DATASET_ALIGNED:
        default:
            return "aligned";
    }
}

static float qihse_bench_query_value(qihse_bench_dataset_t dataset, size_t dim) {
    if (dataset == QIHSE_BENCH_DATASET_BANDED) {
        return ((dim / 8u) % 2u == 0u) ? 1.0f : -1.0f;
    }
    if (dataset == QIHSE_BENCH_DATASET_WEIGHTED) {
        return (dim % 5u == 0u || dim % 5u == 1u) ? 1.0f : -1.0f;
    }
    return (dim % 3u == 0u) ? 1.0f : -1.0f;
}

static int qihse_bench_dataset_is_hard(qihse_bench_dataset_t dataset) {
    return dataset == QIHSE_BENCH_DATASET_MAGNITUDE_SKEW ||
           dataset == QIHSE_BENCH_DATASET_NEAR_TIE;
}

static int qihse_bench_dataset_requires_perfect(qihse_bench_dataset_t dataset,
                                                size_t candidate_count) {
    return !qihse_bench_dataset_is_hard(dataset) ||
           candidate_count >= QIHSE_BENCH_ROWS;
}

static int qihse_bench_sweep_enabled(void) {
    const char* value = getenv("QIHSE_BENCH_SWEEP");

    return value && strcmp(value, "1") == 0;
}

static qihse_bench_score_mode_t qihse_bench_score_mode(void) {
    const char* value = getenv("QIHSE_BENCH_TRINARY_SCORE");

    if (value && strcmp(value, "weighted") == 0) {
        return QIHSE_BENCH_SCORE_WEIGHTED;
    }
    if (value && strcmp(value, "magnitude") == 0) {
        return QIHSE_BENCH_SCORE_MAGNITUDE;
    }
    return QIHSE_BENCH_SCORE_SCALAR;
}

static const char* qihse_bench_score_mode_name(qihse_bench_score_mode_t mode) {
    switch (mode) {
        case QIHSE_BENCH_SCORE_WEIGHTED:
            return "weighted";
        case QIHSE_BENCH_SCORE_MAGNITUDE:
            return "magnitude";
        case QIHSE_BENCH_SCORE_SCALAR:
        default:
            return "scalar";
    }
}

static int32_t qihse_bench_weight_from_query(float value) {
    float magnitude = fabsf(value);
    int32_t weight;

    if (magnitude <= 0.0f) {
        return 0;
    }
    weight = (int32_t)(magnitude * 100.0f + 0.5f);
    return weight > 0 ? weight : 1;
}

static uint8_t qihse_bench_magnitude_bucket(float value) {
    float magnitude = fabsf(value);
    int bucket;

    if (magnitude <= 0.0f) {
        return 0u;
    }
    bucket = (int)(magnitude * 100.0f + 0.5f);
    if (bucket < 1) {
        return 1u;
    }
    if (bucket > 255) {
        return 255u;
    }
    return (uint8_t)bucket;
}

static void qihse_bench_fill_magnitude_skew(float* rows,
                                            float* query,
                                            uint64_t* ids) {
    size_t row;
    size_t dim;

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        float sign = (dim % 2u == 0u) ? 1.0f : -1.0f;
        query[dim] = sign * (dim < 8u ? 10.0f : 0.1f);
    }

    for (row = 0u; row < QIHSE_BENCH_ROWS; row++) {
        ids[row] = 3100000u + (uint64_t)row;
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            float sign = query[dim] > 0.0f ? 1.0f : -1.0f;
            rows[(row * QIHSE_BENCH_DIMS) + dim] = -sign * 0.05f;
        }
    }

    for (row = 0u; row < 96u && row < QIHSE_BENCH_ROWS; row++) {
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            float sign = query[dim] > 0.0f ? 1.0f : -1.0f;
            rows[(row * QIHSE_BENCH_DIMS) + dim] = sign;
        }
    }

    for (row = 0u; row < QIHSE_BENCH_TOPK && 256u + row < QIHSE_BENCH_ROWS; row++) {
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            float sign = query[dim] > 0.0f ? 1.0f : -1.0f;
            if (dim < 8u) {
                rows[((256u + row) * QIHSE_BENCH_DIMS) + dim] =
                    sign * (10.0f - ((float)row * 0.01f));
            } else {
                rows[((256u + row) * QIHSE_BENCH_DIMS) + dim] = -sign * 0.1f;
            }
        }
    }
}

static void qihse_bench_fill_near_tie(float* rows,
                                      float* query,
                                      uint64_t* ids) {
    size_t row;
    size_t dim;

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        query[dim] = 1.0f;
    }

    for (row = 0u; row < QIHSE_BENCH_ROWS; row++) {
        ids[row] = 4100000u + (uint64_t)row;
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            rows[(row * QIHSE_BENCH_DIMS) + dim] = -1.0f;
        }
    }

    for (row = 0u; row < 96u && row < QIHSE_BENCH_ROWS; row++) {
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            rows[(row * QIHSE_BENCH_DIMS) + dim] =
                dim < 8u ? 0.70f : 1.0f;
        }
    }

    for (row = 0u; row < QIHSE_BENCH_TOPK && 256u + row < QIHSE_BENCH_ROWS; row++) {
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            rows[((256u + row) * QIHSE_BENCH_DIMS) + dim] =
                dim == row ? 1.0f - ((float)row * 0.001f) : 1.0f;
        }
    }
}

static void qihse_bench_fill_data(float* rows, float* query, uint64_t* ids) {
    qihse_bench_dataset_t dataset = qihse_bench_dataset();
    size_t row;
    size_t dim;

    if (dataset == QIHSE_BENCH_DATASET_MAGNITUDE_SKEW) {
        qihse_bench_fill_magnitude_skew(rows, query, ids);
        return;
    }
    if (dataset == QIHSE_BENCH_DATASET_NEAR_TIE) {
        qihse_bench_fill_near_tie(rows, query, ids);
        return;
    }

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        query[dim] = qihse_bench_query_value(dataset, dim);
    }

    for (row = 0u; row < QIHSE_BENCH_ROWS; row++) {
        ids[row] = 100000u + ((uint64_t)dataset * 1000000u) + (uint64_t)row;
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            uint32_t mixed = qihse_bench_mix32((uint32_t)((row + 17u) * 131u +
                                                          (dim + 5u) * 977u +
                                                          ((uint32_t)dataset * 65537u)));
            uint32_t bucket = mixed % (dataset == QIHSE_BENCH_DATASET_ALIGNED ? 5u : 7u);
            float value = 0.0f;

            if (bucket == 0u || bucket == 1u ||
                (dataset == QIHSE_BENCH_DATASET_WEIGHTED && bucket == 2u)) {
                value = query[dim];
            } else if (bucket == 2u || bucket == 3u || bucket == 4u) {
                value = -query[dim];
            }
            if (dataset == QIHSE_BENCH_DATASET_WEIGHTED && value != 0.0f) {
                value *= (dim % 7u == 0u) ? 2.0f : 0.75f;
            }
            rows[(row * QIHSE_BENCH_DIMS) + dim] = value;
        }
    }

    for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
        float scale = dataset == QIHSE_BENCH_DATASET_WEIGHTED && dim % 7u == 0u ? 2.0f : 1.0f;
        rows[dim] = query[dim] * scale;
        rows[QIHSE_BENCH_DIMS + dim] = dim == 7u ? 0.0f : query[dim] * scale;
        rows[(2u * QIHSE_BENCH_DIMS) + dim] = dim == 11u ? -query[dim] : query[dim] * scale;
        rows[(3u * QIHSE_BENCH_DIMS) + dim] =
            (dim == 13u || dim == 17u) ? -query[dim] : query[dim] * scale;
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

static int64_t qihse_bench_candidate_score_for_row(const size_t* candidate_rows,
                                                   const int64_t* candidate_scores,
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

static int qihse_bench_build_magnitude_buckets(
    const qihse_vector_store_snapshot_t* snapshot,
    uint8_t* out_buckets) {
    size_t row_index;

    if (!snapshot || !out_buckets) {
        errno = EINVAL;
        return 0;
    }
    for (row_index = 0u; row_index < snapshot->row_count; row_index++) {
        const qihse_index_row_t* row = snapshot->rows + row_index;
        const float* vector =
            qihse_bench_snapshot_vector_at(snapshot, row, QIHSE_BENCH_DIMS);
        size_t dim;

        if (!vector) {
            errno = EINVAL;
            return 0;
        }
        for (dim = 0u; dim < QIHSE_BENCH_DIMS; dim++) {
            out_buckets[(row_index * QIHSE_BENCH_DIMS) + dim] =
                qihse_bench_magnitude_bucket(vector[dim]);
        }
    }
    return 1;
}

static int qihse_bench_build_signed_trits(const uint8_t* encoded_rows,
                                          size_t row_count,
                                          size_t dims,
                                          int8_t* out_trits) {
    size_t row_bytes;
    size_t row;

    if (!out_trits) {
        errno = EINVAL;
        return 0;
    }
    if (!qihse_trinary_tryte_row_bytes(dims, &row_bytes)) {
        return 0;
    }
    if (!encoded_rows && row_count != 0u && row_bytes != 0u) {
        errno = EINVAL;
        return 0;
    }
    for (row = 0u; row < row_count; row++) {
        size_t dim = 0u;
        size_t byte_index;

        for (byte_index = 0u; byte_index < row_bytes; byte_index++) {
            uint8_t trits[QIHSE_TRINARY_TRITS_PER_TRYTE];
            size_t trit_index;

            if (!qihse_trinary_tryte_unpack(encoded_rows[(row * row_bytes) + byte_index],
                                            trits)) {
                return 0;
            }
            for (trit_index = 0u; trit_index < QIHSE_TRINARY_TRITS_PER_TRYTE &&
                                  dim < dims;
                 trit_index++, dim++) {
                uint8_t trit = trits[trit_index];
                out_trits[(row * dims) + dim] =
                    trit == 0u ? -1 : trit == 2u ? 1 : 0;
            }
        }
    }
    return 1;
}

static int qihse_bench_select_topk_magnitude(
    const int8_t* row_trits,
    const int8_t* query_trits,
    const int32_t* dim_weights,
    const uint8_t* magnitude_buckets,
    size_t row_count,
    size_t dims,
    size_t* out_row_indexes,
    int64_t* out_scores,
    size_t max_results,
    size_t* out_count) {
    size_t selected = 0u;
    size_t row;

    if (!out_count) {
        errno = EINVAL;
        return 0;
    }
    *out_count = 0u;
    if ((!row_trits || !query_trits || !dim_weights || !magnitude_buckets) &&
        dims != 0u) {
        errno = EINVAL;
        return 0;
    }
    if ((!out_row_indexes || !out_scores) && max_results != 0u) {
        errno = EINVAL;
        return 0;
    }
    if (row_count == 0u || max_results == 0u) {
        return 1;
    }

    for (row = 0u; row < row_count; row++) {
        int64_t score = 0;
        size_t dim;
        size_t insert_at;

        for (dim = 0u; dim < dims; dim++) {
            score += (int64_t)row_trits[(row * dims) + dim] *
                     (int64_t)query_trits[dim] *
                     (int64_t)dim_weights[dim] *
                     (int64_t)magnitude_buckets[(row * dims) + dim];
        }

        insert_at = selected;
        while (insert_at > 0u &&
               (score > out_scores[insert_at - 1u] ||
                (score == out_scores[insert_at - 1u] &&
                 row < out_row_indexes[insert_at - 1u]))) {
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
                out_row_indexes[move] = out_row_indexes[move - 1u];
                out_scores[move] = out_scores[move - 1u];
            }
        }
        out_row_indexes[insert_at] = row;
        out_scores[insert_at] = score;
    }

    *out_count = selected;
    return 1;
}

int main(void) {
    qihse_bench_dataset_t dataset = qihse_bench_dataset();
    const int sweep_enabled = qihse_bench_sweep_enabled();
    const qihse_bench_score_mode_t score_mode = qihse_bench_score_mode();
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
    size_t* candidate_rows = NULL;
    int64_t* candidate_scores = NULL;
    int32_t* scalar_candidate_scores = NULL;
    uint8_t* magnitude_buckets = NULL;
    int8_t* row_trits = NULL;
    int8_t query_trits[QIHSE_BENCH_DIMS];
    int32_t dim_weights[QIHSE_BENCH_DIMS];
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
    size_t sweep_candidates[] = {
        QIHSE_BENCH_TOPK,
        16u,
        32u,
        64u,
        128u,
        256u,
        512u,
        1024u,
        QIHSE_BENCH_ROWS
    };
    size_t sweep_len = sizeof(sweep_candidates) / sizeof(sweep_candidates[0]);
    size_t candidate_passes = sweep_enabled ? sweep_len : 1u;
    size_t pass;
    int exit_code = 1;

    memset(&snapshot, 0, sizeof(snapshot));
    rows = (float*)calloc(QIHSE_BENCH_ROWS * QIHSE_BENCH_DIMS, sizeof(float));
    ids = (uint64_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*ids));
    full_results = (qihse_vector_result_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*full_results));
    candidate_rows = (size_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*candidate_rows));
    candidate_scores = (int64_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*candidate_scores));
    scalar_candidate_scores =
        (int32_t*)calloc(QIHSE_BENCH_ROWS, sizeof(*scalar_candidate_scores));
    magnitude_buckets =
        (uint8_t*)calloc(QIHSE_BENCH_ROWS * QIHSE_BENCH_DIMS, sizeof(*magnitude_buckets));
    row_trits = (int8_t*)calloc(QIHSE_BENCH_ROWS * QIHSE_BENCH_DIMS, sizeof(*row_trits));
    if (!rows || !ids || !full_results || !candidate_rows || !candidate_scores ||
        !scalar_candidate_scores || !magnitude_buckets || !row_trits) {
        perror("calloc");
        goto cleanup;
    }
    qihse_bench_fill_data(rows, query, ids);
    for (i = 0u; i < QIHSE_BENCH_DIMS; i++) {
        dim_weights[i] = qihse_bench_weight_from_query(query[i]);
    }

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
    if (score_mode == QIHSE_BENCH_SCORE_MAGNITUDE &&
        (!qihse_bench_build_magnitude_buckets(&snapshot, magnitude_buckets) ||
         !qihse_bench_build_signed_trits(snapshot.trinary,
                                         snapshot.row_count,
                                         QIHSE_BENCH_DIMS,
                                         row_trits) ||
         !qihse_bench_build_signed_trits(encoded_query,
                                         1u,
                                         QIHSE_BENCH_DIMS,
                                         query_trits))) {
        perror("build magnitude sidecar inputs");
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

    if (!qihse_bench_exact_rank(&snapshot,
                                query,
                                NULL,
                                snapshot.row_count,
                                oracle,
                                QIHSE_BENCH_TOPK,
                                &oracle_count) ||
        !qihse_bench_verify_full_search(full_results, full_count, oracle, oracle_count)) {
        goto cleanup;
    }

    for (pass = 0u; pass < candidate_passes; pass++) {
        size_t candidate_limit = sweep_enabled
            ? sweep_candidates[pass]
            : QIHSE_BENCH_CANDIDATES;

        if (candidate_limit < QIHSE_BENCH_TOPK) {
            candidate_limit = QIHSE_BENCH_TOPK;
        }
        if (candidate_limit > QIHSE_BENCH_ROWS) {
            candidate_limit = QIHSE_BENCH_ROWS;
        }
        if (pass > 0u && candidate_limit == sweep_candidates[pass - 1u]) {
            continue;
        }

        memset(candidate_rows, 0, QIHSE_BENCH_ROWS * sizeof(*candidate_rows));
        memset(candidate_scores, 0, QIHSE_BENCH_ROWS * sizeof(*candidate_scores));
        memset(scalar_candidate_scores,
               0,
               QIHSE_BENCH_ROWS * sizeof(*scalar_candidate_scores));

        select_start = qihse_bench_seconds();
        for (iter = 0u; iter < QIHSE_BENCH_ITERS; iter++) {
            if (score_mode == QIHSE_BENCH_SCORE_MAGNITUDE) {
                if (!qihse_bench_select_topk_magnitude(row_trits,
                                                       query_trits,
                                                       dim_weights,
                                                       magnitude_buckets,
                                                       snapshot.row_count,
                                                       QIHSE_BENCH_DIMS,
                                                       candidate_rows,
                                                       candidate_scores,
                                                       candidate_limit,
                                                       &candidate_count)) {
                    perror("qihse_bench_select_topk_magnitude");
                    goto cleanup;
                }
            } else if (score_mode == QIHSE_BENCH_SCORE_WEIGHTED) {
                if (!qihse_trinary_tryte_select_topk_weighted(snapshot.trinary,
                                                              encoded_query,
                                                              dim_weights,
                                                              snapshot.row_count,
                                                              QIHSE_BENCH_DIMS,
                                                              candidate_rows,
                                                              candidate_scores,
                                                              candidate_limit,
                                                              &candidate_count)) {
                    perror("qihse_trinary_tryte_select_topk_weighted");
                    goto cleanup;
                }
            } else {
                if (!qihse_trinary_tryte_select_topk(snapshot.trinary,
                                                     encoded_query,
                                                     snapshot.row_count,
                                                     QIHSE_BENCH_DIMS,
                                                     candidate_rows,
                                                     scalar_candidate_scores,
                                                     candidate_limit,
                                                     &candidate_count)) {
                    perror("qihse_trinary_tryte_select_topk");
                    goto cleanup;
                }
                for (i = 0u; i < candidate_count; i++) {
                    candidate_scores[i] = (int64_t)scalar_candidate_scores[i];
                }
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

        if (!sweep_enabled &&
            qihse_bench_dataset_requires_perfect(dataset, candidate_count) &&
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

        printf("%s dataset=%s score=%s rows=%u dims=%u qtri_row_bytes=%zu "
               "candidates=%zu topk=%u iterations=%u\n",
               sweep_enabled ? "trinary_search_path_sweep" : "trinary_search_path_bench",
               qihse_bench_dataset_name(dataset),
               qihse_bench_score_mode_name(score_mode),
               (unsigned)QIHSE_BENCH_ROWS,
               (unsigned)QIHSE_BENCH_DIMS,
               row_bytes,
               candidate_limit,
               (unsigned)QIHSE_BENCH_TOPK,
               (unsigned)QIHSE_BENCH_ITERS);
        printf("load_ms=%.3f full_float32_avg_us=%.3f trinary_select_avg_us=%.3f "
               "exact_rerank_avg_us=%.3f trinary_rerank_avg_us=%.3f "
               "speedup_vs_full=%.3fx recall_at_%u=%.3f ordered_at_%u=%.3f "
               "perfect_required=%s checksum=%lld\n",
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
               !sweep_enabled &&
                       qihse_bench_dataset_requires_perfect(dataset, candidate_count)
                   ? "yes"
                   : "no",
               (long long)checksum);
        if (!sweep_enabled) {
            for (i = 0u; i < reranked_count; i++) {
                printf("result[%zu] row=%zu id=%llu tri_score=%lld exact_score=%.6f\n",
                       i,
                       reranked[i].row_index,
                       (unsigned long long)reranked[i].id,
                       (long long)qihse_bench_candidate_score_for_row(
                           candidate_rows,
                           candidate_scores,
                           candidate_count,
                           reranked[i].row_index),
                       reranked[i].score);
            }
        }
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
    free(candidate_scores);
    free(scalar_candidate_scores);
    free(magnitude_buckets);
    free(row_trits);
    free(candidate_rows);
    free(ids);
    free(full_results);
    free(rows);
    return exit_code;
}
