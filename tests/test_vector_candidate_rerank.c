#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_container_keys_fixture.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "persistence/qihse_vector_store.h"

#include <assert.h>
#include <errno.h>
#include <float.h>
#include <ftw.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Both selectors initially prefer row 100: the min/max INT8 dot product
 * prefers its negative first coordinate, and binary Hamming prefers ++ over
 * +-. Exact DOT and COSINE prefer row 101. The entire two-row pool must be
 * reranked even for top_k=1. Neither INT8 endpoint incurs rounding error. */
static const float vectors[2][2] = {{100.0f, 100.0f}, {101.0f, -100.0f}};
static const float needle[2] = {100.0f, 0.01f};
static const uint64_t ids[2] = {100u, 101u};
static const char *labels[2] = {"first", "second"};

static float oracle_score(size_t row, qihse_distance_metric_t metric) {
    const float *v = vectors[row];
    float dot = needle[0] * v[0] + needle[1] * v[1];
    if (metric == QIHSE_DISTANCE_DOT_PRODUCT) return dot;
    if (metric == QIHSE_DISTANCE_EUCLIDEAN) {
        float dx = needle[0] - v[0], dy = needle[1] - v[1];
        return 1.0f / (1.0f + sqrtf(dx * dx + dy * dy));
    }
    return dot / (hypotf(needle[0], needle[1]) * hypotf(v[0], v[1]));
}

static bool first_only(const void *metadata, size_t size, void *opaque) {
    (void)opaque;
    return size == sizeof("first") && memcmp(metadata, "first", size) == 0;
}

static void free_results(qihse_vector_result_t *results, int count) {
    for (int i = 0; i < count; ++i) {
        free(results[i].vector);
        free(results[i].metadata);
    }
}

static void check_results(qihse_vector_db_t db, qihse_vector_query_t *query,
                          size_t expected_first, size_t expected_count) {
    qihse_vector_result_t results[2] = {0};
    /* Exercise the selector on every call rather than a cached result. */
    qihse_vector_db_clear_cache(db);
    int count = qihse_vector_db_search(db, query, results, 2u);
    if (count != (int)expected_count || results[0].id != ids[expected_first]) {
        fprintf(stderr, "mode=%d metric=%d top_k=%zu expected=%llu got=%llu count=%d errno=%d\n",
                (int)query->query_mode, (int)query->distance_metric, query->top_k,
                (unsigned long long)ids[expected_first],
                (unsigned long long)(count > 0 ? results[0].id : 0u), count, errno);
    }
    assert(count == (int)expected_count);
    for (int i = 0; i < count; ++i) {
        size_t row = i == 0 ? expected_first : 1u - expected_first;
        float expected_score = oracle_score(row, query->distance_metric);
        assert(results[i].id == ids[row]);
        assert(fabsf(results[i].score - expected_score) <= 1e-5f * fmaxf(1.0f, fabsf(expected_score)));
        assert(results[i].vector_dims == 2u && results[i].vector);
        assert(memcmp(results[i].vector, vectors[row], sizeof(vectors[row])) == 0);
        assert(results[i].metadata_size == strlen(labels[row]) + 1u);
        assert(memcmp(results[i].metadata, labels[row], results[i].metadata_size) == 0);
    }
    free_results(results, count);
}

static void test_selectors(qihse_user_t *operator_user) {
    const void *metadata[2] = {labels[0], labels[1]};
    const size_t metadata_sizes[2] = {sizeof("first"), sizeof("second")};
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(db);
    assert(qihse_vector_db_add_vectors(db, &vectors[0][0], 2u, 2u, ids,
                                        metadata, metadata_sizes));
    assert(qihse_vector_db_build_int8(db));
    assert(qihse_vector_db_build_binary(db));

    const qihse_vector_db_query_mode_t modes[2] = {
        QIHSE_VDB_QUERY_INT8, QIHSE_VDB_QUERY_BINARY
    };
    for (size_t m = 0; m < 2u; ++m) {
        qihse_vector_query_t query = {0};
        query.query_vector = needle;
        query.vector_dims = 2u;
        query.candidate_pool_size = 2u;
        query.query_mode = modes[m];
        query.similarity_threshold = -FLT_MAX;
        query.include_vectors = true;
        query.include_metadata = true;
        query.user = operator_user;
        for (int metric = QIHSE_DISTANCE_COSINE;
             metric <= QIHSE_DISTANCE_EUCLIDEAN; ++metric) {
            query.distance_metric = (qihse_distance_metric_t)metric;
            size_t winner = oracle_score(1u, query.distance_metric) >
                            oracle_score(0u, query.distance_metric) ? 1u : 0u;
            query.top_k = 1u;
            check_results(db, &query, winner, 1u);
            query.top_k = 2u;
            check_results(db, &query, winner, 2u);
        }
        query.top_k = 1u;
        query.distance_metric = QIHSE_DISTANCE_DOT_PRODUCT;
        query.metadata_filter = first_only;
        check_results(db, &query, 0u, 1u);

        /* Extending rerank must retain the existing public identity boundary. */
        qihse_vector_result_t denied[2] = {0};
        query.user = NULL;
        errno = 0;
        assert(qihse_vector_db_search(db, &query, denied, 2u) == -1);
        assert(errno == EACCES && !denied[0].vector && !denied[0].metadata);
    }
    qihse_vector_db_destroy(db);
}

static void test_binary_clearance(const char *root, qihse_user_t *operator_user) {
    char path[512];
    assert(snprintf(path, sizeof(path), "%s/binary-clearance.qdb", root) < (int)sizeof(path));
    qihse_user_t *guest = qihse_auth_create_user(operator_user, 771u,
        QIHSE_ROLE_GUEST, QIHSE_CLASS_UNCLASSIFIED, QIHSE_SCI_NONE,
        "BinaryCandidateGuest123!", false);
    assert(guest);
    assert(!qihse_auth_can_access(guest, QIHSE_CLASS_SECRET, QIHSE_SCI_SI));
    assert(qihse_auth_can_access(operator_user, QIHSE_CLASS_SECRET, QIHSE_SCI_SI));

    /* The hidden row has strictly better Hamming distance and exact score.
     * A pool of one must still return the visible row for the guest. */
    const float protected_vectors[4] = {100.0f, 100.0f, 1.0f, -0.1f};
    const char protected_metadata[] = "protected\0public";
    qihse_index_row_t rows[2] = {0};
    rows[0].vector_id = 900u;
    rows[0].row_flags = QIHSE_ROW_F_LIVE;
    rows[0].commit_generation = 1u;
    rows[0].classification = QIHSE_CLASS_SECRET;
    rows[0].sci_compartment = QIHSE_SCI_SI;
    rows[0].metadata_size = sizeof("protected");
    rows[1].vector_id = 901u;
    rows[1].vector_offset = 2u * sizeof(float);
    rows[1].row_flags = QIHSE_ROW_F_LIVE;
    rows[1].commit_generation = 1u;
    rows[1].classification = QIHSE_CLASS_UNCLASSIFIED;
    rows[1].sci_compartment = QIHSE_SCI_NONE;
    rows[1].metadata_offset = sizeof("protected");
    rows[1].metadata_size = sizeof("public");
    qihse_vector_store_flush_t flush = {0};
    flush.vector_dims = 2u;
    flush.commit_generation = 1u;
    flush.rows = rows;
    flush.row_count = 2u;
    flush.vectors = protected_vectors;
    flush.vector_bytes = sizeof(protected_vectors);
    flush.metadata = protected_metadata;
    flush.metadata_bytes = sizeof(protected_metadata);
    assert(qihse_vector_store_flush(path, &flush));
    qihse_vector_db_t db = qihse_vector_db_open(QIHSE_VECTOR_DB_INMEMORY,
        NULL, path, QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db && qihse_vector_db_build_binary(db));

    const float q[2] = {1.0f, 1.0f};
    qihse_vector_query_t query = {0};
    query.query_vector = q;
    query.vector_dims = 2u;
    query.query_mode = QIHSE_VDB_QUERY_BINARY;
    query.distance_metric = QIHSE_DISTANCE_DOT_PRODUCT;
    query.candidate_pool_size = query.top_k = 1u;
    query.include_vectors = query.include_metadata = true;
    query.similarity_threshold = -FLT_MAX;
    qihse_vector_result_t results[2] = {0};

    query.user = operator_user;
    int count = qihse_vector_db_search(db, &query, results, 2u);
    assert(count == 1 && results[0].id == 900u);
    free_results(results, count);
    memset(results, 0, sizeof(results));
    qihse_vector_db_clear_cache(db);
    query.user = guest;
    count = qihse_vector_db_search(db, &query, results, 2u);
    assert(count == 1 && results[0].id == 901u);
    assert(results[0].vector_dims == 2u && results[0].vector);
    assert(memcmp(results[0].vector, protected_vectors + 2u, 2u * sizeof(float)) == 0);
    assert(results[0].metadata_size == sizeof("public"));
    assert(memcmp(results[0].metadata, "public", sizeof("public")) == 0);
    free_results(results, count);

    /* Direct public candidate entry points also require an explicit user. */
    query.user = NULL;
    memset(results, 0, sizeof(results));
    errno = 0;
    assert(qihse_vector_db_search_binary_candidates(db, &query, 1u, results, 2u) == -1);
    assert(errno == EACCES && !results[0].vector && !results[0].metadata);
    qihse_vector_db_destroy(db);
}

static int remove_entry(const char *path, const struct stat *info, int type,
                        struct FTW *walk) {
    (void)info; (void)type; (void)walk;
    return remove(path);
}

int main(void) {
    char root[] = "tests/vector-candidate-rerank-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    qihse_test_container_keys(root);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("VectorCandidateRerank123!"));
    qihse_user_t *operator_user = qihse_auth_get_user(0u);
    assert(operator_user);
    test_selectors(operator_user);
    test_binary_clearance(root, operator_user);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("PASS full-pool exact rerank, metrics, payloads, filters, and binary clearance boundary");
    return 0;
}
