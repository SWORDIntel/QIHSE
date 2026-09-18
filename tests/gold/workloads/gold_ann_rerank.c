/*
 * gold_ann_rerank.c — gold workload (area: ann-rerank).
 *
 * Exercises the approximate-nearest-neighbour candidate path and its exact
 * float32 rerank through the public vector DB API, on a deterministic fixture
 * generated in-process (no external dataset, no absolute paths):
 *
 *   1. exact float32 search must agree with a brute-force scan computed here
 *      (ids and scores), for top_k = 10 over 512 rows;
 *   2. the graph (ANN) candidate path must find at least the declared recall
 *      floor against that brute-force ground truth, and every row it returns
 *      must carry the EXACT float32 score of the row it names — this is the
 *      rerank claim: candidates are selected approximately, scored exactly;
 *   3. a deleted row must never be returned by the ANN path after the graph is
 *      rebuilt (live-row awareness, not just candidate caching);
 *   4. the metadata filter must be honoured on the ANN path.
 *
 * The graph build consumes rand(); the workload seeds it so the fixture and
 * the recall figure are reproducible.
 *
 * Exit status: 0 = every check held; non-zero = the claimed behaviour is
 * absent.  The runner additionally requires the final PASS line.
 */
#include "qihse_abi.h"
#include "qihse_memory.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "qihse_cpu_distance.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOLD_ROWS   512u
#define GOLD_DIMS   16u
#define GOLD_TOP_K  10u
#define GOLD_EF     64u
#define GOLD_M      16u
#define GOLD_RECALL_FLOOR 0.9

typedef struct gold_ann_s {
    qihse_vector_db_t db;
    float* vectors;          /* GOLD_ROWS * GOLD_DIMS, row-major */
    uint64_t* ids;
    unsigned char* tags;     /* metadata byte per row */
    float query[GOLD_DIMS];
    qihse_user_t* user;
} gold_ann_t;

static int fail(const char* what) {
    fprintf(stderr, "gold_ann_rerank: FAIL: %s (errno=%d %s)\n",
            what, errno, strerror(errno));
    return 1;
}

/* Deterministic vector fixture: a private LCG, so the library's own rand()
 * stream (used by the graph builder) is not perturbed by fixture generation. */
static void fill_fixture(gold_ann_t* ann) {
    uint32_t seed = 0x9E3779B9u;
    for (size_t i = 0; i < GOLD_ROWS * GOLD_DIMS; i++) {
        seed = seed * 1664525u + 1013904223u;
        ann->vectors[i] = ((float)(int)(seed % 2001u) - 1000.0f) / 1000.0f;
    }
    for (size_t row = 0; row < GOLD_ROWS; row++) {
        ann->ids[row] = 1000u + row;
        ann->tags[row] = (unsigned char)(row % 2u);
    }
    /* Query: row 7 plus a small deterministic perturbation, so it is close to
     * a known row without being identical to it. */
    for (size_t d = 0; d < GOLD_DIMS; d++) {
        ann->query[d] = ann->vectors[7u * GOLD_DIMS + d] + (float)((int)d - 8) * 0.001f;
    }
}

static bool keep_even(const void* metadata, size_t size, void* opaque) {
    (void)opaque;
    return size == 1u && *(const unsigned char*)metadata == 0u;
}

static void free_results(qihse_vector_result_t* results, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(results[i].vector);
        free(results[i].metadata);
        results[i].vector = NULL;
        results[i].metadata = NULL;
    }
}

/* ── Check 1: exact float32 parity with a brute-force scan ──────────────── */
static int check_exact_parity(gold_ann_t* ann) {
    size_t truth[GOLD_TOP_K];
    bool used[GOLD_ROWS];
    float truth_scores[GOLD_TOP_K];
    memset(used, 0, sizeof(used));

    for (size_t rank = 0; rank < GOLD_TOP_K; rank++) {
        size_t best = GOLD_ROWS;
        float best_score = 0.0f;
        for (size_t row = 0; row < GOLD_ROWS; row++) {
            if (used[row]) continue;
            float score = qihse_distance_cosine(ann->query,
                                                ann->vectors + row * GOLD_DIMS,
                                                GOLD_DIMS);
            if (best == GOLD_ROWS || score > best_score) {
                best = row;
                best_score = score;
            }
        }
        truth[rank] = best;
        truth_scores[rank] = best_score;
        used[best] = true;
    }

    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = ann->query;
    query.vector_dims = GOLD_DIMS;
    query.top_k = GOLD_TOP_K;
    query.similarity_threshold = -1.0f;
    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.user = ann->user;

    qihse_vector_result_t results[GOLD_TOP_K];
    memset(results, 0, sizeof(results));
    int count = qihse_vector_db_search(ann->db, &query, results, GOLD_TOP_K);
    if (count != (int)GOLD_TOP_K) {
        fprintf(stderr,
                "gold_ann_rerank: FAIL: exact search returned %d rows "
                "(expected %u)\n", count, GOLD_TOP_K);
        return 1;
    }
    for (size_t rank = 0; rank < GOLD_TOP_K; rank++) {
        if (results[rank].id != ann->ids[truth[rank]]) {
            fprintf(stderr,
                    "gold_ann_rerank: FAIL: exact rank %zu is id=%llu, brute "
                    "force says id=%llu\n", rank,
                    (unsigned long long)results[rank].id,
                    (unsigned long long)ann->ids[truth[rank]]);
            free_results(results, GOLD_TOP_K);
            return 1;
        }
        if (memcmp(&results[rank].score, &truth_scores[rank], sizeof(float)) != 0) {
            fprintf(stderr,
                    "gold_ann_rerank: FAIL: exact rank %zu score %.9g != "
                    "brute-force %.9g\n", rank, (double)results[rank].score,
                    (double)truth_scores[rank]);
            free_results(results, GOLD_TOP_K);
            return 1;
        }
    }
    free_results(results, GOLD_TOP_K);
    printf("  check 1: exact float32 top-%u matched the brute-force scan "
           "(ids and scores)\n", GOLD_TOP_K);
    return 0;
}

/* ── Checks 2-4: ANN candidates, exact rerank, liveness, filter ─────────── */
static int check_graph_ann(gold_ann_t* ann) {
    srand(12345u);                      /* graph levels are drawn from rand() */
    if (!qihse_vector_db_build_graph(ann->db, GOLD_M, GOLD_EF))
        return fail("qihse_vector_db_build_graph failed");

    size_t truth[GOLD_TOP_K];
    bool used[GOLD_ROWS];
    memset(used, 0, sizeof(used));
    for (size_t rank = 0; rank < GOLD_TOP_K; rank++) {
        size_t best = GOLD_ROWS;
        float best_score = 0.0f;
        for (size_t row = 0; row < GOLD_ROWS; row++) {
            if (used[row]) continue;
            float score = qihse_distance_cosine(ann->query,
                                                ann->vectors + row * GOLD_DIMS,
                                                GOLD_DIMS);
            if (best == GOLD_ROWS || score > best_score) {
                best = row;
                best_score = score;
            }
        }
        truth[rank] = best;
        used[best] = true;
    }

    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = ann->query;
    query.vector_dims = GOLD_DIMS;
    query.top_k = GOLD_TOP_K;
    query.similarity_threshold = -1.0f;
    query.query_mode = QIHSE_VDB_QUERY_GRAPH;
    query.candidate_pool_size = GOLD_EF;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.user = ann->user;

    qihse_vector_result_t results[GOLD_TOP_K];
    memset(results, 0, sizeof(results));
    int count = qihse_vector_db_search(ann->db, &query, results, GOLD_TOP_K);
    if (count <= 0) {
        fprintf(stderr, "gold_ann_rerank: FAIL: graph search returned %d\n", count);
        return 1;
    }

    size_t hits = 0;
    for (int i = 0; i < count; i++) {
        /* Rerank claim: the score must be the exact float32 cosine of the row
         * the result names.  A candidate-path score (trinary/magnitude/graph
         * distance) would not match this. */
        size_t row = (size_t)(results[i].id - 1000u);
        if (row >= GOLD_ROWS) {
            fprintf(stderr, "gold_ann_rerank: FAIL: graph search returned an "
                    "unknown id %llu\n", (unsigned long long)results[i].id);
            free_results(results, GOLD_TOP_K);
            return 1;
        }
        float exact = qihse_distance_cosine(ann->query,
                                            ann->vectors + row * GOLD_DIMS,
                                            GOLD_DIMS);
        if (memcmp(&results[i].score, &exact, sizeof(float)) != 0) {
            fprintf(stderr,
                    "gold_ann_rerank: FAIL: graph rank %d score %.9g is not the "
                    "exact float32 score %.9g of id=%llu (rerank not applied)\n",
                    i, (double)results[i].score, (double)exact,
                    (unsigned long long)results[i].id);
            free_results(results, GOLD_TOP_K);
            return 1;
        }
        for (size_t rank = 0; rank < GOLD_TOP_K; rank++)
            if (truth[rank] == row) hits++;
    }
    free_results(results, GOLD_TOP_K);

    double recall = (double)hits / (double)GOLD_TOP_K;
    if (recall < GOLD_RECALL_FLOOR) {
        fprintf(stderr,
                "gold_ann_rerank: FAIL: graph recall@%u = %.3f is below the "
                "declared floor %.2f\n", GOLD_TOP_K, recall, GOLD_RECALL_FLOOR);
        return 1;
    }
    printf("  check 2: graph ANN recall@%u = %.3f (floor %.2f); every returned "
           "row carried its exact float32 score\n",
           GOLD_TOP_K, recall, GOLD_RECALL_FLOOR);

    /* Check 3: a deleted row must disappear from the ANN path. */
    uint64_t victim = ann->ids[truth[0]];
    if (!qihse_vector_db_delete_by_id(ann->db, victim))
        return fail("delete_by_id failed");
    srand(12345u);
    if (!qihse_vector_db_build_graph(ann->db, GOLD_M, GOLD_EF))
        return fail("graph rebuild after delete failed");
    memset(results, 0, sizeof(results));
    count = qihse_vector_db_search(ann->db, &query, results, GOLD_TOP_K);
    if (count < 0) {
        fprintf(stderr, "gold_ann_rerank: FAIL: graph search after delete "
                "returned %d\n", count);
        return 1;
    }
    for (int i = 0; i < count; i++) {
        if (results[i].id == victim) {
            fprintf(stderr, "gold_ann_rerank: FAIL: deleted id %llu was still "
                    "returned by the ANN path\n", (unsigned long long)victim);
            free_results(results, GOLD_TOP_K);
            return 1;
        }
    }
    free_results(results, GOLD_TOP_K);
    printf("  check 3: deleted id %llu was not returned by the ANN path after "
           "the graph rebuild\n", (unsigned long long)victim);

    /* Check 4: the metadata filter must be honoured on the ANN path. */
    query.metadata_filter = keep_even;
    memset(results, 0, sizeof(results));
    count = qihse_vector_db_search(ann->db, &query, results, GOLD_TOP_K);
    if (count < 0) {
        fprintf(stderr, "gold_ann_rerank: FAIL: filtered graph search "
                "returned %d\n", count);
        return 1;
    }
    for (int i = 0; i < count; i++) {
        size_t row = (size_t)(results[i].id - 1000u);
        if (row >= GOLD_ROWS || ann->tags[row] != 0u) {
            fprintf(stderr, "gold_ann_rerank: FAIL: filtered graph search "
                    "returned id %llu, which does not pass the filter\n",
                    (unsigned long long)results[i].id);
            free_results(results, GOLD_TOP_K);
            return 1;
        }
    }
    free_results(results, GOLD_TOP_K);
    printf("  check 4: metadata filter honoured on the ANN path (%d rows)\n", count);
    return 0;
}

int main(void) {
    gold_ann_t ann;
    memset(&ann, 0, sizeof(ann));

    if (!qihse_auth_init()) return fail("qihse_auth_init failed");
    const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
    if (env_pw && *env_pw) ann.user = qihse_auth_authenticate_id(0, env_pw);
    if (!ann.user) {
        if (!qihse_auth_bootstrap_operator("gold-suite-test-password"))
            return fail("operator bootstrap failed");
        ann.user = qihse_auth_authenticate_id(0, "gold-suite-test-password");
    }
    if (!ann.user) return fail("no authenticated identity");

    qihse_context_t ctx;
    if (qihse_context_create(NULL, &ctx) != QIHSE_OK)
        return fail("qihse_context_create failed");
    qihse_memory_manager_t memory = qihse_memory_manager_create(ctx, "uma");
    if (!memory) return fail("memory manager create failed");
    qihse_uma_manager_t uma = qihse_uma_create(memory, QIHSE_UMA_MIGRATE_ON_ACCESS);
    if (!uma) return fail("uma create failed");

    ann.vectors = (float*)malloc(GOLD_ROWS * GOLD_DIMS * sizeof(float));
    ann.ids = (uint64_t*)malloc(GOLD_ROWS * sizeof(uint64_t));
    ann.tags = (unsigned char*)malloc(GOLD_ROWS);
    if (!ann.vectors || !ann.ids || !ann.tags) return fail("fixture allocation failed");
    fill_fixture(&ann);

    ann.db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, NULL);
    if (!ann.db) return fail("vector db create failed");

    /* Metadata pointers live on the heap: the fixture is large enough that
     * keeping the per-row arrays off the stack is the house rule. */
    const void** metadata = (const void**)malloc(GOLD_ROWS * sizeof(void*));
    size_t* metadata_sizes = (size_t*)malloc(GOLD_ROWS * sizeof(size_t));
    if (!metadata || !metadata_sizes) return fail("metadata allocation failed");
    for (size_t row = 0; row < GOLD_ROWS; row++) {
        metadata[row] = &ann.tags[row];
        metadata_sizes[row] = 1u;
    }
    bool added = qihse_vector_db_add_vectors(ann.db, ann.vectors, GOLD_ROWS,
                                             GOLD_DIMS, ann.ids, metadata,
                                             metadata_sizes);
    free(metadata);
    free(metadata_sizes);
    if (!added) return fail("add_vectors failed");

    int rc = 0;
    rc |= check_exact_parity(&ann);
    rc |= check_graph_ann(&ann);

    qihse_vector_db_destroy(ann.db);
    qihse_uma_destroy(uma);
    qihse_memory_manager_destroy(memory);
    qihse_context_destroy(ctx);
    free(ann.vectors);
    free(ann.ids);
    free(ann.tags);

    if (rc != 0) return 1;
    printf("gold_ann_rerank: PASS (exact parity, ANN recall floor, exact rerank "
           "scores, live-row and filter behaviour)\n");
    return 0;
}
