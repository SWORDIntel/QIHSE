#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "backends/cpu/qihse_cpu_distance.h"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double cpu_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts)) exit(1);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static bool keep_even(const void* metadata, size_t size, void* opaque) {
    (void)opaque;
    return size == 1 && *(const unsigned char*)metadata == 0;
}

int main(void) {
    /* Small dataset: per-row audit logging with ML-DSA-87 signing makes
     * larger row counts impractically slow for a correctness test. */
    enum { ROWS = 64, DIMS = 32, K = 5, ITERS = 3 };
    unsigned char random[24];
    char password[49];
    if (RAND_bytes(random, sizeof(random)) != 1) return 1;
    for (size_t i = 0; i < sizeof(random); i++) snprintf(password + i * 2, 3, "%02x", random[i]);
    if (!qihse_auth_init() || !qihse_auth_bootstrap_operator(password)) return 1;
    qihse_user_t* op = qihse_auth_authenticate_id(0, password);
    if (!op || !qihse_auth_create_user(op, 17, QIHSE_ROLE_GUEST, 0, 0, password, false)) return 1;
    qihse_user_t* user = qihse_auth_authenticate_id(17, password);
    OPENSSL_cleanse(password, sizeof(password));
    OPENSSL_cleanse(random, sizeof(random));
    if (!user || !qihse_auth_can_access(user, 0, 0) || qihse_user_get_role(user) != QIHSE_ROLE_GUEST) return 1;
    float* vectors = malloc(ROWS * DIMS * sizeof(float));
    uint64_t ids[ROWS];
    unsigned char tags[ROWS];
    const void* metadata[ROWS];
    size_t sizes[ROWS];
    float query_vector[DIMS];
    if (!vectors) return 1;
    uint32_t seed = 97;
    for (size_t i = 0; i < ROWS * DIMS; i++) {
        seed = seed * 1664525u + 1013904223u;
        vectors[i] = ((int)(seed % 257) - 128) * 0.0078125f;
    }
    /* Make row 1 identical to row 0 to exercise tie-breaking. */
    memcpy(vectors + DIMS, vectors, DIMS * sizeof(float));
    memcpy(query_vector, vectors, sizeof(query_vector));
    for (size_t i = 0; i < ROWS; i++) {
        ids[i] = ROWS - i;
        tags[i] = i % 2;
        metadata[i] = &tags[i];
        sizes[i] = 1;
    }
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!db || !qihse_vector_db_add_vectors(db, vectors, ROWS, DIMS, ids, metadata, sizes)) return 1;
    const qihse_distance_metric_t metrics[] = {QIHSE_DISTANCE_COSINE, QIHSE_DISTANCE_DOT_PRODUCT, QIHSE_DISTANCE_EUCLIDEAN};
    qihse_distance_fn_t functions[] = {qihse_distance_cosine, qihse_distance_dot, qihse_distance_euclidean};
    for (size_t metric = 0; metric < 3; metric++) {
        for (int filtered = 0; filtered < 2; filtered++) {
            qihse_vector_query_t query = {0};
            query.query_vector = query_vector;
            query.vector_dims = DIMS;
            query.top_k = K;
            query.similarity_threshold = -FLT_MAX;
            query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
            query.distance_metric = metrics[metric];
            query.user = user;
            query.metadata_filter = filtered ? keep_even : NULL;
            float scores[ROWS];
            size_t expected[K];
            bool used[ROWS] = {false};
            for (size_t row = 0; row < ROWS; row++) {
                scores[row] = functions[metric](query_vector, vectors + row * DIMS, DIMS);
                if (metrics[metric] == QIHSE_DISTANCE_EUCLIDEAN) scores[row] = 1.0f / (1.0f + scores[row]);
                used[row] = filtered && tags[row] != 0;
            }
            for (size_t rank = 0; rank < K; rank++) {
                size_t best = ROWS;
                for (size_t row = 0; row < ROWS; row++) {
                    if (!used[row] && (best == ROWS || scores[row] > scores[best])) best = row;
                }
                expected[rank] = best;
                used[best] = true;
            }
            qihse_vector_result_t results[K] = {0};
            double start = cpu_seconds();
            for (size_t iteration = 0; iteration < ITERS; iteration++) {
                int count = qihse_vector_db_search(db, &query, results, K);
                if (count != K) { fprintf(stderr, "search count=%d\n", count); return 1; }
                for (size_t rank = 0; rank < K; rank++) {
                    if (results[rank].id != ids[expected[rank]] ||
                        memcmp(&results[rank].score, &scores[expected[rank]], sizeof(float))) {
                        fprintf(stderr, "search parity mismatch metric=%zu filtered=%d rank=%zu\n", metric, filtered, rank);
                        return 1;
                    }
                }
            }
            printf("metric=%zu filtered=%d cpu_us=%.3f iterations=%d parity=PASS\n",
                   metric, filtered, (cpu_seconds() - start) * 1e6 / ITERS, ITERS);
            query.include_vectors = true;
            query.include_metadata = true;
            if (qihse_vector_db_search(db, &query, results, K) != K) return 1;
            for (size_t rank = 0; rank < K; rank++) {
                size_t row = expected[rank];
                if (!results[rank].vector || !results[rank].metadata || results[rank].metadata_size != 1 ||
                    memcmp(results[rank].vector, vectors + row * DIMS, DIMS * sizeof(float)) ||
                    memcmp(results[rank].metadata, &tags[row], 1)) return 1;
                free(results[rank].vector);
                free(results[rank].metadata);
            }
        }
    }
    qihse_vector_db_destroy(db);
    free(vectors);
    if (!qihse_auth_destroy_user(op, 17)) return 1;
    puts("PASS: guest exact-search scores, stable ties, filtering and materialization");
    return 0;
}
