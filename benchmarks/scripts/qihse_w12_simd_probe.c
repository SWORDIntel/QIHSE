/* Standalone W12.4 investigation of the experimental W12.1 scalar codec.
 * No database access or production dispatch is exercised. */
#include "qihse_turboquant.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static uint64_t rng(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return *state = x;
}

int main(int argc, char** argv) {
    if (argc != 4) return 2;
    char* end = NULL;
    unsigned long dim = strtoul(argv[1], &end, 10);
    if (!end || *end || dim < 2 || dim > QIHSE_TQ_MAX_DIMENSIONS) return 2;
    unsigned long enc_reps = strtoul(argv[2], &end, 10);
    if (!end || *end || !enc_reps || enc_reps > 1000000) return 2;
    unsigned long score_reps = strtoul(argv[3], &end, 10);
    if (!end || *end || !score_reps || score_reps > 100000000) return 2;

    qihse_tq_config config = {
        .dimensions = (uint32_t)dim, .scalar_bits = 4,
        .variant = QIHSE_TQ_PRODUCT, .rotation_seed = 42,
        .projection_seed = 43,
    };
    size_t bytes = 0;
    if (qihse_tq_code_size(&config, &bytes)) return 1;
    float* vector = malloc(dim * sizeof *vector);
    float* query_vector = malloc(dim * sizeof *query_vector);
    uint8_t* code = malloc(bytes);
    if (!vector || !query_vector || !code) return 1;
    uint64_t seed = UINT64_C(20261106);
    for (size_t i = 0; i < dim; ++i) {
        vector[i] = (float)((int)(rng(&seed) % 2001u) - 1000) / 1000.0f;
        query_vector[i] = (float)((int)(rng(&seed) % 2001u) - 1000) / 1000.0f;
    }
    qihse_tq_profile* profile = NULL;
    uint64_t started = now_ns();
    if (qihse_tq_profile_create(&config, &profile)) return 1;
    uint64_t setup_ns = now_ns() - started;
    started = now_ns();
    for (unsigned long i = 0; i < enc_reps; ++i)
        if (qihse_tq_encode(profile, vector, dim, code, bytes)) return 1;
    uint64_t encode_ns = now_ns() - started;
    qihse_tq_query* query = NULL;
    started = now_ns();
    if (qihse_tq_prepare_query(profile, query_vector, dim, &query)) return 1;
    uint64_t prepare_ns = now_ns() - started;
    volatile double sink = 0;
    started = now_ns();
    for (unsigned long i = 0; i < score_reps; ++i) {
        double score = 0;
        if (qihse_tq_score(profile, query, code, bytes, QIHSE_TQ_DOT, &score)) return 1;
        sink += score;
    }
    uint64_t score_ns = now_ns() - started;
    printf("{\"dimensions\":%lu,\"code_bytes\":%zu,\"matrix_bytes\":%zu,"
           "\"setup_ms\":%.3f,\"encode_reps\":%lu,\"encode_us\":%.3f,"
           "\"prepare_us\":%.3f,\"score_reps\":%lu,\"score_ns\":%.3f,"
           "\"sink\":%.9g}\n", dim, bytes, qihse_tq_profile_matrix_bytes(profile),
           setup_ns / 1e6, enc_reps, encode_ns / (double)enc_reps / 1e3,
           prepare_ns / 1e3, score_reps, score_ns / (double)score_reps,
           (double)sink);
    qihse_tq_query_destroy(query);
    qihse_tq_profile_destroy(profile);
    free(code); free(query_vector); free(vector);
    return 0;
}
