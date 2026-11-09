/* W12.0 synthetic full-engine probe. All result data flows through
 * qihse_vector_db_search with an explicit operator principal. */
#define _GNU_SOURCE
#include "qihse_vector_db.h"
#include "qihse_auth.h"
#include "memory/include/qihse_memory.h"
#include "memory/include/qihse_uma.h"
#include "core/qihse_abi.h"
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static int read_exact(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n; }

int main(int argc, char **argv) {
    const uint16_t endian = 1;
    if (*(const uint8_t *)&endian != 1 || sizeof(float) != 4) {
        fprintf(stderr, "probe requires little-endian IEEE binary32 host\n");
        return 2;
    }
    if (argc != 5) {
        fprintf(stderr, "usage: %s fixture.bin mode repeats db.qdb\n", argv[0]);
        return 2;
    }
    int mode = atoi(argv[2]), repeats = atoi(argv[3]);
    if (mode < 0 || mode > 12 || repeats < 1 || repeats > 1000) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fixture"); return 2; }
    uint32_t shape[4];
    if (!read_exact(f, shape, sizeof shape) || shape[0] != 0x57313230u ||
        shape[1] < 1 || shape[1] > 100000 || shape[2] < 1 || shape[2] > 1536 ||
        shape[3] < 1 || shape[3] > 10000) return 2;
    size_t rows = shape[1], dims = shape[2], nq = shape[3];
    if (rows > SIZE_MAX / dims / sizeof(float) ||
        nq > SIZE_MAX / dims / sizeof(float)) return 2;
    float *vectors = malloc(rows * dims * sizeof(float));
    float *queries = malloc(nq * dims * sizeof(float));
    uint64_t *ids = malloc(rows * sizeof(uint64_t));
    if (!vectors || !queries || !ids ||
        !read_exact(f, vectors, rows * dims * sizeof(float)) ||
        !read_exact(f, queries, nq * dims * sizeof(float)) || fgetc(f) != EOF) return 2;
    fclose(f);
    for (size_t i = 0; i < rows; ++i) ids[i] = i + 1;
    setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 0);
    setenv("QIHSE_ENFORCE_INTEGRITY", "1", 1);
    if (!qihse_auth_init() || !qihse_auth_bootstrap_operator("W12SyntheticOnlyPass123!")) {
        fprintf(stderr, "auth bootstrap failed\n"); return 3;
    }
    qihse_user_t *user = qihse_auth_get_user(0);
    if (!user) return 3;
    qihse_context_t ctx = NULL;
    if (qihse_context_create(NULL, &ctx) != QIHSE_OK) return 3;
    qihse_memory_manager_t mem = qihse_memory_manager_create(ctx, "uma");
    qihse_uma_manager_t uma = mem ? qihse_uma_create(mem, QIHSE_UMA_MIGRATE_ON_ACCESS) : NULL;
    if (!uma) return 3;
    qihse_vector_db_t db = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, uma, argv[4]);
    if (!db || !qihse_vector_db_add_vectors(db, vectors, rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "database/add failed\n"); return 3;
    }
    if (!qihse_vector_db_flush(db)) { fprintf(stderr, "flush failed\n"); return 3; }
    uint64_t build_start = ns();
    int built = mode == 0;
    if (mode == 4) built = qihse_vector_db_build_graph(db, 16, 200);
    if (mode == 5) built = qihse_vector_db_build_int8(db);
    if (mode == 7) built = qihse_vector_db_build_fp16(db);
    if (mode == 8) built = qihse_vector_db_build_fp32(db);
    if (mode == 9) built = qihse_vector_db_build_fp8(db);
    if (mode == 10) built = qihse_vector_db_build_fp4(db);
    if (mode == 11) built = qihse_vector_db_build_int4(db);
    if (mode == 12) built = qihse_vector_db_build_binary(db);
    if (mode == 1 || mode == 2 || mode == 3) built = 1;
    if (!built) { fprintf(stderr, "sidecar build failed mode=%d errno=%d\n", mode, errno); return 3; }
    if (!qihse_vector_db_flush(db)) {
        fprintf(stderr, "post-build flush failed mode=%d errno=%d\n", mode, errno); return 3;
    }
    uint64_t build_ns = ns() - build_start;
    size_t k = rows < 10 ? rows : 10;
    qihse_vector_result_t *out = calloc(k, sizeof *out);
    if (!out) return 3;
    for (int metric = 0; metric < 3; ++metric) {
        for (int rep = -1; rep < repeats; ++rep) {
            for (size_t qi = 0; qi < nq; ++qi) {
                memset(out, 0, k * sizeof *out);
                qihse_vector_query_t q = {0};
                q.query_vector = queries + qi * dims;
                q.vector_dims = dims;
                q.top_k = k;
                q.similarity_threshold = -FLT_MAX;
                q.query_mode = (qihse_vector_db_query_mode_t)mode;
                q.distance_metric = (qihse_distance_metric_t)metric;
                q.candidate_pool_size = rows < 64 ? rows : 64;
                q.candidate_count = q.candidate_pool_size;
                q.user = user;
                qihse_vector_db_clear_cache(db);
                uint64_t started = ns();
                int count = qihse_vector_db_search(db, &q, out, k);
                uint64_t elapsed = ns() - started;
                if (count < 0) {
                    fprintf(stderr, "search failed mode=%d metric=%d q=%zu errno=%d\n", mode, metric, qi, errno);
                    return 4;
                }
                if (rep >= 0) {
                    printf("Q,%d,%d,%zu,%d,%" PRIu64 ",%d", mode, metric, qi, rep, elapsed, count);
                    for (int j = 0; j < count; ++j) printf(",%" PRIu64 ",%.9g", out[j].id, out[j].score);
                    putchar('\n');
                }
                for (int j = 0; j < count; ++j) { free(out[j].vector); free(out[j].metadata); }
            }
        }
    }
    size_t budget = 0, resident = 0, spilled = 0;
    qihse_vector_db_get_memory_usage(db, &budget, &resident, &spilled);
    printf("S,%d,%" PRIu64 ",%zu,%zu,%zu\n", mode, build_ns,
           resident, qihse_vector_db_index_bytes(db), spilled);
    qihse_vector_db_destroy(db);
    qihse_uma_destroy(uma);
    qihse_memory_manager_destroy(mem);
    qihse_context_destroy(ctx);
    free(vectors); free(queries); free(ids); free(out);
    return 0;
}
