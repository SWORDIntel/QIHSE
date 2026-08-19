/*
 * QIHSE Micro-Benchmark Harness
 *
 * Component-level benchmarks for the hot paths identified in the cosdata audit.
 * Measures exact search, trinary candidate selection, qmag scoring, and
 * distance metric variants with statistical confidence intervals.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <float.h>
#include <errno.h>

#include "qihse_vector_db.h"

#ifndef M_PI
#define M_PI acos(-1.0)
#endif

/* --------------------------------------------------------------------------
 * Benchmark timing primitives
 * -------------------------------------------------------------------------- */
static inline uint64_t bench_ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

typedef struct {
    uint64_t* samples;
    size_t count;
    size_t capacity;
} bench_samples_t;

static bool bench_samples_init(bench_samples_t* s, size_t capacity) {
    s->samples = (uint64_t*)malloc(capacity * sizeof(uint64_t));
    if (!s->samples) return false;
    s->count = 0;
    s->capacity = capacity;
    return true;
}

static void bench_samples_free(bench_samples_t* s) {
    free(s->samples);
    s->samples = NULL;
    s->count = s->capacity = 0;
}

static void bench_samples_push(bench_samples_t* s, uint64_t ns) {
    if (s->count < s->capacity) {
        s->samples[s->count++] = ns;
    }
}

static int bench_cmp_u64(const void* a, const void* b) {
    uint64_t ua = *(const uint64_t*)a;
    uint64_t ub = *(const uint64_t*)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static void bench_samples_report(const char* name, bench_samples_t* s) {
    if (s->count == 0) {
        printf("%-40s: no samples\n", name);
        return;
    }
    qsort(s->samples, s->count, sizeof(uint64_t), bench_cmp_u64);
    uint64_t sum = 0;
    for (size_t i = 0; i < s->count; i++) sum += s->samples[i];
    double mean = (double)sum / (double)s->count;
    size_t p50 = s->count / 2;
    size_t p95 = (size_t)(s->count * 0.95);
    if (p95 >= s->count) p95 = s->count - 1;
    size_t p99 = (size_t)(s->count * 0.99);
    if (p99 >= s->count) p99 = s->count - 1;

    double variance = 0.0;
    for (size_t i = 0; i < s->count; i++) {
        double diff = (double)s->samples[i] - mean;
        variance += diff * diff;
    }
    variance /= (double)s->count;
    double stddev = sqrt(variance);
    double sem = stddev / sqrt((double)s->count);
    double ci95_low = mean - 1.96 * sem;
    double ci95_high = mean + 1.96 * sem;

    printf("%-40s: mean=%8.3f us  p50=%8.3f us  p95=%8.3f us  p99=%8.3f us  n=%zu  ci95=[%.3f, %.3f] us\n",
           name,
           mean / 1000.0,
           (double)s->samples[p50] / 1000.0,
           (double)s->samples[p95] / 1000.0,
           (double)s->samples[p99] / 1000.0,
           s->count,
           ci95_low / 1000.0,
           ci95_high / 1000.0);
}

/* --------------------------------------------------------------------------
 * Synthetic data generators
 * -------------------------------------------------------------------------- */
static float* bench_generate_random_vector(size_t dims, uint64_t* seed) {
    float* v = (float*)malloc(dims * sizeof(float));
    if (!v) return NULL;
    for (size_t i = 0; i < dims; i++) {
        /* Box-Muller approx: uniform [-1, 1] is fine for benchmarking */
        double u = (double)(*seed = (*seed * 1103515245 + 12345) & 0x7fffffff) / (double)0x7fffffff;
        v[i] = (float)(u * 2.0 - 1.0);
    }
    return v;
}

static float* bench_generate_random_unit_vector(size_t dims, uint64_t* seed) {
    float* v = bench_generate_random_vector(dims, seed);
    if (!v) return NULL;
    double norm = 0.0;
    for (size_t i = 0; i < dims; i++) norm += (double)v[i] * (double)v[i];
    if (norm > 0.0) {
        float scale = (float)(1.0 / sqrt(norm));
        for (size_t i = 0; i < dims; i++) v[i] *= scale;
    }
    return v;
}

/* --------------------------------------------------------------------------
 * Benchmark: exact float32 search across distance metrics
 * -------------------------------------------------------------------------- */
static void bench_exact_search(size_t n_rows, size_t dims, size_t n_queries, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);
    }
    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "Failed to add vectors\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    float** queries = (float**)malloc(n_queries * sizeof(float*));
    for (size_t i = 0; i < n_queries; i++) {
        queries[i] = bench_generate_random_unit_vector(dims, &seed);
    }

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(10 * sizeof(qihse_vector_result_t));

    bench_samples_t s_cosine, s_dot, s_euclid;
    bench_samples_init(&s_cosine, iterations * n_queries);
    bench_samples_init(&s_dot, iterations * n_queries);
    bench_samples_init(&s_euclid, iterations * n_queries);

    for (size_t iter = 0; iter < iterations; iter++) {
        for (size_t q = 0; q < n_queries; q++) {
            qihse_vector_query_t query = {0};
            query.query_vector = queries[q];
            query.vector_dims = dims;
            query.top_k = 10;
            query.similarity_threshold = -FLT_MAX;
            query.distance_metric = QIHSE_DISTANCE_COSINE;

            uint64_t t0 = bench_ns_now();
            int n = qihse_vector_db_search(vdb, &query, results, 10);
            uint64_t t1 = bench_ns_now();
            (void)n;
            bench_samples_push(&s_cosine, t1 - t0);

            query.distance_metric = QIHSE_DISTANCE_DOT_PRODUCT;
            t0 = bench_ns_now();
            n = qihse_vector_db_search(vdb, &query, results, 10);
            t1 = bench_ns_now();
            bench_samples_push(&s_dot, t1 - t0);

            query.distance_metric = QIHSE_DISTANCE_EUCLIDEAN;
            t0 = bench_ns_now();
            n = qihse_vector_db_search(vdb, &query, results, 10);
            t1 = bench_ns_now();
            bench_samples_push(&s_euclid, t1 - t0);
        }
    }

    char label[128];
    snprintf(label, sizeof(label), "exact-search-cosine (%zux%zd, k=10)", n_rows, dims);
    bench_samples_report(label, &s_cosine);
    snprintf(label, sizeof(label), "exact-search-dotproduct (%zux%zd, k=10)", n_rows, dims);
    bench_samples_report(label, &s_dot);
    snprintf(label, sizeof(label), "exact-search-euclidean (%zux%zd, k=10)", n_rows, dims);
    bench_samples_report(label, &s_euclid);

    bench_samples_free(&s_cosine);
    bench_samples_free(&s_dot);
    bench_samples_free(&s_euclid);

    for (size_t i = 0; i < n_queries; i++) free(queries[i]);
    free(queries);
    free(results);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Benchmark: batch search throughput
 * -------------------------------------------------------------------------- */
static void bench_batch_search(size_t n_rows, size_t dims, size_t batch_size, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);
    }
    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "Failed to add vectors\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    qihse_vector_query_t* queries = (qihse_vector_query_t*)calloc(batch_size, sizeof(qihse_vector_query_t));
    float** qvecs = (float**)malloc(batch_size * sizeof(float*));
    for (size_t i = 0; i < batch_size; i++) {
        qvecs[i] = bench_generate_random_unit_vector(dims, &seed);
        queries[i].query_vector = qvecs[i];
        queries[i].vector_dims = dims;
        queries[i].top_k = 10;
        queries[i].similarity_threshold = -FLT_MAX;
        queries[i].distance_metric = QIHSE_DISTANCE_COSINE;
    }

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(batch_size * 10 * sizeof(qihse_vector_result_t));
    int* out_counts = (int*)malloc(batch_size * sizeof(int));

    bench_samples_t s_batch, s_serial;
    bench_samples_init(&s_batch, iterations);
    bench_samples_init(&s_serial, iterations);

    for (size_t iter = 0; iter < iterations; iter++) {
        uint64_t t0 = bench_ns_now();
        if (!qihse_vector_db_search_batch(vdb, queries, batch_size, results, 10, out_counts)) {
            fprintf(stderr, "Batch search failed\n");
            break;
        }
        uint64_t t1 = bench_ns_now();
        bench_samples_push(&s_batch, t1 - t0);

        t0 = bench_ns_now();
        for (size_t i = 0; i < batch_size; i++) {
            qihse_vector_db_search(vdb, &queries[i], results + i * 10, 10);
        }
        t1 = bench_ns_now();
        bench_samples_push(&s_serial, t1 - t0);
    }

    char label[128];
    snprintf(label, sizeof(label), "batch-search (%zux%zd, batch=%zu)", n_rows, dims, batch_size);
    bench_samples_report(label, &s_batch);
    snprintf(label, sizeof(label), "serial-search (%zux%zd, batch=%zu)", n_rows, dims, batch_size);
    bench_samples_report(label, &s_serial);

    bench_samples_free(&s_batch);
    bench_samples_free(&s_serial);

    for (size_t i = 0; i < batch_size; i++) {
        free(qvecs[i]);
    }
    free(qvecs);
    free(queries);
    free(results);
    free(out_counts);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Benchmark: hybrid search with RRF fusion
 * -------------------------------------------------------------------------- */
static void bench_hybrid_search(size_t n_rows, size_t dims, size_t top_k, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);
    }
    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "Failed to add vectors\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    float* qvec_a = bench_generate_random_unit_vector(dims, &seed);
    float* qvec_b = bench_generate_random_unit_vector(dims, &seed);

    qihse_hybrid_request_t request = {0};
    request.query_a.query_vector = qvec_a;
    request.query_a.vector_dims = dims;
    request.query_a.top_k = top_k;
    request.query_a.similarity_threshold = -FLT_MAX;
    request.query_a.distance_metric = QIHSE_DISTANCE_COSINE;

    request.query_b.query_vector = qvec_b;
    request.query_b.vector_dims = dims;
    request.query_b.top_k = top_k;
    request.query_b.similarity_threshold = -FLT_MAX;
    request.query_b.distance_metric = QIHSE_DISTANCE_DOT_PRODUCT;

    request.fusion_constant_k = 60.0f;

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(top_k * sizeof(qihse_vector_result_t));
    bench_samples_t s;
    bench_samples_init(&s, iterations);

    for (size_t iter = 0; iter < iterations; iter++) {
        uint64_t t0 = bench_ns_now();
        int n = qihse_vector_db_hybrid_search(vdb, &request, results, top_k);
        uint64_t t1 = bench_ns_now();
        (void)n;
        bench_samples_push(&s, t1 - t0);
    }

    char label[128];
    snprintf(label, sizeof(label), "hybrid-rrf (%zux%zd, k=%zu)", n_rows, dims, top_k);
    bench_samples_report(label, &s);

    bench_samples_free(&s);
    free(qvec_a);
    free(qvec_b);
    free(results);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Benchmark: metadata filtering overhead
 * -------------------------------------------------------------------------- */
static bool bench_tag_filter(const void* metadata, size_t metadata_size, void* opaque) {
    (void)metadata_size;
    const char* tag = (const char*)opaque;
    const char* md = (const char*)metadata;
    return strstr(md, tag) != NULL;
}

static void bench_metadata_filter(size_t n_rows, size_t dims, float match_rate, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    void** metadatas = (void**)malloc(n_rows * sizeof(void*));
    size_t* metadata_sizes = (size_t*)malloc(n_rows * sizeof(size_t));

    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);

        char buf[64];
        if ((double)(seed % 1000) / 1000.0 < match_rate) {
            snprintf(buf, sizeof(buf), "tag:important id=%zu", i);
        } else {
            snprintf(buf, sizeof(buf), "tag:other id=%zu", i);
        }
        metadata_sizes[i] = strlen(buf) + 1;
        metadatas[i] = malloc(metadata_sizes[i]);
        memcpy(metadatas[i], buf, metadata_sizes[i]);
        seed = seed * 1103515245 + 12345;
    }

    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids,
                                     (const void* const*)metadatas, metadata_sizes)) {
        fprintf(stderr, "Failed to add vectors\n");
        goto cleanup;
    }

    float* qvec = bench_generate_random_unit_vector(dims, &seed);
    qihse_vector_query_t query = {0};
    query.query_vector = qvec;
    query.vector_dims = dims;
    query.top_k = 10;
    query.similarity_threshold = -FLT_MAX;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.metadata_filter = bench_tag_filter;
    query.metadata_filter_opaque = (void*)"important";

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(10 * sizeof(qihse_vector_result_t));
    bench_samples_t s_filtered, s_unfiltered;
    bench_samples_init(&s_filtered, iterations);
    bench_samples_init(&s_unfiltered, iterations);

    for (size_t iter = 0; iter < iterations; iter++) {
        uint64_t t0 = bench_ns_now();
        int n = qihse_vector_db_search(vdb, &query, results, 10);
        uint64_t t1 = bench_ns_now();
        (void)n;
        bench_samples_push(&s_filtered, t1 - t0);

        query.metadata_filter = NULL;
        t0 = bench_ns_now();
        n = qihse_vector_db_search(vdb, &query, results, 10);
        t1 = bench_ns_now();
        bench_samples_push(&s_unfiltered, t1 - t0);
        query.metadata_filter = bench_tag_filter;
    }

    char label[128];
    snprintf(label, sizeof(label), "metadata-filtered (%zux%zd, match=%.0f%%)", n_rows, dims, match_rate * 100);
    bench_samples_report(label, &s_filtered);
    snprintf(label, sizeof(label), "unfiltered (%zux%zd)", n_rows, dims);
    bench_samples_report(label, &s_unfiltered);

    bench_samples_free(&s_filtered);
    bench_samples_free(&s_unfiltered);
    free(qvec);
    free(results);

cleanup:
    for (size_t i = 0; i < n_rows; i++) free(metadatas[i]);
    free(metadatas);
    free(metadata_sizes);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Benchmark: trinary candidate selection (if sidecar available)
 * -------------------------------------------------------------------------- */
static void bench_trinary_candidate_selection(size_t n_rows, size_t dims, size_t candidate_count, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);
    }
    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "Failed to add vectors\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    /* Build sidecars */
    if (!qihse_vector_db_flush(vdb)) {
        fprintf(stderr, "Flush failed\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    float* qvec = bench_generate_random_unit_vector(dims, &seed);
    qihse_vector_query_t query = {0};
    query.query_vector = qvec;
    query.vector_dims = dims;
    query.top_k = 10;
    query.similarity_threshold = -FLT_MAX;
    query.distance_metric = QIHSE_DISTANCE_COSINE;

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(10 * sizeof(qihse_vector_result_t));
    bench_samples_t s_tri, s_qmag, s_exact;
    bench_samples_init(&s_tri, iterations);
    bench_samples_init(&s_qmag, iterations);
    bench_samples_init(&s_exact, iterations);

    for (size_t iter = 0; iter < iterations; iter++) {
        uint64_t t0 = bench_ns_now();
        int n = qihse_vector_db_search_trinary_candidates(vdb, &query, candidate_count, results, 10);
        uint64_t t1 = bench_ns_now();
        if (n >= 0) bench_samples_push(&s_tri, t1 - t0);

        query.query_mode = QIHSE_VDB_QUERY_TRINARY_MAGNITUDE;
        query.candidate_pool_size = candidate_count;
        t0 = bench_ns_now();
        n = qihse_vector_db_search(vdb, &query, results, 10);
        t1 = bench_ns_now();
        if (n >= 0) bench_samples_push(&s_qmag, t1 - t0);

        query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
        query.candidate_pool_size = 0;
        t0 = bench_ns_now();
        n = qihse_vector_db_search(vdb, &query, results, 10);
        t1 = bench_ns_now();
        if (n >= 0) bench_samples_push(&s_exact, t1 - t0);
    }

    char label[128];
    snprintf(label, sizeof(label), "trinary-scalar (%zux%zd, cand=%zu)", n_rows, dims, candidate_count);
    bench_samples_report(label, &s_tri);
    snprintf(label, sizeof(label), "trinary-magnitude (%zux%zd, cand=%zu)", n_rows, dims, candidate_count);
    bench_samples_report(label, &s_qmag);
    snprintf(label, sizeof(label), "exact-float32 (%zux%zd, k=10)", n_rows, dims);
    bench_samples_report(label, &s_exact);

    bench_samples_free(&s_tri);
    bench_samples_free(&s_qmag);
    bench_samples_free(&s_exact);

    free(qvec);
    free(results);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Benchmark: INT8 scalar quantization candidate selection
 * -------------------------------------------------------------------------- */
static void bench_int8_search(size_t n_rows, size_t dims, size_t top_k, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);
    }
    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "Failed to add vectors\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    /* Build INT8 sidecar */
    uint64_t t_build0 = bench_ns_now();
    if (!qihse_vector_db_build_int8(vdb)) {
        fprintf(stderr, "Failed to build INT8 sidecar\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }
    uint64_t t_build1 = bench_ns_now();
    printf("int8-build (%zux%zd)                          : build_time= %0.3f ms\n",
           n_rows, dims, (t_build1 - t_build0) / 1e6);

    float* qvec = bench_generate_random_unit_vector(dims, &seed);
    qihse_vector_query_t query = {0};
    query.query_vector = qvec;
    query.vector_dims = dims;
    query.top_k = top_k;
    query.similarity_threshold = -FLT_MAX;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.query_mode = QIHSE_VDB_QUERY_INT8;
    query.candidate_pool_size = top_k * 12;

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(top_k * sizeof(qihse_vector_result_t));
    bench_samples_t s;
    bench_samples_init(&s, iterations);

    for (size_t iter = 0; iter < iterations; iter++) {
        uint64_t t0 = bench_ns_now();
        int n = qihse_vector_db_search(vdb, &query, results, top_k);
        uint64_t t1 = bench_ns_now();
        (void)n;
        bench_samples_push(&s, t1 - t0);
    }

    char label[128];
    snprintf(label, sizeof(label), "int8-search (%zux%zd, k=%zu)", n_rows, dims, top_k);
    bench_samples_report(label, &s);

    bench_samples_free(&s);
    free(qvec);
    free(results);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Benchmark: graph index candidate selection
 * -------------------------------------------------------------------------- */
static void bench_graph_search(size_t n_rows, size_t dims, size_t top_k, size_t iterations) {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        fprintf(stderr, "Failed to create VDB\n");
        return;
    }

    uint64_t seed = 42;
    float* vectors = (float*)malloc(n_rows * dims * sizeof(float));
    uint64_t* ids = (uint64_t*)malloc(n_rows * sizeof(uint64_t));
    for (size_t i = 0; i < n_rows; i++) {
        ids[i] = (uint64_t)i;
        float* v = bench_generate_random_unit_vector(dims, &seed);
        memcpy(vectors + i * dims, v, dims * sizeof(float));
        free(v);
    }
    if (!qihse_vector_db_add_vectors(vdb, vectors, n_rows, dims, ids, NULL, NULL)) {
        fprintf(stderr, "Failed to add vectors\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }

    /* Build graph index sidecar */
    uint64_t t_build0 = bench_ns_now();
    if (!qihse_vector_db_build_graph(vdb, 16, 200)) {
        fprintf(stderr, "Failed to build graph\n");
        free(vectors); free(ids); qihse_vector_db_destroy(vdb);
        return;
    }
    uint64_t t_build1 = bench_ns_now();
    printf("graph-build (%zux%zd)                          : build_time= %0.3f ms\n",
           n_rows, dims, (t_build1 - t_build0) / 1e6);

    float* qvec = bench_generate_random_unit_vector(dims, &seed);
    qihse_vector_query_t query = {0};
    query.query_vector = qvec;
    query.vector_dims = dims;
    query.top_k = top_k;
    query.similarity_threshold = -FLT_MAX;
    query.distance_metric = QIHSE_DISTANCE_COSINE;
    query.query_mode = QIHSE_VDB_QUERY_GRAPH;
    query.candidate_pool_size = top_k * 4;

    qihse_vector_result_t* results = (qihse_vector_result_t*)malloc(top_k * sizeof(qihse_vector_result_t));
    bench_samples_t s;
    bench_samples_init(&s, iterations);

    for (size_t iter = 0; iter < iterations; iter++) {
        uint64_t t0 = bench_ns_now();
        int n = qihse_vector_db_search(vdb, &query, results, top_k);
        uint64_t t1 = bench_ns_now();
        (void)n;
        bench_samples_push(&s, t1 - t0);
    }

    char label[128];
    snprintf(label, sizeof(label), "graph-search (%zux%zd, k=%zu)", n_rows, dims, top_k);
    bench_samples_report(label, &s);

    bench_samples_free(&s);
    free(qvec);
    free(results);
    free(vectors);
    free(ids);
    qihse_vector_db_destroy(vdb);
}

/* --------------------------------------------------------------------------
 * Main harness
 * -------------------------------------------------------------------------- */
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    printf("================================================================================\n");
    printf("QIHSE Micro-Benchmark Harness\n");
    printf("================================================================================\n\n");

    printf("--- Exact Search: Distance Metrics ---\n");
    bench_exact_search(1000, 128, 32, 50);
    bench_exact_search(10000, 128, 32, 20);
    bench_exact_search(100000, 128, 16, 5);

    printf("\n--- Batch Search Throughput ---\n");
    bench_batch_search(10000, 128, 32, 20);
    bench_batch_search(100000, 128, 64, 10);

    printf("\n--- Hybrid Search (RRF Fusion) ---\n");
    bench_hybrid_search(10000, 128, 10, 20);
    bench_hybrid_search(100000, 128, 10, 10);

    printf("\n--- INT8 Scalar Quantization ---\n");
    bench_int8_search(1000, 128, 10, 20);
    bench_int8_search(10000, 128, 10, 20);
    bench_int8_search(100000, 128, 10, 5);

    printf("\n--- Graph Index Candidate Selection ---\n");
    bench_graph_search(1000, 128, 10, 20);
    bench_graph_search(10000, 128, 10, 10);

    printf("\n--- Metadata Filtering ---\n");
    bench_metadata_filter(10000, 128, 0.1f, 20);
    bench_metadata_filter(100000, 128, 0.05f, 10);

    printf("\n--- Trinary Candidate Selection ---\n");
    bench_trinary_candidate_selection(10000, 128, 100, 20);
    bench_trinary_candidate_selection(100000, 128, 500, 10);

    printf("\n================================================================================\n");
    printf("Benchmark complete.\n");
    return 0;
}
