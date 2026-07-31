/*
 * QIHSE AMX/BF16/VNNI Benchmark
 *
 * Benchmarks AMX BF16 GEMM, AVX-512 BF16 distance functions,
 * and AVX-512 VNNI INT8 quantized dot product against the
 * existing AVX-512 FMA and scalar implementations.
 *
 * Build: gcc -O3 -march=sapphirerapids -I../include -I../backends/cpu \
 *        bench_amx.c ../backends/cpu/qihse_cpu_amx.c \
 *        ../backends/cpu/qihse_cpu_distance.c ../backends/cpu/qihse_cpu_detect.c \
 *        -lm -lpthread -o bench_amx
 */

#include "qihse_cpu_avx512.h"
#include "qihse_cpu_distance.h"
#include "qihse_cpu_detect.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define BENCH_ITER 10000
#define WARMUP_ITER 1000

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void bench_dot(const char* label, float (*fn)(const float*, const float*, size_t),
                      const float* a, const float* b, size_t dims) {
    /* Warmup */
    for (int i = 0; i < WARMUP_ITER; i++) fn(a, b, dims);

    double t0 = now_us();
    float result = 0.0f;
    for (int i = 0; i < BENCH_ITER; i++) {
        result += fn(a, b, dims);
    }
    double t1 = now_us();
    double total_ns = (t1 - t0) * 1000.0 / BENCH_ITER;
    double gflops = (2.0 * dims) / (total_ns / 1e9) / 1e9;
    printf("  %-28s dims=%-5zu  %8.1f ns/op  %6.1f GFLOPS  (result=%.4f)\n",
           label, dims, total_ns, gflops, result / BENCH_ITER);
}

static void bench_cosine(const char* label, float (*fn)(const float*, const float*, size_t),
                         const float* a, const float* b, size_t dims) {
    for (int i = 0; i < WARMUP_ITER; i++) fn(a, b, dims);
    double t0 = now_us();
    float result = 0.0f;
    for (int i = 0; i < BENCH_ITER; i++) result += fn(a, b, dims);
    double t1 = now_us();
    double total_ns = (t1 - t0) * 1000.0 / BENCH_ITER;
    double gflops = (3.0 * dims) / (total_ns / 1e9) / 1e9;
    printf("  %-28s dims=%-5zu  %8.1f ns/op  %6.1f GFLOPS  (cos=%.6f)\n",
           label, dims, total_ns, gflops, result / BENCH_ITER);
}

static void bench_euclidean(const char* label, float (*fn)(const float*, const float*, size_t),
                            const float* a, const float* b, size_t dims) {
    for (int i = 0; i < WARMUP_ITER; i++) fn(a, b, dims);
    double t0 = now_us();
    float result = 0.0f;
    for (int i = 0; i < BENCH_ITER; i++) result += fn(a, b, dims);
    double t1 = now_us();
    double total_ns = (t1 - t0) * 1000.0 / BENCH_ITER;
    double gflops = (2.0 * dims) / (total_ns / 1e9) / 1e9;
    printf("  %-28s dims=%-5zu  %8.1f ns/op  %6.1f GFLOPS  (dist=%.4f)\n",
           label, dims, total_ns, gflops, result / BENCH_ITER);
}

static void bench_gemm(const char* label, size_t M, size_t N, size_t K) {
    float* A = aligned_alloc(64, M * K * sizeof(float));
    float* B = aligned_alloc(64, K * N * sizeof(float));
    float* C = aligned_alloc(64, M * N * sizeof(float));

    /* Initialize with random data */
    for (size_t i = 0; i < M * K; i++) A[i] = (float)(rand() % 1000) / 1000.0f - 0.5f;
    for (size_t i = 0; i < K * N; i++) B[i] = (float)(rand() % 1000) / 1000.0f - 0.5f;

    /* AMX GEMM */
    qihse_amx_pim_gemm_t gemm;
    qihse_amx_pim_gemm_init(&gemm, M, N, K, A, B, 16);

    /* Warmup */
    for (int i = 0; i < 10; i++) qihse_amx_pim_gemm_execute_amx(&gemm, C);

    double t0 = now_us();
    int iterations = 100;
    for (int i = 0; i < iterations; i++) {
        qihse_amx_pim_gemm_execute_amx(&gemm, C);
    }
    double t1 = now_us();
    double ms_per_op = (t1 - t0) / 1000.0 / iterations;
    double gflops = (2.0 * M * N * K) / (ms_per_op / 1e3) / 1e9;
    printf("  %-28s M=%-4zu N=%-4zu K=%-4zu  %8.2f ms  %8.1f GFLOPS\n",
           label, M, N, K, ms_per_op, gflops);

    qihse_amx_pim_gemm_destroy(&gemm);
    free(A); free(B); free(C);
}

int main(void) {
    printf("=== QIHSE AMX/BF16/VNNI Benchmark ===\n\n");

    qihse_cpu_info_t info = qihse_cpu_detect();
    printf("CPU: %s\n", info.brand);
    printf("AVX-512F:  %s\n", qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX512F) ? "YES" : "NO");
    printf("AVX-512 BF16: %s\n", qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX512BF16) ? "YES" : "NO");
    printf("AVX-512 VNNI: %s\n", qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX512VNNI) ? "YES" : "NO");
    printf("AMX:       %s\n", qihse_amx_pim_supported() ? "YES" : "NO");
    printf("\n");

    /* Test dimensions */
    size_t dims_list[] = {128, 256, 512, 1024, 4096};
    int num_dims = sizeof(dims_list) / sizeof(dims_list[0]);

    for (int d = 0; d < num_dims; d++) {
        size_t dims = dims_list[d];
        float* a = aligned_alloc(64, dims * sizeof(float));
        float* b = aligned_alloc(64, dims * sizeof(float));

        /* Initialize with normalized random data */
        for (size_t i = 0; i < dims; i++) {
            a[i] = (float)(rand() % 1000) / 1000.0f - 0.5f;
            b[i] = (float)(rand() % 1000) / 1000.0f - 0.5f;
        }

        printf("--- Dot Product (dims=%zu) ---\n", dims);
        bench_dot("Scalar",          qihse_distance_dot_scalar,    a, b, dims);
        bench_dot("AVX-512 FMA",     qihse_distance_dot_avx512,    a, b, dims);
        bench_dot("AVX-512 BF16",    qihse_distance_dot_bf16,      a, b, dims);
        printf("\n");

        printf("--- Cosine Distance (dims=%zu) ---\n", dims);
        bench_cosine("Scalar",       qihse_distance_cosine_scalar, a, b, dims);
        bench_cosine("AVX-512 FMA",  qihse_distance_cosine_avx512, a, b, dims);
        bench_cosine("AVX-512 BF16", qihse_distance_cosine_bf16,   a, b, dims);
        printf("\n");

        printf("--- Euclidean Distance (dims=%zu) ---\n", dims);
        bench_euclidean("Scalar",       qihse_distance_euclidean_scalar, a, b, dims);
        bench_euclidean("AVX-512 FMA",  qihse_distance_euclidean_avx512, a, b, dims);
        bench_euclidean("AVX-512 BF16", qihse_distance_euclidean_bf16,   a, b, dims);
        printf("\n");

        free(a); free(b);
    }

    /* VNNI INT8 benchmark */
    printf("--- VNNI INT8 Quantized Dot Product ---\n");
    for (int d = 0; d < num_dims; d++) {
        size_t dims = dims_list[d];
        float* a = aligned_alloc(64, dims * sizeof(float));
        float* b = aligned_alloc(64, dims * sizeof(float));
        for (size_t i = 0; i < dims; i++) {
            a[i] = (float)(rand() % 256 - 128) / 128.0f;
            b[i] = (float)(rand() % 256 - 128) / 128.0f;
        }

        for (int i = 0; i < WARMUP_ITER; i++) qihse_distance_dot_int8(a, b, dims);
        double t0 = now_us();
        int32_t result = 0;
        for (int i = 0; i < BENCH_ITER; i++) result += qihse_distance_dot_int8(a, b, dims);
        double t1 = now_us();
        double total_ns = (t1 - t0) * 1000.0 / BENCH_ITER;
        double gops = (2.0 * dims) / (total_ns / 1e9) / 1e9;
        printf("  VNNI INT8  dims=%-5zu  %8.1f ns/op  %6.1f GOPS  (result=%d)\n",
               dims, total_ns, gops, result / BENCH_ITER);

        free(a); free(b);
    }
    printf("\n");

    /* AMX GEMM benchmark */
    printf("--- AMX BF16 GEMM ---\n");
    bench_gemm("AMX BF16 Tile", 64,  64,  64);
    bench_gemm("AMX BF16 Tile", 128, 128, 128);
    bench_gemm("AMX BF16 Tile", 256, 256, 256);
    bench_gemm("AMX BF16 Tile", 512, 512, 512);
    bench_gemm("AMX BF16 Tile", 1024, 1024, 1024);

    printf("\n=== Benchmark Complete ===\n");
    return 0;
}
