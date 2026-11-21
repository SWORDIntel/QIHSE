#include "qihse_math.h"
#include "qihse_hetero.h"
#include <errno.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(TEST_AVX2)
#include "qihse_cpu_avx2.h"
typedef qihse_rff_kernel_avx2_t test_simd_kernel_t;
#define test_simd_project qihse_rff_avx2_project
#elif defined(TEST_AVX512)
#include "qihse_cpu_avx512.h"
typedef qihse_rff_kernel_avx512_t test_simd_kernel_t;
extern void qihse_rff_avx512_project(const qihse_rff_kernel_avx512_t*, const float*, float*);
#define test_simd_project qihse_rff_avx512_project
#endif

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 0; \
} } while (0)

typedef struct {
    const qihse_rff_kernel_t* expected;
    int matches;
} rff_thread_t;

static void* create_same_kernel(void* argument) {
    rff_thread_t* test = argument;
    qihse_rff_kernel_t* kernel = qihse_rff_create(3, 64, 0.7, 42);
    test->matches = kernel &&
        !memcmp(kernel->omega, test->expected->omega, 3 * 64 * sizeof(double)) &&
        !memcmp(kernel->bias, test->expected->bias, 64 * sizeof(double));
    qihse_rff_destroy(kernel);
    return NULL;
}

static int test_rff_contract(void) {
    double invalid_gamma[] = {0.0, -1.0, NAN, INFINITY};
    for (size_t i = 0; i < sizeof(invalid_gamma) / sizeof(*invalid_gamma); i++) {
        errno = 0;
        CHECK(qihse_rff_create(1, 8, invalid_gamma[i], 1) == NULL && errno == EINVAL);
    }
    errno = 0;
    CHECK(qihse_rff_create(SIZE_MAX / sizeof(double) + 1, 1, 1.0, 1) == NULL && errno == EOVERFLOW);
    CHECK(qihse_rff_create(1, SIZE_MAX, 1.0, 1) == NULL && errno == EOVERFLOW);
    CHECK(qihse_rff_create(0, 8, 1.0, 1) == NULL);

    /* Kernel construction may not reset or consume unrelated process RNG. */
    srand(123);
    int first = rand(), second = rand();
    srand(123);
    CHECK(rand() == first);
    qihse_rff_kernel_t* expected = qihse_rff_create(3, 64, 0.7, 42);
    CHECK(expected != NULL && rand() == second);
    pthread_t threads[6];
    rff_thread_t work[6];
    for (size_t i = 0; i < 6; i++) {
        work[i] = (rff_thread_t){expected, 0};
        CHECK(pthread_create(&threads[i], NULL, create_same_kernel, &work[i]) == 0);
    }
    for (size_t i = 0; i < 6; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(work[i].matches);
    }
    qihse_rff_kernel_t* different = qihse_rff_create(3, 64, 0.7, 43);
    CHECK(different && memcmp(expected->omega, different->omega, 3 * 64 * sizeof(double)) != 0);
    qihse_rff_destroy(different);
    qihse_rff_destroy(expected);
    qihse_rff_kernel_t* zero_a = qihse_rff_create(1, 8, 1.0, 0);
    qihse_rff_kernel_t* zero_b = qihse_rff_create(1, 8, 1.0, 0);
    CHECK(zero_a && zero_b && !memcmp(zero_a->omega, zero_b->omega, 8 * sizeof(double)));
    qihse_rff_destroy(zero_a);
    qihse_rff_destroy(zero_b);

    /* An independently specified RBF kernel checks the actual feature map,
     * not merely its own accessors or its own normalization predicate. */
    const size_t dimensions = 8192;
    qihse_rff_kernel_t* kernel = qihse_rff_create(3, dimensions, 0.7, 7);
    double *zx = malloc(dimensions * sizeof(double)), *zy = malloc(dimensions * sizeof(double));
    CHECK(kernel && zx && zy);
    const double x[3] = {-0.4, 0.7, 0.2}, y[3] = {-0.1, 0.5, 0.4};
    qihse_rff_project(kernel, x, zx);
    qihse_rff_project(kernel, y, zy);
    double dot = 0.0, norm = 0.0;
    const double feature_bound = sqrt(2.0 / dimensions);
    for (size_t d = 0; d < dimensions; d++) {
        CHECK(isfinite(zx[d]) && fabs(zx[d]) <= feature_bound);
        CHECK(isfinite(zy[d]) && fabs(zy[d]) <= feature_bound);
        dot += zx[d] * zy[d];
        norm += zx[d] * zx[d];
    }
    CHECK(fabs(dot - exp(-0.7 * 0.17)) < 0.04);
    CHECK(fabs(norm - 1.0) < 0.04);
    free(zx); free(zy); qihse_rff_destroy(kernel);
    return 1;
}

static int test_math_identities(void) {
    for (int mode = QIHSE_MATH_PRECISION_FULL; mode <= QIHSE_MATH_PRECISION_FAST; mode++) {
        qihse_math_precision_t precision = (qihse_math_precision_t)mode;
        CHECK(qihse_math_fast_exp(0, precision) == 1.0);
        CHECK(qihse_math_fast_log(1, precision) == 0.0);
        CHECK(qihse_math_fast_sqrt(4, precision) == 2.0);
        CHECK(fabs(qihse_math_fast_log(2, precision) - 0.6931471805599453) < 1e-15);
        CHECK(fabs(qihse_math_fast_sqrt(1e300, precision) / 1e150 - 1.0) < 1e-15);
        CHECK(qihse_math_fast_exp(-710, precision) > 0.0);
        CHECK(isinf(qihse_math_fast_exp(1000, precision)));
        CHECK(isnan(qihse_math_fast_log(-1, precision)));
        CHECK(isnan(qihse_math_fast_sqrt(-1, precision)));
        CHECK(isinf(qihse_math_fast_log(0, precision)) && qihse_math_fast_log(0, precision) < 0.0);
        double sine, cosine;
        qihse_math_fast_sincos(0, &sine, &cosine, precision);
        CHECK(sine == 0.0 && cosine == 1.0);
        qihse_math_fast_sincos(1e20, &sine, &cosine, precision);
        CHECK(fabs(sine - sin(1e20)) < 1e-15 && fabs(cosine - cos(1e20)) < 1e-15);
    }
    return 1;
}

static int check_schedule(qihse_compute_pool_t* pool, size_t candidates) {
    qihse_work_schedule_t* schedule = qihse_create_work_schedule(pool, candidates, 64);
    CHECK(schedule && schedule->partition_count > 0);
    size_t covered = 0;
    for (size_t i = 0; i < schedule->partition_count; i++) {
        qihse_work_partition_t* partition = &schedule->partitions[i];
        CHECK(partition->start_idx == covered && partition->count > 0);
        CHECK(partition->count <= candidates - covered);
        covered += partition->count;
    }
    CHECK(covered == candidates);
    qihse_work_schedule_destroy(schedule);
    return 1;
}

static int test_schedule_coverage(void) {
    qihse_compute_pool_t pool = {0};
    pool.devices[QIHSE_DEV_CPU_AVX2] = (qihse_compute_device_t){
        .available=true, .measured_tops=1.0, .type=QIHSE_DEV_CPU_AVX2, .min_batch_size=1};
    pool.devices[QIHSE_DEV_CPU_AVX512] = (qihse_compute_device_t){
        .available=true, .measured_tops=1.0, .type=QIHSE_DEV_CPU_AVX512, .min_batch_size=1};
    CHECK(check_schedule(&pool, 5));
    for (size_t n = 1; n <= 257; n++) CHECK(check_schedule(&pool, n));
    pool.devices[QIHSE_DEV_CPU_AVX2].measured_tops = DBL_MAX;
    pool.devices[QIHSE_DEV_CPU_AVX512].measured_tops = DBL_MAX;
    CHECK(check_schedule(&pool, 5));
    CHECK(check_schedule(&pool, SIZE_MAX));
    pool.devices[QIHSE_DEV_CPU_AVX512].min_batch_size = SIZE_MAX;
    pool.devices[QIHSE_DEV_CPU_AVX2].measured_tops = DBL_MIN;
    CHECK(check_schedule(&pool, 7));
    pool.devices[QIHSE_DEV_CPU_AVX2].measured_tops = NAN;
    pool.devices[QIHSE_DEV_CPU_AVX512].measured_tops = INFINITY;
    errno = 0;
    CHECK(qihse_create_work_schedule(&pool, 5, 64) == NULL && errno == ENODEV);
    return 1;
}

#if defined(TEST_AVX2) || defined(TEST_AVX512)
static int test_simd_reference(void) {
    const size_t inputs[] = {1, 2, 3, 17}, outputs[] = {1, 7, 8, 9, 15, 16, 17, 31};
    for (size_t a = 0; a < sizeof(inputs)/sizeof(*inputs); a++) {
        for (size_t b = 0; b < sizeof(outputs)/sizeof(*outputs); b++) {
            size_t n = inputs[a], d = outputs[b];
            float *omega = malloc(n*d*sizeof(float)), *bias = malloc(d*sizeof(float));
            float *input = malloc(n*sizeof(float)), *output = malloc((d+2)*sizeof(float));
            CHECK(omega && bias && input && output);
            for (size_t i = 0; i < n*d; i++) omega[i] = (float)((int)(i % 19)-9) * 0.01f;
            for (size_t i = 0; i < n; i++) input[i] = (float)(i+1) * 0.1f;
            for (size_t i = 0; i < d; i++) bias[i] = (i % 2) ? 6.283185307179586f : 0.0f;
            output[d] = 12345.0f; output[d+1] = -12345.0f;
            test_simd_kernel_t kernel = {.input_dims=n, .output_dims=d, .omega_real=omega, .bias=bias};
            test_simd_project(&kernel, input, output);
            const float scale = sqrtf(2.0f/(float)d);
            for (size_t row = 0; row < d; row++) {
                double phase = bias[row];
                for (size_t i = 0; i < n; i++) phase += (double)omega[row*n+i] * input[i];
                CHECK(isfinite(output[row]) && fabsf(output[row]) <= scale);
                CHECK(fabs(output[row] - scale * cos(phase)) < 2e-6);
            }
            CHECK(output[d] == 12345.0f && output[d+1] == -12345.0f);
            memset(omega, 0, n*d*sizeof(float));
            for (size_t i = 0; i < d; i++) bias[i] = (i%2) ? -10000.0f : 10000.0f;
            test_simd_project(&kernel, input, output);
            for (size_t row = 0; row < d; row++) {
                CHECK(fabs(output[row] - scale * cos((double)bias[row])) < 2e-7);
                CHECK(fabsf(output[row]) <= scale);
            }
            free(omega); free(bias); free(input); free(output);
        }
    }
#if defined(TEST_AVX2)
    errno = 0;
    CHECK(qihse_rff_avx2_create(1, SIZE_MAX, 1, 1) == NULL && errno == EOVERFLOW);
    CHECK(qihse_rff_avx2_create(1, 8, NAN, 1) == NULL && errno == EINVAL);
    qihse_rff_kernel_avx2_t* rounded = qihse_rff_avx2_create(3, 65, 0.4, 0);
    CHECK(rounded && rounded->output_dims == 72);
    qihse_rff_kernel_t* same_basis = qihse_rff_create(3, 72, 0.4, 0);
    CHECK(same_basis != NULL);
    for (size_t i = 0; i < 3*72; i++) {
        CHECK(isfinite(rounded->omega_real[i]));
        CHECK(rounded->omega_real[i] == (float)same_basis->omega[i]);
    }
    for (size_t i = 0; i < 72; i++) CHECK(rounded->bias[i] == (float)same_basis->bias[i]);
    qihse_rff_destroy(same_basis);
    qihse_rff_avx2_destroy(rounded);
#endif
    return 1;
}
#endif

int main(void) {
    if (!test_rff_contract() || !test_math_identities() || !test_schedule_coverage()) return 1;
#if defined(TEST_AVX2) || defined(TEST_AVX512)
    if (!test_simd_reference()) return 1;
#endif
    puts("runtime math regressions: PASS");
    return 0;
}
