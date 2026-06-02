/*
 * QIHSE - CPU Distance Function Dispatch
 *
 * Runtime selection of the best distance function implementation
 * based on CPU feature detection.
 */

#include "qihse_cpu_distance.h"
#include "qihse_cpu_detect.h"
#include <pthread.h>
#include <math.h>

/* -------------------------------------------------------------------------- */
/* Scalar fallback implementations */
/* -------------------------------------------------------------------------- */
static float qihse_distance_dot_scalar(const float* a, const float* b, size_t dims) {
    float sum = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        sum += a[i] * b[i];
    }
    return sum;
}

static float qihse_distance_cosine_scalar(const float* a, const float* b, size_t dims) {
    float dot = 0.0f, na = 0.0f, nb = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        dot += a[i] * b[i];
        na  += a[i] * a[i];
        nb  += b[i] * b[i];
    }
    if (na <= 0.0f || nb <= 0.0f) return 0.0f;
    return dot / (sqrtf(na) * sqrtf(nb));
}

static float qihse_distance_euclidean_scalar(const float* a, const float* b, size_t dims) {
    float sum = 0.0f;
    for (size_t i = 0; i < dims; i++) {
        float d = a[i] - b[i];
        sum += d * d;
    }
    return sqrtf(sum);
}

/* -------------------------------------------------------------------------- */
/* Dispatch table */
/* -------------------------------------------------------------------------- */
static qihse_distance_fn_t g_cosine_fn = NULL;
static qihse_distance_fn_t g_dot_fn = NULL;
static qihse_distance_fn_t g_euclidean_fn = NULL;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void qihse_distance_init_once(void) {
    qihse_cpu_info_t info = qihse_cpu_detect();

    if (qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX2) &&
        qihse_cpu_has_feature(&info, QIHSE_CPU_FEATURE_AVX)) {
        g_cosine_fn    = qihse_distance_cosine_avx2;
        g_dot_fn       = qihse_distance_dot_avx2;
        g_euclidean_fn = qihse_distance_euclidean_avx2;
    } else {
        g_cosine_fn    = qihse_distance_cosine_scalar;
        g_dot_fn       = qihse_distance_dot_scalar;
        g_euclidean_fn = qihse_distance_euclidean_scalar;
    }
}

/* -------------------------------------------------------------------------- */
/* Public API */
/* -------------------------------------------------------------------------- */
float qihse_distance_cosine(const float* a, const float* b, size_t dims) {
    pthread_once(&g_init_once, qihse_distance_init_once);
    return g_cosine_fn(a, b, dims);
}

float qihse_distance_dot(const float* a, const float* b, size_t dims) {
    pthread_once(&g_init_once, qihse_distance_init_once);
    return g_dot_fn(a, b, dims);
}

float qihse_distance_euclidean(const float* a, const float* b, size_t dims) {
    pthread_once(&g_init_once, qihse_distance_init_once);
    return g_euclidean_fn(a, b, dims);
}
