#include "backends/cpu/qihse_cpu_distance.h"
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(void) {
    const size_t dimensions[] = {0, 1, 7, 8, 9, 15, 16, 31, 32, 63, 64, 127, 128, 129, 257};
    qihse_distance_functions_t functions = qihse_distance_resolve();
    qihse_distance_fn_t resolved[] = {functions.cosine, functions.dot, functions.euclidean};
    qihse_distance_fn_t public[] = {qihse_distance_cosine, qihse_distance_dot, qihse_distance_euclidean};
    for (size_t t = 0; t < sizeof(dimensions) / sizeof(dimensions[0]); t++) {
        size_t dims = dimensions[t];
        float *a_base = calloc(dims + 1, sizeof(float)), *b_base = calloc(dims + 1, sizeof(float));
        if (!a_base || !b_base) { free(a_base); free(b_base); return 1; }
        float *a = a_base + 1, *b = b_base + 1;
        for (size_t d = 0; d < dims; d++) {
            a[d] = ((int)(d % 13) - 6) * 0.125f;
            b[d] = ((int)(d % 7) - 3) * 0.0625f;
        }
        for (int variant = 0; variant < 5; variant++) {
            if (variant == 1) memset(a, 0, dims * sizeof(float));
            if (dims && variant == 2) a[0] = INFINITY;
            if (dims && variant == 3) a[0] = NAN;
            if (dims && variant == 4) a[0] = -0.0f;
            for (size_t f = 0; f < 3; f++) {
                float expected = public[f](a, b, dims), actual = resolved[f](a, b, dims);
                if (!(isnan(expected) && isnan(actual)) && memcmp(&expected, &actual, sizeof(float))) {
                    fprintf(stderr, "dispatch mismatch dims=%zu function=%zu variant=%d\n", dims, f, variant);
                    free(a_base); free(b_base); return 1;
                }
            }
        }
        free(a_base); free(b_base);
    }
    return 0;
}

static void* worker(void* arg) {
    *(int*)arg = check();
    return NULL;
}

int main(void) {
    pthread_t threads[8];
    int status[8] = {0};
    for (size_t i = 0; i < 8; i++) {
        if (pthread_create(&threads[i], NULL, worker, &status[i])) return 1;
    }
    for (size_t i = 0; i < 8; i++) {
        if (pthread_join(threads[i], NULL) || status[i]) return 1;
    }
    puts("PASS: concurrent distance resolution and bitwise score parity");
    return 0;
}
