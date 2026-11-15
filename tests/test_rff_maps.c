#include "qihse_math.h"
#include <errno.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); return 0; \
} } while (0)

static double dot(const double* a, const double* b, size_t n) {
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) sum += a[i] * b[i];
    return sum;
}

static int test_layouts_and_identity(void) {
    const size_t input_sizes[] = {1, 3, 17};
    const size_t output_sizes[] = {2, 6, 16, 64, 130};
    for (size_t a = 0; a < sizeof(input_sizes) / sizeof(*input_sizes); ++a) {
        size_t d = input_sizes[a];
        double x[17], y[17], shifted_x[17], shifted_y[17];
        for (size_t i = 0; i < d; ++i) {
            x[i] = .125 * (double)((int)i - 3);
            y[i] = -.0625 * (double)((int)i + 1);
            shifted_x[i] = x[i] + .25;
            shifted_y[i] = y[i] + .25;
        }
        for (size_t b = 0; b < sizeof(output_sizes) / sizeof(*output_sizes); ++b) {
            size_t D = output_sizes[b], m = D / 2;
            qihse_rff_map_t* phase = qihse_rff_map_create(d, D, .7, 0, QIHSE_RFF_COSINE_PHASE);
            qihse_rff_map_t* paired = qihse_rff_map_create(d, D, .7, 0, QIHSE_RFF_PAIRED_SINCOS);
            qihse_rff_kernel_t* legacy = qihse_rff_create(d, D, .7, 0);
            CHECK(phase && paired && legacy);
            double zx[132], zy[130], tx[130], ty[130], reference[130];
            zx[0] = 1234.0; zx[D + 1] = -1234.0;
            qihse_rff_project(legacy, x, reference);
            CHECK(qihse_rff_map_project(phase, x, zx + 1) == 0);
            CHECK(memcmp(reference, zx + 1, D * sizeof(double)) == 0);
            CHECK(zx[0] == 1234.0 && zx[D + 1] == -1234.0);
            CHECK(qihse_rff_map_project(paired, x, zx + 1) == 0);
            CHECK(qihse_rff_map_project(paired, y, zy) == 0);
            CHECK(qihse_rff_map_project(paired, shifted_x, tx) == 0);
            CHECK(qihse_rff_map_project(paired, shifted_y, ty) == 0);
            CHECK(zx[0] == 1234.0 && zx[D + 1] == -1234.0);
            const double scale = 1.0 / sqrt((double)m);
            double kernel_reference = 0.0;
            for (size_t j = 0; j < m; ++j) {
                double wx = 0.0, w_difference = 0.0;
                for (size_t i = 0; i < d; ++i) {
                    wx += legacy->omega[j * d + i] * x[i];
                    w_difference += legacy->omega[j * d + i] * (x[i] - y[i]);
                }
                CHECK(fabs(zx[1 + 2 * j] - scale * cos(wx)) < 1e-14);
                CHECK(fabs(zx[1 + 2 * j + 1] - scale * sin(wx)) < 1e-14);
                CHECK(fabs(zx[1 + 2 * j]) <= scale && fabs(zx[1 + 2 * j + 1]) <= scale);
                kernel_reference += cos(w_difference) / (double)m;
            }
            CHECK(fabs(dot(zx + 1, zx + 1, D) - 1.0) < 2e-14);
            CHECK(fabs(dot(zx + 1, zy, D) - kernel_reference) < 2e-14);
            CHECK(fabs(dot(zx + 1, zy, D) - dot(tx, ty, D)) < 2e-14);
            CHECK(qihse_rff_map_input_dims(paired) == d && qihse_rff_map_output_dims(paired) == D);
            /* Equal output bytes; only basis allocation differs. This also
             * catches an accidental paired bias allocation or D frequencies. */
            size_t phase_bytes = qihse_rff_map_storage_bytes(phase);
            size_t paired_bytes = qihse_rff_map_storage_bytes(paired);
            CHECK(phase_bytes > paired_bytes);
            CHECK(phase_bytes - paired_bytes == (D * d + D - m * d) * sizeof(double));
            CHECK(paired_bytes > m * d * sizeof(double) + sizeof(qihse_rff_kernel_t));
            qihse_rff_map_descriptor_t p, q;
            CHECK(qihse_rff_map_get_descriptor(phase, &p, sizeof(p)) == 0);
            CHECK(qihse_rff_map_get_descriptor(paired, &q, sizeof(q)) == 0);
            CHECK(p.basis_version == QIHSE_RFF_BASIS_VERSION && q.basis_version == QIHSE_RFF_BASIS_VERSION);
            CHECK(p.method == QIHSE_RFF_COSINE_PHASE && q.method == QIHSE_RFF_PAIRED_SINCOS);
            CHECK(p.input_dims == d && q.input_dims == d && p.output_dims == D && q.output_dims == D);
            CHECK(p.seed == 0 && q.seed == 0 && p.gamma == .7 && q.gamma == .7);
            qihse_rff_map_destroy(phase); qihse_rff_map_destroy(paired); qihse_rff_destroy(legacy);
        }
    }
    return 1;
}

static int test_invalid_inputs(void) {
    CHECK(qihse_rff_map_create(1, 3, 1, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(1, 0, 1, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(0, 2, 1, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(1, 2, NAN, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(1, 2, INFINITY, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(1, 2, 0, 42, QIHSE_RFF_COSINE_PHASE) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(1, 2, 1, 42, (qihse_rff_method_t)2) == NULL && errno == EINVAL);
    CHECK(qihse_rff_map_create(SIZE_MAX, 2, 1, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EOVERFLOW);
    CHECK(qihse_rff_map_create(1, SIZE_MAX - 1, 1, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EOVERFLOW);
    CHECK(qihse_rff_map_create(SIZE_MAX / sizeof(double) - 1, 2, 1, 42, QIHSE_RFF_PAIRED_SINCOS) == NULL && errno == EOVERFLOW);
    for (int method = QIHSE_RFF_COSINE_PHASE; method <= QIHSE_RFF_PAIRED_SINCOS; ++method) {
        qihse_rff_map_t* map = qihse_rff_map_create(3, 8, .7, 42, (qihse_rff_method_t)method);
        CHECK(map);
        double input[3] = {NAN, 0, 0}, output[8];
        CHECK(qihse_rff_map_project(map, input, output) == -1 && errno == EDOM);
        for (size_t i = 0; i < 8; ++i) CHECK(isnan(output[i]));
        input[0] = 0;
        CHECK(qihse_rff_map_project(NULL, input, output) == -1 && errno == EINVAL);
        CHECK(qihse_rff_map_project(map, NULL, output) == -1 && errno == EINVAL);
        CHECK(qihse_rff_map_project(map, input, NULL) == -1 && errno == EINVAL);
        double overlap[12] = {1, 2, 3}, before[12]; memcpy(before, overlap, sizeof(before));
        CHECK(qihse_rff_map_project(map, overlap, overlap + 1) == -1 && errno == EINVAL);
        CHECK(memcmp(before, overlap, sizeof(before)) == 0);
        qihse_rff_map_descriptor_t descriptor, saved;
        memset(&descriptor, 0xa5, sizeof(descriptor));
        memcpy(&saved, &descriptor, sizeof(saved));
        CHECK(qihse_rff_map_get_descriptor(map, &descriptor, 0) == -1 && errno == EINVAL);
        CHECK(memcmp(&descriptor, &saved, sizeof(descriptor)) == 0);
        qihse_rff_map_destroy(map);
        map = qihse_rff_map_create(1, 8, DBL_MAX, 42, (qihse_rff_method_t)method);
        CHECK(map);
        double large = DBL_MAX;
        CHECK(qihse_rff_map_project(map, &large, output) == -1 && errno == ERANGE);
        for (size_t i = 0; i < 8; ++i) CHECK(isnan(output[i]));
        qihse_rff_map_destroy(map);
    }
    qihse_rff_map_t* odd_phase = qihse_rff_map_create(1, 3, .7, 0, QIHSE_RFF_COSINE_PHASE);
    CHECK(odd_phase); qihse_rff_map_destroy(odd_phase);
    CHECK(qihse_rff_map_storage_bytes(NULL) == 0);
    qihse_rff_map_destroy(NULL);
    return 1;
}

typedef struct {
    qihse_rff_method_t method;
    const qihse_rff_map_t* shared;
    double expected[64];
    int matched;
} thread_input_t;

static void* repeated_projection(void* argument) {
    thread_input_t* test = argument;
    const double input[] = {-.4, .7, .2};
    double created[64], shared[64];
    qihse_rff_map_t* copy = qihse_rff_map_create(3, 64, .7, 42, test->method);
    test->matched = copy && qihse_rff_map_project(copy, input, created) == 0 &&
        qihse_rff_map_project(test->shared, input, shared) == 0 &&
        !memcmp(created, test->expected, sizeof(created)) && !memcmp(shared, test->expected, sizeof(shared));
    qihse_rff_map_destroy(copy);
    return NULL;
}

static int test_reproducibility_and_kernel(void) {
    const double x[] = {-.4, .7, .2}, y[] = {-.1, .5, .4};
    for (int method = QIHSE_RFF_COSINE_PHASE; method <= QIHSE_RFF_PAIRED_SINCOS; ++method) {
        srand(123); int expected_next = rand(); srand(123);
        qihse_rff_map_t* map = qihse_rff_map_create(3, 64, .7, 42, (qihse_rff_method_t)method);
        CHECK(map && rand() == expected_next);
        pthread_t threads[4]; thread_input_t input[4];
        for (size_t i = 0; i < 4; ++i) {
            input[i].method = (qihse_rff_method_t)method; input[i].shared = map; input[i].matched = 0;
            CHECK(qihse_rff_map_project(map, x, input[i].expected) == 0);
            CHECK(pthread_create(&threads[i], NULL, repeated_projection, &input[i]) == 0);
        }
        for (size_t i = 0; i < 4; ++i) { CHECK(pthread_join(threads[i], NULL) == 0); CHECK(input[i].matched); }
        qihse_rff_map_destroy(map);
        const size_t D = 32768;
        map = qihse_rff_map_create(3, D, .7, 7, (qihse_rff_method_t)method);
        double* zx = malloc(D * sizeof(double)), *zy = malloc(D * sizeof(double));
        CHECK(map && zx && zy);
        CHECK(qihse_rff_map_project(map, x, zx) == 0 && qihse_rff_map_project(map, y, zy) == 0);
        CHECK(fabs(dot(zx, zy, D) - exp(-.7 * .17)) < .03);
        if (method == QIHSE_RFF_PAIRED_SINCOS) CHECK(fabs(dot(zx, zx, D) - 1.0) < 1e-12);
        free(zx); free(zy); qihse_rff_map_destroy(map);
    }
    return 1;
}

int main(void) {
    if (!test_layouts_and_identity() || !test_invalid_inputs() || !test_reproducibility_and_kernel()) return 1;
    puts("RFF maps: PASS (legacy parity, paired identity/norm, equal-byte accounting, failures, reproducibility)");
    return 0;
}
