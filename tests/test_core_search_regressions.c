#include "qihse.h"
#include <assert.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_queries_and_absence(void) {
    int64_t data[32], queries[33];
    not_stisla_result_t results[33];
    qihse_config_t config;
    assert(qihse_config_init(&config, QIHSE_TYPE_INT64, 32) == 0);
    assert(config.type_descriptor.element_size == sizeof(int64_t));
    assert(config.rff_gamma > 0 && config.verification.mode == QIHSE_VERIFY_EXACT);
    for (size_t i = 0; i < 32; ++i) data[i] = queries[i] = (int64_t)i * 4;
    queries[32] = 999;
    assert(qihse_batch_search(data, 32, queries, 33, results, NULL, &config) == 32);
    for (size_t i = 0; i < 32; ++i) assert(results[i] == i);
    assert(results[32] == NOT_STISLA_NOT_FOUND);

    /* A complete fallback must not hide query-independent candidate scoring. */
    config.auto_dimensions = false;
    config.fixed_dimensions = 512;
    config.verification.mode = QIHSE_VERIFY_NONE;
    config.verification.fallback_to_classical = false;
    for (size_t i = 0; i < 32; ++i)
        assert(qihse_search(data, 32, &data[i], NULL, &config) == i);
    assert(qihse_search(data, 32, &queries[32], NULL, &config) == NOT_STISLA_NOT_FOUND);

    qihse_verify_config_t verification;
    qihse_verify_config_init(&verification, 1.0);
    qihse_collapse_result_t collapse = {.predicted_index = 0, .confidence = 1.0};
    assert(qihse_verify_result(data, 32, &data[31], QIHSE_TYPE_INT64, &collapse, &verification) == 31);
    assert(qihse_verify_search_result(data, 32, &queries[32], QIHSE_TYPE_INT64, &collapse, &verification) == NOT_STISLA_NOT_FOUND);
    collapse.predicted_index = SIZE_MAX - 1;
    assert(qihse_verify_result(data, 32, &queries[32], QIHSE_TYPE_INT64, &collapse, &verification) == NOT_STISLA_NOT_FOUND);
    assert(qihse_verify_result(data, 32, &data[31], QIHSE_TYPE_INT64, &collapse, &verification) == 31);
    puts("PASS 32/32 values, absent queries, query-dependent candidates and exact verification");
}

static void test_original_precision(void) {
    int64_t signed_values[] = {INT64_MIN, -1, INT64_C(9007199254740992), INT64_C(9007199254740993), INT64_MAX};
    uint64_t unsigned_values[] = {UINT64_C(9007199254740992), UINT64_C(9007199254740993), UINT64_MAX};
    qihse_config_t config;
    assert(qihse_config_init(&config, QIHSE_TYPE_INT64, 5) == 0);
    for (size_t i = 0; i < 5; ++i)
        assert(qihse_search(signed_values, 5, &signed_values[i], NULL, &config) == i);
    assert(qihse_config_init(&config, QIHSE_TYPE_UINT64, 3) == 0);
    for (size_t i = 0; i < 3; ++i)
        assert(qihse_search(unsigned_values, 3, &unsigned_values[i], NULL, &config) == i);

    double values[] = {NAN, -INFINITY, -0.0, 0.5, INFINITY};
    assert(qihse_config_init(&config, QIHSE_TYPE_DOUBLE, 5) == 0);
    assert(qihse_search(values, 5, &values[0], NULL, &config) == NOT_STISLA_NOT_FOUND);
    for (size_t i = 1; i < 5; ++i)
        assert(qihse_search(values, 5, &values[i], NULL, &config) == i);
    double zero = 0.0;
    assert(qihse_search(values, 5, &zero, NULL, &config) == 2);
    puts("PASS original integer precision, infinities, NaN and signed-zero semantics");
}

struct record { int key; int payload; };
static int compare_record(const void* lhs, const void* rhs) {
    const struct record* a = lhs;
    const struct record* b = rhs;
    return (a->key > b->key) - (a->key < b->key);
}

static void test_record_layouts(void) {
    qihse_config_t config;
    unsigned char padded[27] = {0};
    int64_t numbers[] = {7, 11, 17};
    for (size_t i = 0; i < 3; ++i) memcpy(padded + i * 9, &numbers[i], sizeof(int64_t));
    assert(qihse_config_init(&config, QIHSE_TYPE_INT64, 3) == 0);
    config.type_descriptor.element_size = 9;
    for (size_t i = 0; i < 3; ++i)
        assert(qihse_search(padded, 3, &numbers[i], NULL, &config) == i);

    char words[][8] = {"alpha", "beta", "gamma"};
    assert(qihse_config_init(&config, QIHSE_TYPE_STRING, 3) == 0);
    config.type_descriptor.element_size = 8;
    assert(qihse_search(words, 3, "beta", NULL, &config) == 1);
    assert(qihse_search(words, 3, "delta", NULL, &config) == NOT_STISLA_NOT_FOUND);
    char unterminated[8]; memset(unterminated, 'x', sizeof(unterminated));
    assert(qihse_search(words, 3, unterminated, NULL, &config) == NOT_STISLA_NOT_FOUND);

    unsigned char blobs[][3] = {{0, 1, 0}, {3, 0, 4}};
    assert(qihse_config_init(&config, QIHSE_TYPE_BINARY, 2) == 0);
    config.type_descriptor.element_size = 3;
    assert(qihse_search(blobs, 2, blobs[1], NULL, &config) == 1);
    struct record records[] = {{1, 2}, {3, 4}}, query = {3, 999};
    assert(qihse_config_init(&config, QIHSE_TYPE_CUSTOM, 2) == 0);
    config.type_descriptor.element_size = sizeof(struct record);
    config.type_descriptor.compare_fn = compare_record;
    assert(qihse_search(records, 2, &query, NULL, &config) == 1);
    puts("PASS unaligned strides, bounded strings, binary and custom equality");
}

static void test_bounds_and_memory(void) {
    int64_t* data = malloc(4096 * sizeof(*data));
    assert(data);
    for (size_t i = 0; i < 4096; ++i) data[i] = (int64_t)i;
    qihse_config_t config;
    assert(qihse_config_init(&config, QIHSE_TYPE_INT64, 4096) == 0);
    config.auto_dimensions = false;
    config.fixed_dimensions = 64;
    config.enable_profiling = true;
    qihse_performance_stats_t small, large;
    assert(qihse_search(data, 32, &data[3], NULL, &config) == 3);
    assert(qihse_get_performance_stats(&small) == 0);
    assert(qihse_search(data, 4096, &data[4000], NULL, &config) == 4000);
    assert(qihse_get_performance_stats(&large) == 0);
    assert(small.peak_memory_bytes == large.peak_memory_bytes);
    assert(large.peak_memory_bytes == 4 * 64 * sizeof(double) + sizeof(qihse_rff_kernel_t));
    errno = 0;
    assert(qihse_search(data, SIZE_MAX, data, NULL, &config) == NOT_STISLA_NOT_FOUND);
    assert(errno == EOVERFLOW);
    not_stisla_result_t result;
    errno = 0;
    assert(qihse_batch_search(data, 1, data, SIZE_MAX, &result, NULL, &config) == 0);
    assert(errno == EOVERFLOW);
    qihse_config_t narrow;
    assert(qihse_config_init(&narrow, QIHSE_TYPE_BINARY, 1) == 0);
    narrow.type_descriptor.element_size = 1;
    errno = 0;
    assert(qihse_batch_search(data, 1, data, SIZE_MAX / sizeof(result) + 1,
                              &result, NULL, &narrow) == 0);
    assert(errno == EOVERFLOW);
    config.type_descriptor.element_size = 0;
    assert(qihse_search(data, 32, data, NULL, &config) == NOT_STISLA_NOT_FOUND);
    config.type_descriptor.element_size = sizeof(int64_t);
    config.rff_gamma = NAN;
    assert(qihse_search(data, 32, data, NULL, &config) == NOT_STISLA_NOT_FOUND);
    config.rff_gamma = 1.0;
    config.min_dimensions = config.max_dimensions + 1;
    assert(qihse_search(data, 32, data, NULL, &config) == NOT_STISLA_NOT_FOUND);
    free(data);
    puts("PASS checked sizes, invalid configurations and N-independent projection storage");
}

static void test_collapse_and_diffusion(void) {
    double values[] = {DBL_MAX / 2, DBL_MAX / 2, DBL_MAX / 2, DBL_MAX / 2};
    double imaginary[4] = {0};
    qihse_superposition_t state = {0};
    assert(qihse_create_superposition_from_amplitudes(values, imaginary, 4, &state) == 0);
    qihse_apply_grover_diffusion(&state);
    for (size_t i = 0; i < 4; ++i) assert(state.real[i] == values[i]);
    qihse_collapse_result_t collapse = qihse_dimensional_collapse_l2_norm(&state);
    assert(collapse.predicted_index == 0 && collapse.confidence == .25);
    qihse_superposition_t forged = state;
    forged.num_states = SIZE_MAX / sizeof(double) + 1;
    errno = 0;
    collapse = qihse_dimensional_collapse_l2_norm(&forged);
    assert(collapse.predicted_index == NOT_STISLA_NOT_FOUND && errno == EOVERFLOW);
    qihse_destroy_superposition(&state);
    puts("PASS shared diffusion implementation and bounded normalized collapse");
}

int main(void) {
    test_queries_and_absence();
    test_original_precision();
    test_record_layouts();
    test_bounds_and_memory();
    test_collapse_and_diffusion();
    return 0;
}
