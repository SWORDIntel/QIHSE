/* Execution contracts for exact, phase-RFF and paired-RFF scalar lookup.
 * Linker allocation wrappers test failure handling without production hooks. */
#include "qihse.h"

#include <assert.h>
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int watch_allocations;
static size_t allocation_attempts, fail_allocation;
static int watch_clock;
static size_t clock_attempts, fail_clock;

void *__real_malloc(size_t bytes);
void *__real_calloc(size_t count, size_t bytes);
void *__real_realloc(void *old, size_t bytes);
int __real_clock_gettime(clockid_t clock_id, struct timespec *value);

int __wrap_clock_gettime(clockid_t clock_id, struct timespec *value) {
    if (watch_clock && ++clock_attempts == fail_clock) {
        errno = EIO;
        return -1;
    }
    return __real_clock_gettime(clock_id, value);
}

static int allocation_fails(void) {
    if (!watch_allocations) return 0;
    ++allocation_attempts;
    if (allocation_attempts != fail_allocation) return 0;
    errno = ENOMEM;
    return 1;
}

void *__wrap_malloc(size_t bytes) {
    return allocation_fails() ? NULL : __real_malloc(bytes);
}
void *__wrap_calloc(size_t count, size_t bytes) {
    return allocation_fails() ? NULL : __real_calloc(count, bytes);
}
void *__wrap_realloc(void *old, size_t bytes) {
    return allocation_fails() ? NULL : __real_realloc(old, bytes);
}

static void allocations_begin(size_t failure) {
    allocation_attempts = 0;
    fail_allocation = failure;
    watch_allocations = 1;
}
static size_t allocations_end(void) {
    watch_allocations = 0;
    return allocation_attempts;
}

static qihse_search_options_t options_for(qihse_search_method_t method, size_t tile) {
    qihse_search_options_t options;
    assert(qihse_search_options_init(&options, sizeof(options)) == 0);
    options.method = method;
    options.tile_size = tile;
    return options;
}

static qihse_search_metrics_t empty_metrics(void) {
    qihse_search_metrics_t metrics;
    assert(qihse_search_metrics_init(&metrics, sizeof(metrics)) == 0);
    return metrics;
}

static qihse_config_t config_for(qihse_data_type_t type, size_t n, size_t dims) {
    qihse_config_t config;
    assert(qihse_config_init(&config, type, n) == 0);
    config.auto_dimensions = false;
    config.fixed_dimensions = dims;
    config.random_seed = 42;
    return config;
}

static void candidate_only(qihse_config_t *config) {
    config->verification.mode = QIHSE_VERIFY_NONE;
    config->verification.fallback_to_classical = false;
}

static void assert_no_features(const qihse_search_metrics_t *metrics) {
    assert(metrics->query_projections == 0);
    assert(metrics->row_projections == 0);
    assert(metrics->projection_failures == 0);
    assert(metrics->kernel_builds == 0);
    assert(metrics->tiles == 0);
    assert(metrics->peak_scratch_bytes == 0);
}

static void test_sized_api_and_argument_guards(void) {
    struct { qihse_search_options_t value; unsigned char guard[16]; } options;
    struct { qihse_search_metrics_t value; unsigned char guard[16]; } metrics;
    unsigned char before_options[sizeof(options)], before_metrics[sizeof(metrics)];
    memset(&options, 0xa5, sizeof(options));
    memset(&metrics, 0x5a, sizeof(metrics));
    memcpy(before_options, &options, sizeof(options));
    memcpy(before_metrics, &metrics, sizeof(metrics));
    errno = 0;
    assert(qihse_search_options_init(&options.value, sizeof(options.value) - 1) == -1);
    assert(errno == EINVAL && memcmp(&options, before_options, sizeof(options)) == 0);
    errno = 0;
    assert(qihse_search_metrics_init(&metrics.value, sizeof(metrics.value) - 1) == -1);
    assert(errno == EINVAL && memcmp(&metrics, before_metrics, sizeof(metrics)) == 0);
    assert(qihse_search_options_init(&options.value, sizeof(options.value)) == 0);
    assert(qihse_search_metrics_init(&metrics.value, sizeof(metrics.value)) == 0);
    for (size_t i = 0; i < sizeof(options.guard); ++i) assert(options.guard[i] == 0xa5);
    for (size_t i = 0; i < sizeof(metrics.guard); ++i) assert(metrics.guard[i] == 0x5a);
    assert(options.value.struct_size == sizeof(options.value));
    assert(options.value.version == QIHSE_SEARCH_OPTIONS_VERSION);
    assert(options.value.method == QIHSE_SEARCH_RFF_COSINE && options.value.tile_size == 16);
    assert(qihse_search_options_init(NULL, sizeof(options.value)) == -1);
    assert(qihse_search_metrics_init(NULL, sizeof(metrics.value)) == -1);

    int64_t data[] = {7, 11};
    not_stisla_result_t result;
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, 2, 64);
    qihse_search_options_t valid = options_for(QIHSE_SEARCH_EXACT, 1), invalid;
    for (size_t kind = 0; kind < 5; ++kind) {
        invalid = valid;
        if (kind == 0) invalid.method = (qihse_search_method_t)99;
        if (kind == 1) invalid.tile_size = 0;
        if (kind == 2) invalid.tile_size = QIHSE_SEARCH_MAX_TILE_SIZE + 1;
        if (kind == 3) ++invalid.version;
        if (kind == 4) invalid.struct_size = sizeof(invalid) - 1;
        errno = 0;
        assert(qihse_search_ex(data, 2, &data[1], NULL, &config, &invalid,
                               &result, NULL) == -1 && errno == EINVAL);
    }
    for (size_t kind = 0; kind < 2; ++kind) {
        metrics.value = empty_metrics();
        if (kind == 0) ++metrics.value.version;
        else metrics.value.struct_size = sizeof(metrics.value) - 1;
        memcpy(before_metrics, &metrics, sizeof(metrics));
        errno = 0;
        assert(qihse_search_ex(data, 2, &data[1], NULL, &config, &valid,
                               &result, &metrics.value) == -1 && errno == EINVAL);
        assert(memcmp(before_metrics, &metrics, sizeof(metrics)) == 0);
    }
    assert(qihse_search_ex(NULL, 2, data, NULL, &config, &valid, &result, NULL) == -1);
    assert(qihse_search_ex(data, 0, data, NULL, &config, &valid, &result, NULL) == -1);
    assert(qihse_search_ex(data, 2, NULL, NULL, &config, &valid, &result, NULL) == -1);
    assert(qihse_search_ex(data, 2, data, NULL, NULL, &valid, &result, NULL) == -1);
    assert(qihse_search_ex(data, 2, data, NULL, &config, &valid, NULL, NULL) == -1);
    metrics.value = empty_metrics();
    assert(qihse_batch_search_ex(data, 2, NULL, 0, NULL, NULL, &config,
                                 &valid, &metrics.value) == 0);
    assert(metrics.value.queries == 0 && metrics.value.matches == 0);
    assert_no_features(&metrics.value);
    errno = 0;
    assert(qihse_search_ex(data, SIZE_MAX, data, NULL, &config, &valid,
                           &result, NULL) == -1 && errno == EOVERFLOW);
    errno = 0;
    assert(qihse_batch_search_ex(data, 2, data, SIZE_MAX, &result, NULL, &config,
                                 &valid, NULL) == -1 && errno == EOVERFLOW);
    config = config_for(QIHSE_TYPE_BINARY, 2, 64);
    config.type_descriptor.element_size = 1;
    errno = 0;
    assert(qihse_batch_search_ex(data, 2, data, SIZE_MAX / sizeof(result) + 1,
                                 &result, NULL, &config, &valid, NULL) == -1);
    assert(errno == EOVERFLOW);
    puts("PASS sized options/metrics, invalid selectors, pointers and byte-count guards");
}

static void test_exact_is_allocation_free(void) {
    int64_t data[] = {INT64_MIN, -9, INT64_C(9007199254740992),
        INT64_C(9007199254740993), INT64_C(9007199254740993), INT64_MAX};
    int64_t queries[] = {INT64_MIN, INT64_C(9007199254740993), -9, INT64_MAX, 100};
    const not_stisla_result_t expected[] = {0, 3, 1, 5, NOT_STISLA_NOT_FOUND};
    not_stisla_result_t results[5];
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, 6, 64);
    candidate_only(&config);
    /* An exact equality scan does not depend on any projection setting. */
    config.rff_gamma = NAN;
    config.min_dimensions = config.max_dimensions = 0;
    config.fixed_dimensions = SIZE_MAX;
    qihse_search_options_t options = options_for(QIHSE_SEARCH_EXACT, 7);
    qihse_search_metrics_t metrics = empty_metrics();
    allocations_begin(1);
    int rc = qihse_batch_search_ex(data, 6, queries, 5, results, NULL, &config,
                                  &options, &metrics);
    size_t attempts = allocations_end();
    assert(rc == 0 && attempts == 0);
    assert(memcmp(results, expected, sizeof(results)) == 0);
    assert(metrics.method == QIHSE_SEARCH_EXACT);
    assert(metrics.queries == 5 && metrics.matches == 4 && metrics.direct_queries == 5);
    assert(metrics.candidate_hits == 0 && metrics.fallback_queries == 0);
    assert(metrics.fallback_hits == 0 && metrics.unprojected_queries == 0);
    assert(metrics.comparisons == 19);
    assert_no_features(&metrics);
    assert(qihse_search_ex(data, 6, &queries[1], NULL, &config, &options,
                           &results[0], NULL) == 0 && results[0] == 3);
    puts("PASS allocation-free exact method, first duplicates and 64-bit equality");
}

static void test_candidates_without_fallback(void) {
    int64_t data[32], queries[33];
    not_stisla_result_t results[33];
    for (size_t i = 0; i < 32; ++i) data[i] = queries[i] = (int64_t)i * 4;
    queries[32] = 999;
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, 32, 512);
    candidate_only(&config);
    for (int method = QIHSE_SEARCH_RFF_COSINE; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 7);
        qihse_search_metrics_t metrics = empty_metrics();
        assert(qihse_batch_search_ex(data, 32, queries, 33, results, NULL, &config,
                                     &options, &metrics) == 0);
        for (size_t i = 0; i < 32; ++i) assert(results[i] == i);
        assert(results[32] == NOT_STISLA_NOT_FOUND);
        assert(metrics.matches == 32 && metrics.candidate_hits == 32);
        assert(metrics.fallback_queries == 0 && metrics.fallback_hits == 0);
        assert(metrics.query_projections == 33 && metrics.row_projections == 32 * 5);
        assert(metrics.kernel_builds == 1 && metrics.tiles == 5 && metrics.dimensions == 512);
        assert(metrics.comparisons == 33 && metrics.projection_failures == 0);
        assert(metrics.unprojected_queries == 0 && metrics.direct_queries == 0);
    }

    /* Integer-to-double collision: projection cannot distinguish these values.
     * Recovery must be credited to exact fallback, never to candidate coverage. */
    int64_t close[] = {INT64_C(9007199254740992), INT64_C(9007199254740993)};
    for (int method = QIHSE_SEARCH_RFF_COSINE; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 1);
        qihse_search_metrics_t metrics = empty_metrics();
        not_stisla_result_t result;
        candidate_only(&config);
        assert(qihse_search_ex(close, 2, &close[1], NULL, &config, &options,
                               &result, &metrics) == 0);
        assert(result == NOT_STISLA_NOT_FOUND && metrics.candidate_hits == 0);
        assert(metrics.matches == 0 && metrics.fallback_queries == 0);
        assert(metrics.comparisons == 1);
        config.verification.mode = QIHSE_VERIFY_EXACT;
        config.verification.fallback_to_classical = true;
        assert(qihse_search_ex(close, 2, &close[1], NULL, &config, &options,
                               &result, &metrics) == 0);
        assert(result == 1 && metrics.matches == 1 && metrics.candidate_hits == 0);
        assert(metrics.fallback_queries == 1 && metrics.fallback_hits == 1);
    }
    puts("PASS query-dependent candidates without fallback and honest fallback accounting");
}

static void add_outcome_counters(qihse_search_metrics_t *sum,
                                 const qihse_search_metrics_t *one) {
    sum->matches += one->matches;
    sum->candidate_hits += one->candidate_hits;
    sum->fallback_queries += one->fallback_queries;
    sum->fallback_hits += one->fallback_hits;
    sum->direct_queries += one->direct_queries;
    sum->unprojected_queries += one->unprojected_queries;
    sum->comparisons += one->comparisons;
}

static void assert_outcome_counters(const qihse_search_metrics_t *batch,
                                    const qihse_search_metrics_t *singles) {
    assert(batch->matches == singles->matches);
    assert(batch->candidate_hits == singles->candidate_hits);
    assert(batch->fallback_queries == singles->fallback_queries);
    assert(batch->fallback_hits == singles->fallback_hits);
    assert(batch->direct_queries == singles->direct_queries);
    assert(batch->unprojected_queries == singles->unprojected_queries);
    assert(batch->comparisons == singles->comparisons);
}

static void test_batch_tiles_and_unaligned_records(void) {
    enum { N = 17, Q = 67, STRIDE = 9 };
    unsigned char data_store[N * STRIDE + 1], query_store[Q * STRIDE + 1];
    unsigned char *data = data_store + 1, *queries = query_store + 1;
    int64_t values[N];
    not_stisla_result_t singles[Q], batch[Q], exact_expected[Q];
    const size_t tiles[] = {1, 2, 7, 16, 64};
    memset(data_store, 0xa5, sizeof(data_store));
    memset(query_store, 0x5a, sizeof(query_store));
    for (size_t i = 0; i < N; ++i) values[i] = (int64_t)i * 4 - 20;
    values[14] = values[3];
    for (size_t i = 0; i < N; ++i) memcpy(data + i * STRIDE, &values[i], sizeof(values[i]));
    for (size_t i = 0; i < Q; ++i) {
        int64_t value = i % 11 == 0 ? (int64_t)i + 10000 : values[(i * 7) % N];
        memcpy(queries + i * STRIDE, &value, sizeof(value));
        exact_expected[i] = NOT_STISLA_NOT_FOUND;
        for (size_t j = 0; j < N; ++j) if (values[j] == value) { exact_expected[i] = j; break; }
    }
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, N, 64);
    config.type_descriptor.element_size = STRIDE;
    for (int exhaustive = 0; exhaustive <= 1; ++exhaustive) {
        config.verification.mode = exhaustive ? QIHSE_VERIFY_EXACT : QIHSE_VERIFY_NONE;
        config.verification.fallback_to_classical = exhaustive != 0;
        for (int method = QIHSE_SEARCH_EXACT; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
            qihse_search_options_t options = options_for((qihse_search_method_t)method, 1);
            qihse_search_metrics_t summed = empty_metrics();
            for (size_t i = 0; i < Q; ++i) {
                qihse_search_metrics_t one = empty_metrics();
                assert(qihse_search_ex(data, N, queries + i * STRIDE, NULL, &config,
                                       &options, &singles[i], &one) == 0);
                add_outcome_counters(&summed, &one);
                if (exhaustive || method == QIHSE_SEARCH_EXACT)
                    assert(singles[i] == exact_expected[i]);
            }
            for (size_t t = 0; t < sizeof(tiles) / sizeof(tiles[0]); ++t) {
                options.tile_size = tiles[t];
                qihse_search_metrics_t metrics = empty_metrics();
                assert(qihse_batch_search_ex(data, N, queries, Q, batch, NULL,
                                             &config, &options, &metrics) == 0);
                assert(memcmp(singles, batch, sizeof(batch)) == 0);
                assert(metrics.queries == Q && metrics.method == (qihse_search_method_t)method);
                assert_outcome_counters(&metrics, &summed);
                if (method == QIHSE_SEARCH_EXACT) {
                    assert_no_features(&metrics);
                } else {
                    size_t expected_tiles = Q / tiles[t] + (Q % tiles[t] != 0);
                    assert(metrics.tiles == expected_tiles && metrics.tile_size == tiles[t]);
                    assert(metrics.kernel_builds == 1 && metrics.query_projections == Q);
                    assert(metrics.row_projections == N * expected_tiles);
                    assert(metrics.dimensions == 64 && metrics.peak_scratch_bytes > 0);
                }
            }
        }
    }
    for (size_t i = 0; i < N; ++i) assert(data[i * STRIDE + 8] == 0xa5);
    for (size_t i = 0; i < Q; ++i) assert(queries[i * STRIDE + 8] == 0x5a);
    puts("PASS single/batch parity, duplicate ties, unaligned strides and every tail tile");
}

struct record { int key; int payload; };
static size_t comparator_calls;
static int compare_record(const void *left, const void *right) {
    struct record a, b;
    memcpy(&a, left, sizeof(a));
    memcpy(&b, right, sizeof(b));
    ++comparator_calls;
    return (a.key > b.key) - (a.key < b.key);
}

static void test_nonnumeric_and_comparator_accounting(void) {
    struct record data[] = {{1, 99}, {7, 3}, {7, 4}};
    struct record queries[] = {{7, -100}, {-9, 0}, {1, 100}};
    const not_stisla_result_t expected[] = {1, NOT_STISLA_NOT_FOUND, 0};
    not_stisla_result_t results[4];
    qihse_config_t config = config_for(QIHSE_TYPE_CUSTOM, 3, 64);
    config.type_descriptor.element_size = sizeof(struct record);
    config.type_descriptor.compare_fn = compare_record;
    for (int method = QIHSE_SEARCH_EXACT; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 2);
        qihse_search_metrics_t metrics = empty_metrics();
        comparator_calls = 0;
        assert(qihse_batch_search_ex(data, 3, queries, 3, results, NULL, &config,
                                     &options, &metrics) == 0);
        assert(memcmp(results, expected, sizeof(expected)) == 0);
        assert(metrics.comparisons == comparator_calls && comparator_calls == 6);
        assert(metrics.matches == 2 && metrics.candidate_hits == 0);
        assert_no_features(&metrics);
        if (method == QIHSE_SEARCH_EXACT) {
            assert(metrics.direct_queries == 3 && metrics.unprojected_queries == 0);
        } else {
            assert(metrics.unprojected_queries == 3 && metrics.direct_queries == 0);
            assert(metrics.fallback_queries == 3 && metrics.fallback_hits == 2);
        }
    }

    char words[][8] = {"alpha", "beta", "gamma"};
    char word_queries[][8] = {"beta", "xxxxxxxx", "delta", "alpha"};
    config = config_for(QIHSE_TYPE_STRING, 3, 64);
    config.type_descriptor.element_size = sizeof(words[0]);
    for (int method = QIHSE_SEARCH_EXACT; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 2);
        qihse_search_metrics_t metrics = empty_metrics();
        assert(qihse_batch_search_ex(words, 3, word_queries, 4, results, NULL,
                                     &config, &options, &metrics) == 0);
        assert(results[0] == 1 && results[1] == NOT_STISLA_NOT_FOUND);
        assert(results[2] == NOT_STISLA_NOT_FOUND && results[3] == 0);
        assert_no_features(&metrics);
    }
    puts("PASS custom equality, bounded strings and independently counted comparisons");
}

static void test_nonfinite_and_unprojectable_values(void) {
    double data[] = {NAN, -INFINITY, -0.0, .5, INFINITY, DBL_MAX, -DBL_MAX, 2.0};
    double queries[] = {NAN, -INFINITY, 0.0, .5, INFINITY, DBL_MAX, -DBL_MAX, 2.0};
    not_stisla_result_t results[8];
    qihse_config_t config = config_for(QIHSE_TYPE_DOUBLE, 8, 64);
    for (int method = QIHSE_SEARCH_EXACT; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 2);
        qihse_search_metrics_t metrics = empty_metrics();
        assert(qihse_batch_search_ex(data, 8, queries, 8, results, NULL, &config,
                                     &options, &metrics) == 0);
        assert(results[0] == NOT_STISLA_NOT_FOUND);
        for (size_t i = 1; i < 8; ++i) assert(results[i] == i);
        assert(metrics.matches == 7);
        if (method == QIHSE_SEARCH_EXACT) assert_no_features(&metrics);
        else {
            assert(metrics.unprojected_queries >= 3);
            assert(metrics.projection_failures > 0);
            assert(metrics.fallback_hits >= 2);
        }
    }
    puts("PASS finite projection overflow, NaN, infinities and signed-zero equality");
}

static void test_memory_defaults_and_paired_dimension_policy(void) {
    int64_t data[256], queries[] = {4, 12, 999};
    for (size_t i = 0; i < 256; ++i) data[i] = (int64_t)i * 4;
    not_stisla_result_t results[3], defaults[3];
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, 256, 64);
    qihse_search_metrics_t first = empty_metrics(), second = empty_metrics();
    for (int method = QIHSE_SEARCH_RFF_COSINE; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 7);
        assert(qihse_batch_search_ex(data, 4, queries, 3, results, NULL, &config,
                                     &options, &first) == 0);
        qihse_search_metrics_t saved = first;
        assert(qihse_batch_search_ex(data, 256, queries, 3, results, NULL, &config,
                                     &options, &second) == 0);
        assert(first.peak_scratch_bytes == second.peak_scratch_bytes);
        assert(memcmp(&first, &saved, sizeof(first)) == 0);
    }
    qihse_search_options_t phase = options_for(QIHSE_SEARCH_RFF_COSINE, 16);
    assert(qihse_batch_search_ex(data, 256, queries, 3, defaults, NULL, &config,
                                 NULL, &first) == 0);
    assert(qihse_batch_search_ex(data, 256, queries, 3, results, NULL, &config,
                                 &phase, NULL) == 0);
    assert(memcmp(defaults, results, sizeof(results)) == 0);
    assert(first.method == QIHSE_SEARCH_RFF_COSINE && first.tile_size == 3);

    config.fixed_dimensions = 65;
    qihse_search_options_t paired = options_for(QIHSE_SEARCH_RFF_PAIRED, 1);
    errno = 0;
    assert(qihse_search_ex(data, 256, queries, NULL, &config, &paired,
                           &results[0], NULL) == -1 && errno == EINVAL);
    assert(qihse_search_ex(data, 256, queries, NULL, &config, &phase,
                           &results[0], NULL) == 0 && results[0] == 1);
    puts("PASS N-independent scratch, independent metrics, defaults and paired even-D rule");
}

static void test_allocation_failures_are_transactional(void) {
    int64_t data[] = {0, 4, 8, 12, 16, 20};
    int64_t queries[] = {0, 4, 999, 12, 16, 20, 8};
    not_stisla_result_t results[7];
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, 6, 64);
    for (int method = QIHSE_SEARCH_RFF_COSINE; method <= QIHSE_SEARCH_RFF_PAIRED; ++method) {
        qihse_search_options_t options = options_for((qihse_search_method_t)method, 3);
        qihse_search_metrics_t metrics = empty_metrics();
        allocations_begin(SIZE_MAX);
        int rc = qihse_batch_search_ex(data, 6, queries, 7, results, NULL,
                                      &config, &options, &metrics);
        size_t baseline = allocations_end();
        assert(rc == 0 && baseline > 0);
        for (size_t failure = 1; failure <= baseline; ++failure) {
            for (size_t i = 0; i < 7; ++i) results[i] = 12345;
            metrics = empty_metrics();
            errno = 0;
            allocations_begin(failure);
            rc = qihse_batch_search_ex(data, 6, queries, 7, results, NULL,
                                       &config, &options, &metrics);
            int error = errno;
            allocations_end();
            assert(rc == -1 && error == ENOMEM);
            for (size_t i = 0; i < 7; ++i) assert(results[i] == NOT_STISLA_NOT_FOUND);
            assert(metrics.matches == 0 && metrics.candidate_hits == 0);
        }
        results[0] = 12345;
        allocations_begin(1);
        rc = qihse_search_ex(data, 6, queries, NULL, &config, &options, &results[0], NULL);
        int error = errno;
        allocations_end();
        assert(rc == -1 && error == ENOMEM && results[0] == NOT_STISLA_NOT_FOUND);
    }
    puts("PASS every allocation failure leaves deterministic empty outputs");
}

static void test_failed_clock_reads(void) {
    int64_t data[] = {3, 7, 11}, queries[] = {7, 99, 3};
    const not_stisla_result_t expected[] = {1, NOT_STISLA_NOT_FOUND, 0};
    not_stisla_result_t results[3];
    qihse_config_t config = config_for(QIHSE_TYPE_INT64, 3, 64);
    qihse_search_options_t options = options_for(QIHSE_SEARCH_EXACT, 1);
    qihse_search_metrics_t metrics = empty_metrics();
    clock_attempts = 0; fail_clock = SIZE_MAX; watch_clock = 1;
    int rc = qihse_batch_search_ex(data, 3, queries, 3, results, NULL, &config,
                                  &options, &metrics);
    watch_clock = 0;
    size_t baseline = clock_attempts;
    assert(rc == 0 && baseline > 0);
    for (size_t failure = 1; failure <= baseline; ++failure) {
        metrics = empty_metrics();
        clock_attempts = 0; fail_clock = failure; watch_clock = 1;
        rc = qihse_batch_search_ex(data, 3, queries, 3, results, NULL, &config,
                                   &options, &metrics);
        watch_clock = 0;
        assert(rc == 0 && memcmp(results, expected, sizeof(results)) == 0);
        assert(isfinite(metrics.setup_time_ns) && metrics.setup_time_ns >= 0.0);
        assert(isfinite(metrics.scoring_time_ns) && metrics.scoring_time_ns >= 0.0);
        assert(isfinite(metrics.verification_time_ns) && metrics.verification_time_ns >= 0.0);
        assert(isfinite(metrics.total_time_ns) && metrics.total_time_ns >= 0.0);
        if (failure == 1) {
            assert(metrics.setup_time_ns == 0.0 && metrics.total_time_ns == 0.0);
        }
    }
    puts("PASS failed clock reads preserve results and do not fabricate elapsed times");
}

int main(void) {
    test_sized_api_and_argument_guards();
    test_exact_is_allocation_free();
    test_candidates_without_fallback();
    test_batch_tiles_and_unaligned_records();
    test_nonnumeric_and_comparator_accounting();
    test_nonfinite_and_unprojectable_values();
    test_memory_defaults_and_paired_dimension_policy();
    test_allocation_failures_are_transactional();
    test_failed_clock_reads();
    return 0;
}
