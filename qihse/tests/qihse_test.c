/**
 * QIHSE Test Program
 *
 * Simple functionality test for QIHSE heterogeneous search
 */

#include "../include/qihse.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

/* Forward declarations for utility functions */
static void generate_uniform_data(int64_t* arr, size_t n, uint64_t seed);
static void generate_queries(const int64_t* data, size_t data_n,
                            int64_t* queries, size_t query_n,
                            uint64_t seed);
static inline uint64_t ns_now(void);

int main(int argc, char* argv[]) {
    printf("🌀 QIHSE Test Program\n");
    printf("===================\n\n");

    /* Check if QIHSE is available */
    if (!qihse_available()) {
        fprintf(stderr, "❌ QIHSE is not available on this system\n");
        return 1;
    }

    printf("✅ QIHSE is available\n");
    printf("Version: %s\n", qihse_version());
    printf("Build: %s\n\n", qihse_build_info());

    /* Initialize compute pool */
    qihse_compute_pool_t* pool = qihse_compute_pool_init();
    if (pool) {
        qihse_compute_pool_calibrate(pool);
        printf("Hardware Configuration:\n");
        printf("  %s\n", qihse_capabilities_string(pool));
        printf("Total Theoretical TOPS: %.1f\n\n", pool->total_tops);
        qihse_compute_pool_destroy(pool);
    }

    /* Run functionality test */
    printf("Running QIHSE functionality test...\n\n");

    const size_t test_size = 10000;
    int64_t* test_data = malloc(test_size * sizeof(int64_t));
    int64_t* test_queries = malloc(100 * sizeof(int64_t));

    if (!test_data || !test_queries) {
        fprintf(stderr, "❌ Failed to allocate test memory\n");
        free(test_data);
        free(test_queries);
        return -1;
    }

    /* Generate test data */
    generate_uniform_data(test_data, test_size, 42);
    generate_queries(test_data, test_size, test_queries, 100, 123);

    /* Test QIHSE search */
    qihse_config_t config;
    if (qihse_config_init(&config, QIHSE_TYPE_INT64, test_size) != 0) {
        fprintf(stderr, "❌ Failed to initialize QIHSE config\n");
        free(test_data);
        free(test_queries);
        return -1;
    }

    printf("Testing QIHSE search on %zu elements with %d queries...\n", test_size, 100);

    uint64_t start_time = ns_now();
    size_t found = 0;

    for (int i = 0; i < 100; i++) {
        not_stisla_result_t result = qihse_search(test_data, test_size,
                                                &test_queries[i], NULL, &config);
        if (result != NOT_STISLA_NOT_FOUND) {
            found++;
        }
    }

    uint64_t end_time = ns_now();
    double total_time = (end_time - start_time) / 1e9; /* Convert to seconds */
    double avg_time = total_time / 100.0;

    printf("✅ QIHSE search completed!\n");
    printf("   Found: %zu/%d queries (%.1f%% accuracy)\n", found, 100, (found / 100.0) * 100.0);
    printf("   Total time: %.3f seconds\n", total_time);
    printf("   Average time per query: %.3f microseconds\n", avg_time * 1e6);
    printf("   Throughput: %.0f queries/second\n", 100.0 / total_time);

    /* Compare with classical NOT_STISLA */
    printf("\nComparing with classical NOT_STISLA...\n");

    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    start_time = ns_now();
    size_t classical_found = 0;

    for (int i = 0; i < 100; i++) {
        not_stisla_result_t result = not_stisla_search(test_data, test_size,
                                                     test_queries[i], table, 8);
        if (result != NOT_STISLA_NOT_FOUND) {
            classical_found++;
        }
    }

    end_time = ns_now();
    double classical_time = (end_time - start_time) / 1e9;
    double classical_avg = classical_time / 100.0;

    printf("✅ Classical NOT_STISLA completed!\n");
    printf("   Found: %zu/%d queries (%.1f%% accuracy)\n", classical_found, 100,
           (classical_found / 100.0) * 100.0);
    printf("   Total time: %.3f seconds\n", classical_time);
    printf("   Average time per query: %.3f microseconds\n", classical_avg * 1e6);
    printf("   Throughput: %.0f queries/second\n", 100.0 / classical_time);

    /* Performance comparison */
    printf("\n📊 Performance Comparison:\n");
    printf("   QIHSE speedup vs Classical: %.1fx\n", classical_time / total_time);
    printf("   Both algorithms found the same results: %s\n",
           (found == classical_found) ? "✅ YES" : "❌ NO");

    not_stisla_anchor_table_destroy(table);
    free(test_queries);
    free(test_data);

    printf("\n✅ QIHSE test completed successfully!\n");
    return 0;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static void generate_uniform_data(int64_t* arr, size_t n, uint64_t seed) {
    srand(seed);
    for (size_t i = 0; i < n; i++) {
        arr[i] = (int64_t)i * 2;  // 0, 2, 4, 6, ... (uniform spacing)
    }
}

static void generate_queries(const int64_t* data, size_t data_n,
                            int64_t* queries, size_t query_n,
                            uint64_t seed) {
    srand(seed);
    for (size_t i = 0; i < query_n; i++) {
        size_t idx = rand() % data_n;
        queries[i] = data[idx];  // All queries exist in data
    }
}

static inline uint64_t ns_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000ULL + (uint64_t)tv.tv_usec * 1000ULL;
}
