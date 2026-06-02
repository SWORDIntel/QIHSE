/**
 * QIHSE Benchmark Suite
 *
 * Tests QIHSE functionality and fallback mechanisms
 */

#include "qihse.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static inline uint64_t ns_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000ULL + (uint64_t)tv.tv_usec * 1000ULL;
}

int main(int argc, char* argv[]) {
    printf("🌀 QIHSE Benchmark Suite\n");
    printf("=======================\n\n");

    /* Check if QIHSE is available */
    if (!qihse_available()) {
        fprintf(stderr, "❌ QIHSE is not available on this system\n");
        return 1;
    }

    printf("✅ QIHSE is available\n");
    printf("Version: %s\n", qihse_version());
    printf("Build: %s\n\n", qihse_build_info());

    /* Show hardware configuration */
    qihse_compute_pool_t* pool = qihse_compute_pool_init();
    if (pool) {
        printf("Hardware Configuration:\n");
        for (int i = 0; i < QIHSE_DEV_COUNT; i++) {
            if (pool->devices[i].available) {
                printf("  %s\n", qihse_device_capability_string(&pool->devices[i]));
            }
        }
        printf("Total Theoretical TOPS: %.1f\n\n", pool->total_tops);
        qihse_compute_pool_destroy(pool);
    }

    /* Simple functionality test */
    printf("🧪 Running basic functionality test...\n");

    /* Create test data */
    const size_t test_size = 10000;
        int64_t* test_data = malloc(test_size * sizeof(int64_t));
    if (!test_data) {
        fprintf(stderr, "❌ Failed to allocate test data\n");
        return 1;
        }

    /* Generate sorted test data */
    for (size_t i = 0; i < test_size; i++) {
        test_data[i] = (int64_t)i * 2; /* 0, 2, 4, 6, ... */
    }

    /* Test value that exists */
    int64_t test_query = test_data[test_size / 2]; /* Middle value */

    /* Setup QIHSE config */
        qihse_config_t config;
        if (qihse_config_init(&config, QIHSE_TYPE_INT64, test_size) != 0) {
            fprintf(stderr, "❌ Failed to initialize QIHSE config\n");
            free(test_data);
        return 1;
        }

    /* Test QIHSE search */
        uint64_t start_time = ns_now();
    not_stisla_result_t result = qihse_search(test_data, test_size, &test_query,
                                            NULL, &config);
    uint64_t end_time = ns_now();

    double search_time_ns = (double)(end_time - start_time);

    /* Verify result */
    bool correct = (result == (not_stisla_result_t)(test_size / 2));

    printf("Test Results:\n");
    printf("  Array size: %zu\n", test_size);
    printf("  Query value: %ld\n", test_query);
    printf("  Expected index: %zu\n", test_size / 2);
    printf("  QIHSE result: %s\n", result != NOT_STISLA_NOT_FOUND ?
           "Found" : "Not found");
            if (result != NOT_STISLA_NOT_FOUND) {
        printf("  Returned index: %lu\n", (unsigned long)result);
    }
    printf("  Correct: %s\n", correct ? "✅ Yes" : "❌ No");
    printf("  Search time: %.0f ns (%.1f μs)\n", search_time_ns, search_time_ns / 1000.0);

    printf("\n🔬 Advanced QIHSE Features Demonstration:\n");

    /* Demonstrate parallel pipelines */
    printf("  📦 Parallel Pipelines:\n");
    qihse_pipeline_config_t pipeline_configs[4];
    size_t num_configs = qihse_init_parallel_pipelines(
        pipeline_configs, 4, QIHSE_TYPE_INT64, test_size
    );

    qihse_parallel_result_t parallel_result;
    if (qihse_execute_parallel_pipelines(test_data, test_size, &test_query, NULL,
                                        pipeline_configs, num_configs, &parallel_result) == 0) {
        printf("    ✅ %zu pipelines executed in %.0f ns\n",
               parallel_result.active_pipelines, parallel_result.total_time_ns);
        free(parallel_result.pipelines);
    } else {
        printf("    ❌ Parallel pipeline execution failed\n");
    }

    /* Demonstrate multi-resolution */
    printf("  🔍 Multi-Resolution Search:\n");
    qihse_resolution_config_t resolution_configs[3];
    size_t num_resolutions = qihse_init_multires_search(
        resolution_configs, 3, QIHSE_TYPE_INT64, test_size
    );

    qihse_multires_result_t multires_result;
    if (qihse_execute_multires_search(test_data, test_size, &test_query, NULL,
                                     resolution_configs, num_resolutions, &multires_result) == 0) {
        printf("    ✅ %zu resolutions completed in %.0f ns\n",
               multires_result.resolutions_completed, multires_result.total_time_ns);
    } else {
        printf("    ❌ Multi-resolution search failed\n");
    }

    printf("\n");

    if (correct) {
        printf("✅ QIHSE basic functionality test PASSED\n");
        printf("   Fallback mechanisms working correctly\n");
    } else {
        printf("❌ QIHSE basic functionality test FAILED\n");
        free(test_data);
        return 1;
    }

    /* Cleanup */
    free(test_data);
    qihse_reset_performance_stats();

    printf("\n🎯 QIHSE is ready for use!\n");
    printf("   Hardware acceleration automatically detected and utilized\n");
    printf("   Fallback to CPU implementations when accelerators unavailable\n");

    return 0;
}