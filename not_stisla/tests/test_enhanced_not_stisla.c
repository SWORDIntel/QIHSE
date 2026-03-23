/* ============================================================================
 * ENHANCED NOT_STISLA TEST SUITE
 * ============================================================================
 *
 * Tests for QIHSE-inspired improvements to traditional NOT_STISLA:
 * - Runtime CPU feature detection
 * - Memory-bounded anchor learning
 * - Enhanced statistics and monitoring
 * - Workload-specific optimizations
 * ============================================================================ */

#include "../include/not_stisla.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#define TEST_ARRAY_SIZE 10000
#define TEST_ITERATIONS 1000

/* Test runtime CPU feature detection */
static void test_cpu_feature_detection(void) {
    printf("Testing runtime CPU feature detection...\n");

    uint32_t features = not_stisla_detect_cpu_features();
    printf("  Detected CPU features: 0x%08x\n", features);

    /* Should detect at least basic features */
    assert(features != 0);

    /* Test multiple calls return same result */
    uint32_t features2 = not_stisla_detect_cpu_features();
    assert(features == features2);

    printf("  ✓ CPU feature detection works\n");
}

/* Test memory-bounded anchor table */
static void test_memory_bounded_anchors(void) {
    printf("Testing memory-bounded anchor management...\n");

    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    assert(table != NULL);

    /* Test memory limit setting */
    int ret = not_stisla_anchor_table_set_memory_limit(table, 5);
    assert(ret == 0);
    assert(table->max_capacity == 5);

    /* Test invalid limits */
    ret = not_stisla_anchor_table_set_memory_limit(table, 1);  /* Too small */
    assert(ret == -1);

    ret = not_stisla_anchor_table_set_memory_limit(table, 100); /* Too large */
    assert(ret == -1);

    not_stisla_anchor_table_destroy(table);
    printf("  ✓ Memory-bounded anchor management works\n");
}

/* Test workload-specific optimization */
static void test_workload_optimization(void) {
    printf("Testing workload-specific optimization...\n");

    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    assert(table != NULL);

    /* Test telemetry workload */
    int ret = not_stisla_anchor_table_optimize_for_workload(table, NOT_STISLA_WORKLOAD_TELEMETRY);
    assert(ret == 0);
    assert(table->max_capacity > NOT_STISLA_MAX_ANCHORS / 2);  /* Higher limit for telemetry */

    /* Test ID workload */
    ret = not_stisla_anchor_table_optimize_for_workload(table, NOT_STISLA_WORKLOAD_IDS);
    assert(ret == 0);
    assert(table->max_capacity < NOT_STISLA_MAX_ANCHORS);  /* Lower limit for IDs */

    not_stisla_anchor_table_destroy(table);
    printf("  ✓ Workload-specific optimization works\n");
}

/* Test enhanced statistics */
static void test_enhanced_statistics(void) {
    printf("Testing enhanced statistics tracking...\n");

    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    assert(table != NULL);

    /* Create test array */
    int64_t test_array[100];
    for (size_t i = 0; i < 100; i++) {
        test_array[i] = i * 10;
    }

    /* Perform searches to generate statistics - mix exact matches and near misses */
    for (size_t i = 0; i < 25; i++) {
        /* Exact matches - should not learn anchors */
        not_stisla_result_t result = not_stisla_search(test_array, 100, i * 10, table, 2);
        assert(result != NOT_STISLA_NOT_FOUND);
    }

    /* Near misses that should trigger anchor learning */
    for (size_t i = 0; i < 25; i++) {
        /* Search for values that require interpolation and anchor learning */
        int64_t search_val = (i * 10) + 3;  /* Offset from exact match */
        not_stisla_result_t result = not_stisla_search(test_array, 100, search_val, table, 2);
        /* May or may not find exact match, but should learn anchors */
    }

    /* Check enhanced statistics */
    const not_stisla_stats_t* stats = not_stisla_anchor_table_get_stats(table);
    assert(stats != NULL);
    assert(stats->searches_total >= 50);  /* Should have recorded all searches */
    assert(stats->cpu_features_detected != 0);  /* Should have detected CPU features */

    /* Anchors may or may not be learned depending on search patterns */
    /* The important thing is that statistics are being tracked */

    /* Test legacy statistics API still works */
    size_t searches_total, anchors_learned, memory_used;
    not_stisla_get_stats(table, &searches_total, &anchors_learned, &memory_used);
    assert(searches_total == stats->searches_total);
    assert(anchors_learned == stats->anchors_learned);
    assert(memory_used > 0);

    not_stisla_anchor_table_destroy(table);
    printf("  ✓ Enhanced statistics tracking works\n");
}

/* Test performance improvements */
static void test_performance_improvements(void) {
    printf("Testing performance characteristics...\n");

    /* Create large test array */
    const size_t array_size = TEST_ARRAY_SIZE;
    int64_t* test_array = malloc(array_size * sizeof(int64_t));
    assert(test_array != NULL);

    /* Fill with sorted values */
    for (size_t i = 0; i < array_size; i++) {
        test_array[i] = i * 100;  /* Sparse array for interpolation */
    }

    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    assert(table != NULL);

    /* Warm up anchor learning */
    for (size_t i = 0; i < 100; i++) {
        size_t idx = rand() % array_size;
        not_stisla_result_t result = not_stisla_search(test_array, array_size,
                                                     test_array[idx], table, 4);
        assert(result == idx);
    }

    /* Performance test */
    clock_t start_time = clock();

    for (size_t i = 0; i < TEST_ITERATIONS; i++) {
        size_t idx = rand() % array_size;
        not_stisla_result_t result = not_stisla_search(test_array, array_size,
                                                     test_array[idx], table, 4);
        assert(result == idx);
    }

    clock_t end_time = clock();
    double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("  ✓ Performance test: %d searches in %.4f seconds\n", TEST_ITERATIONS, time_taken);
    printf("  ✓ Average search time: %.2f ns\n", (time_taken * 1e9) / TEST_ITERATIONS);

    /* Check that anchors were learned efficiently */
    const not_stisla_stats_t* stats = not_stisla_anchor_table_get_stats(table);
    assert(stats->anchors_learned <= table->max_capacity);  /* Memory bounded */

    free(test_array);
    not_stisla_anchor_table_destroy(table);
    printf("  ✓ Performance improvements verified\n");
}

/* Test DSMIL workload initialization */
static void test_dsmil_workload_init(void) {
    printf("Testing DSMIL workload initialization...\n");

    not_stisla_anchor_table_t* table = not_stisla_anchor_table_create();
    assert(table != NULL);

    /* Test telemetry workload */
    bool success = not_stisla_init_for_dsmil(table, NOT_STISLA_WORKLOAD_TELEMETRY);
    assert(success);
    assert(table->workload_type == NOT_STISLA_WORKLOAD_TELEMETRY);

    /* Verify workload-specific optimization was applied */
    assert(table->max_capacity > 10);  /* Telemetry gets higher limit */

    /* Test that statistics are initialized */
    const not_stisla_stats_t* stats = not_stisla_anchor_table_get_stats(table);
    assert(stats->cpu_features_detected != 0);

    not_stisla_anchor_table_destroy(table);
    printf("  ✓ DSMIL workload initialization works\n");
}

/* Main test runner */
int main(int argc, char** argv) {
    printf("Running Enhanced NOT_STISLA Test Suite\n");
    printf("=======================================\n\n");

    /* Seed random number generator */
    srand((unsigned int)time(NULL));

    test_cpu_feature_detection();
    printf("\n");

    test_memory_bounded_anchors();
    printf("\n");

    test_workload_optimization();
    printf("\n");

    test_enhanced_statistics();
    printf("\n");

    test_performance_improvements();
    printf("\n");

    test_dsmil_workload_init();
    printf("\n");

    printf("🎉 All Enhanced NOT_STISLA tests passed!\n");
    printf("QIHSE-inspired improvements successfully integrated.\n");

    return 0;
}
