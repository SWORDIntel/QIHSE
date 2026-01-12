/* ============================================================================
 * QIHSE BENCHMARK SUITE TEST SUITE
 * ============================================================================
 *
 * Comprehensive tests for the enterprise benchmark framework.
 * Validates benchmark execution, performance measurement, and regression detection.
 * ============================================================================ */

#include "../include/qihse_benchmark.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

/* Test benchmark framework initialization */
static void test_benchmark_init(void) {
    printf("Testing benchmark framework initialization...\n");

    /* Initialize benchmark framework */
    int ret = qihse_benchmark_init();
    assert(ret == 0);

    /* Cleanup */
    qihse_benchmark_cleanup();

    printf("  Benchmark framework initialization test passed!\n");
}

/* Test dataset loading */
static void test_dataset_loading(void) {
    printf("Testing dataset loading...\n");

    /* Initialize framework */
    int ret = qihse_benchmark_init();
    assert(ret == 0);

    /* Test SIFT1M dataset loading */
    qihse_dataset_t dataset;
    ret = qihse_benchmark_load_dataset(QIHSE_DATASET_SIFT1M, &dataset);
    assert(ret == 0);
    assert(dataset.type == QIHSE_DATASET_SIFT1M);
    assert(dataset.workload_type == QIHSE_WORKLOAD_VECTOR);
    assert(dataset.data.vector.num_vectors == 1000000);
    assert(dataset.data.vector.dimensions == 128);
    assert(dataset.data.vector.vectors != NULL);
    assert(dataset.data.vector.ids != NULL);

    /* Cleanup dataset */
    free(dataset.data.vector.vectors);
    free(dataset.data.vector.ids);

    /* Test GIST1M dataset loading */
    ret = qihse_benchmark_load_dataset(QIHSE_DATASET_GIST1M, &dataset);
    assert(ret == 0);
    assert(dataset.type == QIHSE_DATASET_GIST1M);
    assert(dataset.data.vector.num_vectors == 1000000);
    assert(dataset.data.vector.dimensions == 960);

    /* Cleanup dataset */
    free(dataset.data.vector.vectors);
    free(dataset.data.vector.ids);

    /* Cleanup framework */
    qihse_benchmark_cleanup();

    printf("  Dataset loading test passed!\n");
}

/* Test SIFT1M benchmark execution */
static void test_sift1m_benchmark(void) {
    printf("Testing SIFT1M benchmark execution...\n");

    /* Initialize framework */
    int ret = qihse_benchmark_init();
    assert(ret == 0);

    /* Run SIFT1M benchmark */
    qihse_benchmark_results_t results;
    ret = qihse_benchmark_sift1m(&results);
    assert(ret == 0);

    /* Validate results */
    assert(strcmp(results.benchmark_name, "SIFT1M") == 0);
    assert(results.workload_type == QIHSE_WORKLOAD_VECTOR);
    assert(results.num_queries_executed > 0);
    assert(results.metrics.qps > 0.0);
    assert(results.metrics.latency_p50 > 0.0);
    assert(results.metrics.correctness_score >= 0.0);

    /* Test results saving */
    ret = qihse_benchmark_save_results(&results, "/tmp/sift1m_results.json");
    assert(ret == 0);

    /* Cleanup */
    qihse_benchmark_cleanup();

    printf("  SIFT1M benchmark test passed!\n");
}

/* Test GIST1M benchmark execution */
static void test_gist1m_benchmark(void) {
    printf("Testing GIST1M benchmark execution...\n");

    /* Initialize framework */
    int ret = qihse_benchmark_init();
    assert(ret == 0);

    /* Run GIST1M benchmark */
    qihse_benchmark_results_t results;
    ret = qihse_benchmark_gist1m(&results);
    assert(ret == 0);

    /* Validate results */
    assert(strcmp(results.benchmark_name, "GIST1M") == 0);
    assert(results.workload_type == QIHSE_WORKLOAD_VECTOR);
    assert(results.num_queries_executed > 0);

    /* Cleanup */
    qihse_benchmark_cleanup();

    printf("  GIST1M benchmark test passed!\n");
}

/* Test regression detection */
static void test_regression_detection(void) {
    printf("Testing regression detection...\n");

    qihse_regression_detector_t detector;

    /* Initialize detector */
    int ret = qihse_regression_detector_init(&detector, 3.0, 5);
    assert(ret == 0);

    /* Add baseline measurements */
    qihse_regression_status_t status;

    /* Establish baseline with consistent performance */
    status = qihse_regression_detector_update(&detector, 1000.0);
    assert(status == QIHSE_REGRESSION_NONE);

    status = qihse_regression_detector_update(&detector, 1010.0);
    assert(status == QIHSE_REGRESSION_NONE);

    status = qihse_regression_detector_update(&detector, 990.0);
    assert(status == QIHSE_REGRESSION_NONE);

    status = qihse_regression_detector_update(&detector, 1005.0);
    assert(status == QIHSE_REGRESSION_NONE);

    status = qihse_regression_detector_update(&detector, 995.0);
    assert(status == QIHSE_REGRESSION_NONE);
    assert(detector.baseline_established == true);

    /* Test normal variation (should not trigger regression) */
    status = qihse_regression_detector_check(&detector, 1000.0);
    assert(status == QIHSE_REGRESSION_NONE);

    /* Test improvement (should be detected) */
    status = qihse_regression_detector_check(&detector, 1200.0);
    assert(status == QIHSE_REGRESSION_IMPROVEMENT);

    /* Test warning-level degradation */
    status = qihse_regression_detector_check(&detector, 900.0);
    assert(status == QIHSE_REGRESSION_WARNING);

    /* Test critical regression */
    status = qihse_regression_detector_check(&detector, 700.0);
    assert(status == QIHSE_REGRESSION_CRITICAL);

    /* Cleanup */
    qihse_regression_detector_destroy(&detector);

    printf("  Regression detection test passed!\n");
}

/* Test benchmark validation */
static void test_benchmark_validation(void) {
    printf("Testing benchmark validation...\n");

    /* Initialize framework */
    int ret = qihse_benchmark_init();
    assert(ret == 0);

    /* Create test results */
    qihse_benchmark_results_t results = {
        .benchmark_name = "TestBenchmark",
        .workload_type = QIHSE_WORKLOAD_VECTOR,
        .dataset_type = QIHSE_DATASET_SIFT1M,
        .num_queries_executed = 100,
        .num_queries_failed = 0
    };

    /* Create test ground truth */
    qihse_ground_truth_t ground_truth = {
        .num_queries = 100,
        .k_values = NULL  /* Would be populated in real implementation */
    };

    /* Create test config */
    qihse_benchmark_config_t config = {
        .type = QIHSE_WORKLOAD_VECTOR,
        .enable_verification = true,
        .confidence_threshold = 0.9
    };

    /* Run validation */
    ret = qihse_benchmark_validate(&results, &ground_truth, &config);
    assert(ret == 0);

    /* Check that validation populated metrics */
    assert(results.metrics.correctness_score >= 0.0);
    assert(results.metrics.recall_at_1 >= 0.0);
    assert(results.metrics.recall_at_10 >= 0.0);

    /* Cleanup */
    qihse_benchmark_cleanup();

    printf("  Benchmark validation test passed!\n");
}

/* Main test runner */
int main(int argc, char** argv) {
    printf("Running QIHSE Benchmark Suite Tests...\n\n");

    test_benchmark_init();
    printf("\n");

    test_dataset_loading();
    printf("\n");

    test_sift1m_benchmark();
    printf("\n");

    test_gist1m_benchmark();
    printf("\n");

    test_regression_detection();
    printf("\n");

    test_benchmark_validation();
    printf("\n");

    printf("All QIHSE Benchmark Suite tests passed!\n");
    return 0;
}
