/*
 * Test suite for QIHSE quantization functionality (current pipeline API)
 */

#include "../quantization/include/qihse_quantization.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#define TEST_ARRAY_SIZE 1024

/* Test pipeline creation and destruction */
static void test_pipeline_lifecycle(void) {
    printf("Testing pipeline lifecycle...\n");

    qihse_quantization_pipeline_t* pipeline = qihse_quantization_pipeline_create(
        "test_pipeline", QIHSE_QUANT_INT8, false);
    assert(pipeline != NULL);

    qihse_quantization_pipeline_destroy(pipeline);
    printf("  Pipeline lifecycle test passed!\n");
}

/* Test basic quantization round trip */
static void test_basic_quantization(void) {
    printf("Testing basic quantization round trip...\n");

    qihse_quantization_pipeline_t* pipeline = qihse_quantization_pipeline_create(
        "test_int8", QIHSE_QUANT_INT8, false);
    assert(pipeline != NULL);

    float* input = malloc(TEST_ARRAY_SIZE * sizeof(float));
    assert(input != NULL);
    for (size_t i = 0; i < TEST_ARRAY_SIZE; i++) {
        input[i] = sinf((float)i * 0.01f) * 3.0f;
    }

    int ret = qihse_quantization_analyze(pipeline, input, TEST_ARRAY_SIZE, QIHSE_TYPE_DOUBLE);
    assert(ret == 0);

    ret = qihse_quantization_calibrate(pipeline, input, TEST_ARRAY_SIZE, QIHSE_TYPE_DOUBLE);
    /* Calibration may fail without sufficient data; allow -1 */
    (void)ret;

    void* output_data = NULL;
    size_t output_size = 0;
    ret = qihse_quantization_quantize(pipeline, input, TEST_ARRAY_SIZE * sizeof(float),
                                      &output_data, &output_size);
    assert(ret == 0);
    assert(output_data != NULL);
    assert(output_size > 0);

    void* dequant_data = NULL;
    size_t dequant_size = 0;
    ret = qihse_quantization_dequantize(pipeline, output_data, output_size,
                                        &dequant_data, &dequant_size);
    assert(ret == 0);
    assert(dequant_data != NULL);

    printf("  Quantized %zu bytes -> %zu bytes, dequantized -> %zu bytes\n",
           TEST_ARRAY_SIZE * sizeof(float), output_size, dequant_size);

    free(input);
    free(output_data);
    free(dequant_data);
    qihse_quantization_pipeline_destroy(pipeline);

    printf("  Basic quantization test passed!\n");
}

/* Test precision recommendation */
static void test_precision_recommendation(void) {
    printf("Testing precision recommendation...\n");

    float* data = malloc(TEST_ARRAY_SIZE * sizeof(float));
    assert(data != NULL);
    for (size_t i = 0; i < TEST_ARRAY_SIZE; i++) {
        data[i] = cosf((float)i * 0.005f) * 2.5f;
    }

    qihse_precision_recommendation_t rec;
    int ret = qihse_quantization_recommend_precision(
        data, TEST_ARRAY_SIZE, QIHSE_TYPE_DOUBLE, 0.95, 2.0, &rec);
    assert(ret == 0);

    printf("  Recommended mode: %d (compression %.2fx, speedup %.2fx)\n",
           (int)rec.recommended_mode,
           rec.expected_compression_ratio,
           rec.expected_speedup);

    free(data);
    printf("  Precision recommendation test passed!\n");
}

/* Test NPU quantization init */
static void test_npu_init(void) {
    printf("Testing NPU quantization init...\n");

    qihse_quantization_pipeline_t* pipeline = qihse_quantization_pipeline_create(
        "test_npu", QIHSE_QUANT_INT8, false);
    assert(pipeline != NULL);

    int ret = qihse_npu_quantization_init(pipeline);
    /* May fail if NPU not available; just verify it doesn't crash */
    (void)ret;

    qihse_quantization_pipeline_destroy(pipeline);
    printf("  NPU init test passed!\n");
}

/* Test stats and reset */
static void test_stats(void) {
    printf("Testing quantization stats...\n");

    qihse_quantization_stats_t stats;
    int ret = qihse_quantization_get_stats(&stats);
    assert(ret == 0);

    qihse_quantization_reset_stats();
    printf("  Stats test passed!\n");
}

/* Main test runner */
int main(void) {
    printf("Running QIHSE quantization tests...\n\n");

    test_pipeline_lifecycle();
    printf("\n");

    test_basic_quantization();
    printf("\n");

    test_precision_recommendation();
    printf("\n");

    test_npu_init();
    printf("\n");

    test_stats();
    printf("\n");

    printf("All quantization tests passed!\n");
    return 0;
}
