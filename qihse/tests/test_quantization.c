/*
 * Test suite for QIHSE quantization functionality
 */

#include "../quantization/include/qihse_quantization.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#define TEST_EPSILON 1e-3f
#define TEST_ARRAY_SIZE 1024

/* Test quantization/dequantization round trip */
static void test_basic_quantization(void) {
    printf("Testing quantization round trip...\n");

    /* Create engine */
    qihse_quantization_scheme_t scheme = {
        .precision = QIHSE_PRECISION_INT8,
        .symmetric = true,
        .per_channel = false,
        .power_of_two = false,
        .clip_threshold = 6.0f,
        .calibration_samples = 1000
    };

    qihse_quantization_engine_t engine = qihse_quantization_engine_create(&scheme);
    assert(engine != NULL);

    /* Create test data */
    float* input = malloc(TEST_ARRAY_SIZE * sizeof(float));
    void* quantized = malloc(TEST_ARRAY_SIZE * sizeof(int8_t));
    float* output = malloc(TEST_ARRAY_SIZE * sizeof(float));

    assert(input != NULL && quantized != NULL && output != NULL);

    /* Fill with test data */
    for (size_t i = 0; i < TEST_ARRAY_SIZE; i++) {
        input[i] = sinf((float)i * 0.01f) * 3.0f; /* Range approximately -3 to 3 */
    }

    /* Quantize */
    qihse_quantization_params_t params;
    bool success = qihse_quantize_tensor(engine, input, quantized, TEST_ARRAY_SIZE, &scheme, &params);
    assert(success == true);
    assert(params.precision == QIHSE_PRECISION_INT8);
    assert(params.symmetric == true);

    /* Dequantize */
    success = qihse_dequantize_tensor(engine, quantized, output, TEST_ARRAY_SIZE, &params);
    assert(success == true);

    /* Check accuracy */
    float max_error = 0.0f;
    float total_error = 0.0f;
    for (size_t i = 0; i < TEST_ARRAY_SIZE; i++) {
        float error = fabsf(input[i] - output[i]);
        max_error = fmaxf(max_error, error);
        total_error += error;
    }

    float avg_error = total_error / TEST_ARRAY_SIZE;
    printf("  INT8 quantization - Max error: %.6f, Avg error: %.6f\n", max_error, avg_error);

    /* Should be reasonably accurate for INT8 */
    assert(max_error < 0.1f);
    assert(avg_error < 0.01f);

    /* Cleanup */
    free(input);
    free(quantized);
    free(output);
    qihse_quantization_engine_destroy(engine);

    printf("  Basic quantization test passed!\n");
}

/* Test different precisions */
static void test_precision_variations(void) {
    printf("Testing precision variations...\n");

    qihse_precision_t precisions[] = {
        QIHSE_PRECISION_FP16,
        QIHSE_PRECISION_BF16,
        QIHSE_PRECISION_INT8,
        QIHSE_PRECISION_INT4,
        QIHSE_PRECISION_INT2
    };

    qihse_quantization_scheme_t scheme = {
        .precision = QIHSE_PRECISION_INT8, /* Will be overridden */
        .symmetric = true,
        .per_channel = false,
        .power_of_two = false,
        .clip_threshold = 6.0f,
        .calibration_samples = 1000
    };

    qihse_quantization_engine_t engine = qihse_quantization_engine_create(&scheme);
    assert(engine != NULL);

    /* Create test data */
    float* input = malloc(TEST_ARRAY_SIZE * sizeof(float));
    void* quantized = malloc(TEST_ARRAY_SIZE * 4); /* Max size for any precision */
    float* output = malloc(TEST_ARRAY_SIZE * sizeof(float));

    assert(input != NULL && quantized != NULL && output != NULL);

    /* Fill with test data */
    for (size_t i = 0; i < TEST_ARRAY_SIZE; i++) {
        input[i] = cosf((float)i * 0.005f) * 2.5f;
    }

    for (size_t p = 0; p < sizeof(precisions) / sizeof(precisions[0]); p++) {
        qihse_precision_t precision = precisions[p];
        printf("  Testing %s...\n", qihse_precision_to_string(precision));

        scheme.precision = precision;

        /* Quantize */
        qihse_quantization_params_t params;
        bool success = qihse_quantize_tensor(engine, input, quantized, TEST_ARRAY_SIZE, &scheme, &params);
        assert(success == true);
        assert(params.precision == precision);

        /* Dequantize */
        success = qihse_dequantize_tensor(engine, quantized, output, TEST_ARRAY_SIZE, &params);
        assert(success == true);

        /* Check that we get reasonable results */
        float total_error = 0.0f;
        size_t valid_samples = 0;
        for (size_t i = 0; i < TEST_ARRAY_SIZE; i++) {
            if (isfinite(input[i]) && isfinite(output[i])) {
                total_error += fabsf(input[i] - output[i]);
                valid_samples++;
            }
        }

        if (valid_samples > 0) {
            float avg_error = total_error / valid_samples;
            printf("    %s - Avg error: %.6f\n", qihse_precision_to_string(precision), avg_error);
        }
    }

    /* Cleanup */
    free(input);
    free(quantized);
    free(output);
    qihse_quantization_engine_destroy(engine);

    printf("  Precision variations test passed!\n");
}

/* Test calibration */
static void test_calibration(void) {
    printf("Testing calibration...\n");

    qihse_quantization_scheme_t scheme = {
        .precision = QIHSE_PRECISION_INT8,
        .symmetric = false, /* Test asymmetric */
        .per_channel = false,
        .power_of_two = false,
        .clip_threshold = 0.0f, /* No clipping */
        .calibration_samples = 1000
    };

    qihse_quantization_engine_t engine = qihse_quantization_engine_create(&scheme);
    assert(engine != NULL);

    /* Create calibration data */
    size_t tensor_size = 512;
    float* tensor1 = malloc(tensor_size * sizeof(float));
    float* tensor2 = malloc(tensor_size * sizeof(float));

    assert(tensor1 != NULL && tensor2 != NULL);

    /* Fill with different ranges */
    for (size_t i = 0; i < tensor_size; i++) {
        tensor1[i] = sinf((float)i * 0.02f) * 2.0f;  /* -2 to 2 */
        tensor2[i] = cosf((float)i * 0.015f) * 3.0f; /* -3 to 3 */
    }

    const float* data[] = {tensor1, tensor2};
    size_t sizes[] = {tensor_size, tensor_size};

    /* Calibrate */
    qihse_calibration_stats_t stats;
    qihse_quantization_params_t params;

    bool success = qihse_calibrate_quantization(engine, data, 2, sizes, &scheme, &stats, &params);
    assert(success == true);

    /* Check statistics */
    assert(stats.min_val <= -2.9f); /* Should capture the range */
    assert(stats.max_val >= 2.9f);
    assert(stats.sample_count == tensor_size * 2);
    assert(fabsf(stats.mean_val) < 0.1f); /* Should be close to zero */

    /* Check parameters */
    assert(params.precision == QIHSE_PRECISION_INT8);
    assert(params.symmetric == false);
    assert(params.scale > 0.0f);
    assert(params.original_range >= 5.8f); /* At least -3 to 3 */

    printf("  Calibration - Min: %.3f, Max: %.3f, Mean: %.3f, Scale: %.6f\n",
           stats.min_val, stats.max_val, stats.mean_val, params.scale);

    /* Cleanup */
    free(tensor1);
    free(tensor2);
    qihse_quantization_engine_destroy(engine);

    printf("  Calibration test passed!\n");
}

/* Test precision ladder */
static void test_precision_ladder(void) {
    printf("Testing precision ladder...\n");

    qihse_precision_ladder_t ladder;

    /* Initialize with high accuracy requirement */
    qihse_precision_ladder_init(&ladder, 0.95f, 0.3f); /* 95% accuracy, balanced performance */

    printf("  Precision ladder (%zu options):\n", ladder.num_precisions);
    for (size_t i = 0; i < ladder.num_precisions; i++) {
        printf("    %s: accuracy=%.2f, perf=%.1fx\n",
               qihse_precision_to_string(ladder.precisions[i]),
               ladder.accuracy_targets[i],
               ladder.performance_multipliers[i]);
    }

    /* Test selection */
    qihse_precision_t selected = qihse_precision_ladder_select(
        &ladder, 0.90f, 5.0f, 0xFFFFFFFF);
    assert(selected != QIHSE_PRECISION_MAX);

    printf("  Selected precision for 90%% accuracy, 5x perf: %s\n",
           qihse_precision_to_string(selected));

    printf("  Precision ladder test passed!\n");
}

/* Test adaptive quantization */
static void test_adaptive_quantization(void) {
    printf("Testing adaptive quantization...\n");

    qihse_adaptive_quantization_t adaptive;
    qihse_adaptive_quantization_init(&adaptive, 0.92f, 0.1f);

    /* Generate test accuracy feedback */
    float accuracies[] = {0.95f, 0.93f, 0.90f, 0.88f, 0.91f};
    float perf_metrics[] = {1.0f, 1.5f, 2.0f, 3.0f, 2.5f};

    for (size_t i = 0; i < 5; i++) {
        qihse_precision_t selected = qihse_adaptive_quantization_step(
            &adaptive, accuracies[i], perf_metrics);
        printf("  Step %zu: accuracy=%.2f -> selected %s\n",
               i, accuracies[i], qihse_precision_to_string(selected));
    }

    printf("  Adaptive quantization test passed!\n");
}

/* Test QAT */
static void test_qat(void) {
    printf("Testing quantization-aware training...\n");

    qihse_qat_context_t qat;
    qihse_quantization_scheme_t scheme = {
        .precision = QIHSE_PRECISION_INT8,
        .symmetric = true,
        .per_channel = false,
        .power_of_two = false,
        .clip_threshold = 6.0f,
        .calibration_samples = 1000
    };

    qihse_qat_init(&qat, &scheme, 100, 1000);

    /* Test forward pass */
    float input[8] = {-2.0f, -1.0f, 0.0f, 1.0f, 2.0f, -0.5f, 0.5f, 1.5f};
    float output[8];

    bool success = qihse_qat_forward(&qat, input, output, 8, 150); /* After warmup */
    assert(success == true);

    printf("  QAT forward - quantization loss: %.6f\n", qat.quantization_loss);

    /* Test backward pass */
    float gradients[8] = {0.1f, -0.2f, 0.3f, -0.1f, 0.2f, -0.3f, 0.1f, -0.2f};
    float quantized_grads[8];

    success = qihse_qat_backward(&qat, gradients, quantized_grads, 8, 150);
    assert(success == true);

    printf("  QAT backward completed\n");

    printf("  QAT test passed!\n");
}

/* Main test runner */
int main(void) {
    printf("Running QIHSE quantization tests...\n\n");

    test_basic_quantization();
    printf("\n");

    test_precision_variations();
    printf("\n");

    test_calibration();
    printf("\n");

    test_precision_ladder();
    printf("\n");

    test_adaptive_quantization();
    printf("\n");

    test_qat();
    printf("\n");

    printf("All quantization tests passed! ✓\n");
    return 0;
}
