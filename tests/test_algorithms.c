/*
 * QIHSE Algorithm Tests
 *
 * Tests for quantum-inspired core algorithms (Phase 0.5)
 */

#include "../core/qihse_abi.h"
#include "../algorithms/qihse_rff.h"
#include "../algorithms/qihse_superposition.h"
#include "../algorithms/qihse_amplification.h"
#include "../algorithms/qihse_dimensions.h"
#include "../algorithms/qihse_verification.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/* Test macros */
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "TEST FAILED: %s:%d - %s\n", __FILE__, __LINE__, msg); \
            return 0; \
        } \
    } while (0)

#define TEST_ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)
#define TEST_ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)
#define TEST_ASSERT_NEAR(a, b, tol, msg) TEST_ASSERT(fabs((a) - (b)) <= (tol), msg)

/* Test RFF functionality */
static int test_rff_functionality(void) {
    printf("Testing RFF functionality...\n");

    /* Create RFF kernel */
    qihse_rff_kernel_t* kernel = qihse_rff_create(4, 16, 0.5, 42);
    TEST_ASSERT(kernel != NULL, "RFF kernel creation failed");

    /* Test properties */
    TEST_ASSERT_EQ(qihse_rff_get_input_dims(kernel), 4, "Input dims mismatch");
    TEST_ASSERT_EQ(qihse_rff_get_output_dims(kernel), 16, "Output dims mismatch");
    TEST_ASSERT_NEAR(qihse_rff_get_gamma(kernel), 0.5, 1e-6, "Gamma mismatch");
    TEST_ASSERT_EQ(qihse_rff_get_seed(kernel), 42, "Seed mismatch");

    /* Test projection */
    double input[4] = {1.0, 2.0, 3.0, 4.0};
    double output[16];

    qihse_rff_project(kernel, input, output);

    /* Check that output is finite */
    for (int i = 0; i < 16; i++) {
        TEST_ASSERT(isfinite(output[i]), "RFF output is not finite");
    }

    qihse_rff_destroy(kernel);
    printf("RFF functionality test passed\n");
    return 1;
}

/* Test superposition functionality */
static int test_superposition_functionality(void) {
    printf("Testing superposition functionality...\n");

    /* Create some test RFF data */
    size_t n = 10, dims = 8;
    double* rff_data = malloc(n * dims * sizeof(double));
    TEST_ASSERT(rff_data != NULL, "RFF data allocation failed");

    /* Fill with test data */
    for (size_t i = 0; i < n * dims; i++) {
        rff_data[i] = sin((double)i * 0.1);
    }

    /* Create superposition */
    qihse_superposition_t superposition;
    int ret = qihse_create_superposition(rff_data, n, dims, &superposition);
    TEST_ASSERT_EQ(ret, 0, "Superposition creation failed");

    /* Test properties */
    TEST_ASSERT_EQ(qihse_superposition_get_num_states(&superposition), n, "Num states mismatch");
    TEST_ASSERT_EQ(qihse_superposition_get_dims_per_state(&superposition), dims, "Dims per state mismatch");

    /* Test normalization */
    ret = qihse_superposition_normalize(&superposition);
    TEST_ASSERT_EQ(ret, 0, "Normalization failed");
    TEST_ASSERT(qihse_superposition_is_normalized(&superposition), "Superposition not normalized");

    /* Test measurement */
    size_t measurement = qihse_superposition_measure(&superposition, 12345);
    TEST_ASSERT(measurement < n, "Invalid measurement result");

    qihse_destroy_superposition(&superposition);
    free(rff_data);
    printf("Superposition functionality test passed\n");
    return 1;
}

/* Test amplification functionality */
static int test_amplification_functionality(void) {
    printf("Testing amplification functionality...\n");

    /* Create test superposition */
    qihse_superposition_t superposition;
    double real_data[4] = {1.0, 0.5, 0.3, 0.2};
    double imag_data[4] = {0.0, 0.5, 0.7, 0.8};

    int ret = qihse_create_superposition_from_amplitudes(real_data, imag_data, 4, &superposition);
    TEST_ASSERT_EQ(ret, 0, "Superposition creation failed");

    /* Configure amplification */
    qihse_amplification_config_t config;
    qihse_amplification_config_init(&config, 4);

    /* Test amplification */
    size_t target_indices[2] = {0, 1}; /* Target first two states */
    int rounds = qihse_amplify(&superposition, target_indices, 2, &config);
    TEST_ASSERT(rounds > 0, "Amplification failed");

    qihse_destroy_superposition(&superposition);
    printf("Amplification functionality test passed\n");
    return 1;
}

/* Test dimensions functionality */
static int test_dimensions_functionality(void) {
    printf("Testing dimensions functionality...\n");

    /* Create test characteristics */
    qihse_problem_characteristics_t chars = {
        .input_size = 1000,
        .output_size = 100,
        .data_entropy = 0.8,
        .data_complexity = 0.5,
        .sparsity = 0.1,
        .correlation = 0.2,
        .memory_budget = 1024 * 1024 * 1024, /* 1GB */
        .performance_target = 1000.0 /* 1000 queries/sec */
    };

    /* Test dimension calculation */
    qihse_dimension_config_t config;
    qihse_dimension_config_init(&config);

    size_t dims = qihse_calculate_optimal_dimensions(&chars, &config);
    TEST_ASSERT(dims >= config.min_dims && dims <= config.max_dims, "Dimensions out of range");

    /* Test validation */
    int valid = qihse_validate_dimensions(dims, &chars, &config);
    TEST_ASSERT(valid, "Dimensions should be valid");

    printf("Dimensions functionality test passed\n");
    return 1;
}

/* Test verification functionality */
static int test_verification_functionality(void) {
    printf("Testing verification functionality...\n");

    /* Configure verification */
    qihse_verification_config_t config;
    qihse_verification_config_init(&config, QIHSE_VERIFY_FAST);

    /* Test config validation */
    int valid = qihse_verification_config_validate(&config);
    TEST_ASSERT(valid, "Verification config should be valid");

    /* Test verification result */
    qihse_verification_result_t result;
    qihse_verification_result_init(&result);

    int ret = qihse_verify_result(NULL, NULL, NULL, &config, &result);
    TEST_ASSERT_EQ(ret, -1, "Verification with NULL result should fail");

    qihse_verification_result_destroy(&result);
    printf("Verification functionality test passed\n");
    return 1;
}

/* Main test runner */
int main(void) {
    printf("QIHSE Algorithm Tests\n");
    printf("=====================\n\n");

    int tests_passed = 0;
    int total_tests = 0;

    /* Run tests */
    total_tests++;
    if (test_rff_functionality()) tests_passed++;

    total_tests++;
    if (test_superposition_functionality()) tests_passed++;

    total_tests++;
    if (test_amplification_functionality()) tests_passed++;

    total_tests++;
    if (test_dimensions_functionality()) tests_passed++;

    total_tests++;
    if (test_verification_functionality()) tests_passed++;

    printf("\n=====================\n");
    printf("Tests passed: %d/%d\n", tests_passed, total_tests);

    if (tests_passed == total_tests) {
        printf("ALL ALGORITHM TESTS PASSED ✅\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED ❌\n");
        return 1;
    }
}
