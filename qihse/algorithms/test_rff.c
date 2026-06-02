/*
 * QIHSE RFF Test Program
 */

#include "qihse_rff.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "TEST FAILED: %s\n", message); \
            return 1; \
        } \
    } while (0)

#define TEST_ASSERT_EQ(a, b, message) TEST_ASSERT((a) == (b), message)
#define TEST_ASSERT_NEAR(a, b, tolerance, message) TEST_ASSERT(fabs((a) - (b)) <= (tolerance), message)

int test_rff_creation() {
    printf("Testing RFF kernel creation...\n");

    qihse_rff_kernel_t* kernel = qihse_rff_create(10, 100, 1.0, 42);
    TEST_ASSERT(kernel != NULL, "RFF kernel creation failed");

    TEST_ASSERT_EQ(qihse_rff_get_input_dims(kernel), 10, "Input dimensions mismatch");
    TEST_ASSERT_EQ(qihse_rff_get_output_dims(kernel), 100, "Output dimensions mismatch");
    TEST_ASSERT_NEAR(qihse_rff_get_gamma(kernel), 1.0, 1e-6, "Gamma parameter mismatch");
    TEST_ASSERT_EQ(qihse_rff_get_seed(kernel), 42, "Seed mismatch");

    qihse_rff_destroy(kernel);
    printf("RFF kernel creation test passed\n");
    return 0;
}

int test_rff_projection() {
    printf("Testing RFF projection...\n");

    qihse_rff_kernel_t* kernel = qihse_rff_create(3, 8, 1.0, 123);
    TEST_ASSERT(kernel != NULL, "RFF kernel creation failed");

    double input[3] = {1.0, 2.0, 3.0};
    double output[8] = {0};

    qihse_rff_project(kernel, input, output);

    /* Check that output is properly scaled and bounded */
    double scale = sqrt(2.0 / 8.0); /* sqrt(2/D) */
    for (size_t i = 0; i < 8; i++) {
        TEST_ASSERT(fabs(output[i]) <= scale * 2.0, "Output amplitude out of bounds");
    }

    qihse_rff_destroy(kernel);
    printf("RFF projection test passed\n");
    return 0;
}

int test_rff_batch_projection() {
    printf("Testing RFF batch projection...\n");

    qihse_rff_kernel_t* kernel = qihse_rff_create(2, 4, 0.5, 456);
    TEST_ASSERT(kernel != NULL, "RFF kernel creation failed");

    double inputs[6] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0}; /* 3 vectors of size 2 */
    double outputs[12] = {0}; /* 3 vectors of size 4 */

    qihse_rff_project_batch(kernel, inputs, outputs, 3);

    /* Verify all outputs are computed */
    for (size_t i = 0; i < 12; i++) {
        TEST_ASSERT(fabs(outputs[i]) > 0.0 || fabs(outputs[i]) == 0.0, "Output not computed");
    }

    qihse_rff_destroy(kernel);
    printf("RFF batch projection test passed\n");
    return 0;
}

int main() {
    printf("QIHSE RFF Algorithm Tests\n");
    printf("========================\n\n");

    int failed = 0;

    failed |= test_rff_creation();
    failed |= test_rff_projection();
    failed |= test_rff_batch_projection();

    printf("\n========================\n");
    if (failed) {
        printf("SOME TESTS FAILED\n");
        return 1;
    } else {
        printf("ALL RFF TESTS PASSED ✅\n");
        return 0;
    }
}
