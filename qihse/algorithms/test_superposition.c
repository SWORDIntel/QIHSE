/*
 * QIHSE Superposition Test Program
 */

#include "qihse_superposition.h"
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

int test_superposition_creation() {
    printf("Testing superposition creation...\n");

    /* Create some test RFF data */
    double rff_data[12] = {
        0.1, 0.2, 0.3, 0.4,
        0.5, 0.6, 0.7, 0.8,
        0.9, 1.0, 1.1, 1.2
    }; /* 3 states, 4 RFF dims each */

    qihse_superposition_t superposition;
    int ret = qihse_create_superposition(rff_data, 3, 4, &superposition);
    TEST_ASSERT(ret == 0, "Superposition creation failed");

    TEST_ASSERT_EQ(superposition.num_states, 3, "Number of states mismatch");
    TEST_ASSERT_EQ(superposition.dims_per_state, 4, "Dimensions per state mismatch");
    TEST_ASSERT(superposition.real != NULL, "Real amplitudes not allocated");
    TEST_ASSERT(superposition.imag != NULL, "Imaginary amplitudes not allocated");
    TEST_ASSERT(superposition.phase != NULL, "Phase array not allocated");

    qihse_destroy_superposition(&superposition);
    printf("Superposition creation test passed\n");
    return 0;
}

int test_superposition_normalization() {
    printf("Testing superposition normalization...\n");

    /* Create superposition from amplitudes */
    double real[2] = {1.0, 2.0};
    double imag[2] = {1.0, 2.0};

    qihse_superposition_t superposition;
    int ret = qihse_create_superposition_from_amplitudes(real, imag, 2, &superposition);
    TEST_ASSERT(ret == 0, "Superposition creation failed");

    /* Check it's not normalized initially */
    TEST_ASSERT(!qihse_superposition_is_normalized(&superposition), "Should not be normalized initially");

    /* Normalize */
    ret = qihse_superposition_normalize(&superposition);
    TEST_ASSERT(ret == 0, "Normalization failed");

    /* Check it's normalized now */
    TEST_ASSERT(qihse_superposition_is_normalized(&superposition), "Should be normalized after normalization");

    qihse_destroy_superposition(&superposition);
    printf("Superposition normalization test passed\n");
    return 0;
}

int test_superposition_measurement() {
    printf("Testing superposition measurement...\n");

    /* Create normalized superposition */
    double real[4] = {0.5, 0.5, 0.5, 0.5};
    double imag[4] = {0.5, 0.5, 0.5, 0.5};

    qihse_superposition_t superposition;
    int ret = qihse_create_superposition_from_amplitudes(real, imag, 4, &superposition);
    TEST_ASSERT(ret == 0, "Superposition creation failed");

    /* Measure */
    size_t result = qihse_superposition_measure(&superposition, 12345);
    TEST_ASSERT(result < 4, "Measurement result out of bounds");

    qihse_destroy_superposition(&superposition);
    printf("Superposition measurement test passed\n");
    return 0;
}

int test_superposition_properties() {
    printf("Testing superposition properties...\n");

    qihse_superposition_t superposition;
    double real[2] = {1.0, 0.0};
    double imag[2] = {0.0, 1.0};

    int ret = qihse_create_superposition_from_amplitudes(real, imag, 2, &superposition);
    TEST_ASSERT(ret == 0, "Superposition creation failed");

    TEST_ASSERT_EQ(qihse_superposition_get_num_states(&superposition), 2, "Num states getter failed");
    TEST_ASSERT_EQ(qihse_superposition_get_dims_per_state(&superposition), 1, "Dims per state getter failed");

    qihse_destroy_superposition(&superposition);
    printf("Superposition properties test passed\n");
    return 0;
}

int main() {
    printf("QIHSE Superposition Algorithm Tests\n");
    printf("==================================\n\n");

    int failed = 0;

    failed |= test_superposition_creation();
    failed |= test_superposition_normalization();
    failed |= test_superposition_measurement();
    failed |= test_superposition_properties();

    printf("\n==================================\n");
    if (failed) {
        printf("SOME TESTS FAILED\n");
        return 1;
    } else {
        printf("ALL SUPERPOSITION TESTS PASSED ✅\n");
        return 0;
    }
}
