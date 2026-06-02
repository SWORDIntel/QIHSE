/*
 * QIHSE ABI Compliance Tests
 *
 * This file contains tests to ensure ABI compliance and stability.
 * These tests verify that the ABI functions work correctly and maintain
 * backward compatibility.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "../core/qihse_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ============================================================================
 * TEST UTILITIES
 * ============================================================================ */

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "TEST FAILED: %s (%s:%d)\n", message, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#define TEST_ASSERT_EQ(a, b, message) \
    TEST_ASSERT((a) == (b), message)

#define TEST_ASSERT_NE(a, b, message) \
    TEST_ASSERT((a) != (b), message)

/* ============================================================================
 * ABI VERSION TESTS
 * ============================================================================ */

void test_abi_version(void) {
    printf("Testing ABI version...\n");

    /* Test version constants */
    TEST_ASSERT_EQ(QIHSE_ABI_VERSION, 100, "ABI version should be 100");
    TEST_ASSERT_EQ(QIHSE_ABI_VERSION_MAJOR, 1, "Major version should be 1");
    TEST_ASSERT_EQ(QIHSE_ABI_VERSION_MINOR, 0, "Minor version should be 0");
    TEST_ASSERT_EQ(QIHSE_ABI_VERSION_PATCH, 0, "Patch version should be 0");

    /* Test version functions */
    TEST_ASSERT_EQ(qihse_get_abi_version(NULL), QIHSE_ABI_VERSION,
                   "ABI version function should return correct version");

    /* Test compatibility check */
    TEST_ASSERT_EQ(qihse_check_abi_compatibility(100), 1,
                   "Should accept version 100");
    TEST_ASSERT_EQ(qihse_check_abi_compatibility(99), 1,
                   "Should accept older version 99");
    TEST_ASSERT_EQ(qihse_check_abi_compatibility(101), 0,
                   "Should reject newer version 101");

    printf("ABI version tests passed\n");
}

/* ============================================================================
 * ERROR CODE TESTS
 * ============================================================================ */

void test_error_codes(void) {
    printf("Testing error codes...\n");

    /* Test error string conversion */
    TEST_ASSERT_NE(qihse_error_string(QIHSE_OK), NULL,
                   "Error string for OK should not be NULL");
    TEST_ASSERT_NE(qihse_error_string(QIHSE_ERROR_INVALID_ARGUMENT), NULL,
                   "Error string for invalid argument should not be NULL");
    TEST_ASSERT_NE(qihse_error_string(QIHSE_ERROR_OUT_OF_MEMORY), NULL,
                   "Error string for out of memory should not be NULL");

    /* Test that all error codes have strings */
    for (int i = QIHSE_OK; i >= -50; i--) {
        const char* str = qihse_error_string((qihse_error_t)i);
        TEST_ASSERT_NE(str, NULL, "All error codes should have string representations");
        TEST_ASSERT_NE(strlen(str), 0, "Error strings should not be empty");
    }

    printf("Error code tests passed\n");
}

/* ============================================================================
 * CONTEXT MANAGEMENT TESTS
 * ============================================================================ */

void test_context_management(void) {
    printf("Testing context management...\n");

    qihse_context_t ctx = NULL;

    /* Test context creation */
    qihse_error_t ret = qihse_context_create(NULL, &ctx);
    TEST_ASSERT_EQ(ret, QIHSE_OK, "Context creation should succeed");
    TEST_ASSERT_NE(ctx, NULL, "Context should not be NULL after creation");

    /* Test ABI version through context */
    TEST_ASSERT_EQ(qihse_get_abi_version(ctx), QIHSE_ABI_VERSION,
                   "Context ABI version should match global version");

    /* Test context destruction */
    qihse_context_destroy(ctx);

    printf("Context management tests passed\n");
}

/* ============================================================================
 * BUFFER MANAGEMENT TESTS
 * ============================================================================ */

void test_buffer_management(void) {
    printf("Testing buffer management...\n");

    qihse_context_t ctx = NULL;
    qihse_buffer_t buffer = {0};

    /* Create context */
    qihse_error_t ret = qihse_context_create(NULL, &ctx);
    TEST_ASSERT_EQ(ret, QIHSE_OK, "Context creation should succeed");

    /* Test buffer creation */
    ret = qihse_buffer_create(ctx, 1024, QIHSE_DATA_TYPE_FLOAT32,
                              QIHSE_MEMORY_HOST, &buffer);
    TEST_ASSERT_EQ(ret, QIHSE_OK, "Buffer creation should succeed");
    TEST_ASSERT_NE(buffer.data, NULL, "Buffer data should not be NULL");
    TEST_ASSERT_EQ(buffer.size, 1024, "Buffer size should be 1024");
    TEST_ASSERT_EQ(buffer.type, QIHSE_DATA_TYPE_FLOAT32,
                   "Buffer type should be FLOAT32");
    TEST_ASSERT_EQ(buffer.flags, QIHSE_MEMORY_HOST,
                   "Buffer flags should be HOST");

    /* Test buffer operations */
    if (buffer.data) {
        /* Fill buffer with test data */
        float* data = (float*)buffer.data;
        for (size_t i = 0; i < 1024 / sizeof(float); i++) {
            data[i] = (float)i;
        }

        /* Test buffer copy */
        qihse_buffer_t dst_buffer = {0};
        ret = qihse_buffer_create(ctx, 1024, QIHSE_DATA_TYPE_FLOAT32,
                                  QIHSE_MEMORY_HOST, &dst_buffer);
        TEST_ASSERT_EQ(ret, QIHSE_OK, "Destination buffer creation should succeed");

        ret = qihse_buffer_copy(&dst_buffer, &buffer);
        TEST_ASSERT_EQ(ret, QIHSE_OK, "Buffer copy should succeed");

        /* Verify copy */
        if (dst_buffer.data) {
            float* dst_data = (float*)dst_buffer.data;
            for (size_t i = 0; i < 1024 / sizeof(float); i++) {
                TEST_ASSERT_EQ(dst_data[i], (float)i,
                              "Copied data should match original");
            }
        }

        qihse_buffer_destroy(&dst_buffer);
    }

    /* Test buffer destruction */
    qihse_buffer_destroy(&buffer);
    TEST_ASSERT_EQ(buffer.data, NULL, "Buffer data should be NULL after destruction");

    /* Cleanup */
    qihse_context_destroy(ctx);

    printf("Buffer management tests passed\n");
}

/* ============================================================================
 * DATA TYPE COMPATIBILITY TESTS
 * ============================================================================ */

void test_data_types(void) {
    printf("Testing data types...\n");

    /* Test data type sizes for ABI stability */
    TEST_ASSERT(sizeof(float) == 4, "FLOAT32 should be 4 bytes");
    TEST_ASSERT(sizeof(double) == 8, "FLOAT64 should be 8 bytes");

    /* Test enum values are distinct */
    TEST_ASSERT_NE(QIHSE_DATA_TYPE_FLOAT32, QIHSE_DATA_TYPE_FLOAT16,
                   "Data types should be distinct");
    TEST_ASSERT_NE(QIHSE_BACKEND_CPU, QIHSE_BACKEND_GPU_NVIDIA,
                   "Backend types should be distinct");

    printf("Data type tests passed\n");
}

/* ============================================================================
 * MEMORY FLAG TESTS
 * ============================================================================ */

void test_memory_flags(void) {
    printf("Testing memory flags...\n");

    /* Test flag combinations */
    qihse_memory_flags_t flags = QIHSE_MEMORY_HOST | QIHSE_MEMORY_PINNED;
    TEST_ASSERT((flags & QIHSE_MEMORY_HOST) != 0,
                "HOST flag should be set");
    TEST_ASSERT((flags & QIHSE_MEMORY_PINNED) != 0,
                "PINNED flag should be set");
    TEST_ASSERT((flags & QIHSE_MEMORY_DEVICE) == 0,
                "DEVICE flag should not be set");

    printf("Memory flag tests passed\n");
}

/* ============================================================================
 * OPERATION INFO TESTS
 * ============================================================================ */

void test_operation_info(void) {
    printf("Testing operation info...\n");

    /* Test operation types */
    TEST_ASSERT_NE(QIHSE_SEARCH_OP_VECTOR_KNN, QIHSE_SEARCH_OP_GRAPH_BFS,
                   "Operation types should be distinct");

    /* Test metric types */
    TEST_ASSERT_NE(QIHSE_METRIC_L2, QIHSE_METRIC_COSINE,
                   "Metric types should be distinct");

    printf("Operation info tests passed\n");
}

/* ============================================================================
 * ABI STABILITY TESTS
 * ============================================================================ */

/**
 * Test that ABI structures have expected sizes.
 * This ensures ABI stability - if sizes change unexpectedly,
 * the ABI has been broken.
 */
void test_abi_stability(void) {
    printf("Testing ABI stability...\n");

    /* Test structure sizes (ABI stability check) */
    TEST_ASSERT_EQ(sizeof(qihse_buffer_t), 32, "qihse_buffer_t size should be stable");
    TEST_ASSERT_EQ(sizeof(qihse_search_config_t), 32, "qihse_search_config_t size should be stable");

    /* Test enum sizes */
    TEST_ASSERT_EQ(sizeof(qihse_error_t), 4, "qihse_error_t should be 4 bytes");
    TEST_ASSERT_EQ(sizeof(qihse_data_type_t), 4, "qihse_data_type_t should be 4 bytes");

    printf("ABI stability tests passed\n");
}

/* ============================================================================
 * MAIN TEST FUNCTION
 * ============================================================================ */

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    printf("QIHSE ABI Compliance Tests\n");
    printf("==========================\n\n");

    /* Run all tests */
    test_abi_version();
    test_error_codes();
    test_context_management();
    test_buffer_management();
    test_data_types();
    test_memory_flags();
    test_operation_info();
    test_abi_stability();

    printf("\n==========================\n");
    printf("ALL ABI TESTS PASSED ✅\n");
    printf("==========================\n");

    return 0;
}
