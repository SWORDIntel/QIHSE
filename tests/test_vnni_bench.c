#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include "qihse_instr.h"
#include "qihse_math.h"

#define VECTOR_SIZE 1000000
#define ITERATIONS 1000

static inline uint64_t ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main() {
    int8_t *a, *b;
    int32_t result;
    qihse_intel_hw_info_t hw_info;

    a = (int8_t*)aligned_alloc(32, VECTOR_SIZE);
    b = (int8_t*)aligned_alloc(32, VECTOR_SIZE);

    if (!a || !b) {
        printf("Memory allocation failed\n");
        return 1;
    }

    // Initialize with some data
    for (int i = 0; i < VECTOR_SIZE; i++) {
        a[i] = (int8_t)(i % 127);
        b[i] = (int8_t)(i % 127 - 64);
    }

    qihse_intel_detect_hardware(&hw_info);
    
    // Test without VNNI (fallback)
    qihse_intel_enable_features(0);
    uint64_t start = ns_now();
    for (int i = 0; i < ITERATIONS; i++) {
        result = qihse_math_int8_dot(a, b, VECTOR_SIZE);
    }
    uint64_t end = ns_now();
    double fallback_time = (double)(end - start) / 1e9;
    printf("Fallback Result: %d, Time: %.4f s\n", result, fallback_time);

    // Test with VNNI
    if (hw_info.available_features & QIHSE_INTEL_HW_AVX_VNNI) {
        printf("VNNI hardware detected. Enabling...\n");
        qihse_intel_enable_features(QIHSE_INTEL_HW_AVX_VNNI);
        
        start = ns_now();
        for (int i = 0; i < ITERATIONS; i++) {
            result = qihse_math_int8_dot(a, b, VECTOR_SIZE);
        }
        end = ns_now();
        double vnni_time = (double)(end - start) / 1e9;
        printf("VNNI Result: %d, Time: %.4f s\n", result, vnni_time);
        printf("Acceleration: %.2fx\n", fallback_time / vnni_time);
    } else {
        printf("VNNI hardware not detected on this CPU.\n");
    }

    free(a);
    free(b);
    return 0;
}
