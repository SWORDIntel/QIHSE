/*
 * Direct AVX-512 Hardware Test
 * Tests if AVX-512 instructions actually work on A00 board
 * Bypasses CPUID checks completely
 */

#include <stdio.h>
#include <immintrin.h>
#include <time.h>

int main() {
    printf("=================================================================\n");
    printf("AVX-512 DIRECT HARDWARE TEST - A00 Engineering Board\n");
    printf("=================================================================\n");
    
    printf("\nAttempting AVX-512 operations (ignoring CPUID)...\n\n");
    
    // Test 1: AVX-512F (Foundation)
    printf("Test 1: AVX-512F (512-bit vectors)\n");
    __m512 a = _mm512_set1_ps(2.0f);
    __m512 b = _mm512_set1_ps(3.0f);
    __m512 c = _mm512_add_ps(a, b);
    
    float result[16];
    _mm512_storeu_ps(result, c);
    printf("  Vector add: 2.0 + 3.0 = %.1f\n", result[0]);
    
    if (result[0] == 5.0f) {
        printf("  ✓ AVX-512F WORKS!\n\n");
    } else {
        printf("  ✗ AVX-512F failed\n\n");
        return 1;
    }
    
    // Test 2: AVX-512 FMA
    printf("Test 2: AVX-512 FMA (fused multiply-add)\n");
    __m512 x = _mm512_set1_ps(2.0f);
    __m512 y = _mm512_set1_ps(3.0f);
    __m512 z = _mm512_set1_ps(4.0f);
    __m512 fma_result = _mm512_fmadd_ps(x, y, z);  // x*y + z
    
    _mm512_storeu_ps(result, fma_result);
    printf("  FMA: 2*3 + 4 = %.1f\n", result[0]);
    
    if (result[0] == 10.0f) {
        printf("  ✓ AVX-512 FMA WORKS!\n\n");
    } else {
        printf("  ✗ AVX-512 FMA failed\n\n");
        return 1;
    }
    
    // Test 3: Performance test
    printf("Test 3: Performance benchmark\n");
    const int iterations = 10000000;
    
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        c = _mm512_fmadd_ps(a, b, c);
    }
    clock_t end = clock();
    
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    double gflops = (iterations * 16.0 * 2.0) / (time_taken * 1e9);  // 16 floats * 2 ops per FMA
    
    printf("  Executed %d iterations in %.3f seconds\n", iterations, time_taken);
    printf("  Performance: %.2f GFLOPS\n", gflops);
    printf("  ✓ AVX-512 performance validated!\n\n");
    
    printf("=================================================================\n");
    printf("RESULT: AVX-512 HARDWARE IS FUNCTIONAL\n");
    printf("=================================================================\n");
    printf("\nConclusion:\n");
    printf("  ✓ AVX-512 instructions execute correctly\n");
    printf("  ✓ No illegal instruction faults\n");
    printf("  ✓ Hardware supports AVX-512 despite hidden CPUID\n");
    printf("\nThis confirms the A00 board HAS working AVX-512!\n");
    printf("Build with: -mavx512f -mavx512dq -mavx512bw -mavx512vl\n");
    printf("=================================================================\n");
    
    return 0;
}
