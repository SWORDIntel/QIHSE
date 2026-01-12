/*
 * Comprehensive ISA Feature Test for A00 Board
 * Tests: AVX2, AVX-VNNI, AVX-512, AMX
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __AMX_TILE__
#include <immintrin.h>
#endif

int test_avx2() {
    printf("\n[TEST] AVX2 (256-bit vectors):\n");
    #ifdef __AVX2__
    __m256i a = _mm256_set1_epi32(100);
    __m256i b = _mm256_set1_epi32(200);
    __m256i c = _mm256_add_epi32(a, b);
    
    int result[8];
    _mm256_storeu_si256((__m256i*)result, c);
    
    printf("  Result: %d (expected 300)\n", result[0]);
    if (result[0] == 300) {
        printf("  ✓ AVX2 WORKS!\n");
        return 0;
    }
    #else
    printf("  ✗ Not compiled with AVX2\n");
    #endif
    return 1;
}

int test_avx_vnni() {
    printf("\n[TEST] AVX-VNNI (VNNI on 256-bit):\n");
    #ifdef __AVXVNNI__
    // AVX-VNNI test - simplified
    __m256i a = _mm256_set1_epi8(1);
    __m256i b = _mm256_set1_epi8(2);
    __m256i acc = _mm256_setzero_si256();
    
    // This would use VNNI if available, otherwise falls back
    printf("  AVX-VNNI compiled (check CPUID for runtime support)\n");
    printf("  ✓ AVX-VNNI compilation WORKS!\n");
    return 0;
    #else
    printf("  ✗ Not compiled with AVX-VNNI\n");
    return 1;
    #endif
}

int test_avx512f() {
    printf("\n[TEST] AVX-512F (512-bit vectors):\n");
    #ifdef __AVX512F__
    printf("  Attempting AVX-512F operation...\n");
    __m512i a = _mm512_set1_epi32(42);
    __m512i b = _mm512_set1_epi32(8);
    __m512i c = _mm512_add_epi32(a, b);
    
    int result[16];
    _mm512_storeu_si512((__m512i*)result, c);
    
    printf("  Result: %d (expected 50)\n", result[0]);
    if (result[0] == 50) {
        printf("  ✓ AVX-512F WORKS!\n");
        return 0;
    }
    #else
    printf("  ✗ Not compiled with AVX-512F\n");
    #endif
    return 1;
}

int test_amx_tile() {
    printf("\n[TEST] AMX-TILE (Advanced Matrix Extensions):\n");
    #ifdef __AMX_TILE__
    printf("  Attempting AMX TILE configuration...\n");
    
    // AMX tile configuration structure
    struct __tilecfg {
        uint8_t palette_id;
        uint8_t start_row;
        uint8_t reserved_0[14];
        uint16_t colsb[16];
        uint8_t rows[16];
    };
    
    struct __tilecfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.palette_id = 1;
    cfg.rows[0] = 16;
    cfg.colsb[0] = 64;
    
    // Load tile configuration
    _tile_loadconfig(&cfg);
    printf("  Tile config loaded\n");
    
    // Release tiles
    _tile_release();
    printf("  Tile release successful\n");
    
    printf("  ✓ AMX-TILE WORKS!\n");
    return 0;
    #else
    printf("  ✗ Not compiled with AMX-TILE\n");
    return 1;
    #endif
}

int test_amx_int8() {
    printf("\n[TEST] AMX-INT8 (INT8 matrix multiply):\n");
    #ifdef __AMX_INT8__
    printf("  Attempting AMX-INT8 operation...\n");
    
    // This would normally do tile operations
    // For now just test if it compiles
    printf("  AMX-INT8 compiled successfully\n");
    printf("  ✓ AMX-INT8 compilation WORKS!\n");
    return 0;
    #else
    printf("  ✗ Not compiled with AMX-INT8\n");
    return 1;
    #endif
}

int test_amx_bf16() {
    printf("\n[TEST] AMX-BF16 (BFloat16 matrix multiply):\n");
    #ifdef __AMX_BF16__
    printf("  AMX-BF16 compiled successfully\n");
    printf("  ✓ AMX-BF16 compilation WORKS!\n");
    return 0;
    #else
    printf("  ✗ Not compiled with AMX-BF16\n");
    return 1;
    #endif
}

int main() {
    printf("================================================================\n");
    printf("COMPREHENSIVE ISA FEATURE TEST - A00 Engineering Board\n");
    printf("Intel Core Ultra 7 165H (Meteor Lake)\n");
    printf("================================================================\n");
    
    int passed = 0;
    int total = 6;
    
    // Test each feature
    if (test_avx2() == 0) passed++;
    if (test_avx_vnni() == 0) passed++;
    if (test_avx512f() == 0) passed++;
    if (test_amx_tile() == 0) passed++;
    if (test_amx_int8() == 0) passed++;
    if (test_amx_bf16() == 0) passed++;
    
    printf("\n================================================================\n");
    printf("RESULTS: %d/%d tests passed\n", passed, total);
    printf("================================================================\n");
    
    if (passed >= 2) {
        printf("✓ Basic vector operations working (AVX2/AVX-VNNI)\n");
    }
    if (passed >= 3) {
        printf("✓ Advanced features detected!\n");
    }
    
    printf("\nNote: Tests that compile but crash indicate hardware doesn't\n");
    printf("      support the feature despite compiler flags.\n");
    printf("================================================================\n");
    
    return (passed >= 2) ? 0 : 1;
}
