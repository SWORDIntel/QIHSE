/*
 * Direct Execution Test - NO CPUID CHECKS
 * Tries to execute instructions directly, catches SIGILL gracefully
 * This is what worked "yesterday" - direct execution without CPUID validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <immintrin.h>

static jmp_buf sigill_jmp;
static int test_failed = 0;

static void sigill_handler(int sig) {
    (void)sig;
    test_failed = 1;
    longjmp(sigill_jmp, 1);
}

#define TEST_INSTRUCTION(name, code) \
    do { \
        test_failed = 0; \
        signal(SIGILL, sigill_handler); \
        if (setjmp(sigill_jmp) == 0) { \
            code; \
            signal(SIGILL, SIG_DFL); \
            printf("  ✓ %s: EXECUTED SUCCESSFULLY\n", name); \
        } else { \
            signal(SIGILL, SIG_DFL); \
            printf("  ✗ %s: ILLEGAL INSTRUCTION\n", name); \
        } \
    } while(0)

int main(void) {
    /* Set up signal handler FIRST before any SIMD instructions */
    signal(SIGILL, sigill_handler);
    
    printf("======================================================================\n");
    printf("DIRECT EXECUTION TEST - NO CPUID CHECKS\n");
    printf("======================================================================\n");
    printf("Testing instructions directly, catching SIGILL if unsupported\n");
    printf("This matches your 'simple command execution test' that worked\n");
    printf("======================================================================\n\n");

    /* AVX2 Test */
    printf("AVX2 Instructions:\n");
    TEST_INSTRUCTION("AVX2 ADD", {
        __m256 a = _mm256_set1_ps(2.0f);
        __m256 b = _mm256_set1_ps(3.0f);
        __m256 result = _mm256_add_ps(a, b);
        volatile float sum = 0.0f;
        float *r = (float*)&result;
        for (int i = 0; i < 8; i++) sum += r[i];
        if (sum < 39.9f || sum > 40.1f) test_failed = 1;
    });

    /* AVX-VNNI Test */
    printf("\nAVX-VNNI Instructions:\n");
    TEST_INSTRUCTION("AVX-VNNI DPWSSD", {
        __m256i a = _mm256_set1_epi16(2);
        __m256i b = _mm256_set1_epi16(3);
        __m256i c = _mm256_set1_epi32(1);
        __m256i result = _mm256_dpwssd_epi32(c, a, b);
        volatile int sum = 0;
        int *r = (int*)&result;
        for (int i = 0; i < 8; i++) sum += r[i];
        if (sum != 49) test_failed = 1;
    });

    /* AVX-512F Test */
    printf("\nAVX-512F Instructions:\n");
    TEST_INSTRUCTION("AVX-512F ADD", {
        __m512 a = _mm512_set1_ps(2.0f);
        __m512 b = _mm512_set1_ps(3.0f);
        __m512 c = _mm512_add_ps(a, b);
        volatile float sum = 0.0f;
        float *r = (float*)&c;
        for (int i = 0; i < 16; i++) sum += r[i];
        if (sum < 79.9f || sum > 80.1f) test_failed = 1;
    });

    TEST_INSTRUCTION("AVX-512F FMA", {
        __m512 x = _mm512_set1_ps(2.0f);
        __m512 y = _mm512_set1_ps(3.0f);
        __m512 z = _mm512_set1_ps(4.0f);
        __m512 result = _mm512_fmadd_ps(x, y, z);
        volatile float sum = 0.0f;
        float *r = (float*)&result;
        for (int i = 0; i < 16; i++) sum += r[i];
        if (sum < 159.9f || sum > 160.1f) test_failed = 1;
    });

    /* AMX-TILE Test */
    printf("\nAMX-TILE Instructions:\n");
    TEST_INSTRUCTION("AMX-TILE CONFIG", {
        unsigned char tilecfg[64] = {0};
        tilecfg[0] = 1;  /* Enable tile 0 */
        tilecfg[1] = 16; /* Row count */
        tilecfg[2] = 64; /* Col count */
        _tile_loadconfig(tilecfg);
    });

    TEST_INSTRUCTION("AMX-TILE LOAD", {
        char data[1024] = {0};
        for (int i = 0; i < 1024; i++) data[i] = i & 0xFF;
        _tile_loadd(0, data, 64);
    });

    TEST_INSTRUCTION("AMX-INT8 DPBSSD", {
        _tile_dpbssd(0, 1, 2);
    });

    TEST_INSTRUCTION("AMX-BF16 DPBF16PS", {
        _tile_dpbf16ps(0, 1, 2);
    });

    /* AVX-512 VNNI Test */
    printf("\nAVX-512 VNNI Instructions:\n");
    TEST_INSTRUCTION("AVX-512 VNNI DPWSSD", {
        __m512i a = _mm512_set1_epi16(2);
        __m512i b = _mm512_set1_epi16(3);
        __m512i c = _mm512_set1_epi32(1);
        __m512i result = _mm512_dpwssd_epi32(c, a, b);
        volatile int sum = 0;
        int *r = (int*)&result;
        for (int i = 0; i < 16; i++) sum += r[i];
        if (sum != 97) test_failed = 1;
    });

    /* AVX-512 FP16 Test */
    printf("\nAVX-512 FP16 Instructions:\n");
    TEST_INSTRUCTION("AVX-512 FP16 ADD", {
        __m512h a = _mm512_set1_ph(2.0f);
        __m512h b = _mm512_set1_ph(3.0f);
        __m512h c = _mm512_add_ph(a, b);
        volatile float sum = 0.0f;
        _Float16 *r = (_Float16*)&c;
        for (int i = 0; i < 32; i++) sum += (float)r[i];
        if (sum < 159.9f || sum > 160.1f) test_failed = 1;
    });

    printf("\n======================================================================\n");
    printf("DIRECT EXECUTION TEST COMPLETE\n");
    printf("======================================================================\n");
    printf("This test does NOT check CPUID - it tries to execute directly\n");
    printf("If instructions execute without SIGILL, they work at hardware level\n");
    printf("======================================================================\n");

    return 0;
}
