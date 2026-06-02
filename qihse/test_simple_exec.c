/*
 * Simple Direct Execution - What worked "yesterday"
 * Tests each instruction set individually with proper signal handling
 */

#include <stdio.h>
#include <signal.h>
#include <setjmp.h>
#include <immintrin.h>

static jmp_buf jmp;
static volatile int caught_sigill = 0;

void sigill_handler(int sig) {
    (void)sig;
    caught_sigill = 1;
    longjmp(jmp, 1);
}

/* Test AVX2 */
int test_avx2(void) {
    caught_sigill = 0;
    signal(SIGILL, sigill_handler);
    
    if (setjmp(jmp) == 0) {
        __m256 a = _mm256_set1_ps(2.0f);
        __m256 b = _mm256_set1_ps(3.0f);
        __m256 c = _mm256_add_ps(a, b);
        volatile float sum = 0.0f;
        float *r = (float*)&c;
        for (int i = 0; i < 8; i++) sum += r[i];
        signal(SIGILL, SIG_DFL);
        printf("AVX2: ✓ WORKS (sum=%.1f)\n", sum);
        return 1;
    }
    signal(SIGILL, SIG_DFL);
    printf("AVX2: ✗ ILLEGAL\n");
    return 0;
}

/* Test AVX-512F */
int test_avx512f(void) {
    caught_sigill = 0;
    signal(SIGILL, sigill_handler);
    
    if (setjmp(jmp) == 0) {
        __m512 a = _mm512_set1_ps(2.0f);
        __m512 b = _mm512_set1_ps(3.0f);
        __m512 c = _mm512_add_ps(a, b);
        volatile float sum = 0.0f;
        float *r = (float*)&c;
        for (int i = 0; i < 16; i++) sum += r[i];
        signal(SIGILL, SIG_DFL);
        printf("AVX-512F: ✓ WORKS (sum=%.1f)\n", sum);
        return 1;
    }
    signal(SIGILL, SIG_DFL);
    printf("AVX-512F: ✗ ILLEGAL\n");
    return 0;
}

/* Test AMX-TILE */
int test_amx_tile(void) {
    caught_sigill = 0;
    signal(SIGILL, sigill_handler);
    
    if (setjmp(jmp) == 0) {
        unsigned char cfg[64] = {0};
        cfg[0] = 1;
        _tile_loadconfig(cfg);
        _tile_release();
        signal(SIGILL, SIG_DFL);
        printf("AMX-TILE: ✓ WORKS\n");
        return 1;
    }
    signal(SIGILL, SIG_DFL);
    printf("AMX-TILE: ✗ ILLEGAL\n");
    return 0;
}

int main(void) {
    printf("Simple Direct Execution Test\n");
    printf("============================\n\n");
    
    int avx2 = test_avx2();
    int avx512 = test_avx512f();
    int amx = test_amx_tile();
    
    printf("\n============================\n");
    printf("Results: AVX2=%d, AVX-512=%d, AMX=%d\n", avx2, avx512, amx);
    
    return 0;
}
