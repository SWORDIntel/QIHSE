#include <immintrin.h>
#include <stdio.h>

int main() {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_avx2_only_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    printf("Testing AVX2...\n");
    __m256i a = _mm256_set1_epi32(100);
    __m256i b = _mm256_set1_epi32(200);
    __m256i c = _mm256_add_epi32(a, b);
    int result[8];
    _mm256_storeu_si256((__m256i*)result, c);
    printf("AVX2 result: %d (expected 300)\n", result[0]);
    return (result[0] == 300) ? 0 : 1;
}
