#include <immintrin.h>
#include <stdio.h>

int main() {
    printf("Testing AVX-VNNI...\n");
    __m256i a = _mm256_set1_epi8(2);
    __m256i b = _mm256_set1_epi8(3);
    __m256i acc = _mm256_setzero_si256();

    acc = _mm256_dpbusd_epi32(acc, a, b);

    int result = _mm256_extract_epi32(acc, 0);
    printf("AVX-VNNI result: %d\n", result);
    printf("✓ AVX-VNNI compilation SUCCESS\n");
    (void)result;
    return 0;
}
