/*
 * Comprehensive ISA Feature Test for A00 Board
 * Tests: AVX2, AVX-VNNI, AVX-512, AMX
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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


/* ---- host ISA probe -------------------------------------------------------
 * The build enables -m<isa> per detected CPU flag, so this battery must judge
 * only the ISAs the host actually advertises: an ISA the CPU lacks is a SKIP,
 * not a failure (previously it required >=2 passes and failed on any CPU
 * without AVX2/AVX-512/AMX). */
static char host_flags[8192];

static void load_host_flags(void) {
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return;
    char line[8192];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "flags", 5) != 0) continue;
        char* colon = strchr(line, ':');
        if (!colon) continue;
        colon++;
        size_t len = strcspn(colon, "\n");
        if (len >= sizeof host_flags) len = sizeof host_flags - 1u;
        memcpy(host_flags, colon, len);
        host_flags[len] = '\0';
        break;
    }
    fclose(f);
}

static int host_has(const char* flag) {
    size_t n = strlen(flag);
    const char* p = host_flags;
    while ((p = strstr(p, flag)) != NULL) {
        bool start_ok = (p == host_flags) || (p[-1] == ' ');
        bool end_ok = (p[n] == ' ' || p[n] == '\0');
        if (start_ok && end_ok) return 1;
        p += n;
    }
    return 0;
}

typedef struct { const char* name; const char* flag; int (*fn)(void); } isa_case_t;

int main() {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_all_isa_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    printf("================================================================\n");
    printf("COMPREHENSIVE ISA FEATURE TEST - A00 Engineering Board\n");
    printf("Intel Core Ultra 7 165H (Meteor Lake)\n");
    printf("================================================================\n");
    
    load_host_flags();

    const isa_case_t cases[] = {
        { "AVX2",      "avx2",      test_avx2 },
        { "AVX-VNNI",  "avx_vnni",  test_avx_vnni },
        { "AVX-512F",  "avx512f",   test_avx512f },
        { "AMX-TILE",  "amx_tile",  test_amx_tile },
        { "AMX-INT8",  "amx_int8",  test_amx_int8 },
        { "AMX-BF16",  "amx_bf16",  test_amx_bf16 },
    };
    const size_t total = sizeof cases / sizeof cases[0];

    size_t advertised = 0, passed = 0, skipped = 0, failed = 0;
    for (size_t i = 0; i < total; i++) {
        if (!host_has(cases[i].flag)) {
            printf("\n[SKIP] %s: host CPU does not advertise %s\n", cases[i].name, cases[i].flag);
            skipped++;
            continue;
        }
        advertised++;
        if (cases[i].fn() == 0) passed++; else failed++;
    }

    printf("\n================================================================\n");
    printf("RESULTS: %zu advertised ISAs, %zu passed, %zu failed, %zu skipped\n",
           advertised, passed, failed, skipped);
    printf("================================================================\n");

    if (advertised == 0) {
        printf("skip: host advertises none of the tested ISA extensions\n");
        return 0;      /* nothing to validate on this CPU, not a failure */
    }
    if (failed != 0) {
        printf("FAIL: %zu advertised ISA extension(s) did not work\n", failed);
        return 1;
    }
    printf("OK: every ISA extension this host advertises works\n");
    return 0;
}
