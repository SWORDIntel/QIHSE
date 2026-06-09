/*
 * QIHSE - CPU Feature Detection via Execution Testing Implementation
 *
 * Runtime detection through actual instruction execution with signal handling.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#include "qihse_cpu_detect.h"
#ifdef _WIN32
#include <intrin.h>
#else
#include <signal.h>
#include <setjmp.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

/* ============================================================================
 * RUNTIME CPU FEATURE TESTING
 * ============================================================================ */

#ifndef _WIN32
static sigjmp_buf cpu_test_jmp_buf;

static void cpu_feature_signal_handler(int signo) {
    (void)signo;
    siglongjmp(cpu_test_jmp_buf, 1);
}
#endif

static bool qihse_force_full_features(void) {
#ifdef QIHSE_FORCE_FULL_FEATURES
    return true;
#else
    const char* env = getenv("QIHSE_FORCE_FULL_FEATURES");
    return env && env[0] != '\0';
#endif
}

/**
 * Execute the test function while trapping illegal/segfault signals.
 */
static bool safe_execute_test(bool (*test_func)(void)) {
#ifdef _WIN32
    (void)test_func;
    return false;
#else
    struct sigaction sa, old_ill, old_segv;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cpu_feature_signal_handler;
    sigemptyset(&sa.sa_mask);
#ifdef SA_NODEFER
    sa.sa_flags = SA_NODEFER;
#else
    sa.sa_flags = 0;
#endif

    sigaction(SIGILL, &sa, &old_ill);
    sigaction(SIGSEGV, &sa, &old_segv);

    if (sigsetjmp(cpu_test_jmp_buf, 1) == 0) {
        bool success = test_func();
        sigaction(SIGILL, &old_ill, NULL);
        sigaction(SIGSEGV, &old_segv, NULL);
        return success;
    }

    sigaction(SIGILL, &old_ill, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    return false;
#endif
}

/* ============================================================================
 * INDIVIDUAL FEATURE TEST IMPLEMENTATIONS
 * ============================================================================ */

bool qihse_cpu_test_sse(void) {
    /* Test SSE instruction execution */
    __asm__ volatile (
        "xorps %%xmm0, %%xmm0\n\t"  /* Clear XMM0 register */
        "xorps %%xmm1, %%xmm1\n\t"  /* Clear XMM1 register */
        "addps %%xmm0, %%xmm1\n\t"  /* Add (should work) */
        :
        :
        : "xmm0", "xmm1"
    );
    return true;
}

bool qihse_cpu_test_sse2(void) {
    /* Test SSE2 instruction execution */
    __asm__ volatile (
        "pxor %%xmm0, %%xmm0\n\t"   /* Clear XMM0 register */
        "pxor %%xmm1, %%xmm1\n\t"   /* Clear XMM1 register */
        "por %%xmm0, %%xmm1\n\t"    /* OR (should work) */
        :
        :
        : "xmm0", "xmm1"
    );
    return true;
}

bool qihse_cpu_test_avx(void) {
    /* Test AVX instruction execution */
    __asm__ volatile (
        "vzeroall\n\t"              /* Clear all YMM registers */
        "vmovaps %%ymm0, %%ymm1\n\t" /* Move between YMM registers */
        :
        :
        : "ymm0", "ymm1"
    );
    return true;
}

bool qihse_cpu_test_avx2(void) {
    /* Test AVX2 instruction execution with gather */
    float data[8] __attribute__((aligned(32))) = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    int indices[8] __attribute__((aligned(32))) = {0, 1, 2, 3, 4, 5, 6, 7};

    __asm__ volatile (
        "vmovaps (%0), %%ymm0\n\t"         /* Load data */
        "vmovdqa (%1), %%ymm1\n\t"         /* Load indices */
        "vgatherdps %%ymm0, (%0, %%ymm1, 4), %%ymm2\n\t"  /* Gather operation */
        :
        : "r"(data), "r"(indices)
        : "ymm0", "ymm1", "ymm2", "memory"
    );
    return true;
}

bool qihse_cpu_test_avx512f(void) {
    /* Test AVX-512 foundation instructions */
    __asm__ volatile (
        "vzeroall\n\t"
        "vmovaps %%zmm0, %%zmm1\n\t"
        :
        :
        : "zmm0", "zmm1"
    );
    return true;
}

bool qihse_cpu_test_avx512bw(void) {
#ifdef __AVX512BW__
    /* Test AVX-512 byte/word operations */
    uint8_t data[64] __attribute__((aligned(64))) = {0};
    __asm__ volatile (
        "vmovdqu8 (%0), %%zmm0\n\t"         /* Load bytes */
        "vpabsb %%zmm0, %%zmm1\n\t"         /* Absolute value of bytes */
        :
        : "r"(data)
        : "zmm0", "zmm1", "memory"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_avx512dq(void) {
#ifdef __AVX512DQ__
    /* Test AVX-512 doubleword/quadword operations */
    __asm__ volatile (
        "vpxorq %%zmm0, %%zmm0, %%zmm0\n\t" /* XOR quadwords */
        "vmovdqa64 %%zmm0, %%zmm1\n\t"      /* Move quadwords */
        :
        :
        : "zmm0", "zmm1"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_avx512vl(void) {
#ifdef __AVX512VL__
    /* Test AVX-512 vector length operations (128-bit vectors) */
    __asm__ volatile (
        "vpxord %%xmm0, %%xmm0, %%xmm0\n\t" /* XOR 128-bit vectors */
        "vmovdqa %%xmm0, %%xmm1\n\t"        /* Move 128-bit vectors */
        :
        :
        : "xmm0", "xmm1"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_amx(void) {
#ifdef __AMX__
    /* AMX requires proper tile configuration and setup */
    /* Test comprehensive AMX functionality with tile operations */

    /* Define tile configuration structure (must be 64-byte aligned) */
    struct __tile_config {
        uint8_t palette_id;
        uint8_t start_row;
        uint8_t reserved_0[14];
        uint16_t colsb[16];    /* Column bytes for each tile */
        uint8_t rowsb[16];     /* Row bytes for each tile */
    } __attribute__((aligned(64))) tile_config = {0};

    /* Configure tile 0: 4x4 matrix of 32-bit elements (16 bytes per row) */
    tile_config.palette_id = 1;  /* Use palette 1 */
    tile_config.colsb[0] = 16;   /* 16 bytes per row (4 floats) */
    tile_config.rowsb[0] = 4;    /* 4 rows */

    /* Allocate aligned memory for tile data */
    float __attribute__((aligned(64))) tile_data[4 * 4]; /* 4x4 floats = 64 bytes */

    /* Initialize tile data with known pattern */
    for (int i = 0; i < 16; i++) {
        tile_data[i] = (float)(i + 1);  /* 1.0, 2.0, 3.0, ... */
    }

    /* Load tile configuration */
    __asm__ volatile (
        "ldtilecfg (%0)\n\t"
        :
        : "r"(&tile_config)
        : "memory"
    );

    /* Load tile data into tile register tmm0 */
    __asm__ volatile (
        "tileloadd tmm0, (%0)\n\t"
        :
        : "r"(tile_data)
        : "memory"
    );

    /* Perform tile operations to test AMX functionality */

    /* 1. Test tile copy (tilemove) */
    __asm__ volatile (
        "tilemove tmm1, tmm0\n\t"  /* Copy tmm0 to tmm1 */
        :
        :
        :
    );

    /* 2. Test tile zero operation */
    __asm__ volatile (
        "tilezero tmm2\n\t"  /* Zero tile tmm2 */
        :
        :
        :
    );

    /* Store tile data back to memory to verify operations */
    float __attribute__((aligned(64))) result_data[4 * 4] = {0};
    float __attribute__((aligned(64))) zero_data[4 * 4] = {0};

    /* Store tmm1 (should match original data) */
    __asm__ volatile (
        "tilestored (%0), tmm1\n\t"
        :
        : "r"(result_data)
        : "memory"
    );

    /* Store tmm2 (should be all zeros) */
    __asm__ volatile (
        "tilestored (%0), tmm2\n\t"
        :
        : "r"(zero_data)
        : "memory"
    );

    /* Release tile configuration */
    __asm__ volatile (
        "tilerelease\n\t"
        :
        :
        :
    );

    /* Verify the results */

    /* Check that tilemove worked (tmm1 should match original) */
    for (int i = 0; i < 16; i++) {
        if (result_data[i] != (float)(i + 1)) {
            return false; /* tilemove failed */
        }
    }

    /* Check that tilezero worked (tmm2 should be all zeros) */
    for (int i = 0; i < 16; i++) {
        if (zero_data[i] != 0.0f) {
            return false; /* tilezero failed */
        }
    }

    /* If we reach here, all AMX operations succeeded */
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_vnni(void) {
#ifdef __AVX512VNNI__
    /* Test VNNI operations (subset of AVX-512) */
    int32_t a[16] __attribute__((aligned(64))) = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    int32_t b[16] __attribute__((aligned(64))) = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    __asm__ volatile (
        "vmovdqa32 (%0), %%zmm0\n\t"        /* Load A */
        "vmovdqa32 (%1), %%zmm1\n\t"        /* Load B */
        "vpdpbusd %%zmm0, %%zmm1, %%zmm2\n\t" /* Dot product accumulate */
        :
        : "r"(a), "r"(b)
        : "zmm0", "zmm1", "zmm2", "memory"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_avx512vnni(void) {
    /* AVX-512 VNNI is tested in qihse_cpu_test_vnni() */
    return qihse_cpu_test_vnni();
}

/* ============================================================================
 * CPU INFORMATION GATHERING
 * ============================================================================ */

/**
 * Initialize CPU info structure.
 */
static void init_cpu_info(qihse_cpu_info_t* info) {
    /* Initialize with defaults - no CPUID or /proc/cpuinfo usage */
    memset(info, 0, sizeof(*info));
    info->family = -1;
    info->model = -1;
    info->stepping = -1;
}

/* ============================================================================
 * MAIN DETECTION FUNCTION
 * ============================================================================ */

qihse_cpu_info_t qihse_cpu_detect(void) {
    qihse_cpu_info_t info;
    init_cpu_info(&info);

    if (qihse_force_full_features()) {
        uint64_t features = QIHSE_CPU_FEATURE_SSE |
                            QIHSE_CPU_FEATURE_SSE2 |
                            QIHSE_CPU_FEATURE_SSE3 |
                            QIHSE_CPU_FEATURE_SSSE3 |
                            QIHSE_CPU_FEATURE_SSE4_1 |
                            QIHSE_CPU_FEATURE_SSE4_2 |
                            QIHSE_CPU_FEATURE_AVX |
                            QIHSE_CPU_FEATURE_AVX2 |
                            QIHSE_CPU_FEATURE_AVX512F |
                            QIHSE_CPU_FEATURE_AVX512BW |
                            QIHSE_CPU_FEATURE_AVX512DQ |
                            QIHSE_CPU_FEATURE_AVX512VL |
                            QIHSE_CPU_FEATURE_AVX512VNNI |
                            QIHSE_CPU_FEATURE_AMX |
                            QIHSE_CPU_FEATURE_AMX_TILE |
                            QIHSE_CPU_FEATURE_AMX_INT8 |
                            QIHSE_CPU_FEATURE_VNNI;
        info.has_osxsave = true;
        info.has_avx_support = true;
        info.has_avx512_support = true;
        info.features = features;
        return info;
    }

#ifdef _WIN32
    uint64_t features = QIHSE_CPU_FEATURE_NONE;
    int cpuInfo[4];

    __cpuid(cpuInfo, 1);
    if (cpuInfo[3] & (1 << 25)) features |= QIHSE_CPU_FEATURE_SSE;
    if (cpuInfo[3] & (1 << 26)) features |= QIHSE_CPU_FEATURE_SSE2;

    bool osxsave = (cpuInfo[2] & (1 << 27)) != 0;
    info.has_osxsave = osxsave;
    info.has_avx_support = (cpuInfo[2] & (1 << 28)) != 0;

    if (info.has_avx_support && osxsave) {
        features |= QIHSE_CPU_FEATURE_AVX;
        
        __cpuidex(cpuInfo, 7, 0);
        if (cpuInfo[1] & (1 << 5)) features |= QIHSE_CPU_FEATURE_AVX2;
        
        info.has_avx512_support = (cpuInfo[1] & (1 << 16)) != 0;
        if (info.has_avx512_support) {
            features |= QIHSE_CPU_FEATURE_AVX512F;
            if (cpuInfo[1] & (1 << 30)) features |= QIHSE_CPU_FEATURE_AVX512BW;
            if (cpuInfo[1] & (1 << 17)) features |= QIHSE_CPU_FEATURE_AVX512DQ;
            if (cpuInfo[1] & (1 << 31)) features |= QIHSE_CPU_FEATURE_AVX512VL;
            if (cpuInfo[2] & (1 << 11)) features |= QIHSE_CPU_FEATURE_AVX512VNNI;
        }

        if (cpuInfo[3] & (1 << 22)) {
            features |= QIHSE_CPU_FEATURE_AMX;
            features |= QIHSE_CPU_FEATURE_AMX_TILE;
        }
        if (cpuInfo[3] & (1 << 23)) features |= QIHSE_CPU_FEATURE_AMX_INT8;
        if (cpuInfo[3] & (1 << 22)) features |= QIHSE_CPU_FEATURE_AMX_BF16;

        if (cpuInfo[2] & (1 << 11)) {
            features |= QIHSE_CPU_FEATURE_VNNI;
        }

        /* AVX-VNNI (leaf 7, sub-leaf 1, EAX bit 4) */
        __cpuidex(cpuInfo, 7, 1);
        if (cpuInfo[0] & (1 << 4)) features |= QIHSE_CPU_FEATURE_AVX_VNNI;
    }

    info.features = features;
#else
    /* Test each feature through actual execution */
    uint64_t features = QIHSE_CPU_FEATURE_NONE;

    /* Test SIMD features */
    if (safe_execute_test(qihse_cpu_test_sse)) {
        features |= QIHSE_CPU_FEATURE_SSE;
    }
    if (safe_execute_test(qihse_cpu_test_sse2)) {
        features |= QIHSE_CPU_FEATURE_SSE2;
    }

    /* Test AVX features (require OS support) */
    /* OSXSAVE is required for AVX - test by attempting AVX execution */
    info.has_osxsave = safe_execute_test(qihse_cpu_test_avx);
    info.has_avx_support = info.has_osxsave;
    if (info.has_avx_support) {
        features |= QIHSE_CPU_FEATURE_AVX;
        if (safe_execute_test(qihse_cpu_test_avx2)) {
            features |= QIHSE_CPU_FEATURE_AVX2;
        }
    }

    /* Test AVX-512 features (require OS support) */
    info.has_avx512_support = safe_execute_test(qihse_cpu_test_avx512f);
    if (info.has_avx512_support) {
        features |= QIHSE_CPU_FEATURE_AVX512F;
        if (safe_execute_test(qihse_cpu_test_avx512bw)) {
            features |= QIHSE_CPU_FEATURE_AVX512BW;
        }
        if (safe_execute_test(qihse_cpu_test_avx512dq)) {
            features |= QIHSE_CPU_FEATURE_AVX512DQ;
        }
        if (safe_execute_test(qihse_cpu_test_avx512vl)) {
            features |= QIHSE_CPU_FEATURE_AVX512VL;
        }
        if (safe_execute_test(qihse_cpu_test_avx512vnni)) {
            features |= QIHSE_CPU_FEATURE_AVX512VNNI;
        }
    }

    /* Test specialized features */
    if (safe_execute_test(qihse_cpu_test_amx)) {
        features |= QIHSE_CPU_FEATURE_AMX;
        features |= QIHSE_CPU_FEATURE_AMX_TILE;
    }
    if (safe_execute_test(qihse_cpu_test_vnni)) {
        features |= QIHSE_CPU_FEATURE_VNNI;
    }
    /* AVX-VNNI runtime test: attempt vpdpbusd ymm0,ymm0,ymm0 */
    {
        bool avx_vnni_ok = false;
#if defined(__AVXVNNI__) || (defined(QIHSE_ENABLE_AVX_VNNI) && QIHSE_ENABLE_AVX_VNNI)
        __asm__ volatile (
            "vpdpbusd %%ymm1, %%ymm0, %%ymm0\n"
            : : : "ymm0", "ymm1"
        );
        avx_vnni_ok = true;
#endif
        (void)avx_vnni_ok;
        if (avx_vnni_ok) features |= QIHSE_CPU_FEATURE_AVX_VNNI;
    }

    info.features = features;
#endif
    return info;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

bool qihse_cpu_has_feature(const qihse_cpu_info_t* info, qihse_cpu_feature_t feature) {
    return (info->features & feature) != 0;
}

const char* qihse_cpu_feature_name(qihse_cpu_feature_t feature) {
    switch (feature) {
        case QIHSE_CPU_FEATURE_SSE: return "SSE";
        case QIHSE_CPU_FEATURE_SSE2: return "SSE2";
        case QIHSE_CPU_FEATURE_AVX: return "AVX";
        case QIHSE_CPU_FEATURE_AVX2: return "AVX2";
        case QIHSE_CPU_FEATURE_AVX512F: return "AVX-512F";
        case QIHSE_CPU_FEATURE_AVX512BW: return "AVX-512BW";
        case QIHSE_CPU_FEATURE_AVX512DQ: return "AVX-512DQ";
        case QIHSE_CPU_FEATURE_AVX512VL: return "AVX-512VL";
        case QIHSE_CPU_FEATURE_AMX: return "AMX";
        case QIHSE_CPU_FEATURE_AMX_TILE: return "AMX-Tile";
        case QIHSE_CPU_FEATURE_AMX_INT8: return "AMX-Int8";
        case QIHSE_CPU_FEATURE_AMX_BF16: return "AMX-BF16";
        case QIHSE_CPU_FEATURE_VNNI: return "AVX512-VNNI";
        case QIHSE_CPU_FEATURE_AVX512VNNI: return "AVX-512VNNI";
        case QIHSE_CPU_FEATURE_AVX_VNNI: return "AVX-VNNI";
        default: return "UNKNOWN";
    }
}

const char* qihse_cpu_feature_description(qihse_cpu_feature_t feature) {
    switch (feature) {
        case QIHSE_CPU_FEATURE_SSE: return "Streaming SIMD Extensions";
        case QIHSE_CPU_FEATURE_SSE2: return "Streaming SIMD Extensions 2";
        case QIHSE_CPU_FEATURE_AVX: return "Advanced Vector Extensions";
        case QIHSE_CPU_FEATURE_AVX2: return "Advanced Vector Extensions 2";
        case QIHSE_CPU_FEATURE_AVX512F: return "AVX-512 Foundation";
        case QIHSE_CPU_FEATURE_AVX512BW: return "AVX-512 Byte and Word Instructions";
        case QIHSE_CPU_FEATURE_AVX512DQ: return "AVX-512 Doubleword and Quadword Instructions";
        case QIHSE_CPU_FEATURE_AVX512VL: return "AVX-512 Vector Length Extensions";
        case QIHSE_CPU_FEATURE_AMX: return "Advanced Matrix Extensions (base)";
        case QIHSE_CPU_FEATURE_AMX_TILE: return "AMX Tile memory operations";
        case QIHSE_CPU_FEATURE_AMX_INT8: return "AMX INT8 tile multiply";
        case QIHSE_CPU_FEATURE_AMX_BF16: return "AMX BFloat16 tile multiply";
        case QIHSE_CPU_FEATURE_VNNI: return "AVX-512 Vector Neural Network Instructions";
        case QIHSE_CPU_FEATURE_AVX512VNNI: return "AVX-512 VNNI (alias)";
        case QIHSE_CPU_FEATURE_AVX_VNNI: return "AVX-VNNI: VEX vpdpbusd/vpdpwssd (256-bit, no AVX-512)";
        default: return "Unknown CPU feature";
    }
}

int qihse_cpu_optimal_vector_width(const qihse_cpu_info_t* info) {
    if (info->features & QIHSE_CPU_FEATURE_AVX512F) {
        return 64; /* AVX-512: 512 bits = 64 bytes */
    } else if (info->features & QIHSE_CPU_FEATURE_AVX) {
        return 32; /* AVX/AVX2: 256 bits = 32 bytes */
    } else if (info->features & QIHSE_CPU_FEATURE_SSE2) {
        return 16; /* SSE2: 128 bits = 16 bytes */
    } else {
        return 8; /* Scalar fallback */
    }
}

bool qihse_cpu_supports_efficient_gather(const qihse_cpu_info_t* info) {
    /* AVX-512 has efficient gather, AVX2 has gather but less efficient */
    return (info->features & QIHSE_CPU_FEATURE_AVX512F) != 0;
}

int qihse_cpu_cache_line_size(void) {
    /* Most modern x86 CPUs have 64-byte cache lines */
    return 64;
}

size_t qihse_cpu_l2_cache_size(void) {
    FILE *fp;
    char buffer[32];
    size_t cache_size = 0;

    /* Read L2 cache size from sysfs using standard C file I/O */
    fp = fopen("/sys/devices/system/cpu/cpu0/cache/index2/size", "r");
    if (!fp) {
        /* Fallback to reasonable default if sysfs not available */
        return 256 * 1024; /* 256KB L2 cache */
    }

    if (fgets(buffer, sizeof(buffer), fp)) {
        /* Parse cache size (format: "256K" or "1024K") */
        char *endptr;
        cache_size = strtoul(buffer, &endptr, 10);

        /* Check for suffix and convert */
        if (*endptr) {
            if (*endptr == 'K' || *endptr == 'k') {
                cache_size *= 1024;
            } else if (*endptr == 'M' || *endptr == 'm') {
                cache_size *= 1024 * 1024;
            }
        }
        /* If no suffix, assume bytes */

        /* Sanity check - cache size should be reasonable */
        if (cache_size < 1024 || cache_size > 100 * 1024 * 1024) {
            cache_size = 256 * 1024; /* Fallback on invalid values */
        }
    } else {
        /* Fallback if read failed */
        cache_size = 256 * 1024; /* 256KB L2 cache */
    }

    fclose(fp);
    return cache_size;
}

qihse_cpu_feature_t qihse_cpu_detect_features(void) {
    qihse_cpu_info_t info = qihse_cpu_detect();
    return (qihse_cpu_feature_t)info.features;
}
