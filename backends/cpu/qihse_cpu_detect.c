/*
 * QIHSE - CPU Feature Detection via Execution Testing Implementation
 *
 * Runtime detection through actual instruction execution with signal handling.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_cpu_detect.h"
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#ifdef _WIN32
#include <intrin.h>
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <signal.h>
#include <setjmp.h>
#include <immintrin.h>
static inline void qihse_raw_cpuid(int cpuInfo[4], int leaf, int subleaf) {
    __asm__ volatile("cpuid"
                     : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
                     : "a"(leaf), "c"(subleaf));
}
static inline uint64_t qihse_xgetbv(uint32_t index) {
    uint32_t eax, edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
    return ((uint64_t)edx << 32) | eax;
}
#else
#include <signal.h>
#include <setjmp.h>
#endif

/* ============================================================================
 * RUNTIME CPU FEATURE TESTING
 * ============================================================================ */

#ifndef _WIN32
static sigjmp_buf cpu_test_jmp_buf;
static pthread_mutex_t cpu_test_mutex = PTHREAD_MUTEX_INITIALIZER;

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
bool qihse_cpu_safe_execute_test(bool (*test_func)(void)) {
#ifdef _WIN32
    (void)test_func;
    return false;
#else
    pthread_mutex_lock(&cpu_test_mutex);
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
        pthread_mutex_unlock(&cpu_test_mutex);
        return success;
    }

    sigaction(SIGILL, &old_ill, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    pthread_mutex_unlock(&cpu_test_mutex);
    return false;
#endif
}

static __attribute__((unused)) bool safe_execute_test(bool (*test_func)(void)) {
    return qihse_cpu_safe_execute_test(test_func);
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

bool qihse_cpu_test_avx_vnni(void) {
#if defined(__AVXVNNI__) || (defined(QIHSE_ENABLE_AVX_VNNI) && QIHSE_ENABLE_AVX_VNNI)
    __asm__ volatile (
        "vpdpbusd %%ymm1, %%ymm0, %%ymm0\n"
        : : : "ymm0", "ymm1"
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

bool qihse_cpu_test_pclmul(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile (
        "pxor %%xmm0, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm1\n\t"
        "pclmulqdq $0x00, %%xmm1, %%xmm0\n\t"
        : : : "xmm0", "xmm1"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_popcnt(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    uint32_t val = 0x12345678U;
    uint32_t cnt = 0;
    __asm__ volatile (
        "popcnt %1, %0\n\t"
        : "=r"(cnt)
        : "r"(val)
    );
    return cnt == 13;
#else
    return false;
#endif
}

bool qihse_cpu_test_aesni(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile (
        "pxor %%xmm0, %%xmm0\n\t"
        "pxor %%xmm1, %%xmm1\n\t"
        "aesenc %%xmm1, %%xmm0\n\t"
        : : : "xmm0", "xmm1"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_f16c(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile (
        "vxorps %%xmm0, %%xmm0, %%xmm0\n\t"
        "vcvtph2ps %%xmm0, %%ymm1\n\t"
        "vcvtps2ph $0, %%ymm1, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0", "ymm1"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_rdrand(void) {
#if defined(__x86_64__) || defined(_M_X64)
    unsigned long val = 0;
    unsigned char ok = 0;
    __asm__ volatile (
        "rdrand %0\n\t"
        "setc %1\n\t"
        : "=r"(val), "=qm"(ok)
        :
        : "cc"
    );
    (void)val;
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_fma(void) {
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile (
        "vxorps %%xmm0, %%xmm0, %%xmm0\n\t"
        "vfmadd213ps %%xmm0, %%xmm0, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0"
    );
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_movbe(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    uint32_t src = 0x12345678, dst = 0;
    __asm__ volatile (
        "movbe %1, %0\n\t"
        : "=r"(dst)
        : "m"(src)
    );
    return dst == 0x78563412;
#else
    return false;
#endif
}

bool qihse_cpu_test_lzcnt(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    uint32_t val = 0x00010000;
    uint32_t cnt = 0;
    __asm__ volatile (
        "lzcnt %1, %0\n\t"
        : "=r"(cnt)
        : "r"(val)
    );
    return cnt == 15;
#else
    return false;
#endif
}

bool qihse_cpu_test_bmi1(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    uint32_t val = 0x00010000;
    uint32_t res = 0;
    __asm__ volatile (
        "tzcnt %1, %0\n\t"
        : "=r"(res)
        : "r"(val)
    );
    return res == 16;
#else
    return false;
#endif
}

bool qihse_cpu_test_bmi2(void) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
    uint32_t val = 0x12345678;
    uint32_t res = 0;
    __asm__ volatile (
        "rorx $4, %1, %0\n\t"
        : "=r"(res)
        : "r"(val)
    );
    return res != 0;
#else
    return false;
#endif
}

#if defined(__x86_64__) || defined(_M_X64)
#ifndef _XBEGIN_STARTED
#define _XBEGIN_STARTED (~0u)
#endif
__attribute__((target("rtm")))
bool qihse_cpu_test_rtm(void) {
    unsigned int status = _xbegin();
    if (status == _XBEGIN_STARTED) {
        _xend();
        return true;
    }
    return false;
}
#else
bool qihse_cpu_test_rtm(void) {
    return false;
}
#endif

bool qihse_cpu_test_rdseed(void) {
#if defined(__x86_64__) || defined(_M_X64)
    unsigned long val = 0;
    unsigned char ok = 0;
    __asm__ volatile (
        "rdseed %0\n\t"
        "setc %1\n\t"
        : "=r"(val), "=qm"(ok)
        :
        : "cc"
    );
    (void)val;
    return true;
#else
    return false;
#endif
}

bool qihse_cpu_test_adx(void) {
#if defined(__x86_64__) || defined(_M_X64)
    unsigned long a = 1, b = 2;
    unsigned char carry = 0;
    __asm__ volatile (
        "clc\n\t"
        "adcx %2, %0\n\t"
        "setc %1\n\t"
        : "+r"(a), "=qm"(carry)
        : "r"(b)
        : "cc"
    );
    (void)carry;
    return a == 3;
#else
    return false;
#endif
}

#if defined(__x86_64__) || defined(_M_X64)

__attribute__((target("sha,sse4.1")))
bool qihse_cpu_test_shani(void) {
    __asm__ volatile (
        "sha256msg1 %%xmm0, %%xmm1\n\t"
        : : : "xmm0", "xmm1"
    );
    return true;
}

__attribute__((target("avx512vpopcntdq,avx512vl")))
bool qihse_cpu_test_avx512vpopcntdq(void) {
    __asm__ volatile (
        "vpopcntq %%xmm0, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0"
    );
    return true;
}

__attribute__((target("vpclmulqdq,avx2")))
bool qihse_cpu_test_vpclmul(void) {
    __asm__ volatile (
        "vpclmulqdq $0x00, %%ymm0, %%ymm0, %%ymm1\n\t"
        "vzeroupper\n\t"
        : : : "ymm0", "ymm1"
    );
    return true;
}

__attribute__((target("vaes,avx2")))
bool qihse_cpu_test_vaes(void) {
    __asm__ volatile (
        "vaesenc %%ymm0, %%ymm0, %%ymm1\n\t"
        "vzeroupper\n\t"
        : : : "ymm0", "ymm1"
    );
    return true;
}

__attribute__((target("avx512bitalg,avx512vl")))
bool qihse_cpu_test_avx512bitalg(void) {
    __asm__ volatile (
        "vpopcntb %%xmm0, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0"
    );
    return true;
}

__attribute__((target("avx512vbmi,avx512vl")))
bool qihse_cpu_test_avx512vbmi(void) {
    __asm__ volatile (
        "vpermb %%xmm0, %%xmm0, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0"
    );
    return true;
}

__attribute__((target("avx512vbmi2,avx512vl")))
bool qihse_cpu_test_avx512vbmi2(void) {
    __asm__ volatile (
        "vpcompressb %%xmm0, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0"
    );
    return true;
}

__attribute__((target("avx512ifma,avx512vl")))
bool qihse_cpu_test_avx512ifma(void) {
    __asm__ volatile (
        "vpmadd52luq %%xmm0, %%xmm0, %%xmm0\n\t"
        "vzeroupper\n\t"
        : : : "xmm0"
    );
    return true;
}

__attribute__((target("gfni")))
bool qihse_cpu_test_gfni(void) {
    __asm__ volatile (
        "gf2p8affineqb $0x00, %%xmm0, %%xmm0\n\t"
        : : : "xmm0"
    );
    return true;
}

__attribute__((target("clzero")))
bool qihse_cpu_test_clzero(void) {
    uint8_t buf[128] __attribute__((aligned(64))) = {0};
    uintptr_t addr = ((uintptr_t)buf + 63) & ~63ULL;
    __asm__ volatile (
        "clzero\n\t"
        :
        : "a"(addr)
        : "memory"
    );
    return true;
}

__attribute__((target("clwb")))
bool qihse_cpu_test_clwb(void) {
    uint8_t buf[64] __attribute__((aligned(64))) = {0};
    __asm__ volatile (
        "clwb %0\n\t"
        :
        : "m"(buf[0])
        : "memory"
    );
    return true;
}

__attribute__((target("rdpid")))
bool qihse_cpu_test_rdpid(void) {
    unsigned long id = 0;
    __asm__ volatile (
        "rdpid %0\n\t"
        : "=r"(id)
    );
    (void)id;
    return true;
}

bool qihse_cpu_test_cx16(void) {
    uint64_t val[2] __attribute__((aligned(16))) = {0, 0};
    uint64_t old_lo = 0, old_hi = 0;
    uint64_t new_lo = 1, new_hi = 1;
    unsigned char ok = 0;
    __asm__ volatile (
        "lock cmpxchg16b %1\n\t"
        "sete %0\n\t"
        : "=qm"(ok), "+m"(*val), "+a"(old_lo), "+d"(old_hi)
        : "b"(new_lo), "c"(new_hi)
        : "cc", "memory"
    );
    return ok && val[0] == 1 && val[1] == 1;
}

#else

bool qihse_cpu_test_shani(void) { return false; }
bool qihse_cpu_test_avx512vpopcntdq(void) { return false; }
bool qihse_cpu_test_vpclmul(void) { return false; }
bool qihse_cpu_test_vaes(void) { return false; }
bool qihse_cpu_test_avx512bitalg(void) { return false; }
bool qihse_cpu_test_avx512vbmi(void) { return false; }
bool qihse_cpu_test_avx512vbmi2(void) { return false; }
bool qihse_cpu_test_avx512ifma(void) { return false; }
bool qihse_cpu_test_gfni(void) { return false; }
bool qihse_cpu_test_clzero(void) { return false; }
bool qihse_cpu_test_clwb(void) { return false; }
bool qihse_cpu_test_rdpid(void) { return false; }
bool qihse_cpu_test_cx16(void) { return false; }

#endif

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

static qihse_cpu_info_t s_cached_cpu_info;
static volatile int s_cached_cpu_info_ready = 0;
static pthread_mutex_t s_cached_cpu_mutex = PTHREAD_MUTEX_INITIALIZER;

qihse_cpu_info_t qihse_cpu_detect(void) {
    if (qihse_force_full_features()) {
        qihse_cpu_info_t info;
        init_cpu_info(&info);
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
                            QIHSE_CPU_FEATURE_AMX_BF16 |
                            QIHSE_CPU_FEATURE_AVX512BF16 |
                            QIHSE_CPU_FEATURE_VNNI |
                            QIHSE_CPU_FEATURE_PCLMUL |
                            QIHSE_CPU_FEATURE_POPCNT |
                            QIHSE_CPU_FEATURE_AESNI |
                            QIHSE_CPU_FEATURE_F16C |
                            QIHSE_CPU_FEATURE_RDRAND |
                            QIHSE_CPU_FEATURE_FSGSBASE |
                            QIHSE_CPU_FEATURE_ERMS |
                            QIHSE_CPU_FEATURE_FMA |
                            QIHSE_CPU_FEATURE_MOVBE |
                            QIHSE_CPU_FEATURE_LZCNT |
                            QIHSE_CPU_FEATURE_BMI1 |
                            QIHSE_CPU_FEATURE_BMI2 |
                            QIHSE_CPU_FEATURE_RTM |
                            QIHSE_CPU_FEATURE_RDSEED |
                            QIHSE_CPU_FEATURE_ADX |
                            QIHSE_CPU_FEATURE_SHANI |
                            QIHSE_CPU_FEATURE_AVX512VPOPCNTDQ |
                            QIHSE_CPU_FEATURE_VPCLMUL |
                            QIHSE_CPU_FEATURE_VAES |
                            QIHSE_CPU_FEATURE_AVX512BITALG |
                            QIHSE_CPU_FEATURE_AVX512VBMI |
                            QIHSE_CPU_FEATURE_AVX512VBMI2 |
                            QIHSE_CPU_FEATURE_AVX512IFMA |
                            QIHSE_CPU_FEATURE_GFNI |
                            QIHSE_CPU_FEATURE_CLZERO |
                            QIHSE_CPU_FEATURE_CLWB |
                            QIHSE_CPU_FEATURE_RDPID |
                            QIHSE_CPU_FEATURE_CX16;
        info.has_osxsave = true;
        info.has_avx_support = true;
        info.has_avx512_support = true;
        info.features = features;
        return info;
    }

    if (s_cached_cpu_info_ready) {
        return s_cached_cpu_info;
    }
    pthread_mutex_lock(&s_cached_cpu_mutex);
    if (s_cached_cpu_info_ready) {
        pthread_mutex_unlock(&s_cached_cpu_mutex);
        return s_cached_cpu_info;
    }

    qihse_cpu_info_t info;
    init_cpu_info(&info);

#if defined(_WIN32) || defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    uint64_t features = QIHSE_CPU_FEATURE_NONE;
    int cpuInfo[4] = {0};

    qihse_raw_cpuid(cpuInfo, 0, 0);
    int max_leaf = cpuInfo[0];

    if (max_leaf >= 1) {
        qihse_raw_cpuid(cpuInfo, 1, 0);
        if (cpuInfo[3] & (1 << 25)) features |= QIHSE_CPU_FEATURE_SSE;
        if (cpuInfo[3] & (1 << 26)) features |= QIHSE_CPU_FEATURE_SSE2;
        if (cpuInfo[2] & (1 << 0))  features |= QIHSE_CPU_FEATURE_SSE3;
        if (cpuInfo[2] & (1 << 9))  features |= QIHSE_CPU_FEATURE_SSSE3;
        if (cpuInfo[2] & (1 << 19)) features |= QIHSE_CPU_FEATURE_SSE4_1;
        if (cpuInfo[2] & (1 << 20)) features |= QIHSE_CPU_FEATURE_SSE4_2;

        /* Ivy Bridge / Sandy Bridge crypto, bit manipulation, and FP16 */
        if (cpuInfo[2] & (1 << 1))  features |= QIHSE_CPU_FEATURE_PCLMUL;
        if (cpuInfo[2] & (1 << 22)) features |= QIHSE_CPU_FEATURE_MOVBE;
        if (cpuInfo[2] & (1 << 23)) features |= QIHSE_CPU_FEATURE_POPCNT;
        if (cpuInfo[2] & (1 << 25)) features |= QIHSE_CPU_FEATURE_AESNI;
        if (cpuInfo[2] & (1 << 29)) features |= QIHSE_CPU_FEATURE_F16C;
        if (cpuInfo[2] & (1 << 30)) features |= QIHSE_CPU_FEATURE_RDRAND;
        if (cpuInfo[2] & (1 << 13)) {
            if (safe_execute_test(qihse_cpu_test_cx16)) {
                features |= QIHSE_CPU_FEATURE_CX16;
            }
        }

        bool osxsave = (cpuInfo[2] & (1 << 27)) != 0;
        bool cpu_avx = (cpuInfo[2] & (1 << 28)) != 0;
        bool cpu_fma = (cpuInfo[2] & (1 << 12)) != 0;
        info.has_osxsave = osxsave;

        if (osxsave) {
            uint64_t xcr0 = 0;
#ifdef _WIN32
            xcr0 = _xgetbv(0);
#else
            xcr0 = qihse_xgetbv(0);
#endif
            /* Check if XMM (bit 1) and YMM (bit 2) are enabled by OS */
            if ((xcr0 & 0x6) == 0x6) {
                if (cpu_avx) {
                    info.has_avx_support = true;
                    features |= QIHSE_CPU_FEATURE_AVX;
                }
                if (cpu_fma) {
                    features |= QIHSE_CPU_FEATURE_FMA;
                }

                if (max_leaf >= 7) {
                    qihse_raw_cpuid(cpuInfo, 7, 0);
                    if (cpuInfo[1] & (1 << 5)) {
                        features |= QIHSE_CPU_FEATURE_AVX2;
                    }

                    if (info.has_avx_support) {
                        if (cpuInfo[2] & (1 << 9)) {
                            if (safe_execute_test(qihse_cpu_test_vaes)) {
                                features |= QIHSE_CPU_FEATURE_VAES;
                            }
                        }
                        if (cpuInfo[2] & (1 << 10)) {
                            if (safe_execute_test(qihse_cpu_test_vpclmul)) {
                                features |= QIHSE_CPU_FEATURE_VPCLMUL;
                            }
                        }
                    }

                    /* Check AVX512: Foundation (EBX bit 16), OS support for ZMM (bits 5, 6, 7) */
                    bool cpu_avx512 = (cpuInfo[1] & (1 << 16)) != 0;
                    bool os_avx512 = (xcr0 & 0xe6) == 0xe6;
                    const char* avx512_env = getenv("QIHSE_ENABLE_AVX512");
                    bool avx512_allowed = !avx512_env || avx512_env[0] != '0';

                    if (cpu_avx512 && os_avx512 && avx512_allowed) {
                        info.has_avx512_support = true;
                        features |= QIHSE_CPU_FEATURE_AVX512F;
                        if (cpuInfo[1] & (1 << 30)) features |= QIHSE_CPU_FEATURE_AVX512BW;
                        if (cpuInfo[1] & (1 << 17)) features |= QIHSE_CPU_FEATURE_AVX512DQ;
                        if ((unsigned int)cpuInfo[1] & (1u << 31)) features |= QIHSE_CPU_FEATURE_AVX512VL;
                        if (cpuInfo[2] & (1 << 11)) features |= QIHSE_CPU_FEATURE_AVX512VNNI;
                        if (cpuInfo[1] & (1 << 21)) {
                            if (safe_execute_test(qihse_cpu_test_avx512ifma)) {
                                features |= QIHSE_CPU_FEATURE_AVX512IFMA;
                            }
                        }
                        if (cpuInfo[2] & (1 << 1)) {
                            if (safe_execute_test(qihse_cpu_test_avx512vbmi)) {
                                features |= QIHSE_CPU_FEATURE_AVX512VBMI;
                            }
                        }
                        if (cpuInfo[2] & (1 << 6)) {
                            if (safe_execute_test(qihse_cpu_test_avx512vbmi2)) {
                                features |= QIHSE_CPU_FEATURE_AVX512VBMI2;
                            }
                        }
                        if (cpuInfo[2] & (1 << 12)) {
                            if (safe_execute_test(qihse_cpu_test_avx512bitalg)) {
                                features |= QIHSE_CPU_FEATURE_AVX512BITALG;
                            }
                        }
                        if (cpuInfo[2] & (1 << 14)) {
                            if (safe_execute_test(qihse_cpu_test_avx512vpopcntdq)) {
                                features |= QIHSE_CPU_FEATURE_AVX512VPOPCNTDQ;
                            }
                        }
                    }

                    /* AMX features: leaf 7 sub-leaf 0, EDX bits 22/24/25 */
                    const char* amx_env = getenv("QIHSE_ENABLE_AMX");
                    bool amx_allowed = !amx_env || amx_env[0] != '0';
                    if (amx_allowed) {
                        if (cpuInfo[3] & (1 << 24)) {
                            features |= QIHSE_CPU_FEATURE_AMX;
                            features |= QIHSE_CPU_FEATURE_AMX_TILE;
                        }
                        if (cpuInfo[3] & (1 << 25)) features |= QIHSE_CPU_FEATURE_AMX_INT8;
                        if (cpuInfo[3] & (1 << 22)) features |= QIHSE_CPU_FEATURE_AMX_BF16;
                    }

                    if (cpuInfo[2] & (1 << 11)) {
                        features |= QIHSE_CPU_FEATURE_VNNI;
                    }

                    /* Leaf 7 sub-leaf 1: AVX-VNNI (EAX bit 4) and AVX-512 BF16 (EAX bit 5) */
                    qihse_raw_cpuid(cpuInfo, 7, 1);
                    const char* avx_vnni_env = getenv("QIHSE_ENABLE_AVX_VNNI");
                    bool avx_vnni_allowed = !avx_vnni_env || avx_vnni_env[0] != '0';
                    if (avx_vnni_allowed && (cpuInfo[0] & (1 << 4))) {
                        features |= QIHSE_CPU_FEATURE_AVX_VNNI;
                    }
                    if (avx512_allowed && os_avx512 && (cpuInfo[0] & (1 << 5))) {
                        features |= QIHSE_CPU_FEATURE_AVX512BF16;
                    }
                }
            }
        }

        /* Leaf 0x80000001: ECX[5] for LZCNT (ABM) */
        qihse_raw_cpuid(cpuInfo, (int)0x80000000, 0);
        uint32_t max_ext_leaf = (uint32_t)cpuInfo[0];
        if (max_ext_leaf >= 0x80000001) {
            qihse_raw_cpuid(cpuInfo, (int)0x80000001, 0);
            if (cpuInfo[2] & (1 << 5)) {
                features |= QIHSE_CPU_FEATURE_LZCNT;
            }
        }

        /* Leaf 7 Subleaf 0: non-vector features probed independently of AVX / OSXSAVE */
        if (max_leaf >= 7) {
            qihse_raw_cpuid(cpuInfo, 7, 0);
            if (cpuInfo[1] & (1 << 0))  features |= QIHSE_CPU_FEATURE_FSGSBASE;
            if (cpuInfo[1] & (1 << 3))  features |= QIHSE_CPU_FEATURE_BMI1;
            if (cpuInfo[1] & (1 << 8))  features |= QIHSE_CPU_FEATURE_BMI2;
            if (cpuInfo[1] & (1 << 9))  features |= QIHSE_CPU_FEATURE_ERMS;
            if (cpuInfo[1] & (1 << 18)) features |= QIHSE_CPU_FEATURE_RDSEED;
            if (cpuInfo[1] & (1 << 19)) features |= QIHSE_CPU_FEATURE_ADX;
            if (cpuInfo[1] & (1 << 24)) {
                if (safe_execute_test(qihse_cpu_test_clwb)) {
                    features |= QIHSE_CPU_FEATURE_CLWB;
                }
            }
            if (cpuInfo[1] & (1 << 29)) {
                if (safe_execute_test(qihse_cpu_test_shani)) {
                    features |= QIHSE_CPU_FEATURE_SHANI;
                }
            }
            if (cpuInfo[2] & (1 << 8)) {
                if (safe_execute_test(qihse_cpu_test_gfni)) {
                    features |= QIHSE_CPU_FEATURE_GFNI;
                }
            }
            if (cpuInfo[2] & (1 << 22)) {
                if (safe_execute_test(qihse_cpu_test_rdpid)) {
                    features |= QIHSE_CPU_FEATURE_RDPID;
                }
            }
            if (cpuInfo[1] & (1 << 11)) {
                if (safe_execute_test(qihse_cpu_test_rtm)) {
                    features |= QIHSE_CPU_FEATURE_RTM;
                }
            }
        }

        /* Extended Leaf 0x80000008: CLZERO in EBX bit 0 */
        if (max_ext_leaf >= 0x80000008) {
            qihse_raw_cpuid(cpuInfo, (int)0x80000008, 0);
            if (cpuInfo[1] & (1 << 0)) {
                if (safe_execute_test(qihse_cpu_test_clzero)) {
                    features |= QIHSE_CPU_FEATURE_CLZERO;
                }
            }
        }
    }

    info.features = features;
#else
    /* Fallback for non-x86 architectures */
    uint64_t features = QIHSE_CPU_FEATURE_NONE;
    if (safe_execute_test(qihse_cpu_test_sse)) features |= QIHSE_CPU_FEATURE_SSE;
    if (safe_execute_test(qihse_cpu_test_sse2)) features |= QIHSE_CPU_FEATURE_SSE2;
    info.features = features;
#endif
    s_cached_cpu_info = info;
    s_cached_cpu_info_ready = 1;
    pthread_mutex_unlock(&s_cached_cpu_mutex);
    return info;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

bool qihse_cpu_has_feature(const qihse_cpu_info_t* info, qihse_cpu_feature_t feature) {
    return info && (info->features & feature) != 0;
}

const char* qihse_cpu_feature_name(qihse_cpu_feature_t feature) {
    switch (feature) {
        case QIHSE_CPU_FEATURE_SSE: return "SSE";
        case QIHSE_CPU_FEATURE_SSE2: return "SSE2";
        case QIHSE_CPU_FEATURE_SSE3: return "SSE3";
        case QIHSE_CPU_FEATURE_SSSE3: return "SSSE3";
        case QIHSE_CPU_FEATURE_SSE4_1: return "SSE4.1";
        case QIHSE_CPU_FEATURE_SSE4_2: return "SSE4.2";
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
        case QIHSE_CPU_FEATURE_AVX512BF16: return "AVX-512BF16";
        case QIHSE_CPU_FEATURE_PCLMUL: return "PCLMULQDQ";
        case QIHSE_CPU_FEATURE_POPCNT: return "POPCNT";
        case QIHSE_CPU_FEATURE_AESNI: return "AES-NI";
        case QIHSE_CPU_FEATURE_F16C: return "F16C";
        case QIHSE_CPU_FEATURE_RDRAND: return "RDRAND";
        case QIHSE_CPU_FEATURE_FSGSBASE: return "FSGSBASE";
        case QIHSE_CPU_FEATURE_ERMS: return "ERMS";
        case QIHSE_CPU_FEATURE_FMA: return "FMA";
        case QIHSE_CPU_FEATURE_MOVBE: return "MOVBE";
        case QIHSE_CPU_FEATURE_LZCNT: return "LZCNT";
        case QIHSE_CPU_FEATURE_BMI1: return "BMI1";
        case QIHSE_CPU_FEATURE_BMI2: return "BMI2";
        case QIHSE_CPU_FEATURE_RTM: return "RTM";
        case QIHSE_CPU_FEATURE_RDSEED: return "RDSEED";
        case QIHSE_CPU_FEATURE_ADX: return "ADX";
        case QIHSE_CPU_FEATURE_SHANI: return "SHA-NI";
        case QIHSE_CPU_FEATURE_AVX512VPOPCNTDQ: return "AVX-512 VPOPCNTDQ";
        case QIHSE_CPU_FEATURE_VPCLMUL: return "VPCLMULQDQ";
        case QIHSE_CPU_FEATURE_VAES: return "VAES";
        case QIHSE_CPU_FEATURE_AVX512BITALG: return "AVX-512 BITALG";
        case QIHSE_CPU_FEATURE_AVX512VBMI: return "AVX-512 VBMI";
        case QIHSE_CPU_FEATURE_AVX512VBMI2: return "AVX-512 VBMI2";
        case QIHSE_CPU_FEATURE_AVX512IFMA: return "AVX-512 IFMA";
        case QIHSE_CPU_FEATURE_GFNI: return "GFNI";
        case QIHSE_CPU_FEATURE_CLZERO: return "CLZERO";
        case QIHSE_CPU_FEATURE_CLWB: return "CLWB";
        case QIHSE_CPU_FEATURE_RDPID: return "RDPID";
        case QIHSE_CPU_FEATURE_CX16: return "CX16";
        default: return "UNKNOWN";
    }
}

const char* qihse_cpu_feature_description(qihse_cpu_feature_t feature) {
    switch (feature) {
        case QIHSE_CPU_FEATURE_SSE: return "Streaming SIMD Extensions";
        case QIHSE_CPU_FEATURE_SSE2: return "Streaming SIMD Extensions 2";
        case QIHSE_CPU_FEATURE_SSE3: return "Streaming SIMD Extensions 3";
        case QIHSE_CPU_FEATURE_SSSE3: return "Supplemental Streaming SIMD Extensions 3";
        case QIHSE_CPU_FEATURE_SSE4_1: return "Streaming SIMD Extensions 4.1";
        case QIHSE_CPU_FEATURE_SSE4_2: return "Streaming SIMD Extensions 4.2";
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
        case QIHSE_CPU_FEATURE_AVX512BF16: return "AVX-512 BFloat16 (dpbf16ps)";
        case QIHSE_CPU_FEATURE_PCLMUL: return "Carry-Less Multiplication (PCLMULQDQ)";
        case QIHSE_CPU_FEATURE_POPCNT: return "Hardware Population Count (POPCNT)";
        case QIHSE_CPU_FEATURE_AESNI: return "Advanced Encryption Standard New Instructions (AES-NI)";
        case QIHSE_CPU_FEATURE_F16C: return "16-bit Floating-Point Conversion Instructions (F16C)";
        case QIHSE_CPU_FEATURE_RDRAND: return "Digital Random Number Generator (RDRAND)";
        case QIHSE_CPU_FEATURE_FSGSBASE: return "User-space FS/GS Base Access (FSGSBASE)";
        case QIHSE_CPU_FEATURE_ERMS: return "Enhanced REP MOVSB/STOSB (ERMS)";
        case QIHSE_CPU_FEATURE_FMA: return "Fused Multiply-Add (FMA3)";
        case QIHSE_CPU_FEATURE_MOVBE: return "Move Data After Swapping Bytes (MOVBE)";
        case QIHSE_CPU_FEATURE_LZCNT: return "Count the Number of Leading Zero Bits (LZCNT/ABM)";
        case QIHSE_CPU_FEATURE_BMI1: return "Bit Manipulation Instruction Set 1 (BMI1)";
        case QIHSE_CPU_FEATURE_BMI2: return "Bit Manipulation Instruction Set 2 (BMI2)";
        case QIHSE_CPU_FEATURE_RTM: return "Restricted Transactional Memory (TSX-RTM)";
        case QIHSE_CPU_FEATURE_RDSEED: return "Random Seed Generator (RDSEED)";
        case QIHSE_CPU_FEATURE_ADX: return "Multi-Precision Add-Carry Instruction Extensions (ADX)";
        case QIHSE_CPU_FEATURE_SHANI: return "Secure Hash Algorithm New Instructions (SHA-NI)";
        case QIHSE_CPU_FEATURE_AVX512VPOPCNTDQ: return "AVX-512 Vector Population Count (Double/Quadword)";
        case QIHSE_CPU_FEATURE_VPCLMUL: return "Vector Carry-Less Multiplication (VPCLMULQDQ)";
        case QIHSE_CPU_FEATURE_VAES: return "Vector AES Instructions (VAES)";
        case QIHSE_CPU_FEATURE_AVX512BITALG: return "AVX-512 Bit Algorithms (BITALG)";
        case QIHSE_CPU_FEATURE_AVX512VBMI: return "AVX-512 Vector Byte Manipulation Instructions (VBMI)";
        case QIHSE_CPU_FEATURE_AVX512VBMI2: return "AVX-512 Vector Byte Manipulation Instructions 2 (VBMI2)";
        case QIHSE_CPU_FEATURE_AVX512IFMA: return "AVX-512 Integer Fused Multiply-Add (IFMA)";
        case QIHSE_CPU_FEATURE_GFNI: return "Galois Field New Instructions (GFNI)";
        case QIHSE_CPU_FEATURE_CLZERO: return "Zero Cache Line Instruction (CLZERO)";
        case QIHSE_CPU_FEATURE_CLWB: return "Cache Line Write Back (CLWB)";
        case QIHSE_CPU_FEATURE_RDPID: return "Read Processor ID (RDPID)";
        case QIHSE_CPU_FEATURE_CX16: return "CMPXCHG16B 16-byte Atomic Compare-and-Swap";
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
