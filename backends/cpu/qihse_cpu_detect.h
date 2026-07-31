/*
 * QIHSE - CPU Feature Detection via Execution Testing
 *
 * Runtime detection of SIMD capabilities through actual instruction execution,
 * not CPUID. Uses signal handling to safely test unsupported instructions.
 *
 * Version: 1.0.0
 * Author: DSMIL System
 * License: MIT
 */

#ifndef QIHSE_CPU_DETECT_H
#define QIHSE_CPU_DETECT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CPU SIMD FEATURE FLAGS
 * ============================================================================ */

/**
 * CPU SIMD capability flags.
 * Each flag represents a tested and verified SIMD feature.
 */
typedef enum qihse_cpu_feature_e {
    QIHSE_CPU_FEATURE_NONE      = 0,
    QIHSE_CPU_FEATURE_SSE       = (1 << 0),  /* SSE instruction set */
    QIHSE_CPU_FEATURE_SSE2      = (1 << 1),  /* SSE2 instruction set */
    QIHSE_CPU_FEATURE_SSE3      = (1 << 2),  /* SSE3 instruction set */
    QIHSE_CPU_FEATURE_SSSE3     = (1 << 3),  /* SSSE3 instruction set */
    QIHSE_CPU_FEATURE_SSE4_1    = (1 << 4),  /* SSE4.1 instruction set */
    QIHSE_CPU_FEATURE_SSE4_2    = (1 << 5),  /* SSE4.2 instruction set */
    QIHSE_CPU_FEATURE_AVX       = (1 << 6),  /* AVX instruction set */
    QIHSE_CPU_FEATURE_AVX2      = (1 << 7),  /* AVX2 instruction set */
    QIHSE_CPU_FEATURE_AVX512F   = (1 << 8),  /* AVX-512 Foundation */
    QIHSE_CPU_FEATURE_AVX512BW  = (1 << 9),  /* AVX-512 Byte/Word */
    QIHSE_CPU_FEATURE_AVX512DQ  = (1 << 10), /* AVX-512 Doubleword/Quadword */
    QIHSE_CPU_FEATURE_AVX512VL  = (1 << 11), /* AVX-512 Vector Length */
    QIHSE_CPU_FEATURE_AMX       = (1 << 12), /* Advanced Matrix Extensions */
    QIHSE_CPU_FEATURE_AMX_TILE  = (1 << 13), /* AMX Tile operations */
    QIHSE_CPU_FEATURE_AMX_INT8  = (1 << 14), /* AMX INT8 operations */
    QIHSE_CPU_FEATURE_VNNI       = (1 << 15), /* AVX-512 VNNI (512-bit) */
    QIHSE_CPU_FEATURE_AVX512VNNI = (1 << 16), /* AVX-512 VNNI (alias) */
    QIHSE_CPU_FEATURE_AVX_VNNI   = (1 << 17), /* AVX-VNNI: VEX vpdpbusd, no AVX-512 needed */
    QIHSE_CPU_FEATURE_AMX_BF16   = (1 << 18), /* AMX BFloat16 tile multiply */
    QIHSE_CPU_FEATURE_AVX512BF16 = (1 << 19)  /* AVX-512 BFloat16 (dpbf16ps) */
} qihse_cpu_feature_t;

/* ============================================================================
 * BUILD-TIME ISA GUARD MACROS
 * ============================================================================
 * These are set by the Makefile (-DQIHSE_ENABLE_xxx=1) and map directly onto
 * compiler intrinsic availability.  Use these in source files to gate code
 * that requires a specific ISA extension, e.g.:
 *
 *   #if QIHSE_HAS_AVX2
 *   ... __m256 code ...
 *   #endif
 *
 * The QIHSE_HAS_* forms normalise the Makefile flag with the compiler's own
 * predefined macros, so the guard works even when the Makefile flag was not
 * passed (e.g. direct compilation outside Make).
 * ============================================================================ */

#if defined(QIHSE_ENABLE_AVX2) && QIHSE_ENABLE_AVX2
#  define QIHSE_HAS_AVX2      1
#elif defined(__AVX2__)
#  define QIHSE_HAS_AVX2      1
#else
#  define QIHSE_HAS_AVX2      0
#endif

#if defined(QIHSE_ENABLE_AVX512) && QIHSE_ENABLE_AVX512
#  define QIHSE_HAS_AVX512    1
#elif defined(__AVX512F__)
#  define QIHSE_HAS_AVX512    1
#else
#  define QIHSE_HAS_AVX512    0
#endif

/* AVX-VNNI: VEX-encoded vpdpbusd/vpdpwssd (Alder Lake+, Zen4+).
 * Distinct from AVX-512 VNNI — works in 256-bit mode without AVX-512. */
#if defined(QIHSE_ENABLE_AVX_VNNI) && QIHSE_ENABLE_AVX_VNNI
#  define QIHSE_HAS_AVX_VNNI  1
#elif defined(__AVXVNNI__)
#  define QIHSE_HAS_AVX_VNNI  1
#else
#  define QIHSE_HAS_AVX_VNNI  0
#endif

/* AMX: 2-D tile matrix multiply (Sapphire Rapids+).
 * Requires arch_prctl(ARCH_REQ_XCOMP_PERM, XFEATURE_XTILECFG) at runtime. */
#if defined(QIHSE_ENABLE_AMX) && QIHSE_ENABLE_AMX
#  define QIHSE_HAS_AMX       1
#elif defined(__AMX_TILE__)
#  define QIHSE_HAS_AMX       1
#else
#  define QIHSE_HAS_AMX       0
#endif

/* ============================================================================
 * CPU DETECTION RESULTS
 * ============================================================================ */

/**
 * CPU detection results structure.
 */
typedef struct qihse_cpu_info_s {
    uint64_t features;              /* Bitmask of available features */
    char vendor[13];                /* CPU vendor string (null-terminated) */
    char brand[49];                 /* CPU brand string (null-terminated) */
    int family;                     /* CPU family */
    int model;                      /* CPU model */
    int stepping;                   /* CPU stepping */
    bool has_osxsave;               /* OSXSAVE support (required for AVX/AVX512) */
    bool has_avx_support;           /* AVX OS support */
    bool has_avx512_support;        /* AVX-512 OS support */
} qihse_cpu_info_t;

/* ============================================================================
 * CPU FEATURE DETECTION API
 * ============================================================================ */

/**
 * Detect CPU SIMD capabilities through execution testing.
 *
 * This function actually executes SIMD instructions to verify they work,
 * rather than relying on CPUID which may report unsupported features.
 *
 * @return CPU information with verified feature support
 */
qihse_cpu_info_t qihse_cpu_detect(void);

/**
 * Get CPU feature bitmask for fast feature checking.
 *
 * @return Bitmask of supported CPU features
 */
qihse_cpu_feature_t qihse_cpu_detect_features(void);

/**
 * Check if a specific CPU feature is supported.
 *
 * @param info CPU information structure
 * @param feature Feature to check
 * @return true if feature is supported and tested, false otherwise
 */
bool qihse_cpu_has_feature(const qihse_cpu_info_t* info, qihse_cpu_feature_t feature);

/**
 * Get human-readable feature name.
 *
 * @param feature CPU feature
 * @return Feature name string
 */
const char* qihse_cpu_feature_name(qihse_cpu_feature_t feature);

/**
 * Get feature description.
 *
 * @param feature CPU feature
 * @return Feature description string
 */
const char* qihse_cpu_feature_description(qihse_cpu_feature_t feature);

/* ============================================================================
 * INDIVIDUAL FEATURE TESTS
 * ============================================================================ */

/**
 * Test SSE instruction execution.
 *
 * @return true if SSE instructions execute successfully
 */
bool qihse_cpu_test_sse(void);

/**
 * Test SSE2 instruction execution.
 *
 * @return true if SSE2 instructions execute successfully
 */
bool qihse_cpu_test_sse2(void);

/**
 * Test AVX instruction execution.
 *
 * @return true if AVX instructions execute successfully
 */
bool qihse_cpu_test_avx(void);

/**
 * Test AVX2 instruction execution.
 *
 * @return true if AVX2 instructions execute successfully
 */
bool qihse_cpu_test_avx2(void);

/**
 * Test AVX-512 Foundation instruction execution.
 *
 * @return true if AVX-512F instructions execute successfully
 */
bool qihse_cpu_test_avx512f(void);

/**
 * Test AVX-512 Byte/Word instruction execution.
 *
 * @return true if AVX-512BW instructions execute successfully
 */
bool qihse_cpu_test_avx512bw(void);

/**
 * Test AVX-512 Doubleword/Quadword instruction execution.
 *
 * @return true if AVX-512DQ instructions execute successfully
 */
bool qihse_cpu_test_avx512dq(void);

/**
 * Test AVX-512 Vector Length instruction execution.
 *
 * @return true if AVX-512VL instructions execute successfully
 */
bool qihse_cpu_test_avx512vl(void);

bool qihse_cpu_test_amx(void);

/**
 * Test AMX instruction execution.
 *
 * @return true if AMX instructions execute successfully
 */

/**
 * Test VNNI instruction execution.
 *
 * @return true if VNNI instructions execute successfully
 */
bool qihse_cpu_test_vnni(void);

/**
 * Test AVX-512 VNNI instruction execution.
 *
 * @return true if AVX-512 VNNI instructions execute successfully
 */
bool qihse_cpu_test_avx512vnni(void);

/* ============================================================================
 * CPU OPTIMIZATION HINTS
 * ============================================================================ */

/**
 * Get optimal SIMD vector width for current CPU.
 *
 * @param info CPU information
 * @return Optimal vector width in bytes (16=SSE, 32=AVX, 64=AVX512)
 */
int qihse_cpu_optimal_vector_width(const qihse_cpu_info_t* info);

/**
 * Check if CPU supports efficient gather operations.
 *
 * @param info CPU information
 * @return true if gather operations are efficient
 */
bool qihse_cpu_supports_efficient_gather(const qihse_cpu_info_t* info);

/**
 * Get L1 cache line size for optimal alignment.
 *
 * @return Cache line size in bytes
 */
int qihse_cpu_cache_line_size(void);

/**
 * Get L2 cache size for algorithm tuning.
 *
 * @return L2 cache size in bytes, or 0 if unknown
 */
size_t qihse_cpu_l2_cache_size(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_CPU_DETECT_H */
