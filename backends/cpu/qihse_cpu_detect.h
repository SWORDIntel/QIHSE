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
typedef uint64_t qihse_cpu_feature_t;

#define QIHSE_CPU_FEATURE_NONE          0ULL
#define QIHSE_CPU_FEATURE_SSE           (1ULL << 0)  /* SSE instruction set */
#define QIHSE_CPU_FEATURE_SSE2          (1ULL << 1)  /* SSE2 instruction set */
#define QIHSE_CPU_FEATURE_SSE3          (1ULL << 2)  /* SSE3 instruction set */
#define QIHSE_CPU_FEATURE_SSSE3         (1ULL << 3)  /* SSSE3 instruction set */
#define QIHSE_CPU_FEATURE_SSE4_1        (1ULL << 4)  /* SSE4.1 instruction set */
#define QIHSE_CPU_FEATURE_SSE4_2        (1ULL << 5)  /* SSE4.2 instruction set */
#define QIHSE_CPU_FEATURE_AVX           (1ULL << 6)  /* AVX instruction set */
#define QIHSE_CPU_FEATURE_AVX2          (1ULL << 7)  /* AVX2 instruction set */
#define QIHSE_CPU_FEATURE_AVX512F       (1ULL << 8)  /* AVX-512 Foundation */
#define QIHSE_CPU_FEATURE_AVX512BW      (1ULL << 9)  /* AVX-512 Byte/Word */
#define QIHSE_CPU_FEATURE_AVX512DQ      (1ULL << 10) /* AVX-512 Doubleword/Quadword */
#define QIHSE_CPU_FEATURE_AVX512VL      (1ULL << 11) /* AVX-512 Vector Length */
#define QIHSE_CPU_FEATURE_AMX           (1ULL << 12) /* Advanced Matrix Extensions */
#define QIHSE_CPU_FEATURE_AMX_TILE      (1ULL << 13) /* AMX Tile operations */
#define QIHSE_CPU_FEATURE_AMX_INT8      (1ULL << 14) /* AMX INT8 operations */
#define QIHSE_CPU_FEATURE_VNNI          (1ULL << 15) /* AVX-512 VNNI (512-bit) */
#define QIHSE_CPU_FEATURE_AVX512VNNI    (1ULL << 16) /* AVX-512 VNNI (alias) */
#define QIHSE_CPU_FEATURE_AVX_VNNI      (1ULL << 17) /* AVX-VNNI: VEX vpdpbusd, no AVX-512 needed */
#define QIHSE_CPU_FEATURE_AMX_BF16      (1ULL << 18) /* AMX BFloat16 tile multiply */
#define QIHSE_CPU_FEATURE_AVX512BF16    (1ULL << 19) /* AVX-512 BFloat16 (dpbf16ps) */
#define QIHSE_CPU_FEATURE_PCLMUL        (1ULL << 20) /* PCLMULQDQ carryless multiply */
#define QIHSE_CPU_FEATURE_POPCNT        (1ULL << 21) /* POPCNT population count */
#define QIHSE_CPU_FEATURE_AESNI         (1ULL << 22) /* AES-NI dedicated round instructions */
#define QIHSE_CPU_FEATURE_F16C          (1ULL << 23) /* F16C half-precision float conversions */
#define QIHSE_CPU_FEATURE_RDRAND        (1ULL << 24) /* RDRAND hardware random number generator */
#define QIHSE_CPU_FEATURE_FSGSBASE      (1ULL << 25) /* FSGSBASE user-space base register access */
#define QIHSE_CPU_FEATURE_ERMS          (1ULL << 26) /* ERMS Enhanced REP MOVSB/STOSB */
#define QIHSE_CPU_FEATURE_FMA           (1ULL << 27) /* FMA fused multiply-add */
#define QIHSE_CPU_FEATURE_MOVBE         (1ULL << 28) /* MOVBE move data after swapping bytes */
#define QIHSE_CPU_FEATURE_LZCNT         (1ULL << 29) /* LZCNT leading zero count */
#define QIHSE_CPU_FEATURE_BMI1          (1ULL << 30) /* BMI1 bit manipulation instruction set 1 */
#define QIHSE_CPU_FEATURE_BMI2          (1ULL << 31) /* BMI2 bit manipulation instruction set 2 */
#define QIHSE_CPU_FEATURE_RTM           (1ULL << 32) /* RTM restricted transactional memory */
#define QIHSE_CPU_FEATURE_RDSEED        (1ULL << 33) /* RDSEED random seed generator */
#define QIHSE_CPU_FEATURE_ADX           (1ULL << 34) /* ADX multi-precision add-carry extensions */

/* ============================================================================
 * BUILD-TIME ISA GUARD MACROS
 * ============================================================================
 * These are set by the Makefile (-DQIHSE_ENABLE_xxx=1) and map directly onto
 * compiler intrinsic availability.  Use these in source files to gate code
 * that requires a specific ISA extension, e.g.:
 *
 *   #if QIHSE_HAS_AVX
 *   ... __m256 code ...
 *   #endif
 * ============================================================================ */

#if defined(QIHSE_ENABLE_AVX) && QIHSE_ENABLE_AVX
#  define QIHSE_HAS_AVX       1
#elif defined(__AVX__)
#  define QIHSE_HAS_AVX       1
#else
#  define QIHSE_HAS_AVX       0
#endif

#if defined(QIHSE_ENABLE_F16C) && QIHSE_ENABLE_F16C
#  define QIHSE_HAS_F16C      1
#elif defined(__F16C__)
#  define QIHSE_HAS_F16C      1
#else
#  define QIHSE_HAS_F16C      0
#endif

#if defined(QIHSE_ENABLE_AESNI) && QIHSE_ENABLE_AESNI
#  define QIHSE_HAS_AESNI     1
#elif defined(__AES__)
#  define QIHSE_HAS_AESNI     1
#else
#  define QIHSE_HAS_AESNI     0
#endif

#if defined(QIHSE_ENABLE_PCLMUL) && QIHSE_ENABLE_PCLMUL
#  define QIHSE_HAS_PCLMUL    1
#elif defined(__PCLMUL__)
#  define QIHSE_HAS_PCLMUL    1
#else
#  define QIHSE_HAS_PCLMUL    0
#endif

#if defined(QIHSE_ENABLE_POPCNT) && QIHSE_ENABLE_POPCNT
#  define QIHSE_HAS_POPCNT    1
#elif defined(__POPCNT__)
#  define QIHSE_HAS_POPCNT    1
#else
#  define QIHSE_HAS_POPCNT    0
#endif

#if defined(QIHSE_ENABLE_RDRAND) && QIHSE_ENABLE_RDRAND
#  define QIHSE_HAS_RDRAND    1
#elif defined(__RDRND__)
#  define QIHSE_HAS_RDRAND    1
#else
#  define QIHSE_HAS_RDRAND    0
#endif

#if defined(QIHSE_ENABLE_FSGSBASE) && QIHSE_ENABLE_FSGSBASE
#  define QIHSE_HAS_FSGSBASE  1
#elif defined(__FSGSBASE__)
#  define QIHSE_HAS_FSGSBASE  1
#else
#  define QIHSE_HAS_FSGSBASE  0
#endif

#if defined(QIHSE_ENABLE_ERMS) && QIHSE_ENABLE_ERMS
#  define QIHSE_HAS_ERMS      1
#else
#  define QIHSE_HAS_ERMS      0
#endif

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

#if defined(QIHSE_ENABLE_FMA) && QIHSE_ENABLE_FMA
#  define QIHSE_HAS_FMA       1
#elif defined(__FMA__)
#  define QIHSE_HAS_FMA       1
#else
#  define QIHSE_HAS_FMA       0
#endif

#if defined(QIHSE_ENABLE_MOVBE) && QIHSE_ENABLE_MOVBE
#  define QIHSE_HAS_MOVBE     1
#elif defined(__MOVBE__)
#  define QIHSE_HAS_MOVBE     1
#else
#  define QIHSE_HAS_MOVBE     0
#endif

#if defined(QIHSE_ENABLE_LZCNT) && QIHSE_ENABLE_LZCNT
#  define QIHSE_HAS_LZCNT     1
#elif defined(__LZCNT__)
#  define QIHSE_HAS_LZCNT     1
#else
#  define QIHSE_HAS_LZCNT     0
#endif

#if defined(QIHSE_ENABLE_BMI1) && QIHSE_ENABLE_BMI1
#  define QIHSE_HAS_BMI1      1
#elif defined(__BMI__)
#  define QIHSE_HAS_BMI1      1
#else
#  define QIHSE_HAS_BMI1      0
#endif

#if defined(QIHSE_ENABLE_BMI2) && QIHSE_ENABLE_BMI2
#  define QIHSE_HAS_BMI2      1
#elif defined(__BMI2__)
#  define QIHSE_HAS_BMI2      1
#else
#  define QIHSE_HAS_BMI2      0
#endif

#if defined(QIHSE_ENABLE_RTM) && QIHSE_ENABLE_RTM
#  define QIHSE_HAS_RTM       1
#elif defined(__RTM__)
#  define QIHSE_HAS_RTM       1
#else
#  define QIHSE_HAS_RTM       0
#endif

#if defined(QIHSE_ENABLE_RDSEED) && QIHSE_ENABLE_RDSEED
#  define QIHSE_HAS_RDSEED    1
#elif defined(__RDSEED__)
#  define QIHSE_HAS_RDSEED    1
#else
#  define QIHSE_HAS_RDSEED    0
#endif

#if defined(QIHSE_ENABLE_ADX) && QIHSE_ENABLE_ADX
#  define QIHSE_HAS_ADX       1
#elif defined(__ADX__)
#  define QIHSE_HAS_ADX       1
#else
#  define QIHSE_HAS_ADX       0
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

/**
 * Test PCLMULQDQ instruction execution.
 * @return true if PCLMULQDQ instructions execute successfully
 */
bool qihse_cpu_test_pclmul(void);

/**
 * Test POPCNT instruction execution.
 * @return true if POPCNT instructions execute successfully
 */
bool qihse_cpu_test_popcnt(void);

/**
 * Test AES-NI instruction execution.
 * @return true if AES-NI instructions execute successfully
 */
bool qihse_cpu_test_aesni(void);

/**
 * Test F16C half-precision float conversion instruction execution.
 * @return true if F16C instructions execute successfully
 */
bool qihse_cpu_test_f16c(void);

/**
 * Test RDRAND hardware random number generator instruction execution.
 * @return true if RDRAND instructions execute successfully
 */
bool qihse_cpu_test_rdrand(void);
bool qihse_cpu_test_fma(void);
bool qihse_cpu_test_movbe(void);
bool qihse_cpu_test_lzcnt(void);
bool qihse_cpu_test_bmi1(void);
bool qihse_cpu_test_bmi2(void);
bool qihse_cpu_test_rtm(void);
bool qihse_cpu_test_rdseed(void);
bool qihse_cpu_test_adx(void);

static inline bool qihse_cpu_has_pclmul(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_PCLMUL);
}
static inline bool qihse_cpu_has_popcnt(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_POPCNT);
}
static inline bool qihse_cpu_has_aesni(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_AESNI);
}
static inline bool qihse_cpu_has_f16c(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_F16C);
}
static inline bool qihse_cpu_has_rdrand(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_RDRAND);
}
static inline bool qihse_cpu_has_fsgsbase(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_FSGSBASE);
}
static inline bool qihse_cpu_has_erms(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_ERMS);
}
static inline bool qihse_cpu_has_fma(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_FMA);
}
static inline bool qihse_cpu_has_movbe(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_MOVBE);
}
static inline bool qihse_cpu_has_lzcnt(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_LZCNT);
}
static inline bool qihse_cpu_has_bmi1(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_BMI1);
}
static inline bool qihse_cpu_has_bmi2(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_BMI2);
}
static inline bool qihse_cpu_has_rtm(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_RTM);
}
static inline bool qihse_cpu_has_rdseed(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_RDSEED);
}
static inline bool qihse_cpu_has_adx(const qihse_cpu_info_t* info) {
    return qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_ADX);
}
static inline bool qihse_cpu_has_avx(const qihse_cpu_info_t* info) {
    return info && info->has_avx_support && qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_AVX);
}
static inline bool qihse_cpu_has_avx2(const qihse_cpu_info_t* info) {
    return info && info->has_avx_support && qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_AVX2);
}
static inline bool qihse_cpu_has_ssse3(const qihse_cpu_info_t* info) {
    return info && qihse_cpu_has_feature(info, QIHSE_CPU_FEATURE_SSSE3);
}

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
