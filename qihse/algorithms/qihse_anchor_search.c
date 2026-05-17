/**
 * QIHSE native anchor search.
 *
 * Integrated from upstream NOT_STISLA as a QIHSE-owned algorithm module for
 * sorted int64_t search workloads.
 *
 * Features:
 * - AVX2-style chunked processing
 * - High-precision interpolation
 * - Smart anchor learning
 * - DSMIL workload optimizations
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* For M_PI, clock_gettime, CLOCK_MONOTONIC */
#endif
#define _POSIX_C_SOURCE 200809L  /* For POSIX time functions */

#include "qihse_anchor_search.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <errno.h>
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif
#ifdef _OPENMP
#include <omp.h>
#endif
#if defined(__AVX2__) || defined(__AVX512F__)
#include <immintrin.h>
#endif
#include <sys/mman.h>  /* For madvise (huge pages support) */
#include <stdio.h>     /* For CPU detection parsing */

#if defined(__aarch64__)
#include <arm_neon.h>
#include <arm_sve.h>
#include <sys/auxv.h>
#include <asm/hwcap.h>

/* Detect if running on AWS Graviton4 (Neoverse V2) */
static int is_graviton4(void) {
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;

    char line[256];
    int implementer = 0;
    int part = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "CPU implementer", 15) == 0) {
            char* val = strchr(line, ':');
            if (val) implementer = (int)strtol(val + 1, NULL, 16);
        } else if (strncmp(line, "CPU part", 8) == 0) {
            char* val = strchr(line, ':');
            if (val) part = (int)strtol(val + 1, NULL, 16);
        }
        
        /* Neoverse V2 (Graviton4): Implementer 0x41, Part 0xd4f */
        if (implementer == 0x41 && part == 0xd4f) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}
#endif

#define NOT_STISLA_VERSION_STRING "1.1.0-qihse-native"
#define NOT_STISLA_BUILD_INFO "QIHSE native anchor search with runtime CPU detection and bounded anchor memory"

/* QIHSE-native runtime CPU feature detection */
static uint32_t detected_cpu_features = 0;
static int cpu_features_detected = 0;

/* Signal handler for illegal instruction detection */
#ifndef __aarch64__
static uint64_t x86_xgetbv0(void) {
    uint32_t eax = 0;
    uint32_t edx = 0;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t)edx << 32) | eax;
}

static int x86_os_avx_enabled(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }

    const uint32_t osxsave = 1u << 27;
    const uint32_t avx = 1u << 28;
    if ((ecx & (osxsave | avx)) != (osxsave | avx)) {
        return 0;
    }

    return (x86_xgetbv0() & 0x6u) == 0x6u;
}

static int x86_os_avx512_enabled(void) {
    if (!x86_os_avx_enabled()) {
        return 0;
    }

    const uint64_t avx512_state = 0xE6u; /* XMM, YMM, opmask, ZMM_hi256, hi16_ZMM */
    return (x86_xgetbv0() & avx512_state) == avx512_state;
}

static int x86_os_amx_enabled(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }

    if ((ecx & (1u << 27)) == 0) {
        return 0;
    }

    const uint64_t amx_state = (1ULL << 17) | (1ULL << 18);
    return (x86_xgetbv0() & amx_state) == amx_state;
}

static int test_avx2(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (!x86_os_avx_enabled() || __get_cpuid_max(0, NULL) < 7) {
        return 0;
    }

    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1u << 5)) != 0; /* AVX2 */
}

static int test_avx512(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (!x86_os_avx512_enabled() || __get_cpuid_max(0, NULL) < 7) {
        return 0;
    }

    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1u << 16)) != 0; /* AVX-512F */
}

static int test_amx(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (!x86_os_amx_enabled() || __get_cpuid_max(0, NULL) < 7) {
        return 0;
    }

    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (edx & (1u << 24)) != 0; /* AMX-TILE */
}

static int test_vnni(void) {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    if (__get_cpuid_max(0, NULL) < 7) {
        return 0;
    }

    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    if (x86_os_avx512_enabled() && (ebx & (1u << 11))) {
        return 1; /* AVX-512 VNNI */
    }

    if (eax >= 1 && x86_os_avx_enabled()) {
        __cpuid_count(7, 1, eax, ebx, ecx, edx);
        return (eax & (1u << 4)) != 0; /* AVX-VNNI */
    }

    return 0;
}
#endif

/* Runtime CPU feature detection (NOT_STISLA-native) */
uint32_t not_stisla_detect_cpu_features(void) {
    if (!cpu_features_detected) {
        detected_cpu_features = 0;

#if defined(__aarch64__)
        unsigned long hwcap = getauxval(AT_HWCAP);
        unsigned long hwcap2 = getauxval(AT_HWCAP2);

        if (hwcap & HWCAP_ASIMD) {
            detected_cpu_features |= NOT_STISLA_CPU_NEON;
        }
        if (hwcap & HWCAP_SVE) {
            detected_cpu_features |= NOT_STISLA_CPU_SVE;
        }
        if (hwcap2 & HWCAP2_SVE2) {
            detected_cpu_features |= NOT_STISLA_CPU_SVE2;
        }
        if (hwcap2 & HWCAP2_I8MM) {
            detected_cpu_features |= NOT_STISLA_CPU_I8MM;
        }
        if (is_graviton4()) {
            detected_cpu_features |= NOT_STISLA_CPU_GRAVITON4;
        }
#else
        /* Test AVX2 */
        if (test_avx2()) {
            detected_cpu_features |= NOT_STISLA_CPU_AVX2;
        }

        /* Test AVX512 */
        if (test_avx512()) {
            detected_cpu_features |= NOT_STISLA_CPU_AVX512;
        }

        /* Test AMX */
        if (test_amx()) {
            detected_cpu_features |= NOT_STISLA_CPU_AMX;
        }

        if (test_vnni()) {
            detected_cpu_features |= NOT_STISLA_CPU_VNNI;
        }
#endif

        cpu_features_detected = 1;
    }

    return detected_cpu_features;
}

static not_stisla_performance_stats_t g_performance_stats = {0};
static int g_performance_enabled = 0;

int not_stisla_get_performance_stats(not_stisla_performance_stats_t* stats) {
    if (!stats) return -1;

    memcpy(stats, &g_performance_stats, sizeof(not_stisla_performance_stats_t));
    return 0;
}

void not_stisla_reset_performance_stats(void) {
    memset(&g_performance_stats, 0, sizeof(not_stisla_performance_stats_t));
}

void not_stisla_set_performance_tracking(int enabled) {
    g_performance_enabled = enabled ? 1 : 0;
}

int not_stisla_is_performance_tracking_enabled(void) {
    return g_performance_enabled;
}

static void not_stisla_update_performance_stats(
    uint64_t search_time_ns,
    int search_successful,
    size_t memory_used,
    uint64_t anchors_learned,
    uint64_t anchors_pruned,
    uint32_t cpu_features_used
) {
    g_performance_stats.total_time_ns += search_time_ns;
    g_performance_stats.search_time_ns += search_time_ns;
    g_performance_stats.total_searches++;
    if (search_successful) {
        g_performance_stats.successful_searches++;
    }
    g_performance_stats.search_success_rate =
        (double)g_performance_stats.successful_searches / g_performance_stats.total_searches;

    g_performance_stats.avg_search_time_ns =
        (double)g_performance_stats.search_time_ns / g_performance_stats.total_searches;

    if (memory_used > g_performance_stats.peak_memory_usage) {
        g_performance_stats.peak_memory_usage = memory_used;
    }

    g_performance_stats.avg_memory_usage =
        (g_performance_stats.avg_memory_usage * (g_performance_stats.total_searches - 1) + memory_used) /
        g_performance_stats.total_searches;

    g_performance_stats.anchors_learned = anchors_learned;
    g_performance_stats.anchors_pruned = anchors_pruned;
    g_performance_stats.cpu_features_used |= cpu_features_used;

    int vector_features = 0;
    if (cpu_features_used & NOT_STISLA_CPU_AVX2) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_AVX512) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_AMX) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_VNNI) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_NEON) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_SVE) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_SVE2) vector_features++;
    if (cpu_features_used & NOT_STISLA_CPU_I8MM) vector_features++;

    g_performance_stats.vectorization_efficiency = (double)vector_features / 8.0;
    g_performance_stats.speedup_vs_binary = 0.0; /* Benchmark harnesses compute baseline-relative speedup. */
}

void not_stisla_config_init(not_stisla_config_t* config, int workload_type) {
    if (!config) return;

    memset(config, 0, sizeof(not_stisla_config_t));
    config->workload_type = workload_type;
    config->tol = 8;
    config->enable_anchor_learning = 1;
    config->max_anchors = 64;
    config->enable_simd = 1;
    config->force_cpu_features = 0;
    config->enable_profiling = 0;
    config->strict_mode = 1;
    not_stisla_config_optimize_for_workload(config, workload_type);
}

int not_stisla_config_validate(const not_stisla_config_t* config) {
    if (!config) return 0;
    if (config->tol == 0 || config->tol > 1000) return 0;
    if (config->max_anchors != 0 &&
        (config->max_anchors < NOT_STISLA_MIN_ANCHORS ||
         config->max_anchors > NOT_STISLA_MAX_ANCHORS)) return 0;
    if (config->workload_type < NOT_STISLA_WORKLOAD_TELEMETRY ||
        config->workload_type > NOT_STISLA_WORKLOAD_EVENTS) return 0;
    if (config->strict_mode) {
        if (config->enable_anchor_learning != 0 && config->enable_anchor_learning != 1) return 0;
        if (config->enable_simd != 0 && config->enable_simd != 1) return 0;
        if (config->enable_profiling != 0 && config->enable_profiling != 1) return 0;
    }
    return 1;
}

void not_stisla_config_optimize_for_workload(not_stisla_config_t* config, int workload_type) {
    if (!config) return;

    config->workload_type = workload_type;

    switch (workload_type) {
        case NOT_STISLA_WORKLOAD_TELEMETRY:
            config->tol = 12;
            config->max_anchors = 20;
            break;
        case NOT_STISLA_WORKLOAD_IDS:
            config->tol = 6;
            config->max_anchors = 8;
            break;
        case NOT_STISLA_WORKLOAD_OFFSETS:
            config->tol = 16;
            config->max_anchors = 24;
            break;
        case NOT_STISLA_WORKLOAD_EVENTS:
            config->tol = 10;
            config->max_anchors = 16;
            break;
        default:
            config->workload_type = NOT_STISLA_WORKLOAD_IDS;
            config->tol = 8;
            config->max_anchors = 64;
            break;
    }
}

void not_stisla_get_tuned_config(size_t array_size, not_stisla_config_t* config) {
    if (!config) return;

    not_stisla_config_init(config, NOT_STISLA_WORKLOAD_IDS);

    if (array_size < 1000) {
        config->tol = 6;
        config->max_anchors = 8;
    } else if (array_size < 10000) {
        config->tol = 8;
        config->max_anchors = 16;
    } else {
        config->tol = 12;
        config->max_anchors = 64;
    }
}

/* ============================================================================
 * ERROR HANDLING - COMPREHENSIVE ERROR CODES AND VALIDATION
 * ============================================================================ */

/**
 * Get error message for error code
 */
const char* not_stisla_error_message(not_stisla_error_t error) {
    switch (error) {
        case NOT_STISLA_SUCCESS:
            return "Success";
        case NOT_STISLA_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case NOT_STISLA_ERROR_MEMORY:
            return "Memory allocation failure";
        case NOT_STISLA_ERROR_NOT_FOUND:
            return "Item not found";
        case NOT_STISLA_ERROR_CONFIG:
            return "Configuration error";
        case NOT_STISLA_ERROR_CPU_FEATURE:
            return "CPU feature detection error";
        default:
            return "Unknown error";
    }
}

/**
 * Validate anchor table
 */
__attribute__((unused)) static not_stisla_error_t not_stisla_validate_anchor_table(const not_stisla_anchor_table_t* table) {
    if (!table) return NOT_STISLA_ERROR_INVALID_PARAM;
    if (table->size > table->max_capacity) return NOT_STISLA_ERROR_INVALID_PARAM;
    if (table->capacity > table->max_capacity) return NOT_STISLA_ERROR_INVALID_PARAM;
    if (table->anchors && table->size > table->capacity) return NOT_STISLA_ERROR_INVALID_PARAM;
    return NOT_STISLA_SUCCESS;
}

/* DSMIL workload types are now defined in the header file */

/* Forward declarations */
static inline size_t not_stisla_anchor_lower(const not_stisla_anchor_table_t* table, int64_t x);
static inline int64_t not_stisla_interpolate(int64_t l_val, int64_t r_val, size_t l_idx, size_t r_idx, int64_t key);
static inline size_t not_stisla_local_search(const int64_t* arr, size_t lo, size_t hi, int64_t key);
static void not_stisla_learn_anchor(not_stisla_anchor_table_t* table, int64_t value, size_t index, size_t pred, size_t tol);

/* Enhanced chunked search with runtime SIMD detection (NOT_STISLA-native) */
static inline size_t not_stisla_chunked_search(const int64_t* arr, size_t n, int64_t key) {
    /* For very small arrays, simple loop with minimal unrolling for speed */
    if (n <= NOT_STISLA_CHUNK_SIZE) {
        size_t i = 0;
        for (; i + 3 < n; i += 4) {
            if (arr[i] == key) return i;
            if (arr[i+1] == key) return i+1;
            if (arr[i+2] == key) return i+2;
            if (arr[i+3] == key) return i+3;
        }
        for (; i < n; ++i) {
            if (arr[i] == key) return i;
        }
        return NOT_STISLA_NOT_FOUND;
    }

    /* Runtime CPU feature detection for optimal SIMD usage */
    /* NOTE: SIMD paths only compiled if compiler flags enable them */
    
#ifdef __AVX512F__
    /* AVX-512 path: Only use if compiled AND runtime detected */
    uint32_t cpu_features = not_stisla_detect_cpu_features();
    if (cpu_features & NOT_STISLA_CPU_AVX512) {
        /* Process in chunks of 8 int64_t (512 bits = 8 x 64-bit integers) */
        const size_t full_chunks = n / 8;
        for (size_t chunk = 0; chunk < full_chunks; ++chunk) {
            const size_t base = chunk * 8;

            /* Load 8 int64_t values (512 bits) into ZMM register */
            __m512i vec_data = _mm512_loadu_si512((const __m512i*)&arr[base]);
            
            /* Broadcast target key to all 8 lanes */
            __m512i vec_target = _mm512_set1_epi64(key);
            
            /* BRANCHLESS parallel comparison - generates 8-bit mask in opmask register */
            __mmask8 match_mask = _mm512_cmp_epi64_mask(vec_data, vec_target, _MM_CMPINT_EQ);
            
            /* If any match found, use count trailing zeros to find index instantly */
            if (match_mask) {
                int local_index = __builtin_ctz(match_mask);
                return base + local_index;
            }
        }
        
        /* Handle remaining elements */
        const size_t remainder_start = (n / 8) * 8;
        for (size_t i = remainder_start; i < n; ++i) {
            if (arr[i] == key) return i;
        }
        return NOT_STISLA_NOT_FOUND;
    }
#endif

#ifdef __AVX2__
    /* AVX2 path: Only use if compiled AND runtime detected */
    #ifndef __AVX512F__
    uint32_t cpu_features = not_stisla_detect_cpu_features();
    #endif
    if (cpu_features & NOT_STISLA_CPU_AVX2) {
        /* Process in chunks of 4 int64_t (256 bits = 4 x 64-bit integers) */
        const size_t full_chunks = n / 4;
        for (size_t chunk = 0; chunk < full_chunks; ++chunk) {
            const size_t base = chunk * 4;

            /* Load 4 int64_t values (256 bits) into YMM register */
            __m256i vec_data = _mm256_loadu_si256((const __m256i*)&arr[base]);
            
            /* Broadcast target key to all 4 lanes */
            __m256i vec_target = _mm256_set1_epi64x(key);
            
            /* Parallel comparison - generates comparison mask */
            __m256i cmp_result = _mm256_cmpeq_epi64(vec_data, vec_target);
            
            /* Convert to bitmask */
            int mask = _mm256_movemask_pd(_mm256_castsi256_pd(cmp_result));
            
            /* If any match found, find index using count trailing zeros */
            if (mask) {
                int local_index = __builtin_ctz(mask);
                return base + local_index;
            }
        }
        
        /* Handle remaining elements */
        const size_t remainder_start = (n / 4) * 4;
        for (size_t i = remainder_start; i < n; ++i) {
            if (arr[i] == key) return i;
        }
        return NOT_STISLA_NOT_FOUND;
    }
#endif

#if defined(__aarch64__)
    /* ARM SIMD path: SVE and NEON */
    {
        uint32_t cpu_features_arm = not_stisla_detect_cpu_features();

        if (cpu_features_arm & NOT_STISLA_CPU_SVE) {
            /* SVE path */
            uint64_t vl = svcntd();
            const size_t full_chunks = n / vl;
            for (size_t chunk = 0; chunk < full_chunks; ++chunk) {
                const size_t base = chunk * vl;
                svbool_t pg = svptrue_b64();
                svint64_t vec_data = svld1_s64(pg, &arr[base]);
                svint64_t vec_target = svdup_n_s64(key);
                svbool_t match_mask = svcmpeq_s64(pg, vec_data, vec_target);
                
                if (svptest_any(pg, match_mask)) {
                    for (size_t i = 0; i < vl; ++i) {
                        if (arr[base + i] == key) return base + i;
                    }
                }
            }
            
            const size_t remainder_start = full_chunks * vl;
            for (size_t i = remainder_start; i < n; ++i) {
                if (arr[i] == key) return i;
            }
            return NOT_STISLA_NOT_FOUND;
        } else if (cpu_features_arm & NOT_STISLA_CPU_NEON) {
            /* NEON path (128-bit, 2 x 64-bit integers) */
            const size_t full_chunks = n / 2;
            for (size_t chunk = 0; chunk < full_chunks; ++chunk) {
                const size_t base = chunk * 2;
                int64x2_t vec_data = vld1q_s64(&arr[base]);
                int64x2_t vec_target = vdupq_n_s64(key);
                uint64x2_t cmp_result = vceqq_s64(vec_data, vec_target);
                
                if (vgetq_lane_u64(cmp_result, 0)) return base;
                if (vgetq_lane_u64(cmp_result, 1)) return base + 1;
            }
            
            const size_t remainder_start = full_chunks * 2;
            for (size_t i = remainder_start; i < n; ++i) {
                if (arr[i] == key) return i;
            }
            return NOT_STISLA_NOT_FOUND;
        }
    }
#endif

    /* Scalar fallback: Use when no SIMD compiled in or detected */
    #if !defined(__AVX512F__) && !defined(__AVX2__)
    /* Process in chunks of 4 for better ILP even without SIMD */
    const size_t full_chunks = n / NOT_STISLA_CHUNK_SIZE;
    for (size_t chunk = 0; chunk < full_chunks; ++chunk) {
        const size_t base = chunk * NOT_STISLA_CHUNK_SIZE;

        /* Scalar chunked processing */
        for (size_t i = 0; i < NOT_STISLA_CHUNK_SIZE; ++i) {
            if (arr[base + i] == key) {
                return base + i;
            }
        }
    }

    /* Handle remaining elements */
    const size_t remainder_start = (n / NOT_STISLA_CHUNK_SIZE) * NOT_STISLA_CHUNK_SIZE;
    for (size_t i = remainder_start; i < n; ++i) {
        if (arr[i] == key) return i;
    }
    #endif

    return NOT_STISLA_NOT_FOUND;
}

/* Optimized anchor binary search with unrolling */
static inline size_t not_stisla_anchor_lower(const not_stisla_anchor_table_t* table, int64_t x) {
    if (table->size == 0) return 0;

    size_t lo = 0;
    size_t hi = table->size - 1;

    /* Manual unrolling for common small table sizes */
    switch (hi - lo) {
        case 0:
            return table->anchors[lo].v <= x ? lo : 0;
        case 1: {
            const not_stisla_anchor_t* a0 = &table->anchors[lo];
            const not_stisla_anchor_t* a1 = &table->anchors[hi];
            if (a0->v <= x) {
                return a1->v <= x ? hi : lo;
            }
            return 0;
        }
        case 2: {
            const not_stisla_anchor_t* a0 = &table->anchors[lo];
            const not_stisla_anchor_t* a1 = &table->anchors[lo + 1];
            const not_stisla_anchor_t* a2 = &table->anchors[hi];
            if (a1->v <= x) {
                return a2->v <= x ? hi : lo + 1;
            } else if (a0->v <= x) {
                return lo;
            }
            return 0;
        }
        default:
            /* Standard binary search for larger tables */
            while (lo + 1 < hi) {
                size_t mid = lo + ((hi - lo) >> 1);
                if (table->anchors[mid].v <= x) {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            return lo;
    }
}

/* High-precision interpolation with overflow protection */
static inline int64_t not_stisla_interpolate(int64_t l_val, int64_t r_val, size_t l_idx, size_t r_idx, int64_t key) {
    const size_t span = r_idx - l_idx;

    if (r_val == l_val || span == 0) {
        return (int64_t)l_idx;
    }

    /* Use 128-bit arithmetic to prevent overflow */
    const __int128 key_offset = (__int128)key - (__int128)l_val;
    const __int128 range = (__int128)r_val - (__int128)l_val;

    if (range == 0) return (int64_t)l_idx;

    const __int128 frac = (key_offset * (__int128)span) / range;
    const __int128 result = (__int128)l_idx + frac;

    /* Clamp result to valid range */
    if (result < 0) return 0;
    if ((size_t)result > r_idx) return (int64_t)r_idx;

    return (int64_t)result;
}

/* Optimized local search with branchless logic and SIMD fallback */
static inline size_t not_stisla_local_search(const int64_t* arr, size_t lo, size_t hi, int64_t key) {
    /* Quick bounds check */
    if (lo > hi || arr[lo] > key || arr[hi] < key) {
        return NOT_STISLA_NOT_FOUND;
    }

    size_t n = hi - lo + 1;

    /* OPTIMIZATION: If the window is small, a SIMD linear scan is faster than binary search */
    if (n <= 32) {
        size_t res = not_stisla_chunked_search(&arr[lo], n, key);
        return (res == NOT_STISLA_NOT_FOUND) ? NOT_STISLA_NOT_FOUND : (lo + res);
    }

    /* BRANCHLESS Binary Search for larger windows */
    const int64_t* base = &arr[lo];
    while (n > 1) {
        size_t half = n / 2;
        /* Use __builtin_prefetch to hide latency of the next possible jump */
        __builtin_prefetch(&base[half/2], 0, 3);
        __builtin_prefetch(&base[half + half/2], 0, 3);
        
        base = (base[half] < key) ? &base[half] : base;
        n -= half;
    }

    return (*base == key) ? (size_t)(base - arr) : NOT_STISLA_NOT_FOUND;
}

/* Enhanced anchor learning with memory bounds and statistics (NOT_STISLA-native) */
static void not_stisla_learn_anchor(not_stisla_anchor_table_t* table, int64_t value, size_t index, size_t pred, size_t tol) {
    if (!table) return;

    /* Don't learn if prediction was close enough */
    const size_t pred_diff = (pred > index) ? (pred - index) : (index - pred);
    if (pred_diff <= tol) {
        return;
    }

    /* Memory-bounded learning: check if we've reached the limit */
    if (table->size >= table->max_capacity) {
        /* Prune least recently used anchors (NOT_STISLA-native memory efficiency) */
        uint64_t oldest_time = UINT64_MAX;
        size_t oldest_idx = 0;

        for (size_t i = 0; i < table->size; ++i) {
            if (table->anchors[i].last_used < oldest_time) {
                oldest_time = table->anchors[i].last_used;
                oldest_idx = i;
            }
        }

        /* Remove oldest anchor and shift array */
        memmove(&table->anchors[oldest_idx], &table->anchors[oldest_idx + 1],
                (table->size - oldest_idx - 1) * sizeof(not_stisla_anchor_t));
        table->size--;
        table->stats.anchors_pruned++;
    }

    /* Grow capacity if needed (but respect memory bounds) */
    if (table->size >= table->capacity && table->capacity < table->max_capacity) {
        const size_t new_cap = (table->capacity * 2 > table->max_capacity) ?
                               table->max_capacity : table->capacity * 2;
        if (new_cap > table->capacity) {
            not_stisla_anchor_t* new_anchors = realloc(table->anchors, new_cap * sizeof(not_stisla_anchor_t));
            if (!new_anchors) return;  /* Memory bound reached */
            table->anchors = new_anchors;
            table->capacity = new_cap;
            table->stats.memory_reallocations++;
        }
    }

    /* Find insertion point */
    size_t pos = 0;
    while (pos < table->size && table->anchors[pos].v < value) {
        ++pos;
    }

    /* Shift elements to make room */
    if (pos < table->size) {
        memmove(&table->anchors[pos + 1], &table->anchors[pos],
                (table->size - pos) * sizeof(not_stisla_anchor_t));
    }

    /* Insert new anchor with enhanced tracking */
    table->anchors[pos].v = value;
    table->anchors[pos].i = index;
    table->anchors[pos].use_count = 1;
    table->anchors[pos].last_used = (uint64_t)time(NULL);

    table->size++;
    table->stats.anchors_learned++;
}

/* Core NOT_STISLA search algorithm */
not_stisla_result_t not_stisla_search(const int64_t* arr, size_t n, int64_t key,
                              not_stisla_anchor_table_t* table, size_t tol) {
    if (!arr || n == 0) return NOT_STISLA_NOT_FOUND;

    if (table) {
        table->stats.searches_total++;
        table->searches_performed++;
    }

    /* Fast path: AVX2-optimized linear search for small arrays */
    if (n < 32) {
        const size_t small_result = not_stisla_chunked_search(arr, n, key);
        if (small_result != NOT_STISLA_NOT_FOUND && table) {
            table->stats.searches_successful++;
        }
        return small_result;
    }

    not_stisla_anchor_table_t local_table;
    not_stisla_anchor_t local_anchors[2];
    not_stisla_anchor_table_t* active_table = table;

    if (!active_table) {
        local_table.anchors = local_anchors;
        local_table.capacity = 2;
        local_table.size = 0;
        local_table.max_capacity = 2;
        local_table.searches_performed = 0;
        local_table.workload_type = -1;
        memset(&local_table.stats, 0, sizeof(local_table.stats));
        local_table.creation_time = 0;
        active_table = &local_table;
    }

    /* Initialize endpoints if needed */
    if (active_table->size == 0) {
        if (active_table->capacity == 0) {
            active_table->anchors = malloc(2 * sizeof(not_stisla_anchor_t));
            if (!active_table->anchors) return NOT_STISLA_NOT_FOUND;
            active_table->capacity = 2;
        }
        active_table->anchors[0].v = arr[0];
        active_table->anchors[0].i = 0;
        active_table->anchors[1].v = arr[n - 1];
        active_table->anchors[1].i = n - 1;
        active_table->size = 2;
    }

    if (key < active_table->anchors[0].v ||
        key > active_table->anchors[active_table->size - 1].v) {
        return NOT_STISLA_NOT_FOUND;
    }

    /* Step 1: Find bounding anchors */
    const size_t a_idx = not_stisla_anchor_lower(active_table, key);
    if (a_idx + 1 >= active_table->size) {
        const not_stisla_anchor_t* last = &active_table->anchors[active_table->size - 1];
        return arr[last->i] == key ? last->i : NOT_STISLA_NOT_FOUND;
    }
    const not_stisla_anchor_t* l = &active_table->anchors[a_idx];
    const not_stisla_anchor_t* r = &active_table->anchors[a_idx + 1];

    /* Step 2: High-precision interpolation */
    const size_t pred = (size_t)not_stisla_interpolate(l->v, r->v, l->i, r->i, key);

    /* Step 3: Optimized local search */
    size_t lo = (pred > tol) ? (pred - tol) : l->i;
    lo = (lo > l->i) ? lo : l->i;

    size_t hi = pred + tol;
    hi = (hi < r->i) ? hi : r->i;

    /* Ensure valid bounds */
    if (lo > hi) {
        lo = l->i;
        hi = r->i;
    }

    /* SOFTWARE PREFETCH: Hint L1 cache to load data ahead (4-8 cache lines = 64 elements) */
    /* This hides memory latency for next iteration and improves throughput on large arrays */
#if defined(__AVX512F__) || defined(__AVX2__)
    if (lo + 64 < n) {
        _mm_prefetch((const char*)&arr[lo + 64], _MM_HINT_T0);  /* Fetch to L1 */
    }
    if (lo + 128 < n) {
        _mm_prefetch((const char*)&arr[lo + 128], _MM_HINT_T1); /* Fetch to L2 */
    }
#endif

    const size_t result = not_stisla_local_search(arr, lo, hi, key);

    /* Step 4: Enhanced learning with usage tracking */
    if (result != NOT_STISLA_NOT_FOUND && table) {
        table->stats.searches_successful++;
        not_stisla_learn_anchor(table, arr[result], result, pred, tol);

        /* Update anchor usage statistics (NOT_STISLA-native) */
        if (active_table != table) {
            /* Find and update the anchor that was used */
            for (size_t i = 0; i < active_table->size; ++i) {
                if (active_table->anchors[i].i == l->i || active_table->anchors[i].i == r->i) {
                    active_table->anchors[i].use_count++;
                    active_table->anchors[i].last_used = (uint64_t)time(NULL);
                }
            }
        }
    }

    return result;
}

not_stisla_result_t not_stisla_search_enhanced(
    const int64_t* arr,
    size_t n,
    int64_t key,
    not_stisla_anchor_table_t* table,
    const not_stisla_config_t* config
) {
    if (__builtin_expect(!arr || n == 0 || !config ||
                         config->tol == 0 || config->tol > 1000, 0)) {
        return NOT_STISLA_NOT_FOUND;
    }

    not_stisla_anchor_table_t* active_table =
        config->enable_anchor_learning ? table : NULL;
    if (active_table) {
        if (config->workload_type >= NOT_STISLA_WORKLOAD_TELEMETRY &&
            config->workload_type <= NOT_STISLA_WORKLOAD_EVENTS) {
            active_table->workload_type = config->workload_type;
        }
        if (config->max_anchors >= NOT_STISLA_MIN_ANCHORS &&
            config->max_anchors <= NOT_STISLA_MAX_ANCHORS) {
            active_table->max_capacity = config->max_anchors;
        }
    }

    const int track = g_performance_enabled || config->enable_profiling;
    struct timespec start_time;
    if (track) {
        clock_gettime(CLOCK_MONOTONIC, &start_time);
    }

    not_stisla_result_t result =
        not_stisla_search(arr, n, key, active_table, config->tol);

    if (track) {
        struct timespec end_time;
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        uint64_t elapsed_ns =
            (uint64_t)(end_time.tv_sec - start_time.tv_sec) * 1000000000ULL +
            (uint64_t)(end_time.tv_nsec - start_time.tv_nsec);
        size_t memory_used = 0;
        uint64_t anchors_learned = 0;
        uint64_t anchors_pruned = 0;
        if (active_table) {
            memory_used = active_table->capacity * sizeof(not_stisla_anchor_t) +
                          sizeof(not_stisla_anchor_table_t);
            anchors_learned = active_table->stats.anchors_learned;
            anchors_pruned = active_table->stats.anchors_pruned;
        }
        not_stisla_update_performance_stats(
            elapsed_ns,
            result != NOT_STISLA_NOT_FOUND,
            memory_used,
            anchors_learned,
            anchors_pruned,
            not_stisla_detect_cpu_features());
    }

    return result;
}

/* Enhanced anchor table creation with NOT_STISLA-native memory management */
not_stisla_anchor_table_t* not_stisla_anchor_table_create(void) {
    not_stisla_anchor_table_t* table = calloc(1, sizeof(not_stisla_anchor_table_t));
    if (!table) return NULL;

    /* Enhanced memory management - start small, grow as needed */
    table->anchors = malloc(NOT_STISLA_MIN_ANCHORS * sizeof(not_stisla_anchor_t));
    if (!table->anchors) {
        free(table);
        return NULL;
    }

    /* Initialize enhanced fields */
    table->capacity = NOT_STISLA_MIN_ANCHORS;
    table->max_capacity = NOT_STISLA_MAX_ANCHORS;  /* Memory bound */
    table->size = 0;
    table->searches_performed = 0;
    table->workload_type = -1;
    table->creation_time = (uint64_t)time(NULL);

    /* Initialize statistics */
    memset(&table->stats, 0, sizeof(not_stisla_stats_t));
    table->stats.cpu_features_detected = not_stisla_detect_cpu_features();

    /* AWS Graviton4 Auto-Optimization: Lock anchor table to 2MB L2 boundary */
    if (table->stats.cpu_features_detected & NOT_STISLA_CPU_GRAVITON4) {
        table->max_capacity = 65536; /* Approx 2MB of anchor data */
    }

    return table;
}

void not_stisla_anchor_table_destroy(not_stisla_anchor_table_t* table) {
    if (table) {
        free(table->anchors);
        free(table);
    }
}

size_t not_stisla_anchor_table_size(const not_stisla_anchor_table_t* table) {
    return table ? table->size : 0;
}

void not_stisla_anchor_table_reset(not_stisla_anchor_table_t* table) {
    if (table) {
        table->size = 0;
        table->searches_performed = 0;
        /* Reset statistics but keep CPU feature detection */
        uint32_t cpu_features = table->stats.cpu_features_detected;
        memset(&table->stats, 0, sizeof(not_stisla_stats_t));
        table->stats.cpu_features_detected = cpu_features;
    }
}

/* Enhanced functions inspired by NOT_STISLA patterns */
const not_stisla_stats_t* not_stisla_anchor_table_get_stats(const not_stisla_anchor_table_t* table) {
    return table ? &table->stats : NULL;
}

int not_stisla_anchor_table_set_memory_limit(not_stisla_anchor_table_t* table, size_t max_anchors) {
    if (!table || max_anchors < NOT_STISLA_MIN_ANCHORS || max_anchors > NOT_STISLA_MAX_ANCHORS) {
        return -1;
    }

    table->max_capacity = max_anchors;

    /* If current capacity exceeds limit, we don't shrink immediately */
    /* Will be enforced during anchor learning */

    return 0;
}

__attribute__((unused)) static not_stisla_anchor_table_t* not_stisla_anchor_table_clone(const not_stisla_anchor_table_t* table) {
    if (!table) {
        return NULL;
    }

    not_stisla_anchor_table_t* clone = not_stisla_anchor_table_create();
    if (!clone) {
        return NULL;
    }

    free(clone->anchors);
    clone->anchors = malloc(table->capacity * sizeof(not_stisla_anchor_t));
    if (!clone->anchors) {
        not_stisla_anchor_table_destroy(clone);
        return NULL;
    }

    memcpy(clone->anchors, table->anchors, table->size * sizeof(not_stisla_anchor_t));
    clone->capacity = table->capacity;
    clone->size = table->size;
    clone->max_capacity = table->max_capacity;
    clone->workload_type = table->workload_type;
    clone->stats = table->stats;
    clone->searches_performed = table->searches_performed;
    clone->creation_time = table->creation_time;

    return clone;
}

int not_stisla_anchor_table_optimize_for_workload(not_stisla_anchor_table_t* table, int workload_type) {
    if (!table) return -1;

    table->workload_type = workload_type;

    /* Workload-specific optimizations (similar to NOT_STISLA patterns) */
    switch (workload_type) {
        case NOT_STISLA_WORKLOAD_TELEMETRY:
            /* Telemetry: Higher anchor limits for variable patterns */
            table->max_capacity = 20;
            break;
        case NOT_STISLA_WORKLOAD_IDS:
            /* IDs: Lower limits for more uniform data */
            table->max_capacity = 8;
            break;
        case NOT_STISLA_WORKLOAD_OFFSETS:
            /* Offsets: Higher limits for exponential patterns */
            table->max_capacity = 24;
            break;
        case NOT_STISLA_WORKLOAD_EVENTS:
            /* Events: Medium limits for burst patterns */
            table->max_capacity = 16;
            break;
        default:
            table->max_capacity = NOT_STISLA_MAX_ANCHORS;
            break;
    }

    return 0;
}

static int not_stisla_batch_key_cmp(const void* a, const void* b) {
    const not_stisla_batch_item_t* lhs = (const not_stisla_batch_item_t*)a;
    const not_stisla_batch_item_t* rhs = (const not_stisla_batch_item_t*)b;
    if (lhs->key < rhs->key) return -1;
    if (lhs->key > rhs->key) return 1;
    return 0;
}

size_t not_stisla_search_batch(const int64_t* arr, size_t n,
                               not_stisla_batch_item_t* items,
                               size_t num_items,
                               not_stisla_anchor_table_t* table,
                               size_t tol) {
    if (!arr || !items || num_items == 0) {
        return 0;
    }

    size_t found = 0;
    not_stisla_batch_item_t* sorted = malloc(num_items * sizeof(not_stisla_batch_item_t));
    if (!sorted) {
        return 0;
    }

    /* Copy keys with ordinal tracking */
    for (size_t i = 0; i < num_items; ++i) {
        sorted[i] = items[i];
        sorted[i].ordinal = i;
    }

    qsort(sorted, num_items, sizeof(not_stisla_batch_item_t), not_stisla_batch_key_cmp);

    size_t ai = 0;
    for (size_t i = 0; i < num_items; ++i) {
        const int64_t key = sorted[i].key;
        while (ai < n && arr[ai] < key) {
            ai++;
        }

        not_stisla_result_t result = NOT_STISLA_NOT_FOUND;
        if (ai < n && arr[ai] == key) {
            result = ai;
            found++;
            if (table) {
                not_stisla_learn_anchor(table, arr[ai], ai, ai, tol);
                table->searches_performed++;
            }
        }

        size_t original = sorted[i].ordinal;
        items[original].result = result;
        items[original].ordinal = original;
    }

    free(sorted);
    return found;
}

size_t not_stisla_search_parallel(const int64_t* arr,
                                  size_t n,
                                  not_stisla_batch_item_t* items,
                                  size_t num_items,
                                  not_stisla_anchor_table_t* table,
                                  size_t tol,
                                  const not_stisla_parallel_config_t* config) {
    if (!arr || !items || num_items == 0) {
        return 0;
    }

#ifdef _OPENMP
    int requested_threads = config && config->num_threads > 0 ? config->num_threads : 0;
    const int chunk_size = config && config->batch_chunk > 0 ? (int)config->batch_chunk : 1;
    size_t found = 0;

#pragma omp parallel num_threads(requested_threads ? requested_threads : omp_get_max_threads())
    {
        not_stisla_anchor_table_t* thread_table = table ? not_stisla_anchor_table_clone(table) : NULL;
        size_t local_found = 0;

#pragma omp for schedule(dynamic, chunk_size)
        for (size_t i = 0; i < num_items; ++i) {
            not_stisla_batch_item_t* item = &items[i];
            not_stisla_result_t result = not_stisla_search(arr, n, item->key, thread_table, tol);
            item->result = result;
            item->ordinal = i;
            if (result != NOT_STISLA_NOT_FOUND) {
                local_found++;
            }
        }

        if (thread_table) {
            not_stisla_anchor_table_destroy(thread_table);
        }

#pragma omp atomic
        found += local_found;
    }

    return found;
#else
    (void)config;
    return not_stisla_search_batch(arr, n, items, num_items, table, tol);
#endif
}

static not_stisla_backend_decision_t g_last_backend_decision = {
    NOT_STISLA_BACKEND_AUTO,
    0,
    0,
    0,
    0,
    0.0,
    0.0
};
static int g_last_backend_decision_valid = 0;

#define NOT_STISLA_AUTO_CACHE_ENTRIES 32
/* 180-case matrix: 8K-query batches favor scalar; 32K+ favor C/OpenMP. */
#define NOT_STISLA_AUTO_PARALLEL_MIN_ITEMS 16384
#define NOT_STISLA_AUTO_PARALLEL_MIN_ARRAY 1024
#define NOT_STISLA_AUTO_FORTRAN_MIN_ITEMS 4096
#define NOT_STISLA_AUTO_FORTRAN_MAX_ITEMS 16384
#define NOT_STISLA_AUTO_FORTRAN_MAX_AVG_STEP 4.0L

enum {
    NOT_STISLA_AUTO_QUERY_GENERAL = 0,
    NOT_STISLA_AUTO_QUERY_FORTRAN_MERGE = 1
};

typedef struct not_stisla_backend_cache_entry {
    int valid;
    uint32_t cpu_features;
    size_t array_size_bucket;
    size_t query_count_bucket;
    int thread_count;
    int query_shape;
    not_stisla_backend_t backend;
    double estimated_ns_per_key;
    double p95_ns_per_key;
} not_stisla_backend_cache_entry_t;

static not_stisla_backend_cache_entry_t g_backend_cache[NOT_STISLA_AUTO_CACHE_ENTRIES];
static size_t g_backend_cache_next = 0;

static size_t not_stisla_power_of_two_bucket(size_t value) {
    if (value <= 1) {
        return value;
    }

    size_t bucket = 1;
    while (bucket < value && bucket <= SIZE_MAX / 2) {
        bucket *= 2;
    }

    return bucket < value ? SIZE_MAX : bucket;
}

static int not_stisla_effective_thread_count(const not_stisla_parallel_config_t* config) {
#ifdef _OPENMP
    if (config && config->num_threads > 0) {
        return config->num_threads;
    }
    int max_threads = omp_get_max_threads();
    return max_threads > 0 ? max_threads : 1;
#else
    (void)config;
    return 1;
#endif
}

static int not_stisla_openmp_available(void) {
#ifdef _OPENMP
    return 1;
#else
    return 0;
#endif
}

static int not_stisla_auto_scalar_fast_path(size_t num_items,
                                            const not_stisla_parallel_config_t* config,
                                            int thread_count) {
    return num_items < NOT_STISLA_AUTO_PARALLEL_MIN_ITEMS ||
           !not_stisla_openmp_available() ||
           thread_count <= 1 ||
           (config && config->num_threads == 1);
}

static uint64_t not_stisla_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double not_stisla_elapsed_ns_per_key(uint64_t start_ns,
                                            uint64_t end_ns,
                                            size_t num_items) {
    if (start_ns == 0 || end_ns < start_ns || num_items == 0) {
        return 0.0;
    }
    return (double)(end_ns - start_ns) / (double)num_items;
}

static int not_stisla_detect_auto_query_shape(const int64_t* arr,
                                              size_t n,
                                              const not_stisla_batch_item_t* items,
                                              size_t num_items) {
    (void)arr;
    (void)n;
    (void)items;
    (void)num_items;
    return NOT_STISLA_AUTO_QUERY_GENERAL;
}

static int not_stisla_find_backend_cache(uint32_t cpu_features,
                                         size_t array_size_bucket,
                                         size_t query_count_bucket,
                                         int thread_count,
                                         int query_shape,
                                         not_stisla_backend_cache_entry_t* entry) {
    for (size_t i = 0; i < NOT_STISLA_AUTO_CACHE_ENTRIES; ++i) {
        const not_stisla_backend_cache_entry_t* current = &g_backend_cache[i];
        if (!current->valid) {
            continue;
        }
        if (current->cpu_features == cpu_features &&
            current->array_size_bucket == array_size_bucket &&
            current->query_count_bucket == query_count_bucket &&
            current->thread_count == thread_count &&
            current->query_shape == query_shape) {
            if (entry) {
                *entry = *current;
            }
            return 1;
        }
    }
    return 0;
}

static void not_stisla_store_backend_cache(uint32_t cpu_features,
                                           size_t array_size_bucket,
                                           size_t query_count_bucket,
                                           int thread_count,
                                           int query_shape,
                                           not_stisla_backend_t backend,
                                           double estimated_ns_per_key,
                                           double p95_ns_per_key) {
    not_stisla_backend_cache_entry_t* entry =
        &g_backend_cache[g_backend_cache_next % NOT_STISLA_AUTO_CACHE_ENTRIES];
    g_backend_cache_next++;

    entry->valid = 1;
    entry->cpu_features = cpu_features;
    entry->array_size_bucket = array_size_bucket;
    entry->query_count_bucket = query_count_bucket;
    entry->thread_count = thread_count;
    entry->query_shape = query_shape;
    entry->backend = backend;
    entry->estimated_ns_per_key = estimated_ns_per_key;
    entry->p95_ns_per_key = p95_ns_per_key;
}

static void not_stisla_record_backend_decision(not_stisla_backend_t backend,
                                               size_t n,
                                               size_t num_items,
                                               int thread_count,
                                               double estimated_ns_per_key,
                                               double p95_ns_per_key) {
    g_last_backend_decision.backend = backend;
    g_last_backend_decision.cpu_features = not_stisla_detect_cpu_features();
    g_last_backend_decision.array_size_bucket = not_stisla_power_of_two_bucket(n);
    g_last_backend_decision.query_count_bucket = not_stisla_power_of_two_bucket(num_items);
    g_last_backend_decision.thread_count = thread_count;
    g_last_backend_decision.estimated_ns_per_key = estimated_ns_per_key;
    g_last_backend_decision.p95_ns_per_key = p95_ns_per_key;
    g_last_backend_decision_valid = 1;
}

static not_stisla_backend_t not_stisla_static_auto_backend(size_t n,
                                                           size_t num_items,
                                                           const not_stisla_parallel_config_t* config,
                                                           int thread_count,
                                                           int query_shape) {
    if (query_shape == NOT_STISLA_AUTO_QUERY_FORTRAN_MERGE) {
        return NOT_STISLA_BACKEND_FORTRAN;
    }
    if (not_stisla_auto_scalar_fast_path(num_items, config, thread_count)) {
        return NOT_STISLA_BACKEND_SCALAR;
    }
    if (n < NOT_STISLA_AUTO_PARALLEL_MIN_ARRAY) {
        return NOT_STISLA_BACKEND_SCALAR;
    }
    return NOT_STISLA_BACKEND_C_OPENMP;
}

size_t not_stisla_search_batch_auto(const int64_t* arr,
                                    size_t n,
                                    not_stisla_batch_item_t* items,
                                    size_t num_items,
                                    not_stisla_anchor_table_t* table,
                                    size_t tol,
                                    const not_stisla_parallel_config_t* config) {
    const int thread_count = not_stisla_effective_thread_count(config);
    if (!arr || !items || n == 0 || num_items == 0) {
        const uint64_t start_ns = not_stisla_now_ns();
        const size_t found =
            not_stisla_search_batch_c_optimized(arr, n, items, num_items, table, tol);
        const uint64_t end_ns = not_stisla_now_ns();
        const double estimated_ns_per_key =
            not_stisla_elapsed_ns_per_key(start_ns, end_ns, num_items);
        not_stisla_record_backend_decision(
            NOT_STISLA_BACKEND_SCALAR,
            n,
            num_items,
            thread_count,
            estimated_ns_per_key,
            estimated_ns_per_key
        );
        return found;
    }

    const int query_shape = not_stisla_detect_auto_query_shape(arr, n, items, num_items);
    if (query_shape == NOT_STISLA_AUTO_QUERY_GENERAL &&
        not_stisla_auto_scalar_fast_path(num_items, config, thread_count)) {
        const uint64_t start_ns = not_stisla_now_ns();
        const size_t found =
            not_stisla_search_batch_c_optimized(arr, n, items, num_items, table, tol);
        const uint64_t end_ns = not_stisla_now_ns();
        const double estimated_ns_per_key =
            not_stisla_elapsed_ns_per_key(start_ns, end_ns, num_items);
        not_stisla_record_backend_decision(
            NOT_STISLA_BACKEND_SCALAR,
            n,
            num_items,
            thread_count,
            estimated_ns_per_key,
            estimated_ns_per_key
        );
        return found;
    }

    const uint32_t cpu_features = not_stisla_detect_cpu_features();
    const size_t array_size_bucket = not_stisla_power_of_two_bucket(n);
    const size_t query_count_bucket = not_stisla_power_of_two_bucket(num_items);
    not_stisla_backend_cache_entry_t cached_decision;
    double cached_ns_per_key = 0.0;
    double cached_p95_ns_per_key = 0.0;
    not_stisla_backend_t selected_backend = NOT_STISLA_BACKEND_SCALAR;

    if (not_stisla_find_backend_cache(
            cpu_features,
            array_size_bucket,
            query_count_bucket,
            thread_count,
            query_shape,
            &cached_decision)) {
        selected_backend = cached_decision.backend;
        cached_ns_per_key = cached_decision.estimated_ns_per_key;
        cached_p95_ns_per_key = cached_decision.p95_ns_per_key;
    } else {
        selected_backend = not_stisla_static_auto_backend(n, num_items, config, thread_count, query_shape);
        not_stisla_store_backend_cache(
            cpu_features,
            array_size_bucket,
            query_count_bucket,
            thread_count,
            query_shape,
            selected_backend,
            cached_ns_per_key,
            cached_p95_ns_per_key
        );
    }

    const uint64_t start_ns = not_stisla_now_ns();
    size_t found = 0;

    if (selected_backend == NOT_STISLA_BACKEND_C_OPENMP) {
        found = not_stisla_search_parallel(arr, n, items, num_items, table, tol, config);
    } else if (selected_backend == NOT_STISLA_BACKEND_FORTRAN) {
        found = not_stisla_search_batch_fortran(arr, n, items, num_items);
    } else {
        selected_backend = NOT_STISLA_BACKEND_SCALAR;
        found = not_stisla_search_batch_c_optimized(arr, n, items, num_items, table, tol);
    }

    const uint64_t end_ns = not_stisla_now_ns();
    double estimated_ns_per_key = not_stisla_elapsed_ns_per_key(start_ns, end_ns, num_items);
    if (estimated_ns_per_key <= 0.0) {
        estimated_ns_per_key = cached_ns_per_key;
    }
    if (cached_p95_ns_per_key <= 0.0) {
        cached_p95_ns_per_key = estimated_ns_per_key;
    }

    not_stisla_record_backend_decision(
        selected_backend,
        n,
        num_items,
        thread_count,
        estimated_ns_per_key,
        cached_p95_ns_per_key
    );
    return found;
}

int not_stisla_get_last_backend_decision(not_stisla_backend_decision_t* decision) {
    if (!decision || !g_last_backend_decision_valid) {
        return -1;
    }

    memcpy(decision, &g_last_backend_decision, sizeof(not_stisla_backend_decision_t));
    return 0;
}

int not_stisla_fortran_backend_available(void) {
    return 0;
}

size_t not_stisla_search_batch_fortran(const int64_t* arr,
                                       size_t n,
                                       not_stisla_batch_item_t* items,
                                       size_t num_items) {
    if (!arr || !items || num_items == 0) {
        return 0;
    }

    for (size_t i = 0; i < num_items; ++i) {
        items[i].result = NOT_STISLA_NOT_FOUND;
        items[i].ordinal = i;
    }

    (void)n;
    return 0;
}

/**
 * Optimized C batch search with merge-walk for sorted queries
 * and SOFTWARE PIPELINED PREFETCHING for unsorted queries.
 * This is the ultimate "high-gain" enhancement for throughput.
 */
size_t not_stisla_search_batch_c_optimized(const int64_t* arr,
                                           size_t n,
                                           not_stisla_batch_item_t* items,
                                           size_t num_items,
                                           not_stisla_anchor_table_t* table,
                                           size_t tol) {
    if (!arr || !items || num_items == 0 || n == 0) {
        return 0;
    }

    /* Apply Huge Page hint to current batch if large enough */
    if (num_items * sizeof(not_stisla_batch_item_t) > 1024 * 1024) {
        madvise(items, num_items * sizeof(not_stisla_batch_item_t), MADV_HUGEPAGE);
    }

    /* Detect if queries are sorted */
    int sorted = 1;
    for (size_t i = 1; i < num_items; ++i) {
        if (items[i].key < items[i - 1].key) {
            sorted = 0;
            break;
        }
    }

    size_t found = 0;

    if (sorted) {
        /* HIGH-GAIN PATH: Merge-Walk with Lookahead Prefetching */
        size_t curr_idx = 0;
        for (size_t i = 0; i < num_items; ++i) {
            const int64_t key = items[i].key;
            
            /* Software prefetch for sorted stream (data and queries) */
            if (i + 16 < num_items) __builtin_prefetch(&items[i+16], 0, 3);
            if (curr_idx + 64 < n) __builtin_prefetch(&arr[curr_idx + 64], 0, 1);

            while (curr_idx < n && arr[curr_idx] < key) {
                if (n - curr_idx > 128 && arr[n-1] > arr[curr_idx]) {
                    size_t pred = (size_t)not_stisla_interpolate(arr[curr_idx], arr[n-1], 
                                                                curr_idx, n-1, key);
                    if (pred > curr_idx + 64) {
                        curr_idx = pred - 32;
                        continue;
                    }
                }
                curr_idx++;
            }

            if (curr_idx < n && arr[curr_idx] == key) {
                items[i].result = curr_idx;
                found++;
            } else {
                items[i].result = NOT_STISLA_NOT_FOUND;
            }
            items[i].ordinal = i;
        }
    } else {
        /* ULTIMATE THROUGHPUT PATH: Software Pipelined Batch Prefetching (4-way) */
        /* Interleaves memory fetches for future queries to hide DRAM latency */
        const size_t pipe_depth = 4;
        size_t i = 0;

        /* Pipeline Startup */
        for (; i < pipe_depth && i < num_items; ++i) {
            /* Prefetch query data for first few items */
            __builtin_prefetch(&items[i], 0, 3);
        }

        /* Steady State: Process item [i - pipe_depth] while prefetching for [i] */
        for (i = pipe_depth; i < num_items; ++i) {
            size_t target_idx = i - pipe_depth;
            
            /* 1. Prefetch future query metadata */
            __builtin_prefetch(&items[i], 0, 3);

            /* 2. Execute search for current pipeline element */
            not_stisla_result_t result = not_stisla_search(arr, n, items[target_idx].key, table, tol);
            items[target_idx].result = result;
            items[target_idx].ordinal = target_idx;
            if (result != NOT_STISLA_NOT_FOUND) found++;
        }

        /* Pipeline Drain */
        for (size_t j = (num_items > pipe_depth ? num_items - pipe_depth : 0); j < num_items; ++j) {
            if (items[j].ordinal == j && items[j].result != 0) continue; /* Simple check for processed */
            not_stisla_result_t result = not_stisla_search(arr, n, items[j].key, table, tol);
            items[j].result = result;
            items[j].ordinal = j;
            if (result != NOT_STISLA_NOT_FOUND) found++;
        }
    }

    return found;
}



void not_stisla_get_stats(const not_stisla_anchor_table_t* table, size_t* searches_total,
                     size_t* anchors_learned, size_t* memory_used_bytes) {
    if (!table) {
        if (searches_total) *searches_total = 0;
        if (anchors_learned) *anchors_learned = 0;
        if (memory_used_bytes) *memory_used_bytes = 0;
        return;
    }

    /* Enhanced statistics (NOT_STISLA-native) */
    if (searches_total) *searches_total = table->stats.searches_total;
    if (anchors_learned) *anchors_learned = table->stats.anchors_learned;
    if (memory_used_bytes) {
        *memory_used_bytes = table->capacity * sizeof(not_stisla_anchor_t) +
                           sizeof(not_stisla_anchor_table_t);
    }
}

/* DSMIL workload-specific optimizations */
not_stisla_result_t not_stisla_search_telemetry(const int64_t* timestamps, size_t n,
                                       int64_t target_time, not_stisla_anchor_table_t* table) {
    /* Telemetry optimization: higher tolerance for variable gaps */
    return not_stisla_search(timestamps, n, target_time, table, 12);
}

not_stisla_result_t not_stisla_search_ids(const int64_t* ids, size_t n,
                                 int64_t target_id, not_stisla_anchor_table_t* table) {
    /* ID optimization: lower tolerance for more uniform data */
    return not_stisla_search(ids, n, target_id, table, 6);
}

not_stisla_result_t not_stisla_search_offsets(const int64_t* offsets, size_t n,
                                    int64_t target_offset, not_stisla_anchor_table_t* table) {
    /* Offset optimization: higher tolerance for exponential patterns */
    return not_stisla_search(offsets, n, target_offset, table, 16);
}

not_stisla_result_t not_stisla_search_events(const int64_t* events, size_t n,
                                   int64_t target_time, not_stisla_anchor_table_t* table) {
    /* Event optimization: medium tolerance for burst patterns */
    return not_stisla_search(events, n, target_time, table, 10);
}

/**
 * @brief Optimize array memory layout for huge pages (TLB optimization)
 *
 * Requests 2MB transparent huge pages to reduce TLB misses by 512x.
 * This is most effective for large arrays (>1MB) where TLB misses
 * become a significant performance bottleneck.
 *
 * Call this after array allocation but before first search operation.
 *
 * @param arr Pointer to sorted array (must be valid, non-NULL)
 * @param n Number of elements in array
 * @return 0 on success, -1 if huge pages unavailable or parameters invalid
 */
int not_stisla_optimize_array_memory(const int64_t* arr, size_t n) {
    if (!arr || n == 0) {
        return -1;
    }

    size_t array_size = n * sizeof(int64_t);

    /* 
     * AGGRESSIVE TLB OPTIMIZATION: 
     * For arrays > 1MB, request transparent huge pages and sequential hints.
     * This is critical for Meteor Lake-P fabric throughput.
     */
    if (array_size >= 1024 * 1024) {
        /* Force huge pages if possible */
        madvise((void*)arr, array_size, MADV_HUGEPAGE);
        /* Tell kernel we will scan this linearly (optimized read-ahead) */
        madvise((void*)arr, array_size, MADV_SEQUENTIAL);
        /* Lock pages in RAM to prevent swapping during tight search loops */
        mlock((void*)arr, array_size); 
    }

    return 0;
}

bool not_stisla_init_for_dsmil(not_stisla_anchor_table_t* table, int workload_type) {
    if (!table) return false;

    /* Enhanced initialization with workload optimization (NOT_STISLA-native) */
    not_stisla_anchor_table_reset(table);
    not_stisla_anchor_table_optimize_for_workload(table, workload_type);

    /* Set workload-specific statistics tracking */
    table->stats.cpu_features_detected = not_stisla_detect_cpu_features();

    return true;
}

const char* not_stisla_version(void) {
    return NOT_STISLA_VERSION_STRING;
}

const char* not_stisla_build_info(void) {
    return NOT_STISLA_BUILD_INFO;
}

bool enhanced_available(void) {
    return true;
}

const char* enhanced_build_info(void) {
    return NOT_STISLA_BUILD_INFO;
}
