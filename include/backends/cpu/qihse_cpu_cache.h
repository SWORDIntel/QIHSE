/*
 * QIHSE - Hardware Cache & Synchronization Utilities
 *
 * Safe runtime-dispatched cache manipulation and core identification:
 * - clzero: Fast 64-byte cache line clearing (AMD Zen) with memset fallback
 * - clwb: Cache line writeback without invalidation with clflush/clflushopt fallback
 * - rdpid: Fast user-space CPU and NUMA node retrieval with sched_getcpu fallback
 *
 * Licensed under MIT.
 */

#ifndef QIHSE_CPU_CACHE_H
#define QIHSE_CPU_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include "qihse_cpu_detect.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__x86_64__) || defined(_M_X64)

__attribute__((target("clzero")))
static inline void qihse_clzero_raw(void* ptr) {
    __asm__ volatile (
        "clzero\n\t"
        :
        : "a"(ptr)
        : "memory"
    );
}

__attribute__((target("clwb")))
static inline void qihse_clwb_raw(const void* ptr) {
    __asm__ volatile (
        "clwb %0\n\t"
        :
        : "m"(*(const char*)ptr)
        : "memory"
    );
}

__attribute__((target("clflushopt")))
static inline void qihse_clflushopt_raw(const void* ptr) {
    __asm__ volatile (
        "clflushopt %0\n\t"
        :
        : "m"(*(const char*)ptr)
        : "memory"
    );
}

static inline void qihse_clflush_raw(const void* ptr) {
    __asm__ volatile (
        "clflush %0\n\t"
        :
        : "m"(*(const char*)ptr)
        : "memory"
    );
}

__attribute__((target("rdpid")))
static inline uint32_t qihse_rdpid_raw(void) {
    unsigned long aux = 0;
    __asm__ volatile (
        "rdpid %0\n\t"
        : "=r"(aux)
    );
    return (uint32_t)aux;
}

#endif /* __x86_64__ */

/**
 * Clear a 64-byte cache line to zero.
 * Uses AMD CLZERO instruction if supported by hardware, otherwise falls back to memset(ptr, 0, 64).
 * @param ptr Pointer to 64-byte aligned (or 64-byte block) memory
 */
static inline void qihse_cache_zero_64(void* ptr) {
    if (!ptr) return;
#if defined(__x86_64__) || defined(_M_X64)
    qihse_cpu_feature_t feats = qihse_cpu_detect_features();
    if ((feats & QIHSE_CPU_FEATURE_CLZERO) && (((uintptr_t)ptr & 63u) == 0)) {
        qihse_clzero_raw(ptr);
        return;
    }
#endif
    memset(ptr, 0, 64);
}

/**
 * Write back modified cache line to memory without invalidating it from cache hierarchy.
 * Uses CLWB instruction if supported, falls back to CLFLUSHOPT/CLFLUSH, or no-op on non-x86.
 * @param ptr Pointer to memory line
 */
static inline void qihse_cache_writeback(const void* ptr) {
    if (!ptr) return;
#if defined(__x86_64__) || defined(_M_X64)
    qihse_cpu_feature_t feats = qihse_cpu_detect_features();
    if (feats & QIHSE_CPU_FEATURE_CLWB) {
        qihse_clwb_raw(ptr);
        return;
    }
    qihse_clflush_raw(ptr);
#endif
}

/**
 * Retrieve current logical CPU ID and optional NUMA node ID.
 * Uses RDPID instruction if supported, falls back to sched_getcpu().
 * @param node_id Pointer to store NUMA node ID (can be NULL)
 * @return CPU ID (non-negative)
 */
static inline int qihse_get_cpu_id(uint32_t* node_id) {
#if defined(__x86_64__) || defined(_M_X64)
    qihse_cpu_feature_t feats = qihse_cpu_detect_features();
    if (feats & QIHSE_CPU_FEATURE_RDPID) {
        uint32_t aux = qihse_rdpid_raw();
        if (node_id) {
            *node_id = aux >> 12;
        }
        return (int)(aux & 0xFFF);
    }
#endif
    int cpu = sched_getcpu();
    if (node_id) {
        *node_id = 0;
    }
    return cpu;
}

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CPU_CACHE_H */
