#ifndef QIHSE_ENDIAN_H
#define QIHSE_ENDIAN_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QIHSE Endian Primitives
 * Clean, zero-overhead inline big-endian and little-endian load/store primitives.
 *
 * On x86-64 when __MOVBE__ is defined or under target("movbe"),
 * big-endian load/store emit single-cycle hardware MOVBE instructions (movbew, movbel, movbeq)
 * for unaligned access with zero register spills.
 * Portable fallback uses memcpy with compiler bswap builtins (__builtin_bswap16/32/64)
 * ensuring strict alignment safety and auto-vectorization across all architectures.
 */

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__MOVBE__) || defined(__movbe__))

static inline uint16_t qihse_load_be16(const void* ptr) {
    uint16_t val;
    __asm__ ("movbew %1, %0" : "=r"(val) : "m"(*(const uint16_t*)ptr));
    return val;
}

static inline uint32_t qihse_load_be32(const void* ptr) {
    uint32_t val;
    __asm__ ("movbel %1, %0" : "=r"(val) : "m"(*(const uint32_t*)ptr));
    return val;
}

static inline uint64_t qihse_load_be64(const void* ptr) {
    uint64_t val;
    __asm__ ("movbeq %1, %0" : "=r"(val) : "m"(*(const uint64_t*)ptr));
    return val;
}

static inline void qihse_store_be16(void* ptr, uint16_t val) {
    __asm__ ("movbew %1, %0" : "=m"(*(uint16_t*)ptr) : "r"(val));
}

static inline void qihse_store_be32(void* ptr, uint32_t val) {
    __asm__ ("movbel %1, %0" : "=m"(*(uint32_t*)ptr) : "r"(val));
}

static inline void qihse_store_be64(void* ptr, uint64_t val) {
    __asm__ ("movbeq %1, %0" : "=m"(*(uint64_t*)ptr) : "r"(val));
}

#else

static inline uint16_t qihse_load_be16(const void* ptr) {
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
    return __builtin_bswap16(v);
}

static inline uint32_t qihse_load_be32(const void* ptr) {
    uint32_t v;
    memcpy(&v, ptr, sizeof(v));
    return __builtin_bswap32(v);
}

static inline uint64_t qihse_load_be64(const void* ptr) {
    uint64_t v;
    memcpy(&v, ptr, sizeof(v));
    return __builtin_bswap64(v);
}

static inline void qihse_store_be16(void* ptr, uint16_t val) {
    uint16_t s = __builtin_bswap16(val);
    memcpy(ptr, &s, sizeof(s));
}

static inline void qihse_store_be32(void* ptr, uint32_t val) {
    uint32_t s = __builtin_bswap32(val);
    memcpy(ptr, &s, sizeof(s));
}

static inline void qihse_store_be64(void* ptr, uint64_t val) {
    uint64_t s = __builtin_bswap64(val);
    memcpy(ptr, &s, sizeof(s));
}

#endif

/* Standard intrinsic aliases for MOVBE compatibility */
#ifndef _loadbe_i16
#define _loadbe_i16(p)    ((int16_t)qihse_load_be16(p))
#endif
#ifndef _loadbe_i32
#define _loadbe_i32(p)    ((int32_t)qihse_load_be32(p))
#endif
#ifndef _loadbe_i64
#define _loadbe_i64(p)    ((int64_t)qihse_load_be64(p))
#endif
#ifndef _storebe_i16
#define _storebe_i16(p, v) qihse_store_be16((p), (uint16_t)(v))
#endif
#ifndef _storebe_i32
#define _storebe_i32(p, v) qihse_store_be32((p), (uint32_t)(v))
#endif
#ifndef _storebe_i64
#define _storebe_i64(p, v) qihse_store_be64((p), (uint64_t)(v))
#endif

/* Clean little-endian load/store primitives */
static inline uint16_t qihse_load_le16(const void* ptr) {
    uint16_t v;
    memcpy(&v, ptr, sizeof(v));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap16(v);
#else
    return v;
#endif
}

static inline uint32_t qihse_load_le32(const void* ptr) {
    uint32_t v;
    memcpy(&v, ptr, sizeof(v));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap32(v);
#else
    return v;
#endif
}

static inline uint64_t qihse_load_le64(const void* ptr) {
    uint64_t v;
    memcpy(&v, ptr, sizeof(v));
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

static inline void qihse_store_le16(void* ptr, uint16_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    uint16_t s = __builtin_bswap16(val);
    memcpy(ptr, &s, sizeof(s));
#else
    memcpy(ptr, &val, sizeof(val));
#endif
}

static inline void qihse_store_le32(void* ptr, uint32_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    uint32_t s = __builtin_bswap32(val);
    memcpy(ptr, &s, sizeof(s));
#else
    memcpy(ptr, &val, sizeof(val));
#endif
}

static inline void qihse_store_le64(void* ptr, uint64_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    uint64_t s = __builtin_bswap64(val);
    memcpy(ptr, &s, sizeof(s));
#else
    memcpy(ptr, &val, sizeof(val));
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_ENDIAN_H */
