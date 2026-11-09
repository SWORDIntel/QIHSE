/* SPDX-License-Identifier: MIT */
#ifndef QX3_INTERNAL_H
#define QX3_INTERNAL_H
#include "qihse_xxh3.h"
#include <string.h>
static inline void qx3_store_be64(unsigned char *out, uint64_t value)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && (defined(__GNUC__) || defined(__clang__))
    value = __builtin_bswap64(value);
    memcpy(out, &value, sizeof value);
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    memcpy(out, &value, sizeof value);
#else
    for (unsigned i=0;i<8;++i) out[i]=(unsigned char)(value >> (56-8*i));
#endif
}
typedef struct {
    int (*reset)(void *, uint64_t);
    int (*update)(void *, const void *, size_t);
    qx3_hash128_t (*digest)(const void *);
} qx3_stream_ops;
extern const qx3_backend qx3_backend_scalar;
#ifdef QX3_X86_MULTI
extern const qx3_backend qx3_backend_sse2;
extern const qx3_backend qx3_backend_avx2;
extern const qx3_backend qx3_backend_avx512;
#endif
#endif
