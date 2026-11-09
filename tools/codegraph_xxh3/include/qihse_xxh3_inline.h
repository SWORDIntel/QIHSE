/* SPDX-License-Identifier: MIT
 * Optional: include in performance-sensitive translation units compiled -O3.
 * Constant small lengths can then be folded at the call site. Long inputs keep
 * runtime dispatch. Do not globally compile distributable binaries -march=native.
 */
#ifndef QIHSE_XXH3_INLINE_H
#define QIHSE_XXH3_INLINE_H
#include "qihse_xxh3.h"
#ifndef XXH_INLINE_ALL
#define XXH_INLINE_ALL
#define QX3_UNDEF_INLINE_ALL
#endif
#include "../vendor/xxhash.h"
#ifdef QX3_UNDEF_INLINE_ALL
#undef XXH_INLINE_ALL
#undef QX3_UNDEF_INLINE_ALL
#endif
static inline qx3_hash128_t qx3_hash128_inline(const qx3_backend *b,
                                            const void *p, size_t n)
{
    if (n <= 240) {
        XXH128_hash_t h = XXH3_128bits(p, n);
        qx3_hash128_t out = {h.low64, h.high64};
        return out;
    }
    return b->hash128(p, n);
}
static inline qx3_hash128_t qx3_hash128_seed_inline(const qx3_backend *b,
                                                 const void *p, size_t n,
                                                 uint64_t seed)
{
    if (n <= 240) {
        XXH128_hash_t h = XXH3_128bits_withSeed(p, n, seed);
        qx3_hash128_t out = {h.low64, h.high64};
        return out;
    }
    return b->hash128_seed(p, n, seed);
}
#endif
