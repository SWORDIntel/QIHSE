/* SPDX-License-Identifier: MIT
 * Compile this same small adapter separately for each ISA. Upstream algorithm
 * is not modified. No global -march=native or forced unaligned pointer casts.
 */
#include "internal.h"
#define XXH_INLINE_ALL
#define XXH_VECTOR QX3_VECTOR
#include "xxhash.h"
#ifndef QX3_SYMBOL
#error QX3_SYMBOL and QX3_NAME must be supplied by the build
#endif
static qx3_hash128_t result(XXH128_hash_t h)
{ return (qx3_hash128_t){h.low64, h.high64}; }
static qx3_hash128_t hash128(const void *p, size_t n)
{ return result(XXH3_128bits(p, n)); }
static qx3_hash128_t seeded(const void *p, size_t n, uint64_t seed)
{ return result(XXH3_128bits_withSeed(p, n, seed)); }
static void batch(const qx3_span *spans, size_t count, qx3_hash128_t *out)
{
    /* Inline upstream short-input paths inside the loop; one dispatch/batch. */
    for (size_t i=0; i<count; ++i)
        out[i] = result(XXH3_128bits(spans[i].data, spans[i].size));
}
static void canonical_batch(const void *blob, const size_t *offsets, size_t count,
                            unsigned char *out)
{
    const unsigned char *bytes = blob;
    for (size_t i = 0; i < count; ++i) {
        XXH128_hash_t h = XXH3_128bits(bytes + offsets[i], offsets[i+1] - offsets[i]);
        qx3_store_be64(out+16*i, h.high64);
        qx3_store_be64(out+16*i+8, h.low64);
    }
}
static int reset(void *s, uint64_t seed)
{ return (int)XXH3_128bits_reset_withSeed((XXH3_state_t *)s, seed); }
static int update(void *s, const void *p, size_t n)
{ return (int)XXH3_128bits_update((XXH3_state_t *)s, p, n); }
static qx3_hash128_t digest(const void *s)
{ return result(XXH3_128bits_digest((const XXH3_state_t *)s)); }
static const qx3_stream_ops stream_ops = {reset, update, digest};
const qx3_backend QX3_SYMBOL = {QX3_NAME, hash128, seeded, batch, &stream_ops, canonical_batch};
