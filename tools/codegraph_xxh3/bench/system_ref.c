/* SPDX-License-Identifier: MIT
 * Separate translation unit: use the installed shared xxHash library, not
 * XXH_INLINE_ALL. It is a reference/comparison, never a module dependency.
 */
#include "qihse_xxh3.h"
#include <xxhash.h>
qx3_hash128_t system_hash(const void *p, size_t n)
{
    XXH128_hash_t h=XXH3_128bits(p,n);
    return (qx3_hash128_t){h.low64,h.high64};
}
qx3_hash128_t system_seed(const void *p, size_t n, uint64_t seed)
{
    XXH128_hash_t h=XXH3_128bits_withSeed(p,n,seed);
    return (qx3_hash128_t){h.low64,h.high64};
}
unsigned system_version(void) { return XXH_versionNumber(); }
void system_canonical(qx3_hash128_t h, unsigned char out[16])
{
    XXH128_canonical_t c; XXH128_hash_t v={h.low64,h.high64};
    XXH128_canonicalFromHash(&c,v);
    for (unsigned i=0; i<16; ++i) out[i]=c.digest[i];
}
