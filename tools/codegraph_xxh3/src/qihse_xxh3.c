/* SPDX-License-Identifier: MIT */
#include "internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define XXH_STATIC_LINKING_ONLY
#include "xxhash.h"
#ifdef QX3_X86_MULTI
#include <cpuid.h>
#endif

struct qx3_stream {
    const qx3_stream_ops *ops;
    uint64_t total;
    XXH3_state_t state;
};
_Static_assert(_Alignof(struct qx3_stream) >= 64, "xxHash state must be aligned");
_Static_assert(sizeof(struct qx3_stream) % 64 == 0, "aligned_alloc size");

const char *qx3_version(void) { return "qihse-xxh3-tuned/2 xxhash/0.8.3"; }

#ifdef QX3_X86_MULTI
static unsigned capabilities(void)
{
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    unsigned caps = (d & bit_SSE2) ? 1U : 0U;
    if (!(c & bit_OSXSAVE) || !(c & bit_AVX)) return caps;
    unsigned lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    (void)hi;
    if ((lo & 6U) != 6U || !__get_cpuid_count(7, 0, &a, &b, &c, &d)) return caps;
    if (b & bit_AVX2) caps |= 2U;
    if ((caps & 2U) && (lo & 0xe6U) == 0xe6U && (b & bit_AVX512F) &&
        (b & bit_AVX512BW) && (b & bit_AVX512DQ)) caps |= 4U;
    return caps;
}
#endif
const qx3_backend *qx3_backend_get(const char *name)
{
    if (!name) name = "auto";
#ifdef QX3_X86_MULTI
    unsigned caps = capabilities();
    if (!strcmp(name, "auto")) {
        if (caps & 4U) return &qx3_backend_avx512;
        if (caps & 2U) return &qx3_backend_avx2;
        if (caps & 1U) return &qx3_backend_sse2;
        return &qx3_backend_scalar;
    }
    if (!strcmp(name, "sse2") && (caps & 1U)) return &qx3_backend_sse2;
    if (!strcmp(name, "avx2") && (caps & 2U)) return &qx3_backend_avx2;
    if (!strcmp(name, "avx512") && (caps & 4U)) return &qx3_backend_avx512;
#else
    if (!strcmp(name, "auto")) return &qx3_backend_scalar;
#endif
    if (!strcmp(name, "scalar")) return &qx3_backend_scalar;
    errno = (!strcmp(name,"avx512") || !strcmp(name,"avx2") || !strcmp(name,"sse2"))
          ? ENOTSUP : EINVAL;
    return NULL;
}
void qx3_canonical(qx3_hash128_t h, unsigned char out[16])
{
    qx3_store_be64(out, h.high64);
    qx3_store_be64(out+8, h.low64);
}
void qx3_hex(qx3_hash128_t h, char out[33])
{
    static const char digits[] = "0123456789abcdef";
    unsigned char bytes[16];
    qx3_canonical(h, bytes);
    for (unsigned i=0; i<16; ++i) {
        out[2*i] = digits[bytes[i] >> 4]; out[2*i+1] = digits[bytes[i] & 15];
    }
    out[32] = '\0';
}
qx3_stream *qx3_stream_create(const qx3_backend *b, uint64_t seed)
{
    if (!b) { errno=EINVAL; return NULL; }
    qx3_stream *s = aligned_alloc(64, sizeof(*s));
    if (!s) return NULL;
    memset(s, 0, sizeof(*s));
    s->ops = (const qx3_stream_ops *)b->_stream_ops;
    if (qx3_stream_reset(s, seed)) { free(s); return NULL; }
    return s;
}
void qx3_stream_free(qx3_stream *s) { free(s); }
int qx3_stream_reset(qx3_stream *s, uint64_t seed)
{
    if (!s) { errno=EINVAL; return -1; }
    if (s->ops->reset(&s->state, seed)) { errno=EINVAL; return -1; }
    s->total=0; return 0;
}
int qx3_stream_update(qx3_stream *s, const void *p, size_t n)
{
    if (!s || (!p && n)) { errno=EINVAL; return -1; }
    if (n > UINT64_MAX - s->total) { errno=EOVERFLOW; return -1; }
    if (!n) return 0;
    if (s->ops->update(&s->state, p, n)) { errno=EINVAL; return -1; }
    s->total += n; return 0;
}
qx3_hash128_t qx3_stream_digest(const qx3_stream *s)
{
    if (!s) { errno = EINVAL; return (qx3_hash128_t){0,0}; }
    return s->ops->digest(&s->state);
}

/* Integer range checks avoid undefined relational comparisons between unrelated
 * pointers. Callers still supply valid object ranges, as with memcpy/xxHash. */
static int range_overlaps(const void *a, size_t an, const void *b, size_t bn)
{
    if (!an || !bn) return 0;
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (an > UINTPTR_MAX - x || bn > UINTPTR_MAX - y) return 1;
    return x < y + bn && y < x + an;
}
int qx3_hash_canonical128(const qx3_backend *b, const void *data, size_t size,
                          unsigned char out[16])
{
    if (!b || !out || (!data && size) || range_overlaps(data, size, out, 16)) {
        errno = EINVAL; return -1;
    }
    static const unsigned char empty = 0;
    qx3_canonical(b->hash128(data ? data : &empty, size), out);
    return 0;
}
int qx3_batch_canonical128(const qx3_backend *b, const void *blob, size_t blob_size,
                           const size_t *offsets, size_t count, unsigned char *out)
{
    if (!b || (!blob && blob_size)) { errno = EINVAL; return -1; }
    if (!count) {
        if (blob_size) { errno = EINVAL; return -1; }
        return 0;
    }
    if (count > SIZE_MAX / 16 || count > SIZE_MAX / sizeof(size_t) - 1) {
        errno = EOVERFLOW; return -1;
    }
    if (!offsets || !out || range_overlaps(blob, blob_size, out, count*16) ||
        range_overlaps(offsets, (count+1)*sizeof(size_t), out, count*16)) {
        errno = EINVAL; return -1;
    }
    if (offsets[0] || offsets[count] != blob_size) { errno = EINVAL; return -1; }
    for (size_t i = 0; i < count; ++i)
        if (offsets[i] > offsets[i+1] || offsets[i+1] > blob_size) {
            errno = EINVAL; return -1;
        }
    static const unsigned char empty = 0;
    b->_canonical_batch(blob ? blob : &empty, offsets, count, out);
    return 0;
}
