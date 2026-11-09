/* SPDX-License-Identifier: MIT
 * Standard XXH3-128, with explicitly selected runtime-safe backends.
 * One-shot/batch hot paths require valid arguments, like upstream xxHash.
 */
#ifndef QIHSE_XXH3_H
#define QIHSE_XXH3_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint64_t low64, high64; } qx3_hash128_t;
typedef struct { const void *data; size_t size; } qx3_span;
typedef qx3_hash128_t (*qx3_hash_fn)(const void *, size_t);
typedef qx3_hash128_t (*qx3_seed_fn)(const void *, size_t, uint64_t);
typedef void (*qx3_canonical_batch_fn)(const void *, const size_t *, size_t, unsigned char *);
typedef void (*qx3_batch_fn)(const qx3_span *, size_t, qx3_hash128_t *);
typedef struct qx3_backend {
    const char *name;
    qx3_hash_fn hash128;
    qx3_seed_fn hash128_seed;
    qx3_batch_fn batch128;
    const void *_stream_ops; /* private; do not modify the returned descriptor */
    qx3_canonical_batch_fn _canonical_batch; /* private module ABI v2 */
} qx3_backend;
typedef struct qx3_stream qx3_stream;

/* Select once, outside hot loops. NULL/"auto": widest supported backend.
 * "scalar", "sse2", "avx2", "avx512" are explicit and safely checked.
 * Returns NULL and sets errno to EINVAL (name) or ENOTSUP (unavailable).
 * No mutable process-global dispatch state. Descriptors are immutable.
 */
const qx3_backend *qx3_backend_get(const char *name);
const char *qx3_version(void);

/* Allocation-free; input may be NULL only for size==0. Backend must be valid.
 * Return native numeric words. For storage/network bytes use qx3_canonical().
 */
static inline qx3_hash128_t qx3_hash128(const qx3_backend *b, const void *p, size_t n)
{ return b->hash128(p, n); }
static inline qx3_hash128_t qx3_hash128_seed(const qx3_backend *b, const void *p,
                                         size_t n, uint64_t seed)
{ return b->hash128_seed(p, n, seed); }
/* count==0 allows NULL arrays; otherwise arrays and every span must be valid.
 * Output must not overlap descriptors or any input span. No multi-message
 * hash construction: each output equals the ordinary one-shot hash.
 */
static inline void qx3_batch128(const qx3_backend *b, const qx3_span *spans,
                              size_t count, qx3_hash128_t *out)
{ b->batch128(spans, count, out); }

/* Checked FFI adapters. Data and output ranges must be valid objects. Offsets
 * contains count+1 elements, starts at zero, ends at blob_size, and is monotonic.
 * Empty batches permit NULL arrays with blob_size==0. Backend is always required.
 * Output must not overlap the blob or offsets. Invalid lengths/overlap return -1
 * before writing output. No allocation; one canonical backend dispatch per batch.
 * These functions hash caller-supplied bytes, not classified QIHSE store records. */
int qx3_hash_canonical128(const qx3_backend *b, const void *data, size_t size,
                          unsigned char out[16]);
int qx3_batch_canonical128(const qx3_backend *b, const void *blob, size_t blob_size,
                           const size_t *offsets, size_t count, unsigned char *out);

/* Canonical upstream byte order: BE64(high64) || BE64(low64), NOT struct bytes. */
void qx3_canonical(qx3_hash128_t h, unsigned char out[16]);
void qx3_hex(qx3_hash128_t h, char out[33]);

/* One aligned allocation per stream; reset/reuse to avoid per-file allocation.
 * Updates/digests allocate nothing. A stream is single-writer; independent
 * streams and one-shot calls can share the same immutable backend.
 * reset/update return 0 on success, -1 with errno on invalid input/overflow.
 * digest is non-destructive; NULL returns an all-zero value and sets EINVAL.
 * Non-NULL state must be valid. Total length <= UINT64_MAX.
 */
qx3_stream *qx3_stream_create(const qx3_backend *b, uint64_t seed);
void qx3_stream_free(qx3_stream *s);
int qx3_stream_reset(qx3_stream *s, uint64_t seed);
int qx3_stream_update(qx3_stream *s, const void *p, size_t n);
qx3_hash128_t qx3_stream_digest(const qx3_stream *s);

#ifdef __cplusplus
}
#endif
#endif
