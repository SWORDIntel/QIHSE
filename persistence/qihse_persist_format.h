/*
 * QIHSE persistence format helpers.
 *
 * These functions intentionally avoid native struct serialization. All
 * multi-byte values are encoded little-endian on disk.
 */

#ifndef QIHSE_PERSIST_FORMAT_H
#define QIHSE_PERSIST_FORMAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_PERSIST_FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define QIHSE_PERSIST_FNV1A64_PRIME  UINT64_C(1099511628211)

void qihse_le_write_u32(uint8_t out[4], uint32_t value);
void qihse_le_write_u64(uint8_t out[8], uint64_t value);
uint32_t qihse_le_read_u32(const uint8_t in[4]);
uint64_t qihse_le_read_u64(const uint8_t in[8]);

uint64_t qihse_fnv1a64_init(void);
uint64_t qihse_fnv1a64_update(uint64_t hash, const void* data, size_t size);
uint64_t qihse_fnv1a64(const void* data, size_t size);

/*
 * Parallel FNV-1a for large buffers.
 *
 * Splits the buffer into nthreads chunks, computes FNV-1a on each
 * independently (each from the offset basis), then XORs the per-chunk
 * hashes. This is NOT the same value as sequential qihse_fnv1a64() —
 * it's a distinct "parallel fingerprint" that must be stored and
 * verified as such.
 *
 * For production integrity where the on-disk CRC was written by the
 * sequential qihse_fnv1a64(), use qihse_fnv1a64_parallel_verify()
 * instead, which computes the sequential hash in parallel chunks
 * and combines them correctly.
 *
 * Returns the parallel fingerprint, or 0 on error.
 */
uint64_t qihse_fnv1a64_parallel(const void* data, size_t size, int nthreads);

/*
 * Verify a sequential FNV-1a hash in parallel.
 *
 * Computes the same value as qihse_fnv1a64(data, size) but uses
 * multiple threads. Each chunk's partial hash is folded into the
 * running hash by re-applying the FNV-1a multiply-XOR step on the
 * chunk's final hash value.
 *
 * This produces the EXACT same result as the sequential version,
 * so it can verify existing on-disk CRCs written by qihse_fnv1a64().
 *
 * Returns the verified hash, or 0 on error.
 */
uint64_t qihse_fnv1a64_parallel_verify(const void* data, size_t size, int nthreads);

bool qihse_checked_add_size(size_t a, size_t b, size_t* out);
bool qihse_checked_mul_size(size_t a, size_t b, size_t* out);
bool qihse_checked_add_u64(uint64_t a, uint64_t b, uint64_t* out);
bool qihse_checked_mul_u64(uint64_t a, uint64_t b, uint64_t* out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_PERSIST_FORMAT_H */
