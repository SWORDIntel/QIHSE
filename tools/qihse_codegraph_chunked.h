/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_CHUNKED_H
#define QIHSE_CODEGRAPH_CHUNKED_H
#include "qihse_codegraph_checksum.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
/* QCGP0004: independent bounded chunks. Seven varint metadata columns,
 * exact header exceptions, and the lossless v3 token dictionary body are
 * compressed separately. Values/unknown fields retain exact bytes. The
 * complete source is checksum-bound using a private descriptor copy; labels
 * precede body decode. No output is published until complete validation.
 * Temporary disk use grows with the encoded and raw stream, not resident RAM.
 * Validation/admission failures leave output empty; callers must discard the
 * private output stage after any failure (including interrupted final copy). */
#define CG_CHUNKED_MAGIC "QCGP0004"
#define CG_CHUNKED_MAX_RAW_BYTES (UINT64_C(64) << 30)
#ifndef CG_CHUNKED_TARGET_RAW_BYTES
#define CG_CHUNKED_TARGET_RAW_BYTES (16u << 20)
#endif
#define CG_CHUNKED_MAX_CHUNK_BYTES (32u << 20)
#define CG_CHUNKED_MAX_RECORDS 16000000u
bool cg_chunked_encode_snapshot(FILE *input, FILE *output, qihse_user_t *principal,
                                size_t max_bytes, size_t max_records);
bool cg_chunked_decode_checksum_snapshot(FILE *input, FILE *output, qihse_user_t *principal,
                                         const cg_snapshot_checksum *expected, size_t max_bytes,
                                         size_t max_records);
#endif
