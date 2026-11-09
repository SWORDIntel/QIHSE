#ifndef QIHSE_CODEGRAPH_DICTIONARY_H
#define QIHSE_CODEGRAPH_DICTIONARY_H
#include "qihse_auth.h"
#include "qihse_codegraph_checksum.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

/* Lossless packed-v3 dictionary codec. Decoder requires a trusted manifest
 * digest and parses only an immutable copy of the same descriptor bytes it
 * verified. Caller stdio caches/pushback are ignored.
 * Label access is checked before body decompression; no bytes are emitted until all
 * records pass validation and the explicit principal is still authorized.
 * Output streams must be empty private staging files. Discard after failure. */
#define CG_DICTIONARY_MAX_RAW_BYTES ((size_t)64u << 20)
#define CG_DICTIONARY_MAX_TOKEN_BYTES ((size_t)128u << 20)
#define CG_DICTIONARY_MAX_RECORDS 2000000u
#define CG_DICTIONARY_MAX_TOKENS 2000000u
#define CG_DICTIONARY_MAGIC "QCGP0003"
/* Big-endian feature mask at outer offset 44. Bit 0 permits dictionary kind 2:
 * exactly 16 binary bytes reconstructing 32 lowercase hex bytes. Kind 1 remains
 * 32 binary bytes / 64 hex. Writers leave the mask zero for legacy-only input;
 * older readers reject the feature bit before decoding. Unknown bits fail closed.
 * The explicitly selected snapshot checksum covers this mask and encoded bytes.
 * XXH3 detects ordinary corruption; it is not a cryptographic authenticator. */
#define CG_DICTIONARY_FEATURE_DIGEST128 UINT32_C(1)
bool cg_dictionary_encode_snapshot(FILE *authorized_export, FILE *encoded_output,
                                qihse_user_t *principal, size_t max_bytes,
                                size_t max_records);
bool cg_dictionary_decode_snapshot(FILE *encoded_input, FILE *raw_output,
                                qihse_user_t *principal, const char *expected_sha256,
                                size_t max_bytes,
                                size_t max_records);
bool cg_dictionary_decode_checksum_snapshot(FILE *input, FILE *output,
    qihse_user_t *principal, const cg_snapshot_checksum *expected,
    size_t max_bytes, size_t max_records);
#endif
