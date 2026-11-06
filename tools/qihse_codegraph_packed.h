#ifndef QIHSE_CODEGRAPH_PACKED_H
#define QIHSE_CODEGRAPH_PACKED_H

#include "qihse_auth.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Authenticated reversible transform of qihse_kv_save_user's live-record
 * snapshot stream. The caller must own the complete authorized export and
 * verify the packed file against its trusted manifest before decoding.
 * Both FILE* outputs must be empty private staging files. On authorization or
 * format failure, decode writes no raw bytes. Discard output after any false
 * return, including an I/O error. Final publication must use an authenticated
 * QIHSE KV load/open and an atomic manifest update. */
#define CG_PACKED_MAX_RAW_BYTES ((size_t)64u << 20)
#define CG_PACKED_MAX_RECORDS 2000000u
#define CG_PACKED_MAGIC "QCGP0002"

bool cg_packed_encode_snapshot(FILE *authorized_export, FILE *packed_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records);
bool cg_packed_decode_snapshot(FILE *packed_input, FILE *raw_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records);

#endif
