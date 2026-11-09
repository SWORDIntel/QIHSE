#ifndef QIHSE_CODEGRAPH_PACKED_H
#define QIHSE_CODEGRAPH_PACKED_H

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Authenticated reversible transform of qihse_kv_save_user's live-record
 * snapshot stream. The caller must own the complete authorized export and
 * verify the packed file against its trusted manifest before decoding.
 * Both FILE* outputs must be empty private staging files. Decode validates and
 * authorizes the entire input before writing a raw byte. Discard output after
 * any false return, including I/O failure or revocation while copying an
 * already validated stream. Final publication must use an authenticated
 * QIHSE KV load/open and an atomic manifest update. */
#define CG_PACKED_MAX_RAW_BYTES ((size_t)64u << 20)
#define CG_PACKED_MAX_RECORDS 2000000u
#define CG_PACKED_MAGIC "QCGP0002"

/* Shared by packed and compact writers. This affects build cost/ratio only;
 * readers accept the same format at every level. Override at build time when
 * measurements on a different workload justify another Zstd setting. */
#ifndef CG_CODEGRAPH_ZSTD_LEVEL
#define CG_CODEGRAPH_ZSTD_LEVEL 9
#endif

bool cg_packed_encode_snapshot(FILE *authorized_export, FILE *packed_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records);
bool cg_packed_decode_snapshot(FILE *packed_input, FILE *raw_output,
                               qihse_user_t *principal, size_t max_bytes,
                               size_t max_records);

/* Validate/authorize a packed snapshot and return a detached immutable store.
 * The internal reconstruction stream is consumed only by the principal-bound
 * KV parser; no buffered plaintext FILE is exposed. The caller must verify
 * the exact opened packed_input descriptor against trusted publication metadata
 * before and after this call, with identity/size/mtime/ctime invariance checks;
 * it must destroy the returned store on verification failure. Header labels
 * and Zstd checksums alone do not authenticate the record classification. Closing the
 * store clears its private snapshot. packed_input remains caller-owned.
 * raw_bytes is optional and written only on success. */
qihse_kv_store_t *cg_packed_open_snapshot_user(FILE *packed_input,
    qihse_user_t *principal, size_t max_bytes, size_t max_records, size_t *raw_bytes);

#endif
