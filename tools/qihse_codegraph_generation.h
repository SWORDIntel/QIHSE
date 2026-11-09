/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_GENERATION_H
#define QIHSE_CODEGRAPH_GENERATION_H
#include "qihse_auth.h"
#include "qihse_codegraph_checksum.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CG_GENERATION_MAGIC "QCGG0001"
#define CG_GENERATION_MAX_RECORDS 2000000u
#define CG_GENERATION_MAX_BLOCKS 65536u
#define CG_GENERATION_MAX_SCAN_ENTRIES (4u * CG_GENERATION_MAX_BLOCKS)
#define CG_GENERATION_MAX_RAW_BYTES (UINT64_C(4) << 30)
#define CG_GENERATION_MAX_BLOCK_BYTES ((size_t)32u << 20)

typedef struct {
  uint64_t parent_bytes, block_bytes, new_block_bytes, reused_block_bytes;
  uint64_t raw_bytes;
  uint32_t blocks, new_blocks, reused_blocks, records;
} cg_generation_info;

typedef struct {
  FILE *parent;
  cg_snapshot_checksum checksum;
} cg_generation_root;

/* Immutable per-source-file block generations. Streams are caller-private.
 * Input must be an authenticated KV export; every label is checked again here.
 * Headers (including exact formatting, sequence and extension fields) live in
 * the parent; key/value and immutable metadata live in reusable file blocks.
 * These functions do not publish the parent. The caller must hold the native
 * lifecycle lock EX for encode/GC and SH for decode, fsync+publish the parent,
 * then GC with BOTH current and previous committed roots. Orphans after an
 * interrupted write are safe and reclaimed only by that validated-root GC.
 * No caller may read a block directly to bypass its parent and labels. */
bool cg_generation_encode_snapshot(FILE *authorized_export, FILE *parent_output,
                                   const char *block_directory,
                                   qihse_user_t *principal, uint64_t max_bytes,
                                   size_t max_records,
                                   cg_generation_info *info);
bool cg_generation_decode_snapshot(FILE *parent_input, FILE *raw_output,
                                   const char *block_directory,
                                   qihse_user_t *principal,
                                   const cg_snapshot_checksum *expected,
                                   uint64_t max_bytes, size_t max_records,
                                   cg_generation_info *info);
/* Fully validate every retained root and block before deleting anything.
 * roots may contain zero, one or two entries. NULL principal always denies.
 * Invalid/missing/denied roots leave all blocks untouched. Unknown filenames,
 * symlinks, non-private files and files owned by others are never removed.
 * Strictly named private pending-write artifacts may be reclaimed only by a
 * fully cleared system Operator, since partial frames cannot prove narrower
 * authorization. */
bool cg_generation_gc(const char *block_directory, qihse_user_t *principal,
                      const cg_generation_root *roots, size_t root_count,
                      size_t *removed_blocks, uint64_t *removed_bytes);
typedef struct {
  uint64_t referenced_bytes, referenced_allocated_bytes;
  uint64_t orphan_bytes, orphan_allocated_bytes;
  uint32_t referenced_blocks, orphan_blocks;
  bool coverage_complete;
} cg_generation_account;
/* Authenticated read-only union accounting for current/previous roots. Unknown
 * or inaccessible orphan blocks are excluded and set coverage_complete=false;
 * no names, protected counts or payloads are returned. Invalid retained roots
 * fail with no result. Call under the shared lifecycle lock. */
bool cg_generation_account_user(const char *block_directory,
                                qihse_user_t *principal,
                                const cg_generation_root *roots,
                                size_t root_count, cg_generation_account *out);
#endif
