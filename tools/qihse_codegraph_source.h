/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_SOURCE_H
#define QIHSE_CODEGRAPH_SOURCE_H
#include "qihse_auth.h"
#include <stdbool.h>
#include <stdint.h>

#define CG_SOURCE_FILESYSTEM_POLICY "filesystem-content-v1"
#define CG_SOURCE_OVERLAY_POLICY "filesystem-overlay-content-v1"
#define CG_SOURCE_MAX_FILES 200000u
#define CG_SOURCE_MAX_FILE_BYTES (UINT64_C(256) << 20)
#define CG_SOURCE_MAX_TOTAL_BYTES (UINT64_C(8) << 30)
#define CG_SOURCE_MAX_OVERLAY_BYTES (16u << 20)
#define CG_SOURCE_MAX_OVERLAY_FILES 4096u

typedef struct {
    char digest[65];
    char disk_digest[65];
    char effective_digest[65];
    char overlay_digest[65]; /* Empty for filesystem-only identity. */
    uint64_t disk_files, disk_bytes, effective_files, effective_bytes;
} cg_source_identity;

/* Content identity for explicit source providers. Reads inherit caller-provided
 * labels and require an active authenticated principal before any file is read.
 * The caller must carry source labels from its authenticated source contract;
 * this function is not a way to infer labels from a filesystem pathname.
 * Fixed exclusions: .git and .code-review-graph at any depth. Symlinks and
 * special files fail closed. overlay_path must be an owner-private, single-link,
 * canonical version-1 overlay snapshot OUTSIDE the source root (Python writer
 * write_overlay_snapshot produces it). All paths and bytes are bounded.
 * Outputs are cleared on failure; no protected source bytes are returned. */
bool cg_source_identity_user(const char *root, const char *overlay_path, qihse_user_t *principal,
                             uint16_t classification, uint16_t sci, cg_source_identity *out);
#endif
