/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef QIHSE_CODEGRAPH_GENERATION_ADAPTER_H
#define QIHSE_CODEGRAPH_GENERATION_ADAPTER_H
#include "qihse_codegraph_generation.h"
#include "qihse_codegraph_storage.h"
/* Hold lifecycle EX for save, SH for open; scratch must be leased/private. */
/* Routing hint only; it never authorizes use of the source or exposes payload. */
bool cg_generation_path_user(const char *path, qihse_user_t *user);
bool cg_generation_store_save_user(qihse_kv_store_t *store, const char *path,
    const char *scratch, const char *blocks, qihse_user_t *user, cg_generation_info *out);
qihse_kv_store_t *cg_generation_store_open_user(const char *path,
    const char *scratch, const char *blocks, qihse_user_t *user,
    const cg_snapshot_checksum *expected, cg_storage_info_t *storage,
    cg_generation_info *generation);
#endif
