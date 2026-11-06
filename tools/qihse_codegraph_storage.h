#ifndef QIHSE_CODEGRAPH_STORAGE_H
#define QIHSE_CODEGRAPH_STORAGE_H
#include <stdbool.h>
#include <stdint.h>
#include "qihse_kv_store.h"
/* Populated only after the same open snapshot has passed authenticated load.
 * valid is false for legacy large-store fallback, whose path-based KV loader
 * cannot bind the metadata descriptor to the authenticated read. */
typedef struct {
    uint64_t encoded_bytes, allocated_bytes, decoded_bytes;
    char sha256[65];
    bool compact, packed, valid;
} cg_storage_info_t;
/* Authenticated compact snapshots. Legacy KV files remain readable. Temporary
 * KV serialization uses the caller's private QIHSE_DATA_DIR and is removed on
 * return. A new snapshot is atomically published only after compression succeeds. */
bool cg_storage_save(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_save_packed(qihse_kv_store_t *store, const char *path,
                            qihse_user_t *principal);
bool cg_storage_load(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_load_info(qihse_kv_store_t *store, const char *path,
                          qihse_user_t *principal, cg_storage_info_t *out);
bool cg_storage_load_verified_info(qihse_kv_store_t *store, const char *path,
                                   qihse_user_t *principal, const char *expected_sha,
                                   cg_storage_info_t *out);
/* Bounded no-disk reader. Returns a detached immutable store. NULL errors:
 * EFBIG/E2BIG only for limits, EACCES for authorization, EINVAL malformed.
 * Large callers may explicitly fall back to cg_storage_load on limits. */
qihse_kv_store_t *cg_storage_open(const char *path, qihse_user_t *principal,
                                 size_t max_bytes, size_t max_records);
qihse_kv_store_t *cg_storage_open_info(const char *path, qihse_user_t *principal,
                                      size_t max_bytes, size_t max_records,
                                      cg_storage_info_t *out);
qihse_kv_store_t *cg_storage_open_verified_info(const char *path,
    qihse_user_t *principal, size_t max_bytes, size_t max_records,
    const char *expected_sha, cg_storage_info_t *out);
#endif
