#ifndef QIHSE_CODEGRAPH_STORAGE_H
#define QIHSE_CODEGRAPH_STORAGE_H
#include <stdbool.h>
#include <stdint.h>
#include "qihse_kv_store.h"
#include "qihse_codegraph_checksum.h"
/* Populated only after the same open snapshot has passed authenticated load.
 * valid is false for legacy large-store fallback, whose path-based KV loader
 * cannot bind the metadata descriptor to the authenticated read. */
typedef struct {
    uint64_t encoded_bytes, allocated_bytes, decoded_bytes;
    uint64_t framing_encoded_bytes, metadata_encoded_bytes, body_encoded_bytes;
    uint64_t storage_chunks, storage_sections;
    bool section_accounting_valid;
    char sha256[65]; /* Compatibility: populated only for SHA-256. */
    cg_snapshot_checksum checksum;
    bool compact, packed, dictionary, chunked, generations, valid;
} cg_storage_info_t;
/* Authenticated compact snapshots. Legacy KV files remain readable. Temporary
 * KV serialization uses the caller's private QIHSE_DATA_DIR and is removed on
 * return. A new snapshot is atomically published only after compression succeeds. */
typedef enum { CG_STORAGE_ZSTD = 0, CG_STORAGE_PACKED = 1, CG_STORAGE_DICTIONARY = 2, CG_STORAGE_CHUNKED = 3, CG_STORAGE_GENERATIONS = 4 } cg_storage_format;
const char *cg_storage_format_name(cg_storage_format format);
bool cg_storage_save_chunked(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_save_dictionary(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_save_auto_format(qihse_kv_store_t *store, const char *path, qihse_user_t *principal, cg_storage_format *format);
bool cg_storage_save(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_save_packed(qihse_kv_store_t *store, const char *path,
                            qihse_user_t *principal);
/* Select the smallest complete Zstd/v2/v3/v4 candidate from one authenticated
 * export. Earlier formats win ties; v4 uses bounded chunks above the v2/v3 size limits.
 * Generations require an explicit block directory and are never auto-selected here.
 * Compatibility out_packed means v2, v3 OR v4, not specifically v2. Use the enum API
 * when the exact format matters. Outputs are written only on success. */
bool cg_storage_save_auto(qihse_kv_store_t *store, const char *path,
                          qihse_user_t *principal, bool *out_packed);
bool cg_storage_load(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_load_info(qihse_kv_store_t *store, const char *path,
                          qihse_user_t *principal, cg_storage_info_t *out);
bool cg_storage_load_verified_info(qihse_kv_store_t *store, const char *path,
                                   qihse_user_t *principal, const char *expected_sha,
                                   cg_storage_info_t *out);
/* Bounded reader returning a detached immutable store. V3 reconstruction uses
 * a private anonymous temporary stream; v2/Zstd avoid expanded disk copies. NULL errors:
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
bool cg_storage_load_checksum_info(qihse_kv_store_t *store, const char *path,
    qihse_user_t *principal, const cg_snapshot_checksum *expected, cg_storage_info_t *out);
qihse_kv_store_t *cg_storage_open_checksum_info(const char *path, qihse_user_t *principal,
    size_t max_bytes, size_t max_records, const cg_snapshot_checksum *expected, cg_storage_info_t *out);
#endif
