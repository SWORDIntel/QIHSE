#ifndef QIHSE_CODEGRAPH_STORAGE_H
#define QIHSE_CODEGRAPH_STORAGE_H
#include <stdbool.h>
#include "qihse_kv_store.h"
/* Authenticated compact snapshots. Legacy KV files remain readable. Temporary
 * KV serialization uses the caller's private QIHSE_DATA_DIR and is removed on
 * return. A new snapshot is atomically published only after compression succeeds. */
bool cg_storage_save(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
bool cg_storage_load(qihse_kv_store_t *store, const char *path, qihse_user_t *principal);
#endif
