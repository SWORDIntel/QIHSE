/*
 * qihse_vfs_page_cache.h — QIHSE KV-backed page cache for the SQLite VFS
 * ========================================================================
 *
 * Wraps qihse_kv_store_t (Black Hole LSM-tree) as a transparent read/write
 * cache for SQLite database pages.
 *
 * Key format  : printf("P%016" PRIx64, page_id)   — hex string, 17 chars
 * Value format: hex-encoded raw page bytes         — 2 * page_size chars
 *
 * NOTE: hex-encoding is an interim measure because qihse_kv_store currently
 * requires NULL-terminated string values.  When qihse_kv_set_binary() is
 * added to the Black Hole API this module should be updated to store raw
 * bytes directly, halving I/O cost.
 *
 * The cache is per-file-handle; no sharing between concurrent openers.
 */

#ifndef QIHSE_VFS_PAGE_CACHE_H
#define QIHSE_VFS_PAGE_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    qihse_kv_store_t* kv;        /* Black Hole KV store instance */
    uint32_t          page_size; /* SQLite page size (bytes); 0 until first write */
    uint64_t          file_size; /* Logical EOF in bytes */
} qihse_vfs_page_cache_t;

/*
 * qihse_vfs_cache_create — allocate and initialise a page cache.
 * Returns NULL on allocation failure.
 */
qihse_vfs_page_cache_t* qihse_vfs_cache_create(void);

/*
 * qihse_vfs_cache_destroy — flush pending state and free the cache.
 */
void qihse_vfs_cache_destroy(qihse_vfs_page_cache_t* cache);

/*
 * qihse_vfs_cache_get — read page_id into buf (size bytes).
 *
 * Returns true on cache hit; buf is populated with the cached page.
 * Returns false on cache miss; buf is unchanged.
 */
bool qihse_vfs_cache_get(qihse_vfs_page_cache_t* cache,
                          uint64_t page_id,
                          void* buf, size_t size);

/*
 * qihse_vfs_cache_put — write/update page_id in the cache with buf (size bytes).
 */
void qihse_vfs_cache_put(qihse_vfs_page_cache_t* cache,
                          uint64_t page_id,
                          const void* buf, size_t size);

/*
 * qihse_vfs_cache_evict_above — remove all cached pages with id >= cutoff_id.
 * Called after a TRUNCATE to keep the cache coherent with the shorter file.
 */
void qihse_vfs_cache_evict_above(qihse_vfs_page_cache_t* cache,
                                  uint64_t cutoff_id);

/*
 * qihse_vfs_cache_flush — mark the cache as clean.
 * The underlying KV WAL already guarantees persistence so no explicit flush
 * is required; this exists to reset the dirty state and keep the API complete.
 */
void qihse_vfs_cache_flush(qihse_vfs_page_cache_t* cache);

/*
 * qihse_vfs_cache_set_page_size — fix the page size from the SQLite header.
 * Must be called once when the page size is known (on first xWrite at offset 0).
 */
void qihse_vfs_cache_set_page_size(qihse_vfs_page_cache_t* cache,
                                    uint32_t page_size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_VFS_PAGE_CACHE_H */
