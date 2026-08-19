/*
 * qihse_vfs_page_cache.c — QIHSE KV-backed SQLite page cache
 * ===========================================================
 *
 * Implements the page-cache layer defined in qihse_vfs_page_cache.h.
 *
 * Page keys are formatted as printf("P%016" PRIx64, page_id) — a 17-byte
 * null-terminated hex string that can be stored directly in the trinary-trie
 * KV store without any binary encoding.
 *
 * Page values are hex-encoded raw bytes (2 chars per byte + NUL).  This is
 * an interim measure until qihse_kv_set_binary() is available in the Black
 * Hole API.
 *
 * The KV store is configured with classification 0 / SCI 0 so no auth
 * checks are performed on page reads; the caller (the VFS) is trusted.
 */

#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 200809L
#endif

#include "qihse_vfs_page_cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* Format the KV key for a given page number into key_buf (must be >= 18 bytes). */
static void fmt_page_key(char* key_buf, uint64_t page_id)
{
    snprintf(key_buf, 18, "P%016" PRIx64, page_id);
}

/* Hex-encode src[0..len) into dst (must be >= 2*len+1 bytes). */
static void hex_encode(const uint8_t* src, size_t len, char* dst)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = hex[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex[src[i] & 0xF];
    }
    dst[len * 2] = '\0';
}

/* Hex-decode src (len hex chars) into dst.  Returns false on bad input. */
static bool hex_decode(const char* src, size_t hex_len, uint8_t* dst)
{
    if (hex_len & 1u) return false;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi, lo;
        /* high nibble */
        char c = src[i];
        if      (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return false;
        /* low nibble */
        c = src[i + 1];
        if      (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return false;
        dst[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

qihse_vfs_page_cache_t* qihse_vfs_cache_create(void)
{
    qihse_vfs_page_cache_t* c =
        (qihse_vfs_page_cache_t*)calloc(1, sizeof(qihse_vfs_page_cache_t));
    if (!c) return NULL;

    c->kv = qihse_kv_store_create();
    if (!c->kv) {
        free(c);
        return NULL;
    }
    c->page_size = 0u;   /* unknown until first write */
    c->file_size = 0u;

    return c;
}

void qihse_vfs_cache_destroy(qihse_vfs_page_cache_t* cache)
{
    if (!cache) return;
    if (cache->kv) {
        qihse_kv_store_destroy(cache->kv);
        cache->kv = NULL;
    }
    free(cache);
}

/* ── Page size ───────────────────────────────────────────────────────────── */

void qihse_vfs_cache_set_page_size(qihse_vfs_page_cache_t* cache,
                                    uint32_t page_size)
{
    if (!cache || cache->page_size != 0u) return;  /* immutable once set */
    if (page_size >= 512u && page_size <= 65536u &&
        (page_size & (page_size - 1u)) == 0u)
    {
        cache->page_size = page_size;
    }
}

/* ── Cache get ───────────────────────────────────────────────────────────── */

bool qihse_vfs_cache_get(qihse_vfs_page_cache_t* cache,
                          uint64_t page_id,
                          void* buf, size_t size)
{
    if (!cache || !cache->kv || !buf || size == 0u) return false;

    char key[18];
    fmt_page_key(key, page_id);

    /* qihse_kv_get_user with NULL user → uses OPERATOR access (classification 0). */
    char* hex_val = qihse_kv_get_user(cache->kv, key, NULL);
    if (!hex_val) return false;

    size_t hex_len = strlen(hex_val);
    /* Each byte is two hex chars; the decoded size must match the requested size. */
    if (hex_len != size * 2u) {
        free(hex_val);
        return false;
    }

    bool ok = hex_decode(hex_val, hex_len, (uint8_t*)buf);
    free(hex_val);
    return ok;
}

/* ── Cache put ───────────────────────────────────────────────────────────── */

void qihse_vfs_cache_put(qihse_vfs_page_cache_t* cache,
                          uint64_t page_id,
                          const void* buf, size_t size)
{
    if (!cache || !cache->kv || !buf || size == 0u) return;

    /* Allocate hex-encoded value buffer: 2 chars per byte + NUL. */
    char* hex_val = (char*)malloc(size * 2u + 1u);
    if (!hex_val) return;

    hex_encode((const uint8_t*)buf, size, hex_val);

    char key[18];
    fmt_page_key(key, page_id);

    qihse_kv_set(cache->kv, key, hex_val, 0u, 0u);
    free(hex_val);
}

/* ── Evict above ─────────────────────────────────────────────────────────── */

void qihse_vfs_cache_evict_above(qihse_vfs_page_cache_t* cache,
                                  uint64_t cutoff_id)
{
    if (!cache || !cache->kv) return;

    /*
     * The KV store has no range-delete API yet.  We scan pages starting at
     * cutoff_id upwards until we fail to find a key.  This is O(n) over the
     * number of pages to evict — acceptable since VACUUM/TRUNCATE is rare.
     *
     * We cap the scan at 2^20 pages (~4 GB at 4 KB pages) to bound the loop.
     */
    char key[18];
    uint64_t id = cutoff_id;
    const uint64_t SCAN_LIMIT = cutoff_id + (1u << 20);

    while (id < SCAN_LIMIT) {
        fmt_page_key(key, id);
        if (!qihse_kv_exists_user(cache->kv, key, NULL)) break;
        qihse_kv_del_user(cache->kv, key, NULL);
        id++;
    }
}

/* ── Flush ───────────────────────────────────────────────────────────────── */

void qihse_vfs_cache_flush(qihse_vfs_page_cache_t* cache)
{
    /*
     * The KV store's own WAL already guarantees that every qihse_kv_set()
     * call is durable (flushed via fprintf+fflush on every SET).  There is
     * nothing additional to flush here; this function exists to complete the
     * API contract and provide a future hook for a dirty-page set.
     */
    (void)cache;
}
