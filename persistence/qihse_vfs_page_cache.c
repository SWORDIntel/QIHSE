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
 * Cache entries use classification 0 / SCI 0. The legacy NULL context reads
 * only that unclassified view; it does not confer Operator authority.
 */

#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 200809L
#endif

#include "qihse_vfs_page_cache.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

typedef struct {
    size_t count;
    size_t capacity;
    char (*keys)[18];
    bool failed;
} cache_key_list_t;

static void cache_disable(qihse_vfs_page_cache_t* cache)
{
    if (!cache || !cache->kv) return;
    qihse_kv_store_destroy(cache->kv);
    cache->kv = NULL;
}

static bool cache_key_count_cb(const char* key, const char* value, void* user_data)
{
    (void)value;
    cache_key_list_t* list = user_data;
    if (!list || !key || strlen(key) != 17u || key[0] != 'P') return true;
    if (list->count == SIZE_MAX) list->failed = true;
    else list->count++;
    return !list->failed;
}

static bool cache_key_copy_cb(const char* key, const char* value, void* user_data)
{
    (void)value;
    cache_key_list_t* list = user_data;
    if (!list || !key || strlen(key) != 17u || key[0] != 'P') return true;
    if (list->count >= list->capacity) {
        list->failed = true;
        return false;
    }
    memcpy(list->keys[list->count++], key, 18u);
    return true;
}

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

    /* The cache uses the legacy unclassified-only view. */
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

    /* Enumerate actual keys: page IDs are sparse, so probing upward from the
     * cutoff can stop at a hole and miss later pages. Do not mutate the KV
     * store from its read-locked iteration callback. Two bounded passes let us
     * allocate the exact key list before performing any deletions. */
    cache_key_list_t count = {0};
    if (!qihse_kv_foreach_prefix_user(cache->kv, "P", NULL,
                                      cache_key_count_cb, &count) || count.failed ||
        count.count > SIZE_MAX / sizeof(*count.keys)) {
        cache_disable(cache);
        return;
    }
    if (count.count == 0u) return;

    char (*keys)[18] = calloc(count.count, sizeof(*keys));
    if (!keys) { cache_disable(cache); return; }
    cache_key_list_t copy = {.capacity = count.count, .keys = keys};
    if (!qihse_kv_foreach_prefix_user(cache->kv, "P", NULL,
                                      cache_key_copy_cb, &copy) || copy.failed ||
        copy.count != count.count) {
        free(keys);
        cache_disable(cache);
        return;
    }

    bool ok = true;
    for (size_t i = 0; i < copy.count; i++) {
        uint64_t page_id = 0u;
        bool valid = true;
        for (size_t j = 1; j < 17u; j++) {
            unsigned char c = (unsigned char)keys[i][j];
            unsigned digit = c >= '0' && c <= '9' ? (unsigned)(c - '0') :
                             c >= 'a' && c <= 'f' ? (unsigned)(c - 'a') + 10u : 16u;
            if (digit > 15u) { valid = false; break; }
            page_id = (page_id << 4) | digit;
        }
        if (valid && page_id >= cutoff_id && !qihse_kv_del_user(cache->kv, keys[i], NULL))
            ok = false;
    }
    free(keys);
    if (!ok) cache_disable(cache);
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
