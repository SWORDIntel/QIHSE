#define _GNU_SOURCE
/* qihse_hash_index.c — Phase 3.2 open-addressed hash index with linear
 * probing, dynamic resizing, and tombstone-based deletion.
 */
#include "qihse_hash_index.h"
#include "qihse_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Slot states. */
enum { SLOT_EMPTY = 0, SLOT_OCCUPIED = 1, SLOT_TOMBSTONE = 2 };

typedef struct {
    uint8_t  state;
    uint16_t key_len;   /* bytes of key stored */
    uint64_t row_id;
    /* key bytes follow (for STRING type) or key_len=8 for INT64 */
} hash_slot_t;

/* We store keys inline after each slot header. For int64 keys, key_len=8 and
 * the 8 bytes hold the int64. For string keys, key_len is the string length
 * (no NUL). */

struct qihse_hash_index {
    qihse_hash_key_type_t key_type;
    unsigned char* table;      /* contiguous array of slots + keys */
    size_t slot_stride;        /* bytes per slot (header + max_key_inline) */
    size_t capacity;           /* number of slots */
    size_t count;              /* occupied (non-tombstone, non-empty) entries */
    size_t tombstones;         /* tombstone count */
    pthread_rwlock_t lock;
};

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

static uint64_t fnv1a(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t hash_key(qihse_hash_index_t* idx,
                         const void* key, size_t key_len) {
    if (idx->key_type == QIHSE_HASH_KEY_INT64) {
        /* key_len should be 8; use the raw bytes */
        return fnv1a(key, key_len ? key_len : 8);
    }
    return fnv1a(key, key_len);
}

/* ------------------------------------------------------------------ */
/* Slot access                                                         */
/* ------------------------------------------------------------------ */

static hash_slot_t* slot_at(qihse_hash_index_t* idx, size_t i) {
    return (hash_slot_t*)(idx->table + i * idx->slot_stride);
}

static unsigned char* slot_key(hash_slot_t* s) {
    return (unsigned char*)s + sizeof(hash_slot_t);
}

static bool slot_key_match(hash_slot_t* s, const void* key, size_t key_len) {
    if (s->key_len != key_len) return false;
    return memcmp(slot_key(s), key, key_len) == 0;
}

/* ------------------------------------------------------------------ */
/* Table management                                                    */
/* ------------------------------------------------------------------ */

static size_t next_pow2(size_t v) {
    if (v < 16) return 16;
    size_t r = v - 1;
    r |= r >> 1; r |= r >> 2; r |= r >> 4;
    r |= r >> 8; r |= r >> 16; r |= r >> 32;
    return r + 1;
}

static bool table_init(qihse_hash_index_t* idx, size_t capacity) {
    idx->capacity = capacity;
    idx->count = 0;
    idx->tombstones = 0;
    /* stride: header + key storage. For int64, 8 bytes. For string, we store
     * the key inline. We use a variable stride: for int64 it's fixed; for
     * string we need to store variable-length keys, so we use a fixed max. */
    if (idx->key_type == QIHSE_HASH_KEY_INT64)
        idx->slot_stride = sizeof(hash_slot_t) + 8;
    else
        idx->slot_stride = sizeof(hash_slot_t) + 256; /* max key inline 256B */

    size_t total = idx->slot_stride * idx->capacity;
    idx->table = (unsigned char*)calloc(1, total);
    if (!idx->table) return false;
    return true;
}

static bool table_resize(qihse_hash_index_t* idx, size_t new_cap) {
    unsigned char* old_table = idx->table;
    size_t old_cap = idx->capacity;
    size_t old_stride = idx->slot_stride;

    idx->table = NULL;
    if (!table_init(idx, new_cap)) {
        idx->table = old_table;
        idx->capacity = old_cap;
        return false;
    }

    /* Re-insert all occupied slots. */
    for (size_t i = 0; i < old_cap; i++) {
        hash_slot_t* s = (hash_slot_t*)(old_table + i * old_stride);
        if (s->state != SLOT_OCCUPIED) continue;
        /* Re-insert into new table. */
        uint64_t h = fnv1a(slot_key(s), s->key_len);
        size_t mask = idx->capacity - 1;
        size_t j = h & mask;
        for (;;) {
            hash_slot_t* ns = slot_at(idx, j);
            if (ns->state == SLOT_EMPTY) {
                ns->state = SLOT_OCCUPIED;
                ns->key_len = s->key_len;
                ns->row_id = s->row_id;
                memcpy(slot_key(ns), slot_key(s), s->key_len);
                idx->count++;
                break;
            }
            j = (j + 1) & mask;
        }
    }
    free(old_table);
    return true;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

qihse_hash_index_t* qihse_hash_index_create(qihse_hash_key_type_t key_type,
                                            size_t initial_capacity) {
    qihse_hash_index_t* idx = (qihse_hash_index_t*)calloc(1, sizeof(*idx));
    if (!idx) return NULL;
    idx->key_type = key_type;
    size_t cap = initial_capacity ? next_pow2(initial_capacity) : 1024;
    if (!table_init(idx, cap)) { free(idx); return NULL; }
    pthread_rwlock_init(&idx->lock, NULL);
    return idx;
}

void qihse_hash_index_destroy(qihse_hash_index_t* idx) {
    if (!idx) return;
    pthread_rwlock_wrlock(&idx->lock);
    free(idx->table);
    pthread_rwlock_unlock(&idx->lock);
    pthread_rwlock_destroy(&idx->lock);
    free(idx);
}

/* Internal insert assuming write lock held. Does NOT resize. */
static bool hash_insert_internal(qihse_hash_index_t* idx,
                                 const void* key, size_t key_len,
                                 uint64_t row_id) {
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;
    if (idx->key_type == QIHSE_HASH_KEY_STRING && key_len > 255) return false;

    uint64_t h = hash_key(idx, key, key_len);
    size_t mask = idx->capacity - 1;
    size_t i = h & mask;
    size_t first_tomb = (size_t)-1;

    for (;;) {
        hash_slot_t* s = slot_at(idx, i);
        if (s->state == SLOT_EMPTY) {
            /* Insert here (or at first tombstone). */
            size_t target = (first_tomb != (size_t)-1) ? first_tomb : i;
            hash_slot_t* ts = slot_at(idx, target);
            ts->state = SLOT_OCCUPIED;
            ts->key_len = (uint16_t)key_len;
            ts->row_id = row_id;
            memcpy(slot_key(ts), key, key_len);
            idx->count++;
            if (first_tomb != (size_t)-1) idx->tombstones--;
            return true;
        }
        if (s->state == SLOT_TOMBSTONE) {
            if (first_tomb == (size_t)-1) first_tomb = i;
        } else if (s->state == SLOT_OCCUPIED) {
            if (slot_key_match(s, key, key_len)) {
                /* Replace. */
                s->row_id = row_id;
                return true;
            }
        }
        i = (i + 1) & mask;
    }
}

bool qihse_hash_index_insert(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t row_id) {
    if (!idx || !key) return false;
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;

    pthread_rwlock_wrlock(&idx->lock);

    /* Check load factor: (count + tombstones) / capacity > 0.7 => resize. */
    double lf = (double)(idx->count + idx->tombstones + 1) / (double)idx->capacity;
    if (lf > 0.7) {
        if (!table_resize(idx, idx->capacity * 2)) {
            pthread_rwlock_unlock(&idx->lock);
            return false;
        }
    }

    bool ok = hash_insert_internal(idx, key, key_len, row_id);
    pthread_rwlock_unlock(&idx->lock);
    return ok;
}

bool qihse_hash_index_lookup(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t* out) {
    if (!idx || !key) return false;
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;

    pthread_rwlock_rdlock(&idx->lock);
    uint64_t h = hash_key(idx, key, key_len);
    size_t mask = idx->capacity - 1;
    size_t i = h & mask;
    bool found = false;
    for (;;) {
        hash_slot_t* s = slot_at(idx, i);
        if (s->state == SLOT_EMPTY) break;
        if (s->state == SLOT_OCCUPIED && slot_key_match(s, key, key_len)) {
            if (out) *out = s->row_id;
            found = true;
            break;
        }
        i = (i + 1) & mask;
    }
    pthread_rwlock_unlock(&idx->lock);
    return found;
}

bool qihse_hash_index_delete(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t* row_id_out) {
    if (!idx || !key) return false;
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;

    pthread_rwlock_wrlock(&idx->lock);
    uint64_t h = hash_key(idx, key, key_len);
    size_t mask = idx->capacity - 1;
    size_t i = h & mask;
    bool found = false;
    for (;;) {
        hash_slot_t* s = slot_at(idx, i);
        if (s->state == SLOT_EMPTY) break;
        if (s->state == SLOT_OCCUPIED && slot_key_match(s, key, key_len)) {
            if (row_id_out) *row_id_out = s->row_id;
            s->state = SLOT_TOMBSTONE;
            s->key_len = 0;
            idx->count--;
            idx->tombstones++;
            found = true;
            /* If tombstones accumulate, resize to clean them. */
            if (idx->tombstones > idx->capacity / 4)
                table_resize(idx, idx->capacity);
            break;
        }
        i = (i + 1) & mask;
    }
    pthread_rwlock_unlock(&idx->lock);
    return found;
}

size_t qihse_hash_index_size(const qihse_hash_index_t* idx) {
    if (!idx) return 0;
    return idx->count;
}
