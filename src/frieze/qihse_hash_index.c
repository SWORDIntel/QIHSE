#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* qihse_hash_index.c — Phase 3.2 open-addressed hash index with linear
 * probing, dynamic resizing, and tombstone-based deletion.
 */
#include "qihse_hash_index.h"
#include "qihse_platform.h"
#include "qihse_tsx_lock.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__x86_64__) || defined(_M_X64)
#if defined(__SSE4_2__) && defined(__AES__)
#include <nmmintrin.h>
#include <wmmintrin.h>
#define QIHSE_HW_HASH 1
#endif
#endif

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
    qihse_tsx_rwlock_t lock;
};

/* ------------------------------------------------------------------ */
/* Hashing                                                             */
/* ------------------------------------------------------------------ */

static inline uint64_t qihse_hardware_hash(const void* data, size_t len) {
#if defined(QIHSE_HW_HASH)
    const uint8_t* p = (const uint8_t*)data;
    uint64_t crc0 = 0x9e3779b97f4a7c15ULL ^ (uint64_t)len;
    uint64_t crc1 = 0x517cc1b727220a95ULL ^ ((uint64_t)len << 32);

    while (len >= 16) {
        uint64_t v0, v1;
        memcpy(&v0, p, 8);
        memcpy(&v1, p + 8, 8);
        crc0 = _mm_crc32_u64(crc0, v0);
        crc1 = _mm_crc32_u64(crc1, v1);
        p += 16;
        len -= 16;
    }
    if (len >= 8) {
        uint64_t v0;
        memcpy(&v0, p, 8);
        crc0 = _mm_crc32_u64(crc0, v0);
        p += 8;
        len -= 8;
    }
    if (len & 4) {
        uint32_t v4;
        memcpy(&v4, p, 4);
        crc1 = _mm_crc32_u32((uint32_t)crc1, v4);
        p += 4;
    }
    if (len & 2) {
        uint16_t v2;
        memcpy(&v2, p, 2);
        crc0 = _mm_crc32_u16((uint32_t)crc0, v2);
        p += 2;
    }
    if (len & 1) {
        crc1 = _mm_crc32_u8((uint32_t)crc1, *p);
    }

    __m128i state = _mm_set_epi64x((int64_t)crc1, (int64_t)crc0);
    const __m128i rk = _mm_set_epi64x((int64_t)0x76543210fedcba98ULL, (int64_t)0x0123456789abcdefULL);
    state = _mm_aesenc_si128(state, rk);

    uint64_t low = (uint64_t)_mm_cvtsi128_si64(state);
    uint64_t high = (uint64_t)_mm_extract_epi64(state, 1);
    return low ^ high;
#else
    const unsigned char* p = (const unsigned char*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
#endif
}

static uint64_t hash_key(qihse_hash_index_t* idx,
                         const void* key, size_t key_len) {
    if (idx->key_type == QIHSE_HASH_KEY_INT64) {
        /* key_len should be 8; use the raw bytes */
        return qihse_hardware_hash(key, key_len ? key_len : 8);
    }
    return qihse_hardware_hash(key, key_len);
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
        uint64_t h = hash_key(idx, slot_key(s), s->key_len);
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
    qihse_tsx_rwlock_init(&idx->lock);
    return idx;
}

void qihse_hash_index_destroy(qihse_hash_index_t* idx) {
    if (!idx) return;
    qihse_tsx_wrlock(&idx->lock);
    free(idx->table);
    qihse_tsx_unlock(&idx->lock);
    qihse_tsx_rwlock_destroy(&idx->lock);
    free(idx);
}

/* Internal insert assuming write lock or TSX transaction held. Does NOT resize. */
static bool hash_insert_internal(qihse_hash_index_t* idx,
                                 const void* key, size_t key_len,
                                 uint64_t row_id, uint64_t h) {
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;
    if (idx->key_type == QIHSE_HASH_KEY_STRING && key_len > 255) return false;

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
    if (idx->key_type == QIHSE_HASH_KEY_STRING && key_len > 255) return false;

    /* Pre-compute AES-NI hash outside critical section */
    uint64_t h = hash_key(idx, key, key_len);

    /* Fast path: non-resizing insert when lf <= 0.7 wrapped in TSX elision */
    double lf = (double)(idx->count + idx->tombstones + 1) / (double)idx->capacity;
    if (lf <= 0.7 && qihse_has_rtm_support()) {
        int retries = 3;
        while (retries > 0) {
            while (__atomic_load_n(&idx->lock.fallback_held, __ATOMIC_RELAXED) != 0) {
                _mm_pause();
            }

            unsigned int status = qihse_rtm_xbegin();
            if (status == _XBEGIN_STARTED) {
                if (idx->lock.fallback_held != 0) {
                    qihse_rtm_xabort(0xff);
                }

                double cur_lf = (double)(idx->count + idx->tombstones + 1) / (double)idx->capacity;
                if (cur_lf > 0.7) {
                    qihse_rtm_xabort(0xfe); /* Table filled up; abort to trigger resize on fallback */
                }

                bool ok = hash_insert_internal(idx, key, key_len, row_id, h);
                qihse_rtm_xend();
                return ok;
            }

            if ((status & _XABORT_RETRY) || (status & _XABORT_CONFLICT)) {
                _mm_pause();
                retries--;
            } else {
                break;
            }
        }
    }

    /* Fallback / slow path: acquire write lock */
    qihse_tsx_wrlock(&idx->lock);

    /* Check load factor: (count + tombstones) / capacity > 0.7 => resize. */
    double cur_lf = (double)(idx->count + idx->tombstones + 1) / (double)idx->capacity;
    if (cur_lf > 0.7) {
        if (!table_resize(idx, idx->capacity * 2)) {
            qihse_tsx_unlock(&idx->lock);
            return false;
        }
    }

    bool ok = hash_insert_internal(idx, key, key_len, row_id, h);
    qihse_tsx_unlock(&idx->lock);
    return ok;
}

bool qihse_hash_index_lookup(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t* out) {
    if (!idx || !key) return false;
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;

    /* Hoist hash_key OUTSIDE the lock so AES-NI hashing runs before entering critical section */
    uint64_t h = hash_key(idx, key, key_len);

    /* Wrap the critical table search in qihse_tsx_rdlock() / qihse_tsx_unlock() */
    qihse_tsx_rdlock(&idx->lock);
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
    qihse_tsx_unlock(&idx->lock);
    return found;
}

bool qihse_hash_index_delete(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t* row_id_out) {
    if (!idx || !key) return false;
    if (idx->key_type == QIHSE_HASH_KEY_INT64) key_len = 8;

    /* Hoist hash_key OUTSIDE the lock so AES-NI hashing runs before entering critical section */
    uint64_t h = hash_key(idx, key, key_len);

    /* Fast path: non-resizing delete wrapped in TSX elision */
    if (qihse_has_rtm_support() && (idx->tombstones + 1 <= idx->capacity / 4)) {
        int retries = 3;
        while (retries > 0) {
            while (__atomic_load_n(&idx->lock.fallback_held, __ATOMIC_RELAXED) != 0) {
                _mm_pause();
            }

            unsigned int status = qihse_rtm_xbegin();
            if (status == _XBEGIN_STARTED) {
                if (idx->lock.fallback_held != 0) {
                    qihse_rtm_xabort(0xff);
                }

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
                        if (idx->tombstones > idx->capacity / 4) {
                            qihse_rtm_xabort(0xfe); /* abort to purge tombstones via resize on fallback */
                        }
                        break;
                    }
                    i = (i + 1) & mask;
                }
                qihse_rtm_xend();
                return found;
            }

            if ((status & _XABORT_RETRY) || (status & _XABORT_CONFLICT)) {
                _mm_pause();
                retries--;
            } else {
                break;
            }
        }
    }

    /* Fallback path: acquire write lock */
    qihse_tsx_wrlock(&idx->lock);
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
    qihse_tsx_unlock(&idx->lock);
    return found;
}

size_t qihse_hash_index_size(const qihse_hash_index_t* idx) {
    if (!idx) return 0;
    return idx->count;
}

size_t qihse_hash_index_bytes(const qihse_hash_index_t* idx) {
    if (!idx) return 0u;
    /* Same accounting the save format documents: fixed header words
     * (magic/version/key_type/capacity/count/tombstones/slot_stride)
     * plus the slot table at capacity * slot_stride. */
    const size_t header_words = 7u * sizeof(uint64_t);
    return sizeof(*idx) + header_words +
           idx->capacity * idx->slot_stride;
}

/* ------------------------------------------------------------------ */
/* Persistence (save/load)                                             */
/* ------------------------------------------------------------------ */

#include <stdio.h>

#define QIHSE_HASH_INDEX_MAGIC   0x51484958  /* "QHIX" */
#define QIHSE_HASH_INDEX_VERSION 1

int qihse_hash_index_save(const qihse_hash_index_t* idx, const char* path) {
    if (!idx || !path) return -1;

    qihse_tsx_rdlock((qihse_tsx_rwlock_t*)&idx->lock);

    FILE* f = fopen(path, "wb");
    if (!f) {
        qihse_tsx_unlock((qihse_tsx_rwlock_t*)&idx->lock);
        return -1;
    }

    uint32_t magic = QIHSE_HASH_INDEX_MAGIC;
    uint32_t version = QIHSE_HASH_INDEX_VERSION;
    uint32_t key_type = (uint32_t)idx->key_type;

    /* Header */
    fwrite(&magic, 4, 1, f);
    fwrite(&version, 4, 1, f);
    fwrite(&key_type, 4, 1, f);
    fwrite(&idx->capacity, sizeof(size_t), 1, f);
    fwrite(&idx->count, sizeof(size_t), 1, f);
    fwrite(&idx->tombstones, sizeof(size_t), 1, f);
    fwrite(&idx->slot_stride, sizeof(size_t), 1, f);

    /* Table data */
    size_t total = idx->slot_stride * idx->capacity;
    fwrite(idx->table, 1, total, f);

    fclose(f);
    qihse_tsx_unlock((qihse_tsx_rwlock_t*)&idx->lock);
    return 0;
}

qihse_hash_index_t* qihse_hash_index_load(const char* path) {
    if (!path) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    uint32_t magic, version, key_type;
    size_t capacity, count, tombstones, slot_stride;

    if (fread(&magic, 4, 1, f) != 1 || magic != QIHSE_HASH_INDEX_MAGIC) {
        fclose(f); return NULL;
    }
    if (fread(&version, 4, 1, f) != 1 || version != QIHSE_HASH_INDEX_VERSION) {
        fclose(f); return NULL;
    }
    if (fread(&key_type, 4, 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&capacity, sizeof(size_t), 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&count, sizeof(size_t), 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&tombstones, sizeof(size_t), 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&slot_stride, sizeof(size_t), 1, f) != 1) { fclose(f); return NULL; }

    /* Sanity checks */
    if (capacity == 0 || slot_stride == 0 || capacity > (SIZE_MAX / slot_stride)) {
        fclose(f); return NULL;
    }

    qihse_hash_index_t* idx = (qihse_hash_index_t*)calloc(1, sizeof(*idx));
    if (!idx) { fclose(f); return NULL; }

    idx->key_type = (qihse_hash_key_type_t)key_type;
    idx->capacity = capacity;
    idx->count = count;
    idx->tombstones = tombstones;
    idx->slot_stride = slot_stride;

    size_t total = slot_stride * capacity;
    idx->table = (unsigned char*)malloc(total);
    if (!idx->table) {
        free(idx);
        fclose(f);
        return NULL;
    }

    if (fread(idx->table, 1, total, f) != total) {
        free(idx->table);
        free(idx);
        fclose(f);
        return NULL;
    }

    fclose(f);
    qihse_tsx_rwlock_init(&idx->lock);
    return idx;
}
