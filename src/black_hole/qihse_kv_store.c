#include "qihse_kv_store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "../broad_oak/qihse_quantum_defense.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define LSM_MEMTABLE_MAX (512u * 1024u)
#define WAL_BUFFER_FLUSH_THRESHOLD 65536u
#define KV_MAX_KEY_LEN 65535u
#define KV_MAX_VALUE_LEN (16u * 1024u * 1024u)
#define KV_FLAG_TOMBSTONE 0x01u
#define KV_ALLOWED_FLAGS KV_FLAG_TOMBSTONE
#define KV_WAL_MAGIC "QKV2"
#define KV_WAL_OP_SET 1u
#define KV_WAL_OP_DEL 2u
#define KV_HEADER_LINE_MAX 256u

typedef struct {
    uint64_t expire_time_ms;
    uint16_t classification;
    uint16_t sci_compartment;
    uint8_t flags;
    uint8_t reserved[3];
    char val[];
} kv_payload_t;

/*
 * In-memory key metadata index over flushed SSTables.
 *
 * The write path must know whether a key already exists (and at what
 * classification) so it can enforce the auth-on-overwrite invariant.  The
 * original implementation answered that question by calling logical_lookup(),
 * which linear-scans every record in every SSTable on disk.  Because SSTables
 * accumulate as data is flushed, bulk ingestion degraded to O(N^2) disk reads.
 *
 * This index holds only the metadata needed for the authorization decision
 * (classification, compartment, expiry, flags) -- never values -- so it is not
 * a classified read primitive and does not weaken AGENTS.md invariant #1: the
 * authorization check itself is unchanged, only its data source is faster.
 * Values are still only ever returned through the context-checked read path.
 *
 * The index is exact (no false negatives); if it cannot record a key (OOM) it
 * marks itself degraded and the write path falls back to the authoritative
 * logical_lookup() so correctness/authorization is never compromised.
 */
typedef struct {
    char* key;                  /* NULL == empty slot */
    uint16_t classification;
    uint16_t sci_compartment;
    uint64_t expire_time_ms;
    uint8_t flags;
    int32_t sstable_id;         /* SSTable that holds the newest copy */
    uint64_t sst_offset;        /* byte offset of the record within that file */
} sst_meta_entry_t;

typedef struct {
    sst_meta_entry_t* slots;
    size_t cap;                 /* power of two */
    size_t count;
    bool degraded;              /* true if any insert/lookup fell back to OOM */
} sst_meta_index_t;

static uint64_t sst_meta_hash(const char* key) {
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char* p = (const unsigned char*)key; *p; p++) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL;
    }
    return h;
}

static sst_meta_index_t* sst_meta_index_create(void) {
    sst_meta_index_t* idx = (sst_meta_index_t*)calloc(1u, sizeof(*idx));
    if (!idx) return NULL;
    idx->cap = 1024u;
    idx->slots = (sst_meta_entry_t*)calloc(idx->cap, sizeof(*idx->slots));
    if (!idx->slots) { free(idx); return NULL; }
    return idx;
}

static void sst_meta_index_destroy(sst_meta_index_t* idx) {
    if (!idx) return;
    if (idx->slots) {
        for (size_t i = 0; i < idx->cap; i++) free(idx->slots[i].key);
        free(idx->slots);
    }
    free(idx);
}

static bool sst_meta_index_grow(sst_meta_index_t* idx) {
    size_t new_cap = idx->cap * 2u;
    sst_meta_entry_t* new_slots = (sst_meta_entry_t*)calloc(new_cap, sizeof(*new_slots));
    if (!new_slots) return false;
    for (size_t i = 0; i < idx->cap; i++) {
        sst_meta_entry_t* e = &idx->slots[i];
        if (!e->key) continue;
        size_t j = (size_t)(sst_meta_hash(e->key) & (new_cap - 1u));
        while (new_slots[j].key) j = (j + 1u) & (new_cap - 1u);
        new_slots[j] = *e;
    }
    free(idx->slots);
    idx->slots = new_slots;
    idx->cap = new_cap;
    return true;
}

static void sst_meta_index_insert(sst_meta_index_t* idx, const char* key,
                                  uint16_t classification, uint16_t sci_compartment,
                                  uint64_t expire_time_ms, uint8_t flags,
                                  int32_t sstable_id, uint64_t sst_offset) {
    if (!idx || !key) return;
    if ((idx->count + 1u) * 10u >= idx->cap * 7u) {
        if (!sst_meta_index_grow(idx)) { idx->degraded = true; return; }
    }
    size_t j = (size_t)(sst_meta_hash(key) & (idx->cap - 1u));
    while (idx->slots[j].key) {
        if (strcmp(idx->slots[j].key, key) == 0) {
            idx->slots[j].classification = classification;
            idx->slots[j].sci_compartment = sci_compartment;
            idx->slots[j].expire_time_ms = expire_time_ms;
            idx->slots[j].flags = flags;
            idx->slots[j].sstable_id = sstable_id;
            idx->slots[j].sst_offset = sst_offset;
            return;
        }
        j = (j + 1u) & (idx->cap - 1u);
    }
    char* kcopy = strdup(key);
    if (!kcopy) { idx->degraded = true; return; }
    idx->slots[j].key = kcopy;
    idx->slots[j].classification = classification;
    idx->slots[j].sci_compartment = sci_compartment;
    idx->slots[j].expire_time_ms = expire_time_ms;
    idx->slots[j].flags = flags;
    idx->slots[j].sstable_id = sstable_id;
    idx->slots[j].sst_offset = sst_offset;
    idx->count++;
}

static bool sst_meta_index_lookup(const sst_meta_index_t* idx, const char* key,
                                  uint16_t* out_class, uint16_t* out_comp,
                                  uint64_t* out_expire, uint8_t* out_flags,
                                  int32_t* out_sstable_id, uint64_t* out_offset) {
    if (!idx || !key || idx->count == 0u) return false;
    size_t j = (size_t)(sst_meta_hash(key) & (idx->cap - 1u));
    while (idx->slots[j].key) {
        if (strcmp(idx->slots[j].key, key) == 0) {
            if (out_class) *out_class = idx->slots[j].classification;
            if (out_comp) *out_comp = idx->slots[j].sci_compartment;
            if (out_expire) *out_expire = idx->slots[j].expire_time_ms;
            if (out_flags) *out_flags = idx->slots[j].flags;
            if (out_sstable_id) *out_sstable_id = idx->slots[j].sstable_id;
            if (out_offset) *out_offset = idx->slots[j].sst_offset;
            return true;
        }
        j = (j + 1u) & (idx->cap - 1u);
    }
    return false;
}

struct qihse_kv_store {
    qihse_trinary_trie_t* trie;
    FILE* wal_fd;
    size_t wal_unflushed_bytes;
    size_t mem_usage;
    int sstable_counter;
    qihse_quantum_defense_ctx_t* qdd_ctx;
    bool bulk_load_mode;
    sst_meta_index_t* sst_meta;
};

/* Drop and rebuild an empty SSTable metadata index.  Called whenever SSTables
 * are merged back into the memtable (compaction / snapshot load), after which
 * the trie alone is authoritative.  If reallocation fails the index is left
 * NULL and the write path falls back to logical_lookup(). */
static void sst_meta_index_reset(qihse_kv_store_t* store) {
    if (!store) return;
    sst_meta_index_destroy(store->sst_meta);
    store->sst_meta = sst_meta_index_create();
}

typedef struct {
    char* key;
    char* val;
    uint64_t expire_time_ms;
    uint16_t classification;
    uint16_t sci_compartment;
    uint8_t flags;
} kv_disk_record_t;

typedef enum {
    KV_LOOKUP_ERROR = -1,
    KV_LOOKUP_MISS = 0,
    KV_LOOKUP_LIVE = 1,
    KV_LOOKUP_DEAD = 2
} kv_lookup_state_t;

typedef struct {
    kv_lookup_state_t state;
    char* value;
    uint64_t expire_time_ms;
    uint16_t classification;
    uint16_t sci_compartment;
    uint8_t flags;
} kv_lookup_result_t;

static uint64_t current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

static const char* get_qihse_data_dir(void) {
    static char data_dir[4096] = {0};
    if (data_dir[0] != '\0') return data_dir;
    const char* env = getenv("QIHSE_DATA_DIR");
    if (env && env[0]) {
        size_t n = strlen(env);
        if (n + 2u > sizeof(data_dir)) return NULL;
        memcpy(data_dir, env, n);
        if (env[n - 1u] != '/') data_dir[n++] = '/';
        data_dir[n] = '\0';
        return data_dir;
    }
    if (access("/var/lib/qihse", R_OK | W_OK) == 0) {
        snprintf(data_dir, sizeof(data_dir), "%s", "/var/lib/qihse/");
        return data_dir;
    }
    (void)mkdir("data", 0700);
    (void)mkdir("data/qihse", 0700);
    (void)chmod("data", 0700);
    (void)chmod("data/qihse", 0700);
    snprintf(data_dir, sizeof(data_dir), "%s", "data/qihse/");
    return data_dir;
}

static bool build_data_path(char* out, size_t out_size, const char* suffix) {
    const char* dir = get_qihse_data_dir();
    if (!out || out_size == 0u || !dir || !suffix) return false;
    int n = snprintf(out, out_size, "%s%s", dir, suffix);
    return n >= 0 && (size_t)n < out_size;
}

static int open_secure_read(const char* path) {
    if (!path) { errno = EINVAL; return -1; }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int saved = errno ? errno : EINVAL;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static int open_secure_write_exclusive(const char* path) {
    if (!path) { errno = EINVAL; return -1; }
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
}

static bool finish_file(FILE* f) {
    if (!f) return false;
    bool ok = fflush(f) == 0;
    int fd = fileno(f);
    if (ok && fd >= 0 && fsync(fd) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool atomic_file_begin(const char* final_path, char* tmp_path, size_t tmp_size, FILE** out) {
    if (!final_path || !tmp_path || !out) return false;
    int n = snprintf(tmp_path, tmp_size, "%s.tmp.%ld.%llu", final_path, (long)getpid(),
                     (unsigned long long)current_time_ms());
    if (n < 0 || (size_t)n >= tmp_size) return false;
    int fd = open_secure_write_exclusive(tmp_path);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); unlink(tmp_path); return false; }
    *out = f;
    return true;
}

static bool atomic_file_commit(FILE* f, const char* tmp_path, const char* final_path) {
    if (!f || !tmp_path || !final_path) return false;
    if (!finish_file(f)) { unlink(tmp_path); return false; }
    if (rename(tmp_path, final_path) != 0) { unlink(tmp_path); return false; }
    return true;
}

static bool fwrite_exact(const void* ptr, size_t size, size_t count, FILE* f) {
    return count == 0u || (f && fwrite(ptr, size, count, f) == count);
}

static uint64_t fnv1a64_update(uint64_t h, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < len; i++) { h ^= (uint64_t)p[i]; h *= 1099511628211ULL; }
    return h;
}

static uint64_t wal_record_crc(uint8_t op, uint8_t flags, uint16_t key_len, uint32_t val_len,
                               uint16_t classification, uint16_t sci_compartment,
                               uint64_t expire_time_ms, const char* key, const char* val) {
    uint64_t h = 14695981039346656037ULL;
    h = fnv1a64_update(h, &op, sizeof(op));
    h = fnv1a64_update(h, &flags, sizeof(flags));
    h = fnv1a64_update(h, &key_len, sizeof(key_len));
    h = fnv1a64_update(h, &val_len, sizeof(val_len));
    h = fnv1a64_update(h, &classification, sizeof(classification));
    h = fnv1a64_update(h, &sci_compartment, sizeof(sci_compartment));
    h = fnv1a64_update(h, &expire_time_ms, sizeof(expire_time_ms));
    h = fnv1a64_update(h, key, key_len);
    if (val_len != 0u) h = fnv1a64_update(h, val, val_len);
    return h;
}

static bool payload_is_dead(const kv_payload_t* p, uint64_t now) {
    return !p || (p->flags & KV_FLAG_TOMBSTONE) != 0u ||
           (p->expire_time_ms != 0u && p->expire_time_ms <= now);
}

static kv_payload_t* payload_create(const char* value, uint64_t expire_time_ms,
                                    uint16_t classification, uint16_t sci_compartment,
                                    uint8_t flags, size_t* out_size) {
    if ((flags & ~KV_ALLOWED_FLAGS) != 0u) return NULL;
    const char* src = value ? value : "";
    size_t val_len = strlen(src);
    if (val_len > KV_MAX_VALUE_LEN) return NULL;
    size_t total = sizeof(kv_payload_t) + val_len + 1u;
    kv_payload_t* p = (kv_payload_t*)calloc(1, total);
    if (!p) return NULL;
    p->expire_time_ms = expire_time_ms;
    p->classification = classification;
    p->sci_compartment = sci_compartment;
    p->flags = flags;
    memcpy(p->val, src, val_len + 1u);
    if (out_size) *out_size = total;
    return p;
}

static void disk_record_free(kv_disk_record_t* r) {
    if (!r) return;
    free(r->key); free(r->val); memset(r, 0, sizeof(*r));
}

static int disk_record_read(FILE* f, kv_disk_record_t* r) {
    if (!f || !r) return -1;
    memset(r, 0, sizeof(*r));
    char header[KV_HEADER_LINE_MAX];
    if (!fgets(header, sizeof(header), f)) return feof(f) ? 0 : -1;
    size_t hlen = strlen(header);
    if (hlen == 0u || header[hlen - 1u] != '\n') return -1;
    size_t key_len = 0u, val_len = 0u;
    unsigned long long expire = 0u;
    unsigned int classif = 0u, sci = 0u, flags = 0u;
    int fields = sscanf(header, "%zu %zu %llu %u %u %u", &key_len, &val_len,
                        &expire, &classif, &sci, &flags);
    if (fields != 5 && fields != 6) return -1;
    if (fields == 5) flags = 0u;
    if (key_len == 0u || key_len > KV_MAX_KEY_LEN || val_len > KV_MAX_VALUE_LEN ||
        classif > UINT16_MAX || sci > UINT16_MAX || (flags & ~KV_ALLOWED_FLAGS) != 0u) return -1;
    if ((flags & KV_FLAG_TOMBSTONE) != 0u && val_len != 0u) return -1;
    r->key = (char*)malloc(key_len + 1u);
    r->val = (char*)malloc(val_len + 1u);
    if (!r->key || !r->val) { disk_record_free(r); return -1; }
    if (fread(r->key, 1u, key_len, f) != key_len || fread(r->val, 1u, val_len, f) != val_len) {
        disk_record_free(r); return -1;
    }
    if (fgetc(f) != '\n') { disk_record_free(r); return -1; }
    if (memchr(r->key, '\0', key_len) != NULL || memchr(r->val, '\0', val_len) != NULL) {
        disk_record_free(r); return -1;
    }
    r->key[key_len] = '\0'; r->val[val_len] = '\0';
    r->expire_time_ms = (uint64_t)expire;
    r->classification = (uint16_t)classif;
    r->sci_compartment = (uint16_t)sci;
    r->flags = (uint8_t)flags;
    return 1;
}

static bool disk_record_write(FILE* f, const char* key, const kv_payload_t* p) {
    if (!f || !key || !p) return false;
    size_t key_len = strlen(key);
    size_t val_len = (p->flags & KV_FLAG_TOMBSTONE) ? 0u : strlen(p->val);
    if (key_len == 0u || key_len > KV_MAX_KEY_LEN || val_len > KV_MAX_VALUE_LEN) return false;
    if (fprintf(f, "%zu %zu %llu %u %u %u\n", key_len, val_len,
                (unsigned long long)p->expire_time_ms, (unsigned)p->classification,
                (unsigned)p->sci_compartment, (unsigned)p->flags) < 0) return false;
    if (!fwrite_exact(key, 1u, key_len, f)) return false;
    if (val_len != 0u && !fwrite_exact(p->val, 1u, val_len, f)) return false;
    return fputc('\n', f) != EOF;
}

static bool insert_internal(qihse_kv_store_t* store, const char* key, const char* value,
                            uint64_t expire_time_ms, uint16_t classification,
                            uint16_t sci_compartment, uint8_t flags) {
    if (!store || !store->trie || !key || key[0] == '\0') return false;
    size_t key_len = strlen(key);
    if (key_len > KV_MAX_KEY_LEN) return false;
    size_t payload_size = 0u;
    kv_payload_t* payload = payload_create(value, expire_time_ms, classification,
                                           sci_compartment, flags, &payload_size);
    if (!payload) return false;
    if (!qihse_trinary_trie_insert_nocopy(store->trie, key, payload, payload_size)) {
        free(payload); return false;
    }
    store->mem_usage += key_len + payload_size;
    return true;
}

typedef struct { FILE* f; bool ok; qihse_kv_store_t* store; int32_t sstable_id; } memtable_save_ctx_t;
static bool write_memtable_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size;
    memtable_save_ctx_t* ctx = (memtable_save_ctx_t*)user_data;
    if (!ctx || !ctx->ok || !key || !value || !ctx->f) return false;
    const kv_payload_t* p = (const kv_payload_t*)value;
    long rec_off = ftell(ctx->f);
    if (!disk_record_write(ctx->f, key, p)) { ctx->ok = false; return false; }
    /* Record the flushed key's metadata so the write/read paths can answer
     * existence and location in memory instead of scanning this file. */
    if (ctx->store && ctx->store->sst_meta) {
        sst_meta_index_insert(ctx->store->sst_meta, key,
                              p->classification, p->sci_compartment,
                              p->expire_time_ms, p->flags,
                              ctx->sstable_id,
                              rec_off >= 0 ? (uint64_t)rec_off : 0u);
    }
    return true;
}

static int kv_save_memtable_only(qihse_kv_store_t* store, const char* filepath, int32_t sstable_id) {
    if (!store || !store->trie || !filepath) return -1;
    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &f)) return -1;
    memtable_save_ctx_t ctx = { .f = f, .ok = true, .store = store, .sstable_id = sstable_id };
    qihse_trinary_trie_foreach(store->trie, write_memtable_cb, &ctx);
    if (!ctx.ok || ferror(f)) { fclose(f); unlink(tmp); return -1; }
    if (!atomic_file_commit(f, tmp, filepath)) return -1;
    return 0;
}

static bool rotate_wal_empty(qihse_kv_store_t* store) {
    if (!store) return false;
    char wal_path[4096], tmp_path[8192];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) return false;
    FILE* tmp = NULL;
    if (!atomic_file_begin(wal_path, tmp_path, sizeof(tmp_path), &tmp)) return false;
    if (!atomic_file_commit(tmp, tmp_path, wal_path)) return false;
    if (store->wal_fd) fclose(store->wal_fd);
    int fd = open(wal_path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { store->wal_fd = NULL; return false; }
    store->wal_fd = fdopen(fd, "ab");
    if (!store->wal_fd) { close(fd); return false; }
    store->wal_unflushed_bytes = 0u;
    return true;
}

static bool flush_memtable_to_sstable(qihse_kv_store_t* store) {
    if (!store || !store->trie) return false;
    const char* dir = get_qihse_data_dir();
    if (!dir) return false;
    char sst_path[4096];
    int n = snprintf(sst_path, sizeof(sst_path), "%ssstable_%d.db", dir, store->sstable_counter);
    if (n < 0 || (size_t)n >= sizeof(sst_path)) return false;
    if (kv_save_memtable_only(store, sst_path, store->sstable_counter) != 0) return false;
    qihse_trinary_trie_t* replacement = qihse_trinary_trie_create();
    if (!replacement) { unlink(sst_path); return false; }
    qihse_trinary_trie_t* old = store->trie;
    store->trie = replacement;
    store->mem_usage = 0u;
    store->sstable_counter++;
    qihse_trinary_trie_destroy(old);
    (void)rotate_wal_empty(store);
    return true;
}

static void flush_wal_buffer(qihse_kv_store_t* store) {
    if (!store || !store->wal_fd || store->wal_unflushed_bytes == 0u) return;
    if (fflush(store->wal_fd) == 0) store->wal_unflushed_bytes = 0u;
}

static bool wal_append(qihse_kv_store_t* store, uint8_t op, const char* key, const char* value,
                       uint64_t expire_time_ms, uint16_t classification,
                       uint16_t sci_compartment, uint8_t flags) {
    if (!store || !key) return false;
    if (store->bulk_load_mode) return true;
    if (!store->wal_fd) return false;
    size_t key_len_sz = strlen(key), val_len_sz = value ? strlen(value) : 0u;
    if (key_len_sz == 0u || key_len_sz > KV_MAX_KEY_LEN || val_len_sz > KV_MAX_VALUE_LEN) return false;
    if (op != KV_WAL_OP_SET && op != KV_WAL_OP_DEL) return false;
    if ((flags & ~KV_ALLOWED_FLAGS) != 0u) return false;
    uint16_t key_len = (uint16_t)key_len_sz;
    uint32_t val_len = (uint32_t)val_len_sz;
    uint64_t crc = wal_record_crc(op, flags, key_len, val_len, classification,
                                  sci_compartment, expire_time_ms, key, value ? value : "");
    /* Coalesce the fixed 32-byte header into one buffer so the record is
     * written with 3 stdio calls (header, key, value) instead of 11. */
    unsigned char hdr[32];
    memcpy(hdr + 0, KV_WAL_MAGIC, 4u);
    hdr[4] = op;
    hdr[5] = flags;
    memcpy(hdr + 6,  &key_len, 2u);
    memcpy(hdr + 8,  &val_len, 4u);
    memcpy(hdr + 12, &classification, 2u);
    memcpy(hdr + 14, &sci_compartment, 2u);
    memcpy(hdr + 16, &expire_time_ms, 8u);
    memcpy(hdr + 24, &crc, 8u);
    bool ok = fwrite_exact(hdr, 1u, sizeof(hdr), store->wal_fd) &&
              fwrite_exact(key, 1u, key_len, store->wal_fd) &&
              fwrite_exact(value ? value : "", 1u, val_len, store->wal_fd);
    if (!ok) return false;
    store->wal_unflushed_bytes += 32u + key_len + val_len;
    if (store->wal_unflushed_bytes >= WAL_BUFFER_FLUSH_THRESHOLD) flush_wal_buffer(store);
    return true;
}

/* Read a single record by (file id, byte offset) as pinpointed by the
 * metadata index. */
static kv_lookup_state_t lookup_one_sstable(const char* dir, const char* key,
                                            int32_t sstable_id, uint64_t offset,
                                            kv_lookup_result_t* out) {
    char path[4096];
    int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, sstable_id);
    if (n < 0 || (size_t)n >= sizeof(path)) return KV_LOOKUP_ERROR;
    int fd = open_secure_read(path);
    if (fd < 0) return (errno == ENOENT) ? KV_LOOKUP_MISS : KV_LOOKUP_ERROR;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return KV_LOOKUP_ERROR; }
    if (fseeko(f, (off_t)offset, SEEK_SET) != 0) { fclose(f); return KV_LOOKUP_ERROR; }
    uint64_t now = current_time_ms();
    kv_disk_record_t r;
    int rc = disk_record_read(f, &r);
    if (rc != 1) { fclose(f); return (rc < 0) ? KV_LOOKUP_ERROR : KV_LOOKUP_MISS; }
    if (strcmp(r.key, key) != 0) { disk_record_free(&r); fclose(f); return KV_LOOKUP_MISS; }
    out->classification = r.classification;
    out->sci_compartment = r.sci_compartment;
    out->expire_time_ms = r.expire_time_ms;
    out->flags = r.flags;
    bool dead = (r.flags & KV_FLAG_TOMBSTONE) != 0u ||
                (r.expire_time_ms != 0u && r.expire_time_ms <= now);
    if (!dead) { out->value = r.val; r.val = NULL; }
    disk_record_free(&r); fclose(f);
    out->state = dead ? KV_LOOKUP_DEAD : KV_LOOKUP_LIVE;
    return out->state;
}

static kv_lookup_state_t lookup_sstables(qihse_kv_store_t* store, const char* key,
                                         kv_lookup_result_t* out) {
    if (!store || !key || !out) return KV_LOOKUP_ERROR;
    const char* dir = get_qihse_data_dir();
    if (!dir) return KV_LOOKUP_ERROR;
    uint64_t now = current_time_ms();
    for (int i = store->sstable_counter - 1; i >= 0; i--) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, i);
        if (n < 0 || (size_t)n >= sizeof(path)) return KV_LOOKUP_ERROR;
        int fd = open_secure_read(path);
        if (fd < 0) { if (errno == ENOENT) continue; return KV_LOOKUP_ERROR; }
        FILE* f = fdopen(fd, "rb");
        if (!f) { close(fd); return KV_LOOKUP_ERROR; }
        kv_disk_record_t r; int rc;
        while ((rc = disk_record_read(f, &r)) == 1) {
            if (strcmp(r.key, key) == 0) {
                out->classification = r.classification;
                out->sci_compartment = r.sci_compartment;
                out->expire_time_ms = r.expire_time_ms;
                out->flags = r.flags;
                bool dead = (r.flags & KV_FLAG_TOMBSTONE) != 0u ||
                            (r.expire_time_ms != 0u && r.expire_time_ms <= now);
                if (!dead) { out->value = r.val; r.val = NULL; }
                disk_record_free(&r); fclose(f);
                out->state = dead ? KV_LOOKUP_DEAD : KV_LOOKUP_LIVE;
                return out->state;
            }
            disk_record_free(&r);
        }
        fclose(f);
        if (rc < 0) return KV_LOOKUP_ERROR;
    }
    return KV_LOOKUP_MISS;
}

static kv_lookup_state_t logical_lookup(qihse_kv_store_t* store, const char* key,
                                        kv_lookup_result_t* out) {
    if (!out) return KV_LOOKUP_ERROR;
    memset(out, 0, sizeof(*out)); out->state = KV_LOOKUP_MISS;
    if (!store || !store->trie || !key) return KV_LOOKUP_ERROR;
    size_t out_size = 0u;
    kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &out_size);
    if (p) {
        out->classification = p->classification;
        out->sci_compartment = p->sci_compartment;
        out->expire_time_ms = p->expire_time_ms;
        out->flags = p->flags;
        if (payload_is_dead(p, current_time_ms())) { out->state = KV_LOOKUP_DEAD; return out->state; }
        out->value = strdup(p->val);
        if (!out->value) { out->state = KV_LOOKUP_ERROR; return out->state; }
        out->state = KV_LOOKUP_LIVE; return out->state;
    }
    /* Fast path: the SSTable metadata index pinpoints the single file holding
     * the newest copy, so we open just that file instead of scanning them all.
     * When the index is complete (not degraded) an index miss is authoritative:
     * the key is absent from every SSTable. */
    if (store->sst_meta && !store->sst_meta->degraded) {
        int32_t sid = -1; uint64_t off = 0u;
        if (sst_meta_index_lookup(store->sst_meta, key, NULL, NULL, NULL, NULL, &sid, &off)) {
            const char* dir = get_qihse_data_dir();
            if (!dir) return KV_LOOKUP_ERROR;
            return lookup_one_sstable(dir, key, sid, off, out);
        }
        return KV_LOOKUP_MISS;
    }
    return lookup_sstables(store, key, out);
}

static void lookup_result_free(kv_lookup_result_t* r) {
    if (!r) return; free(r->value); memset(r, 0, sizeof(*r));
}

typedef struct { qihse_trinary_trie_t* dst; bool ok; size_t mem_usage; } copy_trie_ctx_t;
static bool copy_payload_cb(const char* key, void* value, size_t value_size, void* user_data) {
    copy_trie_ctx_t* ctx = (copy_trie_ctx_t*)user_data;
    if (!ctx || !ctx->ok || !key || !value || value_size < sizeof(kv_payload_t)) return false;
    void* copy = malloc(value_size);
    if (!copy) { ctx->ok = false; return false; }
    memcpy(copy, value, value_size);
    if (!qihse_trinary_trie_insert_nocopy(ctx->dst, key, copy, value_size)) {
        free(copy); ctx->ok = false; return false;
    }
    ctx->mem_usage += strlen(key) + value_size;
    return true;
}

static bool load_sstable_into_trie(const char* path, qihse_trinary_trie_t* dst, size_t* mem_usage) {
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    kv_disk_record_t r; int rc; bool ok = true;
    while ((rc = disk_record_read(f, &r)) == 1) {
        size_t ps = 0u;
        kv_payload_t* p = payload_create(r.val, r.expire_time_ms, r.classification,
                                         r.sci_compartment, r.flags, &ps);
        if (!p || !qihse_trinary_trie_insert_nocopy(dst, r.key, p, ps)) {
            free(p); disk_record_free(&r); ok = false; break;
        }
        if (mem_usage) *mem_usage += strlen(r.key) + ps;
        disk_record_free(&r);
    }
    if (rc < 0) ok = false;
    fclose(f); return ok;
}

static bool compact_sstables_into_memtable(qihse_kv_store_t* store) {
    if (!store || !store->trie) return false;
    if (store->sstable_counter == 0) return true;
    qihse_trinary_trie_t* merged = qihse_trinary_trie_create();
    if (!merged) return false;
    size_t merged_usage = 0u;
    const char* dir = get_qihse_data_dir();
    if (!dir) { qihse_trinary_trie_destroy(merged); return false; }
    for (int i = 0; i < store->sstable_counter; i++) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, i);
        if (n < 0 || (size_t)n >= sizeof(path) || !load_sstable_into_trie(path, merged, &merged_usage)) {
            qihse_trinary_trie_destroy(merged); return false;
        }
    }
    copy_trie_ctx_t copy_ctx = { .dst = merged, .ok = true, .mem_usage = merged_usage };
    qihse_trinary_trie_foreach(store->trie, copy_payload_cb, &copy_ctx);
    if (!copy_ctx.ok) { qihse_trinary_trie_destroy(merged); return false; }
    qihse_trinary_trie_t* old = store->trie;
    store->trie = merged; store->mem_usage = copy_ctx.mem_usage;
    qihse_trinary_trie_destroy(old);
    for (int i = 0; i < store->sstable_counter; i++) {
        char path[4096]; int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, i);
        if (n >= 0 && (size_t)n < sizeof(path)) (void)unlink(path);
    }
    store->sstable_counter = 0;
    sst_meta_index_reset(store);
    return true;
}

static bool wal_replay_new_record(qihse_kv_store_t* store, FILE* f) {
    uint8_t op = 0u, flags = 0u;
    uint16_t key_len = 0u, classification = 0u, sci = 0u;
    uint32_t val_len = 0u;
    uint64_t expire = 0u, crc = 0u;
    if (fread(&op, sizeof(op), 1u, f) != 1u || fread(&flags, sizeof(flags), 1u, f) != 1u ||
        fread(&key_len, sizeof(key_len), 1u, f) != 1u || fread(&val_len, sizeof(val_len), 1u, f) != 1u ||
        fread(&classification, sizeof(classification), 1u, f) != 1u || fread(&sci, sizeof(sci), 1u, f) != 1u ||
        fread(&expire, sizeof(expire), 1u, f) != 1u || fread(&crc, sizeof(crc), 1u, f) != 1u) return false;
    if ((op != KV_WAL_OP_SET && op != KV_WAL_OP_DEL) || key_len == 0u ||
        val_len > KV_MAX_VALUE_LEN || (flags & ~KV_ALLOWED_FLAGS) != 0u) return false;
    if (op == KV_WAL_OP_DEL && (val_len != 0u || (flags & KV_FLAG_TOMBSTONE) == 0u)) return false;
    char* key = (char*)malloc((size_t)key_len + 1u);
    char* val = (char*)malloc((size_t)val_len + 1u);
    if (!key || !val) { free(key); free(val); return false; }
    if (fread(key, 1u, key_len, f) != key_len || fread(val, 1u, val_len, f) != val_len) {
        free(key); free(val); return false;
    }
    if (memchr(key, '\0', key_len) || memchr(val, '\0', val_len)) { free(key); free(val); return false; }
    key[key_len] = '\0'; val[val_len] = '\0';
    uint64_t actual = wal_record_crc(op, flags, key_len, val_len, classification, sci, expire, key, val);
    if (actual != crc) { free(key); free(val); return false; }
    bool ok = insert_internal(store, key, val, expire, classification, sci, flags);
    free(key); free(val); return ok;
}

static void recover_from_wal(qihse_kv_store_t* store) {
    if (!store) return;
    char wal_path[4096];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) return;
    int fd = open_secure_read(wal_path);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return; }
    for (;;) {
        int c = fgetc(f);
        if (c == EOF) break;
        if (c == 'Q') {
            char magic[4] = { 'Q', 0, 0, 0 };
            if (fread(magic + 1, 1u, 3u, f) != 3u) break;
            if (memcmp(magic, KV_WAL_MAGIC, 4u) != 0 || !wal_replay_new_record(store, f)) break;
            continue;
        }
        if (c == 'S') {
            char tag[4] = { 'S', 0, 0, 0 };
            if (fread(tag + 1, 1u, 3u, f) != 3u) break;
            if (tag[1] == 'E' && tag[2] == 'T' && tag[3] == '\0') {
                uint16_t key_len = 0u, classification = 0u, sci = 0u; uint32_t val_len = 0u;
                if (fread(&key_len, sizeof(key_len), 1u, f) != 1u || fread(&val_len, sizeof(val_len), 1u, f) != 1u ||
                    fread(&classification, sizeof(classification), 1u, f) != 1u || fread(&sci, sizeof(sci), 1u, f) != 1u ||
                    key_len == 0u || val_len > KV_MAX_VALUE_LEN) break;
                char* key = (char*)malloc((size_t)key_len + 1u); char* val = (char*)malloc((size_t)val_len + 1u);
                if (!key || !val) { free(key); free(val); break; }
                if (fread(key, 1u, key_len, f) != key_len || fread(val, 1u, val_len, f) != val_len) {
                    free(key); free(val); break;
                }
                key[key_len] = '\0'; val[val_len] = '\0';
                if (!insert_internal(store, key, val, 0u, classification, sci, 0u)) { free(key); free(val); break; }
                free(key); free(val); continue;
            }
            if (tag[1] == 'E' && tag[2] == 'T' && tag[3] == ' ') {
                char line[65536];
                if (!fgets(line, sizeof(line), f)) break;
                unsigned int classif = 0u, sci = 0u; char key[256], rest[63488];
                if (sscanf(line, "%255s %63487[^\n]", key, rest) >= 2) {
                    char* end = rest + strlen(rest);
                    while (end > rest && (end[-1] == ' ' || end[-1] == '\n')) --end;
                    *end = '\0';
                    char* p2 = strrchr(rest, ' ');
                    if (p2) { sci = (unsigned int)strtoul(p2 + 1, NULL, 10); *p2 = '\0';
                        char* p1 = strrchr(rest, ' ');
                        if (p1) { classif = (unsigned int)strtoul(p1 + 1, NULL, 10); *p1 = '\0'; }
                    }
                    if (classif <= UINT16_MAX && sci <= UINT16_MAX)
                        (void)insert_internal(store, key, rest, 0u, (uint16_t)classif, (uint16_t)sci, 0u);
                }
                continue;
            }
            break;
        }
        if (c == 'D') {
            char tag[4] = { 'D', 0, 0, 0 };
            if (fread(tag + 1, 1u, 3u, f) != 3u) break;
            if (tag[1] == 'E' && tag[2] == 'L' && tag[3] == ' ') {
                char line[KV_MAX_KEY_LEN + 2u];
                if (!fgets(line, sizeof(line), f)) break;
                line[strcspn(line, "\r\n")] = '\0';
                if (line[0] != '\0') {
                    kv_lookup_result_t prior; kv_lookup_state_t state = logical_lookup(store, line, &prior);
                    uint16_t cclass = 0u, csci = 0u;
                    if (state == KV_LOOKUP_LIVE || state == KV_LOOKUP_DEAD) { cclass = prior.classification; csci = prior.sci_compartment; }
                    lookup_result_free(&prior);
                    (void)insert_internal(store, line, "", 0u, cclass, csci, KV_FLAG_TOMBSTONE);
                }
                continue;
            }
            break;
        }
        break;
    }
    fclose(f);
}

/* Populate the in-memory SSTable metadata index from one on-disk SSTable. */
static void sst_index_load_file(qihse_kv_store_t* store, const char* path, int32_t sstable_id) {
    if (!store || !store->sst_meta || !path) return;
    int fd = open_secure_read(path);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return; }
    kv_disk_record_t r; int rc;
    for (;;) {
        long rec_off = ftell(f);
        rc = disk_record_read(f, &r);
        if (rc != 1) break;
        sst_meta_index_insert(store->sst_meta, r.key,
                              r.classification, r.sci_compartment,
                              r.expire_time_ms, r.flags, sstable_id,
                              rec_off >= 0 ? (uint64_t)rec_off : 0u);
        disk_record_free(&r);
    }
    fclose(f);
}

qihse_kv_store_t* qihse_kv_store_create(void) {
    qihse_kv_store_t* store = (qihse_kv_store_t*)calloc(1u, sizeof(*store));
    if (!store) return NULL;
    store->trie = qihse_trinary_trie_create();
    if (!store->trie) { free(store); return NULL; }
    store->sst_meta = sst_meta_index_create();
    if (!store->sst_meta) { qihse_kv_store_destroy(store); return NULL; }
    const char* dir = get_qihse_data_dir();
    if (!dir) { qihse_kv_store_destroy(store); return NULL; }
    DIR* d = opendir(dir);
    if (d) {
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "sstable_", 8u) == 0) {
                char* end = NULL; long id = strtol(ent->d_name + 8u, &end, 10);
                if (end && strcmp(end, ".db") == 0 && id >= 0 && id < INT_MAX && id + 1 > store->sstable_counter)
                    store->sstable_counter = (int)id + 1;
            }
        }
        closedir(d);
    }
    /* Load key metadata from existing SSTables (oldest first so newer files
     * overwrite older entries, matching lookup_sstables' newest-first scan). */
    for (int i = 0; i < store->sstable_counter; i++) {
        char sst_path[4096];
        int n = snprintf(sst_path, sizeof(sst_path), "%ssstable_%d.db", dir, i);
        if (n < 0 || (size_t)n >= sizeof(sst_path)) continue;
        sst_index_load_file(store, sst_path, i);
    }
    recover_from_wal(store);
    char wal_path[4096];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) { qihse_kv_store_destroy(store); return NULL; }
    int fd = open(wal_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { qihse_kv_store_destroy(store); return NULL; }
    store->wal_fd = fdopen(fd, "ab");
    if (!store->wal_fd) { close(fd); qihse_kv_store_destroy(store); return NULL; }
    return store;
}

void qihse_kv_store_destroy(qihse_kv_store_t* store) {
    if (!store) return;
    if (store->qdd_ctx) qihse_qdd_free(__atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE));
    if (store->wal_fd) { flush_wal_buffer(store); fclose(store->wal_fd); }
    if (store->trie) qihse_trinary_trie_destroy(store->trie);
    sst_meta_index_destroy(store->sst_meta);
    free(store);
}

void qihse_kv_bulk_load_begin(qihse_kv_store_t* store) { if (store) store->bulk_load_mode = true; }
void qihse_kv_bulk_load_end(qihse_kv_store_t* store) {
    if (!store) return; store->bulk_load_mode = false; flush_wal_buffer(store);
}

static bool set_user_with_expiry(qihse_kv_store_t* store, const char* key, const char* value,
                                 uint64_t expire_time_ms, uint16_t classification,
                                 uint16_t sci_compartment, qihse_user_t* user) {
    if (!store || !store->trie || !key || !value || key[0] == '\0') return false;
    if (strlen(key) > KV_MAX_KEY_LEN || strlen(value) > KV_MAX_VALUE_LEN) return false;
    if (!qihse_auth_can_access(user, classification, sci_compartment)) return false;
    /* Determine whether the key already exists, and at what classification, so
     * the auth-on-overwrite invariant can be enforced.  The memtable (trie) is
     * newest; the SSTable metadata index covers flushed data.  Both are
     * in-memory, so this no longer linear-scans every SSTable per write.
     * If the index is degraded (OOM) we fall back to the authoritative
     * logical_lookup() so authorization is never skipped. */
    bool key_exists = false;
    uint16_t ex_class = 0u, ex_comp = 0u;
    size_t existing_size = 0u;
    kv_payload_t* trie_hit = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &existing_size);
    if (trie_hit) {
        key_exists = true;
        ex_class = trie_hit->classification;
        ex_comp = trie_hit->sci_compartment;
    } else if (store->sst_meta && !store->sst_meta->degraded) {
        uint64_t ex_expire = 0u; uint8_t ex_flags = 0u;
        if (sst_meta_index_lookup(store->sst_meta, key, &ex_class, &ex_comp, &ex_expire, &ex_flags, NULL, NULL)) {
            key_exists = true;
        }
    } else {
        kv_lookup_result_t existing;
        kv_lookup_state_t state = logical_lookup(store, key, &existing);
        if (state == KV_LOOKUP_ERROR) return false;
        if (state == KV_LOOKUP_LIVE || state == KV_LOOKUP_DEAD) {
            key_exists = true;
            ex_class = existing.classification;
            ex_comp = existing.sci_compartment;
        }
        lookup_result_free(&existing);
    }
    if (key_exists && !qihse_auth_can_access(user, ex_class, ex_comp)) return false;
    if (!wal_append(store, KV_WAL_OP_SET, key, value, expire_time_ms, classification, sci_compartment, 0u)) return false;
    if (!insert_internal(store, key, value, expire_time_ms, classification, sci_compartment, 0u)) return false;
    if (!store->bulk_load_mode && store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) return false;
    return true;
}

bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value,
                       uint16_t classification, uint16_t sci_compartment, qihse_user_t* user) {
    return set_user_with_expiry(store, key, value, 0u, classification, sci_compartment, user);
}

bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value,
                  uint16_t classification, uint16_t sci_compartment) {
    return qihse_kv_set_user(store, key, value, classification, sci_compartment, NULL);
}

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return NULL;
    if (!store->qdd_ctx) {
        qihse_quantum_defense_ctx_t* ctx = qihse_qdd_init();
        __atomic_store_n(&store->qdd_ctx, ctx, __ATOMIC_RELEASE);
    }
    qihse_quantum_defense_ctx_t* qdd = __atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE);
    if (qdd) {
        uint64_t h = 14695981039346656037ULL; h = fnv1a64_update(h, key, strlen(key));
        qihse_qdd_report_access(qdd, h, "0.0.0.0");
    }
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE || !qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
        lookup_result_free(&r); return NULL;
    }
    char* value = r.value; r.value = NULL; lookup_result_free(&r); return value;
}

bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    char* v = qihse_kv_get_user(store, key, user); if (!v) return false; free(v); return true;
}

bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return false;
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE) { lookup_result_free(&r); return false; }
    if (!qihse_auth_can_access(user, r.classification, r.sci_compartment)) { lookup_result_free(&r); return false; }
    uint16_t classification = r.classification, sci = r.sci_compartment; lookup_result_free(&r);
    if (!wal_append(store, KV_WAL_OP_DEL, key, "", 0u, classification, sci, KV_FLAG_TOMBSTONE)) return false;
    if (!insert_internal(store, key, "", 0u, classification, sci, KV_FLAG_TOMBSTONE)) return false;
    if (!store->bulk_load_mode && store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) return false;
    return true;
}

bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms, qihse_user_t* user) {
    if (!store || !key) return false;
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE || !qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
        lookup_result_free(&r); return false;
    }
    uint64_t expire = current_time_ms();
    if (UINT64_MAX - expire < ttl_ms) { lookup_result_free(&r); return false; }
    expire += ttl_ms;
    bool ok = set_user_with_expiry(store, key, r.value, expire, r.classification, r.sci_compartment, user);
    lookup_result_free(&r); return ok;
}

int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return -2;
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE || !qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
        lookup_result_free(&r); return -2;
    }
    if (r.expire_time_ms == 0u) { lookup_result_free(&r); return -1; }
    uint64_t now = current_time_ms();
    if (r.expire_time_ms <= now) { lookup_result_free(&r); return -2; }
    uint64_t remaining = r.expire_time_ms - now; lookup_result_free(&r);
    return remaining > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)remaining;
}

typedef struct { uint64_t now; char** keys; size_t count; size_t cap; bool ok; } expired_collect_ctx_t;
static bool collect_expired_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; expired_collect_ctx_t* ctx = (expired_collect_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if ((p->flags & KV_FLAG_TOMBSTONE) == 0u && p->expire_time_ms != 0u && p->expire_time_ms <= ctx->now) {
        if (ctx->count == ctx->cap) {
            size_t new_cap = ctx->cap ? ctx->cap * 2u : 32u;
            char** next = (char**)realloc(ctx->keys, new_cap * sizeof(*next));
            if (!next) { ctx->ok = false; return false; }
            ctx->keys = next; ctx->cap = new_cap;
        }
        ctx->keys[ctx->count] = strdup(key);
        if (!ctx->keys[ctx->count]) { ctx->ok = false; return false; }
        ctx->count++;
    }
    return true;
}

void qihse_kv_sweep_expired(qihse_kv_store_t* store) {
    if (!store || !store->trie || store->bulk_load_mode) return;
    if (!compact_sstables_into_memtable(store)) return;
    expired_collect_ctx_t ctx = { .now = current_time_ms(), .ok = true };
    qihse_trinary_trie_foreach(store->trie, collect_expired_cb, &ctx);
    if (ctx.ok) {
        for (size_t i = 0; i < ctx.count; i++) {
            size_t sz = 0u; kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, ctx.keys[i], &sz);
            if (p) {
                uint16_t c = p->classification, s = p->sci_compartment;
                (void)wal_append(store, KV_WAL_OP_DEL, ctx.keys[i], "", 0u, c, s, KV_FLAG_TOMBSTONE);
                (void)insert_internal(store, ctx.keys[i], "", 0u, c, s, KV_FLAG_TOMBSTONE);
            }
        }
    }
    for (size_t i = 0; i < ctx.count; i++) free(ctx.keys[i]); free(ctx.keys);
}

typedef struct { qihse_user_t* user; qihse_kv_iter_cb cb; void* user_data; uint64_t now; bool ok; } foreach_user_ctx_t;
static bool foreach_user_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; foreach_user_ctx_t* ctx = (foreach_user_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if (payload_is_dead(p, ctx->now)) return true;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) return true;
    return ctx->cb(key, p->val, ctx->user_data);
}

bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user,
                           qihse_kv_iter_cb cb, void* user_data) {
    if (!store || !cb || !compact_sstables_into_memtable(store)) return false;
    foreach_user_ctx_t ctx = { .user = user, .cb = cb, .user_data = user_data, .now = current_time_ms(), .ok = true };
    qihse_trinary_trie_foreach(store->trie, foreach_user_cb, &ctx); return ctx.ok;
}
void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data) {
    (void)qihse_kv_foreach_user(store, NULL, cb, user_data);
}

typedef struct { qihse_user_t* user; size_t count; uint64_t now; } count_ctx_t;
static bool count_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)key; (void)value_size; count_ctx_t* ctx = (count_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !p) return false;
    if (!payload_is_dead(p, ctx->now) && qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) ctx->count++;
    return true;
}
size_t qihse_kv_count_user(qihse_kv_store_t* store, qihse_user_t* user) {
    if (!store || !compact_sstables_into_memtable(store)) return 0u;
    count_ctx_t ctx = { .user = user, .count = 0u, .now = current_time_ms() };
    qihse_trinary_trie_foreach(store->trie, count_cb, &ctx); return ctx.count;
}
size_t qihse_kv_count(qihse_kv_store_t* store) { return qihse_kv_count_user(store, NULL); }

typedef struct { qihse_user_t* user; char** keys; size_t count; size_t cap; uint64_t now; bool ok; } clear_collect_ctx_t;
static bool clear_collect_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; clear_collect_ctx_t* ctx = (clear_collect_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if (payload_is_dead(p, ctx->now) || !qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) return true;
    if (ctx->count == ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2u : 32u; char** next = (char**)realloc(ctx->keys, new_cap * sizeof(*next));
        if (!next) { ctx->ok = false; return false; } ctx->keys = next; ctx->cap = new_cap;
    }
    ctx->keys[ctx->count] = strdup(key);
    if (!ctx->keys[ctx->count]) { ctx->ok = false; return false; }
    ctx->count++; return true;
}
size_t qihse_kv_clear_user(qihse_kv_store_t* store, qihse_user_t* user) {
    if (!store || !compact_sstables_into_memtable(store)) return 0u;
    clear_collect_ctx_t ctx = { .user = user, .now = current_time_ms(), .ok = true };
    qihse_trinary_trie_foreach(store->trie, clear_collect_cb, &ctx);
    size_t removed = 0u;
    if (ctx.ok) for (size_t i = 0; i < ctx.count; i++) if (qihse_kv_del_user(store, ctx.keys[i], user)) removed++;
    for (size_t i = 0; i < ctx.count; i++) free(ctx.keys[i]); free(ctx.keys); return removed;
}
size_t qihse_kv_clear(qihse_kv_store_t* store) { return qihse_kv_clear_user(store, NULL); }

typedef struct { qihse_user_t* user; uint64_t now; bool authorized; } export_auth_ctx_t;
static bool export_auth_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)key; (void)value_size; export_auth_ctx_t* ctx = (export_auth_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !p) return false;
    if (payload_is_dead(p, ctx->now)) return true;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) { ctx->authorized = false; return false; }
    return true;
}
typedef struct { FILE* f; uint64_t now; bool ok; } export_write_ctx_t;
static bool export_write_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; export_write_ctx_t* ctx = (export_write_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if (payload_is_dead(p, ctx->now)) return true;
    if (!disk_record_write(ctx->f, key, p)) { ctx->ok = false; return false; }
    return true;
}
int qihse_kv_save_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user) {
    if (!store || !filepath || !compact_sstables_into_memtable(store)) return -1;
    export_auth_ctx_t auth = { .user = user, .now = current_time_ms(), .authorized = true };
    qihse_trinary_trie_foreach(store->trie, export_auth_cb, &auth);
    if (!auth.authorized) { errno = EACCES; return -2; }
    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &f)) return -1;
    export_write_ctx_t wr = { .f = f, .now = current_time_ms(), .ok = true };
    qihse_trinary_trie_foreach(store->trie, export_write_cb, &wr);
    if (!wr.ok || ferror(f)) { fclose(f); unlink(tmp); return -1; }
    if (!atomic_file_commit(f, tmp, filepath)) return -1;
    return 0;
}
int qihse_kv_save(qihse_kv_store_t* store, const char* filepath) { return qihse_kv_save_user(store, filepath, NULL); }

static bool parse_snapshot_into_trie(const char* filepath, qihse_user_t* user,
                                     qihse_trinary_trie_t** out_trie, size_t* out_usage) {
    int fd = open_secure_read(filepath);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    qihse_trinary_trie_t* trie = qihse_trinary_trie_create();
    if (!trie) { fclose(f); return false; }
    size_t usage = 0u; kv_disk_record_t r; int rc; bool ok = true;
    while ((rc = disk_record_read(f, &r)) == 1) {
        if (!qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
            disk_record_free(&r); errno = EACCES; ok = false; break;
        }
        size_t ps = 0u;
        kv_payload_t* p = payload_create(r.val, r.expire_time_ms, r.classification, r.sci_compartment, r.flags, &ps);
        if (!p || !qihse_trinary_trie_insert_nocopy(trie, r.key, p, ps)) {
            free(p); disk_record_free(&r); ok = false; break;
        }
        usage += strlen(r.key) + ps; disk_record_free(&r);
    }
    if (rc < 0) ok = false;
    fclose(f);
    if (!ok) { qihse_trinary_trie_destroy(trie); return false; }
    *out_trie = trie; if (out_usage) *out_usage = usage; return true;
}

int qihse_kv_load_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user) {
    if (!store || !filepath) return -1;
    qihse_trinary_trie_t* replacement = NULL; size_t replacement_usage = 0u;
    if (!parse_snapshot_into_trie(filepath, user, &replacement, &replacement_usage))
        return errno == EACCES ? -2 : -1;
    char wal_path[4096], wal_tmp[8192];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) { qihse_trinary_trie_destroy(replacement); return -1; }
    FILE* new_wal_tmp = NULL;
    if (!atomic_file_begin(wal_path, wal_tmp, sizeof(wal_tmp), &new_wal_tmp)) { qihse_trinary_trie_destroy(replacement); return -1; }
    if (!atomic_file_commit(new_wal_tmp, wal_tmp, wal_path)) { qihse_trinary_trie_destroy(replacement); return -1; }
    int new_wal_fd = open(wal_path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (new_wal_fd < 0) { qihse_trinary_trie_destroy(replacement); return -1; }
    FILE* new_wal = fdopen(new_wal_fd, "ab");
    if (!new_wal) { close(new_wal_fd); qihse_trinary_trie_destroy(replacement); return -1; }
    qihse_trinary_trie_t* old = store->trie; FILE* old_wal = store->wal_fd;
    store->trie = replacement; store->mem_usage = replacement_usage; store->wal_fd = new_wal; store->wal_unflushed_bytes = 0u;
    if (old_wal) fclose(old_wal); if (old) qihse_trinary_trie_destroy(old);
    const char* dir = get_qihse_data_dir();
    if (dir) for (int i = 0; i < store->sstable_counter; i++) {
        char path[4096]; int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, i);
        if (n >= 0 && (size_t)n < sizeof(path)) (void)unlink(path);
    }
    store->sstable_counter = 0;
    sst_meta_index_reset(store);
    return 0;
}
int qihse_kv_load(qihse_kv_store_t* store, const char* filepath) { return qihse_kv_load_user(store, filepath, NULL); }

bool qihse_kv_store_is_under_attack(qihse_kv_store_t* store) {
    if (!store) return false;
    qihse_quantum_defense_ctx_t* ctx = __atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE);
    return ctx && qihse_qdd_is_under_attack(ctx);
}

typedef struct {
    qihse_kv_iter_cb cb;
    void* user_data;
    qihse_trinary_trie_t* trie;
    uint64_t now;
} kv_foreach_ctx_t;

static bool kv_foreach_callback(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size;
    kv_foreach_ctx_t* ctx = (kv_foreach_ctx_t*)user_data;
    if (!key || !value || !ctx) return true;
    kv_payload_t* p = (kv_payload_t*)value;
    if (p->expire_time_ms > 0 && p->expire_time_ms <= ctx->now) {
        qihse_trinary_trie_delete(ctx->trie, key);
        return true;
    }
    return ctx->cb(key, p->val, ctx->user_data);
}

