#include "qihse_kv_store.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64)
#if defined(__SSE4_2__) && defined(__AES__)
#include <nmmintrin.h>
#include <wmmintrin.h>
#define QIHSE_HW_HASH 1
#endif
#endif

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
#define KV_WAL_MAGIC_REPLICA "QKV3"
#define KV_REPLICA_CURSOR_MAGIC "QRC1"
#define KV_REPLICA_CURSOR_MAX_ITEMS 4096u
#define KV_REPLICA_CURSOR_MAX_ID 128u
#define KV_WAL_OP_SET 1u
#define KV_WAL_OP_DEL 2u

#ifdef QIHSE_REPLICA_CRASH_TEST
static void replica_install_test_crash_point(const char* point) {
    const char* selected = getenv("QIHSE_REPLICA_CRASH_AT");
    if (selected && point && strcmp(selected, point) == 0) _exit(86);
}
#else
#define replica_install_test_crash_point(point) ((void)(point))
#endif
#define KV_HEADER_LINE_MAX 256u

/* The text record header line, versioned by FIELD COUNT exactly the way the
 * flags field was: a reader accepts 5, 6 or 7 fields and defaults the rest.
 *
 *   5 fields  "key_len val_len expire classif sci\n"             (legacy, flags=0)
 *   6 fields  "key_len val_len expire classif sci flags\n"       (legacy, seq=0)
 *   7 fields  "key_len val_len expire classif sci flags seq\n"   (current)
 *
 * The 7th field is the store-global change sequence stamped on the record's
 * last authorized mutation.  A record written before sequences existed
 * decodes with sequence 0 — the defined value for "predates the sequence" —
 * so every older snapshot, SSTable and hand-built fixture stays readable.
 * Sequence-0 records are never part of a delta (a delta is "seq > since",
 * since >= 0): callers bootstrap with a full export and then track deltas.
 */
#define KV_SEQ_FIELDS_MIN 5
#define KV_SEQ_FIELDS_V4  7

typedef struct {
    uint64_t expire_time_ms;
    /* Store-global change sequence stamped on the mutation that produced
     * this payload.  0 means the record predates sequences (loaded from a
     * pre-v4 file) or was re-created by a legacy WAL replay. */
    uint64_t change_seq;
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

static inline uint64_t sst_meta_hash(const char* key) {
    if (!key) return 0;
    size_t len = strlen(key);
#if defined(QIHSE_HW_HASH)
    const uint8_t* p = (const uint8_t*)key;
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
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)((const unsigned char*)key)[i];
        h *= 1099511628211ULL;
    }
    return h;
#endif
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
    bool replica_read_only;
    sst_meta_index_t* sst_meta;
    /* Store-global monotonic change sequence: the LAST sequence issued to an
     * authorized mutation (the high-water).  Advanced once per authorized
     * set/delete and stamped on the affected record's payload; maintained
     * with atomics so concurrent writers get unique sequences without a
     * store-wide lock (the write path is otherwise unlocked, same as
     * mem_usage).  Loads/restores raise it with a CAS-max so a restore never
     * regresses it; it is never reset.  Exposed through
     * qihse_kv_change_seq(). */
    uint64_t change_seq;
    struct kv_replica_cursor* replica_cursors;
    /* Read-side fd cache: keep a bounded set of SSTable fds open so a
     * point GET on flushed data does not pay open()+close() per request.
     * Safe because SSTable files are immutable once written and ids are
     * monotonically increasing.  Invalidated whenever SSTables are deleted
     * or replaced (compaction, load, destroy).  Reads use pread() so there
     * is no shared file position — sst_fd_lock only covers cache
     * lookup/insert, letting concurrent readers hit the same fd in
     * parallel when kv_lock is held read-side. */
    pthread_mutex_t sst_fd_lock;
    struct { int32_t sid; int fd; } sst_fds[8];
    /* Store-internal operation lock (nil-GET fix 2026-10-02).  The store
     * mutates its whole read structure in place: flush_memtable_to_sstable()
     * swaps and destroys the memtable trie, sst_meta_index_grow() frees the
     * index slot array mid-lookup, insert_internal() replaces payloads.  The
     * RESP surface serializes with its engine kv_lock, but several modules
     * (AI memory, federation, cluster brain, fabric dispatch, backup, the
     * bus group path and the killswitch fan-out) call the public qihse_kv_*
     * API directly on background threads with no external lock, so a lookup
     * could land inside a flush window and answer nil for an existing key
     * (or fault).  Every public operation now takes this lock: read-side for
     * pure reads, write-side for mutations and for any path that may run
     * compaction.  Lock ORDER with the engine kv_lock is strictly
     * outer(kv_lock) -> inner(store_lock) and this lock never calls back
     * out, so no cycle is possible.  Reader-preferring kind so enumeration
     * callbacks may call qihse_kv_get_user re-entrantly (rd-over-rd). */
    pthread_rwlock_t store_lock;
};

struct qihse_kv_replica_snapshot {
    int fd;
    uint64_t size;
};

typedef struct kv_replica_cursor {
    struct kv_replica_cursor* next;
    char* peer_id;
    char* namespace_id;
    uint64_t seq;
} kv_replica_cursor_t;

static bool fsync_dir_path(const char* dir);
bool qihse_kv_sync_store(qihse_kv_store_t* store);
static void replica_snapshot_marker_namespace(const char* glob, char out[48]);

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
    uint64_t change_seq;   /* 0 for pre-v4 records (defined default) */
} kv_disk_record_t;

/* ── Change sequence discipline ──────────────────────────────────────────
 *
 * One 64-bit counter per store, advanced on EVERY authorized mutation (set
 * with classification/SCI, delete, expiry-setting update, sweep tombstone)
 * and stamped on the mutated record's payload, which persists it through the
 * v4 record header.  The high-water is queryable (qihse_kv_change_seq) and
 * is the delta exporter's upper bound.
 *
 * Not advanced by: reads (get/exists/ttl), failed/unauthorized mutations,
 * compaction (which preserves stamped sequences), snapshot load (which
 * preserves them and only raises the high-water to the file's maximum).
 * Crash recovery replays the WAL, whose records carry no sequence (the
 * binary WAL format is unchanged for backward compatibility): each replayed
 * mutation is re-stamped with a fresh sequence.  Replay order is mutation
 * order, so relative order survives; the store never regresses. */

/* Issue the next sequence.  0 means the counter is exhausted (2^64
 * mutations): the caller must fail the mutation rather than issue a
 * duplicate sequence.  The counter is pinned at UINT64_MAX on exhaustion so
 * every later mutation keeps failing closed. */
static uint64_t kv_change_seq_next(qihse_kv_store_t* store) {
    if (!store) return 0u;
    uint64_t seq = __atomic_add_fetch(&store->change_seq, 1u, __ATOMIC_RELAXED);
    if (seq != 0u) return seq;
    __atomic_store_n(&store->change_seq, UINT64_MAX, __ATOMIC_RELAXED);
    return 0u;
}

/* Raise the high-water to at least `floor` (persist/load paths feed the
 * maximum sequence they observed).  Never lowers. */
static void kv_change_seq_floor(qihse_kv_store_t* store, uint64_t floor) {
    if (!store || floor == 0u) return;
    uint64_t cur = __atomic_load_n(&store->change_seq, __ATOMIC_RELAXED);
    while (floor > cur &&
           !__atomic_compare_exchange_n(&store->change_seq, &cur, floor,
                                        false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        /* cur was reloaded on failure; retry while the floor is still above. */
    }
}

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
    uint64_t change_seq;
} kv_lookup_result_t;

static uint64_t current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

/* Resolved data directory (cached; trailing slash guaranteed). */
static char data_dir[4096] = {0};

/* A candidate data directory is usable only if the store's WAL file is
 * either creatable by us (directory writable, no hostile file) or openable
 * for append (pre-existing file we own/access). access() on the directory
 * alone is NOT sufficient: /opt/qihse-data may be group/other-writable via
 * ownership while wal.log inside is root-owned 0600. Never touches or
 * deletes a pre-existing wal.log. */
static bool data_dir_usable(const char* dir) {
    char path[4096];
    if (!dir) return false;
    int n = snprintf(path, sizeof(path), "%swal.log", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        close(fd);
        unlink(path); /* probe artifact only; the real create re-creates it */
        return true;
    }
    if (errno != EEXIST) return false; /* EACCES/EROFS/... : directory itself unusable */
    fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false; /* pre-existing file not ours to append */
    close(fd);
    return true;
}

static bool data_dir_probe_and_set(const char* dir) {
    if (!data_dir_usable(dir)) return false;
    snprintf(data_dir, sizeof(data_dir), "%s", dir);
    return true;
}

static const char* get_qihse_data_dir(void) {
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
    if (access("/opt/qihse-data", R_OK | W_OK) == 0 &&
        data_dir_probe_and_set("/opt/qihse-data/")) {
        return data_dir;
    }
    if (access("/var/lib/qihse", R_OK | W_OK) == 0 &&
        data_dir_probe_and_set("/var/lib/qihse/")) {
        return data_dir;
    }
    (void)mkdir("/opt/qihse-data", 0700);
    (void)chmod("/opt/qihse-data", 0700);
    if (data_dir_probe_and_set("/opt/qihse-data/")) {
        return data_dir;
    }
    /* Last resort (original behavior): a workspace-local directory. */
    if (mkdir("data", 0700) == 0 || errno == EEXIST) {
        (void)chmod("data", 0700);
        if (mkdir("data/qihse", 0700) == 0 || errno == EEXIST) {
            (void)chmod("data/qihse", 0700);
            if (data_dir_probe_and_set("data/qihse/")) {
                return data_dir;
            }
        }
    }
    return NULL;
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

static uint64_t cursor_file_crc(uint32_t count, const kv_replica_cursor_t* entries) {
    uint64_t h = 14695981039346656037ULL;
    h = fnv1a64_update(h, KV_REPLICA_CURSOR_MAGIC, 4u);
    h = fnv1a64_update(h, &count, sizeof(count));
    for (const kv_replica_cursor_t* e = entries; e; e = e->next) {
        uint16_t pl = (uint16_t)strlen(e->peer_id), nl = (uint16_t)strlen(e->namespace_id);
        h = fnv1a64_update(h, &pl, sizeof(pl));
        h = fnv1a64_update(h, &nl, sizeof(nl));
        h = fnv1a64_update(h, &e->seq, sizeof(e->seq));
        h = fnv1a64_update(h, e->peer_id, pl);
        h = fnv1a64_update(h, e->namespace_id, nl);
    }
    return h;
}

static bool cursor_id_valid(const char* s) {
    if (!s) return false;
    size_t n = strlen(s);
    if (n == 0u || n > KV_REPLICA_CURSOR_MAX_ID) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-' ||
              c == '*' || c == '?' || c == '[' || c == ']' || c == '/')) return false;
    }
    return true;
}

static kv_replica_cursor_t* cursor_find(qihse_kv_store_t* store, const char* peer, const char* ns) {
    for (kv_replica_cursor_t* e = store ? store->replica_cursors : NULL; e; e = e->next)
        if (strcmp(e->peer_id, peer) == 0 && strcmp(e->namespace_id, ns) == 0) return e;
    return NULL;
}

static void cursor_list_free(kv_replica_cursor_t* e) {
    while (e) { kv_replica_cursor_t* next = e->next; free(e->peer_id); free(e->namespace_id); free(e); e = next; }
}

static bool cursor_write_file(const char* path, const kv_replica_cursor_t* entries, uint32_t count) {
    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(path, tmp, sizeof(tmp), &f)) return false;
    bool ok = fwrite_exact(KV_REPLICA_CURSOR_MAGIC, 1u, 4u, f) &&
              fwrite_exact(&count, sizeof(count), 1u, f);
    for (const kv_replica_cursor_t* e = entries; ok && e; e = e->next) {
        uint16_t pl = (uint16_t)strlen(e->peer_id), nl = (uint16_t)strlen(e->namespace_id);
        ok = fwrite_exact(&pl, sizeof(pl), 1u, f) && fwrite_exact(&nl, sizeof(nl), 1u, f) &&
             fwrite_exact(&e->seq, sizeof(e->seq), 1u, f) &&
             fwrite_exact(e->peer_id, 1u, pl, f) && fwrite_exact(e->namespace_id, 1u, nl, f);
    }
    uint64_t crc = cursor_file_crc(count, entries);
    if (ok) ok = fwrite_exact(&crc, sizeof(crc), 1u, f);
    if (!ok || ferror(f)) { fclose(f); unlink(tmp); return false; }
    return atomic_file_commit(f, tmp, path);
}

static bool cursor_read_file(qihse_kv_store_t* store) {
    char path[4096];
    if (!build_data_path(path, sizeof(path), "replica-cursors.bin")) return false;
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    char magic[4]; uint32_t count = 0u; bool ok = fread(magic, 1u, 4u, f) == 4u &&
        memcmp(magic, KV_REPLICA_CURSOR_MAGIC, 4u) == 0 && fread(&count, sizeof(count), 1u, f) == 1u &&
        count <= KV_REPLICA_CURSOR_MAX_ITEMS;
    kv_replica_cursor_t* list = NULL; kv_replica_cursor_t** tail = &list; uint32_t loaded = 0u;
    while (ok && loaded < count) {
        uint16_t pl = 0u, nl = 0u; uint64_t seq = 0u;
        if (fread(&pl, sizeof(pl), 1u, f) != 1u || fread(&nl, sizeof(nl), 1u, f) != 1u ||
            fread(&seq, sizeof(seq), 1u, f) != 1u || pl == 0u || nl == 0u ||
            pl > KV_REPLICA_CURSOR_MAX_ID || nl > KV_REPLICA_CURSOR_MAX_ID) { ok = false; break; }
        kv_replica_cursor_t* e = (kv_replica_cursor_t*)calloc(1u, sizeof(*e));
        if (!e) { ok = false; break; }
        e->peer_id = (char*)malloc((size_t)pl + 1u); e->namespace_id = (char*)malloc((size_t)nl + 1u); e->seq = seq;
        if (!e->peer_id || !e->namespace_id || fread(e->peer_id, 1u, pl, f) != pl || fread(e->namespace_id, 1u, nl, f) != nl) {
            free(e->peer_id); free(e->namespace_id); free(e); ok = false; break;
        }
        e->peer_id[pl] = '\0'; e->namespace_id[nl] = '\0';
        bool duplicate = false;
        for (kv_replica_cursor_t* prior = list; prior; prior = prior->next)
            if (strcmp(prior->peer_id, e->peer_id) == 0 && strcmp(prior->namespace_id, e->namespace_id) == 0) duplicate = true;
        if (!cursor_id_valid(e->peer_id) || !cursor_id_valid(e->namespace_id) || duplicate) {
            free(e->peer_id); free(e->namespace_id); free(e); ok = false; break;
        }
        *tail = e; tail = &e->next; loaded++;
    }
    uint64_t stored_crc = 0u;
    if (ok) ok = fread(&stored_crc, sizeof(stored_crc), 1u, f) == 1u && fgetc(f) == EOF &&
                 stored_crc == cursor_file_crc(count, list);
    fclose(f);
    if (!ok) { cursor_list_free(list); return false; }
    store->replica_cursors = list;
    return true;
}

typedef struct {
    char peer[KV_REPLICA_CURSOR_MAX_ID + 1u];
    char glob[KV_REPLICA_CURSOR_MAX_ID + 1u];
    uint64_t source_seq;
    uint64_t image_hash;
} replica_install_meta_t;

static uint64_t replica_install_meta_crc(const replica_install_meta_t* m) {
    uint64_t h = 14695981039346656037ULL;
    uint16_t pl = (uint16_t)strlen(m->peer), gl = (uint16_t)strlen(m->glob);
    h = fnv1a64_update(h, "QRIM1", 5u);
    h = fnv1a64_update(h, &pl, sizeof(pl)); h = fnv1a64_update(h, &gl, sizeof(gl));
    h = fnv1a64_update(h, &m->source_seq, sizeof(m->source_seq));
    h = fnv1a64_update(h, &m->image_hash, sizeof(m->image_hash));
    h = fnv1a64_update(h, m->peer, pl); h = fnv1a64_update(h, m->glob, gl);
    return h;
}

static bool replica_install_meta_write(const char* path, const replica_install_meta_t* m) {
    char tmp[8192]; FILE* f = NULL;
    if (!m || !cursor_id_valid(m->peer) || !cursor_id_valid(m->glob) ||
        !atomic_file_begin(path, tmp, sizeof(tmp), &f)) return false;
    uint16_t pl = (uint16_t)strlen(m->peer), gl = (uint16_t)strlen(m->glob);
    uint64_t crc = replica_install_meta_crc(m);
    bool ok = fwrite_exact("QRIM1", 1u, 5u, f) && fwrite_exact(&pl, sizeof(pl), 1u, f) &&
        fwrite_exact(&gl, sizeof(gl), 1u, f) &&
        fwrite_exact(&m->source_seq, sizeof(m->source_seq), 1u, f) &&
        fwrite_exact(&m->image_hash, sizeof(m->image_hash), 1u, f) &&
        fwrite_exact(m->peer, 1u, pl, f) && fwrite_exact(m->glob, 1u, gl, f) &&
        fwrite_exact(&crc, sizeof(crc), 1u, f);
    if (!ok) { fclose(f); unlink(tmp); return false; }
    if (!atomic_file_commit(f, tmp, path)) return false;
    return fsync_dir_path(get_qihse_data_dir());
}

static bool replica_install_meta_read(const char* path, replica_install_meta_t* m,
                                     bool* out_present) {
    if (out_present) *out_present = false;
    if (!path || !m || !out_present) return false;
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    *out_present = true;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    memset(m, 0, sizeof(*m));
    char magic[5]; uint16_t pl = 0u, gl = 0u; uint64_t crc = 0u;
    bool ok = fread(magic, 1u, sizeof(magic), f) == sizeof(magic) &&
        memcmp(magic, "QRIM1", sizeof(magic)) == 0 &&
        fread(&pl, sizeof(pl), 1u, f) == 1u && fread(&gl, sizeof(gl), 1u, f) == 1u &&
        fread(&m->source_seq, sizeof(m->source_seq), 1u, f) == 1u &&
        fread(&m->image_hash, sizeof(m->image_hash), 1u, f) == 1u &&
        pl != 0u && gl != 0u && pl <= KV_REPLICA_CURSOR_MAX_ID &&
        gl <= KV_REPLICA_CURSOR_MAX_ID &&
        fread(m->peer, 1u, pl, f) == pl && fread(m->glob, 1u, gl, f) == gl &&
        fread(&crc, sizeof(crc), 1u, f) == 1u && fgetc(f) == EOF;
    fclose(f);
    if (pl > KV_REPLICA_CURSOR_MAX_ID || gl > KV_REPLICA_CURSOR_MAX_ID) return false;
    m->peer[pl] = '\0'; m->glob[gl] = '\0';
    return ok && cursor_id_valid(m->peer) && cursor_id_valid(m->glob) &&
           crc == replica_install_meta_crc(m);
}

static bool copy_file_atomic_hash(const char* source, const char* destination,
                                  uint64_t* out_hash) {
    int fd = open_secure_read(source);
    if (fd < 0) return false;
    FILE* in = fdopen(fd, "rb");
    if (!in) { close(fd); return false; }
    char tmp[8192]; FILE* out = NULL;
    if (!atomic_file_begin(destination, tmp, sizeof(tmp), &out)) { fclose(in); return false; }
    uint8_t buffer[65536]; uint64_t hash = 14695981039346656037ULL; bool ok = true;
    for (;;) {
        size_t n = fread(buffer, 1u, sizeof(buffer), in);
        if (n) {
            hash = fnv1a64_update(hash, buffer, n);
            if (!fwrite_exact(buffer, 1u, n, out)) { ok = false; break; }
        }
        if (n < sizeof(buffer)) {
            if (ferror(in)) ok = false;
            break;
        }
    }
    fclose(in);
    if (!ok) { fclose(out); unlink(tmp); return false; }
    if (!atomic_file_commit(out, tmp, destination)) return false;
    if (out_hash) *out_hash = hash;
    return true;
}

static bool replica_install_recover_image(const char* dir) {
    char meta_path[4096], image_path[4096], candidate[4096], sstable0[4096], wal_path[4096];
    if (!dir) return false;
    int a = snprintf(meta_path, sizeof(meta_path), "%sreplica-install.meta", dir);
    int b = snprintf(image_path, sizeof(image_path), "%sreplica-install.image", dir);
    int c = snprintf(candidate, sizeof(candidate), "%sreplica-install.candidate", dir);
    int dpath = snprintf(sstable0, sizeof(sstable0), "%ssstable_0.db", dir);
    int w = snprintf(wal_path, sizeof(wal_path), "%swal.log", dir);
    if (a < 0 || (size_t)a >= sizeof(meta_path) || b < 0 || (size_t)b >= sizeof(image_path) ||
        c < 0 || (size_t)c >= sizeof(candidate) || dpath < 0 || (size_t)dpath >= sizeof(sstable0) ||
        w < 0 || (size_t)w >= sizeof(wal_path))
        return false;
    replica_install_meta_t meta; bool present = false;
    if (!replica_install_meta_read(meta_path, &meta, &present)) return false;
    if (!present) {
        bool removed = false;
        if (unlink(image_path) == 0) removed = true;
        else if (errno != ENOENT) return false;
        if (unlink(candidate) == 0) removed = true;
        else if (errno != ENOENT) return false;
        return !removed || fsync_dir_path(dir);
    }
    uint64_t image_hash = 0u;
    (void)unlink(candidate);
    if (!copy_file_atomic_hash(image_path, candidate, &image_hash)) return false;
    if (image_hash != meta.image_hash) { (void)unlink(candidate); return false; }
    if (rename(candidate, sstable0) != 0 || !fsync_dir_path(dir))
        return false;
    DIR* d = opendir(dir);
    if (!d) return false;
    struct dirent* ent;
    bool ok = true;
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, "sstable_", 8u) != 0) continue;
        char* end = NULL; long id = strtol(ent->d_name + 8u, &end, 10);
        if (!end || strcmp(end, ".db") != 0 || id <= 0 || id >= INT_MAX) continue;
        char path[4096]; int n = snprintf(path, sizeof(path), "%s%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path) || unlink(path) != 0) { ok = false; break; }
    }
    closedir(d);
    if (!ok) return false;
    char tmp[8192]; FILE* empty_wal = NULL;
    if (!atomic_file_begin(wal_path, tmp, sizeof(tmp), &empty_wal) ||
        !atomic_file_commit(empty_wal, tmp, wal_path)) return false;
    return fsync_dir_path(dir);
}

static bool replica_cursor_force_set(qihse_kv_store_t* store, const char* peer,
                                     const char* ns, uint64_t seq) {
    kv_replica_cursor_t* e = cursor_find(store, peer, ns);
    if (e && seq < e->seq) return false;
    uint32_t count = 0u;
    for (kv_replica_cursor_t* p = store->replica_cursors; p; p = p->next) count++;
    bool added = false; uint64_t prior = 0u;
    if (!e) {
        if (count >= KV_REPLICA_CURSOR_MAX_ITEMS) return false;
        e = calloc(1u, sizeof(*e));
        if (!e) return false;
        e->peer_id = strdup(peer); e->namespace_id = strdup(ns);
        if (!e->peer_id || !e->namespace_id) {
            free(e->peer_id); free(e->namespace_id); free(e); return false;
        }
        e->next = store->replica_cursors; store->replica_cursors = e; added = true;
    } else prior = e->seq;
    e->seq = seq;
    char path[4096];
    bool ok = build_data_path(path, sizeof(path), "replica-cursors.bin") &&
        cursor_write_file(path, store->replica_cursors, count + (added ? 1u : 0u)) &&
        fsync_dir_path(get_qihse_data_dir());
    if (!ok) {
        if (added) { store->replica_cursors = e->next; free(e->peer_id); free(e->namespace_id); free(e); }
        else e->seq = prior;
    }
    return ok;
}

static bool replica_install_finish_recovery(qihse_kv_store_t* store, const char* dir) {
    char meta_path[4096], image_path[4096];
    if (!dir) return false;
    int a = snprintf(meta_path, sizeof(meta_path), "%sreplica-install.meta", dir);
    int b = snprintf(image_path, sizeof(image_path), "%sreplica-install.image", dir);
    if (a < 0 || (size_t)a >= sizeof(meta_path) || b < 0 || (size_t)b >= sizeof(image_path)) return false;
    replica_install_meta_t meta; bool present = false;
    if (!replica_install_meta_read(meta_path, &meta, &present)) return false;
    if (!present) return true;
    char marker[48]; replica_snapshot_marker_namespace(meta.glob, marker);
    if (!replica_cursor_force_set(store, meta.peer, meta.glob, meta.source_seq) ||
        !replica_cursor_force_set(store, meta.peer, marker, 1u)) return false;
    if (unlink(meta_path) != 0 || !fsync_dir_path(dir)) return false;
    if (unlink(image_path) != 0 && errno != ENOENT) return false;
    return fsync_dir_path(dir);
}

static bool cursor_principal_ok(qihse_user_t* principal) {
    return principal && qihse_auth_user_is_active(principal) &&
           qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR;
}

bool qihse_kv_replica_cursor_get(qihse_kv_store_t* store, const char* peer_id,
                                const char* namespace_id, qihse_user_t* principal,
                                uint64_t* out_seq) {
    if (!store || !cursor_id_valid(peer_id) || !cursor_id_valid(namespace_id) ||
        !cursor_principal_ok(principal) || !out_seq) return false;
    kv_replica_cursor_t* e = cursor_find(store, peer_id, namespace_id);
    *out_seq = e ? e->seq : 0u;
    return true;
}

bool qihse_kv_replica_cursor_advance(qihse_kv_store_t* store, const char* peer_id,
                                    const char* namespace_id, uint64_t seq,
                                    qihse_user_t* principal) {
    if (!store || !cursor_id_valid(peer_id) || !cursor_id_valid(namespace_id) ||
        !cursor_principal_ok(principal) || store->bulk_load_mode) return false;
    kv_replica_cursor_t* e = cursor_find(store, peer_id, namespace_id);
    if (e && seq < e->seq) return false;
    if (e && seq == e->seq) {
        /* The previous call may have renamed the cursor file successfully but
         * failed its directory fsync.  Retrying the same sequence must retry
         * both durable-store and cursor-directory synchronization. */
        return qihse_kv_sync_store(store) &&
               fsync_dir_path(get_qihse_data_dir());
    }
    uint32_t count = 0u;
    for (kv_replica_cursor_t* p = store->replica_cursors; p; p = p->next) count++;
    if (!e && count >= KV_REPLICA_CURSOR_MAX_ITEMS) return false;

    /* Ensure every applied record preceding this checkpoint survives a crash
     * before a caller can ACK the new cursor. */
    if (!qihse_kv_sync_store(store)) return false;

    bool added = false; uint64_t prior_seq = 0u;
    if (!e) {
        e = (kv_replica_cursor_t*)calloc(1u, sizeof(*e));
        if (!e) return false;
        e->peer_id = strdup(peer_id); e->namespace_id = strdup(namespace_id);
        if (!e->peer_id || !e->namespace_id) { free(e->peer_id); free(e->namespace_id); free(e); return false; }
        e->next = store->replica_cursors; store->replica_cursors = e; added = true;
    } else prior_seq = e->seq;
    e->seq = seq;
    char path[4096]; bool persisted = build_data_path(path, sizeof(path), "replica-cursors.bin") &&
        cursor_write_file(path, store->replica_cursors, count + (added ? 1u : 0u));
    if (!persisted) {
        if (added) { store->replica_cursors = e->next; free(e->peer_id); free(e->namespace_id); free(e); }
        else e->seq = prior_seq;
        return false;
    }
    /* A failed directory fsync means no ACK; retain the in-memory high-water
     * so a retry in this process cannot overwrite it with a lower value. */
    return fsync_dir_path(get_qihse_data_dir());
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

static uint64_t wal_replica_record_crc(uint8_t op, uint8_t flags, uint16_t key_len,
                                       uint32_t val_len, uint16_t classification,
                                       uint16_t sci_compartment, uint64_t expire_time_ms,
                                       uint64_t change_seq, const char* key, const char* val) {
    uint64_t h = wal_record_crc(op, flags, key_len, val_len, classification,
                                sci_compartment, expire_time_ms, key, val);
    return fnv1a64_update(h, &change_seq, sizeof(change_seq));
}

static bool payload_is_dead(const kv_payload_t* p, uint64_t now) {
    return !p || (p->flags & KV_FLAG_TOMBSTONE) != 0u ||
           (p->expire_time_ms != 0u && p->expire_time_ms <= now);
}

static kv_payload_t* payload_create(const char* value, uint64_t expire_time_ms,
                                    uint16_t classification, uint16_t sci_compartment,
                                    uint8_t flags, uint64_t change_seq, size_t* out_size) {
    if ((flags & ~KV_ALLOWED_FLAGS) != 0u) return NULL;
    const char* src = value ? value : "";
    size_t val_len = strlen(src);
    if (val_len > KV_MAX_VALUE_LEN) return NULL;
    size_t total = sizeof(kv_payload_t) + val_len + 1u;
    kv_payload_t* p = (kv_payload_t*)calloc(1, total);
    if (!p) return NULL;
    p->expire_time_ms = expire_time_ms;
    p->change_seq = change_seq;
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
    unsigned long long seq = 0u;
    unsigned int classif = 0u, sci = 0u, flags = 0u;
    int fields = sscanf(header, "%zu %zu %llu %u %u %u %llu", &key_len, &val_len,
                        &expire, &classif, &sci, &flags, &seq);
    if (fields < KV_SEQ_FIELDS_MIN || fields > KV_SEQ_FIELDS_V4) return -1;
    if (fields < 6) flags = 0u;      /* legacy: no flags field */
    if (fields < KV_SEQ_FIELDS_V4) seq = 0u; /* pre-v4: no sequence field */
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
    r->change_seq = (uint64_t)seq;
    return 1;
}

static bool disk_record_write_fields(FILE* f, const char* key, const char* val,
                                     uint64_t expire_time_ms, uint16_t classification,
                                     uint16_t sci_compartment, uint8_t flags,
                                     uint64_t change_seq) {
    if (!f || !key) return false;
    size_t key_len = strlen(key);
    size_t val_len = (flags & KV_FLAG_TOMBSTONE) ? 0u : strlen(val ? val : "");
    if (key_len == 0u || key_len > KV_MAX_KEY_LEN || val_len > KV_MAX_VALUE_LEN) return false;
    if (fprintf(f, "%zu %zu %llu %u %u %u %llu\n", key_len, val_len,
                (unsigned long long)expire_time_ms, (unsigned)classification,
                (unsigned)sci_compartment, (unsigned)flags,
                (unsigned long long)change_seq) < 0) return false;
    if (!fwrite_exact(key, 1u, key_len, f)) return false;
    if (val_len != 0u && !fwrite_exact(val, 1u, val_len, f)) return false;
    return fputc('\n', f) != EOF;
}

static bool disk_record_write(FILE* f, const char* key, const kv_payload_t* p) {
    if (!p) return false;
    return disk_record_write_fields(f, key, p->val, p->expire_time_ms,
                                    p->classification, p->sci_compartment, p->flags,
                                    p->change_seq);
}

/* Header-only variant of disk_record_read: parses the header line and reads
 * the key, then seeks past the value bytes instead of allocating/copying them.
 * r->val is left NULL.  Used by index rebuild and any metadata-only scan where
 * reading every value (up to KV_MAX_VALUE_LEN each) would be pure waste. */
static int disk_record_read_header(FILE* f, kv_disk_record_t* r) {
    if (!f || !r) return -1;
    memset(r, 0, sizeof(*r));
    char header[KV_HEADER_LINE_MAX];
    if (!fgets(header, sizeof(header), f)) return feof(f) ? 0 : -1;
    size_t hlen = strlen(header);
    if (hlen == 0u || header[hlen - 1u] != '\n') return -1;
    size_t key_len = 0u, val_len = 0u;
    unsigned long long expire = 0u;
    unsigned long long seq = 0u;
    unsigned int classif = 0u, sci = 0u, flags = 0u;
    int fields = sscanf(header, "%zu %zu %llu %u %u %u %llu", &key_len, &val_len,
                        &expire, &classif, &sci, &flags, &seq);
    if (fields < KV_SEQ_FIELDS_MIN || fields > KV_SEQ_FIELDS_V4) return -1;
    if (fields < 6) flags = 0u;
    if (fields < KV_SEQ_FIELDS_V4) seq = 0u;
    if (key_len == 0u || key_len > KV_MAX_KEY_LEN || val_len > KV_MAX_VALUE_LEN ||
        classif > UINT16_MAX || sci > UINT16_MAX || (flags & ~KV_ALLOWED_FLAGS) != 0u) return -1;
    if ((flags & KV_FLAG_TOMBSTONE) != 0u && val_len != 0u) return -1;
    r->key = (char*)malloc(key_len + 1u);
    if (!r->key) return -1;
    if (fread(r->key, 1u, key_len, f) != key_len) { disk_record_free(r); return -1; }
    if (memchr(r->key, '\0', key_len) != NULL) { disk_record_free(r); return -1; }
    r->key[key_len] = '\0';
    if (fseeko(f, (off_t)val_len, SEEK_CUR) != 0 || fgetc(f) != '\n') {
        disk_record_free(r); return -1;
    }
    r->expire_time_ms = (uint64_t)expire;
    r->classification = (uint16_t)classif;
    r->sci_compartment = (uint16_t)sci;
    r->flags = (uint8_t)flags;
    r->change_seq = (uint64_t)seq;
    return 1;
}

static bool insert_internal(qihse_kv_store_t* store, const char* key, const char* value,
                            uint64_t expire_time_ms, uint16_t classification,
                            uint16_t sci_compartment, uint8_t flags, uint64_t change_seq) {
    if (!store || !store->trie || !key || key[0] == '\0') return false;
    size_t key_len = strlen(key);
    if (key_len > KV_MAX_KEY_LEN) return false;
    size_t payload_size = 0u;
    kv_payload_t* payload = payload_create(value, expire_time_ms, classification,
                                           sci_compartment, flags, change_seq, &payload_size);
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

/* Replica records use a versioned WAL frame carrying the primary's sequence.
 * QKV2 remains readable and keeps its historical local re-stamping behavior. */
static bool wal_append_replica(qihse_kv_store_t* store, uint8_t op, const char* key,
                               const char* value, uint64_t expire_time_ms,
                               uint16_t classification, uint16_t sci_compartment,
                               uint8_t flags, uint64_t change_seq) {
    if (!store || !key || !store->wal_fd || store->bulk_load_mode || change_seq == 0u) return false;
    size_t key_len_sz = strlen(key), val_len_sz = value ? strlen(value) : 0u;
    if (key_len_sz == 0u || key_len_sz > KV_MAX_KEY_LEN || val_len_sz > KV_MAX_VALUE_LEN ||
        (op != KV_WAL_OP_SET && op != KV_WAL_OP_DEL) || (flags & ~KV_ALLOWED_FLAGS) != 0u) return false;
    uint16_t key_len = (uint16_t)key_len_sz;
    uint32_t val_len = (uint32_t)val_len_sz;
    uint64_t crc = wal_replica_record_crc(op, flags, key_len, val_len, classification,
                                          sci_compartment, expire_time_ms, change_seq,
                                          key, value ? value : "");
    unsigned char hdr[40];
    memcpy(hdr + 0, KV_WAL_MAGIC_REPLICA, 4u);
    hdr[4] = op; hdr[5] = flags;
    memcpy(hdr + 6, &key_len, 2u); memcpy(hdr + 8, &val_len, 4u);
    memcpy(hdr + 12, &classification, 2u); memcpy(hdr + 14, &sci_compartment, 2u);
    memcpy(hdr + 16, &expire_time_ms, 8u); memcpy(hdr + 24, &change_seq, 8u);
    memcpy(hdr + 32, &crc, 8u);
    if (!fwrite_exact(hdr, 1u, sizeof(hdr), store->wal_fd) ||
        !fwrite_exact(key, 1u, key_len, store->wal_fd) ||
        !fwrite_exact(value ? value : "", 1u, val_len, store->wal_fd)) return false;
    store->wal_unflushed_bytes += sizeof(hdr) + key_len + val_len;
    if (store->wal_unflushed_bytes >= WAL_BUFFER_FLUSH_THRESHOLD) flush_wal_buffer(store);
    return true;
}

/* Close every cached SSTable fd.  Called whenever SSTable files are deleted
 * or replaced (compaction, load, destroy) so a stale FILE* can never serve
 * data from an unlinked inode. */
static void sst_fd_cache_clear(qihse_kv_store_t* store) {
    if (!store) return;
    pthread_mutex_lock(&store->sst_fd_lock);
    for (size_t i = 0; i < sizeof(store->sst_fds) / sizeof(store->sst_fds[0]); i++) {
        if (store->sst_fds[i].fd >= 0) close(store->sst_fds[i].fd);
        store->sst_fds[i].fd = -1;
        store->sst_fds[i].sid = -1;
    }
    pthread_mutex_unlock(&store->sst_fd_lock);
}

/* Fetch a cached fd for sstable `sid`, opening it on miss.  Caller must NOT
 * close the result and must call this with sst_fd_lock held.  Returns -1
 * when the file cannot be opened — errno is preserved so ENOENT still maps
 * to KV_LOOKUP_MISS. */
static int sst_fd_get(qihse_kv_store_t* store, const char* dir, int32_t sid) {
    if (!store || !dir || sid < 0) { errno = EINVAL; return -1; }
    size_t nslots = sizeof(store->sst_fds) / sizeof(store->sst_fds[0]);
    for (size_t i = 0; i < nslots; i++)
        if (store->sst_fds[i].fd >= 0 && store->sst_fds[i].sid == sid)
            return store->sst_fds[i].fd;
    char path[4096];
    int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, sid);
    if (n < 0 || (size_t)n >= sizeof(path)) { errno = EINVAL; return -1; }
    int fd = open_secure_read(path);
    if (fd < 0) return -1;
    size_t slot = nslots;
    for (size_t i = 0; i < nslots; i++)
        if (store->sst_fds[i].fd < 0) { slot = i; break; }
    if (slot == nslots) { slot = 0u; close(store->sst_fds[0].fd); }
    store->sst_fds[slot].fd = fd;
    store->sst_fds[slot].sid = sid;
    return fd;
}

/* pread()-based sibling of disk_record_read: identical on-disk format and
 * return contract (1 ok, 0 EOF-before-header, -1 malformed/truncated), but
 * position-independent so concurrent readers can share the fd. */
static int disk_record_read_at(int fd, uint64_t offset, kv_disk_record_t* r) {
    if (fd < 0 || !r) return -1;
    memset(r, 0, sizeof(*r));
    char hbuf[KV_HEADER_LINE_MAX + 1u];
    ssize_t hn = pread(fd, hbuf, KV_HEADER_LINE_MAX, (off_t)offset);
    if (hn <= 0) return (hn == 0) ? 0 : -1;
    const char* nl = (const char*)memchr(hbuf, '\n', (size_t)hn);
    if (!nl) return -1;
    size_t hlen = (size_t)(nl - hbuf) + 1u;
    hbuf[hlen - 1u] = '\0'; /* sscanf parses text up to the newline only */
    size_t key_len = 0u, val_len = 0u;
    unsigned long long expire = 0u;
    unsigned long long seq = 0u;
    unsigned int classif = 0u, sci = 0u, flags = 0u;
    int fields = sscanf(hbuf, "%zu %zu %llu %u %u %u %llu", &key_len, &val_len,
                        &expire, &classif, &sci, &flags, &seq);
    if (fields < KV_SEQ_FIELDS_MIN || fields > KV_SEQ_FIELDS_V4) return -1;
    if (fields < 6) flags = 0u;
    if (fields < KV_SEQ_FIELDS_V4) seq = 0u;
    if (key_len == 0u || key_len > KV_MAX_KEY_LEN || val_len > KV_MAX_VALUE_LEN ||
        classif > UINT16_MAX || sci > UINT16_MAX || (flags & ~KV_ALLOWED_FLAGS) != 0u) return -1;
    if ((flags & KV_FLAG_TOMBSTONE) != 0u && val_len != 0u) return -1;
    r->key = (char*)malloc(key_len + 1u);
    r->val = (char*)malloc(val_len + 1u);
    if (!r->key || !r->val) { disk_record_free(r); return -1; }
    off_t pos = (off_t)offset + (off_t)hlen;
    if (pread(fd, r->key, key_len, pos) != (ssize_t)key_len) { disk_record_free(r); return -1; }
    pos += (off_t)key_len;
    if (pread(fd, r->val, val_len, pos) != (ssize_t)val_len) { disk_record_free(r); return -1; }
    pos += (off_t)val_len;
    char term = 0;
    if (pread(fd, &term, 1u, pos) != 1 || term != '\n') { disk_record_free(r); return -1; }
    if (memchr(r->key, '\0', key_len) != NULL || memchr(r->val, '\0', val_len) != NULL) {
        disk_record_free(r); return -1;
    }
    r->key[key_len] = '\0'; r->val[val_len] = '\0';
    r->expire_time_ms = (uint64_t)expire;
    r->classification = (uint16_t)classif;
    r->sci_compartment = (uint16_t)sci;
    r->flags = (uint8_t)flags;
    r->change_seq = (uint64_t)seq;
    return 1;
}

/* Read a single record by (file id, byte offset) as pinpointed by the
 * metadata index.  sst_fd_lock only guards the cache lookup — the read
 * itself is pread()-based and position-independent. */
static kv_lookup_state_t lookup_one_sstable(qihse_kv_store_t* store, const char* dir,
                                            const char* key, int32_t sstable_id,
                                            uint64_t offset, kv_lookup_result_t* out) {
    pthread_mutex_lock(&store->sst_fd_lock);
    int fd = sst_fd_get(store, dir, sstable_id);
    int e = errno;
    pthread_mutex_unlock(&store->sst_fd_lock);
    if (fd < 0) return (e == ENOENT) ? KV_LOOKUP_MISS : KV_LOOKUP_ERROR;
    uint64_t now = current_time_ms();
    kv_disk_record_t r;
    int rc = disk_record_read_at(fd, offset, &r);
    if (rc != 1) return (rc < 0) ? KV_LOOKUP_ERROR : KV_LOOKUP_MISS;
    if (strcmp(r.key, key) != 0) { disk_record_free(&r); return KV_LOOKUP_MISS; }
    out->classification = r.classification;
    out->sci_compartment = r.sci_compartment;
    out->expire_time_ms = r.expire_time_ms;
    out->flags = r.flags;
    out->change_seq = r.change_seq;
    bool dead = (r.flags & KV_FLAG_TOMBSTONE) != 0u ||
                (r.expire_time_ms != 0u && r.expire_time_ms <= now);
    if (!dead) { out->value = r.val; r.val = NULL; }
    disk_record_free(&r);
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
                out->change_seq = r.change_seq;
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
        out->change_seq = p->change_seq;
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
            return lookup_one_sstable(store, dir, key, sid, off, out);
        }
        return KV_LOOKUP_MISS;
    }
    return lookup_sstables(store, key, out);
}

static void lookup_result_free(kv_lookup_result_t* r) {
    if (!r) return;
    free(r->value);
    memset(r, 0, sizeof(*r));
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

/* Load one SSTable's records into a trie, PRESERVING each record's stamped
 * sequence (compaction is not a mutation), and reporting the maximum
 * sequence seen so the caller can raise the store's high-water. */
static bool load_sstable_into_trie(const char* path, qihse_trinary_trie_t* dst,
                                   size_t* mem_usage, uint64_t* max_seq) {
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    kv_disk_record_t r; int rc; bool ok = true;
    while ((rc = disk_record_read(f, &r)) == 1) {
        size_t ps = 0u;
        kv_payload_t* p = payload_create(r.val, r.expire_time_ms, r.classification,
                                         r.sci_compartment, r.flags, r.change_seq, &ps);
        if (!p || !qihse_trinary_trie_insert_nocopy(dst, r.key, p, ps)) {
            free(p); disk_record_free(&r); ok = false; break;
        }
        if (max_seq && r.change_seq > *max_seq) *max_seq = r.change_seq;
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
    uint64_t max_seq = 0u;
    const char* dir = get_qihse_data_dir();
    if (!dir) { qihse_trinary_trie_destroy(merged); return false; }
    for (int i = 0; i < store->sstable_counter; i++) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, i);
        if (n < 0 || (size_t)n >= sizeof(path) || !load_sstable_into_trie(path, merged, &merged_usage, &max_seq)) {
            qihse_trinary_trie_destroy(merged); return false;
        }
    }
    /* Merging never issues sequences, but the files' sequences must be
     * reflected if this runs before the index pass raised the high-water. */
    kv_change_seq_floor(store, max_seq);
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
    sst_fd_cache_clear(store);
    return true;
}

/* Compact SSTables once more than this many have accumulated, even if the
 * expiry scan found nothing — bounds file count and reclaims stale copies. */
#define KV_SSTABLE_COMPACT_THRESHOLD 16

static void sst_index_load_file(qihse_kv_store_t* store, const char* path, int32_t sstable_id);

/* True if any index entry is live-but-expired at `now` (RAM scan, no I/O). */
static bool sst_meta_index_has_expired(const sst_meta_index_t* idx, uint64_t now) {
    if (!idx) return false;
    for (size_t i = 0; i < idx->cap; i++) {
        const sst_meta_entry_t* e = &idx->slots[i];
        if (e->key && (e->flags & KV_FLAG_TOMBSTONE) == 0u &&
            e->expire_time_ms != 0u && e->expire_time_ms <= now) return true;
    }
    return false;
}

/* Callback for sst_foreach_newest.  Return false to stop iterating early. */
typedef bool (*kv_sst_record_cb)(const char* key, const kv_disk_record_t* r, void* ud);

/* Stream the newest live version of every key held in SSTables.
 *
 * Each file is read sequentially; for every physical record the metadata
 * index is probed and the record is emitted only when the index still pins
 * this exact (sstable_id, offset) — i.e. this copy is the newest one, with
 * all older copies in older files filtered out.  Tombstoned/expired records
 * and keys shadowed by a newer memtable entry are skipped.  Values are read
 * (the callback receives them) but nothing is merged into RAM: memory stays
 * O(1) beyond the index itself.
 *
 * `include_tombstones` is the delta exporter's mode: a newest TOMBSTONE is
 * a deletion a delta must be able to carry, so it is emitted instead of
 * skipped (expired-but-live records are still skipped, matching the full
 * export's liveness semantics).  Every existing caller passes false and
 * keeps the live-only behavior.
 *
 * Returns 1 when the scan completed, 0 when the callback asked to stop,
 * -1 on error.  Only usable when the index is present and not degraded;
 * callers must provide the compact_sstables_into_memtable() fallback. */
static int sst_foreach_newest(qihse_kv_store_t* store, bool include_tombstones,
                              kv_sst_record_cb cb, void* ud) {
    if (!store || !store->trie || !cb) return -1;
    if (!store->sst_meta || store->sst_meta->degraded) return -1;
    const char* dir = get_qihse_data_dir();
    if (!dir) return -1;
    uint64_t now = current_time_ms();
    for (int sid = store->sstable_counter - 1; sid >= 0; sid--) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, sid);
        if (n < 0 || (size_t)n >= sizeof(path)) return -1;
        int fd = open_secure_read(path);
        if (fd < 0) { if (errno == ENOENT) continue; return -1; }
        FILE* f = fdopen(fd, "rb");
        if (!f) { close(fd); return -1; }
        kv_disk_record_t r; int rc = 0; int stopped = 0;
        for (;;) {
            long rec_off = ftell(f);
            rc = disk_record_read(f, &r);
            if (rc < 0) {
                /* One malformed/unreadable record must not blind the whole
                 * enumeration: this used to abort the entire scan, so a
                 * single poison record — often in the NEWEST sstable, which
                 * is scanned first — silently emptied every KEYS/SCAN over
                 * data that GET and DBSIZE (index-driven) still served.
                 * Resync at the next line and keep going; at true EOF the
                 * resync immediately falls through to the clean break. */
                int c;
                while ((c = fgetc(f)) != EOF && c != '\n') {}
                if (c == EOF) { rc = 0; break; } /* clean end of file */
                continue;
            }
            if (rc != 1) break;
            int32_t isid = -1; uint64_t ioff = 0u;
            bool newest = sst_meta_index_lookup(store->sst_meta, r.key,
                                                NULL, NULL, NULL, NULL,
                                                &isid, &ioff) &&
                          isid == sid && ioff == (uint64_t)(rec_off >= 0 ? rec_off : 0);
            bool tombstone = (r.flags & KV_FLAG_TOMBSTONE) != 0u;
            bool expired = (!tombstone && r.expire_time_ms != 0u && r.expire_time_ms <= now);
            size_t z = 0u;
            bool shadowed = qihse_trinary_trie_search(store->trie, r.key, &z) != NULL;
            bool emit = newest && !shadowed && !expired &&
                        (include_tombstones || !tombstone);
            if (emit) {
                if (!cb(r.key, &r, ud)) stopped = 1;
            }
            disk_record_free(&r);
            if (stopped) { fclose(f); return 0; }
        }
        fclose(f);
        if (rc < 0) return -1;
    }
    return 1;
}

/* Streaming compaction: write one merged SSTable containing only the newest
 * live, unshadowed records, then atomically swap out the old files and
 * re-index.  Unlike compact_sstables_into_memtable() this never materializes
 * the whole dataset in a RAM trie and it physically drops tombstoned and
 * expired records. */
typedef struct { FILE* f; bool ok; size_t written; qihse_kv_store_t* store; } compact_emit_ctx_t;
static bool tombstone_has_unacked_replica(qihse_kv_store_t* store, const char* key,
                                          uint64_t change_seq) {
    for (kv_replica_cursor_t* c = store ? store->replica_cursors : NULL; c; c = c->next) {
        if (c->seq < change_seq && fnmatch(c->namespace_id, key, 0) == 0) return true;
    }
    return false;
}

static bool compact_emit_cb(const char* key, const kv_disk_record_t* r, void* ud) {
    compact_emit_ctx_t* ctx = (compact_emit_ctx_t*)ud;
    if (!ctx || !ctx->ok || !key || !r) return false;
    if ((r->flags & KV_FLAG_TOMBSTONE) != 0u &&
        !tombstone_has_unacked_replica(ctx->store, key, r->change_seq)) return true;
    if (!disk_record_write_fields(ctx->f, key, r->val, r->expire_time_ms,
                                  r->classification, r->sci_compartment, r->flags,
                                  r->change_seq)) {
        ctx->ok = false; return false;
    }
    ctx->written++;
    return true;
}

static bool compact_sstables_stream(qihse_kv_store_t* store) {
    if (!store || !store->trie) return false;
    if (store->sstable_counter == 0) return true;
    if (!store->sst_meta || store->sst_meta->degraded) {
        return compact_sstables_into_memtable(store);
    }
    const char* dir = get_qihse_data_dir();
    if (!dir) return false;
    int new_id = store->sstable_counter;
    char new_path[4096];
    int n = snprintf(new_path, sizeof(new_path), "%ssstable_%d.db", dir, new_id);
    if (n < 0 || (size_t)n >= sizeof(new_path)) return false;
    char tmp[8192]; FILE* out = NULL;
    if (!atomic_file_begin(new_path, tmp, sizeof(tmp), &out)) return false;
    compact_emit_ctx_t wctx = { .f = out, .ok = true, .written = 0u, .store = store };
    int rc = sst_foreach_newest(store, true, compact_emit_cb, &wctx);
    if (rc < 0 || !wctx.ok || ferror(out)) { fclose(out); unlink(tmp); return false; }
    if (wctx.written == 0u) {
        /* Nothing live left in SSTables — drop all old files, no new one. */
        fclose(out); unlink(tmp);
    } else if (!atomic_file_commit(out, tmp, new_path)) {
        return false;
    }
    for (int i = 0; i < store->sstable_counter; i++) {
        char p[4096]; int m = snprintf(p, sizeof(p), "%ssstable_%d.db", dir, i);
        if (m >= 0 && (size_t)m < sizeof(p)) (void)unlink(p);
    }
    sst_fd_cache_clear(store);
    if (wctx.written == 0u) {
        store->sstable_counter = 0;
        sst_meta_index_reset(store); /* entries now point at deleted files — rebuild empty */
    } else {
        store->sstable_counter = new_id + 1;
        sst_meta_index_reset(store);
        /* Re-index the merged file.  If the index is gone (OOM) lookups fall
         * back to the degraded full scan, which still finds sstable_<new_id>
         * because sstable_counter covers it. */
        if (store->sst_meta) sst_index_load_file(store, new_path, new_id);
    }
    return true;
}

static bool wal_replay_new_record(qihse_kv_store_t* store, FILE* f, bool has_source_seq) {
    uint8_t op = 0u, flags = 0u;
    uint16_t key_len = 0u, classification = 0u, sci = 0u;
    uint32_t val_len = 0u;
    uint64_t expire = 0u, crc = 0u, source_seq = 0u;
    if (fread(&op, sizeof(op), 1u, f) != 1u || fread(&flags, sizeof(flags), 1u, f) != 1u ||
        fread(&key_len, sizeof(key_len), 1u, f) != 1u || fread(&val_len, sizeof(val_len), 1u, f) != 1u ||
        fread(&classification, sizeof(classification), 1u, f) != 1u || fread(&sci, sizeof(sci), 1u, f) != 1u ||
        fread(&expire, sizeof(expire), 1u, f) != 1u) return false;
    if (has_source_seq && fread(&source_seq, sizeof(source_seq), 1u, f) != 1u) return false;
    if (fread(&crc, sizeof(crc), 1u, f) != 1u) return false;
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
    uint64_t actual = has_source_seq
        ? wal_replica_record_crc(op, flags, key_len, val_len, classification, sci,
                                 expire, source_seq, key, val)
        : wal_record_crc(op, flags, key_len, val_len, classification, sci, expire, key, val);
    if (actual != crc) { free(key); free(val); return false; }
    if (has_source_seq) {
        if (source_seq == 0u ||
            (op == KV_WAL_OP_DEL && (val_len != 0u || expire != 0u || (flags & KV_FLAG_TOMBSTONE) == 0u)) ||
            (op == KV_WAL_OP_SET && flags != 0u)) {
            free(key); free(val); return false;
        }
        kv_payload_t* prior = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, NULL);
        if (prior && prior->change_seq >= source_seq) {
            bool duplicate = prior->change_seq == source_seq && prior->flags == flags &&
                             prior->expire_time_ms == expire && prior->classification == classification &&
                             prior->sci_compartment == sci && strcmp(prior->val, val) == 0;
            free(key); free(val); return duplicate;
        }
        bool ok = insert_internal(store, key, val, expire, classification, sci, flags, source_seq);
        if (ok) kv_change_seq_floor(store, source_seq);
        free(key); free(val); return ok;
    }
    /* The binary WAL format carries no sequence (unchanged, so existing
     * wal.log files keep decoding); recovery re-stamps each replayed
     * mutation with a fresh sequence.  Replay order is mutation order, so
     * relative order survives and the high-water only moves forward. */
    uint64_t seq = kv_change_seq_next(store);
    if (seq == 0u) { free(key); free(val); return false; }
    bool ok = insert_internal(store, key, val, expire, classification, sci, flags, seq);
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
            bool replica = memcmp(magic, KV_WAL_MAGIC_REPLICA, 4u) == 0;
            if ((!replica && memcmp(magic, KV_WAL_MAGIC, 4u) != 0) ||
                !wal_replay_new_record(store, f, replica)) break;
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
                uint64_t seq = kv_change_seq_next(store);
                if (seq == 0u || !insert_internal(store, key, val, 0u, classification, sci, 0u, seq)) {
                    free(key); free(val); break;
                }
                free(key); free(val); continue;
            }
            if (tag[1] == 'E' && tag[2] == 'T' && tag[3] == ' ') {
                char* line = (char*)malloc(65536);
                char* rest = (char*)malloc(63488);
                if (!line || !rest) {
                    free(line);
                    free(rest);
                    break;
                }
                if (!fgets(line, 65536, f)) {
                    free(line);
                    free(rest);
                    break;
                }
                unsigned int classif = 0u, sci = 0u; char key[256];
                if (sscanf(line, "%255s %63487[^\n]", key, rest) >= 2) {
                    char* end = rest + strlen(rest);
                    while (end > rest && (end[-1] == ' ' || end[-1] == '\n')) --end;
                    *end = '\0';
                    char* p2 = strrchr(rest, ' ');
                    if (p2) { sci = (unsigned int)strtoul(p2 + 1, NULL, 10); *p2 = '\0';
                        char* p1 = strrchr(rest, ' ');
                        if (p1) { classif = (unsigned int)strtoul(p1 + 1, NULL, 10); *p1 = '\0'; }
                    }
                    if (classif <= UINT16_MAX && sci <= UINT16_MAX) {
                        uint64_t seq = kv_change_seq_next(store);
                        if (seq != 0u)
                            (void)insert_internal(store, key, rest, 0u, (uint16_t)classif,
                                                  (uint16_t)sci, 0u, seq);
                    }
                }
                free(line);
                free(rest);
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
                    /* Legacy DEL records carry only the key; the tombstone
                     * needs the prior classification/SCI.  Probe the memtable
                     * (earlier WAL records) then the metadata index — both in
                     * RAM.  Only a degraded index falls back to the disk scan. */
                    uint16_t cclass = 0u, csci = 0u;
                    size_t psz = 0u;
                    kv_payload_t* mp = (kv_payload_t*)qihse_trinary_trie_search(store->trie, line, &psz);
                    if (mp) {
                        cclass = mp->classification; csci = mp->sci_compartment;
                    } else if (store->sst_meta && !store->sst_meta->degraded) {
                        (void)sst_meta_index_lookup(store->sst_meta, line, &cclass, &csci,
                                                    NULL, NULL, NULL, NULL);
                    } else {
                        kv_lookup_result_t prior;
                        kv_lookup_state_t state = logical_lookup(store, line, &prior);
                        if (state == KV_LOOKUP_LIVE || state == KV_LOOKUP_DEAD) {
                            cclass = prior.classification; csci = prior.sci_compartment;
                        }
                        lookup_result_free(&prior);
                    }
                    uint64_t seq = kv_change_seq_next(store);
                    if (seq != 0u)
                        (void)insert_internal(store, line, "", 0u, cclass, csci,
                                              KV_FLAG_TOMBSTONE, seq);
                }
                continue;
            }
            break;
        }
        break;
    }
    fclose(f);
}

/* Populate the in-memory SSTable metadata index from one on-disk SSTable.
 * Uses the header-only reader so the value bytes (up to 16MB each) are
 * skipped with fseeko rather than malloc'd + read + discarded.  The stamped
 * sequences pass by on the header line; the maximum observed raises the
 * store's high-water so a restart does not regress it. */
static void sst_index_load_file(qihse_kv_store_t* store, const char* path, int32_t sstable_id) {
    if (!store || !store->sst_meta || !path) return;
    int fd = open_secure_read(path);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return; }
    kv_disk_record_t r; int rc;
    for (;;) {
        long rec_off = ftell(f);
        rc = disk_record_read_header(f, &r);
        if (rc != 1) break;
        sst_meta_index_insert(store->sst_meta, r.key,
                              r.classification, r.sci_compartment,
                              r.expire_time_ms, r.flags, sstable_id,
                              rec_off >= 0 ? (uint64_t)rec_off : 0u);
        if (r.change_seq != 0u) kv_change_seq_floor(store, r.change_seq);
        disk_record_free(&r);
    }
    fclose(f);
}

qihse_kv_store_t* qihse_kv_store_create(void) {
    qihse_kv_store_t* store = (qihse_kv_store_t*)calloc(1u, sizeof(*store));
    if (!store) return NULL;
    store->trie = qihse_trinary_trie_create();
    if (!store->trie) { free(store); return NULL; }
    /* Mark cache slots empty before ANY early destroy path can run —
     * a zeroed slot otherwise looks like fd 0 (stdin). */
    for (size_t i = 0; i < sizeof(store->sst_fds) / sizeof(store->sst_fds[0]); i++) {
        store->sst_fds[i].fd = -1;
        store->sst_fds[i].sid = -1;
    }
    store->sst_meta = sst_meta_index_create();
    if (!store->sst_meta) { qihse_kv_store_destroy(store); return NULL; }
    if (pthread_mutex_init(&store->sst_fd_lock, NULL) != 0) {
        qihse_kv_store_destroy(store);
        return NULL;
    }
    const char* dir = get_qihse_data_dir();
    if (!dir) { qihse_kv_store_destroy(store); return NULL; }
    if (!replica_install_recover_image(dir)) { qihse_kv_store_destroy(store); return NULL; }
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
    if (!cursor_read_file(store)) { qihse_kv_store_destroy(store); return NULL; }
    if (!replica_install_finish_recovery(store, dir)) { qihse_kv_store_destroy(store); return NULL; }
    char wal_path[4096];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) { qihse_kv_store_destroy(store); return NULL; }
    int fd = open(wal_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { qihse_kv_store_destroy(store); return NULL; }
    store->wal_fd = fdopen(fd, "ab");
    if (!store->wal_fd) { close(fd); qihse_kv_store_destroy(store); return NULL; }
    return store;
}

bool qihse_kv_store_enable_replica_read_only(qihse_kv_store_t* store) {
    if (!store || !store->trie) return false;
    __atomic_store_n(&store->replica_read_only, true, __ATOMIC_RELEASE);
    return true;
}

void qihse_kv_store_destroy(qihse_kv_store_t* store) {
    if (!store) return;
    if (store->qdd_ctx) qihse_qdd_free(__atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE));
    if (store->wal_fd) { flush_wal_buffer(store); fclose(store->wal_fd); }
    sst_fd_cache_clear(store);
    pthread_mutex_destroy(&store->sst_fd_lock);
    if (store->trie) qihse_trinary_trie_destroy(store->trie);
    sst_meta_index_destroy(store->sst_meta);
    cursor_list_free(store->replica_cursors);
    free(store);
}

const char* qihse_kv_store_data_directory(qihse_kv_store_t* store) {
    if (!store) return NULL;
    return get_qihse_data_dir();
}

void qihse_kv_bulk_load_begin(qihse_kv_store_t* store) {
    if (store) store->bulk_load_mode = true;
}
void qihse_kv_bulk_load_end(qihse_kv_store_t* store) {
    if (!store) return;
    store->bulk_load_mode = false;
    flush_wal_buffer(store);
}

/* ── Store-internal operation lock (nil-GET fix 2026-10-02) ──────────────
 * Every public qihse_kv_* operation takes store_lock: read-side for pure
 * reads, write-side for mutations and for paths that may run compaction.
 * Internal *_impl helpers below carry the original bodies and NEVER take
 * the lock themselves — only public entry points lock, so there is no
 * same-thread wr->wr or rd->wr re-entry.  The one legal re-entry is
 * rd-over-rd (enumeration callbacks calling qihse_kv_get_user), which the
 * reader-preferring lock kind permits. */
static void kv_store_rdlock(qihse_kv_store_t* store) { pthread_rwlock_rdlock(&store->store_lock); }
static void kv_store_wrlock(qihse_kv_store_t* store) { pthread_rwlock_wrlock(&store->store_lock); }
static void kv_store_unlock(qihse_kv_store_t* store) { pthread_rwlock_unlock(&store->store_lock); }

/* Internal (lock-free) implementations, defined below near their public
 * wrappers. */
static char* kv_get_user_impl(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static bool kv_del_user_impl(qihse_kv_store_t* store, const char* key, qihse_user_t* user);

static bool set_user_with_expiry(qihse_kv_store_t* store, const char* key, const char* value,
                                 uint64_t expire_time_ms, uint16_t classification,
                                 uint16_t sci_compartment, qihse_user_t* user) {
    if (!store || !store->trie || __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) ||
        !key || !value || key[0] == '\0') return false;
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
    /* Authorized mutation: issue the change sequence BEFORE any side effect,
     * so a failure after this point at worst skips a number (monotonicity is
     * what matters, not density) and no unauthorized mutation ever advances
     * or receives one. */
    uint64_t seq = kv_change_seq_next(store);
    if (seq == 0u) return false;
    if (!wal_append(store, KV_WAL_OP_SET, key, value, expire_time_ms, classification, sci_compartment, 0u)) return false;
    if (!insert_internal(store, key, value, expire_time_ms, classification, sci_compartment, 0u, seq)) return false;
    if (!store->bulk_load_mode && store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) return false;
    return true;
}

bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value,
                       uint16_t classification, uint16_t sci_compartment, qihse_user_t* user) {
    if (!store) return false;
    kv_store_wrlock(store);
    bool ok = set_user_with_expiry(store, key, value, 0u, classification, sci_compartment, user);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value,
                  uint16_t classification, uint16_t sci_compartment) {
    return qihse_kv_set_user(store, key, value, classification, sci_compartment, NULL);
}

qihse_kv_cas_result_t qihse_kv_compare_set_user(
        qihse_kv_store_t* store, const char* key, const char* expected_value,
        const char* new_value, uint16_t classification,
        uint16_t sci_compartment, qihse_user_t* user) {
    if (!store || !key || !new_value || !user || !qihse_auth_user_is_active(user))
        return QIHSE_KV_CAS_FAILED;
    kv_store_wrlock(store);
    char* current = kv_get_user_impl(store, key, user);
    bool matches = expected_value ? current && strcmp(current, expected_value) == 0
                                  : current == NULL;
    if (!matches) {
        /* An absent result can also mean an inaccessible existing record.
         * set_user_with_expiry performs the overwrite authorization check;
         * never report MISMATCH for the create-if-absent case until that
         * distinction is known to be harmless. */
        qihse_kv_cas_result_t result = expected_value && current
            ? QIHSE_KV_CAS_MISMATCH : QIHSE_KV_CAS_FAILED;
        free(current);
        kv_store_unlock(store);
        return result;
    }
    bool updated = set_user_with_expiry(store, key, new_value, 0u,
        classification, sci_compartment, user);
    free(current);
    kv_store_unlock(store);
    return updated ? QIHSE_KV_CAS_UPDATED : QIHSE_KV_CAS_FAILED;
}

static char* kv_get_user_impl(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return NULL;
    if (!__atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE)) {
        /* CAS-publish so concurrent readers (kv_lock read side) can't
         * double-init; the loser frees its context instead of leaking it. */
        qihse_quantum_defense_ctx_t* ctx = qihse_qdd_init();
        qihse_quantum_defense_ctx_t* expected = NULL;
        if (ctx && !__atomic_compare_exchange_n(&store->qdd_ctx, &expected, ctx,
                                                false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
            qihse_qdd_free(ctx);
        }
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

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store) return NULL;
    kv_store_rdlock(store);
    char* value = kv_get_user_impl(store, key, user);
    kv_store_unlock(store);
    return value;
}

bool qihse_kv_meta_user(qihse_kv_store_t* store, const char* key,
                        qihse_user_t* user, qihse_kv_record_meta_t* out) {
    if (!store || !key || !out) return false;
    kv_store_rdlock(store);
    memset(out, 0, sizeof(*out));
    /* Same lookup and same authorization gate as the value path; the value
     * is materialized by the lookup and freed here without ever leaving
     * this function. Miss/expired/not-cleared remain indistinguishable. */
    kv_lookup_result_t r;
    kv_lookup_state_t state = logical_lookup(store, key, &r);
    bool ok = state == KV_LOOKUP_LIVE &&
              qihse_auth_can_access(user, r.classification, r.sci_compartment);
    if (ok) {
        out->classification = r.classification;
        out->sci_compartment = r.sci_compartment;
        out->expire_time_ms = r.expire_time_ms;
        out->flags = r.flags;
    }
    lookup_result_free(&r);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store) return false;
    kv_store_rdlock(store);
    char* v = kv_get_user_impl(store, key, user);
    kv_store_unlock(store);
    if (!v) return false;
    free(v);
    return true;
}

static bool kv_del_user_impl(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return false;
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE) { lookup_result_free(&r); return false; }
    if (!qihse_auth_can_access(user, r.classification, r.sci_compartment)) { lookup_result_free(&r); return false; }
    uint16_t classification = r.classification, sci = r.sci_compartment; lookup_result_free(&r);
    /* Authorized delete: the tombstone is stamped like any mutation, so a
     * delta can carry the deletion. */
    uint64_t seq = kv_change_seq_next(store);
    if (seq == 0u) return false;
    if (!wal_append(store, KV_WAL_OP_DEL, key, "", 0u, classification, sci, KV_FLAG_TOMBSTONE)) return false;
    if (!insert_internal(store, key, "", 0u, classification, sci, KV_FLAG_TOMBSTONE, seq)) return false;
    if (!store->bulk_load_mode && store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) return false;
    return true;
}

bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) || !key) return false;
    kv_store_wrlock(store);
    bool ok = kv_del_user_impl(store, key, user);
    kv_store_unlock(store);
    return ok;
}

/* Compare a retry against the stored bytes even if the key's TTL has elapsed.
 * logical_lookup intentionally hides expired values from readers; this private
 * comparison is used only after the replication principal passed authorization. */
static bool replica_record_matches_stored(qihse_kv_store_t* store,
                                          const qihse_kv_replica_record_t* record) {
    if (!store || !record) return false;
    const char* expected_value = record->tombstone ? "" : record->value;
    size_t payload_size = 0u;
    kv_payload_t* payload = (kv_payload_t*)qihse_trinary_trie_search(store->trie, record->key,
                                                                     &payload_size);
    if (payload) {
        return payload->change_seq == record->change_seq &&
               payload->classification == record->classification &&
               payload->sci_compartment == record->sci_compartment &&
               payload->expire_time_ms == record->expire_time_ms &&
               payload->flags == (record->tombstone ? KV_FLAG_TOMBSTONE : 0u) &&
               strcmp(payload->val, expected_value) == 0;
    }
    const char* dir = get_qihse_data_dir();
    if (!dir) return false;
    for (int sid = store->sstable_counter - 1; sid >= 0; --sid) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, sid);
        if (n < 0 || (size_t)n >= sizeof(path)) return false;
        int fd = open_secure_read(path);
        if (fd < 0) { if (errno == ENOENT) continue; return false; }
        FILE* f = fdopen(fd, "rb");
        if (!f) { close(fd); return false; }
        kv_disk_record_t disk;
        int rc;
        while ((rc = disk_record_read(f, &disk)) == 1) {
            if (strcmp(disk.key, record->key) == 0) {
                bool match = disk.change_seq == record->change_seq &&
                    disk.classification == record->classification &&
                    disk.sci_compartment == record->sci_compartment &&
                    disk.expire_time_ms == record->expire_time_ms &&
                    disk.flags == (record->tombstone ? KV_FLAG_TOMBSTONE : 0u) &&
                    strcmp(disk.val, expected_value) == 0;
                disk_record_free(&disk);
                fclose(f);
                return match;
            }
            disk_record_free(&disk);
        }
        fclose(f);
        if (rc < 0) return false;
    }
    return false;
}

bool qihse_kv_apply_replica_record(qihse_kv_store_t* store,
                                   const qihse_kv_replica_record_t* record,
                                   qihse_user_t* principal) {
    if (!store || !store->trie || !record || !principal || !record->key ||
        record->key[0] == '\0' || record->change_seq == 0u ||
        strlen(record->key) > KV_MAX_KEY_LEN ||
        (record->tombstone ? (record->value != NULL || record->expire_time_ms != 0u) : record->value == NULL) ||
        (!record->tombstone && strlen(record->value) > KV_MAX_VALUE_LEN) ||
        !qihse_auth_user_is_active(principal) ||
        qihse_user_get_role(principal) != QIHSE_ROLE_OPERATOR ||
        !qihse_auth_can_access(principal, record->classification, record->sci_compartment))
        return false;

    kv_store_wrlock(store);
    kv_lookup_result_t current;
    kv_lookup_state_t state = logical_lookup(store, record->key, &current);
    if (state == KV_LOOKUP_ERROR) { kv_store_unlock(store); return false; }
    if (state == KV_LOOKUP_LIVE || state == KV_LOOKUP_DEAD) {
        if (!qihse_auth_can_access(principal, current.classification, current.sci_compartment)) {
            lookup_result_free(&current);
            kv_store_unlock(store);
            return false;
        }
        if (current.change_seq > record->change_seq) {
            lookup_result_free(&current);
            kv_store_unlock(store);
            return false; /* stale source update */
        }
        if (current.change_seq == record->change_seq) {
            bool same_tombstone = (((current.flags & KV_FLAG_TOMBSTONE) != 0u) == record->tombstone);
            bool same = same_tombstone && current.classification == record->classification &&
                        current.sci_compartment == record->sci_compartment &&
                        current.expire_time_ms == record->expire_time_ms;
            if (same && record->tombstone) {
                lookup_result_free(&current);
                kv_store_unlock(store);
                return true;
            }
            if (same && replica_record_matches_stored(store, record)) {
                lookup_result_free(&current);
                kv_store_unlock(store);
                return true;
            }
            lookup_result_free(&current);
            kv_store_unlock(store);
            return false; /* same sequence with different or unobservable payload */
        }
    }
    lookup_result_free(&current);

    uint8_t flags = record->tombstone ? KV_FLAG_TOMBSTONE : 0u;
    uint8_t op = record->tombstone ? KV_WAL_OP_DEL : KV_WAL_OP_SET;
    const char* value = record->tombstone ? "" : record->value;
    if (!wal_append_replica(store, op, record->key, value, record->expire_time_ms,
                            record->classification, record->sci_compartment,
                            flags, record->change_seq)) { kv_store_unlock(store); return false; }
    if (!insert_internal(store, record->key, value, record->expire_time_ms,
                         record->classification, record->sci_compartment,
                         flags, record->change_seq)) { kv_store_unlock(store); return false; }
    kv_change_seq_floor(store, record->change_seq);
    if (store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) {
        kv_store_unlock(store);
        return false;
    }
    kv_store_unlock(store);
    return true;
}

bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms, qihse_user_t* user) {
    if (!store || __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) || !key) return false;
    kv_store_wrlock(store);
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE || !qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
        lookup_result_free(&r); kv_store_unlock(store); return false;
    }
    uint64_t expire = current_time_ms();
    if (UINT64_MAX - expire < ttl_ms) { lookup_result_free(&r); kv_store_unlock(store); return false; }
    expire += ttl_ms;
    bool ok = set_user_with_expiry(store, key, r.value, expire, r.classification, r.sci_compartment, user);
    lookup_result_free(&r); kv_store_unlock(store); return ok;
}

int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return -2;
    kv_store_rdlock(store);
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE || !qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
        lookup_result_free(&r); kv_store_unlock(store); return -2;
    }
    if (r.expire_time_ms == 0u) { lookup_result_free(&r); kv_store_unlock(store); return -1; }
    uint64_t now = current_time_ms();
    if (r.expire_time_ms <= now) { lookup_result_free(&r); kv_store_unlock(store); return -2; }
    uint64_t remaining = r.expire_time_ms - now; lookup_result_free(&r); kv_store_unlock(store);
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

static void tombstone_expired_keys(qihse_kv_store_t* store, char** keys, size_t count) {
    for (size_t i = 0; i < count; i++) {
        size_t sz = 0u;
        kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, keys[i], &sz);
        if (p) {
            uint16_t c = p->classification, s = p->sci_compartment;
            /* A sweep tombstone is a mutation: it advances the sequence so a
             * delta consumer learns the key is gone. */
            uint64_t seq = kv_change_seq_next(store);
            if (seq == 0u) continue;
            (void)wal_append(store, KV_WAL_OP_DEL, keys[i], "", 0u, c, s, KV_FLAG_TOMBSTONE);
            (void)insert_internal(store, keys[i], "", 0u, c, s, KV_FLAG_TOMBSTONE, seq);
        }
    }
}

void qihse_kv_sweep_expired(qihse_kv_store_t* store) {
    if (!store || !store->trie ||
        __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE)) return;
    kv_store_wrlock(store);
    if (store->bulk_load_mode) { kv_store_unlock(store); return; }
    uint64_t now = current_time_ms();
    if (!store->sst_meta || store->sst_meta->degraded) {
        /* Index unavailable — expired SSTable records are invisible from RAM,
         * so keep the original merge-everything-then-sweep semantics. */
        if (!compact_sstables_into_memtable(store)) { kv_store_unlock(store); return; }
        expired_collect_ctx_t ctx = { .now = now, .ok = true };
        qihse_trinary_trie_foreach(store->trie, collect_expired_cb, &ctx);
        if (ctx.ok) tombstone_expired_keys(store, ctx.keys, ctx.count);
        for (size_t i = 0; i < ctx.count; i++) free(ctx.keys[i]);
        free(ctx.keys);
        kv_store_unlock(store);
        return;
    }
    /* Fast path: tombstone expired memtable keys in RAM, and physically
     * compact SSTables only when the index actually reports expired records
     * (or the file count needs bounding).  A sweep with nothing to expire no
     * longer reads a single byte of SSTable data. */
    expired_collect_ctx_t ctx = { .now = now, .ok = true };
    qihse_trinary_trie_foreach(store->trie, collect_expired_cb, &ctx);
        if (ctx.ok) tombstone_expired_keys(store, ctx.keys, ctx.count);
    for (size_t i = 0; i < ctx.count; i++) free(ctx.keys[i]);
    free(ctx.keys);
    if (sst_meta_index_has_expired(store->sst_meta, now) ||
        store->sstable_counter >= KV_SSTABLE_COMPACT_THRESHOLD) {
        (void)compact_sstables_stream(store);
    }
    kv_store_unlock(store);
}

typedef struct {
    qihse_user_t* user;
    qihse_kv_iter_cb cb;
    void* user_data;
    const char* prefix;
    size_t prefix_len;
    uint64_t now;
    bool ok;
} foreach_user_ctx_t;
static bool foreach_user_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; foreach_user_ctx_t* ctx = (foreach_user_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if (ctx->prefix && strncmp(key, ctx->prefix, ctx->prefix_len) != 0) return true;
    if (payload_is_dead(p, ctx->now)) return true;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) return true;
    return ctx->cb(key, p->val, ctx->user_data);
}

static bool foreach_sst_emit_cb(const char* key, const kv_disk_record_t* r, void* ud) {
    foreach_user_ctx_t* ctx = (foreach_user_ctx_t*)ud;
    if (!ctx || !key || !r) return false;
    if (ctx->prefix && strncmp(key, ctx->prefix, ctx->prefix_len) != 0) return true;
    if (!qihse_auth_can_access(ctx->user, r->classification, r->sci_compartment)) return true;
    return ctx->cb(key, r->val, ctx->user_data);
}

/* Prefix reads use the existing exact SST metadata index to locate candidate
 * records.  Scan keys in RAM, then read only matching records by pinned file
 * offset.  The index is not an authorization source: check the classification
 * and SCI from the actual record before releasing its value. */
static int sst_foreach_prefix_indexed(qihse_kv_store_t* store,
                                      foreach_user_ctx_t* ctx) {
    if (!store || !ctx || !ctx->prefix || !store->sst_meta ||
        store->sst_meta->degraded) return -1;
    const char* dir = get_qihse_data_dir();
    if (!dir) return -1;
    const sst_meta_index_t* idx = store->sst_meta;
    for (size_t i = 0; i < idx->cap; i++) {
        const sst_meta_entry_t* e = &idx->slots[i];
        if (!e->key || strncmp(e->key, ctx->prefix, ctx->prefix_len) != 0)
            continue;
        if (qihse_trinary_trie_search(store->trie, e->key, NULL) != NULL)
            continue;
        kv_lookup_result_t record;
        memset(&record, 0, sizeof(record));
        kv_lookup_state_t state = lookup_one_sstable(store, dir, e->key,
                                                      e->sstable_id,
                                                      e->sst_offset, &record);
        if (state == KV_LOOKUP_ERROR) {
            lookup_result_free(&record);
            return -1;
        }
        if (state == KV_LOOKUP_LIVE &&
            qihse_auth_can_access(ctx->user, record.classification,
                                  record.sci_compartment)) {
            bool keep_going = ctx->cb(e->key, record.value, ctx->user_data);
            lookup_result_free(&record);
            if (!keep_going) return 0;
        } else {
            lookup_result_free(&record);
        }
    }
    return 1;
}

static bool foreach_user_filtered(qihse_kv_store_t* store, const char* prefix,
                                  qihse_user_t* user, qihse_kv_iter_cb cb,
                                  void* user_data) {
    if (!store || !store->trie || !cb) return false;
    kv_store_rdlock(store);
    bool compact_needed = store->sstable_counter > 0 &&
                          (!store->sst_meta || store->sst_meta->degraded);
    kv_store_unlock(store);
    if (compact_needed) {
        /* Degraded index: merge under the WRITE side, then restart so the
         * user callback always runs with only a read lock (it may re-enter
         * this store for another authorized read). */
        kv_store_wrlock(store);
        bool ok = store->sstable_counter == 0 ||
                  ((store->sst_meta && !store->sst_meta->degraded) ||
                   compact_sstables_into_memtable(store));
        kv_store_unlock(store);
        return ok && foreach_user_filtered(store, prefix, user, cb, user_data);
    }
    /* No compaction: iterate the memtable, then stream the index-pinned
     * newest SSTable records. Callbacks may re-enter qihse_kv_get_user. */
    /* Recheck after taking the read lock: a writer may have degraded the
     * index between the first probe and this lock. */
    kv_store_rdlock(store);
    if (store->sstable_counter > 0 && (!store->sst_meta || store->sst_meta->degraded)) {
        kv_store_unlock(store);
        return foreach_user_filtered(store, prefix, user, cb, user_data);
    }
    foreach_user_ctx_t ctx = {
        .user = user, .cb = cb, .user_data = user_data,
        .prefix = prefix, .prefix_len = prefix ? strlen(prefix) : 0u,
        .now = current_time_ms(), .ok = true
    };
    qihse_trinary_trie_foreach(store->trie, foreach_user_cb, &ctx);
    int rc = 0;
    if (store->sstable_counter > 0) {
        rc = prefix && *prefix
           ? sst_foreach_prefix_indexed(store, &ctx)
           : sst_foreach_newest(store, false, foreach_sst_emit_cb, &ctx);
    }
    kv_store_unlock(store);
    return rc >= 0;
}
bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user,
                           qihse_kv_iter_cb cb, void* user_data) {
    return foreach_user_filtered(store, NULL, user, cb, user_data);
}
bool qihse_kv_foreach_prefix_user(qihse_kv_store_t* store, const char* prefix,
                                  qihse_user_t* user, qihse_kv_iter_cb cb,
                                  void* user_data) {
    if (!prefix) return false;
    return foreach_user_filtered(store, prefix, user, cb, user_data);
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
    if (!store || !store->trie) return 0u;
    kv_store_rdlock(store);
    bool compact_needed = store->sstable_counter > 0 &&
                          (!store->sst_meta || store->sst_meta->degraded);
    kv_store_unlock(store);
    if (compact_needed) {
        kv_store_wrlock(store);
        bool ok = store->sstable_counter == 0 ||
                  ((store->sst_meta && !store->sst_meta->degraded) ||
                   compact_sstables_into_memtable(store));
        kv_store_unlock(store);
        if (!ok) return 0u;
        return qihse_kv_count_user(store, user);
    }
    /* No compaction: count live+authorized memtable keys, then live+
     * authorized index entries not shadowed by the memtable.  Pure RAM. */
    kv_store_rdlock(store);
    if (store->sstable_counter > 0 && (!store->sst_meta || store->sst_meta->degraded)) {
        kv_store_unlock(store);
        return qihse_kv_count_user(store, user);
    }
    uint64_t now = current_time_ms();
    count_ctx_t ctx = { .user = user, .count = 0u, .now = now };
    qihse_trinary_trie_foreach(store->trie, count_cb, &ctx);
    const sst_meta_index_t* idx = store->sst_meta;
    for (size_t i = 0; idx && i < idx->cap; i++) {
        const sst_meta_entry_t* e = &idx->slots[i];
        if (!e->key) continue;
        if ((e->flags & KV_FLAG_TOMBSTONE) != 0u ||
            (e->expire_time_ms != 0u && e->expire_time_ms <= now)) continue;
        if (!qihse_auth_can_access(user, e->classification, e->sci_compartment)) continue;
        size_t z = 0u;
        if (qihse_trinary_trie_search(store->trie, e->key, &z) != NULL) continue;
        ctx.count++;
    }
    kv_store_unlock(store);
    return ctx.count;
}
size_t qihse_kv_count(qihse_kv_store_t* store) { return qihse_kv_count_user(store, NULL); }

/* fsync a directory so renames inside it survive power loss. */
static bool fsync_dir_path(const char* dir) {
    if (!dir) return false;
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

bool qihse_kv_sync_store(qihse_kv_store_t* store) {
    if (!store || !store->trie) return false;
    kv_store_wrlock(store);
    /* 1. WAL: stdio buffer to the kernel, then the fd itself. Without the
     * fsync the WAL lives only in the page cache -- fine against process
     * death, lost on power loss; SAVE promises both. */
    if (store->wal_fd) {
        if (fflush(store->wal_fd) != 0) { kv_store_unlock(store); return false; }
        int wfd = fileno(store->wal_fd);
        if (wfd >= 0 && fsync(wfd) != 0) { kv_store_unlock(store); return false; }
        store->wal_unflushed_bytes = 0u;
    }
    /* 2. Memtable -> new SSTable (atomic rename, file fsynced inside the
     * atomic commit) + WAL rotation. Every mutation lands in BOTH the WAL
     * and the memtable, so an empty memtable means the WAL holds nothing
     * that is not already durable -- skip the flush, keep the fsyncs. */
    if (store->mem_usage > 0u && !flush_memtable_to_sstable(store)) { kv_store_unlock(store); return false; }
    /* 3. The renames above and in flush/rotate are only as durable as the
     * directory entry that points at them. */
    const char* dir = get_qihse_data_dir();
    if (dir && !fsync_dir_path(dir)) { kv_store_unlock(store); return false; }
    kv_store_unlock(store);
    return true;
}


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
    if (!store || !store->trie || __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE)) return 0u;
    /* Whole-operation write side: this enumerates, tombstones, and may
     * compact — and the internal deletes use kv_del_user_impl so the lock
     * is taken exactly once. */
    kv_store_wrlock(store);
    uint64_t now = current_time_ms();
    clear_collect_ctx_t ctx = { .user = user, .now = now, .ok = true };
    bool fast = store->sst_meta && !store->sst_meta->degraded;
    if (!fast && !compact_sstables_into_memtable(store)) { kv_store_unlock(store); return 0u; }
    qihse_trinary_trie_foreach(store->trie, clear_collect_cb, &ctx);
    if (fast) {
        /* Enumerate SSTable keys from the index instead of merging files. */
        const sst_meta_index_t* idx = store->sst_meta;
        for (size_t i = 0; ctx.ok && i < idx->cap; i++) {
            const sst_meta_entry_t* e = &idx->slots[i];
            if (!e->key) continue;
            if ((e->flags & KV_FLAG_TOMBSTONE) != 0u ||
                (e->expire_time_ms != 0u && e->expire_time_ms <= now)) continue;
            if (!qihse_auth_can_access(user, e->classification, e->sci_compartment)) continue;
            size_t z = 0u;
            if (qihse_trinary_trie_search(store->trie, e->key, &z) != NULL) continue;
            if (ctx.count == ctx.cap) {
                size_t new_cap = ctx.cap ? ctx.cap * 2u : 32u;
                char** next = (char**)realloc(ctx.keys, new_cap * sizeof(*next));
                if (!next) { ctx.ok = false; break; }
                ctx.keys = next; ctx.cap = new_cap;
            }
            ctx.keys[ctx.count] = strdup(e->key);
            if (!ctx.keys[ctx.count]) { ctx.ok = false; break; }
            ctx.count++;
        }
    }
    size_t removed = 0u;
    if (ctx.ok) for (size_t i = 0; i < ctx.count; i++) if (kv_del_user_impl(store, ctx.keys[i], user)) removed++;
    for (size_t i = 0; i < ctx.count; i++) free(ctx.keys[i]);
    free(ctx.keys);
    /* Physically purge the SSTable copies of everything just tombstoned —
     * same on-disk removal guarantee as the old compact-first version. */
    if (removed > 0 && fast && store->sstable_counter > 0)
        (void)compact_sstables_stream(store);
    kv_store_unlock(store);
    return removed;
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
static bool export_sst_write_cb(const char* key, const kv_disk_record_t* r, void* ud) {
    export_write_ctx_t* ctx = (export_write_ctx_t*)ud;
    if (!ctx || !ctx->ok || !key || !r) return false;
    if (!disk_record_write_fields(ctx->f, key, r->val, r->expire_time_ms,
                                  r->classification, r->sci_compartment, r->flags,
                                  r->change_seq)) {
        ctx->ok = false; return false;
    }
    return true;
}

typedef struct {
    FILE* f;
    qihse_user_t* user;
    const char* glob;
    uint64_t now;
    bool ok;
    bool authorized;
} replica_snapshot_write_ctx_t;

static bool replica_snapshot_write_mem_cb(const char* key, void* value,
                                          size_t value_size, void* ud) {
    (void)value_size;
    replica_snapshot_write_ctx_t* ctx = (replica_snapshot_write_ctx_t*)ud;
    kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !ctx->authorized || !key || !p) return false;
    if (fnmatch(ctx->glob, key, 0) != 0 || payload_is_dead(p, ctx->now)) return true;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) {
        ctx->authorized = false;
        return false;
    }
    if (!disk_record_write(ctx->f, key, p)) { ctx->ok = false; return false; }
    return true;
}

static bool replica_snapshot_write_sst_cb(const char* key,
                                          const kv_disk_record_t* r, void* ud) {
    replica_snapshot_write_ctx_t* ctx = (replica_snapshot_write_ctx_t*)ud;
    if (!ctx || !ctx->ok || !ctx->authorized || !key || !r) return false;
    if (fnmatch(ctx->glob, key, 0) != 0) return true;
    if (!qihse_auth_can_access(ctx->user, r->classification, r->sci_compartment)) {
        ctx->authorized = false;
        return false;
    }
    if (!disk_record_write_fields(ctx->f, key, r->val, r->expire_time_ms,
                                  r->classification, r->sci_compartment, r->flags,
                                  r->change_seq)) {
        ctx->ok = false;
        return false;
    }
    return true;
}

static int qihse_kv_save_replica_snapshot_file(qihse_kv_store_t* store,
                                               const char* filepath,
                                               qihse_user_t* user,
                                               const char* glob) {
    if (!store || !store->trie || !filepath || !glob || !*glob) return -1;
    bool fast = store->sst_meta && !store->sst_meta->degraded;
    if (!fast && !compact_sstables_into_memtable(store)) return -1;
    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &f)) return -1;
    replica_snapshot_write_ctx_t ctx = {
        .f = f, .user = user, .glob = glob, .now = current_time_ms(),
        .ok = true, .authorized = true
    };
    qihse_trinary_trie_foreach(store->trie, replica_snapshot_write_mem_cb, &ctx);
    if (ctx.ok && ctx.authorized && fast) {
        int rc = sst_foreach_newest(store, false, replica_snapshot_write_sst_cb, &ctx);
        if (rc < 0) ctx.ok = false;
    }
    if (!ctx.authorized) { fclose(f); unlink(tmp); errno = EACCES; return -2; }
    if (!ctx.ok || ferror(f)) { fclose(f); unlink(tmp); return -1; }
    return atomic_file_commit(f, tmp, filepath) ? 0 : -1;
}

int qihse_kv_save_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user) {
    if (!store || !store->trie || !filepath) return -1;
    /* The fast path only reads (trie + index + immutable SSTables), but the
     * !fast path compacts; taking the WRITE side unconditionally keeps the
     * snapshot internally consistent either way. */
    kv_store_wrlock(store);
    uint64_t now = current_time_ms();
    bool fast = store->sst_meta && !store->sst_meta->degraded;
    if (!fast && !compact_sstables_into_memtable(store)) { kv_store_unlock(store); return -1; }
    /* Auth gate: refuse the whole snapshot if any live record is above the
     * caller's clearance.  The index carries classification metadata, so on
     * the fast path this check touches no values and no disk. */
    export_auth_ctx_t auth = { .user = user, .now = now, .authorized = true };
    qihse_trinary_trie_foreach(store->trie, export_auth_cb, &auth);
    if (auth.authorized && fast) {
        const sst_meta_index_t* idx = store->sst_meta;
        for (size_t i = 0; i < idx->cap && auth.authorized; i++) {
            const sst_meta_entry_t* e = &idx->slots[i];
            if (!e->key) continue;
            if ((e->flags & KV_FLAG_TOMBSTONE) != 0u ||
                (e->expire_time_ms != 0u && e->expire_time_ms <= now)) continue;
            size_t z = 0u;
            if (qihse_trinary_trie_search(store->trie, e->key, &z) != NULL) continue;
            if (!qihse_auth_can_access(user, e->classification, e->sci_compartment))
                auth.authorized = false;
        }
    }
    if (!auth.authorized) { errno = EACCES; kv_store_unlock(store); return -2; }
    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &f)) { kv_store_unlock(store); return -1; }
    export_write_ctx_t wr = { .f = f, .now = now, .ok = true };
    qihse_trinary_trie_foreach(store->trie, export_write_cb, &wr);
    if (wr.ok && fast) {
        int rc = sst_foreach_newest(store, false, export_sst_write_cb, &wr);
        if (rc < 0) wr.ok = false;
    }
    if (!wr.ok || ferror(f)) { fclose(f); unlink(tmp); kv_store_unlock(store); return -1; }
    if (!atomic_file_commit(f, tmp, filepath)) { kv_store_unlock(store); return -1; }
    kv_store_unlock(store);
    return 0;
}
int qihse_kv_save(qihse_kv_store_t* store, const char* filepath) { return qihse_kv_save_user(store, filepath, NULL); }

int qihse_kv_replica_snapshot_create(qihse_kv_store_t* store, qihse_user_t* user,
                                     const char* namespace_glob,
                                     qihse_kv_replica_snapshot_t** out_snapshot) {
    if (out_snapshot) *out_snapshot = NULL;
    if (!store || !out_snapshot || !namespace_glob || !*namespace_glob) return -1;
    const char* dir = get_qihse_data_dir();
    if (!dir) return -1;
    char path[4096];
    int n = snprintf(path, sizeof(path), "%sqihse-repl-snapshot-XXXXXX", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return -1;
    int seed_fd = mkstemp(path);
    if (seed_fd < 0) return -1;
    (void)fchmod(seed_fd, 0600);
    close(seed_fd);
    /* save_user() atomically replaces this unique path with the complete
     * authorized snapshot. The name is never sent over the replication wire. */
    if (qihse_kv_save_replica_snapshot_file(store, path, user, namespace_glob) != 0) {
        int saved_errno = errno;
        (void)unlink(path);
        errno = saved_errno;
        return saved_errno == EACCES ? -2 : -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int saved_errno = errno;
    (void)unlink(path);
    if (fd < 0) { errno = saved_errno; return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        return -1;
    }
    qihse_kv_replica_snapshot_t* snapshot =
        (qihse_kv_replica_snapshot_t*)calloc(1u, sizeof(*snapshot));
    if (!snapshot) { close(fd); return -1; }
    snapshot->fd = fd;
    snapshot->size = (uint64_t)st.st_size;
    *out_snapshot = snapshot;
    return 0;
}

uint64_t qihse_kv_replica_snapshot_size(const qihse_kv_replica_snapshot_t* snapshot) {
    return snapshot ? snapshot->size : 0u;
}

bool qihse_kv_replica_snapshot_read(qihse_kv_replica_snapshot_t* snapshot,
                                    uint64_t offset, void* out, size_t capacity,
                                    size_t* out_read) {
    if (out_read) *out_read = 0u;
    if (!snapshot || snapshot->fd < 0 || !out_read || (capacity && !out) || offset > snapshot->size)
        return false;
    uint64_t remain = snapshot->size - offset;
    size_t want = remain < (uint64_t)capacity ? (size_t)remain : capacity;
    size_t done = 0u;
    while (done < want) {
        ssize_t n = pread(snapshot->fd, (char*)out + done, want - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    *out_read = done;
    return true;
}

void qihse_kv_replica_snapshot_destroy(qihse_kv_replica_snapshot_t* snapshot) {
    if (!snapshot) return;
    if (snapshot->fd >= 0) close(snapshot->fd);
    free(snapshot);
}

/* Parse a snapshot file into a replacement trie, PRESERVING each record's
 * stamped sequence (a restore is not a mutation) and reporting the maximum
 * sequence seen so qihse_kv_load_user can raise — never lower — the store's
 * high-water. */
static bool parse_snapshot_into_trie(const char* filepath, qihse_user_t* user,
                                     qihse_trinary_trie_t** out_trie, size_t* out_usage,
                                     uint64_t* out_max_seq) {
    int fd = open_secure_read(filepath);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    qihse_trinary_trie_t* trie = qihse_trinary_trie_create();
    if (!trie) { fclose(f); return false; }
    size_t usage = 0u; uint64_t max_seq = 0u;
    kv_disk_record_t r; int rc; bool ok = true;
    while ((rc = disk_record_read(f, &r)) == 1) {
        if (!qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
            disk_record_free(&r); errno = EACCES; ok = false; break;
        }
        size_t ps = 0u;
        kv_payload_t* p = payload_create(r.val, r.expire_time_ms, r.classification,
                                         r.sci_compartment, r.flags, r.change_seq, &ps);
        if (!p || !qihse_trinary_trie_insert_nocopy(trie, r.key, p, ps)) {
            free(p); disk_record_free(&r); ok = false; break;
        }
        if (r.change_seq > max_seq) max_seq = r.change_seq;
        usage += strlen(r.key) + ps; disk_record_free(&r);
    }
    if (rc < 0) ok = false;
    fclose(f);
    if (!ok) { qihse_trinary_trie_destroy(trie); return false; }
    *out_trie = trie;
    if (out_usage) *out_usage = usage;
    if (out_max_seq) *out_max_seq = max_seq;
    return true;
}

static int qihse_kv_load_user_internal(qihse_kv_store_t* store, const char* filepath,
                                       qihse_user_t* user, bool replica_install) {
    if (!store || !filepath ||
        (__atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) && !replica_install)) return -1;
    qihse_trinary_trie_t* replacement = NULL; size_t replacement_usage = 0u;
    uint64_t replacement_max_seq = 0u;
    if (!parse_snapshot_into_trie(filepath, user, &replacement, &replacement_usage,
                                  &replacement_max_seq))
        return errno == EACCES ? -2 : -1;
    char wal_path[4096], wal_tmp[8192];
    kv_store_wrlock(store);
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) {
        kv_store_unlock(store); qihse_trinary_trie_destroy(replacement); return -1;
    }
    FILE* new_wal_tmp = NULL;
    if (!atomic_file_begin(wal_path, wal_tmp, sizeof(wal_tmp), &new_wal_tmp)) {
        kv_store_unlock(store); qihse_trinary_trie_destroy(replacement); return -1;
    }
    if (!atomic_file_commit(new_wal_tmp, wal_tmp, wal_path)) {
        kv_store_unlock(store); qihse_trinary_trie_destroy(replacement); return -1;
    }
    int new_wal_fd = open(wal_path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (new_wal_fd < 0) { kv_store_unlock(store); qihse_trinary_trie_destroy(replacement); return -1; }
    FILE* new_wal = fdopen(new_wal_fd, "ab");
    if (!new_wal) { close(new_wal_fd); kv_store_unlock(store); qihse_trinary_trie_destroy(replacement); return -1; }
    qihse_trinary_trie_t* old = store->trie; FILE* old_wal = store->wal_fd;
    store->trie = replacement; store->mem_usage = replacement_usage; store->wal_fd = new_wal; store->wal_unflushed_bytes = 0u;
    /* A restore must not regress the change sequence: the loaded records
     * keep their stamped sequences and the high-water rises to the file's
     * maximum if it was higher.  It is NOT re-stamped — a restore is not a
     * mutation — so a caller holding a cursor from BEFORE a restore should
     * re-baseline with a full export (the restored dataset may be older
     * than the cursor). */
    kv_change_seq_floor(store, replacement_max_seq);
    if (old_wal) fclose(old_wal);
    if (old) qihse_trinary_trie_destroy(old);
    const char* dir = get_qihse_data_dir();
    if (dir) for (int i = 0; i < store->sstable_counter; i++) {
        char path[4096]; int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, i);
        if (n >= 0 && (size_t)n < sizeof(path)) (void)unlink(path);
    }
    store->sstable_counter = 0;
    sst_meta_index_reset(store);
    sst_fd_cache_clear(store);
    kv_store_unlock(store);
    return 0;
}
int qihse_kv_load_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user) {
    return qihse_kv_load_user_internal(store, filepath, user, false);
}

static void replica_snapshot_marker_namespace(const char* glob, char out[48]) {
    uint64_t a = 14695981039346656037ULL;
    uint64_t b = 1099511628211ULL;
    for (const unsigned char* p = (const unsigned char*)glob; *p; p++) {
        a = fnv1a64_update(a, p, 1u);
        b ^= (uint64_t)(*p + 0x9dU);
        b *= 0x100000001b3ULL;
    }
    snprintf(out, 48u, "snapshot-%016llx%016llx",
             (unsigned long long)a, (unsigned long long)b);
}

bool qihse_kv_replica_snapshot_installed(qihse_kv_store_t* store,
                                         const char* peer_id,
                                         const char* namespace_glob,
                                         qihse_user_t* principal,
                                         bool* out_installed) {
    if (!store || !namespace_glob || !*namespace_glob || !out_installed) return false;
    char marker[48]; uint64_t seq = 0u;
    replica_snapshot_marker_namespace(namespace_glob, marker);
    if (!qihse_kv_replica_cursor_get(store, peer_id, marker, principal, &seq)) return false;
    *out_installed = seq != 0u;
    return true;
}

static bool replica_snapshot_file_valid(const char* filepath, qihse_user_t* principal,
                                        const char* glob, uint64_t source_highwater) {
    int fd = open_secure_read(filepath);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    bool valid = true;
    kv_disk_record_t record;
    int rc;
    while ((rc = disk_record_read(f, &record)) == 1) {
        valid = fnmatch(glob, record.key, 0) == 0 &&
            (record.flags & KV_FLAG_TOMBSTONE) == 0u &&
            (record.change_seq == 0u || record.change_seq <= source_highwater) &&
            qihse_auth_can_access(principal, record.classification,
                                  record.sci_compartment);
        disk_record_free(&record);
        if (!valid) break;
    }
    if (rc < 0) valid = false;
    fclose(f);
    return valid;
}

bool qihse_kv_replica_snapshot_install(qihse_kv_store_t* store,
                                       const char* filepath,
                                       qihse_user_t* principal,
                                       const char* peer_id,
                                       const char* namespace_glob,
                                       uint64_t source_highwater) {
    if (!store || !filepath || !namespace_glob || !*namespace_glob ||
        !__atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) ||
        !cursor_principal_ok(principal) || !cursor_id_valid(peer_id) ||
        !cursor_id_valid(namespace_glob)) return false;
    bool installed = false;
    if (!qihse_kv_replica_snapshot_installed(store, peer_id, namespace_glob,
                                              principal, &installed)) return false;
    /* A snapshot replaces the logical KV image. It is safe only in a
     * dedicated replica store (empty on first bootstrap, already owned by
     * this exact peer/namespace on re-baseline). */
    if (!installed && qihse_kv_count_user(store, principal) != 0u) return false;
    uint64_t current = 0u;
    if (!replica_snapshot_file_valid(filepath, principal, namespace_glob,
                                     source_highwater) ||
        !qihse_kv_replica_cursor_get(store, peer_id, namespace_glob, principal, &current) ||
        current > source_highwater) return false;
    const char* dir = get_qihse_data_dir();
    char image_path[4096], meta_path[4096];
    int image_len = dir ? snprintf(image_path, sizeof(image_path), "%sreplica-install.image", dir) : -1;
    int meta_len = dir ? snprintf(meta_path, sizeof(meta_path), "%sreplica-install.meta", dir) : -1;
    if (image_len < 0 || (size_t)image_len >= sizeof(image_path) ||
        meta_len < 0 || (size_t)meta_len >= sizeof(meta_path)) return false;
    replica_install_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    snprintf(meta.peer, sizeof(meta.peer), "%s", peer_id);
    snprintf(meta.glob, sizeof(meta.glob), "%s", namespace_glob);
    meta.source_seq = source_highwater;
    if (!copy_file_atomic_hash(filepath, image_path, &meta.image_hash) ||
        !fsync_dir_path(dir)) {
        (void)unlink(image_path);
        return false;
    }
    replica_install_test_crash_point("image");
    if (!replica_install_meta_write(meta_path, &meta)) {
        (void)unlink(image_path);
        return false;
    }
    replica_install_test_crash_point("intent");
    if (qihse_kv_load_user_internal(store, image_path, principal, true) != 0) return false;
    replica_install_test_crash_point("wal-replaced");
    if (!qihse_kv_sync_store(store)) return false;
    replica_install_test_crash_point("sst-wal-durable");
    if (!qihse_kv_replica_cursor_advance(store, peer_id, namespace_glob,
                                         source_highwater, principal)) return false;
    replica_install_test_crash_point("cursor-durable");
    char marker[48];
    replica_snapshot_marker_namespace(namespace_glob, marker);
    if (!qihse_kv_replica_cursor_advance(store, peer_id, marker, 1u, principal)) return false;
    replica_install_test_crash_point("marker-durable");
    if (unlink(meta_path) != 0 || !fsync_dir_path(dir)) return false;
    replica_install_test_crash_point("journal-removed");
    if (unlink(image_path) != 0 && errno != ENOENT) return false;
    return fsync_dir_path(dir);
}

int qihse_kv_load(qihse_kv_store_t* store, const char* filepath) { return qihse_kv_load_user(store, filepath, NULL); }

/* ── Change sequence and incremental (delta) export ──────────────────────
 *
 * The delta read path.  It enumerates records whose stamped sequence is
 * STRICTLY greater than `since_seq`, carrying live records AND tombstones
 * (a delete is a mutation a delta must express), with the SAME
 * authorization-aware iteration the full export uses: the caller's identity
 * reaches this, the lowest data-retrieval layer, and each record is checked
 * with qihse_auth_can_access against its classification/SCI before the
 * callback sees anything (AGENTS.md invariant 1).  A NULL user keeps this
 * layer's family convention (the deliberately unclassified-only view);
 * higher layers that must refuse NULL wrap this and add their own gate.
 *
 * METADATA DISCLOSURE — the resume point is need-to-know, by default and
 * only.  It is the highest sequence among the records THIS principal was
 * allowed to see, never the store-global high-water.  Mutations the
 * principal may not see are filtered before the resume point is computed,
 * so they are never enumerated, and a caller comparing successive resume
 * points cannot infer how many hidden mutations occurred — the resume point
 * simply does not move until the principal is allowed to see something
 * newer.  The cost is a re-scan of the records between the resume point and
 * the global high-water on each export, which is a sequence compare during
 * iteration.  No "global high-water with gaps visible" form is offered,
 * even opt-in: it would disclose the count of hidden mutations.
 *
 * Records predating the sequence (sequence 0, from pre-v4 files) are never
 * part of a delta — a caller bootstraps with a full export (which carries
 * them) and then tracks deltas. */

uint64_t qihse_kv_change_seq(qihse_kv_store_t* store) {
    if (!store) return 0u;
    return __atomic_load_n(&store->change_seq, __ATOMIC_RELAXED);
}

void qihse_kv_delta_records_free(qihse_kv_delta_record_t* records, size_t count) {
    if (!records) return;
    for (size_t i = 0; i < count; i++) {
        free(records[i].key);
        free(records[i].value);
    }
    free(records);
}

typedef struct {
    qihse_user_t* user;
    uint64_t since;
    uint64_t now;
    qihse_kv_delta_record_t* recs;
    size_t count;
    size_t cap;
    uint64_t resume;   /* highest sequence the principal was ALLOWED to see */
    const char* glob;
    size_t max_records;
    size_t max_bytes;
    size_t bytes;
    bool ok;
} delta_collect_ctx_t;

/* Grow-by-doubling collector shared by the memtable and SSTable walks.  The
 * array (not one stack buffer per record) keeps frames bounded. */
static bool delta_collect_push(delta_collect_ctx_t* ctx, const char* key, const char* val,
                               const kv_payload_t* p) {
    size_t key_len = strlen(key);
    bool tombstone = (p->flags & KV_FLAG_TOMBSTONE) != 0u;
    size_t value_len = tombstone ? 0u : strlen(val ? val : "");
    size_t cost = key_len + value_len + 160u;
    if (ctx->max_records != 0u) {
        if (cost > ctx->max_bytes) return true;
        size_t largest = SIZE_MAX;
        for (size_t i = 0; i < ctx->count; i++) {
            if (largest == SIZE_MAX || ctx->recs[i].change_seq > ctx->recs[largest].change_seq ||
                (ctx->recs[i].change_seq == ctx->recs[largest].change_seq &&
                 strcmp(ctx->recs[i].key, ctx->recs[largest].key) > 0)) largest = i;
        }
        bool before_largest = largest == SIZE_MAX || p->change_seq < ctx->recs[largest].change_seq ||
            (p->change_seq == ctx->recs[largest].change_seq &&
             strcmp(key, ctx->recs[largest].key) < 0);
        if ((ctx->count >= ctx->max_records || ctx->bytes + cost > ctx->max_bytes) &&
            !before_largest) return true;
        while (ctx->count > 0u &&
               (ctx->count >= ctx->max_records || ctx->bytes + cost > ctx->max_bytes)) {
            largest = 0u;
            for (size_t i = 1u; i < ctx->count; i++)
                if (ctx->recs[i].change_seq > ctx->recs[largest].change_seq ||
                    (ctx->recs[i].change_seq == ctx->recs[largest].change_seq &&
                     strcmp(ctx->recs[i].key, ctx->recs[largest].key) > 0)) largest = i;
            ctx->bytes -= strlen(ctx->recs[largest].key) +
                (ctx->recs[largest].value ? strlen(ctx->recs[largest].value) : 0u) + 160u;
            free(ctx->recs[largest].key); free(ctx->recs[largest].value);
            ctx->count--;
            if (largest != ctx->count) ctx->recs[largest] = ctx->recs[ctx->count];
            memset(&ctx->recs[ctx->count], 0, sizeof(ctx->recs[ctx->count]));
        }
    }
    if (ctx->count == ctx->cap) {
        size_t new_cap = ctx->cap ? ctx->cap * 2u : 16u;
        qihse_kv_delta_record_t* next =
            (qihse_kv_delta_record_t*)realloc(ctx->recs, new_cap * sizeof(*next));
        if (!next) { ctx->ok = false; return false; }
        ctx->recs = next;
        ctx->cap = new_cap;
    }
    qihse_kv_delta_record_t* out = &ctx->recs[ctx->count];
    memset(out, 0, sizeof(*out));
    out->key = strdup(key);
    if (!out->key) { ctx->ok = false; return false; }
    if (!tombstone) {
        out->value = strdup(val ? val : "");
        if (!out->value) { free(out->key); out->key = NULL; ctx->ok = false; return false; }
    }
    out->tombstone = tombstone;
    out->change_seq = p->change_seq;
    out->classification = p->classification;
    out->sci_compartment = p->sci_compartment;
    out->expire_time_ms = p->expire_time_ms;
    ctx->count++;
    ctx->bytes += cost;
    if (ctx->max_records == 0u && p->change_seq > ctx->resume) ctx->resume = p->change_seq;
    return true;
}

/* Memtable walk: one payload at a time, authorization-checked HERE before
 * anything is copied.  Tombstones are included (a delete is a delta event);
 * live-but-expired payloads are skipped, matching the full export. */
static bool delta_trie_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size;
    delta_collect_ctx_t* ctx = (delta_collect_ctx_t*)user_data;
    kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if (p->change_seq <= ctx->since || p->change_seq == 0u) return true; /* skip */
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) return true;
    if (ctx->glob && fnmatch(ctx->glob, key, 0) != 0) return true;
    bool tombstone = (p->flags & KV_FLAG_TOMBSTONE) != 0u;
    bool expired = !tombstone && p->expire_time_ms != 0u && p->expire_time_ms <= ctx->now;
    if (expired) return true;
    return delta_collect_push(ctx, key, p->val, p);
}

/* SSTable walk: the index-pinned newest record at this (id, offset); the
 * same checks as the memtable walk. */
static bool delta_sst_cb(const char* key, const kv_disk_record_t* r, void* ud) {
    delta_collect_ctx_t* ctx = (delta_collect_ctx_t*)ud;
    if (!ctx || !ctx->ok || !key || !r) return false;
    if (r->change_seq <= ctx->since || r->change_seq == 0u) return true;
    if (!qihse_auth_can_access(ctx->user, r->classification, r->sci_compartment)) return true;
    if (ctx->glob && fnmatch(ctx->glob, key, 0) != 0) return true;
    kv_payload_t view;
    memset(&view, 0, sizeof(view));
    view.expire_time_ms = r->expire_time_ms;
    view.change_seq = r->change_seq;
    view.classification = r->classification;
    view.sci_compartment = r->sci_compartment;
    view.flags = r->flags;
    bool tombstone = (r->flags & KV_FLAG_TOMBSTONE) != 0u;
    bool expired = !tombstone && r->expire_time_ms != 0u && r->expire_time_ms <= ctx->now;
    if (expired) return true;
    return delta_collect_push(ctx, key, r->val, &view);
}

/* Deterministic order for consumers and tests: ascending sequence, with the
 * key as a tie-break (only hand-crafted files can tie). */
static int delta_record_cmp(const void* a, const void* b) {
    const qihse_kv_delta_record_t* ra = (const qihse_kv_delta_record_t*)a;
    const qihse_kv_delta_record_t* rb = (const qihse_kv_delta_record_t*)b;
    if (ra->change_seq != rb->change_seq) return ra->change_seq < rb->change_seq ? -1 : 1;
    if (ra->key && rb->key) return strcmp(ra->key, rb->key);
    return 0;
}

static int kv_export_incremental_common(qihse_kv_store_t* store, qihse_user_t* user,
                                     const char* glob, uint64_t since_seq,
                                     size_t max_records, size_t max_bytes,
                                     qihse_kv_delta_record_t** out_records,
                                     size_t* out_count, uint64_t* out_resume_seq) {
    if (out_records) *out_records = NULL;
    if (out_count) *out_count = 0u;
    if (out_resume_seq) *out_resume_seq = 0u;
    if (!store || !store->trie || !out_records || !out_count || !out_resume_seq) return -1;

    delta_collect_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.user = user;
    ctx.since = since_seq;
    ctx.now = current_time_ms();
    ctx.resume = since_seq;   /* the no-leak default: it does not move
                               * unless the principal sees something newer */
    ctx.glob = glob;
    ctx.max_records = max_records;
    ctx.max_bytes = max_bytes;
    ctx.ok = true;

    /* This can compact a degraded index and otherwise reads both the trie
     * and SSTable metadata as one snapshot.  Serialize the complete walk so
     * concurrent writes cannot move records between those two sources. */
    kv_store_wrlock(store);
    bool fast = store->sst_meta && !store->sst_meta->degraded;
    if (!fast && !compact_sstables_into_memtable(store)) { kv_store_unlock(store); return -1; }
    qihse_trinary_trie_foreach(store->trie, delta_trie_cb, &ctx);
    if (ctx.ok && fast) {
        int rc = sst_foreach_newest(store, true, delta_sst_cb, &ctx);
        if (rc < 0) ctx.ok = false;
    }
    if (!ctx.ok) {
        qihse_kv_delta_records_free(ctx.recs, ctx.count);
        kv_store_unlock(store);
        return -1;
    }
    kv_store_unlock(store);
    if (ctx.count > 1u) {
        qsort(ctx.recs, ctx.count, sizeof(*ctx.recs), delta_record_cmp);
    }
    if (max_records != 0u && ctx.count != 0u)
        ctx.resume = ctx.recs[ctx.count - 1u].change_seq;
    *out_records = ctx.recs;
    *out_count = ctx.count;
    *out_resume_seq = ctx.resume;
    return 0;
}

int qihse_kv_export_incremental_user(qihse_kv_store_t* store, qihse_user_t* user,
                                     uint64_t since_seq,
                                     qihse_kv_delta_record_t** out_records,
                                     size_t* out_count, uint64_t* out_resume_seq) {
    return kv_export_incremental_common(store, user, NULL, since_seq, 0u, 0u,
                                        out_records, out_count, out_resume_seq);
}

int qihse_kv_export_incremental_user_bounded(qihse_kv_store_t* store,
                                     qihse_user_t* user, const char* namespace_glob,
                                     uint64_t since_seq, size_t max_records,
                                     size_t max_bytes,
                                     qihse_kv_delta_record_t** out_records,
                                     size_t* out_count, uint64_t* out_resume_seq) {
    if (!namespace_glob || !*namespace_glob || max_records == 0u || max_bytes == 0u)
        return -1;
    return kv_export_incremental_common(store, user, namespace_glob, since_seq,
        max_records, max_bytes, out_records, out_count, out_resume_seq);
}

/* File form of the delta: the same text record stream qihse_kv_save_user
 * writes (v4 headers with the sequence; tombstones included), assembled
 * atomically like every snapshot.  Unlike qihse_kv_save_user this FILTERS
 * by authorization rather than refusing whole: a delta is explicitly "the
 * mutations you may see since the cursor", and its resume point is the
 * allowed-high-water — a partial-by-clearance delta is the CONTRACT here,
 * whereas a full snapshot claims complete coverage and must refuse (the KV
 * layer's save refuses whole for exactly that reason). */
int qihse_kv_save_delta_user(qihse_kv_store_t* store, const char* filepath,
                             qihse_user_t* user, uint64_t since_seq,
                             uint64_t* out_resume_seq) {
    if (out_resume_seq) *out_resume_seq = 0u;
    if (!store || !filepath) return -1;
    qihse_kv_delta_record_t* recs = NULL;
    size_t count = 0u;
    uint64_t resume = 0u;
    int rc = qihse_kv_export_incremental_user(store, user, since_seq, &recs, &count, &resume);
    if (rc != 0) return rc;

    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &f)) {
        qihse_kv_delta_records_free(recs, count);
        return -1;
    }
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        const qihse_kv_delta_record_t* r = &recs[i];
        uint8_t flags = r->tombstone ? KV_FLAG_TOMBSTONE : 0u;
        const char* val = r->tombstone ? "" : r->value;
        if (!disk_record_write_fields(f, r->key, val, r->expire_time_ms,
                                      r->classification, r->sci_compartment,
                                      flags, r->change_seq)) {
            ok = false;
        }
    }
    qihse_kv_delta_records_free(recs, count);
    if (!ok || ferror(f)) { fclose(f); unlink(tmp); return -1; }
    if (!atomic_file_commit(f, tmp, filepath)) return -1;
    if (out_resume_seq) *out_resume_seq = resume;
    return 0;
}

bool qihse_kv_store_is_under_attack(qihse_kv_store_t* store) {
    if (!store) return false;
    kv_store_rdlock(store);
    qihse_quantum_defense_ctx_t* ctx = __atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE);
    bool under_attack = ctx && qihse_qdd_is_under_attack(ctx);
    kv_store_unlock(store);
    return under_attack;
}

