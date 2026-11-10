#include "qihse_kv_store.h"
#include "qihse_cluster_slot.h"
#include "qihse_cluster_reclaim.h"
#include "qihse_ct_codec.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/random.h>
#include <time.h>
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
#define KV_WAL_MAGIC_LOCAL_SEQ "QKV4"
#define KV_WAL_MAGIC_DELETE_RECEIPT "QKV5"
#define KV_WAL_MAGIC_CT "QKV6"
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
#ifdef QIHSE_AIMEM_DURABILITY_TEST
static bool aimem_durability_test_fail_once(const char* point) {
    static char fired_point[128];
    const char* selected = getenv("QIHSE_AIMEM_FAIL_AT");
    if (selected && point && strcmp(selected, point) == 0 &&
        strcmp(fired_point, point) != 0) {
        snprintf(fired_point, sizeof(fired_point), "%s", point);
        errno = EIO;
        return true;
    }
    return false;
}
static bool wal_replay_test_fail_apply(void) {
    static unsigned attempts;
    static bool fired;
    const char* selected = getenv("QIHSE_AIMEM_FAIL_AT");
    if (!selected || fired) return false;
    attempts++;
    bool match = (!strcmp(selected, "wal-replay-apply") && attempts == 1u) ||
                 (!strcmp(selected, "wal-replay-apply-second") && attempts == 2u);
    if (!match) return false;
    fired = true;
    errno = EIO;
    return true;
}
#else
#define aimem_durability_test_fail_once(point) false
#define wal_replay_test_fail_apply() false
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
    if (!kcopy) {
        if (!idx->degraded) {
            fprintf(stderr,
                    "qihse-kv: sstable metadata index degraded (out of memory); "
                    "reads fall back to scanning every file until the next "
                    "compaction rebuilds the index\n");
        }
        idx->degraded = true;
        return;
    }
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
    int sstable_counter; /* next SSTable id, not the number of live files */
    size_t sstable_live_count;
    qihse_quantum_defense_ctx_t* qdd_ctx;
    bool bulk_load_mode;
    bool durable_batch_mode; /* Keep WAL appends, defer threshold flush/rotation. */
    bool replica_read_only;
    bool memory_snapshot; /* Immutable detached snapshot: never writes configured storage. */
    uint32_t replication_principal_id; /* QKP replication service principal id */
    bool ct_enabled;
    bool ct_admitted; /* runtime-only: reopened source requires QKP reconcile */
    uint8_t ct_mode; /* 1 source, 2 receiver */
    char ct_source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char ct_target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char ct_successor_id[QIHSE_KV_CT_ID_MAX + 1u];
    char ct_generation[QIHSE_KV_CT_ID_MAX + 1u];
    unsigned char ct_owner_token[QIHSE_KV_CT_TOKEN_BYTES];
    uint32_t ct_tenant_id;
    qihse_user_t* ct_system_principal; /* borrowed authenticated open context */
    qihse_kv_ct_tenant_policy_t ct_tenant_policy;
    uint64_t ct_baseline_lsn;
    unsigned char ct_baseline_digest[32];
    bool ct_baseline_sealed;
    uint64_t ct_durable_lsn;
    uint64_t ct_ack_lsn;
    uint64_t ct_retained_bytes;
    uint64_t ct_limit_bytes;
    unsigned char ct_last_group_digest[32];
    uint8_t ct_fence_state; /* 0 none, 1 transfer in progress, 2 moved */
    uint16_t ct_fence_first, ct_fence_last;
    uint64_t ct_fence_cut_position;
    unsigned char ct_moved_slots[QIHSE_CLUSTER_SLOT_COUNT / 8u];
    char ct_transfer_id[QIHSE_KV_CT_ID_MAX + 1u];
    uint8_t ct_transfer_phase; /* 0 none, 1 staged, 2 applied awaiting ACK/seal */
    char ct_transfer_source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char ct_transfer_source_generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t ct_transfer_source_cut;
    uint64_t ct_transfer_target_position;
    unsigned char ct_transfer_image_digest[32];
    unsigned char ct_transfer_group_digest[32];
    unsigned char ct_transfer_range_digest[32];
    pthread_mutex_t ct_ack_lock;
    pthread_cond_t ct_ack_changed;
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
    uint64_t projection_epoch; /* store-local; invalidates derived delta cursors */
    uint64_t instance_id; /* fresh on every create, including after restart */
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
    bool recovery_pending; /* Ambiguous publication/batch requires authenticated reopen. */
};

struct qihse_kv_replica_snapshot {
    int fd;
    uint64_t size;
    uint64_t source_change_seq;
    qihse_user_t* principal;
    uint32_t principal_id;
    uint32_t tenant_id;
    uint16_t classification;
    uint16_t sci;
};

typedef struct kv_replica_cursor {
    struct kv_replica_cursor* next;
    char* peer_id;
    char* namespace_id;
    uint64_t seq;
} kv_replica_cursor_t;

static bool fsync_dir_path(const char* dir);
static void kv_store_rdlock(qihse_kv_store_t* store);
static void kv_store_wrlock(qihse_kv_store_t* store);
static void kv_store_unlock(qihse_kv_store_t* store);
static bool kv_sync_store_locked(qihse_kv_store_t* store);
static void kv_store_rdlock(qihse_kv_store_t* store);
static void kv_store_wrlock(qihse_kv_store_t* store);
static void kv_store_unlock(qihse_kv_store_t* store);
bool qihse_kv_sync_store(qihse_kv_store_t* store);
static bool compact_sstables_stream(qihse_kv_store_t* store);

/* Backstop independent of the sweep clock. The sweep is the normal trigger,
 * but it stops for good reasons (cadence 0, thread failed to start, a run of
 * merge failures) and for bad ones (nobody noticed). Waiting on a clock to
 * bound on-disk state is how a store reaches thousands of files; at this
 * ceiling a flush merges inline instead. Chosen well above the normal
 * threshold so the inline path only ever fires when compaction has genuinely
 * stopped, and costs one slow write rather than unbounded read slowdown. */
#define KV_SSTABLE_HARD_CEILING 64u
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
static kv_lookup_state_t logical_lookup(qihse_kv_store_t* store,
                                        const char* key, kv_lookup_result_t* out);
static void lookup_result_free(kv_lookup_result_t* result);

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
    if (ok && aimem_durability_test_fail_once("sstable-file-fsync")) ok = false;
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
    if (aimem_durability_test_fail_once("sstable-rename") ||
        rename(tmp_path, final_path) != 0) { unlink(tmp_path); return false; }
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

typedef struct {
    char magic[8];
    uint8_t mode;
    uint8_t fence_state;
    uint16_t fence_first, fence_last;
    uint32_t tenant_id;
    uint32_t tenant_policy;
    uint64_t baseline_lsn, durable_lsn, ack_lsn, retained_bytes, limit_bytes;
    unsigned char baseline_digest[32];
    uint8_t baseline_sealed;
    uint64_t fence_cut_position;
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char successor_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    char transfer_id[QIHSE_KV_CT_ID_MAX + 1u];
    uint8_t transfer_phase;
    char transfer_source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char transfer_source_generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t transfer_source_cut;
    uint64_t transfer_target_position;
    unsigned char transfer_image_digest[32];
    unsigned char transfer_group_digest[32];
    unsigned char transfer_range_digest[32];
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char last_group_digest[32];
    unsigned char moved_slots[QIHSE_CLUSTER_SLOT_COUNT / 8u];
    uint64_t checksum;
} kv_ct_disk_t;

struct qihse_kv_ct_writer_scope {
    qihse_kv_store_t* store;
    qihse_user_t* principal;
    struct qihse_kv_ct_writer_scope* previous;
    uint64_t last_seq;
};
struct qihse_kv_ct_proof {
    uint32_t kind; /* 1 promotion, 2 source range seal, 3 target range seal */
    uint64_t store_instance_id;
    qihse_user_t* data_principal;
    uint64_t data_generation;
    uint32_t data_principal_id, data_tenant_id;
    uint16_t data_classification, data_sci;
    char transfer_id[QIHSE_KV_CT_ID_MAX + 1u];
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint16_t first_slot, last_slot;
    uint64_t source_lsn, target_lsn;
    unsigned char checksum[32];
    unsigned char mac[32];
};
static _Thread_local qihse_kv_ct_writer_scope_t* kv_ct_scope;
static _Thread_local qihse_kv_store_t* kv_ct_baseline_import_store;
static _Thread_local qihse_user_t* kv_ct_baseline_import_principal;

static bool ct_id_valid(const char* id) {
    if (!id) return false;
    size_t n = strnlen(id, QIHSE_KV_CT_ID_MAX + 1u);
    if (!n || n > QIHSE_KV_CT_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' ||
              c == '.' || c == ':')) return false;
    }
    return true;
}

static bool ct_admin(qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
           qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR;
}

static bool ct_replication_principal(qihse_kv_store_t* store,
                                     qihse_user_t* user) {
    return store && user && qihse_auth_user_is_active(user) &&
        (qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR ||
         (store->replication_principal_id != 0u &&
          qihse_user_get_id(user) == store->replication_principal_id));
}

static bool ct_state_write(qihse_kv_store_t* store) {
    if (!store || store->memory_snapshot) return false;
    if (aimem_durability_test_fail_once("ct-state-before-publish")) {
        errno = EIO;
        return false;
    }
    kv_ct_disk_t disk;
    memset(&disk, 0, sizeof(disk));
    memcpy(disk.magic, "QCTST002", 8u);
    disk.mode = store->ct_mode;
    disk.fence_state = store->ct_fence_state;
    disk.fence_first = store->ct_fence_first;
    disk.fence_last = store->ct_fence_last;
    disk.tenant_id = store->ct_tenant_id;
    disk.tenant_policy = (uint32_t)store->ct_tenant_policy;
    disk.baseline_lsn = store->ct_baseline_lsn;
    memcpy(disk.baseline_digest, store->ct_baseline_digest,
           sizeof(disk.baseline_digest));
    disk.baseline_sealed = store->ct_baseline_sealed ? 1u : 0u;
    disk.durable_lsn = store->ct_durable_lsn;
    disk.ack_lsn = store->ct_ack_lsn;
    disk.retained_bytes = store->ct_retained_bytes;
    disk.limit_bytes = store->ct_limit_bytes;
    disk.fence_cut_position = store->ct_fence_cut_position;
    memcpy(disk.source_id, store->ct_source_id, sizeof(disk.source_id));
    memcpy(disk.target_id, store->ct_target_id, sizeof(disk.target_id));
    memcpy(disk.successor_id, store->ct_successor_id, sizeof(disk.successor_id));
    memcpy(disk.generation, store->ct_generation, sizeof(disk.generation));
    memcpy(disk.transfer_id, store->ct_transfer_id, sizeof(disk.transfer_id));
    disk.transfer_phase = store->ct_transfer_phase;
    memcpy(disk.transfer_source_id, store->ct_transfer_source_id,
           sizeof(disk.transfer_source_id));
    memcpy(disk.transfer_source_generation,
           store->ct_transfer_source_generation,
           sizeof(disk.transfer_source_generation));
    disk.transfer_source_cut = store->ct_transfer_source_cut;
    disk.transfer_target_position = store->ct_transfer_target_position;
    memcpy(disk.transfer_image_digest, store->ct_transfer_image_digest, 32u);
    memcpy(disk.transfer_group_digest, store->ct_transfer_group_digest, 32u);
    memcpy(disk.transfer_range_digest, store->ct_transfer_range_digest, 32u);
    memcpy(disk.owner_token, store->ct_owner_token, sizeof(disk.owner_token));
    memcpy(disk.last_group_digest, store->ct_last_group_digest,
           sizeof(disk.last_group_digest));
    memcpy(disk.moved_slots, store->ct_moved_slots, sizeof(disk.moved_slots));
    disk.checksum = fnv1a64_update(14695981039346656037ULL, &disk,
                                  offsetof(kv_ct_disk_t, checksum));
    char path[4096], temp[8192]; FILE* f = NULL;
    if (!build_data_path(path, sizeof(path), "ct-state.bin") ||
        !atomic_file_begin(path, temp, sizeof(temp), &f)) return false;
    if (!fwrite_exact(&disk, 1u, sizeof(disk), f)) { fclose(f); unlink(temp); return false; }
    return atomic_file_commit(f, temp, path) && fsync_dir_path(get_qihse_data_dir());
}

static bool ct_state_read(qihse_kv_store_t* store, qihse_user_t* user,
                          bool legacy_bootstrap) {
    char path[4096];
    if (!build_data_path(path, sizeof(path), "ct-state.bin")) return false;
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    if (legacy_bootstrap || !ct_admin(user)) {
        close(fd); errno = EACCES; return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid != geteuid() ||
        (st.st_mode & 077) || st.st_nlink != 1) { close(fd); errno = EACCES; return false; }
    kv_ct_disk_t disk;
    bool ok = read(fd, &disk, sizeof(disk)) == (ssize_t)sizeof(disk);
    char extra;
    if (ok) ok = read(fd, &extra, 1u) == 0;
    close(fd);
    ok = ok && memcmp(disk.magic, "QCTST002", 8u) == 0 &&
        (disk.mode == 1u || disk.mode == 2u) &&
        disk.fence_state <= 4u && disk.fence_first <= disk.fence_last &&
        disk.baseline_sealed <= 1u &&
        disk.fence_last < QIHSE_CLUSTER_SLOT_COUNT &&
        disk.source_id[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.target_id[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.successor_id[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.generation[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.transfer_id[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.transfer_source_id[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.transfer_source_generation[QIHSE_KV_CT_ID_MAX] == '\0' &&
        disk.transfer_phase <= 2u &&
        ct_id_valid(disk.source_id) && ct_id_valid(disk.generation) &&
        (disk.mode != 1u || ct_id_valid(disk.successor_id)) &&
        (disk.mode != 2u || ct_id_valid(disk.target_id)) &&
        (disk.mode != 2u || (disk.tenant_policy == QIHSE_KV_CT_TENANT_EXACT ||
                             disk.tenant_policy == QIHSE_KV_CT_TENANT_SYSTEM_ALL)) &&
        (!disk.fence_state || ct_id_valid(disk.transfer_id)) &&
        (!disk.transfer_phase ||
         (disk.mode == 1u && disk.fence_state == 1u &&
          ct_id_valid(disk.transfer_source_id) &&
          ct_id_valid(disk.transfer_source_generation))) &&
        disk.checksum == fnv1a64_update(14695981039346656037ULL, &disk,
                                       offsetof(kv_ct_disk_t, checksum));
    if (!ok) { errno = EINVAL; return false; }
    store->ct_enabled = true;
    store->ct_system_principal = user;
    store->ct_mode = disk.mode;
    store->ct_fence_state = disk.fence_state;
    store->ct_fence_first = disk.fence_first;
    store->ct_fence_last = disk.fence_last;
    store->ct_tenant_id = disk.tenant_id;
    store->ct_tenant_policy = (qihse_kv_ct_tenant_policy_t)disk.tenant_policy;
    store->ct_baseline_lsn = disk.baseline_lsn;
    memcpy(store->ct_baseline_digest, disk.baseline_digest,
           sizeof(disk.baseline_digest));
    store->ct_baseline_sealed = disk.baseline_sealed != 0u;
    store->ct_durable_lsn = disk.durable_lsn;
    store->ct_ack_lsn = disk.ack_lsn;
    store->ct_retained_bytes = disk.retained_bytes;
    store->ct_limit_bytes = disk.limit_bytes;
    store->ct_fence_cut_position = disk.fence_cut_position;
    memcpy(store->ct_source_id, disk.source_id, sizeof(disk.source_id));
    memcpy(store->ct_target_id, disk.target_id, sizeof(disk.target_id));
    memcpy(store->ct_successor_id, disk.successor_id, sizeof(disk.successor_id));
    memcpy(store->ct_generation, disk.generation, sizeof(disk.generation));
    memcpy(store->ct_transfer_id, disk.transfer_id, sizeof(disk.transfer_id));
    store->ct_transfer_phase = disk.transfer_phase;
    memcpy(store->ct_transfer_source_id, disk.transfer_source_id,
           sizeof(disk.transfer_source_id));
    memcpy(store->ct_transfer_source_generation,
           disk.transfer_source_generation,
           sizeof(disk.transfer_source_generation));
    store->ct_transfer_source_cut = disk.transfer_source_cut;
    store->ct_transfer_target_position = disk.transfer_target_position;
    memcpy(store->ct_transfer_image_digest, disk.transfer_image_digest, 32u);
    memcpy(store->ct_transfer_group_digest, disk.transfer_group_digest, 32u);
    memcpy(store->ct_transfer_range_digest, disk.transfer_range_digest, 32u);
    memcpy(store->ct_owner_token, disk.owner_token, sizeof(disk.owner_token));
    memcpy(store->ct_last_group_digest, disk.last_group_digest,
           sizeof(disk.last_group_digest));
    memcpy(store->ct_moved_slots, disk.moved_slots, sizeof(disk.moved_slots));
    return true;
}

static bool ct_write_allowed(qihse_kv_store_t* store, qihse_user_t* user,
                             const char* key) {
    if (!store->ct_enabled) return true;
    if (store->ct_transfer_phase == 1u) { errno = EBUSY; return false; }
    if (!user || !qihse_auth_user_is_active(user) ||
        !kv_ct_scope || kv_ct_scope->store != store ||
        kv_ct_scope->principal != user) { errno = EACCES; return false; }
    if (key && !qihse_cluster_key_is_node_local(key)) {
        uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
        if ((store->ct_moved_slots[slot / 8u] & (1u << (slot % 8u))) ||
            (store->ct_fence_state == 1u &&
             slot >= store->ct_fence_first && slot <= store->ct_fence_last)) {
            errno = EBUSY; return false;
        }
    }
    return true;
}

/* Ordinary readers never materialize a primary value that the successor has
 * not durably acknowledged. A CT receiver serves reads only after a durable
 * promotion transition changes its mode to source and it reconciles. */
static bool ct_read_ready(qihse_kv_store_t* store) {
    if (!store->ct_enabled) return true;
    if (store->ct_mode != 1u || !store->ct_admitted ||
        store->ct_durable_lsn > store->ct_ack_lsn) {
        errno = EAGAIN;
        return false;
    }
    return true;
}

static bool ct_key_owned_for_read(qihse_kv_store_t* store, const char* key) {
    if (!store->ct_enabled || !key || qihse_cluster_key_is_node_local(key)) return true;
    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    return !(store->ct_moved_slots[slot / 8u] & (1u << (slot % 8u))) &&
        !(store->ct_fence_state == 1u &&
          store->ct_transfer_source_id[0] != '\0' &&
          slot >= store->ct_fence_first && slot <= store->ct_fence_last);
}

static bool ct_key_read_ready(qihse_kv_store_t* store, const char* key) {
    if (!store->ct_enabled) return true;
    if (store->ct_mode != 1u || !store->ct_admitted ||
        store->ct_durable_lsn > store->ct_ack_lsn) {
        errno = EAGAIN; return false;
    }
    if (!ct_key_owned_for_read(store, key)) {
        errno = EAGAIN;
        return false;
    }
    return true;
}

static bool ct_token_matches(qihse_kv_store_t* store,
    const unsigned char token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !token || !store->ct_enabled) return false;
    unsigned difference = 0u;
    for (size_t i = 0; i < QIHSE_KV_CT_TOKEN_BYTES; i++)
        difference |= token[i] ^ store->ct_owner_token[i];
    return difference == 0u;
}

static void ct_scope_note_seq(qihse_kv_store_t* store, uint64_t seq) {
    if (store->ct_enabled && store->ct_mode == 1u && kv_ct_scope &&
        kv_ct_scope->store == store && seq > kv_ct_scope->last_seq)
        kv_ct_scope->last_seq = seq;
}

bool qihse_kv_ct_owner_token_get(qihse_kv_store_t* store,
    qihse_user_t* principal, unsigned char out[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !out || !ct_admin(principal)) return false;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && !store->recovery_pending;
    if (ok) memcpy(out, store->ct_owner_token, QIHSE_KV_CT_TOKEN_BYTES);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_writer_scope_enter(qihse_kv_store_t* store,
    qihse_user_t* principal, const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    qihse_kv_ct_writer_scope_t** out_scope) {
    if (out_scope) *out_scope = NULL;
    if (!store || !principal || !owner_token || !out_scope || kv_ct_scope ||
        !qihse_auth_user_is_active(principal)) return false;
    kv_store_rdlock(store);
    unsigned mismatch = 0u;
    for (size_t i = 0; i < QIHSE_KV_CT_TOKEN_BYTES; i++)
        mismatch |= owner_token[i] ^ store->ct_owner_token[i];
    bool ok = store->ct_enabled && !store->recovery_pending && mismatch == 0u;
    if (ok && store->ct_mode == 1u && !store->ct_admitted) ok = false;
    kv_store_unlock(store);
    if (!ok) { errno = EACCES; return false; }
    qihse_kv_ct_writer_scope_t* scope = calloc(1u, sizeof(*scope));
    if (!scope) return false;
    scope->store = store;
    scope->principal = principal;
    kv_ct_scope = scope;
    *out_scope = scope;
    return true;
}

void qihse_kv_ct_writer_scope_leave(qihse_kv_ct_writer_scope_t* scope) {
    if (!scope || kv_ct_scope != scope) return;
    kv_ct_scope = scope->previous;
    free(scope);
}

bool qihse_kv_ct_writer_scope_finish(qihse_kv_ct_writer_scope_t* scope,
    uint32_t timeout_ms, uint64_t* out_last_seq) {
    if (out_last_seq) *out_last_seq = 0u;
    if (!scope || kv_ct_scope != scope || timeout_ms > 60000u) return false;
    qihse_kv_store_t* store = scope->store;
    uint64_t seq = scope->last_seq;
    if (out_last_seq) *out_last_seq = seq;
    kv_ct_scope = scope->previous;
    free(scope);
    if (seq == 0u) return true;
    struct timespec deadline;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return false;
    deadline.tv_sec += timeout_ms / 1000u;
    deadline.tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }
    if (pthread_mutex_lock(&store->ct_ack_lock) != 0) return false;
    int rc = 0;
    while (__atomic_load_n(&store->ct_ack_lsn, __ATOMIC_ACQUIRE) < seq && rc == 0)
        rc = pthread_cond_timedwait(&store->ct_ack_changed, &store->ct_ack_lock, &deadline);
    bool ok = __atomic_load_n(&store->ct_ack_lsn, __ATOMIC_ACQUIRE) >= seq;
    pthread_mutex_unlock(&store->ct_ack_lock);
    if (!ok) {
        kv_store_wrlock(store);
        store->ct_admitted = false;
        kv_store_unlock(store);
    }
    return ok;
}

/* The image can be empty (or older than this store's mutation history).
 * Keep its sequence floor outside the replaceable row set. */
static bool image_highwater_read(uint64_t* out) {
    char path[4096];
    if (!out || !build_data_path(path, sizeof(path), "restore-highwater.bin")) return false;
    *out = 0u;
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    char magic[5]; uint64_t seq = 0u, crc = 0u;
    bool ok = fread(magic, 1u, 5u, f) == 5u && memcmp(magic, "QRHW1", 5u) == 0 &&
        fread(&seq, sizeof(seq), 1u, f) == 1u && fread(&crc, sizeof(crc), 1u, f) == 1u &&
        fgetc(f) == EOF && !ferror(f) &&
        crc == fnv1a64_update(14695981039346656037ULL, &seq, sizeof(seq));
    fclose(f);
    if (ok) *out = seq;
    return ok;
}

static bool image_highwater_publish(uint64_t seq) {
    uint64_t prior = 0u;
    if (!image_highwater_read(&prior)) return false;
    if (prior > seq) seq = prior;
    char path[4096], tmp[8192]; FILE* f = NULL;
    if (!build_data_path(path, sizeof(path), "restore-highwater.bin") ||
        !atomic_file_begin(path, tmp, sizeof(tmp), &f)) return false;
    uint64_t crc = fnv1a64_update(14695981039346656037ULL, &seq, sizeof(seq));
    if (!fwrite_exact("QRHW1", 1u, 5u, f) || !fwrite_exact(&seq, sizeof(seq), 1u, f) ||
        !fwrite_exact(&crc, sizeof(crc), 1u, f)) { fclose(f); unlink(tmp); return false; }
    if (aimem_durability_test_fail_once("restore-highwater-commit")) {
        fclose(f); unlink(tmp); return false;
    }
    if (!atomic_file_commit(f, tmp, path)) return false;
    return !aimem_durability_test_fail_once("restore-highwater-dir-fsync") &&
           fsync_dir_path(get_qihse_data_dir());
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
    bool full_image;
    bool auth_bound;
    uint16_t required_classification;
    uint16_t required_sci;
} replica_install_meta_t;

static const char* replica_install_magic(const replica_install_meta_t* m) {
    if (m->auth_bound) return m->full_image ? "QRIL2" : "QRIM2";
    return m->full_image ? "QRIL1" : "QRIM1";
}

static uint64_t replica_install_meta_crc(const replica_install_meta_t* m) {
    uint64_t h = 14695981039346656037ULL;
    uint16_t pl = (uint16_t)strlen(m->peer), gl = (uint16_t)strlen(m->glob);
    h = fnv1a64_update(h, replica_install_magic(m), 5u);
    h = fnv1a64_update(h, &pl, sizeof(pl)); h = fnv1a64_update(h, &gl, sizeof(gl));
    h = fnv1a64_update(h, &m->source_seq, sizeof(m->source_seq));
    h = fnv1a64_update(h, &m->image_hash, sizeof(m->image_hash));
    if (m->auth_bound) {
        h = fnv1a64_update(h, &m->required_classification, sizeof(m->required_classification));
        h = fnv1a64_update(h, &m->required_sci, sizeof(m->required_sci));
    }
    h = fnv1a64_update(h, m->peer, pl); h = fnv1a64_update(h, m->glob, gl);
    return h;
}

static bool replica_install_meta_write(const char* path, const replica_install_meta_t* m) {
    char tmp[8192]; FILE* f = NULL;
    if (!m || (!m->full_image && (!cursor_id_valid(m->peer) || !cursor_id_valid(m->glob))) ||
        !atomic_file_begin(path, tmp, sizeof(tmp), &f)) return false;
    uint16_t pl = (uint16_t)strlen(m->peer), gl = (uint16_t)strlen(m->glob);
    uint64_t crc = replica_install_meta_crc(m);
    bool ok = fwrite_exact(replica_install_magic(m), 1u, 5u, f) && fwrite_exact(&pl, sizeof(pl), 1u, f) &&
        fwrite_exact(&gl, sizeof(gl), 1u, f) &&
        fwrite_exact(&m->source_seq, sizeof(m->source_seq), 1u, f) &&
        fwrite_exact(&m->image_hash, sizeof(m->image_hash), 1u, f) &&
        (!m->auth_bound ||
         (fwrite_exact(&m->required_classification, sizeof(m->required_classification), 1u, f) &&
          fwrite_exact(&m->required_sci, sizeof(m->required_sci), 1u, f))) &&
        fwrite_exact(m->peer, 1u, pl, f) && fwrite_exact(m->glob, 1u, gl, f) &&
        fwrite_exact(&crc, sizeof(crc), 1u, f);
    if (!ok) { fclose(f); unlink(tmp); return false; }
    if (!atomic_file_commit(f, tmp, path)) return false;
    if (aimem_durability_test_fail_once("restore-intent-dir-fsync")) return false;
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
    char magic[5] = {0}; uint16_t pl = 0u, gl = 0u; uint64_t crc = 0u;
    bool ok = fread(magic, 1u, sizeof(magic), f) == sizeof(magic);
    m->auth_bound = ok && (memcmp(magic, "QRIM2", sizeof(magic)) == 0 ||
                          memcmp(magic, "QRIL2", sizeof(magic)) == 0);
    m->full_image = ok && (memcmp(magic, "QRIL1", sizeof(magic)) == 0 ||
                          memcmp(magic, "QRIL2", sizeof(magic)) == 0);
    ok = ok && (m->auth_bound || memcmp(magic, "QRIM1", sizeof(magic)) == 0 ||
                memcmp(magic, "QRIL1", sizeof(magic)) == 0) &&
        fread(&pl, sizeof(pl), 1u, f) == 1u && fread(&gl, sizeof(gl), 1u, f) == 1u &&
        fread(&m->source_seq, sizeof(m->source_seq), 1u, f) == 1u &&
        fread(&m->image_hash, sizeof(m->image_hash), 1u, f) == 1u &&
        (!m->auth_bound ||
         (fread(&m->required_classification, sizeof(m->required_classification), 1u, f) == 1u &&
          fread(&m->required_sci, sizeof(m->required_sci), 1u, f) == 1u)) &&
        pl <= KV_REPLICA_CURSOR_MAX_ID &&
        gl <= KV_REPLICA_CURSOR_MAX_ID &&
        fread(m->peer, 1u, pl, f) == pl && fread(m->glob, 1u, gl, f) == gl &&
        fread(&crc, sizeof(crc), 1u, f) == 1u && fgetc(f) == EOF;
    fclose(f);
    if (pl > KV_REPLICA_CURSOR_MAX_ID || gl > KV_REPLICA_CURSOR_MAX_ID) return false;
    m->peer[pl] = '\0'; m->glob[gl] = '\0';
    if (!m->auth_bound) {
        /* Legacy intents did not retain the authority needed for old rows. */
        m->required_classification = UINT16_MAX;
        m->required_sci = UINT16_MAX;
    }
    return ok && (m->full_image ? (pl == 0u && gl == 0u) :
                  (cursor_id_valid(m->peer) && cursor_id_valid(m->glob))) &&
           crc == replica_install_meta_crc(m);
}

static bool copy_file_atomic_hash(const char* source, const char* destination,
                                  uint64_t* out_hash, qihse_user_t* user) {
    if (!user || !qihse_auth_user_is_active(user)) { errno = EACCES; return false; }
    int fd = open_secure_read(source);
    if (fd < 0) return false;
    FILE* in = fdopen(fd, "rb");
    if (!in) { close(fd); return false; }
    char tmp[8192]; FILE* out = NULL;
    if (!atomic_file_begin(destination, tmp, sizeof(tmp), &out)) { fclose(in); return false; }
    uint8_t* buffer = malloc(65536u);
    if (!buffer) { fclose(in); fclose(out); unlink(tmp); return false; }
    uint64_t hash = 14695981039346656037ULL; bool ok = true;
    for (;;) {
        size_t n = fread(buffer, 1u, 65536u, in);
        if (n) {
            hash = fnv1a64_update(hash, buffer, n);
            if (!fwrite_exact(buffer, 1u, n, out)) { ok = false; break; }
        }
        if (n < 65536u) {
            if (ferror(in)) ok = false;
            break;
        }
    }
    free(buffer);
    fclose(in);
    if (!ok) { fclose(out); unlink(tmp); return false; }
    if (!atomic_file_commit(out, tmp, destination)) return false;
    if (out_hash) *out_hash = hash;
    return true;
}

static bool parse_snapshot_into_trie(const char* filepath, qihse_user_t* user,
                                     qihse_trinary_trie_t** out_trie, size_t* out_usage,
                                     uint64_t* out_max_seq);

static bool replica_install_recover_image(const char* dir, qihse_user_t* user) {
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
        if (unlink(image_path) != 0 && errno != ENOENT) return false;
        if (unlink(candidate) != 0 && errno != ENOENT) return false;
        /* Absence may be the result of a prior unlink whose directory fsync
         * failed. Fence that absence before accepting any new WAL writes. */
        return fsync_dir_path(dir);
    }
    if (!user || !qihse_auth_user_is_active(user) ||
        !qihse_auth_can_access(user, meta.required_classification, meta.required_sci)) {
        errno = EACCES; return false;
    }
    uint64_t image_hash = 0u;
    (void)unlink(candidate);
    if (!copy_file_atomic_hash(image_path, candidate, &image_hash, user)) return false;
    if (image_hash != meta.image_hash) { (void)unlink(candidate); return false; }
    qihse_trinary_trie_t* checked = NULL; uint64_t image_seq = 0u;
    if (!parse_snapshot_into_trie(candidate, user, &checked, NULL, &image_seq)) return false;
    if (meta.source_seq > image_seq) image_seq = meta.source_seq;
    qihse_trinary_trie_destroy(checked);
    replica_install_test_crash_point("before-publish");
    if (!qihse_auth_user_is_active(user) ||
        aimem_durability_test_fail_once("restore-sstable-rename") ||
        rename(candidate, sstable0) != 0 ||
        aimem_durability_test_fail_once("restore-publish-dir-fsync") || !fsync_dir_path(dir))
        return false;
    replica_install_test_crash_point("sst-published");
    DIR* d = opendir(dir);
    if (!d) return false;
    struct dirent* ent;
    bool ok = true;
    for (;;) {
        errno = 0;
        ent = readdir(d);
        if (!ent) { if (errno != 0) ok = false; break; }
        if (strncmp(ent->d_name, "sstable_", 8u) != 0) continue;
        char* end = NULL; long id = strtol(ent->d_name + 8u, &end, 10);
        if (!end || strcmp(end, ".db") != 0 || id <= 0 || id >= INT_MAX) continue;
        char path[4096]; int n = snprintf(path, sizeof(path), "%s%s", dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path) ||
            aimem_durability_test_fail_once("restore-sstable-unlink") || unlink(path) != 0) { ok = false; break; }
    }
    if (closedir(d) != 0) ok = false;
    if (!ok) return false;
    replica_install_test_crash_point("sst-pruned");
    char tmp[8192]; FILE* empty_wal = NULL;
    if (!atomic_file_begin(wal_path, tmp, sizeof(tmp), &empty_wal)) return false;
    if (aimem_durability_test_fail_once("restore-wal-rename")) {
        fclose(empty_wal); unlink(tmp); return false;
    }
    if (!atomic_file_commit(empty_wal, tmp, wal_path)) return false;
    if (aimem_durability_test_fail_once("restore-wal-dir-fsync")) return false;
    return fsync_dir_path(dir) && image_highwater_publish(image_seq);
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

static bool replica_install_finish_recovery(qihse_kv_store_t* store, const char* dir,
                                             qihse_user_t* user) {
    char meta_path[4096], image_path[4096];
    if (!dir) return false;
    int a = snprintf(meta_path, sizeof(meta_path), "%sreplica-install.meta", dir);
    int b = snprintf(image_path, sizeof(image_path), "%sreplica-install.image", dir);
    if (a < 0 || (size_t)a >= sizeof(meta_path) || b < 0 || (size_t)b >= sizeof(image_path)) return false;
    replica_install_meta_t meta; bool present = false;
    if (!replica_install_meta_read(meta_path, &meta, &present)) return false;
    if (!present) return true;
    if (!user || !qihse_auth_user_is_active(user)) { errno = EACCES; return false; }
    if (!meta.full_image) {
        char marker[48]; replica_snapshot_marker_namespace(meta.glob, marker);
        if (!replica_cursor_force_set(store, meta.peer, meta.glob, meta.source_seq)) return false;
        replica_install_test_crash_point("cursor-durable");
        if (!replica_cursor_force_set(store, meta.peer, marker, 1u)) return false;
        replica_install_test_crash_point("marker-durable");
    }
    if (aimem_durability_test_fail_once("restore-intent-unlink") || unlink(meta_path) != 0 ||
        aimem_durability_test_fail_once("restore-cleanup-dir-fsync") || !fsync_dir_path(dir)) return false;
    replica_install_test_crash_point("journal-removed");
    if (unlink(image_path) != 0 && errno != ENOENT) return false;
    return !aimem_durability_test_fail_once("restore-image-cleanup-dir-fsync") && fsync_dir_path(dir);
}

/* Replica-plane operations (cursors, snapshot install, record apply) may be
 * performed by the Operator or by the dedicated replication service
 * principal (registered via qihse_kv_store_set_replication_principal_id).
 * The RESP engine deliberately maps the pinned QKP replication peer to a
 * non-Operator principal, so these checks must not require OPERATOR. */
static bool replica_principal_ok(qihse_kv_store_t* store, qihse_user_t* principal) {
    if (!store || store->memory_snapshot || __atomic_load_n(&store->recovery_pending, __ATOMIC_ACQUIRE) ||
        !principal || !qihse_auth_user_is_active(principal)) return false;
    if (qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR) return true;
    return store && __atomic_load_n(&store->replication_principal_id,
                                    __ATOMIC_ACQUIRE) != 0u &&
           qihse_user_get_id(principal) ==
               __atomic_load_n(&store->replication_principal_id,
                               __ATOMIC_ACQUIRE);
}

bool qihse_kv_replica_cursor_get(qihse_kv_store_t* store, const char* peer_id,
                                const char* namespace_id, qihse_user_t* principal,
                                uint64_t* out_seq) {
    if (!store || !cursor_id_valid(peer_id) || !cursor_id_valid(namespace_id) ||
        !replica_principal_ok(store, principal) || !out_seq) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending) { kv_store_unlock(store); return false; }
    kv_replica_cursor_t* e = cursor_find(store, peer_id, namespace_id);
    *out_seq = e ? e->seq : 0u;
    kv_store_unlock(store);
    return true;
}

static bool replica_cursor_advance_locked(qihse_kv_store_t* store, const char* peer_id,
                                    const char* namespace_id, uint64_t seq,
                                    qihse_user_t* principal) {
    if (!store || !cursor_id_valid(peer_id) || !cursor_id_valid(namespace_id) ||
        !replica_principal_ok(store, principal) || store->bulk_load_mode) return false;
    kv_replica_cursor_t* e = cursor_find(store, peer_id, namespace_id);
    if (e && seq < e->seq) return false;
    if (e && seq == e->seq) {
        /* The previous call may have renamed the cursor file successfully but
         * failed its directory fsync.  Retrying the same sequence must retry
         * both durable-store and cursor-directory synchronization. */
        return kv_sync_store_locked(store) &&
               fsync_dir_path(get_qihse_data_dir());
    }
    uint32_t count = 0u;
    for (kv_replica_cursor_t* p = store->replica_cursors; p; p = p->next) count++;
    if (!e && count >= KV_REPLICA_CURSOR_MAX_ITEMS) return false;

    /* Ensure every applied record preceding this checkpoint survives a crash
     * before a caller can ACK the new cursor. */
    if (!kv_sync_store_locked(store)) return false;

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

bool qihse_kv_replica_cursor_advance(qihse_kv_store_t* store, const char* peer_id,
                                    const char* namespace_id, uint64_t seq,
                                    qihse_user_t* principal) {
    if (!store) return false;
    kv_store_wrlock(store);
    bool ok = replica_cursor_advance_locked(store, peer_id, namespace_id, seq, principal);
    kv_store_unlock(store);
    return ok;
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

/* QKV5 is one independently checksummed frame. A torn frame is discarded by
 * recovery before either member is materialized. The receipt is a normal SET
 * after replay, so SST flush, replication deltas and compaction need no new
 * record type. Header bytes 44..47 are reserved and must be zero. */
static uint64_t wal_delete_receipt_crc(const unsigned char hdr[48],
                                       const char* source_key, size_t source_len,
                                       const char* receipt_key, size_t receipt_len,
                                       const char* receipt, size_t receipt_len_bytes) {
    uint64_t h = fnv1a64_update(14695981039346656037ULL, hdr, 36u);
    h = fnv1a64_update(h, hdr + 44u, 4u);
    h = fnv1a64_update(h, source_key, source_len);
    h = fnv1a64_update(h, receipt_key, receipt_len);
    return fnv1a64_update(h, receipt, receipt_len_bytes);
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

typedef struct {
    qihse_user_t* user;
    bool legacy_bootstrap;
    size_t* remaining_snapshot_bytes; /* Optional bounded stream allocation budget. */
    size_t* remaining_snapshot_records;
} kv_read_context_t;

static bool kv_read_allowed(const kv_read_context_t* context, uint16_t classification,
                            uint16_t sci) {
    if (context && context->legacy_bootstrap) return true;
    if (context && context->user && qihse_auth_user_is_active(context->user) &&
        qihse_auth_can_access(context->user, classification, sci)) return true;
    errno = EACCES;
    return false;
}

static int disk_record_read_context(FILE* f, kv_disk_record_t* r,
                                    const kv_read_context_t* context) {
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
    if (classif > UINT16_MAX || sci > UINT16_MAX) return -1;
    if (!kv_read_allowed(context, (uint16_t)classif, (uint16_t)sci)) return -2;
    if (key_len == 0u || key_len > KV_MAX_KEY_LEN || val_len > KV_MAX_VALUE_LEN ||
        classif > UINT16_MAX || sci > UINT16_MAX || (flags & ~KV_ALLOWED_FLAGS) != 0u) return -1;
    if ((flags & KV_FLAG_TOMBSTONE) != 0u && val_len != 0u) return -1;
    if (context && context->remaining_snapshot_records) {
        if (*context->remaining_snapshot_records == 0u) { errno = E2BIG; return -4; }
        --*context->remaining_snapshot_records;
    }
    if (context && context->remaining_snapshot_bytes) {
        size_t bytes = hlen + key_len + val_len + 1u;
        if (bytes > *context->remaining_snapshot_bytes) { errno = EFBIG; return -3; }
        *context->remaining_snapshot_bytes -= bytes;
    }
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

static int disk_record_read(FILE* f, kv_disk_record_t* r) {
    const kv_read_context_t context = { .legacy_bootstrap = true };
    return disk_record_read_context(f, r, &context);
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
static int disk_record_read_header(FILE* f, kv_disk_record_t* r,
                                   const kv_read_context_t* context) {
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
    if (!kv_read_allowed(context, (uint16_t)classif, (uint16_t)sci)) return -2;
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
    if (aimem_durability_test_fail_once("sstable-record-write") ||
        !disk_record_write(ctx->f, key, p)) { ctx->ok = false; return false; }
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

static bool fsync_dir_path(const char* dir);

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
    /* The SST name must be durable BEFORE rotating away a WAL that may
     * contain a completed delete+receipt pair. Otherwise a power loss could
     * preserve the empty WAL rename but lose the SST rename. */
    if (!fsync_dir_path(dir)) return false;
    qihse_trinary_trie_t* replacement = qihse_trinary_trie_create();
    if (!replacement) { unlink(sst_path); return false; }
    qihse_trinary_trie_t* old = store->trie;
    store->trie = replacement;
    store->mem_usage = 0u;
    store->sstable_counter++;
    store->sstable_live_count++;
    qihse_trinary_trie_destroy(old);
    if (!store->ct_enabled) (void)rotate_wal_empty(store);
    if (store->sstable_live_count >= KV_SSTABLE_HARD_CEILING) {
        int32_t before = store->sstable_counter;
        if (compact_sstables_stream(store) && before > 1) {
            fprintf(stderr,
                    "qihse-kv: hard-ceiling compaction fired at %d sstable(s); "
                    "the sweep is not keeping up (cadence or thread failure)\n",
                    before);
        }
    }
    return true;
}

static void flush_wal_buffer(qihse_kv_store_t* store) {
    if (!store || !store->wal_fd || store->wal_unflushed_bytes == 0u) return;
    if (fflush(store->wal_fd) == 0) store->wal_unflushed_bytes = 0u;
}

static bool wal_append(qihse_kv_store_t* store, uint8_t op, const char* key, const char* value,
                       uint64_t expire_time_ms, uint16_t classification,
                       uint16_t sci_compartment, uint8_t flags,
                       uint64_t change_seq) {
    if (!store || !key) return false;
    if (store->bulk_load_mode) return true;
    if (!store->wal_fd) return false;
    size_t key_len_sz = strlen(key), val_len_sz = value ? strlen(value) : 0u;
    if (key_len_sz == 0u || key_len_sz > KV_MAX_KEY_LEN || val_len_sz > KV_MAX_VALUE_LEN) return false;
    if (op != KV_WAL_OP_SET && op != KV_WAL_OP_DEL) return false;
    if ((flags & ~KV_ALLOWED_FLAGS) != 0u) return false;
    uint16_t key_len = (uint16_t)key_len_sz;
    uint32_t val_len = (uint32_t)val_len_sz;
    if (change_seq == 0u) return false;
    /* QKV4 carries the stable local mutation LSN. QKV2 remains readable; QKV3
     * remains the replica frame. */
    unsigned char hdr[40];
    memcpy(hdr + 0, KV_WAL_MAGIC_LOCAL_SEQ, 4u);
    hdr[4] = op;
    hdr[5] = flags;
    memcpy(hdr + 6,  &key_len, 2u);
    memcpy(hdr + 8,  &val_len, 4u);
    memcpy(hdr + 12, &classification, 2u);
    memcpy(hdr + 14, &sci_compartment, 2u);
    memcpy(hdr + 16, &expire_time_ms, 8u);
    memcpy(hdr + 24, &change_seq, 8u);
    uint64_t seq_crc = wal_replica_record_crc(op, flags, key_len, val_len,
        classification, sci_compartment, expire_time_ms, change_seq,
        key, value ? value : "");
    memcpy(hdr + 32, &seq_crc, 8u);
    if (aimem_durability_test_fail_once("wal-partial-header")) {
        (void)fwrite(hdr, 1u, sizeof(hdr) / 2u, store->wal_fd);
        return false;
    }
    bool ok = !aimem_durability_test_fail_once("wal-write-header") &&
              fwrite_exact(hdr, 1u, sizeof(hdr), store->wal_fd) &&
              !aimem_durability_test_fail_once("wal-write-key") &&
              fwrite_exact(key, 1u, key_len, store->wal_fd) &&
              !aimem_durability_test_fail_once("wal-write-value") &&
              fwrite_exact(value ? value : "", 1u, val_len, store->wal_fd);
    if (!ok) return false;
    store->wal_unflushed_bytes += sizeof(hdr) + key_len + val_len;
    if (!store->durable_batch_mode && store->wal_unflushed_bytes >= WAL_BUFFER_FLUSH_THRESHOLD) flush_wal_buffer(store);
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
    if (!store->durable_batch_mode && store->wal_unflushed_bytes >= WAL_BUFFER_FLUSH_THRESHOLD) flush_wal_buffer(store);
    return true;
}

/* QKV6 is the canonical WAL frame in CT mode. Each group is persisted before
 * any contained row is exposed in the memtable; replay reconstructs both
 * rows and the dense stream cursor from the same complete frame. */
static bool ct_append_group_locked(qihse_kv_store_t* store,
                                   qihse_user_t* principal,
                                   qihse_kv_ct_group_t* group) {
    if (!store || !store->ct_enabled || !store->wal_fd || !group ||
        group->count == 0u || group->count > QIHSE_KV_CT_MAX_GROUP_RECORDS ||
        store->recovery_pending) return false;
    qihse_kv_ct_tenant_policy_t policy = store->ct_tenant_policy;
    uint32_t tenant = store->ct_tenant_id;
    qihse_user_t* codec_principal = principal;
    if (store->ct_mode == 1u) {
        /* A source stream may contain multiple resource tenants. Keep one
         * canonical policy for every frame so replay and export cannot
         * disagree with capture. The mutator has already passed its own
         * label and key authorization checks before this call. */
        codec_principal = store->ct_system_principal;
        if (!ct_admin(codec_principal)) return false;
        policy = QIHSE_KV_CT_TENANT_SYSTEM_ALL;
        tenant = 0u;
    }
    size_t frame_bytes = 0u;
    unsigned char digest[32];
    if (!qihse_ct_codec_encoded_size(codec_principal, policy, tenant, store->ct_mode,
                                     group, (size_t)store->ct_limit_bytes, &frame_bytes) ||
        !qihse_ct_codec_group_digest(codec_principal, policy, tenant, group, digest) ||
        frame_bytes > store->ct_limit_bytes ||
        store->ct_retained_bytes > store->ct_limit_bytes - frame_bytes) {
        errno = ENOSPC; return false;
    }
    size_t written = 0u;
    uint8_t mode = store->ct_mode;
    if (!qihse_ct_codec_write(store->wal_fd, codec_principal, policy, tenant,
                              mode, group, (size_t)store->ct_limit_bytes, &written) ||
        written != frame_bytes || fflush(store->wal_fd) != 0 ||
        fdatasync(fileno(store->wal_fd)) != 0) {
        store->recovery_pending = true;
        return false;
    }
    uint64_t old_position = store->ct_durable_lsn;
    uint64_t old_bytes = store->ct_retained_bytes;
    unsigned char old_digest[32];
    memcpy(old_digest, store->ct_last_group_digest, sizeof(old_digest));
    store->ct_durable_lsn = group->stream_position;
    store->ct_retained_bytes += frame_bytes;
    memcpy(store->ct_last_group_digest, digest, sizeof(digest));
    if (aimem_durability_test_fail_once("ct-after-group-fsync") ||
        !ct_state_write(store)) {
        store->ct_durable_lsn = old_position;
        store->ct_retained_bytes = old_bytes;
        memcpy(store->ct_last_group_digest, old_digest, sizeof(old_digest));
        store->recovery_pending = true;
        return false;
    }
    store->wal_unflushed_bytes = 0u;
    return true;
}

static bool ct_resource_tenant(const char* key, uint32_t actor_tenant,
                               uint32_t* out) {
    if (!key || !out) return false;
    if (key[0] == 't' && key[1] == ':') {
        const char* p = key + 2;
        uint64_t value = 0u;
        if (*p < '0' || *p > '9') return false;
        while (*p >= '0' && *p <= '9') {
            value = value * 10u + (unsigned)(*p++ - '0');
            if (value > UINT32_MAX) return false;
        }
        if (*p != '/' || value == 0u) return false;
        if (actor_tenant != 0u && actor_tenant != value) return false;
        *out = (uint32_t)value;
        return true;
    }
    if (actor_tenant != 0u && strncmp(key, "commons/", 8u) != 0) return false;
    *out = 0u;
    return true;
}

static bool ct_source_record(qihse_kv_store_t* store, qihse_user_t* user,
                             const char* key, const char* value, uint64_t seq,
                             uint64_t expiry, uint16_t classification,
                             uint16_t sci, bool tombstone, bool dry_run,
                             qihse_kv_ct_actor_t actor_kind) {
    bool system_expiry = store && actor_kind == QIHSE_KV_CT_ACTOR_EXPIRY &&
        user == store->ct_system_principal && ct_admin(user);
    if (!store || !user || !key || !store->ct_enabled || store->ct_mode != 1u ||
        !store->ct_admitted ||
        (!system_expiry && !ct_write_allowed(store, user, key)) ||
        store->ct_durable_lsn == UINT64_MAX) return false;
    if (system_expiry) {
        uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
        if ((store->ct_moved_slots[slot / 8u] & (1u << (slot % 8u))) ||
            (store->ct_fence_state == 1u &&
             slot >= store->ct_fence_first && slot <= store->ct_fence_last))
            return false;
    }
    uint32_t tenant = 0u;
    uint32_t actor_tenant = qihse_user_get_tenant_id(user);
    if (!ct_resource_tenant(key, actor_tenant, &tenant)) return false;
    qihse_kv_ct_record_t record = {
        .key = (char*)key, .value = tombstone ? NULL : (char*)value,
        .change_seq = seq, .expire_time_ms = expiry,
        .actor_id = qihse_user_get_id(user),
        .actor_tenant_id = actor_tenant, .resource_tenant_id = tenant,
        .classification = classification, .sci_compartment = sci,
        .actor_kind = actor_kind, .tombstone = tombstone
    };
    qihse_kv_ct_group_t group = {0};
    snprintf(group.source_id, sizeof(group.source_id), "%s", store->ct_source_id);
    snprintf(group.generation, sizeof(group.generation), "%s", store->ct_generation);
    group.stream_position = store->ct_durable_lsn + 1u;
    group.first_seq = group.last_seq = seq;
    group.records = &record;
    group.count = 1u;
    if (dry_run) {
        size_t bytes = 0u;
        return ct_admin(store->ct_system_principal) &&
            qihse_ct_codec_encoded_size(store->ct_system_principal,
                                         QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
                                         1u, &group,
                                         (size_t)store->ct_limit_bytes, &bytes) &&
            bytes <= store->ct_limit_bytes &&
            store->ct_retained_bytes <= store->ct_limit_bytes - bytes;
    }
    if (!ct_append_group_locked(store, user, &group)) return false;
    ct_scope_note_seq(store, group.stream_position);
    return true;
}

bool qihse_kv_ct_receiver_apply(qihse_kv_store_t* store, qihse_user_t* principal,
    const qihse_kv_ct_group_t* group, uint64_t* out_durable_cursor) {
    if (out_durable_cursor) *out_durable_cursor = 0u;
    if (!store || !group || !out_durable_cursor ||
        !ct_replication_principal(store, principal) ||
        !group->records || group->count == 0u ||
        group->count > QIHSE_KV_CT_MAX_GROUP_RECORDS) return false;
    kv_store_wrlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 2u &&
        store->ct_baseline_sealed && !store->recovery_pending &&
        !store->memory_snapshot &&
        strcmp(group->source_id, store->ct_source_id) == 0 &&
        strcmp(group->generation, store->ct_generation) == 0 &&
        group->stream_position != 0u &&
        group->first_seq == group->records[0].change_seq &&
        group->last_seq == group->records[group->count - 1u].change_seq;
    if (!ok) goto done;
    ok = false;
    unsigned char digest[32];
    if (!qihse_ct_codec_group_digest(principal, store->ct_tenant_policy,
                                     store->ct_tenant_id, group, digest)) goto done;
    if (group->stream_position == store->ct_durable_lsn) {
        unsigned difference = 0u;
        for (size_t i = 0; i < sizeof(digest); i++)
            difference |= digest[i] ^ store->ct_last_group_digest[i];
        ok = difference == 0u;
        if (ok) *out_durable_cursor = store->ct_durable_lsn;
        goto done;
    }
    if (group->stream_position != store->ct_durable_lsn + 1u) goto done;
    uint64_t previous_seq = 0u;
    for (size_t i = 0; i < group->count; i++) {
        const qihse_kv_ct_record_t* row = &group->records[i];
        if (!row->key || !row->change_seq || row->change_seq <= previous_seq ||
            (row->tombstone ? (row->value != NULL || row->expire_time_ms != 0u) :
                              row->value == NULL) ||
            !qihse_auth_can_access(principal, row->classification,
                                   row->sci_compartment) ||
            (store->ct_tenant_policy == QIHSE_KV_CT_TENANT_EXACT &&
             row->resource_tenant_id != store->ct_tenant_id)) goto done;
        uint32_t from_key = 0u;
        if (!ct_resource_tenant(row->key, row->actor_tenant_id, &from_key) ||
            from_key != row->resource_tenant_id) goto done;
        if (store->ct_fence_state == 1u ||
            store->ct_moved_slots[qihse_cluster_key_slot(row->key, strlen(row->key)) / 8u]) {
            uint16_t slot = qihse_cluster_key_slot(row->key, strlen(row->key));
            if ((store->ct_moved_slots[slot / 8u] & (1u << (slot % 8u))) ||
                (store->ct_fence_state == 1u &&
                 slot >= store->ct_fence_first && slot <= store->ct_fence_last)) goto done;
        }
        kv_lookup_result_t old;
        kv_lookup_state_t state = logical_lookup(store, row->key, &old);
        if (state == KV_LOOKUP_ERROR) goto done;
        if (state == KV_LOOKUP_LIVE || state == KV_LOOKUP_DEAD) {
            bool allowed = qihse_auth_can_access(principal, old.classification,
                                                  old.sci_compartment) &&
                row->classification >= old.classification &&
                (row->sci_compartment & old.sci_compartment) == old.sci_compartment &&
                old.change_seq < row->change_seq;
            lookup_result_free(&old);
            if (!allowed) goto done;
        } else lookup_result_free(&old);
        previous_seq = row->change_seq;
    }
    if (!ct_append_group_locked(store, principal, (qihse_kv_ct_group_t*)group)) goto done;
    for (size_t i = 0; i < group->count; i++) {
        const qihse_kv_ct_record_t* row = &group->records[i];
        if (!insert_internal(store, row->key, row->tombstone ? "" : row->value,
                             row->expire_time_ms, row->classification,
                             row->sci_compartment,
                             row->tombstone ? KV_FLAG_TOMBSTONE : 0u,
                             row->change_seq)) {
            store->recovery_pending = true;
            goto done;
        }
        kv_change_seq_floor(store, row->change_seq);
    }
    *out_durable_cursor = group->stream_position;
    ok = true;
done:
    kv_store_unlock(store);
    return ok;
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

static void kv_projection_epoch_advance(qihse_kv_store_t* store) {
    /* Wrapping would make a stale generation indistinguishable from a fresh
     * one. Fail closed rather than silently reusing a cursor. */
    if (__atomic_add_fetch(&store->projection_epoch, 1u, __ATOMIC_RELEASE) == 0u) abort();
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
    store->sstable_live_count = 0u;
    sst_meta_index_reset(store);
    sst_fd_cache_clear(store);
    kv_projection_epoch_advance(store);
    return true;
}

/* Compact SSTables once more than this many have accumulated, even if the
 * expiry scan found nothing — bounds file count and reclaims stale copies. */
#define KV_SSTABLE_COMPACT_THRESHOLD 16


static bool sst_index_load_file(qihse_kv_store_t* store, const char* path, int32_t sstable_id,
                                const kv_read_context_t* context);

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
 * all older copies in older files filtered out.  A degraded index cannot
 * answer that question, so the first occurrence of a key while scanning
 * newest-first is used instead: the result is identical either way.  Tombstoned/expired records
 * and keys shadowed by a newer memtable entry are skipped.  Values are read
 * (the callback receives them) but nothing is merged into RAM: memory stays
 * O(keys) only for the temporary membership set used while the metadata index
 * is degraded.
 *
 * `include_tombstones` and `include_expired` are used by the owner recovery
 * snapshot: those dead states are needed to avoid turning a retained delete
 * into an apparent absence. Existing callers keep the default live-only or
 * tombstone-only behavior.
 *
 * Returns 1 when the scan completed, 0 when the callback asked to stop,
 * -1 on error.
 *
 * Streaming compaction needs an index only to decide which copy of a key is
 * newest.  Scanning newest file first answers that without one: the first
 * occurrence of a key is its newest copy.  When the metadata index is absent
 * or degraded we therefore track seen keys in a temporary membership set, so
 * compaction still runs and can rebuild a healthy index afterwards.  A
 * degraded index must never block the merge that repairs it. */
static int sst_foreach_newest(qihse_kv_store_t* store, bool include_tombstones,
                              bool include_expired, kv_sst_record_cb cb, void* ud) {
    if (!store || !store->trie || !cb) return -1;
    const bool index_usable = store->sst_meta && !store->sst_meta->degraded;
    sst_meta_index_t* seen = NULL;
    if (!index_usable) {
        seen = sst_meta_index_create();
        if (!seen) return -1;
    }
    const char* dir = get_qihse_data_dir();
    if (!dir) { sst_meta_index_destroy(seen); return -1; }
    uint64_t now = current_time_ms();
    for (int sid = store->sstable_counter - 1; sid >= 0; sid--) {
        char path[4096];
        int n = snprintf(path, sizeof(path), "%ssstable_%d.db", dir, sid);
        if (n < 0 || (size_t)n >= sizeof(path)) { sst_meta_index_destroy(seen); return -1; }
        int fd = open_secure_read(path);
        if (fd < 0) { if (errno == ENOENT) continue; sst_meta_index_destroy(seen); return -1; }
        FILE* f = fdopen(fd, "rb");
        if (!f) { close(fd); sst_meta_index_destroy(seen); return -1; }
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
            bool newest;
            if (index_usable) {
                newest = sst_meta_index_lookup(store->sst_meta, r.key,
                                               NULL, NULL, NULL, NULL,
                                               &isid, &ioff) &&
                         isid == sid && ioff == (uint64_t)(rec_off >= 0 ? rec_off : 0);
            } else {
                newest = !sst_meta_index_lookup(seen, r.key, NULL, NULL, NULL, NULL,
                                                NULL, NULL);
                if (newest) sst_meta_index_insert(seen, r.key, 0u, 0u, 0u, 0u, 0, 0u);
            }
            bool tombstone = (r.flags & KV_FLAG_TOMBSTONE) != 0u;
            bool expired = (!tombstone && r.expire_time_ms != 0u && r.expire_time_ms <= now);
            size_t z = 0u;
            bool shadowed = qihse_trinary_trie_search(store->trie, r.key, &z) != NULL;
            bool emit = newest && !shadowed && (include_expired || !expired) &&
                        (include_tombstones || !tombstone);
            if (emit) {
                if (!cb(r.key, &r, ud)) stopped = 1;
            }
            disk_record_free(&r);
            if (stopped) { fclose(f); sst_meta_index_destroy(seen); return 0; }
        }
        fclose(f);
        if (rc < 0) { sst_meta_index_destroy(seen); return -1; }
    }
    sst_meta_index_destroy(seen);
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
    /* Streaming compaction drops expired physical rows. A CT2 source range
     * must remain byte-identical from its fence cut through every retry. */
    if (store->ct_enabled && store->ct_fence_state == 1u) {
        errno = EBUSY;
        return false;
    }
    if (store->sstable_counter == 0) return true;
    const char* dir = get_qihse_data_dir();
    if (!dir) return false;
    int new_id = store->sstable_counter;
    char new_path[4096];
    int n = snprintf(new_path, sizeof(new_path), "%ssstable_%d.db", dir, new_id);
    if (n < 0 || (size_t)n >= sizeof(new_path)) return false;
    char tmp[8192]; FILE* out = NULL;
    if (!atomic_file_begin(new_path, tmp, sizeof(tmp), &out)) return false;
    compact_emit_ctx_t wctx = { .f = out, .ok = true, .written = 0u, .store = store };
    int rc = sst_foreach_newest(store, true, false, compact_emit_cb, &wctx);
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
        store->sstable_live_count = 0u;
        sst_meta_index_reset(store); /* entries now point at deleted files — rebuild empty */
    } else {
        store->sstable_counter = new_id + 1;
        store->sstable_live_count = 1u;
        sst_meta_index_reset(store);
        /* Re-index the merged file.  If the index is gone (OOM) lookups fall
         * back to the degraded full scan, which still finds sstable_<new_id>
         * because sstable_counter covers it. */
        if (store->sst_meta) {
            const kv_read_context_t context = { .legacy_bootstrap = true };
            if (!sst_index_load_file(store, new_path, new_id, &context)) {
                store->sst_meta->degraded = true;
                fprintf(stderr,
                        "qihse-kv: re-index of merged sstable %d failed; reads "
                        "fall back to the scan path until the next compaction\n",
                        new_id);
            }
        }
    }
    kv_projection_epoch_advance(store);
    return true;
}

static int wal_replay_new_record(qihse_kv_store_t* store, FILE* f, bool has_source_seq,
                                  const kv_read_context_t* context) {
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
        val_len > KV_MAX_VALUE_LEN || (flags & ~KV_ALLOWED_FLAGS) != 0u) return 0;
    if (op == KV_WAL_OP_DEL && (val_len != 0u || (flags & KV_FLAG_TOMBSTONE) == 0u)) return 0;
    if (!kv_read_allowed(context, classification, sci)) return -2;
    char* key = (char*)malloc((size_t)key_len + 1u);
    char* val = (char*)malloc((size_t)val_len + 1u);
    if (!key || !val) { free(key); free(val); errno = ENOMEM; return -1; }
    if (fread(key, 1u, key_len, f) != key_len || fread(val, 1u, val_len, f) != val_len) {
        free(key); free(val); return 0;
    }
    if (memchr(key, '\0', key_len) || memchr(val, '\0', val_len)) { free(key); free(val); return 0; }
    key[key_len] = '\0'; val[val_len] = '\0';
    uint64_t actual = has_source_seq
        ? wal_replica_record_crc(op, flags, key_len, val_len, classification, sci,
                                 expire, source_seq, key, val)
        : wal_record_crc(op, flags, key_len, val_len, classification, sci, expire, key, val);
    if (actual != crc) { free(key); free(val); return 0; }
    if (has_source_seq) {
        if (source_seq == 0u ||
            (op == KV_WAL_OP_DEL && (val_len != 0u || expire != 0u || (flags & KV_FLAG_TOMBSTONE) == 0u)) ||
            (op == KV_WAL_OP_SET && flags != 0u)) {
            free(key); free(val); return 0;
        }
        kv_payload_t* prior = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, NULL);
        if (prior && prior->change_seq >= source_seq) {
            bool duplicate = prior->change_seq == source_seq && prior->flags == flags &&
                             prior->expire_time_ms == expire && prior->classification == classification &&
                             prior->sci_compartment == sci && strcmp(prior->val, val) == 0;
            free(key); free(val);
            if (!duplicate) errno = EINVAL;
            return duplicate ? 1 : -1;
        }
        bool ok = !wal_replay_test_fail_apply() &&
            insert_internal(store, key, val, expire, classification, sci, flags, source_seq);
        if (ok) kv_change_seq_floor(store, source_seq);
        free(key); free(val);
        if (!ok) { if (errno == 0) errno = EIO; return -1; }
        return 1;
    }
    /* The binary WAL format carries no sequence (unchanged, so existing
     * wal.log files keep decoding); recovery re-stamps each replayed
     * mutation with a fresh sequence.  Replay order is mutation order, so
     * relative order survives and the high-water only moves forward. */
    uint64_t seq = kv_change_seq_next(store);
    if (seq == 0u) { free(key); free(val); errno = EOVERFLOW; return -1; }
    bool ok = !wal_replay_test_fail_apply() &&
        insert_internal(store, key, val, expire, classification, sci, flags, seq);
    free(key); free(val);
    if (!ok) { if (errno == 0) errno = EIO; return -1; }
    return 1;
}

static int wal_replay_delete_receipt(qihse_kv_store_t* store, FILE* f,
                                     const kv_read_context_t* context) {
    unsigned char hdr[48] = {0};
    memcpy(hdr, KV_WAL_MAGIC_DELETE_RECEIPT, 4u);
    if (fread(hdr + 4u, 1u, sizeof(hdr) - 4u, f) != sizeof(hdr) - 4u) return 0;
    uint16_t source_len, receipt_key_len, source_class, source_sci, receipt_class, receipt_sci;
    uint32_t value_len;
    uint64_t delete_seq, receipt_seq, crc;
    memcpy(&source_len, hdr + 4u, 2u); memcpy(&receipt_key_len, hdr + 6u, 2u);
    memcpy(&value_len, hdr + 8u, 4u);
    memcpy(&source_class, hdr + 12u, 2u); memcpy(&source_sci, hdr + 14u, 2u);
    memcpy(&receipt_class, hdr + 16u, 2u); memcpy(&receipt_sci, hdr + 18u, 2u);
    memcpy(&delete_seq, hdr + 20u, 8u); memcpy(&receipt_seq, hdr + 28u, 8u);
    memcpy(&crc, hdr + 36u, 8u);
    if (!source_len || !receipt_key_len || value_len > QIHSE_KV_DELETE_RECEIPT_MAX_VALUE ||
        !delete_seq || receipt_seq != delete_seq + 1u || receipt_seq == 0u ||
        hdr[44] || hdr[45] || hdr[46] || hdr[47]) return 0;
    if (!kv_read_allowed(context, source_class, source_sci) ||
        !kv_read_allowed(context, receipt_class, receipt_sci)) return -2;
    char* source = malloc((size_t)source_len + 1u);
    char* receipt_key = malloc((size_t)receipt_key_len + 1u);
    char* value = malloc((size_t)value_len + 1u);
    if (!source || !receipt_key || !value) {
        free(source); free(receipt_key); free(value); return -1;
    }
    bool ok = fread(source, 1u, source_len, f) == source_len &&
              fread(receipt_key, 1u, receipt_key_len, f) == receipt_key_len &&
              fread(value, 1u, value_len, f) == value_len;
    if (ok) {
        ok = !memchr(source, 0, source_len) && !memchr(receipt_key, 0, receipt_key_len) &&
             !memchr(value, 0, value_len) &&
             wal_delete_receipt_crc(hdr, source, source_len, receipt_key,
                                    receipt_key_len, value, value_len) == crc;
    }
    if (ok) {
        source[source_len] = '\0'; receipt_key[receipt_key_len] = '\0'; value[value_len] = '\0';
        ok = strcmp(source, receipt_key) != 0;
    }
    bool fatal = false;
    if (ok) {
        kv_lookup_result_t old;
        kv_lookup_state_t state = logical_lookup(store, source, &old);
        fatal = state == KV_LOOKUP_ERROR;
        ok = !fatal;
        if (ok && state != KV_LOOKUP_MISS && old.change_seq == delete_seq) {
            ok = state == KV_LOOKUP_DEAD && (old.flags & KV_FLAG_TOMBSTONE) &&
                 old.classification == source_class && old.sci_compartment == source_sci;
            if (!ok) fatal = true;
        }
        if (ok && (state == KV_LOOKUP_MISS || old.change_seq < delete_seq)) {
            ok = insert_internal(store, source, "", 0u, source_class, source_sci,
                                 KV_FLAG_TOMBSTONE, delete_seq);
            if (!ok) fatal = true;
        }
        lookup_result_free(&old);
    }
    if (ok) {
        kv_lookup_result_t old;
        kv_lookup_state_t state = logical_lookup(store, receipt_key, &old);
        fatal = state == KV_LOOKUP_ERROR;
        ok = !fatal;
        if (ok && state != KV_LOOKUP_MISS && old.change_seq == receipt_seq) {
            ok = state == KV_LOOKUP_LIVE && old.value &&
                 strcmp(old.value, value) == 0 &&
                 old.classification == receipt_class && old.sci_compartment == receipt_sci;
            if (!ok) fatal = true;
        }
        if (ok && (state == KV_LOOKUP_MISS || old.change_seq < receipt_seq)) {
            ok = insert_internal(store, receipt_key, value, 0u, receipt_class,
                                 receipt_sci, 0u, receipt_seq);
            if (!ok) fatal = true;
        }
        lookup_result_free(&old);
    }
    if (ok) kv_change_seq_floor(store, receipt_seq);
    free(source); free(receipt_key); free(value);
    return ok ? 1 : fatal ? -1 : 0;
}

/* Text WAL labels trail the payload. Inspect only the final label tokens,
 * then rewind before the legacy parser materializes the key/value. */
static bool wal_text_read_allowed(FILE* f, const kv_read_context_t* context) {
    if (context->legacy_bootstrap) return true;
    off_t start = ftello(f);
    if (start < 0) return false;
    uint32_t last[2] = {0u, 0u}, token = 0u;
    bool valid[2] = {false, false}, numeric = true, in_token = false;
    unsigned tokens = 0u;
    size_t length = 0u;
    int c;
    do {
        c = fgetc(f);
        /* Do not authorize a suffix the bounded legacy parser cannot reach. */
        if (++length >= 63488u) { errno = EINVAL; return false; }
        if (c == ' ' || c == '\n' || c == EOF) {
            if (in_token) {
                last[0] = last[1]; valid[0] = valid[1];
                last[1] = token; valid[1] = numeric;
                tokens++; token = 0u; numeric = true; in_token = false;
            }
        } else {
            in_token = true;
            if (c < '0' || c > '9' || token > UINT16_MAX / 10u ||
                token * 10u + (unsigned)(c - '0') > UINT16_MAX) numeric = false;
            else if (numeric) token = token * 10u + (unsigned)(c - '0');
        }
    } while (c != '\n' && c != EOF);
    if (fseeko(f, start, SEEK_SET) != 0) return false;
    if (tokens == 2u) return kv_read_allowed(context, 0u, 0u);
    if (tokens == 3u && valid[1]) return kv_read_allowed(context, 0u, (uint16_t)last[1]);
    if (tokens < 4u || !valid[0] || !valid[1]) { errno = EINVAL; return false; }
    return kv_read_allowed(context, (uint16_t)last[0], (uint16_t)last[1]);
}

static int ct_replay_group(qihse_kv_store_t* store, FILE* f,
                           const kv_read_context_t* context,
                           uint64_t* last_seen_position) {
    if (!store->ct_enabled || !context || !context->user ||
        fseeko(f, -4, SEEK_CUR) != 0) return -1;
    qihse_kv_ct_group_t group = {0};
    uint8_t mode = 0u;
    size_t frame_bytes = 0u;
    int rc = qihse_ct_codec_read(f, context->user,
        store->ct_mode == 2u ? store->ct_tenant_policy : QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        store->ct_mode == 2u ? store->ct_tenant_id : 0u,
        QIHSE_KV_DURABLE_BATCH_MAX_BYTES, &group, &mode, &frame_bytes);
    if (rc != 1) return rc == -2 ? -2 : (feof(f) && !ferror(f) ? 0 : -1);
    bool ok = mode == store->ct_mode &&
        strcmp(group.source_id, store->ct_source_id) == 0 &&
        strcmp(group.generation, store->ct_generation) == 0 &&
        group.stream_position != 0u &&
        (*last_seen_position ? group.stream_position == *last_seen_position + 1u :
         (store->ct_mode == 2u ? group.stream_position == 1u :
          group.stream_position <= store->ct_ack_lsn + 1u));
    if (ok) {
        for (size_t i = 0; i < group.count; i++) {
            qihse_kv_ct_record_t* r = &group.records[i];
            kv_lookup_result_t old;
            kv_lookup_state_t state = logical_lookup(store, r->key, &old);
            if (state == KV_LOOKUP_ERROR) { ok = false; break; }
            if (state == KV_LOOKUP_LIVE || state == KV_LOOKUP_DEAD) {
                if (old.change_seq > r->change_seq) {
                    lookup_result_free(&old);
                    continue;
                }
                if (old.change_seq == r->change_seq) {
                    bool same = old.classification == r->classification &&
                        old.sci_compartment == r->sci_compartment &&
                        old.expire_time_ms == r->expire_time_ms &&
                        (((old.flags & KV_FLAG_TOMBSTONE) != 0u) == r->tombstone) &&
                        (r->tombstone || (old.value && r->value &&
                                          strcmp(old.value, r->value) == 0));
                    lookup_result_free(&old);
                    if (!same) { ok = false; break; }
                    continue;
                }
            }
            lookup_result_free(&old);
            if (!insert_internal(store, r->key, r->tombstone ? "" : r->value,
                                 r->expire_time_ms, r->classification,
                                 r->sci_compartment,
                                 r->tombstone ? KV_FLAG_TOMBSTONE : 0u,
                                 r->change_seq)) { ok = false; break; }
            kv_change_seq_floor(store, r->change_seq);
        }
    }
    if (ok) {
        unsigned char recovered_digest[32];
        if (!qihse_ct_codec_group_digest(context->user,
                store->ct_mode == 2u ? store->ct_tenant_policy :
                                       QIHSE_KV_CT_TENANT_SYSTEM_ALL,
                store->ct_mode == 2u ? store->ct_tenant_id : 0u,
                &group, recovered_digest)) ok = false;
        if (ok) memcpy(store->ct_last_group_digest, recovered_digest,
                       sizeof(recovered_digest));
    }
    if (ok) {
        *last_seen_position = group.stream_position;
        if (group.stream_position > store->ct_durable_lsn)
            store->ct_durable_lsn = group.stream_position;
    }
    qihse_ct_codec_clear(&group);
    return ok ? 1 : -1;
}

static bool recover_from_wal(qihse_kv_store_t* store, const kv_read_context_t* context) {
    if (!store) return false;
    char wal_path[4096];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) return false;
    int fd = open_secure_read(wal_path);
    if (fd < 0) return errno == ENOENT;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    off_t last_good = 0;
    uint64_t ct_last_seen_position = 0u;
    for (;;) {
        int c = fgetc(f);
        if (c == EOF) break;
        if (c == 'Q') {
            char magic[4] = { 'Q', 0, 0, 0 };
            if (fread(magic + 1, 1u, 3u, f) != 3u) break;
            /* Once the CT state is published, every logical mutation must
             * carry a QKV6 group and cursor. Legacy WAL frames are a bypass,
             * even if a previous transition should have rotated them away. */
            if (store->ct_enabled && memcmp(magic, KV_WAL_MAGIC_CT, 4u) != 0) {
                fclose(f); errno = EINVAL; return false;
            }
            if (memcmp(magic, KV_WAL_MAGIC_DELETE_RECEIPT, 4u) == 0) {
                int replay = wal_replay_delete_receipt(store, f, context);
                if (replay == -2) goto denied;
                if (replay == -1) { fclose(f); return false; }
                if (!replay) break;
                last_good = ftello(f);
                continue;
            }
            if (memcmp(magic, KV_WAL_MAGIC_CT, 4u) == 0) {
                int replay = ct_replay_group(store, f, context,
                                              &ct_last_seen_position);
                if (replay == -2) goto denied;
                if (replay < 0) { fclose(f); return false; }
                if (!replay) break;
                last_good = ftello(f);
                continue;
            }
            bool sequenced = memcmp(magic, KV_WAL_MAGIC_REPLICA, 4u) == 0 ||
                             memcmp(magic, KV_WAL_MAGIC_LOCAL_SEQ, 4u) == 0;
            if (!sequenced && memcmp(magic, KV_WAL_MAGIC, 4u) != 0) break;
            int replay = wal_replay_new_record(store, f, sequenced, context);
            if (replay == -2) goto denied;
            if (replay < 0) { fclose(f); return false; }
            if (!replay) break;
            last_good = ftello(f);
            continue;
        }
        if (store->ct_enabled) { fclose(f); errno = EINVAL; return false; }
        if (c == 'S') {
            char tag[4] = { 'S', 0, 0, 0 };
            if (fread(tag + 1, 1u, 3u, f) != 3u) break;
            if (tag[1] == 'E' && tag[2] == 'T' && tag[3] == '\0') {
                uint16_t key_len = 0u, classification = 0u, sci = 0u; uint32_t val_len = 0u;
                if (fread(&key_len, sizeof(key_len), 1u, f) != 1u || fread(&val_len, sizeof(val_len), 1u, f) != 1u ||
                    fread(&classification, sizeof(classification), 1u, f) != 1u || fread(&sci, sizeof(sci), 1u, f) != 1u ||
                    key_len == 0u || val_len > KV_MAX_VALUE_LEN) break;
                if (!kv_read_allowed(context, classification, sci)) goto denied;
                char* key = (char*)malloc((size_t)key_len + 1u); char* val = (char*)malloc((size_t)val_len + 1u);
                if (!key || !val) {
                    free(key); free(val); errno = ENOMEM; fclose(f); return false;
                }
                if (fread(key, 1u, key_len, f) != key_len || fread(val, 1u, val_len, f) != val_len) {
                    free(key); free(val); break;
                }
                key[key_len] = '\0'; val[val_len] = '\0';
                uint64_t seq = kv_change_seq_next(store);
                bool applied = seq != 0u &&
                    !wal_replay_test_fail_apply() &&
                    insert_internal(store, key, val, 0u, classification, sci, 0u, seq);
                if (!applied) {
                    free(key); free(val); errno = seq == 0u ? EOVERFLOW : EIO;
                    fclose(f); return false;
                }
                free(key); free(val); last_good = ftello(f); continue;
            }
            if (tag[1] == 'E' && tag[2] == 'T' && tag[3] == ' ') {
                if (!wal_text_read_allowed(f, context)) goto denied;
                char* line = (char*)malloc(65536);
                char* rest = (char*)malloc(63488);
                if (!line || !rest) {
                    free(line);
                    free(rest);
                    errno = ENOMEM; fclose(f); return false;
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
                        if (!kv_read_allowed(context, (uint16_t)classif, (uint16_t)sci)) {
                            free(line); free(rest); goto denied;
                        }
                        uint64_t seq = kv_change_seq_next(store);
                        if (seq == 0u || wal_replay_test_fail_apply() ||
                            !insert_internal(store, key, rest, 0u, (uint16_t)classif,
                                             (uint16_t)sci, 0u, seq)) {
                            free(line); free(rest); errno = seq == 0u ? EOVERFLOW : EIO;
                            fclose(f); return false;
                        }
                    }
                }
                free(line);
                free(rest);
                last_good = ftello(f);
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
                    if (!kv_read_allowed(context, cclass, csci)) goto denied;
                    uint64_t seq = kv_change_seq_next(store);
                    if (seq == 0u || wal_replay_test_fail_apply() ||
                        !insert_internal(store, line, "", 0u, cclass, csci,
                                         KV_FLAG_TOMBSTONE, seq)) {
                        errno = seq == 0u ? EOVERFLOW : EIO;
                        fclose(f); return false;
                    }
                }
                last_good = ftello(f);
                continue;
            }
            break;
        }
        break;
    }
    off_t end = ftello(f);
    fclose(f);
    /* A short/invalid final frame is an unacknowledged write tail. Remove it
     * before opening the append handle so a retry's valid frame is replayable. */
    if (end >= 0 && last_good >= 0 && end > last_good) {
        int repair_fd = open(wal_path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (repair_fd >= 0) {
            if (ftruncate(repair_fd, last_good) == 0) (void)fsync(repair_fd);
            close(repair_fd);
        }
    }
    if (store->ct_enabled &&
        ((store->ct_mode == 1u && store->ct_durable_lsn > store->ct_ack_lsn &&
          ct_last_seen_position < store->ct_durable_lsn) ||
         (store->ct_mode == 2u && store->ct_durable_lsn > 0u &&
          ct_last_seen_position < store->ct_durable_lsn))) return false;
    if (store->ct_enabled) store->ct_retained_bytes = (uint64_t)last_good;
    return true;
denied:
    /* Authorization failure is not a torn tail: never repair/truncate it. */
    fclose(f);
    errno = EACCES;
    return false;
}

/* Populate the in-memory SSTable metadata index from one on-disk SSTable.
 * Uses the header-only reader so the value bytes (up to 16MB each) are
 * skipped with fseeko rather than malloc'd + read + discarded.  The stamped
 * sequences pass by on the header line; the maximum observed raises the
 * store's high-water so a restart does not regress it. */
static bool sst_index_load_file(qihse_kv_store_t* store, const char* path, int32_t sstable_id,
                                const kv_read_context_t* context) {
    if (!store || !store->sst_meta || !path) return false;
    /* Fault injection: reproduces a store whose index cannot be built, the
     * state that used to strand compaction on the memtable path forever. */
    if (aimem_durability_test_fail_once("sst-index-load")) return false;
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    kv_disk_record_t r; int rc;
    for (;;) {
        long rec_off = ftell(f);
        rc = disk_record_read_header(f, &r, context);
        if (rc != 1) break;
        sst_meta_index_insert(store->sst_meta, r.key,
                              r.classification, r.sci_compartment,
                              r.expire_time_ms, r.flags, sstable_id,
                              rec_off >= 0 ? (uint64_t)rec_off : 0u);
        if (r.change_seq != 0u) kv_change_seq_floor(store, r.change_seq);
        disk_record_free(&r);
    }
    fclose(f);
    return rc == 0;
}

static qihse_kv_store_t* kv_store_allocate(void) {
    qihse_kv_store_t* store = (qihse_kv_store_t*)calloc(1u, sizeof(*store));
    if (!store) return NULL;
    size_t random_bytes = 0u;
    while (random_bytes < sizeof store->instance_id) {
        ssize_t n = getrandom((char*)&store->instance_id + random_bytes,
                              sizeof store->instance_id - random_bytes, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(store); return NULL; }
        random_bytes += (size_t)n;
    }
    if (store->instance_id == 0u) { free(store); return NULL; }
    store->trie = qihse_trinary_trie_create();
    if (!store->trie) { free(store); return NULL; }
    __atomic_store_n(&store->projection_epoch, 1u, __ATOMIC_RELAXED);
    /* Mark cache slots empty before ANY early destroy path can run —
     * a zeroed slot otherwise looks like fd 0 (stdin). */
    for (size_t i = 0; i < sizeof(store->sst_fds) / sizeof(store->sst_fds[0]); i++) {
        store->sst_fds[i].fd = -1;
        store->sst_fds[i].sid = -1;
    }
    if (pthread_mutex_init(&store->sst_fd_lock, NULL) != 0) {
        qihse_trinary_trie_destroy(store->trie); free(store); return NULL;
    }
    if (pthread_rwlock_init(&store->store_lock, NULL) != 0) {
        pthread_mutex_destroy(&store->sst_fd_lock);
        qihse_trinary_trie_destroy(store->trie); free(store); return NULL;
    }
    if (pthread_mutex_init(&store->ct_ack_lock, NULL) != 0) {
        pthread_rwlock_destroy(&store->store_lock);
        pthread_mutex_destroy(&store->sst_fd_lock);
        qihse_trinary_trie_destroy(store->trie); free(store); return NULL;
    }
    if (pthread_cond_init(&store->ct_ack_changed, NULL) != 0) {
        pthread_mutex_destroy(&store->ct_ack_lock);
        pthread_rwlock_destroy(&store->store_lock);
        pthread_mutex_destroy(&store->sst_fd_lock);
        qihse_trinary_trie_destroy(store->trie); free(store); return NULL;
    }
    store->sst_meta = sst_meta_index_create();
    if (!store->sst_meta) { qihse_kv_store_destroy(store); return NULL; }
    return store;
}

static qihse_kv_store_t* kv_store_create_internal(const kv_read_context_t* context) {
    qihse_user_t* user = context->user;
    if (!context->legacy_bootstrap && (!user || !qihse_auth_user_is_active(user))) {
        errno = EACCES; return NULL;
    }
    qihse_kv_store_t* store = kv_store_allocate();
    if (!store) return NULL;
    const char* dir = get_qihse_data_dir();
    if (!dir) { qihse_kv_store_destroy(store); return NULL; }
    if (!ct_state_read(store, user, context->legacy_bootstrap)) {
        qihse_kv_store_destroy(store); return NULL;
    }
    if (!replica_install_recover_image(dir, user)) { qihse_kv_store_destroy(store); return NULL; }
    DIR* d = opendir(dir);
    if (d) {
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            if (strncmp(ent->d_name, "sstable_", 8u) == 0) {
                char* end = NULL; long id = strtol(ent->d_name + 8u, &end, 10);
                if (end && strcmp(end, ".db") == 0 && id >= 0 && id < INT_MAX) {
                    store->sstable_live_count++;
                    if (id + 1 > store->sstable_counter)
                        store->sstable_counter = (int)id + 1;
                }
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
        if (!sst_index_load_file(store, sst_path, i, context)) {
            qihse_kv_store_destroy(store); return NULL;
        }
    }
    /* Legacy DEL replay must resolve labels from the authorized metadata,
     * not fall back to a context-free value scan on allocation failure. */
    if (!context->legacy_bootstrap && store->sst_meta->degraded) {
        qihse_kv_store_destroy(store); errno = ENOMEM; return NULL;
    }
    if (!recover_from_wal(store, context)) { qihse_kv_store_destroy(store); return NULL; }
    uint64_t image_floor = 0u;
    if (!image_highwater_read(&image_floor)) { qihse_kv_store_destroy(store); return NULL; }
    kv_change_seq_floor(store, image_floor);
    if (!cursor_read_file(store)) { qihse_kv_store_destroy(store); return NULL; }
    if (!replica_install_finish_recovery(store, dir, user)) { qihse_kv_store_destroy(store); return NULL; }
    char wal_path[4096];
    if (!build_data_path(wal_path, sizeof(wal_path), "wal.log")) { qihse_kv_store_destroy(store); return NULL; }
    int fd = open(wal_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { qihse_kv_store_destroy(store); return NULL; }
    store->wal_fd = fdopen(fd, "ab");
    if (!store->wal_fd) { close(fd); qihse_kv_store_destroy(store); return NULL; }
    if (!context->legacy_bootstrap && !qihse_auth_user_is_active(user)) {
        qihse_kv_store_destroy(store); errno = EACCES; return NULL;
    }
    return store;
}

qihse_kv_store_t* qihse_kv_store_create_user(qihse_user_t* user) {
    const kv_read_context_t context = { .user = user };
    return kv_store_create_internal(&context);
}

qihse_kv_store_t* qihse_kv_store_create(void) {
    const kv_read_context_t context = { .legacy_bootstrap = true };
    return kv_store_create_internal(&context);
}

bool qihse_kv_store_enable_replica_read_only(qihse_kv_store_t* store) {
    if (!store) return false;
    kv_store_wrlock(store);
    bool ok = store->trie && !store->recovery_pending;
    if (ok) __atomic_store_n(&store->replica_read_only, true, __ATOMIC_RELEASE);
    kv_store_unlock(store);
    return ok;
}

void qihse_kv_store_set_replication_principal_id(qihse_kv_store_t* store,
                                                 uint32_t principal_id) {
    if (!store || store->memory_snapshot) return;
    kv_store_wrlock(store);
    if (!store->recovery_pending)
        __atomic_store_n(&store->replication_principal_id, principal_id, __ATOMIC_RELEASE);
    kv_store_unlock(store);
}

static bool ct_make_token(unsigned char out[QIHSE_KV_CT_TOKEN_BYTES],
                          const unsigned char supplied[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (supplied) { memcpy(out, supplied, QIHSE_KV_CT_TOKEN_BYTES); return true; }
    size_t done = 0u;
    while (done < QIHSE_KV_CT_TOKEN_BYTES) {
        ssize_t n = getrandom(out + done, QIHSE_KV_CT_TOKEN_BYTES - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

bool qihse_kv_ct_source_enable(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* source_id, const char* successor_id, const char* generation,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t max_retained_bytes) {
    if (!store || !ct_admin(principal) || !ct_id_valid(source_id) ||
        !ct_id_valid(successor_id) || !ct_id_valid(generation) ||
        max_retained_bytes < (uint64_t)QIHSE_KV_DURABLE_BATCH_MAX_BYTES + 4096u ||
        store->memory_snapshot) return false;
    kv_store_wrlock(store);
    bool ok = !store->ct_enabled && !store->recovery_pending &&
        !store->bulk_load_mode && !store->durable_batch_mode &&
        !store->replica_read_only && kv_sync_store_locked(store) &&
        rotate_wal_empty(store) && fsync_dir_path(get_qihse_data_dir());
    if (ok) {
        store->ct_enabled = true;
        store->ct_admitted = false;
        store->ct_mode = 1u;
        store->ct_system_principal = principal;
        snprintf(store->ct_source_id, sizeof(store->ct_source_id), "%s", source_id);
        snprintf(store->ct_successor_id, sizeof(store->ct_successor_id), "%s", successor_id);
        snprintf(store->ct_generation, sizeof(store->ct_generation), "%s", generation);
        store->ct_baseline_lsn = __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE);
        store->ct_baseline_sealed = false;
        store->ct_durable_lsn = 0u;
        store->ct_ack_lsn = 0u;
        store->ct_retained_bytes = 0u;
        store->ct_limit_bytes = max_retained_bytes;
        ok = ct_make_token(store->ct_owner_token, owner_token) && ct_state_write(store);
        if (!ok) {
            store->ct_enabled = false;
            store->ct_mode = 0u;
        }
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_source_status(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_kv_ct_source_status_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store || !out || !ct_replication_principal(store, principal)) return false;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 1u && !store->recovery_pending;
    if (ok) {
        snprintf(out->source_id, sizeof(out->source_id), "%s", store->ct_source_id);
        snprintf(out->successor_id, sizeof(out->successor_id), "%s", store->ct_successor_id);
        snprintf(out->generation, sizeof(out->generation), "%s", store->ct_generation);
        out->durable_lsn = store->ct_durable_lsn;
        out->oldest_lsn = store->ct_ack_lsn + 1u;
        out->acknowledged_lsn = store->ct_ack_lsn;
        out->retained_bytes = store->ct_retained_bytes;
        out->limit_bytes = store->ct_limit_bytes;
        out->baseline_row_seq = store->ct_baseline_lsn;
        out->admitted = store->ct_admitted;
        memcpy(out->baseline_digest, store->ct_baseline_digest,
               sizeof(out->baseline_digest));
    }
    kv_store_unlock(store);
    return ok;
}

static bool ct_fd_sha256(int fd, unsigned char out[32]) {
    if (fd < 0 || !out) return false;
    EVP_MD_CTX* digest = EVP_MD_CTX_new();
    if (!digest) return false;
    bool ok = EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1;
    unsigned char chunk[8192];
    off_t offset = 0;
    while (ok) {
        ssize_t n = pread(fd, chunk, sizeof(chunk), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        ok = EVP_DigestUpdate(digest, chunk, (size_t)n) == 1;
        offset += n;
    }
    unsigned int len = 0u;
    if (ok) ok = EVP_DigestFinal_ex(digest, out, &len) == 1 && len == 32u;
    EVP_MD_CTX_free(digest);
    return ok;
}

typedef struct {
    kv_disk_record_t* rows;
    size_t count, capacity, bytes;
} ct_range_image_t;

static void ct_range_image_free(ct_range_image_t* image);
static bool ct_range_import_existing_locked(qihse_kv_store_t* store,
    qihse_user_t* principal, uint16_t first_slot, uint16_t last_slot,
    ct_range_image_t* out);

static bool ct_hash_u64(EVP_MD_CTX* md, uint64_t value) {
    unsigned char encoded[8];
    for (unsigned i = 0u; i < 8u; i++)
        encoded[i] = (unsigned char)(value >> (56u - i * 8u));
    return EVP_DigestUpdate(md, encoded, sizeof(encoded)) == 1;
}

/* Proofs hash only the frozen range under the explicit data principal,
 * including local preimage rows during transfer-back. Generic snapshots
 * filter moved slots and cannot provide this internal seal. */
static bool ct_range_digest(qihse_kv_store_t* store, qihse_user_t* data_principal,
    uint16_t first_slot, uint16_t last_slot, unsigned char out[32]) {
    if (!store || !data_principal ||
        !qihse_auth_user_is_active(data_principal) || !out) return false;
    ct_range_image_t image = {0};
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && !store->recovery_pending &&
        ct_range_import_existing_locked(store, data_principal, first_slot,
                                        last_slot, &image);
    kv_store_unlock(store);
    if (!ok) return false;
    for (size_t i = 0u; i < image.count; i++) {
        if (!qihse_auth_user_is_active(data_principal) ||
            !qihse_auth_can_access(data_principal,
                image.rows[i].classification, image.rows[i].sci_compartment)) {
            ct_range_image_free(&image);
            errno = EACCES;
            return false;
        }
    }
    size_t live_count = 0u;
    for (size_t i = 0u; i < image.count; i++)
        if ((image.rows[i].flags & KV_FLAG_TOMBSTONE) == 0u) live_count++;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    unsigned int digest_len = 0u;
    ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md, "QCT-RANGE-V1", 12u) == 1 &&
        ct_hash_u64(md, first_slot) && ct_hash_u64(md, last_slot) &&
        ct_hash_u64(md, live_count);
    for (size_t i = 0u; ok && i < image.count; i++) {
        const kv_disk_record_t* row = &image.rows[i];
        if ((row->flags & KV_FLAG_TOMBSTONE) != 0u) continue;
        size_t key_len = strlen(row->key), value_len = strlen(row->val);
        EVP_MD_CTX* row_md = EVP_MD_CTX_new();
        unsigned char row_digest[32];
        unsigned int row_len = 0u;
        bool hashed = row_md && EVP_DigestInit_ex(row_md, EVP_sha256(), NULL) == 1 &&
            ct_hash_u64(row_md, key_len) &&
            EVP_DigestUpdate(row_md, row->key, key_len) == 1 &&
            ct_hash_u64(row_md, value_len) &&
            EVP_DigestUpdate(row_md, row->val, value_len) == 1 &&
            ct_hash_u64(row_md, row->expire_time_ms) &&
            ct_hash_u64(row_md, row->classification) &&
            ct_hash_u64(row_md, row->sci_compartment) &&
            ct_hash_u64(row_md, row->flags) &&
            EVP_DigestFinal_ex(row_md, row_digest, &row_len) == 1 &&
            row_len == 32u;
        EVP_MD_CTX_free(row_md);
        ok = hashed && (i == 0u ||
            strcmp(image.rows[i - 1u].key, row->key) != 0) &&
            ct_hash_u64(md, key_len) &&
            EVP_DigestUpdate(md, row->key, key_len) == 1 &&
            EVP_DigestUpdate(md, row_digest, 32u) == 1;
    }
    if (ok) ok = EVP_DigestFinal_ex(md, out, &digest_len) == 1 &&
                 digest_len == 32u;
    EVP_MD_CTX_free(md);
    ct_range_image_free(&image);
    return ok && qihse_auth_user_is_active(data_principal);
}

static void ct_range_image_free(ct_range_image_t* image) {
    if (!image) return;
    for (size_t i = 0u; i < image->count; i++)
        disk_record_free(&image->rows[i]);
    free(image->rows);
    memset(image, 0, sizeof(*image));
}

static int ct_image_row_cmp(const void* lhs, const void* rhs) {
    const kv_disk_record_t* a = lhs;
    const kv_disk_record_t* b = rhs;
    return strcmp(a->key, b->key);
}

static bool ct_range_image_read(FILE* input, qihse_user_t* principal,
    uint16_t first_slot, uint16_t last_slot, bool exact_range,
    ct_range_image_t* out) {
    if (!input || !principal || !out) return false;
    memset(out, 0, sizeof(*out));
    const kv_read_context_t context = { .user = principal };
    bool ok = true;
    for (;;) {
        kv_disk_record_t row;
        int rc = disk_record_read_context(input, &row, &context);
        if (rc == 0) break;
        if (rc != 1) { ok = false; break; }
        uint16_t slot = qihse_cluster_key_slot(row.key, strlen(row.key));
        if (qihse_cluster_key_is_node_local(row.key) ||
            slot < first_slot || slot > last_slot) {
            disk_record_free(&row);
            if (exact_range) { ok = false; break; }
            continue;
        }
        size_t bytes = strlen(row.key) + strlen(row.val) + 64u;
        if ((row.flags & ~KV_FLAG_TOMBSTONE) != 0u ||
            ((row.flags & KV_FLAG_TOMBSTONE) != 0u &&
             (row.val[0] != '\0' || row.expire_time_ms != 0u)) ||
            out->count >= QIHSE_KV_CT_MAX_GROUP_RECORDS ||
            bytes > QIHSE_KV_DURABLE_BATCH_MAX_BYTES - out->bytes) {
            disk_record_free(&row); ok = false; errno = E2BIG; break;
        }
        if (out->count == out->capacity) {
            size_t next = out->capacity ? out->capacity * 2u : 128u;
            kv_disk_record_t* grown = realloc(out->rows, next * sizeof(*grown));
            if (!grown) { disk_record_free(&row); ok = false; break; }
            out->rows = grown; out->capacity = next;
        }
        out->rows[out->count++] = row;
        out->bytes += bytes;
    }
    if (ok) {
        qsort(out->rows, out->count, sizeof(*out->rows), ct_image_row_cmp);
        for (size_t i = 1u; i < out->count; i++)
            if (strcmp(out->rows[i - 1u].key, out->rows[i].key) == 0) ok = false;
    }
    if (!ok || !qihse_auth_user_is_active(principal)) {
        ct_range_image_free(out);
        return false;
    }
    return true;
}

static bool ct_range_stage_copy(const char* source_path,
    const unsigned char expected_digest[32], char stage_path[4096]) {
    if (!build_data_path(stage_path, 4096u, "ct-transfer-stage.qfs")) return false;
    int source_fd = open_secure_read(source_path);
    if (source_fd < 0) return false;
    struct stat st;
    bool ok = fstat(source_fd, &st) == 0 && st.st_size >= 0 &&
        (uint64_t)st.st_size <= QIHSE_KV_DURABLE_BATCH_MAX_BYTES;
    char* temp = malloc(8192u);
    FILE* output = NULL;
    if (ok) ok = temp && atomic_file_begin(stage_path, temp, 8192u, &output);
    unsigned char buffer[4096];
    while (ok) {
        ssize_t n = read(source_fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        if (fwrite(buffer, 1u, (size_t)n, output) != (size_t)n) ok = false;
    }
    close(source_fd);
    if (output) {
        if (ok) ok = atomic_file_commit(output, temp, stage_path) &&
                     fsync_dir_path(get_qihse_data_dir());
        else { fclose(output); unlink(temp); }
    }
    free(temp);
    if (ok) {
        int stage_fd = open_secure_read(stage_path);
        unsigned char actual[32];
        ok = stage_fd >= 0 && ct_fd_sha256(stage_fd, actual) &&
             memcmp(actual, expected_digest, 32u) == 0;
        if (stage_fd >= 0) close(stage_fd);
    }
    if (!ok) (void)unlink(stage_path);
    return ok;
}

static bool ct_range_image_from_path(const char* path, qihse_user_t* principal,
    uint16_t first_slot, uint16_t last_slot, bool exact_range,
    ct_range_image_t* out) {
    int fd = open_secure_read(path);
    if (fd < 0) return false;
    FILE* input = fdopen(fd, "rb");
    if (!input) { close(fd); return false; }
    bool ok = ct_range_image_read(input, principal, first_slot, last_slot,
                                  exact_range, out);
    if (fclose(input) != 0) ok = false;
    if (!ok) ct_range_image_free(out);
    return ok;
}

static bool ct_range_merge_group(qihse_kv_store_t* store,
    qihse_user_t* principal, const ct_range_image_t* incoming,
    const ct_range_image_t* existing, qihse_kv_ct_group_t* group) {
    if (!store || !principal || !incoming || !existing || !group) return false;
    memset(group, 0, sizeof(*group));
    qihse_kv_ct_record_t* rows = calloc(QIHSE_KV_CT_MAX_GROUP_RECORDS,
                                        sizeof(*rows));
    if (!rows) return false;
    snprintf(group->source_id, sizeof(group->source_id), "%s", store->ct_source_id);
    snprintf(group->generation, sizeof(group->generation), "%s", store->ct_generation);
    group->stream_position = store->ct_durable_lsn + 1u;
    group->records = rows;
    size_t i = 0u, j = 0u;
    while (i < incoming->count || j < existing->count) {
        const kv_disk_record_t* source = i < incoming->count ? &incoming->rows[i] : NULL;
        const kv_disk_record_t* target = j < existing->count ? &existing->rows[j] : NULL;
        int order = source && target ? strcmp(source->key, target->key) :
                    source ? -1 : 1;
        if (group->count == QIHSE_KV_CT_MAX_GROUP_RECORDS) goto failed;
        qihse_kv_ct_record_t* row = &rows[group->count++];
        const char* key = source && order <= 0 ? source->key : target->key;
        uint32_t resource_tenant = 0u;
        if (!ct_resource_tenant(key, 0u, &resource_tenant)) goto failed;
        bool source_tombstone = source && (source->flags & KV_FLAG_TOMBSTONE);
        row->key = (char*)key;
        row->value = source && order <= 0 && !source_tombstone ? source->val : NULL;
        row->classification = source && order <= 0 ? source->classification : target->classification;
        row->sci_compartment = source && order <= 0 ? source->sci_compartment : target->sci_compartment;
        row->expire_time_ms = source && order <= 0 && !source_tombstone ? source->expire_time_ms : 0u;
        row->actor_id = qihse_user_get_id(principal);
        row->actor_tenant_id = 0u;
        row->resource_tenant_id = resource_tenant;
        row->actor_kind = QIHSE_KV_CT_ACTOR_REPLICA;
        row->tombstone = !source || order > 0 || source_tombstone;
        row->change_seq = group->count;
        if (!qihse_auth_can_access(principal, row->classification, row->sci_compartment)) goto failed;
        if (source && target && order == 0 &&
            (source->classification < target->classification ||
             (source->sci_compartment & target->sci_compartment) != target->sci_compartment)) goto failed;
        if (source && order <= 0) i++;
        if (target && order >= 0) j++;
    }
    group->first_seq = group->count ? 1u : 0u;
    group->last_seq = group->count;
    return true;
failed:
    free(rows);
    memset(group, 0, sizeof(*group));
    return false;
}

static bool ct_persist_baseline_fd(int source_fd, unsigned char digest[32]) {
    char path[4096];
    char* temp = malloc(8192u);
    FILE* output = NULL;
    if (!build_data_path(path, sizeof(path), "ct-baseline.qfs") ||
        !temp || !atomic_file_begin(path, temp, 8192u, &output)) {
        free(temp);
        return false;
    }
    unsigned char chunk[4096];
    off_t offset = 0;
    bool ok = true;
    for (;;) {
        ssize_t n = pread(source_fd, chunk, sizeof(chunk), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        if (fwrite(chunk, 1u, (size_t)n, output) != (size_t)n) { ok = false; break; }
        offset += n;
    }
    if (ok) ok = atomic_file_commit(output, temp, path) &&
                 fsync_dir_path(get_qihse_data_dir());
    else { fclose(output); unlink(temp); }
    free(temp);
    if (!ok) return false;
    int fd = open_secure_read(path);
    unsigned char actual[32];
    ok = fd >= 0 && ct_fd_sha256(fd, actual) &&
         memcmp(actual, digest, 32u) == 0;
    if (fd >= 0) close(fd);
    return ok;
}

static qihse_kv_replica_snapshot_t* ct_open_baseline_snapshot(
    qihse_user_t* principal, const unsigned char expected_digest[32]) {
    char path[4096];
    if (!build_data_path(path, sizeof(path), "ct-baseline.qfs")) return NULL;
    int fd = open_secure_read(path);
    if (fd < 0) return NULL;
    struct stat st;
    unsigned char digest[32];
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        !ct_fd_sha256(fd, digest) ||
        memcmp(digest, expected_digest, 32u) != 0) {
        close(fd); return NULL;
    }
    qihse_kv_replica_snapshot_t* snapshot = calloc(1u, sizeof(*snapshot));
    if (!snapshot) { close(fd); return NULL; }
    snapshot->fd = fd;
    snapshot->size = (uint64_t)st.st_size;
    snapshot->principal = principal;
    snapshot->principal_id = qihse_user_get_id(principal);
    snapshot->tenant_id = qihse_user_get_tenant_id(principal);
    snapshot->classification = qihse_user_get_classification(principal);
    snapshot->sci = qihse_user_get_sci(principal);
    return snapshot;
}

int qihse_kv_ct_source_baseline_snapshot_create(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_kv_replica_snapshot_t** out_snapshot,
    uint64_t* out_baseline_row_seq, unsigned char out_digest[32]) {
    if (out_snapshot) *out_snapshot = NULL;
    if (out_baseline_row_seq) *out_baseline_row_seq = 0u;
    if (out_digest) memset(out_digest, 0, 32u);
    if (!store || !ct_replication_principal(store, principal) ||
        !out_snapshot || !out_baseline_row_seq || !out_digest) return -1;
    kv_store_rdlock(store);
    bool allowed = store->ct_enabled && store->ct_mode == 1u &&
        !store->recovery_pending;
    bool sealed = allowed && store->ct_baseline_sealed;
    unsigned char sealed_digest[32];
    memcpy(sealed_digest, store->ct_baseline_digest, 32u);
    uint64_t sealed_seq = store->ct_baseline_lsn;
    bool initial = allowed && !sealed && !store->ct_admitted &&
                   store->ct_durable_lsn == 0u;
    kv_store_unlock(store);
    if (!allowed) return -1;
    if (sealed) {
        qihse_kv_replica_snapshot_t* persisted =
            ct_open_baseline_snapshot(principal, sealed_digest);
        if (!persisted) return -1;
        *out_snapshot = persisted;
        *out_baseline_row_seq = sealed_seq;
        memcpy(out_digest, sealed_digest, 32u);
        return 0;
    }
    if (!initial) return -1;
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    int rc = qihse_kv_replica_snapshot_create(store, principal, "*", &snapshot);
    if (rc != 0) return rc;
    unsigned char digest[32];
    if (!ct_fd_sha256(snapshot->fd, digest)) {
        qihse_kv_replica_snapshot_destroy(snapshot);
        return -1;
    }
    kv_store_wrlock(store);
    allowed = store->ct_enabled && store->ct_mode == 1u &&
        !store->ct_admitted && store->ct_durable_lsn == 0u &&
        !store->recovery_pending;
    if (allowed && store->ct_baseline_sealed)
        allowed = memcmp(store->ct_baseline_digest, digest, 32u) == 0;
    if (allowed && !store->ct_baseline_sealed)
        allowed = ct_persist_baseline_fd(snapshot->fd, digest);
    if (allowed && !store->ct_baseline_sealed) {
        memcpy(store->ct_baseline_digest, digest, 32u);
        store->ct_baseline_sealed = true;
        allowed = ct_state_write(store);
        if (!allowed) {
            memset(store->ct_baseline_digest, 0, 32u);
            store->ct_baseline_sealed = false;
        }
    }
    if (allowed) *out_baseline_row_seq = store->ct_baseline_lsn;
    kv_store_unlock(store);
    if (!allowed) { qihse_kv_replica_snapshot_destroy(snapshot); return -1; }
    memcpy(out_digest, digest, 32u);
    *out_snapshot = snapshot;
    return 0;
}

bool qihse_kv_ct_source_ack(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* peer_id, const char* generation, uint64_t durable_lsn) {
    if (!store || !ct_replication_principal(store, principal) || !peer_id || !generation) return false;
    kv_store_wrlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 1u &&
        !store->recovery_pending &&
        store->ct_transfer_phase != 1u &&
        strcmp(store->ct_successor_id, peer_id) == 0 &&
        strcmp(store->ct_generation, generation) == 0 &&
        durable_lsn >= store->ct_ack_lsn &&
        durable_lsn <= store->ct_durable_lsn;
    if (ok && durable_lsn > store->ct_ack_lsn) {
        uint64_t prior = store->ct_ack_lsn;
        store->ct_ack_lsn = durable_lsn;
        if (!ct_state_write(store)) {
            store->ct_ack_lsn = prior;
            ok = false;
        }
    }
    if (ok && store->ct_ack_lsn == store->ct_durable_lsn &&
        store->ct_retained_bytes != 0u) {
        /* The SST and its directory entry must be durable before the only
         * recovery copy of an ACKed QKV6 frame can be retired. */
        if (!kv_sync_store_locked(store)) ok = false;
        if (ok) {
            store->ct_retained_bytes = 0u;
            if (!ct_state_write(store) || !rotate_wal_empty(store) ||
                !fsync_dir_path(get_qihse_data_dir())) {
                store->recovery_pending = true;
                ok = false;
            }
        }
    }
    if (ok) {
        pthread_mutex_lock(&store->ct_ack_lock);
        pthread_cond_broadcast(&store->ct_ack_changed);
        pthread_mutex_unlock(&store->ct_ack_lock);
    }
    kv_store_unlock(store);
    return ok;
}

static bool ct_source_reconcile_internal(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const char* peer_id, const char* generation,
    const unsigned char receiver_baseline_digest[32],
    uint64_t peer_durable_position) {
    if (!store || !ct_admin(principal) || !peer_id || !generation ||
        !receiver_baseline_digest) return false;
    kv_store_wrlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 1u &&
        !store->recovery_pending && store->ct_transfer_phase != 1u &&
        (!data_principal || (store->replication_principal_id != 0u &&
          qihse_auth_user_is_active(data_principal) &&
          qihse_user_get_id(data_principal) == store->replication_principal_id)) &&
        strcmp(store->ct_successor_id, peer_id) == 0 &&
        strcmp(store->ct_generation, generation) == 0 &&
        store->ct_baseline_sealed &&
        memcmp(store->ct_baseline_digest, receiver_baseline_digest, 32u) == 0 &&
        peer_durable_position >= store->ct_ack_lsn &&
        peer_durable_position <= store->ct_durable_lsn &&
        (store->ct_admitted || peer_durable_position == store->ct_durable_lsn);
    /* During initial admission the successor must prove the exact current cut.
     * Once admitted, a periodic reconcile can race a new local write after the
     * successor's STATUS read. Accept that older, still-monotonic durable cut
     * without claiming later groups: the ordinary ACK boundary advances only
     * to peer_durable_position, and the pull loop will ACK any newer groups. */
    if (ok && peer_durable_position > store->ct_ack_lsn) {
        uint64_t prior = store->ct_ack_lsn;
        store->ct_ack_lsn = peer_durable_position;
        if (!ct_state_write(store)) {
            store->ct_ack_lsn = prior;
            ok = false;
        }
    }
    if (ok) store->ct_admitted = true;
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_source_reconcile(qihse_kv_store_t* store,
    qihse_user_t* principal, const char* peer_id, const char* generation,
    const unsigned char receiver_baseline_digest[32],
    uint64_t peer_durable_position) {
    return ct_source_reconcile_internal(store, principal, NULL, peer_id,
        generation, receiver_baseline_digest, peer_durable_position);
}

bool qihse_kv_ct_source_reconcile_peer(qihse_kv_store_t* store,
    qihse_user_t* local_operator, qihse_user_t* replication_principal,
    const char* peer_id, const char* generation,
    const unsigned char receiver_baseline_digest[32],
    uint64_t peer_durable_position) {
    if (!replication_principal) return false;
    return ct_source_reconcile_internal(store, local_operator,
        replication_principal, peer_id, generation,
        receiver_baseline_digest, peer_durable_position);
}

void qihse_kv_ct_groups_free(qihse_kv_ct_group_t* groups, size_t count) {
    if (!groups) return;
    for (size_t i = 0; i < count; i++) qihse_ct_codec_clear(&groups[i]);
    free(groups);
}

bool qihse_kv_ct_source_read(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* generation, uint64_t after_seq, size_t max_groups,
    size_t max_bytes, qihse_kv_ct_group_t** out_groups, size_t* out_count,
    uint64_t* out_resume_seq) {
    if (out_groups) *out_groups = NULL;
    if (out_count) *out_count = 0u;
    if (out_resume_seq) *out_resume_seq = after_seq;
    if (!store || !ct_replication_principal(store, principal) || !generation || !out_groups ||
        !out_count || !out_resume_seq || max_groups == 0u || max_groups > 4096u ||
        max_bytes == 0u || max_bytes > QIHSE_KV_DURABLE_BATCH_MAX_BYTES) return false;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 1u &&
        !store->recovery_pending &&
        strcmp(store->ct_generation, generation) == 0 &&
        after_seq >= store->ct_ack_lsn && after_seq <= store->ct_durable_lsn;
    if (!ok) { kv_store_unlock(store); return false; }
    char path[4096];
    if (!build_data_path(path, sizeof(path), "wal.log")) {
        kv_store_unlock(store); return false;
    }
    int fd = open_secure_read(path);
    if (fd < 0) { kv_store_unlock(store); return false; }
    FILE* input = fdopen(fd, "rb");
    if (!input) { close(fd); kv_store_unlock(store); return false; }
    qihse_kv_ct_group_t* groups = calloc(max_groups, sizeof(*groups));
    if (!groups) { fclose(input); kv_store_unlock(store); return false; }
    size_t count = 0u, used = 0u;
    uint64_t cursor = after_seq;
    for (;;) {
        if (count == max_groups || used == max_bytes) break;
        qihse_kv_ct_group_t next = {0};
        uint8_t mode = 0u;
        size_t read_bytes = 0u;
        int rc = qihse_ct_codec_read(input, principal,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
            max_bytes - used, &next, &mode, &read_bytes);
        if (rc == 0) break;
        if (rc != 1 || mode != 1u ||
            strcmp(next.source_id, store->ct_source_id) != 0 ||
            strcmp(next.generation, store->ct_generation) != 0 ||
            next.stream_position > store->ct_durable_lsn) {
            qihse_ct_codec_clear(&next); ok = false; break;
        }
        if (next.stream_position <= after_seq) {
            qihse_ct_codec_clear(&next);
            continue;
        }
        if (count == max_groups || read_bytes > max_bytes - used) {
            qihse_ct_codec_clear(&next);
            if (count == 0u) ok = false;
            break;
        }
        if (next.stream_position != cursor + 1u) {
            qihse_ct_codec_clear(&next); ok = false; break;
        }
        groups[count++] = next;
        used += read_bytes;
        cursor = next.stream_position;
    }
    fclose(input);
    kv_store_unlock(store);
    if (!ok) { qihse_kv_ct_groups_free(groups, count); return false; }
    *out_groups = groups;
    *out_count = count;
    *out_resume_seq = cursor;
    return true;
}

bool qihse_kv_ct_receiver_bind(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* source_id, const char* target_id, const char* generation,
    qihse_kv_ct_tenant_policy_t tenant_policy, uint32_t tenant_id,
    uint64_t baseline_lsn,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(principal) || !ct_id_valid(source_id) ||
        !ct_id_valid(target_id) ||
        !ct_id_valid(generation) ||
        (tenant_policy != QIHSE_KV_CT_TENANT_EXACT &&
         tenant_policy != QIHSE_KV_CT_TENANT_SYSTEM_ALL) ||
        (tenant_policy == QIHSE_KV_CT_TENANT_SYSTEM_ALL && tenant_id != 0u) ||
        store->memory_snapshot) return false;
    kv_store_wrlock(store);
    bool ok = !store->ct_enabled && !store->recovery_pending &&
        !store->bulk_load_mode && !store->durable_batch_mode &&
        kv_sync_store_locked(store) && rotate_wal_empty(store) &&
        fsync_dir_path(get_qihse_data_dir());
    if (ok) {
        store->ct_enabled = true;
        store->ct_admitted = false;
        store->ct_mode = 2u;
        store->ct_system_principal = principal;
        store->ct_tenant_id = tenant_id;
        store->ct_tenant_policy = tenant_policy;
        store->ct_baseline_lsn = baseline_lsn;
        store->ct_baseline_sealed = false;
        store->ct_durable_lsn = 0u;
        store->ct_limit_bytes = 512u * 1024u * 1024u;
        snprintf(store->ct_source_id, sizeof(store->ct_source_id), "%s", source_id);
        snprintf(store->ct_target_id, sizeof(store->ct_target_id), "%s", target_id);
        snprintf(store->ct_generation, sizeof(store->ct_generation), "%s", generation);
        ok = ct_make_token(store->ct_owner_token, owner_token) && ct_state_write(store);
        if (!ok) { store->ct_enabled = false; store->ct_mode = 0u; }
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_receiver_status(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_kv_ct_receiver_status_t* out) {
    if (!store || !out || !ct_replication_principal(store, principal)) return false;
    memset(out, 0, sizeof(*out));
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 2u && !store->recovery_pending;
    if (ok) {
        snprintf(out->source_id, sizeof(out->source_id), "%s", store->ct_source_id);
        snprintf(out->generation, sizeof(out->generation), "%s", store->ct_generation);
        out->durable_cursor = store->ct_durable_lsn;
        out->tenant_id = store->ct_tenant_id;
        out->tenant_policy = store->ct_tenant_policy;
        out->baseline_sealed = store->ct_baseline_sealed;
        memcpy(out->baseline_digest, store->ct_baseline_digest,
               sizeof(out->baseline_digest));
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_fence_range(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* transfer_id, uint16_t first_slot, uint16_t last_slot,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t* out_cut_position) {
    if (out_cut_position) *out_cut_position = 0u;
    if (!store || !out_cut_position || !ct_admin(principal) ||
        !ct_id_valid(transfer_id) || first_slot > last_slot ||
        last_slot >= QIHSE_CLUSTER_SLOT_COUNT) return false;
    kv_store_wrlock(store);
    if (store->ct_enabled && store->ct_fence_state == 1u &&
        strcmp(store->ct_transfer_id, transfer_id) == 0 &&
        store->ct_fence_first == first_slot &&
        store->ct_fence_last == last_slot &&
        ct_token_matches(store, owner_token) && !store->recovery_pending) {
        *out_cut_position = store->ct_fence_cut_position;
        kv_store_unlock(store);
        return true;
    }
    bool ok = ct_token_matches(store, owner_token) &&
        !store->recovery_pending && store->ct_fence_state != 1u &&
        (store->ct_mode != 1u ||
         (store->ct_admitted && store->ct_ack_lsn == store->ct_durable_lsn));
    for (uint32_t slot = first_slot; ok && slot <= last_slot; slot++)
        if (store->ct_moved_slots[slot / 8u] & (1u << (slot % 8u))) ok = false;
    if (ok) {
        uint8_t prior_state = store->ct_fence_state;
        uint16_t prior_first = store->ct_fence_first;
        uint16_t prior_last = store->ct_fence_last;
        uint64_t prior_cut = store->ct_fence_cut_position;
        char prior_id[sizeof(store->ct_transfer_id)];
        char prior_target[sizeof(store->ct_target_id)];
        char prior_source[sizeof(store->ct_transfer_source_id)];
        char prior_generation[sizeof(store->ct_transfer_source_generation)];
        unsigned char prior_image[32], prior_group[32], prior_range[32];
        uint64_t prior_source_cut = store->ct_transfer_source_cut;
        uint64_t prior_target_position = store->ct_transfer_target_position;
        memcpy(prior_id, store->ct_transfer_id, sizeof(prior_id));
        memcpy(prior_target, store->ct_target_id, sizeof(prior_target));
        memcpy(prior_source, store->ct_transfer_source_id, sizeof(prior_source));
        memcpy(prior_generation, store->ct_transfer_source_generation,
               sizeof(prior_generation));
        memcpy(prior_image, store->ct_transfer_image_digest, 32u);
        memcpy(prior_group, store->ct_transfer_group_digest, 32u);
        memcpy(prior_range, store->ct_transfer_range_digest, 32u);
        if (store->ct_mode == 1u) store->ct_target_id[0] = '\0';
        store->ct_transfer_source_id[0] = '\0';
        store->ct_transfer_source_generation[0] = '\0';
        store->ct_transfer_source_cut = 0u;
        store->ct_transfer_target_position = 0u;
        store->ct_transfer_phase = 0u;
        memset(store->ct_transfer_image_digest, 0, 32u);
        memset(store->ct_transfer_group_digest, 0, 32u);
        memset(store->ct_transfer_range_digest, 0, 32u);
        store->ct_fence_state = 1u;
        store->ct_fence_first = first_slot;
        store->ct_fence_last = last_slot;
        store->ct_fence_cut_position = store->ct_durable_lsn;
        snprintf(store->ct_transfer_id, sizeof(store->ct_transfer_id), "%s", transfer_id);
        ok = ct_state_write(store);
        if (ok) *out_cut_position = store->ct_durable_lsn;
        else {
            store->ct_fence_state = prior_state;
            store->ct_fence_first = prior_first;
            store->ct_fence_last = prior_last;
            memcpy(store->ct_transfer_id, prior_id, sizeof(prior_id));
            memcpy(store->ct_target_id, prior_target, sizeof(prior_target));
            memcpy(store->ct_transfer_source_id, prior_source, sizeof(prior_source));
            memcpy(store->ct_transfer_source_generation, prior_generation,
                   sizeof(prior_generation));
            store->ct_transfer_source_cut = prior_source_cut;
            store->ct_transfer_target_position = prior_target_position;
            memcpy(store->ct_transfer_image_digest, prior_image, 32u);
            memcpy(store->ct_transfer_group_digest, prior_group, 32u);
            memcpy(store->ct_transfer_range_digest, prior_range, 32u);
            store->ct_fence_cut_position = prior_cut;
        }
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_target_prepare(qihse_kv_store_t* store,
    qihse_user_t* principal,
    const qihse_kv_ct_target_receipt_claim_t* source_prepared_claim,
    qihse_kv_ct_receipt_verify_fn verify_source_prepared,
    void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t* out_local_cut) {
    if (out_local_cut) *out_local_cut = 0u;
    if (!store || !ct_admin(principal) || !source_prepared_claim ||
        !verify_source_prepared || !owner_token || !out_local_cut) return false;
    qihse_kv_ct_target_receipt_claim_t claim = *source_prepared_claim;
    if (!ct_id_valid(claim.transfer_id) || !ct_id_valid(claim.source_id) ||
        !ct_id_valid(claim.target_id) || !ct_id_valid(claim.generation) ||
        claim.first_slot > claim.last_slot ||
        claim.last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !verify_source_prepared(&claim, verify_context)) return false;
    kv_store_wrlock(store);
    bool ok = ct_token_matches(store, owner_token) &&
        !store->recovery_pending && store->ct_mode == 1u &&
        strcmp(store->ct_source_id, claim.target_id) == 0;
    if (ok && store->ct_fence_state == 3u &&
        strcmp(store->ct_transfer_id, claim.transfer_id) == 0) {
        ok = store->ct_fence_first == claim.first_slot &&
            store->ct_fence_last == claim.last_slot &&
            strcmp(store->ct_transfer_source_id, claim.source_id) == 0 &&
            strcmp(store->ct_transfer_source_generation, claim.generation) == 0 &&
            store->ct_transfer_source_cut == claim.source_cut &&
            memcmp(store->ct_transfer_range_digest,
                   claim.range_checksum, 32u) == 0;
        if (ok) *out_local_cut = store->ct_fence_cut_position;
        kv_store_unlock(store);
        return ok;
    }
    ok = ok && store->ct_admitted &&
         store->ct_ack_lsn == store->ct_durable_lsn;
    if (ok && store->ct_fence_state == 1u) {
        ok = strcmp(store->ct_transfer_id, claim.transfer_id) == 0 &&
            store->ct_fence_first == claim.first_slot &&
            store->ct_fence_last == claim.last_slot &&
            strcmp(store->ct_transfer_source_id, claim.source_id) == 0 &&
            strcmp(store->ct_transfer_source_generation, claim.generation) == 0 &&
            store->ct_transfer_source_cut == claim.source_cut &&
            memcmp(store->ct_transfer_range_digest,
                   claim.range_checksum, 32u) == 0;
        if (ok) *out_local_cut = store->ct_fence_cut_position;
        kv_store_unlock(store);
        return ok;
    }
    ok = ok && store->ct_transfer_phase == 0u;
    if (ok) {
        store->ct_fence_state = 1u;
        store->ct_fence_first = claim.first_slot;
        store->ct_fence_last = claim.last_slot;
        store->ct_fence_cut_position = store->ct_durable_lsn;
        snprintf(store->ct_transfer_id, sizeof(store->ct_transfer_id),
                 "%s", claim.transfer_id);
        snprintf(store->ct_transfer_source_id,
                 sizeof(store->ct_transfer_source_id), "%s", claim.source_id);
        snprintf(store->ct_transfer_source_generation,
                 sizeof(store->ct_transfer_source_generation), "%s",
                 claim.generation);
        store->ct_transfer_source_cut = claim.source_cut;
        store->ct_transfer_target_position = 0u;
        memcpy(store->ct_transfer_range_digest,
               claim.range_checksum, 32u);
        memset(store->ct_transfer_image_digest, 0, 32u);
        memset(store->ct_transfer_group_digest, 0, 32u);
        ok = ct_state_write(store);
        if (ok) *out_local_cut = store->ct_fence_cut_position;
        else store->recovery_pending = true;
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_target_abort(qihse_kv_store_t* store,
    qihse_user_t* principal,
    const qihse_kv_ct_target_receipt_claim_t* source_aborted_claim,
    qihse_kv_ct_receipt_verify_fn verify_source_aborted,
    void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(principal) || !source_aborted_claim ||
        !verify_source_aborted || !owner_token) return false;
    qihse_kv_ct_target_receipt_claim_t claim = *source_aborted_claim;
    if (!ct_id_valid(claim.transfer_id) || !ct_id_valid(claim.source_id) ||
        !ct_id_valid(claim.target_id) || !ct_id_valid(claim.generation) ||
        claim.first_slot > claim.last_slot ||
        claim.last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !verify_source_aborted(&claim, verify_context)) return false;
    kv_store_wrlock(store);
    bool ok = ct_token_matches(store, owner_token) &&
        !store->recovery_pending && store->ct_mode == 1u &&
        strcmp(store->ct_transfer_id, claim.transfer_id) == 0 &&
        strcmp(store->ct_transfer_source_id, claim.source_id) == 0 &&
        strcmp(store->ct_source_id, claim.target_id) == 0 &&
        strcmp(store->ct_transfer_source_generation, claim.generation) == 0 &&
        store->ct_fence_first == claim.first_slot &&
        store->ct_fence_last == claim.last_slot &&
        store->ct_transfer_source_cut == claim.source_cut &&
        memcmp(store->ct_transfer_range_digest,
               claim.range_checksum, 32u) == 0;
    if (ok && store->ct_fence_state == 4u) {
        kv_store_unlock(store);
        return true;
    }
    ok = ok && store->ct_fence_state == 1u &&
        store->ct_transfer_phase == 0u;
    if (ok) {
        store->ct_fence_state = 4u;
        ok = ct_state_write(store);
        if (!ok) store->ct_fence_state = 1u;
    }
    kv_store_unlock(store);
    return ok;
}

static void ct_transfer_status_fill_locked(qihse_kv_store_t* store,
    qihse_kv_ct_transfer_status_t* out) {
    out->mode = store->ct_mode;
    out->fence_state = store->ct_fence_state;
    out->transfer_phase = store->ct_transfer_phase;
    out->first_slot = store->ct_fence_first;
    out->last_slot = store->ct_fence_last;
    out->cut_position = store->ct_fence_cut_position;
    memcpy(out->transfer_id, store->ct_transfer_id, sizeof(out->transfer_id));
    memcpy(out->source_id, store->ct_source_id, sizeof(out->source_id));
    memcpy(out->target_id, store->ct_target_id, sizeof(out->target_id));
    memcpy(out->generation, store->ct_generation, sizeof(out->generation));
}

bool qihse_kv_ct_transfer_status(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_kv_ct_transfer_status_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store || !out || !ct_admin(control_principal)) return false;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && !store->recovery_pending &&
        ct_admin(control_principal);
    if (ok) ct_transfer_status_fill_locked(store, out);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_transfer_status_detail(qihse_kv_store_t* store,
    qihse_user_t* control_principal,
    qihse_kv_ct_transfer_status_detail_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store || !out || !ct_admin(control_principal)) return false;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && !store->recovery_pending &&
        ct_admin(control_principal);
    if (ok) {
        ct_transfer_status_fill_locked(store, &out->base);
        memcpy(out->transfer_source_id, store->ct_transfer_source_id,
               sizeof(out->transfer_source_id));
        memcpy(out->transfer_source_generation,
               store->ct_transfer_source_generation,
               sizeof(out->transfer_source_generation));
        out->transfer_source_cut = store->ct_transfer_source_cut;
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_fence_finish(qihse_kv_store_t* store, qihse_user_t* principal,
    const char* transfer_id, bool transferred,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    /* A caller assertion is never evidence of target durability. CT2 commit
     * uses the proof-consuming completion path below. */
    if (transferred) { errno = EACCES; return false; }
    if (!store || !ct_admin(principal) || !transfer_id) return false;
    kv_store_wrlock(store);
    bool ok = ct_token_matches(store, owner_token) &&
        !store->recovery_pending && store->ct_fence_state == 1u &&
        store->ct_transfer_phase == 0u &&
        store->ct_transfer_source_id[0] == '\0' &&
        strcmp(store->ct_transfer_id, transfer_id) == 0;
    if (ok) {
        unsigned char prior[sizeof(store->ct_moved_slots)];
        memcpy(prior, store->ct_moved_slots, sizeof(prior));
        uint16_t prior_first = store->ct_fence_first;
        uint16_t prior_last = store->ct_fence_last;
        uint64_t prior_cut = store->ct_fence_cut_position;
        char prior_id[sizeof(store->ct_transfer_id)];
        char prior_target[sizeof(store->ct_target_id)];
        memcpy(prior_id, store->ct_transfer_id, sizeof(prior_id));
        memcpy(prior_target, store->ct_target_id, sizeof(prior_target));
        store->ct_fence_state = 0u;
        store->ct_fence_first = store->ct_fence_last = 0u;
        store->ct_fence_cut_position = 0u;
        store->ct_transfer_id[0] = '\0';
        store->ct_target_id[0] = '\0';
        ok = ct_state_write(store);
        if (!ok) {
            store->ct_fence_state = 1u;
            memcpy(store->ct_moved_slots, prior, sizeof(prior));
            store->ct_fence_first = prior_first;
            store->ct_fence_last = prior_last;
            store->ct_fence_cut_position = prior_cut;
            memcpy(store->ct_transfer_id, prior_id, sizeof(prior_id));
            memcpy(store->ct_target_id, prior_target, sizeof(prior_target));
        }
    }
    kv_store_unlock(store);
    return ok;
}

static bool ct_proof_mac(qihse_kv_store_t* store,
                         const qihse_kv_ct_proof_t* proof,
                         unsigned char out[32]) {
    unsigned int len = 0u;
    return HMAC(EVP_sha256(), store->ct_owner_token,
                (int)sizeof(store->ct_owner_token),
                (const unsigned char*)proof,
                offsetof(qihse_kv_ct_proof_t, mac), out, &len) != NULL &&
           len == 32u;
}

static bool ct_proof_data_context_valid(const qihse_kv_ct_proof_t* proof,
                                        qihse_user_t* data_principal) {
    if (!proof) return false;
    if (proof->kind == 1u) return data_principal == NULL;
    return data_principal && proof->data_principal == data_principal &&
        qihse_auth_validate_handle_generation(data_principal,
                                              proof->data_generation) &&
        proof->data_principal_id == qihse_user_get_id(data_principal) &&
        proof->data_tenant_id == qihse_user_get_tenant_id(data_principal) &&
        proof->data_classification == qihse_user_get_classification(data_principal) &&
        proof->data_sci == qihse_user_get_sci(data_principal);
}

static bool ct_range_proof_state_locked(qihse_kv_store_t* store,
    uint32_t kind, const char* transfer_id, const char* source_id,
    const char* target_id, const char* generation, uint16_t first_slot,
    uint16_t last_slot, uint64_t source_lsn, uint64_t target_lsn) {
    if (!store->ct_enabled || store->recovery_pending ||
        store->ct_fence_state != 1u ||
        strcmp(store->ct_transfer_id, transfer_id) != 0 ||
        store->ct_fence_first != first_slot ||
        store->ct_fence_last != last_slot) return false;
    if (kind == 2u)
        return store->ct_mode == 1u && store->ct_baseline_sealed &&
            strcmp(store->ct_source_id, source_id) == 0 &&
            strcmp(store->ct_target_id, target_id) == 0 &&
            strcmp(store->ct_generation, generation) == 0 &&
            store->ct_fence_cut_position == source_lsn &&
            store->ct_ack_lsn >= source_lsn && target_lsn == 0u;
    if (kind == 3u && store->ct_mode == 2u)
        return store->ct_baseline_sealed &&
            strcmp(store->ct_source_id, source_id) == 0 &&
            strcmp(store->ct_target_id, target_id) == 0 &&
            strcmp(store->ct_generation, generation) == 0 &&
            store->ct_fence_cut_position >= source_lsn &&
            store->ct_durable_lsn >= source_lsn &&
            store->ct_durable_lsn == target_lsn;
    if (kind == 3u)
        return store->ct_mode == 1u && store->ct_baseline_sealed &&
            store->ct_transfer_phase == 2u &&
            strcmp(store->ct_transfer_source_id, source_id) == 0 &&
            strcmp(store->ct_source_id, target_id) == 0 &&
            strcmp(store->ct_transfer_source_generation, generation) == 0 &&
            store->ct_transfer_source_cut == source_lsn &&
            store->ct_transfer_target_position == target_lsn &&
            store->ct_ack_lsn >= target_lsn;
    return false;
}

static bool ct_proof_valid_locked(qihse_kv_store_t* store,
                                  const qihse_kv_ct_proof_t* proof) {
    if (!store || !proof || !store->ct_enabled || store->recovery_pending ||
        proof->store_instance_id != store->instance_id) return false;
    unsigned char mac[32];
    if (!ct_proof_mac(store, proof, mac)) return false;
    unsigned mismatch = 0u;
    for (size_t i = 0; i < sizeof(mac); i++) mismatch |= mac[i] ^ proof->mac[i];
    if (mismatch) return false;
    if (!ct_proof_data_context_valid(proof, proof->data_principal)) return false;
    if (proof->kind == 1u)
        return store->ct_mode == 2u && store->ct_baseline_sealed &&
            strcmp(store->ct_source_id, proof->source_id) == 0 &&
            strcmp(store->ct_target_id, proof->target_id) == 0 &&
            strcmp(store->ct_generation, proof->generation) == 0 &&
            store->ct_durable_lsn >= proof->source_lsn &&
            proof->target_lsn == store->ct_durable_lsn &&
            memcmp(proof->checksum, store->ct_baseline_digest, 32u) == 0;
    if (proof->kind == 2u || proof->kind == 3u)
        return ct_range_proof_state_locked(store, proof->kind,
            proof->transfer_id, proof->source_id, proof->target_id,
            proof->generation, proof->first_slot, proof->last_slot,
            proof->source_lsn, proof->target_lsn);
    return false;
}

qihse_kv_ct_proof_t* qihse_kv_ct_promotion_proof_create(
    qihse_kv_store_t* store, qihse_user_t* principal, const char* source_id,
    const char* target_id, const char* generation, uint64_t handoff_lsn) {
    if (!store || !ct_admin(principal) || !source_id || !target_id ||
        !generation) return NULL;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 2u &&
        store->ct_baseline_sealed && !store->recovery_pending &&
        strcmp(store->ct_source_id, source_id) == 0 &&
        strcmp(store->ct_target_id, target_id) == 0 &&
        strcmp(store->ct_generation, generation) == 0 &&
        store->ct_durable_lsn >= handoff_lsn;
    qihse_kv_ct_proof_t* proof = ok ? calloc(1u, sizeof(*proof)) : NULL;
    if (proof) {
        proof->kind = 1u;
        proof->store_instance_id = store->instance_id;
        snprintf(proof->source_id, sizeof(proof->source_id), "%s", source_id);
        snprintf(proof->target_id, sizeof(proof->target_id), "%s", target_id);
        snprintf(proof->generation, sizeof(proof->generation), "%s", generation);
        proof->source_lsn = handoff_lsn;
        proof->target_lsn = store->ct_durable_lsn;
        memcpy(proof->checksum, store->ct_baseline_digest, 32u);
        if (!ct_proof_mac(store, proof, proof->mac)) {
            free(proof); proof = NULL;
        }
    }
    kv_store_unlock(store);
    return proof;
}

/* A local proof binds the durable fence, the actual canonical range image,
 * and the exact ACKed target stream position. */
static qihse_kv_ct_proof_t* ct_range_proof_create(
    qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, uint32_t kind,
    const char* transfer_id, const char* source_id, const char* target_id,
    const char* generation, uint16_t first_slot, uint16_t last_slot,
    uint64_t source_lsn) {
    if (!store || !ct_admin(principal) || !data_principal ||
        !qihse_auth_user_is_active(data_principal) ||
        !ct_id_valid(transfer_id) ||
        !ct_id_valid(source_id) || !ct_id_valid(target_id) ||
        !ct_id_valid(generation) || first_slot > last_slot ||
        last_slot >= QIHSE_CLUSTER_SLOT_COUNT) return NULL;
    uint32_t data_id = qihse_user_get_id(data_principal);
    uint32_t data_tenant = qihse_user_get_tenant_id(data_principal);
    uint16_t data_class = qihse_user_get_classification(data_principal);
    uint16_t data_sci = qihse_user_get_sci(data_principal);
    uint64_t data_generation = 0u;
    qihse_user_t* borrowed = qihse_auth_borrow_principal_scoped(
        data_id, &data_generation);
    if (borrowed != data_principal || data_generation == 0u) {
        qihse_auth_release_principal_scoped(borrowed);
        return NULL;
    }
    kv_store_rdlock(store);
    bool source = kind == 2u;
    uint64_t target_lsn = source ? 0u :
        (store->ct_mode == 2u ? store->ct_durable_lsn :
         store->ct_transfer_target_position);
    bool ok = ct_range_proof_state_locked(store, kind, transfer_id,
        source_id, target_id, generation, first_slot, last_slot,
        source_lsn, target_lsn);
    kv_store_unlock(store);
    if (!ok) {
        qihse_auth_release_principal_scoped(borrowed);
        return NULL;
    }
    unsigned char digest[32];
    if (!ct_range_digest(store, data_principal, first_slot, last_slot, digest) ||
        !qihse_auth_user_is_active(data_principal) ||
        qihse_user_get_id(data_principal) != data_id ||
        qihse_user_get_tenant_id(data_principal) != data_tenant ||
        qihse_user_get_classification(data_principal) != data_class ||
        qihse_user_get_sci(data_principal) != data_sci ||
        !qihse_auth_validate_handle_generation(data_principal,
                                               data_generation)) {
        qihse_auth_release_principal_scoped(borrowed);
        return NULL;
    }
    kv_store_rdlock(store);
    if (kind == 3u && store->ct_mode == 1u &&
        memcmp(digest, store->ct_transfer_range_digest, 32u) != 0) {
        kv_store_unlock(store);
        qihse_auth_release_principal_scoped(borrowed);
        return NULL;
    }
    ok = ct_range_proof_state_locked(store, kind, transfer_id,
        source_id, target_id, generation, first_slot, last_slot,
        source_lsn, target_lsn);
    qihse_kv_ct_proof_t* proof = ok ? calloc(1u, sizeof(*proof)) : NULL;
    if (proof) {
        proof->kind = kind;
        proof->store_instance_id = store->instance_id;
        proof->data_principal = borrowed;
        proof->data_generation = data_generation;
        proof->data_principal_id = data_id;
        proof->data_tenant_id = data_tenant;
        proof->data_classification = data_class;
        proof->data_sci = data_sci;
        snprintf(proof->transfer_id, sizeof(proof->transfer_id), "%s", transfer_id);
        snprintf(proof->source_id, sizeof(proof->source_id), "%s", source_id);
        snprintf(proof->target_id, sizeof(proof->target_id), "%s", target_id);
        snprintf(proof->generation, sizeof(proof->generation), "%s", generation);
        proof->first_slot = first_slot;
        proof->last_slot = last_slot;
        proof->source_lsn = source_lsn;
        proof->target_lsn = target_lsn;
        memcpy(proof->checksum, digest, 32u);
        if (!ct_proof_mac(store, proof, proof->mac)) {
            free(proof); proof = NULL;
        } else {
            borrowed = NULL; /* proof owns the scoped handle */
        }
    }
    kv_store_unlock(store);
    qihse_auth_release_principal_scoped(borrowed);
    return proof;
}

qihse_kv_ct_proof_t* qihse_kv_ct_target_seal_create(
    qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, const char* transfer_id,
    const char* source_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn) {
    return ct_range_proof_create(store, principal, data_principal, 3u,
                                 transfer_id, source_id,
                                 target_id, generation, first_slot, last_slot,
                                 source_lsn);
}

qihse_kv_ct_proof_t* qihse_kv_ct_source_transfer_proof_create(
    qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, const char* transfer_id,
    const char* source_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_lsn) {
    return ct_range_proof_create(store, principal, data_principal, 2u,
                                 transfer_id, source_id,
                                 target_id, generation, first_slot, last_slot,
                                 source_lsn);
}

bool qihse_kv_ct_proof_validate(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const qihse_kv_ct_proof_t* proof) {
    if (!store || !ct_admin(principal) || !proof) return false;
    kv_store_rdlock(store);
    bool ok = ct_proof_data_context_valid(proof, data_principal) &&
        ct_proof_valid_locked(store, proof);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_source_fence_commit(qihse_kv_store_t* store,
    qihse_user_t* principal, const qihse_kv_ct_proof_t* source_proof,
    const qihse_kv_ct_target_receipt_claim_t* target_claim,
    qihse_kv_ct_receipt_verify_fn verify_receipt, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(principal) || !target_claim || !verify_receipt ||
        !owner_token) return false;
    qihse_kv_ct_target_receipt_claim_t claim = *target_claim;
    if (!ct_id_valid(claim.transfer_id) || !ct_id_valid(claim.source_id) ||
        !ct_id_valid(claim.target_id) || !ct_id_valid(claim.generation) ||
        claim.first_slot > claim.last_slot ||
        claim.last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !verify_receipt(&claim, verify_context)) return false;
    kv_store_wrlock(store);
    bool ok = ct_token_matches(store, owner_token) &&
        !store->recovery_pending && store->ct_mode == 1u &&
        strcmp(store->ct_source_id, claim.source_id) == 0 &&
        strcmp(store->ct_target_id, claim.target_id) == 0 &&
        strcmp(store->ct_generation, claim.generation) == 0 &&
        strcmp(store->ct_transfer_id, claim.transfer_id) == 0 &&
        store->ct_fence_first == claim.first_slot &&
        store->ct_fence_last == claim.last_slot &&
        store->ct_fence_cut_position == claim.source_cut;
    if (ok && store->ct_fence_state == 2u) {
        ok = memcmp(store->ct_transfer_image_digest,
                    claim.range_checksum, 32u) == 0 &&
             store->ct_transfer_target_position == claim.target_durable_cursor;
        kv_store_unlock(store);
        return ok;
    }
    ok = ok && store->ct_fence_state == 1u && source_proof &&
        source_proof->kind == 2u && ct_proof_valid_locked(store, source_proof) &&
        strcmp(source_proof->transfer_id, claim.transfer_id) == 0 &&
        source_proof->first_slot == claim.first_slot &&
        source_proof->last_slot == claim.last_slot &&
        source_proof->source_lsn == claim.source_cut &&
        memcmp(source_proof->checksum, claim.range_checksum, 32u) == 0;
    if (ok) {
        unsigned char prior_slots[sizeof(store->ct_moved_slots)];
        memcpy(prior_slots, store->ct_moved_slots, sizeof(prior_slots));
        store->ct_fence_state = 2u;
        for (uint32_t slot = claim.first_slot; slot <= claim.last_slot; slot++)
            store->ct_moved_slots[slot / 8u] |= (unsigned char)(1u << (slot % 8u));
        memcpy(store->ct_transfer_image_digest, claim.range_checksum, 32u);
        store->ct_transfer_target_position = claim.target_durable_cursor;
        ok = ct_state_write(store);
        if (!ok) {
            store->ct_fence_state = 1u;
            memcpy(store->ct_moved_slots, prior_slots, sizeof(prior_slots));
            memset(store->ct_transfer_image_digest, 0, 32u);
            store->ct_transfer_target_position = 0u;
        }
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_target_activate(qihse_kv_store_t* store,
    qihse_user_t* principal, const qihse_kv_ct_proof_t* target_seal,
    const qihse_kv_ct_target_receipt_claim_t* source_commit_claim,
    qihse_kv_ct_receipt_verify_fn verify_source_commit, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(principal) || !source_commit_claim ||
        !verify_source_commit || !owner_token) return false;
    qihse_kv_ct_target_receipt_claim_t claim = *source_commit_claim;
    if (!ct_id_valid(claim.transfer_id) || !ct_id_valid(claim.source_id) ||
        !ct_id_valid(claim.target_id) || !ct_id_valid(claim.generation) ||
        claim.first_slot > claim.last_slot ||
        claim.last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !verify_source_commit(&claim, verify_context)) return false;
    kv_store_wrlock(store);
    bool ok = ct_token_matches(store, owner_token) &&
        !store->recovery_pending && store->ct_mode == 1u &&
        strcmp(store->ct_transfer_id, claim.transfer_id) == 0 &&
        strcmp(store->ct_transfer_source_id, claim.source_id) == 0 &&
        strcmp(store->ct_source_id, claim.target_id) == 0 &&
        strcmp(store->ct_transfer_source_generation, claim.generation) == 0 &&
        store->ct_fence_first == claim.first_slot &&
        store->ct_fence_last == claim.last_slot &&
        store->ct_transfer_source_cut == claim.source_cut &&
        store->ct_transfer_target_position == claim.target_durable_cursor &&
        (store->ct_fence_state != 3u ||
         memcmp(store->ct_transfer_range_digest,
                claim.range_checksum, 32u) == 0);
    if (ok && store->ct_fence_state == 3u) {
        kv_store_unlock(store);
        return true;
    }
    ok = ok && store->ct_fence_state == 1u &&
        store->ct_transfer_phase == 2u &&
        store->ct_ack_lsn >= store->ct_transfer_target_position &&
        target_seal && target_seal->kind == 3u &&
        ct_proof_valid_locked(store, target_seal) &&
        memcmp(target_seal->checksum, claim.range_checksum, 32u) == 0;
    if (ok) {
        unsigned char prior_slots[sizeof(store->ct_moved_slots)];
        memcpy(prior_slots, store->ct_moved_slots, sizeof(prior_slots));
        store->ct_fence_state = 3u;
        store->ct_transfer_phase = 0u;
        for (uint32_t slot = claim.first_slot; slot <= claim.last_slot; slot++)
            store->ct_moved_slots[slot / 8u] &=
                (unsigned char)~(1u << (slot % 8u));
        ok = ct_state_write(store);
        if (!ok) {
            store->ct_fence_state = 1u;
            store->ct_transfer_phase = 2u;
            memcpy(store->ct_moved_slots, prior_slots,
                   sizeof(prior_slots));
        }
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_proof_fields(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const qihse_kv_ct_proof_t* proof,
    const char** out_transfer_id, const char** out_source_id,
    const char** out_target_id, const char** out_generation,
    uint16_t* out_first_slot, uint16_t* out_last_slot,
    uint64_t* out_source_lsn, uint64_t* out_target_lsn,
    unsigned char out_checksum[32]) {
    if (!store || !ct_admin(principal) || !proof) return false;
    kv_store_rdlock(store);
    bool valid = ct_proof_data_context_valid(proof, data_principal) &&
        ct_proof_valid_locked(store, proof);
    if (!valid) { kv_store_unlock(store); return false; }
    if (out_transfer_id) *out_transfer_id = proof->transfer_id;
    if (out_source_id) *out_source_id = proof->source_id;
    if (out_target_id) *out_target_id = proof->target_id;
    if (out_generation) *out_generation = proof->generation;
    if (out_first_slot) *out_first_slot = proof->first_slot;
    if (out_last_slot) *out_last_slot = proof->last_slot;
    if (out_source_lsn) *out_source_lsn = proof->source_lsn;
    if (out_target_lsn) *out_target_lsn = proof->target_lsn;
    if (out_checksum) memcpy(out_checksum, proof->checksum, 32u);
    kv_store_unlock(store);
    return true;
}

void qihse_kv_ct_proof_destroy(qihse_kv_ct_proof_t* proof) {
    if (!proof) return;
    qihse_auth_release_principal_scoped(proof->data_principal);
    memset(proof, 0, sizeof(*proof));
    free(proof);
}

bool qihse_kv_ct_receiver_promote(qihse_kv_store_t* store,
    qihse_user_t* principal, const qihse_kv_ct_proof_t* proof,
    const char* new_generation, const char* new_successor_id,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(principal) || !ct_id_valid(new_generation) ||
        !ct_id_valid(new_successor_id)) return false;
    kv_store_wrlock(store);
    bool ok = ct_token_matches(store, owner_token) &&
        ct_proof_valid_locked(store, proof) && proof->kind == 1u &&
        strcmp(store->ct_generation, new_generation) != 0 &&
        store->ct_fence_state == 0u && kv_sync_store_locked(store) &&
        rotate_wal_empty(store) && fsync_dir_path(get_qihse_data_dir());
    if (ok) {
        store->ct_mode = 1u;
        store->ct_admitted = false;
        snprintf(store->ct_source_id, sizeof(store->ct_source_id), "%s",
                 proof->target_id);
        snprintf(store->ct_successor_id, sizeof(store->ct_successor_id), "%s",
                 new_successor_id);
        store->ct_target_id[0] = '\0';
        snprintf(store->ct_generation, sizeof(store->ct_generation), "%s",
                 new_generation);
        store->ct_baseline_lsn = __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE);
        store->ct_baseline_sealed = false;
        memset(store->ct_baseline_digest, 0, 32u);
        store->ct_durable_lsn = 0u;
        store->ct_ack_lsn = 0u;
        store->ct_retained_bytes = 0u;
        store->ct_limit_bytes = 512u * 1024u * 1024u;
        memset(store->ct_last_group_digest, 0, 32u);
        ok = ct_state_write(store);
        if (!ok) store->recovery_pending = true;
    }
    kv_store_unlock(store);
    return ok;
}

void qihse_kv_store_destroy(qihse_kv_store_t* store) {
    if (!store) return;
    if (store->qdd_ctx) qihse_qdd_free(__atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE));
    if (store->wal_fd) { flush_wal_buffer(store); fclose(store->wal_fd); }
    sst_fd_cache_clear(store);
    pthread_mutex_destroy(&store->sst_fd_lock);
    pthread_cond_destroy(&store->ct_ack_changed);
    pthread_mutex_destroy(&store->ct_ack_lock);
    pthread_rwlock_destroy(&store->store_lock);
    if (store->trie) qihse_trinary_trie_destroy(store->trie);
    sst_meta_index_destroy(store->sst_meta);
    cursor_list_free(store->replica_cursors);
    free(store);
}

const char* qihse_kv_store_data_directory(qihse_kv_store_t* store) {
    if (!store || store->memory_snapshot || __atomic_load_n(&store->recovery_pending, __ATOMIC_ACQUIRE)) return NULL;
    return get_qihse_data_dir();
}

void qihse_kv_bulk_load_begin(qihse_kv_store_t* store) {
    if (!store || store->memory_snapshot) return;
    kv_store_wrlock(store);
    if (!store->recovery_pending && !store->ct_enabled) store->bulk_load_mode = true;
    kv_store_unlock(store);
}
void qihse_kv_bulk_load_end(qihse_kv_store_t* store) {
    if (!store || store->memory_snapshot) return;
    kv_store_wrlock(store);
    if (!store->recovery_pending) {
        store->bulk_load_mode = false;
        flush_wal_buffer(store);
    }
    kv_store_unlock(store);
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
static bool kv_del_user_impl(qihse_kv_store_t* store, const char* key,
                             qihse_user_t* user, uint64_t* out_change_seq);

static bool set_user_preflight(qihse_kv_store_t* store, const char* key, const char* value,
                                uint16_t classification, uint16_t sci_compartment,
                                qihse_user_t* user) {
    if (!store || !store->trie || __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) ||
        !key || !value || key[0] == '\0') return false;
    if (store->ct_enabled && (store->ct_mode != 1u ||
        !ct_write_allowed(store, user, key))) return false;
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
    if (key_exists && store->ct_enabled &&
        (classification < ex_class ||
         (sci_compartment & ex_comp) != ex_comp)) return false;
    return !key_exists || qihse_auth_can_access(user, ex_class, ex_comp);
}

static bool set_user_with_expiry(qihse_kv_store_t* store, const char* key, const char* value,
                                 uint64_t expire_time_ms, uint16_t classification,
                                 uint16_t sci_compartment, qihse_user_t* user,
                                 uint64_t* out_change_seq) {
    if (out_change_seq) *out_change_seq = 0u;
    if (!set_user_preflight(store, key, value, classification, sci_compartment, user)) return false;
    if (store->ct_enabled &&
        !ct_source_record(store, user, key, value, 1u, expire_time_ms,
                          classification, sci_compartment, false, true,
                          QIHSE_KV_CT_ACTOR_USER)) return false;
    /* Authorized mutation: issue the change sequence BEFORE any side effect,
     * so a failure after this point at worst skips a number (monotonicity is
     * what matters, not density) and no unauthorized mutation ever advances
     * or receives one. */
    uint64_t seq = kv_change_seq_next(store);
    if (seq == 0u) return false;
    bool logged = store->ct_enabled
        ? ct_source_record(store, user, key, value, seq, expire_time_ms,
                           classification, sci_compartment, false, false,
                           QIHSE_KV_CT_ACTOR_USER)
        : wal_append(store, KV_WAL_OP_SET, key, value, expire_time_ms,
                     classification, sci_compartment, 0u, seq);
    if (!logged) return false;
    if (!insert_internal(store, key, value, expire_time_ms, classification,
                         sci_compartment, 0u, seq)) {
        if (store->ct_enabled) store->recovery_pending = true;
        return false;
    }
    if (!store->bulk_load_mode && !store->durable_batch_mode &&
        store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) return false;
    if (out_change_seq) *out_change_seq = seq;
    return true;
}

static int batch_key_compare(const void* a, const void* b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

bool qihse_kv_set_batch_durable_user(qihse_kv_store_t* store,
                                     const qihse_kv_batch_set_record_t* records,
                                     size_t count, qihse_user_t* user) {
    if (!store || !records || count == 0u ||
        count > QIHSE_KV_DURABLE_BATCH_MAX_RECORDS || !user) return false;
    const char** keys = malloc(count * sizeof(*keys));
    if (!keys) return false;
    bool ok = false;
    kv_store_wrlock(store);
    if (!store->trie || !store->wal_fd || store->recovery_pending ||
        store->bulk_load_mode || store->durable_batch_mode ||
        __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) ||
        !qihse_auth_user_is_active(user) ||
        count > UINT64_MAX - __atomic_load_n(&store->change_seq, __ATOMIC_RELAXED)) goto done;
    size_t bytes = 0u;
    for (size_t i = 0u; i < count; i++) {
        const qihse_kv_batch_set_record_t* r = &records[i];
        if (!r->key || !r->value) goto done;
        size_t k = strnlen(r->key, KV_MAX_KEY_LEN + 1u);
        size_t v = strnlen(r->value, KV_MAX_VALUE_LEN + 1u);
        if (k == 0u || k > KV_MAX_KEY_LEN || v > KV_MAX_VALUE_LEN) goto done;
        size_t record_bytes = 40u + k + v;
        if (record_bytes > QIHSE_KV_DURABLE_BATCH_MAX_BYTES - bytes) goto done;
        bytes += record_bytes;
        keys[i] = r->key;
        if (!set_user_preflight(store, r->key, r->value,
                                r->classification, r->sci_compartment, user)) goto done;
    }
    qsort(keys, count, sizeof(*keys), batch_key_compare);
    for (size_t i = 1u; i < count; i++) {
        if (strcmp(keys[i - 1u], keys[i]) == 0) goto done;
    }

    if (store->ct_enabled) {
        if (store->ct_mode != 1u || !store->ct_admitted ||
            store->ct_durable_lsn == UINT64_MAX) goto done;
        qihse_kv_ct_record_t* rows = calloc(count, sizeof(*rows));
        if (!rows) goto done;
        qihse_kv_ct_group_t group = {0};
        snprintf(group.source_id, sizeof(group.source_id), "%s", store->ct_source_id);
        snprintf(group.generation, sizeof(group.generation), "%s", store->ct_generation);
        group.stream_position = store->ct_durable_lsn + 1u;
        group.records = rows;
        group.count = count;
        uint32_t actor_tenant = qihse_user_get_tenant_id(user);
        for (size_t i = 0u; i < count; i++) {
            const qihse_kv_batch_set_record_t* r = &records[i];
            uint32_t resource_tenant = 0u;
            if (!ct_resource_tenant(r->key, actor_tenant, &resource_tenant)) goto ct_batch_done;
            rows[i] = (qihse_kv_ct_record_t){
                .key = (char*)r->key, .value = (char*)r->value,
                .change_seq = 1u, .expire_time_ms = r->expire_time_ms,
                .actor_id = qihse_user_get_id(user),
                .actor_tenant_id = actor_tenant,
                .resource_tenant_id = resource_tenant,
                .classification = r->classification,
                .sci_compartment = r->sci_compartment,
                .actor_kind = QIHSE_KV_CT_ACTOR_USER
            };
        }
        group.first_seq = group.last_seq = 1u;
        size_t frame_bytes = 0u;
        if (!ct_admin(store->ct_system_principal) ||
            !qihse_ct_codec_encoded_size(store->ct_system_principal,
                                         QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u, 1u,
                                         &group, (size_t)store->ct_limit_bytes,
                                         &frame_bytes) ||
            frame_bytes > store->ct_limit_bytes ||
            store->ct_retained_bytes > store->ct_limit_bytes - frame_bytes) goto ct_batch_done;
        for (size_t i = 0u; i < count; i++) {
            rows[i].change_seq = kv_change_seq_next(store);
            if (!rows[i].change_seq) goto ct_batch_done;
        }
        group.first_seq = rows[0].change_seq;
        group.last_seq = rows[count - 1u].change_seq;
        if (!ct_append_group_locked(store, user, &group)) goto ct_batch_done;
        for (size_t i = 0u; i < count; i++) {
            const qihse_kv_batch_set_record_t* r = &records[i];
            if (!insert_internal(store, r->key, r->value, r->expire_time_ms,
                                 r->classification, r->sci_compartment, 0u,
                                 rows[i].change_seq)) {
                store->recovery_pending = true;
                goto ct_batch_done;
            }
        }
        ct_scope_note_seq(store, group.stream_position);
        ok = true;
ct_batch_done:
        free(rows);
        goto done;
    }

    store->durable_batch_mode = true;
    for (size_t i = 0u; i < count; i++) {
        const qihse_kv_batch_set_record_t* r = &records[i];
        if (!set_user_with_expiry(store, r->key, r->value, r->expire_time_ms,
                                  r->classification, r->sci_compartment, user, NULL)) goto failed;
    }
    if (aimem_durability_test_fail_once("wal-fflush") || fflush(store->wal_fd) != 0) goto failed;
    if (fdatasync(fileno(store->wal_fd)) != 0) goto failed;
    store->wal_unflushed_bytes = 0u;
    store->durable_batch_mode = false;
    ok = true;
    goto done;
failed:
    /* WAL/memtable may now contain a prefix. Never let a caller observe or
     * extend this ambiguous state; reopen replays the authoritative WAL. */
    store->durable_batch_mode = false;
    __atomic_store_n(&store->recovery_pending, true, __ATOMIC_RELEASE);
done:
    kv_store_unlock(store);
    free(keys);
    return ok;
}

bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value,
                       uint16_t classification, uint16_t sci_compartment, qihse_user_t* user) {
    return qihse_kv_set_user_with_seq(store, key, value, classification,
                                      sci_compartment, user, NULL);
}

bool qihse_kv_set_user_with_seq(qihse_kv_store_t* store, const char* key,
                       const char* value, uint16_t classification,
                       uint16_t sci_compartment, qihse_user_t* user,
                       uint64_t* out_change_seq) {
    if (!store) return false;
    kv_store_wrlock(store);
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
    bool ok = set_user_with_expiry(store, key, value, 0u, classification,
                                   sci_compartment, user, out_change_seq);
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
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
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
        classification, sci_compartment, user, NULL);
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
    if (store->recovery_pending || !ct_key_read_ready(store, key)) { kv_store_unlock(store); return NULL; }
    char* value = kv_get_user_impl(store, key, user);
    kv_store_unlock(store);
    return value;
}

bool qihse_kv_meta_user(qihse_kv_store_t* store, const char* key,
                        qihse_user_t* user, qihse_kv_record_meta_t* out) {
    if (!store || !key || !out) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_key_read_ready(store, key)) { kv_store_unlock(store); return false; }
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
        out->change_seq = r.change_seq;
        out->flags = r.flags;
    }
    lookup_result_free(&r);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_change_seq_user(qihse_kv_store_t* store, const char* key,
                              qihse_user_t* user, uint64_t* out_change_seq,
                              bool* out_tombstone) {
    if (out_change_seq) *out_change_seq = 0u;
    if (out_tombstone) *out_tombstone = false;
    if (!store || !key || !out_change_seq || !out_tombstone) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_key_read_ready(store, key)) { kv_store_unlock(store); return false; }
    kv_lookup_result_t r;
    kv_lookup_state_t state = logical_lookup(store, key, &r);
    bool tombstone = state == KV_LOOKUP_DEAD && (r.flags & KV_FLAG_TOMBSTONE) != 0u;
    bool ok = (state == KV_LOOKUP_LIVE || tombstone) &&
              qihse_auth_can_access(user, r.classification, r.sci_compartment);
    if (ok) {
        *out_change_seq = r.change_seq;
        *out_tombstone = tombstone;
    }
    lookup_result_free(&r);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_change_meta_user(qihse_kv_store_t* store, const char* key,
                               qihse_user_t* user, qihse_kv_change_meta_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store || !key || !out || !user || !qihse_auth_user_is_active(user))
        return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_key_read_ready(store, key)) { kv_store_unlock(store); return false; }
    kv_lookup_result_t r;
    kv_lookup_state_t state = logical_lookup(store, key, &r);
    bool tombstone = state == KV_LOOKUP_DEAD && (r.flags & KV_FLAG_TOMBSTONE) != 0u;
    bool ok = (state == KV_LOOKUP_LIVE || tombstone) &&
              qihse_auth_user_is_active(user) &&
              qihse_auth_can_access(user, r.classification, r.sci_compartment);
    if (ok) {
        out->classification = r.classification;
        out->sci_compartment = r.sci_compartment;
        out->change_seq = r.change_seq;
        out->tombstone = tombstone;
    }
    lookup_result_free(&r);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_key_read_ready(store, key)) { kv_store_unlock(store); return false; }
    char* v = kv_get_user_impl(store, key, user);
    kv_store_unlock(store);
    if (!v) return false;
    free(v);
    return true;
}

static bool kv_del_user_impl(qihse_kv_store_t* store, const char* key,
                             qihse_user_t* user, uint64_t* out_change_seq) {
    if (out_change_seq) *out_change_seq = 0u;
    if (!store || !key) return false;
    if (store->ct_enabled && (store->ct_mode != 1u ||
        !ct_write_allowed(store, user, key))) return false;
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE) { lookup_result_free(&r); return false; }
    if (!qihse_auth_can_access(user, r.classification, r.sci_compartment)) { lookup_result_free(&r); return false; }
    uint16_t classification = r.classification, sci = r.sci_compartment; lookup_result_free(&r);
    if (store->ct_enabled &&
        !ct_source_record(store, user, key, NULL, 1u, 0u,
                          classification, sci, true, true,
                          QIHSE_KV_CT_ACTOR_USER)) return false;
    /* Authorized delete: the tombstone is stamped like any mutation, so a
     * delta can carry the deletion. */
    uint64_t seq = kv_change_seq_next(store);
    if (seq == 0u) return false;
    bool logged = store->ct_enabled
        ? ct_source_record(store, user, key, NULL, seq, 0u,
                           classification, sci, true, false,
                           QIHSE_KV_CT_ACTOR_USER)
        : wal_append(store, KV_WAL_OP_DEL, key, "", 0u, classification, sci,
                     KV_FLAG_TOMBSTONE, seq);
    if (!logged) return false;
    if (!insert_internal(store, key, "", 0u, classification, sci,
                         KV_FLAG_TOMBSTONE, seq)) {
        if (store->ct_enabled) store->recovery_pending = true;
        return false;
    }
    if (!store->bulk_load_mode && !store->durable_batch_mode &&
        store->mem_usage > LSM_MEMTABLE_MAX && !flush_memtable_to_sstable(store)) return false;
    if (out_change_seq) *out_change_seq = seq;
    return true;
}

bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    return qihse_kv_del_user_with_seq(store, key, user, NULL);
}

bool qihse_kv_del_user_with_seq(qihse_kv_store_t* store, const char* key,
                                qihse_user_t* user, uint64_t* out_change_seq) {
    if (!store || __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) || !key) return false;
    kv_store_wrlock(store);
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
    bool ok = kv_del_user_impl(store, key, user, out_change_seq);
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_del_with_receipt_user(qihse_kv_store_t* store,
    const char* source_key, uint64_t expected_source_seq,
    const char* receipt_key, const char* expected_prepared_value,
    uint16_t receipt_classification, uint16_t receipt_sci,
    qihse_kv_receipt_builder_t build_receipt, void* context,
    qihse_user_t* user, uint64_t* out_delete_seq) {
    if (out_delete_seq) *out_delete_seq = 0u;
    if (!store || !source_key || !receipt_key || !expected_prepared_value ||
        !build_receipt || !user || !qihse_auth_user_is_active(user) ||
        expected_source_seq == 0u) return false;
    size_t source_len = strnlen(source_key, KV_MAX_KEY_LEN + 1u);
    size_t receipt_len = strnlen(receipt_key, KV_MAX_KEY_LEN + 1u);
    if (!source_len || !receipt_len || source_len > KV_MAX_KEY_LEN ||
        receipt_len > KV_MAX_KEY_LEN || strcmp(source_key, receipt_key) == 0)
        return false;
    bool ok = false, writing = false;
    char completed[QIHSE_KV_DELETE_RECEIPT_MAX_VALUE + 1u];
    kv_store_wrlock(store);
    if (!store->trie || !store->wal_fd || store->memory_snapshot ||
        store->recovery_pending || store->bulk_load_mode || store->durable_batch_mode ||
        __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) ||
        !qihse_auth_user_is_active(user) ||
        !qihse_auth_can_access(user, receipt_classification, receipt_sci) ||
        __atomic_load_n(&store->change_seq, __ATOMIC_RELAXED) >= UINT64_MAX - 2u)
        goto done;
    if (store->ct_enabled && (store->ct_mode != 1u || !store->ct_admitted ||
        !ct_write_allowed(store, user, source_key) ||
        !ct_write_allowed(store, user, receipt_key) ||
        store->ct_retained_bytes > store->ct_limit_bytes ||
        (uint64_t)source_len + receipt_len + QIHSE_KV_DELETE_RECEIPT_MAX_VALUE + 1024u >
            store->ct_limit_bytes - store->ct_retained_bytes)) goto done;
    kv_lookup_result_t source, prepared;
    kv_lookup_state_t source_state = logical_lookup(store, source_key, &source);
    kv_lookup_state_t prepared_state = logical_lookup(store, receipt_key, &prepared);
    bool match = source_state == KV_LOOKUP_LIVE &&
        prepared_state == KV_LOOKUP_LIVE &&
        source.change_seq == expected_source_seq &&
        prepared.classification == receipt_classification &&
        prepared.sci_compartment == receipt_sci &&
        prepared.value && strcmp(prepared.value, expected_prepared_value) == 0 &&
        qihse_auth_can_access(user, source.classification, source.sci_compartment) &&
        qihse_auth_can_access(user, prepared.classification, prepared.sci_compartment);
    uint16_t source_class = source.classification, source_sci = source.sci_compartment;
    lookup_result_free(&source); lookup_result_free(&prepared);
    if (!match) goto done;
    uint64_t delete_seq = kv_change_seq_next(store);
    uint64_t receipt_seq = kv_change_seq_next(store);
    if (!delete_seq || receipt_seq != delete_seq + 1u) goto done;
    memset(completed, 0, sizeof completed);
    if (!build_receipt(delete_seq, completed, sizeof completed, context) ||
        !memchr(completed, '\0', sizeof completed)) goto done;
    size_t value_len = strlen(completed);
    if (!value_len || value_len > QIHSE_KV_DELETE_RECEIPT_MAX_VALUE) goto done;

    if (store->ct_enabled) {
        uint32_t actor_tenant = qihse_user_get_tenant_id(user);
        uint32_t source_tenant = 0u, receipt_tenant = 0u;
        if (!ct_resource_tenant(source_key, actor_tenant, &source_tenant) ||
            !ct_resource_tenant(receipt_key, actor_tenant, &receipt_tenant)) goto done;
        qihse_kv_ct_record_t rows[2] = {
            { .key = (char*)source_key, .value = NULL,
              .change_seq = delete_seq, .actor_id = qihse_user_get_id(user),
              .actor_tenant_id = actor_tenant,
              .resource_tenant_id = source_tenant,
              .classification = source_class, .sci_compartment = source_sci,
              .actor_kind = QIHSE_KV_CT_ACTOR_USER, .tombstone = true },
            { .key = (char*)receipt_key, .value = completed,
              .change_seq = receipt_seq, .actor_id = qihse_user_get_id(user),
              .actor_tenant_id = actor_tenant,
              .resource_tenant_id = receipt_tenant,
              .classification = receipt_classification,
              .sci_compartment = receipt_sci,
              .actor_kind = QIHSE_KV_CT_ACTOR_USER }
        };
        qihse_kv_ct_group_t group = {0};
        snprintf(group.source_id, sizeof(group.source_id), "%s", store->ct_source_id);
        snprintf(group.generation, sizeof(group.generation), "%s", store->ct_generation);
        group.stream_position = store->ct_durable_lsn + 1u;
        group.first_seq = delete_seq;
        group.last_seq = receipt_seq;
        group.records = rows;
        group.count = 2u;
        writing = true;
        if (!ct_append_group_locked(store, user, &group)) goto failed;
        if (!insert_internal(store, source_key, "", 0u, source_class,
                             source_sci, KV_FLAG_TOMBSTONE, delete_seq) ||
            !insert_internal(store, receipt_key, completed, 0u,
                             receipt_classification, receipt_sci, 0u, receipt_seq))
            goto failed;
        ct_scope_note_seq(store, group.stream_position);
        if (out_delete_seq) *out_delete_seq = delete_seq;
        ok = true;
        goto done;
    }

    unsigned char hdr[48] = {0};
    uint16_t source_len16 = (uint16_t)source_len, receipt_len16 = (uint16_t)receipt_len;
    uint32_t value_len32 = (uint32_t)value_len;
    memcpy(hdr, KV_WAL_MAGIC_DELETE_RECEIPT, 4u);
    memcpy(hdr + 4u, &source_len16, 2u); memcpy(hdr + 6u, &receipt_len16, 2u);
    memcpy(hdr + 8u, &value_len32, 4u);
    memcpy(hdr + 12u, &source_class, 2u); memcpy(hdr + 14u, &source_sci, 2u);
    memcpy(hdr + 16u, &receipt_classification, 2u); memcpy(hdr + 18u, &receipt_sci, 2u);
    memcpy(hdr + 20u, &delete_seq, 8u); memcpy(hdr + 28u, &receipt_seq, 8u);
    uint64_t crc = wal_delete_receipt_crc(hdr, source_key, source_len, receipt_key,
                                           receipt_len, completed, value_len);
    memcpy(hdr + 36u, &crc, 8u);
    writing = true;
    if (aimem_durability_test_fail_once("forget-pair-partial-header")) {
        (void)fwrite(hdr, 1u, sizeof(hdr) / 2u, store->wal_fd);
        goto failed;
    }
    if (!fwrite_exact(hdr, 1u, sizeof hdr, store->wal_fd) ||
        !fwrite_exact(source_key, 1u, source_len, store->wal_fd) ||
        !fwrite_exact(receipt_key, 1u, receipt_len, store->wal_fd) ||
        aimem_durability_test_fail_once("forget-pair-partial-body") ||
        !fwrite_exact(completed, 1u, value_len, store->wal_fd) ||
        aimem_durability_test_fail_once("forget-pair-fflush") ||
        fflush(store->wal_fd) != 0 ||
        aimem_durability_test_fail_once("forget-pair-fsync") ||
        fdatasync(fileno(store->wal_fd)) != 0 ||
        !fsync_dir_path(get_qihse_data_dir())) goto failed;
    store->wal_unflushed_bytes = 0u;
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    if (getenv("QIHSE_AIMEM_CRASH_AT") &&
        strcmp(getenv("QIHSE_AIMEM_CRASH_AT"), "forget-pair-after-fsync") == 0)
        _exit(86);
#endif
    store->durable_batch_mode = true;
    if (!insert_internal(store, source_key, "", 0u, source_class, source_sci,
                         KV_FLAG_TOMBSTONE, delete_seq) ||
        !insert_internal(store, receipt_key, completed, 0u, receipt_classification,
                         receipt_sci, 0u, receipt_seq)) {
        store->durable_batch_mode = false;
        goto failed;
    }
    store->durable_batch_mode = false;
    if (out_delete_seq) *out_delete_seq = delete_seq;
    ok = true;
    goto done;
failed:
    if (writing) __atomic_store_n(&store->recovery_pending, true, __ATOMIC_RELEASE);
done:
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
        !replica_principal_ok(store, principal) ||
        !qihse_auth_can_access(principal, record->classification, record->sci_compartment))
        return false;

    kv_store_wrlock(store);
    if (store->ct_enabled) { kv_store_unlock(store); errno = EACCES; return false; }
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
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
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
    kv_lookup_result_t r; kv_lookup_state_t state = logical_lookup(store, key, &r);
    if (state != KV_LOOKUP_LIVE || !qihse_auth_can_access(user, r.classification, r.sci_compartment)) {
        lookup_result_free(&r); kv_store_unlock(store); return false;
    }
    uint64_t expire = current_time_ms();
    if (UINT64_MAX - expire < ttl_ms) { lookup_result_free(&r); kv_store_unlock(store); return false; }
    expire += ttl_ms;
    bool ok = set_user_with_expiry(store, key, r.value, expire, r.classification,
                                   r.sci_compartment, user, NULL);
    lookup_result_free(&r); kv_store_unlock(store); return ok;
}

int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !key) return -2;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_key_read_ready(store, key)) { kv_store_unlock(store); return -2; }
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
        if (!ct_key_owned_for_read(store, keys[i])) continue;
        size_t sz = 0u;
        kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, keys[i], &sz);
        if (p) {
            uint16_t c = p->classification, s = p->sci_compartment;
            if (store->ct_enabled) {
                if (store->ct_mode != 1u || !store->ct_admitted ||
                    !store->ct_system_principal ||
                    !qihse_auth_can_access(store->ct_system_principal, c, s)) {
                    store->recovery_pending = true;
                    return;
                }
                if (!ct_source_record(store, store->ct_system_principal, keys[i],
                                      NULL, 1u, 0u, c, s, true, true,
                                      QIHSE_KV_CT_ACTOR_EXPIRY)) {
                    store->recovery_pending = true;
                    return;
                }
                uint64_t seq = kv_change_seq_next(store);
                if (!seq || !ct_source_record(store, store->ct_system_principal,
                       keys[i], NULL, seq, 0u, c, s, true, false,
                       QIHSE_KV_CT_ACTOR_EXPIRY) ||
                    !insert_internal(store, keys[i], "", 0u, c, s,
                                     KV_FLAG_TOMBSTONE, seq)) {
                    store->recovery_pending = true;
                    return;
                }
                continue;
            }
            /* A sweep tombstone is a mutation: it advances the sequence so a
             * delta consumer learns the key is gone. */
            uint64_t seq = kv_change_seq_next(store);
            if (seq == 0u) continue;
            (void)wal_append(store, KV_WAL_OP_DEL, keys[i], "", 0u, c, s,
                             KV_FLAG_TOMBSTONE, seq);
            (void)insert_internal(store, keys[i], "", 0u, c, s, KV_FLAG_TOMBSTONE, seq);
        }
    }
}

void qihse_kv_sweep_expired(qihse_kv_store_t* store) {
    if (!store || !store->trie) return;
    /* A read-only replica must not expire records (that is a logical
     * mutation), but it must still compact: merging SSTables is a physical
     * rewrite that preserves the newest copy of every key. Skipping it left
     * every replica's file count growing with each pull until reads slowed
     * the same way they did on node5. */
    const bool read_only =
        __atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE);
    if (read_only) {
        kv_store_wrlock(store);
        if (store->sstable_live_count >= KV_SSTABLE_COMPACT_THRESHOLD &&
            !store->recovery_pending && !store->bulk_load_mode) {
            int32_t before = store->sstable_counter;
            if (compact_sstables_stream(store) && before > 1) {
                fprintf(stderr,
                        "qihse-kv: compacted %d replica sstable(s) into %zu live "
                        "file(s)\n", before, store->sstable_live_count);
            }
        }
        kv_store_unlock(store);
        return;
    }
    kv_store_wrlock(store);
    if (store->recovery_pending) { kv_store_unlock(store); return; }
    if (store->bulk_load_mode) { kv_store_unlock(store); return; }
    /* Reads still treat expired values as absent. Defer the physical
     * tombstone/compaction until the frozen CT2 image is no longer needed. */
    if (store->ct_enabled && store->ct_fence_state == 1u) {
        kv_store_unlock(store);
        return;
    }
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
        store->sstable_live_count >= KV_SSTABLE_COMPACT_THRESHOLD) {
        int32_t before = store->sstable_counter;
        if (compact_sstables_stream(store)) {
            if (before > 1) {
                fprintf(stderr,
                        "qihse-kv: compacted %d sstable(s) into %zu live file(s), "
                        "%s index\n",
                        before, store->sstable_live_count,
                        (store->sst_meta && !store->sst_meta->degraded)
                            ? "healthy" : "degraded");
            }
        } else {
            fprintf(stderr,
                    "qihse-kv: sstable compaction failed; %zu live file(s) "
                    "retained and reads stay on the scan path\n",
                    store->sstable_live_count);
        }
    }
    kv_store_unlock(store);
}

typedef struct {
    qihse_kv_store_t* store;
    qihse_user_t* user;
    qihse_kv_iter_cb cb;
    qihse_kv_iter_meta_cb meta_cb;
    void* user_data;
    const char* prefix;
    size_t prefix_len;
    uint64_t now;
    bool bounded_label;
    uint16_t max_classification;
    uint16_t allowed_sci;
    bool ok;
} foreach_user_ctx_t;
static bool foreach_label_allowed(const foreach_user_ctx_t* ctx,
                                  uint16_t classification, uint16_t sci) {
    return !ctx->bounded_label ||
           (classification <= ctx->max_classification &&
            (sci & (uint16_t)~ctx->allowed_sci) == 0u);
}
/* One delivery helper: a plain enumeration calls cb, a metadata enumeration
 * calls meta_cb with the ACL read from the same record. */
static bool foreach_user_deliver(foreach_user_ctx_t* ctx, const char* key,
                                 const char* value, uint16_t classification,
                                 uint16_t sci_compartment) {
    if (!ctx->ok) return false;
    if (!ct_key_owned_for_read(ctx->store, key)) return true;
    if (ctx->meta_cb) {
        return ctx->meta_cb(key, value, classification, sci_compartment,
                            ctx->user_data);
    }
    return ctx->cb(key, value, ctx->user_data);
}
static bool foreach_user_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; foreach_user_ctx_t* ctx = (foreach_user_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !key || !p) return false;
    if (ctx->prefix && strncmp(key, ctx->prefix, ctx->prefix_len) != 0) return true;
    if (payload_is_dead(p, ctx->now)) return true;
    if (!foreach_label_allowed(ctx, p->classification, p->sci_compartment)) return true;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) return true;
    return foreach_user_deliver(ctx, key, p->val, p->classification, p->sci_compartment);
}

static bool foreach_sst_emit_cb(const char* key, const kv_disk_record_t* r, void* ud) {
    foreach_user_ctx_t* ctx = (foreach_user_ctx_t*)ud;
    if (!ctx || !key || !r) return false;
    if (ctx->prefix && strncmp(key, ctx->prefix, ctx->prefix_len) != 0) return true;
    if (!foreach_label_allowed(ctx, r->classification, r->sci_compartment)) return true;
    if (!qihse_auth_can_access(ctx->user, r->classification, r->sci_compartment)) return true;
    return foreach_user_deliver(ctx, key, r->val, r->classification, r->sci_compartment);
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
            foreach_label_allowed(ctx, record.classification,
                                  record.sci_compartment) &&
            qihse_auth_can_access(ctx->user, record.classification,
                                  record.sci_compartment)) {
            bool keep_going = foreach_user_deliver(ctx, e->key, record.value,
                record.classification, record.sci_compartment);
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
                                  qihse_kv_iter_meta_cb meta_cb,
                                  void* user_data, bool bounded_label,
                                  uint16_t max_classification,
                                  uint16_t allowed_sci) {
    if (!store || !store->trie || (!cb && !meta_cb)) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return false; }
    bool compact_needed = store->sstable_counter > 0 &&
                          (!store->sst_meta || store->sst_meta->degraded);
    kv_store_unlock(store);
    if (compact_needed) {
        /* Degraded index: merge under the WRITE side, then restart so the
         * user callback always runs with only a read lock (it may re-enter
         * this store for another authorized read). */
        kv_store_wrlock(store);
        if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return false; }
        bool ok = store->sstable_counter == 0 ||
                  ((store->sst_meta && !store->sst_meta->degraded) ||
                   compact_sstables_into_memtable(store));
        kv_store_unlock(store);
        return ok && foreach_user_filtered(store, prefix, user, cb, meta_cb,
                                           user_data, bounded_label,
                                           max_classification, allowed_sci);
    }
    /* No compaction: iterate the memtable, then stream the index-pinned
     * newest SSTable records. Callbacks may re-enter qihse_kv_get_user. */
    /* Recheck after taking the read lock: a writer may have degraded the
     * index between the first probe and this lock. */
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return false; }
    if (store->sstable_counter > 0 && (!store->sst_meta || store->sst_meta->degraded)) {
        kv_store_unlock(store);
        return foreach_user_filtered(store, prefix, user, cb, meta_cb,
                                     user_data, bounded_label,
                                     max_classification, allowed_sci);
    }
    foreach_user_ctx_t ctx = {
        .store = store, .user = user, .cb = cb, .meta_cb = meta_cb, .user_data = user_data,
        .prefix = prefix, .prefix_len = prefix ? strlen(prefix) : 0u,
        .now = current_time_ms(), .bounded_label = bounded_label,
        .max_classification = max_classification, .allowed_sci = allowed_sci,
        .ok = true
    };
    qihse_trinary_trie_foreach(store->trie, foreach_user_cb, &ctx);
    int rc = 0;
    if (store->sstable_counter > 0) {
        rc = prefix && *prefix
           ? sst_foreach_prefix_indexed(store, &ctx)
           : sst_foreach_newest(store, false, false, foreach_sst_emit_cb, &ctx);
    }
    kv_store_unlock(store);
    return rc >= 0;
}
bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user,
                           qihse_kv_iter_cb cb, void* user_data) {
    return foreach_user_filtered(store, NULL, user, cb, NULL, user_data,
                                 false, 0u, 0u);
}
bool qihse_kv_foreach_meta_user(qihse_kv_store_t* store, qihse_user_t* user,
                                qihse_kv_iter_meta_cb cb, void* user_data) {
    if (!cb) return false;
    return foreach_user_filtered(store, NULL, user, NULL, cb, user_data,
                                 false, 0u, 0u);
}
bool qihse_kv_foreach_meta_bounded_user(qihse_kv_store_t* store,
    qihse_user_t* actor, uint16_t max_classification, uint16_t allowed_sci,
    qihse_kv_iter_meta_cb cb, void* user_data) {
    if (!actor || !qihse_auth_user_is_active(actor) || !cb) return false;
    return foreach_user_filtered(store, NULL, actor, NULL, cb, user_data,
                                 true, max_classification, allowed_sci);
}
bool qihse_kv_sstable_stats(qihse_kv_store_t* store, qihse_kv_sstable_stats_t* out) {
    if (!store || !out) return false;
    memset(out, 0, sizeof(*out));
    kv_store_rdlock(store);
    if (store->recovery_pending) { kv_store_unlock(store); return false; }
    out->live_sstable_files = store->sstable_live_count;
    out->sstable_counter = (size_t)store->sstable_counter;
    out->index_degraded = !store->sst_meta || store->sst_meta->degraded;
    kv_store_unlock(store);
    return true;
}

bool qihse_kv_foreach_prefix_user(qihse_kv_store_t* store, const char* prefix,
                                  qihse_user_t* user, qihse_kv_iter_cb cb,
                                  void* user_data) {
    if (!prefix) return false;
    return foreach_user_filtered(store, prefix, user, cb, NULL, user_data,
                                 false, 0u, 0u);
}

typedef struct {
    qihse_kv_store_t* store;
    qihse_user_t* user;
    qihse_kv_key_iter_cb cb;
    void* user_data;
    uint64_t now;
    bool stopped;
} key_iter_ctx_t;

static bool key_iter_mem_cb(const char* key, void* value, size_t value_size,
                            void* user_data) {
    (void)value_size;
    key_iter_ctx_t* ctx = (key_iter_ctx_t*)user_data;
    const kv_payload_t* p = (const kv_payload_t*)value;
    if (!ctx || !key || !p || payload_is_dead(p, ctx->now) ||
        !ct_key_owned_for_read(ctx->store, key) ||
        !qihse_auth_can_access(ctx->user, p->classification,
                               p->sci_compartment)) return true;
    if (!ctx->cb(key, ctx->user_data)) {
        ctx->stopped = true;
        return false;
    }
    return true;
}

bool qihse_kv_foreach_key_user(qihse_kv_store_t* store, qihse_user_t* user,
                               qihse_kv_key_iter_cb cb, void* user_data) {
    if (!store || !store->trie || !user ||
        !qihse_auth_user_is_active(user) || !cb) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return false; }
    /* The index is the only source for flushed-record ACLs. If degraded, fail
     * closed instead of forcing a full value-materializing compaction. */
    if (store->sstable_counter > 0 &&
        (!store->sst_meta || store->sst_meta->degraded)) {
        kv_store_unlock(store);
        return false;
    }
    key_iter_ctx_t ctx = { .store = store, .user = user, .cb = cb, .user_data = user_data,
                           .now = current_time_ms(), .stopped = false };
    qihse_trinary_trie_foreach(store->trie, key_iter_mem_cb, &ctx);
    if (!ctx.stopped && store->sstable_counter > 0) {
        const sst_meta_index_t* idx = store->sst_meta;
        for (size_t i = 0; i < idx->cap; i++) {
            const sst_meta_entry_t* e = &idx->slots[i];
            if (!e->key || !ct_key_owned_for_read(store, e->key) ||
                (e->flags & KV_FLAG_TOMBSTONE) != 0u ||
                (e->expire_time_ms != 0u && e->expire_time_ms <= ctx.now) ||
                qihse_trinary_trie_search(store->trie, e->key, NULL) != NULL ||
                !qihse_auth_can_access(user, e->classification,
                                       e->sci_compartment)) continue;
            if (!cb(e->key, user_data)) break;
        }
    }
    kv_store_unlock(store);
    return true;
}
void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data) {
    (void)qihse_kv_foreach_user(store, NULL, cb, user_data);
}

typedef struct { qihse_kv_store_t* store; qihse_user_t* user;
    size_t count; uint64_t now; } count_ctx_t;
static bool count_cb(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; count_ctx_t* ctx = (count_ctx_t*)user_data; kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !p) return false;
    if (!payload_is_dead(p, ctx->now) &&
        ct_key_owned_for_read(ctx->store, key) && qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) ctx->count++;
    return true;
}
size_t qihse_kv_count_user(qihse_kv_store_t* store, qihse_user_t* user) {
    if (!store || !store->trie) return 0u;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return 0; }
    bool compact_needed = store->sstable_counter > 0 &&
                          (!store->sst_meta || store->sst_meta->degraded);
    kv_store_unlock(store);
    if (compact_needed) {
        kv_store_wrlock(store);
        if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return 0; }
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
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return 0; }
    if (store->sstable_counter > 0 && (!store->sst_meta || store->sst_meta->degraded)) {
        kv_store_unlock(store);
        return qihse_kv_count_user(store, user);
    }
    uint64_t now = current_time_ms();
    count_ctx_t ctx = { .store = store, .user = user,
                        .count = 0u, .now = now };
    qihse_trinary_trie_foreach(store->trie, count_cb, &ctx);
    const sst_meta_index_t* idx = store->sst_meta;
    for (size_t i = 0; idx && i < idx->cap; i++) {
        const sst_meta_entry_t* e = &idx->slots[i];
        if (!e->key || !ct_key_owned_for_read(store, e->key)) continue;
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
    if (aimem_durability_test_fail_once("directory-fsync")) return false;
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

static bool kv_sync_store_locked(qihse_kv_store_t* store) {
    if (!store || !store->trie || store->memory_snapshot || store->recovery_pending) return false;
    /* 1. WAL: stdio buffer to the kernel, then the fd itself. Without the
     * fsync the WAL lives only in the page cache -- fine against process
     * death, lost on power loss; SAVE promises both. */
    if (store->wal_fd) {
        if (aimem_durability_test_fail_once("wal-fflush")) return false;
        if (fflush(store->wal_fd) != 0) return false;
        int wfd = fileno(store->wal_fd);
        if (aimem_durability_test_fail_once("wal-fsync")) return false;
        if (wfd >= 0 && fsync(wfd) != 0) return false;
        store->wal_unflushed_bytes = 0u;
    }
    /* 2. Memtable -> new SSTable (atomic rename, file fsynced inside the
     * atomic commit) + WAL rotation. Every mutation lands in BOTH the WAL
     * and the memtable, so an empty memtable means the WAL holds nothing
     * that is not already durable -- skip the flush, keep the fsyncs. */
    if (store->mem_usage > 0u && !flush_memtable_to_sstable(store)) return false;
    /* 3. The renames above and in flush/rotate are only as durable as the
     * directory entry that points at them. */
    const char* dir = get_qihse_data_dir();
    return !dir || fsync_dir_path(dir);
}

bool qihse_kv_sync_store(qihse_kv_store_t* store) {
    if (!store) return false;
    kv_store_wrlock(store);
    bool ok = kv_sync_store_locked(store);
    kv_store_unlock(store);
    return ok;
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
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
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
    if (ctx.ok) for (size_t i = 0; i < ctx.count; i++) if (kv_del_user_impl(store, ctx.keys[i], user, NULL)) removed++;
    for (size_t i = 0; i < ctx.count; i++) free(ctx.keys[i]);
    free(ctx.keys);
    /* Physically purge the SSTable copies of everything just tombstoned —
     * same on-disk removal guarantee as the old compact-first version. */
    if (removed > 0 && fast && store->sstable_counter > 0 &&
        !compact_sstables_stream(store)) {
        fprintf(stderr,
                "qihse-kv: post-delete compaction failed; tombstoned copies "
                "remain in %d sstable(s)\n", store->sstable_counter);
    }
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
    qihse_kv_store_t* store;
    qihse_user_t* user;
    const char* glob;
    uint64_t now;
    bool include_dead;
    bool ok;
    bool authorized;
} replica_snapshot_write_ctx_t;

static bool replica_snapshot_write_mem_cb(const char* key, void* value,
                                          size_t value_size, void* ud) {
    (void)value_size;
    replica_snapshot_write_ctx_t* ctx = (replica_snapshot_write_ctx_t*)ud;
    kv_payload_t* p = (kv_payload_t*)value;
    if (!ctx || !ctx->ok || !ctx->authorized || !key || !p) return false;
    if (fnmatch(ctx->glob, key, 0) != 0 ||
        (!ctx->include_dead && payload_is_dead(p, ctx->now)) ||
        !ct_key_owned_for_read(ctx->store, key)) return true;
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
    if (fnmatch(ctx->glob, key, 0) != 0 ||
        !ct_key_owned_for_read(ctx->store, key)) return true;
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
                                               const char* glob,
                                               bool include_dead) {
    if (!store || !store->trie || !filepath || !glob || !*glob) return -1;
    /* The newest-first SST iterator has a bounded metadata-only fallback for
     * degraded indexes. Do not compact here: compaction intentionally drops
     * expired rows, which an owner recovery image must preserve. */
    char tmp[8192]; FILE* f = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &f)) return -1;
    replica_snapshot_write_ctx_t ctx = {
        .f = f, .store = store, .user = user, .glob = glob, .now = current_time_ms(),
        .include_dead = include_dead, .ok = true, .authorized = true
    };
    qihse_trinary_trie_foreach(store->trie, replica_snapshot_write_mem_cb, &ctx);
    if (ctx.ok && ctx.authorized && store->sstable_counter > 0) {
        int rc = sst_foreach_newest(store, include_dead, include_dead,
                                    replica_snapshot_write_sst_cb, &ctx);
        if (rc < 0) ctx.ok = false;
    }
    if (!ctx.authorized) { fclose(f); unlink(tmp); errno = EACCES; return -2; }
    if (!ctx.ok || ferror(f)) { fclose(f); unlink(tmp); return -1; }
    return atomic_file_commit(f, tmp, filepath) ? 0 : -1;
}

static int qihse_kv_save_user_internal(qihse_kv_store_t* store,
    const char* filepath, qihse_user_t* user, uint64_t principal_generation,
    bool generation_bound) {
    if (!store || !store->trie || !filepath) return -1;
    if (generation_bound &&
        !qihse_auth_validate_handle_generation(user, principal_generation)) {
        errno = EACCES;
        return -2;
    }
    /* The fast path only reads (trie + index + immutable SSTables), but the
     * !fast path compacts; taking the WRITE side unconditionally keeps the
     * snapshot internally consistent either way. */
    kv_store_wrlock(store);
    if (store->ct_enabled) { kv_store_unlock(store); errno = EACCES; return -1; }
    if (store->recovery_pending) { kv_store_unlock(store); return -1; }
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
        int rc = sst_foreach_newest(store, false, false, export_sst_write_cb, &wr);
        if (rc < 0) wr.ok = false;
    }
    if (!wr.ok || ferror(f)) { fclose(f); unlink(tmp); kv_store_unlock(store); return -1; }
    if (generation_bound &&
        !qihse_auth_validate_handle_generation(user, principal_generation)) {
        fclose(f); unlink(tmp); kv_store_unlock(store); errno = EACCES; return -2;
    }
    if (!atomic_file_commit(f, tmp, filepath)) { kv_store_unlock(store); return -1; }
    /* Publication may include a parent-directory sync. If identity changes
     * while that sync completes, report the changed authority even though the
     * now-published candidate cannot safely be rolled back. */
    if (generation_bound &&
        !qihse_auth_validate_handle_generation(user, principal_generation)) {
        kv_store_unlock(store); errno = EACCES; return -2;
    }
    kv_store_unlock(store);
    return 0;
}

int qihse_kv_save_user(qihse_kv_store_t* store, const char* filepath,
                       qihse_user_t* user) {
    if (!user)
        return qihse_kv_save_user_internal(store, filepath, NULL, 0u, false);
    if (!qihse_auth_user_is_active(user)) { errno = EACCES; return -2; }
    uint64_t generation = 0u;
    qihse_user_t* principal = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (!principal || !generation ||
        qihse_user_get_id(principal) != qihse_user_get_id(user) ||
        !qihse_auth_validate_handle_generation(user, generation) ||
        !qihse_auth_validate_handle_generation(principal, generation)) {
        if (principal) qihse_auth_release_principal_scoped(principal);
        errno = EACCES;
        return -2;
    }
    int rc = qihse_kv_save_user_internal(store, filepath, principal,
                                         generation, true);
    qihse_auth_release_principal_scoped(principal);
    return rc;
}
int qihse_kv_save(qihse_kv_store_t* store, const char* filepath) { return qihse_kv_save_user(store, filepath, NULL); }

int qihse_kv_replica_snapshot_create(qihse_kv_store_t* store, qihse_user_t* user,
                                     const char* namespace_glob,
                                     qihse_kv_replica_snapshot_t** out_snapshot) {
    if (out_snapshot) *out_snapshot = NULL;
    if (!store || store->memory_snapshot || !out_snapshot || !namespace_glob || !*namespace_glob) return -1;
    if (!user || !qihse_auth_user_is_active(user)) { errno = EACCES; return -2; }
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
    kv_store_wrlock(store);
    int save_rc = store->recovery_pending ? -1 :
        qihse_kv_save_replica_snapshot_file(store, path, user, namespace_glob, false);
    /* The data file and this watermark must describe the same locked store
     * view. Callers can safely resume delta replication after this value. */
    uint64_t source_change_seq = save_rc == 0 ? store->change_seq : 0u;
    kv_store_unlock(store);
    if (save_rc != 0) {
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
    snapshot->source_change_seq = source_change_seq;
    snapshot->principal = user;
    snapshot->principal_id = qihse_user_get_id(user);
    snapshot->tenant_id = qihse_user_get_tenant_id(user);
    snapshot->classification = qihse_user_get_classification(user);
    snapshot->sci = qihse_user_get_sci(user);
    *out_snapshot = snapshot;
    return 0;
}

int qihse_kv_ct_owner_data_snapshot_create(qihse_kv_store_t* store,
    qihse_user_t* operator_principal,
    qihse_kv_replica_snapshot_t** out_snapshot) {
    if (out_snapshot) *out_snapshot = NULL;
    if (!store || store->memory_snapshot || !out_snapshot ||
        !ct_admin(operator_principal) ||
        !qihse_auth_can_access(operator_principal, UINT16_MAX, UINT16_MAX)) {
        errno = EACCES;
        return -2;
    }
    qihse_user_t* principal = operator_principal;
    if (!qihse_auth_user_is_active(principal) ||
        !qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX)) {
        errno = EACCES;
        return -2;
    }
    const char* dir = get_qihse_data_dir();
    if (!dir) return -1;
    char path[4096];
    int n = snprintf(path, sizeof(path), "%sqihse-owner-backup-XXXXXX", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return -1;
    }
    int seed_fd = mkstemp(path);
    if (seed_fd < 0) return -1;
    (void)fchmod(seed_fd, 0600);
    close(seed_fd);

    kv_store_wrlock(store);
    bool owner_ready = store->ct_enabled && store->ct_mode == 1u &&
        store->ct_admitted && !store->recovery_pending &&
        store->ct_fence_state == 0u && store->ct_transfer_phase == 0u &&
        store->ct_transfer_source_id[0] == '\0';
    if (!owner_ready) errno = EBUSY;
    int save_rc = owner_ready
        ? qihse_kv_save_replica_snapshot_file(store, path, principal, "*", true)
        : -1;
    uint64_t source_change_seq = save_rc == 0 ? store->change_seq : 0u;
    kv_store_unlock(store);
    if (!qihse_auth_user_is_active(principal) ||
        !qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX)) {
        save_rc = -2; errno = EACCES;
    }
    if (save_rc != 0) {
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
    qihse_kv_replica_snapshot_t* snapshot = calloc(1u, sizeof(*snapshot));
    if (!snapshot) {
        close(fd);
        return -1;
    }
    snapshot->fd = fd;
    snapshot->size = (uint64_t)st.st_size;
    snapshot->source_change_seq = source_change_seq;
    snapshot->principal = principal;
    snapshot->principal_id = qihse_user_get_id(principal);
    snapshot->tenant_id = qihse_user_get_tenant_id(principal);
    snapshot->classification = qihse_user_get_classification(principal);
    snapshot->sci = qihse_user_get_sci(principal);
    *out_snapshot = snapshot;
    return 0;
}

static bool replica_snapshot_authorized(const qihse_kv_replica_snapshot_t* snapshot,
    qihse_user_t* principal) {
    return snapshot && principal && principal == snapshot->principal &&
        qihse_auth_user_is_active(principal) &&
        qihse_user_get_id(principal) == snapshot->principal_id &&
        qihse_user_get_tenant_id(principal) == snapshot->tenant_id &&
        qihse_auth_can_access(principal, snapshot->classification, snapshot->sci);
}

bool qihse_kv_replica_snapshot_size(const qihse_kv_replica_snapshot_t* snapshot,
    qihse_user_t* principal, uint64_t* out_size) {
    if (out_size) *out_size = 0u;
    if (!out_size || !replica_snapshot_authorized(snapshot, principal)) {
        errno = EACCES; return false;
    }
    *out_size = snapshot->size;
    return true;
}

bool qihse_kv_replica_snapshot_change_seq(
    const qihse_kv_replica_snapshot_t* snapshot, qihse_user_t* principal,
    uint64_t* out_change_seq) {
    if (out_change_seq) *out_change_seq = 0u;
    if (!out_change_seq || !replica_snapshot_authorized(snapshot, principal)) {
        errno = EACCES;
        return false;
    }
    *out_change_seq = snapshot->source_change_seq;
    return true;
}

bool qihse_kv_replica_snapshot_read(qihse_kv_replica_snapshot_t* snapshot,
                                    qihse_user_t* principal, uint64_t offset, void* out, size_t capacity,
                                    size_t* out_read) {
    if (out_read) *out_read = 0u;
    if (!snapshot || snapshot->fd < 0 || !out_read || (capacity && !out) || offset > snapshot->size)
        return false;
    if (!replica_snapshot_authorized(snapshot, principal)) {
        errno = EACCES; return false;
    }
    uint64_t remain = snapshot->size - offset;
    size_t want = remain < (uint64_t)capacity ? (size_t)remain : capacity;
    size_t done = 0u;
    while (done < want) {
        ssize_t n = pread(snapshot->fd, (char*)out + done, want - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    if (!qihse_auth_user_is_active(principal) ||
        !qihse_auth_can_access(principal, snapshot->classification, snapshot->sci)) {
        if (done) memset(out, 0, done);
        errno = EACCES; return false;
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
    if (!user || !qihse_auth_user_is_active(user)) { errno = EACCES; return false; }
    int fd = open_secure_read(filepath);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    qihse_trinary_trie_t* trie = qihse_trinary_trie_create();
    if (!trie) { fclose(f); return false; }
    size_t usage = 0u; uint64_t max_seq = 0u;
    kv_disk_record_t r; int rc; bool ok = true;
    const kv_read_context_t context = { .user = user };
    while ((rc = disk_record_read_context(f, &r, &context)) == 1) {
        size_t ps = 0u;
        kv_payload_t* p = payload_create(r.val, r.expire_time_ms, r.classification,
                                         r.sci_compartment, r.flags, r.change_seq, &ps);
        if (!p || !qihse_trinary_trie_insert_nocopy(trie, r.key, p, ps)) {
            free(p); disk_record_free(&r); ok = false; break;
        }
        if (r.change_seq > max_seq) max_seq = r.change_seq;
        usage += strlen(r.key) + ps; disk_record_free(&r);
    }
    if (rc < 0) { errno = rc == -2 ? EACCES : EINVAL; ok = false; }
    if (!qihse_auth_user_is_active(user)) { errno = EACCES; ok = false; }
    fclose(f);
    if (!ok) { qihse_trinary_trie_destroy(trie); return false; }
    *out_trie = trie;
    if (out_usage) *out_usage = usage;
    if (out_max_seq) *out_max_seq = max_seq;
    return true;
}

typedef struct {
    qihse_user_t* user;
    uint64_t now;
    bool authorized;
    bool has_live;
    bool include_dead;
    uint16_t required_classification;
    uint16_t required_sci;
} restore_auth_ctx_t;

static bool restore_auth_cb(const char* key, void* value, size_t value_size, void* ud) {
    (void)key; (void)value_size;
    restore_auth_ctx_t* ctx = (restore_auth_ctx_t*)ud;
    kv_payload_t* p = (kv_payload_t*)value;
    if (!p) { ctx->authorized = false; return false; }
    /* Prior authorized deletions/expiry are not live rows being replaced. */
    if (!ctx->include_dead && payload_is_dead(p, ctx->now)) return true;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) {
        ctx->authorized = false; return false;
    }
    if (p->classification > ctx->required_classification)
        ctx->required_classification = p->classification;
    ctx->required_sci |= p->sci_compartment;
    if (!payload_is_dead(p, ctx->now)) ctx->has_live = true;
    return true;
}

/* Detached immutable snapshot open. No storage path, WAL, recovery, or SST is
 * touched. Parsing finishes and the principal is rechecked before publication. */
qihse_kv_store_t* qihse_kv_open_snapshot_user(FILE* stream, qihse_user_t* user,
                                             size_t max_bytes, size_t max_records) {
    if (!user || !qihse_auth_user_is_active(user)) { errno = EACCES; return NULL; }
    if (!stream || max_bytes == 0u || max_records == 0u) { errno = EINVAL; return NULL; }
    qihse_kv_store_t* store = kv_store_allocate();
    if (!store) { errno = ENOMEM; return NULL; }
    store->memory_snapshot = true;
    store->replica_read_only = true;
    const kv_read_context_t context = { .user = user, .remaining_snapshot_bytes = &max_bytes,
        .remaining_snapshot_records = &max_records };
    kv_disk_record_t record;
    int rc = 0, failure = 0;
    while ((rc = disk_record_read_context(stream, &record, &context)) == 1) {
        size_t old_size = 0u, size = 0u;
        if (qihse_trinary_trie_search(store->trie, record.key, &old_size)) {
            disk_record_free(&record); failure = EINVAL; break;
        }
        kv_payload_t* value = payload_create(record.val, record.expire_time_ms,
            record.classification, record.sci_compartment, record.flags, record.change_seq, &size);
        if (!value || !qihse_trinary_trie_insert_nocopy(store->trie, record.key, value, size)) {
            free(value); disk_record_free(&record); failure = ENOMEM; break;
        }
        kv_change_seq_floor(store, record.change_seq);
        store->mem_usage += strlen(record.key) + size;
        disk_record_free(&record);
    }
    if (rc < 0) failure = rc == -2 ? EACCES : rc == -3 ? EFBIG : rc == -4 ? E2BIG : EINVAL;
    if (ferror(stream) && !failure) failure = EIO;
    if (!failure) {
        restore_auth_ctx_t auth = { .user = user, .now = current_time_ms(),
            .authorized = true, .include_dead = true };
        qihse_trinary_trie_foreach(store->trie, restore_auth_cb, &auth);
        if (!auth.authorized) failure = EACCES;
    }
    if (!qihse_auth_user_is_active(user)) failure = EACCES;
    if (failure) { qihse_kv_store_destroy(store); errno = failure; return NULL; }
    return store;
}

typedef struct {
    qihse_kv_store_t* store;
    qihse_user_t* user;
    qihse_kv_snapshot_record_cb callback;
    void* user_data;
    bool authorized;
    bool callback_ok;
} snapshot_iter_ctx_t;

static bool snapshot_iter_record_cb(const char* key, void* value,
    size_t value_size, void* opaque) {
    (void)value_size;
    snapshot_iter_ctx_t* ctx = opaque;
    kv_payload_t* p = value;
    if (!ctx || !ctx->authorized || !ctx->callback_ok || !key || !p) return false;
    if (!qihse_auth_can_access(ctx->user, p->classification, p->sci_compartment)) {
        ctx->authorized = false;
        return false;
    }
    qihse_kv_record_meta_t metadata = {
        .classification = p->classification,
        .sci_compartment = p->sci_compartment,
        .expire_time_ms = p->expire_time_ms,
        .change_seq = p->change_seq,
        .flags = p->flags
    };
    if (!ctx->callback(key, p->val, &metadata, ctx->user_data)) {
        ctx->callback_ok = false;
        return false;
    }
    return true;
}

bool qihse_kv_snapshot_foreach_record_user(qihse_kv_store_t* snapshot,
    qihse_user_t* user, qihse_kv_snapshot_record_cb callback, void* user_data) {
    if (!snapshot || !snapshot->memory_snapshot || !snapshot->trie ||
        !user || !qihse_auth_user_is_active(user) || !callback) {
        errno = EACCES;
        return false;
    }
    kv_store_rdlock(snapshot);
    snapshot_iter_ctx_t ctx = {
        .store = snapshot, .user = user, .callback = callback,
        .user_data = user_data, .authorized = true, .callback_ok = true
    };
    qihse_trinary_trie_foreach(snapshot->trie, snapshot_iter_record_cb, &ctx);
    bool ok = ctx.authorized && ctx.callback_ok && qihse_auth_user_is_active(user);
    kv_store_unlock(snapshot);
    if (!ok) errno = ctx.authorized ? EIO : EACCES;
    return ok;
}

bool qihse_kv_snapshot_get_record_user(qihse_kv_store_t* snapshot,
    const char* key, qihse_user_t* user, char** out_value,
    qihse_kv_record_meta_t* out_metadata) {
    if (out_value) *out_value = NULL;
    if (out_metadata) memset(out_metadata, 0, sizeof(*out_metadata));
    if (!snapshot || !snapshot->memory_snapshot || !snapshot->trie || !key ||
        !user || !qihse_auth_user_is_active(user) || !out_value || !out_metadata) {
        errno = EACCES;
        return false;
    }
    kv_store_rdlock(snapshot);
    size_t value_size = 0u;
    kv_payload_t* p = qihse_trinary_trie_search(snapshot->trie, key, &value_size);
    bool ok = p && qihse_auth_can_access(user, p->classification, p->sci_compartment);
    char* copy = ok ? strdup(p->val) : NULL;
    if (ok && !copy) ok = false;
    if (ok) {
        *out_metadata = (qihse_kv_record_meta_t){
            .classification = p->classification,
            .sci_compartment = p->sci_compartment,
            .expire_time_ms = p->expire_time_ms,
            .change_seq = p->change_seq,
            .flags = p->flags
        };
        *out_value = copy;
    }
    kv_store_unlock(snapshot);
    if (!ok) errno = p ? EACCES : ENOENT;
    return ok;
}

typedef struct { FILE* file; bool ok; } snapshot_save_ctx_t;
static bool snapshot_save_record_cb(const char* key, const char* value,
    const qihse_kv_record_meta_t* metadata, void* opaque) {
    snapshot_save_ctx_t* ctx = opaque;
    if (!ctx || !ctx->ok || !metadata) return false;
    ctx->ok = disk_record_write_fields(ctx->file, key, value,
        metadata->expire_time_ms, metadata->classification,
        metadata->sci_compartment, metadata->flags, metadata->change_seq);
    return ctx->ok;
}

int qihse_kv_snapshot_save_user(qihse_kv_store_t* snapshot,
    const char* filepath, qihse_user_t* user) {
    if (!snapshot || !snapshot->memory_snapshot || !filepath || !*filepath || !user) {
        errno = EINVAL;
        return -1;
    }
    uint64_t generation = 0u;
    qihse_user_t* principal = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (!principal || !generation ||
        !qihse_auth_validate_handle_generation(principal, generation)) {
        if (principal) qihse_auth_release_principal_scoped(principal);
        errno = EACCES;
        return -2;
    }
    char tmp[8192];
    FILE* file = NULL;
    if (!atomic_file_begin(filepath, tmp, sizeof(tmp), &file)) {
        qihse_auth_release_principal_scoped(principal);
        return -1;
    }
    snapshot_save_ctx_t ctx = {.file = file, .ok = true};
    bool iter_ok = qihse_kv_snapshot_foreach_record_user(
        snapshot, principal, snapshot_save_record_cb, &ctx);
    if (!iter_ok || !ctx.ok || ferror(file) ||
        !qihse_auth_validate_handle_generation(principal, generation)) {
        fclose(file);
        unlink(tmp);
        qihse_auth_release_principal_scoped(principal);
        errno = iter_ok && ctx.ok ? EACCES : EIO;
        return iter_ok && ctx.ok ? -2 : -1;
    }
    bool committed = atomic_file_commit(file, tmp, filepath);
    qihse_auth_release_principal_scoped(principal);
    return committed ? 0 : -1;
}

static bool replica_snapshot_file_valid(const char* filepath, qihse_user_t* principal,
                                        const char* glob, uint64_t source_highwater);

static int qihse_kv_load_user_internal(qihse_kv_store_t* store, const char* filepath,
                                       qihse_user_t* user, const replica_install_meta_t* install_meta) {
    bool replica_install = install_meta != NULL;
    if (!store || !filepath ||
        (__atomic_load_n(&store->replica_read_only, __ATOMIC_ACQUIRE) && !replica_install)) return -1;
    if (!user || !qihse_auth_user_is_active(user)) { errno = EACCES; return -2; }
    qihse_trinary_trie_t* replacement = NULL; size_t replacement_usage = 0u;
    uint64_t replacement_max_seq = 0u;
    char image_path[4096], meta_path[4096], wal_path[4096];
    const char* dir = get_qihse_data_dir();
    if (!dir || !build_data_path(image_path, sizeof(image_path), "replica-install.image") ||
        !build_data_path(meta_path, sizeof(meta_path), "replica-install.meta") ||
        !build_data_path(wal_path, sizeof(wal_path), "wal.log")) return -1;
    kv_store_wrlock(store);
    if (store->ct_enabled &&
        (store->ct_mode != 2u || store->ct_baseline_sealed ||
         kv_ct_baseline_import_store != store ||
         kv_ct_baseline_import_principal != user)) {
        kv_store_unlock(store); errno = EACCES; return -1;
    }
    if (store->recovery_pending) { kv_store_unlock(store); return -1; }
    replica_install_meta_t meta; bool present = false;
    if (!replica_install_meta_read(meta_path, &meta, &present) || present) {
        kv_store_unlock(store); return -1;
    }
    /* Replacing the complete target also removes its existing records. Deny
     * the whole operation if even one logical label is outside the caller. */
    restore_auth_ctx_t auth = { .user = user, .now = current_time_ms(), .authorized = true };
    qihse_trinary_trie_foreach(store->trie, restore_auth_cb, &auth);
    if (store->sstable_counter > 0 && (!store->sst_meta || store->sst_meta->degraded)) {
        kv_store_unlock(store); return -1;
    }
    if (store->sst_meta) for (size_t i = 0; auth.authorized && i < store->sst_meta->cap; i++) {
        const sst_meta_entry_t* e = &store->sst_meta->slots[i];
        size_t z = 0u;
        if (!e->key || qihse_trinary_trie_search(store->trie, e->key, &z)) continue;
        if ((e->flags & KV_FLAG_TOMBSTONE) != 0u ||
            (e->expire_time_ms != 0u && e->expire_time_ms <= auth.now)) continue;
        if (!qihse_auth_can_access(user, e->classification, e->sci_compartment))
            auth.authorized = false;
        if (e->classification > auth.required_classification)
            auth.required_classification = e->classification;
        auth.required_sci |= e->sci_compartment;
        if ((e->flags & KV_FLAG_TOMBSTONE) == 0u &&
            (e->expire_time_ms == 0u || e->expire_time_ms > auth.now)) auth.has_live = true;
    }
    if (!auth.authorized) { errno = EACCES; kv_store_unlock(store); return -2; }
    if (install_meta) {
        char marker[48]; replica_snapshot_marker_namespace(install_meta->glob, marker);
        kv_replica_cursor_t* checkpoint = cursor_find(store, install_meta->peer, install_meta->glob);
        kv_replica_cursor_t* installed = cursor_find(store, install_meta->peer, marker);
        if (!replica_principal_ok(store, user) ||
            (checkpoint && checkpoint->seq > install_meta->source_seq) ||
            ((!installed || installed->seq == 0u) && auth.has_live)) {
            kv_store_unlock(store); return -1;
        }
    }
    /* Both entry points use one serialized, principal-bound publication. */
    memset(&meta, 0, sizeof(meta));
    if (install_meta) meta = *install_meta;
    else meta.full_image = true;
    if (aimem_durability_test_fail_once("restore-image-write") ||
        !copy_file_atomic_hash(filepath, image_path, &meta.image_hash, user) ||
        !fsync_dir_path(dir)) { kv_store_unlock(store); return -1; }
    if (!parse_snapshot_into_trie(image_path, user, &replacement, &replacement_usage,
                                  &replacement_max_seq)) {
        kv_store_unlock(store); return errno == EACCES ? -2 : -1;
    }
    if (!install_meta) {
        meta.source_seq = __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE);
        if (replacement_max_seq > meta.source_seq) meta.source_seq = replacement_max_seq;
    }
    if (install_meta && !replica_snapshot_file_valid(image_path, user, meta.glob, meta.source_seq)) {
        qihse_trinary_trie_destroy(replacement); kv_store_unlock(store); return -1;
    }
    auth.include_dead = true; /* Every encoded incoming record must be readable. */
    qihse_trinary_trie_foreach(replacement, restore_auth_cb, &auth);
    if (!auth.authorized || !qihse_auth_user_is_active(user)) {
        qihse_trinary_trie_destroy(replacement); kv_store_unlock(store); errno = EACCES; return -2;
    }
    meta.auth_bound = true;
    meta.required_classification = auth.required_classification;
    meta.required_sci = auth.required_sci;
    /* Image rows are already durable in SST0 after publication. The writable
     * memtable must contain only later WAL-backed mutations, not shadow them. */
    qihse_trinary_trie_t* empty = qihse_trinary_trie_create();
    if (!empty) { qihse_trinary_trie_destroy(replacement); kv_store_unlock(store); return -1; }
    qihse_trinary_trie_destroy(replacement);
    replacement = empty;
    replacement_usage = 0u;
    replica_install_test_crash_point("image");
    /* Receiver progress belongs to the source; preserve the target's own
     * mutation floor separately before a replica image can replace its rows. */
    if (install_meta && !image_highwater_publish(
            __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE))) {
        qihse_trinary_trie_destroy(replacement); kv_store_unlock(store); return -1;
    }
    /* A failed directory fsync may have published the intent. Preserve
     * both files and freeze this handle until authenticated recovery. */
    __atomic_store_n(&store->recovery_pending, true, __ATOMIC_RELEASE);
    if (!replica_install_meta_write(meta_path, &meta)) goto publication_failed;
    replica_install_test_crash_point("intent");
    if (!replica_install_recover_image(dir, user)) goto publication_failed;
    replica_install_test_crash_point("wal-replaced");
    int new_wal_fd = open(wal_path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (new_wal_fd < 0) goto publication_failed;
    FILE* new_wal = fdopen(new_wal_fd, "ab");
    if (!new_wal) { close(new_wal_fd); goto publication_failed; }
    qihse_trinary_trie_t* old = store->trie; FILE* old_wal = store->wal_fd;
    store->trie = replacement; store->mem_usage = replacement_usage; store->wal_fd = new_wal; store->wal_unflushed_bytes = 0u;
    /* A restore must not regress the change sequence: the loaded records
     * keep their stamped sequences and the high-water rises to the file's
     * maximum if it was higher.  It is NOT re-stamped — a restore is not a
     * mutation — so a caller holding a cursor from BEFORE a restore should
     * re-baseline with a full export (the restored dataset may be older
     * than the cursor). */
    kv_change_seq_floor(store, replacement_max_seq);
    kv_change_seq_floor(store, meta.source_seq);
    if (old_wal) fclose(old_wal);
    if (old) qihse_trinary_trie_destroy(old);
    store->sstable_counter = 1;
    store->sstable_live_count = 1u;
    sst_meta_index_reset(store);
    sst_fd_cache_clear(store);
    char sstable0[4096];
    const kv_read_context_t context = { .user = user };
    if (!build_data_path(sstable0, sizeof(sstable0), "sstable_0.db") ||
        !sst_index_load_file(store, sstable0, 0, &context)) {
        kv_store_unlock(store); return -1;
    }
    kv_projection_epoch_advance(store);
    replica_install_test_crash_point("sst-wal-durable");
    if (!replica_install_finish_recovery(store, dir, user)) {
        kv_store_unlock(store); return -1;
    }
    __atomic_store_n(&store->recovery_pending, false, __ATOMIC_RELEASE);
    kv_store_unlock(store);
    return 0;
publication_failed:
    qihse_trinary_trie_destroy(replacement);
    kv_store_unlock(store);
    return -1;
}
int qihse_kv_load_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user) {
    return qihse_kv_load_user_internal(store, filepath, user, NULL);
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
    if (!principal || !qihse_auth_user_is_active(principal)) { errno = EACCES; return false; }
    int fd = open_secure_read(filepath);
    if (fd < 0) return false;
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return false; }
    bool valid = true;
    kv_disk_record_t record;
    int rc;
    const kv_read_context_t context = { .user = principal };
    while ((rc = disk_record_read_context(f, &record, &context)) == 1) {
        valid = fnmatch(glob, record.key, 0) == 0 &&
            (record.flags & KV_FLAG_TOMBSTONE) == 0u &&
            (record.change_seq == 0u || record.change_seq <= source_highwater) &&
            qihse_auth_can_access(principal, record.classification,
                                  record.sci_compartment);
        disk_record_free(&record);
        if (!valid) break;
    }
    if (rc < 0 || !qihse_auth_user_is_active(principal)) valid = false;
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
        !replica_principal_ok(store, principal) || !cursor_id_valid(peer_id) ||
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
    replica_install_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    snprintf(meta.peer, sizeof(meta.peer), "%s", peer_id);
    snprintf(meta.glob, sizeof(meta.glob), "%s", namespace_glob);
    meta.source_seq = source_highwater;
    return qihse_kv_load_user_internal(store, filepath, principal, &meta) == 0;
}

bool qihse_kv_ct_receiver_install_baseline(qihse_kv_store_t* store,
    qihse_user_t* principal, qihse_user_t* data_principal,
    const char* source_id, const char* generation,
    const char* filepath, uint64_t baseline_row_seq,
    const unsigned char expected_digest[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(principal) || !data_principal ||
        !qihse_auth_user_is_active(data_principal) || !source_id || !generation ||
        !filepath || !expected_digest || !owner_token) return false;
    kv_store_rdlock(store);
    bool ok = store->ct_enabled && store->ct_mode == 2u &&
        store->replication_principal_id != 0u &&
        qihse_user_get_id(data_principal) == store->replication_principal_id &&
        !store->ct_baseline_sealed && store->ct_durable_lsn == 0u &&
        !store->recovery_pending && ct_token_matches(store, owner_token) &&
        strcmp(store->ct_source_id, source_id) == 0 &&
        strcmp(store->ct_generation, generation) == 0 &&
        store->ct_baseline_lsn == baseline_row_seq;
    kv_store_unlock(store);
    if (!ok) return false;
    int fd = open_secure_read(filepath);
    if (fd < 0) return false;
    unsigned char digest[32];
    ok = ct_fd_sha256(fd, digest);
    close(fd);
    if (!ok || memcmp(digest, expected_digest, 32u) != 0 ||
        !replica_snapshot_file_valid(filepath, data_principal, "*", baseline_row_seq))
        return false;
    if (kv_ct_baseline_import_store) return false;
    kv_ct_baseline_import_store = store;
    kv_ct_baseline_import_principal = data_principal;
    int rc = qihse_kv_load_user_internal(store, filepath, data_principal, NULL);
    kv_ct_baseline_import_principal = NULL;
    kv_ct_baseline_import_store = NULL;
    if (rc != 0) return false;
    kv_store_wrlock(store);
    ok = store->ct_enabled && store->ct_mode == 2u &&
        !store->ct_baseline_sealed && store->ct_durable_lsn == 0u &&
        !store->recovery_pending && ct_token_matches(store, owner_token);
    if (ok) {
        memcpy(store->ct_baseline_digest, digest, 32u);
        store->ct_baseline_sealed = true;
        ok = ct_state_write(store);
        if (!ok) store->recovery_pending = true;
    }
    kv_store_unlock(store);
    return ok;
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
    if (!store || __atomic_load_n(&store->recovery_pending, __ATOMIC_ACQUIRE)) return 0u;
    return __atomic_load_n(&store->change_seq, __ATOMIC_RELAXED);
}

uint64_t qihse_kv_instance_id(qihse_kv_store_t* store) {
    return store && !__atomic_load_n(&store->recovery_pending, __ATOMIC_ACQUIRE) ? store->instance_id : 0u;
}

uint64_t qihse_kv_projection_epoch(qihse_kv_store_t* store) {
    if (!store || __atomic_load_n(&store->recovery_pending, __ATOMIC_ACQUIRE)) return 0u;
    return __atomic_load_n(&store->projection_epoch, __ATOMIC_ACQUIRE);
}

bool qihse_kv_projection_marker(qihse_kv_store_t* store,
                                uint64_t* out_seq, uint64_t* out_epoch) {
    if (!store || !out_seq || !out_epoch) return false;
    kv_store_rdlock(store);
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return false; }
    *out_seq = __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE);
    *out_epoch = __atomic_load_n(&store->projection_epoch, __ATOMIC_ACQUIRE);
    kv_store_unlock(store);
    return true;
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
    qihse_kv_store_t* store;
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
    bool truncated;
    bool ok;
} delta_collect_ctx_t;

/* Grow-by-doubling collector shared by the memtable and SSTable walks.  The
 * array (not one stack buffer per record) keeps frames bounded. */
static bool delta_collect_push(delta_collect_ctx_t* ctx, const char* key, const char* val,
                               const kv_payload_t* p) {
    size_t key_len = strlen(key);
    bool tombstone = (p->flags & KV_FLAG_TOMBSTONE) != 0u;
    size_t value_len = tombstone ? 0u : strlen(val ? val : "");
    if (key_len > SIZE_MAX - 160u || value_len > SIZE_MAX - key_len - 160u) {
        ctx->ok = false;
        return false;
    }
    size_t cost = key_len + value_len + 160u;
    if (ctx->max_records != 0u) {
        /* A visible oversized row cannot be silently skipped: doing so
         * would let a derived index advance past a missing mutation. */
        if (cost > ctx->max_bytes) { ctx->ok = false; return false; }
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
            !before_largest) { ctx->truncated = true; return true; }
        while (ctx->count > 0u &&
               (ctx->count >= ctx->max_records || ctx->bytes + cost > ctx->max_bytes)) {
            ctx->truncated = true;
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
    if (!ct_key_owned_for_read(ctx->store, key)) return true;
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
    if (!ct_key_owned_for_read(ctx->store, key)) return true;
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
                                     size_t* out_count, uint64_t* out_resume_seq,
                                     bool* out_complete) {
    if (out_complete) *out_complete = false;
    if (out_records) *out_records = NULL;
    if (out_count) *out_count = 0u;
    if (out_resume_seq) *out_resume_seq = 0u;
    if (!store || !store->trie || !out_records || !out_count || !out_resume_seq) return -1;

    delta_collect_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.store = store;
    ctx.user = user;
    ctx.since = since_seq;
    ctx.now = current_time_ms();
    ctx.resume = since_seq;   /* the no-leak default: it does not move
                               * unless the principal sees something newer */
    ctx.glob = glob;
    ctx.max_records = max_records;
    ctx.max_bytes = max_bytes;
    ctx.ok = true;

    /* This reads the trie and SSTable metadata as one snapshot: writers are
     * excluded for the whole walk, so records cannot move between the two
     * sources. A READ lock is sufficient for that and lets other readers
     * (interactive KEYS/GET/DBSIZE) proceed concurrently — holding a write
     * lock here serialized every replica delta pull against the entire
     * interactive read path for seconds at a time. The degraded fallback
     * below materializes records into the trie, which mutates, so it alone
     * upgrades to the write lock. */
    bool fast = store->sst_meta && !store->sst_meta->degraded;
    if (fast) kv_store_rdlock(store);
    else kv_store_wrlock(store);
    if (store->recovery_pending || !ct_read_ready(store)) { kv_store_unlock(store); return -1; }
    if (!fast && !compact_sstables_into_memtable(store)) { kv_store_unlock(store); return -1; }
    qihse_trinary_trie_foreach(store->trie, delta_trie_cb, &ctx);
    if (ctx.ok && fast) {
        int rc = sst_foreach_newest(store, true, false, delta_sst_cb, &ctx);
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
    if (out_complete) *out_complete = !ctx.truncated;
    return 0;
}

int qihse_kv_export_incremental_user(qihse_kv_store_t* store, qihse_user_t* user,
                                     uint64_t since_seq,
                                     qihse_kv_delta_record_t** out_records,
                                     size_t* out_count, uint64_t* out_resume_seq) {
    return kv_export_incremental_common(store, user, NULL, since_seq, 0u, 0u,
                                        out_records, out_count, out_resume_seq, NULL);
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
        max_records, max_bytes, out_records, out_count, out_resume_seq, NULL);
}

int qihse_kv_export_incremental_user_bounded_complete(qihse_kv_store_t* store,
    qihse_user_t* user, const char* namespace_glob, uint64_t since_seq,
    size_t max_records, size_t max_bytes,
    qihse_kv_delta_record_t** out_records, size_t* out_count,
    uint64_t* out_resume_seq, bool* out_complete) {
    if (!out_complete || !namespace_glob || !*namespace_glob ||
        max_records == 0u || max_bytes == 0u) {
        if (out_complete) *out_complete = false;
        return -1;
    }
    return kv_export_incremental_common(store, user, namespace_glob, since_seq,
        max_records, max_bytes, out_records, out_count, out_resume_seq, out_complete);
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
    if (store->recovery_pending) { kv_store_unlock(store); return 0; }
    qihse_quantum_defense_ctx_t* ctx = __atomic_load_n(&store->qdd_ctx, __ATOMIC_ACQUIRE);
    bool under_attack = ctx && qihse_qdd_is_under_attack(ctx);
    kv_store_unlock(store);
    return under_attack;
}

#include "qihse_ct_range_export.inc"

