#include "qihse_cluster_ownership_journal.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>

#define QIHSE_OWNERSHIP_JOURNAL_MAGIC 0x4A534F51u /* "QOSJ" */
#define QIHSE_OWNERSHIP_JOURNAL_NAME  "slot-ownership.journal"
#define QIHSE_OWNERSHIP_JOURNAL_FRAME 65u            /* see wire layout below */
#define QIHSE_OWNERSHIP_JOURNAL_V2_MAGIC 0x32534F51u /* "QOS2" */
#define QIHSE_OWNERSHIP_JOURNAL_V2_FRAME 2596u
#define QIHSE_OWNERSHIP_JOURNAL_V3_MAGIC 0x33534F51u /* "QOS3" */
#define QIHSE_OWNERSHIP_JOURNAL_V3_FRAME 2661u
#define QIHSE_OWNERSHIP_JOURNAL_TXN_FRAME_MAX QIHSE_OWNERSHIP_JOURNAL_V3_FRAME
#define QIHSE_OWNERSHIP_JOURNAL_LOCK_NAME "slot-ownership.journal.lock"

/* Serialize journal state transitions across both threads and processes.
 * The lock is on a stable sidecar inode, never the append-only journal inode. */
static pthread_mutex_t journal_process_lock = PTHREAD_MUTEX_INITIALIZER;

static int journal_lock_acquire(const char* data_dir) {
    if (!data_dir || pthread_mutex_lock(&journal_process_lock) != 0) {
        errno = EINVAL; return -1;
    }
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s", data_dir,
                     QIHSE_OWNERSHIP_JOURNAL_LOCK_NAME);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        pthread_mutex_unlock(&journal_process_lock); errno = ENAMETOOLONG; return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) { pthread_mutex_unlock(&journal_process_lock); return -1; }
    struct stat st;
    int saved = 0;
    if (fstat(fd, &st) != 0) saved = errno;
    else if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
             (st.st_mode & 077) != 0 || st.st_nlink != 1) saved = EACCES;
    else if (flock(fd, LOCK_EX) != 0) saved = errno;
    if (saved) {
        close(fd); pthread_mutex_unlock(&journal_process_lock); errno = saved; return -1;
    }
    return fd;
}

static void journal_lock_release(int fd) {
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        (void)close(fd);
    }
    (void)pthread_mutex_unlock(&journal_process_lock);
}

/* Fixed wire layout (little-endian):
 *   [0..3]   magic (uint32)
 *   [4..5]   start (uint16)
 *   [6..7]   end   (uint16)
 *   [8..48]  owner_id (41 bytes, NUL-padded)
 *   [49..56] config_epoch (uint64)
 *   [57..64] FNV-1a checksum of bytes [0..56]
 */

static uint64_t fnv1a64(const uint8_t* p, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void put_u16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v & 0xffu); p[1] = (uint8_t)(v >> 8); }
static void put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu); p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu); p[3] = (uint8_t)((v >> 24) & 0xffu);
}
static void put_u64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}
static uint16_t get_u16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void put_bytes(uint8_t* p, const void* src, size_t n) { memcpy(p, src, n); }
static bool fixed_string(const char* s, size_t cap, bool allow_empty) {
    if (!s) return false;
    size_t n = strnlen(s, cap);
    return n < cap && (allow_empty || n != 0);
}
static bool digest_nonzero(const uint8_t digest[32]) {
    uint8_t v = 0;
    for (size_t i = 0; i < 32; ++i) v |= digest[i];
    return v != 0;
}
static bool valid_lane_id(const char* lane_id) {
    if (!lane_id || !*lane_id) return lane_id != NULL;
    if (strnlen(lane_id, QIHSE_OWNERSHIP_ID_MAX + 1u) != 64u) return false;
    for (size_t i = 0; i < 64u; ++i)
        if (!((lane_id[i] >= '0' && lane_id[i] <= '9') ||
              (lane_id[i] >= 'a' && lane_id[i] <= 'f'))) return false;
    return true;
}
static bool txn_shape_valid(const qihse_cluster_ownership_txn_t* t) {
    if (!t || t->start > t->end || t->end >= QIHSE_CLUSTER_SLOT_COUNT ||
        !fixed_string(t->transfer_id, sizeof(t->transfer_id), false) ||
        !fixed_string(t->source_id, sizeof(t->source_id), false) ||
        !fixed_string(t->target_id, sizeof(t->target_id), false) ||
        !fixed_string(t->source_qkp_id, sizeof(t->source_qkp_id), false) ||
        !fixed_string(t->target_qkp_id, sizeof(t->target_qkp_id), false) ||
        !fixed_string(t->generation, sizeof(t->generation), false) ||
        !fixed_string(t->lane_id, sizeof(t->lane_id), true) ||
        !valid_lane_id(t->lane_id) ||
        !fixed_string(t->next_generation, sizeof(t->next_generation), true) ||
        !fixed_string(t->owner_id, sizeof(t->owner_id), false) ||
        !strcmp(t->source_id, t->target_id) ||
        !strcmp(t->source_qkp_id, t->target_qkp_id)) return false;
    bool bitmap_any = false;
    uint16_t bitmap_first = QIHSE_CLUSTER_SLOT_COUNT, bitmap_last = 0;
    for (uint32_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; ++slot) {
        if (!(t->slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u)))) continue;
        bitmap_any = true;
        if (slot < bitmap_first) bitmap_first = (uint16_t)slot;
        bitmap_last = (uint16_t)slot;
    }
    if (t->next_generation[0] || t->lane_id[0]) {
        if (!bitmap_any || t->start != bitmap_first || t->end != bitmap_last) return false;
        /* A group CT2 receipt describes one exact interval. Promotions may
         * cover sparse membership; transfers may not hide holes in the frame. */
        if (!t->next_generation[0])
            for (uint32_t slot = t->start; slot <= t->end; ++slot)
                if (!(t->slot_bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))))
                    return false;
    } else if (bitmap_any) return false;
    if (t->phase == QIHSE_OWNERSHIP_COMMITTED || t->phase == QIHSE_OWNERSHIP_FINALIZED ||
        t->phase == QIHSE_OWNERSHIP_ADOPTED)
        return (t->next_generation[0] || !strcmp(t->owner_id, t->target_id)) &&
               digest_nonzero(t->proof_digest) &&
               (!t->next_generation[0] || t->lane_id[0] ||
                t->target_lsn >= t->source_lsn);
    if (t->phase == QIHSE_OWNERSHIP_INTENT ||
        t->phase == QIHSE_OWNERSHIP_PREPARED ||
        t->phase == QIHSE_OWNERSHIP_ABORTED) {
        uint8_t v = 0;
        for (size_t i = 0; i < sizeof(t->proof_digest); ++i) v |= t->proof_digest[i];
        return v == 0 && (t->next_generation[0] || !strcmp(t->owner_id, t->source_id)) &&
               t->target_lsn == 0 &&
               (t->phase != QIHSE_OWNERSHIP_ABORTED || !t->next_generation[0]);
    }
    return false;
}

/* V3 adds the stable lane ID after the V2 payload. The receipt digest is an
 * audit binding; peer identity and remote copy still require independent
 * verification before COMMITTED. */
static bool txn_encode(const qihse_cluster_ownership_txn_t* t,
                       uint8_t frame[QIHSE_OWNERSHIP_JOURNAL_V3_FRAME]) {
    if (!txn_shape_valid(t)) { errno = EINVAL; return false; }
    memset(frame, 0, QIHSE_OWNERSHIP_JOURNAL_V3_FRAME);
    put_u32(frame, QIHSE_OWNERSHIP_JOURNAL_V3_MAGIC);
    frame[4] = 3;
    frame[5] = (uint8_t)t->phase;
    put_u16(frame + 8, t->start); put_u16(frame + 10, t->end);
    put_u64(frame + 12, t->config_epoch);
    put_u64(frame + 20, t->source_lsn); put_u64(frame + 28, t->target_lsn);
    put_bytes(frame + 36, t->transfer_id, strlen(t->transfer_id));
    put_bytes(frame + 101, t->source_id, strlen(t->source_id));
    put_bytes(frame + 142, t->target_id, strlen(t->target_id));
    put_bytes(frame + 183, t->generation, strlen(t->generation));
    put_bytes(frame + 248, t->source_qkp_id, strlen(t->source_qkp_id));
    put_bytes(frame + 313, t->target_qkp_id, strlen(t->target_qkp_id));
    put_bytes(frame + 378, t->owner_id, strlen(t->owner_id));
    put_bytes(frame + 419, t->next_generation, strlen(t->next_generation));
    put_bytes(frame + 484, t->proof_digest, sizeof(t->proof_digest));
    put_bytes(frame + 516, t->slot_bitmap, sizeof(t->slot_bitmap));
    put_bytes(frame + 2564, t->lane_id, strlen(t->lane_id));
    unsigned int n = 0;
    if (!EVP_Digest(frame, 2629, frame + 2629, &n, EVP_sha256(), NULL) || n != 32) {
        errno = EIO; return false;
    }
    return true;
}

static bool field_string(const uint8_t* p, size_t cap, char* out, size_t out_cap) {
    const uint8_t* nul = memchr(p, 0, cap);
    if (!nul || (size_t)(nul - p) >= out_cap) return false;
    size_t n = (size_t)(nul - p);
    memcpy(out, p, n); out[n] = '\0';
    /* Require zero padding to make the encoding canonical. */
    for (size_t i = n + 1; i < cap; ++i) if (p[i]) return false;
    return true;
}

static bool txn_decode(const uint8_t* frame, size_t frame_len,
                       qihse_cluster_ownership_txn_t* t) {
    uint8_t digest[32]; unsigned int n = 0;
    bool v3 = get_u32(frame) == QIHSE_OWNERSHIP_JOURNAL_V3_MAGIC;
    if ((!v3 && get_u32(frame) != QIHSE_OWNERSHIP_JOURNAL_V2_MAGIC) ||
        frame_len != (v3 ? QIHSE_OWNERSHIP_JOURNAL_V3_FRAME : QIHSE_OWNERSHIP_JOURNAL_V2_FRAME) ||
        frame[4] != (v3 ? 3 : 2) || frame[6] || frame[7]) return false;
    size_t body_len = v3 ? 2629u : 2564u;
    if (!EVP_Digest(frame, body_len, digest, &n, EVP_sha256(), NULL) || n != 32 ||
        memcmp(digest, frame + body_len, 32)) return false;
    memset(t, 0, sizeof(*t));
    t->phase = (qihse_cluster_ownership_phase_t)frame[5];
    t->start = get_u16(frame + 8); t->end = get_u16(frame + 10);
    t->config_epoch = get_u64(frame + 12); t->source_lsn = get_u64(frame + 20);
    t->target_lsn = get_u64(frame + 28);
    if (!field_string(frame + 36, 65, t->transfer_id, sizeof(t->transfer_id)) ||
        !field_string(frame + 101, 41, t->source_id, sizeof(t->source_id)) ||
        !field_string(frame + 142, 41, t->target_id, sizeof(t->target_id)) ||
        !field_string(frame + 183, 65, t->generation, sizeof(t->generation)) ||
        !field_string(frame + 248, 65, t->source_qkp_id, sizeof(t->source_qkp_id)) ||
        !field_string(frame + 313, 65, t->target_qkp_id, sizeof(t->target_qkp_id)) ||
        !field_string(frame + 378, 41, t->owner_id, sizeof(t->owner_id))) return false;
    if (!field_string(frame + 419, 65, t->next_generation, sizeof(t->next_generation))) return false;
    memcpy(t->proof_digest, frame + 484, sizeof(t->proof_digest));
    memcpy(t->slot_bitmap, frame + 516, sizeof(t->slot_bitmap));
    if (v3 && !field_string(frame + 2564, 65, t->lane_id, sizeof(t->lane_id))) return false;
    return txn_shape_valid(t);
}

static int write_all(int fd, const uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t k = write(fd, p + off, n - off);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return -1;
        off += (size_t)k;
    }
    return 0;
}

static int fsync_data_dir(const char* data_dir) {
#ifdef O_DIRECTORY
    int fd = open(data_dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
#else
    int fd = open(data_dir, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
#endif
    if (fd < 0) return -1;
    int rc = fsync(fd), saved = errno;
    close(fd); errno = saved;
    return rc;
}

static int journal_path(const char* data_dir, char* out, size_t out_cap) {
    int n = snprintf(out, out_cap, "%s/%s", data_dir, QIHSE_OWNERSHIP_JOURNAL_NAME);
    return (n > 0 && (size_t)n < out_cap) ? 0 : -1;
}

static int read_exact_frame(int fd, uint8_t* frame, size_t cap, size_t* out_len) {
    uint8_t magic[4]; size_t got = 0;
    while (got < sizeof(magic)) {
        ssize_t n = read(fd, magic + got, sizeof(magic) - got);
        if (n == 0) { *out_len = got; return got == 0 ? 0 : -1; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        got += (size_t)n;
    }
    uint32_t m = get_u32(magic);
    size_t need = m == QIHSE_OWNERSHIP_JOURNAL_MAGIC ? QIHSE_OWNERSHIP_JOURNAL_FRAME :
                  m == QIHSE_OWNERSHIP_JOURNAL_V2_MAGIC ? QIHSE_OWNERSHIP_JOURNAL_V2_FRAME :
                  m == QIHSE_OWNERSHIP_JOURNAL_V3_MAGIC ? QIHSE_OWNERSHIP_JOURNAL_V3_FRAME : 0;
    if (!need || need > cap) { *out_len = 4; return -1; }
    memcpy(frame, magic, 4); got = 4;
    while (got < need) {
        ssize_t n = read(fd, frame + got, need - got);
        if (n == 0) { *out_len = got; return -1; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return -1;
        got += (size_t)n;
    }
    *out_len = need;
    return m == QIHSE_OWNERSHIP_JOURNAL_MAGIC ? 1 :
        m == QIHSE_OWNERSHIP_JOURNAL_V2_MAGIC ? 2 : 3;
}

static int journal_append_legacy_unlocked(const char* data_dir,
                                          uint16_t start, uint16_t end,
                                          const char* owner_id,
                                          uint64_t config_epoch) {
    if (!data_dir || !owner_id || !*owner_id) { errno = EINVAL; return -1; }
    char path[4096];
    if (journal_path(data_dir, path, sizeof(path)) != 0) { errno = ENAMETOOLONG; return -1; }

    uint8_t frame[QIHSE_OWNERSHIP_JOURNAL_FRAME];
    memset(frame, 0, sizeof(frame));
    put_u32(frame, QIHSE_OWNERSHIP_JOURNAL_MAGIC);
    put_u16(frame + 4, start);
    put_u16(frame + 6, end);
    size_t oid = strlen(owner_id);
    if (oid > QIHSE_CLUSTER_NODE_ID_LEN) oid = QIHSE_CLUSTER_NODE_ID_LEN;
    memcpy(frame + 8, owner_id, oid);
    put_u64(frame + 49, config_epoch);
    uint64_t cksum = fnv1a64(frame, 57u);
    put_u64(frame + 57, cksum);

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t w = 0;
    while (w < (ssize_t)sizeof(frame)) {
        ssize_t n = write(fd, frame + w, sizeof(frame) - (size_t)w);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        w += n;
    }
    if (fsync(fd) != 0) { int e = errno; close(fd); errno = e; return -1; }
    close(fd);
    return 0;
}

int qihse_cluster_ownership_journal_append(const char* data_dir,
                                           uint16_t start, uint16_t end,
                                           const char* owner_id,
                                           uint64_t config_epoch) {
    int lockfd = journal_lock_acquire(data_dir);
    if (lockfd < 0) return -1;
    int result = journal_append_legacy_unlocked(data_dir, start, end, owner_id, config_epoch);
    int saved = errno;
    journal_lock_release(lockfd);
    errno = saved;
    return result;
}

typedef struct {
    bool pending;
    qihse_cluster_ownership_phase_t phase;
    qihse_cluster_ownership_txn_t txn;
    const char* new_intent_id;
    bool transfer_id_seen;
} txn_state_t;
static bool txn_state_cb(const qihse_cluster_ownership_txn_t* t, void* ctx) {
    txn_state_t* s = ctx;
    if (s->new_intent_id && !strcmp(s->new_intent_id, t->transfer_id))
        s->transfer_id_seen = true;
    if (t->phase == QIHSE_OWNERSHIP_INTENT ||
        t->phase == QIHSE_OWNERSHIP_PREPARED ||
        t->phase == QIHSE_OWNERSHIP_COMMITTED) {
        s->pending = true; s->phase = t->phase; s->txn = *t;
    } else { s->pending = false; s->phase = t->phase; memset(&s->txn, 0, sizeof(s->txn)); }
    return true;
}
static bool same_txn(const qihse_cluster_ownership_txn_t* a,
                     const qihse_cluster_ownership_txn_t* b) {
    return !strcmp(a->transfer_id, b->transfer_id) &&
           !strcmp(a->source_id, b->source_id) && !strcmp(a->target_id, b->target_id) &&
           !strcmp(a->source_qkp_id, b->source_qkp_id) &&
           !strcmp(a->target_qkp_id, b->target_qkp_id) &&
           !strcmp(a->generation, b->generation) &&
           !strcmp(a->lane_id, b->lane_id) &&
           !strcmp(a->next_generation, b->next_generation) &&
           (!a->next_generation[0] || !strcmp(a->owner_id, b->owner_id)) &&
           a->start == b->start && a->end == b->end &&
           a->source_lsn == b->source_lsn && a->config_epoch == b->config_epoch &&
           memcmp(a->slot_bitmap, b->slot_bitmap, sizeof(a->slot_bitmap)) == 0;
}
static bool same_intent_prepare(const qihse_cluster_ownership_txn_t* intent,
                                const qihse_cluster_ownership_txn_t* prepared) {
    if (!intent || !prepared || intent->phase != QIHSE_OWNERSHIP_INTENT ||
        prepared->phase != QIHSE_OWNERSHIP_PREPARED ||
        (intent->source_lsn != 0u && intent->source_lsn != prepared->source_lsn))
        return false;
    qihse_cluster_ownership_txn_t a = *intent, b = *prepared;
    a.phase = b.phase;
    a.source_lsn = b.source_lsn;
    /* A lane promotion records its identity before obtaining a common grant.
     * Only this unassigned epoch may be filled by PREPARED; a known epoch is
     * immutable, just like every other request field. */
    if (a.lane_id[0] && a.next_generation[0] && !a.config_epoch && b.config_epoch)
        a.config_epoch = b.config_epoch;
    return same_txn(&a, &b);
}

static int journal_append_txn_unlocked(
    const char* data_dir, const qihse_cluster_ownership_txn_t* txn,
    bool* out_write_may_have_occurred) {
    if (out_write_may_have_occurred) *out_write_may_have_occurred = false;
    if (!data_dir || !txn_shape_valid(txn)) { errno = EINVAL; return -1; }
    txn_state_t state = {
        .new_intent_id = txn->phase == QIHSE_OWNERSHIP_INTENT
            ? txn->transfer_id : NULL
    };
    bool unresolved = false;
    int replayed = qihse_cluster_ownership_journal_replay_txn(
        data_dir, txn_state_cb, &state, &unresolved);
    if (replayed < 0) { if (!errno) errno = EBUSY; return -1; }
    if (state.transfer_id_seen) { errno = EEXIST; return -1; }
    bool transition_ok = false;
    if (txn->phase == QIHSE_OWNERSHIP_INTENT)
        transition_ok = !state.pending;
    else if (txn->phase == QIHSE_OWNERSHIP_PREPARED)
        transition_ok = (!state.pending) ||
            (state.pending && state.phase == QIHSE_OWNERSHIP_INTENT &&
             same_intent_prepare(&state.txn, txn));
    else if (txn->phase == QIHSE_OWNERSHIP_COMMITTED || txn->phase == QIHSE_OWNERSHIP_ABORTED)
        transition_ok = state.pending &&
            (state.phase == QIHSE_OWNERSHIP_PREPARED ||
             (txn->phase == QIHSE_OWNERSHIP_ABORTED &&
              state.phase == QIHSE_OWNERSHIP_INTENT)) &&
            same_txn(&state.txn, txn);
    else if (txn->phase == QIHSE_OWNERSHIP_FINALIZED)
        transition_ok = state.pending && state.phase == QIHSE_OWNERSHIP_COMMITTED &&
                        same_txn(&state.txn, txn);
    else if (txn->phase == QIHSE_OWNERSHIP_ADOPTED)
        transition_ok = !state.pending && txn->next_generation[0];
    if (!transition_ok) {
        errno = EPROTO; return -1;
    }
    uint8_t frame[QIHSE_OWNERSHIP_JOURNAL_V3_FRAME];
    if (!txn_encode(txn, frame)) return -1;
    char path[4096];
    if (journal_path(data_dir, path, sizeof(path)) != 0) { errno = ENAMETOOLONG; return -1; }
    struct stat before;
    bool created = lstat(path, &before) != 0 && errno == ENOENT;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) != 0 || st.st_nlink != 1) {
        int e = errno ? errno : EACCES; close(fd); errno = e; return -1;
    }
    if (out_write_may_have_occurred) *out_write_may_have_occurred = true;
    int ok = write_all(fd, frame, sizeof(frame));
    if (ok == 0 && fsync(fd) != 0) ok = -1;
    if (ok == 0 && created && fsync_data_dir(data_dir) != 0) ok = -1;
    int e = errno;
    if (close(fd) != 0 && ok == 0) { ok = -1; e = errno; }
    errno = e;
    return ok;
}

int qihse_cluster_ownership_journal_append_txn(
    const char* data_dir, const qihse_cluster_ownership_txn_t* txn) {
    bool write_may_have_occurred = false;
    return qihse_cluster_ownership_journal_append_txn_ex(
        data_dir, txn, &write_may_have_occurred);
}

int qihse_cluster_ownership_journal_append_txn_ex(
    const char* data_dir, const qihse_cluster_ownership_txn_t* txn,
    bool* out_write_may_have_occurred) {
    if (out_write_may_have_occurred) *out_write_may_have_occurred = false;
    if (!out_write_may_have_occurred) { errno = EINVAL; return -1; }
    int lockfd = journal_lock_acquire(data_dir);
    if (lockfd < 0) return -1;
    int result = journal_append_txn_unlocked(data_dir, txn,
        out_write_may_have_occurred);
    int saved = errno;
    journal_lock_release(lockfd);
    errno = saved;
    return result;
}

int qihse_cluster_ownership_journal_replay_txn(
    const char* data_dir, qihse_cluster_ownership_txn_cb cb, void* ctx,
    bool* out_unresolved) {
    if (out_unresolved) *out_unresolved = false;
    if (!data_dir || !out_unresolved) { errno = EINVAL; return -1; }
    char path[4096];
    if (journal_path(data_dir, path, sizeof(path)) != 0) { errno = ENAMETOOLONG; return -1; }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    uint8_t* frame = malloc(QIHSE_OWNERSHIP_JOURNAL_TXN_FRAME_MAX);
    if (!frame) { close(fd); errno = ENOMEM; return -1; }
    int replayed = 0; bool pending = false;
    qihse_cluster_ownership_phase_t active_phase = 0;
    qihse_cluster_ownership_txn_t active;
    for (;;) {
        size_t length = 0;
        int kind = read_exact_frame(fd, frame, QIHSE_OWNERSHIP_JOURNAL_TXN_FRAME_MAX, &length);
        if (kind == 0) break;
        if (kind < 0) { *out_unresolved = true; free(frame); close(fd); errno = EILSEQ; return -1; }
        if (kind == 1) {
            uint64_t stored = get_u64(frame + 57);
            if (stored != fnv1a64(frame, 57u)) { *out_unresolved = true; free(frame); close(fd); errno = EILSEQ; return -1; }
            continue;
        }
        qihse_cluster_ownership_txn_t t;
        if (!txn_decode(frame, length, &t)) { *out_unresolved = true; free(frame); close(fd); errno = EILSEQ; return -1; }
        if (t.phase == QIHSE_OWNERSHIP_INTENT) {
            if (pending) { *out_unresolved = true; free(frame); close(fd); errno = EPROTO; return -1; }
            active = t; pending = true; active_phase = QIHSE_OWNERSHIP_INTENT;
        } else if (t.phase == QIHSE_OWNERSHIP_PREPARED) {
            if (!pending) {
                active = t; pending = true; active_phase = QIHSE_OWNERSHIP_PREPARED;
            } else if (active_phase == QIHSE_OWNERSHIP_INTENT &&
                       same_intent_prepare(&active, &t)) {
                active = t; active_phase = QIHSE_OWNERSHIP_PREPARED;
            } else {
                *out_unresolved = true; free(frame); close(fd); errno = EPROTO; return -1;
            }
        } else if (t.phase == QIHSE_OWNERSHIP_COMMITTED) {
            if (!pending ||
                active_phase != QIHSE_OWNERSHIP_PREPARED ||
                !same_txn(&active, &t)) {
                *out_unresolved = true; free(frame); close(fd); errno = EPROTO; return -1;
            }
            active = t; active_phase = QIHSE_OWNERSHIP_COMMITTED;
        } else if (t.phase == QIHSE_OWNERSHIP_FINALIZED) {
            if (!pending || active_phase != QIHSE_OWNERSHIP_COMMITTED || !same_txn(&active, &t)) {
                *out_unresolved = true; free(frame); close(fd); errno = EPROTO; return -1;
            }
            pending = false; active_phase = QIHSE_OWNERSHIP_FINALIZED;
            memset(&active, 0, sizeof(active));
        } else if (t.phase == QIHSE_OWNERSHIP_ADOPTED) {
            if (pending || !t.next_generation[0]) {
                *out_unresolved = true; free(frame); close(fd); errno = EPROTO; return -1;
            }
            active_phase = QIHSE_OWNERSHIP_ADOPTED;
        } else {
            if (!pending ||
                (active_phase != QIHSE_OWNERSHIP_PREPARED &&
                 active_phase != QIHSE_OWNERSHIP_INTENT) ||
                !same_txn(&active, &t)) {
                *out_unresolved = true; free(frame); close(fd); errno = EPROTO; return -1;
            }
            pending = false; active_phase = QIHSE_OWNERSHIP_ABORTED;
            memset(&active, 0, sizeof(active));
        }
        if (cb && !cb(&t, ctx)) { free(frame); close(fd); errno = ECANCELED; return -1; }
        replayed++;
    }
    close(fd);
    free(frame);
    *out_unresolved = pending;
    return replayed;
}

int qihse_cluster_ownership_journal_replay(const char* data_dir,
                                           qihse_cluster_ownership_journal_cb cb,
                                           void* ctx) {
    if (!data_dir || !cb) { errno = EINVAL; return -1; }
    char path[4096];
    if (journal_path(data_dir, path, sizeof(path)) != 0) { errno = ENAMETOOLONG; return -1; }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return (errno == ENOENT) ? 0 : -1; /* no journal yet = nothing to replay */

    int replayed = 0;
    uint8_t frame[QIHSE_OWNERSHIP_JOURNAL_V3_FRAME];
    for (;;) {
        size_t length = 0;
        int kind = read_exact_frame(fd, frame, sizeof(frame), &length);
        if (kind == 0) break;
        if (kind < 0) break; /* corrupt/torn tail: preserve earlier records */
        if (kind == 2 || kind == 3) continue; /* transfer journals replay only in fenced runtime */
        uint64_t stored = get_u64(frame + 57);
        if (stored != fnv1a64(frame, 57u)) {
            break; /* corrupt/torn entry — stop, preserve earlier valid entries */
        }
        qihse_cluster_ownership_entry_t e;
        e.start = get_u16(frame + 4);
        e.end = get_u16(frame + 6);
        memcpy(e.owner_id, frame + 8, QIHSE_CLUSTER_NODE_ID_LEN);
        e.owner_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
        e.config_epoch = get_u64(frame + 49);
        cb(&e, ctx);
        replayed++;
    }
    close(fd);
    return replayed;
}
