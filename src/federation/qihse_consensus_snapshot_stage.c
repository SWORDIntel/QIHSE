#include "qihse_consensus_snapshot_stage.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define QCSS_MAGIC "QCSSTG1\n"
#define QCSS_MAGIC_SIZE 8u
#define QCSS_RECORD_MAX 4096u
#define QCSS_FILE_MAX (32u * 1024u * 1024u)
#define QCSS_HEADER_RECORD 1u
#define QCSS_CHUNK_RECORD 2u
#define QCSS_REBIND_RECORD 3u

typedef struct {
    uint64_t first;
    size_t count;
    bool final_chunk;
    uint64_t digest;
} qcss_chunk_ref_t;

typedef struct {
    const uint8_t* p;
    size_t len;
    size_t n;
    bool ok;
} qcss_reader_t;

struct qihse_consensus_snapshot_stage {
    int fd;
    bool poisoned;
    pthread_mutex_t lock;
    char path[QIHSE_CONSENSUS_RECORD_PATH_MAX + 1u];
    char group[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    qihse_consensus_validate_data_fn validate_data;
    void* validate_data_context;
    bool require_data_validator;

    bool has_transfer;
    bool complete;
    uint64_t transfer_id;
    uint64_t total_entries;
    uint64_t last_included_term;
    uint64_t snapshot_fencing_epoch;
    uint64_t journal_generation;
    uint64_t digest;
    uint64_t term;
    uint64_t fencing_epoch;
    qihse_uuid_t from;
    qihse_uuid_t to;

    qihse_consensus_entry_t* entries;
    size_t entry_count;
    size_t entry_cap;
    qcss_chunk_ref_t* chunks;
    size_t chunk_count;
    size_t chunk_cap;
};

static bool qcss_active(const qihse_user_t* principal) {
    return principal && qihse_auth_user_is_active(principal);
}

static bool qcss_group_valid(const char* s) {
    if (!s) return false;
    size_t n = 0u;
    while (n <= QIHSE_CONSENSUS_GROUP_ID_MAX && s[n]) n++;
    if (!n || n > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    for (size_t i = 0u; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
              c == '/' || c == ':' || c == '+')) return false;
    }
    return true;
}

static bool qcss_path_valid(const char* path) {
    if (!path || !path[0] || path[0] == '/') return false;
    size_t n = 0u;
    while (path[n]) {
        if (++n > QIHSE_CONSENSUS_RECORD_PATH_MAX) return false;
    }
    const char* p = path;
    while (*p) {
        const char* start = p;
        while (*p && *p != '/') p++;
        size_t part = (size_t)(p - start);
        if (part == 2u && start[0] == '.' && start[1] == '.') return false;
        if (*p == '/') p++;
    }
    return true;
}

static bool qcss_sync_parent_directory(const char* path) {
    char parent[QIHSE_CONSENSUS_RECORD_PATH_MAX + 1u];
    size_t n = strlen(path);
    if (n > QIHSE_CONSENSUS_RECORD_PATH_MAX) return false;
    memcpy(parent, path, n + 1u);
    char* slash = strrchr(parent, '/');
    if (slash) {
        if (slash == parent) slash[1] = '\0';
        else *slash = '\0';
    } else {
        parent[0] = '.';
        parent[1] = '\0';
    }
    int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return false;
    bool ok = fsync(dirfd) == 0;
    close(dirfd);
    return ok;
}

static uint64_t qcss_checksum(const uint8_t* p, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0u; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void qcss_put_u8(uint8_t* p, size_t* n, uint8_t v) {
    p[(*n)++] = v;
}

static void qcss_put_u16(uint8_t* p, size_t* n, uint16_t v) {
    p[(*n)++] = (uint8_t)(v >> 8);
    p[(*n)++] = (uint8_t)v;
}

static void qcss_put_u32(uint8_t* p, size_t* n, uint32_t v) {
    p[(*n)++] = (uint8_t)(v >> 24);
    p[(*n)++] = (uint8_t)(v >> 16);
    p[(*n)++] = (uint8_t)(v >> 8);
    p[(*n)++] = (uint8_t)v;
}

static void qcss_put_u64(uint8_t* p, size_t* n, uint64_t v) {
    for (unsigned i = 0u; i < 8u; i++)
        p[(*n)++] = (uint8_t)(v >> (56u - 8u * i));
}

static void qcss_put_entry(uint8_t* p, size_t* n,
                           const qihse_consensus_entry_t* e) {
    qcss_put_u64(p, n, e->index);
    qcss_put_u64(p, n, e->term);
    qcss_put_u64(p, n, e->journal_generation);
    qcss_put_u64(p, n, e->hlc.physical_ms);
    qcss_put_u32(p, n, e->hlc.logical);
    qcss_put_u16(p, n, e->classif);
    qcss_put_u16(p, n, e->sci);
    qcss_put_u8(p, n, (uint8_t)e->type);
    qcss_put_u16(p, n, (uint16_t)e->payload_len);
    if (e->payload_len) {
        memcpy(p + *n, e->payload, e->payload_len);
        *n += e->payload_len;
    }
}

static uint8_t qcss_get_u8(qcss_reader_t* r) {
    if (r->n >= r->len) { r->ok = false; return 0u; }
    return r->p[r->n++];
}

static uint16_t qcss_get_u16(qcss_reader_t* r) {
    uint16_t a = qcss_get_u8(r), b = qcss_get_u8(r);
    return (uint16_t)((a << 8) | b);
}

static uint32_t qcss_get_u32(qcss_reader_t* r) {
    uint32_t a = qcss_get_u8(r), b = qcss_get_u8(r);
    uint32_t c = qcss_get_u8(r), d = qcss_get_u8(r);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static uint64_t qcss_get_u64(qcss_reader_t* r) {
    uint64_t v = 0u;
    for (unsigned i = 0u; i < 8u; i++) v = (v << 8) | qcss_get_u8(r);
    return v;
}

static bool qcss_get_bytes(qcss_reader_t* r, void* out, size_t n) {
    if (!r->ok || n > r->len - r->n) { r->ok = false; return false; }
    if (n) memcpy(out, r->p + r->n, n);
    r->n += n;
    return true;
}

static bool qcss_get_entry(qcss_reader_t* r, qihse_consensus_entry_t* e) {
    memset(e, 0, sizeof(*e));
    e->index = qcss_get_u64(r);
    e->term = qcss_get_u64(r);
    e->journal_generation = qcss_get_u64(r);
    e->hlc.physical_ms = qcss_get_u64(r);
    e->hlc.logical = qcss_get_u32(r);
    e->classif = qcss_get_u16(r);
    e->sci = qcss_get_u16(r);
    e->type = (qihse_consensus_entry_type_t)qcss_get_u8(r);
    e->payload_len = qcss_get_u16(r);
    if (!r->ok || e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX ||
        e->type < QIHSE_CONSENSUS_ENTRY_DATA ||
        e->type > QIHSE_CONSENSUS_ENTRY_CONFIG_JOINT_END) return false;
    return qcss_get_bytes(r, e->payload, e->payload_len);
}

static bool qcss_write_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t wrote = write(fd, p, n);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) return false;
        p += (size_t)wrote;
        n -= (size_t)wrote;
    }
    return true;
}

static bool qcss_persist_record(qihse_consensus_snapshot_stage_t* s,
                                const uint8_t* payload, size_t payload_len) {
    if (payload_len == 0u || payload_len > QCSS_RECORD_MAX || s->poisoned)
        return false;
    uint8_t frame[4u + QCSS_RECORD_MAX + 8u];
    size_t n = 0u;
    qcss_put_u32(frame, &n, (uint32_t)payload_len);
    memcpy(frame + n, payload, payload_len);
    n += payload_len;
    qcss_put_u64(frame, &n, qcss_checksum(payload, payload_len));
    struct stat st;
    if (fstat(s->fd, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > QCSS_FILE_MAX ||
        n > QCSS_FILE_MAX - (uint64_t)st.st_size) return false;
    if (!qcss_write_all(s->fd, frame, n) || fdatasync(s->fd) != 0) {
        s->poisoned = true;
        return false;
    }
    return true;
}

static bool qcss_record_fits(qihse_consensus_snapshot_stage_t* s,
                             size_t payload_len) {
    struct stat st;
    uint64_t frame_len = 4u + (uint64_t)payload_len + 8u;
    return fstat(s->fd, &st) == 0 && st.st_size >= 0 &&
           (uint64_t)st.st_size <= QCSS_FILE_MAX &&
           frame_len <= QCSS_FILE_MAX - (uint64_t)st.st_size;
}

static bool qcss_metadata_matches(const qihse_consensus_snapshot_stage_t* s,
                                  const qihse_consensus_msg_t* m) {
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    return strcmp(s->group, m->group_id) == 0 &&
           qihse_uuid_equal(&s->from, &m->from) &&
           qihse_uuid_equal(&s->to, &m->to) && s->term == m->term &&
           s->fencing_epoch == m->fencing_epoch &&
           s->transfer_id == c->transfer_id && s->total_entries == c->total_entries &&
           s->last_included_term == c->last_included_term &&
           s->snapshot_fencing_epoch == c->snapshot_fencing_epoch &&
           s->journal_generation == c->journal_generation && s->digest == c->digest;
}

static bool qcss_validate_message(const qihse_consensus_snapshot_stage_t* s,
                                  const qihse_user_t* principal,
                                  const qihse_consensus_msg_t* m,
                                  qihse_consensus_snapshot_stage_result_t* why);
static bool qcss_entry_equal(const qihse_consensus_entry_t* a,
                             const qihse_consensus_entry_t* b);

static bool qcss_snapshot_descriptor_matches(
    const qihse_consensus_snapshot_stage_t* s,
    const qihse_consensus_msg_t* m) {
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    return strcmp(s->group, m->group_id) == 0 &&
           qihse_uuid_equal(&s->from, &m->from) &&
           qihse_uuid_equal(&s->to, &m->to) &&
           s->transfer_id == c->transfer_id &&
           s->total_entries == c->total_entries &&
           s->last_included_term == c->last_included_term &&
           s->snapshot_fencing_epoch == c->snapshot_fencing_epoch &&
           s->journal_generation == c->journal_generation &&
           s->digest == c->digest;
}

static bool qcss_rebind_chunk_matches(const qihse_consensus_snapshot_stage_t* s,
                                      const qihse_consensus_msg_t* m) {
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    uint64_t next_index = (uint64_t)s->entry_count + 1u;
    if (c->first_entry_index > next_index) return false;
    if (c->first_entry_index == next_index) return true;
    for (size_t k = 0u; k < s->chunk_count; k++) {
        const qcss_chunk_ref_t* ref = &s->chunks[k];
        if (ref->first != c->first_entry_index) continue;
        if (ref->count != c->entry_count || ref->final_chunk != c->final_chunk ||
            ref->digest != c->chunk_digest) return false;
        for (size_t i = 0u; i < c->entry_count; i++)
            if (!qcss_entry_equal(
                    &s->entries[(size_t)c->first_entry_index - 1u + i],
                    &c->entries[i])) return false;
        return true;
    }
    return false;
}

static size_t qcss_encode_rebind(
    const qihse_consensus_snapshot_stage_t* s,
    const qihse_consensus_msg_t* m, uint8_t* out) {
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    size_t n = 0u;
    qcss_put_u8(out, &n, QCSS_REBIND_RECORD);
    memcpy(out + n, s->from.bytes, QIHSE_UUID_BYTES); n += QIHSE_UUID_BYTES;
    memcpy(out + n, s->to.bytes, QIHSE_UUID_BYTES); n += QIHSE_UUID_BYTES;
    qcss_put_u64(out, &n, s->term);
    qcss_put_u64(out, &n, s->fencing_epoch);
    qcss_put_u64(out, &n, m->term);
    qcss_put_u64(out, &n, m->fencing_epoch);
    qcss_put_u64(out, &n, c->transfer_id);
    qcss_put_u64(out, &n, c->total_entries);
    qcss_put_u64(out, &n, c->last_included_term);
    qcss_put_u64(out, &n, c->snapshot_fencing_epoch);
    qcss_put_u64(out, &n, c->journal_generation);
    qcss_put_u64(out, &n, c->digest);
    return n;
}

static bool qcss_apply_rebind(qihse_consensus_snapshot_stage_t* s,
                              const qihse_user_t* principal,
                              const qihse_consensus_msg_t* m,
                              bool persist) {
    qihse_consensus_snapshot_stage_result_t why;
    if (!qcss_validate_message(s, principal, m, &why) || !s->has_transfer ||
        !qcss_snapshot_descriptor_matches(s, m) ||
        !qcss_rebind_chunk_matches(s, m) ||
        m->term <= s->term || m->fencing_epoch <= s->fencing_epoch)
        return false;

    uint8_t record[128];
    size_t record_len = qcss_encode_rebind(s, m, record);
    if (persist && !qcss_persist_record(s, record, record_len)) return false;
    s->term = m->term;
    s->fencing_epoch = m->fencing_epoch;
    return true;
}

static bool qcss_validate_message(const qihse_consensus_snapshot_stage_t* s,
                                  const qihse_user_t* principal,
                                  const qihse_consensus_msg_t* m,
                                  qihse_consensus_snapshot_stage_result_t* why) {
    if (!qcss_active(principal)) { *why = QIHSE_SNAPSHOT_STAGE_AUTH; return false; }
    if (!m || m->type != QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK ||
        !qcss_group_valid(m->group_id) || strcmp(m->group_id, s->group) != 0 ||
        qihse_uuid_is_nil(&m->from) || qihse_uuid_is_nil(&m->to) ||
        m->fencing_epoch < m->term) {
        *why = QIHSE_SNAPSHOT_STAGE_INVALID;
        return false;
    }
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    if (!c->transfer_id || !c->total_entries ||
        c->total_entries > QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES ||
        c->first_entry_index == 0u || c->first_entry_index > c->total_entries ||
        c->entry_count == 0u ||
        c->entry_count > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES ||
        c->first_entry_index > UINT64_MAX - (uint64_t)c->entry_count + 1u ||
        c->snapshot_fencing_epoch < c->last_included_term ||
        c->snapshot_fencing_epoch > m->fencing_epoch ||
        c->last_included_term > m->term ||
        c->journal_generation == 0u) {
        *why = c->total_entries > QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES
                   ? QIHSE_SNAPSHOT_STAGE_LIMIT : QIHSE_SNAPSHOT_STAGE_INVALID;
        return false;
    }
    uint64_t last = c->first_entry_index + (uint64_t)c->entry_count - 1u;
    if (last > c->total_entries || c->final_chunk != (last == c->total_entries)) {
        *why = QIHSE_SNAPSHOT_STAGE_INVALID;
        return false;
    }
    uint64_t previous_term = 0u, previous_gen = 0u;
    for (size_t i = 0u; i < c->entry_count; i++) {
        const qihse_consensus_entry_t* e = &c->entries[i];
        if (e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX ||
            e->type < QIHSE_CONSENSUS_ENTRY_DATA ||
            e->type > QIHSE_CONSENSUS_ENTRY_CONFIG_JOINT_END ||
            e->index != c->first_entry_index + (uint64_t)i ||
            e->term > c->last_included_term ||
            e->journal_generation > c->journal_generation ||
            (i && (e->term < previous_term || e->journal_generation <= previous_gen))) {
            *why = QIHSE_SNAPSHOT_STAGE_INVALID;
            return false;
        }
        if (!qihse_auth_can_access(principal, e->classif, e->sci)) {
            *why = QIHSE_SNAPSHOT_STAGE_AUTH;
            return false;
        }
        if (e->type == QIHSE_CONSENSUS_ENTRY_DATA && s->validate_data &&
            !s->validate_data(s->validate_data_context, e)) {
            *why = QIHSE_SNAPSHOT_STAGE_INTEGRITY;
            return false;
        }
        previous_term = e->term;
        previous_gen = e->journal_generation;
    }
    if (c->final_chunk &&
        (c->entries[c->entry_count - 1u].term != c->last_included_term ||
         c->entries[c->entry_count - 1u].journal_generation != c->journal_generation)) {
        *why = QIHSE_SNAPSHOT_STAGE_INVALID;
        return false;
    }
    if (qihse_consensus_snapshot_chunk_digest(c) != c->chunk_digest) {
        *why = QIHSE_SNAPSHOT_STAGE_INTEGRITY;
        return false;
    }
    *why = QIHSE_SNAPSHOT_STAGE_OK;
    return true;
}

static bool qcss_reserve_chunks(qihse_consensus_snapshot_stage_t* s,
                                size_t need) {
    if (need <= s->chunk_cap) return true;
    size_t cap = s->chunk_cap ? s->chunk_cap * 2u : 8u;
    while (cap < need) {
        if (cap > QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES / 2u) {
            cap = QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES;
            break;
        }
        cap *= 2u;
    }
    if (cap > QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES ||
        cap > SIZE_MAX / sizeof(*s->chunks)) return false;
    qcss_chunk_ref_t* p = realloc(s->chunks, cap * sizeof(*p));
    if (!p) return false;
    s->chunks = p;
    s->chunk_cap = cap;
    return true;
}

static bool qcss_set_header(qihse_consensus_snapshot_stage_t* s,
                            const qihse_consensus_msg_t* m) {
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    if (c->first_entry_index != 1u ||
        c->total_entries > SIZE_MAX / sizeof(*s->entries)) return false;
    qihse_consensus_entry_t* entries = calloc((size_t)c->total_entries,
                                              sizeof(*entries));
    if (!entries) return false;
    s->entries = entries;
    s->entry_cap = (size_t)c->total_entries;
    s->has_transfer = true;
    snprintf(s->group, sizeof(s->group), "%s", m->group_id);
    s->from = m->from;
    s->to = m->to;
    s->term = m->term;
    s->fencing_epoch = m->fencing_epoch;
    s->transfer_id = c->transfer_id;
    s->total_entries = c->total_entries;
    s->last_included_term = c->last_included_term;
    s->snapshot_fencing_epoch = c->snapshot_fencing_epoch;
    s->journal_generation = c->journal_generation;
    s->digest = c->digest;
    return true;
}

static void qcss_forget_transfer(qihse_consensus_snapshot_stage_t* s);
static size_t qcss_encode_header(const qihse_consensus_msg_t* m,
                                 uint8_t* out);

/* Atomically swap the durable file for a new, empty descriptor. The current
 * inode remains locked while the replacement is prepared; the temporary inode
 * is also locked before rename, preventing a second opener from slipping into
 * the rename window. The stage's in-memory descriptor changes only after the
 * rename makes the complete new header visible. */
static qihse_consensus_snapshot_stage_result_t qcss_replace_file(
    qihse_consensus_snapshot_stage_t* s,
    const qihse_consensus_msg_t* m) {
    qihse_consensus_snapshot_stage_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.fd = -1;
    snprintf(candidate.group, sizeof(candidate.group), "%s", s->group);
    if (!qcss_set_header(&candidate, m)) return QIHSE_SNAPSHOT_STAGE_LIMIT;

    uint8_t header[QCSS_RECORD_MAX];
    size_t header_len = qcss_encode_header(m, header);
    size_t path_len = strlen(s->path);
    char temporary[QIHSE_CONSENSUS_RECORD_PATH_MAX + 32u];
    if (path_len + sizeof(".replace.XXXXXX") > sizeof(temporary)) {
        free(candidate.entries);
        return QIHSE_SNAPSHOT_STAGE_LIMIT;
    }
    int printed = snprintf(temporary, sizeof(temporary), "%s.replace.XXXXXX",
                           s->path);
    if (printed <= 0 || (size_t)printed >= sizeof(temporary)) {
        free(candidate.entries);
        return QIHSE_SNAPSHOT_STAGE_LIMIT;
    }

    int fd = mkstemp(temporary);
    if (fd < 0) {
        free(candidate.entries);
        return QIHSE_SNAPSHOT_STAGE_IO;
    }
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    bool ok = fchmod(fd, S_IRUSR | S_IWUSR) == 0 &&
              flock(fd, LOCK_EX | LOCK_NB) == 0 &&
              qcss_write_all(fd, (const uint8_t*)QCSS_MAGIC, QCSS_MAGIC_SIZE) &&
              fdatasync(fd) == 0;
    qihse_consensus_snapshot_stage_t replacement_file;
    memset(&replacement_file, 0, sizeof(replacement_file));
    replacement_file.fd = fd;
    if (ok) ok = qcss_persist_record(&replacement_file, header, header_len);
    if (!ok) {
        close(fd);
        unlink(temporary);
        free(candidate.entries);
        return QIHSE_SNAPSHOT_STAGE_IO;
    }

    if (rename(temporary, s->path) != 0) {
        close(fd);
        unlink(temporary);
        free(candidate.entries);
        return QIHSE_SNAPSHOT_STAGE_IO;
    }

    int old_fd = s->fd;
    s->fd = fd;
    qcss_forget_transfer(s);
    s->entries = candidate.entries;
    s->entry_cap = candidate.entry_cap;
    s->has_transfer = candidate.has_transfer;
    s->from = candidate.from;
    s->to = candidate.to;
    s->term = candidate.term;
    s->fencing_epoch = candidate.fencing_epoch;
    s->transfer_id = candidate.transfer_id;
    s->total_entries = candidate.total_entries;
    s->last_included_term = candidate.last_included_term;
    s->snapshot_fencing_epoch = candidate.snapshot_fencing_epoch;
    s->journal_generation = candidate.journal_generation;
    s->digest = candidate.digest;
    candidate.entries = NULL;
    close(old_fd);

    if (!qcss_sync_parent_directory(s->path)) {
        s->poisoned = true;
        return QIHSE_SNAPSHOT_STAGE_IO;
    }
    return QIHSE_SNAPSHOT_STAGE_OK;
}

static void qcss_forget_transfer(qihse_consensus_snapshot_stage_t* s) {
    free(s->entries);
    s->entries = NULL;
    s->entry_count = 0u;
    s->entry_cap = 0u;
    s->chunk_count = 0u;
    s->has_transfer = false;
    s->complete = false;
    s->transfer_id = 0u;
    s->total_entries = 0u;
    s->last_included_term = 0u;
    s->snapshot_fencing_epoch = 0u;
    s->journal_generation = 0u;
    s->digest = 0u;
    s->term = 0u;
    s->fencing_epoch = 0u;
    memset(&s->from, 0, sizeof(s->from));
    memset(&s->to, 0, sizeof(s->to));
}

static size_t qcss_encode_header(const qihse_consensus_msg_t* m,
                                 uint8_t* out) {
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
    size_t n = 0u, group_len = strlen(m->group_id);
    qcss_put_u8(out, &n, QCSS_HEADER_RECORD);
    qcss_put_u8(out, &n, (uint8_t)group_len);
    memcpy(out + n, m->group_id, group_len); n += group_len;
    memcpy(out + n, m->from.bytes, QIHSE_UUID_BYTES); n += QIHSE_UUID_BYTES;
    memcpy(out + n, m->to.bytes, QIHSE_UUID_BYTES); n += QIHSE_UUID_BYTES;
    qcss_put_u64(out, &n, m->term);
    qcss_put_u64(out, &n, m->fencing_epoch);
    qcss_put_u64(out, &n, c->transfer_id);
    qcss_put_u64(out, &n, c->total_entries);
    qcss_put_u64(out, &n, c->last_included_term);
    qcss_put_u64(out, &n, c->snapshot_fencing_epoch);
    qcss_put_u64(out, &n, c->journal_generation);
    qcss_put_u64(out, &n, c->digest);
    return n;
}

static size_t qcss_encode_chunk(const qihse_consensus_snapshot_chunk_t* c,
                                uint8_t* out) {
    size_t n = 0u;
    qcss_put_u8(out, &n, QCSS_CHUNK_RECORD);
    qcss_put_u64(out, &n, c->first_entry_index);
    qcss_put_u8(out, &n, (uint8_t)c->entry_count);
    qcss_put_u8(out, &n, c->final_chunk ? 1u : 0u);
    qcss_put_u64(out, &n, c->chunk_digest);
    for (size_t i = 0u; i < c->entry_count; i++) qcss_put_entry(out, &n, &c->entries[i]);
    return n;
}

static bool qcss_entry_equal(const qihse_consensus_entry_t* a,
                             const qihse_consensus_entry_t* b) {
    return a->index == b->index && a->term == b->term &&
           a->journal_generation == b->journal_generation &&
           a->hlc.physical_ms == b->hlc.physical_ms &&
           a->hlc.logical == b->hlc.logical && a->classif == b->classif &&
           a->sci == b->sci && a->type == b->type &&
           a->payload_len == b->payload_len &&
           memcmp(a->payload, b->payload, a->payload_len) == 0;
}

static qihse_consensus_snapshot_stage_result_t qcss_apply_chunk(
    qihse_consensus_snapshot_stage_t* s, const qihse_user_t* principal,
    const qihse_consensus_msg_t* m, bool persist) {
    qihse_consensus_snapshot_stage_result_t why;
    if (!qcss_validate_message(s, principal, m, &why)) return why;
    const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;

    bool new_header = !s->has_transfer;
    if (new_header) {
        if (c->first_entry_index != 1u) return QIHSE_SNAPSHOT_STAGE_GAP;
        if (!qcss_set_header(s, m)) return QIHSE_SNAPSHOT_STAGE_LIMIT;
    } else if (!qcss_metadata_matches(s, m)) {
        return QIHSE_SNAPSHOT_STAGE_CONFLICT;
    }

    if (!qcss_reserve_chunks(s, s->chunk_count + 1u)) {
        if (new_header) qcss_forget_transfer(s);
        return QIHSE_SNAPSHOT_STAGE_LIMIT;
    }

    uint64_t next_index = (uint64_t)s->entry_count + 1u;
    if (c->first_entry_index < next_index) {
        for (size_t k = 0u; k < s->chunk_count; k++) {
            const qcss_chunk_ref_t* ref = &s->chunks[k];
            if (ref->first != c->first_entry_index) continue;
            if (ref->count != c->entry_count || ref->final_chunk != c->final_chunk ||
                ref->digest != c->chunk_digest) return QIHSE_SNAPSHOT_STAGE_CONFLICT;
            for (size_t i = 0u; i < c->entry_count; i++) {
                if (!qcss_entry_equal(&s->entries[(size_t)c->first_entry_index - 1u + i],
                                      &c->entries[i])) return QIHSE_SNAPSHOT_STAGE_CONFLICT;
            }
            return QIHSE_SNAPSHOT_STAGE_DUPLICATE;
        }
        return QIHSE_SNAPSHOT_STAGE_CONFLICT;
    }
    if (c->first_entry_index > next_index) return QIHSE_SNAPSHOT_STAGE_GAP;
    if (s->complete) return QIHSE_SNAPSHOT_STAGE_CONFLICT;
    if (c->entry_count > s->entry_cap - s->entry_count) return QIHSE_SNAPSHOT_STAGE_LIMIT;

    memcpy(s->entries + s->entry_count, c->entries,
           c->entry_count * sizeof(*s->entries));
    size_t old_count = s->entry_count;
    size_t new_count = old_count + c->entry_count;
    if (c->final_chunk) {
        uint64_t whole = qihse_consensus_snapshot_entries_digest(s->entries, new_count);
        if (new_count != s->total_entries || whole != s->digest) {
            memset(s->entries + old_count, 0, c->entry_count * sizeof(*s->entries));
            if (new_header) qcss_forget_transfer(s);
            return QIHSE_SNAPSHOT_STAGE_INTEGRITY;
        }
    }

    uint8_t header_record[QCSS_RECORD_MAX];
    uint8_t record[QCSS_RECORD_MAX];
    size_t header_len = 0u;
    if (new_header) header_len = qcss_encode_header(m, header_record);
    size_t record_len = qcss_encode_chunk(c, record);
    if (persist && ((new_header && !qcss_record_fits(s, header_len + 12u + record_len)) ||
                    (!new_header && !qcss_record_fits(s, record_len)))) {
        memset(s->entries + old_count, 0, c->entry_count * sizeof(*s->entries));
        if (new_header) qcss_forget_transfer(s);
        return QIHSE_SNAPSHOT_STAGE_LIMIT;
    }
    if (new_header && persist) {
        if (!qcss_persist_record(s, header_record, header_len)) {
            qcss_forget_transfer(s);
            return QIHSE_SNAPSHOT_STAGE_IO;
        }
    }
    if (persist) {
        record_len = qcss_encode_chunk(c, record);
        if (!qcss_persist_record(s, record, record_len)) {
            memset(s->entries + old_count, 0, c->entry_count * sizeof(*s->entries));
            return QIHSE_SNAPSHOT_STAGE_IO;
        }
    }
    qcss_chunk_ref_t* ref = &s->chunks[s->chunk_count++];
    ref->first = c->first_entry_index;
    ref->count = c->entry_count;
    ref->final_chunk = c->final_chunk;
    ref->digest = c->chunk_digest;
    s->entry_count = new_count;
    s->complete = c->final_chunk;
    return QIHSE_SNAPSHOT_STAGE_OK;
}

static bool qcss_decode_header(qihse_consensus_snapshot_stage_t* s,
                               const qihse_user_t* principal,
                               const uint8_t* p, size_t n) {
    qcss_reader_t r = {p, n, 0u, true};
    if (qcss_get_u8(&r) != QCSS_HEADER_RECORD) return false;
    uint8_t group_len = qcss_get_u8(&r);
    if (!group_len || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    char group[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u] = {0};
    if (!qcss_get_bytes(&r, group, group_len) || !qcss_group_valid(group) ||
        strcmp(group, s->group) != 0) return false;
    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK;
    memcpy(m.group_id, group, group_len);
    if (!qcss_get_bytes(&r, m.from.bytes, QIHSE_UUID_BYTES) ||
        !qcss_get_bytes(&r, m.to.bytes, QIHSE_UUID_BYTES)) return false;
    m.term = qcss_get_u64(&r);
    m.fencing_epoch = qcss_get_u64(&r);
    qihse_consensus_snapshot_chunk_t* c = &m.u.snapshot_chunk;
    c->transfer_id = qcss_get_u64(&r);
    c->total_entries = qcss_get_u64(&r);
    c->first_entry_index = 1u;
    c->last_included_term = qcss_get_u64(&r);
    c->snapshot_fencing_epoch = qcss_get_u64(&r);
    c->journal_generation = qcss_get_u64(&r);
    c->digest = qcss_get_u64(&r);
    if (!r.ok || r.n != r.len || qihse_uuid_is_nil(&m.from) ||
        qihse_uuid_is_nil(&m.to) || m.fencing_epoch < m.term ||
        !c->transfer_id || !c->total_entries ||
        c->total_entries > QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES ||
        c->total_entries > SIZE_MAX / sizeof(*s->entries) ||
        c->last_included_term > m.term ||
        c->snapshot_fencing_epoch < c->last_included_term ||
        c->snapshot_fencing_epoch > m.fencing_epoch || !c->journal_generation)
        return false;
    if (!qcss_set_header(s, &m)) return false;
    (void)principal;
    return true;
}

static bool qcss_decode_chunk_record(qihse_consensus_snapshot_stage_t* s,
                                     const qihse_user_t* principal,
                                     const uint8_t* p, size_t n) {
    qcss_reader_t r = {p, n, 0u, true};
    if (qcss_get_u8(&r) != QCSS_CHUNK_RECORD || !s->has_transfer) return false;
    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK;
    snprintf(m.group_id, sizeof(m.group_id), "%s", s->group);
    m.from = s->from; m.to = s->to;
    m.term = s->term; m.fencing_epoch = s->fencing_epoch;
    qihse_consensus_snapshot_chunk_t* c = &m.u.snapshot_chunk;
    c->transfer_id = s->transfer_id;
    c->total_entries = s->total_entries;
    c->last_included_term = s->last_included_term;
    c->snapshot_fencing_epoch = s->snapshot_fencing_epoch;
    c->journal_generation = s->journal_generation;
    c->digest = s->digest;
    c->first_entry_index = qcss_get_u64(&r);
    c->entry_count = qcss_get_u8(&r);
    uint8_t final = qcss_get_u8(&r);
    c->chunk_digest = qcss_get_u64(&r);
    if (final > 1u || c->entry_count > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES)
        return false;
    c->final_chunk = final != 0u;
    for (size_t i = 0u; i < c->entry_count; i++)
        if (!qcss_get_entry(&r, &c->entries[i])) return false;
    if (!r.ok || r.n != r.len) return false;
    qihse_consensus_snapshot_stage_result_t result =
        qcss_apply_chunk(s, principal, &m, false);
    return result == QIHSE_SNAPSHOT_STAGE_OK ||
           result == QIHSE_SNAPSHOT_STAGE_DUPLICATE;
}

static bool qcss_decode_rebind_record(qihse_consensus_snapshot_stage_t* s,
                                      const uint8_t* p, size_t n) {
    qcss_reader_t r = {p, n, 0u, true};
    if (qcss_get_u8(&r) != QCSS_REBIND_RECORD || !s->has_transfer)
        return false;
    qihse_uuid_t from, to;
    memset(&from, 0, sizeof(from));
    memset(&to, 0, sizeof(to));
    if (!qcss_get_bytes(&r, from.bytes, QIHSE_UUID_BYTES) ||
        !qcss_get_bytes(&r, to.bytes, QIHSE_UUID_BYTES)) return false;
    uint64_t old_term = qcss_get_u64(&r);
    uint64_t old_epoch = qcss_get_u64(&r);
    uint64_t new_term = qcss_get_u64(&r);
    uint64_t new_epoch = qcss_get_u64(&r);
    uint64_t transfer_id = qcss_get_u64(&r);
    uint64_t total_entries = qcss_get_u64(&r);
    uint64_t last_included_term = qcss_get_u64(&r);
    uint64_t snapshot_fencing_epoch = qcss_get_u64(&r);
    uint64_t journal_generation = qcss_get_u64(&r);
    uint64_t digest = qcss_get_u64(&r);
    if (!r.ok || r.n != r.len || !qihse_uuid_equal(&from, &s->from) ||
        !qihse_uuid_equal(&to, &s->to) || old_term != s->term ||
        old_epoch != s->fencing_epoch || new_term <= old_term ||
        new_epoch <= old_epoch || new_epoch < new_term ||
        snapshot_fencing_epoch < last_included_term ||
        snapshot_fencing_epoch > new_epoch ||
        transfer_id != s->transfer_id || total_entries != s->total_entries ||
        last_included_term != s->last_included_term ||
        snapshot_fencing_epoch != s->snapshot_fencing_epoch ||
        journal_generation != s->journal_generation || digest != s->digest)
        return false;
    s->term = new_term;
    s->fencing_epoch = new_epoch;
    return true;
}

static bool qcss_recover(qihse_consensus_snapshot_stage_t* s,
                         const qihse_user_t* principal) {
    struct stat st;
    if (fstat(s->fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0 ||
        st.st_size < 0 || (uint64_t)st.st_size > QCSS_FILE_MAX) return false;
    if (st.st_size == 0) {
        if (!qcss_write_all(s->fd, (const uint8_t*)QCSS_MAGIC, QCSS_MAGIC_SIZE) ||
            fdatasync(s->fd) != 0) return false;
        return true;
    }
    if (st.st_size < (off_t)QCSS_MAGIC_SIZE) return false;
    uint8_t magic[QCSS_MAGIC_SIZE];
    if (pread(s->fd, magic, sizeof(magic), 0) != (ssize_t)sizeof(magic) ||
        memcmp(magic, QCSS_MAGIC, sizeof(magic)) != 0) return false;

    off_t offset = QCSS_MAGIC_SIZE;
    off_t valid_end = offset;
    while (offset < st.st_size) {
        uint8_t len_bytes[4];
        off_t remaining = st.st_size - offset;
        if (remaining < 4) break;
        if (pread(s->fd, len_bytes, sizeof(len_bytes), offset) != (ssize_t)sizeof(len_bytes))
            return false;
        qcss_reader_t lr = {len_bytes, sizeof(len_bytes), 0u, true};
        uint32_t len = qcss_get_u32(&lr);
        if (!len || len > QCSS_RECORD_MAX) return false;
        if (remaining < (off_t)(4u + len + 8u)) break;
        uint8_t payload[QCSS_RECORD_MAX];
        if (pread(s->fd, payload, len, offset + 4) != (ssize_t)len) return false;
        uint8_t check_bytes[8];
        if (pread(s->fd, check_bytes, sizeof(check_bytes), offset + 4 + len) !=
            (ssize_t)sizeof(check_bytes)) return false;
        qcss_reader_t cr = {check_bytes, sizeof(check_bytes), 0u, true};
        if (qcss_get_u64(&cr) != qcss_checksum(payload, len)) return false;

        bool ok = false;
        if (!s->has_transfer) {
            ok = qcss_decode_header(s, principal, payload, len);
        } else if (payload[0] == QCSS_REBIND_RECORD) {
            ok = qcss_decode_rebind_record(s, payload, len);
        } else {
            ok = qcss_decode_chunk_record(s, principal, payload, len);
        }
        if (!ok) return false;
        offset += (off_t)(4u + len + 8u);
        valid_end = offset;
    }
    if (valid_end != st.st_size) {
        if (ftruncate(s->fd, valid_end) != 0 || fdatasync(s->fd) != 0) return false;
    }
    if (lseek(s->fd, 0, SEEK_END) < 0) return false;
    return true;
}

bool qihse_consensus_snapshot_stage_open(
    const char* path, const char* expected_group,
    const qihse_user_t* principal,
    qihse_consensus_validate_data_fn validate_data,
    void* validate_data_context, bool require_data_validator,
    qihse_consensus_snapshot_stage_t** out) {
    if (out) *out = NULL;
    if (!out || !qcss_path_valid(path) || !qcss_group_valid(expected_group) ||
        !qcss_active(principal) || (require_data_validator && !validate_data))
        return false;

    qihse_consensus_snapshot_stage_t* s = calloc(1u, sizeof(*s));
    if (!s) return false;
    s->fd = -1;
    snprintf(s->group, sizeof(s->group), "%s", expected_group);
    snprintf(s->path, sizeof(s->path), "%s", path);
    s->validate_data = validate_data;
    s->validate_data_context = validate_data_context;
    s->require_data_validator = require_data_validator;
    if (pthread_mutex_init(&s->lock, NULL) != 0) { free(s); return false; }

    bool created = false;
    s->fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_APPEND | O_CLOEXEC |
                 O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (s->fd >= 0) {
        created = true;
    } else if (errno == EEXIST) {
        s->fd = open(path, O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    }
    if (s->fd < 0 || flock(s->fd, LOCK_EX | LOCK_NB) != 0 ||
        (created && !qcss_sync_parent_directory(path)) ||
        !qcss_recover(s, principal)) {
        if (s->fd >= 0) close(s->fd);
        free(s->entries); free(s->chunks);
        pthread_mutex_destroy(&s->lock);
        free(s);
        return false;
    }
    *out = s;
    return true;
}

void qihse_consensus_snapshot_stage_close(
    qihse_consensus_snapshot_stage_t* s) {
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    free(s->entries);
    free(s->chunks);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

qihse_consensus_snapshot_stage_result_t
qihse_consensus_snapshot_stage_accept(
    qihse_consensus_snapshot_stage_t* s, const qihse_user_t* principal,
    const qihse_consensus_msg_t* m) {
    if (!s || !m) return QIHSE_SNAPSHOT_STAGE_INVALID;
    pthread_mutex_lock(&s->lock);
    qihse_consensus_snapshot_stage_result_t r = s->poisoned
        ? QIHSE_SNAPSHOT_STAGE_IO
        : qcss_apply_chunk(s, principal, m, true);
    pthread_mutex_unlock(&s->lock);
    return r;
}

qihse_consensus_snapshot_stage_result_t
qihse_consensus_snapshot_stage_rebind(
    qihse_consensus_snapshot_stage_t* s, const qihse_user_t* principal,
    const qihse_consensus_msg_t* m) {
    if (!s || !m) return QIHSE_SNAPSHOT_STAGE_INVALID;
    pthread_mutex_lock(&s->lock);
    qihse_consensus_snapshot_stage_result_t result = QIHSE_SNAPSHOT_STAGE_OK;
    if (s->poisoned) {
        result = QIHSE_SNAPSHOT_STAGE_IO;
    } else {
        qihse_consensus_snapshot_stage_result_t why;
        if (!qcss_validate_message(s, principal, m, &why)) {
            result = why;
        } else if (!s->has_transfer ||
                   !qcss_snapshot_descriptor_matches(s, m) ||
                   !qcss_rebind_chunk_matches(s, m) ||
                   m->term <= s->term ||
                   m->fencing_epoch <= s->fencing_epoch) {
            result = QIHSE_SNAPSHOT_STAGE_CONFLICT;
        } else if (!qcss_apply_rebind(s, principal, m, true)) {
            result = s->poisoned ? QIHSE_SNAPSHOT_STAGE_IO
                                 : QIHSE_SNAPSHOT_STAGE_CONFLICT;
        }
    }
    pthread_mutex_unlock(&s->lock);
    return result;
}

qihse_consensus_snapshot_stage_result_t
qihse_consensus_snapshot_stage_replace(
    qihse_consensus_snapshot_stage_t* s, const qihse_user_t* principal,
    const qihse_uuid_t* authenticated_current_leader,
    const qihse_consensus_msg_t* m) {
    if (!s || !m) return QIHSE_SNAPSHOT_STAGE_INVALID;
    pthread_mutex_lock(&s->lock);
    qihse_consensus_snapshot_stage_result_t result = QIHSE_SNAPSHOT_STAGE_OK;
    if (s->poisoned) {
        result = QIHSE_SNAPSHOT_STAGE_IO;
    } else if (!authenticated_current_leader ||
               qihse_uuid_is_nil(authenticated_current_leader) ||
               !qihse_uuid_equal(authenticated_current_leader, &m->from)) {
        result = QIHSE_SNAPSHOT_STAGE_AUTH;
    } else {
        qihse_consensus_snapshot_stage_result_t why;
        if (!qcss_validate_message(s, principal, m, &why)) {
            result = why;
        } else {
            const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
            bool same_descriptor = qcss_snapshot_descriptor_matches(s, m);
            if (!s->has_transfer || s->complete || same_descriptor ||
                c->first_entry_index != 1u || m->term <= s->term ||
                m->fencing_epoch <= s->fencing_epoch ||
                c->total_entries <= s->total_entries ||
                c->last_included_term < s->last_included_term ||
                c->snapshot_fencing_epoch < s->snapshot_fencing_epoch ||
                c->journal_generation <= s->journal_generation) {
                result = QIHSE_SNAPSHOT_STAGE_CONFLICT;
            } else {
                result = qcss_replace_file(s, m);
            }
        }
    }
    pthread_mutex_unlock(&s->lock);
    return result;
}

bool qihse_consensus_snapshot_stage_get_progress(
    const qihse_consensus_snapshot_stage_t* s, const qihse_user_t* principal,
    qihse_consensus_snapshot_stage_progress_t* out) {
    if (!s || !qcss_active(principal) || !out) return false;
    qihse_consensus_snapshot_stage_t* mut =
        (qihse_consensus_snapshot_stage_t*)s;
    pthread_mutex_lock(&mut->lock);
    memset(out, 0, sizeof(*out));
    out->has_transfer = s->has_transfer;
    out->complete = s->complete;
    out->transfer_id = s->transfer_id;
    out->total_entries = s->total_entries;
    out->next_entry_index = s->has_transfer ? (uint64_t)s->entry_count + 1u : 1u;
    pthread_mutex_unlock(&mut->lock);
    return true;
}

bool qihse_consensus_snapshot_stage_get_descriptor(
    const qihse_consensus_snapshot_stage_t* s,
    const qihse_user_t* principal,
    qihse_consensus_snapshot_descriptor_t* out) {
    if (!s || !qcss_active(principal) || !out) return false;
    qihse_consensus_snapshot_stage_t* mut =
        (qihse_consensus_snapshot_stage_t*)s;
    pthread_mutex_lock(&mut->lock);
    bool ok = s->has_transfer && s->complete &&
              s->entry_count == s->total_entries;
    if (ok) {
        memset(out, 0, sizeof(*out));
        snprintf(out->group_id, sizeof(out->group_id), "%s", s->group);
        out->from = s->from;
        out->to = s->to;
        out->term = s->term;
        out->fencing_epoch = s->fencing_epoch;
        out->last_included_index = s->total_entries;
        out->last_included_term = s->last_included_term;
        out->snapshot_fencing_epoch = s->snapshot_fencing_epoch;
        out->journal_generation = s->journal_generation;
        out->digest = s->digest;
    }
    pthread_mutex_unlock(&mut->lock);
    return ok;
}

bool qihse_consensus_snapshot_stage_read(
    const qihse_consensus_snapshot_stage_t* s,
    const qihse_user_t* principal, uint64_t first_index,
    qihse_consensus_entry_t* out_entries, size_t capacity,
    size_t* out_count) {
    if (out_count) *out_count = 0u;
    if (!s || !qcss_active(principal) || !out_entries || !out_count ||
        capacity == 0u || capacity > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES)
        return false;
    qihse_consensus_snapshot_stage_t* mut =
        (qihse_consensus_snapshot_stage_t*)s;
    pthread_mutex_lock(&mut->lock);
    if (!s->has_transfer || !s->complete ||
        s->entry_count != s->total_entries || first_index == 0u ||
        first_index > s->total_entries) {
        pthread_mutex_unlock(&mut->lock);
        return false;
    }
    size_t available = s->entry_count - (size_t)(first_index - 1u);
    size_t n = available < capacity ? available : capacity;
    for (size_t i = 0u; i < n; i++) {
        const qihse_consensus_entry_t* e =
            &s->entries[(size_t)(first_index - 1u) + i];
        if (!qihse_auth_can_access(principal, e->classif, e->sci)) {
            pthread_mutex_unlock(&mut->lock);
            return false;
        }
    }
    memcpy(out_entries, s->entries + (size_t)(first_index - 1u),
           n * sizeof(*out_entries));
    *out_count = n;
    pthread_mutex_unlock(&mut->lock);
    return true;
}

bool qihse_consensus_snapshot_stage_publish(
    const qihse_consensus_snapshot_stage_t* s,
    const qihse_user_t* principal, qihse_consensus_t* consensus) {
    if (!s || !consensus || !qcss_active(principal) ||
        qihse_user_get_role(principal) != QIHSE_ROLE_OPERATOR) return false;
    qihse_consensus_snapshot_descriptor_t descriptor;
    if (!qihse_consensus_snapshot_stage_get_descriptor(s, principal,
                                                        &descriptor)) return false;
    if (!descriptor.last_included_index ||
        descriptor.last_included_index > SIZE_MAX / sizeof(qihse_consensus_entry_t))
        return false;
    size_t count = (size_t)descriptor.last_included_index;
    qihse_consensus_entry_t* entries =
        calloc(count, sizeof(qihse_consensus_entry_t));
    if (!entries) return false;
    bool ok = true;
    for (size_t offset = 0u; offset < count;) {
        size_t got = 0u;
        size_t cap = count - offset;
        if (cap > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES)
            cap = QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES;
        if (!qihse_consensus_snapshot_stage_read(
                s, principal, (uint64_t)offset + 1u, entries + offset,
                cap, &got) || got != cap) {
            ok = false;
            break;
        }
        offset += got;
    }
    if (ok) ok = qihse_consensus_install_snapshot_prefix(
        consensus, principal, &descriptor, entries, count);
    memset(entries, 0, count * sizeof(*entries));
    free(entries);
    return ok;
}

const char* qihse_consensus_snapshot_stage_result_name(
    qihse_consensus_snapshot_stage_result_t r) {
    switch (r) {
        case QIHSE_SNAPSHOT_STAGE_OK: return "ok";
        case QIHSE_SNAPSHOT_STAGE_DUPLICATE: return "duplicate";
        case QIHSE_SNAPSHOT_STAGE_GAP: return "gap";
        case QIHSE_SNAPSHOT_STAGE_CONFLICT: return "conflict";
        case QIHSE_SNAPSHOT_STAGE_INTEGRITY: return "integrity";
        case QIHSE_SNAPSHOT_STAGE_AUTH: return "auth";
        case QIHSE_SNAPSHOT_STAGE_INVALID: return "invalid";
        case QIHSE_SNAPSHOT_STAGE_LIMIT: return "limit";
        case QIHSE_SNAPSHOT_STAGE_IO: return "io";
        default: return "unknown";
    }
}
