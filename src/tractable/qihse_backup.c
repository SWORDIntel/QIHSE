#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * QIHSE whole-store backup — the manifest-free container.
 *
 * A container is a 64-byte fixed header plus a data section produced by the
 * KV layer's own authorization-aware export.  Three rules drive the code:
 *
 *   - The security context is mandatory and is propagated to the KV layer,
 *     which is the only layer that knows a record's classification
 *     (AGENTS.md invariant 1).  A NULL context is an argument error, never
 *     "export everything"; a revoked handle is denied.  The clearance
 *     decision is not re-implemented here.
 *
 *   - A refusal writes nothing.  The KV layer refuses the WHOLE export when
 *     any live record is above the caller's clearance, so a denied backup is
 *     never a partially disclosed one, and the container is assembled beside
 *     the target and renamed into place only once every byte is down, so a
 *     denied export cannot damage the backup already at the path.
 *
 *   - Verify precedes apply.  The header and the data section are hashed
 *     together, and the bytes that are verified are the bytes handed to the
 *     KV layer's transactional load, so an edited, truncated or re-pointed
 *     container is refused whole rather than half-applied.
 *
 * The container is integrity-checked, not authenticated: FNV-1a catches an
 * accident or a careless edit, not a writer with filesystem access, who can
 * substitute a container that hashes correctly.  A backup path must be as
 * protected as the dataset it holds.  Signing containers against the node
 * identity key is the same documented follow-up as the federation writer's.
 *
 * Incremental containers (BACKUP_INCREMENTAL) carry the KV layer's delta
 * stream: only the records whose stamped change sequence is strictly
 * greater than the caller's cursor (start_lsn), tombstones included,
 * clearance/SCI-FILTERED at the KV layer, with the no-leak resume point as
 * end_lsn.  Whole-store restore still refuses them — a delta is not a
 * whole-store image.
 */
#include "qihse_backup.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── Container layout ──────────────────────────────────────────────────── */
/*
 * Fixed-size header, little-endian, so the data section's offset never
 * depends on a variable-length field and a truncated container is
 * detectable by comparing the declared length with the file's actual size:
 *
 *     0   magic "QIHSEBAK"                      8
 *     8   version (2)                           4
 *    12   type (backup_type_t)                  4
 *    16   start_lsn                             8
 *    24   end_lsn                               8
 *    32   timestamp (unix seconds)              8
 *    40   data_length                           8
 *    48   writer_user_id                        4
 *    52   writer_classification                 2
 *    54   writer_sci                            2
 *    56   checksum (FNV-1a)                     8
 *    64   end
 *
 * The checksum covers bytes [0, 56) and the data section, so editing the
 * recorded bound or the LSN range invalidates the container just as editing
 * the data does.  The data section is the KV layer's snapshot stream, which
 * carries each record's classification/SCI, so a restore cannot downgrade a
 * record to unclassified.
 */
#define BACKUP_MAGIC "QIHSEBAK"
#define BACKUP_VERSION 2u
#define BACKUP_HEADER_BYTES 64u

#define BACKUP_OFF_MAGIC        0u
#define BACKUP_OFF_VERSION      8u
#define BACKUP_OFF_TYPE         12u
#define BACKUP_OFF_START_LSN    16u
#define BACKUP_OFF_END_LSN      24u
#define BACKUP_OFF_TIMESTAMP    32u
#define BACKUP_OFF_DATA_LENGTH  40u
#define BACKUP_OFF_WRITER_ID    48u
#define BACKUP_OFF_WRITER_CLASS 52u
#define BACKUP_OFF_WRITER_SCI   54u
#define BACKUP_OFF_CHECKSUM     56u

/* Everything before the checksum is hashed, then the data section. */
#define BACKUP_HASHED_HEADER_BYTES BACKUP_OFF_CHECKSUM

#define BACKUP_PATH_MAX 2048u

/* ONE reusable heap buffer for the data section, never one array element per
 * record (AGENTS.md: bounded stack frames). */
#define BACKUP_COPY_CHUNK (64u * 1024u)

typedef struct {
    backup_type_t type;
    uint64_t start_lsn;
    uint64_t end_lsn;
    uint64_t timestamp;
    uint64_t data_length;
    uint32_t writer_user_id;
    uint16_t writer_classification;
    uint16_t writer_sci;
    uint64_t checksum;
} backup_header_t;

static void backup_put_bytes(uint8_t* out, size_t off, const void* src, size_t n) {
    memcpy(out + off, src, n);
}

static void backup_get_bytes(const uint8_t* in, size_t off, void* dst, size_t n) {
    memcpy(dst, in + off, n);
}

static void backup_encode_header(const backup_header_t* h,
                                 uint8_t out[BACKUP_HEADER_BYTES]) {
    uint32_t version = BACKUP_VERSION;
    uint32_t type = (uint32_t)h->type;
    uint32_t writer_id = h->writer_user_id;
    uint16_t classif = h->writer_classification;
    uint16_t sci = h->writer_sci;

    memset(out, 0, BACKUP_HEADER_BYTES);
    backup_put_bytes(out, BACKUP_OFF_MAGIC, BACKUP_MAGIC, 8u);
    backup_put_bytes(out, BACKUP_OFF_VERSION, &version, 4u);
    backup_put_bytes(out, BACKUP_OFF_TYPE, &type, 4u);
    backup_put_bytes(out, BACKUP_OFF_START_LSN, &h->start_lsn, 8u);
    backup_put_bytes(out, BACKUP_OFF_END_LSN, &h->end_lsn, 8u);
    backup_put_bytes(out, BACKUP_OFF_TIMESTAMP, &h->timestamp, 8u);
    backup_put_bytes(out, BACKUP_OFF_DATA_LENGTH, &h->data_length, 8u);
    backup_put_bytes(out, BACKUP_OFF_WRITER_ID, &writer_id, 4u);
    backup_put_bytes(out, BACKUP_OFF_WRITER_CLASS, &classif, 2u);
    backup_put_bytes(out, BACKUP_OFF_WRITER_SCI, &sci, 2u);
    backup_put_bytes(out, BACKUP_OFF_CHECKSUM, &h->checksum, 8u);
}

/* A decoder must refuse a container it could not have written. */
static bool backup_decode_header(const uint8_t in[BACKUP_HEADER_BYTES],
                                 backup_header_t* out) {
    uint32_t version = 0u, type = 0u, writer_id = 0u;
    uint16_t classif = 0u, sci = 0u;

    if (memcmp(in + BACKUP_OFF_MAGIC, BACKUP_MAGIC, 8u) != 0) return false;
    backup_get_bytes(in, BACKUP_OFF_VERSION, &version, 4u);
    if (version != BACKUP_VERSION) return false;
    backup_get_bytes(in, BACKUP_OFF_TYPE, &type, 4u);
    if (type != (uint32_t)BACKUP_FULL && type != (uint32_t)BACKUP_INCREMENTAL &&
        type != (uint32_t)BACKUP_WAL && type != (uint32_t)BACKUP_OWNER_DATA) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->type = (backup_type_t)type;
    backup_get_bytes(in, BACKUP_OFF_START_LSN, &out->start_lsn, 8u);
    backup_get_bytes(in, BACKUP_OFF_END_LSN, &out->end_lsn, 8u);
    backup_get_bytes(in, BACKUP_OFF_TIMESTAMP, &out->timestamp, 8u);
    backup_get_bytes(in, BACKUP_OFF_DATA_LENGTH, &out->data_length, 8u);
    backup_get_bytes(in, BACKUP_OFF_WRITER_ID, &writer_id, 4u);
    backup_get_bytes(in, BACKUP_OFF_WRITER_CLASS, &classif, 2u);
    backup_get_bytes(in, BACKUP_OFF_WRITER_SCI, &sci, 2u);
    backup_get_bytes(in, BACKUP_OFF_CHECKSUM, &out->checksum, 8u);
    out->writer_user_id = writer_id;
    out->writer_classification = classif;
    out->writer_sci = sci;
    return true;
}

/* ── FNV-1a (container integrity, not authentication) ──────────────────── */

static uint64_t backup_hash_init(void) {
    return 1469598103934665603ULL;
}

static uint64_t backup_hash_update(uint64_t hash, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

/* ── Authorization gates ───────────────────────────────────────────────── */

/* Liveness first: the KV layer's unclassified fast path would otherwise let a
 * revoked handle through for unclassified data, and "not live" must not be
 * confused with "unclassified".  A NULL context is an argument error, never
 * an implicit security-disabled mode (AGENTS.md invariant 1). */
static int backup_principal_gate(const qihse_user_t* user) {
    if (!user) return QIHSE_BACKUP_EXPORT_ERR;
    if (!qihse_auth_user_is_active(user)) {
        errno = EACCES;
        return QIHSE_BACKUP_EXPORT_DENIED;
    }
    return QIHSE_BACKUP_EXPORT_OK;
}

/* A container is as sensitive as its writer's clearance: the KV layer refuses
 * an export containing a record above the writer's clearance, so the recorded
 * bound is an upper bound on what the container holds.  A principal that does
 * not dominate it may neither know the container exists, read it, nor apply
 * it.  qihse_auth_can_access is the same authoritative check the KV layer
 * applies per record; no classifier is re-implemented here. */
static int backup_container_gate(const qihse_user_t* user, const backup_header_t* h) {
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;
    if (!qihse_auth_can_access(user, h->writer_classification, h->writer_sci)) {
        errno = EACCES;
        return QIHSE_BACKUP_EXPORT_DENIED;
    }
    return QIHSE_BACKUP_EXPORT_OK;
}

/* ── Filesystem helpers ────────────────────────────────────────────────── */

static bool backup_sibling_path(const char* path, const char* suffix,
                                char* out, size_t cap) {
    struct timespec ts;
    unsigned long long ms = 0u;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        ms = (unsigned long long)ts.tv_sec * 1000u +
             (unsigned long long)(ts.tv_nsec / 1000000);
    }
    int n = snprintf(out, cap, "%s%s.%ld.%llu", path, suffix, (long)getpid(), ms);
    return n >= 0 && (size_t)n < cap;
}

static FILE* backup_open_read(const char* path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }
    FILE* f = fdopen(fd, "rb");
    if (!f) { close(fd); return NULL; }
    return f;
}

/* 0600: a backup of a classified dataset is not world-readable, and the mode
 * is set at creation rather than left to the umask. */
static FILE* backup_create_exclusive(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return NULL;
    FILE* f = fdopen(fd, "wb");
    if (!f) { close(fd); unlink(path); return NULL; }
    return f;
}

/* Always closes, so a caller cannot both double-close and leak on the
 * failure path. */
static bool backup_finish_file(FILE* f) {
    if (!f) return false;
    bool ok = fflush(f) == 0;
    int fd = fileno(f);
    if (ok && fd >= 0 && fsync(fd) != 0) ok = false;
    if (fclose(f) != 0) ok = false;
    return ok;
}

/* The temp file is already fsynced before rename. Persist the new directory
 * entry too; after a successful return, the requested backup name survives a
 * power loss. A failure after rename is ambiguous: keep the published file
 * and return an error rather than deleting a candidate or implying rollback. */
static bool backup_fsync_parent(const char* path) {
    if (!path || !*path) return false;
    char parent[BACKUP_PATH_MAX];
    size_t length = strnlen(path, sizeof(parent));
    if (length == 0u || length >= sizeof(parent)) return false;
    memcpy(parent, path, length + 1u);
    char* slash = strrchr(parent, '/');
    if (!slash) {
        memcpy(parent, ".", 2u);
    } else if (slash == parent) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    int saved = errno;
    close(fd);
    errno = saved;
    return ok;
}

/* Stream `len` bytes out of `src`, optionally into `dst` and always through
 * the running hash.  A short read is reported rather than padded, so a
 * truncated container cannot be verified as if it were whole.  `buf` is the
 * caller's ONE reusable heap buffer. */
static int backup_move_section(FILE* src, uint64_t len, FILE* dst, uint64_t* hash,
                               uint8_t* buf, size_t buf_cap, uint64_t* out_moved) {
    uint64_t moved = 0u;
    while (moved < len) {
        uint64_t want = len - moved;
        size_t take = (want < (uint64_t)buf_cap) ? (size_t)want : buf_cap;
        size_t got = fread(buf, 1u, take, src);
        if (got == 0u) {
            if (ferror(src)) return QIHSE_BACKUP_EXPORT_ERR;
            break;
        }
        if (dst && fwrite(buf, 1u, got, dst) != got) return QIHSE_BACKUP_EXPORT_ERR;
        if (hash) *hash = backup_hash_update(*hash, buf, got);
        moved += (uint64_t)got;
    }
    if (out_moved) *out_moved = moved;
    return (moved == len) ? QIHSE_BACKUP_EXPORT_OK : QIHSE_BACKUP_EXPORT_ERR;
}

/* ── Result record ─────────────────────────────────────────────────────── */

/* The two strings `info` owns are allocated before anything is written, so no
 * allocation can fail once the container exists. */
static bool backup_info_reserve(qihse_backup_info_t* info, const char* path) {
    if (!info) return true;
    info->path = strdup(path);
    info->checksum = (char*)malloc(32u);
    if (!info->path || !info->checksum) {
        free(info->path);
        free(info->checksum);
        memset(info, 0, sizeof(*info));
        return false;
    }
    return true;
}

static void backup_info_commit(qihse_backup_info_t* info, const backup_header_t* h) {
    if (!info) return;
    snprintf(info->checksum, 32u, "%016llx", (unsigned long long)h->checksum);
    info->type = h->type;
    info->start_lsn = h->start_lsn;
    info->end_lsn = h->end_lsn;
    info->timestamp = (time_t)h->timestamp;
    info->size_bytes = (size_t)(BACKUP_HEADER_BYTES + h->data_length);
    info->classification = h->writer_classification;
    info->sci_compartment = h->writer_sci;
    info->writer_user_id = h->writer_user_id;
}

/* ── Writer ────────────────────────────────────────────────────────────── */

/* Seal a data section — already produced by the KV layer at `data_path`,
 * which this function consumes and unlinks — into a container at
 * `output_path`.  Shared by the full and incremental writers so both get
 * the same discipline: fixed header, single-pass hash while the section is
 * copied (the bytes verified are the bytes sealed), checksum written last,
 * rename into place only once every byte is down, and no container at
 * `output_path` on any failure.  The caller has already reserved `info`,
 * which is released here on failure. */
static int backup_seal_container(const char* output_path, backup_type_t type,
                                 uint64_t start_lsn, uint64_t end_lsn,
                                 const char* data_path, const qihse_user_t* user,
                                 uint64_t principal_generation,
                                 bool* out_published,
                                 qihse_backup_info_t* info) {
    int result = QIHSE_BACKUP_EXPORT_ERR;
    FILE* data_f = NULL;
    FILE* out_f = NULL;
    uint8_t* chunk = NULL;
    char tmp_path[BACKUP_PATH_MAX];
    bool tmp_pending = false;
    uint64_t data_bytes = 0u, moved = 0u, checksum = 0u;
    if (out_published) *out_published = false;

    data_f = backup_open_read(data_path);
    if (!data_f) goto done;
    struct stat st;
    if (fstat(fileno(data_f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        goto done;
    }
    data_bytes = (uint64_t)st.st_size;

    backup_header_t h;
    memset(&h, 0, sizeof(h));
    h.type = type;
    h.start_lsn = start_lsn;
    h.end_lsn = end_lsn;
    h.timestamp = (uint64_t)time(NULL);
    h.data_length = data_bytes;
    h.writer_user_id = qihse_user_get_id(user);
    h.writer_classification = qihse_user_get_classification(user);
    h.writer_sci = qihse_user_get_sci(user);

    /* ONE reusable heap buffer for the whole section: no frame carries a
     * per-record array, and every failure path frees exactly this one. */
    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) goto done;

    if (!backup_sibling_path(output_path, ".tmp", tmp_path, sizeof(tmp_path))) goto done;
    out_f = backup_create_exclusive(tmp_path);
    if (!out_f) goto done;
    tmp_pending = true;

    uint8_t header[BACKUP_HEADER_BYTES];
    backup_encode_header(&h, header);
    if (fwrite(header, 1u, sizeof(header), out_f) != sizeof(header)) goto done;

    checksum = backup_hash_update(backup_hash_init(), header, BACKUP_HASHED_HEADER_BYTES);
    if (backup_move_section(data_f, data_bytes, out_f, &checksum, chunk,
                            BACKUP_COPY_CHUNK, &moved) != QIHSE_BACKUP_EXPORT_OK) {
        goto done;
    }
    if (moved != data_bytes) goto done;

    /* The checksum is written last, over a header that had none. */
    h.checksum = checksum;
    uint8_t ck[8];
    backup_put_bytes(ck, 0u, &checksum, 8u);
    if (fseeko(out_f, (off_t)BACKUP_OFF_CHECKSUM, SEEK_SET) != 0) goto done;
    if (fwrite(ck, 1u, sizeof(ck), out_f) != sizeof(ck)) goto done;

    /* Renamed into place only once every byte is down and flushed, so a
     * failed export never leaves a container at `output_path` — and never
     * damages the previous backup that was there. */
    if (!backup_finish_file(out_f)) { out_f = NULL; goto done; }
    out_f = NULL;
    if (!qihse_auth_validate_handle_generation(user, principal_generation)) {
        result = QIHSE_BACKUP_EXPORT_DENIED; errno = EACCES; goto done;
    }
    if (rename(tmp_path, output_path) != 0) goto done;
    tmp_pending = false;
    if (out_published) *out_published = true;
    if (!backup_fsync_parent(output_path)) goto done;
    if (!qihse_auth_validate_handle_generation(user, principal_generation)) {
        result = QIHSE_BACKUP_EXPORT_DENIED; errno = EACCES; goto done;
    }

    backup_info_commit(info, &h);
    result = QIHSE_BACKUP_EXPORT_OK;

done:
    if (out_f) fclose(out_f);
    if (tmp_pending) unlink(tmp_path);
    if (data_f) fclose(data_f);
    unlink(data_path);
    free(chunk);
    if (result != QIHSE_BACKUP_EXPORT_OK && info) {
        qihse_backup_info_free(info);
        memset(info, 0, sizeof(*info));
    }
    return result;
}

/* Produce the data section beside the target, run one writer gate around
 * it, and hand the section to the sealer.  `info` is already reserved by
 * the caller and released on every failure path.  `produce` returning -2 is
 * a denial (the KV layer's convention). */
static int backup_write_container(qihse_kv_store_t* kv, qihse_user_t* user,
                                  const char* output_path, backup_type_t type,
                                  uint64_t since_seq, qihse_backup_info_t* info,
                                  int (*produce)(qihse_kv_store_t*, const char*,
                                                 qihse_user_t*, uint64_t, uint64_t*)) {
    int gate = backup_principal_gate(user);
    if (gate != QIHSE_BACKUP_EXPORT_OK) {
        qihse_backup_info_free(info);
        if (info) memset(info, 0, sizeof(*info));
        return gate;
    }
    uint64_t generation = 0u;
    qihse_user_t* principal = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (!principal || !generation ||
        qihse_user_get_id(principal) != qihse_user_get_id(user) ||
        !qihse_auth_validate_handle_generation(principal, generation)) {
        if (principal) qihse_auth_release_principal_scoped(principal);
        qihse_backup_info_free(info);
        if (info) memset(info, 0, sizeof(*info));
        return QIHSE_BACKUP_EXPORT_DENIED;
    }
    char data_path[BACKUP_PATH_MAX];
    if (!backup_sibling_path(output_path, ".data", data_path, sizeof(data_path))) {
        qihse_auth_release_principal_scoped(principal);
        qihse_backup_info_free(info);
        if (info) memset(info, 0, sizeof(*info));
        return QIHSE_BACKUP_EXPORT_ERR;
    }
    uint64_t resume_seq = 0u;
    int save_rc = produce(kv, data_path, principal, since_seq, &resume_seq);
    /* The KV layer only ever leaves a file at data_path when it returns 0,
     * so a truncated or unbuilt scratch path is never unlinked. */
    if (save_rc == -2) {
        qihse_auth_release_principal_scoped(principal);
        qihse_backup_info_free(info);
        if (info) memset(info, 0, sizeof(*info));
        return QIHSE_BACKUP_EXPORT_DENIED;
    }
    if (save_rc != 0) {
        qihse_auth_release_principal_scoped(principal);
        qihse_backup_info_free(info);
        if (info) memset(info, 0, sizeof(*info));
        return QIHSE_BACKUP_EXPORT_ERR;
    }
    if (!qihse_auth_validate_handle_generation(principal, generation)) {
        unlink(data_path);
        qihse_auth_release_principal_scoped(principal);
        qihse_backup_info_free(info);
        if (info) memset(info, 0, sizeof(*info));
        return QIHSE_BACKUP_EXPORT_DENIED;
    }
    int result = backup_seal_container(output_path, type, since_seq, resume_seq,
                                       data_path, principal, generation, NULL, info);
    qihse_auth_release_principal_scoped(principal);
    return result;
}

/* The full writer's data-section producer: the KV layer's authorization-
 * aware export refuses the WHOLE export when any live record is outside
 * this principal's clearance/SCI (a full container claims complete
 * coverage; a quietly partial one would be a lie about coverage), and it
 * writes atomically.  The identity reaches the lowest data-retrieval layer
 * instead of being re-implemented here, which is what makes the clearance
 * check authoritative rather than advisory.  The change sequence is not a
 * full container's concern: start/end are 0. */
static int backup_full_produce(qihse_kv_store_t* kv, const char* data_path,
                               qihse_user_t* user, uint64_t since_seq, uint64_t* out_resume) {
    (void)since_seq;
    if (out_resume) *out_resume = 0u;
    return qihse_kv_save_user(kv, data_path, user);
}

int qihse_backup_full_user(qihse_kv_store_t* kv, qihse_user_t* user,
                           const char* output_path, qihse_backup_info_t* info) {
    /* A failed call hands back nothing that could be mistaken for a result. */
    if (info) memset(info, 0, sizeof(*info));
    if (!kv || !output_path || output_path[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;
    if (!backup_info_reserve(info, output_path)) return QIHSE_BACKUP_EXPORT_ERR;
    return backup_write_container(kv, user, output_path, BACKUP_FULL, 0u, info,
                                  backup_full_produce);
}

struct qihse_backup_owner_snapshot {
    int fd;
    uint64_t size;
    qihse_user_t* principal;
    uint64_t principal_generation;
    uint32_t principal_id;
    uint32_t tenant_id;
    uint16_t classification;
    uint16_t sci;
};

static bool owner_snapshot_authorized(
    const qihse_backup_owner_snapshot_t* snapshot, qihse_user_t* user) {
    return snapshot && snapshot->fd >= 0 && user &&
        qihse_user_get_id(user) == snapshot->principal_id &&
        qihse_user_get_tenant_id(user) == snapshot->tenant_id &&
        qihse_auth_validate_handle_generation(user, snapshot->principal_generation) &&
        qihse_auth_can_access(user, snapshot->classification, snapshot->sci);
}

int qihse_backup_owner_snapshot_create(qihse_kv_store_t* kv, qihse_user_t* user,
    qihse_backup_owner_snapshot_t** out_snapshot, uint64_t* out_source_change_seq) {
    if (out_snapshot) *out_snapshot = NULL;
    if (out_source_change_seq) *out_source_change_seq = 0u;
    if (!kv || !user || !out_snapshot || !out_source_change_seq)
        return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;

    uint64_t generation = 0u;
    qihse_user_t* principal = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (!principal || !generation || qihse_user_get_id(principal) != qihse_user_get_id(user) ||
        !qihse_auth_validate_handle_generation(principal, generation) ||
        !qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX)) {
        if (principal) qihse_auth_release_principal_scoped(principal);
        errno = EACCES;
        return QIHSE_BACKUP_EXPORT_DENIED;
    }

    int result = QIHSE_BACKUP_EXPORT_ERR;
    qihse_kv_replica_snapshot_t* raw_snapshot = NULL;
    qihse_backup_owner_snapshot_t* snapshot = NULL;
    uint8_t* chunk = NULL;
    char raw_path[BACKUP_PATH_MAX] = {0};
    char container_path[BACKUP_PATH_MAX] = {0};
    char unique_path[BACKUP_PATH_MAX] = {0};
    FILE* raw_out = NULL;
    bool raw_pending = false, container_pending = false;
    const char* dir = qihse_kv_store_data_directory(kv);
    if (!dir) goto done;

    int snap_rc = qihse_kv_ct_owner_data_snapshot_create(kv, principal, &raw_snapshot);
    if (snap_rc == -2) { result = QIHSE_BACKUP_EXPORT_DENIED; goto done; }
    if (snap_rc != 0) goto done;
    uint64_t raw_size = 0u, source_seq = 0u;
    if (!qihse_kv_replica_snapshot_size(raw_snapshot, principal, &raw_size) ||
        !qihse_kv_replica_snapshot_change_seq(raw_snapshot, principal, &source_seq)) {
        result = errno == EACCES ? QIHSE_BACKUP_EXPORT_DENIED : QIHSE_BACKUP_EXPORT_ERR;
        goto done;
    }

    int n = snprintf(raw_path, sizeof(raw_path), "%sqihse-owner-data-%ld-XXXXXX",
                     dir, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(raw_path)) goto done;
    int raw_fd = mkstemp(raw_path);
    if (raw_fd < 0) goto done;
    raw_pending = true;
    (void)fchmod(raw_fd, 0600);
    raw_out = fdopen(raw_fd, "wb");
    if (!raw_out) { close(raw_fd); goto done; }

    chunk = malloc(BACKUP_COPY_CHUNK);
    if (!chunk) goto done;
    uint64_t offset = 0u;
    while (offset < raw_size) {
        size_t got = 0u;
        size_t want = raw_size - offset < BACKUP_COPY_CHUNK
            ? (size_t)(raw_size - offset) : BACKUP_COPY_CHUNK;
        if (!qihse_kv_replica_snapshot_read(raw_snapshot, principal, offset,
                chunk, want, &got) || got != want || fwrite(chunk, 1u, got, raw_out) != got) {
            result = errno == EACCES ? QIHSE_BACKUP_EXPORT_DENIED : QIHSE_BACKUP_EXPORT_ERR;
            goto done;
        }
        offset += got;
    }
    if (!backup_finish_file(raw_out)) { raw_out = NULL; goto done; }
    raw_out = NULL;

    if (!qihse_auth_validate_handle_generation(principal, generation)) {
        result = QIHSE_BACKUP_EXPORT_DENIED; errno = EACCES; goto done;
    }
    n = snprintf(unique_path, sizeof(unique_path),
                 "%sqihse-owner-container-%ld-XXXXXX", dir, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(unique_path)) goto done;
    int seed_fd = mkstemp(unique_path);
    if (seed_fd < 0) goto done;
    (void)fchmod(seed_fd, 0600);
    close(seed_fd);
    container_pending = true;
    memcpy(container_path, unique_path, strlen(unique_path) + 1u);
    int seal_rc = backup_seal_container(container_path, BACKUP_OWNER_DATA, 0u,
            source_seq, raw_path, principal, generation, NULL, NULL);
    if (seal_rc != QIHSE_BACKUP_EXPORT_OK) {
        raw_pending = false; /* sealer always consumes the data path */
        goto done;
    }
    raw_pending = false;

    int fd = open(container_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) goto done;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        !qihse_auth_validate_handle_generation(principal, generation)) {
        int saved = errno ? errno : EACCES;
        close(fd); errno = saved; goto done;
    }
    (void)unlink(container_path);
    container_pending = false;
    snapshot = calloc(1u, sizeof(*snapshot));
    if (!snapshot) { close(fd); goto done; }
    snapshot->fd = fd;
    snapshot->size = (uint64_t)st.st_size;
    snapshot->principal = principal;
    snapshot->principal_generation = generation;
    snapshot->principal_id = qihse_user_get_id(principal);
    snapshot->tenant_id = qihse_user_get_tenant_id(principal);
    snapshot->classification = qihse_user_get_classification(principal);
    snapshot->sci = qihse_user_get_sci(principal);
    *out_source_change_seq = source_seq;
    *out_snapshot = snapshot;
    principal = NULL; /* snapshot now owns the scoped principal reference */
    result = QIHSE_BACKUP_EXPORT_OK;

done:
    if (raw_out) fclose(raw_out);
    if (raw_pending) unlink(raw_path);
    if (container_pending) unlink(unique_path);
    if (raw_snapshot) qihse_kv_replica_snapshot_destroy(raw_snapshot);
    free(chunk);
    if (principal) qihse_auth_release_principal_scoped(principal);
    if (result != QIHSE_BACKUP_EXPORT_OK && snapshot) {
        if (snapshot->fd >= 0) close(snapshot->fd);
        free(snapshot);
    }
    return result;
}

bool qihse_backup_owner_snapshot_size(const qihse_backup_owner_snapshot_t* snapshot,
    qihse_user_t* user, uint64_t* out_size) {
    if (out_size) *out_size = 0u;
    if (!out_size || !owner_snapshot_authorized(snapshot, user)) {
        errno = EACCES; return false;
    }
    *out_size = snapshot->size;
    return true;
}

bool qihse_backup_owner_snapshot_read(qihse_backup_owner_snapshot_t* snapshot,
    qihse_user_t* user, uint64_t offset, void* out, size_t capacity, size_t* out_read) {
    if (out_read) *out_read = 0u;
    if (!snapshot || !out_read || (capacity && !out) || offset > snapshot->size ||
        !owner_snapshot_authorized(snapshot, user)) {
        if (out && capacity) memset(out, 0, capacity);
        errno = EACCES; return false;
    }
    size_t want = snapshot->size - offset < (uint64_t)capacity
        ? (size_t)(snapshot->size - offset) : capacity;
    size_t done = 0u;
    while (done < want) {
        ssize_t n = pread(snapshot->fd, (char*)out + done, want - done,
                          (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            int saved_errno = n == 0 ? EIO : errno;
            if (done) memset(out, 0, done);
            errno = saved_errno;
            return false;
        }
        done += (size_t)n;
    }
    if (!owner_snapshot_authorized(snapshot, user)) {
        if (done) memset(out, 0, done);
        errno = EACCES; return false;
    }
    *out_read = done;
    return true;
}

void qihse_backup_owner_snapshot_destroy(qihse_backup_owner_snapshot_t* snapshot) {
    if (!snapshot) return;
    if (snapshot->fd >= 0) close(snapshot->fd);
    qihse_auth_release_principal_scoped(snapshot->principal);
    free(snapshot);
}

int qihse_backup_owner_data_user(qihse_kv_store_t* kv, qihse_user_t* user,
                                 const char* output_path,
                                 qihse_backup_info_t* info) {
    if (info) memset(info, 0, sizeof(*info));
    if (!kv || !user || !output_path || !*output_path)
        return QIHSE_BACKUP_EXPORT_ERR;
    if (!backup_info_reserve(info, output_path)) return QIHSE_BACKUP_EXPORT_ERR;
    qihse_backup_owner_snapshot_t* snapshot = NULL;
    uint64_t source_seq = 0u, size = 0u;
    int rc = qihse_backup_owner_snapshot_create(kv, user, &snapshot, &source_seq);
    if (rc != QIHSE_BACKUP_EXPORT_OK) goto done;
    if (!qihse_backup_owner_snapshot_size(snapshot, snapshot->principal, &size)) {
        rc = QIHSE_BACKUP_EXPORT_DENIED; goto done;
    }
    char tmp_path[BACKUP_PATH_MAX];
    if (!backup_sibling_path(output_path, ".owner", tmp_path, sizeof(tmp_path))) {
        rc = QIHSE_BACKUP_EXPORT_ERR; goto done;
    }
    FILE* out = backup_create_exclusive(tmp_path);
    if (!out) { rc = QIHSE_BACKUP_EXPORT_ERR; goto done; }
    bool ok = true;
    uint8_t* buf = malloc(BACKUP_COPY_CHUNK);
    if (!buf) ok = false;
    uint64_t off = 0u;
    while (ok && off < size) {
        size_t got = 0u;
        size_t want = size - off < BACKUP_COPY_CHUNK ? (size_t)(size - off) : BACKUP_COPY_CHUNK;
        if (!qihse_backup_owner_snapshot_read(snapshot, snapshot->principal, off,
                buf, want, &got) || got != want || fwrite(buf, 1u, got, out) != got) ok = false;
        off += got;
    }
    free(buf);
    if (!ok || !backup_finish_file(out)) {
        if (ok) out = NULL;
        else fclose(out);
        unlink(tmp_path); rc = QIHSE_BACKUP_EXPORT_ERR; goto done;
    }
    if (!owner_snapshot_authorized(snapshot, snapshot->principal)) {
        unlink(tmp_path); rc = QIHSE_BACKUP_EXPORT_DENIED; goto done;
    }
    if (rename(tmp_path, output_path) != 0 || !backup_fsync_parent(output_path)) {
        unlink(tmp_path); rc = QIHSE_BACKUP_EXPORT_ERR; goto done;
    }
    if (!owner_snapshot_authorized(snapshot, snapshot->principal)) {
        rc = QIHSE_BACKUP_EXPORT_DENIED; errno = EACCES; goto done;
    }
    backup_header_t h;
    FILE* verify = backup_open_read(output_path);
    uint8_t header[BACKUP_HEADER_BYTES];
    if (!verify || fread(header, 1u, sizeof(header), verify) != sizeof(header) ||
        !backup_decode_header(header, &h) || h.type != BACKUP_OWNER_DATA) {
        if (verify) fclose(verify);
        rc = QIHSE_BACKUP_EXPORT_ERR; goto done;
    }
    fclose(verify);
    if (!owner_snapshot_authorized(snapshot, snapshot->principal)) {
        rc = QIHSE_BACKUP_EXPORT_DENIED; errno = EACCES; goto done;
    }
    backup_info_commit(info, &h);
    rc = QIHSE_BACKUP_EXPORT_OK;
done:
    if (snapshot) qihse_backup_owner_snapshot_destroy(snapshot);
    if (rc != QIHSE_BACKUP_EXPORT_OK && info) {
        qihse_backup_info_free(info); memset(info, 0, sizeof(*info));
    }
    return rc;
}

/* The incremental writer's data-section producer: the KV layer's delta
 * stream — only records whose change sequence is strictly greater than
 * `since_seq`, tombstones included, clearance/SCI-FILTERED at the KV layer
 * (a delta's contract is "the mutations you may see since the cursor", so
 * it filters where the full export refuses whole), with the no-leak resume
 * point as the continuation. */
static int backup_incremental_produce(qihse_kv_store_t* kv, const char* data_path,
                                      qihse_user_t* user, uint64_t since_seq,
                                      uint64_t* out_resume) {
    return qihse_kv_save_delta_user(kv, data_path, user, since_seq, out_resume);
}

int qihse_backup_incremental_user(qihse_kv_store_t* kv, qihse_user_t* user,
                                  const char* output_path, uint64_t since_lsn,
                                  qihse_backup_info_t* info) {
    if (info) memset(info, 0, sizeof(*info));
    if (!kv || !output_path || output_path[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;
    if (!backup_info_reserve(info, output_path)) return QIHSE_BACKUP_EXPORT_ERR;
    return backup_write_container(kv, user, output_path, BACKUP_INCREMENTAL,
                                  since_lsn, info, backup_incremental_produce);
}

/* ── Reader ────────────────────────────────────────────────────────────── */

int qihse_restore_user(qihse_kv_store_t* kv, qihse_user_t* user, const char* backup_path) {
    if (!kv || !backup_path || backup_path[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;

    int result = QIHSE_BACKUP_EXPORT_ERR;
    FILE* f = NULL;
    FILE* scratch_f = NULL;
    uint8_t* chunk = NULL;
    char scratch_path[BACKUP_PATH_MAX];
    bool scratch_pending = false;
    backup_header_t h;

    f = backup_open_read(backup_path);
    if (!f) return QIHSE_BACKUP_EXPORT_ERR;

    uint8_t header[BACKUP_HEADER_BYTES];
    if (fread(header, 1u, sizeof(header), f) != sizeof(header)) goto done;
    if (!backup_decode_header(header, &h)) goto done;
    /* This reader replaces the live dataset with a whole-store image, so it
     * can only apply a container that is one.  Delta containers CAN now be
     * written (BACKUP_INCREMENTAL, via qihse_kv_save_delta_user) — that is
     * exactly why they are refused here: applying a delta as though it were
     * the whole store would silently drop every record the delta did not
     * carry.  A delta is applied by a delta-aware consumer against the base
     * it extends, not by whole-store restore. */
    if (h.type != BACKUP_FULL && h.type != BACKUP_OWNER_DATA) {
        result = QIHSE_BACKUP_EXPORT_UNSUPPORTED; goto done;
    }

    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) goto done;
    /* The declared length must agree with the bytes actually present: this
     * catches both a truncated container and one with bytes appended. */
    if ((uint64_t)st.st_size != BACKUP_HEADER_BYTES + h.data_length) goto done;

    /* The recorded bound is the only classification signal a container
     * carries, so it is checked before the KV layer is asked; a NULL or
     * revoked principal never reaches it at all. */
    rc = backup_container_gate(user, &h);
    if (rc != QIHSE_BACKUP_EXPORT_OK) { result = rc; goto done; }

    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) goto done;

    if (!backup_sibling_path(backup_path, ".restore", scratch_path, sizeof(scratch_path))) {
        goto done;
    }
    scratch_f = backup_create_exclusive(scratch_path);
    if (!scratch_f) goto done;
    scratch_pending = true;

    /* Verify-then-apply in a single pass: the section is copied to a scratch
     * file while the checksum is recomputed, so the bytes that are verified
     * are the bytes that will be applied and nothing can change in between. */
    uint64_t hash = backup_hash_update(backup_hash_init(), header, BACKUP_HASHED_HEADER_BYTES);
    uint64_t moved = 0u;
    if (backup_move_section(f, h.data_length, scratch_f, &hash, chunk,
                            BACKUP_COPY_CHUNK, &moved) != QIHSE_BACKUP_EXPORT_OK) {
        goto done;
    }
    if (hash != h.checksum) goto done;
    if (!backup_finish_file(scratch_f)) { scratch_f = NULL; goto done; }
    scratch_f = NULL;

    /* The KV layer applies the section, and it is the layer that knows each
     * record's classification: it refuses the WHOLE load (EACCES) if any
     * record is outside this principal's clearance/SCI, and its load is
     * transactional, so a denial leaves the live dataset untouched rather
     * than half-restored (AGENTS.md invariants 1 and 2). Owner-data images
     * are data-only recovery images and the KV layer's CT guard prevents
     * importing one into an active CT source; it never resumes CT cursors. */
    int load_rc = qihse_kv_load_user(kv, scratch_path, user);
    if (load_rc == -2) { result = QIHSE_BACKUP_EXPORT_DENIED; goto done; }
    if (load_rc != 0) goto done;
    result = QIHSE_BACKUP_EXPORT_OK;

done:
    if (scratch_f) fclose(scratch_f);
    if (scratch_pending) unlink(scratch_path);
    if (f) fclose(f);
    free(chunk);
    return result;
}

/* A verified detached view; never opens a configured storage directory. */
static qihse_kv_store_t* backup_merge_open(qihse_user_t* user, const char* path,
    size_t max_bytes, size_t max_records, backup_type_t* out_type, int* result) {
    FILE* in = backup_open_read(path);
    FILE* raw = NULL;
    uint8_t* chunk = NULL;
    qihse_kv_store_t* view = NULL;
    uint8_t encoded[BACKUP_HEADER_BYTES];
    backup_header_t h;
    struct stat st;
    *result = QIHSE_BACKUP_EXPORT_ERR;
    if (!in) goto done;
    if (fread(encoded, 1, sizeof(encoded), in) != sizeof(encoded) ||
        !backup_decode_header(encoded, &h) ||
        (h.type != BACKUP_FULL && h.type != BACKUP_OWNER_DATA) ||
        h.data_length > max_bytes || fstat(fileno(in), &st) || st.st_size < 0 ||
        (uint64_t)st.st_size != BACKUP_HEADER_BYTES + h.data_length) goto done;
    *result = backup_container_gate(user, &h);
    if (*result != QIHSE_BACKUP_EXPORT_OK) goto done;
    *result = QIHSE_BACKUP_EXPORT_ERR;
    raw = tmpfile();
    chunk = malloc(BACKUP_COPY_CHUNK);
    if (!raw || !chunk) goto done;
    uint64_t hash = backup_hash_update(backup_hash_init(), encoded,
                                       BACKUP_HASHED_HEADER_BYTES), moved = 0;
    if (backup_move_section(in, h.data_length, raw, &hash, chunk,
            BACKUP_COPY_CHUNK, &moved) || hash != h.checksum ||
        fflush(raw) || fseeko(raw, 0, SEEK_SET)) goto done;
    view = qihse_kv_open_snapshot_user(raw, user, max_bytes, max_records);
    if (view) { *out_type = h.type; *result = QIHSE_BACKUP_EXPORT_OK; }
    else if (errno == EACCES) *result = QIHSE_BACKUP_EXPORT_DENIED;
done:
    if (in) fclose(in);
    if (raw) fclose(raw);
    free(chunk);
    return view;
}

typedef struct {
    qihse_kv_store_t *base, *incoming;
    qihse_user_t* user;
    FILE* out;
    qihse_backup_merge_stats_t stats;
    size_t max_bytes;
    size_t max_records;
    size_t records;
    uint64_t principal_generation;
    bool owner_data;
    bool denied;
    bool ok;
} backup_merge_context;

static bool backup_merge_row_common(const char* key, const char* value,
    const qihse_kv_record_meta_t* incoming_meta, uint16_t classification,
    uint16_t sci, void* opaque) {
    backup_merge_context* c = opaque;
    if (!qihse_auth_validate_handle_generation(c->user,
                                               c->principal_generation)) {
        c->denied = true; c->ok = false; errno = EACCES; return false;
    }
    qihse_kv_record_meta_t m = incoming_meta ? *incoming_meta : (qihse_kv_record_meta_t){0};
    qihse_kv_record_meta_t old = {0};
    char* existing = NULL;
    bool exists;
    errno = 0;
    if (c->owner_data) {
        exists = qihse_kv_snapshot_get_record_user(c->base, key, c->user,
                                                   &existing, &old);
    } else {
        existing = qihse_kv_get_user(c->base, key, c->user);
        exists = existing && qihse_kv_meta_user(c->base, key, c->user, &old);
    }
    if (!qihse_auth_validate_handle_generation(c->user,
                                                c->principal_generation) ||
        (!exists && errno == EACCES)) {
        free(existing); c->denied = true; c->ok = false;
        errno = EACCES; return false;
    }
    if (exists) {
        bool same = existing && !strcmp(existing, value) &&
            old.classification == classification && old.sci_compartment == sci &&
            old.expire_time_ms == m.expire_time_ms && old.flags == m.flags;
        free(existing);
        if (same) c->stats.identical++;
        else c->stats.conflicts++;
        return true;
    }
    free(existing);
    if (!qihse_auth_validate_handle_generation(c->user,
                                                c->principal_generation)) {
        c->denied = true; c->ok = false; errno = EACCES; return false;
    }
    if (++c->records > c->max_records) { c->ok = false; errno = E2BIG; return false; }
    c->stats.added++;
    if (fprintf(c->out, "%zu %zu %llu %u %u %u %llu\n", strlen(key), strlen(value),
            (unsigned long long)m.expire_time_ms, (unsigned)classification,
            (unsigned)sci, (unsigned)m.flags, (unsigned long long)m.change_seq) < 0 ||
        fwrite(key, 1, strlen(key), c->out) != strlen(key) ||
        fwrite(value, 1, strlen(value), c->out) != strlen(value) ||
        fputc('\n', c->out) == EOF) c->ok = false;
    off_t bytes = ftello(c->out);
    if (bytes < 0 || (uint64_t)bytes > c->max_bytes) c->ok = false;
    return c->ok;
}

static bool backup_merge_row(const char* key, const char* value,
    uint16_t classification, uint16_t sci, void* opaque) {
    backup_merge_context* c = opaque;
    qihse_kv_record_meta_t m;
    errno = 0;
    if (!qihse_kv_meta_user(c->incoming, key, c->user, &m)) {
        if (errno == EACCES || !qihse_auth_validate_handle_generation(
                c->user, c->principal_generation)) {
            c->denied = true; c->ok = false; errno = EACCES; return false;
        }
        return true;
    }
    return backup_merge_row_common(key, value, &m, classification, sci, opaque);
}

static bool backup_merge_snapshot_row(const char* key, const char* value,
    const qihse_kv_record_meta_t* metadata, void* opaque) {
    if (!metadata) return false;
    return backup_merge_row_common(key, value, metadata, metadata->classification,
                                   metadata->sci_compartment, opaque);
}

static bool backup_merge_count_row(const char* key, const char* value,
    const qihse_kv_record_meta_t* metadata, void* opaque) {
    (void)key; (void)value; (void)metadata;
    size_t* count = opaque;
    if (*count == SIZE_MAX) return false;
    ++*count;
    return true;
}

static bool backup_merge_count_full_row(const char* key, const char* value,
    uint16_t classification, uint16_t sci, void* opaque) {
    (void)key; (void)value; (void)classification; (void)sci;
    size_t* count = opaque;
    if (*count == SIZE_MAX) return false;
    ++*count;
    return true;
}

int qihse_backup_merge_user(qihse_user_t* user, const char* base_path,
    const char* incoming_path, const char* output_path, size_t max_bytes,
    size_t max_records, qihse_backup_merge_stats_t* stats) {
    if (stats) memset(stats, 0, sizeof(*stats));
    int rc = backup_principal_gate(user);
    if (rc) return rc;
    if (!base_path || !incoming_path || !output_path || !*output_path ||
        !max_bytes || max_bytes > QIHSE_BACKUP_MAX_MERGE_BYTES || !max_records ||
        max_records > 2000000u || !strcmp(base_path, output_path) ||
        !strcmp(incoming_path, output_path)) return QIHSE_BACKUP_EXPORT_ERR;
    /* Reject aliases as well as identical spellings. */
    struct stat a, b, out;
    if (stat(base_path, &a) || stat(incoming_path, &b)) return QIHSE_BACKUP_EXPORT_ERR;
    if (!lstat(output_path, &out) &&
        ((a.st_dev == out.st_dev && a.st_ino == out.st_ino) ||
         (b.st_dev == out.st_dev && b.st_ino == out.st_ino) || S_ISLNK(out.st_mode)))
        return QIHSE_BACKUP_EXPORT_ERR;
    uint64_t generation = 0u;
    qihse_user_t* principal = qihse_auth_borrow_principal_scoped(
        qihse_user_get_id(user), &generation);
    if (!principal || !generation ||
        !qihse_auth_validate_handle_generation(principal, generation)) {
        if (principal) qihse_auth_release_principal_scoped(principal);
        errno = EACCES; return QIHSE_BACKUP_EXPORT_DENIED;
    }
    qihse_kv_store_t *base = NULL, *incoming = NULL;
    FILE* merged = NULL;
    char path[BACKUP_PATH_MAX] = {0};
    bool pending = false, owner_data = false;
    backup_type_t base_type = BACKUP_FULL, incoming_type = BACKUP_FULL;
    backup_merge_context c = {.user = principal, .max_bytes = max_bytes,
        .max_records = max_records, .principal_generation = generation, .ok = true};
    base = backup_merge_open(principal, base_path, max_bytes, max_records,
                             &base_type, &rc);
    if (!base) goto done;
    incoming = backup_merge_open(principal, incoming_path, max_bytes, max_records,
                                 &incoming_type, &rc);
    if (!incoming) goto done;
    if (base_type != incoming_type) { rc = QIHSE_BACKUP_EXPORT_UNSUPPORTED; goto done; }
    owner_data = base_type == BACKUP_OWNER_DATA;
    c.owner_data = owner_data;
    rc = QIHSE_BACKUP_EXPORT_ERR;
    if (!backup_sibling_path(output_path, ".merge", path, sizeof(path))) goto done;
    int save_rc = owner_data
        ? qihse_kv_snapshot_save_user(base, path, principal)
        : qihse_kv_save_user(base, path, principal);
    if (save_rc != 0) {
        if (save_rc == -2 || errno == EACCES) rc = QIHSE_BACKUP_EXPORT_DENIED;
        goto done;
    }
    pending = true;
    size_t base_records = 0u;
    bool count_ok = owner_data
        ? qihse_kv_snapshot_foreach_record_user(base, principal,
            backup_merge_count_row, &base_records)
        : qihse_kv_foreach_meta_user(base, principal,
            backup_merge_count_full_row, &base_records);
    if (!count_ok || base_records > max_records) goto done;
    c.records = base_records;
    merged = fopen(path, "a+");
    if (!merged) goto done;
    if (fseeko(merged, 0, SEEK_END) || ftello(merged) < 0 ||
        (uint64_t)ftello(merged) > max_bytes) goto done;
    c.base = base; c.incoming = incoming; c.out = merged;
    bool iter_ok = owner_data
        ? qihse_kv_snapshot_foreach_record_user(incoming, principal,
            backup_merge_snapshot_row, &c)
        : qihse_kv_foreach_meta_user(incoming, principal, backup_merge_row, &c);
    if (!iter_ok || !c.ok) {
        if (c.denied || errno == EACCES) rc = QIHSE_BACKUP_EXPORT_DENIED;
        goto done;
    }
    if (!qihse_auth_validate_handle_generation(principal, generation)) {
        rc = QIHSE_BACKUP_EXPORT_DENIED; errno = EACCES; goto done;
    }
    if (c.stats.conflicts) { rc = QIHSE_BACKUP_EXPORT_CONFLICT; goto done; }
    if (fflush(merged) || fseeko(merged, 0, SEEK_SET)) goto done;
    fclose(merged); merged = NULL;
    rc = backup_seal_container(output_path, base_type, 0, 0, path,
                               principal, generation, NULL, NULL);
    pending = false;
done:
    if (merged) fclose(merged);
    if (pending) unlink(path);
    if (incoming) qihse_kv_store_destroy(incoming);
    if (base) qihse_kv_store_destroy(base);
    if (stats && (rc == QIHSE_BACKUP_EXPORT_OK || rc == QIHSE_BACKUP_EXPORT_CONFLICT))
        *stats = c.stats;
    qihse_auth_release_principal_scoped(principal);
    return rc;
}

int qihse_backup_verify_user(qihse_user_t* user, const char* backup_path) {
    if (!backup_path || backup_path[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;

    FILE* f = backup_open_read(backup_path);
    if (!f) return QIHSE_BACKUP_EXPORT_ERR;

    int result = QIHSE_BACKUP_EXPORT_ERR;
    uint8_t* chunk = NULL;
    backup_header_t h;

    uint8_t header[BACKUP_HEADER_BYTES];
    if (fread(header, 1u, sizeof(header), f) != sizeof(header)) goto done;
    if (!backup_decode_header(header, &h)) goto done;

    rc = backup_container_gate(user, &h);
    if (rc != QIHSE_BACKUP_EXPORT_OK) { result = rc; goto done; }

    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) goto done;
    if ((uint64_t)st.st_size != BACKUP_HEADER_BYTES + h.data_length) goto done;

    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) goto done;
    uint64_t hash = backup_hash_update(backup_hash_init(), header, BACKUP_HASHED_HEADER_BYTES);
    uint64_t moved = 0u;
    /* Hashed, not written anywhere: verify reads the payload only to check it. */
    if (backup_move_section(f, h.data_length, NULL, &hash, chunk,
                            BACKUP_COPY_CHUNK, &moved) != QIHSE_BACKUP_EXPORT_OK) {
        goto done;
    }
    if (hash != h.checksum) goto done;
    result = QIHSE_BACKUP_EXPORT_OK;

done:
    fclose(f);
    free(chunk);
    return result;
}

int qihse_backup_list_user(qihse_user_t* user, const char* dir,
                           qihse_backup_info_t** out_backups, size_t* out_count) {
    if (out_backups) *out_backups = NULL;
    if (out_count) *out_count = 0u;
    if (!out_backups || !out_count || !dir || dir[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;

    DIR* d = opendir(dir);
    if (!d) return QIHSE_BACKUP_EXPORT_ERR;

    size_t cap = 8u, count = 0u;
    qihse_backup_info_t* list = (qihse_backup_info_t*)calloc(cap, sizeof(*list));
    /* ONE reusable heap buffer for the variable-length path, reused for every
     * entry (AGENTS.md: bounded stack frames). */
    char* path = (char*)malloc(BACKUP_PATH_MAX);
    if (!list || !path) {
        free(list);
        free(path);
        closedir(d);
        return QIHSE_BACKUP_EXPORT_ERR;
    }

    int fail = QIHSE_BACKUP_EXPORT_OK;
    struct dirent* entry;
    while (fail == QIHSE_BACKUP_EXPORT_OK && (entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        int n = snprintf(path, BACKUP_PATH_MAX, "%s/%s", dir, entry->d_name);
        if (n < 0 || (size_t)n >= BACKUP_PATH_MAX) continue;
        FILE* f = backup_open_read(path);
        if (!f) continue;
        uint8_t header[BACKUP_HEADER_BYTES];
        backup_header_t h;
        if (fread(header, 1u, sizeof(header), f) == sizeof(header) &&
            backup_decode_header(header, &h)) {
            /* The existence of a container above the caller's bound is itself
             * metadata the caller may not see, so the listing is refused WHOLE
             * rather than filtered: a filtered inventory cannot be told apart
             * from a complete one, and this way it never claims to be. */
            if (!qihse_auth_can_access(user, h.writer_classification, h.writer_sci)) {
                errno = EACCES;
                fail = QIHSE_BACKUP_EXPORT_DENIED;
            } else {
                if (count == cap) {
                    size_t new_cap = cap * 2u;
                    qihse_backup_info_t* next =
                        (qihse_backup_info_t*)realloc(list, new_cap * sizeof(*next));
                    if (!next) {
                        fail = QIHSE_BACKUP_EXPORT_ERR;
                    } else {
                        list = next;
                        cap = new_cap;
                    }
                }
                if (fail == QIHSE_BACKUP_EXPORT_OK && !backup_info_reserve(&list[count], path)) {
                    fail = QIHSE_BACKUP_EXPORT_ERR;
                }
                if (fail == QIHSE_BACKUP_EXPORT_OK) {
                    backup_info_commit(&list[count], &h);
                    count++;
                }
            }
        }
        fclose(f);
    }
    closedir(d);
    free(path);

    if (fail != QIHSE_BACKUP_EXPORT_OK) {
        for (size_t i = 0; i < count; i++) qihse_backup_info_free(&list[i]);
        free(list);
        return fail;
    }
    *out_backups = list;
    *out_count = count;
    return QIHSE_BACKUP_EXPORT_OK;
}

void qihse_backup_info_free(qihse_backup_info_t* info) {
    if (!info) return;
    free(info->path);
    free(info->checksum);
    info->path = NULL;
    info->checksum = NULL;
}
