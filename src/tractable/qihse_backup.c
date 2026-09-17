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
        type != (uint32_t)BACKUP_WAL) {
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

int qihse_backup_full_user(qihse_kv_store_t* kv, qihse_user_t* user,
                           const char* output_path, qihse_backup_info_t* info) {
    /* A failed call hands back nothing that could be mistaken for a result. */
    if (info) memset(info, 0, sizeof(*info));
    if (!kv || !output_path || output_path[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;
    if (!backup_info_reserve(info, output_path)) return QIHSE_BACKUP_EXPORT_ERR;

    int result = QIHSE_BACKUP_EXPORT_ERR;
    FILE* data_f = NULL;
    FILE* out_f = NULL;
    uint8_t* chunk = NULL;
    char data_path[BACKUP_PATH_MAX];
    char tmp_path[BACKUP_PATH_MAX];
    bool tmp_pending = false;
    /* The KV layer only ever leaves a file at data_path when it returns 0, so
     * a truncated or unbuilt scratch path is never unlinked. */
    bool data_pending = false;
    uint64_t data_bytes = 0u, moved = 0u, checksum = 0u;

    /* The data section is produced by the KV layer's own authorization-aware
     * export: it refuses the WHOLE export when any live record is outside
     * this principal's clearance/SCI, and it writes atomically.  The identity
     * reaches the lowest data-retrieval layer instead of being re-implemented
     * here, which is what makes the clearance check authoritative rather than
     * advisory. */
    if (!backup_sibling_path(output_path, ".data", data_path, sizeof(data_path))) goto done;
    int save_rc = qihse_kv_save_user(kv, data_path, user);
    if (save_rc == -2) { result = QIHSE_BACKUP_EXPORT_DENIED; goto done; }
    if (save_rc != 0) goto done;
    data_pending = true;

    data_f = backup_open_read(data_path);
    if (!data_f) goto done;
    struct stat st;
    if (fstat(fileno(data_f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        goto done;
    }
    data_bytes = (uint64_t)st.st_size;

    backup_header_t h;
    memset(&h, 0, sizeof(h));
    h.type = BACKUP_FULL;
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
    if (rename(tmp_path, output_path) != 0) goto done;
    tmp_pending = false;

    backup_info_commit(info, &h);
    result = QIHSE_BACKUP_EXPORT_OK;

done:
    if (out_f) fclose(out_f);
    if (tmp_pending) unlink(tmp_path);
    if (data_f) fclose(data_f);
    if (data_pending) unlink(data_path);
    free(chunk);
    if (result != QIHSE_BACKUP_EXPORT_OK && info) {
        qihse_backup_info_free(info);
        memset(info, 0, sizeof(*info));
    }
    return result;
}

int qihse_backup_incremental_user(qihse_kv_store_t* kv, qihse_user_t* user,
                                  const char* output_path, uint64_t since_lsn,
                                  qihse_backup_info_t* info) {
    (void)since_lsn;
    if (info) memset(info, 0, sizeof(*info));
    if (!kv || !output_path || output_path[0] == '\0') return QIHSE_BACKUP_EXPORT_ERR;
    int rc = backup_principal_gate(user);
    if (rc != QIHSE_BACKUP_EXPORT_OK) return rc;
    /* The KV layer exposes no change sequence or LSN, so there is nothing to
     * filter on.  Writing a full snapshot labelled "incremental" would make a
     * restore silently non-incremental, and exporting the caller's whole
     * authorized view under a delta's name is a lie about coverage — so this
     * refuses and writes nothing. */
    return QIHSE_BACKUP_EXPORT_UNSUPPORTED;
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
     * can only apply a container that is one.  A delta container would have
     * to be applied as a delta, and none can be written (see the writer). */
    if (h.type != BACKUP_FULL) { result = QIHSE_BACKUP_EXPORT_UNSUPPORTED; goto done; }

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
     * than half-restored (AGENTS.md invariants 1 and 2). */
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
