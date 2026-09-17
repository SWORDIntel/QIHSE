/*
 * QIHSE federation backup writer and reader — the data a snapshot manifest
 * refers to.  See v3.md §20, §21, §23.
 *
 * A manifest is a claim; this makes the claim true and refuses to pretend
 * otherwise.  Two rules are worth restating where the code enforces them:
 *
 *   - The security context is mandatory and is propagated to the KV layer
 *     rather than re-implemented here (AGENTS.md invariant 1).  The KV layer
 *     is the only code that knows a record's classification, so it is the
 *     only code that can decide whether this principal may export or import
 *     it — and it decides all-or-nothing, which is what keeps a denied
 *     backup from being a partially disclosed one (invariant 2).
 *
 *   - Verification precedes application.  The manifest checksum is checked
 *     before the container is opened, the container's SHA-384 is checked
 *     before the KV layer is handed the section, and the KV load is
 *     transactional, so a truncated, edited or unauthorized restore leaves
 *     the live dataset exactly as it was.
 */
#include "qihse_backup.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "qihse_kv_store.h"

/* ── Result vocabulary ─────────────────────────────────────────────────── */

typedef struct { qihse_backup_result_t v; const char* name; } backup_result_entry_t;

static const backup_result_entry_t g_backup_results[] = {
    { QIHSE_BACKUP_OK,                    "ok"                    },
    { QIHSE_BACKUP_ERR_ARGUMENT,          "argument"              },
    { QIHSE_BACKUP_ERR_DENIED,            "denied"                },
    { QIHSE_BACKUP_ERR_MANIFEST,          "manifest"              },
    { QIHSE_BACKUP_ERR_TRUNCATED,         "truncated"             },
    { QIHSE_BACKUP_ERR_CHECKSUM,          "checksum"              },
    { QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH, "snapshot_mismatch"     },
    { QIHSE_BACKUP_ERR_WAL_POINT,         "wal_point"             },
    { QIHSE_BACKUP_ERR_COVERAGE,          "coverage"              },
    { QIHSE_BACKUP_ERR_KEY_MATERIAL,      "key_material"          },
    { QIHSE_BACKUP_ERR_IO,                "io"                    },
};

const char* qihse_backup_result_name(qihse_backup_result_t r) {
    for (size_t i = 0; i < sizeof(g_backup_results) / sizeof(g_backup_results[0]); i++) {
        if (g_backup_results[i].v == r) return g_backup_results[i].name;
    }
    return "unknown";
}

/* One writer per process is enough: the container is assembled through temp
 * files in a caller-named directory, and two writers racing on the same path
 * would fight over the rename.  The KV layer keeps its own locking; this
 * covers only the container. */
static pthread_mutex_t g_backup_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Container layout ──────────────────────────────────────────────────── */

/* Fixed-size header, little-endian, so the data section's offset never
 * depends on a variable-length field and a truncated container is detectable
 * by comparing the declared length with the file's actual size:
 *
 *    0   magic "QIHSEBK1"                     8
 *    8   version                              4
 *   12   reserved (0)                         4
 *   16   snapshot_id                         16
 *   32   wal_continuation_offset              8
 *   40   max_generation                       8
 *   48   object_count                         8
 *   56   data_bytes                           8
 *   64   manifest_checksum                   48
 *  112   data_checksum                       48
 *  160   encryption_key_id (NUL-terminated) 128
 *  288   schema_id                            4
 *  292   schema_version                       4
 *  296   minimum_reader_version               4
 *  300   reserved (0)                         4
 *  304   required_features                    8
 *  312   optional_features                    8
 *  320   end
 */
#define BACKUP_OFF_MAGIC        0u
#define BACKUP_OFF_VERSION      8u
#define BACKUP_OFF_RESERVED     12u
#define BACKUP_OFF_SNAPSHOT_ID  16u
#define BACKUP_OFF_WAL          32u
#define BACKUP_OFF_MAX_GEN      40u
#define BACKUP_OFF_OBJECTS      48u
#define BACKUP_OFF_DATA_BYTES   56u
#define BACKUP_OFF_MANIFEST_CK  64u
#define BACKUP_OFF_DATA_CK      112u
#define BACKUP_OFF_KEY_ID       160u
#define BACKUP_OFF_SCHEMA_ID    288u
#define BACKUP_OFF_SCHEMA_VER   292u
#define BACKUP_OFF_SCHEMA_MIN   296u
#define BACKUP_OFF_RESERVED2    300u
#define BACKUP_OFF_SCHEMA_REQ   304u
#define BACKUP_OFF_SCHEMA_OPT   312u

#define BACKUP_CK_BYTES 48u
#define BACKUP_KEY_ID_BYTES (QIHSE_BACKUP_KEY_ID_MAX + 1u)
#define BACKUP_PATH_MAX 2048u

/* One reusable heap buffer for every copy, never one array element per
 * record (AGENTS.md: bounded stack frames). */
#define BACKUP_COPY_CHUNK (64u * 1024u)

static void backup_put_bytes(uint8_t* out, size_t off, const void* src, size_t n) {
    memcpy(out + off, src, n);
}

static void backup_get_bytes(const uint8_t* in, size_t off, void* dst, size_t n) {
    memcpy(dst, in + off, n);
}

static void backup_encode_header(const qihse_backup_descriptor_t* d,
                                 uint8_t out[QIHSE_BACKUP_HEADER_BYTES]) {
    uint32_t version = QIHSE_BACKUP_VERSION;
    uint32_t zero = 0u;
    uint32_t schema_id = d->schema.schema_id;
    uint32_t schema_version = d->schema.schema_version;
    uint32_t schema_min = d->schema.minimum_reader_version;

    /* The zeroed tail also NUL-terminates the key id field. */
    memset(out, 0, QIHSE_BACKUP_HEADER_BYTES);
    backup_put_bytes(out, BACKUP_OFF_MAGIC, QIHSE_BACKUP_MAGIC, QIHSE_BACKUP_MAGIC_LEN);
    backup_put_bytes(out, BACKUP_OFF_VERSION, &version, 4u);
    backup_put_bytes(out, BACKUP_OFF_RESERVED, &zero, 4u);
    backup_put_bytes(out, BACKUP_OFF_SNAPSHOT_ID, d->snapshot_id.bytes, QIHSE_UUID_BYTES);
    backup_put_bytes(out, BACKUP_OFF_WAL, &d->wal_continuation_offset, 8u);
    backup_put_bytes(out, BACKUP_OFF_MAX_GEN, &d->max_generation, 8u);
    backup_put_bytes(out, BACKUP_OFF_OBJECTS, &d->object_count, 8u);
    backup_put_bytes(out, BACKUP_OFF_DATA_BYTES, &d->data_bytes, 8u);
    backup_put_bytes(out, BACKUP_OFF_MANIFEST_CK, d->manifest_checksum, BACKUP_CK_BYTES);
    backup_put_bytes(out, BACKUP_OFF_DATA_CK, d->data_checksum, BACKUP_CK_BYTES);
    backup_put_bytes(out, BACKUP_OFF_KEY_ID, d->encryption_key_id,
                     strlen(d->encryption_key_id));
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_ID, &schema_id, 4u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_VER, &schema_version, 4u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_MIN, &schema_min, 4u);
    backup_put_bytes(out, BACKUP_OFF_RESERVED2, &zero, 4u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_REQ, &d->schema.required_features, 8u);
    backup_put_bytes(out, BACKUP_OFF_SCHEMA_OPT, &d->schema.optional_features, 8u);
}

/* A decoder must refuse a container it could not have written.  Every field
 * is validated against the bytes actually present, so a malformed or hostile
 * container is rejected rather than half-interpreted. */
static bool backup_decode_header(const uint8_t* in, qihse_backup_descriptor_t* out) {
    uint32_t version = 0u, reserved = 0u, reserved2 = 0u;
    if (memcmp(in + BACKUP_OFF_MAGIC, QIHSE_BACKUP_MAGIC, QIHSE_BACKUP_MAGIC_LEN) != 0) {
        return false;
    }
    backup_get_bytes(in, BACKUP_OFF_VERSION, &version, 4u);
    backup_get_bytes(in, BACKUP_OFF_RESERVED, &reserved, 4u);
    backup_get_bytes(in, BACKUP_OFF_RESERVED2, &reserved2, 4u);
    if (version != QIHSE_BACKUP_VERSION || reserved != 0u || reserved2 != 0u) return false;

    memset(out, 0, sizeof(*out));
    backup_get_bytes(in, BACKUP_OFF_SNAPSHOT_ID, out->snapshot_id.bytes, QIHSE_UUID_BYTES);
    backup_get_bytes(in, BACKUP_OFF_WAL, &out->wal_continuation_offset, 8u);
    backup_get_bytes(in, BACKUP_OFF_MAX_GEN, &out->max_generation, 8u);
    backup_get_bytes(in, BACKUP_OFF_OBJECTS, &out->object_count, 8u);
    backup_get_bytes(in, BACKUP_OFF_DATA_BYTES, &out->data_bytes, 8u);
    backup_get_bytes(in, BACKUP_OFF_MANIFEST_CK, out->manifest_checksum, BACKUP_CK_BYTES);
    backup_get_bytes(in, BACKUP_OFF_DATA_CK, out->data_checksum, BACKUP_CK_BYTES);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_ID, &out->schema.schema_id, 4u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_VER, &out->schema.schema_version, 4u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_MIN, &out->schema.minimum_reader_version, 4u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_REQ, &out->schema.required_features, 8u);
    backup_get_bytes(in, BACKUP_OFF_SCHEMA_OPT, &out->schema.optional_features, 8u);
    return true;
}

/* The manifest carries a key ID and nothing else (v3.md §20, §21).  A backup
 * is the one artefact where a key mistake is unrecoverable, so a value that
 * looks like key material is refused here rather than copied.  An empty key
 * id records a backup the snapshot itself declared unencrypted. */
static bool backup_key_id_is_identifier(const char* id) {
    if (!id) return false;
    size_t n = strlen(id);
    if (n > QIHSE_BACKUP_KEY_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)id[i];
        if (c < 0x20u || c == 0x7Fu) return false;
    }
    if (strstr(id, "-----BEGIN") != NULL) return false;
    if (strstr(id, "PRIVATE KEY") != NULL) return false;
    return true;
}

/* ── Filesystem helpers ────────────────────────────────────────────────── */

static uint64_t backup_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0u;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static bool backup_sibling_path(const char* path, const char* suffix,
                                char* out, size_t cap) {
    int n = snprintf(out, cap, "%s%s.%ld.%llu", path, suffix, (long)getpid(),
                     (unsigned long long)backup_now_ms());
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

/* Stream `len` bytes out of `src`, optionally into `dst` and optionally
 * through a digest.  A short read is reported rather than padded, so a
 * truncated container cannot be verified as if it were whole. */
static qihse_backup_result_t backup_move_section(FILE* src, uint64_t len, FILE* dst,
                                                 EVP_MD_CTX* md, uint8_t* buf,
                                                 size_t buf_cap, uint64_t* out_moved) {
    uint64_t moved = 0u;
    while (moved < len) {
        uint64_t want = len - moved;
        size_t take = (want < (uint64_t)buf_cap) ? (size_t)want : buf_cap;
        size_t got = fread(buf, 1u, take, src);
        if (got == 0u) {
            if (ferror(src)) return QIHSE_BACKUP_ERR_IO;
            break;
        }
        if (dst && fwrite(buf, 1u, got, dst) != got) return QIHSE_BACKUP_ERR_IO;
        if (md && EVP_DigestUpdate(md, buf, got) != 1) return QIHSE_BACKUP_ERR_IO;
        moved += (uint64_t)got;
    }
    if (out_moved) *out_moved = moved;
    return (moved == len) ? QIHSE_BACKUP_OK : QIHSE_BACKUP_ERR_TRUNCATED;
}

/* ── Manifest binding ──────────────────────────────────────────────────── */

/* The caller must present exactly the recorded manifest.  qihse_snapshot_verify()
 * recomputes the digest over the STORED body, so an edited or truncated
 * manifest is caught there; comparing the fields that decide what a restore
 * does means an edited in-memory manifest is refused too, even though its
 * checksum bytes still name the recorded digest. */
static bool backup_manifest_matches(const qihse_snapshot_manifest_t* given,
                                    const qihse_snapshot_manifest_t* recorded) {
    if (!qihse_uuid_equal(&given->snapshot_id, &recorded->snapshot_id)) return false;
    if (given->kind != recorded->kind) return false;
    if (given->wal_continuation_offset != recorded->wal_continuation_offset) return false;
    if (given->max_generation != recorded->max_generation) return false;
    if (given->object_count != recorded->object_count) return false;
    if (memcmp(given->checksum, recorded->checksum, BACKUP_CK_BYTES) != 0) return false;
    if (strcmp(given->encryption_key_id, recorded->encryption_key_id) != 0) return false;
    if (given->group_count > QIHSE_SNAPSHOT_MAX_GROUPS) return false;
    if (given->group_count != recorded->group_count) return false;
    for (uint32_t i = 0; i < given->group_count; i++) {
        if (strcmp(given->groups[i], recorded->groups[i]) != 0) return false;
    }
    if (given->schema.schema_id != recorded->schema.schema_id) return false;
    if (given->schema.schema_version != recorded->schema.schema_version) return false;
    if (given->schema.minimum_reader_version != recorded->schema.minimum_reader_version) return false;
    if (given->schema.required_features != recorded->schema.required_features) return false;
    if (given->schema.optional_features != recorded->schema.optional_features) return false;
    return true;
}

/* Verify the recorded manifest's checksum, then confirm the caller presented
 * that manifest.  Nothing is read, written or applied before this passes. */
static qihse_backup_result_t backup_manifest_gate(void* store_void, void* user_void,
                                                 const qihse_snapshot_manifest_t* manifest) {
    if (!qihse_snapshot_verify(store_void, user_void, &manifest->snapshot_id)) {
        return QIHSE_BACKUP_ERR_MANIFEST;
    }
    qihse_snapshot_manifest_t recorded;
    memset(&recorded, 0, sizeof(recorded));
    if (!qihse_snapshot_lookup(store_void, user_void, &manifest->snapshot_id, &recorded)) {
        return QIHSE_BACKUP_ERR_MANIFEST;
    }
    if (!backup_manifest_matches(manifest, &recorded)) return QIHSE_BACKUP_ERR_MANIFEST;
    return QIHSE_BACKUP_OK;
}

/* ── Writer ────────────────────────────────────────────────────────────── */

qihse_backup_result_t qihse_backup_write(void* store_void, void* user_void,
                                         const qihse_snapshot_manifest_t* manifest,
                                         const char* path,
                                         qihse_backup_descriptor_t* out) {
    /* A failed call hands back nothing that could be mistaken for a result. */
    if (out) memset(out, 0, sizeof(*out));
    /* NULL is not an authorization bypass: without an authenticated principal
     * there is no clearance to check against, so the call fails closed
     * (AGENTS.md invariant 1). */
    if (!store_void || !user_void || !manifest || !path || path[0] == '\0') {
        return QIHSE_BACKUP_ERR_ARGUMENT;
    }
    if (!backup_key_id_is_identifier(manifest->encryption_key_id)) {
        return QIHSE_BACKUP_ERR_KEY_MATERIAL;
    }

    qihse_backup_result_t rc = QIHSE_BACKUP_ERR_IO;
    uint8_t* chunk = NULL;
    EVP_MD_CTX* md = NULL;
    FILE* data_f = NULL;
    FILE* out_f = NULL;
    char data_path[BACKUP_PATH_MAX];
    char tmp_path[BACKUP_PATH_MAX];
    bool tmp_pending = false;
    data_path[0] = '\0';

    pthread_mutex_lock(&g_backup_lock);

    rc = backup_manifest_gate(store_void, user_void, manifest);
    if (rc != QIHSE_BACKUP_OK) goto done;

    /* The manifest's object count was counted through the snapshotting
     * principal's authorized view.  A caller whose own view is narrower than
     * that cannot produce the data the manifest refers to, and refusing beats
     * writing a backup that is quietly not the snapshot it names.  A wider
     * view is allowed — the manifest was counted before its own record
     * existed — and the captured count is reported in the descriptor. */
    uint64_t visible = (uint64_t)qihse_kv_count_user((qihse_kv_store_t*)store_void,
                                                    (qihse_user_t*)user_void);
    if (visible < manifest->object_count) {
        rc = QIHSE_BACKUP_ERR_COVERAGE;
        goto done;
    }

    if (!backup_sibling_path(path, ".data", data_path, sizeof(data_path))) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }

    /* The data section is produced by the KV layer's own authorization-aware
     * export: it refuses the WHOLE export when any live record is outside the
     * caller's clearance/SCI, and it writes atomically.  The identity reaches
     * the lowest data-retrieval layer instead of being re-implemented here,
     * which is what makes the clearance check authoritative rather than
     * advisory. */
    int save_rc = qihse_kv_save_user((qihse_kv_store_t*)store_void, data_path,
                                     (qihse_user_t*)user_void);
    if (save_rc == -2) { rc = QIHSE_BACKUP_ERR_DENIED; goto done; }
    if (save_rc != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    data_f = backup_open_read(data_path);
    if (!data_f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    struct stat st;
    if (fstat(fileno(data_f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }

    qihse_backup_descriptor_t desc;
    memset(&desc, 0, sizeof(desc));
    desc.snapshot_id = manifest->snapshot_id;
    desc.wal_continuation_offset = manifest->wal_continuation_offset;
    desc.max_generation = manifest->max_generation;
    desc.object_count = visible;
    desc.data_bytes = (uint64_t)st.st_size;
    desc.schema = manifest->schema;
    memcpy(desc.manifest_checksum, manifest->checksum, BACKUP_CK_BYTES);
    snprintf(desc.encryption_key_id, sizeof(desc.encryption_key_id), "%s",
             manifest->encryption_key_id);

    /* ONE reusable heap buffer for the whole section: no frame carries a
     * per-record array, and every failure path frees exactly this one. */
    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    uint64_t moved = 0u;
    rc = backup_move_section(data_f, desc.data_bytes, NULL, md, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;
    unsigned int digest_len = 0u;
    if (EVP_DigestFinal_ex(md, desc.data_checksum, &digest_len) != 1 ||
        digest_len != BACKUP_CK_BYTES) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    EVP_MD_CTX_free(md);
    md = NULL;

    if (!backup_sibling_path(path, ".tmp", tmp_path, sizeof(tmp_path))) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    out_f = backup_create_exclusive(tmp_path);
    if (!out_f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    tmp_pending = true;

    uint8_t header[QIHSE_BACKUP_HEADER_BYTES];
    backup_encode_header(&desc, header);
    if (fwrite(header, 1u, sizeof(header), out_f) != sizeof(header)) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    if (fseek(data_f, 0L, SEEK_SET) != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    rc = backup_move_section(data_f, desc.data_bytes, out_f, NULL, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;

    /* Renamed into place only once every byte is down and flushed, so a
     * failed backup never leaves a container at `path` — and never damages
     * the previous backup that was there. */
    bool flushed = backup_finish_file(out_f);
    out_f = NULL;
    if (!flushed) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    if (rename(tmp_path, path) != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    tmp_pending = false;

    if (out) *out = desc;
    rc = QIHSE_BACKUP_OK;

done:
    if (md) EVP_MD_CTX_free(md);
    if (out_f) fclose(out_f);
    if (tmp_pending) unlink(tmp_path);
    if (data_f) fclose(data_f);
    if (data_path[0]) unlink(data_path);
    free(chunk);
    pthread_mutex_unlock(&g_backup_lock);
    return rc;
}

/* ── Reader / restore ──────────────────────────────────────────────────── */

qihse_backup_result_t qihse_backup_restore(void* store_void, void* user_void,
                                           const qihse_snapshot_manifest_t* manifest,
                                           const char* path,
                                           qihse_backup_descriptor_t* out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store_void || !user_void || !manifest || !path || path[0] == '\0') {
        return QIHSE_BACKUP_ERR_ARGUMENT;
    }

    qihse_backup_result_t rc = QIHSE_BACKUP_ERR_IO;
    uint8_t* chunk = NULL;
    EVP_MD_CTX* md = NULL;
    FILE* f = NULL;
    FILE* scratch_f = NULL;
    char scratch_path[BACKUP_PATH_MAX];
    bool scratch_pending = false;
    qihse_backup_descriptor_t desc;

    pthread_mutex_lock(&g_backup_lock);

    /* Verify the manifest checksum BEFORE restoring: this recomputes the
     * digest over the stored body and compares it with the recorded value, so
     * a truncated or edited manifest stops here. */
    rc = backup_manifest_gate(store_void, user_void, manifest);
    if (rc != QIHSE_BACKUP_OK) goto done;

    f = backup_open_read(path);
    if (!f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    if ((uint64_t)st.st_size < QIHSE_BACKUP_HEADER_BYTES) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }

    uint8_t header[QIHSE_BACKUP_HEADER_BYTES];
    if (fread(header, 1u, sizeof(header), f) != sizeof(header)) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    memset(&desc, 0, sizeof(desc));
    if (!backup_decode_header(header, &desc)) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    /* The declared length must agree with the bytes actually present: this
     * catches both a truncated container and one with bytes appended. */
    uint64_t section_bytes = (uint64_t)st.st_size - QIHSE_BACKUP_HEADER_BYTES;
    if (desc.data_bytes != section_bytes) {
        rc = QIHSE_BACKUP_ERR_TRUNCATED;
        goto done;
    }
    /* A container is only restorable as the snapshot it was written for. */
    if (!qihse_uuid_equal(&desc.snapshot_id, &manifest->snapshot_id)) {
        rc = QIHSE_BACKUP_ERR_SNAPSHOT_MISMATCH;
        goto done;
    }
    if (memcmp(desc.manifest_checksum, manifest->checksum, BACKUP_CK_BYTES) != 0) {
        rc = QIHSE_BACKUP_ERR_MANIFEST;
        goto done;
    }
    /* Resuming from any point other than the one the manifest names would
     * restore a state that never existed, so a disagreement is a refusal and
     * not a warning. */
    if (desc.wal_continuation_offset != manifest->wal_continuation_offset) {
        rc = QIHSE_BACKUP_ERR_WAL_POINT;
        goto done;
    }
    if (desc.object_count < manifest->object_count) {
        rc = QIHSE_BACKUP_ERR_COVERAGE;
        goto done;
    }

    chunk = (uint8_t*)malloc(BACKUP_COPY_CHUNK);
    if (!chunk) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    /* Verify-then-apply in a single pass: the section is copied to a scratch
     * file while its SHA-384 is recomputed, so the bytes that are verified
     * are the bytes that will be applied and nothing can change in between. */
    if (!backup_sibling_path(path, ".restore", scratch_path, sizeof(scratch_path))) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    scratch_f = backup_create_exclusive(scratch_path);
    if (!scratch_f) { rc = QIHSE_BACKUP_ERR_IO; goto done; }
    scratch_pending = true;

    md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_sha384(), NULL) != 1) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    uint64_t moved = 0u;
    rc = backup_move_section(f, desc.data_bytes, scratch_f, md, chunk,
                             BACKUP_COPY_CHUNK, &moved);
    if (rc != QIHSE_BACKUP_OK) goto done;
    uint8_t digest[BACKUP_CK_BYTES];
    unsigned int digest_len = 0u;
    if (EVP_DigestFinal_ex(md, digest, &digest_len) != 1 ||
        digest_len != BACKUP_CK_BYTES) {
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    EVP_MD_CTX_free(md);
    md = NULL;
    if (memcmp(digest, desc.data_checksum, BACKUP_CK_BYTES) != 0) {
        rc = QIHSE_BACKUP_ERR_CHECKSUM;
        goto done;
    }
    if (!backup_finish_file(scratch_f)) {
        scratch_f = NULL;
        rc = QIHSE_BACKUP_ERR_IO;
        goto done;
    }
    scratch_f = NULL;

    /* The KV layer applies the section, and it is the layer that knows each
     * record's classification: it refuses the WHOLE load (EACCES) if any
     * record is outside this principal's clearance/SCI, and its load is
     * transactional, so a denial leaves the live dataset untouched rather
     * than half-restored (AGENTS.md invariants 1 and 2). */
    int load_rc = qihse_kv_load_user((qihse_kv_store_t*)store_void, scratch_path,
                                     (qihse_user_t*)user_void);
    if (load_rc == -2) { rc = QIHSE_BACKUP_ERR_DENIED; goto done; }
    if (load_rc != 0) { rc = QIHSE_BACKUP_ERR_IO; goto done; }

    if (out) *out = desc;
    rc = QIHSE_BACKUP_OK;

done:
    if (md) EVP_MD_CTX_free(md);
    if (scratch_f) fclose(scratch_f);
    if (scratch_pending) unlink(scratch_path);
    if (f) fclose(f);
    free(chunk);
    pthread_mutex_unlock(&g_backup_lock);
    return rc;
}
