#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_recovery_manifest.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* Canonical big-endian V2: fixed offsets, zero padding, corruption checksum.
 * Neither the checksum nor frozen digests authenticate a historical author. */
enum { HEADER = 12, ID_BYTES = 65, DIGEST_BYTES = 32,
       FILE_BYTES = 1 + ID_BYTES + 8 + DIGEST_BYTES,
       CHECKSUM_OFFSET = QIHSE_CT1_RECOVERY_WIRE_SIZE - 32,
       USED_BYTES = HEADER + 10 * ID_BYTES + 6 * DIGEST_BYTES +
           12 * 8 + 2 * 4 + 5 * 2 +
           (QIHSE_CT1_RECOVERY_SOURCE_FILES + QIHSE_CT1_RECOVERY_TARGET_FILES) * FILE_BYTES };
typedef char recovery_wire_fits[(USED_BYTES <= CHECKSUM_OFFSET) ? 1 : -1];
static const unsigned char magic[8] = {'Q','C','T','1','B','R','0','2'};

static void put64(unsigned char* p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (56u - i * 8u));
}
static uint64_t get64(const unsigned char* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
static void put16(unsigned char* p, uint16_t v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}
static uint16_t get16(const unsigned char* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static void put32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8); p[3] = (unsigned char)v;
}
static uint32_t get32(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | p[3];
}
static bool id_ok(const char* s) {
    if (!s) return false;
    size_t n = strnlen(s, ID_BYTES);
    if (!n || n >= ID_BYTES) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == ':' || c == '_' ||
              c == '.' || c == '-')) return false;
    }
    return true;
}
static bool digest_ok(const unsigned char* p) {
    unsigned char any = 0;
    for (size_t i = 0; i < DIGEST_BYTES; ++i) any |= p[i];
    return any != 0;
}
static bool filename_ok(const qihse_ct1_recovery_file_t* f) {
    const char* s = f->filename;
    size_t len = strnlen(s, ID_BYTES);
    if (!len || len >= ID_BYTES) return false;
    switch (f->kind) {
    case QIHSE_CT1_FILE_WAL: return strcmp(s, "wal.log") == 0;
    case QIHSE_CT1_FILE_CT_STATE: return strcmp(s, "ct-state.bin") == 0;
    case QIHSE_CT1_FILE_BASELINE: return strcmp(s, "ct-baseline.qfs") == 0;
    case QIHSE_CT1_FILE_REPLICA_CURSORS:
        return strcmp(s, "replica-cursors.bin") == 0;
    case QIHSE_CT1_FILE_RESTORE_HIGHWATER:
        return strcmp(s, "restore-highwater.bin") == 0;
    case QIHSE_CT1_FILE_SLOT_JOURNAL:
        return strcmp(s, "slot-ownership.journal") == 0;
    case QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK:
        return strcmp(s, "slot-ownership.journal.lock") == 0;
    case QIHSE_CT1_FILE_SSTABLE: {
        static const char prefix[] = "sstable_";
        if (strncmp(s, prefix, sizeof(prefix) - 1) != 0 ||
            len <= sizeof(prefix) + 2 || strcmp(s + len - 3, ".db")) return false;
        const char* digits = s + sizeof(prefix) - 1;
        size_t count = len - 3 - (sizeof(prefix) - 1);
        if (count > 10 || (count > 1 && digits[0] == '0')) return false;
        uint64_t id = 0;
        for (size_t i = 0; i < count; ++i) {
            if (digits[i] < '0' || digits[i] > '9') return false;
            id = id * 10 + (unsigned)(digits[i] - '0');
        }
        return id <= INT32_MAX;
    }
    default: return false;
    }
}
static bool roster_ok(const qihse_ct1_recovery_file_t* files, size_t count,
    bool source) {
    const unsigned required = (1u << QIHSE_CT1_FILE_WAL) |
        (1u << QIHSE_CT1_FILE_CT_STATE) |
        (1u << QIHSE_CT1_FILE_RESTORE_HIGHWATER) |
        (1u << QIHSE_CT1_FILE_SLOT_JOURNAL) |
        (1u << QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK) |
        (source ? (1u << QIHSE_CT1_FILE_BASELINE) : 0u);
    unsigned seen = 0, sstables = 0;
    unsigned char empty_sha256[32];
    if (!SHA256((const unsigned char*)"", 0, empty_sha256)) return false;
    for (size_t i = 0; i < count; ++i) {
        const qihse_ct1_recovery_file_t* f = &files[i];
        if (!filename_ok(f) ||
            f->size > QIHSE_CT1_RECOVERY_FILE_SIZE_MAX || !digest_ok(f->sha256) ||
            (i && strcmp(files[i - 1].filename, f->filename) >= 0)) return false;
        if (f->kind == QIHSE_CT1_FILE_SLOT_JOURNAL_LOCK) {
            if (f->size || memcmp(f->sha256, empty_sha256, sizeof(empty_sha256)))
                return false;
        } else if (!f->size) return false;
        if (f->kind == QIHSE_CT1_FILE_SSTABLE) {
            ++sstables;
        } else {
            unsigned bit = 1u << f->kind;
            if (seen & bit) return false;
            seen |= bit;
        }
    }
    return seen == required && sstables == 2;
}
static bool shape(const qihse_ct1_recovery_manifest_t* m) {
    return m && id_ok(m->issuer_qkp_id) && id_ok(m->source_qkp_id) &&
        id_ok(m->target_qkp_id) && id_ok(m->generation) &&
        id_ok(m->source_store_id) && id_ok(m->target_store_id) &&
        id_ok(m->replication_principal_id) && id_ok(m->row_key) &&
        id_ok(m->source_peer_qkp_id) && id_ok(m->target_peer_qkp_id) &&
        strcmp(m->source_qkp_id, m->target_qkp_id) != 0 &&
        strcmp(m->source_store_id, m->target_store_id) != 0 &&
        roster_ok(m->source_files, QIHSE_CT1_RECOVERY_SOURCE_FILES, true) &&
        roster_ok(m->target_files, QIHSE_CT1_RECOVERY_TARGET_FILES, false) &&
        digest_ok(m->issuer_operator_pin) &&
        digest_ok(m->source_peer_pin) && digest_ok(m->target_peer_pin) &&
        digest_ok(m->frame_sha256) && digest_ok(m->baseline_sha256) &&
        digest_ok(m->nonce) && m->epoch && m->issued_ms &&
        m->expires_ms > m->issued_ms &&
        m->expires_ms - m->issued_ms <= QIHSE_CT1_RECOVERY_MAX_AGE_MS &&
        m->frame_length == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        m->frame_position && m->frame_offset <= UINT64_MAX - m->frame_length &&
        m->target_cursor && m->target_high_water && m->source_high_water &&
        m->row_change_seq && m->tombstone_position &&
        m->operation == QIHSE_CT1_RECOVERY_VERIFY;
}
static void put_id(unsigned char* out, const char* s) {
    memcpy(out, s, strlen(s));
}
static bool get_id(const unsigned char* in, char* out) {
    const unsigned char* end = memchr(in, 0, ID_BYTES);
    if (!end || end == in) return false;
    size_t n = (size_t)(end - in);
    for (size_t i = n; i < ID_BYTES; ++i) if (in[i]) return false;
    memcpy(out, in, n);
    out[n] = 0;
    return id_ok(out);
}
static void put_files(unsigned char* out, const qihse_ct1_recovery_file_t* files,
    size_t count) {
    for (size_t i = 0; i < count; ++i, out += FILE_BYTES) {
        out[0] = files[i].kind;
        put_id(out + 1, files[i].filename);
        put64(out + 1 + ID_BYTES, files[i].size);
        memcpy(out + 1 + ID_BYTES + 8, files[i].sha256, DIGEST_BYTES);
    }
}
static bool get_files(const unsigned char* in, qihse_ct1_recovery_file_t* files,
    size_t count) {
    for (size_t i = 0; i < count; ++i, in += FILE_BYTES) {
        files[i].kind = in[0];
        if (!get_id(in + 1, files[i].filename)) return false;
        files[i].size = get64(in + 1 + ID_BYTES);
        memcpy(files[i].sha256, in + 1 + ID_BYTES + 8, DIGEST_BYTES);
    }
    return true;
}

bool qihse_ct1_recovery_encode(const qihse_ct1_recovery_manifest_t* m,
    bool receipt, bool spent, unsigned char out[QIHSE_CT1_RECOVERY_WIRE_SIZE]) {
    if (!out || !shape(m) || (spent && !receipt)) return false;
    memset(out, 0, QIHSE_CT1_RECOVERY_WIRE_SIZE);
    memcpy(out, magic, sizeof(magic)); out[8] = receipt ? 2 : 1;
    out[9] = spent ? 1 : 0;
    size_t n = HEADER;
    const char* ids[] = {m->issuer_qkp_id, m->source_qkp_id, m->target_qkp_id,
        m->generation, m->source_store_id, m->target_store_id,
        m->replication_principal_id, m->row_key,
        m->source_peer_qkp_id, m->target_peer_qkp_id};
    for (size_t i = 0; i < 10; ++i, n += ID_BYTES) put_id(out + n, ids[i]);
    const unsigned char* hashes[] = {m->issuer_operator_pin, m->source_peer_pin,
        m->target_peer_pin, m->frame_sha256, m->baseline_sha256, m->nonce};
    for (size_t i = 0; i < 6; ++i, n += DIGEST_BYTES)
        memcpy(out + n, hashes[i], DIGEST_BYTES);
    const uint64_t values[] = {m->epoch, m->issued_ms, m->expires_ms,
        m->frame_offset, m->frame_length, m->frame_position, m->baseline_row_seq,
        m->target_cursor, m->target_high_water, m->source_high_water,
        m->row_change_seq, m->tombstone_position};
    for (size_t i = 0; i < 12; ++i, n += 8) put64(out + n, values[i]);
    const uint32_t words[] = {m->row_tenant_id, m->principal_tenant_id};
    for (size_t i = 0; i < 2; ++i, n += 4) put32(out + n, words[i]);
    const uint16_t shorts[] = {m->classification, m->sci,
        m->principal_classification, m->principal_sci, m->operation};
    for (size_t i = 0; i < 5; ++i, n += 2) put16(out + n, shorts[i]);
    put_files(out + n, m->source_files, QIHSE_CT1_RECOVERY_SOURCE_FILES);
    n += FILE_BYTES * QIHSE_CT1_RECOVERY_SOURCE_FILES;
    put_files(out + n, m->target_files, QIHSE_CT1_RECOVERY_TARGET_FILES);
    n += FILE_BYTES * QIHSE_CT1_RECOVERY_TARGET_FILES;
    if (n != USED_BYTES) return false;
    return SHA256(out, CHECKSUM_OFFSET, out + CHECKSUM_OFFSET) != NULL;
}

bool qihse_ct1_recovery_decode(const unsigned char* data, size_t length,
    bool receipt, qihse_ct1_recovery_manifest_t* out, bool* out_spent) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (out_spent) *out_spent = false;
    if (!data || length != QIHSE_CT1_RECOVERY_WIRE_SIZE ||
        memcmp(data, magic, sizeof(magic)) || data[8] != (receipt ? 2 : 1) ||
        data[9] > (receipt ? 1 : 0) || data[10] || data[11]) return false;
    unsigned char checksum[32];
    if (!SHA256(data, CHECKSUM_OFFSET, checksum) ||
        memcmp(checksum, data + CHECKSUM_OFFSET, 32)) return false;
    qihse_ct1_recovery_manifest_t m = {0};
    size_t n = HEADER;
    char* ids[] = {m.issuer_qkp_id, m.source_qkp_id, m.target_qkp_id,
        m.generation, m.source_store_id, m.target_store_id,
        m.replication_principal_id, m.row_key,
        m.source_peer_qkp_id, m.target_peer_qkp_id};
    for (size_t i = 0; i < 10; ++i, n += ID_BYTES)
        if (!get_id(data + n, ids[i])) return false;
    unsigned char* hashes[] = {m.issuer_operator_pin, m.source_peer_pin,
        m.target_peer_pin, m.frame_sha256, m.baseline_sha256, m.nonce};
    for (size_t i = 0; i < 6; ++i, n += DIGEST_BYTES)
        memcpy(hashes[i], data + n, DIGEST_BYTES);
    uint64_t* values[] = {&m.epoch, &m.issued_ms, &m.expires_ms,
        &m.frame_offset, &m.frame_length, &m.frame_position, &m.baseline_row_seq,
        &m.target_cursor, &m.target_high_water, &m.source_high_water,
        &m.row_change_seq, &m.tombstone_position};
    for (size_t i = 0; i < 12; ++i, n += 8) *values[i] = get64(data + n);
    uint32_t* words[] = {&m.row_tenant_id, &m.principal_tenant_id};
    for (size_t i = 0; i < 2; ++i, n += 4) *words[i] = get32(data + n);
    uint16_t* shorts[] = {&m.classification, &m.sci,
        &m.principal_classification, &m.principal_sci, &m.operation};
    for (size_t i = 0; i < 5; ++i, n += 2) *shorts[i] = get16(data + n);
    if (!get_files(data + n, m.source_files, QIHSE_CT1_RECOVERY_SOURCE_FILES)) return false;
    n += FILE_BYTES * QIHSE_CT1_RECOVERY_SOURCE_FILES;
    if (!get_files(data + n, m.target_files, QIHSE_CT1_RECOVERY_TARGET_FILES)) return false;
    n += FILE_BYTES * QIHSE_CT1_RECOVERY_TARGET_FILES;
    if (n != USED_BYTES) return false;
    for (; n < CHECKSUM_OFFSET; ++n) if (data[n]) return false;
    if (!shape(&m)) return false;
    *out = m;
    if (out_spent) *out_spent = data[9] != 0;
    return true;
}

bool qihse_ct1_recovery_matches(const qihse_ct1_recovery_manifest_t* actual,
    const qihse_ct1_recovery_manifest_t* expected, uint64_t now_ms, bool spent) {
    unsigned char a[QIHSE_CT1_RECOVERY_WIRE_SIZE], b[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    return !spent && actual && expected && now_ms >= actual->issued_ms &&
        now_ms < actual->expires_ms &&
        qihse_ct1_recovery_encode(actual, false, false, a) &&
        qihse_ct1_recovery_encode(expected, false, false, b) &&
        memcmp(a, b, sizeof(a)) == 0;
}
static bool write_all(int fd, const unsigned char* data, size_t n) {
    while (n) {
        ssize_t count = write(fd, data, n);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        data += count; n -= (size_t)count;
    }
    return true;
}
static bool read_record(int fd, bool receipt, qihse_ct1_recovery_manifest_t* out,
    bool* spent) {
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
        st.st_size != QIHSE_CT1_RECOVERY_WIRE_SIZE || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    unsigned char data[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    size_t done = 0;
    while (done < sizeof(data)) {
        ssize_t n = read(fd, data + done, sizeof(data) - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return qihse_ct1_recovery_decode(data, sizeof(data), receipt, out, spent);
}
static bool sync_parent(const char* path) {
    const char* slash = strrchr(path, '/');
    char dir[4096];
    size_t len = slash ? (size_t)(slash - path) : 1;
    if (!slash) dir[0] = '.';
    else if (!len) { dir[0] = '/'; len = 1; }
    else if (len < sizeof(dir)) memcpy(dir, path, len);
    if (!len || len >= sizeof(dir)) return false;
    dir[len] = 0;
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}
bool qihse_ct1_recovery_create(const char* path,
    const qihse_ct1_recovery_manifest_t* manifest, bool receipt) {
    unsigned char data[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    if (!path || !*path || !qihse_ct1_recovery_encode(manifest, receipt, false, data))
        return false;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = write_all(fd, data, sizeof(data)) && fsync(fd) == 0;
    if (close(fd)) ok = false;
    return ok && sync_parent(path);
}
bool qihse_ct1_recovery_load(const char* path, bool receipt,
    qihse_ct1_recovery_manifest_t* out, bool* out_spent) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (out_spent) *out_spent = false;
    if (!path || !*path) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = read_record(fd, receipt, out, out_spent);
    close(fd);
    return ok;
}
bool qihse_ct1_recovery_spend(const char* path,
    const qihse_ct1_recovery_manifest_t* expected, uint64_t now_ms) {
    if (!path || !*path || !expected) return false;
    int fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = false, spent = false;
    qihse_ct1_recovery_manifest_t actual;
    if (flock(fd, LOCK_EX) == 0 && read_record(fd, true, &actual, &spent) &&
        qihse_ct1_recovery_matches(&actual, expected, now_ms, spent)) {
        unsigned char data[QIHSE_CT1_RECOVERY_WIRE_SIZE];
        if (qihse_ct1_recovery_encode(&actual, true, true, data) &&
            lseek(fd, 0, SEEK_SET) == 0 && write_all(fd, data, sizeof(data)) &&
            fsync(fd) == 0) ok = true;
    }
    if (close(fd)) ok = false;
    return ok;
}
/* A same-inode replacement or in-place write is detected by identity and
 * timestamps, in addition to the independently streamed content digest. */
static bool frozen_same(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool frozen_dir_ok(const struct stat* st, bool final) {
    return S_ISDIR(st->st_mode) &&
        (st->st_uid == 0 || st->st_uid == geteuid()) &&
        !(st->st_mode & (final ? 077 : 022)) &&
        (!final || st->st_uid == geteuid());
}
/* Reject empty, dot (except a single leading ./), dot-dot and overlong
 * components; never ask openat to interpret a slash-containing component. */
static int frozen_open_dir(const char* path) {
    if (!path || !*path || strnlen(path, 4097) > 4096) return -1;
    int fd = open(path[0] == '/' ? "/" : ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !frozen_dir_ok(&st, false)) goto fail;
    const char* p = path + (path[0] == '/');
    if (p[0] == '.' && p[1] == '/') p += 2;
    if (!*p) goto fail;
    while (*p) {
        const char* end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || n > 255 || (n == 1 && p[0] == '.') ||
            (n == 2 && p[0] == '.' && p[1] == '.') ||
            (end && !end[1])) goto fail;
        char component[256];
        memcpy(component, p, n); component[n] = 0;
        int next = openat(fd, component, O_RDONLY | O_DIRECTORY |
            O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (next < 0) goto fail;
        close(fd); fd = next;
        if (fstat(fd, &st) || !frozen_dir_ok(&st, !end)) goto fail;
        p = end ? end + 1 : p + n;
    }
    return fd;
fail:
    close(fd);
    return -1;
}
static bool frozen_entries(int fd, const qihse_ct1_recovery_file_t* files,
    size_t count) {
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
        O_NONBLOCK | O_CLOEXEC);
    if (scan < 0) return false;
    DIR* dir = fdopendir(scan);
    if (!dir) { close(scan); return false; }
    unsigned seen = 0;
    bool ok = true;
    struct dirent* entry;
    errno = 0;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        size_t i = 0;
        for (; i < count; ++i)
            if (!strcmp(entry->d_name, files[i].filename)) break;
        if (i == count || (seen & (1u << i))) { ok = false; break; }
        seen |= 1u << i;
        errno = 0;
    }
    if (!entry && errno) ok = false;
    if (closedir(dir)) ok = false;
    return ok && seen == (1u << count) - 1u;
}
static bool frozen_file(int dir, const qihse_ct1_recovery_file_t* file) {
    int fd = openat(dir, file->filename,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat before, after, named;
    bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) &&
        before.st_uid == geteuid() && before.st_nlink == 1 &&
        ((before.st_mode & 07777) == 0600 ||
         (before.st_mode & 07777) == 0400) &&
        before.st_size >= 0 && (uint64_t)before.st_size == file->size;
    EVP_MD_CTX* ctx = ok ? EVP_MD_CTX_new() : NULL;
    if (ok) ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    uint64_t total = 0;
    unsigned char block[16384], digest[32];
    while (ok) {
        ssize_t n = read(fd, block, sizeof(block));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || (uint64_t)n > file->size - total) { ok = false; break; }
        if (!n) break;
        total += (uint64_t)n;
        ok = EVP_DigestUpdate(ctx, block, (size_t)n) == 1;
    }
    unsigned digest_len = 0;
    if (ok) ok = total == file->size &&
        EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1 &&
        digest_len == sizeof(digest) &&
        memcmp(digest, file->sha256, sizeof(digest)) == 0 &&
        fstat(fd, &after) == 0 && frozen_same(&before, &after) &&
        fstatat(dir, file->filename, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        frozen_same(&after, &named);
    EVP_MD_CTX_free(ctx);
    if (close(fd)) ok = false;
    return ok;
}
bool qihse_ct1_recovery_verify_frozen(const char* frozen_dir,
    const qihse_ct1_recovery_manifest_t* manifest, bool source) {
    if (!shape(manifest)) return false;
    const qihse_ct1_recovery_file_t* files = source ?
        manifest->source_files : manifest->target_files;
    size_t count = source ? QIHSE_CT1_RECOVERY_SOURCE_FILES :
        QIHSE_CT1_RECOVERY_TARGET_FILES;
    int dir = frozen_open_dir(frozen_dir);
    if (dir < 0) return false;
    struct stat before, after, reopened;
    bool ok = fstat(dir, &before) == 0 && frozen_entries(dir, files, count);
    for (size_t i = 0; ok && i < count; ++i)
        ok = frozen_file(dir, &files[i]);
    if (ok) ok = frozen_entries(dir, files, count);
    /* A second full pass catches changes to earlier files while later ones
     * were being read; this is evidence, not a writer-exclusion lock. */
    for (size_t i = 0; ok && i < count; ++i)
        ok = frozen_file(dir, &files[i]);
    if (ok) ok = frozen_entries(dir, files, count) &&
        fstat(dir, &after) == 0 && frozen_same(&before, &after);
    int check = frozen_open_dir(frozen_dir);
    if (ok) ok = check >= 0 && fstat(check, &reopened) == 0 &&
        frozen_same(&after, &reopened);
    if (check >= 0 && close(check)) ok = false;
    if (close(dir)) ok = false;
    return ok;
}
bool qihse_ct1_recovery_issuer_authorized(void) { return false; }
