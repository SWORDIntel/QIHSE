#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_shared_backup.h"
#include "qihse_auth.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define SB_MANIFEST_MAX (1024u * 1024u)
#define SB_CHUNK (64u * 1024u)
#define SB_NAME 64u
#define SB_MAC_LINE 101u
#define SB_JOURNAL_MAX (64u * 1024u * 1024u)

static const char sb_magic[] = "QIHSE-SHARED-BACKUP 1\n";

typedef struct {
    char name[SB_NAME];
    uint64_t length;
    unsigned char hash[48];
} sb_member_t;

typedef struct {
    int fd;
    qihse_shared_backup_info_t info;
    sb_member_t* members;
    unsigned char* manifest;
    size_t manifest_length;
} sb_package_t;

typedef struct {
    int parent, fd;
    char* parent_path;
    char* name;
    char* path;
    char stage[48];
    bool published;
} sb_stage_t;

static bool sb_authorized(const qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_id(user) == 0u && qihse_user_get_tenant_id(user) == 0u;
}

static qihse_user_t* sb_principal(qihse_user_t* user, uint64_t* generation) {
    if (!sb_authorized(user)) return NULL;
    qihse_user_t* held = qihse_auth_borrow_principal_scoped(0u, generation);
    if (held == user && sb_authorized(held)) return held;
    if (held) qihse_auth_release_principal_scoped(held);
    return NULL;
}

static bool sb_principal_valid(qihse_user_t* user, uint64_t generation) {
    uint64_t current = 0u;
    qihse_user_t* held = sb_principal(user, &current);
    bool ok = held && current == generation;
    if (held) qihse_auth_release_principal_scoped(held);
    return ok;
}

static bool sb_dir(int fd) {
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
        st.st_uid == geteuid() && !(st.st_mode & 0077);
}

static bool sb_file(int fd, struct stat* st) {
    return fstat(fd, st) == 0 && S_ISREG(st->st_mode) && st->st_nlink == 1 &&
        st->st_uid == geteuid() && !(st->st_mode & 0077) && st->st_size >= 0;
}

/* Reject special files before open; NONBLOCK also closes the FIFO replacement
 * race between the directory lookup and the descriptor identity check. */
static int sb_open_member(int directory, const char* name, int flags,
                           qihse_user_t* user) {
    struct stat named, opened;
    if (!sb_authorized(user) ||
        fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(named.st_mode) || named.st_nlink != 1 || named.st_uid != geteuid() ||
        (named.st_mode & 0077) || named.st_size < 0) return -1;
    int fd = openat(directory, name, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd >= 0 && sb_file(fd, &opened) && opened.st_dev == named.st_dev &&
        opened.st_ino == named.st_ino && opened.st_size == named.st_size) return fd;
    if (fd >= 0) close(fd);
    return -1;
}

static bool sb_write(int fd, const void* data, size_t length) {
    const unsigned char* p = data;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || (size_t)n > length) return false;
        p += n;
        length -= (size_t)n;
    }
    return true;
}

static bool sb_read(int fd, void* data, size_t length, qihse_user_t* user) {
    unsigned char* p = data;
    while (length) {
        if (!sb_authorized(user)) return false;
        ssize_t n = read(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || (size_t)n > length) return false;
        p += n;
        length -= (size_t)n;
    }
    return true;
}

static void sb_hex(const unsigned char* data, size_t length, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0u; i < length; ++i) {
        out[2u * i] = digits[data[i] >> 4];
        out[2u * i + 1u] = digits[data[i] & 15u];
    }
    out[2u * length] = '\0';
}

static int sb_nibble(char c) {
    return c >= '0' && c <= '9' ? c - '0' :
        c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static bool sb_unhex(const char* text, size_t length, unsigned char* out) {
    for (size_t i = 0u; i < length; ++i) {
        int hi = sb_nibble(text[2u * i]), lo = sb_nibble(text[2u * i + 1u]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

static bool sb_mac(const uint8_t* key, const void* data, size_t length,
                   unsigned char out[48]) {
    EVP_MAC* algorithm = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX* ctx = algorithm ? EVP_MAC_CTX_new(algorithm) : NULL;
    EVP_MAC_free(algorithm);
    char digest[] = "SHA384";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()
    };
    size_t n = 0u;
    bool ok = ctx && EVP_MAC_init(ctx, key, QIHSE_SHARED_BACKUP_KEY_BYTES, params) == 1 &&
        EVP_MAC_update(ctx, data, length) == 1 &&
        EVP_MAC_final(ctx, out, &n, 48u) == 1 && n == 48u;
    EVP_MAC_CTX_free(ctx);
    return ok;
}

static bool sb_name(const char* name, uint64_t next_id) {
    if (!strcmp(name, QIHSE_SHARED_BACKUP_KV_FILE) ||
        !strcmp(name, QIHSE_SHARED_BACKUP_SQL_FILE) ||
        !strcmp(name, QIHSE_SHARED_BACKUP_BLOB_FILE) ||
        !strcmp(name, QIHSE_SHARED_BACKUP_JOURNAL_FILE)) return true;
    static const char prefix[] = QIHSE_SHARED_BACKUP_SQL_FILE ".decision.";
    size_t n = sizeof(prefix) - 1u;
    if (strlen(name) != n + 16u || strncmp(name, prefix, n)) return false;
    uint64_t id = 0u;
    for (size_t i = 0u; i < 16u; ++i) {
        int digit = sb_nibble(name[n + i]);
        if (digit < 0) return false;
        id = (id << 4) | (unsigned)digit;
    }
    return id && id < next_id;
}

static int sb_member_order(const void* a, const void* b) {
    return strcmp(((const sb_member_t*)a)->name, ((const sb_member_t*)b)->name);
}

static bool sb_journal_chunk(const unsigned char* data, size_t length,
                              const qihse_shared_backup_info_t* info) {
    if (length % 36u) return false;
    for (size_t at = 0u; at < length; at += 36u) {
        const unsigned char* r = data + at;
        uint32_t crc = UINT32_MAX;
        for (size_t i = 0u; i < 32u; ++i) {
            crc ^= r[i];
            for (unsigned b = 0u; b < 8u; ++b)
                crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1u));
        }
        uint32_t stored = ((uint32_t)r[32] << 24) | ((uint32_t)r[33] << 16) |
            ((uint32_t)r[34] << 8) | r[35];
        uint64_t id = 0u;
        for (size_t i = 8u; i < 16u; ++i) id = (id << 8) | r[i];
        if (memcmp(r, "QT2P", 4u) || r[4] != 1u || r[7] ||
            r[5] < 1u || r[5] > 3u || r[6] > QIHSE_TXN_MAX_PARTICIPANTS ||
            (r[5] != 1u && r[6]) || ~crc != stored ||
            !id || id >= info->coordinator.next_txn_id) return false;
        for (size_t i = 0u; i < r[6]; ++i) {
            if (r[16u + i] != info->sql_engine_id && r[16u + i] != info->blob_engine_id)
                return false;
            for (size_t j = 0u; j < i; ++j)
                if (r[16u + i] == r[16u + j]) return false;
        }
        for (size_t i = r[6]; i < QIHSE_TXN_MAX_PARTICIPANTS; ++i)
            if (r[16u + i]) return false;
    }
    return true;
}

/* Authenticate every byte copied; no content-sized allocations. */
static bool sb_hash_member(int directory, const sb_member_t* expected,
    int output, qihse_user_t* user, const qihse_shared_backup_info_t* info,
    sb_member_t* actual, bool sync_source) {
    if (!sb_authorized(user)) return false;
    int fd = sb_open_member(directory, expected->name,
        sync_source ? O_RDWR : O_RDONLY, user);
    struct stat before, after;
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    unsigned char* chunk = malloc(SB_CHUNK);
    bool ok = fd >= 0 && hash && chunk && sb_file(fd, &before) &&
        (uint64_t)before.st_size <= QIHSE_SHARED_BACKUP_MAX_PAYLOAD_BYTES &&
        EVP_DigestInit_ex(hash, EVP_sha384(), NULL) == 1;
    uint64_t total = 0u;
    bool journal = !strcmp(expected->name, QIHSE_SHARED_BACKUP_JOURNAL_FILE);
    size_t chunk_size = journal ? (SB_CHUNK / 36u) * 36u : SB_CHUNK;
    while (ok && total < (uint64_t)before.st_size) {
        size_t n = (uint64_t)before.st_size - total > chunk_size ? chunk_size :
            (size_t)((uint64_t)before.st_size - total);
        ok = sb_read(fd, chunk, n, user) && (!journal || sb_journal_chunk(chunk, n, info)) &&
            EVP_DigestUpdate(hash, chunk, n) == 1;
        if (ok && output >= 0) ok = sb_write(output, chunk, n);
        total += n;
    }
    unsigned int n = 0u;
    if (ok) ok = sb_file(fd, &after) && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        EVP_DigestFinal_ex(hash, actual->hash, &n) == 1 && n == 48u;
    if (ok && sync_source) ok = fsync(fd) == 0;
    if (ok && output >= 0) ok = fsync(output) == 0;
    if (ok) {
        memcpy(actual->name, expected->name, sizeof(actual->name));
        actual->length = total;
    }
    if (fd >= 0 && close(fd) != 0) ok = false;
    free(chunk);
    EVP_MD_CTX_free(hash);
    return ok;
}

static bool sb_members_valid(const qihse_shared_backup_info_t* info,
                              const sb_member_t* members) {
    if (info->member_count < 4u || info->member_count > QIHSE_SHARED_BACKUP_MAX_MEMBERS ||
        info->payload_bytes > QIHSE_SHARED_BACKUP_MAX_PAYLOAD_BYTES ||
        !info->kv.instance_id || !info->kv.projection_epoch ||
        info->kv.change_seq == UINT64_MAX || info->kv.projection_epoch == UINT64_MAX ||
        info->sql_epoch == UINT64_MAX || info->blob_epoch == UINT64_MAX ||
        info->coordinator.epoch == UINT64_MAX || !info->coordinator.next_txn_id ||
        info->coordinator.next_txn_id == UINT64_MAX ||
        info->coordinator.journal_bytes > SB_JOURNAL_MAX ||
        info->coordinator.journal_bytes % 36u || info->sql_engine_id == info->blob_engine_id)
        return false;
    uint64_t total = 0u;
    unsigned required = 0u;
    for (uint32_t i = 0u; i < info->member_count; ++i) {
        const sb_member_t* m = members + i;
        if (!sb_name(m->name, info->coordinator.next_txn_id) ||
            (i && strcmp(members[i - 1u].name, m->name) >= 0) ||
            m->length > QIHSE_SHARED_BACKUP_MAX_PAYLOAD_BYTES - total) return false;
        total += m->length;
        if (!strcmp(m->name, QIHSE_SHARED_BACKUP_KV_FILE)) {
            if (m->length < 64u) return false;
            required |= 1u;
        } else if (!strcmp(m->name, QIHSE_SHARED_BACKUP_SQL_FILE)) {
            if (!m->length) return false;
            required |= 2u;
        } else if (!strcmp(m->name, QIHSE_SHARED_BACKUP_BLOB_FILE)) {
            if (m->length < 80u) return false;
            required |= 4u;
        } else if (!strcmp(m->name, QIHSE_SHARED_BACKUP_JOURNAL_FILE)) {
            if (m->length != info->coordinator.journal_bytes) return false;
            required |= 8u;
        } else if (m->length != 32u) return false;
    }
    return required == 15u && total == info->payload_bytes;
}

static bool sb_body(const qihse_shared_backup_info_t* info, const sb_member_t* members,
                     qihse_user_t* user, unsigned char** output, size_t* length) {
    if (!sb_authorized(user) || !sb_members_valid(info, members)) return false;
    unsigned char* text = malloc(SB_MANIFEST_MAX);
    if (!text) return false;
    int n = snprintf((char*)text, SB_MANIFEST_MAX,
        "%sKV %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n"
        "SQL %016" PRIx64 "\nBLOB %016" PRIx64 "\n"
        "COORD %016" PRIx64 " %016" PRIx64 " %016" PRIx64 "\n"
        "ENGINES %02x %02x\nTOTAL %08" PRIx32 " %016" PRIx64 "\n",
        sb_magic, info->kv.instance_id, info->kv.change_seq, info->kv.projection_epoch,
        info->sql_epoch, info->blob_epoch, info->coordinator.epoch,
        info->coordinator.next_txn_id, info->coordinator.journal_bytes,
        (unsigned)info->sql_engine_id, (unsigned)info->blob_engine_id,
        info->member_count, info->payload_bytes);
    bool ok = n > 0 && (size_t)n < SB_MANIFEST_MAX;
    size_t at = ok ? (size_t)n : 0u;
    for (uint32_t i = 0u; ok && i < info->member_count; ++i) {
        char hex[97];
        sb_hex(members[i].hash, 48u, hex);
        n = snprintf((char*)text + at, SB_MANIFEST_MAX - at,
            "FILE %s %016" PRIx64 " %s\n", members[i].name, members[i].length, hex);
        ok = n > 0 && (size_t)n < SB_MANIFEST_MAX - at;
        if (ok) at += (size_t)n;
    }
    if (!ok || at > SB_MANIFEST_MAX - SB_MAC_LINE) { free(text); return false; }
    *output = text;
    *length = at;
    return true;
}

static char* sb_line(char** cursor) {
    char* line = cursor && *cursor ? strsep(cursor, "\n") : NULL;
    return line && strlen(line) < 256u ? line : NULL;
}

static bool sb_parse(sb_package_t* package, qihse_user_t* user, const uint8_t* key) {
    if (package->manifest_length < SB_MAC_LINE) return false;
    size_t body_length = package->manifest_length - SB_MAC_LINE;
    const unsigned char* tail = package->manifest + body_length;
    unsigned char expected[48], actual[48];
    if (memcmp(tail, "MAC ", 4u) || tail[100] != '\n' ||
        !sb_unhex((const char*)tail + 4u, 48u, expected) ||
        !sb_mac(key, package->manifest, body_length, actual) ||
        CRYPTO_memcmp(expected, actual, sizeof(actual)) ||
        memchr(package->manifest, '\0', body_length)) return false;
    char* text = strndup((const char*)package->manifest, body_length);
    if (!text) return false;
    char* cursor = text;
    char* line = sb_line(&cursor);
    qihse_shared_backup_info_t* i = &package->info;
    memset(i, 0, sizeof(*i));
    int used = -1;
    bool ok = line && !strcmp(line, "QIHSE-SHARED-BACKUP 1");
#define SB_PARSE_LINE(format, fields, wanted) \
    do { \
        line = ok ? sb_line(&cursor) : NULL; used = -1; \
        ok = line && sscanf(line, format "%n", fields, &used) == (wanted) && \
            used >= 0 && (size_t)used == strlen(line); \
    } while (0)
    /* Spell multi-field lines separately to keep format arguments type-checked. */
    line = ok ? sb_line(&cursor) : NULL; used = -1;
    ok = line && sscanf(line, "KV %16" SCNx64 " %16" SCNx64 " %16" SCNx64 "%n",
        &i->kv.instance_id, &i->kv.change_seq, &i->kv.projection_epoch, &used) == 3 &&
        used >= 0 && (size_t)used == strlen(line);
    SB_PARSE_LINE("SQL %16" SCNx64, &i->sql_epoch, 1);
    SB_PARSE_LINE("BLOB %16" SCNx64, &i->blob_epoch, 1);
    line = ok ? sb_line(&cursor) : NULL; used = -1;
    ok = line && sscanf(line, "COORD %16" SCNx64 " %16" SCNx64 " %16" SCNx64 "%n",
        &i->coordinator.epoch, &i->coordinator.next_txn_id,
        &i->coordinator.journal_bytes, &used) == 3 && used >= 0 && (size_t)used == strlen(line);
    unsigned sql_id = 0u, blob_id = 0u;
    line = ok ? sb_line(&cursor) : NULL; used = -1;
    ok = line && sscanf(line, "ENGINES %2x %2x%n", &sql_id, &blob_id, &used) == 2 &&
        used >= 0 && (size_t)used == strlen(line) && sql_id <= UINT8_MAX && blob_id <= UINT8_MAX;
    i->sql_engine_id = (uint8_t)sql_id;
    i->blob_engine_id = (uint8_t)blob_id;
    line = ok ? sb_line(&cursor) : NULL; used = -1;
    ok = line && sscanf(line, "TOTAL %8" SCNx32 " %16" SCNx64 "%n",
        &i->member_count, &i->payload_bytes, &used) == 2 && used >= 0 &&
        (size_t)used == strlen(line) && i->member_count >= 4u &&
        i->member_count <= QIHSE_SHARED_BACKUP_MAX_MEMBERS;
    if (ok) {
        package->members = calloc(i->member_count, sizeof(*package->members));
        ok = package->members != NULL;
    }
    for (uint32_t n = 0u; ok && n < i->member_count; ++n) {
        char hex[97] = {0};
        sb_member_t* m = package->members + n;
        line = sb_line(&cursor); used = -1;
        ok = line && sscanf(line, "FILE %63s %16" SCNx64 " %96s%n",
            m->name, &m->length, hex, &used) == 3 && used >= 0 &&
            (size_t)used == strlen(line) && strlen(hex) == 96u && sb_unhex(hex, 48u, m->hash);
    }
#undef SB_PARSE_LINE
    unsigned char* canonical = NULL;
    size_t canonical_length = 0u;
    ok = ok && cursor && !*cursor && sb_body(i, package->members, user,
        &canonical, &canonical_length) && canonical_length == body_length &&
        !memcmp(canonical, package->manifest, body_length);
    free(canonical);
    free(text);
    return ok;
}

static bool sb_directory_members(int fd, const sb_package_t* package, qihse_user_t* user) {
    if (!sb_authorized(user) || !sb_dir(fd)) return false;
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR* directory = scan >= 0 ? fdopendir(scan) : NULL;
    if (!directory) { if (scan >= 0) close(scan); return false; }
    bool ok = true;
    uint32_t count = 0u;
    bool manifest = false;
    struct dirent* entry;
    errno = 0;
    while (ok && (entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!sb_authorized(user)) { ok = false; break; }
        if (!strcmp(entry->d_name, QIHSE_SHARED_BACKUP_MANIFEST_FILE)) {
            if (manifest) { ok = false; break; }
            manifest = true;
        } else {
            sb_member_t needle = {0};
            if (strlen(entry->d_name) >= sizeof needle.name) { ok = false; break; }
            strcpy(needle.name, entry->d_name);
            if (!bsearch(&needle, package->members, package->info.member_count,
                sizeof(*package->members), sb_member_order)) { ok = false; break; }
            count++;
        }
        errno = 0;
    }
    if (errno) ok = false;
    closedir(directory);
    return ok && manifest && count == package->info.member_count;
}

static void sb_package_close(sb_package_t* package) {
    if (package->fd >= 0) close(package->fd);
    free(package->members);
    free(package->manifest);
}

static bool sb_package_load(const char* path, qihse_user_t* user, const uint8_t* key,
                             sb_package_t* package) {
    if (!path || !sb_authorized(user)) return false;
    package->fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (package->fd < 0 || !sb_dir(package->fd)) return false;
    int fd = sb_open_member(package->fd, QIHSE_SHARED_BACKUP_MANIFEST_FILE, O_RDONLY, user);
    struct stat st;
    bool ok = fd >= 0 && sb_file(fd, &st) && st.st_size >= (off_t)SB_MAC_LINE &&
        (uint64_t)st.st_size <= SB_MANIFEST_MAX;
    if (ok) {
        package->manifest_length = (size_t)st.st_size;
        package->manifest = malloc(package->manifest_length + 1u);
        ok = package->manifest && sb_read(fd, package->manifest, package->manifest_length, user);
        if (ok) package->manifest[package->manifest_length] = '\0';
        struct stat after;
        unsigned char extra;
        ssize_t trailing = -1;
        if (ok) {
            if (sb_authorized(user))
                do { trailing = read(fd, &extra, 1u); } while (trailing < 0 && errno == EINTR);
            ok = trailing == 0 && sb_file(fd, &after) && st.st_dev == after.st_dev &&
                st.st_ino == after.st_ino && st.st_size == after.st_size;
        }
    }
    if (fd >= 0 && close(fd) != 0) ok = false;
    ok = ok && sb_parse(package, user, key) && sb_directory_members(package->fd, package, user);
    for (uint32_t n = 0u; ok && n < package->info.member_count; ++n) {
        sb_member_t actual = {0};
        ok = sb_hash_member(package->fd, package->members + n, -1, user,
            &package->info, &actual, false) && actual.length == package->members[n].length &&
            !CRYPTO_memcmp(actual.hash, package->members[n].hash, sizeof(actual.hash));
    }
    return ok;
}

static bool sb_stage_identity(const sb_stage_t* stage) {
    struct stat opened, named, path;
    return stage->fd >= 0 && stage->path && fstat(stage->fd, &opened) == 0 &&
        fstatat(stage->parent, stage->stage, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        lstat(stage->path, &path) == 0 && S_ISDIR(named.st_mode) &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino &&
        opened.st_dev == path.st_dev && opened.st_ino == path.st_ino && sb_dir(stage->fd);
}

static void sb_stage_close(sb_stage_t* stage) {
    if (!stage->published && stage->fd >= 0) {
        int scan = openat(stage->fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        DIR* directory = scan >= 0 ? fdopendir(scan) : NULL;
        if (directory) {
            struct dirent* entry;
            while ((entry = readdir(directory))) {
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                struct stat st;
                if (fstatat(stage->fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0)
                    (void)unlinkat(stage->fd, entry->d_name, S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0);
            }
            closedir(directory);
        } else if (scan >= 0) close(scan);
        if (sb_stage_identity(stage)) (void)unlinkat(stage->parent, stage->stage, AT_REMOVEDIR);
    }
    if (stage->fd >= 0) close(stage->fd);
    if (stage->parent >= 0) close(stage->parent);
    free(stage->parent_path); free(stage->name); free(stage->path);
}

static bool sb_stage_open(const char* destination, sb_stage_t* stage) {
    if (!destination || !*destination) return false;
    const char* slash = strrchr(destination, '/');
    stage->name = strdup(slash ? slash + 1 : destination);
    stage->parent_path = slash ? strndup(destination,
        slash == destination ? 1u : (size_t)(slash - destination)) : strdup(".");
    if (!stage->name || !stage->parent_path || !*stage->name ||
        !strcmp(stage->name, ".") || !strcmp(stage->name, "..")) return false;
    stage->parent = open(stage->parent_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (stage->parent < 0 || !sb_dir(stage->parent)) return false;
    struct stat st;
    if (fstatat(stage->parent, stage->name, &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
        return false;
    bool made = false;
    for (unsigned attempt = 0u; !made && attempt < 8u; ++attempt) {
        unsigned char random[16];
        size_t at = 0u;
        while (at < sizeof random) {
            ssize_t n = getrandom(random + at, sizeof random - at, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || (size_t)n > sizeof random - at) return false;
            at += (size_t)n;
        }
        char hex[33]; sb_hex(random, sizeof random, hex);
        if (snprintf(stage->stage, sizeof stage->stage, ".qsb-stage-%s", hex) < 0) return false;
        if (mkdirat(stage->parent, stage->stage, 0700) == 0) made = true;
        else if (errno != EEXIST) return false;
    }
    if (!made) return false;
    stage->fd = openat(stage->parent, stage->stage,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (asprintf(&stage->path, "%s/%s", stage->parent_path, stage->stage) < 0) return false;
    return sb_stage_identity(stage);
}

static qihse_shared_backup_result_t sb_publish(sb_stage_t* stage,
    qihse_user_t* user, uint64_t generation) {
    if (!sb_stage_identity(stage) || fsync(stage->fd) != 0 ||
        !sb_principal_valid(user, generation) || !sb_stage_identity(stage) ||
        renameat2(stage->parent, stage->stage, stage->parent, stage->name, RENAME_NOREPLACE) != 0)
        return QIHSE_SHARED_BACKUP_ERROR;
    stage->published = true;
    return fsync(stage->parent) == 0 ? QIHSE_SHARED_BACKUP_OK :
        QIHSE_SHARED_BACKUP_PUBLISHED_UNSYNCED;
}

static bool sb_checkpoint(const qihse_shared_backup_sources_t* sources,
    qihse_user_t* user, qihse_shared_backup_info_t* info) {
    memset(info, 0, sizeof(*info));
    if (!sources || !sources->kv || !sources->sql || !sources->blob ||
        !sources->coordinator || sources->sql_engine_id == sources->blob_engine_id) return false;
    info->sql_engine_id = sources->sql_engine_id;
    info->blob_engine_id = sources->blob_engine_id;
    return qihse_kv_snapshot_checkpoint_user(sources->kv, user, &info->kv) &&
        qihse_table_store_snapshot_epoch_user(sources->sql, user, &info->sql_epoch) &&
        qihse_blob_snapshot_epoch_user(sources->blob, user, &info->blob_epoch) &&
        qihse_txn_backup_checkpoint_user(sources->coordinator, user, &info->coordinator);
}

static bool sb_checkpoint_equal(const qihse_shared_backup_info_t* a,
                                const qihse_shared_backup_info_t* b) {
    return a->kv.instance_id == b->kv.instance_id && a->kv.change_seq == b->kv.change_seq &&
        a->kv.projection_epoch == b->kv.projection_epoch && a->sql_epoch == b->sql_epoch &&
        a->blob_epoch == b->blob_epoch && a->coordinator.epoch == b->coordinator.epoch &&
        a->coordinator.next_txn_id == b->coordinator.next_txn_id &&
        a->coordinator.journal_bytes == b->coordinator.journal_bytes &&
        a->sql_engine_id == b->sql_engine_id && a->blob_engine_id == b->blob_engine_id;
}

static bool sb_collect(sb_stage_t* stage, qihse_user_t* user, sb_package_t* package) {
    if (!sb_authorized(user) || !sb_stage_identity(stage)) return false;
    package->members = calloc(QIHSE_SHARED_BACKUP_MAX_MEMBERS, sizeof(*package->members));
    if (!package->members) return false;
    int scan = openat(stage->fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    DIR* directory = scan >= 0 ? fdopendir(scan) : NULL;
    if (!directory) { if (scan >= 0) close(scan); return false; }
    bool ok = true;
    struct dirent* entry;
    errno = 0;
    while (ok && (entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        uint32_t n = package->info.member_count;
        sb_member_t named = {0}, actual = {0};
        ok = n < QIHSE_SHARED_BACKUP_MAX_MEMBERS && strlen(entry->d_name) < sizeof named.name &&
            sb_name(entry->d_name, package->info.coordinator.next_txn_id);
        if (ok) {
            strcpy(named.name, entry->d_name);
            ok = sb_hash_member(stage->fd, &named, -1, user, &package->info, &actual, true) &&
                actual.length <= QIHSE_SHARED_BACKUP_MAX_PAYLOAD_BYTES - package->info.payload_bytes;
        }
        if (ok) {
            package->members[n] = actual;
            package->info.member_count++;
            package->info.payload_bytes += actual.length;
        }
        errno = 0;
    }
    if (errno) ok = false;
    closedir(directory);
    if (!ok) return false;
    qsort(package->members, package->info.member_count, sizeof(*package->members), sb_member_order);
    return sb_members_valid(&package->info, package->members);
}

static bool sb_manifest_write(sb_stage_t* stage, sb_package_t* package,
                               qihse_user_t* user, const uint8_t* key) {
    unsigned char* body = NULL;
    size_t length = 0u;
    unsigned char mac[48]; char hex[97];
    if (!sb_body(&package->info, package->members, user, &body, &length) ||
        !sb_mac(key, body, length, mac)) { free(body); return false; }
    sb_hex(mac, sizeof(mac), hex);
    package->manifest_length = length + SB_MAC_LINE;
    package->manifest = malloc(package->manifest_length + 1u);
    bool ok = package->manifest != NULL;
    if (ok) {
        memcpy(package->manifest, body, length);
        ok = snprintf((char*)package->manifest + length, SB_MAC_LINE + 1u,
            "MAC %s\n", hex) == (int)SB_MAC_LINE;
    }
    free(body);
    int fd = ok ? openat(stage->fd, QIHSE_SHARED_BACKUP_MANIFEST_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    ok = ok && fd >= 0 && sb_write(fd, package->manifest, package->manifest_length) && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    return ok;
}

typedef struct {
    int fd;
    uint64_t bytes;
    qihse_user_t* user;
} sb_sink_t;

static bool sb_sink_write(sb_sink_t* sink, const void* data, size_t length) {
    if (!sb_authorized(sink->user) || length > QIHSE_SHARED_BACKUP_MAX_PAYLOAD_BYTES - sink->bytes ||
        !sb_write(sink->fd, data, length)) return false;
    sink->bytes += length;
    return true;
}

static bool sb_blob_write(void* opaque, const uint8_t* data, size_t length) {
    return sb_sink_write(opaque, data, length);
}

static bool sb_journal_write(void* opaque, const void* data, size_t length) {
    return sb_sink_write(opaque, data, length);
}

qihse_shared_backup_result_t qihse_shared_backup_export_user(
    const char* destination, const qihse_shared_backup_sources_t* sources,
    qihse_user_t* user, const uint8_t* key, size_t key_length,
    qihse_shared_backup_info_t* info) {
    if (!key || key_length != QIHSE_SHARED_BACKUP_KEY_BYTES) return QIHSE_SHARED_BACKUP_ERROR;
    uint64_t generation = 0u;
    qihse_user_t* held = sb_principal(user, &generation);
    if (!held) return QIHSE_SHARED_BACKUP_ERROR;
    unsigned char secret[QIHSE_SHARED_BACKUP_KEY_BYTES];
    memcpy(secret, key, sizeof(secret));
    sb_stage_t stage = { .parent = -1, .fd = -1 };
    sb_package_t package = { .fd = -1 };
    qihse_shared_backup_result_t result = QIHSE_SHARED_BACKUP_ERROR;
    uint64_t sql_next = 0u, blob_next = 0u;
    if (!sb_checkpoint(sources, held, &package.info) ||
        !qihse_table_store_decision_next_id(sources->sql, &sql_next) ||
        !qihse_blob_decision_next_id(sources->blob, &blob_next) ||
        package.info.coordinator.next_txn_id < sql_next ||
        package.info.coordinator.next_txn_id < blob_next ||
        !sb_principal_valid(held, generation) || !sb_stage_open(destination, &stage)) goto done;
    char* path = NULL;
    qihse_backup_info_t kv_info = {0};
    bool ok = asprintf(&path, "%s/%s", stage.path, QIHSE_SHARED_BACKUP_KV_FILE) >= 0;
    if (ok) ok = sb_stage_identity(&stage) &&
        qihse_backup_full_user(sources->kv, held, path, &kv_info) == QIHSE_BACKUP_EXPORT_OK;
    qihse_backup_info_free(&kv_info);
    free(path); path = NULL;
    if (ok) ok = asprintf(&path, "%s/%s", stage.path, QIHSE_SHARED_BACKUP_SQL_FILE) >= 0;
    if (ok) ok = sb_stage_identity(&stage) && qihse_table_store_backup(sources->sql, held, path);
    free(path);
    if (!ok) goto done;
    if (unlinkat(stage.fd, QIHSE_SHARED_BACKUP_SQL_FILE ".lock", 0) != 0 && errno != ENOENT) goto done;
    sb_sink_t sink = { .fd = openat(stage.fd, QIHSE_SHARED_BACKUP_BLOB_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600), .user = held };
    ok = sink.fd >= 0 && qihse_blob_archive_export_user(sources->blob, held, secret, sizeof(secret),
        sb_blob_write, &sink) && fsync(sink.fd) == 0;
    if (sink.fd >= 0 && close(sink.fd) != 0) ok = false;
    if (!ok) goto done;
    sink.fd = openat(stage.fd, QIHSE_SHARED_BACKUP_JOURNAL_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    sink.bytes = 0u;
    qihse_txn_backup_checkpoint_t captured;
    ok = sink.fd >= 0 && qihse_txn_backup_export_user(sources->coordinator, held,
        &package.info.coordinator, sb_journal_write, &sink, &captured) &&
        sink.bytes == package.info.coordinator.journal_bytes && fsync(sink.fd) == 0;
    if (sink.fd >= 0 && close(sink.fd) != 0) ok = false;
    qihse_shared_backup_info_t after;
    if (!ok || !sb_collect(&stage, held, &package) ||
        !sb_checkpoint(sources, held, &after) || !sb_checkpoint_equal(&package.info, &after) ||
        !sb_principal_valid(held, generation) || !sb_manifest_write(&stage, &package, held, secret) ||
        !sb_directory_members(stage.fd, &package, held) || !sb_principal_valid(held, generation)) goto done;
    result = sb_publish(&stage, held, generation);
    if (result != QIHSE_SHARED_BACKUP_ERROR && info) *info = package.info;
done:
    sb_stage_close(&stage);
    sb_package_close(&package);
    OPENSSL_cleanse(secret, sizeof(secret));
    qihse_auth_release_principal_scoped(held);
    return result;
}

bool qihse_shared_backup_verify_user(const char* bundle, qihse_user_t* user,
    const uint8_t* key, size_t key_length, qihse_shared_backup_info_t* info) {
    if (!key || key_length != QIHSE_SHARED_BACKUP_KEY_BYTES) return false;
    uint64_t generation = 0u;
    qihse_user_t* held = sb_principal(user, &generation);
    if (!held) return false;
    sb_package_t package = { .fd = -1 };
    bool ok = sb_package_load(bundle, held, key, &package) && sb_principal_valid(held, generation);
    if (ok && info) *info = package.info;
    sb_package_close(&package);
    qihse_auth_release_principal_scoped(held);
    return ok;
}

qihse_shared_backup_result_t qihse_shared_backup_unpack_user(
    const char* bundle, const char* destination, qihse_user_t* user,
    const uint8_t* key, size_t key_length, qihse_shared_backup_info_t* info) {
    if (!key || key_length != QIHSE_SHARED_BACKUP_KEY_BYTES) return QIHSE_SHARED_BACKUP_ERROR;
    uint64_t generation = 0u;
    qihse_user_t* held = sb_principal(user, &generation);
    if (!held) return QIHSE_SHARED_BACKUP_ERROR;
    sb_package_t package = { .fd = -1 };
    sb_stage_t stage = { .parent = -1, .fd = -1 };
    qihse_shared_backup_result_t result = QIHSE_SHARED_BACKUP_ERROR;
    if (!sb_package_load(bundle, held, key, &package) ||
        !sb_principal_valid(held, generation) || !sb_stage_open(destination, &stage)) goto done;
    for (uint32_t n = 0u; n < package.info.member_count; ++n) {
        int fd = openat(stage.fd, package.members[n].name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        sb_member_t actual = {0};
        bool ok = fd >= 0 && sb_hash_member(package.fd, package.members + n, fd, held,
            &package.info, &actual, false) && actual.length == package.members[n].length &&
            !CRYPTO_memcmp(actual.hash, package.members[n].hash, sizeof(actual.hash));
        if (fd >= 0 && close(fd) != 0) ok = false;
        if (!ok) goto done;
    }
    int fd = openat(stage.fd, QIHSE_SHARED_BACKUP_MANIFEST_FILE,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok = fd >= 0 && sb_write(fd, package.manifest, package.manifest_length) && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (!ok || !sb_directory_members(package.fd, &package, held) ||
        !sb_directory_members(stage.fd, &package, held) || !sb_principal_valid(held, generation)) goto done;
    result = sb_publish(&stage, held, generation);
    if (result != QIHSE_SHARED_BACKUP_ERROR && info) *info = package.info;
done:
    sb_stage_close(&stage);
    sb_package_close(&package);
    qihse_auth_release_principal_scoped(held);
    return result;
}
