#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_archive.h"
#include "qihse_ct1_disposition.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* No native struct layout or caller-chosen path is placed on disk. */
enum { HEADER = 16, B = HEADER, SOURCE_QUOTE = B + QIHSE_CT1_RECOVERY_WIRE_SIZE,
    TARGET_QUOTE = SOURCE_QUOTE + QIHSE_CT1_NODE_QUOTE_SIZE,
    FRAME = TARGET_QUOTE + QIHSE_CT1_NODE_QUOTE_SIZE,
    CHECKSUM = FRAME + QIHSE_CT1_RECOVERY_FRAME_BYTES, SIZE = CHECKSUM + 32 };
static const unsigned char magic[8] = {'C','T','1','A','R','C','0','1'};

static bool principal_ok(const qihse_user_t *principal)
{
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    if (!principal) return false;
    qihse_auth_user_active_and_tenant(principal, &active, &tenant);
    return active && tenant == QIHSE_TENANT_SYSTEM &&
        qihse_user_get_classification(principal) == UINT16_MAX &&
        qihse_user_get_sci(principal) == UINT16_MAX &&
        qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX);
}

static bool dir_ok(const qihse_ct1_archive_root_t *root)
{
    struct stat st;
    return root && geteuid() == 0 && root->dirfd >= 0 &&
        root->frozen_source_dir && root->frozen_target_dir &&
        root->source_pub_path && root->target_pub_path &&
        root->source_expected && root->target_expected &&
        !fstat(root->dirfd, &st) && S_ISDIR(st.st_mode) &&
        st.st_uid == 0 && (st.st_mode & 07777) == 0700;
}

static bool archive_id(const unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    char out[QIHSE_CT1_ARCHIVE_ID_SIZE])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char hash[32];
    if (!SHA256(wire, QIHSE_CT1_RECOVERY_WIRE_SIZE, hash)) return false;
    memcpy(out, "ct1-", 4);
    for (size_t i = 0; i < sizeof(hash); ++i) {
        out[4 + 2*i] = hex[hash[i] >> 4];
        out[5 + 2*i] = hex[hash[i] & 15];
    }
    memcpy(out + 68, ".arc", 5);
    return true;
}

static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_nlink == b->st_nlink &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static bool wal_original(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *m,
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES])
{
    if (!principal_ok(principal) ||
        !qihse_ct1_recovery_verify_frozen(principal, root->frozen_source_dir, m, true) ||
        !qihse_ct1_recovery_verify_frozen(principal, root->frozen_target_dir, m, false))
        return false;
    int dir = open(root->frozen_source_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return false;
    int fd = openat(dir, "wal.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat before, after, named;
    bool ok = false;
    const qihse_ct1_recovery_file_t *wal = NULL;
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_SOURCE_FILES; ++i)
        if (m->source_files[i].kind == QIHSE_CT1_FILE_WAL &&
            !strcmp(m->source_files[i].filename, "wal.log")) wal = &m->source_files[i];
    unsigned char stored[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    unsigned char digest[32];
    if (fd >= 0 && wal && m->frame_offset == 0 &&
        wal->size == sizeof(stored) && m->frame_length == sizeof(stored) &&
        !fstat(fd, &before) &&
        S_ISREG(before.st_mode) && before.st_uid == 0 &&
        ((before.st_mode & 07777) == 0400 ||
         (before.st_mode & 07777) == 0600) && before.st_nlink == 1 &&
        before.st_size >= 0 && (uint64_t)before.st_size == wal->size &&
        principal_ok(principal) &&
        pread(fd, stored, sizeof(stored), 0) == (ssize_t)sizeof(stored) &&
        SHA256(stored, sizeof(stored), digest) &&
        !CRYPTO_memcmp(digest, m->frame_sha256, sizeof(digest)) &&
        !fstat(fd, &after) && !fstatat(dir, "wal.log", &named, AT_SYMLINK_NOFOLLOW) &&
        same_file(&before, &after) && same_file(&after, &named) &&
        qihse_ct1_recovery_verify_frozen(principal, root->frozen_source_dir, m, true)) {
        memcpy(frame, stored, sizeof(stored));
        ok = true;
    }
    OPENSSL_cleanse(stored, sizeof(stored));
    if (fd >= 0 && close(fd)) ok = false;
    if (close(dir)) ok = false;
    if (!ok || !principal_ok(principal)) OPENSSL_cleanse(frame, QIHSE_CT1_RECOVERY_FRAME_BYTES);
    return ok && principal_ok(principal);
}

static bool checked_evidence(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *m,
    const unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const unsigned char source_quote[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char target_quote[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES])
{
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE], digest[32];
    qihse_ct1_recovery_manifest_t decoded;
    unsigned char disposition[QIHSE_CT1_DISPOSITION_SIZE];
    bool ok = principal_ok(principal) &&
        qihse_ct1_recovery_encode(m, false, false, canonical) &&
        !CRYPTO_memcmp(canonical, wire, sizeof(canonical)) &&
        qihse_ct1_recovery_decode(wire, sizeof(canonical), false, &decoded, NULL) &&
        qihse_ct1_node_quote_verify_paired_stale(source_quote, QIHSE_CT1_NODE_QUOTE_SIZE,
            target_quote, QIHSE_CT1_NODE_QUOTE_SIZE, wire, sizeof(canonical),
            m->nonce, root->source_pub_path, root->target_pub_path,
            root->source_expected, root->target_expected) &&
        SHA256(frame, QIHSE_CT1_RECOVERY_FRAME_BYTES, digest) &&
        !CRYPTO_memcmp(digest, m->frame_sha256, sizeof(digest)) &&
        qihse_ct1_disposition_encode(principal, m, frame,
            QIHSE_CT1_RECOVERY_FRAME_BYTES, disposition);
    OPENSSL_cleanse(disposition, sizeof(disposition));
    return ok && principal_ok(principal);
}

static bool write_all(int fd, const unsigned char *p, size_t n)
{
    while (n) {
        ssize_t got = write(fd, p, n);
        if (got <= 0) return false;
        p += got;
        n -= (size_t)got;
    }
    return true;
}

#ifdef QIHSE_CT1_TEST_CRASH_CUT
static void archive_cut(const char *phase)
{
    const char *selected = getenv("QIHSE_CT1_ARCHIVE_CUT");
    if (selected && !strcmp(selected, phase)) _exit(87);
}
#else
static void archive_cut(const char *phase) { (void)phase; }
#endif

static bool archive_verify_read(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *id, unsigned char *out)
{
    if (out) OPENSSL_cleanse(out, QIHSE_CT1_RECOVERY_FRAME_BYTES);
    unsigned char wire[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    char name[QIHSE_CT1_ARCHIVE_ID_SIZE];
    if (!dir_ok(root) || !principal_ok(principal) || !expected || !id ||
        !qihse_ct1_recovery_encode(expected, false, false, wire) ||
        !archive_id(wire, name) || strcmp(id, name)) return false;
    char seal_name[QIHSE_CT1_ARCHIVE_ID_SIZE + 4];
    if (snprintf(seal_name, sizeof(seal_name), "%s.ok", name) >=
        (int)sizeof(seal_name)) return false;
    int fd = openat(root->dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat before, after, named;
    unsigned char *data = malloc(SIZE);
    bool ok = data && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
        before.st_uid == 0 && (before.st_mode & 07777) == 0400 &&
        before.st_nlink == 1 && before.st_size == SIZE;
    if (ok) {
        size_t total = 0;
        while (total < SIZE) {
            if (!principal_ok(principal)) { ok = false; break; }
            ssize_t n = read(fd, data + total, SIZE - total);
            if (n <= 0) { ok = false; break; }
            total += (size_t)n;
        }
    }
    unsigned char hash[32], original[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    if (ok) ok = !memcmp(data, magic, sizeof(magic)) && data[8] == 1 &&
        data[9] == 0 && data[10] == 0 && data[11] == 0 &&
        data[12] == (unsigned char)(SIZE >> 24) &&
        data[13] == (unsigned char)(SIZE >> 16) &&
        data[14] == (unsigned char)(SIZE >> 8) &&
        data[15] == (unsigned char)SIZE &&
        !CRYPTO_memcmp(data + B, wire, sizeof(wire)) &&
        SHA256(data, CHECKSUM, hash) && !CRYPTO_memcmp(hash, data + CHECKSUM, 32) &&
        !fstat(fd, &after) && !fstatat(root->dirfd, name, &named, AT_SYMLINK_NOFOLLOW) &&
        same_file(&before, &after) && same_file(&after, &named) &&
        checked_evidence(root, principal, expected, data + B,
            data + SOURCE_QUOTE, data + TARGET_QUOTE, data + FRAME) &&
        wal_original(root, principal, expected, original) &&
        !CRYPTO_memcmp(original, data + FRAME, sizeof(original));
    OPENSSL_cleanse(original, sizeof(original));
    if (ok) {
        int seal = openat(root->dirfd, seal_name,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat first, last, on_disk;
        unsigned char record[40], digest[32];
        ok = seal >= 0 && !fstat(seal, &first) && S_ISREG(first.st_mode) &&
            first.st_uid == 0 && (first.st_mode & 07777) == 0400 &&
            first.st_nlink == 1 && first.st_size == sizeof(record) &&
            read(seal, record, sizeof(record)) == sizeof(record) &&
            !memcmp(record, "CT1S\1\0\0\0", 8) &&
            SHA256(data, SIZE, digest) && !CRYPTO_memcmp(record + 8, digest, 32) &&
            !fstat(seal, &last) &&
            !fstatat(root->dirfd, seal_name, &on_disk, AT_SYMLINK_NOFOLLOW) &&
            same_file(&first, &last) && same_file(&last, &on_disk);
        if (seal >= 0 && close(seal)) ok = false;
    }
    if (close(fd)) ok = false;
    ok = ok && dir_ok(root) && principal_ok(principal);
    if (ok && out) memcpy(out, data + FRAME, QIHSE_CT1_RECOVERY_FRAME_BYTES);
    if (data) { OPENSSL_cleanse(data, SIZE); free(data); }
    return ok;
}

bool qihse_ct1_archive_verify(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *id)
{
    return archive_verify_read(root, principal, expected, id, NULL);
}

bool qihse_ct1_archive_read_source_root(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const char *archive_id,
    unsigned char out[QIHSE_CT1_RECOVERY_FRAME_BYTES])
{
    return out && archive_verify_read(root, principal, expected, archive_id, out);
}

bool qihse_ct1_archive_write_root(const qihse_ct1_archive_root_t *root,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *expected,
    const unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE],
    const unsigned char source_quote[QIHSE_CT1_NODE_QUOTE_SIZE],
    const unsigned char target_quote[QIHSE_CT1_NODE_QUOTE_SIZE],
    char id[QIHSE_CT1_ARCHIVE_ID_SIZE])
{
    if (id) id[0] = 0;
    unsigned char original[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    if (!id || !canonical || !source_quote || !target_quote ||
        !dir_ok(root) || !expected ||
        !wal_original(root, principal, expected, original)) return false;
    if (!checked_evidence(root, principal, expected, canonical,
            source_quote, target_quote, original)) {
        OPENSSL_cleanse(original, sizeof(original));
        return false;
    }
    char name[QIHSE_CT1_ARCHIVE_ID_SIZE];
    if (!archive_id(canonical, name)) {
        OPENSSL_cleanse(original, sizeof(original));
        return false;
    }
    unsigned char *data = calloc(1, SIZE);
    if (!data) {
        OPENSSL_cleanse(original, sizeof(original));
        return false;
    }
    memcpy(data, magic, sizeof(magic));
    data[8] = 1;
    data[12] = (unsigned char)(SIZE >> 24);
    data[13] = (unsigned char)(SIZE >> 16);
    data[14] = (unsigned char)(SIZE >> 8);
    data[15] = (unsigned char)SIZE;
    memcpy(data + B, canonical, QIHSE_CT1_RECOVERY_WIRE_SIZE);
    memcpy(data + SOURCE_QUOTE, source_quote, QIHSE_CT1_NODE_QUOTE_SIZE);
    memcpy(data + TARGET_QUOTE, target_quote, QIHSE_CT1_NODE_QUOTE_SIZE);
    memcpy(data + FRAME, original, sizeof(original));
    OPENSSL_cleanse(original, sizeof(original));
    bool ok = SHA256(data, CHECKSUM, data + CHECKSUM) != NULL &&
        principal_ok(principal);
    int fd = ok ? openat(root->dirfd, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    if (fd >= 0) {
        archive_cut("create");
        ok = write_all(fd, data, SIZE) && fchmod(fd, 0400) == 0;
        archive_cut("write");
        if (ok) ok = fsync(fd) == 0;
        archive_cut("file-sync");
        if (close(fd)) ok = false;
        if (ok) ok = fsync(root->dirfd) == 0;
        archive_cut("dir-sync");
        int check = ok ? openat(root->dirfd, name,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) : -1;
        struct stat before, after, named;
        unsigned char *reopened = malloc(SIZE);
        ok = check >= 0 && reopened && !fstat(check, &before) &&
            S_ISREG(before.st_mode) && before.st_uid == 0 &&
            (before.st_mode & 07777) == 0400 && before.st_nlink == 1 &&
            before.st_size == SIZE;
        size_t total = 0;
        while (ok && total < SIZE) {
            if (!principal_ok(principal)) { ok = false; break; }
            ssize_t n = read(check, reopened + total, SIZE - total);
            if (n <= 0) ok = false;
            else total += (size_t)n;
        }
        if (ok) ok = !CRYPTO_memcmp(reopened, data, SIZE) &&
            !fstat(check, &after) &&
            !fstatat(root->dirfd, name, &named, AT_SYMLINK_NOFOLLOW) &&
            same_file(&before, &after) && same_file(&after, &named);
        if (reopened) { OPENSSL_cleanse(reopened, SIZE); free(reopened); }
        if (check >= 0 && close(check)) ok = false;
        archive_cut("reopen");
        char seal_name[QIHSE_CT1_ARCHIVE_ID_SIZE + 4];
        unsigned char seal[40] = {'C','T','1','S',0,0,0,0};
        if (ok) ok = snprintf(seal_name, sizeof(seal_name), "%s.ok", name) <
            (int)sizeof(seal_name) && SHA256(data, SIZE, seal + 8) != NULL;
        if (ok) ok = principal_ok(principal);
        int committed = ok ? openat(root->dirfd, seal_name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
        ok = committed >= 0;
        if (committed >= 0) {
            ok = write_all(committed, seal, sizeof(seal)) &&
                fsync(committed) == 0 && fsync(root->dirfd) == 0;
            archive_cut("seal-file");
            const unsigned char committed_version = 1;
            if (ok) ok = pwrite(committed, &committed_version, 1, 4) == 1 &&
                fchmod(committed, 0400) == 0 && fsync(committed) == 0;
            archive_cut("seal-commit");
            if (close(committed)) ok = false;
            if (ok) ok = qihse_ct1_archive_verify(root, principal, expected, name);
        }
    } else ok = false;
    OPENSSL_cleanse(data, SIZE);
    free(data);
    if (ok) memcpy(id, name, sizeof(name));
    return ok;
}
