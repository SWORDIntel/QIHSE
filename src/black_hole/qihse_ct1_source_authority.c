#include "qihse_ct1_source_authority.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static bool principals_ok(const qihse_user_t *operator_user,
    const qihse_user_t *service, uint32_t configured_id)
{
    bool operator_active = false, service_active = false;
    uint32_t operator_tenant = QIHSE_TENANT_INVALID;
    uint32_t service_tenant = QIHSE_TENANT_INVALID;
    if (!operator_user || !service || !configured_id) return false;
    qihse_auth_user_active_and_tenant(operator_user, &operator_active, &operator_tenant);
    qihse_auth_user_active_and_tenant(service, &service_active, &service_tenant);
    return operator_active && service_active &&
        operator_tenant == QIHSE_TENANT_SYSTEM &&
        service_tenant == QIHSE_TENANT_SYSTEM &&
        qihse_user_get_role(operator_user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_role(service) != QIHSE_ROLE_OPERATOR &&
        qihse_user_get_id(operator_user) != configured_id &&
        qihse_user_get_id(service) == configured_id &&
        qihse_user_get_classification(service) == UINT16_MAX &&
        qihse_user_get_sci(service) == UINT16_MAX &&
        qihse_auth_can_access(service, UINT16_MAX, UINT16_MAX);
}

static uint64_t be64(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}

static bool same_inode(const struct stat *a, const struct stat *b);

static bool physical_frame_matches(int dir, const qihse_user_t *operator_user,
    const qihse_user_t *service, uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected)
{
    const qihse_ct1_recovery_file_t *wal = NULL;
    struct stat before, after, named;
    unsigned char frame[QIHSE_CT1_RECOVERY_FRAME_BYTES];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    bool ok = false;
    int fd = -1, reopened = -1;

    if (!principals_ok(operator_user, service, configured_service_id) ||
        expected->frame_position != 11111u ||
        expected->frame_length != sizeof(frame) ||
        expected->frame_offset > INT64_MAX ||
        expected->frame_length > (uint64_t)INT64_MAX - expected->frame_offset)
        return false;
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_SOURCE_FILES; ++i)
        if (!strcmp(expected->source_files[i].filename, "wal.log") &&
            expected->source_files[i].kind == QIHSE_CT1_FILE_WAL)
            wal = &expected->source_files[i];
    if (!wal || expected->frame_offset + expected->frame_length > wal->size)
        return false;
    fd = openat(dir, "wal.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || before.st_nlink != 1 ||
        ((before.st_mode & 07777) != 0600 &&
         (before.st_mode & 07777) != 0400) ||
        before.st_size < 0 || (uint64_t)before.st_size != wal->size)
        goto done;
    if (!principals_ok(operator_user, service, configured_service_id) ||
        pread(fd, frame, sizeof(frame), (off_t)expected->frame_offset) !=
            (ssize_t)sizeof(frame) ||
        !principals_ok(operator_user, service, configured_service_id) ||
        memcmp(frame, "QKV6CT01", 8) || frame[8] != 1u ||
        be64(frame + 32) != 11111u ||
        be64(frame + 40) != expected->row_change_seq ||
        be64(frame + 48) != expected->row_change_seq ||
        !frame[56] || !frame[57] ||
        (size_t)frame[56] + frame[57] > sizeof(frame) - 96u ||
        strlen(expected->source_store_id) != frame[56] ||
        memcmp(frame + 96, expected->source_store_id, frame[56]) ||
        strlen(expected->generation) != frame[57] ||
        memcmp(frame + 96 + frame[56], expected->generation, frame[57]) ||
        !SHA256(frame, sizeof(frame), digest) ||
        CRYPTO_memcmp(digest, expected->frame_sha256, sizeof(digest))) goto done;
    reopened = openat(dir, "wal.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (reopened < 0 || fstat(reopened, &named) || fstat(fd, &after) ||
        !same_inode(&before, &after) || !same_inode(&after, &named) ||
        !principals_ok(operator_user, service, configured_service_id))
        goto done;
    ok = true;
done:
    OPENSSL_cleanse(frame, sizeof(frame));
    OPENSSL_cleanse(digest, sizeof(digest));
    if (reopened >= 0 && close(reopened)) ok = false;
    if (fd >= 0 && close(fd)) ok = false;
    return ok;
}

static bool same_inode(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

/* Descriptor-only traversal rejects aliases and symlinks. This path is a
 * root-provisioned ORIGINAL, not a caller's archive or frozen working copy. */
static int open_original(const char *path)
{
    int fd, next;
    struct stat st;
    const char *p;
    if (!path || path[0] != '/' || strnlen(path, PATH_MAX) >= PATH_MAX)
        return -1;
    fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    p = path + 1;
    if (!*p) goto fail;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t length = slash ? (size_t)(slash - p) : strlen(p);
        char component[256];
        if (!length || length > 255 || (length == 1 && p[0] == '.') ||
            (length == 2 && p[0] == '.' && p[1] == '.') ||
            (slash && !slash[1]) || fstat(fd, &st) ||
            !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
            ((st.st_mode & 0022) && !(st.st_mode & S_ISVTX))) goto fail;
        memcpy(component, p, length);
        component[length] = 0;
        next = openat(fd, component, O_RDONLY | O_DIRECTORY |
            O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (next < 0) goto fail;
        close(fd);
        fd = next;
        p = slash ? slash + 1 : p + length;
    }
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 07777) != 0700) goto fail;
    return fd;
fail:
    close(fd);
    return -1;
}

bool qihse_ct1_source_authority_probe_offline(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const qihse_user_t *operator_user, const qihse_user_t *service,
    uint32_t configured_service_id, const qihse_ct1_recovery_manifest_t *expected)
{
    struct stat before, after;
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    bool ok = false;
    int dir = -1;
    char service_id[32];
    int n;

    if (geteuid() != 0 || !original_dev || !original_ino || !expected ||
        !principals_ok(operator_user, service, configured_service_id) ||
        expected->frame_position != 11111u ||
        expected->frame_length != QIHSE_CT1_RECOVERY_FRAME_BYTES ||
        expected->frame_offset > INT64_MAX ||
        expected->frame_length > (uint64_t)INT64_MAX - expected->frame_offset ||
        !qihse_ct1_recovery_encode(expected, false, false, canonical))
        return false;
    n = snprintf(service_id, sizeof(service_id), "%u", configured_service_id);
    if (n <= 0 || (size_t)n >= sizeof(service_id) ||
        strcmp(expected->replication_principal_id, service_id) ||
        expected->principal_tenant_id != QIHSE_TENANT_SYSTEM ||
        expected->principal_classification != UINT16_MAX ||
        expected->principal_sci != UINT16_MAX) return false;
    dir = open_original(original_dir);
    if (dir < 0 || flock(dir, LOCK_EX | LOCK_NB) || fstat(dir, &before) ||
        before.st_dev != original_dev || before.st_ino != original_ino)
        goto done;
    /* The roster is read with the configured, active full-clearance context.
     * Flock does not exclude stale B-UID descriptors or non-participating code. */
    if (!qihse_ct1_recovery_verify_frozen(service, original_dir, expected, true) ||
        !principals_ok(operator_user, service, configured_service_id)) goto done;
    if (!physical_frame_matches(dir, operator_user, service,
            configured_service_id, expected) ||
        fstat(dir, &after) || !same_inode(&before, &after) ||
        !principals_ok(operator_user, service, configured_service_id)) goto done;
    /* The original name must still designate the pinned directory. */
    {
        int current = open_original(original_dir);
        if (current >= 0) {
            struct stat current_st;
            ok = !fstat(current, &current_st) && same_inode(&after, &current_st);
            if (close(current)) ok = false;
        }
    }
done:
    if (dir >= 0 && close(dir)) ok = false;
    return ok;
}

static bool stage_one(int source, int stage, const qihse_ct1_recovery_file_t *file,
    const qihse_user_t *operator_user, const qihse_user_t *service,
    uint32_t service_id)
{
    struct stat before, after, named, copied;
    unsigned char block[16384], digest[SHA256_DIGEST_LENGTH];
    unsigned digest_len = 0;
    EVP_MD_CTX *hash = NULL;
    uint64_t remaining = file->size;
    bool ok = false;
    int in = -1, out = -1;

    if (!principals_ok(operator_user, service, service_id)) return false;
    in = openat(source, file->filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (in < 0 || fstat(in, &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || before.st_nlink != 1 ||
        ((before.st_mode & 07777) != 0600 && (before.st_mode & 07777) != 0400) ||
        before.st_size < 0 || (uint64_t)before.st_size != file->size) goto done;
    out = openat(stage, file->filename, O_WRONLY | O_CREAT | O_EXCL |
        O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0 || fstat(out, &copied) || !S_ISREG(copied.st_mode) ||
        copied.st_uid != 0 || copied.st_nlink != 1 ||
        (copied.st_mode & 07777) != 0600 ||
        (copied.st_dev == before.st_dev && copied.st_ino == before.st_ino)) goto done;
    hash = EVP_MD_CTX_new();
    if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1) goto done;
    while (remaining) {
        size_t want = remaining < sizeof(block) ? (size_t)remaining : sizeof(block);
        ssize_t n;
        if (!principals_ok(operator_user, service, service_id)) goto done;
        n = read(in, block, want);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || (size_t)n > want ||
            EVP_DigestUpdate(hash, block, (size_t)n) != 1) goto done;
        for (ssize_t offset = 0; offset < n;) {
            ssize_t written = write(out, block + offset, (size_t)(n - offset));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) goto done;
            offset += written;
        }
        remaining -= (uint64_t)n;
    }
    if (EVP_DigestFinal_ex(hash, digest, &digest_len) != 1 ||
        digest_len != sizeof(digest) ||
        CRYPTO_memcmp(digest, file->sha256, sizeof(digest)) ||
        fstat(in, &after) || !same_inode(&before, &after) ||
        fstatat(source, file->filename, &named, AT_SYMLINK_NOFOLLOW) ||
        !same_inode(&after, &named) ||
        fsync(out) || fstat(out, &copied) ||
        copied.st_size < 0 || (uint64_t)copied.st_size != file->size ||
        copied.st_uid != 0 || copied.st_nlink != 1 ||
        (copied.st_mode & 07777) != 0600 ||
        (copied.st_dev == before.st_dev && copied.st_ino == before.st_ino) ||
        !principals_ok(operator_user, service, service_id)) goto done;
    ok = true;
done:
    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_cleanse(digest, sizeof(digest));
    EVP_MD_CTX_free(hash);
    if (out >= 0 && close(out)) ok = false;
    if (in >= 0 && close(in)) ok = false;
    return ok;
}

bool qihse_ct1_source_authority_stage_offline(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const char *staging_parent, dev_t parent_dev, ino_t parent_ino,
    const char *staging_name, const qihse_user_t *operator_user,
    const qihse_user_t *service, uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected)
{
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    struct stat source_st, source_after, parent_st, stage_st, named;
    char stage_path[PATH_MAX];
    bool ok = false;
    int source = -1, parent = -1, stage = -1, reopened = -1;
    size_t length;

    if (geteuid() != 0 || !original_dev || !original_ino ||
        !parent_dev || !parent_ino || !expected || !staging_parent ||
        !staging_name || !(length = strlen(staging_name)) || length > 255 ||
        strchr(staging_name, '/') || !strcmp(staging_name, ".") ||
        !strcmp(staging_name, "..") ||
        snprintf(stage_path, sizeof(stage_path), "%s/%s", staging_parent,
            staging_name) <= 0 ||
        strlen(stage_path) >= sizeof(stage_path) - 1 ||
        !qihse_ct1_recovery_encode(expected, false, false, canonical) ||
        !qihse_ct1_source_authority_probe_offline(original_dir, original_dev,
            original_ino, operator_user, service, configured_service_id, expected))
        return false;
    source = open_original(original_dir);
    parent = open_original(staging_parent);
    if (source < 0 || parent < 0 ||
        flock(source, LOCK_EX | LOCK_NB) ||
        fstat(source, &source_st) || fstat(parent, &parent_st) ||
        source_st.st_dev != original_dev || source_st.st_ino != original_ino ||
        parent_st.st_dev != parent_dev || parent_st.st_ino != parent_ino ||
        (source_st.st_dev == parent_st.st_dev &&
         source_st.st_ino == parent_st.st_ino) ||
        !qihse_ct1_recovery_verify_frozen(service, original_dir, expected, true) ||
        !principals_ok(operator_user, service, configured_service_id)) goto done;
    if (mkdirat(parent, staging_name, 0700)) goto done; /* never reuse a crash cut */
    stage = openat(parent, staging_name, O_RDONLY | O_DIRECTORY |
        O_NOFOLLOW | O_CLOEXEC);
    if (stage < 0 || fstat(stage, &stage_st) ||
        !S_ISDIR(stage_st.st_mode) || stage_st.st_uid != 0 ||
        (stage_st.st_mode & 07777) != 0700 ||
        (stage_st.st_dev == source_st.st_dev &&
         stage_st.st_ino == source_st.st_ino) ||
        fsync(parent)) goto done;
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_SOURCE_FILES; ++i)
        if (!stage_one(source, stage, &expected->source_files[i],
                operator_user, service, configured_service_id)) goto done;
    if (fsync(stage) || fsync(parent) ||
        fstat(stage, &stage_st) ||
        !qihse_ct1_recovery_verify_frozen(service, stage_path, expected, true) ||
        !physical_frame_matches(stage, operator_user, service,
            configured_service_id, expected) ||
        !qihse_ct1_recovery_verify_frozen(service, original_dir, expected, true) ||
        fstat(source, &source_after) || !same_inode(&source_st, &source_after) ||
        fstatat(parent, staging_name, &named, AT_SYMLINK_NOFOLLOW) ||
        !same_inode(&stage_st, &named) ||
        fstat(parent, &parent_st) || parent_st.st_dev != parent_dev ||
        parent_st.st_ino != parent_ino || parent_st.st_uid != 0 ||
        (parent_st.st_mode & 07777) != 0700) goto done;
    reopened = open_original(stage_path);
    if (reopened < 0 || fstat(reopened, &named) ||
        !same_inode(&stage_st, &named) ||
        !principals_ok(operator_user, service, configured_service_id)) goto done;
    ok = true;
done:
    if (reopened >= 0 && close(reopened)) ok = false;
    if (stage >= 0 && close(stage)) ok = false;
    if (parent >= 0 && close(parent)) ok = false;
    if (source >= 0 && close(source)) ok = false;
    /* The probe's flock is observational only; its release grants no hold. */
    if (ok) ok = qihse_ct1_source_authority_probe_offline(original_dir,
        original_dev, original_ino, operator_user, service,
        configured_service_id, expected);
    return ok;
}

bool qihse_ct1_source_authority_verify_stage_offline(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const char *staging_parent, dev_t parent_dev, ino_t parent_ino,
    const char *staging_name, dev_t staged_dev, ino_t staged_ino,
    const qihse_user_t *operator_user, const qihse_user_t *service,
    uint32_t configured_service_id, const qihse_ct1_recovery_manifest_t *expected)
{
    unsigned char canonical[QIHSE_CT1_RECOVERY_WIRE_SIZE];
    struct stat source_st, parent_st, stage_st, before, after, named, current;
    char stage_path[PATH_MAX];
    bool ok = false;
    int source = -1, parent = -1, stage = -1, file = -1, check = -1;
    size_t length;
    int n;

    if (geteuid() != 0 || !original_dev || !original_ino || !parent_dev ||
        !parent_ino || !staged_dev || !staged_ino || !staging_parent ||
        !staging_name || !(length = strnlen(staging_name, 256)) || length > 255 ||
        strchr(staging_name, '/') || !strcmp(staging_name, ".") ||
        !strcmp(staging_name, "..") || !expected ||
        !principals_ok(operator_user, service, configured_service_id) ||
        !qihse_ct1_recovery_encode(expected, false, false, canonical))
        return false;
    n = snprintf(stage_path, sizeof(stage_path), "%s/%s", staging_parent,
        staging_name);
    if (n <= 0 || (size_t)n >= sizeof(stage_path)) return false;
    source = open_original(original_dir);
    parent = open_original(staging_parent);
    stage = open_original(stage_path);
    if (source < 0 || parent < 0 || stage < 0 ||
        fstat(source, &source_st) || fstat(parent, &parent_st) ||
        fstat(stage, &stage_st) ||
        source_st.st_dev != original_dev || source_st.st_ino != original_ino ||
        parent_st.st_dev != parent_dev || parent_st.st_ino != parent_ino ||
        stage_st.st_dev != staged_dev || stage_st.st_ino != staged_ino ||
        (source_st.st_dev == parent_st.st_dev &&
         source_st.st_ino == parent_st.st_ino) ||
        (source_st.st_dev == stage_st.st_dev &&
         source_st.st_ino == stage_st.st_ino) ||
        (parent_st.st_dev == stage_st.st_dev &&
         parent_st.st_ino == stage_st.st_ino) ||
        !qihse_ct1_recovery_verify_frozen(service, stage_path, expected, true) ||
        !physical_frame_matches(stage, operator_user, service,
            configured_service_id, expected))
        goto done;
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_SOURCE_FILES; ++i) {
        const char *name = expected->source_files[i].filename;
        if (!principals_ok(operator_user, service, configured_service_id) ||
            fstatat(source, name, &before, AT_SYMLINK_NOFOLLOW) ||
            !S_ISREG(before.st_mode) || before.st_uid != 0 ||
            before.st_nlink != 1 ||
            ((before.st_mode & 07777) != 0600 &&
             (before.st_mode & 07777) != 0400)) goto done;
        file = openat(stage, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (file < 0 || fstat(file, &after) || !S_ISREG(after.st_mode) ||
            after.st_uid != 0 || after.st_nlink != 1 ||
            ((after.st_mode & 07777) != 0600 &&
             (after.st_mode & 07777) != 0400) ||
            (before.st_dev == after.st_dev && before.st_ino == after.st_ino) ||
            fsync(file) || fstat(file, &named) || !same_inode(&after, &named) ||
            fstatat(stage, name, &named, AT_SYMLINK_NOFOLLOW) ||
            !same_inode(&after, &named)) goto done;
        if (close(file)) { file = -1; goto done; }
        file = -1;
    }
    if (fsync(stage) || fsync(parent) ||
        !qihse_ct1_recovery_verify_frozen(service, stage_path, expected, true) ||
        !physical_frame_matches(stage, operator_user, service,
            configured_service_id, expected) ||
        fstat(stage, &after) || !same_inode(&stage_st, &after) ||
        fstatat(parent, staging_name, &named, AT_SYMLINK_NOFOLLOW) ||
        !same_inode(&stage_st, &named) ||
        fstat(source, &current) || current.st_dev != original_dev ||
        current.st_ino != original_ino ||
        fstat(parent, &current) || current.st_dev != parent_dev ||
        current.st_ino != parent_ino ||
        !principals_ok(operator_user, service, configured_service_id)) goto done;
    check = open_original(original_dir);
    if (check < 0 || fstat(check, &current) || current.st_dev != original_dev ||
        current.st_ino != original_ino) goto done;
    if (close(check)) { check = -1; goto done; }
    check = -1;
    check = open_original(stage_path);
    if (check < 0 || fstat(check, &current) || !same_inode(&stage_st, &current))
        goto done;
    ok = true;
done:
    if (check >= 0 && close(check)) ok = false;
    if (file >= 0 && close(file)) ok = false;
    if (stage >= 0 && close(stage)) ok = false;
    if (parent >= 0 && close(parent)) ok = false;
    if (source >= 0 && close(source)) ok = false;
    return ok;
}

struct qihse_ct1_source_fixture_lease {
    int dirfd;
};

qihse_ct1_source_fixture_lease_t *qihse_ct1_source_fixture_lease_acquire(
    const char *original_dir, dev_t original_dev, ino_t original_ino,
    const char *staging_parent, dev_t parent_dev, ino_t parent_ino,
    const char *fresh_name, const char *local_operator_password,
    uint32_t configured_service_id,
    const qihse_ct1_recovery_manifest_t *expected)
{
    qihse_ct1_source_fixture_lease_t *lease = NULL;
    qihse_user_t *operator_user, *service;
    struct stat parent_st, staged_st, named, current;
    char fresh_path[PATH_MAX];
    int parent = -1, dir = -1, n;

    if (geteuid() != 0 || !local_operator_password ||
        !*local_operator_password || !configured_service_id ||
        !staging_parent || !fresh_name || !expected ||
        !*fresh_name || strnlen(fresh_name, 256) > 255 ||
        strchr(fresh_name, '/') || !strcmp(fresh_name, ".") ||
        !strcmp(fresh_name, "..") ||
        qihse_auth_is_operator_password_default()) return NULL;
    n = snprintf(fresh_path, sizeof(fresh_path), "%s/%s",
        staging_parent, fresh_name);
    if (n <= 0 || (size_t)n >= sizeof(fresh_path)) return NULL;
    operator_user = qihse_auth_authenticate_id(0, local_operator_password);
    service = qihse_auth_get_user(configured_service_id);
    if (!principals_ok(operator_user, service, configured_service_id) ||
        !qihse_ct1_source_authority_stage_offline(original_dir, original_dev,
            original_ino, staging_parent, parent_dev, parent_ino, fresh_name,
            operator_user, service, configured_service_id, expected)) return NULL;

    parent = open_original(staging_parent);
    dir = open_original(fresh_path);
    if (parent < 0 || dir < 0 ||
        fstat(parent, &parent_st) || parent_st.st_dev != parent_dev ||
        parent_st.st_ino != parent_ino ||
        flock(dir, LOCK_EX | LOCK_NB) || fstat(dir, &staged_st) ||
        fstatat(parent, fresh_name, &named, AT_SYMLINK_NOFOLLOW) ||
        !same_inode(&staged_st, &named) ||
        !qihse_ct1_source_authority_verify_stage_offline(original_dir,
            original_dev, original_ino, staging_parent, parent_dev, parent_ino,
            fresh_name, staged_st.st_dev, staged_st.st_ino,
            operator_user, service, configured_service_id, expected) ||
        !qihse_ct1_source_authority_probe_offline(original_dir, original_dev,
            original_ino, operator_user, service, configured_service_id, expected) ||
        fstat(dir, &current) || !same_inode(&staged_st, &current) ||
        fstatat(parent, fresh_name, &named, AT_SYMLINK_NOFOLLOW) ||
        !same_inode(&current, &named) ||
        !principals_ok(operator_user, service, configured_service_id)) goto done;
    lease = calloc(1, sizeof(*lease));
    if (lease) { lease->dirfd = dir; dir = -1; }
done:
    if (dir >= 0) close(dir);
    if (parent >= 0 && close(parent) && lease) {
        close(lease->dirfd);
        free(lease);
        lease = NULL;
    }
    return lease;
}

void qihse_ct1_source_fixture_lease_destroy(qihse_ct1_source_fixture_lease_t *lease)
{
    if (!lease) return;
    close(lease->dirfd);
    free(lease);
}
