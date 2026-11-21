#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_ct1_receiver_writer.h"
#include "qihse_ct_codec.h"
#include "qihse_kv_store.h"
#include "qihse_cluster_ownership_journal.h"

#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef QIHSE_CT1_TEST_CRASH_CUT
extern void qihse_ct1_receiver_test_before_recheck(void) __attribute__((weak));
#endif

/* QCTST005 uses the native scalar disk layout; fail closed on older magic.
 * This is read-only: a cold KV reopen may repair state and is not a preflight. */
typedef struct {
    char magic[8];
    uint8_t mode, fence_state;
    uint16_t fence_first, fence_last;
    uint32_t tenant_id, tenant_policy;
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
    uint64_t transfer_source_cut, transfer_target_position;
    unsigned char transfer_image_digest[32], transfer_group_digest[32];
    unsigned char transfer_range_digest[32];
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char last_group_digest[32];
    unsigned char moved_slots[QIHSE_CLUSTER_SLOT_COUNT / 8u];
    uint64_t transfer_base_change_seq, transfer_applied_records;
    uint8_t transfer_chunked;
    uint64_t checksum;
} receiver_state_t;

static uint64_t state_checksum(const receiver_state_t *state)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    const unsigned char *bytes = (const unsigned char *)state;
    for (size_t i = 0; i < offsetof(receiver_state_t, checksum); ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static bool same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static bool regular_pinned(int dirfd, const char *name, int fd, struct stat *saved)
{
    struct stat named;
    return fstat(fd, saved) == 0 && S_ISREG(saved->st_mode) &&
        saved->st_uid == 0 && saved->st_nlink == 1 &&
        ((saved->st_mode & 07777) == 0400 || (saved->st_mode & 07777) == 0600) &&
        fstatat(dirfd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_file(saved, &named);
}

static bool still_pinned(int dirfd, const char *name, int fd, const struct stat *saved)
{
    struct stat current, named;
    return fstat(fd, &current) == 0 &&
        fstatat(dirfd, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_file(saved, &current) && same_file(saved, &named);
}

static bool directory_pinned(int dirfd, const char *path, const struct stat *saved)
{
    struct stat current, named;
    int reopened = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool ok = reopened >= 0 && fstat(dirfd, &current) == 0 &&
        fstat(reopened, &named) == 0 && same_file(saved, &current) &&
        same_file(saved, &named);
    if (reopened >= 0) close(reopened);
    return ok;
}

static bool full_service(const qihse_user_t *principal)
{
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    if (principal) qihse_auth_user_active_and_tenant(principal, &active, &tenant);
    return geteuid() == 0 && active && tenant == QIHSE_TENANT_SYSTEM &&
        qihse_user_get_classification(principal) == UINT16_MAX &&
        qihse_user_get_sci(principal) == UINT16_MAX &&
        qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX);
}

#ifdef QIHSE_CT1_TEST_CRASH_CUT
static void fresh_cut(const char *phase)
{
    const char *cut = getenv("QIHSE_CT1_RECEIVER_FRESH_CUT");
    if (cut && !strcmp(cut, phase)) _exit(86);
}
#else
static void fresh_cut(const char *phase) { (void)phase; }
#endif

bool qihse_ct1_receiver_fresh_pinned(int dirfd, const char *destination,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *m,
    const struct stat pins[QIHSE_CT1_RECOVERY_TARGET_FILES])
{
    struct stat directory;
    if (!pins || !m || !full_service(principal) || dirfd < 0 ||
        !destination || fstat(dirfd, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != 0 || (directory.st_mode & 07777) != 0700 ||
        !directory_pinned(dirfd, destination, &directory)) return false;
    for (size_t i = 0; i < QIHSE_CT1_RECOVERY_TARGET_FILES; ++i) {
        const char *name = m->target_files[i].filename;
        int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat found;
        bool ok = fd >= 0 && regular_pinned(dirfd, name, fd, &found) &&
            (found.st_mode & 07777) == 0400 && same_file(&pins[i], &found);
        if (fd >= 0 && close(fd)) ok = false;
        if (!ok) return false;
    }
    return qihse_ct1_recovery_verify_frozen(principal, destination, m, false) &&
        directory_pinned(dirfd, destination, &directory);
}

bool qihse_ct1_receiver_fresh_provision(int parentfd, const char *basename,
    const char *source, const char *destination, const qihse_user_t *principal,
    const qihse_ct1_recovery_manifest_t *m, int *dirfd,
    struct stat pins[QIHSE_CT1_RECOVERY_TARGET_FILES])
{
    struct stat parent, absent;
    if (!dirfd || !pins || !m || !basename || !*basename ||
        !strcmp(basename, ".") || !strcmp(basename, "..") ||
        strchr(basename, '/') || !source || !destination ||
        !full_service(principal) || fstat(parentfd, &parent) ||
        !S_ISDIR(parent.st_mode) || parent.st_uid != 0 ||
        (parent.st_mode & 07777) != 0700 ||
        !qihse_ct1_recovery_verify_frozen(principal, source, m, false) ||
        fstatat(parentfd, basename, &absent, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT || mkdirat(parentfd, basename, 0700)) return false;
    *dirfd = -1;
    fresh_cut("mkdir");
    int dest = openat(parentfd, basename,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int srcdir = open(source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat created, named;
    bool ok = dest >= 0 && srcdir >= 0 && fstat(dest, &created) == 0 &&
        S_ISDIR(created.st_mode) && created.st_uid == 0 &&
        (created.st_mode & 07777) == 0700 &&
        fstatat(parentfd, basename, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        created.st_dev == named.st_dev && created.st_ino == named.st_ino &&
        fsync(parentfd) == 0;
    for (size_t i = 0; ok && i < QIHSE_CT1_RECOVERY_TARGET_FILES; ++i) {
        const qihse_ct1_recovery_file_t *file = &m->target_files[i];
        int src = openat(srcdir, file->filename,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat before, after;
        ok = src >= 0 && regular_pinned(srcdir, file->filename, src, &before) &&
            before.st_size >= 0 && (uint64_t)before.st_size == file->size &&
            full_service(principal);
        int dst = ok ? openat(dest, file->filename,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
        ok = ok && dst >= 0 && regular_pinned(dest, file->filename, dst, &after) &&
            after.st_size == 0 && (after.st_mode & 07777) == 0600 &&
            (before.st_dev != after.st_dev || before.st_ino != after.st_ino);
        EVP_MD_CTX *hash = ok ? EVP_MD_CTX_new() : NULL;
        ok = ok && hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1;
        unsigned char block[16384], digest[32];
        uint64_t total = 0;
        while (ok && total < file->size) {
            size_t want = file->size - total < sizeof(block) ?
                (size_t)(file->size - total) : sizeof(block);
            ssize_t n = read(src, block, want);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || !full_service(principal) ||
                EVP_DigestUpdate(hash, block, (size_t)n) != 1) { ok = false; break; }
            size_t written = 0;
            while (written < (size_t)n) {
                ssize_t w = write(dst, block + written, (size_t)n - written);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { ok = false; break; }
                written += (size_t)w;
            }
            total += (uint64_t)n;
        }
        OPENSSL_cleanse(block, sizeof(block));
        unsigned length = 0;
        if (ok) ok = read(src, digest, 1) == 0 &&
            EVP_DigestFinal_ex(hash, digest, &length) == 1 && length == 32 &&
            !memcmp(digest, file->sha256, 32) &&
            still_pinned(srcdir, file->filename, src, &before) &&
            fchmod(dst, 0400) == 0 && fsync(dst) == 0 &&
            regular_pinned(dest, file->filename, dst, &after) &&
            (after.st_mode & 07777) == 0400 &&
            after.st_size >= 0 && (uint64_t)after.st_size == file->size;
        if (ok) pins[i] = after;
        EVP_MD_CTX_free(hash);
        if (src >= 0 && close(src)) ok = false;
        if (dst >= 0 && close(dst)) ok = false;
        if (ok) fresh_cut("file");
    }
    if (ok) ok = fsync(dest) == 0 &&
        qihse_ct1_recovery_verify_frozen(principal, source, m, false) &&
        qihse_ct1_receiver_fresh_pinned(dest, destination, principal, m, pins) &&
        fstatat(parentfd, basename, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        created.st_dev == named.st_dev && created.st_ino == named.st_ino &&
        fsync(parentfd) == 0 && full_service(principal);
    if (srcdir >= 0 && close(srcdir)) ok = false;
    if (!ok) { if (dest >= 0) close(dest); return false; }
    *dirfd = dest;
    return true;
}

/* The host pins the path and holds the stable directory flock, excluding
 * new receiver handles with a lifetime lease. V3 is deliberately denied;
 * V5 prevents old binaries from cold-opening state, but cannot fence an old
 * handle opened before conversion. The protected writer remains disabled. */
bool qihse_ct1_receiver_preflight_locked(int dirfd, const char *path,
    const qihse_user_t *principal, const qihse_ct1_recovery_manifest_t *m)
{
    bool active = false;
    uint32_t tenant = QIHSE_TENANT_INVALID;
    if (principal) qihse_auth_user_active_and_tenant(principal, &active, &tenant);
    if (geteuid() != 0 || dirfd < 0 || !path || !m || !active ||
        tenant != QIHSE_TENANT_SYSTEM ||
        qihse_user_get_classification(principal) != UINT16_MAX ||
        qihse_user_get_sci(principal) != UINT16_MAX ||
        !qihse_auth_can_access(principal, UINT16_MAX, UINT16_MAX)) return false;
    struct stat directory;
    if (fstat(dirfd, &directory) || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != 0 || (directory.st_mode & 07777) != 0700 ||
        !directory_pinned(dirfd, path, &directory) ||
        !qihse_ct1_recovery_verify_frozen(principal, path, m, false)) return false;

    int statefd = openat(dirfd, "ct-state.bin", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int walfd = openat(dirfd, "wal.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat state_stat = {0}, wal_stat = {0};
    receiver_state_t state = {0};
    bool ok = statefd >= 0 && walfd >= 0 &&
        regular_pinned(dirfd, "ct-state.bin", statefd, &state_stat) &&
        regular_pinned(dirfd, "wal.log", walfd, &wal_stat) &&
        state_stat.st_size == (off_t)sizeof(state) && wal_stat.st_size > 0 &&
        read(statefd, &state, sizeof(state)) == (ssize_t)sizeof(state) &&
        !memcmp(state.magic, "QCTST005", 8) && state.checksum == state_checksum(&state) &&
        state.mode == 2 && state.fence_state == 0 && state.transfer_phase == 0 &&
        state.baseline_sealed == 1 && state.baseline_lsn == m->baseline_row_seq &&
        !memcmp(state.baseline_digest, m->baseline_sha256, 32) &&
        state.durable_lsn == m->target_cursor && state.durable_lsn > m->tombstone_position &&
        state.retained_bytes == (uint64_t)wal_stat.st_size &&
        state.tenant_policy == QIHSE_KV_CT_TENANT_SYSTEM_ALL && state.tenant_id == 0 &&
        memchr(state.source_id, 0, sizeof(state.source_id)) &&
        memchr(state.target_id, 0, sizeof(state.target_id)) &&
        memchr(state.generation, 0, sizeof(state.generation)) &&
        !strcmp(state.source_id, m->source_store_id) &&
        !strcmp(state.target_id, m->target_store_id) &&
        !strcmp(state.generation, m->generation);
    /* The canonical complete roster excludes rotated WALs, recovery fences,
     * state sidecars and any other extra entry, including hidden ones. */
    FILE *wal = NULL;
    if (ok) {
        wal = fdopen(walfd, "rb");
        if (wal) walfd = -1;
        ok = wal && setvbuf(wal, NULL, _IONBF, 0) == 0;
    }
    char key[QIHSE_CT1_RECOVERY_ID_MAX + 32];
    int key_len = m->row_tenant_id ? snprintf(key, sizeof(key), "t:%u/%s",
        m->row_tenant_id, m->row_key) :
        snprintf(key, sizeof(key), "commons/%s", m->row_key);
    ok = ok && key_len > 0 && (size_t)key_len < sizeof(key);
    uint64_t matched_position = 0, matched_seq = 0, highest_seq = 0;
    for (uint64_t position = 1; ok && position <= m->target_cursor; ++position) {
        qihse_kv_ct_group_t group = {0};
        uint8_t mode = 0;
        size_t bytes = 0;
        int rc = qihse_ct_codec_read(wal, (qihse_user_t *)principal,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, QIHSE_CT_CODEC_MAX_FRAME,
            &group, &mode, &bytes);
        ok = rc == 1 && bytes && mode == QIHSE_CT_CODEC_MODE_RECEIVER &&
            group.stream_position == position &&
            !strcmp(group.source_id, m->source_store_id) &&
            !strcmp(group.generation, m->generation) &&
            group.last_seq <= m->target_high_water;
        if (ok) {
            if (group.last_seq > highest_seq) highest_seq = group.last_seq;
            for (size_t i = 0; i < group.count; ++i) {
                const qihse_kv_ct_record_t *row = &group.records[i];
                if (strcmp(row->key, key)) continue;
                matched_position = matched_seq = 0;
                if (row->tombstone && row->actor_kind != QIHSE_KV_CT_ACTOR_REPLICA &&
                    row->resource_tenant_id == m->row_tenant_id &&
                    row->classification == m->classification &&
                    row->sci_compartment == m->sci &&
                    row->change_seq == m->tombstone_row_seq) {
                    matched_position = group.stream_position;
                    matched_seq = row->change_seq;
                }
            }
        }
        if (ok && position == m->target_cursor) {
            unsigned char digest[32];
            ok = qihse_ct_codec_group_digest((qihse_user_t *)principal,
                QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, &group, digest) &&
                !memcmp(digest, state.last_group_digest, sizeof(digest));
        }
        qihse_ct_codec_clear(&group);
    }
#ifdef QIHSE_CT1_TEST_CRASH_CUT
    if (ok && qihse_ct1_receiver_test_before_recheck)
        qihse_ct1_receiver_test_before_recheck();
#endif
    if (ok) ok = matched_position == m->tombstone_position &&
        matched_seq == m->tombstone_row_seq && highest_seq <= m->target_high_water &&
        fgetc(wal) == EOF && !ferror(wal) &&
        ftello(wal) == wal_stat.st_size &&
        still_pinned(dirfd, "wal.log", fileno(wal), &wal_stat);
    if (wal && fclose(wal)) ok = false;
    if (walfd >= 0 && close(walfd)) ok = false;
    if (statefd >= 0) {
        if (!ok || !still_pinned(dirfd, "ct-state.bin", statefd, &state_stat)) ok = false;
        if (close(statefd)) ok = false;
    }
    OPENSSL_cleanse(&state, sizeof(state));
    return ok && directory_pinned(dirfd, path, &directory) &&
        qihse_ct1_recovery_verify_frozen(principal, path, m, false) &&
        directory_pinned(dirfd, path, &directory);
}
