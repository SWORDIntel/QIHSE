/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_generation_adapter.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool active(qihse_user_t *user) {
    return user && qihse_auth_user_is_active(user) && qihse_auth_can_access(user, 0, 0);
}
static int temporary(const char *directory, char path[PATH_MAX]) {
    int fd = directory ? open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    struct stat st;
    bool ok = fd >= 0 && !fstat(fd, &st) && S_ISDIR(st.st_mode) &&
              st.st_uid == geteuid() && !(st.st_mode & 077);
    if (fd >= 0) close(fd);
    if (!ok || snprintf(path, PATH_MAX, "%s/.generation-XXXXXX", directory) >= PATH_MAX) {
        errno = EACCES; return -1;
    }
    return mkstemp(path);
}
static bool unchanged(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
bool cg_generation_path_user(const char *path, qihse_user_t *user) {
    if (!path || !active(user)) { errno = EACCES; return false; }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat st;
    char magic[8];
    bool result = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        !(st.st_mode & 077) && st.st_nlink == 1 && read(fd, magic, sizeof(magic)) == sizeof(magic) &&
        !memcmp(magic, CG_GENERATION_MAGIC, sizeof(magic)) && active(user);
    close(fd);
    return result;
}
bool cg_generation_store_save_user(qihse_kv_store_t *store, const char *path,
    const char *scratch, const char *blocks, qihse_user_t *user, cg_generation_info *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!store || !path || !blocks || !active(user)) { errno = EACCES; return false; }
    char raw_path[PATH_MAX] = {0};
    FILE *input = NULL, *output = NULL;
    bool ok = false;
    int fd = temporary(scratch, raw_path);
    if (fd < 0) return false;
    close(fd);
    if (qihse_kv_save_user(store, raw_path, user)) goto done;
    fd = open(raw_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) goto done;
    input = fdopen(fd, "rb");
    if (!input) { close(fd); goto done; }
    fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) goto done;
    output = fdopen(fd, "w+b");
    if (!output) { close(fd); unlink(path); goto done; }
    ok = cg_generation_encode_snapshot(input, output, blocks, user,
        CG_GENERATION_MAX_RAW_BYTES, CG_GENERATION_MAX_RECORDS, out) &&
        !fflush(output) && !fsync(fileno(output)) && active(user);
done:
    if (input && fclose(input)) ok = false;
    if (output && fclose(output)) ok = false;
    if (raw_path[0]) unlink(raw_path);
    if (!ok) { if (output) unlink(path); if (out) memset(out, 0, sizeof(*out)); }
    return ok;
}
qihse_kv_store_t *cg_generation_store_open_user(const char *path,
    const char *scratch, const char *blocks, qihse_user_t *user,
    const cg_snapshot_checksum *expected, cg_storage_info_t *storage,
    cg_generation_info *generation) {
    if (storage) memset(storage, 0, sizeof(*storage));
    if (generation) memset(generation, 0, sizeof(*generation));
    if (!path || !blocks || !expected || !active(user)) { errno = EACCES; return NULL; }
    FILE *input = NULL, *raw = NULL;
    qihse_kv_store_t *store = NULL;
    char raw_path[PATH_MAX] = {0};
    struct stat before, after;
    cg_generation_info info;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return NULL;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != geteuid() ||
        (before.st_mode & 077) || before.st_nlink != 1 || before.st_size < 64) {
        close(fd); errno = EINVAL; return NULL;
    }
    input = fdopen(fd, "rb");
    if (!input) { close(fd); return NULL; }
    fd = temporary(scratch, raw_path);
    if (fd < 0) goto done;
    raw = fdopen(fd, "w+b");
    if (!raw) { close(fd); goto done; }
    /* Keep reconstructed bytes anonymous before writing any payload. A named
     * file could be replaced or modified between decoder and SDK consumption. */
    if (unlink(raw_path)) goto done;
    raw_path[0] = '\0';
    if (!cg_generation_decode_snapshot(input, raw, blocks, user, expected,
        CG_GENERATION_MAX_RAW_BYTES, CG_GENERATION_MAX_RECORDS, &info) ||
        fflush(raw) || fseeko(raw, 0, SEEK_SET)) goto done;
    /* The SDK accepts caller bounds; the generic reader's 64 MiB/150k policy
     * is not an SDK limit. Preserve descriptor identity for larger generations
     * too, instead of reopening a mutable staging pathname. The generation
     * codec caps both raw bytes and records before this bounded allocation. */
    store = qihse_kv_open_snapshot_user(raw, user, (size_t)info.raw_bytes + 1,
                                       (size_t)info.records + 1);
    if (store && (fstat(fileno(input), &after) || !unchanged(&before, &after) || !active(user))) {
        qihse_kv_store_destroy(store); store = NULL; errno = EIO;
    }
    if (store && storage) {
        storage->encoded_bytes = (uint64_t)before.st_size;
        storage->allocated_bytes = (uint64_t)before.st_blocks * 512u;
        storage->decoded_bytes = info.raw_bytes;
        storage->checksum = *expected;
        if (expected->algorithm == CG_CHECKSUM_SHA256)
            memcpy(storage->sha256, expected->hex, sizeof(storage->sha256));
        storage->generations = storage->valid = storage->section_accounting_valid = true;
        storage->framing_encoded_bytes = 64;
        storage->metadata_encoded_bytes = storage->encoded_bytes - 64;
        storage->storage_chunks = storage->storage_sections = 1;
    }
    if (store && generation) *generation = info;
done:
    if (input) fclose(input);
    if (raw) fclose(raw);
    if (raw_path[0]) unlink(raw_path);
    return store;
}
