#include "qihse_wal.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>

int qihse_test_sync_fail;
int qihse_test_fsync_fail;

int qihse_test_fdatasync(int fd) {
    if (qihse_test_sync_fail) {
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_fdatasync, fd);
}

int qihse_test_fsync(int fd) {
    if (qihse_test_fsync_fail) {
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

static bool count_record(const qihse_wal_record_t* record,
                         const void* key, uint32_t key_len,
                         const void* value, uint32_t value_len,
                         void* opaque) {
    (void)record;
    (void)key;
    (void)key_len;
    (void)value;
    (void)value_len;
    (*(int*)opaque)++;
    return true;
}

static void remove_single_segment(const char* dir) {
    DIR* entries = opendir(dir);
    assert(entries);
    struct dirent* ent;
    while ((ent = readdir(entries)) != NULL) {
        if (strncmp(ent->d_name, "wal_", 4) != 0) continue;
        char path[512];
        assert(snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) <
               (int)sizeof(path));
        assert(unlink(path) == 0);
    }
    assert(closedir(entries) == 0);
    assert(rmdir(dir) == 0);
}

/* Repeated startup rejection must preserve every byte, not just file size. */
static void assert_reopen_rejected_unchanged(const char* dir, const char* path) {
    uint8_t before[4096], after[4096];
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    ssize_t size = read(fd, before, sizeof(before));
    assert(size > 0 && size < (ssize_t)sizeof(before));
    assert(close(fd) == 0);
    for (int attempt = 0; attempt < 2; attempt++) {
        assert(qihse_wal_create(dir, 4096, QIHSE_WAL_DURABILITY_FDATASYNC) == NULL);
        fd = open(path, O_RDONLY);
        assert(fd >= 0);
        assert(read(fd, after, sizeof(after)) == size);
        assert(memcmp(before, after, (size_t)size) == 0);
        assert(close(fd) == 0);
    }
}

static void test_short_write_fence(qihse_wal_durability_t durability) {
    char dir[] = "tests/wal_short_write_XXXXXX";
    assert(mkdtemp(dir));
    qihse_wal_t* wal = qihse_wal_create(dir, 128, durability);
    assert(wal && qihse_wal_append_begin(wal, 1) == 1);
    assert(qihse_wal_append_checkpoint(wal, 1) == 2);
    char path[512];
    snprintf(path, sizeof(path), "%s/wal_%020u.log", dir, 0u);
    struct stat st;
    assert(stat(path, &st) == 0);
    off_t prefix_size = st.st_size;

    /* A real kernel positive short write, without a production test hook. */
    struct rlimit original, limited;
    assert(getrlimit(RLIMIT_FSIZE, &original) == 0);
    limited = original;
    limited.rlim_cur = (rlim_t)prefix_size + 5;
    assert(original.rlim_cur == RLIM_INFINITY ||
           original.rlim_cur >= limited.rlim_cur);
    void (*old_handler)(int) = signal(SIGXFSZ, SIG_IGN);
    assert(old_handler != SIG_ERR);
    assert(setrlimit(RLIMIT_FSIZE, &limited) == 0);
    assert(qihse_wal_append(wal, 1, 0, QIHSE_WAL_OP_INSERT,
                            "k", 1, "v", 1) == 0);
    assert(setrlimit(RLIMIT_FSIZE, &original) == 0);
    assert(signal(SIGXFSZ, old_handler) != SIG_ERR);
    assert(stat(path, &st) == 0 && st.st_size == prefix_size + 5);
    uint64_t next = qihse_wal_current_lsn(wal);

    char large_value[80] = {0};
    /* This append would rotate using the stale pre-short-write offset. */
    assert(qihse_wal_append(wal, 2, 0, QIHSE_WAL_OP_INSERT,
                            "k", 1, large_value, sizeof(large_value)) == 0);
    assert(qihse_wal_append_begin(wal, 2) == 0);
    assert(qihse_wal_append_commit(wal, 2) == 0);
    assert(qihse_wal_append_abort(wal, 2) == 0);
    assert(qihse_wal_append_checkpoint(wal, 1) == 0);
    assert(qihse_wal_flush(wal) == -1);
    int count = 0;
    assert(qihse_wal_replay(wal, 0, count_record, &count) == -1 && count == 0);
    assert(qihse_wal_checkpoint(wal, 1) == -1);
    assert(qihse_wal_last_checkpoint(wal) == 0);
    assert(qihse_wal_current_lsn(wal) == next);
    assert(stat(path, &st) == 0 && st.st_size == prefix_size + 5);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", dir, 1u);
    assert(access(path, F_OK) == -1 && errno == ENOENT);
    qihse_wal_destroy(wal);

    /* Only a new handle may repair this unambiguous short-header tail. */
    wal = qihse_wal_create(dir, 128, durability);
    assert(wal && qihse_wal_current_lsn(wal) == 3);
    assert(qihse_wal_append_commit(wal, 1) == 3);
    qihse_wal_destroy(wal);
    remove_single_segment(dir);
}

static void test_malformed_headers(void) {
    const qihse_wal_op_t ops[] = {QIHSE_WAL_OP_BEGIN, QIHSE_WAL_OP_COMMIT,
                                  QIHSE_WAL_OP_ABORT, QIHSE_WAL_OP_CHECKPOINT,
                                  QIHSE_WAL_OP_DELETE, (qihse_wal_op_t)99};
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        char dir[] = "tests/wal_bad_shape_XXXXXX";
        assert(mkdtemp(dir));
        qihse_wal_t* wal = qihse_wal_create(dir, 4096, QIHSE_WAL_DURABILITY_FDATASYNC);
        assert(wal && qihse_wal_append_commit(wal, 1) == 1);
        /* Invalid requests must not consume an LSN or reach disk. */
        assert(qihse_wal_append(wal, 1, 0, ops[i], "k", 1, "v", 1) == 0);
        assert(qihse_wal_current_lsn(wal) == 2);
        qihse_wal_destroy(wal);
        char path[512];
        snprintf(path, sizeof(path), "%s/wal_%020u.log", dir, 0u);
        int fd = open(path, O_RDWR);
        assert(fd >= 0);
        uint8_t hdr[QIHSE_WAL_RECORD_HEADER_SIZE];
        assert(pread(fd, hdr, sizeof(hdr), 0) == (ssize_t)sizeof(hdr));
        hdr[17] = (uint8_t)ops[i];
        uint32_t one = 1;
        memcpy(hdr + 18, &one, sizeof(one));
        /* Specifically includes final COMMIT key_length 0 -> 1 with its
         * original checksum: formerly silently truncated as a torn payload. */
        assert(pwrite(fd, hdr, sizeof(hdr), 0) == (ssize_t)sizeof(hdr));
        assert(close(fd) == 0);
        assert_reopen_rejected_unchanged(dir, path);

        /* Even a matching legacy checksum cannot legitimize a malformed
         * complete control record, DELETE payload or unknown operation. */
        uint8_t complete[QIHSE_WAL_RECORD_HEADER_SIZE + 2];
        memcpy(complete, hdr, sizeof(hdr));
        memcpy(complete + 22, &one, sizeof(one));
        complete[sizeof(hdr)] = 'k';
        complete[sizeof(hdr) + 1] = 'v';
        uint32_t crc = qihse_wal_crc32(complete, 8) ^
                       qihse_wal_crc32(complete + 8, 8) ^
                       qihse_wal_crc32(complete + 16, 1) ^
                       qihse_wal_crc32(complete + 17, 1) ^
                       qihse_wal_crc32(complete + 18, 4) ^
                       qihse_wal_crc32(complete + 22, 4) ^
                       qihse_wal_crc32(complete + sizeof(hdr), 1) ^
                       qihse_wal_crc32(complete + sizeof(hdr) + 1, 1);
        memcpy(complete + 26, &crc, sizeof(crc));
        fd = open(path, O_RDWR);
        assert(fd >= 0);
        assert(pwrite(fd, complete, sizeof(complete), 0) == (ssize_t)sizeof(complete));
        assert(close(fd) == 0);
        assert_reopen_rejected_unchanged(dir, path);
        remove_single_segment(dir);
    }
}

int main(void) {
    test_short_write_fence(QIHSE_WAL_DURABILITY_NONE);
    test_short_write_fence(QIHSE_WAL_DURABILITY_FDATASYNC);
    test_short_write_fence(QIHSE_WAL_DURABILITY_GROUP_COMMIT);
    test_malformed_headers();
    char dirsync_dir[] = "tests/wal_dirsync_failure_XXXXXX";
    assert(mkdtemp(dirsync_dir) != NULL);
    qihse_test_fsync_fail = 1;
    assert(qihse_wal_create(dirsync_dir, 64 * 1024,
                            QIHSE_WAL_DURABILITY_FDATASYNC) == NULL);
    qihse_test_fsync_fail = 0;
    remove_single_segment(dirsync_dir);

    char dir[] = "tests/wal_sync_failure_XXXXXX";
    assert(mkdtemp(dir) != NULL);
    qihse_wal_t* wal = qihse_wal_create(
        dir, 64 * 1024, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal != NULL);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        qihse_wal_t* second = qihse_wal_create(
            dir, 64 * 1024, QIHSE_WAL_DURABILITY_FDATASYNC);
        _exit(second == NULL ? 0 : 1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    const char key[] = "k";
    const char value[] = "v";
    qihse_test_sync_fail = 1;
    assert(qihse_wal_append(wal, 1, 0, QIHSE_WAL_OP_INSERT,
                            key, sizeof(key), value, sizeof(value)) == 0);
    assert(qihse_wal_flush(wal) == -1);
    int replayed = 0;
    assert(qihse_wal_replay(wal, 0, count_record, &replayed) == -1);
    assert(qihse_wal_checkpoint(wal, 9) == -1);
    assert(qihse_wal_last_checkpoint(wal) == 0);

    qihse_test_sync_fail = 0;
    assert(qihse_wal_flush(wal) == 0);
    assert(qihse_wal_replay(wal, 0, count_record, &replayed) == 1);
    assert(replayed == 1);
    assert(qihse_wal_checkpoint(wal, 9) == -1);
    uint64_t checkpoint = qihse_wal_current_lsn(wal);
    assert(qihse_wal_append_checkpoint(wal, checkpoint) != 0);
    assert(qihse_wal_checkpoint(wal, checkpoint) == 0);
    assert(qihse_wal_last_checkpoint(wal) == checkpoint);
    qihse_wal_destroy(wal);
    remove_single_segment(dir);

    char rotate_dir[] = "tests/wal_rotate_sync_failure_XXXXXX";
    assert(mkdtemp(rotate_dir) != NULL);
    qihse_wal_t* rotating = qihse_wal_create(
        rotate_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(rotating != NULL);
    assert(qihse_wal_append(rotating, 2, 0, QIHSE_WAL_OP_INSERT,
                            key, sizeof(key), value, sizeof(value)) != 0);
    assert(qihse_wal_append(rotating, 2, 0, QIHSE_WAL_OP_INSERT,
                            key, sizeof(key), value, sizeof(value)) != 0);
    uint64_t next_lsn = qihse_wal_current_lsn(rotating);
    qihse_test_sync_fail = 1;
    assert(qihse_wal_append(rotating, 2, 0, QIHSE_WAL_OP_INSERT,
                            key, sizeof(key), value, sizeof(value)) == 0);
    assert(qihse_wal_current_lsn(rotating) == next_lsn);
    qihse_test_sync_fail = 0;
    assert(qihse_wal_append(rotating, 2, 0, QIHSE_WAL_OP_INSERT,
                            key, sizeof(key), value, sizeof(value)) == next_lsn);
    qihse_wal_destroy(rotating);
    remove_single_segment(rotate_dir);

    char crash_dir[] = "tests/wal_torn_tail_XXXXXX";
    assert(mkdtemp(crash_dir));
    wal = qihse_wal_create(crash_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal);
    assert(qihse_wal_append_commit(wal, 10) == 1);
    assert(qihse_wal_append_commit(wal, 11) == 2);
    assert(qihse_wal_append_commit(wal, 12) == 3); /* segment 1 */
    qihse_wal_destroy(wal);
    char path[512];
    snprintf(path, sizeof(path), "%s/wal_%020u.log", crash_dir, 1u);
    int fd = open(path, O_WRONLY | O_APPEND);
    assert(fd >= 0);
    assert(write(fd, "tear", 4) == 4);
    assert(close(fd) == 0);
    wal = qihse_wal_create(crash_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal);
    assert(qihse_wal_current_lsn(wal) == 4);
    struct stat st;
    assert(stat(path, &st) == 0 && st.st_size == QIHSE_WAL_RECORD_HEADER_SIZE);
    assert(qihse_wal_append_commit(wal, 13) == 4);
    assert(qihse_wal_checkpoint(wal, 4) == -1); /* no durable marker */
    assert(qihse_wal_append_checkpoint(wal, 4) == 5);
    assert(qihse_wal_checkpoint(wal, 4) == 0);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", crash_dir, 0u);
    assert(access(path, F_OK) != 0); /* max LSN 2 < fence 4 */
    qihse_wal_destroy(wal);
    wal = qihse_wal_create(crash_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal && qihse_wal_current_lsn(wal) == 6);
    assert(qihse_wal_last_checkpoint(wal) == 4);
    qihse_wal_destroy(wal);
    remove_single_segment(crash_dir);

    char bad_dir[] = "tests/wal_corrupt_record_XXXXXX";
    assert(mkdtemp(bad_dir));
    wal = qihse_wal_create(bad_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal && qihse_wal_append_commit(wal, 10) == 1);
    qihse_wal_destroy(wal);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", bad_dir, 0u);
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    char byte;
    assert(pread(fd, &byte, 1, 8) == 1);
    byte ^= 1;
    assert(pwrite(fd, &byte, 1, 8) == 1);
    assert(close(fd) == 0);
    assert(qihse_wal_create(bad_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC) == NULL);
    assert(stat(path, &st) == 0 && st.st_size == QIHSE_WAL_RECORD_HEADER_SIZE);
    remove_single_segment(bad_dir);

    char earlier_dir[] = "tests/wal_earlier_tail_XXXXXX";
    assert(mkdtemp(earlier_dir));
    wal = qihse_wal_create(earlier_dir, 40, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal && qihse_wal_append_commit(wal, 1) == 1);
    assert(qihse_wal_append_commit(wal, 2) == 2);
    qihse_wal_destroy(wal);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", earlier_dir, 0u);
    fd = open(path, O_WRONLY | O_APPEND);
    assert(fd >= 0 && write(fd, "tear", 4) == 4);
    assert(close(fd) == 0);
    assert(qihse_wal_create(earlier_dir, 40,
                            QIHSE_WAL_DURABILITY_FDATASYNC) == NULL);
    assert(stat(path, &st) == 0 && st.st_size == QIHSE_WAL_RECORD_HEADER_SIZE + 4);
    remove_single_segment(earlier_dir);

    char payload_dir[] = "tests/wal_payload_tail_XXXXXX";
    assert(mkdtemp(payload_dir));
    wal = qihse_wal_create(payload_dir, 80, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal && qihse_wal_append_commit(wal, 1) == 1);
    assert(qihse_wal_append(wal, 2, 0, QIHSE_WAL_OP_INSERT,
                            "k", 1, "vv", 2) == 2);
    qihse_wal_destroy(wal);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", payload_dir, 0u);
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    /* A genuine valid record truncated in its payload has an unverifiable
     * header. Preserve it: the old format cannot distinguish a corrupted
     * length on an acknowledged mutation from this physical payload tear. */
    assert(ftruncate(fd, 2 * QIHSE_WAL_RECORD_HEADER_SIZE + 2) == 0);
    assert(close(fd) == 0);
    assert_reopen_rejected_unchanged(payload_dir, path);
    remove_single_segment(payload_dir);

    char length_dir[] = "tests/wal_corrupt_length_XXXXXX";
    assert(mkdtemp(length_dir));
    wal = qihse_wal_create(length_dir, 4096, QIHSE_WAL_DURABILITY_FDATASYNC);
    assert(wal && qihse_wal_append_commit(wal, 1) == 1);
    assert(qihse_wal_append(wal, 2, 0, QIHSE_WAL_OP_UPDATE,
                            "k", 1, "v", 1) == 2);
    qihse_wal_destroy(wal);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", length_dir, 0u);
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    uint32_t forged_length = 3;
    assert(pwrite(fd, &forged_length, sizeof(forged_length),
                  QIHSE_WAL_RECORD_HEADER_SIZE + 22) == (ssize_t)sizeof(forged_length));
    assert(close(fd) == 0);
    assert_reopen_rejected_unchanged(length_dir, path);
    remove_single_segment(length_dir);
    puts("PASS WAL durability, torn tail, checksum rejection, checkpoint fence and restart LSN");
    return 0;
}
