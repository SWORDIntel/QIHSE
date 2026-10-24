#include "qihse_wal.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
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
    char path[512];
    snprintf(path, sizeof(path), "%s/wal_%020u.log", dir, 0u);
    (void)unlink(path);
    snprintf(path, sizeof(path), "%s/wal_%020u.log", dir, 1u);
    (void)unlink(path);
    assert(rmdir(dir) == 0);
}

int main(void) {
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
    assert(qihse_wal_checkpoint(wal, 9) == 0);
    assert(qihse_wal_last_checkpoint(wal) == 9);
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
    puts("PASS WAL reports sync failures for append, flush, replay, checkpoint, and rotation");
    return 0;
}
