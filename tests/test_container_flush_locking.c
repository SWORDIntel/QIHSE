/* Persistence regression: after rename, WAL writes MUST target the
 * currently published inode, and the replacement must remain locked. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qihse_container.h"

/* An independently opened process must not write-lock the published inode. */
static void assert_locked_in_another_process(const char* path) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        int fd = open(path, O_RDWR);
        if (fd < 0) _exit(2);
        struct flock lock = {0};
        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        int rc = fcntl(fd, F_SETLK, &lock);
        int err = errno;
        close(fd);
        _exit(rc < 0 && (err == EACCES || err == EAGAIN) ? 0 : 3);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    char dir[] = "build/qihse_ctr_atomic_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_KEY_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 1) == 0);
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/test.qdb", dir);
    assert(n > 0 && (size_t)n < sizeof(path));
    /* A link to a writable peer file must never become our database. */
    char sentinel[512];
    n = snprintf(sentinel, sizeof(sentinel), "%s/sentinel", dir);
    assert(n > 0 && (size_t)n < sizeof(sentinel));
    int fd = open(sentinel, O_RDWR | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0 && write(fd, "KEEP", 4) == 4 && close(fd) == 0);
    assert(symlink("sentinel", path) == 0);
    qihse_container_t writer = {0};
    assert(!qihse_ctr_open_write(path, true, &writer));
    assert(unlink(path) == 0);
    char sentinel_data[4] = {0};
    fd = open(sentinel, O_RDONLY);
    assert(fd >= 0 && read(fd, sentinel_data, 4) == 4);
    assert(memcmp(sentinel_data, "KEEP", 4) == 0 && close(fd) == 0);
    assert(unlink(sentinel) == 0);
    assert(qihse_ctr_open_write(path, true, &writer));
    const uint8_t val[] = {'a','b','c','d'};
    qihse_ctr_section_buf_t item = {
        .section_id = QIHSE_CTR_SEC_METADATA, .data = val, .size = sizeof(val)
    };
    assert(qihse_ctr_flush(&writer, &item, 1));

    struct stat published, live;
    assert(stat(path, &published) == 0 && fstat(writer.fd, &live) == 0);
    assert(published.st_dev == live.st_dev && published.st_ino == live.st_ino);
    assert_locked_in_another_process(path);
    const char wal[] = "WAL-A";
    assert(qihse_ctr_wal_append(&writer, wal, sizeof(wal) - 1u));
    assert(qihse_ctr_fsync(&writer));
    assert(qihse_ctr_section_length(&writer, QIHSE_CTR_SEC_WAL) == sizeof(wal)-1u);

    /* Another flush must preserve the prior WAL and keep a live fd. */
    const uint8_t val2[] = {'x','y'};
    item.data = val2;
    item.size = sizeof(val2);
    assert(qihse_ctr_flush(&writer, &item, 1));
    assert(stat(path, &published) == 0 && fstat(writer.fd, &live) == 0);
    assert(published.st_dev == live.st_dev && published.st_ino == live.st_ino);
    assert_locked_in_another_process(path);
    assert(qihse_ctr_section_length(&writer, QIHSE_CTR_SEC_WAL) == sizeof(wal)-1u);
    qihse_ctr_close(&writer);

    qihse_container_t reader = {0};
    assert(qihse_ctr_open_read(path, &reader));
    assert(qihse_ctr_section_length(&reader, QIHSE_CTR_SEC_WAL) == sizeof(wal)-1u);
    uint8_t* data = NULL;
    size_t size = 0;
    assert(qihse_ctr_read_section_alloc(&reader, QIHSE_CTR_SEC_METADATA, &data, &size));
    assert(size == sizeof(val2) && memcmp(data, val2, size) == 0);
    free(data);
    qihse_ctr_close(&reader);

    /* Section offsets in v1's table are not authenticated by its header.
     * A structural bounds check must reject this forged, out-of-range entry. */
    fd = open(path, O_RDWR);
    assert(fd >= 0);
    unsigned char original_offset[8], forged_offset[8] = {0};
    off_t field = (off_t)QIHSE_CTR_TABLE_OFFSET + 8;
    assert(pread(fd, original_offset, 8, field) == 8);
    assert(pwrite(fd, forged_offset, 8, field) == 8);
    assert(close(fd) == 0);
    assert(!qihse_ctr_open_read(path, &reader));
    fd = open(path, O_RDWR);
    assert(fd >= 0 && pwrite(fd, original_offset, 8, field) == 8);
    assert(close(fd) == 0);

    assert(unlink(path) == 0 && rmdir(dir) == 0);
    puts("PASS: atomic flush transfers locked inode and preserves WAL after rename");
    return 0;
}
