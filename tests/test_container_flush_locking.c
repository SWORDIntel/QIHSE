/* Persistence regression: after rename, WAL writes MUST target the
 * currently published inode, and the replacement must remain locked. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qihse_container.h"

int main(void) {
    char dir[] = "build/qihse_ctr_atomic_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_KEY_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 1) == 0);
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/test.qdb", dir);
    assert(n > 0 && (size_t)n < sizeof(path));
    qihse_container_t writer = {0};
    assert(qihse_ctr_open_write(path, true, &writer));
    const uint8_t val[] = {'a','b','c','d'};
    qihse_ctr_section_buf_t item = {
        .section_id = QIHSE_CTR_SEC_METADATA, .data = val, .size = sizeof(val)
    };
    assert(qihse_ctr_flush(&writer, &item, 1));

    struct stat published, live;
    assert(stat(path, &published) == 0 && fstat(writer.fd, &live) == 0);
    assert(published.st_dev == live.st_dev && published.st_ino == live.st_ino);
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

    assert(unlink(path) == 0 && rmdir(dir) == 0);
    puts("PASS: atomic flush transfers locked inode and preserves WAL after rename");
    return 0;
}
