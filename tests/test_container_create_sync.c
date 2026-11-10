#include "qihse_container.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sync_calls;
static int fail_sync_call;

int qihse_test_fsync(int fd) {
    sync_calls++;
    if (sync_calls == fail_sync_call) {
        errno = EIO;
        return -1;
    }
    return (int)syscall(SYS_fsync, fd);
}

static void make_path(char *path, size_t cap, const char *dir, const char *leaf) {
    int n = snprintf(path, cap, "%s/%s", dir, leaf);
    assert(n > 0 && (size_t)n < cap);
}

int main(void) {
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    char dir[] = "build/container_create_sync_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_KEY_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 1) == 0);
    char path[512];
    make_path(path, sizeof(path), dir, "durable.qdb");

    qihse_container_t ctr;
    sync_calls = 0;
    fail_sync_call = 0;
    assert(qihse_ctr_open_write(path, true, &ctr));
    assert(sync_calls == 2); /* initialized inode, then its parent directory */
    qihse_ctr_close(&ctr);
    sync_calls = 0;
    fail_sync_call = 1;
    assert(qihse_ctr_open_write(path, false, &ctr));
    assert(sync_calls == 0); /* hot WAL reopens remain unsynced */
    qihse_ctr_close(&ctr);
    assert(unlink(path) == 0);

    make_path(path, sizeof(path), dir, "file-sync-fails.qdb");
    sync_calls = 0;
    fail_sync_call = 1;
    errno = 0;
    assert(!qihse_ctr_open_write(path, true, &ctr));
    assert(sync_calls == 1 && errno == EIO);
    sync_calls = 0;
    fail_sync_call = 0;
    assert(qihse_ctr_open_write(path, true, &ctr));
    assert(sync_calls == 2); /* retry re-syncs file and parent */
    qihse_ctr_close(&ctr);
    assert(unlink(path) == 0);

    make_path(path, sizeof(path), dir, "directory-sync-fails.qdb");
    sync_calls = 0;
    fail_sync_call = 2;
    errno = 0;
    assert(!qihse_ctr_open_write(path, true, &ctr));
    assert(sync_calls == 2 && errno == EIO);
    /* The file is valid, but the parent sync was uncertain. Retry through the
     * create=true contract and verify both syncs are attempted again. */
    sync_calls = 0;
    fail_sync_call = 0;
    assert(qihse_ctr_open_write(path, true, &ctr));
    assert(sync_calls == 2);
    qihse_ctr_close(&ctr);
    assert(unlink(path) == 0);

    assert(unsetenv("QIHSE_ALLOW_INSECURE_CONTAINER") == 0);
    assert(rmdir(dir) == 0);
    puts("container initial file and directory sync checks passed");
    return 0;
}
