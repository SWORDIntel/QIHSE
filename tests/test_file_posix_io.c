#include "qihse_file.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char path[] = "tests/file_posix_io_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(write(fd, "seed", 4) == 4);
    assert(close(fd) == 0);

    qihse_file_t file = {QIHSE_FILE_INVALID_FD};
    assert(qihse_file_open(&file, path, O_RDWR, 0600));

    const uint64_t max_off = INT64_MAX;
    const char payload[] = "xy";
    errno = 0;
    assert(!qihse_file_pwrite_exact(&file, payload, sizeof(payload), max_off));
    assert(errno == EOVERFLOW);

    char readback[4] = {0};
    assert(qihse_file_pread_exact(&file, readback, sizeof(readback), 0));
    assert(memcmp(readback, "seed", sizeof(readback)) == 0);
    char untouched = 'z';
    errno = 0;
    assert(!qihse_file_pread_exact(&file, &untouched, 2, max_off));
    assert(errno == EOVERFLOW && untouched == 'z');

    struct stat st;
    assert(fstat(file.fd, &st) == 0 && st.st_size == 4);
    assert(qihse_file_close(&file));
    assert(file.fd == QIHSE_FILE_INVALID_FD);
    assert(unlink(path) == 0);
    puts("file exact-I/O range checks passed");
    return 0;
}
