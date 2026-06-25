#include "qihse_platform.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include "qihse_file.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#include <windows.h>

static HANDLE io_mutex = NULL;
static void lock_io(void) {
    if (!io_mutex) {
        HANDLE m = CreateMutexA(NULL, FALSE, NULL);
        if (InterlockedCompareExchangePointer((PVOID volatile *)&io_mutex, (PVOID)m, NULL) != NULL) {
            CloseHandle(m);
        }
    }
    WaitForSingleObject(io_mutex, INFINITE);
}
static void unlock_io(void) {
    ReleaseMutex(io_mutex);
}
#endif

static bool qihse_file_offset_ok(uint64_t offset, off_t* out) {
    uint64_t max_off = (((uint64_t)1u) << ((sizeof(off_t) * CHAR_BIT) - 1u)) - 1u;
    if (!out || offset > max_off) {
        errno = EOVERFLOW;
        return false;
    }
    *out = (off_t)offset;
    return true;
}

bool qihse_path_join(const char* dir, const char* name, char* out, size_t out_size) {
    size_t dir_len;
    size_t name_len;
    bool need_slash;
    size_t total;

    if (!dir || !name || !out || out_size == 0) {
        errno = EINVAL;
        return false;
    }

    dir_len = strlen(dir);
    name_len = strlen(name);
    need_slash = (dir_len > 0 && dir[dir_len - 1] != '/');
    total = dir_len + (need_slash ? 1u : 0u) + name_len;
    if (total + 1u < total || total + 1u > out_size) {
        errno = ENAMETOOLONG;
        return false;
    }

    memcpy(out, dir, dir_len);
    if (need_slash) {
        out[dir_len] = '/';
        memcpy(out + dir_len + 1u, name, name_len);
    } else {
        memcpy(out + dir_len, name, name_len);
    }
    out[total] = '\0';
    return true;
}

bool qihse_mkdir_p(const char* path, mode_t mode) {
    char* tmp;
    size_t len;
    size_t i;

    if (!path || path[0] == '\0') {
        errno = EINVAL;
        return false;
    }

    len = strlen(path);
    tmp = (char*)malloc(len + 1u);
    if (!tmp) {
        errno = ENOMEM;
        return false;
    }
    memcpy(tmp, path, len + 1u);

    for (i = 1u; i < len; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            #ifndef _WIN32
            if (tmp[0] != '\0' && mkdir(tmp, mode) != 0 && errno != EEXIST) {
#else
            if (tmp[0] != '\0' && mkdir(tmp) != 0 && errno != EEXIST) {
#endif
                free(tmp);
                return false;
            }
            tmp[i] = '/';
        }
    }

    #ifndef _WIN32
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
#else
    if (mkdir(tmp) != 0 && errno != EEXIST) {
#endif
        free(tmp);
        return false;
    }

    free(tmp);
    return true;
}

bool qihse_file_open(qihse_file_t* file, const char* path, int flags, mode_t mode) {
    int fd;

    if (!file || !path) {
        errno = EINVAL;
        return false;
    }

    fd = open(path, flags, mode);
    if (fd < 0) {
        file->fd = QIHSE_FILE_INVALID_FD;
        return false;
    }

    file->fd = fd;
    return true;
}

bool qihse_file_close(qihse_file_t* file) {
    int rc;

    if (!file || file->fd == QIHSE_FILE_INVALID_FD) {
        return true;
    }

    do {
        rc = close(file->fd);
    } while (rc != 0 && errno == EINTR);

    file->fd = QIHSE_FILE_INVALID_FD;
    return rc == 0;
}

bool qihse_file_pread_exact(qihse_file_t* file, void* buf, size_t size, uint64_t offset) {
    uint8_t* p = (uint8_t*)buf;
    size_t done = 0u;

    if (!file || file->fd == QIHSE_FILE_INVALID_FD || (!buf && size != 0u)) {
        errno = EINVAL;
        return false;
    }

    while (done < size) {
        off_t off;
        ssize_t n;
        if ((uint64_t)done > UINT64_MAX - offset) {
            errno = EOVERFLOW;
            return false;
        }
        if (!qihse_file_offset_ok(offset + (uint64_t)done, &off)) {
            return false;
        }
#ifdef _WIN32
        lock_io();
        lseek(file->fd, off, SEEK_SET);
        n = read(file->fd, p + done, (unsigned int)(size - done));
        unlock_io();
#else
        n = pread(file->fd, p + done, size - done, off);
#endif
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            errno = EIO;
            return false;
        }
        done += (size_t)n;
    }

    return true;
}

bool qihse_file_pwrite_exact(qihse_file_t* file, const void* buf, size_t size, uint64_t offset) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t done = 0u;

    if (!file || file->fd == QIHSE_FILE_INVALID_FD || (!buf && size != 0u)) {
        errno = EINVAL;
        return false;
    }

    while (done < size) {
        off_t off;
        ssize_t n;
        if ((uint64_t)done > UINT64_MAX - offset) {
            errno = EOVERFLOW;
            return false;
        }
        if (!qihse_file_offset_ok(offset + (uint64_t)done, &off)) {
            return false;
        }
#ifdef _WIN32
        lock_io();
        lseek(file->fd, off, SEEK_SET);
        n = write(file->fd, p + done, (unsigned int)(size - done));
        unlock_io();
#else
        n = pwrite(file->fd, p + done, size - done, off);
#endif
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            errno = EIO;
            return false;
        }
        done += (size_t)n;
    }

    return true;
}

bool qihse_file_fsync(qihse_file_t* file) {
    int rc;

    if (!file || file->fd == QIHSE_FILE_INVALID_FD) {
        errno = EINVAL;
        return false;
    }

    do {
#ifdef _WIN32
        rc = _commit(file->fd);
#else
        rc = fsync(file->fd);
#endif
    } while (rc != 0 && errno == EINTR);

    return rc == 0;
}

bool qihse_file_size(qihse_file_t* file, uint64_t* size_out) {
    struct stat st;

    if (!file || file->fd == QIHSE_FILE_INVALID_FD || !size_out) {
        errno = EINVAL;
        return false;
    }

    if (fstat(file->fd, &st) != 0) {
        return false;
    }
    if (st.st_size < 0) {
        errno = EIO;
        return false;
    }

    *size_out = (uint64_t)st.st_size;
    return true;
}

bool qihse_file_truncate(qihse_file_t* file, uint64_t size) {
    off_t off;

    if (!file || file->fd == QIHSE_FILE_INVALID_FD) {
        errno = EINVAL;
        return false;
    }
    if (!qihse_file_offset_ok(size, &off)) {
        return false;
    }

#ifdef _WIN32
    return _chsize(file->fd, off) == 0;
#else
    return ftruncate(file->fd, off) == 0;
#endif
}

bool qihse_rename_file(const char* old_path, const char* new_path) {
    if (!old_path || !new_path) {
        errno = EINVAL;
        return false;
    }
    return rename(old_path, new_path) == 0;
}

bool qihse_fsync_dir(const char* path) {
#ifdef _WIN32
    (void)path;
    return true;
#else
    int fd;
    int rc;

    if (!path) {
        errno = EINVAL;
        return false;
    }

    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        return false;
    }

    do {
        rc = fsync(fd);
    } while (rc != 0 && errno == EINTR);

    {
        int saved = errno;
        close(fd);
        errno = saved;
    }

    return rc == 0;
#endif
}

bool qihse_lock_acquire(qihse_lock_t* lock, const char* path) {
#ifndef _WIN32
    struct flock fl;
#endif

    if (!lock || !path) {
        errno = EINVAL;
        return false;
    }

    lock->file.fd = QIHSE_FILE_INVALID_FD;
    lock->held = false;
    if (!qihse_file_open(&lock->file, path, O_RDWR | O_CREAT, 0600)) {
        return false;
    }

#ifndef _WIN32
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    if (fcntl(lock->file.fd, F_SETLK, &fl) != 0) {
        qihse_file_close(&lock->file);
        return false;
    }
#endif

    lock->held = true;
    return true;
}

bool qihse_lock_release(qihse_lock_t* lock) {
#ifndef _WIN32
    struct flock fl;
#endif
    bool ok = true;

    if (!lock) {
        errno = EINVAL;
        return false;
    }

    if (lock->held && lock->file.fd != QIHSE_FILE_INVALID_FD) {
#ifndef _WIN32
        memset(&fl, 0, sizeof(fl));
        fl.l_type = F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(lock->file.fd, F_SETLK, &fl) != 0) {
            ok = false;
        }
#endif
    }

    lock->held = false;
    if (!qihse_file_close(&lock->file)) {
        ok = false;
    }
    return ok;
}
