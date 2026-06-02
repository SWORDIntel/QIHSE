/*
 * QIHSE POSIX file helpers for snapshot persistence.
 */

#ifndef QIHSE_FILE_H
#define QIHSE_FILE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_file_s {
    int fd;
} qihse_file_t;

typedef struct qihse_lock_s {
    qihse_file_t file;
    bool held;
} qihse_lock_t;

#define QIHSE_FILE_INVALID_FD (-1)

bool qihse_path_join(const char* dir, const char* name, char* out, size_t out_size);
bool qihse_mkdir_p(const char* path, mode_t mode);

bool qihse_file_open(qihse_file_t* file, const char* path, int flags, mode_t mode);
bool qihse_file_close(qihse_file_t* file);
bool qihse_file_pread_exact(qihse_file_t* file, void* buf, size_t size, uint64_t offset);
bool qihse_file_pwrite_exact(qihse_file_t* file, const void* buf, size_t size, uint64_t offset);
bool qihse_file_fsync(qihse_file_t* file);
bool qihse_file_size(qihse_file_t* file, uint64_t* size_out);
bool qihse_file_truncate(qihse_file_t* file, uint64_t size);

bool qihse_rename_file(const char* old_path, const char* new_path);
bool qihse_fsync_dir(const char* path);

bool qihse_lock_acquire(qihse_lock_t* lock, const char* path);
bool qihse_lock_release(qihse_lock_t* lock);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* QIHSE_FILE_H */
