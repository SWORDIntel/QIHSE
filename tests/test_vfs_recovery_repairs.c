/* Focused regression checks for VFS WAL replay and sparse page-cache eviction. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_vfs_wal.h"
#include "qihse_vfs_page_cache.h"
#include "qihse_audit.h"
#include "qihse_persist_format.h"

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

static void remove_tree(const char* path)
{
    DIR* dir = opendir(path);
    if (!dir) return;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        char child[1024];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        assert(n > 0 && (size_t)n < sizeof(child));
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) remove_tree(child);
        else unlink(child);
    }
    closedir(dir);
    rmdir(path);
}

static void test_vfs_wal(void)
{
    char dir[] = "/tmp/qihse_vfs_recovery_XXXXXX";
    assert(mkdtemp(dir));
    qihse_vfs_wal_t* wal = qihse_vfs_wal_create(dir);
    assert(wal);

    const uint8_t data[] = {1, 2, 3, 4};
    assert(!qihse_vfs_wal_append(wal, (int64_t)QIHSE_VFS_WAL_MAX_BYTES - 1,
                                 data, sizeof(data)));
    assert(!qihse_vfs_wal_append(wal, INT64_MAX, data, sizeof(data)));
    assert(qihse_vfs_wal_append(wal, 0, data, sizeof(data)));
    assert(qihse_vfs_wal_flush(wal));
    assert(qihse_vfs_wal_rebuild_flat(wal));
    assert(qihse_vfs_wal_size(wal) == sizeof(data));
    uint8_t got[sizeof(data)];
    assert(qihse_vfs_wal_read(wal, 0, got, sizeof(got)));
    assert(memcmp(got, data, sizeof(data)) == 0);
    qihse_vfs_wal_destroy(wal);

    char log[1024];
    assert(snprintf(log, sizeof(log), "%s/wal.log", dir) > 0);
    int fd = open(log, O_RDWR | O_CLOEXEC);
    assert(fd >= 0);
    uint32_t bad_magic = 0;
    assert(pwrite(fd, &bad_magic, sizeof(bad_magic), 0) == sizeof(bad_magic));
    close(fd);

    wal = qihse_vfs_wal_create(dir);
    assert(wal);
    assert(!qihse_vfs_wal_rebuild_flat(wal));
    assert(qihse_vfs_wal_size(wal) == 0);
    qihse_vfs_wal_destroy(wal);
    remove_tree(dir);
}

typedef struct {
    const uint8_t* data;
    size_t size;
    uint32_t checksum;
} crc_thread_arg_t;

static void* crc_first_call_thread(void* context)
{
    crc_thread_arg_t* arg = context;
    (void)qihse_crc32c_available();
    arg->checksum = qihse_crc32c(arg->data, arg->size);
    return NULL;
}

static void test_concurrent_crc_initialization(void)
{
    uint8_t data[4096];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i * 37u);
    pthread_t threads[16];
    crc_thread_arg_t args[16];
    for (size_t i = 0; i < 16; i++) {
        args[i] = (crc_thread_arg_t){.data = data, .size = sizeof(data), .checksum = 0u};
        assert(pthread_create(&threads[i], NULL, crc_first_call_thread, &args[i]) == 0);
    }
    for (size_t i = 0; i < 16; i++) assert(pthread_join(threads[i], NULL) == 0);
    uint32_t expected = args[0].checksum;
    for (size_t i = 1; i < 16; i++) assert(args[i].checksum == expected);
}

static void test_sparse_cache_eviction(void)
{
    qihse_vfs_page_cache_t* cache = qihse_vfs_cache_create();
    assert(cache);
    const uint8_t a[] = {0xaa}, b[] = {0xbb};
    uint8_t got = 0;
    qihse_vfs_cache_put(cache, 0, a, sizeof(a));
    qihse_vfs_cache_put(cache, 10, b, sizeof(b));
    assert(qihse_vfs_cache_get(cache, 0, &got, 1) && got == a[0]);
    qihse_vfs_cache_evict_above(cache, 5);
    assert(qihse_vfs_cache_get(cache, 0, &got, 1) && got == a[0]);
    assert(!qihse_vfs_cache_get(cache, 10, &got, 1));
    qihse_vfs_cache_destroy(cache);
}

int main(void)
{
    char data_dir[] = "/tmp/qihse_vfs_cache_XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    qihse_audit_init();
    test_concurrent_crc_initialization();
    test_vfs_wal();
    test_sparse_cache_eviction();
    qihse_audit_shutdown();
    remove_tree(data_dir);
    puts("PASS VFS replay completeness, offset bounds, sparse cache eviction");
    return 0;
}
