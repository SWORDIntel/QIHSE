/* Regression: failed SSTable cleanup must not resurrect a shadowed value. */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"

static int fail_sstable_unlink;
static int fail_directory_sync, watch_unlinks, watched_unlinks;

int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    struct stat st;
    if (fail_directory_sync && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        fail_directory_sync = 0;
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

int __real_unlink(const char* path);
int __wrap_unlink(const char* path) {
    if (watch_unlinks && path && strstr(path, "sstable_") &&
        strlen(path) >= 3u && !strcmp(path + strlen(path) - 3u, ".db"))
        watched_unlinks++;
    if (fail_sstable_unlink && path && strstr(path, "sstable_") &&
        strstr(path, ".db")) {
        fail_sstable_unlink = 0;
        errno = EACCES;
        return -1;
    }
    return __real_unlink(path);
}

static int count_sstables(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return -1;
    int count = 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        if (!strncmp(ent->d_name, "sstable_", 8u) && strstr(ent->d_name, ".db") &&
            !strstr(ent->d_name, ".tmp")) count++;
    }
    closedir(d);
    return count;
}

static int write_round(qihse_kv_store_t* store, qihse_user_t* user,
                       int round, const char* value) {
    char key[80];
    for (int i = 0; i < 80; ++i) {
        snprintf(key, sizeof(key), "compaction-fault:%d:%d", round, i);
        if (!qihse_kv_set_user(store, key, value, 0u, 0u, user)) return 0;
    }
    return 1;
}

int main(void) {
    char data_dir[] = "build/test_kv_compaction_unlink_XXXXXX";
    if (!mkdtemp(data_dir)) { perror("mkdtemp"); return 1; }
    if (setenv("QIHSE_DATA_DIR", data_dir, 1) != 0 || !qihse_auth_init()) {
        fprintf(stderr, "test setup failed\n"); return 1;
    }
    qihse_user_t* user = qihse_auth_get_user(0);
    qihse_kv_store_t* store = qihse_kv_store_create_user(user);
    if (!user || !store) { fprintf(stderr, "store setup failed\n"); return 1; }

    char* value = malloc(8193u);
    if (!value) return 1;
    memset(value, 'v', 8192u); value[8192] = '\0';

    if (!qihse_kv_set_user(store, "compaction-fault:victim", "old value", 0u, 0u, user) ||
        !qihse_kv_set_user(store, "compaction-fault:expired", "old unexpired value", 0u, 0u, user) ||
        !write_round(store, user, 0, value) ||
        !qihse_kv_del_user(store, "compaction-fault:victim", user) ||
        !qihse_kv_sync_store(store)) {
        fprintf(stderr, "could not persist old values and tombstone\n");
        return 1;
    }
    qihse_kv_batch_set_record_t expired = {
        .key = "compaction-fault:expired",
        .value = "new expired value",
        .expire_time_ms = 1u,
        .classification = 0u,
        .sci_compartment = 0u
    };
    if (!qihse_kv_set_batch_durable_user(store, &expired, 1u, user) ||
        !qihse_kv_sync_store(store)) {
        fprintf(stderr, "could not persist newest expired value\n");
        return 1;
    }
    for (int round = 1; round < 18; ++round) {
        if (!write_round(store, user, round, value)) {
            fprintf(stderr, "filler write failed at round %d\n", round);
            return 1;
        }
    }
    if (count_sstables(data_dir) < 16) {
        fprintf(stderr, "did not establish compaction backlog\n"); return 1;
    }

    /* No original may be retired until the replacement directory entry is
     * durable. A failed sync can leave a harmless duplicate candidate. */
    fail_directory_sync = 1;
    watch_unlinks = 1;
    qihse_kv_sweep_expired(store);
    watch_unlinks = 0;
    if (fail_directory_sync || watched_unlinks) {
        fprintf(stderr, "compaction retired inputs before durable publication\n");
        return 1;
    }

    fail_sstable_unlink = 1;
    qihse_kv_sweep_expired(store);
    if (fail_sstable_unlink) {
        fprintf(stderr, "compaction did not attempt old SSTable cleanup\n"); return 1;
    }
    qihse_kv_store_destroy(store);

    store = qihse_kv_store_create_user(user);
    if (!store) { fprintf(stderr, "store reopen failed\n"); return 1; }
    int resurrected = 0;
    char* got = qihse_kv_get_user(store, "compaction-fault:victim", user);
    if (got) {
        fprintf(stderr, "deleted key resurrected after failed compaction cleanup: %.32s\n", got);
        free(got);
        resurrected = 1;
    }
    got = qihse_kv_get_user(store, "compaction-fault:expired", user);
    if (got) {
        fprintf(stderr, "expired newest key resurrected an older value: %.32s\n", got);
        free(got);
        resurrected = 1;
    }
    /* Once a retry durably retires the old inputs, ordinary GC may reclaim
     * the shadow markers too. Preserve the existing delta/epoch contract. */
    qihse_kv_sweep_expired(store);
    qihse_kv_delta_record_t* rows = NULL;
    size_t row_count = 0u;
    uint64_t resume = 0u;
    if (qihse_kv_export_incremental_user(store, user, 0u,
            &rows, &row_count, &resume) != 0) return 1;
    for (size_t i = 0u; i < row_count; ++i) {
        if (!strcmp(rows[i].key, "compaction-fault:victim") ||
            !strcmp(rows[i].key, "compaction-fault:expired")) {
            fprintf(stderr, "successful cleanup retained a reclaimable dead row\n");
            resurrected = 1;
        }
    }
    qihse_kv_delta_records_free(rows, row_count);
    got = qihse_kv_get_user(store, "compaction-fault:0:0", user);
    if (!got || strcmp(got, value)) resurrected = 1;
    free(got);
    qihse_kv_store_destroy(store);
    free(value);
    if (resurrected) return 1;
    puts("compaction cleanup failure kept tombstone authoritative");
    return 0;
}
