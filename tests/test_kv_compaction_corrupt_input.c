/* A forgiving read scan may skip damaged rows; compaction must not publish
 * from that partial view or remove its source SSTables. */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"

static int count_sstables(const char* dir, char* newest, size_t newest_size) {
    DIR* d = opendir(dir);
    if (!d) return -1;
    int count = 0, newest_id = -1;
    struct dirent* ent;
    while ((ent = readdir(d)) != NULL) {
        int id = -1; char tail = '\0';
        if (sscanf(ent->d_name, "sstable_%d.db%c", &id, &tail) != 1 || id < 0)
            continue;
        count++;
        if (id > newest_id) {
            int n = snprintf(newest, newest_size, "%s/%s", dir, ent->d_name);
            if (n < 0 || (size_t)n >= newest_size) {
                closedir(d); return -1;
            }
            newest_id = id;
        }
    }
    closedir(d);
    return count;
}

int main(void) {
    char data_dir[] = "build/test_kv_compaction_corrupt_XXXXXX";
    if (!mkdtemp(data_dir)) { perror("mkdtemp"); return 1; }
    if (setenv("QIHSE_DATA_DIR", data_dir, 1) != 0 || !qihse_auth_init()) {
        fprintf(stderr, "test setup failed\n"); return 1;
    }
    qihse_kv_store_t* store = qihse_kv_store_create();
    if (!store) { fprintf(stderr, "store create failed\n"); return 1; }
    char* value = malloc(8193u);
    if (!value) return 1;
    memset(value, 'c', 8192u); value[8192] = '\0';
    char key[80];
    for (int round = 0; round < 20; ++round) {
        for (int i = 0; i < 80; ++i) {
            snprintf(key, sizeof(key), "corrupt-compact:%d:%d", round, i);
            if (!qihse_kv_set(store, key, value, 0u, 0u)) {
                fprintf(stderr, "write failed\n"); return 1;
            }
        }
    }
    if (!qihse_kv_sync_store(store)) {
        fprintf(stderr, "could not flush test records\n"); return 1;
    }

    char newest[4096];
    int before = count_sstables(data_dir, newest, sizeof(newest));
    if (before < 16) { fprintf(stderr, "compaction backlog too small: %d\n", before); return 1; }
    int fd = open(newest, O_WRONLY | O_CLOEXEC);
    static const char bad_header[] = "broken header\n";
    if (fd < 0 || pwrite(fd, bad_header, sizeof(bad_header) - 1u, 0) !=
                  (ssize_t)(sizeof(bad_header) - 1u) || fsync(fd) != 0) {
        perror("corrupt newest SSTable"); if (fd >= 0) close(fd); return 1;
    }
    close(fd);

    qihse_kv_sweep_expired(store);
    char still_newest[4096];
    int after = count_sstables(data_dir, still_newest, sizeof(still_newest));
    qihse_kv_store_destroy(store);
    free(value);
    if (after != before || strcmp(newest, still_newest) != 0) {
        fprintf(stderr, "compaction discarded damaged inputs: files %d -> %d\n",
                before, after);
        return 1;
    }
    puts("corrupt compaction input was retained without replacement");
    return 0;
}
