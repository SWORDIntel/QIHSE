/* A forgiving read scan may skip damaged rows; compaction must not publish
 * from that partial view or remove its source SSTables. */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
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

static int write_sentinel(const char* path) {
    static const char bytes[] = "keep-this-snapshot\0byte-exact";
    FILE* f = fopen(path, "wb");
    if (!f) return 0;
    int ok = fwrite(bytes, 1u, sizeof(bytes), f) == sizeof(bytes);
    if (fclose(f) != 0) ok = 0;
    return ok;
}

static int sentinel_unchanged(const char* path) {
    static const char expected[] = "keep-this-snapshot\0byte-exact";
    char actual[sizeof(expected) + 1u];
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(actual, 1u, sizeof(actual), f);
    int extra = fgetc(f);
    int ok = fclose(f) == 0 && n == sizeof(expected) && extra == EOF &&
             memcmp(actual, expected, sizeof(expected)) == 0;
    return ok;
}

static int corrupt_latest_sstable(const char* data_dir) {
    char newest[4096];
    if (count_sstables(data_dir, newest, sizeof(newest)) < 1) return 0;
    int fd = open(newest, O_WRONLY | O_CLOEXEC);
    static const char bad_header[] = "broken header\n";
    if (fd < 0) return 0;
    bool ok = pwrite(fd, bad_header, sizeof(bad_header) - 1u, 0) ==
              (ssize_t)(sizeof(bad_header) - 1u) && fsync(fd) == 0;
    close(fd);
    return ok;
}

static int owner_export_child(void) {
    char data_dir[] = "build/test_kv_owner_export_corrupt_XXXXXX";
    if (!mkdtemp(data_dir) || setenv("QIHSE_DATA_DIR", data_dir, 1) != 0 ||
        !qihse_auth_init()) return 1;
    qihse_user_t* op = qihse_auth_get_user(0);
    qihse_user_t* service = op ? qihse_auth_create_user(op, 9402u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "CorruptExportService1!", false) : NULL;
    qihse_kv_store_t* store = op ? qihse_kv_store_create_user(op) : NULL;
    if (!op || !service || !store) return 1;
    char* value = malloc(8193u);
    if (!value) return 1;
    memset(value, 'o', 8192u); value[8192] = '\0';
    char key[80];
    for (int round = 0; round < 20; ++round) {
        for (int i = 0; i < 80; ++i) {
            snprintf(key, sizeof(key), "owner-corrupt:%d:%d", round, i);
            if (!qihse_kv_set_user(store, key, value, 0u, 0u, op)) return 1;
        }
    }
    free(value);
    if (!qihse_kv_sync_store(store)) return 1;
    qihse_kv_store_set_replication_principal_id(store, 9402u);
    if (!qihse_kv_ct_source_enable(store, op, "owner-source", "owner-target",
                                   "owner-generation", NULL,
                                   128u * 1024u * 1024u)) return 1;
    qihse_kv_replica_snapshot_t* baseline = NULL;
    uint64_t baseline_seq = 0u;
    unsigned char digest[32];
    if (qihse_kv_ct_source_baseline_snapshot_create(store, op, &baseline,
            &baseline_seq, digest) != 0 || !baseline) return 1;
    qihse_kv_replica_snapshot_destroy(baseline);
    if (!qihse_kv_ct_source_reconcile_peer(store, op, service, "owner-target",
            "owner-generation", digest, 0u) || !corrupt_latest_sstable(data_dir)) return 1;

    qihse_kv_replica_snapshot_t* owner_snapshot = NULL;
    int rc = qihse_kv_ct_owner_data_snapshot_create(store, op, &owner_snapshot);
    if (rc == 0) {
        qihse_kv_replica_snapshot_destroy(owner_snapshot);
        fprintf(stderr, "corrupt SSTable produced a partial owner-data snapshot\n");
        qihse_kv_store_destroy(store);
        return 1;
    }
    qihse_kv_store_destroy(store);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "owner") == 0) return owner_export_child();
    if (argc != 1) return 2;
    char data_dir[] = "build/test_kv_compaction_corrupt_XXXXXX";
    if (!mkdtemp(data_dir)) { perror("mkdtemp"); return 1; }
    if (setenv("QIHSE_DATA_DIR", data_dir, 1) != 0 || !qihse_auth_init()) {
        fprintf(stderr, "test setup failed\n"); return 1;
    }
    qihse_user_t* user = qihse_auth_get_user(0);
    qihse_kv_store_t* store = user ? qihse_kv_store_create_user(user) : NULL;
    if (!store) { fprintf(stderr, "store create failed\n"); return 1; }
    char* value = malloc(8193u);
    if (!value) return 1;
    memset(value, 'c', 8192u); value[8192] = '\0';
    char key[80];
    for (int round = 0; round < 20; ++round) {
        for (int i = 0; i < 80; ++i) {
            snprintf(key, sizeof(key), "corrupt-compact:%d:%d", round, i);
            if (!qihse_kv_set_user(store, key, value, 0u, 0u, user)) {
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
    if (!corrupt_latest_sstable(data_dir)) { fprintf(stderr, "could not corrupt newest SSTable\n"); return 1; }

    /* Full snapshots must not replace a previously valid destination with
     * a partial export after the shared SST iterator skips a malformed row. */
    char export_path[4096];
    int path_n = snprintf(export_path, sizeof(export_path), "%s/snapshot.bin", data_dir);
    if (path_n < 0 || (size_t)path_n >= sizeof(export_path) ||
        !write_sentinel(export_path)) {
        fprintf(stderr, "could not create preexisting snapshot fixture\n"); return 1;
    }
    int export_failure = 0;
    if (qihse_kv_save_user(store, export_path, user) == 0 ||
        !sentinel_unchanged(export_path)) {
        fprintf(stderr, "corrupt SSTable published a partial full snapshot\n");
        export_failure = 1;
    }

    if (!write_sentinel(export_path)) return 1;
    qihse_kv_replica_snapshot_t* replica_snapshot = NULL;
    if (qihse_kv_replica_snapshot_create(store, user, "*", &replica_snapshot) == 0) {
        qihse_kv_replica_snapshot_destroy(replica_snapshot);
        fprintf(stderr, "corrupt SSTable produced a partial replica snapshot\n");
        export_failure = 1;
    }

    if (!write_sentinel(export_path)) return 1;
    uint64_t resume_seq = UINT64_MAX;
    if (qihse_kv_save_delta_user(store, export_path, user, 0u, &resume_seq) == 0 ||
        !sentinel_unchanged(export_path)) {
        fprintf(stderr, "corrupt SSTable published a partial delta snapshot\n");
        export_failure = 1;
    }

    qihse_kv_sweep_expired(store);
    char still_newest[4096];
    int after = count_sstables(data_dir, still_newest, sizeof(still_newest));
    qihse_kv_store_destroy(store);
    free(value);
    int compaction_failure = after < 0 || after != before ||
        (after > 0 && strcmp(newest, still_newest) != 0);
    if (compaction_failure) {
        fprintf(stderr, "compaction discarded damaged inputs: files %d -> %d\n",
                before, after);
    }
    char* self_argv[] = { argv[0], "owner", NULL };
    pid_t child = fork();
    int owner_status = -1;
    if (child == 0) { execv(argv[0], self_argv); _exit(127); }
    if (child > 0 && waitpid(child, &owner_status, 0) == child &&
        WIFEXITED(owner_status)) owner_status = WEXITSTATUS(owner_status);
    if (export_failure || compaction_failure || owner_status != 0) return 1;
    puts("corrupt compaction input was retained without replacement");
    return 0;
}
