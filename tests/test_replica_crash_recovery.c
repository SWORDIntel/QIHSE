#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"

#define OPERATOR_PASSWORD "CrashTestOperatorPass1!"
#define SNAPSHOT_HIGHWATER 1u

static void make_dir(const char* path) { assert(mkdir(path, 0700) == 0); }

static void write_file(const char* path, const void* bytes, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    assert(fd >= 0);
    size_t done = 0u;
    while (done < len) {
        ssize_t n = write(fd, (const char*)bytes + done, len - done);
        assert(n > 0); done += (size_t)n;
    }
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
}

static qihse_user_t* bootstrap(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    return op;
}

static void prepare_snapshot(const char* root) {
    char source[512], filepath[512];
    snprintf(source, sizeof(source), "%s/source", root); make_dir(source);
    assert(setenv("QIHSE_DATA_DIR", source, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    qihse_user_t* op = bootstrap();
    qihse_kv_store_t* store = qihse_kv_store_create(); assert(store);
    assert(qihse_kv_set_user(store, "public:crash-row", "recovered-value", 0u, 0u, op));
    assert(qihse_kv_change_seq(store) == SNAPSHOT_HIGHWATER);
    qihse_kv_replica_snapshot_t* snapshot = NULL;
    assert(qihse_kv_replica_snapshot_create(store, op, "public:*", &snapshot) == 0);
    uint64_t size = qihse_kv_replica_snapshot_size(snapshot);
    assert(size > 0u && size < 1024u);
    uint8_t bytes[1024]; size_t read_size = 0u;
    assert(qihse_kv_replica_snapshot_read(snapshot, 0u, bytes, (size_t)size, &read_size));
    assert(read_size == (size_t)size);
    snprintf(filepath, sizeof(filepath), "%s/snapshot.qkv", root);
    write_file(filepath, bytes, read_size);
    qihse_kv_replica_snapshot_destroy(snapshot);
    qihse_kv_store_destroy(store);
}

static int child_main(const char* mode, const char* root, const char* point,
                      const char* data_dir) {
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    qihse_user_t* op = bootstrap();
    if (strcmp(mode, "install") == 0) {
        assert(setenv("QIHSE_REPLICA_CRASH_AT", point, 1) == 0);
        qihse_kv_store_t* store = qihse_kv_store_create(); assert(store);
        assert(qihse_kv_store_enable_replica_read_only(store));
        char snapshot[512]; snprintf(snapshot, sizeof(snapshot), "%s/snapshot.qkv", root);
        (void)qihse_kv_replica_snapshot_install(store, snapshot, op,
            "crash-peer", "public:*", SNAPSHOT_HIGHWATER);
        fprintf(stderr, "crash failpoint '%s' was not reached\n", point);
        return 1;
    }
    assert(strcmp(mode, "recover") == 0);
    assert(unsetenv("QIHSE_REPLICA_CRASH_AT") == 0);
    qihse_kv_store_t* store = qihse_kv_store_create(); assert(store);
    bool installed = false;
    assert(qihse_kv_replica_snapshot_installed(store, "crash-peer", "public:*",
                                                op, &installed));
    if (strcmp(point, "image") == 0) {
        assert(!installed);
        assert(qihse_kv_count_user(store, op) == 0u);
        uint64_t cursor = 0u;
        assert(qihse_kv_replica_cursor_get(store, "crash-peer", "public:*", op, &cursor));
        assert(cursor == 0u);
    } else {
        assert(installed);
        uint64_t cursor = 0u;
        assert(qihse_kv_replica_cursor_get(store, "crash-peer", "public:*", op, &cursor));
        assert(cursor == SNAPSHOT_HIGHWATER);
        char* value = qihse_kv_get_user(store, "public:crash-row", op);
        assert(value && strcmp(value, "recovered-value") == 0);
        free(value);
        char meta[512]; snprintf(meta, sizeof(meta), "%s/replica-install.meta", data_dir);
        assert(access(meta, F_OK) != 0 && errno == ENOENT);
    }
    qihse_kv_store_destroy(store);
    return 0;
}

static int run_child(const char* self, const char* mode, const char* root,
                     const char* point, const char* data_dir) {
    pid_t pid = fork(); assert(pid >= 0);
    if (pid == 0) {
        execl(self, self, "--child", mode, root, point, data_dir, (char*)NULL);
        _exit(127);
    }
    int status = 0; assert(waitpid(pid, &status, 0) == pid);
    if (strcmp(mode, "install") == 0)
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 6 && strcmp(argv[1], "--child") == 0)
        return child_main(argv[2], argv[3], argv[4], argv[5]);
    assert(argc == 1);
    const char* root = getenv("QIHSE_REPLICA_CRASH_DIR"); assert(root && *root);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    prepare_snapshot(root);
    static const char* points[] = {
        "image", "intent", "wal-replaced", "sst-wal-durable",
        "cursor-durable", "marker-durable", "journal-removed"
    };
    for (size_t i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
        char data_dir[512]; snprintf(data_dir, sizeof(data_dir), "%s/data-%zu", root, i);
        make_dir(data_dir);
        assert(run_child(argv[0], "install", root, points[i], data_dir) == 86);
        run_child(argv[0], "recover", root, points[i], data_dir);
    }
    puts("replica snapshot install kill/restart boundaries: 7 PASS");
    return 0;
}
