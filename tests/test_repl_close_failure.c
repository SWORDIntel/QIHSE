#include "qihse_kv_store.h"
#include "qihse_repl.h"
#include "qihse_wal.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct qihse_kv_store {
    char key[64];
    char value[64];
    unsigned deletes;
};

static int inject_directory_close;
static unsigned injected_close_count;

int qihse_test_close(int fd) {
    struct stat st;
    if (inject_directory_close && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        inject_directory_close = 0;
        injected_close_count++;
        (void)syscall(SYS_close, fd); /* released descriptor, reported EINTR */
        errno = EINTR;
        return -1;
    }
    return (int)syscall(SYS_close, fd);
}

bool qihse_kv_set(qihse_kv_store_t *opaque, const char *key, const char *value,
                  uint16_t classification, uint16_t sci_compartment) {
    (void)classification;
    (void)sci_compartment;
    struct qihse_kv_store *store = (struct qihse_kv_store *)opaque;
    snprintf(store->key, sizeof(store->key), "%s", key);
    snprintf(store->value, sizeof(store->value), "%s", value);
    return true;
}

bool qihse_kv_del_user(qihse_kv_store_t *opaque, const char *key,
                       qihse_user_t *user) {
    (void)user;
    struct qihse_kv_store *store = (struct qihse_kv_store *)opaque;
    if (strcmp(store->key, key) != 0) return false;
    store->key[0] = '\0';
    store->value[0] = '\0';
    store->deletes++;
    return true;
}

static void remove_temp_dir(const char *path) {
    DIR *dir = opendir(path);
    assert(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[512];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        assert(n > 0 && (size_t)n < sizeof(child));
        struct stat st;
        assert(lstat(child, &st) == 0);
        if (S_ISDIR(st.st_mode)) remove_temp_dir(child);
        else assert(unlink(child) == 0);
    }
    assert(closedir(dir) == 0);
    assert(rmdir(path) == 0);
}

int main(void) {
    char root[] = "tests/qihse-repl-close-XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("TMPDIR", root, 1) == 0);
    const char key[] = "replica:delete-retry";

    char input_dir[512];
    assert(snprintf(input_dir, sizeof(input_dir), "%s/input", root) <
           (int)sizeof(input_dir));
    assert(mkdir(input_dir, 0700) == 0);
    qihse_wal_t *input = qihse_wal_create(input_dir, 4096,
                                         QIHSE_WAL_DURABILITY_NONE);
    assert(input);
    uint64_t lsn = qihse_wal_append(input, 1, 0, QIHSE_WAL_OP_DELETE,
                                    key, (uint32_t)strlen(key), NULL, 0);
    assert(lsn != QIHSE_WAL_INVALID_LSN);
    char segment[512];
    assert(snprintf(segment, sizeof(segment), "%s/wal_%020lu.log",
                    input_dir, 0ul) < (int)sizeof(segment));
    assert(qihse_wal_destroy_checked(input) == 0);
    int fd = open(segment, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    uint8_t record[256];
    ssize_t record_len = read(fd, record, sizeof(record));
    assert(record_len > (ssize_t)QIHSE_WAL_RECORD_HEADER_SIZE);
    assert(close(fd) == 0);
    assert(unlink(segment) == 0 && rmdir(input_dir) == 0);

    struct qihse_kv_store store = {{0}, {0}, 0};
    snprintf(store.key, sizeof(store.key), "%s", key);
    snprintf(store.value, sizeof(store.value), "present");
    qihse_repl_context_t *ctx = qihse_repl_create(REPL_ROLE_REPLICA);
    assert(ctx && qihse_repl_set_store(ctx, (qihse_kv_store_t *)&store) == 0);

    /* Inject a failure on the staging WAL's directory-fd close, after record
     * replay. The delete must not happen and the LSN must remain retryable. */
    inject_directory_close = 1;
    assert(qihse_repl_apply_wal(ctx, record, (size_t)record_len, lsn) == -1);
    assert(injected_close_count == 1);
    assert(store.deletes == 0 && !strcmp(store.value, "present"));
    uint64_t last = 0, flush = 0;
    repl_state_t state;
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0 && flush == 0);

    assert(qihse_repl_apply_wal(ctx, record, (size_t)record_len, lsn) == 0);
    assert(store.deletes == 1 && store.key[0] == '\0');
    assert(qihse_repl_apply_wal(ctx, record, (size_t)record_len, lsn) == 0);
    assert(store.deletes == 1);
    assert(qihse_repl_get_status(ctx, &last, &flush, &state) == 0 && flush == lsn);

    qihse_repl_destroy(ctx);
    remove_temp_dir(root);
    puts("replica DELETE retry after checked-close failure passed");
    return 0;
}
