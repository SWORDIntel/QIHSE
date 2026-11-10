#define _GNU_SOURCE
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "aimem_fixture_cleanup.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned char* read_file(const char* path, size_t* out_size) {
    *out_size = 0u;
    FILE* file = fopen(path, "rb");
    assert(file);
    assert(fseeko(file, 0, SEEK_END) == 0);
    off_t length = ftello(file);
    assert(length >= 0);
    assert(fseeko(file, 0, SEEK_SET) == 0);
    unsigned char* bytes = malloc(length ? (size_t)length : 1u);
    assert(bytes);
    assert(fread(bytes, 1u, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    *out_size = (size_t)length;
    return bytes;
}

static void append_tail(const char* path) {
    FILE* file = fopen(path, "ab");
    assert(file);
    assert(fwrite("QKV", 1u, 3u, file) == 3u);
    assert(fflush(file) == 0);
    assert(fclose(file) == 0);
}

int main(void) {
    char data_dir[] = "./tests/wal_replay_apply_XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("WalReplayOperator1!"));
    qihse_user_t* operator_user = qihse_auth_authenticate_id(0u,
        "WalReplayOperator1!");
    assert(operator_user);

    qihse_kv_store_t* store = qihse_kv_store_create_user(operator_user);
    assert(store);
    assert(qihse_kv_set_user(store, "wal-replay-apply", "committed", 0u, 0u,
                             operator_user));
    assert(qihse_kv_set_user(store, "wal-replay-apply-second", "also-committed",
                             0u, 0u, operator_user));
    qihse_kv_store_destroy(store);

    char wal_path[512];
    int n = snprintf(wal_path, sizeof(wal_path), "%s/wal.log", data_dir);
    assert(n > 0 && (size_t)n < sizeof(wal_path));
    size_t before_size = 0u;
    unsigned char* before = read_file(wal_path, &before_size);
    assert(before_size > 0u);

    /* Simulate an apply-time allocation/state failure after a complete valid
     * frame has been read and checked. Recovery must fail without classifying
     * the committed frame as a torn tail or truncating any WAL bytes. */
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "wal-replay-apply-second", 1) == 0);
    assert(qihse_kv_store_create_user(operator_user) == NULL);
    size_t after_size = 0u;
    unsigned char* after = read_file(wal_path, &after_size);
    assert(after_size == before_size && memcmp(after, before, before_size) == 0);
    char sstable_path[512];
    n = snprintf(sstable_path, sizeof(sstable_path), "%s/sstable_0.db", data_dir);
    assert(n > 0 && (size_t)n < sizeof(sstable_path));
    assert(access(sstable_path, F_OK) != 0);
    free(after);
    free(before);
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);

    /* A later retry consumes the same preserved committed frame. */
    store = qihse_kv_store_create_user(operator_user);
    assert(store);
    char* value = qihse_kv_get_user(store, "wal-replay-apply", operator_user);
    assert(value && strcmp(value, "committed") == 0);
    free(value);
    value = qihse_kv_get_user(store, "wal-replay-apply-second", operator_user);
    assert(value && strcmp(value, "also-committed") == 0);
    free(value);
    qihse_kv_store_destroy(store);

    /* A read error while examining a malformed tail must leave the entire WAL
     * untouched. Only a subsequent healthy startup may repair the tail. */
    append_tail(wal_path);
    before = read_file(wal_path, &before_size);
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "wal-replay-read", 1) == 0);
    assert(qihse_kv_store_create_user(operator_user) == NULL);
    after = read_file(wal_path, &after_size);
    assert(after_size == before_size && memcmp(after, before, before_size) == 0);
    free(after);
    free(before);

    before = read_file(wal_path, &before_size);
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "wal-tail-truncate", 1) == 0);
    assert(qihse_kv_store_create_user(operator_user) == NULL);
    after = read_file(wal_path, &after_size);
    assert(after_size == before_size && memcmp(after, before, before_size) == 0);
    free(after);
    free(before);

    /* Tail truncation is not considered complete until its fsync succeeds. */
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "wal-tail-fsync", 1) == 0);
    assert(qihse_kv_store_create_user(operator_user) == NULL);
    assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
    store = qihse_kv_store_create_user(operator_user);
    assert(store);
    value = qihse_kv_get_user(store, "wal-replay-apply", operator_user);
    assert(value && strcmp(value, "committed") == 0);
    free(value);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(data_dir);
    puts("PASS WAL apply failure preserves committed frame for retry");
    return 0;
}
