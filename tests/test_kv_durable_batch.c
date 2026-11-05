#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* Build with the store source, QIHSE_AIMEM_DURABILITY_TEST, and linker flags
 * --wrap=fdatasync --wrap=fflush. No hooks are present in production builds. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_kv_store.h"

#define PASSWORD "DurableBatchOperator1!"
#define EXPIRY UINT64_C(4000000000000)
static bool measuring, fail_sync, fail_flush;
static unsigned sync_calls, flush_calls;
int __real_fdatasync(int fd);
int __wrap_fdatasync(int fd) {
    if (measuring) {
        sync_calls++;
        if (fail_sync) { errno = EIO; return -1; }
    }
    return __real_fdatasync(fd);
}
int __real_fflush(FILE* f);
int __wrap_fflush(FILE* f) {
    if (measuring) {
        flush_calls++;
        if (fail_flush) { errno = EIO; return EOF; }
    }
    return __real_fflush(f);
}
static bool batch(qihse_kv_store_t* s, const qihse_kv_batch_set_record_t* r,
                  size_t n, qihse_user_t* u) {
    sync_calls = flush_calls = 0u;
    measuring = true;
    bool ok = qihse_kv_set_batch_durable_user(s, r, n, u);
    measuring = false;
    return ok;
}
static off_t wal_size(const char* dir) {
    char path[1024];
    assert(snprintf(path, sizeof(path), "%s/wal.log", dir) > 0);
    struct stat st; assert(stat(path, &st) == 0); return st.st_size;
}
static void value_is(qihse_kv_store_t* s, qihse_user_t* u,
                     const char* k, const char* expected) {
    char* v = qihse_kv_get_user(s, k, u);
    assert(expected ? v && strcmp(v, expected) == 0 : v == NULL);
    free(v);
}
static void refused(qihse_kv_store_t* s, const char* dir,
                    const qihse_kv_batch_set_record_t* r, size_t n,
                    qihse_user_t* u) {
    uint64_t seq = qihse_kv_change_seq(s);
    off_t bytes = wal_size(dir);
    assert(!batch(s, r, n, u));
    assert(sync_calls == 0u && flush_calls == 0u);
    assert(qihse_kv_change_seq(s) == seq && wal_size(dir) == bytes);
}
static void fenced(qihse_kv_store_t* s, qihse_user_t* u,
                   const qihse_kv_batch_set_record_t* r) {
    value_is(s, u, "before", NULL);
    assert(!qihse_kv_set_user(s, "later", "no", 0u, 0u, u));
    assert(!qihse_kv_del_user(s, "before", u));
    assert(!qihse_kv_expire(s, "before", 1000u, u));
    assert(!qihse_kv_sync_store(s));
    assert(!qihse_kv_exists_user(s, "before", u));
    qihse_kv_record_meta_t meta;
    assert(!qihse_kv_meta_user(s, "before", u, &meta));
    qihse_kv_sstable_stats_t stats;
    assert(!qihse_kv_sstable_stats(s, &stats));
    assert(qihse_kv_count_user(s, u) == 0u);
    assert(qihse_kv_change_seq(s) == 0u);
    assert(qihse_kv_instance_id(s) == 0u);
    assert(qihse_kv_projection_epoch(s) == 0u);
    assert(qihse_kv_store_data_directory(s) == NULL);
    assert(!qihse_kv_store_enable_replica_read_only(s));
    assert(!batch(s, r, 1u, u) && sync_calls == 0u && flush_calls == 0u);
    qihse_kv_bulk_load_begin(s); qihse_kv_bulk_load_end(s);
    assert(!qihse_kv_set_user(s, "later", "no", 0u, 0u, u));
}
static void scenario(const char* mode, const char* dir) {
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t* op = qihse_auth_authenticate_id(0u, PASSWORD); assert(op);
    qihse_kv_store_t* s = qihse_kv_store_create_user(op); assert(s);
    qihse_kv_batch_set_record_t r[] = {
        {"one", "first", EXPIRY, 4u, 2u},
        {"two", "second", 0u, 0u, 0u},
        {"expired", "gone", 1u, 0u, 0u}
    };
    if (strcmp(mode, "success") == 0) {
        /* Exceed both ordinary flush thresholds; WAL must remain intact. */
        char* large = malloc(600001u); assert(large);
        memset(large, 'x', 600000u); large[600000u] = '\0';
        r[1].value = large;
        assert(batch(s, r, 3u, op));
        assert(sync_calls == 1u && flush_calls == 1u);
        assert(wal_size(dir) == (off_t)(120u + 13u + 5u + 600000u + 4u));
        qihse_kv_sstable_stats_t stats; assert(qihse_kv_sstable_stats(s, &stats));
        assert(stats.live_sstable_files == 0u);
        qihse_kv_record_meta_t m; assert(qihse_kv_meta_user(s, "one", op, &m));
        assert(m.expire_time_ms == EXPIRY && m.classification == 4u &&
               m.sci_compartment == 2u && m.change_seq == 1u);
        assert(qihse_kv_change_seq(s) == 3u);
        qihse_kv_store_destroy(s);
        s = qihse_kv_store_create_user(op); assert(s);
        value_is(s, op, "one", "first"); value_is(s, op, "two", large);
        value_is(s, op, "expired", NULL);
        assert(qihse_kv_meta_user(s, "one", op, &m) && m.change_seq == 1u &&
               m.expire_time_ms == EXPIRY && m.classification == 4u && m.sci_compartment == 2u);
        assert(qihse_kv_change_seq(s) == 3u);
        r[0].value = "replacement";
        assert(batch(s, r, 1u, op) && sync_calls == 1u && flush_calls == 1u);
        assert(qihse_kv_change_seq(s) == 4u);
        free(large);
    } else if (strcmp(mode, "auth") == 0) {
        qihse_user_t* low = qihse_auth_create_user(op, 42u, QIHSE_ROLE_ANALYST,
                                                   0u, 0u, PASSWORD, false); assert(low);
        qihse_user_t* no_sci = qihse_auth_create_user(op, 43u, QIHSE_ROLE_ANALYST,
                                                      4u, 0u, PASSWORD, false); assert(no_sci);
        assert(batch(s, r, 1u, op));
        r[0] = (qihse_kv_batch_set_record_t){"public", "allowed", 0u, 0u, 0u};
        r[1] = (qihse_kv_batch_set_record_t){"one", "downgrade", 0u, 0u, 0u};
        refused(s, dir, r, 2u, low); refused(s, dir, r, 2u, no_sci);
        value_is(s, op, "public", NULL); value_is(s, op, "one", "first");
        assert(qihse_kv_sync_store(s)); /* Also enforce overwrite auth on SST metadata. */
        refused(s, dir, r, 2u, low);
        assert(qihse_kv_del_user(s, "one", op));
        refused(s, dir, r, 2u, low); /* Tombstones retain overwrite labels. */
        r[1] = (qihse_kv_batch_set_record_t){"new-secret", "hidden", 0u, 4u, 2u};
        refused(s, dir, r, 2u, low); refused(s, dir, r, 2u, no_sci);
        refused(s, dir, r, 1u, NULL);
        assert(qihse_auth_destroy_user(op, 42u)); refused(s, dir, r, 1u, low);
        value_is(s, op, "public", NULL); value_is(s, op, "new-secret", NULL);
        qihse_kv_store_destroy(s); s = qihse_kv_store_create_user(op); assert(s);
        value_is(s, op, "public", NULL); value_is(s, op, "one", NULL);
    } else if (strcmp(mode, "bounds") == 0) {
        refused(s, dir, r, 0u, op); refused(s, dir, NULL, 1u, op);
        refused(s, dir, r, 4097u, op);
        r[1].key = r[0].key; refused(s, dir, r, 2u, op);
        r[1].key = ""; refused(s, dir, r, 2u, op);
        r[1].key = NULL; refused(s, dir, r, 2u, op);
        r[1].key = "two"; r[1].value = NULL; refused(s, dir, r, 2u, op);
        char* long_key = malloc(65537u); assert(long_key);
        memset(long_key, 'k', 65536u); long_key[65536u] = '\0';
        r[1].key = long_key; r[1].value = "v"; refused(s, dir, r, 2u, op); free(long_key);
        char* large = malloc(16u * 1024u * 1024u + 2u); assert(large);
        memset(large, 'v', 16u * 1024u * 1024u + 1u); large[16u * 1024u * 1024u + 1u] = '\0';
        r[1].key = "two"; r[1].value = large; refused(s, dir, r, 2u, op);
        large[16u * 1024u * 1024u] = '\0';
        qihse_kv_batch_set_record_t huge[4] = {
            {"a", large, 0u, 0u, 0u}, {"b", large, 0u, 0u, 0u},
            {"c", large, 0u, 0u, 0u}, {"d", large, 0u, 0u, 0u}
        };
        refused(s, dir, huge, 4u, op);
        huge[3].value = large + 164u; /* Four 40-byte headers and one-byte keys. */
        assert(batch(s, huge, 4u, op) && sync_calls == 1u && flush_calls == 1u);
        assert(wal_size(dir) == QIHSE_KV_DURABLE_BATCH_MAX_BYTES);
        free(large);
        qihse_kv_batch_set_record_t* many = calloc(4096u, sizeof(*many)); assert(many);
        char (*keys)[16] = calloc(4096u, sizeof(*keys)); assert(keys);
        for (size_t i = 0u; i < 4096u; i++) {
            snprintf(keys[i], sizeof(keys[i]), "key-%zu", i);
            many[i] = (qihse_kv_batch_set_record_t){keys[i], "", 0u, 0u, 0u};
        }
        assert(batch(s, many, 4096u, op) && sync_calls == 1u && flush_calls == 1u);
        assert(qihse_kv_count_user(s, op) == 4100u); free(keys); free(many);
    } else if (strcmp(mode, "modes") == 0) {
        qihse_kv_bulk_load_begin(s); refused(s, dir, r, 1u, op);
        value_is(s, op, "one", NULL);
        qihse_kv_bulk_load_end(s);
        assert(batch(s, r, 1u, op) && wal_size(dir) > 0);
        assert(qihse_kv_store_enable_replica_read_only(s));
        refused(s, dir, r, 1u, op);
    } else {
        assert(qihse_kv_set_user(s, "before", "retain", 0u, 0u, op));
        fail_sync = strcmp(mode, "fdatasync") == 0;
        fail_flush = strcmp(mode, "fflush") == 0;
        if (!fail_sync && !fail_flush) assert(setenv("QIHSE_AIMEM_FAIL_AT", mode, 1) == 0);
        assert(!batch(s, r, 3u, op));
        assert(sync_calls == (fail_sync ? 1u : 0u));
        assert(flush_calls == (fail_sync || fail_flush ? 1u : 0u));
        fenced(s, op, r);
        fail_sync = fail_flush = false;
        qihse_kv_store_destroy(s);
        assert(unsetenv("QIHSE_AIMEM_FAIL_AT") == 0);
        s = qihse_kv_store_create_user(op); assert(s);
        value_is(s, op, "before", "retain"); value_is(s, op, "later", NULL);
        if (strcmp(mode, "fdatasync") == 0 || strcmp(mode, "fflush") == 0) {
            value_is(s, op, "one", "first"); value_is(s, op, "two", "second");
        }
        assert(batch(s, r, 1u, op) && sync_calls == 1u);
    }
    qihse_kv_store_destroy(s);
}
static void remove_fixture(const char* dir) {
    DIR* d = opendir(dir); assert(d); struct dirent* e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char path[2048]; snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        assert(unlink(path) == 0);
    }
    assert(closedir(d) == 0 && rmdir(dir) == 0);
}
int main(void) {
    const char* cases[] = {"success", "auth", "bounds", "modes", "fdatasync", "fflush",
                           "wal-partial-header", "wal-write-header", "wal-write-key", "wal-write-value"};
    for (size_t i = 0u; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char dir[] = "./build/kv-durable-batch-XXXXXX"; assert(mkdtemp(dir));
        pid_t pid = fork(); assert(pid >= 0);
        if (pid == 0) { scenario(cases[i], dir); _exit(0); }
        int status; assert(waitpid(pid, &status, 0) == pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            fprintf(stderr, "durable batch %s failed: status=%d\n", cases[i], status);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        remove_fixture(dir);
    }
    puts("durable KV batch: 10 scenarios passed");
    return 0;
}
