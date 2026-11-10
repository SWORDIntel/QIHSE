/* Private-unit fault injection: a degraded metadata index must not make a
 * read/export retire the database's durable SSTables. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../src/black_hole/qihse_kv_store.c"
#include "qihse_audit.h"
#include <assert.h>
#include <ftw.h>
#include <sys/wait.h>

static void fixture_auth(const char* directory) {
    assert(setenv("QIHSE_DATA_DIR", directory, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DegradedRecoveryOperator123!"));
}

static int seed_and_export(const char* directory) {
    fixture_auth(directory);
    qihse_user_t* user = qihse_auth_get_user(0u);
    qihse_kv_store_t* store = qihse_kv_store_create_user(user);
    assert(store);
    char value[8193]; memset(value, 'd', sizeof(value)-1); value[sizeof(value)-1] = 0;
    assert(qihse_kv_set_user(store, "degraded:durable", "must survive", 0u, 0u, user));
    for (unsigned i = 0; i < 180; ++i) {
        char key[64]; snprintf(key, sizeof(key), "degraded:filler:%u", i);
        assert(qihse_kv_set_user(store, key, value, 0u, 0u, user));
    }
    assert(qihse_kv_sync_store(store) && store->sstable_counter > 0);
    /* Simulate an allocation failure in the optional metadata index, after
     * durable data has already left the WAL and moved to SSTables. */
    store->sst_meta->degraded = true;
    char export_path[4096];
    assert(snprintf(export_path, sizeof(export_path), "%s/read-copy.qfs", directory) <
           (int)sizeof(export_path));
    assert(qihse_kv_save_user(store, export_path, user) == 0);
    _exit(0); /* no destructor/flush: exercise restart at the read boundary */
}

static int remove_fixture(const char* path, const struct stat* info, int kind,
                          struct FTW* walk) {
    (void)info; (void)walk;
    return kind == FTW_D || kind == FTW_DP ? rmdir(path) : unlink(path);
}

int main(int argc, char** argv) {
    if (argc == 3 && !strcmp(argv[1], "seed")) return seed_and_export(argv[2]);
    assert(argc == 1);
    char directory[] = "build/test_kv_degraded_recovery_XXXXXX";
    assert(mkdtemp(directory));
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        execl(argv[0], argv[0], "seed", directory, (char*)NULL);
        _exit(127);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    fixture_auth(directory);
    qihse_user_t* user = qihse_auth_get_user(0u);
    qihse_kv_store_t* store = qihse_kv_store_create_user(user);
    assert(store);
    char* value = qihse_kv_get_user(store, "degraded:durable", user);
    if (!value || strcmp(value, "must survive")) {
        fprintf(stderr, "degraded read/export discarded durable SST data: %s\n", directory);
        return 1;
    }
    free(value);
    qihse_kv_store_destroy(store);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(directory, remove_fixture, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("PASS degraded read/export crash preserves durable SST records");
    return 0;
}
