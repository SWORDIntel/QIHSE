#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <ftw.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "qihse_auth.h"
#include "qihse_kv_store.h"

#define PASSWORD "ChangeMetaAuth1!"

static void denied(qihse_kv_store_t *store, const char *key, qihse_user_t *user) {
    qihse_kv_change_meta_t meta;
    memset(&meta, 0xa5, sizeof(meta));
    assert(!qihse_kv_change_meta_user(store, key, user, &meta));
    assert(meta.change_seq == 0u && meta.classification == 0u &&
           meta.sci_compartment == 0u && !meta.tombstone);
}

static int remove_entry(const char *path, const struct stat *st, int type,
                        struct FTW *ftw) {
    (void)st; (void)type; (void)ftw;
    return remove(path);
}

static void scenario(const char *dir) {
    assert(chdir(dir) == 0);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0u, PASSWORD);
    assert(op);
    qihse_user_t *low = qihse_auth_create_user(op, 91u, QIHSE_ROLE_ANALYST,
                                               0u, 0u, PASSWORD, false);
    qihse_user_t *no_sci = qihse_auth_create_user(op, 92u, QIHSE_ROLE_ANALYST,
                                                  4u, 0u, PASSWORD, false);
    qihse_user_t *high = qihse_auth_create_user(op, 93u, QIHSE_ROLE_ANALYST,
                                                4u, 2u, PASSWORD, false);
    assert(low && no_sci && high);
    qihse_kv_store_t *store = qihse_kv_store_create_user(op);
    assert(store);

    uint64_t live_seq = 0u, delete_seq = 0u;
    assert(qihse_kv_set_user_with_seq(store, "secret", "value", 4u, 2u,
                                      op, &live_seq));
    assert(live_seq > 0u);
    qihse_kv_change_meta_t meta;
    assert(qihse_kv_change_meta_user(store, "secret", high, &meta));
    assert(meta.change_seq == live_seq && meta.classification == 4u &&
           meta.sci_compartment == 2u && !meta.tombstone);
    denied(store, "secret", low);
    denied(store, "secret", no_sci);
    denied(store, "secret", NULL);
    denied(store, "missing", op);

    assert(qihse_kv_del_user_with_seq(store, "secret", op, &delete_seq));
    assert(delete_seq > live_seq);
    assert(qihse_kv_change_meta_user(store, "secret", high, &meta));
    assert(meta.change_seq == delete_seq && meta.classification == 4u &&
           meta.sci_compartment == 2u && meta.tombstone);
    denied(store, "secret", low);
    denied(store, "secret", no_sci);
    denied(store, "secret", NULL);
    denied(NULL, "secret", op);
    denied(store, NULL, op);
    assert(qihse_auth_destroy_user(op, 93u));
    denied(store, "secret", high);

    qihse_kv_store_destroy(store);
}

int main(void) {
    umask(0077);
    assert(mkdir("build", 0700) == 0 || access("build", F_OK) == 0);
    char temp[] = "build/kv-change-meta-auth-XXXXXX";
    assert(mkdtemp(temp));
    char *dir = realpath(temp, NULL);
    assert(dir);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        scenario(dir);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(nftw(dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    free(dir);
    puts("kv change metadata auth: PASS");
    return 0;
}
