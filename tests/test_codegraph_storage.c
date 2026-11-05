#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_codegraph_storage.h"
#include <assert.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define PASSWORD "CodegraphCodecOperator1!"
static void value_is(qihse_kv_store_t *s, qihse_user_t *u, const char *key, const char *wanted) {
    char *v = qihse_kv_get_user(s, key, u);
    assert(wanted ? v && strcmp(v, wanted) == 0 : v == NULL);
    free(v);
}
static int clean_test(const char *path, const struct stat *st, int type, struct FTW *walk) {
    (void)st; (void)type; (void)walk; return remove(path);
}
int main(void) {
    char root[4096];
    const char *temporary = getenv("TMPDIR");
    assert(snprintf(root, sizeof(root), "%s/qihse-codegraph-codec-test-XXXXXX",
                    temporary && *temporary ? temporary : ".") < (int)sizeof(root));
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
    qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD); assert(op);
    assert(qihse_auth_create_user(op, 71, QIHSE_ROLE_ANALYST, 0, 0, PASSWORD, false));
    qihse_user_t *low = qihse_auth_authenticate_id(71, PASSWORD); assert(low);
    qihse_kv_store_t *s = qihse_kv_store_create_user(op); assert(s);
    const char *json = "{\"traversable\":false,\"extra\":{\"future_field\":\"untouched\"},\"id\":\"unresolved\"}";
    assert(qihse_kv_set_user(s, "future", json, 0, 0, op));
    char *large = malloc(1024 * 1024 + 1); assert(large);
    memset(large, 'a', 1024 * 1024); large[1024 * 1024] = 0;
    assert(qihse_kv_set_user(s, "large", large, 0, 0, op));
    char compact[sizeof(root) + 32], legacy[sizeof(root) + 32], denied[sizeof(root) + 32];
    snprintf(compact, sizeof(compact), "%s/graph.kv", root);
    snprintf(legacy, sizeof(legacy), "%s/legacy.kv", root);
    snprintf(denied, sizeof(denied), "%s/denied.kv", root);
    assert(qihse_kv_set_user(s, "public", "retained", 0, 0, op));
    assert(qihse_kv_set_user(s, "protected", "CLASSIFIED-PAYLOAD", 4, 2, op));
    qihse_kv_record_meta_t before, after;
    assert(qihse_kv_meta_user(s, "protected", op, &before));
    assert(cg_storage_save(s, compact, op));
    assert(qihse_kv_save_user(s, legacy, op) == 0);
    assert(!cg_storage_save(s, denied, NULL));
    assert(!cg_storage_save(s, denied, low));
    assert(access(denied, F_OK) != 0);
    assert(qihse_kv_clear_user(s, op) == 4);
    assert(qihse_kv_set_user(s, "marker", "unchanged", 0, 0, op));
    assert(!cg_storage_load(s, compact, NULL));
    assert(!cg_storage_load(s, compact, low));
    value_is(s, op, "protected", NULL); value_is(s, low, "marker", "unchanged");
    assert(!cg_storage_load(s, legacy, low));
    value_is(s, op, "protected", NULL); value_is(s, low, "marker", "unchanged");
    assert(cg_storage_load(s, compact, op));
    value_is(s, op, "future", json);
    value_is(s, op, "large", large);
    value_is(s, op, "protected", "CLASSIFIED-PAYLOAD");
    value_is(s, low, "protected", NULL);
    assert(qihse_kv_meta_user(s, "protected", op, &after));
    assert(before.classification == after.classification && before.sci_compartment == after.sci_compartment &&
           before.expire_time_ms == after.expire_time_ms && before.flags == after.flags &&
           before.change_seq == after.change_seq);
    assert(cg_storage_load(s, legacy, op));
    value_is(s, op, "public", "retained");
    int fd = open(compact, O_RDWR); assert(fd >= 0);
    off_t size = lseek(fd, 0, SEEK_END); assert(size > 20);
    unsigned char byte;
    assert(pread(fd, &byte, 1, size - 1) == 1);
    unsigned char bad = byte ^ 0x40;
    assert(pwrite(fd, &bad, 1, size - 1) == 1);
    assert(!cg_storage_load(s, compact, op)); /* frame checksum */
    assert(pwrite(fd, &byte, 1, size - 1) == 1);
    assert(ftruncate(fd, size - 1) == 0);
    assert(!cg_storage_load(s, compact, op)); /* truncation */
    close(fd);
    assert(cg_storage_save(s, compact, op));
    fd = open(compact, O_WRONLY | O_APPEND); assert(fd >= 0);
    assert(write(fd, "x", 1) == 1); close(fd);
    assert(!cg_storage_load(s, compact, op)); /* trailing bytes */
    assert(cg_storage_save(s, compact, op));
    fd = open(compact, O_WRONLY); assert(fd >= 0);
    assert(pwrite(fd, "\377", 1, 8) == 1); close(fd);
    assert(!cg_storage_load(s, compact, op)); /* advertised length bound */
    value_is(s, op, "public", "retained");
    assert(qihse_auth_destroy_user(op, 71));
    assert(!cg_storage_load(s, legacy, low));
    free(large);
    qihse_kv_store_destroy(s);
    qihse_audit_shutdown();
    assert(nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("CodeGraph compact storage: round-trip, legacy, metadata, malformed and authorization checks passed");
    return 0;
}
