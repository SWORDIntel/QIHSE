/* KEYSTONE projection integration with a real ONNX model. */
#include "qihse_ai_memory.h"
#include "qihse_aimem_onnx_embedder.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int remove_fixture(const char* path, const struct stat* st,
        int flag, struct FTW* walk) {
    (void)st; (void)walk;
    return flag == FTW_D || flag == FTW_DP ? rmdir(path) : unlink(path);
}

static uint64_t monotonic_us(void) {
    struct timespec ts;
    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int compare_us(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

static size_t recall(qihse_resp_server_t* server, qihse_user_t* reader,
        const qihse_ai_memory_scope_t* scope, const char* words,
        qihse_ai_memory_mode_t mode, qihse_ai_memory_hit_t* hits) {
    return qihse_ai_memory_recall_scoped(server, reader, words, 8u, mode,
        QIHSE_AIMEM_KIND_ANY, scope, hits, 8u);
}

int main(void) {
    char dir[] = "./aimem_keystone_test_XXXXXX";
    assert(mkdtemp(dir) && chmod(dir, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("KeystoneProjection123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    qihse_user_t* owner = qihse_auth_create_tenant_user(op, 17u, 171u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "KeystoneOwner123!", false);
    qihse_user_t* reader = qihse_auth_create_tenant_user(op, 17u, 172u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "KeystoneReader123!", false);
    qihse_user_t* hidden = qihse_auth_create_tenant_user(op, 17u, 173u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "KeystoneHidden123!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(op, 18u, 181u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "KeystoneForeign123!", false);
    assert(owner && reader && hidden && foreign);
    qihse_kv_store_t* kv = qihse_kv_store_create();
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = kv; config.port = 0u; config.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);
    qihse_ai_memory_scope_t scope = {"projection-test", "tree-a", "stream-a", "session-a"};
    qihse_ai_memory_hit_t hits[8] = {0};
    assert(recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_SEMANTIC, hits) == 0u);
    assert(errno == ENOTSUP);
    assert(recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_HYBRID, hits) == 0u);
    assert(errno == ENOTSUP);
    const char* model = getenv("QIHSE_AIMEM_EMBEDDER_ONNX_TEST_DIR");
    const char* lib = getenv("QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY");
    if (!model || !*model || !lib || !*lib) {
        qihse_resp_server_destroy(server); qihse_kv_store_destroy(kv);
        qihse_audit_shutdown();
        assert(nftw(dir, remove_fixture, 16, FTW_DEPTH | FTW_PHYS) == 0);
        puts("SKIP: configure QIHSE_AIMEM_EMBEDDER_ONNX_TEST_DIR and QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY");
        return 77;
    }
    assert(qihse_aimem_onnx_embedder_install(model));
    char cat[37], unrelated[37], secret[37], foreign_id[37];
    assert(qihse_ai_memory_store_scoped(server, owner, "A feline perched on the rug",
        QIHSE_AIMEM_SEMANTIC, &scope, cat));
    assert(qihse_ai_memory_store_scoped(server, owner, "Quarterly revenue exceeded expectations",
        QIHSE_AIMEM_SEMANTIC, &scope, unrelated));
    assert(qihse_ai_memory_store_scoped(server, hidden, "A cat sitting on a classified rug",
        QIHSE_AIMEM_SEMANTIC, &scope, secret));
    assert(qihse_ai_memory_store_scoped(server, foreign, "A cat sitting in another tenant",
        QIHSE_AIMEM_SEMANTIC, &scope, foreign_id));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 172u));
    qihse_ai_memory_scope_t noise_scope = {"projection-noise", "tree-b", "stream-b", "session-b"};
    for (size_t i = 0; i < 550u; i++) {
        char text[128], id[37];
        assert(snprintf(text, sizeof text, "unrelated controlled corpus record %zu", i) < (int)sizeof text);
        assert(qihse_ai_memory_store_scoped(server, reader, text,
            QIHSE_AIMEM_SEMANTIC, &noise_scope, id));
    }
    uint64_t start = monotonic_us();
    assert(qihse_ai_memory_projection_enable(server, reader, lib, dir));
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 60000u));
    uint64_t backfill_us = monotonic_us() - start;
    uint64_t latency[20];
    for (size_t i = 0; i < 20u; i++) {
        start = monotonic_us();
        size_t sampled = recall(server, reader, &scope, "The cat sat on the mat",
            QIHSE_AIMEM_MODE_SEMANTIC, hits);
        latency[i] = monotonic_us() - start;
        assert(errno == 0 && sampled == 2u && strcmp(hits[0].id, cat) == 0);
        qihse_ai_memory_hits_free(hits, sampled);
        memset(hits, 0, sizeof hits);
    }
    qsort(latency, 20u, sizeof latency[0], compare_us);
    fprintf(stderr, "AIMEM indexed 552 visible scoped rows: backfill=%llu ms semantic p50=%llu us p95=%llu us\n",
        (unsigned long long)(backfill_us / 1000u),
        (unsigned long long)latency[10], (unsigned long long)latency[18]);
    qihse_ai_memory_projection_shutdown(server);
    start = monotonic_us();
    assert(qihse_ai_memory_projection_enable(server, reader, lib, dir));
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 30000u));
    fprintf(stderr, "AIMEM canonical rebaseline with cached vectors: %llu ms\n",
        (unsigned long long)((monotonic_us() - start) / 1000u));
    size_t n = recall(server, reader, &scope, "The cat sat on the mat",
        QIHSE_AIMEM_MODE_SEMANTIC, hits);
    assert(errno == 0 && n == 2u && strcmp(hits[0].id, cat) == 0);
    for (size_t i = 0; i < n; i++) assert(strcmp(hits[i].id, secret) && strcmp(hits[i].id, foreign_id));
    qihse_ai_memory_hits_free(hits, n);
    memset(hits, 0, sizeof hits);
    n = recall(server, reader, &scope, "feline rug", QIHSE_AIMEM_MODE_HYBRID, hits);
    assert(errno == 0 && n > 0u && strcmp(hits[0].id, cat) == 0);
    qihse_ai_memory_hits_free(hits, n);
    assert(qihse_auth_modify_user(op, 172u, NULL, NULL, -1, -1, 1, 1));
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 30000u));
    memset(hits, 0, sizeof hits);
    n = recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_SEMANTIC, hits);
    assert(errno == 0 && n == 2u);
    qihse_ai_memory_hits_free(hits, n);
    assert(qihse_auth_modify_user(op, 172u, NULL, NULL, -1, -1, 0, 0));
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 30000u));
    assert(qihse_kv_set_user(kv, "t:17/unrelated:heartbeat", "v1", 0u, 0u, reader));
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 3000u));
    char snapshot[512];
    assert(snprintf(snapshot, sizeof snapshot, "%s/restore.snap", dir) < (int)sizeof snapshot);
    assert(qihse_kv_save_user(kv, snapshot, op) == 0);
    assert(qihse_ai_memory_project_revoke(server, owner, scope.project, 172u));
    memset(hits, 0, sizeof hits);
    n = recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_SEMANTIC, hits);
    assert(n == 0u && (errno == 0 || errno == ESTALE));
    assert(qihse_kv_load_user(kv, snapshot, op) == 0);
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 30000u));
    memset(hits, 0, sizeof hits);
    n = recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_SEMANTIC, hits);
    assert(errno == 0 && n > 0u);
    qihse_ai_memory_hits_free(hits, n);
    assert(qihse_ai_memory_forget_scoped(server, owner, cat, &scope));
    memset(hits, 0, sizeof hits);
    n = recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_SEMANTIC, hits);
    for (size_t i = 0; i < n; i++) assert(strcmp(hits[i].id, cat));
    qihse_ai_memory_hits_free(hits, n);
    assert(qihse_ai_memory_projection_wait_ready(server, reader, 30000u));
    assert(qihse_ai_memory_set_embedder(NULL));
    assert(recall(server, reader, &scope, "cat", QIHSE_AIMEM_MODE_SEMANTIC, hits) == 0u);
    assert(errno == ESTALE);
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(kv);
    qihse_audit_shutdown();
    assert(nftw(dir, remove_fixture, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("PASS: ranking, negative auth, grant revocation, restore, tombstone, model mismatch");
    return 0;
}
