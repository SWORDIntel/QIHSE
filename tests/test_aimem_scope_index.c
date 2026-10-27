/* QH-01 persistent scope-index and hierarchy restart regression. */
#include "aimem_fixture_cleanup.h"
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static qihse_resp_server_t* make_server(qihse_kv_store_t* store) {
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.port = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server);
    return server;
}

static uint64_t now_us(void) {
    struct timespec ts;
    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int compare_u64(const void* a, const void* b) {
    uint64_t left = *(const uint64_t*)a, right = *(const uint64_t*)b;
    return left < right ? -1 : left > right ? 1 : 0;
}

static size_t count(qihse_resp_server_t* server, qihse_user_t* user,
                    const qihse_ai_memory_scope_t* scope) {
    return qihse_ai_memory_count_scoped(server, user, QIHSE_AIMEM_KIND_ANY, scope);
}

static char* store(qihse_resp_server_t* server, qihse_user_t* user,
                   const qihse_ai_memory_scope_t* scope, const char* text,
                   const char* key) {
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    qihse_ai_memory_write_result_t result = qihse_ai_memory_store_scoped_idempotent(
        server, user, text, QIHSE_AIMEM_SEMANTIC, scope, key, id);
    assert(result == QIHSE_AIMEM_WRITE_NEW);
    return strdup(id);
}

static size_t recall(qihse_resp_server_t* server, qihse_user_t* user,
                     const qihse_ai_memory_scope_t* scope, const char* query,
                     qihse_ai_memory_hit_t* hits, size_t cap) {
    return qihse_ai_memory_recall_scoped(server, user, query, cap,
        QIHSE_AIMEM_MODE_BM25, QIHSE_AIMEM_KIND_ANY, scope, hits, cap);
}

int main(void) {
    char data_root[] = "./aimem_scope_index_XXXXXX";
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ScopeIndexOperator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    qihse_user_t* owner = qihse_auth_create_tenant_user(op, 77u, 9771u,
        QIHSE_ROLE_GUEST, 0u, 0u, "ScopeIndexOwner123!", false);
    qihse_user_t* competitor = qihse_auth_create_tenant_user(op, 77u, 9772u,
        QIHSE_ROLE_GUEST, 0u, 0u, "ScopeIndexCompetitor123!", false);
    assert(op && owner && competitor);

    qihse_kv_store_t* store_handle = qihse_kv_store_create();
    assert(store_handle);
    qihse_resp_server_t* server = make_server(store_handle);

    qihse_ai_memory_scope_t root = { "scope-restart", "", "", "" };
    qihse_ai_memory_scope_t tree_a = { "scope-restart", "tree-a", "", "" };
    qihse_ai_memory_scope_t stream_a = { "scope-restart", "tree-a", "stream-a", "" };
    qihse_ai_memory_scope_t session_a = { "scope-restart", "tree-a", "stream-a", "session-a" };
    qihse_ai_memory_scope_t session_b = { "scope-restart", "tree-a", "stream-a", "session-b" };
    qihse_ai_memory_scope_t stream_b = { "scope-restart", "tree-a", "stream-b", "session-c" };
    qihse_ai_memory_scope_t tree_b = { "scope-restart", "tree-b", "stream-a", "session-a" };

    char* root_id = store(server, owner, &root, "root hierarchy marker", "root-key");
    char* a1_id = store(server, owner, &session_a, "alpha hierarchy marker", "alpha-key");
    char* a2_id = store(server, owner, &session_b, "beta hierarchy marker", "beta-key");
    char* a3_id = store(server, owner, &stream_b, "gamma hierarchy marker", "gamma-key");
    char* b1_id = store(server, owner, &tree_b, "delta hierarchy marker", "delta-key");
    assert(root_id && a1_id && a2_id && a3_id && b1_id);

    assert(count(server, owner, &root) == 5u);
    assert(count(server, owner, &tree_a) == 3u);
    assert(count(server, owner, &stream_a) == 2u);
    assert(count(server, owner, &session_a) == 1u);
    qihse_ai_memory_scope_t sibling_tree = { "scope-restart", "tree-z", "", "" };
    qihse_ai_memory_scope_t sibling_stream = { "scope-restart", "tree-a", "stream-z", "" };
    qihse_ai_memory_scope_t sibling_session = { "scope-restart", "tree-a", "stream-a", "session-z" };
    assert(count(server, owner, &sibling_tree) == 0u);
    assert(count(server, owner, &sibling_stream) == 0u);
    assert(count(server, owner, &sibling_session) == 0u);

    /* A project index may contain other owners' records, but they must be
     * removed by live policy before their text affects BM25 statistics. */
    qihse_ai_memory_scope_t project_index = { "project-index", "", "", "" };
    char* target_id = store(server, owner, &project_index,
        "unique pivot token", "target-key");
    qihse_ai_memory_hit_t baseline[4] = {0};
    size_t baseline_n = recall(server, owner, &project_index, "unique", baseline, 4u);
    assert(baseline_n == 1u && strcmp(baseline[0].id, target_id) == 0);
    double baseline_score = baseline[0].score;
    qihse_ai_memory_hits_free(baseline, baseline_n);
    for (size_t i = 0; i < 48u; i++) {
        char text[96], key[48];
        snprintf(text, sizeof text, "unique pivot token foreign document %zu", i);
        snprintf(key, sizeof key, "foreign-%zu", i);
        char* ignored = store(server, competitor, &project_index, text, key);
        free(ignored);
    }
    qihse_ai_memory_hit_t after_foreign[4] = {0};
    size_t after_n = recall(server, owner, &project_index, "unique", after_foreign, 4u);
    assert(after_n == 1u && strcmp(after_foreign[0].id, target_id) == 0);
    assert(fabs(after_foreign[0].score - baseline_score) < 0.000001);
    qihse_ai_memory_hits_free(after_foreign, after_n);

    /* Load evidence: 8 projects × 64 records, then measure scoped recall. */
    qihse_ai_memory_scope_t load_scopes[8];
    for (size_t project = 0; project < 8u; project++) {
        snprintf(load_scopes[project].project, sizeof load_scopes[project].project,
                 "load-project-%zu", project);
        load_scopes[project].worktree[0] = '\0';
        load_scopes[project].workstream[0] = '\0';
        load_scopes[project].session[0] = '\0';
        for (size_t record = 0; record < 64u; record++) {
            char text[128], key[64];
            snprintf(text, sizeof text, "load marker project %zu record %zu", project, record);
            snprintf(key, sizeof key, "load-%zu-%zu", project, record);
            char* ignored = store(server, owner, &load_scopes[project], text, key);
            free(ignored);
        }
    }
    qihse_ai_memory_hit_t loaded_hits[8] = {0};
    assert(recall(server, owner, &load_scopes[3], "load marker project 3",
                  loaded_hits, 8u) == 8u);
    qihse_ai_memory_hits_free(loaded_hits, 8u);
    assert(qihse_kv_sync_store(store_handle));

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store_handle);
    qihse_ai_memory_reset();
    store_handle = qihse_kv_store_create();
    assert(store_handle);
    server = make_server(store_handle);

    /* All hierarchy boundaries survive reopen and the first recall reloads
     * the persisted project/scope index from the private QIHSE data root. */
    assert(count(server, owner, &root) == 5u);
    assert(count(server, owner, &tree_a) == 3u);
    assert(count(server, owner, &stream_a) == 2u);
    assert(count(server, owner, &session_a) == 1u);
    assert(count(server, owner, &sibling_session) == 0u);
    qihse_ai_memory_hit_t restart_hits[8] = {0};
    size_t restart_n = recall(server, owner, &session_a,
        "alpha hierarchy marker", restart_hits, 8u);
    assert(restart_n == 1u && strcmp(restart_hits[0].id, a1_id) == 0);
    qihse_ai_memory_hits_free(restart_hits, restart_n);
    assert(recall(server, owner, &session_a, "beta",
                  restart_hits, 8u) == 0u);

    uint64_t latency[40];
    for (size_t i = 0; i < 40u; i++) {
        qihse_ai_memory_hit_t hits[8] = {0};
        uint64_t start = now_us();
        size_t n = recall(server, owner, &load_scopes[3], "load marker project 3", hits, 8u);
        latency[i] = now_us() - start;
        assert(n == 8u);
        qihse_ai_memory_hits_free(hits, n);
    }
    qsort(latency, 40u, sizeof latency[0], compare_u64);
    fprintf(stderr, "QH-01 scoped index load: 512 records across 8 projects; restart recall p50=%llu us p95=%llu us\n",
        (unsigned long long)latency[20], (unsigned long long)latency[37]);

    /* A restore can reinstall an older document while retaining the high-water
     * sequence. A persisted index built for the deleted state must not win. */
    qihse_ai_memory_scope_t recovered = { "restore-rebaseline", "", "", "" };
    char* recovered_id = store(server, owner, &recovered,
        "restored canonical sentinel", "restore-sentinel");
    char snapshot[512];
    assert(snprintf(snapshot, sizeof snapshot, "%s/recovery.snap", data_root) < (int)sizeof snapshot);
    assert(qihse_kv_save_user(store_handle, snapshot, op) == 0);
    assert(qihse_ai_memory_forget_scoped(server, owner, recovered_id, &recovered));
    qihse_ai_memory_hit_t recovered_hits[2] = {0};
    assert(recall(server, owner, &recovered, "canonical sentinel", recovered_hits, 2u) == 0u);
    uint64_t high_water = qihse_kv_change_seq(store_handle);
    assert(qihse_kv_load_user(store_handle, snapshot, op) == 0);
    assert(qihse_kv_change_seq(store_handle) == high_water);
    assert(qihse_kv_sync_store(store_handle));
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store_handle);
    qihse_ai_memory_reset();
    store_handle = qihse_kv_store_create();
    assert(store_handle);
    server = make_server(store_handle);
    size_t recovered_n = recall(server, owner, &recovered,
        "canonical sentinel", recovered_hits, 2u);
    assert(recovered_n == 1u && strcmp(recovered_hits[0].id, recovered_id) == 0);
    qihse_ai_memory_hits_free(recovered_hits, recovered_n);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store_handle);
    qihse_ai_memory_reset();
    unlink(snapshot);
    free(recovered_id);
    free(root_id); free(a1_id); free(a2_id); free(a3_id); free(b1_id); free(target_id);
    aimem_fixture_cleanup(data_root);
    puts("PASS QH-01 persistent scoped index, live ranking visibility, hierarchy restart and load");
    return 0;
}
