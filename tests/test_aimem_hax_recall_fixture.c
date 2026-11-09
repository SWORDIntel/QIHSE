/* Fixed, authorized HAX recall fixture. --benchmark requires a real indexed
 * semantic provider; the ordinary test checks BM25 and fail-closed modes. */
#include "aimem_fixture_cleanup.h"
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#ifdef QIHSE_ENABLE_AIMEM_KEYSTONE
#include "qihse_aimem_onnx_embedder.h"
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VISIBLE_COUNT 64u
#define SAMPLE_COUNT 40u
#define HIT_CAP 8u

typedef struct { char id[QIHSE_AIMEM_ID_LEN + 1u]; char text[128]; } fixture_row_t;
typedef struct { const char* words; size_t expected; } fixture_query_t;
static const fixture_query_t queries[] = {
    { "cat rug", 0u }, { "quarterly revenue", 1u },
    { "garden irrigation", 2u }
};

static qihse_resp_server_t* make_server(qihse_kv_store_t* kv) {
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = kv; config.auth_required = true; config.port = 0u;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server); return server;
}

#ifdef QIHSE_ENABLE_AIMEM_KEYSTONE
static uint64_t monotonic_us(void) {
    struct timespec ts;
    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int compare_us(const void* left, const void* right) {
    uint64_t a = *(const uint64_t*)left, b = *(const uint64_t*)right;
    return (a > b) - (a < b);
}
#endif

static void verify_hits(const qihse_ai_memory_hit_t* hits, size_t count,
                        const fixture_row_t rows[VISIBLE_COUNT],
                        const char* high_id, const char* foreign_id,
                        const char* sibling_id) {
    for (size_t i = 0u; i < count; i++) {
        assert(strcmp(hits[i].id, high_id) != 0);
        assert(strcmp(hits[i].id, foreign_id) != 0);
        assert(strcmp(hits[i].id, sibling_id) != 0);
        bool known = false;
        for (size_t j = 0u; j < VISIBLE_COUNT; j++) {
            if (strcmp(hits[i].id, rows[j].id) == 0) {
                assert(strcmp(hits[i].text, rows[j].text) == 0);
                known = true; break;
            }
        }
        assert(known);
    }
}

static size_t recall(qihse_resp_server_t* server, qihse_user_t* reader,
                     const qihse_ai_memory_scope_t* scope, const char* words,
                     qihse_ai_memory_mode_t mode, qihse_ai_memory_hit_t hits[HIT_CAP]) {
    return qihse_ai_memory_recall_scoped(server, reader, words, HIT_CAP, mode,
        QIHSE_AIMEM_KIND_ANY, scope, hits, HIT_CAP);
}

#ifdef QIHSE_ENABLE_AIMEM_KEYSTONE
static void measure_mode(qihse_resp_server_t* server, qihse_user_t* reader,
                         const qihse_ai_memory_scope_t* scope,
                         const fixture_row_t rows[VISIBLE_COUNT],
                         const char* high_id, const char* foreign_id,
                         const char* sibling_id, qihse_ai_memory_mode_t mode,
                         const char* name) {
    uint64_t elapsed[SAMPLE_COUNT];
    size_t top1 = 0u, returned = 0u;
    for (size_t i = 0u; i < SAMPLE_COUNT + 3u; i++) {
        const fixture_query_t* query = &queries[i % (sizeof queries / sizeof queries[0])];
        qihse_ai_memory_hit_t hits[HIT_CAP] = {0};
        uint64_t start = monotonic_us();
        size_t count = recall(server, reader, scope, query->words, mode, hits);
        uint64_t duration = monotonic_us() - start;
        assert(errno == 0 && count > 0u);
        verify_hits(hits, count, rows, high_id, foreign_id, sibling_id);
        if (i >= 3u) {
            elapsed[i - 3u] = duration;
            top1 += strcmp(hits[0].id, rows[query->expected].id) == 0;
            returned += count;
        }
        qihse_ai_memory_hits_free(hits, count);
    }
    qsort(elapsed, SAMPLE_COUNT, sizeof elapsed[0], compare_us);
    printf("%s p50=%llu us p95=%llu us top1=%zu/%u citation_ids=%zu/%zu\n",
        name, (unsigned long long)elapsed[19],
        (unsigned long long)elapsed[37], top1, SAMPLE_COUNT,
        returned, returned);
}
#endif

int main(int argc, char** argv) {
    bool benchmark = argc == 2 && strcmp(argv[1], "--benchmark") == 0;
    assert(argc == 1 || benchmark);
    char data_root[] = "./build/aimem_hax_recall_XXXXXX";
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("HaxRecallOperator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    qihse_user_t* owner = qihse_auth_create_tenant_user(op, 47u, 9471u,
        QIHSE_ROLE_GUEST, 0u, 0u, "HaxRecallOwner123!", false);
    qihse_user_t* reader = qihse_auth_create_tenant_user(op, 47u, 9472u,
        QIHSE_ROLE_GUEST, 0u, 0u, "HaxRecallReader123!", false);
    qihse_user_t* high = qihse_auth_create_tenant_user(op, 47u, 9473u,
        QIHSE_ROLE_GUEST, 5u, 1u, "HaxRecallHigh123!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(op, 48u, 9481u,
        QIHSE_ROLE_GUEST, 0u, 0u, "HaxRecallForeign123!", false);
    assert(op && owner && reader && high && foreign);
    qihse_kv_store_t* kv = qihse_kv_store_create(); assert(kv);
    qihse_resp_server_t* server = make_server(kv);
    qihse_ai_memory_scope_t scope = { "hax-recall", "tree", "stream", "session" };
    qihse_ai_memory_scope_t sibling = { "hax-recall", "other-tree", "stream", "session" };
    fixture_row_t rows[VISIBLE_COUNT] = {0};
    const char* first[] = {
        "cat sleeping on red rug", "quarterly revenue exceeded forecast",
        "garden irrigation schedule updated", "dog walking in the park"
    };
    for (size_t i = 0u; i < VISIBLE_COUNT; i++) {
        if (i < sizeof first / sizeof first[0])
            snprintf(rows[i].text, sizeof rows[i].text, "%s", first[i]);
        else
            snprintf(rows[i].text, sizeof rows[i].text,
                     "controlled corpus filler record number %zu", i);
        assert(qihse_ai_memory_store_scoped(server, owner, rows[i].text,
            QIHSE_AIMEM_SEMANTIC, &scope, rows[i].id));
    }
    char high_id[QIHSE_AIMEM_ID_LEN + 1u];
    char foreign_id[QIHSE_AIMEM_ID_LEN + 1u];
    char sibling_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, high, "cat rug classified marker",
        QIHSE_AIMEM_SEMANTIC, &scope, high_id));
    assert(qihse_ai_memory_store_scoped(server, foreign, "cat rug foreign marker",
        QIHSE_AIMEM_SEMANTIC, &scope, foreign_id));
    assert(qihse_ai_memory_store_scoped(server, owner, "cat rug sibling marker",
        QIHSE_AIMEM_SEMANTIC, &sibling, sibling_id));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9472u));
    qihse_ai_memory_hit_t hits[HIT_CAP] = {0};
    for (size_t i = 0u; i < sizeof queries / sizeof queries[0]; i++) {
        size_t n = recall(server, reader, &scope, queries[i].words,
                          QIHSE_AIMEM_MODE_BM25, hits);
        assert(errno == 0 && n > 0u &&
               strcmp(hits[0].id, rows[queries[i].expected].id) == 0);
        verify_hits(hits, n, rows, high_id, foreign_id, sibling_id);
        qihse_ai_memory_hits_free(hits, n);
        memset(hits, 0, sizeof hits);
    }
    assert(!qihse_ai_memory_get_scoped(server, reader, high_id, &scope, hits));
    assert(hits[0].text == NULL);

    int status = 0;
    if (benchmark) {
#ifdef QIHSE_ENABLE_AIMEM_KEYSTONE
        const char* model = getenv("QIHSE_AIMEM_EMBEDDER_ONNX_TEST_DIR");
        const char* library = getenv("QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY");
        if (!model || !*model || !library || !*library ||
            !qihse_aimem_onnx_embedder_install(model) ||
            !qihse_ai_memory_projection_enable(server, reader, library, data_root) ||
            !qihse_ai_memory_projection_wait_ready(server, reader, 60000u)) {
            fprintf(stderr, "semantic provider unavailable; no comparative latency claim\n");
            status = 77;
        } else {
            measure_mode(server, reader, &scope, rows, high_id, foreign_id,
                         sibling_id, QIHSE_AIMEM_MODE_BM25, "bm25");
            measure_mode(server, reader, &scope, rows, high_id, foreign_id,
                         sibling_id, QIHSE_AIMEM_MODE_SEMANTIC, "semantic");
            measure_mode(server, reader, &scope, rows, high_id, foreign_id,
                         sibling_id, QIHSE_AIMEM_MODE_HYBRID, "hybrid");
        }
        qihse_ai_memory_projection_shutdown(server);
#else
        fprintf(stderr, "semantic/hybrid recall unavailable in standard build (ENOTSUP); no comparative latency claim\n");
        status = 77;
#endif
    } else {
#ifndef QIHSE_ENABLE_AIMEM_KEYSTONE
        assert(recall(server, reader, &scope, "cat rug", QIHSE_AIMEM_MODE_SEMANTIC,
                      hits) == 0u && errno == ENOTSUP);
        assert(recall(server, reader, &scope, "cat rug", QIHSE_AIMEM_MODE_HYBRID,
                      hits) == 0u && errno == ENOTSUP);
#endif
        puts("PASS HAX fixed authorized BM25 corpus and citation UUID fixture");
    }
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);
    qihse_ai_memory_reset();
    aimem_fixture_cleanup(data_root);
    return status;
}
