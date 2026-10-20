/* QH-04 immutable version lineage, CAS, temporal and authorization gates. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    qihse_resp_server_t* server;
    qihse_user_t* user;
    const char* knowledge_id;
    const char* version_id;
    uint64_t revision;
    const char* content;
    pthread_barrier_t* barrier;
    qihse_ai_memory_write_result_t result;
    qihse_ai_memory_knowledge_version_t value;
} revise_worker_t;

static void* revise_worker(void* opaque) {
    revise_worker_t* w = (revise_worker_t*)opaque;
    int barrier_result = pthread_barrier_wait(w->barrier);
    assert(barrier_result == 0 || barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);
    w->result = qihse_ai_memory_knowledge_revise(w->server, w->user,
        w->knowledge_id, w->version_id, w->revision,
        QIHSE_AIMEM_KNOWLEDGE_PROPOSED, w->content, &w->value);
    return NULL;
}

static qihse_resp_server_t* make_server(qihse_kv_store_t* store) {
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store; cfg.auth_required = true; cfg.port = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server);
    return server;
}

int main(void) {
    char data_root[] = "build/aimem_knowledge_XXXXXX";
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("KnowledgeOperator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    qihse_user_t* owner = qihse_auth_create_tenant_user(op, 7u, 9201u,
        QIHSE_ROLE_GUEST, 0u, 0u, "KnowledgeOwner123!", false);
    qihse_user_t* reader = qihse_auth_create_tenant_user(op, 7u, 9202u,
        QIHSE_ROLE_GUEST, 0u, 0u, "KnowledgeReader123!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(op, 8u, 9203u,
        QIHSE_ROLE_GUEST, 0u, 0u, "KnowledgeForeign123!", false);
    qihse_user_t* high = qihse_auth_create_tenant_user(op, 7u, 9204u,
        QIHSE_ROLE_GUEST, 5u, 0u, "KnowledgeHigh123!", false);
    qihse_user_t* low_reader = qihse_auth_create_tenant_user(op, 7u, 9205u,
        QIHSE_ROLE_GUEST, 0u, 0u, "KnowledgeLowReader123!", false);
    assert(op && owner && reader && foreign && high && low_reader);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_t* server = make_server(store);
    qihse_ai_memory_scope_t scope = { "project-knowledge", "tree-a", "stream-a", "session-a" };
    char seed[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, owner, "scope ownership seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));

    qihse_ai_memory_knowledge_version_t first;
    assert(qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "keep the durable lineage", &first) == QIHSE_AIMEM_WRITE_NEW);
    assert(first.revision == 1u && first.valid_to_ingest_ms == 0u);
    assert(first.status == QIHSE_AIMEM_KNOWLEDGE_PROPOSED);
    assert(!qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_APPROVED,
        "guest cannot approve", &(qihse_ai_memory_knowledge_version_t){0}));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9202u));
    qihse_ai_memory_knowledge_version_t readback;
    assert(qihse_ai_memory_knowledge_get(server, reader, first.version_id, &scope, &readback));
    assert(strcmp(readback.content, first.content) == 0);
    qihse_ai_memory_knowledge_free(&readback);

    pthread_barrier_t barrier;
    assert(pthread_barrier_init(&barrier, NULL, 2u) == 0);
    revise_worker_t workers[2] = {
        { .server = server, .user = owner, .knowledge_id = first.knowledge_id,
          .version_id = first.version_id, .revision = first.revision,
          .content = "winner alpha", .barrier = &barrier },
        { .server = server, .user = owner, .knowledge_id = first.knowledge_id,
          .version_id = first.version_id, .revision = first.revision,
          .content = "winner beta", .barrier = &barrier }
    };
    pthread_t threads[2];
    assert(pthread_create(&threads[0], NULL, revise_worker, &workers[0]) == 0);
    assert(pthread_create(&threads[1], NULL, revise_worker, &workers[1]) == 0);
    assert(pthread_join(threads[0], NULL) == 0);
    assert(pthread_join(threads[1], NULL) == 0);
    assert(pthread_barrier_destroy(&barrier) == 0);
    size_t won = 0u, conflicted = 0u;
    for (size_t i = 0; i < 2u; i++) {
        won += workers[i].result == QIHSE_AIMEM_WRITE_NEW;
        conflicted += workers[i].result == QIHSE_AIMEM_WRITE_CONFLICT;
    }
    assert(won == 1u && conflicted == 1u);

    qihse_ai_memory_knowledge_version_t prior, latest, temporal;
    assert(qihse_ai_memory_knowledge_get(server, owner, first.version_id, &scope, &prior));
    assert(prior.status == QIHSE_AIMEM_KNOWLEDGE_SUPERSEDED && prior.valid_to_ingest_ms > 0u);
    assert(qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &scope, &latest));
    assert(latest.revision == 2u && strcmp(latest.supersedes_version, first.version_id) == 0);
    assert(qihse_ai_memory_knowledge_as_of(server, owner, first.knowledge_id,
        &scope, prior.valid_to_ingest_ms - 1u, &temporal));
    assert(strcmp(temporal.version_id, first.version_id) == 0);
    qihse_ai_memory_knowledge_free(&temporal);
    assert(qihse_ai_memory_knowledge_as_of(server, owner, first.knowledge_id,
        &scope, prior.valid_to_ingest_ms, &temporal));
    assert(strcmp(temporal.version_id, latest.version_id) == 0);
    qihse_ai_memory_knowledge_free(&temporal);

    qihse_ai_memory_scope_t wrong = scope;
    snprintf(wrong.project, sizeof wrong.project, "%s", "project-wrong");
    assert(!qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &wrong, &temporal));
    assert(!qihse_ai_memory_knowledge_get(server, foreign, first.version_id, &scope, &temporal));
    assert(!qihse_ai_memory_knowledge_get(server, NULL, first.version_id, &scope, &temporal));
    assert(qihse_ai_memory_knowledge_revise(server, reader, first.knowledge_id,
        latest.version_id, latest.revision, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "reader cannot write", &temporal) == QIHSE_AIMEM_WRITE_FAILED);
    assert(qihse_ai_memory_project_revoke(server, owner, scope.project, 9202u));
    assert(!qihse_ai_memory_knowledge_latest(server, reader, first.knowledge_id, &scope, &temporal));

    qihse_ai_memory_scope_t high_scope = { "project-high-knowledge", "", "", "" };
    /* Give low_reader valid project membership through a low-label owner;
     * the denial below must therefore come from the high record label. */
    assert(qihse_ai_memory_store_scoped(server, owner, "low membership seed",
        QIHSE_AIMEM_EPISODIC, &high_scope, seed));
    assert(qihse_ai_memory_project_grant(server, owner, high_scope.project, 9205u));
    assert(qihse_ai_memory_store_scoped(server, high, "high ownership seed",
        QIHSE_AIMEM_EPISODIC, &high_scope, seed));
    qihse_ai_memory_knowledge_version_t secret;
    assert(qihse_ai_memory_knowledge_create(server, high, &high_scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "QH04_HIGH_CLASSIFIED_MARKER", &secret) == QIHSE_AIMEM_WRITE_NEW);
    assert(!qihse_ai_memory_knowledge_get(server, low_reader, secret.version_id, &high_scope, &temporal));
    assert(!qihse_ai_memory_knowledge_latest(server, low_reader, secret.knowledge_id, &high_scope, &temporal));
    assert(qihse_kv_sync_store(store));

    qihse_ai_memory_knowledge_free(&first);
    qihse_ai_memory_knowledge_free(&prior);
    qihse_ai_memory_knowledge_free(&latest);
    qihse_ai_memory_knowledge_free(&secret);
    for (size_t i = 0; i < 2u; i++) qihse_ai_memory_knowledge_free(&workers[i].value);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("PASS QH-04 immutable lineage, CAS, as-of and authorization gates\n");
    return 0;
}
