/* QH-04 immutable version lineage, CAS, temporal and authorization gates. */
#include "qihse_ai_memory.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool file_contains(const char* path, const char* needle) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    assert(fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f);
    assert(size >= 0 && fseek(f, 0, SEEK_SET) == 0);
    char* bytes = calloc((size_t)size + 1u, 1u);
    assert(bytes);
    assert(fread(bytes, 1u, (size_t)size, f) == (size_t)size);
    fclose(f);
    bool found = strstr(bytes, needle) != NULL;
    free(bytes);
    return found;
}

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
    qihse_user_t* tenant_operator = qihse_auth_create_tenant_user(op, 7u, 9206u,
        QIHSE_ROLE_OPERATOR, 5u, 0u, "KnowledgeTenantOp123!", false);
    assert(op && owner && reader && foreign && high && low_reader && tenant_operator);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_t* server = make_server(store);
    qihse_ai_memory_scope_t scope = { "project-knowledge", "tree-a", "stream-a", "session-a" };
    char seed[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, owner, "scope ownership seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));
    char evidence_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_event_append(server, owner, &scope, "qh04-test",
        "event-1", "decision", 1000u, "evidence without secret payload",
        evidence_id) == QIHSE_AIMEM_WRITE_NEW);

    const char* sources[] = { evidence_id };
    qihse_ai_memory_knowledge_provenance_t provenance = {
        .idempotency_key = "create-retry-1", .source_event_ids = sources,
        .source_event_count = 1u, .confidence_ppm = 875000u
    };
    const char* missing_sources[] = { "00000000-0000-4000-8000-000000000001" };
    qihse_ai_memory_knowledge_provenance_t missing_evidence = {
        .idempotency_key = "missing-evidence", .source_event_ids = missing_sources,
        .source_event_count = 1u
    };
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "must not admit missing evidence", &missing_evidence,
        &(qihse_ai_memory_knowledge_version_t){0}) == QIHSE_AIMEM_WRITE_FAILED);

    qihse_ai_memory_knowledge_version_t first;
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "keep the durable lineage", &provenance, &first) == QIHSE_AIMEM_WRITE_NEW);
    assert(first.revision == 1u && first.valid_to_ingest_ms == 0u);
    assert(first.status == QIHSE_AIMEM_KNOWLEDGE_PROPOSED);
    assert(first.generated_by == 9201u && first.reviewed_by == 0u);
    assert(first.confidence_ppm == 875000u && first.source_event_count == 1u);
    assert(strcmp(first.source_event_ids[0], evidence_id) == 0);
    assert(strlen(first.content_sha256) == QIHSE_AIMEM_CONTENT_SHA256_HEX_LEN);
    qihse_ai_memory_knowledge_version_t replay;
    qihse_ai_memory_write_result_t replay_result = qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "keep the durable lineage", &provenance, &replay);
    assert(replay_result == QIHSE_AIMEM_WRITE_REPLAY);
    assert(strcmp(replay.knowledge_id, first.knowledge_id) == 0 &&
           strcmp(replay.version_id, first.version_id) == 0);
    qihse_ai_memory_knowledge_free(&replay);
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "changed retry payload", &provenance, &replay) == QIHSE_AIMEM_WRITE_CONFLICT);
    qihse_ai_memory_relation_t fixes = {
        .type = QIHSE_AIMEM_RELATION_FIXES, .target_scope = scope
    };
    snprintf(fixes.target_version_id, sizeof fixes.target_version_id, "%s",
             first.version_id);
    qihse_ai_memory_knowledge_provenance_t related_provenance = {
        .idempotency_key = "related-create-1", .relations = &fixes,
        .relation_count = 1u, .confidence_ppm = 700000u
    };
    qihse_ai_memory_knowledge_version_t related;
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "typed relation", &related_provenance, &related) == QIHSE_AIMEM_WRITE_NEW);
    assert(related.relation_count == 1u &&
           related.relations[0].type == QIHSE_AIMEM_RELATION_FIXES);
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

    /* Approval binds the authenticated reviewer and permanently removes the
     * original owner's ability to replace the approved head. */
    qihse_ai_memory_knowledge_provenance_t approval = {
        .idempotency_key = "approve-retry-1", .confidence_ppm = 950000u
    };
    qihse_ai_memory_knowledge_version_t approved;
    assert(qihse_ai_memory_knowledge_revise_ex(server, tenant_operator,
        first.knowledge_id, latest.version_id, latest.revision,
        QIHSE_AIMEM_KNOWLEDGE_APPROVED, "reviewed durable lineage", &approval,
        &approved) == QIHSE_AIMEM_WRITE_NEW);
    assert(approved.reviewed_by == 9206u && approved.generated_by == 9206u);
    assert(approved.relation_count == 1u &&
           approved.relations[0].type == QIHSE_AIMEM_RELATION_SUPERSEDES &&
           strcmp(approved.relations[0].target_version_id, latest.version_id) == 0);
    assert(qihse_ai_memory_knowledge_revise(server, owner, first.knowledge_id,
        approved.version_id, approved.revision, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "post approval owner attack", &temporal) == QIHSE_AIMEM_WRITE_FAILED);
    qihse_ai_memory_knowledge_version_t approved_replay;
    assert(qihse_ai_memory_knowledge_revise_ex(server, tenant_operator,
        first.knowledge_id, latest.version_id, latest.revision,
        QIHSE_AIMEM_KNOWLEDGE_APPROVED, "reviewed durable lineage", &approval,
        &approved_replay) == QIHSE_AIMEM_WRITE_REPLAY);
    assert(strcmp(approved_replay.version_id, approved.version_id) == 0);
    qihse_ai_memory_knowledge_free(&approved_replay);
    qihse_ai_memory_knowledge_provenance_t retraction = {
        .idempotency_key = "retract-retry-1", .confidence_ppm = 950000u
    };
    qihse_ai_memory_knowledge_version_t retracted, retracted_replay;
    assert(qihse_ai_memory_knowledge_revise_ex(server, tenant_operator,
        first.knowledge_id, approved.version_id, approved.revision,
        QIHSE_AIMEM_KNOWLEDGE_RETRACTED, "reviewed durable lineage retracted",
        &retraction, &retracted) == QIHSE_AIMEM_WRITE_NEW);
    assert(retracted.reviewed_by == 9206u &&
           retracted.status == QIHSE_AIMEM_KNOWLEDGE_RETRACTED);
    assert(qihse_ai_memory_knowledge_revise_ex(server, tenant_operator,
        first.knowledge_id, approved.version_id, approved.revision,
        QIHSE_AIMEM_KNOWLEDGE_RETRACTED, "reviewed durable lineage retracted",
        &retraction, &retracted_replay) == QIHSE_AIMEM_WRITE_REPLAY);
    qihse_ai_memory_knowledge_free(&retracted_replay);
    assert(qihse_ai_memory_knowledge_revise(server, tenant_operator,
        first.knowledge_id, retracted.version_id, retracted.revision,
        QIHSE_AIMEM_KNOWLEDGE_APPROVED, "cannot resurrect terminal retraction",
        &temporal) == QIHSE_AIMEM_WRITE_FAILED);
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
    qihse_audit_flush();
    char audit_path[512];
    assert(snprintf(audit_path, sizeof audit_path, "%s/qihse_audit.log", data_root) > 0);
    assert(!file_contains(audit_path, "QH04_HIGH_CLASSIFIED_MARKER"));
    assert(!file_contains(audit_path, "reviewed durable lineage"));

    /* A durable restart must preserve retry identity and return the original
     * receipt instead of appending another version. */
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create();
    assert(store);
    server = make_server(store);
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "keep the durable lineage", &provenance, &replay) == QIHSE_AIMEM_WRITE_REPLAY);
    assert(strcmp(replay.knowledge_id, first.knowledge_id) == 0);
    qihse_ai_memory_knowledge_free(&replay);

    qihse_ai_memory_knowledge_free(&first);
    qihse_ai_memory_knowledge_free(&prior);
    qihse_ai_memory_knowledge_free(&latest);
    qihse_ai_memory_knowledge_free(&approved);
    qihse_ai_memory_knowledge_free(&retracted);
    qihse_ai_memory_knowledge_free(&secret);
    qihse_ai_memory_knowledge_free(&related);
    for (size_t i = 0; i < 2u; i++) qihse_ai_memory_knowledge_free(&workers[i].value);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("PASS QH-04 immutable lineage, CAS, as-of and authorization gates\n");
    return 0;
}
