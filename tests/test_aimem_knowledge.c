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
    qihse_user_t* sci_owner = qihse_auth_create_tenant_user(op, 7u, 9207u,
        QIHSE_ROLE_GUEST, 5u, 1u, "KnowledgeSciOwner123!", false);
    qihse_user_t* missing_sci_reader = qihse_auth_create_tenant_user(op, 7u, 9208u,
        QIHSE_ROLE_GUEST, 5u, 0u, "KnowledgeMissingSci123!", false);
    assert(op && owner && reader && foreign && high && low_reader &&
           tenant_operator && sci_owner && missing_sci_reader);

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
    qihse_ai_memory_walk_hit_t walk[8];
    size_t walked = qihse_ai_memory_knowledge_walk(server, owner,
        related.version_id, &scope, 1u, 8u, walk);
    assert(walked == 2u && walk[0].depth == 0u && walk[1].depth == 1u);
    assert(strcmp(walk[1].version.version_id, first.version_id) == 0);
    qihse_ai_memory_walk_hits_free(walk, walked);
    walked = qihse_ai_memory_knowledge_walk_v2(server, owner,
        related.version_id, &scope, 1u, 8u, walk);
    assert(walked == 2u && !walk[0].has_traversed_relation &&
           walk[1].has_traversed_relation &&
           walk[1].traversed_relation.type == QIHSE_AIMEM_RELATION_FIXES &&
           strcmp(walk[1].traversed_from_version_id, related.version_id) == 0 &&
           strcmp(walk[1].traversed_relation.target_version_id,
                  first.version_id) == 0);
    qihse_ai_memory_walk_hits_free(walk, walked);
    assert(qihse_ai_memory_knowledge_walk(server, NULL,
        related.version_id, &scope, 1u, 8u, walk) == 0u);
    assert(qihse_ai_memory_knowledge_walk(server, owner,
        related.version_id, &scope, 5u, 8u, walk) == 0u);
    assert(!qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_APPROVED,
        "guest cannot approve", &(qihse_ai_memory_knowledge_version_t){0}));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9202u));
    walked = qihse_ai_memory_knowledge_walk_in(server, reader,
        first.version_id, &scope, 1u, 8u, walk);
    assert(walked == 2u && walk[0].depth == 0u && walk[1].depth == 1u);
    assert(strcmp(walk[1].version.version_id, related.version_id) == 0);
    assert(!walk[0].has_traversed_relation &&
           walk[1].has_traversed_relation &&
           walk[1].traversed_relation.type == QIHSE_AIMEM_RELATION_FIXES &&
           strcmp(walk[1].traversed_relation.target_version_id,
                  first.version_id) == 0);
    qihse_ai_memory_walk_hits_free(walk, walked);
    assert(qihse_ai_memory_knowledge_walk_in(server, NULL,
        first.version_id, &scope, 1u, 8u, walk) == 0u);
    assert(qihse_ai_memory_knowledge_walk_in(server, reader,
        first.version_id, &scope, 5u, 8u, walk) == 0u);
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9204u));
    assert(qihse_ai_memory_store_scoped(server, high, "high incoming seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));
    assert(qihse_ai_memory_project_grant(server, high, scope.project, 9202u));
    qihse_ai_memory_relation_t high_causes = fixes;
    high_causes.type = QIHSE_AIMEM_RELATION_CAUSES;
    qihse_ai_memory_knowledge_provenance_t high_relation_provenance = {
        .idempotency_key = "high-incoming-1", .relations = &high_causes,
        .relation_count = 1u
    };
    qihse_ai_memory_knowledge_version_t high_incoming;
    assert(qihse_ai_memory_knowledge_create_ex(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "HIGH_INCOMING_RELATION_MARKER", &high_relation_provenance,
        &high_incoming) == QIHSE_AIMEM_WRITE_NEW);
    walked = qihse_ai_memory_knowledge_walk_in(server, reader,
        first.version_id, &scope, 1u, 8u, walk);
    assert(walked == 2u);
    for (size_t i = 0; i < walked; i++) {
        assert(!strstr(walk[i].version.content, "HIGH_INCOMING_RELATION_MARKER"));
        assert(!walk[i].has_traversed_relation ||
               walk[i].traversed_relation.type != QIHSE_AIMEM_RELATION_CAUSES);
    }
    qihse_ai_memory_walk_hits_free(walk, walked);
    walked = qihse_ai_memory_knowledge_walk_in(server, high,
        first.version_id, &scope, 1u, 8u, walk);
    assert(walked == 3u);
    bool saw_high_edge = false;
    for (size_t i = 0; i < walked; i++)
        if (walk[i].has_traversed_relation &&
            walk[i].traversed_relation.type == QIHSE_AIMEM_RELATION_CAUSES)
            saw_high_edge = true;
    assert(saw_high_edge);
    qihse_ai_memory_walk_hits_free(walk, walked);
    static const char url_body[] = "First line\nSecond line\n";
    qihse_ai_memory_source_ref_t url_source = {
        .system = QIHSE_AIMEM_URL_SOURCE_SYSTEM,
        .id = "https://example.com/guide?edition=2",
        .revision = "sha256:20044dfdde9c2681fcde44a4cb3350920fb3a7ace75284626addfeec460a0755",
        .line_start = 1u, .line_end = 2u
    };
    assert(qihse_ai_memory_url_source_ref_valid(&url_source));
    qihse_ai_memory_source_ref_t bad_url = url_source;
    snprintf(bad_url.id, sizeof bad_url.id, "%s", "HTTPS://Example.com/guide");
    assert(!qihse_ai_memory_url_source_ref_valid(&bad_url));
    snprintf(bad_url.id, sizeof bad_url.id, "%s", "https://example.com/guide/../x");
    assert(!qihse_ai_memory_url_source_ref_valid(&bad_url));
    bad_url = url_source;
    bad_url.revision[7] = 'A';
    assert(!qihse_ai_memory_url_source_ref_valid(&bad_url));
    qihse_ai_memory_knowledge_provenance_t url_provenance = {
        .idempotency_key = "url-source-low-1", .source_ref = &url_source
    };
    qihse_ai_memory_knowledge_version_t url_low;
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "URL_LOW_MARKER", &url_provenance, &url_low) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_knowledge_version_t url_read = {0};
    assert(qihse_ai_memory_knowledge_get(server, reader,
        url_low.version_id, &scope, &url_read));
    assert(strcmp(url_read.source_ref.id, url_source.id) == 0 &&
           strcmp(url_read.source_ref.revision, url_source.revision) == 0);
    qihse_ai_memory_knowledge_free(&url_read);
    assert(qihse_ai_memory_knowledge_url_citation_valid(server, reader,
        url_low.version_id, &scope, &url_source,
        url_body, sizeof url_body - 1u, url_body, sizeof url_body - 1u));
    assert(!qihse_ai_memory_knowledge_url_citation_valid(server, reader,
        url_low.version_id, &scope, &url_source,
        "changed", 7u, url_body, sizeof url_body - 1u));
    assert(!qihse_ai_memory_knowledge_url_citation_valid(server, reader,
        url_low.version_id, &scope, &url_source,
        url_body, sizeof url_body - 1u, "First line", 10u));
    url_provenance.idempotency_key = "url-source-high-1";
    qihse_ai_memory_knowledge_version_t url_high;
    assert(qihse_ai_memory_knowledge_create_ex(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "URL_HIGH_MARKER", &url_provenance, &url_high) == QIHSE_AIMEM_WRITE_NEW);
    assert(!qihse_ai_memory_knowledge_get(server, reader,
        url_high.version_id, &scope, &url_read));
    assert(!qihse_ai_memory_knowledge_url_citation_valid(server, reader,
        url_high.version_id, &scope, &url_source,
        url_body, sizeof url_body - 1u, url_body, sizeof url_body - 1u));
    static const char url_body_v2[] = "Changed first line\nChanged second line\n";
    qihse_ai_memory_source_ref_t url_source_v2 = url_source;
    snprintf(url_source_v2.revision, sizeof url_source_v2.revision, "%s",
        "sha256:5d8493d058ca19b7828a7dc282f6d404a3bf9574a677320f4a54aa5b65bda293");
    qihse_ai_memory_knowledge_provenance_t url_revision_provenance = {
        .idempotency_key = "url-source-revision-2", .source_ref = &url_source_v2
    };
    qihse_ai_memory_knowledge_version_t url_v2;
    assert(qihse_ai_memory_knowledge_revise_ex(server, owner,
        url_low.knowledge_id, url_low.version_id, url_low.revision,
        QIHSE_AIMEM_KNOWLEDGE_PROPOSED, "URL_REVISION_TWO",
        &url_revision_provenance, &url_v2) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_knowledge_url_citation_valid(server, reader,
        url_v2.version_id, &scope, &url_source_v2,
        url_body_v2, sizeof url_body_v2 - 1u,
        url_body_v2, sizeof url_body_v2 - 1u));
    assert(!qihse_ai_memory_knowledge_url_citation_valid(server, reader,
        url_v2.version_id, &scope, &url_source_v2,
        url_body, sizeof url_body - 1u, url_body, sizeof url_body - 1u));
    qihse_ai_memory_query_v1_t url_query = {
        .scope = scope, .source_ref = &url_source,
        .mode = QIHSE_AIMEM_MODE_BM25, .max_rows = 8u
    };
    qihse_ai_memory_query_snapshot_t* url_cursor =
        qihse_ai_memory_query_begin(server, reader, &url_query);
    assert(url_cursor);
    qihse_ai_memory_query_hit_t url_hits[8] = {0};
    size_t url_count = qihse_ai_memory_query_next(url_cursor, reader,
        url_hits, 8u);
    assert(url_count == 1u &&
           strcmp(url_hits[0].version.version_id, url_low.version_id) == 0);
    qihse_ai_memory_query_hits_free(url_hits, url_count);
    qihse_ai_memory_query_end(url_cursor);
    url_query.source_ref = &url_source_v2;
    url_cursor = qihse_ai_memory_query_begin(server, reader, &url_query);
    assert(url_cursor);
    url_count = qihse_ai_memory_query_next(url_cursor, reader, url_hits, 8u);
    assert(url_count == 1u &&
           strcmp(url_hits[0].version.version_id, url_v2.version_id) == 0);
    qihse_ai_memory_query_hits_free(url_hits, url_count);
    qihse_ai_memory_query_end(url_cursor);
    bad_url = url_source;
    bad_url.revision[70] = bad_url.revision[70] == '0' ? '1' : '0';
    url_query.source_ref = &bad_url;
    url_cursor = qihse_ai_memory_query_begin(server, reader, &url_query);
    assert(url_cursor);
    assert(qihse_ai_memory_query_next(url_cursor, reader, url_hits, 8u) == 0u);
    qihse_ai_memory_query_end(url_cursor);
    qihse_ai_memory_knowledge_version_t readback;
    assert(qihse_ai_memory_knowledge_get(server, reader, first.version_id, &scope, &readback));
    assert(strcmp(readback.content, first.content) == 0);
    qihse_ai_memory_knowledge_free(&readback);
    qihse_ai_memory_query_v1_t source_query = {
        .scope = scope, .source_event_id = evidence_id,
        .mode = QIHSE_AIMEM_MODE_BM25, .max_rows = 8u
    };
    qihse_ai_memory_query_snapshot_t* source_cursor =
        qihse_ai_memory_query_begin(server, reader, &source_query);
    assert(source_cursor);
    qihse_ai_memory_query_hit_t source_hits[8] = {0};
    size_t source_count = qihse_ai_memory_query_next(source_cursor, reader,
        source_hits, 8u);
    assert(source_count == 1u);
    assert(strcmp(source_hits[0].version.version_id, first.version_id) == 0);
    qihse_ai_memory_query_hits_free(source_hits, source_count);
    qihse_ai_memory_query_end(source_cursor);
    source_query.source_event_id = "00000000-0000-4000-8000-000000000001";
    assert(qihse_ai_memory_query_begin(server, reader, &source_query) == NULL);
    source_query.source_event_id = evidence_id;

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
    source_cursor = qihse_ai_memory_query_begin(server, reader, &source_query);
    assert(source_cursor);
    assert(qihse_ai_memory_project_revoke(server, owner, scope.project, 9202u));
    assert(!qihse_ai_memory_knowledge_latest(server, reader, first.knowledge_id, &scope, &temporal));
    assert(qihse_ai_memory_query_next(source_cursor, reader,
        source_hits, 8u) == 0u);
    qihse_ai_memory_query_end(source_cursor);
    assert(qihse_ai_memory_query_begin(server, reader, &source_query) == NULL);

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
    assert(qihse_ai_memory_knowledge_walk(server, low_reader,
        secret.version_id, &high_scope, 1u, 8u, walk) == 0u);
    qihse_ai_memory_relation_t secret_edge = {
        .type = QIHSE_AIMEM_RELATION_CAUSES, .target_scope = high_scope
    };
    snprintf(secret_edge.target_version_id, sizeof secret_edge.target_version_id,
        "%s", secret.version_id);
    qihse_ai_memory_knowledge_provenance_t secret_edge_provenance = {
        .idempotency_key = "secret-outgoing-edge",
        .relations = &secret_edge, .relation_count = 1u
    };
    qihse_ai_memory_knowledge_version_t secret_source;
    assert(qihse_ai_memory_knowledge_create_ex(server, high, &high_scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "QH04_SECRET_EDGE_SOURCE", &secret_edge_provenance,
        &secret_source) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_knowledge_walk_v2(server, low_reader,
        secret_source.version_id, &high_scope, 1u, 8u, walk) == 0u);
    walked = qihse_ai_memory_knowledge_walk_v2(server, high,
        secret_source.version_id, &high_scope, 1u, 8u, walk);
    assert(walked == 2u && walk[1].traversed_relation.type ==
           QIHSE_AIMEM_RELATION_CAUSES);
    qihse_ai_memory_walk_hits_free(walk, walked);
    char high_event_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_event_append(server, high, &high_scope,
        "qh05-high", "source-1", "observation", 1001u,
        "HIGH_SOURCE_EVENT_MARKER", high_event_id) == QIHSE_AIMEM_WRITE_NEW);
    const char* high_sources[] = { high_event_id };
    qihse_ai_memory_knowledge_provenance_t high_provenance = {
        .idempotency_key = "high-source-knowledge", .source_event_ids = high_sources,
        .source_event_count = 1u
    };
    qihse_ai_memory_knowledge_version_t high_source_version;
    assert(qihse_ai_memory_knowledge_create_ex(server, high, &high_scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "HIGH_SOURCE_KNOWLEDGE_MARKER", &high_provenance,
        &high_source_version) == QIHSE_AIMEM_WRITE_NEW);
    source_query.scope = high_scope;
    source_query.source_event_id = high_event_id;
    assert(qihse_ai_memory_query_begin(server, low_reader, &source_query) == NULL);
    source_cursor = qihse_ai_memory_query_begin(server, high, &source_query);
    assert(source_cursor);
    source_count = qihse_ai_memory_query_next(source_cursor, high,
        source_hits, 8u);
    assert(source_count == 1u);
    qihse_ai_memory_query_hits_free(source_hits, source_count);
    qihse_ai_memory_query_end(source_cursor);
    /* Equal classification and valid project membership isolate the SCI gate. */
    assert(qihse_ai_memory_project_grant(server, owner, high_scope.project, 9208u));
    assert(qihse_ai_memory_store_scoped(server, sci_owner, "SCI ownership seed",
        QIHSE_AIMEM_EPISODIC, &high_scope, seed));
    qihse_ai_memory_knowledge_version_t sci_secret;
    assert(qihse_ai_memory_knowledge_create(server, sci_owner, &high_scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "QH04_SCI_CLASSIFIED_MARKER", &sci_secret) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_knowledge_get(server, sci_owner,
        sci_secret.version_id, &high_scope, &temporal));
    qihse_ai_memory_knowledge_free(&temporal);
    assert(!qihse_ai_memory_knowledge_get(server, missing_sci_reader,
        sci_secret.version_id, &high_scope, &temporal));
    assert(temporal.content == NULL);
    assert(!qihse_ai_memory_knowledge_latest(server, missing_sci_reader,
        sci_secret.knowledge_id, &high_scope, &temporal));
    assert(qihse_ai_memory_knowledge_walk(server, missing_sci_reader,
        sci_secret.version_id, &high_scope, 1u, 8u, walk) == 0u);
    assert(qihse_ai_memory_knowledge_walk_v2(server, missing_sci_reader,
        sci_secret.version_id, &high_scope, 1u, 8u, walk) == 0u);
    assert(temporal.content == NULL);
    assert(qihse_kv_sync_store(store));
    qihse_audit_flush();
    char audit_path[512];
    assert(snprintf(audit_path, sizeof audit_path, "%s/qihse_audit.log", data_root) > 0);
    assert(!file_contains(audit_path, "QH04_HIGH_CLASSIFIED_MARKER"));
    assert(!file_contains(audit_path, "QH04_SCI_CLASSIFIED_MARKER"));
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

    source_query.scope = scope;
    source_query.source_event_id = evidence_id;
    source_cursor = qihse_ai_memory_query_begin(server, owner, &source_query);
    assert(source_cursor);
    assert(qihse_ai_memory_forget_scoped(server, owner, evidence_id, &scope));
    assert(qihse_ai_memory_query_next(source_cursor, owner,
        source_hits, 8u) == 0u);
    qihse_ai_memory_query_end(source_cursor);
    assert(qihse_ai_memory_query_begin(server, owner, &source_query) == NULL);

    qihse_ai_memory_knowledge_free(&first);
    qihse_ai_memory_knowledge_free(&prior);
    qihse_ai_memory_knowledge_free(&latest);
    qihse_ai_memory_knowledge_free(&approved);
    qihse_ai_memory_knowledge_free(&retracted);
    qihse_ai_memory_knowledge_free(&secret);
    qihse_ai_memory_knowledge_free(&high_source_version);
    qihse_ai_memory_knowledge_free(&secret_source);
    qihse_ai_memory_knowledge_free(&sci_secret);
    qihse_ai_memory_knowledge_free(&related);
    qihse_ai_memory_knowledge_free(&high_incoming);
    qihse_ai_memory_knowledge_free(&url_low);
    qihse_ai_memory_knowledge_free(&url_high);
    qihse_ai_memory_knowledge_free(&url_v2);
    for (size_t i = 0; i < 2u; i++) qihse_ai_memory_knowledge_free(&workers[i].value);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("PASS QH-04 immutable lineage, CAS, as-of and authorization gates\n");
    return 0;
}
