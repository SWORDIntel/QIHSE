/* Focused QH-05..08 native contracts: stable authorized paging, reversible
 * one-lineage maintenance, canonical projection, and redacted rebuild state. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static qihse_resp_server_t* make_server(qihse_kv_store_t* store) {
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store; cfg.auth_required = true; cfg.port = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server); return server;
}

static size_t export_count(const qihse_ai_memory_export_t* value) {
    char* copy = strndup((const char*)value->data, value->len);
    assert(copy); char* cur = copy; char* token = NULL;
    for (size_t i = 0; i < 7u; i++) token = strsep(&cur, "|");
    assert(token); size_t count = (size_t)strtoull(token, NULL, 10);
    free(copy); return count;
}

static size_t authenticated_export_count(const qihse_ai_memory_export_t* value) {
    char* copy = strndup((const char*)value->data, value->len);
    assert(copy); char* cur = copy; char* token = NULL;
    for (size_t i = 0; i < 8u; i++) token = strsep(&cur, "|");
    assert(token); size_t count = (size_t)strtoull(token, NULL, 10);
    free(copy); return count;
}

typedef struct { uint8_t* data; size_t len; size_t cap; size_t at; } stream_t;
static bool stream_write(void* opaque, const uint8_t* data, size_t len) {
    stream_t* s = opaque;
    if (s->len > SIZE_MAX - len) return false;
    if (s->len + len > s->cap) {
        size_t cap = s->cap ? s->cap * 2u : 1024u;
        while (cap < s->len + len) cap *= 2u;
        uint8_t* grown = realloc(s->data, cap); if (!grown) return false;
        s->data = grown; s->cap = cap;
    }
    memcpy(s->data + s->len, data, len); s->len += len; return true;
}
static size_t stream_read(void* opaque, uint8_t* data, size_t cap) {
    stream_t* s = opaque; size_t n = s->len - s->at;
    if (n > cap) n = cap;
    if (n) memcpy(data, s->data + s->at, n);
    s->at += n; return n;
}
static size_t invalid_stream_read(void* opaque, uint8_t* data, size_t cap) {
    (void)opaque; (void)data; return cap + 1u;
}

int main(void) {
    char source_root[] = "./aimem_qh05_08_source_XXXXXX";
    assert(mkdtemp(source_root));
    assert(setenv("QIHSE_DATA_DIR", source_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("Qh0508Operator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    qihse_user_t* owner = qihse_auth_create_tenant_user(op, 17u, 9501u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh0508Owner123!", false);
    qihse_user_t* reader = qihse_auth_create_tenant_user(op, 17u, 9502u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh0508Reader123!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(op, 18u, 9503u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh0508Foreign123!", false);
    qihse_user_t* high = qihse_auth_create_tenant_user(op, 17u, 9504u,
        QIHSE_ROLE_GUEST, 5u, 0u, "Qh0508High123!", false);
    qihse_user_t* tenant_op = qihse_auth_create_tenant_user(op, 17u, 9505u,
        QIHSE_ROLE_OPERATOR, UINT16_MAX, UINT16_MAX, "Qh0508TenantOp123!", false);
    assert(op && owner && reader && foreign && high && tenant_op);

    qihse_kv_store_t* store = qihse_kv_store_create(); assert(store);
    qihse_resp_server_t* server = make_server(store);
    qihse_ai_memory_scope_t scope = { "project-qh0508", "tree-a", "stream-a", "session-a" };
    char seed[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, owner, "owner seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9502u));
    char event_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_event_append_evidence(server, owner, &scope, "qh07-test",
        "event-1", "checkpoint", 1234u, "QH07_EVENT_ROUND_TRIP", seed, event_id) ==
        QIHSE_AIMEM_WRITE_NEW);

    qihse_ai_memory_knowledge_version_t first, second;
    assert(qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "stable paging first", &first) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "stable paging second", &second) == QIHSE_AIMEM_WRITE_NEW);
    const char* sources[] = { event_id };
    qihse_ai_memory_relation_t relation = {
        .type = QIHSE_AIMEM_RELATION_CAUSES, .target_scope = scope
    };
    snprintf(relation.target_version_id, sizeof relation.target_version_id,
             "%s", first.version_id);
    qihse_ai_memory_knowledge_provenance_t provenance = {
        .idempotency_key = "qh07-provenance", .source_event_ids = sources,
        .source_event_count = 1u, .relations = &relation, .relation_count = 1u,
        .confidence_ppm = 800000u
    };
    qihse_ai_memory_knowledge_version_t related;
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_ARCHITECTURE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "QH07 provenance and relation round trip", &provenance, &related) ==
        QIHSE_AIMEM_WRITE_NEW);

    qihse_ai_memory_query_v1_t query = {
        .scope = scope, .current_only = true, .text = "stable paging", .max_rows = 8u
    };
    qihse_ai_memory_query_snapshot_t* snapshot =
        qihse_ai_memory_query_begin(server, reader, &query);
    assert(snapshot);
    qihse_ai_memory_query_hit_t page[2]; memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, foreign, page, 1u) == 0u);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 1u);
    assert(page[0].explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_TEXT_MATCH);
    assert(page[0].explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_CURRENT);
    char snap_first_content[64];
    snprintf(snap_first_content, sizeof snap_first_content, "%s", page[0].version.content);
    qihse_ai_memory_query_hits_free(page, 1u);

    qihse_ai_memory_knowledge_version_t updated;
    assert(qihse_ai_memory_knowledge_revise(server, owner, first.knowledge_id,
        first.version_id, first.revision, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "post-snapshot replacement", &updated) == QIHSE_AIMEM_WRITE_NEW);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 2u) == 1u);
    assert(strstr(page[0].version.content, "stable paging") != NULL);
    assert(strstr(page[0].version.content, "post-snapshot") == NULL);
    assert(strcmp(page[0].version.content, snap_first_content) != 0);
    qihse_ai_memory_query_hits_free(page, 1u);
    qihse_ai_memory_query_end(snapshot);

    qihse_ai_memory_query_v1_t changed = query;
    changed.text = NULL;
    changed.current_only = false;
    changed.changed_since_ms = first.valid_from_ingest_ms ? first.valid_from_ingest_ms - 1u : 0u;
    snapshot = qihse_ai_memory_query_begin(server, reader, &changed); assert(snapshot);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 2u) == 2u);
    qihse_ai_memory_query_hits_free(page, 2u);
    qihse_ai_memory_query_end(snapshot);

    qihse_ai_memory_query_v1_t as_of = query;
    as_of.text = NULL;
    as_of.as_of_ingest_ms = first.valid_from_ingest_ms;
    snapshot = qihse_ai_memory_query_begin(server, reader, &as_of); assert(snapshot);
    bool saw_first = false;
    bool saw_replacement = false;
    size_t as_of_count = 0u;
    for (;;) {
        memset(page, 0, sizeof page);
        size_t n = qihse_ai_memory_query_next(snapshot, reader, page, 2u);
        if (!n) break;
        as_of_count += n;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(page[i].version.version_id, first.version_id) == 0)
                saw_first = true;
            if (strcmp(page[i].version.version_id, updated.version_id) == 0)
                saw_replacement = true;
        }
        qihse_ai_memory_query_hits_free(page, n);
    }
    assert(as_of_count >= 1u && saw_first && !saw_replacement);
    qihse_ai_memory_query_end(snapshot);

    qihse_ai_memory_query_v1_t semantic = query;
    semantic.mode = QIHSE_AIMEM_MODE_SEMANTIC;
    semantic.text = "stable paging";
    snapshot = qihse_ai_memory_query_begin(server, reader, &semantic); assert(snapshot);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 1u);
    assert(page[0].explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_SEMANTIC);
    assert(page[0].semantic_score > 0.0);
    qihse_ai_memory_query_hits_free(page, 1u);
    qihse_ai_memory_query_end(snapshot);

    qihse_ai_memory_query_v1_t hybrid = query;
    hybrid.mode = QIHSE_AIMEM_MODE_HYBRID;
    snapshot = qihse_ai_memory_query_begin(server, reader, &hybrid); assert(snapshot);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 1u);
    assert(page[0].explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_BM25);
    assert(page[0].explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_SEMANTIC);
    assert(page[0].explain_flags & QIHSE_AIMEM_QUERY_EXPLAIN_RRF);
    qihse_ai_memory_query_hits_free(page, 1u);
    qihse_ai_memory_query_end(snapshot);

    snapshot = qihse_ai_memory_query_begin(server, reader, &query); assert(snapshot);
    assert(qihse_ai_memory_project_revoke(server, owner, scope.project, 9502u));
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 0u);
    qihse_ai_memory_query_end(snapshot);
    qihse_ai_memory_health_t denied_health;
    assert(!qihse_ai_memory_health(server, reader, &scope, &denied_health));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9502u));

    qihse_ai_memory_maintenance_plan_t extractive = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
        &scope, "post-snapshot", QIHSE_AIMEM_RETENTION_EPISODIC,
        QIHSE_AIMEM_MAINT_EXTRACTIVE, true, &extractive) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_maintenance_free(&extractive);
    qihse_ai_memory_maintenance_plan_t dry = {0}, plan = {0}, applied = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
        &scope, "maintenance replacement", QIHSE_AIMEM_RETENTION_SEMANTIC,
        QIHSE_AIMEM_MAINT_REWRITE, true, &dry) == QIHSE_AIMEM_WRITE_NEW);
    assert(strlen(dry.source_content_sha256) == 64u &&
           strlen(dry.replacement_content_sha256) == 64u);
    assert(dry.retention_tier == QIHSE_AIMEM_RETENTION_SEMANTIC);
    qihse_ai_memory_maintenance_plan_t dry_repeat = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
        &scope, "maintenance replacement", QIHSE_AIMEM_RETENTION_SEMANTIC,
        QIHSE_AIMEM_MAINT_REWRITE, true, &dry_repeat) == QIHSE_AIMEM_WRITE_NEW);
    assert(strcmp(dry.plan_id, dry_repeat.plan_id) == 0);
    assert(strcmp(dry.source_content_sha256, dry_repeat.source_content_sha256) == 0);
    qihse_ai_memory_maintenance_free(&dry_repeat);
    for (uint32_t tier = QIHSE_AIMEM_RETENTION_WORKING;
         tier <= QIHSE_AIMEM_RETENTION_PINNED; tier++) {
        qihse_ai_memory_maintenance_plan_t tier_plan = {0};
        assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
            &scope, "post-snapshot replacement", tier,
            QIHSE_AIMEM_MAINT_RETENTION_CHANGE, true, &tier_plan) == QIHSE_AIMEM_WRITE_NEW);
        assert(tier_plan.retention_tier == tier);
        qihse_ai_memory_maintenance_free(&tier_plan);
    }
    qihse_ai_memory_maintenance_plan_t pinned_rewrite = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
        &scope, "forbidden pinned rewrite", QIHSE_AIMEM_RETENTION_PINNED,
        QIHSE_AIMEM_MAINT_REWRITE, true, &pinned_rewrite) == QIHSE_AIMEM_WRITE_FAILED);
    qihse_ai_memory_knowledge_version_t latest;
    assert(qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &scope, &latest));
    assert(strcmp(latest.content, "post-snapshot replacement") == 0);
    qihse_ai_memory_knowledge_free(&latest);
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
        &scope, "maintenance replacement", QIHSE_AIMEM_RETENTION_SEMANTIC,
        QIHSE_AIMEM_MAINT_REWRITE, false, &plan) == QIHSE_AIMEM_WRITE_NEW);
    assert(strcmp(dry.plan_id, plan.plan_id) == 0);
    qihse_ai_memory_maintenance_plan_t plan_replay = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, first.knowledge_id,
        &scope, "maintenance replacement", QIHSE_AIMEM_RETENTION_SEMANTIC,
        QIHSE_AIMEM_MAINT_REWRITE, false, &plan_replay) == QIHSE_AIMEM_WRITE_REPLAY);
    assert(strcmp(plan.plan_id, plan_replay.plan_id) == 0);
    qihse_ai_memory_maintenance_free(&plan_replay);
    qihse_ai_memory_maintenance_plan_t unauthorized = {0};
    assert(qihse_ai_memory_maintenance_apply(server, reader, plan.plan_id,
        &unauthorized) == QIHSE_AIMEM_WRITE_FAILED);

    /* Close the parent handles before fork so the child never inherits a live
     * store/server pthread object or a stale WAL descriptor. */
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset(); server = NULL; store = NULL;
    /* The audit writer lock is exclusive across processes. Release it before
     * the child opens its own audit context, then reacquire after child death. */
    qihse_audit_flush(); qihse_audit_shutdown();
    /* Kill a separate process after the plan transition is durably synced. */
    pid_t maintainer = fork();
    assert(maintainer >= 0);
    if (maintainer == 0) {
        /* Never reuse the inherited server/store pthread state in the forked
         * process. Open a fresh store handle and server before recovery. */
        qihse_audit_init();
        qihse_kv_store_t* child_store = qihse_kv_store_create();
        assert(child_store);
        server = make_server(child_store);
        qihse_ai_memory_maintenance_plan_t child_applied = {0};
        assert(qihse_ai_memory_maintenance_apply(server, owner, plan.plan_id,
            &child_applied) == QIHSE_AIMEM_WRITE_NEW);
        assert(qihse_kv_sync_store(child_store));
        qihse_ai_memory_maintenance_free(&child_applied);
        kill(getpid(), SIGKILL);
        _exit(99);
    }
    int maintainer_status = 0;
    assert(waitpid(maintainer, &maintainer_status, 0) == maintainer);
    assert(WIFSIGNALED(maintainer_status) && WTERMSIG(maintainer_status) == SIGKILL);
    qihse_audit_init();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    assert(qihse_ai_memory_maintenance_apply(server, owner, plan.plan_id, &applied) ==
           QIHSE_AIMEM_WRITE_REPLAY);
    assert(applied.state == QIHSE_AIMEM_MAINT_APPLIED);
    qihse_ai_memory_maintenance_plan_t replay = {0};
    assert(qihse_ai_memory_maintenance_apply(server, owner, plan.plan_id, &replay) ==
           QIHSE_AIMEM_WRITE_REPLAY);
    qihse_ai_memory_maintenance_free(&replay);
    assert(qihse_kv_sync_store(store));

    query.text = "maintenance replacement";
    snapshot = qihse_ai_memory_query_begin(server, reader, &query); assert(snapshot);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 1u);
    assert(strcmp(page[0].version.content, "maintenance replacement") == 0);
    qihse_ai_memory_query_hits_free(page, 1u);
    qihse_ai_memory_query_end(snapshot);

    /* Simulate a crash after the QHK successor is durable but before QHM2 is
     * advanced: restart must recognize its exact source hash and finish it. */
    qihse_ai_memory_maintenance_plan_t gap_plan = {0}, gap_result = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, second.knowledge_id,
        &scope, "recovered after gap", QIHSE_AIMEM_RETENTION_PROCEDURAL,
        QIHSE_AIMEM_MAINT_REWRITE, false, &gap_plan) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_knowledge_version_t gap_source = {0}, gap_successor = {0};
    assert(qihse_ai_memory_knowledge_latest(server, owner, second.knowledge_id,
        &scope, &gap_source));
    assert(qihse_ai_memory_knowledge_revise(server, owner, second.knowledge_id,
        gap_source.version_id, gap_source.revision, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "recovered after gap", &gap_successor) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_knowledge_free(&gap_source);
    qihse_ai_memory_knowledge_free(&gap_successor);
    assert(qihse_kv_sync_store(store));
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    assert(qihse_ai_memory_maintenance_apply(server, owner, gap_plan.plan_id,
        &gap_result) == QIHSE_AIMEM_WRITE_NEW);
    assert(gap_result.state == QIHSE_AIMEM_MAINT_APPLIED);
    qihse_ai_memory_maintenance_free(&gap_result);

    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    assert(qihse_ai_memory_maintenance_apply(server, owner, plan.plan_id, &replay) ==
           QIHSE_AIMEM_WRITE_REPLAY);
    qihse_ai_memory_maintenance_free(&replay);

    qihse_ai_memory_maintenance_plan_t rolled = {0};
    assert(qihse_ai_memory_maintenance_rollback(server, owner, plan.plan_id, &rolled) ==
           QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &scope, &latest));
    assert(strcmp(latest.content, "post-snapshot replacement") == 0);
    assert(strcmp(rolled.source_content_sha256, plan.source_content_sha256) == 0);
    qihse_ai_memory_knowledge_free(&latest);
    query.text = "post-snapshot replacement";
    snapshot = qihse_ai_memory_query_begin(server, reader, &query); assert(snapshot);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 1u);
    assert(strcmp(page[0].version.content, "post-snapshot replacement") == 0);
    qihse_ai_memory_query_hits_free(page, 1u);
    qihse_ai_memory_query_end(snapshot);

    /* Same project membership, insufficient label: query and export omit it. */
    assert(qihse_ai_memory_store_scoped(server, high, "high owner seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));
    qihse_ai_memory_knowledge_version_t secret;
    assert(qihse_ai_memory_knowledge_create(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "stable paging QH0508_HIGH_SECRET", &secret) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_query_v1_t hidden_query = query;
    hidden_query.text = "QH0508_HIGH_SECRET";
    qihse_ai_memory_query_snapshot_t* hidden_snapshot =
        qihse_ai_memory_query_begin(server, reader, &hidden_query);
    assert(hidden_snapshot);
    memset(page, 0, sizeof page);
    assert(qihse_ai_memory_query_next(hidden_snapshot, reader, page, 2u) == 0u);
    qihse_ai_memory_query_end(hidden_snapshot);
    qihse_ai_memory_export_t low_export = {0};
    assert(qihse_ai_memory_export_scope(server, reader, &scope, &low_export));
    assert(export_count(&low_export) == 3u);
    assert(!memmem(low_export.data, low_export.len, secret.version_id,
                   strlen(secret.version_id)));
    uint8_t* tampered = malloc(low_export.len); assert(tampered);
    memcpy(tampered, low_export.data, low_export.len); tampered[5] ^= 1u;
    size_t imported = 99u;
    assert(qihse_ai_memory_import_scope(server, owner, &scope, tampered,
        low_export.len, true, &imported) == QIHSE_AIMEM_IMPORT_FAILED);
    assert(imported == 0u); free(tampered);

    static const uint8_t archive_key[] = "QH07-test-authentication-key-32";
    static const uint8_t wrong_key[] = "QH07-wrong-authentication-key-32";
    qihse_ai_memory_export_t authenticated = {0};
    assert(qihse_ai_memory_export_authenticated(server, reader, &scope,
        archive_key, sizeof archive_key - 1u, &authenticated));
    assert(authenticated_export_count(&authenticated) == 4u);
    assert(memmem(authenticated.data, authenticated.len, "QH0508_HIGH_SECRET",
                  strlen("QH0508_HIGH_SECRET")) == NULL);
    uint8_t* auth_tampered = malloc(authenticated.len); assert(auth_tampered);
    memcpy(auth_tampered, authenticated.data, authenticated.len);
    auth_tampered[authenticated.len / 2u] ^= 1u;
    assert(qihse_ai_memory_import_authenticated(server, owner, &scope,
        archive_key, sizeof archive_key - 1u, auth_tampered, authenticated.len,
        true, &imported) == QIHSE_AIMEM_IMPORT_FAILED);
    assert(qihse_ai_memory_import_authenticated(server, owner, &scope,
        wrong_key, sizeof wrong_key - 1u, authenticated.data, authenticated.len,
        true, &imported) == QIHSE_AIMEM_IMPORT_FAILED);
    free(auth_tampered);
    stream_t streamed = {0}; size_t streamed_bytes = 0u;
    assert(qihse_ai_memory_export_stream(server, reader, &scope,
        archive_key, sizeof archive_key - 1u, 97u, stream_write, &streamed,
        &streamed_bytes));
    assert(streamed_bytes == streamed.len && streamed.len == authenticated.len &&
           memcmp(streamed.data, authenticated.data, streamed.len) == 0);
    assert(!qihse_ai_memory_export_stream(server, reader, &scope,
        archive_key, sizeof archive_key - 1u, QIHSE_AIMEM_ARCHIVE_CHUNK_MAX + 1u,
        stream_write, &streamed, &streamed_bytes));
    assert(qihse_ai_memory_import_stream(server, owner, &scope,
        archive_key, sizeof archive_key - 1u, invalid_stream_read, NULL,
        true, &imported) == QIHSE_AIMEM_IMPORT_FAILED);

    assert(!qihse_ai_memory_index_rebuild(server, owner, &scope));
    assert(qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    qihse_ai_memory_health_t health;
    assert(qihse_ai_memory_health(server, owner, &scope, &health));
    assert(health.ready && health.provider[0] && health.dimension > 0u);
    assert(health.generation == 0u && health.query_snapshots == 0u &&
           health.exports == 0u && health.rejected == 0u);
    assert(qihse_kv_sync_store(store));

    /* Remove the caller-visible projection and restore it through the logical
     * archive.  The high-classified row survives the low caller's clear. */
    assert(qihse_kv_clear_user(store, owner) > 0u);
    assert(qihse_ai_memory_store_scoped(server, owner, "destination owner seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));
    streamed.at = 0u;
    assert(qihse_ai_memory_import_stream(server, owner, &scope,
        archive_key, sizeof archive_key - 1u, stream_read, &streamed,
        true, &imported) == QIHSE_AIMEM_IMPORT_VALID);
    assert(imported == 0u);
    assert(setenv("QIHSE_AIMEM_IMPORT_FAIL_AFTER", "1", 1) == 0);
    qihse_ai_memory_import_result_t import_result = qihse_ai_memory_import_authenticated(
        server, owner, &scope, archive_key, sizeof archive_key - 1u,
        authenticated.data, authenticated.len, false, &imported);
    assert(import_result == QIHSE_AIMEM_IMPORT_FAILED && imported == 1u);
    assert(unsetenv("QIHSE_AIMEM_IMPORT_FAIL_AFTER") == 0);
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    import_result = qihse_ai_memory_import_authenticated(server, owner, &scope,
        archive_key, sizeof archive_key - 1u, authenticated.data,
        authenticated.len, false, &imported);
    if (import_result != QIHSE_AIMEM_IMPORT_APPLIED)
        fprintf(stderr, "import result=%u imported=%zu\n", (unsigned)import_result, imported);
    assert(import_result == QIHSE_AIMEM_IMPORT_APPLIED);
    assert(imported == 3u);
    assert(qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &scope, &latest));
    assert(strcmp(latest.content, "post-snapshot replacement") == 0);
    qihse_ai_memory_knowledge_free(&latest);
    assert(!qihse_ai_memory_knowledge_get(server, owner, secret.version_id, &scope, &latest));
    assert(qihse_ai_memory_knowledge_latest(server, owner, related.knowledge_id,
        &scope, &latest));
    assert(latest.source_event_count == 1u && latest.relation_count == 1u &&
           strcmp(latest.source_event_ids[0], event_id) == 0 &&
           latest.relations[0].type == QIHSE_AIMEM_RELATION_CAUSES &&
           latest.confidence_ppm == 800000u);
    qihse_ai_memory_knowledge_free(&latest);
    qihse_ai_memory_hit_t restored_event = {0};
    assert(qihse_ai_memory_event_get(server, owner, event_id, &scope, &restored_event));
    assert(strstr(restored_event.text, "QH07_EVENT_ROUND_TRIP") != NULL);
    free(restored_event.text);
    assert(qihse_ai_memory_import_authenticated(server, owner, &scope,
        archive_key, sizeof archive_key - 1u, authenticated.data,
        authenticated.len, false, &imported) == QIHSE_AIMEM_IMPORT_APPLIED);
    assert(imported == 0u);
    char collision_key[160];
    assert(snprintf(collision_key, sizeof collision_key,
        "t:17/aimem-knowledge:%s", first.knowledge_id) > 0);
    assert(qihse_kv_set_user(store, collision_key, "QHK-COLLISION", 0u, 0u, owner));
    assert(qihse_ai_memory_import_authenticated(server, owner, &scope,
        archive_key, sizeof archive_key - 1u, authenticated.data,
        authenticated.len, false, &imported) == QIHSE_AIMEM_IMPORT_CONFLICT);

    qihse_ai_memory_maintenance_plan_t high_plan = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, high, secret.knowledge_id,
        &scope, secret.content, QIHSE_AIMEM_RETENTION_PINNED,
        QIHSE_AIMEM_MAINT_RETENTION_CHANGE, false, &high_plan) == QIHSE_AIMEM_WRITE_NEW);
    char high_plan_key[128];
    snprintf(high_plan_key, sizeof high_plan_key, "t:17/aimem-maint:%s", high_plan.plan_id);
    qihse_kv_record_meta_t high_plan_meta;
    assert(qihse_kv_meta_user(store, high_plan_key, high, &high_plan_meta));
    assert(high_plan_meta.classification == 5u);
    assert(!qihse_kv_meta_user(store, high_plan_key, reader, &high_plan_meta));
    char* unauthorized_plan = qihse_kv_get_user(store, high_plan_key, reader);
    assert(unauthorized_plan == NULL);

    qihse_ai_memory_relation_t contradiction = {
        .type = QIHSE_AIMEM_RELATION_CONTRADICTS,
        .target_scope = scope
    };
    snprintf(contradiction.target_version_id,
        sizeof contradiction.target_version_id, "%s", second.version_id);
    qihse_ai_memory_knowledge_provenance_t contradiction_provenance = {
        .relations = &contradiction, .relation_count = 1u
    };
    qihse_ai_memory_knowledge_version_t flagged = {0};
    assert(qihse_ai_memory_knowledge_create_ex(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "explicitly contradictory item", &contradiction_provenance, &flagged) ==
        QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_maintenance_plan_t rejected_contradiction = {0};
    assert(qihse_ai_memory_maintenance_plan_ex(server, owner, flagged.knowledge_id,
        &scope, "explicitly contradictory item", QIHSE_AIMEM_RETENTION_SEMANTIC,
        QIHSE_AIMEM_MAINT_EXTRACTIVE, true, &rejected_contradiction) ==
        QIHSE_AIMEM_WRITE_FAILED);
    assert(qihse_ai_memory_knowledge_latest(server, owner, flagged.knowledge_id,
        &scope, &latest));
    assert(strcmp(latest.content, "explicitly contradictory item") == 0);
    qihse_ai_memory_knowledge_free(&latest);

    qihse_ai_memory_export_free(&low_export);
    qihse_ai_memory_export_free(&authenticated);
    free(streamed.data);
    qihse_ai_memory_knowledge_free(&first);
    qihse_ai_memory_knowledge_free(&second);
    qihse_ai_memory_knowledge_free(&updated);
    qihse_ai_memory_knowledge_free(&secret);
    qihse_ai_memory_knowledge_free(&related);
    qihse_ai_memory_maintenance_free(&dry);
    qihse_ai_memory_maintenance_free(&plan);
    qihse_ai_memory_maintenance_free(&applied);
    qihse_ai_memory_maintenance_free(&rolled);
    qihse_ai_memory_maintenance_free(&high_plan);
    qihse_ai_memory_knowledge_free(&flagged);
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    puts("PASS QH-05 stable query, QH-06 rollback, QH-07 round-trip, QH-08 redaction");
    return 0;
}
