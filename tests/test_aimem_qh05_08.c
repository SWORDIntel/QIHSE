/* Focused QH-05..08 native contracts: stable authorized paging, reversible
 * one-lineage maintenance, canonical projection, and redacted rebuild state. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int main(void) {
    char source_root[] = "build/aimem_qh05_08_source_XXXXXX";
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

    qihse_ai_memory_knowledge_version_t first, second;
    assert(qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_DECISION, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "stable paging first", &first) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "stable paging second", &second) == QIHSE_AIMEM_WRITE_NEW);

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

    snapshot = qihse_ai_memory_query_begin(server, reader, &query); assert(snapshot);
    assert(qihse_ai_memory_project_revoke(server, owner, scope.project, 9502u));
    assert(qihse_ai_memory_query_next(snapshot, reader, page, 1u) == 0u);
    qihse_ai_memory_query_end(snapshot);
    qihse_ai_memory_health_t denied_health;
    assert(!qihse_ai_memory_health(server, reader, &scope, &denied_health));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9502u));

    qihse_ai_memory_maintenance_plan_t dry = {0}, plan = {0}, applied = {0};
    assert(qihse_ai_memory_maintenance_plan(server, owner, first.knowledge_id,
        &scope, "maintenance replacement", true, &dry) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_knowledge_version_t latest;
    assert(qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &scope, &latest));
    assert(strcmp(latest.content, "post-snapshot replacement") == 0);
    qihse_ai_memory_knowledge_free(&latest);
    assert(qihse_ai_memory_maintenance_plan(server, owner, first.knowledge_id,
        &scope, "maintenance replacement", false, &plan) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_maintenance_apply(server, owner, plan.plan_id, &applied) ==
           QIHSE_AIMEM_WRITE_NEW);
    assert(applied.state == QIHSE_AIMEM_MAINT_APPLIED);
    qihse_ai_memory_maintenance_plan_t replay = {0};
    assert(qihse_ai_memory_maintenance_apply(server, owner, plan.plan_id, &replay) ==
           QIHSE_AIMEM_WRITE_REPLAY);
    qihse_ai_memory_maintenance_free(&replay);
    assert(qihse_kv_sync_store(store));

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
    qihse_ai_memory_knowledge_free(&latest);

    /* Same project membership, insufficient label: query and export omit it. */
    assert(qihse_ai_memory_store_scoped(server, high, "high owner seed",
        QIHSE_AIMEM_EPISODIC, &scope, seed));
    qihse_ai_memory_knowledge_version_t secret;
    assert(qihse_ai_memory_knowledge_create(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "QH0508_HIGH_SECRET", &secret) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_export_t low_export = {0};
    assert(qihse_ai_memory_export_scope(server, reader, &scope, &low_export));
    assert(export_count(&low_export) == 2u);
    assert(!memmem(low_export.data, low_export.len, secret.version_id,
                   strlen(secret.version_id)));
    uint8_t* tampered = malloc(low_export.len); assert(tampered);
    memcpy(tampered, low_export.data, low_export.len); tampered[5] ^= 1u;
    size_t imported = 99u;
    assert(qihse_ai_memory_import_scope(server, owner, &scope, tampered,
        low_export.len, true, &imported) == QIHSE_AIMEM_IMPORT_FAILED);
    assert(imported == 0u); free(tampered);

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
    assert(qihse_ai_memory_import_scope(server, owner, &scope,
        low_export.data, low_export.len, true, &imported) == QIHSE_AIMEM_IMPORT_VALID);
    assert(imported == 0u);
    qihse_ai_memory_import_result_t import_result = qihse_ai_memory_import_scope(
        server, owner, &scope, low_export.data, low_export.len, false, &imported);
    if (import_result != QIHSE_AIMEM_IMPORT_APPLIED)
        fprintf(stderr, "import result=%u imported=%zu\n", (unsigned)import_result, imported);
    assert(import_result == QIHSE_AIMEM_IMPORT_APPLIED);
    assert(imported == 2u);
    assert(qihse_ai_memory_knowledge_latest(server, owner, first.knowledge_id, &scope, &latest));
    assert(strcmp(latest.content, "post-snapshot replacement") == 0);
    qihse_ai_memory_knowledge_free(&latest);
    assert(!qihse_ai_memory_knowledge_get(server, owner, secret.version_id, &scope, &latest));

    qihse_ai_memory_export_free(&low_export);
    qihse_ai_memory_knowledge_free(&first);
    qihse_ai_memory_knowledge_free(&second);
    qihse_ai_memory_knowledge_free(&updated);
    qihse_ai_memory_knowledge_free(&secret);
    qihse_ai_memory_maintenance_free(&dry);
    qihse_ai_memory_maintenance_free(&plan);
    qihse_ai_memory_maintenance_free(&applied);
    qihse_ai_memory_maintenance_free(&rolled);
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    puts("PASS QH-05 stable query, QH-06 rollback, QH-07 round-trip, QH-08 redaction");
    return 0;
}
