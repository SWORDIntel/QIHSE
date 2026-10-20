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
    assert(op && owner && reader && foreign && high);

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

    assert(qihse_ai_memory_index_rebuild(server, owner, &scope));
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
    qihse_ai_memory_knowledge_free(&first);
    qihse_ai_memory_knowledge_free(&second);
    qihse_ai_memory_knowledge_free(&updated);
    qihse_ai_memory_knowledge_free(&secret);
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
