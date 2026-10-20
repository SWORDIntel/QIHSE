/* QH-08: durable generation cutover, interrupted-build recovery, provider
 * failure, Operator controls and ordinary-principal redaction. */
#include "qihse_ai_memory.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static qihse_resp_server_t* make_server(qihse_kv_store_t* store) {
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store; cfg.auth_required = true; cfg.port = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server); return server;
}

static bool failing_embed(const char* text, float* out, size_t dim, void* ctx) {
    (void)text; (void)out; (void)dim; (void)ctx; return false;
}

static void assert_redacted(const qihse_ai_memory_health_t* health) {
    assert(health->index_state == 0u && health->generation == 0u &&
           health->candidate_generation == 0u && health->source_highwater == 0u &&
           health->indexed_records == 0u && health->rebuild_started == 0u &&
           health->rebuild_ready == 0u && health->rebuild_failed == 0u &&
           health->provider_failures == 0u && health->recovered_builds == 0u &&
           health->audit_events == 0u && health->query_snapshots == 0u &&
           health->maintenance_versions == 0u && health->exports == 0u &&
           health->imports == 0u && health->rejected == 0u);
}

static int crash_child(const char* phase, const char* root) {
    if (setenv("QIHSE_DATA_DIR", root, 1) != 0 || !qihse_auth_init() ||
        !qihse_auth_bootstrap_operator("Qh08SystemOperator123!")) return 31;
    qihse_user_t* system_op = qihse_auth_get_user(0u);
    qihse_user_t* tenant_op = qihse_auth_create_tenant_user(system_op, 28u, 9801u,
        QIHSE_ROLE_OPERATOR, UINT16_MAX, UINT16_MAX, "Qh08TenantOperator123!", false);
    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_resp_server_t* child_server = store ? make_server(store) : NULL;
    qihse_ai_memory_scope_t scope = { "project-qh08", "tree-a", "stream-a", "session-a" };
    if (!tenant_op || !store || !child_server ||
        setenv("QIHSE_AIMEM_QH08_FAIL_AT", phase, 1) != 0 ||
        qihse_ai_memory_index_rebuild(child_server, tenant_op, &scope)) return 32;
    _exit(0); /* deliberate crash: skip server/store/audit teardown */
}

int main(int argc, char** argv) {
    if (argc == 3 && (strcmp(argv[1], "after-building") == 0 ||
                      strcmp(argv[1], "after-entries") == 0))
        return crash_child(argv[1], argv[2]);
    char root[] = "build/aimem_qh08_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("Qh08SystemOperator123!"));
    qihse_user_t* system_op = qihse_auth_get_user(0u);
    qihse_user_t* tenant_op = qihse_auth_create_tenant_user(system_op, 28u, 9801u,
        QIHSE_ROLE_OPERATOR, UINT16_MAX, UINT16_MAX, "Qh08TenantOperator123!", false);
    qihse_user_t* owner = qihse_auth_create_tenant_user(system_op, 28u, 9802u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh08OwnerPassword123!", false);
    qihse_user_t* reader = qihse_auth_create_tenant_user(system_op, 28u, 9803u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh08ReaderPassword123!", false);
    qihse_user_t* high = qihse_auth_create_tenant_user(system_op, 28u, 9804u,
        QIHSE_ROLE_GUEST, 5u, 1u, "Qh08HighPassword123!", false);
    qihse_user_t* foreign = qihse_auth_create_tenant_user(system_op, 29u, 9805u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh08ForeignPassword123!", false);
    assert(tenant_op && owner && reader && high && foreign);

    qihse_kv_store_t* store = qihse_kv_store_create(); assert(store);
    qihse_resp_server_t* server = make_server(store);
    qihse_ai_memory_scope_t scope = { "project-qh08", "tree-a", "stream-a", "session-a" };
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, owner, "owner scope seed",
        QIHSE_AIMEM_EPISODIC, &scope, id));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9803u));
    qihse_ai_memory_knowledge_version_t low, secret;
    assert(qihse_ai_memory_knowledge_create(server, owner, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "visible rebuild row", &low) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_store_scoped(server, high, "high scope seed",
        QIHSE_AIMEM_EPISODIC, &scope, id));
    assert(qihse_ai_memory_knowledge_create(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "QH08_HIGH_REBUILD_ROW", &secret) == QIHSE_AIMEM_WRITE_NEW);

    qihse_ai_memory_health_t health;
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(!health.ready && health.index_state == QIHSE_AIMEM_INDEX_NONE);
    assert(!qihse_ai_memory_index_rebuild(server, owner, &scope));
    assert(!qihse_ai_memory_index_recover(server, owner, &scope));
    assert(!qihse_ai_memory_health(server, foreign, &scope, &health));

    assert(qihse_kv_sync_store(store));
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    qihse_audit_flush(); qihse_audit_shutdown();
    pid_t crashed = fork(); assert(crashed >= 0);
    if (crashed == 0) {
        execl(argv[0], argv[0], "after-building", root, (char*)NULL);
        _exit(41);
    }
    int status = 0; assert(waitpid(crashed, &status, 0) == crashed);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    qihse_audit_init();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.index_state == QIHSE_AIMEM_INDEX_BUILDING && !health.ready &&
           health.generation == 0u && health.candidate_generation == 1u &&
           health.rebuild_started == 1u && health.audit_events == 1u);
    assert(qihse_ai_memory_index_recover(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.index_state == QIHSE_AIMEM_INDEX_FAILED && !health.ready &&
           health.rebuild_failed == 1u && health.recovered_builds == 1u &&
           health.audit_events == 2u);

    assert(qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
           health.generation == 2u && health.candidate_generation == 2u &&
           health.indexed_records == 2u && health.rebuild_ready == 1u);
    uint64_t ready_generation = health.generation;
    uint64_t ready_highwater = health.source_highwater;

    qihse_ai_memory_health_t ordinary;
    assert(qihse_ai_memory_health(server, owner, &scope, &ordinary));
    assert(ordinary.ready && ordinary.dimension == health.dimension &&
           strcmp(ordinary.provider, health.provider) == 0);
    assert_redacted(&ordinary);
    assert(qihse_ai_memory_health(server, reader, &scope, &ordinary));
    assert(ordinary.ready); assert_redacted(&ordinary);

    /* READY generation and metrics survive process reconstruction. */
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.ready && health.generation == ready_generation &&
           health.source_highwater == ready_highwater && health.indexed_records == 2u);

    /* A semantic provider failure records FAILED and never publishes a mixed
     * or lexical fallback generation. */
    qihse_ai_memory_embedder_t broken = { "qh08-explicit-failure", 8u,
                                          failing_embed, NULL };
    assert(qihse_ai_memory_set_embedder(&broken));
    assert(!qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(!health.ready && health.index_state == QIHSE_AIMEM_INDEX_FAILED &&
           health.generation == ready_generation && health.candidate_generation == 3u &&
           health.provider_failures == 1u && health.rebuild_failed == 2u);
    assert(strcmp(health.provider, "qh08-explicit-failure") == 0);
    assert(qihse_ai_memory_set_embedder(NULL));
    assert(qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
           health.generation == 4u && health.rebuild_ready == 2u &&
           health.provider_failures == 1u);

    /* Candidate entries are durable but never selected until READY. */
    assert(qihse_kv_sync_store(store));
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    qihse_audit_flush(); qihse_audit_shutdown();
    crashed = fork(); assert(crashed >= 0);
    if (crashed == 0) {
        execl(argv[0], argv[0], "after-entries", root, (char*)NULL);
        _exit(42);
    }
    status = 0; assert(waitpid(crashed, &status, 0) == crashed);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    qihse_audit_init();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(!health.ready && health.index_state == QIHSE_AIMEM_INDEX_BUILDING &&
           health.generation == 4u && health.candidate_generation == 5u);
    assert(qihse_ai_memory_index_recover(server, tenant_op, &scope));
    assert(qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.ready && health.generation == 6u && health.recovered_builds == 2u &&
           health.rebuild_failed == 3u && health.rebuild_ready == 3u &&
           health.audit_events == 12u);

    qihse_ai_memory_knowledge_free(&low);
    qihse_ai_memory_knowledge_free(&secret);
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    puts("PASS QH-08 generation swap, recovery, provider failure and redaction");
    return 0;
}
