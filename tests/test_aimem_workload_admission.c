#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t wake;
    unsigned calls;
    bool blocked;
    bool release;
} slow_embed_t;

static bool slow_embed(const char* text, float* out, size_t dim, void* opaque) {
    (void)text;
    slow_embed_t* state = opaque;
    pthread_mutex_lock(&state->mutex);
    state->calls++;
    if (state->calls == 3u) {
        state->blocked = true;
        pthread_cond_broadcast(&state->wake);
        while (!state->release) pthread_cond_wait(&state->wake, &state->mutex);
    }
    pthread_mutex_unlock(&state->mutex);
    for (size_t i = 0; i < dim; i++) out[i] = (float)i;
    return true;
}

typedef struct {
    qihse_resp_server_t* server;
    qihse_user_t* user;
    qihse_ai_memory_scope_t scope;
    qihse_ai_memory_index_control_t* control;
    bool result;
} rebuild_args_t;

static void* controlled_rebuild(void* opaque) {
    rebuild_args_t* args = opaque;
    args->result = qihse_ai_memory_index_rebuild_controlled(args->server,
        args->user, &args->scope, args->control);
    return NULL;
}

int main(void) {
    char root[] = "build/aimem_workload_admission_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("AimemWorkloadOperator123!"));
    qihse_user_t* system = qihse_auth_get_user(0u);
    assert(system);
    qihse_user_t* tenant_op = qihse_auth_create_tenant_user(system, 37u, 3701u,
        QIHSE_ROLE_OPERATOR, UINT16_MAX, UINT16_MAX,
        "AimemWorkloadTenantOp123!", false);
    qihse_user_t* low = qihse_auth_create_tenant_user(system, 37u, 3702u,
        QIHSE_ROLE_GUEST, 0u, 0u, "AimemWorkloadLow123!", false);
    qihse_user_t* high = qihse_auth_create_tenant_user(system, 37u, 3703u,
        QIHSE_ROLE_GUEST, 5u, 1u, "AimemWorkloadHigh123!", false);
    assert(tenant_op && low && high);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.auth_required = true;
    config.port = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server);
    qihse_ai_memory_scope_t scope = { "workload-project", "tree-a", "stream-a", "session-a" };
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, high, "high scope seed",
        QIHSE_AIMEM_EPISODIC, &scope, id));
    qihse_ai_memory_knowledge_version_t secret = {0};
    assert(qihse_ai_memory_knowledge_create(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_GOTCHA, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "HIGH_WORKLOAD_SECRET", &secret) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_knowledge_free(&secret);
    assert(qihse_ai_memory_knowledge_create(server, high, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "SECOND_HIGH_WORKLOAD_SECRET", &secret) == QIHSE_AIMEM_WRITE_NEW);
    qihse_ai_memory_knowledge_free(&secret);

    /* Admission cannot be used to bypass the existing Operator gate. A
     * low-clearance user gets no classified payload from the rebuild API. */
    assert(!qihse_ai_memory_index_rebuild(server, low, &scope));
    assert(!qihse_ai_memory_index_rebuild(server, NULL, &scope));
    assert(!qihse_ai_memory_index_control_create(low));

    slow_embed_t slow = { .mutex = PTHREAD_MUTEX_INITIALIZER,
                          .wake = PTHREAD_COND_INITIALIZER };
    qihse_ai_memory_embedder_t embedder = { "w11-controlled-embedder", 8u,
                                            slow_embed, &slow };
    assert(qihse_ai_memory_set_embedder(&embedder));
    qihse_ai_memory_index_control_t* control =
        qihse_ai_memory_index_control_create(tenant_op);
    assert(control);
    rebuild_args_t args = { server, tenant_op, scope, control, false };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, controlled_rebuild, &args) == 0);
    pthread_mutex_lock(&slow.mutex);
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 10;
    while (!slow.blocked)
        assert(pthread_cond_timedwait(&slow.wake, &slow.mutex, &deadline) == 0);
    pthread_mutex_unlock(&slow.mutex);

    /* The first rebuild holds the tenant's declared byte reservation. A
     * second request must backpressure before provider work or a BUILDING
     * generation is allocated. */
    assert(!qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    pthread_mutex_lock(&slow.mutex);
    assert(slow.calls == 3u);
    pthread_mutex_unlock(&slow.mutex);

    qihse_ai_memory_rebuild_progress_t progress = {0};
    assert(qihse_ai_memory_index_control_status(control, tenant_op, &progress));
    assert(progress.phase == QIHSE_AIMEM_REBUILD_SCANNING &&
           progress.processed_records == 1u &&
           progress.record_limit == QIHSE_AIMEM_QUERY_MAX_ROWS);
    progress.processed_records = 99u;
    assert(!qihse_ai_memory_index_control_status(control, low, &progress));
    assert(progress.processed_records == 0u && progress.phase == QIHSE_AIMEM_REBUILD_IDLE);
    assert(!qihse_ai_memory_index_control_cancel(control, low));
    assert(!qihse_ai_memory_index_control_destroy(control, low));
    assert(!qihse_ai_memory_index_control_destroy(control, tenant_op));
    assert(qihse_ai_memory_index_control_cancel(control, tenant_op));
    pthread_mutex_lock(&slow.mutex);
    slow.release = true;
    pthread_cond_broadcast(&slow.wake);
    pthread_mutex_unlock(&slow.mutex);
    assert(pthread_join(thread, NULL) == 0);
    assert(!args.result);
    assert(qihse_ai_memory_index_control_status(control, tenant_op, &progress));
    assert(progress.phase == QIHSE_AIMEM_REBUILD_CANCELLED &&
           progress.processed_records == 1u);
    assert(!qihse_ai_memory_index_control_cancel(control, tenant_op));
    assert(qihse_ai_memory_index_control_destroy(control, tenant_op));
    assert(pthread_cond_destroy(&slow.wake) == 0);
    assert(pthread_mutex_destroy(&slow.mutex) == 0);
    qihse_ai_memory_health_t health;
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(!health.ready && health.index_state == QIHSE_AIMEM_INDEX_FAILED &&
           health.generation == 0u && health.candidate_generation == 1u);
    assert(qihse_ai_memory_set_embedder(NULL));
    assert(qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
           health.generation == 2u);

    /* The private READY CAS can commit before public readiness is published.
     * Report that state truthfully, and leave lookups fail closed. */
    control = qihse_ai_memory_index_control_create(tenant_op);
    assert(control);
    assert(setenv("QIHSE_AIMEM_QH08_FAIL_AT", "after-private-ready", 1) == 0);
    assert(!qihse_ai_memory_index_rebuild_controlled(server, tenant_op, &scope, control));
    assert(unsetenv("QIHSE_AIMEM_QH08_FAIL_AT") == 0);
    assert(qihse_ai_memory_index_control_status(control, tenant_op, &progress));
    assert(progress.phase == QIHSE_AIMEM_REBUILD_COMMITTED_UNAVAILABLE);
    assert(!qihse_ai_memory_index_control_cancel(control, tenant_op));
    assert(qihse_ai_memory_index_control_destroy(control, tenant_op));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(!health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
           health.generation == 3u);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create();
    assert(store);
    config.store = store;
    server = qihse_resp_server_create(&config);
    assert(server);
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(!health.ready && health.index_state == QIHSE_AIMEM_INDEX_READY &&
           health.generation == 3u);
    assert(qihse_ai_memory_index_rebuild(server, tenant_op, &scope));
    assert(qihse_ai_memory_health(server, tenant_op, &scope, &health));
    assert(health.ready && health.generation == 4u);

    /* Revocation removes status/cancel authority, but the exact initiating
     * handle may release the process-local allocation after its worker ends. */
    control = qihse_ai_memory_index_control_create(tenant_op);
    assert(control);
    assert(qihse_auth_destroy_user(system, 3701u));
    progress.processed_records = 99u;
    assert(!qihse_ai_memory_index_control_status(control, tenant_op, &progress));
    assert(progress.processed_records == 0u &&
           progress.phase == QIHSE_AIMEM_REBUILD_IDLE);
    assert(!qihse_ai_memory_index_control_cancel(control, tenant_op));
    assert(!qihse_ai_memory_index_control_destroy(control, low));
    assert(qihse_ai_memory_index_control_destroy(control, tenant_op));

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    puts("test_aimem_workload_admission: all assertions passed");
    return 0;
}
