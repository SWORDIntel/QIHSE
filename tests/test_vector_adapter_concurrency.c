/* Focused adapter synchronization regression. The UWP helper is compiled
 * only for this test target; it is the same typed operation called by the
 * live UWP socket route. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_uwp.h"
#include "qihse_resp_wire.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_vector_db.h"

#include <assert.h>
#include <ftw.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define THREADS 8u
#define WRITES_PER_THREAD 160u
#define OPERATOR_PASSWORD "VectorAdapterConcurrencyPa1!"

typedef struct {
    qihse_uwp_context_t* uwp;
    qihse_resp_server_t* resp;
    qihse_user_t* user;
    uint64_t id_base;
    bool use_uwp;
    int failed;
} writer_arg_t;

static void* writer_main(void* opaque) {
    writer_arg_t* arg = opaque;
    const float vector[4] = {0.25f, 0.5f, 0.75f, 1.0f};
    for (size_t i = 0; i < WRITES_PER_THREAD; ++i) {
        uint64_t id = arg->id_base + i;
        if (arg->use_uwp) {
            if (!qihse_uwp_test_vector_set_user(arg->uwp, arg->user, id,
                                               vector, 4u)) {
                arg->failed = 1;
                break;
            }
        } else {
            char id_text[32];
            snprintf(id_text, sizeof(id_text), "%llu",
                     (unsigned long long)id);
            const char* values[] = {"VECSET", id_text, "4", "0.25", "0.5",
                                    "0.75", "1"};
            qihse_resp_arg_t argv[7];
            for (size_t a = 0; a < 7u; ++a) {
                argv[a].data = (const uint8_t*)values[a];
                argv[a].len = strlen(values[a]);
            }
            uint8_t* reply = NULL;
            size_t reply_len = 0u;
            bool ok = qihse_resp_server_execute(arg->resp, arg->user, 7u,
                                                 argv, &reply, &reply_len);
            if (!ok || !reply || reply_len < 3u || memcmp(reply, "+OK", 3u))
                arg->failed = 1;
            free(reply);
            if (arg->failed) break;
        }
    }
    return NULL;
}

typedef struct {
    qihse_vector_db_t vdb;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool acquired;
} independent_arg_t;

static void* independent_lock_main(void* opaque) {
    independent_arg_t* arg = opaque;
    assert(qihse_vector_db_adapter_lock(arg->vdb));
    assert(pthread_mutex_lock(&arg->mutex) == 0);
    arg->acquired = true;
    pthread_cond_signal(&arg->condition);
    pthread_mutex_unlock(&arg->mutex);
    qihse_vector_db_adapter_unlock(arg->vdb);
    return NULL;
}

static int remove_entry(const char* path, const struct stat* st,
                          int type, struct FTW* ftw) {
    (void)st; (void)type; (void)ftw;
    return remove(path);
}

int main(void) {
    char data_dir[] = "build/test_vector_adapter_concurrency_XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op && qihse_auth_user_is_active(op));

    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,
                                                    NULL, NULL);
    qihse_vector_db_t other = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY,
                                                      NULL, NULL);
    assert(vdb && other);
    assert(qihse_vector_db_adapter_lock(vdb));
    independent_arg_t independent = {.vdb = other};
    assert(pthread_mutex_init(&independent.mutex, NULL) == 0);
    assert(pthread_cond_init(&independent.condition, NULL) == 0);
    pthread_t independent_thread;
    assert(pthread_create(&independent_thread, NULL, independent_lock_main,
                          &independent) == 0);
    assert(pthread_mutex_lock(&independent.mutex) == 0);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 2;
    while (!independent.acquired) {
        int rc = pthread_cond_timedwait(&independent.condition,
                                        &independent.mutex, &deadline);
        assert(rc == 0);
    }
    pthread_mutex_unlock(&independent.mutex);
    assert(pthread_join(independent_thread, NULL) == 0);
    qihse_vector_db_adapter_unlock(vdb);
    pthread_cond_destroy(&independent.condition);
    pthread_mutex_destroy(&independent.mutex);
    qihse_vector_db_destroy(other);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = 0u;
    config.auth_required = true;
    config.enable_uwp_bridge = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    qihse_resp_server_t* resp = qihse_resp_server_create(&config);
    assert(resp);

    qihse_uwp_context_t uwp = {0};
    uwp.vdb = vdb;
    uwp.resp_server = resp;

    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(op, 7u, 7u,
        QIHSE_ROLE_ANALYST, 3u, 0u, "TenantVectorPa1!", false);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(op, 8u, 8u,
        QIHSE_ROLE_ANALYST, 3u, 0u, "TenantVectorPa2!", false);
    assert(tenant7 && tenant8);
    const uint64_t protected_id = 9001u;
    assert(qihse_auth_grant_object(op, tenant7, 0u, protected_id,
                                   QIHSE_ACL_WRITE));
    assert(qihse_auth_grant_object(op, tenant8, 0u, protected_id,
                                   QIHSE_ACL_WRITE));
    assert(qihse_auth_grant_object(op, tenant7, 0u, protected_id + 1u,
                                   QIHSE_ACL_WRITE));
    const float protected_vector[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    const char tenant7_tag[] = "t:7/private";
    const void* protected_metadata[] = {tenant7_tag};
    const size_t protected_metadata_sizes[] = {sizeof(tenant7_tag) - 1u};
    assert(qihse_vector_db_upsert_by_ids_user(vdb, op, &protected_id,
        protected_vector, 1u, 4u, protected_metadata,
        protected_metadata_sizes, NULL, NULL));
    const float replacement[4] = {9.0f, 8.0f, 7.0f, 6.0f};
    assert(!qihse_uwp_test_vector_set_user(&uwp, tenant8, protected_id,
                                           replacement, 4u));
    assert(!qihse_uwp_test_vector_set_user(&uwp, tenant7, protected_id + 1u,
                                           replacement, 4u));
    const char* untagged_args[] = {"VECSET", "9003", "4", "1", "2", "3", "4"};
    qihse_resp_arg_t untagged_request[7];
    for (size_t i = 0; i < 7u; ++i) {
        untagged_request[i].data = (const uint8_t*)untagged_args[i];
        untagged_request[i].len = strlen(untagged_args[i]);
    }
    uint8_t* untagged_reply = NULL;
    size_t untagged_reply_size = 0u;
    assert(qihse_resp_server_execute(resp, tenant7, 7u, untagged_request,
        &untagged_reply, &untagged_reply_size));
    assert(untagged_reply && memmem(untagged_reply, untagged_reply_size,
                                    "NOPERM", 6u));
    free(untagged_reply);
    assert(qihse_uwp_test_vector_set_user(&uwp, tenant7, protected_id,
                                           replacement, 4u));
    void* preserved_tag = NULL;
    size_t preserved_tag_size = 0u;
    assert(qihse_vector_db_get_metadata_by_id_user(vdb, tenant7, protected_id,
        &preserved_tag, &preserved_tag_size));
    assert(preserved_tag_size == sizeof(tenant7_tag) - 1u &&
           memcmp(preserved_tag, tenant7_tag, preserved_tag_size) == 0);
    free(preserved_tag);

    pthread_t threads[THREADS];
    writer_arg_t args[THREADS];
    for (size_t i = 0; i < THREADS; ++i) {
        args[i] = (writer_arg_t){
            .uwp = &uwp,
            .resp = resp,
            .user = op,
            .id_base = 10000u + (uint64_t)i * WRITES_PER_THREAD,
            .use_uwp = (i & 1u) == 0u,
            .failed = 0
        };
        if (i & 1u) args[i].id_base += 100000u;
        assert(pthread_create(&threads[i], NULL, writer_main, &args[i]) == 0);
    }
    for (size_t i = 0; i < THREADS; ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
        assert(!args[i].failed);
    }

    float actual[4];
    size_t dims = 0u;
    for (size_t i = 0; i < THREADS; ++i) {
        uint64_t first = args[i].id_base;
        assert(qihse_vector_db_get_vector_by_id_user(vdb, op, first,
                                                      actual, &dims));
        assert(dims == 4u && actual[0] == 0.25f && actual[3] == 1.0f);
        uint64_t last = first + WRITES_PER_THREAD - 1u;
        assert(qihse_vector_db_get_vector_by_id_user(vdb, op, last,
                                                      actual, &dims));
    }

    qihse_resp_server_destroy(resp);
    qihse_kv_store_destroy(store);
    qihse_vector_db_destroy(vdb);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    assert(nftw(data_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    puts("test_vector_adapter_concurrency: all assertions passed");
    return 0;
}
