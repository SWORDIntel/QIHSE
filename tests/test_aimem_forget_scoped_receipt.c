/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
/* Exact scoped forget retries survive restart and never expose high data. */
#include "aimem_fixture_cleanup.h"
#include "qihse_ai_memory.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static qihse_resp_server_t* server;

static char* call(qihse_user_t* user, const char* const* parts, size_t count) {
    qihse_resp_arg_t args[8];
    assert(count <= sizeof args / sizeof args[0]);
    for (size_t i = 0; i < count; ++i) {
        args[i].data = (const uint8_t*)parts[i];
        args[i].len = strlen(parts[i]);
    }
    uint8_t* raw = NULL;
    size_t len = 0;
    assert(qihse_resp_server_execute(server, user, count, args, &raw, &len));
    char* response = malloc(len + 1u);
    assert(response);
    memcpy(response, raw, len);
    response[len] = '\0';
    free(raw);
    return response;
}

static qihse_resp_server_t* make_server(qihse_kv_store_t* store) {
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.port = 0u;
    qihse_resp_server_t* result = qihse_resp_server_create(&cfg);
    assert(result);
    return result;
}

typedef struct {
    qihse_user_t* user;
    const char* const* parts;
    char* response;
} forget_thread_t;

static void* forget_in_thread(void* arg) {
    forget_thread_t* work = arg;
    work->response = call(work->user, work->parts, 8u);
    return NULL;
}

int main(void) {
    char data_root[] = "./aimem_forget_receipt_XXXXXX";
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ForgetReceiptOperator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* high = qihse_auth_create_tenant_user(op, 52u, 9201u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "ForgetReceiptHigh123!", false);
    qihse_user_t* low = qihse_auth_create_tenant_user(op, 52u, 9202u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "ForgetReceiptLow123!", false);
    qihse_user_t* class_only = qihse_auth_create_tenant_user(op, 52u, 9203u,
        QIHSE_ROLE_ANALYST, 0u, 1u, "ForgetReceiptClass123!", false);
    qihse_user_t* sci_only = qihse_auth_create_tenant_user(op, 52u, 9204u,
        QIHSE_ROLE_ANALYST, 5u, 0u, "ForgetReceiptSci123!", false);
    qihse_user_t* peer = qihse_auth_create_tenant_user(op, 52u, 9205u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "ForgetReceiptPeer123!", false);
    assert(high && low && class_only && sci_only && peer);
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    server = make_server(store);

    qihse_ai_memory_scope_t scope = {"project", "tree", "stream", "session"};
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, high, "protected receipt target", 1u,
                                        &scope, id));
    const char* forget[] = {"AIMEM", "FORGET-SCOPED-RECEIPT", id,
                            "project", "tree", "stream", "session", "retry-1"};
    char* denied = call(low, forget, 8u);
    assert(strstr(denied, "protected receipt target") == NULL);
    assert(denied[0] == '-');
    free(denied);

    const char* missing[] = {"AIMEM", "FORGET-SCOPED-RECEIPT",
        "00000000-0000-4000-8000-000000000000", "project", "tree", "stream",
        "session", "retry-missing"};
    char* absent = call(high, missing, 8u);
    assert(strcmp(denied = call(low, forget, 8u), absent) == 0);
    free(denied); free(absent);
    char* by_class = call(class_only, forget, 8u);
    char* by_sci = call(sci_only, forget, 8u);
    char* by_peer = call(peer, forget, 8u);
    assert(by_class[0] == '-' && by_sci[0] == '-' && by_peer[0] == '-');
    assert(strstr(by_class, "protected receipt target") == NULL &&
           strstr(by_sci, "protected receipt target") == NULL &&
           strstr(by_peer, "protected receipt target") == NULL);
    free(by_class); free(by_sci); free(by_peer);

    const char* short_id[] = {"AIMEM", "FORGET-SCOPED-RECEIPT", "x",
                              "project", "tree", "stream", "session", "short-id"};
    char* malformed = call(high, short_id, 8u);
    assert(malformed[0] == '-');
    free(malformed);

    const char* wrong_scope[] = {"AIMEM", "FORGET-SCOPED-RECEIPT", id,
                                "other", "tree", "stream", "session", "retry-wrong"};
    char* wrong = call(high, wrong_scope, 8u);
    assert(wrong[0] == '-');
    free(wrong);

    char* first = call(high, forget, 8u);
    assert(first[0] == '*');
    assert(strstr(first, "FORGET-SCOPED") && strstr(first, id) &&
           strstr(first, "local-fsync"));
    char* replay = call(high, forget, 8u);
    assert(strcmp(first, replay) == 0);
    free(replay);

    const char* changed[] = {"AIMEM", "FORGET-SCOPED-RECEIPT", id,
                             "other", "tree", "stream", "session", "retry-1"};
    char* conflict = call(high, changed, 8u);
    assert(strstr(conflict, "CONFLICT"));
    free(conflict);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    store = qihse_kv_store_create();
    assert(store);
    server = make_server(store);
    replay = call(high, forget, 8u);
    assert(strcmp(first, replay) == 0);
    free(first); free(replay);

    char concurrent_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, high, "concurrent target", 1u,
                                        &scope, concurrent_id));
    const char* parallel[] = {"AIMEM", "FORGET-SCOPED-RECEIPT", concurrent_id,
                              "project", "tree", "stream", "session", "parallel-1"};
    forget_thread_t work[2] = {{high, parallel, NULL}, {high, parallel, NULL}};
    pthread_t threads[2];
    for (size_t i = 0; i < 2u; ++i)
        assert(pthread_create(&threads[i], NULL, forget_in_thread, &work[i]) == 0);
    for (size_t i = 0; i < 2u; ++i)
        assert(pthread_join(threads[i], NULL) == 0);
    assert(work[0].response[0] == '*' &&
           strcmp(work[0].response, work[1].response) == 0);
    free(work[0].response); free(work[1].response);
#ifdef QIHSE_AIMEM_DURABILITY_TEST
    char crash_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, high, "crash target", 1u,
                                        &scope, crash_id));
    const char* crash_forget[] = {"AIMEM", "FORGET-SCOPED-RECEIPT", crash_id,
                                  "project", "tree", "stream", "session", "crash-after-fsync"};
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    qihse_audit_shutdown();
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        qihse_audit_init();
        store = qihse_kv_store_create();
        assert(store);
        server = make_server(store);
        assert(setenv("QIHSE_AIMEM_CRASH_AT", "forget-pair-after-fsync", 1) == 0);
        char* unexpected = call(high, crash_forget, 8u);
        free(unexpected);
        _exit(99);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 86);
    qihse_audit_init();
    store = qihse_kv_store_create();
    assert(store);
    server = make_server(store);
    char* recovered = call(high, crash_forget, 8u);
    assert(recovered[0] == '*' && strstr(recovered, "local-fsync"));
    char* again = call(high, crash_forget, 8u);
    assert(strcmp(recovered, again) == 0);
    free(recovered); free(again);
#endif
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(data_root);
    puts("scoped forget receipt passed");
    return 0;
}
