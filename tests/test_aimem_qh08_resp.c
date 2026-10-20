/* QH-08 operator-only RESP rebuild and status surface. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static qihse_resp_server_t* server;

static char* execute(qihse_user_t* user, size_t argc, const char* const* argv) {
    qihse_resp_arg_t args[8]; assert(argc <= 8u);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i]; args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL; size_t len = 0u;
    assert(qihse_resp_server_execute(server, user, argc, args, &reply, &len));
    char* text = calloc(len + 1u, 1u); assert(text);
    memcpy(text, reply, len); free(reply); return text;
}

static qihse_resp_server_t* make_server(qihse_kv_store_t* store) {
    qihse_resp_server_config_t cfg; qihse_resp_server_config_init(&cfg);
    cfg.store = store; cfg.auth_required = true; cfg.port = 0;
    qihse_resp_server_t* value = qihse_resp_server_create(&cfg);
    assert(value); return value;
}

int main(void) {
    char root[] = "build/aimem_qh08_resp_XXXXXX";
    assert(mkdtemp(root)); assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("Qh08RespSystem123!"));
    qihse_user_t* root_op = qihse_auth_get_user(0u);
    qihse_user_t* tenant_op = qihse_auth_create_tenant_user(root_op, 38u, 9811u,
        QIHSE_ROLE_OPERATOR, UINT16_MAX, UINT16_MAX, "Qh08RespTenant123!", false);
    qihse_user_t* guest = qihse_auth_create_tenant_user(root_op, 38u, 9812u,
        QIHSE_ROLE_GUEST, 0u, 0u, "Qh08RespGuest123!", false);
    qihse_user_t* foreign_op = qihse_auth_create_tenant_user(root_op, 39u, 9813u,
        QIHSE_ROLE_OPERATOR, UINT16_MAX, UINT16_MAX, "Qh08RespForeign123!", false);
    assert(tenant_op && guest && foreign_op);

    qihse_kv_store_t* store = qihse_kv_store_create(); assert(store);
    server = make_server(store);
    qihse_ai_memory_scope_t scope = { "resp-qh08", "tree", "stream", "session" };
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, guest, "project owner seed",
        QIHSE_AIMEM_EPISODIC, &scope, id));
    qihse_ai_memory_knowledge_version_t knowledge;
    assert(qihse_ai_memory_knowledge_create(server, guest, &scope,
        QIHSE_AIMEM_KNOWLEDGE_RULE, QIHSE_AIMEM_KNOWLEDGE_PROPOSED,
        "RESP rebuild row", &knowledge) == QIHSE_AIMEM_WRITE_NEW);

    const char* health[] = { "AIMEM", "HEALTH", "resp-qh08", "tree", "stream", "session" };
    const char* rebuild[] = { "AIMEM", "REBUILD", "resp-qh08", "tree", "stream", "session" };
    char* reply = execute(guest, 6u, health);
    assert(strstr(reply, "NOPERM") && !strstr(reply, "provider")); free(reply);
    reply = execute(guest, 6u, rebuild);
    assert(strstr(reply, "NOPERM")); free(reply);
    reply = execute(tenant_op, 6u, health);
    assert(strstr(reply, "NONE") && strstr(reply, "generation")); free(reply);
    reply = execute(tenant_op, 6u, rebuild);
    assert(strcmp(reply, "+OK\r\n") == 0); free(reply);
    reply = execute(tenant_op, 6u, health);
    assert(strstr(reply, "READY") && strstr(reply, "builtin-lexical-256") &&
           strstr(reply, "indexed-records") && strstr(reply, "$1\r\n1\r\n"));
    free(reply);
    reply = execute(foreign_op, 6u, health);
    assert(strstr(reply, "NONE") && !strstr(reply, "$5\r\nREADY")); free(reply);

    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    qihse_ai_memory_reset();
    store = qihse_kv_store_create(); assert(store); server = make_server(store);
    reply = execute(tenant_op, 6u, health);
    assert(strstr(reply, "READY") && strstr(reply, "builtin-lexical-256") &&
           strstr(reply, "source-highwater")); free(reply);

    qihse_ai_memory_knowledge_free(&knowledge);
    qihse_resp_server_destroy(server); qihse_kv_store_destroy(store);
    puts("PASS QH-08 operator RESP rebuild, status, isolation and restart");
    return 0;
}
