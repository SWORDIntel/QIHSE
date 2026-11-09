/* Disposable real RESP service for the HAX/QIHSE AIMEM contract probe. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || setenv("QIHSE_DATA_DIR", argv[1], 1) != 0 ||
        !qihse_auth_init() || !qihse_auth_bootstrap_operator("SMFixtureOperator123!"))
        return 2;
    qihse_user_t *op = qihse_auth_get_user(0u);
    qihse_user_t *low = qihse_auth_create_tenant_user(op, 47u, 9471u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "SMFixtureLow123!", false);
    qihse_user_t *high_class = qihse_auth_create_tenant_user(op, 47u, 9472u,
        QIHSE_ROLE_ANALYST, 5u, 0u, "SMFixtureHigh123!", false);
    qihse_user_t *high_sci = qihse_auth_create_tenant_user(op, 47u, 9473u,
        QIHSE_ROLE_ANALYST, 0u, 1u, "SMFixtureSCI123!", false);
    qihse_user_t *recipient = qihse_auth_create_tenant_user(op, 47u, 9474u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "SMFixtureRecipient123!", false);
    if (!op || !low || !high_class || !high_sci || !recipient ||
        !qihse_auth_modify_user(op, 9471u, "AIMEM_SERVICE", NULL,
                                -1, -1, -1, -1)) return 3;

    qihse_kv_store_t *store = qihse_kv_store_create();
    if (!store) return 4;
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.aimem_service_user_id = qihse_user_get_id(low);
    cfg.bind_address = "127.0.0.1";
    cfg.port = 0u;
    qihse_resp_server_t *server = qihse_resp_server_create(&cfg);
    if (!server) return 5;

    const qihse_ai_memory_scope_t scope = {"hax-compat", "", "", ""};
    char visible[QIHSE_AIMEM_ID_LEN + 1u] = {0};
    char classified[QIHSE_AIMEM_ID_LEN + 1u] = {0};
    char compartmented[QIHSE_AIMEM_ID_LEN + 1u] = {0};
    if (!qihse_ai_memory_store_scoped(server, low, "hax visible orchard", 2u,
                                      &scope, visible) ||
        !qihse_ai_memory_store_scoped(server, high_class,
                                      "hax classified orchard secret", 2u,
                                      &scope, classified) ||
        !qihse_ai_memory_store_scoped(server, high_sci,
                                      "hax compartment orchard secret", 2u,
                                      &scope, compartmented) ||
        !qihse_ai_memory_project_grant(server, low, scope.project, 9472u) ||
        !qihse_ai_memory_project_grant(server, low, scope.project, 9473u) ||
        !qihse_ai_memory_project_grant(server, low, scope.project, 9474u) ||
        qihse_auth_can_access(low, 5u, 0u) ||
        qihse_auth_can_access(low, 0u, 1u) ||
        qihse_ai_memory_count_scoped(server, low, 0u, &scope) != 1u ||
        qihse_ai_memory_count_scoped(server, high_class, 0u, &scope) != 2u ||
        qihse_ai_memory_count_scoped(server, high_sci, 0u, &scope) != 2u ||
        !qihse_resp_server_start(server)) return 6;

    printf("%u %s %s %s\n", (unsigned)qihse_resp_server_port(server),
           visible, classified, compartmented);
    fflush(stdout);
    (void)getchar();
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    return 0;
}
