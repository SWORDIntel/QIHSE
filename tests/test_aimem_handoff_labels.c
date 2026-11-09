/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
/* A project grant does not let a recipient read an offer above its labels. */
#include "aimem_fixture_cleanup.h"
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static qihse_resp_server_t *server;

static char *reply(qihse_user_t *user, size_t argc, const char *const *parts) {
    qihse_resp_arg_t args[12];
    assert(argc <= sizeof args / sizeof args[0]);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t *)parts[i];
        args[i].len = strlen(parts[i]);
    }
    uint8_t *raw = NULL;
    size_t len = 0;
    assert(qihse_resp_server_execute(server, user, argc, args, &raw, &len));
    char *text = malloc(len + 1u);
    assert(text);
    memcpy(text, raw, len);
    text[len] = '\0';
    free(raw);
    return text;
}

int main(void) {
    char data_root[] = "./aimem_handoff_labels_XXXXXX";
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("FixtureOperator123!"));
    qihse_user_t *op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t *high_owner = qihse_auth_create_tenant_user(op, 47u, 9101u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "HighOwner123!", false);
    qihse_user_t *low_owner = qihse_auth_create_tenant_user(op, 47u, 9102u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "LowOwner123!", false);
    qihse_user_t *low_class = qihse_auth_create_tenant_user(op, 47u, 9103u,
        QIHSE_ROLE_ANALYST, 0u, 1u, "LowClass123!", false);
    qihse_user_t *low_sci = qihse_auth_create_tenant_user(op, 47u, 9104u,
        QIHSE_ROLE_ANALYST, 5u, 0u, "LowSciReader123!", false);
    qihse_user_t *same = qihse_auth_create_tenant_user(op, 47u, 9105u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "SameLabels123!", false);
    assert(high_owner && low_owner && low_class && low_sci && same);

    qihse_kv_store_t *store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.port = 0u;
    server = qihse_resp_server_create(&cfg);
    assert(server);

    const qihse_ai_memory_scope_t scope = {"handoff-labels", "", "", ""};
    char seed[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, low_owner, "low owner seed", 1u,
        &scope, seed));
    assert(qihse_ai_memory_store_scoped(server, high_owner, "high owner seed", 1u,
        &scope, seed));
    assert(qihse_ai_memory_project_grant(server, low_owner, scope.project, 9103u));
    assert(qihse_ai_memory_project_grant(server, low_owner, scope.project, 9104u));
    assert(qihse_ai_memory_project_grant(server, low_owner, scope.project, 9105u));
    assert(qihse_ai_memory_project_grant(server, high_owner, scope.project, 9105u));
    assert(qihse_ai_memory_project_reader_allowed(server, low_class, scope.project));
    assert(qihse_ai_memory_project_reader_allowed(server, low_sci, scope.project));
    assert(qihse_ai_memory_project_reader_allowed(server, same, scope.project));
    assert(!qihse_auth_can_access(low_class, 5u, 1u));
    assert(!qihse_auth_can_access(low_sci, 5u, 1u));
    assert(qihse_auth_can_access(same, 5u, 1u));

    const char *class_offer[] = {"AIMEM", "HANDOFF", "OFFER", "9103", "60000",
        "handoff-labels", "", "", "", "classified handoff"};
    char *class_reply = reply(high_owner, 10u, class_offer);
    assert(strstr(class_reply, "NOPERM") != NULL);
    free(class_reply);

    const char *sci_offer[] = {"AIMEM", "HANDOFF", "OFFER", "9104", "60000",
        "handoff-labels", "", "", "", "compartmented handoff"};
    char *sci_reply = reply(high_owner, 10u, sci_offer);
    assert(strstr(sci_reply, "NOPERM") != NULL);
    free(sci_reply);

    const char *same_offer[] = {"AIMEM", "HANDOFF", "OFFER", "9105", "60000",
        "handoff-labels", "", "", "", "same-label handoff"};
    char *same_reply = reply(high_owner, 10u, same_offer);
    assert(same_reply[0] == '$');
    char *body = strstr(same_reply, "\r\n");
    assert(body && strlen(body + 2u) >= QIHSE_AIMEM_ID_LEN);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    memcpy(id, body + 2u, QIHSE_AIMEM_ID_LEN);
    id[QIHSE_AIMEM_ID_LEN] = '\0';
    free(same_reply);
    const char *get[] = {"AIMEM", "HANDOFF", "GET", id};
    char *get_reply = reply(same, 4u, get);
    if (!strstr(get_reply, "same-label handoff"))
        fprintf(stderr, "same-label recipient GET reply: %s\n", get_reply);
    assert(strstr(get_reply, "same-label handoff") != NULL);
    free(get_reply);

    /* A grant from a different owner must not keep this offer visible. */
    assert(qihse_ai_memory_project_revoke(server, high_owner, scope.project, 9105u));
    assert(qihse_ai_memory_project_reader_allowed(server, same, scope.project));
    assert(!qihse_ai_memory_project_reader_allowed_for_owner(
        server, same, 9101u, scope.project));
    same_reply = reply(high_owner, 10u, same_offer);
    assert(strstr(same_reply, "NOPERM") != NULL);
    free(same_reply);
    get_reply = reply(same, 4u, get);
    assert(strcmp(get_reply, "$-1\r\n") == 0);
    free(get_reply);
    const char *accept[] = {"AIMEM", "HANDOFF", "ACCEPT", id, "1"};
    char *accept_reply = reply(same, 5u, accept);
    assert(strstr(accept_reply, "ACCEPTED") == NULL);
    free(accept_reply);
    get_reply = reply(high_owner, 4u, get);
    assert(strstr(get_reply, "same-label handoff") != NULL);
    free(get_reply);

    assert(qihse_ai_memory_project_grant(server, high_owner, scope.project, 9105u));
    same_reply = reply(high_owner, 10u, same_offer);
    assert(same_reply[0] == '$');
    body = strstr(same_reply, "\r\n");
    assert(body && strlen(body + 2u) >= QIHSE_AIMEM_ID_LEN);
    memcpy(id, body + 2u, QIHSE_AIMEM_ID_LEN);
    id[QIHSE_AIMEM_ID_LEN] = '\0';
    free(same_reply);
    accept_reply = reply(same, 5u, accept);
    assert(strstr(accept_reply, "ACCEPTED") != NULL);
    free(accept_reply);
    assert(qihse_ai_memory_project_revoke(server, high_owner, scope.project, 9105u));
    accept_reply = reply(same, 5u, accept);
    assert(strstr(accept_reply, "ACCEPTED") == NULL);
    free(accept_reply);
    get_reply = reply(same, 4u, get);
    assert(strcmp(get_reply, "$-1\r\n") == 0);
    free(get_reply);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(data_root);
    puts("handoff label admission passed");
    return 0;
}
