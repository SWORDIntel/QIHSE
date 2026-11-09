/* Authenticated AIMEM reads must not disclose hidden scoped data. */
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

static char *command(qihse_user_t *user, size_t count, const char *const *words) {
    qihse_resp_arg_t args[12];
    assert(count <= sizeof args / sizeof args[0]);
    for (size_t i = 0; i < count; ++i) {
        args[i].data = (const uint8_t *)words[i];
        args[i].len = strlen(words[i]);
    }
    uint8_t *raw = NULL;
    size_t length = 0;
    assert(qihse_resp_server_execute(server, user, count, args, &raw, &length));
    char *reply = malloc(length + 1u);
    assert(reply);
    memcpy(reply, raw, length);
    reply[length] = '\0';
    free(raw);
    return reply;
}

static void expect(qihse_user_t *user, size_t count, const char *const *words,
                   const char *exact, const char *secret) {
    char *reply = command(user, count, words);
    if (strstr(reply, secret) != NULL) {
        fprintf(stderr, "payload disclosed by %s %s to user %u\n",
            words[0], words[1], (unsigned)qihse_user_get_id(user));
        abort();
    }
    if (exact && strcmp(reply, exact) != 0) {
        fprintf(stderr, "%s %s: expected %s, got %s\n", words[0], words[1], exact, reply);
        abort();
    }
    free(reply);
}

int main(void) {
    char root[] = "./aimem_scoped_auth_XXXXXX";
    assert(mkdtemp(root));
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("ScopedMatrixOperator123!"));
    qihse_user_t *op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t *owner = qihse_auth_create_tenant_user(op, 53u, 9301u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "ScopedMatrixOwner123!", false);
    qihse_user_t *low_class = qihse_auth_create_tenant_user(op, 53u, 9302u,
        QIHSE_ROLE_ANALYST, 0u, 1u, "ScopedMatrixClass123!", false);
    qihse_user_t *low_sci = qihse_auth_create_tenant_user(op, 53u, 9303u,
        QIHSE_ROLE_ANALYST, 5u, 0u, "ScopedMatrixSci123!", false);
    qihse_user_t *peer = qihse_auth_create_tenant_user(op, 53u, 9304u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "ScopedMatrixPeer123!", false);
    qihse_user_t *foreign = qihse_auth_create_tenant_user(op, 54u, 9305u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "ScopedMatrixForeign123!", false);
    qihse_user_t *stranger = qihse_auth_create_tenant_user(op, 53u, 9306u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "ScopedMatrixStranger123!", false);
    assert(owner && low_class && low_sci && peer && foreign && stranger);

    qihse_kv_store_t *store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.port = 0u;
    server = qihse_resp_server_create(&cfg);
    assert(server);

    const char *secret = "SCOPED_MATRIX_CLASSIFIED_PAYLOAD";
    qihse_ai_memory_scope_t scope = {"matrix-project", "tree", "stream", "session"};
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_scoped(server, owner, secret,
        QIHSE_AIMEM_EPISODIC, &scope, id));
    char event_id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_event_append_evidence(server, owner, &scope,
        "matrix-producer", "matrix-event", "checkpoint", 1234u,
        secret, id, event_id) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9302u));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9303u));
    assert(qihse_ai_memory_project_grant(server, owner, scope.project, 9304u));

    const char *get[] = {"AIMEM", "GET-SCOPED", id,
        "matrix-project", "tree", "stream", "session"};
    const char *wrong_project[] = {"AIMEM", "GET-SCOPED", id,
        "other-project", "tree", "stream", "session"};
    const char *recall[] = {"AIMEM", "RECALL-SCOPED", secret, "10", "bm25", "0",
        "matrix-project", "tree", "stream", "session"};
    const char *count[] = {"AIMEM", "COUNT-SCOPED",
        "matrix-project", "tree", "stream", "session"};
    const char *event[] = {"AIMEM", "EVENT", "READ", event_id,
        "matrix-project", "tree", "stream", "session"};
    const char *global_recall[] = {"AIMEM", "RECALL", secret, "10", "bm25"};
    const char *global_count[] = {"AIMEM", "COUNT"};

    qihse_user_t *denied[] = {low_class, low_sci, stranger, foreign};
    for (size_t i = 0; i < sizeof denied / sizeof denied[0]; ++i) {
        expect(denied[i], 7u, get, "$-1\r\n", secret);
        expect(denied[i], 10u, recall, "*0\r\n", secret);
        expect(denied[i], 6u, count, ":0\r\n", secret);
        expect(denied[i], 8u, event, "$-1\r\n", secret);
        expect(denied[i], 5u, global_recall,
            "-ERR tenant AIMEM access requires explicit project scope\r\n", secret);
        expect(denied[i], 2u, global_count,
            "-ERR tenant AIMEM access requires explicit project scope\r\n", secret);
    }
    expect(owner, 7u, wrong_project, "$-1\r\n", secret);
    char *visible = command(owner, 7u, get);
    assert(strstr(visible, secret));
    free(visible);

    const char *offer[] = {"AIMEM", "HANDOFF", "OFFER", "9304", "60000",
        "matrix-project", "tree", "stream", "session", secret};
    char *offered = command(owner, 10u, offer);
    assert(offered[0] == '$');
    char *body = strstr(offered, "\r\n");
    assert(body && strlen(body + 2u) >= QIHSE_AIMEM_ID_LEN);
    char handoff_id[QIHSE_AIMEM_ID_LEN + 1u];
    memcpy(handoff_id, body + 2u, QIHSE_AIMEM_ID_LEN);
    handoff_id[QIHSE_AIMEM_ID_LEN] = '\0';
    free(offered);
    const char *handoff[] = {"AIMEM", "HANDOFF", "GET", handoff_id};
    expect(low_class, 4u, handoff, "$-1\r\n", secret);
    expect(low_sci, 4u, handoff, "$-1\r\n", secret);
    expect(foreign, 4u, handoff, "$-1\r\n", secret);
    visible = command(peer, 4u, handoff);
    assert(strstr(visible, secret));
    free(visible);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(root);
    puts("AIMEM scoped authorization matrix passed");
    return 0;
}
