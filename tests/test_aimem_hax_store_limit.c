/* HAX's native AIMEM client accepts a 256 KiB scoped payload. Exercise the
 * authenticated QIHSE wire boundary and exact durable replay at that limit. */
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
#include <unistd.h>

#define HAX_TEXT_MAX (256u * 1024u)

static qihse_resp_server_t *server;

static uint8_t *execute(qihse_user_t *user, size_t argc,
                        const char *const argv[], size_t *length) {
    qihse_resp_arg_t args[10];
    assert(argc <= sizeof args / sizeof args[0]);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t *)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t *reply = NULL;
    *length = 0u;
    assert(qihse_resp_server_execute(server, user, argc, args, &reply, length));
    assert(reply);
    return reply;
}

static void bulk_id(const uint8_t *reply, size_t length,
                    char out[QIHSE_AIMEM_ID_LEN + 1u]) {
    assert(length == 5u + QIHSE_AIMEM_ID_LEN + 2u);
    assert(memcmp(reply, "$36\r\n", 5u) == 0);
    assert(memcmp(reply + length - 2u, "\r\n", 2u) == 0);
    memcpy(out, reply + 5u, QIHSE_AIMEM_ID_LEN);
    out[QIHSE_AIMEM_ID_LEN] = '\0';
}

static void verify_get(qihse_user_t *user, const char *id,
                       const char *body, size_t body_length) {
    const char *const get[] = {"AIMEM", "GET-SCOPED", id, "hax-limit", "", "", ""};
    size_t length = 0u;
    uint8_t *reply = execute(user, 7u, get, &length);
    char frame[40];
    int framed = snprintf(frame, sizeof frame, "$%zu\r\n", body_length);
    assert(framed > 0 && (size_t)framed < sizeof frame);
    /* The seventh and final bulk field is the exact, byte-preserved body. */
    const uint8_t *text = memmem(reply, length, frame, (size_t)framed);
    assert(text);
    text += framed;
    assert((size_t)(reply + length - text) == body_length + 2u);
    assert(memcmp(text, body, body_length) == 0);
    assert(memcmp(text + body_length, "\r\n", 2u) == 0);
    free(reply);
}

static void store_and_replay(qihse_user_t *user, size_t text_length,
                             const char *idem) {
    char *text = malloc(text_length + 1u);
    assert(text);
    memset(text, 'x', text_length);
    memcpy(text, "hax-limit:", 10u);
    memcpy(text + text_length - 9u, ":complete", 9u);
    text[text_length] = '\0';
    const char *const put[] = {"AIMEM", "STORE-SCOPED-DURABLE", "1", text,
                               "hax-limit", "", "", "", idem};
    size_t length = 0u;
    uint8_t *reply = execute(user, 9u, put, &length);
    char id[QIHSE_AIMEM_ID_LEN + 1u], replay_id[QIHSE_AIMEM_ID_LEN + 1u];
    bulk_id(reply, length, id);
    free(reply);
    reply = execute(user, 9u, put, &length);
    bulk_id(reply, length, replay_id);
    free(reply);
    assert(strcmp(id, replay_id) == 0);
    verify_get(user, id, text, text_length);
    free(text);
}

int main(void) {
    char data_root[] = "./aimem_hax_limit_XXXXXX";
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("HaxLimitOperator123!"));
    qihse_user_t *op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t *low = qihse_auth_create_tenant_user(op, 51u, 9511u,
        QIHSE_ROLE_ANALYST, 0u, 0u, "HaxLimitLow123!", false);
    qihse_user_t *high = qihse_auth_create_tenant_user(op, 51u, 9512u,
        QIHSE_ROLE_ANALYST, 5u, 1u, "HaxLimitHigh123!", false);
    assert(low && high);
    assert(qihse_auth_modify_user(op, 9511u, "AIMEM_SERVICE", NULL,
                                  -1, -1, -1, -1));
    qihse_kv_store_t *store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.aimem_service_user_id = 9511u;
    cfg.port = 0u;
    server = qihse_resp_server_create(&cfg);
    assert(server);

    store_and_replay(low, 65537u, "hax-limit-above-64k");
    store_and_replay(low, HAX_TEXT_MAX, "hax-limit-exact-256k");

    char *too_large = malloc(HAX_TEXT_MAX + 2u);
    assert(too_large);
    memset(too_large, 'z', HAX_TEXT_MAX + 1u);
    too_large[HAX_TEXT_MAX + 1u] = '\0';
    const char *const oversized[] = {"AIMEM", "STORE-SCOPED-DURABLE", "1", too_large,
                                     "hax-limit", "", "", "", "hax-limit-oversized"};
    size_t length = 0u;
    uint8_t *reply = execute(low, 9u, oversized, &length);
    assert(length >= 4u && memcmp(reply, "-ERR", 4u) == 0);
    free(reply);
    free(too_large);

    char *large_knowledge = malloc(65538u);
    assert(large_knowledge);
    memset(large_knowledge, 'k', 65537u);
    large_knowledge[65537u] = '\0';
    const char *const knowledge[] = {"AIMEM", "KNOWLEDGE", "CREATE", "1", "1",
                                     large_knowledge, "hax-limit", "", "", ""};
    reply = execute(low, 10u, knowledge, &length);
    assert(length >= 4u && memcmp(reply, "-ERR", 4u) == 0);
    free(reply);
    free(large_knowledge);

    const char *const high_put[] = {"AIMEM", "STORE-SCOPED-DURABLE", "1",
                                    "hax-secret-high-classification-and-sci", "hax-limit",
                                    "", "", "", "hax-limit-hidden"};
    reply = execute(high, 9u, high_put, &length);
    char hidden_id[QIHSE_AIMEM_ID_LEN + 1u];
    bulk_id(reply, length, hidden_id);
    free(reply);
    const char *const hidden_get[] = {"AIMEM", "GET-SCOPED", hidden_id,
                                      "hax-limit", "", "", ""};
    reply = execute(low, 7u, hidden_get, &length);
    assert(!memmem(reply, length, "hax-secret", 10u));
    assert(length == 5u && memcmp(reply, "$-1\r\n", 5u) == 0);
    free(reply);
    const char *const count[] = {"AIMEM", "COUNT-SCOPED", "hax-limit", "", "", ""};
    reply = execute(low, 6u, count, &length);
    assert(length == 4u && memcmp(reply, ":2\r\n", 4u) == 0);
    free(reply);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    aimem_fixture_cleanup(data_root);
    puts("PASS HAX AIMEM 256 KiB boundary, durable replay and authorization");
    return 0;
}
