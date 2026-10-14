/* Authenticated RESP surface for native QIHSE AI memory. */
#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static qihse_resp_server_t* server;

static size_t run(qihse_user_t* user, size_t argc, const char* const* argv,
                  uint8_t** out) {
    qihse_resp_arg_t args[8];
    assert(argc <= 8u);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    size_t len = 0;
    assert(qihse_resp_server_execute(server, user, argc, args, out, &len));
    return len;
}

static void expect_contains(qihse_user_t* user, size_t argc,
                            const char* const* argv, const char* needle) {
    uint8_t* reply = NULL;
    size_t len = run(user, argc, argv, &reply);
    assert(len < 16384u);
    char* text = calloc(len + 1u, 1u);
    assert(text);
    memcpy(text, reply, len);
    assert(strstr(text, needle) != NULL);
    free(text);
    free(reply);
}

static char* extract_bulk_id(const uint8_t* reply, size_t len) {
    /* STORE returns one RESP bulk string. */
    const char* p = (const char*)reply;
    const char* body = strstr(p, "\r\n");
    assert(body && body + 2 < p + len);
    body += 2;
    const char* end = strstr(body, "\r\n");
    assert(end && (size_t)(end - body) == QIHSE_AIMEM_ID_LEN);
    return strndup(body, QIHSE_AIMEM_ID_LEN);
}

int main(void) {
    char data_root[] = "build/aimem_resp_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* guest = qihse_auth_create_user(op, 9041u, QIHSE_ROLE_GUEST,
                                                  0u, 0u, "GuestPass123!", false);
    assert(guest);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.enable_uwp_bridge = true;
    cfg.port = 0;
    server = qihse_resp_server_create(&cfg);
    assert(server);

    /* The in-process execution API requires an explicit principal.  Network
     * sessions enforce the unauthenticated NOAUTH path before dispatch; here
     * verify that callers cannot bypass that contract with a NULL principal. */
    const char* unauth[] = { "AIMEM", "COUNT" };
    uint8_t* unauth_reply = NULL;
    size_t unauth_len = 0;
    assert(!qihse_resp_server_execute(server, NULL, 2u,
                                      (const qihse_resp_arg_t[]) {
                                          { (const uint8_t*)unauth[0], strlen(unauth[0]) },
                                          { (const uint8_t*)unauth[1], strlen(unauth[1]) }
                                      }, &unauth_reply, &unauth_len));

    const char* store_public[] = { "AIMEM", "STORE", "1", "public memory", "public-1" };
    uint8_t* reply = NULL;
    size_t reply_len = run(guest, 5u, store_public, &reply);
    char* public_id = extract_bulk_id(reply, reply_len);
    free(reply);
    assert(strlen(public_id) == QIHSE_AIMEM_ID_LEN);

    /* Same principal + idempotency key returns the stable original id. */
    reply = NULL;
    reply_len = run(guest, 5u, store_public, &reply);
    char* public_id_again = extract_bulk_id(reply, reply_len);
    assert(strcmp(public_id, public_id_again) == 0);
    free(public_id_again);
    free(reply);

    const char* store_secret[] = { "AIMEM", "STORE", "2", "classified memory", "secret-1" };
    reply = NULL;
    reply_len = run(op, 5u, store_secret, &reply);
    char* secret_id = extract_bulk_id(reply, reply_len);
    free(reply);

    const char* count[] = { "AIMEM", "COUNT" };
    expect_contains(guest, 2u, count, ":1\r\n");
    const char* recall_public[] = { "AIMEM", "RECALL", "public", "8", "hybrid" };
    expect_contains(guest, 5u, recall_public, public_id);
    const char* recall_secret[] = { "AIMEM", "RECALL", "classified", "8", "hybrid" };
    expect_contains(guest, 5u, recall_secret, "*1\r\n");

    const char* get_public[] = { "AIMEM", "GET", "placeholder" };
    get_public[2] = public_id;
    expect_contains(guest, 3u, get_public, "public memory");
    const char* get_secret[] = { "AIMEM", "GET", "placeholder" };
    get_secret[2] = secret_id;
    expect_contains(guest, 3u, get_secret, "$-1\r\n");

    const char* forget[] = { "AIMEM", "FORGET", "placeholder" };
    forget[2] = public_id;
    expect_contains(guest, 3u, forget, ":1\r\n");
    expect_contains(guest, 2u, count, ":0\r\n");

    free(public_id);
    free(secret_id);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    puts("PASS authenticated AIMEM RESP protocol and principal enforcement");
    return 0;
}
