#include "qihse_ai_memory.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static size_t execute(qihse_resp_server_t* server, qihse_user_t* user,
                      size_t argc, const char* const* argv, uint8_t** out) {
    qihse_resp_arg_t args[8];
    assert(argc <= 8u);
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    size_t len = 0u;
    assert(qihse_resp_server_execute(server, user, argc, args, out, &len));
    return len;
}

static char* response_text(qihse_resp_server_t* server, qihse_user_t* user,
                           size_t argc, const char* const* argv) {
    uint8_t* raw = NULL;
    size_t len = execute(server, user, argc, argv, &raw);
    char* text = calloc(len + 1u, 1u);
    assert(text);
    memcpy(text, raw, len);
    free(raw);
    return text;
}

static int id_compare(const void* lhs, const void* rhs) {
    return strcmp((const char*)lhs, (const char*)rhs);
}

int main(void) {
    char data_root[] = "./aimem_legacy_inventory_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("LegacyInventoryOp123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* low = qihse_auth_create_user(op, 9401u, QIHSE_ROLE_GUEST,
        0u, 0u, "LegacyInventoryLow123!", false);
    assert(low);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.port = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&cfg);
    assert(server);

    char ids[3][QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, low, "PUBLIC-CONTENT-MUST-NOT-LEAK",
        QIHSE_AIMEM_EPISODIC, ids[0]));
    assert(qihse_ai_memory_store(server, op, "SECRET-CONTENT-MUST-NOT-LEAK",
        QIHSE_AIMEM_SEMANTIC, ids[1]));
    assert(qihse_ai_memory_store(server, op, "SECOND-SECRET-MUST-NOT-LEAK",
        QIHSE_AIMEM_EPISODIC, ids[2]));
    qsort(ids, 3u, sizeof(ids[0]), id_compare);

    qihse_ai_memory_legacy_inventory_item_t page[2];
    size_t count = 99u;
    char next[QIHSE_AIMEM_ID_LEN + 1u] = "dirty";
    bool done = true;
    assert(!qihse_ai_memory_legacy_inventory(server, NULL, "", 2u, page,
        &count, next, &done));
    assert(count == 0u && next[0] == '\0' && !done);
    count = 99u; strcpy(next, "dirty"); done = true;
    assert(!qihse_ai_memory_legacy_inventory(server, low, "", 2u, page,
        &count, next, &done));
    assert(count == 0u && next[0] == '\0' && !done);

    assert(qihse_ai_memory_legacy_inventory(server, op, "", 2u, page,
        &count, next, &done));
    assert(count == 2u && !done);
    assert(strcmp(page[0].id, ids[0]) == 0);
    assert(strcmp(page[1].id, ids[1]) == 0);
    assert(strcmp(next, ids[1]) == 0);
    char cursor[QIHSE_AIMEM_ID_LEN + 1u];
    memcpy(cursor, next, sizeof cursor);
    assert(qihse_ai_memory_legacy_inventory(server, op, cursor, 2u, page,
        &count, next, &done));
    assert(count == 1u && done && next[0] == '\0');
    assert(strcmp(page[0].id, ids[2]) == 0);

    const char* inventory[] = { "AIMEM", "LEGACY", "SCAN", "0", "2" };
    char* denied = response_text(server, low, 5u, inventory);
    assert(strstr(denied, "NOPERM AIMEM legacy inventory requires a fully cleared system Operator"));
    assert(!strstr(denied, ids[0]) && !strstr(denied, ids[1]) &&
           !strstr(denied, ids[2]));
    free(denied);

    char* reply = response_text(server, op, 5u, inventory);
    assert(strstr(reply, ids[0]) && strstr(reply, ids[1]));
    assert(!strstr(reply, ids[2]));
    assert(!strstr(reply, "PUBLIC-CONTENT-MUST-NOT-LEAK"));
    assert(!strstr(reply, "SECRET-CONTENT-MUST-NOT-LEAK"));
    assert(!strstr(reply, "SECOND-SECRET-MUST-NOT-LEAK"));
    free(reply);

    /* A parseable row whose embedded label disagrees with its durable KV
     * label must fail the entire preflight inventory, never disappear from it. */
    char bad_key[64], compact_id[17], bad_value[256];
    size_t compact_at = 0u;
    for (size_t i = 0u; ids[0][i] && compact_at < 16u; i++)
        if (ids[0][i] != '-') compact_id[compact_at++] = ids[0][i];
    compact_id[compact_at] = '\0';
    assert(compact_at == 16u);
    snprintf(bad_key, sizeof bad_key, "aimem:%s", compact_id);
    snprintf(bad_value, sizeof bad_value, "%s|1|1|1|0|tampered", ids[0]);
    assert(qihse_kv_set_user(store, bad_key, bad_value, 0u, 0u, op));
    count = 99u; strcpy(next, "dirty"); done = true;
    assert(!qihse_ai_memory_legacy_inventory(server, op, "", 2u, page,
        &count, next, &done));
    assert(count == 0u && next[0] == '\0' && !done);
    char* corrupt = response_text(server, op, 5u, inventory);
    assert(strstr(corrupt, "ERR invalid cursor or AIMEM legacy inventory unavailable"));
    assert(!strstr(corrupt, "tampered"));
    free(corrupt);

    qihse_resp_arg_t null_args[] = {
        { (const uint8_t*)"AIMEM", 5u },
        { (const uint8_t*)"LEGACY", 6u },
        { (const uint8_t*)"SCAN", 4u },
        { (const uint8_t*)"0", 1u },
        { (const uint8_t*)"2", 1u }
    };
    uint8_t* null_reply = NULL;
    size_t null_len = 0u;
    assert(!qihse_resp_server_execute(server, NULL, 5u, null_args,
                                      &null_reply, &null_len));
    assert(!null_reply && null_len == 0u);

    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    puts("PASS AIMEM legacy metadata inventory pagination and authorization");
    return 0;
}
