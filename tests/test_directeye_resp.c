/* Authenticated RESP boundary for DIRECTEYE mutation, feed, and ACK. */
#include "aimem_fixture_cleanup.h"
#include "qihse_auth.h"
#include "qihse_controller.h"
#include "qihse_keystone.h"
#include "qihse_kv_store.h"
#include "qihse_qkp.h"
#include "qihse_resp_wire.h"
#include "persistence/qihse_pqc_crypto.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

static qihse_resp_server_t* server;

static size_t call(qihse_user_t* user, size_t argc, const char* const* values,
                   uint8_t** out) {
    qihse_resp_arg_t args[8];
    assert(argc <= sizeof(args) / sizeof(args[0]));
    for (size_t i = 0; i < argc; ++i) {
        args[i].data = (const uint8_t*)values[i];
        args[i].len = strlen(values[i]);
    }
    size_t len = 0;
    assert(qihse_resp_server_execute(server, user, argc, args, out, &len));
    return len;
}

static char* call_text(qihse_user_t* user, size_t argc, const char* const* values) {
    uint8_t* raw = NULL;
    size_t len = call(user, argc, values, &raw);
    char* text = malloc(len + 1u);
    assert(text);
    memcpy(text, raw, len);
    text[len] = '\0';
    free(raw);
    return text;
}

static uint64_t bulk_number(const char** p) {
    assert(**p == '$');
    char* end = NULL;
    unsigned long n = strtoul(*p + 1, &end, 10);
    assert(end && end[0] == '\r' && end[1] == '\n');
    const char* body = end + 2;
    char* value_end = NULL;
    unsigned long long value = strtoull(body, &value_end, 10);
    assert(value_end && value_end == body + n && value_end[0] == '\r' && value_end[1] == '\n');
    *p = value_end + 2;
    return (uint64_t)value;
}

static void expect_error(qihse_user_t* user, size_t argc, const char* const* args) {
    char* reply = call_text(user, argc, args);
    assert(reply[0] == '-');
    free(reply);
}

static uint64_t reply_u64(const qihse_ctrl_reply_t* reply) {
    assert(reply && (reply->kind == QIHSE_CTRL_BULK || reply->kind == QIHSE_CTRL_SIMPLE));
    assert(reply->text && reply->text_len > 0u && reply->text_len < 32u);
    char text[32];
    memcpy(text, reply->text, reply->text_len);
    text[reply->text_len] = '\0';
    char* end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    assert(end == text + reply->text_len);
    return (uint64_t)value;
}

int main(void) {
    char root[] = "./build/directeye-resp-XXXXXX";
    assert(mkdtemp(root));
    assert(chmod(root, 0700) == 0);
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("DirecteyeRespOperator123!"));
    qihse_user_t* op = qihse_auth_get_user(0u);
    assert(op);
    qihse_user_t* writer = qihse_auth_create_tenant_user(op, 77u, 7701u,
        QIHSE_ROLE_ANALYST, 4u, 2u, "DirecteyeRespWriter123!", false);
    qihse_user_t* indexer = qihse_keystone_feed_identity_provision(op, 77u,
        7702u, 5u, UINT16_MAX, "DirecteyeRespIndexer123!");
    qihse_user_t* low_indexer = qihse_keystone_feed_identity_provision(op, 77u,
        7703u, 0u, 0u, "DirecteyeRespLowIndexer123!");
    assert(writer && indexer && low_indexer);
    char server_keys[256], client_keys[256], server_pub[320], client_pub[320];
    snprintf(server_keys, sizeof(server_keys), "%s/qkp-server", root);
    snprintf(client_keys, sizeof(client_keys), "%s/qkp-client", root);
    assert(mkdir(server_keys, 0700) == 0);
    assert(mkdir(client_keys, 0700) == 0);
    assert(qihse_pqc_keygen(server_keys));
    assert(qihse_pqc_keygen(client_keys));
    snprintf(server_pub, sizeof(server_pub), "%s/qihse_dsa_pub.pem", server_keys);
    snprintf(client_pub, sizeof(client_pub), "%s/qihse_dsa_pub.pem", client_keys);

    qihse_kv_store_t* store = qihse_kv_store_create_user(op);
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.enable_uwp_bridge = true;
    cfg.bind_address = "127.0.0.1";
    cfg.port = 17495u;
    char server_dsa[320], server_kem[320], server_kem_pub[320];
    snprintf(server_dsa, sizeof(server_dsa), "%s/qihse_dsa_key.pem", server_keys);
    snprintf(server_kem, sizeof(server_kem), "%s/qihse_kem_key.pem", server_keys);
    snprintf(server_kem_pub, sizeof(server_kem_pub), "%s/qihse_kem_pub.pem", server_keys);
    const char* trusted_clients[] = {client_pub};
    cfg.pqc.dsa_key_path = server_dsa;
    cfg.pqc.kem_key_path = server_kem;
    cfg.pqc.kem_pub_path = server_kem_pub;
    cfg.pqc.trusted_pubs = trusted_clients;
    cfg.pqc.trusted_count = 1u;
    cfg.pqc.node_id = "directeye-qihse-fixture";
    cfg.pqc.require = true;
    server = qihse_resp_server_create(&cfg);
    assert(server);

    const char* upsert[] = {"DIRECTEYE.RECORD.MUTATE",
        "11111111-1111-4111-8111-111111111111", "record-1", "UPSERT", "0",
        "{\"name\":\"alpha\"}"};
    char* reply = call_text(writer, 6u, upsert);
    assert(reply[0] == '*');
    const char* cursor_text = strstr(reply, "\r\n") + 2;
    uint64_t generation = bulk_number(&cursor_text);
    uint64_t cursor = bulk_number(&cursor_text);
    assert(generation && cursor == generation + 1u);
    free(reply);

    const char* retry[] = {"DIRECTEYE.RECORD.MUTATE",
        "11111111-1111-4111-8111-111111111111", "record-1", "UPSERT", "0",
        "{\"name\":\"alpha\"}"};
    reply = call_text(writer, 6u, retry);
    cursor_text = strstr(reply, "\r\n") + 2;
    assert(bulk_number(&cursor_text) == generation);
    assert(bulk_number(&cursor_text) == cursor);
    free(reply);

    const char* conflict[] = {"DIRECTEYE.RECORD.MUTATE",
        "11111111-1111-4111-8111-111111111111", "record-1", "UPSERT", "0",
        "{\"name\":\"changed\"}"};
    expect_error(writer, 6u, conflict);
    char expected_source_seq[32];
    snprintf(expected_source_seq, sizeof(expected_source_seq), "%llu",
             (unsigned long long)generation);
    const char* replacement[] = {"DIRECTEYE.RECORD.MUTATE",
        "55555555-5555-4555-8555-555555555555", "record-1", "UPSERT",
        expected_source_seq, "{\"name\":\"beta\"}"};
    reply = call_text(writer, 6u, replacement);
    cursor_text = strstr(reply, "\r\n") + 2;
    uint64_t replacement_generation = bulk_number(&cursor_text);
    uint64_t replacement_cursor = bulk_number(&cursor_text);
    assert(replacement_generation > generation && replacement_cursor == replacement_generation + 1u);
    free(reply);
    const char* get_live[] = {"DIRECTEYE.RECORD.GET", "record-1"};
    reply = call_text(writer, 2u, get_live);
    assert(strstr(reply, "beta") && strstr(reply, "\r\n0\r\n$"));
    free(reply);
    reply = call_text(low_indexer, 2u, get_live);
    assert(strstr(reply, "$1\r\n0") && strstr(reply, "$-1\r\n") && !strstr(reply, "beta"));
    free(reply);
    const char* get_missing[] = {"DIRECTEYE.RECORD.GET", "missing"};
    reply = call_text(writer, 2u, get_missing);
    assert(strstr(reply, "$1\r\n0") && strstr(reply, "$-1\r\n"));
    free(reply);
    reply = call_text(writer, 6u, retry);
    cursor_text = strstr(reply, "\r\n") + 2;
    assert(bulk_number(&cursor_text) == generation);
    assert(bulk_number(&cursor_text) == cursor);
    free(reply);
    const char* invalid_json[] = {"DIRECTEYE.RECORD.MUTATE",
        "22222222-2222-4222-8222-222222222222", "record-2", "UPSERT", "0", "[1,2]"};
    expect_error(writer, 6u, invalid_json);
    const char* invalid_id[] = {"DIRECTEYE.RECORD.MUTATE",
        "22222222-2222-4222-8222-222222222222", "bad/id", "UPSERT", "0", "{}"};
    expect_error(writer, 6u, invalid_id);

    const char* read[] = {"DIRECTEYE.FEED.READ", "0", "16"};
    reply = call_text(indexer, 3u, read);
    assert(reply[0] == '*' && strstr(reply, "record-1") && strstr(reply, "committed_at_ms"));
    free(reply);
    expect_error(writer, 3u, read);
    char* filtered = call_text(low_indexer, 3u, read);
    assert(filtered[0] == '*' && strstr(filtered, "record-1") == NULL &&
           strstr(filtered, "alpha") == NULL && strstr(filtered, "$1\r\n0") != NULL);
    free(filtered);
    const char* denied_indexer_write[] = {"DIRECTEYE.RECORD.MUTATE",
        "44444444-4444-4444-8444-444444444444", "indexer-write", "UPSERT", "0", "{}"};
    expect_error(indexer, 6u, denied_indexer_write);
    const char* oversized[] = {"DIRECTEYE.FEED.READ", "0", "129"};
    expect_error(indexer, 3u, oversized);

    snprintf(expected_source_seq, sizeof(expected_source_seq), "%llu",
             (unsigned long long)replacement_generation);
    const char* del[] = {"DIRECTEYE.RECORD.MUTATE",
        "33333333-3333-4333-8333-333333333333", "record-1", "DELETE", expected_source_seq};
    reply = call_text(writer, 5u, del);
    cursor_text = strstr(reply, "\r\n") + 2;
    uint64_t delete_generation = bulk_number(&cursor_text);
    uint64_t delete_cursor = bulk_number(&cursor_text);
    assert(delete_generation > generation && delete_cursor == delete_generation + 1u);
    free(reply);
    reply = call_text(writer, 5u, del);
    cursor_text = strstr(reply, "\r\n") + 2;
    assert(bulk_number(&cursor_text) == delete_generation);
    assert(bulk_number(&cursor_text) == delete_cursor);
    free(reply);
    reply = call_text(writer, 2u, get_live);
    assert(strstr(reply, "$1\r\n1") && strstr(reply, "$-1\r\n") && !strstr(reply, "beta"));
    free(reply);

    char ack_text[32];
    snprintf(ack_text, sizeof(ack_text), "%llu", (unsigned long long)delete_cursor);
    const char* ack[] = {"DIRECTEYE.FEED.ACK", ack_text};
    reply = call_text(indexer, 2u, ack);
    assert(reply[0] == '$' && strstr(reply, ack_text));
    free(reply);
    const char* lower_ack[] = {"DIRECTEYE.FEED.ACK", "1"};
    expect_error(indexer, 2u, lower_ack);
    expect_error(writer, 2u, ack);

    assert(qihse_resp_server_start(server));
    const char* trusted_server[] = {server_pub};
    qihse_controller_config_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.host = "127.0.0.1";
    client_cfg.port = qihse_resp_server_port(server);
    client_cfg.timeout_ms = 20000u;
    client_cfg.qkp_identity_dir = client_keys;
    client_cfg.qkp_trusted_pubs = trusted_server;
    client_cfg.qkp_trusted_count = 1u;
    client_cfg.qkp_node_id = "directeye-index-fixture";

    client_cfg.username = "User_7701";
    client_cfg.password = "DirecteyeRespWriter123!";
    qihse_controller_t* qkp_writer = qihse_controller_connect(&client_cfg);
    assert(qkp_writer && qihse_controller_connected(qkp_writer));
    const char* qkp_mutate[] = {"DIRECTEYE.RECORD.MUTATE",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "qkp-record", "UPSERT", "0",
        "{\"source\":\"sealed\"}"};
    qihse_ctrl_reply_t* qkp_reply = qihse_ctrl_call(qkp_writer, 6u, qkp_mutate);
    assert(qkp_reply && qkp_reply->kind == QIHSE_CTRL_ARRAY && qkp_reply->count == 2u);
    uint64_t qkp_generation = reply_u64(&qkp_reply->items[0]);
    uint64_t qkp_cursor = reply_u64(&qkp_reply->items[1]);
    assert(qkp_generation && qkp_cursor > cursor);
    qihse_ctrl_reply_free(qkp_reply);
    const char* qkp_get[] = {"DIRECTEYE.RECORD.GET", "qkp-record"};
    qkp_reply = qihse_ctrl_call(qkp_writer, 2u, qkp_get);
    assert(qkp_reply && qkp_reply->kind == QIHSE_CTRL_ARRAY && qkp_reply->count == 3u);
    assert(reply_u64(&qkp_reply->items[0]) == qkp_generation);
    assert(reply_u64(&qkp_reply->items[1]) == 0u);
    assert(strstr(qihse_ctrl_reply_text(&qkp_reply->items[2]), "sealed"));
    qihse_ctrl_reply_free(qkp_reply);
    qihse_controller_destroy(qkp_writer);

    client_cfg.qkp_identity_dir = NULL;
    client_cfg.qkp_trusted_pubs = NULL;
    client_cfg.qkp_trusted_count = 0u;
    assert(qihse_controller_connect(&client_cfg) == NULL);
    client_cfg.qkp_identity_dir = client_keys;
    client_cfg.qkp_trusted_pubs = trusted_server;
    client_cfg.qkp_trusted_count = 1u;

    client_cfg.username = "keystone-indexer-7703";
    client_cfg.password = "DirecteyeRespLowIndexer123!";
    qihse_controller_t* qkp_low_indexer = qihse_controller_connect(&client_cfg);
    assert(qkp_low_indexer && qihse_controller_connected(qkp_low_indexer));
    const char* qkp_read[] = {"DIRECTEYE.FEED.READ", "0", "16"};
    qkp_reply = qihse_ctrl_call(qkp_low_indexer, 3u, qkp_read);
    assert(qkp_reply && qkp_reply->kind == QIHSE_CTRL_ARRAY);
    for (size_t i = 0; i < qkp_reply->count; ++i) {
        const char* text = qihse_ctrl_reply_text(&qkp_reply->items[i]);
        assert(!text || !strstr(text, "qkp-record"));
    }
    qihse_ctrl_reply_free(qkp_reply);
    qihse_controller_destroy(qkp_low_indexer);

    client_cfg.username = "keystone-indexer-7702";
    client_cfg.password = "DirecteyeRespIndexer123!";
    qihse_controller_t* qkp_indexer = qihse_controller_connect(&client_cfg);
    assert(qkp_indexer && qihse_controller_connected(qkp_indexer));
    qkp_reply = qihse_ctrl_call(qkp_indexer, 3u, qkp_read);
    assert(qkp_reply && qkp_reply->kind == QIHSE_CTRL_ARRAY && qkp_reply->count >= 4u);
    bool saw_qkp_event = false;
    for (size_t i = 0; i < qkp_reply->count; ++i) {
        const char* text = qihse_ctrl_reply_text(&qkp_reply->items[i]);
        if (text && strstr(text, "qkp-record")) saw_qkp_event = true;
    }
    assert(saw_qkp_event);
    qihse_ctrl_reply_free(qkp_reply);
    char qkp_cursor_text[32];
    snprintf(qkp_cursor_text, sizeof(qkp_cursor_text), "%llu", (unsigned long long)qkp_cursor);
    const char* qkp_ack[] = {"DIRECTEYE.FEED.ACK", qkp_cursor_text};
    qkp_reply = qihse_ctrl_call(qkp_indexer, 2u, qkp_ack);
    assert(qkp_reply && reply_u64(qkp_reply) == qkp_cursor);
    qihse_ctrl_reply_free(qkp_reply);
    qihse_controller_destroy(qkp_indexer);

    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    assert(qihse_keystone_feed_identity_revoke(op, 7702u));
    assert(qihse_keystone_feed_identity_revoke(op, 7703u));
    assert(qihse_auth_destroy_user(op, 7701u));
    assert(qihse_auth_destroy_user(op, 7702u));
    assert(qihse_auth_destroy_user(op, 7703u));
    aimem_fixture_cleanup(root);
    puts("DIRECTEYE authenticated RESP/QKP: record read, mutation, replay, filtered feed, durable ACK and denial passed");
    return 0;
}
