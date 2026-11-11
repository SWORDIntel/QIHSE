/* Exercise the production metadata decoder without allocating an image. */
#include "../src/spinnaker/qihse_resp_engine.c"
#include <assert.h>

/* Boundary doubles drive the production ACTIVATE/RECEIPT admission gate
 * deterministically through the restart window, without weakening KV checks. */
static qihse_kv_ct_source_status_t admission_status;
static bool replay_ok = true, replay_unresolved;
static unsigned replay_calls, status_calls;
static qihse_kv_store_t* expected_store;
static qihse_user_t* expected_principal;

bool qihse_cluster_ownership_replay_control(
        qihse_cluster_ownership_context_t* context, bool* unresolved,
        char* error, size_t error_cap) {
    (void)error; (void)error_cap;
    assert(context && context->store == expected_store);
    ++replay_calls;
    *unresolved = replay_unresolved;
    return replay_ok;
}

bool qihse_kv_ct_source_status(qihse_kv_store_t* store,
        qihse_user_t* principal, qihse_kv_ct_source_status_t* out) {
    assert(store == expected_store && principal == expected_principal);
    ++status_calls;
    *out = admission_status;
    return true;
}

static void activation_admission(void) {
    char error[256] = {0};
    int store_boundary, principal_boundary;
    expected_store = (qihse_kv_store_t*)&store_boundary;
    expected_principal = (qihse_user_t*)&principal_boundary;
    qihse_cluster_ownership_context_t ownership = {.store = expected_store};
    qihse_resp_server_t server = {0};
    server.store = expected_store;
    server.ct_ownership_context = &ownership;
    server.replication_service_principal = expected_principal;
    server.ct_role = "primary";
    server.pqc.node_id = "target";
    strcpy(server.ct_generation, "11111111111111111111111111111111");
    strcpy(server.ct_peer_qkp_runtime, "successor");
    qihse_resp_server_ct_control_only_set(&server, true);
    strcpy(admission_status.source_id, "target");
    strcpy(admission_status.successor_id, "successor");
    strcpy(admission_status.generation, server.ct_generation);
    admission_status.admitted = true;
    admission_status.durable_lsn = 7;
    admission_status.acknowledged_lsn = 6;

    /* Durable activation plus an outstanding successor ACK is insufficient. */
    assert(!qihse_resp_ct2_confirm_activation_admission(&server, false, 7,
        error, sizeof(error)));
    assert(server.ct_control_only && replay_calls == 1 && status_calls == 1);
    admission_status.acknowledged_lsn = 7;
    replay_unresolved = true;
    assert(!qihse_resp_ct2_confirm_activation_admission(&server, false, 7,
        error, sizeof(error)));
    assert(server.ct_control_only && status_calls == 1);
    replay_unresolved = false;
    replay_ok = false;
    assert(!qihse_resp_ct2_confirm_activation_admission(&server, false, 7,
        error, sizeof(error)));
    assert(server.ct_control_only && status_calls == 1);
    replay_ok = true;
    strcpy(admission_status.successor_id, "wrong-pin");
    assert(!qihse_resp_ct2_confirm_activation_admission(&server, false, 7,
        error, sizeof(error)));
    assert(server.ct_control_only);
    strcpy(admission_status.successor_id, "successor");
    assert(!qihse_resp_ct2_confirm_activation_admission(&server, false, 8,
        error, sizeof(error)));
    assert(server.ct_control_only);

    /* Same receipt retry repairs admission before the source can redirect. */
    assert(qihse_resp_ct2_confirm_activation_admission(&server, false, 7,
        error, sizeof(error)));
    assert(!server.ct_control_only);
    unsigned calls = replay_calls;
    replay_ok = false;
    assert(qihse_resp_ct2_confirm_activation_admission(&server, false, 7,
        error, sizeof(error)));
    assert(replay_calls == calls); /* Historical receipt remains immutable. */
    qihse_resp_server_ct_control_only_set(&server, true);
    assert(qihse_resp_ct2_confirm_activation_admission(&server, true, 7,
        error, sizeof(error)));
    assert(server.ct_control_only && replay_calls == calls);
    puts("PASS CT2 activation receipt waits for admission, retries, and preserves group readiness");
}

static bool parses(const char* total) {
    const char* fields[] = {"REPL.CT2", "BEGIN", "image-bounds",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "qkp-source", "qkp-target", "11111111111111111111111111111111",
        "10", "12", "4", "7", total,
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333"};
    qihse_resp_arg_t arguments[15];
    for (size_t i = 0; i < 15; ++i) {
        arguments[i].data = (const unsigned char*)fields[i];
        arguments[i].len = strlen(fields[i]);
    }
    qihse_resp_request_t request = {.argc = 15};
    memcpy(request.argv, arguments, sizeof(arguments));
    qihse_resp_ct2_tuple_t tuple;
    bool ok = qihse_resp_ct2_parse_tuple(&request, &tuple);
    if (ok) assert(tuple.total_bytes == strtoull(total, NULL, 10));
    return ok;
}

int main(void) {
    activation_admission();
    assert(parses("67108864"));
    assert(parses("67284039"));
    assert(parses("9223372036854775807"));
    assert(!parses("0"));
    assert(!parses("9223372036854775808"));
    assert(!parses("18446744073709551615"));
    assert(!parses("18446744073709551616"));
    puts("PASS CT2 metadata accepts images above 64 MiB and rejects unrepresentable offsets");
    return 0;
}
