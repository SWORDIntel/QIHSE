#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_keystone.h"
#include "qihse_kv_store.h"
#include "qihse_cluster_slot.h"
#include "qihse_resp_wire.h"

#define TEST_OPERATOR_PASSWORD "KeystoneIntegrationOpPass1!"
#define TEST_GUEST_PASSWORD "KeystoneGuestPass1!"
#define TEST_GUEST_ID 42u
#define TEST_GUEST_USERNAME "keystone_guest"

static void test_micro_model_classification(void) {
    printf("Testing Neural Micro-Model 6-Class Context Classification...\n");

    const char* fin_ctx = "payment processing bank account swift iban transaction wire 1000 USD transfer";
    qihse_keystone_class_t cls = QIHSE_KEYSTONE_CLASS_UNKNOWN;
    float conf = 0.0f;
    int rc = qihse_keystone_classify_context(fin_ctx, strlen(fin_ctx), &cls, &conf);
    assert(rc == 0);
    assert(conf > 0.0f && conf <= 1.0f);
    printf("  -> Classification: class=%s (id=%d), confidence=%.4f\n",
           qihse_keystone_class_name(cls), cls, conf);
}

static void test_anchor_search_performance(void) {
    printf("Testing Keystone Anchor-Guided Interpolation Search...\n");

    size_t n = 100000;
    int64_t* arr = (int64_t*)malloc(n * sizeof(int64_t));
    assert(arr != NULL);
    for (size_t i = 0; i < n; i++) {
        arr[i] = (int64_t)(i * 3 + 7);
    }

    int64_t target = arr[42424];
    int64_t idx = qihse_keystone_anchor_search(arr, n, target);
    assert(idx == 42424);

    assert(qihse_keystone_anchor_search(arr, n, arr[0]) == 0);
    assert(qihse_keystone_anchor_search(arr, n, arr[n - 1]) == (int64_t)(n - 1));
    assert(qihse_keystone_anchor_search(arr, n, -1) == -1);
    assert(qihse_keystone_anchor_search(arr, n, arr[n - 1] + 100) == -1);
    assert(qihse_keystone_anchor_search(arr, n, arr[50] + 1) == -1);

    free(arr);
    printf("  -> Anchor-guided interpolation search verified across 100,000 keys OK\n");
}

static void test_simd_dirty_log_ingest(void) {
    printf("Testing principal-aware SIMD Dirty Log Ingestion into QIHSE Black Hole KV Store...\n");

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    const char* dirty_payload =
        "--- START DUMP ---\n"
        "2026-08-19 14:00:00 DEBUG Connection to api.bank.internal established\n"
        "Found victim: victim1@financial-corp.com:P@ssw0rd2026! | Status=ACTIVE\n"
        "Payload token: http://c2.stealer.net/gate.php?id=99281\n"
        "User account: admin.ops@defense.gov:ClassifiedKey999;\n"
        "Extra log noise: some random bytes and padding\n"
        "Operator account: dev_lead@infra.cloud.org:SecretDevPass123\n"
        "--- END DUMP ---";

    size_t count = qihse_keystone_ingest_dirty_logs_user(
        kv,
        NULL,
        dirty_payload,
        strlen(dirty_payload),
        1,
        0,
        operator_user
    );

    assert(count >= 3);
    printf("  -> Extracted and indexed %zu classified artifacts with explicit principal\n", count);

    char* val1 = qihse_kv_get_user(kv, "victim1@financial-corp.com", operator_user);
    assert(val1 != NULL);
    assert(strstr(val1, "pass=P@ssw0rd2026!") != NULL);
    assert(strstr(val1, "slot=") != NULL);
    assert(strstr(val1, "class=") != NULL);
    free(val1);

    char* val2 = qihse_kv_get_user(kv, "admin.ops@defense.gov", operator_user);
    assert(val2 != NULL);
    assert(strstr(val2, "pass=ClassifiedKey999") != NULL);
    free(val2);

    /* The legacy NULL-principal path must fail closed for classified data. */
    const char* denied_payload = "legacy_denied@corp.internal:ShouldNotPersist\n";
    assert(qihse_keystone_ingest_dirty_logs(
               kv, NULL, denied_payload, strlen(denied_payload), 1, 0) == 0u);
    assert(qihse_kv_get_user(kv, "legacy_denied@corp.internal", operator_user) == NULL);

    qihse_kv_store_destroy(kv);
}

typedef struct {
    int fd;
    unsigned char buffer[131072];
    size_t used;
} test_client_t;

static int find_crlf(const unsigned char* data, size_t len, size_t start, size_t* end) {
    for (size_t i = start; i + 1u < len; i++) {
        if (data[i] == '\r' && data[i + 1u] == '\n') {
            *end = i;
            return 1;
        }
    }
    return 0;
}

static int parse_number(const unsigned char* data, size_t len, long long* value) {
    if (len == 0 || len >= 64u) return 0;
    char text[64];
    memcpy(text, data, len);
    text[len] = '\0';
    char* end = NULL;
    errno = 0;
    long long parsed = strtoll(text, &end, 10);
    if (errno != 0 || end != text + len) return 0;
    *value = parsed;
    return 1;
}

static int response_length(const unsigned char* data, size_t len, size_t* consumed, unsigned int depth) {
    if (len == 0 || depth > 32u) return 0;
    size_t line_end;
    if (data[0] == '+' || data[0] == '-' || data[0] == ':' || data[0] == ',' || data[0] == '#') {
        if (!find_crlf(data, len, 1u, &line_end)) return 0;
        *consumed = line_end + 2u;
        return 1;
    }
    if (data[0] == '$') {
        if (!find_crlf(data, len, 1u, &line_end)) return 0;
        long long bulk;
        if (!parse_number(data + 1u, line_end - 1u, &bulk)) return -1;
        if (bulk < 0) {
            *consumed = line_end + 2u;
            return 1;
        }
        size_t total = line_end + 2u + (size_t)bulk + 2u;
        if (total > len) return 0;
        if (data[total - 2u] != '\r' || data[total - 1u] != '\n') return -1;
        *consumed = total;
        return 1;
    }
    if (data[0] == '*' || data[0] == '%') {
        if (!find_crlf(data, len, 1u, &line_end)) return 0;
        long long count;
        if (!parse_number(data + 1u, line_end - 1u, &count) || count < 0) return -1;
        size_t elements = (size_t)count * (data[0] == '%' ? 2u : 1u);
        size_t cursor = line_end + 2u;
        for (size_t i = 0; i < elements; i++) {
            size_t child;
            int status = response_length(data + cursor, len - cursor, &child, depth + 1u);
            if (status <= 0) return status;
            cursor += child;
        }
        *consumed = cursor;
        return 1;
    }
    return -1;
}

static char* read_response(test_client_t* client) {
    size_t consumed = 0;
    while (1) {
        int status = response_length(client->buffer, client->used, &consumed, 0u);
        if (status < 0) return NULL;
        if (status > 0) break;
        assert(client->used < sizeof(client->buffer));
        ssize_t received = recv(client->fd, client->buffer + client->used,
                                sizeof(client->buffer) - client->used, 0);
        assert(received > 0);
        client->used += (size_t)received;
    }
    char* response = (char*)malloc(consumed + 1u);
    assert(response != NULL);
    memcpy(response, client->buffer, consumed);
    response[consumed] = '\0';
    memmove(client->buffer, client->buffer + consumed, client->used - consumed);
    client->used -= consumed;
    return response;
}

static void send_all(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t result = send(fd, data + sent, len - sent, 0);
        assert(result > 0);
        sent += (size_t)result;
    }
}

static void send_command(int fd, size_t argc, const char* const* argv) {
    char header[64];
    int len = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    assert(len > 0 && (size_t)len < sizeof(header));
    send_all(fd, header, (size_t)len);
    for (size_t i = 0; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        len = snprintf(header, sizeof(header), "$%zu\r\n", arg_len);
        assert(len > 0 && (size_t)len < sizeof(header));
        send_all(fd, header, (size_t)len);
        send_all(fd, argv[i], arg_len);
        send_all(fd, "\r\n", 2u);
    }
}

static void expect_response(test_client_t* client, const char* expected) {
    char* response = read_response(client);
    assert(response != NULL);
    if (strcmp(response, expected) != 0) {
        fprintf(stderr, "Expected RESP %s, received %s\n", expected, response);
    }
    assert(strcmp(response, expected) == 0);
    free(response);
}

typedef struct {
    qihse_resp_server_t* server;
    int fd;
} resp_thread_arg_t;

static void* resp_server_thread(void* arg) {
    resp_thread_arg_t* args = (resp_thread_arg_t*)arg;
    qihse_resp_server_handle_client_fd(args->server, args->fd);
    return NULL;
}

static void test_resp_keystone_commands(void) {
    printf("Testing authenticated RESP KEYSTONE trust boundaries...\n");

    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    qihse_user_t* guest = qihse_auth_create_user(
        operator_user,
        TEST_GUEST_ID,
        QIHSE_ROLE_GUEST,
        0,
        0,
        TEST_GUEST_PASSWORD,
        false
    );
    assert(guest != NULL);
    assert(qihse_auth_modify_user(operator_user, TEST_GUEST_ID,
                                  TEST_GUEST_USERNAME, NULL, -1, -1));

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo != NULL);
    qihse_cluster_node_t local_node;
    memset(&local_node, 0, sizeof(local_node));
    qihse_cluster_node_id_from_seed("local", 5, local_node.id);
    snprintf(local_node.host, sizeof(local_node.host), "127.0.0.1");
    local_node.port = 6379;
    local_node.bus_port = 16379;
    local_node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    local_node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    local_node.healthy = true;

    uint16_t local_idx = 0;
    assert(qihse_cluster_topology_upsert_node(topo, &local_node, &local_idx));
    assert(qihse_cluster_topology_set_local_node(topo, local_idx));
    assert(qihse_cluster_topology_assign_range(topo, 0, 16383, local_idx));

    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    qihse_column_store_t* columns = qihse_column_store_create();
    assert(vdb != NULL && tsdb != NULL && columns != NULL);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.tsdb = tsdb;
    config.column_store = columns;
    config.topology = topo;
    config.local_node_index = local_idx;
    config.port = 0;
    config.auth_required = true;

    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    resp_thread_arg_t args = { server, sockets[1] };
    pthread_t th;
    assert(pthread_create(&th, NULL, resp_server_thread, &args) == 0);

    test_client_t client;
    memset(&client, 0, sizeof(client));
    client.fd = sockets[0];

    const char* auth_operator[] = { "AUTH", "GODMODE_OP", TEST_OPERATOR_PASSWORD };
    send_command(client.fd, 3, auth_operator);
    expect_response(&client, "+OK\r\n");

    const char* classify_cmd[] = {
        "KEYSTONE.CLASSIFY",
        "swift wire bank transfer transaction USD 500"
    };
    send_command(client.fd, 2, classify_cmd);
    char* classify_response = read_response(&client);
    assert(classify_response != NULL);
    assert(classify_response[0] == '*');
    free(classify_response);

    const char* unclassified_ingest[] = {
        "KEYSTONE.INGEST",
        "breach_user@corp.internal:SecretVaultPass999\n"
    };
    send_command(client.fd, 2, unclassified_ingest);
    expect_response(&client, ":1\r\n");

    const char* clearance_overflow[] = {
        "KEYSTONE.INGEST",
        "overflow_clearance@corp.internal:NoStore\n",
        "65536"
    };
    send_command(client.fd, 3, clearance_overflow);
    expect_response(&client, "-ERR invalid clearance\r\n");

    const char* compartment_overflow[] = {
        "KEYSTONE.INGEST",
        "overflow_compartment@corp.internal:NoStore\n",
        "0",
        "65536"
    };
    send_command(client.fd, 4, compartment_overflow);
    expect_response(&client, "-ERR invalid compartment\r\n");

    const char* operator_classified[] = {
        "KEYSTONE.INGEST",
        "operator_secret@corp.internal:OpSecret123\n",
        "3",
        "1"
    };
    send_command(client.fd, 4, operator_classified);
    expect_response(&client, ":1\r\n");
    char* operator_secret = qihse_kv_get_user(store,
                                               "operator_secret@corp.internal",
                                               operator_user);
    assert(operator_secret != NULL);
    free(operator_secret);

    const char* auth_guest[] = { "AUTH", TEST_GUEST_USERNAME, TEST_GUEST_PASSWORD };
    send_command(client.fd, 3, auth_guest);
    expect_response(&client, "+OK\r\n");

    const char* guest_classified[] = {
        "KEYSTONE.INGEST",
        "guest_denied@corp.internal:ShouldNotPersist\n",
        "1",
        "0"
    };
    send_command(client.fd, 4, guest_classified);
    expect_response(&client, ":0\r\n");
    assert(qihse_kv_get_user(store, "guest_denied@corp.internal", operator_user) == NULL);

    close(sockets[0]);
    pthread_join(th, NULL);
    qihse_resp_server_destroy(server);
    qihse_cluster_topology_destroy(topo);
    qihse_column_store_destroy(columns);
    qihse_tsdb_destroy(tsdb);
    qihse_vector_db_destroy(vdb);
    qihse_kv_store_destroy(store);
    assert(qihse_auth_destroy_user(operator_user, TEST_GUEST_ID));

    printf("  -> RESP principal propagation, denial, and uint16 range checks OK\n");
}

int main(void) {
    printf("==============================================================\n");
    printf("  QIHSE + KEYSTONE Integration & Ingestion Engine Tests        \n");
    printf("==============================================================\n");

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(TEST_OPERATOR_PASSWORD));

    test_micro_model_classification();
    test_anchor_search_performance();
    test_simd_dirty_log_ingest();
    test_resp_keystone_commands();

    printf("\nAll QIHSE + KEYSTONE Integration Tests PASSED!\n");
    return 0;
}
