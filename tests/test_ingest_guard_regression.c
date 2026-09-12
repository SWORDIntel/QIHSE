/* Ingest-guard security regression test (AGENTS.md invariant #3, U4).
 *
 * The telemetry namespace ("t:<id>/tlm/...") enforces a CLOSED record-type
 * whitelist with per-field validators. Positive coverage: all five record
 * types ingest. Negative coverage: unknown record types, free-text payloads,
 * wrong field counts/types, value-tag mismatch — each rejected AND nothing
 * persisted (GET-after-assert). The gate is structural: it binds the
 * operator too. Non-telemetry keys are unaffected.
 */
#define _GNU_SOURCE

#include <assert.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#define TENANT_PW "IngestTenantPas1!"
#define OPERATOR_PASSWORD "OperatorIngestP1!"

typedef struct { qihse_resp_server_t* server; int fd; } server_thread_arg_t;

static void* server_thread(void* argument) {
    server_thread_arg_t* args = (server_thread_arg_t*)argument;
    assert(qihse_resp_server_handle_client_fd(args->server, args->fd));
    return NULL;
}

typedef struct { int fd; } test_client_t;

static void client_init(test_client_t* client, qihse_resp_server_t* server) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    server_thread_arg_t* args = malloc(sizeof(*args));
    assert(args != NULL);
    args->server = server;
    args->fd = sockets[1];
    pthread_t thread;
    assert(pthread_create(&thread, NULL, server_thread, args) == 0);
    pthread_detach(thread);
    client->fd = sockets[0];
}

static void send_command(int fd, size_t argc, const char** argv) {
    char header[64];
    int written = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    assert(written > 0);
    assert(write(fd, header, (size_t)written) == (ssize_t)written);
    for (size_t i = 0; i < argc; i++) {
        written = snprintf(header, sizeof(header), "$%zu\r\n", strlen(argv[i]));
        assert(written > 0);
        assert(write(fd, header, (size_t)written) == (ssize_t)written);
        assert(write(fd, argv[i], strlen(argv[i])) == (ssize_t)strlen(argv[i]));
        assert(write(fd, "\r\n", 2) == 2);
    }
}

static char* read_reply(test_client_t* client) {
    size_t cap = 8192;
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    for (;;) {
        struct pollfd pfd = { client->fd, POLLIN, 0 };
        int ready = poll(&pfd, 1, 15000);
        assert(ready > 0);
        ssize_t received = read(client->fd, buffer + len, cap - len - 1);
        assert(received > 0);
        len += (size_t)received;
        buffer[len] = '\0';
        if (len >= 2 && buffer[len - 2] == '\r' && buffer[len - 1] == '\n') {
            struct pollfd again = { client->fd, POLLIN, 0 };
            if (poll(&again, 1, 50) <= 0) break;
        }
    }
    return buffer;
}

static void expect_contains(test_client_t* client, const char* needle) {
    char* reply = read_reply(client);
    if (strstr(reply, needle) == NULL) {
        fprintf(stderr, "expected '%s' in reply (%zu bytes): ", needle, strlen(reply));
        for (size_t i = 0; i < strlen(reply) && i < 96; i++) fputc((unsigned char)reply[i] >= 32 && (unsigned char)reply[i] < 127 ? reply[i] : '.', stderr);
        fputc('\n', stderr);
        assert(false);
    }
    free(reply);
}

int main(void) {
    char data_dir[] = "/tmp/qihse-ingest-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT_PW, false);
    assert(tenant7 != NULL);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0;
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    test_client_t client;
    client_init(&client, server);
    const char* auth[] = { "AUTH", "User_71", TENANT_PW };
    send_command(client.fd, 3, auth);
    expect_contains(&client, "+OK");

    /* All five whitelisted record types ingest cleanly. */
    const char* ok_build[] = { "SET", "t:7/tlm/build_record/abc",
                               "build_record|0123456789abcdef|fedcba9876543210|123456|ok" };
    send_command(client.fd, 3, ok_build);
    expect_contains(&client, "+OK");
    const char* ok_symbol[] = { "SET", "t:7/tlm/symbol_context/main",
                                "symbol_context|deadbeefdeadbeef|1|42" };
    send_command(client.fd, 3, ok_symbol);
    expect_contains(&client, "+OK");
    const char* ok_census[] = { "SET", "t:7/tlm/census/daily", "census|100000|86400000" };
    send_command(client.fd, 3, ok_census);
    expect_contains(&client, "+OK");
    const char* ok_survival[] = { "SET", "t:7/tlm/survival_observation/s1", "survival_observation|3600000|2" };
    send_command(client.fd, 3, ok_survival);
    expect_contains(&client, "+OK");
    const char* ok_burn[] = { "SET", "t:7/tlm/burn_edge/e1",
                              "burn_edge|deadbeefdeadbeef|cafebabecafebabe|7" };
    send_command(client.fd, 3, ok_burn);
    expect_contains(&client, "+OK");

    /* Free text: any character outside the closed alphabet is rejected. */
    const char* free_text[] = { "SET", "t:7/tlm/build_record/leak",
                                "build_record|0123456789abcdef|fedcba9876543210|1|worked on jonas laptop at reboot.fm" };
    send_command(client.fd, 3, free_text);
    expect_contains(&client, "INGEST record rejected");

    /* Unknown record type: not on the whitelist. */
    const char* unknown_type[] = { "SET", "t:7/tlm/diagnostic/x1", "diagnostic|whatever" };
    send_command(client.fd, 3, unknown_type);
    expect_contains(&client, "INGEST record rejected");

    /* Bad field values (letters where a u64 belongs). */
    const char* bad_field[] = { "SET", "t:7/tlm/census/bad", "census|lots|86400000" };
    send_command(client.fd, 3, bad_field);
    expect_contains(&client, "INGEST record rejected");

    /* Wrong field count. */
    const char* bad_count[] = { "SET", "t:7/tlm/census/bad2", "census|1" };
    send_command(client.fd, 3, bad_count);
    expect_contains(&client, "INGEST record rejected");

    /* Value tag mismatched with key segment. */
    const char* tag_mismatch[] = { "SET", "t:7/tlm/census/mixup", "survival_observation|1|0" };
    send_command(client.fd, 3, tag_mismatch);
    expect_contains(&client, "INGEST record rejected");

    /* Rejected writes persisted NOTHING. */
    const char* get_leak[] = { "GET", "t:7/tlm/build_record/leak" };
    send_command(client.fd, 2, get_leak);
    expect_contains(&client, "$-1");
    const char* get_diag[] = { "GET", "t:7/tlm/diagnostic/x1" };
    send_command(client.fd, 2, get_diag);
    expect_contains(&client, "$-1");

    /* Structural: the operator is bound by the same gate. */
    qihse_resp_arg_t op_write[3] = {
        { (const uint8_t*)"SET", 3 },
        { (const uint8_t*)"t:0/tlm/census/manual", 21 },
        { (const uint8_t*)"census|note from ops|5", 22 }
    };
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    assert(qihse_resp_server_execute(server, operator_user, 3, op_write, &reply, &reply_len));
    assert(memcmp(reply, "-INGEST", 7) == 0);
    free(reply);

    /* Valid operator telemetry still ingests. */
    qihse_resp_arg_t op_write_ok[3] = {
        { (const uint8_t*)"SET", 3 },
        { (const uint8_t*)"t:0/tlm/census/manual", 21 },
        { (const uint8_t*)"census|5|1000", 13 }
    };
    assert(qihse_resp_server_execute(server, operator_user, 3, op_write_ok, &reply, &reply_len));
    assert(reply_len == 5 && memcmp(reply, "+OK\r\n", 5) == 0);
    free(reply);

    /* Non-telemetry tenant keys keep full freedom. */
    const char* free_key[] = { "SET", "t:7/notes/scratchpad", "free text with spaces and punctuation!" };
    send_command(client.fd, 3, free_key);
    expect_contains(&client, "+OK");

    close(client.fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("test_ingest_guard_regression: all assertions passed\n");
    return 0;
}
