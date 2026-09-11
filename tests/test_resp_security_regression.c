/* RESP surface security regression test (AGENTS.md invariant #3).
 *
 * Authenticates a low-clearance GUEST principal against a RESP server with
 * classified KV data and a protected pub/sub channel policy, and asserts
 * denial with no protected payload disclosure across: unauthenticated access,
 * wrong-password AUTH, GET/MGET reads, EXISTS probing, KEYS enumeration,
 * pub/sub subscribe/publish, the stateless execute bridge, and the UWP
 * TARGET_RESP path (including the NULL-user bypass case).
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
#include "qihse_uwp.h"

#define GUEST_PASSWORD "GuestRespPass1!"
#define OPERATOR_PASSWORD "OperatorRespPass1!"

typedef struct {
    qihse_resp_server_t* server;
    int fd;
} server_thread_arg_t;

static void* server_thread(void* argument) {
    server_thread_arg_t* args = (server_thread_arg_t*)argument;
    assert(qihse_resp_server_handle_client_fd(args->server, args->fd));
    return NULL;
}

typedef struct {
    int fd;
    char* buffer;
    size_t len;
    size_t cap;
} test_client_t;

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
    client->buffer = NULL;
    client->len = 0;
    client->cap = 0;
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

/* Read whatever arrives within 2 seconds; returns a NUL-terminated buffer the
 * caller must free. */
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
        /* Heuristic completeness: replies used here end with \r\n and no
         * partial trailing bulk header. Good enough for fixed commands. */
        if (len >= 2 && buffer[len - 2] == '\r' && buffer[len - 1] == '\n') {
            /* Keep reading briefly in case of pipeline, but for this test one
             * reply per command is sent. */
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
        for (size_t i = 0; i < strlen(reply) && i < 64; i++) fputc((unsigned char)reply[i] >= 32 && (unsigned char)reply[i] < 127 ? reply[i] : '.', stderr);
        fputc('\n', stderr);
        assert(false);
    }
    free(reply);
}

static void bootstrap_user(qihse_user_t* operator_user, uint32_t id, uint16_t classif,
                           const char* password, const char* label) {
    qihse_user_t* user = qihse_auth_create_user(operator_user, id, QIHSE_ROLE_GUEST,
                                                classif, 0, password, false);
    assert(user != NULL);
    (void)label;
}

int main(void) {
    char data_dir[] = "/tmp/qihse-resp-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    bootstrap_user(operator_user, 91, 91, GUEST_PASSWORD, "guest");

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    /* Operator plants a secret above the guest's clearance (91). */
    assert(qihse_kv_set_user(store, "secret:direct", "topsecret-payload", 95, 0, operator_user));

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0;
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.channel_classification = 95; /* pub/sub channels are protected */
    config.channel_sci = 0;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    test_client_t guest;
    client_init(&guest, server);

    const char* get_secret[] = { "GET", "secret:direct" };
    send_command(guest.fd, 2, get_secret);
    expect_contains(&guest, "-NOAUTH");

    const char* bad_auth[] = { "AUTH", "guest", "WrongPassword1!" };
    send_command(guest.fd, 3, bad_auth);
    expect_contains(&guest, "WRONGPASS");
    send_command(guest.fd, 2, get_secret);
    expect_contains(&guest, "-NOAUTH");

    const char* guest_auth[] = { "AUTH", "User_91", GUEST_PASSWORD };
    send_command(guest.fd, 3, guest_auth);
    expect_contains(&guest, "+OK");

    send_command(guest.fd, 2, get_secret);
    expect_contains(&guest, "$-1");

    const char* mget[] = { "MGET", "public:x", "secret:direct" };
    send_command(guest.fd, 3, mget);
    {
        char* reply = read_reply(&guest);
        assert(strstr(reply, "topsecret-payload") == NULL);
        free(reply);
    }

    const char* exists[] = { "EXISTS", "secret:direct" };
    send_command(guest.fd, 2, exists);
    expect_contains(&guest, ":0");

    const char* keys[] = { "KEYS", "*" };
    send_command(guest.fd, 2, keys);
    {
        char* reply = read_reply(&guest);
        assert(strstr(reply, "secret:direct") == NULL);
        free(reply);
    }

    const char* subscribe[] = { "SUBSCRIBE", "news" };
    send_command(guest.fd, 2, subscribe);
    expect_contains(&guest, "NOPERM");
    const char* publish[] = { "PUBLISH", "news", "payload" };
    send_command(guest.fd, 3, publish);
    expect_contains(&guest, "NOPERM");

    /* 9. Stateless execute bridge: NULL user is rejected outright; guest gets
     * nil for the secret, never the payload (invariant #1). */
    qihse_resp_arg_t exec_args[2] = {
        { (const uint8_t*)"GET", 3 },
        { (const uint8_t*)"secret:direct", 13 }
    };
    uint8_t* reply = NULL;
    size_t reply_len = 0;
    assert(!qihse_resp_server_execute(server, NULL, 2, exec_args, &reply, &reply_len));
    assert(qihse_resp_server_execute(server, operator_user, 2, exec_args, &reply, &reply_len));
    assert(reply_len == 5 + strlen("topsecret-payload") + 2); /* $18\r\n...\r\n */
    assert(memcmp(reply, "$", 1) == 0 && strstr((char*)reply, "topsecret-payload") != NULL);
    free(reply);
    qihse_user_t* guest_user = qihse_auth_authenticate("User_91", GUEST_PASSWORD);
    assert(guest_user != NULL);
    assert(qihse_resp_server_execute(server, guest_user, 2, exec_args, &reply, &reply_len));
    assert(reply_len == 5 && memcmp(reply, "$-1\r\n", 5) == 0);
    free(reply);

    qihse_uwp_context_t uwp_ctx;
    memset(&uwp_ctx, 0, sizeof(uwp_ctx));
    uwp_ctx.kv = store;
    uwp_ctx.resp_server = server;
    qihse_uwp_header_t header;
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, (const uint8_t[]){ 0x51, 0x49, 0x48, 0x53 }, 4);
    header.version = 0x01;
    header.target_engine = QIHSE_UWP_TARGET_RESP;
    header.command_opcode = QIHSE_UWP_RESP_EXEC;
    uint8_t payload[64];
    size_t payload_len = 0;
    uint32_t argc_host = 2;
    memcpy(payload + payload_len, &argc_host, sizeof(argc_host));
    payload_len += sizeof(argc_host);
    const char* parts[2] = { "GET", "secret:direct" };
    for (int i = 0; i < 2; i++) {
        uint32_t part_len = (uint32_t)strlen(parts[i]);
        memcpy(payload + payload_len, &part_len, sizeof(part_len));
        payload_len += sizeof(part_len);
        memcpy(payload + payload_len, parts[i], part_len);
        payload_len += part_len;
    }
    header.payload_length = payload_len;
    uint8_t out[512];
    size_t out_len = 0;
    assert(!qihse_uwp_dispatch(&uwp_ctx, NULL, &header, payload, payload_len, out, sizeof(out), &out_len));

    /* Guest through the UWP bridge: denied payload, nil reply. */
    assert(qihse_uwp_dispatch(&uwp_ctx, guest_user, &header, payload, payload_len, out, sizeof(out), &out_len));
    assert(out_len == 5 && memcmp(out, "$-1\r\n", 5) == 0);

    /* Positive control: operator through the bridge does get the payload. */
    assert(qihse_uwp_dispatch(&uwp_ctx, operator_user, &header, payload, payload_len, out, sizeof(out), &out_len));
    assert(strstr((char*)out, "topsecret-payload") != NULL);

    /* 11. Operator connection: subscribe works on the protected channel and
     * publish reaches its own subscription (positive pub/sub control). */
    test_client_t operator_client;
    client_init(&operator_client, server);
    const char* operator_auth[] = { "AUTH", qihse_user_get_username(operator_user), OPERATOR_PASSWORD };
    send_command(operator_client.fd, 3, operator_auth);
    expect_contains(&operator_client, "+OK");
    const char* operator_subscribe[] = { "SUBSCRIBE", "news" };
    send_command(operator_client.fd, 2, operator_subscribe);
    {
        char* sub_reply = read_reply(&operator_client);
        assert(strstr(sub_reply, "*3\r\n$9\r\nsubscribe\r\n") == sub_reply);
        free(sub_reply);
    }
    /* A subscribed connection cannot PUBLISH (Redis semantics); publish via
     * the stateless bridge instead and expect the push on the subscription. */
    qihse_resp_arg_t publish_args[3] = {
        { (const uint8_t*)"PUBLISH", 7 },
        { (const uint8_t*)"news", 4 },
        { (const uint8_t*)"hello-fleet", 11 }
    };
    assert(qihse_resp_server_execute(server, operator_user, 3, publish_args, &reply, &reply_len));
    assert(reply_len == 4 && memcmp(reply, ":1\r\n", 4) == 0); /* one receiver */
    free(reply);
    expect_contains(&operator_client, "$7\r\nmessage\r\n$4\r\nnews\r\n$11\r\nhello-fleet\r\n");

    const char* psubscribe[] = { "PSUBSCRIBE", "*" };
    send_command(guest.fd, 2, psubscribe);
    expect_contains(&guest, "NOPERM");

    close(guest.fd);
    close(operator_client.fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("test_resp_security_regression: all assertions passed\n");
    return 0;
}
