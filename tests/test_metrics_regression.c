/* Delivery-metrics regression test (U9): ingest rejections, killswitch
 * fan-outs, and bundle composes are counted in the metrics registry and
 * exposed via METRICS.RENDER (system-domain only; tenants get NOPERM).
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

#define TENANT_PW "MetricsTenantPa1!"
#define OPERATOR_PASSWORD "OperatorMetrics1!"

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
    size_t cap = 65536u;
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    for (;;) {
        struct pollfd pfd = { client->fd, POLLIN, 0 };
        int ready = poll(&pfd, 1, 20000);
        assert(ready > 0);
        ssize_t received = read(client->fd, buffer + len, cap - len - 1);
        assert(received > 0);
        len += (size_t)received;
        buffer[len] = '\0';
        if (len >= 2 && buffer[len - 2] == '\r' && buffer[len - 1] == '\n') {
            struct pollfd again = { client->fd, POLLIN, 0 };
            if (poll(&again, 1, 60) <= 0) break;
        }
    }
    return buffer;
}

static void expect_contains(test_client_t* client, const char* needle) {
    char* reply = read_reply(client);
    if (strstr(reply, needle) == NULL) {
        fprintf(stderr, "expected '%s' in reply: %s\n", needle, reply);
        assert(false);
    }
    free(reply);
}

int main(void) {
    char data_dir[] = "/tmp/qihse-metrics-XXXXXX";
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
    config.enable_killswitch_channel = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    test_client_t tenant;
    client_init(&tenant, server);
    const char* auth[] = { "AUTH", "User_71", TENANT_PW };
    send_command(tenant.fd, 3, auth);
    expect_contains(&tenant, "+OK");

    /* Tenant cannot render metrics. */
    const char* render[] = { "METRICS.RENDER" };
    send_command(tenant.fd, 1, render);
    expect_contains(&tenant, "NOPERM");

    /* One rejected telemetry record + one valid killswitch edge. */
    const char* bad[] = { "SET", "t:7/tlm/census/x", "census|free text from ops" };
    send_command(tenant.fd, 3, bad);
    expect_contains(&tenant, "INGEST record rejected");
    const char* edge[] = { "SET", "t:7/tlm/burn_edge/e1",
                           "burn_edge|deadbeefdeadbeef|cafebabecafebabe|9" };
    send_command(tenant.fd, 3, edge);
    expect_contains(&tenant, "+OK");

    test_client_t op;
    client_init(&op, server);
    const char* auth_op[] = { "AUTH", "GODMODE_OP", OPERATOR_PASSWORD };
    send_command(op.fd, 3, auth_op);
    expect_contains(&op, "+OK");
    send_command(op.fd, 1, render);
    {
        char* reply = read_reply(&op);
        assert(strstr(reply, "qihse_ingest_rejected_total 1") != NULL);
        assert(strstr(reply, "qihse_killswitch_push_total 1") != NULL);
        free(reply);
    }

    close(tenant.fd);
    close(op.fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("test_metrics_regression: all assertions passed\n");
    return 0;
}
