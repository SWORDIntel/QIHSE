/* Tenant isolation security regression test (AGENTS.md invariants #1..#3,
 * SESSION_DELIVERY_UPGRADES.md U2).
 *
 * Authenticates tenant-scoped principals against a RESP server with per-tenant
 * KV data, a shared commons namespace, and classified data, and asserts:
 *   - tenant principals can read/write their own "t:<id>/" namespace and the
 *     shared "commons/" namespace,
 *   - deny-by-default everywhere else (other tenants' namespaces, unscoped
 *     keys), with no cross-tenant payload disclosure,
 *   - clearance denials still apply inside the allowed namespace,
 *   - per-tenant quotas reject over-budget operations (fail closed),
 *   - a destroyed principal loses its live session immediately (revocation
 *     SLA) — the next command on the same connection is refused.
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
#include "qihse_quota.h"
#include "qihse_resp_wire.h"

#define TENANT_PW "Tenant7Passwrd1!"
#define TENANT8_PW "Tenant8Passwrd1!"
#define OPERATOR_PASSWORD "OperatorTenantPass1!"

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
        for (size_t i = 0; i < strlen(reply) && i < 80; i++) fputc((unsigned char)reply[i] >= 32 && (unsigned char)reply[i] < 127 ? reply[i] : '.', stderr);
        fputc('\n', stderr);
        assert(false);
    }
    free(reply);
}

/* Single reply must contain `contains` and must not contain `absent`
 * (negative-authorization assertion with no second reply to consume). */
static void expect_reply(test_client_t* client, const char* contains, const char* absent) {
    char* reply = read_reply(client);
    if (contains && strstr(reply, contains) == NULL) {
        fprintf(stderr, "expected '%s' in reply (%zu bytes): ", contains, strlen(reply));
        for (size_t i = 0; i < strlen(reply) && i < 80; i++) fputc((unsigned char)reply[i] >= 32 && (unsigned char)reply[i] < 127 ? reply[i] : '.', stderr);
        fputc('\n', stderr);
        assert(false);
    }
    if (absent && strstr(reply, absent) != NULL) {
        fprintf(stderr, "payload leak: '%s' present in reply\n", absent);
        assert(false);
    }
    free(reply);
}

int main(void) {
    char data_dir[] = "/tmp/qihse-tenant-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);

    /* Tenant-scoped principals (invariant #2 ladder exercised in
     * test_tenant_privilege_ladder; here they are operator-minted). */
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT_PW, false);
    assert(tenant7 != NULL);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(operator_user, 8, 72,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT8_PW, false);
    assert(tenant8 != NULL);
    assert(qihse_user_get_tenant_id(tenant7) == 7);
    assert(qihse_user_get_tenant_id(tenant8) == 8);
    assert(qihse_user_get_tenant_id(operator_user) == QIHSE_TENANT_SYSTEM);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    /* Operator plants per-tenant, commons, and classified data. */
    assert(qihse_kv_set_user(store, "t:7/data", "tenant7-payload", 0, 0, operator_user));
    assert(qihse_kv_set_user(store, "t:8/data", "tenant8-payload", 0, 0, operator_user));
    assert(qihse_kv_set_user(store, "commons/report", "commons-payload", 0, 0, operator_user));
    assert(qihse_kv_set_user(store, "secret:direct", "topsecret-payload", 95, 0, operator_user));
    /* Classified data inside tenant 7's namespace (above tenant clearance). */
    assert(qihse_kv_set_user(store, "t:7/secret", "tenant7-topsecret", 95, 0, operator_user));

    /* Quotas: tenant 7 may write 3 telemetry records per window. */
    qihse_quota_table_t* quotas = qihse_quota_table_create(64);
    assert(quotas != NULL);
    assert(qihse_quota_configure(quotas, 7, QIHSE_QUOTA_TELEMETRY_INGEST, 3, 60));

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0;
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.channel_classification = 95;
    config.channel_sci = 0;
    config.quotas = quotas;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    test_client_t tenant7_client;
    client_init(&tenant7_client, server);
    const char* auth7[] = { "AUTH", "User_71", TENANT_PW };
    send_command(tenant7_client.fd, 3, auth7);
    expect_contains(&tenant7_client, "+OK");

    /* Own namespace and commons are readable. */
    const char* own[] = { "GET", "t:7/data" };
    send_command(tenant7_client.fd, 2, own);
    expect_contains(&tenant7_client, "tenant7-payload");
    const char* commons[] = { "GET", "commons/report" };
    send_command(tenant7_client.fd, 2, commons);
    expect_contains(&tenant7_client, "commons-payload");

    /* Other tenants' namespace: denied with no payload disclosure. */
    const char* foreign[] = { "GET", "t:8/data" };
    send_command(tenant7_client.fd, 2, foreign);
    expect_reply(&tenant7_client, "NOPERM", "tenant8-payload");
    const char* foreign_write[] = { "SET", "t:8/evil", "x" };
    send_command(tenant7_client.fd, 3, foreign_write);
    expect_contains(&tenant7_client, "NOPERM");

    /* Deny-by-default: unscoped keys are outside a tenant's reach. */
    const char* unscoped[] = { "SET", "global:x", "v" };
    send_command(tenant7_client.fd, 3, unscoped);
    expect_contains(&tenant7_client, "NOPERM");

    /* Clearance enforcement still applies inside the own namespace. */
    const char* classified[] = { "GET", "t:7/secret" };
    send_command(tenant7_client.fd, 2, classified);
    expect_reply(&tenant7_client, "$-1", "tenant7-topsecret");

    /* Unscoped keys are refused at the boundary before any handler runs —
     * including above-clearance ones (no information either way). */
    const char* unscoped_secret[] = { "GET", "secret:direct" };
    send_command(tenant7_client.fd, 2, unscoped_secret);
    expect_reply(&tenant7_client, "NOPERM", "topsecret-payload");

    /* Telemetry ingest quota: 3 allowed, 4th rejected, nothing over budget.
     * Values are schema-valid census records (the U4 ingest gate is active). */
    for (int i = 0; i < 3; i++) {
        const char* tlm[] = { "SET", "t:7/tlm/census/temp", "census|21500|1000" };
        send_command(tenant7_client.fd, 3, tlm);
        expect_contains(&tenant7_client, "+OK");
    }
    const char* tlm_over[] = { "SET", "t:7/tlm/census/temp", "census|22000|1000" };
    send_command(tenant7_client.fd, 3, tlm_over);
    expect_contains(&tenant7_client, "QUOTA");
    /* Non-telemetry writes are a different quota class: unlimited. */
    const char* other_write[] = { "SET", "t:7/state", "ok" };
    send_command(tenant7_client.fd, 3, other_write);
    expect_contains(&tenant7_client, "+OK");

    /* Revocation SLA: destroy the principal; the live session must refuse
     * the very next command. */
    assert(qihse_auth_destroy_user(operator_user, 71));
    assert(!qihse_auth_user_is_active(tenant7));
    const char* after_revoke[] = { "GET", "t:7/data" };
    send_command(tenant7_client.fd, 2, after_revoke);
    expect_contains(&tenant7_client, "NOAUTH");

    /* Tenant 8 likewise cannot see tenant 7 data (payload or key). */
    test_client_t tenant8_client;
    client_init(&tenant8_client, server);
    const char* auth8[] = { "AUTH", "User_72", TENANT8_PW };
    send_command(tenant8_client.fd, 3, auth8);
    expect_contains(&tenant8_client, "+OK");
    const char* cross[] = { "GET", "t:7/data" };
    send_command(tenant8_client.fd, 2, cross);
    expect_reply(&tenant8_client, "NOPERM", "tenant7-payload");
    const char* commons8[] = { "GET", "commons/report" };
    send_command(tenant8_client.fd, 2, commons8);
    expect_contains(&tenant8_client, "commons-payload");

    /* Unauthenticated connections are still refused outright. */
    test_client_t anon;
    client_init(&anon, server);
    const char* get_anon[] = { "GET", "t:7/data" };
    send_command(anon.fd, 2, get_anon);
    expect_contains(&anon, "NOAUTH");

    /* Positive control: the system-domain operator is exempt from tenant
     * scoping and reads across namespaces. */
    test_client_t operator_client;
    client_init(&operator_client, server);
    const char* auth_op[] = { "AUTH", "GODMODE_OP", OPERATOR_PASSWORD };
    send_command(operator_client.fd, 3, auth_op);
    expect_contains(&operator_client, "+OK");
    send_command(operator_client.fd, 2, foreign);
    expect_contains(&operator_client, "tenant8-payload");
    const char* set_op[] = { "SET", "t:8/data", "operator-write" };
    send_command(operator_client.fd, 3, set_op);
    expect_contains(&operator_client, "+OK");

    close(tenant7_client.fd);
    close(tenant8_client.fd);
    close(anon.fd);
    close(operator_client.fd);
    qihse_resp_server_destroy(server);
    qihse_quota_table_destroy(quotas);
    qihse_kv_store_destroy(store);
    printf("test_tenant_security_regression: all assertions passed\n");
    return 0;
}
