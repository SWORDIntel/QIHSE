/* Killswitch push-channel regression test (AGENTS.md invariants #1/#3, U8).
 *
 * A burn_edge telemetry write fans out to every connected tenant on the
 * fleet-wide "killswitch" channel within the propagation SLA, is mirrored to
 * a durable commons record for offline catch-up, and cannot be spoofed:
 * tenants may subscribe but never publish, and invalid edges are rejected at
 * ingest before anything is pushed or persisted.
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
#include <time.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#define TENANT7_PW "KillTenant7Pass1!"
#define TENANT8_PW "KillTenant8Pass1!"
#define OPERATOR_PASSWORD "OperatorKillPas1!"
#define EDGE_VALUE "burn_edge|deadbeefdeadbeef|cafebabecafebabe|9"

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

/* Reads one complete RESP reply (simple/error/integer/bulk) — no heuristics. */
static char* read_reply(test_client_t* client) {
    size_t cap = 65536u;
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    for (;;) {
        size_t line_end = 0;
        for (;;) {
            if (len >= cap - 1u) assert(false);
            struct pollfd pfd = { client->fd, POLLIN, 0 };
            int ready = poll(&pfd, 1, 20000);
            assert(ready > 0);
            ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
            assert(received > 0);
            len += (size_t)received;
            buffer[len] = '\0';
            char* crlf = memchr(buffer, '\r', len);
            if (crlf && (size_t)(crlf - buffer) + 1u < len && crlf[1] == '\n') {
                line_end = (size_t)(crlf - buffer);
                break;
            }
        }
        char type = buffer[0];
        if (type == '+' || type == '-' || type == ':') return buffer;
        assert(type == '$' || type == '*');
        uint64_t count = 0;
        for (size_t i = 1; i < line_end; i++) {
            assert(buffer[i] >= '0' && buffer[i] <= '9');
            count = count * 10u + (uint64_t)(buffer[i] - '0');
        }
        if (type == '$') {
            /* Top-level bulk: payload begins immediately after the type line. */
            size_t needed = line_end + 2u + (size_t)count + 2u;
            while (len < needed) {
                struct pollfd pfd = { client->fd, POLLIN, 0 };
                int ready = poll(&pfd, 1, 20000);
                assert(ready > 0);
                ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
                assert(received > 0);
                len += (size_t)received;
                buffer[len] = '\0';
            }
            return buffer;
        }
        size_t offset = line_end + 2u;
        uint64_t elements = (type == '*') ? count : 1; /* bulk: one element */
        /* Consume `elements` bulk strings ("$len\r\n<payload>\r\n"). */
        for (uint64_t e = 0; e < elements; e++) {
            /* Ensure the element header start byte has arrived. */
            while (offset >= len) {
                struct pollfd pfd = { client->fd, POLLIN, 0 };
                int ready = poll(&pfd, 1, 20000);
                assert(ready > 0);
                ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
                assert(received > 0);
                len += (size_t)received;
                buffer[len] = '\0';
            }
            if (buffer[offset] != '$' && buffer[offset] != ':' && buffer[offset] != '+' && buffer[offset] != '-') {
                fprintf(stderr, "[DBG] element type '%c' (0x%02x) at %zu: %.*s\n",
                        buffer[offset] >= 32 && buffer[offset] < 127 ? buffer[offset] : '?',
                        buffer[offset], offset, (int)(len > 300 ? 300 : len), buffer);
            }
            if (buffer[offset] != '$') {
                /* Simple/integer elements (":1" etc.): consume one line. */
                assert(buffer[offset] == ':' || buffer[offset] == '+' || buffer[offset] == '-');
                for (;;) {
                    char* crlf = memchr(buffer + offset, '\r', len - offset);
                    if (crlf && (size_t)(crlf - buffer) + 1u < len && crlf[1] == '\n') {
                        offset = (size_t)(crlf - buffer) + 2u;
                        break;
                    }
                    struct pollfd pfd = { client->fd, POLLIN, 0 };
                    int ready = poll(&pfd, 1, 20000);
                    assert(ready > 0);
                    ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
                    assert(received > 0);
                    len += (size_t)received;
                    buffer[len] = '\0';
                }
                continue;
            }
            /* Find the header line's CRLF. */
            size_t hdr_cr = 0;
            for (;;) {
                char* crlf = memchr(buffer + offset + 1u, '\r', len - offset - 1u);
                if (crlf && (size_t)(crlf - buffer) + 1u < len && crlf[1] == '\n') {
                    hdr_cr = (size_t)(crlf - buffer);
                    break;
                }
                struct pollfd pfd = { client->fd, POLLIN, 0 };
                int ready = poll(&pfd, 1, 20000);
                assert(ready > 0);
                ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
                assert(received > 0);
                len += (size_t)received;
                buffer[len] = '\0';
            }
            uint64_t bulk_len = 0;
            for (size_t i = offset + 1u; i < hdr_cr; i++) {
                assert(buffer[i] >= '0' && buffer[i] <= '9');
                bulk_len = bulk_len * 10u + (uint64_t)(buffer[i] - '0');
            }
            size_t needed = hdr_cr + 2u + (size_t)bulk_len + 2u;
            while (len < needed) {
                struct pollfd pfd = { client->fd, POLLIN, 0 };
                int ready = poll(&pfd, 1, 20000);
                assert(ready > 0);
                ssize_t received = read(client->fd, buffer + len, cap - len - 1u);
                assert(received > 0);
                len += (size_t)received;
                buffer[len] = '\0';
            }
            offset = needed;
        }
        return buffer;
    }
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

/* Waits up to timeout_ms for a push containing `needle`. */
static void expect_push_within(test_client_t* client, const char* needle, int timeout_ms) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        struct pollfd pfd = { client->fd, POLLIN, 0 };
        int ready = poll(&pfd, 1, timeout_ms);
        assert(ready > 0); /* SLA blown: no push arrived */
        char* reply = read_reply(client);
        if (strstr(reply, needle) != NULL) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1000000L;
            fprintf(stderr, "killswitch push delivered in %ld ms\n", elapsed_ms);
            assert(elapsed_ms < 5000); /* propagation SLA: minutes allowed, loopback must be far below */
            free(reply);
            return;
        }
        free(reply);
    }
}

int main(void) {
    char data_dir[] = "/tmp/qihse-killswitch-sec-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT7_PW, false);
    assert(tenant7 != NULL);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(operator_user, 8, 72,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT8_PW, false);
    assert(tenant8 != NULL);

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
    config.channel_classification = 95; /* default channels stay protected */
    config.channel_sci = 0;
    config.enable_killswitch_channel = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    /* Subscribers: one per tenant, both on the killswitch channel. */
    test_client_t sub7, sub8, writer;
    client_init(&sub7, server);
    const char* auth7[] = { "AUTH", "User_71", TENANT7_PW };
    send_command(sub7.fd, 3, auth7);
    expect_contains(&sub7, "+OK");
    const char* subscribe[] = { "SUBSCRIBE", "killswitch" };
    send_command(sub7.fd, 2, subscribe);
    expect_contains(&sub7, "*3\r\n$9\r\nsubscribe\r\n$10\r\nkillswitch\r\n");

    client_init(&sub8, server);
    const char* auth8[] = { "AUTH", "User_72", TENANT8_PW };
    send_command(sub8.fd, 3, auth8);
    expect_contains(&sub8, "+OK");
    send_command(sub8.fd, 2, subscribe);
    expect_contains(&sub8, "*3\r\n$9\r\nsubscribe\r\n$10\r\nkillswitch\r\n");

    /* Tenants may NOT publish to the killswitch channel (spoofing defense). */
    client_init(&writer, server);
    const char* authw[] = { "AUTH", "User_71", TENANT7_PW };
    send_command(writer.fd, 3, authw);
    expect_contains(&writer, "+OK");
    const char* spoof[] = { "PUBLISH", "killswitch", "fake edge" };
    send_command(writer.fd, 3, spoof);
    expect_contains(&writer, "NOPERM");

    /* A valid burn_edge write fans out to BOTH subscribers within the SLA. */
    const char* edge_write[] = { "SET", "t:7/tlm/burn_edge/e1", EDGE_VALUE };
    send_command(writer.fd, 3, edge_write);
    expect_contains(&writer, "+OK");
    expect_push_within(&sub7, EDGE_VALUE, 5000);
    expect_push_within(&sub8, EDGE_VALUE, 5000);

    /* Durable catch-up record: readable by every tenant. */
    const char* catchup[] = { "GET", "commons/killswitch/latest" };
    send_command(writer.fd, 2, catchup);
    expect_contains(&writer, EDGE_VALUE);

    /* An INVALID edge is rejected at ingest: no push, no durable record. */
    const char* bad_edge[] = { "SET", "t:7/tlm/burn_edge/e2",
                               "burn_edge|I saw the machine named ORION-7 near the router|3" };
    send_command(writer.fd, 3, bad_edge);
    expect_contains(&writer, "INGEST record rejected");
    /* The durable record still holds the LAST VALID edge, and no push for the
     * invalid value arrived (subscribers would have received it first). */
    send_command(writer.fd, 2, catchup);
    expect_contains(&writer, EDGE_VALUE);

    /* Cross-tenant isolation still applies to ordinary telemetry keys: the
     * killswitch channel is the only cross-tenant surface. */
    test_client_t peeker;
    client_init(&peeker, server);
    const char* authp[] = { "AUTH", "User_72", TENANT8_PW };
    send_command(peeker.fd, 3, authp);
    expect_contains(&peeker, "+OK");
    const char* peek[] = { "GET", "t:7/tlm/burn_edge/e1" };
    send_command(peeker.fd, 2, peek);
    expect_contains(&peeker, "NOPERM");
    close(peeker.fd);

    close(sub7.fd);
    close(sub8.fd);
    close(writer.fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("test_killswitch_regression: all assertions passed\n");
    return 0;
}
