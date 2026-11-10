#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_resp_wire.h"
#include "qihse_auth.h"
#include "qihse_audit.h"
#include "qihse_kv_store.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define OPERATOR_PASSWORD "RawWirePass123!"

/* Force the legacy implementation so this test covers the fallback parser. */
bool __wrap_qihse_resp_engine_handle_legacy(int fd, qihse_kv_store_t* store,
                                             qihse_vector_db_t vdb) {
    (void)fd; (void)store; (void)vdb;
    return false;
}

bool qihse_resp_wire_test_write_all(int fd, const char* data, size_t len);

typedef struct {
    int server_fd;
    int client_fd;
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
} client_args_t;

static void* client_main(void* opaque) {
    client_args_t* args = opaque;
    qihse_resp_handle_client(args->server_fd, args->store, args->vdb);
    return NULL;
}

static void write_exact(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        off += (size_t)n;
    }
}

static void read_exact(int fd, char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, data + off, len - off, 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        off += (size_t)n;
    }
}

static void start_client(client_args_t* args, pthread_t* thread,
                         qihse_kv_store_t* store) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    args->server_fd = sockets[1];
    args->client_fd = sockets[0];
    args->store = store;
    args->vdb = NULL;
    assert(pthread_create(thread, NULL, client_main, args) == 0);
}

static void test_split_pipeline(qihse_kv_store_t* store) {
    client_args_t args;
    pthread_t thread;
    start_client(&args, &thread, store);
    static const char first[] =
        "*1\r\n$4\r\nPING\r\n"
        "*3\r\n$4\r\nAUTH\r\n$10\r\nGODMODE_OP\r\n$";
    write_exact(args.client_fd, first, sizeof(first) - 1u);
    char reply[32];
    read_exact(args.client_fd, reply, 7u);
    assert(memcmp(reply, "+PONG\r\n", 7u) == 0);

    static const char second[] =
        "15\r\n" OPERATOR_PASSWORD "\r\n"
        "*1\r\n$4\r\nPING\r\n"
        "*1\r\n$4\r\nPING\r\n";
    write_exact(args.client_fd, second, sizeof(second) - 1u);
    read_exact(args.client_fd, reply, 5u);
    if (memcmp(reply, "+OK\r\n", 5u) != 0)
        fprintf(stderr, "unexpected AUTH response: %.*s\n", 5, reply);
    assert(memcmp(reply, "+OK\r\n", 5u) == 0);
    read_exact(args.client_fd, reply, 14u);
    assert(memcmp(reply, "+PONG\r\n+PONG\r\n", 14u) == 0);

    write_exact(args.client_fd, "PING\r\nPI", 8u);
    read_exact(args.client_fd, reply, 7u);
    assert(memcmp(reply, "+PONG\r\n", 7u) == 0);
    write_exact(args.client_fd, "NG\r\n", 4u);
    read_exact(args.client_fd, reply, 7u);
    assert(memcmp(reply, "+PONG\r\n", 7u) == 0);

    close(args.client_fd);
    assert(pthread_join(thread, NULL) == 0);
}

static void test_bounds(qihse_kv_store_t* store, const char* request) {
    client_args_t args;
    pthread_t thread;
    start_client(&args, &thread, store);
    write_exact(args.client_fd, request, strlen(request));
    char reply[64] = {0};
    read_exact(args.client_fd, reply, 29u);
    assert(memcmp(reply, "-ERR malformed RESP request\r\n", 29u) == 0);
    close(args.client_fd);
    assert(pthread_join(thread, NULL) == 0);
}

typedef struct {
    int fd;
    size_t expected;
    size_t received;
} drain_args_t;

static void* drain_main(void* opaque) {
    drain_args_t* args = opaque;
    char buffer[4096];
    while (args->received < args->expected) {
        ssize_t n = recv(args->fd, buffer, sizeof(buffer), 0);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        args->received += (size_t)n;
    }
    return NULL;
}

static void test_write_all(void) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int small = 1024;
    assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &small,
                      sizeof(small)) == 0);
    char* payload = malloc(1u << 20);
    assert(payload);
    memset(payload, 'x', 1u << 20);
    drain_args_t drain = {.fd = sockets[1], .expected = 1u << 20};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, drain_main, &drain) == 0);
    assert(qihse_resp_wire_test_write_all(sockets[0], payload, 1u << 20));
    assert(pthread_join(thread, NULL) == 0);
    assert(drain.received == (1u << 20));
    free(payload);
    close(sockets[0]);
    close(sockets[1]);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    close(sockets[1]);
    assert(!qihse_resp_wire_test_write_all(sockets[0], "x", 1u));
    close(sockets[0]);
}

static void test_inline_arg_limit(qihse_kv_store_t* store) {
    client_args_t args; pthread_t thread;
    start_client(&args,&thread,store);
    char request[5000]; size_t used=0;
    for(unsigned i=0;i<2049;i++) { request[used++]='x'; request[used++]=' '; }
    request[used++]='\r'; request[used++]='\n';
    write_exact(args.client_fd,request,used);
    static const char expected[]="-ERR malformed inline request\r\n";
    char reply[sizeof(expected)]; read_exact(args.client_fd,reply,sizeof(expected)-1);
    assert(!memcmp(reply,expected,sizeof(expected)-1));
    close(args.client_fd); assert(pthread_join(thread,NULL)==0);
}

static void remove_test_dir(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) return;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char item[512];
        int n = snprintf(item, sizeof(item), "%s/%s", path, entry->d_name);
        assert(n > 0 && (size_t)n < sizeof(item));
        assert(unlink(item) == 0 || errno == ENOENT);
    }
    closedir(dir);
    assert(rmdir(path) == 0);
}

int main(void) {
    char data_dir[] = "build/resp-wire-framing-XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    test_split_pipeline(store);
    test_bounds(store, "*1\r\n$1048577\r\n");
    test_bounds(store, "*2049\r\n");
    test_inline_arg_limit(store);
    test_write_all();

    qihse_kv_store_destroy(store);
    qihse_auth_shutdown_rate_limiter();
    qihse_auth_shutdown_volume_limiter();
    qihse_audit_shutdown();
    remove_test_dir(data_dir);
    puts("test_resp_wire_framing: all assertions passed");
    return 0;
}
