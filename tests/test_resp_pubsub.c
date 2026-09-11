/* RESP pub/sub integration test: real fan-out through the broker, PUBSUB
 * introspection, pattern subscriptions, and durable delivery via the
 * qihse_event_stream_t log (replayed read-only to simulate restart). */
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
#include <sys/stat.h>
#include <unistd.h>

#include "qihse_event_stream.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

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

static bool count_record(const qihse_es_record_header_t* header, const uint8_t* payload,                         size_t payload_size, void* user_data) {
    (void)header;
    (void)payload;
    (void)payload_size;
    (*(size_t*)user_data)++;
    return true;
}

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

static char* read_reply(int fd) {
    size_t cap = 8192;
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    for (;;) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int ready = poll(&pfd, 1, 2000);
        assert(ready > 0);
        ssize_t received = read(fd, buffer + len, cap - len - 1);
        assert(received > 0);
        len += (size_t)received;
        buffer[len] = '\0';
        if (len >= 2 && buffer[len - 2] == '\r' && buffer[len - 1] == '\n') {
            struct pollfd again = { fd, POLLIN, 0 };
            if (poll(&again, 1, 100) <= 0) break;
        }
    }
    return buffer;
}

int main(void) {
    char data_dir[] = "/tmp/qihse-resp-pubsub-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    char pubsub_dir[512];
    snprintf(pubsub_dir, sizeof(pubsub_dir), "%s/pubsub", data_dir);

    assert(qihse_auth_init());
    /* The server assigns the operator as the unauthenticated-session user in
     * non-auth mode; bootstrap so qihse_auth_get_user(0) is non-NULL. */
    assert(qihse_auth_bootstrap_operator("PubsubBootstrap1!"));
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.port = 0;
    config.auth_required = false;
    config.pubsub_log_directory = pubsub_dir;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    test_client_t subscriber;
    test_client_t publisher;
    client_init(&subscriber, server);
    client_init(&publisher, server);

    /* Subscribe and check the confirmation. */
    const char* subscribe[] = { "SUBSCRIBE", "alerts" };
    send_command(subscriber.fd, 2, subscribe);
    char* reply = read_reply(subscriber.fd);

    assert(strstr(reply, "*3\r\n") == reply);
    assert(strstr(reply, "$9\r\nsubscribe\r\n$6\r\nalerts\r\n:1\r\n") != NULL);
    free(reply);

    /* Pattern subscription on a second channel. */
    const char* psubscribe[] = { "PSUBSCRIBE", "metric.*" };
    send_command(subscriber.fd, 2, psubscribe);
    reply = read_reply(subscriber.fd);
    assert(strstr(reply, "$10\r\npsubscribe\r\n$8\r\nmetric.*\r\n:2\r\n") != NULL);
    free(reply);

    /* Publish to the exact channel: subscriber receives both the message push
     * and the publisher gets a receiver count of 1. */
    const char* publish[] = { "PUBLISH", "alerts", "disk-full" };
    send_command(publisher.fd, 3, publish);
    reply = read_reply(publisher.fd);

    assert(strcmp(reply, ":1\r\n") == 0);
    free(reply);
    reply = read_reply(subscriber.fd);
    assert(strstr(reply, "*3\r\n$7\r\nmessage\r\n$6\r\nalerts\r\n$9\r\ndisk-full\r\n") != NULL);    free(reply);

    /* Publish matching the pattern. */
    const char* publish_pattern[] = { "PUBLISH", "metric.cpu", "0.91" };
    send_command(publisher.fd, 3, publish_pattern);
    reply = read_reply(publisher.fd);

    assert(strcmp(reply, ":1\r\n") == 0);
    free(reply);
    reply = read_reply(subscriber.fd);
    assert(strstr(reply, "*4\r\n$8\r\npmessage\r\n$8\r\nmetric.*\r\n$10\r\nmetric.cpu\r\n$4\r\n0.91\r\n") != NULL);
    free(reply);

    /* Publish with no matching subscriber returns 0. */
    const char* publish_empty[] = { "PUBLISH", "empty-channel", "void" };
    send_command(publisher.fd, 3, publish_empty);
    reply = read_reply(publisher.fd);
    assert(strcmp(reply, ":0\r\n") == 0);
    free(reply);

    /* PUBSUB introspection. */
    const char* channels_cmd[] = { "PUBSUB", "CHANNELS" };
    send_command(publisher.fd, 2, channels_cmd);
    reply = read_reply(publisher.fd);
    assert(strstr(reply, "*1\r\n$6\r\nalerts\r\n") != NULL);
    free(reply);
    const char* numsub_cmd[] = { "PUBSUB", "NUMSUB", "alerts" };
    send_command(publisher.fd, 3, numsub_cmd);
    reply = read_reply(publisher.fd);
    assert(strstr(reply, "$6\r\nalerts\r\n:1\r\n") != NULL);
    free(reply);
    const char* numpat_cmd[] = { "PUBSUB", "NUMPAT" };
    send_command(publisher.fd, 2, numpat_cmd);
    reply = read_reply(publisher.fd);
    assert(strcmp(reply, ":1\r\n") == 0);
    free(reply);

    /* Subscribed-mode restriction: GET is rejected on the subscriber. */
    const char* forbidden[] = { "GET", "key" };
    send_command(subscriber.fd, 2, forbidden);
    reply = read_reply(subscriber.fd);
    assert(strstr(reply, "ERR Can't execute 'GET'") != NULL);
    free(reply);

    /* Unsubscribe restores normal command processing. */
    const char* unsubscribe[] = { "UNSUBSCRIBE", "alerts" };
    send_command(subscriber.fd, 2, unsubscribe);
    reply = read_reply(subscriber.fd);
    assert(strstr(reply, "$11\r\nunsubscribe\r\n$6\r\nalerts\r\n:1\r\n") != NULL);
    free(reply);

    /* Durability: the pub/sub log recorded every publish; replay it
     * read-only to prove messages survive an independent open. */
    qihse_event_stream_t* log = qihse_event_stream_open(pubsub_dir, QIHSE_ES_DURABILITY_NONE, true);
    assert(log != NULL);
    size_t records = 0;
    qihse_event_stream_replay(log, "resp.pubsub", count_record, &records);
    assert(records >= 3u);
    qihse_event_stream_destroy(log);

    close(subscriber.fd);
    close(publisher.fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("test_resp_pubsub: all assertions passed\n");
    return 0;
}
