#include "qihse_resp_wire.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int fd;
    unsigned char buffer[131072];
    size_t used;
} test_client_t;

typedef struct {
    qihse_resp_server_t* server;
    int fd;
} server_thread_arg_t;

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
    if (data[0] == '_') {
        if (len < 3u) return 0;
        if (data[1] != '\r' || data[2] != '\n') return -1;
        *consumed = 3u;
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
        ssize_t received = recv(client->fd, client->buffer + client->used, sizeof(client->buffer) - client->used, 0);
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

static void send_fragmented(int fd, const char* data, size_t len) {
    for (size_t i = 0; i < len; i++) send_all(fd, data + i, 1u);
}

static void send_command(int fd, size_t argc, const char* const* argv) {
    char header[64];
    int len = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    assert(len > 0);
    send_all(fd, header, (size_t)len);
    for (size_t i = 0; i < argc; i++) {
        size_t arg_len = strlen(argv[i]);
        len = snprintf(header, sizeof(header), "$%zu\r\n", arg_len);
        assert(len > 0);
        send_all(fd, header, (size_t)len);
        send_all(fd, argv[i], arg_len);
        send_all(fd, "\r\n", 2u);
    }
}

static int connect_local(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
    return fd;
}

static void* server_thread(void* argument) {
    server_thread_arg_t* args = (server_thread_arg_t*)argument;
    assert(qihse_resp_server_handle_client_fd(args->server, args->fd));
    return NULL;
}

static qihse_cluster_node_t node_from_seed(const char* seed, const char* host, uint16_t port) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
    snprintf(node.host, sizeof(node.host), "%s", host);
    node.port = port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = true;
    return node;
}

int main(void) {
    char data_dir[] = "/tmp/qihse-resp-test-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);

    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    qihse_column_store_t* columns = qihse_column_store_create();
    assert(store && vdb && tsdb && columns);

    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology != NULL);
    qihse_cluster_node_t local_node = node_from_seed("local", "127.0.0.1", 7000);
    qihse_cluster_node_t remote_node = node_from_seed("remote", "127.0.0.1", 7001);
    uint16_t local;
    uint16_t remote;
    assert(qihse_cluster_topology_upsert_node(topology, &local_node, &local));
    assert(qihse_cluster_topology_upsert_node(topology, &remote_node, &remote));
    assert(qihse_cluster_topology_set_local_node(topology, local));
    assert(qihse_cluster_topology_assign_range(topology, 0, 8191, local));
    assert(qihse_cluster_topology_assign_range(topology, 8192, 16383, remote));

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.tsdb = tsdb;
    config.column_store = columns;
    config.topology = topology;
    config.local_node_index = local;
    config.port = 0;
    config.auth_required = false;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    server_thread_arg_t args = { server, sockets[1] };
    pthread_t thread;
    assert(pthread_create(&thread, NULL, server_thread, &args) == 0);
    test_client_t client;
    memset(&client, 0, sizeof(client));
    client.fd = sockets[0];

    static const char ping[] = "*1\r\n$4\r\nPING\r\n";
    send_fragmented(client.fd, ping, sizeof(ping) - 1u);
    char* response = read_response(&client);
    assert(strcmp(response, "+PONG\r\n") == 0);
    free(response);

    static const char pipeline[] =
        "*3\r\n$3\r\nSET\r\n$3\r\nbar\r\n$5\r\nvalue\r\n"
        "*2\r\n$3\r\nGET\r\n$3\r\nbar\r\n"
        "*2\r\n$4\r\nPTTL\r\n$3\r\nbar\r\n";
    send_all(client.fd, pipeline, sizeof(pipeline) - 1u);
    response = read_response(&client);
    assert(strcmp(response, "+OK\r\n") == 0);
    free(response);
    response = read_response(&client);
    assert(strcmp(response, "$5\r\nvalue\r\n") == 0);
    free(response);
    response = read_response(&client);
    assert(strcmp(response, ":-1\r\n") == 0);
    free(response);

    static const char hot_get[] = "*2\r\n$3\r\nGET\r\n$3\r\nbar\r\n";
    for (size_t i = 0; i < 64u; i++) {
        send_all(client.fd, hot_get, sizeof(hot_get) - 1u);
        response = read_response(&client);
        assert(strcmp(response, "$5\r\nvalue\r\n") == 0);
        free(response);
    }
    assert(!qihse_kv_store_is_under_attack(store));

    static const char moved[] = "*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n";
    send_all(client.fd, moved, sizeof(moved) - 1u);
    response = read_response(&client);
    assert(strcmp(response, "-MOVED 12182 127.0.0.1:7001\r\n") == 0);
    free(response);

    static const char crossslot[] = "*3\r\n$4\r\nMGET\r\n$3\r\nbar\r\n$3\r\nfoo\r\n";
    send_all(client.fd, crossslot, sizeof(crossslot) - 1u);
    response = read_response(&client);
    assert(strncmp(response, "-CROSSSLOT ", 11u) == 0);
    free(response);

    static const char keyslot[] = "*3\r\n$7\r\nCLUSTER\r\n$7\r\nKEYSLOT\r\n$3\r\nfoo\r\n";
    send_all(client.fd, keyslot, sizeof(keyslot) - 1u);
    response = read_response(&client);
    assert(strcmp(response, ":12182\r\n") == 0);
    free(response);

    static const char slots[] = "*2\r\n$7\r\nCLUSTER\r\n$5\r\nSLOTS\r\n";
    send_all(client.fd, slots, sizeof(slots) - 1u);
    response = read_response(&client);
    assert(strncmp(response, "*2\r\n", 4u) == 0);
    assert(strstr(response, "$9\r\n127.0.0.1\r\n") != NULL);
    free(response);

    const char* command_info_args[] = { "COMMAND", "INFO", "SET", "MSET" };
    send_command(client.fd, 4u, command_info_args);
    response = read_response(&client);
    assert(strncmp(response, "*2\r\n", 4u) == 0);
    assert(strstr(response, "$3\r\nset\r\n") != NULL);
    assert(strstr(response, "$4\r\nmset\r\n") != NULL);
    free(response);
    const char* command_keys_args[] = { "COMMAND", "GETKEYS", "MSET", "{same}a", "1", "{same}b", "2" };
    send_command(client.fd, 7u, command_keys_args);
    response = read_response(&client);
    assert(strncmp(response, "*2\r\n", 4u) == 0);
    assert(strstr(response, "$7\r\n{same}a\r\n") != NULL);
    assert(strstr(response, "$7\r\n{same}b\r\n") != NULL);
    free(response);

    const char* vecset_args[] = { "VECSET", "1", "2", "1", "0", "TAG", "{bar}" };
    send_command(client.fd, 7u, vecset_args);
    response = read_response(&client);
    assert(strcmp(response, "+OK\r\n") == 0);
    free(response);
    const char* vecget_args[] = { "VECGET", "1", "TAG", "{bar}" };
    send_command(client.fd, 4u, vecget_args);
    response = read_response(&client);
    assert(strncmp(response, "*2\r\n", 4u) == 0);
    assert(strstr(response, "$1\r\n1\r\n") != NULL);
    free(response);
    const char* vecsearch_args[] = { "VECSEARCH", "2", "1", "1", "0", "TAG", "{bar}" };
    send_command(client.fd, 7u, vecsearch_args);
    response = read_response(&client);
    assert(strncmp(response, "*1\r\n", 4u) == 0);
    assert(strstr(response, ":1\r\n") != NULL);
    free(response);

    static const char ts_commands[] =
        "*4\r\n$6\r\nTS.ADD\r\n$11\r\n{bar}series\r\n$4\r\n1000\r\n$3\r\n1.5\r\n"
        "*4\r\n$6\r\nTS.ADD\r\n$11\r\n{bar}series\r\n$4\r\n2000\r\n$3\r\n3.5\r\n"
        "*5\r\n$8\r\nTS.RANGE\r\n$11\r\n{bar}series\r\n$1\r\n0\r\n$4\r\n3000\r\n$3\r\nAVG\r\n";
    send_all(client.fd, ts_commands, sizeof(ts_commands) - 1u);
    response = read_response(&client);
    assert(strcmp(response, ":1000\r\n") == 0);
    free(response);
    response = read_response(&client);
    assert(strcmp(response, ":2000\r\n") == 0);
    free(response);
    response = read_response(&client);
    assert(strcmp(response, "$3\r\n2.5\r\n") == 0);
    free(response);

    static const char column_commands[] =
        "*3\r\n$10\r\nCOL.APPEND\r\n$8\r\n{bar}col\r\n$3\r\n1.5\r\n"
        "*3\r\n$10\r\nCOL.APPEND\r\n$8\r\n{bar}col\r\n$3\r\n2.5\r\n"
        "*2\r\n$7\r\nCOL.SUM\r\n$8\r\n{bar}col\r\n";
    send_all(client.fd, column_commands, sizeof(column_commands) - 1u);
    response = read_response(&client);
    assert(strcmp(response, ":1\r\n") == 0);
    free(response);
    response = read_response(&client);
    assert(strcmp(response, ":1\r\n") == 0);
    free(response);
    response = read_response(&client);
    assert(strcmp(response, "$1\r\n4\r\n") == 0);
    free(response);

    uint16_t bar_slot = qihse_cluster_key_slot("bar", 3u);
    assert(qihse_cluster_topology_set_migrating(topology, bar_slot, local, remote));
    static const char ask[] = "*2\r\n$3\r\nGET\r\n$12\r\n{bar}missing\r\n";
    send_all(client.fd, ask, sizeof(ask) - 1u);
    response = read_response(&client);
    assert(strcmp(response, "-ASK 5061 127.0.0.1:7001\r\n") == 0);
    free(response);
    assert(qihse_cluster_topology_set_stable(topology, bar_slot, local));

    static const char hello[] = "*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n";
    send_all(client.fd, hello, sizeof(hello) - 1u);
    response = read_response(&client);
    assert(strncmp(response, "%7\r\n", 4u) == 0);
    free(response);

    static const char quit[] = "*1\r\n$4\r\nQUIT\r\n";
    send_all(client.fd, quit, sizeof(quit) - 1u);
    response = read_response(&client);
    assert(strcmp(response, "+OK\r\n") == 0);
    free(response);
    close(client.fd);
    pthread_join(thread, NULL);

    assert(qihse_resp_server_start(server));
    uint16_t bound_port = qihse_resp_server_port(server);
    assert(bound_port != 0);
    int tcp_client = socket(AF_INET, SOCK_STREAM, 0);
    assert(tcp_client >= 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(bound_port);
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(connect(tcp_client, (struct sockaddr*)&address, sizeof(address)) == 0);
    send_all(tcp_client, ping, sizeof(ping) - 1u);
    test_client_t tcp;
    memset(&tcp, 0, sizeof(tcp));
    tcp.fd = tcp_client;
    response = read_response(&tcp);
    assert(strcmp(response, "+PONG\r\n") == 0);
    free(response);
    qihse_resp_server_stop(server);
    close(tcp_client);

    qihse_kv_store_t* target_store = qihse_kv_store_create();
    qihse_cluster_topology_t* target_topology = qihse_cluster_topology_create();
    assert(target_store && target_topology);
    uint16_t target_source_index;
    uint16_t target_local_index;
    assert(qihse_cluster_topology_upsert_node(target_topology, &local_node, &target_source_index));
    assert(qihse_cluster_topology_upsert_node(target_topology, &remote_node, &target_local_index));
    assert(qihse_cluster_topology_set_local_node(target_topology, target_local_index));
    assert(qihse_cluster_topology_assign_range(target_topology, 0, 8191, target_source_index));
    assert(qihse_cluster_topology_assign_range(target_topology, 8192, 16383, target_local_index));
    qihse_resp_server_config_t target_config;
    qihse_resp_server_config_init(&target_config);
    target_config.store = target_store;
    target_config.topology = target_topology;
    target_config.local_node_index = target_local_index;
    target_config.port = 0;
    target_config.auth_required = false;
    qihse_resp_server_t* target_server = qihse_resp_server_create(&target_config);
    assert(target_server != NULL);
    assert(qihse_resp_server_start(target_server));
    assert(qihse_resp_server_start(server));
    uint16_t source_port = qihse_resp_server_port(server);
    uint16_t target_port = qihse_resp_server_port(target_server);

    qihse_cluster_node_t source_endpoint;
    qihse_cluster_node_t target_endpoint;
    assert(qihse_cluster_topology_get_node(topology, local, &source_endpoint));
    assert(qihse_cluster_topology_get_node(topology, remote, &target_endpoint));
    source_endpoint.port = source_port;
    target_endpoint.port = target_port;
    assert(qihse_cluster_topology_upsert_node(topology, &source_endpoint, NULL));
    assert(qihse_cluster_topology_upsert_node(topology, &target_endpoint, NULL));
    assert(qihse_cluster_topology_upsert_node(target_topology, &source_endpoint, NULL));
    assert(qihse_cluster_topology_upsert_node(target_topology, &target_endpoint, NULL));

    assert(qihse_cluster_topology_set_migrating(topology, bar_slot, local, remote));
    assert(qihse_cluster_topology_set_importing(target_topology, bar_slot, target_source_index, target_local_index));
    int source_client = connect_local(source_port);
    test_client_t migration_client;
    memset(&migration_client, 0, sizeof(migration_client));
    migration_client.fd = source_client;
    char target_port_text[16];
    snprintf(target_port_text, sizeof(target_port_text), "%u", target_port);
    const char* migrate_args[] = { "MIGRATE", "127.0.0.1", target_port_text, "bar", "0", "2000", "REPLACE" };
    send_command(source_client, sizeof(migrate_args) / sizeof(migrate_args[0]), migrate_args);
    response = read_response(&migration_client);
    assert(strcmp(response, "+OK\r\n") == 0);
    free(response);
    char* source_value = qihse_kv_get_user(store, "bar", NULL);
    char* target_value = qihse_kv_get_user(target_store, "bar", NULL);
    assert(source_value == NULL);
    assert(target_value && strcmp(target_value, "value") == 0);
    free(source_value);
    free(target_value);

    assert(qihse_cluster_topology_set_stable(topology, bar_slot, remote));
    assert(qihse_cluster_topology_set_stable(target_topology, bar_slot, target_local_index));
    int target_client = connect_local(target_port);
    test_client_t target_reader;
    memset(&target_reader, 0, sizeof(target_reader));
    target_reader.fd = target_client;
    const char* get_bar_args[] = { "GET", "bar" };
    send_command(target_client, 2u, get_bar_args);
    response = read_response(&target_reader);
    assert(strcmp(response, "$5\r\nvalue\r\n") == 0);
    free(response);
    send_command(source_client, 2u, get_bar_args);
    response = read_response(&migration_client);
    char expected_moved[128];
    snprintf(expected_moved, sizeof(expected_moved), "-MOVED 5061 127.0.0.1:%u\r\n", target_port);
    assert(strcmp(response, expected_moved) == 0);
    free(response);
    close(source_client);
    close(target_client);
    qihse_resp_server_stop(server);
    qihse_resp_server_stop(target_server);
    qihse_resp_server_destroy(target_server);
    qihse_cluster_topology_destroy(target_topology);
    qihse_kv_store_destroy(target_store);

    qihse_resp_server_destroy(server);
    qihse_cluster_topology_destroy(topology);
    qihse_column_store_destroy(columns);
    qihse_tsdb_destroy(tsdb);
    qihse_vector_db_destroy(vdb);
    qihse_kv_store_destroy(store);
    char path[512];
    snprintf(path, sizeof(path), "%s/wal.log", data_dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/wal.log.old", data_dir);
    unlink(path);
    rmdir(data_dir);
    printf("RESP cluster tests passed\n");
    return 0;
}
