#include "qihse_resp_wire.h"
#include "qihse_resp_engine.h"
#include "qihse_resp_cluster.h"
#include "qihse_cluster_numa.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_failover.h"
#include "qihse_cluster_scatter.h"
#include "qihse_crc16.h"
#include "qihse_keystone.h"
#include "qihse_system_guard.h"
#include "qihse_platform.h"
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define QIHSE_RESP_MAX_ARGS 2048u
#define QIHSE_RESP_INITIAL_BUFFER 16384u
#define QIHSE_RESP_DEFAULT_MAX_REQUEST (16u * 1024u * 1024u)
#define QIHSE_RESP_DEFAULT_MAX_CLIENTS 1024u

typedef enum {
    QIHSE_RESP_PARSE_OK = 0,
    QIHSE_RESP_PARSE_MORE = 1,
    QIHSE_RESP_PARSE_ERROR = 2
} qihse_resp_parse_status_t;

typedef struct {
    size_t argc;
    qihse_resp_arg_t argv[QIHSE_RESP_MAX_ARGS];
    size_t consumed;
} qihse_resp_request_t;

typedef struct qihse_resp_client_ctx qihse_resp_client_ctx_t;

typedef struct {
    qihse_resp_server_t* server;
    int fd;
    qihse_user_t* user;
    uint64_t id;
    int protocol_version;
    bool asking;
    bool readonly;
    char name[128];
} qihse_resp_session_t;

struct qihse_resp_client_ctx {
    qihse_resp_server_t* server;
    int fd;
    qihse_resp_client_ctx_t* next;
};

struct qihse_resp_server {
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
    qihse_tsdb_t* tsdb;
    qihse_column_store_t* column_store;
    qihse_cluster_topology_t* topology;
    bool owns_topology;
    char bind_address[QIHSE_CLUSTER_HOST_LEN + 1u];
    char advertise_address[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t port;
    uint16_t bus_port;
    size_t max_clients;
    size_t max_request_bytes;
    bool auth_required;
    qihse_user_t unauthenticated_user;
    bool require_full_coverage;
    bool pin_workers;
    bool strict_hardware_affinity;
    int numa_node_id;
    int listen_fd;
    bool running;
    bool accept_thread_started;
    pthread_t accept_thread;
    pthread_mutex_t state_lock;
    pthread_cond_t clients_drained;
    qihse_resp_client_ctx_t* clients;
    size_t active_clients;
    uint64_t next_client_id;
    uint64_t next_worker;
    pthread_mutex_t kv_lock;
    pthread_mutex_t vdb_lock;
    pthread_mutex_t tsdb_lock;
    pthread_mutex_t column_lock;
    /* Phase 3: cluster bus + failover + guard throttling */
    qihse_cluster_bus_t* bus;
    qihse_cluster_failover_t* failover;
    qihse_system_guard_window_t* guard_window;
    bool owns_bus;
    bool owns_failover;
    bool owns_guard_window;
    /* Phase 4: scatter-gather engine */
    qihse_cluster_scatter_t* scatter;
    bool owns_scatter;
};

typedef struct {
    size_t indexes[QIHSE_RESP_MAX_ARGS];
    size_t count;
    bool kv_keys;
} qihse_resp_keyset_t;

typedef enum {
    QIHSE_COMMAND_WRITE = 1u << 0,
    QIHSE_COMMAND_READONLY = 1u << 1,
    QIHSE_COMMAND_ADMIN = 1u << 2,
    QIHSE_COMMAND_FAST = 1u << 3,
    QIHSE_COMMAND_DENYOOM = 1u << 4
} qihse_resp_command_flag_t;

typedef struct {
    const char* name;
    int arity;
    unsigned int flags;
    int first_key;
    int last_key;
    int key_step;
} qihse_resp_command_descriptor_t;

static const qihse_resp_command_descriptor_t g_qihse_resp_commands[] = {
    {"asking", 1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"auth", -2, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"client", -2, QIHSE_COMMAND_ADMIN, 0, 0, 0},
    {"cluster", -2, QIHSE_COMMAND_ADMIN, 0, 0, 0},
    {"col.append", 3, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, 1, 1},
    {"col.minmax", 2, QIHSE_COMMAND_READONLY, 1, 1, 1},
    {"col.sum", 2, QIHSE_COMMAND_READONLY, 1, 1, 1},
    {"command", -1, QIHSE_COMMAND_ADMIN, 0, 0, 0},
    {"decr", 2, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"del", -2, QIHSE_COMMAND_WRITE, 1, -1, 1},
    {"echo", 2, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"exists", -2, QIHSE_COMMAND_READONLY | QIHSE_COMMAND_FAST, 1, -1, 1},
    {"expire", 3, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"get", 2, QIHSE_COMMAND_READONLY | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"hello", -1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"incr", 2, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"info", -1, QIHSE_COMMAND_ADMIN, 0, 0, 0},
    {"mget", -2, QIHSE_COMMAND_READONLY, 1, -1, 1},
    {"migrate", -6, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_ADMIN, 3, 3, 1},
    {"mset", -3, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, -1, 2},
    {"pexpire", 3, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"ping", -1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"psetex", 4, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, 1, 1},
    {"pttl", 2, QIHSE_COMMAND_READONLY | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"quit", 1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"readonly", 1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"readwrite", 1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"role", 1, QIHSE_COMMAND_ADMIN, 0, 0, 0},
    {"select", 2, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"set", -3, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, 1, 1},
    {"setex", 4, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, 1, 1},
    {"ts.add", 4, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, 1, 1},
    {"ts.range", -4, QIHSE_COMMAND_READONLY, 1, 1, 1},
    {"ttl", 2, QIHSE_COMMAND_READONLY | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"type", 2, QIHSE_COMMAND_READONLY | QIHSE_COMMAND_FAST, 1, 1, 1},
    {"vecget", -2, QIHSE_COMMAND_READONLY, 1, 1, 1},
    {"vecscatter", -4, QIHSE_COMMAND_READONLY, 0, 0, 0},
    {"vecsearch", -4, QIHSE_COMMAND_READONLY, 0, 0, 0},
    {"vecset", -4, QIHSE_COMMAND_WRITE | QIHSE_COMMAND_DENYOOM, 1, 1, 1}
};

static uint64_t qihse_resp_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

static bool qihse_resp_copy_string(char* destination, size_t capacity, const char* source) {
    if (!destination || capacity == 0 || !source) return false;
    size_t len = strnlen(source, capacity);
    if (len >= capacity) return false;
    memcpy(destination, source, len + 1u);
    return true;
}

static bool qihse_resp_is_loopback(const char* address) {
    return address && (strcmp(address, "127.0.0.1") == 0 || strcmp(address, "::1") == 0 || strcmp(address, "localhost") == 0);
}

static bool qihse_resp_arg_equal(const qihse_resp_arg_t* arg, const char* text) {
    size_t len = strlen(text);
    if (!arg || arg->len != len) return false;
    for (size_t i = 0; i < len; i++) {
        if (toupper((unsigned char)arg->data[i]) != toupper((unsigned char)text[i])) return false;
    }
    return true;
}

static bool qihse_resp_find_crlf(const uint8_t* data, size_t len, size_t start, size_t* line_end) {
    if (!data || start > len) return false;
    for (size_t i = start; i + 1u < len; i++) {
        if (data[i] == '\r' && data[i + 1u] == '\n') {
            *line_end = i;
            return true;
        }
    }
    return false;
}

static bool qihse_resp_parse_i64_bytes(const uint8_t* data, size_t len, int64_t* out) {
    if (!data || !out || len == 0) return false;
    size_t index = 0;
    bool negative = false;
    if (data[index] == '-') {
        negative = true;
        index++;
        if (index == len) return false;
    } else if (data[index] == '+') {
        index++;
        if (index == len) return false;
    }
    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
    uint64_t value = 0;
    for (; index < len; index++) {
        if (data[index] < '0' || data[index] > '9') return false;
        unsigned int digit = (unsigned int)(data[index] - '0');
        if (value > (limit - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    if (negative) {
        *out = value == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)value;
    } else {
        *out = (int64_t)value;
    }
    return true;
}

static bool qihse_resp_parse_u64_arg(const qihse_resp_arg_t* arg, uint64_t* out) {
    int64_t value;
    if (!arg || !qihse_resp_parse_i64_bytes(arg->data, arg->len, &value) || value < 0) return false;
    *out = (uint64_t)value;
    return true;
}

static bool qihse_resp_parse_double_arg(const qihse_resp_arg_t* arg, double* out) {
    if (!arg || !out || arg->len == 0 || arg->len >= 128u || memchr(arg->data, '\0', arg->len)) return false;
    char buffer[128];
    memcpy(buffer, arg->data, arg->len);
    buffer[arg->len] = '\0';
    char* end = NULL;
    errno = 0;
    double value = strtod(buffer, &end);
    if (errno != 0 || end != buffer + arg->len || !isfinite(value)) return false;
    *out = value;
    return true;
}

static char* qihse_resp_arg_text(const qihse_resp_arg_t* arg) {
    if (!arg || arg->len == SIZE_MAX || memchr(arg->data, '\0', arg->len)) {
        errno = EINVAL;
        return NULL;
    }
    char* text = (char*)malloc(arg->len + 1u);
    if (!text) return NULL;
    memcpy(text, arg->data, arg->len);
    text[arg->len] = '\0';
    return text;
}

static qihse_resp_parse_status_t qihse_resp_parse_request(const uint8_t* data, size_t len, qihse_resp_request_t* request) {
    memset(request, 0, sizeof(*request));
    if (len == 0) return QIHSE_RESP_PARSE_MORE;
    if (data[0] != '*') {
        size_t end;
        if (!qihse_resp_find_crlf(data, len, 0, &end)) return QIHSE_RESP_PARSE_MORE;
        size_t cursor = 0;
        while (cursor < end) {
            while (cursor < end && (data[cursor] == ' ' || data[cursor] == '\t')) cursor++;
            if (cursor == end) break;
            if (request->argc == QIHSE_RESP_MAX_ARGS) return QIHSE_RESP_PARSE_ERROR;
            size_t start = cursor;
            while (cursor < end && data[cursor] != ' ' && data[cursor] != '\t') cursor++;
            request->argv[request->argc].data = data + start;
            request->argv[request->argc].len = cursor - start;
            request->argc++;
        }
        request->consumed = end + 2u;
        return QIHSE_RESP_PARSE_OK;
    }

    size_t line_end;
    if (!qihse_resp_find_crlf(data, len, 1u, &line_end)) return QIHSE_RESP_PARSE_MORE;
    int64_t argc_value;
    if (!qihse_resp_parse_i64_bytes(data + 1u, line_end - 1u, &argc_value) || argc_value < 0 || argc_value > (int64_t)QIHSE_RESP_MAX_ARGS) {
        return QIHSE_RESP_PARSE_ERROR;
    }
    request->argc = (size_t)argc_value;
    size_t cursor = line_end + 2u;
    for (size_t i = 0; i < request->argc; i++) {
        if (cursor >= len) return QIHSE_RESP_PARSE_MORE;
        if (data[cursor] != '$') return QIHSE_RESP_PARSE_ERROR;
        if (!qihse_resp_find_crlf(data, len, cursor + 1u, &line_end)) return QIHSE_RESP_PARSE_MORE;
        int64_t bulk_len;
        if (!qihse_resp_parse_i64_bytes(data + cursor + 1u, line_end - cursor - 1u, &bulk_len) || bulk_len < 0) {
            return QIHSE_RESP_PARSE_ERROR;
        }
        cursor = line_end + 2u;
        if ((uint64_t)bulk_len > SIZE_MAX - cursor - 2u) return QIHSE_RESP_PARSE_ERROR;
        size_t value_len = (size_t)bulk_len;
        if (cursor + value_len + 2u > len) return QIHSE_RESP_PARSE_MORE;
        if (data[cursor + value_len] != '\r' || data[cursor + value_len + 1u] != '\n') return QIHSE_RESP_PARSE_ERROR;
        request->argv[i].data = data + cursor;
        request->argv[i].len = value_len;
        cursor += value_len + 2u;
    }
    request->consumed = cursor;
    return QIHSE_RESP_PARSE_OK;
}

static bool qihse_resp_write(qihse_resp_session_t* session, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    size_t written = 0;
    while (written < len) {
#ifdef MSG_NOSIGNAL
        ssize_t result = send(session->fd, bytes + written, len - written, MSG_NOSIGNAL);
#else
        ssize_t result = send(session->fd, (const char*)bytes + written, len - written, 0);
#endif
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (result == 0) return false;
        written += (size_t)result;
    }
    return true;
}

static bool qihse_resp_cluster_output(void* context, const void* data, size_t len) {
    return qihse_resp_write((qihse_resp_session_t*)context, data, len);
}

static bool qihse_resp_simple(qihse_resp_session_t* session, const char* value) {
    return qihse_resp_write(session, "+", 1u) && qihse_resp_write(session, value, strlen(value)) && qihse_resp_write(session, "\r\n", 2u);
}

static bool qihse_resp_error(qihse_resp_session_t* session, const char* value) {
    return qihse_resp_write(session, "-", 1u) && qihse_resp_write(session, value, strlen(value)) && qihse_resp_write(session, "\r\n", 2u);
}

static bool qihse_resp_integer(qihse_resp_session_t* session, int64_t value) {
    char buffer[64];
    int len = snprintf(buffer, sizeof(buffer), ":%" PRId64 "\r\n", value);
    return len > 0 && (size_t)len < sizeof(buffer) && qihse_resp_write(session, buffer, (size_t)len);
}

static bool qihse_resp_array(qihse_resp_session_t* session, size_t count) {
    char buffer[64];
    int len = snprintf(buffer, sizeof(buffer), "*%zu\r\n", count);
    return len > 0 && (size_t)len < sizeof(buffer) && qihse_resp_write(session, buffer, (size_t)len);
}

static bool qihse_resp_bulk(qihse_resp_session_t* session, const void* data, size_t len) {
    char header[64];
    int header_len = snprintf(header, sizeof(header), "$%zu\r\n", len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) return false;
    return qihse_resp_write(session, header, (size_t)header_len) &&
           (len == 0 || qihse_resp_write(session, data, len)) &&
           qihse_resp_write(session, "\r\n", 2u);
}

static bool qihse_resp_bulk_text(qihse_resp_session_t* session, const char* text) {
    return qihse_resp_bulk(session, text, strlen(text));
}

static bool qihse_resp_null(qihse_resp_session_t* session) {
    return qihse_resp_write(session, session->protocol_version == 3 ? "_\r\n" : "$-1\r\n", session->protocol_version == 3 ? 3u : 5u);
}

static bool qihse_resp_wrong_arity(qihse_resp_session_t* session, const char* command) {
    char buffer[256];
    int len = snprintf(buffer, sizeof(buffer), "ERR wrong number of arguments for '%s' command", command);
    if (len <= 0 || (size_t)len >= sizeof(buffer)) return qihse_resp_error(session, "ERR wrong number of arguments");
    return qihse_resp_error(session, buffer);
}

static bool qihse_resp_reply_double(qihse_resp_session_t* session, double value) {
    char buffer[64];
    int len = snprintf(buffer, sizeof(buffer), "%.17g", value);
    return len > 0 && (size_t)len < sizeof(buffer) && qihse_resp_bulk(session, buffer, (size_t)len);
}

static bool qihse_resp_command_is(const qihse_resp_request_t* request, const char* command) {
    return request->argc > 0 && qihse_resp_arg_equal(&request->argv[0], command);
}

static bool qihse_resp_extract_keys(const qihse_resp_request_t* request, qihse_resp_keyset_t* keys) {
    memset(keys, 0, sizeof(*keys));
    if (request->argc < 2) return true;
    if (qihse_resp_command_is(request, "GET") || qihse_resp_command_is(request, "SET") ||
        qihse_resp_command_is(request, "EXPIRE") || qihse_resp_command_is(request, "PEXPIRE") ||
        qihse_resp_command_is(request, "TTL") || qihse_resp_command_is(request, "PTTL") ||
        qihse_resp_command_is(request, "INCR") || qihse_resp_command_is(request, "DECR") ||
        qihse_resp_command_is(request, "TYPE") || qihse_resp_command_is(request, "SETEX") ||
        qihse_resp_command_is(request, "PSETEX")) {
        keys->indexes[keys->count++] = 1u;
        keys->kv_keys = true;
    } else if (qihse_resp_command_is(request, "DEL") || qihse_resp_command_is(request, "EXISTS") ||
               qihse_resp_command_is(request, "MGET")) {
        for (size_t i = 1; i < request->argc; i++) keys->indexes[keys->count++] = i;
        keys->kv_keys = true;
    } else if (qihse_resp_command_is(request, "MSET")) {
        for (size_t i = 1; i + 1u < request->argc; i += 2u) keys->indexes[keys->count++] = i;
        keys->kv_keys = true;
    } else if (qihse_resp_command_is(request, "VECSET") || qihse_resp_command_is(request, "VECGET")) {
        size_t selected = 1u;
        for (size_t i = 2; i + 1u < request->argc; i++) {
            if (qihse_resp_arg_equal(&request->argv[i], "TAG")) selected = i + 1u;
        }
        keys->indexes[keys->count++] = selected;
    } else if (qihse_resp_command_is(request, "VECSEARCH")) {
        for (size_t i = 1; i + 1u < request->argc; i++) {
            if (qihse_resp_arg_equal(&request->argv[i], "TAG")) {
                keys->indexes[keys->count++] = i + 1u;
                break;
            }
        }
    } else if (qihse_resp_command_is(request, "MIGRATE") && request->argc >= 6) {
        if (request->argv[3].len > 0) {
            keys->indexes[keys->count++] = 3u;
        } else {
            for (size_t i = 6; i < request->argc; i++) {
                if (qihse_resp_arg_equal(&request->argv[i], "KEYS")) {
                    for (size_t key = i + 1u; key < request->argc; key++) keys->indexes[keys->count++] = key;
                    break;
                }
            }
        }
        keys->kv_keys = true;
    } else if (qihse_resp_command_is(request, "TS.ADD") || qihse_resp_command_is(request, "TS.RANGE") ||
               qihse_resp_command_is(request, "COL.APPEND") || qihse_resp_command_is(request, "COL.SUM") ||
               qihse_resp_command_is(request, "COL.MINMAX")) {
        keys->indexes[keys->count++] = 1u;
    }
    return true;
}

static bool qihse_resp_endpoint(const qihse_cluster_node_t* node, char* output, size_t capacity) {
    int len;
    if (strchr(node->host, ':')) len = snprintf(output, capacity, "[%s]:%u", node->host, node->port);
    else len = snprintf(output, capacity, "%s:%u", node->host, node->port);
    return len > 0 && (size_t)len < capacity;
}

static bool qihse_resp_route(qihse_resp_session_t* session, const qihse_resp_request_t* request, const qihse_resp_keyset_t* keys) {
    if (keys->count == 0) return true;
    qihse_resp_server_t* server = session->server;
    uint16_t slot = qihse_cluster_key_slot(request->argv[keys->indexes[0]].data, request->argv[keys->indexes[0]].len);
    for (size_t i = 1; i < keys->count; i++) {
        uint16_t next_slot = qihse_cluster_key_slot(request->argv[keys->indexes[i]].data, request->argv[keys->indexes[i]].len);
        if (next_slot != slot) {
            session->asking = false;
            qihse_resp_error(session, "CROSSSLOT Keys in request don't hash to the same slot");
            return false;
        }
    }
    if (server->require_full_coverage && !qihse_cluster_topology_is_covered(server->topology)) {
        session->asking = false;
        qihse_resp_error(session, "CLUSTERDOWN Hash slot not served");
        return false;
    }

    uint16_t owner;
    uint16_t peer;
    qihse_cluster_slot_state_t state;
    qihse_cluster_topology_get_slot(server->topology, slot, &owner, &state, &peer);
    uint16_t local = qihse_cluster_topology_local_node(server->topology);
    bool any_exists = false;
    bool all_exist = false;
    if (keys->kv_keys && owner == local && state != QIHSE_CLUSTER_SLOT_STABLE && server->store) {
        all_exist = true;
        pthread_mutex_lock(&server->kv_lock);
        for (size_t i = 0; i < keys->count; i++) {
            char* key = qihse_resp_arg_text(&request->argv[keys->indexes[i]]);
            bool exists = key && qihse_kv_exists_user(server->store, key, session->user);
            free(key);
            any_exists = any_exists || exists;
            all_exist = all_exist && exists;
        }
        pthread_mutex_unlock(&server->kv_lock);
        if (any_exists && !all_exist) {
            session->asking = false;
            qihse_resp_error(session, "TRYAGAIN Multiple keys request during rehashing of slot");
            return false;
        }
    }
    qihse_cluster_route_t route = qihse_cluster_topology_route(server->topology, slot, session->asking, all_exist);
    session->asking = false;
    if (route.decision == QIHSE_CLUSTER_ROUTE_LOCAL) return true;
    if (route.decision == QIHSE_CLUSTER_ROUTE_UNASSIGNED || route.decision == QIHSE_CLUSTER_ROUTE_NODE_DOWN) {
        qihse_resp_error(session, "CLUSTERDOWN The cluster is down");
        return false;
    }
    qihse_cluster_node_t target;
    if (!qihse_cluster_topology_get_node(server->topology, route.target_index, &target)) {
        qihse_resp_error(session, "CLUSTERDOWN Redirect target unavailable");
        return false;
    }
    char endpoint[QIHSE_CLUSTER_HOST_LEN + 32u];
    char response[QIHSE_CLUSTER_HOST_LEN + 96u];
    if (!qihse_resp_endpoint(&target, endpoint, sizeof(endpoint))) {
        qihse_resp_error(session, "CLUSTERDOWN Invalid redirect target");
        return false;
    }
    int len = snprintf(response, sizeof(response), "%s %u %s", route.decision == QIHSE_CLUSTER_ROUTE_ASK ? "ASK" : "MOVED", slot, endpoint);
    if (len <= 0 || (size_t)len >= sizeof(response)) qihse_resp_error(session, "CLUSTERDOWN Invalid redirect target");
    else qihse_resp_error(session, response);
    return false;
}

static bool qihse_resp_authenticate(qihse_resp_session_t* session, const qihse_resp_arg_t* username, const qihse_resp_arg_t* password, bool* authenticated) {
    *authenticated = false;
    char* user_text = qihse_resp_arg_text(username);
    char* password_text = qihse_resp_arg_text(password);
    if (!user_text || !password_text) {
        free(user_text);
        free(password_text);
        return qihse_resp_error(session, "ERR invalid credentials");
    }
    qihse_user_t* user = qihse_auth_authenticate(user_text, password_text);
    free(user_text);
    free(password_text);
    if (!user) return qihse_resp_error(session, "WRONGPASS invalid username-password pair or user is disabled.");
    session->user = user;
    *authenticated = true;
    return true;
}

static bool qihse_resp_handle_auth(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    bool authenticated = false;
    bool response;
    if (request->argc == 2) {
        static const uint8_t default_user[] = "GODMODE_OP";
        qihse_resp_arg_t username = { default_user, sizeof(default_user) - 1u };
        response = qihse_resp_authenticate(session, &username, &request->argv[1], &authenticated);
    } else if (request->argc == 3) {
        response = qihse_resp_authenticate(session, &request->argv[1], &request->argv[2], &authenticated);
    } else {
        return qihse_resp_wrong_arity(session, "auth");
    }
    if (!response || !authenticated) return response;
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_hello(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    int protocol = session->protocol_version;
    size_t cursor = 1u;
    if (cursor < request->argc) {
        uint64_t parsed;
        if (!qihse_resp_parse_u64_arg(&request->argv[cursor], &parsed) || (parsed != 2u && parsed != 3u)) {
            return qihse_resp_error(session, "NOPROTO unsupported protocol version");
        }
        protocol = (int)parsed;
        cursor++;
    }
    while (cursor < request->argc) {
        if (qihse_resp_arg_equal(&request->argv[cursor], "AUTH") && cursor + 2u < request->argc) {
            bool authenticated;
            if (!qihse_resp_authenticate(session, &request->argv[cursor + 1u], &request->argv[cursor + 2u], &authenticated)) return false;
            if (!authenticated) return true;
            cursor += 3u;
        } else if (qihse_resp_arg_equal(&request->argv[cursor], "SETNAME") && cursor + 1u < request->argc) {
            size_t len = request->argv[cursor + 1u].len;
            if (len >= sizeof(session->name) || memchr(request->argv[cursor + 1u].data, '\0', len)) return qihse_resp_error(session, "ERR Client names cannot contain special characters");
            memcpy(session->name, request->argv[cursor + 1u].data, len);
            session->name[len] = '\0';
            cursor += 2u;
        } else {
            return qihse_resp_error(session, "ERR Syntax error in HELLO option");
        }
    }
    if (session->server->auth_required && !session->user) return qihse_resp_error(session, "NOAUTH HELLO must be called with the client already authenticated, otherwise the HELLO AUTH <user> <pass> option can be used to authenticate the client and select the RESP protocol version at the same time");
    session->protocol_version = protocol;
    qihse_cluster_node_t local_node;
    bool replica = qihse_cluster_topology_get_node(session->server->topology, qihse_cluster_topology_local_node(session->server->topology), &local_node) && local_node.role == QIHSE_CLUSTER_NODE_REPLICA;
    if (protocol == 3) {
        if (!qihse_resp_write(session, "%7\r\n", 4u)) return false;
    } else if (!qihse_resp_array(session, 14u)) return false;
    return qihse_resp_bulk_text(session, "server") && qihse_resp_bulk_text(session, "qihse") &&
           qihse_resp_bulk_text(session, "version") && qihse_resp_bulk_text(session, "0.1.0") &&
           qihse_resp_bulk_text(session, "proto") && qihse_resp_integer(session, protocol) &&
           qihse_resp_bulk_text(session, "id") && qihse_resp_integer(session, (int64_t)session->id) &&
           qihse_resp_bulk_text(session, "mode") && qihse_resp_bulk_text(session, "cluster") &&
           qihse_resp_bulk_text(session, "role") && qihse_resp_bulk_text(session, replica ? "slave" : "master") &&
           qihse_resp_bulk_text(session, "modules") && qihse_resp_array(session, 0u);
}

static bool qihse_resp_handle_client_command(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "client");
    if (qihse_resp_arg_equal(&request->argv[1], "SETNAME")) {
        if (request->argc != 3 || request->argv[2].len >= sizeof(session->name) || memchr(request->argv[2].data, '\0', request->argv[2].len)) return qihse_resp_error(session, "ERR invalid client name");
        memcpy(session->name, request->argv[2].data, request->argv[2].len);
        session->name[request->argv[2].len] = '\0';
        return qihse_resp_simple(session, "OK");
    }
    if (qihse_resp_arg_equal(&request->argv[1], "GETNAME")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "client|getname");
        return session->name[0] ? qihse_resp_bulk_text(session, session->name) : qihse_resp_null(session);
    }
    if (qihse_resp_arg_equal(&request->argv[1], "ID")) return request->argc == 2 ? qihse_resp_integer(session, (int64_t)session->id) : qihse_resp_wrong_arity(session, "client|id");
    if (qihse_resp_arg_equal(&request->argv[1], "SETINFO")) return request->argc == 4 ? qihse_resp_simple(session, "OK") : qihse_resp_wrong_arity(session, "client|setinfo");
    return qihse_resp_error(session, "ERR unknown subcommand or wrong number of arguments for 'CLIENT'");
}

static const qihse_resp_command_descriptor_t* qihse_resp_find_command(const qihse_resp_arg_t* name) {
    for (size_t i = 0; i < sizeof(g_qihse_resp_commands) / sizeof(g_qihse_resp_commands[0]); i++) {
        if (qihse_resp_arg_equal(name, g_qihse_resp_commands[i].name)) return &g_qihse_resp_commands[i];
    }
    return NULL;
}

static bool qihse_resp_command_metadata(qihse_resp_session_t* session, const qihse_resp_command_descriptor_t* command) {
    size_t flag_count = 0;
    if (command->flags & QIHSE_COMMAND_WRITE) flag_count++;
    if (command->flags & QIHSE_COMMAND_READONLY) flag_count++;
    if (command->flags & QIHSE_COMMAND_ADMIN) flag_count++;
    if (command->flags & QIHSE_COMMAND_FAST) flag_count++;
    if (command->flags & QIHSE_COMMAND_DENYOOM) flag_count++;
    if (!qihse_resp_array(session, 6u) || !qihse_resp_bulk_text(session, command->name) ||
        !qihse_resp_integer(session, command->arity) || !qihse_resp_array(session, flag_count)) return false;
    if ((command->flags & QIHSE_COMMAND_WRITE) && !qihse_resp_bulk_text(session, "write")) return false;
    if ((command->flags & QIHSE_COMMAND_READONLY) && !qihse_resp_bulk_text(session, "readonly")) return false;
    if ((command->flags & QIHSE_COMMAND_ADMIN) && !qihse_resp_bulk_text(session, "admin")) return false;
    if ((command->flags & QIHSE_COMMAND_FAST) && !qihse_resp_bulk_text(session, "fast")) return false;
    if ((command->flags & QIHSE_COMMAND_DENYOOM) && !qihse_resp_bulk_text(session, "denyoom")) return false;
    return qihse_resp_integer(session, command->first_key) && qihse_resp_integer(session, command->last_key) && qihse_resp_integer(session, command->key_step);
}

static bool qihse_resp_handle_command(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t command_count = sizeof(g_qihse_resp_commands) / sizeof(g_qihse_resp_commands[0]);
    if (request->argc == 1) {
        if (!qihse_resp_array(session, command_count)) return false;
        for (size_t i = 0; i < command_count; i++) {
            if (!qihse_resp_command_metadata(session, &g_qihse_resp_commands[i])) return false;
        }
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "COUNT")) {
        return request->argc == 2 ? qihse_resp_integer(session, (int64_t)command_count) : qihse_resp_wrong_arity(session, "command|count");
    }
    if (qihse_resp_arg_equal(&request->argv[1], "LIST")) {
        if (request->argc != 2) return qihse_resp_error(session, "ERR syntax error");
        if (!qihse_resp_array(session, command_count)) return false;
        for (size_t i = 0; i < command_count; i++) {
            if (!qihse_resp_bulk_text(session, g_qihse_resp_commands[i].name)) return false;
        }
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "INFO")) {
        if (request->argc < 3) return qihse_resp_wrong_arity(session, "command|info");
        if (!qihse_resp_array(session, request->argc - 2u)) return false;
        for (size_t i = 2; i < request->argc; i++) {
            const qihse_resp_command_descriptor_t* command = qihse_resp_find_command(&request->argv[i]);
            if (command) {
                if (!qihse_resp_command_metadata(session, command)) return false;
            } else if (!qihse_resp_null(session)) {
                return false;
            }
        }
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "GETKEYS")) {
        if (request->argc < 3) return qihse_resp_wrong_arity(session, "command|getkeys");
        const qihse_resp_command_descriptor_t* command = qihse_resp_find_command(&request->argv[2]);
        size_t target_argc = request->argc - 2u;
        if (!command || (command->arity > 0 && target_argc != (size_t)command->arity) ||
            (command->arity < 0 && target_argc < (size_t)(-command->arity))) return qihse_resp_error(session, "ERR Invalid arguments specified for command");
        if (command->first_key <= 0 || command->key_step <= 0) return qihse_resp_error(session, "ERR The command has no key arguments");
        int last = command->last_key < 0 ? (int)target_argc + command->last_key : command->last_key;
        if (last < command->first_key || last >= (int)target_argc) return qihse_resp_error(session, "ERR Invalid arguments specified for command");
        size_t key_count = (size_t)((last - command->first_key) / command->key_step + 1);
        if (!qihse_resp_array(session, key_count)) return false;
        for (int position = command->first_key; position <= last; position += command->key_step) {
            const qihse_resp_arg_t* key = &request->argv[2u + (size_t)position];
            if (!qihse_resp_bulk(session, key->data, key->len)) return false;
        }
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "DOCS")) return session->protocol_version == 3 ? qihse_resp_write(session, "%0\r\n", 4u) : qihse_resp_array(session, 0u);
    return qihse_resp_error(session, "ERR unknown subcommand");
}

static bool qihse_resp_handle_info(qihse_resp_session_t* session) {
    qihse_resp_server_t* server = session->server;
    size_t nodes = qihse_cluster_topology_nodes(server->topology, NULL, 0u);
    size_t assigned = qihse_cluster_topology_assigned_slots(server->topology);
    pthread_mutex_lock(&server->state_lock);
    size_t active_clients = server->active_clients;
    pthread_mutex_unlock(&server->state_lock);
    char info[2048];
    int len = snprintf(info, sizeof(info),
                       "# Server\r\nredis_version:7.2.0\r\nredis_mode:cluster\r\nqihse_version:0.1.0\r\n"
                       "# Clients\r\nconnected_clients:%zu\r\n"
                       "# Cluster\r\ncluster_enabled:1\r\ncluster_known_nodes:%zu\r\ncluster_slots_assigned:%zu\r\n"
                       "qihse_crc16_backend:%s\r\n",
                       active_clients, nodes, assigned, qihse_crc16_backend_name());
    return len > 0 && (size_t)len < sizeof(info) && qihse_resp_bulk(session, info, (size_t)len);
}

static bool qihse_resp_handle_get(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "get");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR keys containing NUL bytes are not supported by this storage backend");
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    bool under_attack = qihse_kv_store_is_under_attack(session->server->store);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    if (under_attack) {
        free(value);
        return qihse_resp_error(session, "ERR request rejected by QIHSE defense policy");
    }
    bool result = value ? qihse_resp_bulk_text(session, value) : qihse_resp_null(session);
    free(value);
    return result;
}

static bool qihse_resp_handle_set(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "set");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    bool nx = false;
    bool xx = false;
    bool return_old = false;
    uint64_t ttl_ms = 0;
    bool has_ttl = false;
    for (size_t i = 3; i < request->argc; i++) {
        if (qihse_resp_arg_equal(&request->argv[i], "NX")) nx = true;
        else if (qihse_resp_arg_equal(&request->argv[i], "XX")) xx = true;
        else if (qihse_resp_arg_equal(&request->argv[i], "GET")) return_old = true;
        else if ((qihse_resp_arg_equal(&request->argv[i], "EX") || qihse_resp_arg_equal(&request->argv[i], "PX")) && i + 1u < request->argc) {
            bool seconds = qihse_resp_arg_equal(&request->argv[i], "EX");
            uint64_t value;
            if (!qihse_resp_parse_u64_arg(&request->argv[++i], &value) || value == 0 || (seconds && value > UINT64_MAX / 1000u)) return qihse_resp_error(session, "ERR invalid expire time in 'set' command");
            ttl_ms = seconds ? value * 1000u : value;
            has_ttl = true;
        } else {
            return qihse_resp_error(session, "ERR syntax error");
        }
    }
    if (nx && xx) return qihse_resp_error(session, "ERR syntax error");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* value = qihse_resp_arg_text(&request->argv[2]);
    if (!key || !value) {
        free(key);
        free(value);
        return qihse_resp_error(session, "ERR keys and values containing NUL bytes are not supported by this storage backend");
    }
    if (!qihse_system_guard_check_operation(request->argv[1].len + request->argv[2].len, false)) {
        free(key);
        free(value);
        return qihse_resp_error(session, "OOM command not allowed by QIHSE system guard");
    }
    pthread_mutex_lock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, key, session->user);
    char* old = return_old && exists ? qihse_kv_get_user(session->server->store, key, session->user) : NULL;
    bool condition = (!nx || !exists) && (!xx || exists);
    bool stored = condition && qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user);
    if (stored && has_ttl) stored = qihse_kv_expire(session->server->store, key, ttl_ms, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    free(value);
    if (!condition) {
        free(old);
        return qihse_resp_null(session);
    }
    if (!stored) {
        free(old);
        return qihse_resp_error(session, "ERR set failed");
    }
    bool result = return_old ? (old ? qihse_resp_bulk_text(session, old) : qihse_resp_null(session)) : qihse_resp_simple(session, "OK");
    free(old);
    return result;
}

static bool qihse_resp_handle_setex(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool milliseconds) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, milliseconds ? "psetex" : "setex");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    uint64_t ttl;
    if (!qihse_resp_parse_u64_arg(&request->argv[2], &ttl) || ttl == 0 || (!milliseconds && ttl > UINT64_MAX / 1000u)) return qihse_resp_error(session, "ERR invalid expire time");
    if (!milliseconds) ttl *= 1000u;
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* value = qihse_resp_arg_text(&request->argv[3]);
    if (!key || !value) {
        free(key);
        free(value);
        return qihse_resp_error(session, "ERR keys and values containing NUL bytes are not supported by this storage backend");
    }
    pthread_mutex_lock(&session->server->kv_lock);
    bool stored = qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user) &&
                  qihse_kv_expire(session->server->store, key, ttl, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    free(value);
    return stored ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR set failed");
}

static bool qihse_resp_handle_del_exists(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool remove) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, remove ? "del" : "exists");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    int64_t count = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 1; i < request->argc; i++) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        if (!key) continue;
        count += remove ? qihse_kv_del_user(session->server->store, key, session->user) : qihse_kv_exists_user(session->server->store, key, session->user);
        free(key);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    return qihse_resp_integer(session, count);
}

static bool qihse_resp_handle_mget(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "mget");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    size_t count = request->argc - 1u;
    char** values = (char**)calloc(count, sizeof(*values));
    if (!values) return qihse_resp_error(session, "OOM out of memory");
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 0; i < count; i++) {
        char* key = qihse_resp_arg_text(&request->argv[i + 1u]);
        if (key) values[i] = qihse_kv_get_user(session->server->store, key, session->user);
        free(key);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    bool result = qihse_resp_array(session, count);
    for (size_t i = 0; result && i < count; i++) result = values[i] ? qihse_resp_bulk_text(session, values[i]) : qihse_resp_null(session);
    for (size_t i = 0; i < count; i++) free(values[i]);
    free(values);
    return result;
}

static bool qihse_resp_handle_mset(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3 || (request->argc & 1u) == 0) return qihse_resp_wrong_arity(session, "mset");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    size_t text_count = request->argc - 1u;
    char** text = (char**)calloc(text_count, sizeof(*text));
    if (!text) return qihse_resp_error(session, "OOM out of memory");
    bool valid = true;
    for (size_t i = 0; i < text_count; i++) {
        text[i] = qihse_resp_arg_text(&request->argv[i + 1u]);
        if (!text[i]) valid = false;
    }
    bool stored = valid;
    if (valid) {
        pthread_mutex_lock(&session->server->kv_lock);
        for (size_t i = 0; i < text_count; i += 2u) {
            if (!qihse_kv_set_user(session->server->store, text[i], text[i + 1u], 0, 0, session->user)) {
                stored = false;
                break;
            }
        }
        pthread_mutex_unlock(&session->server->kv_lock);
    }
    for (size_t i = 0; i < text_count; i++) free(text[i]);
    free(text);
    if (!valid) return qihse_resp_error(session, "ERR keys and values containing NUL bytes are not supported by this storage backend");
    return stored ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR mset failed");
}

static bool qihse_resp_handle_expiry(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool milliseconds) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, milliseconds ? "pexpire" : "expire");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    uint64_t ttl;
    if (!qihse_resp_parse_u64_arg(&request->argv[2], &ttl) || (!milliseconds && ttl > UINT64_MAX / 1000u)) return qihse_resp_error(session, "ERR value is not an integer or out of range");
    if (!milliseconds) ttl *= 1000u;
    char* key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR invalid key");
    pthread_mutex_lock(&session->server->kv_lock);
    bool result = qihse_kv_expire(session->server->store, key, ttl, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, result ? 1 : 0);
}

static bool qihse_resp_handle_ttl(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool milliseconds) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, milliseconds ? "pttl" : "ttl");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR invalid key");
    pthread_mutex_lock(&session->server->kv_lock);
    int64_t ttl = qihse_kv_ttl_ms_user(session->server->store, key, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    if (!milliseconds && ttl >= 0) ttl /= 1000;
    return qihse_resp_integer(session, ttl);
}

static bool qihse_resp_handle_increment(qihse_resp_session_t* session, const qihse_resp_request_t* request, int delta) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, delta > 0 ? "incr" : "decr");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR invalid key");
    pthread_mutex_lock(&session->server->kv_lock);
    char* current = qihse_kv_get_user(session->server->store, key, session->user);
    int64_t value = 0;
    bool valid = true;
    if (current) valid = qihse_resp_parse_i64_bytes((const uint8_t*)current, strlen(current), &value);
    if (valid && ((delta > 0 && value == INT64_MAX) || (delta < 0 && value == INT64_MIN))) valid = false;
    bool stored = false;
    if (valid) {
        value += delta;
        char text[64];
        int len = snprintf(text, sizeof(text), "%" PRId64, value);
        stored = len > 0 && (size_t)len < sizeof(text) && qihse_kv_set_user(session->server->store, key, text, 0, 0, session->user);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(current);
    free(key);
    if (!valid) return qihse_resp_error(session, "ERR value is not an integer or out of range");
    return stored ? qihse_resp_integer(session, value) : qihse_resp_error(session, "ERR increment failed");
}

static bool qihse_resp_handle_vecset(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 4 || !session->server->vdb) return request->argc < 4 ? qihse_resp_wrong_arity(session, "vecset") : qihse_resp_error(session, "ERR vector database is not configured");
    uint64_t id;
    uint64_t dims_u64;
    if (!qihse_resp_parse_u64_arg(&request->argv[1], &id) || !qihse_resp_parse_u64_arg(&request->argv[2], &dims_u64) || dims_u64 == 0 || dims_u64 > 65536u) return qihse_resp_error(session, "ERR invalid vector id or dimensions");
    size_t dims = (size_t)dims_u64;
    if (request->argc < 3u + dims) return qihse_resp_wrong_arity(session, "vecset");
    if (!qihse_system_guard_check_operation(dims * sizeof(float), false)) return qihse_resp_error(session, "OOM command not allowed by QIHSE system guard");
    float* vector = (float*)malloc(dims * sizeof(*vector));
    if (!vector) return qihse_resp_error(session, "OOM out of memory");
    bool valid = true;
    for (size_t i = 0; i < dims; i++) {
        double value;
        if (!qihse_resp_parse_double_arg(&request->argv[3u + i], &value) || value < -FLT_MAX || value > FLT_MAX) {
            valid = false;
            break;
        }
        vector[i] = (float)value;
    }
    size_t option = 3u + dims;
    const void* metadata = NULL;
    size_t metadata_size = 0;
    if (valid && option < request->argc) {
        if (option + 2u != request->argc || !qihse_resp_arg_equal(&request->argv[option], "TAG")) valid = false;
        else {
            metadata = request->argv[option + 1u].data;
            metadata_size = request->argv[option + 1u].len;
        }
    }
    if (!valid) {
        free(vector);
        return qihse_resp_error(session, "ERR invalid VECSET format");
    }
    const void* metadata_values[1] = { metadata };
    size_t metadata_sizes[1] = { metadata_size };
    pthread_mutex_lock(&session->server->vdb_lock);
    bool result = qihse_vector_db_upsert_by_ids(session->server->vdb, &id, vector, 1u, dims,
                                                 metadata ? metadata_values : NULL,
                                                 metadata ? metadata_sizes : NULL, NULL, NULL);
    pthread_mutex_unlock(&session->server->vdb_lock);
    free(vector);
    return result ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR vector upsert failed");
}

static bool qihse_resp_handle_vecget(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if ((request->argc != 2 && request->argc != 4) || !session->server->vdb) return !session->server->vdb ? qihse_resp_error(session, "ERR vector database is not configured") : qihse_resp_wrong_arity(session, "vecget");
    if (request->argc == 4 && !qihse_resp_arg_equal(&request->argv[2], "TAG")) return qihse_resp_error(session, "ERR syntax error");
    uint64_t id;
    if (!qihse_resp_parse_u64_arg(&request->argv[1], &id)) return qihse_resp_error(session, "ERR invalid vector id");
    pthread_mutex_lock(&session->server->vdb_lock);
    size_t dims = qihse_vector_db_get_dims(session->server->vdb);
    float* vector = dims ? (float*)malloc(dims * sizeof(*vector)) : NULL;
    bool found = vector && qihse_vector_db_get_vector_by_id(session->server->vdb, id, vector, &dims);
    pthread_mutex_unlock(&session->server->vdb_lock);
    if (!found) {
        free(vector);
        return qihse_resp_null(session);
    }
    bool result = qihse_resp_array(session, dims);
    for (size_t i = 0; result && i < dims; i++) result = qihse_resp_reply_double(session, vector[i]);
    free(vector);
    return result;
}

static bool qihse_resp_handle_vecsearch(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool scatter) {
    if (request->argc < 4 || !session->server->vdb) return !session->server->vdb ? qihse_resp_error(session, "ERR vector database is not configured") : qihse_resp_wrong_arity(session, scatter ? "vecscatter" : "vecsearch");
    if (scatter && !session->server->scatter && qihse_cluster_topology_nodes(session->server->topology, NULL, 0u) > 1u) return qihse_resp_error(session, "ERR distributed vector scatter transport is not configured");
    uint64_t dims_u64;
    uint64_t top_u64;
    if (!qihse_resp_parse_u64_arg(&request->argv[1], &dims_u64) || !qihse_resp_parse_u64_arg(&request->argv[2], &top_u64) || dims_u64 == 0 || dims_u64 > 65536u || top_u64 == 0 || top_u64 > 10000u) return qihse_resp_error(session, "ERR invalid vector search parameters");
    size_t dims = (size_t)dims_u64;
    size_t top_k = (size_t)top_u64;
    if (request->argc < 3u + dims) return qihse_resp_wrong_arity(session, scatter ? "vecscatter" : "vecsearch");
    float* vector = (float*)malloc(dims * sizeof(*vector));
    qihse_vector_result_t* results = (qihse_vector_result_t*)calloc(top_k, sizeof(*results));
    if (!vector || !results) {
        free(vector);
        free(results);
        return qihse_resp_error(session, "OOM out of memory");
    }
    bool valid = true;
    for (size_t i = 0; i < dims; i++) {
        double value;
        if (!qihse_resp_parse_double_arg(&request->argv[3u + i], &value) || value < -FLT_MAX || value > FLT_MAX) {
            valid = false;
            break;
        }
        vector[i] = (float)value;
    }
    size_t option = 3u + dims;
    if (valid && option < request->argc && (option + 2u != request->argc || !qihse_resp_arg_equal(&request->argv[option], "TAG"))) valid = false;
    if (!valid) {
        free(vector);
        free(results);
        return qihse_resp_error(session, "ERR invalid vector search format");
    }

    /* Phase 4: VECSCATTER uses the scatter-gather engine to query all
     * peer shards and merge results via Reciprocal Rank Fusion. */
    if (scatter && session->server->scatter) {
        /* First, search the local shard */
        qihse_vector_query_t query;
        memset(&query, 0, sizeof(query));
        query.query_vector = vector;
        query.vector_dims = dims;
        query.top_k = top_k;
        query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
        query.user = session->user;
        pthread_mutex_lock(&session->server->vdb_lock);
        int local_found = qihse_vector_db_search(session->server->vdb, &query, results, top_k);
        pthread_mutex_unlock(&session->server->vdb_lock);

        /* Query remote peers and merge with RRF */
        qihse_vector_result_t* remote_results = (qihse_vector_result_t*)calloc(top_k, sizeof(*remote_results));
        if (!remote_results) {
            free(vector);
            free(results);
            return qihse_resp_error(session, "OOM out of memory");
        }
        int remote_found = qihse_cluster_scatter_vecsearch(session->server->scatter,
                                                           vector, dims, top_k, session->user,
                                                           remote_results);
        /* Merge local and remote results using RRF in-place */
        if (local_found > 0 || remote_found > 0) {
            typedef struct { uint64_t id; double rrf; float best; } rrf_t;
            size_t total = (size_t)(local_found > 0 ? local_found : 0) + (size_t)(remote_found > 0 ? remote_found : 0);
            rrf_t* table = (rrf_t*)calloc(total > 0 ? total : 1, sizeof(*table));
            size_t tc = 0;
            if (table) {
                for (int r = 0; r < local_found; r++) {
                    bool found = false;
                    for (size_t j = 0; j < tc; j++) {
                        if (table[j].id == results[r].id) { table[j].rrf += 1.0 / (double)(60u + (uint32_t)r); if (results[r].score > table[j].best) table[j].best = results[r].score; found = true; break; }
                    }
                    if (!found && tc < total) { table[tc].id = results[r].id; table[tc].rrf = 1.0 / (double)(60u + (uint32_t)r); table[tc].best = results[r].score; tc++; }
                }
                for (int r = 0; r < remote_found; r++) {
                    bool found = false;
                    for (size_t j = 0; j < tc; j++) {
                        if (table[j].id == remote_results[r].id) { table[j].rrf += 1.0 / (double)(60u + (uint32_t)r); if (remote_results[r].score > table[j].best) table[j].best = remote_results[r].score; found = true; break; }
                    }
                    if (!found && tc < total) { table[tc].id = remote_results[r].id; table[tc].rrf = 1.0 / (double)(60u + (uint32_t)r); table[tc].best = remote_results[r].score; tc++; }
                }
                for (size_t i = 1; i < tc; i++) {
                    rrf_t key = table[i];
                    size_t j = i;
                    while (j > 0 && table[j - 1].rrf < key.rrf) { table[j] = table[j - 1]; j--; }
                    table[j] = key;
                }
                size_t output = tc < top_k ? tc : top_k;
                for (size_t i = 0; i < output; i++) {
                    results[i].id = table[i].id;
                    results[i].score = table[i].best;
                }
                local_found = (int)output;
                free(table);
            }
        }
        free(remote_results);
        bool response = local_found > 0 ? qihse_resp_array(session, (size_t)local_found) : qihse_resp_null(session);
        for (int i = 0; response && i < local_found; i++) {
            response = qihse_resp_array(session, 2u) && qihse_resp_integer(session, (int64_t)results[i].id) && qihse_resp_reply_double(session, results[i].score);
        }
        free(vector);
        free(results);
        return response;
    }

    /* Standard local-only VECSEARCH */
    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = vector;
    query.vector_dims = dims;
    query.top_k = top_k;
    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
    query.user = session->user;
    pthread_mutex_lock(&session->server->vdb_lock);
    int found = qihse_vector_db_search(session->server->vdb, &query, results, top_k);
    pthread_mutex_unlock(&session->server->vdb_lock);
    bool response = found >= 0 ? qihse_resp_array(session, (size_t)found) : qihse_resp_error(session, "ERR vector search failed");
    for (int i = 0; response && i < found; i++) {
        response = qihse_resp_array(session, 2u) && qihse_resp_integer(session, (int64_t)results[i].id) && qihse_resp_reply_double(session, results[i].score);
    }
    free(vector);
    free(results);
    return response;
}

static uint32_t qihse_resp_series_id(const qihse_resp_arg_t* key) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < key->len; i++) hash = (hash ^ key->data[i]) * 16777619u;
    return hash;
}

static bool qihse_resp_handle_ts_add(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "ts.add");
    if (!session->server->tsdb) return qihse_resp_error(session, "ERR time-series database is not configured");
    uint64_t timestamp;
    if (request->argv[2].len == 1u && request->argv[2].data[0] == '*') timestamp = qihse_resp_now_ms();
    else if (!qihse_resp_parse_u64_arg(&request->argv[2], &timestamp)) return qihse_resp_error(session, "ERR invalid timestamp");
    double value;
    if (!qihse_resp_parse_double_arg(&request->argv[3], &value)) return qihse_resp_error(session, "ERR invalid value");
    pthread_mutex_lock(&session->server->tsdb_lock);
    bool inserted = qihse_tsdb_insert(session->server->tsdb, qihse_resp_series_id(&request->argv[1]), timestamp, value, 0, 0);
    pthread_mutex_unlock(&session->server->tsdb_lock);
    return inserted ? qihse_resp_integer(session, timestamp > INT64_MAX ? INT64_MAX : (int64_t)timestamp) : qihse_resp_error(session, "ERR time-series insert failed");
}

static bool qihse_resp_handle_ts_range(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4 && request->argc != 5) return qihse_resp_wrong_arity(session, "ts.range");
    if (!session->server->tsdb) return qihse_resp_error(session, "ERR time-series database is not configured");
    uint64_t start;
    uint64_t end;
    if (!qihse_resp_parse_u64_arg(&request->argv[2], &start) || !qihse_resp_parse_u64_arg(&request->argv[3], &end) || start > end) return qihse_resp_error(session, "ERR invalid timestamp range");
    qihse_ts_aggregation_t aggregation = QIHSE_TS_AGG_AVG;
    if (request->argc == 5) {
        if (qihse_resp_arg_equal(&request->argv[4], "AVG")) aggregation = QIHSE_TS_AGG_AVG;
        else if (qihse_resp_arg_equal(&request->argv[4], "SUM")) aggregation = QIHSE_TS_AGG_SUM;
        else if (qihse_resp_arg_equal(&request->argv[4], "MIN")) aggregation = QIHSE_TS_AGG_MIN;
        else if (qihse_resp_arg_equal(&request->argv[4], "MAX")) aggregation = QIHSE_TS_AGG_MAX;
        else return qihse_resp_error(session, "ERR unsupported aggregation");
    }
    double value;
    uint64_t count;
    pthread_mutex_lock(&session->server->tsdb_lock);
    bool found = qihse_tsdb_aggregate_range_user(session->server->tsdb, qihse_resp_series_id(&request->argv[1]), start, end, aggregation, session->user, &value, &count);
    pthread_mutex_unlock(&session->server->tsdb_lock);
    return found ? qihse_resp_reply_double(session, value) : qihse_resp_null(session);
}

static bool qihse_resp_handle_column(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->column_store) return qihse_resp_error(session, "ERR column store is not configured");
    char* key = request->argc > 1 ? qihse_resp_arg_text(&request->argv[1]) : NULL;
    if (!key) return qihse_resp_error(session, "ERR invalid column key");
    bool result;
    pthread_mutex_lock(&session->server->column_lock);
    if (qihse_resp_command_is(request, "COL.APPEND")) {
        if (request->argc != 3) {
            pthread_mutex_unlock(&session->server->column_lock);
            free(key);
            return qihse_resp_wrong_arity(session, "col.append");
        }
        double parsed;
        bool valid = qihse_resp_parse_double_arg(&request->argv[2], &parsed) && parsed >= -FLT_MAX && parsed <= FLT_MAX;
        bool appended = valid && qihse_column_append_float32(session->server->column_store, key, (float)parsed, 0, 0);
        if (valid && !appended) {
            qihse_column_create(session->server->column_store, key, QIHSE_COL_TYPE_FLOAT32);
            appended = qihse_column_append_float32(session->server->column_store, key, (float)parsed, 0, 0);
        }
        pthread_mutex_unlock(&session->server->column_lock);
        free(key);
        if (!valid) return qihse_resp_error(session, "ERR invalid column value");
        return appended ? qihse_resp_integer(session, 1) : qihse_resp_error(session, "ERR column append failed");
    }
    if (request->argc != 2) {
        pthread_mutex_unlock(&session->server->column_lock);
        free(key);
        return qihse_resp_wrong_arity(session, qihse_resp_command_is(request, "COL.SUM") ? "col.sum" : "col.minmax");
    }
    if (qihse_resp_command_is(request, "COL.SUM")) {
        float sum = qihse_column_sum_float32_user(session->server->column_store, key, session->user);
        pthread_mutex_unlock(&session->server->column_lock);
        free(key);
        return qihse_resp_reply_double(session, sum);
    }
    float minimum;
    float maximum;
    bool found = qihse_column_minmax_float32_user(session->server->column_store, key, session->user, &minimum, &maximum);
    pthread_mutex_unlock(&session->server->column_lock);
    free(key);
    result = found ? qihse_resp_array(session, 2u) && qihse_resp_reply_double(session, minimum) && qihse_resp_reply_double(session, maximum) : qihse_resp_null(session);
    return result;
}

static bool qihse_resp_fd_write(int fd, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    size_t written = 0;
    while (written < len) {
#ifdef MSG_NOSIGNAL
        ssize_t result = send(fd, bytes + written, len - written, MSG_NOSIGNAL);
#else
        ssize_t result = send(fd, (const char*)bytes + written, len - written, 0);
#endif
        if (result < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (result == 0) return false;
        written += (size_t)result;
    }
    return true;
}

static bool qihse_resp_fd_command(int fd, size_t argc, const qihse_resp_arg_t* argv, char* error, size_t error_capacity) {
    char header[64];
    int len = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    if (len <= 0 || (size_t)len >= sizeof(header) || !qihse_resp_fd_write(fd, header, (size_t)len)) return false;
    for (size_t i = 0; i < argc; i++) {
        len = snprintf(header, sizeof(header), "$%zu\r\n", argv[i].len);
        if (len <= 0 || (size_t)len >= sizeof(header) || !qihse_resp_fd_write(fd, header, (size_t)len) ||
            (argv[i].len > 0 && !qihse_resp_fd_write(fd, argv[i].data, argv[i].len)) || !qihse_resp_fd_write(fd, "\r\n", 2u)) return false;
    }
    char line[1024];
    size_t used = 0;
    while (used + 1u < sizeof(line)) {
        ssize_t received = recv(fd, line + used, 1u, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (received == 0) return false;
        used++;
        if (used >= 2u && line[used - 2u] == '\r' && line[used - 1u] == '\n') break;
    }
    if (used < 3u || line[used - 2u] != '\r' || line[used - 1u] != '\n') {
        errno = EPROTO;
        return false;
    }
    line[used - 2u] = '\0';
    if (line[0] == '+') return true;
    if (error && error_capacity > 0) {
        if (line[0] == '-') snprintf(error, error_capacity, "%s", line + 1u);
        else snprintf(error, error_capacity, "target did not acknowledge command");
    }
    errno = EREMOTEIO;
    return false;
}

static int qihse_resp_connect_timeout(const char* host, uint16_t port, int timeout_ms) {
    char service[16];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    struct addrinfo* addresses = NULL;
    if (getaddrinfo(host, service, &hints, &addresses) != 0) {
        errno = EHOSTUNREACH;
        return -1;
    }
    int fd = -1;
    for (struct addrinfo* address = addresses; address; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) continue;
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close_socket(fd);
            fd = -1;
            continue;
        }
        int result = connect(fd, address->ai_addr, address->ai_addrlen);
        if (result != 0 && errno == EINPROGRESS) {
            struct pollfd poll_fd = { fd, POLLOUT, 0 };
            do {
                result = poll(&poll_fd, 1u, timeout_ms);
            } while (result < 0 && errno == EINTR);
            if (result > 0) {
                int socket_error = 0;
                socklen_t error_len = sizeof(socket_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) != 0 || socket_error != 0) {
                    errno = socket_error ? socket_error : errno;
                    result = -1;
                } else {
                    result = 0;
                }
            } else if (result == 0) {
                errno = ETIMEDOUT;
                result = -1;
            }
        }
        fcntl(fd, F_SETFL, flags);
        if (result == 0) break;
        close_socket(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd >= 0) {
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    return fd;
}

typedef struct {
    char* key;
    char* value;
    int64_t ttl_ms;
} qihse_resp_migrate_item_t;

static bool qihse_resp_handle_migrate(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 6) return qihse_resp_wrong_arity(session, "migrate");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char* host = qihse_resp_arg_text(&request->argv[1]);
    uint64_t port_value;
    uint64_t database;
    uint64_t timeout_value;
    if (!host || !qihse_resp_parse_u64_arg(&request->argv[2], &port_value) || port_value == 0 || port_value > UINT16_MAX ||
        !qihse_resp_parse_u64_arg(&request->argv[4], &database) || database != 0 ||
        !qihse_resp_parse_u64_arg(&request->argv[5], &timeout_value) || timeout_value == 0 || timeout_value > INT_MAX) {
        free(host);
        return qihse_resp_error(session, "ERR invalid MIGRATE target, database, or timeout");
    }
    bool copy = false;
    bool replace = false;
    const qihse_resp_arg_t* auth_user = NULL;
    const qihse_resp_arg_t* auth_password = NULL;
    size_t key_indexes[QIHSE_RESP_MAX_ARGS];
    size_t key_count = 0;
    if (request->argv[3].len > 0) key_indexes[key_count++] = 3u;
    size_t cursor = 6u;
    bool syntax_valid = true;
    while (cursor < request->argc) {
        if (qihse_resp_arg_equal(&request->argv[cursor], "COPY")) {
            copy = true;
            cursor++;
        } else if (qihse_resp_arg_equal(&request->argv[cursor], "REPLACE")) {
            replace = true;
            cursor++;
        } else if (qihse_resp_arg_equal(&request->argv[cursor], "AUTH") && cursor + 1u < request->argc) {
            auth_password = &request->argv[cursor + 1u];
            cursor += 2u;
        } else if (qihse_resp_arg_equal(&request->argv[cursor], "AUTH2") && cursor + 2u < request->argc) {
            auth_user = &request->argv[cursor + 1u];
            auth_password = &request->argv[cursor + 2u];
            cursor += 3u;
        } else if (qihse_resp_arg_equal(&request->argv[cursor], "KEYS") && request->argv[3].len == 0 && cursor + 1u < request->argc) {
            for (size_t i = cursor + 1u; i < request->argc; i++) key_indexes[key_count++] = i;
            cursor = request->argc;
        } else {
            syntax_valid = false;
            break;
        }
    }
    if (!syntax_valid || key_count == 0) {
        free(host);
        return qihse_resp_error(session, "ERR syntax error");
    }
    qihse_resp_migrate_item_t* items = (qihse_resp_migrate_item_t*)calloc(key_count, sizeof(*items));
    if (!items) {
        free(host);
        return qihse_resp_error(session, "OOM out of memory");
    }
    size_t found = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 0; i < key_count; i++) {
        char* key = qihse_resp_arg_text(&request->argv[key_indexes[i]]);
        char* value = key ? qihse_kv_get_user(session->server->store, key, session->user) : NULL;
        if (key && value) {
            items[found].key = key;
            items[found].value = value;
            items[found].ttl_ms = qihse_kv_ttl_ms_user(session->server->store, key, session->user);
            found++;
        } else {
            free(key);
            free(value);
        }
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    if (found == 0) {
        free(items);
        free(host);
        return qihse_resp_simple(session, "NOKEY");
    }
    int target_fd = qihse_resp_connect_timeout(host, (uint16_t)port_value, (int)timeout_value);
    free(host);
    char remote_error[1024] = {0};
    bool migrated = target_fd >= 0;
    if (migrated && auth_password) {
        static const uint8_t auth_command[] = "AUTH";
        static const uint8_t default_user[] = "GODMODE_OP";
        qihse_resp_arg_t auth_args[3];
        auth_args[0] = (qihse_resp_arg_t){ auth_command, sizeof(auth_command) - 1u };
        if (auth_user) {
            auth_args[1] = *auth_user;
            auth_args[2] = *auth_password;
            migrated = qihse_resp_fd_command(target_fd, 3u, auth_args, remote_error, sizeof(remote_error));
        } else {
            auth_args[1] = (qihse_resp_arg_t){ default_user, sizeof(default_user) - 1u };
            auth_args[2] = *auth_password;
            migrated = qihse_resp_fd_command(target_fd, 3u, auth_args, remote_error, sizeof(remote_error));
        }
    }
    static const uint8_t asking_command[] = "ASKING";
    static const uint8_t set_command[] = "SET";
    static const uint8_t nx_option[] = "NX";
    static const uint8_t px_option[] = "PX";
    for (size_t i = 0; migrated && i < found; i++) {
        qihse_resp_arg_t asking = { asking_command, sizeof(asking_command) - 1u };
        migrated = qihse_resp_fd_command(target_fd, 1u, &asking, remote_error, sizeof(remote_error));
        if (!migrated) break;
        qihse_resp_arg_t set_args[6];
        size_t set_argc = 3u;
        set_args[0] = (qihse_resp_arg_t){ set_command, sizeof(set_command) - 1u };
        set_args[1] = (qihse_resp_arg_t){ (const uint8_t*)items[i].key, strlen(items[i].key) };
        set_args[2] = (qihse_resp_arg_t){ (const uint8_t*)items[i].value, strlen(items[i].value) };
        char ttl[64];
        if (items[i].ttl_ms > 0) {
            int ttl_len = snprintf(ttl, sizeof(ttl), "%" PRId64, items[i].ttl_ms);
            set_args[set_argc++] = (qihse_resp_arg_t){ px_option, sizeof(px_option) - 1u };
            set_args[set_argc++] = (qihse_resp_arg_t){ (const uint8_t*)ttl, (size_t)ttl_len };
        }
        if (!replace) set_args[set_argc++] = (qihse_resp_arg_t){ nx_option, sizeof(nx_option) - 1u };
        migrated = qihse_resp_fd_command(target_fd, set_argc, set_args, remote_error, sizeof(remote_error));
    }
    if (target_fd >= 0) close_socket(target_fd);
    if (migrated && !copy) {
        pthread_mutex_lock(&session->server->kv_lock);
        for (size_t i = 0; i < found; i++) qihse_kv_del_user(session->server->store, items[i].key, session->user);
        pthread_mutex_unlock(&session->server->kv_lock);
    }
    for (size_t i = 0; i < found; i++) {
        free(items[i].key);
        free(items[i].value);
    }
    free(items);
    if (!migrated) {
        char response[1200];
        if (remote_error[0]) snprintf(response, sizeof(response), "ERR Target instance replied with error: %s", remote_error);
        else snprintf(response, sizeof(response), "IOERR error or timeout connecting to the client");
        return qihse_resp_error(session, response);
    }
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_keystone_ingest(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2 || request->argc > 4) return qihse_resp_wrong_arity(session, "keystone.ingest");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    uint16_t clearance = 0;
    uint16_t compartment = 0;
    if (request->argc >= 3) {
        uint64_t cl;
        if (!qihse_resp_parse_u64_arg(&request->argv[2], &cl)) return qihse_resp_error(session, "ERR invalid clearance");
        clearance = (uint16_t)cl;
    }
    if (request->argc >= 4) {
        uint64_t cp;
        if (!qihse_resp_parse_u64_arg(&request->argv[3], &cp)) return qihse_resp_error(session, "ERR invalid compartment");
        compartment = (uint16_t)cp;
    }

    pthread_mutex_lock(&session->server->kv_lock);
    size_t count = qihse_keystone_ingest_dirty_logs(
        session->server->store,
        session->server->topology,
        (const char*)request->argv[1].data,
        request->argv[1].len,
        clearance,
        compartment
    );
    pthread_mutex_unlock(&session->server->kv_lock);
    return qihse_resp_integer(session, (int64_t)count);
}

static bool qihse_resp_handle_keystone_classify(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "keystone.classify");
    qihse_keystone_class_t cls = QIHSE_KEYSTONE_CLASS_UNKNOWN;
    float conf = 0.0f;
    int rc = qihse_keystone_classify_context((const char*)request->argv[1].data, request->argv[1].len, &cls, &conf);
    if (rc != 0) return qihse_resp_error(session, "ERR classification failed");

    if (!qihse_resp_array(session, 2u)) return false;
    if (!qihse_resp_bulk_text(session, qihse_keystone_class_name(cls))) return false;
    return qihse_resp_reply_double(session, (double)conf);
}

static bool qihse_resp_dispatch(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool* keep_open) {
    *keep_open = true;
    if (request->argc == 0) return true;
    if (qihse_resp_command_is(request, "AUTH")) return qihse_resp_handle_auth(session, request);
    if (qihse_resp_command_is(request, "HELLO")) return qihse_resp_handle_hello(session, request);
    if (qihse_resp_command_is(request, "PING")) {
        if (request->argc == 1) return qihse_resp_simple(session, "PONG");
        if (request->argc == 2) return qihse_resp_bulk(session, request->argv[1].data, request->argv[1].len);
        return qihse_resp_wrong_arity(session, "ping");
    }
    if (qihse_resp_command_is(request, "QUIT")) {
        if (request->argc != 1) return qihse_resp_wrong_arity(session, "quit");
        *keep_open = false;
        return qihse_resp_simple(session, "OK");
    }
    if (session->server->auth_required && !session->user) return qihse_resp_error(session, "NOAUTH Authentication required.");
    /* Phase 3: System Guard bus-saturation throttling for DENYOOM commands */
    if (session->server->guard_window) {
        size_t request_bytes = 0;
        for (size_t i = 0; i < request->argc; i++) request_bytes += request->argv[i].len;
        qihse_system_guard_window_record(session->server->guard_window, request_bytes);
        if (!qihse_system_guard_window_safe(session->server->guard_window)) {
            /* Allow readonly commands to proceed; reject write/DENYOOM commands */
            bool is_write = qihse_resp_command_is(request, "SET") || qihse_resp_command_is(request, "SETEX") ||
                qihse_resp_command_is(request, "PSETEX") || qihse_resp_command_is(request, "MSET") ||
                qihse_resp_command_is(request, "DEL") || qihse_resp_command_is(request, "INCR") ||
                qihse_resp_command_is(request, "DECR") || qihse_resp_command_is(request, "EXPIRE") ||
                qihse_resp_command_is(request, "PEXPIRE") || qihse_resp_command_is(request, "MIGRATE") ||
                qihse_resp_command_is(request, "VECSET") || qihse_resp_command_is(request, "TS.ADD") ||
                qihse_resp_command_is(request, "COL.APPEND") || qihse_resp_command_is(request, "KEYSTONE.INGEST");
            if (is_write) return qihse_resp_error(session, "BUSY Bus saturation: try again later");
        }
    }
    if (qihse_resp_command_is(request, "ASKING")) {
        if (request->argc != 1) return qihse_resp_wrong_arity(session, "asking");
        session->asking = true;
        return qihse_resp_simple(session, "OK");
    }
    if (qihse_resp_command_is(request, "READONLY") || qihse_resp_command_is(request, "READWRITE")) {
        if (request->argc != 1) return qihse_resp_wrong_arity(session, qihse_resp_command_is(request, "READONLY") ? "readonly" : "readwrite");
        session->readonly = qihse_resp_command_is(request, "READONLY");
        return qihse_resp_simple(session, "OK");
    }
    if (qihse_resp_command_is(request, "CLUSTER")) {
        qihse_resp_cluster_context_t context = { session->server->topology, qihse_resp_cluster_output, session };
        return qihse_resp_cluster_dispatch(&context, request->argc, request->argv);
    }
    if (qihse_resp_command_is(request, "CLIENT")) return qihse_resp_handle_client_command(session, request);
    if (qihse_resp_command_is(request, "COMMAND")) return qihse_resp_handle_command(session, request);
    if (qihse_resp_command_is(request, "INFO")) return qihse_resp_handle_info(session);
    if (qihse_resp_command_is(request, "ECHO")) return request->argc == 2 ? qihse_resp_bulk(session, request->argv[1].data, request->argv[1].len) : qihse_resp_wrong_arity(session, "echo");
    if (qihse_resp_command_is(request, "SELECT")) {
        uint64_t database;
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "select");
        if (!qihse_resp_parse_u64_arg(&request->argv[1], &database) || database != 0) return qihse_resp_error(session, "ERR SELECT is not allowed in cluster mode");
        return qihse_resp_simple(session, "OK");
    }
    if (qihse_resp_command_is(request, "ROLE")) {
        qihse_cluster_node_t node;
        bool replica = qihse_cluster_topology_get_node(session->server->topology, qihse_cluster_topology_local_node(session->server->topology), &node) && node.role == QIHSE_CLUSTER_NODE_REPLICA;
        if (!qihse_resp_array(session, 3u) || !qihse_resp_bulk_text(session, replica ? "slave" : "master") || !qihse_resp_integer(session, 0)) return false;
        return qihse_resp_array(session, 0u);
    }

    /* KEYSTONE Ingestion and Semantic Extensions (Cluster Scoped) */
    if (qihse_resp_command_is(request, "KEYSTONE.INGEST")) return qihse_resp_handle_keystone_ingest(session, request);
    if (qihse_resp_command_is(request, "KEYSTONE.CLASSIFY")) return qihse_resp_handle_keystone_classify(session, request);

    qihse_resp_keyset_t keys;
    qihse_resp_extract_keys(request, &keys);
    if (keys.count > 0 && !qihse_resp_route(session, request, &keys)) return true;

    if (qihse_resp_command_is(request, "GET")) return qihse_resp_handle_get(session, request);
    if (qihse_resp_command_is(request, "SET")) return qihse_resp_handle_set(session, request);
    if (qihse_resp_command_is(request, "SETEX")) return qihse_resp_handle_setex(session, request, false);
    if (qihse_resp_command_is(request, "PSETEX")) return qihse_resp_handle_setex(session, request, true);
    if (qihse_resp_command_is(request, "DEL")) return qihse_resp_handle_del_exists(session, request, true);
    if (qihse_resp_command_is(request, "EXISTS")) return qihse_resp_handle_del_exists(session, request, false);
    if (qihse_resp_command_is(request, "MGET")) return qihse_resp_handle_mget(session, request);
    if (qihse_resp_command_is(request, "MSET")) return qihse_resp_handle_mset(session, request);
    if (qihse_resp_command_is(request, "MIGRATE")) return qihse_resp_handle_migrate(session, request);
    if (qihse_resp_command_is(request, "EXPIRE")) return qihse_resp_handle_expiry(session, request, false);
    if (qihse_resp_command_is(request, "PEXPIRE")) return qihse_resp_handle_expiry(session, request, true);
    if (qihse_resp_command_is(request, "TTL")) return qihse_resp_handle_ttl(session, request, false);
    if (qihse_resp_command_is(request, "PTTL")) return qihse_resp_handle_ttl(session, request, true);
    if (qihse_resp_command_is(request, "INCR")) return qihse_resp_handle_increment(session, request, 1);
    if (qihse_resp_command_is(request, "DECR")) return qihse_resp_handle_increment(session, request, -1);
    if (qihse_resp_command_is(request, "TYPE")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "type");
        if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
        char* key = qihse_resp_arg_text(&request->argv[1]);
        pthread_mutex_lock(&session->server->kv_lock);
        bool exists = key && qihse_kv_exists_user(session->server->store, key, session->user);
        pthread_mutex_unlock(&session->server->kv_lock);
        free(key);
        return qihse_resp_simple(session, exists ? "string" : "none");
    }
    if (qihse_resp_command_is(request, "VECSET")) return qihse_resp_handle_vecset(session, request);
    if (qihse_resp_command_is(request, "VECGET")) return qihse_resp_handle_vecget(session, request);
    if (qihse_resp_command_is(request, "VECSEARCH")) return qihse_resp_handle_vecsearch(session, request, false);
    if (qihse_resp_command_is(request, "VECSCATTER")) return qihse_resp_handle_vecsearch(session, request, true);
    if (qihse_resp_command_is(request, "TS.ADD")) return qihse_resp_handle_ts_add(session, request);
    if (qihse_resp_command_is(request, "TS.RANGE")) return qihse_resp_handle_ts_range(session, request);
    if (qihse_resp_command_is(request, "COL.APPEND") || qihse_resp_command_is(request, "COL.SUM") || qihse_resp_command_is(request, "COL.MINMAX")) return qihse_resp_handle_column(session, request);
    return qihse_resp_error(session, "ERR unknown command");
}

static bool qihse_resp_session_loop(qihse_resp_server_t* server, int fd) {
    qihse_resp_session_t session;
    memset(&session, 0, sizeof(session));
    session.server = server;
    session.fd = fd;
    session.protocol_version = 2;
    if (!server->auth_required) session.user = &server->unauthenticated_user;
    session.id = __atomic_add_fetch(&server->next_client_id, 1u, __ATOMIC_RELAXED);
    if (server->pin_workers) {
        int cpus[256];
        size_t count = qihse_cluster_available_cpus(cpus, sizeof(cpus) / sizeof(cpus[0]));
        if (count > 0) {
            uint64_t worker = __atomic_fetch_add(&server->next_worker, 1u, __ATOMIC_RELAXED);
            qihse_cluster_binding_result_t binding;
            if (!qihse_cluster_bind_current_thread(cpus[worker % count], server->numa_node_id, server->strict_hardware_affinity, &binding)) {
                qihse_resp_error(&session, "ERR unable to apply required hardware affinity");
                return false;
            }
        } else if (server->strict_hardware_affinity) {
            qihse_resp_error(&session, "ERR no CPUs available for required hardware affinity");
            return false;
        }
    }

    size_t capacity = QIHSE_RESP_INITIAL_BUFFER;
    if (capacity > server->max_request_bytes) capacity = server->max_request_bytes;
    uint8_t* buffer = (uint8_t*)malloc(capacity);
    if (!buffer) {
        qihse_resp_error(&session, "OOM out of memory");
        return false;
    }
    size_t used = 0;
    bool keep_open = true;
    bool successful = true;
    while (keep_open && __atomic_load_n(&server->running, __ATOMIC_ACQUIRE)) {
        size_t offset = 0;
        while (offset < used) {
            qihse_resp_request_t request;
            qihse_resp_parse_status_t status = qihse_resp_parse_request(buffer + offset, used - offset, &request);
            if (status == QIHSE_RESP_PARSE_MORE) break;
            if (status == QIHSE_RESP_PARSE_ERROR) {
                qihse_resp_error(&session, "ERR Protocol error: invalid request");
                successful = false;
                keep_open = false;
                break;
            }
            if (!qihse_resp_dispatch(&session, &request, &keep_open)) {
                successful = false;
                keep_open = false;
                break;
            }
            offset += request.consumed;
        }
        if (offset > 0) {
            memmove(buffer, buffer + offset, used - offset);
            used -= offset;
        }
        if (!keep_open) break;
        if (used == capacity) {
            if (capacity >= server->max_request_bytes) {
                qihse_resp_error(&session, "ERR Protocol error: request exceeds configured maximum");
                successful = false;
                break;
            }
            size_t next = capacity > server->max_request_bytes / 2u ? server->max_request_bytes : capacity * 2u;
            uint8_t* grown = (uint8_t*)realloc(buffer, next);
            if (!grown) {
                qihse_resp_error(&session, "OOM out of memory");
                successful = false;
                break;
            }
            buffer = grown;
            capacity = next;
        }
        ssize_t received = recv(fd, buffer + used, capacity - used, 0);
        if (received == 0) break;
        if (received < 0) {
            if (errno == EINTR) continue;
            successful = errno == ECONNRESET || errno == ENOTCONN;
            break;
        }
        used += (size_t)received;
    }
    free(buffer);
    return successful;
}

static void qihse_resp_remove_client(qihse_resp_client_ctx_t* client) {
    qihse_resp_server_t* server = client->server;
    pthread_mutex_lock(&server->state_lock);
    qihse_resp_client_ctx_t** cursor = &server->clients;
    while (*cursor && *cursor != client) cursor = &(*cursor)->next;
    if (*cursor == client) {
        *cursor = client->next;
        if (server->active_clients > 0) server->active_clients--;
    }
    if (server->active_clients == 0) pthread_cond_broadcast(&server->clients_drained);
    pthread_mutex_unlock(&server->state_lock);
}

static void* qihse_resp_client_main(void* argument) {
    qihse_resp_client_ctx_t* client = (qihse_resp_client_ctx_t*)argument;
    qihse_resp_server_t* server = client->server;
    int fd = client->fd;
    qihse_resp_session_loop(server, fd);
    shutdown(fd, SHUT_RDWR);
    close_socket(fd);
    qihse_resp_remove_client(client);
    free(client);
    return NULL;
}

static int qihse_resp_open_listener(qihse_resp_server_t* server) {
    char service[16];
    snprintf(service, sizeof(service), "%u", server->port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    struct addrinfo* addresses = NULL;
    int resolved = getaddrinfo(server->bind_address, service, &hints, &addresses);
    if (resolved != 0) {
        errno = EADDRNOTAVAIL;
        return -1;
    }
    int listener = -1;
    for (struct addrinfo* address = addresses; address; address = address->ai_next) {
        listener = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (listener < 0) continue;
        int enabled = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (bind(listener, address->ai_addr, address->ai_addrlen) == 0 && listen(listener, 256) == 0) break;
        close_socket(listener);
        listener = -1;
    }
    freeaddrinfo(addresses);
    if (listener < 0) return -1;
    if (server->port == 0) {
        struct sockaddr_storage bound;
        socklen_t bound_len = sizeof(bound);
        if (getsockname(listener, (struct sockaddr*)&bound, &bound_len) != 0) {
            close_socket(listener);
            return -1;
        }
        if (bound.ss_family == AF_INET) server->port = ntohs(((struct sockaddr_in*)&bound)->sin_port);
        else if (bound.ss_family == AF_INET6) server->port = ntohs(((struct sockaddr_in6*)&bound)->sin6_port);
    }
    uint16_t local = qihse_cluster_topology_local_node(server->topology);
    qihse_cluster_node_t node;
    if (qihse_cluster_topology_get_node(server->topology, local, &node)) {
        node.port = server->port;
        node.bus_port = server->bus_port ? server->bus_port : (server->port <= UINT16_MAX - 10000u ? (uint16_t)(server->port + 10000u) : 0u);
        qihse_resp_copy_string(node.host, sizeof(node.host), server->advertise_address);
        qihse_cluster_topology_upsert_node(server->topology, &node, NULL);
    }
    return listener;
}

static bool qihse_resp_accept_loop(qihse_resp_server_t* server) {
    while (__atomic_load_n(&server->running, __ATOMIC_ACQUIRE)) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(server->listen_fd, (struct sockaddr*)&peer, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            if (!__atomic_load_n(&server->running, __ATOMIC_ACQUIRE) || errno == EBADF || errno == EINVAL) break;
            continue;
        }
        int enabled = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        qihse_resp_client_ctx_t* client = (qihse_resp_client_ctx_t*)calloc(1, sizeof(*client));
        if (!client) {
            close_socket(client_fd);
            continue;
        }
        client->server = server;
        client->fd = client_fd;
        pthread_mutex_lock(&server->state_lock);
        if (!server->running || server->active_clients >= server->max_clients) {
            pthread_mutex_unlock(&server->state_lock);
            qihse_resp_session_t rejected;
            memset(&rejected, 0, sizeof(rejected));
            rejected.server = server;
            rejected.fd = client_fd;
            rejected.protocol_version = 2;
            qihse_resp_error(&rejected, "ERR max number of clients reached");
            close_socket(client_fd);
            free(client);
            continue;
        }
        client->next = server->clients;
        server->clients = client;
        server->active_clients++;
        pthread_mutex_unlock(&server->state_lock);
        pthread_t thread;
        int error = pthread_create(&thread, NULL, qihse_resp_client_main, client);
        if (error != 0) {
            qihse_resp_remove_client(client);
            close_socket(client_fd);
            free(client);
            continue;
        }
        pthread_detach(thread);
    }
    return true;
}

static void* qihse_resp_accept_main(void* argument) {
    qihse_resp_server_t* server = (qihse_resp_server_t*)argument;
    qihse_resp_accept_loop(server);
    return NULL;
}

void qihse_resp_server_config_init(qihse_resp_server_config_t* config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    config->bind_address = "127.0.0.1";
    config->advertise_address = "127.0.0.1";
    config->port = 6379u;
    config->local_node_index = QIHSE_CLUSTER_NODE_NONE;
    config->max_clients = QIHSE_RESP_DEFAULT_MAX_CLIENTS;
    config->max_request_bytes = QIHSE_RESP_DEFAULT_MAX_REQUEST;
    config->auth_required = true;
    config->require_full_coverage = true;
    config->numa_node_id = -1;
    config->enable_bus = false;
    config->enable_failover = false;
    config->enable_guard_throttle = false;
    config->xdp_interface = NULL;
    config->guard_window_ms = 1000u;
    config->guard_saturation_fraction = 0.8;
    config->enable_scatter = false;
    config->scatter_timeout_ms = 2000u;
}

qihse_resp_server_t* qihse_resp_server_create(const qihse_resp_server_config_t* supplied) {
    if (!supplied || supplied->max_request_bytes < 64u || supplied->max_request_bytes > (size_t)INT_MAX || supplied->max_clients == 0) {
        errno = EINVAL;
        return NULL;
    }
    const char* bind_address = supplied->bind_address ? supplied->bind_address : "127.0.0.1";
    const char* advertise_address = supplied->advertise_address ? supplied->advertise_address : bind_address;
    if (!supplied->auth_required && !qihse_resp_is_loopback(bind_address)) {
        errno = EACCES;
        return NULL;
    }
    qihse_resp_server_t* server = (qihse_resp_server_t*)calloc(1, sizeof(*server));
    if (!server) return NULL;
    server->store = supplied->store;
    server->vdb = supplied->vdb;
    server->tsdb = supplied->tsdb;
    server->column_store = supplied->column_store;
    server->port = supplied->port;
    server->bus_port = supplied->bus_port;
    server->max_clients = supplied->max_clients;
    server->max_request_bytes = supplied->max_request_bytes;
    server->auth_required = supplied->auth_required;
    server->unauthenticated_user.user_id = UINT32_MAX;
    server->unauthenticated_user.role = QIHSE_ROLE_OPERATOR;
    server->unauthenticated_user.classification_level = UINT16_MAX;
    server->unauthenticated_user.sci_compartments = UINT16_MAX;
    server->unauthenticated_user.hardware_token_present = true;
    snprintf(server->unauthenticated_user.username, sizeof(server->unauthenticated_user.username), "QIHSE_LOOPBACK");
    server->require_full_coverage = supplied->require_full_coverage;
    server->pin_workers = supplied->pin_workers;
    server->strict_hardware_affinity = supplied->strict_hardware_affinity;
    server->numa_node_id = supplied->numa_node_id;
    server->listen_fd = -1;
    if (!qihse_resp_copy_string(server->bind_address, sizeof(server->bind_address), bind_address) ||
        !qihse_resp_copy_string(server->advertise_address, sizeof(server->advertise_address), advertise_address)) {
        free(server);
        errno = ENAMETOOLONG;
        return NULL;
    }
    if (pthread_mutex_init(&server->state_lock, NULL) != 0 || pthread_cond_init(&server->clients_drained, NULL) != 0 ||
        pthread_mutex_init(&server->kv_lock, NULL) != 0 || pthread_mutex_init(&server->vdb_lock, NULL) != 0 ||
        pthread_mutex_init(&server->tsdb_lock, NULL) != 0 || pthread_mutex_init(&server->column_lock, NULL) != 0) {
        free(server);
        errno = ENOMEM;
        return NULL;
    }
    server->topology = supplied->topology;
    if (!server->topology) {
        server->topology = qihse_cluster_topology_create();
        server->owns_topology = true;
    }
    if (!server->topology) {
        qihse_resp_server_destroy(server);
        return NULL;
    }
    uint16_t local = supplied->local_node_index;
    if (local == QIHSE_CLUSTER_NODE_NONE) local = qihse_cluster_topology_local_node(server->topology);
    if (local == QIHSE_CLUSTER_NODE_NONE) {
        qihse_cluster_node_t node;
        memset(&node, 0, sizeof(node));
        if (supplied->node_id) {
            if (!qihse_resp_copy_string(node.id, sizeof(node.id), supplied->node_id)) {
                qihse_resp_server_destroy(server);
                errno = EINVAL;
                return NULL;
            }
        } else {
            char seed[QIHSE_CLUSTER_HOST_LEN + 32u];
            int seed_len = snprintf(seed, sizeof(seed), "%s:%u", advertise_address, supplied->port);
            qihse_cluster_node_id_from_seed(seed, seed_len > 0 ? (size_t)seed_len : 0u, node.id);
        }
        qihse_resp_copy_string(node.host, sizeof(node.host), advertise_address);
        node.port = supplied->port ? supplied->port : 1u;
        node.bus_port = supplied->bus_port;
        node.role = QIHSE_CLUSTER_NODE_PRIMARY;
        node.primary_index = QIHSE_CLUSTER_NODE_NONE;
        node.healthy = true;
        if (!qihse_cluster_topology_upsert_node(server->topology, &node, &local) || !qihse_cluster_topology_set_local_node(server->topology, local)) {
            qihse_resp_server_destroy(server);
            return NULL;
        }
    } else if (!qihse_cluster_topology_set_local_node(server->topology, local)) {
        qihse_resp_server_destroy(server);
        return NULL;
    }
    if (server->owns_topology && qihse_cluster_topology_assigned_slots(server->topology) == 0) {
        if (!qihse_cluster_topology_assign_range(server->topology, 0u, QIHSE_CLUSTER_SLOT_COUNT - 1u, local)) {
            qihse_resp_server_destroy(server);
            return NULL;
        }
    }
    /* Phase 3: create cluster bus if requested */
    if (supplied->enable_bus) {
        qihse_cluster_bus_config_t bus_cfg;
        memset(&bus_cfg, 0, sizeof(bus_cfg));
        bus_cfg.topology = server->topology;
        bus_cfg.local_node_index = local;
        bus_cfg.bus_port = server->bus_port;
        bus_cfg.bind_address = supplied->bind_address;
        bus_cfg.xdp_interface = supplied->xdp_interface;
        server->bus = qihse_cluster_bus_create(&bus_cfg);
        server->owns_bus = server->bus != NULL;
    }
    /* Phase 3: create failover coordinator if requested */
    if (supplied->enable_failover) {
        qihse_cluster_failover_config_t fo_cfg;
        memset(&fo_cfg, 0, sizeof(fo_cfg));
        fo_cfg.topology = server->topology;
        fo_cfg.bus = server->bus;
        fo_cfg.local_node_index = local;
        fo_cfg.single_coordinator = false;
        server->failover = qihse_cluster_failover_create(&fo_cfg);
        server->owns_failover = server->failover != NULL;
        /* Wire the failover callback into the bus by recreating it with
         * the callback set. */
        if (server->bus && server->failover) {
            qihse_cluster_bus_config_t re_cfg;
            memset(&re_cfg, 0, sizeof(re_cfg));
            re_cfg.topology = server->topology;
            re_cfg.local_node_index = local;
            re_cfg.bus_port = server->bus_port;
            re_cfg.bind_address = supplied->bind_address;
            re_cfg.xdp_interface = supplied->xdp_interface;
            re_cfg.on_fail = qihse_cluster_failover_on_fail_cb;
            re_cfg.on_fail_user_data = server->failover;
            qihse_cluster_bus_destroy(server->bus);
            server->bus = qihse_cluster_bus_create(&re_cfg);
            server->owns_bus = server->bus != NULL;
        }
    }
    /* Phase 3: create system guard throttling window if requested */
    if (supplied->enable_guard_throttle) {
        server->guard_window = qihse_system_guard_window_create(
            supplied->guard_window_ms, supplied->guard_saturation_fraction);
        server->owns_guard_window = server->guard_window != NULL;
    }
    /* Phase 4: create scatter-gather engine if requested */
    if (supplied->enable_scatter) {
        qihse_cluster_scatter_config_t sg_cfg;
        memset(&sg_cfg, 0, sizeof(sg_cfg));
        sg_cfg.topology = server->topology;
        sg_cfg.local_node_index = local;
        sg_cfg.timeout_ms = supplied->scatter_timeout_ms;
        server->scatter = qihse_cluster_scatter_create(&sg_cfg);
        server->owns_scatter = server->scatter != NULL;
    }
    return server;
}

bool qihse_resp_server_start(qihse_resp_server_t* server) {
    if (!server) {
        errno = EINVAL;
        return false;
    }
    if (server->auth_required && qihse_auth_is_operator_password_default()) {
        errno = EACCES;
        return false;
    }
    pthread_mutex_lock(&server->state_lock);
    if (server->running || server->listen_fd >= 0) {
        pthread_mutex_unlock(&server->state_lock);
        errno = EALREADY;
        return false;
    }
    server->listen_fd = qihse_resp_open_listener(server);
    if (server->listen_fd < 0) {
        pthread_mutex_unlock(&server->state_lock);
        return false;
    }
    __atomic_store_n(&server->running, true, __ATOMIC_RELEASE);
    int error = pthread_create(&server->accept_thread, NULL, qihse_resp_accept_main, server);
    if (error != 0) {
        __atomic_store_n(&server->running, false, __ATOMIC_RELEASE);
        close_socket(server->listen_fd);
        server->listen_fd = -1;
        pthread_mutex_unlock(&server->state_lock);
        errno = error;
        return false;
    }
    server->accept_thread_started = true;
    pthread_mutex_unlock(&server->state_lock);
    /* Phase 3: start cluster bus if present */
    if (server->bus) qihse_cluster_bus_start(server->bus);
    return true;
}

bool qihse_resp_server_run(qihse_resp_server_t* server) {
    if (!server) {
        errno = EINVAL;
        return false;
    }
    if (server->auth_required && qihse_auth_is_operator_password_default()) {
        errno = EACCES;
        return false;
    }
    pthread_mutex_lock(&server->state_lock);
    if (server->running || server->listen_fd >= 0) {
        pthread_mutex_unlock(&server->state_lock);
        errno = EALREADY;
        return false;
    }
    server->listen_fd = qihse_resp_open_listener(server);
    if (server->listen_fd < 0) {
        pthread_mutex_unlock(&server->state_lock);
        return false;
    }
    __atomic_store_n(&server->running, true, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&server->state_lock);
    bool result = qihse_resp_accept_loop(server);
    qihse_resp_server_stop(server);
    return result;
}

void qihse_resp_server_stop(qihse_resp_server_t* server) {
    if (!server) return;
    pthread_t accept_thread;
    bool join_accept = false;
    pthread_mutex_lock(&server->state_lock);
    __atomic_store_n(&server->running, false, __ATOMIC_RELEASE);
    if (server->listen_fd >= 0) {
        shutdown(server->listen_fd, SHUT_RDWR);
        close_socket(server->listen_fd);
        server->listen_fd = -1;
    }
    for (qihse_resp_client_ctx_t* client = server->clients; client; client = client->next) shutdown(client->fd, SHUT_RDWR);
    if (server->accept_thread_started) {
        accept_thread = server->accept_thread;
        server->accept_thread_started = false;
        join_accept = !pthread_equal(pthread_self(), accept_thread);
    }
    pthread_mutex_unlock(&server->state_lock);
    if (join_accept) pthread_join(accept_thread, NULL);
    pthread_mutex_lock(&server->state_lock);
    while (server->active_clients > 0) pthread_cond_wait(&server->clients_drained, &server->state_lock);
    pthread_mutex_unlock(&server->state_lock);
    /* Phase 3: stop cluster bus if present */
    if (server->bus) qihse_cluster_bus_stop(server->bus);
}

void qihse_resp_server_destroy(qihse_resp_server_t* server) {
    if (!server) return;
    qihse_resp_server_stop(server);
    if (server->owns_failover && server->failover) qihse_cluster_failover_destroy(server->failover);
    if (server->owns_bus && server->bus) qihse_cluster_bus_destroy(server->bus);
    if (server->owns_guard_window && server->guard_window) qihse_system_guard_window_destroy(server->guard_window);
    if (server->owns_scatter && server->scatter) qihse_cluster_scatter_destroy(server->scatter);
    if (server->owns_topology) qihse_cluster_topology_destroy(server->topology);
    pthread_mutex_destroy(&server->column_lock);
    pthread_mutex_destroy(&server->tsdb_lock);
    pthread_mutex_destroy(&server->vdb_lock);
    pthread_mutex_destroy(&server->kv_lock);
    pthread_cond_destroy(&server->clients_drained);
    pthread_mutex_destroy(&server->state_lock);
    free(server);
}

uint16_t qihse_resp_server_port(const qihse_resp_server_t* server) {
    return server ? server->port : 0u;
}

qihse_cluster_topology_t* qihse_resp_server_topology(qihse_resp_server_t* server) {
    return server ? server->topology : NULL;
}

qihse_cluster_bus_t* qihse_resp_server_bus(qihse_resp_server_t* server) {
    return server ? server->bus : NULL;
}

qihse_cluster_failover_t* qihse_resp_server_failover(qihse_resp_server_t* server) {
    return server ? server->failover : NULL;
}

qihse_system_guard_window_t* qihse_resp_server_guard_window(qihse_resp_server_t* server) {
    return server ? server->guard_window : NULL;
}

qihse_cluster_scatter_t* qihse_resp_server_scatter(qihse_resp_server_t* server) {
    return server ? server->scatter : NULL;
}

bool qihse_resp_server_handle_client_fd(qihse_resp_server_t* server, int client_fd) {
    if (!server || client_fd < 0) {
        errno = EINVAL;
        return false;
    }
    bool was_running = __atomic_load_n(&server->running, __ATOMIC_ACQUIRE);
    if (!was_running) __atomic_store_n(&server->running, true, __ATOMIC_RELEASE);
    bool result = qihse_resp_session_loop(server, client_fd);
    shutdown(client_fd, SHUT_RDWR);
    close_socket(client_fd);
    if (!was_running) __atomic_store_n(&server->running, false, __ATOMIC_RELEASE);
    return result;
}

bool qihse_resp_engine_handle_legacy(int client_fd, qihse_kv_store_t* store, qihse_vector_db_t vdb) {
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) return false;
    qihse_resp_server_handle_client_fd(server, client_fd);
    qihse_resp_server_destroy(server);
    return true;
}

bool qihse_resp_engine_run_legacy(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address) {
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = port;
    config.bind_address = bind_address ? bind_address : "127.0.0.1";
    config.advertise_address = config.bind_address;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) return false;
    bool result = qihse_resp_server_run(server);
    qihse_resp_server_destroy(server);
    return result;
}
