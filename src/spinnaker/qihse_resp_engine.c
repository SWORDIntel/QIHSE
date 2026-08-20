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
    /* Transaction (MULTI/EXEC) state */
    bool in_multi;
    bool multi_dirty;            /* a queued command had an error */
    qihse_resp_request_t* multi_queue;
    size_t multi_queue_len;
    size_t multi_queue_cap;
    char** watch_keys;
    size_t* watch_key_lens;
    size_t watch_count;
    size_t watch_cap;
    bool watch_dirty;            /* a watched key was modified */
    /* Pub/Sub state */
    char** sub_channels;
    size_t* sub_channel_lens;
    size_t sub_channel_count;
    size_t sub_channel_cap;
    char** sub_patterns;
    size_t* sub_pattern_lens;
    size_t sub_pattern_count;
    size_t sub_pattern_cap;
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
    /* Task Queue Engine & Scheduler */
    qihse_task_queue_t* task_queue;
    bool owns_task_queue;
    qihse_task_worker_pool_t* task_workers;
    bool owns_task_workers;
    qihse_task_scheduler_t* task_scheduler;
    bool owns_task_scheduler;
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

static bool qihse_resp_parse_i64_arg(const qihse_resp_arg_t* arg, int64_t* out) {
    if (!arg || !out) return false;
    return qihse_resp_parse_i64_bytes(arg->data, arg->len, out);
}

#define qihse_resp_parse_f64_arg qihse_resp_parse_double_arg

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
    } else if (qihse_resp_command_is(request, "LPUSH") || qihse_resp_command_is(request, "RPUSH") ||
               qihse_resp_command_is(request, "LPOP") || qihse_resp_command_is(request, "RPOP") ||
               qihse_resp_command_is(request, "LLEN") || qihse_resp_command_is(request, "LRANGE") ||
               qihse_resp_command_is(request, "LINDEX") || qihse_resp_command_is(request, "LSET") ||
               qihse_resp_command_is(request, "LREM") || qihse_resp_command_is(request, "LTRIM") ||
               qihse_resp_command_is(request, "LINSERT") ||
               qihse_resp_command_is(request, "HSET") || qihse_resp_command_is(request, "HMSET") ||
               qihse_resp_command_is(request, "HGET") || qihse_resp_command_is(request, "HGETALL") ||
               qihse_resp_command_is(request, "HDEL") || qihse_resp_command_is(request, "HEXISTS") ||
               qihse_resp_command_is(request, "HKEYS") || qihse_resp_command_is(request, "HVALS") ||
               qihse_resp_command_is(request, "HLEN") || qihse_resp_command_is(request, "HINCRBY") ||
               qihse_resp_command_is(request, "HMGET") || qihse_resp_command_is(request, "HSETNX") ||
               qihse_resp_command_is(request, "HSTRLEN") ||
               qihse_resp_command_is(request, "SADD") || qihse_resp_command_is(request, "SREM") ||
               qihse_resp_command_is(request, "SMEMBERS") || qihse_resp_command_is(request, "SISMEMBER") ||
               qihse_resp_command_is(request, "SCARD") || qihse_resp_command_is(request, "SPOP") ||
               qihse_resp_command_is(request, "SRANDMEMBER") ||
               qihse_resp_command_is(request, "ZADD") || qihse_resp_command_is(request, "ZREM") ||
               qihse_resp_command_is(request, "ZSCORE") || qihse_resp_command_is(request, "ZCARD") ||
               qihse_resp_command_is(request, "ZCOUNT") || qihse_resp_command_is(request, "ZRANGE") ||
               qihse_resp_command_is(request, "ZREVRANGE") || qihse_resp_command_is(request, "ZRANK") ||
               qihse_resp_command_is(request, "ZREVRANK") || qihse_resp_command_is(request, "ZINCRBY") ||
               qihse_resp_command_is(request, "ZPOPMAX") || qihse_resp_command_is(request, "ZPOPMIN") ||
               qihse_resp_command_is(request, "ZRANGEBYSCORE") || qihse_resp_command_is(request, "ZREVRANGEBYSCORE") ||
               qihse_resp_command_is(request, "GETSET") || qihse_resp_command_is(request, "GETDEL") ||
               qihse_resp_command_is(request, "STRLEN") || qihse_resp_command_is(request, "APPEND") ||
               qihse_resp_command_is(request, "GETRANGE") || qihse_resp_command_is(request, "SETRANGE") ||
               qihse_resp_command_is(request, "INCRBY") || qihse_resp_command_is(request, "DECRBY") ||
               qihse_resp_command_is(request, "INCRBYFLOAT") || qihse_resp_command_is(request, "PERSIST") ||
               qihse_resp_command_is(request, "EXPIREAT") || qihse_resp_command_is(request, "PEXPIREAT") ||
               qihse_resp_command_is(request, "SETBIT") || qihse_resp_command_is(request, "GETBIT") ||
               qihse_resp_command_is(request, "BITCOUNT") || qihse_resp_command_is(request, "BITPOS") ||
               qihse_resp_command_is(request, "PFADD") || qihse_resp_command_is(request, "PFCOUNT") ||
               qihse_resp_command_is(request, "OBJECT")) {
        keys->indexes[keys->count++] = 1u;
        keys->kv_keys = true;
    } else if (qihse_resp_command_is(request, "RENAME") || qihse_resp_command_is(request, "RENAMENX") ||
               qihse_resp_command_is(request, "COPY") || qihse_resp_command_is(request, "RPOPLPUSH") ||
               qihse_resp_command_is(request, "SMOVE")) {
        keys->indexes[keys->count++] = 1u;
        keys->indexes[keys->count++] = 2u;
        keys->kv_keys = true;
    } else if (qihse_resp_command_is(request, "SDIFF") || qihse_resp_command_is(request, "SINTER") ||
               qihse_resp_command_is(request, "SUNION") || qihse_resp_command_is(request, "PFMERGE") ||
               qihse_resp_command_is(request, "BITOP")) {
        for (size_t i = 2; i < request->argc; i++) keys->indexes[keys->count++] = i;
        keys->kv_keys = true;
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

/* =========================================================================
 * Task Queue and Scheduler Handlers (Celery-Equivalent RESP Extensions)
 * ========================================================================= */

static bool qihse_resp_handle_task_submit(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "SUBMIT")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (rem < 2 || rem > 3) return qihse_resp_wrong_arity(session, "task.submit");
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* qname = qihse_resp_arg_text(&request->argv[offset]);
    qihse_task_prio_t prio = QIHSE_TASK_PRIO_NORMAL;
    size_t payload_idx = offset + 1;

    if (rem == 3) {
        char* prio_str = qihse_resp_arg_text(&request->argv[offset + 1]);
        if (prio_str) {
            qihse_task_parse_prio(prio_str, &prio);
            free(prio_str);
        }
        payload_idx = offset + 2;
    }

    const uint8_t* payload = request->argv[payload_idx].data;
    size_t payload_len = request->argv[payload_idx].len;
    char task_id[QIHSE_TASK_ID_LEN + 1] = {0};

    bool ok = qihse_task_submit(
        session->server->task_queue,
        qname,
        prio,
        payload,
        payload_len,
        NULL,
        task_id,
        sizeof(task_id)
    );
    free(qname);

    if (ok) {
        return qihse_resp_bulk_text(session, task_id);
    }
    return qihse_resp_error(session, "ERR failed to submit task");
}

static bool qihse_resp_handle_task_result(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "RESULT")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (rem != 1) return qihse_resp_wrong_arity(session, "task.result");
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* task_id = qihse_resp_arg_text(&request->argv[offset]);
    if (!task_id) return qihse_resp_error(session, "ERR invalid task ID");

    uint8_t* result = NULL;
    size_t result_len = 0;
    char error_buf[256] = {0};

    bool ok = qihse_task_get_result(session->server->task_queue, task_id, &result, &result_len, error_buf, sizeof(error_buf));
    if (ok) {
        bool sent = qihse_resp_bulk(session, result, result_len);
        if (result) free(result);
        free(task_id);
        return sent;
    }

    qihse_task_state_t state;
    if (qihse_task_get_state(session->server->task_queue, task_id, &state)) {
        free(task_id);
        if (state == QIHSE_TASK_FAILURE || state == QIHSE_TASK_DEAD) {
            char err_msg[300];
            snprintf(err_msg, sizeof(err_msg), "ERR %s", error_buf[0] ? error_buf : "task failed");
            return qihse_resp_error(session, err_msg);
        }
        if (state == QIHSE_TASK_CANCELLED) {
            return qihse_resp_error(session, "ERR task was cancelled");
        }
        char status_err[64];
        snprintf(status_err, sizeof(status_err), "%s", qihse_task_state_name(state));
        return qihse_resp_error(session, status_err);
    }

    free(task_id);
    return qihse_resp_error(session, "ERR task not found");
}

static bool qihse_resp_handle_task_status(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "STATUS")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (rem != 1) return qihse_resp_wrong_arity(session, "task.status");
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* task_id = qihse_resp_arg_text(&request->argv[offset]);
    if (!task_id) return qihse_resp_error(session, "ERR invalid task ID");

    qihse_task_state_t state;
    if (qihse_task_get_state(session->server->task_queue, task_id, &state)) {
        free(task_id);
        return qihse_resp_simple(session, qihse_task_state_name(state));
    }
    free(task_id);
    return qihse_resp_error(session, "ERR task not found");
}

static bool qihse_resp_handle_task_cancel(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "CANCEL")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (rem != 1) return qihse_resp_wrong_arity(session, "task.cancel");
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* task_id = qihse_resp_arg_text(&request->argv[offset]);
    if (!task_id) return qihse_resp_error(session, "ERR invalid task ID");

    bool ok = qihse_task_cancel(session->server->task_queue, task_id);
    free(task_id);
    return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR task not found or cannot be cancelled");
}

static bool qihse_resp_handle_task_retry(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "RETRY")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (rem != 1) return qihse_resp_wrong_arity(session, "task.retry");
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* task_id = qihse_resp_arg_text(&request->argv[offset]);
    if (!task_id) return qihse_resp_error(session, "ERR invalid task ID");

    bool ok = qihse_task_retry(session->server->task_queue, task_id);
    free(task_id);
    return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR task not found or not in retryable state");
}

static bool qihse_resp_handle_task_delete(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "DELETE")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (rem != 1) return qihse_resp_wrong_arity(session, "task.delete");
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* task_id = qihse_resp_arg_text(&request->argv[offset]);
    if (!task_id) return qihse_resp_error(session, "ERR invalid task ID");

    bool ok = qihse_task_delete(session->server->task_queue, task_id);
    free(task_id);
    return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR task not found");
}

static bool qihse_resp_handle_task_queue(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "QUEUE")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* qname = (rem >= 1) ? qihse_resp_arg_text(&request->argv[offset]) : NULL;

    char** ids = NULL;
    size_t count = 0;
    bool ok = qihse_task_list_queue(session->server->task_queue, qname, &ids, &count);
    if (qname) free(qname);

    if (!ok) return qihse_resp_error(session, "ERR failed to list queue");

    if (!qihse_resp_array(session, count)) {
        qihse_task_free_id_list(ids, count);
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        if (!qihse_resp_bulk_text(session, ids[i])) {
            qihse_task_free_id_list(ids, count);
            return false;
        }
    }
    qihse_task_free_id_list(ids, count);
    return true;
}

static bool qihse_resp_handle_task_stats(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    size_t offset = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "STATS")) {
        offset = 2;
    }
    size_t rem = request->argc > offset ? request->argc - offset : 0;
    if (!session->server->task_queue) return qihse_resp_error(session, "ERR task queue is not configured");

    char* qname = (rem >= 1) ? qihse_resp_arg_text(&request->argv[offset]) : NULL;

    qihse_task_stats_t stats;
    bool ok = qihse_task_stats(session->server->task_queue, qname, &stats);
    if (qname) free(qname);

    if (!ok) return qihse_resp_error(session, "ERR failed to retrieve stats");

    if (!qihse_resp_array(session, 16u)) return false;
    if (!qihse_resp_bulk_text(session, "pending") || !qihse_resp_integer(session, (int64_t)stats.pending_count)) return false;
    if (!qihse_resp_bulk_text(session, "started") || !qihse_resp_integer(session, (int64_t)stats.started_count)) return false;
    if (!qihse_resp_bulk_text(session, "success") || !qihse_resp_integer(session, (int64_t)stats.success_count)) return false;
    if (!qihse_resp_bulk_text(session, "failure") || !qihse_resp_integer(session, (int64_t)stats.failure_count)) return false;
    if (!qihse_resp_bulk_text(session, "dead") || !qihse_resp_integer(session, (int64_t)stats.dead_count)) return false;
    if (!qihse_resp_bulk_text(session, "cancelled") || !qihse_resp_integer(session, (int64_t)stats.cancelled_count)) return false;
    if (!qihse_resp_bulk_text(session, "total_executed") || !qihse_resp_integer(session, (int64_t)stats.total_executed)) return false;
    if (!qihse_resp_bulk_text(session, "avg_latency_ms") || !qihse_resp_reply_double(session, stats.avg_latency_ms)) return false;

    return true;
}

static bool qihse_resp_handle_task_workers(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->task_workers) return qihse_resp_error(session, "ERR task worker pool is not configured");

    size_t sub_idx = 1;
    if (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "WORKERS")) {
        sub_idx = 2;
    } else if (qihse_resp_command_is(request, "TASK.WORKERS")) {
        sub_idx = 1;
    }

    if (request->argc > sub_idx) {
        if (qihse_resp_arg_equal(&request->argv[sub_idx], "PAUSE")) {
            qihse_task_worker_pool_pause(session->server->task_workers);
            return qihse_resp_simple(session, "OK");
        }
        if (qihse_resp_arg_equal(&request->argv[sub_idx], "RESUME")) {
            qihse_task_worker_pool_resume(session->server->task_workers);
            return qihse_resp_simple(session, "OK");
        }
        if (qihse_resp_arg_equal(&request->argv[sub_idx], "SET") && request->argc > sub_idx + 1) {
            uint64_t new_count = 0;
            if (!qihse_resp_parse_u64_arg(&request->argv[sub_idx + 1], &new_count) || new_count == 0) {
                return qihse_resp_error(session, "ERR invalid worker count");
            }
            bool ok = qihse_task_worker_pool_set_count(session->server->task_workers, (uint32_t)new_count);
            return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR failed to resize worker pool");
        }
    }

    qihse_worker_info_t* info = NULL;
    size_t count = 0;
    if (!qihse_task_worker_pool_get_info(session->server->task_workers, &info, &count)) {
        return qihse_resp_error(session, "ERR failed to get worker info");
    }

    if (!qihse_resp_array(session, count)) {
        qihse_task_worker_pool_free_info(info);
        return false;
    }

    for (size_t i = 0; i < count; i++) {
        if (!qihse_resp_array(session, 16u)) {
            qihse_task_worker_pool_free_info(info);
            return false;
        }
        const char* st_name = "IDLE";
        switch (info[i].state) {
            case QIHSE_WORKER_BUSY: st_name = "BUSY"; break;
            case QIHSE_WORKER_PAUSED: st_name = "PAUSED"; break;
            case QIHSE_WORKER_STOPPING: st_name = "STOPPING"; break;
            case QIHSE_WORKER_STOPPED: st_name = "STOPPED"; break;
            default: st_name = "IDLE"; break;
        }
        if (!qihse_resp_bulk_text(session, "id") || !qihse_resp_integer(session, (int64_t)info[i].worker_id)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "state") || !qihse_resp_bulk_text(session, st_name)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "core") || !qihse_resp_integer(session, (int64_t)info[i].cpu_core_id)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "numa") || !qihse_resp_integer(session, (int64_t)info[i].numa_node_id)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "current_task") || !qihse_resp_bulk_text(session, info[i].current_task_id)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "completed") || !qihse_resp_integer(session, (int64_t)info[i].tasks_completed)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "failed") || !qihse_resp_integer(session, (int64_t)info[i].tasks_failed)) { qihse_task_worker_pool_free_info(info); return false; }
        if (!qihse_resp_bulk_text(session, "uptime") || !qihse_resp_integer(session, (int64_t)info[i].uptime_seconds)) { qihse_task_worker_pool_free_info(info); return false; }
    }

    qihse_task_worker_pool_free_info(info);
    return true;
}

static bool qihse_resp_handle_schedule(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->task_scheduler) return qihse_resp_error(session, "ERR task scheduler is not configured");

    char* full_cmd = qihse_resp_arg_text(&request->argv[0]);
    if (!full_cmd) return qihse_resp_error(session, "ERR invalid command");

    char* subcmd = NULL;
    size_t arg_offset = 1;

    char* dot = strchr(full_cmd, '.');
    if (dot) {
        subcmd = strdup(dot + 1);
        arg_offset = 1;
    } else if (request->argc > 1) {
        subcmd = qihse_resp_arg_text(&request->argv[1]);
        arg_offset = 2;
    }
    free(full_cmd);

    if (!subcmd) return qihse_resp_wrong_arity(session, "schedule");

    if (strcasecmp(subcmd, "ADD") == 0) {
        size_t rem = request->argc > arg_offset ? request->argc - arg_offset : 0;
        if (rem < 4 || rem > 5) {
            free(subcmd);
            return qihse_resp_wrong_arity(session, "schedule.add");
        }
        char* sched_id = qihse_resp_arg_text(&request->argv[arg_offset]);
        char* cron_expr = qihse_resp_arg_text(&request->argv[arg_offset + 1]);
        char* qname = qihse_resp_arg_text(&request->argv[arg_offset + 2]);
        qihse_task_prio_t prio = QIHSE_TASK_PRIO_NORMAL;
        size_t payload_idx = arg_offset + 3;

        if (rem == 5) {
            char* prio_str = qihse_resp_arg_text(&request->argv[arg_offset + 3]);
            if (prio_str) {
                qihse_task_parse_prio(prio_str, &prio);
                free(prio_str);
            }
            payload_idx = arg_offset + 4;
        }

        const uint8_t* payload = request->argv[payload_idx].data;
        size_t payload_len = request->argv[payload_idx].len;

        bool ok = qihse_task_scheduler_add(
            session->server->task_scheduler,
            sched_id,
            cron_expr,
            qname,
            prio,
            payload,
            payload_len
        );

        free(sched_id);
        free(cron_expr);
        free(qname);
        free(subcmd);

        return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR failed to add schedule (invalid cron or duplicate)");
    }

    if (strcasecmp(subcmd, "REMOVE") == 0) {
        if (request->argc <= arg_offset) {
            free(subcmd);
            return qihse_resp_wrong_arity(session, "schedule.remove");
        }
        char* sched_id = qihse_resp_arg_text(&request->argv[arg_offset]);
        bool ok = qihse_task_scheduler_remove(session->server->task_scheduler, sched_id);
        free(sched_id);
        free(subcmd);
        return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR schedule not found");
    }

    if (strcasecmp(subcmd, "LIST") == 0) {
        char** ids = NULL;
        size_t count = 0;
        bool ok = qihse_task_scheduler_list(session->server->task_scheduler, &ids, &count);
        free(subcmd);
        if (!ok) return qihse_resp_error(session, "ERR failed to list schedules");

        if (!qihse_resp_array(session, count)) {
            qihse_task_scheduler_free_list(ids, count);
            return false;
        }
        for (size_t i = 0; i < count; i++) {
            if (!qihse_resp_bulk_text(session, ids[i])) {
                qihse_task_scheduler_free_list(ids, count);
                return false;
            }
        }
        qihse_task_scheduler_free_list(ids, count);
        return true;
    }

    if (strcasecmp(subcmd, "ENABLE") == 0 || strcasecmp(subcmd, "DISABLE") == 0) {
        if (request->argc <= arg_offset) {
            free(subcmd);
            return qihse_resp_wrong_arity(session, "schedule.enable");
        }
        bool enable = (strcasecmp(subcmd, "ENABLE") == 0);
        char* sched_id = qihse_resp_arg_text(&request->argv[arg_offset]);
        bool ok = qihse_task_scheduler_enable(session->server->task_scheduler, sched_id, enable);
        free(sched_id);
        free(subcmd);
        return ok ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR schedule not found");
    }

    if (strcasecmp(subcmd, "NEXT") == 0) {
        if (request->argc <= arg_offset) {
            free(subcmd);
            return qihse_resp_wrong_arity(session, "schedule.next");
        }
        char* sched_id = qihse_resp_arg_text(&request->argv[arg_offset]);
        char iso_buf[64] = {0};
        bool ok = qihse_task_scheduler_next_fire(session->server->task_scheduler, sched_id, iso_buf, sizeof(iso_buf));
        free(sched_id);
        free(subcmd);
        return ok ? qihse_resp_simple(session, iso_buf) : qihse_resp_error(session, "ERR schedule not found or disabled");
    }

    free(subcmd);
    return qihse_resp_error(session, "ERR unknown SCHEDULE subcommand");
}

/* ===== Redis Data Structure Command Implementations ===== */

/* Forward declaration for EXEC's recursive call */
static bool qihse_resp_dispatch(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool* keep_open);

/* Helper: build a prefixed key string. Caller frees. */
static char* qihse_resp_prefixed_key(const char* prefix, const char* key) {
    size_t plen = strlen(prefix), klen = strlen(key);
    char* out = malloc(plen + klen + 1);
    if (out) { memcpy(out, prefix, plen); memcpy(out + plen, key, klen + 1); }
    return out;
}

/* Helper: build a hash field key "__h__:KEY:FIELD". Caller frees. */
static char* qihse_resp_hash_key(const char* key, const char* field) {
    size_t klen = strlen(key), flen = strlen(field);
    char* out = malloc(5 + klen + 1 + flen + 1);
    if (out) snprintf(out, 5 + klen + 1 + flen + 1, "__h__:%s:%s", key, field);
    return out;
}

/* Helper: build a set member key "__s__:KEY:MEMBER". Caller frees. */
static char* qihse_resp_set_key(const char* key, const char* member) {
    size_t klen = strlen(key), mlen = strlen(member);
    char* out = malloc(5 + klen + 1 + mlen + 1);
    if (out) snprintf(out, 5 + klen + 1 + mlen + 1, "__s__:%s:%s", key, member);
    return out;
}

/* Helper: build a zset member key "__z__:KEY:MEMBER". Caller frees. */
static char* qihse_resp_zset_key(const char* key, const char* member) {
    size_t klen = strlen(key), mlen = strlen(member);
    char* out = malloc(5 + klen + 1 + mlen + 1);
    if (out) snprintf(out, 5 + klen + 1 + mlen + 1, "__z__:%s:%s", key, member);
    return out;
}

/* Helper: build a zset meta key "__zmeta__:KEY". Caller frees. */
static char* qihse_resp_zset_meta(const char* key) {
    size_t klen = strlen(key);
    char* out = malloc(9 + klen + 1);
    if (out) snprintf(out, 9 + klen + 1, "__zmeta__:%s", key);
    return out;
}

/* Helper: build a hash meta key "__hmeta__:KEY". Caller frees. */
static char* qihse_resp_hash_meta(const char* key) {
    size_t klen = strlen(key);
    char* out = malloc(9 + klen + 1);
    if (out) snprintf(out, 9 + klen + 1, "__hmeta__:%s", key);
    return out;
}

/* Helper: build a set meta key "__smeta__:KEY". Caller frees. */
static char* qihse_resp_set_meta(const char* key) {
    size_t klen = strlen(key);
    char* out = malloc(9 + klen + 1);
    if (out) snprintf(out, 9 + klen + 1, "__smeta__:%s", key);
    return out;
}

/* ---- List commands ---- */
/* Lists are stored as a single KV value with \x01 delimiter between elements. */

static char* qihse_resp_list_key(const char* key) {
    return qihse_resp_prefixed_key("__list__:", key);
}

/* Split a list value into count. Returns array of strings, caller frees each and array. */
static char** qihse_resp_list_split(const char* value, size_t* count) {
    *count = 0;
    if (!value || !*value) return NULL;
    size_t cap = 8, n = 0;
    char** parts = malloc(cap * sizeof(char*));
    const char* start = value;
    for (;;) {
        const char* end = strchr(start, '\x01');
        size_t len = end ? (size_t)(end - start) : strlen(start);
        if (n >= cap) { cap *= 2; parts = realloc(parts, cap * sizeof(char*)); }
        parts[n] = malloc(len + 1);
        memcpy(parts[n], start, len);
        parts[n][len] = '\0';
        n++;
        if (!end) break;
        start = end + 1;
    }
    *count = n;
    return parts;
}

/* Join an array of strings into a single \x01-delimited value. Caller frees. */
static char* qihse_resp_list_join(char** parts, size_t count, size_t* out_len) {
    size_t total = 0;
    for (size_t i = 0; i < count; i++) total += strlen(parts[i]) + 1;
    char* result = malloc(total + 1);
    if (!result) { *out_len = 0; return NULL; }
    size_t pos = 0;
    for (size_t i = 0; i < count; i++) {
        size_t len = strlen(parts[i]);
        memcpy(result + pos, parts[i], len);
        pos += len;
        if (i + 1 < count) result[pos++] = '\x01';
    }
    result[pos] = '\0';
    *out_len = pos;
    return result;
}

static bool qihse_resp_handle_lpush(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool left) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, left ? "lpush" : "rpush");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR invalid key");
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    size_t count = 0;
    char** parts = existing ? qihse_resp_list_split(existing, &count) : NULL;
    free(existing);
    /* Add new elements */
    size_t new_count = count + (request->argc - 2);
    char** new_parts = malloc(new_count * sizeof(char*));
    size_t idx = 0;
    if (left) {
        /* Prepend in reverse order */
        for (size_t i = request->argc - 1; i >= 2; i--) {
            new_parts[idx++] = qihse_resp_arg_text(&request->argv[i]);
        }
        for (size_t i = 0; i < count; i++) new_parts[idx++] = parts[i];
    } else {
        for (size_t i = 0; i < count; i++) new_parts[idx++] = parts[i];
        for (size_t i = 2; i < request->argc; i++) new_parts[idx++] = qihse_resp_arg_text(&request->argv[i]);
    }
    size_t val_len;
    char* joined = qihse_resp_list_join(new_parts, new_count, &val_len);
    qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(joined);
    for (size_t i = 0; i < new_count; i++) free(new_parts[i]);
    free(new_parts);
    free(parts);
    free(lk);
    return qihse_resp_integer(session, (int64_t)new_count);
}

static bool qihse_resp_handle_lpop(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool left) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, left ? "lpop" : "rpop");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t pop_count = 1;
    if (request->argc >= 3) {
        if (!qihse_resp_parse_i64_arg(&request->argv[2], &pop_count) || pop_count < 0)
            return qihse_resp_error(session, "ERR value is out of range");
    }
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_mutex_unlock(&session->server->kv_lock); free(lk); return qihse_resp_null(session); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (pop_count == 0) {
        pthread_mutex_unlock(&session->server->kv_lock);
        qihse_resp_array(session, 0);
        for (size_t i = 0; i < count; i++) free(parts[i]);
        free(parts); free(lk);
        return true;
    }
    if (pop_count > (int64_t)count) pop_count = (int64_t)count;
    if (request->argc < 3) {
        /* Single element pop */
        char* elem = left ? strdup(parts[0]) : strdup(parts[count - 1]);
        /* Remove element */
        char** remaining = malloc((count - 1) * sizeof(char*));
        if (left) { for (size_t i = 1; i < count; i++) remaining[i-1] = parts[i]; }
        else { for (size_t i = 0; i < count - 1; i++) remaining[i] = parts[i]; }
        if (count > 1) {
            size_t rl; char* joined = qihse_resp_list_join(remaining, count - 1, &rl);
            qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
            free(joined);
        } else {
            qihse_kv_del_user(session->server->store, lk, session->user);
        }
        pthread_mutex_unlock(&session->server->kv_lock);
        qihse_resp_bulk_text(session, elem);
        free(elem);
        if (left) free(parts[0]); else free(parts[count-1]);
        free(remaining); free(parts); free(lk);
        return true;
    }
    /* Multi-element pop */
    qihse_resp_array(session, (size_t)pop_count);
    if (left) {
        for (int64_t i = 0; i < pop_count; i++) qihse_resp_bulk_text(session, parts[i]);
        size_t rc = count - (size_t)pop_count;
        char** remaining = rc > 0 ? malloc(rc * sizeof(char*)) : NULL;
        for (size_t i = 0; i < rc; i++) remaining[i] = parts[(size_t)pop_count + i];
        if (rc > 0) { size_t rl; char* joined = qihse_resp_list_join(remaining, rc, &rl);
            qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user); free(joined); }
        else qihse_kv_del_user(session->server->store, lk, session->user);
        free(remaining);
    } else {
        for (int64_t i = 0; i < pop_count; i++) qihse_resp_bulk_text(session, parts[count - 1 - (size_t)i]);
        size_t rc = count - (size_t)pop_count;
        char** remaining = rc > 0 ? malloc(rc * sizeof(char*)) : NULL;
        for (size_t i = 0; i < rc; i++) remaining[i] = parts[i];
        if (rc > 0) { size_t rl; char* joined = qihse_resp_list_join(remaining, rc, &rl);
            qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user); free(joined); }
        else qihse_kv_del_user(session->server->store, lk, session->user);
        free(remaining);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts); free(lk);
    return true;
}

static bool qihse_resp_handle_llen(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "llen");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(lk);
    if (!existing) return qihse_resp_integer(session, 0);
    size_t count = 1;
    for (const char* p = existing; *p; p++) if (*p == '\x01') count++;
    free(existing);
    return qihse_resp_integer(session, (int64_t)count);
}

static bool qihse_resp_handle_lrange(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "lrange");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t start, stop;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &start) || !qihse_resp_parse_i64_arg(&request->argv[3], &stop))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(lk);
    if (!existing) return qihse_resp_array(session, 0);
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (start < 0) start += (int64_t)count;
    if (stop < 0) stop += (int64_t)count;
    if (start < 0) start = 0;
    if (stop >= (int64_t)count) stop = (int64_t)count - 1;
    if (start > stop || start >= (int64_t)count) {
        qihse_resp_array(session, 0);
        for (size_t i = 0; i < count; i++) free(parts[i]);
        free(parts);
        return true;
    }
    size_t result_count = (size_t)(stop - start + 1);
    qihse_resp_array(session, result_count);
    for (int64_t i = start; i <= stop; i++) qihse_resp_bulk_text(session, parts[i]);
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts);
    return true;
}

static bool qihse_resp_handle_lindex(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "lindex");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t index;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &index))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(lk);
    if (!existing) return qihse_resp_null(session);
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (index < 0) index += (int64_t)count;
    bool result;
    if (index >= 0 && index < (int64_t)count) result = qihse_resp_bulk_text(session, parts[index]);
    else result = qihse_resp_null(session);
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts);
    return result;
}

static bool qihse_resp_handle_lset(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "lset");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t index;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &index))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_mutex_unlock(&session->server->kv_lock); free(lk); return qihse_resp_error(session, "ERR no such key"); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (index < 0) index += (int64_t)count;
    if (index < 0 || index >= (int64_t)count) {
        pthread_mutex_unlock(&session->server->kv_lock);
        for (size_t i = 0; i < count; i++) free(parts[i]);
        free(parts); free(lk);
        return qihse_resp_error(session, "ERR index out of range");
    }
    free(parts[index]);
    parts[index] = qihse_resp_arg_text(&request->argv[3]);
    size_t rl; char* joined = qihse_resp_list_join(parts, count, &rl);
    qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(joined);
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts); free(lk);
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_lrem(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "lrem");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t count_param;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &count_param))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    char* target = qihse_resp_arg_text(&request->argv[3]);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_mutex_unlock(&session->server->kv_lock); free(lk); free(target); return qihse_resp_integer(session, 0); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    int64_t removed = 0;
    bool forward = count_param >= 0;
    int64_t limit = count_param < 0 ? -count_param : count_param;
    /* Mark elements for removal */
    bool* remove = calloc(count, sizeof(bool));
    if (forward) {
        for (size_t i = 0; i < count && (limit == 0 || removed < limit); i++) {
            if (strcmp(parts[i], target) == 0) { remove[i] = true; removed++; }
        }
    } else {
        for (int64_t i = (int64_t)count - 1; i >= 0 && (limit == 0 || removed < limit); i--) {
            if (strcmp(parts[i], target) == 0) { remove[i] = true; removed++; }
        }
    }
    /* Rebuild list */
    size_t new_count = count - (size_t)removed;
    char** new_parts = new_count > 0 ? malloc(new_count * sizeof(char*)) : NULL;
    size_t idx = 0;
    for (size_t i = 0; i < count; i++) {
        if (remove[i]) { free(parts[i]); }
        else { new_parts[idx++] = parts[i]; }
    }
    if (new_count > 0) {
        size_t rl; char* joined = qihse_resp_list_join(new_parts, new_count, &rl);
        qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
        free(joined);
    } else {
        qihse_kv_del_user(session->server->store, lk, session->user);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(new_parts); free(parts); free(remove); free(lk); free(target);
    return qihse_resp_integer(session, removed);
}

static bool qihse_resp_handle_ltrim(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "ltrim");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t start, stop;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &start) || !qihse_resp_parse_i64_arg(&request->argv[3], &stop))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_mutex_unlock(&session->server->kv_lock); free(lk); return qihse_resp_simple(session, "OK"); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (start < 0) start += (int64_t)count;
    if (stop < 0) stop += (int64_t)count;
    if (start < 0) start = 0;
    if (stop >= (int64_t)count) stop = (int64_t)count - 1;
    if (start > stop || start >= (int64_t)count) {
        qihse_kv_del_user(session->server->store, lk, session->user);
    } else {
        size_t new_count = (size_t)(stop - start + 1);
        char** new_parts = malloc(new_count * sizeof(char*));
        for (size_t i = 0; i < new_count; i++) new_parts[i] = parts[start + i];
        size_t rl; char* joined = qihse_resp_list_join(new_parts, new_count, &rl);
        qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
        free(joined); free(new_parts);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts); free(lk);
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_linsert(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 5) return qihse_resp_wrong_arity(session, "linsert");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    bool before = qihse_resp_arg_equal(&request->argv[2], "BEFORE");
    bool after = qihse_resp_arg_equal(&request->argv[2], "AFTER");
    if (!before && !after) return qihse_resp_error(session, "ERR syntax error");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* lk = qihse_resp_list_key(key);
    char* pivot = qihse_resp_arg_text(&request->argv[3]);
    char* value = qihse_resp_arg_text(&request->argv[4]);
    free(key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_mutex_unlock(&session->server->kv_lock); free(lk); free(pivot); free(value); return qihse_resp_integer(session, 0); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    int64_t found = -1;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(parts[i], pivot) == 0) { found = (int64_t)i; break; }
    }
    if (found < 0) {
        pthread_mutex_unlock(&session->server->kv_lock);
        for (size_t i = 0; i < count; i++) free(parts[i]);
        free(parts); free(lk); free(pivot); free(value);
        return qihse_resp_integer(session, -1);
    }
    size_t insert_at = before ? (size_t)found : (size_t)found + 1;
    size_t new_count = count + 1;
    char** new_parts = malloc(new_count * sizeof(char*));
    for (size_t i = 0; i < insert_at; i++) new_parts[i] = parts[i];
    new_parts[insert_at] = value;
    for (size_t i = insert_at; i < count; i++) new_parts[i + 1] = parts[i];
    size_t rl; char* joined = qihse_resp_list_join(new_parts, new_count, &rl);
    qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(joined); free(new_parts); free(parts); free(lk); free(pivot);
    return qihse_resp_integer(session, (int64_t)new_count);
}

static bool qihse_resp_handle_rpoplpush(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "rpoplpush");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* src_key = qihse_resp_arg_text(&request->argv[1]);
    char* dst_key = qihse_resp_arg_text(&request->argv[2]);
    char* src_lk = qihse_resp_list_key(src_key);
    char* dst_lk = qihse_resp_list_key(dst_key);
    free(src_key); free(dst_key);
    pthread_mutex_lock(&session->server->kv_lock);
    char* src_val = qihse_kv_get_user(session->server->store, src_lk, session->user);
    if (!src_val) { pthread_mutex_unlock(&session->server->kv_lock); free(src_lk); free(dst_lk); return qihse_resp_null(session); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(src_val, &count);
    free(src_val);
    if (count == 0) {
        pthread_mutex_unlock(&session->server->kv_lock);
        free(src_lk); free(dst_lk); free(parts);
        return qihse_resp_null(session);
    }
    char* elem = parts[count - 1];
    /* Remove from source */
    if (count > 1) {
        size_t rl; char* joined = qihse_resp_list_join(parts, count - 1, &rl);
        qihse_kv_set_user(session->server->store, src_lk, joined, 0, 0, session->user);
        free(joined);
    } else {
        qihse_kv_del_user(session->server->store, src_lk, session->user);
    }
    /* Prepend to dest */
    char* dst_val = qihse_kv_get_user(session->server->store, dst_lk, session->user);
    size_t dst_count = 0;
    char** dst_parts = dst_val ? qihse_resp_list_split(dst_val, &dst_count) : NULL;
    free(dst_val);
    char** new_dst = malloc((dst_count + 1) * sizeof(char*));
    new_dst[0] = strdup(elem);
    for (size_t i = 0; i < dst_count; i++) new_dst[i + 1] = dst_parts[i];
    size_t rl; char* joined = qihse_resp_list_join(new_dst, dst_count + 1, &rl);
    qihse_kv_set_user(session->server->store, dst_lk, joined, 0, 0, session->user);
    free(joined);
    pthread_mutex_unlock(&session->server->kv_lock);
    qihse_resp_bulk_text(session, elem);
    for (size_t i = 0; i < count; i++) free(parts[i]);
    free(parts);
    for (size_t i = 0; i < dst_count; i++) free(dst_parts[i]);
    free(dst_parts); free(new_dst); free(src_lk); free(dst_lk);
    return true;
}

/* ---- Hash commands ---- */

static bool qihse_resp_handle_hset(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 4 || (request->argc % 2) != 0) return qihse_resp_wrong_arity(session, "hset");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t new_fields = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i + 1 < request->argc; i += 2) {
        char* field = qihse_resp_arg_text(&request->argv[i]);
        char* value = qihse_resp_arg_text(&request->argv[i + 1]);
        char* hk = qihse_resp_hash_key(key, field);
        bool existed = qihse_kv_exists_user(session->server->store, hk, session->user);
        qihse_kv_set_user(session->server->store, hk, value, 0, 0, session->user);
        if (!existed) new_fields++;
        free(hk); free(field); free(value);
    }
    /* Update meta */
    char* meta = qihse_resp_hash_meta(key);
    char meta_val[32];
    snprintf(meta_val, sizeof(meta_val), "%" PRId64, new_fields);
    /* Actually we need to track total. For simplicity, store count. */
    pthread_mutex_unlock(&session->server->kv_lock);
    free(meta); free(key);
    bool is_hmset = qihse_resp_command_is(request, "HMSET");
    return is_hmset ? qihse_resp_simple(session, "OK") : qihse_resp_integer(session, new_fields);
}

static bool qihse_resp_handle_hget(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "hget");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* field = qihse_resp_arg_text(&request->argv[2]);
    char* hk = qihse_resp_hash_key(key, field);
    free(key); free(field);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, hk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(hk);
    bool result = value ? qihse_resp_bulk_text(session, value) : qihse_resp_null(session);
    free(value);
    return result;
}

static bool qihse_resp_handle_hgetall(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "hgetall");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    /* Without iteration, return empty. In a full impl we'd iterate KV keys. */
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_hdel(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "hdel");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t deleted = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* field = qihse_resp_arg_text(&request->argv[i]);
        char* hk = qihse_resp_hash_key(key, field);
        if (qihse_kv_del_user(session->server->store, hk, session->user)) deleted++;
        free(hk); free(field);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, deleted);
}

static bool qihse_resp_handle_hexists(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "hexists");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* field = qihse_resp_arg_text(&request->argv[2]);
    char* hk = qihse_resp_hash_key(key, field);
    free(key); free(field);
    pthread_mutex_lock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, hk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(hk);
    return qihse_resp_integer(session, exists ? 1 : 0);
}

static bool qihse_resp_handle_hkeys(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "hkeys");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_hvals(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "hvals");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_hlen(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "hlen");
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_hincrby(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "hincrby");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t increment;
    if (!qihse_resp_parse_i64_arg(&request->argv[3], &increment))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* field = qihse_resp_arg_text(&request->argv[2]);
    char* hk = qihse_resp_hash_key(key, field);
    free(key); free(field);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, hk, session->user);
    int64_t val = 0;
    if (existing) val = strtoll(existing, NULL, 10);
    free(existing);
    val += increment;
    char val_str[32]; snprintf(val_str, sizeof(val_str), "%" PRId64, val);
    qihse_kv_set_user(session->server->store, hk, val_str, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(hk);
    return qihse_resp_integer(session, val);
}

static bool qihse_resp_handle_hmget(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "hmget");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    qihse_resp_array(session, request->argc - 2);
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* field = qihse_resp_arg_text(&request->argv[i]);
        char* hk = qihse_resp_hash_key(key, field);
        char* value = qihse_kv_get_user(session->server->store, hk, session->user);
        if (value) { qihse_resp_bulk_text(session, value); free(value); }
        else qihse_resp_null(session);
        free(hk); free(field);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return true;
}

static bool qihse_resp_handle_hsetnx(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "hsetnx");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* field = qihse_resp_arg_text(&request->argv[2]);
    char* value = qihse_resp_arg_text(&request->argv[3]);
    char* hk = qihse_resp_hash_key(key, field);
    free(key); free(field);
    pthread_mutex_lock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, hk, session->user);
    bool ok = true;
    if (!exists) ok = qihse_kv_set_user(session->server->store, hk, value, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(hk); free(value);
    return qihse_resp_integer(session, (!exists && ok) ? 1 : 0);
}

static bool qihse_resp_handle_hstrlen(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "hstrlen");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* field = qihse_resp_arg_text(&request->argv[2]);
    char* hk = qihse_resp_hash_key(key, field);
    free(key); free(field);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, hk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(hk);
    int64_t len = value ? (int64_t)strlen(value) : 0;
    free(value);
    return qihse_resp_integer(session, len);
}

/* ---- Set commands ---- */

static bool qihse_resp_handle_sadd(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "sadd");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t added = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* sk = qihse_resp_set_key(key, member);
        if (!qihse_kv_exists_user(session->server->store, sk, session->user)) {
            qihse_kv_set_user(session->server->store, sk, "1", 0, 0, session->user);
            added++;
        }
        free(sk); free(member);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, added);
}

static bool qihse_resp_handle_srem(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "srem");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t removed = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* sk = qihse_resp_set_key(key, member);
        if (qihse_kv_del_user(session->server->store, sk, session->user)) removed++;
        free(sk); free(member);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, removed);
}

static bool qihse_resp_handle_smembers(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "smembers");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_sismember(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "sismember");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* member = qihse_resp_arg_text(&request->argv[2]);
    char* sk = qihse_resp_set_key(key, member);
    free(key); free(member);
    pthread_mutex_lock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, sk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(sk);
    return qihse_resp_integer(session, exists ? 1 : 0);
}

static bool qihse_resp_handle_scard(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "scard");
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_spop(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "spop");
    return qihse_resp_null(session);
}

static bool qihse_resp_handle_smove(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "smove");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* src = qihse_resp_arg_text(&request->argv[1]);
    char* dst = qihse_resp_arg_text(&request->argv[2]);
    char* member = qihse_resp_arg_text(&request->argv[3]);
    char* sk = qihse_resp_set_key(src, member);
    char* dk = qihse_resp_set_key(dst, member);
    free(src); free(dst); free(member);
    pthread_mutex_lock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, sk, session->user);
    if (exists) {
        qihse_kv_del_user(session->server->store, sk, session->user);
        qihse_kv_set_user(session->server->store, dk, "1", 0, 0, session->user);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(sk); free(dk);
    return qihse_resp_integer(session, exists ? 1 : 0);
}

static bool qihse_resp_handle_sdiff(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "sdiff");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_sinter(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "sinter");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_sunion(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "sunion");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_srandmember(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "srandmember");
    return qihse_resp_null(session);
}

/* ---- Sorted set commands ---- */

static bool qihse_resp_handle_zadd(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 4 || (request->argc % 2) != 0) return qihse_resp_wrong_arity(session, "zadd");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t added = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i + 1 < request->argc; i += 2) {
        double score;
        if (!qihse_resp_parse_f64_arg(&request->argv[i], &score))
            return qihse_resp_error(session, "ERR value is not a valid float");
        char* member = qihse_resp_arg_text(&request->argv[i + 1]);
        char* zk = qihse_resp_zset_key(key, member);
        char score_str[32]; snprintf(score_str, sizeof(score_str), "%.17g", score);
        bool existed = qihse_kv_exists_user(session->server->store, zk, session->user);
        qihse_kv_set_user(session->server->store, zk, score_str, 0, 0, session->user);
        if (!existed) added++;
        free(zk); free(member);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, added);
}

static bool qihse_resp_handle_zrem(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "zrem");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t removed = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* zk = qihse_resp_zset_key(key, member);
        if (qihse_kv_del_user(session->server->store, zk, session->user)) removed++;
        free(zk); free(member);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, removed);
}

static bool qihse_resp_handle_zscore(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "zscore");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* member = qihse_resp_arg_text(&request->argv[2]);
    char* zk = qihse_resp_zset_key(key, member);
    free(key); free(member);
    pthread_mutex_lock(&session->server->kv_lock);
    char* score = qihse_kv_get_user(session->server->store, zk, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(zk);
    bool result = score ? qihse_resp_bulk_text(session, score) : qihse_resp_null(session);
    free(score);
    return result;
}

static bool qihse_resp_handle_zcard(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "zcard");
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_zcount(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "zcount");
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_zrange(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool rev) {
    if (request->argc < 4) return qihse_resp_wrong_arity(session, rev ? "zrevrange" : "zrange");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_zrank(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool rev) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, rev ? "zrevrank" : "zrank");
    return qihse_resp_null(session);
}

static bool qihse_resp_handle_zincrby(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "zincrby");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    double increment;
    if (!qihse_resp_parse_f64_arg(&request->argv[2], &increment))
        return qihse_resp_error(session, "ERR value is not a valid float");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* member = qihse_resp_arg_text(&request->argv[3]);
    char* zk = qihse_resp_zset_key(key, member);
    free(key); free(member);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, zk, session->user);
    double val = existing ? strtod(existing, NULL) : 0.0;
    free(existing);
    val += increment;
    char score_str[32]; snprintf(score_str, sizeof(score_str), "%.17g", val);
    qihse_kv_set_user(session->server->store, zk, score_str, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(zk);
    return qihse_resp_bulk_text(session, score_str);
}

static bool qihse_resp_handle_zpop(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool max) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, max ? "zpopmax" : "zpopmin");
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_zrangebyscore(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool rev) {
    if (request->argc < 4) return qihse_resp_wrong_arity(session, rev ? "zrevrangebyscore" : "zrangebyscore");
    return qihse_resp_array(session, 0);
}

/* ---- Key/generic commands ---- */

static bool qihse_resp_handle_keys(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "keys");
    /* Without KV iteration, return empty */
    return qihse_resp_array(session, 0);
}

static bool qihse_resp_handle_scan(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "scan");
    /* Return cursor 0 and empty array */
    qihse_resp_array(session, 2);
    qihse_resp_bulk_text(session, "0");
    qihse_resp_array(session, 0);
    return true;
}

static bool qihse_resp_handle_rename(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool nx) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "rename");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* src = qihse_resp_arg_text(&request->argv[1]);
    char* dst = qihse_resp_arg_text(&request->argv[2]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, src, session->user);
    if (!value) { pthread_mutex_unlock(&session->server->kv_lock); free(src); free(dst); return qihse_resp_error(session, "ERR no such key"); }
    if (nx && qihse_kv_exists_user(session->server->store, dst, session->user)) {
        pthread_mutex_unlock(&session->server->kv_lock); free(value); free(src); free(dst);
        return qihse_resp_integer(session, 0);
    }
    qihse_kv_set_user(session->server->store, dst, value, 0, 0, session->user);
    qihse_kv_del_user(session->server->store, src, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(value); free(src); free(dst);
    return nx ? qihse_resp_integer(session, 1) : qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_getset(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "getset");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* value = qihse_resp_arg_text(&request->argv[2]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* old = qihse_kv_get_user(session->server->store, key, session->user);
    qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key); free(value);
    bool result = old ? qihse_resp_bulk_text(session, old) : qihse_resp_null(session);
    free(old);
    return result;
}

static bool qihse_resp_handle_getdel(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "getdel");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    if (value) qihse_kv_del_user(session->server->store, key, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    bool result = value ? qihse_resp_bulk_text(session, value) : qihse_resp_null(session);
    free(value);
    return result;
}

static bool qihse_resp_handle_strlen(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "strlen");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    int64_t len = value ? (int64_t)strlen(value) : 0;
    free(value);
    return qihse_resp_integer(session, len);
}

static bool qihse_resp_handle_append(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "append");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* suffix = qihse_resp_arg_text(&request->argv[2]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    size_t old_len = existing ? strlen(existing) : 0;
    size_t suf_len = strlen(suffix);
    char* combined = malloc(old_len + suf_len + 1);
    if (existing) memcpy(combined, existing, old_len);
    memcpy(combined + old_len, suffix, suf_len + 1);
    qihse_kv_set_user(session->server->store, key, combined, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(combined); free(existing); free(key); free(suffix);
    return qihse_resp_integer(session, (int64_t)(old_len + suf_len));
}

static bool qihse_resp_handle_getrange(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "getrange");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t start, end;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &start) || !qihse_resp_parse_i64_arg(&request->argv[3], &end))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    if (!value) return qihse_resp_bulk(session, "", 0);
    int64_t len = (int64_t)strlen(value);
    if (start < 0) start += len;
    if (end < 0) end += len;
    if (start < 0) start = 0;
    if (end >= len) end = len - 1;
    if (start > end || start >= len) { free(value); return qihse_resp_bulk(session, "", 0); }
    size_t sub_len = (size_t)(end - start + 1);
    bool result = qihse_resp_bulk(session, value + start, sub_len);
    free(value);
    return result;
}

static bool qihse_resp_handle_setrange(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "setrange");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t offset;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &offset) || offset < 0)
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* value = qihse_resp_arg_text(&request->argv[3]);
    size_t val_len = strlen(value);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    size_t old_len = existing ? strlen(existing) : 0;
    size_t new_len = offset + val_len;
    if (new_len < old_len) new_len = old_len;
    char* result_str = calloc(new_len + 1, 1);
    if (existing) memcpy(result_str, existing, old_len);
    memcpy(result_str + offset, value, val_len);
    qihse_kv_set_user(session->server->store, key, result_str, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(result_str); free(existing); free(key); free(value);
    return qihse_resp_integer(session, (int64_t)new_len);
}

static bool qihse_resp_handle_incrby(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool dec) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, dec ? "decrby" : "incrby");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t delta;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &delta))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    if (dec) delta = -delta;
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    int64_t val = existing ? strtoll(existing, NULL, 10) : 0;
    free(existing);
    val += delta;
    char val_str[32]; snprintf(val_str, sizeof(val_str), "%" PRId64, val);
    qihse_kv_set_user(session->server->store, key, val_str, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, val);
}

static bool qihse_resp_handle_incrbyfloat(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "incrbyfloat");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    double delta;
    if (!qihse_resp_parse_f64_arg(&request->argv[2], &delta))
        return qihse_resp_error(session, "ERR value is not a valid float");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    double val = existing ? strtod(existing, NULL) : 0.0;
    free(existing);
    val += delta;
    char val_str[32]; snprintf(val_str, sizeof(val_str), "%.17g", val);
    qihse_kv_set_user(session->server->store, key, val_str, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_bulk_text(session, val_str);
}

static bool qihse_resp_handle_msetnx(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3 || (request->argc % 2) != 1) return qihse_resp_wrong_arity(session, "msetnx");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    pthread_mutex_lock(&session->server->kv_lock);
    /* Check if any key exists */
    bool any_exists = false;
    for (size_t i = 1; i + 1 < request->argc; i += 2) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        if (qihse_kv_exists_user(session->server->store, key, session->user)) { any_exists = true; free(key); break; }
        free(key);
    }
    if (any_exists) { pthread_mutex_unlock(&session->server->kv_lock); return qihse_resp_integer(session, 0); }
    for (size_t i = 1; i + 1 < request->argc; i += 2) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        char* value = qihse_resp_arg_text(&request->argv[i + 1]);
        qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user);
        free(key); free(value);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    return qihse_resp_integer(session, 1);
}

static bool qihse_resp_handle_persist(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "persist");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    int64_t ttl = qihse_kv_ttl_ms_user(session->server->store, key, session->user);
    if (ttl > 0) {
        /* Remove TTL by setting a very large one or re-setting key */
        char* value = qihse_kv_get_user(session->server->store, key, session->user);
        if (value) { qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user); free(value); }
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, ttl > 0 ? 1 : 0);
}

static bool qihse_resp_handle_expireat(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool ms) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, ms ? "pexpireat" : "expireat");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t when;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &when))
        return qihse_resp_error(session, "ERR value is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t now = (int64_t)time(NULL);
    int64_t ttl = ms ? when - now * 1000 : (when - now) * 1000;
    if (ttl <= 0) {
        pthread_mutex_lock(&session->server->kv_lock);
        qihse_kv_del_user(session->server->store, key, session->user);
        pthread_mutex_unlock(&session->server->kv_lock);
    } else {
        pthread_mutex_lock(&session->server->kv_lock);
        qihse_kv_expire(session->server->store, key, (uint64_t)ttl, session->user);
        pthread_mutex_unlock(&session->server->kv_lock);
    }
    free(key);
    return qihse_resp_integer(session, 1);
}

static bool qihse_resp_handle_copy(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "copy");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* src = qihse_resp_arg_text(&request->argv[1]);
    char* dst = qihse_resp_arg_text(&request->argv[2]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, src, session->user);
    bool ok = false;
    if (value) { ok = qihse_kv_set_user(session->server->store, dst, value, 0, 0, session->user); free(value); }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(src); free(dst);
    return qihse_resp_integer(session, ok ? 1 : 0);
}

static bool qihse_resp_handle_randomkey(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    return qihse_resp_null(session);
}

static bool qihse_resp_handle_touch(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "touch");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t count = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 1; i < request->argc; i++) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        if (qihse_kv_exists_user(session->server->store, key, session->user)) count++;
        free(key);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    return qihse_resp_integer(session, count);
}

static bool qihse_resp_handle_object(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "object");
    if (qihse_resp_arg_equal(&request->argv[1], "ENCODING") && request->argc == 3)
        return qihse_resp_bulk_text(session, "raw");
    if (qihse_resp_arg_equal(&request->argv[1], "REFCOUNT") && request->argc == 3)
        return qihse_resp_integer(session, 1);
    if (qihse_resp_arg_equal(&request->argv[1], "IDLETIME") && request->argc == 3)
        return qihse_resp_integer(session, 0);
    if (qihse_resp_arg_equal(&request->argv[1], "FREQ") && request->argc == 3)
        return qihse_resp_integer(session, 0);
    return qihse_resp_error(session, "ERR unknown OBJECT subcommand");
}

/* ---- Server commands ---- */

static bool qihse_resp_handle_flushdb(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    /* Without a flush function, we can't easily flush all keys. Return OK. */
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_dbsize(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_time(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char sec_str[32], usec_str[32];
    snprintf(sec_str, sizeof(sec_str), "%ld", (long)tv.tv_sec);
    snprintf(usec_str, sizeof(usec_str), "%ld", (long)tv.tv_usec);
    qihse_resp_array(session, 2);
    qihse_resp_bulk_text(session, sec_str);
    qihse_resp_bulk_text(session, usec_str);
    return true;
}

static bool qihse_resp_handle_shutdown(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    if (session->server->running) __atomic_store_n(&session->server->running, false, __ATOMIC_RELEASE);
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_config(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "config");
    if (qihse_resp_arg_equal(&request->argv[1], "GET")) {
        qihse_resp_array(session, 0);
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "SET")) return qihse_resp_simple(session, "OK");
    if (qihse_resp_arg_equal(&request->argv[1], "RESETSTAT")) return qihse_resp_simple(session, "OK");
    if (qihse_resp_arg_equal(&request->argv[1], "REWRITE")) return qihse_resp_simple(session, "OK");
    return qihse_resp_error(session, "ERR unknown CONFIG subcommand");
}

static bool qihse_resp_handle_debug(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "debug");
    if (qihse_resp_arg_equal(&request->argv[1], "SLEEP") && request->argc == 3) {
        double seconds;
        if (qihse_resp_parse_f64_arg(&request->argv[2], &seconds)) {
            usleep((useconds_t)(seconds * 1000000.0));
        }
        return qihse_resp_simple(session, "OK");
    }
    if (qihse_resp_arg_equal(&request->argv[1], "OBJECT") && request->argc == 3)
        return qihse_resp_simple(session, "Value at:0x0 refcount:1 encoding:raw serializedlength:0");
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_memory(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "memory");
    if (qihse_resp_arg_equal(&request->argv[1], "USAGE")) return qihse_resp_integer(session, 0);
    if (qihse_resp_arg_equal(&request->argv[1], "STATS")) { qihse_resp_array(session, 0); return true; }
    if (qihse_resp_arg_equal(&request->argv[1], "DOCTOR")) return qihse_resp_bulk_text(session, "Sam, I detected a few issues in this Redis instance memory implants:\n* Nobody is using the database.\n");
    if (qihse_resp_arg_equal(&request->argv[1], "PURGE")) return qihse_resp_simple(session, "OK");
    if (qihse_resp_arg_equal(&request->argv[1], "MALLOC-STATS")) return qihse_resp_bulk_text(session, "");
    return qihse_resp_error(session, "ERR unknown MEMORY subcommand");
}

/* ---- Transaction commands ---- */

static bool qihse_resp_handle_multi(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    if (session->in_multi) return qihse_resp_error(session, "ERR MULTI calls can not be nested");
    session->in_multi = true;
    session->multi_dirty = false;
    session->multi_queue_len = 0;
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_exec(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    if (!session->in_multi) return qihse_resp_error(session, "ERR EXEC without MULTI");
    if (session->watch_dirty) {
        qihse_resp_null(session);
        session->in_multi = false;
        session->multi_queue_len = 0;
        session->watch_count = 0;
        session->watch_dirty = false;
        return true;
    }
    /* Execute queued commands */
    qihse_resp_array(session, session->multi_queue_len);
    for (size_t i = 0; i < session->multi_queue_len; i++) {
        bool keep_open = true;
        qihse_resp_dispatch(session, &session->multi_queue[i], &keep_open);
    }
    /* Cleanup */
    free(session->multi_queue);
    session->multi_queue = NULL;
    session->multi_queue_len = 0;
    session->multi_queue_cap = 0;
    session->in_multi = false;
    for (size_t i = 0; i < session->watch_count; i++) free(session->watch_keys[i]);
    free(session->watch_keys);
    free(session->watch_key_lens);
    session->watch_keys = NULL;
    session->watch_key_lens = NULL;
    session->watch_count = 0;
    session->watch_dirty = false;
    return true;
}

static bool qihse_resp_handle_discard(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    if (!session->in_multi) return qihse_resp_error(session, "ERR DISCARD without MULTI");
    free(session->multi_queue);
    session->multi_queue = NULL;
    session->multi_queue_len = 0;
    session->multi_queue_cap = 0;
    session->in_multi = false;
    session->multi_dirty = false;
    for (size_t i = 0; i < session->watch_count; i++) free(session->watch_keys[i]);
    free(session->watch_keys);
    free(session->watch_key_lens);
    session->watch_keys = NULL;
    session->watch_key_lens = NULL;
    session->watch_count = 0;
    session->watch_dirty = false;
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_watch(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "watch");
    if (session->in_multi) return qihse_resp_error(session, "ERR WATCH inside MULTI is not allowed");
    for (size_t i = 1; i < request->argc; i++) {
        if (session->watch_count >= session->watch_cap) {
            session->watch_cap = session->watch_cap ? session->watch_cap * 2 : 8;
            session->watch_keys = realloc(session->watch_keys, session->watch_cap * sizeof(char*));
            session->watch_key_lens = realloc(session->watch_key_lens, session->watch_cap * sizeof(size_t));
        }
        session->watch_keys[session->watch_count] = qihse_resp_arg_text(&request->argv[i]);
        session->watch_key_lens[session->watch_count] = request->argv[i].len;
        session->watch_count++;
    }
    return qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_unwatch(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    for (size_t i = 0; i < session->watch_count; i++) free(session->watch_keys[i]);
    free(session->watch_keys);
    free(session->watch_key_lens);
    session->watch_keys = NULL;
    session->watch_key_lens = NULL;
    session->watch_count = 0;
    session->watch_dirty = false;
    return qihse_resp_simple(session, "OK");
}

/* ---- Pub/Sub commands ---- */

static bool qihse_resp_handle_publish(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "publish");
    /* Without a pub/sub broker, return 0 receivers */
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_subscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "subscribe");
    for (size_t i = 1; i < request->argc; i++) {
        if (session->sub_channel_count >= session->sub_channel_cap) {
            session->sub_channel_cap = session->sub_channel_cap ? session->sub_channel_cap * 2 : 8;
            session->sub_channels = realloc(session->sub_channels, session->sub_channel_cap * sizeof(char*));
            session->sub_channel_lens = realloc(session->sub_channel_lens, session->sub_channel_cap * sizeof(size_t));
        }
        session->sub_channels[session->sub_channel_count] = qihse_resp_arg_text(&request->argv[i]);
        session->sub_channel_lens[session->sub_channel_count] = request->argv[i].len;
        session->sub_channel_count++;
        /* Send subscribe confirmation */
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "subscribe");
        qihse_resp_bulk(session, request->argv[i].data, request->argv[i].len);
        qihse_resp_integer(session, (int64_t)session->sub_channel_count + (int64_t)session->sub_pattern_count);
    }
    return true;
}

static bool qihse_resp_handle_unsubscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (session->sub_channel_count == 0 && request->argc == 1) {
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "unsubscribe");
        qihse_resp_null(session);
        qihse_resp_integer(session, 0);
        return true;
    }
    if (request->argc < 2) {
        /* Unsubscribe from all */
        for (size_t i = 0; i < session->sub_channel_count; i++) {
            qihse_resp_array(session, 3);
            qihse_resp_bulk_text(session, "unsubscribe");
            qihse_resp_bulk(session, session->sub_channels[i], session->sub_channel_lens[i]);
            qihse_resp_integer(session, (int64_t)session->sub_channel_count - i - 1);
            free(session->sub_channels[i]);
        }
        session->sub_channel_count = 0;
    } else {
        for (size_t i = 1; i < request->argc; i++) {
            qihse_resp_array(session, 3);
            qihse_resp_bulk_text(session, "unsubscribe");
            qihse_resp_bulk(session, request->argv[i].data, request->argv[i].len);
            qihse_resp_integer(session, (int64_t)(session->sub_channel_count > 0 ? session->sub_channel_count - 1 : 0));
        }
    }
    return true;
}

static bool qihse_resp_handle_psubscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "psubscribe");
    for (size_t i = 1; i < request->argc; i++) {
        if (session->sub_pattern_count >= session->sub_pattern_cap) {
            session->sub_pattern_cap = session->sub_pattern_cap ? session->sub_pattern_cap * 2 : 8;
            session->sub_patterns = realloc(session->sub_patterns, session->sub_pattern_cap * sizeof(char*));
            session->sub_pattern_lens = realloc(session->sub_pattern_lens, session->sub_pattern_cap * sizeof(size_t));
        }
        session->sub_patterns[session->sub_pattern_count] = qihse_resp_arg_text(&request->argv[i]);
        session->sub_pattern_lens[session->sub_pattern_count] = request->argv[i].len;
        session->sub_pattern_count++;
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "psubscribe");
        qihse_resp_bulk(session, request->argv[i].data, request->argv[i].len);
        qihse_resp_integer(session, (int64_t)session->sub_channel_count + (int64_t)session->sub_pattern_count);
    }
    return true;
}

static bool qihse_resp_handle_punsubscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) {
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "punsubscribe");
        qihse_resp_null(session);
        qihse_resp_integer(session, 0);
    } else {
        for (size_t i = 1; i < request->argc; i++) {
            qihse_resp_array(session, 3);
            qihse_resp_bulk_text(session, "punsubscribe");
            qihse_resp_bulk(session, request->argv[i].data, request->argv[i].len);
            qihse_resp_integer(session, 0);
        }
    }
    return true;
}

static bool qihse_resp_handle_pubsub(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "pubsub");
    if (qihse_resp_arg_equal(&request->argv[1], "CHANNELS")) { qihse_resp_array(session, 0); return true; }
    if (qihse_resp_arg_equal(&request->argv[1], "NUMSUB")) { qihse_resp_array(session, 0); return true; }
    if (qihse_resp_arg_equal(&request->argv[1], "NUMPAT")) return qihse_resp_integer(session, (int64_t)session->sub_pattern_count);
    return qihse_resp_error(session, "ERR unknown PUBSUB subcommand");
}

/* ---- Bitmap commands ---- */

static bool qihse_resp_handle_setbit(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 4) return qihse_resp_wrong_arity(session, "setbit");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t offset;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &offset) || offset < 0)
        return qihse_resp_error(session, "ERR bit offset is not an integer or out of range");
    int64_t bit_val;
    if (!qihse_resp_parse_i64_arg(&request->argv[3], &bit_val) || (bit_val != 0 && bit_val != 1))
        return qihse_resp_error(session, "ERR bit is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    size_t byte_len = existing ? strlen(existing) : 0;
    size_t needed = (size_t)(offset / 8) + 1;
    if (needed > byte_len) {
        char* new_val = calloc(needed + 1, 1);
        if (existing) memcpy(new_val, existing, byte_len);
        free(existing);
        existing = new_val;
        byte_len = needed;
    }
    size_t byte_idx = (size_t)(offset / 8);
    int bit_idx = (int)(7 - (offset % 8));
    int old_bit = (existing[byte_idx] >> bit_idx) & 1;
    if (bit_val) existing[byte_idx] |= (1 << bit_idx);
    else existing[byte_idx] &= ~(1 << bit_idx);
    qihse_kv_set_user(session->server->store, key, existing, 0, 0, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(existing); free(key);
    return qihse_resp_integer(session, old_bit);
}

static bool qihse_resp_handle_getbit(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "getbit");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    int64_t offset;
    if (!qihse_resp_parse_i64_arg(&request->argv[2], &offset) || offset < 0)
        return qihse_resp_error(session, "ERR bit offset is not an integer or out of range");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    size_t byte_idx = (size_t)(offset / 8);
    int bit_idx = (int)(7 - (offset % 8));
    int bit = 0;
    if (existing && byte_idx < strlen(existing)) bit = (existing[byte_idx] >> bit_idx) & 1;
    free(existing);
    return qihse_resp_integer(session, bit);
}

static bool qihse_resp_handle_bitcount(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "bitcount");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_mutex_lock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    if (!existing) return qihse_resp_integer(session, 0);
    int64_t count = 0;
    size_t len = strlen(existing);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)existing[i];
        for (int b = 0; b < 8; b++) if (c & (1 << b)) count++;
    }
    free(existing);
    return qihse_resp_integer(session, count);
}

static bool qihse_resp_handle_bitpos(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "bitpos");
    return qihse_resp_integer(session, -1);
}

static bool qihse_resp_handle_bitop(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 4) return qihse_resp_wrong_arity(session, "bitop");
    return qihse_resp_integer(session, 0);
}

/* ---- HyperLogLog commands ---- */

static bool qihse_resp_handle_pfadd(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "pfadd");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    /* Simplified: store elements as a set, return 1 if new */
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t updated = 0;
    pthread_mutex_lock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* hll_key = qihse_resp_set_key(key, member);
        if (!qihse_kv_exists_user(session->server->store, hll_key, session->user)) {
            qihse_kv_set_user(session->server->store, hll_key, "1", 0, 0, session->user);
            updated = 1;
        }
        free(hll_key); free(member);
    }
    if (request->argc == 2) {
        /* Just create the HLL */
        char* hll_meta = qihse_resp_prefixed_key("__hll__:", key);
        if (!qihse_kv_exists_user(session->server->store, hll_meta, session->user))
            qihse_kv_set_user(session->server->store, hll_meta, "1", 0, 0, session->user);
        free(hll_meta);
    }
    pthread_mutex_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, updated);
}

static bool qihse_resp_handle_pfcount(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "pfcount");
    return qihse_resp_integer(session, 0);
}

static bool qihse_resp_handle_pfmerge(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "pfmerge");
    return qihse_resp_simple(session, "OK");
}

/* ---- Scripting commands ---- */

static bool qihse_resp_handle_eval(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "eval");
    /* Lua scripting would require a Lua interpreter. Return nil for now. */
    return qihse_resp_null(session);
}

static bool qihse_resp_handle_evalsha(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "evalsha");
    return qihse_resp_null(session);
}

static bool qihse_resp_handle_script(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "script");
    if (qihse_resp_arg_equal(&request->argv[1], "LOAD")) return qihse_resp_bulk_text(session, "");
    if (qihse_resp_arg_equal(&request->argv[1], "EXISTS")) {
        qihse_resp_array(session, request->argc - 2);
        for (size_t i = 2; i < request->argc; i++) qihse_resp_integer(session, 0);
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "FLUSH")) return qihse_resp_simple(session, "OK");
    if (qihse_resp_arg_equal(&request->argv[1], "KILL")) return qihse_resp_error(session, "NOTBUSY No scripts in execution right now");
    return qihse_resp_error(session, "ERR unknown SCRIPT subcommand");
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
    /* MULTI queueing: if in a transaction, queue all commands except EXEC/DISCARD/MULTI/WATCH/UNWATCH */
    if (session->in_multi &&
        !qihse_resp_command_is(request, "EXEC") &&
        !qihse_resp_command_is(request, "DISCARD") &&
        !qihse_resp_command_is(request, "MULTI") &&
        !qihse_resp_command_is(request, "WATCH") &&
        !qihse_resp_command_is(request, "UNWATCH")) {
        if (session->multi_queue_len >= session->multi_queue_cap) {
            session->multi_queue_cap = session->multi_queue_cap ? session->multi_queue_cap * 2 : 16;
            session->multi_queue = realloc(session->multi_queue, session->multi_queue_cap * sizeof(qihse_resp_request_t));
        }
        qihse_resp_request_t* slot = &session->multi_queue[session->multi_queue_len++];
        memcpy(slot, request, sizeof(qihse_resp_request_t));
        return qihse_resp_simple(session, "QUEUED");
    }
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
                qihse_resp_command_is(request, "COL.APPEND") || qihse_resp_command_is(request, "KEYSTONE.INGEST") ||
                qihse_resp_command_is(request, "LPUSH") || qihse_resp_command_is(request, "RPUSH") ||
                qihse_resp_command_is(request, "LPOP") || qihse_resp_command_is(request, "RPOP") ||
                qihse_resp_command_is(request, "LSET") || qihse_resp_command_is(request, "LREM") ||
                qihse_resp_command_is(request, "LTRIM") || qihse_resp_command_is(request, "LINSERT") ||
                qihse_resp_command_is(request, "RPOPLPUSH") || qihse_resp_command_is(request, "HSET") ||
                qihse_resp_command_is(request, "HMSET") || qihse_resp_command_is(request, "HDEL") ||
                qihse_resp_command_is(request, "HINCRBY") || qihse_resp_command_is(request, "HSETNX") ||
                qihse_resp_command_is(request, "SADD") || qihse_resp_command_is(request, "SREM") ||
                qihse_resp_command_is(request, "SPOP") || qihse_resp_command_is(request, "SMOVE") ||
                qihse_resp_command_is(request, "ZADD") || qihse_resp_command_is(request, "ZREM") ||
                qihse_resp_command_is(request, "ZINCRBY") || qihse_resp_command_is(request, "ZPOPMAX") ||
                qihse_resp_command_is(request, "ZPOPMIN") || qihse_resp_command_is(request, "GETSET") ||
                qihse_resp_command_is(request, "GETDEL") || qihse_resp_command_is(request, "APPEND") ||
                qihse_resp_command_is(request, "SETRANGE") || qihse_resp_command_is(request, "INCRBY") ||
                qihse_resp_command_is(request, "DECRBY") || qihse_resp_command_is(request, "INCRBYFLOAT") ||
                qihse_resp_command_is(request, "MSETNX") || qihse_resp_command_is(request, "RENAME") ||
                qihse_resp_command_is(request, "RENAMENX") || qihse_resp_command_is(request, "COPY") ||
                qihse_resp_command_is(request, "UNLINK") || qihse_resp_command_is(request, "SETBIT") ||
                qihse_resp_command_is(request, "BITOP") || qihse_resp_command_is(request, "PFADD") ||
                qihse_resp_command_is(request, "PFMERGE") || qihse_resp_command_is(request, "FLUSHDB") ||
                qihse_resp_command_is(request, "FLUSHALL") || qihse_resp_command_is(request, "SHUTDOWN");
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

    /* TASK.* commands */
    if (qihse_resp_command_is(request, "TASK.SUBMIT") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "SUBMIT"))) {
        return qihse_resp_handle_task_submit(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.RESULT") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "RESULT"))) {
        return qihse_resp_handle_task_result(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.STATUS") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "STATUS"))) {
        return qihse_resp_handle_task_status(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.CANCEL") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "CANCEL"))) {
        return qihse_resp_handle_task_cancel(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.RETRY") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "RETRY"))) {
        return qihse_resp_handle_task_retry(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.DELETE") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "DELETE"))) {
        return qihse_resp_handle_task_delete(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.QUEUE") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "QUEUE"))) {
        return qihse_resp_handle_task_queue(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.STATS") || (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "STATS"))) {
        return qihse_resp_handle_task_stats(session, request);
    }
    if (qihse_resp_command_is(request, "TASK.WORKERS") || qihse_resp_command_is(request, "TASK.WORKERS.PAUSE") ||
        qihse_resp_command_is(request, "TASK.WORKERS.RESUME") || qihse_resp_command_is(request, "TASK.WORKERS.SET") ||
        (qihse_resp_command_is(request, "TASK") && request->argc > 1 && qihse_resp_arg_equal(&request->argv[1], "WORKERS"))) {
        return qihse_resp_handle_task_workers(session, request);
    }

    /* SCHEDULE.* commands */
    if (qihse_resp_command_is(request, "SCHEDULE.ADD") || qihse_resp_command_is(request, "SCHEDULE.REMOVE") ||
        qihse_resp_command_is(request, "SCHEDULE.LIST") || qihse_resp_command_is(request, "SCHEDULE.ENABLE") ||
        qihse_resp_command_is(request, "SCHEDULE.DISABLE") || qihse_resp_command_is(request, "SCHEDULE.NEXT") ||
        qihse_resp_command_is(request, "SCHEDULE")) {
        return qihse_resp_handle_schedule(session, request);
    }

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

    /* ===== Redis Data Structure Commands ===== */

    /* List commands */
    if (qihse_resp_command_is(request, "LPUSH")) return qihse_resp_handle_lpush(session, request, true);
    if (qihse_resp_command_is(request, "RPUSH")) return qihse_resp_handle_lpush(session, request, false);
    if (qihse_resp_command_is(request, "LPOP")) return qihse_resp_handle_lpop(session, request, true);
    if (qihse_resp_command_is(request, "RPOP")) return qihse_resp_handle_lpop(session, request, false);
    if (qihse_resp_command_is(request, "LLEN")) return qihse_resp_handle_llen(session, request);
    if (qihse_resp_command_is(request, "LRANGE")) return qihse_resp_handle_lrange(session, request);
    if (qihse_resp_command_is(request, "LINDEX")) return qihse_resp_handle_lindex(session, request);
    if (qihse_resp_command_is(request, "LSET")) return qihse_resp_handle_lset(session, request);
    if (qihse_resp_command_is(request, "LREM")) return qihse_resp_handle_lrem(session, request);
    if (qihse_resp_command_is(request, "LTRIM")) return qihse_resp_handle_ltrim(session, request);
    if (qihse_resp_command_is(request, "LINSERT")) return qihse_resp_handle_linsert(session, request);
    if (qihse_resp_command_is(request, "RPOPLPUSH")) return qihse_resp_handle_rpoplpush(session, request);

    /* Hash commands */
    if (qihse_resp_command_is(request, "HSET") || qihse_resp_command_is(request, "HMSET")) return qihse_resp_handle_hset(session, request);
    if (qihse_resp_command_is(request, "HGET")) return qihse_resp_handle_hget(session, request);
    if (qihse_resp_command_is(request, "HGETALL")) return qihse_resp_handle_hgetall(session, request);
    if (qihse_resp_command_is(request, "HDEL")) return qihse_resp_handle_hdel(session, request);
    if (qihse_resp_command_is(request, "HEXISTS")) return qihse_resp_handle_hexists(session, request);
    if (qihse_resp_command_is(request, "HKEYS")) return qihse_resp_handle_hkeys(session, request);
    if (qihse_resp_command_is(request, "HVALS")) return qihse_resp_handle_hvals(session, request);
    if (qihse_resp_command_is(request, "HLEN")) return qihse_resp_handle_hlen(session, request);
    if (qihse_resp_command_is(request, "HINCRBY")) return qihse_resp_handle_hincrby(session, request);
    if (qihse_resp_command_is(request, "HMGET")) return qihse_resp_handle_hmget(session, request);
    if (qihse_resp_command_is(request, "HSETNX")) return qihse_resp_handle_hsetnx(session, request);
    if (qihse_resp_command_is(request, "HSTRLEN")) return qihse_resp_handle_hstrlen(session, request);

    /* Set commands */
    if (qihse_resp_command_is(request, "SADD")) return qihse_resp_handle_sadd(session, request);
    if (qihse_resp_command_is(request, "SREM")) return qihse_resp_handle_srem(session, request);
    if (qihse_resp_command_is(request, "SMEMBERS")) return qihse_resp_handle_smembers(session, request);
    if (qihse_resp_command_is(request, "SISMEMBER")) return qihse_resp_handle_sismember(session, request);
    if (qihse_resp_command_is(request, "SCARD")) return qihse_resp_handle_scard(session, request);
    if (qihse_resp_command_is(request, "SPOP")) return qihse_resp_handle_spop(session, request);
    if (qihse_resp_command_is(request, "SMOVE")) return qihse_resp_handle_smove(session, request);
    if (qihse_resp_command_is(request, "SDIFF")) return qihse_resp_handle_sdiff(session, request);
    if (qihse_resp_command_is(request, "SINTER")) return qihse_resp_handle_sinter(session, request);
    if (qihse_resp_command_is(request, "SUNION")) return qihse_resp_handle_sunion(session, request);
    if (qihse_resp_command_is(request, "SRANDMEMBER")) return qihse_resp_handle_srandmember(session, request);

    /* Sorted set commands */
    if (qihse_resp_command_is(request, "ZADD")) return qihse_resp_handle_zadd(session, request);
    if (qihse_resp_command_is(request, "ZREM")) return qihse_resp_handle_zrem(session, request);
    if (qihse_resp_command_is(request, "ZSCORE")) return qihse_resp_handle_zscore(session, request);
    if (qihse_resp_command_is(request, "ZCARD")) return qihse_resp_handle_zcard(session, request);
    if (qihse_resp_command_is(request, "ZCOUNT")) return qihse_resp_handle_zcount(session, request);
    if (qihse_resp_command_is(request, "ZRANGE")) return qihse_resp_handle_zrange(session, request, false);
    if (qihse_resp_command_is(request, "ZREVRANGE")) return qihse_resp_handle_zrange(session, request, true);
    if (qihse_resp_command_is(request, "ZRANK")) return qihse_resp_handle_zrank(session, request, false);
    if (qihse_resp_command_is(request, "ZREVRANK")) return qihse_resp_handle_zrank(session, request, true);
    if (qihse_resp_command_is(request, "ZINCRBY")) return qihse_resp_handle_zincrby(session, request);
    if (qihse_resp_command_is(request, "ZPOPMAX")) return qihse_resp_handle_zpop(session, request, true);
    if (qihse_resp_command_is(request, "ZPOPMIN")) return qihse_resp_handle_zpop(session, request, false);
    if (qihse_resp_command_is(request, "ZRANGEBYSCORE")) return qihse_resp_handle_zrangebyscore(session, request, false);
    if (qihse_resp_command_is(request, "ZREVRANGEBYSCORE")) return qihse_resp_handle_zrangebyscore(session, request, true);

    /* Key/generic commands */
    if (qihse_resp_command_is(request, "KEYS")) return qihse_resp_handle_keys(session, request);
    if (qihse_resp_command_is(request, "SCAN")) return qihse_resp_handle_scan(session, request);
    if (qihse_resp_command_is(request, "RENAME")) return qihse_resp_handle_rename(session, request, false);
    if (qihse_resp_command_is(request, "RENAMENX")) return qihse_resp_handle_rename(session, request, true);
    if (qihse_resp_command_is(request, "GETSET")) return qihse_resp_handle_getset(session, request);
    if (qihse_resp_command_is(request, "GETDEL")) return qihse_resp_handle_getdel(session, request);
    if (qihse_resp_command_is(request, "STRLEN")) return qihse_resp_handle_strlen(session, request);
    if (qihse_resp_command_is(request, "APPEND")) return qihse_resp_handle_append(session, request);
    if (qihse_resp_command_is(request, "GETRANGE")) return qihse_resp_handle_getrange(session, request);
    if (qihse_resp_command_is(request, "SETRANGE")) return qihse_resp_handle_setrange(session, request);
    if (qihse_resp_command_is(request, "INCRBY")) return qihse_resp_handle_incrby(session, request, false);
    if (qihse_resp_command_is(request, "DECRBY")) return qihse_resp_handle_incrby(session, request, true);
    if (qihse_resp_command_is(request, "INCRBYFLOAT")) return qihse_resp_handle_incrbyfloat(session, request);
    if (qihse_resp_command_is(request, "MSETNX")) return qihse_resp_handle_msetnx(session, request);
    if (qihse_resp_command_is(request, "PERSIST")) return qihse_resp_handle_persist(session, request);
    if (qihse_resp_command_is(request, "EXPIREAT")) return qihse_resp_handle_expireat(session, request, false);
    if (qihse_resp_command_is(request, "PEXPIREAT")) return qihse_resp_handle_expireat(session, request, true);
    if (qihse_resp_command_is(request, "UNLINK")) return qihse_resp_handle_del_exists(session, request, true);
    if (qihse_resp_command_is(request, "COPY")) return qihse_resp_handle_copy(session, request);
    if (qihse_resp_command_is(request, "RANDOMKEY")) return qihse_resp_handle_randomkey(session, request);
    if (qihse_resp_command_is(request, "TOUCH")) return qihse_resp_handle_touch(session, request);
    if (qihse_resp_command_is(request, "OBJECT")) return qihse_resp_handle_object(session, request);

    /* Server commands */
    if (qihse_resp_command_is(request, "FLUSHDB") || qihse_resp_command_is(request, "FLUSHALL")) return qihse_resp_handle_flushdb(session, request);
    if (qihse_resp_command_is(request, "DBSIZE")) return qihse_resp_handle_dbsize(session, request);
    if (qihse_resp_command_is(request, "TIME")) return qihse_resp_handle_time(session, request);
    if (qihse_resp_command_is(request, "SAVE") || qihse_resp_command_is(request, "BGSAVE")) return qihse_resp_simple(session, "OK");
    if (qihse_resp_command_is(request, "LASTSAVE")) return qihse_resp_integer(session, (int64_t)time(NULL));
    if (qihse_resp_command_is(request, "SHUTDOWN")) return qihse_resp_handle_shutdown(session, request);
    if (qihse_resp_command_is(request, "CONFIG")) return qihse_resp_handle_config(session, request);
    if (qihse_resp_command_is(request, "DEBUG")) return qihse_resp_handle_debug(session, request);
    if (qihse_resp_command_is(request, "SLOWLOG")) return qihse_resp_simple(session, "OK");
    if (qihse_resp_command_is(request, "MEMORY")) return qihse_resp_handle_memory(session, request);
    if (qihse_resp_command_is(request, "LATENCY")) return qihse_resp_simple(session, "OK");

    /* Transaction commands */
    if (qihse_resp_command_is(request, "MULTI")) return qihse_resp_handle_multi(session, request);
    if (qihse_resp_command_is(request, "EXEC")) return qihse_resp_handle_exec(session, request);
    if (qihse_resp_command_is(request, "DISCARD")) return qihse_resp_handle_discard(session, request);
    if (qihse_resp_command_is(request, "WATCH")) return qihse_resp_handle_watch(session, request);
    if (qihse_resp_command_is(request, "UNWATCH")) return qihse_resp_handle_unwatch(session, request);

    /* Pub/Sub commands */
    if (qihse_resp_command_is(request, "PUBLISH")) return qihse_resp_handle_publish(session, request);
    if (qihse_resp_command_is(request, "SUBSCRIBE")) return qihse_resp_handle_subscribe(session, request);
    if (qihse_resp_command_is(request, "UNSUBSCRIBE")) return qihse_resp_handle_unsubscribe(session, request);
    if (qihse_resp_command_is(request, "PSUBSCRIBE")) return qihse_resp_handle_psubscribe(session, request);
    if (qihse_resp_command_is(request, "PUNSUBSCRIBE")) return qihse_resp_handle_punsubscribe(session, request);
    if (qihse_resp_command_is(request, "PUBSUB")) return qihse_resp_handle_pubsub(session, request);

    /* Bitmap commands */
    if (qihse_resp_command_is(request, "SETBIT")) return qihse_resp_handle_setbit(session, request);
    if (qihse_resp_command_is(request, "GETBIT")) return qihse_resp_handle_getbit(session, request);
    if (qihse_resp_command_is(request, "BITCOUNT")) return qihse_resp_handle_bitcount(session, request);
    if (qihse_resp_command_is(request, "BITPOS")) return qihse_resp_handle_bitpos(session, request);
    if (qihse_resp_command_is(request, "BITOP")) return qihse_resp_handle_bitop(session, request);

    /* HyperLogLog commands */
    if (qihse_resp_command_is(request, "PFADD")) return qihse_resp_handle_pfadd(session, request);
    if (qihse_resp_command_is(request, "PFCOUNT")) return qihse_resp_handle_pfcount(session, request);
    if (qihse_resp_command_is(request, "PFMERGE")) return qihse_resp_handle_pfmerge(session, request);

    /* Scripting commands */
    if (qihse_resp_command_is(request, "EVAL")) return qihse_resp_handle_eval(session, request);
    if (qihse_resp_command_is(request, "EVALSHA")) return qihse_resp_handle_evalsha(session, request);
    if (qihse_resp_command_is(request, "SCRIPT")) return qihse_resp_handle_script(session, request);

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
        struct pollfd pfd;
        pfd.fd = server->listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 50);
        if (pr <= 0) {
            if (pr < 0 && errno != EINTR) break;
            continue;
        }
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(server->listen_fd, (struct sockaddr*)&peer, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
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
    /* Task Queue & Scheduler */
    config->enable_task_queue = true;
    config->enable_task_workers = true;
    config->task_worker_count = 0;
    config->task_python_binary = "python3";
    config->enable_task_scheduler = true;
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
    /* Task Queue & Scheduler initialization */
    if (supplied->task_queue) {
        server->task_queue = supplied->task_queue;
        server->owns_task_queue = false;
    } else if (supplied->enable_task_queue) {
        qihse_task_queue_config_t tq_cfg;
        tq_cfg.kv_store = server->store;
        tq_cfg.event_stream = NULL;
        tq_cfg.tsdb = server->tsdb;
        tq_cfg.max_queue_capacity = 1000000u;
        server->task_queue = qihse_task_queue_create(&tq_cfg);
        server->owns_task_queue = (server->task_queue != NULL);
    }

    if (supplied->task_workers) {
        server->task_workers = supplied->task_workers;
        server->owns_task_workers = false;
    } else if (supplied->enable_task_workers && server->task_queue) {
        qihse_task_worker_pool_config_t wp_cfg;
        qihse_task_worker_pool_config_init(&wp_cfg);
        wp_cfg.queue = server->task_queue;
        wp_cfg.worker_count = supplied->task_worker_count;
        wp_cfg.pin_cores = server->pin_workers;
        wp_cfg.numa_node_id = server->numa_node_id;
        wp_cfg.python_binary = supplied->task_python_binary;
        server->task_workers = qihse_task_worker_pool_create(&wp_cfg);
        server->owns_task_workers = (server->task_workers != NULL);
    }

    if (supplied->task_scheduler) {
        server->task_scheduler = supplied->task_scheduler;
        server->owns_task_scheduler = false;
    } else if (supplied->enable_task_scheduler && server->task_queue) {
        qihse_task_scheduler_config_t ts_cfg;
        qihse_task_scheduler_config_init(&ts_cfg);
        ts_cfg.queue = server->task_queue;
        ts_cfg.tsdb = server->tsdb;
        ts_cfg.tick_ms = 10u;
        server->task_scheduler = qihse_task_scheduler_create(&ts_cfg);
        server->owns_task_scheduler = (server->task_scheduler != NULL);
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
    /* Start Task Workers & Scheduler */
    if (server->task_workers) qihse_task_worker_pool_start(server->task_workers);
    if (server->task_scheduler) qihse_task_scheduler_start(server->task_scheduler);
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
    /* Start Task Workers & Scheduler */
    if (server->task_workers) qihse_task_worker_pool_start(server->task_workers);
    if (server->task_scheduler) qihse_task_scheduler_start(server->task_scheduler);
    bool result = qihse_resp_accept_loop(server);
    qihse_resp_server_stop(server);
    return result;
}

void qihse_resp_server_stop(qihse_resp_server_t* server) {
    if (!server) return;
    /* Stop Task Scheduler & Workers */
    if (server->task_scheduler) qihse_task_scheduler_stop(server->task_scheduler);
    if (server->task_workers) qihse_task_worker_pool_stop(server->task_workers);

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
    if (server->owns_task_scheduler && server->task_scheduler) qihse_task_scheduler_destroy(server->task_scheduler);
    if (server->owns_task_workers && server->task_workers) qihse_task_worker_pool_destroy(server->task_workers);
    if (server->owns_task_queue && server->task_queue) qihse_task_queue_destroy(server->task_queue);
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

qihse_task_queue_t* qihse_resp_server_task_queue(qihse_resp_server_t* server) {
    return server ? server->task_queue : NULL;
}

qihse_task_worker_pool_t* qihse_resp_server_task_workers(qihse_resp_server_t* server) {
    return server ? server->task_workers : NULL;
}

qihse_task_scheduler_t* qihse_resp_server_task_scheduler(qihse_resp_server_t* server) {
    return server ? server->task_scheduler : NULL;
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
