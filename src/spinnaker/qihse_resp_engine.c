#include "qihse_resp_wire.h"
#include "qihse_resp_engine.h"
#include "qihse_resp_cluster.h"
#include "qihse_resp_pubsub.h"
#include "qihse_cluster_numa.h"
#include "qihse_ai_memory.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_ops.h"
#include "qihse_federation.h"
#include "qihse_supply_chain.h"
#include "qihse_runtime_trust.h"
#include "qihse_security_audit.h"
#include "qihse_operations.h"
#include "qihse_cluster_failover.h"
#include "qihse_cluster_scatter.h"
#include "qihse_crc16.h"
#include "qihse_keystone.h"
#include "qihse_fabric_index.h"
#include "qihse_ingest_guard.h"
#include "qihse_metrics.h"
#include "qihse_system_guard.h"
#include "qihse_platform.h"
#ifndef _WIN32
#include "qihse_af_xdp.h"
#endif
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
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
#include <strings.h>
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

#define QIHSE_RESP_MAX_WATCHES 8u

typedef struct {
    qihse_resp_server_t* server;
    int fd;
    qihse_user_t* user;
    uint32_t user_id;            /* numeric user id for federation attribution */
    uint64_t id;
    int protocol_version;
    bool asking;
    bool readonly;
    char name[128];
    /* F2: per-session federation watch handles. */
    qihse_federation_watch_t* federation_watches[QIHSE_RESP_MAX_WATCHES];
    /* W2.5: per-session KEYSTONE change-feed handles (read/index identity). */
    qihse_keystone_feed_t* keystone_feeds[QIHSE_RESP_MAX_WATCHES];
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
    /* Serializes socket writes between this session's command thread and
     * pub/sub publisher threads pushing messages to a subscribed client. */
    pthread_mutex_t io_lock;
    /* Buffered mode: replies accumulate in io_buf instead of a socket
     * (used by the stateless execute path for the UWP bridge). */
    uint8_t* io_buf;
    size_t io_len;
    size_t io_cap;
    /* W5.2: the query type of the command currently being dispatched, so an
     * error reply produced deep inside a handler is attributed to the
     * command that caused it.  OTHER until classification runs, never a
     * caller-supplied string. */
    qihse_query_type_t query_type;
} qihse_resp_session_t;

struct qihse_resp_client_ctx {
    qihse_resp_server_t* server;
    int fd;
    qihse_resp_client_ctx_t* next;
};

/* Group update push (GROUP.*): membership lives under grp:<name>, applied
 * updates under grpupd:<name>:<id>. Acks are held for the most recent
 * updates so GROUP.STATUS can report per-member outcomes. */
#define GROUP_MEMBERSHIP_PREFIX "grp:"
#define GROUP_UPDATE_PREFIX "grpupd:"
#define GROUP_ACK_SLOTS 8u

typedef struct {
    bool used;
    uint64_t update_id;
    uint16_t status[QIHSE_CLUSTER_MAX_NODES];
    bool seen[QIHSE_CLUSTER_MAX_NODES];
} group_ack_set_t;

/* W5.2 telemetry handles.
 *
 * Every handle is resolved ONCE, when the registry is populated, so the
 * request path never looks a metric up by name (a lookup takes the registry
 * lock and walks it).  A NULL handle means that family was not registered —
 * the metric is then simply not produced, rather than crashing the path that
 * would have counted it.
 *
 * The gauges at the bottom are sampled at scrape time by
 * qihse_resp_metrics_sample(): cluster/replication status and engine
 * occupancy are read from live structures, and doing that per request would
 * cost far more than the request. */
typedef struct {
    qihse_metric_series_t* queries[QIHSE_QUERY_TYPE_COUNT];
    qihse_metric_series_t* errors[QIHSE_QUERY_TYPE_COUNT];
    qihse_metric_series_t* latency[QIHSE_QUERY_TYPE_COUNT];
    qihse_metric_series_t* backend_queries[QIHSE_ENGINE_BACKEND_COUNT];
    qihse_metric_series_t* backend_available[QIHSE_ENGINE_BACKEND_COUNT];
    /* Scrape-time status: cluster + replication. */
    qihse_metric_series_t* cluster_nodes_total;
    qihse_metric_series_t* cluster_nodes_healthy;
    qihse_metric_series_t* cluster_slots_assigned;
    qihse_metric_series_t* cluster_epoch;
    qihse_metric_series_t* cluster_local_role;
    qihse_metric_series_t* federation_state[6]; /* qihse_federation_state_t */
    qihse_metric_series_t* federation_pending_events;
    qihse_metric_series_t* replication_attempts;
    qihse_metric_series_t* replication_failures;
    /* Scrape-time status: memory + index movement. */
    qihse_metric_series_t* kv_keys;
    qihse_metric_series_t* vector_bytes_in_ram;
    qihse_metric_series_t* vector_rows_spilled;
    qihse_metric_series_t* label_rejected;
    /* Scrape-time status: network/XDP. */
    qihse_metric_series_t* xdp_frames_rx;
    qihse_metric_series_t* xdp_frames_dropped;
    qihse_metric_series_t* xdp_frames_ingested;
    qihse_metric_series_t* xdp_ingest_denied;
} qihse_resp_telemetry_t;

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
    qihse_user_t* unauthenticated_user;
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
    pthread_rwlock_t kv_lock;
    pthread_mutex_t vdb_lock; /* VECSET writes; VECGET/VECSEARCH share — see notes */
    pthread_mutex_t tsdb_lock;
    pthread_mutex_t column_lock;
    /* Phase 3: cluster bus + failover + guard throttling */
    qihse_cluster_bus_t* bus;
    qihse_cluster_failover_t* failover;
    /* Group update push: monotonic id source + per-update member acks. */
    qihse_hlc_t group_clock;
    uint64_t group_last_update;
    pthread_mutex_t group_lock;
    group_ack_set_t group_acks[GROUP_ACK_SLOTS];
    /* F1: sovereign local state — federation status + node UUID derived
     * from the cluster node id. The status is recomputed on demand. */
    qihse_uuid_t federation_node_id;
    qihse_federation_status_t federation_status;
    pthread_mutex_t federation_lock;
    /* F2: event journal + watches. The journal is opened if a directory
     * was configured; otherwise FEDERATION.EVENT.* returns an error. */
    qihse_federation_journal_t* federation_journal;
    /* F5: node identity key directory. NULL = enrollment via RESP fails
     * closed. The directory is not owned by the server. */
    char* federation_key_directory;
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
    /* Pub/Sub broker and channel security policy */
    qihse_resp_pubsub_t* pubsub;
    uint16_t channel_classification;
    uint16_t channel_sci;
    bool enable_uwp_bridge;
    /* Per-tenant quota policies (caller-owned, may be NULL) */
    qihse_quota_table_t* quotas;
    /* U3 session-bundle delivery */
    qihse_blob_store_t* blobs;
    qihse_bundle_composer_t* composer;
    bool owns_composer;
    /* U6 background expiry sweeper */
    uint32_t kv_sweep_interval_seconds;
    pthread_t sweeper_thread;
    bool sweeper_started;
    bool sweeper_shutdown;
    /* U9 delivery metrics */
    qihse_metrics_registry_t* metrics;
    /* W5.2 telemetry: per-query-type series handles + status gauges. */
    qihse_resp_telemetry_t tlm;
    /* W5.2: async write-duplication attempts/failures (replication status). */
    uint64_t replication_attempts;
    uint64_t replication_failures;
    /* CLUSTER MOVESLOTS target auth */
    const char* cluster_migrate_password;
    /* Data redundancy peer ("host:port") */
    const char* redundancy_peer;
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

/* Command dispatch table — one hash probe replaces the ~130-branch
 * command_is if-else chain that previously ran for every request.
 * flags: DSP_SUB_OK     — allowed while the session is subscribed
 *        DSP_MULTI_OK   — executes immediately inside MULTI (not queued)
 *        DSP_BUSY_WRITE — DENYOOM write class for the guard-window gate */
typedef bool (*qihse_resp_cmd_fn)(qihse_resp_session_t*, const qihse_resp_request_t*);
typedef struct { const char* name; qihse_resp_cmd_fn fn; uint32_t flags; } qihse_resp_dispatch_ent_t;
#define DSP_SUB_OK     0x1u
#define DSP_MULTI_OK   0x2u
#define DSP_BUSY_WRITE 0x4u
/* Key-extraction shape (upper nibble) — replaces the second command_is
 * chain in qihse_resp_extract_keys. */
#define DSP_KEY_1KV       (1u << 4)  /* key at argv[1], is a KV-store key */
#define DSP_KEY_ALLKV     (2u << 4)  /* all args argv[1..n] are KV keys */
#define DSP_KEY_ODDKV     (3u << 4)  /* argv[1,3,5...] are KV keys (MSET) */
#define DSP_KEY_1         (4u << 4)  /* key at argv[1], NOT a KV key */
#define DSP_KEY_12KV      (5u << 4)  /* argv[1] and argv[2] are KV keys */
#define DSP_KEY_FROM2KV   (6u << 4)  /* argv[2..n] are KV keys */
#define DSP_KEY_VECTAG    (7u << 4)  /* VECSET/VECGET: TAG-scanned key */
#define DSP_KEY_VECSEARCH (8u << 4)  /* VECSEARCH: first TAG-scanned key */
#define DSP_KEY_MIGRATE   (9u << 4)  /* MIGRATE: argv[3] or KEYS clause */
#define DSP_KEY_MASK      (0xfu << 4)

static const qihse_resp_command_descriptor_t g_qihse_resp_commands[] = {
    {"asking", 1, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"auth", -2, QIHSE_COMMAND_FAST, 0, 0, 0},
    {"bundle.chunk", 3, QIHSE_COMMAND_READONLY, 0, 0, 0},
    {"bundle.prepare", -2, QIHSE_COMMAND_READONLY, 0, 0, 0},
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
    {"metrics.render", 1, QIHSE_COMMAND_ADMIN, 0, 0, 0},
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

/* Stack-buffer fast path for arg → NUL-terminated text.  Returns buf on
 * success (no allocation) or NULL if the arg is invalid / doesn't fit.
 * Caller MUST free() the result only when it != buf. */
static char* qihse_resp_arg_text_buf(const qihse_resp_arg_t* arg, char* buf, size_t bufsize) {
    if (!arg || arg->len == SIZE_MAX || memchr(arg->data, '\0', arg->len) || arg->len + 1u > bufsize) {
        errno = EINVAL;
        return NULL;
    }
    memcpy(buf, arg->data, arg->len);
    buf[arg->len] = '\0';
    return buf;
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
    if (session->io_buf) {
        if (session->io_len + len > session->io_cap) {
            size_t next = session->io_cap ? session->io_cap : 4096u;
            while (session->io_len + len > next) next *= 2u;
            uint8_t* grown = realloc(session->io_buf, next);
            if (!grown) return false;
            session->io_buf = grown;
            session->io_cap = next;
        }
        memcpy(session->io_buf + session->io_len, bytes, len);
        session->io_len += len;
        return true;
    }
    pthread_mutex_lock(&session->io_lock);
    size_t written = 0;
    while (written < len) {
#ifdef MSG_NOSIGNAL
        ssize_t result = send(session->fd, bytes + written, len - written, MSG_NOSIGNAL);
#else
        ssize_t result = send(session->fd, (const char*)bytes + written, len - written, 0);
#endif
        if (result < 0) {
            if (errno == EINTR) continue;
            pthread_mutex_unlock(&session->io_lock);
            return false;
        }
        if (result == 0) {
            pthread_mutex_unlock(&session->io_lock);
            return false;
        }
        written += (size_t)result;
    }
    pthread_mutex_unlock(&session->io_lock);
    return true;
}

static bool qihse_resp_cluster_output(void* context, const void* data, size_t len) {
    return qihse_resp_write((qihse_resp_session_t*)context, data, len);
}

static bool qihse_resp_simple(qihse_resp_session_t* session, const char* value) {
    return qihse_resp_write(session, "+", 1u) && qihse_resp_write(session, value, strlen(value)) && qihse_resp_write(session, "\r\n", 2u);
}

static bool qihse_resp_error(qihse_resp_session_t* session, const char* value) {
    /* W5.2: every error reply is counted once, here, attributed to the query
     * type the session is currently running.  Counting at the single place
     * that writes '-' means a handler cannot forget to report its failure,
     * and it costs one lock-free add on a path that has already failed. */
    if (session && session->server && session->server->metrics) {
        qihse_metric_series_t* series = session->server->tlm.errors[session->query_type];
        if (series) qihse_metrics_series_increment(series, 1u);
    }
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

/* W2.5: KEYSTONE.FEED.<sub> — one command family, matched by prefix so the
 * dispatch allowlist for the index identity can be expressed in one place. */
static bool qihse_resp_command_is_keystone_feed(const qihse_resp_request_t* request) {
    static const char prefix[] = "KEYSTONE.FEED.";
    if (request->argc == 0 || request->argv[0].len < sizeof(prefix) - 1u) return false;
    return strncasecmp((const char*)request->argv[0].data, prefix, sizeof(prefix) - 1u) == 0;
}

static bool qihse_resp_extract_keys(const qihse_resp_request_t* request, qihse_resp_keyset_t* keys,
                                    const qihse_resp_dispatch_ent_t* dispatch_entry) {
    memset(keys, 0, sizeof(*keys));
    if (request->argc < 2 || !dispatch_entry) return true;
    switch (dispatch_entry->flags & DSP_KEY_MASK) {
    case DSP_KEY_1KV:
        keys->indexes[keys->count++] = 1u;
        keys->kv_keys = true;
        break;
    case DSP_KEY_ALLKV:
        for (size_t i = 1; i < request->argc; i++) keys->indexes[keys->count++] = i;
        keys->kv_keys = true;
        break;
    case DSP_KEY_ODDKV:
        for (size_t i = 1; i + 1u < request->argc; i += 2u) keys->indexes[keys->count++] = i;
        keys->kv_keys = true;
        break;
    case DSP_KEY_1:
        keys->indexes[keys->count++] = 1u;
        break;
    case DSP_KEY_12KV:
        keys->indexes[keys->count++] = 1u;
        keys->indexes[keys->count++] = 2u;
        keys->kv_keys = true;
        break;
    case DSP_KEY_FROM2KV:
        for (size_t i = 2; i < request->argc; i++) keys->indexes[keys->count++] = i;
        keys->kv_keys = true;
        break;
    case DSP_KEY_VECTAG: {
        size_t selected = 1u;
        for (size_t i = 2; i + 1u < request->argc; i++) {
            if (qihse_resp_arg_equal(&request->argv[i], "TAG")) selected = i + 1u;
        }
        keys->indexes[keys->count++] = selected;
        break;
    }
    case DSP_KEY_VECSEARCH:
        for (size_t i = 1; i + 1u < request->argc; i++) {
            if (qihse_resp_arg_equal(&request->argv[i], "TAG")) {
                keys->indexes[keys->count++] = i + 1u;
                break;
            }
        }
        break;
    case DSP_KEY_MIGRATE:
        if (request->argc >= 6) {
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
        }
        break;
    default:
        break;
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
        pthread_rwlock_rdlock(&server->kv_lock);
        for (size_t i = 0; i < keys->count; i++) {
            char keybuf[256];
            char* key = qihse_resp_arg_text_buf(&request->argv[keys->indexes[i]], keybuf, sizeof(keybuf));
            if (!key) key = qihse_resp_arg_text(&request->argv[keys->indexes[i]]);
            bool exists = key && qihse_kv_exists_user(server->store, key, session->user);
            if (key && key != keybuf) free(key);
            any_exists = any_exists || exists;
            all_exist = all_exist && exists;
        }
        pthread_rwlock_unlock(&server->kv_lock);
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
    session->user_id = qihse_user_get_id(user);
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

/* Case-insensitive FNV-1a over the command name bytes — matches the
 * semantics of qihse_resp_arg_equal (ASCII case fold). */
static uint32_t qihse_resp_cmd_hash(const uint8_t* data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];
        if (c >= 'a' && c <= 'z') c = (unsigned char)(c - ('a' - 'A'));
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

/* Command-dispatch index: open-addressed map name->descriptor built once so
 * dispatch is one hash + one strcmp-verify instead of scanning all ~40
 * command names with per-char toupper. */
#define RESP_CMD_MAP_CAP 128u
static const qihse_resp_command_descriptor_t* g_cmd_map[RESP_CMD_MAP_CAP];
static pthread_once_t g_cmd_map_once = PTHREAD_ONCE_INIT;

static void qihse_resp_cmd_map_build(void) {
    size_t n = sizeof(g_qihse_resp_commands) / sizeof(g_qihse_resp_commands[0]);
    for (size_t i = 0; i < n; i++) {
        const char* nm = g_qihse_resp_commands[i].name;
        uint32_t h = qihse_resp_cmd_hash((const uint8_t*)nm, strlen(nm)) & (RESP_CMD_MAP_CAP - 1u);
        for (size_t j = 0; j < RESP_CMD_MAP_CAP; j++) {
            size_t pos = (h + j) & (RESP_CMD_MAP_CAP - 1u);
            if (!g_cmd_map[pos]) { g_cmd_map[pos] = &g_qihse_resp_commands[i]; break; }
            if (strcasecmp(g_cmd_map[pos]->name, nm) == 0) break; /* dup name */
        }
    }
}

static const qihse_resp_command_descriptor_t* qihse_resp_find_command(const qihse_resp_arg_t* name) {
    if (!name) return NULL;
    pthread_once(&g_cmd_map_once, qihse_resp_cmd_map_build);
    uint32_t h = qihse_resp_cmd_hash(name->data, name->len) & (RESP_CMD_MAP_CAP - 1u);
    for (size_t i = 0; i < RESP_CMD_MAP_CAP; i++) {
        const qihse_resp_command_descriptor_t* cmd = g_cmd_map[(h + i) & (RESP_CMD_MAP_CAP - 1u)];
        if (!cmd) return NULL;
        if (strlen(cmd->name) == name->len && qihse_resp_arg_equal(name, cmd->name)) return cmd;
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
    size_t pubsub_channels = server->pubsub ? qihse_resp_pubsub_channel_count(server->pubsub, NULL) : 0;
    size_t pubsub_patterns = server->pubsub ? qihse_resp_pubsub_pattern_subscription_count(server->pubsub) : 0;
    int len = snprintf(info, sizeof(info),
                       "# Server\r\nredis_version:7.2.0\r\nredis_mode:cluster\r\nqihse_version:0.1.0\r\n"
                       "qihse_uwp_bridge:%s\r\n"
                       "# Clients\r\nconnected_clients:%zu\r\n"
                       "# Pub/Sub\r\nactive_channels:%zu\r\npattern_subscriptions:%zu\r\n"
                       "# Cluster\r\ncluster_enabled:1\r\ncluster_known_nodes:%zu\r\ncluster_slots_assigned:%zu\r\n"
                       "qihse_crc16_backend:%s\r\n",
                       server->enable_uwp_bridge ? "1" : "0",
                       active_clients, pubsub_channels, pubsub_patterns,
                       nodes, assigned, qihse_crc16_backend_name());
    return len > 0 && (size_t)len < sizeof(info) && qihse_resp_bulk(session, info, (size_t)len);
}

static bool qihse_resp_handle_get(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "get");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char keybuf[256];
    char* key = qihse_resp_arg_text_buf(&request->argv[1], keybuf, sizeof(keybuf));
    if (!key) key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR keys containing NUL bytes are not supported by this storage backend");
    pthread_rwlock_rdlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    bool under_attack = qihse_kv_store_is_under_attack(session->server->store);
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (key != keybuf) free(key);
    if (under_attack) {
        free(value);
        return qihse_resp_error(session, "ERR request rejected by QIHSE defense policy");
    }
    bool result = value ? qihse_resp_bulk_text(session, value) : qihse_resp_null(session);
    free(value);
    return result;
}

/* U8 killswitch fan-out: a successfully stored burn_edge telemetry record is
 * pushed to every connected tenant on the fleet-wide "killswitch" channel
 * (system-domain publisher, per-channel policy) and mirrored to a durable
 * unclassified commons record that offline clients pick up on their next
 * pull. */
static void qihse_resp_maybe_publish_killswitch(qihse_resp_session_t* session, const char* key, const char* value) {
    if (!session->server->pubsub || !session->server->store || !key || !value) return;
    if (strncmp(key, "t:", 2u) != 0) return;
    if (!strstr(key, "/tlm/burn_edge/")) return;
    qihse_user_t* system_user = session->server->unauthenticated_user;
    qihse_resp_pubsub_publish(session->server->pubsub, system_user,
                              "killswitch", sizeof("killswitch") - 1u,
                              value, strlen(value));
    if (session->server->metrics) qihse_metrics_increment(session->server->metrics, "qihse_killswitch_push_total", 1);
    qihse_kv_set_user(session->server->store, "commons/killswitch/latest", value, 0, 0, system_user);
}

/* ---------------------------------------------------------------------------
 * Data redundancy link (phase 1: string KV, fire-and-forget)
 * After a local commit, the write is replayed to the redundancy peer with
 * ASKING (accepted regardless of slot ownership) so the peer holds a
 * duplicate that survives this node's failure. Loss window: writes in flight
 * when this node dies are gone (async replication); the redundancy peer is
 * not consulted for reads until failover re-homes the slots. Hash/list/set
 * structures replicate in phase 2.
 * ------------------------------------------------------------------------- */
static int qihse_resp_connect_timeout(const char* host, uint16_t port, int timeout_ms);
static bool qihse_resp_fd_command(int fd, size_t argc, const qihse_resp_arg_t* argv,
                                  char* remote_error, size_t remote_error_cap);

static void redundancy_log(const char* stage, const char* detail) {
    static time_t last_log = 0;
    time_t now = time(NULL);
    if (now - last_log >= 10) {
        fprintf(stderr, "qihse redundancy: %s failed: %s\n", stage, detail);
        last_log = now;
    }
}

static void qihse_resp_replicate_write(qihse_resp_server_t* server, const char* key,
                                       const char* value, int64_t ttl_ms) {
    if (!server || !server->redundancy_peer || !*server->redundancy_peer) return;
    char spec[QIHSE_CLUSTER_HOST_LEN + 16u];
    snprintf(spec, sizeof(spec), "%s", server->redundancy_peer);
    char* colon = strrchr(spec, ':');
    if (!colon) return;
    *colon = '\0';
    uint16_t port = (uint16_t)strtoul(colon + 1, NULL, 10);
    if (port == 0) return;

    /* W5.2 replication status: an attempt is a write the operator asked to be
     * duplicated, a failure is one that did not reach the peer.  Both are
     * plain increments on a path that already opens a socket, so the counter
     * is free relative to the work it measures. */
    server->replication_attempts++;
    int fd = qihse_resp_connect_timeout(spec, port, 2000);
    if (fd < 0) {
        server->replication_failures++;
        redundancy_log("connect", errno ? strerror(errno) : "timeout");
        return; /* peer down: local commit stands; failover re-homes later */
    }
    char remote_error[256] = {0};
    const char* password = server->cluster_migrate_password;
    if (password && *password) {
        static const uint8_t auth_cmd[] = "AUTH";
        static const uint8_t op_user[] = "GODMODE_OP";
        qihse_resp_arg_t auth_args[3] = {
            { auth_cmd, sizeof(auth_cmd) - 1u },
            { (const uint8_t*)op_user, sizeof(op_user) - 1u },
            { (const uint8_t*)password, strlen(password) }
        };
        if (!qihse_resp_fd_command(fd, 3u, auth_args, remote_error, sizeof(remote_error))) {
            server->replication_failures++;
            redundancy_log("target auth", remote_error);
            close_socket(fd);
            return;
        }
    }
    static const uint8_t asking_cmd[] = "ASKING";
    static const uint8_t set_cmd[] = "SET";
    static const uint8_t px_opt[] = "PX";
    qihse_resp_arg_t asking = { asking_cmd, sizeof(asking_cmd) - 1u };
    if (qihse_resp_fd_command(fd, 1u, &asking, remote_error, sizeof(remote_error))) {
        qihse_resp_arg_t set_args[5];
        size_t argc = 0;
        set_args[argc++] = (qihse_resp_arg_t){ set_cmd, sizeof(set_cmd) - 1u };
        set_args[argc++] = (qihse_resp_arg_t){ (const uint8_t*)key, strlen(key) };
        set_args[argc++] = (qihse_resp_arg_t){ (const uint8_t*)value, strlen(value) };
        char ttl_buf[32];
        if (ttl_ms > 0) {
            int n = snprintf(ttl_buf, sizeof(ttl_buf), "%lld", (long long)ttl_ms);
            set_args[argc++] = (qihse_resp_arg_t){ px_opt, sizeof(px_opt) - 1u };
            set_args[argc++] = (qihse_resp_arg_t){ (const uint8_t*)ttl_buf, (size_t)n };
        }
        if (!qihse_resp_fd_command(fd, argc, set_args, remote_error, sizeof(remote_error))) {
            server->replication_failures++;
            redundancy_log("SET replay", remote_error);
        }
    }
    close_socket(fd);
}

static void qihse_resp_replicate_del(qihse_resp_server_t* server, const char* key) {
    if (!server || !server->redundancy_peer || !*server->redundancy_peer) return;
    char spec[QIHSE_CLUSTER_HOST_LEN + 16u];
    snprintf(spec, sizeof(spec), "%s", server->redundancy_peer);
    char* colon = strrchr(spec, ':');
    if (!colon) return;
    *colon = '\0';
    uint16_t port = (uint16_t)strtoul(colon + 1, NULL, 10);
    if (port == 0) return;

    server->replication_attempts++;
    int fd = qihse_resp_connect_timeout(spec, port, 2000);
    if (fd < 0) {
        server->replication_failures++;
        return;
    }
    char remote_error[256] = {0};
    const char* password = server->cluster_migrate_password;
    if (password && *password) {
        static const uint8_t auth_cmd[] = "AUTH";
        static const uint8_t op_user[] = "GODMODE_OP";
        qihse_resp_arg_t auth_args[3] = {
            { auth_cmd, sizeof(auth_cmd) - 1u },
            { (const uint8_t*)op_user, sizeof(op_user) - 1u },
            { (const uint8_t*)password, strlen(password) }
        };
        if (!qihse_resp_fd_command(fd, 3u, auth_args, remote_error, sizeof(remote_error))) {
            server->replication_failures++;
            close_socket(fd);
            return;
        }
    }
    static const uint8_t asking_cmd[] = "ASKING";
    static const uint8_t del_cmd[] = "DEL";
    qihse_resp_arg_t asking = { asking_cmd, sizeof(asking_cmd) - 1u };
    if (qihse_resp_fd_command(fd, 1u, &asking, remote_error, sizeof(remote_error))) {
        qihse_resp_arg_t del_args[2] = {
            { del_cmd, sizeof(del_cmd) - 1u },
            { (const uint8_t*)key, strlen(key) }
        };
        if (!qihse_resp_fd_command(fd, 2u, del_args, remote_error, sizeof(remote_error))) {
            server->replication_failures++;
        }
    } else {
        server->replication_failures++;
    }
    close_socket(fd);
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
    char keybuf[256];
    char* key = qihse_resp_arg_text_buf(&request->argv[1], keybuf, sizeof(keybuf));
    if (!key) key = qihse_resp_arg_text(&request->argv[1]);
    char* value = qihse_resp_arg_text(&request->argv[2]);
    if (!key || !value) {
        if (key && key != keybuf) free(key);
        free(value);
        return qihse_resp_error(session, "ERR keys and values containing NUL bytes are not supported by this storage backend");
    }
    if (!qihse_system_guard_check_operation(request->argv[1].len + request->argv[2].len, false)) {
        if (key && key != keybuf) free(key);
        free(value);
        return qihse_resp_error(session, "OOM command not allowed by QIHSE system guard");
    }
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, key, session->user);
    char* old = return_old && exists ? qihse_kv_get_user(session->server->store, key, session->user) : NULL;
    bool condition = (!nx || !exists) && (!xx || exists);
    bool stored = condition && qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user);
    if (stored && has_ttl) stored = qihse_kv_expire(session->server->store, key, ttl_ms, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (stored && condition) {
        qihse_resp_maybe_publish_killswitch(session, key, value);
        if (session->server->redundancy_peer)
            qihse_resp_replicate_write(session->server, key, value, has_ttl ? (int64_t)ttl_ms : 0);
        /* AI fabric artifacts (ai_fabric.md build item 2): classify + index
         * fabric: writes via KEYSTONE once. Best-effort — indexing failures
         * never fail an already-persisted write. */
        if (strncmp(key, "fabric:", 7u) == 0)
            (void)qihse_fabric_index_artifact_user(key, value, strlen(value), 0u, 0u, session->user);
    }
    if (key != keybuf) free(key);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool stored = qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user) &&
                  qihse_kv_expire(session->server->store, key, ttl, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key);
    free(value);
    return stored ? qihse_resp_simple(session, "OK") : qihse_resp_error(session, "ERR set failed");
}

static bool qihse_resp_handle_del_exists(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool remove) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, remove ? "del" : "exists");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    int64_t count = 0;
    char deleted_keys[16][256];
    size_t deleted_count = 0;
    if (remove) pthread_rwlock_wrlock(&session->server->kv_lock);
    else        pthread_rwlock_rdlock(&session->server->kv_lock);
    for (size_t i = 1; i < request->argc; i++) {
        char keybuf[256];
        char* key = qihse_resp_arg_text_buf(&request->argv[i], keybuf, sizeof(keybuf));
        if (!key) key = qihse_resp_arg_text(&request->argv[i]);
        if (!key) continue;
        int64_t removed_now = remove ? qihse_kv_del_user(session->server->store, key, session->user) : 0;
        if (remove && removed_now && deleted_count < 16u && strlen(key) < 256u) {
            snprintf(deleted_keys[deleted_count], sizeof(deleted_keys[0]), "%s", key);
            deleted_count++;
        }
        count += removed_now;
        if (key != keybuf) free(key);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (remove && session->server->redundancy_peer) {
        for (size_t i = 0; i < deleted_count; i++)
            qihse_resp_replicate_del(session->server, deleted_keys[i]);
    }
    return qihse_resp_integer(session, count);
}

static bool qihse_resp_handle_mget(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "mget");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    size_t count = request->argc - 1u;
    char** values = (char**)calloc(count, sizeof(*values));
    if (!values) return qihse_resp_error(session, "OOM out of memory");
    pthread_rwlock_rdlock(&session->server->kv_lock);
    for (size_t i = 0; i < count; i++) {
        char keybuf[256];
        char* key = qihse_resp_arg_text_buf(&request->argv[i + 1u], keybuf, sizeof(keybuf));
        if (!key) key = qihse_resp_arg_text(&request->argv[i + 1u]);
        if (key) values[i] = qihse_kv_get_user(session->server->store, key, session->user);
        if (key && key != keybuf) free(key);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
        pthread_rwlock_wrlock(&session->server->kv_lock);
        for (size_t i = 0; i < text_count; i += 2u) {
            if (!qihse_kv_set_user(session->server->store, text[i], text[i + 1u], 0, 0, session->user)) {
                stored = false;
                break;
            }
        }
        pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool result = qihse_kv_expire(session->server->store, key, ttl, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, result ? 1 : 0);
}

static bool qihse_resp_handle_ttl(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool milliseconds) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, milliseconds ? "pttl" : "ttl");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char keybuf[256];
    char* key = qihse_resp_arg_text_buf(&request->argv[1], keybuf, sizeof(keybuf));
    if (!key) key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR invalid key");
    pthread_rwlock_rdlock(&session->server->kv_lock);
    int64_t ttl = qihse_kv_ttl_ms_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (key != keybuf) free(key);
    if (!milliseconds && ttl >= 0) ttl /= 1000;
    return qihse_resp_integer(session, ttl);
}

static bool qihse_resp_handle_increment(qihse_resp_session_t* session, const qihse_resp_request_t* request, int delta) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, delta > 0 ? "incr" : "decr");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char keybuf[256];
    char* key = qihse_resp_arg_text_buf(&request->argv[1], keybuf, sizeof(keybuf));
    if (!key) key = qihse_resp_arg_text(&request->argv[1]);
    if (!key) return qihse_resp_error(session, "ERR invalid key");
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(current);
    if (key != keybuf) free(key);
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

/* U5: hard collection boundary for ANN search. The TAG argument selects the
 * collection; without this filter an approximate search sweeps the whole
 * index and leaks cross-tenant neighbors (candidate-stage clearance filtering
 * does not help — the rows are unclassified). */
typedef struct { const char* tag; size_t len; } qihse_vec_tag_filter_t;

static bool qihse_vec_tag_match(const void* metadata, size_t metadata_size, void* opaque) {
    qihse_vec_tag_filter_t* filter = (qihse_vec_tag_filter_t*)opaque;
    if (!filter || !filter->tag) return true; /* no tag: unfiltered */
    return metadata && metadata_size == filter->len &&
           memcmp(metadata, filter->tag, filter->len) == 0;
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
        query.query_mode = QIHSE_VDB_QUERY_GRAPH;
        query.user = session->user;
        qihse_vec_tag_filter_t tag_filter = { NULL, 0 };
        if (valid && option + 2u == request->argc) {
            tag_filter.tag = (const char*)request->argv[option + 1u].data;
            tag_filter.len = request->argv[option + 1u].len;
            query.metadata_filter = qihse_vec_tag_match;
            query.metadata_filter_opaque = &tag_filter;
        }
        pthread_mutex_lock(&session->server->vdb_lock);
        int local_found = qihse_vector_db_search(session->server->vdb, &query, results, top_k);
        if (local_found < 0 && errno == ENOENT) {
            query.query_mode = QIHSE_VDB_QUERY_FLOAT32; /* no graph — exact scan */
            local_found = qihse_vector_db_search(session->server->vdb, &query, results, top_k);
        }
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
    query.query_mode = QIHSE_VDB_QUERY_GRAPH;
    query.user = session->user;
    pthread_mutex_lock(&session->server->vdb_lock);
    int found = qihse_vector_db_search(session->server->vdb, &query, results, top_k);
    if (found < 0 && errno == ENOENT) {
        query.query_mode = QIHSE_VDB_QUERY_FLOAT32; /* graph absent — exact scan */
        found = qihse_vector_db_search(session->server->vdb, &query, results, top_k);
    }
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
        if (line[0] == '-') {
            /* Bounded copy: `line` is a full read buffer, so the diagnostic
             * must be clipped to the caller's capacity explicitly rather than
             * relying on snprintf truncation. */
            size_t copy_len = strlen(line + 1u);
            if (copy_len >= error_capacity) copy_len = error_capacity - 1u;
            memcpy(error, line + 1u, copy_len);
            error[copy_len] = '\0';
        } else {
            snprintf(error, error_capacity, "target did not acknowledge command");
        }
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
        pthread_rwlock_wrlock(&session->server->kv_lock);
        for (size_t i = 0; i < found; i++) qihse_kv_del_user(session->server->store, items[i].key, session->user);
        pthread_rwlock_unlock(&session->server->kv_lock);
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
        if (!qihse_resp_parse_u64_arg(&request->argv[2], &cl) || cl > UINT16_MAX) return qihse_resp_error(session, "ERR invalid clearance");
        clearance = (uint16_t)cl;
    }
    if (request->argc >= 4) {
        uint64_t cp;
        if (!qihse_resp_parse_u64_arg(&request->argv[3], &cp) || cp > UINT16_MAX) return qihse_resp_error(session, "ERR invalid compartment");
        compartment = (uint16_t)cp;
    }

    pthread_rwlock_wrlock(&session->server->kv_lock);
    size_t count = qihse_keystone_ingest_dirty_logs_user(
        session->server->store,
        session->server->topology,
        (const char*)request->argv[1].data,
        request->argv[1].len,
        clearance,
        compartment,
        session->user
    );
    pthread_rwlock_unlock(&session->server->kv_lock);
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

/* ---------------------------------------------------------------------------
 * KEYSTONE.FEED.* — W2.5: the change-feed surface of the KEYSTONE index
 * identity.
 *
 * This is the one surface the read/index identity may use. It is deliberately
 * NOT part of FEDERATION.*: the federation control plane stays system-domain
 * and operator-only, and a provisioned index identity is tenant-scoped, so it
 * cannot reach FEDERATION.*, CLUSTER MOVESLOTS, GROUP.*, FABRIC.* or
 * METRICS.RENDER even if a handler's own gate were ever relaxed (the dispatch
 * allowlist is the chokepoint).
 *
 * Every record delivered here has already been checked against the session
 * principal's clearance, SCI compartments and tenant by
 * qihse_keystone_feed_next(); records the principal is not cleared for are
 * skipped and counted, never sent.
 * ------------------------------------------------------------------------- */
static bool qihse_resp_keystone_feed_reader(qihse_resp_session_t* session) {
    if (!session->user) return false;
    if (qihse_keystone_feed_identity_is_indexer(session->user)) return true;
    return qihse_user_get_role(session->user) == QIHSE_ROLE_OPERATOR;
}

static bool qihse_resp_handle_keystone_feed(qihse_resp_session_t* session,
                                           const qihse_resp_request_t* request) {
    static const char prefix[] = "KEYSTONE.FEED.";
    if (request->argc < 1 || request->argv[0].len <= sizeof(prefix) - 1u) {
        return qihse_resp_error(session, "ERR unknown KEYSTONE.FEED subcommand");
    }
    char sub[32];
    size_t sub_len = request->argv[0].len - (sizeof(prefix) - 1u);
    if (sub_len >= sizeof(sub)) return qihse_resp_error(session, "ERR unknown KEYSTONE.FEED subcommand");
    memcpy(sub, (const char*)request->argv[0].data + (sizeof(prefix) - 1u), sub_len);
    sub[sub_len] = '\0';

    if (!session->server->federation_journal) {
        return qihse_resp_error(session, "ERR federation journal not configured");
    }

    /* Publishing is a federation control-plane write and is gated by scope
     * inside qihse_keystone_feed_publish(), so the index identity's denial
     * comes from the privilege ladder rather than from this handler. */
    if (strcasecmp(sub, "PUBLISH") == 0) {
        if (request->argc != 8) {
            return qihse_resp_error(session, "ERR usage: KEYSTONE.FEED.PUBLISH <event_type> <resource_id> <classification> <sci> <tenant> <generation> <payload>");
        }
        char event_type[QIHSE_FEDERATION_EVENT_TYPE_MAX + 1u];
        size_t etl = request->argv[1].len;
        if (etl == 0 || etl > QIHSE_FEDERATION_EVENT_TYPE_MAX) return qihse_resp_error(session, "ERR invalid event type");
        memcpy(event_type, request->argv[1].data, etl); event_type[etl] = '\0';
        char resource_id[64];
        size_t rl = request->argv[2].len;
        if (rl == 0 || rl >= sizeof(resource_id)) return qihse_resp_error(session, "ERR invalid resource id");
        memcpy(resource_id, request->argv[2].data, rl); resource_id[rl] = '\0';
        uint64_t classif = 0, sci = 0, tenant = 0, generation = 0;
        if (!qihse_resp_parse_u64_arg(&request->argv[3], &classif) || classif > UINT16_MAX) {
            return qihse_resp_error(session, "ERR invalid classification");
        }
        if (!qihse_resp_parse_u64_arg(&request->argv[4], &sci) || sci > UINT16_MAX) {
            return qihse_resp_error(session, "ERR invalid sci");
        }
        if (!qihse_resp_parse_u64_arg(&request->argv[5], &tenant) || tenant > UINT32_MAX) {
            return qihse_resp_error(session, "ERR invalid tenant");
        }
        if (!qihse_resp_parse_u64_arg(&request->argv[6], &generation)) {
            return qihse_resp_error(session, "ERR invalid generation");
        }
        qihse_keystone_feed_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.classification = (uint16_t)classif;
        rec.sci = (uint16_t)sci;
        rec.tenant_id = (uint32_t)tenant;
        rec.generation = generation;
        /* Deterministic object identity for the RESP surface: the same
         * resource always maps to the same indexed object. */
        if (!qihse_uuid_from_seed(resource_id, rl, &rec.object_id)) {
            return qihse_resp_error(session, "ERR could not derive object id");
        }
        qihse_federation_event_t ev;
        if (!qihse_keystone_feed_publish(session->server->federation_journal, session->user,
                                         &session->server->federation_node_id,
                                         event_type, resource_id, &rec,
                                         request->argv[7].data, request->argv[7].len, &ev)) {
            return qihse_resp_error(session, "NOPERM feed publish requires FEDERATION_WRITE");
        }
        return qihse_resp_integer(session, (int64_t)ev.journal_offset);
    }

    if (!qihse_resp_keystone_feed_reader(session)) {
        return qihse_resp_error(session, "NOPERM KEYSTONE.FEED.* requires the KEYSTONE index identity");
    }

    if (strcasecmp(sub, "OPEN") == 0) {
        if (request->argc != 1 && request->argc != 2) {
            return qihse_resp_error(session, "ERR usage: KEYSTONE.FEED.OPEN [prefix]");
        }
        qihse_keystone_feed_config_t fcfg;
        memset(&fcfg, 0, sizeof(fcfg));
        if (request->argc == 2) {
            size_t pl = request->argv[1].len;
            if (pl >= sizeof(fcfg.prefix)) return qihse_resp_error(session, "ERR prefix too long");
            memcpy(fcfg.prefix, request->argv[1].data, pl); fcfg.prefix[pl] = '\0';
        }
        qihse_keystone_feed_t* feed = qihse_keystone_feed_open(
            session->server->federation_journal, session->user, &fcfg);
        if (!feed) return qihse_resp_error(session, "NOPERM change-feed open refused for this principal");
        for (size_t i = 0; i < QIHSE_RESP_MAX_WATCHES; i++) {
            if (!session->keystone_feeds[i]) {
                session->keystone_feeds[i] = feed;
                return qihse_resp_integer(session, (int64_t)i);
            }
        }
        qihse_keystone_feed_close(feed);
        return qihse_resp_error(session, "ERR too many open feeds");
    }

    if (request->argc < 2) return qihse_resp_error(session, "ERR usage: KEYSTONE.FEED.<sub> <feed-id> ...");
    uint64_t slot = 0;
    if (!qihse_resp_parse_u64_arg(&request->argv[1], &slot) || slot >= QIHSE_RESP_MAX_WATCHES ||
        !session->keystone_feeds[slot]) {
        return qihse_resp_error(session, "ERR unknown feed id");
    }
    qihse_keystone_feed_t* feed = session->keystone_feeds[slot];

    if (strcasecmp(sub, "NEXT") == 0) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "keystone.feed.next");
        qihse_federation_event_t ev;
        qihse_keystone_feed_record_t rec;
        uint8_t* payload = NULL;
        size_t payload_len = 0;
        if (!qihse_keystone_feed_next(feed, &ev, &rec, &payload, &payload_len)) {
            return qihse_resp_integer(session, 0);
        }
        bool ok = qihse_resp_array(session, 8u);
        if (ok) ok = qihse_resp_integer(session, (int64_t)ev.journal_offset);
        if (ok) ok = qihse_resp_bulk_text(session, ev.event_type);
        if (ok) ok = qihse_resp_bulk_text(session, ev.resource_id);
        if (ok) ok = qihse_resp_integer(session, (int64_t)rec.classification);
        if (ok) ok = qihse_resp_integer(session, (int64_t)rec.sci);
        if (ok) ok = qihse_resp_integer(session, (int64_t)rec.tenant_id);
        if (ok) ok = qihse_resp_integer(session, (int64_t)rec.generation);
        if (ok) ok = qihse_resp_bulk(session, payload, payload_len);
        free(payload);
        return ok;
    }

    if (strcasecmp(sub, "ACK") == 0) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "keystone.feed.ack");
        uint64_t offset = 0;
        if (!qihse_resp_parse_u64_arg(&request->argv[2], &offset)) {
            return qihse_resp_error(session, "ERR invalid offset");
        }
        if (!qihse_keystone_feed_ack(feed, offset)) {
            return qihse_resp_error(session, "ERR feed ack failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (strcasecmp(sub, "RESUME") == 0) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "keystone.feed.resume");
        uint64_t cursor = 0;
        if (!qihse_resp_parse_u64_arg(&request->argv[2], &cursor)) {
            return qihse_resp_error(session, "ERR invalid cursor");
        }
        if (!qihse_keystone_feed_resume(feed, cursor)) {
            return qihse_resp_error(session, "ERR feed resume refused");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (strcasecmp(sub, "CLOSE") == 0) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "keystone.feed.close");
        qihse_keystone_feed_close(feed);
        session->keystone_feeds[slot] = NULL;
        return qihse_resp_simple(session, "OK");
    }

    if (strcasecmp(sub, "STATUS") == 0) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "keystone.feed.status");
        if (!qihse_resp_array(session, 4u)) return false;
        if (!qihse_resp_integer(session, (int64_t)qihse_keystone_feed_cursor(feed))) return false;
        if (!qihse_resp_integer(session, (int64_t)qihse_keystone_feed_last_ack(feed))) return false;
        if (!qihse_resp_integer(session, (int64_t)qihse_keystone_feed_denied(feed))) return false;
        return qihse_resp_integer(session, (int64_t)qihse_keystone_feed_malformed(feed));
    }

    return qihse_resp_error(session, "ERR unknown KEYSTONE.FEED subcommand");
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
__attribute__((unused)) static char* qihse_resp_zset_meta(const char* key) {
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
__attribute__((unused)) static char* qihse_resp_set_meta(const char* key) {
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_rwlock_unlock(&session->server->kv_lock); free(lk); return qihse_resp_null(session); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (pop_count == 0) {
        pthread_rwlock_unlock(&session->server->kv_lock);
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
        pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_rwlock_unlock(&session->server->kv_lock); free(lk); return qihse_resp_error(session, "ERR no such key"); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    if (index < 0) index += (int64_t)count;
    if (index < 0 || index >= (int64_t)count) {
        pthread_rwlock_unlock(&session->server->kv_lock);
        for (size_t i = 0; i < count; i++) free(parts[i]);
        free(parts); free(lk);
        return qihse_resp_error(session, "ERR index out of range");
    }
    free(parts[index]);
    parts[index] = qihse_resp_arg_text(&request->argv[3]);
    size_t rl; char* joined = qihse_resp_list_join(parts, count, &rl);
    qihse_kv_set_user(session->server->store, lk, joined, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_rwlock_unlock(&session->server->kv_lock); free(lk); free(target); return qihse_resp_integer(session, 0); }
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_rwlock_unlock(&session->server->kv_lock); free(lk); return qihse_resp_simple(session, "OK"); }
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, lk, session->user);
    if (!existing) { pthread_rwlock_unlock(&session->server->kv_lock); free(lk); free(pivot); free(value); return qihse_resp_integer(session, 0); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(existing, &count);
    free(existing);
    int64_t found = -1;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(parts[i], pivot) == 0) { found = (int64_t)i; break; }
    }
    if (found < 0) {
        pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* src_val = qihse_kv_get_user(session->server->store, src_lk, session->user);
    if (!src_val) { pthread_rwlock_unlock(&session->server->kv_lock); free(src_lk); free(dst_lk); return qihse_resp_null(session); }
    size_t count = 0;
    char** parts = qihse_resp_list_split(src_val, &count);
    free(src_val);
    if (count == 0) {
        pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, hk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* field = qihse_resp_arg_text(&request->argv[i]);
        char* hk = qihse_resp_hash_key(key, field);
        if (qihse_kv_del_user(session->server->store, hk, session->user)) deleted++;
        free(hk); free(field);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, hk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, hk, session->user);
    int64_t val = 0;
    if (existing) val = strtoll(existing, NULL, 10);
    free(existing);
    val += increment;
    char val_str[32]; snprintf(val_str, sizeof(val_str), "%" PRId64, val);
    qihse_kv_set_user(session->server->store, hk, val_str, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(hk);
    return qihse_resp_integer(session, val);
}

static bool qihse_resp_handle_hmget(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "hmget");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    qihse_resp_array(session, request->argc - 2);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* field = qihse_resp_arg_text(&request->argv[i]);
        char* hk = qihse_resp_hash_key(key, field);
        char* value = qihse_kv_get_user(session->server->store, hk, session->user);
        if (value) { qihse_resp_bulk_text(session, value); free(value); }
        else qihse_resp_null(session);
        free(hk); free(field);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, hk, session->user);
    bool ok = true;
    if (!exists) ok = qihse_kv_set_user(session->server->store, hk, value, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, hk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* sk = qihse_resp_set_key(key, member);
        if (!qihse_kv_exists_user(session->server->store, sk, session->user)) {
            qihse_kv_set_user(session->server->store, sk, "1", 0, 0, session->user);
            added++;
        }
        free(sk); free(member);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, added);
}

static bool qihse_resp_handle_srem(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "srem");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t removed = 0;
    pthread_rwlock_wrlock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* sk = qihse_resp_set_key(key, member);
        if (qihse_kv_del_user(session->server->store, sk, session->user)) removed++;
        free(sk); free(member);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, sk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool exists = qihse_kv_exists_user(session->server->store, sk, session->user);
    if (exists) {
        qihse_kv_del_user(session->server->store, sk, session->user);
        qihse_kv_set_user(session->server->store, dk, "1", 0, 0, session->user);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_integer(session, added);
}

static bool qihse_resp_handle_zrem(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "zrem");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    int64_t removed = 0;
    pthread_rwlock_wrlock(&session->server->kv_lock);
    for (size_t i = 2; i < request->argc; i++) {
        char* member = qihse_resp_arg_text(&request->argv[i]);
        char* zk = qihse_resp_zset_key(key, member);
        if (qihse_kv_del_user(session->server->store, zk, session->user)) removed++;
        free(zk); free(member);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* score = qihse_kv_get_user(session->server->store, zk, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, zk, session->user);
    double val = existing ? strtod(existing, NULL) : 0.0;
    free(existing);
    val += increment;
    char score_str[32]; snprintf(score_str, sizeof(score_str), "%.17g", val);
    qihse_kv_set_user(session->server->store, zk, score_str, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, src, session->user);
    if (!value) { pthread_rwlock_unlock(&session->server->kv_lock); free(src); free(dst); return qihse_resp_error(session, "ERR no such key"); }
    if (nx && qihse_kv_exists_user(session->server->store, dst, session->user)) {
        pthread_rwlock_unlock(&session->server->kv_lock); free(value); free(src); free(dst);
        return qihse_resp_integer(session, 0);
    }
    qihse_kv_set_user(session->server->store, dst, value, 0, 0, session->user);
    qihse_kv_del_user(session->server->store, src, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(value); free(src); free(dst);
    return nx ? qihse_resp_integer(session, 1) : qihse_resp_simple(session, "OK");
}

static bool qihse_resp_handle_getset(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "getset");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    char* value = qihse_resp_arg_text(&request->argv[2]);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* old = qihse_kv_get_user(session->server->store, key, session->user);
    qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key); free(value);
    bool result = old ? qihse_resp_bulk_text(session, old) : qihse_resp_null(session);
    free(old);
    return result;
}

static bool qihse_resp_handle_getdel(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "getdel");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    if (value) qihse_kv_del_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key);
    bool result = value ? qihse_resp_bulk_text(session, value) : qihse_resp_null(session);
    free(value);
    return result;
}

static bool qihse_resp_handle_strlen(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "strlen");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    size_t old_len = existing ? strlen(existing) : 0;
    size_t suf_len = strlen(suffix);
    char* combined = malloc(old_len + suf_len + 1);
    if (existing) memcpy(combined, existing, old_len);
    memcpy(combined + old_len, suffix, suf_len + 1);
    qihse_kv_set_user(session->server->store, key, combined, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    size_t old_len = existing ? strlen(existing) : 0;
    size_t new_len = offset + val_len;
    if (new_len < old_len) new_len = old_len;
    char* result_str = calloc(new_len + 1, 1);
    if (existing) memcpy(result_str, existing, old_len);
    memcpy(result_str + offset, value, val_len);
    qihse_kv_set_user(session->server->store, key, result_str, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    int64_t val = existing ? strtoll(existing, NULL, 10) : 0;
    free(existing);
    val += delta;
    char val_str[32]; snprintf(val_str, sizeof(val_str), "%" PRId64, val);
    qihse_kv_set_user(session->server->store, key, val_str, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    double val = existing ? strtod(existing, NULL) : 0.0;
    free(existing);
    val += delta;
    char val_str[32]; snprintf(val_str, sizeof(val_str), "%.17g", val);
    qihse_kv_set_user(session->server->store, key, val_str, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    free(key);
    return qihse_resp_bulk_text(session, val_str);
}

static bool qihse_resp_handle_msetnx(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3 || (request->argc % 2) != 1) return qihse_resp_wrong_arity(session, "msetnx");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    pthread_rwlock_wrlock(&session->server->kv_lock);
    /* Check if any key exists */
    bool any_exists = false;
    for (size_t i = 1; i + 1 < request->argc; i += 2) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        if (qihse_kv_exists_user(session->server->store, key, session->user)) { any_exists = true; free(key); break; }
        free(key);
    }
    if (any_exists) { pthread_rwlock_unlock(&session->server->kv_lock); return qihse_resp_integer(session, 0); }
    for (size_t i = 1; i + 1 < request->argc; i += 2) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        char* value = qihse_resp_arg_text(&request->argv[i + 1]);
        qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user);
        free(key); free(value);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
    return qihse_resp_integer(session, 1);
}

static bool qihse_resp_handle_persist(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "persist");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* key = qihse_resp_arg_text(&request->argv[1]);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    int64_t ttl = qihse_kv_ttl_ms_user(session->server->store, key, session->user);
    if (ttl > 0) {
        /* Remove TTL by setting a very large one or re-setting key */
        char* value = qihse_kv_get_user(session->server->store, key, session->user);
        if (value) { qihse_kv_set_user(session->server->store, key, value, 0, 0, session->user); free(value); }
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
        pthread_rwlock_wrlock(&session->server->kv_lock);
        qihse_kv_del_user(session->server->store, key, session->user);
        pthread_rwlock_unlock(&session->server->kv_lock);
    } else {
        pthread_rwlock_wrlock(&session->server->kv_lock);
        qihse_kv_expire(session->server->store, key, (uint64_t)ttl, session->user);
        pthread_rwlock_unlock(&session->server->kv_lock);
    }
    free(key);
    return qihse_resp_integer(session, 1);
}

static bool qihse_resp_handle_copy(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 3) return qihse_resp_wrong_arity(session, "copy");
    if (!session->server->store) return qihse_resp_error(session, "ERR store not configured");
    char* src = qihse_resp_arg_text(&request->argv[1]);
    char* dst = qihse_resp_arg_text(&request->argv[2]);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* value = qihse_kv_get_user(session->server->store, src, session->user);
    bool ok = false;
    if (value) { ok = qihse_kv_set_user(session->server->store, dst, value, 0, 0, session->user); free(value); }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    for (size_t i = 1; i < request->argc; i++) {
        char* key = qihse_resp_arg_text(&request->argv[i]);
        if (qihse_kv_exists_user(session->server->store, key, session->user)) count++;
        free(key);
    }
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    if (!session->server->store) return qihse_resp_integer(session, 0);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    /* Authorization-aware count: callers see only records they may read. */
    size_t count = qihse_kv_count_user(session->server->store, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    return qihse_resp_integer(session, (int64_t)count);
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

/* Delivery callback invoked by the broker (on a publisher's thread) while it
 * holds the registry read lock. The whole push frame is composed into one
 * buffer and emitted with a single qihse_resp_write call so the frame is
 * atomic with respect to this session's own command replies (io_lock). */
static bool qihse_resp_pubsub_deliver(void* context, bool pattern,
                                      const char* pattern_value, size_t pattern_len,
                                      const char* channel, size_t channel_len,
                                      const char* message, size_t message_len) {
    qihse_resp_session_t* session = (qihse_resp_session_t*)context;
    size_t frame_cap = 64u + channel_len + message_len + (pattern ? pattern_len : 0u) + 32u;
    uint8_t* frame = malloc(frame_cap);
    if (!frame) return false;
    size_t len = 0;
    char header[64];
    int written = snprintf(header, sizeof(header), pattern ? "*4\r\n$8\r\npmessage\r\n$%zu\r\n" : "*3\r\n$7\r\nmessage\r\n$%zu\r\n",
                           pattern ? pattern_len : channel_len);
    if (written <= 0 || (size_t)written >= sizeof(header) || (size_t)written + channel_len + message_len + 64u > frame_cap) {
        free(frame);
        return false;
    }
    memcpy(frame + len, header, (size_t)written);
    len += (size_t)written;
    if (pattern) {
        memcpy(frame + len, pattern_value, pattern_len);
        len += pattern_len;
        written = snprintf(header, sizeof(header), "\r\n$%zu\r\n", channel_len);
        if (written <= 0 || (size_t)written >= sizeof(header)) {
            free(frame);
            return false;
        }
        memcpy(frame + len, header, (size_t)written);
        len += (size_t)written;
    }
    memcpy(frame + len, channel, channel_len);
    len += channel_len;
    written = snprintf(header, sizeof(header), "\r\n$%zu\r\n", message_len);
    if (written <= 0 || (size_t)written >= sizeof(header)) {
        free(frame);
        return false;
    }
    memcpy(frame + len, header, (size_t)written);
    len += (size_t)written;
    memcpy(frame + len, message, message_len);
    len += message_len;
    frame[len++] = '\r';
    frame[len++] = '\n';
    bool delivered = qihse_resp_write(session, frame, len);
    free(frame);
    return delivered;
}

static bool qihse_resp_pubsub_subscribed(const qihse_resp_session_t* session) {
    return session->sub_channel_count > 0 || session->sub_pattern_count > 0;
}

static size_t qihse_resp_sub_find(char** values, size_t* lens, size_t count, const char* value, size_t len) {
    for (size_t i = 0; i < count; i++) {
        if (lens[i] == len && memcmp(values[i], value, len) == 0) return i;
    }
    return SIZE_MAX;
}

static void qihse_resp_sub_remove_at(char*** values, size_t** lens, size_t* count, size_t index) {
    free((*values)[index]);
    for (size_t i = index; i + 1u < *count; i++) {
        (*values)[i] = (*values)[i + 1u];
        (*lens)[i] = (*lens)[i + 1u];
    }
    (*count)--;
}

static bool qihse_resp_sub_add(char*** values, size_t** lens, size_t* count, size_t* cap,
                               char* value, size_t len) {
    if (*count >= *cap) {
        *cap = *cap ? *cap * 2u : 8u;
        *values = realloc(*values, *cap * sizeof(char*));
        *lens = realloc(*lens, *cap * sizeof(size_t));
        if (!*values || !*lens) return false;
    }
    (*values)[*count] = value;
    (*lens)[*count] = len;
    (*count)++;
    return true;
}

static void qihse_resp_session_pubsub_cleanup(qihse_resp_session_t* session) {
    if (session->server->pubsub) qihse_resp_pubsub_detach_client(session->server->pubsub, session);
    for (size_t i = 0; i < session->sub_channel_count; i++) free(session->sub_channels[i]);
    free(session->sub_channels);
    free(session->sub_channel_lens);
    session->sub_channels = NULL;
    session->sub_channel_lens = NULL;
    session->sub_channel_count = 0;
    session->sub_channel_cap = 0;
    for (size_t i = 0; i < session->sub_pattern_count; i++) free(session->sub_patterns[i]);
    free(session->sub_patterns);
    free(session->sub_pattern_lens);
    session->sub_patterns = NULL;
    session->sub_pattern_lens = NULL;
    session->sub_pattern_count = 0;
    session->sub_pattern_cap = 0;
    /* F2: release any open federation watches. */
    if (session->server && session->server->federation_journal) {
        for (size_t i = 0; i < QIHSE_RESP_MAX_WATCHES; i++) {
            if (session->federation_watches[i]) {
                qihse_federation_watch_destroy(session->federation_watches[i]);
                session->federation_watches[i] = NULL;
            }
        }
    }
    /* W2.5: release any open KEYSTONE change feeds. */
    for (size_t i = 0; i < QIHSE_RESP_MAX_WATCHES; i++) {
        if (session->keystone_feeds[i]) {
            qihse_keystone_feed_close(session->keystone_feeds[i]);
            session->keystone_feeds[i] = NULL;
        }
    }
}

static bool qihse_resp_handle_publish(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "publish");
    if (!session->server->pubsub) return qihse_resp_error(session, "ERR pub/sub is not available");
    if (!qihse_resp_pubsub_channel_access(session->server->pubsub, session->user,
                                          (const char*)request->argv[1].data, request->argv[1].len,
                                          true))
        return qihse_resp_error(session, "NOPERM channel clearance required for PUBLISH");
    uint64_t receivers = qihse_resp_pubsub_publish(session->server->pubsub, session->user,
                                                   (const char*)request->argv[1].data, request->argv[1].len,
                                                   (const char*)request->argv[2].data, request->argv[2].len);
    return qihse_resp_integer(session, (int64_t)receivers);
}

static bool qihse_resp_handle_subscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "subscribe");
    if (!session->server->pubsub) return qihse_resp_error(session, "ERR pub/sub is not available");
    for (size_t i = 1; i < request->argc; i++) {
        if (!qihse_resp_pubsub_channel_access(session->server->pubsub, session->user,
                                              (const char*)request->argv[i].data, request->argv[i].len,
                                              false))
            return qihse_resp_error(session, "NOPERM channel clearance required for SUBSCRIBE");
    }
    for (size_t i = 1; i < request->argc; i++) {
        const char* channel = (const char*)request->argv[i].data;
        size_t len = request->argv[i].len;
        if (qihse_resp_sub_find(session->sub_channels, session->sub_channel_lens, session->sub_channel_count, channel, len) == SIZE_MAX) {
            char* copy = malloc(len + 1u);
            if (!copy) return qihse_resp_error(session, "OOM out of memory");
            memcpy(copy, channel, len);
            copy[len] = '\0';
            if (!qihse_resp_pubsub_subscribe(session->server->pubsub, session, qihse_resp_pubsub_deliver, channel, len) ||
                !qihse_resp_sub_add(&session->sub_channels, &session->sub_channel_lens, &session->sub_channel_count, &session->sub_channel_cap, copy, len)) {
                free(copy);
                qihse_resp_pubsub_unsubscribe(session->server->pubsub, session, channel, len);
                return qihse_resp_error(session, "OOM out of memory");
            }
        }
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "subscribe");
        qihse_resp_bulk(session, channel, len);
        qihse_resp_integer(session, (int64_t)(session->sub_channel_count + session->sub_pattern_count));
    }
    return true;
}

static bool qihse_resp_handle_unsubscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->pubsub) return qihse_resp_error(session, "ERR pub/sub is not available");
    if (request->argc == 1) {
        while (session->sub_channel_count > 0) {
            size_t last = session->sub_channel_count - 1u;
            char* channel = session->sub_channels[last];
            size_t len = session->sub_channel_lens[last];
            qihse_resp_pubsub_unsubscribe(session->server->pubsub, session, channel, len);
            qihse_resp_array(session, 3);
            qihse_resp_bulk_text(session, "unsubscribe");
            qihse_resp_bulk(session, channel, len);
            qihse_resp_integer(session, (int64_t)session->sub_channel_count - 1);
            free(channel);
            session->sub_channel_count = last;
        }
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "unsubscribe");
        qihse_resp_null(session);
        qihse_resp_integer(session, 0);
        return true;
    }
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "unsubscribe");
    for (size_t i = 1; i < request->argc; i++) {
        const char* channel = (const char*)request->argv[i].data;
        size_t len = request->argv[i].len;
        size_t index = qihse_resp_sub_find(session->sub_channels, session->sub_channel_lens, session->sub_channel_count, channel, len);
        if (index != SIZE_MAX) {
            qihse_resp_pubsub_unsubscribe(session->server->pubsub, session, channel, len);
            qihse_resp_sub_remove_at(&session->sub_channels, &session->sub_channel_lens, &session->sub_channel_count, index);
        }
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "unsubscribe");
        qihse_resp_bulk(session, channel, len);
        qihse_resp_integer(session, (int64_t)(session->sub_channel_count + session->sub_pattern_count));
    }
    return true;
}

static bool qihse_resp_handle_psubscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "psubscribe");
    if (!session->server->pubsub) return qihse_resp_error(session, "ERR pub/sub is not available");
    for (size_t i = 1; i < request->argc; i++) {
        if (!qihse_resp_pubsub_channel_allowed(session->server->pubsub, session->user))
            return qihse_resp_error(session, "NOPERM channel clearance required for PSUBSCRIBE");
    }
    for (size_t i = 1; i < request->argc; i++) {
        const char* pattern = (const char*)request->argv[i].data;
        size_t len = request->argv[i].len;
        if (qihse_resp_sub_find(session->sub_patterns, session->sub_pattern_lens, session->sub_pattern_count, pattern, len) == SIZE_MAX) {
            char* copy = malloc(len + 1u);
            if (!copy) return qihse_resp_error(session, "OOM out of memory");
            memcpy(copy, pattern, len);
            copy[len] = '\0';
            if (!qihse_resp_pubsub_psubscribe(session->server->pubsub, session, qihse_resp_pubsub_deliver, pattern, len) ||
                !qihse_resp_sub_add(&session->sub_patterns, &session->sub_pattern_lens, &session->sub_pattern_count, &session->sub_pattern_cap, copy, len)) {
                free(copy);
                qihse_resp_pubsub_punsubscribe(session->server->pubsub, session, pattern, len);
                return qihse_resp_error(session, "OOM out of memory");
            }
        }
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "psubscribe");
        qihse_resp_bulk(session, pattern, len);
        qihse_resp_integer(session, (int64_t)(session->sub_channel_count + session->sub_pattern_count));
    }
    return true;
}

static bool qihse_resp_handle_punsubscribe(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->pubsub) return qihse_resp_error(session, "ERR pub/sub is not available");
    if (request->argc == 1) {
        while (session->sub_pattern_count > 0) {
            size_t last = session->sub_pattern_count - 1u;
            char* pattern = session->sub_patterns[last];
            size_t len = session->sub_pattern_lens[last];
            qihse_resp_pubsub_punsubscribe(session->server->pubsub, session, pattern, len);
            qihse_resp_array(session, 3);
            qihse_resp_bulk_text(session, "punsubscribe");
            qihse_resp_bulk(session, pattern, len);
            qihse_resp_integer(session, (int64_t)session->sub_pattern_count - 1);
            free(pattern);
            session->sub_pattern_count = last;
        }
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "punsubscribe");
        qihse_resp_null(session);
        qihse_resp_integer(session, 0);
        return true;
    }
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "punsubscribe");
    for (size_t i = 1; i < request->argc; i++) {
        const char* pattern = (const char*)request->argv[i].data;
        size_t len = request->argv[i].len;
        size_t index = qihse_resp_sub_find(session->sub_patterns, session->sub_pattern_lens, session->sub_pattern_count, pattern, len);
        if (index != SIZE_MAX) {
            qihse_resp_pubsub_punsubscribe(session->server->pubsub, session, pattern, len);
            qihse_resp_sub_remove_at(&session->sub_patterns, &session->sub_pattern_lens, &session->sub_pattern_count, index);
        }
        qihse_resp_array(session, 3);
        qihse_resp_bulk_text(session, "punsubscribe");
        qihse_resp_bulk(session, pattern, len);
        qihse_resp_integer(session, (int64_t)(session->sub_channel_count + session->sub_pattern_count));
    }
    return true;
}

static bool qihse_resp_handle_pubsub(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_wrong_arity(session, "pubsub");
    if (!session->server->pubsub) return qihse_resp_error(session, "ERR pub/sub is not available");
    if (qihse_resp_arg_equal(&request->argv[1], "CHANNELS")) {
        const char* glob = NULL;
        char glob_buffer[4096];
        if (request->argc >= 3) {
            if (request->argv[2].len >= sizeof(glob_buffer)) return qihse_resp_error(session, "ERR pattern too long");
            memcpy(glob_buffer, request->argv[2].data, request->argv[2].len);
            glob_buffer[request->argv[2].len] = '\0';
            glob = glob_buffer;
        }
        char* names[256];
        size_t count = qihse_resp_pubsub_channels(session->server->pubsub, glob, names, sizeof(names) / sizeof(names[0]));
        qihse_resp_array(session, count);
        for (size_t i = 0; i < count; i++) {
            qihse_resp_bulk_text(session, names[i]);
            free(names[i]);
        }
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "NUMSUB")) {
        if (request->argc == 2) return qihse_resp_array(session, 0);
        qihse_resp_array(session, request->argc - 2);
        for (size_t i = 2; i < request->argc; i++) {
            qihse_resp_bulk(session, request->argv[i].data, request->argv[i].len);
            qihse_resp_integer(session, (int64_t)qihse_resp_pubsub_channel_subscribers(session->server->pubsub, (const char*)request->argv[i].data, request->argv[i].len));
        }
        return true;
    }
    if (qihse_resp_arg_equal(&request->argv[1], "NUMPAT"))
        return qihse_resp_integer(session, (int64_t)qihse_resp_pubsub_pattern_subscription_count(session->server->pubsub));
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
    char* existing = qihse_kv_get_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
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
    pthread_rwlock_wrlock(&session->server->kv_lock);
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
    pthread_rwlock_unlock(&session->server->kv_lock);
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

/* ---------------------------------------------------------------------------
 * U2 tenant scoping + quotas
 * Tenant principals (tenant_id != 0) are deny-by-default at the engine
 * boundary: they may only touch keys in their own "t:<tenant_id>/" namespace
 * or the shared "commons/" namespace, and quota-bearing command classes are
 * charged per command. System-domain principals (tenant 0, incl. the
 * operator) are exempt. This is defense in depth against a mis-prefixed or
 * malicious tenant client — per-record clearance checks still apply below.
 * ------------------------------------------------------------------------- */
static bool qihse_resp_tenant_key_allowed(uint32_t tenant, const qihse_resp_arg_t* key) {
    static const char commons_prefix[] = "commons/";
    if (key->len >= sizeof(commons_prefix) - 1u &&
        memcmp(key->data, commons_prefix, sizeof(commons_prefix) - 1u) == 0) {
        return true;
    }
    if (key->len > 2 && key->data[0] == 't' && key->data[1] == ':') {
        uint64_t parsed = 0;
        size_t i = 2;
        for (; i < key->len && key->data[i] >= '0' && key->data[i] <= '9'; i++) {
            parsed = parsed * 10u + (uint64_t)(key->data[i] - '0');
            if (parsed > 0xFFFFFFFFu) return false;
        }
        if (i > 2 && i < key->len && key->data[i] == '/' && (uint32_t)parsed == tenant) {
            return true;
        }
    }
    return false;
}

static bool qihse_resp_key_is_tenant_telemetry(uint32_t tenant, const qihse_resp_arg_t* key) {
    char prefix[32];
    int len = snprintf(prefix, sizeof(prefix), "t:%u/tlm/", tenant);
    return len > 0 && (size_t)len < sizeof(prefix) && key->len >= (size_t)len &&
           memcmp(key->data, prefix, (size_t)len) == 0;
}

/* Returns false only when the command is over quota (reply already sent). */
static bool qihse_resp_tenant_quota(qihse_resp_session_t* session, const qihse_resp_request_t* request, uint32_t tenant) {
    if (!session->server->quotas) return true;
    if (tenant == QIHSE_TENANT_SYSTEM) return true;

    qihse_quota_class_t quota_class = QIHSE_QUOTA_KV_WRITE;
    bool chargeable = false;
    if (qihse_resp_command_is(request, "BUNDLE.PREPARE")) {
        quota_class = QIHSE_QUOTA_BUNDLE_PULL;
        chargeable = true;
    } else if (qihse_resp_command_is(request, "VECSEARCH") || qihse_resp_command_is(request, "VECSCATTER")) {
        quota_class = QIHSE_QUOTA_ANN_QUERY;
        chargeable = true;
    } else {
        const qihse_resp_command_descriptor_t* descriptor = qihse_resp_find_command(&request->argv[0]);
        if (descriptor && (descriptor->flags & QIHSE_COMMAND_WRITE)) {
            /* Telemetry-namespace writes are charged against the ingest
             * budget; other tenant writes against the generic write budget.
             * Writes missing from the descriptor table go uncharged
             * (under-charging is acceptable; clearance checks still apply). */
            quota_class = QIHSE_QUOTA_KV_WRITE;
            for (size_t i = 1; i < request->argc; i++) {
                if (qihse_resp_key_is_tenant_telemetry(tenant, &request->argv[i])) {
                    quota_class = QIHSE_QUOTA_TELEMETRY_INGEST;
                    break;
                }
            }
            chargeable = true;
        }
    }
    if (!chargeable) return true;
    if (qihse_quota_allow(session->server->quotas, tenant, quota_class)) return true;
    if (session->server->metrics) qihse_metrics_increment(session->server->metrics, "qihse_quota_rejected_total", 1);
    qihse_resp_error(session, "QUOTA Tenant quota exceeded for this operation class");
    return false; /* error emitted; dispatch keeps the session open */
}

static bool qihse_resp_tenant_scope(qihse_resp_session_t* session, const qihse_resp_request_t* request, const qihse_resp_keyset_t* keys, uint32_t tenant) {
    if (tenant == QIHSE_TENANT_SYSTEM) return true;
    for (size_t i = 0; i < keys->count; i++) {
        const qihse_resp_arg_t* key = &request->argv[keys->indexes[i]];
        if (!qihse_resp_tenant_key_allowed(tenant, key)) {
            char buffer[160];
            int len = snprintf(buffer, sizeof(buffer), "NOPERM key '%.*s' is outside tenant namespace t:%u/",
                               key->len > 96 ? 96 : (int)key->len, (const char*)key->data, tenant);
            if (len > 0) qihse_resp_error(session, buffer);
            else qihse_resp_error(session, "NOPERM key outside tenant namespace");
            return false; /* error emitted; dispatch keeps the session open */
        }
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * U4 PII-free ingest gate
 * Writes into the telemetry namespace ("t:<id>/tlm/...") must match the
 * closed record-type whitelist with per-field validators. Violations are
 * REJECTED at ingest for every principal — this is structural, not policy.
 * ------------------------------------------------------------------------- */
static bool qihse_resp_ingest_gate(qihse_resp_session_t* session, const qihse_resp_request_t* request, const qihse_resp_keyset_t* keys) {
    const qihse_resp_command_descriptor_t* descriptor = qihse_resp_find_command(&request->argv[0]);
    if (!descriptor || !(descriptor->flags & QIHSE_COMMAND_WRITE)) return true;

    for (size_t i = 0; i < keys->count; i++) {
        size_t key_index = keys->indexes[i];
        const qihse_resp_arg_t* key = &request->argv[key_index];
        if (!qihse_ingest_is_telemetry_key(key->data, key->len)) continue;
        /* Locate the value argument for this key. */
        size_t value_index;
        if (qihse_resp_command_is(request, "MSET")) value_index = key_index + 1u;
        else if (qihse_resp_command_is(request, "TS.ADD") || qihse_resp_command_is(request, "SETEX") ||
                 qihse_resp_command_is(request, "PSETEX")) value_index = 3u;
        else value_index = key_index + 1u;
        if (value_index >= request->argc) {
            qihse_resp_error(session, "INGEST malformed telemetry write rejected");
            return false;
        }
        const qihse_resp_arg_t* value = &request->argv[value_index];
        char reason[128];
        if (!qihse_ingest_guard_validate(key->data, key->len, value->data, value->len, reason, sizeof(reason))) {
            if (session->server->metrics) qihse_metrics_increment(session->server->metrics, "qihse_ingest_rejected_total", 1);
            char buffer[192];
            int len = snprintf(buffer, sizeof(buffer), "INGEST record rejected: %s", reason);
            if (len <= 0) len = snprintf(buffer, sizeof(buffer), "INGEST record rejected");
            qihse_resp_error(session, buffer);
            return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------------------
 * U3 session-bundle delivery (RESP-native). The manifest is self-contained
 * (blob hashes + fresh per-session KEM encapsulation), so BUNDLE.CHUNK needs
 * no server-side session state. Every blob byte is served through
 * qihse_blob_get_user with the caller's user context (invariant #1).
 * ------------------------------------------------------------------------- */
static bool qihse_resp_handle_bundle_prepare(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->composer) return qihse_resp_error(session, "ERR bundle delivery is not configured on this server");
    uint32_t session_tenant = qihse_user_get_tenant_id(session->user);
    uint32_t tenant_id = session_tenant;
    size_t fingerprint_index = 1u;
    if (session_tenant == QIHSE_TENANT_SYSTEM) {
        /* System-domain callers compose on behalf of a tenant. */
        uint64_t parsed;
        if (request->argc < 3 || !qihse_resp_parse_u64_arg(&request->argv[1], &parsed) || parsed > 0xFFFFFFFFu) {
            return qihse_resp_error(session, "ERR usage: BUNDLE.PREPARE <tenant_id> <fingerprint> [have-hash ...]");
        }
        tenant_id = (uint32_t)parsed;
        fingerprint_index = 2u;
    }
    if (request->argc < (int)fingerprint_index + 1u) return qihse_resp_wrong_arity(session, "bundle.prepare");
    if (request->argv[fingerprint_index].len != 16u ||
        memchr(request->argv[fingerprint_index].data, '\0', 16u)) {
        return qihse_resp_error(session, "ERR fingerprint must be 16 lowercase hex characters");
    }
    char fingerprint[17];
    memcpy(fingerprint, request->argv[fingerprint_index].data, 16u);
    fingerprint[16u] = '\0';

    /* Remaining args are have-list hashes (delta). */
    const char* have[QIHSE_BUNDLE_MAX_BLOBS];
    size_t have_count = 0;
    size_t hash_hex_len = QIHSE_BLOB_HASH_HEX - 1u;
    for (size_t i = fingerprint_index + 1u; i < request->argc && have_count < QIHSE_BUNDLE_MAX_BLOBS; i++) {
        if (request->argv[i].len != hash_hex_len) continue; /* ignore malformed have entries */
        char* hex = malloc(hash_hex_len + 1u);
        if (!hex) break;
        memcpy(hex, request->argv[i].data, hash_hex_len);
        hex[hash_hex_len] = '\0';
        have[have_count++] = hex;
    }

    char err[192];
    char* manifest = NULL;
    size_t manifest_len = 0;
    uint64_t compose_started_ms = qihse_resp_now_ms();
    bool composed = qihse_bundle_compose(session->server->composer, session->user, tenant_id,
                                         fingerprint, have, have_count,
                                         &manifest, &manifest_len, err, sizeof(err));
    if (session->server->metrics) {
        if (composed) {
            qihse_metrics_increment(session->server->metrics, "qihse_bundle_compose_total", 1);
            qihse_metrics_observe(session->server->metrics, "qihse_bundle_compose_latency_ms",
                                  (double)(qihse_resp_now_ms() - compose_started_ms));
            if (have_count > 0) qihse_metrics_increment(session->server->metrics, "qihse_bundle_delta_hits", (double)have_count);
        }
    }
    for (size_t i = 0; i < have_count; i++) free((void*)have[i]);
    if (!composed) {
        char buffer[256];
        int len = snprintf(buffer, sizeof(buffer), "ERR bundle compose failed: %s", err);
        if (len <= 0) qihse_resp_error(session, "ERR bundle compose failed");
        else qihse_resp_error(session, buffer);
        return true;
    }
    bool ok = qihse_resp_bulk(session, (const uint8_t*)manifest, manifest_len);
    free(manifest);
    return ok;
}

static bool qihse_resp_handle_bundle_chunk(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->blobs) return qihse_resp_error(session, "ERR bundle delivery is not configured on this server");
    if (request->argc != 3) return qihse_resp_wrong_arity(session, "bundle.chunk");
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    char hex[QIHSE_BLOB_HASH_HEX];
    size_t hash_hex_len = QIHSE_BLOB_HASH_HEX - 1u;
    if (request->argv[1].len != hash_hex_len) return qihse_resp_error(session, "ERR blob hash must be " /* 96 */ "96 hex characters (SHA-384)");
    memcpy(hex, request->argv[1].data, hash_hex_len);
    hex[hash_hex_len] = '\0';
    if (!qihse_blob_hash_from_hex(hex, hash)) return qihse_resp_error(session, "ERR blob hash must be 96 hex characters (SHA-384)");
    uint64_t offset;
    if (!qihse_resp_parse_u64_arg(&request->argv[2], &offset)) return qihse_resp_error(session, "ERR invalid offset");

    uint8_t* buffer = malloc(QIHSE_BUNDLE_CHUNK_SIZE);
    if (!buffer) return qihse_resp_error(session, "OOM out of memory");
    size_t nread = 0;
    /* Authorization is re-checked inside the blob store on every read: a
     * revoked or foreign principal cannot drain a transfer (invariant #1). */
    if (!qihse_blob_get_user(session->server->blobs, hash, offset, buffer,
                             QIHSE_BUNDLE_CHUNK_SIZE, &nread, session->user)) {
        free(buffer);
        /* Denial and I/O failure are indistinguishable to the client. */
        return qihse_resp_error(session, "ERR blob read denied");
    }
    bool ok = qihse_resp_bulk(session, buffer, nread);
    free(buffer);
    return ok;
}

/* ---------------------------------------------------------------------------
 * W5.2 telemetry: registration, then scrape-time sampling.
 *
 * Everything below registers into the ONE registry that already backs
 * METRICS.RENDER.  There is no second metrics surface, no second exporter and
 * no parallel naming scheme: the new families use the `qihse_*` names the
 * whitepaper's telemetry contract already lists.
 * ------------------------------------------------------------------------- */

/* Latency bucket ladder, in seconds.
 *
 * Chosen deliberately, not geometrically-by-accident:
 *   - Ratio 2.5 between bounds (4 buckets per decade), which is the ladder
 *     Prometheus uses for its own http_request_duration_seconds.  It bounds
 *     the quantization error at any point to ~25%, which is enough to see a
 *     regression and not enough to lie about one.
 *   - Starts at 50 us rather than Prometheus's 5 ms, because a native
 *     in-process store answers a point operation in tens of microseconds; a
 *     ladder that starts at 5 ms would put every healthy request in the first
 *     bucket and measure nothing.
 *   - Ends at 5 s.  Beyond that a query is not "slow", it is hung, and one
 *     overflow bucket (the +Inf bucket, which is `_count`) says so honestly
 *     instead of pretending to resolve it.
 *   - 16 bounds is the compile-time cap (QIHSE_METRICS_MAX_BUCKETS), so the
 *     per-series cost is a fixed 16 counters x 16 bytes and cannot grow with
 *     traffic.  Quantiles (p50/p95/p99) are derived by the scraper with
 *     histogram_quantile() from these buckets; the registry deliberately does
 *     not maintain a decayed reservoir, which would be the only way to get a
 *     native quantile and is lossy under the hood.
 */
static const double g_query_latency_bounds[] = {
    0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01,
    0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
};

#define QIHSE_FEDERATION_STATE_VALUES 6u

/* Register one unlabelled series and cache its handle. */
static void qihse_resp_telemetry_gauge(qihse_metrics_registry_t* reg,
                                       qihse_metric_series_t** handle,
                                       const char* name, const char* help,
                                       metric_type_t type) {
    if (qihse_metrics_register(reg, name, help, type) != 0) return;
    *handle = qihse_metrics_series(reg, name, NULL);
}

/* Register the W5.2 families.  Called once, from server create, so every
 * value set is fixed before the first request is served. */
static void qihse_resp_telemetry_register(qihse_resp_server_t* server) {
    qihse_metrics_registry_t* reg = server->metrics;
    if (!reg) return;

    const char* query_types[QIHSE_QUERY_TYPE_COUNT];
    for (size_t i = 0; i < (size_t)QIHSE_QUERY_TYPE_COUNT; i++) {
        query_types[i] = qihse_query_type_name((qihse_query_type_t)i);
    }
    const char* backends[QIHSE_ENGINE_BACKEND_COUNT];
    for (size_t i = 0; i < (size_t)QIHSE_ENGINE_BACKEND_COUNT; i++) {
        backends[i] = qihse_engine_backend_name((qihse_engine_backend_t)i);
    }

    if (qihse_metrics_register_bounded(reg, "qihse_queries_total",
                                       "Commands dispatched, by query type",
                                       METRIC_COUNTER, "type",
                                       query_types, (size_t)QIHSE_QUERY_TYPE_COUNT) == 0) {
        for (size_t i = 0; i < (size_t)QIHSE_QUERY_TYPE_COUNT; i++) {
            server->tlm.queries[i] = qihse_metrics_series(reg, "qihse_queries_total", query_types[i]);
        }
    }
    if (qihse_metrics_register_bounded(reg, "qihse_query_errors_total",
                                       "Error replies, by query type",
                                       METRIC_COUNTER, "type",
                                       query_types, (size_t)QIHSE_QUERY_TYPE_COUNT) == 0) {
        for (size_t i = 0; i < (size_t)QIHSE_QUERY_TYPE_COUNT; i++) {
            server->tlm.errors[i] = qihse_metrics_series(reg, "qihse_query_errors_total", query_types[i]);
        }
    }
    if (qihse_metrics_register_bounded(reg, "qihse_query_latency_seconds",
                                       "Command latency, by query type",
                                       METRIC_HISTOGRAM, "type",
                                       query_types, (size_t)QIHSE_QUERY_TYPE_COUNT) == 0) {
        size_t buckets = sizeof(g_query_latency_bounds) / sizeof(g_query_latency_bounds[0]);
        for (size_t i = 0; i < (size_t)QIHSE_QUERY_TYPE_COUNT; i++) {
            qihse_metrics_set_buckets(reg, "qihse_query_latency_seconds", query_types[i],
                                      g_query_latency_bounds, buckets);
            server->tlm.latency[i] = qihse_metrics_series(reg, "qihse_query_latency_seconds", query_types[i]);
        }
    }
    if (qihse_metrics_register_bounded(reg, "qihse_backend_queries_total",
                                       "Commands attributed to each engine backend",
                                       METRIC_COUNTER, "backend",
                                       backends, (size_t)QIHSE_ENGINE_BACKEND_COUNT) == 0) {
        for (size_t i = 0; i < (size_t)QIHSE_ENGINE_BACKEND_COUNT; i++) {
            server->tlm.backend_queries[i] = qihse_metrics_series(reg, "qihse_backend_queries_total", backends[i]);
        }
    }
    if (qihse_metrics_register_bounded(reg, "qihse_backend_available",
                                       "Engine backend configured and usable on this node (1/0)",
                                       METRIC_GAUGE, "backend",
                                       backends, (size_t)QIHSE_ENGINE_BACKEND_COUNT) == 0) {
        for (size_t i = 0; i < (size_t)QIHSE_ENGINE_BACKEND_COUNT; i++) {
            server->tlm.backend_available[i] = qihse_metrics_series(reg, "qihse_backend_available", backends[i]);
        }
    }

    /* Federation state as a bounded info-style family: exactly one member is
     * 1 and the rest are 0, so `sum(qihse_federation_state)` stays 1 and a
     * state the enum does not name cannot appear as a series. */
    const char* fed_states[QIHSE_FEDERATION_STATE_VALUES];
    for (size_t i = 0; i < QIHSE_FEDERATION_STATE_VALUES; i++) {
        const char* nm = qihse_federation_state_name((qihse_federation_state_t)i);
        fed_states[i] = nm ? nm : "unknown";
    }
    if (qihse_metrics_register_bounded(reg, "qihse_federation_state",
                                       "Federation operating state of this node (1 for the current state)",
                                       METRIC_GAUGE, "state",
                                       fed_states, QIHSE_FEDERATION_STATE_VALUES) == 0) {
        for (size_t i = 0; i < QIHSE_FEDERATION_STATE_VALUES; i++) {
            server->tlm.federation_state[i] = qihse_metrics_series(reg, "qihse_federation_state", fed_states[i]);
        }
    }

    qihse_resp_telemetry_gauge(reg, &server->tlm.cluster_nodes_total, "qihse_cluster_nodes_total",
                               "Nodes known to the cluster topology", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.cluster_nodes_healthy, "qihse_cluster_nodes_healthy",
                               "Nodes the cluster topology reports healthy", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.cluster_slots_assigned, "qihse_cluster_slots_assigned",
                               "Hash slots with an assigned owner", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.cluster_epoch, "qihse_cluster_epoch",
                               "Topology configuration epoch", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.cluster_local_role, "qihse_cluster_local_role",
                               "This node's role (0 primary, 1 replica)", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.federation_pending_events, "qihse_replication_pending_events",
                               "Replication events not yet acknowledged", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.replication_attempts, "qihse_replication_attempts_total",
                               "Async write-duplication attempts to the redundancy peer", METRIC_COUNTER);
    qihse_resp_telemetry_gauge(reg, &server->tlm.replication_failures, "qihse_replication_failures_total",
                               "Async write-duplication attempts that did not reach the peer", METRIC_COUNTER);
    qihse_resp_telemetry_gauge(reg, &server->tlm.kv_keys, "qihse_kv_keys",
                               "Live keys in the local key-value store", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.vector_bytes_in_ram, "qihse_vector_bytes_in_ram",
                               "Vector bytes resident in RAM", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.vector_rows_spilled, "qihse_vector_rows_spilled",
                               "Vector rows evicted to the spill file", METRIC_GAUGE);
    qihse_resp_telemetry_gauge(reg, &server->tlm.label_rejected, "qihse_metrics_label_rejected_total",
                               "Attempts to use a label value outside its declared value set", METRIC_COUNTER);
    qihse_resp_telemetry_gauge(reg, &server->tlm.xdp_frames_rx, "qihse_xdp_frames_rx_total",
                               "AF_XDP frames taken off the RX ring", METRIC_COUNTER);
    qihse_resp_telemetry_gauge(reg, &server->tlm.xdp_frames_dropped, "qihse_xdp_frames_dropped_total",
                               "AF_XDP frames that produced no ingested artifact", METRIC_COUNTER);
    qihse_resp_telemetry_gauge(reg, &server->tlm.xdp_frames_ingested, "qihse_xdp_artifacts_ingested_total",
                               "Artifacts the XDP path ingested into Keystone", METRIC_COUNTER);
    qihse_resp_telemetry_gauge(reg, &server->tlm.xdp_ingest_denied, "qihse_xdp_ingest_denied_total",
                               "XDP frames refused for lack of clearance or SCI compartment", METRIC_COUNTER);
}

/* Refresh the values that are too expensive to maintain per request: cluster
 * and replication status, engine availability, engine occupancy and the XDP
 * datapath totals.  Called immediately before the registry is exported, so a
 * scrape always reports the state at scrape time and the request path pays
 * nothing for any of it. */
static void qihse_resp_metrics_sample(qihse_resp_server_t* server) {
    if (!server || !server->metrics) return;
    qihse_resp_telemetry_t* t = &server->tlm;

    if (t->label_rejected) {
        qihse_metrics_series_set(t->label_rejected,
                                 (double)__atomic_load_n(&server->metrics->label_rejected_total, __ATOMIC_RELAXED));
    }

    /* ── Cluster + replication status ── */
    if (server->topology) {
        /* One heap buffer, not a 24 KB stack frame: QIHSE_CLUSTER_MAX_NODES is
         * 256 and a node record is ~90 bytes.  Scrape-time only. */
        qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(QIHSE_CLUSTER_MAX_NODES * sizeof(*nodes));
        size_t total = qihse_cluster_topology_nodes(server->topology, NULL, 0);
        size_t healthy = 0;
        if (nodes) {
            size_t n = qihse_cluster_topology_nodes(server->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
            for (size_t i = 0; i < n; i++) {
                if (nodes[i].healthy) healthy++;
            }
            free(nodes);
        }
        if (t->cluster_nodes_total) qihse_metrics_series_set(t->cluster_nodes_total, (double)total);
        if (t->cluster_nodes_healthy) qihse_metrics_series_set(t->cluster_nodes_healthy, (double)healthy);
        if (t->cluster_slots_assigned) {
            qihse_metrics_series_set(t->cluster_slots_assigned,
                                     (double)qihse_cluster_topology_assigned_slots(server->topology));
        }
        if (t->cluster_epoch) {
            qihse_metrics_series_set(t->cluster_epoch,
                                     (double)qihse_cluster_topology_epoch(server->topology));
        }
        if (t->cluster_local_role) {
            qihse_cluster_node_t local_node;
            uint16_t local = qihse_cluster_topology_local_node(server->topology);
            bool replica = qihse_cluster_topology_get_node(server->topology, local, &local_node) &&
                           local_node.role == QIHSE_CLUSTER_NODE_REPLICA;
            qihse_metrics_series_set(t->cluster_local_role, replica ? 1.0 : 0.0);
        }
    }
    pthread_mutex_lock(&server->federation_lock);
    qihse_federation_status_recompute(&server->federation_status);
    qihse_federation_state_t state = server->federation_status.federation_state;
    uint64_t pending = server->federation_status.pending_replication_events;
    pthread_mutex_unlock(&server->federation_lock);
    for (size_t i = 0; i < QIHSE_FEDERATION_STATE_VALUES; i++) {
        if (t->federation_state[i]) {
            qihse_metrics_series_set(t->federation_state[i], ((size_t)state == i) ? 1.0 : 0.0);
        }
    }
    if (t->federation_pending_events) qihse_metrics_series_set(t->federation_pending_events, (double)pending);
    if (t->replication_attempts) {
        qihse_metrics_series_set(t->replication_attempts, (double)server->replication_attempts);
    }
    if (t->replication_failures) {
        qihse_metrics_series_set(t->replication_failures, (double)server->replication_failures);
    }

    /* ── Backend availability (the engines actually attached) + occupancy ── */
    if (t->backend_available[QIHSE_ENGINE_BACKEND_KV]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_KV], server->store ? 1.0 : 0.0);
    }
    if (t->backend_available[QIHSE_ENGINE_BACKEND_VECTOR]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_VECTOR], server->vdb ? 1.0 : 0.0);
    }
    if (t->backend_available[QIHSE_ENGINE_BACKEND_TIMESERIES]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_TIMESERIES], server->tsdb ? 1.0 : 0.0);
    }
    if (t->backend_available[QIHSE_ENGINE_BACKEND_COLUMN]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_COLUMN], server->column_store ? 1.0 : 0.0);
    }
    /* The RESP server holds no document, graph or FTS engine handle, so those
     * backends report 0 rather than a fabricated availability.  The control
     * plane is always "available": it is this process. */
    if (t->backend_available[QIHSE_ENGINE_BACKEND_DOCUMENT]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_DOCUMENT], 0.0);
    }
    if (t->backend_available[QIHSE_ENGINE_BACKEND_GRAPH]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_GRAPH], 0.0);
    }
    if (t->backend_available[QIHSE_ENGINE_BACKEND_FTS]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_FTS], 0.0);
    }
    if (t->backend_available[QIHSE_ENGINE_BACKEND_CONTROL]) {
        qihse_metrics_series_set(t->backend_available[QIHSE_ENGINE_BACKEND_CONTROL], 1.0);
    }

    /* ── Memory + index movement ── */
    if (t->kv_keys && server->store) {
        qihse_metrics_series_set(t->kv_keys, (double)qihse_kv_count(server->store));
    }
    if (server->vdb && (t->vector_bytes_in_ram || t->vector_rows_spilled)) {
        size_t budget = 0;
        size_t in_ram = 0;
        size_t spilled = 0;
        pthread_mutex_lock(&server->vdb_lock);
        bool have = qihse_vector_db_get_memory_usage(server->vdb, &budget, &in_ram, &spilled);
        pthread_mutex_unlock(&server->vdb_lock);
        if (have) {
            if (t->vector_bytes_in_ram) qihse_metrics_series_set(t->vector_bytes_in_ram, (double)in_ram);
            if (t->vector_rows_spilled) qihse_metrics_series_set(t->vector_rows_spilled, (double)spilled);
        }
    }

    /* ── Network / XDP ── */
#ifndef _WIN32
    qihse_af_xdp_stats_t xdp;
    qihse_af_xdp_stats_get(&xdp);
    if (t->xdp_frames_rx) qihse_metrics_series_set(t->xdp_frames_rx, (double)xdp.frames_rx);
    if (t->xdp_frames_dropped) qihse_metrics_series_set(t->xdp_frames_dropped, (double)xdp.frames_dropped);
    if (t->xdp_frames_ingested) qihse_metrics_series_set(t->xdp_frames_ingested, (double)xdp.artifacts_ingested);
    if (t->xdp_ingest_denied) qihse_metrics_series_set(t->xdp_ingest_denied, (double)xdp.ingest_denied);
#endif
}

/* U9: render the delivery metrics registry (Prometheus text). System-domain
 * only — metric values are operational data tenants have no business reading. */
static bool qihse_resp_handle_metrics_render(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    (void)request;
    if (!session->server->metrics) return qihse_resp_error(session, "ERR metrics are not available");
    if (qihse_user_get_tenant_id(session->user) != QIHSE_TENANT_SYSTEM) {
        return qihse_resp_error(session, "NOPERM metrics exposure is restricted to the system domain");
    }
    /* W5.2: refresh the scrape-time series before rendering, so the export is
     * a snapshot of now rather than of whenever the last request ran. */
    qihse_resp_metrics_sample(session->server);
    char* text = qihse_metrics_export(session->server->metrics);
    if (!text) return qihse_resp_error(session, "ERR metrics export failed");
    bool ok = qihse_resp_bulk_text(session, text);
    free(text);
    return ok;
}

/* -------------------------------------------------------------------------
 * Command dispatch table — one hash probe replaces the ~130-branch
 * command_is if-else chain that previously ran for every request.
 * ------------------------------------------------------------------------- */
/* Thin wrappers for parameterized handlers so the table has one signature. */
static bool dsp_setex_s(qihse_resp_session_t* s, const qihse_resp_request_t* r)  { return qihse_resp_handle_setex(s, r, false); }
static bool dsp_setex_ms(qihse_resp_session_t* s, const qihse_resp_request_t* r) { return qihse_resp_handle_setex(s, r, true); }
static bool dsp_del(qihse_resp_session_t* s, const qihse_resp_request_t* r)      { return qihse_resp_handle_del_exists(s, r, true); }
static bool dsp_exists(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_del_exists(s, r, false); }
static bool dsp_expire(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_expiry(s, r, false); }
static bool dsp_expire_ms(qihse_resp_session_t* s, const qihse_resp_request_t* r){ return qihse_resp_handle_expiry(s, r, true); }
static bool dsp_ttl(qihse_resp_session_t* s, const qihse_resp_request_t* r)      { return qihse_resp_handle_ttl(s, r, false); }
static bool dsp_ttl_ms(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_ttl(s, r, true); }
static bool dsp_incr(qihse_resp_session_t* s, const qihse_resp_request_t* r)     { return qihse_resp_handle_increment(s, r, 1); }
static bool dsp_decr(qihse_resp_session_t* s, const qihse_resp_request_t* r)     { return qihse_resp_handle_increment(s, r, -1); }
static bool dsp_vecsearch(qihse_resp_session_t* s, const qihse_resp_request_t* r){ return qihse_resp_handle_vecsearch(s, r, false); }
static bool dsp_vecscatter(qihse_resp_session_t* s, const qihse_resp_request_t* r){ return qihse_resp_handle_vecsearch(s, r, true); }
static bool dsp_lpush(qihse_resp_session_t* s, const qihse_resp_request_t* r)    { return qihse_resp_handle_lpush(s, r, true); }
static bool dsp_rpush(qihse_resp_session_t* s, const qihse_resp_request_t* r)    { return qihse_resp_handle_lpush(s, r, false); }
static bool dsp_lpop(qihse_resp_session_t* s, const qihse_resp_request_t* r)     { return qihse_resp_handle_lpop(s, r, true); }
static bool dsp_rpop(qihse_resp_session_t* s, const qihse_resp_request_t* r)     { return qihse_resp_handle_lpop(s, r, false); }
static bool dsp_zrange(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_zrange(s, r, false); }
static bool dsp_zrevrange(qihse_resp_session_t* s, const qihse_resp_request_t* r){ return qihse_resp_handle_zrange(s, r, true); }
static bool dsp_zrank(qihse_resp_session_t* s, const qihse_resp_request_t* r)    { return qihse_resp_handle_zrank(s, r, false); }
static bool dsp_zrevrank(qihse_resp_session_t* s, const qihse_resp_request_t* r) { return qihse_resp_handle_zrank(s, r, true); }
static bool dsp_zpopmax(qihse_resp_session_t* s, const qihse_resp_request_t* r)  { return qihse_resp_handle_zpop(s, r, true); }
static bool dsp_zpopmin(qihse_resp_session_t* s, const qihse_resp_request_t* r)  { return qihse_resp_handle_zpop(s, r, false); }
static bool dsp_zrangebyscore(qihse_resp_session_t* s, const qihse_resp_request_t* r)    { return qihse_resp_handle_zrangebyscore(s, r, false); }
static bool dsp_zrevrangebyscore(qihse_resp_session_t* s, const qihse_resp_request_t* r) { return qihse_resp_handle_zrangebyscore(s, r, true); }
static bool dsp_rename(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_rename(s, r, false); }
static bool dsp_renamenx(qihse_resp_session_t* s, const qihse_resp_request_t* r) { return qihse_resp_handle_rename(s, r, true); }
static bool dsp_incrby(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_incrby(s, r, false); }
static bool dsp_decrby(qihse_resp_session_t* s, const qihse_resp_request_t* r)   { return qihse_resp_handle_incrby(s, r, true); }
static bool dsp_expireat(qihse_resp_session_t* s, const qihse_resp_request_t* r) { return qihse_resp_handle_expireat(s, r, false); }
static bool dsp_pexpireat(qihse_resp_session_t* s, const qihse_resp_request_t* r){ return qihse_resp_handle_expireat(s, r, true); }
static bool dsp_save(qihse_resp_session_t* s, const qihse_resp_request_t* r)     { (void)r; return qihse_resp_simple(s, "OK"); }
static bool dsp_lastsave(qihse_resp_session_t* s, const qihse_resp_request_t* r) { (void)r; return qihse_resp_integer(s, (int64_t)time(NULL)); }
static bool dsp_type(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc != 2) return qihse_resp_wrong_arity(session, "type");
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    char keybuf[256];
    char* key = qihse_resp_arg_text_buf(&request->argv[1], keybuf, sizeof(keybuf));
    if (!key) key = qihse_resp_arg_text(&request->argv[1]);
    pthread_rwlock_rdlock(&session->server->kv_lock);
    bool exists = key && qihse_kv_exists_user(session->server->store, key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (key && key != keybuf) free(key);
    return qihse_resp_simple(session, exists ? "string" : "none");
}

static const qihse_resp_dispatch_ent_t g_dispatch_table[] = {
    {"get", qihse_resp_handle_get, DSP_KEY_1KV},
    {"set", qihse_resp_handle_set, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"setex", dsp_setex_s, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"psetex", dsp_setex_ms, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"del", dsp_del, DSP_BUSY_WRITE | DSP_KEY_ALLKV},
    {"unlink", dsp_del, DSP_BUSY_WRITE},
    {"exists", dsp_exists, DSP_KEY_ALLKV},
    {"mget", qihse_resp_handle_mget, DSP_KEY_ALLKV},
    {"mset", qihse_resp_handle_mset, DSP_BUSY_WRITE | DSP_KEY_ODDKV},
    {"migrate", qihse_resp_handle_migrate, DSP_BUSY_WRITE | DSP_KEY_MIGRATE},
    {"expire", dsp_expire, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"pexpire", dsp_expire_ms, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"ttl", dsp_ttl, DSP_KEY_1KV}, {"pttl", dsp_ttl_ms, DSP_KEY_1KV},
    {"incr", dsp_incr, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"decr", dsp_decr, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"type", dsp_type, DSP_KEY_1KV},
    {"vecset", qihse_resp_handle_vecset, DSP_BUSY_WRITE | DSP_KEY_VECTAG},
    {"vecget", qihse_resp_handle_vecget, DSP_KEY_VECTAG},
    {"vecsearch", dsp_vecsearch, DSP_KEY_VECSEARCH}, {"vecscatter", dsp_vecscatter, 0},
    {"ts.add", qihse_resp_handle_ts_add, DSP_BUSY_WRITE | DSP_KEY_1},
    {"ts.range", qihse_resp_handle_ts_range, DSP_KEY_1},
    {"col.append", qihse_resp_handle_column, DSP_BUSY_WRITE | DSP_KEY_1},
    {"col.sum", qihse_resp_handle_column, DSP_KEY_1}, {"col.minmax", qihse_resp_handle_column, DSP_KEY_1},
    {"lpush", dsp_lpush, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"rpush", dsp_rpush, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"lpop", dsp_lpop, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"rpop", dsp_rpop, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"llen", qihse_resp_handle_llen, DSP_KEY_1KV}, {"lrange", qihse_resp_handle_lrange, DSP_KEY_1KV},
    {"lindex", qihse_resp_handle_lindex, DSP_KEY_1KV}, {"lset", qihse_resp_handle_lset, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"lrem", qihse_resp_handle_lrem, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"ltrim", qihse_resp_handle_ltrim, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"linsert", qihse_resp_handle_linsert, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"rpoplpush", qihse_resp_handle_rpoplpush, DSP_BUSY_WRITE | DSP_KEY_12KV},
    {"hset", qihse_resp_handle_hset, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"hmset", qihse_resp_handle_hset, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"hget", qihse_resp_handle_hget, DSP_KEY_1KV}, {"hgetall", qihse_resp_handle_hgetall, DSP_KEY_1KV},
    {"hdel", qihse_resp_handle_hdel, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"hexists", qihse_resp_handle_hexists, DSP_KEY_1KV},
    {"hkeys", qihse_resp_handle_hkeys, DSP_KEY_1KV}, {"hvals", qihse_resp_handle_hvals, DSP_KEY_1KV},
    {"hlen", qihse_resp_handle_hlen, DSP_KEY_1KV}, {"hincrby", qihse_resp_handle_hincrby, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"hmget", qihse_resp_handle_hmget, DSP_KEY_1KV}, {"hsetnx", qihse_resp_handle_hsetnx, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"hstrlen", qihse_resp_handle_hstrlen, DSP_KEY_1KV},
    {"sadd", qihse_resp_handle_sadd, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"srem", qihse_resp_handle_srem, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"smembers", qihse_resp_handle_smembers, DSP_KEY_1KV}, {"sismember", qihse_resp_handle_sismember, DSP_KEY_1KV},
    {"scard", qihse_resp_handle_scard, DSP_KEY_1KV}, {"spop", qihse_resp_handle_spop, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"smove", qihse_resp_handle_smove, DSP_BUSY_WRITE | DSP_KEY_12KV},
    {"sdiff", qihse_resp_handle_sdiff, DSP_KEY_FROM2KV}, {"sinter", qihse_resp_handle_sinter, DSP_KEY_FROM2KV},
    {"sunion", qihse_resp_handle_sunion, DSP_KEY_FROM2KV},
    {"srandmember", qihse_resp_handle_srandmember, DSP_KEY_1KV},
    {"zadd", qihse_resp_handle_zadd, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"zrem", qihse_resp_handle_zrem, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"zscore", qihse_resp_handle_zscore, DSP_KEY_1KV}, {"zcard", qihse_resp_handle_zcard, DSP_KEY_1KV},
    {"zcount", qihse_resp_handle_zcount, DSP_KEY_1KV}, {"zincrby", qihse_resp_handle_zincrby, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"zrange", dsp_zrange, DSP_KEY_1KV}, {"zrevrange", dsp_zrevrange, DSP_KEY_1KV},
    {"zrank", dsp_zrank, DSP_KEY_1KV}, {"zrevrank", dsp_zrevrank, DSP_KEY_1KV},
    {"zpopmax", dsp_zpopmax, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"zpopmin", dsp_zpopmin, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"zrangebyscore", dsp_zrangebyscore, DSP_KEY_1KV}, {"zrevrangebyscore", dsp_zrevrangebyscore, DSP_KEY_1KV},
    {"keys", qihse_resp_handle_keys, 0}, {"scan", qihse_resp_handle_scan, 0},
    {"rename", dsp_rename, DSP_BUSY_WRITE | DSP_KEY_12KV}, {"renamenx", dsp_renamenx, DSP_BUSY_WRITE | DSP_KEY_12KV},
    {"getset", qihse_resp_handle_getset, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"getdel", qihse_resp_handle_getdel, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"strlen", qihse_resp_handle_strlen, DSP_KEY_1KV}, {"append", qihse_resp_handle_append, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"getrange", qihse_resp_handle_getrange, DSP_KEY_1KV}, {"setrange", qihse_resp_handle_setrange, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"incrby", dsp_incrby, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"decrby", dsp_decrby, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"incrbyfloat", qihse_resp_handle_incrbyfloat, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"msetnx", qihse_resp_handle_msetnx, DSP_BUSY_WRITE}, {"persist", qihse_resp_handle_persist, DSP_KEY_1KV},
    {"expireat", dsp_expireat, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"pexpireat", dsp_pexpireat, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"copy", qihse_resp_handle_copy, DSP_BUSY_WRITE | DSP_KEY_12KV}, {"randomkey", qihse_resp_handle_randomkey, 0},
    {"touch", qihse_resp_handle_touch, 0}, {"object", qihse_resp_handle_object, DSP_KEY_1KV},
    {"flushdb", qihse_resp_handle_flushdb, DSP_BUSY_WRITE}, {"flushall", qihse_resp_handle_flushdb, DSP_BUSY_WRITE},
    {"dbsize", qihse_resp_handle_dbsize, 0}, {"time", qihse_resp_handle_time, 0},
    {"save", dsp_save, 0}, {"bgsave", dsp_save, 0}, {"lastsave", dsp_lastsave, 0},
    {"shutdown", qihse_resp_handle_shutdown, DSP_BUSY_WRITE}, {"config", qihse_resp_handle_config, 0},
    {"debug", qihse_resp_handle_debug, 0}, {"slowlog", dsp_save, 0},
    {"memory", qihse_resp_handle_memory, 0}, {"latency", dsp_save, 0},
    {"multi", qihse_resp_handle_multi, DSP_MULTI_OK}, {"exec", qihse_resp_handle_exec, DSP_MULTI_OK},
    {"discard", qihse_resp_handle_discard, DSP_MULTI_OK}, {"watch", qihse_resp_handle_watch, DSP_MULTI_OK},
    {"unwatch", qihse_resp_handle_unwatch, DSP_MULTI_OK},
    {"publish", qihse_resp_handle_publish, 0},
    {"subscribe", qihse_resp_handle_subscribe, DSP_SUB_OK}, {"unsubscribe", qihse_resp_handle_unsubscribe, DSP_SUB_OK},
    {"psubscribe", qihse_resp_handle_psubscribe, DSP_SUB_OK}, {"punsubscribe", qihse_resp_handle_punsubscribe, DSP_SUB_OK},
    {"pubsub", qihse_resp_handle_pubsub, 0},
    {"setbit", qihse_resp_handle_setbit, DSP_BUSY_WRITE | DSP_KEY_1KV}, {"getbit", qihse_resp_handle_getbit, DSP_KEY_1KV},
    {"bitcount", qihse_resp_handle_bitcount, DSP_KEY_1KV}, {"bitpos", qihse_resp_handle_bitpos, DSP_KEY_1KV},
    {"bitop", qihse_resp_handle_bitop, DSP_BUSY_WRITE | DSP_KEY_FROM2KV},
    {"pfadd", qihse_resp_handle_pfadd, DSP_BUSY_WRITE | DSP_KEY_1KV},
    {"pfcount", qihse_resp_handle_pfcount, DSP_KEY_1KV},
    {"pfmerge", qihse_resp_handle_pfmerge, DSP_BUSY_WRITE | DSP_KEY_FROM2KV},
    {"eval", qihse_resp_handle_eval, 0}, {"evalsha", qihse_resp_handle_evalsha, 0},
    {"script", qihse_resp_handle_script, 0},
};

#define RESP_DISPATCH_MAP_CAP 256u
static const qihse_resp_dispatch_ent_t* g_dispatch_map[RESP_DISPATCH_MAP_CAP];
static pthread_once_t g_dispatch_map_once = PTHREAD_ONCE_INIT;

static void qihse_resp_dispatch_map_build(void) {
    size_t n = sizeof(g_dispatch_table) / sizeof(g_dispatch_table[0]);
    for (size_t i = 0; i < n; i++) {
        const char* nm = g_dispatch_table[i].name;
        uint32_t h = qihse_resp_cmd_hash((const uint8_t*)nm, strlen(nm)) & (RESP_DISPATCH_MAP_CAP - 1u);
        for (size_t j = 0; j < RESP_DISPATCH_MAP_CAP; j++) {
            size_t pos = (h + j) & (RESP_DISPATCH_MAP_CAP - 1u);
            if (!g_dispatch_map[pos]) { g_dispatch_map[pos] = &g_dispatch_table[i]; break; }
            if (strcasecmp(g_dispatch_map[pos]->name, nm) == 0) break; /* dup name */
        }
    }
}

static const qihse_resp_dispatch_ent_t* qihse_resp_dispatch_find(const qihse_resp_arg_t* name) {
    if (!name) return NULL;
    pthread_once(&g_dispatch_map_once, qihse_resp_dispatch_map_build);
    uint32_t h = qihse_resp_cmd_hash(name->data, name->len) & (RESP_DISPATCH_MAP_CAP - 1u);
    for (size_t i = 0; i < RESP_DISPATCH_MAP_CAP; i++) {
        const qihse_resp_dispatch_ent_t* e = g_dispatch_map[(h + i) & (RESP_DISPATCH_MAP_CAP - 1u)];
        if (!e) return NULL;
        if (strlen(e->name) == name->len && qihse_resp_arg_equal(name, e->name)) return e;
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * CLUSTER MOVESLOTS <first>-<last> <host>:<port>  (system domain only)
 * Streams every locally-owned KV record whose slot falls in the range to the
 * target node over the MIGRATE wire flow (AUTH, ASKING, SET [PX]), deletes it
 * locally, then flips ownership and broadcasts the change on the cluster bus.
 * Keys written to moved slots during the transfer remain on this node until
 * the ownership flip; a short ASK-state window is future work.
 * ------------------------------------------------------------------------- */
#define MOVESLOTS_KEY_MAX 512u
#define MOVESLOTS_KEY_CAP 100000u

typedef struct {
    char (*keys)[MOVESLOTS_KEY_MAX + 1u];
    size_t count;
    size_t cap;
    size_t skipped;
    uint16_t first, last;
} moveslots_collector_t;

static bool moveslots_collect_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    moveslots_collector_t* c = (moveslots_collector_t*)user_data;
    size_t len = strlen(key);
    uint16_t slot = qihse_cluster_key_slot(key, len);
    if (slot < c->first || slot > c->last) return true;
    if (len > MOVESLOTS_KEY_MAX) { c->skipped++; return true; }
    if (c->count >= MOVESLOTS_KEY_CAP) return false; /* stop collecting: cap reached */
    if (c->count == c->cap) {
        size_t next = c->cap ? c->cap * 2u : 256u;
        char (*grown)[MOVESLOTS_KEY_MAX + 1u] = realloc(c->keys, next * sizeof(*grown));
        if (!grown) return false;
        c->keys = grown;
        c->cap = next;
    }
    memcpy(c->keys[c->count], key, len + 1u);
    c->count++;
    return true;
}

/* ---- Shared cluster ops (declared in include/qihse_cluster_ops.h) ---------
 * The CLUSTER MOVESLOTS handler and the cluster brain's R1 re-home share one
 * implementation so a brain action is byte-for-byte the audited migration
 * path, not a parallel copy of it. */

bool qihse_cluster_set_range_owner(qihse_resp_server_t* server, uint16_t first, uint16_t last,
                                   uint16_t owner_index) {
    if (!server || !server->topology) return false;
    if (!qihse_cluster_topology_assign_range(server->topology, first, last, owner_index)) return false;
    if (server->bus) qihse_cluster_bus_broadcast_slot_update(server->bus, first, last, owner_index);
    return true;
}

typedef struct {
    uint16_t first, last;
    size_t seen;
    size_t limit;
    bool found;
} cluster_range_probe_t;

/* Is this key NODE-LOCAL bookkeeping rather than shardable data?
 *
 * Slot ownership exists to decide which node holds a piece of the sharded
 * keyspace. A node's own operational records are not a piece of anything: an
 * incident history, a job record or a capability claim describes THIS node and
 * has no meaning on a peer. Counting them as local data made the brain believe
 * it held shardable content in a range owned by an unhealthy node, so it
 * re-homed that range to a peer — moving bookkeeping, not data.
 *
 * Found by dogfooding: recording brain incidents as AI memories (W3.6) put new
 * keys into the managed keyspace, and the rebalance/prune test caught the
 * consequence. Without that test the effect would have been silent range
 * movement in production.
 *
 * This list is a POLICY STATEMENT, not a derived fact, and CLASSIFYING A NEW
 * NAMESPACE IS MANDATORY EITHER WAY. The failure mode is symmetric and only
 * one direction is obvious:
 *
 *   - A node-local namespace left out of this list makes bookkeeping look like
 *     shardable data, so ranges get re-homed for no reason. That is the bug
 *     this function was written for.
 *   - Application data wrongly ADDED to this list makes a range holding real
 *     records look empty, so it is never replicated to the node that owns it.
 *     That is silent data loss, and it is worse.
 *
 * When in doubt, ask whether the records would mean anything on a peer. Two
 * cases already decided, recorded here so they are not re-litigated:
 *
 *   `ns:` is NOT excluded — it is the application keyspace, which is precisely
 *   what slot ownership partitions.
 *
 *   `task:` is NOT excluded — the task queue is a DISTRIBUTED queue by design
 *   (docs/plans/qihse_task_queue_plan.md: the event stream is the broker and
 *   the KV store is the result backend), so task records are data that should
 *   follow their range.
 *
 * A sweep of every KV prefix in the tree found no other namespace in the
 * ambiguous position. */
static bool cluster_key_is_node_local(const char* key) {
    static const char* const prefixes[] = {
        "aimem:",             /* AI memory records */
        "aimemv:",            /* their embedding vectors */
        "fabric:",            /* fabric job and ingest records */
        "fednode:",           /* this node's federation identity record */
        "federation/node/",   /* capability records */
        "snapshot/manifest:", /* snapshot manifests */
        "rejoin/state:",      /* rejoin progress */
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(key, prefixes[i], n) == 0) return true;
    }
    return false;
}

static bool cluster_range_probe_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    cluster_range_probe_t* p = (cluster_range_probe_t*)user_data;
    /* Node-local bookkeeping is not shardable data and must not make a range
     * look locally owned. */
    if (cluster_key_is_node_local(key)) return true;
    p->seen++;
    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    if (slot >= p->first && slot <= p->last) {
        p->found = true;
        return false; /* first hit is enough */
    }
    if (p->limit && p->seen >= p->limit) return false;
    return true;
}

bool qihse_cluster_range_has_local_keys(qihse_resp_server_t* server, uint16_t first, uint16_t last,
                                        size_t limit) {
    if (!server || !server->store) return false;
    qihse_user_t* user = qihse_auth_get_user(0);
    if (!user) return false;
    cluster_range_probe_t probe = { first, last, 0, limit, false };
    pthread_rwlock_wrlock(&server->kv_lock);
    qihse_kv_foreach_user(server->store, user, cluster_range_probe_cb, &probe);
    pthread_rwlock_unlock(&server->kv_lock);
    return probe.found;
}

int qihse_cluster_handoff_range(qihse_resp_server_t* server, uint16_t first, uint16_t last,
                                uint16_t target_index, uint64_t* out_moved, uint64_t* out_collected,
                                char* err, size_t err_cap) {
    if (out_moved) *out_moved = 0;
    if (out_collected) *out_collected = 0;
    if (err && err_cap) err[0] = '\0';
    if (!server || !server->store) {
        if (err && err_cap) snprintf(err, err_cap, "key-value store is not configured");
        return -1;
    }
    qihse_cluster_node_t target;
    if (!qihse_cluster_topology_get_node(server->topology, target_index, &target)) {
        if (err && err_cap) snprintf(err, err_cap, "unknown target node");
        return -1;
    }
    if (target_index == qihse_cluster_topology_local_node(server->topology)) {
        if (err && err_cap) snprintf(err, err_cap, "target is the local node");
        return -1;
    }
    qihse_user_t* user = qihse_auth_get_user(0);
    if (!user) {
        if (err && err_cap) snprintf(err, err_cap, "system principal unavailable");
        return -1;
    }

    /* Collect local keys whose slot falls in the range. */
    moveslots_collector_t collector = { NULL, 0, 0, 0, first, last };
    pthread_rwlock_wrlock(&server->kv_lock);
    qihse_kv_foreach_user(server->store, user, moveslots_collect_cb, &collector);
    pthread_rwlock_unlock(&server->kv_lock);
    if (out_collected) *out_collected = collector.count;

    /* Flip ownership FIRST (locally + bus broadcast): the target must accept
     * SETs for the range during the transfer, and its clients route there.
     * The source keeps reading its store directly (no routing), so in-flight
     * keys stream over after the flip. Redis-style ASK-state windows are
     * future work; a brief not-found window exists for not-yet-moved keys. */
    if (!qihse_cluster_set_range_owner(server, first, last, target_index)) {
        free(collector.keys);
        if (err && err_cap) snprintf(err, err_cap, "ownership flip failed");
        return -1;
    }
    if (collector.count == 0) {
        free(collector.keys);
        return 0; /* nothing to move: the range still takes load on the target */
    }

    /* Connect + authenticate to the target. */
    int target_fd = qihse_resp_connect_timeout(target.host, target.port, 5000);
    if (target_fd < 0) {
        free(collector.keys);
        if (err && err_cap) snprintf(err, err_cap, "cannot connect to target node");
        return -1;
    }
    char remote_error[512] = {0};
    const char* password = server->cluster_migrate_password;
    if (password && *password) {
        static const uint8_t auth_cmd[] = "AUTH";
        static const uint8_t op_user[] = "GODMODE_OP";
        qihse_resp_arg_t auth_args[3] = {
            { auth_cmd, sizeof(auth_cmd) - 1u },
            { (const uint8_t*)op_user, sizeof(op_user) - 1u },
            { (const uint8_t*)password, strlen(password) }
        };
        if (!qihse_resp_fd_command(target_fd, 3u, auth_args, remote_error, sizeof(remote_error))) {
            close_socket(target_fd);
            free(collector.keys);
            if (err && err_cap) snprintf(err, err_cap, "target authentication failed");
            return -1;
        }
    }

    static const uint8_t asking_cmd[] = "ASKING";
    static const uint8_t set_cmd[] = "SET";
    static const uint8_t px_opt[] = "PX";
    uint64_t moved = 0;
    pthread_rwlock_wrlock(&server->kv_lock);
    for (size_t i = 0; i < collector.count; i++) {
        char* key = collector.keys[i];
        char* value = qihse_kv_get_user(server->store, key, user);
        if (!value) continue; /* vanished mid-migration */
        int64_t ttl = qihse_kv_ttl_ms_user(server->store, key, user);
        qihse_resp_arg_t asking = { asking_cmd, sizeof(asking_cmd) - 1u };
        bool sent = qihse_resp_fd_command(target_fd, 1u, &asking, remote_error, sizeof(remote_error));
        qihse_resp_arg_t set_args[5];
        size_t set_argc = 0;
        set_args[set_argc++] = (qihse_resp_arg_t){ set_cmd, sizeof(set_cmd) - 1u };
        set_args[set_argc++] = (qihse_resp_arg_t){ (const uint8_t*)key, strlen(key) };
        set_args[set_argc++] = (qihse_resp_arg_t){ (const uint8_t*)value, strlen(value) };
        char ttl_buf[32];
        if (sent && ttl > 0) {
            int n = snprintf(ttl_buf, sizeof(ttl_buf), "%lld", (long long)ttl);
            set_args[set_argc++] = (qihse_resp_arg_t){ px_opt, sizeof(px_opt) - 1u };
            set_args[set_argc++] = (qihse_resp_arg_t){ (const uint8_t*)ttl_buf, (size_t)n };
        }
        if (sent) sent = qihse_resp_fd_command(target_fd, set_argc, set_args, remote_error, sizeof(remote_error));
        if (sent) {
            /* Transferred: drop the local copy (MIGRATE semantics, no COPY). */
            qihse_kv_del_user(server->store, key, user);
            moved++;
        } else {
            fprintf(stderr, "qihse-cluster: slot handoff key transfer failed: %s\n", remote_error);
        }
        free(value);
        if (!sent) break;
    }
    pthread_rwlock_unlock(&server->kv_lock);
    close_socket(target_fd);
    if (out_moved) *out_moved = moved;
    size_t collected = collector.count;
    free(collector.keys);
    if (moved < collected) {
        if (err && err_cap)
            snprintf(err, err_cap, "transfer incomplete (%llu of %zu keys)",
                     (unsigned long long)moved, collected);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * CLUSTER MOVESLOTS <first>-<last> <host>:<port>  (system domain only)
 * Parses the request and delegates to qihse_cluster_handoff_range(), the same
 * path the cluster brain's R1 re-home uses.
 * ------------------------------------------------------------------------- */
static bool qihse_resp_handle_moveslots(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (!session->server->store) return qihse_resp_error(session, "ERR key-value store is not configured");
    if (qihse_user_get_tenant_id(session->user) != QIHSE_TENANT_SYSTEM) {
        return qihse_resp_error(session, "NOPERM MOVESLOTS is restricted to the system domain");
    }
    if (request->argc != 4) return qihse_resp_error(session, "ERR usage: CLUSTER MOVESLOTS <first>-<last> <host>:<port>");

    /* Range: "first-last" or single "slot". */
    char range[64];
    size_t rl = request->argv[2].len;
    if (rl == 0 || rl >= sizeof(range)) return qihse_resp_error(session, "ERR invalid slot range");
    memcpy(range, request->argv[2].data, rl);
    range[rl] = '\0';
    uint32_t first, last;
    char* dash = strchr(range, '-');
    if (dash) {
        *dash = '\0';
        first = (uint32_t)strtoul(range, NULL, 10);
        last = (uint32_t)strtoul(dash + 1, NULL, 10);
    } else {
        first = last = (uint32_t)strtoul(range, NULL, 10);
    }
    if (first > last || last >= QIHSE_CLUSTER_SLOT_COUNT) {
        return qihse_resp_error(session, "ERR invalid slot range");
    }

    /* Target: resolve by host:port among known topology nodes. */
    char target_spec[QIHSE_CLUSTER_HOST_LEN + 16u];
    size_t tl = request->argv[3].len;
    if (tl == 0 || tl >= sizeof(target_spec)) return qihse_resp_error(session, "ERR invalid target");
    memcpy(target_spec, request->argv[3].data, tl);
    target_spec[tl] = '\0';
    char* colon = strrchr(target_spec, ':');
    if (!colon) return qihse_resp_error(session, "ERR target must be host:port");
    *colon = '\0';
    uint16_t target_port = (uint16_t)strtoul(colon + 1, NULL, 10);

    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t node_count = qihse_cluster_topology_nodes(session->server->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint16_t target_index = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < node_count; i++) {
        if (strcmp(nodes[i].host, target_spec) == 0 && nodes[i].port == target_port) {
            target_index = nodes[i].index;
            break;
        }
    }
    if (target_index == QIHSE_CLUSTER_NODE_NONE) {
        return qihse_resp_error(session, "ERR target node is not part of this cluster");
    }
    if (target_index == qihse_cluster_topology_local_node(session->server->topology)) {
        return qihse_resp_error(session, "ERR target is the local node");
    }

    uint64_t moved = 0, collected = 0;
    char err[160];
    if (qihse_cluster_handoff_range(session->server, (uint16_t)first, (uint16_t)last, target_index,
                                    &moved, &collected, err, sizeof(err)) != 0) {
        char reply[256];
        snprintf(reply, sizeof(reply), "ERR %s", err[0] ? err : "slot handoff failed");
        return qihse_resp_error(session, reply);
    }
    if (collected == 0) {
        /* Nothing to move: ownership still flipped so the range takes load. */
        return qihse_resp_integer(session, 0);
    }
    char summary[128];
    snprintf(summary, sizeof(summary), "%llu keys moved; slots %u-%u now owned by %.64s:%u",
             (unsigned long long)moved, first, last, target_spec, target_port);
    return qihse_resp_bulk_text(session, summary);
}

/* ---------------------------------------------------------------------------
 * GROUP.* — group update push
 * GROUP.DEFINE <name> <addr|node-id>...   (system domain)
 * GROUP.LIST                              (system domain)
 * GROUP.PUSH <name> <payload>             (system domain)
 * GROUP.STATUS <name>                     (system domain)
 *
 * A group is a named set of cluster nodes stored in KV (`grp:<name>` ->
 * comma-separated node ids). PUSH assigns a monotonic, sortable update id
 * (hybrid logical clock), broadcasts it on the cluster bus, and applies it
 * locally; members apply the update to their own KV (`grpupd:<name>:<id>`)
 * and answer with an ack frame, so the pusher can report per-member status.
 * Membership is enforced by the consumer: a node that is not a member ignores
 * the frame. Payloads are text (NUL-terminated), max
 * QIHSE_CLUSTER_BUS_GROUP_UPDATE_MAX bytes.
 * ------------------------------------------------------------------------- */

static uint16_t qihse_resp_group_apply(qihse_resp_server_t* server, uint64_t update_id,
                                       const char* group, const uint8_t* payload,
                                       size_t payload_len);

static void qihse_resp_group_ack_record(qihse_resp_server_t* server, uint64_t update_id,
                                        uint16_t node_index, uint16_t status) {
    pthread_mutex_lock(&server->group_lock);
    group_ack_set_t* slot = NULL;
    for (size_t i = 0; i < GROUP_ACK_SLOTS && !slot; i++) {
        if (server->group_acks[i].used && server->group_acks[i].update_id == update_id) {
            slot = &server->group_acks[i];
        }
    }
    if (!slot) {
        for (size_t i = 0; i < GROUP_ACK_SLOTS && !slot; i++) {
            if (!server->group_acks[i].used) slot = &server->group_acks[i];
        }
    }
    if (!slot) {
        /* Evict the oldest slot (smallest update id: ids are monotonic). */
        slot = &server->group_acks[0];
        for (size_t i = 1; i < GROUP_ACK_SLOTS; i++) {
            if (server->group_acks[i].update_id < slot->update_id) slot = &server->group_acks[i];
        }
    }
    if (!slot->used || slot->update_id != update_id) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->update_id = update_id;
    }
    if (node_index < QIHSE_CLUSTER_MAX_NODES) {
        slot->seen[node_index] = true;
        slot->status[node_index] = status;
    }
    pthread_mutex_unlock(&server->group_lock);
}

static bool qihse_resp_group_ack_lookup(qihse_resp_server_t* server, uint64_t update_id,
                                        uint16_t node_index, uint16_t* out_status) {
    bool seen = false;
    pthread_mutex_lock(&server->group_lock);
    for (size_t i = 0; i < GROUP_ACK_SLOTS; i++) {
        if (server->group_acks[i].used && server->group_acks[i].update_id == update_id &&
            node_index < QIHSE_CLUSTER_MAX_NODES && server->group_acks[i].seen[node_index]) {
            if (out_status) *out_status = server->group_acks[i].status[node_index];
            seen = true;
            break;
        }
    }
    pthread_mutex_unlock(&server->group_lock);
    return seen;
}

/* Bus thread: an update arrived. Apply it if this node is a member. */
static void qihse_resp_on_group_update(qihse_cluster_bus_t* bus, uint64_t update_id,
                                       const char* group, const uint8_t* payload,
                                       size_t payload_len, uint16_t sender_index,
                                       void* user_data) {
    (void)bus;
    (void)sender_index;
    qihse_resp_server_t* server = (qihse_resp_server_t*)user_data;
    if (!server || !group || !payload) return;
    uint16_t status = qihse_resp_group_apply(server, update_id, group, payload, payload_len);
    qihse_cluster_bus_broadcast_group_ack(server->bus, update_id, status);
}

/* Bus thread: a member reported the outcome of an update we pushed. */
static void qihse_resp_on_group_ack(qihse_cluster_bus_t* bus, uint64_t update_id,
                                    uint16_t sender_index, uint16_t status, void* user_data) {
    (void)bus;
    qihse_resp_server_t* server = (qihse_resp_server_t*)user_data;
    if (!server) return;
    qihse_resp_group_ack_record(server, update_id, sender_index, status);
}

static void qihse_resp_group_wire_bus(qihse_resp_server_t* server, qihse_cluster_bus_t* bus) {
    if (!bus) return;
    qihse_cluster_bus_set_group_callbacks(bus, qihse_resp_on_group_update, server,
                                          qihse_resp_on_group_ack, server);
}

/* Membership helpers. The local node id is what the registry stores, so a
 * pushed update can be applied by any node without extra identity plumbing. */
static size_t qihse_resp_group_members(qihse_resp_server_t* server, const char* name, char* out,
                                       size_t out_cap) {
    if (!server->store || !name || !*name) return 0;
    char key[128];
    snprintf(key, sizeof(key), GROUP_MEMBERSHIP_PREFIX "%s", name);
    char* value = qihse_kv_get_user(server->store, key, qihse_auth_get_user(0));
    if (!value) return 0;
    size_t len = strlen(value);
    if (len >= out_cap) len = out_cap - 1u;
    memcpy(out, value, len);
    out[len] = '\0';
    free(value);
    return len;
}

static bool qihse_resp_group_is_member(qihse_resp_server_t* server, const char* name) {
    char members[1024];
    if (qihse_resp_group_members(server, name, members, sizeof(members)) == 0) return false;
    qihse_cluster_node_t local;
    if (!qihse_cluster_topology_get_node(server->topology,
                                         qihse_cluster_topology_local_node(server->topology),
                                         &local)) {
        return false;
    }
    const char* p = members;
    while (*p) {
        const char* comma = strchr(p, ',');
        size_t len = comma ? (size_t)(comma - p) : strlen(p);
        if (len == QIHSE_CLUSTER_NODE_ID_LEN && strncmp(p, local.id, len) == 0) return true;
        if (!comma) break;
        p = comma + 1;
    }
    return false;
}

/* Apply a pushed update on this node. Returns the ack status:
 * 0 = applied, 1 = not a member (ignored), 2 = rejected (size/store). */
static uint16_t qihse_resp_group_apply(qihse_resp_server_t* server, uint64_t update_id,
                                       const char* group, const uint8_t* payload,
                                       size_t payload_len) {
    if (!server || !server->store || !group || !*group) return 2;
    if (payload_len == 0 || payload_len > QIHSE_CLUSTER_BUS_GROUP_UPDATE_MAX) return 2;
    if (!qihse_resp_group_is_member(server, group)) return 1;
    char key[192];
    snprintf(key, sizeof(key), GROUP_UPDATE_PREFIX "%s:%016llx", group,
             (unsigned long long)update_id);
    char* value = malloc(payload_len + 1u);
    if (!value) return 2;
    memcpy(value, payload, payload_len);
    value[payload_len] = '\0';
    bool ok = qihse_kv_set_user(server->store, key, value, 0, 0, qihse_auth_get_user(0));
    free(value);
    return ok ? 0u : 2u;
}

typedef struct {
    char names[64][QIHSE_CLUSTER_BUS_GROUP_NAME_MAX + 1u];
    size_t count;
} group_list_t;

static bool qihse_resp_group_list_cb(const char* key, const char* value, void* user_data) {
    (void)value;
    group_list_t* list = (group_list_t*)user_data;
    /* Membership keys are `grp:<name>`; applied-update keys are `grpupd:...`
     * (which does not share the `grp:` prefix) so this stays unambiguous. */
    if (strncmp(key, GROUP_MEMBERSHIP_PREFIX, sizeof(GROUP_MEMBERSHIP_PREFIX) - 1u) != 0) return true;
    if (list->count >= 64u) return false;
    const char* name = key + sizeof(GROUP_MEMBERSHIP_PREFIX) - 1u;
    if (strlen(name) > QIHSE_CLUSTER_BUS_GROUP_NAME_MAX) return true;
    snprintf(list->names[list->count], sizeof(list->names[0]), "%s", name);
    list->count++;
    return true;
}

static bool qihse_resp_handle_group(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    if (request->argc < 2) {
        return qihse_resp_error(session, "ERR usage: GROUP.DEFINE|LIST|PUSH|STATUS ...");
    }
    if (qihse_user_get_tenant_id(session->user) != QIHSE_TENANT_SYSTEM) {
        return qihse_resp_error(session, "NOPERM GROUP.* is restricted to the system domain");
    }
    const qihse_resp_arg_t* sub = &request->argv[1];

    if (qihse_resp_arg_equal(sub, "LIST")) {
        if (!session->server->store) return qihse_resp_error(session, "ERR no store");
        group_list_t list;
        memset(&list, 0, sizeof(list));
        qihse_kv_foreach_user(session->server->store, qihse_auth_get_user(0),
                              qihse_resp_group_list_cb, &list);
        if (!qihse_resp_array(session, list.count * 2u)) return false;
        for (size_t i = 0; i < list.count; i++) {
            if (!qihse_resp_bulk_text(session, list.names[i])) return false;
            char members[1024];
            size_t len = qihse_resp_group_members(session->server, list.names[i], members,
                                                  sizeof(members));
            size_t member_count = len ? 1u : 0u;
            for (size_t k = 0; k < len; k++)
                if (members[k] == ',') member_count++;
            char count_buf[32];
            snprintf(count_buf, sizeof(count_buf), "%zu", member_count);
            if (!qihse_resp_bulk_text(session, count_buf)) return false;
        }
        return true;
    }

    if (request->argc < 3) return qihse_resp_error(session, "ERR missing group name");
    char name[QIHSE_CLUSTER_BUS_GROUP_NAME_MAX + 1u];
    size_t nl = request->argv[2].len;
    if (nl == 0 || nl > QIHSE_CLUSTER_BUS_GROUP_NAME_MAX) return qihse_resp_error(session, "ERR invalid group name");
    memcpy(name, request->argv[2].data, nl);
    name[nl] = '\0';

    if (qihse_resp_arg_equal(sub, "DEFINE")) {
        if (request->argc < 4) return qihse_resp_error(session, "ERR usage: GROUP.DEFINE <name> <host:port|node-id>...");
        if (!session->server->store) return qihse_resp_error(session, "ERR no store");
        char members[1024];
        size_t off = 0;
        for (size_t i = 3; i < request->argc; i++) {
            char spec[QIHSE_CLUSTER_HOST_LEN + 16u];
            size_t sl = request->argv[i].len;
            if (sl == 0 || sl >= sizeof(spec)) return qihse_resp_error(session, "ERR invalid member");
            memcpy(spec, request->argv[i].data, sl);
            spec[sl] = '\0';
            qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
            size_t count = qihse_cluster_topology_nodes(session->server->topology, nodes,
                                                        QIHSE_CLUSTER_MAX_NODES);
            const char* found_id = NULL;
            for (size_t k = 0; k < count; k++) {
                if (strcmp(nodes[k].id, spec) == 0) { found_id = nodes[k].id; break; }
                char addr[QIHSE_CLUSTER_HOST_LEN + 8u];
                snprintf(addr, sizeof(addr), "%s:%u", nodes[k].host, nodes[k].port);
                if (strcmp(addr, spec) == 0) { found_id = nodes[k].id; break; }
            }
            if (!found_id) {
                char msg[160];
                snprintf(msg, sizeof(msg), "ERR member '%.100s' is not a known cluster node", spec);
                return qihse_resp_error(session, msg);
            }
            int n = snprintf(members + off, sizeof(members) - off, "%s%s",
                             off ? "," : "", found_id);
            if (n <= 0 || (size_t)n >= sizeof(members) - off) return qihse_resp_error(session, "ERR too many members");
            off += (size_t)n;
        }
        char key[128];
        snprintf(key, sizeof(key), GROUP_MEMBERSHIP_PREFIX "%s", name);
        if (!qihse_kv_set_user(session->server->store, key, members, 0, 0, qihse_auth_get_user(0))) {
            return qihse_resp_error(session, "ERR cannot store group");
        }
        return qihse_resp_integer(session, (long long)request->argc - 3);
    }

    if (qihse_resp_arg_equal(sub, "PUSH")) {
        if (request->argc != 4) return qihse_resp_error(session, "ERR usage: GROUP.PUSH <name> <payload>");
        char members[1024];
        if (qihse_resp_group_members(session->server, name, members, sizeof(members)) == 0) {
            return qihse_resp_error(session, "ERR unknown group");
        }
        if (request->argv[3].len == 0 ||
            request->argv[3].len > QIHSE_CLUSTER_BUS_GROUP_UPDATE_MAX) {
            return qihse_resp_error(session, "ERR payload too large");
        }
        qihse_hlc_t ts;
        qihse_hlc_tick(&session->server->group_clock, &ts);
        uint64_t update_id = qihse_hlc_pack(&ts);
        session->server->group_last_update = update_id;
        const uint8_t* payload = request->argv[3].data;
        size_t payload_len = request->argv[3].len;
        bool broadcast = false;
        if (session->server->bus) {
            broadcast = qihse_cluster_bus_broadcast_group_update(session->server->bus, update_id,
                                                                 name, payload, payload_len);
        }
        /* Apply locally (the pusher may or may not be a member) and record the
         * local outcome so GROUP.STATUS is complete without waiting for a
         * frame to come back. */
        uint16_t local_status = qihse_resp_group_apply(session->server, update_id, name,
                                                       payload, payload_len);
        qihse_resp_group_ack_record(session->server, update_id,
                                    qihse_cluster_topology_local_node(session->server->topology),
                                    local_status);
        char reply[128];
        snprintf(reply, sizeof(reply), "%llu %s local=%u",
                 (unsigned long long)update_id, broadcast ? "broadcast" : "local-only",
                 (unsigned)local_status);
        return qihse_resp_bulk_text(session, reply);
    }

    if (qihse_resp_arg_equal(sub, "STATUS")) {
        char members[1024];
        size_t len = qihse_resp_group_members(session->server, name, members, sizeof(members));
        if (len == 0) return qihse_resp_error(session, "ERR unknown group");
        /* Report every member with the latest ack we hold for it. */
        size_t member_count = 1;
        for (size_t i = 0; i < len; i++)
            if (members[i] == ',') member_count++;
        if (!qihse_resp_array(session, member_count * 2u)) return false;
        const char* p = members;
        for (size_t i = 0; i < member_count; i++) {
            const char* comma = strchr(p, ',');
            size_t id_len = comma ? (size_t)(comma - p) : strlen(p);
            char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
            if (id_len != QIHSE_CLUSTER_NODE_ID_LEN) return false;
            memcpy(id, p, id_len);
            id[id_len] = '\0';
            if (!qihse_resp_bulk_text(session, id)) return false;
            uint16_t node_index = QIHSE_CLUSTER_NODE_NONE;
            uint16_t status = 0;
            qihse_cluster_topology_find_node(session->server->topology, id, &node_index);
            bool seen = node_index != QIHSE_CLUSTER_NODE_NONE &&
                        qihse_resp_group_ack_lookup(session->server, session->server->group_last_update,
                                                    node_index, &status);
            char state[64];
            if (!seen) snprintf(state, sizeof(state), "pending");
            else if (status == 0) snprintf(state, sizeof(state), "applied");
            else if (status == 1) snprintf(state, sizeof(state), "not-member");
            else snprintf(state, sizeof(state), "rejected(%u)", (unsigned)status);
            if (!qihse_resp_bulk_text(session, state)) return false;
            if (!comma) break;
            p = comma + 1;
        }
        return true;
    }

    return qihse_resp_error(session, "ERR unknown GROUP subcommand");
}

/* ---------------------------------------------------------------------------
 * FEDERATION.* — F1 sovereign local state (plan §4, §5).
 * FEDERATION.STATUS                       — status snapshot (system domain)
 * FEDERATION.STATE <connected|degraded|...> — set the node's federation state
 * FEDERATION.NS.REGISTER <name> <class> [authority-node-id] — register a namespace
 * FEDERATION.NS.UNREGISTER <name>          — remove a namespace
 * FEDERATION.NS.LIST                       — list registered namespaces
 * FEDERATION.NS.WRITABLE <name>           — is this namespace writable now?
 * ------------------------------------------------------------------------- */
static bool qihse_fed_ns_count_cb(const qihse_federation_namespace_t* ns, void* ud) {
    (void)ns; (*(size_t*)ud)++; return true;
}

static bool qihse_fed_ns_list_cb(const qihse_federation_namespace_t* ns, void* ud) {
    qihse_resp_session_t* session = (qihse_resp_session_t*)ud;
    if (!qihse_resp_bulk_text(session, ns->name)) return false;
    if (!qihse_resp_bulk_text(session, qihse_consistency_class_name(ns->consistency))) return false;
    char auth_str[QIHSE_UUID_STR_LEN + 1u];
    qihse_uuid_format(&ns->authority_node, auth_str);
    if (!qihse_resp_bulk_text(session, auth_str)) return false;
    if (!qihse_resp_bulk_text(session, ns->local_authority ? "local" : "federation")) return false;
    return true;
}

/* F3: callback for FEDERATION.CONFLICT.LIST — collects unresolved conflict IDs. */
struct qihse_resp_conflict_list_ctx {
    char ids[32][QIHSE_UUID_STR_LEN + 1u];
    char namespaces[32][QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    size_t count;
};

bool qihse_resp_conflict_list_cb(const qihse_federation_conflict_t* c, void* ud) {
    struct qihse_resp_conflict_list_ctx* ctx = (struct qihse_resp_conflict_list_ctx*)ud;
    if (ctx->count >= 32) return false; /* stop at capacity */
    qihse_uuid_format(&c->conflict_id, ctx->ids[ctx->count]);
    snprintf(ctx->namespaces[ctx->count], sizeof(ctx->namespaces[ctx->count]),
             "%s", c->namespace_name);
    ctx->count++;
    return true;
}

/* F4: callback for FEDERATION.GROUP.LIST — collects group ids. */
struct qihse_resp_fedgroup_list_ctx {
    char ids[32][64];
    size_t count;
};

static bool qihse_resp_fedgroup_list_cb(const qihse_federation_group_t* g, void* ud) {
    struct qihse_resp_fedgroup_list_ctx* ctx = (struct qihse_resp_fedgroup_list_ctx*)ud;
    if (ctx->count >= 32) return false;
    snprintf(ctx->ids[ctx->count], sizeof(ctx->ids[ctx->count]), "%s", g->group_id);
    ctx->count++;
    return true;
}

/* F5: callback for FEDERATION.NODE.LIST — collects node ids, trust, kinds. */
struct qihse_resp_node_list_ctx {
    char ids[32][QIHSE_UUID_STR_LEN + 1u];
    char trust[32][16];
    char kinds[32][32];
    size_t count;
};

static bool qihse_resp_node_list_cb(const qihse_federation_node_identity_t* n, void* ud) {
    struct qihse_resp_node_list_ctx* ctx = (struct qihse_resp_node_list_ctx*)ud;
    if (ctx->count >= 32) return false;
    qihse_uuid_format(&n->node_id, ctx->ids[ctx->count]);
    snprintf(ctx->trust[ctx->count], sizeof(ctx->trust[ctx->count]),
             "%s", qihse_trust_state_name(n->trust));
    snprintf(ctx->kinds[ctx->count], sizeof(ctx->kinds[ctx->count]),
             "%s", qihse_service_identity_name(n->identity_kind));
    ctx->count++;
    return true;
}

/* F6: helpers and callbacks for the supply-chain commands. */

/* Parse an "ENTITY|id" reference used by PROV.EDGE. */
static bool qihse_resp_parse_prov_ref(const qihse_resp_arg_t* arg,
                                      qihse_prov_entity_t* entity,
                                      char* out_id, size_t out_cap) {
    if (!arg || !entity || !out_id || arg->len == 0) return false;
    const char* data = (const char*)arg->data;
    const char* bar = NULL;
    for (size_t i = 0; i < arg->len; i++) {
        if (data[i] == '|') { bar = data + i; break; }
    }
    if (!bar) return false;
    size_t el = (size_t)(bar - data);
    size_t il = arg->len - el - 1u;
    if (el == 0 || el >= 64u || il == 0 || il >= out_cap) return false;
    char ent_name[64];
    memcpy(ent_name, data, el); ent_name[el] = '\0';
    if (!qihse_prov_entity_parse(ent_name, entity)) return false;
    memcpy(out_id, bar + 1, il); out_id[il] = '\0';
    return true;
}

struct qihse_resp_prov_ctx {
    char entities[32][32];
    char ids[32][QIHSE_PROV_ID_MAX + 1u];
    char edges[32][32];
    size_t count;
};

static bool qihse_resp_prov_collect_cb(const qihse_prov_hit_t* hit, void* ud) {
    struct qihse_resp_prov_ctx* ctx = (struct qihse_resp_prov_ctx*)ud;
    if (ctx->count >= 32) return false;
    snprintf(ctx->entities[ctx->count], sizeof(ctx->entities[0]),
             "%s", qihse_prov_entity_name(hit->entity));
    snprintf(ctx->ids[ctx->count], sizeof(ctx->ids[0]), "%s", hit->id);
    snprintf(ctx->edges[ctx->count], sizeof(ctx->edges[0]),
             "%s", qihse_prov_edge_name(hit->via_edge));
    ctx->count++;
    return true;
}

struct qihse_resp_build_list_ctx {
    char ids[32][QIHSE_UUID_STR_LEN + 1u];
    char packages[32][128];
    char states[32][32];
    size_t count;
};

static bool qihse_resp_build_list_cb(const qihse_build_job_t* job, void* ud) {
    struct qihse_resp_build_list_ctx* ctx = (struct qihse_resp_build_list_ctx*)ud;
    if (ctx->count >= 32) return false;
    qihse_uuid_format(&job->build_id, ctx->ids[ctx->count]);
    snprintf(ctx->packages[ctx->count], sizeof(ctx->packages[0]), "%s", job->package);
    snprintf(ctx->states[ctx->count], sizeof(ctx->states[0]),
             "%s", qihse_build_state_name(job->state));
    ctx->count++;
    return true;
}

struct qihse_resp_snapshot_list_ctx {
    char ids[32][QIHSE_UUID_STR_LEN + 1u];
    char releases[32][64];
    char digests[32][QIHSE_PROV_DIGEST_MAX * 2u + 1u];
    size_t count;
};

static bool qihse_resp_snapshot_list_cb(const qihse_repo_snapshot_t* snap, void* ud) {
    struct qihse_resp_snapshot_list_ctx* ctx = (struct qihse_resp_snapshot_list_ctx*)ud;
    if (ctx->count >= 32) return false;
    qihse_uuid_format(&snap->snapshot_id, ctx->ids[ctx->count]);
    snprintf(ctx->releases[ctx->count], sizeof(ctx->releases[0]), "%s", snap->release);
    snprintf(ctx->digests[ctx->count], sizeof(ctx->digests[0]), "%s", snap->snapshot_digest);
    ctx->count++;
    return true;
}

/* F2: journal replay callbacks for FEDERATION.EVENT.REPLAY. */
static bool qihse_fed_replay_count_cb(const qihse_federation_event_t* event,
                                     const uint8_t* payload, size_t payload_len,
                                     void* user_data) {
    (void)event; (void)payload; (void)payload_len;
    (*(size_t*)user_data)++;
    return true;
}

static bool qihse_fed_replay_emit_cb(const qihse_federation_event_t* event,
                                    const uint8_t* payload, size_t payload_len,
                                    void* user_data) {
    qihse_resp_session_t* session = (qihse_resp_session_t*)user_data;
    if (!qihse_resp_integer(session, (int64_t)event->journal_offset)) return false;
    if (!qihse_resp_bulk_text(session, event->event_type)) return false;
    if (!qihse_resp_bulk_text(session, event->resource_id)) return false;
    (void)payload; (void)payload_len;
    return true;
}

static bool qihse_resp_handle_federation(qihse_resp_session_t* session,
                                        const qihse_resp_request_t* request) {
    if (request->argc < 2) return qihse_resp_error(session, "ERR usage: FEDERATION.STATUS|STATE|NS.REGISTER|NS.UNREGISTER|NS.LIST|NS.WRITABLE ...");
    if (qihse_user_get_tenant_id(session->user) != QIHSE_TENANT_SYSTEM) {
        return qihse_resp_error(session, "NOPERM FEDERATION.* is restricted to the system domain");
    }
    /* W2.5, defense in depth: the federation control plane is operator work,
     * never the index identity's. A provisioned index identity is refused
     * before any subcommand runs, so even a future change to the tenant gate
     * above cannot hand it the control plane. */
    if (qihse_keystone_feed_identity_is_indexer(session->user)) {
        return qihse_resp_error(session,
            "NOPERM FEDERATION.* is not available to the KEYSTONE index identity; use KEYSTONE.FEED.*");
    }
    const qihse_resp_arg_t* sub = &request->argv[1];

    if (qihse_resp_arg_equal(sub, "STATUS")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.status");
        pthread_mutex_lock(&session->server->federation_lock);
        qihse_federation_status_recompute(&session->server->federation_status);
        char buf[512];
        qihse_federation_status_format(&session->server->federation_status, buf, sizeof(buf));
        pthread_mutex_unlock(&session->server->federation_lock);
        return qihse_resp_bulk_text(session, buf);
    }

    if (qihse_resp_arg_equal(sub, "STATE")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.state");
        char name[32];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(name)) return qihse_resp_error(session, "ERR invalid state name");
        memcpy(name, request->argv[2].data, nl); name[nl] = '\0';
        qihse_federation_state_t s;
        if (!qihse_federation_state_parse(name, &s)) return qihse_resp_error(session, "ERR unknown federation state");
        pthread_mutex_lock(&session->server->federation_lock);
        session->server->federation_status.federation_state = s;
        qihse_federation_status_recompute(&session->server->federation_status);
        pthread_mutex_unlock(&session->server->federation_lock);
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "NS.REGISTER")) {
        if (request->argc < 4 || request->argc > 5) return qihse_resp_error(session, "ERR usage: FEDERATION.NS.REGISTER <name> <class> [authority-node-id]");
        char name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(name, request->argv[2].data, nl); name[nl] = '\0';
        char class_name[32];
        size_t cl = request->argv[3].len;
        if (cl == 0 || cl >= sizeof(class_name)) return qihse_resp_error(session, "ERR invalid consistency class");
        memcpy(class_name, request->argv[3].data, cl); class_name[cl] = '\0';
        qihse_consistency_class_t cc;
        if (!qihse_consistency_class_parse(class_name, &cc)) return qihse_resp_error(session, "ERR unknown consistency class");
        qihse_uuid_t authority;
        if (request->argc == 5) {
            char auth_str[QIHSE_UUID_STR_LEN + 1u];
            size_t al = request->argv[4].len;
            if (al != QIHSE_UUID_STR_LEN) return qihse_resp_error(session, "ERR authority node id must be a 36-char UUID");
            memcpy(auth_str, request->argv[4].data, al); auth_str[al] = '\0';
            if (!qihse_uuid_parse(auth_str, &authority)) return qihse_resp_error(session, "ERR invalid authority node UUID");
        } else {
            authority = session->server->federation_node_id;
        }
        if (!qihse_federation_namespace_register(session->server->store, qihse_auth_get_user(0),
                                                  name, cc, &authority,
                                                  &session->server->federation_node_id)) {
            return qihse_resp_error(session, "ERR cannot register namespace");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "NS.UNREGISTER")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.ns.unregister");
        char name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(name, request->argv[2].data, nl); name[nl] = '\0';
        if (!qihse_federation_namespace_unregister(session->server->store, qihse_auth_get_user(0), name)) {
            return qihse_resp_error(session, "ERR namespace not found");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "NS.LIST")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.ns.list");
        if (!session->server->store) return qihse_resp_error(session, "ERR no store");
        /* Count first, then emit. */
        size_t count = 0;
        qihse_federation_namespace_foreach(session->server->store, qihse_auth_get_user(0),
                                           qihse_fed_ns_count_cb, &count);
        if (!qihse_resp_array(session, count * 4u)) return false;
        qihse_federation_namespace_foreach(session->server->store, qihse_auth_get_user(0),
                                           qihse_fed_ns_list_cb, session);
        return true;
    }

    if (qihse_resp_arg_equal(sub, "NS.WRITABLE")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.ns.writable");
        char name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(name, request->argv[2].data, nl); name[nl] = '\0';
        qihse_federation_namespace_t ns;
        if (!qihse_federation_namespace_lookup(session->server->store, qihse_auth_get_user(0), name, &ns)) {
            return qihse_resp_error(session, "ERR namespace not found");
        }
        pthread_mutex_lock(&session->server->federation_lock);
        qihse_federation_state_t s = session->server->federation_status.federation_state;
        pthread_mutex_unlock(&session->server->federation_lock);
        bool w = qihse_federation_namespace_writable(&ns, s, &session->server->federation_node_id);
        return qihse_resp_integer(session, w ? 1 : 0);
    }

    /* ── F2: Event journal + watches ────────────────────────────────────── */
    if (qihse_resp_arg_equal(sub, "EVENT.APPEND")) {
        if (request->argc < 4 || request->argc > 5) return qihse_resp_error(session, "ERR usage: FEDERATION.EVENT.APPEND <event_type> <resource_id> [payload]");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        char event_type[QIHSE_FEDERATION_EVENT_TYPE_MAX + 1u];
        size_t etl = request->argv[2].len;
        if (etl == 0 || etl > QIHSE_FEDERATION_EVENT_TYPE_MAX) return qihse_resp_error(session, "ERR invalid event type");
        memcpy(event_type, request->argv[2].data, etl); event_type[etl] = '\0';
        char resource_id[64];
        size_t rl = request->argv[3].len;
        if (rl == 0 || rl >= sizeof(resource_id)) return qihse_resp_error(session, "ERR invalid resource id");
        memcpy(resource_id, request->argv[3].data, rl); resource_id[rl] = '\0';
        const uint8_t* payload = NULL;
        size_t payload_len = 0;
        if (request->argc == 5) { payload = request->argv[4].data; payload_len = request->argv[4].len; }
        qihse_federation_mutation_t m;
        memset(&m, 0, sizeof(m));
        m.origin_node = session->server->federation_node_id;
        /* principal_id: derive from the authenticated user id. */
        qihse_uuid_from_seed(&session->user_id, sizeof(session->user_id), &m.principal_id);
        m.consistency = QIHSE_CONSISTENCY_LOCAL;
        qihse_federation_event_t ev;
        uint64_t off = qihse_federation_journal_append(session->server->federation_journal,
                                                      &m, event_type, resource_id,
                                                      payload, payload_len, &ev);
        if (off == 0) return qihse_resp_error(session, "ERR journal append failed");
        return qihse_resp_integer(session, (int64_t)off);
    }

    if (qihse_resp_arg_equal(sub, "EVENT.REPLAY")) {
        if (request->argc != 2 && request->argc != 3) return qihse_resp_error(session, "ERR usage: FEDERATION.EVENT.REPLAY [from_cursor]");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        uint64_t from = 0;
        if (request->argc == 3) {
            char cur_str[32];
            size_t cl = request->argv[2].len;
            if (cl == 0 || cl >= sizeof(cur_str)) return qihse_resp_error(session, "ERR invalid cursor");
            memcpy(cur_str, request->argv[2].data, cl); cur_str[cl] = '\0';
            from = (uint64_t)strtoull(cur_str, NULL, 10);
        }
        /* Two-pass: count then emit. */
        size_t count = 0;
        qihse_federation_journal_replay(session->server->federation_journal, from,
                                        qihse_fed_replay_count_cb, &count);
        if (!qihse_resp_array(session, count * 3u)) return false;
        qihse_federation_journal_replay(session->server->federation_journal, from,
                                        qihse_fed_replay_emit_cb, session);
        return true;
    }

    if (qihse_resp_arg_equal(sub, "EVENT.LENGTH")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.event.length");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        uint64_t len = qihse_federation_journal_length(session->server->federation_journal);
        return qihse_resp_integer(session, (int64_t)len);
    }

    if (qihse_resp_arg_equal(sub, "WATCH.OPEN")) {
        if (request->argc != 2 && request->argc != 3) return qihse_resp_error(session, "ERR usage: FEDERATION.WATCH.OPEN [prefix]");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        qihse_federation_watch_config_t wcfg;
        memset(&wcfg, 0, sizeof(wcfg));
        if (request->argc == 3) {
            size_t pl = request->argv[2].len;
            if (pl >= sizeof(wcfg.prefix)) return qihse_resp_error(session, "ERR prefix too long");
            memcpy(wcfg.prefix, request->argv[2].data, pl); wcfg.prefix[pl] = '\0';
        }
        wcfg.backlog_limit = 1024;
        qihse_federation_watch_t* w = qihse_federation_watch_open(
            session->server->federation_journal, &wcfg);
        if (!w) return qihse_resp_error(session, "ERR watch open failed");
        /* Store the watch on the session. We use a simple slot array. */
        for (size_t i = 0; i < QIHSE_RESP_MAX_WATCHES; i++) {
            if (!session->federation_watches[i]) {
                session->federation_watches[i] = w;
                return qihse_resp_integer(session, (int64_t)i);
            }
        }
        qihse_federation_watch_destroy(w);
        return qihse_resp_error(session, "ERR too many open watches");
    }

    if (qihse_resp_arg_equal(sub, "WATCH.NEXT")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.watch.next");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        char id_str[16];
        size_t il = request->argv[2].len;
        if (il == 0 || il >= sizeof(id_str)) return qihse_resp_error(session, "ERR invalid watch id");
        memcpy(id_str, request->argv[2].data, il); id_str[il] = '\0';
        int wid = atoi(id_str);
        if (wid < 0 || (size_t)wid >= QIHSE_RESP_MAX_WATCHES || !session->federation_watches[wid]) {
            return qihse_resp_error(session, "ERR invalid watch id");
        }
        qihse_federation_event_t ev;
        uint8_t* payload = NULL;
        size_t plen = 0;
        if (!qihse_federation_watch_next(session->federation_watches[wid], &ev, &payload, &plen)) {
            return qihse_resp_integer(session, 0); /* end of journal */
        }
        /* Emit as array: [offset, event_type, resource_id, payload] */
        if (!qihse_resp_array(session, 4)) { if (payload) free(payload); return false; }
        if (!qihse_resp_integer(session, (int64_t)ev.journal_offset)) { if (payload) free(payload); return false; }
        if (!qihse_resp_bulk_text(session, ev.event_type)) { if (payload) free(payload); return false; }
        if (!qihse_resp_bulk_text(session, ev.resource_id)) { if (payload) free(payload); return false; }
        bool ok = qihse_resp_bulk(session, payload, plen);
        if (payload) free(payload);
        return ok;
    }

    if (qihse_resp_arg_equal(sub, "WATCH.ACK")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.watch.ack");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        char id_str[16];
        size_t il = request->argv[2].len;
        if (il == 0 || il >= sizeof(id_str)) return qihse_resp_error(session, "ERR invalid watch id");
        memcpy(id_str, request->argv[2].data, il); id_str[il] = '\0';
        int wid = atoi(id_str);
        if (wid < 0 || (size_t)wid >= QIHSE_RESP_MAX_WATCHES || !session->federation_watches[wid]) {
            return qihse_resp_error(session, "ERR invalid watch id");
        }
        char off_str[32];
        size_t ol = request->argv[3].len;
        if (ol == 0 || ol >= sizeof(off_str)) return qihse_resp_error(session, "ERR invalid offset");
        memcpy(off_str, request->argv[3].data, ol); off_str[ol] = '\0';
        uint64_t off = (uint64_t)strtoull(off_str, NULL, 10);
        if (!qihse_federation_watch_ack(session->federation_watches[wid], off)) {
            return qihse_resp_error(session, "ERR ack failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "WATCH.RESUME")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.watch.resume");
        if (!session->server->federation_journal) return qihse_resp_error(session, "ERR federation journal not configured");
        char id_str[16];
        size_t il = request->argv[2].len;
        if (il == 0 || il >= sizeof(id_str)) return qihse_resp_error(session, "ERR invalid watch id");
        memcpy(id_str, request->argv[2].data, il); id_str[il] = '\0';
        int wid = atoi(id_str);
        if (wid < 0 || (size_t)wid >= QIHSE_RESP_MAX_WATCHES || !session->federation_watches[wid]) {
            return qihse_resp_error(session, "ERR invalid watch id");
        }
        char cur_str[32];
        size_t cl = request->argv[3].len;
        if (cl == 0 || cl >= sizeof(cur_str)) return qihse_resp_error(session, "ERR invalid cursor");
        memcpy(cur_str, request->argv[3].data, cl); cur_str[cl] = '\0';
        uint64_t cur = (uint64_t)strtoull(cur_str, NULL, 10);
        if (!qihse_federation_watch_resume(session->federation_watches[wid], cur)) {
            return qihse_resp_error(session, "ERR resume failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    /* ── F3: Replication correctness ──────────────────────────────────── */
    if (qihse_resp_arg_equal(sub, "MANIFEST")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.manifest");
        char ns[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(ns, request->argv[2].data, nl); ns[nl] = '\0';
        qihse_federation_manifest_t m;
        if (!qihse_federation_manifest_build(session->server->store, session->user, ns, &m)) {
            return qihse_resp_error(session, "ERR manifest build failed");
        }
        /* Return: namespace total_objects max_generation max_hlc entry_count
         *        then for each entry: range_start range_end object_count digest_hex */
        size_t total_fields = 5 + m.entry_count * 4;
        if (!qihse_resp_array(session, total_fields)) return false;
        if (!qihse_resp_bulk_text(session, m.namespace_name)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.total_objects)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.max_generation)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.max_hlc.physical_ms)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.entry_count)) return false;
        for (size_t i = 0; i < m.entry_count; i++) {
            if (!qihse_resp_bulk_text(session, m.entries[i].range_start)) return false;
            if (!qihse_resp_bulk_text(session, m.entries[i].range_end)) return false;
            if (!qihse_resp_integer(session, (int64_t)m.entries[i].object_count)) return false;
            char hex[97];
            for (size_t j = 0; j < 48; j++) snprintf(hex + j * 2, 3, "%02x", m.entries[i].digest[j]);
            hex[96] = '\0';
            if (!qihse_resp_bulk_text(session, hex)) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "CONFLICT.LIST")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.conflict.list");
        struct qihse_resp_conflict_list_ctx ctx;
        ctx.count = 0;
        qihse_federation_conflict_foreach(session->server->store, session->user,
                                          qihse_resp_conflict_list_cb, &ctx);
        if (!qihse_resp_array(session, ctx.count * 2)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.namespaces[i])) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "CONFLICT.RESOLVE")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.conflict.resolve");
        char id_str[QIHSE_UUID_STR_LEN + 1u];
        size_t il = request->argv[2].len;
        if (il == 0 || il >= sizeof(id_str)) return qihse_resp_error(session, "ERR invalid conflict id");
        memcpy(id_str, request->argv[2].data, il); id_str[il] = '\0';
        qihse_uuid_t cid;
        if (!qihse_uuid_parse(id_str, &cid)) return qihse_resp_error(session, "ERR invalid conflict id");
        char resolver_str[QIHSE_UUID_STR_LEN + 1u];
        size_t rl = request->argv[3].len;
        if (rl == 0 || rl >= sizeof(resolver_str)) return qihse_resp_error(session, "ERR invalid resolver id");
        memcpy(resolver_str, request->argv[3].data, rl); resolver_str[rl] = '\0';
        qihse_uuid_t resolver;
        if (!qihse_uuid_parse(resolver_str, &resolver)) return qihse_resp_error(session, "ERR invalid resolver id");
        if (!qihse_federation_conflict_resolve(session->server->store, session->user, &cid, &resolver)) {
            return qihse_resp_error(session, "ERR conflict resolve failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    /* ── F4: Strong namespace ─────────────────────────────────────────── */
    if (qihse_resp_arg_equal(sub, "EPOCH.NEXT")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.epoch.next");
        uint64_t e = qihse_federation_epoch_next(session->server->store, session->user,
                                                 &session->server->federation_node_id);
        if (e == 0) return qihse_resp_error(session, "ERR epoch advance failed");
        return qihse_resp_integer(session, (int64_t)e);
    }

    if (qihse_resp_arg_equal(sub, "EPOCH.CURRENT")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.epoch.current");
        uint64_t e = qihse_federation_epoch_current(session->server->store, session->user,
                                                    &session->server->federation_node_id);
        return qihse_resp_integer(session, (int64_t)e);
    }

    if (qihse_resp_arg_equal(sub, "OBJECT.CAS")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.OBJECT.CAS <namespace> <resource_id> <value> [expected_generation]");
        }
        char ns[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(ns, request->argv[2].data, nl); ns[nl] = '\0';
        char rid[64];
        size_t rl = request->argv[3].len;
        if (rl == 0 || rl >= sizeof(rid)) return qihse_resp_error(session, "ERR invalid resource id");
        memcpy(rid, request->argv[3].data, rl); rid[rl] = '\0';
        char value[512];
        size_t vl = request->argv[4].len;
        if (vl >= sizeof(value)) return qihse_resp_error(session, "ERR value too long");
        memcpy(value, request->argv[4].data, vl); value[vl] = '\0';
        uint64_t expected = 0;
        if (request->argc == 6) {
            char gen_str[32];
            size_t gl = request->argv[5].len;
            if (gl == 0 || gl >= sizeof(gen_str)) return qihse_resp_error(session, "ERR invalid generation");
            memcpy(gen_str, request->argv[5].data, gl); gen_str[gl] = '\0';
            expected = (uint64_t)strtoull(gen_str, NULL, 10);
        }
        qihse_federation_cas_result_t r;
        if (!qihse_federation_object_cas(session->server->store, session->user, ns, rid,
                                        expected, value, &r)) {
            return qihse_resp_error(session, "ERR cas failed");
        }
        return qihse_resp_integer(session, r.swapped ? 1 : 0);
    }

    if (qihse_resp_arg_equal(sub, "OBJECT.GET")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.object.get");
        char ns[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(ns, request->argv[2].data, nl); ns[nl] = '\0';
        char rid[64];
        size_t rl = request->argv[3].len;
        if (rl == 0 || rl >= sizeof(rid)) return qihse_resp_error(session, "ERR invalid resource id");
        memcpy(rid, request->argv[3].data, rl); rid[rl] = '\0';
        uint64_t gen = 0;
        char value[512];
        if (!qihse_federation_object_get(session->server->store, session->user, ns, rid,
                                        &gen, value, sizeof(value))) {
            return qihse_resp_error(session, "ERR object not found");
        }
        if (!qihse_resp_array(session, 2)) return false;
        if (!qihse_resp_integer(session, (int64_t)gen)) return false;
        if (!qihse_resp_bulk_text(session, value)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "GROUP.CREATE")) {
        if (request->argc < 3 || request->argc > 4) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.GROUP.CREATE <group_id> [consistency]");
        }
        qihse_federation_group_t g;
        memset(&g, 0, sizeof(g));
        size_t gl = request->argv[2].len;
        if (gl == 0 || gl >= sizeof(g.group_id)) return qihse_resp_error(session, "ERR invalid group id");
        memcpy(g.group_id, request->argv[2].data, gl); g.group_id[gl] = '\0';
        g.consistency = QIHSE_CONSISTENCY_QUORUM;
        if (request->argc == 4) {
            char cons[32];
            size_t cl = request->argv[3].len;
            if (cl == 0 || cl >= sizeof(cons)) return qihse_resp_error(session, "ERR invalid consistency");
            memcpy(cons, request->argv[3].data, cl); cons[cl] = '\0';
            qihse_consistency_class_t cc;
            if (qihse_consistency_class_parse(cons, &cc)) g.consistency = cc;
        }
        if (!qihse_federation_group_create(session->server->store, session->user, &g)) {
            return qihse_resp_error(session, "ERR group create failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "GROUP.ADVANCE")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.group.advance");
        char gid[64];
        size_t gl = request->argv[2].len;
        if (gl == 0 || gl >= sizeof(gid)) return qihse_resp_error(session, "ERR invalid group id");
        memcpy(gid, request->argv[2].data, gl); gid[gl] = '\0';
        uint64_t term = qihse_federation_group_advance_term(session->server->store, session->user, gid);
        if (term == 0) return qihse_resp_error(session, "ERR group advance failed");
        return qihse_resp_integer(session, (int64_t)term);
    }

    if (qihse_resp_arg_equal(sub, "GROUP.ADD")) {
        if (request->argc < 4 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.GROUP.ADD <group_id> <member_uuid> [voter] [witness]");
        }
        char gid[64];
        size_t gl = request->argv[2].len;
        if (gl == 0 || gl >= sizeof(gid)) return qihse_resp_error(session, "ERR invalid group id");
        memcpy(gid, request->argv[2].data, gl); gid[gl] = '\0';
        char mid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t ml = request->argv[3].len;
        if (ml == 0 || ml >= sizeof(mid_str)) return qihse_resp_error(session, "ERR invalid member id");
        memcpy(mid_str, request->argv[3].data, ml); mid_str[ml] = '\0';
        qihse_federation_group_member_t m;
        memset(&m, 0, sizeof(m));
        if (!qihse_uuid_parse(mid_str, &m.member_id)) return qihse_resp_error(session, "ERR invalid member id");
        m.is_voter = true;
        if (request->argc >= 5) {
            m.is_voter = request->argv[4].len == 1u && request->argv[4].data[0] == '1';
        }
        if (request->argc >= 6) {
            m.is_witness = request->argv[5].len == 1u && request->argv[5].data[0] == '1';
        }
        if (!qihse_federation_group_add_member(session->server->store, session->user, gid, &m)) {
            return qihse_resp_error(session, "ERR group add failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "GROUP.REMOVE")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.group.remove");
        char gid[64];
        size_t gl = request->argv[2].len;
        if (gl == 0 || gl >= sizeof(gid)) return qihse_resp_error(session, "ERR invalid group id");
        memcpy(gid, request->argv[2].data, gl); gid[gl] = '\0';
        char mid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t ml = request->argv[3].len;
        if (ml == 0 || ml >= sizeof(mid_str)) return qihse_resp_error(session, "ERR invalid member id");
        memcpy(mid_str, request->argv[3].data, ml); mid_str[ml] = '\0';
        qihse_uuid_t mid;
        if (!qihse_uuid_parse(mid_str, &mid)) return qihse_resp_error(session, "ERR invalid member id");
        if (!qihse_federation_group_remove_member(session->server->store, session->user, gid, &mid)) {
            return qihse_resp_error(session, "ERR group remove failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "GROUP.SHOW")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.group.show");
        char gid[64];
        size_t gl = request->argv[2].len;
        if (gl == 0 || gl >= sizeof(gid)) return qihse_resp_error(session, "ERR invalid group id");
        memcpy(gid, request->argv[2].data, gl); gid[gl] = '\0';
        qihse_federation_group_t g;
        if (!qihse_federation_group_lookup(session->server->store, session->user, gid, &g)) {
            return qihse_resp_error(session, "ERR group not found");
        }
        if (!qihse_resp_array(session, 4 + g.member_count * 3)) return false;
        if (!qihse_resp_bulk_text(session, g.group_id)) return false;
        if (!qihse_resp_integer(session, (int64_t)g.term)) return false;
        if (!qihse_resp_bulk_text(session, qihse_consistency_class_name(g.consistency))) return false;
        if (!qihse_resp_integer(session, (int64_t)g.member_count)) return false;
        for (size_t i = 0; i < g.member_count; i++) {
            char mid[QIHSE_UUID_STR_LEN + 1u];
            qihse_uuid_format(&g.members[i].member_id, mid);
            if (!qihse_resp_bulk_text(session, mid)) return false;
            if (!qihse_resp_integer(session, g.members[i].is_voter ? 1 : 0)) return false;
            if (!qihse_resp_integer(session, g.members[i].is_witness ? 1 : 0)) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "GROUP.LIST")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.group.list");
        struct qihse_resp_fedgroup_list_ctx ctx;
        ctx.count = 0;
        qihse_federation_group_foreach(session->server->store, session->user,
                                       qihse_resp_fedgroup_list_cb, &ctx);
        if (!qihse_resp_array(session, ctx.count)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "LEASE.ACQUIRE")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.LEASE.ACQUIRE <namespace> <resource_id> <fencing_epoch> [expires_ms]");
        }
        qihse_federation_lease_t req;
        memset(&req, 0, sizeof(req));
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl > QIHSE_FEDERATION_NS_NAME_MAX) return qihse_resp_error(session, "ERR invalid namespace name");
        memcpy(req.namespace_name, request->argv[2].data, nl); req.namespace_name[nl] = '\0';
        size_t rl = request->argv[3].len;
        if (rl == 0 || rl >= sizeof(req.resource_id)) return qihse_resp_error(session, "ERR invalid resource id");
        memcpy(req.resource_id, request->argv[3].data, rl); req.resource_id[rl] = '\0';
        char epoch_str[32];
        size_t el = request->argv[4].len;
        if (el == 0 || el >= sizeof(epoch_str)) return qihse_resp_error(session, "ERR invalid fencing epoch");
        memcpy(epoch_str, request->argv[4].data, el); epoch_str[el] = '\0';
        req.fencing_epoch = (uint64_t)strtoull(epoch_str, NULL, 10);
        if (request->argc == 6) {
            char exp_str[32];
            size_t xl = request->argv[5].len;
            if (xl == 0 || xl >= sizeof(exp_str)) return qihse_resp_error(session, "ERR invalid expiry");
            memcpy(exp_str, request->argv[5].data, xl); exp_str[xl] = '\0';
            req.expires_hlc_physical = (uint64_t)strtoull(exp_str, NULL, 10);
        }
        req.owner_node = session->server->federation_node_id;
        req.issuer = session->server->federation_node_id;
        if (!qihse_uuid_generate(&req.lease_id) || !qihse_uuid_generate(&req.request_id)) {
            return qihse_resp_error(session, "ERR could not generate lease identity");
        }
        req.issued_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        qihse_federation_lease_t out;
        if (!qihse_federation_lease_acquire(session->server->store, session->user, &req, &out)) {
            return qihse_resp_error(session, "ERR lease acquire failed");
        }
        char lid[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&out.lease_id, lid);
        return qihse_resp_bulk_text(session, lid);
    }

    if (qihse_resp_arg_equal(sub, "LEASE.READ")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.lease.read");
        char lid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t ll = request->argv[2].len;
        if (ll == 0 || ll >= sizeof(lid_str)) return qihse_resp_error(session, "ERR invalid lease id");
        memcpy(lid_str, request->argv[2].data, ll); lid_str[ll] = '\0';
        qihse_uuid_t lid;
        if (!qihse_uuid_parse(lid_str, &lid)) return qihse_resp_error(session, "ERR invalid lease id");
        qihse_federation_lease_t l;
        if (!qihse_federation_lease_read(session->server->store, session->user, &lid, &l)) {
            return qihse_resp_error(session, "ERR lease not found");
        }
        if (!qihse_resp_array(session, 5)) return false;
        if (!qihse_resp_bulk_text(session, l.resource_id)) return false;
        if (!qihse_resp_bulk_text(session, qihse_lease_state_name(l.state))) return false;
        if (!qihse_resp_integer(session, (int64_t)l.fencing_epoch)) return false;
        if (!qihse_resp_integer(session, (int64_t)l.generation)) return false;
        if (!qihse_resp_integer(session, (int64_t)l.expires_hlc_physical)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "LEASE.RENEW")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.lease.renew");
        char lid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t ll = request->argv[2].len;
        if (ll == 0 || ll >= sizeof(lid_str)) return qihse_resp_error(session, "ERR invalid lease id");
        memcpy(lid_str, request->argv[2].data, ll); lid_str[ll] = '\0';
        qihse_uuid_t lid;
        if (!qihse_uuid_parse(lid_str, &lid)) return qihse_resp_error(session, "ERR invalid lease id");
        char exp_str[32];
        size_t xl = request->argv[3].len;
        if (xl == 0 || xl >= sizeof(exp_str)) return qihse_resp_error(session, "ERR invalid expiry");
        memcpy(exp_str, request->argv[3].data, xl); exp_str[xl] = '\0';
        uint64_t expires = (uint64_t)strtoull(exp_str, NULL, 10);
        qihse_federation_lease_t out;
        if (!qihse_federation_lease_renew(session->server->store, session->user, &lid, expires, &out)) {
            return qihse_resp_error(session, "ERR lease renew failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "LEASE.RELEASE")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.lease.release");
        char lid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t ll = request->argv[2].len;
        if (ll == 0 || ll >= sizeof(lid_str)) return qihse_resp_error(session, "ERR invalid lease id");
        memcpy(lid_str, request->argv[2].data, ll); lid_str[ll] = '\0';
        qihse_uuid_t lid;
        if (!qihse_uuid_parse(lid_str, &lid)) return qihse_resp_error(session, "ERR invalid lease id");
        if (!qihse_federation_lease_release(session->server->store, session->user, &lid)) {
            return qihse_resp_error(session, "ERR lease release failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    /* ── F5: Trust plane ─────────────────────────────────────────────── */
    if (qihse_resp_arg_equal(sub, "SCOPE.LIST")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.scope.list");
        static const qihse_infra_scope_t scopes[] = {
            QIHSE_SCOPE_FEDERATION_READ, QIHSE_SCOPE_FEDERATION_WRITE,
            QIHSE_SCOPE_NODE_ENROLL, QIHSE_SCOPE_NODE_REVOKE,
            QIHSE_SCOPE_POLICY_READ, QIHSE_SCOPE_POLICY_WRITE,
            QIHSE_SCOPE_LEASE_READ, QIHSE_SCOPE_LEASE_WRITE,
            QIHSE_SCOPE_SECURITY_ADMIN, QIHSE_SCOPE_AUDIT_READ,
            QIHSE_SCOPE_TELEMETRY_WRITE,
        };
        size_t n = sizeof(scopes) / sizeof(scopes[0]);
        if (!qihse_resp_array(session, n)) return false;
        for (size_t i = 0; i < n; i++) {
            if (!qihse_resp_bulk_text(session, qihse_infra_scope_name(scopes[i]))) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SCOPE.CHECK")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.scope.check");
        char scope_name[64];
        size_t sl = request->argv[2].len;
        if (sl == 0 || sl >= sizeof(scope_name)) return qihse_resp_error(session, "ERR invalid scope name");
        memcpy(scope_name, request->argv[2].data, sl); scope_name[sl] = '\0';
        qihse_infra_scope_t scope;
        if (!qihse_infra_scope_parse(scope_name, &scope)) return qihse_resp_error(session, "ERR unknown scope");
        bool held = qihse_infra_scope_check(session->user, scope);
        return qihse_resp_integer(session, held ? 1 : 0);
    }

    if (qihse_resp_arg_equal(sub, "SCOPE.DEFAULTS")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.scope.defaults");
        char kind_name[64];
        size_t kl = request->argv[2].len;
        if (kl == 0 || kl >= sizeof(kind_name)) return qihse_resp_error(session, "ERR invalid identity kind");
        memcpy(kind_name, request->argv[2].data, kl); kind_name[kl] = '\0';
        qihse_service_identity_t kind;
        if (!qihse_service_identity_parse(kind_name, &kind)) {
            return qihse_resp_error(session, "ERR unknown service identity");
        }
        qihse_infra_scope_t scopes = qihse_service_identity_default_scopes(kind);
        return qihse_resp_integer(session, (int64_t)scopes);
    }

    if (qihse_resp_arg_equal(sub, "NODE.LIST")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.node.list");
        struct qihse_resp_node_list_ctx ctx;
        ctx.count = 0;
        qihse_federation_node_foreach(session->server->store, session->user,
                                      qihse_resp_node_list_cb, &ctx);
        if (!qihse_resp_array(session, ctx.count * 3)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.trust[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.kinds[i])) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "NODE.SHOW")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.node.show");
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        qihse_federation_node_identity_t node;
        if (!qihse_federation_node_lookup(session->server->store, session->user, &nid, &node)) {
            return qihse_resp_error(session, "ERR node not found");
        }
        char fp_hex[97];
        for (size_t i = 0; i < QIHSE_FEDERATION_NODE_FINGERPRINT_BYTES; i++)
            snprintf(fp_hex + i * 2, 3, "%02x", node.fingerprint[i]);
        fp_hex[96] = '\0';
        if (!qihse_resp_array(session, 10)) return false;
        if (!qihse_resp_bulk_text(session, node.hostname)) return false;
        if (!qihse_resp_bulk_text(session, qihse_trust_state_name(node.trust))) return false;
        if (!qihse_resp_bulk_text(session, qihse_service_identity_name(node.identity_kind))) return false;
        if (!qihse_resp_integer(session, (int64_t)node.scopes)) return false;
        if (!qihse_resp_integer(session, (int64_t)node.enrollment_epoch)) return false;
        if (!qihse_resp_integer(session, (int64_t)node.capabilities)) return false;
        if (!qihse_resp_bulk_text(session, fp_hex)) return false;
        if (!qihse_resp_bulk_text(session, node.key_handle)) return false;
        if (!qihse_resp_bulk_text(session, qihse_sig_alg_name(node.sig_alg))) return false;
        if (!qihse_resp_integer(session, (int64_t)node.public_key_len)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "NODE.ENROLL")) {
        if (request->argc != 5) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.NODE.ENROLL <identity_kind> <hostname> <boot_id>");
        }
        if (!session->server->federation_key_directory) {
            return qihse_resp_error(session, "ERR node enrollment is disabled (no key directory configured)");
        }
        char kind_name[64];
        size_t kl = request->argv[2].len;
        if (kl == 0 || kl >= sizeof(kind_name)) return qihse_resp_error(session, "ERR invalid identity kind");
        memcpy(kind_name, request->argv[2].data, kl); kind_name[kl] = '\0';
        qihse_service_identity_t kind;
        if (!qihse_service_identity_parse(kind_name, &kind)) {
            return qihse_resp_error(session, "ERR unknown service identity");
        }
        qihse_federation_node_identity_t id;
        memset(&id, 0, sizeof(id));
        if (!qihse_uuid_generate(&id.node_id)) return qihse_resp_error(session, "ERR could not generate node id");
        size_t hl = request->argv[3].len;
        if (hl == 0 || hl >= sizeof(id.hostname)) return qihse_resp_error(session, "ERR invalid hostname");
        memcpy(id.hostname, request->argv[3].data, hl); id.hostname[hl] = '\0';
        size_t bl = request->argv[4].len;
        if (bl == 0 || bl >= sizeof(id.boot_id)) return qihse_resp_error(session, "ERR invalid boot id");
        memcpy(id.boot_id, request->argv[4].data, bl); id.boot_id[bl] = '\0';
        id.identity_kind = kind;
        /* Generate the identity keypair with the post-quantum default.  The
         * private key is written to the configured directory and never enters
         * a QIHSE record. */
        if (!qihse_federation_node_keygen_alg(session->server->federation_key_directory,
                                             QIHSE_SIG_ALG_DEFAULT, &id)) {
            return qihse_resp_error(session, "ERR node keygen failed");
        }
        if (!qihse_federation_node_enroll_request(session->server->store, session->user, &id)) {
            return qihse_resp_error(session, "ERR node enroll request failed");
        }
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&id.node_id, nid_str);
        return qihse_resp_bulk_text(session, nid_str);
    }

    if (qihse_resp_arg_equal(sub, "NODE.APPROVE")) {
        if (request->argc < 3 || request->argc > 4) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.NODE.APPROVE <node_id> [enrollment_epoch]");
        }
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        uint64_t epoch = qihse_federation_epoch_next(session->server->store, session->user,
                                                     &session->server->federation_node_id);
        if (request->argc == 4) {
            char ep_str[32];
            size_t el = request->argv[3].len;
            if (el == 0 || el >= sizeof(ep_str)) return qihse_resp_error(session, "ERR invalid epoch");
            memcpy(ep_str, request->argv[3].data, el); ep_str[el] = '\0';
            epoch = (uint64_t)strtoull(ep_str, NULL, 10);
        }
        if (!qihse_federation_node_enroll_approve(session->server->store, session->user, &nid, epoch)) {
            return qihse_resp_error(session, "ERR node approve failed");
        }
        return qihse_resp_integer(session, (int64_t)epoch);
    }

    if (qihse_resp_arg_equal(sub, "NODE.REVOKE")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.node.revoke");
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        if (!qihse_federation_node_revoke(session->server->store, session->user, &nid)) {
            return qihse_resp_error(session, "ERR node revoke failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "GOSSIP.STATUS")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.gossip.status");
        char nid_str[QIHSE_UUID_STR_LEN + 1u], bid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len, bl = request->argv[3].len;
        if (nl == 0 || nl >= sizeof(nid_str) || bl == 0 || bl >= sizeof(bid_str)) {
            return qihse_resp_error(session, "ERR invalid node or boot id");
        }
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        memcpy(bid_str, request->argv[3].data, bl); bid_str[bl] = '\0';
        qihse_uuid_t nid, bid;
        if (!qihse_uuid_parse(nid_str, &nid) || !qihse_uuid_parse(bid_str, &bid)) {
            return qihse_resp_error(session, "ERR invalid node or boot id");
        }
        qihse_federation_replay_state_t st;
        if (!qihse_federation_replay_state_read(session->server->store, session->user,
                                                &nid, &bid, &st)) {
            return qihse_resp_error(session, "ERR no gossip state for that node/boot");
        }
        return qihse_resp_integer(session, (int64_t)st.highest_sequence);
    }

    /* ── F6: Build & supply-chain substrate ───────────────────────────── */
    if (qihse_resp_arg_equal(sub, "PROV.EDGE")) {
        if (request->argc != 5) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.PROV.EDGE <ENTITY|id> <edge> <ENTITY|id>");
        }
        qihse_prov_entity_t fe, te;
        qihse_prov_edge_t edge;
        char fid[QIHSE_PROV_ID_MAX + 1u], tid[QIHSE_PROV_ID_MAX + 1u];
        if (!qihse_resp_parse_prov_ref(&request->argv[2], &fe, fid, sizeof(fid))) {
            return qihse_resp_error(session, "ERR invalid from reference (want ENTITY|id)");
        }
        char edge_name[64];
        size_t el = request->argv[3].len;
        if (el == 0 || el >= sizeof(edge_name)) return qihse_resp_error(session, "ERR invalid edge");
        memcpy(edge_name, request->argv[3].data, el); edge_name[el] = '\0';
        if (!qihse_prov_edge_parse(edge_name, &edge)) return qihse_resp_error(session, "ERR unknown edge");
        if (!qihse_resp_parse_prov_ref(&request->argv[4], &te, tid, sizeof(tid))) {
            return qihse_resp_error(session, "ERR invalid to reference (want ENTITY|id)");
        }
        if (!qihse_provenance_edge_put(session->server->store, session->user,
                                       fe, fid, edge, te, tid)) {
            return qihse_resp_error(session, "ERR edge put failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "PROV.NODE")) {
        if (request->argc < 4 || request->argc > 5) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.PROV.NODE <entity> <id> [label]");
        }
        char ent_name[64], id[QIHSE_PROV_ID_MAX + 1u];
        size_t el = request->argv[2].len, il = request->argv[3].len;
        if (el == 0 || el >= sizeof(ent_name) || il == 0 || il >= sizeof(id)) {
            return qihse_resp_error(session, "ERR invalid entity or id");
        }
        memcpy(ent_name, request->argv[2].data, el); ent_name[el] = '\0';
        memcpy(id, request->argv[3].data, il); id[il] = '\0';
        qihse_prov_entity_t entity;
        if (!qihse_prov_entity_parse(ent_name, &entity)) return qihse_resp_error(session, "ERR unknown entity");
        qihse_prov_node_t node;
        memset(&node, 0, sizeof(node));
        node.entity = entity;
        snprintf(node.id, sizeof(node.id), "%s", id);
        if (request->argc == 5) {
            size_t ll = request->argv[4].len;
            if (ll >= sizeof(node.label)) return qihse_resp_error(session, "ERR label too long");
            memcpy(node.label, request->argv[4].data, ll); node.label[ll] = '\0';
        }
        if (!qihse_provenance_node_put(session->server->store, session->user, &node)) {
            return qihse_resp_error(session, "ERR node put failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "PROV.SHOW")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.prov.show");
        char ent_name[64], id[QIHSE_PROV_ID_MAX + 1u];
        size_t el = request->argv[2].len, il = request->argv[3].len;
        if (el == 0 || el >= sizeof(ent_name) || il == 0 || il >= sizeof(id)) {
            return qihse_resp_error(session, "ERR invalid entity or id");
        }
        memcpy(ent_name, request->argv[2].data, el); ent_name[el] = '\0';
        memcpy(id, request->argv[3].data, il); id[il] = '\0';
        qihse_prov_entity_t entity;
        if (!qihse_prov_entity_parse(ent_name, &entity)) return qihse_resp_error(session, "ERR unknown entity");
        qihse_prov_node_t node;
        if (!qihse_provenance_node_get(session->server->store, session->user, entity, id, &node)) {
            return qihse_resp_error(session, "ERR node not found");
        }
        if (!qihse_resp_array(session, 3)) return false;
        if (!qihse_resp_bulk_text(session, qihse_prov_entity_name(node.entity))) return false;
        if (!qihse_resp_bulk_text(session, node.label)) return false;
        if (!qihse_resp_integer(session, node.immutable ? 1 : 0)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "PROV.TRACE")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.PROV.TRACE <entity> <id> <forward|reverse> [depth]");
        }
        char ent_name[64], id[QIHSE_PROV_ID_MAX + 1u], dir[16];
        size_t el = request->argv[2].len, il = request->argv[3].len, dl = request->argv[4].len;
        if (el == 0 || el >= sizeof(ent_name) || il == 0 || il >= sizeof(id) ||
            dl == 0 || dl >= sizeof(dir)) return qihse_resp_error(session, "ERR invalid arguments");
        memcpy(ent_name, request->argv[2].data, el); ent_name[el] = '\0';
        memcpy(id, request->argv[3].data, il); id[il] = '\0';
        memcpy(dir, request->argv[4].data, dl); dir[dl] = '\0';
        qihse_prov_entity_t entity;
        if (!qihse_prov_entity_parse(ent_name, &entity)) return qihse_resp_error(session, "ERR unknown entity");
        uint32_t depth = 16u;
        if (request->argc == 6) {
            char d_str[8];
            size_t sl = request->argv[5].len;
            if (sl == 0 || sl >= sizeof(d_str)) return qihse_resp_error(session, "ERR invalid depth");
            memcpy(d_str, request->argv[5].data, sl); d_str[sl] = '\0';
            depth = (uint32_t)strtoul(d_str, NULL, 10);
        }
        struct qihse_resp_prov_ctx ctx;
        ctx.count = 0;
        if (strcasecmp(dir, "forward") == 0) {
            qihse_provenance_trace_forward(session->server->store, session->user, entity, id,
                                           depth, qihse_resp_prov_collect_cb, &ctx);
        } else if (strcasecmp(dir, "reverse") == 0) {
            qihse_provenance_trace_reverse(session->server->store, session->user, entity, id,
                                           depth, qihse_resp_prov_collect_cb, &ctx);
        } else {
            return qihse_resp_error(session, "ERR direction must be forward or reverse");
        }
        if (!qihse_resp_array(session, ctx.count * 3)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.entities[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.edges[i])) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "PROV.IMPACT")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.PROV.IMPACT <entity> <id> <want_entity> [depth]");
        }
        char ent_name[64], id[QIHSE_PROV_ID_MAX + 1u], want_name[64];
        size_t el = request->argv[2].len, il = request->argv[3].len, wl = request->argv[4].len;
        if (el == 0 || el >= sizeof(ent_name) || il == 0 || il >= sizeof(id) ||
            wl == 0 || wl >= sizeof(want_name)) return qihse_resp_error(session, "ERR invalid arguments");
        memcpy(ent_name, request->argv[2].data, el); ent_name[el] = '\0';
        memcpy(id, request->argv[3].data, il); id[il] = '\0';
        memcpy(want_name, request->argv[4].data, wl); want_name[wl] = '\0';
        qihse_prov_entity_t entity, want;
        if (!qihse_prov_entity_parse(ent_name, &entity)) return qihse_resp_error(session, "ERR unknown entity");
        if (!qihse_prov_entity_parse(want_name, &want)) return qihse_resp_error(session, "ERR unknown entity");
        uint32_t depth = 16u;
        if (request->argc == 6) {
            char d_str[8];
            size_t sl = request->argv[5].len;
            if (sl == 0 || sl >= sizeof(d_str)) return qihse_resp_error(session, "ERR invalid depth");
            memcpy(d_str, request->argv[5].data, sl); d_str[sl] = '\0';
            depth = (uint32_t)strtoul(d_str, NULL, 10);
        }
        struct qihse_resp_prov_ctx ctx;
        ctx.count = 0;
        qihse_provenance_reverse_impact(session->server->store, session->user,
                                        entity, id, want, depth,
                                        qihse_resp_prov_collect_cb, &ctx);
        if (!qihse_resp_array(session, ctx.count * 3)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.entities[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.edges[i])) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "BUILD.STATES")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.build.states");
        static const qihse_build_state_t states[] = {
            QIHSE_BUILD_QUEUED, QIHSE_BUILD_PLANNING, QIHSE_BUILD_LEASED,
            QIHSE_BUILD_BUILDING, QIHSE_BUILD_TESTING, QIHSE_BUILD_VERIFYING,
            QIHSE_BUILD_SIGNING, QIHSE_BUILD_PUBLISHED, QIHSE_BUILD_FAILED,
            QIHSE_BUILD_RETRYABLE, QIHSE_BUILD_QUARANTINED, QIHSE_BUILD_CANCELLED,
        };
        size_t n = sizeof(states) / sizeof(states[0]);
        if (!qihse_resp_array(session, n)) return false;
        for (size_t i = 0; i < n; i++) {
            if (!qihse_resp_bulk_text(session, qihse_build_state_name(states[i]))) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "BUILD.CREATE")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.BUILD.CREATE <package> <revision> <profile> <toolchain>");
        }
        qihse_build_job_t job;
        memset(&job, 0, sizeof(job));
        if (!qihse_uuid_generate(&job.build_id)) return qihse_resp_error(session, "ERR could not generate build id");
        size_t pl = request->argv[2].len, rl = request->argv[3].len,
               fl = request->argv[4].len, tl = request->argv[5].len;
        if (pl == 0 || pl >= sizeof(job.package) || rl == 0 || rl >= sizeof(job.source_revision) ||
            fl >= sizeof(job.profile) || tl >= sizeof(job.toolchain)) {
            return qihse_resp_error(session, "ERR invalid argument length");
        }
        memcpy(job.package, request->argv[2].data, pl); job.package[pl] = '\0';
        memcpy(job.source_revision, request->argv[3].data, rl); job.source_revision[rl] = '\0';
        memcpy(job.profile, request->argv[4].data, fl); job.profile[fl] = '\0';
        memcpy(job.toolchain, request->argv[5].data, tl); job.toolchain[tl] = '\0';
        job.created_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        qihse_build_job_t out;
        if (!qihse_build_job_create(session->server->store, session->user, &job, &out)) {
            return qihse_resp_error(session, "ERR build create failed");
        }
        char bid[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&out.build_id, bid);
        return qihse_resp_bulk_text(session, bid);
    }

    if (qihse_resp_arg_equal(sub, "BUILD.SHOW")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.build.show");
        char bid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t bl = request->argv[2].len;
        if (bl == 0 || bl >= sizeof(bid_str)) return qihse_resp_error(session, "ERR invalid build id");
        memcpy(bid_str, request->argv[2].data, bl); bid_str[bl] = '\0';
        qihse_uuid_t bid;
        if (!qihse_uuid_parse(bid_str, &bid)) return qihse_resp_error(session, "ERR invalid build id");
        qihse_build_job_t job;
        if (!qihse_build_job_get(session->server->store, session->user, &bid, &job)) {
            return qihse_resp_error(session, "ERR build not found");
        }
        if (!qihse_resp_array(session, 7)) return false;
        if (!qihse_resp_bulk_text(session, job.package)) return false;
        if (!qihse_resp_bulk_text(session, qihse_build_state_name(job.state))) return false;
        if (!qihse_resp_integer(session, (int64_t)job.generation)) return false;
        if (!qihse_resp_bulk_text(session, job.source_revision)) return false;
        if (!qihse_resp_bulk_text(session, job.profile)) return false;
        if (!qihse_resp_bulk_text(session, job.toolchain)) return false;
        if (!qihse_resp_bulk_text(session, job.failure_reason)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "BUILD.TRANSITION")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.BUILD.TRANSITION <build_id> <state> <request_id> [reason]");
        }
        char bid_str[QIHSE_UUID_STR_LEN + 1u], state_name[32], req_name[128];
        size_t bl = request->argv[2].len, sl = request->argv[3].len, rl = request->argv[4].len;
        if (bl == 0 || bl >= sizeof(bid_str) || sl == 0 || sl >= sizeof(state_name) ||
            rl == 0 || rl >= sizeof(req_name)) return qihse_resp_error(session, "ERR invalid arguments");
        memcpy(bid_str, request->argv[2].data, bl); bid_str[bl] = '\0';
        memcpy(state_name, request->argv[3].data, sl); state_name[sl] = '\0';
        memcpy(req_name, request->argv[4].data, rl); req_name[rl] = '\0';
        qihse_uuid_t bid, req_id;
        if (!qihse_uuid_parse(bid_str, &bid)) return qihse_resp_error(session, "ERR invalid build id");
        qihse_build_state_t next;
        if (!qihse_build_state_parse(state_name, &next)) return qihse_resp_error(session, "ERR unknown state");
        if (!qihse_uuid_from_seed(req_name, strlen(req_name), &req_id)) {
            return qihse_resp_error(session, "ERR invalid request id");
        }
        char reason[256];
        reason[0] = '\0';
        if (request->argc == 6) {
            size_t xl = request->argv[5].len;
            if (xl >= sizeof(reason)) return qihse_resp_error(session, "ERR reason too long");
            memcpy(reason, request->argv[5].data, xl); reason[xl] = '\0';
        }
        qihse_build_job_t out;
        if (!qihse_build_job_transition(session->server->store, session->user, &bid, next,
                                        &req_id, reason[0] ? reason : NULL, &out)) {
            return qihse_resp_error(session, "ERR illegal transition");
        }
        return qihse_resp_integer(session, (int64_t)out.generation);
    }

    if (qihse_resp_arg_equal(sub, "BUILD.LIST")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.build.list");
        struct qihse_resp_build_list_ctx ctx;
        ctx.count = 0;
        qihse_build_job_foreach(session->server->store, session->user,
                                qihse_resp_build_list_cb, &ctx);
        if (!qihse_resp_array(session, ctx.count * 3)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.packages[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.states[i])) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "PKG.MODES")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.pkg.modes");
        static const qihse_pkg_mode_t modes[] = {
            QIHSE_PKG_UPSTREAM_BINARY, QIHSE_PKG_UPSTREAM_SOURCE_REBUILD,
            QIHSE_PKG_CITADEL_OVERLAY, QIHSE_PKG_CITADEL_FORK,
            QIHSE_PKG_FORBIDDEN, QIHSE_PKG_ISOLATED_EXCEPTION,
        };
        size_t n = sizeof(modes) / sizeof(modes[0]);
        if (!qihse_resp_array(session, n)) return false;
        for (size_t i = 0; i < n; i++) {
            if (!qihse_resp_bulk_text(session, qihse_pkg_mode_name(modes[i]))) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "PKG.SET")) {
        if (request->argc != 5) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.PKG.SET <package> <mode> <reason>");
        }
        qihse_pkg_policy_t p;
        memset(&p, 0, sizeof(p));
        size_t pl = request->argv[2].len, ml = request->argv[3].len, rl = request->argv[4].len;
        if (pl == 0 || pl >= sizeof(p.package) || ml == 0 || ml >= 32 ||
            rl == 0 || rl >= sizeof(p.reason)) return qihse_resp_error(session, "ERR invalid arguments");
        memcpy(p.package, request->argv[2].data, pl); p.package[pl] = '\0';
        char mode_name[32];
        memcpy(mode_name, request->argv[3].data, ml); mode_name[ml] = '\0';
        if (!qihse_pkg_mode_parse(mode_name, &p.mode)) return qihse_resp_error(session, "ERR unknown package mode");
        memcpy(p.reason, request->argv[4].data, rl); p.reason[rl] = '\0';
        p.decided_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        if (!qihse_pkg_policy_set(session->server->store, session->user, &p)) {
            return qihse_resp_error(session, "ERR policy set failed (a reason is required)");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "PKG.GET")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.pkg.get");
        char package[128];
        size_t pl = request->argv[2].len;
        if (pl == 0 || pl >= sizeof(package)) return qihse_resp_error(session, "ERR invalid package");
        memcpy(package, request->argv[2].data, pl); package[pl] = '\0';
        qihse_pkg_policy_t p;
        if (!qihse_pkg_policy_get(session->server->store, session->user, package, &p)) {
            return qihse_resp_error(session, "ERR no policy for that package");
        }
        if (!qihse_resp_array(session, 2)) return false;
        if (!qihse_resp_bulk_text(session, qihse_pkg_mode_name(p.mode))) return false;
        if (!qihse_resp_bulk_text(session, p.reason)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "BUILDER.CAP")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.BUILDER.CAP <node_id> <cores_available> <ram_available_gb> <queue_depth>");
        }
        qihse_builder_capability_t cap;
        memset(&cap, 0, sizeof(cap));
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        if (!qihse_uuid_parse(nid_str, &cap.node_id)) return qihse_resp_error(session, "ERR invalid node id");
        char nums[3][16];
        for (size_t i = 0; i < 3; i++) {
            size_t l = request->argv[3 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[3 + i].data, l); nums[i][l] = '\0';
        }
        cap.cores_available = (uint32_t)strtoul(nums[0], NULL, 10);
        cap.ram_available_gb = (uint64_t)strtoull(nums[1], NULL, 10);
        cap.build_queue_depth = (uint32_t)strtoul(nums[2], NULL, 10);
        cap.trust_state = QIHSE_TRUST_APPROVED;
        cap.observed_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        if (!qihse_builder_capability_put(session->server->store, session->user, &cap)) {
            return qihse_resp_error(session, "ERR capability put failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "BUILDER.SHOW")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.builder.show");
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        qihse_builder_capability_t cap;
        if (!qihse_builder_capability_get(session->server->store, session->user, &nid, &cap)) {
            return qihse_resp_error(session, "ERR no capability record for that node");
        }
        if (!qihse_resp_array(session, 4)) return false;
        if (!qihse_resp_integer(session, (int64_t)cap.cores_available)) return false;
        if (!qihse_resp_integer(session, (int64_t)cap.ram_available_gb)) return false;
        if (!qihse_resp_integer(session, (int64_t)cap.build_queue_depth)) return false;
        if (!qihse_resp_bulk_text(session, qihse_trust_state_name(cap.trust_state))) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SUPPLY.SBOM")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SUPPLY.SBOM <artifact_digest> <sbom_digest> <signing_identity> <format>");
        }
        qihse_sbom_record_t rec;
        memset(&rec, 0, sizeof(rec));
        if (!qihse_uuid_generate(&rec.sbom_id)) return qihse_resp_error(session, "ERR could not generate sbom id");
        size_t al = request->argv[2].len, sl = request->argv[3].len,
               il = request->argv[4].len, fl = request->argv[5].len;
        if (al == 0 || al >= sizeof(rec.artifact_digest) || sl == 0 || sl >= sizeof(rec.sbom_digest) ||
            il == 0 || il >= sizeof(rec.signing_identity) || fl == 0 || fl >= sizeof(rec.format)) {
            return qihse_resp_error(session, "ERR invalid argument length");
        }
        memcpy(rec.artifact_digest, request->argv[2].data, al); rec.artifact_digest[al] = '\0';
        memcpy(rec.sbom_digest, request->argv[3].data, sl); rec.sbom_digest[sl] = '\0';
        memcpy(rec.signing_identity, request->argv[4].data, il); rec.signing_identity[il] = '\0';
        memcpy(rec.format, request->argv[5].data, fl); rec.format[fl] = '\0';
        rec.signature_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        snprintf(rec.verification_status, sizeof(rec.verification_status), "unverified");
        /* QIHSE records no key material — only an external handle. */
        snprintf(rec.signing_key_handle, sizeof(rec.signing_key_handle), "external");
        if (!qihse_sbom_record_put(session->server->store, session->user, &rec)) {
            return qihse_resp_error(session, "ERR sbom record failed");
        }
        char sid[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&rec.sbom_id, sid);
        return qihse_resp_bulk_text(session, sid);
    }

    if (qihse_resp_arg_equal(sub, "SUPPLY.SBOM.GET")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.supply.sbom.get");
        char sid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t sl = request->argv[2].len;
        if (sl == 0 || sl >= sizeof(sid_str)) return qihse_resp_error(session, "ERR invalid sbom id");
        memcpy(sid_str, request->argv[2].data, sl); sid_str[sl] = '\0';
        qihse_uuid_t sid;
        if (!qihse_uuid_parse(sid_str, &sid)) return qihse_resp_error(session, "ERR invalid sbom id");
        qihse_sbom_record_t rec;
        if (!qihse_sbom_record_get(session->server->store, session->user, &sid, &rec)) {
            return qihse_resp_error(session, "ERR sbom not found");
        }
        if (!qihse_resp_array(session, 4)) return false;
        if (!qihse_resp_bulk_text(session, rec.artifact_digest)) return false;
        if (!qihse_resp_bulk_text(session, rec.signing_identity)) return false;
        if (!qihse_resp_bulk_text(session, rec.verification_status)) return false;
        if (!qihse_resp_bulk_text(session, rec.format)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SUPPLY.VULN")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SUPPLY.VULN <component_digest> <advisory> <severity> <status>");
        }
        qihse_vuln_observation_t obs;
        memset(&obs, 0, sizeof(obs));
        if (!qihse_uuid_generate(&obs.observation_id)) {
            return qihse_resp_error(session, "ERR could not generate observation id");
        }
        size_t cl = request->argv[2].len, al = request->argv[3].len,
               sl = request->argv[4].len, tl = request->argv[5].len;
        if (cl == 0 || cl >= sizeof(obs.component_digest) || al == 0 || al >= sizeof(obs.advisory_id) ||
            sl == 0 || sl >= sizeof(obs.severity) || tl == 0 || tl >= sizeof(obs.status)) {
            return qihse_resp_error(session, "ERR invalid argument length");
        }
        memcpy(obs.component_digest, request->argv[2].data, cl); obs.component_digest[cl] = '\0';
        memcpy(obs.advisory_id, request->argv[3].data, al); obs.advisory_id[al] = '\0';
        memcpy(obs.severity, request->argv[4].data, sl); obs.severity[sl] = '\0';
        memcpy(obs.status, request->argv[5].data, tl); obs.status[tl] = '\0';
        obs.observed_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        if (!qihse_vuln_observation_put(session->server->store, session->user, &obs)) {
            return qihse_resp_error(session, "ERR observation record failed");
        }
        char oid[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&obs.observation_id, oid);
        return qihse_resp_bulk_text(session, oid);
    }

    if (qihse_resp_arg_equal(sub, "SUPPLY.VULN.COUNT")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.supply.vuln.count");
        char digest[QIHSE_PROV_DIGEST_MAX * 2u + 1u];
        size_t dl = request->argv[2].len;
        if (dl == 0 || dl >= sizeof(digest)) return qihse_resp_error(session, "ERR invalid component digest");
        memcpy(digest, request->argv[2].data, dl); digest[dl] = '\0';
        size_t n = qihse_vuln_count_by_component(session->server->store, session->user, digest);
        return qihse_resp_integer(session, (int64_t)n);
    }

    if (qihse_resp_arg_equal(sub, "SUPPLY.SNAPSHOT")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SUPPLY.SNAPSHOT <repository> <digest> <release> [package_count]");
        }
        qihse_repo_snapshot_t snap;
        memset(&snap, 0, sizeof(snap));
        if (!qihse_uuid_generate(&snap.snapshot_id)) {
            return qihse_resp_error(session, "ERR could not generate snapshot id");
        }
        size_t rl = request->argv[2].len, dl = request->argv[3].len, ll = request->argv[4].len;
        if (rl == 0 || rl >= sizeof(snap.repository) || dl == 0 || dl >= sizeof(snap.snapshot_digest) ||
            ll == 0 || ll >= sizeof(snap.release)) return qihse_resp_error(session, "ERR invalid argument length");
        memcpy(snap.repository, request->argv[2].data, rl); snap.repository[rl] = '\0';
        memcpy(snap.snapshot_digest, request->argv[3].data, dl); snap.snapshot_digest[dl] = '\0';
        memcpy(snap.release, request->argv[4].data, ll); snap.release[ll] = '\0';
        if (request->argc == 6) {
            char c_str[24];
            size_t cl = request->argv[5].len;
            if (cl == 0 || cl >= sizeof(c_str)) return qihse_resp_error(session, "ERR invalid package count");
            memcpy(c_str, request->argv[5].data, cl); c_str[cl] = '\0';
            snap.package_count = (uint64_t)strtoull(c_str, NULL, 10);
        }
        snap.created_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        snap.created_by = session->server->federation_node_id;
        snprintf(snap.signing_key_handle, sizeof(snap.signing_key_handle), "external");
        if (!qihse_repo_snapshot_put(session->server->store, session->user, &snap)) {
            return qihse_resp_error(session, "ERR snapshot record failed");
        }
        char sid[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&snap.snapshot_id, sid);
        return qihse_resp_bulk_text(session, sid);
    }

    if (qihse_resp_arg_equal(sub, "SUPPLY.SNAPSHOT.LIST")) {
        if (request->argc < 2 || request->argc > 3) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SUPPLY.SNAPSHOT.LIST [repository]");
        }
        char repo[128];
        repo[0] = '\0';
        if (request->argc == 3) {
            size_t rl = request->argv[2].len;
            if (rl == 0 || rl >= sizeof(repo)) return qihse_resp_error(session, "ERR invalid repository");
            memcpy(repo, request->argv[2].data, rl); repo[rl] = '\0';
        }
        struct qihse_resp_snapshot_list_ctx ctx;
        ctx.count = 0;
        qihse_repo_snapshot_foreach(session->server->store, session->user,
                                    repo[0] ? repo : NULL,
                                    qihse_resp_snapshot_list_cb, &ctx);
        if (!qihse_resp_array(session, ctx.count * 3)) return false;
        for (size_t i = 0; i < ctx.count; i++) {
            if (!qihse_resp_bulk_text(session, ctx.ids[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.releases[i])) return false;
            if (!qihse_resp_bulk_text(session, ctx.digests[i])) return false;
        }
        return true;
    }

    /* ── F7: Runtime trust and hardening ─────────────────────────────── */
    if (qihse_resp_arg_equal(sub, "TRUST.STATES")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.trust.states");
        static const qihse_runtime_trust_t states[] = {
            QIHSE_RTRUST_UNKNOWN, QIHSE_RTRUST_TRUSTED, QIHSE_RTRUST_TRUSTED_DEGRADED,
            QIHSE_RTRUST_LOCAL_ONLY, QIHSE_RTRUST_QUARANTINED, QIHSE_RTRUST_REVOKED,
        };
        size_t n = sizeof(states) / sizeof(states[0]);
        if (!qihse_resp_array(session, n)) return false;
        for (size_t i = 0; i < n; i++) {
            if (!qihse_resp_bulk_text(session, qihse_runtime_trust_name(states[i]))) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "TRUST.ADMISSION")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.trust.admission");
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        qihse_admission_t a;
        if (!qihse_runtime_admission_for_node(session->server->store, session->user, &nid, &a)) {
            return qihse_resp_error(session, "ERR admission lookup failed");
        }
        if (!qihse_resp_array(session, 7)) return false;
        if (!qihse_resp_bulk_text(session, qihse_runtime_trust_name(a.trust_state))) return false;
        if (!qihse_resp_integer(session, a.local_usable ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, a.may_replicate ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, a.may_read_remote ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, a.may_strong_write ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, a.may_vote ? 1 : 0)) return false;
        if (!qihse_resp_bulk_text(session, a.reason)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "TRUST.SET")) {
        if (request->argc != 5) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.TRUST.SET <node_id> <trust_state> <result>");
        }
        char nid_str[QIHSE_UUID_STR_LEN + 1u], state_name[32], result[64];
        size_t nl = request->argv[2].len, sl = request->argv[3].len, rl = request->argv[4].len;
        if (nl == 0 || nl >= sizeof(nid_str) || sl == 0 || sl >= sizeof(state_name) ||
            rl == 0 || rl >= sizeof(result)) return qihse_resp_error(session, "ERR invalid arguments");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        memcpy(state_name, request->argv[3].data, sl); state_name[sl] = '\0';
        memcpy(result, request->argv[4].data, rl); result[rl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        qihse_runtime_trust_t trust;
        if (!qihse_runtime_trust_parse(state_name, &trust)) {
            return qihse_resp_error(session, "ERR unknown trust state");
        }
        qihse_trust_verification_t v;
        memset(&v, 0, sizeof(v));
        v.node_id = nid;
        v.trust_state = trust;
        v.trust_policy_generation = qihse_federation_epoch_current(
            session->server->store, session->user, &session->server->federation_node_id);
        v.evidence_verified_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        v.verification_principal = session->server->federation_node_id;
        snprintf(v.verification_result, sizeof(v.verification_result), "%s", result);
        if (!qihse_trust_verification_put(session->server->store, session->user, &v,
                                          session->server->federation_journal)) {
            return qihse_resp_error(session, "ERR trust verification failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "SECURITY.IFACES")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.security.ifaces");
        if (!qihse_resp_array(session, QIHSE_IFACE_COUNT)) return false;
        for (size_t i = 0; i < QIHSE_IFACE_COUNT; i++) {
            if (!qihse_resp_bulk_text(session, qihse_kernel_iface_name((qihse_kernel_iface_t)i))) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SECURITY.OBSERVE")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.security.observe");
        qihse_runtime_observation_t o;
        if (!qihse_runtime_observe(&o)) return qihse_resp_error(session, "ERR runtime observation failed");
        if (!qihse_resp_array(session, 9)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.uid)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.euid)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.gid)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.egid)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.effective_capabilities)) return false;
        if (!qihse_resp_integer(session, o.core_dumps_enabled ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, o.dumpable ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.seccomp_mode)) return false;
        if (!qihse_resp_integer(session, (int64_t)o.listening_port_count)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SECURITY.AUDIT")) {
        if (request->argc < 2 || request->argc > 4) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SECURITY.AUDIT [service] [version]");
        }
        char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u], version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
        service[0] = '\0';
        version[0] = '\0';
        if (request->argc >= 3) {
            size_t sl = request->argv[2].len;
            if (sl == 0 || sl >= sizeof(service)) return qihse_resp_error(session, "ERR invalid service");
            memcpy(service, request->argv[2].data, sl); service[sl] = '\0';
        }
        if (request->argc == 4) {
            size_t vl = request->argv[3].len;
            if (vl == 0 || vl >= sizeof(version)) return qihse_resp_error(session, "ERR invalid version");
            memcpy(version, request->argv[3].data, vl); version[vl] = '\0';
        }
        qihse_runtime_profile_t profile;
        qihse_net_profile_t net;
        bool have_profile = false;
        bool have_net = false;
        if (service[0] && version[0]) {
            have_profile = qihse_runtime_profile_get(session->server->store, session->user,
                                                    service, version, &profile);
            have_net = qihse_net_profile_get(session->server->store, session->user,
                                             service, version, &net);
        }
        qihse_runtime_observation_t o;
        if (!qihse_runtime_observe(&o)) return qihse_resp_error(session, "ERR runtime observation failed");
        uint32_t declared[32];
        size_t declared_count = 0;
        if (have_net) {
            /* Declared listeners come from the network exposure profile. */
            declared_count = net.listener_count;
            for (size_t i = 0; i < declared_count && i < 32u; i++) declared[i] = net.ports[i];
        } else {
            /* Without a declared network profile, treat the process's own
             * current listeners as the baseline so the report is still
             * meaningful. */
            declared_count = o.listening_port_count;
            for (size_t i = 0; i < declared_count && i < 32u; i++) declared[i] = o.listening_ports[i];
        }
        qihse_audit_report_t report;
        if (!qihse_runtime_audit(have_profile ? &profile : NULL, &o, declared, declared_count, &report)) {
            return qihse_resp_error(session, "ERR audit failed");
        }
        if (!qihse_resp_array(session, 9)) return false;
        if (!qihse_resp_bulk_text(session, qihse_runtime_trust_name(report.recommended_trust))) return false;
        if (!qihse_resp_integer(session, report.critical ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, report.profile_found ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, (int64_t)report.unexpected_capability_count)) return false;
        if (!qihse_resp_integer(session, (int64_t)report.unexpected_listener_count)) return false;
        if (!qihse_resp_integer(session, (int64_t)report.unclassified_interface_count)) return false;
        if (!qihse_resp_integer(session, (int64_t)report.forbidden_interface_count)) return false;
        if (!qihse_resp_integer(session, (int64_t)report.finding_count)) return false;
        if (!qihse_resp_bulk_text(session, report.finding_count ? report.findings[0].detail : "")) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SECURITY.PROFILE.SET")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SECURITY.PROFILE.SET <service> <version> <allowed_caps_mask> <core_dumps> <require_seccomp>");
        }
        char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u], version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
        size_t sl = request->argv[2].len, vl = request->argv[3].len;
        if (sl == 0 || sl >= sizeof(service) || vl == 0 || vl >= sizeof(version)) {
            return qihse_resp_error(session, "ERR invalid service or version");
        }
        memcpy(service, request->argv[2].data, sl); service[sl] = '\0';
        memcpy(version, request->argv[3].data, vl); version[vl] = '\0';
        char nums[3][24];
        for (size_t i = 0; i < 3u; i++) {
            size_t l = request->argv[4 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[4 + i].data, l); nums[i][l] = '\0';
        }
        qihse_runtime_profile_t p;
        qihse_runtime_profile_init(&p, service, version);
        p.allowed_capabilities = (uint64_t)strtoull(nums[0], NULL, 0);
        p.core_dumps_allowed = strtoul(nums[1], NULL, 10) != 0;
        p.require_seccomp = strtoul(nums[2], NULL, 10) != 0;
        if (!qihse_runtime_profile_put(session->server->store, session->user, &p)) {
            return qihse_resp_error(session, "ERR profile put failed");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "SECURITY.PROFILE.GET")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.security.profile.get");
        char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u], version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
        size_t sl = request->argv[2].len, vl = request->argv[3].len;
        if (sl == 0 || sl >= sizeof(service) || vl == 0 || vl >= sizeof(version)) {
            return qihse_resp_error(session, "ERR invalid service or version");
        }
        memcpy(service, request->argv[2].data, sl); service[sl] = '\0';
        memcpy(version, request->argv[3].data, vl); version[vl] = '\0';
        qihse_runtime_profile_t p;
        if (!qihse_runtime_profile_get(session->server->store, session->user, service, version, &p)) {
            return qihse_resp_error(session, "ERR profile not found");
        }
        if (!qihse_resp_array(session, 5)) return false;
        if (!qihse_resp_integer(session, (int64_t)p.allowed_capabilities)) return false;
        if (!qihse_resp_integer(session, p.core_dumps_allowed ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, p.require_seccomp ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, (int64_t)p.generation)) return false;
        if (!qihse_resp_integer(session, (int64_t)p.expected_uid)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SECURITY.NET.GET")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.security.net.get");
        char service[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u], version[QIHSE_RUNTIME_PROFILE_ID_MAX + 1u];
        size_t sl = request->argv[2].len, vl = request->argv[3].len;
        if (sl == 0 || sl >= sizeof(service) || vl == 0 || vl >= sizeof(version)) {
            return qihse_resp_error(session, "ERR invalid service or version");
        }
        memcpy(service, request->argv[2].data, sl); service[sl] = '\0';
        memcpy(version, request->argv[3].data, vl); version[vl] = '\0';
        qihse_net_profile_t np;
        if (!qihse_net_profile_get(session->server->store, session->user, service, version, &np)) {
            return qihse_resp_error(session, "ERR network profile not found");
        }
        if (!qihse_resp_array(session, 3)) return false;
        if (!qihse_resp_integer(session, qihse_net_profile_is_egress_restricted(&np) ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, (int64_t)np.listener_count)) return false;
        if (!qihse_resp_integer(session, (int64_t)np.generation)) return false;
        return true;
    }

    /* ── F8: Operational hardening ───────────────────────────────────── */
    if (qihse_resp_arg_equal(sub, "SCHEMA.CHECK")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SCHEMA.CHECK <writer_version> <min_reader> <required_hex> <optional_hex>");
        }
        char nums[4][32];
        for (size_t i = 0; i < 4u; i++) {
            size_t l = request->argv[2 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[2 + i].data, l); nums[i][l] = '\0';
        }
        qihse_schema_header_t h;
        qihse_schema_header_init(&h, QIHSE_SCHEMA_ID_FEDERATION,
                                 (uint32_t)strtoul(nums[0], NULL, 10));
        h.minimum_reader_version = (uint32_t)strtoul(nums[1], NULL, 10);
        h.required_features = (uint64_t)strtoull(nums[2], NULL, 0);
        h.optional_features = (uint64_t)strtoull(nums[3], NULL, 0);
        /* The reader is this build, so its capabilities are this build's —
         * not the object's, which would make the check vacuous. */
        qihse_schema_reader_t reader;
        reader.max_schema_version = QIHSE_SCHEMA_MAX_VERSION;
        reader.known_features = QIHSE_SCHEMA_KNOWN_FEATURES;
        qihse_schema_result_t res = qihse_schema_check(&h, &reader);
        return qihse_resp_bulk_text(session, qihse_schema_result_name(res));
    }

    if (qihse_resp_arg_equal(sub, "SCHEMA.MIGRATE")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SCHEMA.MIGRATE <schema_id> <from_version> <to_version> <resumable>");
        }
        char nums[4][32];
        for (size_t i = 0; i < 4u; i++) {
            size_t l = request->argv[2 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[2 + i].data, l); nums[i][l] = '\0';
        }
        qihse_schema_migration_t m;
        memset(&m, 0, sizeof(m));
        m.schema_id = (uint32_t)strtoul(nums[0], NULL, 10);
        m.from_version = (uint32_t)strtoul(nums[1], NULL, 10);
        m.to_version = (uint32_t)strtoul(nums[2], NULL, 10);
        m.resumable = strtoul(nums[3], NULL, 10) != 0;
        snprintf(m.description, sizeof(m.description), "registered via RESP");
        if (!qihse_schema_migration_register(session->server->store, session->user, &m)) {
            return qihse_resp_error(session, "ERR migration must move forward");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "SCHEMA.PROGRESS")) {
        if (request->argc != 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SCHEMA.PROGRESS <schema_id> <version> <completed> <total>");
        }
        char nums[4][32];
        for (size_t i = 0; i < 4u; i++) {
            size_t l = request->argv[2 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[2 + i].data, l); nums[i][l] = '\0';
        }
        uint32_t schema_id = (uint32_t)strtoul(nums[0], NULL, 10);
        uint32_t version = (uint32_t)strtoul(nums[1], NULL, 10);
        uint64_t completed = (uint64_t)strtoull(nums[2], NULL, 10);
        uint64_t total = (uint64_t)strtoull(nums[3], NULL, 10);
        if (!qihse_schema_progress_set(session->server->store, session->user,
                                       schema_id, version, completed, total)) {
            return qihse_resp_error(session, "ERR progress cannot over-report");
        }
        return qihse_resp_simple(session, "OK");
    }

    if (qihse_resp_arg_equal(sub, "SCHEMA.STATUS")) {
        if (request->argc != 4) return qihse_resp_wrong_arity(session, "federation.schema.status");
        char nums[2][32];
        for (size_t i = 0; i < 2u; i++) {
            size_t l = request->argv[2 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[2 + i].data, l); nums[i][l] = '\0';
        }
        uint32_t schema_id = (uint32_t)strtoul(nums[0], NULL, 10);
        uint32_t version = (uint32_t)strtoul(nums[1], NULL, 10);
        uint64_t completed = 0, total = 0;
        bool found = qihse_schema_progress_get(session->server->store, session->user,
                                               schema_id, version, &completed, &total);
        bool complete = qihse_schema_progress_complete(session->server->store, session->user,
                                                       schema_id, version);
        if (!qihse_resp_array(session, 4)) return false;
        if (!qihse_resp_integer(session, found ? 1 : 0)) return false;
        if (!qihse_resp_integer(session, (int64_t)completed)) return false;
        if (!qihse_resp_integer(session, (int64_t)total)) return false;
        if (!qihse_resp_integer(session, complete ? 1 : 0)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SNAPSHOT.CREATE")) {
        if (request->argc < 5 || request->argc > 6) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.SNAPSHOT.CREATE <local|coordinated> <max_generation> <wal_offset> [key_id]");
        }
        char kind_name[24], nums[2][32];
        size_t kl = request->argv[2].len;
        if (kl == 0 || kl >= sizeof(kind_name)) return qihse_resp_error(session, "ERR invalid kind");
        memcpy(kind_name, request->argv[2].data, kl); kind_name[kl] = '\0';
        qihse_snapshot_kind_t kind;
        if (!qihse_snapshot_kind_parse(kind_name, &kind)) {
            return qihse_resp_error(session, "ERR unknown snapshot kind");
        }
        for (size_t i = 0; i < 2u; i++) {
            size_t l = request->argv[3 + i].len;
            if (l == 0 || l >= sizeof(nums[i])) return qihse_resp_error(session, "ERR invalid numeric argument");
            memcpy(nums[i], request->argv[3 + i].data, l); nums[i][l] = '\0';
        }
        qihse_snapshot_manifest_t m;
        memset(&m, 0, sizeof(m));
        if (!qihse_uuid_generate(&m.snapshot_id)) {
            return qihse_resp_error(session, "ERR could not generate snapshot id");
        }
        m.kind = kind;
        m.cluster_id = session->server->federation_node_id;
        m.created_by = session->server->federation_node_id;
        m.created_hlc_physical = (uint64_t)time(NULL) * 1000ULL;
        qihse_schema_header_init(&m.schema, QIHSE_SCHEMA_ID_FEDERATION, 1);
        m.max_generation = (uint64_t)strtoull(nums[0], NULL, 10);
        m.wal_continuation_offset = (uint64_t)strtoull(nums[1], NULL, 10);
        if (request->argc == 6) {
            size_t xl = request->argv[5].len;
            if (xl >= sizeof(m.encryption_key_id)) return qihse_resp_error(session, "ERR key id too long");
            memcpy(m.encryption_key_id, request->argv[5].data, xl);
            m.encryption_key_id[xl] = '\0';
        }
        m.object_count = qihse_kv_count_user(session->server->store, session->user);
        if (!qihse_snapshot_record(session->server->store, session->user, &m)) {
            return qihse_resp_error(session, "ERR snapshot record failed");
        }
        char sid[QIHSE_UUID_STR_LEN + 1u];
        qihse_uuid_format(&m.snapshot_id, sid);
        return qihse_resp_bulk_text(session, sid);
    }

    if (qihse_resp_arg_equal(sub, "SNAPSHOT.SHOW")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.snapshot.show");
        char sid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t sl = request->argv[2].len;
        if (sl == 0 || sl >= sizeof(sid_str)) return qihse_resp_error(session, "ERR invalid snapshot id");
        memcpy(sid_str, request->argv[2].data, sl); sid_str[sl] = '\0';
        qihse_uuid_t sid;
        if (!qihse_uuid_parse(sid_str, &sid)) return qihse_resp_error(session, "ERR invalid snapshot id");
        qihse_snapshot_manifest_t m;
        if (!qihse_snapshot_lookup(session->server->store, session->user, &sid, &m)) {
            return qihse_resp_error(session, "ERR snapshot not found");
        }
        bool verified = qihse_snapshot_verify(session->server->store, session->user, &sid);
        if (!qihse_resp_array(session, 7)) return false;
        if (!qihse_resp_bulk_text(session, qihse_snapshot_kind_name(m.kind))) return false;
        if (!qihse_resp_integer(session, (int64_t)m.max_generation)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.wal_continuation_offset)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.object_count)) return false;
        if (!qihse_resp_integer(session, (int64_t)m.group_count)) return false;
        if (!qihse_resp_bulk_text(session, m.encryption_key_id)) return false;
        if (!qihse_resp_integer(session, verified ? 1 : 0)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "SNAPSHOT.VERIFY")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.snapshot.verify");
        char sid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t sl = request->argv[2].len;
        if (sl == 0 || sl >= sizeof(sid_str)) return qihse_resp_error(session, "ERR invalid snapshot id");
        memcpy(sid_str, request->argv[2].data, sl); sid_str[sl] = '\0';
        qihse_uuid_t sid;
        if (!qihse_uuid_parse(sid_str, &sid)) return qihse_resp_error(session, "ERR invalid snapshot id");
        bool ok = qihse_snapshot_verify(session->server->store, session->user, &sid);
        return qihse_resp_integer(session, ok ? 1 : 0);
    }

    if (qihse_resp_arg_equal(sub, "REJOIN.STEPS")) {
        if (request->argc != 2) return qihse_resp_wrong_arity(session, "federation.rejoin.steps");
        static const qihse_rejoin_step_t steps[] = {
            QIHSE_REJOIN_IDLE, QIHSE_REJOIN_AUTHENTICATE_PEER,
            QIHSE_REJOIN_COMPARE_FEDERATION_UUID, QIHSE_REJOIN_COMPARE_BOOT_UUID,
            QIHSE_REJOIN_EXCHANGE_HLC, QIHSE_REJOIN_EXCHANGE_MANIFESTS,
            QIHSE_REJOIN_IDENTIFY_DIVERGENCE, QIHSE_REJOIN_TRANSFER_EVENTS,
            QIHSE_REJOIN_APPLY_CONFLICT_POLICY, QIHSE_REJOIN_RECONSTRUCT_STATE,
            QIHSE_REJOIN_VERIFY_CHECKSUMS, QIHSE_REJOIN_COMPLETE, QIHSE_REJOIN_ABORTED,
        };
        size_t n = sizeof(steps) / sizeof(steps[0]);
        if (!qihse_resp_array(session, n)) return false;
        for (size_t i = 0; i < n; i++) {
            if (!qihse_resp_bulk_text(session, qihse_rejoin_step_name(steps[i]))) return false;
        }
        return true;
    }

    if (qihse_resp_arg_equal(sub, "REJOIN.STATUS")) {
        if (request->argc != 3) return qihse_resp_wrong_arity(session, "federation.rejoin.status");
        char nid_str[QIHSE_UUID_STR_LEN + 1u];
        size_t nl = request->argv[2].len;
        if (nl == 0 || nl >= sizeof(nid_str)) return qihse_resp_error(session, "ERR invalid node id");
        memcpy(nid_str, request->argv[2].data, nl); nid_str[nl] = '\0';
        qihse_uuid_t nid;
        if (!qihse_uuid_parse(nid_str, &nid)) return qihse_resp_error(session, "ERR invalid node id");
        qihse_rejoin_state_t st;
        if (!qihse_rejoin_state_get(session->server->store, session->user, &nid, &st)) {
            return qihse_resp_error(session, "ERR no rejoin state for that node");
        }
        if (!qihse_resp_array(session, 5)) return false;
        if (!qihse_resp_bulk_text(session, qihse_rejoin_step_name(st.step))) return false;
        if (!qihse_resp_integer(session, (int64_t)st.events_transferred)) return false;
        if (!qihse_resp_integer(session, (int64_t)st.conflicts_applied)) return false;
        if (!qihse_resp_integer(session,
                qihse_rejoin_may_publish_ownership(st.step) ? 1 : 0)) return false;
        if (!qihse_resp_bulk_text(session, st.last_error)) return false;
        return true;
    }

    if (qihse_resp_arg_equal(sub, "METRICS")) {
        if (request->argc < 2 || request->argc > 3) {
            return qihse_resp_error(session, "ERR usage: FEDERATION.METRICS [prefix]");
        }
        qihse_federation_metrics_t m;
        qihse_federation_metrics_init(&m);
        pthread_mutex_lock(&session->server->federation_lock);
        qihse_federation_status_recompute(&session->server->federation_status);
        m.federation_peer_state_connected =
            (session->server->federation_status.federation_state == QIHSE_FEDERATION_STATE_CONNECTED)
                ? 1u : 0u;
        m.runtime_trust_state = (uint64_t)session->server->federation_status.federation_state;
        pthread_mutex_unlock(&session->server->federation_lock);
        m.unreplicated_bytes = 0;
        char prefix[64];
        prefix[0] = '\0';
        if (request->argc == 3) {
            size_t pl = request->argv[2].len;
            if (pl == 0 || pl >= sizeof(prefix)) return qihse_resp_error(session, "ERR invalid prefix");
            memcpy(prefix, request->argv[2].data, pl); prefix[pl] = '\0';
        }
        char out[4096];
        if (!qihse_federation_metrics_render(&m, prefix[0] ? prefix : NULL, out, sizeof(out))) {
            return qihse_resp_error(session, "ERR metrics render failed");
        }
        return qihse_resp_bulk_text(session, out);
    }

    return qihse_resp_error(session, "ERR unknown FEDERATION subcommand");
}

/* ---------------------------------------------------------------------------
 * FABRIC.* — heterogeneous compute dispatch
 * FABRIC.CAPS    — cluster capability map (system domain only)
 * FABRIC.SUBMIT <min_isa> <payload> — dispatch a job to the best-fit node
 * FABRIC.RESULT <job-id> — read a job result
 * Jobs are stored in KV under fabric:job:<id>; the target node's worker
 * scans for them and executes. Phase 1: local execution only (the node
 * that receives the submit runs it if it matches, else forwards).
 * ------------------------------------------------------------------------- */
static bool qihse_resp_handle_fabric_caps(qihse_resp_session_t* session) {
    if (!session->server->bus) return qihse_resp_error(session, "ERR bus not available");
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(session->server->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    if (!qihse_resp_array(session, (size_t)(count * 2))) return false;
    for (size_t i = 0; i < count; i++) {
        char addr[128];
        snprintf(addr, sizeof(addr), "%s:%u", nodes[i].host, nodes[i].port);
        if (!qihse_resp_bulk_text(session, addr)) return false;
        uint8_t isa = 0, npu = 0, gpu = 0;
        uint32_t ram = 0;
        uint16_t load = 0;
        bool answered = false;

        /* Prefer the DURABLE capability record when the node's federation
         * identity is known. The live bus hint is ephemeral — it is rebuilt
         * from incoming datagrams and lost on restart — so a node that has
         * been quiet since boot has no hint even though its last claim is on
         * disk. The durable lookup additionally requires the node to be
         * APPROVED right now, so a revoked node's stale claim is not served.
         *
         * `src=` tells the caller which it got. That matters: a durable record
         * is attributable and survives restart, a live hint is neither, and a
         * caller that cannot tell them apart will treat the weaker one as the
         * stronger. */
        if (nodes[i].has_uuid) {
            qihse_uuid_t nu;
            memcpy(nu.bytes, nodes[i].node_uuid, sizeof nu.bytes);
            qihse_federation_node_capability_t rec;
            memset(&rec, 0, sizeof rec);
            qihse_kv_store_t* st = qihse_resp_server_store(session->server);
            if (st && qihse_federation_node_capability_lookup_admissible(
                          st, session->user, &nu, &rec)) {
                char cap_buf[256];
                (void)snprintf(cap_buf, sizeof(cap_buf),
                    "isa=%u npu=%u gpu=%u ram=%u load=%u src=durable trust=%u attested=%u",
                    (unsigned)rec.values.isa_tier, (unsigned)rec.values.npu,
                    (unsigned)rec.values.gpu, (unsigned)rec.values.free_ram_mb,
                    (unsigned)rec.values.load_pct, (unsigned)rec.trust,
                    (unsigned)((rec.flags & QIHSE_CAP_FLAG_ATTESTED) ? 1u : 0u));
                if (!qihse_resp_bulk_text(session, cap_buf)) return false;
                answered = true;
            }
        }
        if (!answered &&
            qihse_cluster_bus_node_caps(session->server->bus, nodes[i].index, &isa, &npu, &gpu, &ram, &load)) {
            char cap_buf[192];
            (void)snprintf(cap_buf, sizeof(cap_buf),
                "isa=%u npu=%u gpu=%u ram=%u load=%u src=hint", isa, npu, gpu, ram, load);
            if (!qihse_resp_bulk_text(session, cap_buf)) return false;
            answered = true;
        }
        if (!answered) {
            if (!qihse_resp_bulk_text(session, "no-cap")) return false;
        }
    }
    return true;
}

static bool qihse_resp_handle_fabric_submit(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    /* Superset signature. The 4-argument form is the original and is kept
     * working: it is an `embed` job. The 5-argument form names the type
     * explicitly. Changing the original would break every existing caller for
     * no gain, so the new form is additive. */
    /* argv[0] is FABRIC and argv[1] is SUBMIT, so the legacy form
     * `FABRIC SUBMIT <min_isa> <need_npu> <payload>` is argc == 5. */
    const char* job_type = "embed";
    int base = 2;
    if (request->argc == 6) {
        job_type = (const char*)request->argv[2].data;
        base = 3;
    } else if (request->argc != 5) {
        return qihse_resp_error(session,
            "ERR usage: FABRIC.SUBMIT [<type>] <min_isa> <need_npu> <payload>");
    }
    if (qihse_user_get_tenant_id(session->user) != QIHSE_TENANT_SYSTEM) {
        return qihse_resp_error(session, "NOPERM FABRIC dispatch is system-domain only");
    }
    uint64_t min_isa, need_npu;
    if (!qihse_resp_parse_u64_arg(&request->argv[base], &min_isa) ||
        !qihse_resp_parse_u64_arg(&request->argv[base + 1], &need_npu)) {
        return qihse_resp_error(session, "ERR invalid capability spec");
    }
    char payload[4096];
    size_t plen = request->argv[base + 2].len;
    if (plen == 0 || plen >= sizeof(payload)) return qihse_resp_error(session, "ERR payload too large (max 4095)");
    memcpy(payload, request->argv[base + 2].data, plen);
    payload[plen] = '\0';

    /* A type with no executor is REFUSED, not accepted-and-ignored. Silently
     * storing a job nobody will ever run is how a queue fills with work that
     * reports success. */
    /* Plain strcmp: building a compound qihse_resp_arg_t here meant casting
     * away const to satisfy a uint8_t* field, which is both noisy and a
     * pointer-target mismatch the compiler warns about. */
    bool is_embed = strcmp(job_type, "embed") == 0;
    bool is_ingest = strcmp(job_type, "keystone-ingest") == 0;
    if (!is_embed && !is_ingest) {
        char err[192];
        snprintf(err, sizeof(err),
                 "ERR job type not implemented: %s (implemented: embed, keystone-ingest)",
                 job_type);
        return qihse_resp_error(session, err);
    }

    /* Find best-fit node: lowest load_pct among nodes meeting the capability */
    if (!session->server->bus) return qihse_resp_error(session, "ERR bus not available");
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(session->server->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint16_t best_idx = QIHSE_CLUSTER_NODE_NONE;
    uint16_t best_load = UINT16_MAX;
    for (size_t i = 0; i < count; i++) {
        uint8_t isa, npu, gpu;
        uint32_t ram;
        uint16_t load;
        if (qihse_cluster_bus_node_caps(session->server->bus, nodes[i].index, &isa, &npu, &gpu, &ram, &load)) {
            if (isa < min_isa || (need_npu && !npu)) continue;
            if (load < best_load) { best_load = load; best_idx = nodes[i].index; }
        }
    }
    /* Also consider THIS node. Nothing sends a node its own bus hint, so on a
     * single-node deployment the loop above finds nothing and no job can ever
     * run. The local node's capabilities are not unknown — they are durable
     * (the bus records its own probe at start) — they are simply not in the
     * hint table. Reading them here is what makes a one-node fabric work. */
    if (best_idx == QIHSE_CLUSTER_NODE_NONE && session->server->topology) {
        uint16_t local_idx = qihse_cluster_topology_local_node(session->server->topology);
        for (size_t i = 0; i < count && local_idx != QIHSE_CLUSTER_NODE_NONE; i++) {
            if (nodes[i].index != local_idx) continue;
            if (!nodes[i].has_uuid) break;
            qihse_uuid_t nu;
            memcpy(nu.bytes, nodes[i].node_uuid, sizeof nu.bytes);
            qihse_federation_node_capability_t rec;
            memset(&rec, 0, sizeof rec);
            pthread_rwlock_rdlock(&session->server->kv_lock);
            /* The NON-admissible lookup, deliberately. The admissibility check
             * answers "may I trust this PEER's claim about its hardware". For
             * the local node that question does not arise: the probe is this
             * node's own measurement of itself, and requiring the node to be
             * federation-approved before it may know its own CPU would make a
             * single-node deployment unable to place any work. Peer claims
             * still go through the admissible accessor in the brain. */
            bool have = qihse_federation_node_capability_lookup(
                session->server->store, session->user, &nu, &rec);
            pthread_rwlock_unlock(&session->server->kv_lock);
            if (!have) break;
            if (rec.values.isa_tier < min_isa || (need_npu && !rec.values.npu)) break;
            best_idx = local_idx;
            best_load = rec.values.load_pct;
            break;
        }
    }
    if (best_idx == QIHSE_CLUSTER_NODE_NONE)
        return qihse_resp_error(session, "ERR no node matches the capability requirement");

    /* EXECUTE, then record what actually happened.
     *
     * Phase 1 is LOCAL execution only, and the record says so rather than
     * implying a dispatch that did not occur. When the best-fit node is not
     * this node the job is recorded as `queued` with the chosen target, which
     * is the truth: it has been placed but not run. Remote dispatch needs a
     * transport and a result path that do not exist yet. */
    static uint64_t job_seq = 0;
    uint64_t jid = __atomic_add_fetch(&job_seq, 1, __ATOMIC_RELAXED);

    uint16_t local_idx = session->server->topology
        ? qihse_cluster_topology_local_node(session->server->topology)
        : QIHSE_CLUSTER_NODE_NONE;
    bool is_local = (best_idx == local_idx);

    /* Big enough for either a memory id (36) or an artifact key
     * ("fabric:ingest:<job-id>"). Sized to the larger: at 37 this silently
     * TRUNCATED an artifact key, so FABRIC.RESULT would have handed back a key
     * that does not exist — a job reporting a result nobody could look up. */
    char result[128];
    result[0] = '\0';
    const char* status = "queued";
    const char* exec = "none";
    char err[160];
    err[0] = '\0';

    if (is_local) {
        exec = "local";
        if (is_embed) {
            /* `embed`: turn the payload into a memory, which indexes it for
             * both lexical and semantic recall. */
            char mem_id[QIHSE_AIMEM_ID_LEN + 1u];
            if (qihse_ai_memory_store(session->server, session->user, payload,
                                      QIHSE_AIMEM_SEMANTIC, mem_id)) {
                snprintf(result, sizeof(result), "%s", mem_id);
                status = "done";
            } else {
                status = "failed";
                snprintf(err, sizeof(err), "embed failed");
            }
        } else {
            /* `keystone-ingest`: persist the payload as a fabric artifact and
             * classify+index it through KEYSTONE.
             *
             * The index is a SOFT dependency (it dlopens libkeystone.so), so
             * "stored but not indexed" is a real and reportable outcome. It is
             * reported as its own status rather than as success, because a
             * caller told `done` would reasonably expect the artifact to be
             * findable, and it would not be. */
            char art_key[128];
            snprintf(art_key, sizeof(art_key), "fabric:ingest:%llu", (unsigned long long)jid);
            pthread_rwlock_wrlock(&session->server->kv_lock);
            bool stored = qihse_kv_set_user(session->server->store, art_key, payload,
                                            0, 0, session->user);
            pthread_rwlock_unlock(&session->server->kv_lock);
            if (!stored) {
                status = "failed";
                snprintf(err, sizeof(err), "artifact store failed");
            } else {
                int irc = qihse_fabric_index_artifact_user(art_key, payload, strlen(payload),
                                                          0u, 0u, session->user);
                snprintf(result, sizeof(result), "%s", art_key);
                if (irc == 0) {
                    status = "done";
                } else {
                    status = "stored-unindexed";
                    snprintf(err, sizeof(err),
                             "artifact persisted but KEYSTONE indexing failed (%d)", irc);
                }
            }
        }
    }

    char job_key[128], job_val[4600];
    snprintf(job_key, sizeof(job_key), "fabric:job:%llu", (unsigned long long)jid);
    snprintf(job_val, sizeof(job_val),
             "{\"type\":\"%s\",\"status\":\"%s\",\"exec\":\"%s\",\"target\":%u,"
             "\"isa\":%llu,\"npu\":%llu,\"result\":\"%s\",\"err\":\"%s\"}",
             job_type, status, exec, (unsigned)best_idx,
             (unsigned long long)min_isa, (unsigned long long)need_npu, result, err);
    pthread_rwlock_wrlock(&session->server->kv_lock);
    bool ok = qihse_kv_set_user(session->server->store, job_key, job_val, 0, 0, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (!ok) return qihse_resp_error(session, "ERR failed to store job");
    char reply[192];
    snprintf(reply, sizeof(reply), "job:%llu node:%u status:%s",
             (unsigned long long)jid, (unsigned)best_idx, status);
    return qihse_resp_bulk_text(session, reply);
}

static bool qihse_resp_handle_fabric_result(qihse_resp_session_t* session, const qihse_resp_request_t* request) {
    /* argv[0] is FABRIC, argv[1] is RESULT, argv[2] is the job id: argc == 3.
     * This check said 2, so the dispatcher routed the command and the handler
     * then rejected its own arity — FABRIC.RESULT could not work even after
     * the record it reads was made to exist. */
    if (request->argc != 3) return qihse_resp_error(session, "ERR usage: FABRIC RESULT <job-id>");
    if (qihse_user_get_tenant_id(session->user) != QIHSE_TENANT_SYSTEM) {
        return qihse_resp_error(session, "NOPERM FABRIC.RESULT is system-domain only");
    }
    /* The job record IS the result. The previous version read a
     * `fabric:result:<id>` key that NOTHING in the tree ever wrote, so
     * FABRIC.RESULT could not succeed for any job ever submitted. */
    char job_key[128];
    snprintf(job_key, sizeof(job_key), "fabric:job:%s", (const char*)request->argv[2].data);
    char* val = NULL;
    pthread_rwlock_wrlock(&session->server->kv_lock);
    val = qihse_kv_get_user(session->server->store, job_key, session->user);
    pthread_rwlock_unlock(&session->server->kv_lock);
    if (!val) return qihse_resp_error(session, "ERR no such job");
    bool ok = qihse_resp_bulk_text(session, val);
    free(val);
    return ok;
}

/* ---------------------------------------------------------------------------
 * W5.2 query-type classification.
 *
 * The `type` label of qihse_queries_total / qihse_query_errors_total /
 * qihse_query_latency_seconds is bounded by the qihse_query_type_t enum: this
 * table maps command NAMES (never an argument, never a key) onto that enum,
 * and a name that is not listed lands in OTHER.  A command added to the
 * engine without a type therefore shows up as `other` — a slightly less
 * useful number, never a new series and never a cardinality leak.
 *
 * The lookup is the same folded FNV-1a hash the dispatch table uses, so
 * attribution costs one hash and one probe.  It is skipped entirely when the
 * registry is absent, which is the only case where a hot path pays nothing.
 * ------------------------------------------------------------------------- */
typedef struct { const char* name; uint8_t type; } qihse_resp_qtype_ent_t;

static const qihse_resp_qtype_ent_t g_qtype_table[] = {
    /* single-key value reads */
    {"get", QIHSE_QUERY_TYPE_GET}, {"getrange", QIHSE_QUERY_TYPE_GET},
    {"getbit", QIHSE_QUERY_TYPE_GET}, {"strlen", QIHSE_QUERY_TYPE_GET},
    {"hget", QIHSE_QUERY_TYPE_GET}, {"hmget", QIHSE_QUERY_TYPE_GET},
    {"hgetall", QIHSE_QUERY_TYPE_GET}, {"hkeys", QIHSE_QUERY_TYPE_GET},
    {"hvals", QIHSE_QUERY_TYPE_GET}, {"hlen", QIHSE_QUERY_TYPE_GET},
    {"hexists", QIHSE_QUERY_TYPE_GET}, {"hstrlen", QIHSE_QUERY_TYPE_GET},
    {"lindex", QIHSE_QUERY_TYPE_GET}, {"llen", QIHSE_QUERY_TYPE_GET},
    {"lrange", QIHSE_QUERY_TYPE_GET}, {"zscore", QIHSE_QUERY_TYPE_GET},
    {"zcard", QIHSE_QUERY_TYPE_GET}, {"zcount", QIHSE_QUERY_TYPE_GET},
    {"zrange", QIHSE_QUERY_TYPE_GET}, {"zrevrange", QIHSE_QUERY_TYPE_GET},
    {"zrangebyscore", QIHSE_QUERY_TYPE_GET}, {"zrevrangebyscore", QIHSE_QUERY_TYPE_GET},
    {"zrank", QIHSE_QUERY_TYPE_GET}, {"zrevrank", QIHSE_QUERY_TYPE_GET},
    {"sismember", QIHSE_QUERY_TYPE_GET}, {"scard", QIHSE_QUERY_TYPE_GET},
    {"smembers", QIHSE_QUERY_TYPE_GET}, {"sdiff", QIHSE_QUERY_TYPE_GET},
    {"sinter", QIHSE_QUERY_TYPE_GET}, {"sunion", QIHSE_QUERY_TYPE_GET},
    {"srandmember", QIHSE_QUERY_TYPE_GET}, {"pfcount", QIHSE_QUERY_TYPE_GET},
    {"bitcount", QIHSE_QUERY_TYPE_GET}, {"bitpos", QIHSE_QUERY_TYPE_GET},
    {"memory", QIHSE_QUERY_TYPE_GET},
    /* writes */
    {"set", QIHSE_QUERY_TYPE_SET}, {"setex", QIHSE_QUERY_TYPE_SET},
    {"psetex", QIHSE_QUERY_TYPE_SET}, {"setrange", QIHSE_QUERY_TYPE_SET},
    {"setbit", QIHSE_QUERY_TYPE_SET}, {"getset", QIHSE_QUERY_TYPE_SET},
    {"append", QIHSE_QUERY_TYPE_SET}, {"incr", QIHSE_QUERY_TYPE_SET},
    {"decr", QIHSE_QUERY_TYPE_SET}, {"incrby", QIHSE_QUERY_TYPE_SET},
    {"decrby", QIHSE_QUERY_TYPE_SET}, {"incrbyfloat", QIHSE_QUERY_TYPE_SET},
    {"mset", QIHSE_QUERY_TYPE_SET}, {"msetnx", QIHSE_QUERY_TYPE_SET},
    {"hset", QIHSE_QUERY_TYPE_SET}, {"hmset", QIHSE_QUERY_TYPE_SET},
    {"hsetnx", QIHSE_QUERY_TYPE_SET}, {"hincrby", QIHSE_QUERY_TYPE_SET},
    {"lpush", QIHSE_QUERY_TYPE_SET}, {"rpush", QIHSE_QUERY_TYPE_SET},
    {"lpop", QIHSE_QUERY_TYPE_SET}, {"rpop", QIHSE_QUERY_TYPE_SET},
    {"lset", QIHSE_QUERY_TYPE_SET}, {"ltrim", QIHSE_QUERY_TYPE_SET},
    {"linsert", QIHSE_QUERY_TYPE_SET}, {"rpoplpush", QIHSE_QUERY_TYPE_SET},
    {"sadd", QIHSE_QUERY_TYPE_SET}, {"smove", QIHSE_QUERY_TYPE_SET},
    {"spop", QIHSE_QUERY_TYPE_SET}, {"zadd", QIHSE_QUERY_TYPE_SET},
    {"zincrby", QIHSE_QUERY_TYPE_SET}, {"zpopmax", QIHSE_QUERY_TYPE_SET},
    {"zpopmin", QIHSE_QUERY_TYPE_SET}, {"pfadd", QIHSE_QUERY_TYPE_SET},
    {"pfmerge", QIHSE_QUERY_TYPE_SET}, {"bitop", QIHSE_QUERY_TYPE_SET},
    {"copy", QIHSE_QUERY_TYPE_SET}, {"rename", QIHSE_QUERY_TYPE_SET},
    {"renamenx", QIHSE_QUERY_TYPE_SET}, {"flushdb", QIHSE_QUERY_TYPE_SET},
    {"flushall", QIHSE_QUERY_TYPE_SET}, {"save", QIHSE_QUERY_TYPE_SET},
    {"bgsave", QIHSE_QUERY_TYPE_SET},
    /* deletes */
    {"del", QIHSE_QUERY_TYPE_DELETE}, {"unlink", QIHSE_QUERY_TYPE_DELETE},
    {"getdel", QIHSE_QUERY_TYPE_DELETE}, {"hdel", QIHSE_QUERY_TYPE_DELETE},
    {"srem", QIHSE_QUERY_TYPE_DELETE}, {"zrem", QIHSE_QUERY_TYPE_DELETE},
    {"lrem", QIHSE_QUERY_TYPE_DELETE},
    /* expiry */
    {"expire", QIHSE_QUERY_TYPE_EXPIRE}, {"pexpire", QIHSE_QUERY_TYPE_EXPIRE},
    {"expireat", QIHSE_QUERY_TYPE_EXPIRE}, {"pexpireat", QIHSE_QUERY_TYPE_EXPIRE},
    {"persist", QIHSE_QUERY_TYPE_EXPIRE}, {"ttl", QIHSE_QUERY_TYPE_EXPIRE},
    {"pttl", QIHSE_QUERY_TYPE_EXPIRE},
    /* multi-key / metadata reads */
    {"mget", QIHSE_QUERY_TYPE_SCAN}, {"keys", QIHSE_QUERY_TYPE_SCAN},
    {"scan", QIHSE_QUERY_TYPE_SCAN}, {"dbsize", QIHSE_QUERY_TYPE_SCAN},
    {"randomkey", QIHSE_QUERY_TYPE_SCAN}, {"type", QIHSE_QUERY_TYPE_SCAN},
    {"exists", QIHSE_QUERY_TYPE_SCAN}, {"object", QIHSE_QUERY_TYPE_SCAN},
    {"touch", QIHSE_QUERY_TYPE_SCAN},
    /* model-specific engines */
    {"vecset", QIHSE_QUERY_TYPE_VECTOR}, {"vecget", QIHSE_QUERY_TYPE_VECTOR},
    {"vecsearch", QIHSE_QUERY_TYPE_VECTOR}, {"vecscatter", QIHSE_QUERY_TYPE_VECTOR},
    {"ts.add", QIHSE_QUERY_TYPE_TIMESERIES}, {"ts.range", QIHSE_QUERY_TYPE_TIMESERIES},
    {"col.append", QIHSE_QUERY_TYPE_COLUMN}, {"col.sum", QIHSE_QUERY_TYPE_COLUMN},
    {"col.minmax", QIHSE_QUERY_TYPE_COLUMN},
    {"keystone.ingest", QIHSE_QUERY_TYPE_KEYSTONE},
    {"keystone.classify", QIHSE_QUERY_TYPE_KEYSTONE},
    {"fabric.caps", QIHSE_QUERY_TYPE_FABRIC}, {"fabric.submit", QIHSE_QUERY_TYPE_FABRIC},
    {"fabric.result", QIHSE_QUERY_TYPE_FABRIC},
    /* control plane */
    {"cluster", QIHSE_QUERY_TYPE_CLUSTER}, {"migrate", QIHSE_QUERY_TYPE_CLUSTER},
    {"asking", QIHSE_QUERY_TYPE_CLUSTER}, {"readonly", QIHSE_QUERY_TYPE_CLUSTER},
    {"readwrite", QIHSE_QUERY_TYPE_CLUSTER}, {"role", QIHSE_QUERY_TYPE_CLUSTER},
    {"federation", QIHSE_QUERY_TYPE_FEDERATION},
    {"publish", QIHSE_QUERY_TYPE_PUBSUB}, {"subscribe", QIHSE_QUERY_TYPE_PUBSUB},
    {"unsubscribe", QIHSE_QUERY_TYPE_PUBSUB}, {"psubscribe", QIHSE_QUERY_TYPE_PUBSUB},
    {"punsubscribe", QIHSE_QUERY_TYPE_PUBSUB}, {"pubsub", QIHSE_QUERY_TYPE_PUBSUB},
    {"info", QIHSE_QUERY_TYPE_ADMIN}, {"config", QIHSE_QUERY_TYPE_ADMIN},
    {"debug", QIHSE_QUERY_TYPE_ADMIN}, {"command", QIHSE_QUERY_TYPE_ADMIN},
    {"client", QIHSE_QUERY_TYPE_ADMIN}, {"shutdown", QIHSE_QUERY_TYPE_ADMIN},
    {"slowlog", QIHSE_QUERY_TYPE_ADMIN}, {"latency", QIHSE_QUERY_TYPE_ADMIN},
    {"time", QIHSE_QUERY_TYPE_ADMIN}, {"lastsave", QIHSE_QUERY_TYPE_ADMIN},
    {"script", QIHSE_QUERY_TYPE_ADMIN}, {"eval", QIHSE_QUERY_TYPE_ADMIN},
    {"evalsha", QIHSE_QUERY_TYPE_ADMIN}, {"metrics.render", QIHSE_QUERY_TYPE_ADMIN},
    {"auth", QIHSE_QUERY_TYPE_SESSION}, {"hello", QIHSE_QUERY_TYPE_SESSION},
    {"ping", QIHSE_QUERY_TYPE_SESSION}, {"quit", QIHSE_QUERY_TYPE_SESSION},
    {"select", QIHSE_QUERY_TYPE_SESSION}, {"echo", QIHSE_QUERY_TYPE_SESSION},
    {"reset", QIHSE_QUERY_TYPE_SESSION}, {"multi", QIHSE_QUERY_TYPE_SESSION},
    {"exec", QIHSE_QUERY_TYPE_SESSION}, {"discard", QIHSE_QUERY_TYPE_SESSION},
    {"watch", QIHSE_QUERY_TYPE_SESSION}, {"unwatch", QIHSE_QUERY_TYPE_SESSION}
};

#define RESP_QTYPE_MAP_CAP 256u
static const qihse_resp_qtype_ent_t* g_qtype_map[RESP_QTYPE_MAP_CAP];
static pthread_once_t g_qtype_map_once = PTHREAD_ONCE_INIT;

static void qihse_resp_qtype_map_build(void) {
    size_t n = sizeof(g_qtype_table) / sizeof(g_qtype_table[0]);
    for (size_t i = 0; i < n; i++) {
        const char* nm = g_qtype_table[i].name;
        uint32_t h = qihse_resp_cmd_hash((const uint8_t*)nm, strlen(nm)) & (RESP_QTYPE_MAP_CAP - 1u);
        for (size_t j = 0; j < RESP_QTYPE_MAP_CAP; j++) {
            size_t pos = (h + j) & (RESP_QTYPE_MAP_CAP - 1u);
            if (!g_qtype_map[pos]) { g_qtype_map[pos] = &g_qtype_table[i]; break; }
            if (strcasecmp(g_qtype_map[pos]->name, nm) == 0) break; /* dup name */
        }
    }
}

/* Command families whose subcommand set is open-ended: a subcommand added
 * later is still the same query type, so a prefix rule keeps the LABEL
 * bounded while the vocabulary grows.  The list is fixed and short, and only
 * consulted for names the table above does not cover. */
static const struct { const char* prefix; uint8_t type; } g_qtype_prefixes[] = {
    {"KEYSTONE.FEED.", QIHSE_QUERY_TYPE_KEYSTONE},
    {"TASK.", QIHSE_QUERY_TYPE_FABRIC},
    {"SCHEDULE.", QIHSE_QUERY_TYPE_FABRIC},
    {"GROUP.", QIHSE_QUERY_TYPE_CLUSTER},
    {"CLUSTER.", QIHSE_QUERY_TYPE_CLUSTER},
    {"FEDERATION.", QIHSE_QUERY_TYPE_FEDERATION},
    {"FABRIC.", QIHSE_QUERY_TYPE_FABRIC},
    {"BUNDLE.", QIHSE_QUERY_TYPE_ADMIN}
};

static qihse_query_type_t qihse_resp_classify(const qihse_resp_request_t* request) {
    if (!request || request->argc == 0) return QIHSE_QUERY_TYPE_OTHER;
    const qihse_resp_arg_t* name = &request->argv[0];
    /* The longest name in the vocabulary is well under 32 bytes; anything
     * longer is not a command this build knows. */
    if (name->len == 0 || name->len > 31u) return QIHSE_QUERY_TYPE_OTHER;
    pthread_once(&g_qtype_map_once, qihse_resp_qtype_map_build);
    uint32_t h = qihse_resp_cmd_hash(name->data, name->len) & (RESP_QTYPE_MAP_CAP - 1u);
    for (size_t i = 0; i < RESP_QTYPE_MAP_CAP; i++) {
        const qihse_resp_qtype_ent_t* e = g_qtype_map[(h + i) & (RESP_QTYPE_MAP_CAP - 1u)];
        if (!e) break;
        if (strlen(e->name) == name->len && qihse_resp_arg_equal(name, e->name)) {
            return (qihse_query_type_t)e->type;
        }
    }
    for (size_t i = 0; i < sizeof(g_qtype_prefixes) / sizeof(g_qtype_prefixes[0]); i++) {
        size_t plen = strlen(g_qtype_prefixes[i].prefix);
        if (name->len < plen) continue;
        if (strncasecmp((const char*)name->data, g_qtype_prefixes[i].prefix, plen) == 0) {
            return (qihse_query_type_t)g_qtype_prefixes[i].type;
        }
    }
    return QIHSE_QUERY_TYPE_OTHER;
}

/* Which engine serves a query type.  Used for the backend dimension; the
 * mapping is a property of the command vocabulary, not of the caller. */
static qihse_engine_backend_t qihse_resp_backend_for_type(qihse_query_type_t type) {
    switch (type) {
        case QIHSE_QUERY_TYPE_GET:
        case QIHSE_QUERY_TYPE_SET:
        case QIHSE_QUERY_TYPE_DELETE:
        case QIHSE_QUERY_TYPE_SCAN:
        case QIHSE_QUERY_TYPE_EXPIRE:
            return QIHSE_ENGINE_BACKEND_KV;
        case QIHSE_QUERY_TYPE_VECTOR:     return QIHSE_ENGINE_BACKEND_VECTOR;
        case QIHSE_QUERY_TYPE_TIMESERIES: return QIHSE_ENGINE_BACKEND_TIMESERIES;
        case QIHSE_QUERY_TYPE_COLUMN:     return QIHSE_ENGINE_BACKEND_COLUMN;
        case QIHSE_QUERY_TYPE_DOCUMENT:   return QIHSE_ENGINE_BACKEND_DOCUMENT;
        case QIHSE_QUERY_TYPE_GRAPH:      return QIHSE_ENGINE_BACKEND_GRAPH;
        case QIHSE_QUERY_TYPE_FTS:        return QIHSE_ENGINE_BACKEND_FTS;
        default:                          return QIHSE_ENGINE_BACKEND_CONTROL;
    }
}

static bool qihse_resp_dispatch_inner(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool* keep_open);

/* W5.2: the timing/attribution wrapper.
 *
 * It exists so that every early return inside dispatch — and there are many —
 * is still measured and attributed to a query type without editing a hundred
 * return statements.  When the registry is absent this is a tail call: no
 * clock read, no hash, no counter, so a build without metrics pays nothing.
 *
 * Measured cost when metrics are present: ~100 ns per command — two
 * clock_gettime (44 ns), the two counter adds (16 ns), the histogram
 * observation (23 ns) and one folded-hash classification (~10-20 ns).  That is
 * ~5% of a ~2 us point operation and is stated here rather than left as an
 * assumption; if it ever became a larger share than the thing it measures,
 * the histogram would be the part to drop, not the counters.
 */
static bool qihse_resp_dispatch(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool* keep_open) {
    qihse_resp_server_t* server = session->server;
    if (!server || !server->metrics || request->argc == 0) {
        return qihse_resp_dispatch_inner(session, request, keep_open);
    }
    qihse_query_type_t type = qihse_resp_classify(request);
    session->query_type = type;
    struct timespec started;
    struct timespec finished;
    clock_gettime(CLOCK_MONOTONIC, &started);
    bool ok = qihse_resp_dispatch_inner(session, request, keep_open);
    clock_gettime(CLOCK_MONOTONIC, &finished);
    double seconds = (double)(finished.tv_sec - started.tv_sec) +
                     (double)(finished.tv_nsec - started.tv_nsec) / 1000000000.0;
    if (seconds < 0.0) seconds = 0.0;
    if (server->tlm.queries[type]) qihse_metrics_series_increment(server->tlm.queries[type], 1u);
    qihse_engine_backend_t backend = qihse_resp_backend_for_type(type);
    if (server->tlm.backend_queries[backend]) qihse_metrics_series_increment(server->tlm.backend_queries[backend], 1u);
    if (server->tlm.latency[type]) qihse_metrics_series_observe(server->tlm.latency[type], seconds);
    return ok;
}

static bool qihse_resp_dispatch_inner(qihse_resp_session_t* session, const qihse_resp_request_t* request, bool* keep_open) {
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
    /* U2 revocation SLA: re-validate the session principal authoritatively
     * once per command. A destroyed principal loses the session immediately —
     * including on the unclassified per-row fast path, which intentionally
     * skips identity resolution for throughput. */
    /* Fused liveness + tenant probe: one auth_rwlock trip per command, still
     * a live lookup so revocation lands on the next command. */
    bool session_active = true;
    uint32_t session_tenant = QIHSE_TENANT_SYSTEM;
    if (session->user) {
        qihse_auth_user_active_and_tenant(session->user, &session_active, &session_tenant);
        if (!session_active) {
            session->user = NULL;
            session_tenant = QIHSE_TENANT_SYSTEM;
            if (session->server->auth_required) return qihse_resp_error(session, "NOAUTH Session principal revoked.");
        }
    }
    /* W2.5: the KEYSTONE index identity is a narrow read/index principal. Its
     * command surface is the change feed and nothing else — enforced here at
     * the single dispatch chokepoint rather than trusting every handler's own
     * gate. A compromised indexer therefore cannot reach a write, an
     * administrative command, or a federation control-plane command, and
     * KEYSTONE.FEED.PUBLISH still has to pass the FEDERATION_WRITE scope check
     * in qihse_keystone_feed_publish(). */
    if (session->user && qihse_keystone_feed_identity_is_indexer(session->user) &&
        !qihse_resp_command_is_keystone_feed(request)) {
        return qihse_resp_error(session,
            "NOPERM the KEYSTONE index identity may only consume KEYSTONE.FEED.*");
    }
    /* One hash probe per command — reused by the subscribed, MULTI-queue,
     * guard-write and final-dispatch checks below. */
    const qihse_resp_dispatch_ent_t* dispatch_entry = qihse_resp_dispatch_find(&request->argv[0]);

    /* Subscribed-mode command restriction (Redis semantics) */
    if (qihse_resp_pubsub_subscribed(session) &&
        !(dispatch_entry && (dispatch_entry->flags & DSP_SUB_OK)) &&
        !qihse_resp_command_is(request, "PING") &&
        !qihse_resp_command_is(request, "QUIT") &&
        !qihse_resp_command_is(request, "RESET")) {
        char buffer[256];
        size_t name_len = request->argv[0].len < 128u ? request->argv[0].len : 128u;
        int len = snprintf(buffer, sizeof(buffer),
                           "ERR Can't execute '%.*s': only (P|S)SUBSCRIBE / (P|S)UNSUBSCRIBE / PING / QUIT / RESET are allowed in this context",
                           (int)name_len, (const char*)request->argv[0].data);
        return len > 0 ? qihse_resp_error(session, buffer) : qihse_resp_error(session, "ERR command not allowed in subscribed mode");
    }
    /* U2 per-tenant quota enforcement (ann queries, ingest, kv writes) */
    if (!qihse_resp_tenant_quota(session, request, session_tenant)) return true;
    /* MULTI queueing: if in a transaction, queue all commands except EXEC/DISCARD/MULTI/WATCH/UNWATCH */
    if (session->in_multi &&
        !(dispatch_entry && (dispatch_entry->flags & DSP_MULTI_OK))) {
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
            bool is_write = (dispatch_entry && (dispatch_entry->flags & DSP_BUSY_WRITE)) ||
                            qihse_resp_command_is(request, "KEYSTONE.INGEST");
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
    if (qihse_resp_command_is(request, "CLUSTER") && request->argc >= 2 &&
        qihse_resp_arg_equal(&request->argv[1], "MOVESLOTS")) {
        /* Before the generic CLUSTER dispatch: MOVESLOTS needs store + bus. */
        return qihse_resp_handle_moveslots(session, request);
    }
    if (qihse_resp_command_is(request, "GROUP") && request->argc >= 2) {
        return qihse_resp_handle_group(session, request);
    }
    if (qihse_resp_command_is(request, "FEDERATION") && request->argc >= 2) {
        return qihse_resp_handle_federation(session, request);
    }
    if (qihse_resp_command_is(request, "FABRIC") && request->argc >= 2) {
        if (qihse_resp_arg_equal(&request->argv[1], "CAPS")) return qihse_resp_handle_fabric_caps(session);
        if (qihse_resp_arg_equal(&request->argv[1], "SUBMIT")) return qihse_resp_handle_fabric_submit(session, request);
        if (qihse_resp_arg_equal(&request->argv[1], "RESULT") && request->argc == 3) return qihse_resp_handle_fabric_result(session, request);
    }
    if (qihse_resp_command_is(request, "CLUSTER")) {
        qihse_resp_cluster_context_t context = { session->server->topology, qihse_resp_cluster_output, session };
        return qihse_resp_cluster_dispatch(&context, request->argc, request->argv);
    }
    if (qihse_resp_command_is(request, "CLIENT")) return qihse_resp_handle_client_command(session, request);
    if (qihse_resp_command_is(request, "COMMAND")) return qihse_resp_handle_command(session, request);
    if (qihse_resp_command_is(request, "INFO")) return qihse_resp_handle_info(session);
    if (qihse_resp_command_is(request, "METRICS.RENDER")) return qihse_resp_handle_metrics_render(session, request);
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

    /* U3 session-bundle delivery */
    if (qihse_resp_command_is(request, "BUNDLE.PREPARE")) return qihse_resp_handle_bundle_prepare(session, request);
    if (qihse_resp_command_is(request, "BUNDLE.CHUNK")) return qihse_resp_handle_bundle_chunk(session, request);

    /* KEYSTONE Ingestion and Semantic Extensions (Cluster Scoped) */
    if (qihse_resp_command_is(request, "KEYSTONE.INGEST")) return qihse_resp_handle_keystone_ingest(session, request);
    if (qihse_resp_command_is(request, "KEYSTONE.CLASSIFY")) return qihse_resp_handle_keystone_classify(session, request);
    /* W2.5: KEYSTONE change feed (read/index identity) */
    if (qihse_resp_command_is_keystone_feed(request)) return qihse_resp_handle_keystone_feed(session, request);

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
    qihse_resp_extract_keys(request, &keys, dispatch_entry);
    if (keys.count > 0 && !qihse_resp_tenant_scope(session, request, &keys, session_tenant)) return true;
    if (keys.count > 0 && !qihse_resp_ingest_gate(session, request, &keys)) return true;
    if (keys.count > 0 && !qihse_resp_route(session, request, &keys)) return true;

    if (dispatch_entry) return dispatch_entry->fn(session, request);
    return qihse_resp_error(session, "ERR unknown command");
}

static bool qihse_resp_session_loop(qihse_resp_server_t* server, int fd) {
    qihse_resp_session_t session;
    memset(&session, 0, sizeof(session));
    session.server = server;
    session.fd = fd;
    session.protocol_version = 2;
    /* W5.2: an error raised before the first command is classified must not
     * be attributed to query type 0 (GET). */
    session.query_type = QIHSE_QUERY_TYPE_OTHER;
    if (!server->auth_required) session.user = server->unauthenticated_user;
    if (pthread_mutex_init(&session.io_lock, NULL) != 0) return false;
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
    qihse_resp_session_pubsub_cleanup(&session);
    pthread_mutex_destroy(&session.io_lock);
    free(session.io_buf);
    free(buffer);
    return successful;
}

static void qihse_resp_remove_client(qihse_resp_client_ctx_t* client) {
    qihse_resp_server_t* server = client->server;
    pthread_mutex_lock(&server->state_lock);
    qihse_resp_client_ctx_t** cursor = &server->clients;
    while (*cursor && *cursor != client) cursor = &(*cursor)->next;
    shutdown(client->fd, SHUT_RDWR);
    close_socket(client->fd);
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

/* U6: background expiry sweeper — qihse_kv_sweep_expired previously had no
 * callers; this thread physically removes expired records on a fixed cadence. */
static void* qihse_resp_kv_sweeper_main(void* argument) {
    qihse_resp_server_t* server = (qihse_resp_server_t*)argument;
    while (!__atomic_load_n(&server->sweeper_shutdown, __ATOMIC_ACQUIRE)) {
        for (size_t i = 0; i < (size_t)server->kv_sweep_interval_seconds * 10u; i++) {
            if (__atomic_load_n(&server->sweeper_shutdown, __ATOMIC_ACQUIRE)) return NULL;
            struct timespec pause = { 0, 100 * 1000 * 1000L };
            nanosleep(&pause, NULL);
        }
        if (server->store) {
            pthread_rwlock_wrlock(&server->kv_lock);
            qihse_kv_sweep_expired(server->store);
            pthread_rwlock_unlock(&server->kv_lock);
        }
    }
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
    /* Pub/Sub + UWP bridge */
    config->pubsub_log_directory = NULL;
    config->channel_classification = 0;
    config->channel_sci = 0;
    config->enable_uwp_bridge = true;
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
    server->unauthenticated_user = qihse_auth_get_user(0);
    server->require_full_coverage = supplied->require_full_coverage;
    server->pin_workers = supplied->pin_workers;
    server->strict_hardware_affinity = supplied->strict_hardware_affinity;
    server->numa_node_id = supplied->numa_node_id;
    server->listen_fd = -1;
    server->channel_classification = supplied->channel_classification;
    server->channel_sci = supplied->channel_sci;
    server->enable_uwp_bridge = supplied->enable_uwp_bridge;
    server->quotas = supplied->quotas;
    server->blobs = supplied->blobs;
    server->metrics = qihse_metrics_create();
    if (server->metrics) {
        qihse_metrics_register(server->metrics, "qihse_bundle_compose_total", "Session bundles composed", METRIC_COUNTER);
        qihse_metrics_register(server->metrics, "qihse_bundle_compose_latency_ms", "Bundle compose latency", METRIC_HISTOGRAM);
        qihse_metrics_register(server->metrics, "qihse_bundle_delta_hits", "Blobs already held by clients (delta)", METRIC_COUNTER);
        qihse_metrics_register(server->metrics, "qihse_ingest_rejected_total", "Telemetry records rejected by the ingest guard", METRIC_COUNTER);
        qihse_metrics_register(server->metrics, "qihse_killswitch_push_total", "Killswitch edges fanned out", METRIC_COUNTER);
        qihse_metrics_register(server->metrics, "qihse_quota_rejected_total", "Operations rejected by tenant quotas", METRIC_COUNTER);
        /* W5.2: label-bounded families + status gauges.  Registered here, so
         * every value set is fixed before the first request is served. */
        qihse_resp_telemetry_register(server);
    }
    if (supplied->blobs) {
        server->composer = qihse_bundle_composer_create(supplied->blobs, server->store,
                                                        supplied->bundle_keys_dir,
                                                        supplied->bundle_dsa_private_key_path);
        server->owns_composer = server->composer != NULL;
    }
    server->pubsub = qihse_resp_pubsub_create(supplied->pubsub_log_directory);
    if (!server->pubsub) {
        free(server);
        errno = ENOMEM;
        return NULL;
    }
    qihse_resp_pubsub_set_policy(server->pubsub, server->channel_classification, server->channel_sci);
    if (supplied->enable_killswitch_channel) {
        qihse_resp_pubsub_set_channel_policy(server->pubsub, "killswitch", sizeof("killswitch") - 1u,
                                             0, 0, true);
    }
    server->kv_sweep_interval_seconds = supplied->kv_sweep_interval_seconds;
    server->cluster_migrate_password = supplied->cluster_migrate_password;
    server->redundancy_peer = supplied->redundancy_peer;
    server->redundancy_peer = supplied->redundancy_peer;
    if (server->kv_sweep_interval_seconds > 0 && server->store) {
        server->sweeper_shutdown = false;
        if (pthread_create(&server->sweeper_thread, NULL, qihse_resp_kv_sweeper_main, server) == 0) {
            server->sweeper_started = true;
        }
    }
    if (!qihse_resp_copy_string(server->bind_address, sizeof(server->bind_address), bind_address) ||
        !qihse_resp_copy_string(server->advertise_address, sizeof(server->advertise_address), advertise_address)) {
        free(server);
        errno = ENAMETOOLONG;
        return NULL;
    }
    if (pthread_mutex_init(&server->state_lock, NULL) != 0 || pthread_cond_init(&server->clients_drained, NULL) != 0 ||
        pthread_rwlock_init(&server->kv_lock, NULL) != 0 || pthread_mutex_init(&server->vdb_lock, NULL) != 0 ||
        pthread_mutex_init(&server->tsdb_lock, NULL) != 0 || pthread_mutex_init(&server->column_lock, NULL) != 0 ||
        pthread_mutex_init(&server->group_lock, NULL) != 0 ||
        pthread_mutex_init(&server->federation_lock, NULL) != 0) {
        free(server);
        errno = ENOMEM;
        return NULL;
    }
    server->topology = supplied->topology;
    if (!server->topology) {
        server->topology = qihse_cluster_topology_create();
        server->owns_topology = true;
    }
    qihse_hlc_init(&server->group_clock);
    /* F1: derive a stable federation UUID from the configured cluster node id
     * (or a default seed) and initialize the federation status snapshot. */
    {
        const char* seed = supplied->node_id ? supplied->node_id : "qihse-federation-default";
        qihse_uuid_from_seed(seed, strlen(seed), &server->federation_node_id);
        qihse_federation_status_init(&server->federation_status, &server->federation_node_id);
    }
    /* F2: open the federation event journal if a directory was configured. */
    if (supplied->federation_journal_directory) {
        server->federation_journal = qihse_federation_journal_open(
            supplied->federation_journal_directory,
            supplied->federation_journal_durability);
    }
    /* F5: node identity key directory. Copied so the caller's buffer may be
     * transient. NULL leaves enrollment via RESP disabled. */
    if (supplied->federation_key_directory) {
        size_t n = strlen(supplied->federation_key_directory);
        server->federation_key_directory = (char*)malloc(n + 1u);
        if (!server->federation_key_directory) {
            qihse_resp_server_destroy(server);
            return NULL;
        }
        memcpy(server->federation_key_directory, supplied->federation_key_directory, n + 1u);
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
        bus_cfg.veil_key = supplied->veil_key;
        server->bus = qihse_cluster_bus_create(&bus_cfg);
        server->owns_bus = server->bus != NULL;
        qihse_resp_group_wire_bus(server, server->bus);
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
            re_cfg.veil_key = supplied->veil_key;
            re_cfg.on_fail = qihse_cluster_failover_on_fail_cb;
            re_cfg.on_fail_user_data = server->failover;
            qihse_cluster_bus_destroy(server->bus);
            server->bus = qihse_cluster_bus_create(&re_cfg);
            server->owns_bus = server->bus != NULL;
            qihse_resp_group_wire_bus(server, server->bus);
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
    /* Phase 3: start cluster bus if present (mirrors qihse_resp_server_start;
     * run() previously never started the bus, silently disabling clustering
     * for run()-only deployments). */
    if (server->bus) qihse_cluster_bus_start(server->bus);
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
    if (server->listen_fd >= 0) shutdown(server->listen_fd, SHUT_RDWR);
    for (qihse_resp_client_ctx_t* client = server->clients; client; client = client->next) shutdown(client->fd, SHUT_RDWR);
    if (server->accept_thread_started) {
        accept_thread = server->accept_thread;
        server->accept_thread_started = false;
        join_accept = !pthread_equal(pthread_self(), accept_thread);
    }
    pthread_mutex_unlock(&server->state_lock);
    if (join_accept) pthread_join(accept_thread, NULL);
    pthread_mutex_lock(&server->state_lock);
    if (server->listen_fd >= 0) {
        close_socket(server->listen_fd);
        server->listen_fd = -1;
    }
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
    if (server->sweeper_started) {
        __atomic_store_n(&server->sweeper_shutdown, true, __ATOMIC_RELEASE);
        pthread_join(server->sweeper_thread, NULL);
        server->sweeper_started = false;
    }
    if (server->metrics) qihse_metrics_destroy(server->metrics);
    if (server->owns_composer && server->composer) qihse_bundle_composer_destroy(server->composer);
    if (server->owns_topology) qihse_cluster_topology_destroy(server->topology);
    if (server->pubsub) qihse_resp_pubsub_destroy(server->pubsub);
    pthread_mutex_destroy(&server->column_lock);
    pthread_mutex_destroy(&server->tsdb_lock);
    pthread_mutex_destroy(&server->vdb_lock);
    pthread_rwlock_destroy(&server->kv_lock);
    pthread_cond_destroy(&server->clients_drained);
    pthread_mutex_destroy(&server->state_lock);
    pthread_mutex_destroy(&server->group_lock);
    pthread_mutex_destroy(&server->federation_lock);
    if (server->federation_journal) {
        qihse_federation_journal_destroy(server->federation_journal);
        server->federation_journal = NULL;
    }
    free(server->federation_key_directory);
    free(server);
}

uint16_t qihse_resp_server_port(const qihse_resp_server_t* server) {
    return server ? server->port : 0u;
}

qihse_cluster_topology_t* qihse_resp_server_topology(qihse_resp_server_t* server) {
    return server ? server->topology : NULL;
}

qihse_kv_store_t* qihse_resp_server_store(qihse_resp_server_t* server) {
    return server ? server->store : NULL;
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

bool qihse_resp_server_execute(qihse_resp_server_t* server, qihse_user_t* user,
                               size_t argc, const qihse_resp_arg_t* argv,
                               uint8_t** out_reply, size_t* out_reply_len) {
    if (!server || !user || !argv || argc == 0 || argc > QIHSE_RESP_MAX_ARGS || !out_reply || !out_reply_len) {
        errno = EINVAL;
        return false;
    }
    if (!server->enable_uwp_bridge) {
        errno = EACCES;
        return false;
    }
    qihse_resp_session_t session;
    memset(&session, 0, sizeof(session));
    session.server = server;
    session.user = user;
    session.query_type = QIHSE_QUERY_TYPE_OTHER;
    session.fd = -1;
    session.protocol_version = 2;
    qihse_resp_request_t request;
    memset(&request, 0, sizeof(request));
    request.argc = argc;
    for (size_t i = 0; i < argc; i++) request.argv[i] = argv[i];
    request.consumed = argc;
    session.io_cap = 4096u;
    session.io_buf = malloc(session.io_cap);
    if (!session.io_buf) {
        errno = ENOMEM;
        return false;
    }
    bool keep_open = true;
    if (!qihse_resp_dispatch(&session, &request, &keep_open)) {
        free(session.io_buf);
        return false;
    }
    *out_reply = session.io_buf;
    *out_reply_len = session.io_len;
    return true;
}
