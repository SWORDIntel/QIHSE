/* qihse-cluster-daemon — run one QIHSE RESP node of a multi-machine cluster.
 *
 * Unlike tests/qihse_cluster_node.c (three hardcoded localhost nodes), this
 * daemon takes an explicit topology so real hosts can form a cluster:
 *
 *   qihse-cluster-daemon \
 *       --index 0 --bind 192.168.1.91 --port 7100 --bus-port 17100 \
 *       --slot-range 0-8191 \
 *       --node 0:192.168.1.91:7100:17100 \
 *       --node 1:192.168.1.95:7101:17101 \
 *       --slot-range-of 1:8192-16383 \
 *       --operator-password "…" [--dir /opt/qihse-data] [--enable-scatter]
 *
 * Every node must be given the same --node list (the topology is a
 * config-time artifact; the UDP cluster bus on the bus ports carries
 * gossip/failover at runtime). Slots not explicitly assigned default to the
 * local node only when it is the sole node of the cluster.
 *
 * Build: make cluster-daemon
 */
#include "qihse_resp_wire.h"
#include "qihse_auth.h"
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_brain.h"
#include "qihse_overlay.h"
#include "qihse_kv_store.h"
#include "qihse_fts.h"
#include "qihse_qkp.h"
#include "qihse_machine_auth.h"
#include "qihse_platform.h"
#include <netdb.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_PEERS 64u

typedef struct {
    unsigned int index;
    char host[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t port;
    uint16_t bus_port;
    bool has_slots;
    uint16_t slot_first;
    uint16_t slot_last;
} peer_spec_t;

/* Recursive mkdir -p (parents must be writable). */
static bool mkdirs(const char* path) {
    if (!path || !*path) return false;
    char copy[600];
    snprintf(copy, sizeof(copy), "%s", path);
    size_t len = strlen(copy);
    if (len && copy[len - 1u] == '/') copy[len - 1u] = '\0';
    for (char* p = copy + 1u; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0700) != 0 && errno != EEXIST) return false;
            *p = '/';
        }
    }
    if (mkdir(copy, 0700) != 0 && errno != EEXIST) return false;
    return true;
}

/* Deterministic node identity: the same host:port must mint the same id on
 * every machine that describes the topology, or the nodes will not recognize
 * each other. */
static void fill_node(const char* host, uint16_t port, uint16_t bus_port,
                      qihse_cluster_node_t* node) {
    memset(node, 0, sizeof(*node));
    char seed[QIHSE_CLUSTER_HOST_LEN + 16u];
    int len = snprintf(seed, sizeof(seed), "qihse-node-%s:%u", host, port);
    qihse_cluster_node_id_from_seed(seed, len > 0 ? (size_t)len : 0u, node->id);
    snprintf(node->host, sizeof(node->host), "%s", host);
    node->port = port;
    node->bus_port = bus_port;
    node->role = QIHSE_CLUSTER_NODE_PRIMARY;
    node->primary_index = QIHSE_CLUSTER_NODE_NONE;
    node->healthy = true;
}

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static bool parse_u16(const char* s, uint16_t* out) {
    if (!s || !*s) return false;
    char* end = NULL;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v > UINT16_MAX) return false;
    *out = (uint16_t)v;
    return true;
}

/* "first-last" (inclusive); "N" means the single slot N. */
static bool parse_slot_range(const char* s, uint16_t* first, uint16_t* last) {
    if (!s || !*s) return false;
    char* dash = strchr(s, '-');
    if (!dash) return parse_u16(s, first) && (*last = *first, true);
    char first_buf[16];
    size_t n = (size_t)(dash - s);
    if (n == 0 || n >= sizeof(first_buf)) return false;
    memcpy(first_buf, s, n);
    first_buf[n] = '\0';
    return parse_u16(first_buf, first) && parse_u16(dash + 1, last) && *first <= *last;
}

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s --index N --bind ADDR --port P --bus-port B\n"
        "          (--node INDEX:HOST:PORT:BUS-PORT [--node …] | --join HOST:BUS-PORT [--join …])\n"
        "          [--slot-range FIRST-LAST] [--slot-range-of INDEX:FIRST-LAST]\n"
        "          [--operator-password PW] [--dir DIR] [--enable-scatter]\n"
        "          (the operator password also keys the veiled bus framing;\n"
        "           every cluster node must use the same password)\n"
        "          [--node-key PATH] [--require-signed-ops]\n"
 "          (signed ops frames: SLOT/NODE/GROUP updates carry ML-DSA\n"
 "           signatures; require-signed-ops refuses unsigned ones)\n"
 "          [--brain] [--brain-act] [--brain-dir DIR] [--brain-interval S] [--brain-dsa-key PATH]\n"
        "          [--brain-cooldown S] [--brain-rollback-window S]\n"
        "          [--brain-prune-timeout S] [--brain-rebalance-min-slots N]\n"
        "          [--brain-fed-dir DIR] [--brain-node-key PATH]\n"
        "          [--redundancy-peer HOST:PORT]\n"
        "          [--max-clients N]\n"
        "          (each daemon owns an in-memory BM25 index over its local KV:\n"
        "           FTS.BUILD <pattern> indexes matching keys, FTS.SEARCH <query>\n"
        "           [limit] replies [key, score, ...]; the index resets on restart)\n"
        "\n  --join sends MEET frames to a seed node's bus port; membership is\n"
        "  learned dynamically over the cluster bus (gossip). Without --join, the\n"
        "  static --node list defines the topology.\n"
        "\n  --brain-fed-dir is the federation event journal the brain publishes\n"
        "  observations and signed decisions to (default: --brain-dir); the brain\n"
        "  refuses to act when that journal is unavailable. --brain-node-key is the\n"
        "  node identity key that signs decisions (default: --brain-dsa-key).\n"
        "\n  --brain observes and journals always; --brain-act additionally re-homes\n"
        "  a failed owner's range to a healthy target (evidence-gated) and rolls\n"
        "  it back if the move did not complete or the target failed within\n"
        "  --brain-rollback-window seconds.\n"
        "\n  --replicate GLOB marks a sovereign-local namespace.\n"
        "  --replication-source-host DEST --replication-source-port PORT\n"
        "  enables one-way QKP-protected I2P pull through local SOCKS\n"
        "  (--replication-socks-port, default 4447); requires --replica-read-only.\n"
        "  --replication-peer-node-id and --replication-peer-dsa-pub pin the\n"
        "  sole upstream identity; --pqc-node-id sets this daemon's stable ID.\n",
        argv0);
}

/* ── One-way, QKP-protected I2P replication puller ───────────────────────── */
#define REPL_AE_MAX_KEYS 10000u
#define REPL_AE_GLOBS_MAX 64u
#define REPL_AE_VALUE_MAX (16u * 1024u * 1024u)

typedef struct {
    int fd;
    char err[256];
    char last[128]; /* most recent simple (+/-) reply line */
    /* QKP1 may return one plaintext record up to QIHSE_QKP_MAX_PAYLOAD. */
    unsigned char buf[QIHSE_QKP_MAX_PAYLOAD];
    size_t buf_len;
    size_t buf_pos;
    qihse_qkp_session_t* qkp; /* anti-entropy RESP always runs inside QKP1 */
    qihse_qkp_config_t qkp_config; /* borrowed paths/anchors live for daemon lifetime */
} mini_resp_t;

static bool mini_resp_command(mini_resp_t* c, size_t argc, const char* const* argv);
static void mini_resp_close(mini_resp_t* c);

static bool socket_send_all(int fd, const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    while (len) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n; len -= (size_t)n;
    }
    return true;
}

static bool socket_recv_all(int fd, void* data, size_t len) {
    unsigned char* p = (unsigned char*)data;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += (size_t)n; len -= (size_t)n;
    }
    return true;
}

/* Connect to an I2P destination only through the local i2pd SOCKS5 proxy.
 * The proxy address is deliberately loopback-only; there is no direct-host
 * fallback if SOCKS negotiation or remote-name resolution fails. */
static int connect_i2p_socks5(const char* host, uint16_t port, uint16_t socks_port) {
    if (!host || !*host || strlen(host) > 255u || socks_port == 0u) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in proxy;
    memset(&proxy, 0, sizeof(proxy));
    proxy.sin_family = AF_INET;
    proxy.sin_port = htons(socks_port);
    proxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr*)&proxy, sizeof(proxy)) != 0) { close(fd); return -1; }

    const uint8_t greeting[] = {0x05u, 0x01u, 0x00u};
    uint8_t reply[4];
    if (!socket_send_all(fd, greeting, sizeof(greeting)) || !socket_recv_all(fd, reply, 2u) ||
        reply[0] != 0x05u || reply[1] != 0x00u) { close(fd); return -1; }
    uint8_t request[4u + 1u + 255u + 2u];
    size_t host_len = strlen(host);
    request[0] = 0x05u; request[1] = 0x01u; request[2] = 0x00u; request[3] = 0x03u;
    request[4] = (uint8_t)host_len;
    memcpy(request + 5u, host, host_len);
    request[5u + host_len] = (uint8_t)(port >> 8);
    request[6u + host_len] = (uint8_t)port;
    if (!socket_send_all(fd, request, 7u + host_len) || !socket_recv_all(fd, reply, sizeof(reply)) ||
        reply[0] != 0x05u || reply[1] != 0x00u || reply[2] != 0x00u) { close(fd); return -1; }
    size_t bound_len = 0u;
    if (reply[3] == 0x01u) bound_len = 4u;
    else if (reply[3] == 0x04u) bound_len = 16u;
    else if (reply[3] == 0x03u) {
        uint8_t n = 0u;
        if (!socket_recv_all(fd, &n, 1u)) { close(fd); return -1; }
        bound_len = n;
    } else { close(fd); return -1; }
    uint8_t discard[16u + 2u];
    if (bound_len > sizeof(discard) - 2u ||
        !socket_recv_all(fd, discard, bound_len + 2u)) { close(fd); return -1; }
    return fd;
}

static int mini_resp_connect_mode(mini_resp_t* c, const char* host, uint16_t port,
                                  const qihse_qkp_config_t* qkp,
                                  bool via_i2p, uint16_t socks_port) {
    if (!c || !qkp || !qkp->dsa_key_path || !qkp->trusted_pubs || qkp->trusted_count == 0u) return -1;
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->qkp_config = *qkp;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int fd = -1;
    if (via_i2p) {
        fd = connect_i2p_socks5(host, port, socks_port);
    } else {
        if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd >= 0) {
            struct timeval tv = {5, 0};
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) { close(fd); fd = -1; }
        }
        freeaddrinfo(res);
    }
    if (fd < 0) return -1;
    c->fd = fd;
    /* No cleartext fallback: the auth secret and every subsequent command
     * must be protected by the daemon's signed, mutually authenticated QKP1
     * session. */
    if (qihse_qkp_client_negotiate(fd, &c->qkp_config, &c->qkp) != QIHSE_QKP_SECURE || !c->qkp) {
        close(fd);
        c->fd = -1;
        return -1;
    }
    return fd;
}

static int mini_resp_connect_i2p(mini_resp_t* c, const char* destination, uint16_t port,
                                 uint16_t socks_port, const qihse_qkp_config_t* qkp) {
    return mini_resp_connect_mode(c, destination, port, qkp, true, socks_port);
}

static bool mini_resp_auth(mini_resp_t* c, const char* password) {
    if (!password || !*password) return false;
    const char* argv[2] = {"AUTH", password};
    return mini_resp_command(c, 2u, argv);
}

static void mini_resp_close(mini_resp_t* c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    qihse_qkp_session_free(c->qkp);
    c->qkp = NULL;
}

static bool mini_resp_write(mini_resp_t* c, const void* data, size_t len) {
    if (!c || c->fd < 0 || !c->qkp || (!data && len != 0u)) return false;
    return qihse_qkp_send_sealed(c->qkp, c->fd, data, len);
}

static ssize_t mini_resp_read(mini_resp_t* c, void* data, size_t cap) {
    if (!c || c->fd < 0 || !c->qkp || !data || cap == 0u) return -1;
    return qihse_qkp_recv_sealed(c->qkp, c->fd, (uint8_t*)data, cap);
}

static bool mini_resp_send(mini_resp_t* c, size_t argc, const char* const* argv) {
    char head[64];
    int len = snprintf(head, sizeof(head), "*%zu\r\n", argc);
    if (len <= 0 || (size_t)len >= sizeof(head) || !mini_resp_write(c, head, (size_t)len)) return false;
    for (size_t i = 0; i < argc; i++) {
        size_t alen = strlen(argv[i]);
        len = snprintf(head, sizeof(head), "$%zu\r\n", alen);
        if (len <= 0 || (size_t)len >= sizeof(head) || !mini_resp_write(c, head, (size_t)len)) return false;
        if (!mini_resp_write(c, argv[i], alen) || !mini_resp_write(c, "\r\n", 2u)) return false;
    }
    return true;
}

static int mini_resp_read_line(mini_resp_t* c, char* buf, size_t cap) {
    size_t used = 0;
    while (used + 1u < cap) {
        if (c->buf_pos >= c->buf_len) {
            ssize_t r = mini_resp_read(c, c->buf, sizeof(c->buf));
            if (r <= 0) return -1;
            c->buf_len = (size_t)r;
            c->buf_pos = 0;
        }
        char ch = (char)c->buf[c->buf_pos++];
        if (ch == '\n') {
            if (used == 0u || buf[used - 1u] != '\r') return -1;
            used--;
            buf[used] = '\0';
            return (int)used;
        }
        if (ch == '\r') return -1;
        buf[used++] = ch;
    }
    return -1;
}

/* Buffered bulk read into caller memory (used for value payloads). */
static bool mini_resp_read_exact(mini_resp_t* c, char* out, size_t len) {
    size_t got = 0;
    while (got < len) {
        if (c->buf_pos < c->buf_len) {
            size_t take = c->buf_len - c->buf_pos;
            if (take > len - got) take = len - got;
            memcpy(out + got, c->buf + c->buf_pos, take);
            c->buf_pos += take;
            got += take;
            continue;
        }
        ssize_t r = mini_resp_read(c, c->buf, sizeof(c->buf));
        if (r <= 0) return false;
        c->buf_len = (size_t)r;
        c->buf_pos = 0;
    }
    return true;
}

/* Execute a command. Replies:
 *   MINI_REP_SIMPLE: +line (buf holds payload) or -line (buf holds error)
 *   MINI_REP_BULK:   out_value = malloc'd string (NULL for nil)
 *   MINI_REP_ARRAY:  out_items/out_count = malloc'd array of malloc'd strings
 *   MINI_REP_ERROR:  transport/protocol failure (c->err set) */
#define MINI_REP_SIMPLE 1
#define MINI_REP_BULK   2
#define MINI_REP_ARRAY  3
#define MINI_REP_ERROR  4

static void mini_resp_free_array(char** items, size_t count) {
    if (!items) return;
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

static int mini_resp_do(mini_resp_t* c, size_t argc, const char* const* argv,
                        char** out_value, char*** out_items, size_t* out_count) {
    if (out_value) *out_value = NULL;
    if (out_items) *out_items = NULL;
    if (out_count) *out_count = 0;
    if (!mini_resp_send(c, argc, argv)) {
        snprintf(c->err, sizeof(c->err), "send failed");
        return MINI_REP_ERROR;
    }
    char line[128];
    if (mini_resp_read_line(c, line, sizeof(line)) < 0) {
        snprintf(c->err, sizeof(c->err), "read failed");
        return MINI_REP_ERROR;
    }
    if (line[0] == '+' || line[0] == '-') {
        snprintf(c->last, sizeof(c->last), "%s", line);
        return MINI_REP_SIMPLE;
    }
    if (line[0] == '$') {
        if (!out_value) return MINI_REP_BULK;
        long long len = strtoll(line + 1, NULL, 10);
        if (len < 0) return MINI_REP_BULK; /* nil */
        if (len > (16 << 20)) { snprintf(c->err, sizeof(c->err), "reply too large"); return MINI_REP_ERROR; }
        char* v = malloc((size_t)len + 1u);
        if (!v) { snprintf(c->err, sizeof(c->err), "oom"); return MINI_REP_ERROR; }
        if (!mini_resp_read_exact(c, v, (size_t)len)) {
            free(v); snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
        }
        char tail[2];
        if (!mini_resp_read_exact(c, tail, 2u) || tail[0] != '\r' || tail[1] != '\n') {
            free(v); snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
        }
        v[len] = '\0';
        *out_value = v;
        return MINI_REP_BULK;
    }
    if (line[0] == '*' && out_items && out_count) {
        long long count = strtoll(line + 1, NULL, 10);
        if (count < 0 || count > 100000) { snprintf(c->err, sizeof(c->err), "bad array"); return MINI_REP_ERROR; }
        char** items = calloc(count ? (size_t)count : 1u, sizeof(char*));
        if (!items) { snprintf(c->err, sizeof(c->err), "oom"); return MINI_REP_ERROR; }
        for (long long i = 0; i < count; i++) {
            char sub[64];
            if (mini_resp_read_line(c, sub, sizeof(sub)) < 0 || sub[0] != '$') {
                mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "bad array item");
                return MINI_REP_ERROR;
            }
            long long len = strtoll(sub + 1, NULL, 10);
            if (len < 0 || len > REPL_AE_VALUE_MAX) {
                mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "bad item length");
                return MINI_REP_ERROR;
            }
            items[i] = malloc((size_t)len + 1u);
            if (!items[i]) { mini_resp_free_array(items, (size_t)i); snprintf(c->err, sizeof(c->err), "oom"); return MINI_REP_ERROR; }
            if (!mini_resp_read_exact(c, items[i], (size_t)len)) {
                free(items[i]); mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
            }
            items[i][len] = '\0';
            char tail[2];
            if (!mini_resp_read_exact(c, tail, 2u) || tail[0] != '\r' || tail[1] != '\n') {
                free(items[i]); mini_resp_free_array(items, (size_t)i);
                snprintf(c->err, sizeof(c->err), "truncated"); return MINI_REP_ERROR;
            }
        }
        *out_items = items;
        *out_count = (size_t)count;
        return MINI_REP_ARRAY;
    }
    snprintf(c->err, sizeof(c->err), "unexpected reply");
    return MINI_REP_ERROR;
}

/* Fire-and-verify form for AUTH/SET: true on +OK. */
static bool mini_resp_command(mini_resp_t* c, size_t argc, const char* const* argv) {
    return mini_resp_do(c, argc, argv, NULL, NULL, NULL) == MINI_REP_SIMPLE && c->last[0] == '+';
}

typedef struct {
    qihse_resp_server_t* server;
    const peer_spec_t* peers;
    size_t peer_count;
    unsigned int self_index;
    const char* password;      /* operator password (borrowed) */
    const char* self_host;     /* bind address for loopback */
    uint16_t self_port;
    const char* source_host;   /* operator-only I2P destination */
    uint16_t source_port;
    uint16_t socks_port;       /* local loopback i2pd SOCKS5 */
    qihse_user_t* replica_principal;
    const qihse_qkp_config_t* qkp; /* required signed/sealed peer transport */
    const char* data_dir;
    uint32_t interval_seconds;
    volatile sig_atomic_t* stop;
} ae_ctx_t;

static bool parse_u64_decimal(const char* text, uint64_t* value) {
    if (!text || !*text || !value) return false;
    for (const unsigned char* p = (const unsigned char*)text; *p; p++)
        if (*p < '0' || *p > '9') return false;
    errno = 0; char* end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || !end || *end) return false;
    *value = (uint64_t)parsed;
    return true;
}

static bool fd_write_all(int fd, const char* data, size_t len) {
    size_t done = 0u;
    while (done < len) {
        ssize_t n = write(fd, data + done, len - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool replica_snapshot_pull(ae_ctx_t* ae, mini_resp_t* source, const char* glob) {
    const char* begin_argv[3] = {"REPL.SNAPSHOT.BEGIN", glob, NULL};
    char** manifest = NULL; size_t manifest_count = 0u;
    int reply = mini_resp_do(source, 2u, begin_argv, NULL, &manifest, &manifest_count);
    uint64_t snapshot_size = 0u, source_seq = 0u;
    bool ok = reply == MINI_REP_ARRAY && manifest_count == 2u &&
        parse_u64_decimal(manifest[0], &snapshot_size) &&
        parse_u64_decimal(manifest[1], &source_seq) && snapshot_size <= (uint64_t)INT64_MAX;
    mini_resp_free_array(manifest, manifest_count);
    if (!ok) return false;

    const char* dir = ae->data_dir;
    if (!dir || !*dir) dir = getenv("QIHSE_DATA_DIR");
    if (!dir || !*dir) {
        if (access("/opt/qihse-data", R_OK | W_OK) == 0) dir = "/opt/qihse-data";
        else if (access("/var/lib/qihse", R_OK | W_OK) == 0) dir = "/var/lib/qihse";
        else dir = "/opt/qihse-data";
    }
    if (!mkdirs(dir)) {
        const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
        (void)mini_resp_command(source, 1u, end_argv);
        return false;
    }
    char incoming[4096];
    int path_len = snprintf(incoming, sizeof(incoming), "%s%sqihse-repl-snapshot-XXXXXX",
        dir, dir[strlen(dir) - 1u] == '/' ? "" : "/");
    if (path_len <= 0 || (size_t)path_len >= sizeof(incoming)) return false;
    int fd = mkstemp(incoming);
    if (fd < 0) {
        const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
        (void)mini_resp_command(source, 1u, end_argv);
        return false;
    }
    if (fchmod(fd, 0600) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        close(fd); (void)unlink(incoming);
        const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
        (void)mini_resp_command(source, 1u, end_argv);
        return false;
    }
    uint64_t offset = 0u;
    while (ok && offset < snapshot_size) {
        uint64_t request_len = snapshot_size - offset;
        if (request_len > REPL_AE_VALUE_MAX) request_len = REPL_AE_VALUE_MAX;
        char offset_buf[32], len_buf[32];
        snprintf(offset_buf, sizeof(offset_buf), "%llu", (unsigned long long)offset);
        snprintf(len_buf, sizeof(len_buf), "%llu", (unsigned long long)request_len);
        const char* read_argv[3] = {"REPL.SNAPSHOT.READ", offset_buf, len_buf};
        char* chunk = NULL;
        reply = mini_resp_do(source, 3u, read_argv, &chunk, NULL, NULL);
        ok = reply == MINI_REP_BULK && chunk && strlen(chunk) == (size_t)request_len &&
             fd_write_all(fd, chunk, (size_t)request_len);
        free(chunk);
        if (ok) offset += request_len;
    }
    if (ok && fsync(fd) != 0) ok = false;
    if (close(fd) != 0) ok = false;
    if (ok) ok = qihse_resp_server_repl_snapshot_install_local(ae->server, source->qkp,
        glob, incoming, source_seq, ae->replica_principal);
    (void)unlink(incoming);
    const char* end_argv[1] = {"REPL.SNAPSHOT.END"};
    if (!mini_resp_command(source, 1u, end_argv)) ok = false;
    return ok;
}

static bool replica_pull_glob(ae_ctx_t* ae, mini_resp_t* source, const char* glob,
                              uint64_t* applied_total) {
    bool snapshot_installed = false;
    if (!qihse_resp_server_repl_snapshot_installed_local(ae->server, source->qkp,
            glob, ae->replica_principal, &snapshot_installed)) return false;
    if (!snapshot_installed && !replica_snapshot_pull(ae, source, glob)) return false;
    uint64_t cursor = 0u;
    if (!qihse_resp_server_repl_cursor_local(ae->server, source->qkp, glob,
            ae->replica_principal, &cursor)) return false;
    uint64_t start_cursor = cursor;
    while (!*ae->stop && *applied_total < REPL_AE_MAX_KEYS) {
        char since_buf[32];
        snprintf(since_buf, sizeof(since_buf), "%llu", (unsigned long long)cursor);
        /* One row keeps even a maximum-sized 16 MiB value within the
         * bounded RESP delta reply. */
        const char* argv[4] = {"REPL.DELTA", glob, since_buf, "1"};
        char** fields = NULL; size_t field_count = 0u;
        int reply = mini_resp_do(source, 4u, argv, NULL, &fields, &field_count);
        if (reply != MINI_REP_ARRAY || field_count < 2u) {
            mini_resp_free_array(fields, field_count);
            return false;
        }
        uint64_t page_cursor = 0u, row_count_u64 = 0u;
        bool valid = parse_u64_decimal(fields[0], &page_cursor) &&
                     parse_u64_decimal(fields[1], &row_count_u64) &&
                     row_count_u64 <= 1u && field_count == 2u + (size_t)row_count_u64 * 7u;
        if (!valid || page_cursor < cursor) {
            mini_resp_free_array(fields, field_count);
            return false;
        }
        if (row_count_u64 == 0u) {
            valid = page_cursor == cursor;
            mini_resp_free_array(fields, field_count);
            return valid;
        }
        uint64_t last_seq = cursor;
        for (size_t j = 0; valid && j < (size_t)row_count_u64; j++) {
            size_t base = 2u + j * 7u;
            uint64_t seq = 0u, class_u64 = 0u, sci_u64 = 0u, expiry = 0u;
            bool tombstone = strcmp(fields[base], "D") == 0;
            valid = (tombstone || strcmp(fields[base], "S") == 0) &&
                    parse_u64_decimal(fields[base + 1u], &seq) && seq > last_seq &&
                    parse_u64_decimal(fields[base + 2u], &class_u64) && class_u64 <= UINT16_MAX &&
                    parse_u64_decimal(fields[base + 3u], &sci_u64) && sci_u64 <= UINT16_MAX &&
                    parse_u64_decimal(fields[base + 4u], &expiry) && fields[base + 5u][0] != '\0' &&
                    fnmatch(glob, fields[base + 5u], 0) == 0 &&
                    (!tombstone || (fields[base + 6u][0] == '\0' && expiry == 0u));
            if (!valid) break;
            qihse_kv_replica_record_t record = {
                .key = fields[base + 5u], .value = tombstone ? NULL : fields[base + 6u],
                .change_seq = seq, .classification = (uint16_t)class_u64,
                .sci_compartment = (uint16_t)sci_u64, .expire_time_ms = expiry,
                .tombstone = tombstone
            };
            if (!qihse_resp_server_repl_apply_local(ae->server, source->qkp, glob,
                    &record, ae->replica_principal)) {
                valid = false;
                break;
            }
            last_seq = seq;
            (*applied_total)++;
        }
        if (valid && page_cursor != last_seq) valid = false;
        mini_resp_free_array(fields, field_count);
        if (!valid) return false;
        char ack_seq[32];
        snprintf(ack_seq, sizeof(ack_seq), "%llu", (unsigned long long)last_seq);
        const char* ack_argv[3] = {"REPL.ACK", glob, ack_seq};
        if (!mini_resp_command(source, 3u, ack_argv)) return false;
        cursor = last_seq;
        if (row_count_u64 == 0u) return true;
    }
    return cursor >= start_cursor;
}

static void* ae_main(void* argument) {
    ae_ctx_t* ae = (ae_ctx_t*)argument;
    while (!__atomic_load_n(ae->stop, __ATOMIC_ACQUIRE)) {
        for (uint32_t slept = 0; slept < ae->interval_seconds &&
             !__atomic_load_n(ae->stop, __ATOMIC_ACQUIRE); slept++) {
            struct timespec ts = {1, 0};
            nanosleep(&ts, NULL);
        }
        if (__atomic_load_n(ae->stop, __ATOMIC_ACQUIRE)) break;
        char globs[REPL_AE_GLOBS_MAX][128];
        size_t glob_count = qihse_resp_server_repl_list(ae->server, globs, NULL, REPL_AE_GLOBS_MAX);
        if (glob_count == 0u) continue;
        mini_resp_t source;
        int connected = mini_resp_connect_i2p(&source, ae->source_host, ae->source_port,
            ae->socks_port, ae->qkp);
        bool peer_ok = connected >= 0 && qihse_qkp_client_session_is_replication_peer(
            source.qkp, ae->qkp->replication_peer_node_id,
            ae->qkp->replication_peer_dsa_pub_path) && mini_resp_auth(&source, ae->password);
        if (!peer_ok) {
            if (connected >= 0) mini_resp_close(&source);
            for (size_t i = 0; i < glob_count; i++)
                qihse_resp_server_repl_note(ae->server, globs[i], ae->source_host,
                    0u, 0u, UINT64_MAX, UINT64_MAX, false);
            fprintf(stderr, "qihse-cluster-daemon: replica pull: I2P/QKP source connection or identity pin failed\n");
            continue;
        }
        uint64_t total = 0u;
        bool all_ok = true;
        for (size_t i = 0; i < glob_count && !*ae->stop && total < REPL_AE_MAX_KEYS; i++) {
            uint64_t before = total;
            bool ok = replica_pull_glob(ae, &source, globs[i], &total);
            qihse_resp_server_repl_note(ae->server, globs[i], ae->source_host,
                total - before, 0u, UINT64_MAX, UINT64_MAX, ok);
            if (!ok) { all_ok = false; break; }
        }
        mini_resp_close(&source);
        fprintf(stderr, "qihse-cluster-daemon: replica pull: %llu row(s) from pinned I2P source (%s)\n",
                (unsigned long long)total, all_ok ? "ok" : "stopped on error");
    }
    return NULL;
}

typedef struct {
    qihse_resp_server_t* server;
    char seeds[8][QIHSE_CLUSTER_HOST_LEN + 8u];
    size_t seed_count;
} join_ctx_t;

/* Dynamic join: once the bus is running, repeatedly MEET the seeds until the
 * topology contains at least one other node (or retries are exhausted). */
static void* join_main(void* argument) {
    join_ctx_t* j = (join_ctx_t*)argument;
    qihse_cluster_bus_t* bus = NULL;
    for (int wait = 0; wait < 40 && !bus; wait++) { /* bus starts with the server */
        bus = qihse_resp_server_bus(j->server);
        if (bus && qihse_cluster_bus_fd(bus) < 0) bus = NULL; /* not started yet */
        struct timespec ts = {0, 250 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    if (!bus) {
        fprintf(stderr, "qihse-cluster-daemon: bus never started; join failed\n");
        return NULL;
    }
    /* Retry indefinitely while the daemon lives: lossy/asymmetric paths
     * (WiFi, firewalled segments) can take far longer than a fixed window
     * to come up, and a node that stopped trying never joins. */
    for (int round = 0; ; round++) {
        for (size_t i = 0; i < j->seed_count; i++) {
            char spec[QIHSE_CLUSTER_HOST_LEN + 8u];
            snprintf(spec, sizeof(spec), "%s", j->seeds[i]);
            char* colon = strrchr(spec, ':');
            if (!colon) continue;
            *colon = '\0';
            char* end = NULL;
            unsigned long port = strtoul(colon + 1, &end, 10);
            if (end == colon + 1 || *end != '\0' || port == 0 || port > UINT16_MAX) continue;
            qihse_cluster_bus_meet(bus, spec, (uint16_t)port);
        }
        /* Joined = membership discovered AND slot map received (a joiner
         * without slots cannot route anything). */
        qihse_cluster_topology_t* topology =
            (qihse_cluster_topology_t*)qihse_resp_server_topology(j->server);
        qihse_cluster_node_t nodes[64];
        size_t count = qihse_cluster_topology_nodes(topology, nodes, 64);
        if (count > 1 && qihse_cluster_topology_is_covered(topology)) {
            fprintf(stderr, "qihse-cluster-daemon: joined cluster, %zu nodes discovered\n", count);
            return NULL;
        }
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
    }
}

int main(int argc, char** argv) {

    /* Signed ops frames (hybrid bus upgrade): load this node's ML-DSA
     * identity to sign SLOT/NODE/GROUP frames; optionally require
     * signatures from peers on receive. */
    const char* node_key_path = NULL;
    bool require_signed_ops = false;

    unsigned int self_index = 0;
    const char* bind = "127.0.0.1";
    uint16_t port = 7100, bus_port = 17100;
    const char* operator_password = NULL;
    const char* data_dir = NULL;
    bool enable_scatter = false;
    size_t max_clients = 4096u;
    peer_spec_t peers[MAX_PEERS];
    size_t peer_count = 0;
    /* Dynamic discovery seeds (--join HOST:BUSPORT). When present, the static
     * peer list is optional: membership is learned over the bus via MEET. */
    char seeds[8][QIHSE_CLUSTER_HOST_LEN + 8u];
    size_t seed_count = 0;
    bool self_has_slots = false;
    uint16_t self_slot_first = 0, self_slot_last = 0;
    bool brain_enabled = false, brain_act = false;
    const char* redundancy_peer = NULL;
    const char* irc_server = NULL;
    const char* irc_channel = NULL;
    const char* irc_nick_prefix = "qihse";
    const char* brain_dir = NULL;
    const char* brain_dsa_key = "/etc/qihse/keys/qihse_dsa_key.pem";
    const char* brain_fed_dir = NULL;   /* federation journal (default: brain_dir) */
    const char* brain_node_key = NULL;  /* decision signing key (default: brain_dsa_key) */
    uint32_t brain_interval = 5;
    uint32_t brain_cooldown = 30;         /* per-range re-home cooldown (seconds) */
    uint32_t brain_rollback_window = 60;  /* R4 evaluation window (seconds) */
    uint32_t brain_prune_timeout = 0;     /* stale-node prune (0 = disabled) */
    uint32_t brain_rebalance_min = 0;     /* rebalance-on-join threshold (0 = disabled) */
    char repl_globs[16][128];
    const char* repl_glob_ptrs[16];
    size_t repl_glob_count = 0;
    uint32_t repl_interval = 60;          /* anti-entropy tick (0 = disabled) */
    const char* pqc_identity_dir = NULL;  /* --pqc-identity-dir */
    const char* pqc_node_id = NULL;
    const char* replication_source_host = NULL;
    uint16_t replication_source_port = 0;
    uint16_t replication_socks_port = 4447;
    bool replica_read_only = false;
    const char* replication_peer_node_id = NULL;
    const char* replication_peer_dsa_pub = NULL;
    const char* pqc_trusted[16];
    size_t pqc_trusted_count = 0;
    bool pqc_require = false;
    bool pqc_degraded = false;            /* identity dir requested, keys missing */

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "--index") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v >= MAX_PEERS) return usage(argv[0]), 2;
            self_index = (unsigned int)v;
        } else if (strcmp(a, "--bind") == 0 && i + 1 < argc) {
            bind = argv[++i];
        } else if (strcmp(a, "--port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &port)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--node-key") == 0 && i + 1 < argc) {
            node_key_path = argv[++i];
        } else if (strcmp(a, "--require-signed-ops") == 0) {
            require_signed_ops = true;
        } else if (strcmp(a, "--bus-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &bus_port)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--operator-password") == 0 && i + 1 < argc) {
            operator_password = argv[++i];
        } else if (strcmp(a, "--dir") == 0 && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (strcmp(a, "--enable-scatter") == 0) {
            enable_scatter = true;
        } else if (strcmp(a, "--max-clients") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 65536u) return usage(argv[0]), 2;
            max_clients = v;
        } else if (strcmp(a, "--slot-range") == 0 && i + 1 < argc) {
            self_has_slots = parse_slot_range(argv[++i], &self_slot_first, &self_slot_last);
            if (!self_has_slots) return usage(argv[0]), 2;
        } else if (strcmp(a, "--redundancy-peer") == 0 && i + 1 < argc) {
            redundancy_peer = argv[++i];
        } else if (strcmp(a, "--irc-server") == 0 && i + 1 < argc) {
            irc_server = argv[++i];
        } else if (strcmp(a, "--irc-channel") == 0 && i + 1 < argc) {
            irc_channel = argv[++i];
        } else if (strcmp(a, "--irc-nick-prefix") == 0 && i + 1 < argc) {
            irc_nick_prefix = argv[++i];
        } else if (strcmp(a, "--brain") == 0) {
            brain_enabled = true;
        } else if (strcmp(a, "--brain-act") == 0) {
            brain_enabled = true;
            brain_act = true;
        } else if (strcmp(a, "--brain-dir") == 0 && i + 1 < argc) {
            brain_dir = argv[++i];
        } else if (strcmp(a, "--brain-interval") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 3600u) return usage(argv[0]), 2;
            brain_interval = (uint32_t)v;
        } else if (strcmp(a, "--brain-dsa-key") == 0 && i + 1 < argc) {
            brain_dsa_key = argv[++i];
        } else if (strcmp(a, "--brain-fed-dir") == 0 && i + 1 < argc) {
            brain_fed_dir = argv[++i];
        } else if (strcmp(a, "--brain-node-key") == 0 && i + 1 < argc) {
            brain_node_key = argv[++i];
        } else if (strcmp(a, "--brain-cooldown") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 86400u) return usage(argv[0]), 2;
            brain_cooldown = (uint32_t)v;
        } else if (strcmp(a, "--brain-rollback-window") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v == 0 || v > 86400u) return usage(argv[0]), 2;
            brain_rollback_window = (uint32_t)v;
        } else if (strcmp(a, "--brain-prune-timeout") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > 86400u) return usage(argv[0]), 2;
            brain_prune_timeout = (uint32_t)v;
        } else if (strcmp(a, "--brain-rebalance-min-slots") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > QIHSE_CLUSTER_SLOT_COUNT) return usage(argv[0]), 2;
            brain_rebalance_min = (uint32_t)v;
        } else if (strcmp(a, "--replicate") == 0 && i + 1 < argc) {
            if (repl_glob_count >= sizeof(repl_globs) / sizeof(repl_globs[0])) return usage(argv[0]), 2;
            if (strlen(argv[++i]) >= sizeof(repl_globs[0])) return usage(argv[0]), 2;
            snprintf(repl_globs[repl_glob_count], sizeof(repl_globs[0]), "%s", argv[i]);
            repl_glob_ptrs[repl_glob_count] = repl_globs[repl_glob_count];
            repl_glob_count++;
        } else if (strcmp(a, "--pqc-identity-dir") == 0 && i + 1 < argc) {
            pqc_identity_dir = argv[++i];
        } else if (strcmp(a, "--pqc-node-id") == 0 && i + 1 < argc) {
            pqc_node_id = argv[++i];
            if (!*pqc_node_id || strlen(pqc_node_id) > QIHSE_QKP_NODE_ID_LEN) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-source-host") == 0 && i + 1 < argc) {
            replication_source_host = argv[++i];
            if (!*replication_source_host || strlen(replication_source_host) > 255u) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-source-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &replication_source_port)) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-socks-port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &replication_socks_port) || replication_socks_port == 0u) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replica-read-only") == 0) {
            replica_read_only = true;
        } else if (strcmp(a, "--pqc-trusted-pub") == 0 && i + 1 < argc) {
            if (pqc_trusted_count >= sizeof(pqc_trusted) / sizeof(pqc_trusted[0])) return usage(argv[0]), 2;
            pqc_trusted[pqc_trusted_count++] = argv[++i];
        } else if (strcmp(a, "--replication-peer-node-id") == 0 && i + 1 < argc) {
            replication_peer_node_id = argv[++i];
            if (!*replication_peer_node_id || strlen(replication_peer_node_id) > QIHSE_QKP_NODE_ID_LEN) return usage(argv[0]), 2;
        } else if (strcmp(a, "--replication-peer-dsa-pub") == 0 && i + 1 < argc) {
            replication_peer_dsa_pub = argv[++i];
            if (!*replication_peer_dsa_pub) return usage(argv[0]), 2;
        } else if (strcmp(a, "--pqc-require") == 0) {
            pqc_require = true;
        } else if (strcmp(a, "--replicate-interval") == 0 && i + 1 < argc) {
            char* end = NULL; errno = 0;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (errno != 0 || !end || *end || v > 86400u) return usage(argv[0]), 2;
            repl_interval = (uint32_t)v;
        } else if (strcmp(a, "--join") == 0 && i + 1 < argc) {
            if (seed_count >= 8u) return usage(argv[0]), 2;
            snprintf(seeds[seed_count++], QIHSE_CLUSTER_HOST_LEN + 8u, "%s", argv[++i]);
        } else if (strcmp(a, "--node") == 0 && i + 1 < argc) {
            /* INDEX:HOST:PORT:BUS-PORT */
            char spec[512];
            snprintf(spec, sizeof(spec), "%s", argv[++i]);
            char* save = NULL;
            char* idx_s = strtok_r(spec, ":", &save);
            char* host = strtok_r(NULL, ":", &save);
            char* port_s = strtok_r(NULL, ":", &save);
            char* bus_s = strtok_r(NULL, ":", &save);
            unsigned long idx;
            if (!idx_s || !host || !port_s || !bus_s || peer_count >= MAX_PEERS) return usage(argv[0]), 2;
            char* end = NULL; errno = 0;
            idx = strtoul(idx_s, &end, 10);
            if (errno != 0 || !end || *end || idx >= MAX_PEERS) return usage(argv[0]), 2;
            peer_spec_t* p = &peers[peer_count++];
            p->index = (unsigned int)idx;
            snprintf(p->host, sizeof(p->host), "%s", host);
            if (!parse_u16(port_s, &p->port) || !parse_u16(bus_s, &p->bus_port)) return usage(argv[0]), 2;
            p->has_slots = false;
        } else if (strcmp(a, "--slot-range-of") == 0 && i + 1 < argc) {
            /* INDEX:FIRST-LAST */
            char spec[128];
            snprintf(spec, sizeof(spec), "%s", argv[++i]);
            char* colon = strchr(spec, ':');
            if (!colon || peer_count == 0) return usage(argv[0]), 2;
            *colon = '\0';
            char* end = NULL; errno = 0;
            unsigned long idx = strtoul(spec, &end, 10);
            if (errno != 0 || !end || *end || idx >= MAX_PEERS) return usage(argv[0]), 2;
            for (size_t k = peer_count; k > 0; k--) {
                if (peers[k - 1u].index == (unsigned int)idx) {
                    peers[k - 1u].has_slots =
                        parse_slot_range(colon + 1, &peers[k - 1u].slot_first, &peers[k - 1u].slot_last);
                    if (!peers[k - 1u].has_slots) return usage(argv[0]), 2;
                    break;
                }
            }
        } else {
            return usage(argv[0]), 2;
        }
    }

    const bool replication_configured = replication_source_host != NULL ||
        replication_peer_node_id != NULL || replication_peer_dsa_pub != NULL;
    if ((replication_source_host != NULL) != (replication_source_port != 0u)) {
        fprintf(stderr, "qihse-cluster-daemon: replication source host and port must be configured together\n");
        return 2;
    }
    if (replication_source_host) {
        size_t source_len = strlen(replication_source_host);
        if (source_len < 4u || strcasecmp(replication_source_host + source_len - 4u, ".i2p") != 0) {
            fprintf(stderr, "qihse-cluster-daemon: replication source must be an I2P destination name\n");
            return 2;
        }
    }

    /* Prefer a protected service environment over a command-line secret.
     * Keep --operator-password for interactive development, but production
     * systemd units should load QIHSE_OPERATOR_PASSWORD from a root-only
     * EnvironmentFile so it does not appear in process listings. */
    if (!operator_password) {
        const char* configured_password = getenv("QIHSE_OPERATOR_PASSWORD");
        if (configured_password && *configured_password) {
            operator_password = configured_password;
        }
    }

    if (replication_source_host && (!replica_read_only || repl_glob_count != 1u ||
            repl_interval == 0u || !operator_password || !replication_peer_node_id ||
            !replication_peer_dsa_pub || !pqc_node_id)) {
        fprintf(stderr, "qihse-cluster-daemon: I2P replica pull requires --replica-read-only, exactly one dedicated --replicate namespace, nonzero interval, operator password, stable --pqc-node-id, and a pinned upstream identity\n");
        return 2;
    }
    if (replication_configured && !pqc_node_id) {
        fprintf(stderr, "qihse-cluster-daemon: replication requires explicit stable --pqc-node-id\n");
        return 2;
    }
    if (replication_configured) pqc_require = true;

    if (data_dir && *data_dir) {
        if (!mkdirs(data_dir)) {
            fprintf(stderr, "qihse-cluster-daemon: cannot create data dir %s\n", data_dir);
            return 1;
        }
        setenv("QIHSE_DATA_DIR", data_dir, 1);
    }
    if (operator_password && strlen(operator_password) >= 12) {
        setenv("QIHSE_OPERATOR_PASSWORD", operator_password, 1);
    } else if (operator_password) {
        /* qihse_auth_bootstrap_operator() refuses passwords under 12 chars.
         * Continuing would enable auth_required with no usable verifier:
         * every AUTH would fail with WRONGPASS and nothing would say why. */
        fprintf(stderr, "qihse-cluster-daemon: --operator-password must be at least 12 characters\n");
        return 2;
    }
    if (!qihse_auth_init()) {
        fprintf(stderr, "qihse-cluster-daemon: auth init failed\n");
        return 1;
    }
    if (operator_password && strlen(operator_password) >= 12) {
        if (!qihse_auth_bootstrap_operator(operator_password)) {
            /* Already bootstrapped on a previous run: re-init with the
             * password in the environment so the operator verifier matches,
             * exactly as tools/qihse_federation_ca.c and
             * tools/qihse_redis_server.c do it. */
            setenv("QIHSE_OPERATOR_PASSWORD", operator_password, 1);
            if (!qihse_auth_init()) {
                fprintf(stderr, "qihse-cluster-daemon: auth re-init failed\n");
                return 1;
            }
        }
    }

    qihse_kv_store_t* store = qihse_kv_store_create();
    if (!store) {
        fprintf(stderr, "qihse-cluster-daemon: kv store create failed (data dir unusable?)\n");
        return 1;
    }
    if (replica_read_only && !qihse_kv_store_enable_replica_read_only(store)) {
        fprintf(stderr, "qihse-cluster-daemon: could not enable replica read-only fence\n");
        return 1;
    }
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    if (!topology) return 1;

    /* Insert every peer, then self (self also appears in --node for clarity). */
    uint16_t indexes[MAX_PEERS];
    memset(indexes, 0xFF, sizeof(indexes));
    for (size_t k = 0; k < peer_count; k++) {
        qihse_cluster_node_t node;
        fill_node(peers[k].host, peers[k].port, peers[k].bus_port, &node);
        uint16_t idx;
        if (!qihse_cluster_topology_upsert_node(topology, &node, &idx)) {
            fprintf(stderr, "qihse-cluster-daemon: upsert node %zu failed\n", k);
            return 1;
        }
        indexes[peers[k].index] = idx;
    }
    {
        qihse_cluster_node_t node;
        fill_node(bind, port, bus_port, &node);
        uint16_t idx;
        if (!qihse_cluster_topology_upsert_node(topology, &node, &idx)) return 1;
        if (indexes[self_index] == 0xFFFFu) indexes[self_index] = idx;
    }
    if (!qihse_cluster_topology_set_local_node(topology, indexes[self_index])) return 1;

    /* Slot assignment: explicit ranges; anything unassigned falls to self so a
     * single-node deployment owns all slots. */
    bool assigned_any_to_self = self_has_slots;
    for (size_t k = 0; k < peer_count; k++) {
        if (peers[k].index == self_index || !peers[k].has_slots) continue;
        if (!qihse_cluster_topology_assign_range(topology, peers[k].slot_first,
                                                 peers[k].slot_last, indexes[peers[k].index])) {
            fprintf(stderr, "qihse-cluster-daemon: slot assign for peer %zu failed\n", k);
            return 1;
        }
    }
    if (self_has_slots) {
        if (!qihse_cluster_topology_assign_range(topology, self_slot_first, self_slot_last,
                                                 indexes[self_index]))
            return 1;
    }
    /* A lone node owns every slot; a JOINER (has seeds) starts slotless and
     * learns ownership from the seed's slot announcements over the bus. */
    if (!assigned_any_to_self && peer_count == 0 && seed_count == 0) {
        if (!qihse_cluster_topology_assign_range(topology, 0u, QIHSE_CLUSTER_SLOT_COUNT - 1u,
                                                 indexes[self_index]))
            return 1;
    }

    /* R4c QKP1: resolve identity/trust from --pqc-* flags.
     *   --pqc-require            → identity + ≥1 trust anchor MUST exist,
     *                              otherwise refuse to start.
     *   opportunistic (default)  → missing keys ⇒ warn once, serve cleartext
     *                              (the pre-PQC warning spam disappears once
     *                              keys exist on the host). */
    qihse_qkp_config_t pqc;
    memset(&pqc, 0, sizeof(pqc));
    pqc.require = pqc_require;
    pqc.node_id = pqc_node_id ? pqc_node_id : bind;
    if ((replication_peer_node_id == NULL) != (replication_peer_dsa_pub == NULL)) {
        fprintf(stderr, "qihse-cluster-daemon: replication peer node id and DSA public key must be configured together\n");
        return 2;
    }
    pqc.replication_peer_node_id = replication_peer_node_id;
    pqc.replication_peer_dsa_pub_path = replication_peer_dsa_pub;
    static char pqc_dsa_key[512], pqc_kem_key[512], pqc_kem_pub[512];
    const char* pqc_dir = pqc_identity_dir ? pqc_identity_dir : "/etc/qihse/keys";
    snprintf(pqc_dsa_key, sizeof(pqc_dsa_key), "%s/qihse_dsa_key.pem", pqc_dir);
    snprintf(pqc_kem_key, sizeof(pqc_kem_key), "%s/qihse_kem_key.pem", pqc_dir);
    snprintf(pqc_kem_pub, sizeof(pqc_kem_pub), "%s/qihse_kem_pub.pem", pqc_dir);
    pqc.dsa_key_path = pqc_dsa_key;
    pqc.kem_key_path = pqc_kem_key;
    pqc.kem_pub_path = pqc_kem_pub;
    pqc.trusted_pubs = pqc_trusted;
    pqc.trusted_count = pqc_trusted_count;
    /* MACHINEAUTH trust plane: the same file-configured ML-DSA anchors the
     * bus trusts. Only explicitly configured anchors enable it (R4c
     * philosophy: no flags → no machine auth → password AUTH only). */
    if (pqc_trusted_count > 0) {
        if (!qihse_machine_auth_configure(pqc_trusted, pqc_trusted_count)) {
            fprintf(stderr, "qihse-cluster-daemon: warning: no --pqc-trusted-pub anchor loaded; "
                            "MACHINEAUTH disabled (password AUTH only)\n");
        }
    }
    if (pqc_require || pqc_identity_dir) {
        bool have_keys = access(pqc.dsa_key_path, R_OK) == 0 &&
                         access(pqc.kem_key_path, R_OK) == 0 &&
                         access(pqc.kem_pub_path, R_OK) == 0;
        if (!have_keys) {
            if (pqc_require) {
                fprintf(stderr, "qihse-cluster-daemon: --pqc-require but identity keys are missing under %s "
                                "(need qihse_dsa_key.pem, qihse_kem_key.pem, qihse_kem_pub.pem); refusing to start\n", pqc_dir);
                return 1;
            }
            /* f6: keys missing under an explicitly requested identity dir —
             * stay ARMED (degraded) so the engine still probes connections:
             * a QKP1 client gets a clean "-ERR PQC unavailable" line instead
             * of the probe disappearing into the cleartext RESP parser
             * (silence until timeout). Cleartext sessions are unaffected. */
            pqc_degraded = true;
            fprintf(stderr, "qihse-cluster-daemon: PQC identity keys not found under %s; "
                            "serving cleartext, QKP1 probes answered with -ERR PQC unavailable\n", pqc_dir);
        }
    }
    /* Anti-entropy carries credentials and replicated values. Refuse to
     * enable it unless every connection can use QKP1 with configured node
     * trust anchors; the transport client has no cleartext fallback. */
    if ((replication_configured || (repl_glob_count > 0u && repl_interval > 0u)) &&
        (!pqc.dsa_key_path || access(pqc.dsa_key_path, R_OK) != 0 ||
         !pqc.kem_key_path || access(pqc.kem_key_path, R_OK) != 0 ||
         !pqc.kem_pub_path || access(pqc.kem_pub_path, R_OK) != 0 ||
         pqc_trusted_count == 0u)) {
        fprintf(stderr, "qihse-cluster-daemon: --replicate requires readable QKP1 DSA/KEM identity keys and at least one --pqc-trusted-pub; refusing unsafe replication\n");
        return 2;
    }

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.topology = topology;
    config.local_node_index = indexes[self_index];
    config.bind_address = bind;
    config.advertise_address = bind;
    config.port = port;
    config.bus_port = bus_port;
    config.max_clients = max_clients;
    config.auth_required = (operator_password != NULL);
    config.enable_bus = true;
    config.enable_failover = true;
    config.enable_scatter = enable_scatter;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    config.cluster_migrate_password = operator_password;
    config.redundancy_peer = redundancy_peer;
    /* R4 replicated namespaces: must be set BEFORE server create — the
     * engine ingests the globs into its registry during creation. */
    config.replicate_globs = repl_glob_ptrs;
    config.replicate_glob_count = repl_glob_count;
    /* The cluster password also keys the veiled bus framing: every bus
     * datagram is wrapped as [nonce][pad][XOR(HMAC-SHA384 keystream)] so the
     * UDP gossip is not scannable as a known protocol. NULL = plain frames. */
    config.veil_key = operator_password;
    /* Signed ops: without --node-key the daemon cannot sign its own ops
     * frames; with --require-signed-ops it also refuses unsigned ones from
     * peers (hardened mode — every node must then run --node-key). */
    /* Signed ops (hybrid bus upgrade): load the node identity BEFORE the
     * RESP server is created — the bus inherits signing/verification from
     * the server config below. */
    void* node_sign_pkey = NULL;
    if (node_key_path) {
        node_sign_pkey = qihse_federation_node_key_load(node_key_path);
        if (!node_sign_pkey) {
            fprintf(stderr,
                    "[qihse-cluster-daemon] --node-key: cannot load '%s'\n",
                    node_key_path);
            return 2;
        }
        fprintf(stderr,
                "[qihse-cluster-daemon] signing ops frames with %s\n",
                node_key_path);
    } else if (require_signed_ops) {
        fprintf(stderr,
                "[qihse-cluster-daemon] --require-signed-ops without --node-key: "
                "this node cannot SIGN its own ops frames and will refuse to "
                "start in hardened mode\n");
        return 2;
    }
    config.federation_sign_key = node_sign_pkey;
    config.require_signed_ops = require_signed_ops;
    /* R4c: PQC must be OFF unless explicitly requested via --pqc-* flags or
     * required by anti-entropy. pqc.dsa_key_path points at a static buffer
     * and is always non-NULL, so it cannot be the opt-in condition. */
    if ((pqc_identity_dir != NULL || pqc_require || replication_configured ||
         (repl_glob_count > 0u && repl_interval > 0u)) && pqc.dsa_key_path) {
        config.pqc = pqc; /* opportunistic default: PQC on QKP1 probe, cleartext allowed */
    }
    /* BM25 full-text search surface (FTS.BUILD / FTS.SEARCH): unlike
     * VECHYBRID, which expects the caller to bring an index, every cluster
     * daemon owns one over its local KV. In-memory by design: after a
     * restart FTS.SEARCH returns an empty array until the next FTS.BUILD. */
    qihse_fts_index_t* fts = qihse_fts_create();
    if (!fts)
        fprintf(stderr, "qihse-cluster-daemon: FTS index create failed (FTS.* unavailable)\n");
    config.fts = fts;

    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) {
        fprintf(stderr, "qihse-cluster-daemon: server create failed (bind %s port %u): %s\n",
                bind, port, strerror(errno));
        return 1;
    }
    if (irc_server && irc_channel) {
        qihse_cluster_node_t self_node;
        if (qihse_cluster_topology_get_node(topology, indexes[self_index], &self_node)) {
            qihse_cluster_bus_t* bus = qihse_resp_server_bus(server);
            if (bus) {
                qihse_overlay_config_t ocfg = {0};
                ocfg.irc_server = irc_server;
                ocfg.irc_channel = irc_channel;
                ocfg.nick_prefix = irc_nick_prefix;
                ocfg.node_id = self_node.id;
                ocfg.bind_host = bind;
                ocfg.bind_port = bus_port;
                ocfg.hmac_password = operator_password;
                ocfg.bus = bus;
                if (qihse_overlay_start(&ocfg))
                    fprintf(stderr, "qihse-cluster-daemon: overlay bootstrap active on %s\n", irc_channel);
                else
                    fprintf(stderr, "qihse-cluster-daemon: overlay bootstrap failed to start\n");
            }
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "qihse-cluster-daemon: node %u serving %s:%u (bus %u), %zu peers, %zu join seeds, auth=%s%s\n",
            self_index, bind, port, bus_port, peer_count, seed_count, config.auth_required ? "on" : "off",
            config.pqc.dsa_key_path ? (config.pqc.require ? ", pqc=required"
                                      : (pqc_degraded ? ", pqc=unavailable (keys missing)" : ", pqc=opportunistic"))
                                    : ", pqc=off");
    if (brain_enabled) {
        char default_dir[600];
        if (!brain_dir) {
            snprintf(default_dir, sizeof(default_dir), "%s/brain", data_dir ? data_dir : ".");
            brain_dir = default_dir;
        }
        qihse_brain_config_t brain_cfg = {
            .server = server,
            .journal_dir = brain_dir,
            .dsa_key_path = brain_dsa_key,
            .interval_seconds = brain_interval,
            .act = brain_act,
            .act_cooldown_seconds = brain_cooldown,
            .rollback_window_seconds = brain_rollback_window,
            .prune_timeout_seconds = brain_prune_timeout,
            .rebalance_min_slots = brain_rebalance_min,
            .federation_journal_dir = brain_fed_dir,
            .node_key_handle = brain_node_key
        };
        if (!qihse_cluster_brain_start(&brain_cfg)) {
            fprintf(stderr, "qihse-cluster-daemon: brain failed to start (continuing without it)\n");
        } else {
            fprintf(stderr, "qihse-cluster-daemon: brain active (%s)\n", brain_act ? "observe+act" : "observe");
        }
    }
    pthread_t ae_thread;
    static volatile sig_atomic_t ae_stop = 0;
    ae_ctx_t ae_ctx;
    bool ae_started = false;
    if (replication_source_host && repl_interval > 0u) {
        ae_ctx.server = server;
        ae_ctx.password = operator_password;
        ae_ctx.source_host = replication_source_host;
        ae_ctx.source_port = replication_source_port;
        ae_ctx.socks_port = replication_socks_port;
        ae_ctx.replica_principal = qihse_auth_get_user(0u);
        ae_ctx.qkp = &pqc;
        ae_ctx.data_dir = data_dir;
        ae_ctx.interval_seconds = repl_interval;
        ae_ctx.stop = &ae_stop;
        if (!ae_ctx.replica_principal || pthread_create(&ae_thread, NULL, ae_main, &ae_ctx) != 0) {
            fprintf(stderr, "qihse-cluster-daemon: replica pull thread failed to start (operator principal unavailable)\n");
            qihse_resp_server_stop(server);
            qihse_resp_server_destroy(server);
            return 1;
        }
        ae_started = true;
    }

    pthread_t join_thread;
    join_ctx_t join_ctx = { server, {{0}}, seed_count };
    if (seed_count > 0) {
        for (size_t i = 0; i < seed_count; i++)
            snprintf(join_ctx.seeds[i], QIHSE_CLUSTER_HOST_LEN + 8u, "%s", seeds[i]);
        if (pthread_create(&join_thread, NULL, join_main, &join_ctx) == 0) pthread_detach(join_thread);
    }
    bool ok = qihse_resp_server_run(server);
    __atomic_store_n(&ae_stop, 1, __ATOMIC_RELEASE);
    if (ae_started) pthread_join(ae_thread, NULL); /* holds server: join before destroy */
    qihse_cluster_brain_stop(); /* before destroy: the brain reads the topology every cycle */
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    if (fts) qihse_fts_destroy(fts); /* caller-owned: destroyed with the server */
    fprintf(stderr, "qihse-cluster-daemon: stopped\n");
    return ok ? 0 : 1;
}
