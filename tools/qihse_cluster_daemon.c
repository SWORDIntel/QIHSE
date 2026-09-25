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
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_brain.h"
#include "qihse_overlay.h"
#include "qihse_kv_store.h"
#include "qihse_fts.h"
#include "qihse_platform.h"
#include <netdb.h>
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
        "\n  --replicate GLOB marks a sovereign-local namespace: keys matching\n"
        "  GLOB are served from this node's own store (never MOVED or\n"
        "  CLUSTERDOWN-gated) and the anti-entropy thread pulls keys peers hold\n"
        "  and this node lacks, every --replicate-interval seconds (default 60,\n"
        "  0 disables). Divergent/orphaned keys are reported via REPL.STATUS,\n"
        "  never auto-resolved; deletes are not propagated in phase 1.\n"
        "  REPL.MARK/REPL.UNMARK manage globs at runtime (in-memory).\n",
        argv0);
}

/* ── R4 anti-entropy for replicated namespaces ──────────────────────────────
 * Every --replicate-interval seconds, per marked glob and per static peer:
 * dial the peer's RESP port, AUTH with the operator password, KEYS the glob,
 * and pull keys the peer has and we lack (GET + local SET; legal because
 * marked keys are sovereign-local). Divergent keys (both sides, different
 * bytes) and orphans (local, missing on EVERY peer) are counted for
 * REPL.STATUS and never auto-resolved; deletes are not propagated in
 * phase 1. Bound: at most REPL_AE_MAX_KEYS key transfers per tick overall,
 * so a large backfill amortizes across ticks. One summary log line/tick.
 *
 * The client below is deliberately minimal (AUTH/KEYS/GET/SET with simple,
 * bulk and array replies) and dials by host:port — loopback for self reads,
 * the peer's RESP endpoint otherwise. */
#define REPL_AE_MAX_KEYS 10000u
#define REPL_AE_GLOBS_MAX 64u
#define REPL_AE_KEYLEN_MAX 512u

typedef struct {
    int fd;
    char err[256];
    char last[128]; /* most recent simple (+/-) reply line */
    /* Small read buffer: one syscall per 4KB instead of one per byte —
     * byte-at-a-time reads made a full tick over a 1.5k-key namespace take
     * minutes instead of seconds. */
    unsigned char buf[4096];
    size_t buf_len;
    size_t buf_pos;
} mini_resp_t;

static bool mini_resp_command(mini_resp_t* c, size_t argc, const char* const* argv);

static int mini_resp_connect(mini_resp_t* c, const char* host, uint16_t port, const char* password) {
    memset(c, 0, sizeof(*c));
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    c->fd = fd;
    if (password && *password) {
        const char* argv[2] = {"AUTH", password};
        if (!mini_resp_command(c, 2, argv)) {
            close(fd);
            c->fd = -1;
            return -1;
        }
    }
    return fd;
}

static void mini_resp_close(mini_resp_t* c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
}

static bool mini_resp_send(mini_resp_t* c, size_t argc, const char* const* argv) {
    char head[64];
    int len = snprintf(head, sizeof(head), "*%zu\r\n", argc);
    if (len <= 0 || (size_t)len >= sizeof(head) || write(c->fd, head, (size_t)len) != len) return false;
    for (size_t i = 0; i < argc; i++) {
        size_t alen = strlen(argv[i]);
        len = snprintf(head, sizeof(head), "$%zu\r\n", alen);
        if (len <= 0 || (size_t)len >= sizeof(head) || write(c->fd, head, (size_t)len) != len) return false;
        size_t done = 0;
        while (done < alen) {
            ssize_t w = write(c->fd, argv[i] + done, alen - done);
            if (w <= 0) return false;
            done += (size_t)w;
        }
        if (write(c->fd, "\r\n", 2u) != 2) return false;
    }
    return true;
}

static int mini_resp_read_line(mini_resp_t* c, char* buf, size_t cap) {
    size_t used = 0;
    while (used + 1u < cap) {
        if (c->buf_pos >= c->buf_len) {
            ssize_t r = read(c->fd, c->buf, sizeof(c->buf));
            if (r <= 0) return -1;
            c->buf_len = (size_t)r;
            c->buf_pos = 0;
        }
        char ch = (char)c->buf[c->buf_pos++];
        if (ch == '\n') {
            if (used > 0 && buf[used - 1u] == '\r') used--;
            buf[used] = '\0';
            return (int)used;
        }
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
        ssize_t r = read(c->fd, out + got, len - got);
        if (r <= 0) return false;
        got += (size_t)r;
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
            if (len < 0 || len > REPL_AE_KEYLEN_MAX) {
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
            if (!mini_resp_read_exact(c, tail, 2u)) {
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
    uint32_t interval_seconds;
    volatile sig_atomic_t* stop;
} ae_ctx_t;

/* str-list helpers */
static bool str_in_list(char** items, size_t count, const char* key) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(items[i], key) == 0) return true;
    }
    return false;
}

static void* ae_main(void* argument) {
    ae_ctx_t* ae = (ae_ctx_t*)argument;
    while (!*ae->stop) {
        for (uint32_t slept = 0; slept < ae->interval_seconds && !*ae->stop; slept++) {
            struct timespec ts = {1, 0};
            nanosleep(&ts, NULL);
        }
        if (*ae->stop) break;

        char globs[REPL_AE_GLOBS_MAX][128];
        bool from_flag[REPL_AE_GLOBS_MAX];
        size_t glob_count = qihse_resp_server_repl_list(ae->server, globs, from_flag, REPL_AE_GLOBS_MAX);
        if (glob_count == 0) continue;

        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        unsigned long long tick_pulled = 0;

        /* Loopback connection for local KEYS/GET/SET. */
        mini_resp_t self;
        bool self_ok = mini_resp_connect(&self, ae->self_host, ae->self_port, ae->password) >= 0;
        if (!self_ok) fprintf(stderr, "qihse-cluster-daemon: repl AE: loopback connect failed\n");

        for (size_t g = 0; g < glob_count && !*ae->stop; g++) {
            size_t local_count = 0;
            char** local_list = NULL;
            if (self_ok) {
                const char* keys_argv[2] = {"KEYS", globs[g]};
                if (mini_resp_do(&self, 2, keys_argv, NULL, &local_list, &local_count) != MINI_REP_ARRAY) {
                    mini_resp_free_array(local_list, local_count);
                    local_list = NULL;
                    local_count = 0;
                }
            }

            /* Union of peer keysets for orphan detection. */
            char* seen_anywhere[REPL_AE_MAX_KEYS];
            size_t seen_count = 0;
            unsigned long long divergent_total = 0;

            for (size_t p = 0; p < ae->peer_count && !*ae->stop; p++) {
                if (ae->peers[p].index == ae->self_index) continue;
                char peer_addr[96];
                snprintf(peer_addr, sizeof(peer_addr), "%s:%u", ae->peers[p].host, ae->peers[p].port);
                mini_resp_t peer;
                if (mini_resp_connect(&peer, ae->peers[p].host, ae->peers[p].port, ae->password) < 0) {
                    qihse_resp_server_repl_note(ae->server, globs[g], peer_addr, 0, 0, UINT64_MAX, UINT64_MAX, false);
                    continue;
                }
                char** peer_list = NULL;
                size_t peer_n = 0;
                const char* keys_argv[2] = {"KEYS", globs[g]};
                unsigned long long pulled = 0, divergent = 0;
                if (mini_resp_do(&peer, 2, keys_argv, NULL, &peer_list, &peer_n) == MINI_REP_ARRAY) {
                    for (size_t i = 0; i < peer_n; i++) {
                        if (seen_count < REPL_AE_MAX_KEYS) {
                            char* dup = strdup(peer_list[i]);
                            if (dup) seen_anywhere[seen_count++] = dup;
                        }
                        if (tick_pulled >= REPL_AE_MAX_KEYS) continue;
                        bool have_local = local_list && str_in_list(local_list, local_count, peer_list[i]);
                        const char* get_argv[2] = {"GET", peer_list[i]};
                        char* peer_value = NULL;
                        if (mini_resp_do(&peer, 2, get_argv, &peer_value, NULL, NULL) != MINI_REP_BULK || !peer_value) {
                            free(peer_value);
                            continue; /* vanished mid-tick */
                        }
                        if (!have_local && self_ok) {
                            const char* set_argv[3] = {"SET", peer_list[i], peer_value};
                            if (mini_resp_command(&self, 3, set_argv)) {
                                pulled++;
                                tick_pulled++;
                            }
                        } else if (have_local && self_ok) {
                            const char* lget_argv[2] = {"GET", peer_list[i]};
                            char* local_value = NULL;
                            if (mini_resp_do(&self, 2, lget_argv, &local_value, NULL, NULL) == MINI_REP_BULK &&
                                local_value && strcmp(local_value, peer_value) != 0) {
                                divergent++; /* report-only in phase 1 */
                            }
                            free(local_value);
                        }
                        free(peer_value);
                    }
                }
                mini_resp_free_array(peer_list, peer_n);
                mini_resp_close(&peer);
                qihse_resp_server_repl_note(ae->server, globs[g], peer_addr, pulled, divergent, UINT64_MAX, UINT64_MAX, true);
                divergent_total += divergent;
            }

            /* Orphans: local keys no peer listed. Report-only. */
            unsigned long long orphaned = 0;
            if (local_list) {
                for (size_t i = 0; i < local_count; i++) {
                    if (!str_in_list(seen_anywhere, seen_count, local_list[i])) orphaned++;
                }
            }
            qihse_resp_server_repl_note(ae->server, globs[g], NULL, UINT64_MAX, UINT64_MAX,
                                        (uint64_t)local_count, orphaned, true);
            for (size_t i = 0; i < seen_count; i++) free(seen_anywhere[i]);
            mini_resp_free_array(local_list, local_count);
            if (tick_pulled >= REPL_AE_MAX_KEYS) break;
        }
        if (self_ok) mini_resp_close(&self);
        struct timespec t1;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
        fprintf(stderr, "qihse-cluster-daemon: repl AE tick: %zu pattern(s), pulled %llu key(s) (%.0fms)\n",
                glob_count, tick_pulled, ms);
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
    fprintf(stderr, "qihse-cluster-daemon: node %u serving %s:%u (bus %u), %zu peers, %zu join seeds, auth=%s\n",
            self_index, bind, port, bus_port, peer_count, seed_count, config.auth_required ? "on" : "off");
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
    if (repl_interval > 0) {
        ae_ctx.server = server;
        ae_ctx.peers = peers;
        ae_ctx.peer_count = peer_count;
        ae_ctx.self_index = self_index;
        ae_ctx.password = operator_password;
        ae_ctx.self_host = bind;
        ae_ctx.self_port = port;
        ae_ctx.interval_seconds = repl_interval;
        ae_ctx.stop = &ae_stop;
        if (pthread_create(&ae_thread, NULL, ae_main, &ae_ctx) == 0) ae_started = true;
        else fprintf(stderr, "qihse-cluster-daemon: repl AE thread failed to start\n");
    }

    pthread_t join_thread;
    join_ctx_t join_ctx = { server, {{0}}, seed_count };
    if (seed_count > 0) {
        for (size_t i = 0; i < seed_count; i++)
            snprintf(join_ctx.seeds[i], QIHSE_CLUSTER_HOST_LEN + 8u, "%s", seeds[i]);
        if (pthread_create(&join_thread, NULL, join_main, &join_ctx) == 0) pthread_detach(join_thread);
    }
    bool ok = qihse_resp_server_run(server);
    ae_stop = 1;
    if (ae_started) pthread_join(ae_thread, NULL); /* holds server: join before destroy */
    qihse_cluster_brain_stop(); /* before destroy: the brain reads the topology every cycle */
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    if (fts) qihse_fts_destroy(fts); /* caller-owned: destroyed with the server */
    fprintf(stderr, "qihse-cluster-daemon: stopped\n");
    return ok ? 0 : 1;
}
