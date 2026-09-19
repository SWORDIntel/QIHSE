/*
 * QIHSE overlay — IRC dead-drop bootstrap (phase 1b).
 *
 * Layer 2 of docs/architecture/overlay_protocol.md: a per-node IRC client
 * thread that beacons a signed node record into a shared channel every 30 s
 * and introduces freshly discovered endpoints to the cluster bus via
 * qihse_cluster_bus_meet().  The IRC server is treated as an untrusted
 * bulletin board:
 *
 *   - authenticity: HMAC-SHA-384 over the record body with the cluster
 *     operator password as key (phase-2 upgrade path: ML-DSA-87)
 *   - replay: record timestamps must be within ±5 min of local time
 *   - integrity: the signature covers the endpoint, so records cannot be
 *     redirected to an attacker-chosen host:port
 *
 * Fail-closed rule: any decode/HMAC/freshness/parse failure drops the record
 * before any state is mutated and before a MEET is ever sent.  Records are
 * accepted from any PRIVMSG; the HMAC is the gate, not the channel name.
 *
 * Plain TCP (no TLS) for phase 1, per the implementation order table.
 */

#include "qihse_overlay.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
typedef int socklen_t;
#endif

#define OVERLAY_LOG(...)                                                     \
    do {                                                                     \
        fprintf(stderr, "[qihse-overlay] " __VA_ARGS__);                     \
        fputc('\n', stderr);                                                 \
    } while (0)

/* Record limits.  IRC lines are capped at 512 bytes on the wire, so real
 * records are far smaller; these bounds just keep stack buffers safe. */
#define OVERLAY_MAX_BIN 1024u                     /* max decoded record */
#define OVERLAY_MAX_B64 1400u                     /* max base64 token */
#define OVERLAY_MAX_JSON (OVERLAY_MAX_BIN - QIHSE_OVERLAY_HMAC_SIZE)
#define OVERLAY_CHANNEL_MAX 128u
#define OVERLAY_PASSWORD_MAX 256u
#define OVERLAY_CONNECT_TIMEOUT_MS 5000
#define OVERLAY_POLL_SLICE_MS 250                 /* bounds stop() latency */
#define OVERLAY_RECONNECT_DELAY_MS 2000
#define OVERLAY_IRC_DEFAULT_PORT 6667u
#define OVERLAY_NICK_MAX 48u

/* One discovered peer.  Keyed by endpoint (host:bus_port) because a MEET is
 * addressed to an endpoint; the announcing node id is kept alongside so a
 * re-keyed node is visible in logs and node-id tracking stays meaningful. */
typedef struct {
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t bus_port;
    bool met;
} overlay_seen_t;

typedef struct {
    /* immutable configuration (deep copy of qihse_overlay_config_t) */
    char irc_host[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t irc_port;
    char irc_channel[OVERLAY_CHANNEL_MAX];
    char nick_base[OVERLAY_NICK_MAX];   /* nick_prefix + node_id[:8] */
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char bind_host[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t bind_port;
    char hmac_password[OVERLAY_PASSWORD_MAX];
    struct qihse_cluster_bus* bus;

    /* lifecycle */
    pthread_mutex_t exit_lock;
    pthread_cond_t exit_cond;
    bool running;          /* accessed with __atomic builtins */
    bool thread_exited;    /* set under exit_lock before signal */

    /* discovered-peer table; touched only by the overlay thread */
    overlay_seen_t seen[QIHSE_CLUSTER_MAX_NODES];

    /* statistics; thread-private until stop() reads them post-exit */
    struct {
        uint64_t records_verified;
        uint64_t records_bad_hmac;
        uint64_t records_stale;
        uint64_t records_malformed;
        uint64_t meets_sent;
        uint64_t meets_failed;
        uint64_t advertises_sent;
    } stats;
} overlay_t;

static overlay_t* g_overlay = NULL;
static pthread_mutex_t g_overlay_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── clocks ──────────────────────────────────────────────────────────── */

static uint64_t overlay_realtime_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t overlay_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Sleep in small slices so stop() is never held off for long. */
static bool overlay_sleep_slices(const overlay_t* o, uint32_t total_ms) {
    uint32_t done = 0;
    while (done < total_ms) {
        if (!__atomic_load_n(&o->running, __ATOMIC_ACQUIRE)) return false;
        uint32_t slice = total_ms - done;
        if (slice > 100u) slice = 100u;
        struct timespec ts = { (time_t)(slice / 1000u),
                               (long)((slice % 1000u) * 1000000L) };
        nanosleep(&ts, NULL);
        done += slice;
    }
    return __atomic_load_n(&o->running, __ATOMIC_ACQUIRE);
}

/* ── sockets ─────────────────────────────────────────────────────────── */

static void overlay_set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void overlay_set_block(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static bool overlay_send_all(int fd, const char* data, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, data, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

/* 1 = readable, 0 = timeout, -1 = error/hangup */
static int overlay_wait_readable(int fd, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int r = poll(&pfd, 1, timeout_ms);
    if (r <= 0) return r;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
    return (pfd.revents & POLLIN) ? 1 : 0;
}

/* Bound-blocking TCP connect (non-blocking connect + POLLOUT wait) so a
 * black-holed address cannot stall stop() for minutes. */
static int overlay_connect_tcp(const char* host, uint16_t port, int timeout_ms) {
    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        overlay_set_nonblock(fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            if (errno != EINPROGRESS) {
                close(fd);
                fd = -1;
                continue;
            }
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int soerr = 0;
            socklen_t slen = sizeof soerr;
            if (poll(&pfd, 1, timeout_ms) <= 0 || !(pfd.revents & POLLOUT) ||
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen) != 0 ||
                soerr != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }
        overlay_set_block(fd);
#ifdef IPPROTO_TCP
        {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&one,
                       sizeof one);
        }
#endif
        break;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── base64 ──────────────────────────────────────────────────────────── */

static const char OVERLAY_B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t overlay_b64_encoded_size(size_t n) {
    return 4u * ((n + 2u) / 3u);
}

static void overlay_b64_encode(const uint8_t* src, size_t len,
                               char* out, size_t out_cap) {
    size_t o = 0;
    for (size_t i = 0; i < len && o + 4u < out_cap; i += 3u) {
        uint32_t v = (uint32_t)src[i] << 16;
        if (i + 1u < len) v |= (uint32_t)src[i + 1u] << 8;
        if (i + 2u < len) v |= (uint32_t)src[i + 2u];
        out[o++] = OVERLAY_B64[(v >> 18) & 63u];
        out[o++] = OVERLAY_B64[(v >> 12) & 63u];
        out[o++] = (i + 1u < len) ? OVERLAY_B64[(v >> 6) & 63u] : '=';
        out[o++] = (i + 2u < len) ? OVERLAY_B64[v & 63u] : '=';
    }
    out[o] = '\0';
}

/* Accepts padded and unpadded canonical base64; anything else fails. */
static bool overlay_b64_decode(const char* in, size_t in_len,
                               uint8_t* out, size_t out_cap, size_t* out_len) {
    int8_t rev[256];
    memset(rev, -1, sizeof rev);
    for (int i = 0; i < 64; i++) rev[(uint8_t)OVERLAY_B64[i]] = (int8_t)i;

    size_t n = in_len;
    size_t pad = 0;
    while (n > 0 && in[n - 1u] == '=') {
        pad++;
        n--;
        if (pad > 2u) return false;
    }
    if (n == 0 || (n % 4u) == 1u) return false;

    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int8_t v = rev[(uint8_t)in[i]];
        if (v < 0) return false;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= out_cap) return false;
            out[o++] = (uint8_t)(acc >> bits);
        }
    }
    *out_len = o;
    return o > 0;
}

/* ── record crypto ───────────────────────────────────────────────────── */

static void overlay_hmac_sha384(const char* key, const uint8_t* data,
                                size_t len,
                                uint8_t out[QIHSE_OVERLAY_HMAC_SIZE]) {
    unsigned int md_len = QIHSE_OVERLAY_HMAC_SIZE;
    HMAC(EVP_sha384(), key, (int)strlen(key), data, len, out, &md_len);
}

/* ── minimal JSON field extraction (flat, self-emitted shape) ────────── */

static bool overlay_json_string(const char* json, const char* key,
                                char* out, size_t cap) {
    char needle[80];
    int n = snprintf(needle, sizeof needle, "\"%s\":\"", key);
    if (n <= 0 || (size_t)n >= sizeof needle) return false;
    const char* p = strstr(json, needle);
    if (!p) return false;
    p += (size_t)n;
    size_t i = 0;
    while (*p && *p != '"') {
        if (*p == '\\' || i + 1u >= cap) return false; /* no escapes expected */
        out[i++] = *p++;
    }
    if (*p != '"') return false;
    out[i] = '\0';
    return true;
}

static bool overlay_json_u64(const char* json, const char* key, uint64_t* out) {
    char needle[80];
    int n = snprintf(needle, sizeof needle, "\"%s\":", key);
    if (n <= 0 || (size_t)n >= sizeof needle) return false;
    const char* p = strstr(json, needle);
    if (!p) return false;
    p += (size_t)n;
    if (*p < '0' || *p > '9') return false;
    char* end = NULL;
    unsigned long long v = strtoull(p, &end, 10);
    if (end == p) return false;
    *out = (uint64_t)v;
    return true;
}

/* Split "host:port" at the LAST colon (IPv6 literals are not supported in
 * phase 1; lab deployments advertise v4 hostnames).  Truncates `spec` at the
 * colon so the caller is left with the host part either way. */
static bool overlay_split_host_port(char* spec, uint16_t* port_out) {
    char* colon = strrchr(spec, ':');
    if (!colon || colon == spec) return false;
    *colon = '\0';
    if (*spec == '\0' || strlen(spec) > QIHSE_CLUSTER_HOST_LEN) return false;
    if (colon[1] == '\0') return false;
    char* end = NULL;
    unsigned long v = strtoul(colon + 1, &end, 10);
    if (end == colon + 1 || v == 0 || v > 65535ul) return false;
    *port_out = (uint16_t)v;
    return true;
}

/* ── MEET trigger ────────────────────────────────────────────────────── */

/* THE HINT GATE.  This is the only function in this file that turns a
 * discovered endpoint into an action, and the only action available is a MEET
 * — a dial.  It is shared by the IRC path (overlay_consider_meet) and the DHT
 * path (qihse_overlay_dht_handle_nodes), so neither can grow its own way of
 * acting on a hint.
 *
 * A MEET carries no authority: qihse_bus_msg_carries_authority() returns false
 * for it, which is why it is usable during bootstrap at all.  If that ever
 * stops being true, discovery stops dialing rather than becoming an admission
 * path — the fail-closed direction. */
static bool overlay_dial_hint(struct qihse_cluster_bus* bus, const char* host,
                              uint16_t port) {
    if (!bus || !host || port == 0) return false;
    if (qihse_bus_msg_carries_authority(QIHSE_BUS_MSG_MEET)) {
        OVERLAY_LOG("refusing to dial %s:%u: MEET now reports as "
                    "authority-bearing, which discovery must never use",
                    host, (unsigned)port);
        return false;
    }
    return qihse_cluster_bus_meet(bus, host, port);
}

/* Suppress redundant MEETs: once an endpoint has been introduced, later
 * records for it (whatever node re-announces it) are ignored. */
static void overlay_consider_meet(overlay_t* o, const char* id,
                                  const char* host, uint16_t bus_port) {
    for (size_t i = 0; i < QIHSE_CLUSTER_MAX_NODES; i++) {
        const overlay_seen_t* e = &o->seen[i];
        if (e->met && e->bus_port == bus_port && strcmp(e->host, host) == 0) {
            return;
        }
    }
    /* Find a slot: refresh the entry for this node id, else first free. */
    overlay_seen_t* slot = NULL;
    for (size_t i = 0; i < QIHSE_CLUSTER_MAX_NODES && !slot; i++) {
        if (o->seen[i].id[0] && strcmp(o->seen[i].id, id) == 0) {
            slot = &o->seen[i];
        }
    }
    for (size_t i = 0; i < QIHSE_CLUSTER_MAX_NODES && !slot; i++) {
        if (!o->seen[i].id[0]) slot = &o->seen[i];
    }
    if (!slot) return; /* table full (== max cluster size); nothing to do */

    if (overlay_dial_hint(o->bus, host, bus_port)) {
        snprintf(slot->id, sizeof slot->id, "%s", id);
        snprintf(slot->host, sizeof slot->host, "%s", host);
        slot->bus_port = bus_port;
        slot->met = true;
        o->stats.meets_sent++;
        OVERLAY_LOG("MEET -> %s:%u (node %.12s)", host, (unsigned)bus_port, id);
    } else {
        o->stats.meets_failed++;
        OVERLAY_LOG("MEET failed for %s:%u (will retry on next beacon)",
                    host, (unsigned)bus_port);
    }
}

/* ── Layer 3: DHT peer exchange (simplified Kademlia) ────────────────────
 *
 * A peer-exchange that returns CLOSER peers, and nothing more.  Read the gate
 * note in qihse_overlay.h first: a DHT record is an unauthenticated HINT, the
 * only action it can cause is a dial (overlay_dial_hint), and there is no call
 * anywhere in this section to a topology upsert, a federation write or a
 * trust-state change.
 *
 * Frames are fixed-size with no length field to lie about:
 *
 *   DHT_FIND  (160 B)
 *     version u8 | flags u8 | max_peers u8 | reserved u8
 *     ts u64 | requester_port u16
 *     requester_id[41] | target_id[41] | requester_host[64]
 *   DHT_NODES (53 + n*107 B, n <= QIHSE_DHT_K)
 *     version u8 | flags u8 | count u8 | reserved u8
 *     ts u64 | responder_id[41]
 *     entries[n]: id[41] | host[64] | port u16
 *
 * flags and reserved must be zero: a record cannot smuggle a semantic this
 * version does not know, and a frame that is not exactly the size its count
 * implies is dropped whole (no partial application).  ts is bounded by the
 * same ±5 min replay window the IRC records use.
 *
 * A lookup is ONE hop.  A FIND is answered, never forwarded, and a NODES frame
 * never causes another query — so no request can recurse, and no record can
 * make us generate another DHT frame.  The only third-party traffic a record
 * can cause is a bounded number of MEETs (QIHSE_DHT_DIAL_MAX_PER_WINDOW per
 * second, each a few hundred bytes).
 */

typedef enum {
    OVERLAY_DHT_OK = 0,
    OVERLAY_DHT_MALFORMED,   /* wrong size, bad id/host/port, bad count */
    OVERLAY_DHT_UNSUPPORTED, /* unknown version, or flags/reserved set */
    OVERLAY_DHT_STALE        /* outside the replay window */
} overlay_dht_parse_t;

typedef struct {
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_DHT_HOST_MAX];
    uint16_t port;
    uint8_t distance[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
} overlay_dht_candidate_t;

typedef struct {
    uint8_t max_peers;
    uint16_t requester_port;
    char requester_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char target_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char requester_host[QIHSE_DHT_HOST_MAX];
} overlay_dht_find_t;

typedef struct {
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_DHT_HOST_MAX];
    uint16_t port;
} overlay_dht_entry_t;

typedef struct {
    char responder_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint8_t count;
    overlay_dht_entry_t entries[QIHSE_DHT_K];
} overlay_dht_nodes_t;

typedef struct {
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char advertise_host[QIHSE_DHT_HOST_MAX];
    uint16_t advertise_port;
    struct qihse_cluster_bus* bus;
    void* federation_store;   /* negative filter only; never a grant */
    void* federation_user;

    pthread_mutex_t lock;
    /* Fixed-size dedupe table of endpoints already dialed.  Round-robin
     * insertion: the state cannot grow, and a flood cannot evict its way to
     * more dials because the dial budget is a separate bound. */
    qihse_overlay_dht_hint_t hints[QIHSE_DHT_MAX_HINTS];
    size_t hint_count;
    size_t hint_next;
    uint64_t serve_window_ms;
    uint32_t serve_window_count;
    uint64_t hint_window_ms;
    uint32_t hint_window_count;
    uint64_t dial_window_ms;
    uint32_t dial_window_count;
    uint32_t refs;            /* in-flight handlers; atomic */
    qihse_overlay_dht_stats_t stats;
} overlay_dht_t;

static overlay_dht_t* g_dht = NULL;
static pthread_mutex_t g_dht_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_overlay_dht_owned = false; /* started by qihse_overlay_start() */

static int overlay_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Strict: exactly 40 lowercase hex chars.  Accepting an upper-case spelling of
 * the same id would make one node two keys, which is a dedupe bypass. */
static bool overlay_dht_id_bytes(const char* id,
                                 uint8_t out[QIHSE_CLUSTER_NODE_ID_LEN / 2u]) {
    if (!id || strlen(id) != QIHSE_CLUSTER_NODE_ID_LEN) return false;
    for (size_t i = 0; i < QIHSE_CLUSTER_NODE_ID_LEN / 2u; i++) {
        int hi = overlay_hex_val(id[i * 2u]);
        int lo = overlay_hex_val(id[i * 2u + 1u]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* IPv4 literal, and nothing else: the bus send path is inet_pton(AF_INET), so
 * a name would only ever fail later — and refusing it here keeps an
 * unauthenticated record from ever reaching a resolver. */
static bool overlay_dht_host_literal(const char* host) {
    if (!host || !*host || strlen(host) >= QIHSE_DHT_HOST_MAX) return false;
    struct in_addr addr;
    return inet_pton(AF_INET, host, &addr) == 1;
}

/* ...and one we are willing to dial.  Refusing the unspecified address
 * matters: dialing 0.0.0.0 reaches the LOCAL host on Linux, so a hostile
 * record could otherwise point a MEET back at our own bus port. */
static bool overlay_dht_host_dialable(const char* host) {
    if (!overlay_dht_host_literal(host)) return false;
    struct in_addr addr;
    if (inet_pton(AF_INET, host, &addr) != 1) return false;
    uint32_t v = ntohl(addr.s_addr);
    if (v == INADDR_ANY || v == INADDR_BROADCAST) return false;
    if ((v & 0xF0000000u) == 0xE0000000u) return false; /* multicast */
    return true;
}

static bool overlay_dht_fresh(uint64_t ts) {
    int64_t delta = (int64_t)overlay_realtime_ms() - (int64_t)ts;
    if (delta < 0) delta = -delta;
    return (uint64_t)delta <= QIHSE_OVERLAY_FRESHNESS_MS;
}

/* Common header checks for both frame types. */
static overlay_dht_parse_t overlay_dht_check_header(const uint8_t* p, size_t len,
                                                    size_t min_len, uint64_t* ts) {
    if (!p || len < min_len) return OVERLAY_DHT_MALFORMED;
    if (p[0] != QIHSE_DHT_FRAME_VERSION) return OVERLAY_DHT_UNSUPPORTED;
    if (p[1] != 0u || p[3] != 0u) return OVERLAY_DHT_UNSUPPORTED;
    memcpy(ts, p + 4u, 8u);
    if (!overlay_dht_fresh(*ts)) return OVERLAY_DHT_STALE;
    return OVERLAY_DHT_OK;
}

static overlay_dht_parse_t overlay_dht_parse_find(const uint8_t* p, size_t len,
                                                  overlay_dht_find_t* out) {
    uint64_t ts = 0;
    if (len != QIHSE_DHT_FIND_PAYLOAD_SIZE) return OVERLAY_DHT_MALFORMED;
    overlay_dht_parse_t r = overlay_dht_check_header(p, len, QIHSE_DHT_FIND_PAYLOAD_SIZE, &ts);
    if (r != OVERLAY_DHT_OK) return r;
    memset(out, 0, sizeof *out);
    out->max_peers = p[2];
    memcpy(&out->requester_port, p + 12u, 2u);
    memcpy(out->requester_id, p + 14u, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    memcpy(out->target_id, p + 55u, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    memcpy(out->requester_host, p + 96u, QIHSE_DHT_HOST_MAX);
    out->requester_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    out->target_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    out->requester_host[QIHSE_DHT_HOST_MAX - 1u] = '\0';
    uint8_t scratch[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
    if (!overlay_dht_id_bytes(out->requester_id, scratch)) return OVERLAY_DHT_MALFORMED;
    if (!overlay_dht_id_bytes(out->target_id, scratch)) return OVERLAY_DHT_MALFORMED;
    if (!overlay_dht_host_dialable(out->requester_host)) return OVERLAY_DHT_MALFORMED;
    if (out->requester_port == 0) return OVERLAY_DHT_MALFORMED;
    return OVERLAY_DHT_OK;
}

/* All-or-nothing: one bad entry drops the whole frame.  A frame that is partly
 * applied is a frame whose meaning depends on where the attacker stopped. */
static overlay_dht_parse_t overlay_dht_parse_nodes(const uint8_t* p, size_t len,
                                                   overlay_dht_nodes_t* out) {
    uint64_t ts = 0;
    if (len < QIHSE_DHT_NODES_HEADER_SIZE) return OVERLAY_DHT_MALFORMED;
    overlay_dht_parse_t r = overlay_dht_check_header(p, len, QIHSE_DHT_NODES_HEADER_SIZE, &ts);
    if (r != OVERLAY_DHT_OK) return r;
    uint8_t count = p[2];
    if (count > QIHSE_DHT_K) return OVERLAY_DHT_MALFORMED;
    if (len != QIHSE_DHT_NODES_HEADER_SIZE + (size_t)count * QIHSE_DHT_ENTRY_SIZE) {
        return OVERLAY_DHT_MALFORMED;
    }
    memset(out, 0, sizeof *out);
    out->count = count;
    memcpy(out->responder_id, p + 12u, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    out->responder_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    uint8_t scratch[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
    if (!overlay_dht_id_bytes(out->responder_id, scratch)) return OVERLAY_DHT_MALFORMED;
    for (uint8_t i = 0; i < count; i++) {
        const uint8_t* e = p + QIHSE_DHT_NODES_HEADER_SIZE +
                           (size_t)i * QIHSE_DHT_ENTRY_SIZE;
        overlay_dht_entry_t* entry = &out->entries[i];
        memcpy(entry->id, e, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        memcpy(entry->host, e + QIHSE_CLUSTER_NODE_ID_LEN + 1u, QIHSE_DHT_HOST_MAX);
        memcpy(&entry->port, e + QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_DHT_HOST_MAX, 2u);
        entry->id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
        entry->host[QIHSE_DHT_HOST_MAX - 1u] = '\0';
        if (!overlay_dht_id_bytes(entry->id, scratch)) return OVERLAY_DHT_MALFORMED;
        if (!overlay_dht_host_dialable(entry->host)) return OVERLAY_DHT_MALFORMED;
        if (entry->port == 0) return OVERLAY_DHT_MALFORMED;
    }
    return OVERLAY_DHT_OK;
}

/* Take a reference so stop() cannot free the state under a live handler. */
static overlay_dht_t* overlay_dht_ref(struct qihse_cluster_bus* bus) {
    if (!bus) return NULL;
    pthread_mutex_lock(&g_dht_lock);
    overlay_dht_t* d = g_dht;
    if (d && d->bus == bus) {
        __atomic_add_fetch(&d->refs, 1u, __ATOMIC_ACQ_REL);
    } else {
        d = NULL; /* not enabled, or bound to a different bus: drop */
    }
    pthread_mutex_unlock(&g_dht_lock);
    return d;
}

static void overlay_dht_unref(overlay_dht_t* d) {
    if (d) __atomic_sub_fetch(&d->refs, 1u, __ATOMIC_ACQ_REL);
}

static void overlay_dht_note_reject(overlay_dht_t* d, bool is_find,
                                    overlay_dht_parse_t why) {
    pthread_mutex_lock(&d->lock);
    if (is_find) d->stats.finds_rejected++;
    else d->stats.nodes_rejected++;
    if (why == OVERLAY_DHT_STALE) d->stats.frames_stale++;
    pthread_mutex_unlock(&d->lock);
}

/* Returns true and consumes one unit of the serve budget, or false when the
 * per-second budget is spent (so a FIND flood cannot make us answer forever). */
static bool overlay_dht_serve_budget(overlay_dht_t* d) {
    bool ok = false;
    pthread_mutex_lock(&d->lock);
    uint64_t now = overlay_mono_ms();
    if (now - d->serve_window_ms >= QIHSE_DHT_SERVE_WINDOW_MS) {
        d->serve_window_ms = now;
        d->serve_window_count = 0;
    }
    if (d->serve_window_count < QIHSE_DHT_SERVE_MAX_PER_WINDOW) {
        d->serve_window_count++;
        ok = true;
    } else {
        d->stats.finds_rate_limited++;
    }
    pthread_mutex_unlock(&d->lock);
    return ok;
}

static bool overlay_dht_hint_known_locked(const overlay_dht_t* d, const char* id,
                                          const char* host, uint16_t port) {
    for (size_t i = 0; i < QIHSE_DHT_MAX_HINTS; i++) {
        const qihse_overlay_dht_hint_t* h = &d->hints[i];
        if (h->id[0] == '\0') continue;
        /* Dedupe on the id as well as the endpoint: an id already dialed is
         * not dialed again at a NEW endpoint through the unauthenticated
         * path.  Re-pointing a known id is exactly how a hostile record would
         * redirect a dial, so it does not get to. */
        if (h->port == port && strcmp(h->host, host) == 0) return true;
        if (strcmp(h->id, id) == 0) return true;
    }
    return false;
}

static void overlay_dht_hint_store_locked(overlay_dht_t* d, const char* id,
                                          const char* host, uint16_t port,
                                          uint64_t now) {
    qihse_overlay_dht_hint_t* slot = &d->hints[d->hint_next];
    if (slot->id[0] == '\0') d->hint_count++;
    snprintf(slot->id, sizeof slot->id, "%s", id);
    snprintf(slot->host, sizeof slot->host, "%s", host);
    slot->port = port;
    slot->dialed_ms = now;
    d->hint_next = (d->hint_next + 1u) % QIHSE_DHT_MAX_HINTS;
}

/* NEGATIVE filter only: a hint for a REVOKED identity is never dialed, so the
 * DHT cannot undo an operator decision.  It grants nothing — an unknown or
 * PENDING identity is still dialable as a hint, and still cannot become a
 * member without enrollment. */
static bool overlay_dht_revoked(const overlay_dht_t* d, const char* node_id) {
    if (!d->federation_store || !d->federation_user) return false;
    uint8_t uuid_bytes[QIHSE_UUID_BYTES];
    if (!qihse_cluster_node_federation_uuid(node_id, uuid_bytes)) return false;
    qihse_uuid_t uuid;
    memcpy(uuid.bytes, uuid_bytes, sizeof uuid.bytes);
    qihse_federation_node_identity_t identity;
    if (!qihse_federation_node_lookup(d->federation_store, d->federation_user,
                                      &uuid, &identity)) {
        return false; /* not enrolled at all: a hint, never a member */
    }
    return identity.trust == QIHSE_TRUST_REVOKED;
}

/* Insert one candidate into the k-best set, ordered by XOR distance to the
 * target (ascending).  k is a compile-time constant, so this is bounded work
 * with no allocation and no recursion. */
static void overlay_dht_offer(overlay_dht_candidate_t* best, size_t* count,
                              size_t cap, const overlay_dht_candidate_t* cand) {
    size_t pos = 0;
    while (pos < *count &&
           memcmp(best[pos].distance, cand->distance,
                  QIHSE_CLUSTER_NODE_ID_LEN / 2u) <= 0) {
        pos++;
    }
    if (pos >= cap) return;
    size_t last = (*count < cap) ? *count : cap - 1u;
    for (size_t i = last; i > pos; i--) best[i] = best[i - 1u];
    best[pos] = *cand;
    if (*count < cap) (*count)++;
}

/* The k closest peers WE ALREADY KNOW, from the cluster topology.  Nothing is
 * invented here: a response can only hand back endpoints the responder itself
 * learned from the bus. */
static void overlay_dht_collect_closest(const qihse_cluster_topology_t* topology,
                                        const char* requester_id,
                                        const uint8_t target[QIHSE_CLUSTER_NODE_ID_LEN / 2u],
                                        overlay_dht_candidate_t* best, size_t* count,
                                        size_t want) {
    for (uint16_t idx = 0; idx < QIHSE_CLUSTER_MAX_NODES && *count < want; idx++) {
        qihse_cluster_node_t node;
        if (!qihse_cluster_topology_get_node(topology, idx, &node)) continue;
        if (node.id[0] == '\0') continue;
        if (strcmp(node.id, requester_id) == 0) continue; /* it knows itself */
        if (!overlay_dht_host_dialable(node.host)) continue;
        if (node.bus_port == 0) continue;
        size_t host_len = strlen(node.host);
        if (host_len >= QIHSE_DHT_HOST_MAX) continue;
        overlay_dht_candidate_t cand;
        memset(&cand, 0, sizeof cand);
        snprintf(cand.id, sizeof cand.id, "%s", node.id);
        memcpy(cand.host, node.host, host_len + 1u);
        cand.port = node.bus_port;
        uint8_t bytes[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
        if (!overlay_dht_id_bytes(node.id, bytes)) continue;
        for (size_t i = 0; i < sizeof bytes; i++) {
            cand.distance[i] = (uint8_t)(bytes[i] ^ target[i]);
        }
        overlay_dht_offer(best, count, want, &cand);
    }
}

static bool overlay_dht_send_nodes(struct qihse_cluster_bus* bus,
                                   const overlay_dht_t* d, const char* host,
                                   uint16_t port,
                                   const overlay_dht_candidate_t* best,
                                   size_t count) {
    uint8_t payload[QIHSE_DHT_NODES_MAX_PAYLOAD];
    size_t len = QIHSE_DHT_NODES_HEADER_SIZE + count * QIHSE_DHT_ENTRY_SIZE;
    memset(payload, 0, len);
    payload[0] = QIHSE_DHT_FRAME_VERSION;
    payload[1] = 0u;
    payload[2] = (uint8_t)count;
    payload[3] = 0u;
    uint64_t ts = overlay_realtime_ms();
    memcpy(payload + 4u, &ts, 8u);
    memcpy(payload + 12u, d->node_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    for (size_t i = 0; i < count; i++) {
        uint8_t* e = payload + QIHSE_DHT_NODES_HEADER_SIZE + i * QIHSE_DHT_ENTRY_SIZE;
        memcpy(e, best[i].id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        snprintf((char*)(e + QIHSE_CLUSTER_NODE_ID_LEN + 1u), QIHSE_DHT_HOST_MAX,
                 "%s", best[i].host);
        memcpy(e + QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_DHT_HOST_MAX,
               &best[i].port, 2u);
    }
    return qihse_cluster_bus_send_frame(bus, QIHSE_BUS_MSG_DHT_NODES, payload, len,
                                        host, port);
}

bool qihse_overlay_dht_handle_find(struct qihse_cluster_bus* bus,
                                   const qihse_cluster_topology_t* topology,
                                   const uint8_t* payload, size_t payload_len) {
    overlay_dht_t* d = overlay_dht_ref(bus);
    if (!d) return false; /* DHT not enabled for this bus: drop, fail closed */
    if (!topology) {
        overlay_dht_unref(d);
        return false;
    }
    bool served = false;
    overlay_dht_find_t f;
    overlay_dht_parse_t pr = overlay_dht_parse_find(payload, payload_len, &f);
    if (pr != OVERLAY_DHT_OK) {
        overlay_dht_note_reject(d, true, pr);
        goto done;
    }
    /* A query from ourselves, or one we cannot answer, is not served. */
    if (strcmp(f.requester_id, d->node_id) == 0) {
        overlay_dht_note_reject(d, true, OVERLAY_DHT_MALFORMED);
        goto done;
    }
    {
        uint8_t target[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
        if (!overlay_dht_id_bytes(f.target_id, target)) {
            overlay_dht_note_reject(d, true, OVERLAY_DHT_MALFORMED);
            goto done;
        }
        if (!overlay_dht_serve_budget(d)) goto done; /* already counted */
        size_t want = f.max_peers;
        if (want == 0u || want > QIHSE_DHT_K) want = QIHSE_DHT_K;
        overlay_dht_candidate_t best[QIHSE_DHT_K];
        size_t count = 0;
        memset(best, 0, sizeof best);
        overlay_dht_collect_closest(topology, f.requester_id, target, best, &count, want);
        served = overlay_dht_send_nodes(bus, d, f.requester_host, f.requester_port,
                                        best, count);
        pthread_mutex_lock(&d->lock);
        if (served) d->stats.finds_served++;
        pthread_mutex_unlock(&d->lock);
    }
done:
    overlay_dht_unref(d);
    return served;
}

bool qihse_overlay_dht_handle_nodes(struct qihse_cluster_bus* bus,
                                    const uint8_t* payload, size_t payload_len) {
    overlay_dht_t* d = overlay_dht_ref(bus);
    if (!d) return false; /* DHT not enabled for this bus: drop, fail closed */
    bool accepted = false;
    overlay_dht_nodes_t n;
    overlay_dht_parse_t pr = overlay_dht_parse_nodes(payload, payload_len, &n);
    if (pr != OVERLAY_DHT_OK) {
        overlay_dht_note_reject(d, false, pr);
        goto done;
    }
    /* A reply claiming to come from us is not a reply. */
    if (strcmp(n.responder_id, d->node_id) == 0) {
        overlay_dht_note_reject(d, false, OVERLAY_DHT_MALFORMED);
        goto done;
    }
    {
        struct {
            char host[QIHSE_DHT_HOST_MAX];
            uint16_t port;
        } dial[QIHSE_DHT_K];
        size_t dial_count = 0;

        pthread_mutex_lock(&d->lock);
        uint64_t now = overlay_mono_ms();
        if (now - d->hint_window_ms >= QIHSE_DHT_HINT_WINDOW_MS) {
            d->hint_window_ms = now;
            d->hint_window_count = 0;
        }
        if (now - d->dial_window_ms >= QIHSE_DHT_DIAL_WINDOW_MS) {
            d->dial_window_ms = now;
            d->dial_window_count = 0;
        }
        for (uint8_t i = 0; i < n.count; i++) {
            const overlay_dht_entry_t* e = &n.entries[i];
            if (strcmp(e->id, d->node_id) == 0 ||
                (e->port == d->advertise_port &&
                 strcmp(e->host, d->advertise_host) == 0)) {
                d->stats.hints_self++;
                continue;
            }
            /* Bound the WORK first: a dedupe scan and (with a trust context) a
             * durable lookup per entry must not be free. */
            if (d->hint_window_count >= QIHSE_DHT_HINT_MAX_PER_WINDOW) {
                d->stats.hints_rate_limited++;
                continue;
            }
            d->hint_window_count++;
            if (overlay_dht_hint_known_locked(d, e->id, e->host, e->port)) {
                d->stats.hints_duplicate++;
                continue;
            }
            if (overlay_dht_revoked(d, e->id)) {
                d->stats.hints_revoked++;
                continue;
            }
            if (d->dial_window_count >= QIHSE_DHT_DIAL_MAX_PER_WINDOW) {
                d->stats.hints_rate_limited++;
                continue;
            }
            overlay_dht_hint_store_locked(d, e->id, e->host, e->port, now);
            d->dial_window_count++;
            d->stats.hints_dialed++;
            snprintf(dial[dial_count].host, sizeof dial[dial_count].host, "%s",
                     e->host);
            dial[dial_count].port = e->port;
            dial_count++;
        }
        d->stats.nodes_accepted++;
        pthread_mutex_unlock(&d->lock);

        /* THE HINT GATE, outside the lock (a bus call must never run under the
         * DHT lock).  This loop is the entire outward effect of a DHT record:
         * a bounded number of dials, and nothing else. */
        for (size_t i = 0; i < dial_count; i++) {
            (void)overlay_dial_hint(bus, dial[i].host, dial[i].port);
        }
    }
    accepted = true;
done:
    overlay_dht_unref(d);
    return accepted;
}

bool qihse_overlay_dht_query(struct qihse_cluster_bus* bus, const char* host,
                             uint16_t port, const char* target_id) {
    overlay_dht_t* d = overlay_dht_ref(bus);
    if (!d) return false;
    bool sent = false;
    uint8_t scratch[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
    if (!overlay_dht_id_bytes(target_id, scratch)) goto done;
    if (!overlay_dht_host_dialable(host) || port == 0) goto done;
    if (!overlay_dht_host_dialable(d->advertise_host) || d->advertise_port == 0) {
        OVERLAY_LOG("dht query: no dialable advertise endpoint to be answered at");
        goto done;
    }
    {
        uint8_t payload[QIHSE_DHT_FIND_PAYLOAD_SIZE];
        memset(payload, 0, sizeof payload);
        payload[0] = QIHSE_DHT_FRAME_VERSION;
        payload[1] = 0u;
        payload[2] = (uint8_t)QIHSE_DHT_K;
        payload[3] = 0u;
        uint64_t ts = overlay_realtime_ms();
        memcpy(payload + 4u, &ts, 8u);
        memcpy(payload + 12u, &d->advertise_port, 2u);
        memcpy(payload + 14u, d->node_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        memcpy(payload + 55u, target_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        snprintf((char*)(payload + 96u), QIHSE_DHT_HOST_MAX, "%s",
                 d->advertise_host);
        sent = qihse_cluster_bus_send_frame(bus, QIHSE_BUS_MSG_DHT_FIND, payload,
                                            sizeof payload, host, port);
    }
done:
    overlay_dht_unref(d);
    return sent;
}

bool qihse_overlay_dht_start(const qihse_overlay_dht_config_t* config) {
    if (!config || !config->bus || !config->node_id || !config->advertise_host) {
        return false;
    }
    uint8_t scratch[QIHSE_CLUSTER_NODE_ID_LEN / 2u];
    if (!overlay_dht_id_bytes(config->node_id, scratch)) {
        OVERLAY_LOG("dht start: node_id must be 40 lowercase hex chars");
        return false;
    }
    if (!overlay_dht_host_literal(config->advertise_host)) {
        OVERLAY_LOG("dht start: advertise_host \"%s\" is not an IPv4 literal",
                    config->advertise_host);
        return false;
    }
    if (config->advertise_port == 0) {
        OVERLAY_LOG("dht start: advertise_port must be non-zero");
        return false;
    }

    overlay_dht_t* d = calloc(1, sizeof *d);
    if (!d) return false;
    if (pthread_mutex_init(&d->lock, NULL) != 0) {
        free(d);
        return false;
    }
    snprintf(d->node_id, sizeof d->node_id, "%s", config->node_id);
    snprintf(d->advertise_host, sizeof d->advertise_host, "%s",
             config->advertise_host);
    d->advertise_port = config->advertise_port;
    d->bus = config->bus;
    d->federation_store = config->federation_store;
    d->federation_user = config->federation_user;

    pthread_mutex_lock(&g_dht_lock);
    if (g_dht) {
        pthread_mutex_unlock(&g_dht_lock);
        pthread_mutex_destroy(&d->lock);
        free(d);
        return false; /* singleton per process, like the overlay itself */
    }
    g_dht = d;
    pthread_mutex_unlock(&g_dht_lock);

    OVERLAY_LOG("dht up: node %.12s advertising %s:%u (k=%u, hints<=%u, "
                "serve<=%u/s, dial<=%u/s)",
                d->node_id, d->advertise_host, (unsigned)d->advertise_port,
                (unsigned)QIHSE_DHT_K, (unsigned)QIHSE_DHT_MAX_HINTS,
                (unsigned)QIHSE_DHT_SERVE_MAX_PER_WINDOW,
                (unsigned)QIHSE_DHT_DIAL_MAX_PER_WINDOW);
    return true;
}

void qihse_overlay_dht_stop(void) {
    pthread_mutex_lock(&g_dht_lock);
    overlay_dht_t* d = g_dht;
    g_dht = NULL;
    pthread_mutex_unlock(&g_dht_lock);
    if (!d) return;

    /* Bounded wait for in-flight handlers (they run on the bus thread).  If
     * one does not finish we leak rather than free under a live thread — the
     * same discipline qihse_overlay_stop() uses. */
    for (int i = 0; i < 500; i++) {
        if (__atomic_load_n(&d->refs, __ATOMIC_ACQUIRE) == 0u) break;
        struct timespec ts = { 0, 10000000L }; /* 10 ms */
        nanosleep(&ts, NULL);
    }
    if (__atomic_load_n(&d->refs, __ATOMIC_ACQUIRE) != 0u) {
        OVERLAY_LOG("dht stop: handler still running; leaking state");
        return;
    }
    pthread_mutex_destroy(&d->lock);
    free(d);
}

bool qihse_overlay_dht_enabled(void) {
    pthread_mutex_lock(&g_dht_lock);
    bool enabled = g_dht != NULL;
    pthread_mutex_unlock(&g_dht_lock);
    return enabled;
}

size_t qihse_overlay_dht_hints(qihse_overlay_dht_hint_t* out, size_t capacity) {
    pthread_mutex_lock(&g_dht_lock);
    overlay_dht_t* d = g_dht;
    if (d) __atomic_add_fetch(&d->refs, 1u, __ATOMIC_ACQ_REL);
    pthread_mutex_unlock(&g_dht_lock);
    if (!d) return 0;
    size_t count = 0;
    pthread_mutex_lock(&d->lock);
    count = d->hint_count;
    if (out) {
        size_t copied = 0;
        for (size_t i = 0; i < QIHSE_DHT_MAX_HINTS && copied < capacity; i++) {
            if (d->hints[i].id[0] == '\0') continue;
            out[copied++] = d->hints[i];
        }
    }
    pthread_mutex_unlock(&d->lock);
    overlay_dht_unref(d);
    return count;
}

void qihse_overlay_dht_stats(qihse_overlay_dht_stats_t* out_stats) {
    if (!out_stats) return;
    memset(out_stats, 0, sizeof *out_stats);
    pthread_mutex_lock(&g_dht_lock);
    overlay_dht_t* d = g_dht;
    if (d) __atomic_add_fetch(&d->refs, 1u, __ATOMIC_ACQ_REL);
    pthread_mutex_unlock(&g_dht_lock);
    if (!d) return;
    pthread_mutex_lock(&d->lock);
    *out_stats = d->stats;
    pthread_mutex_unlock(&d->lock);
    overlay_dht_unref(d);
}

/* ── inbound record handling ─────────────────────────────────────────── */

static void overlay_handle_record(overlay_t* o, const char* token) {
    size_t b64_len = strlen(token);
    if (b64_len == 0 || b64_len > OVERLAY_MAX_B64) {
        o->stats.records_malformed++;
        return;
    }

    /* +1 so the JSON body can be NUL-terminated for parsing. */
    uint8_t bin[OVERLAY_MAX_BIN + 1u];
    size_t bin_len = 0;
    if (!overlay_b64_decode(token, b64_len, bin, OVERLAY_MAX_BIN, &bin_len)) {
        o->stats.records_malformed++;
        OVERLAY_LOG("dropped record: not valid base64");
        return;
    }
    if (bin_len < QIHSE_OVERLAY_HMAC_SIZE + 2u) {
        o->stats.records_malformed++;
        OVERLAY_LOG("dropped record: too short (%zu bytes)", bin_len);
        return;
    }
    bin[bin_len] = '\0';

    /* Wire format: HMAC-SHA-384(password, json) || json.  Constant-time
     * verify BEFORE any parse/state change: an unauthenticated record must
     * not influence the cluster in any way. */
    uint8_t expected[QIHSE_OVERLAY_HMAC_SIZE];
    overlay_hmac_sha384(o->hmac_password, bin + QIHSE_OVERLAY_HMAC_SIZE,
                        bin_len - QIHSE_OVERLAY_HMAC_SIZE, expected);
    if (CRYPTO_memcmp(expected, bin, QIHSE_OVERLAY_HMAC_SIZE) != 0) {
        o->stats.records_bad_hmac++;
        OVERLAY_LOG("dropped record: bad HMAC (%zu byte body)",
                    bin_len - QIHSE_OVERLAY_HMAC_SIZE);
        return;
    }
    o->stats.records_verified++;

    const char* json = (const char*)bin + QIHSE_OVERLAY_HMAC_SIZE;
    char ep_spec[QIHSE_CLUSTER_HOST_LEN + 8u];
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint64_t ts = 0;
    uint64_t bus64 = 0;
    if (!overlay_json_string(json, "ep", ep_spec, sizeof ep_spec) ||
        !overlay_json_string(json, "id", id, sizeof id) ||
        !overlay_json_u64(json, "ts", &ts)) {
        o->stats.records_malformed++;
        OVERLAY_LOG("dropped record: missing ep/id/ts fields");
        return;
    }
    uint16_t ep_port = 0;
    if (!overlay_split_host_port(ep_spec, &ep_port)) {
        o->stats.records_malformed++;
        OVERLAY_LOG("dropped record: bad ep field");
        return;
    }
    uint16_t bus_port = ep_port;
    if (overlay_json_u64(json, "bus", &bus64) && bus64 > 0 &&
        bus64 <= 65535ull) {
        bus_port = (uint16_t)bus64; /* the bus field is the MEET target */
    }

    /* Freshness: reject anything outside the ±5 min replay window. */
    int64_t delta = (int64_t)overlay_realtime_ms() - (int64_t)ts;
    if (delta < 0) delta = -delta;
    if ((uint64_t)delta > QIHSE_OVERLAY_FRESHNESS_MS) {
        o->stats.records_stale++;
        OVERLAY_LOG("dropped record: stale by %lld ms (node %.12s)",
                    (long long)delta, id);
        return;
    }

    /* Never MEET ourselves (by node id or by advertised endpoint). */
    if (strcmp(id, o->node_id) == 0) return;
    if (strcmp(ep_spec, o->bind_host) == 0 && bus_port == o->bind_port) return;

    overlay_consider_meet(o, id, ep_spec, bus_port);
}

static void overlay_handle_privmsg(overlay_t* o, char* text) {
    /* Tokenise on spaces; each literal "QIHSE1" token is followed by its
     * base64 blob.  A QIHSE1 string inside a blob cannot false-positive
     * because tokens are space-delimited. */
    char* prev = NULL;
    char* p = text;
    while (p) {
        char* tok = p;
        char* sp = strchr(p, ' ');
        if (sp) {
            *sp = '\0';
            p = sp + 1;
        } else {
            p = NULL;
        }
        if (prev && strcmp(prev, QIHSE_OVERLAY_RECORD_PREFIX) == 0) {
            overlay_handle_record(o, tok);
        }
        prev = tok;
    }
}

/* ── IRC session ─────────────────────────────────────────────────────── */

typedef struct {
    int fd;
    char nick[OVERLAY_NICK_MAX + 2u];
    int nick_attempts;
    bool joined;
    bool drop;
    uint64_t next_advertise_ms;
    char line_buf[2048];
    size_t fill;
} overlay_session_t;

static bool overlay_send_line(overlay_session_t* s, const char* fmt, ...) {
    char out[576];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, sizeof out, fmt, ap);
    va_end(ap);
    if (n <= 0 || (size_t)n >= sizeof out) return false;
    if (!overlay_send_all(s->fd, out, (size_t)n)) {
        s->drop = true;
        return false;
    }
    return true;
}

static void overlay_advertise(overlay_t* o, overlay_session_t* s) {
    char json[OVERLAY_MAX_JSON];
    int jn = snprintf(json, sizeof json,
                      "{\"ep\":\"%s:%u\",\"bus\":%u,\"id\":\"%s\",\"ts\":%llu}",
                      o->bind_host, (unsigned)o->bind_port,
                      (unsigned)o->bind_port, o->node_id,
                      (unsigned long long)overlay_realtime_ms());
    if (jn <= 0 || (size_t)jn >= sizeof json) return;

    uint8_t bin[OVERLAY_MAX_JSON + QIHSE_OVERLAY_HMAC_SIZE];
    overlay_hmac_sha384(o->hmac_password, (const uint8_t*)json, (size_t)jn, bin);
    memcpy(bin + QIHSE_OVERLAY_HMAC_SIZE, json, (size_t)jn);
    size_t bin_len = (size_t)jn + QIHSE_OVERLAY_HMAC_SIZE;

    char b64[overlay_b64_encoded_size(sizeof bin) + 1u];
    overlay_b64_encode(bin, bin_len, b64, sizeof b64);

    /* Respect the IRC 512-byte line cap; skip rather than send a record the
     * server would truncate (lab hosts are short so this never fires). */
    size_t need = 8u + strlen(o->irc_channel) + 2u +
                  strlen(QIHSE_OVERLAY_RECORD_PREFIX) + 1u + strlen(b64) + 2u;
    if (need > 512u) {
        static bool warned = false;
        if (!warned) {
            OVERLAY_LOG("advertise record is %zu B (IRC limit 512); skipped",
                        need);
            warned = true;
        }
        return;
    }
    if (overlay_send_line(s, "PRIVMSG %s :%s %s\r\n",
                          o->irc_channel, QIHSE_OVERLAY_RECORD_PREFIX, b64)) {
        o->stats.advertises_sent++;
    }
}

static void overlay_handle_line(overlay_t* o, overlay_session_t* s,
                                char* line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1u] == '\r' || line[len - 1u] == '\n')) {
        line[--len] = '\0';
    }
    if (len == 0) return;

    /* "[":" prefix SPACE ] command SPACE params(":" trailing) */
    char* p = line;
    if (*p == ':') {
        char* sp = strchr(p, ' ');
        if (!sp) return;
        p = sp + 1;
    }
    char* cmd = p;
    char* sp = strchr(p, ' ');
    if (sp) {
        *sp = '\0';
        p = sp + 1;
    } else {
        p = NULL;
    }

    if (strcmp(cmd, "PING") == 0) {
        const char* tok = p ? p : "";
        if (*tok == ':') tok++;
        overlay_send_line(s, "PONG %s\r\n", tok);
        return;
    }
    if (strcmp(cmd, "ERROR") == 0) {
        OVERLAY_LOG("server ERROR: %s", p ? p : "");
        s->drop = true;
        return;
    }
    if (strcmp(cmd, "PRIVMSG") == 0 && p) {
        char* sp2 = strchr(p, ' ');
        if (!sp2) return;
        char* text = sp2 + 1;
        if (*text == ':') text++;
        *sp2 = '\0'; /* target unused: the HMAC is the gate, not the channel */
        overlay_handle_privmsg(o, text);
        return;
    }
    if (strcmp(cmd, "001") == 0) { /* RPL_WELCOME */
        OVERLAY_LOG("registered as %s; joining %s", s->nick, o->irc_channel);
        if (overlay_send_line(s, "JOIN %s\r\n", o->irc_channel)) {
            s->joined = true;
            s->next_advertise_ms = 0; /* beacon immediately for NAT rendezvous */
        }
        return;
    }
    if (strcmp(cmd, "433") == 0) { /* ERR_NICKNAMEINUSE */
        static const char kSuffix[] = "0123456789abcdefghijklmnopqrstuvwxyz";
        if (s->nick_attempts >= (int)(sizeof kSuffix - 2u)) {
            OVERLAY_LOG("nick collisions persist; reconnecting");
            s->drop = true;
            return;
        }
        s->nick_attempts++;
        snprintf(s->nick, sizeof s->nick, "%s%c", o->nick_base,
                 kSuffix[s->nick_attempts - 1]);
        if (overlay_send_line(s, "NICK %s\r\n", s->nick)) {
            OVERLAY_LOG("nick in use; retrying as %s", s->nick);
        }
        return;
    }
}

/* ── thread body ─────────────────────────────────────────────────────── */

static void* overlay_main(void* argument) {
    overlay_t* o = (overlay_t*)argument;

    overlay_session_t sess;
    memset(&sess, 0, sizeof sess);
    sess.fd = -1;
    snprintf(sess.nick, sizeof sess.nick, "%s", o->nick_base);

    char rbuf[2048];
    OVERLAY_LOG("thread up: server %s:%u channel %s node %.12s",
                o->irc_host, (unsigned)o->irc_port, o->irc_channel, o->node_id);

    while (__atomic_load_n(&o->running, __ATOMIC_ACQUIRE)) {
        if (sess.fd < 0) {
            OVERLAY_LOG("connecting to %s:%u", o->irc_host,
                        (unsigned)o->irc_port);
            sess.fd = overlay_connect_tcp(o->irc_host, o->irc_port,
                                          OVERLAY_CONNECT_TIMEOUT_MS);
            if (sess.fd < 0) {
                OVERLAY_LOG("connect to %s:%u failed; retrying",
                            o->irc_host, (unsigned)o->irc_port);
                if (!overlay_sleep_slices(o, OVERLAY_RECONNECT_DELAY_MS)) break;
                continue;
            }
            sess.joined = false;
            sess.drop = false;
            sess.fill = 0;
            sess.nick_attempts = 0;
            sess.next_advertise_ms = 0;
            snprintf(sess.nick, sizeof sess.nick, "%s", o->nick_base);
            if (!overlay_send_line(&sess, "NICK %s\r\n", sess.nick) ||
                !overlay_send_line(&sess,
                                   "USER qihse-overlay 0 * :qihse-fabric\r\n")) {
                close(sess.fd);
                sess.fd = -1;
                continue;
            }
        }

        /* Deadline-driven beacon: advertise right after JOIN, then every
         * QIHSE_OVERLAY_ADVERTISE_MS. */
        uint64_t now = overlay_mono_ms();
        int timeout = OVERLAY_POLL_SLICE_MS;
        if (sess.joined) {
            int64_t until = sess.next_advertise_ms
                                ? (int64_t)sess.next_advertise_ms - (int64_t)now
                                : 0;
            if (until <= 0) {
                overlay_advertise(o, &sess);
                if (sess.drop) {
                    close(sess.fd);
                    sess.fd = -1;
                    continue;
                }
                sess.next_advertise_ms = now + QIHSE_OVERLAY_ADVERTISE_MS;
                continue;
            }
            if (until < timeout) timeout = (int)until;
        }

        int pr = overlay_wait_readable(sess.fd, timeout);
        if (!__atomic_load_n(&o->running, __ATOMIC_ACQUIRE)) break;
        if (pr < 0) {
            OVERLAY_LOG("connection lost (%s:%u)", o->irc_host,
                        (unsigned)o->irc_port);
            close(sess.fd);
            sess.fd = -1;
            continue;
        }
        if (pr > 0) {
            int n = (int)recv(sess.fd, rbuf, sizeof rbuf, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                OVERLAY_LOG("disconnected from %s:%u", o->irc_host,
                            (unsigned)o->irc_port);
                close(sess.fd);
                sess.fd = -1;
                continue;
            }
            for (int i = 0; i < n; i++) {
                char c = rbuf[i];
                if (c == '\n') {
                    sess.line_buf[sess.fill] = '\0';
                    overlay_handle_line(o, &sess, sess.line_buf);
                    sess.fill = 0;
                    if (sess.drop ||
                        !__atomic_load_n(&o->running, __ATOMIC_ACQUIRE)) {
                        break;
                    }
                } else if (c != '\r') {
                    if (sess.fill + 1u >= sizeof sess.line_buf) {
                        sess.fill = 0; /* oversized line: drop it whole */
                    } else {
                        sess.line_buf[sess.fill++] = c;
                    }
                }
            }
        }
        if (sess.drop) {
            close(sess.fd);
            sess.fd = -1;
        }
    }

    if (sess.fd >= 0) close(sess.fd);
    OVERLAY_LOG("thread exit: %llu verified, %llu bad-HMAC, %llu stale, "
                "%llu malformed, %llu MEETs sent, %llu beacons",
                (unsigned long long)o->stats.records_verified,
                (unsigned long long)o->stats.records_bad_hmac,
                (unsigned long long)o->stats.records_stale,
                (unsigned long long)o->stats.records_malformed,
                (unsigned long long)o->stats.meets_sent,
                (unsigned long long)o->stats.advertises_sent);

    pthread_mutex_lock(&o->exit_lock);
    __atomic_store_n(&o->thread_exited, true, __ATOMIC_RELEASE);
    pthread_cond_signal(&o->exit_cond);
    pthread_mutex_unlock(&o->exit_lock);
    return NULL;
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

static bool overlay_valid_hex_id(const char* id) {
    size_t len = strlen(id);
    if (len < 8u || len > QIHSE_CLUSTER_NODE_ID_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

bool qihse_overlay_start(const qihse_overlay_config_t* config) {
    if (!config) return false;

    pthread_mutex_lock(&g_overlay_lock);
    bool already = g_overlay &&
                   __atomic_load_n(&g_overlay->running, __ATOMIC_ACQUIRE);
    pthread_mutex_unlock(&g_overlay_lock);
    if (already) return true;

    /* Validate the full config before allocating anything. */
    if (!config->irc_server || !*config->irc_server ||
        !config->irc_channel || !*config->irc_channel ||
        !config->nick_prefix || !*config->nick_prefix ||
        !config->node_id || !*config->node_id ||
        !config->bind_host || !*config->bind_host ||
        !config->hmac_password || !*config->hmac_password ||
        !config->bus) {
        OVERLAY_LOG("start: missing required config field");
        return false;
    }
    if (strlen(config->irc_channel) >= OVERLAY_CHANNEL_MAX ||
        strlen(config->nick_prefix) + 8u >= OVERLAY_NICK_MAX ||
        !overlay_valid_hex_id(config->node_id) ||
        strlen(config->bind_host) > QIHSE_CLUSTER_HOST_LEN ||
        strlen(config->hmac_password) >= OVERLAY_PASSWORD_MAX) {
        OVERLAY_LOG("start: config field out of range "
                    "(channel<%u, prefix<%u, node_id hex 8..%u, host<=%u, "
                    "password<%u)",
                    (unsigned)OVERLAY_CHANNEL_MAX, (unsigned)OVERLAY_NICK_MAX,
                    (unsigned)QIHSE_CLUSTER_NODE_ID_LEN,
                    (unsigned)QIHSE_CLUSTER_HOST_LEN,
                    (unsigned)OVERLAY_PASSWORD_MAX);
        return false;
    }
    if (config->irc_channel[0] != '#' && config->irc_channel[0] != '&') {
        OVERLAY_LOG("start: irc_channel must start with '#' or '&'");
        return false;
    }
    if (config->bind_port == 0) {
        OVERLAY_LOG("start: bind_port must be non-zero");
        return false;
    }

    overlay_t* o = calloc(1, sizeof *o);
    if (!o) return false;

    /* Parse "host:port" (port optional -> plain-IRC default). */
    {
        char spec[QIHSE_CLUSTER_HOST_LEN + 8u];
        snprintf(spec, sizeof spec, "%s", config->irc_server);
        if (!overlay_split_host_port(spec, &o->irc_port)) {
            if (strlen(spec) == 0) {
                OVERLAY_LOG("start: bad irc_server \"%s\"", config->irc_server);
                OPENSSL_cleanse(o->hmac_password, sizeof o->hmac_password);
                free(o);
                return false;
            }
            o->irc_port = OVERLAY_IRC_DEFAULT_PORT; /* no usable ":port" */
        }
        snprintf(o->irc_host, sizeof o->irc_host, "%s", spec);
    }
    snprintf(o->irc_channel, sizeof o->irc_channel, "%s", config->irc_channel);
    snprintf(o->nick_base, sizeof o->nick_base, "%s%.8s", config->nick_prefix,
             config->node_id);
    snprintf(o->node_id, sizeof o->node_id, "%s", config->node_id);
    snprintf(o->bind_host, sizeof o->bind_host, "%s", config->bind_host);
    o->bind_port = config->bind_port;
    snprintf(o->hmac_password, sizeof o->hmac_password, "%s",
             config->hmac_password);
    o->bus = config->bus;

    if (pthread_mutex_init(&o->exit_lock, NULL) != 0) {
        OPENSSL_cleanse(o->hmac_password, sizeof o->hmac_password);
        free(o);
        return false;
    }
    if (pthread_cond_init(&o->exit_cond, NULL) != 0) {
        pthread_mutex_destroy(&o->exit_lock);
        OPENSSL_cleanse(o->hmac_password, sizeof o->hmac_password);
        free(o);
        return false;
    }

    /* Publish under the singleton lock and spawn the thread while holding
     * it, so a concurrent start()/stop() can never observe a half-built
     * overlay or race a second thread into existence. */
    __atomic_store_n(&o->running, true, __ATOMIC_RELEASE);
    pthread_mutex_lock(&g_overlay_lock);
    if (g_overlay && __atomic_load_n(&g_overlay->running, __ATOMIC_ACQUIRE)) {
        /* Another start raced us to it; discard our (thread-less) copy. */
        pthread_mutex_unlock(&g_overlay_lock);
        pthread_cond_destroy(&o->exit_cond);
        pthread_mutex_destroy(&o->exit_lock);
        OPENSSL_cleanse(o->hmac_password, sizeof o->hmac_password);
        free(o);
        return true;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, overlay_main, o) != 0) {
        g_overlay = NULL; /* never published a live overlay */
        pthread_mutex_unlock(&g_overlay_lock);
        __atomic_store_n(&o->running, false, __ATOMIC_RELEASE);
        pthread_cond_destroy(&o->exit_cond);
        pthread_mutex_destroy(&o->exit_lock);
        OPENSSL_cleanse(o->hmac_password, sizeof o->hmac_password);
        free(o);
        OVERLAY_LOG("start: pthread_create failed");
        return false;
    }
    g_overlay = o;
    pthread_mutex_unlock(&g_overlay_lock);
    pthread_detach(thread); /* detached per spec; stop() waits via exit_cond */

    /* Layer 3 comes up with the overlay unless the operator turned it off.
     * It is best-effort: a deployment whose advertise host is not a dialable
     * IPv4 literal keeps the IRC bootstrap and simply has no DHT. */
    if (!config->disable_dht) {
        qihse_overlay_dht_config_t dcfg;
        memset(&dcfg, 0, sizeof dcfg);
        dcfg.node_id = o->node_id;
        dcfg.advertise_host = o->bind_host;
        dcfg.advertise_port = o->bind_port;
        dcfg.bus = o->bus;
        if (qihse_overlay_dht_start(&dcfg)) {
            pthread_mutex_lock(&g_overlay_lock);
            g_overlay_dht_owned = true;
            pthread_mutex_unlock(&g_overlay_lock);
        } else {
            OVERLAY_LOG("DHT peer exchange not started; IRC bootstrap continues");
        }
    }

    OVERLAY_LOG("started: nick %s advertising %s:%u via %s:%u", o->nick_base,
                o->bind_host, (unsigned)o->bind_port, o->irc_host,
                (unsigned)o->irc_port);
    return true;
}

void qihse_overlay_stop(void) {
    pthread_mutex_lock(&g_overlay_lock);
    overlay_t* o = g_overlay;
    bool owned_dht = g_overlay_dht_owned;
    g_overlay = NULL;
    g_overlay_dht_owned = false;
    pthread_mutex_unlock(&g_overlay_lock);
    if (!o) return;

    __atomic_store_n(&o->running, false, __ATOMIC_RELEASE);

    /* Bounded wait: the thread checks the flag at least every
     * OVERLAY_POLL_SLICE_MS.  getaddrinfo during (re)connect is the one
     * unbounded call; if we exceed the deadline we leak the state instead
     * of freeing it under a live thread. */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    pthread_mutex_lock(&o->exit_lock);
    while (!__atomic_load_n(&o->thread_exited, __ATOMIC_ACQUIRE)) {
        if (pthread_cond_timedwait(&o->exit_cond, &o->exit_lock,
                                   &deadline) == ETIMEDOUT) {
            break;
        }
    }
    bool exited = __atomic_load_n(&o->thread_exited, __ATOMIC_ACQUIRE);
    pthread_mutex_unlock(&o->exit_lock);

    if (!exited) {
        OVERLAY_LOG("stop: thread did not exit within 5 s; leaking state");
        return;
    }
    pthread_cond_destroy(&o->exit_cond);
    pthread_mutex_destroy(&o->exit_lock);
    OPENSSL_cleanse(o->hmac_password, sizeof o->hmac_password);
    free(o);

    /* Only stop layer 3 if this call started it: an application that enabled
     * the DHT itself keeps ownership of it. */
    if (owned_dht) qihse_overlay_dht_stop();
}
