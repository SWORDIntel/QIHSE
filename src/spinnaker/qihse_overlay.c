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

    if (qihse_cluster_bus_meet(o->bus, host, bus_port)) {
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

    OVERLAY_LOG("started: nick %s advertising %s:%u via %s:%u", o->nick_base,
                o->bind_host, (unsigned)o->bind_port, o->irc_host,
                (unsigned)o->irc_port);
    return true;
}

void qihse_overlay_stop(void) {
    pthread_mutex_lock(&g_overlay_lock);
    overlay_t* o = g_overlay;
    g_overlay = NULL;
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
}
