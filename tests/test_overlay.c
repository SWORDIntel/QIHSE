/*
 * test_overlay.c — QIHSE overlay (IRC dead-drop bootstrap) unit test.
 *
 * Runs the real overlay thread against a fake in-process IRC server on
 * 127.0.0.1 (the overlay transport is plain TCP in phase 1) and a real
 * cluster bus, then asserts the security-relevant behaviour end to end:
 *
 *   1. config validation fails closed (missing fields, bad channel,
 *      non-hex node id, zero bind port) and start() is a singleton
 *   2. the node's advert is a well-formed QIHSE1 record whose HMAC-SHA-384
 *      verifies under the operator password and whose ep/id/ts are correct
 *   3. a valid peer record triggers a bus MEET to the advertised endpoint
 *   4. a forged-HMAC record is ignored (no MEET)
 *   5. a stale record (outside the +-5 min replay window) is ignored
 *
 * No absolute paths: everything binds to loopback ephemeral ports.
 */
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_overlay.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TEST_PASSWORD "overlay-test-password"
#define TEST_CHANNEL "#qihse-test"

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool wait_readable(int fd, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, timeout_ms);
    return pr > 0 && (pfd.revents & POLLIN);
}

static bool send_all(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

/* TCP listener on 127.0.0.1 with an ephemeral port. */
static int tcp_listen_ephemeral(uint16_t* port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    assert(listen(fd, 4) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    *port_out = ntohs(addr.sin_port);
    return fd;
}

/* UDP socket on 127.0.0.1 with an ephemeral port (a fake peer bus). */
static int udp_bind_ephemeral(uint16_t* port_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    *port_out = ntohs(addr.sin_port);
    return fd;
}

/* A free UDP port for the bus to bind (bind ephemeral, read, close). */
static uint16_t free_udp_port(void) {
    uint16_t port = 0;
    int fd = udp_bind_ephemeral(&port);
    close(fd);
    return port;
}

/* Buffered line reader (IRC is CRLF-delimited). */
typedef struct {
    int fd;
    char buf[4096];
    size_t fill;
} line_reader_t;

static bool reader_line(line_reader_t* r, int timeout_ms, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < r->fill; i++) {
            if (r->buf[i] == '\n') {
                size_t len = i;
                if (len > 0 && r->buf[len - 1u] == '\r') len--;
                if (len >= cap) len = cap - 1u;
                memcpy(out, r->buf, len);
                out[len] = '\0';
                memmove(r->buf, r->buf + i + 1u, r->fill - i - 1u);
                r->fill -= i + 1u;
                return true;
            }
        }
        if (!wait_readable(r->fd, timeout_ms)) return false;
        ssize_t n = recv(r->fd, r->buf + r->fill, sizeof(r->buf) - r->fill, 0);
        if (n <= 0) return false;
        r->fill += (size_t)n;
    }
}

/* ── base64 / HMAC helpers (independent of the overlay's internals) ─────── */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const uint8_t* src, size_t len, char* out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < len && o + 4u < cap; i += 3u) {
        uint32_t v = (uint32_t)src[i] << 16;
        if (i + 1u < len) v |= (uint32_t)src[i + 1u] << 8;
        if (i + 2u < len) v |= (uint32_t)src[i + 2u];
        out[o++] = B64[(v >> 18) & 63u];
        out[o++] = B64[(v >> 12) & 63u];
        out[o++] = (i + 1u < len) ? B64[(v >> 6) & 63u] : '=';
        out[o++] = (i + 2u < len) ? B64[v & 63u] : '=';
    }
    out[o] = '\0';
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_decode(const char* in, uint8_t* out, size_t cap) {
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char* p = in; *p; p++) {
        if (*p == '=') break;
        int v = b64_val(*p);
        if (v < 0) return 0;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < cap) out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

static void hmac384(const char* key, const uint8_t* data, size_t len,
                    uint8_t out[QIHSE_OVERLAY_HMAC_SIZE]) {
    unsigned int md_len = QIHSE_OVERLAY_HMAC_SIZE;
    assert(HMAC(EVP_sha384(), key, (int)strlen(key), data, len, out, &md_len));
    assert(md_len == QIHSE_OVERLAY_HMAC_SIZE);
}

/* token = base64( HMAC-SHA384(password, json) || json ) */
static void make_record_token(const char* password, const char* json, char* out,
                              size_t cap) {
    uint8_t bin[1024];
    size_t jl = strlen(json);
    assert(QIHSE_OVERLAY_HMAC_SIZE + jl < sizeof(bin));
    hmac384(password, (const uint8_t*)json, jl, bin);
    memcpy(bin + QIHSE_OVERLAY_HMAC_SIZE, json, jl);
    b64_encode(bin, QIHSE_OVERLAY_HMAC_SIZE + jl, out, cap);
}

static void send_record(int fd, const char* from, const char* token) {
    char msg[1600];
    snprintf(msg, sizeof(msg), ":%s!u@host PRIVMSG %s :QIHSE1 %s\r\n", from,
             TEST_CHANNEL, token);
    assert(send_all(fd, msg, strlen(msg)));
}

/* Expect a bus MEET datagram within the timeout. */
static bool expect_meet(int fd, int timeout_ms) {
    if (!wait_readable(fd, timeout_ms)) return false;
    uint8_t datagram[2048];
    ssize_t n = recv(fd, datagram, sizeof(datagram), 0);
    if (n < (ssize_t)QIHSE_CLUSTER_BUS_HEADER_SIZE) return false;
    uint32_t magic = 0, type = 0;
    memcpy(&magic, datagram, 4u);
    memcpy(&type, datagram + 4u, 4u);
    return magic == QIHSE_CLUSTER_BUS_MAGIC && type == QIHSE_BUS_MSG_MEET;
}

static void node_id_for(const char* seed, char out[QIHSE_CLUSTER_NODE_ID_LEN + 1u]) {
    qihse_cluster_node_id_from_seed(seed, strlen(seed), out);
}

int main(void) {
    /* ── cluster bus (the overlay's MEET sink) ─────────────────────────── */
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);
    char local_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("overlay-test-local", local_id);
    uint16_t bus_port = free_udp_port();
    qihse_cluster_node_t local;
    memset(&local, 0, sizeof(local));
    snprintf(local.id, sizeof(local.id), "%s", local_id);
    snprintf(local.host, sizeof(local.host), "127.0.0.1");
    local.port = 7100u;
    local.bus_port = bus_port;
    local.role = QIHSE_CLUSTER_NODE_PRIMARY;
    local.primary_index = QIHSE_CLUSTER_NODE_NONE;
    local.healthy = true;
    uint16_t local_idx = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topo, &local, &local_idx));
    assert(qihse_cluster_topology_set_local_node(topo, local_idx));

    qihse_cluster_bus_config_t bcfg;
    memset(&bcfg, 0, sizeof(bcfg));
    bcfg.topology = topo;
    bcfg.local_node_index = local_idx;
    bcfg.bus_port = bus_port;
    bcfg.bind_address = "127.0.0.1";
    bcfg.heartbeat_ms = 60000u;
    bcfg.timeout_ms = 60000u;
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bcfg);
    assert(bus);
    assert(qihse_cluster_bus_start(bus));

    /* ── fake IRC server + overlay config ──────────────────────────────── */
    uint16_t irc_port = 0;
    int listen_fd = tcp_listen_ephemeral(&irc_port);
    char irc_spec[64];
    snprintf(irc_spec, sizeof(irc_spec), "127.0.0.1:%u", (unsigned)irc_port);

    char overlay_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    node_id_for("overlay-test-node", overlay_id);

    qihse_overlay_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.irc_server = irc_spec;
    cfg.irc_channel = TEST_CHANNEL;
    cfg.nick_prefix = "qihse";
    cfg.node_id = overlay_id;
    cfg.bind_host = "127.0.0.1";
    cfg.bind_port = bus_port;
    cfg.hmac_password = TEST_PASSWORD;
    cfg.bus = bus;

    /* 1 — config validation fails closed, before any overlay is running. */
    assert(!qihse_overlay_start(NULL));
    qihse_overlay_config_t bad;
    memset(&bad, 0, sizeof(bad));
    assert(!qihse_overlay_start(&bad)); /* every required field missing */
    bad = cfg;
    bad.bus = NULL;
    assert(!qihse_overlay_start(&bad)); /* bus is required */
    bad = cfg;
    bad.irc_channel = "qihse-test"; /* no '#' or '&' */
    assert(!qihse_overlay_start(&bad));
    bad = cfg;
    bad.node_id = "not-hex-node-id";
    assert(!qihse_overlay_start(&bad));
    bad = cfg;
    bad.bind_port = 0;
    assert(!qihse_overlay_start(&bad));
    printf("PASS overlay config validation fails closed\n");

    /* 2 — start (singleton) and complete the IRC handshake. */
    assert(qihse_overlay_start(&cfg));
    assert(qihse_overlay_start(&cfg)); /* already running: no-op true */
    assert(wait_readable(listen_fd, 5000));
    int cfd = accept(listen_fd, NULL, NULL);
    assert(cfd >= 0);
    line_reader_t reader;
    memset(&reader, 0, sizeof(reader));
    reader.fd = cfd;

    char line[1024];
    char nick[64] = "qihse";
    bool saw_nick = false, saw_user = false;
    for (int i = 0; i < 8 && !(saw_nick && saw_user); i++) {
        assert(reader_line(&reader, 5000, line, sizeof(line)));
        if (strncmp(line, "NICK ", 5u) == 0) {
            snprintf(nick, sizeof(nick), "%s", line + 5u);
            saw_nick = true;
        } else if (strncmp(line, "USER ", 5u) == 0) {
            saw_user = true;
        }
    }
    assert(saw_nick && saw_user);
    char welcome[160];
    snprintf(welcome, sizeof(welcome), ":fake-irc 001 %s :welcome\r\n", nick);
    assert(send_all(cfd, welcome, strlen(welcome)));
    assert(reader_line(&reader, 5000, line, sizeof(line)));
    assert(strncmp(line, "JOIN ", 5u) == 0 && strstr(line, TEST_CHANNEL));

    /* 3 — the node's advert is a verifiable QIHSE1 record. */
    assert(reader_line(&reader, 5000, line, sizeof(line)));
    const char* marker = QIHSE_OVERLAY_RECORD_PREFIX " ";
    const char* token = strstr(line, marker);
    assert(token);
    token += strlen(marker);
    uint8_t bin[1024];
    size_t bin_len = b64_decode(token, bin, sizeof(bin));
    assert(bin_len > QIHSE_OVERLAY_HMAC_SIZE);
    uint8_t expected[QIHSE_OVERLAY_HMAC_SIZE];
    hmac384(TEST_PASSWORD, bin + QIHSE_OVERLAY_HMAC_SIZE,
            bin_len - QIHSE_OVERLAY_HMAC_SIZE, expected);
    assert(memcmp(expected, bin, QIHSE_OVERLAY_HMAC_SIZE) == 0);
    char json[1024];
    size_t json_len = bin_len - QIHSE_OVERLAY_HMAC_SIZE;
    memcpy(json, bin + QIHSE_OVERLAY_HMAC_SIZE, json_len);
    json[json_len] = '\0';
    assert(strstr(json, overlay_id));
    char ep_needle[64];
    snprintf(ep_needle, sizeof(ep_needle), "127.0.0.1:%u", (unsigned)bus_port);
    assert(strstr(json, ep_needle));
    printf("PASS advert record is HMAC-signed and well-formed\n");

    /* 4 — valid record -> MEET; forged -> silence; stale -> silence. */
    uint16_t peer_a = 0, peer_b = 0, peer_c = 0;
    int fd_a = udp_bind_ephemeral(&peer_a);
    int fd_b = udp_bind_ephemeral(&peer_b);
    int fd_c = udp_bind_ephemeral(&peer_c);
    char peer_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char record[512];
    char record_token[1400];

    node_id_for("overlay-test-peer-a", peer_id);
    snprintf(record, sizeof(record),
             "{\"ep\":\"127.0.0.1:%u\",\"bus\":%u,\"id\":\"%s\",\"ts\":%llu}",
             (unsigned)peer_a, (unsigned)peer_a, peer_id,
             (unsigned long long)now_ms());
    make_record_token(TEST_PASSWORD, record, record_token, sizeof(record_token));
    send_record(cfd, "peer-a", record_token);
    assert(expect_meet(fd_a, 2000));
    printf("PASS valid peer record triggers bus MEET\n");

    node_id_for("overlay-test-peer-b", peer_id);
    snprintf(record, sizeof(record),
             "{\"ep\":\"127.0.0.1:%u\",\"bus\":%u,\"id\":\"%s\",\"ts\":%llu}",
             (unsigned)peer_b, (unsigned)peer_b, peer_id,
             (unsigned long long)now_ms());
    make_record_token("wrong-password", record, record_token, sizeof(record_token));
    send_record(cfd, "peer-b", record_token);
    assert(!expect_meet(fd_b, 800));
    printf("PASS forged-HMAC record is ignored\n");

    node_id_for("overlay-test-peer-c", peer_id);
    snprintf(record, sizeof(record),
             "{\"ep\":\"127.0.0.1:%u\",\"bus\":%u,\"id\":\"%s\",\"ts\":%llu}",
             (unsigned)peer_c, (unsigned)peer_c, peer_id,
             (unsigned long long)(now_ms() - 10u * 60u * 1000u));
    make_record_token(TEST_PASSWORD, record, record_token, sizeof(record_token));
    send_record(cfd, "peer-c", record_token);
    assert(!expect_meet(fd_c, 800));
    printf("PASS stale record is ignored (replay window enforced)\n");

    /* ── teardown ──────────────────────────────────────────────────────── */
    qihse_overlay_stop();
    qihse_overlay_stop(); /* second stop is a no-op */
    close(cfd);
    close(listen_fd);
    close(fd_a);
    close(fd_b);
    close(fd_c);
    qihse_cluster_bus_stop(bus);
    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("overlay tests passed\n");
    return 0;
}
