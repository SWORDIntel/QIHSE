#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "include/qihse_qkp.h"
#include "include/qihse_auth.h"

typedef struct {
    int fd;
    qihse_qkp_config_t qkp_config;
    qihse_qkp_session_t* qkp;
    uint8_t buf[65536];
    size_t buf_pos;
    size_t buf_len;
    char last[256];
    char err[128];
} mini_resp_t;

#define MINI_REP_SIMPLE 1
#define MINI_REP_BULK   2
#define MINI_REP_ARRAY  3
#define MINI_REP_ERROR  4

static bool socket_send_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t w = send(fd, p + done, len - done, MSG_NOSIGNAL);
        if (w <= 0) return false;
        done += (size_t)w;
    }
    return true;
}

static bool socket_recv_all(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t r = recv(fd, p + done, len - done, 0);
        if (r <= 0) return false;
        done += (size_t)r;
    }
    return true;
}

static int connect_i2p_socks5(const char* host, uint16_t port, uint16_t socks_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
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
        reply[0] != 0x05u || reply[1] != 0x00u) { close(fd); return -1; }
    size_t bound_len = 0u;
    if (reply[3] == 0x01u) bound_len = 4u;
    else if (reply[3] == 0x04u) bound_len = 16u;
    else if (reply[3] == 0x03u) {
        uint8_t n = 0u;
        if (!socket_recv_all(fd, &n, 1u)) { close(fd); return -1; }
        bound_len = n;
    } else { close(fd); return -1; }
    uint8_t discard[18u];
    if (!socket_recv_all(fd, discard, bound_len + 2u)) { close(fd); return -1; }
    return fd;
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
        buf[used++] = ch;
    }
    return -1;
}

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

static void mini_resp_free_array(char** items, size_t count) {
    if (!items) return;
    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
}

static int mini_resp_do(mini_resp_t* c, size_t argc, const char* const* argv,
                        char** out_value, size_t* out_value_len,
                        char*** out_items, size_t* out_count) {
    if (out_value) *out_value = NULL;
    if (out_value_len) *out_value_len = 0u;
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
    if (line[0] == ':') {
        snprintf(c->last, sizeof(c->last), "%s", line);
        return MINI_REP_SIMPLE;
    }
    if (line[0] == '$') {
        long long len = strtoll(line + 1, NULL, 10);
        if (len < 0) {
            if (out_value) *out_value = NULL;
            return MINI_REP_BULK; /* nil */
        }
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
        if (out_value) *out_value = v; else free(v);
        if (out_value_len) *out_value_len = (size_t)len;
        return MINI_REP_BULK;
    }
    if (line[0] == '*') {
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
            if (len < 0) {
                items[i] = NULL;
                continue;
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
        if (out_items) *out_items = items; else mini_resp_free_array(items, (size_t)count);
        if (out_count) *out_count = (size_t)count;
        return MINI_REP_ARRAY;
    }
    snprintf(c->err, sizeof(c->err), "unknown reply prefix '%c'", line[0]);
    return MINI_REP_ERROR;
}

static int mini_resp_connect(mini_resp_t* c, const char* host, uint16_t port,
                             bool via_i2p, uint16_t socks_port, const qihse_qkp_config_t* qkp) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->qkp_config = *qkp;
    int fd = -1;
    if (via_i2p) {
        fd = connect_i2p_socks5(host, port, socks_port);
    } else {
        char portstr[8];
        snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
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
    if (qihse_qkp_client_negotiate(fd, &c->qkp_config, &c->qkp) != QIHSE_QKP_SECURE || !c->qkp) {
        close(fd); c->fd = -1; return -1;
    }
    return fd;
}

static void mini_resp_close(mini_resp_t* c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    if (c->qkp) qihse_qkp_session_free(c->qkp);
    c->qkp = NULL;
}

int main(int argc, char** argv) {
    const char* host = "127.0.0.1";
    uint16_t port = 7101;
    bool via_i2p = false;
    uint16_t socks_port = 4447;
    const char* node_id = "node0";
    const char* keys_dir = "/etc/qihse/keys";
    const char* peers_dir = "/opt/qihse/data/peers";
    const char* password = NULL;
    int cmd_start = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--i2p") == 0 && i + 1 < argc) { host = argv[++i]; via_i2p = true; }
        else if (strcmp(argv[i], "--socks") == 0 && i + 1 < argc) socks_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc) node_id = argv[++i];
        else if (strcmp(argv[i], "--keys-dir") == 0 && i + 1 < argc) keys_dir = argv[++i];
        else if (strcmp(argv[i], "--peers-dir") == 0 && i + 1 < argc) peers_dir = argv[++i];
        else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) password = argv[++i];
        else if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc) { cmd_start = i + 1; break; }
    }

    if (cmd_start < 0) {
        fprintf(stderr, "Usage: %s [--host H|--i2p DEST] [--port P] [--socks S] [--node-id ID] [--keys-dir D] [--peers-dir D] [--password PW] --cmd ARGS...\n", argv[0]);
        return 1;
    }

    static char s_file_pw[256];
    if (!password) {
        const char* env_pw = getenv("QIHSE_OPERATOR_PASSWORD");
        if (env_pw && *env_pw) {
            password = env_pw;
        } else {
            FILE* ef = fopen("/etc/qihse/cluster-node0.env", "r");
            if (ef) {
                char line[512];
                while (fgets(line, sizeof(line), ef)) {
                    if (strncmp(line, "QIHSE_OPERATOR_PASSWORD=", 24) == 0) {
                        char* p = line + 24;
                        p[strcspn(p, "\r\n")] = '\0';
                        if (strlen(p) >= 12 && strlen(p) < sizeof(s_file_pw)) {
                            snprintf(s_file_pw, sizeof(s_file_pw), "%s", p);
                            password = s_file_pw;
                            break;
                        }
                    }
                }
                fclose(ef);
            }
        }
    }
    if (!password) {
        fprintf(stderr, "qihse_i2p_test_cli: operator password required (--password, QIHSE_OPERATOR_PASSWORD, or /etc/qihse/cluster-node0.env)\n");
        return 1;
    }

    char dsa_path[512], kem_path[512], pub_path[512];
    snprintf(dsa_path, sizeof(dsa_path), "%s/qihse_dsa_key.pem", keys_dir);
    snprintf(kem_path, sizeof(kem_path), "%s/qihse_kem_key.pem", keys_dir);
    snprintf(pub_path, sizeof(pub_path), "%s/qihse_kem_pub.pem", keys_dir);

    char p0[512], p1[512], p2[512];
    snprintf(p0, sizeof(p0), "%s/node0.pem", peers_dir);
    snprintf(p1, sizeof(p1), "%s/node1.pem", peers_dir);
    snprintf(p2, sizeof(p2), "%s/node2.pem", peers_dir);
    const char* trusted[3] = { p0, p1, p2 };

    qihse_qkp_config_t qkp;
    memset(&qkp, 0, sizeof(qkp));
    qkp.node_id = node_id;
    qkp.dsa_key_path = dsa_path;
    qkp.kem_key_path = kem_path;
    qkp.kem_pub_path = pub_path;
    qkp.trusted_pubs = trusted;
    qkp.trusted_count = 3;

    mini_resp_t c;
    if (mini_resp_connect(&c, host, port, via_i2p, socks_port, &qkp) < 0) {
        fprintf(stderr, "Connection or QKP handshake failed to %s:%u\n", host, port);
        return 2;
    }

    // Authenticate
    const char* auth_argv[2] = { "AUTH", password };
    int r = mini_resp_do(&c, 2, auth_argv, NULL, NULL, NULL, NULL);
    if (r != MINI_REP_SIMPLE || c.last[0] != '+') {
        fprintf(stderr, "AUTH failed: %s (%s)\n", c.last, c.err);
        mini_resp_close(&c);
        return 3;
    }

    // Run command
    size_t cmd_argc = (size_t)(argc - cmd_start);
    const char** cmd_argv = (const char**)&argv[cmd_start];

    char* val = NULL;
    size_t val_len = 0;
    char** items = NULL;
    size_t item_count = 0;

    r = mini_resp_do(&c, cmd_argc, cmd_argv, &val, &val_len, &items, &item_count);
    if (r == MINI_REP_SIMPLE) {
        printf("%s\n", c.last);
    } else if (r == MINI_REP_BULK) {
        if (val) {
            printf("\"%s\"\n", val);
            free(val);
        } else {
            printf("(nil)\n");
        }
    } else if (r == MINI_REP_ARRAY) {
        for (size_t i = 0; i < item_count; i++) {
            if (items[i]) printf("%zu) \"%s\"\n", i + 1, items[i]);
            else printf("%zu) (nil)\n", i + 1);
        }
        mini_resp_free_array(items, item_count);
    } else {
        fprintf(stderr, "Command failed: %s\n", c.err);
        mini_resp_close(&c);
        return 4;
    }

    mini_resp_close(&c);
    return 0;
}
