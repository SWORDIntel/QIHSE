/* qihse-admin-cli — administration client for QKP-hardened QIHSE masters.
 *
 * The masters reject cleartext RESP (pqc_require) once replication pins are
 * configured, so plain redis-cli can no longer reach them. This tool is the
 * supported operator path:
 *
 *   1. TCP connect + QKP1 post-quantum handshake (sealed channel);
 *   2. MACHINEAUTH <token-hex> inside the sealed session — the token is a
 *      MACHINE-purpose capability token minted by qihse-machine-token and
 *      verified by the daemon against its --pqc-trusted-pub anchors;
 *   3. one RESP command, reply printed to stdout.
 *
 * Usage:
 *   qihse-admin-cli --host 192.168.1.91 --port 7100 \
 *       --identity-dir /etc/qihse/keys \
 *       --trusted-pub /etc/qihse/keys/qihse_dsa_pub_t420.pem \
 *       --token-file /etc/qihse/admin-token.hex \
 *       --command "CLUSTER NODES"
 *
 * Exit codes: 0 ok, 2 usage/config, 3 connect/handshake, 4 auth, 5 command.
 * The token file is a bearer credential: keep it 0600 root-only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "qihse_qkp.h"
#include "qihse_fabric_dispatch.h"
#include "qihse_federation.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#define CLI_MAX_TOKEN_BYTES (QIHSE_FABRIC_TOKEN_MAX_BYTES * 2u + 64u)
#define CLI_MAX_REPLY (16u << 20)

static const char* g_host = NULL;
static uint16_t g_port = 7100;
static const char* g_identity_dir = "/etc/qihse/keys";
static const char* g_trusted_pub = NULL;
static const char* g_node_id = "admin-cli";
static const char* g_command = "PING";

static void usage(void) {
    fprintf(stderr,
        "usage: qihse-admin-cli --host H --port P --trusted-pub FILE\n"
        "       [--node-id ID] [--identity-dir DIR]\n"
        "       [--command \"CMD ARG...\"] [--ping | --cluster-nodes | --repl-status]\n"
        "\nThe master must pin this identity with\n"
        "  --admin-peer-node-id ID --admin-peer-dsa-pub FILE\n"
        "and the identity key must match the pinned pub.\n");
    exit(2);
}

static int tcp_connect(const char* host, uint16_t port) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        fprintf(stderr, "getaddrinfo(%s) failed\n", host);
        return -1;
    }
    int fd = -1;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) fprintf(stderr, "connect(%s:%u) failed: %s\n", host,
                        (unsigned)port, strerror(errno));
    return fd;
}

/* Encode argc/argv as a RESP array-of-bulk request; returns malloc'd buffer. */
static char* resp_encode_request(size_t argc, const char* const* argv,
                                 size_t* out_len) {
    size_t cap = 64u;
    for (size_t i = 0; i < argc; i++) cap += 16u + strlen(argv[i]);
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;
    size_t used = 0u;
    used += (size_t)snprintf(buf + used, cap - used, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++) {
        used += (size_t)snprintf(buf + used, cap - used, "$%zu\r\n",
                                 strlen(argv[i]));
        size_t alen = strlen(argv[i]);
        memcpy(buf + used, argv[i], alen);
        used += alen;
        memcpy(buf + used, "\r\n", 2u);
        used += 2u;
    }
    *out_len = used;
    return buf;
}

/* Read one sealed payload into a caller buffer. Returns length or -1. */
static ssize_t recv_one_frame(qihse_qkp_session_t* s, int fd, uint8_t* buf,
                              size_t cap) {
    return qihse_qkp_recv_sealed(s, fd, buf, cap);
}

/* Is the accumulated buffer a COMPLETE RESP reply? The server seals each
 * qihse_resp_write chunk as its own frame, so a single reply arrives as
 * several frames ("-", "ERR ...", "\r\n") and must be reassembled. */
static bool resp_complete(const char* p, size_t len, int depth) {
    if (depth > 8 || len == 0u) return false;
    char kind = p[0];
    if (kind == '+' || kind == '-' || kind == ':') {
        const char* eol = (const char*)memchr(p, '\r', len);
        return eol && eol + 1u < p + len && eol[1] == '\n';
    }
    if (kind == '$') {
        const char* eol = (const char*)memchr(p, '\r', len);
        if (!eol || eol + 1u >= p + len || eol[1] != '\n') return false;
        long long blen = strtoll(p + 1, NULL, 10);
        if (blen < 0) return true; /* nil */
        size_t body_start = (size_t)(eol + 2u - p);
        return body_start + (size_t)blen + 2u <= len;
    }
    if (kind == '*') {
        const char* eol = (const char*)memchr(p, '\r', len);
        if (!eol || eol + 1u >= p + len || eol[1] != '\n') return false;
        long long count = strtoll(p + 1, NULL, 10);
        if (count < 0) return true;
        size_t off = (size_t)(eol + 2u - p);
        for (long long k = 0; k < count; k++) {
            if (off >= len) return false;
            const char* sub = p + off;
            if (sub[0] == '$') {
                const char* e2 = (const char*)memchr(sub, '\r', len - off);
                if (!e2) return false;
                long long blen2 = strtoll(sub + 1, NULL, 10);
                off = (size_t)(e2 + 2u - p);
                if (blen2 >= 0) off += (size_t)blen2 + 2u;
                if (off > len) return false;
            } else if (sub[0] == ':') {
                const char* e2 = (const char*)memchr(sub, '\r', len - off);
                if (!e2) return false;
                off = (size_t)(e2 + 2u - p);
            } else {
                return false;
            }
        }
        return true;
    }
    return false;
}

/* Read sealed frames until a complete RESP reply is assembled. */
static ssize_t recv_reply(qihse_qkp_session_t* s, int fd, char** out) {
    size_t cap = 4096u;
    size_t used = 0u;
    char* buf = (char*)malloc(cap);
    if (!buf) return -1;
    for (;;) {
        uint8_t* frame = (uint8_t*)malloc(QIHSE_QKP_MAX_FRAME + 64u);
        if (!frame) { free(buf); return -1; }
        ssize_t n = recv_one_frame(s, fd, frame, QIHSE_QKP_MAX_FRAME + 64u);
        if (n <= 0) { free(frame); free(buf); return -1; }
        while (used + (size_t)n + 1u > cap) {
            size_t next = cap * 2u;
            char* grown = (char*)realloc(buf, next);
            if (!grown) { free(buf); return -1; }
            buf = grown;
            cap = next;
        }
        memcpy(buf + used, frame, (size_t)n);
        free(frame);
        used += (size_t)n;
        buf[used] = '\0';
        if (resp_complete(buf, used, 0)) break;
    }
    *out = buf;
    return (ssize_t)used;
}

/* Print a RESP reply (simple/bulk/array/integer), bounded recursion. */
static void print_resp(const char* p, size_t len, int depth) {
    if (depth > 6 || len == 0u) { printf("(unparseable)\n"); return; }
    size_t i = 0u;
    while (i < len) {
        char kind = p[i++];
        if (kind == '+' || kind == '-') {
            size_t start = i;
            while (i < len && p[i] != '\r') i++;
            printf("%.*s\n", (int)(i - start), p + start);
            if (i + 1u < len) i += 2u;
            break;
        } else if (kind == ':') {
            size_t start = i;
            while (i < len && p[i] != '\r') i++;
            printf("%.*s\n", (int)(i - start), p + start);
            if (i + 1u < len) i += 2u;
            break;
        } else if (kind == '$') {
            size_t start = i;
            while (i < len && p[i] != '\r') i++;
            long long blen = strtoll(p + start, NULL, 10);
            if (i + 1u < len) i += 2u;
            if (blen < 0) { printf("(nil)\n"); continue; }
            if (i + (size_t)blen + 2u > len) { printf("(truncated)\n"); return; }
            printf("%.*s\n", (int)blen, p + i);
            i += (size_t)blen + 2u;
        } else if (kind == '*') {
            size_t start = i;
            while (i < len && p[i] != '\r') i++;
            long long count = strtoll(p + start, NULL, 10);
            if (i + 1u < len) i += 2u;
            if (count < 0) { printf("(nil array)\n"); continue; }
            for (long long k = 0; k < count; k++) {
                if (i >= len) return;
                char c = p[i++];
                if (c == '$') {
                    size_t s2 = i;
                    while (i < len && p[i] != '\r') i++;
                    long long blen2 = strtoll(p + s2, NULL, 10);
                    if (i + 1u < len) i += 2u;
                    if (blen2 < 0) { printf("(nil)"); continue; }
                    if (i + (size_t)blen2 + 2u > len) return;
                    printf("%.*s", (int)blen2, p + i);
                    i += (size_t)blen2 + 2u;
                } else if (c == ':') {
                    size_t s2 = i;
                    while (i < len && p[i] != '\r') i++;
                    printf("%.*s", (int)(i - s2), p + s2);
                    if (i + 1u < len) i += 2u;
                } else {
                    /* rewind and recurse */
                    i--;
                    size_t sub = i;
                    /* find the end of this element (scan) */
                    int depth2 = 0;
                    while (i < len) {
                        char cc = p[i];
                        if (cc == '\r' && i + 1u < len && p[i + 1u] == '\n' &&
                            depth2 == 0) { i += 2u; break; }
                        i++;
                    }
                    print_resp(p + sub, i - sub, depth + 1);
                }
            }
            break;
        } else {
            printf("(unknown reply kind %c)\n", kind);
            break;
        }
    }
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) g_host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--identity-dir") == 0 && i + 1 < argc)
            g_identity_dir = argv[++i];
        else if (strcmp(argv[i], "--trusted-pub") == 0 && i + 1 < argc)
            g_trusted_pub = argv[++i];
        else if (strcmp(argv[i], "--node-id") == 0 && i + 1 < argc)
            g_node_id = argv[++i];
        else if (strcmp(argv[i], "--command") == 0 && i + 1 < argc)
            g_command = argv[++i];
        else if (strcmp(argv[i], "--ping") == 0) g_command = "PING";
        else if (strcmp(argv[i], "--cluster-nodes") == 0)
            g_command = "CLUSTER NODES";
        else if (strcmp(argv[i], "--repl-status") == 0)
            g_command = "REPL.STATUS";
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            usage();
        else usage();
    }
    if (!g_host || !g_trusted_pub) usage();

    char dsa_key[512], kem_key[512], kem_pub[512];
    snprintf(dsa_key, sizeof(dsa_key), "%s/qihse_dsa_key.pem", g_identity_dir);
    snprintf(kem_key, sizeof(kem_key), "%s/qihse_kem_key.pem", g_identity_dir);
    snprintf(kem_pub, sizeof(kem_pub), "%s/qihse_kem_pub.pem", g_identity_dir);

    int fd = tcp_connect(g_host, g_port);
    if (fd < 0) return 3;

    const char* anchors[1] = { g_trusted_pub };
    qihse_qkp_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.dsa_key_path = dsa_key;
    cfg.kem_key_path = kem_key;
    cfg.kem_pub_path = kem_pub;
    cfg.trusted_pubs = anchors;
    cfg.trusted_count = 1u;
    cfg.node_id = g_node_id;
    cfg.require = true;

    qihse_qkp_session_t* session = NULL;
    if (qihse_qkp_client_negotiate(fd, &cfg, &session) != QIHSE_QKP_SECURE ||
        !session) {
        fprintf(stderr, "QKP handshake failed (server identity/keys rejected)\n");
        close(fd);
        return 3;
    }

    /* The requested command. */
    {
        char cmdbuf[1024];
        snprintf(cmdbuf, sizeof(cmdbuf), "%s", g_command);
        const char* cargv[64];
        size_t cargc = 0u;
        char* save = NULL;
        for (char* tok = strtok_r(cmdbuf, " \t", &save);
             tok && cargc < 63u; tok = strtok_r(NULL, " \t", &save))
            cargv[cargc++] = tok;
        if (cargc == 0u) cargv[cargc++] = "PING";

        size_t clen = 0u;
        char* creq = resp_encode_request(cargc, cargv, &clen);
        if (!creq || !qihse_qkp_send_sealed(session, fd, creq, clen)) {
            fprintf(stderr, "command send failed\n");
            free(creq);
            qihse_qkp_session_free(session);
            close(fd);
            return 5;
        }
        free(creq);
        char* reply = NULL;
        ssize_t n = recv_reply(session, fd, &reply);
        if (n <= 0) {
            fprintf(stderr, "command reply read failed\n");
            qihse_qkp_session_free(session);
            close(fd);
            return 5;
        }
        print_resp(reply, (size_t)n, 0);
        free(reply);
    }

    qihse_qkp_session_free(session);
    close(fd);
    return 0;
}
