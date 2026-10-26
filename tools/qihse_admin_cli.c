/* qihse-admin-cli — administration client for QKP-hardened QIHSE masters.
 *
 * The masters reject cleartext RESP (pqc_require) once replication pins are
 * configured, so plain redis-cli can no longer reach them. This tool is the
 * supported operator path:
 *
 *   1. TCP connect + QKP1 post-quantum handshake (sealed channel);
 *   2. verify the server against the configured QKP trust anchor; the server
 *      maps this client identity to operator scope only when its node id and
 *      signing public key match the configured admin-peer pin;
 *   3. send one or more RESP commands inside the sealed session.
 *
 * Usage:
 *   qihse-admin-cli --host 192.168.1.91 --port 7100 \
 *       --identity-dir /etc/qihse/keys \
 *       --trusted-pub /etc/qihse/keys/qihse_dsa_pub_t420.pem \
 *       --node-id admin-t420 SET mykey "hello world"
 *
 * Exit codes: 0 ok, 2 usage/config, 3 connect/handshake, 5 command.
 * The local signing key is a privileged credential and must remain protected.
 */

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "qihse_qkp.h"

#define ADMIN_MAX_ARGS 256u
#define ADMIN_LINE_CAP 16384u

static const char* g_host = NULL;
static uint16_t g_port = 7100;
static const char* g_identity_dir = NULL;
static const char* g_trusted_pub = NULL;
static const char* g_node_id = NULL;
static const char* g_command = NULL;
static const char* g_command_args[ADMIN_MAX_ARGS];
static size_t g_command_argc = 0u;
static bool g_interactive = false;
static bool g_stdin_batch = false;
static bool g_read_stdin_val = false;
static bool g_strict_err = false;

static void usage(int code) {
    FILE* out = (code == 0) ? stdout : stderr;
    fprintf(out,
        "usage: qihse-admin-cli [options] [CMD [ARG ...]]\n"
        "\nConnection & QKP Identity:\n"
        "  --host, -H HOST            Target master address ($QIHSE_HOST)\n"
        "  --port, -p PORT            Target master port (default: 7100 or $QIHSE_PORT)\n"
        "  --trusted-pub, -t FILE     Pinned server ML-DSA public key ($QIHSE_TRUSTED_PUB)\n"
        "  --identity-dir, -i DIR     Client identity key dir ($QIHSE_IDENTITY_DIR, ./keys, /etc/qihse/keys)\n"
        "  --node-id, -n ID           Client node identity (default: admin-cli or $QIHSE_NODE_ID)\n"
        "\nExecution Modes:\n"
        "  CMD [ARG ...]              Positional RESP command and arguments (redis-cli style)\n"
        "  --arg ARG                  Append an exact argument (repeatable, binary/whitespace safe)\n"
        "  --command, -c \"CMD ...\"    Execute quote-aware command string\n"
        "  -x                         Read last command argument from stdin\n"
        "  --stdin, --batch           Execute commands line-by-line from stdin over one QKP session\n"
        "  --interactive, --repl      Interactive shell over a persistent QKP session\n"
        "  --fail-on-error            Exit 5 if server returns a RESP error (-ERR / -NOAUTH / -MOVED)\n"
        "\nCluster & Admin Shortcuts:\n"
        "  --ping                     PING\n"
        "  --cluster-info             CLUSTER INFO\n"
        "  --cluster-nodes            CLUSTER NODES\n"
        "  --cluster-slots            CLUSTER SLOTS\n"
        "  --cluster-keyslot KEY      CLUSTER KEYSLOT <key>\n"
        "  --cluster-reclaim [LIMIT]  CLUSTER RECLAIM [limit]\n"
        "  --cluster-moveslots R H:P  CLUSTER MOVESLOTS <first-last> <host:port>\n"
        "  --cluster-failover         CLUSTER FAILOVER\n"
        "  --repl-status              REPL.STATUS\n"
        "  --info [SECTION]           INFO [section]\n"
        "  --dbsize                   DBSIZE\n"
        "  --save / --bgsave          SAVE / BGSAVE\n"
        "  --help, -h                 Show this help\n"
        "\nThe master must pin this identity with:\n"
        "  --admin-peer-node-id ID --admin-peer-dsa-pub FILE\n");
    exit(code);
}

static bool push_arg(const char* arg) {
    if (g_command_argc >= ADMIN_MAX_ARGS - 1u) {
        fprintf(stderr, "qihse-admin-cli: too many arguments (max %u)\n",
                (unsigned)(ADMIN_MAX_ARGS - 1u));
        return false;
    }
    g_command_args[g_command_argc++] = arg;
    return true;
}

/* Quote-aware in-place tokenizer supporting 'single', "double", and \escapes. */
static bool parse_command_line(char* line, const char** out_argv, size_t max_args,
                               size_t* out_argc) {
    size_t argc = 0u;
    char* p = line;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') break;
        if (argc >= max_args - 1u) {
            fprintf(stderr, "qihse-admin-cli: too many arguments (max %zu)\n",
                    max_args - 1u);
            return false;
        }
        char* dst = p;
        char* start = dst;
        char quote = 0;
        while (*p) {
            if (quote) {
                if (*p == quote) {
                    quote = 0;
                    p++;
                } else if (*p == '\\' && quote == '"' && p[1]) {
                    p++;
                    switch (*p) {
                        case 'n': *dst++ = '\n'; break;
                        case 'r': *dst++ = '\r'; break;
                        case 't': *dst++ = '\t'; break;
                        default:  *dst++ = *p;   break;
                    }
                    p++;
                } else {
                    *dst++ = *p++;
                }
            } else {
                if (isspace((unsigned char)*p)) {
                    p++;
                    break;
                }
                if (*p == '"' || *p == '\'') {
                    quote = *p++;
                } else if (*p == '\\' && p[1]) {
                    p++;
                    *dst++ = *p++;
                } else {
                    *dst++ = *p++;
                }
            }
        }
        if (quote != 0) {
            fprintf(stderr, "qihse-admin-cli: unterminated quote (%c)\n", quote);
            return false;
        }
        *dst = '\0';
        out_argv[argc++] = start;
    }
    *out_argc = argc;
    return true;
}

static char* read_all_stdin(size_t* out_len) {
    size_t cap = 4096u, len = 0u;
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 2048u > cap) {
            size_t next = cap * 2u;
            char* grown = (char*)realloc(buf, next);
            if (!grown) { free(buf); return NULL; }
            buf = grown;
            cap = next;
        }
        size_t n = fread(buf + len, 1u, cap - len - 1u, stdin);
        len += n;
        if (n == 0u) break;
    }
    if (len > 0u && buf[len - 1u] == '\n') {
        len--;
        if (len > 0u && buf[len - 1u] == '\r') len--;
    }
    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

/* ── Persistent Session Support (for --interactive and --stdin) ─────────── */

static int cli_tcp_connect(const char* host, uint16_t port,
                           char* err_buf, size_t err_cap) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        if (err_buf && err_cap)
            snprintf(err_buf, err_cap, "getaddrinfo(%s) failed", host);
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
    if (fd < 0 && err_buf && err_cap) {
        snprintf(err_buf, err_cap, "connect(%s:%u) failed: %s",
                 host, (unsigned)port, strerror(errno));
    }
    return fd;
}

static char* cli_encode_resp(size_t argc, const char* const* argv, size_t* out_len) {
    size_t cap = 64u;
    for (size_t i = 0; i < argc; i++) cap += 24u + strlen(argv[i]);
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;
    size_t used = 0u;
    used += (size_t)snprintf(buf + used, cap - used, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++) {
        size_t alen = strlen(argv[i]);
        used += (size_t)snprintf(buf + used, cap - used, "$%zu\r\n", alen);
        memcpy(buf + used, argv[i], alen);
        used += alen;
        memcpy(buf + used, "\r\n", 2u);
        used += 2u;
    }
    *out_len = used;
    return buf;
}

static ssize_t cli_resp_measure(const char* p, size_t len, int depth) {
    if (depth > 8 || len == 0u) return 0;
    char kind = p[0];
    if (kind == '+' || kind == '-' || kind == ':') {
        const char* eol = (const char*)memchr(p, '\r', len);
        if (!eol || eol + 1u >= p + len || eol[1] != '\n') return 0;
        return (ssize_t)(eol + 2u - p);
    }
    if (kind == '$') {
        const char* eol = (const char*)memchr(p, '\r', len);
        if (!eol || eol + 1u >= p + len || eol[1] != '\n') return 0;
        long long blen = strtoll(p + 1, NULL, 10);
        if (blen < 0) return (ssize_t)(eol + 2u - p);
        size_t body = (size_t)(eol + 2u - p);
        size_t total = body + (size_t)blen + 2u;
        if (total > len) return 0;
        return (ssize_t)total;
    }
    if (kind == '*') {
        const char* eol = (const char*)memchr(p, '\r', len);
        if (!eol || eol + 1u >= p + len || eol[1] != '\n') return 0;
        long long count = strtoll(p + 1, NULL, 10);
        if (count < 0) return (ssize_t)(eol + 2u - p);
        size_t off = (size_t)(eol + 2u - p);
        for (long long k = 0; k < count; k++) {
            if (off >= len) return 0;
            ssize_t sub = cli_resp_measure(p + off, len - off, depth + 1);
            if (sub <= 0) return 0;
            off += (size_t)sub;
        }
        return (ssize_t)off;
    }
    return 0;
}

static void cli_print_resp(const char* p, size_t len, int depth, bool* out_is_err) {
    if (depth > 6 || len == 0u) {
        fputs("(unparseable)\n", stdout);
        return;
    }
    size_t i = 0u;
    while (i < len) {
        char kind = p[i];
        if (kind == '+' || kind == '-' || kind == ':') {
            if (kind == '-' && depth == 0 && out_is_err) *out_is_err = true;
            size_t start = i + 1u;
            size_t j = start;
            while (j < len && p[j] != '\r') j++;
            fwrite(p + start, 1u, j - start, stdout);
            fputc('\n', stdout);
            i = (j + 2u <= len) ? j + 2u : len;
        } else if (kind == '$') {
            size_t j = i + 1u;
            while (j < len && p[j] != '\r') j++;
            long long blen = strtoll(p + i + 1u, NULL, 10);
            i = (j + 2u <= len) ? j + 2u : len;
            if (blen < 0) {
                fputs("(nil)\n", stdout);
                continue;
            }
            if (i + (size_t)blen + 2u > len) {
                fputs("(truncated)\n", stdout);
                return;
            }
            fwrite(p + i, 1u, (size_t)blen, stdout);
            fputc('\n', stdout);
            i += (size_t)blen + 2u;
        } else if (kind == '*') {
            size_t j = i + 1u;
            while (j < len && p[j] != '\r') j++;
            long long count = strtoll(p + i + 1u, NULL, 10);
            i = (j + 2u <= len) ? j + 2u : len;
            if (count < 0) {
                fputs("(nil array)\n", stdout);
                continue;
            }
            for (long long k = 0; k < count; k++) {
                if (i >= len) return;
                ssize_t sub = cli_resp_measure(p + i, len - i, depth + 1);
                if (sub <= 0) {
                    fputs("(truncated)\n", stdout);
                    return;
                }
                cli_print_resp(p + i, (size_t)sub, depth + 1, NULL);
                i += (size_t)sub;
            }
        } else {
            printf("(unknown reply kind %c)\n", kind);
            return;
        }
    }
}

static int run_persistent_session(const char* host, uint16_t port,
                                  const char* node_id, const char* identity_dir,
                                  const char* trusted_pub_path, bool interactive) {
    const char* id_dir = identity_dir;
    if (!id_dir || !*id_dir) {
        const char* env_dir = getenv("QIHSE_IDENTITY_DIR");
        if (env_dir && *env_dir) id_dir = env_dir;
        else if (access("keys/qihse_dsa_key.pem", R_OK) == 0) id_dir = "keys";
        else id_dir = "/etc/qihse/keys";
    }
    char dsa_key[512], kem_key[512], kem_pub[512];
    snprintf(dsa_key, sizeof(dsa_key), "%s/qihse_dsa_key.pem", id_dir);
    snprintf(kem_key, sizeof(kem_key), "%s/qihse_kem_key.pem", id_dir);
    snprintf(kem_pub, sizeof(kem_pub), "%s/qihse_kem_pub.pem", id_dir);
    if (access(dsa_key, R_OK) != 0 || access(kem_key, R_OK) != 0 ||
        access(kem_pub, R_OK) != 0) {
        fprintf(stderr, "identity keys missing/unreadable in %s\n", id_dir);
        return 2;
    }
    if (access(trusted_pub_path, R_OK) != 0) {
        fprintf(stderr, "trusted-pub unreadable: %s\n", trusted_pub_path);
        return 2;
    }

    char err_buf[512] = {0};
    int fd = cli_tcp_connect(host, port, err_buf, sizeof(err_buf));
    if (fd < 0) {
        fprintf(stderr, "%s\n", err_buf[0] ? err_buf : "connect failed");
        return 3;
    }

    const char* anchors[1] = { trusted_pub_path };
    qihse_qkp_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.dsa_key_path = dsa_key;
    cfg.kem_key_path = kem_key;
    cfg.kem_pub_path = kem_pub;
    cfg.trusted_pubs = anchors;
    cfg.trusted_count = 1u;
    cfg.node_id = (node_id && *node_id) ? node_id : "admin-cli";
    cfg.require = true;

    qihse_qkp_session_t* session = NULL;
    if (qihse_qkp_client_negotiate(fd, &cfg, &session) != QIHSE_QKP_SECURE || !session) {
        fprintf(stderr, "QKP handshake failed (server identity/keys rejected)\n");
        close(fd);
        return 3;
    }

    char line[ADMIN_LINE_CAP];
    int exit_rc = 0;
    bool is_tty = isatty(STDIN_FILENO);
    for (;;) {
        if (interactive && is_tty) {
            printf("qkp %s:%u> ", host, (unsigned)port);
            fflush(stdout);
        }
        if (!fgets(line, sizeof(line), stdin)) break;

        const char* cargv[ADMIN_MAX_ARGS];
        size_t cargc = 0u;
        if (!parse_command_line(line, cargv, ADMIN_MAX_ARGS, &cargc)) {
            if (!interactive && g_strict_err) { exit_rc = 2; break; }
            continue;
        }
        if (cargc == 0u) continue;
        if (cargc == 1u && (strcasecmp(cargv[0], "QUIT") == 0 ||
                            strcasecmp(cargv[0], "EXIT") == 0)) {
            break;
        }

        size_t req_len = 0u;
        char* req = cli_encode_resp(cargc, cargv, &req_len);
        if (!req || !qihse_qkp_send_sealed(session, fd, req, req_len)) {
            fprintf(stderr, "command send failed\n");
            free(req);
            exit_rc = 5;
            break;
        }
        free(req);

        size_t cap = 4096u, used = 0u;
        char* rbuf = (char*)malloc(cap);
        if (!rbuf) { exit_rc = 5; break; }
        bool read_ok = true;
        for (;;) {
            uint8_t frame[QIHSE_QKP_MAX_FRAME + 64u];
            ssize_t n = qihse_qkp_recv_sealed(session, fd, frame, sizeof(frame));
            if (n <= 0) { read_ok = false; break; }
            while (used + (size_t)n + 1u > cap) {
                size_t next = cap * 2u;
                char* grown = (char*)realloc(rbuf, next);
                if (!grown) { read_ok = false; break; }
                rbuf = grown;
                cap = next;
            }
            if (!read_ok) break;
            memcpy(rbuf + used, frame, (size_t)n);
            used += (size_t)n;
            rbuf[used] = '\0';
            ssize_t measured = cli_resp_measure(rbuf, used, 0);
            if (measured > 0 && (size_t)measured == used) break;
        }
        if (!read_ok || used == 0u) {
            free(rbuf);
            fprintf(stderr, "command reply read failed\n");
            exit_rc = 5;
            break;
        }
        bool is_err = false;
        cli_print_resp(rbuf, used, 0, &is_err);
        fflush(stdout);
        free(rbuf);
        if (is_err && g_strict_err) {
            exit_rc = 5;
            if (!interactive) break;
        }
    }

    qihse_qkp_session_free(session);
    close(fd);
    return exit_rc;
}

int main(int argc, char** argv) {
    const char* env_host = getenv("QIHSE_HOST");
    if (env_host && *env_host) g_host = env_host;
    const char* env_port = getenv("QIHSE_PORT");
    if (env_port && *env_port) g_port = (uint16_t)atoi(env_port);
    const char* env_pub = getenv("QIHSE_TRUSTED_PUB");
    if (env_pub && *env_pub) g_trusted_pub = env_pub;
    const char* env_id = getenv("QIHSE_NODE_ID");
    if (env_id && *env_id) g_node_id = env_id;
    else g_node_id = "admin-cli";

    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "--") == 0) {
            for (int j = i + 1; j < argc; j++) {
                if (!push_arg(argv[j])) return 2;
            }
            break;
        } else if ((strcmp(a, "--host") == 0 || strcmp(a, "-H") == 0) && i + 1 < argc) {
            g_host = argv[++i];
        } else if ((strcmp(a, "--port") == 0 || strcmp(a, "-p") == 0) && i + 1 < argc) {
            long p = strtol(argv[++i], NULL, 10);
            if (p <= 0 || p > 65535) usage(2);
            g_port = (uint16_t)p;
        } else if ((strcmp(a, "--identity-dir") == 0 || strcmp(a, "-i") == 0) && i + 1 < argc) {
            g_identity_dir = argv[++i];
        } else if ((strcmp(a, "--trusted-pub") == 0 || strcmp(a, "-t") == 0) && i + 1 < argc) {
            g_trusted_pub = argv[++i];
        } else if ((strcmp(a, "--node-id") == 0 || strcmp(a, "-n") == 0) && i + 1 < argc) {
            g_node_id = argv[++i];
        } else if ((strcmp(a, "--command") == 0 || strcmp(a, "-c") == 0) && i + 1 < argc) {
            g_command = argv[++i];
        } else if (strcmp(a, "--arg") == 0 && i + 1 < argc) {
            if (!push_arg(argv[++i])) return 2;
        } else if (strcmp(a, "-x") == 0) {
            g_read_stdin_val = true;
        } else if (strcmp(a, "--interactive") == 0 || strcmp(a, "--repl") == 0) {
            g_interactive = true;
        } else if (strcmp(a, "--stdin") == 0 || strcmp(a, "--batch") == 0) {
            g_stdin_batch = true;
        } else if (strcmp(a, "--fail-on-error") == 0) {
            g_strict_err = true;
        } else if (strcmp(a, "--ping") == 0) {
            g_command = "PING";
        } else if (strcmp(a, "--cluster-nodes") == 0) {
            g_command = "CLUSTER NODES";
        } else if (strcmp(a, "--cluster-info") == 0) {
            g_command = "CLUSTER INFO";
        } else if (strcmp(a, "--cluster-slots") == 0) {
            g_command = "CLUSTER SLOTS";
        } else if (strcmp(a, "--cluster-failover") == 0) {
            g_command = "CLUSTER FAILOVER";
        } else if (strcmp(a, "--cluster-keyslot") == 0 && i + 1 < argc) {
            if (!push_arg("CLUSTER") || !push_arg("KEYSLOT") || !push_arg(argv[++i])) return 2;
        } else if (strcmp(a, "--cluster-reclaim") == 0) {
            if (!push_arg("CLUSTER") || !push_arg("RECLAIM")) return 2;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (!push_arg(argv[++i])) return 2;
            }
        } else if (strcmp(a, "--cluster-moveslots") == 0 && i + 2 < argc) {
            static char ms_range[64], ms_target[280];
            if (!push_arg("CLUSTER") || !push_arg("MOVESLOTS")) return 2;
            if (i + 4 < argc && strchr(argv[i + 1], '-') == NULL &&
                strchr(argv[i + 3], ':') == NULL && argv[i + 3][0] != '-') {
                snprintf(ms_range, sizeof(ms_range), "%s-%s", argv[i + 1], argv[i + 2]);
                snprintf(ms_target, sizeof(ms_target), "%s:%s", argv[i + 3], argv[i + 4]);
                if (!push_arg(ms_range) || !push_arg(ms_target)) return 2;
                i += 4;
            } else {
                if (!push_arg(argv[i + 1]) || !push_arg(argv[i + 2])) return 2;
                i += 2;
            }
        } else if (strcmp(a, "--repl-status") == 0) {
            g_command = "REPL.STATUS";
        } else if (strcmp(a, "--info") == 0) {
            if (!push_arg("INFO")) return 2;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (!push_arg(argv[++i])) return 2;
            }
        } else if (strcmp(a, "--dbsize") == 0) {
            g_command = "DBSIZE";
        } else if (strcmp(a, "--save") == 0) {
            g_command = "SAVE";
        } else if (strcmp(a, "--bgsave") == 0) {
            g_command = "BGSAVE";
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(0);
        } else if (a[0] == '-') {
            fprintf(stderr, "qihse-admin-cli: unknown or incomplete option: %s\n", a);
            usage(2);
        } else {
            /* Positional command + arguments: consume the rest of argv directly */
            for (int j = i; j < argc; j++) {
                if (!push_arg(argv[j])) return 2;
            }
            break;
        }
    }

    if (!g_host || !g_trusted_pub) usage(2);

    if (g_interactive || g_stdin_batch) {
        return run_persistent_session(g_host, g_port, g_node_id, g_identity_dir,
                                      g_trusted_pub, g_interactive);
    }

    char cmdbuf[ADMIN_LINE_CAP];
    const char* cargv[ADMIN_MAX_ARGS];
    size_t cargc = 0u;
    if (g_command_argc > 0u) {
        for (size_t i = 0; i < g_command_argc; i++)
            cargv[cargc++] = g_command_args[i];
    } else {
        const char* cmd_str = g_command ? g_command : "PING";
        snprintf(cmdbuf, sizeof(cmdbuf), "%s", cmd_str);
        if (!parse_command_line(cmdbuf, cargv, ADMIN_MAX_ARGS, &cargc)) {
            return 2;
        }
    }

    char* stdin_val = NULL;
    if (g_read_stdin_val) {
        stdin_val = read_all_stdin(NULL);
        if (!stdin_val) {
            fprintf(stderr, "qihse-admin-cli: failed to read stdin for -x\n");
            return 2;
        }
        if (cargc >= ADMIN_MAX_ARGS - 1u) {
            fprintf(stderr, "qihse-admin-cli: too many arguments\n");
            free(stdin_val);
            return 2;
        }
        cargv[cargc++] = stdin_val;
    }

    if (cargc == 0u) cargv[cargc++] = "PING";

    char* out_text = NULL;
    char err_buf[512] = {0};
    int rc = qihse_qkp_admin_exec(g_host, g_port, g_node_id, g_identity_dir,
                                  g_trusted_pub, cargc, cargv, &out_text,
                                  err_buf, sizeof(err_buf));
    free(stdin_val);
    if (rc != 0) {
        fprintf(stderr, "%s\n", err_buf[0] ? err_buf : "admin command failed");
        qihse_qkp_admin_free(out_text);
        return rc;
    }
    if (out_text) {
        fputs(out_text, stdout);
        bool looks_err = (strncmp(out_text, "ERR ", 4) == 0 ||
                          strncmp(out_text, "NOAUTH ", 7) == 0 ||
                          strncmp(out_text, "NOPERM ", 7) == 0 ||
                          strncmp(out_text, "MOVED ", 6) == 0 ||
                          strncmp(out_text, "ASK ", 4) == 0 ||
                          strncmp(out_text, "CLUSTERDOWN ", 12) == 0 ||
                          strncmp(out_text, "WRONGTYPE ", 10) == 0);
        qihse_qkp_admin_free(out_text);
        if (g_strict_err && looks_err) return 5;
    }
    return 0;
}
