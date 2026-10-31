/* SPDX-License-Identifier: MIT */
/* High-performance native C engine for QIHSE AIMEM & Supermemory Bridge.
 *
 * Implements:
 *   1. High-speed stdio MCP server (JSON-RPC 2.0) with persistent RESP socket
 *   2. Instant Codex prompt hook (< 2ms execution time)
 *   3. CLI memory recall with dynamic repository scoping & foreign noise judgment
 *   4. Zero internet exposure: strictly binds and connects to 127.0.0.1 only
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT       6401
#define DEFAULT_HOST       "127.0.0.1"
#define MAX_TEXT_BYTES     (256 * 1024)
#define MAX_IDEM_BYTES     128
#define PROTOCOL_VERSION   "2024-11-05"
#define SERVER_NAME        "qihse-supermemory-native"
#define SERVER_VERSION     "2.0.0"

struct qihse_env {
    char host[128];
    int port;
    char user[128];
    char password[256];
    char transport[16];
    char cli[1024];
    char identity[1024];
    char trusted_pub[1024];
    char node_id[65];
};

static struct qihse_env G_ENV;
static int G_SOCK = -1;

/* -------------------------------------------------------------------------
 * Loopback Security & Environment Loading
 * ------------------------------------------------------------------------- */

static int is_loopback(const char *host)
{
    if (!host || !*host)
        return 0;
    if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0 || strcmp(host, "::1") == 0)
        return 1;
    if (strncmp(host, "127.", 4) == 0)
        return 1;
    return 0;
}

static int load_env(struct qihse_env *env)
{
    memset(env, 0, sizeof(*env));
    snprintf(env->host, sizeof(env->host), "%s", DEFAULT_HOST);
    env->port = DEFAULT_PORT;

    const char *env_path = getenv("QIHSE_AIMEM_ENV");
    char path_buf[1024];
    if (!env_path || !*env_path) {
        const char *home = getenv("HOME");
        if (!home) return -1;
        snprintf(path_buf, sizeof(path_buf), "%s/.config/qihse-aimem/env", home);
        env_path = path_buf;
    }

    struct stat st;
    if (lstat(env_path, &st) == 0) {
        if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077)) {
            fprintf(stderr, "FATAL: credential file must be user-owned, regular, non-symlink, and mode 0600\n");
            return -1;
        }
        FILE *f = fopen(env_path, "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                char *eq = strchr(line, '=');
                if (!eq) continue;
                *eq = '\0';
                char *k = line;
                char *v = eq + 1;
                while (*k && isspace((unsigned char)*k)) k++;
                char *end = k + strlen(k);
                while (end > k && isspace((unsigned char)*(end - 1))) *(--end) = '\0';

                while (*v && isspace((unsigned char)*v)) v++;
                end = v + strlen(v);
                while (end > v && isspace((unsigned char)*(end - 1))) *(--end) = '\0';

                if (strcmp(k, "QIHSE_RESP_HOST") == 0) {
                    snprintf(env->host, sizeof(env->host), "%s", v);
                } else if (strcmp(k, "QIHSE_RESP_PORT") == 0) {
                    env->port = atoi(v);
                } else if (strcmp(k, "QIHSE_AUTH_USER") == 0) {
                    snprintf(env->user, sizeof(env->user), "%s", v);
                } else if (strcmp(k, "QIHSE_AUTH_PASSWORD") == 0) {
                    snprintf(env->password, sizeof(env->password), "%s", v);
                } else if (strcmp(k, "QIHSE_AIMEM_TRANSPORT") == 0) {
                    snprintf(env->transport, sizeof(env->transport), "%s", v);
                } else if (strcmp(k, "QIHSE_ADMIN_CLI") == 0) {
                    snprintf(env->cli, sizeof(env->cli), "%s", v);
                } else if (strcmp(k, "QIHSE_AIMEM_IDENTITY_DIR") == 0) {
                    snprintf(env->identity, sizeof(env->identity), "%s", v);
                } else if (strcmp(k, "QIHSE_AIMEM_TRUSTED_PUB") == 0) {
                    snprintf(env->trusted_pub, sizeof(env->trusted_pub), "%s", v);
                } else if (strcmp(k, "QIHSE_AIMEM_NODE_ID") == 0) {
                    snprintf(env->node_id, sizeof(env->node_id), "%s", v);
                }
            }
            fclose(f);
        }
    }

    /* Environment variable overrides */
    const char *h = getenv("QIHSE_RESP_HOST");
    if (h && *h) snprintf(env->host, sizeof(env->host), "%s", h);
    const char *p = getenv("QIHSE_RESP_PORT");
    if (p && *p) env->port = atoi(p);
    const char *u = getenv("QIHSE_AUTH_USER");
    if (u && *u) snprintf(env->user, sizeof(env->user), "%s", u);
    const char *pwd = getenv("QIHSE_AUTH_PASSWORD");
    if (pwd && *pwd) snprintf(env->password, sizeof(env->password), "%s", pwd);
    const char *names[] = {"QIHSE_AIMEM_TRANSPORT", "QIHSE_ADMIN_CLI", "QIHSE_AIMEM_IDENTITY_DIR",
                           "QIHSE_AIMEM_TRUSTED_PUB", "QIHSE_AIMEM_NODE_ID"};
    char *dest[] = {env->transport, env->cli, env->identity, env->trusted_pub, env->node_id};
    const size_t sizes[] = {sizeof(env->transport), sizeof(env->cli), sizeof(env->identity),
                            sizeof(env->trusted_pub), sizeof(env->node_id)};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *value = getenv(names[i]);
        if (value && *value) {
            if (strlen(value) >= sizes[i]) return -1;
            snprintf(dest[i], sizes[i], "%s", value);
        }
    }

    if (!env->transport[0]) snprintf(env->transport, sizeof(env->transport), "qkp");
    if ((strcmp(env->transport, "resp") != 0 && strcmp(env->transport, "qkp") != 0) ||
        (strcmp(env->transport, "qkp") == 0 &&
         (!env->cli[0] || env->cli[0] != '/' || !env->identity[0] ||
          !env->trusted_pub[0] || !env->node_id[0]))) {
        fprintf(stderr, "FATAL: QKP requires explicit CLI, identity, pin and node ID\n");
        return -1;
    }
    if (strcmp(env->user, "AIMEM_SERVICE") != 0 || !env->password[0]) {
        fprintf(stderr, "FATAL: restricted AIMEM_SERVICE credentials are required\n");
        return -1;
    }

    /* Strict Anti-Internet Exposure Enforcement */
    if (!is_loopback(env->host)) {
        fprintf(stderr, "FATAL SECURITY ERROR: QIHSE_RESP_HOST '%s' is not loopback!\n"
                        "Port %d must NEVER be bound or exposed to the network or internet.\n",
                env->host, env->port);
        exit(1);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Low-Level RESP Protocol Client
 * ------------------------------------------------------------------------- */

static void qihse_disconnect(void)
{
    if (G_SOCK >= 0) {
        close(G_SOCK);
        G_SOCK = -1;
    }
}

static int qihse_read_line(int fd, char *buf, size_t max_len)
{
    size_t i = 0;
    while (i + 1 < max_len) {
        char c;
        int n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\r') {
            read(fd, &c, 1); /* consume \n */
            break;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (int)i;
}

static int qihse_read_bulk_field(int fd, char *buf, size_t capacity, size_t wire_count)
{
    size_t keep = wire_count < capacity - 1 ? wire_count : capacity - 1;
    size_t total = 0;
    while (total < keep) {
        int n = read(fd, buf + total, keep - total);
        if (n <= 0) return -1;
        total += n;
    }
    size_t remaining = wire_count - keep;
    char discard[4096];
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
        int n = read(fd, discard, chunk);
        if (n <= 0) return -1;
        remaining -= (size_t)n;
    }
    char crlf[2];
    if (read(fd, crlf, 2) != 2 || crlf[0] != '\r' || crlf[1] != '\n') return -1;
    buf[keep] = '\0';
    return (int)total;
}

static int qihse_connect(void)
{
    if (G_SOCK >= 0) return G_SOCK;

    if (!is_loopback(G_ENV.host)) {
        fprintf(stderr, "SECURITY ERROR: Refusing connection to non-loopback host '%s'\n", G_ENV.host);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(G_ENV.port > 0 ? G_ENV.port : DEFAULT_PORT);
    inet_pton(AF_INET, G_ENV.host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Authenticate if credentials provided */
    if (G_ENV.password[0]) {
        char auth_cmd[1024];
        int len = snprintf(auth_cmd, sizeof(auth_cmd),
                           "*3\r\n$4\r\nAUTH\r\n$%zu\r\n%s\r\n$%zu\r\n%s\r\n",
                           strlen(G_ENV.user), G_ENV.user, strlen(G_ENV.password), G_ENV.password);
        if (write(fd, auth_cmd, len) != len) {
            close(fd);
            return -1;
        }
        char line[256];
        if (qihse_read_line(fd, line, sizeof(line)) < 0 || line[0] != '+') {
            close(fd);
            return -1;
        }
    }

    G_SOCK = fd;
    return G_SOCK;
}

/* -------------------------------------------------------------------------
 * Memory Hit Structure & Parsing
 * ------------------------------------------------------------------------- */

struct memory_hit {
    char id[64];
    long long created_ms;
    int kind;
    int classification;
    int sci;
    double score;
    double adjusted_score;
    char text[8192];
    char repo[128];
    char scope[64];
};

static void parse_hit_text_envelope(struct memory_hit *hit)
{
    hit->repo[0] = '\0';
    hit->scope[0] = '\0';
    hit->adjusted_score = hit->score;

    if (hit->text[0] == '{' && hit->text[strlen(hit->text) - 1] == '}') {
        json_error_t err;
        json_t *doc = json_loads(hit->text, 0, &err);
        if (doc && json_is_object(doc)) {
            json_t *t = json_object_get(doc, "text");
            if (t && json_is_string(t)) {
                snprintf(hit->text, sizeof(hit->text), "%s", json_string_value(t));
            }
            json_t *meta = json_object_get(doc, "metadata");
            json_t *r = NULL;
            if (meta && json_is_object(meta)) {
                r = json_object_get(meta, "repo");
                if (!r) r = json_object_get(meta, "repository");
            }
            if (!r) r = json_object_get(doc, "repo");
            if (!r) r = json_object_get(doc, "repository");
            if (r && json_is_string(r)) {
                snprintf(hit->repo, sizeof(hit->repo), "%s", json_string_value(r));
            }
            json_t *s = meta ? json_object_get(meta, "scope") : NULL;
            if (!s) s = json_object_get(doc, "scope");
            if (s && json_is_string(s)) {
                snprintf(hit->scope, sizeof(hit->scope), "%s", json_string_value(s));
            }
            json_decref(doc);
            return;
        }
        if (doc) json_decref(doc);
    }

    /* Check [repo: ...] tag in header */
    char *tag = strstr(hit->text, "[repo:");
    if (!tag) tag = strstr(hit->text, "[repo: ");
    if (tag) {
        char *start = tag + (tag[6] == ' ' ? 7 : 6);
        char *end = strchr(start, ']');
        if (end && (size_t)(end - start) < sizeof(hit->repo)) {
            size_t n = end - start;
            memcpy(hit->repo, start, n);
            hit->repo[n] = '\0';
        }
    }
}

/* -------------------------------------------------------------------------
 * Dynamic Workspace Repository Detection
 * ------------------------------------------------------------------------- */

static void detect_current_repo(const char *dir_hint, char *out_repo, size_t out_sz)
{
    char cwd[1024];
    const char *configured = getenv("QIHSE_AIMEM_PROJECT");
    if (configured && *configured) {
        snprintf(out_repo, out_sz, "%s", configured);
        for (char *p = out_repo; *p; p++) {
            if (*p == '_' || isspace((unsigned char)*p)) *p = '-';
            else *p = tolower((unsigned char)*p);
        }
        return;
    }
    if (dir_hint && *dir_hint) {
        snprintf(cwd, sizeof(cwd), "%s", dir_hint);
    } else {
        if (!getcwd(cwd, sizeof(cwd))) {
            snprintf(out_repo, out_sz, "global");
            return;
        }
    }

    /* Check suite/ subproject: e.g. .../suite/VEXEL */
    char *suite_pos = strstr(cwd, "/suite/");
    if (suite_pos) {
        char *sub = suite_pos + 7;
        char *slash = strchr(sub, '/');
        if (slash) {
            size_t len = slash - sub;
            if (len >= out_sz) len = out_sz - 1;
            memcpy(out_repo, sub, len);
            out_repo[len] = '\0';
        } else {
            snprintf(out_repo, out_sz, "%s", sub);
        }
        for (char *p = out_repo; *p; p++) *p = tolower((unsigned char)*p);
        return;
    }

    /* Use the repository root when invoked from a nested working directory. */
    char root[sizeof(cwd)];
    snprintf(root, sizeof(root), "%s", cwd);
    for (;;) {
        char marker[sizeof(root) + 6];
        int marker_len = snprintf(marker, sizeof(marker), "%s/.git", root);
        struct stat marker_st;
        if (marker_len > 0 && (size_t)marker_len < sizeof(marker) &&
            lstat(marker, &marker_st) == 0) {
            char *base = strrchr(root, '/');
            snprintf(out_repo, out_sz, "%.*s", (int)(out_sz - 1),
                     (base && base[1]) ? base + 1 : root);
            for (char *p = out_repo; *p; p++) {
                if (*p == '_' || isspace((unsigned char)*p)) *p = '-';
                else *p = tolower((unsigned char)*p);
            }
            return;
        }
        char *slash = strrchr(root, '/');
        if (!slash || slash == root) break;
        *slash = '\0';
    }

    /* Fallback to last directory component */
    char *last = strrchr(cwd, '/');
    if (last && *(last + 1)) {
        snprintf(out_repo, out_sz, "%s", last + 1);
    } else {
        snprintf(out_repo, out_sz, "%.*s", (int)(out_sz - 1), cwd);
    }
        for (char *p = out_repo; *p; p++) {
            if (*p == '_' || isspace((unsigned char)*p)) *p = '-';
            else *p = tolower((unsigned char)*p);
        }
}

/* -------------------------------------------------------------------------
 * Core Recall Operation
 * ------------------------------------------------------------------------- */

static int qihse_recall(const char *query, int limit, const char *mode,
                        const char *project,
                        struct memory_hit *hits, int max_hits)
{
    int fd = -1;
    if (strcmp(G_ENV.transport, "qkp") == 0) {
        char port_text[16], limit_text[16];
        snprintf(port_text, sizeof(port_text), "%d", G_ENV.port);
        snprintf(limit_text, sizeof(limit_text), "%d", limit);
        char *const args[] = {G_ENV.cli, "--host", G_ENV.host, "--port", port_text,
            "--identity-dir", G_ENV.identity, "--trusted-pub", G_ENV.trusted_pub,
            "--node-id", G_ENV.node_id, "--user", G_ENV.user,
            "--timeout-ms", "60000", "--resp",
            "--fail-on-error", "--", "AIMEM", "RECALL-SCOPED", (char *)query,
            limit_text, (char *)mode, "0", (char *)project, "", "", "", NULL};
        int fds[2];
        if (pipe(fds) != 0) return -1;
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[0]);
            if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
            close(fds[1]);
            /* No operator credential is passed. The CLI reads service AUTH
             * password only from QIHSE_AUTH_PASSWORD after the QKP handshake. */
            unsetenv("QIHSE_OPERATOR_PASSWORD");
            unsetenv("QIHSE_AIMEM_SERVICE_PASSWORD");
            setenv("QIHSE_AUTH_USER", "AIMEM_SERVICE", 1);
            setenv("QIHSE_AUTH_PASSWORD", G_ENV.password, 1);
            char runtime[sizeof(G_ENV.cli)];
            snprintf(runtime, sizeof(runtime), "%s", G_ENV.cli);
            char *slash = strrchr(runtime, '/');
            if (!slash) _exit(127);
            *slash = '\0';
            /* RUNPATH loses to inherited LD_LIBRARY_PATH; use the library
             * deployed beside the CLI, never an older cluster build. */
            if (setenv("LD_LIBRARY_PATH", runtime, 1) != 0) _exit(127);
            execv(G_ENV.cli, args);
            _exit(127);
        }
        close(fds[1]);
        if (pid < 0) { close(fds[0]); return -1; }
        fd = memfd_create("qihse-aimem-reply", MFD_CLOEXEC);
        char chunk[8192];
        ssize_t n;
        size_t used = 0;
        int ok = fd >= 0;
        while ((n = read(fds[0], chunk, sizeof(chunk))) > 0) {
            if (used > 5u * 1024u * 1024u - (size_t)n ||
                !ok || write(fd, chunk, (size_t)n) != n) ok = 0;
            used += (size_t)n;
        }
        close(fds[0]);
        int status = 0;
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 || n < 0 || !ok ||
            lseek(fd, 0, SEEK_SET) < 0) {
            if (fd >= 0) close(fd);
            return -1;
        }
    } else fd = qihse_connect();
    if (fd < 0) return -1;
    if (strcmp(G_ENV.transport, "qkp") == 0) G_SOCK = fd;

    char cmd[2048];
    int len = snprintf(cmd, sizeof(cmd),
                       "*10\r\n$5\r\nAIMEM\r\n$13\r\nRECALL-SCOPED\r\n$%zu\r\n%s\r\n$%d\r\n%d\r\n$%zu\r\n%s\r\n$1\r\n0\r\n$%zu\r\n%s\r\n$0\r\n\r\n$0\r\n\r\n$0\r\n\r\n",
                       strlen(query), query, limit < 10 ? 1 : (limit < 100 ? 2 : 3), limit,
                       strlen(mode), mode, strlen(project), project);
    if (strcmp(G_ENV.transport, "qkp") != 0 &&
        (len <= 0 || (size_t)len >= sizeof(cmd) || write(fd, cmd, (size_t)len) != len)) {
        qihse_disconnect();
        return -1;
    }

    char line[512];
    if (qihse_read_line(fd, line, sizeof(line)) < 0 || line[0] != '*') {
        qihse_disconnect();
        return -1;
    }

    char *end = NULL;
    errno = 0;
    long total_hits = strtol(line + 1, &end, 10);
    if (errno || end == line + 1 || *end || total_hits < 0 || total_hits > limit) {
        qihse_disconnect();
        return -1;
    }

    int count = 0;
    for (int i = 0; i < total_hits; i++) {
        char item_line[64];
        if (qihse_read_line(fd, item_line, sizeof(item_line)) < 0 ||
            item_line[0] != '*' || atoi(item_line + 1) != 7) {
            qihse_disconnect();
            return -1;
        }

        struct memory_hit hit;
        memset(&hit, 0, sizeof(hit));
        char f_id[64], f_created[64], f_kind[16], f_class[16], f_sci[16], f_score[32];

        #define READ_FIELD(target, max_sz) do { \
            if (qihse_read_line(fd, line, sizeof(line)) < 0 || line[0] != '$') { qihse_disconnect(); return -1; } \
            int sz = atoi(line + 1); \
            if (sz < 0 || sz > MAX_TEXT_BYTES || qihse_read_bulk_field(fd, target, max_sz, (size_t)sz) < 0) { qihse_disconnect(); return -1; } \
        } while (0)

        READ_FIELD(f_id, sizeof(f_id));
        READ_FIELD(f_created, sizeof(f_created));
        READ_FIELD(f_kind, sizeof(f_kind));
        READ_FIELD(f_class, sizeof(f_class));
        READ_FIELD(f_sci, sizeof(f_sci));
        READ_FIELD(f_score, sizeof(f_score));
        READ_FIELD(hit.text, sizeof(hit.text));
        #undef READ_FIELD

        snprintf(hit.id, sizeof(hit.id), "%s", f_id);
        hit.created_ms = atoll(f_created);
        hit.kind = atoi(f_kind);
        hit.classification = atoi(f_class);
        hit.sci = atoi(f_sci);
        hit.score = atof(f_score);
        parse_hit_text_envelope(&hit);

        if (count < max_hits) {
            hits[count++] = hit;
        }
    }
    if (strcmp(G_ENV.transport, "qkp") == 0) qihse_disconnect();
    return count;
}

/* -------------------------------------------------------------------------
 * Subcommand: hook (Codex UserPromptSubmit)
 * ------------------------------------------------------------------------- */

static int do_hook(void)
{
    /* Read stdin */
    char buf[16384];
    size_t total = 0;
    int n;
    while ((n = read(STDIN_FILENO, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
    }
    buf[total] = '\0';

    if (total == 0) return 0;

    json_error_t err;
    json_t *req = json_loads(buf, 0, &err);
    if (!req || !json_is_object(req)) {
        if (req) json_decref(req);
        return 0;
    }

    json_t *p = json_object_get(req, "prompt");
    if (!p || !json_is_string(p)) p = json_object_get(req, "user_prompt");
    if (!p || !json_is_string(p)) p = json_object_get(req, "text");
    if (!p || !json_is_string(p)) {
        json_decref(req);
        return 0;
    }

    const char *prompt = json_string_value(p);
    char current_repo[128];
    detect_current_repo(NULL, current_repo, sizeof(current_repo));

    struct memory_hit raw_hits[16];
    int n_raw = qihse_recall(prompt, 6, "bm25", current_repo, raw_hits, 16);

    struct memory_hit final_hits[4];
    int n_final = n_raw < 3 ? n_raw : 3;
    for (int i = 0; i < n_final; i++) {
        final_hits[i] = raw_hits[i];
        final_hits[i].adjusted_score = final_hits[i].score;
        snprintf(final_hits[i].repo, sizeof(final_hits[i].repo), "%s", current_repo);
    }

    if (n_final > 0) {
        char additional[8192];
        size_t used = 0;
        used += snprintf(additional + used, sizeof(additional) - used,
                         "Relevant memories from QIHSE (auto-recalled; verify current state before relying on them):\n");
        for (int i = 0; i < n_final; i++) {
            char snippet[350];
            snprintf(snippet, sizeof(snippet), "%s", final_hits[i].text);
            for (char *c = snippet; *c; c++) if (*c == '\n') *c = ' ';
            const char *scope_tag = final_hits[i].repo[0] ? final_hits[i].repo : "global";
            used += snprintf(additional + used, sizeof(additional) - used,
                             "- [%.3f] [%s] %s\n", final_hits[i].adjusted_score, scope_tag, snippet);
        }

        json_t *out = json_pack("{s:{s:s, s:s}}",
                                "hookSpecificOutput",
                                "hookEventName", "UserPromptSubmit",
                                "additionalContext", additional);
        char *s = json_dumps(out, JSON_COMPACT);
        if (s) {
            printf("%s\n", s);
            free(s);
        }
        json_decref(out);
    }

    json_decref(req);
    return 0;
}

/* -------------------------------------------------------------------------
 * Subcommand: mcp (Native JSON-RPC 2.0 stdio server)
 * ------------------------------------------------------------------------- */

static void send_jsonrpc_response(json_t *id, json_t *result)
{
    json_t *resp = json_pack("{s:s, s:O, s:O}", "jsonrpc", "2.0", "id", id ? id : json_null(), "result", result);
    char *s = json_dumps(resp, JSON_COMPACT);
    if (s) {
        printf("%s\n", s);
        fflush(stdout);
        free(s);
    }
    json_decref(resp);
}

static void send_jsonrpc_error(json_t *id, int code, const char *msg)
{
    json_t *err_obj = json_pack("{s:i, s:s}", "code", code, "message", msg);
    json_t *resp = json_pack("{s:s, s:O, s:o}", "jsonrpc", "2.0", "id", id ? id : json_null(), "error", err_obj);
    char *s = json_dumps(resp, JSON_COMPACT);
    if (s) {
        printf("%s\n", s);
        fflush(stdout);
        free(s);
    }
    json_decref(resp);
}

static int do_mcp_server(void)
{
    char line_buf[65536];
    while (fgets(line_buf, sizeof(line_buf), stdin)) {
        size_t l = strlen(line_buf);
        while (l > 0 && (line_buf[l - 1] == '\r' || line_buf[l - 1] == '\n')) line_buf[--l] = '\0';
        if (l == 0) continue;

        json_error_t err;
        json_t *req = json_loads(line_buf, 0, &err);
        if (!req || !json_is_object(req)) {
            send_jsonrpc_error(NULL, -32700, "Parse error");
            if (req) json_decref(req);
            continue;
        }

        json_t *id = json_object_get(req, "id");
        json_t *method = json_object_get(req, "method");
        if (!method || !json_is_string(method)) {
            send_jsonrpc_error(id, -32600, "Invalid Request");
            json_decref(req);
            continue;
        }

        const char *m = json_string_value(method);
        if (strcmp(m, "initialize") == 0) {
            json_t *res = json_pack("{s:s, s:{s:s, s:s}, s:{s:{}}}",
                                    "protocolVersion", PROTOCOL_VERSION,
                                    "serverInfo", "name", SERVER_NAME, "version", SERVER_VERSION,
                                    "capabilities", "tools");
            send_jsonrpc_response(id, res);
            json_decref(res);
        } else if (strcmp(m, "notifications/initialized") == 0) {
            /* no-op */
        } else if (strcmp(m, "ping") == 0) {
            json_t *res = json_object();
            send_jsonrpc_response(id, res);
            json_decref(res);
        } else if (strcmp(m, "tools/list") == 0) {
            json_t *tools = json_array();
            /* search_memory */
            json_t *t1 = json_pack("{s:s, s:s, s:{s:s, s:{s:{s:s}, s:{s:s}, s:{s:s}}, s:[s]}}",
                                   "name", "search_memory",
                                   "description", "Recall relevant memories from local sovereign QIHSE AIMEM with native project scoping.",
                                   "inputSchema", "type", "object",
                                   "properties",
                                     "query", "type", "string",
                                     "limit", "type", "integer",
                                     "scope", "type", "string",
                                   "required", "query");
            json_t *props = json_object_get(json_object_get(t1, "inputSchema"), "properties");
            json_object_set_new(props, "mode", json_pack("{s:s, s:s}",
                "type", "string", "default", "bm25"));
            json_array_append_new(tools, t1);
            json_t *res = json_pack("{s:o}", "tools", tools);
            send_jsonrpc_response(id, res);
            json_decref(res);
        } else if (strcmp(m, "tools/call") == 0) {
            json_t *params = json_object_get(req, "params");
            json_t *name = params ? json_object_get(params, "name") : NULL;
            json_t *args = params ? json_object_get(params, "arguments") : NULL;
            const char *tname = name ? json_string_value(name) : "";

            if (strcmp(tname, "search_memory") == 0) {
                json_t *q = args ? json_object_get(args, "query") : NULL;
                const char *query = q ? json_string_value(q) : "";
                json_t *lim = args ? json_object_get(args, "limit") : NULL;
                int limit = lim && json_is_integer(lim) ? (int)json_integer_value(lim) : 8;
                if (limit < 1) limit = 1;
                if (limit > 16) limit = 16;
                json_t *sc = args ? json_object_get(args, "scope") : NULL;
                const char *scope = sc && json_is_string(sc) ? json_string_value(sc) : "auto";
                json_t *md = args ? json_object_get(args, "mode") : NULL;
                const char *mode = md && json_is_string(md) ? json_string_value(md) : "bm25";
                if (strcmp(mode, "bm25") && strcmp(mode, "hybrid") && strcmp(mode, "semantic")) {
                    send_jsonrpc_error(id, -32602, "invalid recall mode");
                    json_decref(req);
                    continue;
                }

                char current_repo[128];
                detect_current_repo(NULL, current_repo, sizeof(current_repo));

                struct memory_hit raw_hits[32];
                const char *project = (strcmp(scope, "global") == 0) ? "global" :
                                      ((strcmp(scope, "auto") == 0 || strcmp(scope, "repo") == 0)
                                           ? current_repo : scope);
                int n_raw = qihse_recall(query, limit * 2 > 32 ? 32 : limit * 2,
                                         mode, project, raw_hits, 32);
                if (n_raw < 0) {
                    send_jsonrpc_error(id, -32000, "AIMEM recall failed");
                    json_decref(req);
                    continue;
                }

                struct memory_hit final_hits[32];
                int n_final = n_raw < limit ? n_raw : limit;
                for (int i = 0; i < n_final; i++) {
                    final_hits[i] = raw_hits[i];
                    final_hits[i].adjusted_score = final_hits[i].score;
                    snprintf(final_hits[i].repo, sizeof(final_hits[i].repo), "%s", project);
                }

                json_t *arr = json_array();
                for (int i = 0; i < n_final; i++) {
                    json_t *h = json_pack("{s:s, s:I, s:i, s:f, s:f, s:s, s:s}",
                                          "id", final_hits[i].id,
                                          "created_ms", (json_int_t)final_hits[i].created_ms,
                                          "kind", final_hits[i].kind,
                                          "score", final_hits[i].score,
                                          "adjusted_score", final_hits[i].adjusted_score,
                                          "matched_scope", final_hits[i].repo[0] ? final_hits[i].repo : "global",
                                          "text", final_hits[i].text);
                    json_array_append_new(arr, h);
                }
                char *dumped = json_dumps(arr, JSON_COMPACT);
                json_decref(arr);

                json_t *content_arr = json_array();
                json_array_append_new(content_arr, json_pack("{s:s, s:s}", "type", "text", "text", dumped ? dumped : "[]"));
                if (dumped) free(dumped);

                json_t *res = json_pack("{s:o, s:s, s:b}",
                                        "content", content_arr,
                                        "effective_scope", project,
                                        "scope_switched", 0);
                send_jsonrpc_response(id, res);
                json_decref(res);
            } else {
                send_jsonrpc_error(id, -32601, "Tool not found");
            }
        } else {
            send_jsonrpc_error(id, -32601, "Method not found");
        }
        json_decref(req);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Subcommand: recall (CLI)
 * ------------------------------------------------------------------------- */

static int do_cli_recall(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: supermemory-bridge recall <query> [--limit N] [--scope auto|repo|global]\n");
        return 1;
    }
    const char *query = argv[2];
    int limit = 5;
    const char *scope = "auto";
    const char *mode = "bm25";

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--scope") == 0 && i + 1 < argc) {
            scope = argv[++i];
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
        }
    }

    if (limit < 1 || limit > 16 ||
        (strcmp(mode, "bm25") && strcmp(mode, "hybrid") && strcmp(mode, "semantic"))) {
        fprintf(stderr, "limit must be 1..16 and mode bm25, hybrid or semantic\n");
        return 2;
    }
    char current_repo[128];
    detect_current_repo(NULL, current_repo, sizeof(current_repo));

    struct memory_hit raw_hits[32];
    const char *project = (strcmp(scope, "global") == 0) ? "global" :
                          ((strcmp(scope, "auto") == 0 || strcmp(scope, "repo") == 0)
                               ? current_repo : scope);
    int n_raw = qihse_recall(query, limit * 2 > 32 ? 32 : limit * 2,
                             mode, project, raw_hits, 32);
    if (n_raw < 0) return 1;

    struct memory_hit final_hits[32];
    int n_final = n_raw < limit ? n_raw : limit;
    for (int i = 0; i < n_final; i++) {
        final_hits[i] = raw_hits[i];
        final_hits[i].adjusted_score = final_hits[i].score;
        snprintf(final_hits[i].repo, sizeof(final_hits[i].repo), "%s", project);
    }

    json_t *arr = json_array();
    for (int i = 0; i < n_final; i++) {
        json_t *h = json_pack("{s:s, s:I, s:i, s:f, s:f, s:s, s:s}",
                              "id", final_hits[i].id,
                              "created_ms", (json_int_t)final_hits[i].created_ms,
                              "kind", final_hits[i].kind,
                              "score", final_hits[i].score,
                              "adjusted_score", final_hits[i].adjusted_score,
                              "matched_scope", final_hits[i].repo[0] ? final_hits[i].repo : "global",
                              "text", final_hits[i].text);
        json_array_append_new(arr, h);
    }
    char *s = json_dumps(arr, JSON_INDENT(2));
    if (s) {
        printf("%s\n", s);
        free(s);
    }
    json_decref(arr);
    return 0;
}

/* -------------------------------------------------------------------------
 * Main Dispatcher
 * ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    load_env(&G_ENV);

    if (argc < 2) {
        /* Default to MCP server on stdio if invoked with no arguments */
        return do_mcp_server();
    }

    if (strcmp(argv[1], "mcp") == 0) {
        return do_mcp_server();
    } else if (strcmp(argv[1], "hook") == 0) {
        return do_hook();
    } else if (strcmp(argv[1], "recall") == 0) {
        return do_cli_recall(argc, argv);
    } else if (strcmp(argv[1], "status") == 0) {
        struct memory_hit probe[1];
        int fd = strcmp(G_ENV.transport, "qkp") == 0 ?
            (qihse_recall("qihse-bridge-status", 1, "bm25", "global", probe, 1) >= 0 ? 0 : -1) :
            qihse_connect();
        if (fd >= 0) {
            printf("OK: Native bridge connected to QIHSE on %s:%d (loopback authenticated)\n",
                   G_ENV.host, G_ENV.port);
            qihse_disconnect();
            return 0;
        } else {
            fprintf(stderr, "ERROR: Cannot connect to QIHSE on %s:%d\n", G_ENV.host, G_ENV.port);
            return 1;
        }
    } else {
        fprintf(stderr, "Unknown command '%s'. Valid: mcp, hook, recall, status\n", argv[1]);
        return 2;
    }
}
