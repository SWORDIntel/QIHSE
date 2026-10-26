/* QKP-only administration client. Server pin verification and principal
 * authorization are unchanged; every mode uses the shared native admin API. */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "qihse_qkp.h"

#define ADMIN_MAX_ARGS 256u
static const char* g_host;
static uint16_t g_port = 7100;
static const char* g_identity_dir;
static const char* g_trusted_pub;
static const char* g_node_id;
static const char* g_user;
static const char* g_password_env;
static const char* g_command;
static const char* g_args[ADMIN_MAX_ARGS];
static size_t g_argc;
static bool g_interactive, g_batch, g_stdin_value, g_strict;
static bool g_json, g_resp;
static unsigned g_timeout = 30000u;

static void usage(int code) {
    fprintf(code ? stderr : stdout,
        "usage: qihse-admin-cli [options] [CMD [ARG ...]]\n"
        "Connection (QKP only; no cleartext fallback):\n"
        "  --host, -H HOST          $QIHSE_HOST\n"
        "  --port, -p PORT          $QIHSE_PORT (default 7100)\n"
        "  --identity-dir, -i DIR   $QIHSE_IDENTITY_DIR; local keys or system keys\n"
        "  --trusted-pub, -t FILE   $QIHSE_TRUSTED_PUB; required server pin\n"
        "  --node-id, -n ID         $QIHSE_NODE_ID (default admin-cli)\n"
        "  --timeout-ms MS         Connect/socket wait timeout (default 30000)\n"
        "  --user USER             AUTH principal ($QIHSE_AUTH_USER)\n"
        "  --password-env NAME     Read AUTH password from named environment variable\n"
        "                          Default QIHSE_AUTH_PASSWORD when --user is set\n"
        "Execution:\n"
        "  CMD [ARG ...]           Any server RESP2 command, arguments passed exactly\n"
        "  --command, -c TEXT      Quote-aware command (single/double quotes, escapes)\n"
        "  --arg ARG               Append an exact text argument, repeatable\n"
        "  -x                      Append stdin bytes verbatim, including NUL/newlines\n"
        "  --stdin, --batch        Commands by line; one handshake, persistent state\n"
        "  --interactive, --repl   Persistent interactive shell (EXIT exits locally)\n"
        "  --json                  Nested JSON replies; strings use byte/Latin-1 mapping\n"
        "  --resp                  Exact RESP2 reply bytes, no added separators\n"
        "  --fail-on-error         Exit 5 on any RESP error, including nested errors\n"
        "  --                      End option parsing\n"
        "Shortcuts:\n"
        "  --ping | --info [SECTION] | --dbsize | --save | --bgsave\n"
        "  --cluster-info | --cluster-nodes | --cluster-slots | --cluster-failover\n"
        "  --cluster-keyslot KEY | --cluster-reclaim [LIMIT] | --repl-status\n"
        "  --cluster-moveslots FIRST-LAST HOST:PORT\n"
        "  --help, -h\n"
        "Use COMMAND / COMMAND DOCS for server capabilities. AIMEM, USER, vector,\n"
        "graph, search and cluster commands need no client-specific aliases.\n"
        "Synchronous RESP2 only: no pub/sub streaming or automatic MOVED retries.\n"
        "Exit: 0 success, 2 usage/config, 3 connection/handshake, 5 command/I/O.\n");
    exit(code);
}

static unsigned parse_uint(const char* text, unsigned max) {
    char* end = NULL;
    errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (!*text || !isdigit((unsigned char)*text) || errno || *end || !n || n > max) {
        fprintf(stderr, "invalid numeric option: %s\n", text);
        usage(2);
    }
    return (unsigned)n;
}

static bool push_arg(const char* arg) {
    if (g_argc == ADMIN_MAX_ARGS) {
        fprintf(stderr, "too many arguments (max %u)\n", ADMIN_MAX_ARGS);
        return false;
    }
    g_args[g_argc++] = arg;
    return true;
}

static bool parse_command_line(char* line, const char** argv, size_t* argc) {
    *argc = 0u;
    char* p = line;
    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p || *p == '#') break;
        if (*argc == ADMIN_MAX_ARGS) return false;
        char* dst = p;
        argv[(*argc)++] = dst;
        char quote = 0;
        while (*p) {
            if (quote && *p == quote) { quote = 0; p++; }
            else if (!quote && (*p == '\'' || *p == '"')) quote = *p++;
            else if (!quote && isspace((unsigned char)*p)) { p++; break; }
            else if (*p == '\\' && quote != '\'') {
                p++;
                if (!*p) return false;
                if (quote == '"' && *p == 'n') *dst++ = '\n';
                else if (quote == '"' && *p == 'r') *dst++ = '\r';
                else if (quote == '"' && *p == 't') *dst++ = '\t';
                else *dst++ = *p;
                p++;
            } else *dst++ = *p++;
        }
        if (quote) return false;
        *dst = '\0';
    }
    return true;
}

/* A bounded reader avoids executing the second half of an oversized line. */
static char* read_input(bool line, size_t* len) {
    size_t cap = 4096u;
    *len = 0u;
    char* buf = malloc(cap);
    if (!buf) return NULL;
    int c;
    while ((c = fgetc(stdin)) != EOF) {
        if (*len == QIHSE_QKP_ADMIN_MAX_BYTES) { free(buf); return NULL; }
        if (*len + 1u == cap) {
            size_t next = cap * 2u;
            char* grown = realloc(buf, next);
            if (!grown) { free(buf); return NULL; }
            buf = grown;
            cap = next;
        }
        buf[(*len)++] = (char)c;
        if (line && c == '\n') break;
    }
    if (ferror(stdin)) { free(buf); return NULL; }
    buf[*len] = '\0';
    return buf;
}

static int execute(qihse_qkp_admin_client_t* client, size_t argc,
                   const char* const* argv, const size_t* lengths, bool auth,
                   bool* transport_error) {
    char error[512] = {0};
    char* reply = NULL;
    size_t reply_len = 0u;
    int rc = qihse_qkp_admin_command(client, argc, argv, lengths,
                                    &reply, &reply_len, error, sizeof(error));
    *transport_error = rc != 0;
    if (rc) { fprintf(stderr, "%s\n", error); return rc; }
    if (auth) {
        bool ok = reply_len == 5u && memcmp(reply, "+OK\r\n", 5u) == 0;
        qihse_qkp_admin_free(reply);
        if (!ok) fprintf(stderr, "AUTH rejected; no commands executed\n");
        return ok ? 0 : 5;
    }
    char* output = NULL;
    size_t output_len = 0u;
    bool is_error = false;
    rc = qihse_qkp_admin_format(reply, reply_len, g_json, &output, &output_len, &is_error);
    if (!rc) {
        const char* data = g_resp ? reply : output;
        size_t len = g_resp ? reply_len : output_len;
        if (fwrite(data, 1u, len, stdout) != len || fflush(stdout) == EOF) rc = 5;
    }
    qihse_qkp_admin_free(output);
    qihse_qkp_admin_free(reply);
    *transport_error = rc != 0;
    return rc ? rc : (is_error && g_strict ? 5 : 0);
}

int main(int argc, char** argv) {
    g_host = getenv("QIHSE_HOST");
    g_trusted_pub = getenv("QIHSE_TRUSTED_PUB");
    g_identity_dir = getenv("QIHSE_IDENTITY_DIR");
    g_node_id = getenv("QIHSE_NODE_ID");
    g_user = getenv("QIHSE_AUTH_USER");
    const char* env_port = getenv("QIHSE_PORT");
    if (env_port && *env_port) g_port = (uint16_t)parse_uint(env_port, 65535u);
    if (!g_node_id || !*g_node_id) g_node_id = "admin-cli";
    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
#define OPTION(longopt, shortopt) (strcmp(a, longopt) == 0 || strcmp(a, shortopt) == 0)
#define VALUE() ((i + 1 < argc) ? argv[++i] : (usage(2), (char*)NULL))
        if (OPTION("--help", "-h")) usage(0);
        else if (OPTION("--host", "-H")) g_host = VALUE();
        else if (OPTION("--port", "-p")) g_port = (uint16_t)parse_uint(VALUE(), 65535u);
        else if (OPTION("--identity-dir", "-i")) g_identity_dir = VALUE();
        else if (OPTION("--trusted-pub", "-t")) g_trusted_pub = VALUE();
        else if (OPTION("--node-id", "-n")) g_node_id = VALUE();
        else if (strcmp(a, "--timeout-ms") == 0) g_timeout = parse_uint(VALUE(), INT_MAX);
        else if (strcmp(a, "--user") == 0) g_user = VALUE();
        else if (strcmp(a, "--password-env") == 0) g_password_env = VALUE();
        else if (OPTION("--command", "-c")) {
            if (g_command) usage(2);
            g_command = VALUE();
        } else if (strcmp(a, "--arg") == 0) { if (!push_arg(VALUE())) return 2; }
        else if (strcmp(a, "-x") == 0) g_stdin_value = true;
        else if (OPTION("--interactive", "--repl")) g_interactive = true;
        else if (OPTION("--stdin", "--batch")) g_batch = true;
        else if (strcmp(a, "--fail-on-error") == 0) g_strict = true;
        else if (strcmp(a, "--json") == 0) g_json = true;
        else if (strcmp(a, "--resp") == 0) g_resp = true;
        else if (strcmp(a, "--ping") == 0) { if (!push_arg("PING")) return 2; }
        else if (strcmp(a, "--dbsize") == 0) { if (!push_arg("DBSIZE")) return 2; }
        else if (strcmp(a, "--save") == 0) { if (!push_arg("SAVE")) return 2; }
        else if (strcmp(a, "--bgsave") == 0) { if (!push_arg("BGSAVE")) return 2; }
        else if (strcmp(a, "--repl-status") == 0) { if (!push_arg("REPL.STATUS")) return 2; }
        else if (strcmp(a, "--info") == 0 || strcmp(a, "--cluster-reclaim") == 0) {
            if (strcmp(a, "--info") == 0) { if (!push_arg("INFO")) return 2; }
            else if (!push_arg("CLUSTER") || !push_arg("RECLAIM")) return 2;
            if (i + 1 < argc && argv[i + 1][0] != '-') { if (!push_arg(argv[++i])) return 2; }
        } else if (strcmp(a, "--cluster-keyslot") == 0) {
            if (!push_arg("CLUSTER") || !push_arg("KEYSLOT") || !push_arg(VALUE())) return 2;
        } else if (strcmp(a, "--cluster-info") == 0 || strcmp(a, "--cluster-nodes") == 0 ||
                   strcmp(a, "--cluster-slots") == 0 || strcmp(a, "--cluster-failover") == 0) {
            if (!push_arg("CLUSTER") || !push_arg(a + 10)) return 2;
        } else if (strcmp(a, "--cluster-moveslots") == 0) {
            if (!push_arg("CLUSTER") || !push_arg("MOVESLOTS")) return 2;
            static char range[64], target[280];
            if (i + 4 < argc && !strchr(argv[i + 1], '-') && !strchr(argv[i + 3], ':') && argv[i + 3][0] != '-') {
                if (snprintf(range, sizeof(range), "%s-%s", argv[i + 1], argv[i + 2]) >= (int)sizeof(range) ||
                    snprintf(target, sizeof(target), "%s:%s", argv[i + 3], argv[i + 4]) >= (int)sizeof(target)) usage(2);
                if (!push_arg(range) || !push_arg(target)) return 2;
                i += 4;
            } else if (!push_arg(VALUE()) || !push_arg(VALUE())) return 2;
        } else {
            if (strcmp(a, "--") == 0) i++;
            else if (*a == '-') { fprintf(stderr, "unknown option: %s\n", a); usage(2); }
            for (; i < argc; i++) if (!push_arg(argv[i])) return 2;
            break;
        }
#undef VALUE
#undef OPTION
    }
    if (!g_host || !*g_host || !g_trusted_pub || !*g_trusted_pub || (g_json && g_resp) ||
        (g_interactive && g_batch) ||
        ((g_interactive || g_batch) && (g_argc || g_command || g_stdin_value))) usage(2);
    const char* password = NULL;
    if ((g_user && *g_user) || g_password_env) {
        if (!g_user || !*g_user) usage(2);
        password = getenv(g_password_env ? g_password_env : "QIHSE_AUTH_PASSWORD");
        if (!password || !*password) { fprintf(stderr, "AUTH password environment variable missing/empty\n"); return 2; }
    }
    const char* cargv[ADMIN_MAX_ARGS];
    size_t lengths[ADMIN_MAX_ARGS], cargc = 0u;
    char* command_buf = NULL;
    char* stdin_value = NULL;
    if (g_command) {
        if (strlen(g_command) > QIHSE_QKP_ADMIN_MAX_BYTES) return 2;
        command_buf = strdup(g_command);
        if (!command_buf || !parse_command_line(command_buf, cargv, &cargc)) {
            free(command_buf); fprintf(stderr, "invalid command line\n"); return 2;
        }
    }
    int rc = 2;
    if (cargc + g_argc + (g_stdin_value ? 1u : 0u) > ADMIN_MAX_ARGS) goto done;
    for (size_t i = 0; i < g_argc; i++) cargv[cargc++] = g_args[i];
    if (!cargc && !g_batch && !g_interactive) cargv[cargc++] = "PING";
    for (size_t i = 0; i < cargc; i++) lengths[i] = strlen(cargv[i]);
    if (g_stdin_value) {
        stdin_value = read_input(false, &lengths[cargc]);
        if (!stdin_value) { fprintf(stderr, "stdin read failed or exceeds 64 MiB\n"); goto done; }
        cargv[cargc++] = stdin_value;
    }
    qihse_qkp_admin_client_t* client = NULL;
    char error[512] = {0};
    rc = qihse_qkp_admin_open(g_host, g_port, g_node_id, g_identity_dir, g_trusted_pub,
                             g_timeout, &client, error, sizeof(error));
    if (rc) { fprintf(stderr, "%s\n", error); goto done; }
    bool fatal = false;
    if (password) {
        const char* auth[] = {"AUTH", g_user, password};
        rc = execute(client, 3u, auth, NULL, true, &fatal);
        if (rc) goto close_client;
    }
    if (!g_batch && !g_interactive) rc = execute(client, cargc, cargv, lengths, false, &fatal);
    else for (;;) {
        if (g_interactive && isatty(STDIN_FILENO)) {
            fprintf(stderr, "qkp %s:%u> ", g_host, (unsigned)g_port);
            fflush(stderr);
        }
        size_t len = 0u;
        char* line = read_input(true, &len);
        if (!line) { fprintf(stderr, "command input failed or exceeds 64 MiB\n"); rc = 2; break; }
        if (!len) { free(line); break; }
        if (memchr(line, '\0', len) || !parse_command_line(line, cargv, &cargc)) {
            fprintf(stderr, "invalid command line\n"); free(line); rc = 2;
            if (!g_interactive) break;
            continue;
        }
        if (!cargc) { free(line); continue; }
        if (cargc == 1u && strcasecmp(cargv[0], "EXIT") == 0) { free(line); break; }
        bool quit = cargc == 1u && strcasecmp(cargv[0], "QUIT") == 0;
        int result = execute(client, cargc, cargv, NULL, false, &fatal);
        free(line);
        if (result) rc = result;
        if (fatal || quit || (result && !g_interactive)) break;
    }
close_client:
    qihse_qkp_admin_close(client);
done:
    free(stdin_value);
    free(command_buf);
    return rc;
}
