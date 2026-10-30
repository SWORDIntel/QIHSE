/* QKP-only administration client. Server pin verification and principal
 * authorization are unchanged; every mode uses the shared native admin API. */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
static bool g_arg_files[ADMIN_MAX_ARGS];
static size_t g_argc;
static const char* g_positional_command;
static bool g_shortcut, g_has_arg_file;
static bool g_interactive, g_batch, g_stdin_value, g_strict;
static bool g_json, g_resp;
static unsigned g_timeout = 30000u;
#define AUTHORITY_WIRE_MAX (8u * 1024u * 1024u)
static const char* g_authority_export;
static const char* g_authority_import;
static const char* g_expected_position;
static const char* g_request_id;
static const char* g_transfer_config;
static bool g_authority_checkpoint, g_authority_capabilities;

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
        "  --arg-file PATH         Append one binary argument from a regular file\n"
        "  -x                      Append stdin bytes verbatim, including NUL/newlines\n"
        "  --stdin, --batch        Commands by line; one handshake, persistent state\n"
        "  --interactive, --repl   Persistent interactive shell (EXIT exits locally)\n"
        "  --json                  Nested JSON replies; strings use byte/Latin-1 mapping\n"
        "  --resp                  Exact RESP2 reply bytes, no added separators\n"
        "  --fail-on-error         Exit 5 on any RESP error, including nested errors\n"
        "  --                      End option parsing\n"
        "Authority maintenance (authenticated full-ceiling Operator):\n"
        "  --authority-capabilities\n"
        "  --authority-export FILE  Create private ciphertext archive (never overwrite)\n"
        "  --authority-import FILE  Read private ciphertext archive\n"
        "  --authority-checkpoint\n"
        "  --expected-position HEX  Required for import/checkpoint; 96 hex digits\n"
        "  --request-id HEX         Required for import; 32 hex digits, durable retry ID\n"
        "  --transfer-config FILE   Required for export/import; pinned transfer descriptor\n"
        "  Negotiates before maintenance; unsupported export exits 6, no fallback.\n"
        "Shortcuts:\n"
        "  --ping | --info [SECTION] | --dbsize | --save | --bgsave\n"
        "  --cluster-info | --cluster-nodes | --cluster-slots | --cluster-failover\n"
        "  --cluster-keyslot KEY | --cluster-reclaim [LIMIT] | --repl-status\n"
        "  --cluster-moveslots FIRST-LAST HOST:PORT\n"
        "  --help, -h\n"
        "Use COMMAND / COMMAND DOCS for server capabilities. AIMEM, USER, vector,\n"
        "graph, search and cluster commands need no client-specific aliases.\n"
        "Synchronous RESP2 only: no pub/sub streaming or automatic MOVED retries.\n"
        "Exit: 0 success, 2 usage/config, 3 connection/handshake, 5 command/I/O,\n"
        "      6 UNSUPPORTED_EXPORT_API (source left running and unchanged).\n");
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

static size_t decimal_digits(size_t value) {
    size_t digits = 1u;
    while (value >= 10u) { value /= 10u; digits++; }
    return digits;
}

static bool account_arg(size_t* used, size_t length) {
    size_t header = decimal_digits(length) + 5u; /* $length\r\n...\r\n */
    if (header > QIHSE_QKP_ADMIN_MAX_BYTES - *used ||
        length > QIHSE_QKP_ADMIN_MAX_BYTES - *used - header) return false;
    *used += header + length;
    return true;
}

static int authority_parent(const char* path, char** storage, char** name);

static char* read_arg_file(const char* path, size_t* length, size_t remaining, bool private_file) {
    int fd;
    if (private_file) {
        char *storage = NULL, *name = NULL;
        int parent = authority_parent(path, &storage, &name);
        fd = parent < 0 ? -1 : openat(parent, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (parent >= 0) close(parent);
        free(storage);
    } else fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return NULL;
    struct stat st;
    char* buf = NULL;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size > remaining ||
        (private_file && (st.st_uid != geteuid() || (st.st_mode & 077u) || st.st_nlink != 1u))) goto done;
    *length = (size_t)st.st_size;
    buf = malloc(*length ? *length : 1u);
    if (!buf) goto done;
    size_t got = 0u;
    while (got < *length) {
        ssize_t n = read(fd, buf + got, *length - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto fail;
        got += (size_t)n;
    }
    /* Reject concurrent growth, including growth past the request bound. */
    char extra;
    ssize_t n;
    do { n = read(fd, &extra, 1u); } while (n < 0 && errno == EINTR);
    if (n != 0) goto fail;
    struct stat end;
    if (fstat(fd, &end) != 0 || end.st_size != st.st_size ||
        end.st_dev != st.st_dev || end.st_ino != st.st_ino ||
        end.st_mtim.tv_sec != st.st_mtim.tv_sec ||
        end.st_mtim.tv_nsec != st.st_mtim.tv_nsec ||
        end.st_ctim.tv_sec != st.st_ctim.tv_sec ||
        end.st_ctim.tv_nsec != st.st_ctim.tv_nsec) goto fail;
    goto done;
fail:
    free(buf);
    buf = NULL;
done:
    close(fd);
    return buf;
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

typedef struct {
    unsigned mode;
    bool ready, exporting, importing, checkpoint;
    size_t limit;
    char position[97];
} authority_caps_t;

static bool authority_hex(const char* text, size_t length) {
    if (!text || strlen(text) != length) return false;
    for (size_t i = 0; i < length; i++)
        if (!isxdigit((unsigned char)text[i])) return false;
    return true;
}

static bool authority_number(const char** cursor, const char* end, char type, size_t* out) {
    const char* p = *cursor;
    if (p == end || *p++ != type || p == end || !isdigit((unsigned char)*p)) return false;
    size_t value = 0u;
    do {
        unsigned digit = (unsigned)(*p++ - '0');
        if (value > (SIZE_MAX - digit) / 10u) return false;
        value = value * 10u + digit;
    } while (p < end && isdigit((unsigned char)*p));
    if ((size_t)(end - p) < 2u || p[0] != '\r' || p[1] != '\n') return false;
    *cursor = p + 2u;
    *out = value;
    return true;
}

static bool authority_bulk(const char** cursor, const char* end,
                           const char** data, size_t* length) {
    if (!authority_number(cursor, end, '$', length) ||
        *length > (size_t)(end - *cursor) || (size_t)(end - *cursor) - *length < 2u)
        return false;
    *data = *cursor;
    *cursor += *length;
    if ((*cursor)[0] != '\r' || (*cursor)[1] != '\n') return false;
    *cursor += 2u;
    return true;
}

static int authority_reply_error(const char* reply, size_t length, bool exporting);

static int authority_negotiate(qihse_qkp_admin_client_t* client, authority_caps_t* caps) {
    const char* args[] = {"AUTHORITY.CAPABILITIES"};
    char error[512] = {0}, *reply = NULL;
    size_t length = 0u;
    int rc = qihse_qkp_admin_command(client, 1u, args, NULL, &reply, &length, error, sizeof(error));
    if (rc) { qihse_qkp_admin_free(reply); fprintf(stderr, "authority negotiation transport failure\n"); return rc; }
    if (!reply) { fprintf(stderr, "UNSUPPORTED_EXPORT_API: missing capability reply; source unchanged\n"); return 6; }
    if (length && reply[0] == '-') {
        int status = authority_reply_error(reply, length, true);
        qihse_qkp_admin_free(reply);
        return status;
    }
    const char* p = reply;
    const char* end = reply + length;
    const char* text = NULL;
    size_t count, n, values[6];
    bool ok = authority_number(&p, end, '*', &count) && count == 8u &&
        authority_bulk(&p, end, &text, &n) && n == strlen("QIHSE_AUTHORITY_V1") &&
        memcmp(text, "QIHSE_AUTHORITY_V1", n) == 0;
    for (size_t i = 0; ok && i < 6u; i++) ok = authority_number(&p, end, ':', &values[i]);
    ok = ok && values[0] <= 2u && values[1] <= 1u && values[2] <= 1u &&
        values[3] <= 1u && values[4] <= 1u && values[5] <= AUTHORITY_WIRE_MAX &&
        (values[5] || (!values[2] && !values[3])) && authority_bulk(&p, end, &text, &n) &&
        n == 96u && p == end;
    if (ok) {
        memcpy(caps->position, text, 96u);
        caps->position[96] = '\0';
        ok = authority_hex(caps->position, 96u);
    }
    if (ok) {
        caps->mode = (unsigned)values[0]; caps->ready = values[1] != 0u;
        caps->exporting = values[2] != 0u; caps->importing = values[3] != 0u;
        caps->checkpoint = values[4] != 0u; caps->limit = values[5];
    }
    qihse_qkp_admin_free(reply);
    if (!ok) {
        fprintf(stderr, "UNSUPPORTED_EXPORT_API: no compatible export API; source unchanged\n");
        return 6;
    }
    return 0;
}

static int authority_reply_error(const char* reply, size_t length, bool exporting) {
    static const char unknown[] = "-ERR unknown command";
    if (exporting && length >= sizeof(unknown) - 1u &&
        memcmp(reply, unknown, sizeof(unknown) - 1u) == 0) {
        fprintf(stderr, "UNSUPPORTED_EXPORT_API: unknown export command; source unchanged\n");
        return 6;
    }
    static const char* const names[] = {"INVALID", "DENIED", "UNSUPPORTED", "NOT_READY",
        "CONFLICT", "IO", "CORRUPT", "LIMIT", "UNCERTAIN"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char expected[64];
        int n = snprintf(expected, sizeof(expected), "-ERR AUTHORITY_%s\r\n", names[i]);
        if (n > 0 && length == (size_t)n && memcmp(reply, expected, length) == 0) {
            if (exporting && strcmp(names[i], "UNSUPPORTED") == 0) {
                fprintf(stderr, "UNSUPPORTED_EXPORT_API: export unavailable; source unchanged\n");
                return 6;
            }
            fprintf(stderr, "AUTHORITY_%s\n", names[i]);
            return 5;
        }
    }
    fprintf(stderr, "authority command rejected or malformed reply\n");
    return 5;
}

static int execute(qihse_qkp_admin_client_t* client, size_t argc,
                   const char* const* argv, const size_t* lengths, bool auth,
                   bool* transport_error) {
    bool maintenance = argc && strncasecmp(argv[0], "AUTHORITY.", 10u) == 0;
    if (maintenance && strcasecmp(argv[0], "AUTHORITY.CAPABILITIES") != 0) {
        authority_caps_t caps = {0};
        int result = authority_negotiate(client, &caps);
        if (result) { *transport_error = true; return result; }
        if (strcasecmp(argv[0], "AUTHORITY.EXPORT") == 0 && !caps.exporting) {
            fprintf(stderr, "UNSUPPORTED_EXPORT_API: server has no export capability; source unchanged\n");
            *transport_error = true;
            return 6;
        }
        if (!caps.ready) {
            fprintf(stderr, "authority is not ready\n"); *transport_error = true; return 5;
        }
        if ((strcasecmp(argv[0], "AUTHORITY.IMPORT") == 0 && !caps.importing) ||
            (strcasecmp(argv[0], "AUTHORITY.CHECKPOINT") == 0 && !caps.checkpoint)) {
            fprintf(stderr, "requested authority operation is unsupported\n");
            *transport_error = true;
            return 5;
        }
        if (strcasecmp(argv[0], "AUTHORITY.IMPORT") == 0 &&
            (argc != 5u || (lengths ? lengths[3] : strlen(argv[3])) != 253u ||
             !(lengths ? lengths[4] : strlen(argv[4])) ||
             (lengths ? lengths[4] : strlen(argv[4])) > caps.limit)) {
            fprintf(stderr, "invalid/bounded authority import arguments\n");
            *transport_error = true;
            return 5;
        }
        if (strcasecmp(argv[0], "AUTHORITY.EXPORT") == 0 &&
            (argc != 3u || (lengths ? lengths[2] : strlen(argv[2])) != 253u)) {
            fprintf(stderr, "authority export requires a 253-byte transfer descriptor\n");
            *transport_error = true;
            return 5;
        }
    }
    char error[512] = {0};
    char* reply = NULL;
    size_t reply_len = 0u;
    int rc = qihse_qkp_admin_command(client, argc, argv, lengths,
                                    &reply, &reply_len, error, sizeof(error));
    *transport_error = rc != 0;
    if (rc) { fprintf(stderr, "%s\n", error); return rc; }
    if (maintenance && reply_len && reply[0] == '-' &&
        strcasecmp(argv[0], "AUTHORITY.EXPORT") == 0 &&
        ((reply_len >= strlen("-ERR unknown command") &&
          memcmp(reply, "-ERR unknown command", strlen("-ERR unknown command")) == 0) ||
         (reply_len == strlen("-ERR AUTHORITY_UNSUPPORTED\r\n") &&
          memcmp(reply, "-ERR AUTHORITY_UNSUPPORTED\r\n", reply_len) == 0))) {
        rc = authority_reply_error(reply, reply_len, true);
        qihse_qkp_admin_free(reply);
        return rc;
    }
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
    return rc ? rc : (is_error && (g_strict || maintenance) ? 5 : 0);
}

/* Pin the parent directory before create; never follow a path component symlink.
 * Final directory must be private so a peer cannot replace a newly-created file. */
static int authority_parent(const char* path, char** storage, char** name) {
    *storage = strdup(path);
    if (!*storage) return -1;
    int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char* cursor = *storage;
    while (*cursor == '/') cursor++;
    for (;;) {
        char* slash = strchr(cursor, '/');
        if (!slash) break;
        *slash = '\0';
        if (*cursor && strcmp(cursor, ".") != 0) {
            if (strcmp(cursor, "..") == 0) { close(fd); return -1; }
            int next = openat(fd, cursor, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            close(fd);
            fd = next;
            if (fd < 0) return -1;
        }
        cursor = slash + 1;
    }
    struct stat st;
    if (fd < 0 || !*cursor || strcmp(cursor, ".") == 0 || strcmp(cursor, "..") == 0 ||
        fstat(fd, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 077u)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    *name = cursor;
    return fd;
}

static int authority_run(qihse_qkp_admin_client_t* client) {
    authority_caps_t caps = {0};
    int rc = authority_negotiate(client, &caps);
    if (rc) return rc;
    if (g_authority_capabilities) {
        bool fatal = false;
        const char* args[] = {"AUTHORITY.CAPABILITIES"};
        return execute(client, 1u, args, NULL, false, &fatal);
    }
    if (g_authority_export && !caps.exporting) {
        fprintf(stderr, "UNSUPPORTED_EXPORT_API: server has no export capability; source unchanged\n"); return 6;
    }
    if (!caps.ready) { fprintf(stderr, "authority is not ready\n"); return 5; }
    if ((g_authority_import && !caps.importing) || (g_authority_checkpoint && !caps.checkpoint)) {
        fprintf(stderr, "requested authority operation is unsupported\n"); return 5;
    }
    const char* args[5];
    size_t lengths[5], count = 0u;
    char *descriptor = NULL, *archive = NULL, *reply = NULL, *path_storage = NULL, *name = NULL;
    size_t descriptor_len = 0u, archive_len = 0u, reply_len = 0u;
    int dirfd = -1, fd = -1;
    bool created = false;
    rc = 5;
    if (g_transfer_config) {
        descriptor = read_arg_file(g_transfer_config, &descriptor_len, 253u, true);
        if (!descriptor || descriptor_len != 253u) {
            fprintf(stderr, "invalid/private transfer descriptor required (253 bytes)\n"); goto done;
        }
    }
    if (g_authority_export) {
        /* Reserve output before sending any materializing request. */
        dirfd = authority_parent(g_authority_export, &path_storage, &name);
        if (dirfd < 0) { fprintf(stderr, "export requires a private owned directory without symlinks\n"); goto done; }
        fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) { fprintf(stderr, "archive create failed (no overwrite)\n"); goto done; }
        created = true;
        args[count++] = "AUTHORITY.EXPORT";
    } else if (g_authority_import) {
        archive = read_arg_file(g_authority_import, &archive_len, caps.limit, true);
        if (!archive || !archive_len) { fprintf(stderr, "archive must be private, owned, stable and within negotiated limit\n"); goto done; }
        args[count++] = "AUTHORITY.IMPORT";
    } else args[count++] = "AUTHORITY.CHECKPOINT";
    args[count++] = g_expected_position ? g_expected_position : caps.position;
    if (g_authority_import) args[count++] = g_request_id;
    for (size_t i = 0; i < count; i++) lengths[i] = strlen(args[i]);
    if (descriptor) { args[count] = descriptor; lengths[count++] = descriptor_len; }
    if (archive) { args[count] = archive; lengths[count++] = archive_len; }
    char error[512] = {0};
    rc = qihse_qkp_admin_command(client, count, args, lengths, &reply, &reply_len, error, sizeof(error));
    if (rc) { fprintf(stderr, "authority command transport failure; retry import only with identical request identity/content\n"); goto done; }
    if (!reply) { fprintf(stderr, "missing authority reply\n"); rc = 5; goto done; }
    const char* cursor = reply;
    const char* payload;
    size_t payload_len;
    if (!authority_bulk(&cursor, reply + reply_len, &payload, &payload_len) || cursor != reply + reply_len ||
        (g_authority_export ? (!payload_len || payload_len > caps.limit) : payload_len != 96u)) {
        rc = authority_reply_error(reply, reply_len, g_authority_export != NULL);
        goto done;
    }
    if (g_authority_export) {
        size_t written = 0u;
        while (written < payload_len) {
            ssize_t n = write(fd, payload + written, payload_len - written);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { rc = 5; goto done; }
            written += (size_t)n;
        }
        if (fsync(fd) != 0) { rc = 5; goto done; }
        int result = close(fd);
        fd = -1;
        if (result != 0 || fsync(dirfd) != 0) { rc = 5; goto done; }
        created = false;
    } else {
        char position[97];
        memcpy(position, payload, 96u); position[96] = '\0';
        if (!authority_hex(position, 96u) || fwrite(position, 1u, 96u, stdout) != 96u ||
            fputc('\n', stdout) == EOF || fflush(stdout) != 0) { rc = 5; goto done; }
    }
    rc = 0;
 done:
    if (fd >= 0) close(fd);
    if (created && dirfd >= 0) { unlinkat(dirfd, name, 0); (void)fsync(dirfd); }
    if (dirfd >= 0) close(dirfd);
    free(path_storage); free(descriptor); free(archive);
    qihse_qkp_admin_free(reply);
    return rc;
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
        else if (strcmp(a, "--authority-export") == 0) g_authority_export = VALUE();
        else if (strcmp(a, "--authority-import") == 0) g_authority_import = VALUE();
        else if (strcmp(a, "--authority-checkpoint") == 0) g_authority_checkpoint = true;
        else if (strcmp(a, "--authority-capabilities") == 0) g_authority_capabilities = true;
        else if (strcmp(a, "--expected-position") == 0) g_expected_position = VALUE();
        else if (strcmp(a, "--request-id") == 0) g_request_id = VALUE();
        else if (strcmp(a, "--transfer-config") == 0) g_transfer_config = VALUE();
        else if (strcmp(a, "--user") == 0) g_user = VALUE();
        else if (strcmp(a, "--password-env") == 0) g_password_env = VALUE();
        else if (OPTION("--command", "-c")) {
            if (g_command) usage(2);
            g_command = VALUE();
        } else if (strcmp(a, "--arg") == 0) { if (!push_arg(VALUE())) return 2; }
        else if (strcmp(a, "--arg-file") == 0) {
            if (!push_arg(VALUE())) return 2;
            g_arg_files[g_argc - 1u] = g_has_arg_file = true;
        }
        else if (strcmp(a, "-x") == 0) g_stdin_value = true;
        else if (OPTION("--interactive", "--repl")) g_interactive = true;
        else if (OPTION("--stdin", "--batch")) g_batch = true;
        else if (strcmp(a, "--fail-on-error") == 0) g_strict = true;
        else if (strcmp(a, "--json") == 0) g_json = true;
        else if (strcmp(a, "--resp") == 0) g_resp = true;
        else if (strcmp(a, "--ping") == 0) { g_shortcut = true; if (!push_arg("PING")) return 2; }
        else if (strcmp(a, "--dbsize") == 0) { g_shortcut = true; if (!push_arg("DBSIZE")) return 2; }
        else if (strcmp(a, "--save") == 0) { g_shortcut = true; if (!push_arg("SAVE")) return 2; }
        else if (strcmp(a, "--bgsave") == 0) { g_shortcut = true; if (!push_arg("BGSAVE")) return 2; }
        else if (strcmp(a, "--repl-status") == 0) { g_shortcut = true; if (!push_arg("REPL.STATUS")) return 2; }
        else if (strcmp(a, "--info") == 0 || strcmp(a, "--cluster-reclaim") == 0) {
            g_shortcut = true;
            if (strcmp(a, "--info") == 0) { if (!push_arg("INFO")) return 2; }
            else if (!push_arg("CLUSTER") || !push_arg("RECLAIM")) return 2;
            if (i + 1 < argc && argv[i + 1][0] != '-') { if (!push_arg(argv[++i])) return 2; }
        } else if (strcmp(a, "--cluster-keyslot") == 0) {
            g_shortcut = true;
            if (!push_arg("CLUSTER") || !push_arg("KEYSLOT") || !push_arg(VALUE())) return 2;
        } else if (strcmp(a, "--cluster-info") == 0 || strcmp(a, "--cluster-nodes") == 0 ||
                   strcmp(a, "--cluster-slots") == 0 || strcmp(a, "--cluster-failover") == 0) {
            g_shortcut = true;
            if (!push_arg("CLUSTER") || !push_arg(a + 10)) return 2;
        } else if (strcmp(a, "--cluster-moveslots") == 0) {
            g_shortcut = true;
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
            if (i < argc && !g_command && !g_shortcut && g_argc)
                g_positional_command = argv[i++];
            for (; i < argc; i++) if (!push_arg(argv[i])) return 2;
            break;
        }
#undef VALUE
#undef OPTION
    }
    if (!g_host || !*g_host || !g_trusted_pub || !*g_trusted_pub || (g_json && g_resp) ||
        (g_interactive && g_batch) ||
        ((g_interactive || g_batch) && (g_argc || g_command || g_positional_command || g_stdin_value)) ||
        (g_has_arg_file && (g_interactive || g_batch || g_stdin_value || g_shortcut ||
                            (!g_command && !g_positional_command)))) usage(2);
    unsigned authority_modes = (g_authority_export != NULL) + (g_authority_import != NULL) +
        (unsigned)g_authority_checkpoint + (unsigned)g_authority_capabilities;
    if (authority_modes > 1u ||
        (authority_modes && (g_interactive || g_batch || g_argc || g_command ||
                             g_positional_command || g_stdin_value || !g_user || !*g_user)) ||
        ((g_authority_import || g_authority_checkpoint) && !g_expected_position) ||
        (g_expected_position && !authority_hex(g_expected_position, 96u)) ||
        (g_request_id && !authority_hex(g_request_id, 32u)) ||
        (g_authority_import && !g_request_id) ||
        ((g_authority_export || g_authority_import) && !g_transfer_config) ||
        (g_transfer_config && !(g_authority_export || g_authority_import)) ||
        (g_request_id && !g_authority_import) || (g_expected_position && !authority_modes)) usage(2);
    const char* password = NULL;
    if ((g_user && *g_user) || g_password_env) {
        if (!g_user || !*g_user) usage(2);
        password = getenv(g_password_env ? g_password_env : "QIHSE_AUTH_PASSWORD");
        if (!password || !*password) { fprintf(stderr, "AUTH password environment variable missing/empty\n"); return 2; }
    }
    const char* cargv[ADMIN_MAX_ARGS];
    size_t lengths[ADMIN_MAX_ARGS], cargc = 0u;
    bool file_args[ADMIN_MAX_ARGS] = {false};
    char* file_values[ADMIN_MAX_ARGS] = {NULL};
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
    if (g_has_arg_file && !cargc && !g_positional_command && !g_shortcut) {
        fprintf(stderr, "argument files require a command\n");
        goto done;
    }
    if (cargc + g_argc + (g_positional_command ? 1u : 0u) + (g_stdin_value ? 1u : 0u) > ADMIN_MAX_ARGS) {
        fprintf(stderr, "too many arguments (max %u)\n", ADMIN_MAX_ARGS);
        goto done;
    }
    if (g_positional_command) cargv[cargc++] = g_positional_command;
    for (size_t i = 0; i < g_argc; i++) {
        cargv[cargc] = g_args[i];
        file_args[cargc++] = g_arg_files[i];
    }
    if (!cargc && !g_batch && !g_interactive) cargv[cargc++] = "PING";
    for (size_t i = 0; i < cargc; i++) lengths[i] = file_args[i] ? 0u : strlen(cargv[i]);
    if (g_stdin_value) {
        stdin_value = read_input(false, &lengths[cargc]);
        if (!stdin_value) { fprintf(stderr, "stdin read failed or exceeds 64 MiB\n"); goto done; }
        cargv[cargc++] = stdin_value;
    }
    size_t request_size = 1u + decimal_digits(cargc) + 2u;
    size_t allocation_bound = 64u + 32u * cargc;
    for (size_t i = 0; i < cargc; i++) {
        if (file_args[i]) {
            if (allocation_bound > QIHSE_QKP_ADMIN_MAX_BYTES) goto oversized;
            bool authority_file = cargc && strncasecmp(cargv[0], "AUTHORITY.", 10u) == 0;
            file_values[i] = read_arg_file(cargv[i], &lengths[i],
                QIHSE_QKP_ADMIN_MAX_BYTES - allocation_bound, authority_file);
            if (!file_values[i]) { fprintf(stderr, "argument file invalid, changed, or unreadable\n"); goto done; }
            cargv[i] = file_values[i];
        }
        if (lengths[i] > QIHSE_QKP_ADMIN_MAX_BYTES - allocation_bound ||
            !account_arg(&request_size, lengths[i])) goto oversized;
        allocation_bound += lengths[i];
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
    if (authority_modes) rc = authority_run(client);
    else if (!g_batch && !g_interactive) rc = execute(client, cargc, cargv, lengths, false, &fatal);
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
    goto done;
oversized:
    fprintf(stderr, "request exceeds 64 MiB\n");
done:
    for (size_t i = 0; i < ADMIN_MAX_ARGS; i++) free(file_values[i]);
    free(stdin_value);
    free(command_buf);
    return rc;
}
