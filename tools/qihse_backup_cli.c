#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * qihse-backup: authenticated, offline whole-store backup operations.
 *
 * The CLI never reads WAL or SSTable files itself.  It opens the configured
 * QIHSE store and delegates backup and verification to the public
 * authorization-aware qihse_backup_*_user API.  The backup writer provides
 * the fsync + sibling-file + atomic-rename commit protocol.
 */
#include "qihse_auth.h"
#include "qihse_backup.h"
#include "qihse_kv_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    QIHSE_BACKUP_CLI_NONE = 0,
    QIHSE_BACKUP_CLI_CREATE,
    QIHSE_BACKUP_CLI_VERIFY,
    QIHSE_BACKUP_CLI_RESTORE,
    QIHSE_BACKUP_CLI_MERGE
} qihse_backup_cli_command_t;

typedef struct {
    qihse_backup_cli_command_t command;
    const char* data_dir;
    const char* path;
    const char* password_file;
    const char* base_path;
    const char* incoming_path;
    size_t max_bytes;
    size_t max_records;
} qihse_backup_cli_options_t;

enum {
    QIHSE_BACKUP_CLI_OK = 0,
    QIHSE_BACKUP_CLI_OPERATION_FAILED = 1,
    QIHSE_BACKUP_CLI_USAGE = 2,
    QIHSE_BACKUP_CLI_AUTH_FAILED = 3,
    QIHSE_BACKUP_CLI_INIT_FAILED = 4
};

#ifndef QIHSE_BACKUP_CLI_NO_MAIN
static void qihse_backup_cli_usage(FILE* stream, const char* program) {
    fprintf(stream,
            "Usage:\n"
            "  %s backup --data-dir DIR --output FILE [--password-file FILE]\n"
            "  %s verify --data-dir DIR --input FILE [--password-file FILE]\n"
            "  %s restore --data-dir DIR --input FILE [--password-file FILE]\n"
            "  %s merge --data-dir AUTH_DIR --base FILE --incoming FILE --output FILE [--password-file FILE] [--max-bytes N] [--max-records N]\n"
            "Merge defaults/ceilings: 1073741824 encoded bytes, 2000000 records; each input and union.\n"
            "\n"
            "Environment fallbacks:\n"
            "  QIHSE_DATA_DIR          store and authentication directory\n"
            "  QIHSE_BACKUP_PATH       output/input container path\n"
            "  QIHSE_OPERATOR_PASSWORD operator credential\n"
            "\n"
            "The service using DIR must be stopped while creating a backup.\n"
            "Use --password-file or QIHSE_OPERATOR_PASSWORD; passwords are\n"
            "never accepted as command-line values or emitted in output.\n",
            program, program, program, program);
}
#endif

static bool qihse_backup_cli_next_value(int argc, char** argv, int* index,
                                        const char** out) {
    if (*index + 1 >= argc || argv[*index + 1][0] == '\0') return false;
    *out = argv[++(*index)];
    return true;
}

static bool qihse_backup_cli_parse(int argc, char** argv,
                                   qihse_backup_cli_options_t* options) {
    if (!options || argc < 2) return false;
    memset(options, 0, sizeof(*options));
    options->max_bytes = (size_t)1 << 30;
    options->max_records = 2000000u;
    if (strcmp(argv[1], "backup") == 0) {
        options->command = QIHSE_BACKUP_CLI_CREATE;
    } else if (strcmp(argv[1], "verify") == 0) {
        options->command = QIHSE_BACKUP_CLI_VERIFY;
    } else if (strcmp(argv[1], "restore") == 0) {
        options->command = QIHSE_BACKUP_CLI_RESTORE;
    } else if (strcmp(argv[1], "merge") == 0) {
        options->command = QIHSE_BACKUP_CLI_MERGE;
    } else {
        return false;
    }

    for (int i = 2; i < argc; i++) {
        const char* value = NULL;
        if (strcmp(argv[i], "--data-dir") == 0) {
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value)) return false;
            options->data_dir = value;
        } else if (strcmp(argv[i], "--output") == 0 &&
                   (options->command == QIHSE_BACKUP_CLI_CREATE ||
                    options->command == QIHSE_BACKUP_CLI_MERGE)) {
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value)) return false;
            options->path = value;
        } else if (strcmp(argv[i], "--input") == 0 &&
                   (options->command == QIHSE_BACKUP_CLI_VERIFY ||
                    options->command == QIHSE_BACKUP_CLI_RESTORE)) {
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value)) return false;
            options->path = value;
        } else if (strcmp(argv[i], "--base") == 0 && options->command == QIHSE_BACKUP_CLI_MERGE) {
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value)) return false;
            options->base_path = value;
        } else if (strcmp(argv[i], "--incoming") == 0 && options->command == QIHSE_BACKUP_CLI_MERGE) {
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value)) return false;
            options->incoming_path = value;
        } else if ((strcmp(argv[i], "--max-bytes") == 0 ||
                    strcmp(argv[i], "--max-records") == 0) &&
                   options->command == QIHSE_BACKUP_CLI_MERGE) {
            bool bytes = strcmp(argv[i], "--max-bytes") == 0;
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value) ||
                !*value) return false;
            size_t n = 0;
            for (const char* p = value; *p; p++) {
                if (*p < '0' || *p > '9' || n > (SIZE_MAX - (size_t)(*p - '0'))/10)
                    return false;
                n = n*10 + (size_t)(*p - '0');
            }
            if (!n || (bytes && n > ((size_t)1 << 30)) ||
                (!bytes && n > 2000000u)) return false;
            if (bytes) options->max_bytes = n;
            else options->max_records = n;
        } else if (strcmp(argv[i], "--password-file") == 0) {
            if (!qihse_backup_cli_next_value(argc, argv, &i, &value)) return false;
            options->password_file = value;
        } else {
            return false;
        }
    }

    if (!options->data_dir) options->data_dir = getenv("QIHSE_DATA_DIR");
    if (!options->path) options->path = getenv("QIHSE_BACKUP_PATH");
    if (options->command == QIHSE_BACKUP_CLI_MERGE &&
        (!options->base_path || !options->incoming_path)) return false;
    return options->data_dir && options->data_dir[0] != '\0' &&
           options->path && options->path[0] != '\0';
}

static char* qihse_backup_cli_password_from_file(const char* path) {
    struct stat st;
    FILE* f = NULL;
    char* password = NULL;
    if (!path) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & (S_IRWXG | S_IRWXO)) != 0 || st.st_size <= 0 ||
        st.st_size > 4096) {
        if (fd >= 0) close(fd);
        return NULL;
    }
    f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    password = (char*)calloc((size_t)st.st_size + 1u, 1u);
    if (!password || fread(password, 1u, (size_t)st.st_size, f) !=
                         (size_t)st.st_size) {
        free(password);
        password = NULL;
        goto done;
    }
    size_t len = (size_t)st.st_size;
    while (len > 0u && (password[len - 1u] == '\n' ||
                        password[len - 1u] == '\r')) {
        password[--len] = '\0';
    }
    if (len < 12u) {
        memset(password, 0, (size_t)st.st_size + 1u);
        free(password);
        password = NULL;
    }
done:
    fclose(f);
    return password;
}

static char* qihse_backup_cli_load_password(const char* password_file) {
    if (password_file) return qihse_backup_cli_password_from_file(password_file);
    const char* value = getenv("QIHSE_OPERATOR_PASSWORD");
    if (!value || strlen(value) < 12u) return NULL;
    return strdup(value);
}

static void qihse_backup_cli_clean_password(char* password) {
    if (!password) return;
    size_t len = strlen(password);
    volatile unsigned char* p = (volatile unsigned char*)password;
    while (len-- > 0u) *p++ = 0u;
    free(password);
}

static void qihse_backup_cli_json_string(FILE* stream, const char* value) {
    fputc('"', stream);
    for (const unsigned char* p = (const unsigned char*)(value ? value : "");
         *p; p++) {
        switch (*p) {
            case '"': fputs("\\\"", stream); break;
            case '\\': fputs("\\\\", stream); break;
            case '\b': fputs("\\b", stream); break;
            case '\f': fputs("\\f", stream); break;
            case '\n': fputs("\\n", stream); break;
            case '\r': fputs("\\r", stream); break;
            case '\t': fputs("\\t", stream); break;
            default:
                if (*p < 0x20u) fprintf(stream, "\\u%04x", (unsigned)*p);
                else fputc((int)*p, stream);
        }
    }
    fputc('"', stream);
}

static const char* qihse_backup_cli_result_name(int result) {
    switch (result) {
        case QIHSE_BACKUP_EXPORT_OK: return "ok";
        case QIHSE_BACKUP_EXPORT_ERR: return "error";
        case QIHSE_BACKUP_EXPORT_DENIED: return "denied";
        case QIHSE_BACKUP_EXPORT_UNSUPPORTED: return "unsupported";
        case QIHSE_BACKUP_EXPORT_CONFLICT: return "conflict";
        default: return "unknown";
    }
}

static void qihse_backup_cli_emit_failure(FILE* output, const char* operation,
                                          const char* reason, int api_result) {
    fputs("{\"ok\":false,\"operation\":", output);
    qihse_backup_cli_json_string(output, operation);
    fputs(",\"result\":", output);
    qihse_backup_cli_json_string(output, reason);
    fprintf(output, ",\"api_code\":%d}\n", api_result);
}

/* Separate from authentication so tests and future front ends cannot bypass
 * the CLI's Operator-only policy by supplying another live principal. */
static bool qihse_backup_cli_operator_allowed(const qihse_user_t* principal) {
    return principal && qihse_auth_user_is_active(principal) &&
           qihse_user_get_role(principal) == QIHSE_ROLE_OPERATOR;
}

static int qihse_backup_cli_execute(const qihse_backup_cli_options_t* options,
                                    qihse_kv_store_t* store,
                                    qihse_user_t* principal, FILE* output) {
    const char* operation = options && options->command == QIHSE_BACKUP_CLI_VERIFY
                                ? "verify"
                                : options && options->command == QIHSE_BACKUP_CLI_RESTORE
                                ? "restore" : options && options->command == QIHSE_BACKUP_CLI_MERGE
                                ? "merge" : "backup";
    if (!options || !output || !qihse_backup_cli_operator_allowed(principal)) {
        if (output) qihse_backup_cli_emit_failure(output, operation,
                                                  "operator_required",
                                                  QIHSE_BACKUP_EXPORT_DENIED);
        errno = EACCES;
        return QIHSE_BACKUP_CLI_AUTH_FAILED;
    }

    if (options->command == QIHSE_BACKUP_CLI_MERGE) {
        qihse_backup_merge_stats_t stats;
        int rc = qihse_backup_merge_user(principal, options->base_path,
            options->incoming_path, options->path, options->max_bytes, options->max_records, &stats);
        fprintf(output, "{\"ok\":%s,\"operation\":\"merge\",\"api_code\":%d,"
            "\"added\":%zu,\"identical\":%zu,\"conflicts\":%zu}\n",
            rc == 0 ? "true" : "false", rc, stats.added, stats.identical, stats.conflicts);
        return rc == 0 ? QIHSE_BACKUP_CLI_OK : QIHSE_BACKUP_CLI_OPERATION_FAILED;
    }

    if (options->command == QIHSE_BACKUP_CLI_CREATE) {
        qihse_backup_info_t info;
        memset(&info, 0, sizeof(info));
        int rc = store ? qihse_backup_full_user(store, principal, options->path,
                                                &info)
                       : QIHSE_BACKUP_EXPORT_ERR;
        if (rc != QIHSE_BACKUP_EXPORT_OK) {
            qihse_backup_cli_emit_failure(output, operation,
                                          qihse_backup_cli_result_name(rc), rc);
            qihse_backup_info_free(&info);
            return QIHSE_BACKUP_CLI_OPERATION_FAILED;
        }
        fputs("{\"ok\":true,\"operation\":\"backup\",\"path\":", output);
        qihse_backup_cli_json_string(output, info.path);
        fprintf(output,
                ",\"type\":\"full\",\"size_bytes\":%zu,"
                "\"checksum\":\"%s\",\"writer_user_id\":%u,"
                "\"classification\":%u,\"sci\":%u}\n",
                info.size_bytes, info.checksum, info.writer_user_id,
                (unsigned)info.classification, (unsigned)info.sci_compartment);
        qihse_backup_info_free(&info);
        return QIHSE_BACKUP_CLI_OK;
    }

    if (options->command == QIHSE_BACKUP_CLI_VERIFY) {
        int rc = qihse_backup_verify_user(principal, options->path);
        if (rc != QIHSE_BACKUP_EXPORT_OK) {
            qihse_backup_cli_emit_failure(output, operation,
                                          qihse_backup_cli_result_name(rc), rc);
            return QIHSE_BACKUP_CLI_OPERATION_FAILED;
        }
        fputs("{\"ok\":true,\"operation\":\"verify\",\"path\":", output);
        qihse_backup_cli_json_string(output, options->path);
        fputs(",\"result\":\"valid\"}\n", output);
        return QIHSE_BACKUP_CLI_OK;
    }

    if (options->command == QIHSE_BACKUP_CLI_RESTORE) {
        int rc = store ? qihse_restore_user(store, principal, options->path)
                       : QIHSE_BACKUP_EXPORT_ERR;
        if (rc != QIHSE_BACKUP_EXPORT_OK) {
            qihse_backup_cli_emit_failure(output, operation,
                                          qihse_backup_cli_result_name(rc), rc);
            return QIHSE_BACKUP_CLI_OPERATION_FAILED;
        }
        fputs("{\"ok\":true,\"operation\":\"restore\",\"path\":", output);
        qihse_backup_cli_json_string(output, options->path);
        fputs(",\"result\":\"restored\"}\n", output);
        return QIHSE_BACKUP_CLI_OK;
    }

    qihse_backup_cli_emit_failure(output, operation, "invalid_command",
                                  QIHSE_BACKUP_EXPORT_ERR);
    return QIHSE_BACKUP_CLI_USAGE;
}

#ifndef QIHSE_BACKUP_CLI_NO_MAIN
int main(int argc, char** argv) {
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 ||
                      strcmp(argv[1], "-h") == 0)) {
        qihse_backup_cli_usage(stdout, argv[0]);
        return QIHSE_BACKUP_CLI_OK;
    }
    qihse_backup_cli_options_t options;
    if (!qihse_backup_cli_parse(argc, argv, &options)) {
        qihse_backup_cli_usage(stderr, argv[0]);
        return QIHSE_BACKUP_CLI_USAGE;
    }

    char* password = qihse_backup_cli_load_password(options.password_file);
    if (!password) {
        qihse_backup_cli_emit_failure(stdout,
                                      options.command == QIHSE_BACKUP_CLI_VERIFY
                                          ? "verify" : "backup",
                                      "credentials_unavailable",
                                      QIHSE_BACKUP_EXPORT_DENIED);
        return QIHSE_BACKUP_CLI_AUTH_FAILED;
    }

    if (setenv("QIHSE_DATA_DIR", options.data_dir, 1) != 0 ||
        setenv("QIHSE_OPERATOR_PASSWORD", password, 1) != 0 ||
        !qihse_auth_init()) {
        unsetenv("QIHSE_OPERATOR_PASSWORD");
        qihse_backup_cli_clean_password(password);
        qihse_backup_cli_emit_failure(stdout,
                                      options.command == QIHSE_BACKUP_CLI_VERIFY
                                          ? "verify" : "backup",
                                      "initialization_failed",
                                      QIHSE_BACKUP_EXPORT_ERR);
        return QIHSE_BACKUP_CLI_INIT_FAILED;
    }

    unsetenv("QIHSE_OPERATOR_PASSWORD");
    qihse_user_t* principal = qihse_auth_authenticate_id(0u, password);
    qihse_backup_cli_clean_password(password);
    if (!qihse_backup_cli_operator_allowed(principal)) {
        qihse_backup_cli_emit_failure(stdout,
                                      options.command == QIHSE_BACKUP_CLI_VERIFY
                                          ? "verify" : "backup",
                                      "authentication_failed",
                                      QIHSE_BACKUP_EXPORT_DENIED);
        return QIHSE_BACKUP_CLI_AUTH_FAILED;
    }

    qihse_kv_store_t* store = NULL;
    if (options.command == QIHSE_BACKUP_CLI_CREATE ||
        options.command == QIHSE_BACKUP_CLI_RESTORE) {
        store = qihse_kv_store_create_user(principal);
        if (!store) {
            qihse_backup_cli_emit_failure(stdout, "backup",
                                          "store_open_failed",
                                          QIHSE_BACKUP_EXPORT_ERR);
            return QIHSE_BACKUP_CLI_INIT_FAILED;
        }
    }
    int rc = qihse_backup_cli_execute(&options, store, principal, stdout);
    qihse_kv_store_destroy(store);
    return rc;
}
#endif
