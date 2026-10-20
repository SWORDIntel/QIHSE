#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define QIHSE_BACKUP_CLI_NO_MAIN
#include "../tools/qihse_backup_cli.c"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char cleanup_root[512];

/* Registered before auth initialization so the audit subsystem's later
 * atexit handler runs first and releases its continuity lock. */
static void cleanup_test_directory(void) {
    const char* names[] = {
        "password", "aimem-full.qbak", "wal.log", "qihse_audit.log",
        "qihse_audit.writer.lock", "qihse_integrity.chain"
    };
    char path[1024];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/%s", cleanup_root, names[i]);
        if (n > 0 && (size_t)n < sizeof(path)) unlink(path);
    }
    if (cleanup_root[0] != '\0') rmdir(cleanup_root);
}

static char* read_stream(FILE* stream) {
    assert(fflush(stream) == 0);
    long length = ftell(stream);
    assert(length >= 0);
    assert(fseek(stream, 0, SEEK_SET) == 0);
    char* text = (char*)calloc((size_t)length + 1u, 1u);
    assert(text != NULL);
    assert(fread(text, 1u, (size_t)length, stream) == (size_t)length);
    return text;
}

static int execute_capture(const qihse_backup_cli_options_t* options,
                           qihse_kv_store_t* store, qihse_user_t* user,
                           char** out_text) {
    FILE* output = tmpfile();
    assert(output != NULL);
    int rc = qihse_backup_cli_execute(options, store, user, output);
    *out_text = read_stream(output);
    fclose(output);
    return rc;
}

int main(void) {
    char* parse_argv[] = {
        (char*)"qihse-backup", (char*)"backup", (char*)"--data-dir",
        (char*)"store", (char*)"--output", (char*)"archive.qbak"
    };
    qihse_backup_cli_options_t parsed;
    assert(qihse_backup_cli_parse(6, parse_argv, &parsed));
    assert(parsed.command == QIHSE_BACKUP_CLI_CREATE);
    assert(strcmp(parsed.data_dir, "store") == 0);
    assert(strcmp(parsed.path, "archive.qbak") == 0);

    char root[] = "backup_cli_test_XXXXXX";
    assert(mkdtemp(root) != NULL);
    assert(chmod(root, 0700) == 0);
    assert(snprintf(cleanup_root, sizeof(cleanup_root), "%s", root) > 0);
    assert(atexit(cleanup_test_directory) == 0);
    assert(setenv("QIHSE_DATA_DIR", root, 1) == 0);
    assert(setenv("QIHSE_OPERATOR_PASSWORD", "BackupCliPass1!", 1) == 0);
    assert(qihse_auth_init());

    qihse_user_t* op = qihse_auth_authenticate_id(0u, "BackupCliPass1!");
    assert(op != NULL);
    qihse_user_t* analyst = qihse_auth_create_user(
        op, 41u, QIHSE_ROLE_ANALYST, 1u, 0u, "AnalystCliPass1!", false);
    assert(analyst != NULL);
    assert(!qihse_backup_cli_operator_allowed(NULL));
    assert(!qihse_backup_cli_operator_allowed(analyst));
    assert(qihse_backup_cli_operator_allowed(op));

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    assert(qihse_kv_set_user(store, "aimem:scope:project-a:item-1", "QHK2|record",
                             3u, 2u, op));

    char backup_path[512];
    assert(snprintf(backup_path, sizeof(backup_path), "%s/aimem-full.qbak", root) > 0);
    qihse_backup_cli_options_t backup = {
        .command = QIHSE_BACKUP_CLI_CREATE,
        .data_dir = root,
        .path = backup_path,
        .password_file = NULL
    };
    char* json = NULL;
    assert(execute_capture(&backup, store, NULL, &json) ==
           QIHSE_BACKUP_CLI_AUTH_FAILED);
    assert(strstr(json, "operator_required") != NULL);
    assert(access(backup_path, F_OK) != 0);
    free(json);

    assert(execute_capture(&backup, store, analyst, &json) ==
           QIHSE_BACKUP_CLI_AUTH_FAILED);
    assert(strstr(json, "operator_required") != NULL);
    assert(access(backup_path, F_OK) != 0);
    free(json);

    assert(execute_capture(&backup, store, op, &json) == QIHSE_BACKUP_CLI_OK);
    assert(strstr(json, "\"ok\":true") != NULL);
    assert(strstr(json, "\"type\":\"full\"") != NULL);
    assert(strstr(json, "BackupCliPass1!") == NULL);
    free(json);
    struct stat st;
    assert(stat(backup_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);

    qihse_backup_cli_options_t verify = {
        .command = QIHSE_BACKUP_CLI_VERIFY,
        .data_dir = root,
        .path = backup_path,
        .password_file = NULL
    };
    assert(execute_capture(&verify, NULL, analyst, &json) ==
           QIHSE_BACKUP_CLI_AUTH_FAILED);
    assert(strstr(json, "operator_required") != NULL);
    free(json);
    assert(execute_capture(&verify, NULL, op, &json) == QIHSE_BACKUP_CLI_OK);
    assert(strstr(json, "\"result\":\"valid\"") != NULL);
    free(json);

    int fd = open(backup_path, O_WRONLY | O_APPEND);
    assert(fd >= 0);
    assert(write(fd, "x", 1u) == 1);
    close(fd);
    assert(execute_capture(&verify, NULL, op, &json) ==
           QIHSE_BACKUP_CLI_OPERATION_FAILED);
    assert(strstr(json, "\"ok\":false") != NULL);
    assert(strstr(json, "\"result\":\"error\"") != NULL);
    free(json);

    char password_path[512];
    assert(snprintf(password_path, sizeof(password_path), "%s/password", root) > 0);
    fd = open(password_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(fd >= 0);
    assert(write(fd, "BackupCliPass1!\n", 16u) == 16);
    close(fd);
    char* loaded = qihse_backup_cli_load_password(password_path);
    assert(loaded != NULL && strcmp(loaded, "BackupCliPass1!") == 0);
    qihse_backup_cli_clean_password(loaded);
    assert(chmod(password_path, 0644) == 0);
    assert(qihse_backup_cli_load_password(password_path) == NULL);

    qihse_kv_store_destroy(store);
    puts("PASS authenticated operator backup CLI");
    return 0;
}
