#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define QIHSE_BACKUP_CLI_NO_MAIN
#include "../tools/qihse_backup_cli.c"

#include <assert.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
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

#define RESTORE_KEY "restore:classified"
#define RESTORE_VALUE "DURABLE-CLASSIFIED-PAYLOAD"
#define OLD_KEY "restore:old"
#define OLD_VALUE "durable-old-target"
#define CLI_PASSWORD "BackupCliPass1!"

static void remove_tree(const char* path) {
    struct stat st;
    assert(lstat(path, &st) == 0);
    if (!S_ISDIR(st.st_mode)) {
        assert(unlink(path) == 0);
        return;
    }
    DIR* dir = opendir(path);
    assert(dir != NULL);
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        char child[1024];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        assert(n > 0 && (size_t)n < sizeof(child));
        remove_tree(child);
    }
    assert(closedir(dir) == 0);
    assert(rmdir(path) == 0);
}

static void check_record(qihse_kv_store_t* store, qihse_user_t* op,
                         const char* key, const char* value,
                         const qihse_kv_record_meta_t* expected) {
    char* actual = qihse_kv_get_user(store, key, op);
    assert(actual != NULL && strcmp(actual, value) == 0);
    free(actual);
    qihse_kv_record_meta_t meta;
    assert(qihse_kv_meta_user(store, key, op, &meta));
    assert(meta.classification == expected->classification);
    assert(meta.sci_compartment == expected->sci_compartment);
    assert(meta.expire_time_ms == expected->expire_time_ms);
    assert(meta.flags == expected->flags);
    /* Compare only the same image, not sequences of unrelated stores. */
    assert(meta.change_seq == expected->change_seq);
}

/* Each fixture/probe is exec'd, so auth and KV globals cannot accidentally
 * make a process-local restore look durable. These disposable directories
 * use bootstrap credentials; this does NOT prove source authorization in
 * the offline CLI (which accepts an operator bootstrap password). */
static int fixture_process(int argc, char** argv) {
    assert(argc == 5);
    const char* mode = argv[1];
    const char* dir = argv[2];
    const char* metadata_path = argv[3];
    bool source = strcmp(argv[4], "source") == 0;
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_OPERATOR_PASSWORD", CLI_PASSWORD, 1) == 0);
    assert(qihse_auth_init());
    qihse_user_t* op = qihse_auth_authenticate_id(0u, CLI_PASSWORD);
    assert(op != NULL);
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    const char* key = source ? RESTORE_KEY : OLD_KEY;
    const char* value = source ? RESTORE_VALUE : OLD_VALUE;
    if (strcmp(mode, "--seed") == 0) {
        qihse_kv_replica_record_t record = {
            .key = key, .value = value, .change_seq = source ? 41u : 7u,
            .classification = source ? 3u : 0u,
            .sci_compartment = source ? 2u : 0u,
            .expire_time_ms = ((uint64_t)time(NULL) + 86400u) * 1000u,
            .tombstone = false
        };
        assert(qihse_kv_apply_replica_record(store, &record, op));
        qihse_kv_record_meta_t meta = {0};
        assert(qihse_kv_meta_user(store, key, op, &meta));
        FILE* file = fopen(metadata_path, "wb");
        assert(file != NULL);
        assert(fwrite(&meta, sizeof(meta), 1u, file) == 1u);
        assert(fclose(file) == 0);
    } else if (strcmp(mode, "--probe") == 0) {
        qihse_kv_record_meta_t meta = {0};
        FILE* file = fopen(metadata_path, "rb");
        assert(file != NULL);
        assert(fread(&meta, sizeof(meta), 1u, file) == 1u);
        assert(fclose(file) == 0);
        check_record(store, op, key, value, &meta);
        char* absent = qihse_kv_get_user(store, source ? OLD_KEY : RESTORE_KEY, op);
        assert(absent == NULL);
        qihse_user_t* low = qihse_auth_create_user(
            op, 42u, QIHSE_ROLE_ANALYST, 0u, 0u, "LowRestorePass1!", false);
        assert(low != NULL);
        if (source) {
            assert(qihse_kv_get_user(store, RESTORE_KEY, low) == NULL);
            assert(!qihse_kv_meta_user(store, RESTORE_KEY, low, &meta));
        }
    } else if (strcmp(mode, "--incremental") == 0) {
        qihse_backup_info_t info = {0};
        assert(qihse_backup_incremental_user(store, op, metadata_path, 0u,
                                             &info) == QIHSE_BACKUP_EXPORT_OK);
        qihse_backup_info_free(&info);
    } else if (strcmp(mode, "--denied") == 0) {
        qihse_user_t* low = qihse_auth_create_user(
            op, 43u, QIHSE_ROLE_ANALYST, 0u, 0u, "DeniedRestore1!", false);
        assert(low != NULL);
        assert(qihse_restore_user(store, low, metadata_path) ==
               QIHSE_BACKUP_EXPORT_DENIED);
        qihse_backup_cli_options_t restore = {
            .command = QIHSE_BACKUP_CLI_RESTORE, .data_dir = dir,
            .path = metadata_path
        };
        char* json = NULL;
        assert(execute_capture(&restore, store, low, &json) ==
               QIHSE_BACKUP_CLI_AUTH_FAILED);
        assert(strstr(json, RESTORE_VALUE) == NULL);
        assert(strstr(json, "operator_required") != NULL);
        free(json);
    } else {
        assert(!"unknown fixture mode");
    }
    qihse_kv_store_destroy(store);
    return 0;
}

static void run_process(char* const argv[], int expected_status) {
    FILE* output = tmpfile();
    assert(output != NULL);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        assert(dup2(fileno(output), STDOUT_FILENO) >= 0);
        assert(setenv("QIHSE_OPERATOR_PASSWORD", CLI_PASSWORD, 1) == 0);
        execv(argv[0], argv);
        _exit(127);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    char* text = read_stream(output);
    assert(strstr(text, RESTORE_VALUE) == NULL);
    assert(strstr(text, CLI_PASSWORD) == NULL);
    free(text);
    assert(fclose(output) == 0);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == expected_status);
}

static void run_fixture(const char* executable, const char* mode,
                        const char* dir, const char* path, bool source) {
    char* args[] = {(char*)executable, (char*)mode, (char*)dir, (char*)path,
                    source ? (char*)"source" : (char*)"target", NULL};
    run_process(args, 0);
}

static void run_cli(const char* command, const char* dir, const char* image,
                    int expected_status) {
    char* args[] = {(char*)"./qihse-backup", (char*)command,
                    (char*)"--data-dir", (char*)dir,
                    strcmp(command, "backup") == 0 ? (char*)"--output"
                                                    : (char*)"--input",
                    (char*)image, NULL};
    run_process(args, expected_status);
}

static void test_process_restore(const char* executable) {
    char root[] = "./build/backup_cli_durable_XXXXXX";
    assert(mkdtemp(root) != NULL);
    char source[512], target[512], source_meta[512], target_meta[512];
    char image[512], bad[512], incremental[512];
    assert(snprintf(source, sizeof(source), "%s/source", root) > 0);
    assert(snprintf(target, sizeof(target), "%s/target", root) > 0);
    assert(snprintf(source_meta, sizeof(source_meta), "%s/source.meta", root) > 0);
    assert(snprintf(target_meta, sizeof(target_meta), "%s/target.meta", root) > 0);
    assert(snprintf(image, sizeof(image), "%s/full.qbak", root) > 0);
    assert(snprintf(bad, sizeof(bad), "%s/bad.qbak", root) > 0);
    assert(snprintf(incremental, sizeof(incremental), "%s/delta.qbak", root) > 0);
    assert(mkdir(source, 0700) == 0);
    assert(mkdir(target, 0700) == 0);
    run_fixture(executable, "--seed", source, source_meta, true);
    run_fixture(executable, "--seed", target, target_meta, false);
    run_cli("backup", source, image, QIHSE_BACKUP_CLI_OK);
    run_fixture(executable, "--incremental", source, incremental, true);

    FILE* file = fopen(image, "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file);
    assert(length > 64);
    rewind(file);
    unsigned char* bytes = malloc((size_t)length);
    assert(bytes != NULL);
    assert(fread(bytes, 1u, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    /* Invalid header, truncated payload, and checksum-corrupt payload. */
    for (unsigned variant = 0; variant < 3u; variant++) {
        if (variant == 0u) bytes[0] ^= 1u;
        if (variant == 2u) bytes[length - 1] ^= 1u;
        file = fopen(bad, "wb");
        assert(file != NULL);
        size_t count = (size_t)length - (variant == 1u ? 1u : 0u);
        assert(fwrite(bytes, 1u, count, file) == count);
        assert(fclose(file) == 0);
        if (variant == 0u) bytes[0] ^= 1u;
        run_cli("restore", target, bad, QIHSE_BACKUP_CLI_OPERATION_FAILED);
        run_fixture(executable, "--probe", target, target_meta, false);
    }
    free(bytes);
    run_cli("restore", target, incremental, QIHSE_BACKUP_CLI_OPERATION_FAILED);
    run_fixture(executable, "--probe", target, target_meta, false);
    run_fixture(executable, "--denied", target, image, false);
    run_fixture(executable, "--probe", target, target_meta, false);

    /* A directory blocks cleanup of the reserved image path even as root.
     * Fail during initialization without acknowledging or changing the target. */
    char obstruction[1024];
    assert(snprintf(obstruction, sizeof(obstruction),
                    "%s/replica-install.image", target) > 0);
    assert(mkdir(obstruction, 0700) == 0);
    run_cli("restore", target, image, QIHSE_BACKUP_CLI_INIT_FAILED);
    assert(rmdir(obstruction) == 0);
    run_fixture(executable, "--probe", target, target_meta, false);

    run_cli("restore", target, image, QIHSE_BACKUP_CLI_OK);
    run_fixture(executable, "--probe", target, source_meta, true);
    /* A second fresh process must recover the same metadata, not recreate
     * a relative TTL or depend on the first probe's RAM. */
    run_fixture(executable, "--probe", target, source_meta, true);
    remove_tree(root);
}

int main(int argc, char** argv) {
    if (argc > 1) return fixture_process(argc, argv);
    assert(mkdir("./build", 0700) == 0 || errno == EEXIST);
    test_process_restore(argv[0]);
    char* parse_argv[] = {
        (char*)"qihse-backup", (char*)"backup", (char*)"--data-dir",
        (char*)"store", (char*)"--output", (char*)"archive.qbak"
    };
    qihse_backup_cli_options_t parsed;
    assert(qihse_backup_cli_parse(6, parse_argv, &parsed));
    assert(parsed.command == QIHSE_BACKUP_CLI_CREATE);
    assert(strcmp(parsed.data_dir, "store") == 0);
    assert(strcmp(parsed.path, "archive.qbak") == 0);

    char root[] = "./build/backup_cli_test_XXXXXX";
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
