/* QH-00 compatibility regression for the pre-stable-UUID AIMEM idempotency
 * map format. Legacy clients wrote a random AIMEM UUID followed by the map;
 * a new STORE-DURABLE retry must continue to honor that exact mapping. */
#include "qihse_ai_memory.h"
#include "qihse_audit.h"
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define IDEM_KEY "qh00-legacy-random-map"
#define TEXT "QH00 legacy random UUID mapping fixture"
#define BAD_KEY "qh00-malformed-legacy-map"
#define STALE_KEY "qh00-stale-legacy-map"

static qihse_resp_server_t* server;
static qihse_kv_store_t* store;
static qihse_user_t* operator_user;

static void open_instance(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    operator_user = qihse_auth_get_user(0u);
    assert(operator_user);
    store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = store;
    cfg.auth_required = true;
    cfg.port = 0;
    server = qihse_resp_server_create(&cfg);
    assert(server);
}

static char* command(qihse_user_t* user, size_t argc,
                     const char* const argv[]) {
    assert(argc <= 5u);
    qihse_resp_arg_t args[5];
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL;
    size_t length = 0u;
    assert(qihse_resp_server_execute(server, user, argc, args, &reply, &length));
    char* result = calloc(length + 1u, 1u);
    assert(result);
    memcpy(result, reply, length);
    free(reply);
    return result;
}

static void expect(qihse_user_t* user, size_t argc,
                   const char* const argv[], const char* expected) {
    char* reply = command(user, argc, argv);
    if (!strstr(reply, expected))
        fprintf(stderr, "unexpected AIMEM reply: expected [%s], got [%s]\n",
                expected, reply);
    assert(strstr(reply, expected) != NULL);
    free(reply);
}

static void extract_uuid(const char* reply, char out[QIHSE_AIMEM_ID_LEN + 1u]) {
    assert(strncmp(reply, "$36\r\n", 5u) == 0);
    assert(strlen(reply) >= 5u + QIHSE_AIMEM_ID_LEN + 2u);
    memcpy(out, reply + 5u, QIHSE_AIMEM_ID_LEN);
    out[QIHSE_AIMEM_ID_LEN] = '\0';
    assert(reply[5u + QIHSE_AIMEM_ID_LEN] == '\r');
}

static void write_exact(int fd, const void* data, size_t count) {
    size_t written = 0u;
    while (written < count) {
        ssize_t n = write(fd, (const char*)data + written, count - written);
        assert(n > 0);
        written += (size_t)n;
    }
}

static void read_exact(int fd, void* data, size_t count) {
    size_t received = 0u;
    while (received < count) {
        ssize_t n = read(fd, (char*)data + received, count - received);
        assert(n > 0);
        received += (size_t)n;
    }
}

static void map_key_for(char* out, size_t cap, const char* key) {
    int n = snprintf(out, cap, "aimem-idem:%u:%s",
                     (unsigned)qihse_user_get_id(operator_user), key);
    assert(n > 0 && (size_t)n < cap);
}

static void seed_legacy_map_then_kill(int pipe_fd) {
    open_instance();
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, operator_user, TEXT,
                                  QIHSE_AIMEM_SEMANTIC, id));
    char key[192];
    map_key_for(key, sizeof key, IDEM_KEY);
    assert(qihse_kv_set_user(store, key, id, 0u, 0u, operator_user));
    assert(qihse_kv_sync_store(store));
    qihse_audit_flush();
    write_exact(pipe_fd, id, sizeof id);
    kill(getpid(), SIGKILL);
    _exit(90);
}

static void verify_legacy_retry_and_delete_then_kill(
        const char* original_id, int pipe_fd) {
    open_instance();
    char legacy_key[192];
    map_key_for(legacy_key, sizeof legacy_key, IDEM_KEY);
    char* before = qihse_kv_get_user(store, legacy_key, operator_user);
    assert(before && strcmp(before, original_id) == 0);

    const char* retry[] = { "AIMEM", "STORE-DURABLE", "2", TEXT, IDEM_KEY };
    char* reply = command(operator_user, 5u, retry);
    char retried_id[QIHSE_AIMEM_ID_LEN + 1u];
    extract_uuid(reply, retried_id);
    free(reply);
    assert(strcmp(original_id, retried_id) == 0);
    char* after = qihse_kv_get_user(store, legacy_key, operator_user);
    assert(after && strcmp(after, before) == 0);
    free(before);
    free(after);

    const char* count[] = { "AIMEM", "COUNT" };
    expect(operator_user, 2u, count, ":1\r\n");
    const char* content_conflict[] = {
        "AIMEM", "STORE-DURABLE", "2", "changed legacy content", IDEM_KEY
    };
    const char* kind_conflict[] = {
        "AIMEM", "STORE-DURABLE", "1", TEXT, IDEM_KEY
    };
    expect(operator_user, 5u, content_conflict, "-ERR CONFLICT");
    expect(operator_user, 5u, kind_conflict, "-ERR CONFLICT");

    /* An existing but malformed map value and an absent target are both
     * terminal conflicts. Neither is allowed to fall through to admission. */
    char bad_map[192];
    map_key_for(bad_map, sizeof bad_map, BAD_KEY);
    assert(qihse_kv_set_user(store, bad_map, "not-a-uuid", 0u, 0u,
                             operator_user));
    const char* bad_retry[] = {
        "AIMEM", "STORE-DURABLE", "2", "bad map payload", BAD_KEY
    };
    expect(operator_user, 5u, bad_retry, "-ERR CONFLICT");

    char stale_map[192];
    map_key_for(stale_map, sizeof stale_map, STALE_KEY);
    const char* nonexistent = "00000000-0000-4000-8000-000000000001";
    assert(qihse_kv_set_user(store, stale_map, nonexistent, 0u, 0u,
                             operator_user));
    const char* stale_retry[] = {
        "AIMEM", "STORE-DURABLE", "2", "stale map payload", STALE_KEY
    };
    expect(operator_user, 5u, stale_retry, "-ERR CONFLICT");
    expect(operator_user, 2u, count, ":1\r\n");

    const char* forget[] = { "AIMEM", "FORGET-DURABLE", original_id };
    expect(operator_user, 3u, forget, ":1\r\n");
    qihse_audit_flush();
    write_exact(pipe_fd, "D", 1u);
    kill(getpid(), SIGKILL);
    _exit(91);
}

static void verify_deleted_legacy_retry(const char* original_id) {
    open_instance();
    const char* count[] = { "AIMEM", "COUNT" };
    const char* get[] = { "AIMEM", "GET", original_id };
    const char* retry[] = { "AIMEM", "STORE-DURABLE", "2", TEXT, IDEM_KEY };
    expect(operator_user, 3u, get, "$-1\r\n");
    expect(operator_user, 2u, count, ":0\r\n");
    expect(operator_user, 5u, retry, "-ERR CONFLICT");
    char legacy_key[192];
    map_key_for(legacy_key, sizeof legacy_key, IDEM_KEY);
    char* mapping = qihse_kv_get_user(store, legacy_key, operator_user);
    assert(mapping && strcmp(mapping, original_id) == 0);
    free(mapping);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static void expect_killed(pid_t pid) {
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(void) {
    char data_dir[] = "build/aimem_idem_migration_XXXXXX";
    assert(mkdtemp(data_dir));
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);

    int fds[2];
    assert(pipe(fds) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        seed_legacy_map_then_kill(fds[1]);
    }
    close(fds[1]);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    read_exact(fds[0], id, sizeof id);
    close(fds[0]);
    expect_killed(pid);

    assert(pipe(fds) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fds[0]);
        verify_legacy_retry_and_delete_then_kill(id, fds[1]);
    }
    close(fds[1]);
    char marker;
    read_exact(fds[0], &marker, 1u);
    close(fds[0]);
    assert(marker == 'D');
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_deleted_legacy_retry(id);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("PASS QH-00 legacy random UUID idempotency map migration and tombstone");
    return 0;
}
