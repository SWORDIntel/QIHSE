/* QH-00: pre-map crash replay test using the real native admission path.
 *
 * A child writes a deterministic primary AIMEM document, fences it with the
 * native KV sync, and dies before the legacy idempotency map is inserted.
 * A fresh process must recover the original UUID through RESP, materialize
 * only one logical memory, enforce classification/SCI and survive another
 * immediate SIGKILL after a durable delete. No privileged test-only hooks. */
#define _GNU_SOURCE
#include "qihse_ai_memory.h"
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

#define IDEM_KEY "qh00-premap-crash-v2"
#define MEMORY_TEXT "QH-00 pre-map durable source evidence"

static qihse_resp_server_t* server;
static qihse_kv_store_t* kv;
static qihse_user_t* op;

static void open_server(void) {
    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));
    op = qihse_auth_get_user(0u);
    assert(op);
    kv = qihse_kv_store_create();
    assert(kv);
    qihse_resp_server_config_t cfg;
    qihse_resp_server_config_init(&cfg);
    cfg.store = kv;
    cfg.auth_required = true;
    cfg.port = 0;
    server = qihse_resp_server_create(&cfg);
    assert(server);
}

static char* call(qihse_user_t* actor, size_t argc, const char* const args[]) {
    assert(argc <= 5u);
    qihse_resp_arg_t a[5];
    for (size_t i = 0; i < argc; i++) {
        a[i].data = (const uint8_t*)args[i];
        a[i].len = strlen(args[i]);
    }
    uint8_t* buffer = NULL;
    size_t n = 0;
    assert(qihse_resp_server_execute(server, actor, argc, a, &buffer, &n));
    char* result = calloc(n + 1u, 1u);
    assert(result);
    memcpy(result, buffer, n);
    free(buffer);
    return result;
}

static void expect(qihse_user_t* actor, size_t argc,
                   const char* const args[], const char* needle) {
    char* reply = call(actor, argc, args);
    assert(strstr(reply, needle) != NULL);
    free(reply);
}

static void extract_uuid(const char* reply, char out[QIHSE_AIMEM_ID_LEN + 1u]) {
    assert(strncmp(reply, "$36\r\n", 5u) == 0);
    assert(strlen(reply) >= 5u + QIHSE_AIMEM_ID_LEN + 2u);
    memcpy(out, reply + 5u, QIHSE_AIMEM_ID_LEN);
    out[QIHSE_AIMEM_ID_LEN] = '\0';
    assert(reply[5u + QIHSE_AIMEM_ID_LEN] == '\r');
}

static void transfer(int fd, const void* input, size_t n) {
    const char* p = input;
    while (n) {
        ssize_t count = write(fd, p, n);
        assert(count > 0);
        n -= (size_t)count;
        p += count;
    }
}

static void receive(int fd, void* output, size_t n) {
    char* p = output;
    while (n) {
        ssize_t count = read(fd, p, n);
        assert(count > 0);
        n -= (size_t)count;
        p += count;
    }
}

static void killed(pid_t pid) {
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status));
    assert(WTERMSIG(status) == SIGKILL);
}

static void simulate_crash_before_idempotency_map(int fd) {
    open_server();
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store_idempotent(
            server, op, MEMORY_TEXT, QIHSE_AIMEM_SEMANTIC,
            IDEM_KEY, id) == QIHSE_AIMEM_WRITE_NEW);
    assert(qihse_kv_sync_store(kv));  /* force primary durable, map absent */
    transfer(fd, id, sizeof id);
    kill(getpid(), SIGKILL);
    _exit(71);
}

static void recover_and_check_access(const char* original, int fd) {
    open_server();
    const char* store_args[] = {
        "AIMEM", "STORE-DURABLE", "2", MEMORY_TEXT, IDEM_KEY
    };
    char* stored = call(op, 5u, store_args);
    char recovered[QIHSE_AIMEM_ID_LEN + 1u];
    extract_uuid(stored, recovered);
    free(stored);
    assert(strcmp(original, recovered) == 0);
    const char* count[] = { "AIMEM", "COUNT" };
    expect(op, 2u, count, ":1\r\n");
    stored = call(op, 5u, store_args);
    extract_uuid(stored, recovered);
    free(stored);
    assert(strcmp(original, recovered) == 0);

    const char* other_text[] = {
        "AIMEM", "STORE-DURABLE", "2", "forged event text", IDEM_KEY
    };
    const char* other_kind[] = {
        "AIMEM", "STORE-DURABLE", "1", MEMORY_TEXT, IDEM_KEY
    };
    expect(op, 5u, other_text, "-ERR CONFLICT");
    expect(op, 5u, other_kind, "-ERR CONFLICT");

    const char* get[] = { "AIMEM", "GET", original };
    expect(op, 3u, get, MEMORY_TEXT);
    qihse_user_t* low = qihse_auth_create_user(
        op, 801u, QIHSE_ROLE_GUEST, 0u, 0u, "GuestPass123!", false);
    assert(low);
    expect(low, 3u, get, "$-1\r\n");
    expect(low, 2u, count, ":0\r\n");
    const char* denied_forget[] = { "AIMEM", "FORGET-DURABLE", original };
    expect(low, 3u, denied_forget, ":0\r\n");
    expect(op, 3u, get, MEMORY_TEXT);

    /* The KV key is the high 64 bits only. A different valid UUID sharing
     * those bits is not allowed to read or delete the real document. */
    char colliding[QIHSE_AIMEM_ID_LEN + 1u];
    memcpy(colliding, original, sizeof colliding);
    colliding[35] = colliding[35] == '0' ? '1' : '0';
    const char* false_get[] = { "AIMEM", "GET", colliding };
    const char* false_delete[] = { "AIMEM", "FORGET-DURABLE", colliding };
    expect(op, 3u, false_get, "$-1\r\n");
    expect(op, 3u, false_delete, ":0\r\n");
    expect(op, 3u, get, MEMORY_TEXT);
    expect(op, 2u, count, ":1\r\n");

    transfer(fd, "R", 1u);
    kill(getpid(), SIGKILL);
    _exit(72);
}

static void delete_durably(const char* id, int fd) {
    open_server();
    const char* count[] = { "AIMEM", "COUNT" };
    expect(op, 2u, count, ":1\r\n");
    const char* forget[] = { "AIMEM", "FORGET-DURABLE", id };
    expect(op, 3u, forget, ":1\r\n");
    transfer(fd, "D", 1u);
    kill(getpid(), SIGKILL);
    _exit(73);
}

static void verify_after_delete(const char* id) {
    open_server();
    const char* get[] = { "AIMEM", "GET", id };
    const char* count[] = { "AIMEM", "COUNT" };
    const char* replay[] = {
        "AIMEM", "STORE-DURABLE", "2", MEMORY_TEXT, IDEM_KEY
    };
    expect(op, 3u, get, "$-1\r\n");
    expect(op, 2u, count, ":0\r\n");
    expect(op, 5u, replay, "-ERR CONFLICT");
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(kv);
}

int main(void) {
    char dir[] = "build/aimem_premap_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_DATA_DIR", dir, 1) == 0);

    int fds[2];
    assert(pipe(fds) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) { close(fds[0]); simulate_crash_before_idempotency_map(fds[1]); }
    close(fds[1]);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    receive(fds[0], id, sizeof id);
    close(fds[0]);
    killed(pid);

    assert(pipe(fds) == 0);
    pid = fork();
    assert(pid >= 0);
    if (!pid) { close(fds[0]); recover_and_check_access(id, fds[1]); }
    close(fds[1]);
    char marker;
    receive(fds[0], &marker, 1u);
    close(fds[0]);
    assert(marker == 'R');
    killed(pid);

    assert(pipe(fds) == 0);
    pid = fork();
    assert(pid >= 0);
    if (!pid) { close(fds[0]); delete_durably(id, fds[1]); }
    close(fds[1]);
    receive(fds[0], &marker, 1u);
    close(fds[0]);
    assert(marker == 'D');
    killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (!pid) { verify_after_delete(id); _exit(0); }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("PASS QH-00 pre-map SIGKILL replay, collision denial, durable tombstone");
    return 0;
}
