/* QH-00: synchronous durable AIMEM ACK / SIGKILL recovery regression.
 * The parent never opens the store. Each child has an independent process
 * lifecycle; SIGKILL occurs immediately AFTER the protocol returns an ACK,
 * without destroying the server or flushing during normal exit. */
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

#define TEST_IDEM "qh00-crash-replay-01"
#define TEST_TEXT "QH00-DURABLE-SECRET-FIXTURE"
#define FAULT_IDEM "qh00-sync-boundary-fault-01"
#define FAULT_TEXT "QH00-SYNC-BOUNDARY-FIXTURE"
#define EVENT_ID "qh02-crash-event-01"
#define EVENT_SUMMARY "QH02-DURABLE-EVENT-FIXTURE"
#define HANDOFF_OWNER_ID 9201u
#define HANDOFF_RECIPIENT_ID 9202u
#define HANDOFF_COMPETITOR_ID 9203u
#define MIGRATION_TEXT "QH01-LEGACY-MIGRATION-FIXTURE"

static qihse_resp_server_t* server;
static qihse_kv_store_t* store;
static qihse_user_t* operator_user;
static char data_root[64];

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
    assert(argc <= 12u);
    qihse_resp_arg_t args[12];
    for (size_t i = 0; i < argc; i++) {
        args[i].data = (const uint8_t*)argv[i];
        args[i].len = strlen(argv[i]);
    }
    uint8_t* reply = NULL;
    size_t length = 0;
    assert(qihse_resp_server_execute(server, user, argc, args, &reply, &length));
    char* text = calloc(length + 1u, 1u);
    assert(text);
    memcpy(text, reply, length);
    free(reply);
    return text;
}

static void assert_response(qihse_user_t* user, size_t argc,
                            const char* const argv[], const char* expected) {
    char* reply = command(user, argc, argv);
    if (!strstr(reply, expected))
        fprintf(stderr, "unexpected RESP reply for %s: expected [%s], got [%s]\n",
                argv[1], expected, reply);
    assert(strstr(reply, expected) != NULL);
    free(reply);
}

static void id_from_store(const char* reply,
                          char out[QIHSE_AIMEM_ID_LEN + 1u]) {
    if (strncmp(reply, "$36\r\n", 5u) != 0)
        fprintf(stderr, "expected UUID bulk reply, got [%s]\n", reply);
    assert(strncmp(reply, "$36\r\n", 5u) == 0);
    const char* id = reply + 5u;
    assert(strlen(id) >= QIHSE_AIMEM_ID_LEN + 2u);
    assert(id[QIHSE_AIMEM_ID_LEN] == '\r');
    assert(id[QIHSE_AIMEM_ID_LEN + 1u] == '\n');
    memcpy(out, id, QIHSE_AIMEM_ID_LEN);
    out[QIHSE_AIMEM_ID_LEN] = '\0';
}

static void write_exact(int fd, const void* data, size_t count) {
    size_t written = 0;
    while (written < count) {
        ssize_t n = write(fd, (const char*)data + written, count - written);
        assert(n > 0);
        written += (size_t)n;
    }
}
static void read_exact(int fd, void* data, size_t count) {
    size_t received = 0;
    while (received < count) {
        ssize_t n = read(fd, (char*)data + received, count - received);
        assert(n > 0);
        received += (size_t)n;
    }
}

static void store_then_kill(int pipe_fd) {
    open_instance();
    const char* store_args[] = { "AIMEM", "STORE-DURABLE", "2", TEST_TEXT, TEST_IDEM };
    char* reply = command(operator_user, 5u, store_args);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(reply, id);
    free(reply);
    /* The crash fence concerns the KV acknowledgement. Drain unrelated
     * asynchronous audit signing first, so the intentional SIGKILL cannot
     * strand a signed audit log record before its independent chain tip and
     * stop the recovery child before it reaches the AIMEM assertion. */
    qihse_audit_flush();
    write_exact(pipe_fd, id, sizeof id);
    kill(getpid(), SIGKILL); /* no normal destructor/flush */
    _exit(100);
}

static void verify_then_forget_then_kill(const char* id, int pipe_fd) {
    open_instance();
    const char* get_args[] = { "AIMEM", "GET", id };
    assert_response(operator_user, 3u, get_args, TEST_TEXT);

    /* Direct-ID and delete denial controls on the new durable adapter. */
    qihse_user_t* guest = qihse_auth_create_user(
        operator_user, 9042u, QIHSE_ROLE_GUEST, 0u, 0u,
        "GuestPass123!", false);
    assert(guest);
    assert_response(guest, 3u, get_args, "$-1\r\n");
    const char* count_args[] = { "AIMEM", "COUNT" };
    assert_response(guest, 2u, count_args, ":0\r\n");
    const char* remove_args[] = { "AIMEM", "FORGET-DURABLE", id };
    assert_response(guest, 3u, remove_args, ":0\r\n");
    assert_response(operator_user, 3u, get_args, TEST_TEXT);

    const char* replay_args[] = { "AIMEM", "STORE-DURABLE", "2", TEST_TEXT, TEST_IDEM };
    char* retry = command(operator_user, 5u, replay_args);
    char replay_id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(retry, replay_id);
    free(retry);
    assert(strcmp(id, replay_id) == 0);

    const char* conflict_args[] = { "AIMEM", "STORE-DURABLE", "2", "changed payload", TEST_IDEM };
    assert_response(operator_user, 5u, conflict_args, "-ERR CONFLICT");
    const char* conflict_kind[] = { "AIMEM", "STORE-DURABLE", "1", TEST_TEXT, TEST_IDEM };
    assert_response(operator_user, 5u, conflict_kind, "-ERR CONFLICT");
    assert_response(operator_user, 3u, remove_args, ":1\r\n");
    qihse_audit_flush();
    write_exact(pipe_fd, "D", 1u);
    kill(getpid(), SIGKILL);
    _exit(100);
}

static void verify_tombstone(const char* id) {
    open_instance();
    const char* get_args[] = { "AIMEM", "GET", id };
    assert_response(operator_user, 3u, get_args, "$-1\r\n");
    const char* stale_replay[] = { "AIMEM", "STORE-DURABLE", "2", TEST_TEXT, TEST_IDEM };
    /* A deleted ID's idempotency key must not resurrect the original. */
    assert_response(operator_user, 5u, stale_replay, "-ERR CONFLICT");
    const char* count_args[] = { "AIMEM", "COUNT" };
    assert_response(operator_user, 2u, count_args, ":0\r\n");
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static void event_ack_then_kill(int pipe_fd) {
    open_instance();
    const char* append[] = { "AIMEM", "EVENT", "APPEND", "qh02-project",
        "qh02-tree", "qh02-stream", "qh02-session", "crash-test", EVENT_ID,
        "checkpoint", "1792500000000", EVENT_SUMMARY };
    char* reply = command(operator_user, 12u, append);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(reply, id);
    free(reply);
    /* The RESP result has been produced and the KV fence crossed, but the
     * simulated client receives only this harness marker, not the reply. */
    qihse_audit_flush();
    write_exact(pipe_fd, "E", 1u);
    kill(getpid(), SIGKILL);
    _exit(100);
}

static void verify_event_replay(void) {
    open_instance();
    const char* append[] = { "AIMEM", "EVENT", "APPEND", "qh02-project",
        "qh02-tree", "qh02-stream", "qh02-session", "crash-test", EVENT_ID,
        "checkpoint", "1792500000000", EVENT_SUMMARY };
    char* first = command(operator_user, 12u, append);
    char first_id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(first, first_id);
    free(first);
    char* retry = command(operator_user, 12u, append);
    char retry_id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(retry, retry_id);
    free(retry);
    assert(strcmp(first_id, retry_id) == 0);

    const char* read[] = { "AIMEM", "EVENT", "READ", first_id,
        "qh02-project", "qh02-tree", "qh02-stream", "qh02-session" };
    assert_response(operator_user, 8u, read, EVENT_SUMMARY);
    const char* conflict[] = { "AIMEM", "EVENT", "APPEND", "qh02-project",
        "qh02-tree", "qh02-stream", "qh02-session", "crash-test", EVENT_ID,
        "checkpoint", "1792500000000", "changed event payload" };
    assert_response(operator_user, 12u, conflict, "-ERR CONFLICT");
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static void create_handoff_users(qihse_user_t** owner, qihse_user_t** recipient,
                                 qihse_user_t** competitor) {
    *owner = qihse_auth_create_user(operator_user, HANDOFF_OWNER_ID,
        QIHSE_ROLE_GUEST, 0u, 0u, "HandoffOwner123!", false);
    *recipient = qihse_auth_create_user(operator_user, HANDOFF_RECIPIENT_ID,
        QIHSE_ROLE_GUEST, 0u, 0u,
        "HandoffRecipient123!", false);
    if (competitor) *competitor = qihse_auth_create_user(operator_user,
        HANDOFF_COMPETITOR_ID, QIHSE_ROLE_GUEST, 0u, 0u,
        "HandoffCompetitor123!", false);
    assert(*owner && *recipient && (!competitor || *competitor));
}

static void handoff_accept_then_kill(int pipe_fd) {
    open_instance();
    qihse_user_t *owner, *recipient;
    create_handoff_users(&owner, &recipient, NULL);
    const char* seed[] = { "AIMEM", "STORE-SCOPED", "1", "handoff owner seed",
        "qh03-project", "qh03-tree", "qh03-stream", "qh03-session" };
    char* reply = command(owner, 8u, seed);
    char seed_id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(reply, seed_id);
    free(reply);
    const char* grant[] = { "AIMEM", "PROJECT", "GRANT", "qh03-project", "9202" };
    assert_response(owner, 5u, grant, "+OK\r\n");
    const char* offer[] = { "AIMEM", "HANDOFF", "OFFER", "9202", "60000",
        "qh03-project", "qh03-tree", "qh03-stream", "qh03-session",
        "durable handoff crash fixture" };
    reply = command(owner, 10u, offer);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(reply, id);
    free(reply);
    write_exact(pipe_fd, id, sizeof id);
    const char* accept[] = { "AIMEM", "HANDOFF", "ACCEPT", id, "1" };
    assert_response(recipient, 5u, accept, "ACCEPTED");
    qihse_audit_flush();
    write_exact(pipe_fd, "H", 1u);
    kill(getpid(), SIGKILL);
    _exit(100);
}

static void verify_handoff_replay(const char* id) {
    open_instance();
    qihse_user_t *owner, *recipient, *competitor;
    create_handoff_users(&owner, &recipient, &competitor);
    const char* accept[] = { "AIMEM", "HANDOFF", "ACCEPT", id, "1" };
    assert_response(recipient, 5u, accept, "ACCEPTED");
    const char* get[] = { "AIMEM", "HANDOFF", "GET", id };
    assert_response(recipient, 4u, get, "durable handoff crash fixture");
    assert_response(recipient, 4u, get, "ACCEPTED");
    assert_response(competitor, 4u, get, "$-1\r\n");
    (void)owner;
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static uint64_t test_doc_id(const char* id) {
    qihse_uuid_t uuid;
    assert(qihse_uuid_parse(id, &uuid));
    uint64_t value = 0u;
    for (size_t i = 0; i < 8u; i++) value = (value << 8) | uuid.bytes[i];
    return value;
}

static void migration_destination_then_kill(int pipe_fd) {
    open_instance();
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    assert(qihse_ai_memory_store(server, operator_user, MIGRATION_TEXT,
                                  QIHSE_AIMEM_SEMANTIC, id));
    qihse_ai_memory_hit_t hit;
    memset(&hit, 0, sizeof hit);
    assert(qihse_ai_memory_get(server, operator_user, id, &hit));
    char destination_key[64];
    snprintf(destination_key, sizeof destination_key, "t:0/aimem:%016llx",
             (unsigned long long)test_doc_id(id));
    size_t cap = strlen(hit.text) + 512u;
    char* migrated = malloc(cap);
    assert(migrated);
    int n = snprintf(migrated, cap,
        "v2|%s|%llu|%u|%u|%u|0|qh01-migrated|tree-a|stream-a|session-a|%s",
        id, (unsigned long long)hit.created_ms, (unsigned)hit.kind,
        (unsigned)hit.classification, (unsigned)hit.sci_compartment, hit.text);
    assert(n > 0 && (size_t)n < cap);
    assert(qihse_kv_set_user(store, destination_key, migrated,
                             hit.classification, hit.sci_compartment,
                             operator_user));
    assert(qihse_kv_sync_store(store));
    free(migrated); free(hit.text);
    qihse_audit_flush();
    write_exact(pipe_fd, id, sizeof id);
    kill(getpid(), SIGKILL);
    _exit(100);
}

static void verify_migration_recovery(const char* id) {
    open_instance();
    const char* migrate[] = { "AIMEM", "MIGRATE-LEGACY", id,
        "qh01-migrated", "tree-a", "stream-a", "session-a" };
    char* reply = command(operator_user, 7u, migrate);
    char migrated_id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(reply, migrated_id);
    free(reply);
    assert(strcmp(id, migrated_id) == 0);
    const char* legacy_get[] = { "AIMEM", "GET", id };
    assert_response(operator_user, 3u, legacy_get, "$-1\r\n");
    const char* scoped_get[] = { "AIMEM", "GET-SCOPED", id,
        "qh01-migrated", "tree-a", "stream-a", "session-a" };
    assert_response(operator_user, 7u, scoped_get, MIGRATION_TEXT);
    reply = command(operator_user, 7u, migrate);
    id_from_store(reply, migrated_id);
    free(reply);
    assert(strcmp(id, migrated_id) == 0);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static void fail_wal_fsync_boundary_then_kill(int pipe_fd) {
    open_instance();
    assert(qihse_kv_set_user(store, "qh00-sync-boundary", FAULT_TEXT,
                             0u, 0u, operator_user));
    /* Inject a real fsync error after the WAL record has been admitted. The
     * RESP durable adapter must withhold its ACK, and restart must replay the
     * retained WAL mutation. The failpoint exists only in this test build. */
    assert(setenv("QIHSE_AIMEM_FAIL_AT", "wal-fsync", 1) == 0);
    bool durable = qihse_kv_sync_store(store);
    assert(!durable);
    qihse_audit_flush();
    write_exact(pipe_fd, "F", 1u);
    kill(getpid(), SIGKILL);
    _exit(100);
}

static void verify_failed_fence_retry(void) {
    open_instance();
    char* recovered = qihse_kv_get_user(store, "qh00-sync-boundary", operator_user);
    assert(recovered && strcmp(recovered, FAULT_TEXT) == 0);
    free(recovered);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static void fail_event_fence_then_kill(int pipe_fd) {
    open_instance();
    char moved_root[96];
    snprintf(moved_root, sizeof moved_root, "%s-moved", data_root);
    const char* append[] = { "AIMEM", "EVENT", "APPEND", "qh02-fence",
        "tree", "stream", "session", "fence-test", "qh02-fence-event",
        "checkpoint", "1792500000000", "QH02-FENCE-RETRY" };
    assert(rename(data_root, moved_root) == 0);
    char* reply = command(operator_user, 12u, append);
    assert(strstr(reply, "NOT_DURABLE"));
    free(reply);
    assert(rename(moved_root, data_root) == 0);
    qihse_audit_flush();
    write_exact(pipe_fd, "F", 1u);
    kill(getpid(), SIGKILL);
    _exit(100);
}

static void verify_event_fence_retry(void) {
    open_instance();
    const char* append[] = { "AIMEM", "EVENT", "APPEND", "qh02-fence",
        "tree", "stream", "session", "fence-test", "qh02-fence-event",
        "checkpoint", "1792500000000", "QH02-FENCE-RETRY" };
    char* first = command(operator_user, 12u, append);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(first, id);
    free(first);
    char* replay = command(operator_user, 12u, append);
    char replay_id[QIHSE_AIMEM_ID_LEN + 1u];
    id_from_store(replay, replay_id);
    free(replay);
    assert(strcmp(id, replay_id) == 0);
    const char* count[] = { "AIMEM", "COUNT-SCOPED", "qh02-fence", "tree",
        "stream", "session", "3" };
    assert_response(operator_user, 7u, count, ":1\r\n");
    const char* read[] = { "AIMEM", "EVENT", "READ", id,
        "qh02-fence", "tree", "stream", "session" };
    assert_response(operator_user, 8u, read, "QH02-FENCE-RETRY");
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
}

static void expect_killed(pid_t pid) {
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int main(void) {
    strcpy(data_root, "build/aimem_qh00_XXXXXX");
    assert(mkdtemp(data_root));
    assert(setenv("QIHSE_DATA_DIR", data_root, 1) == 0);

    int fd[2];
    int fault_pipe[2];
    assert(pipe(fd) == 0);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fd[0]);
        store_then_kill(fd[1]);
    }
    close(fd[1]);
    char id[QIHSE_AIMEM_ID_LEN + 1u];
    read_exact(fd[0], id, sizeof id);
    close(fd[0]);
    expect_killed(pid);

    assert(pipe(fd) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fd[0]);
        verify_then_forget_then_kill(id, fd[1]);
    }
    close(fd[1]);
    char marker;
    read_exact(fd[0], &marker, 1u);
    close(fd[0]);
    assert(marker == 'D');
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_tombstone(id);
        _exit(0);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* QH-02: the RESP durability fence must report failure when the SSTable
     * phase cannot reach its directory; restart/retry must recover one event. */
    assert(pipe(fault_pipe) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fault_pipe[0]);
        fail_event_fence_then_kill(fault_pipe[1]);
    }
    close(fault_pipe[1]);
    read_exact(fault_pipe[0], &marker, 1u);
    close(fault_pipe[0]);
    assert(marker == 'F');
    expect_killed(pid);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_event_fence_retry();
        _exit(0);
    }
    status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* QH-01: recover a destination-first migration interrupted before the
     * legacy source deletion and its second durability fence. */
    assert(pipe(fd) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fd[0]);
        migration_destination_then_kill(fd[1]);
    }
    close(fd[1]);
    char migration_id[QIHSE_AIMEM_ID_LEN + 1u];
    read_exact(fd[0], migration_id, sizeof migration_id);
    close(fd[0]);
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_migration_recovery(migration_id);
        _exit(0);
    }
    status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* QH-03: persist ACCEPTED, lose the reply, then recover the same result. */
    assert(pipe(fd) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fd[0]);
        handoff_accept_then_kill(fd[1]);
    }
    close(fd[1]);
    char handoff_id[QIHSE_AIMEM_ID_LEN + 1u];
    read_exact(fd[0], handoff_id, sizeof handoff_id);
    read_exact(fd[0], &marker, 1u);
    close(fd[0]);
    assert(marker == 'H');
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_handoff_replay(handoff_id);
        _exit(0);
    }
    status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* QH-02: lose the durable append reply, restart, and replay exactly once. */
    assert(pipe(fd) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fd[0]);
        event_ack_then_kill(fd[1]);
    }
    close(fd[1]);
    read_exact(fd[0], &marker, 1u);
    close(fd[0]);
    assert(marker == 'E');
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_event_replay();
        _exit(0);
    }
    status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    /* Hide the data directory after opening the WAL. WAL fsync succeeds but
     * the SSTable phase cannot create its output, so the native durability
     * fence must fail. Restart then recovers the WAL record that crossed its
     * earlier fsync boundary. */
    assert(pipe(fault_pipe) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        close(fault_pipe[0]);
        fail_wal_fsync_boundary_then_kill(fault_pipe[1]);
    }
    close(fault_pipe[1]);
    read_exact(fault_pipe[0], &marker, 1u);
    close(fault_pipe[0]);
    assert(marker == 'F');
    expect_killed(pid);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        verify_failed_fence_retry();
        _exit(0);
    }
    status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("PASS QH-00 crash/fence; QH-01 migration recovery; QH-02 event replay/fence; QH-03 handoff recovery");
    return 0;
}
