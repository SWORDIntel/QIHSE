/* FTS.SAVE / FTS.LOAD adapter test: durable per-node projection over a real
 * RESP session, with mandatory low-clearance/high-data negative coverage
 * (AGENTS.md invariant #3) and the restart autoload path.
 *
 * The projection is classified-capable: it is built from KV records that
 * carry their own clearance, and it is written to one shared artifact. Every
 * claim below is asserted through the wire, not through the engine API, so
 * an authorization check that lives only in the handler still fails the
 * test. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_fts.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#define OPERATOR_PASSWORD "FtsPersistOp1!"
#define GUEST_PASSWORD    "FtsPersistGst1!"
#define GUEST_USER_ID     70u
/* Anything above the guest's clearance; the operator sees 0xFFFF/0xFFFF. */
#define SECRET_CLASS      5u

#define PUBLIC_KEY  "docs/public-1"
#define SECRET_KEY  "docs/secret-1"
#define EXTRA_KEY   "docs/public-2"
#define PUBLIC_TEXT "public driver analysis notes"
#define SECRET_TEXT "secret kernel exploit technique"

typedef struct {
    qihse_resp_server_t* server;
    int fd;
} server_thread_arg_t;

static void* server_thread(void* argument) {
    server_thread_arg_t* args = (server_thread_arg_t*)argument;
    qihse_resp_server_t* server = args->server;
    int fd = args->fd;
    free(args);
    (void)qihse_resp_server_handle_client_fd(server, fd);
    return NULL;
}

typedef struct {
    int fd;
    pthread_t thread;
} test_client_t;

static void client_open(test_client_t* client, qihse_resp_server_t* server) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    server_thread_arg_t* args = malloc(sizeof(*args));
    assert(args != NULL);
    args->server = server;
    args->fd = sockets[1];
    assert(pthread_create(&client->thread, NULL, server_thread, args) == 0);
    client->fd = sockets[0];
}

static void client_close(test_client_t* client) {
    shutdown(client->fd, SHUT_RDWR);
    close(client->fd);
    assert(pthread_join(client->thread, NULL) == 0);
}

static void send_command(int fd, size_t argc, const char** argv) {
    char header[64];
    int written = snprintf(header, sizeof(header), "*%zu\r\n", argc);
    assert(written > 0);
    assert(write(fd, header, (size_t)written) == (ssize_t)written);
    for (size_t i = 0; i < argc; i++) {
        written = snprintf(header, sizeof(header), "$%zu\r\n", strlen(argv[i]));
        assert(written > 0);
        assert(write(fd, header, (size_t)written) == (ssize_t)written);
        assert(write(fd, argv[i], strlen(argv[i])) == (ssize_t)strlen(argv[i]));
        assert(write(fd, "\r\n", 2) == 2);
    }
}

static char* read_reply(int fd, const char* command) {
    size_t cap = 8192;
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    struct timespec started;
    assert(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
    for (;;) {
        struct timespec now;
        assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        int64_t elapsed_ms = (int64_t)(now.tv_sec - started.tv_sec) * 1000 +
                             (now.tv_nsec - started.tv_nsec) / 1000000;
        int remaining_ms = elapsed_ms < 30000 ? 30000 - (int)elapsed_ms : 0;
        struct pollfd pfd = { fd, POLLIN, 0 };
        /* Password verification and FTS rebuild can exceed the former 2 s
         * timeout under suite load. Bound the whole reply, not each read. */
        int ready = poll(&pfd, 1, remaining_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0)
            fprintf(stderr, "FTS adapter: no reply to %s within 30 s "
                    "(poll=%d, errno=%d)\n", command, ready, errno);
        assert(ready > 0);
        assert(len < cap - 1);
        ssize_t received = read(fd, buffer + len, cap - len - 1);
        assert(received > 0);
        len += (size_t)received;
        buffer[len] = '\0';
        if (len >= 2 && buffer[len - 2] == '\r' && buffer[len - 1] == '\n') {
            struct pollfd again = { fd, POLLIN, 0 };
            if (poll(&again, 1, 100) <= 0) break;
        }
    }
    return buffer;
}

/* A denial must be exactly one RESP reply. An authorization check that
 * writes its error and then lets the handler fall through leaves a second
 * reply queued, which a prefix match would not notice. */
static void assert_single_reply(const char* reply) {
    size_t len = strlen(reply);
    assert(len >= 2);
    assert(reply[len - 2] == '\r' && reply[len - 1] == '\n');
    assert(strchr(reply, '\r') == reply + len - 2);
}

static char* cmd(test_client_t* client, size_t argc, const char** argv) {
    send_command(client->fd, argc, argv);
    return read_reply(client->fd, argv[0]);
}

static char* auth(test_client_t* client, const char* user, const char* password) {
    const char* argv[] = { "AUTH", user, password };
    return cmd(client, 3, argv);
}

/* Longest-lived artifact reader used to prove a refused command changed
 * nothing on disk. */
static bool read_file(const char* path, char* out, size_t cap, size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t got = read(fd, out, cap);
    close(fd);
    if (got < 0) return false;
    *out_len = (size_t)got;
    return true;
}

static qihse_resp_server_t* make_server(qihse_kv_store_t* store, qihse_user_t* operator_user,
                                        const char* fts_dir) {
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.fts = qihse_fts_create();
    assert(config.fts != NULL);
    config.port = 0;
    config.auth_required = true;
    config.fts_persist_directory = fts_dir;
    config.fts_autoload_principal = operator_user;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);
    return server;
}

int main(void) {
    assert(mkdir("build", 0700) == 0 || errno == EEXIST);
    char data_dir[] = "build/qihse-fts-persist-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);
    char fts_dir[640];
    char index_path[768];
    char keys_path[768];
    assert(snprintf(fts_dir, sizeof(fts_dir), "%s/fts", data_dir) > 0);
    assert(mkdir(fts_dir, 0700) == 0 || errno == EEXIST);
    assert(snprintf(index_path, sizeof(index_path), "%s/fts-index.qfts", fts_dir) > 0);
    assert(snprintf(keys_path, sizeof(keys_path), "%s/fts-index.keys", fts_dir) > 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0u);
    assert(operator_user != NULL);
    qihse_user_t* guest = qihse_auth_create_user(operator_user, GUEST_USER_ID,
                                                 QIHSE_ROLE_GUEST, 0, 0,
                                                 GUEST_PASSWORD, false);
    assert(guest != NULL);
    /* qihse_auth_create_user() refuses nothing here, but a low-clearance
     * principal that is not actually low-clearance would make the negative
     * half of this test vacuous. */
    assert(qihse_user_get_role(guest) == QIHSE_ROLE_GUEST);
    assert(!qihse_auth_can_access(guest, SECRET_CLASS, 0));

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    assert(qihse_kv_set_user(store, PUBLIC_KEY, PUBLIC_TEXT, 0, 0, operator_user));
    assert(qihse_kv_set_user(store, SECRET_KEY, SECRET_TEXT, SECRET_CLASS, 0, operator_user));

    qihse_resp_server_t* server = make_server(store, operator_user, fts_dir);
    test_client_t op;
    test_client_t gst;
    client_open(&op, server);
    client_open(&gst, server);

    char* reply = auth(&op, "GODMODE_OP", OPERATOR_PASSWORD);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    reply = auth(&gst, "User_70", GUEST_PASSWORD);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);

    /* ── operator builds a two-document projection ─────────────────────── */
    const char* build[] = { "FTS.BUILD", "*" };
    reply = cmd(&op, 2, build);
    assert(strcmp(reply, ":2\r\n") == 0);
    free(reply);

    const char* search[] = { "FTS.SEARCH", "exploit" };
    reply = cmd(&op, 2, search);
    assert(strstr(reply, SECRET_KEY) != NULL);
    free(reply);

    /* ── invariant #3: the low-clearance principal sees no high data ───── */
    reply = cmd(&gst, 2, search);
    assert(strcmp(reply, "*0\r\n") == 0);
    free(reply);
    const char* search_public[] = { "FTS.SEARCH", "public" };
    reply = cmd(&gst, 2, search_public);
    assert(strstr(reply, PUBLIC_KEY) != NULL);
    assert(strstr(reply, SECRET_KEY) == NULL);
    assert(strstr(reply, SECRET_TEXT) == NULL);
    free(reply);
    printf("[PASS] FTS.SEARCH filters a high-clearance index for a guest\n");

    /* ── SAVE writes a private pair ────────────────────────────────────── */
    const char* save[] = { "FTS.SAVE" };
    reply = cmd(&op, 1, save);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    struct stat st;
    assert(stat(index_path, &st) == 0 && S_ISREG(st.st_mode));
    assert((st.st_mode & 0777) == 0600);
    assert(stat(keys_path, &st) == 0 && S_ISREG(st.st_mode));
    assert((st.st_mode & 0777) == 0600);
    printf("[PASS] FTS.SAVE writes a mode-0600 artifact and sidecar\n");

    /* A refused low-clearance save must not have touched the pair. */
    char index_before[64 * 1024];
    char keys_before[64 * 1024];
    size_t index_before_len = 0, keys_before_len = 0;
    assert(read_file(index_path, index_before, sizeof(index_before), &index_before_len));
    assert(read_file(keys_path, keys_before, sizeof(keys_before), &keys_before_len));

    /* ── invariant #3: the adapter refuses a low-clearance principal ───── */
    reply = cmd(&gst, 1, save);
    assert(strncmp(reply, "-NOPERM", 7) == 0);
    assert(strstr(reply, SECRET_TEXT) == NULL);
    assert_single_reply(reply);
    free(reply);
    const char* load[] = { "FTS.LOAD" };
    reply = cmd(&gst, 1, load);
    assert(strncmp(reply, "-NOPERM", 7) == 0);
    assert(strstr(reply, SECRET_TEXT) == NULL);
    assert_single_reply(reply);
    free(reply);
    /* A refusal that writes its error and then lets the handler continue
     * leaves a second reply queued behind it. PING must be answered next. */
    const char* ping[] = { "PING" };
    reply = cmd(&gst, 1, ping);
    assert(strcmp(reply, "+PONG\r\n") == 0);
    free(reply);

    char index_after[64 * 1024];
    char keys_after[64 * 1024];
    size_t index_after_len = 0, keys_after_len = 0;
    assert(read_file(index_path, index_after, sizeof(index_after), &index_after_len));
    assert(read_file(keys_path, keys_after, sizeof(keys_after), &keys_after_len));
    assert(index_after_len == index_before_len &&
           memcmp(index_before, index_after, index_before_len) == 0);
    assert(keys_after_len == keys_before_len &&
           memcmp(keys_before, keys_after, keys_before_len) == 0);
    printf("[PASS] FTS.SAVE/FTS.LOAD deny a guest and leave the pair untouched\n");

    /* ── operator LOAD restores the same projection ────────────────────── */
    /* [documents, mutations behind, fresh|stale] */
    reply = cmd(&op, 1, load);
    assert(strcmp(reply, "*3\r\n:2\r\n:0\r\n$5\r\nfresh\r\n") == 0);
    free(reply);
    reply = cmd(&op, 2, search);
    assert(strstr(reply, SECRET_KEY) != NULL);
    free(reply);
    printf("[PASS] FTS.LOAD reinstalls the saved projection\n");

    /* ── staleness: a write after SAVE invalidates the pair ────────────── */
    const char* set_extra[] = { "SET", EXTRA_KEY, "public driver addendum" };
    reply = cmd(&op, 3, set_extra);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    /* A store that keeps moving (a replicating node always does) must still
     * be able to persist. The artifact records the generation its CONTENT
     * describes, so it is a real snapshot of an earlier state, and LOAD says
     * how far behind it is instead of pretending it is current. */
    reply = cmd(&op, 1, save);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    reply = cmd(&op, 1, load);
    assert(strncmp(reply, "*3\r\n:2\r\n:1\r\n", 12) == 0);
    assert(strstr(reply, "stale") != NULL);
    free(reply);
    printf("[PASS] a projection the store has moved past loads and reports its lag\n");

    /* Rebuild + save clears the staleness. */
    reply = cmd(&op, 2, build);
    assert(strcmp(reply, ":3\r\n") == 0);
    free(reply);
    reply = cmd(&op, 1, save);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    reply = cmd(&op, 1, load);
    assert(strcmp(reply, "*3\r\n:3\r\n:0\r\n$5\r\nfresh\r\n") == 0);
    free(reply);
    printf("[PASS] rebuild + save + load round-trips the full projection\n");

    /* ── restart: autoload restores without an explicit FTS.BUILD ──────── */
    client_close(&op);
    client_close(&gst);
    qihse_resp_server_destroy(server);

    server = make_server(store, operator_user, fts_dir);
    test_client_t op2;
    client_open(&op2, server);
    reply = auth(&op2, "GODMODE_OP", OPERATOR_PASSWORD);
    assert(strcmp(reply, "+OK\r\n") == 0);
    free(reply);
    /* No FTS.BUILD: the autoload must install the saved projection. It runs
     * on its own thread so a large artifact never delays the listener, so
     * poll instead of assuming it has already landed. */
    char* autoloaded = NULL;
    for (int attempt = 0; attempt < 100; attempt++) {
        free(autoloaded);
        autoloaded = cmd(&op2, 2, search);
        if (strstr(autoloaded, SECRET_KEY) != NULL) break;
        struct timespec pause = { 0, 50 * 1000 * 1000 };
        nanosleep(&pause, NULL);
    }
    assert(strstr(autoloaded, SECRET_KEY) != NULL);
    free(autoloaded);
    printf("[PASS] startup autoload restores the projection after a restart\n");

    /* The restored map is complete, not just the matching document. */
    const char* search_extra[] = { "FTS.SEARCH", "addendum" };
    reply = cmd(&op2, 2, search_extra);
    assert(strstr(reply, EXTRA_KEY) != NULL);
    free(reply);

    /* ── a torn pair is refused, not served ────────────────────────────── */
    FILE* torn = fopen(index_path, "ab");
    assert(torn != NULL);
    assert(fputc('\x7f', torn) != EOF);
    assert(fclose(torn) == 0);
    reply = cmd(&op2, 1, load);
    assert(strncmp(reply, "-ERR", 4) == 0);
    assert(strstr(reply, "corrupt") != NULL);
    free(reply);
    printf("[PASS] a torn artifact/sidecar pair is refused\n");

    client_close(&op2);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("test_fts_persist_adapter: all assertions passed\n");
    return 0;
}
