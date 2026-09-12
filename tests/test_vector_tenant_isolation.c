/* Vector ANN tenant-isolation / leakage regression test (U5).
 *
 * Two layers are verified:
 *   1. RESP surface: a tenant principal cannot write into or search another
 *      tenant's collection (the dispatch tenant gate rejects foreign TAGs).
 *   2. Library surface (deterministic, wire-format independent): an ANN
 *      search with the engine's TAG metadata filter — the exact filter
 *      qihse_resp_handle_vecsearch installs — must never surface a neighbor
 *      stored under another tenant's tag, even when that neighbor is the
 *      numerically closest match and unclassified (the approximate-search
 *      leakage trap).
 */
#define _GNU_SOURCE

#include <assert.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include "qihse_vector_db.h"

#define TENANT7_PW "VectorTenant7Pa1!"
#define TENANT8_PW "VectorTenant8Pa1!"
#define OPERATOR_PASSWORD "OperatorVectorPa1!"

typedef struct { qihse_resp_server_t* server; int fd; } server_thread_arg_t;

static void* server_thread(void* argument) {
    server_thread_arg_t* args = (server_thread_arg_t*)argument;
    assert(qihse_resp_server_handle_client_fd(args->server, args->fd));
    return NULL;
}

typedef struct { int fd; } test_client_t;

static void client_init(test_client_t* client, qihse_resp_server_t* server) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    server_thread_arg_t* args = malloc(sizeof(*args));
    assert(args != NULL);
    args->server = server;
    args->fd = sockets[1];
    pthread_t thread;
    assert(pthread_create(&thread, NULL, server_thread, args) == 0);
    pthread_detach(thread);
    client->fd = sockets[0];
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

/* Reads one complete RESP simple/error/integer reply ('+', '-', ':'). */
static char* read_line_reply(int fd) {
    size_t cap = 512;
    char* buffer = malloc(cap);
    assert(buffer != NULL);
    size_t len = 0;
    for (;;) {
        if (len >= cap - 1u) assert(false);
        struct pollfd pfd = { fd, POLLIN, 0 };
        int ready = poll(&pfd, 1, 20000);
        assert(ready > 0);
        ssize_t received = read(fd, buffer + len, cap - len - 1u);
        assert(received > 0);
        len += (size_t)received;
        buffer[len] = '\0';
        char* crlf = memchr(buffer, '\r', len);
        if (crlf && (size_t)(crlf - buffer) + 1u < len && crlf[1] == '\n') {
            return buffer;
        }
    }
}

static void expect_contains(int fd, const char* needle) {
    char* reply = read_line_reply(fd);
    if (strstr(reply, needle) == NULL) {
        fprintf(stderr, "expected '%s' in reply: %s\n", needle, reply);
        assert(false);
    }
    free(reply);
}

/* The exact filter semantics qihse_resp_handle_vecsearch installs. */
typedef struct { const char* tag; size_t len; } vec_tag_filter_t;

static bool vec_tag_match(const void* metadata, size_t metadata_size, void* opaque) {
    vec_tag_filter_t* filter = (vec_tag_filter_t*)opaque;
    if (!filter || !filter->tag) return true;
    return metadata && metadata_size == filter->len &&
           memcmp(metadata, filter->tag, filter->len) == 0;
}

int main(void) {
    char data_dir[] = "/tmp/qihse-vector-tenant-XXXXXX";
    assert(mkdtemp(data_dir) != NULL);
    assert(setenv("QIHSE_DATA_DIR", data_dir, 1) == 0);
    assert(setenv("QIHSE_FIPS_MODE", "disabled", 1) == 0);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator(OPERATOR_PASSWORD));
    qihse_user_t* operator_user = qihse_auth_get_user(0);
    assert(operator_user != NULL);
    qihse_user_t* tenant7 = qihse_auth_create_tenant_user(operator_user, 7, 71,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT7_PW, false);
    assert(tenant7 != NULL);
    qihse_user_t* tenant8 = qihse_auth_create_tenant_user(operator_user, 8, 72,
                                                          QIHSE_ROLE_GUEST, 91, 0,
                                                          TENANT8_PW, false);
    assert(tenant8 != NULL);

    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store != NULL);
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(vdb);

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.vdb = vdb;
    config.port = 0;
    config.auth_required = true;
    config.enable_task_queue = false;
    config.enable_task_workers = false;
    config.enable_task_scheduler = false;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    assert(server != NULL);

    /* --- RESP surface: tenant gate rejects foreign-collection access ----- */
    test_client_t op;
    client_init(&op, server);
    const char* auth_op[] = { "AUTH", "GODMODE_OP", OPERATOR_PASSWORD };
    send_command(op.fd, 3, auth_op);
    expect_contains(op.fd, "+OK");
    const char* set7[] = { "VECSET", "1", "2", "0.9", "0.1", "TAG", "t:7/private" };
    send_command(op.fd, 7, set7);
    expect_contains(op.fd, "+OK");
    const char* set_commons[] = { "VECSET", "2", "2", "0.1", "0.9", "TAG", "commons/symbols" };
    send_command(op.fd, 7, set_commons);
    expect_contains(op.fd, "+OK");
    const char* set8[] = { "VECSET", "3", "2", "0.5", "0.5", "TAG", "t:8/private" };
    send_command(op.fd, 7, set8);
    expect_contains(op.fd, "+OK");

    test_client_t t8;
    client_init(&t8, server);
    const char* auth8[] = { "AUTH", "User_72", TENANT8_PW };
    send_command(t8.fd, 3, auth8);
    expect_contains(t8.fd, "+OK");
    const char* cross_write[] = { "VECSET", "4", "2", "0.9", "0.1", "TAG", "t:7/private" };
    send_command(t8.fd, 7, cross_write);
    expect_contains(t8.fd, "NOPERM");
    const char* cross_search[] = { "VECSEARCH", "2", "5", "0.9", "0.1", "TAG", "t:7/private" };
    send_command(t8.fd, 7, cross_search);
    expect_contains(t8.fd, "NOPERM");

    close(t8.fd);
    close(op.fd);
    qihse_resp_server_destroy(server);

    /* --- Library surface: the ANN leakage trap --------------------------- */
    float t7_vec[2] = { 0.9f, 0.1f };
    float t8_vec[2] = { 0.5f, 0.5f };
    float commons_vec[2] = { 0.1f, 0.9f };
    const char* tag7 = "t:7/private";
    const char* tag8 = "t:8/private";
    const char* tagc = "commons/symbols";
    {
        const uint64_t ids[3] = { 101u, 102u, 103u };
        const float* vecs[3] = { t7_vec, commons_vec, t8_vec };
        const void* meta[3] = { tag7, tagc, tag8 };
        const size_t sizes[3] = { strlen(tag7), strlen(tagc), strlen(tag8) };
        assert(qihse_vector_db_upsert_by_ids(vdb, ids, vecs[0], 1u, 2u, &meta[0], &sizes[0], NULL, NULL));
        assert(qihse_vector_db_upsert_by_ids(vdb, &ids[1], vecs[1], 1u, 2u, &meta[1], &sizes[1], NULL, NULL));
        assert(qihse_vector_db_upsert_by_ids(vdb, &ids[2], vecs[2], 1u, 2u, &meta[2], &sizes[2], NULL, NULL));
    }

    float probe[2] = { 0.9f, 0.1f }; /* exact match to tenant 7's vector */
    qihse_vector_query_t query;
    memset(&query, 0, sizeof(query));
    query.query_vector = probe;
    query.vector_dims = 2u;
    query.top_k = 5u;
    query.query_mode = QIHSE_VDB_QUERY_FLOAT32;
    query.user = tenant8;
    vec_tag_filter_t filter = { tag8, strlen(tag8) };
    query.metadata_filter = vec_tag_match;
    query.metadata_filter_opaque = &filter;

    qihse_vector_result_t results[5];
    memset(results, 0, sizeof(results));
    int found = qihse_vector_db_search(vdb, &query, results, 5u);
    fprintf(stderr, "[DBG] filtered found=%d:", found);
    for (int i = 0; i < found; i++) fprintf(stderr, " %llu", (unsigned long long)results[i].id);
    fprintf(stderr, "\n");
    assert(found >= 0);
    for (int i = 0; i < found; i++) {
        assert(results[i].id != 101u && results[i].id != 1u); /* no cross-tenant rows */
        /* Only the caller's own collection (RESP row 3 + library row 103). */
        assert(results[i].id == 3u || results[i].id == 103u);
    }

    /* Unfiltered control: without the TAG filter the search WOULD return the
     * foreign vector first — proving the filter is the load-bearing
     * isolation mechanism (and the probe really is closest to it). */
    query.metadata_filter = NULL;
    query.metadata_filter_opaque = NULL;
    memset(results, 0, sizeof(results));
    found = qihse_vector_db_search(vdb, &query, results, 5u);
    assert(found > 0);
    bool saw_foreign = false;
    for (int i = 0; i < found; i++) {
        if (results[i].id == 101u || results[i].id == 1u) saw_foreign = true;
    }
    assert(saw_foreign); /* unfiltered, the foreign row is visible */

    /* Commons is world-readable to authenticated tenants. */
    vec_tag_filter_t commons_filter = { tagc, strlen(tagc) };
    query.metadata_filter = vec_tag_match;
    query.metadata_filter_opaque = &commons_filter;
    memset(results, 0, sizeof(results));
    found = qihse_vector_db_search(vdb, &query, results, 5u);
    assert(found >= 0);
    for (int i = 0; i < found; i++) {
        /* Commons rows (RESP row 2 + library row 102) only. */
        assert(results[i].id == 2u || results[i].id == 102u);
    }

    qihse_vector_db_destroy(vdb);
    qihse_kv_store_destroy(store);
    printf("test_vector_tenant_isolation: all assertions passed\n");
    return 0;
}
