#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include "qihse_pg_wire.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"
#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_schema.h"

typedef struct {
    int server_fd;
    qihse_kv_store_t* store;
    qihse_cluster_topology_t* topo;
    qihse_uwp_context_t* uwp;
} server_thread_args_t;

static void* server_worker(void* arg) {
    server_thread_args_t* a = (server_thread_args_t*)arg;
    qihse_pg_wire_handle_client_uwp(a->server_fd, a->uwp, a->topo);
    return NULL;
}

static void write_all(int fd, const void* data, size_t len) {
    const uint8_t* p = data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0);
        p += n;
        len -= (size_t)n;
    }
}

static void read_all(int fd, void* data, size_t len) {
    uint8_t* p = data;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        assert(n > 0); /* EOF or receive timeout is a test failure. */
        p += n;
        len -= (size_t)n;
    }
}

static void read_until_ready(int fd) {
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, sizeof(wire_len));
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        char* body = malloc(len - 4 ? len - 4 : 1);
        assert(body);
        read_all(fd, body, len - 4);
        free(body);
        if (tag == 'Z') return;
    }
}

static char read_ready_status(int fd) {
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, sizeof(wire_len));
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        char* body = malloc(len - 4 ? len - 4 : 1);
        assert(body);
        read_all(fd, body, len - 4);
        if (tag == 'Z') {
            assert(len == 5);
            char status = body[0];
            free(body);
            return status;
        }
        free(body);
    }
}

static ssize_t capture_reply(void* opaque, const void* data, size_t len) {
    (void)opaque; (void)data; return (ssize_t)len;
}

static void send_pg_msg(int fd, uint8_t tag, const char* body, size_t body_len) {
    uint32_t msg_len = (uint32_t)(4 + body_len);
    uint8_t header[5];
    header[0] = tag;
    header[1] = (uint8_t)((msg_len >> 24) & 0xff);
    header[2] = (uint8_t)((msg_len >> 16) & 0xff);
    header[3] = (uint8_t)((msg_len >> 8) & 0xff);
    header[4] = (uint8_t)(msg_len & 0xff);
    write_all(fd, header, 5);
    if (body_len > 0) {
        write_all(fd, body, body_len);
    }
}

static void start_pg_client(int fd, const char* username, const char* password) {
    uint8_t startup[512];
    size_t pos = 0;
    const char* keys[] = {"user", "database"};
    const char* values[] = {username, "qihse"};
    for (size_t i = 0; i < 2; ++i) {
        size_t key_len = strlen(keys[i]) + 1u;
        size_t value_len = strlen(values[i]) + 1u;
        memcpy(startup + pos, keys[i], key_len); pos += key_len;
        memcpy(startup + pos, values[i], value_len); pos += value_len;
    }
    startup[pos++] = '\0';
    uint32_t packet_len = htonl((uint32_t)(8u + pos));
    uint32_t protocol = htonl(196608u);
    write_all(fd, &packet_len, sizeof(packet_len));
    write_all(fd, &protocol, sizeof(protocol));
    write_all(fd, startup, pos);

    uint8_t tag;
    uint32_t wire_len, auth_type;
    read_all(fd, &tag, 1);
    assert(tag == 'R');
    read_all(fd, &wire_len, sizeof(wire_len));
    assert(ntohl(wire_len) == 8u);
    read_all(fd, &auth_type, sizeof(auth_type));
    assert(ntohl(auth_type) == 3u);

    size_t password_len = strlen(password) + 1u;
    uint8_t password_tag = 'p';
    uint32_t password_msg_len = htonl((uint32_t)(4u + password_len));
    write_all(fd, &password_tag, 1);
    write_all(fd, &password_msg_len, sizeof(password_msg_len));
    write_all(fd, password, password_len);
    read_until_ready(fd);
}

static char read_ready_status_capture_error(int fd, uint8_t* error,
                                            size_t error_cap,
                                            size_t* error_len) {
    if (error_len) *error_len = 0;
    for (;;) {
        uint8_t tag;
        uint32_t wire_len;
        read_all(fd, &tag, 1);
        read_all(fd, &wire_len, sizeof(wire_len));
        uint32_t len = ntohl(wire_len);
        assert(len >= 4 && len <= 1024 * 1024);
        size_t body_len = (size_t)len - 4u;
        uint8_t* body = malloc(body_len ? body_len : 1u);
        assert(body);
        read_all(fd, body, body_len);
        if (tag == 'E' && error && error_cap && error_len) {
            size_t copy = body_len < error_cap - 1u ? body_len : error_cap - 1u;
            memcpy(error, body, copy);
            *error_len = copy;
        }
        if (tag == 'Z') {
            assert(body_len == 1u);
            char result = (char)body[0];
            free(body);
            return result;
        }
        free(body);
    }
}

static bool contains_bytes(const void* haystack, size_t haystack_len,
                           const char* needle) {
    size_t needle_len = strlen(needle);
    if (!needle_len || needle_len > haystack_len) return false;
    const uint8_t* bytes = haystack;
    for (size_t i = 0; i <= haystack_len - needle_len; ++i)
        if (memcmp(bytes + i, needle, needle_len) == 0) return true;
    return false;
}

static uint64_t table_resource_id(const char* name) {
    uint32_t hash = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)name; *p; ++p) {
        hash ^= *p;
        hash *= 16777619u;
    }
    return (uint64_t)hash;
}

static void test_pg_wire_handshake_and_queries() {
    printf("Testing PostgreSQL Wire Protocol Sharded Multi-Model Ingress...\n");
    signal(SIGPIPE, SIG_IGN);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("PGWireClusterTestPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* user = qihse_auth_create_user(op, 1, QIHSE_ROLE_OPERATOR, 0xFFFF, 0xFFFF, "PGWireClusterTestPass123!", false);
    assert(user);
    qihse_user_t* guest = qihse_auth_create_user(
        op, 2, QIHSE_ROLE_GUEST, 0, 0, "PGWireGuestPass123!", false);
    assert(guest && qihse_user_get_classification(guest) == 0u);

    qihse_uwp_context_t uwp;
    memset(&uwp, 0, sizeof(uwp));
    static int sql_engine_placeholder;
    uwp.sql_engine = &sql_engine_placeholder;
    uwp.schema = qihse_schema_registry_create();
    uwp.txn_manager = qihse_txn_manager_create();
    assert(uwp.schema && uwp.txn_manager);
    const char* ddl = "CREATE TABLE pg_txn_wire (id INT, note TEXT)";
    assert(uwp_dispatch_sql(&uwp, 0x02, (const uint8_t*)ddl, strlen(ddl) + 1,
                            NULL, user, -1, capture_reply, NULL) == UWP_STS_OK);
    const char* protected_ddl =
        "CREATE TABLE pg_txn_protected (id INT, note TEXT)";
    assert(uwp_dispatch_sql(&uwp, 0x02, (const uint8_t*)protected_ddl,
                            strlen(protected_ddl) + 1, NULL, user, -1,
                            capture_reply, NULL) == UWP_STS_OK);
    const char* protected_insert =
        "INSERT INTO pg_txn_protected VALUES (7, 'PG-WIRE-PROTECTED-MARKER')";
    assert(uwp_dispatch_sql(&uwp, 0x02, (const uint8_t*)protected_insert,
                            strlen(protected_insert) + 1, NULL, user, -1,
                            capture_reply, NULL) == UWP_STS_OK);
    assert(qihse_auth_grant_object(op, guest, 0u,
                                   table_resource_id("pg_txn_wire"),
                                   QIHSE_ACL_READ));

    int fds[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(rc == 0);
    struct timeval io_timeout = { .tv_sec = 30 };
    assert(setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);
    assert(setsockopt(fds[1], SOL_SOCKET, SO_SNDTIMEO,
                      &io_timeout, sizeof(io_timeout)) == 0);

    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed("alpha", 5, node.id);
    strncpy(node.host, "127.0.0.1", sizeof(node.host) - 1);
    node.port = 5432;
    node.healthy = true;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    uint16_t idx = 0;
    qihse_cluster_topology_upsert_node(topo, &node, &idx);
    qihse_cluster_topology_set_local_node(topo, idx);

    qihse_kv_store_t* kv = qihse_kv_store_create();
    qihse_kv_set(kv, "{device_4096}", "pg_wire_test_val", 0, 0);

    server_thread_args_t sargs = {
        .server_fd = fds[1],
        .store = kv,
        .topo = topo,
        .uwp = &uwp
    };

    pthread_t stid;
    pthread_create(&stid, NULL, server_worker, &sargs);

    const char* password = "PGWireClusterTestPass123!";
    start_pg_client(fds[0], "User_1", password);
    printf("  -> Startup handshake OK (AuthOk + ParameterStatus + ReadyForQuery)\n");

    const char* begin = "BEGIN\0";
    const char* rollback = "ROLLBACK\0";
    const char* commit = "COMMIT\0";
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert1 = "INSERT INTO pg_txn_wire VALUES (1, 'rollback')\0";
    send_pg_msg(fds[0], 'Q', insert1, strlen(insert1) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    qihse_table_t* table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_wire");
    assert(table && qihse_table_row_count(table) == 0);
    send_pg_msg(fds[0], 'Q', rollback, strlen(rollback) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 0);

    /* A statement error aborts the transaction; later writes stay private,
     * and COMMIT resolves as a rollback. */
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* bad_insert = "INSERT INTO missing_pg_txn_table VALUES (9, 'nope')\0";
    send_pg_msg(fds[0], 'Q', bad_insert, strlen(bad_insert) + 1);
    assert(read_ready_status(fds[0]) == 'E');
    send_pg_msg(fds[0], 'Q', insert1, strlen(insert1) + 1);
    assert(read_ready_status(fds[0]) == 'E');
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 0);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert2 =
        "INSERT INTO pg_txn_wire VALUES (2, 'PG-WIRE-ALLOWED-ROW')\0";
    send_pg_msg(fds[0], 'Q', insert2, strlen(insert2) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 1);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert3 = "INSERT INTO pg_txn_wire VALUES (3, 'disconnect')\0";
    send_pg_msg(fds[0], 'Q', insert3, strlen(insert3) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    assert(qihse_table_row_count(table) == 1);

    /* Disconnecting with a healthy active transaction rolls back its private
     * row shadow. */
    uint32_t term_len = htonl(4);
    uint8_t term_tag = 'X';
    write_all(fds[0], &term_tag, 1);
    write_all(fds[0], &term_len, 4);

    struct timespec join_deadline;
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(stid, NULL, &join_deadline) == 0);
    close(fds[0]);
    assert(qihse_table_row_count(table) == 1);

    /* A second authenticated, clearance-0 principal may read the explicitly
     * granted table. Access to the ungranted table is refused by the UWP SQL
     * executor, and the protected marker is absent from the wire error. */
    int guest_fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, guest_fds) == 0);
    for (size_t i = 0; i < 2; ++i) {
        assert(setsockopt(guest_fds[i], SOL_SOCKET, SO_RCVTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
        assert(setsockopt(guest_fds[i], SOL_SOCKET, SO_SNDTIMEO,
                          &io_timeout, sizeof(io_timeout)) == 0);
    }
    server_thread_args_t guest_args = {
        .server_fd = guest_fds[1], .store = kv, .topo = topo, .uwp = &uwp
    };
    pthread_t guest_thread;
    assert(pthread_create(&guest_thread, NULL, server_worker, &guest_args) == 0);
    start_pg_client(guest_fds[0], "User_2", "PGWireGuestPass123!");

    const char* allowed_read =
        "SELECT id, note FROM pg_txn_wire WHERE id = 2\0";
    send_pg_msg(guest_fds[0], 'Q', allowed_read, strlen(allowed_read) + 1u);
    assert(read_ready_status(guest_fds[0]) == 'I');

    const char* denied_read =
        "SELECT note FROM pg_txn_protected WHERE id = 7\0";
    send_pg_msg(guest_fds[0], 'Q', denied_read, strlen(denied_read) + 1u);
    uint8_t error_body[512];
    size_t error_len = 0;
    assert(read_ready_status_capture_error(guest_fds[0], error_body,
                                           sizeof(error_body), &error_len) == 'I');
    assert(error_len > 0);
    assert(!contains_bytes(error_body, error_len, "PG-WIRE-PROTECTED-MARKER"));
    puts("PASS low-clearance PG wire SELECT: table ACL denied and no marker disclosed");

    write_all(guest_fds[0], &term_tag, 1);
    write_all(guest_fds[0], &term_len, 4);
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(guest_thread, NULL, &join_deadline) == 0);
    close(guest_fds[0]);
    qihse_table_t* protected_table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_protected");
    assert(protected_table && qihse_table_row_count(protected_table) == 1);

    qihse_kv_store_destroy(kv);
    qihse_cluster_topology_destroy(topo);
    assert(qihse_table_row_count(table) == 1);
    qihse_txn_manager_destroy((qihse_txn_manager_t*)uwp.txn_manager);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)uwp.schema);
}

int main() {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_pg_wire_txn_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    printf("==============================================================\n");
    printf("  QIHSE PostgreSQL Wire Transaction Tests                      \n");
    printf("==============================================================\n");

    test_pg_wire_handshake_and_queries();

    printf("\nPostgreSQL Wire transaction tests PASSED!\n");
    return 0;
}
