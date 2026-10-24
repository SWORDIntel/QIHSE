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

static void test_pg_wire_handshake_and_queries() {
    printf("Testing PostgreSQL Wire Protocol Sharded Multi-Model Ingress...\n");
    signal(SIGPIPE, SIG_IGN);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("PGWireClusterTestPass123!"));
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op);
    qihse_user_t* user = qihse_auth_create_user(op, 1, QIHSE_ROLE_OPERATOR, 0xFFFF, 0xFFFF, "PGWireClusterTestPass123!", false);
    assert(user);

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

    // 1. Send Startup packet (Length, Protocol: 3.0, "user\0User_1\0database\0qihse\0\0")
    char startup_payload[128];
    int ppos = 0;
    memcpy(startup_payload + ppos, "user", 5); ppos += 5;
    memcpy(startup_payload + ppos, "User_1", 7); ppos += 7;
    memcpy(startup_payload + ppos, "database", 9); ppos += 9;
    memcpy(startup_payload + ppos, "qihse", 6); ppos += 6;
    startup_payload[ppos++] = '\0';

    uint32_t pkt_len = htonl((uint32_t)(8 + ppos));
    uint32_t proto = htonl(196608);
    write_all(fds[0], &pkt_len, 4);
    write_all(fds[0], &proto, 4);
    write_all(fds[0], startup_payload, ppos);

    // Read AuthenticationCleartextPassword ('R', len=8, type=3)
    uint8_t tag = 0;
    read_all(fds[0], &tag, 1);
    assert(tag == 'R');
    uint32_t auth_len = 0;
    read_all(fds[0], &auth_len, 4);
    auth_len = ntohl(auth_len);
    assert(auth_len == 8);
    uint32_t auth_type = 0;
    read_all(fds[0], &auth_type, 4);
    auth_type = ntohl(auth_type);
    assert(auth_type == 3);

    // Send PasswordMessage ('p', len, password\0)
    const char* password = "PGWireClusterTestPass123!";
    size_t pw_len = strlen(password) + 1;
    uint32_t pw_msg_len = htonl((uint32_t)(4 + pw_len));
    uint8_t pw_tag = 'p';
    write_all(fds[0], &pw_tag, 1);
    write_all(fds[0], &pw_msg_len, 4);
    write_all(fds[0], password, pw_len);

    // Read responses until ReadyForQuery ('Z')
    read_until_ready(fds[0]);
    printf("  -> Startup handshake OK (AuthOk + ParameterStatus + ReadyForQuery)\n");

    const char* begin = "BEGIN\0";
    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert1 = "INSERT INTO pg_txn_wire VALUES (1, 'rollback')\0";
    send_pg_msg(fds[0], 'Q', insert1, strlen(insert1) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    qihse_table_t* table = qihse_table_store_find_table(
        qihse_uwp_sql_table_store(), "pg_txn_wire");
    assert(table && qihse_table_row_count(table) == 0);
    const char* rollback = "ROLLBACK\0";
    send_pg_msg(fds[0], 'Q', rollback, strlen(rollback) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 0);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert2 = "INSERT INTO pg_txn_wire VALUES (2, 'commit')\0";
    send_pg_msg(fds[0], 'Q', insert2, strlen(insert2) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* commit = "COMMIT\0";
    send_pg_msg(fds[0], 'Q', commit, strlen(commit) + 1);
    assert(read_ready_status(fds[0]) == 'I');
    assert(qihse_table_row_count(table) == 1);

    send_pg_msg(fds[0], 'Q', begin, strlen(begin) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    const char* insert3 = "INSERT INTO pg_txn_wire VALUES (3, 'disconnect')\0";
    send_pg_msg(fds[0], 'Q', insert3, strlen(insert3) + 1);
    assert(read_ready_status(fds[0]) == 'T');
    assert(qihse_table_row_count(table) == 1);

    // 2. Query virtual system tables: SELECT * FROM pg_catalog.pg_tables
    const char* q1 = "SELECT * FROM pg_catalog.pg_tables\0";
    send_pg_msg(fds[0], 'Q', q1, strlen(q1) + 1);

    read_until_ready(fds[0]);
    printf("  -> Virtual catalog tables discovery OK\n");

    // 3. Query cluster topology view: SELECT * FROM cluster_nodes
    const char* q2 = "SELECT * FROM cluster_nodes\0";
    send_pg_msg(fds[0], 'Q', q2, strlen(q2) + 1);

    read_until_ready(fds[0]);
    printf("  -> Virtual cluster nodes introspection OK\n");

    // 4. Query sharded multi-model: SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=5)
    const char* q3 = "SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=5)\0";
    send_pg_msg(fds[0], 'Q', q3, strlen(q3) + 1);

    read_until_ready(fds[0]);
    printf("  -> Sharded SQL query executed through distributed multi-model planner OK\n");

    // Terminate connection
    uint32_t term_len = htonl(4);
    uint8_t term_tag = 'X';
    write_all(fds[0], &term_tag, 1);
    write_all(fds[0], &term_len, 4);

    struct timespec join_deadline;
    assert(clock_gettime(CLOCK_REALTIME, &join_deadline) == 0);
    join_deadline.tv_sec += 30;
    assert(pthread_timedjoin_np(stid, NULL, &join_deadline) == 0);
    close(fds[0]);

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
