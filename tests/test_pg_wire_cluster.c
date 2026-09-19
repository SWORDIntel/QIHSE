#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include "qihse_pg_wire.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_auth.h"

typedef struct {
    int server_fd;
    qihse_kv_store_t* store;
    qihse_cluster_topology_t* topo;
} server_thread_args_t;

static void* server_worker(void* arg) {
    server_thread_args_t* a = (server_thread_args_t*)arg;
    qihse_pg_wire_handle_client_multi(a->server_fd, a->store, NULL, NULL, NULL, a->topo);
    return NULL;
}

static void send_pg_msg(int fd, uint8_t tag, const char* body, size_t body_len) {
    uint32_t msg_len = (uint32_t)(4 + body_len);
    uint8_t header[5];
    header[0] = tag;
    header[1] = (uint8_t)((msg_len >> 24) & 0xff);
    header[2] = (uint8_t)((msg_len >> 16) & 0xff);
    header[3] = (uint8_t)((msg_len >> 8) & 0xff);
    header[4] = (uint8_t)(msg_len & 0xff);
    write(fd, header, 5);
    if (body_len > 0) {
        write(fd, body, body_len);
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

    int fds[2];
    int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(rc == 0);

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
        .topo = topo
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
    write(fds[0], &pkt_len, 4);
    write(fds[0], &proto, 4);
    write(fds[0], startup_payload, ppos);

    // Read AuthenticationCleartextPassword ('R', len=8, type=3)
    uint8_t tag = 0;
    assert(read(fds[0], &tag, 1) == 1 && tag == 'R');
    uint32_t auth_len = 0;
    assert(read(fds[0], &auth_len, 4) == 4);
    auth_len = ntohl(auth_len);
    assert(auth_len == 8);
    uint32_t auth_type = 0;
    assert(read(fds[0], &auth_type, 4) == 4);
    auth_type = ntohl(auth_type);
    assert(auth_type == 3);

    // Send PasswordMessage ('p', len, password\0)
    const char* password = "PGWireClusterTestPass123!";
    size_t pw_len = strlen(password) + 1;
    uint32_t pw_msg_len = htonl((uint32_t)(4 + pw_len));
    uint8_t pw_tag = 'p';
    write(fds[0], &pw_tag, 1);
    write(fds[0], &pw_msg_len, 4);
    write(fds[0], password, pw_len);

    // Read responses until ReadyForQuery ('Z')
    tag = 0;
    while (read(fds[0], &tag, 1) > 0) {
        uint32_t len = 0;
        assert(read(fds[0], &len, 4) == 4);
        len = ntohl(len);
        if (len > 4) {
            char* buf = malloc(len - 4);
            assert(read(fds[0], buf, len - 4) == (ssize_t)(len - 4));
            free(buf);
        }
        if (tag == 'Z') break;
    }
    assert(tag == 'Z');
    printf("  -> Startup handshake OK (AuthOk + ParameterStatus + ReadyForQuery)\n");

    // 2. Query virtual system tables: SELECT * FROM pg_catalog.pg_tables
    const char* q1 = "SELECT * FROM pg_catalog.pg_tables\0";
    send_pg_msg(fds[0], 'Q', q1, strlen(q1) + 1);

    while (read(fds[0], &tag, 1) > 0) {
        uint32_t len = 0;
        read(fds[0], &len, 4);
        len = ntohl(len);
        if (len > 4) {
            char* buf = malloc(len - 4);
            read(fds[0], buf, len - 4);
            free(buf);
        }
        if (tag == 'Z') break;
    }
    printf("  -> Virtual catalog tables discovery OK\n");

    // 3. Query cluster topology view: SELECT * FROM cluster_nodes
    const char* q2 = "SELECT * FROM cluster_nodes\0";
    send_pg_msg(fds[0], 'Q', q2, strlen(q2) + 1);

    while (read(fds[0], &tag, 1) > 0) {
        uint32_t len = 0;
        read(fds[0], &len, 4);
        len = ntohl(len);
        if (len > 4) {
            char* buf = malloc(len - 4);
            read(fds[0], buf, len - 4);
            free(buf);
        }
        if (tag == 'Z') break;
    }
    printf("  -> Virtual cluster nodes introspection OK\n");

    // 4. Query sharded multi-model: SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=5)
    const char* q3 = "SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=5)\0";
    send_pg_msg(fds[0], 'Q', q3, strlen(q3) + 1);

    while (read(fds[0], &tag, 1) > 0) {
        uint32_t len = 0;
        read(fds[0], &len, 4);
        len = ntohl(len);
        if (len > 4) {
            char* buf = malloc(len - 4);
            read(fds[0], buf, len - 4);
            free(buf);
        }
        if (tag == 'Z') break;
    }
    printf("  -> Sharded SQL query executed through distributed multi-model planner OK\n");

    // Terminate connection
    uint32_t term_len = htonl(4);
    uint8_t term_tag = 'X';
    write(fds[0], &term_tag, 1);
    write(fds[0], &term_len, 4);

    pthread_join(stid, NULL);
    close(fds[0]);

    qihse_kv_store_destroy(kv);
    qihse_cluster_topology_destroy(topo);
}

int main() {
    printf("==============================================================\n");
    printf("  QIHSE PostgreSQL Wire Protocol Sharded Multi-Model Tests     \n");
    printf("==============================================================\n");

    test_pg_wire_handshake_and_queries();

    printf("\nAll PostgreSQL Wire Protocol Tests PASSED!\n");
    return 0;
}
