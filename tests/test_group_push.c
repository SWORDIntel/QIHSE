/*
 * test_group_push.c — Group update push (GROUP.* + GROUP_UPDATE/GROUP_ACK).
 *
 * A. Bus level: a GROUP_UPDATE frame delivered to a bus fires the member
 *    callback with group/payload/sender intact, and a GROUP_ACK frame fires
 *    the ack callback.
 * B. Engine level (live server): GROUP.DEFINE registers members, GROUP.PUSH
 *    assigns a monotonic sortable update id, applies locally and stores the
 *    update under grpupd:<group>:<id>; GROUP.STATUS reports the member as
 *    applied; GROUP.LIST lists the group.
 * C. Membership is enforced by the consumer: a push to a group this node is
 *    not a member of writes nothing and acks as not-member.
 *
 * Loopback only; the KV namespace is isolated under build/.
 */
#include "qihse_auth.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── capture callbacks ──────────────────────────────────────────────────── */

typedef struct {
    int updates;
    int acks;
    uint64_t last_update_id;
    uint16_t last_sender;
    uint16_t last_status;
    char last_group[64];
    char last_payload[256];
} capture_t;

static void on_update(qihse_cluster_bus_t* bus, uint64_t update_id, const char* group,
                      const uint8_t* payload, size_t payload_len, uint16_t sender_index,
                      void* user_data) {
    (void)bus;
    capture_t* c = (capture_t*)user_data;
    c->updates++;
    c->last_update_id = update_id;
    c->last_sender = sender_index;
    snprintf(c->last_group, sizeof(c->last_group), "%s", group);
    size_t n = payload_len < sizeof(c->last_payload) - 1u ? payload_len
                                                          : sizeof(c->last_payload) - 1u;
    memcpy(c->last_payload, payload, n);
    c->last_payload[n] = '\0';
}

static void on_ack(qihse_cluster_bus_t* bus, uint64_t update_id, uint16_t sender_index,
                   uint16_t status, void* user_data) {
    (void)bus;
    capture_t* c = (capture_t*)user_data;
    c->acks++;
    c->last_update_id = update_id;
    c->last_sender = sender_index;
    c->last_status = status;
}

/* ── helpers ────────────────────────────────────────────────────────────── */

static uint16_t free_tcp_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static void make_node(qihse_cluster_node_t* node, const char* seed, const char* host,
                      uint16_t port, uint16_t bus_port) {
    memset(node, 0, sizeof(*node));
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node->id);
    snprintf(node->host, sizeof(node->host), "%s", host);
    node->port = port;
    node->bus_port = bus_port;
    node->role = QIHSE_CLUSTER_NODE_PRIMARY;
    node->primary_index = QIHSE_CLUSTER_NODE_NONE;
    node->healthy = true;
}

/* ── A: bus frame round-trip via inject ─────────────────────────────────── */

static void test_bus_frames(void) {
    qihse_cluster_topology_t* topo = qihse_cluster_topology_create();
    assert(topo);
    qihse_cluster_node_t local;
    make_node(&local, "group-push-local", "127.0.0.1", 7300u, 17300u);
    uint16_t idx = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topo, &local, &idx));
    assert(qihse_cluster_topology_set_local_node(topo, idx));

    qihse_cluster_bus_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    bcfg.topology = topo;
    bcfg.local_node_index = idx;
    bcfg.bus_port = free_tcp_port();
    bcfg.bind_address = "127.0.0.1";
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bcfg);
    assert(bus);
    assert(qihse_cluster_bus_start(bus));

    capture_t cap;
    memset(&cap, 0, sizeof cap);
    qihse_cluster_bus_set_group_callbacks(bus, on_update, &cap, on_ack, &cap);

    /* GROUP_UPDATE: [u64 id][u16 group_len][u16 payload_len][group][payload] */
    const char* group = "rollout";
    const char* payload = "version=2.1.0;drain=30s";
    uint8_t frame[QIHSE_CLUSTER_BUS_HEADER_SIZE + QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    uint64_t update_id = 0x1122334455667788ull;
    size_t group_len = strlen(group), payload_len = strlen(payload);
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC, type = QIHSE_BUS_MSG_GROUP_UPDATE, sender = 3u;
    uint32_t plen = (uint32_t)(12u + group_len + payload_len);
    memcpy(frame, &magic, 4);
    memcpy(frame + 4, &type, 4);
    memcpy(frame + 8, &sender, 4);
    memcpy(frame + 12, &plen, 4);
    uint8_t* p = frame + QIHSE_CLUSTER_BUS_HEADER_SIZE;
    memcpy(p, &update_id, 8); p += 8;
    uint16_t glen = (uint16_t)group_len, blen = (uint16_t)payload_len;
    memcpy(p, &glen, 2); p += 2;
    memcpy(p, &blen, 2); p += 2;
    memcpy(p, group, group_len); p += group_len;
    memcpy(p, payload, payload_len); p += payload_len;
    assert(qihse_cluster_bus_inject(bus, frame, (size_t)(p - frame), "127.0.0.1", 17000));
    assert(cap.updates == 1);
    assert(cap.last_update_id == update_id);
    assert(cap.last_sender == 3u);
    assert(strcmp(cap.last_group, group) == 0);
    assert(strcmp(cap.last_payload, payload) == 0);

    /* GROUP_ACK: [u64 id][u16 status][node_id[41]] */
    type = QIHSE_BUS_MSG_GROUP_ACK;
    uint16_t status = 7u;
    memcpy(frame, &magic, 4);
    memcpy(frame + 4, &type, 4);
    memcpy(frame + 8, &sender, 4);
    uint32_t alen = (uint32_t)(10u + QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    memcpy(frame + 12, &alen, 4);
    p = frame + QIHSE_CLUSTER_BUS_HEADER_SIZE;
    memcpy(p, &update_id, 8); p += 8;
    memcpy(p, &status, 2); p += 2;
    memcpy(p, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u); p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    assert(qihse_cluster_bus_inject(bus, frame, (size_t)(p - frame), "127.0.0.1", 17000));
    assert(cap.acks == 1);
    assert(cap.last_status == status);
    assert(cap.last_update_id == update_id);

    qihse_cluster_bus_stop(bus);
    qihse_cluster_bus_destroy(bus);
    qihse_cluster_topology_destroy(topo);
    printf("PASS bus GROUP_UPDATE/GROUP_ACK frames reach the callbacks\n");
}

/* ── minimal RESP client ────────────────────────────────────────────────── */

typedef struct {
    int fd;
    char buf[65536];
    size_t fill;
} client_t;

static bool read_line(client_t* c, char* out, size_t cap) {
    for (;;) {
        for (size_t i = 0; i < c->fill; i++) {
            if (c->buf[i] == '\n') {
                size_t len = i;
                if (len && c->buf[len - 1u] == '\r') len--;
                if (len >= cap) len = cap - 1u;
                memcpy(out, c->buf, len);
                out[len] = '\0';
                memmove(c->buf, c->buf + i + 1u, c->fill - i - 1u);
                c->fill -= i + 1u;
                return true;
            }
        }
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
}

static bool read_exact(client_t* c, char* out, size_t len) {
    while (c->fill < len) {
        ssize_t n = recv(c->fd, c->buf + c->fill, sizeof(c->buf) - c->fill, 0);
        if (n <= 0) return false;
        c->fill += (size_t)n;
    }
    memcpy(out, c->buf, len);
    memmove(c->buf, c->buf + len, c->fill - len);
    c->fill -= len;
    return true;
}

/* Reads one reply into out (flattened for arrays as "a|b|c"). */
static bool read_reply(client_t* c, char* out, size_t cap, size_t* used) {
    char line[512];
    if (!read_line(c, line, sizeof(line))) return false;
    char type = line[0];
    const char* rest = line + 1;
    if (type == '+' || type == '-' || type == ':') {
        int n = snprintf(out + *used, cap - *used, "%s", rest);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '$') {
        int len = atoi(rest);
        if (len < 0) return true; /* nil */
        char data[4096];
        if ((size_t)len >= sizeof(data)) return false;
        if (!read_exact(c, data, (size_t)len + 2u)) return false;
        data[len] = '\0';
        int n = snprintf(out + *used, cap - *used, "%s", data);
        *used += (size_t)(n > 0 ? n : 0);
        return true;
    }
    if (type == '*') {
        int count = atoi(rest);
        for (int i = 0; i < count; i++) {
            if (i && *used + 1u < cap) out[(*used)++] = '|';
            if (!read_reply(c, out, cap, used)) return false;
        }
        return true;
    }
    return false;
}

static void send_cmd(client_t* c, const char* a, const char* b, const char* d, const char* e) {
    const char* args[4] = { a, b, d, e };
    size_t argc = 0;
    for (size_t i = 0; i < 4u; i++) if (args[i]) argc++;
    char out[2048];
    size_t off = 0;
    off += (size_t)snprintf(out + off, sizeof(out) - off, "*%zu\r\n", argc);
    for (size_t i = 0; i < argc; i++) {
        off += (size_t)snprintf(out + off, sizeof(out) - off, "$%zu\r\n%s\r\n",
                                strlen(args[i]), args[i]);
    }
    assert(send(c->fd, out, off, 0) == (ssize_t)off);
}

/* ── B/C: engine-level push over a live server ──────────────────────────── */

int main(void) {
    char data_root[] = "build/group_push_data_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    assert(qihse_auth_init());
    assert(qihse_auth_bootstrap_operator("OperatorPass123!"));

    test_bus_frames();

    uint16_t port = free_tcp_port();
    uint16_t bus_port = free_tcp_port();
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);
    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("group-push-server", strlen("group-push-server"), node_id);
    scfg.node_id = node_id;
    scfg.bind_address = "127.0.0.1";
    scfg.advertise_address = "127.0.0.1";
    scfg.port = port;
    scfg.bus_port = bus_port;
    scfg.store = store;
    scfg.enable_bus = true;
    scfg.enable_failover = false;
    scfg.auth_required = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);
    assert(qihse_resp_server_start(server));

    client_t c;
    memset(&c, 0, sizeof c);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    c.fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(c.fd >= 0);
    assert(connect(c.fd, (struct sockaddr*)&addr, sizeof addr) == 0);

    char reply[8192];
    size_t used;
    send_cmd(&c, "AUTH", "GODMODE_OP", "OperatorPass123!", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    if (strcmp(reply, "OK") != 0) fprintf(stderr, "AUTH reply: '%s'\n", reply);
    assert(strcmp(reply, "OK") == 0);

    /* B — define a group containing this node, then push an update. */
    char self_addr[64];
    snprintf(self_addr, sizeof(self_addr), "127.0.0.1:%u", (unsigned)port);
    send_cmd(&c, "GROUP", "DEFINE", "rollout", self_addr);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    if (strcmp(reply, "1") != 0) {
        fprintf(stderr, "GROUP.DEFINE reply: '%s' (self_addr=%s)\n", reply, self_addr);
    }
    assert(strcmp(reply, "1") == 0); /* one member registered */

    send_cmd(&c, "GROUP", "PUSH", "rollout", "version=2.1.0;drain=30s");
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    unsigned long long update_id = strtoull(reply, NULL, 10);
    assert(update_id != 0ull);
    assert(strstr(reply, "local=0") != NULL); /* applied locally */

    char kv_key[192];
    snprintf(kv_key, sizeof(kv_key), "grpupd:rollout:%016llx", update_id);
    char* value = qihse_kv_get_user(store, kv_key, qihse_auth_get_user(0));
    assert(value != NULL);
    assert(strcmp(value, "version=2.1.0;drain=30s") == 0);
    free(value);

    send_cmd(&c, "GROUP", "STATUS", "rollout", NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, node_id) != NULL);
    assert(strstr(reply, "applied") != NULL);

    send_cmd(&c, "GROUP", "LIST", NULL, NULL);
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strstr(reply, "rollout") != NULL);
    printf("PASS GROUP.DEFINE/PUSH/STATUS/LIST apply the update locally\n");

    /* C — a push to a group this node is not a member of writes nothing. */
    qihse_cluster_node_t other;
    make_node(&other, "group-push-other", "127.0.0.1", 7399u, 17399u);
    uint16_t other_idx = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(qihse_resp_server_topology(server), &other,
                                              &other_idx));
    send_cmd(&c, "GROUP", "DEFINE", "others", "127.0.0.1:7399");
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    assert(strcmp(reply, "1") == 0);

    send_cmd(&c, "GROUP", "PUSH", "others", "should-not-apply");
    used = 0; assert(read_reply(&c, reply, sizeof reply, &used));
    unsigned long long other_id = strtoull(reply, NULL, 10);
    assert(other_id != 0ull);
    assert(strstr(reply, "local=1") != NULL); /* 1 = not a member */
    snprintf(kv_key, sizeof(kv_key), "grpupd:others:%016llx", other_id);
    char* missing = qihse_kv_get_user(store, kv_key, qihse_auth_get_user(0));
    assert(missing == NULL); /* nothing written for a non-member */
    printf("PASS non-member nodes ignore a pushed update (nothing written)\n");

    close(c.fd);
    qihse_resp_server_stop(server);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("group push tests passed\n");
    return 0;
}
