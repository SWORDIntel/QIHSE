/*
 * test_brain_rebalance.c — Brain R5 (rebalance on join) and R6 (stale prune).
 *
 *   A. largest owner + healthy slotless joiner
 *      -> a proportional tail range is handed to the joiner (REBALANCE)
 *   B. node unhealthy past the prune timeout, owns no slots
 *      -> pruned from the topology (PRUNE), and it disappears from
 *         qihse_cluster_topology_nodes()
 *   C. node unhealthy past the prune timeout but still owning slots
 *      -> refused (EBUSY): ranges must be re-homed before the owner goes
 *
 * Loopback only; journal dirs are relative.
 */
#include "qihse_auth.h"
#include "qihse_cluster_brain.h"
#include "qihse_cluster_ops.h"
#include "qihse_cluster_slot.h"
#include "qihse_event_stream.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void sleep_ms(uint64_t ms) {
    struct timespec ts = {(time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L};
    nanosleep(&ts, NULL);
}

/* ── fake RESP peer (accepts the handoff) ───────────────────────────────── */

typedef struct {
    int listen_fd;
    uint16_t port;
    volatile int set_count;
    volatile bool stop;
    pthread_t thread;
} fake_peer_t;

static int peer_listen(uint16_t* port_out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    assert(bind(fd, (struct sockaddr*)&addr, sizeof addr) == 0);
    assert(listen(fd, 4) == 0);
    socklen_t len = sizeof addr;
    assert(getsockname(fd, (struct sockaddr*)&addr, &len) == 0);
    *port_out = ntohs(addr.sin_port);
    return fd;
}

static bool peer_read_command(int fd, char* buf, size_t* fill, char* cmd_out, size_t cap) {
    for (;;) {
        if (*fill > 0 && buf[0] == '*') {
            char* nl = memchr(buf, '\n', *fill);
            if (nl) {
                int nargs = atoi(buf + 1);
                size_t off = (size_t)(nl - buf) + 1u;
                bool complete = nargs > 0;
                for (int i = 0; i < nargs && complete; i++) {
                    if (off >= *fill || buf[off] != '$') { complete = false; break; }
                    char* nl2 = memchr(buf + off, '\n', *fill - off);
                    if (!nl2) { complete = false; break; }
                    int len = atoi(buf + off + 1);
                    size_t data_off = (size_t)(nl2 - buf) + 1u;
                    if (data_off + (size_t)len + 2u > *fill) { complete = false; break; }
                    if (i == 0) {
                        size_t c = (size_t)len < cap - 1u ? (size_t)len : cap - 1u;
                        memcpy(cmd_out, buf + data_off, c);
                        cmd_out[c] = '\0';
                    }
                    off = data_off + (size_t)len + 2u;
                }
                if (complete) {
                    memmove(buf, buf + off, *fill - off);
                    *fill -= off;
                    return true;
                }
            }
        }
        ssize_t n = recv(fd, buf + *fill, 4096u - *fill, 0);
        if (n <= 0) return false;
        *fill += (size_t)n;
    }
}

static void* peer_main(void* arg) {
    fake_peer_t* p = (fake_peer_t*)arg;
    while (!p->stop) {
        struct timeval tv = {0, 200000};
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(p->listen_fd, &rfds);
        if (select(p->listen_fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        int cfd = accept(p->listen_fd, NULL, NULL);
        if (cfd < 0) continue;
        char buf[4096];
        size_t fill = 0;
        char cmd[64];
        while (!p->stop && peer_read_command(cfd, buf, &fill, cmd, sizeof cmd)) {
            if (strcmp(cmd, "SET") == 0) __atomic_add_fetch(&p->set_count, 1, __ATOMIC_RELAXED);
            if (send(cfd, "+OK\r\n", 5, 0) <= 0) break;
        }
        close(cfd);
    }
    return NULL;
}

/* ── topology + journal helpers ─────────────────────────────────────────── */

static void add_node(qihse_cluster_topology_t* topo, const char* seed, const char* host,
                     uint16_t port, uint16_t bus_port, bool healthy, uint16_t* idx_out) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof node);
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
    snprintf(node.host, sizeof node.host, "%s", host);
    node.port = port;
    node.bus_port = bus_port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = healthy;
    uint16_t idx = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_upsert_node(topo, &node, &idx));
    if (idx_out) *idx_out = idx;
}

static bool journal_has(const char* dir, const char* kind) {
    qihse_event_stream_t* journal = qihse_event_stream_open(dir, QIHSE_ES_DURABILITY_NONE, true);
    assert(journal);
    uint64_t cursor = 0;
    qihse_es_record_header_t header;
    uint8_t* payload = NULL;
    size_t payload_size = 0;
    char needle[64];
    snprintf(needle, sizeof needle, "\"kind\":\"%s\"", kind);
    bool found = false;
    while (qihse_event_stream_iterate(journal, "cluster.brain", &cursor, &header, &payload,
                                      &payload_size)) {
        if (payload && payload_size < 2048u) {
            char text[2048];
            memcpy(text, payload, payload_size);
            text[payload_size] = '\0';
            if (strstr(text, needle)) found = true;
        }
        free(payload);
        payload = NULL;
    }
    qihse_event_stream_destroy(journal);
    return found;
}

static size_t seed_keys_in_range(qihse_kv_store_t* store, qihse_user_t* user, uint16_t first,
                                 uint16_t last, size_t count) {
    size_t found = 0;
    for (size_t i = 0; found < count && i < 20000u; i++) {
        char key[64];
        snprintf(key, sizeof key, "reb:key%zu", i);
        uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
        if (slot < first || slot > last) continue;
        assert(qihse_kv_set_user(store, key, "payload", 0, 0, user));
        found++;
    }
    return found;
}

int main(void) {
    /* Isolate the KV namespace (see test_brain_actuate.c). */
    char data_root[] = "build/brain_reb_data_XXXXXX";
    assert(mkdtemp(data_root));
    setenv("QIHSE_DATA_DIR", data_root, 1);

    char root[] = "build/brain_reb_XXXXXX";
    assert(mkdtemp(root));
    char dir_a[600], dir_b[600], dir_c[600];
    snprintf(dir_a, sizeof(dir_a), "%s/run_a", root);
    snprintf(dir_b, sizeof(dir_b), "%s/run_b", root);
    snprintf(dir_c, sizeof(dir_c), "%s/run_c", root);
    assert(mkdir(dir_a, 0700) == 0);
    assert(mkdir(dir_b, 0700) == 0);
    assert(mkdir(dir_c, 0700) == 0);

    assert(qihse_auth_init());
    qihse_user_t* system_user = qihse_auth_get_user(0);
    assert(system_user);
    qihse_kv_store_t* store = qihse_kv_store_create();
    assert(store);

    fake_peer_t peer;
    memset(&peer, 0, sizeof peer);
    peer.listen_fd = peer_listen(&peer.port);
    assert(pthread_create(&peer.thread, NULL, peer_main, &peer) == 0);

    qihse_resp_server_config_t scfg;
    qihse_resp_server_config_init(&scfg);
    char local_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    qihse_cluster_node_id_from_seed("brain-reb-local", strlen("brain-reb-local"), local_id);
    scfg.node_id = local_id;
    scfg.auth_required = false;
    scfg.port = 0;
    scfg.store = store;
    scfg.cluster_migrate_password = "reb-test-password";
    qihse_resp_server_t* server = qihse_resp_server_create(&scfg);
    assert(server);
    qihse_cluster_topology_t* topo = qihse_resp_server_topology(server);
    assert(topo);

    uint16_t local = qihse_cluster_topology_local_node(topo);
    assert(local != QIHSE_CLUSTER_NODE_NONE);
    uint16_t joiner = QIHSE_CLUSTER_NODE_NONE;
    add_node(topo, "brain-reb-joiner", "127.0.0.1", peer.port, 17097u, true, &joiner);
    assert(qihse_cluster_topology_assign_range(topo, 0u, 16383u, local));
    assert(seed_keys_in_range(store, system_user, 8192u, 16383u, 3u) == 3u);

    qihse_brain_config_t bcfg;
    memset(&bcfg, 0, sizeof bcfg);
    bcfg.server = server;
    bcfg.journal_dir = dir_a;
    bcfg.interval_seconds = 1u;
    bcfg.act = true;
    bcfg.act_cooldown_seconds = 1u;
    bcfg.rollback_window_seconds = 1u;
    bcfg.rebalance_min_slots = 1024u;
    assert(qihse_cluster_brain_start(&bcfg));
    sleep_ms(3500);
    qihse_cluster_brain_stop();

    /* A — the joiner received the tail half of the local range. */
    assert(journal_has(dir_a, "REBALANCE"));
    uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_slot_state_t state;
    uint16_t peer_index = QIHSE_CLUSTER_NODE_NONE;
    assert(qihse_cluster_topology_get_slot(topo, 8192u, &owner, &state, &peer_index));
    assert(owner == joiner);
    assert(qihse_cluster_topology_get_slot(topo, 8191u, &owner, &state, &peer_index));
    assert(owner == local); /* only the tail moved */
    assert(__atomic_load_n(&peer.set_count, __ATOMIC_RELAXED) >= 3);
    printf("PASS slotless joiner received a proportional range (REBALANCE)\n");

    /* B — a slotless node unhealthy past the prune timeout is pruned. */
    uint16_t stale = QIHSE_CLUSTER_NODE_NONE;
    add_node(topo, "brain-reb-stale", "127.0.0.1", 7098u, 17096u, false, &stale);
    bcfg.journal_dir = dir_b;
    bcfg.rebalance_min_slots = 0u; /* isolate the prune path */
    bcfg.prune_timeout_seconds = 1u;
    assert(qihse_cluster_brain_start(&bcfg));
    sleep_ms(4000);
    qihse_cluster_brain_stop();
    assert(journal_has(dir_b, "PRUNE"));
    qihse_cluster_node_t gone;
    assert(!qihse_cluster_topology_get_node(topo, stale, &gone));
    printf("PASS stale slotless node pruned from the topology\n");

    /* C — an unhealthy node that still owns slots is refused. */
    uint16_t busy = QIHSE_CLUSTER_NODE_NONE;
    add_node(topo, "brain-reb-busy", "127.0.0.1", 7097u, 17095u, false, &busy);
    assert(qihse_cluster_topology_assign_range(topo, 4096u, 8191u, busy));
    bcfg.journal_dir = dir_c;
    assert(qihse_cluster_brain_start(&bcfg));
    sleep_ms(3000);
    qihse_cluster_brain_stop();
    qihse_cluster_node_t still_there;
    assert(qihse_cluster_topology_get_node(topo, busy, &still_there));
    assert(still_there.healthy == false);
    printf("PASS node owning slots is not pruned (ranges must be re-homed first)\n");

    peer.stop = true;
    pthread_join(peer.thread, NULL);
    close(peer.listen_fd);
    qihse_resp_server_destroy(server);
    qihse_kv_store_destroy(store);
    printf("brain rebalance/prune tests passed\n");
    return 0;
}
