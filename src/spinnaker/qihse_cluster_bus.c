#include "qihse_cluster_bus.h"
#include "qihse_platform.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
typedef int socklen_t;
#endif

#define QIHSE_BUS_MAX_DATAGRAM (QIHSE_CLUSTER_BUS_HEADER_SIZE + QIHSE_CLUSTER_BUS_MAX_PAYLOAD)

struct qihse_cluster_bus {
    qihse_cluster_topology_t* topology;
    uint16_t local_node_index;
    uint16_t bus_port;
    char bind_address[QIHSE_CLUSTER_HOST_LEN + 1u];
    char xdp_interface[64];
    uint32_t heartbeat_ms;
    uint32_t timeout_ms;
    qihse_cluster_bus_on_fail_cb on_fail;
    void* on_fail_user_data;
    int sock_fd;
    bool running;
    pthread_t thread;
    pthread_mutex_t lock;
    qihse_cluster_bus_stats_t stats;
    /* Per-node last-seen timestamps (indexed by topology node index) */
    uint64_t* last_seen_ms;
    size_t last_seen_capacity;
};

static uint64_t qihse_bus_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

static void qihse_bus_ensure_last_seen(qihse_cluster_bus_t* bus, size_t needed) {
    if (bus->last_seen_capacity >= needed) return;
    size_t new_cap = bus->last_seen_capacity ? bus->last_seen_capacity * 2u : 16u;
    while (new_cap < needed) new_cap *= 2u;
    uint64_t* resized = (uint64_t*)realloc(bus->last_seen_ms, new_cap * sizeof(*resized));
    if (!resized) return;
    for (size_t i = bus->last_seen_capacity; i < new_cap; i++) resized[i] = 0;
    bus->last_seen_ms = resized;
    bus->last_seen_capacity = new_cap;
}

static void qihse_bus_touch_node(qihse_cluster_bus_t* bus, uint16_t index) {
    if (index == QIHSE_CLUSTER_NODE_NONE) return;
    qihse_bus_ensure_last_seen(bus, (size_t)index + 1u);
    bus->last_seen_ms[index] = qihse_bus_now_ms();
}

/* Serialise a node_t into a payload buffer.  Fixed-size fields only. */
static size_t qihse_bus_serialise_node(const qihse_cluster_node_t* node, uint8_t* out, size_t cap) {
    if (!node || cap < 4u + QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_CLUSTER_HOST_LEN + 1u + 12u) return 0;
    uint8_t* ptr = out;
    uint16_t port = node->port;
    uint16_t bus_port = node->bus_port;
    uint16_t role = (uint16_t)node->role;
    uint16_t primary = node->primary_index;
    uint16_t idx = node->index;
    uint16_t healthy = node->healthy ? 1u : 0u;
    memcpy(ptr, &port, 2u); ptr += 2u;
    memcpy(ptr, &bus_port, 2u); ptr += 2u;
    memcpy(ptr, &role, 2u); ptr += 2u;
    memcpy(ptr, &primary, 2u); ptr += 2u;
    memcpy(ptr, &idx, 2u); ptr += 2u;
    memcpy(ptr, &healthy, 2u); ptr += 2u;
    memcpy(ptr, node->id, QIHSE_CLUSTER_NODE_ID_LEN + 1u); ptr += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    memcpy(ptr, node->host, QIHSE_CLUSTER_HOST_LEN + 1u); ptr += QIHSE_CLUSTER_HOST_LEN + 1u;
    return (size_t)(ptr - out);
}

static bool qihse_bus_deserialise_node(const uint8_t* data, size_t len, qihse_cluster_node_t* out) {
    if (!data || !out || len < 12u + QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_CLUSTER_HOST_LEN + 1u) return false;
    const uint8_t* ptr = data;
    memset(out, 0, sizeof(*out));
    memcpy(&out->port, ptr, 2u); ptr += 2u;
    memcpy(&out->bus_port, ptr, 2u); ptr += 2u;
    uint16_t role; memcpy(&role, ptr, 2u); ptr += 2u;
    out->role = (qihse_cluster_node_role_t)role;
    memcpy(&out->primary_index, ptr, 2u); ptr += 2u;
    memcpy(&out->index, ptr, 2u); ptr += 2u;
    uint16_t healthy; memcpy(&healthy, ptr, 2u); ptr += 2u;
    out->healthy = healthy != 0u;
    memcpy(out->id, ptr, QIHSE_CLUSTER_NODE_ID_LEN + 1u); ptr += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    out->id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    memcpy(out->host, ptr, QIHSE_CLUSTER_HOST_LEN + 1u); ptr += QIHSE_CLUSTER_HOST_LEN + 1u;
    out->host[QIHSE_CLUSTER_HOST_LEN] = '\0';
    return true;
}

static size_t qihse_bus_build_header(uint8_t* buf, qihse_cluster_bus_msg_type_t type,
                                     uint16_t sender, uint32_t payload_len) {
    uint32_t magic = QIHSE_CLUSTER_BUS_MAGIC;
    uint32_t msg = (uint32_t)type;
    uint32_t sender32 = (uint32_t)sender;
    memcpy(buf, &magic, 4u);
    memcpy(buf + 4u, &msg, 4u);
    memcpy(buf + 8u, &sender32, 4u);
    memcpy(buf + 12u, &payload_len, 4u);
    return QIHSE_CLUSTER_BUS_HEADER_SIZE;
}

static bool qihse_bus_parse_header(const uint8_t* buf, size_t len,
                                   uint32_t* magic, uint32_t* type,
                                   uint32_t* sender, uint32_t* payload_len) {
    if (len < QIHSE_CLUSTER_BUS_HEADER_SIZE) return false;
    memcpy(magic, buf, 4u);
    memcpy(type, buf + 4u, 4u);
    memcpy(sender, buf + 8u, 4u);
    memcpy(payload_len, buf + 12u, 4u);
    return *magic == QIHSE_CLUSTER_BUS_MAGIC &&
           *payload_len <= QIHSE_CLUSTER_BUS_MAX_PAYLOAD &&
           len >= QIHSE_CLUSTER_BUS_HEADER_SIZE + *payload_len;
}

static bool qihse_bus_send_datagram(qihse_cluster_bus_t* bus,
                                    const char* host, uint16_t port,
                                    const uint8_t* data, size_t len) {
    if (!bus || bus->sock_fd < 0 || !host || !data || len == 0) return false;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
#ifdef _WIN32
        /* inet_pton for 127.0.0.1 works on Windows too; fall through */
#endif
        return false;
    }
    ssize_t sent = sendto(bus->sock_fd, (const char*)data, (int)len, 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0 || (size_t)sent != len) return false;
    __atomic_add_fetch(&bus->stats.sent, 1u, __ATOMIC_RELAXED);
    return true;
}

static bool qihse_bus_send_to_all_peers(qihse_cluster_bus_t* bus,
                                        qihse_cluster_bus_msg_type_t type,
                                        const uint8_t* payload, size_t payload_len) {
    if (!bus || !bus->topology) return false;
    uint8_t datagram[QIHSE_BUS_MAX_DATAGRAM];
    if (QIHSE_CLUSTER_BUS_HEADER_SIZE + payload_len > sizeof(datagram)) return false;
    qihse_bus_build_header(datagram, type, bus->local_node_index, (uint32_t)payload_len);
    if (payload_len > 0) memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, payload, payload_len);
    size_t total = QIHSE_CLUSTER_BUS_HEADER_SIZE + payload_len;

    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(bus->topology, nodes,
                                                sizeof(nodes) / sizeof(nodes[0]));
    bool any = false;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].index == bus->local_node_index) continue;
        if (nodes[i].bus_port == 0) continue;
        if (qihse_bus_send_datagram(bus, nodes[i].host, nodes[i].bus_port, datagram, total)) any = true;
    }
    return any;
}

static void qihse_bus_handle_ping(qihse_cluster_bus_t* bus, uint16_t sender_index,
                                  const uint8_t* payload, size_t payload_len) {
    (void)payload;
    if (payload_len >= QIHSE_CLUSTER_NODE_ID_LEN + 1u) {
        /* Reply with PONG containing our node_id */
        qihse_cluster_node_t local;
        if (qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) {
            uint8_t pong_payload[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
            memcpy(pong_payload, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
            qihse_cluster_node_t peer;
            if (qihse_cluster_topology_get_node(bus->topology, sender_index, &peer)) {
                uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(pong_payload)];
                qihse_bus_build_header(datagram, QIHSE_BUS_MSG_PONG, bus->local_node_index, sizeof(pong_payload));
                memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, pong_payload, sizeof(pong_payload));
                qihse_bus_send_datagram(bus, peer.host, peer.bus_port, datagram, sizeof(datagram));
            }
        }
    }
    qihse_bus_touch_node(bus, sender_index);
}

static void qihse_bus_handle_pong(qihse_cluster_bus_t* bus, uint16_t sender_index) {
    qihse_bus_touch_node(bus, sender_index);
    __atomic_add_fetch(&bus->stats.pongs_received, 1u, __ATOMIC_RELAXED);
}

static void qihse_bus_handle_meet(qihse_cluster_bus_t* bus, const uint8_t* payload, size_t payload_len) {
    qihse_cluster_node_t node;
    if (!qihse_bus_deserialise_node(payload, payload_len, &node)) return;
    uint16_t idx;
    if (qihse_cluster_topology_upsert_node(bus->topology, &node, &idx)) {
        qihse_bus_touch_node(bus, idx);
    }
}

static void qihse_bus_handle_fail(qihse_cluster_bus_t* bus, uint16_t sender_index,
                                  const uint8_t* payload, size_t payload_len) {
    (void)sender_index;
    if (payload_len < QIHSE_CLUSTER_NODE_ID_LEN + 1u) return;
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(node_id, payload, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    node_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    uint16_t idx;
    if (qihse_cluster_topology_find_node(bus->topology, node_id, &idx)) {
        qihse_cluster_topology_set_node_health(bus->topology, idx, false);
        __atomic_add_fetch(&bus->stats.fail_notices_received, 1u, __ATOMIC_RELAXED);
        if (bus->on_fail) bus->on_fail(bus->topology, idx, bus->on_fail_user_data);
    }
}

static void qihse_bus_handle_slot_update(qihse_cluster_bus_t* bus, const uint8_t* payload, size_t payload_len) {
    if (payload_len < sizeof(qihse_cluster_bus_slot_update_t)) return;
    qihse_cluster_bus_slot_update_t upd;
    memcpy(&upd, payload, sizeof(upd));
    /* Resolve the owner by node ID in the local topology */
    uint16_t local_owner = QIHSE_CLUSTER_NODE_NONE;
    if (upd.owner_id[0] != '\0') {
        qihse_cluster_topology_find_node(bus->topology, upd.owner_id, &local_owner);
    }
    if (local_owner == QIHSE_CLUSTER_NODE_NONE) {
        qihse_cluster_topology_unassign_range(bus->topology, upd.start, upd.end);
    } else {
        qihse_cluster_topology_assign_range(bus->topology, upd.start, upd.end, local_owner);
    }
    __atomic_add_fetch(&bus->stats.slot_updates_received, 1u, __ATOMIC_RELAXED);
}

static void qihse_bus_handle_node_update(qihse_cluster_bus_t* bus, const uint8_t* payload, size_t payload_len) {
    qihse_cluster_node_t node;
    if (!qihse_bus_deserialise_node(payload, payload_len, &node)) return;
    uint16_t idx;
    if (qihse_cluster_topology_upsert_node(bus->topology, &node, &idx)) {
        qihse_cluster_topology_set_node_health(bus->topology, idx, node.healthy);
    }
}

static void qihse_bus_process_datagram(qihse_cluster_bus_t* bus,
                                       const uint8_t* data, size_t len) {
    uint32_t magic, type, sender32, payload_len;
    if (!qihse_bus_parse_header(data, len, &magic, &type, &sender32, &payload_len)) return;
    uint16_t sender = (uint16_t)sender32;
    const uint8_t* payload = data + QIHSE_CLUSTER_BUS_HEADER_SIZE;
    __atomic_add_fetch(&bus->stats.received, 1u, __ATOMIC_RELAXED);
    switch ((qihse_cluster_bus_msg_type_t)type) {
        case QIHSE_BUS_MSG_PING:        qihse_bus_handle_ping(bus, sender, payload, payload_len); break;
        case QIHSE_BUS_MSG_PONG:        qihse_bus_handle_pong(bus, sender); break;
        case QIHSE_BUS_MSG_MEET:        qihse_bus_handle_meet(bus, payload, payload_len); break;
        case QIHSE_BUS_MSG_FAIL:        qihse_bus_handle_fail(bus, sender, payload, payload_len); break;
        case QIHSE_BUS_MSG_SLOT_UPDATE: qihse_bus_handle_slot_update(bus, payload, payload_len); break;
        case QIHSE_BUS_MSG_NODE_UPDATE: qihse_bus_handle_node_update(bus, payload, payload_len); break;
        default: break;
    }
}

static void qihse_bus_send_heartbeat(qihse_cluster_bus_t* bus) {
    qihse_cluster_node_t local;
    if (!qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) return;
    uint8_t payload[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(payload, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_PING, payload, sizeof(payload));
    __atomic_add_fetch(&bus->stats.pings_sent, 1u, __ATOMIC_RELAXED);
}

static void* qihse_bus_thread(void* arg) {
    qihse_cluster_bus_t* bus = (qihse_cluster_bus_t*)arg;
    uint64_t last_heartbeat = 0;
    while (__atomic_load_n(&bus->running, __ATOMIC_ACQUIRE)) {
        qihse_cluster_bus_poll(bus);
        uint64_t now = qihse_bus_now_ms();
        if (now - last_heartbeat >= bus->heartbeat_ms) {
            qihse_bus_send_heartbeat(bus);
            last_heartbeat = now;
        }
        qihse_cluster_bus_check_health(bus);
#ifdef _WIN32
        Sleep(50);
#else
        struct timespec ts = {0, 50 * 1000000};
        nanosleep(&ts, NULL);
#endif
    }
    return NULL;
}

qihse_cluster_bus_t* qihse_cluster_bus_create(const qihse_cluster_bus_config_t* config) {
    if (!config || !config->topology) return NULL;
    qihse_cluster_bus_t* bus = (qihse_cluster_bus_t*)calloc(1, sizeof(*bus));
    if (!bus) return NULL;
    bus->topology = config->topology;
    bus->local_node_index = config->local_node_index;
    bus->bus_port = config->bus_port ? config->bus_port : QIHSE_CLUSTER_BUS_DEFAULT_PORT;
    bus->heartbeat_ms = config->heartbeat_ms ? config->heartbeat_ms : QIHSE_CLUSTER_BUS_HEARTBEAT_MS;
    bus->timeout_ms = config->timeout_ms ? config->timeout_ms : QIHSE_CLUSTER_BUS_TIMEOUT_MS;
    bus->on_fail = config->on_fail;
    bus->on_fail_user_data = config->on_fail_user_data;
    bus->sock_fd = -1;
    bus->running = false;
    if (config->bind_address) {
        strncpy(bus->bind_address, config->bind_address, QIHSE_CLUSTER_HOST_LEN);
        bus->bind_address[QIHSE_CLUSTER_HOST_LEN] = '\0';
    } else {
        snprintf(bus->bind_address, sizeof(bus->bind_address), "%s", "0.0.0.0");
    }
    if (config->xdp_interface) {
        strncpy(bus->xdp_interface, config->xdp_interface, sizeof(bus->xdp_interface) - 1u);
    }
    if (pthread_mutex_init(&bus->lock, NULL) != 0) {
        free(bus);
        return NULL;
    }
    return bus;
}

bool qihse_cluster_bus_start(qihse_cluster_bus_t* bus) {
    if (!bus || bus->running) return false;
    bus->sock_fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (bus->sock_fd < 0) return false;
    int opt = 1;
#ifdef _WIN32
    setsockopt(bus->sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(bus->sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bus->bus_port);
    if (inet_pton(AF_INET, bus->bind_address, &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(bus->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(bus->sock_fd);
        bus->sock_fd = -1;
        return false;
    }
#ifndef _WIN32
    /* Set non-blocking so we can poll in the thread loop */
    int flags = fcntl(bus->sock_fd, F_GETFL, 0);
    if (flags >= 0) fcntl(bus->sock_fd, F_SETFL, flags | O_NONBLOCK);
#endif
    bus->running = true;
    if (pthread_create(&bus->thread, NULL, qihse_bus_thread, bus) != 0) {
        bus->running = false;
        close(bus->sock_fd);
        bus->sock_fd = -1;
        return false;
    }
    return true;
}

void qihse_cluster_bus_stop(qihse_cluster_bus_t* bus) {
    if (!bus || !bus->running) return;
    __atomic_store_n(&bus->running, false, __ATOMIC_RELEASE);
    pthread_join(bus->thread, NULL);
    if (bus->sock_fd >= 0) {
        close(bus->sock_fd);
        bus->sock_fd = -1;
    }
}

void qihse_cluster_bus_destroy(qihse_cluster_bus_t* bus) {
    if (!bus) return;
    qihse_cluster_bus_stop(bus);
    pthread_mutex_destroy(&bus->lock);
    free(bus->last_seen_ms);
    free(bus);
}

bool qihse_cluster_bus_broadcast_slot_update(qihse_cluster_bus_t* bus,
                                             uint16_t start, uint16_t end,
                                             uint16_t owner_index) {
    if (!bus) return false;
    qihse_cluster_node_t owner;
    if (!qihse_cluster_topology_get_node(bus->topology, owner_index, &owner)) return false;
    qihse_cluster_bus_slot_update_t upd;
    memset(&upd, 0, sizeof(upd));
    upd.start = start;
    upd.end = end;
    upd.owner_index = owner_index;
    memcpy(upd.owner_id, owner.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    return qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_SLOT_UPDATE,
                                       (const uint8_t*)&upd, sizeof(upd));
}

bool qihse_cluster_bus_broadcast_node_update(qihse_cluster_bus_t* bus, uint16_t node_index) {
    if (!bus) return false;
    qihse_cluster_node_t node;
    if (!qihse_cluster_topology_get_node(bus->topology, node_index, &node)) return false;
    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t len = qihse_bus_serialise_node(&node, payload, sizeof(payload));
    if (len == 0) return false;
    return qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_NODE_UPDATE, payload, len);
}

bool qihse_cluster_bus_broadcast_fail(qihse_cluster_bus_t* bus, uint16_t failed_node_index) {
    if (!bus) return false;
    qihse_cluster_node_t node;
    if (!qihse_cluster_topology_get_node(bus->topology, failed_node_index, &node)) return false;
    uint8_t payload[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(payload, node.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    return qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_FAIL, payload, sizeof(payload));
}

bool qihse_cluster_bus_meet(qihse_cluster_bus_t* bus, const char* host, uint16_t port) {
    if (!bus || !host) return false;
    qihse_cluster_node_t local;
    if (!qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) return false;
    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t len = qihse_bus_serialise_node(&local, payload, sizeof(payload));
    if (len == 0) return false;
    uint8_t datagram[QIHSE_BUS_MAX_DATAGRAM];
    qihse_bus_build_header(datagram, QIHSE_BUS_MSG_MEET, bus->local_node_index, (uint32_t)len);
    memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, payload, len);
    return qihse_bus_send_datagram(bus, host, port, datagram, QIHSE_CLUSTER_BUS_HEADER_SIZE + len);
}

bool qihse_cluster_bus_inject(qihse_cluster_bus_t* bus,
                              const uint8_t* datagram, size_t len,
                              const char* peer_host, uint16_t peer_port) {
    (void)peer_host;
    (void)peer_port;
    if (!bus || !datagram) return false;
    pthread_mutex_lock(&bus->lock);
    qihse_bus_process_datagram(bus, datagram, len);
    pthread_mutex_unlock(&bus->lock);
    return true;
}

int qihse_cluster_bus_fd(const qihse_cluster_bus_t* bus) {
    return bus ? bus->sock_fd : -1;
}

size_t qihse_cluster_bus_poll(qihse_cluster_bus_t* bus) {
    if (!bus || bus->sock_fd < 0) return 0;
    size_t processed = 0;
    uint8_t buffer[QIHSE_BUS_MAX_DATAGRAM];
    for (int i = 0; i < 64; i++) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t received = recvfrom(bus->sock_fd, (char*)buffer, sizeof(buffer), 0,
                                    (struct sockaddr*)&peer, &peer_len);
        if (received <= 0) break;
        pthread_mutex_lock(&bus->lock);
        qihse_bus_process_datagram(bus, buffer, (size_t)received);
        pthread_mutex_unlock(&bus->lock);
        processed++;
    }
    return processed;
}

size_t qihse_cluster_bus_check_health(qihse_cluster_bus_t* bus) {
    if (!bus || !bus->last_seen_ms) return 0;
    uint64_t now = qihse_bus_now_ms();
    size_t marked = 0;
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(bus->topology, nodes,
                                                sizeof(nodes) / sizeof(nodes[0]));
    for (size_t i = 0; i < count; i++) {
        uint16_t idx = nodes[i].index;
        if (idx == bus->local_node_index) continue;
        if (idx >= bus->last_seen_capacity || bus->last_seen_ms[idx] == 0) continue;
        if (now - bus->last_seen_ms[idx] > bus->timeout_ms) {
            if (nodes[i].healthy) {
                qihse_cluster_topology_set_node_health(bus->topology, idx, false);
                __atomic_add_fetch(&bus->stats.nodes_marked_unhealthy, 1u, __ATOMIC_RELAXED);
                if (bus->on_fail) bus->on_fail(bus->topology, idx, bus->on_fail_user_data);
                marked++;
            }
        }
    }
    return marked;
}

void qihse_cluster_bus_stats(const qihse_cluster_bus_t* bus,
                             qihse_cluster_bus_stats_t* out_stats) {
    if (!bus || !out_stats) return;
    pthread_mutex_lock((pthread_mutex_t*)&bus->lock);
    *out_stats = bus->stats;
    pthread_mutex_unlock((pthread_mutex_t*)&bus->lock);
}
