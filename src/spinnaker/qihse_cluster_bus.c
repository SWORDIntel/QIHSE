#include "qihse_cluster_bus.h"
#include "qihse_platform.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

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

/* Veiled framing (transport obfuscation, not encryption):
 *   wire format: [nonce 8B][pad_len u8][padding 1-64B][xored_frame]
 * keystream = HMAC-SHA384(veil_key, nonce) expanded in 48-byte blocks
 * (nonce || big-endian u32 block counter), XORed over the frame. */
#define QIHSE_BUS_VEIL_NONCE_LEN 8u
#define QIHSE_BUS_VEIL_PAD_MAX 64u
#define QIHSE_BUS_VEIL_HEADER_LEN (QIHSE_BUS_VEIL_NONCE_LEN + 1u)
#define QIHSE_BUS_VEIL_OVERHEAD (QIHSE_BUS_VEIL_HEADER_LEN + QIHSE_BUS_VEIL_PAD_MAX)

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
    uint64_t* first_seen_ms;
    uint64_t* obs_healthy_ms;   /* last time ANY participant reported this node healthy */   /* when this peer first appeared to us */
    size_t last_seen_capacity;
    /* Per-node capability profile from NODE_CAP frames (same indexing) */
    uint8_t* cap_isa;
    uint8_t* cap_npu;
    uint8_t* cap_gpu;
    uint32_t* cap_free_ram_mb;
    uint16_t* cap_load_pct;
    uint8_t* cap_present;       /* 1 once a NODE_CAP has been received */
    /* Veiled framing state (owned copy of the config key; NULL = passthrough) */
    char* veil_key;
    size_t veil_key_len;
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
    /* first_seen grows in lockstep; existing values are preserved */
    uint64_t* grown_first = (uint64_t*)realloc(bus->first_seen_ms, new_cap * sizeof(*grown_first));
    if (grown_first) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_first[i] = 0;
        bus->first_seen_ms = grown_first;
    }
    uint64_t* grown_obs = (uint64_t*)realloc(bus->obs_healthy_ms, new_cap * sizeof(*grown_obs));
    if (grown_obs) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_obs[i] = 0;
        bus->obs_healthy_ms = grown_obs;
    }
    /* Capability profile arrays grow in lockstep with the last-seen table. */
    uint8_t* grown_isa = (uint8_t*)realloc(bus->cap_isa, new_cap * sizeof(*grown_isa));
    if (grown_isa) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_isa[i] = 0;
        bus->cap_isa = grown_isa;
    }
    uint8_t* grown_npu = (uint8_t*)realloc(bus->cap_npu, new_cap * sizeof(*grown_npu));
    if (grown_npu) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_npu[i] = 0;
        bus->cap_npu = grown_npu;
    }
    uint8_t* grown_gpu = (uint8_t*)realloc(bus->cap_gpu, new_cap * sizeof(*grown_gpu));
    if (grown_gpu) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_gpu[i] = 0;
        bus->cap_gpu = grown_gpu;
    }
    uint32_t* grown_ram = (uint32_t*)realloc(bus->cap_free_ram_mb, new_cap * sizeof(*grown_ram));
    if (grown_ram) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_ram[i] = 0;
        bus->cap_free_ram_mb = grown_ram;
    }
    uint16_t* grown_load = (uint16_t*)realloc(bus->cap_load_pct, new_cap * sizeof(*grown_load));
    if (grown_load) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_load[i] = 0;
        bus->cap_load_pct = grown_load;
    }
    uint8_t* grown_present = (uint8_t*)realloc(bus->cap_present, new_cap * sizeof(*grown_present));
    if (grown_present) {
        for (size_t i = bus->last_seen_capacity; i < new_cap; i++) grown_present[i] = 0;
        bus->cap_present = grown_present;
    }
    bus->last_seen_capacity = new_cap;
}

static void qihse_bus_touch_node(qihse_cluster_bus_t* bus, uint16_t index) {
    if (index == QIHSE_CLUSTER_NODE_NONE) return;
    qihse_bus_ensure_last_seen(bus, (size_t)index + 1u);
    if (!bus->first_seen_ms) return;
    uint64_t now = qihse_bus_now_ms();
    if (bus->obs_healthy_ms && __atomic_load_n(&bus->running, __ATOMIC_ACQUIRE))
        bus->obs_healthy_ms[index] = now; /* fresh direct contact = healthy evidence */
    if (bus->first_seen_ms[index] == 0) bus->first_seen_ms[index] = now; /* peer uptime epoch */
    bus->last_seen_ms[index] = now;
    /* Fresh liveness evidence overrides a stale failure verdict: without
     * this a peer that blips stays unhealthy forever (nothing emits
     * NODE_UPDATE on recovery). */
    qihse_cluster_node_t node;
    if (qihse_cluster_topology_get_node(bus->topology, index, &node) && !node.healthy) {
        qihse_cluster_topology_set_node_health(bus->topology, index, true);
    }
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

/* ---- Veiled framing (Layer 1: transport obfuscation) --------------------- */

/* CSPRNG fill with a weak clock/pointer fallback so framing still works in
 * the (never expected) case of a CSPRNG failure — obfuscation quality drops
 * but the bus keeps flowing. */
static void qihse_bus_random_bytes(uint8_t* out, size_t len) {
    if (!out || len == 0) return;
    if (RAND_bytes(out, (int)len) == 1) return;
    uint64_t mix = qihse_bus_now_ms() ^ (uint64_t)(uintptr_t)out;
    for (size_t i = 0; i < len; i++) {
        mix = mix * 6364136223846793005ULL + 1442695040888963407ULL;
        out[i] = (uint8_t)(mix >> 33);
    }
}

/* XOR `len` bytes at `data` with the veil keystream: HMAC-SHA384(veil_key,
 * nonce || BE32 block counter) per 48-byte block, truncated to length. */
static void qihse_bus_veil_xor(const qihse_cluster_bus_t* bus,
                               const uint8_t* nonce, uint8_t* data, size_t len) {
    uint8_t block[EVP_MAX_MD_SIZE];
    uint8_t input[QIHSE_BUS_VEIL_NONCE_LEN + 4u];
    unsigned int md_len = 0;
    memcpy(input, nonce, QIHSE_BUS_VEIL_NONCE_LEN);
    size_t done = 0;
    for (uint32_t counter = 0; done < len; counter++) {
        input[QIHSE_BUS_VEIL_NONCE_LEN + 0u] = (uint8_t)(counter >> 24);
        input[QIHSE_BUS_VEIL_NONCE_LEN + 1u] = (uint8_t)(counter >> 16);
        input[QIHSE_BUS_VEIL_NONCE_LEN + 2u] = (uint8_t)(counter >> 8);
        input[QIHSE_BUS_VEIL_NONCE_LEN + 3u] = (uint8_t)counter;
        if (!HMAC(EVP_sha384(), bus->veil_key, (int)bus->veil_key_len,
                  input, sizeof(input), block, &md_len) || md_len == 0) {
            return; /* keystream unavailable: frame arrives garbled and is dropped */
        }
        size_t n = len - done;
        if (n > (size_t)md_len) n = (size_t)md_len;
        for (size_t i = 0; i < n; i++) data[done + i] ^= block[i];
        done += n;
    }
}

/* Wrap a plain bus frame as [nonce 8B][pad_len u8][padding][xored_frame].
 * Returns the wrapped length, or 0 when the buffer is too small. */
static size_t qihse_bus_veil_encode(const qihse_cluster_bus_t* bus,
                                    const uint8_t* frame, size_t frame_len,
                                    uint8_t* out, size_t cap) {
    if (!bus || !bus->veil_key || !frame || frame_len == 0 || !out) return 0;
    uint8_t pad_roll = 0;
    qihse_bus_random_bytes(&pad_roll, 1u);
    size_t pad_len = (size_t)(pad_roll % QIHSE_BUS_VEIL_PAD_MAX) + 1u; /* 1..64 */
    size_t total = QIHSE_BUS_VEIL_HEADER_LEN + pad_len + frame_len;
    if (total > cap) return 0;
    qihse_bus_random_bytes(out, QIHSE_BUS_VEIL_NONCE_LEN);                 /* nonce */
    out[QIHSE_BUS_VEIL_NONCE_LEN] = (uint8_t)pad_len;
    qihse_bus_random_bytes(out + QIHSE_BUS_VEIL_HEADER_LEN, pad_len);      /* padding */
    uint8_t* xored = out + QIHSE_BUS_VEIL_HEADER_LEN + pad_len;
    memcpy(xored, frame, frame_len);
    qihse_bus_veil_xor(bus, out, xored, frame_len);
    return total;
}

/* Unwrap a veiled datagram into `out`. Returns the inner frame length,
 * or 0 for malformed/short datagrams (dropped by the caller). */
static size_t qihse_bus_veil_decode(const qihse_cluster_bus_t* bus,
                                    const uint8_t* data, size_t len,
                                    uint8_t* out, size_t cap) {
    if (!bus || !bus->veil_key || !data || !out ||
        len < QIHSE_BUS_VEIL_HEADER_LEN + 1u) return 0;
    size_t pad_len = data[QIHSE_BUS_VEIL_NONCE_LEN];
    if (pad_len < 1u || pad_len > QIHSE_BUS_VEIL_PAD_MAX) return 0;
    if (len < QIHSE_BUS_VEIL_HEADER_LEN + pad_len + 1u) return 0;
    size_t frame_len = len - QIHSE_BUS_VEIL_HEADER_LEN - pad_len;
    if (frame_len > cap) return 0;
    memcpy(out, data + QIHSE_BUS_VEIL_HEADER_LEN + pad_len, frame_len);
    qihse_bus_veil_xor(bus, data, out, frame_len);
    return frame_len;
}

static bool qihse_bus_send_datagram(qihse_cluster_bus_t* bus,
                                    const char* host, uint16_t port,
                                    const uint8_t* data, size_t len) {
    if (!bus || bus->sock_fd < 0 || !host || !data || len == 0) return false;
    const uint8_t* wire = data;
    size_t wire_len = len;
    uint8_t veiled[QIHSE_BUS_MAX_DATAGRAM + QIHSE_BUS_VEIL_OVERHEAD];
    if (bus->veil_key) {
        wire_len = qihse_bus_veil_encode(bus, data, len, veiled, sizeof(veiled));
        if (wire_len == 0) return false;
        wire = veiled;
    }
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
    ssize_t sent = sendto(bus->sock_fd, (const char*)wire, (int)wire_len, 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    if (sent < 0 || (size_t)sent != wire_len) return false;
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

/* Resolve a heartbeat peer by the node id carried in its payload — header
 * indexes are per-sender table positions and mean nothing to a receiver that
 * learned membership dynamically (index spaces differ per node). */
static bool qihse_bus_resolve_heartbeat_peer(qihse_cluster_bus_t* bus,
                                             uint16_t sender_index,
                                             const uint8_t* payload, size_t payload_len,
                                             uint16_t* out_peer_index) {
    if (payload_len >= QIHSE_CLUSTER_NODE_ID_LEN + 1u) {
        char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
        memcpy(id, payload, QIHSE_CLUSTER_NODE_ID_LEN);
        id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
        if (id[0] != '\0' && qihse_cluster_topology_find_node(bus->topology, id, out_peer_index)) {
            return true;
        }
    }
    /* Fallback for legacy frames without an id payload. */
    *out_peer_index = sender_index;
    return true;
}

static void qihse_bus_handle_ping(qihse_cluster_bus_t* bus, uint16_t sender_index,
                                  const uint8_t* payload, size_t payload_len) {
    uint16_t peer_index = sender_index;
    if (!qihse_bus_resolve_heartbeat_peer(bus, sender_index, payload, payload_len, &peer_index)) return;
    qihse_cluster_node_t local;
    if (qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) {
        uint8_t pong_payload[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
        memcpy(pong_payload, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        qihse_cluster_node_t peer;
        if (qihse_cluster_topology_get_node(bus->topology, peer_index, &peer)) {
            uint8_t datagram[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(pong_payload)];
            qihse_bus_build_header(datagram, QIHSE_BUS_MSG_PONG, bus->local_node_index, sizeof(pong_payload));
            memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, pong_payload, sizeof(pong_payload));
            qihse_bus_send_datagram(bus, peer.host, peer.bus_port, datagram, sizeof(datagram));
        }
    }
    qihse_bus_touch_node(bus, peer_index);
}

static void qihse_bus_handle_pong(qihse_cluster_bus_t* bus, uint16_t sender_index,
                                  const uint8_t* payload, size_t payload_len) {
    uint16_t peer_index = sender_index;
    qihse_bus_resolve_heartbeat_peer(bus, sender_index, payload, payload_len, &peer_index);
    qihse_bus_touch_node(bus, peer_index);
    __atomic_add_fetch(&bus->stats.pongs_received, 1u, __ATOMIC_RELAXED);
}

/* Send one MEET datagram describing `node` to a bus address. */
static void qihse_bus_send_meet_node(qihse_cluster_bus_t* bus, const qihse_cluster_node_t* node,
                                     const char* host, uint16_t port) {
    uint8_t payload[QIHSE_CLUSTER_BUS_MAX_PAYLOAD];
    size_t len = qihse_bus_serialise_node(node, payload, sizeof(payload));
    if (len == 0) return;
    uint8_t datagram[QIHSE_BUS_MAX_DATAGRAM];
    qihse_bus_build_header(datagram, QIHSE_BUS_MSG_MEET, bus->local_node_index, (uint32_t)len);
    memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, payload, len);
    qihse_bus_send_datagram(bus, host, port, datagram, QIHSE_CLUSTER_BUS_HEADER_SIZE + len);
}

/* Re-announce the slot ranges owned by the LOCAL node as SLOT_UPDATE frames
 * (coalesced into consecutive runs) — sent to one destination. */
static void qihse_bus_announce_local_slots(qihse_cluster_bus_t* bus, const char* host, uint16_t port) {
    qihse_cluster_node_t local;
    if (!qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) return;
    uint16_t run_start = 0;
    bool in_run = false;
    uint8_t datagram[QIHSE_BUS_MAX_DATAGRAM];
    for (uint32_t slot = 0; slot <= QIHSE_CLUSTER_SLOT_COUNT; slot++) {
        uint16_t owner = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_slot_state_t state = QIHSE_CLUSTER_SLOT_STABLE;
        uint16_t peer = QIHSE_CLUSTER_NODE_NONE;
        if (slot < QIHSE_CLUSTER_SLOT_COUNT) {
            qihse_cluster_topology_get_slot(bus->topology, (uint16_t)slot, &owner, &state, &peer);
        }
        bool owned = owner == bus->local_node_index;
        if (owned && !in_run) {
            run_start = (uint16_t)slot;
            in_run = true;
        } else if (!owned && in_run) {
            in_run = false;
            qihse_cluster_bus_slot_update_t upd;
            memset(&upd, 0, sizeof(upd));
            upd.start = run_start;
            upd.end = (uint16_t)(slot - 1u);
            upd.owner_index = bus->local_node_index;
            memcpy(upd.owner_id, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
            qihse_bus_build_header(datagram, QIHSE_BUS_MSG_SLOT_UPDATE, bus->local_node_index,
                                   (uint32_t)sizeof(upd));
            memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, &upd, sizeof(upd));
            qihse_bus_send_datagram(bus, host, port, datagram,
                                    QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(upd));
        }
    }
}

/* Re-announce our FULL KNOWN slot map (every owner, coalesced runs) to a
 * newcomer: membership gossip alone carries no slot map, so a joiner that
 * learned the cluster transitively would otherwise never learn who owns
 * what. Receivers resolve owners by node id (MEETs are delivered first). */
static void qihse_bus_announce_known_slots(qihse_cluster_bus_t* bus, const char* host, uint16_t port) {
    uint16_t* owners = malloc(QIHSE_CLUSTER_SLOT_COUNT * sizeof(uint16_t));
    if (!owners) return;
    if (qihse_cluster_topology_slot_owner_snapshot(bus->topology, owners,
                                                   QIHSE_CLUSTER_SLOT_COUNT) != QIHSE_CLUSTER_SLOT_COUNT) {
        free(owners);
        return;
    }
    uint8_t datagram[QIHSE_BUS_MAX_DATAGRAM];
    uint32_t slot = 0;
    while (slot < QIHSE_CLUSTER_SLOT_COUNT) {
        uint16_t owner = owners[slot];
        uint32_t end = slot;
        while (end + 1u < QIHSE_CLUSTER_SLOT_COUNT && owners[end + 1u] == owner) end++;
        if (owner != QIHSE_CLUSTER_NODE_NONE) {
            qihse_cluster_node_t owner_node;
            if (qihse_cluster_topology_get_node(bus->topology, owner, &owner_node)) {
                qihse_cluster_bus_slot_update_t upd;
                memset(&upd, 0, sizeof(upd));
                upd.start = (uint16_t)slot;
                upd.end = (uint16_t)end;
                upd.owner_index = owner;
                memcpy(upd.owner_id, owner_node.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
                qihse_bus_build_header(datagram, QIHSE_BUS_MSG_SLOT_UPDATE, bus->local_node_index,
                                       (uint32_t)sizeof(upd));
                memcpy(datagram + QIHSE_CLUSTER_BUS_HEADER_SIZE, &upd, sizeof(upd));
                qihse_bus_send_datagram(bus, host, port, datagram,
                                        QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(upd));
            }
        }
        slot = end + 1u;
    }
    free(owners);
}

/* MEET handling with dynamic discovery:
 *   1. upsert the newcomer (idempotent by node id),
 *   2. if the newcomer is NEW to us, introduce OURSELVES back to it (so a
 *      joiner that only knows one seed learns the whole membership),
 *   3. and gossip the newcomer to every other peer we know (they in turn
 *      skip forwarding because the node is already known to them, so the
 *      flood terminates in one hop). */
static void qihse_bus_handle_meet(qihse_cluster_bus_t* bus, const uint8_t* payload, size_t payload_len) {
    qihse_cluster_node_t node;
    if (!qihse_bus_deserialise_node(payload, payload_len, &node)) return;
    uint16_t known_idx;
    bool known = qihse_cluster_topology_find_node(bus->topology, node.id, &known_idx);
    uint16_t idx;
    if (!qihse_cluster_topology_upsert_node(bus->topology, &node, &idx)) return;
    qihse_bus_touch_node(bus, idx);
    if (known) {
        /* UDP is lossy and joiners repeat their MEETs: re-announce the full
         * known slot map on every contact so knowledge self-heals. */
        qihse_bus_announce_known_slots(bus, node.host, node.bus_port);
        return;
    }

    qihse_cluster_node_t local;
    if (qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) {
        /* Introduce ourselves to the newcomer, then re-announce the slot
         * ranges WE own so the joiner can route immediately (membership
         * gossip alone carries no slot map). */
        qihse_bus_send_meet_node(bus, &local, node.host, node.bus_port);
        qihse_bus_announce_known_slots(bus, node.host, node.bus_port);
        qihse_bus_announce_local_slots(bus, node.host, node.bus_port);
        /* Gossip the newcomer to our other peers. */
        qihse_cluster_node_t peers[QIHSE_CLUSTER_MAX_NODES];
        size_t count = qihse_cluster_topology_nodes(bus->topology, peers, QIHSE_CLUSTER_MAX_NODES);
        for (size_t i = 0; i < count; i++) {
            if (memcmp(peers[i].id, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u) == 0 ||
                memcmp(peers[i].id, node.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u) == 0) continue;
            if (peers[i].bus_port == 0 || peers[i].host[0] == '\0') continue;
            qihse_bus_send_meet_node(bus, &node, peers[i].host, peers[i].bus_port);
        }
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

/* NODE_OBS frame: payload = {observer_id[41], about_id[41], healthy u16}.
 * Records third-party health evidence so failover only fires on failures the
 * whole bus agrees on — the fix for asymmetric-link false failovers. */
static void qihse_bus_handle_node_obs(qihse_cluster_bus_t* bus,
                                      const uint8_t* payload, size_t payload_len) {
    if (payload_len < QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_CLUSTER_NODE_ID_LEN + 1u + 2u) return;
    const uint8_t* p = payload;
    char about_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint16_t healthy;
    p += QIHSE_CLUSTER_NODE_ID_LEN + 1u; /* observer id (unused for the verdict) */
    memcpy(about_id, p, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    memcpy(&healthy, p, 2u);
    if (about_id[0] == '\0' || healthy == 0) return; /* only healthy evidence is recorded */
    uint16_t idx;
    if (!qihse_cluster_topology_find_node(bus->topology, about_id, &idx)) return;
    if (!bus->obs_healthy_ms) return;
    bus->obs_healthy_ms[idx] = qihse_bus_now_ms();
    qihse_bus_touch_node(bus, idx);
}

uint64_t qihse_cluster_bus_last_observed_healthy(const qihse_cluster_bus_t* bus,
                                                 uint16_t node_index) {
    if (!bus || !bus->obs_healthy_ms || node_index >= bus->last_seen_capacity) return 0;
    return bus->obs_healthy_ms[node_index];
}

/* NODE_CAP frame: payload = {node_id[41], isa_tier u8, npu u8, gpu u8,
 * free_ram_mb u32, load_pct u16} (50 bytes, field-packed).  Stores the
 * sender's capability profile in the per-bus table so the brain can do
 * capability-aware placement. */
static void qihse_bus_handle_node_cap(qihse_cluster_bus_t* bus,
                                      const uint8_t* payload, size_t payload_len) {
    if (payload_len < QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE) return;
    const uint8_t* p = payload;
    char node_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(node_id, p, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    node_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    uint8_t isa = *p; p += 1u;
    uint8_t npu = *p; p += 1u;
    uint8_t gpu = *p; p += 1u;
    uint32_t free_ram_mb; memcpy(&free_ram_mb, p, 4u); p += 4u;
    uint16_t load_pct; memcpy(&load_pct, p, 2u);
    if (node_id[0] == '\0') return;
    uint16_t idx;
    if (!qihse_cluster_topology_find_node(bus->topology, node_id, &idx)) return;
    qihse_bus_ensure_last_seen(bus, (size_t)idx + 1u);
    if (!bus->cap_present || idx >= bus->last_seen_capacity) return;
    bus->cap_isa[idx] = isa;
    bus->cap_npu[idx] = npu;
    bus->cap_gpu[idx] = gpu;
    bus->cap_free_ram_mb[idx] = free_ram_mb;
    bus->cap_load_pct[idx] = load_pct;
    bus->cap_present[idx] = 1u;
}

bool qihse_cluster_bus_node_caps(const qihse_cluster_bus_t* bus, uint16_t node_index,
                                 uint8_t* isa, uint8_t* npu, uint8_t* gpu,
                                 uint32_t* free_ram, uint16_t* load) {
    if (!bus || node_index == QIHSE_CLUSTER_NODE_NONE ||
        node_index >= bus->last_seen_capacity || !bus->cap_present ||
        bus->cap_present[node_index] == 0u) return false;
    if (isa) *isa = bus->cap_isa[node_index];
    if (npu) *npu = bus->cap_npu[node_index];
    if (gpu) *gpu = bus->cap_gpu[node_index];
    if (free_ram) *free_ram = bus->cap_free_ram_mb[node_index];
    if (load) *load = bus->cap_load_pct[node_index];
    return true;
}

static void qihse_bus_process_datagram(qihse_cluster_bus_t* bus,
                                       const uint8_t* data, size_t len) {
    uint8_t plain[QIHSE_BUS_MAX_DATAGRAM];
    if (bus->veil_key) {
        /* Veiled receive path: peel nonce/padding, de-XOR, then parse the
         * inner frame. Malformed wrappers are dropped silently (UDP). */
        size_t inner_len = qihse_bus_veil_decode(bus, data, len, plain, sizeof(plain));
        if (inner_len == 0) return;
        data = plain;
        len = inner_len;
    }
    uint32_t magic, type, sender32, payload_len;
    if (!qihse_bus_parse_header(data, len, &magic, &type, &sender32, &payload_len)) return;
    uint16_t sender = (uint16_t)sender32;
    const uint8_t* payload = data + QIHSE_CLUSTER_BUS_HEADER_SIZE;
    __atomic_add_fetch(&bus->stats.received, 1u, __ATOMIC_RELAXED);
    switch ((qihse_cluster_bus_msg_type_t)type) {
        case QIHSE_BUS_MSG_PING:        qihse_bus_handle_ping(bus, sender, payload, payload_len); break;
        case QIHSE_BUS_MSG_PONG:        qihse_bus_handle_pong(bus, sender, payload, payload_len); break;
        case QIHSE_BUS_MSG_MEET:        qihse_bus_handle_meet(bus, payload, payload_len); break;
        case QIHSE_BUS_MSG_FAIL:        qihse_bus_handle_fail(bus, sender, payload, payload_len); break;
        case QIHSE_BUS_MSG_SLOT_UPDATE: qihse_bus_handle_slot_update(bus, payload, payload_len); break;
        case QIHSE_BUS_MSG_NODE_UPDATE: qihse_bus_handle_node_update(bus, payload, payload_len); break;
        case QIHSE_BUS_MSG_NODE_OBS:    qihse_bus_handle_node_obs(bus, payload, payload_len); break;
        case QIHSE_BUS_MSG_NODE_CAP:    qihse_bus_handle_node_cap(bus, payload, payload_len); break;
        default: break;
    }
}

/* ---- Local capability probes for NODE_CAP emission ---------------------- */

/* ISA tier from /proc/cpuinfo flags, probed once (single bus thread calls
 * this at heartbeat rate): 4=AVX-512+AMX, 3=AVX-512, 2=AVX2, 1=AVX, 0=generic. */
static uint8_t qihse_bus_local_isa_tier(void) {
#ifndef _WIN32
    static uint8_t tier_cache = 0;
    static bool tier_probed = false;
    if (tier_probed) return tier_cache;
    tier_probed = true;
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    char line[2048];
    bool avx = false, avx2 = false, avx512 = false, amx = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "flags", 5) != 0) continue;
        avx = strstr(line, "avx") != NULL;
        avx2 = strstr(line, "avx2") != NULL;
        avx512 = strstr(line, "avx512f") != NULL;
        amx = strstr(line, "amx_bf16") != NULL || strstr(line, "amx_int8") != NULL;
        break; /* first flags line is representative of the package */
    }
    fclose(f);
    tier_cache = (uint8_t)((avx512 && amx) ? 4 : avx512 ? 3 : avx2 ? 2 : avx ? 1 : 0);
    return tier_cache;
#else
    return 0;
#endif
}

/* Accelerator presence: NPU via the kernel accel subsystem, GPU via DRM
 * render nodes or the NVIDIA control device (CUDA). */
static void qihse_bus_local_accelerators(uint8_t* npu, uint8_t* gpu) {
    *npu = 0;
    *gpu = 0;
#ifndef _WIN32
    if (access("/dev/accel", F_OK) == 0) *npu = 1;
    if (access("/dev/dri", F_OK) == 0 || access("/dev/nvidiactl", F_OK) == 0) *gpu = 1;
#endif
}

/* Free RAM and 1-minute load, read fresh per heartbeat (cheap stdio reads
 * at 1 Hz).  load_pct = loadavg * 100, clamped to 65535. */
static void qihse_bus_local_memory_load(uint32_t* free_ram_mb, uint16_t* load_pct) {
    *free_ram_mb = 0;
    *load_pct = 0;
#ifndef _WIN32
    FILE* f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        unsigned long available_kb = 0, free_kb = 0;
        while (fgets(line, sizeof(line), f)) {
            if (available_kb == 0 && sscanf(line, "MemAvailable: %lu kB", &available_kb) == 1) continue;
            if (free_kb == 0 && sscanf(line, "MemFree: %lu kB", &free_kb) == 1) continue;
        }
        fclose(f);
        unsigned long kb = available_kb ? available_kb : free_kb;
        *free_ram_mb = (uint32_t)(kb / 1024u);
    }
    f = fopen("/proc/loadavg", "r");
    if (f) {
        float load1 = 0.0f;
        if (fscanf(f, "%f", &load1) == 1) {
            double pct = (double)load1 * 100.0;
            if (pct < 0.0) pct = 0.0;
            if (pct > 65535.0) pct = 65535.0;
            *load_pct = (uint16_t)(pct + 0.5);
        }
        fclose(f);
    }
#endif
}

static void qihse_bus_send_heartbeat(qihse_cluster_bus_t* bus) {
    qihse_cluster_node_t local;
    if (!qihse_cluster_topology_get_node(bus->topology, bus->local_node_index, &local)) return;
    uint8_t payload[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    memcpy(payload, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_PING, payload, sizeof(payload));
    __atomic_add_fetch(&bus->stats.pings_sent, 1u, __ATOMIC_RELAXED);

    /* Health-evidence gossip: tell every peer which nodes WE see healthy.
     * A peer marked failed only locally stays failed; one the rest of the
     * cluster still sees alive gets its failure deferred (asymmetry guard). */
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(bus->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    for (size_t i = 0; i < count; i++) {
        if (!nodes[i].healthy || nodes[i].index == bus->local_node_index) continue;
        uint8_t obs[QIHSE_CLUSTER_NODE_ID_LEN + 1u + QIHSE_CLUSTER_NODE_ID_LEN + 1u + 2u];
        memcpy(obs, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        memcpy(obs + QIHSE_CLUSTER_NODE_ID_LEN + 1u, nodes[i].id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
        uint16_t h = 1;
        memcpy(obs + 2u * (QIHSE_CLUSTER_NODE_ID_LEN + 1u), &h, 2u);
        uint8_t dg[QIHSE_CLUSTER_BUS_HEADER_SIZE + sizeof(obs)];
        qihse_bus_build_header(dg, QIHSE_BUS_MSG_NODE_OBS, bus->local_node_index, (uint32_t)sizeof(obs));
        memcpy(dg + QIHSE_CLUSTER_BUS_HEADER_SIZE, obs, sizeof(obs));
        qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_NODE_OBS, obs, sizeof(obs));
    }

    /* Capability profile: ONE NODE_CAP frame describing the LOCAL node,
     * sent alongside every heartbeat so peers can make capability-aware
     * placement decisions. */
    qihse_cluster_bus_node_cap_t cap;
    memset(&cap, 0, sizeof(cap));
    memcpy(cap.node_id, local.id, QIHSE_CLUSTER_NODE_ID_LEN + 1u);
    cap.isa_tier = qihse_bus_local_isa_tier();
    qihse_bus_local_accelerators(&cap.npu, &cap.gpu);
    qihse_bus_local_memory_load(&cap.free_ram_mb, &cap.load_pct);
    uint8_t capbuf[QIHSE_CLUSTER_BUS_NODE_CAP_PAYLOAD_SIZE];
    uint8_t* p = capbuf;
    memcpy(p, cap.node_id, QIHSE_CLUSTER_NODE_ID_LEN + 1u); p += QIHSE_CLUSTER_NODE_ID_LEN + 1u;
    memcpy(p, &cap.isa_tier, 1u); p += 1u;
    memcpy(p, &cap.npu, 1u); p += 1u;
    memcpy(p, &cap.gpu, 1u); p += 1u;
    memcpy(p, &cap.free_ram_mb, 4u); p += 4u;
    memcpy(p, &cap.load_pct, 2u);
    qihse_bus_send_to_all_peers(bus, QIHSE_BUS_MSG_NODE_CAP, capbuf, sizeof(capbuf));
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
    if (config->veil_key && *config->veil_key) {
        /* Own a private copy: the config may be stack-scoped and the key is
         * sensitive enough to outlive it inside the bus only. */
        bus->veil_key_len = strlen(config->veil_key);
        bus->veil_key = (char*)malloc(bus->veil_key_len + 1u);
        if (!bus->veil_key) {
            pthread_mutex_destroy(&bus->lock);
            free(bus);
            return NULL;
        }
        memcpy(bus->veil_key, config->veil_key, bus->veil_key_len + 1u);
    }
    if (pthread_mutex_init(&bus->lock, NULL) != 0) {
        free(bus->veil_key);
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
    free(bus->first_seen_ms);
    free(bus->obs_healthy_ms);
    free(bus->cap_isa);
    free(bus->cap_npu);
    free(bus->cap_gpu);
    free(bus->cap_free_ram_mb);
    free(bus->cap_load_pct);
    free(bus->cap_present);
    free(bus->veil_key);
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

bool qihse_cluster_bus_peer_first_seen(const qihse_cluster_bus_t* bus,
                                       uint16_t node_index, uint64_t* out_first_seen_ms) {
    if (!bus || !out_first_seen_ms || node_index == QIHSE_CLUSTER_NODE_NONE ||
        node_index >= bus->last_seen_capacity || !bus->first_seen_ms) return false;
    *out_first_seen_ms = bus->first_seen_ms[node_index];
    return true;
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
    /* Sized for a fully veiled maximum frame: [nonce][pad_len][64B pad][frame]. */
    uint8_t buffer[QIHSE_BUS_MAX_DATAGRAM + QIHSE_BUS_VEIL_OVERHEAD];
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
            /* re-emit while it REMAINS unhealthy: a gated/deferred failover
             * must re-evaluate once confirming evidence (or the lack of it)
             * resolves. Promote() is idempotent. */
            if (nodes[i].healthy || bus->on_fail) {
                if (nodes[i].healthy) {
                    qihse_cluster_topology_set_node_health(bus->topology, idx, false);
                    __atomic_add_fetch(&bus->stats.nodes_marked_unhealthy, 1u, __ATOMIC_RELAXED);
                }
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
