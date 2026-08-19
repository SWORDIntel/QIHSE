#include "qihse_cluster_slot.h"
#include "qihse_platform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct qihse_cluster_topology {
    uint16_t slot_to_node[QIHSE_CLUSTER_SLOT_COUNT] __attribute__((aligned(64)));
    uint16_t slot_peer[QIHSE_CLUSTER_SLOT_COUNT] __attribute__((aligned(64)));
    uint8_t slot_state[QIHSE_CLUSTER_SLOT_COUNT] __attribute__((aligned(64)));
    uint64_t current_epoch __attribute__((aligned(64)));
    uint16_t local_node;
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t node_count;
    pthread_mutex_t metadata_lock;
};

static uint64_t qihse_cluster_next_epoch(qihse_cluster_topology_t* topology) {
    return __atomic_add_fetch(&topology->current_epoch, 1u, __ATOMIC_ACQ_REL);
}

static bool qihse_cluster_valid_slot_range(uint16_t start, uint16_t end) {
    return start <= end && end < QIHSE_CLUSTER_SLOT_COUNT;
}

static bool qihse_cluster_valid_node_locked(const qihse_cluster_topology_t* topology, uint16_t index) {
    return index < topology->node_count;
}

static bool qihse_cluster_node_id_valid(const char* id) {
    if (!id || strnlen(id, QIHSE_CLUSTER_NODE_ID_LEN + 1u) != QIHSE_CLUSTER_NODE_ID_LEN) return false;
    for (size_t i = 0; i < QIHSE_CLUSTER_NODE_ID_LEN; i++) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

qihse_cluster_topology_t* qihse_cluster_topology_create(void) {
    qihse_cluster_topology_t* topology = NULL;
#ifdef _WIN32
    topology = (qihse_cluster_topology_t*)_aligned_malloc(sizeof(*topology), 64u);
    if (!topology) return NULL;
#else
    if (posix_memalign((void**)&topology, 64u, sizeof(*topology)) != 0) return NULL;
#endif
    memset(topology, 0, sizeof(*topology));
    for (size_t i = 0; i < QIHSE_CLUSTER_SLOT_COUNT; i++) {
        topology->slot_to_node[i] = QIHSE_CLUSTER_NODE_NONE;
        topology->slot_peer[i] = QIHSE_CLUSTER_NODE_NONE;
        topology->slot_state[i] = QIHSE_CLUSTER_SLOT_STABLE;
    }
    topology->local_node = QIHSE_CLUSTER_NODE_NONE;
    topology->current_epoch = 1u;
    if (pthread_mutex_init(&topology->metadata_lock, NULL) != 0) {
#ifdef _WIN32
        _aligned_free(topology);
#else
        free(topology);
#endif
        return NULL;
    }
    return topology;
}

void qihse_cluster_topology_destroy(qihse_cluster_topology_t* topology) {
    if (!topology) return;
    pthread_mutex_destroy(&topology->metadata_lock);
#ifdef _WIN32
    _aligned_free(topology);
#else
    free(topology);
#endif
}

bool qihse_cluster_topology_upsert_node(qihse_cluster_topology_t* topology, const qihse_cluster_node_t* node, uint16_t* out_index) {
    if (!topology || !node || !qihse_cluster_node_id_valid(node->id) || node->host[0] == '\0' || node->port == 0) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&topology->metadata_lock);
    size_t index = topology->node_count;
    for (size_t i = 0; i < topology->node_count; i++) {
        if (memcmp(topology->nodes[i].id, node->id, QIHSE_CLUSTER_NODE_ID_LEN + 1u) == 0) {
            index = i;
            break;
        }
    }
    if (index == topology->node_count && topology->node_count >= QIHSE_CLUSTER_MAX_NODES) {
        pthread_mutex_unlock(&topology->metadata_lock);
        errno = ENOSPC;
        return false;
    }
    qihse_cluster_node_t copy = *node;
    copy.index = (uint16_t)index;
    copy.id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
    copy.host[QIHSE_CLUSTER_HOST_LEN] = '\0';
    if (copy.bus_port == 0 && copy.port <= UINT16_MAX - 10000u) copy.bus_port = (uint16_t)(copy.port + 10000u);
    if (copy.role == QIHSE_CLUSTER_NODE_PRIMARY) copy.primary_index = QIHSE_CLUSTER_NODE_NONE;
    copy.config_epoch = qihse_cluster_next_epoch(topology);
    topology->nodes[index] = copy;
    if (index == topology->node_count) topology->node_count++;
    pthread_mutex_unlock(&topology->metadata_lock);
    if (out_index) *out_index = (uint16_t)index;
    return true;
}

bool qihse_cluster_topology_get_node(const qihse_cluster_topology_t* topology, uint16_t index, qihse_cluster_node_t* out_node) {
    if (!topology || !out_node) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock((pthread_mutex_t*)&topology->metadata_lock);
    bool found = qihse_cluster_valid_node_locked(topology, index);
    if (found) *out_node = topology->nodes[index];
    pthread_mutex_unlock((pthread_mutex_t*)&topology->metadata_lock);
    if (!found) errno = ENOENT;
    return found;
}

bool qihse_cluster_topology_find_node(const qihse_cluster_topology_t* topology, const char* node_id, uint16_t* out_index) {
    if (!topology || !node_id || !out_index) {
        errno = EINVAL;
        return false;
    }
    bool found = false;
    pthread_mutex_lock((pthread_mutex_t*)&topology->metadata_lock);
    for (size_t i = 0; i < topology->node_count; i++) {
        if (strcmp(topology->nodes[i].id, node_id) == 0) {
            *out_index = (uint16_t)i;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock((pthread_mutex_t*)&topology->metadata_lock);
    if (!found) errno = ENOENT;
    return found;
}

size_t qihse_cluster_topology_nodes(const qihse_cluster_topology_t* topology, qihse_cluster_node_t* out_nodes, size_t capacity) {
    if (!topology) return 0;
    pthread_mutex_lock((pthread_mutex_t*)&topology->metadata_lock);
    size_t count = topology->node_count;
    size_t copied = count < capacity ? count : capacity;
    if (out_nodes && copied > 0) memcpy(out_nodes, topology->nodes, copied * sizeof(*out_nodes));
    pthread_mutex_unlock((pthread_mutex_t*)&topology->metadata_lock);
    return count;
}

bool qihse_cluster_topology_set_local_node(qihse_cluster_topology_t* topology, uint16_t index) {
    if (!topology) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&topology->metadata_lock);
    if (!qihse_cluster_valid_node_locked(topology, index)) {
        pthread_mutex_unlock(&topology->metadata_lock);
        errno = ENOENT;
        return false;
    }
    __atomic_store_n(&topology->local_node, index, __ATOMIC_RELEASE);
    qihse_cluster_next_epoch(topology);
    pthread_mutex_unlock(&topology->metadata_lock);
    return true;
}

uint16_t qihse_cluster_topology_local_node(const qihse_cluster_topology_t* topology) {
    return topology ? __atomic_load_n(&topology->local_node, __ATOMIC_ACQUIRE) : QIHSE_CLUSTER_NODE_NONE;
}

bool qihse_cluster_topology_set_node_health(qihse_cluster_topology_t* topology, uint16_t index, bool healthy) {
    if (!topology) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&topology->metadata_lock);
    if (!qihse_cluster_valid_node_locked(topology, index)) {
        pthread_mutex_unlock(&topology->metadata_lock);
        errno = ENOENT;
        return false;
    }
    topology->nodes[index].healthy = healthy;
    topology->nodes[index].config_epoch = qihse_cluster_next_epoch(topology);
    pthread_mutex_unlock(&topology->metadata_lock);
    return true;
}

bool qihse_cluster_topology_assign_range(qihse_cluster_topology_t* topology, uint16_t start, uint16_t end, uint16_t owner_index) {
    if (!topology || !qihse_cluster_valid_slot_range(start, end)) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&topology->metadata_lock);
    if (!qihse_cluster_valid_node_locked(topology, owner_index)) {
        pthread_mutex_unlock(&topology->metadata_lock);
        errno = ENOENT;
        return false;
    }
    for (uint32_t slot = start; slot <= end; slot++) {
        __atomic_store_n(&topology->slot_peer[slot], QIHSE_CLUSTER_NODE_NONE, __ATOMIC_RELAXED);
        __atomic_store_n(&topology->slot_state[slot], QIHSE_CLUSTER_SLOT_STABLE, __ATOMIC_RELAXED);
        __atomic_store_n(&topology->slot_to_node[slot], owner_index, __ATOMIC_RELEASE);
    }
    topology->nodes[owner_index].config_epoch = qihse_cluster_next_epoch(topology);
    pthread_mutex_unlock(&topology->metadata_lock);
    return true;
}

bool qihse_cluster_topology_unassign_range(qihse_cluster_topology_t* topology, uint16_t start, uint16_t end) {
    if (!topology || !qihse_cluster_valid_slot_range(start, end)) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&topology->metadata_lock);
    for (uint32_t slot = start; slot <= end; slot++) {
        __atomic_store_n(&topology->slot_peer[slot], QIHSE_CLUSTER_NODE_NONE, __ATOMIC_RELAXED);
        __atomic_store_n(&topology->slot_state[slot], QIHSE_CLUSTER_SLOT_STABLE, __ATOMIC_RELAXED);
        __atomic_store_n(&topology->slot_to_node[slot], QIHSE_CLUSTER_NODE_NONE, __ATOMIC_RELEASE);
    }
    qihse_cluster_next_epoch(topology);
    pthread_mutex_unlock(&topology->metadata_lock);
    return true;
}

static bool qihse_cluster_topology_set_transition(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index, qihse_cluster_slot_state_t state) {
    if (!topology || slot >= QIHSE_CLUSTER_SLOT_COUNT || source_index == target_index) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&topology->metadata_lock);
    if (!qihse_cluster_valid_node_locked(topology, source_index) || !qihse_cluster_valid_node_locked(topology, target_index)) {
        pthread_mutex_unlock(&topology->metadata_lock);
        errno = ENOENT;
        return false;
    }
    __atomic_store_n(&topology->slot_to_node[slot], source_index, __ATOMIC_RELAXED);
    __atomic_store_n(&topology->slot_peer[slot], target_index, __ATOMIC_RELAXED);
    __atomic_store_n(&topology->slot_state[slot], (uint8_t)state, __ATOMIC_RELEASE);
    qihse_cluster_next_epoch(topology);
    pthread_mutex_unlock(&topology->metadata_lock);
    return true;
}

bool qihse_cluster_topology_set_migrating(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index) {
    return qihse_cluster_topology_set_transition(topology, slot, source_index, target_index, QIHSE_CLUSTER_SLOT_MIGRATING);
}

bool qihse_cluster_topology_set_importing(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index) {
    return qihse_cluster_topology_set_transition(topology, slot, source_index, target_index, QIHSE_CLUSTER_SLOT_IMPORTING);
}

bool qihse_cluster_topology_set_stable(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t owner_index) {
    return qihse_cluster_topology_assign_range(topology, slot, slot, owner_index);
}

bool qihse_cluster_topology_get_slot(const qihse_cluster_topology_t* topology, uint16_t slot, uint16_t* owner_index, qihse_cluster_slot_state_t* state, uint16_t* peer_index) {
    if (!topology || slot >= QIHSE_CLUSTER_SLOT_COUNT) {
        errno = EINVAL;
        return false;
    }
    uint8_t current_state = __atomic_load_n(&topology->slot_state[slot], __ATOMIC_ACQUIRE);
    if (owner_index) *owner_index = __atomic_load_n(&topology->slot_to_node[slot], __ATOMIC_ACQUIRE);
    if (state) *state = (qihse_cluster_slot_state_t)current_state;
    if (peer_index) *peer_index = __atomic_load_n(&topology->slot_peer[slot], __ATOMIC_ACQUIRE);
    return true;
}

qihse_cluster_route_t qihse_cluster_topology_route(const qihse_cluster_topology_t* topology, uint16_t slot, bool asking, bool local_key_exists) {
    qihse_cluster_route_t route;
    memset(&route, 0, sizeof(route));
    route.slot = slot;
    route.owner_index = QIHSE_CLUSTER_NODE_NONE;
    route.target_index = QIHSE_CLUSTER_NODE_NONE;
    route.decision = QIHSE_CLUSTER_ROUTE_UNASSIGNED;
    if (!topology || slot >= QIHSE_CLUSTER_SLOT_COUNT) return route;

    uint16_t owner;
    uint16_t peer;
    qihse_cluster_slot_state_t state;
    qihse_cluster_topology_get_slot(topology, slot, &owner, &state, &peer);
    uint16_t local = qihse_cluster_topology_local_node(topology);
    route.owner_index = owner;
    route.state = state;
    route.config_epoch = qihse_cluster_topology_epoch(topology);
    if (owner == QIHSE_CLUSTER_NODE_NONE) return route;

    if (owner == local) {
        if (state != QIHSE_CLUSTER_SLOT_STABLE && peer != QIHSE_CLUSTER_NODE_NONE && !local_key_exists) {
            route.decision = QIHSE_CLUSTER_ROUTE_ASK;
            route.target_index = peer;
        } else {
            route.decision = QIHSE_CLUSTER_ROUTE_LOCAL;
            route.target_index = local;
        }
        return route;
    }
    if (state != QIHSE_CLUSTER_SLOT_STABLE && peer == local && asking) {
        route.decision = QIHSE_CLUSTER_ROUTE_LOCAL;
        route.target_index = local;
        return route;
    }

    qihse_cluster_node_t owner_node;
    if (!qihse_cluster_topology_get_node(topology, owner, &owner_node) || !owner_node.healthy) {
        route.decision = QIHSE_CLUSTER_ROUTE_NODE_DOWN;
        route.target_index = owner;
        return route;
    }
    route.decision = QIHSE_CLUSTER_ROUTE_MOVED;
    route.target_index = owner;
    return route;
}

size_t qihse_cluster_topology_ranges(const qihse_cluster_topology_t* topology, qihse_cluster_slot_range_t* out_ranges, size_t capacity) {
    if (!topology) return 0;
    size_t count = 0;
    uint32_t slot = 0;
    while (slot < QIHSE_CLUSTER_SLOT_COUNT) {
        uint16_t owner = __atomic_load_n(&topology->slot_to_node[slot], __ATOMIC_ACQUIRE);
        if (owner == QIHSE_CLUSTER_NODE_NONE) {
            slot++;
            continue;
        }
        uint32_t start = slot;
        do {
            slot++;
        } while (slot < QIHSE_CLUSTER_SLOT_COUNT &&
                 __atomic_load_n(&topology->slot_to_node[slot], __ATOMIC_ACQUIRE) == owner);
        if (out_ranges && count < capacity) {
            out_ranges[count].start = (uint16_t)start;
            out_ranges[count].end = (uint16_t)(slot - 1u);
            out_ranges[count].owner_index = owner;
        }
        count++;
    }
    return count;
}

size_t qihse_cluster_topology_assigned_slots(const qihse_cluster_topology_t* topology) {
    if (!topology) return 0;
    size_t count = 0;
    for (size_t slot = 0; slot < QIHSE_CLUSTER_SLOT_COUNT; slot++) {
        if (__atomic_load_n(&topology->slot_to_node[slot], __ATOMIC_ACQUIRE) != QIHSE_CLUSTER_NODE_NONE) count++;
    }
    return count;
}

bool qihse_cluster_topology_is_covered(const qihse_cluster_topology_t* topology) {
    return qihse_cluster_topology_assigned_slots(topology) == QIHSE_CLUSTER_SLOT_COUNT;
}

uint64_t qihse_cluster_topology_epoch(const qihse_cluster_topology_t* topology) {
    return topology ? __atomic_load_n(&topology->current_epoch, __ATOMIC_ACQUIRE) : 0u;
}

void qihse_cluster_node_id_from_seed(const void* seed, size_t seed_len, char out_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u]) {
    static const char hex[] = "0123456789abcdef";
    const uint8_t* bytes = (const uint8_t*)seed;
    uint64_t a = UINT64_C(14695981039346656037);
    uint64_t b = UINT64_C(7809847782465536322);
    for (size_t i = 0; i < seed_len; i++) {
        a = (a ^ bytes[i]) * UINT64_C(1099511628211);
        b ^= (uint64_t)bytes[i] + UINT64_C(0x9e3779b97f4a7c15) + (b << 6) + (b >> 2);
    }
    for (size_t i = 0; i < 20; i++) {
        a ^= a << 13;
        a ^= a >> 7;
        a ^= a << 17;
        b = b * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
        uint8_t value = (uint8_t)((a ^ b ^ (a >> 32) ^ (b >> 40)) & 0xffu);
        out_id[i * 2] = hex[value >> 4];
        out_id[i * 2 + 1] = hex[value & 0x0fu];
    }
    out_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
}
