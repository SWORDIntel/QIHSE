#include "qihse_cluster_failover.h"
#include "qihse_cluster_bus.h"
#include "qihse_platform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t fo_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

#ifndef _WIN32
#include <pthread.h>
#endif

struct qihse_cluster_failover {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    uint16_t local_node_index;
    bool single_coordinator;
    uint64_t failover_events;
    uint64_t last_attempt_ms;
    pthread_mutex_t lock;
};

qihse_cluster_failover_t* qihse_cluster_failover_create(const qihse_cluster_failover_config_t* config) {
    if (!config || !config->topology) return NULL;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)calloc(1, sizeof(*fo));
    if (!fo) return NULL;
    fo->topology = config->topology;
    fo->bus = config->bus;
    fo->local_node_index = config->local_node_index;
    fo->single_coordinator = config->single_coordinator;
    if (pthread_mutex_init(&fo->lock, NULL) != 0) {
        free(fo);
        return NULL;
    }
    return fo;
}

void qihse_cluster_failover_destroy(qihse_cluster_failover_t* fo) {
    if (!fo) return;
    pthread_mutex_destroy(&fo->lock);
    free(fo);
}

uint16_t qihse_cluster_failover_best_replica(const qihse_cluster_topology_t* topology,
                                             uint16_t primary_index) {
    if (!topology || primary_index == QIHSE_CLUSTER_NODE_NONE) return QIHSE_CLUSTER_NODE_NONE;
    /* Heap, not a 256-entry array on the stack. At ~150 bytes per node that
     * was 88 KB of frame in a function on the failover path, and this one is
     * PUBLIC and lock-free, so it can be called from anywhere. */
    qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(
        QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t));
    if (!nodes) return QIHSE_CLUSTER_NODE_NONE;
    size_t count = qihse_cluster_topology_nodes(topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].role != QIHSE_CLUSTER_NODE_REPLICA) continue;
        if (nodes[i].primary_index != primary_index) continue;
        if (!nodes[i].healthy) continue;
        if (best == QIHSE_CLUSTER_NODE_NONE || nodes[i].index < best) {
            best = nodes[i].index;
        }
    }
    free(nodes);
    return best;
}

/* The coordinator is the lowest-index healthy primary.
 *
 * A helper rather than an inline 256-entry array so the frame stays small and
 * the buffer has ONE exit. handle() has several early returns that unlock the
 * mutex; threading a free through each of them is how a leak gets introduced
 * later by someone adding a sixth. */
static uint16_t fo_find_coordinator(const qihse_cluster_topology_t* topology) {
    if (!topology) return QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(
        QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t));
    if (!nodes) return QIHSE_CLUSTER_NODE_NONE;
    size_t count = qihse_cluster_topology_nodes(topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint16_t coordinator = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY || !nodes[i].healthy) continue;
        if (coordinator == QIHSE_CLUSTER_NODE_NONE || nodes[i].index < coordinator) {
            coordinator = nodes[i].index;
        }
    }
    free(nodes);
    return coordinator;
}

/* Sharded-cluster fallback successor: the healthy primary with the LONGEST
 * CONTINUOUS PRESENCE, excluding the failed node. Same single-exit reasoning
 * as fo_find_coordinator. */
static uint16_t fo_pick_fallback_successor(qihse_cluster_failover_t* fo,
                                           uint16_t failed_node_index, uint64_t now) {
    qihse_cluster_node_t* nodes = (qihse_cluster_node_t*)malloc(
        QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t));
    if (!nodes) return QIHSE_CLUSTER_NODE_NONE;
    size_t count = qihse_cluster_topology_nodes(fo->topology, nodes, QIHSE_CLUSTER_MAX_NODES);
    uint64_t best_uptime = 0;
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].index == failed_node_index) continue;
        if (nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY || !nodes[i].healthy) continue;
        uint64_t first_seen = 0;
        uint64_t uptime = 0;
        if (fo->bus && qihse_cluster_bus_peer_first_seen(fo->bus, nodes[i].index, &first_seen) && first_seen > 0)
            uptime = now > first_seen ? now - first_seen : 0;
        /* Our own presence counts too (we are a live successor candidate) */
        if (nodes[i].index == fo->local_node_index) uptime = UINT64_MAX / 2u;
        if (uptime > best_uptime || (uptime == best_uptime && best == QIHSE_CLUSTER_NODE_NONE)) {
            best_uptime = uptime;
            best = nodes[i].index;
        }
    }
    free(nodes);
    return best;
}

bool qihse_cluster_failover_promote(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index) {
    if (!fo || !fo->topology) return false;
    if (failed_primary_index == QIHSE_CLUSTER_NODE_NONE || replica_index == QIHSE_CLUSTER_NODE_NONE) return false;

    qihse_cluster_node_t replica;
    if (!qihse_cluster_topology_get_node(fo->topology, replica_index, &replica)) return false;
    /* Valid successors: a dedicated REPLICA of the failed primary, or (the
     * sharded-cluster fallback) another healthy PRIMARY with the most
     * continuous presence. A failed/unhealthy successor is never chosen. */
    if (replica.role != QIHSE_CLUSTER_NODE_REPLICA && replica.role != QIHSE_CLUSTER_NODE_PRIMARY) return false;
    if (!replica.healthy) return false;

    /* Promote the successor to primary */
    replica.role = QIHSE_CLUSTER_NODE_PRIMARY;
    replica.primary_index = QIHSE_CLUSTER_NODE_NONE;
    replica.healthy = true;
    qihse_cluster_topology_upsert_node(fo->topology, &replica, NULL);

    /* Reassign all slot ranges owned by the failed primary to the promoted
     * replica. Heap, not a QIHSE_CLUSTER_SLOT_COUNT array on the stack: that
     * was ~96 KB of frame, the same defect the brain carried. */
    qihse_cluster_slot_range_t* ranges = (qihse_cluster_slot_range_t*)malloc(
        QIHSE_CLUSTER_SLOT_COUNT * sizeof(qihse_cluster_slot_range_t));
    if (!ranges) return false;
    size_t range_count = qihse_cluster_topology_ranges(fo->topology, ranges, QIHSE_CLUSTER_SLOT_COUNT);
    for (size_t i = 0; i < range_count; i++) {
        if (ranges[i].owner_index == failed_primary_index) {
            qihse_cluster_topology_assign_range(fo->topology, ranges[i].start, ranges[i].end, replica_index);
            if (fo->bus) qihse_cluster_bus_broadcast_slot_update(fo->bus, ranges[i].start, ranges[i].end, replica_index);
        }
    }
    free(ranges);

    /* Broadcast the node role update */
    if (fo->bus) qihse_cluster_bus_broadcast_node_update(fo->bus, replica_index);

    return true;
}

uint16_t qihse_cluster_failover_handle(qihse_cluster_failover_t* fo,
                                       uint16_t failed_node_index) {
    if (!fo || !fo->topology) return QIHSE_CLUSTER_NODE_NONE;
    pthread_mutex_lock(&fo->lock);
    /* cooldown: while a dead node REMAINS unhealthy the bus re-fires on_fail
     * every cycle; promote is idempotent but the broadcasts are not free */
    if (fo->last_attempt_ms && fo_now_ms() - fo->last_attempt_ms < 30000u) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }
    fo->last_attempt_ms = fo_now_ms();

    qihse_cluster_node_t failed;
    if (!qihse_cluster_topology_get_node(fo->topology, failed_node_index, &failed)) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }

    /* Only failover if the failed node was a primary */
    if (failed.role != QIHSE_CLUSTER_NODE_PRIMARY) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
    }

    /* In single-coordinator mode, only the local node performs failover */
    if (fo->single_coordinator && failed_node_index != fo->local_node_index) {
        /* Check if the local node is the coordinator (lowest-index healthy primary) */
        uint16_t coordinator = fo_find_coordinator(fo->topology);
        if (coordinator != fo->local_node_index) {
            pthread_mutex_unlock(&fo->lock);
            return QIHSE_CLUSTER_NODE_NONE;
        }
    }

    uint16_t replica = qihse_cluster_failover_best_replica(fo->topology, failed_node_index);
    if (replica == QIHSE_CLUSTER_NODE_NONE) {
        /* Sharded-cluster fallback: no dedicated replica exists, so the
         * healthy node with the LONGEST CONTINUOUS PRESENCE (most uptime as
         * observed on our bus) succeeds the failed primary and inherits its
         * slot ranges. Its data must have been duplicated by the redundancy
         * link; anything not duplicated is lost with the failed node — that
         * is the documented cost of the phase-1 redundancy design. */
        uint64_t now = fo_now_ms();
        /* Evidence gate: if ANY bus participant recently reported the failed
         * node healthy, this looks like an asymmetric link — defer so we
         * don't strip ranges from a node the rest of the cluster can reach.
         * check_health re-fires on_fail each cycle, so the failover executes
         * as soon as the confirming evidence goes stale. */
        if (fo->bus) {
            uint64_t last_healthy = qihse_cluster_bus_last_observed_healthy(fo->bus, failed_node_index);
            if (last_healthy > 0 && now - last_healthy < QIHSE_CLUSTER_BUS_TIMEOUT_MS) {
                pthread_mutex_unlock(&fo->lock);
                return QIHSE_CLUSTER_NODE_NONE; /* deferred: asymmetry suspect */
            }
        }
        uint16_t best = fo_pick_fallback_successor(fo, failed_node_index, now);
        if (best == QIHSE_CLUSTER_NODE_NONE) {
            pthread_mutex_unlock(&fo->lock);
            return QIHSE_CLUSTER_NODE_NONE;
        }
        replica = best;
    }

    bool promoted = qihse_cluster_failover_promote(fo, failed_node_index, replica);
    if (promoted) {
        fo->failover_events++;
    }
    pthread_mutex_unlock(&fo->lock);
    return promoted ? replica : QIHSE_CLUSTER_NODE_NONE;
}

void qihse_cluster_failover_on_fail_cb(qihse_cluster_topology_t* topology,
                                       uint16_t failed_node_index,
                                       void* user_data) {
    (void)topology;
    qihse_cluster_failover_t* fo = (qihse_cluster_failover_t*)user_data;
    if (!fo) return;
    qihse_cluster_failover_handle(fo, failed_node_index);
}

uint64_t qihse_cluster_failover_events(const qihse_cluster_failover_t* fo) {
    return fo ? __atomic_load_n(&fo->failover_events, __ATOMIC_ACQUIRE) : 0u;
}
