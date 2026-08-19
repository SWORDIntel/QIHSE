#include "qihse_cluster_failover.h"
#include "qihse_platform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <pthread.h>
#endif

struct qihse_cluster_failover {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    uint16_t local_node_index;
    bool single_coordinator;
    uint64_t failover_events;
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
    qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
    size_t count = qihse_cluster_topology_nodes(topology, nodes, sizeof(nodes) / sizeof(nodes[0]));
    uint16_t best = QIHSE_CLUSTER_NODE_NONE;
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].role != QIHSE_CLUSTER_NODE_REPLICA) continue;
        if (nodes[i].primary_index != primary_index) continue;
        if (!nodes[i].healthy) continue;
        if (best == QIHSE_CLUSTER_NODE_NONE || nodes[i].index < best) {
            best = nodes[i].index;
        }
    }
    return best;
}

bool qihse_cluster_failover_promote(qihse_cluster_failover_t* fo,
                                    uint16_t failed_primary_index,
                                    uint16_t replica_index) {
    if (!fo || !fo->topology) return false;
    if (failed_primary_index == QIHSE_CLUSTER_NODE_NONE || replica_index == QIHSE_CLUSTER_NODE_NONE) return false;

    qihse_cluster_node_t replica;
    if (!qihse_cluster_topology_get_node(fo->topology, replica_index, &replica)) return false;
    if (replica.role != QIHSE_CLUSTER_NODE_REPLICA) return false;

    /* Promote the replica to primary */
    replica.role = QIHSE_CLUSTER_NODE_PRIMARY;
    replica.primary_index = QIHSE_CLUSTER_NODE_NONE;
    replica.healthy = true;
    qihse_cluster_topology_upsert_node(fo->topology, &replica, NULL);

    /* Reassign all slot ranges owned by the failed primary to the promoted replica */
    qihse_cluster_slot_range_t ranges[QIHSE_CLUSTER_SLOT_COUNT];
    size_t range_count = qihse_cluster_topology_ranges(fo->topology, ranges, sizeof(ranges) / sizeof(ranges[0]));
    for (size_t i = 0; i < range_count; i++) {
        if (ranges[i].owner_index == failed_primary_index) {
            qihse_cluster_topology_assign_range(fo->topology, ranges[i].start, ranges[i].end, replica_index);
            if (fo->bus) qihse_cluster_bus_broadcast_slot_update(fo->bus, ranges[i].start, ranges[i].end, replica_index);
        }
    }

    /* Broadcast the node role update */
    if (fo->bus) qihse_cluster_bus_broadcast_node_update(fo->bus, replica_index);

    return true;
}

uint16_t qihse_cluster_failover_handle(qihse_cluster_failover_t* fo,
                                       uint16_t failed_node_index) {
    if (!fo || !fo->topology) return QIHSE_CLUSTER_NODE_NONE;
    pthread_mutex_lock(&fo->lock);

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
        qihse_cluster_node_t nodes[QIHSE_CLUSTER_MAX_NODES];
        size_t count = qihse_cluster_topology_nodes(fo->topology, nodes, sizeof(nodes) / sizeof(nodes[0]));
        uint16_t coordinator = QIHSE_CLUSTER_NODE_NONE;
        for (size_t i = 0; i < count; i++) {
            if (nodes[i].role != QIHSE_CLUSTER_NODE_PRIMARY || !nodes[i].healthy) continue;
            if (coordinator == QIHSE_CLUSTER_NODE_NONE || nodes[i].index < coordinator) {
                coordinator = nodes[i].index;
            }
        }
        if (coordinator != fo->local_node_index) {
            pthread_mutex_unlock(&fo->lock);
            return QIHSE_CLUSTER_NODE_NONE;
        }
    }

    uint16_t replica = qihse_cluster_failover_best_replica(fo->topology, failed_node_index);
    if (replica == QIHSE_CLUSTER_NODE_NONE) {
        pthread_mutex_unlock(&fo->lock);
        return QIHSE_CLUSTER_NODE_NONE;
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
