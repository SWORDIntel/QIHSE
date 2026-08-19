#ifndef QIHSE_CLUSTER_SLOT_H
#define QIHSE_CLUSTER_SLOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_crc16.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CLUSTER_MAX_NODES 256u
#define QIHSE_CLUSTER_NODE_ID_LEN 40u
#define QIHSE_CLUSTER_HOST_LEN 255u
#define QIHSE_CLUSTER_NODE_NONE UINT16_MAX

typedef enum {
    QIHSE_CLUSTER_NODE_PRIMARY = 0,
    QIHSE_CLUSTER_NODE_REPLICA = 1
} qihse_cluster_node_role_t;

typedef enum {
    QIHSE_CLUSTER_SLOT_STABLE = 0,
    QIHSE_CLUSTER_SLOT_MIGRATING = 1,
    QIHSE_CLUSTER_SLOT_IMPORTING = 2
} qihse_cluster_slot_state_t;

typedef enum {
    QIHSE_CLUSTER_ROUTE_LOCAL = 0,
    QIHSE_CLUSTER_ROUTE_MOVED = 1,
    QIHSE_CLUSTER_ROUTE_ASK = 2,
    QIHSE_CLUSTER_ROUTE_UNASSIGNED = 3,
    QIHSE_CLUSTER_ROUTE_NODE_DOWN = 4
} qihse_cluster_route_decision_t;

typedef struct {
    uint16_t index;
    char id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char host[QIHSE_CLUSTER_HOST_LEN + 1u];
    uint16_t port;
    uint16_t bus_port;
    qihse_cluster_node_role_t role;
    uint16_t primary_index;
    uint64_t config_epoch;
    bool healthy;
} qihse_cluster_node_t;

typedef struct {
    uint16_t start;
    uint16_t end;
    uint16_t owner_index;
} qihse_cluster_slot_range_t;

typedef struct {
    qihse_cluster_route_decision_t decision;
    uint16_t slot;
    uint16_t owner_index;
    uint16_t target_index;
    qihse_cluster_slot_state_t state;
    uint64_t config_epoch;
} qihse_cluster_route_t;

typedef struct qihse_cluster_topology qihse_cluster_topology_t;

qihse_cluster_topology_t* qihse_cluster_topology_create(void);
void qihse_cluster_topology_destroy(qihse_cluster_topology_t* topology);
bool qihse_cluster_topology_upsert_node(qihse_cluster_topology_t* topology, const qihse_cluster_node_t* node, uint16_t* out_index);
bool qihse_cluster_topology_get_node(const qihse_cluster_topology_t* topology, uint16_t index, qihse_cluster_node_t* out_node);
bool qihse_cluster_topology_find_node(const qihse_cluster_topology_t* topology, const char* node_id, uint16_t* out_index);
size_t qihse_cluster_topology_nodes(const qihse_cluster_topology_t* topology, qihse_cluster_node_t* out_nodes, size_t capacity);
bool qihse_cluster_topology_set_local_node(qihse_cluster_topology_t* topology, uint16_t index);
uint16_t qihse_cluster_topology_local_node(const qihse_cluster_topology_t* topology);
bool qihse_cluster_topology_set_node_health(qihse_cluster_topology_t* topology, uint16_t index, bool healthy);
bool qihse_cluster_topology_assign_range(qihse_cluster_topology_t* topology, uint16_t start, uint16_t end, uint16_t owner_index);
bool qihse_cluster_topology_unassign_range(qihse_cluster_topology_t* topology, uint16_t start, uint16_t end);
bool qihse_cluster_topology_set_migrating(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index);
bool qihse_cluster_topology_set_importing(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index);
bool qihse_cluster_topology_set_stable(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t owner_index);
bool qihse_cluster_topology_get_slot(const qihse_cluster_topology_t* topology, uint16_t slot, uint16_t* owner_index, qihse_cluster_slot_state_t* state, uint16_t* peer_index);
qihse_cluster_route_t qihse_cluster_topology_route(const qihse_cluster_topology_t* topology, uint16_t slot, bool asking, bool local_key_exists);
size_t qihse_cluster_topology_ranges(const qihse_cluster_topology_t* topology, qihse_cluster_slot_range_t* out_ranges, size_t capacity);
size_t qihse_cluster_topology_assigned_slots(const qihse_cluster_topology_t* topology);
bool qihse_cluster_topology_is_covered(const qihse_cluster_topology_t* topology);
uint64_t qihse_cluster_topology_epoch(const qihse_cluster_topology_t* topology);
void qihse_cluster_node_id_from_seed(const void* seed, size_t seed_len, char out_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u]);

#ifdef __cplusplus
}
#endif

#endif
