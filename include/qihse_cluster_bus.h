#ifndef QIHSE_CLUSTER_BUS_H
#define QIHSE_CLUSTER_BUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QIHSE Cluster Bus — gossip transport for cluster membership, heartbeats,
 * and slot ownership updates.  Uses UDP datagrams by default (port 16379 or
 * node.bus_port) with an optional AF_XDP fast path when QIHSE_XDP_OBJ is
 * configured and the interface is available.
 *
 * Wire format (little-endian, fixed header + payload):
 *   uint32_t magic          = 0x51424E53 ('QBNS')
 *   uint32_t message_type   = QIHSE_BUS_MSG_*
 *   uint32_t sender_index   = topology node index of sender
 *   uint32_t payload_len    = byte count of payload
 *   uint8_t  payload[payload_len]
 *
 * Message types:
 *   PING        — heartbeat, payload = sender node_id (40 bytes)
 *   PONG        — heartbeat reply, payload = sender node_id
 *   MEET        — introduce a new node, payload = node_t serialised
 *   FAIL        — mark a node as failed, payload = node_id (40 bytes)
 *   SLOT_UPDATE — slot range ownership change, payload = slot_update_t
 *   NODE_UPDATE — node metadata change (role/health), payload = node_t
 */

#define QIHSE_CLUSTER_BUS_MAGIC 0x51424E53u
#define QIHSE_CLUSTER_BUS_DEFAULT_PORT 16379u
#define QIHSE_CLUSTER_BUS_MAX_PAYLOAD 4096u
#define QIHSE_CLUSTER_BUS_HEADER_SIZE 16u
#define QIHSE_CLUSTER_BUS_HEARTBEAT_MS 1000u
#define QIHSE_CLUSTER_BUS_TIMEOUT_MS 5000u

typedef enum {
    QIHSE_BUS_MSG_PING = 1u,
    QIHSE_BUS_MSG_PONG = 2u,
    QIHSE_BUS_MSG_MEET = 3u,
    QIHSE_BUS_MSG_FAIL = 4u,
    QIHSE_BUS_MSG_SLOT_UPDATE = 5u,
    QIHSE_BUS_MSG_NODE_UPDATE = 6u
} qihse_cluster_bus_msg_type_t;

typedef struct {
    uint16_t start;
    uint16_t end;
    uint16_t owner_index;       /* sender's local index (for sender's reference) */
    uint16_t reserved;
    char owner_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u]; /* owner's node ID (resolved by receiver) */
} qihse_cluster_bus_slot_update_t;

typedef struct qihse_cluster_bus qihse_cluster_bus_t;

typedef void (*qihse_cluster_bus_on_fail_cb)(qihse_cluster_topology_t* topology,
                                             uint16_t failed_node_index,
                                             void* user_data);

typedef struct {
    qihse_cluster_topology_t* topology;
    uint16_t local_node_index;
    uint16_t bus_port;
    const char* bind_address;
    const char* xdp_interface;   /* NULL = standard UDP; set to enable AF_XDP */
    uint32_t heartbeat_ms;
    uint32_t timeout_ms;
    qihse_cluster_bus_on_fail_cb on_fail;
    void* on_fail_user_data;
} qihse_cluster_bus_config_t;

qihse_cluster_bus_t* qihse_cluster_bus_create(const qihse_cluster_bus_config_t* config);
bool qihse_cluster_bus_start(qihse_cluster_bus_t* bus);
void qihse_cluster_bus_stop(qihse_cluster_bus_t* bus);
void qihse_cluster_bus_destroy(qihse_cluster_bus_t* bus);

/* Broadcast a slot ownership update to all known peers. */
bool qihse_cluster_bus_broadcast_slot_update(qihse_cluster_bus_t* bus,
                                             uint16_t start, uint16_t end,
                                             uint16_t owner_index);

/* Broadcast a node metadata update (role change, health change). */
bool qihse_cluster_bus_broadcast_node_update(qihse_cluster_bus_t* bus,
                                             uint16_t node_index);

/* Broadcast a FAIL notice for a node. */
bool qihse_cluster_bus_broadcast_fail(qihse_cluster_bus_t* bus,
                                      uint16_t failed_node_index);

/* Send a MEET to a specific address (introduces this node to a peer). */
bool qihse_cluster_bus_meet(qihse_cluster_bus_t* bus,
                            const char* host, uint16_t port);

/* Manually inject a received datagram (for testing).  Returns true if
 * the message was processed and applied to the topology. */
bool qihse_cluster_bus_inject(qihse_cluster_bus_t* bus,
                              const uint8_t* datagram, size_t len,
                              const char* peer_host, uint16_t peer_port);

/* Get the UDP socket fd (for poll-based integration).  Returns -1 if
 * the bus is not running or uses AF_XDP. */
int qihse_cluster_bus_fd(const qihse_cluster_bus_t* bus);

/* Process one round of pending datagrams (non-blocking).  Returns the
 * number of messages processed. */
size_t qihse_cluster_bus_poll(qihse_cluster_bus_t* bus);

/* Check if a node has been silent beyond the timeout threshold.  Returns
 * the number of nodes marked as unhealthy. */
size_t qihse_cluster_bus_check_health(qihse_cluster_bus_t* bus);

/* Statistics. */
typedef struct {
    uint64_t sent;
    uint64_t received;
    uint64_t pings_sent;
    uint64_t pongs_received;
    uint64_t slot_updates_received;
    uint64_t fail_notices_received;
    uint64_t nodes_marked_unhealthy;
} qihse_cluster_bus_stats_t;

void qihse_cluster_bus_stats(const qihse_cluster_bus_t* bus,
                             qihse_cluster_bus_stats_t* out_stats);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_BUS_H */
