/* ============================================================================
 * QIHSE DISTRIBUTED COHERENCE PROTOCOLS
 * ============================================================================
 *
 * Cluster-scale coherence, message passing, distributed state management,
 * and hierarchical coordination for multi-node QIHSE deployments.
 *
 * Mission-critical distributed systems ensuring consistency across nodes
 * while maintaining the quantum-inspired performance characteristics.
 * ============================================================================ */

#ifndef QIHSE_DISTRIBUTED_H
#define QIHSE_DISTRIBUTED_H

#include "../../core/qihse_abi.h"
#include "../../memory/include/qihse_memory.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/* ============================================================================
 * DISTRIBUTED SYSTEM CONFIGURATION
 * ============================================================================ */

#define QIHSE_MAX_NODES 1024
#define QIHSE_MAX_GROUPS 64
#define QIHSE_MESSAGE_QUEUE_SIZE 8192
#define QIHSE_HEARTBEAT_INTERVAL_MS 1000
#define QIHSE_ELECTION_TIMEOUT_MS 5000

/**
 * Node states in distributed system
 */
typedef enum qihse_node_state_e {
    QIHSE_NODE_DISCONNECTED,    /* Node not connected to cluster */
    QIHSE_NODE_CONNECTING,      /* Node attempting to join cluster */
    QIHSE_NODE_CONNECTED,       /* Node connected, not yet synchronized */
    QIHSE_NODE_SYNCHRONIZED,    /* Node fully synchronized */
    QIHSE_NODE_LEADER,          /* Node is current cluster leader */
    QIHSE_NODE_FOLLOWER,        /* Node is follower in cluster */
    QIHSE_NODE_CANDIDATE        /* Node is candidate for leadership */
} qihse_node_state_t;

/**
 * Message types for distributed communication
 */
typedef enum qihse_message_type_e {
    QIHSE_MSG_HEARTBEAT,        /* Periodic heartbeat */
    QIHSE_MSG_STATE_UPDATE,     /* State synchronization */
    QIHSE_MSG_WORKLOAD_ASSIGN,  /* Workload assignment */
    QIHSE_MSG_RESULT_AGGREGATE, /* Result aggregation */
    QIHSE_MSG_ELECTION_VOTE,    /* Leadership election vote */
    QIHSE_MSG_ELECTION_REQUEST, /* Leadership election request */
    QIHSE_MSG_COHERENCE_UPDATE, /* Cache coherence update */
    QIHSE_MSG_FAILURE_DETECT,   /* Node failure detection */
    QIHSE_MSG_RECOVERY_REQUEST  /* Recovery coordination */
} qihse_message_type_t;

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

/**
 * Distributed node information
 */
typedef struct qihse_distributed_node_s {
    uint32_t node_id;                   /* Unique node identifier */
    char hostname[256];                 /* Node hostname/IP */
    uint16_t port;                      /* Communication port */
    qihse_node_state_t state;           /* Current node state */
    uint64_t last_heartbeat;            /* Last heartbeat timestamp */
    uint32_t term;                      /* Current election term */
    uint32_t group_id;                  /* Hierarchical group ID */
    void* node_data;                    /* Node-specific data */
} qihse_distributed_node_t;

/**
 * Distributed message structure
 */
typedef struct qihse_distributed_message_s {
    uint32_t sender_id;                 /* Sending node ID */
    uint32_t receiver_id;               /* Receiving node ID (0xFFFFFFFF for broadcast) */
    qihse_message_type_t type;          /* Message type */
    uint32_t sequence_number;           /* Message sequence number */
    uint64_t timestamp;                 /* Message timestamp */
    uint32_t payload_size;              /* Payload size in bytes */
    void* payload;                      /* Message payload */
    uint32_t checksum;                  /* Message integrity checksum */
} qihse_distributed_message_t;

/**
 * Distributed state snapshot
 */
typedef struct qihse_distributed_state_s {
    uint32_t term;                      /* Current term */
    uint32_t leader_id;                 /* Current leader node ID */
    uint32_t num_nodes;                 /* Total nodes in cluster */
    qihse_distributed_node_t nodes[QIHSE_MAX_NODES]; /* Node information */
    uint64_t cluster_version;           /* Cluster state version */
    void* state_data;                   /* Cluster-specific state */
    size_t state_size;                  /* State data size */
} qihse_distributed_state_t;

/**
 * Message queue for distributed communication
 */
typedef struct qihse_message_queue_s {
    qihse_distributed_message_t messages[QIHSE_MESSAGE_QUEUE_SIZE];
    uint32_t head;                      /* Queue head index */
    uint32_t tail;                      /* Queue tail index */
    uint32_t count;                     /* Number of messages in queue */
    pthread_mutex_t mutex;              /* Queue protection */
    pthread_cond_t not_empty;           /* Queue not empty condition */
    pthread_cond_t not_full;            /* Queue not full condition */
} qihse_message_queue_t;

/**
 * Distributed coherence manager
 */
typedef struct qihse_distributed_manager_s {
    uint32_t local_node_id;             /* Local node identifier */
    qihse_distributed_state_t cluster_state; /* Current cluster state */
    qihse_message_queue_t message_queue; /* Message queue */
    pthread_t heartbeat_thread;         /* Heartbeat management thread */
    pthread_t message_thread;           /* Message processing thread */
    pthread_t election_thread;          /* Leadership election thread */
    bool running;                       /* Manager running flag */
    void* network_transport;            /* Network transport layer */
    void* coherence_cache;              /* Distributed coherence cache */
    uint64_t last_state_sync;           /* Last state synchronization */
    uint32_t failure_timeout_ms;        /* Node failure timeout */
    void* user_data;                    /* User context */
} qihse_distributed_manager_t;

/* ============================================================================
 * DISTRIBUTED COHERENCE API
 * ============================================================================ */

/**
 * Initialize distributed coherence manager
 *
 * @param manager Manager to initialize
 * @param local_node_id Local node identifier
 * @param hostname Local hostname/IP
 * @param port Communication port
 * @param user_data Optional user context
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_init(
    qihse_distributed_manager_t* manager,
    uint32_t local_node_id,
    const char* hostname,
    uint16_t port,
    void* user_data
);

/**
 * Destroy distributed coherence manager
 *
 * @param manager Manager to destroy
 */
void qihse_distributed_destroy(qihse_distributed_manager_t* manager);

/**
 * Join distributed cluster
 *
 * @param manager Manager instance
 * @param seed_node_hostname Seed node hostname for cluster discovery
 * @param seed_node_port Seed node port
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_join_cluster(
    qihse_distributed_manager_t* manager,
    const char* seed_node_hostname,
    uint16_t seed_node_port
);

/**
 * Leave distributed cluster
 *
 * @param manager Manager instance
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_leave_cluster(qihse_distributed_manager_t* manager);

/**
 * Send message to specific node
 *
 * @param manager Manager instance
 * @param target_node_id Target node identifier
 * @param message Message to send
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_send_message(
    qihse_distributed_manager_t* manager,
    uint32_t target_node_id,
    const qihse_distributed_message_t* message
);

/**
 * Broadcast message to all cluster nodes
 *
 * @param manager Manager instance
 * @param message Message to broadcast
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_broadcast_message(
    qihse_distributed_manager_t* manager,
    const qihse_distributed_message_t* message
);

/**
 * Synchronize cluster state
 *
 * @param manager Manager instance
 * @param timeout_ms Synchronization timeout in milliseconds
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_sync_state(
    qihse_distributed_manager_t* manager,
    uint32_t timeout_ms
);

/**
 * Check cluster coherence
 *
 * @param manager Manager instance
 * @param coherence_score Output coherence score (0.0-1.0)
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_check_coherence(
    qihse_distributed_manager_t* manager,
    double* coherence_score
);

/**
 * Handle node failure and initiate recovery
 *
 * @param manager Manager instance
 * @param failed_node_id Failed node identifier
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_handle_failure(
    qihse_distributed_manager_t* manager,
    uint32_t failed_node_id
);

/**
 * Get distributed system statistics
 *
 * @param manager Manager instance
 * @param num_nodes Output number of active nodes
 * @param leader_id Output current leader node ID
 * @param avg_latency_ms Output average message latency
 * @return 0 on success, negative error code on failure
 */
int qihse_distributed_get_stats(
    const qihse_distributed_manager_t* manager,
    uint32_t* num_nodes,
    uint32_t* leader_id,
    double* avg_latency_ms
);

/* ============================================================================
 * MESSAGE QUEUE API
 * ============================================================================ */

/**
 * Initialize message queue
 *
 * @param queue Queue to initialize
 * @return 0 on success, negative error code on failure
 */
int qihse_message_queue_init(qihse_message_queue_t* queue);

/**
 * Destroy message queue
 *
 * @param queue Queue to destroy
 */
void qihse_message_queue_destroy(qihse_message_queue_t* queue);

/**
 * Enqueue message
 *
 * @param queue Queue instance
 * @param message Message to enqueue
 * @return 0 on success, negative error code on failure
 */
int qihse_message_queue_enqueue(
    qihse_message_queue_t* queue,
    const qihse_distributed_message_t* message
);

/**
 * Dequeue message
 *
 * @param queue Queue instance
 * @param message Output dequeued message
 * @param timeout_ms Timeout in milliseconds (0 for non-blocking)
 * @return 0 on success, negative error code on failure
 */
int qihse_message_queue_dequeue(
    qihse_message_queue_t* queue,
    qihse_distributed_message_t* message,
    uint32_t timeout_ms
);

/**
 * Get queue statistics
 *
 * @param queue Queue instance
 * @param queue_size Output current queue size
 * @param max_queue_size Output maximum queue size
 * @return 0 on success, negative error code on failure
 */
int qihse_message_queue_get_stats(
    const qihse_message_queue_t* queue,
    uint32_t* queue_size,
    uint32_t* max_queue_size
);

#endif /* QIHSE_DISTRIBUTED_H */
