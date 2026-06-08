#ifndef QIHSE_RAFT_H
#define QIHSE_RAFT_H

#include <stdint.h>
#include <stdbool.h>
#include <liburing.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"

typedef enum {
    QIHSE_RAFT_FOLLOWER = 0,
    QIHSE_RAFT_CANDIDATE = 1,
    QIHSE_RAFT_LEADER = 2
} qihse_raft_state_t;

typedef struct qihse_raft_node_s {
    uint32_t node_id;
    qihse_raft_state_t state;
    uint64_t current_term;
    int32_t voted_for;
    
    // WAL / Log Replication
    uint64_t commit_index;
    uint64_t last_applied;
    
    // Election
    time_t last_heartbeat;
    
    // Networking
    struct io_uring ring;
    int server_fd;
    uint16_t port;
    
    // Data stores
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
    
    bool running;
} qihse_raft_node_t;

/**
 * Initializes the Raft Node and sets up the io_uring event loop.
 */
bool qihse_raft_init(qihse_raft_node_t* node, uint32_t node_id, uint16_t port, qihse_kv_store_t* store, qihse_vector_db_t vdb);

/**
 * Starts the background Raft io_uring loop and leader election timers.
 */
void qihse_raft_start(qihse_raft_node_t* node);

/**
 * Shuts down the Raft node.
 */
void qihse_raft_stop(qihse_raft_node_t* node);

/**
 * Request to append an entry to the Raft distributed log.
 * Only succeeds if this node is the LEADER, otherwise it redirects.
 */
bool qihse_raft_append_entry(qihse_raft_node_t* node, const uint8_t* data, size_t len);

/**
 * Handle incoming AppendEntries RPCs from a Leader.
 */
void qihse_raft_receive_append_entries(qihse_raft_node_t* node, uint64_t leader_term, uint32_t leader_id);

#endif /* QIHSE_RAFT_H */
