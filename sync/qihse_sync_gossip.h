/**
 * QIHSE Sync - Gossip Protocol Header
 *
 * Implements epidemic broadcast and anti-entropy mechanisms for decentralized
 * peer-to-peer communication. Supports probabilistic gossip, fan-out control,
 * and message deduplication.
 */

#ifndef QIHSE_SYNC_GOSSIP_H
#define QIHSE_SYNC_GOSSIP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sync command types */
typedef enum {
    QIHSE_SYNC_CMD_HEARTBEAT = 0,
    QIHSE_SYNC_CMD_PEER_DISCOVERY = 1,
    QIHSE_SYNC_CMD_ROUTE_UPDATE = 2,
    QIHSE_SYNC_CMD_DATA_REPLICATE = 3,
    QIHSE_SYNC_CMD_FAILURE_NOTICE = 4,
    QIHSE_SYNC_CMD_METADATA_SYNC = 5,
} qihse_sync_command_t;

/* Gossip Peer Information */
typedef struct {
    char *peer_id;
    char *address;
    uint16_t port;
    uint64_t last_seen;
    uint32_t heartbeat_count;
    float suspicion_level;
} qihse_sync_peer_t;

/* Gossip Message */
typedef struct {
    uint8_t id[16];  // UUID for deduplication
    qihse_sync_command_t command_type;
    char *sender_id;
    uint8_t *payload;
    size_t payload_size;
    uint64_t timestamp;
    uint32_t ttl;
    uint32_t hop_count;
    
    /* Post-Quantum Signature (ML-DSA-87) */
    uint8_t mldsa87_signature[4627];
    bool has_signature;
} qihse_sync_message_t;

/* Gossip Manager */
typedef struct {
    char *node_id;
    qihse_sync_peer_t *peers;
    size_t peer_count;
    size_t peer_capacity;
    uint8_t (*seen_messages)[16];  // Array of message IDs
    uint64_t *seen_timestamps;
    size_t seen_count;
    size_t seen_capacity;
    qihse_sync_message_t *outgoing_queue;
    size_t outgoing_count;
    size_t outgoing_capacity;
    uint32_t fan_out;
    uint64_t gossip_interval_ms;
    uint64_t last_gossip_time;
    uint32_t random_seed;
    
    /* PQC Keys */
    void *mldsa87_pkey; /* EVP_PKEY* */
} qihse_sync_manager_t;

/* Gossip Statistics */
typedef struct {
    size_t total_peers;
    size_t seen_messages;
    size_t queued_messages;
    size_t suspected_failures;
} qihse_sync_statistics_t;

/* Outgoing Message */
typedef struct {
    char *peer_id;
    qihse_sync_message_t message;
} qihse_sync_outgoing_message_t;

/* Function Declarations */

/* Initialize gossip peer */
int qihse_sync_peer_init(
    qihse_sync_peer_t *peer,
    const char *peer_id,
    const char *address,
    uint16_t port
);

/* Cleanup gossip peer */
void qihse_sync_peer_cleanup(qihse_sync_peer_t *peer);

/* Update peer last seen */
void qihse_sync_peer_update_last_seen(qihse_sync_peer_t *peer);

/* Increase peer suspicion */
void qihse_sync_peer_increase_suspicion(qihse_sync_peer_t *peer);

/* Check if peer is suspected failed */
bool qihse_sync_peer_is_suspected_failed(
    const qihse_sync_peer_t *peer,
    float threshold
);

/* Initialize sync message */
int qihse_sync_message_init(
    qihse_sync_message_t *message,
    qihse_sync_command_t command_type,
    const char *sender_id,
    const uint8_t *payload,
    size_t payload_size,
    uint32_t ttl
);

/* Cleanup sync message */
void qihse_sync_message_cleanup(qihse_sync_message_t *message);

/* Check if message is expired */
bool qihse_sync_message_is_expired(const qihse_sync_message_t *message);

/* Decrement message TTL */
void qihse_sync_message_decrement_ttl(qihse_sync_message_t *message);

/* Check if message IDs are equal */
bool qihse_sync_message_id_equals(
    const uint8_t id1[16],
    const uint8_t id2[16]
);

/* Initialize gossip manager */
int qihse_sync_manager_init(
    qihse_sync_manager_t **manager,
    const char *node_id,
    uint32_t fan_out,
    uint64_t gossip_interval_ms
);

/* Cleanup gossip manager */
void qihse_sync_manager_cleanup(qihse_sync_manager_t *manager);

/* Add peer to gossip network */
int qihse_sync_manager_add_peer(
    qihse_sync_manager_t *manager,
    qihse_sync_peer_t peer
);

/* Remove peer from gossip network */
bool qihse_sync_manager_remove_peer(
    qihse_sync_manager_t *manager,
    const char *peer_id
);

/* Broadcast message using gossip */
int qihse_sync_manager_broadcast_message(
    qihse_sync_manager_t *manager,
    qihse_sync_command_t command_type,
    const uint8_t *payload,
    size_t payload_size,
    uint32_t ttl
);

/* Receive sync message */
int qihse_sync_manager_receive_message(
    qihse_sync_manager_t *manager,
    qihse_sync_message_t message,
    const char *from_peer
);

/* Perform gossip round */
int qihse_sync_manager_perform_gossip_round(
    qihse_sync_manager_t *manager,
    qihse_sync_outgoing_message_t **outgoing_messages,
    size_t *message_count
);

/* Cleanup outgoing messages array */
void qihse_sync_outgoing_messages_cleanup(
    qihse_sync_outgoing_message_t *messages,
    size_t count
);

/* Run failure detection */
int qihse_sync_manager_run_failure_detection(
    qihse_sync_manager_t *manager
);

/* Get gossip statistics */
void qihse_sync_manager_get_statistics(
    const qihse_sync_manager_t *manager,
    qihse_sync_statistics_t *statistics
);

/* Clean up old seen messages */
void qihse_sync_manager_cleanup_old_messages(
    qihse_sync_manager_t *manager,
    uint64_t max_age_ns
);

/* Perform anti-entropy synchronization */
int qihse_sync_manager_perform_anti_entropy(
    qihse_sync_manager_t *manager,
    const uint8_t *remote_bloom_filter,
    size_t filter_size,
    qihse_sync_message_t **missing_messages,
    size_t *missing_count
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_SYNC_GOSSIP_H */
