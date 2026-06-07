#ifndef QIHSE_CLUSTER_H
#define QIHSE_CLUSTER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_sync_gossip.h"

/* Magic bytes to identify QIHSE payloads over the QIHSE sync protocol: "QIHSE" */
#define QIHSE_CLUSTER_MAGIC_LEN 5
extern const uint8_t QIHSE_CLUSTER_MAGIC[QIHSE_CLUSTER_MAGIC_LEN];

/**
 * @brief Payload types for QIHSE clustering.
 */
typedef enum {
    QIHSE_PAYLOAD_KV_SET = 1,
    QIHSE_PAYLOAD_KV_DEL = 2,
    QIHSE_PAYLOAD_VEC_SET = 3,
    QIHSE_PAYLOAD_VEC_DEL = 4
} qihse_cluster_payload_type_t;

/**
 * @brief Initialize the QIHSE clustering node over QIHSE sync.
 * @param node_id Unique identifier for this node.
 * @param kv Pointer to the local KV store.
 * @param vdb Pointer to the local Vector DB.
 * @return true on success, false on failure.
 */
bool qihse_cluster_init(const char* node_id, qihse_kv_store_t* kv, qihse_vector_db_t vdb);

/**
 * @brief Join an existing QIHSE sync cluster.
 * @param peer_ip IP address of the peer.
 * @param peer_port QIHSE sync port of the peer.
 * @return true on success.
 */
bool qihse_cluster_join(const char* peer_ip, uint16_t peer_port);

/**
 * @brief Broadcasts a KV SET operation securely via QIHSE sync.
 * @param key The key string.
 * @param value The value string.
 */
void qihse_cluster_broadcast_kv_set(const char* key, const char* value);

/**
 * @brief Broadcasts a Vector SET operation securely via QIHSE sync.
 * @param id The vector ID.
 * @param vector Float array of the vector.
 * @param dims Number of dimensions.
 */
void qihse_cluster_broadcast_vec_set(uint64_t id, const float* vector, size_t dims);

/**
 * @brief Process an incoming QIHSE sync gossip payload.
 * Rejects payloads without the QIHSE magic bytes to prevent crosstalk 
 * with other applications using the QIHSE sync protocol.
 * @param payload Raw payload buffer.
 * @param payload_size Size of the buffer.
 */
void qihse_cluster_receive_payload(const uint8_t* payload, size_t payload_size);

#endif /* QIHSE_CLUSTER_H */
