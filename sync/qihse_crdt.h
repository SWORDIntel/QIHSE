#ifndef QIHSE_CRDT_H
#define QIHSE_CRDT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Conflict-free Replicated Data Type (CRDT) LWW-Set
 * 
 * Implements a Last-Writer-Wins Element Set for safe, decentralized 
 * state replication in disconnected edge environments. 
 */
typedef struct qihse_crdt_record_s {
    uint8_t vector_id[16];   // UUID of the vector/document
    uint64_t timestamp;      // LWW logical/physical clock
    bool is_deleted;         // Tombstone flag
    uint8_t payload_hash[48];// SHA-384 of the actual data
} qihse_crdt_record_t;

/**
 * @brief Trinary Merkle DAG Node
 * 
 * Uses QIHSE's Trinary logic (Left, Middle, Right) to efficiently branch 
 * and reconcile state differences between peers without transferring full datasets.
 */
typedef struct qihse_trinary_dag_node_s {
    uint8_t hash[48]; // SHA-384 of this node and all its children
    struct qihse_trinary_dag_node_s *left;   // Trit -1
    struct qihse_trinary_dag_node_s *middle; // Trit  0
    struct qihse_trinary_dag_node_s *right;  // Trit +1
    
    qihse_crdt_record_t* records;
    size_t record_count;
} qihse_trinary_dag_node_t;

typedef struct qihse_crdt_manager_s {
    qihse_trinary_dag_node_t *dag_root;
    uint64_t local_clock;
} qihse_crdt_manager_t;

/**
 * @brief Initialize the CRDT Manager.
 */
bool qihse_crdt_init(qihse_crdt_manager_t* manager);

/**
 * @brief Insert or Update a record using LWW rules.
 * @return true if the local state was modified, false if the incoming record was older.
 */
bool qihse_crdt_upsert(qihse_crdt_manager_t* manager, const uint8_t vector_id[16], uint64_t timestamp, bool is_deleted, const uint8_t hash[48]);

/**
 * @brief Generates the root hash for anti-entropy comparison.
 */
void qihse_crdt_get_root_hash(qihse_crdt_manager_t* manager, uint8_t out_hash[48]);

/**
 * @brief Destroy the CRDT manager and free the DAG.
 */
void qihse_crdt_destroy(qihse_crdt_manager_t* manager);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_CRDT_H
