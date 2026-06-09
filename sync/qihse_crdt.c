#include "qihse_crdt.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <openssl/evp.h>
#endif

static qihse_trinary_dag_node_t* create_dag_node() {
    qihse_trinary_dag_node_t* node = calloc(1, sizeof(qihse_trinary_dag_node_t));
    return node;
}

static void compute_node_hash(qihse_trinary_dag_node_t* node) {
    if (!node) return;
    
#ifndef _WIN32
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    
    // Hash children root hashes if they exist
    if (node->left) EVP_DigestUpdate(ctx, node->left->hash, 48);
    if (node->middle) EVP_DigestUpdate(ctx, node->middle->hash, 48);
    if (node->right) EVP_DigestUpdate(ctx, node->right->hash, 48);
    
    // Hash local records
    for (size_t i = 0; i < node->record_count; i++) {
        EVP_DigestUpdate(ctx, node->records[i].vector_id, 16);
        
        // Endian-independent serialization of timestamp (Big-Endian)
        uint8_t ts_buf[8];
        uint64_t ts = node->records[i].timestamp;
        for (int j = 0; j < 8; j++) {
            ts_buf[7 - j] = (ts >> (j * 8)) & 0xFF;
        }
        EVP_DigestUpdate(ctx, ts_buf, 8);
        
        uint8_t d = node->records[i].is_deleted ? 1 : 0;
        EVP_DigestUpdate(ctx, &d, 1);
        EVP_DigestUpdate(ctx, node->records[i].payload_hash, 48);
    }
    
    unsigned int len = 48;
    EVP_DigestFinal_ex(ctx, node->hash, &len);
    EVP_MD_CTX_free(ctx);
#else
    memset(node->hash, 0, 48);
#endif
}

bool qihse_crdt_init(qihse_crdt_manager_t* manager) {
    if (!manager) return false;
    manager->dag_root = create_dag_node();
    manager->local_clock = 0;
    return manager->dag_root != NULL;
}

static void free_dag(qihse_trinary_dag_node_t* node) {
    if (!node) return;
    free_dag(node->left);
    free_dag(node->middle);
    free_dag(node->right);
    if (node->records) free(node->records);
    free(node);
}

void qihse_crdt_destroy(qihse_crdt_manager_t* manager) {
    if (!manager) return;
    free_dag(manager->dag_root);
    manager->dag_root = NULL;
}

bool qihse_crdt_upsert(qihse_crdt_manager_t* manager, const uint8_t vector_id[16], uint64_t timestamp, bool is_deleted, const uint8_t hash[48]) {
    if (!manager || !manager->dag_root) return false;
    
    // Simplistic mapping: We should traverse down the Trinary DAG based on the vector_id bits.
    // For this implementation, we will mock routing it to the root node's record list directly.
    // A true Trinary DAG would route vector_id trits (-1, 0, 1) down to the leaves.
    
    qihse_trinary_dag_node_t* target = manager->dag_root;
    
    // LWW (Last-Writer-Wins) resolution with binary search for sorted insertion
    size_t left = 0, right = target->record_count;
    bool found = false;
    size_t pos = 0;
    
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        int cmp = memcmp(target->records[mid].vector_id, vector_id, 16);
        if (cmp == 0) {
            found = true;
            pos = mid;
            break;
        } else if (cmp < 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    
    if (!found) {
        pos = left;
    }
    
    if (found) {
        // Conflict detected! Resolve via LWW clock.
        if (timestamp > target->records[pos].timestamp) {
            target->records[pos].timestamp = timestamp;
            target->records[pos].is_deleted = is_deleted;
            memcpy(target->records[pos].payload_hash, hash, 48);
            compute_node_hash(target); // Recompute Merkle Hash
            return true;
        }
        return false; // Incoming record is older, ignore.
    }
    
    // Insert new record, maintaining sorted order
    target->records = realloc(target->records, (target->record_count + 1) * sizeof(qihse_crdt_record_t));
    if (pos < target->record_count) {
        memmove(&target->records[pos + 1], &target->records[pos], (target->record_count - pos) * sizeof(qihse_crdt_record_t));
    }
    memcpy(target->records[pos].vector_id, vector_id, 16);
    target->records[pos].timestamp = timestamp;
    target->records[pos].is_deleted = is_deleted;
    memcpy(target->records[pos].payload_hash, hash, 48);
    target->record_count++;
    
    compute_node_hash(target); // Recompute Merkle Hash
    return true;
}

void qihse_crdt_get_root_hash(qihse_crdt_manager_t* manager, uint8_t out_hash[48]) {
    if (manager && manager->dag_root) {
        memcpy(out_hash, manager->dag_root->hash, 48);
    } else {
        memset(out_hash, 0, 48);
    }
}
