#include "qihse_document.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct qihse_document_store {
    qihse_kv_store_t* kv;
    qihse_doc_arena_block_t* arena_head;
    qihse_radix_node_t* index_root;
};

static uint64_t simple_hash(const char* str) {
    uint64_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

qihse_document_store_t* qihse_doc_store_create(qihse_kv_store_t* kv) {
    qihse_document_store_t* store = (qihse_document_store_t*)malloc(sizeof(qihse_document_store_t));
    if (!store) return NULL;
    
    store->kv = kv;
    
    /* Allocate initial arena block */
    store->arena_head = (qihse_doc_arena_block_t*)malloc(sizeof(qihse_doc_arena_block_t) + 4096);
    if (store->arena_head) {
        memset(store->arena_head, 0, sizeof(qihse_doc_arena_block_t));
        store->arena_head->capacity = 4096;
    }
    
    /* Allocate index root */
    store->index_root = (qihse_radix_node_t*)malloc(sizeof(qihse_radix_node_t));
    if (store->index_root) {
        memset(store->index_root, 0, sizeof(qihse_radix_node_t));
    }
    
    return store;
}

void qihse_doc_store_destroy(qihse_document_store_t* store) {
    if (!store) return;
    
    qihse_doc_arena_block_t* curr = store->arena_head;
    while (curr) {
        qihse_doc_arena_block_t* next = curr->next;
        free(curr);
        curr = next;
    }
    
    if (store->index_root) {
        free(store->index_root);
    }
    
    free(store);
}

static void update_bloom_filter(qihse_bloom_filter_t* bloom, const char* key) {
    uint64_t hash = simple_hash(key);
    int index = (hash / 64) % 8;
    int bit = hash % 64;
    bloom->bits[index] |= (1ULL << bit);
}

bool qihse_doc_store_insert_json(qihse_document_store_t* store, uint64_t doc_id, const char* json_payload) {
    if (!store || !json_payload) return false;
    
    int depth = 0;
    const char* ptr = json_payload;
    
    /* TODO: AVX-512 SIMD chunk scan */
    
    // Simple state machine to parse JSON keys and values for demo purposes
    while (*ptr) {
        if (*ptr == '{' || *ptr == '[') {
            depth++;
            if (depth > QIHSE_MAX_JSON_DEPTH) {
                return false; // Abort to prevent zip bombs
            }
            ptr++;
        } else if (*ptr == '}' || *ptr == ']') {
            depth--;
            if (depth < 0) depth = 0;
            ptr++;
        } else if (*ptr == '"') {
            // Parse string token (likely a key)
            ptr++;
            char key_str[1024] = {0};
            int len = 0;
            while (*ptr && *ptr != '"' && len < 1023) {
                key_str[len++] = *ptr++;
            }
            while (*ptr && *ptr != '"') ptr++;
            if (*ptr == '"') ptr++;
            
            // Skip whitespace
            while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;
            
            if (*ptr == ':') {
                ptr++;
                // Skip whitespace
                while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') ptr++;
                
                char val_str[2048] = {0};
                int vlen = 0;
                
                if (*ptr == '"') {
                    // String value
                    ptr++;
                    while (*ptr && *ptr != '"' && vlen < 2047) {
                        val_str[vlen++] = *ptr++;
                    }
                    while (*ptr && *ptr != '"') ptr++;
                    if (*ptr == '"') ptr++;
                } else if (*ptr == '{' || *ptr == '[') {
                    // Nested structure, just let the main loop handle it
                    continue;
                } else {
                    // Primitive value (number, boolean, null)
                    while (*ptr && *ptr != ',' && *ptr != '}' && *ptr != ']' && 
                           *ptr != ' ' && *ptr != '\n' && *ptr != '\r' && vlen < 2047) {
                        val_str[vlen++] = *ptr++;
                    }
                    while (*ptr && *ptr != ',' && *ptr != '}' && *ptr != ']' && 
                           *ptr != ' ' && *ptr != '\n' && *ptr != '\r') ptr++;
                }
                
                if (store->arena_head) {
                    update_bloom_filter(&store->arena_head->bloom, key_str);
                }
                
                char full_key[1280];
                snprintf(full_key, sizeof(full_key), "%llu:%s", (unsigned long long)doc_id, key_str);
                
                if (vlen >= 64) {
                    qihse_kv_set(store->kv, full_key, "[io_uring COLD TIER]");
                } else {
                    qihse_kv_set(store->kv, full_key, val_str);
                }
            }
        } else {
            ptr++;
        }
    }
    
    return true;
}
