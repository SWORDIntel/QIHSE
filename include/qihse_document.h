#ifndef QIHSE_DOCUMENT_H
#define QIHSE_DOCUMENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_kv_store.h"

/* Security Limit: Prevent recursive Zip Bombs */
#define QIHSE_MAX_JSON_DEPTH 64

/**
 * @brief 64-byte aligned Bloom Filter for L1 cache optimization.
 */
typedef struct __attribute__((aligned(64))) {
    uint64_t bits[8]; /* 64 bytes total */
} qihse_bloom_filter_t;

/**
 * @brief 64-byte aligned Radix Trie Node for path compression.
 */
typedef struct __attribute__((aligned(64))) qihse_radix_node {
    uint64_t path_hash;
    struct qihse_radix_node* children[3];
    void* value;
    uint32_t path_len;
    uint32_t is_leaf;
} qihse_radix_node_t;

/**
 * @brief 64-byte aligned Arena Block Header with integrated Bloom Filter.
 */
typedef struct __attribute__((aligned(64))) qihse_doc_arena_block {
    qihse_bloom_filter_t bloom;
    struct qihse_doc_arena_block* next;
    size_t used;
    size_t capacity;
    /* Data payload follows implicitly */
} qihse_doc_arena_block_t;

/**
 * @brief Opaque handle for the QIHSE Document Store.
 */
typedef struct qihse_document_store qihse_document_store_t;

/**
 * @brief Initialize the Document Store.
 * @param kv Pointer to the underlying KV store for hot tier routing.
 * @return Pointer to the document store instance.
 */
qihse_document_store_t* qihse_doc_store_create(qihse_kv_store_t* kv);

/**
 * @brief Destroy the Document Store.
 */
void qihse_doc_store_destroy(qihse_document_store_t* store);

/**
 * @brief Ingest a raw JSON payload, flattening it securely.
 * Applies SIMD scanning, checks QIHSE_MAX_JSON_DEPTH, and updates Bloom filters.
 * @param store Document store instance.
 * @param doc_id Unique ID for the document.
 * @param json_payload Null-terminated JSON string.
 * @return true on success.
 */
bool qihse_doc_store_insert_json(qihse_document_store_t* store, uint64_t doc_id, const char* json_payload);

#endif /* QIHSE_DOCUMENT_H */
