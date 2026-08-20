#ifndef QIHSE_HASH_INDEX_H
#define QIHSE_HASH_INDEX_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file qihse_hash_index.h
 * @brief Phase 3.2 — Open-addressed hash index with linear probing.
 *
 * Supports int64 and variable-length string keys mapped to uint64_t row IDs.
 * Point lookups only (no range scans). Dynamic resizing when load factor
 * exceeds 0.7. Tombstone markers for deletions. Thread-safe via rwlock.
 */

/** Opaque handle for a hash index. */
typedef struct qihse_hash_index qihse_hash_index_t;

/** Key type selector. */
typedef enum {
    QIHSE_HASH_KEY_INT64 = 0,
    QIHSE_HASH_KEY_STRING = 1
} qihse_hash_key_type_t;

/**
 * @brief Creates a new hash index.
 * @param key_type Whether keys are int64 or string.
 * @param initial_capacity Starting number of slots (0 => 1024).
 * @return New index handle, or NULL on failure.
 */
qihse_hash_index_t* qihse_hash_index_create(qihse_hash_key_type_t key_type,
                                            size_t initial_capacity);

/** Destroys the hash index and frees all memory. */
void qihse_hash_index_destroy(qihse_hash_index_t* idx);

/**
 * @brief Inserts or replaces a key -> row_id mapping.
 * @return true on success, false on allocation failure.
 */
bool qihse_hash_index_insert(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t row_id);

/**
 * @brief Point lookup.
 * @return true if found (row_id written to *out), false otherwise.
 */
bool qihse_hash_index_lookup(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t* out);

/**
 * @brief Deletes a key (marks slot as tombstone).
 * @return true if the key was present, false otherwise.
 */
bool qihse_hash_index_delete(qihse_hash_index_t* idx,
                             const void* key, size_t key_len,
                             uint64_t* row_id_out);

/** @return number of live entries (excluding tombstones). */
size_t qihse_hash_index_size(const qihse_hash_index_t* idx);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_HASH_INDEX_H */
