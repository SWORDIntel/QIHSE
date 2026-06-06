#ifndef QIHSE_TRINARY_TRIE_H
#define QIHSE_TRINARY_TRIE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Opaque handle for the QIHSE Trinary Trie structure.
 */
typedef struct qihse_trinary_trie qihse_trinary_trie_t;

/**
 * @brief Creates a new Trinary Trie instance.
 * @return Pointer to the allocated trie, or NULL on failure.
 */
qihse_trinary_trie_t* qihse_trinary_trie_create();

/**
 * @brief Destroys a Trinary Trie and frees all associated memory.
 * @param trie The trie to destroy.
 */
void qihse_trinary_trie_destroy(qihse_trinary_trie_t* trie);

/**
 * @brief Inserts a key-value pair into the Trinary Trie.
 * @param trie The trie instance.
 * @param key Null-terminated string key.
 * @param value Pointer to the value buffer.
 * @param value_size Size of the value buffer in bytes.
 * @return true if successfully inserted or updated, false otherwise.
 */
bool qihse_trinary_trie_insert(qihse_trinary_trie_t* trie, const char* key, void* value, size_t value_size);

/**
 * @brief Searches for a key in the Trinary Trie.
 * @param trie The trie instance.
 * @param key Null-terminated string key.
 * @param out_size Pointer to receive the size of the found value (can be NULL).
 * @return Pointer to the value, or NULL if not found.
 */
void* qihse_trinary_trie_search(qihse_trinary_trie_t* trie, const char* key, size_t* out_size);

/**
 * @brief Deletes a key-value pair from the Trinary Trie.
 * @param trie The trie instance.
 * @param key Null-terminated string key.
 * @return true if deleted, false if the key was not found.
 */
bool qihse_trinary_trie_delete(qihse_trinary_trie_t* trie, const char* key);

#endif /* QIHSE_TRINARY_TRIE_H */
