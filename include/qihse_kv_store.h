#ifndef QIHSE_KV_STORE_H
#define QIHSE_KV_STORE_H

#include <stdbool.h>
#include "qihse_trinary_trie.h"
#include "qihse_auth.h"

/**
 * @brief Opaque handle for the QIHSE Key-Value Store.
 */
typedef struct qihse_kv_store qihse_kv_store_t;

/**
 * @brief Creates a new QIHSE Key-Value Store instance.
 * @return Pointer to the newly allocated store, or NULL on failure.
 */
qihse_kv_store_t* qihse_kv_store_create();

/**
 * @brief Destroys a QIHSE Key-Value Store and frees all associated memory.
 * @param store The store to destroy.
 */
void qihse_kv_store_destroy(qihse_kv_store_t* store);

/**
 * @brief Inserts or updates a key-value pair.
 * @param store The KV store instance.
 * @param key Null-terminated string key.
 * @param value Null-terminated string value.
 * @return true if successful, false otherwise.
 */
bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value, uint16_t classification, uint16_t sci_compartment);

/**
 * @brief Retrieves a value by key.
 * @param store The KV store instance.
 * @param key Null-terminated string key.
 * @return A newly allocated string containing the value, or NULL if not found. Caller must free().
 */
char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);

/**
 * @brief Deletes a key-value pair.
 * @param store The KV store instance.
 * @param key Null-terminated string key.
 * @return true if the key was deleted, false if it did not exist.
 */
bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);

/**
 * @brief Checks if a key exists in the store.
 * @param store The KV store instance.
 * @param key Null-terminated string key.
 * @return true if the key exists, false otherwise.
 */
bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);

/* Phase 3: TTL and Persistence */
/**
 * @brief Sets a Time-To-Live (TTL) expiration on a key.
 * @param store The KV store instance.
 * @param key The key to expire.
 * @param ttl_ms Time-to-live in milliseconds.
 * @return true if the TTL was set, false if the key doesn't exist.
 */
bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms, qihse_user_t* user);

/**
 * @brief Sweeps the store and removes all expired keys.
 * @param store The KV store instance.
 */
void qihse_kv_sweep_expired(qihse_kv_store_t* store);

/**
 * @brief Saves the entire KV store to a file on disk.
 * @param store The KV store instance.
 * @param filepath Path to the output file.
 * @return 0 on success, negative on error.
 */
int qihse_kv_save(qihse_kv_store_t* store, const char* filepath);

/**
 * @brief Loads a KV store snapshot from disk.
 * @param store The KV store instance.
 * @param filepath Path to the snapshot file.
 * @return 0 on success, negative on error.
 */
int qihse_kv_load(qihse_kv_store_t* store, const char* filepath);

#endif /* QIHSE_KV_STORE_H */
