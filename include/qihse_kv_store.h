#ifndef QIHSE_KV_STORE_H
#define QIHSE_KV_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_trinary_trie.h"
#include "qihse_auth.h"

/** Opaque handle for the QIHSE Key-Value Store. */
typedef struct qihse_kv_store qihse_kv_store_t;

qihse_kv_store_t* qihse_kv_store_create(void);
void qihse_kv_store_destroy(qihse_kv_store_t* store);

/*
 * Context-free writes are intentionally restricted to unclassified data.
 * Classified/SCI writes MUST use qihse_kv_set_user().
 */
bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value,
                  uint16_t classification, uint16_t sci_compartment);
bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value,
                       uint16_t classification, uint16_t sci_compartment,
                       qihse_user_t* user);

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static inline char* qihse_kv_get(qihse_kv_store_t* store, const char* key) {
    return qihse_kv_get_user(store, key, NULL);
}

bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static inline bool qihse_kv_del(qihse_kv_store_t* store, const char* key) {
    return qihse_kv_del_user(store, key, NULL);
}

bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
static inline bool qihse_kv_exists(qihse_kv_store_t* store, const char* key) {
    return qihse_kv_exists_user(store, key, NULL);
}

bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms,
                     qihse_user_t* user);
int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user);
void qihse_kv_sweep_expired(qihse_kv_store_t* store);

bool qihse_kv_store_is_under_attack(qihse_kv_store_t* store);

/*
 * Persistence is authorization-aware. *_user variants deny the whole export/import
 * if any live record is outside the caller's clearance/SCI. Legacy variants run
 * as NULL/unclassified and therefore cannot export/import classified records.
 */
int qihse_kv_save_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user);
int qihse_kv_load_user(qihse_kv_store_t* store, const char* filepath, qihse_user_t* user);
int qihse_kv_save(qihse_kv_store_t* store, const char* filepath);
int qihse_kv_load(qihse_kv_store_t* store, const char* filepath);

/* Bulk-load mode disables WAL buffering/automatic flush only; authorization rules remain. */
void qihse_kv_bulk_load_begin(qihse_kv_store_t* store);
void qihse_kv_bulk_load_end(qihse_kv_store_t* store);

typedef bool (*qihse_kv_iter_cb)(const char* key, const char* value, void* user_data);

/* Authorization-aware enumeration. Returns false on compaction/storage failure. */
bool qihse_kv_foreach_user(qihse_kv_store_t* store, qihse_user_t* user,
                           qihse_kv_iter_cb cb, void* user_data);
void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data);

size_t qihse_kv_clear_user(qihse_kv_store_t* store, qihse_user_t* user);
size_t qihse_kv_clear(qihse_kv_store_t* store);

size_t qihse_kv_count_user(qihse_kv_store_t* store, qihse_user_t* user);
size_t qihse_kv_count(qihse_kv_store_t* store);

#endif /* QIHSE_KV_STORE_H */
