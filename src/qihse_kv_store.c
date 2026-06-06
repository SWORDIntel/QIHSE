#include "qihse_kv_store.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

typedef struct {
    char* key;
    uint64_t expire_time_ms;
} key_entry_t;

struct qihse_kv_store {
    qihse_trinary_trie_t* trie;
    key_entry_t* keys;
    size_t num_keys;
    size_t capacity;
};

static uint64_t current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

qihse_kv_store_t* qihse_kv_store_create() {
    qihse_kv_store_t* store = (qihse_kv_store_t*)malloc(sizeof(qihse_kv_store_t));
    if (!store) {
        return NULL;
    }
    store->trie = qihse_trinary_trie_create();
    if (!store->trie) {
        free(store);
        return NULL;
    }
    store->keys = NULL;
    store->num_keys = 0;
    store->capacity = 0;
    return store;
}

void qihse_kv_store_destroy(qihse_kv_store_t* store) {
    if (store) {
        if (store->trie) {
            qihse_trinary_trie_destroy(store->trie);
        }
        for (size_t i = 0; i < store->num_keys; i++) {
            free(store->keys[i].key);
        }
        if (store->keys) {
            free(store->keys);
        }
        free(store);
    }
}

bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value) {
    if (!store || !store->trie || !key || !value) {
        return false;
    }

    size_t out_size = 0;
    void* old_val = qihse_trinary_trie_search(store->trie, key, &out_size);
    if (old_val) {
        free(old_val);
    }

    char* dup_val = strdup(value);
    if (!dup_val) {
        return false;
    }

    bool result = qihse_trinary_trie_insert(store->trie, key, dup_val, strlen(dup_val) + 1);
    if (!result) {
        free(dup_val);
        return false;
    }
    
    bool exists = false;
    for (size_t i = 0; i < store->num_keys; i++) {
        if (strcmp(store->keys[i].key, key) == 0) {
            exists = true;
            store->keys[i].expire_time_ms = 0;
            break;
        }
    }
    if (!exists) {
        if (store->num_keys == store->capacity) {
            store->capacity = store->capacity == 0 ? 16 : store->capacity * 2;
            store->keys = (key_entry_t*)realloc(store->keys, store->capacity * sizeof(key_entry_t));
        }
        store->keys[store->num_keys].key = strdup(key);
        store->keys[store->num_keys].expire_time_ms = 0;
        store->num_keys++;
    }
    
    return true;
}

char* qihse_kv_get(qihse_kv_store_t* store, const char* key) {
    if (!store || !store->trie || !key) {
        return NULL;
    }
    
    size_t out_size = 0;
    void* val = qihse_trinary_trie_search(store->trie, key, &out_size);
    return (char*)val;
}

bool qihse_kv_del(qihse_kv_store_t* store, const char* key) {
    if (!store || !store->trie || !key) {
        return false;
    }
    size_t out_size = 0;
    void* val = qihse_trinary_trie_search(store->trie, key, &out_size);
    if (val) {
        free(val);
        bool deleted = qihse_trinary_trie_delete(store->trie, key);
        if (deleted) {
            for (size_t i = 0; i < store->num_keys; i++) {
                if (strcmp(store->keys[i].key, key) == 0) {
                    free(store->keys[i].key);
                    store->keys[i] = store->keys[store->num_keys - 1];
                    store->num_keys--;
                    break;
                }
            }
        }
        return deleted;
    }
    return false;
}

bool qihse_kv_exists(qihse_kv_store_t* store, const char* key) {
    if (!store || !store->trie || !key) {
        return false;
    }

    size_t out_size = 0;
    void* val = qihse_trinary_trie_search(store->trie, key, &out_size);
    return val != NULL;
}

bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms) {
    if (!store || !key) return false;
    if (!qihse_kv_exists(store, key)) return false;

    uint64_t now = current_time_ms();
    for (size_t i = 0; i < store->num_keys; i++) {
        if (strcmp(store->keys[i].key, key) == 0) {
            store->keys[i].expire_time_ms = now + ttl_ms;
            return true;
        }
    }
    return false;
}

void qihse_kv_sweep_expired(qihse_kv_store_t* store) {
    if (!store) return;
    uint64_t now = current_time_ms();
    for (size_t i = 0; i < store->num_keys; ) {
        if (store->keys[i].expire_time_ms > 0 && store->keys[i].expire_time_ms <= now) {
            size_t out_size = 0;
            void* val = qihse_trinary_trie_search(store->trie, store->keys[i].key, &out_size);
            if (val) {
                free(val);
                qihse_trinary_trie_delete(store->trie, store->keys[i].key);
            }
            
            free(store->keys[i].key);
            store->keys[i] = store->keys[store->num_keys - 1];
            store->num_keys--;
        } else {
            i++;
        }
    }
}

int qihse_kv_save(qihse_kv_store_t* store, const char* filepath) {
    if (!store || !filepath) return -1;
    
    qihse_kv_sweep_expired(store);
    
    FILE* f = fopen(filepath, "w");
    if (!f) return -1;
    
    for (size_t i = 0; i < store->num_keys; i++) {
        char* val = qihse_kv_get(store, store->keys[i].key);
        if (val) {
            fprintf(f, "%zu %zu %llu\n", strlen(store->keys[i].key), strlen(val), (unsigned long long)store->keys[i].expire_time_ms);
            fwrite(store->keys[i].key, 1, strlen(store->keys[i].key), f);
            fwrite(val, 1, strlen(val), f);
            fprintf(f, "\n");
        }
    }
    fclose(f);
    return 0;
}

int qihse_kv_load(qihse_kv_store_t* store, const char* filepath) {
    if (!store || !filepath) return -1;
    
    FILE* f = fopen(filepath, "r");
    if (!f) return -1;
    
    char header[256];
    while (fgets(header, sizeof(header), f)) {
        size_t key_len, val_len;
        unsigned long long expire_time;
        if (sscanf(header, "%zu %zu %llu", &key_len, &val_len, &expire_time) != 3) {
            continue;
        }
        
        char* key = (char*)malloc(key_len + 1);
        char* val = (char*)malloc(val_len + 1);
        if (!key || !val) {
            free(key);
            free(val);
            break;
        }
        
        if (fread(key, 1, key_len, f) != key_len) { free(key); free(val); break; }
        key[key_len] = '\0';
        
        if (fread(val, 1, val_len, f) != val_len) { free(key); free(val); break; }
        val[val_len] = '\0';
        
        fgetc(f);
        
        qihse_kv_set(store, key, val);
        if (expire_time > 0) {
            for (size_t i = 0; i < store->num_keys; i++) {
                if (strcmp(store->keys[i].key, key) == 0) {
                    store->keys[i].expire_time_ms = (uint64_t)expire_time;
                    break;
                }
            }
        }
        
        free(key);
        free(val);
    }
    
    fclose(f);
    
    qihse_kv_sweep_expired(store);
    
    return 0;
}
