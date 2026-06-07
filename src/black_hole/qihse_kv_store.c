#include "qihse_kv_store.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#define LSM_MEMTABLE_MAX (8 * 1024 * 1024) // 8MB

typedef struct {
    char* key;
    uint64_t expire_time_ms;
    uint16_t classification;
    uint16_t sci_compartment;
} key_entry_t;

struct qihse_kv_store {
    qihse_trinary_trie_t* trie;
    key_entry_t* keys;
    size_t num_keys;
    size_t capacity;
    
    // LSM-Tree Native Implementation
    FILE* wal_fd;
    size_t mem_usage;
    int sstable_counter;
};

static uint64_t current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

static void flush_memtable_to_sstable(qihse_kv_store_t* store) {
    if (store->num_keys == 0) return;
    
    char sst_path[256];
    snprintf(sst_path, sizeof(sst_path), "sstable_%d.db", store->sstable_counter++);
    
    qihse_kv_save(store, sst_path);
    
    // Reset MemTable
    qihse_trinary_trie_destroy(store->trie);
    store->trie = qihse_trinary_trie_create();
    for (size_t i = 0; i < store->num_keys; i++) free(store->keys[i].key);
    store->num_keys = 0;
    store->mem_usage = 0;
    
    // Truncate WAL
    if (store->wal_fd) fclose(store->wal_fd);
    store->wal_fd = fopen("wal.log", "w");
}

static void recover_from_wal(qihse_kv_store_t* store) {
    FILE* f = fopen("wal.log", "r");
    if (!f) return;
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "SET ", 4) == 0) {
            unsigned int classif, sci;
            char key_buf[256], val_buf[256];
            if (sscanf(line + 4, "%255s %255s %u %u", key_buf, val_buf, &classif, &sci) >= 2) {
                qihse_kv_set(store, key_buf, val_buf, classif, sci);
            }
        } else if (strncmp(line, "DEL ", 4) == 0) {
            char key[256];
            if (sscanf(line + 4, "%255s", key) == 1) {
                qihse_kv_del_user(store, key, NULL);
            }
        }
    }
    fclose(f);
}

qihse_kv_store_t* qihse_kv_store_create() {
    qihse_kv_store_t* store = (qihse_kv_store_t*)malloc(sizeof(qihse_kv_store_t));
    if (!store) return NULL;
    store->trie = qihse_trinary_trie_create();
    if (!store->trie) { free(store); return NULL; }
    store->keys = NULL;
    store->num_keys = 0;
    store->capacity = 0;
    
    store->wal_fd = fopen("wal.log", "a");
    store->mem_usage = 0;
    store->sstable_counter = 0;
    
    // Discover highest sstable counter
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (strncmp(dir->d_name, "sstable_", 8) == 0) {
                int id = atoi(dir->d_name + 8);
                if (id >= store->sstable_counter) store->sstable_counter = id + 1;
            }
        }
        closedir(d);
    }
    
    // Recover WAL
    recover_from_wal(store);
    
    return store;
}

void qihse_kv_store_destroy(qihse_kv_store_t* store) {
    if (store) {
        if (store->wal_fd) fclose(store->wal_fd);
        if (store->trie) qihse_trinary_trie_destroy(store->trie);
        for (size_t i = 0; i < store->num_keys; i++) free(store->keys[i].key);
        if (store->keys) free(store->keys);
        free(store);
    }
}

bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value, uint16_t classification, uint16_t sci_compartment) {
    if (!store || !store->trie || !key || !value) return false;
    
    if (store->wal_fd) {
        fprintf(store->wal_fd, "SET %s %s %u %u\n", key, value, (unsigned)classification, (unsigned)sci_compartment);
        fflush(store->wal_fd);
    }

    size_t out_size = 0;
    qihse_trinary_trie_search(store->trie, key, &out_size);
    if (!qihse_trinary_trie_insert(store->trie, key, (void*)value, strlen(value) + 1)) {
        return false;
    }

    store->mem_usage += strlen(key) + strlen(value) + 16;
    if (store->mem_usage > LSM_MEMTABLE_MAX) {
        flush_memtable_to_sstable(store);
    }
    
    bool exists = false;
    for (size_t i = 0; i < store->num_keys; i++) {
        if (strcmp(store->keys[i].key, key) == 0) {
            exists = true;
            store->keys[i].expire_time_ms = 0;
            store->keys[i].classification = classification;
            store->keys[i].sci_compartment = sci_compartment;
            break;
        }
    }
    if (!exists) {
        if (store->num_keys == store->capacity) {
            size_t new_capacity = store->capacity == 0 ? 16 : store->capacity * 2;
            key_entry_t* new_keys = (key_entry_t*)realloc(store->keys, new_capacity * sizeof(key_entry_t));
            if (!new_keys) return false;
            store->capacity = new_capacity;
            store->keys = new_keys;
        }
        store->keys[store->num_keys].key = strdup(key);
        store->keys[store->num_keys].expire_time_ms = 0;
        store->keys[store->num_keys].classification = classification;
        store->keys[store->num_keys].sci_compartment = sci_compartment;
        store->num_keys++;
    }
    return true;
}

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !store->trie || !key) return NULL;
    
    qihse_kv_sweep_expired(store);
    size_t out_size = 0;
    void* val = qihse_trinary_trie_search(store->trie, key, &out_size);
    if (val) {
        // Find auth info in memory
        for (size_t i = 0; i < store->num_keys; i++) {
            if (strcmp(store->keys[i].key, key) == 0) {
                if (user && !qihse_auth_can_access(user, store->keys[i].classification, store->keys[i].sci_compartment)) {
                    val = NULL; // Masked: pretend it doesn't exist in MemTable
                }
                break;
            }
        }
        if (val) return strdup((char*)val);
    }
    
    // LSM-Tree: Search SSTables (from newest to oldest)
    for (int i = store->sstable_counter - 1; i >= 0; i--) {
        char sst_path[256];
        snprintf(sst_path, sizeof(sst_path), "sstable_%d.db", i);
        FILE* f = fopen(sst_path, "r");
        if (!f) continue;
        
        char header[256];
        while (fgets(header, sizeof(header), f)) {
            size_t key_len, val_len;
            unsigned long long expire_time;
            unsigned int classif, sci;
            if (sscanf(header, "%zu %zu %llu %u %u", &key_len, &val_len, &expire_time, &classif, &sci) != 5) continue;
            
            char* f_key = (char*)malloc(key_len + 1);
            char* f_val = (char*)malloc(val_len + 1);
            if (fread(f_key, 1, key_len, f) != key_len) { free(f_key); free(f_val); break; }
            f_key[key_len] = '\0';
            if (fread(f_val, 1, val_len, f) != val_len) { free(f_key); free(f_val); break; }
            f_val[val_len] = '\0';
            fgetc(f);
            
            if (strcmp(f_key, key) == 0) {
                if (user && !qihse_auth_can_access(user, classif, sci)) {
                    free(f_key);
                    free(f_val);
                    continue; // Masked: pretend it doesn't exist, keep searching to match "not found" timing
                }
                free(f_key);
                fclose(f);
                return f_val; // Found in older SSTable
            }
            free(f_key);
            free(f_val);
        }
        fclose(f);
    }
    return NULL;
}

bool qihse_kv_del_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !store->trie || !key) return false;
    
    // Check auth first
    bool has_auth = false;
    bool found = false;
    for (size_t i = 0; i < store->num_keys; i++) {
        if (strcmp(store->keys[i].key, key) == 0) {
            found = true;
            if (!user || qihse_auth_can_access(user, store->keys[i].classification, store->keys[i].sci_compartment)) {
                has_auth = true;
            }
            break;
        }
    }
    
    // If it exists but we don't have auth, pretend we couldn't delete it because it doesn't exist
    if (found && !has_auth) return false;
    
    if (store->wal_fd) {
        fprintf(store->wal_fd, "DEL %s\n", key);
        fflush(store->wal_fd);
    }

    size_t out_size = 0;
    void* val = qihse_trinary_trie_search(store->trie, key, &out_size);
    if (val) {
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

bool qihse_kv_exists_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    char* val = qihse_kv_get_user(store, key, user);
    if (val) {
        free(val);
        return true;
    }
    return false;
}

bool qihse_kv_expire(qihse_kv_store_t* store, const char* key, uint64_t ttl_ms, qihse_user_t* user) {
    if (!store || !key) return false;
    if (!qihse_kv_exists_user(store, key, NULL)) return false;

    uint64_t now = current_time_ms();
    bool has_auth = false;
    bool found = false;
    for (size_t i = 0; i < store->num_keys; i++) {
        if (strcmp(store->keys[i].key, key) == 0) {
            found = true;
            if (!user || qihse_auth_can_access(user, store->keys[i].classification, store->keys[i].sci_compartment)) {
                has_auth = true;
                store->keys[i].expire_time_ms = now + ttl_ms;
            }
            break;
        }
    }
    
    if (found && !has_auth) return false;
    if (found && has_auth) return true;
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
        size_t out_size = 0;
        char* val = (char*)qihse_trinary_trie_search(store->trie, store->keys[i].key, &out_size);
        if (val) {
            fprintf(f, "%zu %zu %llu %u %u\n", strlen(store->keys[i].key), strlen(val), (unsigned long long)store->keys[i].expire_time_ms, (unsigned)store->keys[i].classification, (unsigned)store->keys[i].sci_compartment);
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
        unsigned int classif, sci;
        if (sscanf(header, "%zu %zu %llu %u %u", &key_len, &val_len, &expire_time, &classif, &sci) != 5) continue;
        
        char* key = (char*)malloc(key_len + 1);
        char* val = (char*)malloc(val_len + 1);
        if (!key || !val) { free(key); free(val); break; }
        
        if (fread(key, 1, key_len, f) != key_len) { free(key); free(val); break; }
        key[key_len] = '\0';
        if (fread(val, 1, val_len, f) != val_len) { free(key); free(val); break; }
        val[val_len] = '\0';
        fgetc(f);
        
        qihse_kv_set(store, key, val, classif, sci);
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
