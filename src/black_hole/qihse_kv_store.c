#include "qihse_kv_store.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include "../broad_oak/qihse_quantum_defense.h"

#define LSM_MEMTABLE_MAX (512 * 1024)        // 512KB MemTable flush threshold
#define WAL_BUFFER_FLUSH_THRESHOLD 65536     // 64KB write buffer

/* Optimized in-node KV payload combining value, auth classification, and expiry */
typedef struct {
    uint16_t classification;
    uint16_t sci_compartment;
    uint64_t expire_time_ms;
    char val[];
} kv_payload_t;

struct qihse_kv_store {
    qihse_trinary_trie_t* trie;
    
    // LSM-Tree Native Implementation
    FILE* wal_fd;
    size_t wal_unflushed_bytes;
    size_t mem_usage;
    int sstable_counter;
    qihse_quantum_defense_ctx_t* qdd_ctx;
    bool bulk_load_mode;
};

static const char* get_qihse_data_dir(void) {
    static char data_dir[256] = {0};
    if (data_dir[0]) return data_dir;
    
    const char* env = getenv("QIHSE_DATA_DIR");
    if (env && env[0]) {
        snprintf(data_dir, sizeof(data_dir), "%s%s", env, env[strlen(env)-1] == '/' ? "" : "/");
        return data_dir;
    }
    
    if (access("/var/lib/qihse", W_OK | R_OK) == 0) {
        strncpy(data_dir, "/var/lib/qihse/", sizeof(data_dir) - 1);
        return data_dir;
    }
    
    // Ensure fallback local directory exists
    mkdir("data", 0755);
    mkdir("data/qihse", 0755);
    strncpy(data_dir, "data/qihse/", sizeof(data_dir) - 1);
    return data_dir;
}

static inline uint64_t current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (uint64_t)(tv.tv_usec) / 1000;
}

static void flush_wal_buffer(qihse_kv_store_t* store) {
    if (store && store->wal_fd && store->wal_unflushed_bytes > 0) {
        fflush(store->wal_fd);
        store->wal_unflushed_bytes = 0;
    }
}

static void flush_memtable_to_sstable(qihse_kv_store_t* store) {
    if (!store || !store->trie) return;
    
    const char* dir = get_qihse_data_dir();
    char sst_path[256];
    snprintf(sst_path, sizeof(sst_path), "%ssstable_%d.db", dir, store->sstable_counter++);
    
    qihse_kv_save(store, sst_path);
    
    // Reset MemTable
    qihse_trinary_trie_destroy(store->trie);
    store->trie = qihse_trinary_trie_create();
    store->mem_usage = 0;
    store->wal_unflushed_bytes = 0;
    
    // Truncate WAL
    if (store->wal_fd) fclose(store->wal_fd);
    char wal_path[256];
    snprintf(wal_path, sizeof(wal_path), "%swal.log", dir);
#ifndef _WIN32
    int tfd = open(wal_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (tfd >= 0) store->wal_fd = fdopen(tfd, "w");
    else store->wal_fd = NULL;
#else
    store->wal_fd = fopen(wal_path, "w");
#endif
}

static void recover_from_wal(qihse_kv_store_t* store) {
    const char* dir = get_qihse_data_dir();
    char wal_path[256];
    snprintf(wal_path, sizeof(wal_path), "%swal.log", dir);
#ifndef _WIN32
    int wfd = open(wal_path, O_RDONLY | O_NOFOLLOW);
    if (wfd < 0) return;
    FILE* f = fdopen(wfd, "r");
    if (!f) { close(wfd); return; }
#else
    FILE* f = fopen(wal_path, "r");
    if (!f) return;
#endif
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "SET ", 4) == 0) {
            unsigned int classif = 0, sci = 0;
            char key_buf[256], val_buf[2048];
            if (sscanf(line + 4, "%255s %2047s %u %u", key_buf, val_buf, &classif, &sci) >= 2) {
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

qihse_kv_store_t* qihse_kv_store_create(void) {
    qihse_kv_store_t* store = (qihse_kv_store_t*)calloc(1, sizeof(qihse_kv_store_t));
    if (!store) return NULL;
    store->trie = qihse_trinary_trie_create();
    if (!store->trie) { free(store); return NULL; }
    store->bulk_load_mode = false;
    
    store->wal_fd = NULL;
    store->wal_unflushed_bytes = 0;
    store->mem_usage = 0;
    store->sstable_counter = 0;
    store->qdd_ctx = qihse_qdd_init();
    
    const char* dir_path = get_qihse_data_dir();
    
    // Discover highest sstable counter
    DIR *d = opendir(dir_path);
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (strncmp(dir->d_name, "sstable_", 8) == 0) {
                char *endp;
                long id = strtol(dir->d_name + 8, &endp, 10);
                if (*endp != '.' && *endp != '\0') continue;
                if (id < 0 || id > 1000000) continue;
                if (id >= store->sstable_counter) store->sstable_counter = id + 1;
            }
        }
        closedir(d);
    }
    
    // Recover WAL
    recover_from_wal(store);
    
    // Rotate WAL — start fresh, archive old log for debugging
    char wal_path[256], wal_old_path[256];
    snprintf(wal_path, sizeof(wal_path), "%swal.log", dir_path);
    snprintf(wal_old_path, sizeof(wal_old_path), "%swal.log.old", dir_path);
    rename(wal_path, wal_old_path);
#ifndef _WIN32
    int rfd = open(wal_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (rfd >= 0) store->wal_fd = fdopen(rfd, "w");
    else store->wal_fd = NULL;
#else
    store->wal_fd = fopen(wal_path, "w");
#endif
    
    return store;
}

void qihse_kv_store_destroy(qihse_kv_store_t* store) {
    if (store) {
        if (store->qdd_ctx) qihse_qdd_free(store->qdd_ctx);
        if (store->wal_fd) {
            flush_wal_buffer(store);
            fclose(store->wal_fd);
        }
        if (store->trie) qihse_trinary_trie_destroy(store->trie);
        free(store);
    }
}

static bool qihse_kv_set_with_expiry(qihse_kv_store_t* store, const char* key, const char* value, uint64_t ttl_ms, uint16_t classification, uint16_t sci_compartment) {
    if (!store || !store->trie || !key || !value) return false;
    
    // Buffered WAL logging
    if (store->wal_fd && !store->bulk_load_mode) {
        int written = fprintf(store->wal_fd, "SET %s %s %u %u\n", key, value, (unsigned)classification, (unsigned)sci_compartment);
        if (written > 0) store->wal_unflushed_bytes += (size_t)written;
        if (store->wal_unflushed_bytes >= WAL_BUFFER_FLUSH_THRESHOLD) {
            flush_wal_buffer(store);
        }
    }

    size_t val_len = strlen(value);
    size_t payload_len = sizeof(kv_payload_t) + val_len + 1;
    kv_payload_t* payload = (kv_payload_t*)malloc(payload_len);
    if (!payload) return false;

    payload->classification = classification;
    payload->sci_compartment = sci_compartment;
    payload->expire_time_ms = ttl_ms > 0 ? current_time_ms() + ttl_ms : 0;
    memcpy(payload->val, value, val_len + 1);

    bool inserted = qihse_trinary_trie_insert(store->trie, key, payload, payload_len);
    free(payload);
    if (!inserted) return false;

    store->mem_usage += strlen(key) + val_len + sizeof(kv_payload_t);
    if (!store->bulk_load_mode && store->mem_usage > LSM_MEMTABLE_MAX) {
        flush_memtable_to_sstable(store);
    }
    
    return true;
}

bool qihse_kv_set(qihse_kv_store_t* store, const char* key, const char* value, uint16_t classification, uint16_t sci_compartment) {
    return qihse_kv_set_with_expiry(store, key, value, 0, classification, sci_compartment);
}

void qihse_kv_bulk_load_begin(qihse_kv_store_t* store) {
    if (store) store->bulk_load_mode = true;
}

void qihse_kv_bulk_load_end(qihse_kv_store_t* store) {
    if (store) {
        store->bulk_load_mode = false;
        flush_wal_buffer(store);
    }
}

bool qihse_kv_set_user(qihse_kv_store_t* store, const char* key, const char* value, uint16_t classification, uint16_t sci_compartment, qihse_user_t* user) {
    if (!store || !key) return false;
    
    // Check access on existing key if present
    size_t out_sz = 0;
    kv_payload_t* existing = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &out_sz);
    if (existing) {
        if (!qihse_auth_can_access(user, existing->classification, existing->sci_compartment)) {
            return false;
        }
    }
    
    return qihse_kv_set_with_expiry(store, key, value, 0, classification, sci_compartment);
}

char* qihse_kv_get_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !store->trie || !key) return NULL;
    
    // QDD Access Tracking
    if (store->qdd_ctx) {
        uint64_t key_hash = 14695981039346656037ULL;
        for (const unsigned char* p = (const unsigned char*)key; *p; ++p) {
            key_hash ^= (uint64_t)*p;
            key_hash *= 1099511628211ULL;
        }
        qihse_qdd_report_access(store->qdd_ctx, key_hash, "0.0.0.0");
    }
    
    // Fast O(key_len) Trinary Trie point lookup
    size_t out_size = 0;
    kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &out_size);
    
    if (p) {
        uint64_t now = current_time_ms();
        if (p->expire_time_ms > 0 && p->expire_time_ms <= now) {
            qihse_trinary_trie_delete(store->trie, key);
            return NULL;
        }
        if (!qihse_auth_can_access(user, p->classification, p->sci_compartment)) {
            return NULL; // Masked unauthorized
        }
        return strdup(p->val);
    }
    
    // LSM-Tree: Search SSTables (from newest to oldest on disk)
    const char* dir = get_qihse_data_dir();
    for (int i = store->sstable_counter - 1; i >= 0; i--) {
        char sst_path[256];
        snprintf(sst_path, sizeof(sst_path), "%ssstable_%d.db", dir, i);
#ifndef _WIN32
        int sfd = open(sst_path, O_RDONLY | O_NOFOLLOW);
        if (sfd < 0) continue;
        FILE* f = fdopen(sfd, "r");
        if (!f) { close(sfd); continue; }
#else
        FILE* f = fopen(sst_path, "r");
        if (!f) continue;
#endif
        
        char header[256];
        while (fgets(header, sizeof(header), f)) {
            size_t key_len, val_len;
            unsigned long long expire_time;
            unsigned int classif, sci;
            if (sscanf(header, "%zu %zu %llu %u %u", &key_len, &val_len, &expire_time, &classif, &sci) != 5) continue;
            if (key_len > 1048576 || val_len > 16777216) continue;
            
            char* f_key = (char*)malloc(key_len + 1);
            char* f_val = (char*)malloc(val_len + 1);
            if (!f_key || !f_val) { free(f_key); free(f_val); break; }
            if (fread(f_key, 1, key_len, f) != key_len) { free(f_key); free(f_val); break; }
            f_key[key_len] = '\0';
            if (fread(f_val, 1, val_len, f) != val_len) { free(f_key); free(f_val); break; }
            f_val[val_len] = '\0';
            fgetc(f);
            
            if (strcmp(f_key, key) == 0) {
                if (!qihse_auth_can_access(user, classif, sci)) {
                    free(f_key);
                    free(f_val);
                    break;
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
    
    size_t out_size = 0;
    kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &out_size);
    if (p) {
        if (!qihse_auth_can_access(user, p->classification, p->sci_compartment)) {
            return false;
        }
    }
    
    if (store->wal_fd && !store->bulk_load_mode) {
        int written = fprintf(store->wal_fd, "DEL %s\n", key);
        if (written > 0) store->wal_unflushed_bytes += (size_t)written;
        if (store->wal_unflushed_bytes >= WAL_BUFFER_FLUSH_THRESHOLD) {
            flush_wal_buffer(store);
        }
    }

    if (p) {
        return qihse_trinary_trie_delete(store->trie, key);
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
    if (!store || !store->trie || !key) return false;

    size_t out_size = 0;
    kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &out_size);
    if (!p) return false;

    if (!qihse_auth_can_access(user, p->classification, p->sci_compartment)) {
        return false;
    }
    
    p->expire_time_ms = current_time_ms() + ttl_ms;
    return true;
}

int64_t qihse_kv_ttl_ms_user(qihse_kv_store_t* store, const char* key, qihse_user_t* user) {
    if (!store || !store->trie || !key) return -2;
    uint64_t now = current_time_ms();
    size_t out_size = 0;
    kv_payload_t* p = (kv_payload_t*)qihse_trinary_trie_search(store->trie, key, &out_size);
    if (p) {
        if (!qihse_auth_can_access(user, p->classification, p->sci_compartment)) return -2;
        if (p->expire_time_ms == 0) return -1;
        if (p->expire_time_ms <= now) {
            qihse_trinary_trie_delete(store->trie, key);
            return -2;
        }
        uint64_t remaining = p->expire_time_ms - now;
        return remaining > INT64_MAX ? INT64_MAX : (int64_t)remaining;
    }

    const char* dir = get_qihse_data_dir();
    for (int i = store->sstable_counter - 1; i >= 0; i--) {
        char sst_path[256];
        snprintf(sst_path, sizeof(sst_path), "%ssstable_%d.db", dir, i);
#ifndef _WIN32
        int sfd = open(sst_path, O_RDONLY | O_NOFOLLOW);
        if (sfd < 0) continue;
        FILE* f = fdopen(sfd, "r");
        if (!f) { close(sfd); continue; }
#else
        FILE* f = fopen(sst_path, "r");
        if (!f) continue;
#endif
        char header[256];
        while (fgets(header, sizeof(header), f)) {
            size_t key_len;
            size_t val_len;
            unsigned long long expire_time;
            unsigned int classif;
            unsigned int sci;
            if (sscanf(header, "%zu %zu %llu %u %u", &key_len, &val_len, &expire_time, &classif, &sci) != 5) continue;
            if (key_len > 1048576 || val_len > 16777216) break;
            char* stored_key = (char*)malloc(key_len + 1u);
            if (!stored_key) { fclose(f); return -2; }
            if (fread(stored_key, 1, key_len, f) != key_len) { free(stored_key); break; }
            stored_key[key_len] = '\0';
            bool match = strcmp(stored_key, key) == 0;
            free(stored_key);
            if (fseek(f, (long)val_len + 1L, SEEK_CUR) != 0) break;
            if (!match) continue;
            fclose(f);
            if (!qihse_auth_can_access(user, (uint16_t)classif, (uint16_t)sci)) return -2;
            if (expire_time == 0) return -1;
            if ((uint64_t)expire_time <= now) return -2;
            uint64_t remaining = (uint64_t)expire_time - now;
            return remaining > INT64_MAX ? INT64_MAX : (int64_t)remaining;
        }
        fclose(f);
    }
    return -2;
}

typedef struct {
    uint64_t now;
    qihse_trinary_trie_t* trie;
    size_t expired_count;
} sweep_ctx_t;

static bool sweep_expired_callback(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size;
    sweep_ctx_t* ctx = (sweep_ctx_t*)user_data;
    if (!key || !value || !ctx) return true;
    kv_payload_t* p = (kv_payload_t*)value;
    if (p->expire_time_ms > 0 && p->expire_time_ms <= ctx->now) {
        qihse_trinary_trie_delete(ctx->trie, key);
        ctx->expired_count++;
    }
    return true;
}

void qihse_kv_sweep_expired(qihse_kv_store_t* store) {
    if (!store || !store->trie || store->bulk_load_mode) return;
    sweep_ctx_t ctx = {
        .now = current_time_ms(),
        .trie = store->trie,
        .expired_count = 0
    };
    qihse_trinary_trie_foreach(store->trie, sweep_expired_callback, &ctx);
}

typedef struct {
    FILE* f;
    size_t count;
} sstable_save_ctx_t;

static bool sstable_save_callback(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size;
    sstable_save_ctx_t* ctx = (sstable_save_ctx_t*)user_data;
    if (!key || !value || !ctx->f) return true;
    kv_payload_t* p = (kv_payload_t*)value;
    size_t klen = strlen(key);
    size_t vlen = strlen(p->val);
    fprintf(ctx->f, "%zu %zu %llu %u %u\n", klen, vlen, (unsigned long long)p->expire_time_ms, (unsigned)p->classification, (unsigned)p->sci_compartment);
    fwrite(key, 1, klen, ctx->f);
    fwrite(p->val, 1, vlen, ctx->f);
    fprintf(ctx->f, "\n");
    ctx->count++;
    return true;
}

int qihse_kv_save(qihse_kv_store_t* store, const char* filepath) {
    if (!store || !filepath || !store->trie) return -1;
    qihse_kv_sweep_expired(store);
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    FILE* f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }
    
    sstable_save_ctx_t ctx = { .f = f, .count = 0 };
    qihse_trinary_trie_foreach(store->trie, sstable_save_callback, &ctx);
    fclose(f);
    return 0;
}

int qihse_kv_load(qihse_kv_store_t* store, const char* filepath) {
    if (!store || !filepath) return -1;
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    FILE* f = fdopen(fd, "r");
    if (!f) { close(fd); return -1; }
    
    char header[256];
    while (fgets(header, sizeof(header), f)) {
        size_t key_len, val_len;
        unsigned long long expire_time;
        unsigned int classif, sci;
        if (sscanf(header, "%zu %zu %llu %u %u", &key_len, &val_len, &expire_time, &classif, &sci) != 5) continue;
        if (key_len > 1048576 || val_len > 16777216) continue;
        
        char* key = (char*)malloc(key_len + 1);
        char* val = (char*)malloc(val_len + 1);
        if (!key || !val) { free(key); free(val); break; }
        
        if (fread(key, 1, key_len, f) != key_len) { free(key); free(val); break; }
        key[key_len] = '\0';
        if (fread(val, 1, val_len, f) != val_len) { free(key); free(val); break; }
        val[val_len] = '\0';
        fgetc(f);
        
        uint64_t ttl_ms = 0;
        uint64_t now = current_time_ms();
        if (expire_time > now) {
            ttl_ms = expire_time - now;
        }
        qihse_kv_set_with_expiry(store, key, val, ttl_ms, classif, sci);
        free(key);
        free(val);
    }
    fclose(f);
    return 0;
}

bool qihse_kv_store_is_under_attack(qihse_kv_store_t* store) {
    if (!store || !store->qdd_ctx) return false;
    return qihse_qdd_is_under_attack(store->qdd_ctx);
}

typedef struct {
    qihse_kv_iter_cb cb;
    void* user_data;
    qihse_trinary_trie_t* trie;
    uint64_t now;
} kv_foreach_ctx_t;

static bool kv_foreach_callback(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size;
    kv_foreach_ctx_t* ctx = (kv_foreach_ctx_t*)user_data;
    if (!key || !value || !ctx) return true;
    kv_payload_t* p = (kv_payload_t*)value;
    if (p->expire_time_ms > 0 && p->expire_time_ms <= ctx->now) {
        qihse_trinary_trie_delete(ctx->trie, key);
        return true;
    }
    return ctx->cb(key, p->val, ctx->user_data);
}

void qihse_kv_foreach(qihse_kv_store_t* store, qihse_kv_iter_cb cb, void* user_data) {
    if (!store || !store->trie || !cb) return;
    kv_foreach_ctx_t ctx = { cb, user_data, store->trie, current_time_ms() };
    qihse_trinary_trie_foreach(store->trie, kv_foreach_callback, &ctx);
}

typedef struct {
    qihse_trinary_trie_t* trie;
    size_t removed;
} kv_clear_ctx_t;

static bool kv_clear_callback(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value; (void)value_size;
    kv_clear_ctx_t* ctx = (kv_clear_ctx_t*)user_data;
    if (!key || !ctx) return true;
    if (qihse_trinary_trie_delete(ctx->trie, key)) ctx->removed++;
    return true;
}

size_t qihse_kv_clear(qihse_kv_store_t* store) {
    if (!store || !store->trie) return 0;
    kv_clear_ctx_t ctx = { store->trie, 0 };
    qihse_trinary_trie_foreach(store->trie, kv_clear_callback, &ctx);
    store->mem_usage = 0;
    return ctx.removed;
}

typedef struct {
    size_t count;
    uint64_t now;
    qihse_trinary_trie_t* trie;
} kv_count_ctx_t;

static bool kv_count_callback(const char* key, void* value, size_t value_size, void* user_data) {
    (void)value_size; (void)key;
    kv_count_ctx_t* ctx = (kv_count_ctx_t*)user_data;
    if (!value || !ctx) return true;
    kv_payload_t* p = (kv_payload_t*)value;
    if (p->expire_time_ms > 0 && p->expire_time_ms <= ctx->now) {
        if (key) qihse_trinary_trie_delete(ctx->trie, key);
        return true;
    }
    ctx->count++;
    return true;
}

size_t qihse_kv_count(qihse_kv_store_t* store) {
    if (!store || !store->trie) return 0;
    kv_count_ctx_t ctx = { 0, current_time_ms(), store->trie };
    qihse_trinary_trie_foreach(store->trie, kv_count_callback, &ctx);
    return ctx.count;
}
