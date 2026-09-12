#include "qihse_blob.h"
#include "qihse_audit.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define BLOB_INDEX_SLOTS 4096u
#define BLOB_INDEX_MAGIC 'Q'
#define BLOB_INDEX_VERSION 2u

typedef struct blob_entry {
    qihse_blob_info_t info;
    struct blob_entry* next;
} blob_entry_t;

struct qihse_blob_store {
    char base_dir[512];
    char objects_dir[512];
    char index_path[576];
    blob_entry_t* slots[BLOB_INDEX_SLOTS];
    size_t entry_count;
    pthread_rwlock_t index_lock;   /* guards slots/entry_count */
    uint64_t put_counter;          /* unique temp-file names; uploads run in parallel */
    FILE* index_log;
    pthread_mutex_t log_lock;
    EVP_MD* sha384;
};

/* --------------------------------------------------------------------------
 * SHA-256 helpers
 * -------------------------------------------------------------------------- */
static const EVP_MD* blob_sha384(qihse_blob_store_t* store) {
    return store->sha384 ? store->sha384 : EVP_sha384();
}

void qihse_blob_hash_to_hex(const uint8_t* hash, char out[QIHSE_BLOB_HASH_HEX]) {
    static const char digits[] = "0123456789abcdef";
    if (!hash || !out) return;
    for (size_t i = 0; i < QIHSE_BLOB_HASH_BYTES; i++) {
        out[i * 2u] = digits[hash[i] >> 4];
        out[i * 2u + 1u] = digits[hash[i] & 0x0Fu];
    }
    out[QIHSE_BLOB_HASH_HEX - 1u] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool qihse_blob_hash_from_hex(const char* hex, uint8_t out[QIHSE_BLOB_HASH_BYTES]) {
    if (!hex || !out) return false;
    if (strlen(hex) != QIHSE_BLOB_HASH_BYTES * 2u) return false;
    for (size_t i = 0; i < QIHSE_BLOB_HASH_BYTES; i++) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* --------------------------------------------------------------------------
 * Index helpers (index_lock held for write)
 * -------------------------------------------------------------------------- */
static size_t blob_slot(const uint8_t* hash) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < QIHSE_BLOB_HASH_BYTES; i++) {
        h ^= hash[i];
        h *= 1099511628211ull;
    }
    return (size_t)(h % BLOB_INDEX_SLOTS);
}

static blob_entry_t* blob_find_entry(qihse_blob_store_t* store, const uint8_t* hash) {
    size_t slot = blob_slot(hash);
    for (blob_entry_t* e = store->slots[slot]; e; e = e->next) {
        if (memcmp(e->info.hash, hash, QIHSE_BLOB_HASH_BYTES) == 0) return e;
    }
    return NULL;
}

static void blob_object_path(qihse_blob_store_t* store, const uint8_t* hash,
                             char* path, size_t path_cap) {
    char hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(hash, hex);
    snprintf(path, path_cap, "%s/objects/%.2s/%s", store->base_dir, hex, hex + 2);
}

/* Append one metadata record and flush. log_lock held. */
static bool blob_log_append(qihse_blob_store_t* store, char op, const qihse_blob_info_t* info) {
    if (!store->index_log) return false;
    unsigned char magic = BLOB_INDEX_MAGIC;
    unsigned char version = BLOB_INDEX_VERSION;
    if (fwrite(&magic, 1, 1, store->index_log) != 1 ||
        fwrite(&version, 1, 1, store->index_log) != 1 ||
        fwrite(&op, 1, 1, store->index_log) != 1) {
        return false;
    }
    if (op == 'D') {
        if (fwrite(info->hash, 1, QIHSE_BLOB_HASH_BYTES, store->index_log) != QIHSE_BLOB_HASH_BYTES) return false;
    } else {
        if (fwrite(info, sizeof(*info), 1, store->index_log) != 1) return false;
    }
    if (fflush(store->index_log) != 0) return false;
    return true;
}

static bool blob_log_replay(qihse_blob_store_t* store) {
    FILE* f = fopen(store->index_path, "rb");
    if (!f) return true; /* fresh store */
    unsigned char header[3];
    qihse_blob_info_t info;
    while (fread(header, 1, sizeof(header), f) == sizeof(header)) {
        if (header[0] != BLOB_INDEX_MAGIC || header[1] != BLOB_INDEX_VERSION) break; /* torn tail */
        if (header[2] == 'D') {
            uint8_t hash[QIHSE_BLOB_HASH_BYTES];
            if (fread(hash, 1, sizeof(hash), f) != sizeof(hash)) break;
            blob_entry_t* e = blob_find_entry(store, hash);
            if (e) {
                blob_entry_t** link = &store->slots[blob_slot(hash)];
                while (*link && *link != e) link = &(*link)->next;
                if (*link) *link = e->next;
                free(e);
                store->entry_count--;
            }
            continue;
        }
        if (header[2] != 'P' && header[2] != 'R' && header[2] != 'U') break;
        if (fread(&info, sizeof(info), 1, f) != 1) break;
        blob_entry_t* e = blob_find_entry(store, info.hash);
        if (e) {
            e->info = info; /* last state wins */
        } else {
            e = calloc(1, sizeof(*e));
            if (!e) break;
            e->info = info;
            size_t slot = blob_slot(info.hash);
            e->next = store->slots[slot];
            store->slots[slot] = e;
            store->entry_count++;
        }
    }
    fclose(f);
    return true;
}

/* --------------------------------------------------------------------------
 * Authorization (AGENTS.md invariants #1)
 * -------------------------------------------------------------------------- */
static bool blob_user_tenant(qihse_user_t* user, uint32_t* out_tenant) {
    if (!user || !qihse_auth_user_is_active(user)) return false;
    *out_tenant = qihse_user_get_tenant_id(user);
    return true;
}

static bool blob_can_read(const blob_entry_t* e, uint32_t user_tenant, qihse_user_t* user) {
    /* System domain reads across tenants; tenants read their own blobs plus
     * the shared commons collection. */
    if (user_tenant != QIHSE_TENANT_SYSTEM &&
        e->info.tag != (uint16_t)QIHSE_BLOB_TAG_COMMONS_SNAPSHOT &&
        e->info.tenant_id != user_tenant) {
        return false;
    }
    return qihse_auth_can_access(user, e->info.classification, e->info.sci_compartment);
}

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */
qihse_blob_store_t* qihse_blob_store_create(const char* base_dir) {
    if (!base_dir || !*base_dir || strlen(base_dir) >= sizeof(((qihse_blob_store_t*)0)->base_dir) - 16u) {
        return NULL;
    }
    qihse_blob_store_t* store = calloc(1, sizeof(*store));
    if (!store) return NULL;
    snprintf(store->base_dir, sizeof(store->base_dir), "%s", base_dir);
    snprintf(store->objects_dir, sizeof(store->objects_dir), "%s/objects", base_dir);
    snprintf(store->index_path, sizeof(store->index_path), "%s/index.log", base_dir);

    if (mkdir(base_dir, 0700) != 0 && errno != EEXIST) {
        free(store);
        return NULL;
    }
    if (mkdir(store->objects_dir, 0700) != 0 && errno != EEXIST) {
        free(store);
        return NULL;
    }
    if (pthread_rwlock_init(&store->index_lock, NULL) != 0 ||
        pthread_mutex_init(&store->log_lock, NULL) != 0) {
        free(store);
        return NULL;
    }
    store->sha384 = EVP_MD_fetch(NULL, "SHA-384", NULL);

    if (!blob_log_replay(store)) {
        qihse_blob_store_destroy(store);
        return NULL;
    }
    store->index_log = fopen(store->index_path, "ab");
    if (!store->index_log) {
        qihse_blob_store_destroy(store);
        return NULL;
    }
    return store;
}

void qihse_blob_store_destroy(qihse_blob_store_t* store) {
    if (!store) return;
    pthread_rwlock_wrlock(&store->index_lock);
    for (size_t i = 0; i < BLOB_INDEX_SLOTS; i++) {
        blob_entry_t* e = store->slots[i];
        while (e) {
            blob_entry_t* next = e->next;
            free(e);
            e = next;
        }
        store->slots[i] = NULL;
    }
    pthread_rwlock_unlock(&store->index_lock);
    if (store->index_log) fclose(store->index_log);
    if (store->sha384) EVP_MD_free(store->sha384);
    pthread_rwlock_destroy(&store->index_lock);
    pthread_mutex_destroy(&store->log_lock);
    free(store);
}

/* --------------------------------------------------------------------------
 * Write path
 * -------------------------------------------------------------------------- */
bool qihse_blob_put_user(qihse_blob_store_t* store, uint32_t tenant_id,
                         qihse_blob_tag_t tag, uint16_t classification,
                         uint16_t sci_compartment, qihse_user_t* user,
                         qihse_blob_read_fn read_fn, void* read_opaque,
                         uint8_t out_hash[QIHSE_BLOB_HASH_BYTES], uint64_t* out_size) {
    if (!store || !read_fn || !out_hash) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) {
        qihse_audit_log("BLOB_DENIED_NULL_OR_DEAD_USER", 0xFFFFFFFFu, 0, classification, sci_compartment);
        return false;
    }
    if (tag == (qihse_blob_tag_t)0 || tag > QIHSE_BLOB_TAG_COMMONS_SNAPSHOT) return false;
    if (user_tenant != QIHSE_TENANT_SYSTEM) {
        /* Tenant principals write only inside their own tenant and never to
         * the commons collection (operator-curated). */
        if (tenant_id != user_tenant || tag == QIHSE_BLOB_TAG_COMMONS_SNAPSHOT) {
            qihse_audit_log("BLOB_DENIED_TENANT_WRITE", user_tenant, tenant_id, classification, sci_compartment);
            return false;
        }
    }
    if (!qihse_auth_can_access(user, classification, sci_compartment)) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    FILE* tmp = NULL;
    char tmp_path[640];
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    bool ok = false;
    uint64_t total = 0;

    do {
        if (!ctx) break;
        if (EVP_DigestInit_ex(ctx, blob_sha384(store), NULL) != 1) break;
        /* Unique per-put temp name: concurrent uploads never collide. */
        uint64_t seq = __atomic_add_fetch(&store->put_counter, 1u, __ATOMIC_RELAXED);
        snprintf(tmp_path, sizeof(tmp_path), "%s/tmp-put-%ld-%llu", store->base_dir,
                 (long)getpid(), (unsigned long long)seq);
        tmp = fopen(tmp_path, "wb");
        if (!tmp) break;

        uint8_t buffer[QIHSE_BLOB_CHUNK_SIZE];
        for (;;) {
            int64_t chunk = read_fn(read_opaque, buffer, sizeof(buffer));
            if (chunk < 0) break;              /* source error */
            if (chunk == 0) { ok = true; break; } /* EOF */
            if ((uint64_t)chunk > QIHSE_BLOB_MAX_SIZE - total) { chunk = -1; break; }
            if (fwrite(buffer, 1, (size_t)chunk, tmp) != (size_t)chunk) break;
            if (EVP_DigestUpdate(ctx, buffer, (size_t)chunk) != 1) break;
            total += (uint64_t)chunk;
        }
        if (!ok) break;

        unsigned int md_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &md_len) != 1 || md_len != QIHSE_BLOB_HASH_BYTES) { ok = false; break; }
        if (fflush(tmp) != 0 || fsync(fileno(tmp)) != 0) { ok = false; break; }
        fclose(tmp);
        tmp = NULL;

        char object_path[640];
        blob_object_path(store, hash, object_path, sizeof(object_path));

        pthread_rwlock_wrlock(&store->index_lock);
        blob_entry_t* existing = blob_find_entry(store, hash);
        if (existing) {
            /* Content already present: identical binding bumps the refcount;
             * a different binding is refused (no cross-tenant dedup claims). */
            if (existing->info.tenant_id != tenant_id ||
                existing->info.tag != (uint16_t)tag ||
                existing->info.classification != classification ||
                existing->info.sci_compartment != sci_compartment) {
                pthread_rwlock_unlock(&store->index_lock);
                qihse_audit_log("BLOB_DENIED_HASH_BINDING_CLASH", user_tenant, tenant_id, classification, sci_compartment);
                ok = false;
                break;
            }
            existing->info.refcount++;
            qihse_blob_info_t snapshot = existing->info;
            pthread_mutex_lock(&store->log_lock);
            blob_log_append(store, 'R', &snapshot);
            pthread_mutex_unlock(&store->log_lock);
            pthread_rwlock_unlock(&store->index_lock);
            unlink(tmp_path);
            memcpy(out_hash, hash, QIHSE_BLOB_HASH_BYTES);
            if (out_size) *out_size = total;
            EVP_MD_CTX_free(ctx);
            return true;
        }

        /* New blob: move the temp file into the CAS tree atomically. */
        char shard_dir[600];
        char hex[QIHSE_BLOB_HASH_HEX];
        qihse_blob_hash_to_hex(hash, hex);
        snprintf(shard_dir, sizeof(shard_dir), "%s/objects/%.2s", store->base_dir, hex);
        if (mkdir(shard_dir, 0700) != 0 && errno != EEXIST) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
        if (rename(tmp_path, object_path) != 0) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }

        blob_entry_t* e = calloc(1, sizeof(*e));
        if (!e) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
        memcpy(e->info.hash, hash, QIHSE_BLOB_HASH_BYTES);
        e->info.size = total;
        e->info.tenant_id = tenant_id;
        e->info.tag = (uint16_t)tag;
        e->info.classification = classification;
        e->info.sci_compartment = sci_compartment;
        e->info.refcount = 1;
        size_t slot = blob_slot(hash);
        e->next = store->slots[slot];
        store->slots[slot] = e;
        store->entry_count++;

        qihse_blob_info_t snapshot = e->info;
        pthread_mutex_lock(&store->log_lock);
        blob_log_append(store, 'P', &snapshot);
        pthread_mutex_unlock(&store->log_lock);
        pthread_rwlock_unlock(&store->index_lock);

        memcpy(out_hash, hash, QIHSE_BLOB_HASH_BYTES);
        if (out_size) *out_size = total;
        EVP_MD_CTX_free(ctx);
        return true;
    } while (0);

    if (tmp) fclose(tmp);
    unlink(tmp_path);
    if (ctx) EVP_MD_CTX_free(ctx);
    return false;
}

typedef struct {
    const uint8_t* data;
    size_t len;
    size_t pos;
} qihse_buffer_reader_t;

static int64_t buffer_read_fn(void* opaque, uint8_t* buffer, size_t capacity) {
    qihse_buffer_reader_t* state = opaque;
    if (state->pos >= state->len) return 0;
    size_t n = state->len - state->pos;
    if (n > capacity) n = capacity;
    memcpy(buffer, state->data + state->pos, n);
    state->pos += n;
    return (int64_t)n;
}

bool qihse_blob_put_buffer_user(qihse_blob_store_t* store, uint32_t tenant_id,
                                qihse_blob_tag_t tag, uint16_t classification,
                                uint16_t sci_compartment, qihse_user_t* user,
                                const uint8_t* data, size_t len,
                                uint8_t out_hash[QIHSE_BLOB_HASH_BYTES]) {
    if (!data && len > 0) return false;
    qihse_buffer_reader_t state = { data, len, 0 };
    return qihse_blob_put_user(store, tenant_id, tag, classification, sci_compartment,
                               user, buffer_read_fn, &state, out_hash, NULL);
}

/* --------------------------------------------------------------------------
 * Read path
 * -------------------------------------------------------------------------- */
/* Locates the entry and authorization-checks it. On success returns true with
 * index_lock HELD (the caller must unlock); on failure returns false unlocked. */
static bool blob_open_entry(qihse_blob_store_t* store, const uint8_t* hash,
                            qihse_user_t* user, blob_entry_t** out_entry,
                            char* object_path, size_t path_cap) {
    *out_entry = NULL;
    if (!store || !hash || !user) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) {
        qihse_audit_log("BLOB_DENIED_NULL_OR_DEAD_USER", 0xFFFFFFFFu, 0, 0, 0);
        return false;
    }
    pthread_rwlock_rdlock(&store->index_lock);
    blob_entry_t* e = blob_find_entry(store, hash);
    if (!e) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    if (!blob_can_read(e, user_tenant, user)) {
        qihse_audit_log("BLOB_DENIED_AUTHZ", user_tenant, e->info.tenant_id,
                        e->info.classification, e->info.sci_compartment);
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    *out_entry = e;
    if (object_path) blob_object_path(store, hash, object_path, path_cap);
    return true;
}

bool qihse_blob_get_user(qihse_blob_store_t* store, const uint8_t* hash,
                         uint64_t offset, uint8_t* buffer, size_t buffer_len,
                         size_t* out_read, qihse_user_t* user) {
    if (!store || !hash || !buffer || buffer_len == 0 || !out_read) return false;
    blob_entry_t* e = NULL;
    char object_path[640];
    if (!blob_open_entry(store, hash, user, &e, object_path, sizeof(object_path))) return false;
    uint64_t size = e->info.size;
    pthread_rwlock_unlock(&store->index_lock);

    if (offset >= size) { *out_read = 0; return true; }
    FILE* f = fopen(object_path, "rb");
    if (!f) return false;
    if (fseeko(f, (off_t)offset, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    size_t n = fread(buffer, 1, buffer_len, f);
    bool ok = n > 0 || (offset == size);
    if (ok) *out_read = n;
    fclose(f);
    return ok;
}

bool qihse_blob_size_user(qihse_blob_store_t* store, const uint8_t* hash,
                          uint64_t* out_size, qihse_user_t* user) {
    if (!store || !hash || !out_size) return false;
    blob_entry_t* e = NULL;
    if (!blob_open_entry(store, hash, user, &e, NULL, 0)) return false;
    *out_size = e->info.size;
    pthread_rwlock_unlock(&store->index_lock);
    return true;
}

bool qihse_blob_info_user(qihse_blob_store_t* store, const uint8_t* hash,
                          qihse_blob_info_t* out_info, qihse_user_t* user) {
    if (!store || !hash || !out_info) return false;
    blob_entry_t* e = NULL;
    if (!blob_open_entry(store, hash, user, &e, NULL, 0)) return false;
    *out_info = e->info;
    pthread_rwlock_unlock(&store->index_lock);
    return true;
}

/* --------------------------------------------------------------------------
 * Reference management / deletion
 * -------------------------------------------------------------------------- */
static bool blob_mutate_ref(qihse_blob_store_t* store, const uint8_t* hash,
                            qihse_user_t* user, int delta, bool allow_delete) {
    if (!store || !hash) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) return false;

    pthread_rwlock_wrlock(&store->index_lock);
    blob_entry_t* e = blob_find_entry(store, hash);
    if (!e) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    bool owner = (user_tenant == QIHSE_TENANT_SYSTEM || e->info.tenant_id == user_tenant);
    if (!owner || !qihse_auth_can_access(user, e->info.classification, e->info.sci_compartment)) {
        qihse_audit_log("BLOB_DENIED_AUTHZ", user_tenant, e->info.tenant_id,
                        e->info.classification, e->info.sci_compartment);
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    if (delta > 0) {
        if (e->info.refcount == UINT32_MAX) {
            pthread_rwlock_unlock(&store->index_lock);
            return false;
        }
        e->info.refcount++;
        qihse_blob_info_t snapshot = e->info;
        pthread_mutex_lock(&store->log_lock);
        blob_log_append(store, 'R', &snapshot);
        pthread_mutex_unlock(&store->log_lock);
        pthread_rwlock_unlock(&store->index_lock);
        return true;
    }
    if (e->info.refcount > 1) {
        e->info.refcount--;
        qihse_blob_info_t snapshot = e->info;
        pthread_mutex_lock(&store->log_lock);
        blob_log_append(store, 'U', &snapshot);
        pthread_mutex_unlock(&store->log_lock);
        pthread_rwlock_unlock(&store->index_lock);
        return true;
    }
    if (!allow_delete) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    /* Refcount drops to zero: remove the object. */
    char object_path[640];
    blob_object_path(store, hash, object_path, sizeof(object_path));
    unlink(object_path);
    qihse_blob_info_t snapshot = e->info;
    blob_entry_t** link = &store->slots[blob_slot(hash)];
    while (*link && *link != e) link = &(*link)->next;
    if (*link) *link = e->next;
    free(e);
    store->entry_count--;
    pthread_mutex_lock(&store->log_lock);
    blob_log_append(store, 'D', &snapshot);
    pthread_mutex_unlock(&store->log_lock);
    pthread_rwlock_unlock(&store->index_lock);
    return true;
}

bool qihse_blob_ref_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user) {
    return blob_mutate_ref(store, hash, user, 1, false);
}

bool qihse_blob_unref_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user) {
    return blob_mutate_ref(store, hash, user, -1, false);
}

bool qihse_blob_delete_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user) {
    return blob_mutate_ref(store, hash, user, -1, true);
}

/* --------------------------------------------------------------------------
 * Enumeration
 * -------------------------------------------------------------------------- */
bool qihse_blob_list_user(qihse_blob_store_t* store, qihse_user_t* user,
                          qihse_blob_list_fn callback, void* callback_opaque) {
    if (!store || !callback) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) return false;

    bool keep_going = true;
    pthread_rwlock_rdlock(&store->index_lock);
    for (size_t i = 0; i < BLOB_INDEX_SLOTS && keep_going; i++) {
        for (blob_entry_t* e = store->slots[i]; e && keep_going; e = e->next) {
            if (!blob_can_read(e, user_tenant, user)) continue;
            keep_going = callback(&e->info, callback_opaque);
        }
    }
    pthread_rwlock_unlock(&store->index_lock);
    return true;
}
