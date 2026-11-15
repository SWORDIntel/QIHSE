#include "qihse_blob.h"
#include "qihse_audit.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#define BLOB_INDEX_SLOTS 4096u
#define BLOB_INDEX_MAGIC 'Q'
#define BLOB_INDEX_VERSION 2u

typedef struct blob_entry {
    qihse_blob_info_t info;
    uint32_t pin_count;
    uint32_t snapshot_refs; /* transient readers holding a stable full-store view */
    struct blob_entry* next;
} blob_entry_t;

typedef struct blob_prepared {
    uint64_t txn_id;
    qihse_blob_info_t info;
    uint8_t decision; /* 0 pending, 'C' committed, 'A' aborted */
    struct blob_prepared* next;
} blob_prepared_t;

struct qihse_blob_store {
    char base_dir[512];
    char objects_dir[512];
    char index_path[576];
    blob_entry_t* slots[BLOB_INDEX_SLOTS];
    blob_prepared_t* prepared;
    size_t entry_count;
    pthread_rwlock_t index_lock;   /* guards slots/entry_count */
    int index_fd;
    pid_t owner_pid;
    bool poisoned;                 /* failed rollback: no further mutations */
    pthread_mutex_t log_lock;
    EVP_MD* sha384;
};

/* --------------------------------------------------------------------------
 * SHA-384 helpers
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

static blob_prepared_t* blob_find_prepared(qihse_blob_store_t* store, uint64_t txn_id) {
    for (blob_prepared_t* p = store->prepared; p; p = p->next)
        if (p->txn_id == txn_id) return p;
    return NULL;
}

static bool blob_hash_reserved_by_other_prepare(const qihse_blob_store_t* store,
    const uint8_t hash[QIHSE_BLOB_HASH_BYTES], uint64_t txn_id) {
    for (const blob_prepared_t* p = store->prepared; p; p = p->next)
        if (!p->decision && p->txn_id != txn_id &&
            memcmp(p->info.hash, hash, QIHSE_BLOB_HASH_BYTES) == 0)
            return true;
    return false;
}

static void blob_object_path(qihse_blob_store_t* store, const uint8_t* hash,
                             char* path, size_t path_cap) {
    char hex[QIHSE_BLOB_HASH_HEX];
    qihse_blob_hash_to_hex(hash, hex);
    snprintf(path, path_cap, "%s/objects/%.2s/%s", store->base_dir, hex, hex + 2);
}

static bool blob_fsync_dir(const char* path) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok;
}

/* Append one metadata record and durably sync it. log_lock held. */
static bool blob_log_append(qihse_blob_store_t* store, char op, const qihse_blob_info_t* info) {
    if (store->index_fd < 0 || store->poisoned || !info) return false;
    unsigned char record[3u + sizeof(*info)];
    record[0] = BLOB_INDEX_MAGIC;
    record[1] = BLOB_INDEX_VERSION;
    record[2] = (unsigned char)op;
    size_t length = 3u;
    if (op == 'D' || op == 'I' || op == 'O') {
        memcpy(record + length, info->hash, QIHSE_BLOB_HASH_BYTES);
        length += QIHSE_BLOB_HASH_BYTES;
    } else {
        memcpy(record + length, info, sizeof(*info));
        length += sizeof(*info);
    }
    off_t start = lseek(store->index_fd, 0, SEEK_END);
    if (start < 0) return false;
    size_t written = 0u;
    while (written < length) {
        ssize_t n = write(store->index_fd, record + written, length - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        written += (size_t)n;
    }
    if (written == length && fsync(store->index_fd) == 0) return true;
    /* Never append past a partial record. If rollback itself is uncertain,
     * refuse further mutation until the store is reopened and replayed. */
    if (ftruncate(store->index_fd, start) != 0 || fsync(store->index_fd) != 0)
        store->poisoned = true;
    return false;
}

static uint64_t blob_size_limit(uint16_t tag) {
    return tag == QIHSE_BLOB_TAG_DUMP_ARTIFACT ? QIHSE_BLOB_ARTIFACT_MAX_SIZE
                                                : QIHSE_BLOB_MAX_SIZE;
}

static void blob_object_path(qihse_blob_store_t* store, const uint8_t* hash,
                             char* path, size_t path_cap);

static bool blob_prepared_content_valid(qihse_blob_store_t* store,
                                        const qihse_blob_info_t* info) {
    char path[640];
    blob_object_path(store, info->hash, path, sizeof(path));
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 &&
              (uint64_t)st.st_size == info->size;
    EVP_MD_CTX* digest = ok ? EVP_MD_CTX_new() : NULL;
    ok = ok && digest && EVP_DigestInit_ex(digest, blob_sha384(store), NULL) == 1;
    uint8_t buffer[64u * 1024u], hash[EVP_MAX_MD_SIZE];
    uint64_t total = 0;
    while (ok && total < info->size) {
        size_t wanted = sizeof(buffer);
        if (info->size - total < wanted) wanted = (size_t)(info->size - total);
        ssize_t n = read(fd, buffer, wanted);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || EVP_DigestUpdate(digest, buffer, (size_t)n) != 1) { ok = false; break; }
        total += (uint64_t)n;
    }
    unsigned int length = 0;
    if (ok) ok = EVP_DigestFinal_ex(digest, hash, &length) == 1 &&
        length == QIHSE_BLOB_HASH_BYTES &&
        CRYPTO_memcmp(hash, info->hash, QIHSE_BLOB_HASH_BYTES) == 0;
    EVP_MD_CTX_free(digest);
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool blob_prepared_log(qihse_blob_store_t* store, char op,
                              uint64_t txn_id, const qihse_blob_info_t* info) {
    if (!txn_id || (op == 'T' && !info) || (op != 'T' && op != 'C' && op != 'A'))
        return false;
    size_t length = 3u + sizeof(txn_id) + (op == 'T' ? sizeof(*info) : 0u);
    unsigned char record[3u + sizeof(txn_id) + sizeof(*info)];
    record[0] = BLOB_INDEX_MAGIC;
    record[1] = BLOB_INDEX_VERSION;
    record[2] = (unsigned char)op;
    memcpy(record + 3, &txn_id, sizeof(txn_id));
    if (op == 'T') memcpy(record + 3 + sizeof(txn_id), info, sizeof(*info));
    off_t start = lseek(store->index_fd, 0, SEEK_END);
    if (start < 0) return false;
    size_t at = 0;
    while (at < length) {
        ssize_t n = write(store->index_fd, record + at, length - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        at += (size_t)n;
    }
    if (at == length && fsync(store->index_fd) == 0) return true;
    if (ftruncate(store->index_fd, start) != 0 || fsync(store->index_fd) != 0)
        store->poisoned = true;
    return false;
}

static bool blob_log_replay(qihse_blob_store_t* store) {
    FILE* f = fopen(store->index_path, "rb+");
    if (!f) return errno == ENOENT; /* fresh store */
    unsigned char header[3];
    qihse_blob_info_t info;
    off_t valid_end = 0;
    bool torn = false, ok = true;
    for (;;) {
        size_t got = fread(header, 1, sizeof(header), f);
        if (got == 0u && feof(f)) break;
        if (got != sizeof(header)) { torn = true; break; }
        if (header[0] != BLOB_INDEX_MAGIC || header[1] != BLOB_INDEX_VERSION) {
            ok = false; break;
        }
        /* 'F' imports a terminal receipt only: never apply its historical
         * COMMIT metadata to today's live index, even if the object is gone. */
        if (header[2] == 'F') {
            uint64_t txn_id;
            uint8_t decision;
            qihse_blob_info_t terminal;
            if (fread(&txn_id, sizeof(txn_id), 1, f) != 1 ||
                fread(&terminal, sizeof(terminal), 1, f) != 1 ||
                fread(&decision, sizeof(decision), 1, f) != 1) {
                torn = true; break;
            }
            if (!txn_id || blob_find_prepared(store, txn_id) ||
                (decision != 'C' && decision != 'A') || !terminal.refcount ||
                !terminal.tag || terminal.tag > QIHSE_BLOB_TAG_DUMP_ARTIFACT ||
                terminal.size > blob_size_limit(terminal.tag) ||
                (terminal.tag == QIHSE_BLOB_TAG_REPL_TRANSACTION &&
                 terminal.tenant_id != QIHSE_TENANT_SYSTEM)) { ok = false; break; }
            blob_prepared_t* receipt = calloc(1, sizeof(*receipt));
            if (!receipt) { ok = false; break; }
            receipt->txn_id = txn_id;
            receipt->info = terminal;
            receipt->decision = decision;
            receipt->next = store->prepared;
            store->prepared = receipt;
            valid_end = ftello(f);
            if (valid_end < 0) { ok = false; break; }
            continue;
        }
        if (header[2] == 'T' || header[2] == 'C' || header[2] == 'A') {
            uint64_t txn_id = 0;
            if (fread(&txn_id, sizeof(txn_id), 1, f) != 1 || !txn_id) {
                torn = true; break;
            }
            blob_prepared_t* prepared = blob_find_prepared(store, txn_id);
            if (header[2] == 'T') {
                qihse_blob_info_t staged;
                if (prepared || fread(&staged, sizeof(staged), 1, f) != 1) {
                    if (feof(f)) torn = true; else ok = false;
                    break;
                }
                if (!staged.refcount || !staged.tag ||
                    staged.tag > QIHSE_BLOB_TAG_DUMP_ARTIFACT ||
                    staged.size > blob_size_limit(staged.tag)) { ok = false; break; }
                prepared = calloc(1, sizeof(*prepared));
                if (!prepared) { ok = false; break; }
                prepared->txn_id = txn_id;
                prepared->info = staged;
                prepared->next = store->prepared;
                store->prepared = prepared;
            } else {
                if (!prepared || prepared->decision) { ok = false; break; }
                prepared->decision = header[2];
                if (header[2] == 'C') {
                    blob_entry_t* entry = blob_find_entry(store, prepared->info.hash);
                    if (entry) entry->info = prepared->info;
                    else {
                        entry = calloc(1, sizeof(*entry));
                        if (!entry) { ok = false; break; }
                        entry->info = prepared->info;
                        size_t slot = blob_slot(entry->info.hash);
                        entry->next = store->slots[slot];
                        store->slots[slot] = entry;
                        store->entry_count++;
                    }
                }
            }
            valid_end = ftello(f);
            if (valid_end < 0) { ok = false; break; }
            continue;
        }
        if (header[2] == 'D') {
            uint8_t hash[QIHSE_BLOB_HASH_BYTES];
            if (fread(hash, 1, sizeof(hash), f) != sizeof(hash)) { torn = true; break; }
            blob_entry_t* e = blob_find_entry(store, hash);
            if (e) {
                blob_entry_t** link = &store->slots[blob_slot(hash)];
                while (*link && *link != e) link = &(*link)->next;
                if (*link) *link = e->next;
                free(e);
                store->entry_count--;
            }
            valid_end = ftello(f);
            if (valid_end < 0) { ok = false; break; }
            continue;
        }
        if (header[2] == 'I') {
            uint8_t hash[QIHSE_BLOB_HASH_BYTES];
            if (fread(hash, 1, sizeof(hash), f) != sizeof(hash)) { torn = true; break; }
            blob_entry_t* e = blob_find_entry(store, hash);
            if (e) e->pin_count++;
            valid_end = ftello(f);
            if (valid_end < 0) { ok = false; break; }
            continue;
        }
        if (header[2] == 'O') {
            uint8_t hash[QIHSE_BLOB_HASH_BYTES];
            if (fread(hash, 1, sizeof(hash), f) != sizeof(hash)) { torn = true; break; }
            blob_entry_t* e = blob_find_entry(store, hash);
            if (e && e->pin_count > 0) e->pin_count--;
            valid_end = ftello(f);
            if (valid_end < 0) { ok = false; break; }
            continue;
        }
        if (header[2] != 'P' && header[2] != 'R' && header[2] != 'U' &&
            header[2] != 'S') { ok = false; break; }
        if (fread(&info, sizeof(info), 1, f) != 1) { torn = true; break; }
        /* Absolute archive state avoids O(pin multiplicity) replay/log growth. */
        uint32_t restored_pins = 0;
        if (header[2] == 'S' &&
            fread(&restored_pins, sizeof(restored_pins), 1, f) != 1) {
            torn = true; break;
        }
        if (info.refcount == 0u || info.tag == 0u ||
            info.tag > QIHSE_BLOB_TAG_DUMP_ARTIFACT ||
            info.size > blob_size_limit(info.tag) ||
            (info.tag == QIHSE_BLOB_TAG_REPL_TRANSACTION &&
             info.tenant_id != QIHSE_TENANT_SYSTEM)) {
            ok = false; break;
        }
        blob_entry_t* e = blob_find_entry(store, info.hash);
        if (e) {
            e->info = info; /* last state wins */
        } else {
            e = calloc(1, sizeof(*e));
            if (!e) { ok = false; break; }
            e->info = info;
            size_t slot = blob_slot(info.hash);
            e->next = store->slots[slot];
            store->slots[slot] = e;
            store->entry_count++;
        }
        if (header[2] == 'S') e->pin_count = restored_pins;
        valid_end = ftello(f);
        if (valid_end < 0) { ok = false; break; }
    }
    if (ferror(f)) ok = false;
    if (ok && torn) {
        clearerr(f);
        if (valid_end < 0 || ftruncate(fileno(f), valid_end) != 0 ||
            fsync(fileno(f)) != 0) ok = false;
    }
    if (fclose(f) != 0) ok = false;
    return ok;
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
    store->index_fd = -1;
    store->owner_pid = getpid();
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
    store->index_fd = open(store->index_path,
                           O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (store->index_fd < 0 || !blob_fsync_dir(store->base_dir)) {
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
    while (store->prepared) {
        blob_prepared_t* next = store->prepared->next;
        free(store->prepared);
        store->prepared = next;
    }
    pthread_rwlock_unlock(&store->index_lock);
    if (store->index_fd >= 0) close(store->index_fd);
    if (store->sha384) EVP_MD_free(store->sha384);
    pthread_rwlock_destroy(&store->index_lock);
    pthread_mutex_destroy(&store->log_lock);
    free(store);
}

/* --------------------------------------------------------------------------
 * Write path
 * -------------------------------------------------------------------------- */
static bool blob_put_internal(qihse_blob_store_t* store, uint32_t tenant_id,
                              qihse_blob_tag_t tag, uint16_t classification,
                              uint16_t sci_compartment, qihse_user_t* user,
                              qihse_blob_read_fn read_fn, void* read_opaque,
                              uint8_t out_hash[QIHSE_BLOB_HASH_BYTES],
                              uint64_t* out_size,
                              const uint8_t* expected_hash,
                              uint64_t expected_size,
                              uint64_t prepare_txn_id) {
    if (!store || !read_fn || !out_hash) return false;
    if (expected_hash && expected_size > blob_size_limit((uint16_t)tag)) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) {
        qihse_audit_log("BLOB_DENIED_NULL_OR_DEAD_USER", 0xFFFFFFFFu, 0, classification, sci_compartment);
        return false;
    }
    if (tag == (qihse_blob_tag_t)0 || tag > QIHSE_BLOB_TAG_DUMP_ARTIFACT) return false;
    if (tag == QIHSE_BLOB_TAG_REPL_TRANSACTION &&
        (tenant_id != QIHSE_TENANT_SYSTEM ||
         user_tenant != QIHSE_TENANT_SYSTEM ||
         qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR)) return false;
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
    char tmp_path[640] = {0};
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    bool ok = false;
    uint64_t total = 0;

    do {
        if (!ctx) break;
        if (EVP_DigestInit_ex(ctx, blob_sha384(store), NULL) != 1) break;
        /* mkstemp also avoids a collision with a temp file left by a
         * previous process after a crash or PID reuse. */
        snprintf(tmp_path, sizeof(tmp_path), "%s/tmp-put-XXXXXX", store->base_dir);
        int tmp_fd = mkstemp(tmp_path);
        if (tmp_fd < 0) break;
        if (fcntl(tmp_fd, F_SETFD, FD_CLOEXEC) != 0) {
            close(tmp_fd);
            break;
        }
        tmp = fdopen(tmp_fd, "wb");
        if (!tmp) { close(tmp_fd); break; }
        if (!tmp) break;

        uint8_t* buffer = (uint8_t*)malloc(QIHSE_BLOB_CHUNK_SIZE);
        if (!buffer) break;
        for (;;) {
            int64_t chunk = read_fn(read_opaque, buffer, QIHSE_BLOB_CHUNK_SIZE);
            if (chunk < 0) break;              /* source error */
            if (chunk == 0) { ok = true; break; } /* EOF */
            if ((uint64_t)chunk > QIHSE_BLOB_CHUNK_SIZE ||
                (uint64_t)chunk > blob_size_limit((uint16_t)tag) - total) break;
            if (fwrite(buffer, 1, (size_t)chunk, tmp) != (size_t)chunk) break;
            if (EVP_DigestUpdate(ctx, buffer, (size_t)chunk) != 1) break;
            total += (uint64_t)chunk;
        }
        free(buffer);
        if (!ok) break;

        unsigned int md_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &md_len) != 1 || md_len != QIHSE_BLOB_HASH_BYTES ||
            (expected_hash && (total != expected_size ||
             CRYPTO_memcmp(hash, expected_hash, QIHSE_BLOB_HASH_BYTES) != 0))) {
            ok = false;
            break;
        }
        if (fflush(tmp) != 0 || fsync(fileno(tmp)) != 0) { ok = false; break; }
        if (fclose(tmp) != 0) { tmp = NULL; ok = false; break; }
        tmp = NULL;

        char object_path[640];
        blob_object_path(store, hash, object_path, sizeof(object_path));

        pthread_rwlock_wrlock(&store->index_lock);
        if (store->poisoned) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
        if (blob_hash_reserved_by_other_prepare(store, hash, prepare_txn_id)) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
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
            if (existing->info.refcount == UINT32_MAX) {
                pthread_rwlock_unlock(&store->index_lock);
                ok = false;
                break;
            }
            qihse_blob_info_t snapshot = existing->info;
            snapshot.refcount++;
            bool logged;
            if (prepare_txn_id) {
                blob_prepared_t* prepared = blob_find_prepared(store, prepare_txn_id);
                if (prepared) {
                    logged = prepared->decision != 'A' &&
                        memcmp(&prepared->info, &snapshot, sizeof(snapshot)) == 0;
                    pthread_rwlock_unlock(&store->index_lock);
                    if (!logged) { ok = false; break; }
                    memcpy(out_hash, hash, QIHSE_BLOB_HASH_BYTES);
                    if (out_size) *out_size = total;
                    EVP_MD_CTX_free(ctx);
                    unlink(tmp_path);
                    return true;
                }
                for (blob_prepared_t* p = store->prepared; p; p = p->next) {
                    if (!p->decision && !memcmp(p->info.hash, hash, QIHSE_BLOB_HASH_BYTES)) {
                        pthread_rwlock_unlock(&store->index_lock); ok = false; break;
                    }
                }
                if (!ok) break;
                prepared = calloc(1, sizeof(*prepared));
                if (!prepared) { pthread_rwlock_unlock(&store->index_lock); ok = false; break; }
                prepared->txn_id = prepare_txn_id;
                prepared->info = snapshot;
                pthread_mutex_lock(&store->log_lock);
                logged = blob_prepared_log(store, 'T', prepare_txn_id, &snapshot);
                pthread_mutex_unlock(&store->log_lock);
                if (logged) { prepared->next = store->prepared; store->prepared = prepared; }
                else free(prepared);
            } else {
                pthread_mutex_lock(&store->log_lock);
                logged = blob_log_append(store, 'R', &snapshot);
                pthread_mutex_unlock(&store->log_lock);
                if (logged) existing->info = snapshot;
            }
            pthread_rwlock_unlock(&store->index_lock);
            if (!logged) { ok = false; break; }
            unlink(tmp_path);
            memcpy(out_hash, hash, QIHSE_BLOB_HASH_BYTES);
            if (out_size) *out_size = total;
            EVP_MD_CTX_free(ctx);
            return true;
        }

        /* New blob: move the temp file into the CAS tree atomically. */
        if (prepare_txn_id) {
            for (blob_prepared_t* p = store->prepared; p; p = p->next) {
                if (!p->decision && !memcmp(p->info.hash, hash, QIHSE_BLOB_HASH_BYTES)) {
                    pthread_rwlock_unlock(&store->index_lock); ok = false; break;
                }
            }
            if (!ok) break;
            blob_prepared_t* prior = blob_find_prepared(store, prepare_txn_id);
            if (prior) {
                bool same = prior->decision != 'A' && prior->info.size == total &&
                    prior->info.tenant_id == tenant_id && prior->info.tag == (uint16_t)tag &&
                    prior->info.classification == classification &&
                    prior->info.sci_compartment == sci_compartment &&
                    !memcmp(prior->info.hash, hash, QIHSE_BLOB_HASH_BYTES);
                pthread_rwlock_unlock(&store->index_lock);
                if (!same) { ok = false; break; }
                unlink(tmp_path); memcpy(out_hash, hash, QIHSE_BLOB_HASH_BYTES);
                if (out_size) *out_size = total;
                EVP_MD_CTX_free(ctx); return true;
            }
        }
        char shard_dir[600];
        char hex[QIHSE_BLOB_HASH_HEX];
        qihse_blob_hash_to_hex(hash, hex);
        snprintf(shard_dir, sizeof(shard_dir), "%s/objects/%.2s", store->base_dir, hex);
        if (mkdir(shard_dir, 0700) != 0 && errno != EEXIST) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
        if (!blob_fsync_dir(store->objects_dir)) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
        if (rename(tmp_path, object_path) != 0) {
            pthread_rwlock_unlock(&store->index_lock);
            ok = false;
            break;
        }
        if (!blob_fsync_dir(shard_dir) || !blob_fsync_dir(store->base_dir)) {
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
        qihse_blob_info_t snapshot = e->info;
        bool logged;
        if (prepare_txn_id) {
            blob_prepared_t* prepared = calloc(1, sizeof(*prepared));
            if (!prepared) { free(e); pthread_rwlock_unlock(&store->index_lock); ok = false; break; }
            prepared->txn_id = prepare_txn_id;
            prepared->info = snapshot;
            pthread_mutex_lock(&store->log_lock);
            logged = blob_prepared_log(store, 'T', prepare_txn_id, &snapshot);
            pthread_mutex_unlock(&store->log_lock);
            if (logged) { prepared->next = store->prepared; store->prepared = prepared; }
            else free(prepared);
            free(e); /* PREPARE publishes only the prepared metadata, not a live entry. */
        } else {
            pthread_mutex_lock(&store->log_lock);
            logged = blob_log_append(store, 'P', &snapshot);
            pthread_mutex_unlock(&store->log_lock);
            if (logged) {
                size_t slot = blob_slot(hash);
                e->next = store->slots[slot];
                store->slots[slot] = e;
                store->entry_count++;
            } else free(e);
        }
        pthread_rwlock_unlock(&store->index_lock);
        if (!logged) { ok = false; break; }

        memcpy(out_hash, hash, QIHSE_BLOB_HASH_BYTES);
        if (out_size) *out_size = total;
        EVP_MD_CTX_free(ctx);
        return true;
    } while (0);

    if (tmp) fclose(tmp);
    if (tmp_path[0]) unlink(tmp_path);
    if (ctx) EVP_MD_CTX_free(ctx);
    return false;
}

bool qihse_blob_prepare_expected_user(qihse_blob_store_t* store, uint64_t txn_id,
                                      uint32_t tenant_id, qihse_blob_tag_t tag,
                                      uint16_t classification, uint16_t sci_compartment,
                                      qihse_user_t* user, qihse_blob_read_fn read_fn,
                                      void* read_opaque,
                                      const uint8_t expected_hash[QIHSE_BLOB_HASH_BYTES],
                                      uint64_t expected_size) {
    if (!txn_id || !expected_hash) return false;
    uint8_t actual[QIHSE_BLOB_HASH_BYTES];
    return blob_put_internal(store, tenant_id, tag, classification, sci_compartment,
        user, read_fn, read_opaque, actual, NULL, expected_hash, expected_size, txn_id);
}

bool qihse_blob_decision_next_id(qihse_blob_store_t* store, uint64_t* next_id) {
    if (!store || !next_id) return false;
    pthread_rwlock_rdlock(&store->index_lock);
    bool ok = !store->poisoned;
    uint64_t next = 1u;
    for (const blob_prepared_t* p = store->prepared; ok && p; p = p->next) {
        if (p->txn_id == UINT64_MAX) ok = false;
        else if (p->txn_id >= next) next = p->txn_id + 1u;
    }
    if (ok) *next_id = next;
    pthread_rwlock_unlock(&store->index_lock);
    return ok;
}

bool qihse_blob_resolve_prepared(qihse_blob_store_t* store, uint64_t txn_id,
                                 bool commit) {
    if (!store || !txn_id || store->owner_pid != getpid()) return false;
    pthread_rwlock_wrlock(&store->index_lock);
    if (store->poisoned) { pthread_rwlock_unlock(&store->index_lock); return false; }
    blob_prepared_t* prepared = blob_find_prepared(store, txn_id);
    /* An earlier participant may reject PREPARE before this one is attempted.
     * The coordinator's durable ABORT is authoritative; no receipt is invented. */
    if (!prepared) { pthread_rwlock_unlock(&store->index_lock); return !commit; }
    uint8_t wanted = commit ? 'C' : 'A';
    if (prepared->decision) {
        bool same = prepared->decision == wanted;
        pthread_rwlock_unlock(&store->index_lock);
        return same;
    }
    blob_entry_t* entry = blob_find_entry(store, prepared->info.hash);
    if (commit && !blob_prepared_content_valid(store, &prepared->info)) {
        pthread_rwlock_unlock(&store->index_lock); return false;
    }
    if (commit && entry && (entry->info.tenant_id != prepared->info.tenant_id ||
        entry->info.tag != prepared->info.tag ||
        entry->info.classification != prepared->info.classification ||
        entry->info.sci_compartment != prepared->info.sci_compartment ||
        prepared->info.refcount != entry->info.refcount + 1u)) {
        pthread_rwlock_unlock(&store->index_lock); return false;
    }
    pthread_mutex_lock(&store->log_lock);
    bool logged = blob_prepared_log(store, wanted, txn_id, NULL);
    pthread_mutex_unlock(&store->log_lock);
    if (!logged) { pthread_rwlock_unlock(&store->index_lock); return false; }
    prepared->decision = wanted;
    if (commit) {
        if (entry) entry->info = prepared->info;
        else {
            entry = calloc(1, sizeof(*entry));
            if (!entry) { store->poisoned = true; pthread_rwlock_unlock(&store->index_lock); return false; }
            entry->info = prepared->info;
            size_t slot = blob_slot(entry->info.hash);
            entry->next = store->slots[slot]; store->slots[slot] = entry;
            store->entry_count++;
        }
    } else if (!entry) {
        char path[640]; blob_object_path(store, prepared->info.hash, path, sizeof(path));
        (void)unlink(path);
        char hex[QIHSE_BLOB_HASH_HEX], shard[600];
        qihse_blob_hash_to_hex(prepared->info.hash, hex);
        snprintf(shard, sizeof(shard), "%s/objects/%.2s", store->base_dir, hex);
        (void)blob_fsync_dir(shard);
    }
    pthread_rwlock_unlock(&store->index_lock);
    return true;
}

bool qihse_blob_put_user(qihse_blob_store_t* store, uint32_t tenant_id,
                         qihse_blob_tag_t tag, uint16_t classification,
                         uint16_t sci_compartment, qihse_user_t* user,
                         qihse_blob_read_fn read_fn, void* read_opaque,
                         uint8_t out_hash[QIHSE_BLOB_HASH_BYTES], uint64_t* out_size) {
    return blob_put_internal(store, tenant_id, tag, classification,
                             sci_compartment, user, read_fn, read_opaque,
                             out_hash, out_size, NULL, 0u, 0u);
}

bool qihse_blob_put_expected_user(qihse_blob_store_t* store,
                                  uint32_t tenant_id, qihse_blob_tag_t tag,
                                  uint16_t classification,
                                  uint16_t sci_compartment, qihse_user_t* user,
                                  qihse_blob_read_fn read_fn, void* read_opaque,
                                  const uint8_t expected_hash[QIHSE_BLOB_HASH_BYTES],
                                  uint64_t expected_size) {
    if (!expected_hash) return false;
    uint8_t actual_hash[QIHSE_BLOB_HASH_BYTES];
    uint64_t actual_size = 0u;
    return blob_put_internal(store, tenant_id, tag, classification,
                             sci_compartment, user, read_fn, read_opaque,
                             actual_hash, &actual_size, expected_hash,
                             expected_size, 0u);
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

bool qihse_blob_verify_with_info_user(qihse_blob_store_t* store,
                                      const uint8_t* hash, qihse_user_t* user,
                                      qihse_blob_info_t* out_info,
                                      uint8_t* out_prefix, size_t prefix_len) {
    if (!store || !hash || !user || prefix_len > 256u ||
        (prefix_len && !out_prefix)) return false;
    blob_entry_t* e = NULL;
    char object_path[640];
    if (!blob_open_entry(store, hash, user, &e, object_path,
                         sizeof(object_path))) return false;
    qihse_blob_info_t info = e->info;
    uint64_t expected_size = info.size;
    int fd = open(object_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    pthread_rwlock_unlock(&store->index_lock);
    if (fd < 0 || prefix_len > expected_size) {
        if (fd >= 0) close(fd);
        return false;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size != expected_size) {
        close(fd);
        return false;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestInit_ex(ctx, blob_sha384(store), NULL) == 1;
    uint8_t buffer[64u * 1024u];
    uint8_t prefix[256u];
    uint64_t total = 0u;
    while (ok && total < expected_size) {
        size_t wanted = sizeof(buffer);
        if (expected_size - total < wanted) wanted = (size_t)(expected_size - total);
        ssize_t n = read(fd, buffer, wanted);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0 || EVP_DigestUpdate(ctx, buffer, (size_t)n) != 1) {
            ok = false;
            break;
        }
        if (total < prefix_len) {
            size_t part = prefix_len - (size_t)total;
            if (part > (size_t)n) part = (size_t)n;
            memcpy(prefix + total, buffer, part);
        }
        total += (uint64_t)n;
    }
    uint8_t actual[QIHSE_BLOB_HASH_BYTES];
    unsigned int actual_len = 0u;
    if (ok) ok = EVP_DigestFinal_ex(ctx, actual, &actual_len) == 1 &&
        actual_len == QIHSE_BLOB_HASH_BYTES &&
        CRYPTO_memcmp(actual, hash, QIHSE_BLOB_HASH_BYTES) == 0;
    EVP_MD_CTX_free(ctx);
    if (close(fd) != 0) ok = false;
    if (ok) {
        if (out_info) *out_info = info;
        if (prefix_len) memcpy(out_prefix, prefix, prefix_len);
    }
    return ok;
}

bool qihse_blob_verify_user(qihse_blob_store_t* store, const uint8_t* hash,
                            qihse_user_t* user) {
    return qihse_blob_verify_with_info_user(store, hash, user, NULL, NULL, 0u);
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
    if (store->poisoned || blob_hash_reserved_by_other_prepare(store, hash, 0u)) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
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
        qihse_blob_info_t snapshot = e->info;
        snapshot.refcount++;
        pthread_mutex_lock(&store->log_lock);
        bool logged = blob_log_append(store, 'R', &snapshot);
        pthread_mutex_unlock(&store->log_lock);
        if (logged) e->info = snapshot;
        pthread_rwlock_unlock(&store->index_lock);
        return logged;
    }
    if (e->info.refcount > 1) {
        qihse_blob_info_t snapshot = e->info;
        snapshot.refcount--;
        pthread_mutex_lock(&store->log_lock);
        bool logged = blob_log_append(store, 'U', &snapshot);
        pthread_mutex_unlock(&store->log_lock);
        if (logged) e->info = snapshot;
        pthread_rwlock_unlock(&store->index_lock);
        return logged;
    }
    if (!allow_delete || e->pin_count > 0 || e->snapshot_refs > 0) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    /* Durably remove the index reference before unlinking the object. A
     * failed unlink can leave an orphan, never a live index to missing data. */
    char object_path[640];
    blob_object_path(store, hash, object_path, sizeof(object_path));
    qihse_blob_info_t snapshot = e->info;
    pthread_mutex_lock(&store->log_lock);
    bool logged = blob_log_append(store, 'D', &snapshot);
    pthread_mutex_unlock(&store->log_lock);
    if (!logged) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    blob_entry_t** link = &store->slots[blob_slot(hash)];
    while (*link && *link != e) link = &(*link)->next;
    if (*link) *link = e->next;
    free(e);
    store->entry_count--;
    if (unlink(object_path) == 0) {
        char shard_dir[600];
        char hex[QIHSE_BLOB_HASH_HEX];
        qihse_blob_hash_to_hex(hash, hex);
        snprintf(shard_dir, sizeof(shard_dir), "%s/objects/%.2s", store->base_dir, hex);
        (void)blob_fsync_dir(shard_dir);
    }
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

bool qihse_blob_pin_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user) {
    if (!store || !hash || !user) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) return false;

    pthread_rwlock_wrlock(&store->index_lock);
    if (store->poisoned) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    blob_entry_t* e = blob_find_entry(store, hash);
    if (!e) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    bool owner = (user_tenant == QIHSE_TENANT_SYSTEM || e->info.tenant_id == user_tenant);
    if (!owner || !qihse_auth_can_access(user, e->info.classification, e->info.sci_compartment)) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    if (e->pin_count == UINT32_MAX) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    qihse_blob_info_t snapshot = e->info;
    pthread_mutex_lock(&store->log_lock);
    bool logged = blob_log_append(store, 'I', &snapshot);
    pthread_mutex_unlock(&store->log_lock);
    if (logged) e->pin_count++;
    pthread_rwlock_unlock(&store->index_lock);
    return logged;
}

bool qihse_blob_unpin_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user) {
    if (!store || !hash || !user) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) return false;

    pthread_rwlock_wrlock(&store->index_lock);
    if (store->poisoned) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    blob_entry_t* e = blob_find_entry(store, hash);
    if (!e) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    bool owner = (user_tenant == QIHSE_TENANT_SYSTEM || e->info.tenant_id == user_tenant);
    if (!owner || !qihse_auth_can_access(user, e->info.classification, e->info.sci_compartment)) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    if (e->pin_count == 0) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    qihse_blob_info_t snapshot = e->info;
    pthread_mutex_lock(&store->log_lock);
    bool logged = blob_log_append(store, 'O', &snapshot);
    pthread_mutex_unlock(&store->log_lock);
    if (logged) e->pin_count--;
    pthread_rwlock_unlock(&store->index_lock);
    return logged;
}

bool qihse_blob_pin_count_user(qihse_blob_store_t* store, const uint8_t* hash,
                               qihse_user_t* user, uint32_t* out_pin_count) {
    if (!out_pin_count) return false;
    *out_pin_count = 0;
    if (!store || !hash || !user) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) return false;

    pthread_rwlock_rdlock(&store->index_lock);
    blob_entry_t* e = blob_find_entry(store, hash);
    if (!e) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    bool owner = (user_tenant == QIHSE_TENANT_SYSTEM || e->info.tenant_id == user_tenant);
    if (!owner || !qihse_auth_can_access(user, e->info.classification, e->info.sci_compartment)) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    *out_pin_count = e->pin_count;
    pthread_rwlock_unlock(&store->index_lock);
    return true;
}

bool qihse_blob_is_pinned_user(qihse_blob_store_t* store, const uint8_t* hash,
                               qihse_user_t* user, bool* out_pinned) {
    if (!out_pinned) return false;
    *out_pinned = false;
    uint32_t pin_count = 0;
    if (!qihse_blob_pin_count_user(store, hash, user, &pin_count)) return false;
    *out_pinned = (pin_count > 0);
    return true;
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

typedef struct {
    blob_entry_t* entry;
    qihse_blob_info_t info;
    uint32_t pin_count;
} blob_snapshot_item_t;

typedef struct {
    int fd;
    uint64_t remaining;
    uint64_t size;
    const uint8_t* expected_hash;
    EVP_MD_CTX* digest;
    bool verified;
    bool failed;
} blob_snapshot_reader_t;

static bool blob_snapshot_reader_finish(blob_snapshot_reader_t* reader) {
    if (!reader || reader->failed || reader->remaining != 0) return false;
    if (reader->verified) return true;

    uint8_t extra = 0;
    ssize_t n;
    do { n = pread(reader->fd, &extra, 1u, (off_t)reader->size); }
    while (n < 0 && errno == EINTR);
    if (n != 0) {
        reader->failed = true;
        return false;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(reader->digest, digest, &digest_len) != 1 ||
        digest_len != QIHSE_BLOB_HASH_BYTES ||
        CRYPTO_memcmp(digest, reader->expected_hash, QIHSE_BLOB_HASH_BYTES) != 0) {
        reader->failed = true;
        return false;
    }
    reader->verified = true;
    return true;
}

static int64_t blob_snapshot_read(void* opaque, uint8_t* buffer, size_t capacity) {
    blob_snapshot_reader_t* reader = opaque;
    if (!reader || !buffer || capacity == 0 || reader->failed) return -1;
    if (reader->remaining == 0)
        return blob_snapshot_reader_finish(reader) ? 0 : -1;
    size_t request = capacity;
    if ((uint64_t)request > reader->remaining) request = (size_t)reader->remaining;
    ssize_t n;
    do { n = read(reader->fd, buffer, request); } while (n < 0 && errno == EINTR);
    if (n <= 0 || EVP_DigestUpdate(reader->digest, buffer, (size_t)n) != 1) {
        reader->failed = true;
        return -1;
    }
    reader->remaining -= (uint64_t)n;
    if (reader->remaining == 0 && !blob_snapshot_reader_finish(reader)) return -1;
    return (int64_t)n;
}

static int blob_snapshot_hash_order(const void* a, const void* b) {
    const blob_snapshot_item_t* left = a;
    const blob_snapshot_item_t* right = b;
    return memcmp(left->info.hash, right->info.hash, QIHSE_BLOB_HASH_BYTES);
}

static bool blob_snapshot_all_user(qihse_blob_store_t* store, qihse_user_t* user,
                                  qihse_blob_snapshot_entry_fn callback,
                                  void* callback_opaque,
                                  blob_prepared_t** receipts, size_t* receipt_count) {
    if (receipts) { *receipts = NULL; *receipt_count = 0u; }
    if (!store || !callback || store->owner_pid != getpid()) return false;
    uint32_t user_tenant = 0;
    if (!blob_user_tenant(user, &user_tenant)) return false;

    pthread_rwlock_wrlock(&store->index_lock);
    if (store->poisoned) {
        pthread_rwlock_unlock(&store->index_lock);
        errno = EIO;
        return false;
    }
    size_t count = store->entry_count;
    blob_snapshot_item_t* items = calloc(count ? count : 1u, sizeof(*items));
    if (!items) {
        pthread_rwlock_unlock(&store->index_lock);
        return false;
    }
    size_t at = 0;
    int preflight_error = 0;
    for (size_t i = 0; i < BLOB_INDEX_SLOTS && preflight_error == 0; i++) {
        for (blob_entry_t* e = store->slots[i]; e; e = e->next) {
            if (!blob_can_read(e, user_tenant, user)) {
                qihse_audit_log("BLOB_SNAPSHOT_DENIED", user_tenant, e->info.tenant_id,
                                e->info.classification, e->info.sci_compartment);
                preflight_error = EACCES;
                break;
            }
            if (e->snapshot_refs == UINT32_MAX) {
                preflight_error = EOVERFLOW;
                break;
            }
            if (at >= count) {
                preflight_error = EIO;
                break;
            }
            items[at].entry = e;
            items[at].info = e->info;
            items[at].pin_count = e->pin_count;
            at++;
        }
    }
    if (preflight_error == 0 && at != count) preflight_error = EIO;
    size_t terminal_count = 0u;
    blob_prepared_t* terminal = NULL;
    if (receipts && !preflight_error) {
        for (blob_prepared_t* p = store->prepared; p; p = p->next) {
            blob_entry_t binding = { .info = p->info };
            if (!p->decision) { preflight_error = EBUSY; break; }
            if (!blob_can_read(&binding, user_tenant, user)) {
                preflight_error = EACCES; break;
            }
            if (terminal_count == UINT32_MAX) { preflight_error = EOVERFLOW; break; }
            terminal_count++;
        }
        if (!preflight_error && terminal_count) {
            if (terminal_count > SIZE_MAX / sizeof(*terminal)) preflight_error = EOVERFLOW;
            else if (!(terminal = calloc(terminal_count, sizeof(*terminal))))
                preflight_error = ENOMEM;
        }
        if (!preflight_error && (count > UINT32_MAX || terminal_count > UINT32_MAX - count))
            preflight_error = EOVERFLOW;
        size_t n = 0u;
        for (blob_prepared_t* p = store->prepared; !preflight_error && p; p = p->next) {
            terminal[n] = *p;
            terminal[n++].next = NULL;
        }
    }
    if (preflight_error != 0) {
        free(terminal);
        free(items);
        pthread_rwlock_unlock(&store->index_lock);
        errno = preflight_error;
        return false;
    }
    for (size_t i = 0; i < count; i++) items[i].entry->snapshot_refs++;
    if (receipts) { *receipts = terminal; *receipt_count = terminal_count; }
    pthread_rwlock_unlock(&store->index_lock);

    /* Stable canonical archive order, independent of insertion/hash buckets. */
    qsort(items, count, sizeof(*items), blob_snapshot_hash_order);
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        char path[640];
        blob_object_path(store, items[i].info.hash, path, sizeof(path));
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) { ok = false; break; }
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
            (uint64_t)st.st_size != items[i].info.size) {
            close(fd);
            ok = false;
            break;
        }
        blob_snapshot_reader_t reader = {
            .fd = fd,
            .remaining = items[i].info.size,
            .size = items[i].info.size,
            .expected_hash = items[i].info.hash,
            .digest = EVP_MD_CTX_new(),
        };
        if (!reader.digest ||
            EVP_DigestInit_ex(reader.digest, blob_sha384(store), NULL) != 1) {
            EVP_MD_CTX_free(reader.digest);
            close(fd);
            ok = false;
            break;
        }
        ok = callback(&items[i].info, items[i].pin_count,
                      blob_snapshot_read, &reader, callback_opaque) &&
             reader.verified && !reader.failed;
        EVP_MD_CTX_free(reader.digest);
        if (close(fd) != 0) ok = false;
    }

    pthread_rwlock_wrlock(&store->index_lock);
    for (size_t i = 0; i < count; i++) {
        if (items[i].entry->snapshot_refs > 0) items[i].entry->snapshot_refs--;
    }
    pthread_rwlock_unlock(&store->index_lock);
    free(items);
    return ok;
}

bool qihse_blob_snapshot_all_user(qihse_blob_store_t* store, qihse_user_t* user,
                                  qihse_blob_snapshot_entry_fn callback,
                                  void* callback_opaque) {
    return blob_snapshot_all_user(store, user, callback, callback_opaque, NULL, NULL);
}

bool qihse_blob_snapshot_epoch_user(qihse_blob_store_t* store, qihse_user_t* user,
                                    uint64_t* epoch) {
    uint32_t tenant = 0u;
    if (!store || !epoch || store->owner_pid != getpid() ||
        !blob_user_tenant(user, &tenant)) return false;
    pthread_rwlock_rdlock(&store->index_lock);
    bool ok = !store->poisoned && store->index_fd >= 0;
    uint16_t classification = 0u, sci = 0u;
    for (size_t slot = 0u; ok && slot < BLOB_INDEX_SLOTS; ++slot)
        for (blob_entry_t* e = store->slots[slot]; ok && e; e = e->next) {
            ok = blob_can_read(e, tenant, user);
            if (e->info.classification > classification) classification = e->info.classification;
            sci |= e->info.sci_compartment;
        }
    for (blob_prepared_t* p = store->prepared; ok && p; p = p->next) {
        blob_entry_t binding = { .info = p->info };
        ok = p->decision && blob_can_read(&binding, tenant, user);
        if (p->info.classification > classification) classification = p->info.classification;
        sci |= p->info.sci_compartment;
    }
    struct stat st;
    uint32_t final_tenant = 0u;
    ok = ok && fstat(store->index_fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size >= 0 && blob_user_tenant(user, &final_tenant) && final_tenant == tenant &&
        qihse_auth_can_access(user, classification, sci);
    /* Every visible mutation appends durably while holding index_lock. Failed
     * appends either restore the old state/length or poison the handle. There
     * is no index compaction during a live handle's lifetime. */
    if (ok) *epoch = (uint64_t)st.st_size;
    pthread_rwlock_unlock(&store->index_lock);
    return ok;
}

/* Archive v1, all integers unsigned big-endian (never native structs):
 * header[16] = "QBLARCH1", version:u32=1, entry_header_bytes:u32=96.
 * entry[96] = type:u64=1, ordinal:u64, hash[48], size:u64, tenant:u32,
 *             tag:u16, classification:u16, sci:u16, reserved:u16=0,
 *             refcount:u32, pins:u32, reserved:u32=0; then size content bytes.
 * Entries are strictly hash-ascending. Footer[16] = type:u64=0, count:u64.
 * HMAC-SHA-384[48] authenticates header, every entry/content and footer.
 * No extensions, trailing bytes or implicit defaults are accepted in v1.
 * V2 retains the magic/entry size, changes version to 2, and appends type=2
 * terminal receipts after live entries. Receipt metadata uses the same 96-byte
 * header (pins=0), followed by txn_id:u64, decision:u8 ('C'/'A'), reserved[7]=0,
 * with no content bytes. Receipts are strictly transaction-ID ascending.
 */
static const uint8_t blob_archive_header[16] = {
    'Q', 'B', 'L', 'A', 'R', 'C', 'H', '1', 0, 0, 0, 1, 0, 0, 0, 96
};

static void blob_archive_encode(uint8_t* p, uint64_t value, size_t bytes) {
    for (size_t i = bytes; i > 0; i--) { p[i - 1u] = (uint8_t)value; value >>= 8; }
}

static uint64_t blob_archive_decode(const uint8_t* p, size_t bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < bytes; i++) value = (value << 8) | p[i];
    return value;
}

static EVP_MAC_CTX* blob_archive_mac(const uint8_t* key, size_t length) {
    if (!key || length != QIHSE_BLOB_ARCHIVE_KEY_BYTES) return NULL;
    EVP_MAC* algorithm = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!algorithm) return NULL;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(algorithm);
    EVP_MAC_free(algorithm);
    char digest[] = "SHA384";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()
    };
    if (ctx && EVP_MAC_init(ctx, key, length, params) == 1) return ctx;
    EVP_MAC_CTX_free(ctx);
    return NULL;
}

typedef struct {
    EVP_MAC_CTX* mac;
    qihse_blob_write_fn write_fn;
    void* opaque;
    uint8_t* buffer;
    uint64_t count;
    bool started;
    blob_prepared_t* receipts;
    size_t receipt_count;
    uint16_t required_classification;
    uint16_t required_sci;
} blob_archive_writer_t;

static bool blob_archive_write(blob_archive_writer_t* writer,
                                const uint8_t* data, size_t length) {
    return EVP_MAC_update(writer->mac, data, length) == 1 &&
           writer->write_fn(writer->opaque, data, length);
}

static bool blob_archive_start(blob_archive_writer_t* writer) {
    if (writer->started) return true;
    writer->started = true;
    uint8_t header[sizeof(blob_archive_header)];
    memcpy(header, blob_archive_header, sizeof(header));
    if (writer->receipt_count) blob_archive_encode(header + 8, 2u, 4u);
    return blob_archive_write(writer, header, sizeof(header));
}

static bool blob_archive_export_entry(const qihse_blob_info_t* info, uint32_t pins,
                                      qihse_blob_read_fn read_fn, void* read_opaque,
                                      void* opaque) {
    blob_archive_writer_t* writer = opaque;
    if (info->classification > writer->required_classification)
        writer->required_classification = info->classification;
    writer->required_sci |= info->sci_compartment;
    if (writer->count == UINT32_MAX || !blob_archive_start(writer)) return false;
    uint8_t record[96] = {0};
    blob_archive_encode(record, 1, 8);
    blob_archive_encode(record + 8, writer->count, 8);
    memcpy(record + 16, info->hash, QIHSE_BLOB_HASH_BYTES);
    blob_archive_encode(record + 64, info->size, 8);
    blob_archive_encode(record + 72, info->tenant_id, 4);
    blob_archive_encode(record + 76, info->tag, 2);
    blob_archive_encode(record + 78, info->classification, 2);
    blob_archive_encode(record + 80, info->sci_compartment, 2);
    blob_archive_encode(record + 84, info->refcount, 4);
    blob_archive_encode(record + 88, pins, 4);
    if (!blob_archive_write(writer, record, sizeof(record))) return false;
    for (;;) {
        int64_t n = read_fn(read_opaque, writer->buffer, QIHSE_BLOB_CHUNK_SIZE);
        if (n < 0 || n > QIHSE_BLOB_CHUNK_SIZE) return false;
        if (n == 0) break;
        if (!blob_archive_write(writer, writer->buffer, (size_t)n)) return false;
    }
    writer->count++;
    return true;
}

static int blob_archive_receipt_order(const void* left, const void* right) {
    uint64_t a = ((const blob_prepared_t*)left)->txn_id;
    uint64_t b = ((const blob_prepared_t*)right)->txn_id;
    return a < b ? -1 : a > b ? 1 : 0;
}

static bool blob_archive_export_receipt(blob_archive_writer_t* writer,
                                        const blob_prepared_t* receipt) {
    if (writer->count == UINT32_MAX) return false;
    const qihse_blob_info_t* info = &receipt->info;
    if (info->classification > writer->required_classification)
        writer->required_classification = info->classification;
    writer->required_sci |= info->sci_compartment;
    uint8_t record[112] = {0};
    blob_archive_encode(record, 2u, 8u);
    blob_archive_encode(record + 8, writer->count, 8u);
    memcpy(record + 16, info->hash, QIHSE_BLOB_HASH_BYTES);
    blob_archive_encode(record + 64, info->size, 8u);
    blob_archive_encode(record + 72, info->tenant_id, 4u);
    blob_archive_encode(record + 76, info->tag, 2u);
    blob_archive_encode(record + 78, info->classification, 2u);
    blob_archive_encode(record + 80, info->sci_compartment, 2u);
    blob_archive_encode(record + 84, info->refcount, 4u);
    blob_archive_encode(record + 96, receipt->txn_id, 8u);
    record[104] = receipt->decision;
    if (!blob_archive_write(writer, record, sizeof(record))) return false;
    writer->count++;
    return true;
}

bool qihse_blob_archive_export_user(qihse_blob_store_t* store, qihse_user_t* user,
                                    const uint8_t* key, size_t key_length,
                                    qihse_blob_write_fn write_fn, void* opaque) {
    uint32_t tenant;
    if (!store || !write_fn || !blob_user_tenant(user, &tenant)) return false;
    blob_archive_writer_t writer = { .mac = blob_archive_mac(key, key_length),
        .write_fn = write_fn, .opaque = opaque, .buffer = malloc(QIHSE_BLOB_CHUNK_SIZE) };
    bool ok = false;
    if (!writer.mac || !writer.buffer) goto done;
    if (!blob_snapshot_all_user(store, user, blob_archive_export_entry, &writer,
            &writer.receipts, &writer.receipt_count) ||
        !blob_archive_start(&writer)) goto done;
    if (writer.receipt_count)
        qsort(writer.receipts, writer.receipt_count, sizeof(*writer.receipts),
            blob_archive_receipt_order);
    for (size_t i = 0u; i < writer.receipt_count; ++i) {
        blob_entry_t binding = { .info = writer.receipts[i].info };
        if (!blob_can_read(&binding, tenant, user) ||
            !blob_archive_export_receipt(&writer, &writer.receipts[i])) goto done;
    }
    uint8_t footer[16] = {0}, mac[QIHSE_BLOB_HASH_BYTES];
    size_t mac_length = 0;
    blob_archive_encode(footer + 8, writer.count, 8);
    if (!blob_archive_write(&writer, footer, sizeof(footer)) ||
        EVP_MAC_final(writer.mac, mac, &mac_length, sizeof(mac)) != 1 ||
        mac_length != sizeof(mac)) goto done;
    uint32_t final_tenant = 0u;
    ok = write_fn(opaque, mac, sizeof(mac)) &&
        blob_user_tenant(user, &final_tenant) && final_tenant == tenant &&
        qihse_auth_can_access(user, writer.required_classification, writer.required_sci);
done:
    EVP_MAC_CTX_free(writer.mac);
    free(writer.receipts);
    free(writer.buffer);
    return ok;
}

typedef struct {
    EVP_MAC_CTX* mac;
    qihse_blob_read_fn read_fn;
    void* opaque;
    uint64_t remaining;
} blob_archive_reader_t;

static bool blob_archive_read_exact(blob_archive_reader_t* reader,
                                     uint8_t* buffer, size_t length, bool authenticate) {
    size_t at = 0;
    while (at < length) {
        int64_t n = reader->read_fn(reader->opaque, buffer + at, length - at);
        if (n <= 0 || (uint64_t)n > length - at) return false;
        if (authenticate && EVP_MAC_update(reader->mac, buffer + at, (size_t)n) != 1)
            return false;
        at += (size_t)n;
    }
    return true;
}

static int64_t blob_archive_content_read(void* opaque, uint8_t* buffer, size_t capacity) {
    blob_archive_reader_t* reader = opaque;
    if (reader->remaining == 0) return 0;
    size_t request = capacity;
    if (reader->remaining < request) request = (size_t)reader->remaining;
    if (!request || !blob_archive_read_exact(reader, buffer, request, true)) return -1;
    reader->remaining -= request;
    return (int64_t)request;
}

/* Only used on a private, unpublished store: a failed write discards the stage.
 * 'S' is an absolute local-index state record, preserving full uint32 pin counts
 * without looping billions of times or changing public blob metadata layout. */
static bool blob_archive_restore_state(qihse_blob_store_t* store,
                                       const qihse_blob_info_t* info, uint32_t pins) {
    uint8_t record[3u + sizeof(*info) + sizeof(pins)];
    record[0] = BLOB_INDEX_MAGIC;
    record[1] = BLOB_INDEX_VERSION;
    record[2] = 'S';
    memcpy(record + 3, info, sizeof(*info));
    memcpy(record + 3 + sizeof(*info), &pins, sizeof(pins));
    size_t at = 0;
    while (at < sizeof(record)) {
        ssize_t n = write(store->index_fd, record + at, sizeof(record) - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    blob_entry_t* entry = blob_find_entry(store, info->hash);
    if (!entry) return false;
    entry->info = *info;
    entry->pin_count = pins;
    return true;
}

static bool blob_archive_receipt_authorized(const qihse_blob_info_t* info,
                                            uint32_t tenant, qihse_user_t* user) {
    blob_entry_t binding = { .info = *info };
    return blob_can_read(&binding, tenant, user) &&
        (tenant == QIHSE_TENANT_SYSTEM ||
         (info->tenant_id == tenant && info->tag != QIHSE_BLOB_TAG_COMMONS_SNAPSHOT)) &&
        (info->tag != QIHSE_BLOB_TAG_REPL_TRANSACTION ||
         (info->tenant_id == QIHSE_TENANT_SYSTEM &&
          qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR));
}

/* Import receipts without replaying their historical row/refcount effects. */
static bool blob_archive_restore_receipt(qihse_blob_store_t* store, uint64_t txn_id,
                                        const qihse_blob_info_t* info, uint8_t decision) {
    blob_prepared_t* receipt = calloc(1u, sizeof(*receipt));
    if (!receipt || blob_find_prepared(store, txn_id)) { free(receipt); return false; }
    uint8_t record[3u + sizeof(txn_id) + sizeof(*info) + 1u];
    record[0] = BLOB_INDEX_MAGIC;
    record[1] = BLOB_INDEX_VERSION;
    record[2] = 'F';
    memcpy(record + 3, &txn_id, sizeof(txn_id));
    memcpy(record + 3 + sizeof(txn_id), info, sizeof(*info));
    record[sizeof(record) - 1u] = decision;
    size_t at = 0u;
    while (at < sizeof(record)) {
        ssize_t n = write(store->index_fd, record + at, sizeof(record) - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(receipt); return false; }
        at += (size_t)n;
    }
    receipt->txn_id = txn_id;
    receipt->info = *info;
    receipt->decision = decision;
    receipt->next = store->prepared;
    store->prepared = receipt;
    return true;
}

/* fd-relative, no symlink traversal; only our fresh stage has this tree shape. */
static void blob_archive_remove_stage(int parent, const char* name, unsigned depth) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { (void)unlinkat(parent, name, 0); return; }
    DIR* dir = fdopendir(fd);
    if (!dir) { close(fd); return; }
    struct dirent* item;
    while ((item = readdir(dir)) != NULL) {
        if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, item->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        if (S_ISDIR(st.st_mode) && depth > 0)
            blob_archive_remove_stage(fd, item->d_name, depth - 1u);
        else (void)unlinkat(fd, item->d_name, 0);
    }
    closedir(dir);
    (void)unlinkat(parent, name, AT_REMOVEDIR);
}

qihse_blob_archive_result_t qihse_blob_archive_restore_user(
    const char* destination, qihse_user_t* user,
    const uint8_t* key, size_t key_length,
    qihse_blob_read_fn read_fn, void* opaque) {
    uint32_t tenant;
    if (!destination || !*destination || !read_fn || !blob_user_tenant(user, &tenant))
        return QIHSE_BLOB_ARCHIVE_ERROR;
    blob_archive_reader_t reader = { .mac = blob_archive_mac(key, key_length),
        .read_fn = read_fn, .opaque = opaque };
    char* path = strdup(destination);
    int parent = -1;
    char stage[96] = {0};
    const char* stage_name = NULL;
    qihse_blob_store_t* store = NULL;
    qihse_blob_archive_result_t result = QIHSE_BLOB_ARCHIVE_ERROR;
    if (!reader.mac || !path) goto done;
    char* slash = strrchr(path, '/');
    const char* name = slash ? slash + 1 : path;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) goto done;
    const char* parent_path = ".";
    if (slash) {
        *slash = '\0';
        parent_path = *path ? path : "/";
    }
    parent = open(parent_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent < 0) goto done;
    struct stat st;
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
        goto done;
    /* The proc FD path keeps all store path-based operations anchored to the
     * held parent, even if its original path is renamed during the stream. */
    int n = snprintf(stage, sizeof(stage), "/proc/self/fd/%d/.qihse-archive-XXXXXX", parent);
    if (n < 0 || (size_t)n >= sizeof(stage) || !mkdtemp(stage)) goto done;
    stage_name = strrchr(stage, '/') + 1;
    store = qihse_blob_store_create(stage);
    if (!store) goto done;
    uint8_t record[112], previous[QIHSE_BLOB_HASH_BYTES] = {0};
    uint64_t count = 0u, live_count = 0u, previous_txn = 0u;
    if (!blob_archive_read_exact(&reader, record, sizeof(blob_archive_header), true) ||
        memcmp(record, blob_archive_header, 8u) != 0 ||
        blob_archive_decode(record + 12, 4u) != 96u) goto done;
    uint64_t version = blob_archive_decode(record + 8, 4u);
    if (version != 1u && version != 2u) goto done;
    for (;;) {
        if (!blob_archive_read_exact(&reader, record, 16, true)) goto done;
        uint64_t type = blob_archive_decode(record, 8);
        if (blob_archive_decode(record + 8, 8) != count) goto done;
        if (type == 0) break;
        if ((type != 1u && (type != 2u || version != 2u)) || count == UINT32_MAX ||
            !blob_archive_read_exact(&reader, record + 16, 80, true)) goto done;
        qihse_blob_info_t info = {0};
        memcpy(info.hash, record + 16, sizeof(info.hash));
        info.size = blob_archive_decode(record + 64, 8);
        info.tenant_id = (uint32_t)blob_archive_decode(record + 72, 4);
        info.tag = (uint16_t)blob_archive_decode(record + 76, 2);
        info.classification = (uint16_t)blob_archive_decode(record + 78, 2);
        info.sci_compartment = (uint16_t)blob_archive_decode(record + 80, 2);
        info.refcount = (uint32_t)blob_archive_decode(record + 84, 4);
        uint32_t pins = (uint32_t)blob_archive_decode(record + 88, 4);
        if (blob_archive_decode(record + 82, 2) || blob_archive_decode(record + 92, 4) ||
            !info.refcount || !info.tag || info.tag > QIHSE_BLOB_TAG_DUMP_ARTIFACT ||
            info.size > blob_size_limit(info.tag)) goto done;
        if (type == 1u) {
            if (previous_txn ||
                (live_count && memcmp(previous, info.hash, sizeof(previous)) >= 0)) goto done;
            reader.remaining = info.size;
            if (!qihse_blob_put_expected_user(store, info.tenant_id, (qihse_blob_tag_t)info.tag,
                    info.classification, info.sci_compartment, user,
                    blob_archive_content_read, &reader, info.hash, info.size) ||
                reader.remaining || !blob_archive_restore_state(store, &info, pins)) goto done;
            memcpy(previous, info.hash, sizeof(previous));
            live_count++;
        } else {
            if (pins || !blob_archive_read_exact(&reader, record + 96, 16u, true)) goto done;
            uint64_t txn_id = blob_archive_decode(record + 96, 8u);
            uint8_t decision = record[104];
            if (!txn_id || txn_id <= previous_txn ||
                (decision != 'C' && decision != 'A') ||
                blob_archive_decode(record + 105, 7u) ||
                !blob_archive_receipt_authorized(&info, tenant, user) ||
                !blob_archive_restore_receipt(store, txn_id, &info, decision)) goto done;
            previous_txn = txn_id;
        }
        count++;
    }
    if (version == 2u && !previous_txn) goto done;
    uint8_t expected[QIHSE_BLOB_HASH_BYTES], actual[QIHSE_BLOB_HASH_BYTES], extra;
    size_t mac_length = 0;
    if (!blob_archive_read_exact(&reader, expected, sizeof(expected), false) ||
        EVP_MAC_final(reader.mac, actual, &mac_length, sizeof(actual)) != 1 ||
        mac_length != sizeof(actual) || CRYPTO_memcmp(expected, actual, sizeof(actual)) ||
        read_fn(opaque, &extra, 1) != 0 || !blob_user_tenant(user, &tenant)) goto done;
    /* Recheck authorization after arbitrary caller I/O, including the final EOF. */
    for (size_t i = 0; i < BLOB_INDEX_SLOTS; i++) {
        for (blob_entry_t* e = store->slots[i]; e; e = e->next) {
            if (!blob_can_read(e, tenant, user) ||
                (tenant != QIHSE_TENANT_SYSTEM &&
                 (e->info.tenant_id != tenant || e->info.tag == QIHSE_BLOB_TAG_COMMONS_SNAPSHOT)) ||
                (e->info.tag == QIHSE_BLOB_TAG_REPL_TRANSACTION &&
                 qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR)) goto done;
        }
    }
    for (blob_prepared_t* p = store->prepared; p; p = p->next)
        if (!blob_archive_receipt_authorized(&p->info, tenant, user)) goto done;
    /* put_expected already fsyncs content and shard dirs before indexing. */
    if (fsync(store->index_fd) != 0 || !blob_fsync_dir(store->objects_dir) ||
        !blob_fsync_dir(store->base_dir)) goto done;
    qihse_blob_store_destroy(store);
    store = NULL;
    if (renameat2(parent, stage_name, parent, name, RENAME_NOREPLACE) != 0) goto done;
    stage_name = NULL;
    result = fsync(parent) == 0 ? QIHSE_BLOB_ARCHIVE_OK :
                                QIHSE_BLOB_ARCHIVE_PUBLISHED_UNSYNCED;
done:
    qihse_blob_store_destroy(store);
    if (stage_name) blob_archive_remove_stage(parent, stage_name, 3);
    if (parent >= 0) close(parent);
    free(path);
    EVP_MAC_CTX_free(reader.mac);
    return result;
}
