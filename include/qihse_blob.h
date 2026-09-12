#ifndef QIHSE_BLOB_H
#define QIHSE_BLOB_H

/* U1 — content-addressed object/blob tier for session-delivery workloads
 * (SESSION_DELIVERY_UPGRADES.md). Blobs are immutable, addressed by their
 * SHA-256, streamed to/from disk (never fully buffered by the store), and
 * bound to a tenant + class tag + classification/SCI at write time.
 *
 * SECURITY (AGENTS.md invariant #1): every operation takes an authenticated
 * qihse_user_t* and NULL is unconditionally denied — there is deliberately
 * no context-free variant of any blob primitive. Tenant principals may only
 * touch blobs bound to their own tenant; commons collections are readable by
 * every authenticated tenant but writable only by the system domain.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_BLOB_HASH_BYTES 48u  /* SHA-384 (CNSA 2.0 aligned; auth uses PBKDF2-HMAC-SHA-384) */
#define QIHSE_BLOB_HASH_HEX   (2u * QIHSE_BLOB_HASH_BYTES + 1u)
#define QIHSE_BLOB_MAX_SIZE   (64u * 1024u * 1024u) /* 64 MiB per blob */
#define QIHSE_BLOB_CHUNK_SIZE (256u * 1024u)

typedef enum {
    QIHSE_BLOB_TAG_ENTITLEMENT_SEED  = 1,
    QIHSE_BLOB_TAG_PATTERN_BUNDLE    = 2,
    QIHSE_BLOB_TAG_SCRIPT_SET        = 3,
    QIHSE_BLOB_TAG_COMMONS_SNAPSHOT  = 4
} qihse_blob_tag_t;

typedef struct qihse_blob_store qihse_blob_store_t;

/* Metadata for one stored blob (list callback payload). */
typedef struct {
    uint8_t hash[QIHSE_BLOB_HASH_BYTES];
    uint64_t size;
    uint32_t tenant_id;
    uint16_t tag;          /* qihse_blob_tag_t */
    uint16_t classification;
    uint16_t sci_compartment;
    uint32_t refcount;
} qihse_blob_info_t;

/* Create a blob store rooted at base_dir (created if missing). Layout:
 *   base_dir/objects/ab/<hex>   immutable content files
 *   base_dir/index.log          append-only metadata log (crash-safe replay)
 * Returns NULL on failure. */
qihse_blob_store_t* qihse_blob_store_create(const char* base_dir);
void qihse_blob_store_destroy(qihse_blob_store_t* store);

/* Streaming write. read_fn is pulled chunk-by-chunk:
 *   return >0: bytes placed in buffer; 0: EOF; <0: read error (aborts put).
 * Dedup: an existing blob with identical content AND identical binding
 * (tenant, tag, classif, sci) just bumps its refcount. A hash collision with
 * a DIFFERENT binding is refused — tenants cannot claim each other's blobs.
 * Commons-tagged blobs require a system-domain writer. out_hash receives the
 * SHA-256. */
typedef int64_t (*qihse_blob_read_fn)(void* opaque, uint8_t* buffer, size_t capacity);
bool qihse_blob_put_user(qihse_blob_store_t* store, uint32_t tenant_id,
                         qihse_blob_tag_t tag, uint16_t classification,
                         uint16_t sci_compartment, qihse_user_t* user,
                         qihse_blob_read_fn read_fn, void* read_opaque,
                         uint8_t out_hash[QIHSE_BLOB_HASH_BYTES], uint64_t* out_size);

/* Convenience one-shot write of an in-memory buffer. */
bool qihse_blob_put_buffer_user(qihse_blob_store_t* store, uint32_t tenant_id,
                                qihse_blob_tag_t tag, uint16_t classification,
                                uint16_t sci_compartment, qihse_user_t* user,
                                const uint8_t* data, size_t len,
                                uint8_t out_hash[QIHSE_BLOB_HASH_BYTES]);

/* Range read for resume/delta pulls. Reads up to buffer_len bytes starting
 * at offset; *out_read receives the byte count. Every call re-checks
 * authorization so a revoked principal cannot drain an in-flight transfer. */
bool qihse_blob_get_user(qihse_blob_store_t* store, const uint8_t* hash,
                         uint64_t offset, uint8_t* buffer, size_t buffer_len,
                         size_t* out_read, qihse_user_t* user);
bool qihse_blob_size_user(qihse_blob_store_t* store, const uint8_t* hash,
                          uint64_t* out_size, qihse_user_t* user);

/* Metadata lookup with full authorization (tenant binding + clearance).
 * Used by the bundle composer's sanity gate to verify a blob's binding. */
bool qihse_blob_info_user(qihse_blob_store_t* store, const uint8_t* hash,
                          qihse_blob_info_t* out_info, qihse_user_t* user);

/* Pin/unpin: manifest references so GC (U6) cannot reap in-use blobs. */
bool qihse_blob_ref_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);
bool qihse_blob_unref_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);

/* Delete one reference; the object is unlinked when the refcount hits zero. */
bool qihse_blob_delete_user(qihse_blob_store_t* store, const uint8_t* hash, qihse_user_t* user);

/* Tenant-scoped enumeration (a read primitive — clearance-checked per entry,
 * confined to the caller's tenant plus commons). Callback returning false
 * stops iteration. */
typedef bool (*qihse_blob_list_fn)(const qihse_blob_info_t* info, void* opaque);
bool qihse_blob_list_user(qihse_blob_store_t* store, qihse_user_t* user,
                          qihse_blob_list_fn callback, void* callback_opaque);

/* Hex helpers (hash <-> lowercase hex, NUL-terminated). */
void qihse_blob_hash_to_hex(const uint8_t* hash, char out[QIHSE_BLOB_HASH_HEX]);
bool qihse_blob_hash_from_hex(const char* hex, uint8_t out[QIHSE_BLOB_HASH_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_BLOB_H */
