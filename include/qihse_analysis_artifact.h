#ifndef QIHSE_ANALYSIS_ARTIFACT_H
#define QIHSE_ANALYSIS_ARTIFACT_H

/* KP14 analysis artifact manifest v1. This is a bounded, in-memory contract,
 * NOT a durable ingest or read API. See docs/KP14_ANALYSIS_ARTIFACT.md. */
#include <stdbool.h>
#include <stdint.h>
#include "qihse_auth.h"
#include "qihse_blob.h"

#define QIHSE_ANALYSIS_ARTIFACT_VERSION 1u
#define QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS 8u
#define QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES 64u
#define QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES 32u
#define QIHSE_ANALYSIS_ARTIFACT_MAX_MANIFEST_BYTES 4096u

typedef enum {
    QIHSE_ANALYSIS_BINARY = 1,
    QIHSE_ANALYSIS_DISASSEMBLY,
    QIHSE_ANALYSIS_CFG,
    QIHSE_ANALYSIS_TRACE,
    QIHSE_ANALYSIS_SOLVER,
    QIHSE_ANALYSIS_VERDICT,
    QIHSE_ANALYSIS_REPORT
} qihse_analysis_kind_t;

typedef enum {
    QIHSE_ANALYSIS_PARTIAL = 1,
    QIHSE_ANALYSIS_COMPLETE
} qihse_analysis_completion_t;

typedef enum {
    QIHSE_ANALYSIS_FIDELITY_UNASSESSED = 1,
    QIHSE_ANALYSIS_FIDELITY_PARTIAL,
    QIHSE_ANALYSIS_FIDELITY_VALIDATED
} qihse_analysis_fidelity_t;

typedef struct {
    uint16_t version;
    uint16_t kind;
    uint16_t completion;
    uint16_t fidelity;
    uint32_t tenant_id;
    uint16_t classification;
    uint16_t sci;
    char artifact_schema[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    char producer[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    char producer_version[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    uint8_t run_id[16];
    uint64_t generation;
    uint8_t binary_sha384[QIHSE_BLOB_HASH_BYTES];
    char isa[QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES];
    char mode[QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES];
    uint16_t address_bits;
    /* Zero means this artifact does not depend on that authority/pack. */
    uint8_t isanity_catalogue_sha384[QIHSE_BLOB_HASH_BYTES];
    uint8_t vexel_pack_sha384[QIHSE_BLOB_HASH_BYTES];
    uint64_t payload_size;
    uint8_t payload_sha384[QIHSE_BLOB_HASH_BYTES];
    uint8_t input_count;
    uint8_t input_ids[QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS][QIHSE_BLOB_HASH_BYTES];
    /* SHA-384 of the canonical field stream, not C struct bytes. */
    uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES];
} qihse_analysis_artifact_v1_t;

/* Build-time size ceiling; a future wire encoding must have its own bounded
 * decoder and may not treat compiler-specific struct layout as wire bytes. */
typedef char qihse_analysis_artifact_size_check[
    sizeof(qihse_analysis_artifact_v1_t) <= QIHSE_ANALYSIS_ARTIFACT_MAX_MANIFEST_BYTES ? 1 : -1];

/* Pure format validator and canonical identity computation. Neither reads
 * classified data; neither proves that payload or input IDs exist. */
bool qihse_analysis_artifact_compute_id(const qihse_analysis_artifact_v1_t* manifest,
                                        uint8_t out_id[QIHSE_BLOB_HASH_BYTES]);
bool qihse_analysis_artifact_validate(const qihse_analysis_artifact_v1_t* manifest);

/* Mandatory visibility gate for future classified-capable manifest reads and
 * exports. NULL, revoked, cross-tenant, above-clearance and missing SCI are
 * denied. Only a system-domain Operator may cross tenants. This is NOT
 * publisher/write authorization: ingestion needs a separate role/scope gate.
 * Never replace this with a context-free adapter. */
bool qihse_analysis_artifact_authorize_user(const qihse_analysis_artifact_v1_t* manifest,
                                            const qihse_user_t* user);

/* Publisher scope is separate from read clearance. Operators may publish
 * across tenants; tenant Analysts require an explicit per-tenant WRITE ACL.
 * Guests and system-domain Analysts cannot publish. */
#define QIHSE_ANALYSIS_PUBLISH_ACL_NAMESPACE 0x4b503134u /* "KP14" */
bool qihse_analysis_artifact_authorize_publisher(const qihse_analysis_artifact_v1_t* manifest,
                                                 const qihse_user_t* publisher);

/* Fail-closed, bounded candidate preflight. This does not write to a store,
 * reserve an ID, pin payload, or publish a feed event. The reader is invoked
 * only after publisher authorization; it must return 0 for EOF, <0 on error,
 * or 1..capacity bytes. No protected data is returned to the caller.
 * Derived artifacts deliberately remain LINEAGE_UNRESOLVED until an
 * authenticated immutable manifest store can prove every input. */
typedef enum {
    QIHSE_ANALYSIS_PREFLIGHT_DENIED = 0,
    QIHSE_ANALYSIS_PREFLIGHT_INVALID,
    QIHSE_ANALYSIS_PREFLIGHT_PAYLOAD_MISMATCH,
    QIHSE_ANALYSIS_PREFLIGHT_READ_ERROR,
    QIHSE_ANALYSIS_PREFLIGHT_LINEAGE_UNRESOLVED,
    QIHSE_ANALYSIS_PREFLIGHT_BINARY_VERIFIED
} qihse_analysis_preflight_result_t;
qihse_analysis_preflight_result_t qihse_analysis_artifact_preflight_user(
    const qihse_analysis_artifact_v1_t* manifest, qihse_user_t* publisher,
    qihse_blob_read_fn payload_reader, void* reader_opaque);

#include "qihse_federation.h"
#include "qihse_keystone.h"

/* Bounded projection carried as the payload of KEYSTONE.FEED.* events.
 * Keeps raw artifact bytes in QIHSE blobs while providing KEYSTONE with
 * the metadata required to index and filter candidates. */
typedef struct {
    uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES];
    uint8_t binary_sha384[QIHSE_BLOB_HASH_BYTES];
    uint8_t payload_sha384[QIHSE_BLOB_HASH_BYTES];
    uint64_t payload_size;
    uint32_t tenant_id;
    uint16_t classification;
    uint16_t sci;
    uint16_t kind;
    uint16_t completion;
    uint16_t fidelity;
    char artifact_schema[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    char producer[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    char producer_version[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
    uint64_t generation;
    char isa[QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES];
    char mode[QIHSE_ANALYSIS_ARTIFACT_CONTEXT_BYTES];
    uint16_t address_bits;
    uint8_t input_count;
    uint8_t input_ids[QIHSE_ANALYSIS_ARTIFACT_MAX_INPUTS][QIHSE_BLOB_HASH_BYTES];
    bool is_tombstone;
    char tombstone_reason[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];
} qihse_analysis_projection_t;

bool qihse_analysis_projection_encode(const qihse_analysis_projection_t* proj,
                                     uint8_t* out, size_t out_cap, size_t* out_len);

bool qihse_analysis_projection_decode(const uint8_t* in, size_t in_len,
                                     qihse_analysis_projection_t* out_proj);

/* Status codes for durable store operations */
typedef enum {
    QIHSE_ANALYSIS_STORE_OK = 0,
    QIHSE_ANALYSIS_STORE_DENIED = -1,
    QIHSE_ANALYSIS_STORE_INVALID = -2,
    QIHSE_ANALYSIS_STORE_NOT_FOUND = -3,
    QIHSE_ANALYSIS_STORE_TOMBSTONED = -4,
    QIHSE_ANALYSIS_STORE_LINEAGE_ERROR = -5,
    QIHSE_ANALYSIS_STORE_PAYLOAD_MISMATCH = -6,
    QIHSE_ANALYSIS_STORE_IO_ERROR = -7,
    QIHSE_ANALYSIS_STORE_INDEX_UNAVAILABLE = -8,
    QIHSE_ANALYSIS_STORE_CONFLICT = -9
} qihse_analysis_store_result_t;

/* Filter for candidate / search queries */
typedef struct {
    uint32_t tenant_id;           /* 0 = any accessible or caller tenant */
    uint16_t kind;                /* 0 = any kind */
    char artifact_schema[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES]; /* "" = any */
    char producer[QIHSE_ANALYSIS_ARTIFACT_TEXT_BYTES];        /* "" = any */
    uint8_t binary_sha384[QIHSE_BLOB_HASH_BYTES];            /* zero bytes = any */
    bool match_binary;
    bool include_tombstones;
} qihse_analysis_search_filter_t;

typedef struct qihse_analysis_artifact_store qihse_analysis_artifact_store_t;

/* Open/create an authenticated durable artifact store.
 * blob_store: backend blob store for payload bytes (created under base_dir/blobs if NULL).
 * journal: optional federation journal for publishing KEYSTONE feed projections.
 * origin_node: optional origin node UUID for published feed events. */
qihse_analysis_artifact_store_t* qihse_analysis_artifact_store_open(
    const char* base_dir,
    qihse_blob_store_t* blob_store,
    qihse_federation_journal_t* journal,
    const qihse_uuid_t* origin_node);

void qihse_analysis_artifact_store_close(qihse_analysis_artifact_store_t* store);

/* Authenticated durable ingest:
 * Atomically binds payload and manifest, verifies input lineage,
 * writes payload to QIHSE blob with QIHSE_BLOB_TAG_ANALYSIS_ARTIFACT,
 * pins blob from deletion, records manifest, and publishes KEYSTONE feed projection. */
qihse_analysis_store_result_t qihse_analysis_artifact_ingest_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_artifact_v1_t* manifest,
    qihse_blob_read_fn payload_reader,
    void* reader_opaque,
    qihse_user_t* publisher,
    uint8_t out_artifact_id[QIHSE_BLOB_HASH_BYTES]);

/* Convenience in-memory buffer ingest */
qihse_analysis_store_result_t qihse_analysis_artifact_ingest_buffer_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_artifact_v1_t* manifest,
    const uint8_t* payload_data,
    size_t payload_len,
    qihse_user_t* publisher,
    uint8_t out_artifact_id[QIHSE_BLOB_HASH_BYTES]);

/* Authenticated direct-ID manifest read.
 * Checks tenant, clearance, and SCI. Fails closed on denial. */
qihse_analysis_store_result_t qihse_analysis_artifact_get_manifest_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user,
    qihse_analysis_artifact_v1_t* out_manifest);

/* Authenticated payload range read.
 * Checks tenant, clearance, and SCI. Buffer untouched on denial. */
qihse_analysis_store_result_t qihse_analysis_artifact_get_payload_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    uint64_t offset,
    uint8_t* buffer,
    size_t buffer_len,
    size_t* out_read,
    qihse_user_t* user);

/* Authenticated tombstone / replacement.
 * Marks manifest as tombstoned, releases blob pin, emits feed tombstone. */
qihse_analysis_store_result_t qihse_analysis_artifact_tombstone_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const char* reason,
    qihse_user_t* publisher);

/* Authenticated lineage validation.
 * Verifies that all ancestor manifests in the DAG exist, are active (not tombstoned),
 * and have valid cryptographic bindings. Returns OK or LINEAGE_ERROR. */
qihse_analysis_store_result_t qihse_analysis_artifact_verify_lineage_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user);

/* Authenticated enumeration callback */
typedef bool (*qihse_analysis_artifact_list_fn)(
    const qihse_analysis_artifact_v1_t* manifest,
    bool is_tombstone,
    void* opaque);

qihse_analysis_store_result_t qihse_analysis_artifact_list_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_user_t* user,
    qihse_analysis_artifact_list_fn callback,
    void* callback_opaque);

/* Authenticated search / candidate lookup */
qihse_analysis_store_result_t qihse_analysis_artifact_search_user(
    qihse_analysis_artifact_store_t* store,
    const qihse_analysis_search_filter_t* filter,
    const qihse_user_t* user,
    uint8_t out_artifact_ids[][QIHSE_BLOB_HASH_BYTES],
    size_t max_results,
    size_t* out_count);

/* Authenticated snapshot / export of manifest + metadata frame */
#define QIHSE_ANALYSIS_EXPORT_FRAME_BYTES 937u
qihse_analysis_store_result_t qihse_analysis_artifact_export_user(
    qihse_analysis_artifact_store_t* store,
    const uint8_t artifact_id[QIHSE_BLOB_HASH_BYTES],
    const qihse_user_t* user,
    uint8_t* out_buf,
    size_t buf_cap,
    size_t* out_len);

/* Freshness check against the feed journal */
bool qihse_analysis_artifact_feed_freshness(
    qihse_analysis_artifact_store_t* store,
    uint64_t consumer_cursor,
    uint64_t* out_latest_offset,
    uint64_t* out_lag_bytes);

/* Access underlying blob store */
qihse_blob_store_t* qihse_analysis_artifact_store_get_blob_store(
    const qihse_analysis_artifact_store_t* store);

#endif
