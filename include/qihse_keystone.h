#ifndef QIHSE_KEYSTONE_H
#define QIHSE_KEYSTONE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_kv_store.h"
#include "qihse_cluster_slot.h"
#include "qihse_federation.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_KEYSTONE_CLASS_UNKNOWN = 0,
    QIHSE_KEYSTONE_CLASS_FINANCIAL = 1,
    QIHSE_KEYSTONE_CLASS_CORPORATE = 2,
    QIHSE_KEYSTONE_CLASS_GOVERNMENT = 3,
    QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE = 4,
    QIHSE_KEYSTONE_CLASS_CONSUMER = 5
} qihse_keystone_class_t;

typedef struct {
    char key[256];
    char value[512];
    uint32_t slot;
    qihse_keystone_class_t semantic_class;
    float confidence;
} qihse_keystone_artifact_t;

/*
 * Principal-aware dirty-log ingestion. Classified/SCI ingestion MUST use this
 * function. Target classification is checked before parsing and every KV write
 * is performed through qihse_kv_set_user(). Only successfully persisted
 * artifacts are included in the returned count.
 */
size_t qihse_keystone_ingest_dirty_logs_user(
    qihse_kv_store_t* kv,
    qihse_cluster_topology_t* topo,
    const char* buffer,
    size_t len,
    uint16_t clearance,
    uint16_t compartment,
    qihse_user_t* user);

/*
 * Legacy ABI retained for unclassified ingestion. It delegates to the
 * principal-aware path with a NULL principal, therefore classification/SCI > 0
 * is denied rather than becoming an implicit authorization bypass.
 */
size_t qihse_keystone_ingest_dirty_logs(
    qihse_kv_store_t* kv,
    qihse_cluster_topology_t* topo,
    const char* buffer,
    size_t len,
    uint16_t clearance,
    uint16_t compartment);

int qihse_keystone_classify_context(
    const char* context,
    size_t len,
    qihse_keystone_class_t* out_class,
    float* out_confidence);

const char* qihse_keystone_class_name(qihse_keystone_class_t cls);

int64_t qihse_keystone_anchor_search(const int64_t* arr, size_t n, int64_t key);
size_t qihse_keystone_anchor_lower_bound(const int64_t* arr, size_t n, int64_t key);
size_t qihse_keystone_anchor_upper_bound(const int64_t* arr, size_t n, int64_t key);

/* ═══════════════════════════════════════════════════════════════════════════
 * W2.5 — KEYSTONE consumes the resumable change feed as a READ/INDEX identity.
 *
 * KEYSTONE keeps its index current by following QIHSE's federation change
 * journal (F2). It does so as a NARROW identity, never as a database
 * administrator:
 *
 *   - a tenant-scoped ANALYST with an explicit clearance/SCI ceiling and no
 *     user-creation delegation; the system domain (tenant 0) is refused,
 *     because in this codebase the system domain is the administrative domain;
 *   - it holds QIHSE_SCOPE_FEDERATION_READ and nothing else, so publishing a
 *     feed record (QIHSE_SCOPE_FEDERATION_WRITE) is denied;
 *   - it may read only records at or below its clearance, inside its SCI
 *     compartments, and in its own tenant.
 *
 * Every entry point takes an explicit authenticated principal. NULL is an
 * argument error, never an authorization bypass (AGENTS.md invariant 1), and
 * no principal may provision an index identity above itself (invariant 2).
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Feed record contract (plan §26; KEYSTONE brief §4 envelope). A journal
 * payload that carries a feed record is a fixed 64-byte header followed by
 * the record body, so a consumer never has to guess what an event is or how
 * it is classified.
 *
 * The envelope on the wire (KEYSTONE.FEED.NEXT, 16 items) is the record
 * plus the journal event's own provenance — event_id, origin_node and
 * fencing_epoch come from the event envelope, not the indexed record:
 *
 *   [journal_offset, event_type, resource_id, classification, sci,
 *    tenant_id, generation, payload,
 *    event_id_hex, origin_node_hex, object_id_hex,
 *    fencing_epoch, hlc_physical_ms, hlc_logical, flags, object_type]
 *
 * Flags vocabulary matches the KEYSTONE brief §4: a deletion is a record
 * with TOMBSTONE set (payload may be empty) — it is delivered on the wire
 * like any other record, because a tombstone the consumer cannot see is a
 * deleted object that resurrects in its index. */
#define QIHSE_KEYSTONE_FEED_MAGIC 0x4B534644u /* "KSFD" */
#define QIHSE_KEYSTONE_FEED_RECORD_VERSION 1u
#define QIHSE_KEYSTONE_FEED_HEADER_BYTES 64u
#define QIHSE_KEYSTONE_FEED_MAX_PAYLOAD (256u * 1024u)
#define QIHSE_KEYSTONE_FEED_FLAG_TOMBSTONE 0x0001u
#define QIHSE_KEYSTONE_FEED_FLAG_SNAPSHOT 0x0002u
#define QIHSE_KEYSTONE_FEED_FLAG_EVENT 0x0004u
#define QIHSE_KEYSTONE_FEED_FLAG_TELEMETRY 0x0008u
#define QIHSE_KEYSTONE_FEED_FLAG_AUDIT 0x0010u
#define QIHSE_KEYSTONE_FEED_FLAG_SECURITY_SENSITIVE 0x0020u
#define QIHSE_KEYSTONE_FEED_FLAG_DERIVED 0x0040u

typedef struct {
    qihse_uuid_t object_id;   /* immutable indexed object identity */
    qihse_hlc_t hlc;          /* causal stamp of the mutation */
    uint64_t generation;      /* object generation, so KEYSTONE can go stale */
    uint32_t tenant_id;       /* security context: owning tenant */
    uint32_t object_type;     /* publisher-assigned type tag (0 = unspecified) */
    uint16_t classification;  /* security context: clearance required */
    uint16_t sci;             /* security context: SCI compartments required */
    uint16_t flags;           /* QIHSE_KEYSTONE_FEED_FLAG_* */
} qihse_keystone_feed_record_t;

/* Encode header + body. Returns false when the record or body is outside the
 * contract (oversized payload, out of range fields). */
bool qihse_keystone_feed_encode(const qihse_keystone_feed_record_t* record,
                                const void* payload, size_t payload_len,
                                uint8_t* out, size_t out_cap, size_t* out_len);

/* Decode a journal payload into a feed record. Validates the declared body
 * length against BOTH the encoded length and the fixed header size and fails
 * closed on anything malformed (AGENTS.md federation-decoder rule 3), so an
 * undecodable record can never reach the index. `out_body` points into
 * `payload` and is valid for as long as the caller's buffer is. */
bool qihse_keystone_feed_decode(const uint8_t* payload, size_t payload_len,
                                qihse_keystone_feed_record_t* out_record,
                                const uint8_t** out_body, size_t* out_body_len);

/* ── The read/index identity ────────────────────────────────────────────── */

/* Provision the KEYSTONE index identity: a tenant-scoped ANALYST at exactly
 * the requested clearance/SCI, with no user-creation delegation. Refused for
 * tenant 0 (the administrative domain) and for any creator that does not
 * already hold every privilege it is granting (invariant 2) — a delegated
 * creator is refused rather than silently floored to GUEST, so the caller
 * learns that no index identity was created. Operator-only in practice, for
 * the same reason. */
qihse_user_t* qihse_keystone_feed_identity_provision(const qihse_user_t* creator,
                                                     uint32_t tenant_id,
                                                     uint32_t user_id,
                                                     uint16_t clearance,
                                                     uint16_t sci,
                                                     const char* plaintext_password);

/* True only for a principal provisioned by the call above that is still an
 * active ANALYST in a non-system tenant. A promoted, revoked or destroyed
 * principal stops being an index identity. */
bool qihse_keystone_feed_identity_is_indexer(const qihse_user_t* user);

/* Operator-only: drop the feed binding so the principal loses change-feed
 * access immediately, without waiting for account destruction. */
bool qihse_keystone_feed_identity_revoke(const qihse_user_t* actor, uint32_t user_id);

/* ── Publishing (never available to the index identity) ──────────────────── */

/* Publish one feed record to the journal. Requires an active principal that
 * holds QIHSE_SCOPE_FEDERATION_WRITE; the index identity holds only
 * FEDERATION_READ, so this is denied for it. The publisher may not publish
 * above its own clearance/SCI, nor outside its own tenant. */
bool qihse_keystone_feed_publish(qihse_federation_journal_t* journal,
                                 const qihse_user_t* publisher,
                                 const qihse_uuid_t* origin_node,
                                 const char* event_type,
                                 const char* resource_id,
                                 const qihse_keystone_feed_record_t* record,
                                 const void* payload, size_t payload_len,
                                 qihse_federation_event_t* out_event);

/* ── Resumable consumption ──────────────────────────────────────────────── */

typedef struct qihse_keystone_feed qihse_keystone_feed_t;

typedef struct {
    char prefix[64];          /* resource_id prefix filter; "" = all */
    uint64_t cursor;          /* resume point; 0 = from the beginning */
    size_t max_payload_bytes; /* 0 = QIHSE_KEYSTONE_FEED_MAX_PAYLOAD */
} qihse_keystone_feed_config_t;

/* Open a feed for an authenticated reader. Allowed for the provisioned index
 * identity and for an operator (administration/debug); any other principal —
 * including a plain analyst — is refused. NULL reader or NULL journal fails
 * closed with NULL. */
qihse_keystone_feed_t* qihse_keystone_feed_open(qihse_federation_journal_t* journal,
                                                const qihse_user_t* reader,
                                                const qihse_keystone_feed_config_t* config);
void qihse_keystone_feed_close(qihse_keystone_feed_t* feed);

/* Deliver the next record the reader is cleared for. Records above the
 * reader's clearance, outside its SCI compartments, in another tenant, larger
 * than the configured cap, or malformed are SKIPPED and counted — never
 * delivered, not even as metadata. The clearance decision is made per record
 * at delivery time, so it does not depend on the cursor: rewinding or
 * transplanting a cursor cannot replay past a denial.
 *
 * Returns false at end-of-journal. On success `*out_payload` is a heap copy
 * the caller frees. */
bool qihse_keystone_feed_next(qihse_keystone_feed_t* feed,
                              qihse_federation_event_t* out_event,
                              qihse_keystone_feed_record_t* out_record,
                              uint8_t** out_payload, size_t* out_payload_len);

/* Acknowledge events up to `offset` (at-least-once: unacked events are
 * re-delivered on resume). */
bool qihse_keystone_feed_ack(qihse_keystone_feed_t* feed, uint64_t offset);
/* Resume from a previously saved cursor. Refuses a cursor beyond the current
 * end of the journal. */
bool qihse_keystone_feed_resume(qihse_keystone_feed_t* feed, uint64_t cursor);

uint64_t qihse_keystone_feed_cursor(const qihse_keystone_feed_t* feed);
uint64_t qihse_keystone_feed_last_ack(const qihse_keystone_feed_t* feed);
size_t qihse_keystone_feed_denied(const qihse_keystone_feed_t* feed);
size_t qihse_keystone_feed_malformed(const qihse_keystone_feed_t* feed);

/* Persist / restore the resume cursor. The cursor file records the principal
 * that minted it; loading it as a different principal is refused, so a cursor
 * minted for a wider identity cannot be transplanted onto the index identity
 * (and vice versa). Writes are atomic (tmp + rename) and 0600. */
bool qihse_keystone_feed_cursor_save(const qihse_keystone_feed_t* feed, const char* path);
bool qihse_keystone_feed_cursor_load(const qihse_user_t* reader, const char* path,
                                     uint64_t* out_cursor);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_KEYSTONE_H */
