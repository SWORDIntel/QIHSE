#ifndef QIHSE_EXPORT_H
#define QIHSE_EXPORT_H

/* U7 — tenant-subset export (SESSION_DELIVERY_UPGRADES.md).
 *
 * Produces a portable artifact containing one tenant's data: every KV record
 * under the tenant's "t:<id>/" namespace plus the shared "commons/"
 * namespace, and the blob manifest entries visible to the caller. Records
 * the caller may not read (above clearance) are excluded by the
 * authorization-aware iteration, so the artifact never discloses protected
 * payload. Deletion/migration of a tenant follows from the same artifact.
 *
 * SECURITY (invariant #1): takes a mandatory qihse_user_t*; a tenant-scoped
 * principal may only export its OWN tenant; NULL is denied.
 *
 * Also home of the incremental (delta) export, qihse_export_incremental_user
 * below.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "qihse_auth.h"
#include "qihse_blob.h"
#include "qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

bool qihse_export_tenant_user(qihse_kv_store_t* kv, qihse_blob_store_t* blobs,
                              uint32_t tenant_id, qihse_user_t* user,
                              const char* out_path,
                              char* err, size_t err_cap);

/* U: incremental (delta) export — the mutations since a cursor.
 *
 * Exports every KV record whose stamped change sequence is STRICTLY greater
 * than `since_seq` (live records AND tombstones, each key's latest state,
 * ascending sequence order), returning the exported records plus the
 * continuation point for the next call (*out_resume_seq).  This is the
 * programmatic form; the file form the backup layer consumes is
 * qihse_kv_save_delta_user().
 *
 * SECURITY (invariant #1): takes a MANDATORY qihse_user_t* — NULL is an
 * argument error, refused, never the KV layer's unclassified-only view —
 * and the principal must be live.  Clearance/SCI filtering happens at the
 * lowest data-retrieval layer (inside the KV store's delta iteration, the
 * same qihse_auth_can_access check the full export applies per record), so
 * this surface never re-implements the classifier and never sees a record
 * it may not read.
 *
 * METADATA-DISCLOSURE DECISION (explicit, and the DEFAULT and ONLY form —
 * no opt-in alternative exists): a low-clearance principal's delta sees
 * sequence numbers of the records it is ALLOWED to see, and its resume
 * point is the highest sequence among those records — never the
 * store-global high-water.  Hidden mutations are filtered out before the
 * resume point is computed, so they are never enumerated and comparing
 * successive resume points cannot reveal HOW MANY hidden mutations
 * occurred: the resume point simply does not move until the principal is
 * allowed to see something newer.  (A form returning the global high-water
 * would let a caller count hidden mutations from the gap and is therefore
 * not provided.)  The cost is a re-scan of records between the resume
 * point and the high-water on each export — a sequence compare during
 * iteration.
 *
 * Boundaries carried from the KV layer, restated: sequence-0 records
 * (pre-sequence files) are never in a delta — bootstrap with a full export
 * then track deltas; if no permitted records exist the resume point equals
 * `since_seq` unchanged; a caller holding a cursor from before a restore
 * should re-baseline; a tombstone dropped by compaction before any export
 * saw it is not re-deliverable.
 *
 * On success owns *out_records (release with qihse_kv_delta_records_free).
 * On every failure *out_records is NULL, *out_count 0, *out_resume_seq 0,
 * and nothing is partially returned. */
bool qihse_export_incremental_user(qihse_kv_store_t* kv, qihse_user_t* user,
                                   uint64_t since_seq,
                                   qihse_kv_delta_record_t** out_records,
                                   size_t* out_count, uint64_t* out_resume_seq,
                                   char* err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_EXPORT_H */
