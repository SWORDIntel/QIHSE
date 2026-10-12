#ifndef QIHSE_CONSENSUS_SNAPSHOT_STAGE_H
#define QIHSE_CONSENSUS_SNAPSHOT_STAGE_H

/* Durable receiver-side staging for the QCS1 consensus snapshot chunks.
 * Staging does not change committed consensus state. Completed payloads are
 * available only through bounded authorized reads and can be installed only
 * through the explicit crash-safe S2 publication API below. */

#include "qihse_consensus_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CONSENSUS_SNAPSHOT_STAGE_MAX_ENTRIES \
    QIHSE_CONSENSUS_SNAPSHOT_STREAM_MAX_ENTRIES

typedef struct qihse_consensus_snapshot_stage qihse_consensus_snapshot_stage_t;

typedef enum {
    QIHSE_SNAPSHOT_STAGE_OK = 0,
    QIHSE_SNAPSHOT_STAGE_DUPLICATE,
    QIHSE_SNAPSHOT_STAGE_GAP,
    QIHSE_SNAPSHOT_STAGE_CONFLICT,
    QIHSE_SNAPSHOT_STAGE_INTEGRITY,
    QIHSE_SNAPSHOT_STAGE_AUTH,
    QIHSE_SNAPSHOT_STAGE_INVALID,
    QIHSE_SNAPSHOT_STAGE_LIMIT,
    QIHSE_SNAPSHOT_STAGE_IO
} qihse_consensus_snapshot_stage_result_t;

typedef struct {
    bool has_transfer;
    bool complete;
    uint64_t transfer_id;
    uint64_t total_entries;
    uint64_t next_entry_index; /* 1-based first missing index */
} qihse_consensus_snapshot_stage_progress_t;

/* `path` must be relative, contain no `..` component, and name a regular
 * owner-only file. It is created mode 0600 when absent. A newly created file's
 * parent directory and each durable record are synced before success is
 * reported, including across power loss on filesystems that honor fsync.
 * One process may own a stage file at a time. `expected_group` binds the file
 * to one QIHSE group.
 * If require_data_validator is true, open fails without validate_data. */
bool qihse_consensus_snapshot_stage_open(
    const char* path, const char* expected_group,
    const qihse_user_t* principal,
    qihse_consensus_validate_data_fn validate_data,
    void* validate_data_context, bool require_data_validator,
    qihse_consensus_snapshot_stage_t** out);

void qihse_consensus_snapshot_stage_close(
    qihse_consensus_snapshot_stage_t* stage);

/* Accept one already-authenticated consensus chunk. The authenticated QKP
 * peer must be bound to msg->from by the caller before this call. Each chunk
 * is durably appended before OK is returned. Exact retransmissions return
 * DUPLICATE; conflicting retransmissions and index gaps are rejected. */
qihse_consensus_snapshot_stage_result_t
qihse_consensus_snapshot_stage_accept(
    qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal,
    const qihse_consensus_msg_t* message);

/* Rebind an incomplete or complete staged transfer to a strictly newer
 * authenticated leader term/epoch without changing its snapshot descriptor.
 * The mesh must first adopt `message` as the current leader through consensus.
 * The record is synced before the in-memory binding changes. Different
 * descriptors and stale/equal terms are refused; staged chunk hashes and
 * entries are preserved. */
qihse_consensus_snapshot_stage_result_t
qihse_consensus_snapshot_stage_rebind(
    qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal,
    const qihse_consensus_msg_t* message);

/* Replace an incomplete, unpublished stage with a newer committed snapshot.
 * The caller must first establish `message->from` as the current authenticated
 * leader through consensus. The new snapshot must start at entry 1, extend the
 * prior boundary, and carry strictly newer leader term and fencing epoch.
 * Complete stages, same-descriptor conflicts, and stale/equal epochs are
 * refused. Replacement uses a synced same-directory temporary file and atomic
 * rename, so restart recovers either the old stage or the new empty stage. */
qihse_consensus_snapshot_stage_result_t
qihse_consensus_snapshot_stage_replace(
    qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal,
    const qihse_uuid_t* authenticated_current_leader,
    const qihse_consensus_msg_t* message);

/* Progress is metadata-only and requires an active principal. It never
 * returns staged entries or payload bytes. */
bool qihse_consensus_snapshot_stage_get_progress(
    const qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal,
    qihse_consensus_snapshot_stage_progress_t* out);

/* Return transfer metadata only after full contiguous coverage and full-prefix
 * digest validation. The caller must be active. */
bool qihse_consensus_snapshot_stage_get_descriptor(
    const qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal,
    qihse_consensus_snapshot_descriptor_t* out);

/* Bounded authenticated iterator over a completed prefix. `first_index` is
 * one-based; capacity is 1..SNAPSHOT_CHUNK_MAX_ENTRIES. Every returned entry
 * is re-authorized against the caller's clearance and SCI compartments. */
bool qihse_consensus_snapshot_stage_read(
    const qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal, uint64_t first_index,
    qihse_consensus_entry_t* out_entries, size_t capacity,
    size_t* out_count);

/* Publish a complete staged prefix into consensus recovery. Requires an
 * active operator; chunk reads remain bounded internally. */
bool qihse_consensus_snapshot_stage_publish(
    const qihse_consensus_snapshot_stage_t* stage,
    const qihse_user_t* principal, qihse_consensus_t* consensus);

const char* qihse_consensus_snapshot_stage_result_name(
    qihse_consensus_snapshot_stage_result_t result);

#ifdef __cplusplus
}
#endif

#endif
