#ifndef QIHSE_PRINCIPAL_STORE_H
#define QIHSE_PRINCIPAL_STORE_H

#include "qihse_principal_record.h"
#include "qihse_consensus.h"
#include <stdint.h>
#include <stddef.h>

/* Internal materialized view of a complete committed principal-log prefix.
 * No network/client adapter may call apply_committed: the caller must first
 * prove the record came from the next durable consensus commit. The view is
 * rebuilt from index 1 after restart; it is not itself a durable log. */
typedef struct qihse_principal_store_s qihse_principal_store_t;

typedef enum {
    QIHSE_PRINCIPAL_APPLY_ERROR = 0,    /* gap, allocation failure, bad input */
    QIHSE_PRINCIPAL_APPLY_REJECTED = 1, /* committed no-op; index advances */
    QIHSE_PRINCIPAL_APPLY_APPLIED = 2   /* committed mutation; index advances */
} qihse_principal_apply_result_t;

/* The bootstrap operator must come from trusted durable authentication
 * bootstrap state. Its identity is never accepted from a log record. */
qihse_principal_store_t* qihse_principal_store_new(
    const qihse_user_t* bootstrap_operator);
/* History must be provisioned from the same authenticated consensus
 * configuration used by replay. A legacy unbound store cannot export. */
qihse_principal_store_t* qihse_principal_store_new_bound(
    const qihse_user_t* bootstrap_operator, const char* group_id,
    const uint8_t history_id[32], uint64_t writer_epoch_floor);
void qihse_principal_store_free(qihse_principal_store_t* store);
uint64_t qihse_principal_store_applied_index(
    const qihse_principal_store_t* store);
uint64_t qihse_principal_store_generation(
    const qihse_principal_store_t* store);

/* Apply exactly the next committed log index. Rejected records still consume
 * their index, so every peer derives the same state from the same prefix.
 * ERROR leaves the store unchanged and must halt replay. A successful caller
 * must subsequently publish the new auth state under its auth write lock;
 * until that integration exists, this view is not an authentication source. */
qihse_principal_apply_result_t qihse_principal_store_apply_committed(
    qihse_principal_store_t* store, uint64_t index,
    const uint8_t* payload, size_t payload_len);

/* Private, read-only materialization for a future atomic auth publisher.
 * Every ever-used non-bootstrap ID is included, including tombstones, so
 * deletion history cannot be mistaken for an unused slot. The caller must
 * serialize export against apply/free. The result owns secret verifier
 * material and must be destroyed with snapshot_free. Neither this API nor
 * its history label proves a consensus prefix: only verified ordered replay
 * into a bound store can supply that provenance. */
typedef struct {
    uint32_t user_id;
    uint64_t principal_generation;
    bool present;
    qihse_user_t principal; /* zero when present is false */
} qihse_principal_snapshot_entry_t;

typedef struct qihse_principal_snapshot_s qihse_principal_snapshot_t;

typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    uint8_t history_id[32];
    uint64_t writer_epoch_floor;
    uint64_t applied_index;
    uint64_t registry_generation;
    size_t entry_count;
} qihse_principal_snapshot_metadata_t;

bool qihse_principal_store_export_user(
    const qihse_principal_store_t* store, const qihse_user_t* requester,
    const char* expected_group_id, const uint8_t expected_history_id[32],
    qihse_principal_snapshot_t** out_snapshot);
/* The snapshot is opaque; metadata and secret-bearing entries require the
 * same live system Operator context on each materializing read. */
bool qihse_principal_snapshot_metadata_user(
    const qihse_principal_snapshot_t* snapshot,
    const qihse_user_t* requester,
    qihse_principal_snapshot_metadata_t* out_metadata);
bool qihse_principal_snapshot_entry_user(
    const qihse_principal_snapshot_t* snapshot,
    const qihse_user_t* requester, size_t position,
    qihse_principal_snapshot_entry_t* out_entry);
typedef bool (*qihse_principal_snapshot_visit_fn)(
    void* opaque, const qihse_principal_snapshot_entry_t* entry);
/* One authorized, read-only pass over every retained ID in ascending order.
 * False from the visitor aborts the pass. Rechecks requester liveness before
 * returning success; callers must discard partial staging on failure. */
bool qihse_principal_snapshot_visit_user(
    const qihse_principal_snapshot_t* snapshot,
    const qihse_user_t* requester,
    qihse_principal_snapshot_visit_fn visit, void* opaque);
void qihse_principal_snapshot_free(qihse_principal_snapshot_t* snapshot);

#endif
