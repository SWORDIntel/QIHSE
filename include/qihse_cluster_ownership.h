#ifndef QIHSE_CLUSTER_OWNERSHIP_H
#define QIHSE_CLUSTER_OWNERSHIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_bus.h"
#include "qihse_cluster_ownership_journal.h"
#include "qihse_kv_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_cluster_ct_peer_receipt qihse_cluster_ct_peer_receipt_t;
typedef struct qihse_cluster_ct_activation_receipt qihse_cluster_ct_activation_receipt_t;
typedef struct qihse_resp_ct_activation_request qihse_resp_ct_activation_request_t;
typedef struct qihse_resp_ct_begin_request qihse_resp_ct_begin_request_t;
typedef struct qihse_resp_ct_abort_request qihse_resp_ct_abort_request_t;
typedef struct qihse_resp_server qihse_resp_server_t;

/* A trusted provisioned mapping between topology IDs and QKP pinned IDs.
 * The callback must consult the authenticated pin registry, never a bus hint
 * or a caller-provided address. */
typedef bool (*qihse_cluster_ownership_peer_id_fn)(
    void* context, const char* topology_node_id,
    char out_qkp_node_id[QIHSE_KV_CT_ID_MAX + 1u]);
typedef bool (*qihse_cluster_ownership_election_fn)(
    void* context, const char* topology_source_id, const char* topology_target_id,
    const char* generation, uint64_t durable_cursor);
typedef bool (*qihse_cluster_ownership_range_reserve_fn)(
    void* context, qihse_user_t* principal,
    qihse_cluster_ownership_txn_t* draft, char* err, size_t err_cap);
typedef bool (*qihse_cluster_ownership_range_check_fn)(
    void* context, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn, char* err, size_t err_cap);
typedef bool (*qihse_cluster_ownership_range_finalize_fn)(
    void* context, qihse_user_t* principal,
    const qihse_cluster_ownership_txn_t* txn,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* err, size_t err_cap);

typedef struct {
    qihse_cluster_topology_t* topology;
    qihse_cluster_bus_t* bus;
    qihse_kv_store_t* store;
    qihse_user_t* principal;      /* local Operator control identity */
    qihse_user_t* data_principal; /* explicit full-scope replication data identity */
    qihse_resp_server_t* resp_server; /* configured peer-pin source for recovery */
    qihse_cluster_ownership_peer_id_fn peer_id;
    void* peer_id_context;
    qihse_cluster_ownership_election_fn promotion_authorized;
    void* promotion_context;
    /* Optional quorum-backed range authority. Configure all four hooks for a
     * group-authoritative context; leave all NULL for legacy/manual mode. */
    qihse_cluster_ownership_range_reserve_fn range_reserve;
    qihse_cluster_ownership_range_check_fn range_check_reserved;
    qihse_cluster_ownership_range_finalize_fn range_finalize;
    qihse_cluster_ownership_range_check_fn range_check_finalized;
    qihse_cluster_ownership_range_check_fn range_abort;
    void* range_authority_context;
} qihse_cluster_ownership_context_t;

/* Persist the source range fence and a PREPARED journal phase before the
 * caller snapshots/sends data. Returns the exact durable source cut through
 * out_source_lsn. The legacy form preserves its ABI; use _ex when the caller
 * must distinguish definite pre-fence rejection from an uncertain durable
 * intent/fence outcome. */
bool qihse_cluster_ownership_transfer_prepare(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    uint16_t source_index, uint16_t target_index, uint16_t first_slot,
    uint16_t last_slot, uint64_t* out_source_lsn, char* err, size_t err_cap);
/* Extended outcome for the transfer manager. out_recovery_may_be_needed is
 * true when durable intent/fence state may have been written despite failure. */
bool qihse_cluster_ownership_transfer_prepare_ex(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    uint16_t source_index, uint16_t target_index, uint16_t first_slot,
    uint16_t last_slot, uint64_t* out_source_lsn,
    bool* out_recovery_may_be_needed, char* err, size_t err_cap);

/* Read the matching durable PREPARED source descriptor for the transfer
 * manager. The descriptor binds both topology IDs and configured QKP IDs. */
bool qihse_cluster_ownership_transfer_get_prepared(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out_txn, char* err, size_t err_cap);
bool qihse_cluster_ownership_transfer_get_committed(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out_txn, char* err, size_t err_cap);
/* Read the latest durable terminal CT2 result for an exact transfer ID. This
 * supports idempotent client retries after later transfers or writes without
 * depending on current slot ownership or mutable peer seals. */
bool qihse_cluster_ownership_transfer_get_finalized(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out_txn, char* err, size_t err_cap);
/* Read an exact durable CT2 ABORTED result for quorum-backed cancellation.
 * The callback must use this getter after local ABORTED persistence and before
 * the source fence is released. */
bool qihse_cluster_ownership_transfer_get_aborted(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    qihse_cluster_ownership_txn_t* out_txn, char* err, size_t err_cap);
/* Finish local routing after a durable CT2 FINALIZED record. This is safe to
 * retry without contacting the target: the journal already records the exact
 * activated receipt. Only unsuperseded slots are applied; proof announcement
 * is best-effort and cannot undo the durable completion. */
bool qihse_cluster_ownership_transfer_finish_finalized(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    char* err, size_t err_cap);

/* Produce source-phase evidence only from the local durable journal and
 * storage state. PREPARED returns the actual frozen-range digest; ABORTED
 * returns a zero digest after the source fence release is verified. */
bool qihse_cluster_ownership_source_phase_receipt(
    qihse_cluster_ownership_context_t* context, const char* phase,
    const qihse_cluster_ownership_txn_t* expected_txn,
    unsigned char out_checksum[32], char* err, size_t err_cap);

/* Target-side begin: persist PREPARED and freeze the receiver's local range
 * before importing the source snapshot. `txn` must be the exact source
 * descriptor retrieved above over the authenticated transfer session. */
bool qihse_cluster_ownership_target_prepare(
    qihse_cluster_ownership_context_t* context,
    const qihse_cluster_ownership_txn_t* txn, uint64_t* out_target_cut,
    char* err, size_t err_cap);
/* RESP callbacks for authenticated CT2 BEGIN/ABORT. They require a matching
 * durable source phase receipt from the configured QKP pin before changing
 * the target fence. */
bool qihse_cluster_ownership_prepare_target_handler(
    void* ownership_context, const qihse_resp_ct_begin_request_t* request,
    uint64_t* out_target_cut, char* err, size_t err_cap);
bool qihse_cluster_ownership_abort_target_handler(
    void* ownership_context, const qihse_resp_ct_abort_request_t* request,
    char* err, size_t err_cap);

/* Validate the QKP-authenticated target receipt against the source's current
 * persisted fence and canonical data seal, permanently fence the old source,
 * append COMMITTED, then switch and broadcast the owner map. Receipt is a
 * private transport object; raw wire fields or caller booleans are rejected. */
bool qihse_cluster_ownership_transfer_commit(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    uint16_t source_index, uint16_t target_index,
    const qihse_cluster_ct_peer_receipt_t* receipt,
    char* err, size_t err_cap);

/* Called only after a typed activation receipt proves target COMMITTED,
 * durable and write-ready. This is the first operation that changes the
 * source topology or broadcasts the new owner map. */
bool qihse_cluster_ownership_transfer_publish(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    const qihse_cluster_ct_activation_receipt_t* activation,
    char* err, size_t err_cap);

/* Abort a CT2 transfer that is still PREPARED. It must belong to the local
 * source and carry no CT1 next-generation transition. The journaled abort is
 * durable before the active source range fence is released. */
bool qihse_cluster_ownership_transfer_abort(
    qihse_cluster_ownership_context_t* context, const char* transfer_id,
    uint16_t source_index, uint16_t target_index,
    char* err, size_t err_cap);

/* Apply a received proof-bearing bus update after the transport has resolved
 * its exact durable target receipt. This persists the local journal before
 * changing topology. */
bool qihse_cluster_ownership_receive_ct_update(
    qihse_cluster_ownership_context_t* context,
    const qihse_cluster_bus_ct_slot_update_t* update,
    const qihse_cluster_ct_activation_receipt_t* receipt,
    char* err, size_t err_cap);
/* Apply a signed target-origin CT1 promotion event after validating its exact
 * journal digest, pinned QKP relationships and per-slot epoch. */
bool qihse_cluster_ownership_receive_ct1_promotion(
    qihse_cluster_ownership_context_t* context,
    const qihse_cluster_bus_ct1_promotion_update_t* update,
    char* err, size_t err_cap);
void qihse_cluster_ownership_ct1_promotion_bus_callback(
    qihse_cluster_bus_t* bus,
    const qihse_cluster_bus_ct1_promotion_update_t* update,
    void* ownership_context);

/* Handler for ACTIVATE requests created only by the RESP QKP replication
 * endpoint after authenticating the configured source pin. It validates the
 * target seal, journals COMMITTED, releases the target staging fence, then
 * adopts ownership; the transport may ACK only after this returns true. */
bool qihse_cluster_ownership_activate_target(
    qihse_cluster_ownership_context_t* context,
    const qihse_resp_ct_activation_request_t* request,
    char* err, size_t err_cap);
bool qihse_cluster_ownership_ct_activation_handler(
    void* ownership_context,
    const qihse_resp_ct_activation_request_t* request,
    char* err, size_t err_cap);

/* Direct callback adapter for qihse_cluster_bus_set_ct_slot_update_callback.
 * Runs on the bus proof worker, queries the configured pinned QKP peer, then
 * calls receive_ct_update; it never treats the bus payload as proof. */
void qihse_cluster_ownership_bus_update_callback(
    qihse_cluster_bus_t* bus,
    const qihse_cluster_bus_ct_slot_update_t* update,
    void* ownership_context);

/* Startup recovery. Committed phases re-query the exact pinned target receipt,
 * revalidate the checksum, finish the persistent source fence, and only then
 * adopt the owner map. An unfinished PREPARED phase returns false and sets
 * out_unresolved so the embedding can keep listeners/writers paused. */
bool qihse_cluster_ownership_replay(
    qihse_cluster_ownership_context_t* context, bool* out_unresolved,
    char* err, size_t err_cap);

/* Control-plane startup variant: returns true when the journal is valid even
 * if the final CT2 transaction still needs its peer. In that case
 * out_unresolved remains true and callers MUST keep ordinary data listeners
 * closed while allowing only pinned CT recovery commands. Reinvoke after a
 * peer ACTIVATE/receipt exchange; it returns unresolved=false only after the
 * durable FINALIZED phase has been locally replayed. */
bool qihse_cluster_ownership_replay_control(
    qihse_cluster_ownership_context_t* context, bool* out_unresolved,
    char* err, size_t err_cap);

#ifdef __cplusplus
}
#endif
#endif
