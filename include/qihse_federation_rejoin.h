#ifndef QIHSE_FEDERATION_REJOIN_H
#define QIHSE_FEDERATION_REJOIN_H

/*
 * QIHSE federation rejoin driver.
 * See v3.md §43 (reconciliation safety) and §10 (anti-entropy).
 *
 * F8.4 produced the ordered sequence and the rule that ownership may only be
 * published after checksums verify.  F3 produces manifests and sync plans.
 * The replication module moves records.  This is the piece that runs the
 * sequence and enforces the gates, so a rejoining node cannot skip a step by
 * calling the transfer directly.
 *
 * The driver owns ORDERING and GATING.  It does not own the wire format: the
 * caller supplies a callback that fetches the peer's manifest however the
 * deployment chooses to carry it.  That keeps the safety rules testable
 * without inventing a serialisation format for manifests here.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_federation.h"
#include "qihse_federation_repl.h"
#include "qihse_federation_transport.h"
#include "qihse_operations.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fetch the peer's manifest for a namespace.  Returns false on any failure;
 * a failed fetch aborts the sequence rather than being skipped, because
 * proceeding without the peer's manifest would mean transferring against a
 * divergence nobody actually established. */
typedef bool (*qihse_rejoin_fetch_manifest_fn)(void* ctx,
                                              const char* namespace_name,
                                              qihse_federation_manifest_t* out);

typedef struct {
    qihse_rejoin_step_t step;
    qihse_uuid_t node_id;
    qihse_uuid_t peer_node;
    char namespace_name[QIHSE_FEDERATION_NS_NAME_MAX + 1u];
    /* Manifests and the divergence the comparison found. */
    qihse_federation_manifest_t local_manifest;
    qihse_federation_manifest_t remote_manifest;
    qihse_federation_manifest_entry_t divergent[QIHSE_FEDERATION_MANIFEST_MAX_RANGES];
    size_t divergent_count;
    size_t divergent_index;
    qihse_repl_sync_t sync;
    uint64_t events_transferred;
    uint64_t conflicts_applied;
    char last_error[128];
} qihse_rejoin_driver_t;

/* Begin a rejoin.
 *
 * `session` must be a verified mTLS session: the driver refuses to start on a
 * transport that cannot name its peer, so a rejoining node cannot be talked
 * into catching up from an unauthenticated source.
 *
 * `expected_peer` is the peer the operator intends to rejoin from.  A verified
 * session whose identity is a DIFFERENT node is refused.  "Verified" and "the
 * peer I meant" are separate questions, and this is where the second one is
 * asked. */
bool qihse_rejoin_driver_begin(qihse_rejoin_driver_t* driver,
                               void* store_void, void* user_void,
                               const qihse_uuid_t* node_id,
                               const qihse_uuid_t* expected_peer,
                               const char* namespace_name,
                               qihse_fed_tls_session_t* session);

/* Advance one step.  Returns false when the sequence has aborted.
 *
 * `journal` is the local journal the transfer reads from or writes to. */
bool qihse_rejoin_driver_step(qihse_rejoin_driver_t* driver,
                              void* store_void, void* user_void,
                              qihse_fed_tls_session_t* session,
                              qihse_repl_transport_t* transport,
                              void* journal_void,
                              qihse_rejoin_fetch_manifest_fn fetch_manifest,
                              void* fetch_ctx);

/* Run to completion or abort.  Returns true only on COMPLETE. */
bool qihse_rejoin_driver_run(qihse_rejoin_driver_t* driver,
                             void* store_void, void* user_void,
                             qihse_fed_tls_session_t* session,
                             qihse_repl_transport_t* transport,
                             void* journal_void,
                             qihse_rejoin_fetch_manifest_fn fetch_manifest,
                             void* fetch_ctx);

/* May this driver publish exclusive ownership yet?
 *
 * True only at VERIFY_CHECKSUMS or COMPLETE, and only if no step failed.  A
 * node that has not reconstructed and verified its state must not claim
 * ownership of anything, which is the whole point of the sequence. */
bool qihse_rejoin_driver_may_publish_ownership(const qihse_rejoin_driver_t* driver);

/* Persist the driver's progress so a crash resumes rather than restarting.
 * A resumed sequence must not skip the gates it had not yet passed. */
bool qihse_rejoin_driver_persist(const qihse_rejoin_driver_t* driver,
                                 void* store_void, void* user_void);

/* Snapshot for observability. */
void qihse_rejoin_driver_state(const qihse_rejoin_driver_t* driver,
                               qihse_rejoin_state_t* out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_REJOIN_H */
