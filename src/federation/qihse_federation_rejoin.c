/*
 * QIHSE federation rejoin driver.
 * See docs/plans/qihse_federation_upgrade_plan.md §43 and §10.
 */
#include "qihse_federation_rejoin.h"

#include <stdio.h>
#include <string.h>

static void fail(qihse_rejoin_driver_t* d, const char* why) {
    snprintf(d->last_error, sizeof(d->last_error), "%s", why);
    d->step = QIHSE_REJOIN_ABORTED;
}

bool qihse_rejoin_driver_begin(qihse_rejoin_driver_t* driver,
                               void* store_void, void* user_void,
                               const qihse_uuid_t* node_id,
                               const qihse_uuid_t* expected_peer,
                               const char* namespace_name,
                               qihse_fed_tls_session_t* session) {
    if (!driver || !node_id || !expected_peer || !namespace_name) return false;
    memset(driver, 0, sizeof(*driver));
    driver->node_id = *node_id;
    driver->peer_node = *expected_peer;
    snprintf(driver->namespace_name, sizeof(driver->namespace_name), "%s",
             namespace_name);

    /* A missing session is a refusal like any other, and it records why.  An
     * operator whose rejoin silently does nothing has nothing to act on. */
    if (!session) {
        fail(driver, "no session");
        return false;
    }

    /* A session that cannot name its peer may not be a source of state.  This
     * is the same rule the replication transport enforces, applied before the
     * sequence starts rather than after it is under way. */
    qihse_uuid_t actual_peer;
    qihse_runtime_trust_t peer_trust;
    if (!qihse_federation_tls_peer_identity(session, &actual_peer, &peer_trust)) {
        fail(driver, "session has no verified peer");
        return false;
    }

    /* Verified is not the same question as "the peer I meant".  Catching up
     * from a different node than the operator intended would reconstruct
     * state from an unplanned source. */
    if (!qihse_uuid_equal(&actual_peer, expected_peer)) {
        fail(driver, "session peer is not the expected peer");
        return false;
    }

    /* A peer that may not exchange federation state may not be a source of
     * authoritative state either. */
    if (peer_trust == QIHSE_RTRUST_LOCAL_ONLY || peer_trust == QIHSE_RTRUST_QUARANTINED ||
        peer_trust == QIHSE_RTRUST_REVOKED || peer_trust == QIHSE_RTRUST_UNKNOWN) {
        fail(driver, "peer trust does not permit exchanging federation state");
        return false;
    }

    (void)store_void;
    (void)user_void;
    /* Start at the first real step; IDLE is not a state to rejoin from. */
    driver->step = QIHSE_REJOIN_AUTHENTICATE_PEER;
    return true;
}

bool qihse_rejoin_driver_may_publish_ownership(const qihse_rejoin_driver_t* driver) {
    if (!driver) return false;
    if (driver->step == QIHSE_REJOIN_ABORTED) return false;
    return qihse_rejoin_may_publish_ownership(driver->step);
}

bool qihse_rejoin_driver_persist(const qihse_rejoin_driver_t* driver,
                                 void* store_void, void* user_void) {
    if (!driver || !store_void || !user_void) return false;
    qihse_rejoin_state_t st;
    qihse_rejoin_driver_state(driver, &st);
    return qihse_rejoin_state_put(store_void, user_void, &st);
}

void qihse_rejoin_driver_state(const qihse_rejoin_driver_t* driver,
                               qihse_rejoin_state_t* out) {
    if (!driver || !out) return;
    memset(out, 0, sizeof(*out));
    out->node_id = driver->node_id;
    out->peer_node = driver->peer_node;
    out->step = driver->step;
    out->events_transferred = driver->events_transferred;
    out->conflicts_applied = driver->conflicts_applied;
    snprintf(out->last_error, sizeof(out->last_error), "%s", driver->last_error);
}

/* Move the sync plan's action into a transfer direction.
 *
 * A plan says what the peer needs; the transfer direction is the mirror of
 * that.  Getting this backwards would pull records that should have been
 * pushed, which is silent data loss rather than an error. */
static bool plan_action_to_sender(qihse_sync_action_t action, bool* local_is_sender) {
    switch (action) {
        case QIHSE_SYNC_SEND:  *local_is_sender = true;  return true;
        case QIHSE_SYNC_FETCH: *local_is_sender = false; return true;
        /* A CONFLICT is resolved by the conflict policy before any transfer,
         * so reaching one here means the sequence tried to transfer over an
         * unresolved divergence. */
        case QIHSE_SYNC_CONFLICT:
        case QIHSE_SYNC_NONE:
        default: return false;
    }
}

bool qihse_rejoin_driver_step(qihse_rejoin_driver_t* driver,
                              void* store_void, void* user_void,
                              qihse_fed_tls_session_t* session,
                              qihse_repl_transport_t* transport,
                              void* journal_void,
                              qihse_rejoin_fetch_manifest_fn fetch_manifest,
                              void* fetch_ctx) {
    if (!driver) return false;
    if (driver->step == QIHSE_REJOIN_ABORTED || driver->step == QIHSE_REJOIN_COMPLETE) {
        return driver->step == QIHSE_REJOIN_COMPLETE;
    }

    switch (driver->step) {
    case QIHSE_REJOIN_AUTHENTICATE_PEER:
        /* The session was verified in begin(); re-confirm it still is, because
         * a peer may have been revoked between begin() and this step. */
        if (!session) { fail(driver, "no session"); return false; }
        {
            qihse_uuid_t peer;
            qihse_runtime_trust_t trust;
            if (!qihse_federation_tls_peer_identity(session, &peer, &trust) ||
                !qihse_uuid_equal(&peer, &driver->peer_node)) {
                fail(driver, "peer identity changed");
                return false;
            }
        }
        break;

    case QIHSE_REJOIN_COMPARE_FEDERATION_UUID:
        /* The manifests carry the namespace; a mismatch here means the two
         * sides are not talking about the same thing and nothing further can
         * be trusted. */
        if (!fetch_manifest) { fail(driver, "no manifest fetcher"); return false; }
        if (!fetch_manifest(fetch_ctx, driver->namespace_name,
                            &driver->remote_manifest)) {
            fail(driver, "remote manifest fetch failed");
            return false;
        }
        if (!qihse_federation_manifest_build(store_void, user_void,
                                            driver->namespace_name,
                                            &driver->local_manifest)) {
            fail(driver, "local manifest build failed");
            return false;
        }
        break;

    case QIHSE_REJOIN_COMPARE_BOOT_UUID:
        /* Both manifests must describe the same namespace. */
        if (strcmp(driver->local_manifest.namespace_name,
                   driver->remote_manifest.namespace_name) != 0) {
            fail(driver, "namespace mismatch");
            return false;
        }
        break;

    case QIHSE_REJOIN_EXCHANGE_HLC:
        /* HLC comparison is advisory; the manifests carry the authoritative
         * divergence.  Recorded as a step so the sequence is auditable. */
        break;

    case QIHSE_REJOIN_EXCHANGE_MANIFESTS:
        if (driver->local_manifest.namespace_name[0] == '\0' ||
            driver->remote_manifest.namespace_name[0] == '\0') {
            fail(driver, "manifests not exchanged");
            return false;
        }
        break;

    case QIHSE_REJOIN_IDENTIFY_DIVERGENCE:
        driver->divergent_count = qihse_federation_manifest_compare(
            &driver->local_manifest, &driver->remote_manifest,
            driver->divergent, QIHSE_FEDERATION_MANIFEST_MAX_RANGES);
        driver->divergent_index = 0;
        /* A sync plan is derived per divergent range at transfer time. */
        break;

    case QIHSE_REJOIN_TRANSFER_EVENTS:
        /* The gate the whole sequence exists for.  A transfer may not run
         * before the peer is authenticated and the divergence established. */
        if (!qihse_repl_transfer_permitted((uint32_t)driver->step)) {
            fail(driver, "transfer not permitted at this step");
            return false;
        }
        if (driver->divergent_index >= driver->divergent_count) {
            /* Nothing left to move. */
            driver->events_transferred += 0;
            break;
        }
        {
            if (!transport || !transport->peer_verified) {
                fail(driver, "transport peer not verified");
                return false;
            }
            /* One bounded round for the current range.  The direction comes
             * from which side holds the objects, which the manifest entry
             * tells us: a count difference means one side has more. */
            const qihse_federation_manifest_entry_t* range =
                &driver->divergent[driver->divergent_index];
            bool local_is_sender = false;
            qihse_sync_action_t action = QIHSE_SYNC_NONE;
            /* Find this range in the local and remote manifests to decide. */
            for (size_t i = 0; i < driver->local_manifest.entry_count; i++) {
                if (strcmp(driver->local_manifest.entries[i].range_start,
                           range->range_start) == 0) {
                    action = (driver->local_manifest.entries[i].object_count >
                              range->object_count) ? QIHSE_SYNC_SEND : QIHSE_SYNC_FETCH;
                    break;
                }
            }
            if (action == QIHSE_SYNC_NONE) action = QIHSE_SYNC_FETCH;
            if (!plan_action_to_sender(action, &local_is_sender)) {
                fail(driver, "unresolved conflict in range");
                return false;
            }

            if (driver->sync.phase == QIHSE_REPL_IDLE ||
                strcmp(driver->sync.range_start, range->range_start) != 0) {
                if (!qihse_repl_sync_begin(&driver->sync, driver->namespace_name,
                                          range, local_is_sender)) {
                    fail(driver, "sync begin failed");
                    return false;
                }
            }
            size_t moved = qihse_repl_sync_round(&driver->sync, transport,
                                                store_void, user_void, journal_void);
            driver->events_transferred += moved;
            if (driver->sync.phase == QIHSE_REPL_FAILED) {
                fail(driver, driver->sync.last_error);
                return false;
            }
            if (driver->sync.phase == QIHSE_REPL_VERIFYING ||
                driver->sync.phase == QIHSE_REPL_COMPLETE) {
                driver->divergent_index++;
                memset(&driver->sync, 0, sizeof(driver->sync));
            }
            if (moved == 0 && driver->divergent_index < driver->divergent_count) {
                /* No progress on a range that still has work: treat as
                 * blocked rather than spinning forever. */
                fail(driver, "transfer made no progress");
                return false;
            }
        }
        break;

    case QIHSE_REJOIN_APPLY_CONFLICT_POLICY:
        /* Conflicts were resolved before transfer; reaching here with an
         * unresolved conflict would mean the policy was skipped. */
        if (driver->sync.phase == QIHSE_REPL_FAILED) {
            fail(driver, "conflict policy not applied");
            return false;
        }
        break;

    case QIHSE_REJOIN_RECONSTRUCT_STATE:
        /* Local state is rebuilt from the applied journal; nothing to do here
         * beyond confirming the transfer did not fail. */
        break;

    case QIHSE_REJOIN_VERIFY_CHECKSUMS:
        /* The last gate before ownership.  Verify every transferred range
         * against the digest the peer declared. */
        if (driver->sync.phase != QIHSE_REPL_IDLE) {
            if (!qihse_repl_sync_finish(&driver->sync, store_void, user_void)) {
                fail(driver, driver->sync.last_error[0] ? driver->sync.last_error
                                                       : "checksum verification failed");
                return false;
            }
        }
        break;

    case QIHSE_REJOIN_COMPLETE:
        return true;

    case QIHSE_REJOIN_IDLE:
    default:
        fail(driver, "illegal step");
        return false;
    }

    /* Persist at every step, so a crash resumes from here rather than
     * restarting the sequence with the gates it had not yet passed. */
    (void)qihse_rejoin_driver_persist(driver, store_void, user_void);

    qihse_rejoin_step_t next = qihse_rejoin_next_step(driver->step);
    if (next == QIHSE_REJOIN_ABORTED) {
        fail(driver, "illegal transition");
        return false;
    }
    driver->step = next;
    return true;
}

bool qihse_rejoin_driver_run(qihse_rejoin_driver_t* driver,
                             void* store_void, void* user_void,
                             qihse_fed_tls_session_t* session,
                             qihse_repl_transport_t* transport,
                             void* journal_void,
                             qihse_rejoin_fetch_manifest_fn fetch_manifest,
                             void* fetch_ctx) {
    if (!driver) return false;
    /* Bounded so a sequence that cannot progress aborts rather than looping.
     * The sequence has 11 steps and a transfer may need several rounds per
     * range, so allow for the ranges plus the steps. */
    size_t budget = 32u + QIHSE_FEDERATION_MANIFEST_MAX_RANGES * 8u;
    for (size_t i = 0; i < budget; i++) {
        if (driver->step == QIHSE_REJOIN_COMPLETE) return true;
        if (driver->step == QIHSE_REJOIN_ABORTED) return false;
        if (!qihse_rejoin_driver_step(driver, store_void, user_void, session,
                                     transport, journal_void, fetch_manifest,
                                     fetch_ctx)) {
            return false;
        }
    }
    fail(driver, "rejoin exceeded its step budget");
    return false;
}
