#ifndef QIHSE_CLUSTER_OWNERSHIP_JOURNAL_H
#define QIHSE_CLUSTER_OWNERSHIP_JOURNAL_H

#include <stdint.h>
#include <stddef.h>
#include "qihse_cluster_slot.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Durable slot-ownership journal (COPY → PERSIST → SWITCH → GC).
 *
 * Each MOVESLOTS/brain re-home appends a small fsync'd record before the
 * ownership switch is broadcast, so the ownership survives a crash/restart.
 * On startup the node replays the journal and adopts each record only if its
 * config_epoch is newer than what it already knows (the adopt-if-newer rule
 * lives in the caller, not here — the journal replays every valid record
 * verbatim).
 *
 * File: <data_dir>/slot-ownership.journal. Corrupt/torn tail records are
 * skipped; earlier valid records are preserved.
 */

/* One ownership delta. */
typedef struct {
    uint16_t start;
    uint16_t end;
    char owner_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint64_t config_epoch;
} qihse_cluster_ownership_entry_t;

typedef void (*qihse_cluster_ownership_journal_cb)(
    const qihse_cluster_ownership_entry_t* entry, void* ctx);

/* Version 2 records are a durable transfer state machine. A PREPARED record
 * is deliberately not an ownership change: startup must keep the local store
 * fenced until the transfer is completed or explicitly aborted. COMMITTED is
 * only appended after the receiver's durable receipt has been verified and
 * the source fence is in force. */
#define QIHSE_OWNERSHIP_ID_MAX 64u
#define QIHSE_OWNERSHIP_PROOF_DIGEST_BYTES 32u
#define QIHSE_OWNERSHIP_SLOT_BITMAP_BYTES (QIHSE_CLUSTER_SLOT_COUNT / 8u)
typedef enum {
    QIHSE_OWNERSHIP_PREPARED = 1,
    QIHSE_OWNERSHIP_COMMITTED = 2,
    QIHSE_OWNERSHIP_ABORTED = 3,
    /* Target activation was verified and the transaction may be replayed
     * locally without depending on mutable/current peer seal state. */
    QIHSE_OWNERSHIP_FINALIZED = 4,
    /* Durable transfer intent written before a KV fence. Recovery can now
     * distinguish a crash before fencing from a fence whose follow-up phase
     * append was interrupted. */
    QIHSE_OWNERSHIP_INTENT = 5,
    QIHSE_OWNERSHIP_ADOPTED = 6
} qihse_cluster_ownership_phase_t;

typedef struct {
    qihse_cluster_ownership_phase_t phase;
    uint16_t start;
    uint16_t end;
    char transfer_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    /* Topology IDs and QKP pinned identities are separate namespaces. Never
     * derive one from the other or use gossip/IP hints as an identity map. */
    char source_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char target_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    char source_qkp_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    char target_qkp_id[QIHSE_OWNERSHIP_ID_MAX + 1u];
    char generation[QIHSE_OWNERSHIP_ID_MAX + 1u];
    /* CT1 receiver promotion's new local generation; empty for CT2 transfer. */
    char next_generation[QIHSE_OWNERSHIP_ID_MAX + 1u];
    /* CT1 promotion records carry the complete transferred slot set so one
     * prepared/commit transition covers disjoint ranges atomically. Empty for
     * single-range CT2 moves. Bit N corresponds to cluster slot N. */
    uint8_t slot_bitmap[QIHSE_OWNERSHIP_SLOT_BITMAP_BYTES];
    char owner_id[QIHSE_CLUSTER_NODE_ID_LEN + 1u];
    uint64_t config_epoch;
    uint64_t source_lsn;
    uint64_t target_lsn;
    /* CT2 stores the verified target checksum; CT1 stores a deterministic
     * tuple fingerprint. This is audit binding, never standalone proof. */
    uint8_t proof_digest[QIHSE_OWNERSHIP_PROOF_DIGEST_BYTES];
} qihse_cluster_ownership_txn_t;

typedef bool (*qihse_cluster_ownership_txn_cb)(
    const qihse_cluster_ownership_txn_t* txn, void* ctx);

/* Append + fsync one entry. Returns 0 on success, -1 on error (errno set). */
int qihse_cluster_ownership_journal_append(const char* data_dir,
                                           uint16_t start, uint16_t end,
                                           const char* owner_id,
                                           uint64_t config_epoch);

/* Replay the journal front-to-back, invoking cb for every valid entry.
 * Returns the number of valid entries replayed, or -1 on open failure. */
int qihse_cluster_ownership_journal_replay(const char* data_dir,
                                           qihse_cluster_ownership_journal_cb cb,
                                           void* ctx);

/* Append + fsync a v2 transfer phase. Sequence: PREPARED→COMMITTED→FINALIZED,
 * or PREPARED→ABORTED. FINALIZED means target activation was verified and
 * can be replayed offline from this node's durable journal. */
int qihse_cluster_ownership_journal_append_txn(
    const char* data_dir, const qihse_cluster_ownership_txn_t* txn);

/* Replay v2 state-machine records in order. The callback sees each validated
 * transition. out_unresolved is true if a transfer ends PREPARED, or replay
 * finds a torn/corrupt v2 tail after a PREPARED phase. Returns phase-record
 * count, or -1 on invalid arguments/open/read/callback failure. */
int qihse_cluster_ownership_journal_replay_txn(
    const char* data_dir, qihse_cluster_ownership_txn_cb cb, void* ctx,
    bool* out_unresolved);

#ifdef __cplusplus
}
#endif

#endif
