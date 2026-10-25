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

#ifdef __cplusplus
}
#endif

#endif
