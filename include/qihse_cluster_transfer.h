#ifndef QIHSE_CLUSTER_TRANSFER_H
#define QIHSE_CLUSTER_TRANSFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_cluster_ownership.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_CLUSTER_TRANSFER_REJECTED = 0, /* no matching transfer was prepared */
    QIHSE_CLUSTER_TRANSFER_PENDING = 1,  /* durable fence; retry/recovery required */
    QIHSE_CLUSTER_TRANSFER_COMMITTED = 2,
    /* Source-size bound, before any peer contact, and a newly prepared
     * source fence was durably aborted. Safe to retry smaller ranges with
     * fresh transfer IDs. Never returned for uncertain/pending transfers. */
    QIHSE_CLUSTER_TRANSFER_TOO_LARGE = 3
} qihse_cluster_transfer_result_t;

typedef enum {
    QIHSE_CLUSTER_TRANSFER_FENCED = 1,
    QIHSE_CLUSTER_TRANSFER_SNAPSHOTTED = 2,
    QIHSE_CLUSTER_TRANSFER_SENDING = 3,
    QIHSE_CLUSTER_TRANSFER_SEALING = 4,
    QIHSE_CLUSTER_TRANSFER_COMMITTING = 5
} qihse_cluster_transfer_phase_t;

typedef void (*qihse_cluster_transfer_progress_fn)(
    void *context, qihse_cluster_transfer_phase_t phase,
    uint64_t bytes_done, uint64_t bytes_total);

typedef struct {
    qihse_cluster_ownership_context_t *ownership;
    qihse_cluster_transfer_progress_fn progress;
    void *progress_context;
    size_t chunk_bytes; /* 1..12 KiB; zero selects the 12 KiB default. */
} qihse_cluster_transfer_context_t;

/* Fenced CT2 source-side transfer. Any failure after PREPARED leaves the
 * source fenced and unpublished; the caller must not resume writes or change
 * owners on an uncertain result. */
qihse_cluster_transfer_result_t qihse_cluster_transfer_range(
    qihse_cluster_transfer_context_t *context, const char *transfer_id,
    uint16_t source_index, uint16_t target_index,
    uint16_t first_slot, uint16_t last_slot,
    char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif
#endif
