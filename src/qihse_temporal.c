#include "qihse_temporal.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Internal metadata struct expected at the beginning of vector metadata
 * for temporal queries. This tracks MVCC information.
 */
typedef struct qihse_temporal_metadata_s {
    uint64_t created_timestamp;
    uint64_t created_wal_lsn;
    uint64_t deleted_timestamp;
    uint64_t deleted_wal_lsn;
} qihse_temporal_metadata_t;

/**
 * @brief Context passed to the temporal wrapper filter.
 */
typedef struct {
    const qihse_temporal_query_t* temporal_query;
    qihse_metadata_filter_fn_t base_filter;
    void* base_opaque;
} temporal_filter_ctx_t;

/**
 * @brief Wrapper filter that evaluates MVCC rules before calling the base filter.
 */
static bool qihse_temporal_filter(const void* metadata, size_t metadata_size, void* opaque) {
    if (!opaque) return true;
    
    temporal_filter_ctx_t* ctx = (temporal_filter_ctx_t*)opaque;
    const qihse_temporal_query_t* tq = ctx->temporal_query;
    
    /* 1. Perform temporal filtering if metadata contains the MVCC header */
    if (metadata && metadata_size >= sizeof(qihse_temporal_metadata_t)) {
        const qihse_temporal_metadata_t* mvcc = (const qihse_temporal_metadata_t*)metadata;
        
        /* Ignore inserts that occurred after the threshold */
        if (tq->max_wal_lsn > 0 && mvcc->created_wal_lsn > tq->max_wal_lsn) {
            return false;
        }
        if (tq->timestamp > 0 && mvcc->created_timestamp > tq->timestamp) {
            return false;
        }
        
        /* Ignore tombstones if they occurred after the threshold (treat as alive).
         * Filter out vectors if they were deleted AT or BEFORE the threshold (treat as dead).
         */
        if (tq->max_wal_lsn > 0 && mvcc->deleted_wal_lsn > 0 && mvcc->deleted_wal_lsn <= tq->max_wal_lsn) {
            return false;
        }
        if (tq->timestamp > 0 && mvcc->deleted_timestamp > 0 && mvcc->deleted_timestamp <= tq->timestamp) {
            return false;
        }
    }
    
    /* 2. Fallback to base filter if configured */
    if (ctx->base_filter) {
        return ctx->base_filter(metadata, metadata_size, ctx->base_opaque);
    }
    
    return true;
}

/**
 * @brief Executes a vector database search as of a specific point in time.
 *
 * This function iterates through the index while actively cross-referencing 
 * MVCC tracking structures to mask out elements mutated after the given temporal threshold.
 *
 * It provides forensic retrieval by ignoring:
 * 1. Inserts that occurred after the `temporal_query->max_wal_lsn` or `timestamp`.
 * 2. Tombstones (deletions) that occurred after the `temporal_query->max_wal_lsn`
 *    or `timestamp`, thereby treating deleted but historically active vectors as alive.
 */
int qihse_vector_db_search_as_of(
    qihse_vector_db_t vdb,
    const qihse_temporal_query_t* temporal_query,
    qihse_vector_result_t* results,
    size_t max_results
) {
    if (!vdb || !temporal_query || !results || max_results == 0) {
        return -1;
    }

    /* Wrap the query to intercept the metadata_filter callback */
    temporal_filter_ctx_t ctx;
    ctx.temporal_query = temporal_query;
    ctx.base_filter = temporal_query->base.metadata_filter;
    ctx.base_opaque = temporal_query->base.metadata_filter_opaque;

    qihse_vector_query_t modified_query = temporal_query->base;
    modified_query.metadata_filter = qihse_temporal_filter;
    modified_query.metadata_filter_opaque = &ctx;

    /* Execute the search with the temporal filter intercepting candidates */
    return qihse_vector_db_search(vdb, &modified_query, results, max_results);
}
