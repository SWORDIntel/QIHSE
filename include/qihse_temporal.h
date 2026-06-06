#ifndef QIHSE_TEMPORAL_H
#define QIHSE_TEMPORAL_H

#include "qihse_vector_db.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Temporal query extension for forensic retrieval and time-travel.
 *
 * This struct extends the standard qihse_vector_query_t by adding temporal constraints.
 * It enables "time-travel" queries where the state of the vector database can be queried
 * exactly as it existed at a prior timestamp or WAL LSN, providing consistent forensic
 * reproducibility.
 */
typedef struct qihse_temporal_query_s {
    qihse_vector_query_t base;  /* The standard vector database query parameters */
    uint64_t timestamp;         /* The temporal snapshot boundary (as-of timestamp) */
    uint64_t max_wal_lsn;       /* The maximum Write-Ahead Log Logical Sequence Number to include */
} qihse_temporal_query_t;

/**
 * @brief Executes a vector database search as of a specific point in time.
 *
 * This function performs forensic retrieval. It executes a similarity search but
 * explicitly filters out any WAL tombstones (deletions) or inserts that occurred
 * after the `timestamp` or `max_wal_lsn` specified in the temporal query.
 * This effectively provides a time-travel view of the data.
 *
 * @param vdb Vector database handle
 * @param temporal_query The temporal query parameters
 * @param results Output array for results
 * @param max_results Maximum number of results to return
 * @return Number of results found, or negative on error
 */
int qihse_vector_db_search_as_of(
    qihse_vector_db_t vdb,
    const qihse_temporal_query_t* temporal_query,
    qihse_vector_result_t* results,
    size_t max_results
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TEMPORAL_H */
