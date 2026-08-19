#ifndef QIHSE_CLUSTER_SCATTER_H
#define QIHSE_CLUSTER_SCATTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"
#include "qihse_vector_db.h"
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QIHSE Cluster Scatter-Gather Engine
 *
 * Provides cross-node fan-out queries for multi-model commands:
 *   - VECSCATTER: parallel vector search across all shards with
 *     Reciprocal Rank Fusion (RRF) merge
 *   - TS.RANGE fan-out: aggregate time-series across shards
 *   - COL.SUM / COL.MINMAX fan-out: aggregate column stats across shards
 *
 * The coordinator opens short-lived TCP connections to each peer node's
 * RESP port, sends the sub-query, parses the RESP response, and merges
 * the results locally.  This mirrors how Redis Cluster smart clients
 * work, but server-side.
 */

typedef struct qihse_cluster_scatter qihse_cluster_scatter_t;

typedef struct {
    qihse_cluster_topology_t* topology;
    uint16_t local_node_index;
    uint32_t timeout_ms;       /* per-peer connect+read timeout */
    size_t max_peers;          /* 0 = all peers */
} qihse_cluster_scatter_config_t;

/* RRF fusion constant (standard value 60).  Higher values reduce the
 * influence of rank position. */
#define QIHSE_RRF_K 60u

/*
 * VECSCATTER: scatter a vector search to all peer shards, gather
 * candidate lists, and merge using Reciprocal Rank Fusion.
 *
 * The local shard is searched in-process; each remote shard is queried
 * via TCP.  Results from all shards are merged by RRF score:
 *   rrf_score(d) = sum_over_shards(1 / (K + rank_in_shard))
 *
 * Returns the number of fused results (<= top_k), or -1 on error.
 * `out_results` must be pre-allocated with `top_k` entries by the caller.
 */
int qihse_cluster_scatter_vecsearch(qihse_cluster_scatter_t* sg,
                                    const float* query_vector, size_t dims,
                                    size_t top_k, const qihse_user_t* user,
                                    qihse_vector_result_t* out_results);

/*
 * TS.RANGE fan-out: scatter a time-series range aggregation to all
 * peer shards and merge the results.
 *
 * For SUM: returns the sum of all shard sums.
 * For MIN: returns the minimum across all shard minimums.
 * For MAX: returns the maximum across all shard maximums.
 * For AVG: returns the weighted average across all shard averages.
 *
 * Returns true if at least one shard returned data.  `out_value` and
 * `out_count` receive the merged result.
 */
bool qihse_cluster_scatter_ts_range(qihse_cluster_scatter_t* sg,
                                    uint32_t series_id, uint64_t start, uint64_t end,
                                    int aggregation, const qihse_user_t* user,
                                    double* out_value, uint64_t* out_count);

/*
 * COL.SUM fan-out: scatter a column sum query to all peer shards
 * and return the total sum across all shards.
 */
bool qihse_cluster_scatter_col_sum(qihse_cluster_scatter_t* sg,
                                   const char* key, const qihse_user_t* user,
                                   double* out_sum);

/*
 * COL.MINMAX fan-out: scatter a column min/max query to all peer shards
 * and return the global min and max across all shards.
 */
bool qihse_cluster_scatter_col_minmax(qihse_cluster_scatter_t* sg,
                                      const char* key, const qihse_user_t* user,
                                      double* out_min, double* out_max);

qihse_cluster_scatter_t* qihse_cluster_scatter_create(const qihse_cluster_scatter_config_t* config);
void qihse_cluster_scatter_destroy(qihse_cluster_scatter_t* sg);

/* Statistics. */
typedef struct {
    uint64_t scatter_queries;
    uint64_t peer_queries_sent;
    uint64_t peer_responses_received;
    uint64_t peer_failures;
} qihse_cluster_scatter_stats_t;

void qihse_cluster_scatter_stats(const qihse_cluster_scatter_t* sg,
                                 qihse_cluster_scatter_stats_t* out_stats);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_SCATTER_H */
