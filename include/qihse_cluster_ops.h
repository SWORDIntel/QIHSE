#ifndef QIHSE_CLUSTER_OPS_H
#define QIHSE_CLUSTER_OPS_H

/* Cluster-internal operations shared by the RESP surface (CLUSTER MOVESLOTS)
 * and the cluster brain's R1 re-home. Internal API: not part of the SDK
 * surface and not stable. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_resp_server qihse_resp_server_t;

/* Slot-range handoff — the CLUSTER MOVESLOTS core.
 *
 * Streams every local KV record whose slot falls in [first,last] to the
 * target node over the MIGRATE wire flow (AUTH, ASKING, SET [PX]), deletes
 * the local copies, and flips ownership (local topology + bus broadcast).
 * Ownership flips BEFORE the transfer so the target accepts incoming writes;
 * a transfer that fails midway therefore leaves ownership at the target with
 * data still local. Callers detect that via *out_moved < *out_collected and
 * roll the ownership back (see qihse_cluster_set_range_owner).
 *
 * Runs as the system-domain principal. Returns 0 when the range moved
 * completely (or there was nothing to move), -1 on failure — err, when
 * non-NULL, receives a short reason. *out_moved / *out_collected report the
 * transfer counts on both paths. */
int qihse_cluster_handoff_range(qihse_resp_server_t* server,
                                uint16_t first, uint16_t last,
                                uint16_t target_index,
                                uint64_t* out_moved,
                                uint64_t* out_collected,
                                char* err, size_t err_cap);

/* Flip slot-range ownership locally and broadcast it on the bus, without
 * moving any data. Used by rollback and by the failover path. Returns true
 * when the local topology accepted the change. */
bool qihse_cluster_set_range_owner(qihse_resp_server_t* server,
                                   uint16_t first, uint16_t last,
                                   uint16_t owner_index);

/* Cheap probe: does this node hold at least one KV record whose slot falls in
 * [first,last]? Stops at the first hit (bounded scan of `limit` keys; limit 0
 * = scan until found). The brain's R1 refuses to re-home a range it cannot
 * actually serve. */
bool qihse_cluster_range_has_local_keys(qihse_resp_server_t* server,
                                        uint16_t first, uint16_t last,
                                        size_t limit);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CLUSTER_OPS_H */
