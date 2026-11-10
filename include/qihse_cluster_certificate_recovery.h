#ifndef QIHSE_CLUSTER_CERTIFICATE_RECOVERY_H
#define QIHSE_CLUSTER_CERTIFICATE_RECOVERY_H

#include "qihse_cluster_ownership.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fetch original signed envelopes from a pinned peer and authenticate the
 * complete chain through the requested canonical QCP2 event before applying
 * it. Run on the ownership recovery worker, never the bus receive thread.
 * timeout_ms is checked between the transport's independently bounded RPCs.
 * No fixed total-history cap is imposed; allocation/transport failure leaves
 * the local topology unchanged. */
bool qihse_cluster_ownership_pull_ct1_promotion_chain(
    qihse_cluster_ownership_context_t* context, uint16_t peer_index,
    const char* lane_id, const uint8_t through_event_digest[32],
    uint32_t timeout_ms, char* error, size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif
