#ifndef QIHSE_RESP_ENGINE_PUBLIC_H
#define QIHSE_RESP_ENGINE_PUBLIC_H

#include "qihse_resp_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Before first listen only. At most QIHSE_QKP_MAX_REPLICATION_PEERS (16)
 * additional exact node/key pins, owned by the server. The active system
 * Operator grantor must dominate the configured non-Operator service principal.
 * A duplicate node ID with a different key is rejected. No general trust,
 * administrator, or migration permission is granted. */
bool qihse_resp_server_add_replication_peer(
    qihse_resp_server_t* server, const char* node_id, const char* dsa_pub_path,
    const qihse_user_t* authenticated_grantor);

#ifdef __cplusplus
}
#endif
#endif
