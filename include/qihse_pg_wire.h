#ifndef QIHSE_PG_WIRE_H
#define QIHSE_PG_WIRE_H

#include <stdbool.h>
#include <stdint.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include "qihse_cluster_slot.h"
#include "qihse_uwp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes and starts the embedded PostgreSQL Wire Protocol Server.
 */
bool qihse_start_pg_wire_server(void* vdb, uint16_t port, const char* bind_address);

/**
 * Initializes and starts the sharded multi-engine PostgreSQL Wire Protocol Server.
 */
bool qihse_start_pg_wire_cluster_server(
    qihse_kv_store_t* store,
    qihse_vector_db_t vdb,
    qihse_tsdb_t* tsdb,
    qihse_column_store_t* col,
    qihse_cluster_topology_t* topo,
    uint16_t port,
    const char* bind_address
);

/**
 * Handles a PostgreSQL client connection synchronously on the given socket.
 */
void qihse_pg_wire_handle_client(int client_fd, void* vdb);

/**
 * Handles a multi-model PostgreSQL client connection with full distributed planning support.
 */
void qihse_pg_wire_handle_client_multi(
    int client_fd,
    qihse_kv_store_t* store,
    qihse_vector_db_t vdb,
    qihse_tsdb_t* tsdb,
    qihse_column_store_t* col,
    qihse_cluster_topology_t* topo
);

/* Handle one accepted PostgreSQL connection with the caller's shared SQL
 * schema and transaction manager. The context and all engine pointers remain
 * caller-owned and must outlive the handler. The legacy multi-engine handler
 * has no transaction manager and therefore refuses BEGIN/COMMIT/ROLLBACK.
 * SQL DDL, DML and SELECT use the authenticated UWP executor. Only an
 * executor-confirmed result is returned to the client; unsupported statements
 * and unsupported extended-protocol bindings fail closed. Named and unnamed
 * prepared statements and portals are connection-local and bounded; Execute
 * revalidates authenticated identity and delegates typed binds to UWP.
 * Transactional reads depend on
 * the executor's isolation and authorization checks. */
void qihse_pg_wire_handle_client_uwp(int client_fd,
                                     qihse_uwp_context_t* uwp_context,
                                     qihse_cluster_topology_t* topo);

/* TCP listener for the context-backed handler. PostgreSQL password
 * authentication sends credentials in cleartext on this legacy loopback-only
 * listener. SSLRequest fails closed (no downgrade); use open_tls_uwp for
 * network access. The listener borrows the UWP
 * context and topology; both must outlive it. It deliberately accepts and
 * serves one connection per accept_once call, leaving concurrency and stop
 * policy to the embedding application. A timeout returns 0, a served client
 * returns 1, and an error returns -1. Only a fully configured SQL context is
 * accepted, so classified SELECT cannot fall back to a context-free path. */
typedef struct qihse_pg_wire_listener qihse_pg_wire_listener_t;
qihse_pg_wire_listener_t* qihse_pg_wire_listener_open_uwp(
    qihse_uwp_context_t* uwp_context,
    qihse_cluster_topology_t* topo,
    const char* bind_address,
    uint16_t port);
/* TLS-required listener, including non-loopback binds. A valid PEM certificate
 * chain and matching private key are mandatory. Accepts only PostgreSQL
 * SSLRequest followed by a successful TLS 1.2+ handshake before AUTH; direct
 * startup, failed TLS and repeated SSLRequest never downgrade to cleartext.
 * Clients must verify the certificate identity/chain themselves. The legacy
 * open_uwp entry point remains restricted to 127.0.0.1. */
qihse_pg_wire_listener_t* qihse_pg_wire_listener_open_tls_uwp(
    qihse_uwp_context_t* uwp, qihse_cluster_topology_t* topo,
    const char* bind_address, uint16_t port,
    const char* certificate_file, const char* private_key_file);
uint16_t qihse_pg_wire_listener_port(const qihse_pg_wire_listener_t* listener);
int qihse_pg_wire_listener_accept_once(qihse_pg_wire_listener_t* listener,
                                       int timeout_ms);
void qihse_pg_wire_listener_close(qihse_pg_wire_listener_t* listener);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_PG_WIRE_H
