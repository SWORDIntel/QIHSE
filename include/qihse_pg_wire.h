#ifndef QIHSE_PG_WIRE_H
#define QIHSE_PG_WIRE_H

#include <stdbool.h>
#include <stdint.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include "qihse_cluster_slot.h"

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

#ifdef __cplusplus
}
#endif

#endif // QIHSE_PG_WIRE_H
