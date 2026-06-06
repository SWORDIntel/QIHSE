#ifndef QIHSE_PG_WIRE_H
#define QIHSE_PG_WIRE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes and starts the embedded PostgreSQL Wire Protocol Server.
 *
 * @param vdb Pointer to the underlying database instance.
 * @param port The port to bind to.
 * @param bind_address The address to bind to (e.g., "127.0.0.1" or "0.0.0.0").
 * @return true if successfully bound and listening, false otherwise.
 */
bool qihse_start_pg_wire_server(void* vdb, uint16_t port, const char* bind_address);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_PG_WIRE_H
