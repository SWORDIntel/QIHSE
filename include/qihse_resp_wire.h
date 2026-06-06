#ifndef QIHSE_RESP_WIRE_H
#define QIHSE_RESP_WIRE_H

#include <stdint.h>
#include <stdbool.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"

/**
 * @brief Starts a TCP server that listens for RESP (Redis Serialization Protocol) commands.
 * 
 * Supports standard Redis commands (PING, SET, GET, DEL) mapped to the QIHSE KV Store,
 * as well as custom commands (VECSET, VECGET, VECSEARCH) mapped to the QIHSE Vector DB.
 * 
 * @param store Pointer to the initialized QIHSE KV Store.
 * @param vdb Pointer to the initialized QIHSE Vector Database.
 * @param port TCP port to bind to (e.g., 6379).
 * @param bind_address IP address to bind to (e.g., "0.0.0.0" or "127.0.0.1").
 * @return true if the server started successfully, false otherwise.
 */
bool qihse_start_resp_server(qihse_kv_store_t* store, qihse_vector_db_t vdb, uint16_t port, const char* bind_address);

/**
 * Handles a RESP client connection synchronously on the given socket.
 * Useful for multiplexing connections.
 */
void qihse_resp_handle_client(int client_fd, qihse_kv_store_t* store, qihse_vector_db_t vdb);

#endif /* QIHSE_RESP_WIRE_H */
