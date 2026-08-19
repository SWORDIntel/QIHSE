#ifndef QIHSE_RESP_WIRE_H
#define QIHSE_RESP_WIRE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "qihse_kv_store.h"
#include "qihse_vector_db.h"
#include "qihse_timeseries.h"
#include "qihse_column.h"
#include "qihse_cluster_slot.h"
#include "qihse_cluster_bus.h"
#include "qihse_cluster_failover.h"
#include "qihse_system_guard.h"

typedef struct qihse_resp_server qihse_resp_server_t;

typedef struct {
    qihse_kv_store_t* store;
    qihse_vector_db_t vdb;
    qihse_tsdb_t* tsdb;
    qihse_column_store_t* column_store;
    qihse_cluster_topology_t* topology;
    const char* bind_address;
    const char* advertise_address;
    const char* node_id;
    uint16_t port;
    uint16_t bus_port;
    uint16_t local_node_index;
    size_t max_clients;
    size_t max_request_bytes;
    bool auth_required;
    bool require_full_coverage;
    bool pin_workers;
    bool strict_hardware_affinity;
    int numa_node_id;
    /* Phase 3: cluster bus + failover + guard throttling */
    bool enable_bus;
    bool enable_failover;
    bool enable_guard_throttle;
    const char* xdp_interface;       /* NULL = standard UDP bus */
    uint64_t guard_window_ms;        /* 0 = default 1000ms */
    double guard_saturation_fraction; /* 0 = default 0.8 */
} qihse_resp_server_config_t;

void qihse_resp_server_config_init(qihse_resp_server_config_t* config);
qihse_resp_server_t* qihse_resp_server_create(const qihse_resp_server_config_t* config);
bool qihse_resp_server_start(qihse_resp_server_t* server);
bool qihse_resp_server_run(qihse_resp_server_t* server);
void qihse_resp_server_stop(qihse_resp_server_t* server);
void qihse_resp_server_destroy(qihse_resp_server_t* server);
uint16_t qihse_resp_server_port(const qihse_resp_server_t* server);
qihse_cluster_topology_t* qihse_resp_server_topology(qihse_resp_server_t* server);
bool qihse_resp_server_handle_client_fd(qihse_resp_server_t* server, int client_fd);
qihse_cluster_bus_t* qihse_resp_server_bus(qihse_resp_server_t* server);
qihse_cluster_failover_t* qihse_resp_server_failover(qihse_resp_server_t* server);
qihse_system_guard_window_t* qihse_resp_server_guard_window(qihse_resp_server_t* server);

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
