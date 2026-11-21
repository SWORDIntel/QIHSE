/* Test-only adapter: configure the real server using the canonical C layout.
 * All handles and strings are owned by the isolated Python server process. */
#include "qihse_resp_wire.h"

qihse_resp_server_t* qihse_test_controller_server_create(
    qihse_kv_store_t* store, const char* node_id, const char* journal_directory,
    uint16_t port, uint16_t bus_port) {
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.node_id = node_id;
    config.bind_address = "127.0.0.1";
    config.advertise_address = "127.0.0.1";
    config.port = port;
    config.bus_port = bus_port;
    config.enable_bus = false;
    config.enable_failover = false;
    config.auth_required = true;
    config.federation_journal_directory = journal_directory;
    return qihse_resp_server_create(&config);
}
