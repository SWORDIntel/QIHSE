#include "qihse_resp_wire.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static qihse_cluster_node_t make_node(unsigned int index, uint16_t port) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    char seed[64];
    int len = snprintf(seed, sizeof(seed), "qihse-local-cluster-%u-%u", index, port);
    qihse_cluster_node_id_from_seed(seed, len > 0 ? (size_t)len : 0u, node.id);
    snprintf(node.host, sizeof(node.host), "127.0.0.1");
    node.port = port;
    node.bus_port = port <= UINT16_MAX - 10000u ? (uint16_t)(port + 10000u) : 0u;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = true;
    return node;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <node-index:0..2> <base-port>\n", argv[0]);
        return 2;
    }
    char* end = NULL;
    errno = 0;
    unsigned long node_index = strtoul(argv[1], &end, 10);
    if (errno != 0 || !end || *end != '\0' || node_index > 2u) return 2;
    errno = 0;
    unsigned long base_port = strtoul(argv[2], &end, 10);
    if (errno != 0 || !end || *end != '\0' || base_port == 0 || base_port > UINT16_MAX - 2u) return 2;

    qihse_kv_store_t* store = qihse_kv_store_create();
    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    if (!store || !topology) return 1;
    uint16_t indexes[3];
    for (unsigned int i = 0; i < 3u; i++) {
        qihse_cluster_node_t node = make_node(i, (uint16_t)(base_port + i));
        if (!qihse_cluster_topology_upsert_node(topology, &node, &indexes[i])) return 1;
    }
    if (!qihse_cluster_topology_set_local_node(topology, indexes[node_index]) ||
        !qihse_cluster_topology_assign_range(topology, 0u, 5460u, indexes[0]) ||
        !qihse_cluster_topology_assign_range(topology, 5461u, 10922u, indexes[1]) ||
        !qihse_cluster_topology_assign_range(topology, 10923u, 16383u, indexes[2])) return 1;

    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.topology = topology;
    config.local_node_index = indexes[node_index];
    config.port = (uint16_t)(base_port + node_index);
    config.auth_required = false;
    config.pin_workers = true;
    qihse_resp_server_t* server = qihse_resp_server_create(&config);
    if (!server) return 1;
    bool result = qihse_resp_server_run(server);
    qihse_resp_server_destroy(server);
    qihse_cluster_topology_destroy(topology);
    qihse_kv_store_destroy(store);
    return result ? 0 : 1;
}
