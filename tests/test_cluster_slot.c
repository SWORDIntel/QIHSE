#include "qihse_cluster_slot.h"
#include "qihse_cluster_migrate.h"
#include "qihse_crc16.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint16_t reference_crc16(const unsigned char* data, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (unsigned int bit = 0; bit < 8; bit++) {
            crc = (uint16_t)(((uint32_t)crc << 1) ^ ((crc & 0x8000u) ? 0x1021u : 0u));
        }
    }
    return crc;
}

static qihse_cluster_node_t make_node(const char* seed, const char* host, uint16_t port) {
    qihse_cluster_node_t node;
    memset(&node, 0, sizeof(node));
    qihse_cluster_node_id_from_seed(seed, strlen(seed), node.id);
    snprintf(node.host, sizeof(node.host), "%s", host);
    node.port = port;
    node.role = QIHSE_CLUSTER_NODE_PRIMARY;
    node.primary_index = QIHSE_CLUSTER_NODE_NONE;
    node.healthy = true;
    return node;
}

int main(void) {
    static const unsigned char check[] = "123456789";
    assert(qihse_crc16_xmodem(check, 9) == 0x31c3u);
    assert(qihse_cluster_key_slot("foo", 3) == 12182u);
    assert(qihse_cluster_key_slot("bar", 3) == 5061u);
    assert(qihse_cluster_key_slot("{user1000}.following", 20) == 3443u);
    assert(qihse_cluster_key_slot("{user1000}.followers", 20) == 3443u);
    assert(qihse_cluster_key_slot("foo{}{bar}", 10) == (reference_crc16((const unsigned char*)"foo{}{bar}", 10) & 0x3fffu));

    unsigned char random_data[4096];
    uint32_t state = 1;
    for (size_t i = 0; i < sizeof(random_data); i++) {
        state = state * 1664525u + 1013904223u;
        random_data[i] = (unsigned char)(state >> 24);
    }
    for (size_t offset = 0; offset < 16; offset++) {
        for (size_t len = 0; len + offset <= sizeof(random_data); len += 13) {
            assert(qihse_crc16_xmodem(random_data + offset, len) == reference_crc16(random_data + offset, len));
        }
    }

    qihse_cluster_topology_t* topology = qihse_cluster_topology_create();
    assert(topology != NULL);
    qihse_cluster_node_t first = make_node("first", "127.0.0.1", 7000);
    qihse_cluster_node_t second = make_node("second", "127.0.0.1", 7001);
    uint16_t first_index;
    uint16_t second_index;
    assert(qihse_cluster_topology_upsert_node(topology, &first, &first_index));
    assert(qihse_cluster_topology_upsert_node(topology, &second, &second_index));
    assert(qihse_cluster_topology_set_local_node(topology, first_index));
    assert(qihse_cluster_topology_assign_range(topology, 0, 8191, first_index));
    assert(qihse_cluster_topology_assign_range(topology, 8192, 16383, second_index));
    assert(qihse_cluster_topology_is_covered(topology));

    qihse_cluster_route_t route = qihse_cluster_topology_route(topology, 100, false, false);
    assert(route.decision == QIHSE_CLUSTER_ROUTE_LOCAL);
    route = qihse_cluster_topology_route(topology, 12000, false, false);
    assert(route.decision == QIHSE_CLUSTER_ROUTE_MOVED);
    assert(route.target_index == second_index);

    assert(qihse_cluster_topology_set_migrating(topology, 100, first_index, second_index));
    route = qihse_cluster_topology_route(topology, 100, false, true);
    assert(route.decision == QIHSE_CLUSTER_ROUTE_LOCAL);
    route = qihse_cluster_topology_route(topology, 100, false, false);
    assert(route.decision == QIHSE_CLUSTER_ROUTE_ASK);
    assert(qihse_cluster_topology_set_local_node(topology, second_index));
    route = qihse_cluster_topology_route(topology, 100, true, false);
    assert(route.decision == QIHSE_CLUSTER_ROUTE_LOCAL);
    route = qihse_cluster_topology_route(topology, 100, false, false);
    assert(route.decision == QIHSE_CLUSTER_ROUTE_MOVED);

    qihse_cluster_slot_range_t ranges[4];
    assert(qihse_cluster_topology_ranges(topology, ranges, 4) == 2);
    assert(ranges[0].start == 0 && ranges[0].end == 8191 && ranges[0].owner_index == first_index);
    assert(ranges[1].start == 8192 && ranges[1].end == 16383 && ranges[1].owner_index == second_index);

    assert(qihse_cluster_topology_set_local_node(topology, first_index));
    assert(qihse_cluster_topology_set_stable(topology, 100, first_index));
    qihse_cluster_migration_t* migration = qihse_cluster_migration_begin(topology, 100, first_index, second_index);
    assert(migration != NULL);
    assert(qihse_cluster_migration_mark_streamed(migration, 128));
    qihse_cluster_migration_status_t status;
    assert(qihse_cluster_migration_status(migration, &status));
    assert(status.state == QIHSE_MIGRATION_STREAMING && status.keys_streamed == 1 && status.bytes_streamed == 128);
    assert(qihse_cluster_migration_commit(migration));
    uint16_t owner;
    assert(qihse_cluster_topology_get_slot(topology, 100, &owner, NULL, NULL) && owner == second_index);
    qihse_cluster_migration_destroy(migration);

    migration = qihse_cluster_migration_begin(topology, 101, first_index, second_index);
    assert(migration != NULL);
    assert(qihse_cluster_migration_abort(migration));
    assert(qihse_cluster_topology_get_slot(topology, 101, &owner, NULL, NULL) && owner == first_index);
    qihse_cluster_migration_destroy(migration);

    qihse_cluster_topology_destroy(topology);
    printf("cluster slot tests passed (%s)\n", qihse_crc16_backend_name());
    return 0;
}
