/* Pure address-policy test. Compile with function/data sections and link GC to
 * isolate the parser from the transport; no sockets or service are opened. */
#include "../src/spinnaker/qihse_cluster_bus.c"
#include "../src/spinnaker/qihse_cluster_failover.c"
#include <assert.h>

static void test_fail_callback(qihse_cluster_topology_t* topology,
                               uint16_t node, void* data) {
    (void)topology;
    (void)node;
    (void)data;
}

/* Reproduce only startup ownership/wiring, without opening a socket. */
static void test_failover_retains_bus(void) {
    int topology_token = 0;
    qihse_cluster_bus_config_t bus_config = {0};
    bus_config.topology = (qihse_cluster_topology_t*)&topology_token;
    bus_config.bind_address = "localhost";
    qihse_cluster_bus_t* bus = qihse_cluster_bus_create(&bus_config);
    assert(bus);
    qihse_cluster_failover_config_t failover_config = {0};
    failover_config.topology = bus_config.topology;
    failover_config.bus = bus;
    qihse_cluster_failover_t* coordinator = qihse_cluster_failover_create(&failover_config);
    assert(coordinator);
    qihse_cluster_bus_set_fail_callback(bus, test_fail_callback, coordinator);
    assert(coordinator->bus == bus);
    assert(coordinator->bus->on_fail == test_fail_callback);
    assert(coordinator->bus->on_fail_user_data == coordinator);
    assert(qihse_cluster_bus_fd(coordinator->bus) == -1);
    qihse_cluster_bus_set_fail_callback(bus, NULL, NULL);
    assert(coordinator->bus->on_fail == NULL);
    assert(coordinator->bus->on_fail_user_data == NULL);
    qihse_cluster_failover_destroy(coordinator);
    qihse_cluster_bus_destroy(bus);
}

int main(void) {
    test_failover_retains_bus();
    struct in_addr addr;
    assert(qihse_bus_bind_ipv4("localhost", &addr));
    assert(addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(qihse_bus_bind_ipv4("127.0.0.1", &addr));
    assert(addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(qihse_bus_bind_ipv4("0.0.0.0", &addr));
    assert(addr.s_addr == htonl(INADDR_ANY));
    assert(qihse_bus_bind_ipv4("192.0.2.1", &addr));
    assert(!qihse_bus_bind_ipv4("::1", &addr));
    assert(!qihse_bus_bind_ipv4("::", &addr));
    assert(!qihse_bus_bind_ipv4("127.0.0.1.invalid", &addr));
    assert(!qihse_bus_bind_ipv4("invalid", &addr));
    assert(!qihse_bus_bind_ipv4("", &addr));
    assert(!qihse_bus_bind_ipv4(NULL, &addr));
    assert(!qihse_bus_bind_ipv4("localhost", NULL));
    puts("PASS cluster bus IPv4 bind policy");
    return 0;
}
