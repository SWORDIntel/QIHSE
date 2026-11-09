/* CT.1/CT.2 fail-closed ownership regression. This topology fixture verifies
 * that a slot cannot be routed to an unproven successor. It does not replace
 * a real durable replication or data-survival drill. */
#include "qihse_cluster_failover.h"
#include "qihse_cluster_slot.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void node(qihse_cluster_node_t *out,const char *seed,
                 qihse_cluster_node_role_t role,uint16_t primary) {
    memset(out,0,sizeof *out);
    qihse_cluster_node_id_from_seed(seed,strlen(seed),out->id);
    strcpy(out->host,"127.0.0.1");
    out->port=7000;
    out->bus_port=17000;
    out->role=role;
    out->primary_index=primary;
    out->healthy=true;
}
static void check_owner(qihse_cluster_topology_t *topology,uint16_t slot,
                        uint16_t expected) {
    uint16_t owner=QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_slot_state_t state;
    assert(qihse_cluster_topology_get_slot(topology,slot,&owner,&state,NULL));
    assert(owner==expected);
    assert(state==QIHSE_CLUSTER_SLOT_STABLE);
}
static void unproven_takeover(qihse_cluster_node_role_t successor_role) {
    qihse_cluster_topology_t *topology=qihse_cluster_topology_create();
    qihse_cluster_node_t primary,successor,check;
    uint16_t old_index,new_index;
    qihse_cluster_failover_config_t config={0};
    qihse_cluster_failover_t *failover;
    assert(topology);
    node(&primary,"ct-old-primary",QIHSE_CLUSTER_NODE_PRIMARY,
         QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_topology_upsert_node(topology,&primary,&old_index));
    node(&successor,"ct-unproven-successor",successor_role,
         successor_role==QIHSE_CLUSTER_NODE_REPLICA?
         old_index:QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_topology_upsert_node(topology,&successor,&new_index));
    /* Explicit topology initialization is intentional and remains supported. */
    assert(qihse_cluster_topology_assign_range(topology,0,99,old_index));
    check_owner(topology,42,old_index);
    config.topology=topology;
    config.local_node_index=new_index;
    failover=qihse_cluster_failover_create(&config);
    assert(failover);
    assert(qihse_cluster_topology_set_node_health(topology,old_index,false));
    assert(qihse_cluster_failover_handle(failover,old_index)==QIHSE_CLUSTER_NODE_NONE);
    assert(!qihse_cluster_failover_promote(failover,old_index,new_index));
    assert(qihse_cluster_failover_events(failover)==0);
    check_owner(topology,0,old_index);
    check_owner(topology,42,old_index);
    check_owner(topology,99,old_index);
    assert(qihse_cluster_topology_get_node(topology,new_index,&check));
    assert(check.role==successor_role);
    assert(check.primary_index==successor.primary_index);
    qihse_cluster_failover_destroy(failover);
    qihse_cluster_topology_destroy(topology);
}
static void empty_owner_role_change(void) {
    qihse_cluster_topology_t *topology=qihse_cluster_topology_create();
    qihse_cluster_node_t primary,successor,check;
    uint16_t old_index,new_index;
    qihse_cluster_failover_config_t config={0};
    qihse_cluster_failover_t *failover;
    assert(topology);
    node(&primary,"empty-old",QIHSE_CLUSTER_NODE_PRIMARY,QIHSE_CLUSTER_NODE_NONE);
    assert(qihse_cluster_topology_upsert_node(topology,&primary,&old_index));
    node(&successor,"empty-successor",QIHSE_CLUSTER_NODE_REPLICA,old_index);
    assert(qihse_cluster_topology_upsert_node(topology,&successor,&new_index));
    config.topology=topology; config.local_node_index=new_index;
    failover=qihse_cluster_failover_create(&config);
    assert(failover);
    assert(qihse_cluster_topology_set_node_health(topology,old_index,false));
    assert(qihse_cluster_failover_promote(failover,old_index,new_index));
    assert(qihse_cluster_topology_get_node(topology,new_index,&check));
    assert(check.role==QIHSE_CLUSTER_NODE_PRIMARY);
    qihse_cluster_failover_destroy(failover);
    qihse_cluster_topology_destroy(topology);
}
int main(void) {
    unproven_takeover(QIHSE_CLUSTER_NODE_REPLICA);
    unproven_takeover(QIHSE_CLUSTER_NODE_PRIMARY);
    empty_owner_role_change();
    puts("PASS unproven failover leaves owner and successor role unchanged");
    return 0;
}
