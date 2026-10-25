#include "qihse_cluster_reclaim.h"

#include <stdio.h>
#include <string.h>

#include "qihse_auth.h"
#include "qihse_crc16.h"
#include "qihse_cluster_slot.h"
#include "qihse_kv_store.h"

/* Deletes every key whose slot is not owned by local_index, returning the
 * number deleted. Used for COPY-then-GC: after an ownership journal replay
 * confirms a slot moved away, this reclaims the stale local copies. The
 * system operator is the enumeration principal so clearance filtering never
 * hides a row that should be reclaimed. */
typedef struct {
    qihse_kv_store_t* store;
    const qihse_cluster_topology_t* topology;
    uint16_t local_index;
    uint16_t owners[16384];
    size_t owners_count;
    qihse_user_t* user;
    size_t deleted;
} reclaim_ctx_t;

static bool reclaim_iter(const char* key, const char* value, void* user_data) {
    (void)value;
    reclaim_ctx_t* c = (reclaim_ctx_t*)user_data;
    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    uint16_t owner = slot < c->owners_count ? c->owners[slot] : QIHSE_CLUSTER_NODE_NONE;
    if (owner != QIHSE_CLUSTER_NODE_NONE && owner != c->local_index) {
        if (qihse_kv_del_user(c->store, key, c->user)) c->deleted++;
    }
    return true;
}

size_t qihse_cluster_reclaim_foreign_slots(qihse_kv_store_t* store,
                                           const qihse_cluster_topology_t* topology,
                                           uint16_t local_index,
                                           qihse_user_t* user) {
    if (!store || !topology || !user) return 0u;
    reclaim_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.store = store;
    c.topology = topology;
    c.local_index = local_index;
    c.user = user;
    c.owners_count = qihse_cluster_topology_slot_owner_snapshot(topology, c.owners, 16384u);
    if (c.owners_count == 0u) return 0u;
    qihse_kv_foreach_user(store, user, reclaim_iter, &c);
    return c.deleted;
}
