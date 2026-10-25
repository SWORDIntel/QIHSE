#include "qihse_cluster_reclaim.h"

#include <stdlib.h>
#include <string.h>

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
    char** keys;
    size_t key_count;
    size_t key_capacity;
    size_t max_keys;
    bool has_more;
    bool failed;
    size_t deleted;
} reclaim_ctx_t;

static bool reclaim_key_is_node_local(const char* key) {
    static const char* const prefixes[] = {
        "aimem:",
        "aimemv:",
        "fabric:",
        "fednode:",
        "federation/node/",
        "snapshot/manifest:",
        "rejoin/state:",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(key, prefixes[i], n) == 0) return true;
    }
    return false;
}

static bool reclaim_iter(const char* key, void* user_data) {
    reclaim_ctx_t* c = (reclaim_ctx_t*)user_data;
    if (reclaim_key_is_node_local(key)) return true;
    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    uint16_t owner = slot < c->owners_count ? c->owners[slot] : QIHSE_CLUSTER_NODE_NONE;
    if (owner == QIHSE_CLUSTER_NODE_NONE || owner == c->local_index) return true;
    uint16_t live_owner = QIHSE_CLUSTER_NODE_NONE;
    qihse_cluster_slot_state_t live_state = QIHSE_CLUSTER_SLOT_STABLE;
    if (!qihse_cluster_topology_get_slot(c->topology, slot, &live_owner, &live_state, NULL) ||
        live_owner == QIHSE_CLUSTER_NODE_NONE ||
        live_owner == c->local_index ||
        live_state != QIHSE_CLUSTER_SLOT_STABLE) {
        return true;
    }
    if (c->max_keys > 0u && c->key_count >= c->max_keys) {
        c->has_more = true;
        return false;
    }
    if (c->key_count == c->key_capacity) {
        size_t cap = c->key_capacity ? c->key_capacity * 2u : 64u;
        if (c->max_keys > 0u && cap > c->max_keys) cap = c->max_keys;
        char** next = (char**)realloc(c->keys, cap * sizeof(*next));
        if (!next) { c->failed = true; return false; }
        c->keys = next;
        c->key_capacity = cap;
    }
    c->keys[c->key_count] = strdup(key);
    if (!c->keys[c->key_count]) { c->failed = true; return false; }
    c->key_count++;
    return true;
}

size_t qihse_cluster_reclaim_foreign_slots_bounded(qihse_kv_store_t* store,
                                                   const qihse_cluster_topology_t* topology,
                                                   uint16_t local_index,
                                                   qihse_user_t* user,
                                                   size_t max_keys,
                                                   bool* out_has_more) {
    if (out_has_more) *out_has_more = false;
    if (!store || !topology || !user) return 0u;
    reclaim_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.store = store;
    c.topology = topology;
    c.local_index = local_index;
    c.user = user;
    c.max_keys = max_keys ? max_keys : 4096u;
    c.owners_count = qihse_cluster_topology_slot_owner_snapshot(topology, c.owners, 16384u);
    if (c.owners_count == 0u) return 0u;
    if (!qihse_kv_foreach_key_user(store, user, reclaim_iter, &c) || c.failed) {
        for (size_t i = 0; i < c.key_count; i++) free(c.keys[i]);
        free(c.keys);
        return 0u;
    }
    if (out_has_more) *out_has_more = c.has_more;
    /* Mutate only after enumeration released its read lock, and re-verify
     * slot ownership + STABLE state immediately before deleting each key. */
    for (size_t i = 0; i < c.key_count; i++) {
        uint16_t slot = qihse_cluster_key_slot(c.keys[i], strlen(c.keys[i]));
        uint16_t live_owner = QIHSE_CLUSTER_NODE_NONE;
        qihse_cluster_slot_state_t live_state = QIHSE_CLUSTER_SLOT_STABLE;
        if (qihse_cluster_topology_get_slot(topology, slot, &live_owner, &live_state, NULL) &&
            live_owner != QIHSE_CLUSTER_NODE_NONE &&
            live_owner != local_index &&
            live_state == QIHSE_CLUSTER_SLOT_STABLE) {
            if (qihse_kv_del_user(store, c.keys[i], user)) c.deleted++;
        }
        free(c.keys[i]);
    }
    free(c.keys);
    return c.deleted;
}

size_t qihse_cluster_reclaim_foreign_slots(qihse_kv_store_t* store,
                                           const qihse_cluster_topology_t* topology,
                                           uint16_t local_index,
                                           qihse_user_t* user) {
    size_t total = 0u;
    bool has_more = false;
    do {
        size_t batch = qihse_cluster_reclaim_foreign_slots_bounded(
            store, topology, local_index, user, 4096u, &has_more);
        total += batch;
        if (batch == 0u) break;
    } while (has_more);
    return total;
}
