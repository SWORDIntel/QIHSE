#ifndef QIHSE_CLUSTER_RECLAIM_H
#define QIHSE_CLUSTER_RECLAIM_H

#include <stddef.h>
#include <stdint.h>
#include "qihse_kv_store.h"
#include "qihse_cluster_slot.h"
#include "qihse_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Delete every key whose slot is NOT owned by local_index in the topology.
 * Returns the number of keys deleted. Used for COPY-then-GC: run after an
 * ownership journal replay has confirmed a slot moved away. */
size_t qihse_cluster_reclaim_foreign_slots(qihse_kv_store_t* store,
                                           const qihse_cluster_topology_t* topology,
                                           uint16_t local_index,
                                           qihse_user_t* user);

/* Bounded variant: collects at most `max_keys` foreign-slot keys (0 = 4096
 * default), verifies each slot is still foreign and not in MIGRATING/IMPORTING
 * state at deletion time, and deletes them. Sets `*out_has_more` to true if
 * additional foreign keys remain. */
size_t qihse_cluster_reclaim_foreign_slots_bounded(qihse_kv_store_t* store,
                                                   const qihse_cluster_topology_t* topology,
                                                   uint16_t local_index,
                                                   qihse_user_t* user,
                                                   size_t max_keys,
                                                   bool* out_has_more);

#ifdef __cplusplus
}
#endif

#endif
