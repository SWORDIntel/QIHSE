#ifndef QIHSE_CLUSTER_MIGRATE_H
#define QIHSE_CLUSTER_MIGRATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qihse_cluster_slot.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_MIGRATION_PREPARING = 0,
    QIHSE_MIGRATION_STREAMING = 1,
    QIHSE_MIGRATION_COMMITTED = 2,
    QIHSE_MIGRATION_ABORTED = 3
} qihse_cluster_migration_state_t;

typedef struct {
    uint16_t slot;
    uint16_t source_index;
    uint16_t target_index;
    qihse_cluster_migration_state_t state;
    uint64_t topology_epoch;
    uint64_t keys_streamed;
    uint64_t bytes_streamed;
} qihse_cluster_migration_status_t;

typedef struct qihse_cluster_migration qihse_cluster_migration_t;

qihse_cluster_migration_t* qihse_cluster_migration_begin(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index);
void qihse_cluster_migration_destroy(qihse_cluster_migration_t* migration);
bool qihse_cluster_migration_mark_streamed(qihse_cluster_migration_t* migration, size_t bytes);
bool qihse_cluster_migration_commit(qihse_cluster_migration_t* migration);
bool qihse_cluster_migration_abort(qihse_cluster_migration_t* migration);
bool qihse_cluster_migration_status(const qihse_cluster_migration_t* migration, qihse_cluster_migration_status_t* out_status);

#ifdef __cplusplus
}
#endif

#endif
