#include "qihse_cluster_migrate.h"
#include "qihse_platform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct qihse_cluster_migration {
    qihse_cluster_topology_t* topology;
    qihse_cluster_migration_status_t status;
    pthread_mutex_t lock;
};

qihse_cluster_migration_t* qihse_cluster_migration_begin(qihse_cluster_topology_t* topology, uint16_t slot, uint16_t source_index, uint16_t target_index) {
    if (!topology || slot >= QIHSE_CLUSTER_SLOT_COUNT || source_index == target_index) {
        errno = EINVAL;
        return NULL;
    }
    uint16_t owner;
    if (!qihse_cluster_topology_get_slot(topology, slot, &owner, NULL, NULL) || owner != source_index) {
        errno = EINVAL;
        return NULL;
    }
    qihse_cluster_migration_t* migration = (qihse_cluster_migration_t*)calloc(1, sizeof(*migration));
    if (!migration) return NULL;
    if (pthread_mutex_init(&migration->lock, NULL) != 0) {
        free(migration);
        errno = ENOMEM;
        return NULL;
    }
    migration->topology = topology;
    migration->status.slot = slot;
    migration->status.source_index = source_index;
    migration->status.target_index = target_index;
    migration->status.state = QIHSE_MIGRATION_PREPARING;
    if (!qihse_cluster_topology_set_migrating(topology, slot, source_index, target_index)) {
        pthread_mutex_destroy(&migration->lock);
        free(migration);
        return NULL;
    }
    migration->status.topology_epoch = qihse_cluster_topology_epoch(topology);
    return migration;
}

void qihse_cluster_migration_destroy(qihse_cluster_migration_t* migration) {
    if (!migration) return;
    pthread_mutex_destroy(&migration->lock);
    free(migration);
}

bool qihse_cluster_migration_mark_streamed(qihse_cluster_migration_t* migration, size_t bytes) {
    if (!migration) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&migration->lock);
    if (migration->status.state == QIHSE_MIGRATION_COMMITTED || migration->status.state == QIHSE_MIGRATION_ABORTED ||
        migration->status.keys_streamed == UINT64_MAX || bytes > UINT64_MAX - migration->status.bytes_streamed) {
        pthread_mutex_unlock(&migration->lock);
        errno = EOVERFLOW;
        return false;
    }
    migration->status.state = QIHSE_MIGRATION_STREAMING;
    migration->status.keys_streamed++;
    migration->status.bytes_streamed += bytes;
    pthread_mutex_unlock(&migration->lock);
    return true;
}

bool qihse_cluster_migration_commit(qihse_cluster_migration_t* migration) {
    if (!migration) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&migration->lock);
    if (migration->status.state == QIHSE_MIGRATION_COMMITTED || migration->status.state == QIHSE_MIGRATION_ABORTED) {
        pthread_mutex_unlock(&migration->lock);
        errno = EALREADY;
        return false;
    }
    if (!qihse_cluster_topology_set_stable(migration->topology, migration->status.slot, migration->status.target_index)) {
        pthread_mutex_unlock(&migration->lock);
        return false;
    }
    migration->status.state = QIHSE_MIGRATION_COMMITTED;
    migration->status.topology_epoch = qihse_cluster_topology_epoch(migration->topology);
    pthread_mutex_unlock(&migration->lock);
    return true;
}

bool qihse_cluster_migration_abort(qihse_cluster_migration_t* migration) {
    if (!migration) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock(&migration->lock);
    if (migration->status.state == QIHSE_MIGRATION_COMMITTED || migration->status.state == QIHSE_MIGRATION_ABORTED) {
        pthread_mutex_unlock(&migration->lock);
        errno = EALREADY;
        return false;
    }
    if (!qihse_cluster_topology_set_stable(migration->topology, migration->status.slot, migration->status.source_index)) {
        pthread_mutex_unlock(&migration->lock);
        return false;
    }
    migration->status.state = QIHSE_MIGRATION_ABORTED;
    migration->status.topology_epoch = qihse_cluster_topology_epoch(migration->topology);
    pthread_mutex_unlock(&migration->lock);
    return true;
}

bool qihse_cluster_migration_status(const qihse_cluster_migration_t* migration, qihse_cluster_migration_status_t* out_status) {
    if (!migration || !out_status) {
        errno = EINVAL;
        return false;
    }
    pthread_mutex_lock((pthread_mutex_t*)&migration->lock);
    *out_status = migration->status;
    pthread_mutex_unlock((pthread_mutex_t*)&migration->lock);
    return true;
}
