#ifndef QIHSE_READ_REPLICA_H
#define QIHSE_READ_REPLICA_H

#include <stdint.h>
#include <pthread.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char* host;
    uint16_t port;
    int healthy;
    uint64_t last_check;
    int active_connections;
} qihse_replica_node_t;

typedef struct {
    qihse_replica_node_t* replicas;
    size_t num_replicas;
    size_t cap;
    pthread_mutex_t lock;
    size_t rr_index;
} qihse_read_replica_pool_t;

qihse_read_replica_pool_t* qihse_read_replica_pool_create(void);
int qihse_read_replica_pool_add(qihse_read_replica_pool_t* pool, const char* host, uint16_t port);
int qihse_read_replica_pool_remove(qihse_read_replica_pool_t* pool, const char* host, uint16_t port);
int qihse_read_replica_route(qihse_read_replica_pool_t* pool, char** out_host, uint16_t* out_port);
int qihse_read_replica_health_check(qihse_read_replica_pool_t* pool);
size_t qihse_read_replica_active_count(qihse_read_replica_pool_t* pool);
void qihse_read_replica_pool_destroy(qihse_read_replica_pool_t* pool);

#ifdef __cplusplus
}
#endif
#endif
