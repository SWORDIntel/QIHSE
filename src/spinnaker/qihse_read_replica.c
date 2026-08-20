#include "qihse_read_replica.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

qihse_read_replica_pool_t* qihse_read_replica_pool_create(void) {
    qihse_read_replica_pool_t* pool = (qihse_read_replica_pool_t*)calloc(1, sizeof(qihse_read_replica_pool_t));
    if (!pool) return NULL;
    pthread_mutex_init(&pool->lock, NULL);
    pool->rr_index = 0;
    return pool;
}

int qihse_read_replica_pool_add(qihse_read_replica_pool_t* pool, const char* host, uint16_t port) {
    if (!pool || !host) return -1;
    pthread_mutex_lock(&pool->lock);
    if (pool->num_replicas >= pool->cap) {
        pool->cap = pool->cap ? pool->cap * 2 : 4;
        pool->replicas = (qihse_replica_node_t*)realloc(pool->replicas, pool->cap * sizeof(qihse_replica_node_t));
    }
    pool->replicas[pool->num_replicas].host = strdup(host);
    pool->replicas[pool->num_replicas].port = port;
    pool->replicas[pool->num_replicas].healthy = 1;
    pool->replicas[pool->num_replicas].last_check = (uint64_t)time(NULL);
    pool->replicas[pool->num_replicas].active_connections = 0;
    pool->num_replicas++;
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

int qihse_read_replica_pool_remove(qihse_read_replica_pool_t* pool, const char* host, uint16_t port) {
    if (!pool || !host) return -1;
    pthread_mutex_lock(&pool->lock);
    for (size_t i = 0; i < pool->num_replicas; i++) {
        if (strcmp(pool->replicas[i].host, host) == 0 && pool->replicas[i].port == port) {
            free(pool->replicas[i].host);
            memmove(&pool->replicas[i], &pool->replicas[i+1], (pool->num_replicas - i - 1) * sizeof(qihse_replica_node_t));
            pool->num_replicas--;
            pthread_mutex_unlock(&pool->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&pool->lock);
    return -1;
}

int qihse_read_replica_route(qihse_read_replica_pool_t* pool, char** out_host, uint16_t* out_port) {
    if (!pool || !out_host || !out_port) return -1;
    pthread_mutex_lock(&pool->lock);
    if (pool->num_replicas == 0) { pthread_mutex_unlock(&pool->lock); return -1; }
    /* Round-robin among healthy replicas */
    for (size_t i = 0; i < pool->num_replicas; i++) {
        size_t idx = (pool->rr_index + i) % pool->num_replicas;
        if (pool->replicas[idx].healthy) {
            *out_host = strdup(pool->replicas[idx].host);
            *out_port = pool->replicas[idx].port;
            pool->rr_index = (idx + 1) % pool->num_replicas;
            pool->replicas[idx].active_connections++;
            pthread_mutex_unlock(&pool->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&pool->lock);
    return -1;
}

int qihse_read_replica_health_check(qihse_read_replica_pool_t* pool) {
    if (!pool) return -1;
    pthread_mutex_lock(&pool->lock);
    int healthy_count = 0;
    for (size_t i = 0; i < pool->num_replicas; i++) {
        /* Try TCP connect */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { pool->replicas[i].healthy = 0; continue; }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(pool->replicas[i].port);
        inet_pton(AF_INET, pool->replicas[i].host, &addr.sin_addr);
        /* Set short timeout */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            pool->replicas[i].healthy = 1;
            healthy_count++;
        } else {
            pool->replicas[i].healthy = 0;
        }
        close(fd);
        pool->replicas[i].last_check = (uint64_t)time(NULL);
    }
    pthread_mutex_unlock(&pool->lock);
    return healthy_count;
}

size_t qihse_read_replica_active_count(qihse_read_replica_pool_t* pool) {
    if (!pool) return 0;
    pthread_mutex_lock(&pool->lock);
    size_t count = 0;
    for (size_t i = 0; i < pool->num_replicas; i++) if (pool->replicas[i].healthy) count++;
    pthread_mutex_unlock(&pool->lock);
    return count;
}

void qihse_read_replica_pool_destroy(qihse_read_replica_pool_t* pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    for (size_t i = 0; i < pool->num_replicas; i++) free(pool->replicas[i].host);
    free(pool->replicas);
    pthread_mutex_unlock(&pool->lock);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}
