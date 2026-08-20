#ifndef QIHSE_POOLER_H
#define QIHSE_POOLER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_pooler_s qihse_pooler_t;

/**
 * @brief Create a new connection pooler.
 * @param max_connections Maximum total backend connections.
 * @param max_per_client Maximum concurrent connections per client.
 */
qihse_pooler_t* qihse_pooler_create(size_t max_connections, size_t max_per_client);

/**
 * @brief Acquire a pooled backend connection for a client.
 * @param pool The pooler.
 * @param client_fd The client file descriptor requesting the connection.
 * @param out_backend_fd Receives the backend file descriptor.
 * @return 0 on success, -1 on failure.
 */
int qihse_pooler_acquire(qihse_pooler_t* pool, int client_fd, int* out_backend_fd);

/**
 * @brief Release a backend connection back to the pool.
 * @param pool The pooler.
 * @param client_fd The client releasing its connection.
 * @return 0 on success, -1 if the client had no active connection.
 */
int qihse_pooler_release(qihse_pooler_t* pool, int client_fd);

/**
 * @brief Number of currently checked-out (active) connections.
 */
size_t qihse_pooler_active_count(qihse_pooler_t* pool);

/**
 * @brief Number of idle connections available in the pool.
 */
size_t qihse_pooler_idle_count(qihse_pooler_t* pool);

/**
 * @brief Destroy the pooler and close all backend connections.
 */
void qihse_pooler_destroy(qihse_pooler_t* pool);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_POOLER_H */

/* ---- Enhanced pooler API ---- */

typedef enum {
    POOL_SESSION = 0,
    POOL_TRANSACTION = 1,
    POOL_STATEMENT = 2
} pool_mode_t;

typedef struct {
    pool_mode_t mode;
    size_t max_connections;
    size_t max_per_client;
    size_t idle_timeout_ms;
    size_t connect_timeout_ms;
    int health_check_interval;
} qihse_pooler_config_t;

typedef struct {
    int fd;
    char* host;
    uint16_t port;
    int in_use;
    uint64_t last_used;
    int healthy;
} qihse_pool_backend_t;

qihse_pooler_t* qihse_pooler_create_ex(const qihse_pooler_config_t* config);
int qihse_pooler_set_mode(qihse_pooler_t* pool, pool_mode_t mode);
int qihse_pooler_health_check(qihse_pooler_t* pool);
size_t qihse_pooler_wait_count(qihse_pooler_t* pool);
int qihse_pooler_add_backend(qihse_pooler_t* pool, const char* host, uint16_t port);
int qihse_pooler_remove_backend(qihse_pooler_t* pool, const char* host, uint16_t port);
size_t qihse_pooler_backend_count(qihse_pooler_t* pool);
