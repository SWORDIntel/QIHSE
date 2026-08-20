#include "qihse_pooler.h"

#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
#else
#include <winsock2.h>
#define close(s) closesocket(s)
#endif

/* A pooled backend connection. Backend fds are simulated here as incrementing
 * synthetic ids (real wiring to upstream servers is done by other subsystems). */

typedef struct {
    int backend_fd;
    int in_use;
    int client_fd;
} qihse_pool_entry_t;

struct qihse_pooler_s {
    size_t max_connections;
    size_t max_per_client;
    qihse_pool_entry_t* entries;
    size_t nentries;
#ifndef _WIN32
    pthread_mutex_t lock;
#else
    CRITICAL_SECTION lock;
#endif
    int next_fd;
};

#ifndef _WIN32
#define POOL_LOCK(p) pthread_mutex_lock(&(p)->lock)
#define POOL_UNLOCK(p) pthread_mutex_unlock(&(p)->lock)
#define POOL_INIT(p) pthread_mutex_init(&(p)->lock, NULL)
#define POOL_DESTROY(p) pthread_mutex_destroy(&(p)->lock)
#else
#define POOL_LOCK(p) EnterCriticalSection(&(p)->lock)
#define POOL_UNLOCK(p) LeaveCriticalSection(&(p)->lock)
#define POOL_INIT(p) InitializeCriticalSection(&(p)->lock)
#define POOL_DESTROY(p) DeleteCriticalSection(&(p)->lock)
#endif

qihse_pooler_t* qihse_pooler_create(size_t max_connections, size_t max_per_client) {
    qihse_pooler_t* p = (qihse_pooler_t*)calloc(1, sizeof(qihse_pooler_t));
    if (!p) return NULL;
    p->max_connections = max_connections ? max_connections : 16;
    p->max_per_client = max_per_client ? max_per_client : 4;
    p->entries = (qihse_pool_entry_t*)calloc(p->max_connections, sizeof(qihse_pool_entry_t));
    if (!p->entries) { free(p); return NULL; }
    p->nentries = 0;
    p->next_fd = 1000;
    POOL_INIT(p);
    return p;
}

static int find_idle(qihse_pooler_t* p) {
    for (size_t i = 0; i < p->nentries; i++) {
        if (!p->entries[i].in_use) return (int)i;
    }
    return -1;
}

static int find_by_client(qihse_pooler_t* p, int client_fd) {
    for (size_t i = 0; i < p->nentries; i++) {
        if (p->entries[i].in_use && p->entries[i].client_fd == client_fd) return (int)i;
    }
    return -1;
}

static size_t count_active(qihse_pooler_t* p) {
    size_t c = 0;
    for (size_t i = 0; i < p->nentries; i++) if (p->entries[i].in_use) c++;
    return c;
}

static size_t count_for_client(qihse_pooler_t* p, int client_fd) {
    size_t c = 0;
    for (size_t i = 0; i < p->nentries; i++)
        if (p->entries[i].in_use && p->entries[i].client_fd == client_fd) c++;
    return c;
}

int qihse_pooler_acquire(qihse_pooler_t* pool, int client_fd, int* out_backend_fd) {
    if (!pool || !out_backend_fd) return -1;
    POOL_LOCK(pool);

    /* Enforce per-client limit */
    if (count_for_client(pool, client_fd) >= pool->max_per_client) {
        POOL_UNLOCK(pool);
        return -1;
    }

    int idx = find_idle(pool);
    if (idx < 0) {
        /* No idle connection; create a new one if under cap */
        if (pool->nentries >= pool->max_connections) {
            POOL_UNLOCK(pool);
            return -1;
        }
        idx = (int)pool->nentries++;
        pool->entries[idx].backend_fd = pool->next_fd++;
        pool->entries[idx].in_use = 0;
    }

    pool->entries[idx].in_use = 1;
    pool->entries[idx].client_fd = client_fd;
    *out_backend_fd = pool->entries[idx].backend_fd;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_release(qihse_pooler_t* pool, int client_fd) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    int idx = find_by_client(pool, client_fd);
    if (idx < 0) {
        POOL_UNLOCK(pool);
        return -1;
    }
    pool->entries[idx].in_use = 0;
    pool->entries[idx].client_fd = -1;
    POOL_UNLOCK(pool);
    return 0;
}

size_t qihse_pooler_active_count(qihse_pooler_t* pool) {
    if (!pool) return 0;
    POOL_LOCK(pool);
    size_t c = count_active(pool);
    POOL_UNLOCK(pool);
    return c;
}

size_t qihse_pooler_idle_count(qihse_pooler_t* pool) {
    if (!pool) return 0;
    POOL_LOCK(pool);
    size_t c = pool->nentries - count_active(pool);
    POOL_UNLOCK(pool);
    return c;
}

void qihse_pooler_destroy(qihse_pooler_t* pool) {
    if (!pool) return;
    /* In a real pooler we would close(real_fd); the synthetic fds here are
     * not real sockets so we just free the table. */
    free(pool->entries);
    POOL_DESTROY(pool);
    free(pool);
}

/* ---- Enhanced pooler implementation ---- */

typedef struct {
    pool_mode_t mode;
    size_t max_connections;
    size_t max_per_client;
    size_t idle_timeout_ms;
    size_t connect_timeout_ms;
    int health_check_interval;
    qihse_pool_backend_t* backends;
    size_t num_backends;
    size_t backends_cap;
    size_t wait_count;
} pooler_enhanced_t;

/* Access the internal structure - the base pooler is qihse_pooler_s */
/* We store enhanced config in a side structure attached via a global */
static pooler_enhanced_t* get_enhanced(qihse_pooler_t* pool) {
    /* For simplicity, we use a static map. In production, this would be a field in the pooler. */
    static qihse_pooler_t* last_pool = NULL;
    static pooler_enhanced_t* enh = NULL;
    if (pool != last_pool) {
        if (enh) free(enh);
        enh = (pooler_enhanced_t*)calloc(1, sizeof(pooler_enhanced_t));
        enh->mode = POOL_SESSION;
        enh->max_connections = 100;
        enh->max_per_client = 10;
        enh->idle_timeout_ms = 30000;
        enh->connect_timeout_ms = 5000;
        enh->health_check_interval = 30;
        last_pool = pool;
    }
    return enh;
}

qihse_pooler_t* qihse_pooler_create_ex(const qihse_pooler_config_t* config) {
    if (!config) return qihse_pooler_create(100, 10);
    qihse_pooler_t* pool = qihse_pooler_create(config->max_connections, config->max_per_client);
    if (!pool) return NULL;
    pooler_enhanced_t* enh = get_enhanced(pool);
    enh->mode = config->mode;
    enh->max_connections = config->max_connections;
    enh->max_per_client = config->max_per_client;
    enh->idle_timeout_ms = config->idle_timeout_ms;
    enh->connect_timeout_ms = config->connect_timeout_ms;
    enh->health_check_interval = config->health_check_interval;
    return pool;
}

int qihse_pooler_set_mode(qihse_pooler_t* pool, pool_mode_t mode) {
    if (!pool) return -1;
    pooler_enhanced_t* enh = get_enhanced(pool);
    enh->mode = mode;
    return 0;
}

int qihse_pooler_health_check(qihse_pooler_t* pool) {
    if (!pool) return -1;
    pooler_enhanced_t* enh = get_enhanced(pool);
    int healthy = 0;
    for (size_t i = 0; i < enh->num_backends; i++) {
        /* Simple health check: just mark as healthy if fd is valid */
        if (enh->backends[i].fd >= 0) {
            enh->backends[i].healthy = 1;
            healthy++;
        } else {
            enh->backends[i].healthy = 0;
        }
    }
    return healthy;
}

size_t qihse_pooler_wait_count(qihse_pooler_t* pool) {
    if (!pool) return 0;
    pooler_enhanced_t* enh = get_enhanced(pool);
    return enh->wait_count;
}

int qihse_pooler_add_backend(qihse_pooler_t* pool, const char* host, uint16_t port) {
    if (!pool || !host) return -1;
    pooler_enhanced_t* enh = get_enhanced(pool);
    if (enh->num_backends >= enh->backends_cap) {
        enh->backends_cap = enh->backends_cap ? enh->backends_cap * 2 : 4;
        enh->backends = (qihse_pool_backend_t*)realloc(enh->backends, enh->backends_cap * sizeof(qihse_pool_backend_t));
    }
    enh->backends[enh->num_backends].fd = -1;
    enh->backends[enh->num_backends].host = strdup(host);
    enh->backends[enh->num_backends].port = port;
    enh->backends[enh->num_backends].in_use = 0;
    enh->backends[enh->num_backends].last_used = 0;
    enh->backends[enh->num_backends].healthy = 1;
    enh->num_backends++;
    return 0;
}

int qihse_pooler_remove_backend(qihse_pooler_t* pool, const char* host, uint16_t port) {
    if (!pool || !host) return -1;
    pooler_enhanced_t* enh = get_enhanced(pool);
    for (size_t i = 0; i < enh->num_backends; i++) {
        if (strcmp(enh->backends[i].host, host) == 0 && enh->backends[i].port == port) {
            free(enh->backends[i].host);
            if (enh->backends[i].fd >= 0) close(enh->backends[i].fd);
            memmove(&enh->backends[i], &enh->backends[i+1], (enh->num_backends - i - 1) * sizeof(qihse_pool_backend_t));
            enh->num_backends--;
            return 0;
        }
    }
    return -1;
}

size_t qihse_pooler_backend_count(qihse_pooler_t* pool) {
    if (!pool) return 0;
    pooler_enhanced_t* enh = get_enhanced(pool);
    return enh->num_backends;
}
