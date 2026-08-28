#include "qihse_pooler.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
#else
#include <winsock2.h>
#define close(s) closesocket(s)
#endif

/* ================================================================== */
/* Internal data structures                                            */
/* ================================================================== */

/* A pooled backend connection. Backend fds are simulated here as
 * incrementing synthetic ids (real wiring to upstream servers is done
 * by other subsystems). */
typedef struct {
    int backend_fd;
    int in_use;
    int client_fd;
} qihse_pool_entry_t;

/* Enhanced pooler state - now embedded directly in the pooler struct
 * (replaces the previous static-singleton hack which only tracked one
 * pool per process). */
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

struct qihse_pooler_s {
    /* base pool */
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

    /* enhanced / pgbouncer state */
    pooler_enhanced_t enh;
    qihse_pooler_config_t config;
    pool_mode_t pool_mode;

    /* databases / users */
    qihse_database_t* databases;
    size_t num_databases;
    size_t databases_cap;
    qihse_pooler_user_t* users;
    size_t num_users;
    size_t users_cap;

    /* client / server connection registries */
    qihse_client_info_t* clients;
    size_t num_clients;
    size_t clients_cap;
    qihse_server_info_t* servers;
    size_t num_servers;
    size_t servers_cap;

    /* global control state */
    int paused;       /*!< global pause (PAUSE with no db) */
    int suspended;    /*!< SUSPEND */
    int shutting_down;

    /* global statistics */
    uint64_t total_xact_count;
    uint64_t total_query_count;
    uint64_t total_received;
    uint64_t total_sent;
    uint64_t total_xact_time;
    uint64_t total_query_time;
    uint64_t total_wait_time;
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

#define QIHSE_POOLER_VERSION "1.0.0-qihse"

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

static pooler_enhanced_t* get_enhanced(qihse_pooler_t* pool) {
    return &pool->enh;
}

static char* dup_str(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* r = (char*)malloc(n);
    if (r) memcpy(r, s, n);
    return r;
}

static int ci_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

/* skip leading whitespace, return pointer to first non-ws char */
static const char* skip_ws(const char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* ================================================================== */
/* Dynamic text buffer for admin output                                */
/* ================================================================== */

typedef struct {
    char* buf;
    size_t len;
    size_t cap;
} textbuf_t;

static int tb_reserve(textbuf_t* t, size_t extra) {
    if (t->len + extra + 1 > t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 256;
        while (ncap < t->len + extra + 1) ncap *= 2;
        char* nb = (char*)realloc(t->buf, ncap);
        if (!nb) return -1;
        t->buf = nb;
        t->cap = ncap;
    }
    return 0;
}

static void tb_put(textbuf_t* t, const char* s) {
    size_t n = strlen(s);
    if (tb_reserve(t, n) == 0) {
        memcpy(t->buf + t->len, s, n);
        t->len += n;
        t->buf[t->len] = 0;
    }
}

static void tb_printf(textbuf_t* t, const char* fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) tb_put(t, tmp);
}

/* ================================================================== */
/* Base pooler API (unchanged behaviour)                               */
/* ================================================================== */

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

    /* initialise enhanced defaults */
    pooler_enhanced_t* e = get_enhanced(p);
    e->mode = POOL_SESSION;
    e->max_connections = p->max_connections;
    e->max_per_client = p->max_per_client;
    e->idle_timeout_ms = 30000;
    e->connect_timeout_ms = 5000;
    e->health_check_interval = 30;
    p->pool_mode = POOL_SESSION;
    qihse_pooler_config_defaults(&p->config);
    p->config.max_connections = p->max_connections;
    p->config.max_per_client = p->max_per_client;
    p->config.mode = POOL_SESSION;
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

    if (pool->paused || pool->suspended) {
        pool->enh.wait_count++;
        POOL_UNLOCK(pool);
        return -1;
    }

    /* Enforce per-client limit */
    if (count_for_client(pool, client_fd) >= pool->max_per_client) {
        POOL_UNLOCK(pool);
        return -1;
    }

    int idx = find_idle(pool);
    if (idx < 0) {
        /* No idle connection; create a new one if under cap */
        if (pool->nentries >= pool->max_connections) {
            pool->enh.wait_count++;
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
    if (pool->enh.wait_count > 0) pool->enh.wait_count--;
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
    free(pool->entries);

    /* enhanced backends */
    for (size_t i = 0; i < pool->enh.num_backends; i++) {
        free(pool->enh.backends[i].host);
        if (pool->enh.backends[i].fd >= 0) close(pool->enh.backends[i].fd);
    }
    free(pool->enh.backends);

    /* databases */
    for (size_t i = 0; i < pool->num_databases; i++) {
        free(pool->databases[i].name);
        free(pool->databases[i].host);
    }
    free(pool->databases);

    /* users */
    for (size_t i = 0; i < pool->num_users; i++) {
        free(pool->users[i].username);
        free(pool->users[i].password);
    }
    free(pool->users);

    /* clients */
    for (size_t i = 0; i < pool->num_clients; i++) {
        free(pool->clients[i].user);
        free(pool->clients[i].database);
    }
    free(pool->clients);

    /* servers */
    for (size_t i = 0; i < pool->num_servers; i++) {
        free(pool->servers[i].user);
        free(pool->servers[i].database);
    }
    free(pool->servers);

    POOL_DESTROY(pool);
    free(pool);
}

/* ================================================================== */
/* Enhanced pooler API                                                 */
/* ================================================================== */

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
    pool->pool_mode = config->mode;
    pool->config = *config;
    return pool;
}

int qihse_pooler_set_mode(qihse_pooler_t* pool, pool_mode_t mode) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    pooler_enhanced_t* enh = get_enhanced(pool);
    enh->mode = mode;
    pool->pool_mode = mode;
    pool->config.mode = mode;
    pool->config.pool_mode = mode;
    POOL_UNLOCK(pool);
    return 0;
}

pool_mode_t qihse_pooler_get_mode(qihse_pooler_t* pool) {
    if (!pool) return POOL_SESSION;
    return pool->pool_mode;
}

const char* qihse_pooler_mode_str(pool_mode_t mode) {
    switch (mode) {
        case POOL_SESSION: return "session";
        case POOL_TRANSACTION: return "transaction";
        case POOL_STATEMENT: return "statement";
        default: return "unknown";
    }
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

/* ================================================================== */
/* Configuration                                                       */
/* ================================================================== */

void qihse_pooler_config_defaults(qihse_pooler_config_t* config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    config->mode = POOL_SESSION;
    config->pool_mode = POOL_SESSION;
    config->max_client_conn = 100;
    config->default_pool_size = 20;
    config->reserve_pool_size = 0;
    config->reserve_pool_timeout = 5;
    config->max_db_connections = 0;
    config->max_user_connections = 0;
    config->server_lifetime = 3600;
    config->server_idle_timeout = 600;
    config->server_connect_timeout = 15;
    config->server_login_retry = 15;
    config->query_timeout = 0;
    config->query_wait_timeout = 120;
    config->client_idle_timeout = 0;
    config->client_login_timeout = 60;
    config->keepalive = 1;
    config->tcp_keepalive = 1;
    config->tcp_keepcnt = 0;
    config->tcp_keepidle = 0;
    config->tcp_keepintvl = 0;
    config->tcp_user_timeout = 0;
    config->verbose = 0;
    config->log_connections = 1;
    config->log_disconnections = 1;
    config->log_pooler_errors = 1;
    config->stats_period = 60;
    config->auth_type = QIHSE_AUTH_TRUST;
    /* legacy compat defaults */
    config->max_connections = config->max_client_conn;
    config->max_per_client = config->default_pool_size;
    config->idle_timeout_ms = config->server_idle_timeout * 1000;
    config->connect_timeout_ms = config->server_connect_timeout * 1000;
    config->health_check_interval = 30;
}

int qihse_pooler_apply_config(qihse_pooler_t* pool, const qihse_pooler_config_t* config) {
    if (!pool || !config) return -1;
    POOL_LOCK(pool);
    pool->config = *config;
    pool->pool_mode = config->pool_mode ? config->pool_mode : config->mode;
    pool->enh.mode = pool->pool_mode;
    /* mirror legacy caps where provided */
    if (config->max_connections) {
        pool->max_connections = config->max_connections;
        pool->enh.max_connections = config->max_connections;
    }
    if (config->max_per_client) {
        pool->max_per_client = config->max_per_client;
        pool->enh.max_per_client = config->max_per_client;
    }
    POOL_UNLOCK(pool);
    return 0;
}

const qihse_pooler_config_t* qihse_pooler_get_config(qihse_pooler_t* pool) {
    if (!pool) return NULL;
    return &pool->config;
}

/* ================================================================== */
/* Database / user management                                          */
/* ================================================================== */

int qihse_pooler_add_database(qihse_pooler_t* pool, const char* name, const char* host, uint16_t port) {
    if (!pool || !name) return -1;
    POOL_LOCK(pool);
    if (pool->num_databases >= pool->databases_cap) {
        size_t ncap = pool->databases_cap ? pool->databases_cap * 2 : 8;
        qihse_database_t* nd = (qihse_database_t*)realloc(pool->databases, ncap * sizeof(qihse_database_t));
        if (!nd) { POOL_UNLOCK(pool); return -1; }
        pool->databases = nd;
        pool->databases_cap = ncap;
    }
    qihse_database_t* db = &pool->databases[pool->num_databases++];
    memset(db, 0, sizeof(*db));
    db->name = dup_str(name);
    db->host = dup_str(host);
    db->port = port;
    db->pool_mode = pool->pool_mode;
    db->max_connections = pool->config.default_pool_size;
    POOL_UNLOCK(pool);
    return 0;
}

qihse_database_t* qihse_pooler_find_database(qihse_pooler_t* pool, const char* name) {
    if (!pool || !name) return NULL;
    for (size_t i = 0; i < pool->num_databases; i++) {
        if (strcmp(pool->databases[i].name, name) == 0) return &pool->databases[i];
    }
    return NULL;
}

size_t qihse_pooler_database_count(qihse_pooler_t* pool) {
    return pool ? pool->num_databases : 0;
}

int qihse_pooler_add_user(qihse_pooler_t* pool, const char* username, const char* password) {
    if (!pool || !username) return -1;
    POOL_LOCK(pool);
    /* update existing */
    for (size_t i = 0; i < pool->num_users; i++) {
        if (strcmp(pool->users[i].username, username) == 0) {
            free(pool->users[i].password);
            pool->users[i].password = dup_str(password);
            POOL_UNLOCK(pool);
            return 0;
        }
    }
    if (pool->num_users >= pool->users_cap) {
        size_t ncap = pool->users_cap ? pool->users_cap * 2 : 8;
        qihse_pooler_user_t* nu = (qihse_pooler_user_t*)realloc(pool->users, ncap * sizeof(qihse_pooler_user_t));
        if (!nu) { POOL_UNLOCK(pool); return -1; }
        pool->users = nu;
        pool->users_cap = ncap;
    }
    qihse_pooler_user_t* u = &pool->users[pool->num_users++];
    memset(u, 0, sizeof(*u));
    u->username = dup_str(username);
    u->password = dup_str(password);
    POOL_UNLOCK(pool);
    return 0;
}

qihse_pooler_user_t* qihse_pooler_find_user(qihse_pooler_t* pool, const char* username) {
    if (!pool || !username) return NULL;
    for (size_t i = 0; i < pool->num_users; i++) {
        if (strcmp(pool->users[i].username, username) == 0) return &pool->users[i];
    }
    return NULL;
}

size_t qihse_pooler_user_count(qihse_pooler_t* pool) {
    return pool ? pool->num_users : 0;
}

/* ================================================================== */
/* Auth file parsing (userlist.txt format)                             */
/*   "username" "password"                                            */
/* ================================================================== */

static int parse_quoted(const char** p, char* out, size_t outsz) {
    const char* s = skip_ws(*p);
    if (*s != '"') return -1;
    s++;
    size_t i = 0;
    while (*s && *s != '"' && i + 1 < outsz) {
        out[i++] = *s++;
    }
    if (*s != '"') return -1;
    out[i] = 0;
    s++;
    *p = s;
    return 0;
}

int qihse_pooler_load_auth_file(qihse_pooler_t* pool, const char* path) {
    if (!pool || !path) return -1;
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        const char* p = skip_ws(line);
        if (*p == 0 || *p == '#' || *p == ';') continue;
        char user[256];
        char pass[256];
        if (parse_quoted(&p, user, sizeof(user)) != 0) continue;
        if (parse_quoted(&p, pass, sizeof(pass)) != 0) {
            pass[0] = 0;
        }
        if (qihse_pooler_add_user(pool, user, pass) == 0) count++;
    }
    fclose(f);
    return count;
}

/* ================================================================== */
/* Client / server connection registration                             */
/* ================================================================== */

int qihse_pooler_register_client(qihse_pooler_t* pool, const qihse_client_info_t* info) {
    if (!pool || !info) return -1;
    POOL_LOCK(pool);
    if (pool->num_clients >= pool->clients_cap) {
        size_t ncap = pool->clients_cap ? pool->clients_cap * 2 : 16;
        qihse_client_info_t* nc = (qihse_client_info_t*)realloc(pool->clients, ncap * sizeof(qihse_client_info_t));
        if (!nc) { POOL_UNLOCK(pool); return -1; }
        pool->clients = nc;
        pool->clients_cap = ncap;
    }
    qihse_client_info_t* c = &pool->clients[pool->num_clients++];
    *c = *info;
    c->user = dup_str(info->user);
    c->database = dup_str(info->database);
    c->ptr = NULL;
    c->link = NULL;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_unregister_client(qihse_pooler_t* pool, int fd) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    for (size_t i = 0; i < pool->num_clients; i++) {
        if (pool->clients[i].fd == fd) {
            free(pool->clients[i].user);
            free(pool->clients[i].database);
            memmove(&pool->clients[i], &pool->clients[i+1], (pool->num_clients - i - 1) * sizeof(qihse_client_info_t));
            pool->num_clients--;
            POOL_UNLOCK(pool);
            return 0;
        }
    }
    POOL_UNLOCK(pool);
    return -1;
}

int qihse_pooler_register_server(qihse_pooler_t* pool, const qihse_server_info_t* info) {
    if (!pool || !info) return -1;
    POOL_LOCK(pool);
    if (pool->num_servers >= pool->servers_cap) {
        size_t ncap = pool->servers_cap ? pool->servers_cap * 2 : 16;
        qihse_server_info_t* ns = (qihse_server_info_t*)realloc(pool->servers, ncap * sizeof(qihse_server_info_t));
        if (!ns) { POOL_UNLOCK(pool); return -1; }
        pool->servers = ns;
        pool->servers_cap = ncap;
    }
    qihse_server_info_t* s = &pool->servers[pool->num_servers++];
    *s = *info;
    s->user = dup_str(info->user);
    s->database = dup_str(info->database);
    s->ptr = NULL;
    s->link = NULL;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_unregister_server(qihse_pooler_t* pool, int fd) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    for (size_t i = 0; i < pool->num_servers; i++) {
        if (pool->servers[i].fd == fd) {
            free(pool->servers[i].user);
            free(pool->servers[i].database);
            memmove(&pool->servers[i], &pool->servers[i+1], (pool->num_servers - i - 1) * sizeof(qihse_server_info_t));
            pool->num_servers--;
            POOL_UNLOCK(pool);
            return 0;
        }
    }
    POOL_UNLOCK(pool);
    return -1;
}

/* ================================================================== */
/* Statistics                                                          */
/* ================================================================== */

void qihse_pooler_record_xact(qihse_pooler_t* pool, const char* database, const char* user, uint64_t duration_us) {
    if (!pool) return;
    POOL_LOCK(pool);
    pool->total_xact_count++;
    pool->total_xact_time += duration_us;
    if (database) {
        qihse_database_t* db = qihse_pooler_find_database(pool, database);
        if (db) {
            db->total_xact_count++;
            db->total_xact_time += duration_us;
        }
    }
    if (user) {
        qihse_pooler_user_t* u = qihse_pooler_find_user(pool, user);
        if (u) {
            u->total_xact_count++;
            u->total_xact_time += duration_us;
        }
    }
    POOL_UNLOCK(pool);
}

void qihse_pooler_record_query(qihse_pooler_t* pool, const char* database, const char* user,
                               uint64_t duration_us, uint64_t bytes_recv, uint64_t bytes_sent) {
    if (!pool) return;
    POOL_LOCK(pool);
    pool->total_query_count++;
    pool->total_query_time += duration_us;
    pool->total_received += bytes_recv;
    pool->total_sent += bytes_sent;
    if (database) {
        qihse_database_t* db = qihse_pooler_find_database(pool, database);
        if (db) {
            db->total_query_count++;
            db->total_query_time += duration_us;
            db->total_received += bytes_recv;
            db->total_sent += bytes_sent;
        }
    }
    if (user) {
        qihse_pooler_user_t* u = qihse_pooler_find_user(pool, user);
        if (u) {
            u->total_query_count++;
            u->total_query_time += duration_us;
            u->total_received += bytes_recv;
            u->total_sent += bytes_sent;
        }
    }
    POOL_UNLOCK(pool);
}

void qihse_pooler_record_wait(qihse_pooler_t* pool, const char* database, const char* user, uint64_t wait_us) {
    if (!pool) return;
    POOL_LOCK(pool);
    pool->total_wait_time += wait_us;
    if (database) {
        qihse_database_t* db = qihse_pooler_find_database(pool, database);
        if (db) {
            db->total_wait_time += wait_us;
            if (wait_us > db->maxwait_us) db->maxwait_us = wait_us;
        }
    }
    if (user) {
        qihse_pooler_user_t* u = qihse_pooler_find_user(pool, user);
        if (u) u->total_wait_time += wait_us;
    }
    POOL_UNLOCK(pool);
}

/* ================================================================== */
/* Control commands                                                    */
/* ================================================================== */

int qihse_pooler_pause(qihse_pooler_t* pool, const char* db) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    if (db) {
        qihse_database_t* d = qihse_pooler_find_database(pool, db);
        if (!d) { POOL_UNLOCK(pool); return -1; }
        d->paused = 1;
    } else {
        pool->paused = 1;
    }
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_resume(qihse_pooler_t* pool, const char* db) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    if (db) {
        qihse_database_t* d = qihse_pooler_find_database(pool, db);
        if (!d) { POOL_UNLOCK(pool); return -1; }
        d->paused = 0;
    } else {
        pool->paused = 0;
        pool->suspended = 0;
    }
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_disable_db(qihse_pooler_t* pool, const char* db) {
    if (!pool || !db) return -1;
    POOL_LOCK(pool);
    qihse_database_t* d = qihse_pooler_find_database(pool, db);
    if (!d) { POOL_UNLOCK(pool); return -1; }
    d->disabled = 1;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_enable_db(qihse_pooler_t* pool, const char* db) {
    if (!pool || !db) return -1;
    POOL_LOCK(pool);
    qihse_database_t* d = qihse_pooler_find_database(pool, db);
    if (!d) { POOL_UNLOCK(pool); return -1; }
    d->disabled = 0;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_reconnect(qihse_pooler_t* pool, const char* db) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    /* Mark all server connections for the database (or all if no db) for
     * reconnect by closing their synthetic fds and resetting state. */
    for (size_t i = 0; i < pool->num_servers; i++) {
        if (!db || (pool->servers[i].database && strcmp(pool->servers[i].database, db) == 0)) {
            pool->servers[i].close_needed = 1;
        }
    }
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_kill_db(qihse_pooler_t* pool, const char* db) {
    if (!pool || !db) return -1;
    POOL_LOCK(pool);
    size_t kept = 0;
    for (size_t i = 0; i < pool->num_servers; i++) {
        if (pool->servers[i].database && strcmp(pool->servers[i].database, db) == 0) {
            free(pool->servers[i].user);
            free(pool->servers[i].database);
            if (pool->servers[i].fd >= 0) close(pool->servers[i].fd);
            continue;
        }
        if (kept != i) pool->servers[kept] = pool->servers[i];
        kept++;
    }
    pool->num_servers = kept;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_suspend(qihse_pooler_t* pool) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    pool->suspended = 1;
    pool->paused = 1;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_shutdown(qihse_pooler_t* pool) {
    if (!pool) return -1;
    POOL_LOCK(pool);
    pool->shutting_down = 1;
    pool->suspended = 1;
    pool->paused = 1;
    POOL_UNLOCK(pool);
    return 0;
}

int qihse_pooler_reload(qihse_pooler_t* pool) {
    if (!pool) return -1;
    /* In a real pooler this re-reads the config file. Here we just mark
     * the request as accepted; the caller is responsible for re-applying
     * the config via qihse_pooler_apply_config(). */
    return 0;
}

int qihse_pooler_wait_db(qihse_pooler_t* pool, const char* db) {
    if (!pool || !db) return -1;
    /* Non-blocking check: return 0 if the database has no active server
     * connections, -1 otherwise (caller should retry). */
    POOL_LOCK(pool);
    int active = 0;
    for (size_t i = 0; i < pool->num_servers; i++) {
        if (pool->servers[i].database && strcmp(pool->servers[i].database, db) == 0 &&
            pool->servers[i].state == SV_STATE_ACTIVE) {
            active++;
        }
    }
    POOL_UNLOCK(pool);
    return active == 0 ? 0 : -1;
}

/* ================================================================== */
/* Admin command parsing                                               */
/* ================================================================== */

static qihse_admin_cmd_t match_show(const char* rest) {
    if (ci_eq(rest, "DATABASES")) return QIHSE_ADMIN_SHOW_DATABASES;
    if (ci_eq(rest, "LISTS")) return QIHSE_ADMIN_SHOW_LISTS;
    if (ci_eq(rest, "POOLS")) return QIHSE_ADMIN_SHOW_POOLS;
    if (ci_eq(rest, "CLIENTS")) return QIHSE_ADMIN_SHOW_CLIENTS;
    if (ci_eq(rest, "SERVERS")) return QIHSE_ADMIN_SHOW_SERVERS;
    if (ci_eq(rest, "USERS")) return QIHSE_ADMIN_SHOW_USERS;
    if (ci_eq(rest, "STATS")) return QIHSE_ADMIN_SHOW_STATS;
    if (ci_eq(rest, "STATS_TOTALS") || ci_eq(rest, "STATS_AVERAGES") || ci_eq(rest, "TOTALS")) return QIHSE_ADMIN_SHOW_STATS;
    if (ci_eq(rest, "VERSION")) return QIHSE_ADMIN_SHOW_VERSION;
    if (ci_eq(rest, "CONFIG")) return QIHSE_ADMIN_SHOW_CONFIG;
    if (ci_eq(rest, "FDS")) return QIHSE_ADMIN_SHOW_FDS;
    if (ci_eq(rest, "SOCKETS")) return QIHSE_ADMIN_SHOW_SOCKETS;
    if (ci_eq(rest, "ACTIVE_SOCKETS")) return QIHSE_ADMIN_SHOW_ACTIVE_SOCKETS;
    if (ci_eq(rest, "MEM")) return QIHSE_ADMIN_SHOW_MEM;
    if (ci_eq(rest, "PEERS")) return QIHSE_ADMIN_SHOW_PEERS;
    if (ci_eq(rest, "PEER_POOLS")) return QIHSE_ADMIN_SHOW_PEER_POOLS;
    return QIHSE_ADMIN_UNKNOWN;
}

int qihse_pooler_parse_admin(const char* command, qihse_admin_cmd_t* out_cmd, char* out_arg, size_t arg_len) {
    if (out_cmd) *out_cmd = QIHSE_ADMIN_UNKNOWN;
    if (out_arg && arg_len) out_arg[0] = 0;
    if (!command) return -1;

    const char* p = skip_ws(command);

    /* strip trailing semicolon / whitespace */
    char work[256];
    size_t n = 0;
    while (*p && n + 1 < sizeof(work) && *p != ';') work[n++] = *p++;
    while (n > 0 && isspace((unsigned char)work[n-1])) n--;
    work[n] = 0;

    /* split first token */
    char* w = work;
    char* sp = strchr(w, ' ');
    char* arg = NULL;
    if (sp) { *sp = 0; arg = sp + 1; while (*arg && isspace((unsigned char)*arg)) arg++; }
    if (!arg) arg = (char*)"";

    qihse_admin_cmd_t cmd = QIHSE_ADMIN_UNKNOWN;
    if (ci_eq(w, "SHOW")) {
        cmd = match_show(arg);
    } else if (ci_eq(w, "PAUSE")) {
        cmd = QIHSE_ADMIN_PAUSE;
    } else if (ci_eq(w, "RESUME")) {
        cmd = QIHSE_ADMIN_RESUME;
    } else if (ci_eq(w, "DISABLE")) {
        cmd = QIHSE_ADMIN_DISABLE;
    } else if (ci_eq(w, "ENABLE")) {
        cmd = QIHSE_ADMIN_ENABLE;
    } else if (ci_eq(w, "RECONNECT")) {
        cmd = QIHSE_ADMIN_RECONNECT;
    } else if (ci_eq(w, "KILL")) {
        cmd = QIHSE_ADMIN_KILL;
    } else if (ci_eq(w, "SUSPEND")) {
        cmd = QIHSE_ADMIN_SUSPEND;
    } else if (ci_eq(w, "SHUTDOWN")) {
        cmd = QIHSE_ADMIN_SHUTDOWN;
    } else if (ci_eq(w, "RELOAD")) {
        cmd = QIHSE_ADMIN_RELOAD;
    } else if (ci_eq(w, "WAIT")) {
        cmd = QIHSE_ADMIN_WAIT;
    }

    if (cmd == QIHSE_ADMIN_UNKNOWN) return -1;
    if (out_cmd) *out_cmd = cmd;
    if (out_arg && arg_len) {
        strncpy(out_arg, arg, arg_len - 1);
        out_arg[arg_len - 1] = 0;
    }
    return 0;
}

/* ================================================================== */
/* Admin SHOW renderers                                                */
/* ================================================================== */

static const char* cl_state_str(qihse_client_state_t s) {
    switch (s) {
        case CL_STATE_ACTIVE: return "active";
        case CL_STATE_WAITING: return "waiting";
        case CL_STATE_IDLE: return "idle";
        case CL_STATE_CLOSED: return "closed";
        default: return "?";
    }
}

static const char* sv_state_str(qihse_server_state_t s) {
    switch (s) {
        case SV_STATE_ACTIVE: return "active";
        case SV_STATE_IDLE: return "idle";
        case SV_STATE_USED: return "used";
        case SV_STATE_TESTED: return "tested";
        case SV_STATE_LOGIN: return "login";
        case SV_STATE_CLOSED: return "closed";
        default: return "?";
    }
}

static const char* auth_type_str(qihse_auth_type_t a) {
    switch (a) {
        case QIHSE_AUTH_ANY: return "any";
        case QIHSE_AUTH_TRUST: return "trust";
        case QIHSE_AUTH_PASSWORD: return "password";
        case QIHSE_AUTH_MD5: return "md5";
        case QIHSE_AUTH_SCRAM_SHA256: return "scram-sha-256";
        case QIHSE_AUTH_CERT: return "cert";
        case QIHSE_AUTH_HBA: return "hba";
        default: return "?";
    }
}

static void show_databases(qihse_pooler_t* pool, textbuf_t* t) {
    tb_put(t, "  name  | host | port | disabled | paused | pool_mode\n");
    tb_put(t, "--------+------+------+----------+--------+----------\n");
    for (size_t i = 0; i < pool->num_databases; i++) {
        qihse_database_t* d = &pool->databases[i];
        tb_printf(t, "%s | %s | %u | %s | %s | %s\n",
                  d->name, d->host ? d->host : "", (unsigned)d->port,
                  d->disabled ? "yes" : "no",
                  d->paused ? "yes" : "no",
                  qihse_pooler_mode_str(d->pool_mode));
    }
    if (pool->num_databases == 0) tb_put(t, "(none)\n");
}

static void show_pools(qihse_pooler_t* pool, textbuf_t* t) {
    tb_put(t, " database | user | cl_active | cl_waiting | sv_active | sv_idle | sv_used | sv_tested | sv_login | maxwait | maxwait_us | pool_mode\n");
    for (size_t i = 0; i < pool->num_databases; i++) {
        qihse_database_t* d = &pool->databases[i];
        /* refresh live counters from the base pool when no explicit tracking */
        tb_printf(t, " %s | pgbouncer | %zu | %zu | %zu | %zu | %zu | %zu | %zu | 0 | %llu | %s\n",
                  d->name, d->cl_active, d->cl_waiting, d->sv_active, d->sv_idle,
                  d->sv_used, d->sv_tested, d->sv_login,
                  (unsigned long long)d->maxwait_us,
                  qihse_pooler_mode_str(d->pool_mode));
    }
    if (pool->num_databases == 0) tb_put(t, "(none)\n");
}

static void show_lists(qihse_pooler_t* pool, textbuf_t* t) {
    /* called with lock already held; use internal non-locking counters */
    size_t active = count_active(pool);
    size_t idle = pool->nentries - active;
    tb_printf(t, " databases        | %zu\n", pool->num_databases);
    tb_printf(t, " users            | %zu\n", pool->num_users);
    tb_printf(t, " clients          | %zu\n", pool->num_clients);
    tb_printf(t, " servers          | %zu\n", pool->num_servers);
    tb_printf(t, " active_conns     | %zu\n", active);
    tb_printf(t, " idle_conns       | %zu\n", idle);
    tb_printf(t, " waiting_clients  | %zu\n", pool->enh.wait_count);
    tb_printf(t, " backends         | %zu\n", pool->enh.num_backends);
    tb_printf(t, " paused           | %d\n", pool->paused ? 1 : 0);
    tb_printf(t, " suspended        | %d\n", pool->suspended ? 1 : 0);
}

static void show_clients(qihse_pooler_t* pool, textbuf_t* t) {
    tb_put(t, " type | user | database | state | addr | port | local_addr | local_port | connect_time | request_time | wait | wait_us | close_needed | ptr | link | remote_pid | tls\n");
    for (size_t i = 0; i < pool->num_clients; i++) {
        qihse_client_info_t* c = &pool->clients[i];
        tb_printf(t, " C | %s | %s | %s | %s | %d | %s | %d | %llu | %llu | 0 | %llu | %d | %p | %p | %d | %d\n",
                  c->user ? c->user : "", c->database ? c->database : "",
                  cl_state_str(c->state), c->addr, c->port, c->local_addr, c->local_port,
                  (unsigned long long)c->connect_time, (unsigned long long)c->request_time,
                  (unsigned long long)c->wait_us, c->close_needed,
                  c->ptr, c->link, c->remote_pid, c->tls);
    }
    if (pool->num_clients == 0) tb_put(t, "(none)\n");
}

static void show_servers(qihse_pooler_t* pool, textbuf_t* t) {
    tb_put(t, " type | user | database | state | addr | port | local_addr | local_port | connect_time | request_time | wait | wait_us | close_needed | ptr | link | remote_pid | tls\n");
    for (size_t i = 0; i < pool->num_servers; i++) {
        qihse_server_info_t* s = &pool->servers[i];
        tb_printf(t, " S | %s | %s | %s | %s | %d | %s | %d | %llu | %llu | 0 | %llu | %d | %p | %p | %d | %d\n",
                  s->user ? s->user : "", s->database ? s->database : "",
                  sv_state_str(s->state), s->addr, s->port, s->local_addr, s->local_port,
                  (unsigned long long)s->connect_time, (unsigned long long)s->request_time,
                  (unsigned long long)s->wait_us, s->close_needed,
                  s->ptr, s->link, s->remote_pid, s->tls);
    }
    if (pool->num_servers == 0) tb_put(t, "(none)\n");
}

static void show_users(qihse_pooler_t* pool, textbuf_t* t) {
    tb_put(t, " name | admin | stats\n");
    tb_put(t, "------+-------+------\n");
    for (size_t i = 0; i < pool->num_users; i++) {
        qihse_pooler_user_t* u = &pool->users[i];
        tb_printf(t, " %s | %s | %s\n",
                  u->username,
                  u->is_admin ? "yes" : "no",
                  u->is_stats ? "yes" : "no");
    }
    if (pool->num_users == 0) tb_put(t, "(none)\n");
}

static void show_stats(qihse_pooler_t* pool, textbuf_t* t) {
    tb_put(t, " database | total_xact_count | total_query_count | total_received | total_sent | total_xact_time | total_query_time | total_wait_time | avg_xact_count | avg_query_count | avg_recv | avg_sent | avg_xact_time | avg_query_time | avg_wait_time\n");
    for (size_t i = 0; i < pool->num_databases; i++) {
        qihse_database_t* d = &pool->databases[i];
        uint64_t xc = d->total_xact_count ? d->total_xact_count : 1;
        uint64_t qc = d->total_query_count ? d->total_query_count : 1;
        tb_printf(t, " %s | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu | %llu\n",
                  d->name,
                  (unsigned long long)d->total_xact_count,
                  (unsigned long long)d->total_query_count,
                  (unsigned long long)d->total_received,
                  (unsigned long long)d->total_sent,
                  (unsigned long long)d->total_xact_time,
                  (unsigned long long)d->total_query_time,
                  (unsigned long long)d->total_wait_time,
                  (unsigned long long)(d->total_xact_count / xc),
                  (unsigned long long)(d->total_query_count / qc),
                  (unsigned long long)(d->total_received / qc),
                  (unsigned long long)(d->total_sent / qc),
                  (unsigned long long)(d->total_xact_time / xc),
                  (unsigned long long)(d->total_query_time / qc),
                  (unsigned long long)(d->total_wait_time / qc));
    }
    if (pool->num_databases == 0) tb_put(t, "(none)\n");
}

static void show_version(qihse_pooler_t* pool, textbuf_t* t) {
    (void)pool;
    tb_printf(t, " PgBouncer version: %s\n", QIHSE_POOLER_VERSION);
}

static void show_config(qihse_pooler_t* pool, textbuf_t* t) {
    const qihse_pooler_config_t* c = &pool->config;
    tb_printf(t, " max_client_conn           | %zu\n", c->max_client_conn);
    tb_printf(t, " default_pool_size         | %zu\n", c->default_pool_size);
    tb_printf(t, " reserve_pool_size         | %zu\n", c->reserve_pool_size);
    tb_printf(t, " reserve_pool_timeout      | %zu\n", c->reserve_pool_timeout);
    tb_printf(t, " max_db_connections        | %zu\n", c->max_db_connections);
    tb_printf(t, " max_user_connections      | %zu\n", c->max_user_connections);
    tb_printf(t, " pool_mode                 | %s\n", qihse_pooler_mode_str(c->pool_mode));
    tb_printf(t, " server_lifetime           | %zu\n", c->server_lifetime);
    tb_printf(t, " server_idle_timeout       | %zu\n", c->server_idle_timeout);
    tb_printf(t, " server_connect_timeout    | %zu\n", c->server_connect_timeout);
    tb_printf(t, " server_login_retry        | %zu\n", c->server_login_retry);
    tb_printf(t, " query_timeout             | %zu\n", c->query_timeout);
    tb_printf(t, " query_wait_timeout        | %zu\n", c->query_wait_timeout);
    tb_printf(t, " client_idle_timeout       | %zu\n", c->client_idle_timeout);
    tb_printf(t, " client_login_timeout      | %zu\n", c->client_login_timeout);
    tb_printf(t, " keepalive                 | %d\n", c->keepalive);
    tb_printf(t, " tcp_keepalive             | %d\n", c->tcp_keepalive);
    tb_printf(t, " tcp_keepcnt               | %d\n", c->tcp_keepcnt);
    tb_printf(t, " tcp_keepidle              | %d\n", c->tcp_keepidle);
    tb_printf(t, " tcp_keepintvl             | %d\n", c->tcp_keepintvl);
    tb_printf(t, " tcp_user_timeout          | %d\n", c->tcp_user_timeout);
    tb_printf(t, " verbose                   | %d\n", c->verbose);
    tb_printf(t, " log_connections           | %d\n", c->log_connections);
    tb_printf(t, " log_disconnections        | %d\n", c->log_disconnections);
    tb_printf(t, " log_pooler_errors         | %d\n", c->log_pooler_errors);
    tb_printf(t, " stats_period              | %zu\n", c->stats_period);
    tb_printf(t, " auth_type                 | %s\n", auth_type_str(c->auth_type));
    tb_printf(t, " auth_file                 | %s\n", c->auth_file);
    tb_printf(t, " admin_users               | %s\n", c->admin_users);
    tb_printf(t, " stats_users               | %s\n", c->stats_users);
    tb_printf(t, " ignore_startup_parameters | %s\n", c->ignore_startup_parameters);
}

static void show_fds(qihse_pooler_t* pool, textbuf_t* t) {
    (void)pool;
    tb_put(t, " fd | task | user | database | addr | port | cancel | link | client_encoding | std_strings | timezone | password\n");
    tb_put(t, "(internal - not exposed)\n");
}

static void show_sockets(qihse_pooler_t* pool, textbuf_t* t, int active_only) {
    tb_put(t, " type | user | database | state | addr | port | local_addr | local_port | connect_time | request_time | wait | wait_us | close_needed | ptr | link | remote_pid | tls\n");
    size_t shown = 0;
    for (size_t i = 0; i < pool->num_clients; i++) {
        if (active_only && pool->clients[i].state != CL_STATE_ACTIVE) continue;
        qihse_client_info_t* c = &pool->clients[i];
        tb_printf(t, " C | %s | %s | %s | %s | %d | %s | %d | %llu | %llu | 0 | %llu | %d | %p | %p | %d | %d\n",
                  c->user ? c->user : "", c->database ? c->database : "",
                  cl_state_str(c->state), c->addr, c->port, c->local_addr, c->local_port,
                  (unsigned long long)c->connect_time, (unsigned long long)c->request_time,
                  (unsigned long long)c->wait_us, c->close_needed,
                  c->ptr, c->link, c->remote_pid, c->tls);
        shown++;
    }
    for (size_t i = 0; i < pool->num_servers; i++) {
        if (active_only && pool->servers[i].state != SV_STATE_ACTIVE) continue;
        qihse_server_info_t* s = &pool->servers[i];
        tb_printf(t, " S | %s | %s | %s | %s | %d | %s | %d | %llu | %llu | 0 | %llu | %d | %p | %p | %d | %d\n",
                  s->user ? s->user : "", s->database ? s->database : "",
                  sv_state_str(s->state), s->addr, s->port, s->local_addr, s->local_port,
                  (unsigned long long)s->connect_time, (unsigned long long)s->request_time,
                  (unsigned long long)s->wait_us, s->close_needed,
                  s->ptr, s->link, s->remote_pid, s->tls);
        shown++;
    }
    if (shown == 0) tb_put(t, "(none)\n");
}

static void show_mem(qihse_pooler_t* pool, textbuf_t* t) {
    size_t db_mem = pool->num_databases * sizeof(qihse_database_t);
    size_t user_mem = pool->num_users * sizeof(qihse_pooler_user_t);
    size_t cl_mem = pool->num_clients * sizeof(qihse_client_info_t);
    size_t sv_mem = pool->num_servers * sizeof(qihse_server_info_t);
    size_t be_mem = pool->enh.num_backends * sizeof(qihse_pool_backend_t);
    size_t ent_mem = pool->nentries * sizeof(qihse_pool_entry_t);
    tb_printf(t, " databases | %zu | %zu bytes\n", pool->num_databases, db_mem);
    tb_printf(t, " users     | %zu | %zu bytes\n", pool->num_users, user_mem);
    tb_printf(t, " clients   | %zu | %zu bytes\n", pool->num_clients, cl_mem);
    tb_printf(t, " servers   | %zu | %zu bytes\n", pool->num_servers, sv_mem);
    tb_printf(t, " backends  | %zu | %zu bytes\n", pool->enh.num_backends, be_mem);
    tb_printf(t, " pool_entries | %zu | %zu bytes\n", pool->nentries, ent_mem);
}

static void show_peers(qihse_pooler_t* pool, textbuf_t* t) {
    (void)pool;
    tb_put(t, " peer_id | host | port | pool_size | pool_mode\n");
    tb_put(t, "(none)\n");
}

static void show_peer_pools(qihse_pooler_t* pool, textbuf_t* t) {
    (void)pool;
    tb_put(t, " database | user | cl_active | cl_waiting | sv_active | sv_idle | sv_used | sv_tested | sv_login | maxwait | maxwait_us | pool_mode\n");
    tb_put(t, "(none)\n");
}

/* ================================================================== */
/* Admin command execution                                             */
/* ================================================================== */

char* qihse_pooler_admin_exec(qihse_pooler_t* pool, qihse_admin_cmd_t cmd, const char* arg) {
    if (!pool) return NULL;
    textbuf_t t = {0,0,0};
    char tmp[160];
    const char* a = arg ? arg : "";

    /* SHOW commands read pooler state under the lock. */
    switch (cmd) {
        case QIHSE_ADMIN_SHOW_DATABASES:
        case QIHSE_ADMIN_SHOW_LISTS:
        case QIHSE_ADMIN_SHOW_POOLS:
        case QIHSE_ADMIN_SHOW_CLIENTS:
        case QIHSE_ADMIN_SHOW_SERVERS:
        case QIHSE_ADMIN_SHOW_USERS:
        case QIHSE_ADMIN_SHOW_STATS:
        case QIHSE_ADMIN_SHOW_VERSION:
        case QIHSE_ADMIN_SHOW_CONFIG:
        case QIHSE_ADMIN_SHOW_FDS:
        case QIHSE_ADMIN_SHOW_SOCKETS:
        case QIHSE_ADMIN_SHOW_ACTIVE_SOCKETS:
        case QIHSE_ADMIN_SHOW_MEM:
        case QIHSE_ADMIN_SHOW_PEERS:
        case QIHSE_ADMIN_SHOW_PEER_POOLS: {
            POOL_LOCK(pool);
            switch (cmd) {
                case QIHSE_ADMIN_SHOW_DATABASES: show_databases(pool, &t); break;
                case QIHSE_ADMIN_SHOW_LISTS: show_lists(pool, &t); break;
                case QIHSE_ADMIN_SHOW_POOLS: show_pools(pool, &t); break;
                case QIHSE_ADMIN_SHOW_CLIENTS: show_clients(pool, &t); break;
                case QIHSE_ADMIN_SHOW_SERVERS: show_servers(pool, &t); break;
                case QIHSE_ADMIN_SHOW_USERS: show_users(pool, &t); break;
                case QIHSE_ADMIN_SHOW_STATS: show_stats(pool, &t); break;
                case QIHSE_ADMIN_SHOW_VERSION: show_version(pool, &t); break;
                case QIHSE_ADMIN_SHOW_CONFIG: show_config(pool, &t); break;
                case QIHSE_ADMIN_SHOW_FDS: show_fds(pool, &t); break;
                case QIHSE_ADMIN_SHOW_SOCKETS: show_sockets(pool, &t, 0); break;
                case QIHSE_ADMIN_SHOW_ACTIVE_SOCKETS: show_sockets(pool, &t, 1); break;
                case QIHSE_ADMIN_SHOW_MEM: show_mem(pool, &t); break;
                case QIHSE_ADMIN_SHOW_PEERS: show_peers(pool, &t); break;
                case QIHSE_ADMIN_SHOW_PEER_POOLS: show_peer_pools(pool, &t); break;
                default: break;
            }
            POOL_UNLOCK(pool);
            if (!t.buf) return dup_str("");
            return t.buf;
        }

        /* Control commands: the helpers take the lock internally, so we must
         * not hold it here. */
        case QIHSE_ADMIN_PAUSE: {
            int rc = qihse_pooler_pause(pool, *a ? a : NULL);
            snprintf(tmp, sizeof(tmp), "PAUSE %s: %s\n", *a ? a : "*", rc == 0 ? "OK" : "not found");
            return dup_str(tmp);
        }
        case QIHSE_ADMIN_RESUME: {
            int rc = qihse_pooler_resume(pool, *a ? a : NULL);
            snprintf(tmp, sizeof(tmp), "RESUME %s: %s\n", *a ? a : "*", rc == 0 ? "OK" : "not found");
            return dup_str(tmp);
        }
        case QIHSE_ADMIN_DISABLE: {
            int rc = qihse_pooler_disable_db(pool, a);
            snprintf(tmp, sizeof(tmp), "DISABLE %s: %s\n", a, rc == 0 ? "OK" : "not found");
            return dup_str(tmp);
        }
        case QIHSE_ADMIN_ENABLE: {
            int rc = qihse_pooler_enable_db(pool, a);
            snprintf(tmp, sizeof(tmp), "ENABLE %s: %s\n", a, rc == 0 ? "OK" : "not found");
            return dup_str(tmp);
        }
        case QIHSE_ADMIN_RECONNECT: {
            int rc = qihse_pooler_reconnect(pool, *a ? a : NULL);
            snprintf(tmp, sizeof(tmp), "RECONNECT %s: %s\n", *a ? a : "*", rc == 0 ? "OK" : "not found");
            return dup_str(tmp);
        }
        case QIHSE_ADMIN_KILL: {
            int rc = qihse_pooler_kill_db(pool, a);
            snprintf(tmp, sizeof(tmp), "KILL %s: %s\n", a, rc == 0 ? "OK" : "not found");
            return dup_str(tmp);
        }
        case QIHSE_ADMIN_SUSPEND: {
            (void)qihse_pooler_suspend(pool);
            return dup_str("SUSPEND: OK\n");
        }
        case QIHSE_ADMIN_SHUTDOWN: {
            (void)qihse_pooler_shutdown(pool);
            return dup_str("SHUTDOWN: OK\n");
        }
        case QIHSE_ADMIN_RELOAD: {
            (void)qihse_pooler_reload(pool);
            return dup_str("RELOAD: OK\n");
        }
        case QIHSE_ADMIN_WAIT: {
            int rc = qihse_pooler_wait_db(pool, a);
            snprintf(tmp, sizeof(tmp), "WAIT %s: %s\n", a, rc == 0 ? "empty" : "busy");
            return dup_str(tmp);
        }
        default:
            break;
    }
    return dup_str("ERROR: unknown command\n");
}

char* qihse_pooler_admin(qihse_pooler_t* pool, const char* command) {
    if (!pool || !command) return NULL;
    qihse_admin_cmd_t cmd;
    char arg[128];
    if (qihse_pooler_parse_admin(command, &cmd, arg, sizeof(arg)) != 0) {
        return dup_str("ERROR: unrecognized command\n");
    }
    return qihse_pooler_admin_exec(pool, cmd, arg);
}
