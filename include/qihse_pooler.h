#ifndef QIHSE_POOLER_H
#define QIHSE_POOLER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Opaque handle                                                       */
/* ------------------------------------------------------------------ */

typedef struct qihse_pooler_s qihse_pooler_t;

/* ------------------------------------------------------------------ */
/* Pooling modes (PgBouncer-style)                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    POOL_SESSION = 0,      /*!< connection bound to client for entire session */
    POOL_TRANSACTION = 1,  /*!< connection returned to pool after each transaction */
    POOL_STATEMENT = 2     /*!< connection returned after each statement */
} pool_mode_t;

/* ------------------------------------------------------------------ */
/* Authentication types                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    QIHSE_AUTH_ANY = 0,        /*!< no authentication required */
    QIHSE_AUTH_TRUST,          /*!< trust all users */
    QIHSE_AUTH_PASSWORD,       /*!< cleartext password */
    QIHSE_AUTH_MD5,            /*!< MD5 challenge/response */
    QIHSE_AUTH_SCRAM_SHA256,   /*!< SCRAM-SHA-256 */
    QIHSE_AUTH_CERT,           /*!< client TLS certificate */
    QIHSE_AUTH_HBA             /*!< pg_hba.conf style */
} qihse_auth_type_t;

/* ------------------------------------------------------------------ */
/* Backend server definition                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int fd;
    char* host;
    uint16_t port;
    int in_use;
    uint64_t last_used;
    int healthy;
} qihse_pool_backend_t;

/* ------------------------------------------------------------------ */
/* Configuration (PgBouncer-style settings)                            */
/* ------------------------------------------------------------------ */

typedef struct {
    pool_mode_t mode;                 /*!< legacy alias for pool_mode */
    size_t max_connections;           /*!< legacy alias for max_client_conn */
    size_t max_per_client;            /*!< legacy alias for default_pool_size */
    size_t idle_timeout_ms;           /*!< legacy alias for server_idle_timeout */
    size_t connect_timeout_ms;        /*!< legacy alias for server_connect_timeout */
    int health_check_interval;        /*!< legacy field */

    /* full PgBouncer-style configuration */
    size_t max_client_conn;
    size_t default_pool_size;
    size_t reserve_pool_size;
    size_t reserve_pool_timeout;
    size_t max_db_connections;
    size_t max_user_connections;
    pool_mode_t pool_mode;
    size_t server_lifetime;
    size_t server_idle_timeout;
    size_t server_connect_timeout;
    size_t server_login_retry;
    size_t query_timeout;
    size_t query_wait_timeout;
    size_t client_idle_timeout;
    size_t client_login_timeout;
    int keepalive;
    int tcp_keepalive;
    int tcp_keepcnt;
    int tcp_keepidle;
    int tcp_keepintvl;
    int tcp_user_timeout;
    int verbose;
    int log_connections;
    int log_disconnections;
    int log_pooler_errors;
    size_t stats_period;
    qihse_auth_type_t auth_type;
    char auth_file[256];
    char admin_users[256];
    char stats_users[256];
    char ignore_startup_parameters[512];
} qihse_pooler_config_t;

/* ------------------------------------------------------------------ */
/* Connection state enums                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    CL_STATE_ACTIVE = 0,
    CL_STATE_WAITING,
    CL_STATE_IDLE,
    CL_STATE_CLOSED
} qihse_client_state_t;

typedef enum {
    SV_STATE_ACTIVE = 0,
    SV_STATE_IDLE,
    SV_STATE_USED,
    SV_STATE_TESTED,
    SV_STATE_LOGIN,
    SV_STATE_CLOSED
} qihse_server_state_t;

/* ------------------------------------------------------------------ */
/* Client / server connection info (for SHOW CLIENTS / SHOW SERVERS)   */
/* ------------------------------------------------------------------ */

typedef struct {
    int fd;
    char* user;
    char* database;
    qihse_client_state_t state;
    char addr[64];
    int port;
    char local_addr[64];
    int local_port;
    uint64_t connect_time;
    uint64_t request_time;
    uint64_t wait_us;
    int close_needed;
    void* ptr;
    void* link;
    int remote_pid;
    int tls;
} qihse_client_info_t;

typedef struct {
    int fd;
    char* user;
    char* database;
    qihse_server_state_t state;
    char addr[64];
    int port;
    char local_addr[64];
    int local_port;
    uint64_t connect_time;
    uint64_t request_time;
    uint64_t wait_us;
    int close_needed;
    void* ptr;
    void* link;
    int remote_pid;
    int tls;
} qihse_server_info_t;

/* ------------------------------------------------------------------ */
/* Database and user records                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    char* name;
    char* host;
    uint16_t port;
    int disabled;
    int paused;
    size_t max_connections;
    pool_mode_t pool_mode;
    /* pool counters */
    size_t cl_active;
    size_t cl_waiting;
    size_t sv_active;
    size_t sv_idle;
    size_t sv_used;
    size_t sv_tested;
    size_t sv_login;
    uint64_t maxwait_us;
    /* statistics */
    uint64_t total_xact_count;
    uint64_t total_query_count;
    uint64_t total_received;
    uint64_t total_sent;
    uint64_t total_xact_time;
    uint64_t total_query_time;
    uint64_t total_wait_time;
} qihse_database_t;

typedef struct {
    char* username;
    char* password;   /*!< from auth_file (userlist.txt) */
    int is_admin;
    int is_stats;
    /* statistics */
    uint64_t total_xact_count;
    uint64_t total_query_count;
    uint64_t total_received;
    uint64_t total_sent;
    uint64_t total_xact_time;
    uint64_t total_query_time;
    uint64_t total_wait_time;
} qihse_pooler_user_t;

/* ------------------------------------------------------------------ */
/* Admin console commands                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    QIHSE_ADMIN_UNKNOWN = 0,
    QIHSE_ADMIN_SHOW_DATABASES,
    QIHSE_ADMIN_SHOW_LISTS,
    QIHSE_ADMIN_SHOW_POOLS,
    QIHSE_ADMIN_SHOW_CLIENTS,
    QIHSE_ADMIN_SHOW_SERVERS,
    QIHSE_ADMIN_SHOW_USERS,
    QIHSE_ADMIN_SHOW_STATS,
    QIHSE_ADMIN_SHOW_VERSION,
    QIHSE_ADMIN_SHOW_CONFIG,
    QIHSE_ADMIN_SHOW_FDS,
    QIHSE_ADMIN_SHOW_SOCKETS,
    QIHSE_ADMIN_SHOW_ACTIVE_SOCKETS,
    QIHSE_ADMIN_SHOW_MEM,
    QIHSE_ADMIN_SHOW_PEERS,
    QIHSE_ADMIN_SHOW_PEER_POOLS,
    QIHSE_ADMIN_PAUSE,
    QIHSE_ADMIN_RESUME,
    QIHSE_ADMIN_DISABLE,
    QIHSE_ADMIN_ENABLE,
    QIHSE_ADMIN_RECONNECT,
    QIHSE_ADMIN_KILL,
    QIHSE_ADMIN_SUSPEND,
    QIHSE_ADMIN_SHUTDOWN,
    QIHSE_ADMIN_RELOAD,
    QIHSE_ADMIN_WAIT
} qihse_admin_cmd_t;

/* ------------------------------------------------------------------ */
/* Base API (unchanged)                                                */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Enhanced pooler API                                                 */
/* ------------------------------------------------------------------ */

qihse_pooler_t* qihse_pooler_create_ex(const qihse_pooler_config_t* config);
int qihse_pooler_set_mode(qihse_pooler_t* pool, pool_mode_t mode);
int qihse_pooler_health_check(qihse_pooler_t* pool);
size_t qihse_pooler_wait_count(qihse_pooler_t* pool);
int qihse_pooler_add_backend(qihse_pooler_t* pool, const char* host, uint16_t port);
int qihse_pooler_remove_backend(qihse_pooler_t* pool, const char* host, uint16_t port);
size_t qihse_pooler_backend_count(qihse_pooler_t* pool);

/* ------------------------------------------------------------------ */
/* PgBouncer-style admin / control API                                 */
/* ------------------------------------------------------------------ */

/**
 * @brief Parse an admin command string into a cmd enum + argument.
 * @return 0 on success, -1 if the command is not recognised.
 */
int qihse_pooler_parse_admin(const char* command, qihse_admin_cmd_t* out_cmd, char* out_arg, size_t arg_len);

/**
 * @brief Execute an admin console command (SQL-like syntax used by the
 *        "pgbouncer" virtual database).
 * @param pool The pooler.
 * @param command NUL-terminated command string (e.g. "SHOW POOLS").
 * @return A dynamically allocated text result (caller must free()). For
 *         control commands the text is a short status message. Returns
 *         NULL on allocation failure or invalid pool.
 */
char* qihse_pooler_admin(qihse_pooler_t* pool, const char* command);

/**
 * @brief Execute a pre-parsed admin command. Lower-level than
 *        qihse_pooler_admin(). Returns a dynamically allocated text result.
 */
char* qihse_pooler_admin_exec(qihse_pooler_t* pool, qihse_admin_cmd_t cmd, const char* arg);

/* ------------------------------------------------------------------ */
/* Database / user management                                          */
/* ------------------------------------------------------------------ */

int qihse_pooler_add_database(qihse_pooler_t* pool, const char* name, const char* host, uint16_t port);
qihse_database_t* qihse_pooler_find_database(qihse_pooler_t* pool, const char* name);
size_t qihse_pooler_database_count(qihse_pooler_t* pool);

int qihse_pooler_add_user(qihse_pooler_t* pool, const char* username, const char* password);
qihse_pooler_user_t* qihse_pooler_find_user(qihse_pooler_t* pool, const char* username);
size_t qihse_pooler_user_count(qihse_pooler_t* pool);

/**
 * @brief Load an auth_file in PgBouncer userlist.txt format:
 *        "username" "password"
 * @return number of users loaded, or -1 on error.
 */
int qihse_pooler_load_auth_file(qihse_pooler_t* pool, const char* path);

/* ------------------------------------------------------------------ */
/* Client / server connection registration (for SHOW CLIENTS/SERVERS)  */
/* ------------------------------------------------------------------ */

int qihse_pooler_register_client(qihse_pooler_t* pool, const qihse_client_info_t* info);
int qihse_pooler_unregister_client(qihse_pooler_t* pool, int fd);
int qihse_pooler_register_server(qihse_pooler_t* pool, const qihse_server_info_t* info);
int qihse_pooler_unregister_server(qihse_pooler_t* pool, int fd);

/* ------------------------------------------------------------------ */
/* Statistics                                                          */
/* ------------------------------------------------------------------ */

void qihse_pooler_record_xact(qihse_pooler_t* pool, const char* database, const char* user, uint64_t duration_us);
void qihse_pooler_record_query(qihse_pooler_t* pool, const char* database, const char* user, uint64_t duration_us, uint64_t bytes_recv, uint64_t bytes_sent);
void qihse_pooler_record_wait(qihse_pooler_t* pool, const char* database, const char* user, uint64_t wait_us);

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

void qihse_pooler_config_defaults(qihse_pooler_config_t* config);
int qihse_pooler_apply_config(qihse_pooler_t* pool, const qihse_pooler_config_t* config);
const qihse_pooler_config_t* qihse_pooler_get_config(qihse_pooler_t* pool);

/* ------------------------------------------------------------------ */
/* Pooling mode helpers                                                */
/* ------------------------------------------------------------------ */

pool_mode_t qihse_pooler_get_mode(qihse_pooler_t* pool);
const char* qihse_pooler_mode_str(pool_mode_t mode);

/* ------------------------------------------------------------------ */
/* Control command helpers (callable directly, not just via admin)     */
/* ------------------------------------------------------------------ */

int qihse_pooler_pause(qihse_pooler_t* pool, const char* db);
int qihse_pooler_resume(qihse_pooler_t* pool, const char* db);
int qihse_pooler_disable_db(qihse_pooler_t* pool, const char* db);
int qihse_pooler_enable_db(qihse_pooler_t* pool, const char* db);
int qihse_pooler_reconnect(qihse_pooler_t* pool, const char* db);
int qihse_pooler_kill_db(qihse_pooler_t* pool, const char* db);
int qihse_pooler_suspend(qihse_pooler_t* pool);
int qihse_pooler_shutdown(qihse_pooler_t* pool);
int qihse_pooler_reload(qihse_pooler_t* pool);
int qihse_pooler_wait_db(qihse_pooler_t* pool, const char* db);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_POOLER_H */
