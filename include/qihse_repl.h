#ifndef QIHSE_REPL_H
#define QIHSE_REPL_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    REPL_ROLE_PRIMARY = 0,
    REPL_ROLE_REPLICA = 1,
    REPL_ROLE_STANDBY = 2
} repl_role_t;

typedef enum {
    REPL_STATE_DISCONNECTED = 0,
    REPL_STATE_CONNECTING = 1,
    REPL_STATE_STREAMING = 2,
    REPL_STATE_SYNCING = 3,
    REPL_STATE_ERROR = 4
} repl_state_t;

typedef struct {
    char* name;
    uint64_t restart_lsn;
    uint64_t confirmed_flush_lsn;
    int active;
} qihse_repl_slot_t;

typedef struct {
    repl_role_t role;
    repl_state_t state;
    char* primary_host;
    uint16_t primary_port;
    char* replica_name;
    uint64_t last_lsn;
    uint64_t flush_lsn;
    uint64_t replay_lsn;
    int sync_mode;
    pthread_t stream_thread;
    int stream_fd;
    pthread_mutex_t lock;
    qihse_repl_slot_t* slots;
    size_t num_slots;
    size_t slots_cap;
} qihse_repl_context_t;

qihse_repl_context_t* qihse_repl_create(repl_role_t role);
int qihse_repl_connect_primary(qihse_repl_context_t* ctx, const char* host, uint16_t port);
int qihse_repl_start_streaming(qihse_repl_context_t* ctx);
int qihse_repl_stop(qihse_repl_context_t* ctx);
void qihse_repl_destroy(qihse_repl_context_t* ctx);

int qihse_repl_ship_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn);
int qihse_repl_apply_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn);
int qihse_repl_get_status(qihse_repl_context_t* ctx, uint64_t* last_lsn, uint64_t* flush_lsn, repl_state_t* state);

int qihse_repl_create_slot(qihse_repl_context_t* ctx, const char* name);
int qihse_repl_drop_slot(qihse_repl_context_t* ctx, const char* name);
int qihse_repl_advance_slot(qihse_repl_context_t* ctx, const char* name, uint64_t new_lsn);
size_t qihse_repl_slot_count(qihse_repl_context_t* ctx);

#ifdef __cplusplus
}
#endif
#endif
