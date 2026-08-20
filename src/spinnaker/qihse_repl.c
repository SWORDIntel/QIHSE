#include "qihse_repl.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

qihse_repl_context_t* qihse_repl_create(repl_role_t role) {
    qihse_repl_context_t* ctx = (qihse_repl_context_t*)calloc(1, sizeof(qihse_repl_context_t));
    if (!ctx) return NULL;
    ctx->role = role;
    ctx->state = REPL_STATE_DISCONNECTED;
    ctx->stream_fd = -1;
    ctx->sync_mode = 0;
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->slots = NULL;
    ctx->num_slots = 0;
    ctx->slots_cap = 0;
    return ctx;
}

int qihse_repl_connect_primary(qihse_repl_context_t* ctx, const char* host, uint16_t port) {
    if (!ctx || !host) return -1;
    pthread_mutex_lock(&ctx->lock);
    free(ctx->primary_host);
    ctx->primary_host = strdup(host);
    ctx->primary_port = port;
    ctx->state = REPL_STATE_CONNECTING;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { ctx->state = REPL_STATE_ERROR; pthread_mutex_unlock(&ctx->lock); return -1; }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        ctx->state = REPL_STATE_ERROR;
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        ctx->state = REPL_STATE_ERROR;
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    
    ctx->stream_fd = fd;
    ctx->state = REPL_STATE_CONNECTING;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_start_streaming(qihse_repl_context_t* ctx) {
    if (!ctx || ctx->stream_fd < 0) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->state = REPL_STATE_STREAMING;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_stop(qihse_repl_context_t* ctx) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (ctx->stream_fd >= 0) { close(ctx->stream_fd); ctx->stream_fd = -1; }
    ctx->state = REPL_STATE_DISCONNECTED;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

void qihse_repl_destroy(qihse_repl_context_t* ctx) {
    if (!ctx) return;
    qihse_repl_stop(ctx);
    pthread_mutex_lock(&ctx->lock);
    free(ctx->primary_host);
    free(ctx->replica_name);
    for (size_t i = 0; i < ctx->num_slots; i++) free(ctx->slots[i].name);
    free(ctx->slots);
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

int qihse_repl_ship_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn) {
    if (!ctx || !wal_data || len == 0) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (ctx->stream_fd < 0 || ctx->state != REPL_STATE_STREAMING) {
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    /* Send: [8-byte LSN][8-byte length][data] */
    uint64_t hdr[2];
    hdr[0] = lsn;
    hdr[1] = (uint64_t)len;
    ssize_t w = write(ctx->stream_fd, hdr, sizeof(hdr));
    if (w != (ssize_t)sizeof(hdr)) { ctx->state = REPL_STATE_ERROR; pthread_mutex_unlock(&ctx->lock); return -1; }
    w = write(ctx->stream_fd, wal_data, len);
    if (w != (ssize_t)len) { ctx->state = REPL_STATE_ERROR; pthread_mutex_unlock(&ctx->lock); return -1; }
    ctx->last_lsn = lsn;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_apply_wal(qihse_repl_context_t* ctx, const uint8_t* wal_data, size_t len, uint64_t lsn) {
    if (!ctx || !wal_data) return -1;
    pthread_mutex_lock(&ctx->lock);
    /* In a real implementation, this would replay the WAL into the local store */
    ctx->replay_lsn = lsn;
    ctx->flush_lsn = lsn;
    (void)wal_data; (void)len;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_get_status(qihse_repl_context_t* ctx, uint64_t* last_lsn, uint64_t* flush_lsn, repl_state_t* state) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    if (last_lsn) *last_lsn = ctx->last_lsn;
    if (flush_lsn) *flush_lsn = ctx->flush_lsn;
    if (state) *state = ctx->state;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_create_slot(qihse_repl_context_t* ctx, const char* name) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    /* Check if slot already exists */
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, name) == 0) { pthread_mutex_unlock(&ctx->lock); return -1; }
    }
    if (ctx->num_slots >= ctx->slots_cap) {
        ctx->slots_cap = ctx->slots_cap ? ctx->slots_cap * 2 : 4;
        ctx->slots = (qihse_repl_slot_t*)realloc(ctx->slots, ctx->slots_cap * sizeof(qihse_repl_slot_t));
    }
    ctx->slots[ctx->num_slots].name = strdup(name);
    ctx->slots[ctx->num_slots].restart_lsn = 0;
    ctx->slots[ctx->num_slots].confirmed_flush_lsn = 0;
    ctx->slots[ctx->num_slots].active = 0;
    ctx->num_slots++;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_repl_drop_slot(qihse_repl_context_t* ctx, const char* name) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, name) == 0) {
            free(ctx->slots[i].name);
            memmove(&ctx->slots[i], &ctx->slots[i+1], (ctx->num_slots - i - 1) * sizeof(qihse_repl_slot_t));
            ctx->num_slots--;
            pthread_mutex_unlock(&ctx->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return -1;
}

int qihse_repl_advance_slot(qihse_repl_context_t* ctx, const char* name, uint64_t new_lsn) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_slots; i++) {
        if (strcmp(ctx->slots[i].name, name) == 0) {
            if (new_lsn > ctx->slots[i].restart_lsn) ctx->slots[i].restart_lsn = new_lsn;
            ctx->slots[i].confirmed_flush_lsn = new_lsn;
            pthread_mutex_unlock(&ctx->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return -1;
}

size_t qihse_repl_slot_count(qihse_repl_context_t* ctx) {
    if (!ctx) return 0;
    pthread_mutex_lock(&ctx->lock);
    size_t n = ctx->num_slots;
    pthread_mutex_unlock(&ctx->lock);
    return n;
}
