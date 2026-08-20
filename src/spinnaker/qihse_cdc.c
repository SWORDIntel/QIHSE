#include "qihse_cdc.h"
#include <stdlib.h>
#include <string.h>

qihse_cdc_context_t* qihse_cdc_create(void) {
    qihse_cdc_context_t* ctx = (qihse_cdc_context_t*)calloc(1, sizeof(qihse_cdc_context_t));
    if (!ctx) return NULL;
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->next_lsn = 1;
    return ctx;
}

void qihse_cdc_destroy(qihse_cdc_context_t* ctx) {
    if (!ctx) return;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_subs; i++) free(ctx->subs[i].name);
    free(ctx->subs);
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

int qihse_cdc_subscribe(qihse_cdc_context_t* ctx, const char* name,
                        qihse_cdc_callback_t callback, void* user_data) {
    if (!ctx || !name || !callback) return -1;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_subs; i++) {
        if (strcmp(ctx->subs[i].name, name) == 0) { pthread_mutex_unlock(&ctx->lock); return -1; }
    }
    if (ctx->num_subs >= ctx->subs_cap) {
        ctx->subs_cap = ctx->subs_cap ? ctx->subs_cap * 2 : 4;
        ctx->subs = (qihse_cdc_subscription_t*)realloc(ctx->subs, ctx->subs_cap * sizeof(qihse_cdc_subscription_t));
    }
    ctx->subs[ctx->num_subs].name = strdup(name);
    ctx->subs[ctx->num_subs].callback = callback;
    ctx->subs[ctx->num_subs].user_data = user_data;
    ctx->subs[ctx->num_subs].active = 1;
    ctx->subs[ctx->num_subs].last_lsn = 0;
    ctx->num_subs++;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_cdc_unsubscribe(qihse_cdc_context_t* ctx, const char* name) {
    if (!ctx || !name) return -1;
    pthread_mutex_lock(&ctx->lock);
    for (size_t i = 0; i < ctx->num_subs; i++) {
        if (strcmp(ctx->subs[i].name, name) == 0) {
            free(ctx->subs[i].name);
            memmove(&ctx->subs[i], &ctx->subs[i+1], (ctx->num_subs - i - 1) * sizeof(qihse_cdc_subscription_t));
            ctx->num_subs--;
            pthread_mutex_unlock(&ctx->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return -1;
}

int qihse_cdc_emit(qihse_cdc_context_t* ctx, cdc_op_t op, const char* table,
                   const char* key,
                   const uint8_t* old_value, size_t old_value_len,
                   const uint8_t* new_value, size_t new_value_len) {
    if (!ctx || !table || !key) return -1;
    qihse_cdc_event_t event;
    event.op = op;
    event.table = (char*)table;
    event.key = (char*)key;
    event.old_value = (uint8_t*)old_value;
    event.old_value_len = old_value_len;
    event.new_value = (uint8_t*)new_value;
    event.new_value_len = new_value_len;
    
    pthread_mutex_lock(&ctx->lock);
    event.lsn = ctx->next_lsn++;
    event.timestamp = (uint64_t)time(NULL);
    
    for (size_t i = 0; i < ctx->num_subs; i++) {
        if (ctx->subs[i].active && ctx->subs[i].callback) {
            ctx->subs[i].callback(&event, ctx->subs[i].user_data);
            ctx->subs[i].last_lsn = event.lsn;
        }
    }
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

size_t qihse_cdc_subscription_count(qihse_cdc_context_t* ctx) {
    if (!ctx) return 0;
    pthread_mutex_lock(&ctx->lock);
    size_t n = ctx->num_subs;
    pthread_mutex_unlock(&ctx->lock);
    return n;
}

uint64_t qihse_cdc_get_lsn(qihse_cdc_context_t* ctx) {
    if (!ctx) return 0;
    pthread_mutex_lock(&ctx->lock);
    uint64_t lsn = ctx->next_lsn - 1;
    pthread_mutex_unlock(&ctx->lock);
    return lsn;
}

void qihse_cdc_event_free(qihse_cdc_event_t* event) {
    if (!event) return;
    /* event fields are borrowed, not owned - nothing to free */
}
