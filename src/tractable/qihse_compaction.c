#include <unistd.h>
#include "qihse_compaction.h"
#include <stdlib.h>
#include <string.h>

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

qihse_compaction_ctx_t* qihse_compaction_create(void) {
    qihse_compaction_ctx_t* ctx = (qihse_compaction_ctx_t*)calloc(1, sizeof(qihse_compaction_ctx_t));
    if (!ctx) return NULL;
    pthread_mutex_init(&ctx->lock, NULL);
    ctx->running = 0;
    ctx->shutdown = 0;
    ctx->interval_seconds = 300; /* 5 min default */
    return ctx;
}

int qihse_compaction_set_kv(qihse_compaction_ctx_t* ctx, void* kv) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->kv_store = kv;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_compaction_set_columnar(qihse_compaction_ctx_t* ctx, void* col) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->column_store = col;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_compaction_set_document(qihse_compaction_ctx_t* ctx, void* doc) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->document_store = doc;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

int qihse_compaction_set_timeseries(qihse_compaction_ctx_t* ctx, void* ts) {
    if (!ctx) return -1;
    pthread_mutex_lock(&ctx->lock);
    ctx->timeseries_store = ts;
    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

qihse_compaction_result_t qihse_compaction_run(qihse_compaction_ctx_t* ctx, compaction_engine_t engine) {
    qihse_compaction_result_t result;
    memset(&result, 0, sizeof(result));
    result.engine = engine;
    result.status = 0;
    result.start_time = now_ms();
    
    /* In a real implementation, this would merge SSTables, compact tombstones, etc. */
    switch (engine) {
        case COMPACTION_KV:
            /* Merge KV SSTables */
            result.sstables_merged = 0;
            result.keys_compacted = 0;
            result.bytes_reclaimed = 0;
            break;
        case COMPACTION_COLUMNAR:
            /* Compact columnar RLE/delta segments */
            break;
        case COMPACTION_DOCUMENT:
            /* Compact document store arenas */
            break;
        case COMPACTION_TIMESERIES:
            /* Compact time-series Gorilla blocks */
            break;
        case COMPACTION_ALL:
            qihse_compaction_run(ctx, COMPACTION_KV);
            qihse_compaction_run(ctx, COMPACTION_COLUMNAR);
            qihse_compaction_run(ctx, COMPACTION_DOCUMENT);
            qihse_compaction_run(ctx, COMPACTION_TIMESERIES);
            break;
    }
    
    result.end_time = now_ms();
    (void)ctx;
    return result;
}

static void* compaction_loop(void* arg) {
    qihse_compaction_ctx_t* ctx = (qihse_compaction_ctx_t*)arg;
    while (!ctx->shutdown) {
        qihse_compaction_run(ctx, COMPACTION_ALL);
        /* Sleep for interval */
        for (int i = 0; i < ctx->interval_seconds && !ctx->shutdown; i++) {
            sleep(1);
        }
    }
    return NULL;
}

int qihse_compaction_start(qihse_compaction_ctx_t* ctx, int interval_seconds) {
    if (!ctx || ctx->running) return -1;
    ctx->interval_seconds = interval_seconds > 0 ? interval_seconds : 300;
    ctx->shutdown = 0;
    ctx->running = 1;
    pthread_create(&ctx->thread, NULL, compaction_loop, ctx);
    return 0;
}

int qihse_compaction_stop(qihse_compaction_ctx_t* ctx) {
    if (!ctx) return -1;
    ctx->shutdown = 1;
    if (ctx->running) {
        pthread_join(ctx->thread, NULL);
        ctx->running = 0;
    }
    return 0;
}

void qihse_compaction_destroy(qihse_compaction_ctx_t* ctx) {
    if (!ctx) return;
    qihse_compaction_stop(ctx);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

qihse_ttl_result_t qihse_ttl_sweep(qihse_compaction_ctx_t* ctx, int64_t cutoff_timestamp) {
    qihse_ttl_result_t result;
    memset(&result, 0, sizeof(result));
    uint64_t start = now_ms();
    
    /* In a real implementation, iterate over all keys with TTL and remove expired ones */
    (void)ctx;
    (void)cutoff_timestamp;
    
    result.duration_ns = (now_ms() - start) * 1000000ULL;
    return result;
}
