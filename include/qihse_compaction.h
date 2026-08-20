#ifndef QIHSE_COMPACTION_H
#define QIHSE_COMPACTION_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    COMPACTION_KV = 0,
    COMPACTION_COLUMNAR = 1,
    COMPACTION_DOCUMENT = 2,
    COMPACTION_TIMESERIES = 3,
    COMPACTION_ALL = 4
} compaction_engine_t;

typedef struct {
    compaction_engine_t engine;
    uint64_t start_time;
    uint64_t end_time;
    size_t keys_compacted;
    size_t bytes_reclaimed;
    size_t sstables_merged;
    int status;  /* 0=success, 1=running, -1=error */
} qihse_compaction_result_t;

typedef struct {
    pthread_t thread;
    volatile int running;
    volatile int shutdown;
    int interval_seconds;
    pthread_mutex_t lock;
    void* kv_store;
    void* column_store;
    void* document_store;
    void* timeseries_store;
} qihse_compaction_ctx_t;

qihse_compaction_ctx_t* qihse_compaction_create(void);
int qihse_compaction_set_kv(qihse_compaction_ctx_t* ctx, void* kv);
int qihse_compaction_set_columnar(qihse_compaction_ctx_t* ctx, void* col);
int qihse_compaction_set_document(qihse_compaction_ctx_t* ctx, void* doc);
int qihse_compaction_set_timeseries(qihse_compaction_ctx_t* ctx, void* ts);
int qihse_compaction_start(qihse_compaction_ctx_t* ctx, int interval_seconds);
int qihse_compaction_stop(qihse_compaction_ctx_t* ctx);
void qihse_compaction_destroy(qihse_compaction_ctx_t* ctx);

qihse_compaction_result_t qihse_compaction_run(qihse_compaction_ctx_t* ctx, compaction_engine_t engine);

/* TTL sweep */
typedef struct {
    size_t keys_expired;
    size_t bytes_reclaimed;
    uint64_t duration_ns;
} qihse_ttl_result_t;

qihse_ttl_result_t qihse_ttl_sweep(qihse_compaction_ctx_t* ctx, int64_t cutoff_timestamp);

#ifdef __cplusplus
}
#endif
#endif
