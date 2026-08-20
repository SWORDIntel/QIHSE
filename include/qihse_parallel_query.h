#ifndef QIHSE_PARALLEL_QUERY_H
#define QIHSE_PARALLEL_QUERY_H

#include "qihse_kv_store.h"
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int num_workers;
    pthread_t* worker_threads;
    volatile int shutdown;
    pthread_mutex_t lock;
} qihse_parallel_ctx_t;

typedef struct {
    char* table_name;
    size_t total_rows;
    size_t rows_per_worker;
    void** results;
    size_t* result_counts;
} qihse_parallel_scan_t;

qihse_parallel_ctx_t* qihse_parallel_init(int num_workers);
int qihse_parallel_scan(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* table_prefix,
                        qihse_parallel_scan_t* out_scan);
void qihse_parallel_cleanup(qihse_parallel_ctx_t* ctx);

int qihse_parallel_join(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                        const char* left_table, const char* right_table,
                        const char* join_key);

int qihse_parallel_aggregate(qihse_parallel_ctx_t* ctx, qihse_kv_store_t* kv,
                             const char* table_name, const char* agg_column,
                             const char* agg_func,
                             double* out_result);

#ifdef __cplusplus
}
#endif
#endif
