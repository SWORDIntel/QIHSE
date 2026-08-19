#ifndef QIHSE_TASK_WORKER_H
#define QIHSE_TASK_WORKER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "qihse_task_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_WORKER_IDLE = 0,
    QIHSE_WORKER_BUSY = 1,
    QIHSE_WORKER_PAUSED = 2,
    QIHSE_WORKER_STOPPING = 3,
    QIHSE_WORKER_STOPPED = 4
} qihse_worker_state_t;

typedef struct {
    uint32_t worker_id;
    int cpu_core_id;
    int numa_node_id;
    qihse_worker_state_t state;
    char current_task_id[QIHSE_TASK_ID_LEN + 1];
    uint64_t tasks_completed;
    uint64_t tasks_failed;
    uint64_t uptime_seconds;
} qihse_worker_info_t;

typedef bool (*qihse_task_handler_fn)(
    const qihse_task_t* task,
    uint8_t** out_result,
    size_t* out_len,
    char* out_error,
    size_t err_len,
    void* user_ctx
);

typedef struct {
    qihse_task_queue_t* queue;
    uint32_t worker_count;
    bool pin_cores;
    int numa_node_id;
    const char* python_binary;
    qihse_task_handler_fn custom_handler;
    void* custom_handler_ctx;
} qihse_task_worker_pool_config_t;

typedef struct qihse_task_worker_pool qihse_task_worker_pool_t;

void qihse_task_worker_pool_config_init(qihse_task_worker_pool_config_t* config);

qihse_task_worker_pool_t* qihse_task_worker_pool_create(const qihse_task_worker_pool_config_t* config);
bool qihse_task_worker_pool_start(qihse_task_worker_pool_t* pool);
void qihse_task_worker_pool_pause(qihse_task_worker_pool_t* pool);
void qihse_task_worker_pool_resume(qihse_task_worker_pool_t* pool);
void qihse_task_worker_pool_stop(qihse_task_worker_pool_t* pool);
void qihse_task_worker_pool_destroy(qihse_task_worker_pool_t* pool);

bool qihse_task_worker_pool_get_info(
    qihse_task_worker_pool_t* pool,
    qihse_worker_info_t** out_info,
    size_t* out_count
);

void qihse_task_worker_pool_free_info(qihse_worker_info_t* info);

bool qihse_task_worker_pool_set_count(
    qihse_task_worker_pool_t* pool,
    uint32_t new_count
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TASK_WORKER_H */
