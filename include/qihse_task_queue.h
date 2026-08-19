#ifndef QIHSE_TASK_QUEUE_H
#define QIHSE_TASK_QUEUE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "qihse_kv_store.h"
#include "qihse_event_stream.h"
#include "qihse_timeseries.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_TASK_ID_LEN 96
#define QIHSE_TASK_QUEUE_NAME_MAX 64
#define QIHSE_TASK_ERROR_MAX 256
#define QIHSE_TASK_DEFAULT_MAX_RETRIES 3
#define QIHSE_TASK_DEFAULT_BASE_DELAY_MS 1000
#define QIHSE_TASK_DEFAULT_MAX_DELAY_MS 60000
#define QIHSE_TASK_DEFAULT_TIMEOUT_MS 30000
#define QIHSE_TASK_DEFAULT_RESULT_TTL_MS 86400000ULL /* 24 hours */

typedef enum {
    QIHSE_TASK_PENDING = 0,
    QIHSE_TASK_STARTED = 1,
    QIHSE_TASK_SUCCESS = 2,
    QIHSE_TASK_FAILURE = 3,
    QIHSE_TASK_RETRYING = 4,
    QIHSE_TASK_DEAD = 5,
    QIHSE_TASK_CANCELLED = 6
} qihse_task_state_t;

typedef enum {
    QIHSE_TASK_PRIO_CRITICAL = 0,
    QIHSE_TASK_PRIO_HIGH = 1,
    QIHSE_TASK_PRIO_NORMAL = 2,
    QIHSE_TASK_PRIO_LOW = 3,
    QIHSE_TASK_PRIO_COUNT = 4
} qihse_task_prio_t;

typedef struct {
    uint32_t max_retries;
    uint64_t base_delay_ms;
    uint64_t max_delay_ms;
    double backoff_factor;
    uint32_t jitter_pct;
    uint64_t timeout_ms;
    uint64_t result_ttl_ms;
} qihse_task_options_t;

typedef struct qihse_task {
    char task_id[QIHSE_TASK_ID_LEN + 1];
    char queue_name[QIHSE_TASK_QUEUE_NAME_MAX];
    qihse_task_prio_t priority;
    qihse_task_state_t state;
    uint8_t* payload;
    size_t payload_len;
    uint8_t* result;
    size_t result_len;
    char error_msg[QIHSE_TASK_ERROR_MAX];
    uint64_t created_at_ns;
    uint64_t started_at_ns;
    uint64_t completed_at_ns;
    uint32_t retry_count;
    qihse_task_options_t opts;
    uint64_t next_retry_at_ns;
    volatile bool cancel_requested;
    struct qihse_task* next;
} qihse_task_t;

typedef struct {
    uint64_t pending_count;
    uint64_t started_count;
    uint64_t success_count;
    uint64_t failure_count;
    uint64_t dead_count;
    uint64_t cancelled_count;
    uint64_t total_executed;
    double avg_latency_ms;
} qihse_task_stats_t;

typedef struct {
    qihse_kv_store_t* kv_store;
    qihse_event_stream_t* event_stream;
    qihse_tsdb_t* tsdb;
    size_t max_queue_capacity;
} qihse_task_queue_config_t;

typedef struct qihse_task_queue qihse_task_queue_t;

void qihse_task_options_init(qihse_task_options_t* opts);

const char* qihse_task_state_name(qihse_task_state_t state);
const char* qihse_task_prio_name(qihse_task_prio_t prio);
bool qihse_task_parse_prio(const char* name, qihse_task_prio_t* out_prio);

qihse_task_queue_t* qihse_task_queue_create(const qihse_task_queue_config_t* config);
void qihse_task_queue_destroy(qihse_task_queue_t* queue);

bool qihse_task_submit(
    qihse_task_queue_t* queue,
    const char* queue_name,
    qihse_task_prio_t priority,
    const uint8_t* payload,
    size_t payload_len,
    const qihse_task_options_t* opts,
    char* out_task_id,
    size_t id_buf_len
);

bool qihse_task_get_state(
    qihse_task_queue_t* queue,
    const char* task_id,
    qihse_task_state_t* out_state
);

bool qihse_task_get_result(
    qihse_task_queue_t* queue,
    const char* task_id,
    uint8_t** out_result,
    size_t* out_result_len,
    char* out_error,
    size_t error_buf_len
);

bool qihse_task_cancel(
    qihse_task_queue_t* queue,
    const char* task_id
);

bool qihse_task_retry(
    qihse_task_queue_t* queue,
    const char* task_id
);

bool qihse_task_delete(
    qihse_task_queue_t* queue,
    const char* task_id
);

bool qihse_task_stats(
    qihse_task_queue_t* queue,
    const char* queue_name,
    qihse_task_stats_t* out_stats
);

bool qihse_task_list_queue(
    qihse_task_queue_t* queue,
    const char* queue_name,
    char*** out_task_ids,
    size_t* out_count
);

void qihse_task_free_id_list(char** task_ids, size_t count);

qihse_task_t* qihse_task_pop(
    qihse_task_queue_t* queue,
    uint32_t timeout_ms
);

bool qihse_task_complete(
    qihse_task_queue_t* queue,
    const char* task_id,
    const uint8_t* result,
    size_t result_len
);

bool qihse_task_fail(
    qihse_task_queue_t* queue,
    const char* task_id,
    const char* error_msg
);

void qihse_task_free(qihse_task_t* task);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TASK_QUEUE_H */
