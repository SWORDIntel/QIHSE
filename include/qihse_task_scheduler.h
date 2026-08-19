#ifndef QIHSE_TASK_SCHEDULER_H
#define QIHSE_TASK_SCHEDULER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "qihse_task_queue.h"
#include "qihse_timeseries.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_SCHEDULE_ID_MAX 64
#define QIHSE_CRON_EXPR_MAX 128

typedef struct {
    char schedule_id[QIHSE_SCHEDULE_ID_MAX];
    char cron_expr[QIHSE_CRON_EXPR_MAX];
    char queue_name[QIHSE_TASK_QUEUE_NAME_MAX];
    qihse_task_prio_t priority;
    uint8_t* payload;
    size_t payload_len;
    bool enabled;
    uint64_t last_fired_ns;
    uint64_t next_fire_ns;
    uint64_t fire_count;
} qihse_schedule_entry_t;

typedef struct {
    qihse_task_queue_t* queue;
    qihse_tsdb_t* tsdb;
    uint32_t tick_ms;
} qihse_task_scheduler_config_t;

typedef struct qihse_task_scheduler qihse_task_scheduler_t;

void qihse_task_scheduler_config_init(qihse_task_scheduler_config_t* config);

qihse_task_scheduler_t* qihse_task_scheduler_create(const qihse_task_scheduler_config_t* config);
bool qihse_task_scheduler_start(qihse_task_scheduler_t* scheduler);
void qihse_task_scheduler_stop(qihse_task_scheduler_t* scheduler);
void qihse_task_scheduler_destroy(qihse_task_scheduler_t* scheduler);

bool qihse_task_scheduler_add(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id,
    const char* cron_expr,
    const char* queue_name,
    qihse_task_prio_t priority,
    const uint8_t* payload,
    size_t payload_len
);

bool qihse_task_scheduler_remove(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id
);

bool qihse_task_scheduler_enable(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id,
    bool enable
);

bool qihse_task_scheduler_list(
    qihse_task_scheduler_t* scheduler,
    char*** out_schedule_ids,
    size_t* out_count
);

void qihse_task_scheduler_free_list(char** schedule_ids, size_t count);

bool qihse_task_scheduler_next_fire(
    qihse_task_scheduler_t* scheduler,
    const char* schedule_id,
    char* out_iso8601,
    size_t buf_len
);

bool qihse_task_scheduler_parse_cron_next(
    const char* cron_expr,
    time_t from_time,
    time_t* out_next_time
);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TASK_SCHEDULER_H */
