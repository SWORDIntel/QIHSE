#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include "qihse_task_queue.h"
#include "qihse_task_scheduler.h"

int main(void) {
    printf("=== Testing QIHSE Periodic Task Scheduler ===\n");

    /* Test 1: Cron parsing calculations */
    time_t base_time = 1700000000; /* fixed timestamp */
    time_t next_t = 0;

    /* Every 15 minutes: */
    assert(qihse_task_scheduler_parse_cron_next("*/15 * * * *", base_time, &next_t));
    assert(next_t > base_time);
    struct tm tm_val;
    gmtime_r(&next_t, &tm_val);
    assert(tm_val.tm_min % 15 == 0);
    assert(tm_val.tm_sec == 0);
    printf("  [✔] Cron parsing */15 * * * * verified (next minute: %d)\n", tm_val.tm_min);

    /* Daily at 02:00 */
    assert(qihse_task_scheduler_parse_cron_next("0 2 * * *", base_time, &next_t));
    gmtime_r(&next_t, &tm_val);
    assert(tm_val.tm_hour == 2 && tm_val.tm_min == 0);
    printf("  [✔] Cron parsing 0 2 * * * verified (next hour: %d, min: %d)\n", tm_val.tm_hour, tm_val.tm_min);

    /* Test 2: Live scheduler instance with Task Queue */
    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    qihse_task_queue_config_t q_cfg;
    q_cfg.kv_store = kv;
    q_cfg.event_stream = NULL;
    q_cfg.tsdb = NULL;
    q_cfg.max_queue_capacity = 1000u;

    qihse_task_queue_t* queue = qihse_task_queue_create(&q_cfg);
    assert(queue != NULL);

    qihse_task_scheduler_config_t s_cfg;
    qihse_task_scheduler_config_init(&s_cfg);
    s_cfg.queue = queue;
    s_cfg.tsdb = NULL;
    s_cfg.tick_ms = 10u;

    qihse_task_scheduler_t* scheduler = qihse_task_scheduler_create(&s_cfg);
    assert(scheduler != NULL);

    /* Add schedules */
    const char* p1 = "{\"job\":\"cleanup\"}";
    assert(qihse_task_scheduler_add(scheduler, "job_cleanup", "* * * * *", "maintenance", QIHSE_TASK_PRIO_LOW, (const uint8_t*)p1, strlen(p1)));
    assert(qihse_task_scheduler_add(scheduler, "job_report", "0 0 * * *", "analytics", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)p1, strlen(p1)));

    /* Test 3: List schedules */
    char** ids = NULL;
    size_t count = 0;
    assert(qihse_task_scheduler_list(scheduler, &ids, &count));
    assert(count == 2);
    assert(strcmp(ids[0], "job_cleanup") == 0 || strcmp(ids[1], "job_cleanup") == 0);
    qihse_task_scheduler_free_list(ids, count);
    printf("  [✔] Schedule registration and listing verified\n");

    /* Test 4: Next fire ISO string */
    char iso[64] = {0};
    assert(qihse_task_scheduler_next_fire(scheduler, "job_cleanup", iso, sizeof(iso)));
    assert(strlen(iso) > 10 && strchr(iso, 'T') != NULL);
    printf("  [✔] Next fire timestamp formatted: %s\n", iso);

    /* Test 5: Enable / Disable */
    assert(qihse_task_scheduler_enable(scheduler, "job_cleanup", false));
    assert(qihse_task_scheduler_enable(scheduler, "job_cleanup", true));

    /* Test 6: Remove */
    assert(qihse_task_scheduler_remove(scheduler, "job_report"));
    assert(qihse_task_scheduler_list(scheduler, &ids, &count));
    assert(count == 1);
    assert(strcmp(ids[0], "job_cleanup") == 0);
    qihse_task_scheduler_free_list(ids, count);
    printf("  [✔] Schedule removal verified\n");

    /* Start and stop scheduler thread */
    assert(qihse_task_scheduler_start(scheduler));
    usleep(50000);
    qihse_task_scheduler_stop(scheduler);
    printf("  [✔] Scheduler thread start/stop lifecycle verified\n");

    /* Cleanup */
    qihse_task_scheduler_destroy(scheduler);
    qihse_task_queue_destroy(queue);
    qihse_kv_store_destroy(kv);

    printf("=== All Task Scheduler Tests Passed ===\n\n");
    return 0;
}
