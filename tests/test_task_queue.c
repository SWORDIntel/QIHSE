#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "qihse_task_queue.h"

int main(void) {
    printf("=== Testing QIHSE Task Queue ===\n");

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    qihse_task_queue_config_t config;
    config.kv_store = kv;
    config.event_stream = NULL;
    config.tsdb = NULL;
    config.max_queue_capacity = 1000u;

    qihse_task_queue_t* queue = qihse_task_queue_create(&config);
    assert(queue != NULL);

    /* Test 1: Submit tasks with different priorities */
    char id_crit[QIHSE_TASK_ID_LEN + 1];
    char id_high[QIHSE_TASK_ID_LEN + 1];
    char id_norm[QIHSE_TASK_ID_LEN + 1];
    char id_low[QIHSE_TASK_ID_LEN + 1];

    const char* p_low = "{\"task\":\"low_priority\"}";
    const char* p_norm = "{\"task\":\"normal_priority\"}";
    const char* p_high = "{\"task\":\"high_priority\"}";
    const char* p_crit = "{\"task\":\"critical_priority\"}";

    /* Submit in reverse priority order */
    assert(qihse_task_submit(queue, "test_q", QIHSE_TASK_PRIO_LOW, (const uint8_t*)p_low, strlen(p_low), NULL, id_low, sizeof(id_low)));
    assert(qihse_task_submit(queue, "test_q", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)p_norm, strlen(p_norm), NULL, id_norm, sizeof(id_norm)));
    assert(qihse_task_submit(queue, "test_q", QIHSE_TASK_PRIO_HIGH, (const uint8_t*)p_high, strlen(p_high), NULL, id_high, sizeof(id_high)));
    assert(qihse_task_submit(queue, "test_q", QIHSE_TASK_PRIO_CRITICAL, (const uint8_t*)p_crit, strlen(p_crit), NULL, id_crit, sizeof(id_crit)));

    printf("  [✔] Submissions with 4 priority levels succeeded\n");

    /* Test 2: Check status */
    qihse_task_state_t st;
    assert(qihse_task_get_state(queue, id_crit, &st) && st == QIHSE_TASK_PENDING);
    assert(qihse_task_get_state(queue, id_low, &st) && st == QIHSE_TASK_PENDING);
    printf("  [✔] Task states correctly initialized to PENDING\n");

    /* Test 3: Verify priority drain order (CRITICAL -> HIGH -> NORMAL -> LOW) */
    qihse_task_t* t1 = qihse_task_pop(queue, 10u);
    assert(t1 != NULL && strcmp(t1->task_id, id_crit) == 0);
    assert(t1->priority == QIHSE_TASK_PRIO_CRITICAL && t1->state == QIHSE_TASK_STARTED);

    qihse_task_t* t2 = qihse_task_pop(queue, 10u);
    assert(t2 != NULL && strcmp(t2->task_id, id_high) == 0);
    assert(t2->priority == QIHSE_TASK_PRIO_HIGH);

    qihse_task_t* t3 = qihse_task_pop(queue, 10u);
    assert(t3 != NULL && strcmp(t3->task_id, id_norm) == 0);
    assert(t3->priority == QIHSE_TASK_PRIO_NORMAL);

    qihse_task_t* t4 = qihse_task_pop(queue, 10u);
    assert(t4 != NULL && strcmp(t4->task_id, id_low) == 0);
    assert(t4->priority == QIHSE_TASK_PRIO_LOW);

    printf("  [✔] Strict priority ordering verified (CRITICAL -> HIGH -> NORMAL -> LOW)\n");

    /* Test 4: Complete task and get result */
    const char* result_data = "{\"result\": 42}";
    assert(qihse_task_complete(queue, id_crit, (const uint8_t*)result_data, strlen(result_data)));
    assert(qihse_task_get_state(queue, id_crit, &st) && st == QIHSE_TASK_SUCCESS);

    uint8_t* out_res = NULL;
    size_t out_len = 0;
    char out_err[256];
    assert(qihse_task_get_result(queue, id_crit, &out_res, &out_len, out_err, sizeof(out_err)));
    assert(out_res != NULL && out_len == strlen(result_data));
    assert(memcmp(out_res, result_data, out_len) == 0);
    free(out_res);
    printf("  [✔] Task completion and result retrieval verified\n");

    /* Test 5: Retry and Exponential Backoff */
    qihse_task_options_t opts;
    qihse_task_options_init(&opts);
    opts.max_retries = 1;
    opts.base_delay_ms = 10;
    opts.jitter_pct = 0;

    char id_retry[QIHSE_TASK_ID_LEN + 1];
    const char* p_fail = "{\"task\":\"will_fail\"}";
    assert(qihse_task_submit(queue, "retry_q", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)p_fail, strlen(p_fail), &opts, id_retry, sizeof(id_retry)));

    qihse_task_t* tr = qihse_task_pop(queue, 10u);
    assert(tr != NULL && strcmp(tr->task_id, id_retry) == 0);

    /* First failure -> RETRYING */
    assert(qihse_task_fail(queue, id_retry, "Temporary network timeout"));
    assert(qihse_task_get_state(queue, id_retry, &st) && st == QIHSE_TASK_RETRYING);

    /* Wait for backoff delay (10ms) */
    usleep(25000);

    /* Pop again should pick up re-enqueued task */
    qihse_task_t* tr2 = qihse_task_pop(queue, 50u);
    assert(tr2 != NULL && strcmp(tr2->task_id, id_retry) == 0);
    assert(tr2->retry_count == 1);

    /* Second failure -> DEAD (exceeded max_retries=1) */
    assert(qihse_task_fail(queue, id_retry, "Fatal server crash"));
    assert(qihse_task_get_state(queue, id_retry, &st) && st == QIHSE_TASK_DEAD);
    printf("  [✔] Exponential backoff retry and DEAD state transition verified\n");

    /* Test 6: Task Cancellation */
    char id_cancel[QIHSE_TASK_ID_LEN + 1];
    const char* p_cancel = "{\"task\":\"to_cancel\"}";
    assert(qihse_task_submit(queue, "cancel_q", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)p_cancel, strlen(p_cancel), NULL, id_cancel, sizeof(id_cancel)));
    assert(qihse_task_cancel(queue, id_cancel));
    assert(qihse_task_get_state(queue, id_cancel, &st) && st == QIHSE_TASK_CANCELLED);
    /* Pop should return NULL since cancelled task was removed from priority queue */
    qihse_task_t* tc = qihse_task_pop(queue, 10u);
    assert(tc == NULL);
    printf("  [✔] Task cancellation verified\n");

    /* Test 7: Queue stats & listing */
    qihse_task_stats_t stats;
    assert(qihse_task_stats(queue, NULL, &stats));
    assert(stats.success_count >= 1);
    assert(stats.dead_count >= 1);
    assert(stats.cancelled_count >= 1);

    char** ids = NULL;
    size_t count = 0;
    assert(qihse_task_list_queue(queue, "test_q", &ids, &count));
    assert(count == 4);
    qihse_task_free_id_list(ids, count);
    printf("  [✔] Queue statistics and task listing verified\n");

    /* Cleanup */
    qihse_task_queue_destroy(queue);
    qihse_kv_store_destroy(kv);

    printf("=== All Task Queue Tests Passed ===\n\n");
    return 0;
}
