#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "qihse_task_queue.h"
#include "qihse_task_worker.h"

static bool mock_custom_handler(
    const qihse_task_t* task,
    uint8_t** out_result,
    size_t* out_len,
    char* out_error,
    size_t err_len,
    void* user_ctx
) {
    (void)user_ctx;
    (void)err_len;
    if (strstr((const char*)task->payload, "error")) {
        snprintf(out_error, err_len, "Mock failure requested");
        return false;
    }
    const char* reply = "{\"mock\":\"success\"}";
    *out_result = (uint8_t*)strdup(reply);
    *out_len = strlen(reply);
    return true;
}

int main(void) {
    printf("=== Testing QIHSE Dedicated Task Worker Pool ===\n");

    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(kv != NULL);

    qihse_task_queue_config_t q_cfg;
    q_cfg.kv_store = kv;
    q_cfg.event_stream = NULL;
    q_cfg.tsdb = NULL;
    q_cfg.max_queue_capacity = 1000u;

    qihse_task_queue_t* queue = qihse_task_queue_create(&q_cfg);
    assert(queue != NULL);

    /* Test 1: Worker pool with custom handler */
    qihse_task_worker_pool_config_t w_cfg;
    qihse_task_worker_pool_config_init(&w_cfg);
    w_cfg.queue = queue;
    w_cfg.worker_count = 2;
    w_cfg.pin_cores = false;
    w_cfg.custom_handler = mock_custom_handler;

    qihse_task_worker_pool_t* pool = qihse_task_worker_pool_create(&w_cfg);
    assert(pool != NULL);
    assert(qihse_task_worker_pool_start(pool));

    char id1[QIHSE_TASK_ID_LEN + 1];
    char id2[QIHSE_TASK_ID_LEN + 1];
    const char* p1 = "{\"data\":\"good\"}";
    const char* p2 = "{\"data\":\"error\"}";

    assert(qihse_task_submit(queue, "default", QIHSE_TASK_PRIO_HIGH, (const uint8_t*)p1, strlen(p1), NULL, id1, sizeof(id1)));
    assert(qihse_task_submit(queue, "default", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)p2, strlen(p2), NULL, id2, sizeof(id2)));

    /* Wait for workers to process */
    for (int i = 0; i < 50; i++) {
        qihse_task_state_t s1, s2;
        qihse_task_get_state(queue, id1, &s1);
        qihse_task_get_state(queue, id2, &s2);
        if (s1 == QIHSE_TASK_SUCCESS && s2 != QIHSE_TASK_PENDING && s2 != QIHSE_TASK_STARTED) break;
        usleep(20000);
    }

    qihse_task_state_t s1, s2;
    assert(qihse_task_get_state(queue, id1, &s1) && s1 == QIHSE_TASK_SUCCESS);
    assert(qihse_task_get_state(queue, id2, &s2) && (s2 == QIHSE_TASK_RETRYING || s2 == QIHSE_TASK_DEAD));

    uint8_t* res = NULL;
    size_t rlen = 0;
    char err[256];
    assert(qihse_task_get_result(queue, id1, &res, &rlen, err, sizeof(err)));
    assert(res != NULL && strstr((char*)res, "success") != NULL);
    free(res);

    printf("  [✔] Worker pool task processing verified\n");

    /* Test 2: Worker Info retrieval */
    qihse_worker_info_t* info = NULL;
    size_t w_count = 0;
    assert(qihse_task_worker_pool_get_info(pool, &info, &w_count));
    assert(w_count == 2);
    assert(info[0].worker_id == 0);
    assert(info[1].worker_id == 1);
    qihse_task_worker_pool_free_info(info);
    printf("  [✔] Worker pool info reporting verified\n");

    /* Test 3: Pause and Resume */
    qihse_task_worker_pool_pause(pool);
    usleep(150000); /* 150ms to ensure workers enter paused sleep state */

    char id3[QIHSE_TASK_ID_LEN + 1];
    const char* p3 = "{\"data\":\"good\"}";
    assert(qihse_task_submit(queue, "default", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)p3, strlen(p3), NULL, id3, sizeof(id3)));

    usleep(50000); /* 50ms */
    qihse_task_state_t s3;
    assert(qihse_task_get_state(queue, id3, &s3) && s3 == QIHSE_TASK_PENDING);

    qihse_task_worker_pool_resume(pool);
    for (int i = 0; i < 50; i++) {
        qihse_task_get_state(queue, id3, &s3);
        if (s3 == QIHSE_TASK_SUCCESS) break;
        usleep(20000);
    }
    assert(qihse_task_get_state(queue, id3, &s3) && s3 == QIHSE_TASK_SUCCESS);
    printf("  [✔] Worker pool pause / resume verified\n");

    /* Stop pool */
    qihse_task_worker_pool_destroy(pool);

    /* Test 4: Lua Task Execution with default executor */
    w_cfg.custom_handler = NULL;
    w_cfg.worker_count = 1;
    qihse_task_worker_pool_t* lua_pool = qihse_task_worker_pool_create(&w_cfg);
    assert(lua_pool != NULL);
    assert(qihse_task_worker_pool_start(lua_pool));

    char id_lua[QIHSE_TASK_ID_LEN + 1];
    const char* lua_code = "lua: local x = 10; local y = 32; return tostring(x + y)";
    assert(qihse_task_submit(queue, "lua_q", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)lua_code, strlen(lua_code), NULL, id_lua, sizeof(id_lua)));

    qihse_task_state_t s_lua = QIHSE_TASK_PENDING;
    for (int i = 0; i < 50; i++) {
        qihse_task_get_state(queue, id_lua, &s_lua);
        if (s_lua == QIHSE_TASK_SUCCESS) break;
        usleep(20000);
    }
    assert(s_lua == QIHSE_TASK_SUCCESS);

    uint8_t* lua_res = NULL;
    size_t lua_len = 0;
    assert(qihse_task_get_result(queue, id_lua, &lua_res, &lua_len, err, sizeof(err)));
    assert(lua_res != NULL && strcmp((char*)lua_res, "42") == 0);
    free(lua_res);
    printf("  [✔] Native sandboxed Lua task execution verified (result: 42)\n");

    qihse_task_worker_pool_destroy(lua_pool);

    /* Test 5: Python Subprocess Task Execution */
    qihse_task_worker_pool_t* py_pool = qihse_task_worker_pool_create(&w_cfg);
    assert(py_pool != NULL);
    assert(qihse_task_worker_pool_start(py_pool));

    char id_py[QIHSE_TASK_ID_LEN + 1];
    const char* py_payload = "{\"func\": \"math.sqrt\", \"args\": [144]}";
    assert(qihse_task_submit(queue, "py_q", QIHSE_TASK_PRIO_NORMAL, (const uint8_t*)py_payload, strlen(py_payload), NULL, id_py, sizeof(id_py)));

    qihse_task_state_t s_py = QIHSE_TASK_PENDING;
    for (int i = 0; i < 100; i++) {
        qihse_task_get_state(queue, id_py, &s_py);
        if (s_py == QIHSE_TASK_SUCCESS) break;
        usleep(20000);
    }
    assert(s_py == QIHSE_TASK_SUCCESS);

    uint8_t* py_res = NULL;
    size_t py_len = 0;
    assert(qihse_task_get_result(queue, id_py, &py_res, &py_len, err, sizeof(err)));
    assert(py_res != NULL && py_len > 0);
    free(py_res);
    printf("  [✔] Python subprocess task execution (math.sqrt(144)) verified\n");

    qihse_task_worker_pool_destroy(py_pool);

    /* Cleanup */
    qihse_task_queue_destroy(queue);
    qihse_kv_store_destroy(kv);

    printf("=== All Task Worker Tests Passed ===\n\n");
    return 0;
}
