#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

/* QIHSE Headers */
#include "qihse_kv_store.h"
#include "qihse_column.h"
#include "qihse_timeseries.h"
#include "qihse_event_stream.h"
#include "qihse_document.h"

#include "qihse_auth.h"

int main() {
    printf("[QIHSE E2E] Commencing Full Engine Spin-Up...\n");

    qihse_auth_init();
    qihse_user_t* test_user = qihse_auth_get_user(0);

    /* 1. KV Store */
    printf("[QIHSE E2E]    // --- KV Store ---\n");
    qihse_kv_store_t* kv = qihse_kv_store_create();
    assert(qihse_kv_set_user(kv, "test_key", "test_value", 0, 0, test_user));
    char* val = qihse_kv_get_user(kv, "test_key", test_user);
    assert(val != NULL);
    assert(strcmp(val, "test_value") == 0);
    free(val);

    // --- Column Store ---
    qihse_column_store_t* col = qihse_column_store_create();
    qihse_column_create(col, "revenue", QIHSE_COL_TYPE_FLOAT32);
    qihse_column_append_float32(col, "revenue", 100.5f, 0, 0);
    qihse_column_append_float32(col, "revenue", 200.5f, 0, 0);
    float sum = qihse_column_sum_float32_user(col, "revenue", test_user);
    assert(sum == 301.0f);
    qihse_column_store_destroy(col);

    // --- Time-Series DB ---
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    for(int i=0; i<100; i++) {
        qihse_tsdb_insert(tsdb, 1, 1000 + i, 42.0, 0, 0);
    }
    double avg = qihse_tsdb_average_range_user(tsdb, 1000, 6000, test_user);
    assert(avg == 42.0);
    qihse_tsdb_destroy(tsdb);
    printf("  -> Time-Series Engine OK\n");

    /* 4. Document Store */
    printf("[QIHSE E2E] Testing Document Engine...\n");
    qihse_document_store_t* doc = qihse_doc_store_create(kv);
    assert(doc != NULL);
    assert(qihse_doc_store_insert_json(doc, 1, "{\"field\": \"value\"}"));
    qihse_doc_store_destroy(doc);
    printf("  -> Document Engine OK\n");

    /* 5. Event Stream */
    printf("[QIHSE E2E] Testing Event Stream...\n");
    system("rm -rf /tmp/qihse_logs && mkdir -p /tmp/qihse_logs");
    qihse_event_stream_t* stream = qihse_event_stream_create("/tmp/qihse_logs");
    assert(stream != NULL);
    const uint8_t payload[] = "event_data";
    assert(qihse_event_stream_append(stream, "test_topic", payload, sizeof(payload)));
    qihse_event_stream_destroy(stream);
    printf("  -> Event Stream OK\n");

    qihse_kv_store_destroy(kv);
    printf("\n[QIHSE E2E] ALL SYSTEMS OPERATIONAL. NO SEGFAULTS DETECTED.\n");
    return 0;
}
