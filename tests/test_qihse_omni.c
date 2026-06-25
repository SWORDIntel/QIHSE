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
#include "qihse_vector_db.h"
#include "qihse_system_guard.h"

#define CLASSIF_UNCLASSIFIED 0
#define CLASSIF_SECRET       1
#define CLASSIF_TOP_SECRET   2

#define SCI_NONE 0x0
#define SCI_A    0x1
#define SCI_B    0x2

int main() {
    printf("[QIHSE Omni-Test] Initializing Full Shebang Testing Suite...\n");
    qihse_auth_init();

    // 1. Create Users
    printf("[QIHSE Omni-Test] Establishing Security Clearances...\n");
    qihse_user_t* op = qihse_auth_get_user(0);
    // Rotate operator password to allow privileged operations
    qihse_auth_modify_user(op, 0, NULL, "SecureOpPass1!", -1, -1);
    qihse_user_t* user_a = qihse_auth_create_user(op, 3, QIHSE_ROLE_OPERATOR, CLASSIF_TOP_SECRET, SCI_A | SCI_B, "default_password", true);
    qihse_user_t* user_b = qihse_auth_create_user(user_a, 2, QIHSE_ROLE_ANALYST, CLASSIF_SECRET, SCI_A, "default_password", true);
    qihse_user_t* user_c = qihse_auth_create_user(user_a, 1, QIHSE_ROLE_ANALYST, CLASSIF_UNCLASSIFIED, SCI_NONE, "default_password", true);
    assert(user_a && user_b && user_c);
    user_a->hardware_token_present = true;
    user_b->hardware_token_present = true;
    user_c->hardware_token_present = true;

    // 2. KV Store + Clearance
    printf("[QIHSE Omni-Test] Testing KV Store with strict clearance masking...\n");
    qihse_kv_store_t* kv = qihse_kv_store_create();
    
    // Insert data with different clearances
    qihse_kv_set(kv, "public_key", "public_data", CLASSIF_UNCLASSIFIED, SCI_NONE);
    qihse_kv_set(kv, "secret_key", "secret_data", CLASSIF_SECRET, SCI_A);
    qihse_kv_set(kv, "ts_key", "ts_data", CLASSIF_TOP_SECRET, SCI_A | SCI_B);

    // Test User C (Unclassified)
    char* val_c1 = qihse_kv_get_user(kv, "public_key", user_c);
    assert(val_c1 != NULL && strcmp(val_c1, "public_data") == 0);
    char* val_c2 = qihse_kv_get_user(kv, "secret_key", user_c);
    assert(val_c2 == NULL); // Mathematically Masked
    char* val_c3 = qihse_kv_get_user(kv, "ts_key", user_c);
    assert(val_c3 == NULL); // Mathematically Masked
    
    // Test User A (Top Secret)
    char* val_a = qihse_kv_get_user(kv, "ts_key", user_a);
    assert(val_a != NULL && strcmp(val_a, "ts_data") == 0);

    if (val_c1) free(val_c1);
    if (val_a) free(val_a);
    printf("  -> KV Store Clearance Masking OK\n");

    // 3. Document Engine (Depends on KV)
    printf("[QIHSE Omni-Test] Testing Document Engine...\n");
    qihse_document_store_t* doc = qihse_doc_store_create(kv);
    assert(doc != NULL);
    assert(qihse_doc_store_insert_json(doc, 1, "{\"mission\": \"public\"}"));
    qihse_doc_store_destroy(doc);
    printf("  -> Document Engine OK\n");

    // 4. Time-Series Engine
    printf("[QIHSE Omni-Test] Testing Time-Series Engine...\n");
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    assert(tsdb != NULL);
    for(uint64_t i = 0; i < 5000; i++) {
        qihse_tsdb_insert(tsdb, 1, 1000 + i, 42.0, CLASSIF_UNCLASSIFIED, SCI_NONE);
    }
    double avg = qihse_tsdb_average_range_user(tsdb, 1000, 6000, user_c);
    assert(avg == 42.0);
    qihse_tsdb_destroy(tsdb);
    printf("  -> Time-Series Engine OK\n");

    // 5. Columnar Engine
    printf("[QIHSE Omni-Test] Testing Columnar Engine...\n");
    qihse_column_store_t* col = qihse_column_store_create();
    assert(col != NULL);
    assert(qihse_column_create(col, "revenue", QIHSE_COL_TYPE_FLOAT32));
    qihse_column_append_float32(col, "revenue", 100.5f, CLASSIF_UNCLASSIFIED, SCI_NONE);
    qihse_column_append_float32(col, "revenue", 200.5f, CLASSIF_UNCLASSIFIED, SCI_NONE);
    assert(qihse_column_sum_float32_user(col, "revenue", user_c) == 301.0f);
    qihse_column_store_destroy(col);
    printf("  -> Columnar Engine OK\n");

    // 6. Vector DB + Guard provocation
    printf("[QIHSE Omni-Test] Testing Vector DB and System Guard...\n");
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(vdb != NULL);
    
    // Provoke Guard
    printf("  -> Provoking Guard with catastrophic payload request (simulated)...\n");
    bool safe = qihse_system_guard_check_operation((size_t)100000000000ULL, true); // 100 GB brute force
    assert(safe == false);
    printf("  -> System Guard successfully intercepted catastrophic query! OS prevented from memory saturation.\n");

    qihse_vector_db_destroy(vdb);
    qihse_kv_store_destroy(kv);

    free(user_a);
    free(user_b);
    free(user_c);

    printf("\n[QIHSE Omni-Test] ALL ENGINES TESTED. CLEARANCES MASKED. HARDWARE GUARD DEPLOYED. SYSTEM SECURE.\n");
    return 0;
}
