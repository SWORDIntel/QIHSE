#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "qihse_document.h"

// Mock KV store needed to create the document store
qihse_kv_store_t* qihse_kv_store_create(void) { return NULL; }
void qihse_kv_store_destroy(qihse_kv_store_t* store) { (void)store; }

int main(void) {
    printf("Testing JIT Document Engine...\n");
    
    qihse_document_store_t* store = qihse_doc_store_create(NULL);
    if (!store) {
        printf("Failed to create document store\n");
        return 1;
    }

    // Insert some JSON documents
    const char* doc1 = "{\"name\": \"Alice\", \"age\": 30, \"score\": 85, \"active\": true}";
    const char* doc2 = "{\"name\": \"Bob\", \"age\": 20, \"score\": 90, \"active\": false}";
    const char* doc3 = "{\"name\": \"Charlie\", \"age\": 25, \"score\": 75, \"active\": true}";

    qihse_doc_store_insert_json(store, 1001, doc1);
    qihse_doc_store_insert_json(store, 1002, doc2);
    qihse_doc_store_insert_json(store, 1003, doc3);

    printf("Executing query: age >= 25 AND score > 80\n");
    qihse_document_result_t res = qihse_doc_store_query(store, "age >= 25 AND score > 80");
    
    printf("Matches found: %zu\n", res.count);
    for (size_t i = 0; i < res.count; i++) {
        printf("  - Matched doc_id: %llu\n", (unsigned long long)res.doc_ids[i]);
    }
    
    bool ok = false;
    if (res.count == 1 && res.doc_ids[0] == 1001) {
        printf("PASS\n");
        ok = true;
    } else {
        printf("FAIL\n");
    }

    free(res.doc_ids);
    qihse_doc_store_destroy(store);
    
    return ok ? 0 : 1;
}
