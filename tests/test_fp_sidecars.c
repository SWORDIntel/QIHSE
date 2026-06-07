#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "qihse_vector_db.h"
#include "qihse_uma.h"

// Basic mock/harness logic just to test the integration.
int main() {
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    if (!vdb) {
        printf("Failed to create vector DB\n");
        return 1;
    }

    // 1. Add some dummy vectors
    float vectors[3 * 4] = {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f,
        0.5f, 0.5f, 0.0f, 0.0f
    };
    uint64_t ids[3] = {1, 2, 3};
    bool ok = qihse_vector_db_add_vectors(vdb, vectors, 3, 4, ids, NULL, NULL);
    if (!ok) {
        printf("Failed to add vectors\n");
        return 1;
    }
    printf("[+] Added vectors.\n");

    // 2. Test NULL robustness
    if (qihse_vector_db_build_fp16(NULL)) {
        printf("[-] FAILED: build_fp16 accepted NULL\n");
        return 1;
    }
    if (qihse_vector_db_build_fp32(NULL)) {
        printf("[-] FAILED: build_fp32 accepted NULL\n");
        return 1;
    }
    printf("[+] NULL handling passed.\n");

    // 3. Build sidecars
    ok = qihse_vector_db_build_fp16(vdb);
    if (!ok) {
        printf("[-] Failed to build FP16\n");
        return 1;
    }
    printf("[+] Built FP16 sidecar.\n");

    ok = qihse_vector_db_build_fp32(vdb);
    if (!ok) {
        printf("[-] Failed to build FP32\n");
        return 1;
    }
    printf("[+] Built FP32 sidecar.\n");

    // 4. Test missing statuses (query should gracefully handle valid/invalid statuses)
    qihse_vector_query_t q;
    memset(&q, 0, sizeof(q));
    q.query_vector = vectors; // Query for vector 1
    q.vector_dims = 4;
    q.top_k = 1;

    qihse_vector_result_t res[1];

    q.query_mode = QIHSE_VDB_QUERY_FP16;
    int n = qihse_vector_db_search(vdb, &q, res, 1);
    if (n < 0) {
        printf("[-] FP16 search failed: %d\n", n);
        return 1;
    }
    printf("[+] FP16 search returned %d results.\n", n);

    q.query_mode = QIHSE_VDB_QUERY_FP32;
    n = qihse_vector_db_search(vdb, &q, res, 1);
    if (n < 0) {
        printf("[-] FP32 search failed: %d\n", n);
        return 1;
    }
    printf("[+] FP32 search returned %d results.\n", n);
    
    // Check results
    if (res[0].id != 1) {
        printf("[-] Expected vector ID 1, got %llu\n", (unsigned long long)res[0].id);
        return 1;
    }

    qihse_vector_db_destroy(vdb);

    printf("ALL TESTS PASSED.\n");
    return 0;
}
