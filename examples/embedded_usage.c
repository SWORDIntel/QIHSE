#include "../include/qihse_vector_db.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("--- QIHSE Embedded Database Framework Test ---\n\n");

    // 1. A systems developer initializes the embedded DB in their own process
    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_AUTO, 
        NULL, 
        "data/embedded_qihse", 
        QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED
    );

    if (!db) {
        printf("Failed to open embedded database.\n");
        return 1;
    }
    printf("[Embedded] Opened database locally.\n");

    // 2. They pass a raw SQL string to the engine
    const char* sql = "SELECT * FROM documents WHERE tenant_id = 42 ORDER BY embedding <=> '[0.1, 0.2]' LIMIT 5";
    printf("[Embedded] Executing SQL: %s\n", sql);
    
    // 3. The framework parses, compiles, and executes entirely in C memory
    qihse_result_set_t* rs_sql = qihse_execute_sql(db, sql);
    if (rs_sql && rs_sql->count > 0) {
        printf("[Embedded] SQL execution found %zu results (Top ID: %lu, Score: %.2f)\n", 
            rs_sql->count, rs_sql->results[0].id, rs_sql->results[0].score);
    }

    // 4. They can also use native QQL Graph syntax directly
    const char* qql = "MATCH (d:Document) SEARCH d.vec WITH VEC([0.1, 0.2]) USING MODE qmag YIELD d LIMIT 5";
    printf("\n[Embedded] Executing Native QQL: %s\n", qql);
    
    qihse_result_set_t* rs_qql = qihse_execute_qql(db, qql);
    if (rs_qql && rs_qql->count > 0) {
        printf("[Embedded] QQL execution found %zu results (Top ID: %lu, Score: %.2f)\n", 
            rs_qql->count, rs_qql->results[0].id, rs_qql->results[0].score);
    }

    // Clean up
    qihse_free_result_set(rs_sql);
    qihse_free_result_set(rs_qql);
    qihse_vector_db_close(db);

    printf("\n--- Test Complete ---\n");
    return 0;
}
