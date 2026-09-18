#include "../include/qihse_vector_db.h"
#include "../include/qihse_auth.h"
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

    // 2. Embedded query execution is a classified-capable read primitive, so it
    //    takes an explicit authenticated context and fails closed without one
    //    (AGENTS.md invariant 1).  There is no context-free qihse_execute_*().
    if (!qihse_auth_init()) {
        printf("Failed to initialise auth.\n");
        qihse_vector_db_close(db);
        return 1;
    }
    if (!qihse_auth_bootstrap_operator("embedded-demo-password")) {
        printf("Failed to bootstrap the operator principal.\n");
        qihse_vector_db_close(db);
        return 1;
    }
    qihse_user_t* user = qihse_auth_authenticate_id(0, "embedded-demo-password");
    if (!user) {
        printf("Failed to authenticate the operator principal.\n");
        qihse_vector_db_close(db);
        return 1;
    }

    // 3. They pass a raw SQL string to the engine
    const char* sql = "SELECT * FROM documents WHERE tenant_id = 42 ORDER BY embedding <=> '[0.1, 0.2]' LIMIT 5";
    printf("[Embedded] Executing SQL: %s\n", sql);
    
    // 4. The framework parses, compiles, and executes entirely in C memory
    qihse_result_set_t* rs_sql = qihse_execute_sql_user(db, user, sql);
    if (rs_sql && rs_sql->count > 0) {
        printf("[Embedded] SQL execution found %zu results (Top ID: %lu, Score: %.2f)\n", 
            rs_sql->count, rs_sql->results[0].id, rs_sql->results[0].score);
    }

    // 5. They can also use native QQL Graph syntax directly
    const char* qql = "MATCH (d:Document) SEARCH d.vec WITH VEC([0.1, 0.2]) USING MODE qmag YIELD d LIMIT 5";
    printf("\n[Embedded] Executing Native QQL: %s\n", qql);
    
    qihse_result_set_t* rs_qql = qihse_execute_qql_user(db, user, qql);
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
