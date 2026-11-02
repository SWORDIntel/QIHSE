#include "../include/qihse_vector_db.h"
#include "../include/qihse_auth.h"
#include "../include/qihse_uwp_sql_txn_schema.h"
#include "../include/qihse_schema.h"
#include "../include/qihse_txn.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("--- QIHSE Embedded Database Framework Test ---\n\n");

    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_AUTO, NULL, "data/embedded_qihse",
        QIHSE_VDB_OPEN_CREATE | QIHSE_VDB_OPEN_FILE_BACKED);
    if (!db) {
        fprintf(stderr, "Failed to open embedded vector database.\n");
        return 1;
    }

    if (!qihse_auth_init() ||
        !qihse_auth_bootstrap_operator("embedded-demo-password")) {
        fprintf(stderr, "Failed to initialize/authenticate the operator.\n");
        qihse_vector_db_close(db);
        return 1;
    }
    qihse_user_t* user = qihse_auth_authenticate_id(
        0, "embedded-demo-password");
    if (!user) {
        fprintf(stderr, "Failed to authenticate the operator principal.\n");
        qihse_vector_db_close(db);
        return 1;
    }

    /* SQL needs its UWP context, schema and transaction state. Bind a durable
     * store with qihse_uwp_sql_open_durable() when persistence is required. */
    qihse_uwp_context_t sql_ctx = {0};
    static int sql_engine_anchor;
    sql_ctx.sql_engine = &sql_engine_anchor;
    sql_ctx.schema = qihse_schema_registry_create();
    sql_ctx.txn_manager = qihse_txn_manager_create();
    if (!sql_ctx.schema || !sql_ctx.txn_manager) {
        fprintf(stderr, "Failed to initialize embedded SQL context.\n");
        qihse_schema_registry_destroy((qihse_schema_registry_t*)sql_ctx.schema);
        qihse_txn_manager_destroy(sql_ctx.txn_manager);
        qihse_vector_db_close(db);
        return 1;
    }

    qihse_txn_t* txn = NULL;
    qihse_uwp_sql_result_t* sql_result = NULL;
    uwp_sts_result_t sql_status = qihse_uwp_sql_execute_typed_user(
        &sql_ctx, "CREATE TABLE documents (id INT, tenant_id INT, content TEXT)",
        NULL, 0, &txn, user, &sql_result);
    qihse_uwp_sql_result_free(sql_result);
    sql_result = NULL;
    if (sql_status == UWP_STS_OK) {
        sql_status = qihse_uwp_sql_execute_typed_user(
            &sql_ctx,
            "INSERT INTO documents VALUES (1, 42, 'embedded SQL row')",
            NULL, 0, &txn, user, &sql_result);
    }
    qihse_uwp_sql_result_free(sql_result);
    sql_result = NULL;
    if (sql_status == UWP_STS_OK) {
        sql_status = qihse_uwp_sql_execute_typed_user(
            &sql_ctx,
            "SELECT id, content FROM documents WHERE tenant_id = 42",
            NULL, 0, &txn, user, &sql_result);
    }
    if (sql_status != UWP_STS_OK) {
        fprintf(stderr, "Context-backed SQL execution failed (%d).\n",
                (int)sql_status);
        qihse_uwp_sql_result_free(sql_result);
        qihse_schema_registry_destroy((qihse_schema_registry_t*)sql_ctx.schema);
        qihse_txn_manager_destroy(sql_ctx.txn_manager);
        qihse_vector_db_close(db);
        return 1;
    }
    if (sql_result && sql_result->nrows > 0) {
        printf("[Embedded] Typed SQL returned id=%d, content=%s\n",
            sql_result->rows[0][0].v.i32,
            sql_result->rows[0][1].v.str);
    }
    qihse_uwp_sql_result_free(sql_result);

    /* Keep vector search on the vector API/QQL path; the deprecated SQL
     * function on qihse_vector_db_t cannot represent relational results. */
    const char* qql =
        "MATCH (d:Document) SEARCH d.vec WITH VEC([0.1, 0.2]) "
        "USING MODE qmag YIELD d LIMIT 5";
    printf("\n[Embedded] Executing Native QQL: %s\n", qql);
    qihse_result_set_t* rs_qql = qihse_execute_qql_user(db, user, qql);
    if (rs_qql && rs_qql->count > 0) {
        printf("[Embedded] QQL execution found %zu results "
               "(Top ID: %lu, Score: %.2f)\n",
            rs_qql->count, rs_qql->results[0].id, rs_qql->results[0].score);
    }

    qihse_free_result_set(rs_qql);
    qihse_schema_registry_destroy((qihse_schema_registry_t*)sql_ctx.schema);
    qihse_txn_manager_destroy(sql_ctx.txn_manager);
    qihse_vector_db_close(db);
    printf("\n--- Test Complete ---\n");
    return 0;
}
