#ifndef QIHSE_UWP_SQL_TXN_SCHEMA_H
#define QIHSE_UWP_SQL_TXN_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

#include "qihse_uwp.h"
#include "qihse_txn.h"
#include "qihse_sql_parser.h"
#include "qihse_table_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UWP_STS_OK = 0,
    UWP_STS_ERR_ARGS,
    UWP_STS_ERR_NO_CTX,
    UWP_STS_ERR_PERM,
    UWP_STS_ERR_FAILED
} uwp_sts_result_t;

/* -------------------------------------------------------------------------
 * SQL row store (UPDATE / DELETE execution)
 *
 * The mutable table store (src/tractable/qihse_table_store.c) is the only
 * in-tree store with in-place update and delete primitives, so parsed UPDATE
 * and DELETE statements execute against it.  The store is process-wide and
 * lazily created, matching the prepared-statement cache in the executor: the
 * UWP SQL path has no per-connection engine state yet, and ctx->sql_engine is
 * an opaque caller-owned pointer the executor never dereferences.  Tables
 * must be created in it with qihse_table_store_create_table() before DML can
 * target them.
 * ------------------------------------------------------------------------- */
qihse_table_store_t* qihse_uwp_sql_table_store(void);

/* Execute a parsed UPDATE or DELETE against the SQL row store.
 *
 * Consumes only the structured AST (ast->set_columns/set_values/num_set and
 * ast->where_conditions); the raw SQL text is never re-parsed for execution.
 * Returns a malloc'd single-line reply (caller frees), or NULL on allocation
 * failure.  The reply reports "rows=N" with the number of rows actually
 * changed, or that the statement was refused without changing anything.  A
 * DELETE with zero parsed conditions is always refused: it never becomes a
 * match-all, and no statement whose raw WHERE clause does not exactly match
 * the parsed conditions is executed. */
char* qihse_uwp_sql_execute_dml(const qihse_sql_ast_t* ast, qihse_user_t* user);

uwp_sts_result_t uwp_dispatch_sql(qihse_uwp_context_t* ctx, uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx);
uwp_sts_result_t uwp_dispatch_txn(qihse_uwp_context_t* ctx, uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx);
uwp_sts_result_t uwp_dispatch_schema(qihse_uwp_context_t* ctx, uint8_t command_opcode,
                                     const uint8_t* payload, size_t payload_len,
                                     qihse_user_t* user, int client_fd,
                                     qihse_uwp_write_fn write_fn, void* write_ctx);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_UWP_SQL_TXN_SCHEMA_H */
