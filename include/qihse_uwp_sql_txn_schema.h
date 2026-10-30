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
 * lazily created, matching the prepared-statement cache in the executor.
 * SQL requires a live authenticated user supplied by the transport; pgwire
 * must authenticate its own client and never substitute a service/operator
 * principal. Tenant rows use INT columns __qihse_tenant_id,
 * __qihse_classification and __qihse_sci together. Missing labels denote
 * system-tenant, unclassified rows; tenant-scoped users cannot use unlabeled
 * tables. Partial/invalid labels are refused. Table ACL and row clearance
 * are both required; security labels cannot be changed by SQL UPDATE.
 * Explicit UWP transactions attach private optimistic shadows for up to 16
 * tables; COMMIT publishes them together under generation fences and ROLLBACK
 * discards them. Explicitly bound stores fsync a single versioned row/catalog
 * snapshot on commit; this is not a cross-model transaction or SQL DDL WAL.
 * ctx->sql_engine remains an opaque caller-owned pointer the executor never
 * dereferences. Tables must exist in the row store before UPDATE/DELETE.
 * ------------------------------------------------------------------------- */
qihse_table_store_t* qihse_uwp_sql_table_store(void);

/* Bind a single explicit UWP context to the exclusive fsynced row/catalog
 * snapshot. A new store requires ctx->schema; an existing store restores it
 * when NULL, or verifies supplied schema bytes exactly. Close releases the
 * writer lock; the caller owns ctx->schema even when it was restored here.
 * Durable CREATE TABLE and the bounded uuid-ossp extension, updated_at
 * function/trigger catalog changes support DDL-only transactions, with one
 * catalog/row publication at COMMIT. Uncommitted catalog changes are visible
 * only to their owning transaction. Mixed DDL/DML, savepoints and indexes
 * without executable row-store access stay refused. CREATE MATERIALIZED VIEW
 * seeds supported aggregates from a principal-authorized source snapshot and
 * fences that source through atomic catalog/row publication. Its EXECUTE reply
 * is `OK stmt_type=CREATE MATERIALIZED VIEW rows=N\n`, where N is the number
 * of aggregate rows inserted (zero for IF NOT EXISTS on an existing view).
 * Call open before SQL requests, close after all sessions/transactions finish. */
int qihse_uwp_sql_open_durable(qihse_uwp_context_t* ctx, const char* path);
void qihse_uwp_sql_close_durable(qihse_uwp_context_t* ctx);
bool qihse_uwp_sql_durable_ready(const qihse_uwp_context_t* ctx);

/* Copy committed table names visible to this authenticated principal. The
 * caller frees each name and the array. Refuses incomplete catalog/row state. */
uwp_sts_result_t qihse_uwp_sql_catalog_tables(qihse_uwp_context_t* ctx,
    qihse_user_t* user, char*** names, size_t* count);
/* Copy committed index names only when the principal can read the relation
 * and its labels; protected or absent relations return an empty result.
 * A NULL table enumerates all accessible committed relations atomically. */
uwp_sts_result_t qihse_uwp_sql_catalog_indexes(qihse_uwp_context_t* ctx,
    qihse_user_t* user, const char* table, char*** names, size_t* count);

/* True only for a staged DDL-only SQL resource. Used by pgwire to reject
 * mixed statements with a truthful unsupported-feature SQLSTATE. */
bool qihse_uwp_sql_txn_has_ddl(const qihse_txn_t* txn);
/* Bind an authenticated request identity to a transaction with staged SQL
 * writes before COMMIT. The resource copies all identity fields; status_out
 * and outcome remain caller-owned until the synchronous commit returns. */
bool qihse_uwp_sql_txn_bind_retry(qihse_txn_t* txn,
    const qihse_ts_retry_identity_t* identity,
    const qihse_ts_retry_outcome_t* outcome,
    qihse_ts_retry_status_t* status_out,
    qihse_ts_retry_outcome_t* committed_outcome);

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

/* Extended pgwire binds: caller retains bytes until execute returns. NULL is
 * represented only by is_null; a text value of "NULL" is ordinary text. */
#define QIHSE_UWP_SQL_MAX_RESULT_COLUMNS 64u
#define QIHSE_UWP_SQL_MAX_BIND_BYTES 1048576u
typedef struct {
    uint32_t oid;                /* 0 requests schema inference */
    const uint8_t* data;
    size_t len;
    bool is_null;
    uint16_t format;             /* PostgreSQL text (0) or binary (1) */
} qihse_uwp_sql_param_t;

typedef struct {
    char name[128];
    int32_t oid;
} qihse_uwp_sql_result_column_t;

typedef struct {
    size_t nparams;
    uint32_t param_oids[QIHSE_SQL_MAX_PARAMETERS];
    size_t ncolumns;
    qihse_uwp_sql_result_column_t columns[QIHSE_UWP_SQL_MAX_RESULT_COLUMNS];
} qihse_uwp_sql_metadata_t;

/* Inspect schema and permissions without executing the SQL or reading rows.
 * Declared parameter OIDs may be zero (infer); unsupported SQL fails closed. */
uwp_sts_result_t qihse_uwp_sql_describe(qihse_uwp_context_t* ctx,
    const char* sql, qihse_user_t* user, const uint32_t* declared_oids,
    size_t nparams, qihse_uwp_sql_metadata_t* metadata);

/* Parse the original SQL, bind typed AST leaves, execute within the supplied
 * transaction, and return the same reply envelope as simple SQL execution. */
uwp_sts_result_t qihse_uwp_sql_execute_params(qihse_uwp_context_t* ctx,
    const char* sql, const qihse_uwp_sql_param_t* params, size_t nparams,
    qihse_txn_t** current_txn, qihse_user_t* user,
    qihse_uwp_write_fn write_fn, void* write_ctx);

/* Resolve a completed, authenticated single-table SELECT's result columns from
 * the live catalog. Copies OIDs under the SQL dispatch lock; never exposes
 * borrowed catalog pointers or infers types from serialized row values. */
uwp_sts_result_t qihse_uwp_sql_select_type_oids(qihse_uwp_context_t* ctx,
    const qihse_sql_ast_t* ast, qihse_user_t* user,
    const char* const* result_names, size_t count, int32_t* oids);

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
