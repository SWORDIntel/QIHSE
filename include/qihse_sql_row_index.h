#ifndef QIHSE_SQL_ROW_INDEX_H
#define QIHSE_SQL_ROW_INDEX_H
#include "qihse_schema.h"
#include "qihse_table_store.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qihse_sql_row_index qihse_sql_row_index_t;
bool qihse_sql_row_index_build(const qihse_schema_index_t* definition,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user, qihse_sql_row_index_t** out);
void qihse_sql_row_index_destroy(qihse_sql_row_index_t* index);
/* Candidate row IDs require authenticated row re-fetch and full predicate
 * recheck. Success returns caller-owned *rows (free it), or NULL when empty. */
bool qihse_sql_row_index_equal(const qihse_sql_row_index_t* index,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user, const qihse_col_value_t* keys, size_t key_count,
    size_t** rows, size_t* count);
/* JSONB: top-level key/scalar value; TSVECTOR: json_key=NULL and term=lexeme. */
bool qihse_sql_row_index_gin(const qihse_sql_row_index_t* index,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user, const char* json_key, const char* term,
    size_t** rows, size_t* count);

#ifdef __cplusplus
}
#endif
#endif
