#ifndef QIHSE_SCHEMA_H
#define QIHSE_SCHEMA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qihse_sql_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Schema Registry — table definitions, column types, index metadata.
 *
 * This is an in-memory catalog that can be wired to persistent storage later.
 * ------------------------------------------------------------------------- */

typedef struct {
    char* name;
    qihse_sql_type_t type;
    int   type_len;
    int   not_null;
    int   is_primary_key;
    char* default_expr;
} qihse_schema_column_t;

typedef struct {
    char* name;
    char* table_name;
    char* column_name;
    int   unique;
} qihse_schema_index_t;

typedef struct {
    char* name;
    qihse_schema_column_t* columns;
    size_t num_columns;
    qihse_schema_index_t* indexes;
    size_t num_indexes;
} qihse_schema_table_t;

typedef struct qihse_schema_registry qihse_schema_registry_t;

/* Create / destroy */
qihse_schema_registry_t* qihse_schema_registry_create(void);
void qihse_schema_registry_destroy(qihse_schema_registry_t* reg);

/* DDL operations — return 0 on success, -1 on error */
int qihse_schema_create_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
int qihse_schema_drop_table(qihse_schema_registry_t* reg, const char* name);
int qihse_schema_create_index(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
int qihse_schema_drop_index(qihse_schema_registry_t* reg, const char* name);
int qihse_schema_alter_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);

/* Lookups */
const qihse_schema_table_t* qihse_schema_get_table(const qihse_schema_registry_t* reg, const char* name);
const qihse_schema_index_t* qihse_schema_get_index(const qihse_schema_registry_t* reg, const char* name);
size_t qihse_schema_table_count(const qihse_schema_registry_t* reg);
const qihse_schema_table_t* qihse_schema_table_at(const qihse_schema_registry_t* reg, size_t idx);

/* Check if a table has an index on a given column */
bool qihse_schema_has_index(const qihse_schema_registry_t* reg, const char* table, const char* column);

#ifdef __cplusplus
}
#endif

#endif
