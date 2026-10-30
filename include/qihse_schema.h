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
 * Registry state is serialized with durable row generations by the table store.
 * ------------------------------------------------------------------------- */

typedef struct {
    char* name;
    qihse_sql_type_t type;
    int   type_len;
    int type_scale;
    char* generated_expr;
    int generated_stored;
    int   not_null;
    int   is_primary_key;
    char* default_expr;
    int is_unique;
    int is_serial;
    qihse_sql_fk_t* fk;
    char* check_expr;
} qihse_schema_column_t;

typedef struct {
    char* name;
    char* table_name;
    char* column_name;
    char** expressions;
    size_t num_expressions;
    int* descending;
    char* using_method;
    int if_not_exists;
    int   unique;
} qihse_schema_index_t;

typedef struct {
    char* name;
    qihse_schema_column_t* columns;
    size_t num_columns;
    qihse_schema_index_t* indexes;
    size_t num_indexes;
    qihse_sql_fk_t* fks;
    size_t num_fks;
    qihse_sql_check_t* checks;
    size_t num_checks;
    qihse_sql_unique_t* uniques;
    size_t num_uniques;
    char* view_query;             /* non-NULL for a materialized relation */
    qihse_sql_trigger_def_t* triggers;
    size_t num_triggers;
} qihse_schema_table_t;

typedef struct qihse_schema_registry qihse_schema_registry_t;

/* Create / destroy */
qihse_schema_registry_t* qihse_schema_registry_create(void);
void qihse_schema_registry_destroy(qihse_schema_registry_t* reg);
/* Transfer staged contents into an existing, exclusively owned registry.
 * Invalidates all borrowed table/column pointers into either registry. */
void qihse_schema_registry_replace(qihse_schema_registry_t* reg,
                                   qihse_schema_registry_t* staged);

/* DDL operations — return 0 on success, -1 on error */
int qihse_schema_create_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
int qihse_schema_drop_table(qihse_schema_registry_t* reg, const char* name);
int qihse_schema_create_index(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
int qihse_schema_drop_index(qihse_schema_registry_t* reg, const char* name);
int qihse_schema_alter_table(qihse_schema_registry_t* reg, const qihse_sql_ast_t* ast);
/* Only extensions with implemented function semantics may be registered. */
int qihse_schema_create_extension(qihse_schema_registry_t* reg, const char* name);
bool qihse_schema_has_extension(const qihse_schema_registry_t* reg, const char* name);

/* Supported bounded SQL objects. Functions/triggers must have executable semantics
 * in the caller; registration alone never runs SQL code. */
int qihse_schema_create_function(qihse_schema_registry_t* reg,
                                 const qihse_sql_function_def_t* definition);
const qihse_sql_function_def_t* qihse_schema_get_function(
    const qihse_schema_registry_t* reg, const char* name);
int qihse_schema_create_trigger(qihse_schema_registry_t* reg,
                                const qihse_sql_trigger_def_t* definition);
int qihse_schema_drop_trigger(qihse_schema_registry_t* reg,
                              const char* table, const char* name);
int qihse_schema_create_materialized_view(qihse_schema_registry_t* reg,
    const char* name, const char* query, const qihse_schema_column_t* columns,
    size_t num_columns);
/* Lookups */
const qihse_schema_table_t* qihse_schema_get_table(const qihse_schema_registry_t* reg, const char* name);
const qihse_schema_index_t* qihse_schema_get_index(const qihse_schema_registry_t* reg, const char* name);
size_t qihse_schema_table_count(const qihse_schema_registry_t* reg);
const qihse_schema_table_t* qihse_schema_table_at(const qihse_schema_registry_t* reg, size_t idx);

/* Portable version-4 binary catalog image. Reads legacy v1/v2/v3 images; writes
 * full column and index definitions. Registration of an index alone is not
 * execution: the executor must build and fence a real backing index before
 * acknowledging CREATE INDEX. Persist the complete blob
 * in the same atomic transaction as SQL rows. At most 1 MiB; no partial output
 * on error. serialize allocates *out (free it); deserialize allocates a new
 * registry (destroy it). Unknown versions, truncation and malformed metadata
 * fail closed. */
#define QIHSE_SCHEMA_IMAGE_MAX (1024u * 1024u)
int qihse_schema_serialize(const qihse_schema_registry_t* reg, uint8_t** out, size_t* len);
int qihse_schema_deserialize(const uint8_t* data, size_t len, qihse_schema_registry_t** out);

/* Check if a table has an index on a given column */
bool qihse_schema_has_index(const qihse_schema_registry_t* reg, const char* table, const char* column);

#ifdef __cplusplus
}
#endif

#endif
