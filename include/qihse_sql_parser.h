#ifndef QIHSE_SQL_PARSER_H
#define QIHSE_SQL_PARSER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QIHSE_SQL_SELECT = 1,
    QIHSE_SQL_INSERT = 2,
    QIHSE_SQL_UPDATE = 3,
    QIHSE_SQL_DELETE = 4,
    QIHSE_SQL_CREATE = 5,
    QIHSE_SQL_DROP   = 6,
    QIHSE_SQL_UNKNOWN= 0
} qihse_sql_stmt_type_t;

typedef struct {
    char* column_name;
    char* table_name;
} qihse_sql_column_ref_t;

typedef struct {
    char* table_name;
    char* alias;
} qihse_sql_table_ref_t;

typedef struct {
    char* column_name;
    char* operator;
    char* value;
    int   value_is_string;
} qihse_sql_condition_t;

typedef struct qihse_sql_ast_s {
    qihse_sql_stmt_type_t stmt_type;
    char** select_columns;
    size_t num_select_columns;
    qihse_sql_table_ref_t* from_tables;
    size_t num_from_tables;
    qihse_sql_condition_t* where_conditions;
    size_t num_where_conditions;
    int limit;
    int offset;
    char* raw_sql;
} qihse_sql_ast_t;

qihse_sql_ast_t* qihse_parse_sql_to_ast(const char* sql);

void qihse_sql_ast_free(qihse_sql_ast_t* ast);

#ifdef __cplusplus
}
#endif

#endif
