#ifndef QIHSE_SQL_PARSER_H
#define QIHSE_SQL_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parses a SQL string into an Abstract Syntax Tree (AST) using libpg_query.
 * 
 * @param sql The SQL string to parse.
 * @return A pointer to the internal AST struct, or NULL on failure.
 */
void* qihse_parse_sql_to_ast(const char* sql);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_SQL_PARSER_H
