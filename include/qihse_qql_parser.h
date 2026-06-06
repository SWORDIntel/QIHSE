#ifndef QIHSE_QQL_PARSER_H
#define QIHSE_QQL_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parses a QQL (Graph Query Language) string into an abstract syntax tree (AST).
 * This is currently a stub for an embedded framework and utilizes tree-sitter conceptually.
 * 
 * @param qql The QQL string to parse.
 * @return A pointer representing the internal AST struct (dummy pointer for now).
 */
void* qihse_parse_qql_to_ast(const char* qql);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_QQL_PARSER_H */
