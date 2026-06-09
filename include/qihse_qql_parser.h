#ifndef QIHSE_QQL_PARSER_H
#define QIHSE_QQL_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char table_name[256];
    int limit;
    
    // Spatial
    int has_spatial;
    float radius;
    float lat;
    float lon;
    
    // Temporal
    int has_temporal;
    char start_time[64];
    char end_time[64];
    
    // Join
    int has_join;
    char join_table[64];
    char join_left[64];
    char join_right[64];
    
    // Mode
    int is_vector_search;
    int is_text_search;
    char query_string[256];
} qihse_qql_ast_t;

/**
 * Parses a QQL (Graph Query Language) string into an abstract syntax tree (AST).
 * This utilizes tree-sitter conceptually.
 * 
 * @param qql The QQL string to parse.
 * @return A pointer representing the internal AST struct. Must be freed by caller.
 */
qihse_qql_ast_t* qihse_parse_qql_to_ast(const char* qql);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_QQL_PARSER_H */
