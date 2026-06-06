#include "qihse_qql_parser.h"
#include <stdio.h>

void* qihse_parse_qql_to_ast(const char* qql) {
    static int dummy_ast_node = 42;

    if (!qql) {
        return NULL;
    }

    // Stub for tree-sitter parsing routine
    printf("Tokenizing QQL string: %s\n", qql);
    printf("Generating AST using tree-sitter (stub)...\n");

    // Return a dummy pointer representing the internal AST struct
    return (void*)&dummy_ast_node;
}
