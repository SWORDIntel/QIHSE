#include "qihse_sql_parser.h"
#include <stdio.h>
#include <stdlib.h>

void* qihse_parse_sql_to_ast(const char* sql) {
    if (!sql) {
        return NULL;
    }
    
    // Stub for libpg_query integration
    printf("Parsing SQL via libpg_query: %s\n", sql);
    
    // Return a dummy pointer representing an internal AST struct
    // For now, we just allocate a single byte to represent the dummy AST
    void* dummy_ast = malloc(1);
    
    return dummy_ast;
}
