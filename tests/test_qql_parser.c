#include <stdio.h>
#include <stdlib.h>
#include "qihse_qql_parser.h"

void print_ast(qihse_qql_ast_t* ast) {
    if (!ast) {
        printf("AST is NULL (Parse Error)\n");
        return;
    }
    
    printf("Table: %s\n", ast->table_name);
    printf("Limit: %d\n", ast->limit);
    
    if (ast->is_vector_search) {
        printf("Mode: Vector Search\n");
    } else if (ast->is_text_search) {
        printf("Mode: Text Search (%s)\n", ast->query_string);
    }
    
    if (ast->has_join) {
        printf("Join: %s ON %s = %s\n", ast->join_table, ast->join_left, ast->join_right);
    }
    
    if (ast->has_temporal) {
        printf("Temporal: %s TO %s\n", ast->start_time, ast->end_time);
    }
    
    if (ast->has_spatial) {
        printf("Spatial: Radius %f OF (%f, %f)\n", ast->radius, ast->lat, ast->lon);
    }
    
    free(ast);
}

int main() {
    const char* q1 = "SEARCH VECTOR [1.0, 2.0, 3.0] FROM documents JOIN metadata ON documents.id = metadata.doc_id WHERE rating > 4 WITHIN TIME '2023-01-01' TO '2024-01-01' LIMIT 5;";
    printf("--- Query 1: Temporal + JOIN ---\n");
    qihse_qql_ast_t* ast1 = qihse_parse_qql_to_ast(q1);
    print_ast(ast1);

    const char* q2 = "SEARCH TEXT \"cybersecurity\" FROM logs WITHIN RADIUS 15.5 OF (37.77, -122.41) LIMIT 100;";
    printf("\n--- Query 2: Spatial Radius ---\n");
    qihse_qql_ast_t* ast2 = qihse_parse_qql_to_ast(q2);
    print_ast(ast2);

    return 0;
}
