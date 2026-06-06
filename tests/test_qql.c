#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qihse_qql_parser.h"

int main() {
    printf("Testing QQL Engine AST Generation...\n");

    const char* queries[] = {
        "SEARCH VECTOR [1.0, 2.5, -0.3] FROM my_vectors WHERE magnitude > 0.8 LIMIT 10;",
        "SEARCH TEXT \"hello world\" FROM my_docs LIMIT 5;",
        "INSERT INTO my_kv (key1, key2) VALUES (\"foo\", \"bar\");"
    };

    for (int i = 0; i < 3; i++) {
        printf("\n========================================\n");
        printf("Executing Query %d:\n%s\n", i + 1, queries[i]);
        printf("========================================\n");
        void* ast = qihse_parse_qql_to_ast(queries[i]);
        if (!ast) {
            printf("FAIL: Query %d failed to parse.\n", i + 1);
            return 1;
        }
    }

    printf("\nAll QQL Queries parsed successfully into Tree-Sitter ASTs!\n");
    return 0;
}
