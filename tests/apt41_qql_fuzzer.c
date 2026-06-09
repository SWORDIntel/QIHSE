#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "qihse_qql_parser.h"

void generate_malformed_qql(char* buffer, size_t max_len) {
    size_t len = (rand() % (max_len - 10)) + 10;
    
    // Sometimes start with SEARCH VECTOR, sometimes just garbage
    if (rand() % 2 == 0) {
        strcpy(buffer, "SEARCH VECTOR [");
    } else {
        buffer[0] = '\0';
    }
    
    size_t current_len = strlen(buffer);
    for (size_t i = current_len; i < len; i++) {
        // Inject random bytes, including unprintable characters and SQL injection attempts
        int r = rand() % 100;
        if (r < 10) {
            buffer[i] = '\'';
        } else if (r < 20) {
            buffer[i] = '"';
        } else if (r < 30) {
            buffer[i] = ';';
        } else if (r < 40) {
            buffer[i] = '\0'; // Early null terminator
        } else {
            buffer[i] = (char)(rand() % 255 + 1); // 1-255
        }
    }
    buffer[max_len - 1] = '\0';
    // ensure at least one null terminator
    buffer[len] = '\0';
}

int main() {
    printf("[APT-41 QQL PARSER FUZZER] Booting fuzzer...\n");
    srand(time(NULL));

    char fuzzer_buffer[4096];
    
    printf("[APT-41 SIMULATION] Commencing 50 extreme QQL parser attacks...\n");

    int crashes = 0;

    for (int i = 0; i < 50; i++) {
        generate_malformed_qql(fuzzer_buffer, 4096);
        
        // This will crash if ASAN catches a heap-buffer-overflow or if there's a segfault.
        qihse_qql_ast_t* ast = qihse_parse_qql_to_ast(fuzzer_buffer);
        if (ast) {
            free(ast);
        }
    }

    printf("[APT-41 SIMULATION] Fuzzer complete. Parser survived 50 malicious payloads!\n");
    return 0;
}
