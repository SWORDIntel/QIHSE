#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qihse_bytecode_compiler.h"
#include "qihse_bytecode.h"

int main() {
    const char* clause = "WHERE age > 25 AND score >= 80";
    uint8_t bc[1024];
    size_t bc_len = 0;
    
    int rc = qihse_bc_compile(clause, bc, sizeof(bc), &bc_len);
    if (rc != 0) {
        printf("Failed to compile bytecode: %d\n", rc);
        return 1;
    }
    
    printf("Bytecode compiled successfully! Length: %zu\n", bc_len);
    for (size_t i = 0; i < bc_len; i++) {
        printf("%02x ", bc[i]);
    }
    printf("\n");

    qihse_bytecode_field_t fields[2];
    fields[0].name = "age";
    fields[0].type = QIHSE_FIELD_INT;
    fields[0].value.i = 30;

    fields[1].name = "score";
    fields[1].type = QIHSE_FIELD_INT;
    fields[1].value.i = 85;

    qihse_bytecode_context_t ctx;
    ctx.fields = fields;
    ctx.num_fields = 2;

    bool passed = qihse_bytecode_eval(bc, &ctx);
    printf("Row 1 (age=30, score=85): %s\n", passed ? "PASS" : "FAIL");
    if (!passed) return 1;

    fields[0].value.i = 20;
    passed = qihse_bytecode_eval(bc, &ctx);
    printf("Row 2 (age=20, score=85): %s\n", passed ? "PASS" : "FAIL");
    if (passed) return 1;

    return 0;
}
