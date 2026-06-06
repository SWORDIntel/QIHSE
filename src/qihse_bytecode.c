#include "qihse_bytecode.h"
#include <stddef.h>
#include <string.h>

#define VM_STACK_SIZE 64

// Internal VM value representation
typedef enum {
    VAL_INT,
    VAL_STR,
    VAL_BOOL
} value_type_t;

typedef struct {
    value_type_t type;
    union {
        int64_t i;
        const char* s;
        bool b;
    } as;
} vm_value_t;

bool qihse_bytecode_eval(const uint8_t* bytecode, const void* metadata) {
    if (!bytecode) return false;

    vm_value_t stack[VM_STACK_SIZE];
    int sp = 0; // Stack pointer
    int pc = 0; // Program counter

    while (1) {
        uint8_t op = bytecode[pc++];

        switch (op) {
            case OP_PUSH_INT: {
                if (sp >= VM_STACK_SIZE) return false; // Stack overflow
                
                // Scaffold: Read 8-byte integer (native endianness)
                int64_t val = 0;
                memcpy(&val, &bytecode[pc], sizeof(int64_t));
                pc += sizeof(int64_t);
                
                stack[sp].type = VAL_INT;
                stack[sp].as.i = val;
                sp++;
                break;
            }
            case OP_PUSH_STR: {
                if (sp >= VM_STACK_SIZE) return false; // Stack overflow
                
                // Scaffold: Read null-terminated string directly from bytecode
                const char* str = (const char*)&bytecode[pc];
                size_t len = strnlen(str, 4096);
                pc += len;
                if (str[len] == '\0') {
                    pc += 1; // Advance past the null terminator
                } else {
                    return false; // Error: string exceeds maximum length or is not null-terminated
                }

                stack[sp].type = VAL_STR;
                stack[sp].as.s = str;
                sp++;
                break;
            }
            case OP_EQ: {
                if (sp < 2) return false; // Stack underflow
                vm_value_t right = stack[--sp];
                vm_value_t left = stack[--sp];
                
                bool result = false;
                if (left.type == VAL_INT && right.type == VAL_INT) {
                    result = (left.as.i == right.as.i);
                } else if (left.type == VAL_STR && right.type == VAL_STR) {
                    result = (strcmp(left.as.s, right.as.s) == 0);
                } else if (left.type == VAL_BOOL && right.type == VAL_BOOL) {
                    result = (left.as.b == right.as.b);
                }
                
                stack[sp].type = VAL_BOOL;
                stack[sp].as.b = result;
                sp++;
                break;
            }
            case OP_GT: {
                if (sp < 2) return false; // Stack underflow
                vm_value_t right = stack[--sp];
                vm_value_t left = stack[--sp];
                
                bool result = false;
                if (left.type == VAL_INT && right.type == VAL_INT) {
                    result = (left.as.i > right.as.i);
                } else if (left.type == VAL_STR && right.type == VAL_STR) {
                    result = (strcmp(left.as.s, right.as.s) > 0);
                }
                
                stack[sp].type = VAL_BOOL;
                stack[sp].as.b = result;
                sp++;
                break;
            }
            case OP_RET: {
                if (sp < 1) return false; // Nothing to return
                vm_value_t res = stack[--sp];
                
                if (res.type == VAL_BOOL) {
                    return res.as.b;
                } else if (res.type == VAL_INT) {
                    return res.as.i != 0;
                }
                return false;
            }
            default:
                // Unknown opcode
                return false;
        }
    }
    
    // Should never reach here if bytecode is properly terminated
    return false;
}
