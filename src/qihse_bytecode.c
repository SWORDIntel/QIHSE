#include "qihse_bytecode.h"
#include <stddef.h>
#include <string.h>

#define VM_STACK_SIZE 64

/* -------------------------------------------------------------------------- */
/* Internal VM value                                                          */
/* -------------------------------------------------------------------------- */
typedef enum {
    VAL_INT,
    VAL_STR,
    VAL_BOOL
} value_type_t;

typedef struct {
    value_type_t type;
    union {
        int64_t     i;
        const char* s;
        bool        b;
    } as;
} vm_value_t;

/* -------------------------------------------------------------------------- */
/* Context field lookup                                                       */
/* -------------------------------------------------------------------------- */
static bool ctx_load_field(const qihse_bytecode_context_t* ctx,
                           const char* name,
                           vm_value_t* out) {
    if (!ctx || !name || !out) return false;
    for (size_t i = 0; i < ctx->num_fields; i++) {
        const qihse_bytecode_field_t* f = &ctx->fields[i];
        if (f->name && strcmp(f->name, name) == 0) {
            switch (f->type) {
                case QIHSE_FIELD_INT:
                    out->type  = VAL_INT;
                    out->as.i  = f->value.i;
                    return true;
                case QIHSE_FIELD_STR:
                    out->type  = VAL_STR;
                    out->as.s  = f->value.s;
                    return true;
                case QIHSE_FIELD_BOOL:
                    out->type  = VAL_BOOL;
                    out->as.b  = f->value.b;
                    return true;
            }
        }
    }
    return false; /* field not found */
}

/* -------------------------------------------------------------------------- */
/* Main evaluator                                                             */
/* -------------------------------------------------------------------------- */
bool qihse_bytecode_eval(const uint8_t* bytecode, const void* ctx_ptr) {
    if (!bytecode) return false;

    const qihse_bytecode_context_t* ctx =
        (const qihse_bytecode_context_t*)ctx_ptr;

    vm_value_t stack[VM_STACK_SIZE];
    int sp = 0;
    int pc = 0;

    while (1) {
        uint8_t op = bytecode[pc++];

        switch ((qihse_opcode_t)op) {

        /* ---- Literals -------------------------------------------------- */
        case OP_PUSH_INT: {
            if (sp >= VM_STACK_SIZE) return false;
            int64_t val = 0;
            memcpy(&val, &bytecode[pc], sizeof(int64_t));
            pc += sizeof(int64_t);
            stack[sp].type  = VAL_INT;
            stack[sp].as.i  = val;
            sp++;
            break;
        }
        case OP_PUSH_STR: {
            if (sp >= VM_STACK_SIZE) return false;
            const char* str = (const char*)&bytecode[pc];
            size_t len = strnlen(str, 4096);
            if (len == 4096) return false; /* unterminated */
            pc += (int)(len + 1);
            stack[sp].type  = VAL_STR;
            stack[sp].as.s  = str;
            sp++;
            break;
        }

        /* ---- Field load ------------------------------------------------- */
        case OP_LOAD_FIELD: {
            if (sp >= VM_STACK_SIZE) return false;
            const char* name = (const char*)&bytecode[pc];
            size_t len = strnlen(name, 256);
            if (len == 256) return false;
            pc += (int)(len + 1);

            vm_value_t fval;
            if (!ctx_load_field(ctx, name, &fval)) {
                /* Field missing — push a false bool so comparisons fail */
                fval.type  = VAL_BOOL;
                fval.as.b  = false;
            }
            stack[sp++] = fval;
            break;
        }

        /* ---- Comparison ------------------------------------------------- */
#define BINARY_CMP(OP_NAME, INT_EXPR, STR_EXPR)                       \
        case OP_NAME: {                                                \
            if (sp < 2) return false;                                  \
            vm_value_t r = stack[--sp];                                \
            vm_value_t l = stack[--sp];                                \
            bool res = false;                                          \
            if (l.type == VAL_INT  && r.type == VAL_INT)               \
                res = (INT_EXPR);                                       \
            else if (l.type == VAL_STR && r.type == VAL_STR)           \
                res = (STR_EXPR);                                       \
            stack[sp].type   = VAL_BOOL;                               \
            stack[sp].as.b   = res;                                    \
            sp++;                                                      \
            break;                                                     \
        }

        BINARY_CMP(OP_EQ,  l.as.i == r.as.i, strcmp(l.as.s, r.as.s) == 0)
        BINARY_CMP(OP_NEQ, l.as.i != r.as.i, strcmp(l.as.s, r.as.s) != 0)
        BINARY_CMP(OP_GT,  l.as.i >  r.as.i, strcmp(l.as.s, r.as.s) >  0)
        BINARY_CMP(OP_GTE, l.as.i >= r.as.i, strcmp(l.as.s, r.as.s) >= 0)
        BINARY_CMP(OP_LT,  l.as.i <  r.as.i, strcmp(l.as.s, r.as.s) <  0)
        BINARY_CMP(OP_LTE, l.as.i <= r.as.i, strcmp(l.as.s, r.as.s) <= 0)

#undef BINARY_CMP

        /* ---- Boolean logic ---------------------------------------------- */
        case OP_AND: {
            if (sp < 2) return false;
            vm_value_t r = stack[--sp];
            vm_value_t l = stack[--sp];
            bool lv = (l.type == VAL_BOOL) ? l.as.b : (l.type == VAL_INT && l.as.i != 0);
            bool rv = (r.type == VAL_BOOL) ? r.as.b : (r.type == VAL_INT && r.as.i != 0);
            stack[sp].type  = VAL_BOOL;
            stack[sp].as.b  = lv && rv;
            sp++;
            break;
        }
        case OP_OR: {
            if (sp < 2) return false;
            vm_value_t r = stack[--sp];
            vm_value_t l = stack[--sp];
            bool lv = (l.type == VAL_BOOL) ? l.as.b : (l.type == VAL_INT && l.as.i != 0);
            bool rv = (r.type == VAL_BOOL) ? r.as.b : (r.type == VAL_INT && r.as.i != 0);
            stack[sp].type  = VAL_BOOL;
            stack[sp].as.b  = lv || rv;
            sp++;
            break;
        }
        case OP_NOT: {
            if (sp < 1) return false;
            vm_value_t v = stack[--sp];
            bool val = (v.type == VAL_BOOL) ? v.as.b : (v.type == VAL_INT && v.as.i != 0);
            stack[sp].type  = VAL_BOOL;
            stack[sp].as.b  = !val;
            sp++;
            break;
        }

        /* ---- Return ----------------------------------------------------- */
        case OP_RET: {
            if (sp < 1) return false;
            vm_value_t res = stack[--sp];
            if (res.type == VAL_BOOL) return res.as.b;
            if (res.type == VAL_INT)  return res.as.i != 0;
            return false;
        }

        default:
            return false; /* unknown opcode */
        }
    }
    return false;
}
