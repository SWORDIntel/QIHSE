#ifndef QIHSE_BYTECODE_H
#define QIHSE_BYTECODE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Native Metadata Bytecode Engine Opcodes
 * A simple stack VM for metadata predicate filtering during vector search.
 * Avoids Python callbacks per-row; bytecode is compiled once and replayed
 * for every candidate row.
 */
typedef enum {
    OP_PUSH_INT   = 1,  /* [int64_t: 8 bytes]  — push literal integer */
    OP_PUSH_STR   = 2,  /* [cstr: N+1 bytes]   — push literal string */
    OP_EQ         = 3,  /* pop r, pop l → push (l == r) */
    OP_GT         = 4,  /* pop r, pop l → push (l >  r) */
    OP_RET        = 5,  /* pop result → return as bool   */
    OP_LOAD_FIELD = 6,  /* [cstr: N+1 bytes]   — load named field from context onto stack */
    OP_LT         = 7,  /* pop r, pop l → push (l <  r) */
    OP_AND        = 8,  /* pop r, pop l → push (l && r) */
    OP_OR         = 9,  /* pop r, pop l → push (l || r) */
    OP_NOT        = 10, /* pop v        → push (!v)      */
    OP_GTE        = 11, /* pop r, pop l → push (l >= r)  */
    OP_LTE        = 12, /* pop r, pop l → push (l <= r)  */
    OP_NEQ        = 13, /* pop r, pop l → push (l != r)  */
} qihse_opcode_t;

/**
 * A single typed field exposed to the bytecode VM.
 * Fields are matched by name at OP_LOAD_FIELD time.
 */
typedef enum {
    QIHSE_FIELD_INT  = 0,
    QIHSE_FIELD_STR  = 1,
    QIHSE_FIELD_BOOL = 2,
} qihse_field_type_t;

typedef struct {
    const char*        name;   /* null-terminated field name */
    qihse_field_type_t type;
    union {
        int64_t     i;
        const char* s;
        bool        b;
    } value;
} qihse_bytecode_field_t;

/**
 * Execution context passed to qihse_bytecode_eval.
 * The caller populates this with the current row's metadata fields before
 * calling eval. Bytecode uses OP_LOAD_FIELD to pull values by name.
 */
typedef struct {
    const qihse_bytecode_field_t* fields;
    size_t                        num_fields;
} qihse_bytecode_context_t;

/**
 * qihse_bytecode_eval
 * Executes the bytecode predicate against a row's metadata context.
 * Returns true if the row passes the filter, false otherwise.
 *
 * @param bytecode  Stream of uint8_t opcodes. Must end with OP_RET.
 * @param ctx       Pointer to qihse_bytecode_context_t with the row's fields.
 *                  May be NULL — OP_LOAD_FIELD will return false for all lookups.
 */
bool qihse_bytecode_eval(const uint8_t* bytecode, const void* ctx);

#endif /* QIHSE_BYTECODE_H */
