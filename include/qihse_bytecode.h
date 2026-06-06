#ifndef QIHSE_BYTECODE_H
#define QIHSE_BYTECODE_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Native Metadata Bytecode Engine Opcodes
 * A simple Virtual Machine for metadata filtering.
 */
typedef enum {
    OP_PUSH_INT = 1,
    OP_PUSH_STR = 2,
    OP_EQ       = 3,
    OP_GT       = 4,
    OP_RET      = 5
    // Add additional opcodes here (e.g. OP_LT, OP_AND, OP_OR, field lookups) as needed
} qihse_opcode_t;

/**
 * qihse_bytecode_eval
 * Executes the bytecode to determine if a row matches the filter.
 * This avoids calling back into Python during vector search.
 *
 * @param bytecode The bytecode array (stream of uint8_t). Must be valid and properly terminated with OP_RET.
 * @param metadata The metadata for the current row (passed as void* to serve as a scaffold for future implementation).
 * @return true if the row matches the filter, false otherwise.
 */
bool qihse_bytecode_eval(const uint8_t* bytecode, const void* metadata);

#endif // QIHSE_BYTECODE_H
