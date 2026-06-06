/**
 * @file qihse_bytecode_compiler.h
 * @brief WHERE-clause bytecode compiler for the QIHSE metadata filter VM.
 *
 * Parses a WHERE expression string and emits a compact uint8_t bytecode stream
 * understood by qihse_bytecode_eval().  The compiler owns an internal
 * recursive-descent parser; no external parser dependency is required.
 *
 * Grammar (simplified BNF):
 *
 *   expr       ::= or_expr
 *   or_expr    ::= and_expr  ( "OR"  and_expr )*
 *   and_expr   ::= not_expr  ( "AND" not_expr )*
 *   not_expr   ::= "NOT" not_expr | cmp_expr | "(" expr ")"
 *   cmp_expr   ::= operand ( "==" | "!=" | ">" | ">=" | "<" | "<=" ) operand
 *   operand    ::= INT_LITERAL | STRING_LITERAL | IDENTIFIER
 *
 * Keywords are case-insensitive (AND, OR, NOT).
 * Identifiers become OP_LOAD_FIELD; integer literals become OP_PUSH_INT;
 * string literals (double-quoted) become OP_PUSH_STR.
 */

#ifndef QIHSE_BYTECODE_COMPILER_H
#define QIHSE_BYTECODE_COMPILER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Error codes returned by qihse_bc_compile().
 */
typedef enum {
    QIHSE_BC_OK            =  0, /**< Compilation succeeded.                */
    QIHSE_BC_ERR_NULL      = -1, /**< Null argument.                        */
    QIHSE_BC_ERR_OVERFLOW  = -2, /**< Output buffer too small.              */
    QIHSE_BC_ERR_SYNTAX    = -3, /**< Unexpected token / parse error.       */
    QIHSE_BC_ERR_DEPTH     = -4, /**< Expression nesting too deep.          */
} qihse_bc_error_t;

/**
 * qihse_bc_compile
 *
 * Compiles a WHERE-clause expression string to QIHSE bytecode.
 *
 * The resulting bytecode ends with OP_RET and is ready to be passed directly
 * to qihse_bytecode_eval().
 *
 * @param where_clause  NUL-terminated expression string.
 *                      May be prefixed with the literal "WHERE" keyword
 *                      (case-insensitive) which is silently consumed.
 * @param out_buf       Caller-supplied output buffer.
 * @param buf_size      Size of out_buf in bytes.
 * @param out_len       If non-NULL, receives the number of bytes written.
 *
 * @return QIHSE_BC_OK on success, or a negative qihse_bc_error_t code.
 */
int qihse_bc_compile(const char   *where_clause,
                     uint8_t      *out_buf,
                     size_t        buf_size,
                     size_t       *out_len);

/**
 * qihse_bc_error_str
 *
 * Returns a human-readable description of a qihse_bc_error_t value.
 */
const char *qihse_bc_error_str(int err);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_BYTECODE_COMPILER_H */
