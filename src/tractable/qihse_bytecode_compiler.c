/**
 * @file qihse_bytecode_compiler.c
 * @brief WHERE-clause recursive-descent compiler → QIHSE bytecode.
 *
 * The QQL parser (qihse_qql_parser.c) is currently a stub that does not
 * produce a real AST.  This file therefore bundles its own lexer and
 * recursive-descent parser so that compilation is self-contained.
 *
 * Compilation pipeline
 * ─────────────────────
 *  Input string
 *     ↓  Lexer (tokenise)
 *  Token stream
 *     ↓  Recursive-descent parser
 *  Bytecode stream (left-to-right post-order emission)
 *     ↓  OP_RET appended
 *  uint8_t buffer ready for qihse_bytecode_eval()
 *
 * The emitter writes directly to the caller-supplied output buffer; no heap
 * allocation is performed.
 */

#include "qihse_bytecode_compiler.h"
#include "qihse_bytecode.h"

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════ */
/* § 1  Lexer                                                                 */
/* ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    TOK_EOF = 0,
    TOK_LPAREN,      /* (              */
    TOK_RPAREN,      /* )              */
    TOK_EQ,          /* ==             */
    TOK_NEQ,         /* !=             */
    TOK_GT,          /* >              */
    TOK_GTE,         /* >=             */
    TOK_LT,          /* <              */
    TOK_LTE,         /* <=             */
    TOK_AND,         /* AND            */
    TOK_OR,          /* OR             */
    TOK_NOT,         /* NOT            */
    TOK_INT,         /* 42, -17 …      */
    TOK_STR,         /* "hello"        */
    TOK_IDENT,       /* field name     */
    TOK_ERROR,       /* lexer error    */
} tok_type_t;

#define LEX_BUF_MAX 256   /* max identifier / string token length */

typedef struct {
    tok_type_t  type;
    char        text[LEX_BUF_MAX]; /* NUL-terminated lexeme for IDENT/STR  */
    int64_t     ival;              /* parsed integer value for TOK_INT      */
} token_t;

typedef struct {
    const char *src;   /* original input                         */
    int         pos;   /* current read position                  */
} lexer_t;

/* Forward declarations for parse functions */
static int parse_expr(lexer_t *lex, token_t *cur, uint8_t *buf,
                      size_t buf_size, size_t *off, int depth);

/* ─── Lexer helpers ──────────────────────────────────────────────────────── */

static void lex_skip_ws(lexer_t *lex) {
    while (lex->src[lex->pos] && isspace((unsigned char)lex->src[lex->pos]))
        lex->pos++;
}

/* Case-insensitive keyword check against null-terminated keyword string.     */
static int kw_match(const char *text, const char *kw) {
    while (*kw) {
        if (tolower((unsigned char)*text) != tolower((unsigned char)*kw))
            return 0;
        text++; kw++;
    }
    /* Ensure the identifier doesn't continue after the keyword              */
    return !isalnum((unsigned char)*text) && *text != '_';
}

/* Advance lexer and fill *tok with the next token.                          */
static void lex_next(lexer_t *lex, token_t *tok) {
    lex_skip_ws(lex);
    tok->text[0] = '\0';
    tok->ival    = 0;

    char c = lex->src[lex->pos];

    if (c == '\0') { tok->type = TOK_EOF;  return; }

    /* Two-character operators ─────────────────────────────────────────── */
    char c2 = lex->src[lex->pos + 1];

    if (c == '=' && c2 == '=') { lex->pos += 2; tok->type = TOK_EQ;  return; }
    if (c == '!' && c2 == '=') { lex->pos += 2; tok->type = TOK_NEQ; return; }
    if (c == '>' && c2 == '=') { lex->pos += 2; tok->type = TOK_GTE; return; }
    if (c == '<' && c2 == '=') { lex->pos += 2; tok->type = TOK_LTE; return; }

    /* Single-character operators ──────────────────────────────────────── */
    if (c == '>') { lex->pos++; tok->type = TOK_GT;     return; }
    if (c == '<') { lex->pos++; tok->type = TOK_LT;     return; }
    if (c == '(') { lex->pos++; tok->type = TOK_LPAREN; return; }
    if (c == ')') { lex->pos++; tok->type = TOK_RPAREN; return; }

    /* String literal ─────────────────────────────────────────────────── */
    if (c == '"') {
        lex->pos++;
        int len = 0;
        while (lex->src[lex->pos] && lex->src[lex->pos] != '"') {
            if (len < LEX_BUF_MAX - 1) {
                /* Handle simple escape sequences */
                if (lex->src[lex->pos] == '\\' && lex->src[lex->pos + 1]) {
                    lex->pos++;
                    char esc = lex->src[lex->pos];
                    switch (esc) {
                        case 'n':  tok->text[len++] = '\n'; break;
                        case 't':  tok->text[len++] = '\t'; break;
                        case '\\': tok->text[len++] = '\\'; break;
                        case '"':  tok->text[len++] = '"';  break;
                        default:   tok->text[len++] = esc;  break;
                    }
                } else {
                    tok->text[len++] = lex->src[lex->pos];
                }
            }
            lex->pos++;
        }
        if (lex->src[lex->pos] == '"') lex->pos++; /* consume closing " */
        tok->text[len] = '\0';
        tok->type      = TOK_STR;
        return;
    }

    /* Integer literal (optional leading minus) ───────────────────────── */
    if (isdigit((unsigned char)c) ||
        (c == '-' && isdigit((unsigned char)c2))) {
        int len   = 0;
        int start = lex->pos;
        if (c == '-') { tok->text[len++] = '-'; lex->pos++; }
        while (isdigit((unsigned char)lex->src[lex->pos]) &&
               len < LEX_BUF_MAX - 1) {
            tok->text[len++] = lex->src[lex->pos++];
        }
        tok->text[len] = '\0';
        tok->ival      = (int64_t)strtoll(tok->text, NULL, 10);
        (void)start;
        tok->type      = TOK_INT;
        return;
    }

    /* Identifier or keyword ──────────────────────────────────────────── */
    if (isalpha((unsigned char)c) || c == '_') {
        int len = 0;
        while ((isalnum((unsigned char)lex->src[lex->pos]) ||
                lex->src[lex->pos] == '_') &&
               len < LEX_BUF_MAX - 1) {
            tok->text[len++] = lex->src[lex->pos++];
        }
        tok->text[len] = '\0';

        if (kw_match(tok->text, "AND")) { tok->type = TOK_AND; return; }
        if (kw_match(tok->text, "OR"))  { tok->type = TOK_OR;  return; }
        if (kw_match(tok->text, "NOT")) { tok->type = TOK_NOT; return; }
        /* "WHERE" prefix — silently skip at top of expression */
        tok->type = TOK_IDENT;
        return;
    }

    /* Unknown character → error */
    tok->type = TOK_ERROR;
    snprintf(tok->text, sizeof(tok->text), "Unexpected char: '%c' (0x%02x)",
             c, (unsigned char)c);
    lex->pos++;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/* § 2  Emitter                                                               */
/* ═══════════════════════════════════════════════════════════════════════════ */

#define MAX_DEPTH 64  /* maximum recursive parse depth */

/* Write one byte to the output buffer; advance *off.  Returns 0 on success. */
static int emit_byte(uint8_t *buf, size_t buf_size, size_t *off, uint8_t b) {
    if (*off >= buf_size) return QIHSE_BC_ERR_OVERFLOW;
    buf[(*off)++] = b;
    return QIHSE_BC_OK;
}

/* Write an int64_t (8 bytes, host byte order) to the output buffer.         */
static int emit_i64(uint8_t *buf, size_t buf_size, size_t *off, int64_t v) {
    if (*off + sizeof(int64_t) > buf_size) return QIHSE_BC_ERR_OVERFLOW;
    memcpy(buf + *off, &v, sizeof(int64_t));
    *off += sizeof(int64_t);
    return QIHSE_BC_OK;
}

/* Write a NUL-terminated string (including the NUL) to the output buffer.   */
static int emit_str(uint8_t *buf, size_t buf_size, size_t *off,
                    const char *s) {
    size_t len = strlen(s) + 1; /* include NUL terminator */
    if (*off + len > buf_size) return QIHSE_BC_ERR_OVERFLOW;
    memcpy(buf + *off, s, len);
    *off += len;
    return QIHSE_BC_OK;
}

/* Convenience: emit opcode byte, then optional int64 / string payload.      */
#define EMIT(b)           do { int _e = emit_byte(buf,buf_size,off,(uint8_t)(b)); if (_e) return _e; } while(0)
#define EMIT_I64(v)       do { int _e = emit_i64(buf,buf_size,off,(v));           if (_e) return _e; } while(0)
#define EMIT_CSTR(s)      do { int _e = emit_str(buf,buf_size,off,(s));           if (_e) return _e; } while(0)

/* ═══════════════════════════════════════════════════════════════════════════ */
/* § 3  Recursive-descent parser / code emitter                              */
/* ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Grammar:
 *   expr       → or_expr
 *   or_expr    → and_expr  ( "OR"  and_expr  )*
 *   and_expr   → not_expr  ( "AND" not_expr  )*
 *   not_expr   → "NOT" not_expr | paren_expr
 *   paren_expr → "(" expr ")" | cmp_expr
 *   cmp_expr   → operand cmp_op operand
 *   operand    → INT | STRING | IDENT
 *
 * Emission is post-order (left operand → right operand → operator), which
 * matches the stack-machine evaluation model.
 */

/* Forward declaration */
static int parse_expr(lexer_t *lex, token_t *cur,
                      uint8_t *buf, size_t buf_size, size_t *off, int depth);

/* ── operand ──────────────────────────────────────────────────────────────── */
static int parse_operand(lexer_t *lex, token_t *cur,
                         uint8_t *buf, size_t buf_size, size_t *off) {
    if (cur->type == TOK_INT) {
        EMIT(OP_PUSH_INT);
        EMIT_I64(cur->ival);
        lex_next(lex, cur);
        return QIHSE_BC_OK;
    }
    if (cur->type == TOK_STR) {
        EMIT(OP_PUSH_STR);
        EMIT_CSTR(cur->text);
        lex_next(lex, cur);
        return QIHSE_BC_OK;
    }
    if (cur->type == TOK_IDENT) {
        EMIT(OP_LOAD_FIELD);
        EMIT_CSTR(cur->text);
        lex_next(lex, cur);
        return QIHSE_BC_OK;
    }
    return QIHSE_BC_ERR_SYNTAX;
}

/* ── cmp_expr ─────────────────────────────────────────────────────────────── */
static int parse_cmp_expr(lexer_t *lex, token_t *cur,
                           uint8_t *buf, size_t buf_size, size_t *off) {
    /* Left operand */
    int rc = parse_operand(lex, cur, buf, buf_size, off);
    if (rc) return rc;

    /* Comparison operator */
    tok_type_t op = cur->type;
    if (op != TOK_EQ  && op != TOK_NEQ && op != TOK_GT  &&
        op != TOK_GTE && op != TOK_LT  && op != TOK_LTE)
        return QIHSE_BC_ERR_SYNTAX;

    lex_next(lex, cur);

    /* Right operand */
    rc = parse_operand(lex, cur, buf, buf_size, off);
    if (rc) return rc;

    /* Emit comparison opcode */
    switch (op) {
        case TOK_EQ:  EMIT(OP_EQ);  break;
        case TOK_NEQ: EMIT(OP_NEQ); break;
        case TOK_GT:  EMIT(OP_GT);  break;
        case TOK_GTE: EMIT(OP_GTE); break;
        case TOK_LT:  EMIT(OP_LT);  break;
        case TOK_LTE: EMIT(OP_LTE); break;
        default: return QIHSE_BC_ERR_SYNTAX;
    }
    return QIHSE_BC_OK;
}

/* ── not_expr / paren_expr ───────────────────────────────────────────────── */
static int parse_not_expr(lexer_t *lex, token_t *cur,
                           uint8_t *buf, size_t buf_size, size_t *off,
                           int depth) {
    if (depth > MAX_DEPTH) return QIHSE_BC_ERR_DEPTH;

    if (cur->type == TOK_NOT) {
        lex_next(lex, cur);
        int rc = parse_not_expr(lex, cur, buf, buf_size, off, depth + 1);
        if (rc) return rc;
        EMIT(OP_NOT);
        return QIHSE_BC_OK;
    }

    if (cur->type == TOK_LPAREN) {
        lex_next(lex, cur); /* consume '(' */
        int rc = parse_expr(lex, cur, buf, buf_size, off, depth + 1);
        if (rc) return rc;
        if (cur->type != TOK_RPAREN) return QIHSE_BC_ERR_SYNTAX;
        lex_next(lex, cur); /* consume ')' */
        return QIHSE_BC_OK;
    }

    /* Must be a comparison expression */
    return parse_cmp_expr(lex, cur, buf, buf_size, off);
}

/* ── and_expr ─────────────────────────────────────────────────────────────── */
static int parse_and_expr(lexer_t *lex, token_t *cur,
                           uint8_t *buf, size_t buf_size, size_t *off,
                           int depth) {
    int rc = parse_not_expr(lex, cur, buf, buf_size, off, depth);
    if (rc) return rc;

    while (cur->type == TOK_AND) {
        lex_next(lex, cur);
        rc = parse_not_expr(lex, cur, buf, buf_size, off, depth);
        if (rc) return rc;
        EMIT(OP_AND);
    }
    return QIHSE_BC_OK;
}

/* ── or_expr / top-level expr ────────────────────────────────────────────── */
static int parse_expr(lexer_t *lex, token_t *cur,
                      uint8_t *buf, size_t buf_size, size_t *off, int depth) {
    int rc = parse_and_expr(lex, cur, buf, buf_size, off, depth);
    if (rc) return rc;

    while (cur->type == TOK_OR) {
        lex_next(lex, cur);
        rc = parse_and_expr(lex, cur, buf, buf_size, off, depth);
        if (rc) return rc;
        EMIT(OP_OR);
    }
    return QIHSE_BC_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/* § 4  Public API                                                            */
/* ═══════════════════════════════════════════════════════════════════════════ */

int qihse_bc_compile(const char *where_clause,
                     uint8_t    *out_buf,
                     size_t      buf_size,
                     size_t     *out_len) {
    if (!where_clause || !out_buf || buf_size == 0)
        return QIHSE_BC_ERR_NULL;

    /* Consume optional leading "WHERE" keyword */
    const char *expr_start = where_clause;
    {
        const char *p = where_clause;
        while (*p && isspace((unsigned char)*p)) p++;
        /* Case-insensitive match for "WHERE" followed by whitespace or '(' */
        if (strncasecmp(p, "WHERE", 5) == 0 &&
            (isspace((unsigned char)p[5]) || p[5] == '(')) {
            expr_start = p + 5;
        }
    }

    lexer_t lex = { .src = expr_start, .pos = 0 };
    token_t cur;
    lex_next(&lex, &cur);

    size_t off = 0;
    int rc = parse_expr(&lex, &cur, out_buf, buf_size, &off, 0);
    if (rc) return rc;

    /* Expect end-of-input */
    if (cur.type != TOK_EOF) return QIHSE_BC_ERR_SYNTAX;

    /* Append OP_RET */
    rc = emit_byte(out_buf, buf_size, &off, (uint8_t)OP_RET);
    if (rc) return rc;

    if (out_len) *out_len = off;
    return QIHSE_BC_OK;
}

const char *qihse_bc_error_str(int err) {
    switch ((qihse_bc_error_t)err) {
        case QIHSE_BC_OK:           return "OK";
        case QIHSE_BC_ERR_NULL:     return "Null argument";
        case QIHSE_BC_ERR_OVERFLOW: return "Output buffer too small";
        case QIHSE_BC_ERR_SYNTAX:   return "Syntax error";
        case QIHSE_BC_ERR_DEPTH:    return "Expression too deeply nested";
        default:                    return "Unknown error";
    }
}

/* ═══════════════════════════════════════════════════════════════════════════ */
/* § 5  Inline self-test  (compiled only when -DQIHSE_BC_COMPILER_TEST)      */
/* ═══════════════════════════════════════════════════════════════════════════ */

#ifdef QIHSE_BC_COMPILER_TEST

#include <assert.h>

/*
 * Run a pair of eval checks for the expression:
 *   age > 25 AND city == "London"
 *
 *  • Matching row    : age=30, city="London"   → expect true
 *  • Non-matching row: age=20, city="Paris"    → expect false
 */
static void run_age_city_test(void) {
    /* ── Step 1: compile ──────────────────────────────────────────────── */
    const char *clause = "age > 25 AND city == \"London\"";

    uint8_t   bc[256];
    size_t    bc_len = 0;
    int       rc     = qihse_bc_compile(clause, bc, sizeof(bc), &bc_len);

    printf("[BC Compiler Test] compile('%s') → rc=%d, len=%zu\n",
           clause, rc, bc_len);
    assert(rc == QIHSE_BC_OK && "compile must succeed");
    assert(bc_len > 0);

    /* ── Step 2: matching context ─────────────────────────────────────── */
    qihse_bytecode_field_t match_fields[] = {
        { "age",  QIHSE_FIELD_INT, { .i = 30       } },
        { "city", QIHSE_FIELD_STR, { .s = "London" } },
    };
    qihse_bytecode_context_t match_ctx = {
        .fields     = match_fields,
        .num_fields = 2,
    };
    bool match_result = qihse_bytecode_eval(bc, &match_ctx);
    printf("[BC Compiler Test] matching row (age=30, city=London) → %s\n",
           match_result ? "PASS (true)" : "FAIL (false)");
    assert(match_result == true && "matching row must pass filter");

    /* ── Step 3: non-matching context ────────────────────────────────── */
    qihse_bytecode_field_t nomatch_fields[] = {
        { "age",  QIHSE_FIELD_INT, { .i = 20      } },
        { "city", QIHSE_FIELD_STR, { .s = "Paris" } },
    };
    qihse_bytecode_context_t nomatch_ctx = {
        .fields     = nomatch_fields,
        .num_fields = 2,
    };
    bool nomatch_result = qihse_bytecode_eval(bc, &nomatch_ctx);
    printf("[BC Compiler Test] non-matching row (age=20, city=Paris) → %s\n",
           nomatch_result ? "FAIL (true)" : "PASS (false)");
    assert(nomatch_result == false && "non-matching row must fail filter");

    /* ── Step 4: partial-match edge case (age passes, city fails) ────── */
    qihse_bytecode_field_t partial_fields[] = {
        { "age",  QIHSE_FIELD_INT, { .i = 30      } },
        { "city", QIHSE_FIELD_STR, { .s = "Paris" } },
    };
    qihse_bytecode_context_t partial_ctx = {
        .fields     = partial_fields,
        .num_fields = 2,
    };
    bool partial_result = qihse_bytecode_eval(bc, &partial_ctx);
    printf("[BC Compiler Test] partial row (age=30, city=Paris) → %s\n",
           partial_result ? "FAIL (true)" : "PASS (false)");
    assert(partial_result == false && "partial match must fail AND filter");
}

/*
 * Additional test: NOT and OR operators.
 *   NOT (score < 10) OR label == "vip"
 */
static void run_not_or_test(void) {
    const char *clause = "NOT (score < 10) OR label == \"vip\"";

    uint8_t bc[256];
    size_t  bc_len = 0;
    int     rc     = qihse_bc_compile(clause, bc, sizeof(bc), &bc_len);

    printf("[BC Compiler Test] compile('%s') → rc=%d, len=%zu\n",
           clause, rc, bc_len);
    assert(rc == QIHSE_BC_OK);

    /* Row where NOT (score < 10) is true → passes */
    qihse_bytecode_field_t r1_fields[] = {
        { "score", QIHSE_FIELD_INT, { .i = 15      } },
        { "label", QIHSE_FIELD_STR, { .s = "basic" } },
    };
    qihse_bytecode_context_t r1 = { .fields = r1_fields, .num_fields = 2 };
    bool r1_result = qihse_bytecode_eval(bc, &r1);
    printf("[BC Compiler Test] NOT (score=15 < 10) OR label=basic → %s\n",
           r1_result ? "PASS (true)" : "FAIL (false)");
    assert(r1_result == true);

    /* Row where score < 10 (NOT false), but label == "vip" → true via OR */
    qihse_bytecode_field_t r2_fields[] = {
        { "score", QIHSE_FIELD_INT, { .i = 5     } },
        { "label", QIHSE_FIELD_STR, { .s = "vip" } },
    };
    qihse_bytecode_context_t r2 = { .fields = r2_fields, .num_fields = 2 };
    bool r2_result = qihse_bytecode_eval(bc, &r2);
    printf("[BC Compiler Test] NOT (score=5 < 10) OR label=vip → %s\n",
           r2_result ? "PASS (true)" : "FAIL (false)");
    assert(r2_result == true);

    /* Row where both branches are false → false */
    qihse_bytecode_field_t r3_fields[] = {
        { "score", QIHSE_FIELD_INT, { .i = 5       } },
        { "label", QIHSE_FIELD_STR, { .s = "basic" } },
    };
    qihse_bytecode_context_t r3 = { .fields = r3_fields, .num_fields = 2 };
    bool r3_result = qihse_bytecode_eval(bc, &r3);
    printf("[BC Compiler Test] NOT (score=5 < 10) OR label=basic → %s\n",
           r3_result ? "FAIL (true)" : "PASS (false)");
    assert(r3_result == false);
}

/*
 * Test: WHERE keyword prefix is silently consumed.
 */
static void run_where_prefix_test(void) {
    const char *clause = "WHERE value != 0";
    uint8_t     bc[128];
    size_t      bc_len = 0;
    int         rc     = qihse_bc_compile(clause, bc, sizeof(bc), &bc_len);
    printf("[BC Compiler Test] compile('%s') → rc=%d\n", clause, rc);
    assert(rc == QIHSE_BC_OK);

    qihse_bytecode_field_t fields[] = {
        { "value", QIHSE_FIELD_INT, { .i = 7 } },
    };
    qihse_bytecode_context_t ctx = { .fields = fields, .num_fields = 1 };
    assert(qihse_bytecode_eval(bc, &ctx) == true);

    qihse_bytecode_field_t fields0[] = {
        { "value", QIHSE_FIELD_INT, { .i = 0 } },
    };
    qihse_bytecode_context_t ctx0 = { .fields = fields0, .num_fields = 1 };
    assert(qihse_bytecode_eval(bc, &ctx0) == false);
    printf("[BC Compiler Test] WHERE-prefix test PASS\n");
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════\n");
    printf(" QIHSE Bytecode Compiler — self-test\n");
    printf("═══════════════════════════════════════════════════════════\n");

    run_age_city_test();
    run_not_or_test();
    run_where_prefix_test();

    printf("═══════════════════════════════════════════════════════════\n");
    printf(" All tests PASSED\n");
    printf("═══════════════════════════════════════════════════════════\n");
    return 0;
}

#endif /* QIHSE_BC_COMPILER_TEST */
