/* QIHSE Cypher Parser — recursive-descent. Produces qihse_cypher_ast_t. */

#include "qihse_cypher_parser.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

/* ---- error reporting ---- */
static char g_error[256] = {0};
const char* qihse_cypher_error(void) { return g_error; }
static void set_err(const char* fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_error, sizeof(g_error), fmt, ap);
    va_end(ap);
}

/* ---- tokenizer ---- */
typedef enum {
    TOK_EOF, TOK_IDENT, TOK_KEYWORD, TOK_STRING, TOK_INT, TOK_DOUBLE,
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACK, TOK_RBRACK, TOK_LBRACE, TOK_RBRACE,
    TOK_COMMA, TOK_COLON, TOK_SEMI, TOK_DOT, TOK_DASH, TOK_ARROW_L, TOK_ARROW_R,
    TOK_PIPE, TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE, TOK_PLUS, TOK_MINUS,
    TOK_STAR, TOK_SLASH, TOK_PERCENT, TOK_DOLLAR, TOK_QUESTION
} tok_kind_t;

typedef struct {
    tok_kind_t kind;
    char* text;       /* owned for ident/string/keyword */
    int64_t i_val;
    double d_val;
    size_t pos;
} token_t;

typedef struct {
    const char* src;
    size_t len;
    size_t pos;
    token_t cur;
    token_t next;
    bool has_next;
} lexer_t;

static const struct { const char* upper; tok_kind_t kind; } KEYWORDS[] = {
    {"MATCH", TOK_KEYWORD}, {"CREATE", TOK_KEYWORD}, {"MERGE", TOK_KEYWORD},
    {"DELETE", TOK_KEYWORD}, {"DETACH", TOK_KEYWORD}, {"SET", TOK_KEYWORD},
    {"REMOVE", TOK_KEYWORD}, {"RETURN", TOK_KEYWORD}, {"WITH", TOK_KEYWORD},
    {"WHERE", TOK_KEYWORD}, {"ORDER", TOK_KEYWORD}, {"BY", TOK_KEYWORD},
    {"LIMIT", TOK_KEYWORD}, {"SKIP", TOK_KEYWORD}, {"UNWIND", TOK_KEYWORD},
    {"UNION", TOK_KEYWORD}, {"ALL", TOK_KEYWORD}, {"DISTINCT", TOK_KEYWORD},
    {"AS", TOK_KEYWORD}, {"AND", TOK_KEYWORD}, {"OR", TOK_KEYWORD}, {"NOT", TOK_KEYWORD},
    {"IN", TOK_KEYWORD}, {"IS", TOK_KEYWORD}, {"NULL", TOK_KEYWORD},
    {"STARTS", TOK_KEYWORD}, {"ENDS", TOK_KEYWORD}, {"WITH", TOK_KEYWORD},
    {"CONTAINS", TOK_KEYWORD}, {"EXISTS", TOK_KEYWORD}, {"TRUE", TOK_KEYWORD},
    {"FALSE", TOK_KEYWORD}, {"CASE", TOK_KEYWORD}, {"WHEN", TOK_KEYWORD},
    {"THEN", TOK_KEYWORD}, {"ELSE", TOK_KEYWORD}, {"END", TOK_KEYWORD},
    {"ASC", TOK_KEYWORD}, {"DESC", TOK_KEYWORD}, {"ON", TOK_KEYWORD},
    {"LOAD", TOK_KEYWORD}, {"CSV", TOK_KEYWORD}, {"FROM", TOK_KEYWORD},
    {"HEADERS", TOK_KEYWORD}, {"CALL", TOK_KEYWORD}, {"YIELD", TOK_KEYWORD},
    {"FOREACH", TOK_KEYWORD}, {"INDEX", TOK_KEYWORD}, {"CONSTRAINT", TOK_KEYWORD},
    {"DROP", TOK_KEYWORD}, {"SHOW", TOK_KEYWORD}, {"DATABASE", TOK_KEYWORD},
    {"DATABASES", TOK_KEYWORD}, {"EXPLAIN", TOK_KEYWORD}, {"PROFILE", TOK_KEYWORD},
    {"USE", TOK_KEYWORD}, {"PERIODIC", TOK_KEYWORD}, {"COMMIT", TOK_KEYWORD},
    {"TRANSACTIONS", TOK_KEYWORD}, {"ROWS", TOK_KEYWORD}, {"NULLS", TOK_KEYWORD},
    {"FIRST", TOK_KEYWORD}, {"LAST", TOK_KEYWORD}, {"ASSERT", TOK_KEYWORD},
    {"UNIQUE", TOK_KEYWORD}, {"KEY", TOK_KEYWORD}, {"START", TOK_KEYWORD},
    {"STOP", TOK_KEYWORD}, {"ALTER", TOK_KEYWORD}, {"READ", TOK_KEYWORD},
    {"ONLY", TOK_KEYWORD}, {"WRITE", TOK_KEYWORD}, {"BUILT", TOK_KEYWORD},
    {"PROCEDURES", TOK_KEYWORD}, {"FUNCTIONS", TOK_KEYWORD},
    {"EXECUTABLE", TOK_KEYWORD}, {"IF", TOK_KEYWORD}, {"COUNT", TOK_KEYWORD},
    {"COLLECT", TOK_KEYWORD},
    {NULL, TOK_EOF}
};

static bool is_ident_start(char c) { return isalpha((unsigned char)c) || c == '_'; }
static bool is_ident_char(char c) { return isalnum((unsigned char)c) || c == '_'; }

static void token_free(token_t* t) {
    free(t->text); t->text = NULL;
}

static bool lex_next(lexer_t* L, token_t* out) {
    while (L->pos < L->len && isspace((unsigned char)L->src[L->pos])) L->pos++;
    token_t t = {0};
    t.pos = L->pos;
    if (L->pos >= L->len) { t.kind = TOK_EOF; *out = t; return true; }
    char c = L->src[L->pos];
    /* comments */
    if (c == '/' && L->pos + 1 < L->len && L->src[L->pos+1] == '/') {
        while (L->pos < L->len && L->src[L->pos] != '\n') L->pos++;
        return lex_next(L, out);
    }
    /* string */
    if (c == '"' || c == '\'') {
        char q = c; L->pos++;
        size_t start = L->pos;
        while (L->pos < L->len && L->src[L->pos] != q) {
            if (L->src[L->pos] == '\\' && L->pos + 1 < L->len) L->pos += 2;
            else L->pos++;
        }
        size_t n = L->pos - start;
        char* s = malloc(n + 1);
        size_t j = 0;
        for (size_t i = 0; i < n; ++i) {
            char x = L->src[start + i];
            if (x == '\\' && i + 1 < n) {
                char nx = L->src[start + ++i];
                switch (nx) {
                    case 'n': s[j++] = '\n'; break;
                    case 't': s[j++] = '\t'; break;
                    case 'r': s[j++] = '\r'; break;
                    case '"': s[j++] = '"'; break;
                    case '\'': s[j++] = '\''; break;
                    case '\\': s[j++] = '\\'; break;
                    default: s[j++] = nx; break;
                }
            } else s[j++] = x;
        }
        s[j] = '\0';
        if (L->pos < L->len) L->pos++; /* closing quote */
        t.kind = TOK_STRING; t.text = s;
        *out = t; return true;
    }
    /* number */
    if (isdigit((unsigned char)c) || (c == '-' && L->pos + 1 < L->len && isdigit((unsigned char)L->src[L->pos+1]))) {
        size_t start = L->pos;
        bool neg = false;
        if (c == '-') { neg = true; L->pos++; }
        bool isdbl = false;
        while (L->pos < L->len && isdigit((unsigned char)L->src[L->pos])) L->pos++;
        if (L->pos < L->len && L->src[L->pos] == '.') {
            isdbl = true; L->pos++;
            while (L->pos < L->len && isdigit((unsigned char)L->src[L->pos])) L->pos++;
        }
        if (L->pos < L->len && (L->src[L->pos] == 'e' || L->src[L->pos] == 'E')) {
            isdbl = true; L->pos++;
            if (L->pos < L->len && (L->src[L->pos] == '+' || L->src[L->pos] == '-')) L->pos++;
            while (L->pos < L->len && isdigit((unsigned char)L->src[L->pos])) L->pos++;
        }
        size_t n = L->pos - start;
        char* buf = malloc(n + 1);
        memcpy(buf, L->src + start, n); buf[n] = '\0';
        if (isdbl) { t.kind = TOK_DOUBLE; t.d_val = atof(buf); if (neg) t.d_val = -t.d_val; }
        else { t.kind = TOK_INT; t.i_val = strtoll(buf, NULL, 10); }
        free(buf);
        *out = t; return true;
    }
    /* identifier / keyword */
    if (is_ident_start(c)) {
        size_t start = L->pos;
        while (L->pos < L->len && is_ident_char(L->src[L->pos])) L->pos++;
        size_t n = L->pos - start;
        char* s = malloc(n + 1);
        memcpy(s, L->src + start, n); s[n] = '\0';
        /* check keyword (case-insensitive) */
        char up[64];
        for (size_t i = 0; i < n && i < 63; ++i) up[i] = (char)toupper((unsigned char)s[i]);
        up[n < 63 ? n : 63] = '\0';
        for (int k = 0; KEYWORDS[k].upper; ++k) {
            if (strcmp(up, KEYWORDS[k].upper) == 0) {
                t.kind = TOK_KEYWORD; t.text = s;
                *out = t; return true;
            }
        }
        t.kind = TOK_IDENT; t.text = s;
        *out = t; return true;
    }
    /* parameter */
    if (c == '$') {
        L->pos++;
        size_t start = L->pos;
        while (L->pos < L->len && is_ident_char(L->src[L->pos])) L->pos++;
        size_t n = L->pos - start;
        char* s = malloc(n + 1);
        memcpy(s, L->src + start, n); s[n] = '\0';
        t.kind = TOK_DOLLAR; t.text = s;
        *out = t; return true;
    }
    /* multi-char operators */
    if (c == '-' && L->pos + 1 < L->len && L->src[L->pos+1] == '>') {
        L->pos += 2; t.kind = TOK_ARROW_R; *out = t; return true;
    }
    if (c == '<' && L->pos + 1 < L->len && L->src[L->pos+1] == '-') {
        L->pos += 2; t.kind = TOK_ARROW_L; *out = t; return true;
    }
    if (c == '<' && L->pos + 1 < L->len && L->src[L->pos+1] == '=') {
        L->pos += 2; t.kind = TOK_LE; *out = t; return true;
    }
    if (c == '>' && L->pos + 1 < L->len && L->src[L->pos+1] == '=') {
        L->pos += 2; t.kind = TOK_GE; *out = t; return true;
    }
    if (c == '<' && L->pos + 1 < L->len && L->src[L->pos+1] == '>') {
        L->pos += 2; t.kind = TOK_NE; *out = t; return true;
    }
    if (c == '=' && L->pos + 1 < L->len && L->src[L->pos+1] == '=') {
        L->pos += 2; t.kind = TOK_EQ; *out = t; return true;
    }
    /* single char */
    L->pos++;
    switch (c) {
        case '(': t.kind = TOK_LPAREN; break;
        case ')': t.kind = TOK_RPAREN; break;
        case '[': t.kind = TOK_LBRACK; break;
        case ']': t.kind = TOK_RBRACK; break;
        case '{': t.kind = TOK_LBRACE; break;
        case '}': t.kind = TOK_RBRACE; break;
        case ',': t.kind = TOK_COMMA; break;
        case ':': t.kind = TOK_COLON; break;
        case ';': t.kind = TOK_SEMI; break;
        case '.': t.kind = TOK_DOT; break;
        case '-': t.kind = TOK_DASH; break;
        case '|': t.kind = TOK_PIPE; break;
        case '=': t.kind = TOK_EQ; break;
        case '<': t.kind = TOK_LT; break;
        case '>': t.kind = TOK_GT; break;
        case '+': t.kind = TOK_PLUS; break;
        case '*': t.kind = TOK_STAR; break;
        case '/': t.kind = TOK_SLASH; break;
        case '%': t.kind = TOK_PERCENT; break;
        case '?': t.kind = TOK_QUESTION; break;
        default:
            set_err("unexpected char '%c' at %zu", c, L->pos);
            return false;
    }
    *out = t;
    return true;
}

static void lex_advance(lexer_t* L) {
    if (L->has_next) { token_free(&L->cur); L->cur = L->next; L->has_next = false; }
    else { token_free(&L->cur); lex_next(L, &L->cur); }
}

static token_t* lex_peek(lexer_t* L) {
    if (!L->has_next) { lex_next(L, &L->next); L->has_next = true; }
    return &L->next;
}

static bool lex_init(lexer_t* L, const char* src) {
    L->src = src; L->len = strlen(src); L->pos = 0;
    L->has_next = false;
    memset(&L->cur, 0, sizeof(L->cur));
    memset(&L->next, 0, sizeof(L->next));
    lex_next(L, &L->cur);
    return true;
}

static bool is_kw(const token_t* t, const char* kw) {
    if (t->kind != TOK_KEYWORD || !t->text) return false;
    return strcasecmp(t->text, kw) == 0;
}

/* ---- AST allocators ---- */

static cypher_expr_t* expr_new(cypher_expr_type_t t) {
    cypher_expr_t* e = calloc(1, sizeof(cypher_expr_t));
    e->type = t;
    return e;
}

static cypher_node_pattern_t* node_new(void) {
    return calloc(1, sizeof(cypher_node_pattern_t));
}
static cypher_rel_pattern_t* rel_new(void) {
    cypher_rel_pattern_t* r = calloc(1, sizeof(cypher_rel_pattern_t));
    r->var_len_min = -1; r->var_len_max = -1;
    return r;
}
static cypher_path_t* path_new(void) {
    return calloc(1, sizeof(cypher_path_t));
}
static cypher_return_item_t* ret_new(cypher_expr_t* e) {
    cypher_return_item_t* r = calloc(1, sizeof(cypher_return_item_t));
    r->expr = e;
    return r;
}
static cypher_set_item_t* setitem_new(void) {
    return calloc(1, sizeof(cypher_set_item_t));
}
static cypher_order_item_t* ord_new(cypher_expr_t* e) {
    cypher_order_item_t* o = calloc(1, sizeof(cypher_order_item_t));
    o->expr = e;
    return o;
}
static qihse_cypher_clause_t* clause_new(qihse_cypher_clause_type_t t) {
    qihse_cypher_clause_t* c = calloc(1, sizeof(qihse_cypher_clause_t));
    c->type = t;
    c->skip = -1; c->limit = -1;
    return c;
}

static void expr_free(cypher_expr_t* e);
static void path_free(cypher_path_t* p);
static void clause_free(qihse_cypher_clause_t* c);

static void expr_free(cypher_expr_t* e) {
    if (!e) return;
    free(e->s_val);
    expr_free(e->left); expr_free(e->right); expr_free(e->else_expr);
    for (size_t i = 0; i < e->count; ++i) { expr_free(e->items[i]); free(e->keys ? e->keys[i] : NULL); }
    free(e->items); free(e->keys);
    for (size_t i = 0; i < e->nargs; ++i) expr_free(e->args[i]);
    free(e->args);
    for (size_t i = 0; i < e->ncase; ++i) { expr_free(e->when_exprs[i]); expr_free(e->then_exprs[i]); }
    free(e->when_exprs); free(e->then_exprs);
    /* comprehension fields */
    free(e->comp_var);
    expr_free(e->comp_list);
    expr_free(e->comp_where);
    expr_free(e->comp_proj);
    path_free(e->comp_path);
    expr_free(e->idx_start);
    expr_free(e->idx_end);
    /* subquery */
    if (e->subquery) {
        clause_free(e->subquery->first);
        free(e->subquery);
    }
    free(e);
}

static void node_free(cypher_node_pattern_t* n) {
    if (!n) return;
    free(n->var); free(n->label);
    for (size_t i = 0; i < n->num_props; ++i) { expr_free(n->prop_keys[i]); expr_free(n->prop_vals[i]); }
    free(n->prop_keys); free(n->prop_vals);
    free(n);
}
static void rel_free(cypher_rel_pattern_t* r) {
    if (!r) return;
    free(r->var); free(r->rel_type);
    for (size_t i = 0; i < r->num_props; ++i) { expr_free(r->prop_keys[i]); expr_free(r->prop_vals[i]); }
    free(r->prop_keys); free(r->prop_vals);
    free(r);
}
static void path_free(cypher_path_t* p) {
    if (!p) return;
    for (size_t i = 0; i < p->num_nodes; ++i) node_free(p->nodes[i]);
    for (size_t i = 0; i < p->num_rels; ++i) rel_free(p->rels[i]);
    free(p->nodes); free(p->rels);
    free(p);
}

static void clause_free(qihse_cypher_clause_t* c) {
    if (!c) return;
    for (size_t i = 0; i < c->num_paths; ++i) path_free(c->paths[i]);
    free(c->paths);
    expr_free(c->where);
    for (size_t i = 0; i < c->num_items; ++i) {
        expr_free(c->items[i]->expr); free(c->items[i]->alias); free(c->items[i]);
    }
    free(c->items);
    for (size_t i = 0; i < c->num_set_items; ++i) {
        free(c->set_items[i]->var); free(c->set_items[i]->prop);
        free(c->set_items[i]->label); expr_free(c->set_items[i]->value);
        free(c->set_items[i]);
    }
    free(c->set_items);
    for (size_t i = 0; i < c->num_del_vars; ++i) free(c->del_vars[i]);
    free(c->del_vars);
    for (size_t i = 0; i < c->num_order_items; ++i) { expr_free(c->order_items[i]->expr); free(c->order_items[i]); }
    free(c->order_items);
    expr_free(c->unwind_expr); free(c->unwind_var);
    /* LOAD CSV */
    free(c->csv_uri); free(c->csv_var);
    /* CALL procedure */
    free(c->proc_namespace); free(c->proc_name);
    for (size_t i = 0; i < c->num_proc_args; ++i) expr_free(c->proc_args[i]);
    free(c->proc_args);
    for (size_t i = 0; i < c->num_yield_vars; ++i) free(c->yield_vars[i]);
    free(c->yield_vars);
    if (c->call_subquery) {
        clause_free(c->call_subquery->first);
        free(c->call_subquery);
    }
    /* FOREACH */
    free(c->foreach_var);
    expr_free(c->foreach_list);
    clause_free(c->foreach_body);
    /* Schema */
    free(c->schema_name); free(c->schema_label);
    for (size_t i = 0; i < c->num_schema_props; ++i) free(c->schema_props[i]);
    free(c->schema_props);
    free(c->schema_rel_type);
    /* SHOW */
    free(c->show_user);
    for (size_t i = 0; i < c->num_show_yield_vars; ++i) free(c->show_yield_vars[i]);
    free(c->show_yield_vars);
    /* USE */
    free(c->use_database);
    clause_free(c->next);
    free(c);
}

void qihse_cypher_ast_free(qihse_cypher_ast_t* ast) {
    if (!ast) return;
    for (size_t i = 0; i < ast->num_queries; ++i) {
        qihse_cypher_query_t* q = ast->queries[i];
        clause_free(q->first);
        free(q);
    }
    free(ast->queries);
    free(ast);
}

/* ---- parser ---- */
typedef struct {
    lexer_t L;
} parser_t;

static bool p_error(parser_t* p, const char* msg) {
    (void)p;
    set_err("%s (near pos %zu)", msg, p->L.cur.pos);
    return false;
}

static bool accept_kw(parser_t* p, const char* kw) {
    if (is_kw(&p->L.cur, kw)) { lex_advance(&p->L); return true; }
    return false;
}
static bool expect_kw(parser_t* p, const char* kw) {
    if (accept_kw(p, kw)) return true;
    return p_error(p, "expected keyword");
}
static bool accept_tok(parser_t* p, tok_kind_t k) {
    if (p->L.cur.kind == k) { lex_advance(&p->L); return true; }
    return false;
}
static bool expect_tok(parser_t* p, tok_kind_t k) {
    if (accept_tok(p, k)) return true;
    return p_error(p, "expected token");
}

static cypher_expr_t* parse_expr(parser_t* p);
static cypher_path_t* parse_path(parser_t* p);

static cypher_expr_t* parse_list_literal(parser_t* p) {
    expect_tok(p, TOK_LBRACK);
    cypher_expr_t* e = expr_new(CEXPR_LIST);
    size_t cap = 4;
    e->items = malloc(cap * sizeof(cypher_expr_t*));
    e->count = 0;
    if (p->L.cur.kind != TOK_RBRACK) {
        do {
            cypher_expr_t* item = parse_expr(p);
            if (!item) { expr_free(e); return NULL; }
            if (e->count == cap) { cap *= 2; e->items = realloc(e->items, cap * sizeof(cypher_expr_t*)); }
            e->items[e->count++] = item;
        } while (accept_tok(p, TOK_COMMA));
    }
    expect_tok(p, TOK_RBRACK);
    return e;
}

static cypher_expr_t* parse_map_literal(parser_t* p) {
    expect_tok(p, TOK_LBRACE);
    cypher_expr_t* e = expr_new(CEXPR_MAP);
    size_t cap = 4;
    e->items = malloc(cap * sizeof(cypher_expr_t*));
    e->keys = malloc(cap * sizeof(char*));
    e->count = 0;
    if (p->L.cur.kind != TOK_RBRACE) {
        do {
            char* key = NULL;
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                key = strdup(p->L.cur.text ? p->L.cur.text : "");
                lex_advance(&p->L);
            } else if (p->L.cur.kind == TOK_STRING) {
                key = strdup(p->L.cur.text ? p->L.cur.text : "");
                lex_advance(&p->L);
            } else return p_error(p, "expected map key"), expr_free(e), (cypher_expr_t*)NULL;
            expect_tok(p, TOK_COLON);
            cypher_expr_t* v = parse_expr(p);
            if (!v) { free(key); expr_free(e); return NULL; }
            if (e->count == cap) {
                cap *= 2;
                e->items = realloc(e->items, cap * sizeof(cypher_expr_t*));
                e->keys = realloc(e->keys, cap * sizeof(char*));
            }
            e->keys[e->count] = key;
            e->items[e->count] = v;
            e->count++;
        } while (accept_tok(p, TOK_COMMA));
    }
    expect_tok(p, TOK_RBRACE);
    return e;
}

static cypher_expr_t* parse_case(parser_t* p) {
    expect_kw(p, "CASE");
    cypher_expr_t* e = expr_new(CEXPR_CASE);
    size_t cap = 4;
    e->when_exprs = malloc(cap * sizeof(cypher_expr_t*));
    e->then_exprs = malloc(cap * sizeof(cypher_expr_t*));
    e->ncase = 0;
    while (accept_kw(p, "WHEN")) {
        cypher_expr_t* w = parse_expr(p);
        if (!w) { expr_free(e); return NULL; }
        if (!expect_kw(p, "THEN")) { expr_free(w); expr_free(e); return NULL; }
        cypher_expr_t* t = parse_expr(p);
        if (!t) { expr_free(w); expr_free(e); return NULL; }
        if ((size_t)e->ncase == cap) {
            cap *= 2;
            e->when_exprs = realloc(e->when_exprs, cap * sizeof(cypher_expr_t*));
            e->then_exprs = realloc(e->then_exprs, cap * sizeof(cypher_expr_t*));
        }
        e->when_exprs[e->ncase] = w;
        e->then_exprs[e->ncase] = t;
        e->ncase++;
    }
    if (accept_kw(p, "ELSE")) {
        e->else_expr = parse_expr(p);
        if (!e->else_expr) { expr_free(e); return NULL; }
    }
    if (!expect_kw(p, "END")) { expr_free(e); return NULL; }
    return e;
}

static cypher_expr_t* parse_primary(parser_t* p);
static qihse_cypher_query_t* parse_subquery_body(parser_t* p);
static qihse_cypher_clause_t* parse_clause(parser_t* p);

/* parse a subquery body enclosed in { ... } */
static qihse_cypher_query_t* parse_subquery_body(parser_t* p) {
    expect_tok(p, TOK_LBRACE);
    qihse_cypher_query_t* q = calloc(1, sizeof(qihse_cypher_query_t));
    qihse_cypher_clause_t* prev = NULL;
    for (;;) {
        qihse_cypher_clause_t* c = parse_clause(p);
        if (!c) break;
        if (prev) prev->next = c; else q->first = c;
        q->last = c; prev = c;
    }
    expect_tok(p, TOK_RBRACE);
    return q;
}

/* parse list comprehension: [var IN list WHERE pred | proj] */
static cypher_expr_t* parse_list_comprehension(parser_t* p) {
    expect_tok(p, TOK_LBRACK);
    cypher_expr_t* e = expr_new(CEXPR_LIST_COMP);
    /* var IN list */
    if (p->L.cur.kind != TOK_IDENT && p->L.cur.kind != TOK_KEYWORD) {
        p_error(p, "expected variable in list comprehension"); expr_free(e); return NULL;
    }
    e->comp_var = strdup(p->L.cur.text ? p->L.cur.text : "");
    lex_advance(&p->L);
    if (!expect_kw(p, "IN")) { expr_free(e); return NULL; }
    e->comp_list = parse_expr(p);
    if (!e->comp_list) { expr_free(e); return NULL; }
    /* optional WHERE */
    if (accept_kw(p, "WHERE")) {
        e->comp_where = parse_expr(p);
        if (!e->comp_where) { expr_free(e); return NULL; }
    }
    /* optional | projection */
    if (accept_tok(p, TOK_PIPE)) {
        e->comp_proj = parse_expr(p);
        if (!e->comp_proj) { expr_free(e); return NULL; }
    }
    expect_tok(p, TOK_RBRACK);
    return e;
}

/* parse pattern comprehension: [(pattern) | proj] or [(pattern) WHERE pred | proj] */
static cypher_expr_t* parse_pattern_comprehension(parser_t* p) {
    expect_tok(p, TOK_LBRACK);
    cypher_expr_t* e = expr_new(CEXPR_PATTERN_COMP);
    e->comp_path = parse_path(p);
    if (!e->comp_path) { expr_free(e); return NULL; }
    /* optional WHERE */
    if (accept_kw(p, "WHERE")) {
        e->comp_where = parse_expr(p);
        if (!e->comp_where) { expr_free(e); return NULL; }
    }
    /* | projection */
    if (accept_tok(p, TOK_PIPE)) {
        e->comp_proj = parse_expr(p);
        if (!e->comp_proj) { expr_free(e); return NULL; }
    }
    expect_tok(p, TOK_RBRACK);
    return e;
}

/* parse postfix [index] or [start..end] on an expression */
static cypher_expr_t* parse_postfix(parser_t* p, cypher_expr_t* base) {
    while (p->L.cur.kind == TOK_LBRACK) {
        lex_advance(&p->L);
        if (p->L.cur.kind == TOK_RBRACK) {
            /* empty — treat as no-op */
            lex_advance(&p->L);
            continue;
        }
        cypher_expr_t* start = parse_expr(p);
        if (!start) { expr_free(base); return NULL; }
        if (accept_tok(p, TOK_DOT)) {
            /* slice: start..end or start..] */
            expect_tok(p, TOK_DOT);
            cypher_expr_t* end = NULL;
            if (p->L.cur.kind != TOK_RBRACK) {
                end = parse_expr(p);
                if (!end) { expr_free(start); expr_free(base); return NULL; }
            }
            expect_tok(p, TOK_RBRACK);
            cypher_expr_t* s = expr_new(CEXPR_SLICE);
            s->left = base; s->idx_start = start; s->idx_end = end;
            base = s;
        } else {
            expect_tok(p, TOK_RBRACK);
            cypher_expr_t* idx = expr_new(CEXPR_INDEX_ACCESS);
            idx->left = base; idx->idx_start = start;
            base = idx;
        }
    }
    return base;
}

static cypher_expr_t* parse_primary(parser_t* p) {
    token_t* t = &p->L.cur;
    if (t->kind == TOK_INT) {
        cypher_expr_t* e = expr_new(CEXPR_LITERAL_INT); e->i_val = t->i_val;
        lex_advance(&p->L); return e;
    }
    if (t->kind == TOK_DOUBLE) {
        cypher_expr_t* e = expr_new(CEXPR_LITERAL_DBL); e->d_val = t->d_val;
        lex_advance(&p->L); return e;
    }
    if (t->kind == TOK_STRING) {
        cypher_expr_t* e = expr_new(CEXPR_LITERAL_STR); e->s_val = strdup(t->text ? t->text : "");
        lex_advance(&p->L); return e;
    }
    if (is_kw(t, "TRUE")) { cypher_expr_t* e = expr_new(CEXPR_LITERAL_BOOL); e->b_val = true; lex_advance(&p->L); return e; }
    if (is_kw(t, "FALSE")) { cypher_expr_t* e = expr_new(CEXPR_LITERAL_BOOL); e->b_val = false; lex_advance(&p->L); return e; }
    if (is_kw(t, "NULL")) { cypher_expr_t* e = expr_new(CEXPR_LITERAL_NULL); lex_advance(&p->L); return e; }
    if (is_kw(t, "CASE")) return parse_case(p);
    if (is_kw(t, "EXISTS")) {
        lex_advance(&p->L);
        if (p->L.cur.kind == TOK_LBRACE) {
            /* EXISTS { subquery } */
            qihse_cypher_query_t* sq = parse_subquery_body(p);
            if (!sq) return NULL;
            cypher_expr_t* e = expr_new(CEXPR_SUBQUERY);
            e->subquery = sq; e->subquery_kind = 1;
            return e;
        }
        expect_tok(p, TOK_LPAREN);
        cypher_expr_t* inner = parse_expr(p);
        if (!inner) return NULL;
        expect_tok(p, TOK_RPAREN);
        cypher_expr_t* e = expr_new(CEXPR_UNARYOP);
        e->op = COP_EXISTS; e->left = inner;
        return e;
    }
    if (is_kw(t, "COUNT") || is_kw(t, "COLLECT")) {
        int kind = is_kw(t, "COUNT") ? 2 : 3;
        /* peek ahead: if next is {, it's a subquery */
        token_t* nxt = lex_peek(&p->L);
        if (nxt->kind == TOK_LBRACE) {
            lex_advance(&p->L); /* consume COUNT/COLLECT */
            qihse_cypher_query_t* sq = parse_subquery_body(p);
            if (!sq) return NULL;
            cypher_expr_t* e = expr_new(CEXPR_SUBQUERY);
            e->subquery = sq; e->subquery_kind = kind;
            return e;
        }
        /* otherwise treat as regular function call — fall through */
    }
    if (t->kind == TOK_DOLLAR) {
        cypher_expr_t* e = expr_new(CEXPR_PARAM); e->s_val = strdup(t->text ? t->text : "");
        lex_advance(&p->L); return e;
    }
    if (t->kind == TOK_STAR) {
        cypher_expr_t* e = expr_new(CEXPR_STAR);
        lex_advance(&p->L); return e;
    }
    if (t->kind == TOK_LBRACK) {
        /* could be list literal, list comprehension, or pattern comprehension */
        token_t* nxt = lex_peek(&p->L);
        if (nxt->kind == TOK_LPAREN) {
            /* pattern comprehension: [(n)-[:R]->(m) | ...] */
            return parse_pattern_comprehension(p);
        }
        /* check for list comprehension: [IDENT IN ...] */
        if (nxt->kind == TOK_IDENT || nxt->kind == TOK_KEYWORD) {
            /* need to look further: is the token after IDENT "IN"? */
            /* save state, try to parse as comprehension, fall back to list */
            size_t save_pos = p->L.pos;
            /* advance past the [ and IDENT */
            lex_advance(&p->L); /* consume [ */
            char* name = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L); /* consume IDENT */
            bool is_comp = is_kw(&p->L.cur, "IN");
            /* restore state */
            p->L.pos = save_pos;
            /* re-lex current token */
            token_free(&p->L.cur);
            p->L.has_next = false;
            lex_next(&p->L, &p->L.cur);
            free(name);
            if (is_comp) return parse_list_comprehension(p);
        }
        return parse_list_literal(p);
    }
    if (t->kind == TOK_LBRACE) return parse_map_literal(p);
    if (t->kind == TOK_LPAREN) {
        lex_advance(&p->L);
        cypher_expr_t* e = parse_expr(p);
        if (!e) return NULL;
        expect_tok(p, TOK_RPAREN);
        return parse_postfix(p, e);
    }
    if (t->kind == TOK_MINUS) {
        lex_advance(&p->L);
        cypher_expr_t* inner = parse_primary(p);
        if (!inner) return NULL;
        cypher_expr_t* e = expr_new(CEXPR_UNARYOP);
        e->op = COP_SUB; e->left = inner;
        return e;
    }
    if (t->kind == TOK_IDENT || t->kind == TOK_KEYWORD) {
        /* could be function call or variable */
        char* name = strdup(t->text ? t->text : "");
        lex_advance(&p->L);
        if (p->L.cur.kind == TOK_LPAREN) {
            /* function call */
            lex_advance(&p->L);
            cypher_expr_t* e = expr_new(CEXPR_FUNC_CALL);
            e->s_val = name;
            /* check for DISTINCT */
            if (is_kw(&p->L.cur, "DISTINCT")) { e->distinct = true; lex_advance(&p->L); }
            size_t cap = 4;
            e->args = malloc(cap * sizeof(cypher_expr_t*));
            e->nargs = 0;
            if (p->L.cur.kind != TOK_RPAREN) {
                do {
                    cypher_expr_t* a = parse_expr(p);
                    if (!a) { expr_free(e); return NULL; }
                    if (e->nargs == cap) { cap *= 2; e->args = realloc(e->args, cap * sizeof(cypher_expr_t*)); }
                    e->args[e->nargs++] = a;
                } while (accept_tok(p, TOK_COMMA));
            }
            expect_tok(p, TOK_RPAREN);
            /* detect aggregate functions */
            const char* aggs[] = {"count","sum","avg","min","max","collect","percentileCont","percentileDisc","stDev","stDevP",NULL};
            for (int i = 0; aggs[i]; ++i) if (strcasecmp(name, aggs[i]) == 0) { e->type = CEXPR_AGG_CALL; break; }
            return parse_postfix(p, e);
        }
        /* variable, possibly property access and index/slice */
        cypher_expr_t* e = expr_new(CEXPR_VAR);
        e->s_val = name;
        for (;;) {
            if (accept_tok(p, TOK_DOT)) {
                char* prop = NULL;
                if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                    prop = strdup(p->L.cur.text ? p->L.cur.text : "");
                    lex_advance(&p->L);
                } else { p_error(p, "expected property name"); expr_free(e); return NULL; }
                cypher_expr_t* acc = expr_new(CEXPR_PROP_ACCESS);
                acc->left = e; acc->s_val = prop;
                e = acc;
            } else if (p->L.cur.kind == TOK_LBRACK) {
                e = parse_postfix(p, e);
                if (!e) return NULL;
            } else break;
        }
        return e;
    }
    p_error(p, "unexpected token in expression");
    return NULL;
}

static cypher_op_t tok_to_cmpop(token_t* t) {
    if (t->kind == TOK_EQ) return COP_EQ;
    if (t->kind == TOK_NE) return COP_NE;
    if (t->kind == TOK_LT) return COP_LT;
    if (t->kind == TOK_GT) return COP_GT;
    if (t->kind == TOK_LE) return COP_LE;
    if (t->kind == TOK_GE) return COP_GE;
    return COP_EQ;
}

static cypher_expr_t* parse_unary(parser_t* p) {
    if (is_kw(&p->L.cur, "NOT")) {
        lex_advance(&p->L);
        cypher_expr_t* inner = parse_unary(p);
        if (!inner) return NULL;
        cypher_expr_t* e = expr_new(CEXPR_UNARYOP);
        e->op = COP_NOT; e->left = inner;
        return e;
    }
    return parse_primary(p);
}

static cypher_expr_t* parse_mul(parser_t* p) {
    cypher_expr_t* left = parse_unary(p);
    if (!left) return NULL;
    while (p->L.cur.kind == TOK_STAR || p->L.cur.kind == TOK_SLASH || p->L.cur.kind == TOK_PERCENT) {
        tok_kind_t k = p->L.cur.kind;
        lex_advance(&p->L);
        cypher_expr_t* right = parse_unary(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP);
        e->op = (k == TOK_STAR) ? COP_MUL : (k == TOK_SLASH) ? COP_DIV : COP_MOD;
        e->left = left; e->right = right; left = e;
    }
    return left;
}

static cypher_expr_t* parse_add(parser_t* p) {
    cypher_expr_t* left = parse_mul(p);
    if (!left) return NULL;
    while (p->L.cur.kind == TOK_PLUS || p->L.cur.kind == TOK_MINUS) {
        tok_kind_t k = p->L.cur.kind;
        lex_advance(&p->L);
        cypher_expr_t* right = parse_mul(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP);
        e->op = (k == TOK_PLUS) ? COP_ADD : COP_SUB;
        e->left = left; e->right = right; left = e;
    }
    return left;
}

static cypher_expr_t* parse_comparison(parser_t* p) {
    cypher_expr_t* left = parse_add(p);
    if (!left) return NULL;
    /* IS NULL / IS NOT NULL */
    if (is_kw(&p->L.cur, "IS")) {
        lex_advance(&p->L);
        bool notnull = accept_kw(p, "NOT");
        if (!expect_kw(p, "NULL")) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_UNARYOP);
        e->op = notnull ? COP_IS_NOT_NULL : COP_IS_NULL;
        e->left = left;
        return e;
    }
    /* comparison ops */
    if (p->L.cur.kind == TOK_EQ || p->L.cur.kind == TOK_NE ||
        p->L.cur.kind == TOK_LT || p->L.cur.kind == TOK_GT ||
        p->L.cur.kind == TOK_LE || p->L.cur.kind == TOK_GE) {
        cypher_op_t op = tok_to_cmpop(&p->L.cur);
        lex_advance(&p->L);
        cypher_expr_t* right = parse_add(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP);
        e->op = op; e->left = left; e->right = right;
        return e;
    }
    /* STARTS WITH / ENDS WITH / CONTAINS / IN */
    if (is_kw(&p->L.cur, "STARTS")) {
        lex_advance(&p->L);
        if (!expect_kw(p, "WITH")) { expr_free(left); return NULL; }
        cypher_expr_t* right = parse_add(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP); e->op = COP_STARTS_WITH;
        e->left = left; e->right = right; return e;
    }
    if (is_kw(&p->L.cur, "ENDS")) {
        lex_advance(&p->L);
        if (!expect_kw(p, "WITH")) { expr_free(left); return NULL; }
        cypher_expr_t* right = parse_add(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP); e->op = COP_ENDS_WITH;
        e->left = left; e->right = right; return e;
    }
    if (is_kw(&p->L.cur, "CONTAINS")) {
        lex_advance(&p->L);
        cypher_expr_t* right = parse_add(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP); e->op = COP_CONTAINS;
        e->left = left; e->right = right; return e;
    }
    if (is_kw(&p->L.cur, "IN")) {
        lex_advance(&p->L);
        cypher_expr_t* right = parse_add(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP); e->op = COP_IN;
        e->left = left; e->right = right; return e;
    }
    return left;
}

static cypher_expr_t* parse_and(parser_t* p) {
    cypher_expr_t* left = parse_comparison(p);
    if (!left) return NULL;
    while (is_kw(&p->L.cur, "AND")) {
        lex_advance(&p->L);
        cypher_expr_t* right = parse_comparison(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP); e->op = COP_AND;
        e->left = left; e->right = right; left = e;
    }
    return left;
}

static cypher_expr_t* parse_or(parser_t* p) {
    cypher_expr_t* left = parse_and(p);
    if (!left) return NULL;
    while (is_kw(&p->L.cur, "OR")) {
        lex_advance(&p->L);
        cypher_expr_t* right = parse_and(p);
        if (!right) { expr_free(left); return NULL; }
        cypher_expr_t* e = expr_new(CEXPR_BINOP); e->op = COP_OR;
        e->left = left; e->right = right; left = e;
    }
    return left;
}

static cypher_expr_t* parse_expr(parser_t* p) {
    return parse_or(p);
}

/* ---- patterns ---- */

static bool parse_prop_map(parser_t* p, cypher_expr_t*** pkeys, cypher_expr_t*** pvals, size_t* n) {
    if (!accept_tok(p, TOK_LBRACE)) return true; /* no prop map */
    size_t cap = 4;
    *pkeys = malloc(cap * sizeof(cypher_expr_t*));
    *pvals = malloc(cap * sizeof(cypher_expr_t*));
    *n = 0;
    if (p->L.cur.kind != TOK_RBRACE) {
        do {
            cypher_expr_t* key;
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                key = expr_new(CEXPR_LITERAL_STR);
                key->s_val = strdup(p->L.cur.text ? p->L.cur.text : "");
                lex_advance(&p->L);
            } else { p_error(p, "expected prop key"); return false; }
            expect_tok(p, TOK_COLON);
            cypher_expr_t* v = parse_expr(p);
            if (!v) { expr_free(key); return false; }
            if (*n == cap) {
                cap *= 2;
                *pkeys = realloc(*pkeys, cap * sizeof(cypher_expr_t*));
                *pvals = realloc(*pvals, cap * sizeof(cypher_expr_t*));
            }
            (*pkeys)[*n] = key; (*pvals)[*n] = v; (*n)++;
        } while (accept_tok(p, TOK_COMMA));
    }
    expect_tok(p, TOK_RBRACE);
    return true;
}

static cypher_node_pattern_t* parse_node_pattern(parser_t* p) {
    expect_tok(p, TOK_LPAREN);
    cypher_node_pattern_t* n = node_new();
    if (p->L.cur.kind == TOK_IDENT) {
        n->var = strdup(p->L.cur.text);
        lex_advance(&p->L);
    }
    if (accept_tok(p, TOK_COLON)) {
        if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
            n->label = strdup(p->L.cur.text);
            lex_advance(&p->L);
        }
    }
    parse_prop_map(p, &n->prop_keys, &n->prop_vals, &n->num_props);
    expect_tok(p, TOK_RPAREN);
    return n;
}

static cypher_rel_pattern_t* parse_rel_pattern(parser_t* p) {
    /* expects current token is DASH or ARROW_L */
    cypher_rel_pattern_t* r = rel_new();
    if (accept_tok(p, TOK_ARROW_L)) {
        r->direction = CREL_DIR_LEFT;
    } else {
        r->direction = CREL_DIR_NONE;
        expect_tok(p, TOK_DASH);
    }
    if (accept_tok(p, TOK_LBRACK)) {
        if (p->L.cur.kind == TOK_IDENT) {
            r->var = strdup(p->L.cur.text);
            lex_advance(&p->L);
        }
        if (accept_tok(p, TOK_COLON)) {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                r->rel_type = strdup(p->L.cur.text);
                lex_advance(&p->L);
            }
        }
        /* variable length *min..max */
        if (accept_tok(p, TOK_STAR)) {
            r->var_len_min = 1; r->var_len_max = 1;
            if (p->L.cur.kind == TOK_INT) {
                r->var_len_min = (int)p->L.cur.i_val;
                r->var_len_max = (int)p->L.cur.i_val;
                lex_advance(&p->L);
                if (accept_tok(p, TOK_DOT)) {
                    if (accept_tok(p, TOK_DOT)) {
                        if (p->L.cur.kind == TOK_INT) {
                            r->var_len_max = (int)p->L.cur.i_val;
                            lex_advance(&p->L);
                        } else { r->var_len_max = 64; }
                    }
                }
            } else { r->var_len_min = 1; r->var_len_max = 64; }
        }
        parse_prop_map(p, &r->prop_keys, &r->prop_vals, &r->num_props);
        expect_tok(p, TOK_RBRACK);
    }
    /* trailing dash / arrow */
    if (accept_tok(p, TOK_DASH)) {
        if (accept_tok(p, TOK_ARROW_R)) r->direction = (r->direction == CREL_DIR_LEFT) ? CREL_DIR_BOTH : CREL_DIR_RIGHT;
        else r->direction = CREL_DIR_NONE;
    } else if (accept_tok(p, TOK_ARROW_R)) {
        r->direction = CREL_DIR_RIGHT;
    }
    return r;
}

static cypher_path_t* parse_path(parser_t* p) {
    cypher_path_t* path = path_new();
    size_t ncap = 4, rcap = 4;
    path->nodes = malloc(ncap * sizeof(cypher_node_pattern_t*));
    path->rels = malloc(rcap * sizeof(cypher_rel_pattern_t*));
    /* first node */
    cypher_node_pattern_t* n0 = parse_node_pattern(p);
    if (!n0) { path_free(path); return NULL; }
    path->nodes[path->num_nodes++] = n0;
    while (p->L.cur.kind == TOK_DASH || p->L.cur.kind == TOK_ARROW_L) {
        cypher_rel_pattern_t* r = parse_rel_pattern(p);
        if (!r) { path_free(path); return NULL; }
        if (path->num_rels == rcap) { rcap *= 2; path->rels = realloc(path->rels, rcap * sizeof(cypher_rel_pattern_t*)); }
        path->rels[path->num_rels++] = r;
        cypher_node_pattern_t* nx = parse_node_pattern(p);
        if (!nx) { path_free(path); return NULL; }
        if (path->num_nodes == ncap) { ncap *= 2; path->nodes = realloc(path->nodes, ncap * sizeof(cypher_node_pattern_t*)); }
        path->nodes[path->num_nodes++] = nx;
    }
    return path;
}

/* ---- clauses ---- */

static qihse_cypher_clause_t* parse_clause(parser_t* p);

static qihse_cypher_clause_t* parse_return_clause(parser_t* p, qihse_cypher_clause_type_t t) {
    /* RETURN or WITH */
    qihse_cypher_clause_t* c = clause_new(t);
    if (t == CYPHER_RETURN) expect_kw(p, "RETURN");
    else expect_kw(p, "WITH");
    if (is_kw(&p->L.cur, "DISTINCT")) { c->distinct = true; lex_advance(&p->L); }
    /* RETURN * — return all variables */
    if (t == CYPHER_RETURN && p->L.cur.kind == TOK_STAR) {
        c->return_star = true;
        lex_advance(&p->L);
        return c;
    }
    size_t cap = 4;
    c->items = malloc(cap * sizeof(cypher_return_item_t*));
    do {
        cypher_expr_t* e = parse_expr(p);
        if (!e) { clause_free(c); return NULL; }
        cypher_return_item_t* ri = ret_new(e);
        if (is_kw(&p->L.cur, "AS")) {
            lex_advance(&p->L);
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                ri->alias = strdup(p->L.cur.text);
                lex_advance(&p->L);
            }
        }
        if (c->num_items == cap) { cap *= 2; c->items = realloc(c->items, cap * sizeof(cypher_return_item_t*)); }
        c->items[c->num_items++] = ri;
    } while (accept_tok(p, TOK_COMMA));
    return c;
}

static qihse_cypher_clause_t* parse_match_like(parser_t* p, qihse_cypher_clause_type_t t) {
    const char* kw = (t == CYPHER_MATCH) ? "MATCH" : (t == CYPHER_CREATE) ? "CREATE" : "MERGE";
    expect_kw(p, kw);
    qihse_cypher_clause_t* c = clause_new(t);
    size_t cap = 4;
    c->paths = malloc(cap * sizeof(cypher_path_t*));
    do {
        cypher_path_t* path = parse_path(p);
        if (!path) { clause_free(c); return NULL; }
        if (c->num_paths == cap) { cap *= 2; c->paths = realloc(c->paths, cap * sizeof(cypher_path_t*)); }
        c->paths[c->num_paths++] = path;
    } while (accept_tok(p, TOK_COMMA));
    return c;
}

static qihse_cypher_clause_t* parse_where(parser_t* p) {
    expect_kw(p, "WHERE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_WHERE);
    c->where = parse_expr(p);
    if (!c->where) { clause_free(c); return NULL; }
    return c;
}

static qihse_cypher_clause_t* parse_set_or_remove(parser_t* p, qihse_cypher_clause_type_t t) {
    if (t == CYPHER_SET) expect_kw(p, "SET");
    else expect_kw(p, "REMOVE");
    qihse_cypher_clause_t* c = clause_new(t);
    size_t cap = 4;
    c->set_items = malloc(cap * sizeof(cypher_set_item_t*));
    do {
        cypher_set_item_t* si = setitem_new();
        if (p->L.cur.kind != TOK_IDENT) { p_error(p, "expected variable"); free(si); clause_free(c); return NULL; }
        si->var = strdup(p->L.cur.text);
        lex_advance(&p->L);
        if (accept_tok(p, TOK_COLON)) {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                si->label = strdup(p->L.cur.text);
                lex_advance(&p->L);
            }
        } else if (accept_tok(p, TOK_DOT)) {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                si->prop = strdup(p->L.cur.text);
                lex_advance(&p->L);
            }
            if (t == CYPHER_SET) {
                expect_tok(p, TOK_EQ);
                si->value = parse_expr(p);
                if (!si->value) { free(si->var); free(si->prop); free(si); clause_free(c); return NULL; }
            }
        }
        if (c->num_set_items == cap) { cap *= 2; c->set_items = realloc(c->set_items, cap * sizeof(cypher_set_item_t*)); }
        c->set_items[c->num_set_items++] = si;
    } while (accept_tok(p, TOK_COMMA));
    return c;
}

static qihse_cypher_clause_t* parse_delete(parser_t* p) {
    qihse_cypher_clause_t* c = calloc(1, sizeof(qihse_cypher_clause_t));
    if (!c) return NULL;
    c->type = CYPHER_DELETE;
    size_t cap = 4;
    c->del_vars = calloc(cap, sizeof(char*));
    do {
        if (p->L.cur.kind != TOK_IDENT && !is_kw(&p->L.cur, "n") && !is_kw(&p->L.cur, "r")) {
            if (c->num_del_vars == 0) { free(c->del_vars); free(c); return NULL; }
            break;
        }
        char* name = strdup(p->L.cur.text ? p->L.cur.text : "");
        if (c->num_del_vars >= cap) { cap *= 2; c->del_vars = realloc(c->del_vars, cap * sizeof(char*)); }
        c->del_vars[c->num_del_vars++] = name;
        lex_advance(&p->L);
    } while (accept_tok(p, TOK_COMMA));
    return c;
}

static qihse_cypher_clause_t* parse_delete_full(parser_t* p) {
    bool detach = false;
    if (is_kw(&p->L.cur, "DETACH")) { detach = true; lex_advance(&p->L); }
    qihse_cypher_clause_t* c = parse_delete(p);
    if (c) c->detach = detach;
    return c;
}

static qihse_cypher_clause_t* parse_order_by(parser_t* p) {
    expect_kw(p, "ORDER");
    expect_kw(p, "BY");
    qihse_cypher_clause_t* c = clause_new(CYPHER_ORDER_BY);
    size_t cap = 4;
    c->order_items = malloc(cap * sizeof(cypher_order_item_t*));
    do {
        cypher_expr_t* e = parse_expr(p);
        if (!e) { clause_free(c); return NULL; }
        cypher_order_item_t* oi = ord_new(e);
        if (is_kw(&p->L.cur, "DESC") || is_kw(&p->L.cur, "DESCENDING")) { oi->descending = true; lex_advance(&p->L); }
        else if (is_kw(&p->L.cur, "ASC") || is_kw(&p->L.cur, "ASCENDING")) { lex_advance(&p->L); }
        /* NULLS FIRST / NULLS LAST */
        if (is_kw(&p->L.cur, "NULLS")) {
            lex_advance(&p->L);
            if (is_kw(&p->L.cur, "FIRST")) { oi->nulls_first = true; lex_advance(&p->L); }
            else if (is_kw(&p->L.cur, "LAST")) { oi->nulls_last = true; lex_advance(&p->L); }
        }
        if (c->num_order_items == cap) { cap *= 2; c->order_items = realloc(c->order_items, cap * sizeof(cypher_order_item_t*)); }
        c->order_items[c->num_order_items++] = oi;
    } while (accept_tok(p, TOK_COMMA));
    return c;
}

static qihse_cypher_clause_t* parse_skip_limit(parser_t* p, qihse_cypher_clause_type_t t) {
    if (t == CYPHER_SKIP) expect_kw(p, "SKIP"); else expect_kw(p, "LIMIT");
    qihse_cypher_clause_t* c = clause_new(t);
    if (p->L.cur.kind != TOK_INT) { p_error(p, "expected integer"); clause_free(c); return NULL; }
    if (t == CYPHER_SKIP) c->skip = p->L.cur.i_val; else c->limit = p->L.cur.i_val;
    lex_advance(&p->L);
    return c;
}

static qihse_cypher_clause_t* parse_unwind(parser_t* p) {
    expect_kw(p, "UNWIND");
    qihse_cypher_clause_t* c = clause_new(CYPHER_UNWIND);
    c->unwind_expr = parse_expr(p);
    if (!c->unwind_expr) { clause_free(c); return NULL; }
    if (!expect_kw(p, "AS")) { clause_free(c); return NULL; }
    if (p->L.cur.kind != TOK_IDENT) { p_error(p, "expected variable"); clause_free(c); return NULL; }
    c->unwind_var = strdup(p->L.cur.text);
    lex_advance(&p->L);
    return c;
}

/* ---- LOAD CSV ---- */
static qihse_cypher_clause_t* parse_load_csv(parser_t* p) {
    expect_kw(p, "LOAD");
    expect_kw(p, "CSV");
    qihse_cypher_clause_t* c = clause_new(CYPHER_LOAD_CSV);
    c->csv_field_term = 0; /* default comma */
    if (accept_kw(p, "WITH")) {
        if (!expect_kw(p, "HEADERS")) { clause_free(c); return NULL; }
        c->csv_with_headers = true;
    }
    if (!expect_kw(p, "FROM")) { clause_free(c); return NULL; }
    if (p->L.cur.kind != TOK_STRING) { p_error(p, "expected string URI in LOAD CSV"); clause_free(c); return NULL; }
    c->csv_uri = strdup(p->L.cur.text ? p->L.cur.text : "");
    lex_advance(&p->L);
    if (!expect_kw(p, "AS")) { clause_free(c); return NULL; }
    if (p->L.cur.kind != TOK_IDENT && p->L.cur.kind != TOK_KEYWORD) {
        p_error(p, "expected row variable in LOAD CSV"); clause_free(c); return NULL;
    }
    c->csv_var = strdup(p->L.cur.text ? p->L.cur.text : "");
    lex_advance(&p->L);
    /* FIELDTERMINATOR */
    if (is_kw(&p->L.cur, "FIELDTERMINATOR")) {
        /* FIELDTERMINATOR is not a keyword; check if current token text matches */
    }
    /* Check for FIELDTERMINATOR as an identifier */
    if (p->L.cur.kind == TOK_IDENT && p->L.cur.text && strcasecmp(p->L.cur.text, "FIELDTERMINATOR") == 0) {
        lex_advance(&p->L);
        if (p->L.cur.kind != TOK_STRING) { p_error(p, "expected string after FIELDTERMINATOR"); clause_free(c); return NULL; }
        c->csv_field_term = p->L.cur.text ? p->L.cur.text[0] : ',';
        lex_advance(&p->L);
    }
    return c;
}

/* ---- CALL procedure ---- */
static qihse_cypher_clause_t* parse_call_clause(parser_t* p) {
    expect_kw(p, "CALL");
    qihse_cypher_clause_t* c = clause_new(CYPHER_CALL);
    /* CALL { subquery } — subquery form */
    if (p->L.cur.kind == TOK_LBRACE) {
        c->call_subquery = parse_subquery_body(p);
        if (!c->call_subquery) { clause_free(c); return NULL; }
        /* optional IN TRANSACTIONS OF n ROWS */
        if (is_kw(&p->L.cur, "IN")) {
            lex_advance(&p->L);
            if (is_kw(&p->L.cur, "TRANSACTIONS")) lex_advance(&p->L);
            if (is_kw(&p->L.cur, "OF")) lex_advance(&p->L);
            if (p->L.cur.kind == TOK_INT) {
                c->call_in_transactions = (int)p->L.cur.i_val;
                lex_advance(&p->L);
            }
            if (is_kw(&p->L.cur, "ROWS")) lex_advance(&p->L);
        }
        return c;
    }
    /* CALL namespace.proc(args) or CALL proc(args) */
    if (p->L.cur.kind != TOK_IDENT && p->L.cur.kind != TOK_KEYWORD) {
        p_error(p, "expected procedure name after CALL"); clause_free(c); return NULL;
    }
    char* first = strdup(p->L.cur.text ? p->L.cur.text : "");
    lex_advance(&p->L);
    if (accept_tok(p, TOK_DOT)) {
        c->proc_namespace = first;
        if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
            /* could be namespace.name or namespace.subname.name */
            char* second = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
            if (accept_tok(p, TOK_DOT)) {
                /* namespace.second.name */
                char buf[256];
                snprintf(buf, sizeof(buf), "%s.%s", second, "");
                free(second);
                if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                    char* third = strdup(p->L.cur.text ? p->L.cur.text : "");
                    lex_advance(&p->L);
                    snprintf(buf, sizeof(buf), "%s", third);
                    free(third);
                }
                c->proc_name = strdup(buf);
            } else {
                c->proc_name = second;
            }
        }
    } else {
        c->proc_name = first;
    }
    /* args */
    if (accept_tok(p, TOK_LPAREN)) {
        size_t cap = 4;
        c->proc_args = malloc(cap * sizeof(cypher_expr_t*));
        c->num_proc_args = 0;
        if (p->L.cur.kind != TOK_RPAREN) {
            do {
                cypher_expr_t* a = parse_expr(p);
                if (!a) { clause_free(c); return NULL; }
                if (c->num_proc_args == cap) { cap *= 2; c->proc_args = realloc(c->proc_args, cap * sizeof(cypher_expr_t*)); }
                c->proc_args[c->num_proc_args++] = a;
            } while (accept_tok(p, TOK_COMMA));
        }
        expect_tok(p, TOK_RPAREN);
    }
    /* YIELD vars */
    if (is_kw(&p->L.cur, "YIELD")) {
        lex_advance(&p->L);
        size_t cap = 4;
        c->yield_vars = malloc(cap * sizeof(char*));
        c->num_yield_vars = 0;
        do {
            if (p->L.cur.kind != TOK_IDENT && p->L.cur.kind != TOK_KEYWORD) {
                p_error(p, "expected yield variable"); clause_free(c); return NULL;
            }
            char* vname = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
            if (c->num_yield_vars == cap) { cap *= 2; c->yield_vars = realloc(c->yield_vars, cap * sizeof(char*)); }
            c->yield_vars[c->num_yield_vars++] = vname;
        } while (accept_tok(p, TOK_COMMA));
    }
    return c;
}

/* ---- FOREACH ---- */
static qihse_cypher_clause_t* parse_foreach(parser_t* p) {
    expect_kw(p, "FOREACH");
    if (!expect_tok(p, TOK_LPAREN)) return NULL;
    qihse_cypher_clause_t* c = clause_new(CYPHER_FOREACH);
    /* var IN list */
    if (p->L.cur.kind != TOK_IDENT && p->L.cur.kind != TOK_KEYWORD) {
        p_error(p, "expected variable in FOREACH"); clause_free(c); return NULL;
    }
    c->foreach_var = strdup(p->L.cur.text ? p->L.cur.text : "");
    lex_advance(&p->L);
    if (!expect_kw(p, "IN")) { clause_free(c); return NULL; }
    c->foreach_list = parse_expr(p);
    if (!c->foreach_list) { clause_free(c); return NULL; }
    if (!expect_tok(p, TOK_PIPE)) { clause_free(c); return NULL; }
    /* body clauses until ')' */
    qihse_cypher_clause_t* prev = NULL;
    for (;;) {
        qihse_cypher_clause_t* bc = parse_clause(p);
        if (!bc) break;
        if (prev) prev->next = bc; else c->foreach_body = bc;
        prev = bc;
    }
    expect_tok(p, TOK_RPAREN);
    return c;
}

/* ---- Schema: CREATE INDEX ---- */
static qihse_cypher_clause_t* parse_create_index(parser_t* p) {
    expect_kw(p, "CREATE");
    expect_kw(p, "INDEX");
    qihse_cypher_clause_t* c = clause_new(CYPHER_CREATE_INDEX);
    /* optional index name */
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        token_t* nxt = lex_peek(&p->L);
        if (nxt->kind != TOK_KEYWORD || !is_kw(nxt, "FOR")) {
            c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
        }
    }
    if (!expect_kw(p, "FOR")) { clause_free(c); return NULL; }
    if (!expect_tok(p, TOK_LPAREN)) { clause_free(c); return NULL; }
    /* (n:Label) */
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) lex_advance(&p->L); /* var */
    if (accept_tok(p, TOK_COLON)) {
        if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
            c->schema_label = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
        }
    }
    expect_tok(p, TOK_RPAREN);
    if (!expect_kw(p, "ON")) { clause_free(c); return NULL; }
    if (!expect_tok(p, TOK_LPAREN)) { clause_free(c); return NULL; }
    /* (n.prop[, n.prop2]) */
    size_t cap = 4;
    c->schema_props = malloc(cap * sizeof(char*));
    c->num_schema_props = 0;
    do {
        if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) lex_advance(&p->L); /* var */
        if (accept_tok(p, TOK_DOT)) {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                if (c->num_schema_props == cap) { cap *= 2; c->schema_props = realloc(c->schema_props, cap * sizeof(char*)); }
                c->schema_props[c->num_schema_props++] = strdup(p->L.cur.text ? p->L.cur.text : "");
                lex_advance(&p->L);
            }
        }
    } while (accept_tok(p, TOK_COMMA));
    expect_tok(p, TOK_RPAREN);
    return c;
}

/* ---- Schema: DROP INDEX ---- */
static qihse_cypher_clause_t* parse_drop_index(parser_t* p) {
    expect_kw(p, "DROP");
    expect_kw(p, "INDEX");
    qihse_cypher_clause_t* c = clause_new(CYPHER_DROP_INDEX);
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

/* ---- Schema: SHOW INDEXES ---- */
static qihse_cypher_clause_t* parse_show_indexes(parser_t* p) {
    expect_kw(p, "SHOW");
    expect_kw(p, "INDEXES");
    qihse_cypher_clause_t* c = clause_new(CYPHER_SHOW_INDEXES);
    /* optional YIELD */
    if (is_kw(&p->L.cur, "YIELD")) {
        lex_advance(&p->L);
        c->show_yield = true;
        size_t cap = 4;
        c->show_yield_vars = malloc(cap * sizeof(char*));
        c->num_show_yield_vars = 0;
        do {
            if (p->L.cur.kind != TOK_IDENT && p->L.cur.kind != TOK_KEYWORD) break;
            if (c->num_show_yield_vars == cap) { cap *= 2; c->show_yield_vars = realloc(c->show_yield_vars, cap * sizeof(char*)); }
            c->show_yield_vars[c->num_show_yield_vars++] = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
        } while (accept_tok(p, TOK_COMMA));
    }
    return c;
}

/* ---- Schema: CREATE CONSTRAINT ---- */
static qihse_cypher_clause_t* parse_create_constraint(parser_t* p) {
    expect_kw(p, "CREATE");
    expect_kw(p, "CONSTRAINT");
    qihse_cypher_clause_t* c = clause_new(CYPHER_CREATE_CONSTRAINT);
    /* optional constraint name */
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        token_t* nxt = lex_peek(&p->L);
        if (nxt->kind != TOK_KEYWORD || !is_kw(nxt, "ON")) {
            c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
        }
    }
    if (is_kw(&p->L.cur, "IF")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "NOT")) { lex_advance(&p->L); }
        if (is_kw(&p->L.cur, "EXISTS")) { c->schema_if_exists = true; lex_advance(&p->L); }
    }
    if (!expect_kw(p, "ON")) { clause_free(c); return NULL; }
    /* (n:Label) or ()-[r:TYPE]-() */
    if (!expect_tok(p, TOK_LPAREN)) { clause_free(c); return NULL; }
    if (p->L.cur.kind == TOK_RPAREN) {
        /* relationship constraint: ()-[r:TYPE]-() */
        lex_advance(&p->L); /* consume ) */
        c->schema_rel = true;
        /* -[r:TYPE]- */
        expect_tok(p, TOK_DASH);
        if (accept_tok(p, TOK_LBRACK)) {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) lex_advance(&p->L); /* var */
            if (accept_tok(p, TOK_COLON)) {
                if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                    c->schema_rel_type = strdup(p->L.cur.text ? p->L.cur.text : "");
                    lex_advance(&p->L);
                }
            }
            expect_tok(p, TOK_RBRACK);
        }
        expect_tok(p, TOK_DASH);
        /* () */
        expect_tok(p, TOK_LPAREN);
        expect_tok(p, TOK_RPAREN);
    } else {
        /* (n:Label) */
        if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) lex_advance(&p->L); /* var */
        if (accept_tok(p, TOK_COLON)) {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                c->schema_label = strdup(p->L.cur.text ? p->L.cur.text : "");
                lex_advance(&p->L);
            }
        }
        expect_tok(p, TOK_RPAREN);
    }
    /* ASSERT */
    if (accept_kw(p, "ASSERT")) {
        size_t cap = 4;
        c->schema_props = malloc(cap * sizeof(char*));
        c->num_schema_props = 0;
        do {
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) lex_advance(&p->L); /* var */
            if (accept_tok(p, TOK_DOT)) {
                if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                    if (c->num_schema_props == cap) { cap *= 2; c->schema_props = realloc(c->schema_props, cap * sizeof(char*)); }
                    c->schema_props[c->num_schema_props++] = strdup(p->L.cur.text ? p->L.cur.text : "");
                    lex_advance(&p->L);
                }
            }
        } while (accept_tok(p, TOK_COMMA));
        /* IS UNIQUE / IS NODE KEY / EXISTS(...) / IS NOT NULL */
        if (is_kw(&p->L.cur, "IS")) {
            lex_advance(&p->L);
            if (is_kw(&p->L.cur, "UNIQUE")) { c->schema_kind = 0; lex_advance(&p->L); }
            else if (is_kw(&p->L.cur, "NOT")) {
                lex_advance(&p->L);
                if (is_kw(&p->L.cur, "NULL")) { c->schema_kind = 3; lex_advance(&p->L); }
            }
            else if (is_kw(&p->L.cur, "NODE")) {
                lex_advance(&p->L);
                if (is_kw(&p->L.cur, "KEY")) { c->schema_kind = 1; lex_advance(&p->L); }
            }
        } else if (is_kw(&p->L.cur, "EXISTS")) {
            lex_advance(&p->L);
            expect_tok(p, TOK_LPAREN);
            if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) lex_advance(&p->L);
            if (accept_tok(p, TOK_DOT)) {
                if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
                    if (c->num_schema_props == 0) {
                        c->schema_props = realloc(c->schema_props, (c->num_schema_props + 1) * sizeof(char*));
                        c->schema_props[c->num_schema_props++] = strdup(p->L.cur.text ? p->L.cur.text : "");
                    }
                    lex_advance(&p->L);
                }
            }
            expect_tok(p, TOK_RPAREN);
            c->schema_kind = 2;
        }
    }
    return c;
}

/* ---- Schema: DROP CONSTRAINT ---- */
static qihse_cypher_clause_t* parse_drop_constraint(parser_t* p) {
    expect_kw(p, "DROP");
    expect_kw(p, "CONSTRAINT");
    qihse_cypher_clause_t* c = clause_new(CYPHER_DROP_CONSTRAINT);
    if (is_kw(&p->L.cur, "IF")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "EXISTS")) { c->schema_if_exists = true; lex_advance(&p->L); }
    }
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

/* ---- Schema: SHOW CONSTRAINTS ---- */
static qihse_cypher_clause_t* parse_show_constraints(parser_t* p) {
    expect_kw(p, "SHOW");
    expect_kw(p, "CONSTRAINTS");
    qihse_cypher_clause_t* c = clause_new(CYPHER_SHOW_CONSTRAINTS);
    return c;
}

/* ---- Database management ---- */
static qihse_cypher_clause_t* parse_create_database(parser_t* p) {
    expect_kw(p, "CREATE");
    expect_kw(p, "DATABASE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_CREATE_DATABASE);
    if (is_kw(&p->L.cur, "IF")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "NOT")) lex_advance(&p->L);
        if (is_kw(&p->L.cur, "EXISTS")) { c->schema_if_exists = true; lex_advance(&p->L); }
    }
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

static qihse_cypher_clause_t* parse_drop_database(parser_t* p) {
    expect_kw(p, "DROP");
    expect_kw(p, "DATABASE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_DROP_DATABASE);
    if (is_kw(&p->L.cur, "IF")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "EXISTS")) { c->schema_if_exists = true; lex_advance(&p->L); }
    }
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

static qihse_cypher_clause_t* parse_show_databases(parser_t* p) {
    expect_kw(p, "SHOW");
    /* could be DATABASES or DEFAULT DATABASE */
    if (is_kw(&p->L.cur, "DEFAULT")) {
        lex_advance(&p->L);
        expect_kw(p, "DATABASE");
        qihse_cypher_clause_t* c = clause_new(CYPHER_SHOW_DATABASES);
        c->show_kind = 4; /* default database */
        return c;
    }
    expect_kw(p, "DATABASES");
    qihse_cypher_clause_t* c = clause_new(CYPHER_SHOW_DATABASES);
    return c;
}

static qihse_cypher_clause_t* parse_show_clause(parser_t* p) {
    expect_kw(p, "SHOW");
    qihse_cypher_clause_t* c = clause_new(CYPHER_SHOW);
    if (is_kw(&p->L.cur, "ALL")) { c->show_kind = 0; lex_advance(&p->L); }
    else if (is_kw(&p->L.cur, "BUILT")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "IN")) { lex_advance(&p->L); }
        c->show_kind = 1;
    }
    else if (is_kw(&p->L.cur, "PROCEDURES")) { c->show_kind = 2; lex_advance(&p->L); }
    else if (is_kw(&p->L.cur, "FUNCTIONS")) { c->show_kind = 3; lex_advance(&p->L); }
    /* optional EXECUTABLE BY user */
    if (is_kw(&p->L.cur, "EXECUTABLE")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "BY")) lex_advance(&p->L);
        if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
            c->show_user = strdup(p->L.cur.text ? p->L.cur.text : "");
            lex_advance(&p->L);
        }
    }
    return c;
}

static qihse_cypher_clause_t* parse_use_clause(parser_t* p) {
    expect_kw(p, "USE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_USE);
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->use_database = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

static qihse_cypher_clause_t* parse_start_database(parser_t* p) {
    expect_kw(p, "START");
    expect_kw(p, "DATABASE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_START_DATABASE);
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

static qihse_cypher_clause_t* parse_stop_database(parser_t* p) {
    expect_kw(p, "STOP");
    expect_kw(p, "DATABASE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_STOP_DATABASE);
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    return c;
}

static qihse_cypher_clause_t* parse_alter_database(parser_t* p) {
    expect_kw(p, "ALTER");
    expect_kw(p, "DATABASE");
    qihse_cypher_clause_t* c = clause_new(CYPHER_ALTER_DATABASE);
    if (p->L.cur.kind == TOK_IDENT || p->L.cur.kind == TOK_KEYWORD) {
        c->schema_name = strdup(p->L.cur.text ? p->L.cur.text : "");
        lex_advance(&p->L);
    }
    if (is_kw(&p->L.cur, "SET")) {
        lex_advance(&p->L);
        if (is_kw(&p->L.cur, "ACCESS")) lex_advance(&p->L);
        if (accept_tok(p, TOK_LBRACE)) {
            if (is_kw(&p->L.cur, "READ")) {
                lex_advance(&p->L);
                if (is_kw(&p->L.cur, "ONLY")) { c->db_access = 0; lex_advance(&p->L); }
                else if (is_kw(&p->L.cur, "WRITE")) { c->db_access = 1; lex_advance(&p->L); }
            }
            expect_tok(p, TOK_RBRACE);
        }
    }
    return c;
}

/* ---- PERIODIC COMMIT ---- */
static qihse_cypher_clause_t* parse_periodic_commit(parser_t* p) {
    expect_kw(p, "PERIODIC");
    expect_kw(p, "COMMIT");
    qihse_cypher_clause_t* c = clause_new(CYPHER_PERIODIC_COMMIT);
    if (p->L.cur.kind == TOK_INT) {
        c->periodic_commit = (int)p->L.cur.i_val;
        lex_advance(&p->L);
    }
    return c;
}

static qihse_cypher_clause_t* parse_clause(parser_t* p) {
    token_t* t = &p->L.cur;
    if (is_kw(t, "MATCH")) return parse_match_like(p, CYPHER_MATCH);
    if (is_kw(t, "MERGE")) return parse_match_like(p, CYPHER_MERGE);
    if (is_kw(t, "RETURN")) return parse_return_clause(p, CYPHER_RETURN);
    if (is_kw(t, "WITH")) return parse_return_clause(p, CYPHER_WITH);
    if (is_kw(t, "WHERE")) return parse_where(p);
    if (is_kw(t, "SET")) return parse_set_or_remove(p, CYPHER_SET);
    if (is_kw(t, "REMOVE")) return parse_set_or_remove(p, CYPHER_REMOVE);
    if (is_kw(t, "DETACH") || is_kw(t, "DELETE")) return parse_delete_full(p);
    if (is_kw(t, "ORDER")) return parse_order_by(p);
    if (is_kw(t, "SKIP")) return parse_skip_limit(p, CYPHER_SKIP);
    if (is_kw(t, "LIMIT")) return parse_skip_limit(p, CYPHER_LIMIT);
    if (is_kw(t, "UNWIND")) return parse_unwind(p);
    if (is_kw(t, "LOAD")) return parse_load_csv(p);
    if (is_kw(t, "CALL")) return parse_call_clause(p);
    if (is_kw(t, "FOREACH")) return parse_foreach(p);
    if (is_kw(t, "PERIODIC")) return parse_periodic_commit(p);
    if (is_kw(t, "USE")) return parse_use_clause(p);
    if (is_kw(t, "EXPLAIN")) {
        lex_advance(&p->L);
        qihse_cypher_clause_t* c = clause_new(CYPHER_EXPLAIN);
        return c;
    }
    if (is_kw(t, "PROFILE")) {
        lex_advance(&p->L);
        qihse_cypher_clause_t* c = clause_new(CYPHER_PROFILE);
        return c;
    }
    if (is_kw(t, "START") && lex_peek(&p->L)->kind == TOK_KEYWORD &&
        strcasecmp(lex_peek(&p->L)->text ? lex_peek(&p->L)->text : "", "DATABASE") == 0)
        return parse_start_database(p);
    if (is_kw(t, "STOP") && lex_peek(&p->L)->kind == TOK_KEYWORD &&
        strcasecmp(lex_peek(&p->L)->text ? lex_peek(&p->L)->text : "", "DATABASE") == 0)
        return parse_stop_database(p);
    if (is_kw(t, "ALTER") && lex_peek(&p->L)->kind == TOK_KEYWORD &&
        strcasecmp(lex_peek(&p->L)->text ? lex_peek(&p->L)->text : "", "DATABASE") == 0)
        return parse_alter_database(p);
    if (is_kw(t, "DROP")) {
        token_t* nxt = lex_peek(&p->L);
        if (is_kw(nxt, "INDEX")) return parse_drop_index(p);
        if (is_kw(nxt, "CONSTRAINT")) return parse_drop_constraint(p);
        if (is_kw(nxt, "DATABASE")) return parse_drop_database(p);
        return NULL;
    }
    if (is_kw(t, "SHOW")) {
        token_t* nxt = lex_peek(&p->L);
        if (is_kw(nxt, "INDEXES") || is_kw(nxt, "INDEX")) return parse_show_indexes(p);
        if (is_kw(nxt, "CONSTRAINTS") || is_kw(nxt, "CONSTRAINT")) return parse_show_constraints(p);
        if (is_kw(nxt, "DATABASES") || is_kw(nxt, "DEFAULT")) return parse_show_databases(p);
        if (is_kw(nxt, "ALL") || is_kw(nxt, "BUILT") || is_kw(nxt, "PROCEDURES") || is_kw(nxt, "FUNCTIONS"))
            return parse_show_clause(p);
        return NULL;
    }
    /* CREATE — check for INDEX/CONSTRAINT/DATABASE prefix */
    if (is_kw(t, "CREATE")) {
        token_t* nxt = lex_peek(&p->L);
        if (is_kw(nxt, "INDEX")) return parse_create_index(p);
        if (is_kw(nxt, "CONSTRAINT")) return parse_create_constraint(p);
        if (is_kw(nxt, "DATABASE")) return parse_create_database(p);
        return parse_match_like(p, CYPHER_CREATE);
    }
    return NULL; /* not a clause */
}

static qihse_cypher_query_t* parse_query(parser_t* p) {
    qihse_cypher_query_t* q = calloc(1, sizeof(qihse_cypher_query_t));
    qihse_cypher_clause_t* prev = NULL;
    for (;;) {
        qihse_cypher_clause_t* c = parse_clause(p);
        if (!c) break;
        if (prev) prev->next = c; else q->first = c;
        q->last = c; prev = c;
        /* optional ON CREATE / ON MATCH for MERGE — skip */
        if (c->type == CYPHER_MERGE) {
            while (is_kw(&p->L.cur, "ON")) {
                lex_advance(&p->L);
                if (is_kw(&p->L.cur, "CREATE") || is_kw(&p->L.cur, "MATCH")) lex_advance(&p->L);
                /* skip following SET clause by parsing it and discarding into chain */
                qihse_cypher_clause_t* sc = parse_clause(p);
                if (sc) { prev->next = sc; q->last = sc; prev = sc; }
                else break;
            }
        }
    }
    if (!q->first) { free(q); return NULL; }
    return q;
}

qihse_cypher_ast_t* qihse_cypher_parse(const char* text) {
    if (!text) return NULL;
    g_error[0] = '\0';
    parser_t p; lex_init(&p.L, text);
    qihse_cypher_ast_t* ast = calloc(1, sizeof(qihse_cypher_ast_t));
    size_t cap = 2;
    ast->queries = malloc(cap * sizeof(qihse_cypher_query_t*));
    for (;;) {
        qihse_cypher_query_t* q = parse_query(&p);
        if (!q) break;
        if (ast->num_queries == cap) { cap *= 2; ast->queries = realloc(ast->queries, cap * sizeof(qihse_cypher_query_t*)); }
        ast->queries[ast->num_queries++] = q;
        /* UNION */
        if (is_kw(&p.L.cur, "UNION")) {
            lex_advance(&p.L);
            bool all = false;
            if (is_kw(&p.L.cur, "ALL")) { all = true; lex_advance(&p.L); }
            /* mark previous query's last RETURN clause with union; we represent union by adding a marker clause */
            qihse_cypher_clause_t* uc = clause_new(CYPHER_UNION);
            uc->union_all = all;
            if (q->last) q->last->next = uc; else q->first = uc;
            q->last = uc;
            continue;
        }
        accept_tok(&p, TOK_SEMI);
        if (p.L.cur.kind == TOK_EOF) break;
    }
    if (ast->num_queries == 0) { qihse_cypher_ast_free(ast); return NULL; }
    return ast;
}
