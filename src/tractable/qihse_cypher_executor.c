#include <ctype.h>
/* QIHSE Cypher Executor — executes a parsed AST against the graph store. */

#include "qihse_cypher_executor.h"
#include "qihse_graph_store.h"
#include "qihse_cypher_parser.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ---- CSV line parser (for LOAD CSV) ---- */

typedef struct {
    char** fields;
    size_t count;
} csv_row_t__;

static csv_row_t__ csv_parse_line__(const char* line, char delim) {
    csv_row_t__ row = { .fields = NULL, .count = 0 };
    size_t cap = 8;
    row.fields = malloc(cap * sizeof(char*));
    size_t fcap = 256;
    char* field = malloc(fcap);
    size_t fi = 0;
    bool in_quotes = false;
    const char* p = line;
    while (*p) {
        if (in_quotes) {
            if (*p == '"') { if (p[1] == '"') { field[fi++] = '"'; p += 2; } else { in_quotes = false; p++; } }
            else field[fi++] = *p++;
        } else {
            if (*p == '"') { in_quotes = true; p++; }
            else if (*p == delim) {
                field[fi] = '\0';
                if (row.count == cap) { cap *= 2; row.fields = realloc(row.fields, cap * sizeof(char*)); }
                row.fields[row.count++] = strdup(field);
                fi = 0; p++;
            } else if (*p == '\r' || *p == '\n') break;
            else field[fi++] = *p++;
        }
        if (fi >= fcap - 1) { fcap *= 2; field = realloc(field, fcap); }
    }
    field[fi] = '\0';
    if (row.count == cap) { cap *= 2; row.fields = realloc(row.fields, cap * sizeof(char*)); }
    row.fields[row.count++] = strdup(field);
    free(field);
    return row;
}

static void csv_row_free__(csv_row_t__* r) {
    for (size_t i = 0; i < r->count; i++) free(r->fields[i]);
    free(r->fields);
    r->fields = NULL; r->count = 0;
}

/* ---- result value helpers ---- */

cypher_res_t cypher_res_int64(int64_t v) { cypher_res_t r = {0}; r.type = CRES_INT64; r.val.i = v; return r; }
cypher_res_t cypher_res_double(double v) { cypher_res_t r = {0}; r.type = CRES_DOUBLE; r.val.d = v; return r; }
cypher_res_t cypher_res_string(const char* s) { cypher_res_t r = {0}; r.type = CRES_STRING; r.val.s = strdup(s ? s : ""); return r; }
cypher_res_t cypher_res_bool(bool b) { cypher_res_t r = {0}; r.type = CRES_BOOL; r.val.b = b; return r; }
cypher_res_t cypher_res_null(void) { cypher_res_t r = {0}; r.type = CRES_NULL; return r; }

void cypher_res_free(cypher_res_t* r) {
    if (!r) return;
    if (r->type == CRES_STRING) { free(r->val.s); r->val.s = NULL; }
    else if (r->type == CRES_LIST) {
        for (size_t i = 0; i < r->val.list.count; ++i) cypher_res_free(&r->val.list.items[i]);
        free(r->val.list.items);
    }
}

static cypher_res_t cypher_res_dup(const cypher_res_t* src) {
    cypher_res_t r = *src;
    if (r.type == CRES_STRING) r.val.s = strdup(src->val.s ? src->val.s : "");
    else if (r.type == CRES_LIST) {
        r.val.list.items = malloc(src->val.list.count * sizeof(cypher_res_t));
        for (size_t i = 0; i < src->val.list.count; ++i)
            r.val.list.items[i] = cypher_res_dup(&src->val.list.items[i]);
    }
    return r;
}

static graph_prop_t res_to_prop(const cypher_res_t* r) {
    switch (r->type) {
        case CRES_INT64: return graph_prop_make_int64(r->val.i);
        case CRES_DOUBLE: return graph_prop_make_double(r->val.d);
        case CRES_STRING: return graph_prop_make_string(r->val.s);
        case CRES_BOOL: return graph_prop_make_bool(r->val.b);
        default: return graph_prop_make_int64(0);
    }
}

static cypher_res_t prop_to_res(const graph_prop_t* p) {
    if (!p) return cypher_res_null();
    switch (p->type) {
        case GRAPH_PROP_INT64: return cypher_res_int64(p->val.i);
        case GRAPH_PROP_DOUBLE: return cypher_res_double(p->val.d);
        case GRAPH_PROP_STRING: return cypher_res_string(p->val.s);
        case GRAPH_PROP_BOOL: return cypher_res_bool(p->val.b);
        default: return cypher_res_null();
    }
}

/* ---- binding row ---- */

typedef struct {
    char** names;
    cypher_res_t* vals;
    size_t count;
    size_t cap;
} brow_t;

static void brow_init(brow_t* r) { r->names = NULL; r->vals = NULL; r->count = 0; r->cap = 0; }
static void brow_free(brow_t* r) {
    for (size_t i = 0; i < r->count; ++i) { free(r->names[i]); cypher_res_free(&r->vals[i]); }
    free(r->names); free(r->vals);
    r->names = NULL; r->vals = NULL; r->count = 0; r->cap = 0;
}
static void brow_set(brow_t* r, const char* name, cypher_res_t v) {
    for (size_t i = 0; i < r->count; ++i) {
        if (strcmp(r->names[i], name) == 0) { cypher_res_free(&r->vals[i]); r->vals[i] = v; return; }
    }
    if (r->count == r->cap) { r->cap = r->cap ? r->cap * 2 : 4; r->names = realloc(r->names, r->cap * sizeof(char*)); r->vals = realloc(r->vals, r->cap * sizeof(cypher_res_t)); }
    r->names[r->count] = strdup(name);
    r->vals[r->count] = v;
    r->count++;
}
static const cypher_res_t* brow_get(const brow_t* r, const char* name) {
    for (size_t i = 0; i < r->count; ++i)
        if (strcmp(r->names[i], name) == 0) return &r->vals[i];
    return NULL;
}
static void brow_copy_into(const brow_t* src, brow_t* dst) {
    brow_init(dst);
    dst->cap = src->count ? src->count : 1;
    dst->names = malloc(dst->cap * sizeof(char*));
    dst->vals = malloc(dst->cap * sizeof(cypher_res_t));
    for (size_t i = 0; i < src->count; ++i) {
        dst->names[i] = strdup(src->names[i]);
        dst->vals[i] = cypher_res_dup(&src->vals[i]);
    }
    dst->count = src->count;
}

/* ---- row table ---- */

typedef struct {
    brow_t* rows;
    size_t count;
    size_t cap;
} table_t;

static void table_init(table_t* t) { t->rows = NULL; t->count = 0; t->cap = 0; }
static void table_free(table_t* t) {
    for (size_t i = 0; i < t->count; ++i) brow_free(&t->rows[i]);
    free(t->rows);
    t->rows = NULL; t->count = 0; t->cap = 0;
}
static void table_add(table_t* t, brow_t r) {
    if (t->count == t->cap) { t->cap = t->cap ? t->cap * 2 : 8; t->rows = realloc(t->rows, t->cap * sizeof(brow_t)); }
    t->rows[t->count++] = r;
}
static void table_clear(table_t* t) {
    for (size_t i = 0; i < t->count; ++i) brow_free(&t->rows[i]);
    t->count = 0;
}

/* ---- expression evaluation ---- */

static cypher_res_t eval_expr(qihse_graph_t* g, const cypher_expr_t* e, const brow_t* row);

static double res_to_num(const cypher_res_t* r) {
    if (!r) return 0;
    if (r->type == CRES_INT64) return (double)r->val.i;
    if (r->type == CRES_DOUBLE) return r->val.d;
    if (r->type == CRES_BOOL) return r->val.b ? 1.0 : 0.0;
    return 0;
}

static bool res_truthy(const cypher_res_t* r) {
    if (!r || r->type == CRES_NULL) return false;
    if (r->type == CRES_BOOL) return r->val.b;
    if (r->type == CRES_INT64) return r->val.i != 0;
    if (r->type == CRES_DOUBLE) return r->val.d != 0.0;
    if (r->type == CRES_STRING) return r->val.s && r->val.s[0] != '\0';
    return false;
}

static bool res_equals(const cypher_res_t* a, const cypher_res_t* b) {
    if (!a || !b) return false;
    if (a->type == CRES_NULL || b->type == CRES_NULL) return a->type == b->type;
    if (a->type == CRES_STRING && b->type == CRES_STRING) return strcmp(a->val.s, b->val.s) == 0;
    if ((a->type == CRES_INT64 || a->type == CRES_DOUBLE || a->type == CRES_BOOL) &&
        (b->type == CRES_INT64 || b->type == CRES_DOUBLE || b->type == CRES_BOOL))
        return res_to_num(a) == res_to_num(b);
    if (a->type == CRES_VERTEX && b->type == CRES_VERTEX) return a->val.id == b->val.id;
    if (a->type == CRES_EDGE && b->type == CRES_EDGE) return a->val.id == b->val.id;
    return false;
}

static int res_cmp(const cypher_res_t* a, const cypher_res_t* b) {
    if (a->type == CRES_STRING && b->type == CRES_STRING) return strcmp(a->val.s, b->val.s);
    double da = res_to_num(a), db = res_to_num(b);
    return (da < db) ? -1 : (da > db) ? 1 : 0;
}

static cypher_res_t eval_func(qihse_graph_t* g, const cypher_expr_t* e, const brow_t* row) {
    const char* fn = e->s_val ? e->s_val : "";
    if (strcasecmp(fn, "id") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_VERTEX || v.type == CRES_EDGE) return v; /* id is the value */
            cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "type") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_EDGE) {
                graph_edge_t* ed = qihse_graph_edge_get(g, v.val.id);
                cypher_res_free(&v);
                if (ed) { cypher_res_t r = cypher_res_string(ed->type); graph_edge_free(ed); return r; }
            } else cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "labels") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_VERTEX) {
                graph_vertex_t* vx = qihse_graph_vertex_get(g, v.val.id);
                cypher_res_free(&v);
                if (vx) {
                    cypher_res_t r = {0}; r.type = CRES_LIST;
                    r.val.list.items = calloc(vx->num_labels ? vx->num_labels : 1, sizeof(cypher_res_t));
                    for (size_t i = 0; i < vx->num_labels; ++i)
                        r.val.list.items[i] = cypher_res_string(vx->labels[i]);
                    r.val.list.count = vx->num_labels;
                    graph_vertex_free(vx);
                    return r;
                }
            } else cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "keys") == 0 || strcasecmp(fn, "properties") == 0) {
        bool want_props = strcasecmp(fn, "properties") == 0;
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            uint64_t id = v.val.id;
            bool is_v = (v.type == CRES_VERTEX), is_e = (v.type == CRES_EDGE);
            cypher_res_free(&v);
            if (is_v) {
                graph_vertex_t* vx = qihse_graph_vertex_get(g, id);
                if (vx) {
                    cypher_res_t r = {0}; r.type = CRES_LIST;
                    r.val.list.items = calloc(vx->num_props ? vx->num_props : 1, sizeof(cypher_res_t));
                    for (size_t i = 0; i < vx->num_props; ++i) {
                        if (want_props) r.val.list.items[i] = prop_to_res(&vx->prop_vals[i]);
                        else r.val.list.items[i] = cypher_res_string(vx->prop_keys[i]);
                    }
                    r.val.list.count = vx->num_props;
                    graph_vertex_free(vx);
                    return r;
                }
            } else if (is_e) {
                graph_edge_t* ed = qihse_graph_edge_get(g, id);
                if (ed) {
                    cypher_res_t r = {0}; r.type = CRES_LIST;
                    r.val.list.items = calloc(ed->num_props ? ed->num_props : 1, sizeof(cypher_res_t));
                    for (size_t i = 0; i < ed->num_props; ++i) {
                        if (want_props) r.val.list.items[i] = prop_to_res(&ed->prop_vals[i]);
                        else r.val.list.items[i] = cypher_res_string(ed->prop_keys[i]);
                    }
                    r.val.list.count = ed->num_props;
                    graph_edge_free(ed);
                    return r;
                }
            }
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "startNode") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_EDGE) {
                graph_edge_t* ed = qihse_graph_edge_get(g, v.val.id);
                cypher_res_free(&v);
                if (ed) { cypher_res_t r = {0}; r.type = CRES_VERTEX; r.val.id = ed->start_vertex_id; graph_edge_free(ed); return r; }
            } else cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "endNode") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_EDGE) {
                graph_edge_t* ed = qihse_graph_edge_get(g, v.val.id);
                cypher_res_free(&v);
                if (ed) { cypher_res_t r = {0}; r.type = CRES_VERTEX; r.val.id = ed->end_vertex_id; graph_edge_free(ed); return r; }
            } else cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "toUpper") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_STRING) {
                for (char* p = v.val.s; *p; ++p) *p = (char)toupper((unsigned char)*p);
                return v;
            }
            cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "toLower") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_STRING) {
                for (char* p = v.val.s; *p; ++p) *p = (char)tolower((unsigned char)*p);
                return v;
            }
            cypher_res_free(&v);
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "length") == 0 || strcasecmp(fn, "size") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            if (v.type == CRES_LIST) { cypher_res_t r = cypher_res_int64((int64_t)v.val.list.count); cypher_res_free(&v); return r; }
            if (v.type == CRES_STRING) { cypher_res_t r = cypher_res_int64((int64_t)strlen(v.val.s)); cypher_res_free(&v); return r; }
            cypher_res_free(&v);
        }
        return cypher_res_int64(0);
    }
    if (strcasecmp(fn, "range") == 0) {
        if (e->nargs >= 2) {
            cypher_res_t a = eval_expr(g, e->args[0], row);
            cypher_res_t b = eval_expr(g, e->args[1], row);
            int64_t start = (int64_t)res_to_num(&a), end = (int64_t)res_to_num(&b), step = 1;
            cypher_res_free(&a); cypher_res_free(&b);
            if (e->nargs >= 3) { cypher_res_t c = eval_expr(g, e->args[2], row); step = (int64_t)res_to_num(&c); cypher_res_free(&c); if (step == 0) step = 1; }
            cypher_res_t r = {0}; r.type = CRES_LIST;
            size_t cap = 8; r.val.list.items = malloc(cap * sizeof(cypher_res_t));
            r.val.list.count = 0;
            if (step > 0) for (int64_t i = start; i <= end; i += step) {
                if (r.val.list.count == cap) { cap *= 2; r.val.list.items = realloc(r.val.list.items, cap * sizeof(cypher_res_t)); }
                r.val.list.items[r.val.list.count++] = cypher_res_int64(i);
            } else for (int64_t i = start; i >= end; i += step) {
                if (r.val.list.count == cap) { cap *= 2; r.val.list.items = realloc(r.val.list.items, cap * sizeof(cypher_res_t)); }
                r.val.list.items[r.val.list.count++] = cypher_res_int64(i);
            }
            return r;
        }
        return cypher_res_null();
    }
    if (strcasecmp(fn, "exists") == 0) {
        if (e->nargs >= 1) {
            cypher_res_t v = eval_expr(g, e->args[0], row);
            bool ex = (v.type != CRES_NULL);
            cypher_res_free(&v);
            return cypher_res_bool(ex);
        }
        return cypher_res_bool(false);
    }
    return cypher_res_null();
}

static cypher_res_t eval_expr(qihse_graph_t* g, const cypher_expr_t* e, const brow_t* row) {
    if (!e) return cypher_res_null();
    switch (e->type) {
        case CEXPR_LITERAL_INT: return cypher_res_int64(e->i_val);
        case CEXPR_LITERAL_DBL: return cypher_res_double(e->d_val);
        case CEXPR_LITERAL_STR: return cypher_res_string(e->s_val);
        case CEXPR_LITERAL_BOOL: return cypher_res_bool(e->b_val);
        case CEXPR_LITERAL_NULL: return cypher_res_null();
        case CEXPR_PARAM: return cypher_res_null(); /* params unsupported in this build */
        case CEXPR_VAR: {
            const cypher_res_t* v = brow_get(row, e->s_val);
            if (v) return cypher_res_dup(v);
            return cypher_res_null();
        }
        case CEXPR_PROP_ACCESS: {
            cypher_res_t base = eval_expr(g, e->left, row);
            if (base.type == CRES_NULL && e->left && e->left->type == CEXPR_VAR && e->left->s_val && e->s_val) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s.%s", e->left->s_val, e->s_val);
                const cypher_res_t* v = brow_get(row, buf);
                if (v) return cypher_res_dup(v);
                /* also try just the property name without the var prefix */
                v = brow_get(row, e->s_val);
                if (v) return cypher_res_dup(v);
            }
            uint64_t id = base.val.id;
            bool is_v = (base.type == CRES_VERTEX), is_e = (base.type == CRES_EDGE);
            cypher_res_free(&base);
            if (is_v) {
                graph_vertex_t* vx = qihse_graph_vertex_get(g, id);
                if (vx) {
                    const graph_prop_t* p = graph_vertex_get_property(vx, e->s_val);
                    cypher_res_t r = prop_to_res(p);
                    graph_vertex_free(vx);
                    return r;
                }
            } else if (is_e) {
                graph_edge_t* ed = qihse_graph_edge_get(g, id);
                if (ed) {
                    const graph_prop_t* p = graph_edge_get_property(ed, e->s_val);
                    cypher_res_t r = prop_to_res(p);
                    graph_edge_free(ed);
                    return r;
                }
            }
            return cypher_res_null();
        }
        case CEXPR_FUNC_CALL: return eval_func(g, e, row);
        case CEXPR_AGG_CALL: return cypher_res_null(); /* handled by aggregation pass */
        case CEXPR_LIST: {
            cypher_res_t r = {0}; r.type = CRES_LIST;
            r.val.list.items = calloc(e->count ? e->count : 1, sizeof(cypher_res_t));
            for (size_t i = 0; i < e->count; ++i) r.val.list.items[i] = eval_expr(g, e->items[i], row);
            r.val.list.count = e->count;
            return r;
        }
        case CEXPR_MAP: {
            /* represent map as a string-ish; for simplicity return null */
            return cypher_res_null();
        }
        case CEXPR_CASE: {
            for (size_t i = 0; i < e->ncase; ++i) {
                cypher_res_t w = eval_expr(g, e->when_exprs[i], row);
                bool match = res_truthy(&w);
                cypher_res_free(&w);
                if (match) return eval_expr(g, e->then_exprs[i], row);
            }
            if (e->else_expr) return eval_expr(g, e->else_expr, row);
            return cypher_res_null();
        }
        case CEXPR_STAR: return cypher_res_int64(1);
        case CEXPR_UNARYOP: {
            if (e->op == COP_NOT) {
                cypher_res_t v = eval_expr(g, e->left, row);
                bool b = !res_truthy(&v);
                cypher_res_free(&v);
                return cypher_res_bool(b);
            }
            if (e->op == COP_IS_NULL) {
                cypher_res_t v = eval_expr(g, e->left, row);
                bool b = (v.type == CRES_NULL);
                cypher_res_free(&v);
                return cypher_res_bool(b);
            }
            if (e->op == COP_IS_NOT_NULL) {
                cypher_res_t v = eval_expr(g, e->left, row);
                bool b = (v.type != CRES_NULL);
                cypher_res_free(&v);
                return cypher_res_bool(b);
            }
            if (e->op == COP_EXISTS) {
                cypher_res_t v = eval_expr(g, e->left, row);
                bool b = (v.type != CRES_NULL);
                cypher_res_free(&v);
                return cypher_res_bool(b);
            }
            if (e->op == COP_SUB) {
                cypher_res_t v = eval_expr(g, e->left, row);
                double d = -res_to_num(&v);
                cypher_res_free(&v);
                return cypher_res_double(d);
            }
            return cypher_res_null();
        }
        case CEXPR_BINOP: {
            if (e->op == COP_AND) {
                cypher_res_t a = eval_expr(g, e->left, row);
                bool ab = res_truthy(&a);
                cypher_res_free(&a);
                if (!ab) return cypher_res_bool(false);
                cypher_res_t b = eval_expr(g, e->right, row);
                bool bb = res_truthy(&b);
                cypher_res_free(&b);
                return cypher_res_bool(bb);
            }
            if (e->op == COP_OR) {
                cypher_res_t a = eval_expr(g, e->left, row);
                bool ab = res_truthy(&a);
                cypher_res_free(&a);
                if (ab) return cypher_res_bool(true);
                cypher_res_t b = eval_expr(g, e->right, row);
                bool bb = res_truthy(&b);
                cypher_res_free(&b);
                return cypher_res_bool(bb);
            }
            cypher_res_t a = eval_expr(g, e->left, row);
            cypher_res_t b = eval_expr(g, e->right, row);
            cypher_res_t r = cypher_res_null();
            switch (e->op) {
                case COP_EQ: r = cypher_res_bool(res_equals(&a, &b)); break;
                case COP_NE: r = cypher_res_bool(!res_equals(&a, &b)); break;
                case COP_LT: r = cypher_res_bool(res_cmp(&a, &b) < 0); break;
                case COP_GT: r = cypher_res_bool(res_cmp(&a, &b) > 0); break;
                case COP_LE: r = cypher_res_bool(res_cmp(&a, &b) <= 0); break;
                case COP_GE: r = cypher_res_bool(res_cmp(&a, &b) >= 0); break;
                case COP_ADD: r = cypher_res_double(res_to_num(&a) + res_to_num(&b)); break;
                case COP_SUB: r = cypher_res_double(res_to_num(&a) - res_to_num(&b)); break;
                case COP_MUL: r = cypher_res_double(res_to_num(&a) * res_to_num(&b)); break;
                case COP_DIV: r = cypher_res_double(res_to_num(&a) / (res_to_num(&b) == 0 ? 1 : res_to_num(&b))); break;
                case COP_MOD: r = cypher_res_double(fmod(res_to_num(&a), res_to_num(&b) == 0 ? 1 : res_to_num(&b))); break;
                case COP_IN: {
                    bool found = false;
                    if (b.type == CRES_LIST) {
                        for (size_t i = 0; i < b.val.list.count; ++i)
                            if (res_equals(&a, &b.val.list.items[i])) { found = true; break; }
                    }
                    r = cypher_res_bool(found);
                    break;
                }
                case COP_STARTS_WITH: {
                    if (a.type == CRES_STRING && b.type == CRES_STRING)
                        r = cypher_res_bool(strncmp(a.val.s, b.val.s, strlen(b.val.s)) == 0);
                    else r = cypher_res_bool(false);
                    break;
                }
                case COP_ENDS_WITH: {
                    if (a.type == CRES_STRING && b.type == CRES_STRING) {
                        size_t la = strlen(a.val.s), lb = strlen(b.val.s);
                        r = cypher_res_bool(la >= lb && strcmp(a.val.s + la - lb, b.val.s) == 0);
                    } else r = cypher_res_bool(false);
                    break;
                }
                case COP_CONTAINS: {
                    if (a.type == CRES_STRING && b.type == CRES_STRING)
                        r = cypher_res_bool(strstr(a.val.s, b.val.s) != NULL);
                    else r = cypher_res_bool(false);
                    break;
                }
                default: break;
            }
            cypher_res_free(&a); cypher_res_free(&b);
            return r;
        }
    }
    return cypher_res_null();
}

/* ---- pattern matching ---- */

static void collect_node_candidates(qihse_graph_t* g, const cypher_node_pattern_t* np,
                                    const brow_t* row, uint64_t** out, size_t* nout) {
    /* if a variable is already bound to a vertex, use that */
    if (np->var) {
        const cypher_res_t* v = brow_get(row, np->var);
        if (v && v->type == CRES_VERTEX) {
            *out = malloc(sizeof(uint64_t)); (*out)[0] = v->val.id; *nout = 1;
            return;
        }
    }
    /* evaluate property filters from the pattern */
    size_t cap = 64;
    uint64_t* ids = malloc(cap * sizeof(uint64_t));
    size_t n = 0;
    if (np->label) {
        n = qihse_graph_get_vertices_by_label(g, np->label, ids, cap);
    } else {
        n = qihse_graph_all_vertex_ids(g, ids, cap);
    }
    /* apply property filters */
    size_t w = 0;
    for (size_t i = 0; i < n; ++i) {
        graph_vertex_t* vx = qihse_graph_vertex_get(g, ids[i]);
        if (!vx) continue;
        bool ok = true;
        for (size_t p = 0; p < np->num_props && ok; ++p) {
            const char* key = np->prop_keys[p]->s_val;
            cypher_res_t want = eval_expr(g, np->prop_vals[p], row);
            const graph_prop_t* gp = graph_vertex_get_property(vx, key);
            cypher_res_t have = prop_to_res(gp);
            if (!res_equals(&want, &have)) ok = false;
            cypher_res_free(&want); cypher_res_free(&have);
        }
        graph_vertex_free(vx);
        if (ok) ids[w++] = ids[i];
    }
    *out = ids; *nout = w;
}

static bool rel_matches(qihse_graph_t* g, const cypher_rel_pattern_t* rp, const graph_edge_t* e,
                        uint64_t from_id, const brow_t* row) {
    if (rp->rel_type && strcmp(rp->rel_type, e->type) != 0) return false;
    /* direction: RIGHT means from->to ; LEFT means to->from ; NONE/BOTH any */
    if (rp->direction == CREL_DIR_RIGHT) {
        if (e->start_vertex_id != from_id) return false;
    } else if (rp->direction == CREL_DIR_LEFT) {
        if (e->end_vertex_id != from_id) return false;
    }
    /* property filters */
    for (size_t p = 0; p < rp->num_props; ++p) {
        const char* key = rp->prop_keys[p]->s_val;
        cypher_res_t want = eval_expr(g, rp->prop_vals[p], row);
        const graph_prop_t* gp = graph_edge_get_property(e, key);
        cypher_res_t have = prop_to_res(gp);
        bool ok = res_equals(&want, &have);
        cypher_res_free(&want); cypher_res_free(&have);
        if (!ok) return false;
    }
    return true;
}

/* expand a single path against the input table, producing output table */
static void exec_match_path(qihse_graph_t* g, const cypher_path_t* path, table_t* in, table_t* out) {
    table_init(out);
    for (size_t r = 0; r < in->count; ++r) {
        brow_t* row = &in->rows[r];
        /* working set of partial bindings, seeded with current row */
        table_t work; table_init(&work);
        brow_t seed; brow_copy_into(row, &seed);
        table_add(&work, seed);
        /* iterate nodes and rels */
        for (size_t ni = 0, ri = 0; ni < path->num_nodes; ++ni) {
            const cypher_node_pattern_t* np = path->nodes[ni];
            table_t next; table_init(&next);
            for (size_t wi = 0; wi < work.count; ++wi) {
                brow_t* wrow = &work.rows[wi];
                uint64_t* cands; size_t ncand;
                collect_node_candidates(g, np, wrow, &cands, &ncand);
                for (size_t c = 0; c < ncand; ++c) {
                    brow_t nr; brow_copy_into(wrow, &nr);
                    if (np->var) {
                        cypher_res_t rv = {0}; rv.type = CRES_VERTEX; rv.val.id = cands[c];
                        brow_set(&nr, np->var, rv);
                    }
                    table_add(&next, nr);
                }
                free(cands);
            }
            table_free(&work); work = next;
            if (work.count == 0) break;
            /* if there's a relationship after this node, expand it */
            if (ri < path->num_rels) {
                const cypher_rel_pattern_t* rp = path->rels[ri++];
                table_t rnext; table_init(&rnext);
                for (size_t wi = 0; wi < work.count; ++wi) {
                    brow_t* wrow = &work.rows[wi];
                    /* the last bound node is the source */
                    const cypher_node_pattern_t* src = path->nodes[ni];
                    const cypher_res_t* sv = src->var ? brow_get(wrow, src->var) : NULL;
                    if (!sv || sv->type != CRES_VERTEX) continue;
                    uint64_t from = sv->val.id;
                    /* variable-length or single hop */
                    if (rp->var_len_min >= 0) {
                        /* BFS up to var_len_max, collect endpoints */
                        int maxh = rp->var_len_max > 0 ? rp->var_len_max : 64;
                        int minh = rp->var_len_min > 0 ? rp->var_len_min : 1;
                        /* simple BFS: track (vertex, hops) */
                        uint64_t* frontier = malloc(sizeof(uint64_t)); frontier[0] = from; size_t fc = 1;
                        for (int h = 1; h <= maxh; ++h) {
                            uint64_t* nextf = malloc(fc * 16 * sizeof(uint64_t)); size_t nf = 0;
                            for (size_t fi = 0; fi < fc; ++fi) {
                                graph_adj_t adj[64];
                                size_t na = qihse_graph_get_neighbors(g, frontier[fi], GRAPH_DIR_BOTH,
                                                                      rp->rel_type, adj, 64);
                                for (size_t a = 0; a < na; ++a) {
                                    if (h >= minh) {
                                        brow_t nr; brow_copy_into(wrow, &nr);
                                        const cypher_node_pattern_t* tgt = path->nodes[ni + 1];
                                        if (tgt->var) { cypher_res_t rv = {0}; rv.type = CRES_VERTEX; rv.val.id = adj[a].neighbor_id; brow_set(&nr, tgt->var, rv); }
                                        if (rp->var) { cypher_res_t rv = {0}; rv.type = CRES_EDGE; rv.val.id = adj[a].edge_id; brow_set(&nr, rp->var, rv); }
                                        table_add(&rnext, nr);
                                    }
                                    nextf[nf++] = adj[a].neighbor_id;
                                }
                            }
                            free(frontier); frontier = nextf; fc = nf;
                        }
                        free(frontier);
                    } else {
                        graph_adj_t adj[64];
                        size_t na = qihse_graph_get_neighbors(g, from, GRAPH_DIR_BOTH,
                                                              rp->rel_type, adj, 64);
                        for (size_t a = 0; a < na; ++a) {
                            graph_edge_t* e = qihse_graph_edge_get(g, adj[a].edge_id);
                            if (!e) continue;
                            bool ok = rel_matches(g, rp, e, from, wrow);
                            if (ok) {
                                uint64_t neighbor = (e->start_vertex_id == from) ? e->end_vertex_id : e->start_vertex_id;
                                brow_t nr; brow_copy_into(wrow, &nr);
                                if (rp->var) { cypher_res_t rv = {0}; rv.type = CRES_EDGE; rv.val.id = e->id; brow_set(&nr, rp->var, rv); }
                                const cypher_node_pattern_t* tgt = path->nodes[ni + 1];
                                if (tgt->var) { cypher_res_t rv = {0}; rv.type = CRES_VERTEX; rv.val.id = neighbor; brow_set(&nr, tgt->var, rv); }
                                /* check target node label/props */
                                if (tgt->label) {
                                    graph_vertex_t* tv = qihse_graph_vertex_get(g, neighbor);
                                    bool labok = false;
                                    if (tv) { for (size_t l = 0; l < tv->num_labels; ++l) if (strcmp(tv->labels[l], tgt->label) == 0) { labok = true; break; } graph_vertex_free(tv); }
                                    if (!labok) { graph_edge_free(e); brow_free(&nr); continue; }
                                }
                                table_add(&rnext, nr);
                            }
                            graph_edge_free(e);
                        }
                    }
                }
                table_free(&work); work = rnext;
                if (work.count == 0) break;
                /* skip the target node expansion since we already bound it */
                ni++;
            }
        }
        for (size_t wi = 0; wi < work.count; ++wi) table_add(out, work.rows[wi]);
        work.count = 0; /* transferred ownership */
        table_free(&work);
    }
}

/* ---- CREATE ---- */

static cypher_res_t create_vertex_from_pattern(qihse_graph_t* g, const cypher_node_pattern_t* np, const brow_t* row) {
    const char* labels[1];
    size_t nl = 0;
    if (np->label) { labels[0] = np->label; nl = 1; }
    const char** pkeys = NULL; graph_prop_t* pvals = NULL;
    if (np->num_props) {
        pkeys = malloc(np->num_props * sizeof(char*));
        pvals = malloc(np->num_props * sizeof(graph_prop_t));
        for (size_t i = 0; i < np->num_props; ++i) {
            pkeys[i] = np->prop_keys[i]->s_val;
            cypher_res_t v = eval_expr(g, np->prop_vals[i], row);
            pvals[i] = res_to_prop(&v);
            cypher_res_free(&v);
        }
    }
    uint64_t id = qihse_graph_vertex_create(g, labels, nl, pkeys, pvals, np->num_props);
    for (size_t i = 0; i < np->num_props; ++i) graph_prop_free(&pvals[i]);
    free(pkeys); free(pvals);
    cypher_res_t r = {0}; r.type = CRES_VERTEX; r.val.id = id;
    return r;
}

static void exec_create_path(qihse_graph_t* g, const cypher_path_t* path, table_t* in, table_t* out) {
    table_init(out);
    if (in->count == 0) {
        /* CREATE with no preceding MATCH: execute once on empty row */
        brow_t empty; brow_init(&empty);
        table_add(in, empty);
    }
    for (size_t r = 0; r < in->count; ++r) {
        brow_t nr; brow_copy_into(&in->rows[r], &nr);
        for (size_t ni = 0, ri = 0; ni < path->num_nodes; ++ni) {
            const cypher_node_pattern_t* np = path->nodes[ni];
            /* if var already bound, reuse; else create */
            const cypher_res_t* existing = np->var ? brow_get(&nr, np->var) : NULL;
            if (existing && (existing->type == CRES_VERTEX)) {
                /* already bound, skip creation */
            } else {
                cypher_res_t v = create_vertex_from_pattern(g, np, &nr);
                if (np->var) brow_set(&nr, np->var, v);
                else cypher_res_free(&v);
            }
            if (ri < path->num_rels) {
                const cypher_rel_pattern_t* rp = path->rels[ri++];
                const cypher_res_t* sv = brow_get(&nr, path->nodes[ni]->var);
                const cypher_res_t* tv = brow_get(&nr, path->nodes[ni + 1]->var);
                if (sv && tv && sv->type == CRES_VERTEX && tv->type == CRES_VERTEX) {
                    const char** pkeys = NULL; graph_prop_t* pvals = NULL;
                    if (rp->num_props) {
                        pkeys = malloc(rp->num_props * sizeof(char*));
                        pvals = malloc(rp->num_props * sizeof(graph_prop_t));
                        for (size_t i = 0; i < rp->num_props; ++i) {
                            pkeys[i] = rp->prop_keys[i]->s_val;
                            cypher_res_t v = eval_expr(g, rp->prop_vals[i], &nr);
                            pvals[i] = res_to_prop(&v);
                            cypher_res_free(&v);
                        }
                    }
                    uint64_t eid = qihse_graph_edge_create(g, rp->rel_type ? rp->rel_type : "",
                                                           sv->val.id, tv->val.id, pkeys, pvals, rp->num_props);
                    for (size_t i = 0; i < rp->num_props; ++i) graph_prop_free(&pvals[i]);
                    free(pkeys); free(pvals);
                    if (rp->var) { cypher_res_t rv = {0}; rv.type = CRES_EDGE; rv.val.id = eid; brow_set(&nr, rp->var, rv); }
                }
                ni++;
            }
        }
        table_add(out, nr);
    }
}

/* ---- MERGE ---- */

static void exec_merge_path(qihse_graph_t* g, const cypher_path_t* path, table_t* in, table_t* out) {
    table_init(out);
    if (in->count == 0) { brow_t empty; brow_init(&empty); table_add(in, empty); }
    for (size_t r = 0; r < in->count; ++r) {
        table_t matched; table_init(&matched);
        exec_match_path(g, path, in, &matched);  /* note: in has 1 row here effectively */
        /* but exec_match_path iterates all of in; restrict to current row */
        /* simpler: build a single-row table */
        (void)matched;
        table_t one; table_init(&one);
        brow_t cp; brow_copy_into(&in->rows[r], &cp); table_add(&one, cp);
        table_t m; exec_match_path(g, path, &one, &m);
        if (m.count > 0) {
            for (size_t i = 0; i < m.count; ++i) table_add(out, m.rows[i]);
            m.count = 0; table_free(&m);
        } else {
            table_t created; exec_create_path(g, path, &one, &created);
            for (size_t i = 0; i < created.count; ++i) table_add(out, created.rows[i]);
            created.count = 0; table_free(&created);
        }
        table_free(&one);
    }
}

/* ---- SET / REMOVE / DELETE ---- */

static void exec_set(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in, table_t* out) {
    table_init(out);
    for (size_t r = 0; r < in->count; ++r) {
        brow_t nr; brow_copy_into(&in->rows[r], &nr);
        for (size_t i = 0; i < c->num_set_items; ++i) {
            const cypher_set_item_t* si = c->set_items[i];
            const cypher_res_t* v = brow_get(&nr, si->var);
            if (!v) continue;
            if (si->label) {
                if (v->type == CRES_VERTEX) qihse_graph_vertex_add_label(g, v->val.id, si->label);
            } else if (si->prop && si->value) {
                cypher_res_t rv = eval_expr(g, si->value, &nr);
                graph_prop_t p = res_to_prop(&rv);
                if (v->type == CRES_VERTEX) qihse_graph_vertex_update(g, v->val.id, (const char* const*)&si->prop, &p, 1);
                else if (v->type == CRES_EDGE) qihse_graph_edge_update(g, v->val.id, (const char* const*)&si->prop, &p, 1);
                graph_prop_free(&p); cypher_res_free(&rv);
            }
        }
        table_add(out, nr);
    }
}

static void exec_remove(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in, table_t* out) {
    table_init(out);
    (void)g;
    for (size_t r = 0; r < in->count; ++r) {
        brow_t nr; brow_copy_into(&in->rows[r], &nr);
        /* property/label removal not fully supported by store; row passes through */
        table_add(out, nr);
    }
}

static void exec_delete(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in, table_t* out) {
    table_init(out);
    for (size_t r = 0; r < in->count; ++r) {
        brow_t nr; brow_copy_into(&in->rows[r], &nr);
        for (size_t i = 0; i < c->num_del_vars; ++i) {
            const cypher_res_t* v = brow_get(&nr, c->del_vars[i]);
            if (!v) continue;
            if (v->type == CRES_VERTEX) {
                qihse_graph_vertex_delete(g, v->val.id);
            } else if (v->type == CRES_EDGE) {
                qihse_graph_edge_delete(g, v->val.id);
            }
        }
        table_add(out, nr);
    }
}

/* ---- WHERE ---- */

static void exec_where(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in, table_t* out) {
    table_init(out);
    for (size_t r = 0; r < in->count; ++r) {
        cypher_res_t v = eval_expr(g, c->where, &in->rows[r]);
        bool keep = res_truthy(&v);
        cypher_res_free(&v);
        if (keep) { brow_t nr; brow_copy_into(&in->rows[r], &nr); table_add(out, nr); }
    }
}

/* ---- UNWIND ---- */

static void exec_unwind(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in, table_t* out) {
    table_init(out);
    for (size_t r = 0; r < in->count; ++r) {
        cypher_res_t v = eval_expr(g, c->unwind_expr, &in->rows[r]);
        if (v.type == CRES_LIST) {
            for (size_t i = 0; i < v.val.list.count; ++i) {
                brow_t nr; brow_copy_into(&in->rows[r], &nr);
                brow_set(&nr, c->unwind_var, cypher_res_dup(&v.val.list.items[i]));
                table_add(out, nr);
            }
        } else {
            brow_t nr; brow_copy_into(&in->rows[r], &nr);
            brow_set(&nr, c->unwind_var, cypher_res_dup(&v));
            table_add(out, nr);
        }
        cypher_res_free(&v);
    }
}

/* ---- LOAD CSV ---- */

static void exec_load_csv(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in, table_t* out) {
    (void)g;
    table_init(out);
    if (!c->csv_uri) return;

    /* strip file:/// prefix if present */
    const char* path = c->csv_uri;
    if (strncmp(path, "file:///", 8) == 0) path += 7; /* keep leading / */
    else if (strncmp(path, "file://", 7) == 0) path += 7;

    FILE* f = fopen(path, "rb");
    if (!f) return;

    char line[65536];
    char delim = c->csv_field_term ? c->csv_field_term : ',';
    csv_row_t__ headers = { .fields = NULL, .count = 0 };

    /* if WITH HEADERS, read first line as headers */
    if (c->csv_with_headers) {
        if (!fgets(line, sizeof(line), f)) { fclose(f); return; }
        line[strcspn(line, "\r\n")] = '\0';
        headers = csv_parse_line__(line, delim);
    }

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        csv_row_t__ row = csv_parse_line__(line, delim);

        /* build a binding row: the csv_var gets a map of column→value */
        brow_t nr;
        brow_init(&nr);

        /* carry over existing bindings from input table (if any) */
        if (in->count > 0) {
            brow_copy_into(&in->rows[0], &nr);
        }

        /* create a map value for the row variable */
        cypher_res_t map_val;
        map_val.type = CRES_LIST; /* reuse LIST as a poor-man's map (pairs) */
        size_t npairs = headers.count ? headers.count : row.count;
        map_val.val.list.items = calloc(npairs, sizeof(cypher_res_t));
        map_val.val.list.count = npairs;

        for (size_t i = 0; i < npairs; i++) {
            const char* key = (i < headers.count) ? headers.fields[i] : NULL;
            const char* val = (i < row.count) ? row.fields[i] : "";
            if (!key) {
                char buf[16]; snprintf(buf, sizeof(buf), "col_%zu", i);
                map_val.val.list.items[i] = cypher_res_string(buf);
            } else {
                map_val.val.list.items[i] = cypher_res_string(key);
            }
            /* store value as next item (key, value pairs) */
            /* Actually, let's use a simpler approach: set each column as a
             * separate binding var.column_name = value, and also set the
             * row var to a map-like structure. For simplicity, we set
             * var.column = value for each column. */
        }

        /* Simpler approach: set csv_var as a string map by setting
         * "csv_var.col_name" = value for each column. But the binding system
         * uses flat names. Let's set the row var to a CRES_LIST of alternating
         * key/value strings, and also set individual "var.col" bindings. */
        cypher_res_free(&map_val);

        for (size_t i = 0; i < row.count; i++) {
            const char* key = (i < headers.count) ? headers.fields[i] : NULL;
            char binding_name[256];
            if (key)
                snprintf(binding_name, sizeof(binding_name), "%s.%s", c->csv_var, key);
            else {
                snprintf(binding_name, sizeof(binding_name), "%s.col_%zu", c->csv_var, i);
            }
            brow_set(&nr, binding_name, cypher_res_string(row.fields[i]));

            /* also set just the column name (without var prefix) for convenience */
            if (key) brow_set(&nr, key, cypher_res_string(row.fields[i]));
        }

        table_add(out, nr);
        csv_row_free__(&row);
    }

    if (headers.fields) csv_row_free__(&headers);
    fclose(f);
}

/* ---- aggregation ---- */

static bool expr_has_aggregate(const cypher_expr_t* e) {
    if (!e) return false;
    if (e->type == CEXPR_AGG_CALL) return true;
    if (expr_has_aggregate(e->left)) return true;
    if (expr_has_aggregate(e->right)) return true;
    if (expr_has_aggregate(e->else_expr)) return true;
    for (size_t i = 0; i < e->nargs; ++i) if (expr_has_aggregate(e->args[i])) return true;
    for (size_t i = 0; i < e->count; ++i) if (expr_has_aggregate(e->items[i])) return true;
    for (size_t i = 0; i < e->ncase; ++i) {
        if (expr_has_aggregate(e->when_exprs[i]) || expr_has_aggregate(e->then_exprs[i])) return true;
    }
    return false;
}

static cypher_res_t eval_aggregate(qihse_graph_t* g, const cypher_expr_t* agg, table_t* rows) {
    const char* fn = agg->s_val ? agg->s_val : "";
    /* count(*) */
    if (strcasecmp(fn, "count") == 0) {
        if (agg->nargs == 0 || (agg->nargs == 1 && agg->args[0]->type == CEXPR_STAR))
            return cypher_res_int64((int64_t)rows->count);
        /* count(expr) : count non-null */
        int64_t cnt = 0;
        for (size_t i = 0; i < rows->count; ++i) {
            cypher_res_t v = eval_expr(g, agg->args[0], &rows->rows[i]);
            if (v.type != CRES_NULL) cnt++;
            cypher_res_free(&v);
        }
        return cypher_res_int64(cnt);
    }
    if (strcasecmp(fn, "sum") == 0) {
        double s = 0;
        for (size_t i = 0; i < rows->count; ++i) { cypher_res_t v = eval_expr(g, agg->args[0], &rows->rows[i]); s += res_to_num(&v); cypher_res_free(&v); }
        return cypher_res_double(s);
    }
    if (strcasecmp(fn, "avg") == 0) {
        double s = 0; size_t n = 0;
        for (size_t i = 0; i < rows->count; ++i) { cypher_res_t v = eval_expr(g, agg->args[0], &rows->rows[i]); if (v.type != CRES_NULL) { s += res_to_num(&v); n++; } cypher_res_free(&v); }
        return cypher_res_double(n ? s / n : 0);
    }
    if (strcasecmp(fn, "min") == 0) {
        bool set = false; double m = 0;
        for (size_t i = 0; i < rows->count; ++i) { cypher_res_t v = eval_expr(g, agg->args[0], &rows->rows[i]); double d = res_to_num(&v); if (!set || d < m) { m = d; set = true; } cypher_res_free(&v); }
        return set ? cypher_res_double(m) : cypher_res_null();
    }
    if (strcasecmp(fn, "max") == 0) {
        bool set = false; double m = 0;
        for (size_t i = 0; i < rows->count; ++i) { cypher_res_t v = eval_expr(g, agg->args[0], &rows->rows[i]); double d = res_to_num(&v); if (!set || d > m) { m = d; set = true; } cypher_res_free(&v); }
        return set ? cypher_res_double(m) : cypher_res_null();
    }
    if (strcasecmp(fn, "collect") == 0) {
        cypher_res_t r = {0}; r.type = CRES_LIST;
        r.val.list.items = calloc(rows->count ? rows->count : 1, sizeof(cypher_res_t));
        size_t n = 0;
        for (size_t i = 0; i < rows->count; ++i) {
            cypher_res_t v = eval_expr(g, agg->args[0], &rows->rows[i]);
            if (v.type != CRES_NULL) r.val.list.items[n++] = v;
            else cypher_res_free(&v);
        }
        r.val.list.count = n;
        return r;
    }
    return cypher_res_null();
}

/* evaluate return item expr; if it contains aggregates, use the grouped rows */
static cypher_res_t eval_return_expr(qihse_graph_t* g, const cypher_expr_t* e, const brow_t* row, table_t* group) {
    if (!e) return cypher_res_null();
    if (e->type == CEXPR_AGG_CALL) return eval_aggregate(g, e, group);
    if (e->type == CEXPR_BINOP) {
        cypher_res_t a = eval_return_expr(g, e->left, row, group);
        cypher_res_t b = eval_return_expr(g, e->right, row, group);
        cypher_res_t r = cypher_res_null();
        switch (e->op) {
            case COP_ADD: r = cypher_res_double(res_to_num(&a) + res_to_num(&b)); break;
            case COP_SUB: r = cypher_res_double(res_to_num(&a) - res_to_num(&b)); break;
            case COP_MUL: r = cypher_res_double(res_to_num(&a) * res_to_num(&b)); break;
            default: break;
        }
        cypher_res_free(&a); cypher_res_free(&b);
        return r;
    }
    return eval_expr(g, e, row);
}

/* ---- RETURN / WITH projection ---- */

static char* return_item_name(const cypher_return_item_t* ri) {
    if (ri->alias) return strdup(ri->alias);
    if (ri->expr->type == CEXPR_VAR) return strdup(ri->expr->s_val);
    if (ri->expr->type == CEXPR_PROP_ACCESS) {
        char buf[128]; snprintf(buf, sizeof(buf), "%s.%s", ri->expr->left->s_val, ri->expr->s_val);
        return strdup(buf);
    }
    if (ri->expr->type == CEXPR_AGG_CALL) {
        char buf[128]; snprintf(buf, sizeof(buf), "%s(...)", ri->expr->s_val);
        return strdup(buf);
    }
    return strdup("expr");
}

static void exec_projection(qihse_graph_t* g, const qihse_cypher_clause_t* c, table_t* in,
                            cypher_result_set_t* rs) {
    bool has_agg = false;
    for (size_t i = 0; i < c->num_items; ++i) if (expr_has_aggregate(c->items[i]->expr)) { has_agg = true; break; }

    /* column names */
    rs->num_cols = c->num_items;
    rs->names = malloc(c->num_items * sizeof(char*));
    for (size_t i = 0; i < c->num_items; ++i) rs->names[i] = return_item_name(c->items[i]);

    if (!has_agg) {
        rs->num_rows = 0;
        size_t cap = in->count ? in->count : 1;
        rs->values = malloc(cap * c->num_items * sizeof(cypher_res_t));
        for (size_t r = 0; r < in->count; ++r) {
            for (size_t i = 0; i < c->num_items; ++i)
                rs->values[r * c->num_items + i] = eval_expr(g, c->items[i]->expr, &in->rows[r]);
            rs->num_rows++;
        }
    } else {
        /* group by non-aggregate items */
        /* determine group key columns */
        size_t* nonagg_idx = malloc(c->num_items * sizeof(size_t));
        size_t nnonagg = 0;
        for (size_t i = 0; i < c->num_items; ++i) if (!expr_has_aggregate(c->items[i]->expr)) nonagg_idx[nnonagg++] = i;
        /* build groups */
        brow_t* groups = malloc((in->count ? in->count : 1) * sizeof(brow_t));
        size_t* group_row_idx = malloc((in->count ? in->count : 1) * sizeof(size_t));
        size_t ngroups = 0;
        for (size_t r = 0; r < in->count; ++r) {
            size_t gi;
            for (gi = 0; gi < ngroups; ++gi) {
                bool same = true;
                for (size_t k = 0; k < nnonagg && same; ++k) {
                    cypher_res_t a = eval_expr(g, c->items[nonagg_idx[k]]->expr, &in->rows[r]);
                    cypher_res_t b = eval_expr(g, c->items[nonagg_idx[k]]->expr, &groups[gi]);
                    if (!res_equals(&a, &b)) same = false;
                    cypher_res_free(&a); cypher_res_free(&b);
                }
                if (same) break;
            }
            if (gi == ngroups) {
                brow_init(&groups[ngroups]);
                for (size_t k = 0; k < nnonagg; ++k) {
                    cypher_res_t v = eval_expr(g, c->items[nonagg_idx[k]]->expr, &in->rows[r]);
                    brow_set(&groups[ngroups], c->items[nonagg_idx[k]]->expr->s_val ? c->items[nonagg_idx[k]]->expr->s_val : "_g", v);
                }
                ngroups++;
            }
            group_row_idx[r] = gi;
        }
        /* for each group, collect rows */
        rs->num_rows = 0;
        rs->values = malloc((ngroups ? ngroups : 1) * c->num_items * sizeof(cypher_res_t));
        for (size_t gi = 0; gi < ngroups; ++gi) {
            table_t gt; table_init(&gt);
            for (size_t r = 0; r < in->count; ++r) if (group_row_idx[r] == gi) table_add(&gt, in->rows[r]);
            for (size_t i = 0; i < c->num_items; ++i)
                rs->values[gi * c->num_items + i] = eval_return_expr(g, c->items[i]->expr, &groups[gi], &gt);
            rs->num_rows++;
            gt.count = 0; table_free(&gt);
        }
        for (size_t g = 0; g < ngroups; ++g) brow_free(&groups[g]);
        free(groups); free(group_row_idx); free(nonagg_idx);
    }

    /* DISTINCT */
    if (c->distinct) {
        size_t w = 0;
        for (size_t r = 0; r < rs->num_rows; ++r) {
            bool dup = false;
            for (size_t k = 0; k < w && !dup; ++k) {
                bool same = true;
                for (size_t i = 0; i < rs->num_cols; ++i) {
                    if (!res_equals(&rs->values[r * rs->num_cols + i], &rs->values[k * rs->num_cols + i])) { same = false; break; }
                }
                if (same) dup = true;
            }
            if (!dup) {
                if (w != r) for (size_t i = 0; i < rs->num_cols; ++i) rs->values[w * rs->num_cols + i] = rs->values[r * rs->num_cols + i];
                w++;
            } else {
                for (size_t i = 0; i < rs->num_cols; ++i) cypher_res_free(&rs->values[r * rs->num_cols + i]);
            }
        }
        rs->num_rows = w;
    }
}

/* ---- ORDER BY / SKIP / LIMIT applied to result set ---- */

static void apply_order_skip_limit(cypher_result_set_t* rs, qihse_cypher_clause_t* order,
                                   int64_t skip, int64_t limit) {
    (void)order; (void)rs; (void)skip; (void)limit;
    /* ORDER BY on result set not fully wired; pass-through */
}

/* ---- main execution ---- */

static cypher_result_set_t* execute_query(qihse_graph_t* g, qihse_cypher_query_t* q) {
    table_t cur; table_init(&cur);
    brow_t seed; brow_init(&seed); table_add(&cur, seed);
    cypher_result_set_t* rs = NULL;
    qihse_cypher_clause_t* pending_order = NULL;
    int64_t pending_skip = -1, pending_limit = -1;

    qihse_cypher_clause_t* c = q->first;
    while (c) {
        switch (c->type) {
            case CYPHER_MATCH: {
                table_t out;
                for (size_t p = 0; p < c->num_paths; ++p) {
                    table_t tmp;
                    exec_match_path(g, c->paths[p], &cur, &tmp);
                    table_free(&cur); cur = tmp;
                }
                (void)out;
                break;
            }
            case CYPHER_CREATE: {
                table_t out;
                for (size_t p = 0; p < c->num_paths; ++p) {
                    table_t tmp;
                    exec_create_path(g, c->paths[p], &cur, &tmp);
                    table_free(&cur); cur = tmp;
                }
                break;
            }
            case CYPHER_MERGE: {
                table_t out;
                for (size_t p = 0; p < c->num_paths; ++p) {
                    table_t tmp;
                    exec_merge_path(g, c->paths[p], &cur, &tmp);
                    table_free(&cur); cur = tmp;
                }
                break;
            }
            case CYPHER_WHERE: {
                table_t out; exec_where(g, c, &cur, &out); table_free(&cur); cur = out; break;
            }
            case CYPHER_SET: {
                table_t out; exec_set(g, c, &cur, &out); table_free(&cur); cur = out; break;
            }
            case CYPHER_REMOVE: {
                table_t out; exec_remove(g, c, &cur, &out); table_free(&cur); cur = out; break;
            }
            case CYPHER_DELETE: {
                table_t out; exec_delete(g, c, &cur, &out); table_free(&cur); cur = out; break;
            }
            case CYPHER_UNWIND: {
                table_t out; exec_unwind(g, c, &cur, &out); table_free(&cur); cur = out; break;
            }
            case CYPHER_LOAD_CSV: {
                table_t out; exec_load_csv(g, c, &cur, &out); table_free(&cur); cur = out; break;
            }
            case CYPHER_RETURN: {
                rs = calloc(1, sizeof(cypher_result_set_t));
                exec_projection(g, c, &cur, rs);
                if (pending_order || pending_skip >= 0 || pending_limit >= 0)
                    apply_order_skip_limit(rs, pending_order, pending_skip, pending_limit);
                /* stop clause chain for this query */
                goto done;
            }
            case CYPHER_WITH: {
                /* project into a new table where columns become bindings */
                cypher_result_set_t* tmp = calloc(1, sizeof(cypher_result_set_t));
                exec_projection(g, c, &cur, tmp);
                table_free(&cur); table_init(&cur);
                for (size_t r = 0; r < tmp->num_rows; ++r) {
                    brow_t nr; brow_init(&nr);
                    for (size_t i = 0; i < tmp->num_cols; ++i)
                        brow_set(&nr, tmp->names[i], cypher_res_dup(&tmp->values[r * tmp->num_cols + i]));
                    table_add(&cur, nr);
                }
                qihse_cypher_result_free(tmp);
                break;
            }
            case CYPHER_ORDER_BY: pending_order = c; break;
            case CYPHER_SKIP: pending_skip = c->skip; break;
            case CYPHER_LIMIT: pending_limit = c->limit; break;
            case CYPHER_UNION: {
                /* result set already built by preceding RETURN; combine with next query's RETURN */
                /* simplified: leave rs as-is for first branch */
                break;
            }
            default: break;
        }
        c = c->next;
    }
done:
    table_free(&cur);
    if (!rs) {
        rs = calloc(1, sizeof(cypher_result_set_t));
        rs->num_cols = 0; rs->num_rows = 0;
    }
    return rs;
}

cypher_result_set_t* qihse_cypher_execute(qihse_graph_t* g, qihse_cypher_ast_t* ast) {
    if (!g || !ast || ast->num_queries == 0) return NULL;
    /* execute first query; UNION with subsequent */
    cypher_result_set_t* rs = execute_query(g, ast->queries[0]);
    for (size_t i = 1; i < ast->num_queries; ++i) {
        cypher_result_set_t* next = execute_query(g, ast->queries[i]);
        if (!next) continue;
        size_t old = rs->num_rows;
        size_t add = next->num_rows;
        rs->values = realloc(rs->values, (old + add) * rs->num_cols * sizeof(cypher_res_t));
        for (size_t r = 0; r < add; ++r)
            for (size_t col = 0; col < rs->num_cols; ++col)
                rs->values[(old + r) * rs->num_cols + col] = cypher_res_dup(&next->values[r * next->num_cols + col]);
        rs->num_rows = old + add;
        qihse_cypher_result_free(next);
    }
    return rs;
}

cypher_result_set_t* qihse_cypher_run(qihse_graph_t* g, const char* cypher) {
    qihse_cypher_ast_t* ast = qihse_cypher_parse(cypher);
    if (!ast) return NULL;
    cypher_result_set_t* rs = qihse_cypher_execute(g, ast);
    qihse_cypher_ast_free(ast);
    return rs;
}

void qihse_cypher_result_free(cypher_result_set_t* rs) {
    if (!rs) return;
    for (size_t i = 0; i < rs->num_rows * rs->num_cols; ++i) cypher_res_free(&rs->values[i]);
    free(rs->values);
    for (size_t i = 0; i < rs->num_cols; ++i) free(rs->names[i]);
    free(rs->names);
    free(rs);
}
