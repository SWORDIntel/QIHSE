#define _GNU_SOURCE
/*
 * QIHSE SQL Parser — Phase 1 Relational Completeness
 *
 * Supports: SELECT (with JOIN, GROUP BY, HAVING, ORDER BY, aggregates, DISTINCT,
 *           subqueries, set operations UNION/INTERSECT/EXCEPT), INSERT, UPDATE,
 *           DELETE, CREATE TABLE (typed columns), CREATE/DROP INDEX,
 *           ALTER TABLE (ADD/DROP/RENAME), DROP TABLE.
 */
#include "qihse_sql_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * Small string utilities
 * ------------------------------------------------------------------------- */
static char* trim_str(char* s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char* end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static char* dup_token(const char* src, size_t len) {
    char* tok = (char*)malloc(len + 1);
    if (!tok) return NULL;
    memcpy(tok, src, len);
    tok[len] = '\0';
    return tok;
}

static char* dup_range(const char* start, const char* end) {
    return dup_token(start, (size_t)(end - start));
}

__attribute__((unused)) static bool str_ieq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
}

/* case-insensitive prefix match; returns pointer just past prefix or NULL */
static const char* match_kw(const char* p, const char* kw) {
    while (*p && isspace((unsigned char)*p)) p++;
    size_t kl = strlen(kw);
    if (strncasecmp(p, kw, kl) != 0) return NULL;
    /* ensure word boundary */
    char after = p[kl];
    if (isalnum((unsigned char)after) || after == '_') return NULL;
    return p + kl;
}

static const char* skip_ws(const char* p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static const char* read_identifier(const char* p, size_t* out_len) {
    *out_len = 0;
    p = skip_ws(p);
    const char* start = p;
    if (*p == '"') {
        p++;
        start = p;
        while (*p && *p != '"') p++;
        *out_len = (size_t)(p - start);
        if (*p == '"') p++;
    } else {
        while (*p && (isalnum((unsigned char)*p) || *p == '_' || *p == '.')) p++;
        *out_len = (size_t)(p - start);
    }
    return start;
}

static const char* read_value(const char* p, size_t* out_len, int* is_string) {
    *out_len = 0;
    *is_string = 0;
    p = skip_ws(p);
    const char* start = p;
    if (*p == '\'') {
        *is_string = 1;
        p++;
        start = p;
        while (*p && *p != '\'') p++;
        *out_len = (size_t)(p - start);
        if (*p == '\'') p++;
    } else {
        while (*p && !isspace((unsigned char)*p) && *p != ';' && *p != ')') p++;
        *out_len = (size_t)(p - start);
    }
    return start;
}

static const char* read_operator(const char* p, size_t* out_len) {
    *out_len = 0;
    p = skip_ws(p);
    const char* start = p;
    if (*p == '=' || *p == '<' || *p == '>' || *p == '!') {
        p++;
        if (*p == '=' || (*start == '<' && *p == '>')) p++;
        *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "LIKE", 4) == 0) {
        p += 4;
        *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "IN", 2) == 0) {
        p += 2;
        *out_len = (size_t)(p - start);
    }
    return start;
}

/* -------------------------------------------------------------------------
 * Type name parsing
 * ------------------------------------------------------------------------- */
static qihse_sql_type_t parse_type_name(const char* p, size_t len, int* type_len) {
    *type_len = 0;
    char tmp[32];
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    memcpy(tmp, p, len);
    tmp[len] = '\0';
    /* uppercase compare */
    for (size_t i = 0; i < len; i++) tmp[i] = (char)toupper((unsigned char)tmp[i]);
    if (strcmp(tmp, "INT") == 0 || strcmp(tmp, "INTEGER") == 0) return QIHSE_TYPE_INT;
    if (strcmp(tmp, "BIGINT") == 0) return QIHSE_TYPE_BIGINT;
    if (strcmp(tmp, "FLOAT") == 0 || strcmp(tmp, "REAL") == 0) return QIHSE_TYPE_FLOAT;
    if (strcmp(tmp, "DOUBLE") == 0 || strcmp(tmp, "DOUBLE PRECISION") == 0) return QIHSE_TYPE_DOUBLE;
    if (strcmp(tmp, "VARCHAR") == 0) return QIHSE_TYPE_VARCHAR;
    if (strcmp(tmp, "TEXT") == 0) return QIHSE_TYPE_TEXT;
    if (strcmp(tmp, "BOOL") == 0 || strcmp(tmp, "BOOLEAN") == 0) return QIHSE_TYPE_BOOL;
    if (strcmp(tmp, "TIMESTAMP") == 0) return QIHSE_TYPE_TIMESTAMP;
    if (strcmp(tmp, "VECTOR") == 0) return QIHSE_TYPE_VECTOR;
    return QIHSE_TYPE_UNKNOWN;
}

/* -------------------------------------------------------------------------
 * Aggregate detection from an expression token
 * ------------------------------------------------------------------------- */
static qihse_sql_agg_kind_t detect_aggregate(const char* expr, size_t len,
                                             const char** arg_start, size_t* arg_len) {
    char tmp[32];
    if (len >= sizeof(tmp)) return QIHSE_AGG_NONE;
    memcpy(tmp, expr, len);
    tmp[len] = '\0';
    /* uppercase */
    for (size_t i = 0; i < len; i++) tmp[i] = (char)toupper((unsigned char)tmp[i]);
    if (strcmp(tmp, "SUM") == 0) return QIHSE_AGG_SUM;
    if (strcmp(tmp, "COUNT") == 0) return QIHSE_AGG_COUNT;
    if (strcmp(tmp, "AVG") == 0) return QIHSE_AGG_AVG;
    if (strcmp(tmp, "MIN") == 0) return QIHSE_AGG_MIN;
    if (strcmp(tmp, "MAX") == 0) return QIHSE_AGG_MAX;
    (void)arg_start; (void)arg_len;
    return QIHSE_AGG_NONE;
}

/* -------------------------------------------------------------------------
 * Find matching closing paren starting at p (which points to '(')
 * ------------------------------------------------------------------------- */
static const char* find_matching_paren(const char* p) {
    if (!p || *p != '(') return NULL;
    int depth = 1;
    p++;
    while (*p) {
        if (*p == '(') depth++;
        else if (*p == ')') { depth--; if (depth == 0) return p; }
        p++;
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Parse a SELECT-list item expression, detecting aggregates and aliases
 * ------------------------------------------------------------------------- */
static void parse_select_item(const char* start, size_t len, qihse_sql_select_item_t* item) {
    memset(item, 0, sizeof(*item));
    /* find " AS " or trailing alias */
    char* buf = dup_token(start, len);
    if (!buf) return;
    
    char* endp = buf + len;

    /* look for " AS " */
    char* as_pos = NULL;
    for (char* c = buf; c < endp - 3; c++) {
        if (strncasecmp(c, " AS ", 4) == 0 || strncasecmp(c, "\tAS\t", 4) == 0) {
            as_pos = c;
            break;
        }
    }
    if (as_pos) {
        *as_pos = '\0';
        char* alias_part = as_pos + 4;
        while (*alias_part && isspace((unsigned char)*alias_part)) alias_part++;
        item->alias = strdup(alias_part);
        /* trim trailing ws of expr */
        char* e = as_pos - 1;
        while (e > buf && isspace((unsigned char)*e)) { *e = '\0'; e--; }
        item->expr = strdup(trim_str(buf));
        free(buf);
        return;
    }

    /* detect aggregate: NAME(arg) possibly at start */
    const char* sp = skip_ws(buf);
    const char* fname = sp;
    const char* fp = sp;
    while (*fp && (isalpha((unsigned char)*fp) || *fp == '_')) fp++;
    size_t fname_len = (size_t)(fp - fname);
    if (fname_len > 0 && *fp == '(') {
        const char* arg_s = fp + 1;
        const char* close = find_matching_paren(fp);
        if (close) {
            /* trim arg whitespace */
            while (arg_s < close && isspace((unsigned char)*arg_s)) arg_s++;
            const char* arg_e = close;
            while (arg_e > arg_s && isspace((unsigned char)arg_e[-1])) arg_e--;
            qihse_sql_agg_kind_t agg = detect_aggregate(fname, fname_len, NULL, NULL);
            if (agg != QIHSE_AGG_NONE) {
                item->agg_kind = agg;
                if ((size_t)(arg_e - arg_s) == 1 && arg_s[0] == '*') {
                    item->agg_kind = QIHSE_AGG_COUNT_STAR;
                    item->agg_arg = strdup("*");
                } else {
                    item->agg_arg = dup_range(arg_s, arg_e);
                }
                item->expr = dup_range(fname, close + 1);
                free(buf);
                return;
            }
        }
    }

    item->expr = strdup(trim_str(buf));
    free(buf);
}

/* -------------------------------------------------------------------------
 * Parse column definition for CREATE TABLE
 * ------------------------------------------------------------------------- */
static void parse_column_def(const char* seg, qihse_sql_column_def_t* col) {
    memset(col, 0, sizeof(*col));
    const char* p = skip_ws(seg);
    size_t name_len;
    const char* name_start = read_identifier(p, &name_len);
    if (name_len == 0) return;
    col->name = dup_token(name_start, name_len);
    p = name_start + name_len;
    p = skip_ws(p);

    /* type name (may include (len)) */
    const char* tstart = p;
    while (*p && (isalpha((unsigned char)*p) || *p == '_')) p++;
    size_t tlen = (size_t)(p - tstart);
    int type_len = 0;
    col->type = parse_type_name(tstart, tlen, &type_len);
    p = skip_ws(p);
    if (*p == '(') {
        p++;
        type_len = (int)strtol(p, (char**)&p, 10);
        p = skip_ws(p);
        if (*p == ')') p++;
    }
    col->type_len = type_len;

    /* constraints */
    for (;;) {
        p = skip_ws(p);
        if (strncasecmp(p, "NOT NULL", 8) == 0) { col->not_null = 1; p += 8; continue; }
        if (strncasecmp(p, "PRIMARY KEY", 11) == 0) { col->is_primary_key = 1; p += 11; continue; }
        if (strncasecmp(p, "DEFAULT", 7) == 0) {
            p += 7;
            p = skip_ws(p);
            const char* dstart = p;
            while (*p && *p != ',' && strncasecmp(p, " NOT", 4) != 0 &&
                   strncasecmp(p, " PRIMARY", 8) != 0) p++;
            col->default_expr = dup_range(dstart, p);
            continue;
        }
        break;
    }
}

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_select(const char** pp);
static qihse_sql_ast_t* parse_statement(const char* sql);

/* -------------------------------------------------------------------------
 * Parse a subquery enclosed in parentheses; *pp points at '('
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_paren_subquery(const char** pp) {
    const char* p = *pp;
    p = skip_ws(p);
    if (*p != '(') return NULL;
    const char* close = find_matching_paren(p);
    if (!close) return NULL;
    /* inner content */
    const char* inner = p + 1;
    size_t inner_len = (size_t)(close - inner);
    char* inner_copy = dup_token(inner, inner_len);
    qihse_sql_ast_t* sub = parse_statement(inner_copy);
    free(inner_copy);
    *pp = close + 1;
    return sub;
}

/* -------------------------------------------------------------------------
 * Parse WHERE conditions, including IN (subquery) and EXISTS (subquery)
 * ------------------------------------------------------------------------- */
static void parse_where(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = *pp;
    size_t cond_cap = 4;
    ast->where_conditions = (qihse_sql_condition_t*)calloc(cond_cap, sizeof(qihse_sql_condition_t));
    ast->num_where_conditions = 0;

    for (;;) {
        p = skip_ws(p);
        /* EXISTS / NOT EXISTS */
        if (strncasecmp(p, "EXISTS", 6) == 0 && !isalnum((unsigned char)p[6])) {
            p += 6;
            qihse_sql_ast_t* sub = parse_paren_subquery(&p);
            if (ast->num_where_conditions >= cond_cap) {
                cond_cap *= 2;
                ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
            }
            qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
            memset(c, 0, sizeof(*c));
            c->subq_kind = QIHSE_SUBQ_EXISTS;
            c->subquery = sub;
            c->operator = strdup("EXISTS");
        } else if (strncasecmp(p, "NOT EXISTS", 10) == 0) {
            p += 10;
            qihse_sql_ast_t* sub = parse_paren_subquery(&p);
            if (ast->num_where_conditions >= cond_cap) {
                cond_cap *= 2;
                ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
            }
            qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
            memset(c, 0, sizeof(*c));
            c->subq_kind = QIHSE_SUBQ_NOT_EXISTS;
            c->subquery = sub;
            c->operator = strdup("NOT EXISTS");
        } else {
            size_t col_len;
            const char* col_start = read_identifier(p, &col_len);
            if (col_len == 0) break;
            p = col_start + col_len;
            p = skip_ws(p);

            /* check for IN (subquery) or NOT IN (subquery) */
            if (strncasecmp(p, "IN", 2) == 0 && (p[2] == 0 || isspace((unsigned char)p[2]) || p[2] == '(')) {
                p += 2;
                qihse_sql_ast_t* sub = parse_paren_subquery(&p);
                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                c->operator = strdup("IN");
                c->subq_kind = QIHSE_SUBQ_IN;
                c->subquery = sub;
            } else if (strncasecmp(p, "NOT IN", 6) == 0) {
                p += 6;
                qihse_sql_ast_t* sub = parse_paren_subquery(&p);
                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                c->operator = strdup("NOT IN");
                c->subq_kind = QIHSE_SUBQ_NOT_IN;
                c->subquery = sub;
            } else {
                size_t op_len;
                const char* op_start = read_operator(p, &op_len);
                if (op_len == 0) break;
                p = op_start + op_len;

                int is_str;
                size_t val_len;
                const char* val_start = read_value(p, &val_len, &is_str);
                if (val_len == 0) break;
                p = val_start + val_len;

                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                c->operator = dup_token(op_start, op_len);
                c->value = dup_token(val_start, val_len);
                c->value_is_string = is_str;
            }
        }

        p = skip_ws(p);
        if (strncasecmp(p, "AND", 3) == 0 && !isalnum((unsigned char)p[3])) { p += 3; continue; }
        if (strncasecmp(p, "OR", 2) == 0 && !isalnum((unsigned char)p[2])) { p += 2; continue; }
        break;
    }
    *pp = p;
}

/* -------------------------------------------------------------------------
 * Parse JOIN clauses following FROM
 * ------------------------------------------------------------------------- */
static void parse_joins(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = *pp;
    size_t join_cap = 4;
    ast->joins = (qihse_sql_join_t*)calloc(join_cap, sizeof(qihse_sql_join_t));
    ast->num_joins = 0;

    for (;;) {
        p = skip_ws(p);
        qihse_sql_join_type_t jt = 0;
        const char* after = NULL;
        if ((after = match_kw(p, "INNER JOIN"))) { jt = QIHSE_JOIN_INNER; p = after; }
        else if ((after = match_kw(p, "LEFT JOIN"))) { jt = QIHSE_JOIN_LEFT; p = after; }
        else if ((after = match_kw(p, "LEFT OUTER JOIN"))) { jt = QIHSE_JOIN_LEFT; p = after; }
        else if ((after = match_kw(p, "RIGHT JOIN"))) { jt = QIHSE_JOIN_RIGHT; p = after; }
        else if ((after = match_kw(p, "RIGHT OUTER JOIN"))) { jt = QIHSE_JOIN_RIGHT; p = after; }
        else if ((after = match_kw(p, "CROSS JOIN"))) { jt = QIHSE_JOIN_CROSS; p = after; }
        else if ((after = match_kw(p, "FULL JOIN"))) { jt = QIHSE_JOIN_FULL; p = after; }
        else if ((after = match_kw(p, "FULL OUTER JOIN"))) { jt = QIHSE_JOIN_FULL; p = after; }
        else if ((after = match_kw(p, "JOIN"))) { jt = QIHSE_JOIN_INNER; p = after; }
        else break;

        /* parse table + optional alias */
        size_t id_len;
        const char* id_start = read_identifier(p, &id_len);
        if (id_len == 0) break;
        p = id_start + id_len;
        if (ast->num_joins >= join_cap) {
            join_cap *= 2;
            ast->joins = (qihse_sql_join_t*)realloc(ast->joins, join_cap * sizeof(qihse_sql_join_t));
        }
        qihse_sql_join_t* j = &ast->joins[ast->num_joins++];
        memset(j, 0, sizeof(*j));
        j->join_type = jt;
        j->table.table_name = dup_token(id_start, id_len);
        j->table.alias = NULL;

        /* optional alias: "AS alias" or bare alias */
        p = skip_ws(p);
        const char* as_after = match_kw(p, "AS");
        if (as_after) {
            p = as_after;
            size_t alen;
            const char* astart = read_identifier(p, &alen);
            if (alen > 0) {
                j->table.alias = dup_token(astart, alen);
                p = astart + alen;
            }
        } else {
            /* bare alias if next token is an identifier not a keyword */
            size_t alen;
            const char* astart = read_identifier(p, &alen);
            if (alen > 0) {
                const char* kw_check = p;
                if (strncasecmp(kw_check, "ON", 2) != 0 &&
                    strncasecmp(kw_check, "WHERE", 5) != 0 &&
                    strncasecmp(kw_check, "GROUP", 5) != 0 &&
                    strncasecmp(kw_check, "ORDER", 5) != 0 &&
                    strncasecmp(kw_check, "LIMIT", 5) != 0 &&
                    strncasecmp(kw_check, "OFFSET", 6) != 0 &&
                    strncasecmp(kw_check, "HAVING", 6) != 0 &&
                    strncasecmp(kw_check, "INNER", 5) != 0 &&
                    strncasecmp(kw_check, "LEFT", 4) != 0 &&
                    strncasecmp(kw_check, "RIGHT", 5) != 0 &&
                    strncasecmp(kw_check, "CROSS", 5) != 0 &&
                    strncasecmp(kw_check, "FULL", 4) != 0 &&
                    strncasecmp(kw_check, "JOIN", 4) != 0 &&
                    strncasecmp(kw_check, "UNION", 5) != 0 &&
                    strncasecmp(kw_check, "INTERSECT", 9) != 0 &&
                    strncasecmp(kw_check, "EXCEPT", 6) != 0) {
                    j->table.alias = dup_token(astart, alen);
                    p = astart + alen;
                }
            }
        }

        /* ON condition for non-cross joins */
        p = skip_ws(p);
        if (jt != QIHSE_JOIN_CROSS) {
            const char* on_after = match_kw(p, "ON");
            if (on_after) {
                p = on_after;
                /* parse: col = col  (single equi-condition) */
                size_t l1;
                const char* lk = read_identifier(p, &l1);
                if (l1 > 0) {
                    j->left_key = dup_token(lk, l1);
                    p = lk + l1;
                    p = skip_ws(p);
                    if (*p == '=') {
                        p++;
                        p = skip_ws(p);
                        size_t r1;
                        const char* rk = read_identifier(p, &r1);
                        if (r1 > 0) {
                            j->right_key = dup_token(rk, r1);
                            p = rk + r1;
                        }
                    }
                }
            }
        }
    }
    *pp = p;
}

/* -------------------------------------------------------------------------
 * Parse GROUP BY ... HAVING ...
 * ------------------------------------------------------------------------- */
static void parse_group_by(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = *pp;
    const char* gb = match_kw(p, "GROUP BY");
    if (!gb) return;
    p = gb;
    ast->group_by = (qihse_sql_group_by_t*)calloc(1, sizeof(qihse_sql_group_by_t));
    size_t cap = 4;
    ast->group_by->group_columns = (char**)calloc(cap, sizeof(char*));
    for (;;) {
        size_t id_len;
        const char* id_start = read_identifier(p, &id_len);
        if (id_len == 0) break;
        p = id_start + id_len;
        if (ast->group_by->num_group_columns >= cap) {
            cap *= 2;
            ast->group_by->group_columns = (char**)realloc(ast->group_by->group_columns, cap * sizeof(char*));
        }
        ast->group_by->group_columns[ast->group_by->num_group_columns++] = dup_token(id_start, id_len);
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        break;
    }
    /* HAVING */
    p = skip_ws(p);
    const char* hv = match_kw(p, "HAVING");
    if (hv) {
        p = hv;
        const char* hstart = p;
        /* HAVING extends until ORDER BY / LIMIT / OFFSET / end */
        const char* hend = hstart;
        while (*hend) {
            if (strncasecmp(hend, "ORDER BY", 8) == 0 || strncasecmp(hend, "LIMIT", 5) == 0 ||
                strncasecmp(hend, "OFFSET", 6) == 0) break;
            hend++;
        }
        ast->group_by->having_expr = dup_range(hstart, hend);
        p = hend;
    }
    *pp = p;
}

/* -------------------------------------------------------------------------
 * Parse ORDER BY
 * ------------------------------------------------------------------------- */
static void parse_order_by(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = *pp;
    const char* ob = match_kw(p, "ORDER BY");
    if (!ob) return;
    p = ob;
    size_t cap = 4;
    ast->order_items = (qihse_sql_order_item_t*)calloc(cap, sizeof(qihse_sql_order_item_t));
    ast->num_order_items = 0;
    for (;;) {
        size_t id_len;
        const char* id_start = read_identifier(p, &id_len);
        if (id_len == 0) break;
        p = id_start + id_len;
        if (ast->num_order_items >= cap) {
            cap *= 2;
            ast->order_items = (qihse_sql_order_item_t*)realloc(ast->order_items, cap * sizeof(qihse_sql_order_item_t));
        }
        qihse_sql_order_item_t* oi = &ast->order_items[ast->num_order_items++];
        memset(oi, 0, sizeof(*oi));
        oi->column_name = dup_token(id_start, id_len);
        oi->ascending = 1;
        p = skip_ws(p);
        if (strncasecmp(p, "ASC", 3) == 0 && !isalnum((unsigned char)p[3])) { oi->ascending = 1; p += 3; }
        else if (strncasecmp(p, "DESC", 4) == 0 && !isalnum((unsigned char)p[4])) { oi->ascending = 0; p += 4; }
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        break;
    }
    *pp = p;
}

/* -------------------------------------------------------------------------
 * Parse LIMIT / OFFSET
 * ------------------------------------------------------------------------- */
static void parse_limit_offset(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = *pp;
    p = skip_ws(p);
    const char* lim = match_kw(p, "LIMIT");
    if (lim) {
        p = lim;
        p = skip_ws(p);
        ast->limit = (int)strtol(p, (char**)&p, 10);
    }
    p = skip_ws(p);
    const char* off = match_kw(p, "OFFSET");
    if (off) {
        p = off;
        p = skip_ws(p);
        ast->offset = (int)strtol(p, (char**)&p, 10);
    }
    *pp = p;
}

/* -------------------------------------------------------------------------
 * Parse SELECT statement (and set operations)
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_select(const char** pp) {
    const char* p = *pp;
    qihse_sql_ast_t* ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
    if (!ast) return NULL;
    ast->limit = -1;
    ast->offset = -1;
    ast->stmt_type = QIHSE_SQL_SELECT;

    /* SELECT [DISTINCT|ALL] */
    const char* after = match_kw(p, "SELECT");
    if (!after) { free(ast); return NULL; }
    p = after;
    p = skip_ws(p);
    if (strncasecmp(p, "DISTINCT", 8) == 0 && !isalnum((unsigned char)p[8])) {
        ast->select_distinct = 1;
        p += 8;
    } else if (strncasecmp(p, "ALL", 3) == 0 && !isalnum((unsigned char)p[3])) {
        p += 3;
    }

    /* SELECT list — collect until FROM (respecting parens) */
    size_t item_cap = 8;
    ast->select_items = (qihse_sql_select_item_t*)calloc(item_cap, sizeof(qihse_sql_select_item_t));
    ast->num_select_items = 0;
    for (;;) {
        p = skip_ws(p);
        const char* start = p;
        int paren_depth = 0;
        while (*p) {
            if (*p == '(') paren_depth++;
            else if (*p == ')') { if (paren_depth == 0) break; paren_depth--; }
            else if (paren_depth == 0 && *p == ',') break;
            else if (paren_depth == 0 && strncasecmp(p, " FROM", 5) == 0) break;
            else if (paren_depth == 0 && strncasecmp(p, "\tFROM", 5) == 0) break;
            else if (paren_depth == 0 && strncasecmp(p, "\nFROM", 5) == 0) break;
            p++;
        }
        size_t len = (size_t)(p - start);
        if (len > 0) {
            /* trim trailing ws */
            while (len > 0 && isspace((unsigned char)start[len-1])) len--;
            if (len > 0) {
                if (ast->num_select_items >= item_cap) {
                    item_cap *= 2;
                    ast->select_items = (qihse_sql_select_item_t*)realloc(ast->select_items, item_cap * sizeof(qihse_sql_select_item_t));
                }
                parse_select_item(start, len, &ast->select_items[ast->num_select_items++]);
            }
        }
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        break;
    }

    /* FROM */
    p = skip_ws(p);
    const char* from_after = match_kw(p, "FROM");
    if (from_after) {
        p = from_after;
        size_t tab_cap = 4;
        ast->from_tables = (qihse_sql_table_ref_t*)calloc(tab_cap, sizeof(qihse_sql_table_ref_t));
        ast->num_from_tables = 0;
        for (;;) {
            size_t id_len;
            const char* id_start = read_identifier(p, &id_len);
            if (id_len == 0) break;
            p = id_start + id_len;
            if (ast->num_from_tables >= tab_cap) {
                tab_cap *= 2;
                ast->from_tables = (qihse_sql_table_ref_t*)realloc(ast->from_tables, tab_cap * sizeof(qihse_sql_table_ref_t));
            }
            qihse_sql_table_ref_t* t = &ast->from_tables[ast->num_from_tables++];
            memset(t, 0, sizeof(*t));
            t->table_name = dup_token(id_start, id_len);
            t->alias = NULL;
            /* optional alias */
            p = skip_ws(p);
            const char* as_after2 = match_kw(p, "AS");
            if (as_after2) {
                p = as_after2;
                size_t alen;
                const char* astart = read_identifier(p, &alen);
                if (alen > 0) { t->alias = dup_token(astart, alen); p = astart + alen; }
            } else {
                size_t alen;
                const char* astart = read_identifier(p, &alen);
                if (alen > 0) {
                    const char* kw = p;
                    if (strncasecmp(kw, "WHERE", 5) != 0 && strncasecmp(kw, "GROUP", 5) != 0 &&
                        strncasecmp(kw, "ORDER", 5) != 0 && strncasecmp(kw, "LIMIT", 5) != 0 &&
                        strncasecmp(kw, "OFFSET", 6) != 0 && strncasecmp(kw, "HAVING", 6) != 0 &&
                        strncasecmp(kw, "INNER", 5) != 0 && strncasecmp(kw, "LEFT", 4) != 0 &&
                        strncasecmp(kw, "RIGHT", 5) != 0 && strncasecmp(kw, "CROSS", 5) != 0 &&
                        strncasecmp(kw, "FULL", 4) != 0 && strncasecmp(kw, "JOIN", 4) != 0 &&
                        strncasecmp(kw, "UNION", 5) != 0 && strncasecmp(kw, "INTERSECT", 9) != 0 &&
                        strncasecmp(kw, "EXCEPT", 6) != 0 && strncasecmp(kw, "ON", 2) != 0) {
                        t->alias = dup_token(astart, alen);
                        p = astart + alen;
                    }
                }
            }
            p = skip_ws(p);
            if (*p == ',') { p++; continue; }
            break;
        }

        /* JOINs */
        parse_joins(&p, ast);
    }

    /* WHERE */
    p = skip_ws(p);
    const char* where_after = match_kw(p, "WHERE");
    if (where_after) {
        p = where_after;
        parse_where(&p, ast);
    }

    /* GROUP BY / HAVING */
    parse_group_by(&p, ast);

    /* ORDER BY */
    parse_order_by(&p, ast);

    /* LIMIT / OFFSET */
    parse_limit_offset(&p, ast);

    /* Set operations: UNION / INTERSECT / EXCEPT */
    p = skip_ws(p);
    const char* set_after = NULL;
    qihse_sql_set_op_t sop = QIHSE_SET_NONE;
    if ((set_after = match_kw(p, "UNION"))) {
        sop = QIHSE_SET_UNION;
        p = set_after;
        const char* all_after = match_kw(p, "ALL");
        if (all_after) { sop = QIHSE_SET_UNION_ALL; p = all_after; }
    } else if ((set_after = match_kw(p, "INTERSECT"))) {
        sop = QIHSE_SET_INTERSECT;
        p = set_after;
    } else if ((set_after = match_kw(p, "EXCEPT"))) {
        sop = QIHSE_SET_EXCEPT;
        p = set_after;
    }
    if (sop != QIHSE_SET_NONE) {
        qihse_sql_ast_t* right = parse_select(&p);
        if (right) {
            /* wrap: current ast becomes left operand */
            qihse_sql_ast_t* wrapper = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
            wrapper->stmt_type = QIHSE_SQL_SELECT;
            wrapper->set_op = sop;
            wrapper->set_left = ast;
            wrapper->set_right = right;
            wrapper->limit = -1;
            wrapper->offset = -1;
            ast = wrapper;
        }
    }

    *pp = p;
    return ast;
}

/* -------------------------------------------------------------------------
 * Parse CREATE TABLE / CREATE INDEX
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_create(const char** pp) {
    const char* p = *pp;
    qihse_sql_ast_t* ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
    ast->limit = -1; ast->offset = -1;
    ast->stmt_type = QIHSE_SQL_CREATE;

    /* CREATE [UNIQUE] INDEX name ON table (col) */
    p = skip_ws(p);
    int unique = 0;
    const char* u_after = match_kw(p, "UNIQUE");
    if (u_after) { unique = 1; p = u_after; }
    const char* idx_after = match_kw(p, "INDEX");
    if (idx_after) {
        p = idx_after;
        size_t id_len;
        const char* id_start = read_identifier(p, &id_len);
        char* idx_name = dup_token(id_start, id_len);
        p = id_start + id_len;
        const char* on_after = match_kw(p, "ON");
        if (on_after) {
            p = on_after;
            size_t tlen;
            const char* tstart = read_identifier(p, &tlen);
            char* tbl = dup_token(tstart, tlen);
            p = tstart + tlen;
            p = skip_ws(p);
            char* col = NULL;
            if (*p == '(') {
                p++;
                size_t clen;
                const char* cstart = read_identifier(p, &clen);
                col = dup_token(cstart, clen);
                p = cstart + clen;
                p = skip_ws(p);
                if (*p == ')') p++;
            }
            ast->index_def = (qihse_sql_index_def_t*)calloc(1, sizeof(qihse_sql_index_def_t));
            ast->index_def->name = idx_name;
            ast->index_def->table_name = tbl;
            ast->index_def->column_name = col;
            ast->index_def->unique = unique;
        } else {
            free(idx_name);
        }
        *pp = p;
        return ast;
    }

    /* CREATE TABLE name ( col defs ) */
    const char* tbl_after = match_kw(p, "TABLE");
    if (!tbl_after) { ast->stmt_type = QIHSE_SQL_UNKNOWN; *pp = p; return ast; }
    p = tbl_after;
    size_t id_len;
    const char* id_start = read_identifier(p, &id_len);
    ast->table_name = dup_token(id_start, id_len);
    p = id_start + id_len;
    p = skip_ws(p);
    if (*p == '(') {
        p++;
        size_t col_cap = 8;
        ast->columns = (qihse_sql_column_def_t*)calloc(col_cap, sizeof(qihse_sql_column_def_t));
        ast->num_columns = 0;
        for (;;) {
            p = skip_ws(p);
            if (*p == ')') { p++; break; }
            /* find next comma at depth 0 */
            const char* seg_start = p;
            int depth = 0;
            while (*p) {
                if (*p == '(') depth++;
                else if (*p == ')') { if (depth == 0) break; depth--; }
                else if (depth == 0 && *p == ',') break;
                p++;
            }
            size_t seg_len = (size_t)(p - seg_start);
            /* trim */
            while (seg_len > 0 && isspace((unsigned char)seg_start[seg_len-1])) seg_len--;
            /* skip table-level constraints */
            char tmp[24];
            size_t cl = seg_len < sizeof(tmp)-1 ? seg_len : sizeof(tmp)-1;
            memcpy(tmp, seg_start, cl); tmp[cl] = '\0';
            if (strncasecmp(tmp, "PRIMARY KEY", 11) == 0 || strncasecmp(tmp, "FOREIGN KEY", 11) == 0 ||
                strncasecmp(tmp, "CONSTRAINT", 9) == 0 || strncasecmp(tmp, "UNIQUE", 6) == 0) {
                /* skip */
            } else if (seg_len > 0) {
                if (ast->num_columns >= col_cap) {
                    col_cap *= 2;
                    ast->columns = (qihse_sql_column_def_t*)realloc(ast->columns, col_cap * sizeof(qihse_sql_column_def_t));
                }
                char* seg_copy = dup_token(seg_start, seg_len);
                parse_column_def(seg_copy, &ast->columns[ast->num_columns++]);
                free(seg_copy);
            }
            p = skip_ws(p);
            if (*p == ',') { p++; continue; }
            if (*p == ')') { p++; break; }
            break;
        }
    }
    *pp = p;
    return ast;
}

/* -------------------------------------------------------------------------
 * Parse ALTER TABLE
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_alter(const char** pp) {
    const char* p = *pp;
    qihse_sql_ast_t* ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
    ast->limit = -1; ast->offset = -1;
    ast->stmt_type = QIHSE_SQL_ALTER;

    const char* tbl_after = match_kw(p, "TABLE");
    if (!tbl_after) { ast->stmt_type = QIHSE_SQL_UNKNOWN; *pp = p; return ast; }
    p = tbl_after;
    size_t id_len;
    const char* id_start = read_identifier(p, &id_len);
    ast->table_name = dup_token(id_start, id_len);
    p = id_start + id_len;

    ast->alter_clause = (qihse_sql_alter_clause_t*)calloc(1, sizeof(qihse_sql_alter_clause_t));
    p = skip_ws(p);
    const char* add_after = match_kw(p, "ADD");
    const char* drop_after = match_kw(p, "DROP");
    const char* ren_after = match_kw(p, "RENAME");
    if (add_after) {
        p = add_after;
        const char* col_after = match_kw(p, "COLUMN");
        if (col_after) p = col_after;
        /* parse rest as a column def */
        const char* seg_start = p;
        while (*p && *p != ';' && *p != ',') p++;
        char* seg = dup_range(seg_start, p);
        ast->alter_clause->action = QIHSE_ALTER_ADD_COLUMN;
        ast->alter_clause->add_column = (qihse_sql_column_def_t*)calloc(1, sizeof(qihse_sql_column_def_t));
        parse_column_def(seg, ast->alter_clause->add_column);
        free(seg);
    } else if (drop_after) {
        p = drop_after;
        const char* col_after = match_kw(p, "COLUMN");
        if (col_after) p = col_after;
        size_t clen;
        const char* cstart = read_identifier(p, &clen);
        ast->alter_clause->action = QIHSE_ALTER_DROP_COLUMN;
        ast->alter_clause->column_name = dup_token(cstart, clen);
        p = cstart + clen;
    } else if (ren_after) {
        p = ren_after;
        const char* col_after = match_kw(p, "COLUMN");
        const char* tbl_kw = match_kw(p, "TO");
        if (col_after) {
            p = col_after;
            size_t clen;
            const char* cstart = read_identifier(p, &clen);
            ast->alter_clause->column_name = dup_token(cstart, clen);
            p = cstart + clen;
            const char* to_after = match_kw(p, "TO");
            if (to_after) {
                p = to_after;
                size_t nlen;
                const char* nstart = read_identifier(p, &nlen);
                ast->alter_clause->action = QIHSE_ALTER_RENAME_COLUMN;
                ast->alter_clause->new_name = dup_token(nstart, nlen);
                p = nstart + nlen;
            }
        } else if (tbl_kw) {
            p = tbl_kw;
            size_t nlen;
            const char* nstart = read_identifier(p, &nlen);
            ast->alter_clause->action = QIHSE_ALTER_RENAME_TABLE;
            ast->alter_clause->new_name = dup_token(nstart, nlen);
            p = nstart + nlen;
        } else {
            /* RENAME TO newname or RENAME col TO newcol */
            size_t clen;
            const char* cstart = read_identifier(p, &clen);
            ast->alter_clause->column_name = dup_token(cstart, clen);
            p = cstart + clen;
            const char* to_after = match_kw(p, "TO");
            if (to_after) {
                p = to_after;
                size_t nlen;
                const char* nstart = read_identifier(p, &nlen);
                ast->alter_clause->new_name = dup_token(nstart, nlen);
                p = nstart + nlen;
                /* if column_name equals table_name-ish, treat as table rename */
                ast->alter_clause->action = QIHSE_ALTER_RENAME_TABLE;
            }
        }
    }
    *pp = p;
    return ast;
}

/* -------------------------------------------------------------------------
 * Parse DROP TABLE / DROP INDEX
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_drop(const char** pp) {
    const char* p = *pp;
    qihse_sql_ast_t* ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
    ast->limit = -1; ast->offset = -1;
    ast->stmt_type = QIHSE_SQL_DROP;

    const char* idx_after = match_kw(p, "INDEX");
    const char* tbl_after = match_kw(p, "TABLE");
    if (idx_after) {
        p = idx_after;
        ast->drop_is_index = 1;
    } else if (tbl_after) {
        p = tbl_after;
        ast->drop_is_index = 0;
    }
    p = skip_ws(p);
    size_t id_len;
    const char* id_start = read_identifier(p, &id_len);
    ast->drop_name = dup_token(id_start, id_len);
    p = id_start + id_len;
    *pp = p;
    return ast;
}

/* -------------------------------------------------------------------------
 * Parse a single statement (top-level dispatch)
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_statement(const char* sql) {
    if (!sql || !*sql) return NULL;
    char* work = strdup(sql);
    if (!work) return NULL;
    const char* p = trim_str(work);

    qihse_sql_ast_t* ast = NULL;
    const char* cur = p;

    if (strncasecmp(cur, "SELECT", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = parse_select(&cur);
    } else if (strncasecmp(cur, "INSERT", 6) == 0) {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_INSERT;
        ast->limit = -1; ast->offset = -1;
    } else if (strncasecmp(cur, "UPDATE", 6) == 0) {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_UPDATE;
        ast->limit = -1; ast->offset = -1;
    } else if (strncasecmp(cur, "DELETE", 6) == 0) {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_DELETE;
        ast->limit = -1; ast->offset = -1;
    } else if (strncasecmp(cur, "CREATE", 6) == 0) {
        cur += 6;
        ast = parse_create(&cur);
    } else if (strncasecmp(cur, "ALTER", 5) == 0) {
        cur += 5;
        ast = parse_alter(&cur);
    } else if (strncasecmp(cur, "DROP", 4) == 0) {
        cur += 4;
        ast = parse_drop(&cur);
    } else {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_UNKNOWN;
        ast->limit = -1; ast->offset = -1;
    }

    free(work);
    if (ast && !ast->raw_sql) ast->raw_sql = strdup(sql);
    return ast;
}

qihse_sql_ast_t* qihse_parse_sql_to_ast(const char* sql) {
    return parse_statement(sql);
}

/* -------------------------------------------------------------------------
 * Free
 * ------------------------------------------------------------------------- */
static void free_column_def(qihse_sql_column_def_t* c) {
    if (!c) return;
    free(c->name);
    free(c->default_expr);
}

void qihse_sql_ast_free(qihse_sql_ast_t* ast) {
    if (!ast) return;
    for (size_t i = 0; i < ast->num_select_items; i++) {
        free(ast->select_items[i].expr);
        free(ast->select_items[i].alias);
        free(ast->select_items[i].agg_arg);
        qihse_sql_ast_free(ast->select_items[i].scalar_subquery);
    }
    free(ast->select_items);
    for (size_t i = 0; i < ast->num_from_tables; i++) {
        free(ast->from_tables[i].table_name);
        free(ast->from_tables[i].alias);
    }
    free(ast->from_tables);
    for (size_t i = 0; i < ast->num_joins; i++) {
        free(ast->joins[i].table.table_name);
        free(ast->joins[i].table.alias);
        free(ast->joins[i].left_key);
        free(ast->joins[i].right_key);
        free(ast->joins[i].on_condition);
    }
    free(ast->joins);
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        free(ast->where_conditions[i].column_name);
        free(ast->where_conditions[i].operator);
        free(ast->where_conditions[i].value);
        qihse_sql_ast_free(ast->where_conditions[i].subquery);
    }
    free(ast->where_conditions);
    if (ast->group_by) {
        for (size_t i = 0; i < ast->group_by->num_group_columns; i++)
            free(ast->group_by->group_columns[i]);
        free(ast->group_by->group_columns);
        free(ast->group_by->having_expr);
        free(ast->group_by);
    }
    for (size_t i = 0; i < ast->num_order_items; i++)
        free(ast->order_items[i].column_name);
    free(ast->order_items);
    qihse_sql_ast_free(ast->set_left);
    qihse_sql_ast_free(ast->set_right);
    free(ast->table_name);
    for (size_t i = 0; i < ast->num_columns; i++) free_column_def(&ast->columns[i]);
    free(ast->columns);
    if (ast->index_def) {
        free(ast->index_def->name);
        free(ast->index_def->table_name);
        free(ast->index_def->column_name);
        free(ast->index_def);
    }
    free(ast->drop_name);
    if (ast->alter_clause) {
        free(ast->alter_clause->column_name);
        free(ast->alter_clause->new_name);
        if (ast->alter_clause->add_column) {
            free_column_def(ast->alter_clause->add_column);
            free(ast->alter_clause->add_column);
        }
        free(ast->alter_clause);
    }
    free(ast->raw_sql);
    free(ast);
}

/* -------------------------------------------------------------------------
 * Name helpers
 * ------------------------------------------------------------------------- */
const char* qihse_sql_type_name(qihse_sql_type_t t) {
    switch (t) {
        case QIHSE_TYPE_INT:       return "INT";
        case QIHSE_TYPE_BIGINT:    return "BIGINT";
        case QIHSE_TYPE_FLOAT:     return "FLOAT";
        case QIHSE_TYPE_DOUBLE:    return "DOUBLE";
        case QIHSE_TYPE_VARCHAR:   return "VARCHAR";
        case QIHSE_TYPE_TEXT:      return "TEXT";
        case QIHSE_TYPE_BOOL:      return "BOOL";
        case QIHSE_TYPE_TIMESTAMP: return "TIMESTAMP";
        case QIHSE_TYPE_VECTOR:    return "VECTOR";
        default: return "UNKNOWN";
    }
}

const char* qihse_sql_join_type_name(qihse_sql_join_type_t j) {
    switch (j) {
        case QIHSE_JOIN_INNER: return "INNER";
        case QIHSE_JOIN_LEFT:  return "LEFT";
        case QIHSE_JOIN_RIGHT: return "RIGHT";
        case QIHSE_JOIN_CROSS: return "CROSS";
        case QIHSE_JOIN_FULL:  return "FULL";
        default: return "NONE";
    }
}

const char* qihse_sql_agg_name(qihse_sql_agg_kind_t a) {
    switch (a) {
        case QIHSE_AGG_SUM:        return "SUM";
        case QIHSE_AGG_COUNT:      return "COUNT";
        case QIHSE_AGG_AVG:        return "AVG";
        case QIHSE_AGG_MIN:        return "MIN";
        case QIHSE_AGG_MAX:        return "MAX";
        case QIHSE_AGG_COUNT_STAR: return "COUNT(*)";
        default: return "NONE";
    }
}
