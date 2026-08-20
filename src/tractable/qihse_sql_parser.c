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

static const char* read_value(const char* p, size_t* out_len, int* is_string, const char** after) {
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
    if (after) *after = p;
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
    } else if (*p == '~' || *p == '|' ) {
        /* PostgreSQL regex / concatenation operators: ~ ~* !~ !~* || */
        p++;
        if (*p == '*') p++;
        *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "LIKE", 4) == 0 && !isalnum((unsigned char)p[4])) {
        p += 4; *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "ILIKE", 5) == 0 && !isalnum((unsigned char)p[5])) {
        p += 5; *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "IN", 2) == 0 && !isalnum((unsigned char)p[2]) && p[2] != '_') {
        p += 2; *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "IS", 2) == 0 && !isalnum((unsigned char)p[2]) && p[2] != '_') {
        p += 2; *out_len = (size_t)(p - start);
    } else if (strncasecmp(p, "BETWEEN", 7) == 0 && !isalnum((unsigned char)p[7])) {
        p += 7; *out_len = (size_t)(p - start);
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
    if (strcmp(tmp, "STRING_AGG") == 0) return QIHSE_AGG_STRING_AGG;
    if (strcmp(tmp, "ARRAY_AGG") == 0) return QIHSE_AGG_ARRAY_AGG;
    if (strcmp(tmp, "BOOL_OR") == 0) return QIHSE_AGG_BOOL_OR;
    if (strcmp(tmp, "BOOL_AND") == 0) return QIHSE_AGG_BOOL_AND;
    if (strcmp(tmp, "EVERY") == 0) return QIHSE_AGG_EVERY;
    if (strcmp(tmp, "VARIANCE") == 0 || strcmp(tmp, "VAR_SAMP") == 0) return QIHSE_AGG_VARIANCE;
    if (strcmp(tmp, "STDDEV") == 0 || strcmp(tmp, "STDDEV_SAMP") == 0) return QIHSE_AGG_STDDEV;
    if (strcmp(tmp, "CORR") == 0) return QIHSE_AGG_CORR;
    if (strcmp(tmp, "COVAR_SAMP") == 0) return QIHSE_AGG_COVAR_SAMP;
    if (strcmp(tmp, "COVAR_POP") == 0) return QIHSE_AGG_COVAR_POP;
    (void)arg_start; (void)arg_len;
    return QIHSE_AGG_NONE;
}

/* -------------------------------------------------------------------------
 * Window function detection from a function name token
 * ------------------------------------------------------------------------- */
static qihse_sql_win_kind_t detect_window(const char* expr, size_t len) {
    char tmp[24];
    if (len >= sizeof(tmp)) return QIHSE_WIN_NONE;
    memcpy(tmp, expr, len);
    tmp[len] = '\0';
    for (size_t i = 0; i < len; i++) tmp[i] = (char)toupper((unsigned char)tmp[i]);
    if (strcmp(tmp, "ROW_NUMBER") == 0) return QIHSE_WIN_ROW_NUMBER;
    if (strcmp(tmp, "RANK") == 0) return QIHSE_WIN_RANK;
    if (strcmp(tmp, "DENSE_RANK") == 0) return QIHSE_WIN_DENSE_RANK;
    if (strcmp(tmp, "LAG") == 0) return QIHSE_WIN_LAG;
    if (strcmp(tmp, "LEAD") == 0) return QIHSE_WIN_LEAD;
    if (strcmp(tmp, "FIRST_VALUE") == 0) return QIHSE_WIN_FIRST_VALUE;
    if (strcmp(tmp, "LAST_VALUE") == 0) return QIHSE_WIN_LAST_VALUE;
    if (strcmp(tmp, "NTH_VALUE") == 0) return QIHSE_WIN_NTH_VALUE;
    if (strcmp(tmp, "NTILE") == 0) return QIHSE_WIN_NTILE;
    if (strcmp(tmp, "PERCENT_RANK") == 0) return QIHSE_WIN_PERCENT_RANK;
    if (strcmp(tmp, "CUME_DIST") == 0) return QIHSE_WIN_CUME_DIST;
    return QIHSE_WIN_NONE;
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
                /* check for OVER clause (aggregate used as window) */
                const char* over_p = close + 1;
                over_p = skip_ws(over_p);
                if (strncasecmp(over_p, "OVER", 4) == 0 && !isalnum((unsigned char)over_p[4])) {
                    over_p += 4;
                    over_p = skip_ws(over_p);
                    if (*over_p == '(') {
                        const char* ov_close = find_matching_paren(over_p);
                        if (ov_close) {
                            item->window = (qihse_sql_window_spec_t*)calloc(1, sizeof(qihse_sql_window_spec_t));
                            over_p = ov_close + 1;
                        }
                    }
                }
                free(buf);
                return;
            }
            /* window function (non-aggregate) followed by OVER */
            qihse_sql_win_kind_t wk = detect_window(fname, fname_len);
            if (wk != QIHSE_WIN_NONE) {
                item->win_kind = wk;
                if ((size_t)(arg_e - arg_s) == 1 && arg_s[0] == '*') {
                    item->win_arg = strdup("*");
                } else {
                    item->win_arg = dup_range(arg_s, arg_e);
                }
                item->expr = dup_range(fname, close + 1);
                const char* over_p = close + 1;
                over_p = skip_ws(over_p);
                if (strncasecmp(over_p, "OVER", 4) == 0 && !isalnum((unsigned char)over_p[4])) {
                    over_p += 4;
                    over_p = skip_ws(over_p);
                    if (*over_p == '(') {
                        const char* ov_close = find_matching_paren(over_p);
                        if (ov_close) {
                            item->window = (qihse_sql_window_spec_t*)calloc(1, sizeof(qihse_sql_window_spec_t));
                            over_p = ov_close + 1;
                        }
                    }
                }
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
        if (strncasecmp(p, "UNIQUE", 6) == 0 && !isalnum((unsigned char)p[6])) { col->is_unique = 1; p += 6; continue; }
        if (strncasecmp(p, "DEFAULT", 7) == 0) {
            p += 7;
            p = skip_ws(p);
            const char* dstart = p;
            while (*p && *p != ',' && strncasecmp(p, " NOT", 4) != 0 &&
                   strncasecmp(p, " PRIMARY", 8) != 0 && strncasecmp(p, " UNIQUE", 7) != 0 &&
                   strncasecmp(p, " CHECK", 6) != 0 && strncasecmp(p, " REFERENCES", 11) != 0) p++;
            col->default_expr = dup_range(dstart, p);
            continue;
        }
        if (strncasecmp(p, "CHECK", 5) == 0 && !isalnum((unsigned char)p[5])) {
            p += 5;
            p = skip_ws(p);
            if (*p == '(') {
                const char* close = find_matching_paren(p);
                if (close) { col->check_expr = dup_range(p, close + 1); p = close + 1; continue; }
            }
            continue;
        }
        if (strncasecmp(p, "REFERENCES", 10) == 0 && !isalnum((unsigned char)p[10])) {
            p += 10;
            p = skip_ws(p);
            size_t rlen;
            const char* rstart = read_identifier(p, &rlen);
            if (rlen > 0) {
                qihse_sql_fk_t* fk = (qihse_sql_fk_t*)calloc(1, sizeof(qihse_sql_fk_t));
                fk->ref_table = dup_token(rstart, rlen);
                fk->on_delete = QIHSE_FK_NO_ACTION;
                fk->on_update = QIHSE_FK_NO_ACTION;
                p = rstart + rlen;
                p = skip_ws(p);
                if (*p == '(') {
                    const char* close = find_matching_paren(p);
                    if (close) {
                        const char* inner = p + 1;
                        size_t ilen = (size_t)(close - inner);
                        char* icopy = dup_token(inner, ilen);
                        const char* ip = icopy;
                        size_t cap = 0;
                        for (;;) {
                            ip = skip_ws(ip);
                            size_t clen;
                            const char* cstart = read_identifier(ip, &clen);
                            if (clen == 0) break;
                            if (fk->num_ref_columns >= cap) { cap = cap ? cap*2 : 4;
                                fk->ref_columns = (char**)realloc(fk->ref_columns, cap*sizeof(char*)); }
                            fk->ref_columns[fk->num_ref_columns++] = dup_token(cstart, clen);
                            ip = cstart + clen;
                            ip = skip_ws(ip);
                            if (*ip == ',') { ip++; continue; }
                            break;
                        }
                        free(icopy);
                        p = close + 1;
                    }
                }
                /* ON DELETE / ON UPDATE */
                for (;;) {
                    p = skip_ws(p);
                    const char* on_del = match_kw(p, "ON DELETE");
                    const char* on_upd = match_kw(p, "ON UPDATE");
                    if (on_del) {
                        p = on_del;
                        const char* casc = match_kw(p, "CASCADE");
                        const char* setn = match_kw(p, "SET NULL");
                        const char* rest = match_kw(p, "RESTRICT");
                        const char* noa = match_kw(p, "NO ACTION");
                        if (casc) { p = casc; fk->on_delete = QIHSE_FK_CASCADE; continue; }
                        if (setn) { p = setn; fk->on_delete = QIHSE_FK_SET_NULL; continue; }
                        if (rest) { p = rest; fk->on_delete = QIHSE_FK_RESTRICT; continue; }
                        if (noa) { p = noa; fk->on_delete = QIHSE_FK_NO_ACTION; continue; }
                        break;
                    }
                    if (on_upd) {
                        p = on_upd;
                        const char* casc = match_kw(p, "CASCADE");
                        const char* setn = match_kw(p, "SET NULL");
                        const char* rest = match_kw(p, "RESTRICT");
                        const char* noa = match_kw(p, "NO ACTION");
                        if (casc) { p = casc; fk->on_update = QIHSE_FK_CASCADE; continue; }
                        if (setn) { p = setn; fk->on_update = QIHSE_FK_SET_NULL; continue; }
                        if (rest) { p = rest; fk->on_update = QIHSE_FK_RESTRICT; continue; }
                        if (noa) { p = noa; fk->on_update = QIHSE_FK_NO_ACTION; continue; }
                        break;
                    }
                    break;
                }
                col->fk = fk;
                continue;
            }
        }
        break;
    }
}

/* -------------------------------------------------------------------------
 * Parse a table-level constraint segment into the AST's constraint arrays.
 * Returns 1 if the segment was a table-level constraint, 0 otherwise.
 * ------------------------------------------------------------------------- */
static int parse_table_constraint(const char* seg, size_t seg_len, qihse_sql_ast_t* ast) {
    const char* p = skip_ws(seg);
    const char* end = seg + seg_len;
    (void)end;
    char* name = NULL;
    /* optional CONSTRAINT name */
    const char* c_after = match_kw(p, "CONSTRAINT");
    if (c_after) {
        p = c_after;
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { name = dup_token(nstart, nlen); p = nstart + nlen; }
        p = skip_ws(p);
    }

    /* PRIMARY KEY (cols) */
    const char* pk_after = match_kw(p, "PRIMARY KEY");
    if (pk_after) {
        p = pk_after;
        p = skip_ws(p);
        if (*p == '(') {
            const char* close = find_matching_paren(p);
            if (close) {
                const char* inner = p + 1;
                size_t ilen = (size_t)(close - inner);
                char* icopy = dup_token(inner, ilen);
                /* reuse unique array slot for PK (mark via name) */
                size_t idx = ast->num_uniques;
                ast->uniques = (qihse_sql_unique_t*)realloc(ast->uniques, (idx+1)*sizeof(qihse_sql_unique_t));
                memset(&ast->uniques[idx], 0, sizeof(qihse_sql_unique_t));
                ast->uniques[idx].name = name ? name : strdup("PRIMARY");
                size_t cap = 0;
                const char* ip = icopy;
                for (;;) {
                    ip = skip_ws(ip);
                    size_t clen;
                    const char* cstart = read_identifier(ip, &clen);
                    if (clen == 0) break;
                    if (ast->uniques[idx].num_columns >= cap) { cap = cap?cap*2:4;
                        ast->uniques[idx].columns = (char**)realloc(ast->uniques[idx].columns, cap*sizeof(char*)); }
                    ast->uniques[idx].columns[ast->uniques[idx].num_columns++] = dup_token(cstart, clen);
                    ip = cstart + clen;
                    ip = skip_ws(ip);
                    if (*ip == ',') { ip++; continue; }
                    break;
                }
                free(icopy);
                ast->num_uniques++;
                /* also mark columns as PK */
                for (size_t k = 0; k < ast->uniques[idx].num_columns; k++) {
                    for (size_t c = 0; c < ast->num_columns; c++) {
                        if (ast->columns[c].name && strcasecmp(ast->columns[c].name, ast->uniques[idx].columns[k]) == 0)
                            ast->columns[c].is_primary_key = 1;
                    }
                }
                p = close + 1;
            }
        }
        return 1;
    }

    /* UNIQUE (cols) */
    const char* u_after = match_kw(p, "UNIQUE");
    if (u_after) {
        p = u_after;
        p = skip_ws(p);
        if (*p == '(') {
            const char* close = find_matching_paren(p);
            if (close) {
                const char* inner = p + 1;
                size_t ilen = (size_t)(close - inner);
                char* icopy = dup_token(inner, ilen);
                size_t idx = ast->num_uniques;
                ast->uniques = (qihse_sql_unique_t*)realloc(ast->uniques, (idx+1)*sizeof(qihse_sql_unique_t));
                memset(&ast->uniques[idx], 0, sizeof(qihse_sql_unique_t));
                ast->uniques[idx].name = name ? name : strdup("UNIQUE");
                size_t cap = 0;
                const char* ip = icopy;
                for (;;) {
                    ip = skip_ws(ip);
                    size_t clen;
                    const char* cstart = read_identifier(ip, &clen);
                    if (clen == 0) break;
                    if (ast->uniques[idx].num_columns >= cap) { cap = cap?cap*2:4;
                        ast->uniques[idx].columns = (char**)realloc(ast->uniques[idx].columns, cap*sizeof(char*)); }
                    ast->uniques[idx].columns[ast->uniques[idx].num_columns++] = dup_token(cstart, clen);
                    ip = cstart + clen;
                    ip = skip_ws(ip);
                    if (*ip == ',') { ip++; continue; }
                    break;
                }
                free(icopy);
                ast->num_uniques++;
                p = close + 1;
            }
        }
        return 1;
    }

    /* CHECK (expr) */
    const char* ck_after = match_kw(p, "CHECK");
    if (ck_after) {
        p = ck_after;
        p = skip_ws(p);
        if (*p == '(') {
            const char* close = find_matching_paren(p);
            if (close) {
                size_t idx = ast->num_checks;
                ast->checks = (qihse_sql_check_t*)realloc(ast->checks, (idx+1)*sizeof(qihse_sql_check_t));
                memset(&ast->checks[idx], 0, sizeof(qihse_sql_check_t));
                ast->checks[idx].name = name;
                ast->checks[idx].expr = dup_range(p, close + 1);
                ast->num_checks++;
                p = close + 1;
                return 1;
            }
        }
        free(name);
        return 1;
    }

    /* FOREIGN KEY (cols) REFERENCES table(cols) [ON DELETE ...] [ON UPDATE ...] */
    const char* fk_after = match_kw(p, "FOREIGN KEY");
    if (fk_after) {
        p = fk_after;
        p = skip_ws(p);
        qihse_sql_fk_t* fk = (qihse_sql_fk_t*)calloc(1, sizeof(qihse_sql_fk_t));
        fk->on_delete = QIHSE_FK_NO_ACTION;
        fk->on_update = QIHSE_FK_NO_ACTION;
        if (*p == '(') {
            const char* close = find_matching_paren(p);
            if (close) {
                const char* inner = p + 1;
                size_t ilen = (size_t)(close - inner);
                char* icopy = dup_token(inner, ilen);
                const char* ip = icopy;
                size_t cap = 0;
                for (;;) {
                    ip = skip_ws(ip);
                    size_t clen;
                    const char* cstart = read_identifier(ip, &clen);
                    if (clen == 0) break;
                    if (fk->num_columns >= cap) { cap = cap?cap*2:4;
                        fk->columns = (char**)realloc(fk->columns, cap*sizeof(char*)); }
                    fk->columns[fk->num_columns++] = dup_token(cstart, clen);
                    ip = cstart + clen;
                    ip = skip_ws(ip);
                    if (*ip == ',') { ip++; continue; }
                    break;
                }
                free(icopy);
                p = close + 1;
            }
        }
        const char* ref_after = match_kw(p, "REFERENCES");
        if (ref_after) {
            p = ref_after;
            p = skip_ws(p);
            size_t rlen;
            const char* rstart = read_identifier(p, &rlen);
            if (rlen > 0) { fk->ref_table = dup_token(rstart, rlen); p = rstart + rlen; }
            p = skip_ws(p);
            if (*p == '(') {
                const char* close = find_matching_paren(p);
                if (close) {
                    const char* inner = p + 1;
                    size_t ilen = (size_t)(close - inner);
                    char* icopy = dup_token(inner, ilen);
                    const char* ip = icopy;
                    size_t cap = 0;
                    for (;;) {
                        ip = skip_ws(ip);
                        size_t clen;
                        const char* cstart = read_identifier(ip, &clen);
                        if (clen == 0) break;
                        if (fk->num_ref_columns >= cap) { cap = cap?cap*2:4;
                            fk->ref_columns = (char**)realloc(fk->ref_columns, cap*sizeof(char*)); }
                        fk->ref_columns[fk->num_ref_columns++] = dup_token(cstart, clen);
                        ip = cstart + clen;
                        ip = skip_ws(ip);
                        if (*ip == ',') { ip++; continue; }
                        break;
                    }
                    free(icopy);
                    p = close + 1;
                }
            }
        }
        /* ON DELETE / ON UPDATE */
        for (;;) {
            p = skip_ws(p);
            const char* on_del = match_kw(p, "ON DELETE");
            const char* on_upd = match_kw(p, "ON UPDATE");
            if (on_del) {
                p = on_del;
                const char* casc = match_kw(p, "CASCADE");
                const char* setn = match_kw(p, "SET NULL");
                const char* rest = match_kw(p, "RESTRICT");
                const char* noa = match_kw(p, "NO ACTION");
                if (casc) { p = casc; fk->on_delete = QIHSE_FK_CASCADE; continue; }
                if (setn) { p = setn; fk->on_delete = QIHSE_FK_SET_NULL; continue; }
                if (rest) { p = rest; fk->on_delete = QIHSE_FK_RESTRICT; continue; }
                if (noa) { p = noa; fk->on_delete = QIHSE_FK_NO_ACTION; continue; }
                break;
            }
            if (on_upd) {
                p = on_upd;
                const char* casc = match_kw(p, "CASCADE");
                const char* setn = match_kw(p, "SET NULL");
                const char* rest = match_kw(p, "RESTRICT");
                const char* noa = match_kw(p, "NO ACTION");
                if (casc) { p = casc; fk->on_update = QIHSE_FK_CASCADE; continue; }
                if (setn) { p = setn; fk->on_update = QIHSE_FK_SET_NULL; continue; }
                if (rest) { p = rest; fk->on_update = QIHSE_FK_RESTRICT; continue; }
                if (noa) { p = noa; fk->on_update = QIHSE_FK_NO_ACTION; continue; }
                break;
            }
            break;
        }
        size_t idx = ast->num_fks;
        ast->fks = (qihse_sql_fk_t*)realloc(ast->fks, (idx+1)*sizeof(qihse_sql_fk_t));
        ast->fks[idx] = *fk;
        ast->num_fks++;
        free(fk); /* shallow copy already taken */
        free(name);
        return 1;
    }

    /* EXCLUDE USING ... — acknowledged but not deeply parsed */
    const char* ex_after = match_kw(p, "EXCLUDE");
    if (ex_after) {
        free(name);
        return 1;
    }

    free(name);
    return 0;
}

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_select(const char** pp);
static qihse_sql_ast_t* parse_statement(const char* sql);
static qihse_sql_ast_t* parse_utility(const char** pp, qihse_sql_stmt_type_t type);
static qihse_sql_util_t* util_new(void);

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

            /* detect leading NOT (NOT IN / NOT BETWEEN / NOT LIKE) */
            int negated = 0;
            if (strncasecmp(p, "NOT", 3) == 0 && !isalnum((unsigned char)p[3]) && p[3] != '_') {
                /* but not NOT EXISTS (handled above) — here we're past column */
                const char* after_not = p + 3;
                after_not = skip_ws(after_not);
                if (strncasecmp(after_not, "IN", 2) == 0 ||
                    strncasecmp(after_not, "BETWEEN", 7) == 0 ||
                    strncasecmp(after_not, "LIKE", 4) == 0 ||
                    strncasecmp(after_not, "ILIKE", 5) == 0) {
                    negated = 1;
                    p = after_not;
                }
            }

            /* IN (subquery or value list) */
            if (strncasecmp(p, "IN", 2) == 0 && (p[2] == 0 || isspace((unsigned char)p[2]) || p[2] == '(')) {
                p += 2;
                p = skip_ws(p);
                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                if (*p == '(') {
                    /* peek: subquery if inner starts with SELECT */
                    const char* inner = skip_ws(p + 1);
                    if (strncasecmp(inner, "SELECT", 6) == 0) {
                        qihse_sql_ast_t* sub = parse_paren_subquery(&p);
                        c->operator = strdup(negated ? "NOT IN" : "IN");
                        c->subq_kind = negated ? QIHSE_SUBQ_NOT_IN : QIHSE_SUBQ_IN;
                        c->subquery = sub;
                    } else {
                        /* value list — capture raw text */
                        const char* close = find_matching_paren(p);
                        if (close) {
                            c->value = dup_range(p + 1, close);
                            c->value_is_string = 0;
                            c->operator = strdup(negated ? "NOT IN" : "IN");
                            p = close + 1;
                        } else {
                            c->operator = strdup(negated ? "NOT IN" : "IN");
                        }
                    }
                } else {
                    c->operator = strdup(negated ? "NOT IN" : "IN");
                }
            } else if (strncasecmp(p, "IS", 2) == 0 && !isalnum((unsigned char)p[2]) && p[2] != '_') {
                /* IS [NOT] NULL | TRUE | FALSE | UNKNOWN */
                p += 2;
                p = skip_ws(p);
                int is_not = 0;
                const char* not_after = match_kw(p, "NOT");
                if (not_after) { p = not_after; is_not = 1; }
                p = skip_ws(p);
                const char* null_after = match_kw(p, "NULL");
                const char* true_after = match_kw(p, "TRUE");
                const char* false_after = match_kw(p, "FALSE");
                const char* unk_after = match_kw(p, "UNKNOWN");
                const char* rhs = "NULL";
                if (null_after) { p = null_after; rhs = "NULL"; }
                else if (true_after) { p = true_after; rhs = "TRUE"; }
                else if (false_after) { p = false_after; rhs = "FALSE"; }
                else if (unk_after) { p = unk_after; rhs = "UNKNOWN"; }
                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                c->operator = strdup(is_not ? "IS NOT" : "IS");
                c->value = strdup(rhs);
            } else if (strncasecmp(p, "BETWEEN", 7) == 0 && !isalnum((unsigned char)p[7])) {
                /* BETWEEN low AND high — capture raw range text */
                p += 7;
                const char* rstart = p;
                /* find the AND that separates low/high (naïve: first standalone AND) */
                const char* rp = rstart;
                while (*rp) {
                    if (strncasecmp(rp, " AND", 4) == 0 && !isalnum((unsigned char)rp[4])) break;
                    rp++;
                }
                const char* and_pos = rp;
                const char* high_start = and_pos ? skip_ws(and_pos + 4) : NULL;
                const char* hend = high_start;
                if (high_start) {
                    while (*hend && !isspace((unsigned char)*hend) && *hend != ')') hend++;
                }
                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = (qihse_sql_condition_t*)realloc(ast->where_conditions, cond_cap * sizeof(qihse_sql_condition_t));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                c->operator = strdup(negated ? "NOT BETWEEN" : "BETWEEN");
                if (and_pos && high_start) {
                    const char* low_e = and_pos;
                    while (low_e > rstart && isspace((unsigned char)low_e[-1])) low_e--;
                    c->value = dup_range(rstart, low_e);
                    c->value_is_string = 0;
                    p = hend;
                } else {
                    p = rstart;
                }
            } else {
                size_t op_len;
                const char* op_start = read_operator(p, &op_len);
                if (op_len == 0) break;
                p = op_start + op_len;

                int is_str;
                size_t val_len;
                const char* after_val = NULL;
                const char* val_start = read_value(p, &val_len, &is_str, &after_val);
                if (val_len == 0) break;
                p = after_val ? after_val : (val_start + val_len);

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

    /* CREATE [OR REPLACE] VIEW name AS select */
    const char* view_after = match_kw(p, "VIEW");
    if (view_after) {
        p = view_after;
        size_t vlen;
        const char* vstart = read_identifier(p, &vlen);
        ast->view_name = dup_token(vstart, vlen);
        p = vstart + vlen;
        p = skip_ws(p);
        const char* as_after = match_kw(p, "AS");
        if (as_after) {
            p = as_after;
            p = skip_ws(p);
            /* Parse the SELECT query for the view */
            ast->view_query = parse_select(&p);
        }
        ast->stmt_type = QIHSE_SQL_CREATE_VIEW;
        *pp = p;
        return ast;
    }

    /* CREATE [MATERIALIZED] VIEW name AS select */
    const char* matview_after = match_kw(p, "MATERIALIZED");
    if (matview_after) {
        p = matview_after;
        p = skip_ws(p);
        const char* mv_after = match_kw(p, "VIEW");
        if (mv_after) {
            p = mv_after;
            size_t vlen;
            const char* vstart = read_identifier(p, &vlen);
            ast->view_name = dup_token(vstart, vlen);
            p = vstart + vlen;
            p = skip_ws(p);
            const char* as_after = match_kw(p, "AS");
            if (as_after) {
                p = as_after;
                p = skip_ws(p);
                ast->view_query = parse_select(&p);
            }
            ast->stmt_type = QIHSE_SQL_CREATE_MATVIEW;
            *pp = p;
            return ast;
        }
    }

    /* CREATE SEQUENCE name [START WITH n] [INCREMENT BY n] [MINVALUE n] [MAXVALUE n] [CACHE n] [CYCLE|NO CYCLE] */
    const char* seq_after = match_kw(p, "SEQUENCE");
    if (seq_after) {
        p = seq_after;
        size_t slen;
        const char* sstart = read_identifier(p, &slen);
        ast->seq_def = (qihse_sql_sequence_def_t*)calloc(1, sizeof(qihse_sql_sequence_def_t));
        ast->seq_def->name = dup_token(sstart, slen);
        ast->seq_def->start = 1;
        ast->seq_def->increment = 1;
        ast->seq_def->minvalue = 1;
        ast->seq_def->maxvalue = 9223372036854775807LL;
        ast->seq_def->cycle = 0;
        p = sstart + slen;
        p = skip_ws(p);
        /* Parse sequence options */
        for (;;) {
            const char* start_after = match_kw(p, "START");
            if (start_after) {
                p = start_after;
                const char* with_after = match_kw(p, "WITH");
                if (with_after) p = with_after;
                p = skip_ws(p);
                ast->seq_def->start = strtoll(p, NULL, 10);
                while (*p && (isdigit((unsigned char)*p) || *p == '-' || *p == '+')) p++;
                continue;
            }
            const char* inc_after = match_kw(p, "INCREMENT");
            if (inc_after) {
                p = inc_after;
                const char* by_after = match_kw(p, "BY");
                if (by_after) p = by_after;
                p = skip_ws(p);
                ast->seq_def->increment = strtoll(p, NULL, 10);
                while (*p && (isdigit((unsigned char)*p) || *p == '-' || *p == '+')) p++;
                continue;
            }
            const char* min_after = match_kw(p, "MINVALUE");
            if (min_after) {
                p = min_after;
                p = skip_ws(p);
                ast->seq_def->minvalue = strtoll(p, NULL, 10);
                while (*p && (isdigit((unsigned char)*p) || *p == '-' || *p == '+')) p++;
                continue;
            }
            const char* max_after = match_kw(p, "MAXVALUE");
            if (max_after) {
                p = max_after;
                p = skip_ws(p);
                ast->seq_def->maxvalue = strtoll(p, NULL, 10);
                while (*p && (isdigit((unsigned char)*p) || *p == '-' || *p == '+')) p++;
                continue;
            }
            const char* cache_after = match_kw(p, "CACHE");
            if (cache_after) {
                p = cache_after;
                p = skip_ws(p);
                ast->seq_def->increment = strtoll(p, NULL, 10);
                while (*p && (isdigit((unsigned char)*p) || *p == '-' || *p == '+')) p++;
                continue;
            }
            const char* cycle_after = match_kw(p, "CYCLE");
            if (cycle_after) { p = cycle_after; ast->seq_def->cycle = 1; continue; }
            const char* nocycle_after = match_kw(p, "NO");
            if (nocycle_after) {
                p = nocycle_after;
                const char* cyc = match_kw(p, "CYCLE");
                if (cyc) { p = cyc; ast->seq_def->cycle = 0; continue; }
            }
            break;
        }
        ast->stmt_type = QIHSE_SQL_CREATE_SEQ;
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
            /* table-level constraints vs column definitions */
            if (parse_table_constraint(seg_start, seg_len, ast)) {
                /* handled as a table-level constraint */
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
 * Utility command helpers
 * ------------------------------------------------------------------------- */
static qihse_sql_util_t* util_new(void) {
    return (qihse_sql_util_t*)calloc(1, sizeof(qihse_sql_util_t));
}

static void util_list_push(char*** list, size_t* n, size_t* cap, char* item) {
    if (*n >= *cap) {
        *cap = *cap ? *cap * 2 : 4;
        *list = (char**)realloc(*list, *cap * sizeof(char*));
    }
    (*list)[(*n)++] = item;
}

/* read a comma-separated list of identifiers starting at *pp */
static void parse_ident_list(const char** pp, char*** out_list, size_t* out_n) {
    const char* p = *pp;
    size_t cap = 0;
    *out_list = NULL;
    *out_n = 0;
    for (;;) {
        p = skip_ws(p);
        size_t ilen;
        const char* istart = read_identifier(p, &ilen);
        if (ilen == 0) break;
        util_list_push(out_list, out_n, &cap, dup_token(istart, ilen));
        p = istart + ilen;
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        break;
    }
    *pp = p;
}

/* read a parenthesised identifier list: ( a, b, c ) */
static void parse_paren_ident_list(const char** pp, char*** out_list, size_t* out_n) {
    const char* p = skip_ws(*pp);
    *out_list = NULL;
    *out_n = 0;
    if (*p != '(') { *pp = p; return; }
    p++;
    parse_ident_list(&p, out_list, out_n);
    p = skip_ws(p);
    if (*p == ')') p++;
    *pp = p;
}

/* read a single quoted string literal into out (newly allocated) */
static char* parse_string_literal(const char** pp) {
    const char* p = skip_ws(*pp);
    if (*p != '\'') { *pp = p; return NULL; }
    p++;
    const char* start = p;
    while (*p && *p != '\'') p++;
    char* out = dup_range(start, p);
    if (*p == '\'') p++;
    *pp = p;
    return out;
}

/* read the remainder of the current statement (until ';' or end) as raw text */
static char* parse_rest(const char** pp) {
    const char* p = skip_ws(*pp);
    const char* start = p;
    while (*p && *p != ';') p++;
    const char* end = p;
    while (end > start && isspace((unsigned char)end[-1])) end--;
    char* out = dup_range(start, end);
    *pp = p;
    return out;
}

/* -------------------------------------------------------------------------
 * Parse transaction / DCL / utility commands.
 * *pp points just past the leading keyword; `type` selects the grammar.
 * ------------------------------------------------------------------------- */
static qihse_sql_ast_t* parse_utility(const char** pp, qihse_sql_stmt_type_t type) {
    const char* p = *pp;
    qihse_sql_ast_t* ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
    ast->limit = -1; ast->offset = -1;
    ast->stmt_type = type;
    ast->util = util_new();

    switch (type) {
    case QIHSE_SQL_BEGIN: {
        /* BEGIN [WORK|TRANSACTION] [ISOLATION LEVEL ...] [READ WRITE|READ ONLY] */
        const char* after = match_kw(p, "WORK");
        if (after) p = after;
        else { after = match_kw(p, "TRANSACTION"); if (after) p = after; }
        for (;;) {
            p = skip_ws(p);
            const char* iso = match_kw(p, "ISOLATION");
            if (iso) {
                p = iso;
                const char* lvl = match_kw(p, "LEVEL");
                if (lvl) p = lvl;
                p = skip_ws(p);
                /* consume level name token(s) */
                while (*p && (isalpha((unsigned char)*p) || *p == '_')) p++;
                continue;
            }
            const char* rw = match_kw(p, "READ WRITE");
            if (rw) { p = rw; continue; }
            const char* ro = match_kw(p, "READ ONLY");
            if (ro) { p = ro; ast->util->flags |= QIHSE_UTIL_READ_ONLY; continue; }
            break;
        }
        break;
    }
    case QIHSE_SQL_COMMIT:
    case QIHSE_SQL_ROLLBACK: {
        const char* after = match_kw(p, "WORK");
        if (after) p = after;
        else { after = match_kw(p, "TRANSACTION"); if (after) p = after; }
        if (type == QIHSE_SQL_ROLLBACK) {
            /* ROLLBACK [TO [SAVEPOINT] name] */
            const char* to_after = match_kw(p, "TO");
            if (to_after) {
                p = to_after;
                const char* sp_after = match_kw(p, "SAVEPOINT");
                if (sp_after) p = sp_after;
                p = skip_ws(p);
                size_t nlen;
                const char* nstart = read_identifier(p, &nlen);
                if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
            }
        }
        break;
    }
    case QIHSE_SQL_SAVEPOINT:
    case QIHSE_SQL_RELEASE: {
        const char* sp_after = match_kw(p, "SAVEPOINT");
        if (sp_after) p = sp_after;
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        break;
    }
    case QIHSE_SQL_SET_TXN:
    case QIHSE_SQL_SET_PARAM: {
        /* SET [TRANSACTION ...] | SET param = value | SET param TO value */
        const char* txn_after = match_kw(p, "TRANSACTION");
        if (txn_after) {
            p = txn_after;
            ast->stmt_type = QIHSE_SQL_SET_TXN;
            /* consume isolation/read options */
            for (;;) {
                p = skip_ws(p);
                const char* iso = match_kw(p, "ISOLATION");
                if (iso) { p = iso; const char* lvl = match_kw(p, "LEVEL"); if (lvl) p = lvl;
                    p = skip_ws(p); while (*p && (isalpha((unsigned char)*p) || *p == '_')) p++; continue; }
                const char* ro = match_kw(p, "READ ONLY");
                if (ro) { p = ro; ast->util->flags |= QIHSE_UTIL_READ_ONLY; continue; }
                const char* rw = match_kw(p, "READ WRITE");
                if (rw) { p = rw; continue; }
                break;
            }
        } else {
            ast->stmt_type = QIHSE_SQL_SET_PARAM;
            p = skip_ws(p);
            size_t nlen;
            const char* nstart = read_identifier(p, &nlen);
            if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
            p = skip_ws(p);
            if (*p == '=' || *p == '=') { if (*p == '=') p++; }
            else { const char* to_after = match_kw(p, "TO"); if (to_after) p = to_after; }
            ast->util->value = parse_rest(&p);
        }
        break;
    }
    case QIHSE_SQL_RESET: {
        p = skip_ws(p);
        const char* all_after = match_kw(p, "ALL");
        if (all_after) { p = all_after; ast->util->flags |= QIHSE_UTIL_ALL; }
        else {
            size_t nlen;
            const char* nstart = read_identifier(p, &nlen);
            if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        }
        break;
    }
    case QIHSE_SQL_SHOW: {
        p = skip_ws(p);
        const char* all_after = match_kw(p, "ALL");
        if (all_after) { p = all_after; ast->util->flags |= QIHSE_UTIL_ALL; }
        else { ast->util->name = parse_rest(&p); }
        break;
    }
    case QIHSE_SQL_DISCARD: {
        p = skip_ws(p);
        const char* all_after = match_kw(p, "ALL");
        if (all_after) { p = all_after; ast->util->flags |= QIHSE_UTIL_ALL; ast->util->name = strdup("ALL"); }
        else {
            const char* seq = match_kw(p, "SEQUENCES");
            if (seq) { p = seq; ast->util->name = strdup("SEQUENCES"); }
            else { const char* tmp = match_kw(p, "TEMPORARY"); if (tmp) { p = tmp; ast->util->name = strdup("TEMPORARY"); }
                   else { const char* pl = match_kw(p, "PLANS"); if (pl) { p = pl; ast->util->name = strdup("PLANS"); } } }
        }
        break;
    }
    case QIHSE_SQL_TRUNCATE: {
        const char* tbl_after = match_kw(p, "TABLE");
        if (tbl_after) p = tbl_after;
        size_t cap = 0;
        for (;;) {
            p = skip_ws(p);
            size_t ilen;
            const char* istart = read_identifier(p, &ilen);
            if (ilen == 0) break;
            util_list_push(&ast->util->list, &ast->util->num_list, &cap, dup_token(istart, ilen));
            p = istart + ilen;
            p = skip_ws(p);
            if (*p == ',') { p++; continue; }
            break;
        }
        for (;;) {
            p = skip_ws(p);
            const char* ri = match_kw(p, "RESTART IDENTITY");
            if (ri) { p = ri; ast->util->flags |= QIHSE_UTIL_RESTART_ID; continue; }
            const char* ci = match_kw(p, "CONTINUE IDENTITY");
            if (ci) { p = ci; ast->util->flags |= QIHSE_UTIL_CONTINUE_ID; continue; }
            const char* casc = match_kw(p, "CASCADE");
            if (casc) { p = casc; ast->util->flags |= QIHSE_UTIL_CASCADE; continue; }
            const char* rest = match_kw(p, "RESTRICT");
            if (rest) { p = rest; ast->util->flags |= QIHSE_UTIL_RESTRICT; continue; }
            break;
        }
        break;
    }
    case QIHSE_SQL_COPY: {
        p = skip_ws(p);
        if (*p == '(') {
            /* COPY (SELECT ...) TO '/path' */
            qihse_sql_ast_t* sub = parse_paren_subquery(&p);
            ast->util->subquery = sub;
            ast->util->flags &= ~QIHSE_UTIL_FROM;
        } else {
            size_t ilen;
            const char* istart = read_identifier(p, &ilen);
            if (ilen > 0) { ast->util->name = dup_token(istart, ilen); p = istart + ilen; }
            p = skip_ws(p);
            if (*p == '(') {
                parse_paren_ident_list(&p, &ast->util->list2, &ast->util->num_list2);
            }
        }
        const char* from_after = match_kw(p, "FROM");
        const char* to_after = match_kw(p, "TO");
        if (from_after) { p = from_after; ast->util->flags |= QIHSE_UTIL_FROM; }
        else if (to_after) { p = to_after; }
        ast->util->value = parse_string_literal(&p);
        /* optional WITH (...) options — consume as raw */
        p = skip_ws(p);
        const char* with_after = match_kw(p, "WITH");
        if (with_after) {
            p = with_after;
            p = skip_ws(p);
            if (*p == '(') { const char* close = find_matching_paren(p); if (close) p = close + 1; }
        }
        break;
    }
    case QIHSE_SQL_DEALLOCATE: {
        const char* prep_after = match_kw(p, "PREPARE");
        if (prep_after) p = prep_after;
        p = skip_ws(p);
        const char* all_after = match_kw(p, "ALL");
        if (all_after) { p = all_after; ast->util->flags |= QIHSE_UTIL_ALL; }
        else { size_t nlen; const char* nstart = read_identifier(p, &nlen);
               if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; } }
        break;
    }
    case QIHSE_SQL_PREPARE: {
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        p = skip_ws(p);
        if (*p == '(') {
            parse_paren_ident_list(&p, &ast->util->list, &ast->util->num_list);
        }
        const char* as_after = match_kw(p, "AS");
        if (as_after) {
            p = as_after;
            p = skip_ws(p);
            if (strncasecmp(p, "SELECT", 6) == 0) {
                ast->util->subquery = parse_select(&p);
            } else {
                ast->util->value = parse_rest(&p);
            }
        }
        break;
    }
    case QIHSE_SQL_EXECUTE: {
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        p = skip_ws(p);
        if (*p == '(') {
            /* parse argument expressions as raw strings */
            p++;
            size_t cap = 0;
            for (;;) {
                p = skip_ws(p);
                if (*p == ')') { p++; break; }
                const char* start = p;
                int depth = 0;
                while (*p) {
                    if (*p == '(') depth++;
                    else if (*p == ')') { if (depth == 0) break; depth--; }
                    else if (depth == 0 && *p == ',') break;
                    p++;
                }
                const char* end = p;
                while (end > start && isspace((unsigned char)end[-1])) end--;
                if (end > start) util_list_push(&ast->util->list, &ast->util->num_list, &cap, dup_range(start, end));
                p = skip_ws(p);
                if (*p == ',') { p++; continue; }
                if (*p == ')') { p++; break; }
                break;
            }
        }
        break;
    }
    case QIHSE_SQL_REINDEX: {
        const char* verbose_after = match_kw(p, "VERBOSE");
        if (verbose_after) { p = verbose_after; ast->util->flags |= QIHSE_UTIL_VERBOSE; }
        const char* tbl_after = match_kw(p, "TABLE");
        const char* idx_after = match_kw(p, "INDEX");
        if (tbl_after) { p = tbl_after; ast->util->name2 = strdup("TABLE"); }
        else if (idx_after) { p = idx_after; ast->util->name2 = strdup("INDEX"); }
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        break;
    }
    case QIHSE_SQL_CLUSTER: {
        const char* verbose_after = match_kw(p, "VERBOSE");
        if (verbose_after) { p = verbose_after; ast->util->flags |= QIHSE_UTIL_VERBOSE; }
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        const char* using_after = match_kw(p, "USING");
        if (using_after) {
            p = using_after;
            p = skip_ws(p);
            size_t ilen;
            const char* istart = read_identifier(p, &ilen);
            if (ilen > 0) { ast->util->name2 = dup_token(istart, ilen); p = istart + ilen; }
        }
        break;
    }
    case QIHSE_SQL_GRANT:
    case QIHSE_SQL_REVOKE: {
        /* GRANT {SELECT|INSERT|UPDATE|DELETE|ALL} ON table TO/FROM {user|PUBLIC} [WITH GRANT OPTION] */
        size_t cap = 0;
        for (;;) {
            p = skip_ws(p);
            const char* all_after = match_kw(p, "ALL");
            if (all_after) { p = all_after; const char* priv = match_kw(p, "PRIVILEGES"); if (priv) p = priv;
                util_list_push(&ast->util->list, &ast->util->num_list, &cap, strdup("ALL")); continue; }
            size_t ilen;
            const char* istart = read_identifier(p, &ilen);
            if (ilen == 0) break;
            util_list_push(&ast->util->list, &ast->util->num_list, &cap, dup_token(istart, ilen));
            p = istart + ilen;
            p = skip_ws(p);
            if (*p == ',') { p++; continue; }
            break;
        }
        const char* on_after = match_kw(p, "ON");
        if (on_after) p = on_after;
        p = skip_ws(p);
        size_t tlen;
        const char* tstart = read_identifier(p, &tlen);
        if (tlen > 0) { ast->util->name = dup_token(tstart, tlen); p = tstart + tlen; }
        const char* to_after = match_kw(p, "TO");
        const char* from_after = match_kw(p, "FROM");
        if (to_after) p = to_after;
        else if (from_after) p = from_after;
        p = skip_ws(p);
        const char* pub_after = match_kw(p, "PUBLIC");
        if (pub_after) { p = pub_after; ast->util->value = strdup("PUBLIC"); }
        else { size_t ulen; const char* ustart = read_identifier(p, &ulen);
               if (ulen > 0) { ast->util->value = dup_token(ustart, ulen); p = ustart + ulen; } }
        if (type == QIHSE_SQL_GRANT) {
            const char* wg = match_kw(p, "WITH GRANT OPTION");
            if (wg) { p = wg; ast->util->flags |= QIHSE_UTIL_WITH_GRANT; }
        }
        break;
    }
    case QIHSE_SQL_CREATE_ROLE: {
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        for (;;) {
            const char* with_after = match_kw(p, "WITH");
            if (with_after) p = with_after;
            p = skip_ws(p);
            const char* login = match_kw(p, "LOGIN");
            if (login) { p = login; continue; }
            const char* nologin = match_kw(p, "NOLOGIN");
            if (nologin) { p = nologin; continue; }
            const char* pass = match_kw(p, "PASSWORD");
            if (pass) { p = pass; ast->util->value = parse_string_literal(&p); continue; }
            break;
        }
        break;
    }
    case QIHSE_SQL_DROP_ROLE: {
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        break;
    }
    case QIHSE_SQL_ALTER_ROLE: {
        p = skip_ws(p);
        size_t nlen;
        const char* nstart = read_identifier(p, &nlen);
        if (nlen > 0) { ast->util->name = dup_token(nstart, nlen); p = nstart + nlen; }
        const char* with_after = match_kw(p, "WITH");
        if (with_after) p = with_after;
        const char* pass = match_kw(p, "PASSWORD");
        if (pass) { p = pass; ast->util->value = parse_string_literal(&p); }
        break;
    }
    default:
        break;
    }

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
    } else if (strncasecmp(cur, "INSERT", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_INSERT;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        const char* into_after = match_kw(cur, "INTO");
        if (into_after) cur = into_after;
        cur = skip_ws(cur);
        size_t tlen;
        const char* tstart = read_identifier(cur, &tlen);
        if (tlen > 0) { ast->table_name = dup_token(tstart, tlen); cur = tstart + tlen; }
        cur = skip_ws(cur);
        /* Optional column list */
        if (*cur == '(') {
            cur++;
            size_t col_cap = 8;
            ast->insert_columns = (char**)calloc(col_cap, sizeof(char*));
            ast->num_insert_columns = 0;
            for (;;) {
                cur = skip_ws(cur);
                size_t clen;
                const char* cstart = read_identifier(cur, &clen);
                if (clen == 0) break;
                if (ast->num_insert_columns >= col_cap) {
                    col_cap *= 2;
                    ast->insert_columns = (char**)realloc(ast->insert_columns, col_cap * sizeof(char*));
                }
                ast->insert_columns[ast->num_insert_columns++] = dup_token(cstart, clen);
                cur = cstart + clen;
                cur = skip_ws(cur);
                if (*cur == ',') { cur++; continue; }
                if (*cur == ')') { cur++; break; }
                break;
            }
        }
        cur = skip_ws(cur);
        /* VALUES or SELECT */
        const char* values_after = match_kw(cur, "VALUES");
        if (values_after) {
            cur = values_after;
            cur = skip_ws(cur);
            size_t row_cap = 4;
            ast->insert_rows = (char***)calloc(row_cap, sizeof(char**));
            ast->num_insert_rows = 0;
                        for (;;) {
                cur = skip_ws(cur);
                if (*cur != '(') break;
                cur++;
                size_t val_cap = 8;
                char** values = (char**)calloc(val_cap, sizeof(char*));
                size_t nvalues = 0;
                for (;;) {
                    cur = skip_ws(cur);
                    if (*cur == ')') { cur++; break; }
                    /* Parse a value token */
                    const char* vstart = cur;
                    if (*cur == '\'') {
                        cur++;
                        vstart = cur;
                        while (*cur && *cur != '\'') cur++;
                        if (*cur == '\'') { size_t vlen = (size_t)(cur - vstart); if (nvalues >= val_cap) { val_cap *= 2; values = (char**)realloc(values, val_cap * sizeof(char*)); } values[nvalues++] = dup_token(vstart, vlen); cur++; }
                    } else {
                        while (*cur && *cur != ',' && *cur != ')') cur++;
                        size_t vlen = (size_t)(cur - vstart);
                        while (vlen > 0 && isspace((unsigned char)vstart[vlen-1])) vlen--;
                        if (nvalues >= val_cap) { val_cap *= 2; values = (char**)realloc(values, val_cap * sizeof(char*)); }
                        values[nvalues++] = dup_token(vstart, vlen);
                    }
                    cur = skip_ws(cur);
                    if (*cur == ',') { cur++; continue; }
                    if (*cur == ')') { cur++; break; }
                    break;
                }
                if (ast->num_insert_rows >= row_cap) {
                    row_cap *= 2;
                    ast->insert_rows = (char***)realloc(ast->insert_rows, row_cap * sizeof(char**));
                                    }
                /* ensure NULL-termination for safe freeing */
                if (nvalues >= val_cap) { val_cap = nvalues + 1; values = (char**)realloc(values, val_cap * sizeof(char*)); }
                values[nvalues] = NULL;
                ast->insert_rows[ast->num_insert_rows] = values;
                                ast->num_insert_rows++;
                cur = skip_ws(cur);
                if (*cur != ',') break;
                cur++;
            }
        }
        cur = skip_ws(cur);
        /* ON CONFLICT (UPSERT) */
        const char* on_after = match_kw(cur, "ON");
        if (on_after) {
            const char* conflict_after = match_kw(on_after, "CONFLICT");
            if (conflict_after) {
                cur = conflict_after;
                ast->on_conflict = (qihse_sql_on_conflict_t*)calloc(1, sizeof(qihse_sql_on_conflict_t));
                ast->on_conflict->action = 1; /* DO UPDATE by default */
                cur = skip_ws(cur);
                if (*cur == '(') {
                    cur++;
                    size_t clen;
                    const char* cstart = read_identifier(cur, &clen);
                    if (clen > 0) { ast->on_conflict->conflict_columns = (char**)calloc(1, sizeof(char*)); ast->on_conflict->conflict_columns[0] = dup_token(cstart, clen); ast->on_conflict->num_conflict_columns = 1; cur = cstart + clen; }
                    cur = skip_ws(cur);
                    if (*cur == ')') cur++;
                }
                cur = skip_ws(cur);
                const char* do_after = match_kw(cur, "DO");
                if (do_after) {
                    cur = do_after;
                    cur = skip_ws(cur);
                    const char* update_after = match_kw(cur, "UPDATE");
                    const char* nothing_after = match_kw(cur, "NOTHING");
                    if (nothing_after) { cur = nothing_after; ast->on_conflict->action = 2; }
                    else if (update_after) { cur = update_after; ast->on_conflict->action = 1; }
                }
            }
        }
        cur = skip_ws(cur);
        /* RETURNING */
        const char* returning_after = match_kw(cur, "RETURNING");
        if (returning_after) {
            cur = returning_after;
            cur = skip_ws(cur);
            if (*cur == '*') {
                ast->returning = (qihse_sql_returning_t*)calloc(1, sizeof(qihse_sql_returning_t));
                ast->returning->is_star = 1;
                cur++;
            } else {
                ast->returning = (qihse_sql_returning_t*)calloc(1, sizeof(qihse_sql_returning_t));
                ast->returning->is_star = 0;
                size_t ret_cap = 4;
                ast->returning->columns = (char**)calloc(ret_cap, sizeof(char*));
                ast->returning->num_columns = 0;
                for (;;) {
                    cur = skip_ws(cur);
                    size_t clen;
                    const char* cstart = read_identifier(cur, &clen);
                    if (clen == 0) break;
                    if (ast->returning->num_columns >= ret_cap) {
                        ret_cap *= 2;
                        ast->returning->columns = (char**)realloc(ast->returning->columns, ret_cap * sizeof(char*));
                    }
                    ast->returning->columns[ast->returning->num_columns++] = dup_token(cstart, clen);
                    cur = cstart + clen;
                    cur = skip_ws(cur);
                    if (*cur == ',') { cur++; continue; }
                    break;
                }
            }
        }
    } else if (strncasecmp(cur, "UPDATE", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_UPDATE;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        size_t tlen;
        const char* tstart = read_identifier(cur, &tlen);
        if (tlen > 0) { ast->table_name = dup_token(tstart, tlen); cur = tstart + tlen; }
    } else if (strncasecmp(cur, "DELETE", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_DELETE;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        const char* from_after = match_kw(cur, "FROM");
        if (from_after) cur = from_after;
        cur = skip_ws(cur);
        size_t tlen;
        const char* tstart = read_identifier(cur, &tlen);
        if (tlen > 0) { ast->table_name = dup_token(tstart, tlen); cur = tstart + tlen; }
        cur = skip_ws(cur);
        /* WHERE */
        const char* where_after = match_kw(cur, "WHERE");
        if (where_after) {
            cur = where_after;
            const char* wstart = cur;
            while (*cur && *cur != ';') cur++;
            size_t wlen = (size_t)(cur - wstart);
            while (wlen > 0 && isspace((unsigned char)wstart[wlen-1])) wlen--;
            { ast->insert_select_query = dup_token(wstart, wlen); }
        }
        /* RETURNING */
        cur = skip_ws(cur);
        const char* returning_after = match_kw(cur, "RETURNING");
        if (returning_after) {
            cur = returning_after;
            cur = skip_ws(cur);
            if (*cur == '*') {
                ast->returning = (qihse_sql_returning_t*)calloc(1, sizeof(qihse_sql_returning_t));
                ast->returning->is_star = 1;
                cur++;
            }
        }
    } else if (strncasecmp(cur, "CREATE ROLE", 11) == 0) {
        cur += 11; ast = parse_utility(&cur, QIHSE_SQL_CREATE_ROLE);
    } else if (strncasecmp(cur, "CREATE", 6) == 0) {
        cur += 6;
        ast = parse_create(&cur);
    } else if (strncasecmp(cur, "ALTER ROLE", 10) == 0) {
        cur += 10; ast = parse_utility(&cur, QIHSE_SQL_ALTER_ROLE);
    } else if (strncasecmp(cur, "ALTER", 5) == 0) {
        cur += 5;
        ast = parse_alter(&cur);
    } else if (strncasecmp(cur, "DROP ROLE", 9) == 0) {
        cur += 9; ast = parse_utility(&cur, QIHSE_SQL_DROP_ROLE);
    } else if (strncasecmp(cur, "DROP", 4) == 0) {
        cur += 4;
        ast = parse_drop(&cur);
    } else if (strncasecmp(cur, "WITH", 4) == 0 && !isalnum((unsigned char)cur[4]) && cur[4] != '_') {
        /* CTE: WITH name AS (...) SELECT ... */
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_WITH;
        ast->limit = -1; ast->offset = -1;
        /* Skip WITH keyword and parse CTE definitions */
        cur += 4;
        cur = skip_ws(cur);
        /* Parse CTE definitions: name AS (select) [, name AS (select)]* */
        ast->with_clause = (qihse_sql_with_t*)calloc(1, sizeof(qihse_sql_with_t));
        size_t cte_cap = 4;
        ast->with_clause->ctes = (qihse_sql_cte_def_t*)calloc(cte_cap, sizeof(qihse_sql_cte_def_t));
        ast->with_clause->num_ctes = 0;
        for (;;) {
            cur = skip_ws(cur);
            /* Optional RECURSIVE */
            const char* rec_after = match_kw(cur, "RECURSIVE");
            if (rec_after) cur = rec_after;
            cur = skip_ws(cur);
            size_t id_len;
            const char* id_start = read_identifier(cur, &id_len);
            if (id_len == 0) break;
            char* cte_name = dup_token(id_start, id_len);
            cur = id_start + id_len;
            cur = skip_ws(cur);
            const char* as_after = match_kw(cur, "AS");
            if (!as_after) { free(cte_name); break; }
            cur = as_after;
            cur = skip_ws(cur);
            /* Skip the (select...) part - find matching paren */
            if (*cur == '(') {
                /* parse the CTE subquery (SELECT ...) */
                qihse_sql_ast_t* cte_query = parse_paren_subquery(&cur);
                if (ast->with_clause->num_ctes >= cte_cap) {
                    cte_cap *= 2;
                    ast->with_clause->ctes = (qihse_sql_cte_def_t*)realloc(ast->with_clause->ctes, cte_cap * sizeof(qihse_sql_cte_def_t));
                }
                ast->with_clause->ctes[ast->with_clause->num_ctes].name = cte_name;
                ast->with_clause->ctes[ast->with_clause->num_ctes].query = cte_query;
                ast->with_clause->num_ctes++;
            } else {
                free(cte_name);
                break;
            }
            cur = skip_ws(cur);
            if (*cur != ',') break;
            cur++;
        }
        /* Now parse the main SELECT */
        cur = skip_ws(cur);
        if (strncasecmp(cur, "SELECT", 6) == 0) {
            qihse_sql_ast_t* sel = parse_select(&cur);
            if (sel) {
                /* Copy select fields into the WITH ast */
                ast->num_select_items = sel->num_select_items;
                ast->select_items = sel->select_items;
                ast->table_name = sel->table_name;
                ast->num_joins = sel->num_joins;
                ast->joins = sel->joins;
                ast->where_conditions = sel->where_conditions; ast->num_where_conditions = sel->num_where_conditions; sel->where_conditions = NULL; sel->num_where_conditions = 0;
                ast->limit = sel->limit;
                ast->offset = sel->offset;
                free(sel);
            }
        }
    } else if (strncasecmp(cur, "VACUUM", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_VACUUM;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        /* Optional ANALYZE */
        const char* analyze_after = match_kw(cur, "ANALYZE");
        if (analyze_after) { cur = analyze_after; cur = skip_ws(cur); }
        /* Optional table name */
        if (*cur && *cur != ';') {
            size_t tlen;
            const char* tstart = read_identifier(cur, &tlen);
            if (tlen > 0) { ast->vacuum_table = dup_token(tstart, tlen); cur = tstart + tlen; }
        }
    } else if (strncasecmp(cur, "ANALYZE", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_ANALYZE;
        ast->limit = -1; ast->offset = -1;
        cur += 7;
        cur = skip_ws(cur);
        if (*cur && *cur != ';') {
            size_t tlen;
            const char* tstart = read_identifier(cur, &tlen);
            if (tlen > 0) { ast->vacuum_table = dup_token(tstart, tlen); cur = tstart + tlen; }
        }
    } else if (strncasecmp(cur, "NOTIFY", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_NOTIFY;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        size_t clen;
        const char* cstart = read_identifier(cur, &clen);
        if (clen > 0) { ast->notify_channel = dup_token(cstart, clen); cur = cstart + clen; }
        cur = skip_ws(cur);
        if (*cur == ',') {
            cur++;
            cur = skip_ws(cur);
            if (*cur == '\'') {
                cur++;
                const char* payload_start = cur;
                while (*cur && *cur != '\'') cur++;
                size_t plen = (size_t)(cur - payload_start);
                ast->notify_payload = dup_token(payload_start, plen);
                if (*cur == '\'') cur++;
            }
        }
    } else if (strncasecmp(cur, "LISTEN", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_LISTEN;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        size_t clen;
        const char* cstart = read_identifier(cur, &clen);
        if (clen > 0) { ast->notify_channel = dup_token(cstart, clen); cur = cstart + clen; }
    } else if (strncasecmp(cur, "UNLISTEN", 8) == 0 && !isalnum((unsigned char)cur[8]) && cur[8] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_LISTEN;
        ast->limit = -1; ast->offset = -1;
        cur += 8;
        cur = skip_ws(cur);
        size_t clen;
        const char* cstart = read_identifier(cur, &clen);
        if (clen > 0) { ast->notify_channel = dup_token(cstart, clen); cur = cstart + clen; }
    } else if (strncasecmp(cur, "EXPLAIN", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_EXPLAIN;
        ast->limit = -1; ast->offset = -1;
        cur += 7;
        cur = skip_ws(cur);
        /* Optional ANALYZE / VERBOSE after EXPLAIN */
        for (;;) {
            const char* ea = match_kw(cur, "ANALYZE");
            if (ea) { cur = ea; ast->explain_analyze = 1; continue; }
            const char* ev = match_kw(cur, "VERBOSE");
            if (ev) { cur = ev; continue; }
            break;
        }
        /* Parse the inner statement */
        qihse_sql_ast_t* inner = parse_statement(cur);
        if (inner) {
            /* Copy relevant fields */
            ast->table_name = inner->table_name;
            ast->num_select_items = inner->num_select_items;
            ast->select_items = inner->select_items;
            ast->where_conditions = inner->where_conditions; ast->num_where_conditions = inner->num_where_conditions; inner->where_conditions = NULL; inner->num_where_conditions = 0;
            ast->explain_query = inner;
        }
    } else if (strncasecmp(cur, "BEGIN", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        cur += 5; ast = parse_utility(&cur, QIHSE_SQL_BEGIN);
    } else if (strncasecmp(cur, "START", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        /* START TRANSACTION — treat as BEGIN */
        cur += 5; const char* tx_kw = match_kw(cur, "TRANSACTION"); if (tx_kw) cur = tx_kw;
        ast = parse_utility(&cur, QIHSE_SQL_BEGIN);
    } else if (strncasecmp(cur, "COMMIT", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        cur += 6; ast = parse_utility(&cur, QIHSE_SQL_COMMIT);
    } else if (strncasecmp(cur, "END", 3) == 0 && !isalnum((unsigned char)cur[3]) && cur[3] != '_') {
        cur += 3; ast = parse_utility(&cur, QIHSE_SQL_COMMIT);
    } else if (strncasecmp(cur, "ROLLBACK", 8) == 0 && !isalnum((unsigned char)cur[8]) && cur[8] != '_') {
        cur += 8; ast = parse_utility(&cur, QIHSE_SQL_ROLLBACK);
    } else if (strncasecmp(cur, "ABORT", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        cur += 5; ast = parse_utility(&cur, QIHSE_SQL_ROLLBACK);
    } else if (strncasecmp(cur, "SAVEPOINT", 9) == 0 && !isalnum((unsigned char)cur[9]) && cur[9] != '_') {
        cur += 9; ast = parse_utility(&cur, QIHSE_SQL_SAVEPOINT);
    } else if (strncasecmp(cur, "RELEASE", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        cur += 7; ast = parse_utility(&cur, QIHSE_SQL_RELEASE);
    } else if (strncasecmp(cur, "SET", 3) == 0 && !isalnum((unsigned char)cur[3]) && cur[3] != '_') {
        cur += 3; ast = parse_utility(&cur, QIHSE_SQL_SET_PARAM);
    } else if (strncasecmp(cur, "RESET", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        cur += 5; ast = parse_utility(&cur, QIHSE_SQL_RESET);
    } else if (strncasecmp(cur, "SHOW", 4) == 0 && !isalnum((unsigned char)cur[4]) && cur[4] != '_') {
        cur += 4; ast = parse_utility(&cur, QIHSE_SQL_SHOW);
    } else if (strncasecmp(cur, "DISCARD", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        cur += 7; ast = parse_utility(&cur, QIHSE_SQL_DISCARD);
    } else if (strncasecmp(cur, "TRUNCATE", 8) == 0 && !isalnum((unsigned char)cur[8]) && cur[8] != '_') {
        cur += 8; ast = parse_utility(&cur, QIHSE_SQL_TRUNCATE);
    } else if (strncasecmp(cur, "COPY", 4) == 0 && !isalnum((unsigned char)cur[4]) && cur[4] != '_') {
        cur += 4; ast = parse_utility(&cur, QIHSE_SQL_COPY);
    } else if (strncasecmp(cur, "DEALLOCATE", 10) == 0 && !isalnum((unsigned char)cur[10]) && cur[10] != '_') {
        cur += 10; ast = parse_utility(&cur, QIHSE_SQL_DEALLOCATE);
    } else if (strncasecmp(cur, "PREPARE", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        cur += 7; ast = parse_utility(&cur, QIHSE_SQL_PREPARE);
    } else if (strncasecmp(cur, "EXECUTE", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        cur += 7; ast = parse_utility(&cur, QIHSE_SQL_EXECUTE);
    } else if (strncasecmp(cur, "REINDEX", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        cur += 7; ast = parse_utility(&cur, QIHSE_SQL_REINDEX);
    } else if (strncasecmp(cur, "CLUSTER", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        cur += 7; ast = parse_utility(&cur, QIHSE_SQL_CLUSTER);
    } else if (strncasecmp(cur, "GRANT", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        cur += 5; ast = parse_utility(&cur, QIHSE_SQL_GRANT);
    } else if (strncasecmp(cur, "REVOKE", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        cur += 6; ast = parse_utility(&cur, QIHSE_SQL_REVOKE);
    } else if (strncasecmp(cur, "DECLARE", 7) == 0 && !isalnum((unsigned char)cur[7]) && cur[7] != '_') {
        /* DECLARE cursor_name CURSOR [(WITH|WITHOUT) HOLD] FOR select */
        cur += 7;
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->limit = -1; ast->offset = -1;
        ast->stmt_type = QIHSE_SQL_DECLARE;
        cur = skip_ws(cur);
        size_t clen;
        const char* cstart = read_identifier(cur, &clen);
        ast->cursor_def = (qihse_sql_cursor_def_t*)calloc(1, sizeof(qihse_sql_cursor_def_t));
        if (clen > 0) { ast->cursor_def->name = dup_token(cstart, clen); cur = cstart + clen; }
        const char* cur_kw = match_kw(cur, "CURSOR");
        if (cur_kw) cur = cur_kw;
        cur = skip_ws(cur);
        const char* with_hold = match_kw(cur, "WITH HOLD");
        if (with_hold) { cur = with_hold; ast->cursor_def->scroll = 1; }
        const char* without_hold = match_kw(cur, "WITHOUT HOLD");
        if (without_hold) { cur = without_hold; }
        const char* for_after = match_kw(cur, "FOR");
        if (for_after) {
            cur = for_after;
            cur = skip_ws(cur);
            ast->cursor_def->query = parse_select(&cur);
        }
    } else if (strncasecmp(cur, "FETCH", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        cur += 5;
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->limit = -1; ast->offset = -1;
        ast->stmt_type = QIHSE_SQL_FETCH;
        cur = skip_ws(cur);
        /* direction: NEXT|ALL|FORWARD n|FIRST|LAST */
        const char* all_after = match_kw(cur, "ALL");
        if (all_after) { cur = all_after; ast->fetch_count = -1; }
        else {
            const char* fwd = match_kw(cur, "FORWARD");
            if (fwd) { cur = fwd; cur = skip_ws(cur);
                if (isdigit((unsigned char)*cur)) { ast->fetch_count = (int)strtol(cur, (char**)&cur, 10); }
                else { const char* fa = match_kw(cur, "ALL"); if (fa) { cur = fa; ast->fetch_count = -1; } } }
            else {
                const char* nxt = match_kw(cur, "NEXT");
                if (nxt) { cur = nxt; ast->fetch_count = 1; }
                else { const char* first_kw = match_kw(cur, "FIRST"); if (first_kw) { cur = first_kw; ast->fetch_count = 1; }
                       else { const char* last_kw = match_kw(cur, "LAST"); if (last_kw) { cur = last_kw; ast->fetch_count = 1; } } }
            }
        }
        const char* from_after = match_kw(cur, "FROM");
        if (from_after) cur = from_after;
        cur = skip_ws(cur);
        size_t cnlen;
        const char* cnstart = read_identifier(cur, &cnlen);
        if (cnlen > 0) { ast->fetch_cursor = dup_token(cnstart, cnlen); cur = cnstart + cnlen; }
    } else if (strncasecmp(cur, "CLOSE", 5) == 0 && !isalnum((unsigned char)cur[5]) && cur[5] != '_') {
        cur += 5;
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->limit = -1; ast->offset = -1;
        ast->stmt_type = QIHSE_SQL_CLOSE;
        const char* all_after = match_kw(cur, "ALL");
        if (all_after) { cur = all_after; ast->close_cursor = strdup("ALL"); }
        else { cur = skip_ws(cur); size_t cnlen; const char* cnstart = read_identifier(cur, &cnlen);
               if (cnlen > 0) { ast->close_cursor = dup_token(cnstart, cnlen); cur = cnstart + cnlen; } }
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
    free(c->check_expr);
    if (c->fk) {
        for (size_t i = 0; i < c->fk->num_columns; i++) free(c->fk->columns[i]);
        free(c->fk->columns);
        for (size_t i = 0; i < c->fk->num_ref_columns; i++) free(c->fk->ref_columns[i]);
        free(c->fk->ref_columns);
        free(c->fk->ref_table);
        free(c->fk);
    }
}

static void free_fk(qihse_sql_fk_t* fk) {
    if (!fk) return;
    for (size_t i = 0; i < fk->num_columns; i++) free(fk->columns[i]);
    free(fk->columns);
    for (size_t i = 0; i < fk->num_ref_columns; i++) free(fk->ref_columns[i]);
    free(fk->ref_columns);
    free(fk->ref_table);
}

static void free_util(qihse_sql_util_t* u) {
    if (!u) return;
    free(u->name);
    free(u->value);
    free(u->name2);
    for (size_t i = 0; i < u->num_list; i++) free(u->list[i]);
    free(u->list);
    for (size_t i = 0; i < u->num_list2; i++) free(u->list2[i]);
    free(u->list2);
    qihse_sql_ast_free(u->subquery);
    free(u);
}

void qihse_sql_ast_free(qihse_sql_ast_t* ast) {
    if (!ast) return;
    for (size_t i = 0; i < ast->num_select_items; i++) {
        free(ast->select_items[i].expr);
        free(ast->select_items[i].alias);
        free(ast->select_items[i].agg_arg);
        free(ast->select_items[i].win_arg);
        free(ast->select_items[i].win_default);
        qihse_sql_ast_free(ast->select_items[i].scalar_subquery);
        if (ast->select_items[i].window) {
            for (size_t j = 0; j < ast->select_items[i].window->num_partition_by; j++)
                free(ast->select_items[i].window->partition_by[j]);
            free(ast->select_items[i].window->partition_by);
            for (size_t j = 0; j < ast->select_items[i].window->num_order_by; j++)
                free(ast->select_items[i].window->order_by[j].column_name);
            free(ast->select_items[i].window->order_by);
            free(ast->select_items[i].window);
        }
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
    /* table-level constraints */
    for (size_t i = 0; i < ast->num_fks; i++) free_fk(&ast->fks[i]);
    free(ast->fks);
    for (size_t i = 0; i < ast->num_checks; i++) {
        free(ast->checks[i].expr);
        free(ast->checks[i].name);
    }
    free(ast->checks);
    for (size_t i = 0; i < ast->num_uniques; i++) {
        for (size_t j = 0; j < ast->uniques[i].num_columns; j++)
            free(ast->uniques[i].columns[j]);
        free(ast->uniques[i].columns);
        free(ast->uniques[i].name);
    }
    free(ast->uniques);
    /* sequence */
    if (ast->seq_def) { free(ast->seq_def->name); free(ast->seq_def); }
    /* view */
    free(ast->view_name);
    qihse_sql_ast_free(ast->view_query);
    /* explain */
    qihse_sql_ast_free(ast->explain_query);
    /* vacuum / analyze */
    free(ast->vacuum_table);
    /* listen / notify */
    free(ast->notify_channel);
    free(ast->notify_payload);
    /* cursor */
    if (ast->cursor_def) {
        free(ast->cursor_def->name);
        qihse_sql_ast_free(ast->cursor_def->query);
        free(ast->cursor_def);
    }
    free(ast->fetch_cursor);
    free(ast->close_cursor);
    /* utility command */
    free_util(ast->util);
    /* with clause */
    if (ast->with_clause) {
        for (size_t i = 0; i < ast->with_clause->num_ctes; i++) {
            free(ast->with_clause->ctes[i].name);
            qihse_sql_ast_free(ast->with_clause->ctes[i].query);
        }
        free(ast->with_clause->ctes);
        qihse_sql_ast_free(ast->with_clause->body);
        free(ast->with_clause);
    }
    /* on conflict */
    if (ast->on_conflict) {
        for (size_t i = 0; i < ast->on_conflict->num_conflict_columns; i++)
            free(ast->on_conflict->conflict_columns[i]);
        free(ast->on_conflict->conflict_columns);
        for (size_t i = 0; i < ast->on_conflict->num_set; i++) {
            free(ast->on_conflict->set_columns[i]);
            free(ast->on_conflict->set_values[i]);
        }
        free(ast->on_conflict->set_columns);
        free(ast->on_conflict->set_values);
        free(ast->on_conflict->where_expr);
        free(ast->on_conflict);
    }
    /* returning */
    if (ast->returning) {
        for (size_t i = 0; i < ast->returning->num_columns; i++)
            free(ast->returning->columns[i]);
        free(ast->returning->columns);
        free(ast->returning);
    }
    /* insert */
    for (size_t i = 0; i < ast->num_insert_columns; i++) free(ast->insert_columns[i]);
    free(ast->insert_columns);
    for (size_t i = 0; i < ast->num_insert_rows; i++) {
        /* values array count unknown per-row; free until NULL or use a parallel
         * count — we stored rows as NULL-terminated via calloc, so free until NULL */
        if (ast->insert_rows[i]) {
            for (char** v = ast->insert_rows[i]; *v; v++) free(*v);
            free(ast->insert_rows[i]);
        }
    }
    free(ast->insert_rows);
    free(ast->insert_select_query);
    /* update set */
    for (size_t i = 0; i < ast->num_set; i++) {
        free(ast->set_columns[i]);
        free(ast->set_values[i]);
    }
    free(ast->set_columns);
    free(ast->set_values);
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
        case QIHSE_AGG_STRING_AGG: return "STRING_AGG";
        case QIHSE_AGG_ARRAY_AGG:  return "ARRAY_AGG";
        case QIHSE_AGG_BOOL_OR:    return "BOOL_OR";
        case QIHSE_AGG_BOOL_AND:   return "BOOL_AND";
        case QIHSE_AGG_EVERY:      return "EVERY";
        case QIHSE_AGG_VARIANCE:   return "VARIANCE";
        case QIHSE_AGG_STDDEV:     return "STDDEV";
        case QIHSE_AGG_CORR:       return "CORR";
        case QIHSE_AGG_COVAR_SAMP: return "COVAR_SAMP";
        case QIHSE_AGG_COVAR_POP:  return "COVAR_POP";
        default: return "NONE";
    }
}

const char* qihse_sql_win_name(qihse_sql_win_kind_t w) {
    switch (w) {
        case QIHSE_WIN_ROW_NUMBER:   return "ROW_NUMBER";
        case QIHSE_WIN_RANK:         return "RANK";
        case QIHSE_WIN_DENSE_RANK:   return "DENSE_RANK";
        case QIHSE_WIN_LAG:          return "LAG";
        case QIHSE_WIN_LEAD:         return "LEAD";
        case QIHSE_WIN_SUM:          return "SUM";
        case QIHSE_WIN_AVG:          return "AVG";
        case QIHSE_WIN_COUNT:        return "COUNT";
        case QIHSE_WIN_MIN:          return "MIN";
        case QIHSE_WIN_MAX:          return "MAX";
        case QIHSE_WIN_FIRST_VALUE:  return "FIRST_VALUE";
        case QIHSE_WIN_LAST_VALUE:   return "LAST_VALUE";
        case QIHSE_WIN_NTH_VALUE:    return "NTH_VALUE";
        case QIHSE_WIN_NTILE:        return "NTILE";
        case QIHSE_WIN_PERCENT_RANK: return "PERCENT_RANK";
        case QIHSE_WIN_CUME_DIST:    return "CUME_DIST";
        default: return "NONE";
    }
}

const char* qihse_sql_stmt_name(qihse_sql_stmt_type_t s) {
    switch (s) {
        case QIHSE_SQL_SELECT:        return "SELECT";
        case QIHSE_SQL_INSERT:        return "INSERT";
        case QIHSE_SQL_UPDATE:        return "UPDATE";
        case QIHSE_SQL_DELETE:        return "DELETE";
        case QIHSE_SQL_CREATE:        return "CREATE";
        case QIHSE_SQL_DROP:          return "DROP";
        case QIHSE_SQL_ALTER:         return "ALTER";
        case QIHSE_SQL_UNION:         return "UNION";
        case QIHSE_SQL_INTERSECT:     return "INTERSECT";
        case QIHSE_SQL_EXCEPT:        return "EXCEPT";
        case QIHSE_SQL_WITH:          return "WITH";
        case QIHSE_SQL_CREATE_VIEW:   return "CREATE VIEW";
        case QIHSE_SQL_DROP_VIEW:     return "DROP VIEW";
        case QIHSE_SQL_CREATE_MATVIEW:return "CREATE MATERIALIZED VIEW";
        case QIHSE_SQL_REFRESH:       return "REFRESH";
        case QIHSE_SQL_CREATE_SEQ:    return "CREATE SEQUENCE";
        case QIHSE_SQL_DROP_SEQ:      return "DROP SEQUENCE";
        case QIHSE_SQL_EXPLAIN:       return "EXPLAIN";
        case QIHSE_SQL_VACUUM:        return "VACUUM";
        case QIHSE_SQL_ANALYZE:       return "ANALYZE";
        case QIHSE_SQL_LISTEN:        return "LISTEN";
        case QIHSE_SQL_NOTIFY:        return "NOTIFY";
        case QIHSE_SQL_DECLARE:       return "DECLARE";
        case QIHSE_SQL_FETCH:         return "FETCH";
        case QIHSE_SQL_CLOSE:         return "CLOSE";
        case QIHSE_SQL_BEGIN:         return "BEGIN";
        case QIHSE_SQL_COMMIT:        return "COMMIT";
        case QIHSE_SQL_ROLLBACK:      return "ROLLBACK";
        case QIHSE_SQL_SAVEPOINT:     return "SAVEPOINT";
        case QIHSE_SQL_RELEASE:       return "RELEASE";
        case QIHSE_SQL_SET_TXN:       return "SET TRANSACTION";
        case QIHSE_SQL_GRANT:         return "GRANT";
        case QIHSE_SQL_REVOKE:        return "REVOKE";
        case QIHSE_SQL_CREATE_ROLE:   return "CREATE ROLE";
        case QIHSE_SQL_DROP_ROLE:     return "DROP ROLE";
        case QIHSE_SQL_ALTER_ROLE:    return "ALTER ROLE";
        case QIHSE_SQL_TRUNCATE:      return "TRUNCATE";
        case QIHSE_SQL_COPY:          return "COPY";
        case QIHSE_SQL_DISCARD:       return "DISCARD";
        case QIHSE_SQL_RESET:         return "RESET";
        case QIHSE_SQL_SET_PARAM:     return "SET";
        case QIHSE_SQL_SHOW:          return "SHOW";
        case QIHSE_SQL_DEALLOCATE:    return "DEALLOCATE";
        case QIHSE_SQL_PREPARE:       return "PREPARE";
        case QIHSE_SQL_EXECUTE:       return "EXECUTE";
        case QIHSE_SQL_REINDEX:       return "REINDEX";
        case QIHSE_SQL_CLUSTER:       return "CLUSTER";
        default: return "UNKNOWN";
    }
}
