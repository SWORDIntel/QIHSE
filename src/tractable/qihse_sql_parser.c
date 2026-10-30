#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <limits.h>

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
        if (*p == '"') *out_len = (size_t)(p - start);
    } else {
        if (isalpha((unsigned char)*p) || *p == '_') {
            p++;
            while (*p && (isalnum((unsigned char)*p) || *p == '_' || *p == '.')) p++;
            *out_len = (size_t)(p - start);
        }
    }
    return start;
}

/* Returns -1 for a malformed/unsupported parameter leaf, 0 for a literal.
 * Only an entire unquoted value (optionally cast to a supported temporal type)
 * can be a parameter; no SQL string substitution is performed. */
static int parameter_leaf(const char* start, size_t len, qihse_sql_type_t* cast) {
    if (!len || *start != '$') return 0;
    size_t pos = 1, index = 0;
    if (!isdigit((unsigned char)start[pos])) return -1;
    while (pos < len && isdigit((unsigned char)start[pos])) {
        index = index * 10 + (unsigned)(start[pos++] - '0');
        if (index > QIHSE_SQL_MAX_PARAMETERS) return -1;
    }
    if (!index) return -1;
    if (pos < len) {
        if (len - pos < 3 || start[pos] != ':' || start[pos + 1] != ':') return -1;
        pos += 2;
        if (len - pos == 9 && strncasecmp(start + pos, "timestamp", 9) == 0)
            *cast = QIHSE_TYPE_TIMESTAMP;
        else if (len - pos == 11 && strncasecmp(start + pos, "timestamptz", 11) == 0)
            *cast = QIHSE_TYPE_TIMESTAMPTZ;
        else return -1;
    }
    return (int)index;
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
        else *out_len = 0;
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
    if (strcmp(tmp, "TIMESTAMPTZ") == 0) return QIHSE_TYPE_TIMESTAMPTZ;
    if (strcmp(tmp, "JSONB") == 0) return QIHSE_TYPE_JSONB;
    if (strcmp(tmp, "UUID") == 0) return QIHSE_TYPE_UUID;
    if (strcmp(tmp, "TSVECTOR") == 0) return QIHSE_TYPE_TSVECTOR;
    if (strcmp(tmp, "INET") == 0) return QIHSE_TYPE_INET;
    if (strcmp(tmp, "NUMERIC") == 0 || strcmp(tmp, "DECIMAL") == 0) return QIHSE_TYPE_NUMERIC;
    if (strcmp(tmp, "DATE") == 0) return QIHSE_TYPE_DATE;
    if (strcmp(tmp, "SERIAL") == 0) return QIHSE_TYPE_SERIAL;
    if (strcmp(tmp, "BIGSERIAL") == 0) return QIHSE_TYPE_BIGSERIAL;
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
static bool has_case_keyword(const char* text) {
    int quoted = 0;
    for (const char* p = text; *p; ++p) {
        if (*p == '\'') { quoted = !quoted; continue; }
        if (!quoted && (p == text || !(isalnum((unsigned char)p[-1]) || p[-1] == '_')) &&
            match_kw(p, "CASE") == p + 4) return true;
    }
    return false;
}

/* Only this bounded CASE shape has an AST representation. */
static bool parse_agg_case(const char* p, const char* end,
                           qihse_sql_select_item_t* item) {
    const char* next = match_kw(p, "CASE");
    if (!next || !(p = match_kw(next, "WHEN"))) return false;
    p = skip_ws(p);
    const char* neg = match_kw(p, "NOT");
    if (neg) p = skip_ws(neg);
    size_t n = 0;
    const char* col = read_identifier(p, &n);
    if (!n || !(isalpha((unsigned char)*col) || *col == '_') ||
        col[n-1] == '.' || !(p = match_kw(col + n, "THEN"))) return false;
    p = skip_ws(p);
    if (*p != '1' || isalnum((unsigned char)p[1]) || p[1] == '_') return false;
    p = skip_ws(p + 1);
    int has_else = 0, else_value = 0;
    next = match_kw(p, "ELSE");
    if (next) {
        has_else = 1;
        p = skip_ws(next);
        if ((*p != '0' && *p != '1') || isalnum((unsigned char)p[1]) || p[1] == '_')
            return false;
        else_value = *p - '0';
        p = skip_ws(p + 1);
    }
    next = match_kw(p, "END");
    if (!next || skip_ws(next) != end) return false;
    item->agg_case = calloc(1, sizeof(*item->agg_case));
    if (!item->agg_case) return false;
    item->agg_case->column = dup_token(col, n);
    if (!item->agg_case->column) return false;
    item->agg_case->negated = neg != NULL;
    item->agg_case->then_value = 1;
    item->agg_case->has_else = has_else;
    item->agg_case->else_value = else_value;
    return true;
}

static bool parse_select_item(const char* start, size_t len, qihse_sql_select_item_t* item) {
    memset(item, 0, sizeof(*item));
    /* find " AS " or trailing alias */
    char* buf = dup_token(start, len);
    if (!buf) return false;

    char* endp = buf + len;

    /* look for " AS " */
    char* as_pos = NULL;
    int depth = 0, quoted = 0;
    for (char* c = buf; c < endp - 3; c++) {
        if (*c == '\'') quoted = !quoted;
        if (quoted) continue;
        if (*c == '(') depth++;
        else if (*c == ')') depth--;
        if (depth == 0 && (strncasecmp(c, " AS ", 4) == 0 ||
                           strncasecmp(c, "\tAS\t", 4) == 0)) {
            as_pos = c;
            break;
        }
    }
    if (as_pos) {
        *as_pos = '\0';
        char* alias_part = as_pos + 4;
        while (*alias_part && isspace((unsigned char)*alias_part)) alias_part++;
        if (!*alias_part || strpbrk(alias_part, " \t\r\n")) { free(buf); return false; }
        item->alias = strdup(alias_part);
        /* trim trailing ws of expr */
        char* e = as_pos - 1;
        while (e > buf && isspace((unsigned char)*e)) { *e = '\0'; e--; }
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
                if (arg_s == arg_e) { free(buf); return false; }
                const char* distinct = match_kw(arg_s, "DISTINCT");
                if (distinct) {
                    if (agg != QIHSE_AGG_COUNT) { free(buf); return false; }
                    arg_s = skip_ws(distinct);
                    if (arg_s >= arg_e) { free(buf); return false; }
                    size_t n = 0;
                    const char* col = read_identifier(arg_s, &n);
                    const char* operand_end = col + n;
                    if (!n || !(isalpha((unsigned char)*col) || *col == '_') ||
                        col[n-1] == '.') { free(buf); return false; }
                    /* JSON text extraction is an expression, not a bare column. */
                    if (operand_end[0] == '-' && operand_end[1] == '>' &&
                        operand_end[2] == '>') {
                        const char* key = skip_ws(operand_end + 3);
                        if (*key++ != '\'') { free(buf); return false; }
                        while (key < arg_e && *key != '\'') key++;
                        if (key == arg_e || key == skip_ws(operand_end + 3) + 1) {
                            free(buf); return false;
                        }
                        operand_end = key + 1;
                    }
                    if (skip_ws(operand_end) != arg_e) { free(buf); return false; }
                    item->is_distinct = 1;
                    item->agg_arg = dup_range(col, operand_end);
                } else if ((size_t)(arg_e - arg_s) == 1 && arg_s[0] == '*') {
                    if (agg != QIHSE_AGG_COUNT) { free(buf); return false; }
                    item->agg_kind = QIHSE_AGG_COUNT_STAR;
                    item->agg_arg = strdup("*");
                } else {
                    item->agg_arg = dup_range(arg_s, arg_e);
                    if (!item->agg_arg) { free(buf); return false; }
                    if (match_kw(arg_s, "CASE")) {
                        if ((agg != QIHSE_AGG_COUNT && agg != QIHSE_AGG_SUM) ||
                            !parse_agg_case(arg_s, arg_e, item)) {
                            free(buf); return false;
                        }
                    } else if (has_case_keyword(item->agg_arg)) {
                        free(buf); return false;
                    }
                }
                item->expr = dup_range(fname, close + 1);
                /* Conditional/DISTINCT windows need separate executor semantics. */
                if ((item->agg_case || item->is_distinct) && match_kw(close + 1, "OVER")) {
                    free(buf); return false;
                }
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
                if (*over_p && !item->window) { free(buf); return false; }
                if (item->agg_case && item->window) { free(buf); return false; }
                free(buf);
                return item->expr && item->agg_arg;
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
                return true;
            }
        }
    }

    if (has_case_keyword(buf)) { free(buf); return false; }
    item->expr = strdup(trim_str(buf));
    free(buf);
    return item->expr != NULL;
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
    if (col->type == QIHSE_TYPE_TIMESTAMP && match_kw(p, "WITH TIME ZONE")) {
        col->type = QIHSE_TYPE_TIMESTAMPTZ;
        p = skip_ws(match_kw(p, "WITH TIME ZONE"));
    } else if (col->type == QIHSE_TYPE_TIMESTAMP && match_kw(p, "WITHOUT TIME ZONE")) {
        p = skip_ws(match_kw(p, "WITHOUT TIME ZONE"));
    }
    if (*p == '(') {
        if (col->type != QIHSE_TYPE_VARCHAR && col->type != QIHSE_TYPE_VECTOR &&
            col->type != QIHSE_TYPE_NUMERIC) { col->type = QIHSE_TYPE_UNKNOWN; return; }
        p = skip_ws(p + 1);
        if (!isdigit((unsigned char)*p)) { col->type = QIHSE_TYPE_UNKNOWN; return; }
        char* end;
        long n = strtol(p, &end, 10);
        if (n <= 0 || n > INT_MAX) { col->type = QIHSE_TYPE_UNKNOWN; return; }
        type_len = (int)n;
        p = skip_ws(end);
        if (*p == ',' && col->type == QIHSE_TYPE_NUMERIC) {
            p = skip_ws(p + 1);
            if (!isdigit((unsigned char)*p)) { col->type = QIHSE_TYPE_UNKNOWN; return; }
            n = strtol(p, &end, 10);
            if (n < 0 || n > type_len) { col->type = QIHSE_TYPE_UNKNOWN; return; }
            col->type_scale = (int)n;
            p = skip_ws(end);
        }
        if (*p != ')') { col->type = QIHSE_TYPE_UNKNOWN; return; }
        p = skip_ws(p + 1);
    }
    if (p[0] == '[' && p[1] == ']') {
        switch (col->type) {
            case QIHSE_TYPE_INT: col->type = QIHSE_TYPE_INT_ARRAY; break;
            case QIHSE_TYPE_FLOAT: col->type = QIHSE_TYPE_FLOAT_ARRAY; break;
            case QIHSE_TYPE_TEXT: col->type = QIHSE_TYPE_TEXT_ARRAY; break;
            case QIHSE_TYPE_BOOL: col->type = QIHSE_TYPE_BOOL_ARRAY; break;
            default: col->type = QIHSE_TYPE_UNKNOWN; return;
        }
        p = skip_ws(p + 2);
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
            col->type = QIHSE_TYPE_UNKNOWN;
            return;
        }
        const char* generated = match_kw(p, "GENERATED ALWAYS AS");
        if (generated) {
            p = skip_ws(generated);
            if (*p != '(') { col->type = QIHSE_TYPE_UNKNOWN; return; }
            const char* close = find_matching_paren(p);
            if (!close || close == p + 1 || col->type != QIHSE_TYPE_TSVECTOR) {
                col->type = QIHSE_TYPE_UNKNOWN;
                return;
            }
            col->generated_expr = dup_range(p + 1, close);
            if (!col->generated_expr) { col->type = QIHSE_TYPE_UNKNOWN; return; }
            p = skip_ws(close + 1);
            const char* stored = match_kw(p, "STORED");
            if (!stored) { col->type = QIHSE_TYPE_UNKNOWN; return; }
            col->generated_stored = 1;
            p = stored;
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
        if (*p) col->type = QIHSE_TYPE_UNKNOWN;
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
                /* Catalog v1 identifies a PK by its column flags; named PK
                 * metadata cannot be preserved by this parser. Reject it. */
                bool named_pk = name != NULL;
                free(name);
                ast->uniques[idx].name = strdup("PRIMARY");
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
                if (named_pk || skip_ws(p) != end) {
                    for (size_t j = 0; j < ast->uniques[idx].num_columns; ++j)
                        free(ast->uniques[idx].columns[j]);
                    free(ast->uniques[idx].columns);
                    ast->uniques[idx].columns = NULL;
                    ast->uniques[idx].num_columns = 0;
                }
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
                if (skip_ws(p) != end) {
                    for (size_t j = 0; j < ast->uniques[idx].num_columns; ++j)
                        free(ast->uniques[idx].columns[j]);
                    free(ast->uniques[idx].columns);
                    ast->uniques[idx].columns = NULL;
                    ast->uniques[idx].num_columns = 0;
                }
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
            if (close && skip_ws(close + 1) == end) {
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
        int columns_valid = 0, ref_columns_valid = 0;
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
                const char* last = ip;
                while (last > icopy && isspace((unsigned char)last[-1])) last--;
                columns_valid = fk->num_columns > 0 && *skip_ws(ip) == '\0' && last > icopy && last[-1] != ',';
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
                    const char* last = ip;
                    while (last > icopy && isspace((unsigned char)last[-1])) last--;
                    ref_columns_valid = fk->num_ref_columns > 0 && *skip_ws(ip) == '\0' && last > icopy && last[-1] != ',';
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
        if (!columns_valid || !ref_columns_valid || !fk->ref_table ||
            fk->num_columns != fk->num_ref_columns || skip_ws(p) != end) {
            for (size_t i = 0; i < fk->num_columns; ++i) free(fk->columns[i]);
            for (size_t i = 0; i < fk->num_ref_columns; ++i) free(fk->ref_columns[i]);
            free(fk->columns);
            free(fk->ref_columns);
            free(fk->ref_table);
            free(fk);
            free(name);
            return 1;
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
        const char* wrapped_start = p;
        int wrapped = *p == '(';
        if (wrapped) p = skip_ws(p + 1);
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
            const char* boolean_not = match_kw(p, "NOT");
            if (boolean_not) p = boolean_not;
            size_t col_len;
            const char* col_start = read_identifier(p, &col_len);
            if (col_len == 0) break;
            p = col_start + col_len;
            p = skip_ws(p);
            if (!strncmp(p, "->>", 3)) {
                if (boolean_not) break;
                const char* key = skip_ws(p + 3);
                if (*key != '\'') break;
                const char* end = key + 1;
                while (*end) {
                    if (*end == '\'' && end[1] == '\'') { end += 2; continue; }
                    if (*end == '\'') break;
                    ++end;
                }
                if (*end != '\'') break;
                p = end + 1;
                col_len = (size_t)(p - col_start);
                p = skip_ws(p);
            }
            if (boolean_not) {
                if (*p && *p != ';' && !match_kw(p, "AND") && !match_kw(p, "OR") &&
                    !match_kw(p, "GROUP BY") && !match_kw(p, "ORDER BY") &&
                    !match_kw(p, "LIMIT") && !match_kw(p, "HAVING")) break;
                if (ast->num_where_conditions >= cond_cap) {
                    cond_cap *= 2;
                    ast->where_conditions = realloc(ast->where_conditions,
                        cond_cap * sizeof(*ast->where_conditions));
                }
                qihse_sql_condition_t* c = &ast->where_conditions[ast->num_where_conditions++];
                memset(c, 0, sizeof(*c));
                c->column_name = dup_token(col_start, col_len);
                c->operator = strdup("=");
                c->value = strdup("FALSE");
                goto condition_done;
            }

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
                qihse_sql_type_t cast_type = QIHSE_TYPE_UNKNOWN;
                int param = is_str ? 0 : parameter_leaf(val_start, val_len, &cast_type);
                if (param < 0) break;
                if (is_str && p[0] == ':' && p[1] == ':') {
                    const char* cast_end = match_kw(p + 2, "TIMESTAMP");
                    if (!cast_end) break;
                    cast_type = QIHSE_TYPE_TIMESTAMP;
                    p = cast_end;
                }

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
                c->value_cast_type = cast_type;
                c->value_parameter_index = (uint16_t)param;
            }
        }

condition_done:
        p = skip_ws(p);
        if (wrapped) {
            if (*p != ')') { *pp = wrapped_start; return; }
            p = skip_ws(p + 1);
        }
        if (strncasecmp(p, "AND", 3) == 0 && !isalnum((unsigned char)p[3])) {
            if (!*skip_ws(p + 3)) break;
            p += 3; continue;
        }
        /* The AST has no boolean connective; accepting OR as AND changes the query. */
        if (match_kw(p, "OR")) { *pp = p; return; }
        break;
    }
    *pp = p;
}

/* -------------------------------------------------------------------------
 * Parse an UPDATE SET list into structured assignments:
 *
 *   SET col = value [, col = value]*
 *
 * A string literal is stored without its quotes, matching insert_rows; any
 * other right-hand side is kept as raw text up to the first top-level comma
 * or the WHERE / RETURNING keyword (so expressions such as "n = n + 1" and
 * "p = point(1, 2)" survive).  Returns the number of assignments written to
 * the AST; 0 means the list was absent or malformed.
 * ------------------------------------------------------------------------- */
static char* parse_string_literal(const char** pp);

static size_t parse_set_list(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = *pp;
    size_t cap = 4;
    ast->set_columns = (char**)calloc(cap, sizeof(char*));
    ast->set_values = (char**)calloc(cap, sizeof(char*));
    ast->set_quoted = calloc(cap, sizeof(*ast->set_quoted));
    ast->set_parameter_indexes = (uint16_t*)calloc(cap, sizeof(uint16_t));
    ast->num_set = 0;
    if (!ast->set_columns || !ast->set_values || !ast->set_quoted ||
        !ast->set_parameter_indexes) return 0;

    for (;;) {
        p = skip_ws(p);
        size_t clen = 0;
        const char* cstart = read_identifier(p, &clen);
        if (clen == 0) break;
        const char* q = skip_ws(cstart + clen);
        if (*q != '=') break;                  /* not "col = ..." */
        q++;
        q = skip_ws(q);
        if (!*q || *q == ',' || *q == ';') break;  /* assignment with no value */

        const char* vstart;
        const char* vend;
        int quoted_value = *q == '\'';
        char* decoded = NULL;
        if (quoted_value) {
            vstart = q;
            decoded = parse_string_literal(&q);
            if (!decoded) break;
            vend = q;
        } else {
            vstart = q;
            int depth = 0;
            while (*q) {
                if (*q == '(') { depth++; q++; continue; }
                if (*q == ')') { if (depth == 0) break; depth--; q++; continue; }
                if (depth == 0 && (*q == ',' || *q == ';')) break;
                if (depth == 0 && q > vstart && isspace((unsigned char)q[-1])) {
                    size_t kwlen = 0;
                    if (strncasecmp(q, "WHERE", 5) == 0) kwlen = 5;
                    else if (strncasecmp(q, "RETURNING", 9) == 0) kwlen = 9;
                    if (kwlen && !isalnum((unsigned char)q[kwlen]) && q[kwlen] != '_')
                        break;
                }
                q++;
            }
            vend = q;
            while (vend > vstart && isspace((unsigned char)vend[-1])) vend--;
        }
        if (vend <= vstart) { free(decoded); break; }

        qihse_sql_type_t cast = QIHSE_TYPE_UNKNOWN;
        int param = quoted_value ? 0 : parameter_leaf(vstart, (size_t)(vend - vstart), &cast);
        if (param < 0 || (param && cast != QIHSE_TYPE_UNKNOWN)) { free(decoded); break; }
        if (ast->num_set >= cap) {
            size_t grown_cap = cap * 2;
            char** columns = realloc(ast->set_columns, grown_cap * sizeof(*columns));
            if (!columns) { free(decoded); break; }
            ast->set_columns = columns;
            char** values = realloc(ast->set_values, grown_cap * sizeof(*values));
            if (!values) { free(decoded); break; }
            ast->set_values = values;
            uint16_t* parameters = realloc(ast->set_parameter_indexes,
                                           grown_cap * sizeof(*parameters));
            if (!parameters) { free(decoded); break; }
            ast->set_parameter_indexes = parameters;
            int* quoted = realloc(ast->set_quoted, grown_cap * sizeof(*quoted));
            if (!quoted) { free(decoded); break; }
            ast->set_quoted = quoted;
            cap = grown_cap;
        }
        char* column = dup_token(cstart, clen);
        char* value = quoted_value ? decoded : dup_range(vstart, vend);
        if (!column || !value) { free(column); free(value); break; }
        ast->set_parameter_indexes[ast->num_set] = (uint16_t)param;
        ast->set_quoted[ast->num_set] = quoted_value;
        ast->set_columns[ast->num_set] = column;
        ast->set_values[ast->num_set] = value;
        ast->num_set++;

        p = skip_ws(q);
        if (*p == ',') { p++; continue; }
        break;
    }
    *pp = p;
    return ast->num_set;
}

/* -------------------------------------------------------------------------
 * Skip an optional table alias after the target table of an UPDATE/DELETE.
 *
 * The AST has no alias field for DML, so the alias is dropped, but it must be
 * consumed here or the SET/WHERE clause that follows would not be recognised —
 * and an unrecognised WHERE on DELETE would silently match every row.  A bare
 * alias is only consumed when SET / WHERE / RETURNING follows it, so a
 * malformed statement still fails its keyword check rather than having the
 * keyword eaten as an alias.
 * ------------------------------------------------------------------------- */
static void skip_dml_table_alias(const char** pp) {
    const char* p = skip_ws(*pp);
    const char* as_after = match_kw(p, "AS");
    if (as_after) {
        p = skip_ws(as_after);
        size_t alen = 0;
        const char* astart = read_identifier(p, &alen);
        if (alen > 0) p = astart + alen;
        *pp = p;
        return;
    }
    size_t alen = 0;
    const char* astart = read_identifier(p, &alen);
    if (alen == 0) return;
    const char* after = skip_ws(astart + alen);
    if (match_kw(after, "SET") || match_kw(after, "WHERE") || match_kw(after, "RETURNING"))
        *pp = after;
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
        const char* he = hend;
        while (he > hstart && isspace((unsigned char)he[-1])) he--;
        ast->group_by->having_expr = dup_range(hstart, he);
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
    if (!*p || match_kw(p, "FROM") || *p == ';') {
        qihse_sql_ast_free(ast); return NULL;
    }
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
        char quote = 0;
        while (*p) {
            if (quote) {
                if (*p == quote && p[1] == quote) { p += 2; continue; }
                if (*p == quote) quote = 0;
                p++; continue;
            }
            if (*p == '\'' || *p == '"') { quote = *p++; continue; }
            if (*p == '(') paren_depth++;
            else if (*p == ')') { if (paren_depth == 0) break; paren_depth--; }
            else if (paren_depth == 0 && (*p == ',' || *p == ';')) break;
            else if (paren_depth == 0 && strncasecmp(p, " FROM", 5) == 0) break;
            else if (paren_depth == 0 && strncasecmp(p, "\tFROM", 5) == 0) break;
            else if (paren_depth == 0 && strncasecmp(p, "\nFROM", 5) == 0) break;
            p++;
        }
        if (quote || paren_depth) { qihse_sql_ast_free(ast); return NULL; }
        size_t len = (size_t)(p - start);
        if (len > 0) {
            /* trim trailing ws */
            while (len > 0 && isspace((unsigned char)start[len-1])) len--;
            if (len > 0) {
                if (ast->num_select_items >= item_cap) {
                    item_cap *= 2;
                    ast->select_items = (qihse_sql_select_item_t*)realloc(ast->select_items, item_cap * sizeof(qihse_sql_select_item_t));
                }
                if (!parse_select_item(start, len, &ast->select_items[ast->num_select_items++])) {
                    qihse_sql_ast_free(ast);
                    return NULL;
                }
            }
        }
        p = skip_ws(p);
        if (*p == ',') {
            p++;
            if (!*skip_ws(p) || match_kw(p, "FROM")) {
                qihse_sql_ast_free(ast);
                return NULL;
            }
            continue;
        }
        break;
    }
    if (!ast->num_select_items) { qihse_sql_ast_free(ast); return NULL; }

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

        if (!ast->num_from_tables) { qihse_sql_ast_free(ast); return NULL; }
        /* JOINs */
        parse_joins(&p, ast);
    }

    /* WHERE */
    p = skip_ws(p);
    const char* where_after = match_kw(p, "WHERE");
    if (where_after) {
        p = where_after;
        parse_where(&p, ast);
        if (!ast->num_where_conditions) { qihse_sql_ast_free(ast); return NULL; }
    }

    /* GROUP BY / HAVING */
    const char* group_at = match_kw(p, "GROUP BY");
    parse_group_by(&p, ast);
    if (group_at && (!ast->group_by || !ast->group_by->num_group_columns)) {
        qihse_sql_ast_free(ast); return NULL;
    }

    /* ORDER BY */
    const char* order_at = match_kw(p, "ORDER BY");
    parse_order_by(&p, ast);
    if (order_at && !ast->num_order_items) { qihse_sql_ast_free(ast); return NULL; }

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
        if (!right) { qihse_sql_ast_free(ast); return NULL; }
        /* wrap: current ast becomes left operand */
        qihse_sql_ast_t* wrapper = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        if (!wrapper) { qihse_sql_ast_free(ast); qihse_sql_ast_free(right); return NULL; }
        wrapper->stmt_type = QIHSE_SQL_SELECT;
        wrapper->set_op = sop;
        wrapper->set_left = ast;
        wrapper->set_right = right;
        wrapper->limit = -1;
        wrapper->offset = -1;
        ast = wrapper;
    }

    p = skip_ws(p);
    if (*p == ';') p = skip_ws(p + 1);
    if (*p) { qihse_sql_ast_free(ast); return NULL; }
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

    /* CREATE [UNIQUE] INDEX [IF NOT EXISTS] name ON table
     * [USING method] (expression [ASC|DESC], ...). */
    p = skip_ws(p);
    int unique = 0;
    const char* u_after = match_kw(p, "UNIQUE");
    if (u_after) { unique = 1; p = u_after; }
    const char* idx_after = match_kw(p, "INDEX");
    if (idx_after) {
        p = skip_ws(idx_after);
        int if_not_exists = 0;
        const char* if_after = match_kw(p, "IF");
        if (if_after) {
            const char* not_after = match_kw(if_after, "NOT");
            const char* exists_after = not_after ? match_kw(not_after, "EXISTS") : NULL;
            if (!exists_after) { qihse_sql_ast_free(ast); return NULL; }
            if_not_exists = 1; p = exists_after;
        }
        size_t id_len, tlen;
        const char* id_start = read_identifier(p, &id_len);
        if (!id_len) { qihse_sql_ast_free(ast); return NULL; }
        char* idx_name = dup_token(id_start, id_len);
        p = id_start + id_len;
        const char* on_after = match_kw(p, "ON");
        if (!on_after) { free(idx_name); qihse_sql_ast_free(ast); return NULL; }
        p = skip_ws(on_after);
        const char* tstart = read_identifier(p, &tlen);
        if (!tlen) { free(idx_name); qihse_sql_ast_free(ast); return NULL; }
        char* tbl = dup_token(tstart, tlen);
        p = skip_ws(tstart + tlen);
        char* method = NULL;
        const char* using_after = match_kw(p, "USING");
        if (using_after) {
            p = skip_ws(using_after);
            size_t mlen; const char* mstart = read_identifier(p, &mlen);
            if (!mlen) { free(idx_name); free(tbl); qihse_sql_ast_free(ast); return NULL; }
            method = dup_token(mstart, mlen); p = skip_ws(mstart + mlen);
        }
        if (*p != '(') { free(idx_name); free(tbl); free(method); qihse_sql_ast_free(ast); return NULL; }
        p++;
        qihse_sql_index_def_t* def = calloc(1, sizeof(*def));
        def->name = idx_name; def->table_name = tbl; def->unique = unique;
        def->if_not_exists = if_not_exists; def->using_method = method;
        for (;;) {
            p = skip_ws(p);
            const char* start = p; int depth = 0; char quote = 0;
            while (*p) {
                if (quote) { if (*p == quote && p[1] == quote) { p += 2; continue; }
                    if (*p == quote) quote = 0;
                    p++; continue; }
                if (*p == '\'' || *p == '"') { quote = *p++; continue; }
                if (*p == '(') { depth++; p++; continue; }
                if (*p == ')') { if (!depth) break; depth--; p++; continue; }
                if (*p == ',' && !depth) break;
                p++;
            }
            if (quote || depth || !*p) {
                ast->index_def = def;
                qihse_sql_ast_free(ast);
                return NULL;
            }
            const char* end = p;
            while (end > start && isspace((unsigned char)end[-1])) end--;
            const char* dir = end;
            while (dir > start && (isalnum((unsigned char)dir[-1]) || dir[-1] == '_')) dir--;
            int desc = 0;
            if (dir > start && isspace((unsigned char)dir[-1])) {
                if ((size_t)(end-dir) == 4 && strncasecmp(dir, "DESC", 4) == 0) { desc = 1; end = dir; }
                else if ((size_t)(end-dir) == 3 && strncasecmp(dir, "ASC", 3) == 0) end = dir;
            }
            while (end > start && isspace((unsigned char)end[-1])) end--;
            if (end == start) { qihse_sql_ast_free(ast); free(def->name); free(def->table_name); free(def->using_method); for(size_t i=0;i<def->num_expressions;i++)free(def->expressions[i]);free(def->expressions);free(def->descending);free(def);return NULL; }
            def->expressions = realloc(def->expressions, (def->num_expressions+1)*sizeof(char*));
            def->descending = realloc(def->descending, (def->num_expressions+1)*sizeof(int));
            def->expressions[def->num_expressions] = dup_range(start, end);
            def->descending[def->num_expressions++] = desc;
            if (*p == ',') { p++; continue; }
            if (*p == ')') { p++; break; }
            qihse_sql_ast_free(ast); free(def->name); free(def->table_name); free(def->using_method); for(size_t i=0;i<def->num_expressions;i++)free(def->expressions[i]);free(def->expressions);free(def->descending);free(def);return NULL;
        }
        if (!def->num_expressions) { free(def->name); free(def->table_name); free(def->using_method); free(def); qihse_sql_ast_free(ast); return NULL; }
        def->column_name = strdup(def->expressions[0]);
        ast->index_def = def;
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
            const char* if_after = match_kw(p, "IF");
            if (if_after) {
                const char* not_after = match_kw(if_after, "NOT");
                const char* exists_after = not_after ? match_kw(not_after, "EXISTS") : NULL;
                if (!exists_after) { qihse_sql_ast_free(ast); return NULL; }
                ast->view_if_not_exists = 1;
                p = exists_after;
            }
            size_t vlen;
            const char* vstart = read_identifier(p, &vlen);
            if (!vlen) { qihse_sql_ast_free(ast); return NULL; }
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
            ast->view_is_materialized = 1;
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

    /* CREATE TABLE [IF NOT EXISTS] name ( col defs ) */
    const char* tbl_after = match_kw(p, "TABLE");
    if (!tbl_after) { ast->stmt_type = QIHSE_SQL_UNKNOWN; *pp = p; return ast; }
    p = tbl_after;
    const char* if_after = match_kw(p, "IF");
    if (if_after) {
        const char* not_after = match_kw(if_after, "NOT");
        const char* exists_after = not_after ? match_kw(not_after, "EXISTS") : NULL;
        if (!exists_after) { qihse_sql_ast_free(ast); return NULL; }
        ast->create_if_not_exists = 1;
        p = exists_after;
    }
    size_t id_len;
    const char* id_start = read_identifier(p, &id_len);
    ast->table_name = dup_token(id_start, id_len);
    p = id_start + id_len;
    p = skip_ws(p);
    if (*p == '(') {
        p++;
        int closed = 0;
        int after_comma = 0;
        size_t col_cap = 8;
        ast->columns = (qihse_sql_column_def_t*)calloc(col_cap, sizeof(qihse_sql_column_def_t));
        ast->num_columns = 0;
        for (;;) {
            p = skip_ws(p);
            if (*p == ')') {
                if (after_comma) { qihse_sql_ast_free(ast); return NULL; }
                p++; closed = 1; break;
            }
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
            after_comma = 0;
            /* trim */
            while (seg_len > 0 && isspace((unsigned char)seg_start[seg_len-1])) seg_len--;
            if (!seg_len) { qihse_sql_ast_free(ast); return NULL; }
            /* A malformed constraint must not disappear from the AST: the
             * executor cannot reject a constraint it never sees. */
            size_t constraints_before = ast->num_fks + ast->num_checks + ast->num_uniques;
            if (parse_table_constraint(seg_start, seg_len, ast)) {
                if (ast->num_fks + ast->num_checks + ast->num_uniques ==
                    constraints_before ||
                    (ast->num_uniques > 0 &&
                     ast->uniques[ast->num_uniques - 1].num_columns == 0)) {
                    qihse_sql_ast_free(ast);
                    return NULL;
                }
            } else if (seg_len > 0) {
                if (ast->num_columns >= col_cap) {
                    col_cap *= 2;
                    ast->columns = (qihse_sql_column_def_t*)realloc(ast->columns, col_cap * sizeof(qihse_sql_column_def_t));
                }
                char* seg_copy = dup_token(seg_start, seg_len);
                parse_column_def(seg_copy, &ast->columns[ast->num_columns++]);
                free(seg_copy);
                if (ast->columns[ast->num_columns - 1].type == QIHSE_TYPE_UNKNOWN) {
                    qihse_sql_ast_free(ast);
                    return NULL;
                }
            }
            p = skip_ws(p);
            if (*p == ',') { p++; after_comma = 1; continue; }
            if (*p == ')') { p++; closed = 1; break; }
            break;
        }
        if (!closed) { qihse_sql_ast_free(ast); return NULL; }
        /* Table-level PK may precede its column definitions. */
        for (size_t k = 0; k < ast->num_uniques; ++k) {
            qihse_sql_unique_t* key = &ast->uniques[k];
            if (!key->name || strcmp(key->name, "PRIMARY")) continue;
            for (size_t j = 0; j < key->num_columns; ++j)
                for (size_t c = 0; c < ast->num_columns; ++c)
                    if (ast->columns[c].name && key->columns[j] &&
                        !strcasecmp(ast->columns[c].name, key->columns[j]))
                        ast->columns[c].is_primary_key = 1;
        }
    } else { qihse_sql_ast_free(ast); return NULL; }
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
        int depth = 0;
        while (*p && *p != ';') {
            if (*p == '(') depth++;
            else if (*p == ')') depth--;
            if (*p == ',' && depth == 0) break;
            p++;
        }
        char* seg = dup_range(seg_start, p);
        ast->alter_clause->action = QIHSE_ALTER_ADD_COLUMN;
        ast->alter_clause->add_column = (qihse_sql_column_def_t*)calloc(1, sizeof(qihse_sql_column_def_t));
        parse_column_def(seg, ast->alter_clause->add_column);
        free(seg);
        if (ast->alter_clause->add_column->type == QIHSE_TYPE_UNKNOWN) {
            qihse_sql_ast_free(ast);
            return NULL;
        }
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

    const char* trigger_after = match_kw(p, "TRIGGER");
    const char* idx_after = match_kw(p, "INDEX");
    const char* tbl_after = match_kw(p, "TABLE");
    if (trigger_after) {
        p = skip_ws(trigger_after);
        const char* if_after = match_kw(p, "IF");
        if (if_after) {
            const char* exists_after = match_kw(if_after, "EXISTS");
            if (!exists_after) { qihse_sql_ast_free(ast); return NULL; }
            ast->trigger_def = calloc(1, sizeof(*ast->trigger_def));
            ast->trigger_def->drop_if_exists = 1;
            p = exists_after;
        } else ast->trigger_def = calloc(1, sizeof(*ast->trigger_def));
        p = skip_ws(p); size_t nlen; const char* nstart = read_identifier(p, &nlen);
        if (!nlen) { qihse_sql_ast_free(ast); return NULL; }
        ast->trigger_def->name = dup_token(nstart, nlen);
        p = skip_ws(nstart + nlen);
        const char* on_after = match_kw(p, "ON");
        if (!on_after) { qihse_sql_ast_free(ast); return NULL; }
        p = skip_ws(on_after); const char* tstart = read_identifier(p, &nlen);
        if (!nlen) { qihse_sql_ast_free(ast); return NULL; }
        ast->trigger_def->table_name = dup_token(tstart, nlen); p = tstart + nlen;
        ast->stmt_type = QIHSE_SQL_DROP_TRIGGER;
        *pp = p;
        return ast;
    } else if (idx_after) {
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
    while (*p) {
        if (*p == '\'' && p[1] == '\'') { p += 2; continue; }
        if (*p == '\'') break;
        ++p;
    }
    if (*p != '\'') return NULL;
    char* out = malloc((size_t)(p - start) + 1);
    if (!out) return NULL;
    size_t n = 0;
    for (const char* s = start; s < p; ++s) {
        out[n++] = *s;
        if (*s == '\'') ++s;
    }
    out[n] = '\0';
    *pp = p + 1;
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
            const char* iso = match_kw(p, "ISOLATION LEVEL");
            if (iso) {
                const char* level = match_kw(iso, "SERIALIZABLE");
                if (!level) level = match_kw(iso, "REPEATABLE READ");
                if (!level) level = match_kw(iso, "READ COMMITTED");
                if (!level) level = match_kw(iso, "READ UNCOMMITTED");
                if (!level) break;
                p = level;
                continue;
            }
            /* Retain the native SQL dispatcher's existing shorthand. */
            const char* serializable = match_kw(p, "SERIALIZABLE");
            if (serializable) { p = serializable; continue; }
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

/* Parse only the ON CONFLICT forms represented by qihse_sql_on_conflict_t.
 * An expression is retained as text; evaluating it is the consumer's job. */
static int parse_on_conflict(const char** pp, qihse_sql_ast_t* ast) {
    const char* p = skip_ws(*pp);
    qihse_sql_on_conflict_t* conflict = calloc(1, sizeof(*conflict));
    if (!conflict) return 0;
    ast->on_conflict = conflict;
    if (*p == '(') {
        p++;
        for (;;) {
            size_t len;
            const char* start = read_identifier(p, &len);
            if (!len || conflict->num_conflict_columns >= 64 ||
                memchr(start, '.', len)) return 0;
            char* name = dup_token(start, len);
            char** columns = realloc(conflict->conflict_columns,
                                     (conflict->num_conflict_columns + 1) * sizeof(char*));
            if (!name || !columns) { free(name); return 0; }
            conflict->conflict_columns = columns;
            columns[conflict->num_conflict_columns++] = name;
            p = skip_ws(start + len);
            if (*p == ')') { p++; break; }
            if (*p != ',') return 0;
            p++;
        }
    }
    p = match_kw(p, "DO");
    if (!p) return 0;
    const char* after = match_kw(p, "NOTHING");
    if (after) {
        conflict->action = QIHSE_CONFLICT_NOTHING;
        *pp = after;
        return 1;
    }
    p = match_kw(p, "UPDATE");
    if (!p || !conflict->num_conflict_columns) return 0;
    p = match_kw(p, "SET");
    if (!p) return 0;
    qihse_sql_ast_t assignments = {0};
    const char* set_start = p;
    if (strlen(set_start) > 8192) return 0;
    size_t count = parse_set_list(&p, &assignments);
    conflict->set_columns = assignments.set_columns;
    conflict->set_values = assignments.set_values;
    conflict->num_set = assignments.num_set;
    free(assignments.set_parameter_indexes);
    free(assignments.set_quoted);
    const char* last = p;
    while (last > set_start && isspace((unsigned char)last[-1])) last--;
    if (!count || count > 64 || (size_t)(p - set_start) > 8192 ||
        (last > set_start && last[-1] == ',')) return 0;
    conflict->action = QIHSE_CONFLICT_UPDATE;
    after = match_kw(p, "WHERE");
    if (after) {
        const char* start = skip_ws(after);
        const char* end = start;
        int depth = 0, quoted = 0;
        while (*end && *end != ';') {
            if (*end == '\'') {
                if (quoted && end[1] == '\'') { end += 2; continue; }
                quoted = !quoted;
            } else if (!quoted) {
                if (*end == '(') depth++;
                else if (*end == ')') { if (!depth) return 0; depth--; }
                if (!depth && end > start && isspace((unsigned char)end[-1]) &&
                    match_kw(end, "RETURNING")) break;
            }
            end++;
            if ((size_t)(end - start) > 8192) return 0;
        }
        if (quoted || depth || end == start) return 0;
        while (end > start && isspace((unsigned char)end[-1])) end--;
        conflict->where_expr = dup_range(start, end);
        if (!conflict->where_expr) return 0;
        p = end;
    }
    *pp = p;
    return 1;
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
        if (!tlen) goto bad_insert;
        ast->table_name = dup_token(tstart, tlen);
        if (!ast->table_name) goto bad_insert;
        cur = skip_ws(tstart + tlen);
        /* Optional column list */
        if (*cur == '(') {
            cur++;
            size_t col_cap = 8;
            ast->insert_columns = (char**)calloc(col_cap, sizeof(char*));
            if (!ast->insert_columns) goto bad_insert;
            ast->num_insert_columns = 0;
            for (;;) {
                cur = skip_ws(cur);
                size_t clen;
                const char* cstart = read_identifier(cur, &clen);
                if (clen == 0) goto bad_insert;
                if (ast->num_insert_columns >= col_cap) {
                    if (col_cap > SIZE_MAX / 2 / sizeof(char*)) goto bad_insert;
                    col_cap *= 2;
                    char** grown = realloc(ast->insert_columns, col_cap * sizeof(char*));
                    if (!grown) goto bad_insert;
                    ast->insert_columns = grown;
                }
                ast->insert_columns[ast->num_insert_columns] = dup_token(cstart, clen);
                if (!ast->insert_columns[ast->num_insert_columns]) goto bad_insert;
                ast->num_insert_columns++;
                cur = cstart + clen;
                cur = skip_ws(cur);
                if (*cur == ',') { cur++; continue; }
                if (*cur == ')') { cur++; break; }
                goto bad_insert;
            }
        }
        cur = skip_ws(cur);
        /* VALUES or SELECT */
        const char* values_after = match_kw(cur, "VALUES");
        if (values_after) {
            cur = values_after;
            cur = skip_ws(cur);
            /* Every row owns parallel value, cast and quotedness arrays.  Keep
             * the value array NULL-terminated even on parse failure. */
            size_t width = ast->num_insert_columns;
            do {
                cur = skip_ws(cur);
                if (*cur++ != '(') goto bad_insert;
                size_t cap = width ? width : 8;
                char** values = calloc(cap + 1, sizeof(*values));
                qihse_sql_type_t* casts = calloc(cap, sizeof(*casts));
                int* quoted = calloc(cap, sizeof(*quoted));
                uint16_t* parameters = calloc(cap, sizeof(*parameters));
                if (!values || !casts || !quoted || !parameters) {
                    free(values); free(casts); free(quoted); free(parameters);
                    goto bad_insert;
                }
                size_t nvalues = 0;
                for (;;) {
                    cur = skip_ws(cur);
                    if (!*cur || *cur == ')' || *cur == ',') goto bad_insert_row;
                    if (nvalues == cap) {
                        if (width || cap > SIZE_MAX / 2 / sizeof(char*)) goto bad_insert_row;
                        size_t next = cap * 2;
                        char** grown_values = realloc(values, (next + 1) * sizeof(*values));
                        if (!grown_values) goto bad_insert_row;
                        values = grown_values;
                        memset(values + cap, 0, (next + 1 - cap) * sizeof(*values));
                        qihse_sql_type_t* grown_casts = realloc(casts, next * sizeof(*casts));
                        if (!grown_casts) goto bad_insert_row;
                        casts = grown_casts;
                        int* grown_quoted = realloc(quoted, next * sizeof(*quoted));
                        if (!grown_quoted) goto bad_insert_row;
                        quoted = grown_quoted;
                        uint16_t* grown_parameters = realloc(parameters, next * sizeof(*parameters));
                        if (!grown_parameters) goto bad_insert_row;
                        parameters = grown_parameters;
                        memset(parameters + cap, 0, (next - cap) * sizeof(*parameters));
                        cap = next;
                    }
                    if (*cur == '\'') {
                        quoted[nvalues] = 1;
                        cur++;
                        const char* start = cur;
                        size_t len = 0;
                        while (*cur) {
                            if (*cur == '\'') {
                                if (cur[1] == '\'') { cur += 2; len++; continue; }
                                break;
                            }
                            cur++; len++;
                        }
                        if (*cur != '\'') goto bad_insert_row;
                        values[nvalues] = malloc(len + 1);
                        if (!values[nvalues]) goto bad_insert_row;
                        char* dst = values[nvalues];
                        for (const char* s = start; s < cur; s++) {
                            *dst++ = *s;
                            if (*s == '\'' && s[1] == '\'') s++;
                        }
                        *dst = '\0';
                        cur = skip_ws(cur + 1);
                        if (cur[0] == ':' && cur[1] == ':') {
                            cur = skip_ws(cur + 2);
                            const char* cast_start = cur;
                            while (isalnum((unsigned char)*cur) || *cur == '_') cur++;
                            size_t cast_len = (size_t)(cur - cast_start);
                            if (cast_len == 9 && strncasecmp(cast_start, "timestamp", 9) == 0)
                                casts[nvalues] = QIHSE_TYPE_TIMESTAMP;
                            else if (cast_len == 11 && strncasecmp(cast_start, "timestamptz", 11) == 0)
                                casts[nvalues] = QIHSE_TYPE_TIMESTAMPTZ;
                            else goto bad_insert_row;
                        }
                    } else {
                        const char* start = cur;
                        while (*cur && *cur != ',' && *cur != ')' && *cur != ';') cur++;
                        const char* end = cur;
                        while (end > start && isspace((unsigned char)end[-1])) end--;
                        if (end == start || memchr(start, '\'', (size_t)(end - start))) goto bad_insert_row;
                        int param = parameter_leaf(start, (size_t)(end - start), &casts[nvalues]);
                        if (param < 0 || (param == 0 && memchr(start, ':', (size_t)(end - start))))
                            goto bad_insert_row;
                        parameters[nvalues] = (uint16_t)param;
                        for (const char* s = start; s < end; s++)
                            if (isspace((unsigned char)*s)) goto bad_insert_row;
                        values[nvalues] = dup_range(start, end);
                        if (!values[nvalues]) goto bad_insert_row;
                    }
                    nvalues++;
                    cur = skip_ws(cur);
                    if (*cur == ')') { cur++; break; }
                    if (*cur != ',') goto bad_insert_row;
                    cur++;
                }
                if (!width) width = nvalues;
                if (nvalues != width) goto bad_insert_row;
                size_t row = ast->num_insert_rows;
                char*** rows = realloc(ast->insert_rows, (row + 1) * sizeof(*rows));
                if (!rows) goto bad_insert_row;
                ast->insert_rows = rows;
                qihse_sql_type_t** row_casts = realloc(ast->insert_cast_types, (row + 1) * sizeof(*row_casts));
                if (!row_casts) goto bad_insert_row;
                ast->insert_cast_types = row_casts;
                int** row_quoted = realloc(ast->insert_quoted, (row + 1) * sizeof(*row_quoted));
                if (!row_quoted) goto bad_insert_row;
                ast->insert_quoted = row_quoted;
                uint16_t** row_parameters = realloc(ast->insert_parameter_indexes,
                                                     (row + 1) * sizeof(*row_parameters));
                if (!row_parameters) goto bad_insert_row;
                ast->insert_parameter_indexes = row_parameters;
                ast->insert_rows[row] = values;
                ast->insert_cast_types[row] = casts;
                ast->insert_quoted[row] = quoted;
                ast->insert_parameter_indexes[row] = parameters;
                ast->num_insert_rows++;
                cur = skip_ws(cur);
                if (*cur != ',') break;
                cur++;
                if (*skip_ws(cur) != '(') goto bad_insert;
                continue;
            bad_insert_row:
                for (size_t i = 0; i < cap; i++) free(values[i]);
                free(values); free(casts); free(quoted); free(parameters);
                goto bad_insert;
            } while (1);
        }
        cur = skip_ws(cur);
        /* ON CONFLICT (UPSERT) */
        const char* on_after = match_kw(cur, "ON");
        if (on_after) {
            const char* conflict_after = match_kw(on_after, "CONFLICT");
            if (!conflict_after || !parse_on_conflict(&conflict_after, ast)) {
                qihse_sql_ast_free(ast); free(work); return NULL;
            }
            cur = conflict_after;
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
        cur = skip_ws(cur);
        if (*cur == ';') cur = skip_ws(cur + 1);
        if (*cur || !values_after || !ast->num_insert_rows ||
            (ast->returning && !ast->returning->is_star && !ast->returning->num_columns))
            goto bad_insert;
        goto insert_done;
    bad_insert:
        qihse_sql_ast_free(ast); free(work); return NULL;
    insert_done:;
    } else if (strncasecmp(cur, "UPDATE", 6) == 0 && !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
        ast->stmt_type = QIHSE_SQL_UPDATE;
        ast->limit = -1; ast->offset = -1;
        cur += 6;
        cur = skip_ws(cur);
        size_t tlen;
        const char* tstart = read_identifier(cur, &tlen);
        if (tlen > 0) { ast->table_name = dup_token(tstart, tlen); cur = tstart + tlen; }
        skip_dml_table_alias(&cur);
        cur = skip_ws(cur);
        /* SET list */
        const char* set_after = match_kw(cur, "SET");
        if (set_after) {
            cur = set_after;
            (void)parse_set_list(&cur, ast);
        }
        if (ast->num_set == 0) {
            /* An UPDATE with no assignments cannot modify anything.  Refuse it
             * (NULL = parse error for every caller) instead of returning an AST
             * that callers would execute as a silent no-op. */
            qihse_sql_ast_free(ast);
            free(work);
            return NULL;
        }
        /* WHERE — structured, the same representation SELECT and DELETE use */
        cur = skip_ws(cur);
        const char* where_after = match_kw(cur, "WHERE");
        if (where_after) {
            cur = where_after;
            parse_where(&cur, ast);
        }
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
        skip_dml_table_alias(&cur);
        cur = skip_ws(cur);
        /* WHERE — parsed into structured conditions, not kept as raw text */
        const char* where_after = match_kw(cur, "WHERE");
        if (where_after) {
            cur = where_after;
            parse_where(&cur, ast);
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
    } else if (strncasecmp(cur, "CREATE", 6) == 0 &&
               !isalnum((unsigned char)cur[6]) && cur[6] != '_') {
        /* Recognize extension and procedural DDL without claiming execution;
         * parsing must consume every suffix, including dollar-quoted bodies. */
        const char* kind = skip_ws(cur + 6);
        if (strncasecmp(kind, "OR REPLACE", 10) == 0 &&
            !isalnum((unsigned char)kind[10]) && kind[10] != '_')
            kind = skip_ws(kind + 10);
        qihse_sql_stmt_type_t opaque_type = QIHSE_SQL_UNKNOWN;
        if (strncasecmp(kind, "EXTENSION", 9) == 0 &&
            !isalnum((unsigned char)kind[9]) && kind[9] != '_')
            opaque_type = QIHSE_SQL_CREATE_EXTENSION;
        else if (strncasecmp(kind, "FUNCTION", 8) == 0 &&
                 !isalnum((unsigned char)kind[8]) && kind[8] != '_')
            opaque_type = QIHSE_SQL_CREATE_FUNCTION;
        else if (strncasecmp(kind, "PROCEDURE", 9) == 0 &&
                 !isalnum((unsigned char)kind[9]) && kind[9] != '_')
            opaque_type = QIHSE_SQL_CREATE_PROCEDURE;
        else if (strncasecmp(kind, "TRIGGER", 7) == 0 &&
                 !isalnum((unsigned char)kind[7]) && kind[7] != '_')
            opaque_type = QIHSE_SQL_CREATE_TRIGGER;
        if (opaque_type == QIHSE_SQL_CREATE_FUNCTION) {
            const char* fp = skip_ws(kind + 8);
            ast = calloc(1, sizeof(*ast));
            ast->limit = -1; ast->offset = -1;
            ast->stmt_type = opaque_type;
            ast->function_def = calloc(1, sizeof(*ast->function_def));
            ast->function_def->or_replace = kind != skip_ws(cur + 6);
            size_t nlen; const char* nstart = read_identifier(fp, &nlen);
            if (!nlen) { qihse_sql_ast_free(ast); ast = NULL; }
            else {
                ast->function_def->name = dup_token(nstart, nlen);
                fp = skip_ws(nstart + nlen);
                const char* args_end = find_matching_paren(fp);
                const char* ret = args_end ? match_kw(args_end + 1, "RETURNS") : NULL;
                if (!args_end || args_end != fp + 1 || !ret) { qihse_sql_ast_free(ast); ast = NULL; }
                else {
                    const char* rstart = read_identifier(ret, &nlen);
                    if (!nlen) { qihse_sql_ast_free(ast); ast = NULL; }
                    else {
                        ast->function_def->returns = dup_token(rstart, nlen);
                        fp = match_kw(rstart + nlen, "AS");
                        fp = fp ? skip_ws(fp) : NULL;
                        const char* delim_end = fp && *fp == '$' ? strchr(fp + 1, '$') : NULL;
                        if (!delim_end) { qihse_sql_ast_free(ast); ast = NULL; }
                        else {
                            size_t delim_len = (size_t)(delim_end - fp + 1);
                            char* delimiter = dup_token(fp, delim_len);
                            const char* body_end = delimiter ? strstr(delim_end + 1, delimiter) : NULL;
                            free(delimiter);
                            if (!body_end) { qihse_sql_ast_free(ast); ast = NULL; }
                            else {
                                ast->function_def->body = dup_range(delim_end + 1, body_end);
                                fp = match_kw(body_end + delim_len, "LANGUAGE");
                                if (!fp) { qihse_sql_ast_free(ast); ast = NULL; }
                                else {
                                    const char* lstart = read_identifier(fp, &nlen);
                                    if (!nlen) { qihse_sql_ast_free(ast); ast = NULL; }
                                    else {
                                        ast->function_def->language = dup_token(lstart, nlen);
                                        cur = lstart + nlen;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (opaque_type == QIHSE_SQL_CREATE_TRIGGER) {
            ast = calloc(1, sizeof(*ast)); ast->limit = -1; ast->offset = -1;
            ast->stmt_type = opaque_type; ast->trigger_def = calloc(1, sizeof(*ast->trigger_def));
            ast->trigger_def->or_replace = strcasestr(sql, "OR REPLACE") != NULL;
            const char* tp = skip_ws(kind + 7); size_t nlen; const char* nstart = read_identifier(tp, &nlen);
            if (!nlen) { qihse_sql_ast_free(ast); ast = NULL; }
            else {
                ast->trigger_def->name = dup_token(nstart, nlen);
                tp = match_kw(nstart + nlen, "BEFORE");
                if (tp) ast->trigger_def->timing = strdup("BEFORE");
                else if ((tp = match_kw(nstart + nlen, "AFTER")))
                    ast->trigger_def->timing = strdup("AFTER");
                else if ((tp = match_kw(nstart + nlen, "INSTEAD OF")))
                    ast->trigger_def->timing = strdup("INSTEAD OF");
                const char* event = tp ? skip_ws(tp) : NULL;
                const char* on = event ? match_kw(event, "UPDATE") : NULL;
                if (on) ast->trigger_def->event = strdup("UPDATE");
                else if (event && (on = match_kw(event, "INSERT")))
                    ast->trigger_def->event = strdup("INSERT");
                else if (event && (on = match_kw(event, "DELETE")))
                    ast->trigger_def->event = strdup("DELETE");
                on = on ? match_kw(on, "ON") : NULL;
                size_t tlen = 0;
                const char* tstart = on ? read_identifier(on, &tlen) : NULL;
                if (tlen) ast->trigger_def->table_name = dup_token(tstart, tlen);
                tp = tlen ? match_kw(tstart + tlen, "FOR EACH ROW") : NULL;
                if (tp) ast->trigger_def->for_each_row = 1;
                const char* exec = tp ? match_kw(tp, "EXECUTE FUNCTION") : NULL;
                size_t flen = 0;
                const char* fn = exec ? read_identifier(exec, &flen) : NULL;
                if (flen) ast->trigger_def->function_name = dup_token(fn, flen);
                const char* args = flen ? skip_ws(fn + flen) : NULL;
                if (!args || *args != '(' || !find_matching_paren(args) ||
                    find_matching_paren(args) != args + 1) {
                    qihse_sql_ast_free(ast); ast = NULL;
                } else cur = args + 2;
            }
        } else if (opaque_type == QIHSE_SQL_CREATE_EXTENSION) {
            const char* ep = skip_ws(kind + 9);
            ast = calloc(1, sizeof(*ast));
            if (ast) {
                ast->stmt_type = opaque_type;
                ast->util = util_new();
                const char* if_after = match_kw(ep, "IF");
                if (if_after) {
                    const char* not_after = match_kw(if_after, "NOT");
                    const char* exists_after = not_after ? match_kw(not_after, "EXISTS") : NULL;
                    if (!exists_after) { qihse_sql_ast_free(ast); ast = NULL; }
                    else { ast->create_if_not_exists = 1; ep = exists_after; }
                }
                if (ast) {
                    size_t nlen = 0;
                    const char* name = read_identifier(ep, &nlen);
                    if (!nlen || !ast->util) { qihse_sql_ast_free(ast); ast = NULL; }
                    else { ast->util->name = dup_token(name, nlen); cur = name + nlen;
                        if (*skip_ws(ep) == '"' && *cur == '"') cur++;
                    }
                }
            }
        } else if (opaque_type == QIHSE_SQL_CREATE_PROCEDURE) {
            /* Procedures remain opaque and are never executable through this
             * parser, but their delimiter and complete suffix are validated. */
            const char* proc = skip_ws(kind + 9);
            size_t nlen = 0;
            const char* name = read_identifier(proc, &nlen);
            const char* args = nlen ? skip_ws(name + nlen) : NULL;
            const char* close_args = args ? find_matching_paren(args) : NULL;
            const char* language = close_args ? match_kw(close_args + 1, "LANGUAGE") : NULL;
            const char* lang_name = language ? read_identifier(language, &nlen) : NULL;
            const char* as = lang_name && nlen ? match_kw(lang_name + nlen, "AS") : NULL;
            const char* dollar = as ? skip_ws(as) : NULL;
            const char* delimiter_end = dollar && *dollar == '$' ? strchr(dollar + 1, '$') : NULL;
            if (args && close_args == args + 1 && delimiter_end) {
                size_t len = (size_t)(delimiter_end - dollar + 1);
                char* delimiter = dup_token(dollar, len);
                const char* body_end = delimiter ? strstr(delimiter_end + 1, delimiter) : NULL;
                free(delimiter);
                if (body_end) {
                    ast = calloc(1, sizeof(*ast));
                    if (ast) { ast->stmt_type = opaque_type; cur = body_end + len; }
                }
            }
        } else {
            cur += 6;
            ast = parse_create(&cur);
        }
        if (ast && ast->stmt_type == QIHSE_SQL_CREATE &&
            !ast->index_def && ast->table_name) {
            const char* tail = skip_ws(cur);
            if (*tail == ';') tail = skip_ws(tail + 1);
            if (*tail) { qihse_sql_ast_free(ast); ast = NULL; }
        }
    } else if (match_kw(cur, "REFRESH")) {
        cur = match_kw(cur, "REFRESH");
        const char* mat = match_kw(cur, "MATERIALIZED VIEW");
        if (mat) {
            size_t nlen = 0;
            const char* name = read_identifier(mat, &nlen);
            if (nlen) {
                ast = calloc(1, sizeof(*ast));
                if (ast) {
                    ast->stmt_type = QIHSE_SQL_REFRESH;
                    ast->view_is_materialized = 1;
                    ast->view_name = dup_token(name, nlen);
                    cur = name + nlen;
                }
            }
        }
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

    /* Every supported grammar must consume its complete statement.  Never
     * return a valid-looking prefix for a second command or malformed suffix. */
    if (ast) {
        const char* tail = skip_ws(cur);
        if (*tail == ';') tail = skip_ws(tail + 1);
        if (*tail || ast->stmt_type == QIHSE_SQL_UNKNOWN ||
            (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW && !ast->view_query) ||
            (ast->stmt_type == QIHSE_SQL_CREATE_VIEW && !ast->view_query)) {
            qihse_sql_ast_free(ast);
            ast = NULL;
        }
    }
    free(work);
    if (ast && !ast->raw_sql) ast->raw_sql = strdup(sql);
    return ast;
}

/* Match raw placeholders against the typed leaves: a repeated $n is fine,
 * but a parameter hidden inside an unsupported expression is never bound. */
static int count_ast_parameters(const qihse_sql_ast_t* ast, unsigned* counts) {
    if (!ast) return 1;
    for (size_t i = 0; i < ast->num_where_conditions; ++i) {
        const qihse_sql_condition_t* c = &ast->where_conditions[i];
        if (c->value_parameter_index) {
            if (c->value_parameter_index > QIHSE_SQL_MAX_PARAMETERS) return 0;
            counts[c->value_parameter_index]++;
        }
        if (!count_ast_parameters(c->subquery, counts)) return 0;
    }
    for (size_t i = 0; i < ast->num_set; ++i) {
        unsigned n = ast->set_parameter_indexes ? ast->set_parameter_indexes[i] : 0;
        if (n > QIHSE_SQL_MAX_PARAMETERS) return 0;
        if (n) counts[n]++;
    }
    for (size_t r = 0; r < ast->num_insert_rows; ++r) {
        if (!ast->insert_rows[r] || !ast->insert_parameter_indexes) return 0;
        for (size_t i = 0; ast->insert_rows[r][i]; ++i) {
            unsigned n = ast->insert_parameter_indexes[r][i];
            if (n > QIHSE_SQL_MAX_PARAMETERS) return 0;
            if (n) counts[n]++;
        }
    }
    for (size_t i = 0; i < ast->num_select_items; ++i)
        if (!count_ast_parameters(ast->select_items[i].scalar_subquery, counts)) return 0;
    if (!count_ast_parameters(ast->set_left, counts) ||
        !count_ast_parameters(ast->set_right, counts) ||
        !count_ast_parameters(ast->view_query, counts) ||
        !count_ast_parameters(ast->explain_query, counts)) return 0;
    if (ast->with_clause) {
        for (size_t i = 0; i < ast->with_clause->num_ctes; ++i)
            if (!count_ast_parameters(ast->with_clause->ctes[i].query, counts)) return 0;
        if (!count_ast_parameters(ast->with_clause->body, counts)) return 0;
    }
    if (ast->cursor_def && !count_ast_parameters(ast->cursor_def->query, counts)) return 0;
    if (ast->util && !count_ast_parameters(ast->util->subquery, counts)) return 0;
    return 1;
}

static int count_sql_parameters(const char* sql, unsigned* counts) {
    if (!sql) return 0;
    const char* p = sql;
    while (*p) {
        if (*p == '\'' || *p == '"') {
            char quote = *p++;
            while (*p) {
                if (*p == quote) {
                    if (p[1] == quote) { p += 2; continue; }
                    break;
                }
                if (*p == '\\' && p[1]) p += 2;
                else p++;
            }
            if (!*p) return 0;
            p++;
            continue;
        }
        if (p[0] == '-' && p[1] == '-') {
            p += 2;
            while (*p && *p != '\n') p++;
            continue;
        }
        if (p[0] == '/' && p[1] == '*') {
            const char* end = strstr(p + 2, "*/");
            if (!end) return 0;
            p = end + 2;
            continue;
        }
        if (*p != '$') { p++; continue; }
        const char* tag = p + 1;
        while (isalnum((unsigned char)*tag) || *tag == '_') tag++;
        if (*tag == '$' && (tag == p + 1 || isalpha((unsigned char)p[1]) || p[1] == '_')) {
            size_t delimiter_len = (size_t)(tag + 1 - p);
            const char* body = tag + 1;
            const char* end = NULL;
            for (const char* q = body; *q; ++q)
                if (*q == '$' && strncmp(q, p, delimiter_len) == 0) { end = q; break; }
            if (!end) return 0;
            p = end + delimiter_len;
            continue;
        }
        p++;
        if (!isdigit((unsigned char)*p)) return 0;
        unsigned n = 0;
        do {
            n = n * 10 + (unsigned)(*p++ - '0');
            if (n > QIHSE_SQL_MAX_PARAMETERS) return 0;
        } while (isdigit((unsigned char)*p));
        if (!n || isalnum((unsigned char)*p) || *p == '_') return 0;
        counts[n]++;
    }
    return 1;
}

int qihse_sql_ast_parameters_valid(const qihse_sql_ast_t* ast) {
    if (!ast || !ast->raw_sql) return 0;
    unsigned parsed[QIHSE_SQL_MAX_PARAMETERS + 1] = {0};
    unsigned source[QIHSE_SQL_MAX_PARAMETERS + 1] = {0};
    if (!count_ast_parameters(ast, parsed) || !count_sql_parameters(ast->raw_sql, source)) return 0;
    unsigned max = 0;
    for (unsigned i = 1; i <= QIHSE_SQL_MAX_PARAMETERS; ++i) {
        if (parsed[i] != source[i]) return 0;
        if (parsed[i]) max = i;
    }
    for (unsigned i = 1; i <= max; ++i) if (!parsed[i]) return 0;
    return 1;
}

size_t qihse_sql_ast_parameter_count(const qihse_sql_ast_t* ast) {
    if (!qihse_sql_ast_parameters_valid(ast)) return 0;
    unsigned counts[QIHSE_SQL_MAX_PARAMETERS + 1] = {0};
    count_ast_parameters(ast, counts);
    for (size_t i = QIHSE_SQL_MAX_PARAMETERS; i > 0; --i)
        if (counts[i]) return i;
    return 0;
}

qihse_sql_ast_t* qihse_parse_sql_to_ast(const char* sql) {
    qihse_sql_ast_t* ast = parse_statement(sql);
    if (ast && !qihse_sql_ast_parameters_valid(ast)) {
        qihse_sql_ast_free(ast);
        return NULL;
    }
    return ast;
}

/* -------------------------------------------------------------------------
 * Free
 * ------------------------------------------------------------------------- */
static void free_column_def(qihse_sql_column_def_t* c) {
    if (!c) return;
    free(c->name);
    free(c->default_expr);
    free(c->generated_expr);
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
        if (ast->select_items[i].agg_case) {
            free(ast->select_items[i].agg_case->column);
            free(ast->select_items[i].agg_case);
        }
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
    if (ast->trigger_def) {
        free(ast->trigger_def->name); free(ast->trigger_def->table_name);
        free(ast->trigger_def->timing); free(ast->trigger_def->event);
        free(ast->trigger_def->function_name); free(ast->trigger_def);
    }
    if (ast->function_def) {
        free(ast->function_def->name); free(ast->function_def->returns);
        free(ast->function_def->language); free(ast->function_def->body);
        free(ast->function_def);
    }
    if (ast->index_def) {
        free(ast->index_def->name);
        free(ast->index_def->table_name);
        free(ast->index_def->column_name);
        for (size_t i = 0; i < ast->index_def->num_expressions; ++i)
            free(ast->index_def->expressions[i]);
        free(ast->index_def->expressions);
        free(ast->index_def->descending);
        free(ast->index_def->using_method);
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
    for (size_t i = 0; i < ast->num_insert_rows; i++) {
        free(ast->insert_cast_types[i]);
        free(ast->insert_quoted[i]);
        free(ast->insert_parameter_indexes[i]);
    }
    free(ast->insert_cast_types);
    free(ast->insert_quoted);
    free(ast->insert_parameter_indexes);
    free(ast->insert_select_query);
    /* update set */
    for (size_t i = 0; i < ast->num_set; i++) {
        free(ast->set_columns[i]);
        free(ast->set_values[i]);
    }
    free(ast->set_columns);
    free(ast->set_values);
    free(ast->set_quoted);
    free(ast->set_parameter_indexes);
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
        case QIHSE_TYPE_SERIAL:    return "SERIAL";
        case QIHSE_TYPE_BIGSERIAL: return "BIGSERIAL";
        case QIHSE_TYPE_INT_ARRAY: return "INT[]";
        case QIHSE_TYPE_FLOAT_ARRAY: return "FLOAT[]";
        case QIHSE_TYPE_TEXT_ARRAY: return "TEXT[]";
        case QIHSE_TYPE_BOOL_ARRAY: return "BOOL[]";
        case QIHSE_TYPE_JSONB:     return "JSONB";
        case QIHSE_TYPE_INET:      return "INET";
        case QIHSE_TYPE_NUMERIC:   return "NUMERIC";
        case QIHSE_TYPE_DATE:      return "DATE";
        case QIHSE_TYPE_TIMESTAMPTZ: return "TIMESTAMPTZ";
        case QIHSE_TYPE_UUID:      return "UUID";
        case QIHSE_TYPE_TSVECTOR:  return "TSVECTOR";
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
        case QIHSE_SQL_CREATE_EXTENSION: return "CREATE EXTENSION";
        case QIHSE_SQL_CREATE_FUNCTION:  return "CREATE FUNCTION";
        case QIHSE_SQL_CREATE_TRIGGER:   return "CREATE TRIGGER";
        case QIHSE_SQL_CREATE_PROCEDURE: return "CREATE PROCEDURE (opaque)";
        case QIHSE_SQL_DROP_TRIGGER: return "DROP TRIGGER";
        default: return "UNKNOWN";
    }
}
