#include "qihse_sql_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

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

static bool str_ieq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++; b++;
    }
    return *a == *b;
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
    } else if (str_ieq(p, "LIKE") || str_ieq(p, "IN ")) {
        while (*p && isalpha((unsigned char)*p)) p++;
        *out_len = (size_t)(p - start);
    }
    return start;
}

qihse_sql_ast_t* qihse_parse_sql_to_ast(const char* sql) {
    if (!sql || !*sql) return NULL;

    char* work = strdup(sql);
    if (!work) return NULL;

    qihse_sql_ast_t* ast = (qihse_sql_ast_t*)calloc(1, sizeof(qihse_sql_ast_t));
    if (!ast) { free(work); return NULL; }
    ast->raw_sql = strdup(sql);
    ast->limit = -1;
    ast->offset = -1;

    const char* p = trim_str(work);

    if (str_ieq(p, "SELECT") || strncasecmp(p, "SELECT ", 7) == 0) {
        ast->stmt_type = QIHSE_SQL_SELECT;
        p += 6;
        while (*p && isspace((unsigned char)*p)) p++;

        size_t col_cap = 8;
        ast->select_columns = (char**)calloc(col_cap, sizeof(char*));
        ast->num_select_columns = 0;

        for (;;) {
            p = skip_ws(p);
            const char* start = p;
            while (*p && *p != ',' && !isspace((unsigned char)*p) && 
                   strncasecmp(p, " FROM", 5) != 0 && *p != ';') p++;
            size_t len = (size_t)(p - start);
            if (len > 0) {
                if (ast->num_select_columns >= col_cap) {
                    col_cap *= 2;
                    ast->select_columns = (char**)realloc(ast->select_columns, col_cap * sizeof(char*));
                }
                ast->select_columns[ast->num_select_columns++] = dup_token(start, len);
            }
            p = skip_ws(p);
            if (*p == ',') { p++; continue; }
            break;
        }

        p = skip_ws(p);
        if (strncasecmp(p, "FROM", 4) == 0) {
            p += 4;
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
                ast->from_tables[ast->num_from_tables].table_name = dup_token(id_start, id_len);
                ast->from_tables[ast->num_from_tables].alias = NULL;
                ast->num_from_tables++;

                p = skip_ws(p);
                if (*p == ',') { p++; continue; }
                break;
            }
        }

        p = skip_ws(p);
        if (strncasecmp(p, "WHERE", 5) == 0) {
            p += 5;
            size_t cond_cap = 4;
            ast->where_conditions = (qihse_sql_condition_t*)calloc(cond_cap, sizeof(qihse_sql_condition_t));
            ast->num_where_conditions = 0;

            for (;;) {
                size_t col_len;
                const char* col_start = read_identifier(p, &col_len);
                if (col_len == 0) break;
                p = col_start + col_len;

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
                ast->where_conditions[ast->num_where_conditions].column_name = dup_token(col_start, col_len);
                ast->where_conditions[ast->num_where_conditions].operator = dup_token(op_start, op_len);
                ast->where_conditions[ast->num_where_conditions].value = dup_token(val_start, val_len);
                ast->where_conditions[ast->num_where_conditions].value_is_string = is_str;
                ast->num_where_conditions++;

                p = skip_ws(p);
                if (strncasecmp(p, "AND", 3) == 0) { p += 3; continue; }
                if (strncasecmp(p, "OR", 2) == 0) { p += 2; continue; }
                break;
            }
        }

        p = skip_ws(p);
        if (strncasecmp(p, "LIMIT", 5) == 0) {
            p += 5;
            p = skip_ws(p);
            ast->limit = (int)strtol(p, NULL, 10);
            while (*p && (isdigit((unsigned char)*p) || isspace((unsigned char)*p))) p++;
        }

        p = skip_ws(p);
        if (strncasecmp(p, "OFFSET", 6) == 0) {
            p += 6;
            p = skip_ws(p);
            ast->offset = (int)strtol(p, NULL, 10);
        }

    } else if (strncasecmp(p, "INSERT", 6) == 0) {
        ast->stmt_type = QIHSE_SQL_INSERT;
    } else if (strncasecmp(p, "UPDATE", 6) == 0) {
        ast->stmt_type = QIHSE_SQL_UPDATE;
    } else if (strncasecmp(p, "DELETE", 6) == 0) {
        ast->stmt_type = QIHSE_SQL_DELETE;
    } else if (strncasecmp(p, "CREATE", 6) == 0) {
        ast->stmt_type = QIHSE_SQL_CREATE;
    } else if (strncasecmp(p, "DROP", 4) == 0) {
        ast->stmt_type = QIHSE_SQL_DROP;
    } else {
        ast->stmt_type = QIHSE_SQL_UNKNOWN;
    }

    free(work);
    return ast;
}

void qihse_sql_ast_free(qihse_sql_ast_t* ast) {
    if (!ast) return;
    for (size_t i = 0; i < ast->num_select_columns; i++) free(ast->select_columns[i]);
    free(ast->select_columns);
    for (size_t i = 0; i < ast->num_from_tables; i++) {
        free(ast->from_tables[i].table_name);
        free(ast->from_tables[i].alias);
    }
    free(ast->from_tables);
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        free(ast->where_conditions[i].column_name);
        free(ast->where_conditions[i].operator);
        free(ast->where_conditions[i].value);
    }
    free(ast->where_conditions);
    free(ast->raw_sql);
    free(ast);
}
