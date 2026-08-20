#include "qihse_sql_extensions.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ---- Helper: extract substring between parens ---- */
static char* extract_parens(const char* sql, const char* func_name) {
    /* Find function name */
    const char* p = strcasestr(sql, func_name);
    if (!p) return NULL;
    p += strlen(func_name);
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '(') return NULL;
    p++;
    /* Find matching close paren */
    int depth = 1;
    const char* start = p;
    while (*p && depth > 0) {
        if (*p == '(') depth++;
        else if (*p == ')') depth--;
        if (depth > 0) p++;
    }
    if (depth != 0) return NULL;
    return strndup(start, p - start);
}

/* ---- Vector SQL Extensions ---- */

int qihse_sql_parse_vector_search(const char* sql, qihse_vector_search_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    char* args = extract_parens(sql, "VECTOR_SEARCH");
    if (!args) return -1;
    
    /* Parse: table_name, query_vec, k [, distance_metric] */
    /* Use a state machine to handle quoted strings and array literals */
    char* p = args;
    char* tokens[4];
    int ntokens = 0;
    while (*p && ntokens < 4) {
        while (*p && (isspace((unsigned char)*p) || *p == ',')) p++;
        if (!*p || *p == ')') break;
        char* start = p;
        if (*p == '\'') {
            p++;
            while (*p && *p != '\'') p++;
            if (*p == '\'') p++;
        } else if (*p == '[') {
            int depth = 1;
            p++;
            while (*p && depth > 0) {
                if (*p == '[') depth++;
                else if (*p == ']') depth--;
                p++;
            }
        } else {
            while (*p && *p != ',' && *p != ')') p++;
        }
        tokens[ntokens++] = strndup(start, p - start);
    }
    
    if (ntokens < 1) { free(args); return -1; }
    
    /* Token 0: table_name */
    char* tok = tokens[0];
    while (isspace((unsigned char)*tok)) tok++;
    if (*tok == '\'') tok++;
    char* end = tok + strlen(tok) - 1;
    while (end > tok && isspace((unsigned char)*end)) end--;
    if (*end == '\'') *end = '\0';
    out->table_name = strdup(tok);
    
    /* Token 1: query_vec (skip parsing) */
    out->query_vector = NULL;
    out->vector_dims = 0;
    
    /* Token 2: k */
    if (ntokens > 2) {
        tok = tokens[2];
        while (isspace((unsigned char)*tok)) tok++;
        out->k = (size_t)atol(tok);
    } else {
        out->k = 10;
    }
    
    /* Token 3: distance_metric */
    if (ntokens > 3) {
        tok = tokens[3];
        while (isspace((unsigned char)*tok)) tok++;
        if (*tok == '\'') tok++;
        end = tok + strlen(tok) - 1;
        while (end > tok && isspace((unsigned char)*end)) end--;
        if (*end == '\'') *end = '\0';
        out->distance_metric = strdup(tok);
    } else {
        out->distance_metric = strdup("euclidean");
    }
    
    return 0;
}

void qihse_vector_search_spec_free(qihse_vector_search_spec_t* spec) {
    if (!spec) return;
    free(spec->table_name);
    free(spec->query_vector);
    free(spec->distance_metric);
}

int qihse_sql_execute_vector_search(const qihse_vector_search_spec_t* spec,
                                    qihse_vector_search_result_t** out_results, size_t* out_count) {
    if (!spec || !out_results || !out_count) return -1;
    /* In a real implementation, call qihse_vector_db_search */
    *out_results = NULL;
    *out_count = 0;
    return 0;
}

/* ---- Time-Series SQL Extensions ---- */

int qihse_sql_parse_time_bucket(const char* sql, qihse_time_bucket_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    char* args = extract_parens(sql, "TIME_BUCKET");
    if (!args) return -1;
    
    /* Parse: bucket_width, time_column [, agg_func, value_column] */
    char* saveptr;
    char* tok = strtok_r(args, ",", &saveptr);
    if (!tok) { free(args); return -1; }
    while (isspace((unsigned char)*tok)) tok++;
    /* Parse duration like '1m', '5m', '1h', '1d' */
    char unit = 0;
    int64_t val = 0;
    if (sscanf(tok, " '%ld%c'", &val, &unit) >= 2 || sscanf(tok, "'%ld%c'", &val, &unit) >= 2) {
        switch (unit) {
            case 's': out->bucket_width_ms = val * 1000; break;
            case 'm': out->bucket_width_ms = val * 60000; break;
            case 'h': out->bucket_width_ms = val * 3600000; break;
            case 'd': out->bucket_width_ms = val * 86400000; break;
            default: out->bucket_width_ms = val; break;
        }
    }
    
    tok = strtok_r(NULL, ",", &saveptr);
    if (tok) {
        while (isspace((unsigned char)*tok)) tok++;
        if (*tok == '\'') tok++;
        char* end = tok + strlen(tok) - 1;
        if (*end == '\'') *end = '\0';
        out->time_column = strdup(tok);
    }
    
    tok = strtok_r(NULL, ",", &saveptr);
    if (tok) {
        while (isspace((unsigned char)*tok)) tok++;
        if (*tok == '\'') tok++;
        char* end = tok + strlen(tok) - 1;
        if (*end == '\'') *end = '\0';
        out->agg_func = strdup(tok);
    } else {
        out->agg_func = strdup("avg");
    }
    
    tok = strtok_r(NULL, ",", &saveptr);
    if (tok) {
        while (isspace((unsigned char)*tok)) tok++;
        if (*tok == '\'') tok++;
        char* end = tok + strlen(tok) - 1;
        if (*end == '\'') *end = '\0';
        out->value_column = strdup(tok);
    }
    
    free(args);
    return 0;
}

void qihse_time_bucket_spec_free(qihse_time_bucket_spec_t* spec) {
    if (!spec) return;
    free(spec->time_column);
    free(spec->agg_func);
    free(spec->value_column);
}

int qihse_sql_execute_time_bucket(const qihse_time_bucket_spec_t* spec,
                                  qihse_time_bucket_result_t** out_results, size_t* out_count) {
    if (!spec || !out_results || !out_count) return -1;
    /* In a real implementation, query timeseries engine and bucket results */
    *out_results = NULL;
    *out_count = 0;
    return 0;
}

int qihse_time_bucket_fill_gaps(qihse_time_bucket_result_t* results, size_t* count,
                                int64_t start_time, int64_t end_time, int64_t bucket_width,
                                int fill_mode) {
    if (!results || !count) return -1;
    /* Fill missing buckets between start_time and end_time */
    size_t expected = (size_t)((end_time - start_time) / bucket_width) + 1;
    if (expected <= *count) return 0;
    
    qihse_time_bucket_result_t* filled = (qihse_time_bucket_result_t*)realloc(results, expected * sizeof(qihse_time_bucket_result_t));
    if (!filled) return -1;
    
    /* In a real implementation, insert NULL/interpolated values for missing buckets */
    (void)fill_mode;
    *count = expected;
    return 0;
}

/* ---- Full-Text SQL Extensions ---- */

int qihse_sql_parse_fts_match(const char* sql, qihse_fts_match_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));
    
    char* args = extract_parens(sql, "MATCH");
    if (!args) return -1;
    
    /* Parse: field, query [, highlight, snippet_size] */
    char* saveptr;
    char* tok = strtok_r(args, ",", &saveptr);
    if (!tok) { free(args); return -1; }
    while (isspace((unsigned char)*tok)) tok++;
    if (*tok == '\'') tok++;
    char* end = tok + strlen(tok) - 1;
    if (*end == '\'') *end = '\0';
    out->field = strdup(tok);
    
    tok = strtok_r(NULL, ",", &saveptr);
    if (tok) {
        while (isspace((unsigned char)*tok)) tok++;
        if (*tok == '\'') tok++;
        char* end = tok + strlen(tok) - 1;
        if (*end == '\'') *end = '\0';
        out->query = strdup(tok);
    }
    
    tok = strtok_r(NULL, ",", &saveptr);
    if (tok) {
        out->highlight = atoi(tok);
    } else {
        out->highlight = 0;
    }
    
    tok = strtok_r(NULL, ",", &saveptr);
    if (tok) {
        out->snippet_size = atoi(tok);
    } else {
        out->snippet_size = 100;
    }
    
    free(args);
    return 0;
}

void qihse_fts_match_spec_free(qihse_fts_match_spec_t* spec) {
    if (!spec) return;
    free(spec->field);
    free(spec->query);
}

int qihse_sql_execute_fts_match(const qihse_fts_match_spec_t* spec,
                                qihse_fts_match_result_t** out_results, size_t* out_count) {
    if (!spec || !out_results || !out_count) return -1;
    /* In a real implementation, call qihse_fts_search */
    *out_results = NULL;
    *out_count = 0;
    return 0;
}

void qihse_fts_match_result_free(qihse_fts_match_result_t* results, size_t count) {
    if (!results) return;
    for (size_t i = 0; i < count; i++) free(results[i].highlight_snippet);
    free(results);
}
