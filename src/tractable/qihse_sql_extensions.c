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

/* ---- ClickHouse SQL Extensions ---- */

/* Helper: case-insensitive comparison of two strings */
static int ch_str_ieq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* Helper: case-insensitive prefix match with word boundary check */
static const char* ch_match_kw(const char* p, const char* kw) {
    while (*p && isspace((unsigned char)*p)) p++;
    size_t kl = strlen(kw);
    if (strncasecmp(p, kw, kl) != 0) return NULL;
    char after = p[kl];
    if (isalnum((unsigned char)after) || after == '_') return NULL;
    return p + kl;
}

/* Helper: find matching closing paren starting at p (which points to '(') */
static const char* ch_find_matching_paren(const char* p) {
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

/* Helper: skip whitespace */
static const char* ch_skip_ws(const char* p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/* Helper: extract a clause (keyword ... ) from SQL, returning the text between
 * the keyword and the next major keyword. Returns a newly allocated string. */
static char* ch_extract_clause(const char* sql, const char* keyword,
                                const char** next_keywords, int num_next) {
    const char* p = strcasestr(sql, keyword);
    if (!p) return NULL;
    p += strlen(keyword);
    p = ch_skip_ws(p);
    const char* start = p;
    const char* end = start + strlen(start);
    /* Find the earliest occurrence of any next keyword */
    for (int i = 0; i < num_next; i++) {
        const char* nk = strcasestr(start, next_keywords[i]);
        if (nk && nk < end) {
            /* Check word boundary before the keyword */
            if (nk > start && (isalnum((unsigned char)nk[-1]) || nk[-1] == '_'))
                continue;
            end = nk;
        }
    }
    /* Trim trailing whitespace */
    while (end > start && isspace((unsigned char)end[-1])) end--;
    return strndup(start, (size_t)(end - start));
}

/* ---- MergeTree engine family ---- */

static qihse_ch_engine_kind_t detect_engine(const char* sql) {
    if (!sql) return QIHSE_CH_ENGINE_NONE;
    /* Search for ENGINE = ... in the SQL */
    const char* p = strcasestr(sql, "ENGINE");
    if (!p) return QIHSE_CH_ENGINE_NONE;
    p += 6;
    p = ch_skip_ws(p);
    if (*p == '=' || *p == '=') p++;
    p = ch_skip_ws(p);
    /* Read engine name (may be in parens) */
    char engname[64] = {0};
    size_t i = 0;
    while (*p && (isalnum((unsigned char)*p) || *p == '_') && i < sizeof(engname) - 1) {
        engname[i++] = *p++;
    }
    engname[i] = '\0';
    /* Uppercase for comparison */
    for (size_t j = 0; j < i; j++) engname[j] = (char)toupper((unsigned char)engname[j]);

    if (strcmp(engname, "MergeTree") == 0) return QIHSE_CH_ENGINE_MERGETREE;
    if (strcmp(engname, "ReplacingMergeTree") == 0) return QIHSE_CH_ENGINE_REPLACING_MERGETREE;
    if (strcmp(engname, "SummingMergeTree") == 0) return QIHSE_CH_ENGINE_SUMMING_MERGETREE;
    if (strcmp(engname, "AggregatingMergeTree") == 0) return QIHSE_CH_ENGINE_AGGREGATING_MERGETREE;
    if (strcmp(engname, "CollapsingMergeTree") == 0) return QIHSE_CH_ENGINE_COLLAPSING_MERGETREE;
    if (strcmp(engname, "VersionedMergeTree") == 0) return QIHSE_CH_ENGINE_VERSIONED_MERGETREE;
    return QIHSE_CH_ENGINE_NONE;
}

int qihse_sql_parse_mergetree(const char* sql, qihse_ch_mergetree_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));

    out->engine_kind = detect_engine(sql);
    if (out->engine_kind == QIHSE_CH_ENGINE_NONE) return -1;

    /* Extract engine params (in parentheses after engine name) */
    const char* ep = strcasestr(sql, "ENGINE");
    if (ep) {
        ep += 6;
        ep = ch_skip_ws(ep);
        if (*ep == '=') { ep++; ep = ch_skip_ws(ep); }
        /* Skip engine name */
        while (*ep && (isalnum((unsigned char)*ep) || *ep == '_')) ep++;
        ep = ch_skip_ws(ep);
        if (*ep == '(') {
            const char* close = ch_find_matching_paren(ep);
            if (close) {
                out->engine_params = strndup(ep + 1, (size_t)(close - ep - 1));
            }
        }
    }

    /* Extract ORDER BY expr (engine-level, not SELECT ORDER BY) */
    const char* next_kws[] = {"PARTITION BY", "PRIMARY KEY", "SAMPLE BY", "TTL", "SETTINGS"};
    /* For CREATE TABLE, ORDER BY is after the engine clause */
    const char* create_pos = strcasestr(sql, "ENGINE");
    if (create_pos) {
        const char* ob = strcasestr(create_pos, "ORDER BY");
        if (ob) {
            ob += 8;
            ob = ch_skip_ws(ob);
            const char* end = ob + strlen(ob);
            for (int i = 0; i < 5; i++) {
                const char* nk = strcasestr(ob, next_kws[i]);
                if (nk && nk < end) end = nk;
            }
            while (end > ob && isspace((unsigned char)end[-1])) end--;
            out->order_by_expr = strndup(ob, (size_t)(end - ob));
        }
    }

    /* PARTITION BY */
    out->partition_by_expr = ch_extract_clause(sql, "PARTITION BY", next_kws, 5);

    /* PRIMARY KEY */
    const char* pk_next[] = {"SAMPLE BY", "TTL", "SETTINGS", "ORDER BY"};
    out->primary_key_expr = ch_extract_clause(sql, "PRIMARY KEY", pk_next, 4);

    /* SAMPLE BY */
    const char* sb_next[] = {"TTL", "SETTINGS", "ORDER BY", "PARTITION BY"};
    out->sample_by_expr = ch_extract_clause(sql, "SAMPLE BY", sb_next, 4);

    /* TTL */
    const char* ttl_next[] = {"SETTINGS", "ORDER BY", "PARTITION BY", "PRIMARY KEY"};
    out->ttl_expr = ch_extract_clause(sql, "TTL", ttl_next, 4);

    /* SETTINGS */
    const char* set_next[] = {"ORDER BY", "PARTITION BY", "PRIMARY KEY"};
    out->settings_expr = ch_extract_clause(sql, "SETTINGS", set_next, 3);

    return 0;
}

void qihse_ch_mergetree_spec_free(qihse_ch_mergetree_spec_t* spec) {
    if (!spec) return;
    free(spec->engine_params);
    free(spec->order_by_expr);
    free(spec->partition_by_expr);
    free(spec->primary_key_expr);
    free(spec->sample_by_expr);
    free(spec->ttl_expr);
    free(spec->settings_expr);
}

/* ---- Materialized views ---- */

int qihse_sql_parse_materialized_view(const char* sql, qihse_ch_matview_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));

    const char* p = strcasestr(sql, "CREATE MATERIALIZED VIEW");
    if (!p) return -1;
    p += 23; /* strlen("CREATE MATERIALIZED VIEW") */

    /* IF NOT EXISTS */
    p = ch_skip_ws(p);
    const char* ine = ch_match_kw(p, "IF NOT EXISTS");
    if (ine) { out->if_not_exists = 1; p = ine; }

    /* View name (may be db.view) */
    p = ch_skip_ws(p);
    const char* name_start = p;
    while (*p && (isalnum((unsigned char)*p) || *p == '_' || *p == '.' || *p == '`')) p++;
    char* full_name = strndup(name_start, (size_t)(p - name_start));
    /* Strip backticks */
    char* clean_name = full_name;
    /* Extract database if present */
    char* dot = strchr(full_name, '.');
    if (dot) {
        *dot = '\0';
        out->database = strdup(full_name);
        out->view_name = strdup(dot + 1);
    } else {
        out->view_name = strdup(full_name);
    }
    free(full_name);
    (void)clean_name;

    /* TO table (optional) */
    const char* to_p = strcasestr(p, "TO");
    if (to_p) {
        const char* tp = to_p + 2;
        tp = ch_skip_ws(tp);
        const char* tstart = tp;
        while (*tp && (isalnum((unsigned char)*tp) || *tp == '_' || *tp == '.' || *tp == '`')) tp++;
        out->target_table = strndup(tstart, (size_t)(tp - tstart));
        p = tp;
    }

    /* ENGINE (optional) */
    const char* eng_p = strcasestr(p, "ENGINE");
    if (eng_p) {
        const char* ep = eng_p;
        const char* end = ep;
        /* Find end of engine clause (AS or end of string) */
        const char* as_p = strcasestr(ep, "AS");
        if (as_p) end = as_p;
        else end = ep + strlen(ep);
        out->engine = strndup(ep, (size_t)(end - ep));
        /* Trim trailing whitespace */
        char* e = out->engine + strlen(out->engine) - 1;
        while (e > out->engine && isspace((unsigned char)*e)) { *e = '\0'; e--; }
    }

    /* AS SELECT ... — extract the SELECT query */
    const char* as_p = strcasestr(sql, "AS");
    if (as_p) {
        as_p += 2;
        as_p = ch_skip_ws(as_p);
        out->select_query = strdup(as_p);
    }

    return 0;
}

void qihse_ch_matview_spec_free(qihse_ch_matview_spec_t* spec) {
    if (!spec) return;
    free(spec->view_name);
    free(spec->target_table);
    free(spec->database);
    free(spec->select_query);
    free(spec->engine);
}

/* ---- Dictionaries ---- */

int qihse_sql_parse_dictionary(const char* sql, qihse_ch_dictionary_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));

    const char* p = strcasestr(sql, "CREATE DICTIONARY");
    if (!p) return -1;
    p += 17;
    p = ch_skip_ws(p);

    /* IF NOT EXISTS */
    const char* ine = ch_match_kw(p, "IF NOT EXISTS");
    if (ine) p = ine;

    /* Dictionary name */
    p = ch_skip_ws(p);
    const char* name_start = p;
    while (*p && (isalnum((unsigned char)*p) || *p == '_' || *p == '.' || *p == '`')) p++;
    out->dict_name = strndup(name_start, (size_t)(p - name_start));

    /* SOURCE(...) */
    const char* src_p = strcasestr(sql, "SOURCE");
    if (src_p) {
        const char* sp = src_p + 6;
        sp = ch_skip_ws(sp);
        if (*sp == '(') {
            const char* close = ch_find_matching_paren(sp);
            if (close) {
                out->source = strndup(sp + 1, (size_t)(close - sp - 1));
            }
        }
    }

    /* LAYOUT(...) */
    const char* lay_p = strcasestr(sql, "LAYOUT");
    if (lay_p) {
        const char* lp = lay_p + 6;
        lp = ch_skip_ws(lp);
        if (*lp == '(') {
            const char* close = ch_find_matching_paren(lp);
            if (close) {
                /* Extract layout name (first identifier inside parens) */
                const char* inner = ch_skip_ws(lp + 1);
                const char* inner_end = inner;
                while (*inner_end && (isalnum((unsigned char)*inner_end) || *inner_end == '_'))
                    inner_end++;
                out->layout = strndup(inner, (size_t)(inner_end - inner));
            }
        }
    }

    /* LIFETIME(...) */
    const char* lt_p = strcasestr(sql, "LIFETIME");
    if (lt_p) {
        const char* lp = lt_p + 8;
        lp = ch_skip_ws(lp);
        if (*lp == '(') {
            const char* close = ch_find_matching_paren(lp);
            if (close) {
                char* val_str = strndup(lp + 1, (size_t)(close - lp - 1));
                /* Try to parse a number, possibly with MIN/MAX */
                int val = atoi(val_str);
                out->lifetime = val;
                free(val_str);
            }
        }
    }

    return 0;
}

void qihse_ch_dictionary_spec_free(qihse_ch_dictionary_spec_t* spec) {
    if (!spec) return;
    free(spec->dict_name);
    free(spec->source);
    free(spec->layout);
    if (spec->columns) {
        for (size_t i = 0; i < spec->num_columns; i++) free(spec->columns[i]);
        free(spec->columns);
    }
    if (spec->column_types) {
        for (size_t i = 0; i < spec->num_column_types; i++) free(spec->column_types[i]);
        free(spec->column_types);
    }
}

/* ---- ClickHouse-specific function detection ---- */

qihse_ch_func_kind_t qihse_ch_detect_function(const char* func_name) {
    if (!func_name) return QIHSE_CH_FUNC_NONE;
    /* Case-insensitive comparison */
    if (ch_str_ieq(func_name, "now")) return QIHSE_CH_FUNC_NOW;
    if (ch_str_ieq(func_name, "today")) return QIHSE_CH_FUNC_TODAY;
    if (ch_str_ieq(func_name, "yesterday")) return QIHSE_CH_FUNC_YESTERDAY;
    if (ch_str_ieq(func_name, "toStartOfMonth")) return QIHSE_CH_FUNC_TOSTARTOFMONTH;
    if (ch_str_ieq(func_name, "toStartOfDay")) return QIHSE_CH_FUNC_TOSTARTOFDAY;
    if (ch_str_ieq(func_name, "countIf")) return QIHSE_CH_FUNC_COUNTIF;
    if (ch_str_ieq(func_name, "sumIf")) return QIHSE_CH_FUNC_SUMIF;
    if (ch_str_ieq(func_name, "avgIf")) return QIHSE_CH_FUNC_AVGIF;
    if (ch_str_ieq(func_name, "groupArray")) return QIHSE_CH_FUNC_GROUPARRAY;
    if (ch_str_ieq(func_name, "groupUniqArray")) return QIHSE_CH_FUNC_GROUPUNIQARRAY;
    return QIHSE_CH_FUNC_NONE;
}

/* ---- ARRAY JOIN clause ---- */

int qihse_sql_parse_array_join(const char* sql, qihse_ch_array_join_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* Look for LEFT ARRAY JOIN or ARRAY JOIN */
    const char* laj = strcasestr(sql, "LEFT ARRAY JOIN");
    if (laj) {
        out->is_left = 1;
        const char* p = laj + 15; /* strlen("LEFT ARRAY JOIN") */
        p = ch_skip_ws(p);
        const char* end = p + strlen(p);
        /* ARRAY JOIN is typically followed by GROUP BY, ORDER BY, LIMIT, etc. */
        const char* next_kws[] = {"GROUP BY", "ORDER BY", "LIMIT", "OFFSET", "HAVING",
                                   "SETTINGS", "UNION", "INTERSECT", "EXCEPT", "WHERE"};
        for (size_t i = 0; i < sizeof(next_kws)/sizeof(next_kws[0]); i++) {
            const char* nk = strcasestr(p, next_kws[i]);
            if (nk && nk < end) end = nk;
        }
        while (end > p && isspace((unsigned char)end[-1])) end--;
        out->array_expr = strndup(p, (size_t)(end - p));
        return 0;
    }

    const char* aj = strcasestr(sql, "ARRAY JOIN");
    if (aj) {
        out->is_left = 0;
        const char* p = aj + 10; /* strlen("ARRAY JOIN") */
        p = ch_skip_ws(p);
        const char* end = p + strlen(p);
        const char* next_kws[] = {"GROUP BY", "ORDER BY", "LIMIT", "OFFSET", "HAVING",
                                   "SETTINGS", "UNION", "INTERSECT", "EXCEPT", "WHERE"};
        for (size_t i = 0; i < sizeof(next_kws)/sizeof(next_kws[0]); i++) {
            const char* nk = strcasestr(p, next_kws[i]);
            if (nk && nk < end) end = nk;
        }
        while (end > p && isspace((unsigned char)end[-1])) end--;
        out->array_expr = strndup(p, (size_t)(end - p));
        return 0;
    }

    return -1; /* No ARRAY JOIN found */
}

void qihse_ch_array_join_free(qihse_ch_array_join_t* spec) {
    if (!spec) return;
    free(spec->array_expr);
}

/* ---- FINAL modifier ---- */

int qihse_sql_has_final_modifier(const char* sql) {
    if (!sql) return 0;
    /* FINAL appears after the table name in FROM clause, before WHERE/GROUP BY/etc. */
    const char* p = strcasestr(sql, "FINAL");
    if (!p) return 0;
    /* Check it's not inside a string literal or function name */
    if (p > sql) {
        char before = p[-1];
        if (isalnum((unsigned char)before) || before == '_') return 0;
    }
    char after = p[5];
    if (isalnum((unsigned char)after) || after == '_') return 0;
    return 1;
}

/* ---- PREWHERE clause ---- */

char* qihse_sql_extract_prewhere(const char* sql) {
    if (!sql) return NULL;
    const char* p = strcasestr(sql, "PREWHERE");
    if (!p) return NULL;
    /* Check word boundary */
    if (p > sql && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) return NULL;
    char after = p[8];
    if (isalnum((unsigned char)after) || after == '_') return NULL;

    p += 8;
    p = ch_skip_ws(p);
    const char* start = p;
    const char* end = start + strlen(start);

    /* PREWHERE is followed by WHERE, GROUP BY, ORDER BY, LIMIT, etc. */
    const char* next_kws[] = {"WHERE", "GROUP BY", "ORDER BY", "LIMIT", "OFFSET",
                               "HAVING", "SETTINGS", "ARRAY JOIN", "LEFT ARRAY JOIN",
                               "UNION", "INTERSECT", "EXCEPT", "SAMPLE"};
    for (size_t i = 0; i < sizeof(next_kws)/sizeof(next_kws[0]); i++) {
        const char* nk = strcasestr(start, next_kws[i]);
        if (nk && nk < end) end = nk;
    }
    while (end > start && isspace((unsigned char)end[-1])) end--;
    return strndup(start, (size_t)(end - start));
}

/* ---- SAMPLE clause ---- */

int qihse_sql_parse_sample(const char* sql, qihse_ch_sample_spec_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* SAMPLE appears after FROM clause, before WHERE/PREWHERE */
    const char* p = strcasestr(sql, "SAMPLE");
    if (!p) return -1;
    /* Check word boundary */
    if (p > sql && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) return -1;
    char after = p[6];
    if (isalnum((unsigned char)after) || after == '_') return -1;

    p += 6;
    p = ch_skip_ws(p);
    const char* start = p;
    const char* end = start + strlen(start);

    /* SAMPLE is followed by OFFSET, WHERE, PREWHERE, GROUP BY, etc. */
    const char* next_kws[] = {"OFFSET", "WHERE", "PREWHERE", "GROUP BY", "ORDER BY",
                               "LIMIT", "HAVING", "SETTINGS", "ARRAY JOIN",
                               "LEFT ARRAY JOIN", "UNION", "INTERSECT", "EXCEPT", "FINAL"};
    for (size_t i = 0; i < sizeof(next_kws)/sizeof(next_kws[0]); i++) {
        const char* nk = strcasestr(start, next_kws[i]);
        if (nk && nk < end) end = nk;
    }
    while (end > start && isspace((unsigned char)end[-1])) end--;

    /* Check for OFFSET */
    const char* off_p = strcasestr(start, "OFFSET");
    if (off_p && off_p < end) {
        out->sample_expr = strndup(start, (size_t)(off_p - start));
        /* Trim whitespace */
        char* e = out->sample_expr + strlen(out->sample_expr) - 1;
        while (e > out->sample_expr && isspace((unsigned char)*e)) { *e = '\0'; e--; }
        const char* off_start = off_p + 6;
        off_start = ch_skip_ws(off_start);
        out->is_offset = 1;
        out->offset_expr = strndup(off_start, (size_t)(end - off_start));
    } else {
        out->sample_expr = strndup(start, (size_t)(end - start));
    }

    return 0;
}

void qihse_ch_sample_spec_free(qihse_ch_sample_spec_t* spec) {
    if (!spec) return;
    free(spec->sample_expr);
    free(spec->offset_expr);
}

/* ---- SETTINGS clause in queries ---- */

int qihse_sql_extract_settings(const char* sql, qihse_ch_query_settings_t* out) {
    if (!sql || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* Find SETTINGS keyword (case-insensitive) */
    const char* p = strcasestr(sql, "SETTINGS");
    if (!p) return -1;
    /* Check word boundary */
    if (p > sql && (isalnum((unsigned char)p[-1]) || p[-1] == '_')) return -1;
    char after = p[8];
    if (isalnum((unsigned char)after) || after == '_') return -1;

    p += 8;
    p = ch_skip_ws(p);
    const char* start = p;
    const char* end = start + strlen(start);

    /* Parse comma-separated key=value pairs */
    const char* curr = start;
    size_t cap = 0;
    while (curr < end) {
        /* Skip whitespace and commas */
        while (curr < end && (isspace((unsigned char)*curr) || *curr == ',')) curr++;
        if (curr >= end) break;
        /* Read key */
        const char* key_start = curr;
        while (curr < end && *curr != '=' && *curr != ',' && !isspace((unsigned char)*curr)) curr++;
        const char* key_end = curr;
        /* Skip whitespace before = */
        while (curr < end && isspace((unsigned char)*curr)) curr++;
        if (curr >= end || *curr != '=') break;
        curr++; /* skip = */
        while (curr < end && isspace((unsigned char)*curr)) curr++;
        /* Read value */
        const char* val_start = curr;
        if (curr < end && *curr == '\'') {
            curr++;
            while (curr < end && *curr != '\'') curr++;
            if (curr < end) curr++;
        } else {
            while (curr < end && *curr != ',' && !isspace((unsigned char)*curr)) curr++;
        }
        const char* val_end = curr;

        /* Store key-value pair */
        if (out->num_settings >= cap) {
            cap = cap ? cap * 2 : 4;
            out->names = (char**)realloc(out->names, cap * sizeof(char*));
            out->values = (char**)realloc(out->values, cap * sizeof(char*));
        }
        out->names[out->num_settings] = strndup(key_start, (size_t)(key_end - key_start));
        out->values[out->num_settings] = strndup(val_start, (size_t)(val_end - val_start));
        out->num_settings++;
    }

    return 0;
}

void qihse_ch_query_settings_free(qihse_ch_query_settings_t* settings) {
    if (!settings) return;
    for (size_t i = 0; i < settings->num_settings; i++) {
        free(settings->names[i]);
        free(settings->values[i]);
    }
    free(settings->names);
    free(settings->values);
}

/* ---- Name helpers ---- */

const char* qihse_ch_engine_name(qihse_ch_engine_kind_t kind) {
    switch (kind) {
        case QIHSE_CH_ENGINE_MERGETREE:             return "MergeTree";
        case QIHSE_CH_ENGINE_REPLACING_MERGETREE:   return "ReplacingMergeTree";
        case QIHSE_CH_ENGINE_SUMMING_MERGETREE:     return "SummingMergeTree";
        case QIHSE_CH_ENGINE_AGGREGATING_MERGETREE: return "AggregatingMergeTree";
        case QIHSE_CH_ENGINE_COLLAPSING_MERGETREE:  return "CollapsingMergeTree";
        case QIHSE_CH_ENGINE_VERSIONED_MERGETREE:   return "VersionedMergeTree";
        default: return "None";
    }
}

const char* qihse_ch_func_name(qihse_ch_func_kind_t kind) {
    switch (kind) {
        case QIHSE_CH_FUNC_NOW:             return "now";
        case QIHSE_CH_FUNC_TODAY:           return "today";
        case QIHSE_CH_FUNC_YESTERDAY:       return "yesterday";
        case QIHSE_CH_FUNC_TOSTARTOFMONTH:  return "toStartOfMonth";
        case QIHSE_CH_FUNC_TOSTARTOFDAY:    return "toStartOfDay";
        case QIHSE_CH_FUNC_COUNTIF:         return "countIf";
        case QIHSE_CH_FUNC_SUMIF:           return "sumIf";
        case QIHSE_CH_FUNC_AVGIF:           return "avgIf";
        case QIHSE_CH_FUNC_GROUPARRAY:      return "groupArray";
        case QIHSE_CH_FUNC_GROUPUNIQARRAY:  return "groupUniqArray";
        default: return "none";
    }
}
