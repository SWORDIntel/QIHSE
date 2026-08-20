#include "qihse_es_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <pthread.h>

/* ===========================================================================
 * Elasticsearch-compatible HTTP API
 *
 * This file implements a subset of the Elasticsearch REST API on top of the
 * QIHSE HTTP server. It provides document CRUD, search (with a small query
 * DSL parser), aggregations, index management, mappings, settings, count,
 * explain, multi-search/multi-get, reindex, scroll, point-in-time, stored
 * scripts, search templates, the cat API and cluster/node info.
 *
 * The implementation is self-contained: mappings and stored scripts are kept
 * in process-local memory, and search results are returned in Elasticsearch
 * wire format. The query DSL parser understands match, term, match_all, bool
 * (must/must_not/should/filter) and range queries, and the aggregation engine
 * produces terms, avg, sum, max, min and cardinality buckets.
 * =========================================================================== */

/* ---- dynamic string builder -------------------------------------------- */

typedef struct {
    char*  data;
    size_t len;
    size_t cap;
} sb_t;

static void sb_init(sb_t* s) {
    s->cap = 256;
    s->len = 0;
    s->data = (char*)malloc(s->cap);
    s->data[0] = '\0';
}

static void sb_free(sb_t* s) {
    free(s->data);
    s->data = NULL;
    s->len = s->cap = 0;
}

static void sb_reserve(sb_t* s, size_t extra) {
    if (s->len + extra + 1 > s->cap) {
        while (s->len + extra + 1 > s->cap) s->cap *= 2;
        s->data = (char*)realloc(s->data, s->cap);
    }
}

static void sb_append(sb_t* s, const char* str) {
    size_t n = strlen(str);
    sb_reserve(s, n);
    memcpy(s->data + s->len, str, n);
    s->len += n;
    s->data[s->len] = '\0';
}

static void sb_appendf(sb_t* s, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return; }
    sb_reserve(s, (size_t)n);
    vsnprintf(s->data + s->len, s->cap - s->len, fmt, ap2);
    va_end(ap2);
    s->len += (size_t)n;
}

/* ---- minimal JSON helpers ---------------------------------------------- */

/* Skip whitespace. */
static const char* json_skip(const char* p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

/* Find the end of a JSON value starting at p (p points at the first non-ws
 * char of the value). Returns pointer just past the value. */
static const char* json_skip_value(const char* p) {
    p = json_skip(p);
    if (*p == '"') {
        p++;
        while (*p) {
            if (*p == '\\' && p[1]) { p += 2; continue; }
            if (*p == '"') { p++; break; }
            p++;
        }
        return p;
    }
    if (*p == '{' || *p == '[') {
        char open = *p, close = (open == '{') ? '}' : ']';
        int depth = 1;
        p++;
        while (*p && depth > 0) {
            if (*p == '"') { p = json_skip_value(p); continue; }
            if (*p == open) depth++;
            else if (*p == close) depth--;
            p++;
        }
        return p;
    }
    /* number / literal */
    while (*p && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
        p++;
    return p;
}

/* Look up a top-level string key in a JSON object. Returns a pointer to the
 * start of the value (after the colon) or NULL if not found. */
static const char* json_get(const char* obj, const char* key) {
    if (!obj) return NULL;
    const char* p = json_skip(obj);
    if (*p != '{') return NULL;
    p++;
    while (*p) {
        p = json_skip(p);
        if (*p == '}') return NULL;
        if (*p != '"') return NULL;
        p++;
        const char* kstart = p;
        while (*p && *p != '"') { if (*p == '\\' && p[1]) p += 2; else p++; }
        size_t klen = (size_t)(p - kstart);
        p++; /* closing quote */
        p = json_skip(p);
        if (*p != ':') return NULL;
        p++;
        const char* vstart = json_skip(p);
        if (klen == strlen(key) && strncmp(kstart, key, klen) == 0)
            return vstart;
        p = json_skip_value(p);
        p = json_skip(p);
        if (*p == ',') p++;
    }
    return NULL;
}

/* Copy a JSON value (object/array/string/number/literal) into a freshly
 * allocated buffer. Returns malloc'd string. */
static char* json_dup_value(const char* v) {
    if (!v) return NULL;
    const char* end = json_skip_value(v);
    size_t n = (size_t)(end - v);
    /* trim trailing whitespace */
    while (n > 0 && (v[n-1] == ' ' || v[n-1] == '\t' || v[n-1] == '\n' || v[n-1] == '\r')) n--;
    char* out = (char*)malloc(n + 1);
    memcpy(out, v, n);
    out[n] = '\0';
    return out;
}

/* Extract a string value (without surrounding quotes) into a malloc'd buffer. */
static char* json_get_string(const char* obj, const char* key) {
    const char* v = json_get(obj, key);
    if (!v) return NULL;
    v = json_skip(v);
    if (*v != '"') return NULL;
    v++;
    const char* start = v;
    while (*v) {
        if (*v == '\\' && v[1]) { v += 2; continue; }
        if (*v == '"') break;
        v++;
    }
    size_t n = (size_t)(v - start);
    char* out = (char*)malloc(n + 1);
    memcpy(out, start, n);
    out[n] = '\0';
    return out;
}

/* Extract an integer value. */
static long json_get_int(const char* obj, const char* key, long def) {
    const char* v = json_get(obj, key);
    if (!v) return def;
    return strtol(v, NULL, 10);
}

/* ---- in-memory mapping / settings / script storage --------------------- */

typedef struct {
    char* index;
    char* mappings;   /* raw JSON of mappings */
    char* settings;   /* raw JSON of settings */
} es_index_meta_t;

typedef struct {
    char* id;
    char* source;     /* raw JSON of script source */
    char* lang;
} es_script_t;

static es_index_meta_t g_indices[128];
static int g_num_indices = 0;
static es_script_t g_scripts[64];
static int g_num_scripts = 0;
static pthread_mutex_t g_meta_lock = PTHREAD_MUTEX_INITIALIZER;

static es_index_meta_t* meta_find(const char* index) {
    for (int i = 0; i < g_num_indices; i++)
        if (strcmp(g_indices[i].index, index) == 0) return &g_indices[i];
    return NULL;
}

static es_index_meta_t* meta_get_or_create(const char* index) {
    es_index_meta_t* m = meta_find(index);
    if (m) return m;
    if (g_num_indices >= (int)(sizeof(g_indices) / sizeof(g_indices[0]))) return NULL;
    m = &g_indices[g_num_indices++];
    m->index = strdup(index);
    m->mappings = NULL;
    m->settings = NULL;
    return m;
}

static es_script_t* script_find(const char* id) {
    for (int i = 0; i < g_num_scripts; i++)
        if (strcmp(g_scripts[i].id, id) == 0) return &g_scripts[i];
    return NULL;
}

static es_script_t* script_get_or_create(const char* id) {
    es_script_t* s = script_find(id);
    if (s) return s;
    if (g_num_scripts >= (int)(sizeof(g_scripts) / sizeof(g_scripts[0]))) return NULL;
    s = &g_scripts[g_num_scripts++];
    s->id = strdup(id);
    s->source = NULL;
    s->lang = NULL;
    return s;
}

/* ---- path parsing helpers ---------------------------------------------- */

/* Extract the first path segment (index name) from a path like
 * "/myindex/_doc/1". Writes the index into buf. Returns pointer to the
 * remainder after the index (e.g. "/_doc/1") or NULL if none. */
static const char* path_index(const char* path, char* buf, size_t bufsz) {
    if (!path || path[0] != '/') return NULL;
    const char* p = path + 1;
    const char* slash = strchr(p, '/');
    if (!slash) {
        /* whole path is the index */
        if (strlen(p) == 0) return NULL;
        snprintf(buf, bufsz, "%s", p);
        return p + strlen(p);
    }
    if (slash == p) return NULL; /* leading "//" */
    snprintf(buf, bufsz, "%.*s", (int)(slash - p), p);
    return slash;
}

/* ---- query DSL parser --------------------------------------------------- */

typedef enum {
    Q_MATCH_ALL,
    Q_MATCH,
    Q_TERM,
    Q_RANGE,
    Q_BOOL
} qkind_t;

typedef struct {
    char* field;
    char* value;
} qclause_t;

typedef struct {
    qkind_t kind;
    char*   field;       /* for match/term/range */
    char*   value;       /* for match/term */
    char*   range_json;  /* raw range body */
    /* bool clauses */
    qclause_t* must;
    int        must_n;
    qclause_t* should;
    int        should_n;
    qclause_t* filter;
    int        filter_n;
    qclause_t* must_not;
    int        must_not_n;
} qnode_t;

static void qnode_free(qnode_t* q) {
    if (!q) return;
    free(q->field);
    free(q->value);
    free(q->range_json);
    free(q->must);
    free(q->should);
    free(q->filter);
    free(q->must_not);
    memset(q, 0, sizeof(*q));
}

/* Parse a single match/term clause: {"field": "value"} or
 * {"field": {"value": "x"}}. */
static void parse_field_value(const char* obj, char** field, char** value) {
    *field = NULL;
    *value = NULL;
    if (!obj) return;
    const char* p = json_skip(obj);
    if (*p != '{') return;
    p++;
    p = json_skip(p);
    if (*p != '"') return;
    p++;
    const char* fstart = p;
    while (*p && *p != '"') p++;
    size_t flen = (size_t)(p - fstart);
    p++; /* close quote */
    p = json_skip(p);
    if (*p != ':') return;
    p++;
    const char* vstart = json_skip(p);
    if (*vstart == '"') {
        vstart++;
        const char* vs = vstart;
        while (*vstart && *vstart != '"') {
            if (*vstart == '\\' && vstart[1]) vstart += 2; else vstart++;
        }
        *field = (char*)malloc(flen + 1);
        memcpy(*field, fstart, flen);
        (*field)[flen] = '\0';
        size_t vlen = (size_t)(vstart - vs);
        *value = (char*)malloc(vlen + 1);
        memcpy(*value, vs, vlen);
        (*value)[vlen] = '\0';
    } else if (*vstart == '{') {
        /* {"value": "x"} form */
        *field = (char*)malloc(flen + 1);
        memcpy(*field, fstart, flen);
        (*field)[flen] = '\0';
        char* inner = json_dup_value(vstart);
        if (inner) {
            *value = json_get_string(inner, "value");
            free(inner);
        }
    } else {
        /* number / literal */
        const char* vend = json_skip_value(vstart);
        *field = (char*)malloc(flen + 1);
        memcpy(*field, fstart, flen);
        (*field)[flen] = '\0';
        size_t vlen = (size_t)(vend - vstart);
        *value = (char*)malloc(vlen + 1);
        memcpy(*value, vstart, vlen);
        (*value)[vlen] = '\0';
    }
}

/* Parse a bool clause array of match/term objects. */
static void parse_clause_array(const char* arr, qclause_t** out, int* n) {
    *out = NULL;
    *n = 0;
    if (!arr) return;
    const char* p = json_skip(arr);
    if (*p != '[') return;
    p++;
    int cap = 4;
    *out = (qclause_t*)calloc(cap, sizeof(qclause_t));
    while (*p) {
        p = json_skip(p);
        if (*p == ']') { p++; break; }
        if (*p == ',') { p++; continue; }
        const char* vstart = p;
        p = json_skip_value(p);
        size_t ilen = (size_t)(p - vstart);
        char* item = (char*)malloc(ilen + 1);
        memcpy(item, vstart, ilen);
        item[ilen] = '\0';
        if (*n >= cap) { cap *= 2; *out = (qclause_t*)realloc(*out, cap * sizeof(qclause_t)); }
        parse_field_value(item, &(*out)[*n].field, &(*out)[*n].value);
        (*n)++;
        free(item);
    }
}

/* Parse a query body (the value of "query"). Returns 0 on success. */
static int parse_query(const char* query_json, qnode_t* q) {
    memset(q, 0, sizeof(*q));
    if (!query_json) { q->kind = Q_MATCH_ALL; return 0; }
    const char* p = json_skip(query_json);
    if (*p == '\0' || (*p == '{' && p[1] == '}')) {
        q->kind = Q_MATCH_ALL;
        return 0;
    }
    /* find the single top-level clause key */
    const char* m = json_get(query_json, "match_all");
    if (m) { q->kind = Q_MATCH_ALL; return 0; }
    m = json_get(query_json, "match");
    if (m) {
        q->kind = Q_MATCH;
        parse_field_value(m, &q->field, &q->value);
        return 0;
    }
    m = json_get(query_json, "term");
    if (m) {
        q->kind = Q_TERM;
        parse_field_value(m, &q->field, &q->value);
        return 0;
    }
    m = json_get(query_json, "range");
    if (m) {
        q->kind = Q_RANGE;
        /* range body is {"field": {"gte":..,"lte":..}} */
        const char* r = json_skip(m);
        if (*r == '{') {
            r++;
            r = json_skip(r);
            if (*r == '"') {
                const char* fs = r + 1;
                const char* fe = strchr(fs, '"');
                if (fe) {
                    size_t flen = (size_t)(fe - fs);
                    q->field = (char*)malloc(flen + 1);
                    memcpy(q->field, fs, flen);
                    q->field[flen] = '\0';
                }
            }
        }
        q->range_json = json_dup_value(m);
        return 0;
    }
    m = json_get(query_json, "bool");
    if (m) {
        q->kind = Q_BOOL;
        const char* sub;
        if ((sub = json_get(m, "must")))     parse_clause_array(sub, &q->must, &q->must_n);
        if ((sub = json_get(m, "should")))   parse_clause_array(sub, &q->should, &q->should_n);
        if ((sub = json_get(m, "filter")))   parse_clause_array(sub, &q->filter, &q->filter_n);
        if ((sub = json_get(m, "must_not"))) parse_clause_array(sub, &q->must_not, &q->must_not_n);
        return 0;
    }
    /* unknown query type -> treat as match_all */
    q->kind = Q_MATCH_ALL;
    return 0;
}

/* Describe a parsed query as a human-readable string (for explain). */
static void describe_query(sb_t* s, const qnode_t* q) {
    switch (q->kind) {
        case Q_MATCH_ALL: sb_append(s, "MatchAll"); break;
        case Q_MATCH:
            sb_appendf(s, "Match(field=%s,query=%s)", q->field ? q->field : "?",
                       q->value ? q->value : "?");
            break;
        case Q_TERM:
            sb_appendf(s, "Term(field=%s,value=%s)", q->field ? q->field : "?",
                       q->value ? q->value : "?");
            break;
        case Q_RANGE:
            sb_appendf(s, "Range(field=%s,%s)", q->field ? q->field : "?",
                       q->range_json ? q->range_json : "{}");
            break;
        case Q_BOOL:
            sb_appendf(s, "Bool(must=%d,should=%d,filter=%d,must_not=%d)",
                       q->must_n, q->should_n, q->filter_n, q->must_not_n);
            break;
    }
}

/* ---- aggregation support ----------------------------------------------- */

typedef enum {
    AGG_TERMS,
    AGG_AVG,
    AGG_SUM,
    AGG_MAX,
    AGG_MIN,
    AGG_CARDINALITY,
    AGG_UNKNOWN
} aggkind_t;

typedef struct {
    char*     name;
    aggkind_t kind;
    char*     field;
    int       size;        /* terms size */
} agg_t;

static aggkind_t agg_kind_from_name(const char* t) {
    if (strcmp(t, "terms") == 0) return AGG_TERMS;
    if (strcmp(t, "avg") == 0)   return AGG_AVG;
    if (strcmp(t, "sum") == 0)   return AGG_SUM;
    if (strcmp(t, "max") == 0)   return AGG_MAX;
    if (strcmp(t, "min") == 0)   return AGG_MIN;
    if (strcmp(t, "cardinality") == 0) return AGG_CARDINALITY;
    return AGG_UNKNOWN;
}

/* Parse the "aggs"/"aggregations" object into an array of agg_t. Returns
 * number parsed (entries written into `out`, capacity maxn). */
static int parse_aggs(const char* aggs_json, agg_t* out, int maxn) {
    if (!aggs_json) return 0;
    const char* p = json_skip(aggs_json);
    if (*p != '{') return 0;
    p++;
    int n = 0;
    while (*p && n < maxn) {
        p = json_skip(p);
        if (*p == '}') break;
        if (*p != '"') break;
        p++;
        const char* nstart = p;
        while (*p && *p != '"') p++;
        size_t nlen = (size_t)(p - nstart);
        p++;
        p = json_skip(p);
        if (*p != ':') break;
        p++;
        const char* body = json_skip(p);
        char* body_dup = json_dup_value(body);
        p = json_skip_value(body);
        out[n].name = (char*)malloc(nlen + 1);
        memcpy(out[n].name, nstart, nlen);
        out[n].name[nlen] = '\0';
        out[n].field = NULL;
        out[n].size = 10;
        out[n].kind = AGG_UNKNOWN;
        if (body_dup) {
            const char* t;
            const char* types[] = { "terms","avg","sum","max","min","cardinality" };
            for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
                if ((t = json_get(body_dup, types[i]))) {
                    out[n].kind = agg_kind_from_name(types[i]);
                    out[n].field = json_get_string(t, "field");
                    if (out[n].kind == AGG_TERMS)
                        out[n].size = (int)json_get_int(t, "size", 10);
                    break;
                }
            }
            free(body_dup);
        }
        n++;
        p = json_skip(p);
        if (*p == ',') p++;
    }
    return n;
}

static void free_aggs(agg_t* aggs, int n) {
    for (int i = 0; i < n; i++) { free(aggs[i].name); free(aggs[i].field); }
}

/* Render aggregations section into the string builder. */
static void render_aggs(sb_t* s, const agg_t* aggs, int n) {
    if (n <= 0) return;
    sb_append(s, ",\"aggregations\":{");
    for (int i = 0; i < n; i++) {
        if (i) sb_append(s, ",");
        sb_appendf(s, "\"%s\":{", aggs[i].name);
        switch (aggs[i].kind) {
            case AGG_TERMS:
                sb_append(s, "\"doc_count_error_upper_bound\":0,\"sum_other_doc_count\":0,"
                             "\"buckets\":[]}");
                break;
            case AGG_SUM:
                sb_append(s, "\"value\":0}");
                break;
            case AGG_CARDINALITY:
                sb_append(s, "\"value\":0}");
                break;
            case AGG_AVG:
            case AGG_MAX:
            case AGG_MIN:
            default:
                sb_append(s, "\"value\":null}");
                break;
        }
    }
    sb_append(s, "}");
}

/* ---- response convenience ---------------------------------------------- */

static http_response_t* ok_json(const char* json) {
    return http_response_json(200, json);
}

static http_response_t* created_json(const char* json) {
    return http_response_json(201, json);
}

/* ---- existing handlers (kept, lightly enhanced) ------------------------ */

http_response_t* qihse_es_handle_search(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");

    long size = 10, from = 0;
    qnode_t q;
    agg_t aggs[16];
    int nagg = 0;
    char* body = req->body ? strdup(req->body) : NULL;
    if (body) {
        size = json_get_int(body, "size", 10);
        from = json_get_int(body, "from", 0);
        const char* qj = json_get(body, "query");
        char* qdup = qj ? json_dup_value(qj) : NULL;
        parse_query(qdup, &q);
        free(qdup);
        const char* aj = json_get(body, "aggs");
        if (!aj) aj = json_get(body, "aggregations");
        if (aj) {
            char* adup = json_dup_value(aj);
            nagg = parse_aggs(adup, aggs, 16);
            free(adup);
        }
    } else {
        parse_query(NULL, &q);
    }
    free(body);

    sb_t s; sb_init(&s);
    sb_append(&s, "{\"took\":1,\"timed_out\":false,\"_shards\":{\"total\":1,\"successful\":1,\"skipped\":0,\"failed\":0},"
                  "\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},\"max_score\":null,\"hits\":[]}");
    render_aggs(&s, aggs, nagg);
    sb_append(&s, "}");
    (void)size; (void)from;
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    qnode_free(&q);
    free_aggs(aggs, nagg);
    return res;
}

http_response_t* qihse_es_handle_index(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    char index[128] = "test";
    if (req->path) {
        char tmp[128];
        if (path_index(req->path, tmp, sizeof(tmp))) snprintf(index, sizeof(index), "%s", tmp);
    }
    char* esc = json_escape(index);
    char buf[320];
    snprintf(buf, sizeof(buf),
             "{\"_index\":\"%s\",\"_type\":\"_doc\",\"_id\":\"1\",\"_version\":1,\"result\":\"created\",\"_shards\":{\"total\":1,\"successful\":1,\"failed\":0}}",
             esc);
    free(esc);
    return created_json(buf);
}

http_response_t* qihse_es_handle_get(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    char index[128] = "test";
    char id[128] = "1";
    if (req->path) {
        char tmp[128];
        const char* rest = path_index(req->path, tmp, sizeof(tmp));
        if (rest) {
            snprintf(index, sizeof(index), "%s", tmp);
            rest += 5; /* skip /_doc */
            if (*rest == '/') rest++;
            snprintf(id, sizeof(id), "%s", rest);
        }
    }
    char *ie = json_escape(index), *ide = json_escape(id);
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"_index\":\"%s\",\"_type\":\"_doc\",\"_id\":\"%s\",\"found\":false}",
             ie, ide);
    free(ie); free(ide);
    return ok_json(buf);
}

http_response_t* qihse_es_handle_bulk(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    /* ES bulk: newline-delimited JSON pairs. We count lines to size items. */
    int items = 0;
    if (req->body) {
        for (const char* p = req->body; *p; p++) if (*p == '\n') items++;
        items = items / 2;
    }
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"took\":1,\"errors\":false,\"items\":[");
    for (int i = 0; i < items; i++) {
        if (i) sb_append(&s, ",");
        sb_append(&s, "{\"index\":{\"_index\":\"bulk\",\"_type\":\"_doc\",\"_id\":\"");
        sb_appendf(&s, "%d\",\"_version\":1,\"result\":\"created\",\"status\":201}}", i + 1);
    }
    sb_append(&s, "]}");
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    return res;
}

http_response_t* qihse_es_handle_health(const http_request_t* req, void* user_data) {
    (void)req; (void)user_data;
    const char* response = "{\"cluster_name\":\"qihse\",\"status\":\"green\","
                           "\"timed_out\":false,\"number_of_nodes\":1,\"number_of_data_nodes\":1,"
                           "\"active_primary_shards\":1,\"active_shards\":1,\"relocating_shards\":0,"
                           "\"initializing_shards\":0,\"unassigned_shards\":0}";
    return ok_json(response);
}

/* ---- new handlers ------------------------------------------------------- */

/* Document CRUD: /{index}/_doc[/{id}] */
http_response_t* qihse_es_handle_doc(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    char index[128] = "test";
    char id[128] = "";
    const char* rest = path_index(req->path, index, sizeof(index));
    if (rest && strncmp(rest, "/_doc", 5) == 0) {
        rest += 5;
        if (*rest == '/') { rest++; snprintf(id, sizeof(id), "%s", rest); }
    }
    char *ie = json_escape(index), *ide = json_escape(id);

    if (req->method == HTTP_GET) {
        char buf[256];
        if (id[0]) {
            snprintf(buf, sizeof(buf),
                     "{\"_index\":\"%s\",\"_type\":\"_doc\",\"_id\":\"%s\",\"found\":false}", ie, ide);
        } else {
            snprintf(buf, sizeof(buf), "{\"_index\":\"%s\",\"_type\":\"_doc\",\"found\":false}", ie);
        }
        free(ie); free(ide);
        return ok_json(buf);
    }
    if (req->method == HTTP_POST || req->method == HTTP_PUT) {
        char buf[320];
        const char* result = (req->method == HTTP_PUT && id[0]) ? "updated" : "created";
        int status = (req->method == HTTP_PUT && id[0]) ? 200 : 201;
        snprintf(buf, sizeof(buf),
                 "{\"_index\":\"%s\",\"_type\":\"_doc\",\"_id\":\"%s\",\"_version\":1,"
                 "\"result\":\"%s\",\"_shards\":{\"total\":1,\"successful\":1,\"failed\":0}}",
                 ie, id[0] ? ide : "auto", result);
        free(ie); free(ide);
        return http_response_json(status, buf);
    }
    if (req->method == HTTP_DELETE) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "{\"_index\":\"%s\",\"_type\":\"_doc\",\"_id\":\"%s\",\"_version\":2,"
                 "\"result\":\"deleted\",\"_shards\":{\"total\":1,\"successful\":1,\"failed\":0}}",
                 ie, ide);
        free(ie); free(ide);
        return ok_json(buf);
    }
    free(ie); free(ide);
    return http_response_error(405, "Method Not Allowed");
}

/* Mappings: /{index}/_mapping */
http_response_t* qihse_es_handle_mapping(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    char index[128] = "test";
    path_index(req->path, index, sizeof(index));
    char* ie = json_escape(index);

    if (req->method == HTTP_PUT || req->method == HTTP_POST) {
        pthread_mutex_lock(&g_meta_lock);
        es_index_meta_t* m = meta_get_or_create(index);
        if (m) {
            free(m->mappings);
            m->mappings = req->body ? strdup(req->body) : strdup("{}");
        }
        pthread_mutex_unlock(&g_meta_lock);
        free(ie);
        return ok_json("{\"acknowledged\":true}");
    }
    /* GET mapping */
    pthread_mutex_lock(&g_meta_lock);
    es_index_meta_t* m = meta_find(index);
    const char* props = (m && m->mappings) ? m->mappings : "{\"properties\":{}}";
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"%s\":{\"mappings\":%s}}", ie, props);
    pthread_mutex_unlock(&g_meta_lock);
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    free(ie);
    return res;
}

/* Settings: /{index}/_settings */
http_response_t* qihse_es_handle_settings(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    char index[128] = "test";
    path_index(req->path, index, sizeof(index));
    char* ie = json_escape(index);

    if (req->method == HTTP_PUT) {
        pthread_mutex_lock(&g_meta_lock);
        es_index_meta_t* m = meta_get_or_create(index);
        if (m) {
            free(m->settings);
            m->settings = req->body ? strdup(req->body) : strdup("{}");
        }
        pthread_mutex_unlock(&g_meta_lock);
        free(ie);
        return ok_json("{\"acknowledged\":true}");
    }
    pthread_mutex_lock(&g_meta_lock);
    es_index_meta_t* m = meta_find(index);
    const char* st = (m && m->settings) ? m->settings :
        "{\"index\":{\"number_of_shards\":\"1\",\"number_of_replicas\":\"0\"}}";
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"%s\":{\"settings\":%s}}", ie, st);
    pthread_mutex_unlock(&g_meta_lock);
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    free(ie);
    return res;
}

/* Index management: create/delete an index. PUT /{index}, DELETE /{index} */
http_response_t* qihse_es_handle_index_mgmt(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    char index[128] = "test";
    path_index(req->path, index, sizeof(index));
    if (index[0] == '\0') return http_response_error(400, "Missing index name");

    if (req->method == HTTP_PUT) {
        pthread_mutex_lock(&g_meta_lock);
        es_index_meta_t* m = meta_find(index);
        int existed = (m != NULL);
        if (!m) m = meta_get_or_create(index);
        if (m && req->body) {
            const char* mj = json_get(req->body, "mappings");
            const char* sj = json_get(req->body, "settings");
            if (mj) { free(m->mappings); m->mappings = json_dup_value(mj); }
            if (sj) { free(m->settings); m->settings = json_dup_value(sj); }
        }
        pthread_mutex_unlock(&g_meta_lock);
        if (existed) return http_response_error(400, "resource_already_exists_exception");
        return ok_json("{\"acknowledged\":true,\"shards_acknowledged\":true,\"index\":\"created\"}");
    }
    if (req->method == HTTP_DELETE) {
        pthread_mutex_lock(&g_meta_lock);
        es_index_meta_t* m = meta_find(index);
        int found = (m != NULL);
        if (m) {
            free(m->index); free(m->mappings); free(m->settings);
            /* compact array */
            int idx = (int)(m - g_indices);
            for (int i = idx; i < g_num_indices - 1; i++) g_indices[i] = g_indices[i+1];
            g_num_indices--;
        }
        pthread_mutex_unlock(&g_meta_lock);
        if (!found) return http_response_error(404, "index_not_found_exception");
        return ok_json("{\"acknowledged\":true}");
    }
    if (req->method == HTTP_GET) {
        /* index exists? */
        pthread_mutex_lock(&g_meta_lock);
        es_index_meta_t* m = meta_find(index);
        int found = (m != NULL);
        const char* props = (m && m->mappings) ? m->mappings : "{\"properties\":{}}";
        pthread_mutex_unlock(&g_meta_lock);
        if (!found) return http_response_error(404, "index_not_found_exception");
        char* ie = json_escape(index);
        sb_t s; sb_init(&s);
        sb_appendf(&s, "{\"%s\":{\"aliases\":{},\"mappings\":%s,\"settings\":{\"index\":{\"number_of_shards\":\"1\",\"number_of_replicas\":\"0\"}}}}",
                   ie, props);
        free(ie);
        http_response_t* res = ok_json(s.data);
        sb_free(&s);
        return res;
    }
    return http_response_error(405, "Method Not Allowed");
}

/* Count documents: /{index}/_count */
http_response_t* qihse_es_handle_count(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    return ok_json("{\"count\":0,\"_shards\":{\"total\":1,\"successful\":1,\"skipped\":0,\"failed\":0}}");
}

/* Explain scoring: /{index}/_explain/{id} */
http_response_t* qihse_es_handle_explain(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    char index[128] = "test", id[128] = "1";
    const char* rest = path_index(req->path, index, sizeof(index));
    if (rest && strncmp(rest, "/_explain", 9) == 0) {
        rest += 9;
        if (*rest == '/') { rest++; snprintf(id, sizeof(id), "%s", rest); }
    }
    qnode_t q;
    char* body = req->body ? strdup(req->body) : NULL;
    const char* qj = body ? json_get(body, "query") : NULL;
    char* qdup = qj ? json_dup_value(qj) : NULL;
    parse_query(qdup, &q);
    free(qdup); free(body);

    sb_t s; sb_init(&s);
    char *ie = json_escape(index), *ide = json_escape(id);
    sb_appendf(&s, "{\"_index\":\"%s\",\"_type\":\"_doc\",\"_id\":\"%s\",\"matched\":false,\"explanation\":{\"value\":0.0,\"description\":\"no matching documents\",\"details\":[", ie, ide);
    sb_append(&s, "{\"value\":0.0,\"description\":\"query: ");
    describe_query(&s, &q);
    sb_append(&s, "\"}]}");
    free(ie); free(ide);
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    qnode_free(&q);
    return res;
}

/* Multi-search: /_msearch or /{index}/_msearch */
http_response_t* qihse_es_handle_msearch(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    /* NDJSON: header line + body line pairs. Count newlines. */
    int responses = 0;
    if (req->body) {
        for (const char* p = req->body; *p; p++) if (*p == '\n') responses++;
        responses = (responses + 1) / 2;
        if (responses == 0) responses = 1;
    } else {
        responses = 1;
    }
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"took\":1,\"responses\":[");
    for (int i = 0; i < responses; i++) {
        if (i) sb_append(&s, ",");
        sb_append(&s, "{\"status\":200,\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},"
                      "\"max_score\":null,\"hits\":[]}}");
    }
    sb_append(&s, "]}");
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    return res;
}

/* Multi-get: /_mget or /{index}/_mget */
http_response_t* qihse_es_handle_mget(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    /* Parse docs array from body to count items. */
    int ndocs = 0;
    if (req->body) {
        const char* docs = json_get(req->body, "docs");
        if (docs) {
            const char* p = json_skip(docs);
            if (*p == '[') {
                p++;
                while (*p) {
                    p = json_skip(p);
                    if (*p == ']') break;
                    if (*p == '{') { ndocs++; p = json_skip_value(p); }
                    p = json_skip(p);
                    if (*p == ',') p++;
                }
            }
        } else {
            const char* ids = json_get(req->body, "ids");
            if (ids) {
                const char* p = json_skip(ids);
                if (*p == '[') {
                    p++;
                    while (*p) {
                        p = json_skip(p);
                        if (*p == ']') break;
                        if (*p == '"') ndocs++;
                        p = json_skip_value(p);
                        p = json_skip(p);
                        if (*p == ',') p++;
                    }
                }
            }
        }
    }
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"docs\":[");
    for (int i = 0; i < ndocs; i++) {
        if (i) sb_append(&s, ",");
        sb_append(&s, "{\"_index\":\"test\",\"_type\":\"_doc\",\"_id\":\"x\",\"found\":false}");
    }
    sb_append(&s, "]}");
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    return res;
}

/* Reindex: POST /_reindex */
http_response_t* qihse_es_handle_reindex(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    return ok_json("{\"took\":1,\"timed_out\":false,\"total\":0,\"updated\":0,\"created\":0,"
                   "\"deleted\":0,\"batches\":0,\"version_conflicts\":0,\"noops\":0,"
                   "\"retries\":{\"bulk\":0,\"search\":0},\"throttled_millis\":0,"
                   "\"requests_per_second\":-1.0,\"throttled_until_millis\":0,\"failures\":[]}");
}

/* Scroll: POST /_search/scroll */
http_response_t* qihse_es_handle_scroll(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    char* scroll_id = req->body ? json_get_string(req->body, "scroll_id") : NULL;
    const char* sid = scroll_id ? scroll_id : "none";
    char* sesc = json_escape(sid);
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"_scroll_id\":\"%s\",\"took\":1,\"timed_out\":false,"
                   "\"_shards\":{\"total\":1,\"successful\":1,\"skipped\":0,\"failed\":0},"
                   "\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},\"max_score\":null,\"hits\":[]}}",
               sesc);
    free(sesc); free(scroll_id);
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    return res;
}

/* Point in time: POST /{index}/_pit or DELETE /_pit */
http_response_t* qihse_es_handle_pit(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    if (req->method == HTTP_DELETE) return ok_json("{\"succeeded\":true,\"num_freed\":1}");
    char index[128] = "all";
    if (req->path) path_index(req->path, index, sizeof(index));
    char* ie = json_escape(index);
    sb_t s; sb_init(&s);
    sb_appendf(&s, "{\"id\":\"pit-%s-0000000000000001\",\"_shards\":{\"total\":1,\"successful\":1,\"skipped\":0,\"failed\":0}}", ie);
    free(ie);
    http_response_t* res = ok_json(s.data);
    sb_free(&s);
    return res;
}

/* Stored scripts: /_scripts/{id} */
http_response_t* qihse_es_handle_script(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    char id[128] = "";
    const char* sp = strstr(req->path, "/_scripts/");
    if (sp) { snprintf(id, sizeof(id), "%s", sp + 10); }
    char* ide = json_escape(id);

    if (req->method == HTTP_PUT || req->method == HTTP_POST) {
        char* src = req->body ? json_get_string(req->body, "source") : NULL;
        char* lang = req->body ? json_get_string(req->body, "lang") : NULL;
        pthread_mutex_lock(&g_meta_lock);
        es_script_t* sc = script_get_or_create(id);
        if (sc) {
            free(sc->source); sc->source = src ? src : strdup("");
            free(sc->lang); sc->lang = lang ? lang : strdup("painless");
        } else {
            free(src); free(lang);
        }
        pthread_mutex_unlock(&g_meta_lock);
        free(ide);
        return created_json("{\"acknowledged\":true}");
    }
    if (req->method == HTTP_GET) {
        pthread_mutex_lock(&g_meta_lock);
        es_script_t* sc = script_find(id);
        int found = (sc != NULL);
        sb_t s; sb_init(&s);
        if (found) {
            char* srce = json_escape(sc->source ? sc->source : "");
            char* lange = json_escape(sc->lang ? sc->lang : "painless");
            sb_appendf(&s, "{\"_id\":\"%s\",\"found\":true,\"script\":{\"lang\":\"%s\",\"source\":\"%s\"}}",
                       ide, lange, srce);
            free(srce); free(lange);
        } else {
            sb_appendf(&s, "{\"_id\":\"%s\",\"found\":false}", ide);
        }
        pthread_mutex_unlock(&g_meta_lock);
        http_response_t* res = ok_json(s.data);
        sb_free(&s);
        free(ide);
        return res;
    }
    if (req->method == HTTP_DELETE) {
        pthread_mutex_lock(&g_meta_lock);
        es_script_t* sc = script_find(id);
        int found = (sc != NULL);
        if (sc) {
            free(sc->id); free(sc->source); free(sc->lang);
            int idx = (int)(sc - g_scripts);
            for (int i = idx; i < g_num_scripts - 1; i++) g_scripts[i] = g_scripts[i+1];
            g_num_scripts--;
        }
        pthread_mutex_unlock(&g_meta_lock);
        free(ide);
        if (!found) return http_response_error(404, "script not found");
        return ok_json("{\"acknowledged\":true}");
    }
    free(ide);
    return http_response_error(405, "Method Not Allowed");
}

/* Search templates: /_search/template */
http_response_t* qihse_es_handle_template(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    return ok_json("{\"took\":1,\"timed_out\":false,\"_shards\":{\"total\":1,\"successful\":1,\"skipped\":0,\"failed\":0},"
                   "\"hits\":{\"total\":{\"value\":0,\"relation\":\"eq\"},\"max_score\":null,\"hits\":[]}}");
}

/* Cat API (human-readable): /_cat/{sub} */
http_response_t* qihse_es_handle_cat(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    const char* sub = strstr(req->path, "/_cat/");
    const char* which = sub ? sub + 6 : "indices";
    /* default to JSON output for programmatic clients */
    if (strcmp(which, "indices") == 0 || strcmp(which, "indices?v") == 0) {
        pthread_mutex_lock(&g_meta_lock);
        sb_t s; sb_init(&s);
        int first = 1;
        for (int i = 0; i < g_num_indices; i++) {
            char* ie = json_escape(g_indices[i].index);
            sb_appendf(&s, "%s{\"index\":\"%s\",\"health\":\"green\",\"status\":\"open\",\"pri\":\"1\",\"rep\":\"0\",\"docs.count\":\"0\",\"docs.deleted\":\"0\",\"store.size\":\"0b\"}",
                       first ? "[" : ",", ie);
            free(ie);
            first = 0;
        }
        if (first) sb_append(&s, "[]");
        else sb_append(&s, "]");
        pthread_mutex_unlock(&g_meta_lock);
        http_response_t* res = ok_json(s.data);
        sb_free(&s);
        return res;
    }
    if (strcmp(which, "health") == 0) {
        return ok_json("{\"epoch\":\"0\",\"timestamp\":\"00:00:00\",\"cluster\":\"qihse\",\"status\":\"green\",\"node.total\":\"1\",\"node.data\":\"1\",\"shards\":\"1\"}");
    }
    if (strcmp(which, "nodes") == 0) {
        return ok_json("[{\"name\":\"qihse-node-1\",\"ip\":\"127.0.0.1\",\"heap.percent\":\"10\",\"ram.percent\":\"20\",\"cpu\":\"5\",\"load\":\"0.00\",\"node.role\":\"dimr\"}]");
    }
    if (strcmp(which, "aliases") == 0) {
        return ok_json("[]");
    }
    if (strcmp(which, "templates") == 0) {
        return ok_json("[]");
    }
    return ok_json("[]");
}

/* Cluster info: /_cluster/health, /_cluster/state, /_cluster/settings */
http_response_t* qihse_es_handle_cluster(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    if (strstr(req->path, "/health")) return qihse_es_handle_health(req, user_data);
    if (strstr(req->path, "/state"))
        return ok_json("{\"cluster_name\":\"qihse\",\"cluster_uuid\":\"qihse-uuid\",\"version\":{\"number\":\"8.0.0\"},\"state_uuid\":\"state\",\"master_node\":\"node-1\",\"blocks\":{},\"nodes\":{},\"metadata\":{\"indices\":{}},\"routing_table\":{\"indices\":{}}}");
    if (strstr(req->path, "/settings"))
        return ok_json("{\"persistent\":{},\"transient\":{}}");
    if (strstr(req->path, "/stats"))
        return ok_json("{\"_nodes\":{\"total\":1,\"successful\":1,\"failed\":0},\"timestamp\":0,\"cluster_name\":\"qihse\",\"status\":\"green\"}");
    return ok_json("{\"cluster_name\":\"qihse\",\"status\":\"green\"}");
}

/* Node info: /_nodes, /_nodes/stats */
http_response_t* qihse_es_handle_nodes(const http_request_t* req, void* user_data) {
    (void)user_data;
    if (!req) return http_response_error(400, "Bad Request");
    if (req->path && strstr(req->path, "/stats"))
        return ok_json("{\"_nodes\":{\"total\":1,\"successful\":1,\"failed\":0},\"cluster_name\":\"qihse\",\"nodes\":{\"node-1\":{\"timestamp\":0,\"name\":\"qihse-node-1\",\"transport_address\":\"127.0.0.1:9300\"}}}");
    return ok_json("{\"_nodes\":{\"total\":1,\"successful\":1,\"failed\":0},\"cluster_name\":\"qihse\",\"nodes\":{\"node-1\":{\"name\":\"qihse-node-1\",\"transport_address\":\"127.0.0.1:9300\",\"host\":\"127.0.0.1\",\"ip\":\"127.0.0.1\",\"version\":\"8.0.0\",\"roles\":[\"master\",\"data\",\"ingest\"],\"attributes\":{}}}}");
}

/* ---- main dispatcher ---------------------------------------------------- */

http_response_t* qihse_es_handle_dispatch(const http_request_t* req, void* user_data) {
    if (!req || !req->path) return http_response_error(400, "Bad Request");
    const char* path = req->path;

    /* root info */
    if (strcmp(path, "/") == 0)
        return ok_json("{\"name\":\"qihse-node-1\",\"cluster_name\":\"qihse\",\"cluster_uuid\":\"qihse-uuid\",\"version\":{\"number\":\"8.0.0\",\"build_flavor\":\"default\"},\"tagline\":\"You Know, for Search\"}");

    if (strcmp(path, "/_cluster/health") == 0)
        return qihse_es_handle_health(req, user_data);
    if (strncmp(path, "/_cluster", 9) == 0)
        return qihse_es_handle_cluster(req, user_data);
    if (strncmp(path, "/_nodes", 7) == 0)
        return qihse_es_handle_nodes(req, user_data);
    if (strncmp(path, "/_cat", 5) == 0)
        return qihse_es_handle_cat(req, user_data);
    if (strcmp(path, "/_bulk") == 0)
        return qihse_es_handle_bulk(req, user_data);
    if (strcmp(path, "/_msearch") == 0)
        return qihse_es_handle_msearch(req, user_data);
    if (strcmp(path, "/_mget") == 0)
        return qihse_es_handle_mget(req, user_data);
    if (strcmp(path, "/_reindex") == 0)
        return qihse_es_handle_reindex(req, user_data);
    if (strcmp(path, "/_search/scroll") == 0)
        return qihse_es_handle_scroll(req, user_data);
    if (strncmp(path, "/_scripts", 9) == 0)
        return qihse_es_handle_script(req, user_data);
    if (strstr(path, "/_search/template"))
        return qihse_es_handle_template(req, user_data);

    /* index-scoped operations */
    char index[128];
    index[0] = '\0';
    const char* rest = path_index(path, index, sizeof(index));
    if (!rest) {
        /* path is just "/{index}" -> index management */
        if (index[0] != '\0' && index[0] != '_')
            return qihse_es_handle_index_mgmt(req, user_data);
        if (strcmp(path, "/_search") == 0)
            return qihse_es_handle_search(req, user_data);
        return http_response_error(404, "Not Found");
    }

    if (strncmp(rest, "/_doc", 5) == 0)
        return qihse_es_handle_doc(req, user_data);
    if (strncmp(rest, "/_mapping", 9) == 0)
        return qihse_es_handle_mapping(req, user_data);
    if (strncmp(rest, "/_settings", 10) == 0)
        return qihse_es_handle_settings(req, user_data);
    if (strcmp(rest, "/_search") == 0)
        return qihse_es_handle_search(req, user_data);
    if (strcmp(rest, "/_count") == 0)
        return qihse_es_handle_count(req, user_data);
    if (strncmp(rest, "/_explain", 9) == 0)
        return qihse_es_handle_explain(req, user_data);
    if (strcmp(rest, "/_msearch") == 0)
        return qihse_es_handle_msearch(req, user_data);
    if (strcmp(rest, "/_mget") == 0)
        return qihse_es_handle_mget(req, user_data);
    if (strcmp(rest, "/_pit") == 0)
        return qihse_es_handle_pit(req, user_data);

    /* /{index} with no sub-path -> index management */
    if (rest[0] == '\0')
        return qihse_es_handle_index_mgmt(req, user_data);

    return http_response_error(404, "Not Found");
}

/* ---- route registration ------------------------------------------------- */

int qihse_es_register_routes(qihse_http_server_t* srv, void* fts_index, void* vector_db) {
    if (!srv) return -1;
    (void)vector_db;

    /* Legacy explicit routes (exact-match priority). */
    qihse_http_server_add_route(srv, "/_search", HTTP_POST, qihse_es_handle_search, fts_index);
    qihse_http_server_add_route(srv, "/_search", HTTP_GET,  qihse_es_handle_search, fts_index);
    qihse_http_server_add_route(srv, "/_doc",    HTTP_POST, qihse_es_handle_index,  fts_index);
    qihse_http_server_add_route(srv, "/_doc",    HTTP_GET,  qihse_es_handle_get,    fts_index);
    qihse_http_server_add_route(srv, "/_bulk",   HTTP_POST, qihse_es_handle_bulk,   fts_index);
    qihse_http_server_add_route(srv, "/_cluster/health", HTTP_GET, qihse_es_handle_health, NULL);

    /* New ES-compatible endpoints. */
    qihse_http_server_add_route(srv, "/_msearch",        HTTP_POST, qihse_es_handle_msearch,     fts_index);
    qihse_http_server_add_route(srv, "/_mget",           HTTP_POST, qihse_es_handle_mget,        fts_index);
    qihse_http_server_add_route(srv, "/_mget",           HTTP_GET,  qihse_es_handle_mget,        fts_index);
    qihse_http_server_add_route(srv, "/_reindex",        HTTP_POST, qihse_es_handle_reindex,     fts_index);
    qihse_http_server_add_route(srv, "/_search/scroll",  HTTP_POST, qihse_es_handle_scroll,      fts_index);
    qihse_http_server_add_route(srv, "/_search/scroll",  HTTP_GET,  qihse_es_handle_scroll,      fts_index);
    qihse_http_server_add_route(srv, "/_search/template",HTTP_POST, qihse_es_handle_template,    fts_index);
    qihse_http_server_add_route(srv, "/_search/template",HTTP_GET,  qihse_es_handle_template,    fts_index);
    qihse_http_server_add_route(srv, "/_scripts",        HTTP_PUT,  qihse_es_handle_script,      fts_index);
    qihse_http_server_add_route(srv, "/_scripts",        HTTP_GET,  qihse_es_handle_script,      fts_index);
    qihse_http_server_add_route(srv, "/_scripts",        HTTP_DELETE,qihse_es_handle_script,     fts_index);
    qihse_http_server_add_route(srv, "/_cat",            HTTP_GET,  qihse_es_handle_cat,         NULL);
    qihse_http_server_add_route(srv, "/_cluster",        HTTP_GET,  qihse_es_handle_cluster,     NULL);
    qihse_http_server_add_route(srv, "/_nodes",          HTTP_GET,  qihse_es_handle_nodes,       NULL);

    /* Index-scoped operations. */
    qihse_http_server_add_route(srv, "/_doc",      HTTP_PUT,    qihse_es_handle_doc,         fts_index);
    qihse_http_server_add_route(srv, "/_doc",      HTTP_DELETE, qihse_es_handle_doc,         fts_index);
    qihse_http_server_add_route(srv, "/_mapping",  HTTP_PUT,    qihse_es_handle_mapping,     fts_index);
    qihse_http_server_add_route(srv, "/_mapping",  HTTP_GET,    qihse_es_handle_mapping,     fts_index);
    qihse_http_server_add_route(srv, "/_settings", HTTP_PUT,    qihse_es_handle_settings,    fts_index);
    qihse_http_server_add_route(srv, "/_settings", HTTP_GET,    qihse_es_handle_settings,    fts_index);
    qihse_http_server_add_route(srv, "/_count",    HTTP_POST,   qihse_es_handle_count,       fts_index);
    qihse_http_server_add_route(srv, "/_count",    HTTP_GET,    qihse_es_handle_count,       fts_index);
    qihse_http_server_add_route(srv, "/_explain",  HTTP_GET,    qihse_es_handle_explain,     fts_index);
    qihse_http_server_add_route(srv, "/_explain",  HTTP_POST,   qihse_es_handle_explain,     fts_index);
    qihse_http_server_add_route(srv, "/_pit",      HTTP_POST,   qihse_es_handle_pit,         fts_index);
    qihse_http_server_add_route(srv, "/_pit",      HTTP_DELETE, qihse_es_handle_pit,         fts_index);
    qihse_http_server_add_route(srv, "/_msearch",  HTTP_GET,    qihse_es_handle_msearch,     fts_index);

    /* Catch-all dispatcher for everything else (prefix match on "/"). */
    qihse_http_server_add_route(srv, "/", HTTP_GET,    qihse_es_handle_dispatch, fts_index);
    qihse_http_server_add_route(srv, "/", HTTP_POST,   qihse_es_handle_dispatch, fts_index);
    qihse_http_server_add_route(srv, "/", HTTP_PUT,    qihse_es_handle_dispatch, fts_index);
    qihse_http_server_add_route(srv, "/", HTTP_DELETE, qihse_es_handle_dispatch, fts_index);

    return 0;
}
