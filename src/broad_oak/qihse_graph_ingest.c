/* QIHSE Graph Bulk Ingest — Neo4j-admin-import equivalent.
 *
 * High-throughput CSV / JSON / JSONL loader for the QIHSE property graph.
 *
 * CSV conventions follow neo4j-admin import:
 *   Node files: :ID column + optional :LABEL column + property columns
 *   Edge files: :START_ID + :END_ID + optional :TYPE + optional :ID + property columns
 *
 * Build: linked into libqihse.so alongside qihse_graph_store.c
 */

#include "qihse_graph_ingest.h"
#include "qihse_arena.h"
#include "qihse_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

/* ---- minimal JSON parser (sufficient for ingest objects) ---- */

typedef enum { JT_NULL, JT_BOOL, JT_INT, JT_DBL, JT_STR, JT_ARR, JT_OBJ } jtype_t;

typedef struct jval {
    jtype_t type;
    int bval;
    int64_t ival;
    double dval;
    char* sval;       /* for JT_STR (owned) */
    struct jval** arr; size_t arr_len;  /* for JT_ARR */
    char** keys; struct jval** vals; size_t obj_len;  /* for JT_OBJ */
} jval_t;

typedef struct {
    const char* p;
    const char* end;
    char err[256];
} jparser_t;

static void jskip_ws(jparser_t* j) {
    while (j->p < j->end && isspace((unsigned char)*j->p)) j->p++;
}

static jval_t* jparse_value(jparser_t* j);

static jval_t* jnew(jtype_t t) {
    jval_t* v = calloc(1, sizeof(jval_t));
    v->type = t;
    return v;
}

static void jfree(jval_t* v) {
    if (!v) return;
    if (v->type == JT_STR) free(v->sval);
    if (v->type == JT_ARR) {
        for (size_t i = 0; i < v->arr_len; i++) jfree(v->arr[i]);
        free(v->arr);
    }
    if (v->type == JT_OBJ) {
        for (size_t i = 0; i < v->obj_len; i++) {
            free(v->keys[i]);
            jfree(v->vals[i]);
        }
        free(v->keys);
        free(v->vals);
    }
    free(v);
}

static jval_t* jparse_string(jparser_t* j) {
    if (*j->p != '"') { snprintf(j->err, sizeof(j->err), "expected '\"' at pos %ld", (long)(j->p - j->end)); return NULL; }
    j->p++;
    const char* start = j->p;
    /* find closing quote (no escape handling for simplicity — ingest data should be clean) */
    while (j->p < j->end && *j->p != '"') {
        if (*j->p == '\\' && j->p + 1 < j->end) j->p += 2;
        else j->p++;
    }
    if (j->p >= j->end) { snprintf(j->err, sizeof(j->err), "unterminated string"); return NULL; }
    size_t len = j->p - start;
    /* unescape in-place */
    char* s = malloc(len + 1);
    size_t si = 0;
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '\\' && i + 1 < len) {
            i++;
            switch (start[i]) {
                case 'n': s[si++] = '\n'; break;
                case 't': s[si++] = '\t'; break;
                case 'r': s[si++] = '\r'; break;
                case '"': s[si++] = '"'; break;
                case '\\': s[si++] = '\\'; break;
                case '/': s[si++] = '/'; break;
                default: s[si++] = start[i]; break;
            }
        } else {
            s[si++] = start[i];
        }
    }
    s[si] = '\0';
    j->p++; /* skip closing quote */
    jval_t* v = jnew(JT_STR);
    v->sval = s;
    return v;
}

static jval_t* jparse_number(jparser_t* j) {
    const char* start = j->p;
    bool is_dbl = false;
    if (*j->p == '-' || *j->p == '+') j->p++;
    while (j->p < j->end && (isdigit((unsigned char)*j->p) || *j->p == '.' || *j->p == 'e' || *j->p == 'E' || *j->p == '+' || *j->p == '-')) {
        if (*j->p == '.' || *j->p == 'e' || *j->p == 'E') is_dbl = true;
        j->p++;
    }
    size_t len = j->p - start;
    char buf[64];
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, start, len);
    buf[len] = '\0';
    jval_t* v = jnew(is_dbl ? JT_DBL : JT_INT);
    if (is_dbl) v->dval = strtod(buf, NULL);
    else v->ival = strtoll(buf, NULL, 10);
    return v;
}

static jval_t* jparse_array(jparser_t* j) {
    j->p++; /* skip '[' */
    jskip_ws(j);
    jval_t* v = jnew(JT_ARR);
    size_t cap = 4;
    v->arr = malloc(cap * sizeof(jval_t*));
    v->arr_len = 0;
    if (*j->p == ']') { j->p++; return v; }
    for (;;) {
        jskip_ws(j);
        jval_t* elem = jparse_value(j);
        if (!elem) { jfree(v); return NULL; }
        if (v->arr_len == cap) { cap *= 2; v->arr = realloc(v->arr, cap * sizeof(jval_t*)); }
        v->arr[v->arr_len++] = elem;
        jskip_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == ']') { j->p++; break; }
        snprintf(j->err, sizeof(j->err), "expected ',' or ']' in array");
        jfree(v);
        return NULL;
    }
    return v;
}

static jval_t* jparse_object(jparser_t* j) {
    j->p++; /* skip '{' */
    jskip_ws(j);
    jval_t* v = jnew(JT_OBJ);
    size_t cap = 4;
    v->keys = malloc(cap * sizeof(char*));
    v->vals = malloc(cap * sizeof(jval_t*));
    v->obj_len = 0;
    if (*j->p == '}') { j->p++; return v; }
    for (;;) {
        jskip_ws(j);
        jval_t* key = jparse_string(j);
        if (!key) { jfree(v); return NULL; }
        jskip_ws(j);
        if (*j->p != ':') { snprintf(j->err, sizeof(j->err), "expected ':' after key"); jfree(key); jfree(v); return NULL; }
        j->p++;
        jskip_ws(j);
        jval_t* val = jparse_value(j);
        if (!val) { jfree(key); jfree(v); return NULL; }
        if (v->obj_len == cap) { cap *= 2; v->keys = realloc(v->keys, cap * sizeof(char*)); v->vals = realloc(v->vals, cap * sizeof(jval_t*)); }
        v->keys[v->obj_len] = key->sval; key->sval = NULL; jfree(key);
        v->vals[v->obj_len] = val;
        v->obj_len++;
        jskip_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == '}') { j->p++; break; }
        snprintf(j->err, sizeof(j->err), "expected ',' or '}' in object");
        jfree(v);
        return NULL;
    }
    return v;
}

static jval_t* jparse_value(jparser_t* j) {
    jskip_ws(j);
    if (j->p >= j->end) { snprintf(j->err, sizeof(j->err), "unexpected EOF"); return NULL; }
    char c = *j->p;
    if (c == '"') return jparse_string(j);
    if (c == '{') return jparse_object(j);
    if (c == '[') return jparse_array(j);
    if (c == '-' || c == '+' || isdigit((unsigned char)c)) return jparse_number(j);
    if (strncmp(j->p, "true", 4) == 0) { j->p += 4; jval_t* v = jnew(JT_BOOL); v->bval = 1; return v; }
    if (strncmp(j->p, "false", 5) == 0) { j->p += 5; jval_t* v = jnew(JT_BOOL); v->bval = 0; return v; }
    if (strncmp(j->p, "null", 4) == 0) { j->p += 4; return jnew(JT_NULL); }
    snprintf(j->err, sizeof(j->err), "unexpected char '%c' at pos %ld", c, (long)(j->p - j->end));
    return NULL;
}

static jval_t* jparse_file(const char* filepath, bool jsonl, char* err, size_t err_len) {
    FILE* f = fopen(filepath, "rb");
    if (!f) { snprintf(err, err_len, "cannot open %s: %s", filepath, strerror(errno)); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = malloc(sz + 1);
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    if (jsonl) {
        /* parse each line as a separate JSON object, return as JT_ARR */
        jval_t* arr = jnew(JT_ARR);
        size_t cap = 64;
        arr->arr = malloc(cap * sizeof(jval_t*));
        arr->arr_len = 0;
        char* line = buf;
        char* eol;
        while ((eol = memchr(line, '\n', buf + sz - line))) {
            *eol = '\0';
            /* trim */
            char* s = line; while (isspace((unsigned char)*s)) s++;
            if (*s != '\0') {
                jparser_t j = { .p = s, .end = s + strlen(s), .err = "" };
                jval_t* v = jparse_value(&j);
                if (v) {
                    if (arr->arr_len == cap) { cap *= 2; arr->arr = realloc(arr->arr, cap * sizeof(jval_t*)); }
                    arr->arr[arr->arr_len++] = v;
                }
            }
            line = eol + 1;
        }
        /* last line (no trailing newline) */
        char* s = line; while (isspace((unsigned char)*s)) s++;
        if (*s != '\0') {
            jparser_t j = { .p = s, .end = buf + sz, .err = "" };
            jval_t* v = jparse_value(&j);
            if (v) {
                if (arr->arr_len == cap) { cap *= 2; arr->arr = realloc(arr->arr, cap * sizeof(jval_t*)); }
                arr->arr[arr->arr_len++] = v;
            }
        }
        free(buf);
        return arr;
    }

    jparser_t j = { .p = buf, .end = buf + sz, .err = "" };
    jval_t* v = jparse_value(&j);
    free(buf);
    if (!v) snprintf(err, err_len, "JSON parse error: %s", j.err);
    return v;
}

static jval_t* jobj_get(const jval_t* obj, const char* key) {
    if (!obj || obj->type != JT_OBJ) return NULL;
    for (size_t i = 0; i < obj->obj_len; i++)
        if (strcmp(obj->keys[i], key) == 0) return obj->vals[i];
    return NULL;
}

/* ---- CSV parser ---- */

typedef struct {
    char** fields;
    size_t count;
} csv_row_t;

typedef struct {
    char** headers;
    size_t num_cols;
    char delimiter;
} csv_ctx_t;

/* Parse one CSV line, handling quoted fields. Returns malloc'd fields array.
 * Caller must free each field and the array. */
static csv_row_t csv_parse_line(const char* line, char delim) {
    csv_row_t row = { .fields = NULL, .count = 0 };
    size_t cap = 8;
    row.fields = malloc(cap * sizeof(char*));
    size_t fcap = 64;
    char* field = malloc(fcap);
    size_t fi = 0;
    bool in_quotes = false;
    const char* p = line;

    while (*p) {
        if (in_quotes) {
            if (*p == '"') {
                if (p[1] == '"') { field[fi++] = '"'; p += 2; }
                else { in_quotes = false; p++; }
            } else {
                field[fi++] = *p++;
            }
        } else {
            if (*p == '"') { in_quotes = true; p++; }
            else if (*p == delim) {
                field[fi] = '\0';
                if (row.count == cap) { cap *= 2; row.fields = realloc(row.fields, cap * sizeof(char*)); }
                row.fields[row.count++] = strdup(field);
                fi = 0;
                p++;
            } else if (*p == '\r') {
                p++; /* skip CR */
            } else if (*p == '\n') {
                break;
            } else {
                field[fi++] = *p++;
            }
        }
        if (fi >= fcap - 1) { fcap *= 2; field = realloc(field, fcap); }
    }
    field[fi] = '\0';
    if (row.count == cap) { cap *= 2; row.fields = realloc(row.fields, cap * sizeof(char*)); }
    row.fields[row.count++] = strdup(field);
    free(field);
    return row;
}

static void csv_row_free(csv_row_t* r) {
    for (size_t i = 0; i < r->count; i++) free(r->fields[i]);
    free(r->fields);
    r->fields = NULL;
    r->count = 0;
}

static int find_col(const csv_row_t* headers, const char* name) {
    for (size_t i = 0; i < headers->count; i++) {
        /* strip leading ':' for comparison (neo4j uses :ID, :LABEL, etc.) */
        const char* h = headers->fields[i];
        if (*h == ':') h++;
        if (strcasecmp(h, name) == 0) return (int)i;
        /* also match with the colon prefix */
        if (strcasecmp(headers->fields[i], name) == 0) return (int)i;
    }
    return -1;
}

/* ---- property conversion ---- */

static graph_prop_t prop_from_jval(const jval_t* v) {
    graph_prop_t p;
    memset(&p, 0, sizeof(p));
    if (!v || v->type == JT_NULL) { p.type = GRAPH_PROP_STRING; p.val.s = strdup(""); return p; }
    switch (v->type) {
        case JT_BOOL: p.type = GRAPH_PROP_BOOL; p.val.b = v->bval; break;
        case JT_INT:  p.type = GRAPH_PROP_INT64; p.val.i = v->ival; break;
        case JT_DBL:  p.type = GRAPH_PROP_DOUBLE; p.val.d = v->dval; break;
        case JT_STR:  p.type = GRAPH_PROP_STRING; p.val.s = strdup(v->sval); break;
        default:      p.type = GRAPH_PROP_STRING; p.val.s = strdup(""); break;
    }
    return p;
}

static graph_prop_t prop_from_string(const char* s) {
    graph_prop_t p;
    memset(&p, 0, sizeof(p));
    if (!s || *s == '\0') { p.type = GRAPH_PROP_STRING; p.val.s = strdup(""); return p; }
    /* try int */
    char* endp;
    int64_t iv = strtoll(s, &endp, 10);
    if (*endp == '\0') { p.type = GRAPH_PROP_INT64; p.val.i = iv; return p; }
    /* try double */
    double dv = strtod(s, &endp);
    if (*endp == '\0') { p.type = GRAPH_PROP_DOUBLE; p.val.d = dv; return p; }
    /* string */
    p.type = GRAPH_PROP_STRING;
    p.val.s = strdup(s);
    return p;
}

/* ---- ID remapping (external string ID → internal uint64_t) ---- */

typedef struct {
    char* key;
    uint64_t id;
} id_map_entry_t;

typedef struct {
    id_map_entry_t* entries;
    size_t cap;
    size_t count;
} id_map_t;

static id_map_t* get_id_map(qihse_graph_t* g) {
    (void)g;
    static id_map_t global_map = { .entries = NULL, .cap = 0, .count = 0 };
    return &global_map;
}

// Simple FNV-1a hash
static uint64_t hash_str(const char* str) {
    uint64_t hash = 14695981039346656037ULL;
    while (*str) {
        hash ^= (unsigned char)*str++;
        hash *= 1099511628211ULL;
    }
    return hash;
}

void qihse_graph_ingest_register_id(qihse_graph_t* g, const char* external_id, uint64_t internal_id) {
    id_map_t* m = get_id_map(g);
    if (m->count * 2 >= m->cap) {
        size_t new_cap = m->cap ? m->cap * 2 : 1024;
        id_map_entry_t* new_entries = calloc(new_cap, sizeof(id_map_entry_t));
        for (size_t i = 0; i < m->cap; i++) {
            if (m->entries[i].key) {
                size_t idx = hash_str(m->entries[i].key) & (new_cap - 1);
                while (new_entries[idx].key) idx = (idx + 1) & (new_cap - 1);
                new_entries[idx] = m->entries[i];
            }
        }
        free(m->entries);
        m->entries = new_entries;
        m->cap = new_cap;
    }
    size_t idx = hash_str(external_id) & (m->cap - 1);
    while (m->entries[idx].key) {
        if (strcmp(m->entries[idx].key, external_id) == 0) {
            m->entries[idx].id = internal_id;
            return;
        }
        idx = (idx + 1) & (m->cap - 1);
    }
    m->entries[idx].key = strdup(external_id);
    m->entries[idx].id = internal_id;
    m->count++;
}

uint64_t qihse_graph_ingest_lookup_id(qihse_graph_t* g, const char* external_id) {
    id_map_t* m = get_id_map(g);
    if (m->cap > 0) {
        size_t idx = hash_str(external_id) & (m->cap - 1);
        while (m->entries[idx].key) {
            if (strcmp(m->entries[idx].key, external_id) == 0) return m->entries[idx].id;
            idx = (idx + 1) & (m->cap - 1);
        }
    }
    /* try numeric */
    char* endp;
    uint64_t num = strtoull(external_id, &endp, 10);
    if (*endp == '\0') return num;
    return 0;
}

void qihse_graph_ingest_clear_ids(qihse_graph_t* g) {
    id_map_t* m = get_id_map(g);
    for (size_t i = 0; i < m->cap; i++) {
        if (m->entries[i].key) free(m->entries[i].key);
    }
    free(m->entries);
    m->entries = NULL;
    m->count = 0;
    m->cap = 0;
}

/* ---- CSV vertex ingest ---- */

int64_t qihse_graph_ingest_vertices_csv(qihse_graph_t* g,
                                        const char* filepath,
                                        bool has_header,
                                        const char* id_column,
                                        const char* label_column,
                                        char delimiter,
                                        int64_t* out_errors)
{
    if (!g || !filepath) return -1;
    FILE* f = fopen(filepath, "rb");
    if (!f) return -1;

    char line[65536];
    int64_t count = 0;
    int64_t errors = 0;
    csv_row_t headers = { .fields = NULL, .count = 0 };
    int id_col_idx = -1;
    int label_col_idx = -1;

    if (has_header) {
        if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
        /* strip newline */
        line[strcspn(line, "\r\n")] = '\0';
        headers = csv_parse_line(line, delimiter);
        if (id_column) {
            id_col_idx = find_col(&headers, id_column);
            if (id_col_idx < 0) id_col_idx = find_col(&headers, "ID");
        }
        if (label_column) {
            label_col_idx = find_col(&headers, label_column);
            if (label_col_idx < 0) label_col_idx = find_col(&headers, "LABEL");
        }
    }

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        csv_row_t row = csv_parse_line(line, delimiter);
        if (row.count == 0) { errors++; csv_row_free(&row); continue; }

        /* determine labels */
        char* labels_buf[16];
        size_t num_labels = 0;
        if (label_col_idx >= 0 && (size_t)label_col_idx < row.count) {
            char* lbls = row.fields[label_col_idx];
            /* split by ';' or '|' (neo4j uses ; for multi-label in admin import) */
            char* tok = strtok(lbls, ";|");
            while (tok && num_labels < 16) {
                while (*tok == ' ') tok++;
                if (*tok) labels_buf[num_labels++] = tok;
                tok = strtok(NULL, ";|");
            }
        }

        /* determine ID */
        uint64_t vid = 0;
        bool has_explicit_id = false;
        if (id_col_idx >= 0 && (size_t)id_col_idx < row.count) {
            char* idstr = row.fields[id_col_idx];
            if (*idstr) {
                char* endp;
                uint64_t parsed = strtoull(idstr, &endp, 10);
                if (*endp == '\0') { vid = parsed; has_explicit_id = true; }
                else {
                    /* string ID — register mapping after creation */
                }
            }
        }

        /* collect properties (all columns except id, label) */
        char* prop_keys[256];
        graph_prop_t prop_vals[256];
        size_t num_props = 0;

        for (size_t c = 0; c < row.count && num_props < 256; c++) {
            if ((int)c == id_col_idx || (int)c == label_col_idx) continue;
            const char* col_name = (has_header && c < headers.count) ? headers.fields[c] : NULL;
            if (!col_name) {
                char buf[16];
                snprintf(buf, sizeof(buf), "col_%zu", c);
                prop_keys[num_props] = strdup(buf);
            } else {
                /* strip leading ':' from property names, and strip :TYPE suffix */
                const char* pn = col_name;
                if (*pn == ':') pn++;
                /* find last ':' and truncate the type suffix (e.g. name:STRING → name) */
                char* colon = strrchr(pn, ':');
                if (colon) {
                    /* only strip if the suffix looks like a type (all caps) */
                    bool is_type = true;
                    for (const char* t = colon + 1; *t; t++)
                        if (!isupper((unsigned char)*t) && *t != '_') { is_type = false; break; }
                    if (is_type && colon > pn)
                        prop_keys[num_props] = strndup(pn, colon - pn);
                    else
                        prop_keys[num_props] = strdup(pn);
                } else {
                    prop_keys[num_props] = strdup(pn);
                }
            }
            prop_vals[num_props] = prop_from_string(row.fields[c]);
            num_props++;
        }

        /* create vertex */
        uint64_t new_vid;
        new_vid = qihse_graph_vertex_create(g,
            (const char* const*)labels_buf, num_labels,
            (const char* const*)prop_keys, prop_vals, num_props);

        /* register ID mapping if there's an ID column (both numeric and string) */
        if (id_col_idx >= 0 && (size_t)id_col_idx < row.count && row.fields[id_col_idx][0]) {
            qihse_graph_ingest_register_id(g, row.fields[id_col_idx], new_vid);
        }

        if (new_vid == 0) errors++;
        else count++;

        /* cleanup */
        for (size_t i = 0; i < num_props; i++) {
            free(prop_keys[i]);
            graph_prop_free(&prop_vals[i]);
        }
        csv_row_free(&row);
    }

    if (has_header) csv_row_free(&headers);
    fclose(f);
    if (out_errors) *out_errors = errors;
    return count;
}

/* ---- CSV edge ingest ---- */

int64_t qihse_graph_ingest_edges_csv(qihse_graph_t* g,
                                     const char* filepath,
                                     bool has_header,
                                     const char* start_column,
                                     const char* end_column,
                                     const char* type_column,
                                     const char* id_column,
                                     char delimiter,
                                     int64_t* out_errors)
{
    if (!g || !filepath) return -1;
    FILE* f = fopen(filepath, "rb");
    if (!f) return -1;

    char line[65536];
    int64_t count = 0;
    int64_t errors = 0;
    csv_row_t headers = { .fields = NULL, .count = 0 };
    int start_idx = -1, end_idx = -1, type_idx = -1, id_idx = -1;

    if (has_header) {
        if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
        line[strcspn(line, "\r\n")] = '\0';
        headers = csv_parse_line(line, delimiter);
        start_idx = find_col(&headers, start_column ? start_column : "START_ID");
        end_idx = find_col(&headers, end_column ? end_column : "END_ID");
        if (type_column) type_idx = find_col(&headers, type_column);
        if (type_idx < 0) type_idx = find_col(&headers, "TYPE");
        if (id_column) id_idx = find_col(&headers, id_column);
    }

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        csv_row_t row = csv_parse_line(line, delimiter);
        if (row.count == 0) { errors++; csv_row_free(&row); continue; }

        if (start_idx < 0 || end_idx < 0 ||
            (size_t)start_idx >= row.count || (size_t)end_idx >= row.count) {
            errors++;
            csv_row_free(&row);
            continue;
        }

        /* resolve start/end IDs */
        const char* start_str = row.fields[start_idx];
        const char* end_str = row.fields[end_idx];
        uint64_t start_vid = qihse_graph_ingest_lookup_id(g, start_str);
        uint64_t end_vid = qihse_graph_ingest_lookup_id(g, end_str);

        if (start_vid == 0 || end_vid == 0) {
            /* try direct numeric */
            char* e;
            if (start_vid == 0) { start_vid = strtoull(start_str, &e, 10); if (*e != '\0') start_vid = 0; }
            if (end_vid == 0) { end_vid = strtoull(end_str, &e, 10); if (*e != '\0') end_vid = 0; }
        }

        if (start_vid == 0 || end_vid == 0) {
            errors++;
            csv_row_free(&row);
            continue;
        }

        /* edge type */
        const char* etype = "RELATED";
        if (type_idx >= 0 && (size_t)type_idx < row.count && row.fields[type_idx][0])
            etype = row.fields[type_idx];

        /* collect properties */
        char* prop_keys[256];
        graph_prop_t prop_vals[256];
        size_t num_props = 0;
        for (size_t c = 0; c < row.count && num_props < 256; c++) {
            if ((int)c == start_idx || (int)c == end_idx || (int)c == type_idx || (int)c == id_idx)
                continue;
            const char* col_name = (has_header && c < headers.count) ? headers.fields[c] : NULL;
            if (!col_name) {
                char buf[16];
                snprintf(buf, sizeof(buf), "col_%zu", c);
                prop_keys[num_props] = strdup(buf);
            } else {
                const char* pn = col_name;
                if (*pn == ':') pn++;
                char* colon = strrchr(pn, ':');
                if (colon) {
                    bool is_type = true;
                    for (const char* t = colon + 1; *t; t++)
                        if (!isupper((unsigned char)*t) && *t != '_') { is_type = false; break; }
                    if (is_type && colon > pn)
                        prop_keys[num_props] = strndup(pn, colon - pn);
                    else
                        prop_keys[num_props] = strdup(pn);
                } else {
                    prop_keys[num_props] = strdup(pn);
                }
            }
            prop_vals[num_props] = prop_from_string(row.fields[c]);
            num_props++;
        }

        uint64_t eid = qihse_graph_edge_create(g, etype, start_vid, end_vid,
            (const char* const*)prop_keys, prop_vals, num_props);

        if (eid == 0) errors++;
        else count++;

        for (size_t i = 0; i < num_props; i++) {
            free(prop_keys[i]);
            graph_prop_free(&prop_vals[i]);
        }
        csv_row_free(&row);
    }

    if (has_header) csv_row_free(&headers);
    fclose(f);
    if (out_errors) *out_errors = errors;
    return count;
}

/* ---- JSON vertex ingest ---- */

int64_t qihse_graph_ingest_vertices_json(qihse_graph_t* g,
                                         const char* filepath,
                                         bool jsonl,
                                         int64_t* out_errors)
{
    if (!g || !filepath) return -1;
    char err[256] = "";
    jval_t* root = jparse_file(filepath, jsonl, err, sizeof(err));
    if (!root) { if (out_errors) *out_errors = 1; return -1; }

    /* root should be an array */
    jval_t* arr = root;
    if (root->type == JT_OBJ) {
        /* single object — wrap in array */
        arr = jnew(JT_ARR);
        arr->arr = malloc(sizeof(jval_t*));
        arr->arr[0] = root;
        arr->arr_len = 1;
    }
    if (arr->type != JT_ARR) { jfree(arr); if (out_errors) *out_errors = 1; return -1; }

    int64_t count = 0, errors = 0;
    for (size_t i = 0; i < arr->arr_len; i++) {
        jval_t* obj = arr->arr[i];
        if (obj->type != JT_OBJ) { errors++; continue; }

        /* labels */
        char* labels[16];
        size_t num_labels = 0;
        jval_t* lbls = jobj_get(obj, "labels");
        if (lbls && lbls->type == JT_ARR) {
            for (size_t j = 0; j < lbls->arr_len && num_labels < 16; j++) {
                if (lbls->arr[j]->type == JT_STR)
                    labels[num_labels++] = lbls->arr[j]->sval;
            }
        }
        /* also accept single "label" string */
        if (num_labels == 0) {
            jval_t* lbl = jobj_get(obj, "label");
            if (lbl && lbl->type == JT_STR) { labels[0] = lbl->sval; num_labels = 1; }
        }

        /* properties */
        jval_t* props = jobj_get(obj, "properties");
        char* prop_keys[256];
        graph_prop_t prop_vals[256];
        size_t num_props = 0;
        if (props && props->type == JT_OBJ) {
            for (size_t j = 0; j < props->obj_len && num_props < 256; j++) {
                prop_keys[num_props] = strdup(props->keys[j]);
                prop_vals[num_props] = prop_from_jval(props->vals[j]);
                num_props++;
            }
        }

        uint64_t vid = qihse_graph_vertex_create(g,
            (const char* const*)labels, num_labels,
            (const char* const*)prop_keys, prop_vals, num_props);

        /* register external ID if present */
        jval_t* idv = jobj_get(obj, "id");
        if (idv) {
            if (idv->type == JT_INT) {
                char idbuf[32]; snprintf(idbuf, sizeof(idbuf), "%lld", (long long)idv->ival);
                qihse_graph_ingest_register_id(g, idbuf, vid);
            } else if (idv->type == JT_STR) {
                qihse_graph_ingest_register_id(g, idv->sval, vid);
            }
        }

        if (vid == 0) errors++;
        else count++;

        for (size_t j = 0; j < num_props; j++) {
            free(prop_keys[j]);
            graph_prop_free(&prop_vals[j]);
        }
    }

    if (arr != root) jfree(arr);
    jfree(root);
    if (out_errors) *out_errors = errors;
    return count;
}

/* ---- JSON edge ingest ---- */

int64_t qihse_graph_ingest_edges_json(qihse_graph_t* g,
                                      const char* filepath,
                                      bool jsonl,
                                      int64_t* out_errors)
{
    if (!g || !filepath) return -1;
    char err[256] = "";
    jval_t* root = jparse_file(filepath, jsonl, err, sizeof(err));
    if (!root) { if (out_errors) *out_errors = 1; return -1; }

    jval_t* arr = root;
    if (root->type == JT_OBJ) {
        arr = jnew(JT_ARR);
        arr->arr = malloc(sizeof(jval_t*));
        arr->arr[0] = root;
        arr->arr_len = 1;
    }
    if (arr->type != JT_ARR) { jfree(arr); if (out_errors) *out_errors = 1; return -1; }

    int64_t count = 0, errors = 0;
    for (size_t i = 0; i < arr->arr_len; i++) {
        jval_t* obj = arr->arr[i];
        if (obj->type != JT_OBJ) { errors++; continue; }

        /* type */
        const char* etype = "RELATED";
        jval_t* tv = jobj_get(obj, "type");
        if (!tv) tv = jobj_get(obj, "rel_type");
        if (tv && tv->type == JT_STR) etype = tv->sval;

        /* start / end */
        jval_t* sv = jobj_get(obj, "start");
        if (!sv) sv = jobj_get(obj, "start_id");
        if (!sv) sv = jobj_get(obj, "source");
        jval_t* ev = jobj_get(obj, "end");
        if (!ev) ev = jobj_get(obj, "end_id");
        if (!ev) ev = jobj_get(obj, "target");

        uint64_t start_vid = 0, end_vid = 0;
        if (sv) {
            if (sv->type == JT_INT) start_vid = (uint64_t)sv->ival;
            else if (sv->type == JT_STR) start_vid = qihse_graph_ingest_lookup_id(g, sv->sval);
        }
        if (ev) {
            if (ev->type == JT_INT) end_vid = (uint64_t)ev->ival;
            else if (ev->type == JT_STR) end_vid = qihse_graph_ingest_lookup_id(g, ev->sval);
        }

        if (start_vid == 0 || end_vid == 0) { errors++; continue; }

        /* properties */
        jval_t* props = jobj_get(obj, "properties");
        char* prop_keys[256];
        graph_prop_t prop_vals[256];
        size_t num_props = 0;
        if (props && props->type == JT_OBJ) {
            for (size_t j = 0; j < props->obj_len && num_props < 256; j++) {
                prop_keys[num_props] = strdup(props->keys[j]);
                prop_vals[num_props] = prop_from_jval(props->vals[j]);
                num_props++;
            }
        }

        uint64_t eid = qihse_graph_edge_create(g, etype, start_vid, end_vid,
            (const char* const*)prop_keys, prop_vals, num_props);

        if (eid == 0) errors++;
        else count++;

        for (size_t j = 0; j < num_props; j++) {
            free(prop_keys[j]);
            graph_prop_free(&prop_vals[j]);
        }
    }

    if (arr != root) jfree(arr);
    jfree(root);
    if (out_errors) *out_errors = errors;
    return count;
}

/* ---- directory ingest ---- */

static bool ends_with(const char* s, const char* suffix) {
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

static bool contains_substring(const char* s, const char* sub) {
    return strstr(s, sub) != NULL;
}

int64_t qihse_graph_ingest_directory(qihse_graph_t* g,
                                     const char* dirpath,
                                     int64_t* out_errors)
{
    if (!g || !dirpath) return -1;
    DIR* d = opendir(dirpath);
    if (!d) return -1;

    int64_t total = 0;
    int64_t errors = 0;
    struct dirent* ent;

    /* first pass: nodes */
    rewinddir(d);
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        const char* name = ent->d_name;
        bool is_node = contains_substring(name, "node") || contains_substring(name, "vertex");
        bool is_edge = contains_substring(name, "edge") || contains_substring(name, "rel") ||
                       contains_substring(name, "relationship");
        if (!is_node || is_edge) continue;
        if (!ends_with(name, ".csv") && !ends_with(name, ".json") && !ends_with(name, ".jsonl"))
            continue;

        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dirpath, name);
        int64_t e = 0;
        int64_t n;
        if (ends_with(name, ".csv"))
            n = qihse_graph_ingest_vertices_csv(g, path, true, "ID", "LABEL", ',', &e);
        else if (ends_with(name, ".jsonl"))
            n = qihse_graph_ingest_vertices_json(g, path, true, &e);
        else
            n = qihse_graph_ingest_vertices_json(g, path, false, &e);
        if (n < 0) errors += e + 1;
        else { total += n; errors += e; }
    }

    /* second pass: edges (after all nodes are loaded for ID mapping) */
    rewinddir(d);
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        const char* name = ent->d_name;
        bool is_edge = contains_substring(name, "edge") || contains_substring(name, "rel") ||
                       contains_substring(name, "relationship");
        if (!is_edge) continue;
        if (!ends_with(name, ".csv") && !ends_with(name, ".json") && !ends_with(name, ".jsonl"))
            continue;

        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dirpath, name);
        int64_t e = 0;
        int64_t n;
        if (ends_with(name, ".csv"))
            n = qihse_graph_ingest_edges_csv(g, path, true, "START_ID", "END_ID", "TYPE", NULL, ',', &e);
        else if (ends_with(name, ".jsonl"))
            n = qihse_graph_ingest_edges_json(g, path, true, &e);
        else
            n = qihse_graph_ingest_edges_json(g, path, false, &e);
        if (n < 0) errors += e + 1;
        else { total += n; errors += e; }
    }

    closedir(d);
    if (out_errors) *out_errors = errors;
    return total;
}
