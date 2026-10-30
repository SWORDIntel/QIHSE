#include "qihse_sql_row_index.h"
#include "qihse_auth.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* An ordered, duplicate-preserving key -> row-ID posting array. Sorting once
 * after the authenticated snapshot walk gives binary-search lookup, rather
 * than a scan disguised as an index. No borrowed row values are retained. */
typedef struct { char* key; size_t row; } posting_t;
struct qihse_sql_row_index {
    const qihse_table_t* table;
    const qihse_table_txn_t* txn;
    uint64_t generation;
    uint32_t principal, tenant;
    uint16_t clearance, sci;
    bool gin, json;
    int columns[16];
    char* json_fields[16];
    size_t ncolumns;
    posting_t* postings;
    size_t length, capacity;
    bool failed;
};

static bool source_generation(const qihse_table_t* table,
    const qihse_table_txn_t* txn, const qihse_user_t* user, uint64_t* generation) {
    return txn ? qihse_table_txn_generation_user(txn, user, generation) :
                 qihse_table_generation_user(table, user, generation);
}

static bool append(posting_t** p, size_t* n, size_t* cap,
                   const char* key, size_t row) {
    if (*n == *cap) {
        if (*cap > SIZE_MAX / 2 / sizeof(**p)) return false;
        size_t next = *cap ? *cap * 2 : 16;
        posting_t* tmp = realloc(*p, next * sizeof(*tmp));
        if (!tmp) return false;
        *p = tmp; *cap = next;
    }
    char* copy = strdup(key);
    if (!copy) return false;
    (*p)[*n].key = copy;
    (*p)[(*n)++].row = row;
    return true;
}

static int posting_cmp(const void* a, const void* b) {
    const posting_t* x = a, *y = b;
    int c = strcmp(x->key, y->key);
    return c ? c : (x->row > y->row) - (x->row < y->row);
}

/* Length-prefixed typed tuple component. NULL is not indexed. */
static bool encode(char** key, size_t* length, const qihse_col_value_t* v) {
    if (!v || v->is_null) return false;
    char num[96];
    char decimal[4097];
    const char* text = NULL;
    switch (v->type) {
    case QIHSE_TS_INT32: snprintf(num, sizeof(num), "%d", v->v.i32); text = num; break;
    case QIHSE_TS_INT64: snprintf(num, sizeof(num), "%lld", (long long)v->v.i64); text = num; break;
    case QIHSE_TS_TIMESTAMPTZ: snprintf(num, sizeof(num), "%lld", (long long)v->v.timestamptz_us); text = num; break;
    case QIHSE_TS_BOOLEAN: text = v->v.boolean ? "1" : "0"; break;
    case QIHSE_TS_FLOAT:
        if (!isfinite(v->v.f32)) return false;
        snprintf(num, sizeof(num), "%a", (double)(v->v.f32 == 0 ? 0.0f : v->v.f32));
        text = num; break;
    case QIHSE_TS_NUMERIC: {
        if (!qihse_ts_numeric_valid(v->v.str, 0, 0)) return false;
        const char* p = v->v.str;
        bool negative = *p == '-';
        if (*p == '-' || *p == '+') ++p;
        while (*p == '0') ++p;
        const char* integer = p;
        while (isdigit((unsigned char)*p)) ++p;
        size_t integer_len = (size_t)(p - integer);
        const char* fractional = *p == '.' ? p + 1 : p;
        size_t fractional_len = strlen(fractional);
        while (fractional_len && fractional[fractional_len - 1] == '0') --fractional_len;
        size_t n = 0;
        if (negative && (integer_len || fractional_len)) decimal[n++] = '-';
        if (integer_len) { memcpy(decimal + n, integer, integer_len); n += integer_len; }
        else decimal[n++] = '0';
        if (fractional_len) {
            decimal[n++] = '.';
            memcpy(decimal + n, fractional, fractional_len); n += fractional_len;
        }
        decimal[n] = '\0';
        text = decimal; break;
    }
    case QIHSE_TS_STRING: case QIHSE_TS_UUID: case QIHSE_TS_JSONB:
    case QIHSE_TS_TSVECTOR: text = v->v.str; break;
    default: return false;
    }
    if (!text) return false;
    size_t n = strlen(text);
    char prefix[48];
    int written = snprintf(prefix, sizeof(prefix), "%u:%zu:", (unsigned)v->type, n);
    if (written < 0 || (size_t)written >= sizeof(prefix) ||
        n > SIZE_MAX - *length - (size_t)written - 1) return false;
    char* p = realloc(*key, *length + (size_t)written + n + 1);
    if (!p) return false;
    *key = p;
    memcpy(p + *length, prefix, (size_t)written);
    memcpy(p + *length + (size_t)written, text, n + 1);
    *length += (size_t)written + n;
    return true;
}

/* Parse one JSON string, decoding escapes used in ordinary JSON object keys.
 * Non-ASCII Unicode escape sequences are refused rather than misindexed. */
static char* json_string(const char** cursor) {
    const char* s = *cursor;
    if (*s++ != '"') return NULL;
    size_t cap = strlen(s) + 1;
    char* out = malloc(cap);
    if (!out) return NULL;
    size_t n = 0;
    while (*s && *s != '"') {
        unsigned char c = (unsigned char)*s++;
        if (c < 0x20) goto fail;
        if (c == '\\') {
            c = (unsigned char)*s++;
            if (c == 'u') {
                unsigned value = 0;
                for (int i = 0; i < 4; ++i) {
                    unsigned char d = (unsigned char)*s++;
                    if (!isxdigit(d)) goto fail;
                    value = value * 16 + (unsigned)(isdigit(d) ? d - '0' : tolower(d) - 'a' + 10);
                }
                if (!value || value >= 128) goto fail;
                c = (unsigned char)value;
            } else if (c == 'n') c = '\n';
            else if (c == 't') c = '\t';
            else if (c == 'r') c = '\r';
            else if (c == 'b') c = '\b';
            else if (c == 'f') c = '\f';
            else if (c != '"' && c != '\\' && c != '/') goto fail;
        }
        if (!c) goto fail;
        out[n++] = (char)c;
    }
    if (*s++ != '"') goto fail;
    out[n] = 0; *cursor = s; return out;
fail:
    free(out); return NULL;
}

static void space(const char** p) { while (isspace((unsigned char)**p)) ++*p; }

/* Top-level scalar visitor. Nested/unsupported JSON fails the entire build,
 * never producing partial postings that could omit a candidate row. */
typedef bool (*json_visit)(const char*, const char*, bool, void*);
static bool json_each(const char* json, json_visit visit, void* ctx) {
    const char* s = json;
    space(&s);
    if (*s++ != '{') return false;
    space(&s);
    if (*s == '}') { ++s; space(&s); return !*s; }
    for (;;) {
        char* key = json_string(&s);
        if (!key) return false;
        space(&s);
        if (*s++ != ':') { free(key); return false; }
        space(&s);
        char* val = NULL;
        bool json_null = false;
        if (*s == '"') val = json_string(&s);
        else if (*s == '{' || *s == '[') {
            /* A nested containment query needs a recursive index. Refuse the
             * build instead of publishing incomplete postings. */
            free(key); return false;
        } else {
            const char* start = s;
            while (*s && *s != ',' && *s != '}' && !isspace((unsigned char)*s)) ++s;
            size_t len = (size_t)(s - start);
            if (!len) { free(key); return false; }
            val = strndup(start, len);
            json_null = val && !strcmp(val, "null");
        }
        bool ok = val && visit(key, val, json_null, ctx);
        free(key); free(val);
        if (!ok) return false;
        space(&s);
        if (*s == '}') { ++s; space(&s); return !*s; }
        if (*s++ != ',') return false;
        space(&s);
    }
}

static bool expression(const qihse_table_t* table, const char* expr,
                       int* column, char** field) {
    if (!expr) return false;
    while (isspace((unsigned char)*expr) || *expr == '(') ++expr;
    const char* start = expr;
    while (isalnum((unsigned char)*expr) || *expr == '_') ++expr;
    if (start == expr || (size_t)(expr - start) > 127) return false;
    char name[128]; memcpy(name, start, (size_t)(expr - start));
    name[expr - start] = 0;
    int col = qihse_table_find_col(table, name);
    if (col < 0) return false;
    while (isspace((unsigned char)*expr)) ++expr;
    if (expr[0] == '-' && expr[1] == '>' && expr[2] == '>') {
        expr += 3; while (isspace((unsigned char)*expr)) ++expr;
        if (*expr++ != '\'') return false;
        start = expr;
        while (*expr && *expr != '\'') ++expr;
        if (*expr != '\'' || expr == start || (size_t)(expr - start) > 127 ||
            qihse_table_col_def(table, (size_t)col)->type != QIHSE_TS_JSONB) return false;
        *field = strndup(start, (size_t)(expr - start));
        if (!*field) return false;
        ++expr;
    }
    while (isspace((unsigned char)*expr) || *expr == ')') ++expr;
    if (*expr) { free(*field); *field = NULL; return false; }
    *column = col;
    return true;
}

struct extract { const char* name; char* value; };
static bool extract_field(const char* key, const char* value,
                          bool json_null, void* ctx) {
    struct extract* e = ctx;
    if (!strcmp(key, e->name)) {
        free(e->value);
        e->value = NULL;
        if (!json_null) {
            e->value = strdup(value);
            if (!e->value) return false;
        }
    }
    return true;
}

static bool gin_json_visit(const char* field, const char* text,
                           bool json_null, void* ctx);

static bool add_row_value(qihse_sql_row_index_t* index,
                          const qihse_col_value_t* values, size_t n, size_t row) {
    if (index->gin) {
        int col = index->columns[0];
        if (col < 0 || (size_t)col >= n) return false;
        const qihse_col_value_t* v = &values[col];
        if (v->is_null) return true;
        if (!v->v.str) return false;
        if (index->json) {
            /* GIN JSON keys are typed length-prefixed tuples. */
            struct gin_ctx { qihse_sql_row_index_t* index; size_t row; } g = {index, row};
            return json_each(v->v.str, gin_json_visit, &g);
        }
        if (!qihse_ts_tsvector_valid(v->v.str)) return false;
        const char* p = v->v.str;
        while (*p) {
            while (isspace((unsigned char)*p)) ++p;
            if (!*p) break;
            if (*p++ != '\'') return false;
            char word[257]; size_t len = 0;
            while (*p && *p != '\'') {
                if (*p == '\\') ++p;
                if (!*p || len >= sizeof(word)-1) return false;
                word[len++] = *p++;
            }
            if (*p != '\'') return false;
            word[len] = 0;
            if (!append(&index->postings, &index->length, &index->capacity, word, row)) return false;
            ++p;
            while (*p && !isspace((unsigned char)*p)) ++p; /* positions */
        }
        return true;
    }
    char* key = NULL; size_t size = 0;
    for (size_t i = 0; i < index->ncolumns; ++i) {
        int col = index->columns[i];
        if (col < 0 || (size_t)col >= n) { free(key); return false; }
        qihse_col_value_t value = values[col];
        struct extract e = {index->json_fields[i], NULL};
        if (e.name && !value.is_null) {
            if (!value.v.str || !json_each(value.v.str, extract_field, &e)) {
                free(e.value); free(key); return false;
            }
            value.type = QIHSE_TS_STRING;
            value.is_null = !e.value;
            value.v.str = e.value;
        }
        bool ok = !value.is_null && encode(&key, &size, &value);
        free(e.value);
        if (!ok) { free(key); return value.is_null; }
    }
    bool ok = append(&index->postings, &index->length, &index->capacity, key, row);
    free(key);
    return ok;
}

static bool gin_json_visit(const char* field, const char* text,
                           bool json_null, void* ctx) {
    (void)json_null;
    struct gin_ctx { qihse_sql_row_index_t* index; size_t row; } *g = ctx;
    qihse_col_value_t key = {.type=QIHSE_TS_STRING, .v.str=(char*)field};
    qihse_col_value_t value = {.type=QIHSE_TS_STRING, .v.str=(char*)text};
    char* tuple = NULL; size_t length = 0;
    bool ok = encode(&tuple, &length, &key) && encode(&tuple, &length, &value) &&
        append(&g->index->postings, &g->index->length, &g->index->capacity, tuple, g->row);
    free(tuple); return ok;
}

static bool add_row(size_t row, const qihse_col_value_t* values,
                    size_t n, void* context) {
    qihse_sql_row_index_t* index = context;
    if (!add_row_value(index, values, n, row)) {
        index->failed = true;
        return false;
    }
    return true;
}

void qihse_sql_row_index_destroy(qihse_sql_row_index_t* index) {
    if (!index) return;
    for (size_t i = 0; i < index->length; ++i) free(index->postings[i].key);
    for (size_t i = 0; i < index->ncolumns; ++i) free(index->json_fields[i]);
    free(index->postings); free(index);
}

bool qihse_sql_row_index_build(const qihse_schema_index_t* definition,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user, qihse_sql_row_index_t** out) {
    if (!out) return false;
    *out = NULL;
    if (!definition || !table || !user || !qihse_auth_user_is_active(user) ||
        !definition->table_name || strcmp(definition->table_name, qihse_table_name(table)) ||
        !definition->num_expressions || definition->num_expressions > 16 ||
        !definition->expressions || definition->unique) return false;
    qihse_sql_row_index_t* index = calloc(1, sizeof(*index));
    if (!index) return false;
    index->table = table; index->txn = txn;
    index->gin = definition->using_method && !strcasecmp(definition->using_method, "gin");
    if (definition->using_method && !index->gin && strcasecmp(definition->using_method, "btree")) goto fail;
    index->ncolumns = definition->num_expressions;
    if (index->gin && index->ncolumns != 1) goto fail;
    for (size_t i = 0; i < index->ncolumns; ++i)
        if (!expression(table, definition->expressions[i], &index->columns[i], &index->json_fields[i])) goto fail;
    if (index->gin) {
        if (index->json_fields[0]) goto fail;
        qihse_ts_type_t type = qihse_table_col_def(table, (size_t)index->columns[0])->type;
        if (type != QIHSE_TS_JSONB && type != QIHSE_TS_TSVECTOR) goto fail;
        index->json = type == QIHSE_TS_JSONB;
    }
    if (!source_generation(table, txn, user, &index->generation)) goto fail;
    index->principal = qihse_user_get_id(user);
    index->tenant = qihse_user_get_tenant_id(user);
    index->clearance = qihse_user_get_classification(user);
    index->sci = qihse_user_get_sci(user);
    if (!(txn ? qihse_table_txn_scan_ids_user(txn, user, add_row, index) :
                qihse_table_scan_ids_user(table, user, add_row, index)) || index->failed) goto fail;
    uint64_t after;
    if (!source_generation(table, txn, user, &after) || after != index->generation) goto fail;
    qsort(index->postings, index->length, sizeof(*index->postings), posting_cmp);
    *out = index; return true;
fail:
    qihse_sql_row_index_destroy(index); return false;
}

static bool available(const qihse_sql_row_index_t* index,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user) {
    uint64_t generation;
    return index && table == index->table && txn == index->txn && user &&
        qihse_auth_user_is_active(user) &&
        qihse_user_get_id(user) == index->principal &&
        qihse_user_get_tenant_id(user) == index->tenant &&
        qihse_user_get_classification(user) == index->clearance &&
        qihse_user_get_sci(user) == index->sci &&
        source_generation(table, txn, user, &generation) && generation == index->generation;
}

static bool find(const qihse_sql_row_index_t* index, const char* key,
                 size_t** rows, size_t* count) {
    *rows = NULL; *count = 0;
    size_t lo = 0, hi = index->length;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (strcmp(index->postings[mid].key, key) < 0) lo = mid + 1;
        else hi = mid;
    }
    size_t end = lo;
    while (end < index->length && !strcmp(index->postings[end].key, key)) ++end;
    if (end == lo) return true;
    size_t* found = malloc((end - lo) * sizeof(*found));
    if (!found) return false;
    size_t n = 0;
    for (size_t i = lo; i < end; ++i)
        if (!n || found[n-1] != index->postings[i].row)
            found[n++] = index->postings[i].row;
    *rows = found; *count = n; return true;
}

bool qihse_sql_row_index_equal(const qihse_sql_row_index_t* index,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user, const qihse_col_value_t* keys, size_t key_count,
    size_t** rows, size_t* count) {
    if (!rows || !count) return false;
    *rows = NULL; *count = 0;
    if (!available(index, table, txn, user) || index->gin || !keys ||
        key_count != index->ncolumns) return false;
    char* key = NULL; size_t size = 0;
    for (size_t i = 0; i < key_count; ++i)
        if (!encode(&key, &size, &keys[i])) { free(key); return false; }
    bool ok = find(index, key, rows, count);
    free(key); return ok;
}

bool qihse_sql_row_index_gin(const qihse_sql_row_index_t* index,
    const qihse_table_t* table, const qihse_table_txn_t* txn,
    const qihse_user_t* user, const char* json_key, const char* term,
    size_t** rows, size_t* count) {
    if (!rows || !count) return false;
    *rows = NULL; *count = 0;
    if (!available(index, table, txn, user) || !index->gin || !term ||
        (index->json ? !json_key : !!json_key)) return false;
    if (!index->json) return find(index, term, rows, count);
    qihse_col_value_t k = {.type=QIHSE_TS_STRING, .v.str=(char*)json_key};
    qihse_col_value_t v = {.type=QIHSE_TS_STRING, .v.str=(char*)term};
    char* tuple = NULL; size_t size = 0;
    if (!encode(&tuple, &size, &k) || !encode(&tuple, &size, &v)) {
        free(tuple); return false;
    }
    bool ok = find(index, tuple, rows, count);
    free(tuple); return ok;
}
