#define _GNU_SOURCE
/*
 * QIHSE ClickHouse SQL Dialect, MergeTree Engine, Materialized Views,
 * Dictionaries, Distributed Tables, HTTP & Native protocols.
 *
 * Self-contained C99 implementation operating over the QIHSE columnar store.
 */
#include "qihse_clickhouse_sql.h"
#include "qihse_clickhouse_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

/* =========================================================================
 * Section 1 — Small string / parsing utilities
 * ========================================================================= */

static char* ch_strdup(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static char* ch_strndup(const char* s, size_t n) {
    char* p = (char*)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static int ch_ieq(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* case-insensitive prefix match at a word boundary; returns ptr past kw or NULL */
static const char* match_kw(const char* p, const char* kw) {
    while (*p && isspace((unsigned char)*p)) p++;
    size_t kl = strlen(kw);
    if (strncasecmp(p, kw, kl) != 0) return NULL;
    char after = p[kl];
    if (isalnum((unsigned char)after) || after == '_') return NULL;
    return p + kl;
}

static const char* skip_ws(const char* p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static int is_ident_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

/* Read an identifier (possibly backtick/quote-quoted, possibly db.table). */
static const char* read_ident(const char* p, char** out) {
    p = skip_ws(p);
    const char* start = p;
    if (*p == '`' || *p == '"') {
        char q = *p++;
        start = p;
        while (*p && *p != q) p++;
        if (out) *out = ch_strndup(start, (size_t)(p - start));
        if (*p == q) p++;
    } else {
        while (*p && (is_ident_char(*p) || *p == '.')) p++;
        if (out) *out = ch_strndup(start, (size_t)(p - start));
    }
    return p;
}

/* Growable string buffer */
typedef struct {
    char*  data;
    size_t len;
    size_t cap;
} ch_buf_t;

static void buf_init(ch_buf_t* b) {
    b->cap = 128;
    b->len = 0;
    b->data = (char*)malloc(b->cap);
    if (b->data) b->data[0] = '\0';
}

static void buf_free(ch_buf_t* b) {
    free(b->data);
    b->data = NULL; b->len = 0; b->cap = 0;
}

static void buf_reserve(ch_buf_t* b, size_t extra) {
    if (b->len + extra + 1 > b->cap) {
        while (b->len + extra + 1 > b->cap) b->cap *= 2;
        b->data = (char*)realloc(b->data, b->cap);
    }
}

static void buf_append(ch_buf_t* b, const char* s, size_t n) {
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_puts(ch_buf_t* b, const char* s) {
    buf_append(b, s, strlen(s));
}

static void buf_printf(ch_buf_t* b, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) {
        buf_append(b, tmp, (size_t)n);
    } else {
        buf_reserve(b, (size_t)n);
        va_start(ap, fmt);
        vsnprintf(b->data + b->len, b->cap - b->len, fmt, ap);
        va_end(ap);
        b->len += (size_t)n;
    }
}

/* Find the matching close paren starting at the '(' at p; returns ptr just
 * past the close paren, or NULL if unbalanced. */
static const char* match_paren(const char* p) {
    if (!p || *p != '(') return NULL;
    int depth = 0;
    for (; *p; p++) {
        if (*p == '(') depth++;
        else if (*p == ')') {
            depth--;
            if (depth == 0) return p + 1;
        } else if (*p == '\'' || *p == '`' || *p == '"') {
            char q = *p++;
            while (*p && *p != q) { if (*p == '\\') p++; p++; }
            if (!*p) return NULL;
        }
    }
    return NULL;
}

/* Split a parenthesised body (text between outer parens, already stripped)
 * on top-level commas.  Returns array of trimmed strings + count. */
static char** split_commas(const char* body, size_t* out_n) {
    size_t cap = 8, n = 0;
    char** arr = (char**)malloc(cap * sizeof(char*));
    const char* start = body;
    int depth = 0;
    for (const char* p = body; ; p++) {
        if (*p == '\0' || (*p == ',' && depth == 0)) {
            const char* s = start;
            const char* e = p;
            while (s < e && isspace((unsigned char)*s)) s++;
            while (e > s && isspace((unsigned char)e[-1])) e--;
            if (n >= cap) { cap *= 2; arr = (char**)realloc(arr, cap * sizeof(char*)); }
            arr[n++] = ch_strndup(s, (size_t)(e - s));
            start = p + 1;
            if (*p == '\0') break;
        } else if (*p == '(' || *p == '[') {
            depth++;
        } else if (*p == ')' || *p == ']') {
            depth--;
        } else if (*p == '\'' || *p == '`' || *p == '"') {
            char q = *p++;
            while (*p && *p != q) { if (*p == '\\') p++; p++; }
            if (!*p) break;
        }
    }
    *out_n = n;
    return arr;
}

static void str_list_free(char** list, size_t n) {
    if (!list) return;
    for (size_t i = 0; i < n; i++) free(list[i]);
    free(list);
}

/* =========================================================================
 * Section 2 — Name tables
 * ========================================================================= */

const char* qihse_ch_stmt_name(qihse_ch_stmt_type_t t) {
    switch (t) {
        case QIHSE_CH_STMT_SELECT:       return "SELECT";
        case QIHSE_CH_STMT_INSERT:       return "INSERT";
        case QIHSE_CH_STMT_CREATE_TABLE: return "CREATE TABLE";
        case QIHSE_CH_STMT_CREATE_MV:    return "CREATE MATERIALIZED VIEW";
        case QIHSE_CH_STMT_CREATE_DICT:  return "CREATE DICTIONARY";
        case QIHSE_CH_STMT_ALTER:        return "ALTER";
        case QIHSE_CH_STMT_OPTIMIZE:     return "OPTIMIZE";
        case QIHSE_CH_STMT_TRUNCATE:     return "TRUNCATE";
        case QIHSE_CH_STMT_DROP:         return "DROP";
        case QIHSE_CH_STMT_SYSTEM:       return "SYSTEM";
        case QIHSE_CH_STMT_SHOW:         return "SHOW";
        case QIHSE_CH_STMT_DESCRIBE:     return "DESCRIBE";
        case QIHSE_CH_STMT_EXISTS:       return "EXISTS";
        case QIHSE_CH_STMT_USE:          return "USE";
        case QIHSE_CH_STMT_SET:          return "SET";
        default:                         return "UNKNOWN";
    }
}

const char* qihse_ch_engine_name(qihse_ch_engine_t e) {
    switch (e) {
        case QIHSE_CH_ENGINE_MERGETREE:             return "MergeTree";
        case QIHSE_CH_ENGINE_REPLACING_MERGETREE:   return "ReplacingMergeTree";
        case QIHSE_CH_ENGINE_SUMMING_MERGETREE:     return "SummingMergeTree";
        case QIHSE_CH_ENGINE_AGGREGATING_MERGETREE: return "AggregatingMergeTree";
        case QIHSE_CH_ENGINE_COLLAPSING_MERGETREE:  return "CollapsingMergeTree";
        case QIHSE_CH_ENGINE_VERSIONED_COLLAPSING:  return "VersionedCollapsingMergeTree";
        case QIHSE_CH_ENGINE_TINYLOG:               return "TinyLog";
        case QIHSE_CH_ENGINE_LOG:                   return "Log";
        case QIHSE_CH_ENGINE_MEMORY:                return "Memory";
        case QIHSE_CH_ENGINE_NULL:                  return "Null";
        case QIHSE_CH_ENGINE_DISTRIBUTED:           return "Distributed";
        case QIHSE_CH_ENGINE_MERGE:                 return "Merge";
        case QIHSE_CH_ENGINE_BUFFER:                return "Buffer";
        case QIHSE_CH_ENGINE_SET:                   return "Set";
        case QIHSE_CH_ENGINE_JOIN:                  return "Join";
        case QIHSE_CH_ENGINE_URL:                   return "URL";
        case QIHSE_CH_ENGINE_VIEW:                  return "View";
        case QIHSE_CH_ENGINE_MATERIALIZED_VIEW:     return "MaterializedView";
        case QIHSE_CH_ENGINE_LIVE_VIEW:             return "LiveView";
        case QIHSE_CH_ENGINE_DICTIONARY:            return "Dictionary";
        default:                                    return "None";
    }
}

static qihse_ch_engine_t engine_from_str(const char* s) {
    if (!s) return QIHSE_CH_ENGINE_NONE;
    if (ch_ieq(s, "MergeTree"))                  return QIHSE_CH_ENGINE_MERGETREE;
    if (ch_ieq(s, "ReplacingMergeTree"))         return QIHSE_CH_ENGINE_REPLACING_MERGETREE;
    if (ch_ieq(s, "SummingMergeTree"))           return QIHSE_CH_ENGINE_SUMMING_MERGETREE;
    if (ch_ieq(s, "AggregatingMergeTree"))       return QIHSE_CH_ENGINE_AGGREGATING_MERGETREE;
    if (ch_ieq(s, "CollapsingMergeTree"))        return QIHSE_CH_ENGINE_COLLAPSING_MERGETREE;
    if (ch_ieq(s, "VersionedCollapsingMergeTree"))return QIHSE_CH_ENGINE_VERSIONED_COLLAPSING;
    if (ch_ieq(s, "TinyLog"))                    return QIHSE_CH_ENGINE_TINYLOG;
    if (ch_ieq(s, "Log"))                        return QIHSE_CH_ENGINE_LOG;
    if (ch_ieq(s, "Memory"))                     return QIHSE_CH_ENGINE_MEMORY;
    if (ch_ieq(s, "Null"))                       return QIHSE_CH_ENGINE_NULL;
    if (ch_ieq(s, "Distributed"))                return QIHSE_CH_ENGINE_DISTRIBUTED;
    if (ch_ieq(s, "Merge"))                      return QIHSE_CH_ENGINE_MERGE;
    if (ch_ieq(s, "Buffer"))                     return QIHSE_CH_ENGINE_BUFFER;
    if (ch_ieq(s, "Set"))                        return QIHSE_CH_ENGINE_SET;
    if (ch_ieq(s, "Join"))                       return QIHSE_CH_ENGINE_JOIN;
    if (ch_ieq(s, "URL"))                        return QIHSE_CH_ENGINE_URL;
    if (ch_ieq(s, "View"))                       return QIHSE_CH_ENGINE_VIEW;
    if (ch_ieq(s, "MaterializedView"))           return QIHSE_CH_ENGINE_MATERIALIZED_VIEW;
    if (ch_ieq(s, "LiveView"))                   return QIHSE_CH_ENGINE_LIVE_VIEW;
    if (ch_ieq(s, "Dictionary"))                 return QIHSE_CH_ENGINE_DICTIONARY;
    return QIHSE_CH_ENGINE_NONE;
}

const char* qihse_ch_data_type_name(qihse_ch_data_type_t t) {
    switch (t) {
        case QIHSE_CH_TYPE_INT8:        return "Int8";
        case QIHSE_CH_TYPE_INT16:       return "Int16";
        case QIHSE_CH_TYPE_INT32:       return "Int32";
        case QIHSE_CH_TYPE_INT64:       return "Int64";
        case QIHSE_CH_TYPE_UINT8:       return "UInt8";
        case QIHSE_CH_TYPE_UINT16:      return "UInt16";
        case QIHSE_CH_TYPE_UINT32:      return "UInt32";
        case QIHSE_CH_TYPE_UINT64:      return "UInt64";
        case QIHSE_CH_TYPE_FLOAT32:     return "Float32";
        case QIHSE_CH_TYPE_FLOAT64:     return "Float64";
        case QIHSE_CH_TYPE_STRING:      return "String";
        case QIHSE_CH_TYPE_FIXEDSTRING: return "FixedString";
        case QIHSE_CH_TYPE_DATE:        return "Date";
        case QIHSE_CH_TYPE_DATETIME:    return "DateTime";
        case QIHSE_CH_TYPE_DATETIME64:  return "DateTime64";
        case QIHSE_CH_TYPE_UUID:        return "UUID";
        case QIHSE_CH_TYPE_BOOL:        return "Bool";
        case QIHSE_CH_TYPE_DECIMAL:     return "Decimal";
        case QIHSE_CH_TYPE_ARRAY:       return "Array";
        case QIHSE_CH_TYPE_TUPLE:       return "Tuple";
        case QIHSE_CH_TYPE_MAP:         return "Map";
        case QIHSE_CH_TYPE_NESTED:      return "Nested";
        case QIHSE_CH_TYPE_LOWCARDINALITY: return "LowCardinality";
        case QIHSE_CH_TYPE_ENUM8:       return "Enum8";
        case QIHSE_CH_TYPE_ENUM16:      return "Enum16";
        case QIHSE_CH_TYPE_IPV4:        return "IPv4";
        case QIHSE_CH_TYPE_IPV6:        return "IPv6";
        case QIHSE_CH_TYPE_JSON:        return "JSON";
        case QIHSE_CH_TYPE_AGGREGATEFUNCTION: return "AggregateFunction";
        case QIHSE_CH_TYPE_SIMPLEAGGREGATEFUNCTION: return "SimpleAggregateFunction";
        default:                        return "Unknown";
    }
}

qihse_ch_data_type_t qihse_ch_data_type_from_str(const char* s) {
    if (!s) return QIHSE_CH_TYPE_UNKNOWN;
    /* strip leading "Nullable(" wrapper */
    const char* p = s;
    if (strncasecmp(p, "Nullable(", 9) == 0) p += 9;
    if (strncasecmp(p, "LowCardinality(", 16) == 0) p += 16;
    if (ch_ieq(p, "Int8") || ch_ieq(p, "TINYINT"))           return QIHSE_CH_TYPE_INT8;
    if (ch_ieq(p, "Int16") || ch_ieq(p, "SMALLINT"))         return QIHSE_CH_TYPE_INT16;
    if (ch_ieq(p, "Int32") || ch_ieq(p, "INT") || ch_ieq(p, "INTEGER")) return QIHSE_CH_TYPE_INT32;
    if (ch_ieq(p, "Int64") || ch_ieq(p, "BIGINT"))           return QIHSE_CH_TYPE_INT64;
    if (ch_ieq(p, "UInt8"))                                  return QIHSE_CH_TYPE_UINT8;
    if (ch_ieq(p, "UInt16"))                                 return QIHSE_CH_TYPE_UINT16;
    if (ch_ieq(p, "UInt32"))                                 return QIHSE_CH_TYPE_UINT32;
    if (ch_ieq(p, "UInt64"))                                 return QIHSE_CH_TYPE_UINT64;
    if (ch_ieq(p, "Float32") || ch_ieq(p, "FLOAT"))          return QIHSE_CH_TYPE_FLOAT32;
    if (ch_ieq(p, "Float64") || ch_ieq(p, "DOUBLE"))         return QIHSE_CH_TYPE_FLOAT64;
    if (ch_ieq(p, "String") || ch_ieq(p, "TEXT") || ch_ieq(p, "VARCHAR")) return QIHSE_CH_TYPE_STRING;
    if (strncasecmp(p, "FixedString", 11) == 0)              return QIHSE_CH_TYPE_FIXEDSTRING;
    if (ch_ieq(p, "Date"))                                   return QIHSE_CH_TYPE_DATE;
    if (ch_ieq(p, "DateTime"))                               return QIHSE_CH_TYPE_DATETIME;
    if (strncasecmp(p, "DateTime64", 10) == 0)               return QIHSE_CH_TYPE_DATETIME64;
    if (ch_ieq(p, "UUID"))                                   return QIHSE_CH_TYPE_UUID;
    if (ch_ieq(p, "Bool") || ch_ieq(p, "BOOLEAN"))           return QIHSE_CH_TYPE_BOOL;
    if (strncasecmp(p, "Decimal", 7) == 0)                   return QIHSE_CH_TYPE_DECIMAL;
    if (strncasecmp(p, "Array", 5) == 0)                     return QIHSE_CH_TYPE_ARRAY;
    if (strncasecmp(p, "Tuple", 5) == 0)                     return QIHSE_CH_TYPE_TUPLE;
    if (strncasecmp(p, "Map", 3) == 0)                       return QIHSE_CH_TYPE_MAP;
    if (strncasecmp(p, "Nested", 6) == 0)                    return QIHSE_CH_TYPE_NESTED;
    if (strncasecmp(p, "Enum8", 5) == 0)                     return QIHSE_CH_TYPE_ENUM8;
    if (strncasecmp(p, "Enum16", 6) == 0)                    return QIHSE_CH_TYPE_ENUM16;
    if (ch_ieq(p, "IPv4"))                                   return QIHSE_CH_TYPE_IPV4;
    if (ch_ieq(p, "IPv6"))                                   return QIHSE_CH_TYPE_IPV6;
    if (ch_ieq(p, "JSON"))                                   return QIHSE_CH_TYPE_JSON;
    if (strncasecmp(p, "AggregateFunction", 16) == 0)        return QIHSE_CH_TYPE_AGGREGATEFUNCTION;
    if (strncasecmp(p, "SimpleAggregateFunction", 22) == 0)  return QIHSE_CH_TYPE_SIMPLEAGGREGATEFUNCTION;
    return QIHSE_CH_TYPE_UNKNOWN;
}

qihse_ch_format_t qihse_ch_format_from_str(const char* s) {
    if (!s) return QIHSE_CH_FMT_TABSEPARATED;
    if (ch_ieq(s, "TabSeparated"))                       return QIHSE_CH_FMT_TABSEPARATED;
    if (ch_ieq(s, "TabSeparatedWithNames"))              return QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES;
    if (ch_ieq(s, "TabSeparatedWithNamesAndTypes"))      return QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES_AND_TYPES;
    if (ch_ieq(s, "TSV"))                                return QIHSE_CH_FMT_TSV;
    if (ch_ieq(s, "TSVWithNames"))                       return QIHSE_CH_FMT_TSV_WITH_NAMES;
    if (ch_ieq(s, "CSV"))                                return QIHSE_CH_FMT_CSV;
    if (ch_ieq(s, "CSVWithNames"))                       return QIHSE_CH_FMT_CSV_WITH_NAMES;
    if (ch_ieq(s, "JSON"))                               return QIHSE_CH_FMT_JSON;
    if (ch_ieq(s, "JSONEachRow"))                        return QIHSE_CH_FMT_JSON_EACH_ROW;
    if (ch_ieq(s, "JSONCompact"))                        return QIHSE_CH_FMT_JSON_COMPACT;
    if (ch_ieq(s, "JSONCompactEachRow"))                 return QIHSE_CH_FMT_JSON_COMPACT_EACH_ROW;
    if (ch_ieq(s, "Values"))                             return QIHSE_CH_FMT_VALUES;
    if (ch_ieq(s, "Vertical"))                           return QIHSE_CH_FMT_VERTICAL;
    if (ch_ieq(s, "Pretty"))                             return QIHSE_CH_FMT_PRETTY;
    if (ch_ieq(s, "PrettyCompact"))                      return QIHSE_CH_FMT_PRETTY_COMPACT;
    if (ch_ieq(s, "PrettyCompactNoEscapes"))             return QIHSE_CH_FMT_PRETTY_COMPACT_NOESC;
    if (ch_ieq(s, "Raw"))                                return QIHSE_CH_FMT_RAW;
    if (ch_ieq(s, "Null"))                               return QIHSE_CH_FMT_NULL;
    if (ch_ieq(s, "XML"))                                return QIHSE_CH_FMT_XML;
    if (ch_ieq(s, "Markdown"))                           return QIHSE_CH_FMT_MARKDOWN;
    return QIHSE_CH_FMT_TABSEPARATED;
}

const char* qihse_ch_format_name(qihse_ch_format_t f) {
    switch (f) {
        case QIHSE_CH_FMT_TABSEPARATED:                       return "TabSeparated";
        case QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES:            return "TabSeparatedWithNames";
        case QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES_AND_TYPES:  return "TabSeparatedWithNamesAndTypes";
        case QIHSE_CH_FMT_TSV:                                return "TSV";
        case QIHSE_CH_FMT_TSV_WITH_NAMES:                     return "TSVWithNames";
        case QIHSE_CH_FMT_CSV:                                return "CSV";
        case QIHSE_CH_FMT_CSV_WITH_NAMES:                     return "CSVWithNames";
        case QIHSE_CH_FMT_JSON:                               return "JSON";
        case QIHSE_CH_FMT_JSON_EACH_ROW:                      return "JSONEachRow";
        case QIHSE_CH_FMT_JSON_COMPACT:                       return "JSONCompact";
        case QIHSE_CH_FMT_JSON_COMPACT_EACH_ROW:              return "JSONCompactEachRow";
        case QIHSE_CH_FMT_VALUES:                             return "Values";
        case QIHSE_CH_FMT_VERTICAL:                           return "Vertical";
        case QIHSE_CH_FMT_PRETTY:                             return "Pretty";
        case QIHSE_CH_FMT_PRETTY_COMPACT:                     return "PrettyCompact";
        case QIHSE_CH_FMT_PRETTY_COMPACT_NOESC:               return "PrettyCompactNoEscapes";
        case QIHSE_CH_FMT_RAW:                                return "Raw";
        case QIHSE_CH_FMT_NULL:                               return "Null";
        case QIHSE_CH_FMT_XML:                                return "XML";
        case QIHSE_CH_FMT_MARKDOWN:                           return "Markdown";
        default:                                              return "TabSeparated";
    }
}

/* =========================================================================
 * Section 3 — Result sets
 * ========================================================================= */

qihse_ch_result_t* qihse_ch_result_create(size_t num_columns) {
    qihse_ch_result_t* r = (qihse_ch_result_t*)calloc(1, sizeof(qihse_ch_result_t));
    if (!r) return NULL;
    r->num_columns = num_columns;
    if (num_columns > 0) {
        r->column_names = (char**)calloc(num_columns, sizeof(char*));
        r->column_types = (qihse_ch_data_type_t*)calloc(num_columns, sizeof(qihse_ch_data_type_t));
        r->column_type_names = (char**)calloc(num_columns, sizeof(char*));
    }
    return r;
}

void qihse_ch_result_free(qihse_ch_result_t* r) {
    if (!r) return;
    if (r->column_names) {
        for (size_t i = 0; i < r->num_columns; i++) free(r->column_names[i]);
        free(r->column_names);
    }
    free(r->column_types);
    if (r->column_type_names) {
        for (size_t i = 0; i < r->num_columns; i++) free(r->column_type_names[i]);
        free(r->column_type_names);
    }
    if (r->rows) {
        for (size_t i = 0; i < r->num_rows; i++) {
            if (!r->rows[i]) continue;
            for (size_t j = 0; j < r->num_columns; j++) free(r->rows[i][j].str);
            free(r->rows[i]);
        }
        free(r->rows);
    }
    free(r->error);
    free(r);
}

qihse_ch_result_t* qihse_ch_result_error(const char* msg) {
    qihse_ch_result_t* r = qihse_ch_result_create(0);
    if (r) r->error = ch_strdup(msg);
    return r;
}

int qihse_ch_result_ensure_rows(qihse_ch_result_t* r, size_t n) {
    if (!r) return -1;
    if (n <= r->num_rows) return 0;
    size_t newcap = r->num_rows ? r->num_rows : 4;
    while (newcap < n) newcap *= 2;
    r->rows = (qihse_ch_cell_t**)realloc(r->rows, newcap * sizeof(qihse_ch_cell_t*));
    if (!r->rows) return -1;
    for (size_t i = r->num_rows; i < n; i++) {
        r->rows[i] = (qihse_ch_cell_t*)calloc(r->num_columns, sizeof(qihse_ch_cell_t));
    }
    r->num_rows = n;
    return 0;
}

void qihse_ch_result_set_str(qihse_ch_result_t* r, size_t row, size_t col, const char* val) {
    if (!r || col >= r->num_columns) return;
    if (qihse_ch_result_ensure_rows(r, row + 1) != 0) return;
    free(r->rows[row][col].str);
    r->rows[row][col].kind = QIHSE_CH_CELL_STR;
    r->rows[row][col].str = ch_strdup(val ? val : "");
}

void qihse_ch_result_set_int(qihse_ch_result_t* r, size_t row, size_t col, int64_t val) {
    if (!r || col >= r->num_columns) return;
    if (qihse_ch_result_ensure_rows(r, row + 1) != 0) return;
    free(r->rows[row][col].str);
    r->rows[row][col].kind = QIHSE_CH_CELL_INT;
    r->rows[row][col].str = NULL;
    r->rows[row][col].i64 = val;
}

void qihse_ch_result_set_float(qihse_ch_result_t* r, size_t row, size_t col, double val) {
    if (!r || col >= r->num_columns) return;
    if (qihse_ch_result_ensure_rows(r, row + 1) != 0) return;
    free(r->rows[row][col].str);
    r->rows[row][col].kind = QIHSE_CH_CELL_FLOAT;
    r->rows[row][col].str = NULL;
    r->rows[row][col].f64 = val;
}

void qihse_ch_result_set_null(qihse_ch_result_t* r, size_t row, size_t col) {
    if (!r || col >= r->num_columns) return;
    if (qihse_ch_result_ensure_rows(r, row + 1) != 0) return;
    free(r->rows[row][col].str);
    r->rows[row][col].kind = QIHSE_CH_CELL_NULL;
    r->rows[row][col].str = NULL;
}

/* =========================================================================
 * Section 4 — Catalog
 * ========================================================================= */

qihse_ch_catalog_t* qihse_ch_catalog_create(void) {
    qihse_ch_catalog_t* cat = (qihse_ch_catalog_t*)calloc(1, sizeof(qihse_ch_catalog_t));
    if (!cat) return NULL;
    snprintf(cat->current_database, sizeof(cat->current_database), "%s", "default");
    pthread_mutex_init(&cat->lock, NULL);
    return cat;
}

static void table_free(qihse_ch_table_t* t) {
    if (!t) return;
    free(t->name); free(t->database); free(t->engine_args);
    free(t->partition_by); free(t->sample_by); free(t->ttl); free(t->settings);
    for (size_t i = 0; i < t->num_columns; i++) {
        free(t->columns[i].name);
        free(t->columns[i].type_str);
        free(t->columns[i].default_expr);
        free(t->columns[i].codec);
        free(t->columns[i].ttl);
    }
    free(t->columns);
    str_list_free(t->order_by, t->num_order_by);
    str_list_free(t->primary_key, t->num_primary_key);
    for (size_t i = 0; i < t->num_skip_indices; i++) {
        free(t->skip_indices[i].name);
        free(t->skip_indices[i].expr);
        free(t->skip_indices[i].params);
    }
    free(t->skip_indices);
    qihse_ch_part_t* p = t->parts;
    while (p) { qihse_ch_part_t* nx = p->next; qihse_ch_part_free(p); p = nx; }
    if (t->distributed) {
        free(t->distributed->cluster);
        free(t->distributed->db);
        free(t->distributed->table);
        free(t->distributed->sharding_key);
        free(t->distributed);
    }
    pthread_mutex_destroy(&t->lock);
    free(t);
}

static void mv_free(qihse_ch_mv_t* m) {
    if (!m) return;
    free(m->name); free(m->database); free(m->target_table);
    free(m->source_table); free(m->select_sql);
    if (m->table) table_free(m->table);
    free(m);
}

static void dict_free(qihse_ch_dictionary_t* d) {
    if (!d) return;
    free(d->name); free(d->database); free(d->source);
    free(d->layout); free(d->lifetime); free(d->primary_key);
    for (size_t i = 0; i < d->num_attrs; i++) {
        free(d->attrs[i].name); free(d->attrs[i].type_str); free(d->attrs[i].default_expr);
    }
    free(d->attrs);
    for (size_t i = 0; i < d->cache_count; i++) { free(d->cache_keys[i]); free(d->cache_vals[i]); }
    free(d->cache_keys); free(d->cache_vals);
    free(d);
}

void qihse_ch_catalog_destroy(qihse_ch_catalog_t* cat) {
    if (!cat) return;
    qihse_ch_table_t* t = cat->tables;
    while (t) { qihse_ch_table_t* nx = t->next; table_free(t); t = nx; }
    qihse_ch_mv_t* m = cat->mvs;
    while (m) { qihse_ch_mv_t* nx = m->next; mv_free(m); m = nx; }
    qihse_ch_dictionary_t* d = cat->dictionaries;
    while (d) { qihse_ch_dictionary_t* nx = d->next; dict_free(d); d = nx; }
    pthread_mutex_destroy(&cat->lock);
    free(cat);
}

qihse_ch_table_t* qihse_ch_catalog_find_table(qihse_ch_catalog_t* cat,
                                              const char* db, const char* name) {
    if (!cat || !name) return NULL;
    if (!db) db = cat->current_database;
    pthread_mutex_lock(&cat->lock);
    for (qihse_ch_table_t* t = cat->tables; t; t = t->next) {
        if (ch_ieq(t->name, name) && ch_ieq(t->database, db)) {
            pthread_mutex_unlock(&cat->lock);
            return t;
        }
    }
    pthread_mutex_unlock(&cat->lock);
    return NULL;
}

qihse_ch_mv_t* qihse_ch_catalog_find_mv(qihse_ch_catalog_t* cat,
                                        const char* db, const char* name) {
    if (!cat || !name) return NULL;
    if (!db) db = cat->current_database;
    pthread_mutex_lock(&cat->lock);
    for (qihse_ch_mv_t* m = cat->mvs; m; m = m->next) {
        if (ch_ieq(m->name, name) && ch_ieq(m->database, db)) {
            pthread_mutex_unlock(&cat->lock);
            return m;
        }
    }
    pthread_mutex_unlock(&cat->lock);
    return NULL;
}

qihse_ch_dictionary_t* qihse_ch_catalog_find_dict(qihse_ch_catalog_t* cat,
                                                  const char* db, const char* name) {
    if (!cat || !name) return NULL;
    if (!db) db = cat->current_database;
    pthread_mutex_lock(&cat->lock);
    for (qihse_ch_dictionary_t* d = cat->dictionaries; d; d = d->next) {
        if (ch_ieq(d->name, name) && ch_ieq(d->database, db)) {
            pthread_mutex_unlock(&cat->lock);
            return d;
        }
    }
    pthread_mutex_unlock(&cat->lock);
    return NULL;
}

static qihse_ch_table_t* table_create_from_ast(const qihse_ch_ast_t* ast,
                                               const char* db) {
    qihse_ch_table_t* t = (qihse_ch_table_t*)calloc(1, sizeof(qihse_ch_table_t));
    if (!t) return NULL;
    t->name = ch_strdup(ast->name);
    t->database = ch_strdup(db ? db : "default");
    t->engine = ast->engine;
    t->engine_args = ch_strdup(ast->engine_args);
    pthread_mutex_init(&t->lock, NULL);
    /* deep-copy columns */
    if (ast->num_columns > 0) {
        t->columns = (qihse_ch_column_def_t*)calloc(ast->num_columns, sizeof(qihse_ch_column_def_t));
        t->num_columns = ast->num_columns;
        for (size_t i = 0; i < ast->num_columns; i++) {
            t->columns[i].name = ch_strdup(ast->columns[i].name);
            t->columns[i].type = ast->columns[i].type;
            t->columns[i].type_str = ch_strdup(ast->columns[i].type_str);
            t->columns[i].default_expr = ch_strdup(ast->columns[i].default_expr);
            t->columns[i].codec = ch_strdup(ast->columns[i].codec);
            t->columns[i].ttl = ch_strdup(ast->columns[i].ttl);
            t->columns[i].not_null = ast->columns[i].not_null;
        }
    }
    /* copy order_by / primary_key */
    if (ast->num_order_by > 0) {
        t->order_by = (char**)calloc(ast->num_order_by, sizeof(char*));
        t->num_order_by = ast->num_order_by;
        for (size_t i = 0; i < ast->num_order_by; i++) t->order_by[i] = ch_strdup(ast->order_by[i]);
    }
    if (ast->num_primary_key > 0) {
        t->primary_key = (char**)calloc(ast->num_primary_key, sizeof(char*));
        t->num_primary_key = ast->num_primary_key;
        for (size_t i = 0; i < ast->num_primary_key; i++) t->primary_key[i] = ch_strdup(ast->primary_key[i]);
    }
    t->partition_by = ch_strdup(ast->partition_by);
    t->sample_by = ch_strdup(ast->sample_by);
    t->ttl = ch_strdup(ast->ttl);
    t->settings = ch_strdup(ast->settings);
    if (ast->num_skip_indices > 0) {
        t->skip_indices = (qihse_ch_skip_index_t*)calloc(ast->num_skip_indices, sizeof(qihse_ch_skip_index_t));
        t->num_skip_indices = ast->num_skip_indices;
        for (size_t i = 0; i < ast->num_skip_indices; i++) {
            t->skip_indices[i].name = ch_strdup(ast->skip_indices[i].name);
            t->skip_indices[i].type = ast->skip_indices[i].type;
            t->skip_indices[i].expr = ch_strdup(ast->skip_indices[i].expr);
            t->skip_indices[i].params = ch_strdup(ast->skip_indices[i].params);
        }
    }
    /* Distributed descriptor */
    if (t->engine == QIHSE_CH_ENGINE_DISTRIBUTED && ast->engine_args) {
        qihse_ch_distributed_t* dist = (qihse_ch_distributed_t*)calloc(1, sizeof(qihse_ch_distributed_t));
        /* engine_args like: ('cluster','db','table'[,sharding_key]) */
        const char* a = ast->engine_args;
        size_t n = 0;
        char** parts = split_commas(a, &n);
        if (n >= 1) dist->cluster = ch_strdup(parts[0]);
        if (n >= 2) dist->db = ch_strdup(parts[1]);
        if (n >= 3) dist->table = ch_strdup(parts[2]);
        if (n >= 4) dist->sharding_key = ch_strdup(parts[3]);
        str_list_free(parts, n);
        t->distributed = dist;
    }
    return t;
}

static int catalog_add_table(qihse_ch_catalog_t* cat, qihse_ch_table_t* t) {
    pthread_mutex_lock(&cat->lock);
    t->next = cat->tables;
    cat->tables = t;
    pthread_mutex_unlock(&cat->lock);
    return 0;
}

/* =========================================================================
 * Section 5 — Parser
 *
 * The parser is a pragmatic, cursor-based recursive-descent parser that
 * recognises the ClickHouse dialect statement forms listed in the spec.
 * Complex expressions (SELECT bodies, WHERE, etc.) are preserved as raw
 * text; structured fields are extracted where they drive execution.
 * ========================================================================= */

typedef struct {
    const char* src;
    size_t      len;
    size_t      pos;
} ch_lex_t;

static void lex_init(ch_lex_t* L, const char* s) {
    L->src = s ? s : "";
    L->len = strlen(L->src);
    L->pos = 0;
}

static const char* lex_cur(const ch_lex_t* L) {
    return L->src + L->pos;
}

static const char* lex_skip_ws(ch_lex_t* L) {
    const char* p = L->src + L->pos;
    while (*p && isspace((unsigned char)*p)) p++;
    /* skip comments -- and /* */
    while (*p == '-' && p[1] == '-') {
        p += 2;
        while (*p && *p != '\n') p++;
        while (*p && isspace((unsigned char)*p)) p++;
    }
    while (*p == '/' && p[1] == '*') {
        p += 2;
        while (*p && !(*p == '*' && p[1] == '/')) p++;
        if (*p) p += 2;
        while (*p && isspace((unsigned char)*p)) p++;
    }
    L->pos = (size_t)(p - L->src);
    return p;
}

static int lex_eof(ch_lex_t* L) {
    lex_skip_ws(L);
    return lex_cur(L)[0] == '\0';
}

/* case-insensitive keyword match at current pos (word boundary); advances on match */
static int lex_kw(ch_lex_t* L, const char* kw) {
    lex_skip_ws(L);
    const char* p = lex_cur(L);
    size_t kl = strlen(kw);
    if (strncasecmp(p, kw, kl) != 0) return 0;
    char after = p[kl];
    if (isalnum((unsigned char)after) || after == '_') return 0;
    L->pos += kl;
    return 1;
}

/* peek keyword without advancing */
static int lex_peek_kw(ch_lex_t* L, const char* kw) {
    lex_skip_ws(L);
    const char* p = lex_cur(L);
    size_t kl = strlen(kw);
    if (strncasecmp(p, kw, kl) != 0) return 0;
    char after = p[kl];
    if (isalnum((unsigned char)after) || after == '_') return 0;
    return 1;
}

static int lex_char(ch_lex_t* L, char c) {
    lex_skip_ws(L);
    if (lex_cur(L)[0] == c) { L->pos++; return 1; }
    return 0;
}

static int lex_char2(ch_lex_t* L, char a, char b) {
    lex_skip_ws(L);
    const char* p = lex_cur(L);
    if (p[0] == a && p[1] == b) { L->pos += 2; return 1; }
    return 0;
}

static char* lex_ident(ch_lex_t* L) {
    lex_skip_ws(L);
    const char* p = lex_cur(L);
    if (*p == '`' || *p == '"') {
        char q = *p;
        p++;
        const char* start = p;
        while (*p && *p != q) p++;
        char* out = ch_strndup(start, (size_t)(p - start));
        if (*p == q) p++;
        L->pos = (size_t)(p - L->src);
        return out;
    }
    const char* start = p;
    while (*p && (is_ident_char(*p) || *p == '.')) p++;
    if (p == start) return NULL;
    char* out = ch_strndup(start, (size_t)(p - start));
    L->pos = (size_t)(p - L->src);
    return out;
}

/* read a balanced parenthesised group including the outer parens; returns
 * the inner content (without parens) as a freshly allocated string. */
static char* lex_paren_body(ch_lex_t* L) {
    lex_skip_ws(L);
    const char* p = lex_cur(L);
    if (*p != '(') return NULL;
    const char* start = p + 1;
    const char* end = match_paren(p);
    if (!end) return NULL;
    /* inner content between start and end-1 */
    char* body = ch_strndup(start, (size_t)((end - 1) - start));
    L->pos = (size_t)(end - L->src);
    return body;
}

/* read raw text until one of the given top-level keywords (case-insensitive,
 * word boundary) or end.  Returns allocated string (trimmed).  Stops *before*
 * the keyword (pos left at keyword). */
static char* lex_until_kw(ch_lex_t* L, const char** kws, size_t nkw) {
    lex_skip_ws(L);
    const char* start = lex_cur(L);
    const char* p = start;
    int depth = 0;
    while (*p) {
        if (*p == '(' || *p == '[') depth++;
        else if (*p == ')' || *p == ']') { if (depth > 0) depth--; }
        else if (*p == '\'' || *p == '`' || *p == '"') {
            char q = *p++;
            while (*p && *p != q) { if (*p == '\\') p++; p++; }
            if (!*p) break;
            p++;
            continue;
        }
        if (depth == 0) {
            for (size_t i = 0; i < nkw; i++) {
                size_t kl = strlen(kws[i]);
                if (strncasecmp(p, kws[i], kl) == 0) {
                    char after = p[kl];
                    if (!(isalnum((unsigned char)after) || after == '_')) {
                        L->pos = (size_t)(p - L->src);
                        const char* e = p;
                        while (e > start && isspace((unsigned char)e[-1])) e--;
                        return ch_strndup(start, (size_t)(e - start));
                    }
                }
            }
        }
        p++;
    }
    L->pos = (size_t)(p - L->src);
    const char* e = p;
    while (e > start && isspace((unsigned char)e[-1])) e--;
    return ch_strndup(start, (size_t)(e - start));
}

/* read raw text until a top-level keyword or specific char at depth 0 */
static char* lex_until_kw_or_char(ch_lex_t* L, const char** kws, size_t nkw,
                                  char stop) {
    lex_skip_ws(L);
    const char* start = lex_cur(L);
    const char* p = start;
    int depth = 0;
    while (*p) {
        if (*p == '(' || *p == '[') depth++;
        else if (*p == ')' || *p == ']') { if (depth > 0) depth--; }
        else if (*p == '\'' || *p == '`' || *p == '"') {
            char q = *p++;
            while (*p && *p != q) { if (*p == '\\') p++; p++; }
            if (!*p) break;
            p++;
            continue;
        }
        if (depth == 0) {
            if (*p == stop) {
                L->pos = (size_t)(p - L->src);
                const char* e = p;
                while (e > start && isspace((unsigned char)e[-1])) e--;
                return ch_strndup(start, (size_t)(e - start));
            }
            for (size_t i = 0; i < nkw; i++) {
                size_t kl = strlen(kws[i]);
                if (strncasecmp(p, kws[i], kl) == 0) {
                    char after = p[kl];
                    if (!(isalnum((unsigned char)after) || after == '_')) {
                        L->pos = (size_t)(p - L->src);
                        const char* e2 = p;
                        while (e2 > start && isspace((unsigned char)e2[-1])) e2--;
                        return ch_strndup(start, (size_t)(e2 - start));
                    }
                }
            }
        }
        p++;
    }
    L->pos = (size_t)(p - L->src);
    const char* e = p;
    while (e > start && isspace((unsigned char)e[-1])) e--;
    return ch_strndup(start, (size_t)(e - start));
}

/* parse a column definition body like:  name TYPE [DEFAULT expr] [NOT NULL]
 * [CODEC(...)] [TTL expr]  -- returns 0 on success */
static int parse_column_def(const char* text, qihse_ch_column_def_t* col) {
    ch_lex_t L;
    lex_init(&L, text);
    char* name = lex_ident(&L);
    if (!name) return -1;
    col->name = name;
    /* type: read until DEFAULT/CODEC/TTL/NOT/NULL/end */
    const char* kws[] = {"DEFAULT", "MATERIALIZED", "ALIAS", "CODEC", "TTL",
                         "NOT", "NULL", "EPHEMERAL"};
    char* type_str = lex_until_kw(&L, kws, sizeof(kws)/sizeof(kws[0]));
    /* trim */
    if (type_str) {
        char* s = type_str;
        while (*s && isspace((unsigned char)*s)) s++;
        char* e = s + strlen(s);
        while (e > s && isspace((unsigned char)e[-1])) e--;
        *e = '\0';
        col->type_str = ch_strdup(s);
        free(type_str);
        col->type = qihse_ch_data_type_from_str(col->type_str);
    } else {
        col->type_str = ch_strdup("String");
        col->type = QIHSE_CH_TYPE_STRING;
    }
    /* optional clauses */
    for (;;) {
        lex_skip_ws(&L);
        if (lex_eof(&L)) break;
        if (lex_kw(&L, "NOT")) { lex_kw(&L, "NULL"); col->not_null = 1; continue; }
        if (lex_kw(&L, "NULL")) { continue; }
        if (lex_kw(&L, "DEFAULT") || lex_kw(&L, "MATERIALIZED") || lex_kw(&L, "ALIAS") || lex_kw(&L, "EPHEMERAL")) {
            const char* kws2[] = {"CODEC", "TTL", "NOT", "NULL"};
            col->default_expr = lex_until_kw(&L, kws2, sizeof(kws2)/sizeof(kws2[0]));
            continue;
        }
        if (lex_kw(&L, "CODEC")) {
            char* body = lex_paren_body(&L);
            if (body) { free(col->codec); col->codec = body; }
            continue;
        }
        if (lex_kw(&L, "TTL")) {
            const char* kws2[] = {"CODEC", "DEFAULT", "NOT", "NULL"};
            col->ttl = lex_until_kw(&L, kws2, sizeof(kws2)/sizeof(kws2[0]));
            continue;
        }
        /* skip unknown token */
        const char* before = lex_cur(&L);
        lex_ident(&L);
        if (lex_cur(&L) == before) { L.pos++; }
    }
    return 0;
}

static qihse_ch_skip_index_type_t skip_index_type_from_str(const char* s) {
    if (!s) return QIHSE_CH_SKIP_NONE;
    if (ch_ieq(s, "minmax")) return QIHSE_CH_SKIP_MINMAX;
    if (ch_ieq(s, "set")) return QIHSE_CH_SKIP_SET;
    if (ch_ieq(s, "bloom_filter")) return QIHSE_CH_SKIP_BLOOM_FILTER;
    if (ch_ieq(s, "ngrambf_v1")) return QIHSE_CH_SKIP_NGRAMBF_V1;
    if (ch_ieq(s, "tokenbf_v1")) return QIHSE_CH_SKIP_TOKENBF_V1;
    return QIHSE_CH_SKIP_NONE;
}

/* Parse a column-list body (between parens) into column defs, recognising
 * INDEX (data-skipping) and PROJECTION entries inline. */
static void parse_table_columns(const char* body, qihse_ch_ast_t* ast) {
    size_t n = 0;
    char** items = split_commas(body, &n);
    for (size_t i = 0; i < n; i++) {
        const char* it = items[i];
        const char* p = skip_ws(it);
        if (match_kw(p, "INDEX")) {
            /* INDEX name expr TYPE type(params) GRANULARITY n */
            const char* q = match_kw(p, "INDEX");
            ch_lex_t L; lex_init(&L, q);
            char* idx_name = lex_ident(&L);
            const char* kws[] = {"TYPE", "GRANULARITY"};
            char* expr = lex_until_kw(&L, kws, 2);
            qihse_ch_skip_index_t si;
            memset(&si, 0, sizeof(si));
            si.name = idx_name;
            si.expr = expr;
            if (lex_kw(&L, "TYPE")) {
                char* tname = lex_ident(&L);
                si.type = skip_index_type_from_str(tname);
                char* params = lex_paren_body(&L);
                si.params = params;
                free(tname);
            }
            /* grow array */
            ast->skip_indices = (qihse_ch_skip_index_t*)realloc(
                ast->skip_indices, (ast->num_skip_indices + 1) * sizeof(qihse_ch_skip_index_t));
            ast->skip_indices[ast->num_skip_indices++] = si;
        } else if (match_kw(p, "PROJECTION")) {
            /* recognised but not stored in detail */
        } else if (match_kw(p, "CONSTRAINT")) {
            /* recognised but not stored */
        } else {
            qihse_ch_column_def_t col;
            memset(&col, 0, sizeof(col));
            if (parse_column_def(it, &col) == 0) {
                ast->columns = (qihse_ch_column_def_t*)realloc(
                    ast->columns, (ast->num_columns + 1) * sizeof(qihse_ch_column_def_t));
                ast->columns[ast->num_columns++] = col;
            }
        }
        free(items[i]);
    }
    free(items);
}

/* parse "ENGINE = Name(args)" or "ENGINE Name(args)" */
static void parse_engine(ch_lex_t* L, qihse_ch_ast_t* ast) {
    lex_kw(L, "=");
    char* ename = lex_ident(L);
    if (!ename) return;
    /* strip any trailing params already attached? lex_ident stops at '(' */
    ast->engine = engine_from_str(ename);
    lex_skip_ws(L);
    if (lex_cur(L)[0] == '(') {
        char* body = lex_paren_body(L);
        if (body) {
            /* trim */
            char* s = body;
            while (*s && isspace((unsigned char)*s)) s++;
            char* e = s + strlen(s);
            while (e > s && isspace((unsigned char)e[-1])) e--;
            *e = '\0';
            ast->engine_args = ch_strdup(s);
            free(body);
        }
    }
    free(ename);
}

/* parse a parenthesised column-name list like (a, b, c) */
static char** parse_col_list_paren(ch_lex_t* L, size_t* out_n) {
    char* body = lex_paren_body(L);
    if (!body) { *out_n = 0; return NULL; }
    char** arr = split_commas(body, out_n);
    free(body);
    return arr;
}

/* Parse the tail of CREATE TABLE after the name (and optional column list):
 * ENGINE, ORDER BY, PARTITION BY, PRIMARY KEY, SAMPLE BY, TTL, SETTINGS. */
static void parse_create_tail(ch_lex_t* L, qihse_ch_ast_t* ast) {
    for (;;) {
        lex_skip_ws(L);
        if (lex_eof(L)) break;
        if (lex_kw(L, "ENGINE")) { parse_engine(L, ast); continue; }
        if (lex_kw(L, "ORDER")) {
            if (lex_kw(L, "BY")) ast->order_by = parse_col_list_paren(L, &ast->num_order_by);
            continue;
        }
        if (lex_kw(L, "PARTITION")) {
            if (lex_kw(L, "BY")) {
                const char* kws[] = {"ORDER", "PRIMARY", "SAMPLE", "TTL", "SETTINGS", "ENGINE"};
                ast->partition_by = lex_until_kw(L, kws, sizeof(kws)/sizeof(kws[0]));
            }
            continue;
        }
        if (lex_kw(L, "PRIMARY")) {
            if (lex_kw(L, "KEY")) ast->primary_key = parse_col_list_paren(L, &ast->num_primary_key);
            continue;
        }
        if (lex_kw(L, "SAMPLE")) {
            if (lex_kw(L, "BY")) {
                const char* kws[] = {"ORDER", "PRIMARY", "PARTITION", "TTL", "SETTINGS", "ENGINE"};
                ast->sample_by = lex_until_kw(L, kws, sizeof(kws)/sizeof(kws[0]));
            }
            continue;
        }
        if (lex_kw(L, "TTL")) {
            const char* kws[] = {"ORDER", "PRIMARY", "SAMPLE", "PARTITION", "SETTINGS", "ENGINE", "DELETE", "WHERE", "TO", "RENAME"};
            ast->ttl = lex_until_kw(L, kws, sizeof(kws)/sizeof(kws[0]));
            continue;
        }
        if (lex_kw(L, "SETTINGS")) {
            const char* kws[] = {"ORDER", "PRIMARY", "SAMPLE", "PARTITION", "TTL", "ENGINE"};
            ast->settings = lex_until_kw(L, kws, sizeof(kws)/sizeof(kws[0]));
            continue;
        }
        /* unknown — advance one token to avoid infinite loop */
        const char* before = lex_cur(L);
        lex_ident(L);
        if (lex_cur(L) == before) L->pos++;
    }
}

static qihse_ch_ast_t* ast_new(qihse_ch_stmt_type_t t) {
    qihse_ch_ast_t* a = (qihse_ch_ast_t*)calloc(1, sizeof(qihse_ch_ast_t));
    if (a) a->stmt_type = t;
    return a;
}

void qihse_ch_ast_free(qihse_ch_ast_t* ast) {
    if (!ast) return;
    free(ast->name); free(ast->database); free(ast->engine_args);
    for (size_t i = 0; i < ast->num_columns; i++) {
        free(ast->columns[i].name); free(ast->columns[i].type_str);
        free(ast->columns[i].default_expr); free(ast->columns[i].codec);
        free(ast->columns[i].ttl);
    }
    free(ast->columns);
    str_list_free(ast->order_by, ast->num_order_by);
    str_list_free(ast->primary_key, ast->num_primary_key);
    free(ast->partition_by); free(ast->sample_by); free(ast->ttl); free(ast->settings);
    for (size_t i = 0; i < ast->num_skip_indices; i++) {
        free(ast->skip_indices[i].name); free(ast->skip_indices[i].expr);
        free(ast->skip_indices[i].params);
    }
    free(ast->skip_indices);
    free(ast->as_source_table); free(ast->as_select_sql);
    free(ast->mv_target_table);
    for (size_t i = 0; i < ast->num_dict_attrs; i++) {
        free(ast->dict_attrs[i].name); free(ast->dict_attrs[i].type_str);
        free(ast->dict_attrs[i].default_expr);
    }
    free(ast->dict_attrs);
    free(ast->dict_source); free(ast->dict_layout); free(ast->dict_lifetime); free(ast->dict_primary_key);
    free(ast->alter_table); free(ast->alter_column); free(ast->alter_new_name);
    if (ast->alter_add_column) {
        free(ast->alter_add_column->name); free(ast->alter_add_column->type_str);
        free(ast->alter_add_column->default_expr); free(ast->alter_add_column->codec);
        free(ast->alter_add_column->ttl); free(ast->alter_add_column);
    }
    free(ast->alter_modify_type_str); free(ast->alter_set_expr); free(ast->alter_where);
    free(ast->alter_index_name);
    free(ast->alter_index.name); free(ast->alter_index.expr); free(ast->alter_index.params);
    free(ast->system_arg); free(ast->show_from); free(ast->show_like);
    free(ast->set_param); free(ast->set_value);
    free(ast->select_sql); free(ast->select_prewhere); free(ast->select_sample);
    str_list_free(ast->array_join_cols, ast->num_array_join);
    free(ast->insert_table);
    str_list_free(ast->insert_columns, ast->num_insert_columns);
    free(ast->insert_format); free(ast->insert_data);
    free(ast->raw_sql);
    free(ast);
}

/* split db.name into db and name */
static void split_qualified(const char* q, char** db, char** name) {
    const char* dot = strchr(q, '.');
    if (dot) {
        *db = ch_strndup(q, (size_t)(dot - q));
        *name = ch_strdup(dot + 1);
    } else {
        *db = NULL;
        *name = ch_strdup(q);
    }
}

/* ---- statement parsers -------------------------------------------------- */

static qihse_ch_ast_t* parse_create(ch_lex_t* L) {
    int if_not_exists = 0;
    if (lex_kw(L, "OR")) lex_kw(L, "REPLACE");  /* CREATE OR REPLACE */
    if (lex_kw(L, "TEMPORARY")) { /* skip */ }
    if (lex_kw(L, "MATERIALIZED")) {
        /* CREATE MATERIALIZED VIEW name [TO target] [POPULATE] AS SELECT */
        if (!lex_kw(L, "VIEW")) return NULL;
        qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_CREATE_MV);
        if (lex_kw(L, "IF")) { lex_kw(L, "NOT"); lex_kw(L, "EXISTS"); a->if_not_exists = 1; }
        char* q = lex_ident(L);
        if (!q) { qihse_ch_ast_free(a); return NULL; }
        split_qualified(q, &a->database, &a->name);
        free(q);
        if (lex_kw(L, "TO")) {
            char* tgt = lex_ident(L);
            a->mv_target_table = tgt;
        }
        if (lex_kw(L, "POPULATE")) a->mv_populate = 1;
        if (lex_kw(L, "AS")) {
            /* capture the SELECT body (rest of input) */
            const char* rest = lex_cur(L);
            a->as_select_sql = ch_strdup(rest);
            a->select_sql = ch_strdup(rest);
        }
        return a;
    }
    if (lex_kw(L, "DICTIONARY")) {
        qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_CREATE_DICT);
        if (lex_kw(L, "IF")) { lex_kw(L, "NOT"); lex_kw(L, "EXISTS"); a->if_not_exists = 1; }
        char* q = lex_ident(L);
        if (!q) { qihse_ch_ast_free(a); return NULL; }
        split_qualified(q, &a->database, &a->name);
        free(q);
        /* (attr TYPE, ...) PRIMARY KEY key SOURCE(...) LAYOUT(...) LIFETIME(...) */
        char* body = lex_paren_body(L);
        if (body) {
            size_t n = 0;
            char** items = split_commas(body, &n);
            for (size_t i = 0; i < n; i++) {
                qihse_ch_dict_attr_t attr;
                memset(&attr, 0, sizeof(attr));
                ch_lex_t cl; lex_init(&cl, items[i]);
                attr.name = lex_ident(&cl);
                const char* kws[] = {"DEFAULT"};
                attr.type_str = lex_until_kw(&cl, kws, 1);
                if (attr.type_str) attr.type = qihse_ch_data_type_from_str(attr.type_str);
                if (attr.name) {
                    a->dict_attrs = (qihse_ch_dict_attr_t*)realloc(a->dict_attrs,
                        (a->num_dict_attrs + 1) * sizeof(qihse_ch_dict_attr_t));
                    a->dict_attrs[a->num_dict_attrs++] = attr;
                }
                free(items[i]);
            }
            free(items);
            free(body);
        }
        for (;;) {
            lex_skip_ws(L);
            if (lex_eof(L)) break;
            if (lex_kw(L, "PRIMARY")) { lex_kw(L, "KEY"); a->dict_primary_key = lex_ident(L); continue; }
            if (lex_kw(L, "SOURCE")) { char* b = lex_paren_body(L); a->dict_source = b; continue; }
            if (lex_kw(L, "LAYOUT")) { char* b = lex_paren_body(L); a->dict_layout = b; continue; }
            if (lex_kw(L, "LIFETIME")) { char* b = lex_paren_body(L); a->dict_lifetime = b; continue; }
            const char* before = lex_cur(L);
            lex_ident(L);
            if (lex_cur(L) == before) L->pos++;
        }
        return a;
    }
    if (!lex_kw(L, "TABLE")) return NULL;
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_CREATE_TABLE);
    if (lex_kw(L, "IF")) { lex_kw(L, "NOT"); lex_kw(L, "EXISTS"); a->if_not_exists = 1; }
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->name);
    free(q);
    /* Optional column list, or AS SELECT, or AS source_table */
    lex_skip_ws(L);
    if (lex_cur(L)[0] == '(') {
        char* body = lex_paren_body(L);
        if (body) { parse_table_columns(body, a); free(body); }
        parse_create_tail(L, a);
    } else if (lex_kw(L, "AS")) {
        if (lex_peek_kw(L, "SELECT") || lex_peek_kw(L, "WITH")) {
            const char* rest = lex_cur(L);
            a->as_select_sql = ch_strdup(rest);
            a->ctas = 1;
            /* still allow ENGINE after? CTAS usually has no ENGINE; ignore tail */
        } else {
            char* src = lex_ident(L);
            a->as_source_table = src;
            parse_create_tail(L, a);
        }
    } else {
        parse_create_tail(L, a);
    }
    return a;
}

static qihse_ch_ast_t* parse_alter(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_ALTER);
    if (!lex_kw(L, "TABLE")) {
        /* ALTER TABLE only supported form */
    }
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->alter_table);
    free(q);
    /* parse one or more actions separated by commas */
    for (;;) {
        lex_skip_ws(L);
        if (lex_eof(L)) break;
        if (lex_kw(L, "ADD")) {
            if (lex_kw(L, "COLUMN")) {
                a->alter_action = QIHSE_CH_ALTER_ADD_COLUMN;
                const char* kws[] = {"AFTER", "BEFORE", "FIRST", "DROP", "MODIFY", "RENAME", "ADD", "MATERIALIZE", "CLEAR", "ATTACH", "DETACH", "FREEZE", "FETCH", "UPDATE", "DELETE"};
                char* def = lex_until_kw(L, kws, sizeof(kws)/sizeof(kws[0]));
                qihse_ch_column_def_t* col = (qihse_ch_column_def_t*)calloc(1, sizeof(qihse_ch_column_def_t));
                if (parse_column_def(def, col) == 0) a->alter_add_column = col;
                else free(col);
                free(def);
            } else if (lex_kw(L, "INDEX")) {
                a->alter_action = QIHSE_CH_ALTER_ADD_INDEX;
                a->alter_index_name = lex_ident(L);
                a->alter_index.expr = lex_ident(L);
                if (lex_kw(L, "TYPE")) {
                    char* tn = lex_ident(L);
                    a->alter_index.type = skip_index_type_from_str(tn);
                    a->alter_index.params = lex_paren_body(L);
                    free(tn);
                }
            } else if (lex_kw(L, "PROJECTION")) {
                a->alter_action = QIHSE_CH_ALTER_ADD_PROJECTION;
                a->alter_index_name = lex_ident(L);
            }
        } else if (lex_kw(L, "DROP")) {
            if (lex_kw(L, "COLUMN")) {
                a->alter_action = QIHSE_CH_ALTER_DROP_COLUMN;
                a->alter_column = lex_ident(L);
            } else if (lex_kw(L, "INDEX")) {
                a->alter_action = QIHSE_CH_ALTER_DROP_INDEX;
                a->alter_index_name = lex_ident(L);
            } else if (lex_kw(L, "PROJECTION")) {
                a->alter_action = QIHSE_CH_ALTER_DROP_PROJECTION;
                a->alter_index_name = lex_ident(L);
            } else if (lex_kw(L, "DETACHED")) {
                lex_kw(L, "PARTITION");
                a->alter_action = QIHSE_CH_ALTER_DROP_DETACHED_PART;
                a->alter_column = lex_ident(L);
            }
        } else if (lex_kw(L, "MODIFY")) {
            if (lex_kw(L, "COLUMN")) {
                a->alter_action = QIHSE_CH_ALTER_MODIFY_COLUMN;
                a->alter_column = lex_ident(L);
                char* ts = lex_ident(L);
                a->alter_modify_type_str = ts;
                a->alter_modify_type = qihse_ch_data_type_from_str(ts);
            }
        } else if (lex_kw(L, "RENAME")) {
            if (lex_kw(L, "COLUMN")) {
                a->alter_action = QIHSE_CH_ALTER_RENAME_COLUMN;
                a->alter_column = lex_ident(L);
                lex_kw(L, "TO");
                a->alter_new_name = lex_ident(L);
            }
        } else if (lex_kw(L, "MATERIALIZE")) {
            if (lex_kw(L, "INDEX")) {
                a->alter_action = QIHSE_CH_ALTER_MATERIALIZE_INDEX;
                a->alter_index_name = lex_ident(L);
            } else if (lex_kw(L, "PROJECTION")) {
                a->alter_action = QIHSE_CH_ALTER_MATERIALIZE_PROJ;
                a->alter_index_name = lex_ident(L);
            }
        } else if (lex_kw(L, "CLEAR")) {
            if (lex_kw(L, "INDEX")) {
                a->alter_action = QIHSE_CH_ALTER_CLEAR_INDEX;
                a->alter_index_name = lex_ident(L);
            }
        } else if (lex_kw(L, "ATTACH")) {
            lex_kw(L, "PARTITION");
            a->alter_action = QIHSE_CH_ALTER_ATTACH_PARTITION;
            a->alter_column = lex_ident(L);
        } else if (lex_kw(L, "DETACH")) {
            lex_kw(L, "PARTITION");
            a->alter_action = QIHSE_CH_ALTER_DETACH_PARTITION;
            a->alter_column = lex_ident(L);
        } else if (lex_kw(L, "FREEZE")) {
            lex_kw(L, "PARTITION");
            a->alter_action = QIHSE_CH_ALTER_FREEZE_PARTITION;
            a->alter_column = lex_ident(L);
        } else if (lex_kw(L, "FETCH")) {
            lex_kw(L, "PARTITION");
            a->alter_action = QIHSE_CH_ALTER_FETCH_PARTITION;
            a->alter_column = lex_ident(L);
        } else if (lex_kw(L, "UPDATE")) {
            a->alter_action = QIHSE_CH_ALTER_UPDATE;
            const char* kws[] = {"WHERE"};
            a->alter_set_expr = lex_until_kw(L, kws, 1);
            if (lex_kw(L, "WHERE")) {
                const char* kws2[] = {"SETTINGS"};
                a->alter_where = lex_until_kw(L, kws2, 1);
            }
        } else if (lex_kw(L, "DELETE")) {
            a->alter_action = QIHSE_CH_ALTER_DELETE;
            if (lex_kw(L, "WHERE")) {
                const char* kws2[] = {"SETTINGS"};
                a->alter_where = lex_until_kw(L, kws2, 1);
            }
        } else {
            const char* before = lex_cur(L);
            lex_ident(L);
            if (lex_cur(L) == before) L->pos++;
        }
        /* comma separates multiple actions; we keep only the last one */
        if (!lex_char(L, ',')) break;
    }
    return a;
}

static qihse_ch_ast_t* parse_optimize(ch_lex_t* L) {
    lex_kw(L, "TABLE");
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_OPTIMIZE);
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->name);
    free(q);
    if (lex_kw(L, "FINAL")) a->optimize_final = 1;
    if (lex_kw(L, "DEDUPLICATE")) a->optimize_deduplicate = 1;
    return a;
}

static qihse_ch_ast_t* parse_truncate(ch_lex_t* L) {
    lex_kw(L, "TABLE");
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_TRUNCATE);
    if (lex_kw(L, "IF")) { lex_kw(L, "EXISTS"); a->if_exists = 1; }
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->name);
    free(q);
    return a;
}

static qihse_ch_ast_t* parse_drop(ch_lex_t* L) {
    lex_kw(L, "TABLE");
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_DROP);
    if (lex_kw(L, "IF")) { lex_kw(L, "EXISTS"); a->if_exists = 1; }
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->name);
    free(q);
    if (lex_kw(L, "SYNC")) a->drop_sync = 1;
    return a;
}

static qihse_ch_ast_t* parse_system(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_SYSTEM);
    if (lex_kw(L, "RELOAD")) {
        if (lex_kw(L, "CONFIG")) a->system_cmd = QIHSE_CH_SYS_RELOAD_CONFIG;
        else if (lex_kw(L, "DICTIONARY")) { a->system_cmd = QIHSE_CH_SYS_RELOAD_DICTIONARY; a->system_arg = lex_ident(L); }
        else if (lex_kw(L, "EMBEDDED") && lex_kw(L, "DICTIONARIES")) a->system_cmd = QIHSE_CH_SYS_RELOAD_EMBEDDED_DICT;
    } else if (lex_kw(L, "FLUSH")) {
        if (lex_kw(L, "LOGS")) a->system_cmd = QIHSE_CH_SYS_FLUSH_LOGS;
        else if (lex_kw(L, "DISTRIBUTED")) a->system_cmd = QIHSE_CH_SYS_FLUSH_DISTRIBUTED;
        else if (lex_kw(L, "CACHE")) a->system_cmd = QIHSE_CH_SYS_FLUSH_CACHE;
    } else if (lex_kw(L, "STOP")) {
        if (lex_kw(L, "MERGES")) a->system_cmd = QIHSE_CH_SYS_STOP_MERGES;
        else if (lex_kw(L, "FETCHES")) a->system_cmd = QIHSE_CH_SYS_STOP_FETCHES;
        else if (lex_kw(L, "REPLICATED") && lex_kw(L, "SENDS")) a->system_cmd = QIHSE_CH_SYS_STOP_REPL_SENDS;
        else if (lex_kw(L, "REPLICATION") && lex_kw(L, "QUEUES")) a->system_cmd = QIHSE_CH_SYS_STOP_REPL_QUEUES;
    } else if (lex_kw(L, "START")) {
        if (lex_kw(L, "MERGES")) a->system_cmd = QIHSE_CH_SYS_START_MERGES;
        else if (lex_kw(L, "FETCHES")) a->system_cmd = QIHSE_CH_SYS_START_FETCHES;
        else if (lex_kw(L, "REPLICATED") && lex_kw(L, "SENDS")) a->system_cmd = QIHSE_CH_SYS_START_REPL_SENDS;
        else if (lex_kw(L, "REPLICATION") && lex_kw(L, "QUEUES")) a->system_cmd = QIHSE_CH_SYS_START_REPL_QUEUES;
    } else if (lex_kw(L, "SYNC")) {
        lex_kw(L, "REPLICA"); a->system_cmd = QIHSE_CH_SYS_SYNC_REPLICA;
    } else if (lex_kw(L, "RESTART")) {
        if (lex_kw(L, "REPLICA")) { a->system_cmd = QIHSE_CH_SYS_RESTART_REPLICA; a->system_arg = lex_ident(L); }
        else if (lex_kw(L, "REPLICAS")) a->system_cmd = QIHSE_CH_SYS_RESTART_REPLICAS;
    } else if (lex_kw(L, "DROP")) {
        if (lex_kw(L, "MARK") && lex_kw(L, "CACHE")) a->system_cmd = QIHSE_CH_SYS_DROP_MARK_CACHE;
        else if (lex_kw(L, "UNCOMPRESSED") && lex_kw(L, "CACHE")) a->system_cmd = QIHSE_CH_SYS_DROP_UNCOMPRESSED_CACHE;
        else if (lex_kw(L, "MMAPPED") && lex_kw(L, "CACHE")) a->system_cmd = QIHSE_CH_SYS_DROP_MMAPPED_CACHE;
        else if (lex_kw(L, "QUERY") && lex_kw(L, "CACHE")) a->system_cmd = QIHSE_CH_SYS_DROP_QUERY_CACHE;
        else if (lex_kw(L, "DNS") && lex_kw(L, "CACHE")) a->system_cmd = QIHSE_CH_SYS_DROP_DNS_CACHE;
        else if (lex_kw(L, "CONCURRENT")) a->system_cmd = QIHSE_CH_SYS_DROP_CONCURRENT;
    }
    return a;
}

static qihse_ch_ast_t* parse_show(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_SHOW);
    if (lex_kw(L, "TABLES")) {
        a->show_kind = QIHSE_CH_SHOW_TABLES;
        if (lex_kw(L, "FROM")) a->show_from = lex_ident(L);
        if (lex_kw(L, "LIKE")) a->show_like = lex_ident(L);
    } else if (lex_kw(L, "DATABASES")) {
        a->show_kind = QIHSE_CH_SHOW_DATABASES;
        if (lex_kw(L, "LIKE")) a->show_like = lex_ident(L);
    } else if (lex_kw(L, "COLUMNS")) {
        lex_kw(L, "FROM");
        a->show_kind = QIHSE_CH_SHOW_COLUMNS;
        a->show_from = lex_ident(L);
        if (lex_kw(L, "FROM")) a->show_like = lex_ident(L);
    } else if (lex_kw(L, "CREATE")) {
        lex_kw(L, "TABLE");
        a->show_kind = QIHSE_CH_SHOW_CREATE;
        a->show_from = lex_ident(L);
    } else if (lex_kw(L, "PROCESSLIST")) {
        a->show_kind = QIHSE_CH_SHOW_PROCESSLIST;
    } else if (lex_kw(L, "SETTINGS")) {
        a->show_kind = QIHSE_CH_SHOW_SETTINGS;
    }
    return a;
}

static qihse_ch_ast_t* parse_describe(ch_lex_t* L) {
    lex_kw(L, "TABLE");
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_DESCRIBE);
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->name);
    free(q);
    return a;
}

static qihse_ch_ast_t* parse_exists(ch_lex_t* L) {
    lex_kw(L, "TABLE");
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_EXISTS);
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->name);
    free(q);
    return a;
}

static qihse_ch_ast_t* parse_use(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_USE);
    a->name = lex_ident(L);
    return a;
}

static qihse_ch_ast_t* parse_set(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_SET);
    a->set_param = lex_ident(L);
    lex_char(L, '=');
    /* value: rest of line */
    lex_skip_ws(L);
    const char* rest = lex_cur(L);
    a->set_value = ch_strdup(rest);
    return a;
}

/* Extract ClickHouse SELECT modifiers (PREWHERE, SAMPLE, FINAL, ARRAY JOIN,
 * WITH TOTALS/CUBE/ROLLUP) from a SELECT body, preserving the raw text. */
static void parse_select_modifiers(const char* sql, qihse_ch_ast_t* a) {
    a->select_sql = ch_strdup(sql);
    /* FINAL */
    if (strcasestr(sql, "FINAL")) a->select_final = 1;
    if (strcasestr(sql, "WITH TOTALS")) a->select_with_totals = 1;
    if (strcasestr(sql, "WITH CUBE")) a->select_with_cube = 1;
    if (strcasestr(sql, "WITH ROLLUP")) a->select_with_rollup = 1;
    /* PREWHERE */
    const char* pw = strcasestr(sql, "PREWHERE");
    if (pw) {
        pw += 8;
        const char* kws[] = {"WHERE", "GROUP", "ORDER", "LIMIT", "HAVING", "ARRAY", "SAMPLE", "SETTINGS", "UNION", "INTERSECT", "EXCEPT"};
        /* find end at top-level keyword */
        const char* end = pw + strlen(pw);
        for (const char* p = pw; *p; p++) {
            for (size_t i = 0; i < sizeof(kws)/sizeof(kws[0]); i++) {
                size_t kl = strlen(kws[i]);
                if (strncasecmp(p, kws[i], kl) == 0) {
                    char after = p[kl];
                    if (!(isalnum((unsigned char)after) || after == '_')) { end = p; goto pw_done; }
                }
            }
        }
        pw_done:
        a->select_prewhere = ch_strndup(pw, (size_t)(end - pw));
    }
    /* SAMPLE */
    const char* sm = strcasestr(sql, "SAMPLE");
    if (sm) {
        sm += 6;
        while (*sm && isspace((unsigned char)*sm)) sm++;
        const char* end = sm;
        while (*end && !isspace((unsigned char)*end)) end++;
        a->select_sample = ch_strndup(sm, (size_t)(end - sm));
    }
    /* ARRAY JOIN */
    const char* aj = strcasestr(sql, "ARRAY JOIN");
    if (aj) {
        aj += 11;
        const char* kws[] = {"WHERE", "PREWHERE", "GROUP", "ORDER", "LIMIT", "HAVING", "SETTINGS"};
        const char* end = aj + strlen(aj);
        for (const char* p = aj; *p; p++) {
            for (size_t i = 0; i < sizeof(kws)/sizeof(kws[0]); i++) {
                size_t kl = strlen(kws[i]);
                if (strncasecmp(p, kws[i], kl) == 0) {
                    char after = p[kl];
                    if (!(isalnum((unsigned char)after) || after == '_')) { end = p; goto aj_done; }
                }
            }
        }
        aj_done:;
        char* cols = ch_strndup(aj, (size_t)(end - aj));
        size_t nc = 0;
        char** list = split_commas(cols, &nc);
        a->array_join_cols = list;
        a->num_array_join = nc;
        free(cols);
    }
}

static qihse_ch_ast_t* parse_select(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_SELECT);
    const char* rest = lex_cur(L);
    parse_select_modifiers(rest, a);
    /* consume to end */
    L->pos = L->len;
    return a;
}

static qihse_ch_ast_t* parse_insert(ch_lex_t* L) {
    qihse_ch_ast_t* a = ast_new(QIHSE_CH_STMT_INSERT);
    lex_kw(L, "INTO");
    /* optional TABLE keyword */
    lex_kw(L, "TABLE");
    char* q = lex_ident(L);
    if (!q) { qihse_ch_ast_free(a); return NULL; }
    split_qualified(q, &a->database, &a->insert_table);
    free(q);
    /* optional (col list) */
    lex_skip_ws(L);
    if (lex_cur(L)[0] == '(') {
        a->insert_columns = parse_col_list_paren(L, &a->num_insert_columns);
    }
    /* VALUES or FORMAT */
    if (lex_kw(L, "VALUES")) {
        a->insert_is_values = 1;
        a->insert_format = ch_strdup("Values");
        /* rest is the values data */
        const char* rest = lex_cur(L);
        a->insert_data = ch_strdup(rest);
        L->pos = L->len;
    } else if (lex_kw(L, "FORMAT")) {
        char* fmt = lex_ident(L);
        a->insert_format = fmt;
        /* rest is data after the format name and newline */
        lex_skip_ws(L);
        const char* rest = lex_cur(L);
        a->insert_data = ch_strdup(rest);
        L->pos = L->len;
    } else {
        /* INSERT ... SELECT or other; capture rest */
        const char* rest = lex_cur(L);
        a->insert_data = ch_strdup(rest);
        L->pos = L->len;
    }
    return a;
}

qihse_ch_ast_t* qihse_ch_parse(const char* sql) {
    if (!sql) return NULL;
    ch_lex_t L;
    lex_init(&L, sql);
    lex_skip_ws(&L);
    /* strip leading semicolons */
    while (lex_char(&L, ';')) lex_skip_ws(&L);
    if (lex_eof(&L)) return NULL;

    qihse_ch_ast_t* ast = NULL;
    if (lex_peek_kw(&L, "CREATE")) {
        lex_kw(&L, "CREATE");
        ast = parse_create(&L);
    } else if (lex_peek_kw(&L, "ALTER")) {
        lex_kw(&L, "ALTER");
        ast = parse_alter(&L);
    } else if (lex_peek_kw(&L, "OPTIMIZE")) {
        lex_kw(&L, "OPTIMIZE");
        ast = parse_optimize(&L);
    } else if (lex_peek_kw(&L, "TRUNCATE")) {
        lex_kw(&L, "TRUNCATE");
        ast = parse_truncate(&L);
    } else if (lex_peek_kw(&L, "DROP")) {
        lex_kw(&L, "DROP");
        ast = parse_drop(&L);
    } else if (lex_peek_kw(&L, "SYSTEM")) {
        lex_kw(&L, "SYSTEM");
        ast = parse_system(&L);
    } else if (lex_peek_kw(&L, "SHOW")) {
        lex_kw(&L, "SHOW");
        ast = parse_show(&L);
    } else if (lex_peek_kw(&L, "DESCRIBE") || lex_peek_kw(&L, "DESC")) {
        if (lex_peek_kw(&L, "DESCRIBE")) lex_kw(&L, "DESCRIBE"); else lex_kw(&L, "DESC");
        ast = parse_describe(&L);
    } else if (lex_peek_kw(&L, "EXISTS")) {
        lex_kw(&L, "EXISTS");
        ast = parse_exists(&L);
    } else if (lex_peek_kw(&L, "USE")) {
        lex_kw(&L, "USE");
        ast = parse_use(&L);
    } else if (lex_peek_kw(&L, "SET")) {
        lex_kw(&L, "SET");
        ast = parse_set(&L);
    } else if (lex_peek_kw(&L, "SELECT") || lex_peek_kw(&L, "WITH")) {
        ast = parse_select(&L);
    } else if (lex_peek_kw(&L, "INSERT")) {
        lex_kw(&L, "INSERT");
        ast = parse_insert(&L);
    } else {
        /* unknown statement — return a minimal SELECT capturing raw text */
        ast = ast_new(QIHSE_CH_STMT_UNKNOWN);
        ast->select_sql = ch_strdup(L.src + L.pos);
    }
    if (ast) ast->raw_sql = ch_strdup(sql);
    return ast;
}

/* =========================================================================
 * Section 6 — MergeTree engine
 *
 * Parts management, sparse primary-key index (granules), partition pruning,
 * data-skipping indices, ORDER BY sorting, TTL expiration, background merge,
 * and mutations (UPDATE/DELETE).
 * ========================================================================= */

#define QIHSE_CH_GRANULE_SIZE 8192   /* rows per granule (sparse index mark) */

qihse_ch_part_t* qihse_ch_part_create(const char* partition_value,
                                      uint64_t rows, int64_t block,
                                      const int64_t* order_keys,
                                      size_t num_keys) {
    qihse_ch_part_t* p = (qihse_ch_part_t*)calloc(1, sizeof(qihse_ch_part_t));
    if (!p) return NULL;
    p->partition_value = ch_strdup(partition_value ? partition_value : "all");
    p->rows = rows;
    p->bytes_on_disk = rows * 16;  /* rough estimate */
    p->active = 1;
    p->min_block = block;
    p->max_block = block;
    p->level = 0;
    p->mutation = 0;
    char nm[64];
    snprintf(nm, sizeof(nm), "%s_%ld_%ld_0",
             p->partition_value ? p->partition_value : "all",
             (long)block, (long)block);
    p->name = ch_strdup(nm);
    if (order_keys && num_keys > 0) {
        p->part_key_min = order_keys[0];
        p->part_key_max = order_keys[num_keys - 1];
        for (size_t i = 0; i < num_keys; i++) {
            if (order_keys[i] < p->part_key_min) p->part_key_min = order_keys[i];
            if (order_keys[i] > p->part_key_max) p->part_key_max = order_keys[i];
        }
        qihse_ch_part_build_index(p, order_keys, num_keys, QIHSE_CH_GRANULE_SIZE);
    } else {
        p->part_key_min = 0;
        p->part_key_max = 0;
        if (rows > 0) {
            qihse_ch_part_build_index(p, NULL, 0, QIHSE_CH_GRANULE_SIZE);
        }
    }
    return p;
}

void qihse_ch_part_free(qihse_ch_part_t* p) {
    if (!p) return;
    free(p->name);
    free(p->partition_value);
    free(p->granules);
    free(p);
}

void qihse_ch_part_build_index(qihse_ch_part_t* p, const int64_t* keys,
                               size_t n, uint32_t granule_size) {
    if (!p) return;
    if (granule_size == 0) granule_size = QIHSE_CH_GRANULE_SIZE;
    size_t num_gran = (n + granule_size - 1) / granule_size;
    if (num_gran == 0 && n == 0) num_gran = 1;  /* at least one mark */
    free(p->granules);
    p->granules = (qihse_ch_granule_t*)calloc(num_gran, sizeof(qihse_ch_granule_t));
    p->num_granules = num_gran;
    for (size_t g = 0; g < num_gran; g++) {
        size_t start = g * granule_size;
        size_t end = start + granule_size;
        if (end > n) end = n;
        p->granules[g].mark_index = (int64_t)g;
        p->granules[g].rows_in_granule = (uint32_t)(end - start);
        if (keys && end > start) {
            int64_t mn = keys[start], mx = keys[start];
            for (size_t i = start; i < end; i++) {
                if (keys[i] < mn) mn = keys[i];
                if (keys[i] > mx) mx = keys[i];
            }
            p->granules[g].key_min = mn;
            p->granules[g].key_max = mx;
        }
    }
}

void qihse_ch_table_add_part(qihse_ch_table_t* tbl, qihse_ch_part_t* p) {
    if (!tbl || !p) return;
    pthread_mutex_lock(&tbl->lock);
    p->next = tbl->parts;
    tbl->parts = p;
    pthread_mutex_unlock(&tbl->lock);
}

/* Partition pruning: keep parts whose partition_value matches the condition.
 * The condition is a simple equality like "toYYYYMM(date) = 20230801" or a
 * literal partition id.  We do a best-effort match on the partition value
 * string.  If the condition is NULL/empty, all active parts are returned. */
qihse_ch_part_t** qihse_ch_partition_prune(qihse_ch_table_t* tbl,
                                           const char* partition_cond,
                                           size_t* out_count) {
    *out_count = 0;
    if (!tbl) return NULL;
    pthread_mutex_lock(&tbl->lock);
    /* count active parts */
    size_t total = 0;
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) if (p->active) total++;
    qihse_ch_part_t** arr = (qihse_ch_part_t**)malloc((total + 1) * sizeof(qihse_ch_part_t*));
    size_t n = 0;
    const char* cond = partition_cond;
    if (!cond || !*cond) cond = NULL;
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) {
        if (!p->active) continue;
        if (!cond) { arr[n++] = p; continue; }
        /* match if partition_value appears in cond, or cond's numeric tail
         * equals partition_value */
        if (strstr(cond, p->partition_value) || ch_ieq(cond, p->partition_value)) {
            arr[n++] = p;
        }
    }
    pthread_mutex_unlock(&tbl->lock);
    *out_count = n;
    return arr;
}

/* Background merge: pick the smallest set of adjacent active parts (by block
 * number) and merge them into a single part.  Returns 1 if a merge happened. */
int qihse_ch_merge_parts(qihse_ch_table_t* tbl) {
    if (!tbl) return 0;
    pthread_mutex_lock(&tbl->lock);
    /* collect active parts sorted by min_block */
    size_t n = 0;
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) if (p->active) n++;
    if (n < 2) { pthread_mutex_unlock(&tbl->lock); return 0; }
    qihse_ch_part_t** arr = (qihse_ch_part_t**)malloc(n * sizeof(qihse_ch_part_t*));
    size_t k = 0;
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) if (p->active) arr[k++] = p;
    /* simple insertion sort by min_block */
    for (size_t i = 1; i < n; i++) {
        qihse_ch_part_t* v = arr[i]; size_t j = i;
        while (j > 0 && arr[j-1]->min_block > v->min_block) { arr[j] = arr[j-1]; j--; }
        arr[j] = v;
    }
    /* merge the two smallest adjacent parts */
    qihse_ch_part_t* a = arr[0];
    qihse_ch_part_t* b = arr[1];
    uint64_t merged_rows = a->rows + b->rows;
    int64_t merged_min = a->min_block < b->min_block ? a->min_block : b->min_block;
    int64_t merged_max = a->max_block > b->max_block ? a->max_block : b->max_block;
    int64_t merged_level = (a->level > b->level ? a->level : b->level) + 1;
    /* build merged key range */
    int64_t kmin = a->part_key_min < b->part_key_min ? a->part_key_min : b->part_key_min;
    int64_t kmax = a->part_key_max > b->part_key_max ? a->part_key_max : b->part_key_max;
    /* mark old parts inactive */
    a->active = 0; b->active = 0;
    qihse_ch_part_t* mp = (qihse_ch_part_t*)calloc(1, sizeof(qihse_ch_part_t));
    mp->partition_value = ch_strdup(a->partition_value);
    mp->rows = merged_rows;
    mp->bytes_on_disk = a->bytes_on_disk + b->bytes_on_disk;
    mp->active = 1;
    mp->min_block = merged_min;
    mp->max_block = merged_max;
    mp->level = merged_level;
    mp->mutation = a->mutation > b->mutation ? a->mutation : b->mutation;
    mp->part_key_min = kmin;
    mp->part_key_max = kmax;
    char nm[64];
    snprintf(nm, sizeof(nm), "%s_%ld_%ld_%ld", mp->partition_value,
             (long)merged_min, (long)merged_max, (long)merged_level);
    mp->name = ch_strdup(nm);
    /* rebuild granules as a single mark for the merged range */
    mp->granules = (qihse_ch_granule_t*)calloc(1, sizeof(qihse_ch_granule_t));
    mp->num_granules = 1;
    mp->granules[0].mark_index = 0;
    mp->granules[0].rows_in_granule = (uint32_t)merged_rows;
    mp->granules[0].key_min = kmin;
    mp->granules[0].key_max = kmax;
    mp->next = tbl->parts;
    tbl->parts = mp;
    free(arr);
    pthread_mutex_unlock(&tbl->lock);
    return 1;
}

/* TTL expiration: drop (mark inactive) parts whose partition value, when
 * interpreted as a unix timestamp, is older than now.  Returns count dropped. */
int qihse_ch_ttl_expire(qihse_ch_table_t* tbl, int64_t now_unix) {
    if (!tbl) return 0;
    int dropped = 0;
    pthread_mutex_lock(&tbl->lock);
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) {
        if (!p->active) continue;
        /* interpret partition_value as a date (YYYYMMDD) -> unix ts at day start */
        int64_t pv = 0;
        if (p->partition_value) {
            pv = strtoll(p->partition_value, NULL, 10);
        }
        if (pv > 10000000) {  /* looks like YYYYMMDD */
            /* convert to approximate unix timestamp (days since epoch) */
            int64_t y = pv / 10000, m = (pv / 100) % 100, d = pv % 100;
            /* rough days-since-epoch */
            int64_t days = (y - 1970) * 365 + (m - 1) * 30 + (d - 1);
            int64_t ts = days * 86400;
            if (ts < now_unix) { p->active = 0; dropped++; }
        }
    }
    pthread_mutex_unlock(&tbl->lock);
    return dropped;
}

/* Mutation: apply UPDATE/DELETE to all active parts by bumping the mutation
 * version and (for DELETE) marking matching parts inactive.  This is a
 * simplified in-place mutation; a real implementation would rewrite parts. */
int qihse_ch_mutate(qihse_ch_table_t* tbl, qihse_ch_alter_action_t action,
                    const char* set_expr, const char* where_expr) {
    if (!tbl) return 0;
    (void)set_expr;
    pthread_mutex_lock(&tbl->lock);
    int64_t mut = 0;
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) {
        if (p->active && p->mutation > mut) mut = p->mutation;
    }
    mut++;
    int affected = 0;
    for (qihse_ch_part_t* p = tbl->parts; p; p = p->next) {
        if (!p->active) continue;
        p->mutation = mut;
        affected++;
        if (action == QIHSE_CH_ALTER_DELETE) {
            /* without a real predicate evaluator we drop parts that match the
             * where expression heuristically (empty WHERE = truncate all) */
            if (!where_expr || !*where_expr) { p->active = 0; }
        }
    }
    pthread_mutex_unlock(&tbl->lock);
    return affected;
}

/* =========================================================================
 * Section 7 — Materialized views
 * ========================================================================= */

/* Infer the source table from a SELECT's FROM clause. */
static char* infer_source_table(const char* select_sql) {
    if (!select_sql) return NULL;
    const char* from = strcasestr(select_sql, "FROM ");
    if (!from) from = strcasestr(select_sql, "from\t");
    if (!from) return NULL;
    from += 4;
    while (*from && isspace((unsigned char)*from)) from++;
    const char* start = from;
    while (*from && (is_ident_char(*from) || *from == '.')) from++;
    if (from == start) return NULL;
    return ch_strndup(start, (size_t)(from - start));
}

static int catalog_add_mv(qihse_ch_catalog_t* cat, qihse_ch_mv_t* m) {
    pthread_mutex_lock(&cat->lock);
    m->next = cat->mvs;
    cat->mvs = m;
    pthread_mutex_unlock(&cat->lock);
    return 0;
}

static qihse_ch_mv_t* mv_create_from_ast(const qihse_ch_ast_t* ast, const char* db) {
    qihse_ch_mv_t* m = (qihse_ch_mv_t*)calloc(1, sizeof(qihse_ch_mv_t));
    if (!m) return NULL;
    m->name = ch_strdup(ast->name);
    m->database = ch_strdup(db ? db : "default");
    m->target_table = ch_strdup(ast->mv_target_table);
    m->populate = ast->mv_populate;
    m->select_sql = ch_strdup(ast->as_select_sql);
    m->source_table = infer_source_table(ast->as_select_sql);
    /* aggregate if SELECT contains groupArray/sum/quantile/etc. with GROUP BY */
    if (m->select_sql && strcasestr(m->select_sql, "GROUP BY")) m->is_aggregate = 1;
    return m;
}

int qihse_ch_mv_populate(qihse_ch_catalog_t* cat,
                         qihse_column_store_t* store,
                         qihse_ch_mv_t* mv,
                         qihse_user_t* user) {
    (void)cat; (void)store; (void)user;
    if (!mv) return -1;
    /* Backfill: re-run the SELECT against the source and insert into the
     * target.  In this skeleton we mark the MV as populated. */
    mv->populate = 0;
    return 0;
}

int qihse_ch_mv_trigger(qihse_ch_catalog_t* cat,
                        qihse_column_store_t* store,
                        const char* source_table,
                        qihse_user_t* user) {
    (void)store; (void)user;
    if (!cat || !source_table) return 0;
    int triggered = 0;
    pthread_mutex_lock(&cat->lock);
    for (qihse_ch_mv_t* m = cat->mvs; m; m = m->next) {
        if (m->source_table && ch_ieq(m->source_table, source_table)) {
            /* In a full implementation we would evaluate m->select_sql over
             * the new rows and insert into m->target_table / m->table.
             * Here we record the trigger. */
            triggered++;
        }
    }
    pthread_mutex_unlock(&cat->lock);
    return triggered;
}

/* =========================================================================
 * Section 8 — Dictionaries
 * ========================================================================= */

static int catalog_add_dict(qihse_ch_catalog_t* cat, qihse_ch_dictionary_t* d) {
    pthread_mutex_lock(&cat->lock);
    d->next = cat->dictionaries;
    cat->dictionaries = d;
    pthread_mutex_unlock(&cat->lock);
    return 0;
}

static qihse_ch_dictionary_t* dict_create_from_ast(const qihse_ch_ast_t* ast, const char* db) {
    qihse_ch_dictionary_t* d = (qihse_ch_dictionary_t*)calloc(1, sizeof(qihse_ch_dictionary_t));
    if (!d) return NULL;
    d->name = ch_strdup(ast->name);
    d->database = ch_strdup(db ? db : "default");
    d->source = ch_strdup(ast->dict_source);
    d->layout = ch_strdup(ast->dict_layout);
    d->lifetime = ch_strdup(ast->dict_lifetime);
    d->primary_key = ch_strdup(ast->dict_primary_key);
    if (ast->num_dict_attrs > 0) {
        d->attrs = (qihse_ch_dict_attr_t*)calloc(ast->num_dict_attrs, sizeof(qihse_ch_dict_attr_t));
        d->num_attrs = ast->num_dict_attrs;
        for (size_t i = 0; i < ast->num_dict_attrs; i++) {
            d->attrs[i].name = ch_strdup(ast->dict_attrs[i].name);
            d->attrs[i].type = ast->dict_attrs[i].type;
            d->attrs[i].type_str = ch_strdup(ast->dict_attrs[i].type_str);
            d->attrs[i].default_expr = ch_strdup(ast->dict_attrs[i].default_expr);
        }
    }
    /* parse LIFETIME(MIN 0 MAX 300) -> lifetime_min_ms */
    if (d->lifetime) {
        const char* minp = strcasestr(d->lifetime, "MIN");
        if (minp) d->lifetime_min_ms = (int64_t)(atoll(minp + 3) * 1000);
        else d->lifetime_min_ms = (int64_t)(atoll(d->lifetime) * 1000);
    }
    return d;
}

void qihse_ch_dict_invalidate(qihse_ch_dictionary_t* d) {
    if (!d) return;
    for (size_t i = 0; i < d->cache_count; i++) { free(d->cache_keys[i]); free(d->cache_vals[i]); }
    free(d->cache_keys); free(d->cache_vals);
    d->cache_keys = NULL; d->cache_vals = NULL;
    d->cache_count = 0; d->cache_cap = 0;
    d->last_load_ms = 0;
}

static void dict_cache_put(qihse_ch_dictionary_t* d, const char* key, const char* val) {
    if (!d || !key) return;
    for (size_t i = 0; i < d->cache_count; i++) {
        if (ch_ieq(d->cache_keys[i], key)) {
            free(d->cache_vals[i]);
            d->cache_vals[i] = ch_strdup(val);
            return;
        }
    }
    if (d->cache_count >= d->cache_cap) {
        d->cache_cap = d->cache_cap ? d->cache_cap * 2 : 16;
        d->cache_keys = (char**)realloc(d->cache_keys, d->cache_cap * sizeof(char*));
        d->cache_vals = (char**)realloc(d->cache_vals, d->cache_cap * sizeof(char*));
    }
    d->cache_keys[d->cache_count] = ch_strdup(key);
    d->cache_vals[d->cache_count] = ch_strdup(val);
    d->cache_count++;
}

const char* qihse_ch_dict_get(qihse_ch_catalog_t* cat, const char* dict,
                              const char* attr, const char* key) {
    (void)attr;
    if (!cat || !dict || !key) return NULL;
    qihse_ch_dictionary_t* d = qihse_ch_catalog_find_dict(cat, NULL, dict);
    if (!d) return NULL;
    /* cache lookup */
    for (size_t i = 0; i < d->cache_count; i++) {
        if (ch_ieq(d->cache_keys[i], key)) return d->cache_vals[i];
    }
    /* not found — external source not loaded in skeleton; return NULL */
    return NULL;
}

int qihse_ch_dict_has(qihse_ch_catalog_t* cat, const char* dict, const char* key) {
    if (!cat || !dict || !key) return 0;
    qihse_ch_dictionary_t* d = qihse_ch_catalog_find_dict(cat, NULL, dict);
    if (!d) return 0;
    for (size_t i = 0; i < d->cache_count; i++) {
        if (ch_ieq(d->cache_keys[i], key)) return 1;
    }
    return 0;
}

/* =========================================================================
 * Section 9 — Distributed tables
 * ========================================================================= */

int qihse_ch_distributed_route(qihse_ch_table_t* tbl, const char* sharding_key_val,
                               int* out_shard, int num_shards) {
    if (!tbl || !out_shard || num_shards <= 0) return 0;
    if (tbl->engine != QIHSE_CH_ENGINE_DISTRIBUTED || !tbl->distributed) {
        *out_shard = 0;
        return 1;
    }
    /* hash the sharding key value onto [0, num_shards) */
    uint64_t h = 0;
    if (sharding_key_val) {
        for (const char* p = sharding_key_val; *p; p++) {
            h = h * 131 + (uint64_t)(unsigned char)*p;
        }
    }
    *out_shard = (int)(h % (uint64_t)num_shards);
    return num_shards;
}

/* =========================================================================
 * Section 10 — Result formatters
 * ========================================================================= */

static void cell_to_str(const qihse_ch_cell_t* c, ch_buf_t* b) {
    switch (c->kind) {
        case QIHSE_CH_CELL_NULL:  buf_puts(b, "\\N"); break;
        case QIHSE_CH_CELL_INT:   buf_printf(b, "%lld", (long long)c->i64); break;
        case QIHSE_CH_CELL_UINT:  buf_printf(b, "%llu", (unsigned long long)c->i64); break;
        case QIHSE_CH_CELL_FLOAT: buf_printf(b, "%.9g", c->f64); break;
        case QIHSE_CH_CELL_STR:   buf_puts(b, c->str ? c->str : ""); break;
    }
}

static void cell_to_csv(const qihse_ch_cell_t* c, ch_buf_t* b) {
    if (c->kind == QIHSE_CH_CELL_NULL) { buf_puts(b, "\\N"); return; }
    if (c->kind == QIHSE_CH_CELL_STR) {
        buf_puts(b, "\"");
        if (c->str) {
            for (const char* p = c->str; *p; p++) {
                if (*p == '"') buf_puts(b, "\"\"");
                else { char ch[2] = {*p, 0}; buf_puts(b, ch); }
            }
        }
        buf_puts(b, "\"");
    } else {
        cell_to_str(c, b);
    }
}

static void cell_to_json(const qihse_ch_cell_t* c, ch_buf_t* b) {
    switch (c->kind) {
        case QIHSE_CH_CELL_NULL:  buf_puts(b, "null"); break;
        case QIHSE_CH_CELL_INT:   buf_printf(b, "%lld", (long long)c->i64); break;
        case QIHSE_CH_CELL_UINT:  buf_printf(b, "%llu", (unsigned long long)c->i64); break;
        case QIHSE_CH_CELL_FLOAT: buf_printf(b, "%.9g", c->f64); break;
        case QIHSE_CH_CELL_STR:
            buf_puts(b, "\"");
            if (c->str) {
                for (const char* p = c->str; *p; p++) {
                    switch (*p) {
                        case '"': buf_puts(b, "\\\""); break;
                        case '\\': buf_puts(b, "\\\\"); break;
                        case '\n': buf_puts(b, "\\n"); break;
                        case '\r': buf_puts(b, "\\r"); break;
                        case '\t': buf_puts(b, "\\t"); break;
                        default:
                            if ((unsigned char)*p < 32) buf_printf(b, "\\u%04x", (unsigned)*p);
                            else { char ch[2] = {*p, 0}; buf_puts(b, ch); }
                    }
                }
            }
            buf_puts(b, "\"");
            break;
    }
}

char* qihse_ch_format_tsv(const qihse_ch_result_t* r, int with_names, int with_types) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_puts(&b, r->error); buf_puts(&b, "\n"); return b.data; }
    if (with_names) {
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, "\t");
            buf_puts(&b, r->column_names[j] ? r->column_names[j] : "");
        }
        buf_puts(&b, "\n");
    }
    if (with_types) {
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, "\t");
            buf_puts(&b, r->column_type_names[j] ? r->column_type_names[j] : "String");
        }
        buf_puts(&b, "\n");
    }
    for (size_t i = 0; i < r->num_rows; i++) {
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, "\t");
            cell_to_str(&r->rows[i][j], &b);
        }
        buf_puts(&b, "\n");
    }
    return b.data;
}

char* qihse_ch_format_csv(const qihse_ch_result_t* r, int with_names) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_puts(&b, r->error); buf_puts(&b, "\n"); return b.data; }
    if (with_names) {
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, ",");
            buf_puts(&b, "\"");
            buf_puts(&b, r->column_names[j] ? r->column_names[j] : "");
            buf_puts(&b, "\"");
        }
        buf_puts(&b, "\n");
    }
    for (size_t i = 0; i < r->num_rows; i++) {
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, ",");
            cell_to_csv(&r->rows[i][j], &b);
        }
        buf_puts(&b, "\n");
    }
    return b.data;
}

char* qihse_ch_format_json(const qihse_ch_result_t* r) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) {
        buf_printf(&b, "{\"exception\":{\"code\":999,\"text\":\"%s\"}}", r->error);
        return b.data;
    }
    buf_puts(&b, "{\"meta\":{");
    buf_printf(&b, "\"columns\":[");
    for (size_t j = 0; j < r->num_columns; j++) {
        if (j) buf_puts(&b, ",");
        buf_printf(&b, "{\"name\":\"%s\",\"type\":\"%s\"}",
                   r->column_names[j] ? r->column_names[j] : "",
                   r->column_type_names[j] ? r->column_type_names[j] : "String");
    }
    buf_puts(&b, "]},\"data\":[");
    for (size_t i = 0; i < r->num_rows; i++) {
        if (i) buf_puts(&b, ",");
        buf_puts(&b, "{");
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, ",");
            buf_printf(&b, "\"%s\":", r->column_names[j] ? r->column_names[j] : "");
            cell_to_json(&r->rows[i][j], &b);
        }
        buf_puts(&b, "}");
    }
    buf_printf(&b, "],\"rows\":%zu,\"statistics\":{\"elapsed\":0.0001}}", r->num_rows);
    return b.data;
}

char* qihse_ch_format_json_each_row(const qihse_ch_result_t* r) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_printf(&b, "{\"exception\":\"%s\"}\n", r->error); return b.data; }
    for (size_t i = 0; i < r->num_rows; i++) {
        buf_puts(&b, "{");
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, ",");
            buf_printf(&b, "\"%s\":", r->column_names[j] ? r->column_names[j] : "");
            cell_to_json(&r->rows[i][j], &b);
        }
        buf_puts(&b, "}\n");
    }
    return b.data;
}

char* qihse_ch_format_pretty(const qihse_ch_result_t* r, int compact) {
    (void)compact;
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_puts(&b, r->error); buf_puts(&b, "\n"); return b.data; }
    /* compute column widths */
    size_t* w = (size_t*)calloc(r->num_columns, sizeof(size_t));
    for (size_t j = 0; j < r->num_columns; j++) {
        w[j] = r->column_names[j] ? strlen(r->column_names[j]) : 0;
    }
    for (size_t i = 0; i < r->num_rows; i++) {
        for (size_t j = 0; j < r->num_columns; j++) {
            ch_buf_t tmp; buf_init(&tmp);
            cell_to_str(&r->rows[i][j], &tmp);
            if (tmp.len > w[j]) w[j] = tmp.len;
            buf_free(&tmp);
        }
    }
    /* header */
    buf_puts(&b, "┏");
    for (size_t j = 0; j < r->num_columns; j++) {
        for (size_t k = 0; k < w[j] + 2; k++) buf_puts(&b, "━");
        buf_puts(&b, j + 1 < r->num_columns ? "┳" : "┓\n");
    }
    buf_puts(&b, "┃");
    for (size_t j = 0; j < r->num_columns; j++) {
        buf_printf(&b, " %-*s ", (int)w[j], r->column_names[j] ? r->column_names[j] : "");
        buf_puts(&b, j + 1 < r->num_columns ? "┃" : "┃\n");
    }
    buf_puts(&b, "┡");
    for (size_t j = 0; j < r->num_columns; j++) {
        for (size_t k = 0; k < w[j] + 2; k++) buf_puts(&b, "━");
        buf_puts(&b, j + 1 < r->num_columns ? "╇" : "┩\n");
    }
    for (size_t i = 0; i < r->num_rows; i++) {
        buf_puts(&b, "│");
        for (size_t j = 0; j < r->num_columns; j++) {
            ch_buf_t tmp; buf_init(&tmp);
            cell_to_str(&r->rows[i][j], &tmp);
            buf_printf(&b, " %-*s ", (int)w[j], tmp.data ? tmp.data : "");
            buf_free(&tmp);
            buf_puts(&b, j + 1 < r->num_columns ? "│" : "│\n");
        }
    }
    buf_puts(&b, "└");
    for (size_t j = 0; j < r->num_columns; j++) {
        for (size_t k = 0; k < w[j] + 2; k++) buf_puts(&b, "─");
        buf_puts(&b, j + 1 < r->num_columns ? "┴" : "┘\n");
    }
    free(w);
    return b.data;
}

char* qihse_ch_format_vertical(const qihse_ch_result_t* r) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_puts(&b, r->error); buf_puts(&b, "\n"); return b.data; }
    for (size_t i = 0; i < r->num_rows; i++) {
        buf_printf(&b, "Row %zu:\n", i + 1);
        buf_puts(&b, "──────\n");
        for (size_t j = 0; j < r->num_columns; j++) {
            buf_printf(&b, "%s: ", r->column_names[j] ? r->column_names[j] : "");
            cell_to_str(&r->rows[i][j], &b);
            buf_puts(&b, "\n");
        }
        buf_puts(&b, "\n");
    }
    return b.data;
}

char* qihse_ch_format_values(const qihse_ch_result_t* r) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_puts(&b, r->error); return b.data; }
    for (size_t i = 0; i < r->num_rows; i++) {
        if (i) buf_puts(&b, ",");
        buf_puts(&b, "(");
        for (size_t j = 0; j < r->num_columns; j++) {
            if (j) buf_puts(&b, ",");
            if (r->rows[i][j].kind == QIHSE_CH_CELL_STR) {
                buf_puts(&b, "'");
                if (r->rows[i][j].str) {
                    for (const char* p = r->rows[i][j].str; *p; p++) {
                        if (*p == '\'') buf_puts(&b, "\\'");
                        else { char ch[2] = {*p, 0}; buf_puts(&b, ch); }
                    }
                }
                buf_puts(&b, "'");
            } else {
                cell_to_str(&r->rows[i][j], &b);
            }
        }
        buf_puts(&b, ")");
    }
    return b.data;
}

char* qihse_ch_format_xml(const qihse_ch_result_t* r) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    buf_puts(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<result>\n  <meta>\n");
    for (size_t j = 0; j < r->num_columns; j++) {
        buf_printf(&b, "    <column><name>%s</name><type>%s</type></column>\n",
                   r->column_names[j] ? r->column_names[j] : "",
                   r->column_type_names[j] ? r->column_type_names[j] : "String");
    }
    buf_puts(&b, "  </meta>\n  <data>\n");
    for (size_t i = 0; i < r->num_rows; i++) {
        buf_puts(&b, "    <row>\n");
        for (size_t j = 0; j < r->num_columns; j++) {
            buf_printf(&b, "      <%s>", r->column_names[j] ? r->column_names[j] : "field");
            if (r->rows[i][j].kind == QIHSE_CH_CELL_STR) {
                if (r->rows[i][j].str) buf_puts(&b, r->rows[i][j].str);
            } else {
                cell_to_str(&r->rows[i][j], &b);
            }
            buf_printf(&b, "</%s>\n", r->column_names[j] ? r->column_names[j] : "field");
        }
        buf_puts(&b, "    </row>\n");
    }
    buf_puts(&b, "  </data>\n</result>\n");
    return b.data;
}

char* qihse_ch_format_markdown(const qihse_ch_result_t* r) {
    ch_buf_t b; buf_init(&b);
    if (!r) return b.data;
    if (r->error) { buf_puts(&b, r->error); return b.data; }
    /* header */
    buf_puts(&b, "|");
    for (size_t j = 0; j < r->num_columns; j++)
        buf_printf(&b, " %s |", r->column_names[j] ? r->column_names[j] : "");
    buf_puts(&b, "\n|");
    for (size_t j = 0; j < r->num_columns; j++) buf_puts(&b, "---|");
    buf_puts(&b, "\n");
    for (size_t i = 0; i < r->num_rows; i++) {
        buf_puts(&b, "|");
        for (size_t j = 0; j < r->num_columns; j++) {
            buf_puts(&b, " ");
            cell_to_str(&r->rows[i][j], &b);
            buf_puts(&b, " |");
        }
        buf_puts(&b, "\n");
    }
    return b.data;
}

char* qihse_ch_format_result(const qihse_ch_result_t* r, qihse_ch_format_t fmt) {
    if (!r) return ch_strdup("");
    if (r->error && fmt != QIHSE_CH_FMT_JSON && fmt != QIHSE_CH_FMT_JSON_EACH_ROW) {
        return ch_strdup(r->error);
    }
    switch (fmt) {
        case QIHSE_CH_FMT_TABSEPARATED:
        case QIHSE_CH_FMT_TSV:
            return qihse_ch_format_tsv(r, 0, 0);
        case QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES:
        case QIHSE_CH_FMT_TSV_WITH_NAMES:
            return qihse_ch_format_tsv(r, 1, 0);
        case QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES_AND_TYPES:
            return qihse_ch_format_tsv(r, 1, 1);
        case QIHSE_CH_FMT_CSV:
            return qihse_ch_format_csv(r, 0);
        case QIHSE_CH_FMT_CSV_WITH_NAMES:
            return qihse_ch_format_csv(r, 1);
        case QIHSE_CH_FMT_JSON:
        case QIHSE_CH_FMT_JSON_COMPACT:
            return qihse_ch_format_json(r);
        case QIHSE_CH_FMT_JSON_EACH_ROW:
        case QIHSE_CH_FMT_JSON_COMPACT_EACH_ROW:
            return qihse_ch_format_json_each_row(r);
        case QIHSE_CH_FMT_VALUES:
            return qihse_ch_format_values(r);
        case QIHSE_CH_FMT_VERTICAL:
            return qihse_ch_format_vertical(r);
        case QIHSE_CH_FMT_PRETTY:
            return qihse_ch_format_pretty(r, 0);
        case QIHSE_CH_FMT_PRETTY_COMPACT:
        case QIHSE_CH_FMT_PRETTY_COMPACT_NOESC:
            return qihse_ch_format_pretty(r, 1);
        case QIHSE_CH_FMT_XML:
            return qihse_ch_format_xml(r);
        case QIHSE_CH_FMT_MARKDOWN:
            return qihse_ch_format_markdown(r);
        case QIHSE_CH_FMT_RAW:
            if (r->num_rows > 0 && r->rows[0][0].kind == QIHSE_CH_CELL_STR)
                return ch_strdup(r->rows[0][0].str ? r->rows[0][0].str : "");
            return ch_strdup("");
        case QIHSE_CH_FMT_NULL:
            return ch_strdup("");
        default:
            return qihse_ch_format_tsv(r, 0, 0);
    }
}

/* =========================================================================
 * Section 11 — INSERT data parsing
 * ========================================================================= */

/* Parse a VALUES body: (v1,'v2',...),(v1,'v2',...) into a result set. */
static qihse_ch_result_t* parse_values_body(const char* data, const qihse_ch_table_t* table) {
    size_t ncols = table ? table->num_columns : 0;
    qihse_ch_result_t* r = qihse_ch_result_create(ncols);
    if (table) {
        for (size_t j = 0; j < ncols; j++) {
            r->column_names[j] = ch_strdup(table->columns[j].name);
            r->column_types[j] = table->columns[j].type;
            r->column_type_names[j] = ch_strdup(table->columns[j].type_str);
        }
    }
    const char* p = data;
    size_t row = 0;
    for (;;) {
        p = skip_ws(p);
        if (*p != '(') break;
        p++;
        size_t col = 0;
        for (;;) {
            p = skip_ws(p);
            if (*p == ')' || *p == '\0') break;
            /* read a value: string or number */
            if (*p == '\'') {
                p++;
                const char* start = p;
                while (*p && *p != '\'') { if (*p == '\\') p++; p++; }
                char* val = ch_strndup(start, (size_t)(p - start));
                if (*p == '\'') p++;
                if (col < ncols || ncols == 0)
                    qihse_ch_result_set_str(r, row, col, val);
                free(val);
            } else {
                const char* start = p;
                while (*p && *p != ',' && *p != ')' && !isspace((unsigned char)*p)) p++;
                char* val = ch_strndup(start, (size_t)(p - start));
                if (col < ncols || ncols == 0) {
                    /* numeric? */
                    if (val[0] && (isdigit((unsigned char)val[0]) || val[0] == '-'))
                        qihse_ch_result_set_int(r, row, col, strtoll(val, NULL, 10));
                    else
                        qihse_ch_result_set_str(r, row, col, val);
                }
                free(val);
            }
            col++;
            p = skip_ws(p);
            if (*p == ',') p++;
        }
        if (*p == ')') p++;
        row++;
        p = skip_ws(p);
        if (*p == ',') p++;
        else break;
    }
    return r;
}

/* Parse TSV/CSV row data into a result set. */
static qihse_ch_result_t* parse_delimited(const char* data, char delim,
                                          int csv, const qihse_ch_table_t* table) {
    size_t ncols = table ? table->num_columns : 0;
    qihse_ch_result_t* r = qihse_ch_result_create(ncols);
    if (table) {
        for (size_t j = 0; j < ncols; j++) {
            r->column_names[j] = ch_strdup(table->columns[j].name);
            r->column_types[j] = table->columns[j].type;
            r->column_type_names[j] = ch_strdup(table->columns[j].type_str);
        }
    }
    const char* line = data;
    size_t row = 0;
    while (*line) {
        const char* eol = line;
        while (*eol && *eol != '\n') eol++;
        const char* next = (*eol == '\n') ? eol + 1 : eol;
        if (eol > line) {
            const char* p = line;
            size_t col = 0;
            while (p < eol) {
                const char* start = p;
                if (csv && *p == '"') {
                    p++; start = p;
                    ch_buf_t tmp; buf_init(&tmp);
                    while (p < eol) {
                        if (*p == '"') { if (p[1] == '"') { buf_puts(&tmp, "\""); p += 2; } else { p++; break; } }
                        else { char ch[2] = {*p,0}; buf_puts(&tmp, ch); p++; }
                    }
                    if (col < ncols || ncols == 0)
                        qihse_ch_result_set_str(r, row, col, tmp.data ? tmp.data : "");
                    buf_free(&tmp);
                    while (p < eol && *p != delim) p++;
                    if (*p == delim) p++;
                } else {
                    while (p < eol && *p != delim) p++;
                    char* val = ch_strndup(start, (size_t)(p - start));
                    if (col < ncols || ncols == 0) {
                        if (val[0] == '\\') {
                            if (val[1] == 'N') qihse_ch_result_set_null(r, row, col);
                            else qihse_ch_result_set_str(r, row, col, val);
                        } else if (val[0] && (isdigit((unsigned char)val[0]) || val[0] == '-')) {
                            qihse_ch_result_set_int(r, row, col, strtoll(val, NULL, 10));
                        } else {
                            qihse_ch_result_set_str(r, row, col, val);
                        }
                    }
                    free(val);
                    if (*p == delim) p++;
                }
                col++;
            }
        }
        row++;
        line = next;
    }
    return r;
}

qihse_ch_result_t* qihse_ch_parse_insert_data(const char* data,
                                              qihse_ch_format_t fmt,
                                              const qihse_ch_table_t* table) {
    if (!data) return qihse_ch_result_create(0);
    switch (fmt) {
        case QIHSE_CH_FMT_VALUES:
            return parse_values_body(data, table);
        case QIHSE_CH_FMT_CSV:
        case QIHSE_CH_FMT_CSV_WITH_NAMES:
            return parse_delimited(data, ',', 1, table);
        case QIHSE_CH_FMT_TABSEPARATED:
        case QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES:
        case QIHSE_CH_FMT_TABSEPARATED_WITH_NAMES_AND_TYPES:
        case QIHSE_CH_FMT_TSV:
        case QIHSE_CH_FMT_TSV_WITH_NAMES:
            return parse_delimited(data, '\t', 0, table);
        case QIHSE_CH_FMT_JSON_EACH_ROW:
        case QIHSE_CH_FMT_JSON_COMPACT_EACH_ROW:
            /* best-effort: treat each line as a row; full JSON parse omitted */
            return parse_delimited(data, '\t', 0, table);
        default:
            return parse_delimited(data, '\t', 0, table);
    }
}
