/*
 * QIHSE Mutable Table Store
 *
 * A row-oriented mutable table store supporting INSERT, UPDATE, DELETE,
 * and SELECT with WHERE filtering.  Tables are stored in a dynamic array
 * within the store.  Each table holds a dynamic array of row pointers;
 * each row is an array of qihse_col_value_t.  String values are deep-copied
 * on insert and freed on delete.
 *
 * DELETE uses tombstones: deleted rows are marked and their values freed.
 * The table is compacted when the tombstone count exceeds 25% of the
 * total row capacity, reclaiming the slots occupied by tombstones.
 *
 * Thread-safety: each table has a pthread_rwlock.  Readers (scan, row_count)
 * acquire a read lock; writers (insert, update, delete) acquire a write lock.
 * The store itself uses a mutex to protect the table array during
 * create_table / find_table.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "qihse_table_store.h"
#include "qihse_schema.h"
#include "qihse_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    qihse_table_txn_t* txn;
    qihse_table_t* table;
    qihse_col_value_t** old_rows;
    size_t old_num_rows;
} ts_group_item_t;

/* -------------------------------------------------------------------------
 * Internal structures
 * ------------------------------------------------------------------------- */

struct qihse_table {
    qihse_table_store_t* owner;        /* borrowed */
    char*               name;         /* owned */
    qihse_col_def_t*    cols;         /* array of num_defs column defs (owned) */
    size_t              num_cols;
    qihse_col_value_t** rows;         /* array of row pointers; NULL = tombstone */
    size_t              num_rows;     /* total slots (live + tombstone) */
    size_t              cap_rows;     /* allocated capacity */
    size_t              num_tomb;     /* number of tombstoned slots */
    uint64_t            generation;   /* optimistic transaction fence */
    pthread_rwlock_t    lock;
};

struct qihse_table_txn {
    qihse_table_t* table;              /* borrowed; store outlives txn */
    qihse_table_t  shadow;             /* rows owned; schema borrowed */
    uint64_t       base_generation;
};

#define TS_RETRY_MAX_ENTRIES 4096u
typedef struct {
    char key[QIHSE_TS_RETRY_MAX_TEXT + 1];
    char principal[QIHSE_TS_RETRY_MAX_TEXT + 1];
    char tenant[QIHSE_TS_RETRY_MAX_TEXT + 1];
    uint8_t digest[QIHSE_TS_RETRY_DIGEST_SIZE];
    qihse_ts_retry_outcome_t outcome;
} ts_retry_entry_t;

struct qihse_table_store {
    qihse_table_t**     tables;
    size_t              num_tables;
    size_t              cap_tables;
    pthread_mutex_t     mutex;        /* protects the table array */
    char*               path;         /* NULL means in-memory */
    int                 lock_fd;      /* lifetime writer exclusion */
    pid_t               owner_pid;    /* inherited handles cannot write after fork */
    bool                poisoned;     /* ambiguous post-rename I/O error */
    unsigned char*      schema_image; /* committed with rows */
    size_t              schema_len;
    ts_retry_entry_t*   retries;
    size_t              num_retries;
    size_t              cap_retries;
};

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static bool ts_string_type(qihse_ts_type_t type) {
    return type == QIHSE_TS_STRING || type == QIHSE_TS_UUID ||
           type == QIHSE_TS_JSONB || type == QIHSE_TS_NUMERIC ||
           type == QIHSE_TS_TSVECTOR;
}

static bool ts_value_type_valid(qihse_ts_type_t type) {
    return type >= QIHSE_TS_INT32 && type <= QIHSE_TS_TSVECTOR;
}

bool qihse_ts_numeric_valid(const char* text, unsigned precision, unsigned scale) {
    if (!text || !*text || strlen(text) > 4096 || (precision && (scale > precision || precision > 1000)))
        return false;
    const unsigned char* p = (const unsigned char*)text;
    if (*p == '+' || *p == '-') ++p;
    unsigned before = 0, after = 0;
    bool significant = false, has_digits = false;
    while (isdigit(*p)) {
        has_digits = true;
        if (*p != '0') significant = true;
        if (significant) ++before;
        ++p;
    }
    if (*p == '.') {
        ++p;
        while (isdigit(*p)) { has_digits = true; ++after; ++p; }
    }
    if (*p || !has_digits ||
        (precision && (after > scale || before > precision - scale)))
        return false;
    return true;
}

bool qihse_ts_tsvector_valid(const char* text) {
    if (!text || strlen(text) > 4096) return false;
    const unsigned char* p = (const unsigned char*)text;
    if (!*p) return true;
    while (*p) {
        if (*p++ != '\'') return false;
        size_t length = 0;
        while (*p && *p != '\'') {
            if (*p == '\\') { ++p; if (!*p) return false; }
            if ((unsigned char)*p < 32 || ++length > 256) return false;
            ++p;
        }
        if (!length || *p++ != '\'') return false;
        if (*p == ':') {
            ++p;
            unsigned previous = 0;
            do {
                unsigned pos = 0;
                if (!isdigit(*p)) return false;
                while (isdigit(*p)) {
                    pos = pos * 10 + (*p++ - '0');
                    if (pos > 16383) return false;
                }
                if (!pos || pos <= previous) return false;
                previous = pos;
                if (*p == 'A' || *p == 'B' || *p == 'C' || *p == 'D') ++p;
                if (*p != ',') break;
                ++p;
            } while (1);
        }
        if (*p && *p++ != ' ') return false;
        if (!*p && p[-1] == ' ') return false;
    }
    return true;
}

static bool ts_uuid_valid(const char* text) {
    if (!text || strlen(text) != 36) return false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i] != '-') return false;
        } else if (!isxdigit((unsigned char)text[i])) return false;
    }
    return true;
}

static bool ts_values_match_schema(const qihse_col_def_t* cols,
                                   size_t num_cols,
                                   const qihse_col_value_t* values,
                                   size_t num_values) {
    if (!cols || !values || num_values != num_cols) return false;
    for (size_t i = 0; i < num_cols; ++i) {
        if (values[i].type != cols[i].type) return false;
        if (values[i].is_null) continue;
        if (values[i].type == QIHSE_TS_NUMERIC &&
            !qihse_ts_numeric_valid(values[i].v.str, 0, 0)) return false;
        if (values[i].type == QIHSE_TS_TSVECTOR &&
            !qihse_ts_tsvector_valid(values[i].v.str)) return false;
        if (values[i].type == QIHSE_TS_UUID &&
            !ts_uuid_valid(values[i].v.str)) return false;
        if (values[i].type == QIHSE_TS_FLOAT && !isfinite(values[i].v.f32)) return false;
    }
    return true;
}

static void ts_free_col_value(qihse_col_value_t* v) {
    if (!v) return;
    if (ts_string_type(v->type)) {
        free(v->v.str);
        v->v.str = NULL;
    }
}

static void ts_free_row(qihse_col_value_t* row, size_t num_cols) {
    if (!row) return;
    for (size_t i = 0; i < num_cols; i++)
        ts_free_col_value(&row[i]);
    free(row);
}

static qihse_col_value_t* ts_dup_row(const qihse_col_value_t* values,
                                     size_t num_values, size_t num_cols) {
    size_t n = num_values < num_cols ? num_values : num_cols;
    qihse_col_value_t* row =
        (qihse_col_value_t*)calloc(num_cols, sizeof(qihse_col_value_t));
    if (!row) return NULL;
    for (size_t i = 0; i < num_cols; i++) {
        if (i < n) {
            if (!ts_value_type_valid(values[i].type)) {
                ts_free_row(row, num_cols);
                return NULL;
            }
            row[i].type = values[i].type;
            row[i].is_null = values[i].is_null;
            if (row[i].is_null) continue;
            switch (values[i].type) {
                case QIHSE_TS_INT32:
                    row[i].v.i32 = values[i].v.i32;
                    break;
                case QIHSE_TS_INT64:
                    row[i].v.i64 = values[i].v.i64;
                    break;
                case QIHSE_TS_FLOAT:
                    row[i].v.f32 = values[i].v.f32;
                    break;
                case QIHSE_TS_BOOLEAN:
                    row[i].v.boolean = values[i].v.boolean;
                    break;
                case QIHSE_TS_TIMESTAMPTZ:
                    row[i].v.timestamptz_us = values[i].v.timestamptz_us;
                    break;
                case QIHSE_TS_STRING:
                case QIHSE_TS_UUID:
                case QIHSE_TS_JSONB:
                case QIHSE_TS_NUMERIC:
                case QIHSE_TS_TSVECTOR:
                    row[i].v.str = values[i].v.str ? strdup(values[i].v.str) : NULL;
                    if (!values[i].v.str || !row[i].v.str) {
                        ts_free_row(row, num_cols);
                        return NULL;
                    }
                    break;
            }
        } else {
            /* missing values default to INT32 0 */
            row[i].type = QIHSE_TS_INT32;
            row[i].v.i32 = 0;
        }
    }
    return row;
}

static void ts_free_rows(qihse_col_value_t** rows, size_t num_rows,
                         size_t num_cols) {
    if (!rows) return;
    for (size_t i = 0; i < num_rows; i++)
        ts_free_row(rows[i], num_cols);
    free(rows);
}

static qihse_col_value_t** ts_dup_rows(qihse_col_value_t* const* rows,
                                       size_t num_rows, size_t num_cols) {
    if (num_rows == 0) return NULL;
    qihse_col_value_t** copy =
        (qihse_col_value_t**)calloc(num_rows, sizeof(*copy));
    if (!copy) return NULL;
    for (size_t i = 0; i < num_rows; i++) {
        if (!rows[i]) continue;
        copy[i] = ts_dup_row(rows[i], num_cols, num_cols);
        if (!copy[i]) {
            ts_free_rows(copy, num_rows, num_cols);
            return NULL;
        }
    }
    return copy;
}

static bool ts_ensure_cap(qihse_table_t* t, size_t needed) {
    if (needed <= t->cap_rows) return true;
    size_t cap = t->cap_rows ? t->cap_rows : 16;
    while (cap < needed) {
        if (cap > (SIZE_MAX / 2)) { cap = needed; break; }
        cap *= 2;
    }
    qihse_col_value_t** rows =
        (qihse_col_value_t**)realloc(t->rows, cap * sizeof(qihse_col_value_t*));
    if (!rows) return false;
    /* initialise new slots to NULL */
    for (size_t i = t->cap_rows; i < cap; i++)
        rows[i] = NULL;
    t->rows = rows;
    t->cap_rows = cap;
    return true;
}

/* Compact: remove tombstoned slots, shifting live rows down. */
static void ts_compact(qihse_table_t* t) {
    if (t->num_tomb == 0) return;
    size_t write = 0;
    for (size_t read = 0; read < t->num_rows; read++) {
        if (t->rows[read] != NULL) {
            if (write != read)
                t->rows[write] = t->rows[read];
            write++;
        }
    }
    /* NULL out the trailing slots */
    for (size_t i = write; i < t->num_rows; i++)
        t->rows[i] = NULL;
    t->num_rows = write;
    t->num_tomb = 0;
}

/* Native snapshots v1-v4 use fixed little-endian integers, bounded payloads,
 * and an FNV-1a integrity check. v4 adds typed values and explicit NULLs.
 * Rename is the atomic commit point. */
#define TS_LIMIT (64u * 1024u * 1024u)
static const unsigned char ts_magic[8] = {'Q','T','S','N','A','P',1,0};
static const unsigned char ts_magic_v2[8] = {'Q','T','S','N','A','P',2,0};
static const unsigned char ts_magic_v3[8] = {'Q','T','S','N','A','P',3,0};
static const unsigned char ts_magic_v4[8] = {'Q','T','S','N','A','P',4,0};
static const unsigned char ts_magic_v5[8] = {'Q','T','S','N','A','P',5,0};

typedef struct { unsigned char* p; size_t n, cap, pos; } ts_buf_t;

static bool ts_put(ts_buf_t* b, const void* src, size_t n) {
    if (n > TS_LIMIT - b->n) return false;
    if (b->n + n > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->n + n) cap = cap > TS_LIMIT / 2 ? TS_LIMIT : cap * 2;
        unsigned char* p = realloc(b->p, cap);
        if (!p) return false;
        b->p = p; b->cap = cap;
    }
    if (n) memcpy(b->p + b->n, src, n);
    b->n += n;
    return true;
}
static bool ts_u64(ts_buf_t* b, uint64_t v) {
    unsigned char x[8];
    for (int i = 0; i < 8; ++i) x[i] = (unsigned char)(v >> (i * 8));
    return ts_put(b, x, 8);
}
static bool ts_get(ts_buf_t* b, void* dst, size_t n) {
    if (n > b->n - b->pos) return false;
    memcpy(dst, b->p + b->pos, n); b->pos += n; return true;
}
static bool ts_read_u64(ts_buf_t* b, uint64_t* v) {
    unsigned char x[8];
    if (!ts_get(b, x, 8)) return false;
    *v = 0;
    for (int i = 0; i < 8; ++i) *v |= (uint64_t)x[i] << (i * 8);
    return true;
}
static uint64_t ts_hash(const unsigned char* p, size_t n) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= UINT64_C(1099511628211); }
    return h;
}
static bool ts_string(ts_buf_t* b, const char* str) {
    if (!str) return ts_u64(b, UINT64_MAX);
    size_t n = strlen(str);
    return ts_u64(b, n) && ts_put(b, str, n);
}
static bool ts_read_string(ts_buf_t* b, char** out, bool nullable) {
    uint64_t n;
    if (!ts_read_u64(b, &n)) return false;
    if (n == UINT64_MAX && nullable) { *out = NULL; return true; }
    if (n >= TS_LIMIT || n > b->n - b->pos) return false;
    char* s = malloc((size_t)n + 1);
    if (!s) return false;
    if (!ts_get(b, s, (size_t)n)) { free(s); return false; }
    s[n] = 0;
    if (memchr(s, 0, (size_t)n)) { free(s); return false; }
    *out = s; return true;
}
static bool ts_retry_valid(const qihse_ts_retry_identity_t* id) {
    return id && id->key && id->principal && id->tenant &&
        strnlen(id->key, QIHSE_TS_RETRY_MAX_TEXT + 1) > 0 &&
        strnlen(id->key, QIHSE_TS_RETRY_MAX_TEXT + 1) <= QIHSE_TS_RETRY_MAX_TEXT &&
        strnlen(id->principal, QIHSE_TS_RETRY_MAX_TEXT + 1) > 0 &&
        strnlen(id->principal, QIHSE_TS_RETRY_MAX_TEXT + 1) <= QIHSE_TS_RETRY_MAX_TEXT &&
        strnlen(id->tenant, QIHSE_TS_RETRY_MAX_TEXT + 1) > 0 &&
        strnlen(id->tenant, QIHSE_TS_RETRY_MAX_TEXT + 1) <= QIHSE_TS_RETRY_MAX_TEXT;
}

static qihse_ts_retry_status_t ts_retry_find(qihse_table_store_t* s,
    const qihse_ts_retry_identity_t* id, qihse_ts_retry_outcome_t* outcome) {
    for (size_t i = 0; i < s->num_retries; ++i) {
        ts_retry_entry_t* e = &s->retries[i];
        if (strcmp(e->key, id->key)) continue;
        if (strcmp(e->principal, id->principal) ||
            strcmp(e->tenant, id->tenant) ||
            memcmp(e->digest, id->digest, sizeof e->digest))
            return QIHSE_TS_RETRY_MISMATCH;
        *outcome = e->outcome;
        return QIHSE_TS_RETRY_COMMITTED;
    }
    return QIHSE_TS_RETRY_ABSENT;
}

qihse_ts_retry_status_t qihse_table_store_retry_lookup(
    qihse_table_store_t* s, const qihse_ts_retry_identity_t* id,
    qihse_ts_retry_outcome_t* outcome) {
    if (!s || !outcome || !ts_retry_valid(id)) return QIHSE_TS_RETRY_ERROR;
    pthread_mutex_lock(&s->mutex);
    qihse_ts_retry_status_t status = s->path && !s->poisoned &&
        s->owner_pid == getpid() ? ts_retry_find(s, id, outcome) :
        QIHSE_TS_RETRY_ERROR;
    pthread_mutex_unlock(&s->mutex);
    return status;
}

static bool ts_encode(qihse_table_store_t* s, ts_buf_t* b,
                      ts_group_item_t* items, size_t count,
                      const ts_retry_entry_t* added) {
    if (!ts_u64(b, s->num_tables)) return false;
    for (size_t i = 0; i < s->num_tables; ++i) {
        qihse_table_t* t = s->tables[i];
        qihse_table_t* data = t;
        for (size_t j = 0; j < count; ++j)
            if (items[j].table == t) { data = &items[j].txn->shadow; break; }
        if (!ts_string(b, t->name) || !ts_u64(b, t->num_cols) ||
            !ts_u64(b, t->generation + (data != t)) ||
            !ts_u64(b, data->num_rows)) return false;
        for (size_t c = 0; c < t->num_cols; ++c)
            if (!ts_string(b, t->cols[c].name) ||
                !ts_u64(b, t->cols[c].type)) return false;
        for (size_t r = 0; r < data->num_rows; ++r) {
            if (!ts_u64(b, data->rows[r] != NULL)) return false;
            if (!data->rows[r]) continue;
            for (size_t c = 0; c < t->num_cols; ++c) {
                qihse_col_value_t* v = &data->rows[r][c];
                uint32_t bits = 0;
                if (!ts_u64(b, v->type) || !ts_u64(b, v->is_null ? 1 : 0)) return false;
                if (v->is_null) continue;
                switch (v->type) {
                case QIHSE_TS_INT32:
                    if (!ts_u64(b, (uint32_t)v->v.i32)) return false;
                    break;
                case QIHSE_TS_INT64:
                    if (!ts_u64(b, (uint64_t)v->v.i64)) return false;
                    break;
                case QIHSE_TS_FLOAT:
                    memcpy(&bits, &v->v.f32, sizeof bits);
                    if (!ts_u64(b, bits)) return false;
                    break;
                case QIHSE_TS_STRING:
                case QIHSE_TS_UUID:
                case QIHSE_TS_JSONB:
                case QIHSE_TS_NUMERIC:
                case QIHSE_TS_TSVECTOR:
                    if (!ts_string(b, v->v.str)) return false;
                    break;
                case QIHSE_TS_BOOLEAN:
                    if (!ts_u64(b, v->v.boolean ? 1 : 0)) return false;
                    break;
                case QIHSE_TS_TIMESTAMPTZ:
                    if (!ts_u64(b, (uint64_t)v->v.timestamptz_us)) return false;
                    break;
                default: return false;
                }
            }
        }
    }
    if (!ts_u64(b, s->schema_len) ||
        !ts_put(b, s->schema_image, s->schema_len) ||
        !ts_u64(b, s->num_retries + (added != NULL))) return false;
    for (size_t i = 0; i < s->num_retries + (added != NULL); ++i) {
        const ts_retry_entry_t* e = i < s->num_retries ? &s->retries[i] : added;
        if (!ts_string(b, e->key) || !ts_string(b, e->principal) ||
            !ts_string(b, e->tenant) ||
            !ts_put(b, e->digest, sizeof e->digest) ||
            !ts_u64(b, e->outcome.affected_rows) ||
            !ts_u64(b, e->outcome.command_count)) return false;
    }
    return true;
}
static qihse_ts_type_t ts_catalog_type(qihse_sql_type_t type) {
    switch (type) {
    case QIHSE_TYPE_INT: case QIHSE_TYPE_SERIAL: return QIHSE_TS_INT32;
    case QIHSE_TYPE_BIGINT: case QIHSE_TYPE_BIGSERIAL: return QIHSE_TS_INT64;
    case QIHSE_TYPE_FLOAT: case QIHSE_TYPE_DOUBLE: return QIHSE_TS_FLOAT;
    case QIHSE_TYPE_BOOL: return QIHSE_TS_BOOLEAN;
    case QIHSE_TYPE_TIMESTAMP: case QIHSE_TYPE_TIMESTAMPTZ: return QIHSE_TS_TIMESTAMPTZ;
    case QIHSE_TYPE_UUID: return QIHSE_TS_UUID;
    case QIHSE_TYPE_JSONB: return QIHSE_TS_JSONB;
    case QIHSE_TYPE_NUMERIC: return QIHSE_TS_NUMERIC;
    case QIHSE_TYPE_TSVECTOR: return QIHSE_TS_TSVECTOR;
    default: return QIHSE_TS_STRING;
    }
}

/* Verify that a checksummed native image is also a complete catalog/row
 * generation. This runs before recovery exposes any table handles. */
static bool ts_validate_catalog(const qihse_table_store_t* s,
                                const ts_group_item_t* items, size_t count) {
    /* Standalone legacy row stores may have no SQL catalog (or an opaque
     * application payload); only QSC1 images claim SQL catalog semantics. */
    if (!s->schema_len || s->schema_len < 4 ||
        memcmp(s->schema_image, "QSC1", 4)) return true;
    qihse_schema_registry_t* reg = NULL;
    if (qihse_schema_deserialize(s->schema_image, s->schema_len, &reg) != 0)
        return false;
    bool valid = qihse_schema_table_count(reg) == s->num_tables;
    for (size_t i = 0; i < s->num_tables && valid; ++i) {
        const qihse_table_t* t = s->tables[i];
        for (size_t j = 0; j < i; ++j)
            if (strcasecmp(t->name, s->tables[j]->name) == 0) {
                valid = false; break;
            }
        if (!valid) break;
        const qihse_table_t* rows = t;
        for (size_t j = 0; j < count; ++j)
            if (items[j].table == t) { rows = &items[j].txn->shadow; break; }
        const qihse_schema_table_t* schema = qihse_schema_get_table(reg, t->name);
        if (!schema || schema->num_columns != t->num_cols) { valid = false; break; }
        for (size_t c = 0; c < t->num_cols && valid; ++c) {
            const qihse_schema_column_t* def = &schema->columns[c];
            if (strcmp(def->name, t->cols[c].name) ||
                ts_catalog_type(def->type) != t->cols[c].type) { valid = false; break; }
            for (size_t r = 0; r < rows->num_rows && valid; ++r) {
                if (!rows->rows[r]) continue;
                const qihse_col_value_t* v = &rows->rows[r][c];
                if (v->is_null && (def->not_null || def->is_primary_key)) valid = false;
                if (!v->is_null && v->type == QIHSE_TS_NUMERIC &&
                    !qihse_ts_numeric_valid(v->v.str, (unsigned)def->type_len,
                                            (unsigned)def->type_scale)) valid = false;
            }
        }
    }
    qihse_schema_registry_destroy(reg);
    return valid;
}

static bool ts_write_all(int fd, const void* p, size_t n) {
    const unsigned char* x = p;
    while (n) {
        ssize_t k = write(fd, x, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return false;
        x += k; n -= (size_t)k;
    }
    return true;
}
static bool ts_persist(qihse_table_store_t* s, ts_group_item_t* items,
                       size_t count, const ts_retry_entry_t* added) {
    ts_buf_t b = {0};
    bool ok = ts_validate_catalog(s, items, count) &&
              ts_encode(s, &b, items, count, added);
    size_t len = strlen(s->path);
    static const char suffix[] = ".tmp.XXXXXX";
    char* tmp = malloc(len + sizeof(suffix));
    char* dir = strdup(s->path);
    bool created = false;
    if (!tmp || !dir) ok = false;
    if (ok) {
        memcpy(tmp, s->path, len);
        memcpy(tmp + len, suffix, sizeof(suffix));
        unsigned char hdr[24];
        memcpy(hdr, ts_magic_v5, 8);
        uint64_t fields[2] = {b.n, ts_hash(b.p, b.n)};
        for (int j = 0; j < 2; ++j)
            for (int k = 0; k < 8; ++k)
                hdr[8 + 8*j + k] = (unsigned char)(fields[j] >> (k*8));
        /* A predictable O_TRUNC path could follow a pre-planted symlink. */
        int fd = mkstemp(tmp);
        if (fd < 0) ok = false;
        else {
            created = true;
            ok = ts_write_all(fd, hdr, sizeof hdr) &&
                 ts_write_all(fd, b.p, b.n) && fsync(fd) == 0;
            if (close(fd) != 0) ok = false;
        }
        if (ok && rename(tmp, s->path) == 0) {
            /* A failure after rename is ambiguous: refuse further writes. */
            s->poisoned = true;
            char* slash = strrchr(dir, '/');
            if (slash) { if (slash == dir) slash[1] = 0; else *slash = 0; }
            else strcpy(dir, ".");
            int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            ok = dfd >= 0 && fsync(dfd) == 0;
            if (dfd >= 0 && close(dfd) != 0) ok = false;
            if (ok) s->poisoned = false;
        } else ok = false;
        if (!ok && created && !s->poisoned) unlink(tmp);
    }
    free(dir); free(tmp); free(b.p);
    return ok;
}
static bool ts_decode(qihse_table_store_t* s, ts_buf_t* b, bool catalog,
                      unsigned version) {
    uint64_t nt;
    if (!ts_read_u64(b, &nt) || nt > 100000) return false;
    for (uint64_t i = 0; i < nt; ++i) {
        char* name = NULL;
        uint64_t nc, gen, nr;
        if (!ts_read_string(b, &name, false)) return false;
        if (!ts_read_u64(b, &nc) || !ts_read_u64(b, &gen) ||
            !ts_read_u64(b, &nr) || !nc || nc > 100000 ||
            nr > TS_LIMIT / 8) { free(name); return false; }
        qihse_col_def_t* cols = calloc((size_t)nc, sizeof(*cols));
        if (!cols) { free(name); return false; }
        bool ok = true;
        for (size_t c = 0; c < nc; ++c) {
            uint64_t type;
            if (!ts_read_string(b, &cols[c].name, false) ||
                !ts_read_u64(b, &type) || type > (version >= 5 ? QIHSE_TS_TSVECTOR : version >= 4 ? QIHSE_TS_TIMESTAMPTZ : QIHSE_TS_STRING)) {
                ok = false; break;
            }
            cols[c].type = (qihse_ts_type_t)type;
        }
        qihse_table_t* t = ok ? qihse_table_store_create_table(s, name, cols, (size_t)nc) : NULL;
        for (size_t c = 0; c < nc; ++c) free(cols[c].name);
        free(cols); free(name);
        if (!t) return false;
        t->generation = gen;
        for (size_t r = 0; r < nr; ++r) {
            uint64_t present;
            if (!ts_read_u64(b, &present) || present > 1 ||
                !ts_ensure_cap(t, r + 1)) return false;
            t->num_rows++;
            if (!present) { t->num_tomb++; continue; }
            qihse_col_value_t* row = calloc((size_t)nc, sizeof(*row));
            if (!row) return false;
            t->rows[r] = row;
            for (size_t c = 0; c < nc; ++c) {
                uint64_t type, val;
                if (!ts_read_u64(b, &type) ||
                    type > (version >= 5 ? QIHSE_TS_TSVECTOR : version >= 4 ? QIHSE_TS_TIMESTAMPTZ : QIHSE_TS_STRING) ||
                    type != (uint64_t)t->cols[c].type) return false;
                row[c].type = (qihse_ts_type_t)type;
                if (version >= 4) {
                    if (!ts_read_u64(b, &val) || val > 1) return false;
                    row[c].is_null = val != 0;
                    if (row[c].is_null) continue;
                }
                if (ts_string_type(row[c].type)) {
                    if (!ts_read_string(b, &row[c].v.str, version < 4)) return false;
                    if (version < 4 && row[c].v.str == NULL) row[c].is_null = true;
                    if (!row[c].is_null &&
                        ((type == QIHSE_TS_NUMERIC && !qihse_ts_numeric_valid(row[c].v.str, 0, 0)) ||
                         (type == QIHSE_TS_UUID && !ts_uuid_valid(row[c].v.str)) ||
                         (type == QIHSE_TS_TSVECTOR && !qihse_ts_tsvector_valid(row[c].v.str))))
                        return false;
                } else {
                    if (!ts_read_u64(b, &val)) return false;
                    if (type == QIHSE_TS_INT32) {
                        if (val > UINT32_MAX) return false;
                        row[c].v.i32 = (int32_t)(uint32_t)val;
                    } else if (type == QIHSE_TS_INT64) row[c].v.i64 = (int64_t)val;
                    else if (type == QIHSE_TS_FLOAT) {
                        if (val > UINT32_MAX) return false;
                        uint32_t bits = (uint32_t)val;
                        memcpy(&row[c].v.f32, &bits, sizeof bits);
                        if (!isfinite(row[c].v.f32)) return false;
                    } else if (type == QIHSE_TS_BOOLEAN) {
                        if (val > 1) return false;
                        row[c].v.boolean = val != 0;
                    } else row[c].v.timestamptz_us = (int64_t)val;
                }
            }
        }
    }
    if (catalog) {
        uint64_t n;
        if (!ts_read_u64(b, &n) || n > 1024u * 1024u ||
            n > b->n - b->pos) return false;
        if (n) {
            s->schema_image = malloc((size_t)n);
            if (!s->schema_image || !ts_get(b, s->schema_image, (size_t)n))
                return false;
            s->schema_len = (size_t)n;
        }
    }
    if (version >= 3) {
        uint64_t n;
        if (!ts_read_u64(b, &n) || n > TS_RETRY_MAX_ENTRIES ||
            n > (b->n - b->pos) / (3 * 8 + QIHSE_TS_RETRY_DIGEST_SIZE + 16))
            return false;
        if (n) {
            s->retries = calloc((size_t)n, sizeof(*s->retries));
            if (!s->retries) return false;
            s->cap_retries = (size_t)n;
        }
        for (size_t i = 0; i < n; ++i) {
            ts_retry_entry_t* e = &s->retries[i];
            char *key = NULL, *principal = NULL, *tenant = NULL;
            bool ok = ts_read_string(b, &key, false) &&
                ts_read_string(b, &principal, false) &&
                ts_read_string(b, &tenant, false);
            if (ok) {
                qihse_ts_retry_identity_t id = { .key = key,
                    .principal = principal, .tenant = tenant };
                ok = ts_retry_valid(&id);
                for (size_t j = 0; ok && j < s->num_retries; ++j)
                    if (!strcmp(s->retries[j].key, key)) ok = false;
                if (ok) {
                    memcpy(e->key, key, strlen(key) + 1);
                    memcpy(e->principal, principal, strlen(principal) + 1);
                    memcpy(e->tenant, tenant, strlen(tenant) + 1);
                }
            }
            free(key); free(principal); free(tenant);
            if (!ok || !ts_get(b, e->digest, sizeof e->digest) ||
                !ts_read_u64(b, &e->outcome.affected_rows) ||
                !ts_read_u64(b, &e->outcome.command_count)) return false;
            s->num_retries++;
        }
    }
    return b->pos == b->n;
}

qihse_table_store_t* qihse_table_store_open_durable(const char* path) {
    if (!path || !*path || strlen(path) > SIZE_MAX - 6) return NULL;
    char* parent = strdup(path);
    if (!parent) return NULL;
    char* slash = strrchr(parent, '/');
    if (slash) {
        if (slash == parent) slash[1] = '\0';
        else *slash = '\0';
    } else strcpy(parent, ".");
    int dirfd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat dir_info;
    bool private_dir = dirfd >= 0 && fstat(dirfd, &dir_info) == 0 &&
        S_ISDIR(dir_info.st_mode) && dir_info.st_uid == geteuid() &&
        (dir_info.st_mode & 077) == 0;
    if (dirfd >= 0) close(dirfd);
    free(parent);
    if (!private_dir) { errno = EACCES; return NULL; }
    qihse_table_store_t* s = qihse_table_store_create();
    if (!s) return NULL;
    size_t n = strlen(path);
    char* lock = malloc(n + 6);
    if (!lock) goto fail;
    memcpy(lock, path, n);
    memcpy(lock + n, ".lock", 6);
    s->lock_fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    free(lock);
    struct stat secured;
    if (s->lock_fd < 0 || fstat(s->lock_fd, &secured) != 0 ||
        !S_ISREG(secured.st_mode) || secured.st_uid != geteuid() ||
        (secured.st_mode & 077) != 0 || secured.st_nlink != 1 ||
        flock(s->lock_fd, LOCK_EX | LOCK_NB) != 0) goto fail;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno != ENOENT) goto fail;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 077) != 0 ||
            st.st_nlink != 1 || st.st_size < 24 || st.st_size > TS_LIMIT + 24) {
            close(fd); goto fail;
        }
        ts_buf_t b = {0};
        b.n = (size_t)st.st_size;
        b.p = malloc(b.n);
        if (!b.p) { close(fd); goto fail; }
        size_t pos = 0;
        while (pos < b.n) {
            ssize_t k = read(fd, b.p + pos, b.n - pos);
            if (k < 0 && errno == EINTR) continue;
            if (k <= 0) break;
            pos += (size_t)k;
        }
        close(fd);
        unsigned version = 0;
        if (pos == b.n && !memcmp(b.p, ts_magic, 8)) version = 1;
        else if (pos == b.n && !memcmp(b.p, ts_magic_v2, 8)) version = 2;
        else if (pos == b.n && !memcmp(b.p, ts_magic_v3, 8)) version = 3;
        else if (pos == b.n && !memcmp(b.p, ts_magic_v4, 8)) version = 4;
        else if (pos == b.n && !memcmp(b.p, ts_magic_v5, 8)) version = 5;
        bool valid = pos == b.n && version != 0;
        b.pos = 8;
        uint64_t size = 0, hash = 0;
        valid = valid && ts_read_u64(&b, &size) && ts_read_u64(&b, &hash) &&
                size == b.n - 24 && hash == ts_hash(b.p + 24, b.n - 24);
        b.pos = 24;
        valid = valid && ts_decode(s, &b, version >= 2, version);
        if (valid && version >= 2) valid = ts_validate_catalog(s, NULL, 0);
        free(b.p);
        if (!valid) goto fail;
    }
    s->path = strdup(path);
    if (!s->path) goto fail;
    s->owner_pid = getpid();
    return s;
fail:
    qihse_table_store_destroy(s);
    return NULL;
}

/* Transfer only already-committed images; never serialize a live shadow or
 * remove an existing destination's receipts. The destination lock is held
 * throughout the atomic no-replace publication. */
static bool ts_copy_snapshot(const char* source, const char* destination) {
    int fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && (st.st_mode & 077) == 0 &&
        st.st_nlink == 1 && st.st_size >= 24 && st.st_size <= TS_LIMIT + 24;
    unsigned char* bytes = ok ? malloc((size_t)st.st_size) : NULL;
    if (!bytes) ok = false;
    size_t pos = 0;
    while (ok && pos < (size_t)st.st_size) {
        ssize_t n = read(fd, bytes + pos, (size_t)st.st_size - pos);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        pos += (size_t)n;
    }
    if (close(fd) != 0) ok = false;
    if (ok) {
        ts_buf_t b = {.p = bytes, .n = pos, .pos = 8};
        uint64_t size = 0, hash = 0;
        unsigned version = memcmp(bytes, ts_magic_v5, 8) == 0 ? 5 :
            (memcmp(bytes, ts_magic_v4, 8) == 0 ? 4 :
            (memcmp(bytes, ts_magic_v3, 8) == 0 ? 3 : 0));
        ok = version != 0 &&
            ts_read_u64(&b, &size) && ts_read_u64(&b, &hash) &&
            size == pos - 24 && hash == ts_hash(bytes + 24, pos - 24);
        if (ok) {
            qihse_table_store_t* checked = qihse_table_store_create();
            b.pos = 24;
            ok = checked && ts_decode(checked, &b, true, version) &&
                 checked->schema_len && ts_validate_catalog(checked, NULL, 0);
            qihse_table_store_destroy(checked);
        }
    }
    if (ok) {
        size_t len = strlen(destination);
        static const char suffix[] = ".tmp.XXXXXX";
        if (len > SIZE_MAX - sizeof(suffix)) ok = false;
        char* tmp = ok ? malloc(len + sizeof(suffix)) : NULL;
        char* dir = ok ? strdup(destination) : NULL;
        if (!tmp || !dir) ok = false;
        if (ok) {
            memcpy(tmp, destination, len);
            memcpy(tmp + len, suffix, sizeof(suffix));
            int out = mkstemp(tmp);
            if (out < 0) ok = false;
            else {
                ok = ts_write_all(out, bytes, pos) && fsync(out) == 0;
                if (close(out) != 0) ok = false;
                if (ok) ok = link(tmp, destination) == 0;
                if (ok) ok = unlink(tmp) == 0;
                if (ok) {
                    char* slash = strrchr(dir, '/');
                    if (slash) { if (slash == dir) slash[1] = 0; else *slash = 0; }
                    else strcpy(dir, ".");
                    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                    ok = dfd >= 0 && fsync(dfd) == 0;
                    if (dfd >= 0 && close(dfd) != 0) ok = false;
                }
                /* A failed unlink or directory sync leaves a possibly published
                 * image; never remove the destination after link succeeds. */
                if (!ok) (void)unlink(tmp);
            }
        }
        free(dir); free(tmp);
    }
    free(bytes);
    return ok;
}

static bool ts_backup_authorized(const qihse_user_t* user) {
    return user && qihse_auth_user_is_active(user) &&
        qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR &&
        qihse_user_get_id(user) == 0 && qihse_user_get_tenant_id(user) == 0;
}

bool qihse_table_store_backup(qihse_table_store_t* s,
                              const qihse_user_t* user, const char* backup_path) {
    if (!s || !backup_path || !ts_backup_authorized(user)) return false;
    pthread_mutex_lock(&s->mutex);
    bool ok = s->path && !s->poisoned && s->owner_pid == getpid() &&
        s->schema_len && strcmp(s->path, backup_path) != 0;
    /* open_durable validates the destination's private directory and takes
     * the same lifetime exclusion lock used by all store writers. */
    qihse_table_store_t* dest = ok ? qihse_table_store_open_durable(backup_path) : NULL;
    ok = dest && !dest->schema_len && !dest->num_tables &&
        access(backup_path, F_OK) != 0 && errno == ENOENT &&
        ts_copy_snapshot(s->path, backup_path);
    qihse_table_store_destroy(dest);
    pthread_mutex_unlock(&s->mutex);
    return ok;
}

bool qihse_table_store_restore(const qihse_user_t* user,
                               const char* backup_path, const char* target_path) {
    if (!backup_path || !target_path || !ts_backup_authorized(user) ||
        strcmp(backup_path, target_path) == 0) return false;
    qihse_table_store_t* source = qihse_table_store_open_durable(backup_path);
    if (!source) return false;
    bool ok = source->schema_len != 0;
    qihse_table_store_t* dest = ok ? qihse_table_store_open_durable(target_path) : NULL;
    ok = dest && !dest->schema_len && !dest->num_tables &&
        access(target_path, F_OK) != 0 && errno == ENOENT &&
        ts_copy_snapshot(backup_path, target_path);
    qihse_table_store_destroy(dest);
    qihse_table_store_destroy(source);
    return ok;
}

/* Install the initial catalog only on a new empty durable store. The same
 * rename/fsync commit point then protects both catalog and row generations. */
bool qihse_table_store_set_schema_image(qihse_table_store_t* s,
                                        const uint8_t* image, size_t len) {
    if (!s || !s->path || !image || !len || len > 1024u * 1024u ||
        s->owner_pid != getpid()) return false;
    pthread_mutex_lock(&s->mutex);
    bool ok = !s->poisoned && !s->schema_len && !s->num_tables;
    unsigned char* copy = ok ? malloc(len) : NULL;
    if (copy) {
        memcpy(copy, image, len);
        s->schema_image = copy;
        s->schema_len = len;
        ok = ts_persist(s, NULL, 0, NULL);
        if (!ok && !s->poisoned) {
            free(s->schema_image);
            s->schema_image = NULL;
            s->schema_len = 0;
        }
    } else ok = false;
    pthread_mutex_unlock(&s->mutex);
    return ok;
}

bool qihse_table_store_replace_schema_image(qihse_table_store_t* s,
    const uint8_t* expected, size_t expected_len,
    const uint8_t* image, size_t image_len) {
    if (!s || !s->path || !expected || !expected_len ||
        expected_len > 1024u * 1024u || !image || !image_len ||
        image_len > 1024u * 1024u || s->owner_pid != getpid()) return false;
    unsigned char* replacement = malloc(image_len);
    if (!replacement) return false;
    memcpy(replacement, image, image_len);
    pthread_mutex_lock(&s->mutex);
    bool ok = !s->poisoned && s->schema_len == expected_len &&
        memcmp(s->schema_image, expected, expected_len) == 0;
    unsigned char* previous = NULL;
    size_t previous_len = 0;
    if (ok) {
        previous = s->schema_image;
        previous_len = s->schema_len;
        s->schema_image = replacement;
        s->schema_len = image_len;
        ok = ts_persist(s, NULL, 0, NULL);
        if (!ok && !s->poisoned) {
            s->schema_image = previous;
            s->schema_len = previous_len;
            previous = NULL;
        }
    }
    if (previous) free(previous);
    if (!ok && s->schema_image != replacement) free(replacement);
    pthread_mutex_unlock(&s->mutex);
    return ok;
}

bool qihse_table_store_schema_image(const qihse_table_store_t* s,
                                    const uint8_t** image, size_t* len) {
    if (!s || !image || !len || !s->path || s->poisoned ||
        s->owner_pid != getpid() || !s->schema_len) return false;
    *image = s->schema_image;
    *len = s->schema_len;
    return true;
}

bool qihse_table_store_is_durable(const qihse_table_store_t* s) {
    return s && s->path && !s->poisoned && s->owner_pid == getpid() &&
           s->schema_len != 0;
}

size_t qihse_table_store_table_count(const qihse_table_store_t* s) {
    return s ? s->num_tables : 0;
}

qihse_table_t* qihse_table_store_table_at(const qihse_table_store_t* s,
                                          size_t index) {
    return s && index < s->num_tables ? s->tables[index] : NULL;
}

/* -------------------------------------------------------------------------
 * Store lifecycle
 * ------------------------------------------------------------------------- */

qihse_table_store_t* qihse_table_store_create(void) {
    qihse_table_store_t* s =
        (qihse_table_store_t*)calloc(1, sizeof(qihse_table_store_t));
    if (!s) return NULL;
    pthread_mutex_init(&s->mutex, NULL);
    s->lock_fd = -1;
    return s;
}

static void ts_free_table(qihse_table_t* t) {
    if (!t) return;
    ts_free_rows(t->rows, t->num_rows, t->num_cols);
    for (size_t c = 0; c < t->num_cols; c++) free(t->cols[c].name);
    free(t->cols);
    free(t->name);
    pthread_rwlock_destroy(&t->lock);
    free(t);
}

void qihse_table_store_destroy(qihse_table_store_t* store) {
    if (!store) return;
    pthread_mutex_lock(&store->mutex);
    for (size_t i = 0; i < store->num_tables; i++)
        ts_free_table(store->tables[i]);
    free(store->tables);
    pthread_mutex_unlock(&store->mutex);
    pthread_mutex_destroy(&store->mutex);
    if (store->lock_fd >= 0) close(store->lock_fd);
    free(store->retries);
    free(store->schema_image);
    free(store->path);
    free(store);
}

/* -------------------------------------------------------------------------
 * Table management
 * ------------------------------------------------------------------------- */

static qihse_table_t* ts_create_table(qihse_table_store_t* store,
                                     const char* name,
                                     const qihse_col_def_t* cols,
                                     size_t num_cols,
                                     const uint8_t* image, size_t image_len) {
    if (!store || !name || !*name || !cols || num_cols == 0 ||
        (image && (!image_len || image_len > 1024u * 1024u || !store->path)))
        return NULL;
    for (size_t i = 0; i < num_cols; ++i)
        if (!cols[i].name || !*cols[i].name ||
            !ts_value_type_valid(cols[i].type)) return NULL;

    pthread_mutex_lock(&store->mutex);
    if (store->poisoned || (store->path && store->owner_pid != getpid())) {
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }

    /* Check for duplicate name. */
    for (size_t i = 0; i < store->num_tables; i++) {
        if (store->tables[i] && strcmp(store->tables[i]->name, name) == 0) {
            pthread_mutex_unlock(&store->mutex);
            return NULL;
        }
    }

    /* Grow the table array if needed. */
    if (store->num_tables >= store->cap_tables) {
        size_t cap = store->cap_tables ? store->cap_tables * 2 : 8;
        qihse_table_t** arr =
            (qihse_table_t**)realloc(store->tables, cap * sizeof(qihse_table_t*));
        if (!arr) {
            pthread_mutex_unlock(&store->mutex);
            return NULL;
        }
        store->tables = arr;
        store->cap_tables = cap;
    }

    qihse_table_t* t = (qihse_table_t*)calloc(1, sizeof(qihse_table_t));
    if (!t) {
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }

    t->owner = store;
    t->name = strdup(name);
    if (!t->name) {
        free(t);
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }

    t->cols = (qihse_col_def_t*)calloc(num_cols, sizeof(qihse_col_def_t));
    if (!t->cols) {
        free(t->name);
        free(t);
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }
    t->num_cols = num_cols;
    for (size_t i = 0; i < num_cols; i++) {
        t->cols[i].name = cols[i].name ? strdup(cols[i].name) : NULL;
        t->cols[i].type = cols[i].type;
        if (cols[i].name && !t->cols[i].name) {
            for (size_t j = 0; j < i; j++) free(t->cols[j].name);
            free(t->cols);
            free(t->name);
            free(t);
            pthread_mutex_unlock(&store->mutex);
            return NULL;
        }
    }

    pthread_rwlock_init(&t->lock, NULL);

    unsigned char* replacement = image ? malloc(image_len) : NULL;
    if (image && (!replacement || !store->schema_len)) {
        free(replacement);
        ts_free_table(t);
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }
    if (image) memcpy(replacement, image, image_len);
    unsigned char* previous = store->schema_image;
    size_t previous_len = store->schema_len;
    store->tables[store->num_tables++] = t;
    if (image) {
        store->schema_image = replacement;
        store->schema_len = image_len;
    }
    if (store->path && !ts_persist(store, NULL, 0, NULL)) {
        store->num_tables--;
        store->schema_image = previous;
        store->schema_len = previous_len;
        free(replacement);
        ts_free_table(t);
        pthread_mutex_unlock(&store->mutex);
        return NULL;
    }
    if (image) free(previous);
    pthread_mutex_unlock(&store->mutex);
    return t;
}

qihse_table_t* qihse_table_store_create_table(qihse_table_store_t* store,
                                              const char* name,
                                              const qihse_col_def_t* cols,
                                              size_t num_cols) {
    return ts_create_table(store, name, cols, num_cols, NULL, 0);
}

bool qihse_table_store_create_table_with_schema(qihse_table_store_t* store,
    const char* name, const qihse_col_def_t* cols, size_t num_cols,
    const uint8_t* image, size_t image_len) {
    return image && ts_create_table(store, name, cols, num_cols,
                                    image, image_len) != NULL;
}

static bool ts_transform_row_allowed(const qihse_user_t* user,
    const qihse_col_value_t* row, int tenant_col, int class_col, int sci_col);
static bool ts_table_access_context(const qihse_table_t* table,
    const qihse_user_t* user, uint8_t permission, uint32_t* resource,
    int* tenant_col, int* class_col, int* sci_col);
static bool ts_table_read_context(const qihse_table_t* table,
    const qihse_user_t* user, uint32_t* resource,
    int* tenant_col, int* class_col, int* sci_col);

bool qihse_table_store_create_tables_seeded_with_schema(qihse_table_store_t* store,
    const qihse_ts_new_table_t* tables, size_t count,
    const qihse_ts_source_fence_t* sources, size_t source_count,
    const qihse_user_t* user, const uint8_t* expected, size_t expected_len,
    const uint8_t* image, size_t image_len) {
    if (!store || !store->path || !tables || !count || count > 16 ||
        !expected || !expected_len || expected_len > 1024u * 1024u ||
        !image || !image_len || image_len > 1024u * 1024u ||
        source_count > 16 || (source_count && (!sources || !user)) ||
        store->owner_pid != getpid()) return false;
    /* Build private tables before touching the durable store. */
    qihse_table_store_t* scratch = qihse_table_store_create();
    if (!scratch) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < count; ++i) {
        ok = tables[i].name && *tables[i].name && tables[i].cols &&
             tables[i].num_cols && tables[i].num_cols <= 256;
        for (size_t c = 0; ok && c < tables[i].num_cols; ++c)
            ok = tables[i].cols[c].name && *tables[i].cols[c].name &&
                 ts_value_type_valid(tables[i].cols[c].type);
        if (ok) ok = qihse_table_store_create_table(scratch, tables[i].name,
            tables[i].cols, tables[i].num_cols) != NULL;
        if (ok && tables[i].num_initial_rows &&
            (!tables[i].initial_rows || !user)) ok = false;
        for (size_t r = 0; ok && r < tables[i].num_initial_rows; ++r)
            ok = tables[i].initial_rows[r] &&
                 qihse_table_insert(scratch->tables[i], tables[i].initial_rows[r],
                                    tables[i].num_cols) >= 0;
    }
    if (!ok) goto done;
    unsigned char* replacement = malloc(image_len);
    if (!replacement) { ok = false; goto done; }
    memcpy(replacement, image, image_len);
    /* Match transaction lock order (table locks before store mutex). Sort the
     * source locks so concurrent multi-source publications cannot invert them. */
    const qihse_table_t* locked[16] = {0};
    size_t locked_count = 0;
    for (size_t i = 0; ok && i < source_count; ++i) {
        const qihse_table_t* source = sources[i].table;
        ok = source && source->owner == store;
        for (size_t j = 0; ok && j < locked_count; ++j)
            if (source == locked[j]) ok = false;
        if (ok) locked[locked_count++] = source;
    }
    if (!ok) { free(replacement); goto done; }
    for (size_t i = 0; i < locked_count; ++i)
        for (size_t j = i + 1; j < locked_count; ++j)
            if ((uintptr_t)locked[j] < (uintptr_t)locked[i]) {
                const qihse_table_t* tmp = locked[i];
                locked[i] = locked[j]; locked[j] = tmp;
            }
    for (size_t i = 0; i < locked_count; ++i)
        pthread_rwlock_rdlock((pthread_rwlock_t*)&locked[i]->lock);
    pthread_mutex_lock(&store->mutex);
    for (size_t i = 0; ok && i < count; ++i) {
        const qihse_table_t* dest = scratch->tables[i];
        if (!dest->num_rows) continue;
        uint32_t resource = 0;
        int tenant_col, class_col, sci_col;
        ok = ts_table_access_context(dest, user, QIHSE_ACL_WRITE, &resource,
                                     &tenant_col, &class_col, &sci_col) &&
             (tenant_col >= 0 ||
              (qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM &&
               qihse_auth_can_access(user, 0, 0)));
        for (size_t r = 0; ok && r < dest->num_rows; ++r)
            if (!ts_transform_row_allowed(user, dest->rows[r],
                    tenant_col, class_col, sci_col)) ok = false;
    }
    for (size_t i = 0; ok && i < source_count; ++i) {
        uint32_t resource = 0;
        int tenant_col, class_col, sci_col;
        const qihse_table_t* source = sources[i].table;
        ok = source->generation == sources[i].generation &&
            ts_table_read_context(source, user, &resource, &tenant_col,
                                  &class_col, &sci_col) &&
            qihse_auth_user_is_active(user) &&
            qihse_auth_can_access_object(user, 0, resource, QIHSE_ACL_READ) &&
            (tenant_col >= 0 ||
             (qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM &&
              qihse_auth_can_access(user, 0, 0)));
        for (size_t r = 0; ok && r < source->num_rows; ++r)
            if (source->rows[r] && !ts_transform_row_allowed(user,
                    source->rows[r], tenant_col, class_col, sci_col)) ok = false;
    }
    ok = ok && !store->poisoned && store->schema_len == expected_len &&
         memcmp(store->schema_image, expected, expected_len) == 0 &&
         count <= SIZE_MAX - store->num_tables &&
         store->num_tables + count <= 100000;
    for (size_t i = 0; ok && i < count; ++i)
        for (size_t j = 0; j < store->num_tables; ++j)
            if (!strcmp(tables[i].name, store->tables[j]->name)) {
                ok = false; break;
            }
    if (ok && store->num_tables + count > store->cap_tables) {
        size_t cap = store->num_tables + count;
        qihse_table_t** grown = realloc(store->tables, cap * sizeof(*grown));
        if (!grown) ok = false;
        else { store->tables = grown; store->cap_tables = cap; }
    }
    if (ok) {
        size_t old_count = store->num_tables;
        unsigned char* old_image = store->schema_image;
        size_t old_len = store->schema_len;
        for (size_t i = 0; i < count; ++i) {
            scratch->tables[i]->owner = store;
            store->tables[store->num_tables++] = scratch->tables[i];
        }
        store->schema_image = replacement;
        store->schema_len = image_len;
        ok = ts_persist(store, NULL, 0, NULL);
        if (ok) {
            scratch->num_tables = 0;
            free(old_image);
            replacement = NULL;
        } else {
            store->num_tables = old_count;
            store->schema_image = old_image;
            store->schema_len = old_len;
            for (size_t i = 0; i < count; ++i)
                scratch->tables[i]->owner = scratch;
        }
    }
    pthread_mutex_unlock(&store->mutex);
    for (size_t i = locked_count; i > 0; --i)
        pthread_rwlock_unlock((pthread_rwlock_t*)&locked[i - 1]->lock);
    free(replacement);
done:
    qihse_table_store_destroy(scratch);
    return ok;
}

bool qihse_table_store_create_tables_with_schema(qihse_table_store_t* store,
    const qihse_ts_new_table_t* tables, size_t count,
    const uint8_t* expected, size_t expected_len,
    const uint8_t* image, size_t image_len) {
    return qihse_table_store_create_tables_seeded_with_schema(store, tables,
        count, NULL, 0, NULL, expected, expected_len, image, image_len);
}

qihse_table_t* qihse_table_store_find_table(qihse_table_store_t* store,
                                            const char* name) {
    if (!store || !name) return NULL;
    pthread_mutex_lock(&store->mutex);
    qihse_table_t* result = NULL;
    for (size_t i = 0; i < store->num_tables; i++) {
        if (store->tables[i] && strcmp(store->tables[i]->name, name) == 0) {
            result = store->tables[i];
            break;
        }
    }
    pthread_mutex_unlock(&store->mutex);
    return result;
}

/* -------------------------------------------------------------------------
 * Row operations
 * ------------------------------------------------------------------------- */

int qihse_table_insert(qihse_table_t* table,
                       const qihse_col_value_t* values, size_t num_values) {
    if (!table || table->owner->path ||
        !ts_values_match_schema(table->cols, table->num_cols, values,
                                num_values)) return -1;

    qihse_col_value_t* row = ts_dup_row(values, num_values, table->num_cols);
    if (!row) return -1;

    pthread_rwlock_wrlock(&table->lock);

    /* Find a free slot (reuse a tombstone if available). */
    size_t slot = table->num_rows;
    if (table->num_tomb > 0) {
        for (size_t i = 0; i < table->num_rows; i++) {
            if (table->rows[i] == NULL) {
                slot = i;
                break;
            }
        }
    }

    if (slot >= table->num_rows) {
        if (!ts_ensure_cap(table, table->num_rows + 1)) {
            pthread_rwlock_unlock(&table->lock);
            ts_free_row(row, table->num_cols);
            return -1;
        }
        slot = table->num_rows;
        table->num_rows++;
    } else {
        table->num_tomb--;
    }

    table->rows[slot] = row;
    table->generation++;

    pthread_rwlock_unlock(&table->lock);
    return (int)slot;
}

static bool ts_assign_value(qihse_col_value_t* cell,
                            const qihse_col_value_t* value);

int qihse_table_update(qihse_table_t* table,
                       int (*pred)(const qihse_col_value_t*, size_t, void*),
                       void* pred_ctx,
                       const int* update_cols,
                       const qihse_col_value_t* new_values,
                       size_t num_updates) {
    if (!table || table->owner->path || !pred || !update_cols || !new_values || num_updates == 0)
        return -1;
    for (size_t u = 0; u < num_updates; ++u) {
        int col = update_cols[u];
        if (col < 0 || (size_t)col >= table->num_cols ||
            new_values[u].type != table->cols[col].type) return -1;
    }

    pthread_rwlock_wrlock(&table->lock);
    qihse_col_value_t** candidate =
        ts_dup_rows(table->rows, table->num_rows, table->num_cols);
    if (table->num_rows > 0 && !candidate) {
        pthread_rwlock_unlock(&table->lock);
        return -1;
    }
    bool any = false;
    for (size_t i = 0; i < table->num_rows; i++) {
        if (!candidate[i]) continue;  /* tombstone */
        if (pred(candidate[i], table->num_cols, pred_ctx)) {
            for (size_t u = 0; u < num_updates; u++) {
                int col = update_cols[u];
                if (col < 0 || (size_t)col >= table->num_cols) continue;
                if (!ts_assign_value(&candidate[i][col], &new_values[u])) {
                    ts_free_rows(candidate, table->num_rows, table->num_cols);
                    pthread_rwlock_unlock(&table->lock);
                    return -1;
                }
            }
            any = true;
        }
    }
    if (any) {
        ts_free_rows(table->rows, table->num_rows, table->num_cols);
        table->rows = candidate;
        table->cap_rows = table->num_rows;
        table->generation++;
    } else {
        ts_free_rows(candidate, table->num_rows, table->num_cols);
    }
    pthread_rwlock_unlock(&table->lock);
    return any ? 1 : 0;
}

bool qihse_table_delete(qihse_table_t* table,
                        int (*pred)(const qihse_col_value_t*, size_t, void*),
                        void* pred_ctx) {
    if (!table || table->owner->path || !pred) return false;

    pthread_rwlock_wrlock(&table->lock);
    bool any = false;
    for (size_t i = 0; i < table->num_rows; i++) {
        if (!table->rows[i]) continue;  /* already tombstoned */
        if (pred(table->rows[i], table->num_cols, pred_ctx)) {
            ts_free_row(table->rows[i], table->num_cols);
            table->rows[i] = NULL;
            table->num_tomb++;
            any = true;
        }
    }

    /* Compact when tombstones exceed 25% of capacity. */
    if (table->num_tomb > 0 && table->cap_rows > 0 &&
        table->num_tomb * 4 >= table->cap_rows) {
        ts_compact(table);
    }
    if (any) table->generation++;

    pthread_rwlock_unlock(&table->lock);
    return any;
}

/* -------------------------------------------------------------------------
 * Queries
 * ------------------------------------------------------------------------- */

size_t qihse_table_row_count(const qihse_table_t* table) {
    if (!table) return 0;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&table->lock);
    size_t count = table->num_rows - table->num_tomb;
    pthread_rwlock_unlock((pthread_rwlock_t*)&table->lock);
    return count;
}

static bool ts_transform_row_allowed(const qihse_user_t* user,
    const qihse_col_value_t* row, int tenant_col, int class_col, int sci_col);

static bool ts_table_access_context(const qihse_table_t* table,
    const qihse_user_t* user, uint8_t permission, uint32_t* resource,
    int* tenant_col, int* class_col, int* sci_col) {
    if (!table || !user || !qihse_auth_user_is_active(user)) return false;
    *tenant_col = qihse_table_find_col(table, "__qihse_tenant_id");
    *class_col = qihse_table_find_col(table, "__qihse_classification");
    *sci_col = qihse_table_find_col(table, "__qihse_sci");
    bool labeled = *tenant_col >= 0 && *class_col >= 0 && *sci_col >= 0;
    if (!labeled && (*tenant_col >= 0 || *class_col >= 0 || *sci_col >= 0)) return false;
    if (labeled && (table->cols[*tenant_col].type != QIHSE_TS_INT32 ||
                    table->cols[*class_col].type != QIHSE_TS_INT32 ||
                    table->cols[*sci_col].type != QIHSE_TS_INT32)) return false;
    *resource = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)table->name; *p; ++p)
        *resource = (*resource ^ *p) * 16777619u;
    return qihse_auth_can_access_object(user, 0, *resource, permission);
}

static bool ts_table_read_context(const qihse_table_t* table,
    const qihse_user_t* user, uint32_t* resource,
    int* tenant_col, int* class_col, int* sci_col) {
    return ts_table_access_context(table, user, QIHSE_ACL_READ, resource,
                                   tenant_col, class_col, sci_col);
}

bool qihse_table_scan_ids_user(const qihse_table_t* table,
    const qihse_user_t* user, qihse_table_row_id_cb cb, void* ctx) {
    if (!cb) return false;
    uint32_t resource = 0;
    int tenant_col, class_col, sci_col;
    if (!ts_table_read_context(table, user, &resource,
                               &tenant_col, &class_col, &sci_col)) return false;
    bool ok = true;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&table->lock);
    for (size_t i = 0; i < table->num_rows; ++i) {
        const qihse_col_value_t* row = table->rows[i];
        if (!row) continue;
        if (!qihse_auth_user_is_active(user) || !qihse_auth_can_access_object(
                user, 0, resource, QIHSE_ACL_READ)) { ok = false; break; }
        if (!ts_transform_row_allowed(user, row, tenant_col, class_col, sci_col))
            continue;
        if (!cb(i, row, table->num_cols, ctx)) break;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&table->lock);
    return ok;
}

bool qihse_table_generation_user(const qihse_table_t* table,
    const qihse_user_t* user, uint64_t* generation) {
    uint32_t resource = 0;
    int tenant_col, class_col, sci_col;
    if (!generation || !ts_table_read_context(table, user, &resource,
                               &tenant_col, &class_col, &sci_col)) return false;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&table->lock);
    bool ok = qihse_auth_user_is_active(user) && qihse_auth_can_access_object(
        user, 0, resource, QIHSE_ACL_READ);
    if (ok) *generation = table->generation;
    pthread_rwlock_unlock((pthread_rwlock_t*)&table->lock);
    return ok;
}

bool qihse_table_row_get_user(const qihse_table_t* table,
    const qihse_user_t* user, uint64_t generation, size_t row_id,
    qihse_table_row_cb cb, void* ctx) {
    uint32_t resource = 0;
    int tenant_col, class_col, sci_col;
    if (!cb || !ts_table_read_context(table, user, &resource,
                               &tenant_col, &class_col, &sci_col)) return false;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&table->lock);
    bool ok = table->generation == generation && row_id < table->num_rows &&
        table->rows[row_id] && qihse_auth_user_is_active(user) &&
        qihse_auth_can_access_object(user, 0, resource, QIHSE_ACL_READ) &&
        ts_transform_row_allowed(user, table->rows[row_id],
                                 tenant_col, class_col, sci_col);
    if (ok) (void)cb(table->rows[row_id], table->num_cols, ctx);
    pthread_rwlock_unlock((pthread_rwlock_t*)&table->lock);
    return ok;
}

typedef struct {
    qihse_table_row_cb cb;
    void* ctx;
} ts_plain_scan_t;

static bool ts_plain_scan_row(size_t id, const qihse_col_value_t* values,
    size_t num_cols, void* opaque) {
    (void)id;
    ts_plain_scan_t* scan = opaque;
    return scan->cb(values, num_cols, scan->ctx);
}

bool qihse_table_scan_user(const qihse_table_t* table,
    const qihse_user_t* user, qihse_table_row_cb cb, void* ctx) {
    if (!cb) return false;
    ts_plain_scan_t scan = {cb, ctx};
    return qihse_table_scan_ids_user(table, user, ts_plain_scan_row, &scan);
}

void qihse_table_scan(const qihse_table_t* table,
                      qihse_table_row_cb cb, void* ctx) {
    if (!table || !cb) return;
    pthread_rwlock_rdlock((pthread_rwlock_t*)&table->lock);
    for (size_t i = 0; i < table->num_rows; i++) {
        if (!table->rows[i]) continue;  /* tombstone */
        if (!cb(table->rows[i], table->num_cols, ctx)) break;
    }
    pthread_rwlock_unlock((pthread_rwlock_t*)&table->lock);
}

/* -------------------------------------------------------------------------
 * Optimistic single-table transactions
 * ------------------------------------------------------------------------- */

static void ts_txn_destroy(qihse_table_txn_t* txn) {
    if (!txn) return;
    ts_free_rows(txn->shadow.rows, txn->shadow.num_rows,
                 txn->shadow.num_cols);
    free(txn);
}

static qihse_table_txn_t* ts_txn_begin_context(qihse_table_t* table,
                                               const qihse_user_t* user) {
    if (!table) return NULL;
    uint32_t resource = 0;
    int tenant_col = -1, class_col = -1, sci_col = -1;
    if (user && !ts_table_read_context(table, user, &resource,
                                       &tenant_col, &class_col, &sci_col)) return NULL;
    qihse_table_txn_t* txn =
        (qihse_table_txn_t*)calloc(1, sizeof(*txn));
    if (!txn) return NULL;

    pthread_rwlock_rdlock(&table->lock);
    bool allowed = table->generation != UINT64_MAX;
    if (user) {
        allowed = allowed && qihse_auth_user_is_active(user) &&
            qihse_auth_can_access_object(user, 0, resource, QIHSE_ACL_READ) &&
            (tenant_col >= 0 ||
             (qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM &&
              qihse_auth_can_access(user, 0, 0)));
        for (size_t r = 0; allowed && r < table->num_rows; ++r)
            if (table->rows[r] && !ts_transform_row_allowed(user,
                    table->rows[r], tenant_col, class_col, sci_col)) allowed = false;
    }
    if (!allowed) {
        pthread_rwlock_unlock(&table->lock);
        free(txn);
        return NULL;
    }
    qihse_col_value_t** rows =
        ts_dup_rows(table->rows, table->num_rows, table->num_cols);
    if (table->num_rows > 0 && !rows) {
        pthread_rwlock_unlock(&table->lock);
        free(txn);
        return NULL;
    }
    txn->table = table;
    txn->base_generation = table->generation;
    txn->shadow.generation = table->generation;
    txn->shadow.cols = table->cols;
    txn->shadow.num_cols = table->num_cols;
    txn->shadow.rows = rows;
    txn->shadow.num_rows = table->num_rows;
    txn->shadow.cap_rows = table->num_rows;
    txn->shadow.num_tomb = table->num_tomb;
    pthread_rwlock_unlock(&table->lock);
    return txn;
}

qihse_table_txn_t* qihse_table_txn_begin(qihse_table_t* table) {
    return ts_txn_begin_context(table, NULL);
}

qihse_table_txn_t* qihse_table_txn_begin_user(qihse_table_t* table,
                                              const qihse_user_t* user) {
    return user ? ts_txn_begin_context(table, user) : NULL;
}

int qihse_table_txn_insert(qihse_table_txn_t* txn,
                           const qihse_col_value_t* values,
                           size_t num_values) {
    if (!txn || !values) return -1;
    qihse_table_t* shadow = &txn->shadow;
    if (shadow->generation == UINT64_MAX) return -1;
    if (!ts_values_match_schema(shadow->cols, shadow->num_cols, values,
                                num_values)) return -1;
    qihse_col_value_t* row =
        ts_dup_row(values, num_values, shadow->num_cols);
    if (!row) return -1;

    size_t slot = shadow->num_rows;
    if (shadow->num_tomb > 0) {
        for (size_t i = 0; i < shadow->num_rows; i++) {
            if (!shadow->rows[i]) { slot = i; break; }
        }
    }
    if (slot >= shadow->num_rows) {
        if (!ts_ensure_cap(shadow, shadow->num_rows + 1)) {
            ts_free_row(row, shadow->num_cols);
            return -1;
        }
        slot = shadow->num_rows++;
    } else {
        shadow->num_tomb--;
    }
    shadow->rows[slot] = row;
    ++shadow->generation;
    return (int)slot;
}

static bool ts_assign_value(qihse_col_value_t* cell,
                            const qihse_col_value_t* value) {
    qihse_col_def_t column = {.type = cell->type};
    if (!ts_values_match_schema(&column, 1, value, 1) ||
        (ts_string_type(value->type) && !value->is_null && !value->v.str))
        return false;
    char* string_copy = NULL;
    if ((value->type == QIHSE_TS_STRING || value->type == QIHSE_TS_UUID ||
         value->type == QIHSE_TS_JSONB || value->type == QIHSE_TS_NUMERIC ||
         value->type == QIHSE_TS_TSVECTOR) && !value->is_null && value->v.str) {
        string_copy = strdup(value->v.str);
        if (!string_copy) return false;
    }
    ts_free_col_value(cell);
    cell->type = value->type;
    cell->is_null = value->is_null;
    if (value->is_null) return true;
    switch (value->type) {
        case QIHSE_TS_INT32: cell->v.i32 = value->v.i32; break;
        case QIHSE_TS_INT64: cell->v.i64 = value->v.i64; break;
        case QIHSE_TS_FLOAT: cell->v.f32 = value->v.f32; break;
        case QIHSE_TS_STRING:
        case QIHSE_TS_UUID:
        case QIHSE_TS_JSONB:
        case QIHSE_TS_NUMERIC:
        case QIHSE_TS_TSVECTOR: cell->v.str = string_copy; break;
        case QIHSE_TS_BOOLEAN: cell->v.boolean = value->v.boolean; break;
        case QIHSE_TS_TIMESTAMPTZ: cell->v.timestamptz_us = value->v.timestamptz_us; break;
        default:
            free(string_copy);
            return false;
    }
    return true;
}

int qihse_table_txn_update(qihse_table_txn_t* txn,
                           int (*pred)(const qihse_col_value_t*, size_t,
                                       void*),
                           void* pred_ctx,
                           const int* update_cols,
                           const qihse_col_value_t* new_values,
                           size_t num_updates) {
    if (!txn || !pred || !update_cols || !new_values || num_updates == 0)
        return -1;
    qihse_table_t* shadow = &txn->shadow;
    if (shadow->generation == UINT64_MAX) return -1;
    for (size_t u = 0; u < num_updates; ++u) {
        int col = update_cols[u];
        if (col < 0 || (size_t)col >= shadow->num_cols ||
            new_values[u].type != shadow->cols[col].type) return -1;
    }
    qihse_col_value_t** candidate =
        ts_dup_rows(shadow->rows, shadow->num_rows, shadow->num_cols);
    if (shadow->num_rows > 0 && !candidate) return -1;

    bool any = false;
    for (size_t i = 0; i < shadow->num_rows; i++) {
        if (!candidate[i] ||
            !pred(candidate[i], shadow->num_cols, pred_ctx)) continue;
        for (size_t u = 0; u < num_updates; u++) {
            int col = update_cols[u];
            if (col < 0 || (size_t)col >= shadow->num_cols) continue;
            if (!ts_assign_value(&candidate[i][col], &new_values[u])) {
                ts_free_rows(candidate, shadow->num_rows, shadow->num_cols);
                return -1;
            }
        }
        any = true;
    }
    if (!any) {
        ts_free_rows(candidate, shadow->num_rows, shadow->num_cols);
        return 0;
    }
    ts_free_rows(shadow->rows, shadow->num_rows, shadow->num_cols);
    shadow->rows = candidate;
    shadow->cap_rows = shadow->num_rows;
    ++shadow->generation;
    return 1;
}

static bool ts_transform_row_allowed(const qihse_user_t* user,
    const qihse_col_value_t* row, int tenant_col, int class_col, int sci_col) {
    if (tenant_col < 0) return qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM &&
                               qihse_auth_can_access(user, 0, 0);
    const qihse_col_value_t* t = &row[tenant_col];
    const qihse_col_value_t* c = &row[class_col];
    const qihse_col_value_t* s = &row[sci_col];
    if (t->is_null || c->is_null || s->is_null || t->v.i32 < 0 ||
        c->v.i32 < 0 || c->v.i32 > UINT16_MAX ||
        s->v.i32 < 0 || s->v.i32 > UINT16_MAX) return false;
    uint32_t tenant = qihse_user_get_tenant_id(user);
    return (tenant == QIHSE_TENANT_SYSTEM || tenant == (uint32_t)t->v.i32) &&
        qihse_auth_can_access(user, (uint16_t)c->v.i32, (uint16_t)s->v.i32);
}

int qihse_table_txn_transform(qihse_table_txn_t* txn, const qihse_user_t* user,
    int (*pred)(const qihse_col_value_t*, size_t, void*), void* pred_ctx,
    qihse_table_row_transform transform, void* transform_ctx) {
    if (!txn || !user || !qihse_auth_user_is_active(user) || !pred || !transform)
        return -1;
    qihse_table_t* shadow = &txn->shadow;
    if (shadow->generation == UINT64_MAX) return -1;
    int tenant_col = qihse_table_find_col(shadow, "__qihse_tenant_id");
    int class_col = qihse_table_find_col(shadow, "__qihse_classification");
    int sci_col = qihse_table_find_col(shadow, "__qihse_sci");
    bool labeled = tenant_col >= 0 && class_col >= 0 && sci_col >= 0;
    if ((!labeled && (tenant_col >= 0 || class_col >= 0 || sci_col >= 0)) ||
        (!labeled && qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM) ||
        (labeled && (shadow->cols[tenant_col].type != QIHSE_TS_INT32 ||
                     shadow->cols[class_col].type != QIHSE_TS_INT32 ||
                     shadow->cols[sci_col].type != QIHSE_TS_INT32))) return -1;
    uint32_t resource = 2166136261u;
    for (const unsigned char* p = (const unsigned char*)txn->table->name; *p; ++p)
        resource = (resource ^ *p) * 16777619u;
    if (!qihse_auth_can_access_object(user, 0, resource,
                                      QIHSE_ACL_READ | QIHSE_ACL_WRITE))
        return -1;
    qihse_col_value_t** candidate = ts_dup_rows(shadow->rows,
        shadow->num_rows, shadow->num_cols);
    if (shadow->num_rows && !candidate) return -1;
    qihse_col_value_t* output = calloc(shadow->num_cols, sizeof(*output));
    if (!output) { ts_free_rows(candidate, shadow->num_rows, shadow->num_cols); return -1; }
    bool changed = false, valid = true;
    for (size_t i = 0; i < shadow->num_rows && valid; ++i) {
        qihse_col_value_t* old = candidate[i];
        if (!old || !ts_transform_row_allowed(user, old, tenant_col, class_col, sci_col) ||
            !pred(old, shadow->num_cols, pred_ctx)) continue;
        memcpy(output, old, shadow->num_cols * sizeof(*output));
        if (!transform(old, shadow->num_cols, output, transform_ctx) ||
            !ts_values_match_schema(shadow->cols, shadow->num_cols,
                                    output, shadow->num_cols) ||
            !ts_transform_row_allowed(user, output, tenant_col, class_col, sci_col)) {
            valid = false; break;
        }
        qihse_col_value_t* replacement = ts_dup_row(output,
            shadow->num_cols, shadow->num_cols);
        if (!replacement) { valid = false; break; }
        ts_free_row(old, shadow->num_cols);
        candidate[i] = replacement;
        changed = true;
    }
    free(output);
    if (!valid || !changed) {
        ts_free_rows(candidate, shadow->num_rows, shadow->num_cols);
        return valid ? 0 : -1;
    }
    ts_free_rows(shadow->rows, shadow->num_rows, shadow->num_cols);
    shadow->rows = candidate;
    shadow->cap_rows = shadow->num_rows;
    ++shadow->generation;
    return 1;
}

bool qihse_table_txn_delete(qihse_table_txn_t* txn,
                            int (*pred)(const qihse_col_value_t*, size_t,
                                        void*),
                            void* pred_ctx) {
    if (!txn || !pred) return false;
    qihse_table_t* shadow = &txn->shadow;
    if (shadow->generation == UINT64_MAX) return false;
    bool any = false;
    for (size_t i = 0; i < shadow->num_rows; i++) {
        if (!shadow->rows[i] ||
            !pred(shadow->rows[i], shadow->num_cols, pred_ctx)) continue;
        ts_free_row(shadow->rows[i], shadow->num_cols);
        shadow->rows[i] = NULL;
        shadow->num_tomb++;
        any = true;
    }
    if (any && shadow->cap_rows > 0 &&
        shadow->num_tomb * 4 >= shadow->cap_rows)
        ts_compact(shadow);
    if (any) ++shadow->generation;
    return any;
}

size_t qihse_table_txn_row_count(const qihse_table_txn_t* txn) {
    return txn ? txn->shadow.num_rows - txn->shadow.num_tomb : 0;
}

void qihse_table_txn_scan(const qihse_table_txn_t* txn,
                          qihse_table_row_cb cb, void* ctx) {
    if (!txn || !cb) return;
    for (size_t i = 0; i < txn->shadow.num_rows; i++) {
        if (!txn->shadow.rows[i]) continue;
        if (!cb(txn->shadow.rows[i], txn->shadow.num_cols, ctx)) break;
    }
}

bool qihse_table_txn_scan_ids_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, qihse_table_row_id_cb cb, void* ctx) {
    if (!txn || !cb) return false;
    uint32_t resource = 0;
    int tenant_col, class_col, sci_col;
    if (!ts_table_read_context(txn->table, user, &resource,
                               &tenant_col, &class_col, &sci_col)) return false;
    for (size_t i = 0; i < txn->shadow.num_rows; ++i) {
        const qihse_col_value_t* row = txn->shadow.rows[i];
        if (!row) continue;
        if (!qihse_auth_user_is_active(user) || !qihse_auth_can_access_object(
                user, 0, resource, QIHSE_ACL_READ)) return false;
        if (!ts_transform_row_allowed(user, row, tenant_col, class_col, sci_col))
            continue;
        if (!cb(i, row, txn->shadow.num_cols, ctx)) break;
    }
    return true;
}

bool qihse_table_txn_generation_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, uint64_t* generation) {
    uint32_t resource = 0;
    int tenant_col, class_col, sci_col;
    if (!txn || !generation || !ts_table_read_context(txn->table, user,
         &resource, &tenant_col, &class_col, &sci_col) ||
        !qihse_auth_user_is_active(user) || !qihse_auth_can_access_object(
            user, 0, resource, QIHSE_ACL_READ)) return false;
    *generation = txn->shadow.generation;
    return true;
}

bool qihse_table_txn_row_get_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, uint64_t generation, size_t row_id,
    qihse_table_row_cb cb, void* ctx) {
    uint32_t resource = 0;
    int tenant_col, class_col, sci_col;
    if (!txn || !cb || !ts_table_read_context(txn->table, user, &resource,
                               &tenant_col, &class_col, &sci_col) ||
        generation != txn->shadow.generation || row_id >= txn->shadow.num_rows ||
        !txn->shadow.rows[row_id] || !qihse_auth_user_is_active(user) ||
        !qihse_auth_can_access_object(user, 0, resource, QIHSE_ACL_READ) ||
        !ts_transform_row_allowed(user, txn->shadow.rows[row_id],
                                  tenant_col, class_col, sci_col)) return false;
    (void)cb(txn->shadow.rows[row_id], txn->shadow.num_cols, ctx);
    return true;
}

bool qihse_table_txn_scan_user(const qihse_table_txn_t* txn,
    const qihse_user_t* user, qihse_table_row_cb cb, void* ctx) {
    if (!cb) return false;
    ts_plain_scan_t scan = {cb, ctx};
    return qihse_table_txn_scan_ids_user(txn, user, ts_plain_scan_row, &scan);
}

static int ts_group_item_cmp(const void* a, const void* b) {
    const ts_group_item_t* ia = (const ts_group_item_t*)a;
    const ts_group_item_t* ib = (const ts_group_item_t*)b;
    uintptr_t pa = (uintptr_t)ia->table;
    uintptr_t pb = (uintptr_t)ib->table;
    return pa < pb ? -1 : pa > pb ? 1 : 0;
}

static void ts_group_destroy_unique(qihse_table_txn_t** txns, size_t count) {
    if (!txns) return;
    for (size_t i = 0; i < count; ++i) {
        if (!txns[i]) continue;
        bool seen = false;
        for (size_t j = 0; j < i; ++j)
            if (txns[j] == txns[i]) { seen = true; break; }
        if (!seen) ts_txn_destroy(txns[i]);
    }
}

static qihse_ts_retry_status_t ts_commit_group(qihse_table_txn_t** txns,
    size_t count, const qihse_ts_retry_identity_t* id,
    qihse_ts_retry_outcome_t* outcome, bool read_only) {
    if (!txns || count == 0 || count > SIZE_MAX / sizeof(ts_group_item_t) ||
        (id && (!outcome || !ts_retry_valid(id))) || (read_only && id))
        return QIHSE_TS_RETRY_ERROR;
    ts_group_item_t* items = (ts_group_item_t*)calloc(count, sizeof(*items));
    if (!items) {
        ts_group_destroy_unique(txns, count);
        return QIHSE_TS_RETRY_ERROR;
    }

    bool valid = true;
    for (size_t i = 0; i < count; ++i) {
        if (!txns[i] || !txns[i]->table) { valid = false; break; }
        items[i].txn = txns[i];
        items[i].table = txns[i]->table;
        for (size_t j = 0; j < i; ++j) {
            if (txns[j] == txns[i] || items[j].table == items[i].table) {
                valid = false;
                break;
            }
        }
        if (!valid) break;
    }
    if (!valid) {
        free(items);
        ts_group_destroy_unique(txns, count);
        return QIHSE_TS_RETRY_ERROR;
    }

    qihse_table_store_t* store = items[0].table->owner;
    bool durable = store->path != NULL;
    for (size_t i = 1; i < count; ++i) {
        if (items[i].table->owner != store &&
            (durable || items[i].table->owner->path)) {
            ts_group_destroy_unique(txns, count);
            free(items);
            return QIHSE_TS_RETRY_ERROR;
        }
    }
    if (id && !durable) {
        ts_group_destroy_unique(txns, count);
        free(items);
        return QIHSE_TS_RETRY_ERROR;
    }
    if (durable && store->owner_pid != getpid()) {
        ts_group_destroy_unique(txns, count);
        free(items);
        return QIHSE_TS_RETRY_ERROR;
    }
    qsort(items, count, sizeof(*items), ts_group_item_cmp);
    for (size_t i = 0; i < count; ++i)
        pthread_rwlock_wrlock(&items[i].table->lock);
    /* Schema creation holds mutex but never waits on table locks. */
    if (durable) pthread_mutex_lock(&store->mutex);
    qihse_ts_retry_status_t existing = QIHSE_TS_RETRY_ABSENT;
    if (id && !store->poisoned) existing = ts_retry_find(store, id, outcome);
    if (id && (store->poisoned || existing != QIHSE_TS_RETRY_ABSENT)) {
        for (size_t j = count; j > 0; --j)
            pthread_rwlock_unlock(&items[j - 1].table->lock);
        pthread_mutex_unlock(&store->mutex);
        ts_group_destroy_unique(txns, count);
        free(items);
        return store->poisoned ? QIHSE_TS_RETRY_ERROR : existing;
    }

    for (size_t i = 0; i < count; ++i) {
        if (items[i].table->generation != items[i].txn->base_generation) {
            for (size_t j = count; j > 0; --j)
                pthread_rwlock_unlock(&items[j - 1].table->lock);
            if (durable) pthread_mutex_unlock(&store->mutex);
            ts_group_destroy_unique(txns, count);
            free(items);
            return QIHSE_TS_RETRY_ABSENT;
        }
    }
    if (read_only) {
        bool ready = !durable || !store->poisoned;
        for (size_t j = count; j > 0; --j)
            pthread_rwlock_unlock(&items[j - 1].table->lock);
        if (durable) pthread_mutex_unlock(&store->mutex);
        ts_group_destroy_unique(txns, count);
        free(items);
        return ready ? QIHSE_TS_RETRY_COMMITTED : QIHSE_TS_RETRY_ERROR;
    }
    ts_retry_entry_t entry = {0};
    if (id) {
        if (store->num_retries == TS_RETRY_MAX_ENTRIES) {
            for (size_t j = count; j > 0; --j)
                pthread_rwlock_unlock(&items[j - 1].table->lock);
            pthread_mutex_unlock(&store->mutex);
            ts_group_destroy_unique(txns, count);
            free(items);
            return QIHSE_TS_RETRY_ERROR;
        }
        if (store->num_retries == store->cap_retries) {
            size_t cap = store->cap_retries ? store->cap_retries * 2 : 16;
            if (cap > TS_RETRY_MAX_ENTRIES) cap = TS_RETRY_MAX_ENTRIES;
            ts_retry_entry_t* grown = realloc(store->retries, cap * sizeof(*grown));
            if (!grown) {
                for (size_t j = count; j > 0; --j)
                    pthread_rwlock_unlock(&items[j - 1].table->lock);
                pthread_mutex_unlock(&store->mutex);
                ts_group_destroy_unique(txns, count);
                free(items);
                return QIHSE_TS_RETRY_ERROR;
            }
            store->retries = grown;
            store->cap_retries = cap;
        }
        strcpy(entry.key, id->key);
        strcpy(entry.principal, id->principal);
        strcpy(entry.tenant, id->tenant);
        memcpy(entry.digest, id->digest, sizeof entry.digest);
        entry.outcome = *outcome;
    }
    if (durable && (store->poisoned ||
                    !ts_persist(store, items, count, id ? &entry : NULL))) {
        for (size_t j = count; j > 0; --j)
            pthread_rwlock_unlock(&items[j - 1].table->lock);
        pthread_mutex_unlock(&store->mutex);
        ts_group_destroy_unique(txns, count);
        free(items);
        return QIHSE_TS_RETRY_ERROR;
    }
    if (id) store->retries[store->num_retries++] = entry;

    for (size_t i = 0; i < count; ++i) {
        qihse_table_t* table = items[i].table;
        qihse_table_txn_t* txn = items[i].txn;
        items[i].old_rows = table->rows;
        items[i].old_num_rows = table->num_rows;
        table->rows = txn->shadow.rows;
        table->num_rows = txn->shadow.num_rows;
        table->cap_rows = txn->shadow.cap_rows;
        table->num_tomb = txn->shadow.num_tomb;
        table->generation++;
        txn->shadow.rows = NULL;
        txn->shadow.num_rows = 0;
    }
    for (size_t i = count; i > 0; --i)
        pthread_rwlock_unlock(&items[i - 1].table->lock);
    if (durable) pthread_mutex_unlock(&store->mutex);

    for (size_t i = 0; i < count; ++i) {
        ts_free_rows(items[i].old_rows, items[i].old_num_rows,
                     items[i].table->num_cols);
        free(items[i].txn);
    }
    free(items);
    return QIHSE_TS_RETRY_COMMITTED;
}

bool qihse_table_txn_commit_group(qihse_table_txn_t** txns, size_t count) {
    return ts_commit_group(txns, count, NULL, NULL, false) == QIHSE_TS_RETRY_COMMITTED;
}

bool qihse_table_txn_validate_group(qihse_table_txn_t** txns, size_t count) {
    return ts_commit_group(txns, count, NULL, NULL, true) == QIHSE_TS_RETRY_COMMITTED;
}

qihse_ts_retry_status_t qihse_table_txn_commit_group_retry(
    qihse_table_txn_t** txns, size_t count,
    const qihse_ts_retry_identity_t* id, qihse_ts_retry_outcome_t* outcome) {
    if (!ts_retry_valid(id) || !outcome) {
        if (txns && count) ts_group_destroy_unique(txns, count);
        return QIHSE_TS_RETRY_ERROR;
    }
    return ts_commit_group(txns, count, id, outcome, false);
}

bool qihse_table_txn_commit(qihse_table_txn_t* txn) {
    qihse_table_txn_t* one[1] = {txn};
    return qihse_table_txn_commit_group(one, 1);
}

void qihse_table_txn_rollback(qihse_table_txn_t* txn) {
    ts_txn_destroy(txn);
}

/* -------------------------------------------------------------------------
 * Introspection
 * ------------------------------------------------------------------------- */

size_t qihse_table_num_cols(const qihse_table_t* table) {
    return table ? table->num_cols : 0;
}

const qihse_col_def_t* qihse_table_col_def(const qihse_table_t* table,
                                           size_t idx) {
    if (!table || idx >= table->num_cols) return NULL;
    return &table->cols[idx];
}

int qihse_table_find_col(const qihse_table_t* table, const char* name) {
    if (!table || !name) return -1;
    for (size_t i = 0; i < table->num_cols; i++) {
        if (table->cols[i].name && strcmp(table->cols[i].name, name) == 0)
            return (int)i;
    }
    return -1;
}

const char* qihse_table_name(const qihse_table_t* table) {
    return table ? table->name : NULL;
}
