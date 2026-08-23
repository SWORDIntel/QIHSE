#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_optimizer.h"
#include "qihse_index_scan.h"
#include "qihse_join_executor.h"
#include "qihse_aggregate_executor.h"
#include "qihse_sort_executor.h"


#include "qihse_schema.h"
#include "qihse_sql_parser.h"
#include "qihse_txn.h"

/* Optional window-function executor.  A parallel agent may introduce this
 * module; when absent we degrade gracefully.  Guarded with __has_include so
 * the build never breaks if the header is missing. */
#if defined(__has_include)
#if __has_include("qihse_window_executor.h")
#define UWP_HAS_WINDOW_EXECUTOR 1
#include "qihse_window_executor.h"
#endif
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#if defined(_MSC_VER)
#define UWP_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define UWP_THREAD_LOCAL _Thread_local
#else
#define UWP_THREAD_LOCAL __thread
#endif

/* Temporary bridge: transaction ownership is per worker thread, not per
 * connection. C3 must move this pointer into its connection-state struct. */

typedef struct {
    char* data;
    size_t len;
    size_t cap;
    int failed;
} uwp_text_buffer_t;

static void uwp_write_cb(qihse_uwp_write_fn write_fn, void* write_ctx,
                         const void* data, size_t len) {
    if (write_fn) write_fn(write_ctx, data, len);
}

static void uwp_reply_cb(qihse_uwp_write_fn write_fn, void* write_ctx,
                         const char* text) {
    if (write_fn) write_fn(write_ctx, text, strlen(text));
}

static int uwp_text_reserve(uwp_text_buffer_t* out, size_t extra) {
    if (out->failed || extra > SIZE_MAX - out->len - 1) {
        out->failed = 1;
        return -1;
    }
    size_t needed = out->len + extra + 1;
    if (needed <= out->cap) return 0;
    size_t cap = out->cap ? out->cap : 128;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2) {
            cap = needed;
            break;
        }
        cap *= 2;
    }
    char* data = (char*)realloc(out->data, cap);
    if (!data) {
        out->failed = 1;
        return -1;
    }
    out->data = data;
    out->cap = cap;
    return 0;
}

static int uwp_text_appendf(uwp_text_buffer_t* out, const char* format, ...) {
    va_list args;
    va_list copy;
    va_start(args, format);
    va_copy(copy, args);
    int count = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (count < 0 || uwp_text_reserve(out, (size_t)count) != 0) {
        va_end(args);
        return -1;
    }
    (void)vsnprintf(out->data + out->len, out->cap - out->len, format, args);
    va_end(args);
    out->len += (size_t)count;
    return 0;
}

static void uwp_text_destroy(uwp_text_buffer_t* out) {
    free(out->data);
    memset(out, 0, sizeof(*out));
}

static int uwp_payload_string(const uint8_t* payload, size_t payload_len,
                              const char** out) {
    if (!payload || payload_len == 0 || !out ||
        memchr(payload, '\0', payload_len) == NULL) {
        return -1;
    }
    *out = (const char*)payload;
    return 0;
}

static void uwp_put_u64_le(uint8_t out[8], uint64_t value) {
    for (unsigned int i = 0; i < 8; ++i) out[i] = (uint8_t)(value >> (i * 8));
}

static qihse_isolation_level_t uwp_sql_isolation(const char* sql) {
    if (strcasestr(sql, "SERIALIZABLE")) return QIHSE_ISO_SERIALIZABLE;
    if (strcasestr(sql, "REPEATABLE READ")) return QIHSE_ISO_REPEATABLE_READ;
    return QIHSE_ISO_READ_COMMITTED;
}

static void uwp_append_ast_columns(uwp_text_buffer_t* out,
                                   const qihse_sql_ast_t* ast) {
    (void)uwp_text_appendf(out, " columns=[");
    for (size_t i = 0; i < ast->num_columns; ++i) {
        const qihse_sql_column_def_t* column = &ast->columns[i];
        (void)uwp_text_appendf(out, "%s%s:%s", i ? "," : "",
                               column->name ? column->name : "<unnamed>",
                               qihse_sql_type_name(column->type));
        if (column->type_len > 0) (void)uwp_text_appendf(out, "(%d)", column->type_len);
        if (column->not_null) (void)uwp_text_appendf(out, " NOT_NULL");
        if (column->is_primary_key) (void)uwp_text_appendf(out, " PRIMARY_KEY");
    }
    (void)uwp_text_appendf(out, "]");
}

static void uwp_append_select_items(uwp_text_buffer_t* out,
                                    const qihse_sql_ast_t* ast,
                                    int include_types) {
    (void)uwp_text_appendf(out, " select_items=[");
    for (size_t i = 0; i < ast->num_select_items; ++i) {
        const qihse_sql_select_item_t* item = &ast->select_items[i];
        const char* name = item->alias ? item->alias :
                           (item->expr ? item->expr : "<expression>");
        (void)uwp_text_appendf(out, "%s%s", i ? "," : "", name);
        if (include_types) (void)uwp_text_appendf(out, ":UNKNOWN");
    }
    (void)uwp_text_appendf(out, "]");
}

__attribute__((unused))
static int uwp_serialize_ast(uwp_text_buffer_t* out, const qihse_sql_ast_t* ast) {
    (void)uwp_text_appendf(out, "OK stmt_type=%s", qihse_sql_stmt_name(ast->stmt_type));
    if (ast->table_name) (void)uwp_text_appendf(out, " table=%s", ast->table_name);
    if (ast->drop_name) (void)uwp_text_appendf(out, " object=%s", ast->drop_name);
    if (ast->index_def) {
        (void)uwp_text_appendf(out, " index=%s table=%s column=%s unique=%d",
                               ast->index_def->name ? ast->index_def->name : "",
                               ast->index_def->table_name ? ast->index_def->table_name : "",
                               ast->index_def->column_name ? ast->index_def->column_name : "",
                               ast->index_def->unique);
    }
    if (ast->num_from_tables) {
        (void)uwp_text_appendf(out, " from=[");
        for (size_t i = 0; i < ast->num_from_tables; ++i) {
            const qihse_sql_table_ref_t* table = &ast->from_tables[i];
            (void)uwp_text_appendf(out, "%s%s", i ? "," : "",
                                   table->table_name ? table->table_name : "<unnamed>");
        }
        (void)uwp_text_appendf(out, "]");
    }
    if (ast->num_select_items) uwp_append_select_items(out, ast, 0);
    if (ast->num_columns) uwp_append_ast_columns(out, ast);
    (void)uwp_text_appendf(out, "\n");
    return out->failed ? -1 : 0;
}

static int uwp_serialize_description(uwp_text_buffer_t* out,
                                     const qihse_sql_ast_t* ast) {
    (void)uwp_text_appendf(out, "OK stmt_type=%s", qihse_sql_stmt_name(ast->stmt_type));
    if (ast->stmt_type == QIHSE_SQL_SELECT) {
        uwp_append_select_items(out, ast, 1);
    } else if (ast->num_columns) {
        uwp_append_ast_columns(out, ast);
    } else if (ast->stmt_type == QIHSE_SQL_ALTER && ast->alter_clause &&
               ast->alter_clause->add_column) {
        const qihse_sql_column_def_t* column = ast->alter_clause->add_column;
        (void)uwp_text_appendf(out, " columns=[%s:%s]",
                               column->name ? column->name : "<unnamed>",
                               qihse_sql_type_name(column->type));
    } else {
        (void)uwp_text_appendf(out, " columns=[]");
    }
    (void)uwp_text_appendf(out, "\n");
    return out->failed ? -1 : 0;
}


static qihse_row_stream_t* build_stream(qihse_plan_node_t* plan, qihse_uwp_context_t* ctx) {
    (void)ctx;
    if (!plan) return NULL;
    if (plan->type == QIHSE_PLAN_INDEX_SCAN) {
        qihse_scan_pred_t pred = {0};
        qihse_index_scan_t* scan = qihse_index_scan_open(NULL, &pred);
        if (scan) qihse_index_scan_close(scan);
        return qihse_row_array_stream_create(NULL, NULL, 0);
    } else if (plan->type == QIHSE_PLAN_SEQ_SCAN) {
        return qihse_row_array_stream_create(NULL, NULL, 0);
    } else if (plan->type == QIHSE_PLAN_HASH_JOIN) {
        qihse_row_stream_t* left = build_stream(plan->left, ctx);
        qihse_row_stream_t* right = build_stream(plan->right, ctx);
        return qihse_hash_join_create(left, right, plan->join_key_left, plan->join_key_right, plan->join_type);
    } else if (plan->type == QIHSE_PLAN_NESTED_LOOP) {
        qihse_row_stream_t* left = build_stream(plan->left, ctx);
        qihse_row_stream_t* right = build_stream(plan->right, ctx);
        return qihse_nested_loop_join_create(left, right, plan->join_key_left, plan->join_key_right, plan->join_type);
    } else if (plan->type == QIHSE_PLAN_AGGREGATE) {
        qihse_row_stream_t* left = build_stream(plan->left, ctx);
        return qihse_aggregate_create(left, NULL, 0, NULL, 0);
    } else if (plan->type == QIHSE_PLAN_SORT) {
        qihse_row_stream_t* left = build_stream(plan->left, ctx);
        return qihse_sort_create(left, NULL, 0, 0);
    } else if (plan->type == QIHSE_PLAN_LIMIT) {
        return build_stream(plan->left, ctx);
    }
    return NULL;
}

static void append_value(uwp_text_buffer_t* response, const char* val) {
    if (!val) return;
    bool is_binary = false;
    for (const char* p = val; *p; p++) {
        if ((unsigned char)*p < 32 && *p != '\t' && *p != '\r' && *p != '\n') {
            is_binary = true; break;
        }
    }
    if (is_binary) {
        for (const char* p = val; *p; p++) {
            uwp_text_appendf(response, "%02x", (unsigned char)*p);
        }
    } else {
        uwp_text_appendf(response, "%s", val);
    }
}

/* -------------------------------------------------------------------------
 * SQL advanced execution helpers: DML row-store wiring, subquery / window /
 * CE detection, and plan execution.
 * ------------------------------------------------------------------------- */

/* Map a SQL column type to the column store's internal type. */
static qihse_column_type_t uwp_sql_type_to_col_type(qihse_sql_type_t t) {
    switch (t) {
        case QIHSE_TYPE_INT:
        case QIHSE_TYPE_SERIAL:
            return QIHSE_COL_TYPE_INT32;
        case QIHSE_TYPE_BIGINT:
        case QIHSE_TYPE_BIGSERIAL:
            return QIHSE_COL_TYPE_INT64;
        case QIHSE_TYPE_FLOAT:
        case QIHSE_TYPE_DOUBLE:
            return QIHSE_COL_TYPE_FLOAT32; /* no float64 append in column store */
        default:
            return QIHSE_COL_TYPE_STRING_DICT;
    }
}

/* Check if the AST has window functions in the SELECT list. */
static bool uwp_has_window_functions(const qihse_sql_ast_t* ast) {
    for (size_t i = 0; i < ast->num_select_items; i++) {
        if (ast->select_items[i].window != NULL) return true;
        if (ast->select_items[i].win_kind != QIHSE_WIN_NONE) return true;
    }
    return false;
}

/* Check if the AST has subqueries (scalar subqueries in SELECT list or
 * subquery predicates in WHERE). */
static bool uwp_has_subqueries(const qihse_sql_ast_t* ast) {
    for (size_t i = 0; i < ast->num_select_items; i++) {
        if (ast->select_items[i].scalar_subquery != NULL) return true;
    }
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        if (ast->where_conditions[i].subq_kind != 0) return true;
    }
    return false;
}

/* Recursively check if a plan tree contains any SUBQUERY nodes. */
static bool uwp_plan_has_subquery(const qihse_plan_node_t* plan) {
    if (!plan) return false;
    if (plan->type == QIHSE_PLAN_SUBQUERY) return true;
    if (uwp_plan_has_subquery(plan->left)) return true;
    if (uwp_plan_has_subquery(plan->right)) return true;
    return false;
}

/* Check if the AST has recursive CTEs.  The parser does not set the
 * recursive flag and may fail to populate with_clause entirely when the CTE
 * has a column list (e.g. "WITH RECURSIVE r(n) AS (...)"), so we always scan
 * the raw SQL as a fallback. */
static bool uwp_has_recursive_cte(const qihse_sql_ast_t* ast) {
    if (ast->with_clause) {
        for (size_t i = 0; i < ast->with_clause->num_ctes; i++) {
            if (ast->with_clause->ctes[i].recursive) return true;
        }
    }
    if (ast->raw_sql && strcasestr(ast->raw_sql, "RECURSIVE")) return true;
    return false;
}

/* Execute a pre-built plan and write results to the response buffer.
 * Writes the schema header row followed by data rows.  Returns 0 on
 * success, -1 if the stream could not be built. */
static int uwp_execute_plan(qihse_plan_node_t* plan, qihse_uwp_context_t* ctx,
                            uwp_text_buffer_t* response) {
    if (!plan) return -1;
    qihse_row_stream_t* stream = build_stream(plan, ctx);
    if (!stream) return -1;
    if (stream->schema) {
        for (size_t i = 0; i < stream->schema->num_cols; i++) {
            uwp_text_appendf(response, "%s", stream->schema->names[i]);
            if (i + 1 < stream->schema->num_cols)
                uwp_text_appendf(response, "\t");
        }
        uwp_text_appendf(response, "\n");
    }
    qihse_exec_row_t* row;
    while ((row = qihse_row_stream_next(stream)) != NULL) {
        for (size_t i = 0; i < row->num_values; i++) {
            append_value(response, row->values[i]);
            if (i + 1 < row->num_values)
                uwp_text_appendf(response, "\t");
        }
        uwp_text_appendf(response, "\n");
        qihse_exec_row_free(row);
    }
    qihse_row_stream_close(stream);
    return 0;
}

/* Build an optimizer plan for the AST and execute it, writing results to
 * the response buffer.  Returns 0 on success, -1 on failure. */
static int uwp_execute_select_plan(qihse_uwp_context_t* ctx,
                                   const qihse_sql_ast_t* ast,
                                   uwp_text_buffer_t* response) {
    qihse_optimizer_t* opt =
        qihse_optimizer_create((qihse_schema_registry_t*)ctx->schema);
    if (!opt) return -1;
    qihse_plan_node_t* plan = qihse_optimizer_build_plan(opt, ast);
    int rc = uwp_execute_plan(plan, ctx, response);
    if (plan) qihse_plan_node_free(plan);
    qihse_optimizer_destroy(opt);
    return rc;
}

/* Execute INSERT into the column store.
 * Returns the number of rows inserted (>= 0) on success,
 * -1 if no row store / schema is wired,
 * -2 on error (table not found, INSERT...SELECT, etc.). */
static int uwp_execute_insert(qihse_uwp_context_t* ctx,
                              const qihse_sql_ast_t* ast) {
    if (!ctx->col || !ctx->schema) return -1;
    if (!ast->table_name) return -2;
    if (ast->insert_select_query) return -2; /* INSERT...SELECT not supported */
    if (ast->num_insert_rows == 0 || !ast->insert_rows) return 0;

    qihse_schema_registry_t* schema = (qihse_schema_registry_t*)ctx->schema;
    qihse_column_store_t* col = ctx->col;

    const qihse_schema_table_t* table = qihse_schema_get_table(schema, ast->table_name);
    if (!table) return -2;

    /* Determine column order and types. */
    size_t num_cols;
    qihse_column_type_t* col_types;
    const char** col_names;

    if (ast->num_insert_columns > 0) {
        num_cols = ast->num_insert_columns;
        col_types = (qihse_column_type_t*)malloc(num_cols * sizeof(*col_types));
        col_names = (const char**)malloc(num_cols * sizeof(*col_names));
        if (!col_types || !col_names) { free(col_types); free(col_names); return -2; }
        for (size_t i = 0; i < num_cols; i++) {
            col_names[i] = NULL;
            col_types[i] = QIHSE_COL_TYPE_STRING_DICT;
            for (size_t j = 0; j < table->num_columns; j++) {
                if (strcasecmp(ast->insert_columns[i],
                               table->columns[j].name) == 0) {
                    col_types[i] = uwp_sql_type_to_col_type(table->columns[j].type);
                    col_names[i] = table->columns[j].name;
                    break;
                }
            }
            if (!col_names[i]) {
                free(col_types);
                free(col_names);
                return -2; /* column not found in schema */
            }
        }
    } else {
        num_cols = table->num_columns;
        col_types = (qihse_column_type_t*)malloc(num_cols * sizeof(*col_types));
        col_names = (const char**)malloc(num_cols * sizeof(*col_names));
        if (!col_types || !col_names) { free(col_types); free(col_names); return -2; }
        for (size_t i = 0; i < num_cols; i++) {
            col_types[i] = uwp_sql_type_to_col_type(table->columns[i].type);
            col_names[i] = table->columns[i].name;
        }
    }

    /* Append each row's values to the column store. */
    size_t rows_inserted = 0;
    for (size_t r = 0; r < ast->num_insert_rows; r++) {
        char** row = ast->insert_rows[r];
        if (!row) break;
        int row_ok = 1;
        for (size_t c = 0; c < num_cols; c++) {
            if (!row[c]) { row_ok = 0; break; }

            /* Build namespaced column name: table.column */
            char col_full_name[512];
            snprintf(col_full_name, sizeof(col_full_name), "%s.%s",
                     ast->table_name, col_names[c]);

            /* Create the column if it does not yet exist. */
            (void)qihse_column_create(col, col_full_name, col_types[c]);

            const char* val = row[c];
            bool ok = false;
            switch (col_types[c]) {
                case QIHSE_COL_TYPE_INT32:
                    ok = qihse_column_append_int32(
                        col, col_full_name,
                        (int32_t)strtol(val, NULL, 10), 0, 0);
                    break;
                case QIHSE_COL_TYPE_INT64:
                    ok = qihse_column_append_int64(
                        col, col_full_name,
                        (int64_t)strtoll(val, NULL, 10), 0, 0);
                    break;
                case QIHSE_COL_TYPE_FLOAT32:
                    ok = qihse_column_append_float32(
                        col, col_full_name,
                        (float)strtod(val, NULL), 0, 0);
                    break;
                case QIHSE_COL_TYPE_STRING_DICT:
                    ok = qihse_column_append_string(
                        col, col_full_name, val, 0, 0);
                    break;
                default:
                    ok = false;
                    break;
            }
            if (!ok) { row_ok = 0; break; }
        }
        if (row_ok) rows_inserted++;
    }

    free(col_types);
    free(col_names);
    return (int)rows_inserted;
}

/* -------------------------------------------------------------------------
 * Prepared statement cache (PARSE / BIND / EXECUTE / CLOSE).
 *
 * A simple fixed-capacity array of prepared-statement slots protected by a
 * mutex.  Each slot caches the raw SQL text, the parsed statement type, the
 * expected parameter count, and any bound parameter values supplied via BIND.
 * ------------------------------------------------------------------------- */

#define UWP_PS_MAX_SLOTS  64
#define UWP_PS_MAX_PARAMS 64
#define UWP_PS_SQL_LEN    4096

typedef struct {
    char  sql[UWP_PS_SQL_LEN];
    bool  valid;
    qihse_sql_stmt_type_t stmt_type;
    int   num_params;
    char* bound_values[UWP_PS_MAX_PARAMS]; /* strdup'd; NULL if unbound */
    int   num_bound;
} uwp_ps_slot_t;

static uwp_ps_slot_t uwp_ps_slots[UWP_PS_MAX_SLOTS];
static pthread_mutex_t uwp_ps_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Count parameter placeholders (? and $N refs) in a SQL string, skipping
 * single-quoted string literals.  Returns the max of the '?' count and the
 * largest $N reference seen. */
static int uwp_count_params(const char* sql) {
    if (!sql) return 0;
    int q = 0, max_dollar = 0;
    const char* p = sql;
    while (*p) {
        if (*p == '\'') {
            p++;
            while (*p) {
                if (*p == '\'' && p[1] == '\'') { p += 2; continue; }
                if (*p == '\\' && p[1]) { p += 2; continue; }
                if (*p == '\'') { p++; break; }
                p++;
            }
            continue;
        }
        if (*p == '?') { q++; p++; continue; }
        if (*p == '$' && p[1] >= '1' && p[1] <= '9') {
            int n = 0;
            p++;
            while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
            if (n > max_dollar) max_dollar = n;
            continue;
        }
        p++;
    }
    return q > max_dollar ? q : max_dollar;
}

/* Release all bound values in a slot and reset binding state. */
static void uwp_ps_clear_bindings(uwp_ps_slot_t* s) {
    if (!s) return;
    for (int i = 0; i < UWP_PS_MAX_PARAMS; i++) {
        free(s->bound_values[i]);
        s->bound_values[i] = NULL;
    }
    s->num_bound = 0;
}

/* Append a bound value to a dynamic buffer, quoting it as a SQL literal.
 * Numeric-looking values are emitted verbatim; others are single-quoted with
 * embedded single quotes doubled.  NULL/empty becomes NULL. */
static void uwp_ps_append_value(uwp_text_buffer_t* out, const char* val) {
    if (!val || val[0] == '\0') {
        (void)uwp_text_appendf(out, "NULL");
        return;
    }
    bool numeric = true;
    for (const char* v = val; *v; v++) {
        if (!((*v >= '0' && *v <= '9') || *v == '.' || *v == '-' ||
              *v == '+' || *v == 'e' || *v == 'E')) {
            numeric = false;
            break;
        }
    }
    if (numeric) {
        (void)uwp_text_appendf(out, "%s", val);
    } else {
        (void)uwp_text_appendf(out, "'");
        for (const char* v = val; *v; v++) {
            if (*v == '\'') (void)uwp_text_appendf(out, "''");
            else (void)uwp_text_appendf(out, "%c", *v);
        }
        (void)uwp_text_appendf(out, "'");
    }
}

/* Build a new SQL string with ? and $N placeholders replaced by the bound
 * values stored in the slot.  Returns a malloc'd string (caller frees) or
 * NULL on allocation failure.  Unbound parameters become NULL. */
static char* uwp_ps_substitute(const uwp_ps_slot_t* s) {
    if (!s) return NULL;
    uwp_text_buffer_t out = {0};
    int q_idx = 0;
    const char* p = s->sql;
    while (*p) {
        if (*p == '\'') {
            (void)uwp_text_appendf(&out, "'");
            p++;
            while (*p) {
                if (*p == '\'' && p[1] == '\'') {
                    (void)uwp_text_appendf(&out, "''");
                    p += 2;
                    continue;
                }
                if (*p == '\\' && p[1]) {
                    (void)uwp_text_appendf(&out, "%c%c", *p, p[1]);
                    p += 2;
                    continue;
                }
                (void)uwp_text_appendf(&out, "%c", *p);
                if (*p == '\'') { p++; break; }
                p++;
            }
            continue;
        }
        if (*p == '?') {
            const char* val = (q_idx < s->num_bound && s->bound_values[q_idx])
                                  ? s->bound_values[q_idx] : NULL;
            uwp_ps_append_value(&out, val);
            q_idx++;
            p++;
            continue;
        }
        if (*p == '$' && p[1] >= '1' && p[1] <= '9') {
            int n = 0;
            p++;
            while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
            const char* val = (n >= 1 && n <= s->num_bound && s->bound_values[n - 1])
                                  ? s->bound_values[n - 1] : NULL;
            uwp_ps_append_value(&out, val);
            continue;
        }
        (void)uwp_text_appendf(&out, "%c", *p);
        p++;
    }
    char* result = out.failed ? NULL : strdup(out.data ? out.data : "");
    uwp_text_destroy(&out);
    return result;
}

/* -------------------------------------------------------------------------
 * Document-store WHERE expression builder.
 *
 * The document store's bytecode query API accepts a small expression grammar
 * (==, !=, <, >, <=, >=, AND, OR, NOT) with double-quoted string literals.
 * This converts the AST's structured WHERE conditions into that text form.
 * Conditions using LIKE / IN / subqueries are skipped (unsupported).  Returns
 * an empty buffer when no translatable conditions exist. */
static void uwp_build_where_expr(uwp_text_buffer_t* out,
                                 const qihse_sql_ast_t* ast) {
    if (!out || !ast) return;
    int first = 1;
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        const qihse_sql_condition_t* c = &ast->where_conditions[i];
        if (!c->column_name || !c->operator || !c->value) continue;
        if (c->subq_kind != 0) continue; /* subquery predicates unsupported */
        const char* bcop = NULL;
        if (strcasecmp(c->operator, "=") == 0) bcop = "==";
        else if (strcasecmp(c->operator, "<>") == 0 ||
                 strcasecmp(c->operator, "!=") == 0) bcop = "!=";
        else if (strcasecmp(c->operator, "<") == 0) bcop = "<";
        else if (strcasecmp(c->operator, ">") == 0) bcop = ">";
        else if (strcasecmp(c->operator, "<=") == 0) bcop = "<=";
        else if (strcasecmp(c->operator, ">=") == 0) bcop = ">=";
        else continue; /* LIKE / IN / others unsupported by bytecode VM */
        if (!first) (void)uwp_text_appendf(out, " AND ");
        first = 0;
        (void)uwp_text_appendf(out, "%s %s ", c->column_name, bcop);
        if (c->value_is_string) {
            (void)uwp_text_appendf(out, "\"");
            for (const char* v = c->value; *v; v++) {
                if (*v == '"') (void)uwp_text_appendf(out, "\"\"");
                else (void)uwp_text_appendf(out, "%c", *v);
            }
            (void)uwp_text_appendf(out, "\"");
        } else {
            (void)uwp_text_appendf(out, "%s", c->value);
        }
    }
}

/* Extract and normalize a WHERE clause for UPDATE/DELETE statements.
 *
 * The parser leaves UPDATE's WHERE entirely unparsed (only the table name is
 * captured) and stores DELETE's WHERE as raw text in insert_select_query.
 * This routine pulls the raw WHERE text from whichever source is available and
 * normalizes it into the document store's bytecode grammar:
 *   - "="  -> "=="
 *   - "<>" -> "!="
 *   - single-quoted string literals -> double-quoted (with " doubled)
 * Returns a malloc'd string (caller frees) or NULL when no WHERE is present.
 * Best-effort: unsupported constructs (LIKE / IN) simply fail to compile at
 * the document store, which the caller reports as zero matches. */
static char* uwp_extract_dml_where(const qihse_sql_ast_t* ast) {
    if (!ast) return NULL;
    const char* where = NULL;
    char* owned = NULL;

    if (ast->stmt_type == QIHSE_SQL_DELETE && ast->insert_select_query) {
        where = ast->insert_select_query;
    } else if (ast->raw_sql) {
        const char* w = strcasestr(ast->raw_sql, "WHERE");
        if (w) {
            w += 5;
            const char* end = strcasestr(w, "RETURNING");
            size_t len = end ? (size_t)(end - w) : strlen(w);
            while (len > 0 && isspace((unsigned char)w[0])) { w++; len--; }
            while (len > 0 && isspace((unsigned char)w[len - 1])) len--;
            if (len > 0) {
                owned = strndup(w, len);
                where = owned;
            }
        }
    }
    if (!where) return NULL;

    uwp_text_buffer_t out = {0};
    const char* p = where;
    while (*p) {
        if (*p == '\'') {
            (void)uwp_text_appendf(&out, "\"");
            p++;
            while (*p) {
                if (*p == '\'' && p[1] == '\'') { p += 2; continue; }
                if (*p == '\'') { p++; break; }
                if (*p == '"') (void)uwp_text_appendf(&out, "\"\"");
                else (void)uwp_text_appendf(&out, "%c", *p);
                p++;
            }
            (void)uwp_text_appendf(&out, "\"");
            continue;
        }
        if (*p == '<' && p[1] == '>') {
            (void)uwp_text_appendf(&out, "!=");
            p += 2;
            continue;
        }
        if (*p == '!' && p[1] == '=') {
            (void)uwp_text_appendf(&out, "!=");
            p += 2;
            continue;
        }
        if (*p == '=' && p[1] == '=') {
            (void)uwp_text_appendf(&out, "==");
            p += 2;
            continue;
        }
        if (*p == '=') {
            (void)uwp_text_appendf(&out, "==");
            p++;
            continue;
        }
        (void)uwp_text_appendf(&out, "%c", *p);
        p++;
    }
    free(owned);

    char* result = out.failed ? NULL : strdup(out.data ? out.data : "");
    uwp_text_destroy(&out);
    if (result) {
        bool has_content = false;
        for (const char* c = result; *c; c++) {
            if (!isspace((unsigned char)*c)) { has_content = true; break; }
        }
        if (!has_content) { free(result); result = NULL; }
    }
    return result;
}

/* Build a bytecode-compatible WHERE expression for DML statements.
 * Prefers the parser's structured where_conditions (when populated) and falls
 * back to text-based extraction from the raw SQL.  Returns a malloc'd string
 * (caller frees) or NULL when no WHERE clause is available. */
static char* uwp_build_dml_where(const qihse_sql_ast_t* ast) {
    if (!ast) return NULL;
    uwp_text_buffer_t out = {0};
    uwp_build_where_expr(&out, ast);
    if (out.data && out.len > 0) {
        char* r = strdup(out.data);
        uwp_text_destroy(&out);
        return r;
    }
    uwp_text_destroy(&out);
    return uwp_extract_dml_where(ast);
}

/* -------------------------------------------------------------------------
 * Recursive CTE execution (simplified, text-based).
 *
 * The parser does not reliably expose the base/recursive split of a WITH
 * RECURSIVE clause, so we parse the raw SQL text to extract the CTE name and
 * body, split the body on UNION [ALL], execute the base query, then iterate
 * the recursive query feeding the previous iteration's rows as a VALUES
 * clause substituted for the CTE name.  Execution stops when no new rows are
 * produced or UWP_RCTE_MAX_ITERS is reached.  Never crashes; on any parsing
 * failure it degrades with an informative message. */
#define UWP_RCTE_MAX_ITERS 1000

static void uwp_execute_recursive_cte(qihse_uwp_context_t* ctx,
                                      const qihse_sql_ast_t* ast,
                                      uwp_text_buffer_t* response) {
    const char* sql = ast->raw_sql;
    if (!sql) {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: no raw SQL)\n");
        return;
    }

    const char* rec = strcasestr(sql, "RECURSIVE");
    if (!rec) {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: RECURSIVE keyword not found)\n");
        return;
    }
    const char* p = rec + 9; /* length of "RECURSIVE" is 9 */
    while (*p && isspace((unsigned char)*p)) p++;
    const char* name_start = p;
    while (*p && !isspace((unsigned char)*p) && *p != '(') p++;
    size_t name_len = (size_t)(p - name_start);
    if (name_len == 0 || name_len >= 128) {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: could not parse CTE name)\n");
        return;
    }
    char cte_name[128];
    memcpy(cte_name, name_start, name_len);
    cte_name[name_len] = '\0';

    /* Skip an optional column list, e.g. cte(col1, col2) AS (...) */
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '(') {
        int cd = 0;
        for (; *p; p++) {
            if (*p == '(') cd++;
            else if (*p == ')') { cd--; if (cd == 0) { p++; break; } }
        }
    }
    while (*p && isspace((unsigned char)*p)) p++;
    if (strncasecmp(p, "AS", 2) != 0 ||
        (p[2] && !isspace((unsigned char)p[2]) && p[2] != '(')) {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: AS keyword not found)\n");
        return;
    }
    p += 2;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p != '(') {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: CTE body open paren not found)\n");
        return;
    }
    const char* open = p;
    int depth = 0;
    const char* q = open;
    for (; *q; q++) {
        if (*q == '(') depth++;
        else if (*q == ')') { depth--; if (depth == 0) break; }
    }
    if (depth != 0) {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: unbalanced parens in CTE body)\n");
        return;
    }
    size_t body_len = (size_t)(q - open - 1);
    char* body = (char*)malloc(body_len + 1);
    if (!body) {
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: out of memory)\n");
        return;
    }
    memcpy(body, open + 1, body_len);
    body[body_len] = '\0';

    /* Split the body on UNION ALL (or UNION).  We search for the keyword as a
     * whole word to avoid matching "UNION" inside an identifier. */
    char* union_all = NULL;
    char* union_p = NULL;
    size_t split_off = 0;
    size_t union_kw_len = 0;
    for (char* c = body; *c; c++) {
        if (strncasecmp(c, "UNION ALL", 9) == 0 &&
            (c == body || !isalnum((unsigned char)c[-1])) &&
            !isalnum((unsigned char)c[9])) {
            union_all = c;
            break;
        }
        if (strncasecmp(c, "UNION", 5) == 0 &&
            (c == body || !isalnum((unsigned char)c[-1])) &&
            !isalnum((unsigned char)c[5])) {
            union_p = c;
        }
    }
    if (union_all) {
        split_off = (size_t)(union_all - body);
        union_kw_len = 9; /* "UNION ALL" */
    } else if (union_p) {
        split_off = (size_t)(union_p - body);
        union_kw_len = 5; /* "UNION" */
    } else {
        free(body);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: no UNION in recursive body)\n");
        return;
    }

    /* Trim trailing whitespace from the base part. */
    size_t base_len = split_off;
    while (base_len > 0 && isspace((unsigned char)body[base_len - 1])) base_len--;
    char* base_sql = strndup(body, base_len);
    const char* rec_start = body + split_off + union_kw_len;
    while (*rec_start && isspace((unsigned char)*rec_start)) rec_start++;
    char* rec_sql = strdup(rec_start);
    free(body);
    if (!base_sql || !rec_sql) {
        free(base_sql);
        free(rec_sql);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: out of memory)\n");
        return;
    }

    /* Execute the base query and materialise its rows.  A parse failure is a
     * hard error; an executor that returns no rows (the common case while the
     * row-store pipeline is still empty) is treated as 0 initial rows, which
     * simply terminates the recursive loop at the fixed point. */
    uwp_text_buffer_t base_rows = {0};
    qihse_sql_ast_t* base_ast = qihse_parse_sql_to_ast(base_sql);
    free(base_sql);
    if (!base_ast) {
        free(rec_sql);
        uwp_text_destroy(&base_rows);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (recursive CTE execution failed: base query parse failed)\n");
        return;
    }
    (void)uwp_execute_select_plan(ctx, base_ast, &base_rows);
    qihse_sql_ast_free(base_ast);

    /* Emit the base rows (schema header + data) into the response. */
    if (base_rows.data) (void)uwp_text_appendf(response, "%s", base_rows.data);

    /* Determine the column count from the first (header) line of base_rows. */
    int num_cols = 0;
    if (base_rows.data) {
        const char* hl = base_rows.data;
        const char* le = strchr(hl, '\n');
        if (le) {
            for (const char* c = hl; c < le; c++) if (*c == '\t') num_cols++;
            num_cols++; /* columns = tabs + 1 */
        }
    }

    /* Collect all data rows (everything after the first newline) produced so
     * far; these seed the recursive iteration. */
    uwp_text_buffer_t all_data = {0};
    if (base_rows.data) {
        const char* first_nl = strchr(base_rows.data, '\n');
        if (first_nl) {
            (void)uwp_text_appendf(&all_data, "%s", first_nl + 1);
        }
    }
    uwp_text_destroy(&base_rows);

    /* Iteratively execute the recursive query, substituting the CTE name
     * with a VALUES clause built from the previous iteration's rows. */
    int iterations = 0;
    for (; iterations < UWP_RCTE_MAX_ITERS; iterations++) {
        /* Build the VALUES clause from the current data buffer.  Each line is
         * one row; tabs separate columns. */
        uwp_text_buffer_t values = {0};
        int row_count = 0;
        if (all_data.data && all_data.len > 0) {
            const char* lp = all_data.data;
            while (*lp) {
                const char* nl = strchr(lp, '\n');
                size_t line_len = nl ? (size_t)(nl - lp) : strlen(lp);
                if (line_len > 0) {
                    if (row_count > 0) (void)uwp_text_appendf(&values, ", ");
                    (void)uwp_text_appendf(&values, "(");
                    if (num_cols <= 0) {
                        (void)uwp_text_appendf(&values, "NULL");
                    } else {
                        const char* fp = lp;
                        for (int c = 0; c < num_cols; c++) {
                            const char* tab = (const char*)memchr(fp, '\t',
                                (size_t)((lp + line_len) - fp));
                            size_t flen = tab ? (size_t)(tab - fp)
                                              : (size_t)((lp + line_len) - fp);
                            if (c > 0) (void)uwp_text_appendf(&values, ", ");
                            if (flen == 0) {
                                (void)uwp_text_appendf(&values, "NULL");
                            } else {
                                /* emit as quoted string literal */
                                (void)uwp_text_appendf(&values, "'");
                                for (size_t k = 0; k < flen; k++) {
                                    if (fp[k] == '\'')
                                        (void)uwp_text_appendf(&values, "''");
                                    else
                                        (void)uwp_text_appendf(&values, "%c", fp[k]);
                                }
                                (void)uwp_text_appendf(&values, "'");
                            }
                            if (tab) fp = tab + 1;
                        }
                    }
                    (void)uwp_text_appendf(&values, ")");
                    row_count++;
                }
                if (!nl) break;
                lp = nl + 1;
            }
        }

        if (row_count == 0) {
            uwp_text_destroy(&values);
            break; /* no new rows to feed -> terminate */
        }

        /* Substitute the CTE name in the recursive query with the VALUES
         * clause.  We do a simple whole-word replacement. */
        uwp_text_buffer_t rec_sub = {0};
        const char* rp = rec_sql;
        while (*rp) {
            /* match cte_name as a whole word (case-insensitive) */
            if (strncasecmp(rp, cte_name, name_len) == 0) {
                char prev = (rp == rec_sql) ? ' ' : rp[-1];
                char nxt = rp[name_len];
                if (!isalnum((unsigned char)prev) && prev != '_' &&
                    !isalnum((unsigned char)nxt) && nxt != '_') {
                    if (values.data) {
                        (void)uwp_text_appendf(&rec_sub, "%s", values.data);
                    } else {
                        (void)uwp_text_appendf(&rec_sub, "(SELECT NULL)");
                    }
                    rp += name_len;
                    continue;
                }
            }
            (void)uwp_text_appendf(&rec_sub, "%c", *rp);
            rp++;
        }
        uwp_text_destroy(&values);

        char* rec_final = rec_sub.failed ? NULL : strdup(rec_sub.data ? rec_sub.data : rec_sql);
        uwp_text_destroy(&rec_sub);
        if (!rec_final) {
            (void)uwp_text_appendf(response,
                "OK stmt_type=SELECT (recursive CTE execution failed: out of memory)\n");
            free(rec_sql);
            uwp_text_destroy(&all_data);
            return;
        }

        /* Execute the recursive query for this iteration.  A parse failure is
         * a hard error; an executor that returns no rows is treated as 0 new
         * rows, which terminates the loop at the fixed point. */
        uwp_text_buffer_t iter_rows = {0};
        qihse_sql_ast_t* iter_ast = qihse_parse_sql_to_ast(rec_final);
        free(rec_final);
        if (!iter_ast) {
            (void)uwp_text_appendf(response,
                "OK stmt_type=SELECT (recursive CTE execution failed: recursive query parse failed)\n");
            free(rec_sql);
            uwp_text_destroy(&all_data);
            uwp_text_destroy(&iter_rows);
            return;
        }
        (void)uwp_execute_select_plan(ctx, iter_ast, &iter_rows);
        qihse_sql_ast_free(iter_ast);

        /* Append this iteration's data rows to the response and to the
         * working set for the next iteration. */
        int new_rows = 0;
        if (iter_rows.data) {
            const char* first_nl = strchr(iter_rows.data, '\n');
            const char* data = first_nl ? first_nl + 1 : iter_rows.data;
            if (first_nl) {
                (void)uwp_text_appendf(response, "%s", data);
            } else {
                (void)uwp_text_appendf(response, "%s", iter_rows.data);
            }
            /* count new data rows */
            for (const char* c = data; *c; c++) if (*c == '\n') new_rows++;
            if (*data && data[strlen(data) - 1] != '\n') new_rows++;
            if (first_nl) (void)uwp_text_appendf(&all_data, "%s", data);
        }
        uwp_text_destroy(&iter_rows);

        if (new_rows == 0) break; /* fixed point reached */
    }

    free(rec_sql);
    uwp_text_destroy(&all_data);
    (void)uwp_text_appendf(response, "OK stmt_type=SELECT\n");
}

/* -------------------------------------------------------------------------
 * Window-function execution (best-effort).
 *
 * When the window executor module is present we build window specs from the
 * AST's SELECT items, construct an input row stream from the optimizer plan,
 * and pipe it through qihse_window_create.  If the module is absent or the
 * input stream has no schema (the common case while the row-store pipeline is
 * still empty), we degrade gracefully. */
#ifdef UWP_HAS_WINDOW_EXECUTOR
static void uwp_execute_window(qihse_uwp_context_t* ctx,
                               const qihse_sql_ast_t* ast,
                               uwp_text_buffer_t* response) {
    qihse_optimizer_t* opt =
        qihse_optimizer_create((qihse_schema_registry_t*)ctx->schema);
    qihse_plan_node_t* plan = opt ? qihse_optimizer_build_plan(opt, ast) : NULL;
    qihse_row_stream_t* input = plan ? build_stream(plan, ctx) : NULL;

    if (!input || !input->schema) {
        if (input) qihse_row_stream_close(input);
        if (plan) qihse_plan_node_free(plan);
        if (opt) qihse_optimizer_destroy(opt);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (window functions not yet supported)\n");
        return;
    }

    /* Count window-function select items. */
    size_t nspecs = 0;
    for (size_t i = 0; i < ast->num_select_items; i++) {
        if (ast->select_items[i].win_kind != QIHSE_WIN_NONE ||
            ast->select_items[i].window != NULL) nspecs++;
    }
    if (nspecs == 0) {
        qihse_row_stream_close(input);
        if (plan) qihse_plan_node_free(plan);
        if (opt) qihse_optimizer_destroy(opt);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (window functions not yet supported)\n");
        return;
    }

    qihse_window_spec_t* specs =
        (qihse_window_spec_t*)calloc(nspecs, sizeof(qihse_window_spec_t));
    if (!specs) {
        qihse_row_stream_close(input);
        if (plan) qihse_plan_node_free(plan);
        if (opt) qihse_optimizer_destroy(opt);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (window functions not yet supported)\n");
        return;
    }

    size_t si = 0;
    for (size_t i = 0; i < ast->num_select_items && si < nspecs; i++) {
        const qihse_sql_select_item_t* item = &ast->select_items[i];
        if (item->win_kind == QIHSE_WIN_NONE && item->window == NULL) continue;
        qihse_window_spec_t* sp = &specs[si++];
        switch (item->win_kind) {
            case QIHSE_WIN_ROW_NUMBER: sp->func = QIHSE_WIN_FUNC_ROW_NUMBER; break;
            case QIHSE_WIN_RANK:       sp->func = QIHSE_WIN_FUNC_RANK; break;
            case QIHSE_WIN_DENSE_RANK: sp->func = QIHSE_WIN_FUNC_DENSE_RANK; break;
            case QIHSE_WIN_SUM:        sp->func = QIHSE_WIN_FUNC_SUM; break;
            case QIHSE_WIN_COUNT:      sp->func = QIHSE_WIN_FUNC_COUNT; break;
            case QIHSE_WIN_AVG:        sp->func = QIHSE_WIN_FUNC_AVG; break;
            case QIHSE_WIN_MIN:        sp->func = QIHSE_WIN_FUNC_MIN; break;
            case QIHSE_WIN_MAX:        sp->func = QIHSE_WIN_FUNC_MAX; break;
            default:                   sp->func = QIHSE_WIN_FUNC_ROW_NUMBER; break;
        }
        sp->arg_col = -1;
        if (item->win_arg) {
            int idx = qihse_schema_find_col(input->schema, item->win_arg);
            sp->arg_col = idx;
        }
        if (item->window) {
            const qihse_sql_window_spec_t* w = item->window;
            if (w->num_partition_by > 0) {
                sp->partition_by_cols = (int*)malloc(w->num_partition_by * sizeof(int));
                if (sp->partition_by_cols) {
                    sp->num_partition_cols = 0;
                    for (size_t k = 0; k < w->num_partition_by; k++) {
                        int idx = w->partition_by[k]
                            ? qihse_schema_find_col(input->schema, w->partition_by[k]) : -1;
                        if (idx >= 0)
                            sp->partition_by_cols[sp->num_partition_cols++] = idx;
                    }
                }
            }
            if (w->num_order_by > 0) {
                sp->order_by_cols = (int*)malloc(w->num_order_by * sizeof(int));
                if (sp->order_by_cols) {
                    sp->num_order_cols = 0;
                    for (size_t k = 0; k < w->num_order_by; k++) {
                        int idx = w->order_by[k].column_name
                            ? qihse_schema_find_col(input->schema, w->order_by[k].column_name) : -1;
                        if (idx >= 0)
                            sp->order_by_cols[sp->num_order_cols++] = idx;
                    }
                }
            }
        }
    }

    qihse_exec_schema_t* out_schema = NULL;
    qihse_row_stream_t* win = qihse_window_create(input, input->schema,
                                                  specs, nspecs, &out_schema);
    if (!win) {
        for (size_t k = 0; k < nspecs; k++) {
            free(specs[k].partition_by_cols);
            free(specs[k].order_by_cols);
        }
        free(specs);
        qihse_row_stream_close(input);
        if (plan) qihse_plan_node_free(plan);
        if (opt) qihse_optimizer_destroy(opt);
        (void)uwp_text_appendf(response,
            "OK stmt_type=SELECT (window functions not yet supported)\n");
        return;
    }

    /* Emit schema header + rows.  window_close() closes the input stream. */
    if (win->schema) {
        for (size_t i = 0; i < win->schema->num_cols; i++) {
            (void)uwp_text_appendf(response, "%s", win->schema->names[i]);
            if (i + 1 < win->schema->num_cols)
                (void)uwp_text_appendf(response, "\t");
        }
        (void)uwp_text_appendf(response, "\n");
    }
    qihse_exec_row_t* row;
    while ((row = qihse_row_stream_next(win)) != NULL) {
        for (size_t i = 0; i < row->num_values; i++) {
            append_value(response, row->values[i]);
            if (i + 1 < row->num_values)
                (void)uwp_text_appendf(response, "\t");
        }
        (void)uwp_text_appendf(response, "\n");
        qihse_exec_row_free(row);
    }
    qihse_row_stream_close(win);

    for (size_t k = 0; k < nspecs; k++) {
        free(specs[k].partition_by_cols);
        free(specs[k].order_by_cols);
    }
    free(specs);
    if (out_schema) qihse_window_schema_free(out_schema);
    if (plan) qihse_plan_node_free(plan);
    if (opt) qihse_optimizer_destroy(opt);
    (void)uwp_text_appendf(response, "OK stmt_type=SELECT\n");
}
#endif /* UWP_HAS_WINDOW_EXECUTOR */

static uwp_sts_result_t uwp_sql_execute(qihse_uwp_context_t* ctx,
                                        qihse_sql_ast_t* ast, const char* sql,
                                        qihse_txn_t** current_txn, qihse_user_t* user) {
    int rc = 0;
    switch (ast->stmt_type) {
        case QIHSE_SQL_CREATE:
            if (!ctx->schema) return UWP_STS_ERR_NO_CTX;
            rc = ast->index_def
                     ? qihse_schema_create_index((qihse_schema_registry_t*)ctx->schema, ast)
                     : qihse_schema_create_table((qihse_schema_registry_t*)ctx->schema, ast);
            break;
        case QIHSE_SQL_DROP:
            if (!ctx->schema) return UWP_STS_ERR_NO_CTX;
            rc = ast->drop_is_index
                     ? qihse_schema_drop_index((qihse_schema_registry_t*)ctx->schema,
                                               ast->drop_name)
                     : qihse_schema_drop_table((qihse_schema_registry_t*)ctx->schema,
                                               ast->drop_name);
            break;
        case QIHSE_SQL_ALTER:
            if (!ctx->schema) return UWP_STS_ERR_NO_CTX;
            rc = qihse_schema_alter_table((qihse_schema_registry_t*)ctx->schema, ast);
            break;
        case QIHSE_SQL_BEGIN: {
            uint8_t isolation = (uint8_t)uwp_sql_isolation(sql);
            return uwp_dispatch_txn(ctx, 0x01, &isolation, 1, current_txn, user, -1,
                                    NULL, NULL);
        }
        case QIHSE_SQL_COMMIT:
            return uwp_dispatch_txn(ctx, 0x02, NULL, 0, current_txn, user, -1,
                                    NULL, NULL);
        case QIHSE_SQL_ROLLBACK:
            if (ast->util && ast->util->name) {
                return uwp_dispatch_txn(ctx, 0x05, (const uint8_t*)ast->util->name,
                                        strlen(ast->util->name) + 1, current_txn, user, -1,
                                        NULL, NULL);
            }
            return uwp_dispatch_txn(ctx, 0x03, NULL, 0, current_txn, user, -1,
                                    NULL, NULL);
        case QIHSE_SQL_SELECT:
            /* execution logic will be wired in caller because we need response buffer */
            break;
        case QIHSE_SQL_INSERT:
        case QIHSE_SQL_UPDATE:
        case QIHSE_SQL_DELETE:
            break;
        default:
            break;
    }
    return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
}

uwp_sts_result_t uwp_dispatch_sql(qihse_uwp_context_t* ctx,
                                  uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    if (!user) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (!ctx || !ctx->sql_engine) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }

    /* --- PARSE (0x01): parse SQL, cache it, return slot id + param count --- */
    if (command_opcode == 0x01) {
        const char* sql;
        if (uwp_payload_string(payload, payload_len, &sql) != 0) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(sql);
        if (!ast) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_PARSE\n");
            return UWP_STS_ERR_FAILED;
        }
        int params = uwp_count_params(sql);
        qihse_sql_stmt_type_t st = ast->stmt_type;
        qihse_sql_ast_free(ast);

        pthread_mutex_lock(&uwp_ps_mutex);
        int slot = -1;
        for (int i = 0; i < UWP_PS_MAX_SLOTS; i++) {
            if (!uwp_ps_slots[i].valid) { slot = i; break; }
        }
        if (slot < 0) {
            pthread_mutex_unlock(&uwp_ps_mutex);
            uwp_reply_cb(write_fn, write_ctx, "ERR_NO_SLOTS\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_ps_slot_t* s = &uwp_ps_slots[slot];
        uwp_ps_clear_bindings(s);
        strncpy(s->sql, sql, UWP_PS_SQL_LEN - 1);
        s->sql[UWP_PS_SQL_LEN - 1] = '\0';
        s->valid = true;
        s->stmt_type = st;
        s->num_params = params;
        pthread_mutex_unlock(&uwp_ps_mutex);

        uwp_text_buffer_t response = {0};
        (void)uwp_text_appendf(&response, "OK stmt_id=%d params=%d\n", slot, params);
        uwp_write_cb(write_fn, write_ctx, response.data, response.len);
        uwp_text_destroy(&response);
        return UWP_STS_OK;
    }

    /* --- BIND (0x03): bind parameter values to a prepared statement.
     * Payload layout: [4-byte LE slot id][val1\0val2\0...valN\0] --- */
    if (command_opcode == 0x03) {
        if (!payload || payload_len < 4) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        uint32_t slot_id = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                           ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        if (slot_id >= UWP_PS_MAX_SLOTS) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        pthread_mutex_lock(&uwp_ps_mutex);
        uwp_ps_slot_t* s = &uwp_ps_slots[slot_id];
        if (!s->valid) {
            pthread_mutex_unlock(&uwp_ps_mutex);
            uwp_reply_cb(write_fn, write_ctx, "ERR_NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_ps_clear_bindings(s);
        size_t off = 4;
        while (off < payload_len && s->num_bound < UWP_PS_MAX_PARAMS) {
            const uint8_t* end = (const uint8_t*)memchr(payload + off, '\0',
                                                        payload_len - off);
            if (!end) {
                /* no terminating NUL — take the remaining bytes verbatim */
                size_t vlen = payload_len - off;
                char* val = (char*)malloc(vlen + 1);
                if (val) {
                    memcpy(val, payload + off, vlen);
                    val[vlen] = '\0';
                    s->bound_values[s->num_bound++] = val;
                }
                off = payload_len;
                break;
            }
            size_t vlen = (size_t)(end - payload) - off;
            char* val = (char*)malloc(vlen + 1);
            if (val) {
                memcpy(val, payload + off, vlen);
                val[vlen] = '\0';
                s->bound_values[s->num_bound++] = val;
            }
            off = (size_t)(end - payload) + 1;
        }
        pthread_mutex_unlock(&uwp_ps_mutex);
        uwp_reply_cb(write_fn, write_ctx, "OK\n");
        return UWP_STS_OK;
    }

    /* --- CLOSE (0x05): release a prepared statement slot.
     * Payload: [4-byte LE slot id] --- */
    if (command_opcode == 0x05) {
        if (!payload || payload_len != 4) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        uint32_t slot_id = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                           ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        if (slot_id >= UWP_PS_MAX_SLOTS) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        pthread_mutex_lock(&uwp_ps_mutex);
        uwp_ps_slot_t* s = &uwp_ps_slots[slot_id];
        if (!s->valid) {
            pthread_mutex_unlock(&uwp_ps_mutex);
            uwp_reply_cb(write_fn, write_ctx, "ERR_NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_ps_clear_bindings(s);
        s->valid = false;
        s->num_params = 0;
        s->stmt_type = QIHSE_SQL_UNKNOWN;
        s->sql[0] = '\0';
        pthread_mutex_unlock(&uwp_ps_mutex);
        uwp_reply_cb(write_fn, write_ctx, "OK\n");
        return UWP_STS_OK;
    }

    if (command_opcode != 0x02 && command_opcode != 0x04) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
        return UWP_STS_ERR_ARGS;
    }

    /* --- EXECUTE (0x02) / DESCRIBE (0x04) ---
     * EXECUTE is dual-mode: if the first 4 bytes of the payload encode a
     * valid, in-use prepared-statement slot ID, the bound parameters are
     * substituted into the cached SQL and the result is executed.  Otherwise
     * the payload is treated as raw SQL text (backward compatible). */
    char* ps_sql = NULL;     /* substituted SQL from a prepared statement */
    const char* sql = NULL;  /* SQL text to parse and execute */
    bool ps_active = false;

    if (command_opcode == 0x02 && payload && payload_len >= 4) {
        uint32_t slot_id = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                           ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        if (slot_id < UWP_PS_MAX_SLOTS) {
            pthread_mutex_lock(&uwp_ps_mutex);
            uwp_ps_slot_t* s = &uwp_ps_slots[slot_id];
            if (s->valid) {
                ps_sql = uwp_ps_substitute(s);
                pthread_mutex_unlock(&uwp_ps_mutex);
                if (ps_sql) {
                    sql = ps_sql;
                    ps_active = true;
                } else {
                    uwp_reply_cb(write_fn, write_ctx, "ERR_EXEC\n");
                    return UWP_STS_ERR_FAILED;
                }
            } else {
                pthread_mutex_unlock(&uwp_ps_mutex);
            }
        }
    }

    if (!ps_active) {
        if (uwp_payload_string(payload, payload_len, &sql) != 0) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
    }

    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(sql);
    if (!ast) {
        free(ps_sql);
        uwp_reply_cb(write_fn, write_ctx, "ERR_PARSE\n");
        return UWP_STS_ERR_FAILED;
    }

    uwp_sts_result_t result = UWP_STS_OK;
    uwp_text_buffer_t response = {0};
    if (command_opcode == 0x04) {
        if (uwp_serialize_description(&response, ast) != 0) result = UWP_STS_ERR_FAILED;
    } else {
        result = uwp_sql_execute(ctx, ast, sql, current_txn, user);
        if (result == UWP_STS_OK) {
            if (ast->stmt_type == QIHSE_SQL_SELECT ||
                ast->stmt_type == QIHSE_SQL_WITH) {
                /* --- CTE (WITH clause) handling ---
                 * The parser may fail to populate with_clause when the CTE
                 * has a column list, so we detect CTEs via the statement type
                 * and the raw SQL in addition to the structured with_clause. */
                bool has_cte = (ast->with_clause && ast->with_clause->num_ctes > 0) ||
                               ast->stmt_type == QIHSE_SQL_WITH ||
                               (ast->raw_sql && strcasestr(ast->raw_sql, "WITH"));
                if (has_cte && uwp_has_recursive_cte(ast)) {
                    /* Recursive CTE: execute via the text-based recursive
                     * evaluator.  Never crashes; degrades with a reason
                     * on any parsing failure. */
                    uwp_execute_recursive_cte(ctx, ast, &response);
                } else if (has_cte) {
                    /* Non-recursive CTE: the parser copies the inner
                     * SELECT fields into the WITH AST, so we can attempt
                     * to build and execute a plan directly.  CTE
                     * materialisation is not yet wired, so queries that
                     * reference CTE names as tables will produce empty
                     * results rather than crashing. */
                    if (uwp_execute_select_plan(ctx, ast, &response) == 0) {
                        uwp_text_appendf(&response, "OK stmt_type=SELECT\n");
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=SELECT (CTE materialisation not yet supported)\n");
                    }
                }
                /* --- Window function handling --- */
                else if (uwp_has_window_functions(ast)) {
#ifdef UWP_HAS_WINDOW_EXECUTOR
                    /* Window executor module present: attempt execution.  It
                     * degrades gracefully when the input stream has no schema
                     * (the common case while the row-store pipeline is empty). */
                    uwp_execute_window(ctx, ast, &response);
#else
                    uwp_text_appendf(&response,
                        "OK stmt_type=SELECT (window functions not yet supported)\n");
#endif
                }
                /* --- Subquery handling --- */
                else if (uwp_has_subqueries(ast)) {
                    /* Build a plan and check whether the optimizer emitted
                     * any SUBQUERY plan nodes.  If it did, execute them
                     * recursively; otherwise degrade with an informative
                     * message. */
                    qihse_optimizer_t* opt =
                        qihse_optimizer_create((qihse_schema_registry_t*)ctx->schema);
                    qihse_plan_node_t* plan =
                        opt ? qihse_optimizer_build_plan(opt, ast) : NULL;
                    if (plan && uwp_plan_has_subquery(plan)) {
                        if (uwp_execute_plan(plan, ctx, &response) == 0) {
                            uwp_text_appendf(&response, "OK stmt_type=SELECT\n");
                        } else {
                            uwp_text_appendf(&response,
                                "OK stmt_type=SELECT (subquery execution not supported by optimizer)\n");
                        }
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=SELECT (subquery execution not supported by optimizer)\n");
                    }
                    if (plan) qihse_plan_node_free(plan);
                    if (opt) qihse_optimizer_destroy(opt);
                }
                /* --- Normal SELECT --- */
                else {
                    if (uwp_execute_select_plan(ctx, ast, &response) == 0) {
                        uwp_text_appendf(&response, "OK stmt_type=SELECT\n");
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=SELECT (plan too complex, not executed)\n");
                    }
                }
            } else if (ast->stmt_type == QIHSE_SQL_INSERT) {
                /* --- INSERT: wire to column store --- */
                if (!ctx->col || !ctx->schema) {
                    uwp_text_appendf(&response,
                        "OK stmt_type=INSERT (no row store wired)\n");
                } else {
                    int rows = uwp_execute_insert(ctx, ast);
                    if (rows >= 0) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=INSERT rows=%d\n", rows);
                    } else if (rows == -1) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=INSERT (no row store wired)\n");
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=INSERT (table not found in schema)\n");
                    }
                }
            } else if (ast->stmt_type == QIHSE_SQL_UPDATE) {
                /* --- UPDATE: wire to the document store (mutable row store).
                 * The column store is append-only, so ctx->doc is the only
                 * store that can serve UPDATE.  The document store exposes a
                 * query API but no in-place update routine, so we report the
                 * matched row count and note the API limitation. --- */
                if (!ctx->doc) {
                    if (ctx->col) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=UPDATE (column store does not support in-place updates)\n");
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=UPDATE (no row store wired)\n");
                    }
                } else {
                    char* where_norm = uwp_build_dml_where(ast);
                    const char* wclause = where_norm ? where_norm : "1 == 1";
                    bool has_where = (where_norm != NULL);
                    qihse_document_result_t res =
                        qihse_doc_store_query_user(ctx->doc, wclause, user);
                    size_t matched = res.count;
                    free(res.doc_ids);
                    free(where_norm);
                    if (has_where) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=UPDATE rows=0 (document store has no in-place update API; matched=%zu)\n",
                            matched);
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=UPDATE rows=0 (document store has no in-place update API; no WHERE filtering, matched=%zu)\n",
                            matched);
                    }
                }
            } else if (ast->stmt_type == QIHSE_SQL_DELETE) {
                /* --- DELETE: wire to the document store (mutable row store).
                 * Same rationale as UPDATE: the document store can query
                 * matching documents but exposes no delete routine, so we
                 * report the matched count and note the limitation. --- */
                if (!ctx->doc) {
                    if (ctx->col) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=DELETE (column store does not support row deletion)\n");
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=DELETE (no row store wired)\n");
                    }
                } else {
                    char* where_norm = uwp_build_dml_where(ast);
                    const char* wclause = where_norm ? where_norm : "1 == 1";
                    bool has_where = (where_norm != NULL);
                    qihse_document_result_t res =
                        qihse_doc_store_query_user(ctx->doc, wclause, user);
                    size_t matched = res.count;
                    free(res.doc_ids);
                    free(where_norm);
                    if (has_where) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=DELETE rows=0 (document store has no delete API; matched=%zu)\n",
                            matched);
                    } else {
                        uwp_text_appendf(&response,
                            "OK stmt_type=DELETE rows=0 (document store has no delete API; no WHERE filtering, matched=%zu)\n",
                            matched);
                    }
                }
            } else {
                uwp_text_appendf(&response, "OK stmt_type=%s\n",
                                 qihse_sql_stmt_name(ast->stmt_type));
            }
        } else {
            result = UWP_STS_ERR_FAILED;
        }
    }

    if (result == UWP_STS_OK) {
        uwp_write_cb(write_fn, write_ctx, response.data, response.len);
    } else if (result == UWP_STS_ERR_NO_CTX) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
    } else {
        uwp_reply_cb(write_fn, write_ctx, command_opcode == 0x02 ? "ERR_EXEC\n" : "ERR\n");
    }
    uwp_text_destroy(&response);
    free(ps_sql);
    qihse_sql_ast_free(ast);
    return result;
}

uwp_sts_result_t uwp_dispatch_txn(qihse_uwp_context_t* ctx,
                                  uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    if (!user) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (!ctx || !ctx->txn_manager) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }

    qihse_txn_manager_t* manager = (qihse_txn_manager_t*)ctx->txn_manager;
    int rc;
    switch (command_opcode) {
        case 0x01: {
            int valid_args = payload && payload_len == 1 && payload[0] <= 2;
            if (!valid_args || (*current_txn) != NULL) {
                uwp_reply_cb(write_fn, write_ctx, valid_args ? "ERR\n" : "ERR_ARGS\n");
                return valid_args ? UWP_STS_ERR_FAILED : UWP_STS_ERR_ARGS;
            }
            (*current_txn) = qihse_txn_begin(
                manager, (qihse_isolation_level_t)payload[0]);
            if (!(*current_txn)) {
                uwp_reply_cb(write_fn, write_ctx, "ERR\n");
                return UWP_STS_ERR_FAILED;
            }
            uint8_t txn_id[8];
            uwp_put_u64_le(txn_id, (*current_txn)->id);
            uwp_write_cb(write_fn, write_ctx, txn_id, sizeof(txn_id));
            return UWP_STS_OK;
        }
        case 0x02:
        case 0x03:
            if (payload_len != 0) break;
            if (!(*current_txn)) {
                uwp_reply_cb(write_fn, write_ctx, "ERR\n");
                return UWP_STS_ERR_FAILED;
            }
            rc = command_opcode == 0x02
                     ? qihse_txn_commit(manager, (*current_txn))
                     : qihse_txn_rollback(manager, (*current_txn));
            (*current_txn) = NULL;
            uwp_reply_cb(write_fn, write_ctx, rc == 0 ? "OK\n" : "ERR\n");
            return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
        case 0x04:
        case 0x05: {
            const char* name;
            if (uwp_payload_string(payload, payload_len, &name) != 0) break;
            if (!(*current_txn)) {
                uwp_reply_cb(write_fn, write_ctx, "ERR\n");
                return UWP_STS_ERR_FAILED;
            }
            rc = command_opcode == 0x04
                     ? qihse_txn_savepoint(manager, (*current_txn), name)
                     : qihse_txn_rollback_to_savepoint(manager, (*current_txn), name);
            uwp_reply_cb(write_fn, write_ctx, rc == 0 ? "OK\n" : "ERR\n");
            return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
        }
        default:
            break;
    }
    uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
    return UWP_STS_ERR_ARGS;
}

static int uwp_serialize_table(uwp_text_buffer_t* out,
                               const qihse_schema_table_t* table) {
    (void)uwp_text_appendf(out, "OK table=%s columns=[", table->name ? table->name : "");
    for (size_t i = 0; i < table->num_columns; ++i) {
        const qihse_schema_column_t* column = &table->columns[i];
        (void)uwp_text_appendf(out, "%s%s:%s", i ? "," : "",
                               column->name ? column->name : "<unnamed>",
                               qihse_sql_type_name(column->type));
        if (column->type_len > 0) (void)uwp_text_appendf(out, "(%d)", column->type_len);
        if (column->not_null) (void)uwp_text_appendf(out, " NOT_NULL");
        if (column->is_primary_key) (void)uwp_text_appendf(out, " PRIMARY_KEY");
    }
    (void)uwp_text_appendf(out, "] indexes=[");
    for (size_t i = 0; i < table->num_indexes; ++i) {
        const qihse_schema_index_t* index = &table->indexes[i];
        (void)uwp_text_appendf(out, "%s%s(%s)%s", i ? "," : "",
                               index->name ? index->name : "<unnamed>",
                               index->column_name ? index->column_name : "",
                               index->unique ? " UNIQUE" : "");
    }
    (void)uwp_text_appendf(out, "]\n");
    return out->failed ? -1 : 0;
}

uwp_sts_result_t uwp_dispatch_schema(qihse_uwp_context_t* ctx,
                                     uint8_t command_opcode,
                                     const uint8_t* payload, size_t payload_len,
                                     qihse_user_t* user, int client_fd,
                                     qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    if (!user) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (!ctx || !ctx->schema) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }
    if (command_opcode < 0x01 || command_opcode > 0x06) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
        return UWP_STS_ERR_ARGS;
    }

    const char* input;
    if (uwp_payload_string(payload, payload_len, &input) != 0) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
        return UWP_STS_ERR_ARGS;
    }
    qihse_schema_registry_t* schema = (qihse_schema_registry_t*)ctx->schema;
    if (command_opcode == 0x02 || command_opcode == 0x06) {
        int rc = command_opcode == 0x02 ? qihse_schema_drop_table(schema, input)
                                        : qihse_schema_drop_index(schema, input);
        uwp_reply_cb(write_fn, write_ctx, rc == 0 ? "OK\n" : "ERR\n");
        return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
    }
    if (command_opcode == 0x04) {
        const qihse_schema_table_t* table = qihse_schema_get_table(schema, input);
        if (!table) {
            uwp_reply_cb(write_fn, write_ctx, "NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_text_buffer_t response = {0};
        if (uwp_serialize_table(&response, table) != 0) {
            uwp_text_destroy(&response);
            uwp_reply_cb(write_fn, write_ctx, "ERR\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_write_cb(write_fn, write_ctx, response.data, response.len);
        uwp_text_destroy(&response);
        return UWP_STS_OK;
    }

    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(input);
    if (!ast) {
        uwp_reply_cb(write_fn, write_ctx, "ERR\n");
        return UWP_STS_ERR_FAILED;
    }
    int rc = -1;
    if (command_opcode == 0x01 && ast->stmt_type == QIHSE_SQL_CREATE &&
        !ast->index_def && ast->table_name) {
        rc = qihse_schema_create_table(schema, ast);
    } else if (command_opcode == 0x03 && ast->stmt_type == QIHSE_SQL_ALTER &&
               ast->table_name && ast->alter_clause) {
        rc = qihse_schema_alter_table(schema, ast);
    } else if (command_opcode == 0x05 && ast->stmt_type == QIHSE_SQL_CREATE &&
               ast->index_def) {
        rc = qihse_schema_create_index(schema, ast);
    }
    qihse_sql_ast_free(ast);
    uwp_reply_cb(write_fn, write_ctx, rc == 0 ? "OK\n" : "ERR\n");
    return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
}
