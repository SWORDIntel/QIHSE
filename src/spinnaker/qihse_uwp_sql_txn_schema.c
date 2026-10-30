#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_optimizer.h"
#include "qihse_index_scan.h"
#include "qihse_join_executor.h"
#include "qihse_aggregate_executor.h"
#include "qihse_sort_executor.h"


#include "qihse_schema.h"
#include "qihse_sql_parser.h"
#include "qihse_table_store.h"
#include "qihse_sql_fts.h"
#include "qihse_sql_row_index.h"
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
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/random.h>

/* Defined below; uwp_execute_insert needs both. */
static qihse_table_t* uwp_sql_row_table(qihse_schema_registry_t* schema,
                                        const char* table_name);
static bool uwp_sql_json_text(const char* json, const char* key, char** value);
static bool uwp_dml_set_value(const qihse_col_def_t* def, const char* text,
                              qihse_col_value_t* out);
static bool uwp_dml_literal_value(const qihse_col_def_t* def, const char* text,
                                  bool quoted, qihse_col_value_t* out);
static bool uwp_dml_parse_timestamp(const char* text, int64_t* micros);
static bool uwp_sql_bound_value(const qihse_col_def_t* def,
    const qihse_schema_column_t* schema, const qihse_uwp_sql_param_t* param,
    const char* text, qihse_col_value_t* out);
static bool uwp_sql_default_value(const qihse_schema_column_t* col,
                                  qihse_col_value_t* out);
static char* uwp_sql_numeric(const char* text, int precision, int scale);
static bool uwp_sql_generated_expr(qihse_sql_type_t type, int stored,
                                   const char* expr);
static char* uwp_sql_generated_vector(const char* json);
static char* uwp_sql_english_vector(const char* text);
static const char* uwp_sql_find_keyword(const char* sql, const char* keyword);
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

/* Bound AST and typed values are scoped to one synchronous dispatch under
 * uwp_sql_dispatch_mutex; no SQL text or prepared global slot is rewritten. */
static UWP_THREAD_LOCAL qihse_sql_ast_t* uwp_bound_ast;
static UWP_THREAD_LOCAL const qihse_uwp_sql_param_t* uwp_bound_params;
static UWP_THREAD_LOCAL size_t uwp_bound_count;

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
static __attribute__((unused)) bool uwp_has_window_functions(const qihse_sql_ast_t* ast) {
    for (size_t i = 0; i < ast->num_select_items; i++) {
        if (ast->select_items[i].window != NULL) return true;
        if (ast->select_items[i].win_kind != QIHSE_WIN_NONE) return true;
    }
    return false;
}

/* Check if the AST has subqueries (scalar subqueries in SELECT list or
 * subquery predicates in WHERE). */
static __attribute__((unused)) bool uwp_has_subqueries(const qihse_sql_ast_t* ast) {
    for (size_t i = 0; i < ast->num_select_items; i++) {
        if (ast->select_items[i].scalar_subquery != NULL) return true;
    }
    for (size_t i = 0; i < ast->num_where_conditions; i++) {
        if (ast->where_conditions[i].subq_kind != 0) return true;
    }
    return false;
}

/* Recursively check if a plan tree contains any SUBQUERY nodes. */
static __attribute__((unused)) bool uwp_plan_has_subquery(const qihse_plan_node_t* plan) {
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
static __attribute__((unused)) bool uwp_has_recursive_cte(const qihse_sql_ast_t* ast) {
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
static bool uwp_sql_table_labeled(const qihse_table_t* table);
static bool uwp_sql_insert_allowed(const qihse_sql_ast_t* ast,
                                   const qihse_user_t* user,
                                   const qihse_table_t* table);

static int uwp_execute_insert(qihse_uwp_context_t* ctx,
                              const qihse_sql_ast_t* ast,
                              qihse_table_txn_t* table_txn,
                              qihse_user_t* user) {
    /* The schema registry is required — it is the table definition.  The
     * column store is optional; the mutable row store is process-wide and
     * needs no ctx. */
    if (!ctx->schema) return -1;
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

    /* The mutable row store: the table mirrors the schema definition, created
     * lazily so a table declared before this path existed still becomes
     * writable.  When the row store can host the table it is the insert's
     * authoritative destination — the column-store append is then the
     * analytic copy.  When it cannot (no schema entry, OOM), the column
     * store cannot host the table, refuse rather than bypassing constraint
     * checks via an analytic-only append. */
    qihse_table_t* row_table = uwp_sql_row_table(schema, ast->table_name);
    if (!row_table) { free(col_types); free(col_names); return -4; }
    if (!uwp_sql_insert_allowed(ast, user, row_table)) {
        free(col_types);
        free(col_names);
        return -3;
    }
    size_t row_cols = row_table ? qihse_table_num_cols(row_table) : 0;
    /* Validate the entire statement before its first write. The row store
     * has no SQL NULL representation: missing nullable columns retain its
     * historical zero value, but a required column must be supplied. */
    if (row_table) {
        if (num_cols > row_cols) { free(col_types); free(col_names); return -4; }
        for (size_t c = 0; c < row_cols; ++c) {
            size_t occurrences = 0;
            for (size_t i = 0; i < num_cols; ++i)
                if (strcasecmp(col_names[i], table->columns[c].name) == 0)
                    ++occurrences;
            if (occurrences > 1 || (table->columns[c].generated_stored && occurrences)) {
                free(col_types); free(col_names); return -4;
            }
        }
        for (size_t r = 0; r < ast->num_insert_rows; ++r) {
            if (!ast->insert_rows[r]) { free(col_types); free(col_names); return -4; }
            for (size_t c = 0; c < num_cols; ++c)
                if (!ast->insert_rows[r][c]) {
                    free(col_types); free(col_names); return -4;
                }
        }
    }
    if (ast->num_insert_rows > INT_MAX ||
        (row_cols && (ast->num_insert_rows > SIZE_MAX / row_cols ||
                      ast->num_insert_rows * row_cols > SIZE_MAX / sizeof(qihse_col_value_t)))) {
        free(col_types); free(col_names); return -4;
    }
    qihse_col_value_t* staged = calloc(ast->num_insert_rows * row_cols,
                                       sizeof(*staged));
    if (!staged) { free(col_types); free(col_names); return -2; }
    int result = -4;

    /* Materialize every value (including defaults and generated values)
     * before publishing any row or analytic copy. */
    for (size_t r = 0; r < ast->num_insert_rows; r++) {
        char** row = ast->insert_rows[r];
        qihse_col_value_t* row_vals = staged + r * row_cols;
        int row_ok = 1;
        /* Omitted columns are explicit NULLs; catalog constraints below
         * reject them where NULL is not permitted. */
        if (row_table) {
            for (size_t i = 0; i < row_cols; i++) {
                const qihse_col_def_t* d = qihse_table_col_def(row_table, i);
                if (!d) { row_ok = 0; break; }
                row_vals[i].type = d->type;
                row_vals[i].is_null = true;
            }
            if (row_ok) {
                for (size_t c = 0; c < num_cols && row_ok; c++) {
                    if (!row[c]) { row_ok = 0; break; }
                    int idx = qihse_table_find_col(row_table, col_names[c]);
                    if (idx < 0) { row_ok = 0; break; }
                    const qihse_col_def_t* d =
                        qihse_table_col_def(row_table, (size_t)idx);
                    const qihse_schema_column_t* sc = &table->columns[idx];
                    bool quoted = ast->insert_quoted && ast->insert_quoted[r] &&
                        ast->insert_quoted[r][c];
                    qihse_sql_type_t cast = ast->insert_cast_types &&
                        ast->insert_cast_types[r] ? ast->insert_cast_types[r][c] :
                        QIHSE_TYPE_UNKNOWN;
                    if (cast != QIHSE_TYPE_UNKNOWN &&
                        ((cast != QIHSE_TYPE_TIMESTAMP && cast != QIHSE_TYPE_TIMESTAMPTZ) ||
                         d->type != QIHSE_TS_TIMESTAMPTZ)) {
                        row_ok = 0; break;
                    }
                    uint16_t bind = ast->insert_parameter_indexes &&
                        ast->insert_parameter_indexes[r] ?
                        ast->insert_parameter_indexes[r][c] : 0;
                    if (bind && uwp_bound_params && bind <= uwp_bound_count) {
                        row_ok = uwp_sql_bound_value(d, sc,
                            &uwp_bound_params[bind - 1], row[c], &row_vals[idx]);
                        continue;
                    }
                    if (!quoted && !strcasecmp(row[c], "DEFAULT")) {
                        if (sc->default_expr)
                            row_ok = uwp_sql_default_value(sc, &row_vals[idx]);
                        if (!row_ok) break;
                        continue;
                    }
                    if (quoted && !strcasecmp(row[c], "NULL")) {
                        if (d->type == QIHSE_TS_STRING ||
                            (d->type == QIHSE_TS_JSONB && !strcmp(row[c], "null"))) {
                            row_vals[idx].v.str = strdup(row[c]);
                            row_vals[idx].is_null = false;
                            if (!row_vals[idx].v.str) { row_ok = 0; break; }
                            continue;
                        }
                        row_ok = 0; break;
                    }
                    if (sc->type == QIHSE_TYPE_NUMERIC &&
                        strcasecmp(row[c], "NULL")) {
                        row_vals[idx].v.str = uwp_sql_numeric(row[c],
                            sc->type_len, sc->type_scale);
                        row_vals[idx].is_null = row_vals[idx].v.str == NULL;
                        if (!row_vals[idx].v.str) { row_ok = 0; break; }
                    } else if (!uwp_dml_set_value(d, row[c], &row_vals[idx])) {
                        row_ok = 0;
                        break;
                    }
                }
            }
            if (row_ok) {
                const qihse_schema_table_t* definition = ctx->schema ?
                    qihse_schema_get_table(ctx->schema, ast->table_name) : NULL;
                if (!definition || definition->num_columns != row_cols) row_ok = 0;
                for (size_t c = 0; row_ok && c < row_cols; ++c) {
                    bool supplied = false;
                    for (size_t j = 0; j < num_cols; ++j)
                        if (!strcasecmp(col_names[j], definition->columns[c].name))
                            supplied = true;
                    if (!supplied && definition->columns[c].default_expr)
                        row_ok = uwp_sql_default_value(&definition->columns[c], &row_vals[c]);
                    if (!definition->columns[c].generated_stored &&
                        (definition->columns[c].not_null ||
                         definition->columns[c].is_primary_key) &&
                        row_vals[c].is_null) row_ok = 0;
                }
                int data_column = qihse_table_find_col(row_table, "data");
                for (size_t c = 0; row_ok && c < row_cols; ++c) {
                    if (!definition->columns[c].generated_stored) continue;
                    if (!uwp_sql_generated_expr(definition->columns[c].type,
                            definition->columns[c].generated_stored,
                            definition->columns[c].generated_expr) ||
                        data_column < 0 ||
                        row_vals[data_column].type != QIHSE_TS_JSONB ||
                        row_vals[data_column].is_null ||
                        !row_vals[data_column].v.str) {
                        row_ok = 0; break;
                    }
                    row_vals[c].v.str = uwp_sql_generated_vector(
                        row_vals[data_column].v.str);
                    if (!row_vals[c].v.str) { row_ok = 0; break; }
                    row_vals[c].is_null = false;
                }
            }
        }
        if (!row_ok) goto insert_done;
    }

    /* Autocommit uses a private snapshot, so a later allocation failure
     * cannot leave earlier rows visible. External transactions are aborted
     * by the caller on failure. */
    qihse_table_txn_t* private_txn = table_txn ? NULL : qihse_table_txn_begin(row_table);
    if (!table_txn && !private_txn) { result = -2; goto insert_done; }
    qihse_table_txn_t* destination = table_txn ? table_txn : private_txn;
    for (size_t r = 0; r < ast->num_insert_rows; r++) {
        if (qihse_table_txn_insert(destination, staged + r * row_cols,
                                   row_cols) < 0) {
            result = -2;
            qihse_table_txn_rollback(private_txn);
            goto insert_done;
        }
    }
    if (private_txn && !qihse_table_txn_commit(private_txn)) {
        result = -2;
        goto insert_done;
    }

    /* The analytic column store is a secondary copy of committed rows. */
    for (size_t r = 0; r < ast->num_insert_rows; r++) {
        char** row = ast->insert_rows[r];
        int col_ok = ctx->col ? 1 : 0;
        /* The column-store copy has no per-row SQL tenant/clearance labels.
         * Never replicate labeled rows into its unclassified namespace. */
        if (ctx->col && !table_txn &&
            !uwp_sql_table_labeled(row_table)) {
            for (size_t c = 0; c < num_cols && col_ok; c++) {
                if (!row[c]) { col_ok = 0; break; }

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
                if (!ok) col_ok = 0;
            }
        }
        (void)col_ok;
    }
    result = (int)ast->num_insert_rows;

insert_done:
    for (size_t r = 0; r < ast->num_insert_rows; ++r) {
        qihse_col_value_t* row_vals = staged + r * row_cols;
        for (size_t i = 0; i < row_cols; ++i) {
            if ((row_vals[i].type == QIHSE_TS_STRING || row_vals[i].type == QIHSE_TS_UUID ||
                 row_vals[i].type == QIHSE_TS_JSONB || row_vals[i].type == QIHSE_TS_NUMERIC ||
                 row_vals[i].type == QIHSE_TS_TSVECTOR) && row_vals[i].v.str)
                free(row_vals[i].v.str);
        }
    }
    free(staged);
    free(col_types);
    free(col_names);
    return result;
}

/* -------------------------------------------------------------------------
 * Prepared statement cache (PARSE / BIND / EXECUTE / CLOSE).
 *
 * A chained hash table keyed by stmt_id (FNV-1a hash of the SQL text).
 * Initial capacity is 256 buckets; the table grows dynamically when the
 * load factor exceeds 0.75, providing O(1) average lookup.  Thread-safe
 * via a single mutex.
 *
 * Each entry caches the raw SQL text, the parsed statement type, the
 * expected parameter count, and any bound parameter values supplied via
 * BIND.  stmt_id is a 32-bit FNV-1a hash of the SQL text, so it is
 * deterministic for the same query text.
 * ------------------------------------------------------------------------- */

#define UWP_PS_MAX_PARAMS    64
#define UWP_PS_SQL_LEN       4096
#define UWP_PS_INIT_BUCKETS  256

typedef struct {
    char  sql[UWP_PS_SQL_LEN];
    bool  valid;
    qihse_sql_stmt_type_t stmt_type;
    int   num_params;
    char* bound_values[UWP_PS_MAX_PARAMS]; /* strdup'd; NULL if unbound */
    int   num_bound;
} uwp_ps_slot_t;

typedef struct uwp_ps_node {
    uint32_t              stmt_id;
    uwp_ps_slot_t*        slot;     /* heap-allocated */
    struct uwp_ps_node*   next;
} uwp_ps_node_t;

typedef struct {
    uwp_ps_node_t** buckets;
    size_t          num_buckets;
    size_t          count;
    pthread_mutex_t mutex;
} uwp_ps_hash_t;

static uwp_ps_hash_t uwp_ps_hash = { NULL, 0, 0, PTHREAD_MUTEX_INITIALIZER };

/* FNV-1a 32-bit hash of a NUL-terminated string. */
static uint32_t uwp_fnv1a(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}

/* SQL row labels are explicit schema columns; an unlabeled table belongs to
 * the system tenant at classification 0. A partial/mistyped label is invalid.
 * SQL clients cannot supply an authorization principal through SQL text. */
typedef struct {
    int tenant, classification, sci;
    bool valid;
} uwp_sql_labels_t;

static uwp_sql_labels_t uwp_sql_labels(const qihse_table_t* table) {
    uwp_sql_labels_t labels = {-1, -1, -1, false};
    if (!table) return labels;
    labels.tenant = qihse_table_find_col(table, "__qihse_tenant_id");
    labels.classification = qihse_table_find_col(table, "__qihse_classification");
    labels.sci = qihse_table_find_col(table, "__qihse_sci");
    if (labels.tenant < 0 && labels.classification < 0 && labels.sci < 0) {
        labels.valid = true;
        return labels;
    }
    if (labels.tenant < 0 || labels.classification < 0 || labels.sci < 0)
        return labels;
    const qihse_col_def_t* t = qihse_table_col_def(table, (size_t)labels.tenant);
    const qihse_col_def_t* c = qihse_table_col_def(table, (size_t)labels.classification);
    const qihse_col_def_t* s = qihse_table_col_def(table, (size_t)labels.sci);
    labels.valid = t && c && s && t->type == QIHSE_TS_INT32 &&
                   c->type == QIHSE_TS_INT32 && s->type == QIHSE_TS_INT32;
    return labels;
}

static bool uwp_sql_table_labeled(const qihse_table_t* table) {
    return uwp_sql_labels(table).tenant >= 0;
}

static bool uwp_sql_row_allowed(const qihse_user_t* user,
                                uwp_sql_labels_t labels,
                                const qihse_col_value_t* values,
                                size_t num_cols) {
    if (!user || !labels.valid || !qihse_auth_user_is_active(user)) return false;
    uint32_t tenant = QIHSE_TENANT_SYSTEM;
    uint16_t classification = 0, sci = 0;
    if (labels.tenant >= 0) {
        if (!values || (size_t)labels.tenant >= num_cols ||
            (size_t)labels.classification >= num_cols ||
            (size_t)labels.sci >= num_cols) return false;
        int32_t t = values[labels.tenant].v.i32;
        int32_t c = values[labels.classification].v.i32;
        int32_t s = values[labels.sci].v.i32;
        if (values[labels.tenant].type != QIHSE_TS_INT32 ||
            values[labels.classification].type != QIHSE_TS_INT32 ||
            values[labels.sci].type != QIHSE_TS_INT32 ||
            t < 0 || c < 0 || c > UINT16_MAX || s < 0 || s > UINT16_MAX)
            return false;
        tenant = (uint32_t)t;
        classification = (uint16_t)c;
        sci = (uint16_t)s;
    }
    uint32_t principal_tenant = qihse_user_get_tenant_id(user);
    return (principal_tenant == QIHSE_TENANT_SYSTEM ||
            principal_tenant == tenant) &&
           qihse_auth_can_access(user, classification, sci);
}

static bool uwp_sql_insert_allowed(const qihse_sql_ast_t* ast,
                                   const qihse_user_t* user,
                                   const qihse_table_t* table) {
    uwp_sql_labels_t labels = uwp_sql_labels(table);
    if (!labels.valid || !user || !qihse_auth_user_is_active(user)) return false;
    if (labels.tenant < 0)
        return qihse_user_get_tenant_id(user) == QIHSE_TENANT_SYSTEM;
    int indices[3] = {labels.tenant, labels.classification, labels.sci};
    size_t positions[3];
    for (size_t i = 0; i < 3; ++i) {
        positions[i] = SIZE_MAX;
        if (!ast->num_insert_columns) {
            positions[i] = (size_t)indices[i];
        } else {
            const qihse_col_def_t* def = qihse_table_col_def(table, (size_t)indices[i]);
            for (size_t j = 0; def && j < ast->num_insert_columns; ++j)
                if (ast->insert_columns[j] &&
                    strcasecmp(ast->insert_columns[j], def->name) == 0) {
                    if (positions[i] != SIZE_MAX) return false;
                    positions[i] = j;
                }
        }
        if (positions[i] >= (ast->num_insert_columns ? ast->num_insert_columns :
                              qihse_table_num_cols(table))) return false;
    }
    for (size_t r = 0; r < ast->num_insert_rows; ++r) {
        if (!ast->insert_rows || !ast->insert_rows[r]) return false;
        qihse_col_value_t values[3] = {{0}, {0}, {0}};
        for (size_t i = 0; i < 3; ++i) {
            const char* text = ast->insert_rows[r][positions[i]];
            char* end = NULL;
            errno = 0;
            if (!text) return false;
            long value = strtol(text, &end, 10);
            if (end == text || *end || errno == ERANGE || value < 0 ||
                value > (i == 0 ? INT32_MAX : UINT16_MAX)) return false;
            values[i].type = QIHSE_TS_INT32;
            values[i].v.i32 = (int32_t)value;
        }
        uwp_sql_labels_t compact = {0, 1, 2, true};
        if (!uwp_sql_row_allowed(user, compact, values, 3)) return false;
    }
    return true;
}

/* Authorize a parsed statement immediately before execution.  Parsing and
 * describing SQL do not touch data, but EXECUTE must revalidate the live
 * principal and enforce the target table's write boundary.  DDL remains an
 * Operator-only surface until QIHSE has a dedicated schema capability. */
static bool uwp_sql_statement_allowed(const qihse_sql_ast_t* ast,
                                      qihse_user_t* user) {
    if (!ast || !user || !qihse_auth_user_is_active(user)) return false;

    switch (ast->stmt_type) {
        case QIHSE_SQL_SELECT:
            for (size_t i = 0; i < ast->num_from_tables; ++i) {
                const char* name = ast->from_tables[i].table_name;
                if (!name || !qihse_auth_can_access_object(
                                 user, 0, (uint64_t)uwp_fnv1a(name),
                                 QIHSE_ACL_READ))
                    return false;
            }
            for (size_t i = 0; i < ast->num_joins; ++i) {
                const char* name = ast->joins[i].table.table_name;
                if (!name || !qihse_auth_can_access_object(
                                 user, 0, (uint64_t)uwp_fnv1a(name),
                                 QIHSE_ACL_READ))
                    return false;
            }
            return true;

        case QIHSE_SQL_INSERT:
        case QIHSE_SQL_UPDATE:
        case QIHSE_SQL_DELETE:
            return ast->table_name && ast->table_name[0] != '\0' &&
                   qihse_auth_can_access_object(
                       user, 0, (uint64_t)uwp_fnv1a(ast->table_name),
                       QIHSE_ACL_WRITE);

        case QIHSE_SQL_CREATE:
        case QIHSE_SQL_CREATE_EXTENSION:
        case QIHSE_SQL_CREATE_FUNCTION:
        case QIHSE_SQL_CREATE_TRIGGER:
        case QIHSE_SQL_DROP_TRIGGER:
        case QIHSE_SQL_DROP:
        case QIHSE_SQL_ALTER:
        case QIHSE_SQL_CREATE_VIEW:
        case QIHSE_SQL_DROP_VIEW:
        case QIHSE_SQL_CREATE_MATVIEW:
        case QIHSE_SQL_REFRESH:
        case QIHSE_SQL_CREATE_SEQ:
        case QIHSE_SQL_DROP_SEQ:
        case QIHSE_SQL_TRUNCATE:
        case QIHSE_SQL_REINDEX:
        case QIHSE_SQL_CLUSTER:
        case QIHSE_SQL_GRANT:
        case QIHSE_SQL_REVOKE:
        case QIHSE_SQL_CREATE_ROLE:
        case QIHSE_SQL_DROP_ROLE:
        case QIHSE_SQL_ALTER_ROLE:
            return qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR;

        default:
            return true;
    }
}

/* Lazily initialise the hash table buckets. */
static void uwp_ps_hash_ensure(uwp_ps_hash_t* h) {
    if (h->buckets) return;
    h->num_buckets = UWP_PS_INIT_BUCKETS;
    h->buckets = (uwp_ps_node_t**)calloc(h->num_buckets, sizeof(uwp_ps_node_t*));
}

/* Grow the hash table when load factor > 0.75. */
static void uwp_ps_hash_grow(uwp_ps_hash_t* h) {
    if (h->count * 4 < h->num_buckets * 3) return;
    size_t new_cap = h->num_buckets * 2;
    uwp_ps_node_t** new_buckets =
        (uwp_ps_node_t**)calloc(new_cap, sizeof(uwp_ps_node_t*));
    if (!new_buckets) return;
    for (size_t i = 0; i < h->num_buckets; i++) {
        uwp_ps_node_t* node = h->buckets[i];
        while (node) {
            uwp_ps_node_t* next = node->next;
            size_t idx = node->stmt_id % new_cap;
            node->next = new_buckets[idx];
            new_buckets[idx] = node;
            node = next;
        }
    }
    free(h->buckets);
    h->buckets = new_buckets;
    h->num_buckets = new_cap;
}

/* Find a node by stmt_id.  Returns NULL if not found. */
static uwp_ps_node_t* uwp_ps_hash_find(uwp_ps_hash_t* h, uint32_t stmt_id) {
    if (!h->buckets) return NULL;
    size_t idx = stmt_id % h->num_buckets;
    uwp_ps_node_t* node = h->buckets[idx];
    while (node) {
        if (node->stmt_id == stmt_id) return node;
        node = node->next;
    }
    return NULL;
}

/* Insert a new node.  Caller must ensure stmt_id is not already present. */
static uwp_ps_node_t* uwp_ps_hash_insert(uwp_ps_hash_t* h, uint32_t stmt_id,
                                         uwp_ps_slot_t* slot) {
    uwp_ps_node_t* node = (uwp_ps_node_t*)malloc(sizeof(uwp_ps_node_t));
    if (!node) return NULL;
    node->stmt_id = stmt_id;
    node->slot = slot;
    size_t idx = stmt_id % h->num_buckets;
    node->next = h->buckets[idx];
    h->buckets[idx] = node;
    h->count++;
    uwp_ps_hash_grow(h);
    return node;
}

/* Remove and free a node by stmt_id.  The slot is freed by the caller. */
static void uwp_ps_hash_remove(uwp_ps_hash_t* h, uint32_t stmt_id) {
    if (!h->buckets) return;
    size_t idx = stmt_id % h->num_buckets;
    uwp_ps_node_t* prev = NULL;
    uwp_ps_node_t* node = h->buckets[idx];
    while (node) {
        if (node->stmt_id == stmt_id) {
            if (prev) prev->next = node->next;
            else      h->buckets[idx] = node->next;
            h->count--;
            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }
}

/* Free a slot and its bound values. */
static void uwp_ps_slot_free(uwp_ps_slot_t* s) {
    if (!s) return;
    for (int i = 0; i < UWP_PS_MAX_PARAMS; i++)
        free(s->bound_values[i]);
    free(s);
}

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

/* -------------------------------------------------------------------------
 * SQL row store and UPDATE / DELETE execution.
 *
 * The mutable table store (src/tractable/qihse_table_store.c) is the only
 * in-tree store with in-place update and delete primitives, so parsed UPDATE
 * and DELETE statements execute against it.  The store is process-wide and
 * lazily created, matching the prepared-statement cache above: the UWP SQL
 * path has no per-connection engine state yet, and ctx->sql_engine is an
 * opaque caller-owned pointer this file does not dereference.  Tables must be
 * created in it (qihse_table_store_create_table) before DML can target them.
 *
 * Execution reads only the structured AST.  The raw WHERE text is consulted
 * solely to *verify* that the AST is a complete, faithful representation of
 * the clause (uwp_dml_where_verifies); a construct the parser dropped -- an
 * OR, parentheses, a NOT, a malformed tail -- refuses the statement instead of
 * silently matching rows the statement did not ask for.  Nothing is executed
 * from the raw text.
 * ------------------------------------------------------------------------- */

static qihse_ts_type_t uwp_sql_type_to_ts_type(qihse_sql_type_t t);
static uwp_sts_result_t uwp_dispatch_txn_locked(qihse_uwp_context_t* ctx,
    uint8_t command_opcode, const uint8_t* payload, size_t payload_len,
    qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
    qihse_uwp_write_fn write_fn, void* write_ctx);
static bool uwp_sql_validate_keys(const qihse_schema_table_t* schema,
                                  const qihse_table_t* table,
                                  const qihse_table_txn_t* txn);
static qihse_table_store_t* uwp_sql_row_store;
static pthread_mutex_t uwp_sql_row_store_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Serializes catalog publication with SQL and schema readers. */
static pthread_mutex_t uwp_sql_dispatch_mutex = PTHREAD_MUTEX_INITIALIZER;
static qihse_uwp_context_t* uwp_sql_durable_ctx;

/* Only a single context may own the process-wide SQL row store. On recovery
 * the caller may supply NULL schema to adopt the restored registry. */
static int uwp_sql_open_durable_locked(qihse_uwp_context_t* ctx, const char* path) {
    if (!ctx || !path || !*path) return -1;
    pthread_mutex_lock(&uwp_sql_row_store_mutex);
    if (uwp_sql_row_store || uwp_sql_durable_ctx) {
        pthread_mutex_unlock(&uwp_sql_row_store_mutex);
        return -1;
    }
    qihse_table_store_t* store = qihse_table_store_open_durable(path);
    if (!store) {
        pthread_mutex_unlock(&uwp_sql_row_store_mutex);
        return -1;
    }
    const uint8_t* image = NULL;
    size_t len = 0;
    bool existing = qihse_table_store_schema_image(store, &image, &len);
    qihse_schema_registry_t* recovered = NULL;
    uint8_t* supplied = NULL;
    size_t supplied_len = 0;
    bool ok = true;
    if (existing) {
        ok = qihse_schema_deserialize(image, len, &recovered) == 0;
        if (ok && ctx->schema) {
            ok = qihse_schema_serialize(ctx->schema, &supplied, &supplied_len) == 0 &&
                 supplied_len == len && !memcmp(supplied, image, len);
        }
    } else if (ctx->schema) {
        ok = qihse_schema_serialize(ctx->schema, &supplied, &supplied_len) == 0 &&
             qihse_table_store_set_schema_image(store, supplied, supplied_len);
    } else ok = false;
    qihse_schema_registry_t* schema = ctx->schema ? ctx->schema : recovered;
    if (ok) {
        /* A catalog-only or row-only generation is not a recovered schema.
         * Unique table names and equal counts make the row-to-schema check
         * below a complete bijection. */
        ok = qihse_schema_table_count(schema) ==
             qihse_table_store_table_count(store);
        for (size_t i = 0; ok && i < qihse_table_store_table_count(store); ++i) {
            qihse_table_t* t = qihse_table_store_table_at(store, i);
            const qihse_schema_table_t* st =
                qihse_schema_get_table(schema, qihse_table_name(t));
            if (!st || qihse_table_num_cols(t) != st->num_columns) {
                ok = false; break;
            }
            for (size_t c = 0; c < st->num_columns; ++c) {
                const qihse_col_def_t* col = qihse_table_col_def(t, c);
                if (!col || strcmp(col->name, st->columns[c].name) ||
                    col->type != uwp_sql_type_to_ts_type(st->columns[c].type)) {
                    ok = false; break;
                }
            }
            if (ok && !uwp_sql_validate_keys(st, t, NULL)) ok = false;
            if (!ok) break;
        }
    }
    free(supplied);
    if (!ok || !qihse_table_store_is_durable(store)) {
        qihse_schema_registry_destroy(recovered);
        qihse_table_store_destroy(store);
        pthread_mutex_unlock(&uwp_sql_row_store_mutex);
        return -1;
    }
    if (!ctx->schema) ctx->schema = recovered;
    else qihse_schema_registry_destroy(recovered);
    uwp_sql_row_store = store;
    uwp_sql_durable_ctx = ctx;
    pthread_mutex_unlock(&uwp_sql_row_store_mutex);
    return 0;
}

int qihse_uwp_sql_open_durable(qihse_uwp_context_t* ctx, const char* path) {
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    int rc = uwp_sql_open_durable_locked(ctx, path);
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return rc;
}

void qihse_uwp_sql_close_durable(qihse_uwp_context_t* ctx) {
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    pthread_mutex_lock(&uwp_sql_row_store_mutex);
    if (ctx && ctx == uwp_sql_durable_ctx) {
        qihse_table_store_destroy(uwp_sql_row_store);
        uwp_sql_row_store = NULL;
        uwp_sql_durable_ctx = NULL;
    }
    pthread_mutex_unlock(&uwp_sql_row_store_mutex);
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
}

bool qihse_uwp_sql_durable_ready(const qihse_uwp_context_t* ctx) {
    pthread_mutex_lock(&uwp_sql_row_store_mutex);
    bool ready = ctx && ctx == uwp_sql_durable_ctx &&
                 qihse_table_store_is_durable(uwp_sql_row_store);
    pthread_mutex_unlock(&uwp_sql_row_store_mutex);
    return ready;
}

static int uwp_catalog_name_cmp(const void* a, const void* b) {
    return strcmp(*(char* const*)a, *(char* const*)b);
}

uwp_sts_result_t qihse_uwp_sql_catalog_tables(qihse_uwp_context_t* ctx,
    qihse_user_t* user, char*** names, size_t* count) {
    if (!names || !count) return UWP_STS_ERR_ARGS;
    *names = NULL;
    *count = 0;
    if (!user || !qihse_auth_user_is_active(user)) return UWP_STS_ERR_PERM;
    uwp_sts_result_t result = UWP_STS_ERR_FAILED;
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    if (!ctx || ctx != uwp_sql_durable_ctx || !ctx->schema ||
        !qihse_table_store_is_durable(uwp_sql_row_store)) goto done;
    size_t total = qihse_schema_table_count(ctx->schema);
    if (total > 256 || total != qihse_table_store_table_count(uwp_sql_row_store))
        goto done;
    char** visible = calloc(total ? total : 1, sizeof(*visible));
    if (!visible) goto done;
    size_t n = 0;
    for (size_t i = 0; i < total; ++i) {
        const qihse_schema_table_t* table = qihse_schema_table_at(ctx->schema, i);
        qihse_table_t* rows = table && table->name ?
            qihse_table_store_find_table(uwp_sql_row_store, table->name) : NULL;
        if (!rows || table->num_columns != qihse_table_num_cols(rows))
            goto invalid;
        for (size_t c = 0; c < table->num_columns; ++c) {
            const qihse_col_def_t* col = qihse_table_col_def(rows, c);
            if (!col || !col->name || !table->columns[c].name ||
                strcmp(col->name, table->columns[c].name) ||
                col->type != uwp_sql_type_to_ts_type(table->columns[c].type))
                goto invalid;
        }
        if (!qihse_auth_can_access_object(user, 0,
                (uint64_t)uwp_fnv1a(table->name), QIHSE_ACL_READ)) continue;
        visible[n] = strdup(table->name);
        if (!visible[n]) goto invalid;
        ++n;
    }
    qsort(visible, n, sizeof(*visible), uwp_catalog_name_cmp);
    *names = visible;
    *count = n;
    result = UWP_STS_OK;
    goto done;
invalid:
    for (size_t i = 0; i < n; ++i) free(visible[i]);
    free(visible);
done:
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return result;
}

static bool uwp_catalog_validate_row(const qihse_col_value_t* row,
                                      size_t columns, void* context) {
    (void)row; (void)columns; (void)context;
    return true;
}

uwp_sts_result_t qihse_uwp_sql_catalog_indexes(qihse_uwp_context_t* ctx,
    qihse_user_t* user, const char* table, char*** names, size_t* count) {
    if (!names || !count || (table && !*table)) return UWP_STS_ERR_ARGS;
    *names = NULL; *count = 0;
    if (!user || !qihse_auth_user_is_active(user)) return UWP_STS_ERR_PERM;
    uwp_sts_result_t result = UWP_STS_ERR_FAILED;
    char** copied = NULL;
    size_t n = 0, capacity = 0;
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    if (!ctx || ctx != uwp_sql_durable_ctx || !ctx->schema ||
        !qihse_table_store_is_durable(uwp_sql_row_store) ||
        qihse_schema_table_count(ctx->schema) !=
            qihse_table_store_table_count(uwp_sql_row_store)) goto done;
    size_t total = qihse_schema_table_count(ctx->schema);
    if (total > 256) goto done;
    for (size_t t = 0; t < total; ++t) {
        const qihse_schema_table_t* definition = qihse_schema_table_at(ctx->schema, t);
        if (!definition || !definition->name) goto done;
        if (table && strcasecmp(definition->name, table)) continue;
        qihse_table_t* rows = qihse_table_store_find_table(uwp_sql_row_store,
                                                        definition->name);
        if (!rows || definition->num_columns != qihse_table_num_cols(rows)) goto done;
        if (!qihse_auth_can_access_object(user, 0, uwp_fnv1a(definition->name),
                                          QIHSE_ACL_READ) ||
            !qihse_table_scan_user(rows, user, uwp_catalog_validate_row, NULL)) continue;
        if (definition->num_indexes > 256 ||
            (definition->num_indexes && !definition->indexes)) goto done;
        for (size_t i = 0; i < definition->num_indexes; ++i) {
            if (n == capacity) {
                if (capacity >= 4096) goto done;
                size_t grown_capacity = capacity ? capacity * 2 : 16;
                char** grown = realloc(copied, grown_capacity * sizeof(*copied));
                if (!grown) goto done;
                copied = grown; capacity = grown_capacity;
            }
            if (!definition->indexes[i].name ||
                !(copied[n] = strdup(definition->indexes[i].name))) goto done;
            ++n;
        }
        if (!qihse_auth_can_access_object(user, 0, uwp_fnv1a(definition->name),
                                          QIHSE_ACL_READ)) {
            result = UWP_STS_ERR_PERM;
            goto done;
        }
    }
    if (!qihse_auth_user_is_active(user)) {
        result = UWP_STS_ERR_PERM;
        goto done;
    }
    if (n > 1) qsort(copied, n, sizeof(*copied), uwp_catalog_name_cmp);
    *names = copied; *count = n;
    copied = NULL;
    result = UWP_STS_OK;
done:
    if (copied) {
        for (size_t i = 0; i < n; ++i) free(copied[i]);
        free(copied);
    }
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return result;
}

#define UWP_SQL_TXN_MAGIC 0x51535458u
#define UWP_SQL_TXN_MAX_TABLES 16u
typedef struct {
    char* table_name;
    qihse_table_txn_t* table_txn;
    bool read_observed;
    bool write_observed;
} uwp_sql_txn_table_entry_t;

typedef struct {
    uint32_t magic;
    size_t table_count;
    uwp_sql_txn_table_entry_t tables[UWP_SQL_TXN_MAX_TABLES];
    const qihse_schema_registry_t* schema;
    qihse_schema_registry_t* ddl_staged;
    uint8_t* ddl_expected;
    size_t ddl_expected_len;
    char* ddl_names[UWP_SQL_TXN_MAX_TABLES];
    qihse_col_value_t** ddl_rows[UWP_SQL_TXN_MAX_TABLES];
    size_t ddl_row_counts[UWP_SQL_TXN_MAX_TABLES];
    qihse_ts_source_fence_t ddl_sources[UWP_SQL_TXN_MAX_TABLES];
    size_t ddl_count;
    bool ddl_changed;
    uint32_t ddl_user_id;
    uint32_t ddl_tenant_id;
    uint32_t principal_id;
    uint32_t principal_tenant_id;
    bool retry_enabled;
    char retry_key[QIHSE_TS_RETRY_MAX_TEXT + 1u];
    char retry_principal[QIHSE_TS_RETRY_MAX_TEXT + 1u];
    char retry_tenant[QIHSE_TS_RETRY_MAX_TEXT + 1u];
    uint8_t retry_digest[QIHSE_TS_RETRY_DIGEST_SIZE];
    qihse_ts_retry_outcome_t retry_outcome;
    qihse_ts_retry_status_t* retry_status_out;
    qihse_ts_retry_outcome_t* committed_outcome;
} uwp_sql_txn_resource_t;

bool qihse_uwp_sql_txn_has_ddl(const qihse_txn_t* txn) {
    const uwp_sql_txn_resource_t* resource = txn ? txn->resource_ctx : NULL;
    return resource && resource->magic == UWP_SQL_TXN_MAGIC &&
        resource->ddl_changed;
}

bool qihse_uwp_sql_txn_bind_retry(qihse_txn_t* txn,
    const qihse_ts_retry_identity_t* identity,
    const qihse_ts_retry_outcome_t* outcome,
    qihse_ts_retry_status_t* status_out,
    qihse_ts_retry_outcome_t* committed_outcome) {
    if (!txn || !identity || !outcome || !status_out || !committed_outcome ||
        !identity->key || !identity->principal || !identity->tenant)
        return false;
    uwp_sql_txn_resource_t* resource = txn->resource_ctx;
    if (!resource || resource->magic != UWP_SQL_TXN_MAGIC ||
        !resource->table_count || resource->retry_enabled) return false;
    size_t k = strnlen(identity->key, sizeof(resource->retry_key));
    size_t p = strnlen(identity->principal, sizeof(resource->retry_principal));
    size_t t = strnlen(identity->tenant, sizeof(resource->retry_tenant));
    if (!k || k >= sizeof(resource->retry_key) || !p ||
        p >= sizeof(resource->retry_principal) || !t ||
        t >= sizeof(resource->retry_tenant)) return false;
    memcpy(resource->retry_key, identity->key, k + 1u);
    memcpy(resource->retry_principal, identity->principal, p + 1u);
    memcpy(resource->retry_tenant, identity->tenant, t + 1u);
    memcpy(resource->retry_digest, identity->digest, sizeof(resource->retry_digest));
    resource->retry_outcome = *outcome;
    resource->retry_status_out = status_out;
    resource->committed_outcome = committed_outcome;
    resource->retry_enabled = true;
    return true;
}

typedef struct {
    const qihse_col_value_t** rows;
    size_t count, cap;
    bool valid;
} uwp_sql_key_rows_t;

static bool uwp_sql_collect_key_row(const qihse_col_value_t* row, size_t n,
                                    void* opaque) {
    (void)n;
    uwp_sql_key_rows_t* keys = opaque;
    if (keys->count == keys->cap) { keys->valid = false; return false; }
    keys->rows[keys->count++] = row;
    return true;
}

static bool uwp_sql_equal_key(const qihse_col_value_t* a,
                              const qihse_col_value_t* b) {
    if (a->type != b->type) return false;
    if (a->is_null || b->is_null) return false;
    switch (a->type) {
        case QIHSE_TS_INT32: return a->v.i32 == b->v.i32;
        case QIHSE_TS_INT64:
        case QIHSE_TS_TIMESTAMPTZ: return a->v.i64 == b->v.i64;
        case QIHSE_TS_BOOLEAN: return a->v.boolean == b->v.boolean;
        case QIHSE_TS_STRING:
        case QIHSE_TS_UUID:
        case QIHSE_TS_JSONB:
        case QIHSE_TS_NUMERIC:
        case QIHSE_TS_TSVECTOR:
            return a->v.str && b->v.str && !strcmp(a->v.str, b->v.str);
        default: return false;
    }
}

/* Validate the complete post-transaction shadow, not individual statements:
 * UPDATE can swap two keys and DELETE can remove an earlier duplicate. */
static bool uwp_sql_validate_keys(const qihse_schema_table_t* schema,
                                  const qihse_table_t* table,
                                  const qihse_table_txn_t* txn) {
    if (!schema || !table || schema->num_columns != qihse_table_num_cols(table) ||
        schema->num_fks || schema->num_checks) return false;
    bool keyed = schema->num_uniques != 0;
    size_t pk_count = 0;
    for (size_t c = 0; c < schema->num_columns; ++c) {
        const qihse_schema_column_t* col = &schema->columns[c];
        keyed |= col->is_unique || col->is_primary_key;
        pk_count += !!col->is_primary_key;
        if (col->fk || col->check_expr || col->is_serial ||
            (col->is_unique && !col->not_null && !col->is_primary_key))
            return false;
    }
    if (pk_count > 1) return false;
    if (!keyed) return true;
    /* A uniqueness failure must not disclose a classified row's key to a
     * lower-clearance writer. Labeled keys need a scoped authorization-aware
     * index; do not read them through the context-free row scanner. */
    for (size_t c = 0; c < schema->num_columns; ++c)
        if (!strncasecmp(schema->columns[c].name, "__qihse_", 8)) return false;
    size_t count = txn ? qihse_table_txn_row_count(txn) : qihse_table_row_count(table);
    if (count > SIZE_MAX / sizeof(qihse_col_value_t*)) return false;
    uwp_sql_key_rows_t rows = { .cap = count, .valid = true };
    rows.rows = calloc(count ? count : 1, sizeof(*rows.rows));
    if (!rows.rows) return false;
    if (txn) qihse_table_txn_scan(txn, uwp_sql_collect_key_row, &rows);
    else qihse_table_scan(table, uwp_sql_collect_key_row, &rows);
    bool ok = rows.valid && rows.count == count &&
              schema->num_columns == qihse_table_num_cols(table) &&
              !schema->num_fks && !schema->num_checks;
    for (size_t c = 0; ok && c < schema->num_columns; ++c) {
        const qihse_schema_column_t* col = &schema->columns[c];
        if (col->fk || col->check_expr || col->is_serial ||
            ((col->is_unique || col->is_primary_key) &&
             col->type != QIHSE_TYPE_INT && col->type != QIHSE_TYPE_BIGINT &&
             col->type != QIHSE_TYPE_TEXT && col->type != QIHSE_TYPE_VARCHAR &&
             col->type != QIHSE_TYPE_UUID)) {
            ok = false; break;
        }
        if (!col->is_unique && !col->is_primary_key) continue;
        for (size_t i = 0; ok && i < count; ++i)
            for (size_t j = 0; j < i; ++j)
                if (uwp_sql_equal_key(&rows.rows[i][c], &rows.rows[j][c])) {
                    ok = false; break;
                }
    }
    for (size_t k = 0; ok && k < schema->num_uniques; ++k) {
        const qihse_sql_unique_t* key = &schema->uniques[k];
        if (!key->columns || key->num_columns != 1 || !key->columns[0]) {
            ok = false; break;
        }
        size_t c = 0;
        while (c < schema->num_columns &&
               strcasecmp(schema->columns[c].name, key->columns[0])) ++c;
        if (c == schema->num_columns ||
            (!schema->columns[c].not_null && !schema->columns[c].is_primary_key)) {
            ok = false; break;
        }
        for (size_t i = 0; ok && i < count; ++i)
            for (size_t j = 0; j < i; ++j)
                if (uwp_sql_equal_key(&rows.rows[i][c], &rows.rows[j][c])) {
                    ok = false; break;
                }
    }
    free(rows.rows);
    return ok;
}

static void uwp_sql_free_stats_rows(qihse_col_value_t** rows, size_t count);
static bool uwp_sql_seed_stats(qihse_uwp_context_t* ctx,
    const uwp_sql_txn_resource_t* staged,
    const qihse_sql_ast_t* query, const qihse_user_t* user,
    qihse_col_value_t*** rows, size_t* count,
    qihse_ts_source_fence_t* source_fence);

static bool uwp_sql_txn_commit_ddl(uwp_sql_txn_resource_t* resource,
                                   const qihse_user_t* principal) {
    qihse_ts_new_table_t defs[UWP_SQL_TXN_MAX_TABLES] = {0};
    uint8_t* image = NULL;
    size_t image_len = 0;
    bool ok = resource->ddl_staged && resource->ddl_changed &&
        qihse_schema_serialize(resource->ddl_staged, &image, &image_len) == 0;
    for (size_t i = 0; ok && i < resource->ddl_count; ++i) {
        const qihse_schema_table_t* table = qihse_schema_get_table(
            resource->ddl_staged, resource->ddl_names[i]);
        if (!table || !table->num_columns || !table->columns) { ok = false; break; }
        qihse_col_def_t* cols = calloc(table->num_columns, sizeof(*cols));
        if (!cols) { ok = false; break; }
        defs[i].name = table->name;
        defs[i].cols = cols;
        defs[i].num_cols = table->num_columns;
        defs[i].initial_rows = (const qihse_col_value_t* const*)resource->ddl_rows[i];
        defs[i].num_initial_rows = resource->ddl_row_counts[i];
        for (size_t c = 0; c < table->num_columns; ++c) {
            cols[c].name = table->columns[c].name;
            cols[c].type = uwp_sql_type_to_ts_type(table->columns[c].type);
        }
    }
    if (ok && resource->ddl_count) {
        qihse_ts_source_fence_t sources[UWP_SQL_TXN_MAX_TABLES] = {0};
        size_t source_count = 0;
        for (size_t i = 0; ok && i < resource->ddl_count; ++i) {
            if (!resource->ddl_sources[i].table) continue;
            size_t j = 0;
            while (j < source_count && sources[j].table !=
                   resource->ddl_sources[i].table) ++j;
            if (j < source_count) {
                if (sources[j].generation != resource->ddl_sources[i].generation)
                    ok = false;
            } else sources[source_count++] = resource->ddl_sources[i];
        }
        if (ok) ok = qihse_table_store_create_tables_seeded_with_schema(
            uwp_sql_row_store, defs, resource->ddl_count, sources, source_count,
            principal, resource->ddl_expected, resource->ddl_expected_len,
            image, image_len);
    } else if (ok) {
        ok = qihse_table_store_replace_schema_image(uwp_sql_row_store,
            resource->ddl_expected, resource->ddl_expected_len, image, image_len);
    }
    if (ok) qihse_schema_registry_replace(
        (qihse_schema_registry_t*)resource->schema, resource->ddl_staged);
    for (size_t i = 0; i < resource->ddl_count; ++i) free((void*)defs[i].cols);
    free(image);
    return ok;
}

static void uwp_sql_txn_cleanup(uwp_sql_txn_resource_t* resource) {
    for (size_t i = 0; i < resource->ddl_count; ++i) {
        free(resource->ddl_names[i]);
        uwp_sql_free_stats_rows(resource->ddl_rows[i], resource->ddl_row_counts[i]);
    }
    free(resource->ddl_expected);
    qihse_schema_registry_destroy(resource->ddl_staged);
    resource->magic = 0;
    free(resource);
}

static int uwp_sql_txn_commit(void* opaque) {
    uwp_sql_txn_resource_t* resource = (uwp_sql_txn_resource_t*)opaque;
    if (!resource || resource->magic != UWP_SQL_TXN_MAGIC ||
        (resource->table_count == 0 && !resource->ddl_changed) ||
        resource->table_count > UWP_SQL_TXN_MAX_TABLES ||
        resource->ddl_count > UWP_SQL_TXN_MAX_TABLES ||
        (resource->ddl_count && (resource->table_count || resource->retry_enabled)))
        return -1;
    uint64_t principal_generation = 0;
    qihse_user_t* principal = qihse_auth_borrow_principal_scoped(
        resource->principal_id, &principal_generation);
    bool authorized = principal && qihse_auth_user_is_active(principal) &&
        qihse_user_get_tenant_id(principal) == resource->principal_tenant_id;
    for (size_t i = 0; authorized && i < resource->table_count; ++i)
        authorized = qihse_auth_can_access_object(principal, 0,
            (uint64_t)uwp_fnv1a(resource->tables[i].table_name),
            resource->tables[i].write_observed ? QIHSE_ACL_WRITE : QIHSE_ACL_READ);
    if (resource->ddl_changed) {
        authorized = authorized && resource->ddl_user_id == resource->principal_id &&
            resource->ddl_tenant_id == resource->principal_tenant_id;
        for (size_t i = 0; authorized && i < resource->ddl_count; ++i) {
            const qihse_schema_table_t* table = qihse_schema_get_table(
                resource->ddl_staged, resource->ddl_names[i]);
            authorized = qihse_auth_can_access_object(principal, 0,
                (uint64_t)uwp_fnv1a(resource->ddl_names[i]), QIHSE_ACL_WRITE);
            if (authorized && table && table->view_query) {
                qihse_sql_ast_t* query = qihse_parse_sql_to_ast(table->view_query);
                authorized = query && query->stmt_type == QIHSE_SQL_SELECT &&
                    query->num_from_tables == 1 && query->from_tables &&
                    query->from_tables[0].table_name &&
                    qihse_auth_can_access_object(principal, 0,
                        (uint64_t)uwp_fnv1a(query->from_tables[0].table_name),
                        QIHSE_ACL_READ);
                qihse_sql_ast_free(query);
            }
        }
        for (size_t i = 0; authorized && i < qihse_schema_table_count(
                resource->ddl_staged); ++i) {
            const qihse_schema_table_t* table = qihse_schema_table_at(
                resource->ddl_staged, i);
            for (size_t j = 0; authorized && j < table->num_indexes; ++j)
                if (!qihse_schema_get_index(resource->schema,
                        table->indexes[j].name))
                    authorized = qihse_auth_can_access_object(principal, 0,
                        (uint64_t)uwp_fnv1a(table->name), QIHSE_ACL_READ);
        }
        bool committed = authorized &&
            qihse_auth_validate_handle_generation(principal, principal_generation) &&
            uwp_sql_txn_commit_ddl(resource, principal);
        if (principal) qihse_auth_release_principal_scoped(principal);
        uwp_sql_txn_cleanup(resource);
        return committed ? 0 : -1;
    }
    qihse_table_txn_t* txns[UWP_SQL_TXN_MAX_TABLES];
    for (size_t i = 0; i < resource->table_count; ++i)
        txns[i] = resource->tables[i].table_txn;
    bool valid = resource->schema != NULL && authorized &&
        qihse_auth_validate_handle_generation(principal, principal_generation);
    for (size_t i = 0; valid && i < resource->table_count; ++i) {
        const char* name = resource->tables[i].table_name;
        valid = uwp_sql_validate_keys(
            qihse_schema_get_table(resource->schema, name),
            qihse_table_store_find_table(uwp_sql_row_store, name), txns[i]);
    }
    bool committed = false;
    if (!valid) {
        if (resource->retry_enabled) *resource->retry_status_out = QIHSE_TS_RETRY_ERROR;
        for (size_t i = 0; i < resource->table_count; ++i)
            qihse_table_txn_rollback(txns[i]);
    } else if (resource->retry_enabled) {
        qihse_ts_retry_identity_t identity = {
            .key = resource->retry_key,
            .principal = resource->retry_principal,
            .tenant = resource->retry_tenant
        };
        memcpy(identity.digest, resource->retry_digest, sizeof(identity.digest));
        *resource->committed_outcome = resource->retry_outcome;
        *resource->retry_status_out = qihse_table_txn_commit_group_retry(txns,
            resource->table_count, &identity, resource->committed_outcome);
        committed = *resource->retry_status_out == QIHSE_TS_RETRY_COMMITTED;
    } else {
        bool wrote = false;
        for (size_t i = 0; i < resource->table_count; ++i)
            wrote |= resource->tables[i].write_observed;
        committed = wrote ? qihse_table_txn_commit_group(txns, resource->table_count)
                          : qihse_table_txn_validate_group(txns, resource->table_count);
    }
    for (size_t i = 0; i < resource->table_count; ++i) {
        resource->tables[i].table_txn = NULL;
        free(resource->tables[i].table_name);
        resource->tables[i].table_name = NULL;
    }
    if (principal) qihse_auth_release_principal_scoped(principal);
    uwp_sql_txn_cleanup(resource);
    return committed ? 0 : -1;
}

static void uwp_sql_txn_rollback(void* opaque) {
    uwp_sql_txn_resource_t* resource = (uwp_sql_txn_resource_t*)opaque;
    if (!resource || resource->magic != UWP_SQL_TXN_MAGIC) return;
    for (size_t i = 0; i < resource->table_count; ++i) {
        qihse_table_txn_rollback(resource->tables[i].table_txn);
        resource->tables[i].table_txn = NULL;
        free(resource->tables[i].table_name);
        resource->tables[i].table_name = NULL;
    }
    uwp_sql_txn_cleanup(resource);
}

qihse_table_store_t* qihse_uwp_sql_table_store(void) {
    pthread_mutex_lock(&uwp_sql_row_store_mutex);
    if (!uwp_sql_row_store)
        uwp_sql_row_store = qihse_table_store_create();
    qihse_table_store_t* store = uwp_sql_row_store;
    pthread_mutex_unlock(&uwp_sql_row_store_mutex);
    return store;
}

/* SQL type -> mutable row store column type.  Mirrors uwp_sql_type_to_col_type
 * so the column store and the row store agree on what a column IS. */
static qihse_ts_type_t uwp_sql_type_to_ts_type(qihse_sql_type_t t) {
    switch (t) {
        case QIHSE_TYPE_INT:
        case QIHSE_TYPE_SERIAL:
            return QIHSE_TS_INT32;
        case QIHSE_TYPE_BIGINT:
        case QIHSE_TYPE_BIGSERIAL:
            return QIHSE_TS_INT64;
        case QIHSE_TYPE_FLOAT:
        case QIHSE_TYPE_DOUBLE:
            return QIHSE_TS_FLOAT;
        case QIHSE_TYPE_BOOL:
            return QIHSE_TS_BOOLEAN;
        case QIHSE_TYPE_TIMESTAMPTZ:
            return QIHSE_TS_TIMESTAMPTZ;
        case QIHSE_TYPE_UUID:
            return QIHSE_TS_UUID;
        case QIHSE_TYPE_JSONB:
            return QIHSE_TS_JSONB;
        case QIHSE_TYPE_NUMERIC:
            return QIHSE_TS_NUMERIC;
        case QIHSE_TYPE_TSVECTOR:
            return QIHSE_TS_TSVECTOR;
        case QIHSE_TYPE_DATE:
        case QIHSE_TYPE_VARCHAR:
        case QIHSE_TYPE_TEXT:
            return QIHSE_TS_STRING;
        default:
            return (qihse_ts_type_t)255;
    }
}

/* UNIQUE is supported only on an explicitly NOT NULL column. PK implies NOT
 * NULL. CHECK, FK, and multi-column keys remain unsupported until their
 * complete semantics can be enforced. */
static bool uwp_sql_text_default(const char* expression, char** value) {
    if (value) *value = NULL;
    if (!expression || *expression != '\'') return false;
    size_t length = strnlen(expression, 4098);
    if (length < 2 || length > 4097 || expression[length - 1] != '\'') return false;
    char* decoded = value ? malloc(length) : NULL;
    if (value && !decoded) return false;
    size_t used = 0;
    for (size_t i = 1; i + 1 < length; ++i) {
        if (expression[i] == '\'') {
            if (i + 2 >= length || expression[i + 1] != '\'') {
                free(decoded); return false;
            }
            ++i;
        }
        if (decoded) decoded[used] = expression[i];
        ++used;
    }
    if (decoded) { decoded[used] = '\0'; *value = decoded; }
    return true;
}

static bool uwp_sql_supported_create(const qihse_sql_ast_t* ast, bool durable) {
    if (!ast || !ast->table_name || !ast->num_columns || !ast->columns ||
        ast->num_fks || ast->num_checks || ast->index_def) return false;
    size_t pk_count = 0;
    for (size_t i = 0; i < ast->num_columns; ++i) {
        const qihse_sql_column_def_t* col = &ast->columns[i];
        if (!col->name || col->is_serial || col->fk || col->check_expr ||
            (col->type == QIHSE_TYPE_NUMERIC &&
             (col->type_len < 1 || col->type_len > 38 ||
              col->type_scale < 0 || col->type_scale > col->type_len)) ||
            ((col->generated_expr || col->generated_stored) &&
             !uwp_sql_generated_expr(col->type, col->generated_stored,
                                     col->generated_expr)) ||
            (col->default_expr &&
             !(col->type == QIHSE_TYPE_UUID &&
               (!strcasecmp(col->default_expr, "gen_random_uuid()") ||
                !strcasecmp(col->default_expr, "uuid_generate_v4()"))) &&
             !(col->type == QIHSE_TYPE_TIMESTAMPTZ &&
               !strcasecmp(col->default_expr, "NOW()")) &&
             !(col->type == QIHSE_TYPE_JSONB &&
               !strcmp(col->default_expr, "'{}'")) &&
             !(col->type == QIHSE_TYPE_INT && !strcmp(col->default_expr, "0")) &&
             !((col->type == QIHSE_TYPE_TEXT || col->type == QIHSE_TYPE_VARCHAR) &&
               uwp_sql_text_default(col->default_expr, NULL))) ||
            ((col->is_primary_key || col->is_unique) &&
            (!durable || (col->is_unique && !col->not_null && !col->is_primary_key))) ||
            (col->type != QIHSE_TYPE_INT && col->type != QIHSE_TYPE_BIGINT &&
             col->type != QIHSE_TYPE_FLOAT && col->type != QIHSE_TYPE_DOUBLE &&
             col->type != QIHSE_TYPE_TEXT && col->type != QIHSE_TYPE_VARCHAR &&
             col->type != QIHSE_TYPE_BOOL && col->type != QIHSE_TYPE_JSONB &&
             col->type != QIHSE_TYPE_UUID && col->type != QIHSE_TYPE_TIMESTAMPTZ &&
             col->type != QIHSE_TYPE_NUMERIC && col->type != QIHSE_TYPE_TSVECTOR))
            return false;
        if (col->generated_stored) {
            bool data_found = false;
            for (size_t j = 0; j < ast->num_columns; ++j)
                if (ast->columns[j].name &&
                    !strcasecmp(ast->columns[j].name, "data") &&
                    ast->columns[j].type == QIHSE_TYPE_JSONB)
                    data_found = true;
            if (!data_found) return false;
            char* probe = uwp_sql_english_vector("");
            if (!probe) return false;
            free(probe);
        }
        pk_count += !!col->is_primary_key;
        for (size_t j = 0; j < i; ++j)
            if (strcasecmp(ast->columns[j].name, col->name) == 0) return false;
    }
    if (pk_count > 1 || (!durable && ast->num_uniques)) return false;
    bool keyed = pk_count || ast->num_uniques;
    for (size_t c = 0; c < ast->num_columns; ++c)
        keyed |= ast->columns[c].is_unique;
    if (keyed)
        for (size_t c = 0; c < ast->num_columns; ++c)
            if (!strncasecmp(ast->columns[c].name, "__qihse_", 8)) return false;
    for (size_t i = 0; i < ast->num_uniques; ++i) {
        const qihse_sql_unique_t* key = &ast->uniques[i];
        if (!key->columns || key->num_columns != 1 || !key->columns[0]) return false;
        size_t c = 0;
        while (c < ast->num_columns &&
               strcasecmp(ast->columns[c].name, key->columns[0])) ++c;
        if (c == ast->num_columns ||
            (!ast->columns[c].is_primary_key && !ast->columns[c].not_null))
            return false;
    }
    return true;
}

static int uwp_sql_txn_create_durable_table(qihse_uwp_context_t* ctx,
    qihse_txn_t* txn, const qihse_sql_ast_t* ast, qihse_user_t* user) {
    if (!txn || !ctx || !ctx->schema || !user ||
        !uwp_sql_supported_create(ast, true)) return -1;
    uwp_sql_txn_resource_t* resource = txn->resource_ctx;
    if (resource && (resource->magic != UWP_SQL_TXN_MAGIC ||
        resource->schema != ctx->schema || resource->table_count ||
        resource->retry_enabled || !resource->ddl_staged ||
        resource->ddl_user_id != qihse_user_get_id(user) ||
        resource->ddl_tenant_id != qihse_user_get_tenant_id(user))) return -1;
    const qihse_schema_registry_t* registry = resource ?
        resource->ddl_staged : ctx->schema;
    if (ast->create_if_not_exists &&
        qihse_schema_get_table(registry, ast->table_name)) {
        if (resource && qihse_schema_get_table(ctx->schema, ast->table_name) == NULL)
            return 0; /* already staged in this transaction */
        return qihse_table_store_find_table(uwp_sql_row_store, ast->table_name)
            ? 0 : -1;
    }
    bool new_resource = resource == NULL;
    if (new_resource) {
        resource = calloc(1, sizeof(*resource));
        if (!resource) return -1;
        resource->magic = UWP_SQL_TXN_MAGIC;
        resource->schema = ctx->schema;
        resource->ddl_user_id = resource->principal_id = qihse_user_get_id(user);
        resource->ddl_tenant_id = resource->principal_tenant_id =
            qihse_user_get_tenant_id(user);
        if (qihse_schema_serialize(ctx->schema, &resource->ddl_expected,
                &resource->ddl_expected_len) != 0 ||
            qihse_schema_deserialize(resource->ddl_expected,
                resource->ddl_expected_len, &resource->ddl_staged) != 0)
            goto fail;
    }
    if (resource->ddl_count >= UWP_SQL_TXN_MAX_TABLES) goto fail;
    char* name = strdup(ast->table_name);
    if (!name) goto fail;
    if (qihse_schema_create_table(resource->ddl_staged, ast) != 0) {
        free(name);
        goto fail;
    }
    resource->ddl_names[resource->ddl_count++] = name;
    resource->ddl_changed = true;
    if (new_resource && qihse_txn_attach_resource(txn, resource,
            uwp_sql_txn_commit, uwp_sql_txn_rollback) != 0) goto fail;
    return 0;
fail:
    if (new_resource) uwp_sql_txn_cleanup(resource);
    return -1;
}

/* Stage a supported CREATE against a private catalog, then persist its
 * catalog and empty row table in a single snapshot before publishing either
 * to readers. Unsupported constraints/types must not be recorded as enforced. */
/* Build a real authenticated index before admitting its catalog definition.
 * On a newly staged table the index is empty; validate its expressions against
 * the staged columns without publishing a row table before the DDL commit. */
static bool uwp_sql_index_ready(const qihse_schema_registry_t* schema,
    const char* index_name, const qihse_user_t* user) {
    const qihse_schema_index_t* definition =
        qihse_schema_get_index(schema, index_name);
    if (!definition || !definition->table_name || !user) return false;
    qihse_table_t* table = uwp_sql_row_store ?
        qihse_table_store_find_table(uwp_sql_row_store, definition->table_name) : NULL;
    qihse_table_store_t* temporary = NULL;
    if (!table) {
        const qihse_schema_table_t* staged =
            qihse_schema_get_table(schema, definition->table_name);
        if (!staged || !staged->num_columns) return false;
        qihse_col_def_t* cols = calloc(staged->num_columns, sizeof(*cols));
        if (!cols) return false;
        bool ok = true;
        for (size_t i = 0; i < staged->num_columns; ++i) {
            cols[i].name = staged->columns[i].name;
            cols[i].type = uwp_sql_type_to_ts_type(staged->columns[i].type);
            if (cols[i].type == (qihse_ts_type_t)255) ok = false;
        }
        if (ok) temporary = qihse_table_store_create();
        if (temporary) table = qihse_table_store_create_table(temporary,
            staged->name, cols, staged->num_columns);
        free(cols);
    }
    qihse_sql_row_index_t* index = NULL;
    bool ready = table && qihse_sql_row_index_build(definition, table, NULL,
                                                      user, &index);
    qihse_sql_row_index_destroy(index);
    qihse_table_store_destroy(temporary);
    return ready;
}

static int uwp_sql_txn_create_durable_index(qihse_uwp_context_t* ctx,
    qihse_txn_t* txn, const qihse_sql_ast_t* ast, qihse_user_t* user) {
    if (!ctx || !ctx->schema || !txn || !user || !ast || !ast->index_def)
        return -1;
    uwp_sql_txn_resource_t* resource = txn->resource_ctx;
    if (resource && (resource->magic != UWP_SQL_TXN_MAGIC ||
        resource->schema != ctx->schema || resource->table_count ||
        resource->retry_enabled || !resource->ddl_staged ||
        resource->ddl_user_id != qihse_user_get_id(user) ||
        resource->ddl_tenant_id != qihse_user_get_tenant_id(user))) return -1;
    qihse_schema_registry_t* staged = resource ? resource->ddl_staged : NULL;
    bool new_resource = resource == NULL;
    if (new_resource) {
        resource = calloc(1, sizeof(*resource));
        if (!resource) return -1;
        resource->magic = UWP_SQL_TXN_MAGIC;
        resource->schema = ctx->schema;
        resource->ddl_user_id = resource->principal_id = qihse_user_get_id(user);
        resource->ddl_tenant_id = resource->principal_tenant_id =
            qihse_user_get_tenant_id(user);
        if (qihse_schema_serialize(ctx->schema, &resource->ddl_expected,
                &resource->ddl_expected_len) != 0 ||
            qihse_schema_deserialize(resource->ddl_expected,
                resource->ddl_expected_len, &resource->ddl_staged) != 0) {
            uwp_sql_txn_cleanup(resource);
            return -1;
        }
        staged = resource->ddl_staged;
    }
    if (ast->index_def->if_not_exists &&
        qihse_schema_get_index(staged, ast->index_def->name)) {
        if (new_resource) uwp_sql_txn_cleanup(resource);
        return 0;
    }
    uint8_t* image = NULL;
    size_t image_len = 0;
    qihse_schema_registry_t* candidate = NULL;
    bool ready = qihse_schema_serialize(staged, &image, &image_len) == 0 &&
        qihse_schema_deserialize(image, image_len, &candidate) == 0 &&
        qihse_schema_create_index(candidate, ast) == 0 &&
        uwp_sql_index_ready(candidate, ast->index_def->name, user);
    free(image);
    if (!ready) {
        qihse_schema_registry_destroy(candidate);
        if (new_resource) uwp_sql_txn_cleanup(resource);
        return -1;
    }
    qihse_schema_registry_replace(staged, candidate);
    qihse_schema_registry_destroy(candidate);
    resource->ddl_changed = true;
    if (new_resource && qihse_txn_attach_resource(txn, resource,
            uwp_sql_txn_commit, uwp_sql_txn_rollback) != 0) {
        uwp_sql_txn_cleanup(resource);
        return -1;
    }
    return 0;
}

static int uwp_sql_create_durable_index(qihse_uwp_context_t* ctx,
                                         const qihse_sql_ast_t* ast,
                                         const qihse_user_t* user) {
    if (!ctx || !ctx->schema || !ast || !ast->index_def) return -1;
    if (ast->index_def->if_not_exists &&
        qihse_schema_get_index(ctx->schema, ast->index_def->name)) return 0;
    uint8_t *expected = NULL, *image = NULL;
    size_t expected_len = 0, image_len = 0;
    qihse_schema_registry_t* staged = NULL;
    int result = -1;
    if (qihse_schema_serialize(ctx->schema, &expected, &expected_len) != 0 ||
        qihse_schema_deserialize(expected, expected_len, &staged) != 0 ||
        qihse_schema_create_index(staged, ast) != 0 ||
        !uwp_sql_index_ready(staged, ast->index_def->name, user) ||
        qihse_schema_serialize(staged, &image, &image_len) != 0) goto done;
    if (qihse_table_store_replace_schema_image(uwp_sql_row_store,
            expected, expected_len, image, image_len)) {
        qihse_schema_registry_replace((qihse_schema_registry_t*)ctx->schema, staged);
        result = 0;
    }
done:
    free(expected); free(image); qihse_schema_registry_destroy(staged);
    return result;
}

static int uwp_sql_create_durable_table(qihse_uwp_context_t* ctx,
                                        const qihse_sql_ast_t* ast) {
    if (!ctx || !ctx->schema || !uwp_sql_supported_create(ast, true)) return -1;
    if (ast->create_if_not_exists &&
        qihse_schema_get_table(ctx->schema, ast->table_name)) {
        return qihse_table_store_find_table(uwp_sql_row_store, ast->table_name)
            ? 0 : -1;
    }
    uint8_t* original = NULL;
    size_t original_len = 0;
    qihse_schema_registry_t* staged = NULL;
    uint8_t* image = NULL;
    size_t image_len = 0;
    qihse_col_def_t* defs = NULL;
    int result = -1;
    if (qihse_schema_serialize(ctx->schema, &original, &original_len) != 0 ||
        qihse_schema_deserialize(original, original_len, &staged) != 0 ||
        qihse_schema_create_table(staged, ast) != 0 ||
        qihse_schema_serialize(staged, &image, &image_len) != 0)
        goto done;
    const qihse_schema_table_t* table = qihse_schema_get_table(staged, ast->table_name);
    if (!table || table->num_columns != ast->num_columns) goto done;
    defs = calloc(table->num_columns, sizeof(*defs));
    if (!defs) goto done;
    for (size_t i = 0; i < table->num_columns; ++i) {
        defs[i].name = table->columns[i].name;
        defs[i].type = uwp_sql_type_to_ts_type(table->columns[i].type);
    }
    if (!qihse_table_store_create_table_with_schema(uwp_sql_row_store,
            table->name, defs, table->num_columns, image, image_len)) goto done;
    qihse_schema_registry_replace(ctx->schema, staged);
    result = 0;
done:
    free(defs);
    free(image);
    free(original);
    qihse_schema_registry_destroy(staged);
    return result;
}

static bool uwp_sql_parse_uuid_ossp_extension(const char* sql,
                                                bool* if_not_exists) {
    if (!sql || !if_not_exists || strnlen(sql, 257) > 256) return false;
    const char* p = sql;
    while (isspace((unsigned char)*p)) ++p;
#define UWP_EXT_KW(word) do { \
    size_t n = sizeof(word) - 1; \
    if (strlen(p) < n || strncasecmp(p, word, n) || \
        (isalnum((unsigned char)p[n]) || p[n] == '_')) return false; \
    p += n; while (isspace((unsigned char)*p)) ++p; \
} while (0)
    UWP_EXT_KW("CREATE");
    UWP_EXT_KW("EXTENSION");
    *if_not_exists = false;
    if (strlen(p) >= 2 && !strncasecmp(p, "IF", 2) &&
        !(isalnum((unsigned char)p[2]) || p[2] == '_')) {
        p += 2; while (isspace((unsigned char)*p)) ++p;
        UWP_EXT_KW("NOT");
        UWP_EXT_KW("EXISTS");
        *if_not_exists = true;
    }
    if (*p == '"') {
        ++p;
        const char* start = p;
        while (*p && *p != '"') ++p;
        if (*p != '"' || (size_t)(p - start) != 9 ||
            strncasecmp(start, "uuid-ossp", 9)) return false;
        ++p;
    } else {
        const char* start = p;
        while (isalnum((unsigned char)*p) || *p == '_') ++p;
        if ((size_t)(p - start) != 9 || strncasecmp(start, "uuid_ossp", 9))
            return false;
    }
    while (isspace((unsigned char)*p)) ++p;
    if (*p == ';') { ++p; while (isspace((unsigned char)*p)) ++p; }
#undef UWP_EXT_KW
    return *p == '\0';
}

static int uwp_sql_txn_create_durable_extension(qihse_uwp_context_t* ctx,
    qihse_txn_t* txn, qihse_user_t* user, bool if_not_exists) {
    if (!ctx || !ctx->schema || !txn || !user || uwp_sql_durable_ctx != ctx)
        return -1;
    uwp_sql_txn_resource_t* resource = txn->resource_ctx;
    if (resource && (resource->magic != UWP_SQL_TXN_MAGIC ||
        resource->schema != ctx->schema || resource->table_count ||
        resource->retry_enabled || !resource->ddl_staged ||
        resource->ddl_user_id != qihse_user_get_id(user) ||
        resource->ddl_tenant_id != qihse_user_get_tenant_id(user))) return -1;
    qihse_schema_registry_t* staged = resource ? resource->ddl_staged :
        (qihse_schema_registry_t*)ctx->schema;
    if (qihse_schema_has_extension(staged, "uuid-ossp"))
        return if_not_exists ? 0 : -1;
    bool new_resource = resource == NULL;
    if (new_resource) {
        resource = calloc(1, sizeof(*resource));
        if (!resource) return -1;
        resource->magic = UWP_SQL_TXN_MAGIC;
        resource->schema = ctx->schema;
        resource->ddl_user_id = resource->principal_id = qihse_user_get_id(user);
        resource->ddl_tenant_id = resource->principal_tenant_id =
            qihse_user_get_tenant_id(user);
        if (qihse_schema_serialize(ctx->schema, &resource->ddl_expected,
                &resource->ddl_expected_len) != 0 ||
            qihse_schema_deserialize(resource->ddl_expected,
                resource->ddl_expected_len, &resource->ddl_staged) != 0) {
            uwp_sql_txn_cleanup(resource);
            return -1;
        }
    }
    if (qihse_schema_create_extension(resource->ddl_staged, "uuid-ossp") != 0)
        goto fail;
    resource->ddl_changed = true;
    if (new_resource && qihse_txn_attach_resource(txn, resource,
            uwp_sql_txn_commit, uwp_sql_txn_rollback) != 0) goto fail;
    return 0;
fail:
    if (new_resource) uwp_sql_txn_cleanup(resource);
    return -1;
}

static int uwp_sql_create_durable_extension(qihse_uwp_context_t* ctx,
    bool if_not_exists) {
    if (!ctx || !ctx->schema || uwp_sql_durable_ctx != ctx) return -1;
    if (qihse_schema_has_extension(ctx->schema, "uuid-ossp"))
        return if_not_exists ? 0 : -1;
    uint8_t *expected = NULL, *image = NULL;
    size_t expected_len = 0, image_len = 0;
    qihse_schema_registry_t* staged = NULL;
    int rc = -1;
    if (qihse_schema_serialize(ctx->schema, &expected, &expected_len) != 0 ||
        qihse_schema_deserialize(expected, expected_len, &staged) != 0 ||
        qihse_schema_create_extension(staged, "uuid-ossp") != 0 ||
        qihse_schema_serialize(staged, &image, &image_len) != 0) goto done;
    if (qihse_table_store_replace_schema_image(uwp_sql_row_store, expected,
            expected_len, image, image_len)) {
        qihse_schema_registry_replace((qihse_schema_registry_t*)ctx->schema,
                                      staged);
        rc = 0;
    }
done:
    free(expected); free(image); qihse_schema_registry_destroy(staged);
    return rc;
}

static bool uwp_sql_view_query_valid(const qihse_sql_ast_t* ast) {
    if (!ast || !ast->view_name || !ast->view_query || !ast->raw_sql ||
        ast->view_query->stmt_type != QIHSE_SQL_SELECT) return false;
    const qihse_sql_ast_t* query = ast->view_query;
    if (query->num_from_tables != 1 || !query->from_tables ||
        !query->from_tables[0].table_name ||
        query->num_joins || query->num_where_conditions || query->select_distinct ||
        query->set_op != QIHSE_SET_NONE || query->num_select_items != 7 ||
        !query->group_by || query->group_by->num_group_columns != 2 ||
        query->group_by->having_expr || query->num_order_items ||
        strcasecmp(query->group_by->group_columns[0], "source") ||
        strcasecmp(query->group_by->group_columns[1], "record_type"))
        return false;
    static const char* names[] = {
        "source", "record_type", "record_count", "unique_emails",
        "unique_phones", "unique_usernames", "last_update"
    };
    static const char* json[] = {
        "data->>'email'", "data->>'phone'", "data->>'username'"
    };
    for (size_t i = 0; i < 7; ++i) {
        const qihse_sql_select_item_t* item = &query->select_items[i];
        if (!item->expr || item->scalar_subquery || item->window ||
            item->win_kind != QIHSE_WIN_NONE ||
            (i >= 2 && (!item->alias || strcasecmp(item->alias, names[i]))))
            return false;
        if (i < 2 && (item->agg_kind != QIHSE_AGG_NONE ||
            strcasecmp(item->expr, names[i]))) return false;
        if (i == 2 && item->agg_kind != QIHSE_AGG_COUNT_STAR) return false;
        if (i >= 3 && i <= 5 &&
            (item->agg_kind != QIHSE_AGG_COUNT || !item->is_distinct ||
             !item->agg_arg || strcasecmp(item->agg_arg, json[i-3]))) return false;
        if (i == 6 && (item->agg_kind != QIHSE_AGG_MAX ||
            !item->agg_arg || strcasecmp(item->agg_arg, "created_at"))) return false;
    }
    return true;
}

static int uwp_sql_catalog_mutate(qihse_schema_registry_t* registry,
                                  const qihse_sql_ast_t* ast) {
    if (!registry || !ast) return -1;
    switch (ast->stmt_type) {
        case QIHSE_SQL_CREATE_MATVIEW: {
            if (!uwp_sql_view_query_valid(ast) ||
                !qihse_schema_get_table(registry,
                    ast->view_query->from_tables[0].table_name)) return -1;
            qihse_schema_column_t cols[] = {
                {.name="source", .type=QIHSE_TYPE_VARCHAR},
                {.name="record_type", .type=QIHSE_TYPE_VARCHAR},
                {.name="record_count", .type=QIHSE_TYPE_BIGINT},
                {.name="unique_emails", .type=QIHSE_TYPE_BIGINT},
                {.name="unique_phones", .type=QIHSE_TYPE_BIGINT},
                {.name="unique_usernames", .type=QIHSE_TYPE_BIGINT},
                {.name="last_update", .type=QIHSE_TYPE_TIMESTAMPTZ}
            };
            const char* query = uwp_sql_find_keyword(ast->raw_sql, "AS");
            if (!query) return -1;
            while (isspace((unsigned char)*query)) ++query;
            return qihse_schema_create_materialized_view(registry,
                ast->view_name, query, cols, 7);
        }
        case QIHSE_SQL_CREATE_FUNCTION:
            return qihse_schema_create_function(registry, ast->function_def);
        case QIHSE_SQL_CREATE_TRIGGER: {
            const qihse_sql_trigger_def_t* trigger = ast->trigger_def;
            const qihse_schema_table_t* table = trigger ?
                qihse_schema_get_table(registry, trigger->table_name) : NULL;
            if (!table) return -1;
            bool updated_at = false;
            for (size_t i = 0; i < table->num_columns; ++i)
                if (!strcasecmp(table->columns[i].name, "updated_at") &&
                    table->columns[i].type == QIHSE_TYPE_TIMESTAMPTZ)
                    updated_at = true;
            if (!updated_at) return -1;
            return qihse_schema_create_trigger(registry, trigger);
        }
        case QIHSE_SQL_DROP_TRIGGER: {
            const qihse_sql_trigger_def_t* trigger = ast->trigger_def;
            if (!trigger || !trigger->table_name || !trigger->name) return -1;
            if (qihse_schema_drop_trigger(registry, trigger->table_name,
                                          trigger->name) == 0) return 0;
            return trigger->drop_if_exists &&
                qihse_schema_get_table(registry, trigger->table_name) ? 0 : -1;
        }
        default: return -1;
    }
}

/* Persist supported catalog-only objects as one atomic row/catalog image.
 * A transaction owns a private clone until its commit callback publishes it. */
static int uwp_sql_durable_catalog_change(qihse_uwp_context_t* ctx,
    qihse_txn_t* txn, const qihse_sql_ast_t* ast, qihse_user_t* user,
    size_t* created_rows) {
    if (created_rows) *created_rows = 0;
    if (!ctx || !ctx->schema || !user || uwp_sql_durable_ctx != ctx)
        return -1;
    uwp_sql_txn_resource_t* resource = txn ? txn->resource_ctx : NULL;
    if (resource && (resource->magic != UWP_SQL_TXN_MAGIC ||
        resource->schema != ctx->schema || resource->table_count ||
        resource->retry_enabled || !resource->ddl_staged ||
        resource->ddl_user_id != qihse_user_get_id(user) ||
        resource->ddl_tenant_id != qihse_user_get_tenant_id(user))) return -1;
    if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW) {
        if (!uwp_sql_view_query_valid(ast) ||
            !qihse_auth_can_access_object(user, 0,
                (uint64_t)uwp_fnv1a(ast->view_query->from_tables[0].table_name),
                QIHSE_ACL_READ) ||
            !qihse_auth_can_access_object(user, 0,
                (uint64_t)uwp_fnv1a(ast->view_name), QIHSE_ACL_WRITE)) return -1;
    }
    if (txn) {
        bool fresh = resource == NULL;
        if (fresh) {
            resource = calloc(1, sizeof(*resource));
            if (!resource) return -1;
            resource->magic = UWP_SQL_TXN_MAGIC;
            resource->schema = ctx->schema;
            resource->ddl_user_id = resource->principal_id = qihse_user_get_id(user);
            resource->ddl_tenant_id = resource->principal_tenant_id =
                qihse_user_get_tenant_id(user);
            if (qihse_schema_serialize(ctx->schema, &resource->ddl_expected,
                    &resource->ddl_expected_len) ||
                qihse_schema_deserialize(resource->ddl_expected,
                    resource->ddl_expected_len, &resource->ddl_staged)) goto fail;
        }
        if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW &&
            ast->view_if_not_exists &&
            qihse_schema_get_table(resource->ddl_staged, ast->view_name)) {
            const qihse_schema_table_t* existing = qihse_schema_get_table(
                resource->ddl_staged, ast->view_name);
            if (!existing->view_query) goto fail;
            if (fresh) uwp_sql_txn_cleanup(resource);
            return 0;
        }
        if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW &&
            resource->ddl_count >= UWP_SQL_TXN_MAX_TABLES) goto fail;
        char* view_name = ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW ?
            strdup(ast->view_name) : NULL;
        if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW && !view_name) goto fail;
        qihse_col_value_t** seed_rows = NULL;
        size_t seed_count = 0;
        qihse_ts_source_fence_t source_fence = {0};
        if (view_name && !uwp_sql_seed_stats(ctx, resource, ast->view_query, user,
                &seed_rows, &seed_count, &source_fence)) {
            free(view_name); goto fail;
        }
        if (uwp_sql_catalog_mutate(resource->ddl_staged, ast)) {
            free(view_name);
            uwp_sql_free_stats_rows(seed_rows, seed_count);
            goto fail;
        }
        if (view_name) {
            size_t index = resource->ddl_count++;
            resource->ddl_names[index] = view_name;
            resource->ddl_rows[index] = seed_rows;
            resource->ddl_row_counts[index] = seed_count;
            resource->ddl_sources[index] = source_fence;
            if (created_rows) *created_rows = seed_count;
        }
        resource->ddl_changed = true;
        if (fresh && qihse_txn_attach_resource(txn, resource,
                uwp_sql_txn_commit, uwp_sql_txn_rollback)) goto fail;
        return 0;
fail:
        if (fresh) uwp_sql_txn_cleanup(resource);
        return -1;
    }
    uint8_t* expected = NULL;
    size_t expected_len = 0;
    qihse_schema_registry_t* staged = NULL;
    int rc = -1;
    if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW &&
        ast->view_if_not_exists &&
        qihse_schema_get_table(ctx->schema, ast->view_name)) {
        const qihse_schema_table_t* existing = qihse_schema_get_table(
            ctx->schema, ast->view_name);
        return existing->view_query &&
            qihse_table_store_find_table(uwp_sql_row_store, ast->view_name) ? 0 : -1;
    }
    if (qihse_schema_serialize(ctx->schema, &expected, &expected_len) ||
        qihse_schema_deserialize(expected, expected_len, &staged)) goto done;
    qihse_col_value_t** seed_rows = NULL;
    size_t seed_count = 0;
    qihse_ts_source_fence_t source_fence = {0};
    if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW &&
        !uwp_sql_seed_stats(ctx, NULL, ast->view_query, user,
            &seed_rows, &seed_count, &source_fence)) goto done;
    if (uwp_sql_catalog_mutate(staged, ast)) {
        uwp_sql_free_stats_rows(seed_rows, seed_count);
        goto done;
    }
    uwp_sql_txn_resource_t pending = {0};
    pending.schema = ctx->schema;
    pending.ddl_staged = staged;
    pending.ddl_expected = expected;
    pending.ddl_expected_len = expected_len;
    pending.ddl_changed = true;
    if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW) {
        pending.ddl_names[0] = ast->view_name;
        pending.ddl_rows[0] = seed_rows;
        pending.ddl_row_counts[0] = seed_count;
        pending.ddl_sources[0] = source_fence;
        pending.ddl_count = 1;
    }
    if (uwp_sql_txn_commit_ddl(&pending, user)) {
        rc = 0;
        if (created_rows) *created_rows = seed_count;
    }
    uwp_sql_free_stats_rows(seed_rows, seed_count);
done:
    free(expected); qihse_schema_registry_destroy(staged);
    return rc;
}

/* Ensure the mutable row store has a table mirroring the schema registry's
 * definition. Called lazily when SQL-created schemas need writable storage. */
static qihse_table_t* uwp_sql_row_table(qihse_schema_registry_t* schema,
                                        const char* table_name) {
    if (!schema || !table_name) return NULL;
    qihse_table_store_t* store = qihse_uwp_sql_table_store();
    if (!store) return NULL;
    qihse_table_t* t = qihse_table_store_find_table(store, table_name);
    const qihse_schema_table_t* st = qihse_schema_get_table(schema, table_name);
    if (t && (!st || qihse_table_num_cols(t) != st->num_columns)) return NULL;
    if (t) {
        for (size_t c = 0; c < st->num_columns; ++c) {
            const qihse_col_def_t* def = qihse_table_col_def(t, c);
            if (!def || strcmp(def->name, st->columns[c].name) ||
                def->type != uwp_sql_type_to_ts_type(st->columns[c].type))
                return NULL;
        }
        return t;
    }
    if (!st || st->num_columns == 0) return NULL;
    qihse_col_def_t* defs =
        (qihse_col_def_t*)calloc(st->num_columns, sizeof(*defs));
    if (!defs) return NULL;
    for (size_t i = 0; i < st->num_columns; i++) {
        defs[i].name = strdup(st->columns[i].name);
        defs[i].type = uwp_sql_type_to_ts_type(st->columns[i].type);
        if (!defs[i].name) {
            for (size_t j = 0; j < i; j++) free(defs[j].name);
            free(defs);
            return NULL;
        }
    }
    /* create_table deep-copies the definitions; on a duplicate-name race the
     * existing table is returned instead. */
    t = qihse_table_store_create_table(store, table_name, defs, st->num_columns);
    for (size_t i = 0; i < st->num_columns; i++) free(defs[i].name);
    free(defs);
    if (!t) t = qihse_table_store_find_table(store, table_name);
    return t;
}

/* Return the transaction-local table shadow for this statement. A bounded
 * set of table shadows is published together by the row store. This remains
 * an in-memory transaction resource: it does not add WAL recovery or durable
 * cross-model coordination. */
static qihse_table_txn_t* uwp_sql_txn_table(qihse_txn_t* txn,
                                           qihse_table_t* table,
                                           const char* table_name,
                                           const qihse_schema_registry_t* schema,
                                           const qihse_user_t* user, bool write) {
    if (!txn || !table || !table_name || !schema || !user ||
        !qihse_auth_user_is_active(user)) return NULL;
    uwp_sql_txn_resource_t* resource =
        (uwp_sql_txn_resource_t*)txn->resource_ctx;
    if (txn->resource_ctx) {
        if (resource->magic != UWP_SQL_TXN_MAGIC || resource->schema != schema ||
            resource->ddl_changed ||
            resource->principal_id != qihse_user_get_id(user) ||
            resource->principal_tenant_id != qihse_user_get_tenant_id(user))
            return NULL;
        for (size_t i = 0; i < resource->table_count; ++i)
            if (strcmp(resource->tables[i].table_name, table_name) == 0) {
                resource->tables[i].write_observed |= write;
                return resource->tables[i].table_txn;
            }
        if (resource->table_count >= UWP_SQL_TXN_MAX_TABLES) return NULL;
    } else {
        resource = calloc(1, sizeof(*resource));
        if (!resource) return NULL;
        resource->magic = UWP_SQL_TXN_MAGIC;
        resource->schema = schema;
        resource->principal_id = qihse_user_get_id(user);
        resource->principal_tenant_id = qihse_user_get_tenant_id(user);
    }

    char* name_copy = strdup(table_name);
    qihse_table_txn_t* table_txn = qihse_table_txn_begin(table);
    if (!name_copy || !table_txn) {
        free(name_copy);
        qihse_table_txn_rollback(table_txn);
        if (!txn->resource_ctx) free(resource);
        return NULL;
    }
    size_t entry = resource->table_count++;
    resource->tables[entry].table_name = name_copy;
    resource->tables[entry].table_txn = table_txn;
    resource->tables[entry].read_observed = false;
    resource->tables[entry].write_observed = write;
    if (entry == 0 &&
        qihse_txn_attach_resource(txn, resource, uwp_sql_txn_commit,
                                  uwp_sql_txn_rollback) != 0) {
        qihse_table_txn_rollback(table_txn);
        free(name_copy);
        free(resource);
        return NULL;
    }
    return table_txn;
}

/* Single-line DML reply, malloc'd; NULL on allocation failure. */
static char* uwp_dml_replyf(const char* format, ...) {
    va_list args;
    va_list copy;
    va_start(args, format);
    va_copy(copy, args);
    int count = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    char* out = NULL;
    if (count >= 0) {
        out = (char*)malloc((size_t)count + 1);
        if (out) (void)vsnprintf(out, (size_t)count + 1, format, args);
    }
    va_end(args);
    return out;
}

/* Find a bare keyword outside single-quoted literals.  Returns a pointer just
 * past it, or NULL. */
static const char* uwp_sql_find_keyword(const char* sql, const char* keyword) {
    if (!sql || !keyword) return NULL;
    size_t klen = strlen(keyword);
    for (const char* p = sql; *p; ) {
        if (*p == '\'') {
            p++;
            while (*p) {
                if (*p == '\'' && p[1] == '\'') { p += 2; continue; }
                if (*p == '\'') { p++; break; }
                p++;
            }
            continue;
        }
        if (strncasecmp(p, keyword, klen) == 0 &&
            (p == sql || (!isalnum((unsigned char)p[-1]) && p[-1] != '_')) &&
            !isalnum((unsigned char)p[klen]) && p[klen] != '_') {
            return p + klen;
        }
        p++;
    }
    return NULL;
}

/* Locate the raw WHERE clause: text after WHERE, up to a bare RETURNING or the
 * end of the statement, trimmed of surrounding whitespace and a trailing
 * semicolon.  *out_len is 0 when the keyword is present but the clause is
 * empty.  Returns true when a WHERE keyword was found at all, so a clause that
 * parsed to nothing can be distinguished from a statement that has no WHERE. */
static bool uwp_dml_where_region(const qihse_sql_ast_t* ast,
                                 const char** out, size_t* out_len) {
    *out = NULL;
    *out_len = 0;
    if (!ast || !ast->raw_sql) return false;
    const char* start = uwp_sql_find_keyword(ast->raw_sql, "WHERE");
    if (!start) return false;
    const char* end = uwp_sql_find_keyword(start, "RETURNING");
    if (end) end -= strlen("RETURNING");  /* find_keyword returns past the word */
    else     end = start + strlen(start);
    /* SELECT's supported LIMIT follows its filter and is not part of the
     * predicate. Keep DML strict: silently dropping an UPDATE/DELETE LIMIT
     * would change which rows the caller asked to affect. */
    if (ast->stmt_type == QIHSE_SQL_SELECT) {
        const char* suffixes[] = { "GROUP", "HAVING", "ORDER", "LIMIT", "OFFSET" };
        for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
            const char* suffix = uwp_sql_find_keyword(start, suffixes[i]);
            if (suffix) {
                suffix -= strlen(suffixes[i]);
                if (suffix < end) end = suffix;
            }
        }
    }
    while (start < end && isspace((unsigned char)*start)) start++;
    while (end > start && isspace((unsigned char)end[-1])) end--;
    while (end > start && end[-1] == ';') {
        end--;
        while (end > start && isspace((unsigned char)end[-1])) end--;
    }
    *out = start;
    *out_len = (size_t)(end - start);
    return true;
}

/* Token mirroring the parser's lexical rules for identifiers, operators and
 * values (see read_identifier / read_operator / read_value in
 * qihse_sql_parser.c).  For quoted strings `text` is the content between the
 * quotes, matching how the parser stores string literals. */
typedef struct {
    const char* text;
    size_t      len;
    bool        is_string;
} uwp_dml_token_t;

static bool uwp_dml_token_eq(const uwp_dml_token_t* token, const char* text) {
    if (!text) return false;
    size_t n = strlen(text);
    return token->len == n && memcmp(token->text, text, n) == 0;
}

static bool uwp_dml_literal_token_eq(const uwp_dml_token_t* token,
                                      const char* value) {
    if (!token->is_string) return uwp_dml_token_eq(token, value);
    if (!value) return false;
    size_t j = 0;
    for (size_t i = 0; i < token->len; ++i) {
        if (!value[j] || token->text[i] != value[j++]) return false;
        if (token->text[i] == '\'' && i + 1 < token->len &&
            token->text[i + 1] == '\'') ++i;
    }
    return value[j] == '\0';
}

static bool uwp_dml_next_token(const char** pp, uwp_dml_token_t* token) {
    const char* p = *pp;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) { *pp = p; return false; }
    token->text = p;
    token->is_string = false;
    if (*p == '\'') {
        token->is_string = true;
        p++;
        token->text = p;
        while (*p) {
            if (*p == '\'' && p[1] == '\'') { p += 2; continue; }
            if (*p == '\'') break;
            ++p;
        }
        token->len = (size_t)(p - token->text);
        if (*p != '\'') return false;
        ++p;
    } else if (*p == '(' || *p == ')') {
        p++;
        token->len = 1;
    } else if (*p == '=' || *p == '<' || *p == '>' || *p == '!' ||
               *p == '~' || *p == '|') {
        p++;
        if (*p == '=' || (*token->text == '<' && *p == '>')) p++;
        else if ((*token->text == '~' || *token->text == '|') && *p == '*') p++;
        token->len = (size_t)(p - token->text);
    } else {
        while (*p && !isspace((unsigned char)*p) && *p != '\'' &&
               *p != '=' && *p != '<' && *p != '>' && *p != '!' &&
               *p != '~' && *p != '|' && *p != '(' && *p != ')')
            p++;
        token->len = (size_t)(p - token->text);
    }
    *pp = p;
    return token->len > 0;
}

static bool uwp_dml_token_parameter_eq(const uwp_dml_token_t* token,
    uint16_t index, qihse_sql_type_t cast) {
    if (!token || token->is_string || token->len < 2 ||
        token->text[0] != '$') return false;
    unsigned value = 0;
    size_t i = 1;
    while (i < token->len && token->text[i] >= '0' && token->text[i] <= '9') {
        if (value >= QIHSE_SQL_MAX_PARAMETERS) return false;
        value = value * 10u + (unsigned)(token->text[i++] - '0');
    }
    if (value != index) return false;
    if (cast == QIHSE_TYPE_UNKNOWN) return i == token->len;
    const char* suffix = cast == QIHSE_TYPE_TIMESTAMP ? "::timestamp" :
                         cast == QIHSE_TYPE_TIMESTAMPTZ ? "::timestamptz" : NULL;
    return suffix && token->len - i == strlen(suffix) &&
           !strncasecmp(token->text + i, suffix, strlen(suffix));
}

/* Verify that the raw WHERE clause is exactly the conjunction of the AST's
 * conditions -- same columns, operators and values, joined by AND, and nothing
 * else.  Returns false (with a reason) for any construct the parser may have
 * dropped or transformed, which refuses the statement rather than executing a
 * match set the user did not write. */
static bool uwp_dml_where_verifies(const qihse_sql_ast_t* ast,
                                   const char** reason) {
    *reason = NULL;
    const char* region = NULL;
    size_t region_len = 0;
    bool has_where = uwp_dml_where_region(ast, &region, &region_len);
    if (!has_where) {
        if (ast->num_where_conditions > 0) {
            *reason = "WHERE clause not found in the statement text";
            return false;
        }
        return true;  /* no WHERE and no conditions: nothing to verify */
    }
    if (region_len == 0) {
        *reason = "WHERE clause is empty";
        return false;
    }
    if (ast->num_where_conditions == 0) {
        *reason = "WHERE clause has no parsed conditions";
        return false;
    }

    /* Tokenise a bounded copy of the clause: the statement text after the
     * clause (RETURNING, a trailing terminator) must not leak into a token. */
    char* clause = (char*)malloc(region_len + 1);
    if (!clause) {
        *reason = "out of memory while verifying the WHERE clause";
        return false;
    }
    memcpy(clause, region, region_len);
    clause[region_len] = '\0';

    bool verified = true;
    size_t paren_depth = 0;
    const char* p = clause;
    for (size_t i = 0; i < ast->num_where_conditions && verified; i++) {
        const qihse_sql_condition_t* c = &ast->where_conditions[i];
        uwp_dml_token_t token = {0};
        while (uwp_dml_next_token(&p, &token) &&
               uwp_dml_token_eq(&token, "(")) ++paren_depth;
        if (!token.len || token.is_string) {
            *reason = "WHERE column text does not match the parsed condition";
            verified = false;
            break;
        }
        if (uwp_dml_token_eq(&token, "NOT") && c->column_name &&
            c->value && !strcasecmp(c->value, "FALSE") &&
            c->operator && !strcmp(c->operator, "=")) {
            if (!uwp_dml_next_token(&p, &token) || token.is_string ||
                !uwp_dml_token_eq(&token, c->column_name)) {
                *reason = "WHERE boolean NOT column differs from parsed condition";
                verified = false;
            }
            goto verified_condition;
        }
        if (c->column_name && strstr(c->column_name, "->>")) {
            size_t expression_len = strlen(c->column_name);
            if (!strncmp(token.text, c->column_name, expression_len)) {
                token.len = expression_len;
                p = token.text + expression_len;
            }
        }
        if (!uwp_dml_token_eq(&token, c->column_name)) {
            *reason = "WHERE column text does not match the parsed condition";
            verified = false;
            break;
        }
        if (!uwp_dml_next_token(&p, &token) || token.is_string ||
            !uwp_dml_token_eq(&token, c->operator)) {
            *reason = "WHERE operator text does not match the parsed condition";
            verified = false;
            break;
        }
        if (!uwp_dml_next_token(&p, &token) ||
            (c->value_parameter_index ?
                !uwp_dml_token_parameter_eq(&token, c->value_parameter_index,
                                            c->value_cast_type) :
                (token.is_string != (c->value_is_string != 0) ||
                 !uwp_dml_literal_token_eq(&token, c->value)))) {
            *reason = "WHERE value text does not match the parsed condition";
            verified = false;
            break;
        }
        if (!c->value_parameter_index &&
            c->value_cast_type != QIHSE_TYPE_UNKNOWN) {
            const char* cast_name = c->value_cast_type == QIHSE_TYPE_TIMESTAMP
                ? "::timestamp" : c->value_cast_type == QIHSE_TYPE_TIMESTAMPTZ
                ? "::timestamptz" : NULL;
            if (!c->value_is_string || !cast_name ||
                !uwp_dml_next_token(&p, &token) || token.is_string ||
                token.len != strlen(cast_name) ||
                strncasecmp(token.text, cast_name, token.len)) {
                *reason = "WHERE literal cast differs from the parsed condition";
                verified = false;
            }
        }
verified_condition:
        if (verified) {
            const char* before = p;
            while (uwp_dml_next_token(&p, &token) &&
                   uwp_dml_token_eq(&token, ")")) {
                if (!paren_depth) { verified = false; break; }
                --paren_depth;
                before = p;
            }
            p = before;
        }
        if (i + 1 < ast->num_where_conditions && verified) {
            if (!uwp_dml_next_token(&p, &token) || token.is_string ||
                token.len != 3 || strncasecmp(token.text, "AND", 3) != 0) {
                *reason = "WHERE conditions are not joined by AND";
                verified = false;
                break;
            }
        }
    }
    if (verified && paren_depth) {
        *reason = "WHERE parentheses are unbalanced";
        verified = false;
    }
    if (verified) {
        uwp_dml_token_t trailing;
        if (uwp_dml_next_token(&p, &trailing)) {
            *reason = "WHERE clause has text the parser did not represent";
            verified = false;
        }
    }
    free(clause);
    return verified;
}

/* Operators the row-store predicate can evaluate.  Everything else (IS,
 * BETWEEN, IN, regex operators, subqueries) is refused: the parser drops part
 * of BETWEEN's range, so executing it would match the wrong set. */
static bool uwp_dml_operator_supported(const char* op) {
    if (!op) return false;
    return strcmp(op, "=") == 0 || strcmp(op, "<>") == 0 ||
           strcmp(op, "!=") == 0 || strcmp(op, "<") == 0 ||
           strcmp(op, ">") == 0 || strcmp(op, "<=") == 0 ||
           strcmp(op, ">=") == 0 || strcasecmp(op, "LIKE") == 0 ||
           strcasecmp(op, "ILIKE") == 0;
}

/* Resolve a condition's column name in the table.  A qualified name (x.id, the
 * alias the parser consumed and dropped) resolves on its last component. */
static bool uwp_dml_json_field(const char* expression,
    char* column, size_t column_cap, char* key, size_t key_cap) {
    if (!expression) return false;
    const char* arrow = strstr(expression, "->>");
    if (!arrow) return false;
    const char* begin = expression;
    while (isspace((unsigned char)*begin)) ++begin;
    const char* end = arrow;
    while (end > begin && isspace((unsigned char)end[-1])) --end;
    size_t n = (size_t)(end - begin);
    if (!n || n >= column_cap) return false;
    for (size_t i = 0; i < n; ++i)
        if (!(isalnum((unsigned char)begin[i]) || begin[i] == '_' || begin[i] == '.'))
            return false;
    memcpy(column, begin, n); column[n] = '\0';
    const char* p = arrow + 3;
    while (isspace((unsigned char)*p)) ++p;
    if (*p++ != '\'') return false;
    n = 0;
    while (*p) {
        if (*p == '\'' && p[1] != '\'') break;
        if (n + 1 >= key_cap) return false;
        key[n++] = *p;
        if (*p == '\'') ++p;
        ++p;
    }
    if (*p++ != '\'') return false;
    while (isspace((unsigned char)*p)) ++p;
    key[n] = '\0';
    return *p == '\0';
}

static int uwp_dml_resolve_column(const qihse_table_t* table, const char* name) {
    if (!table || !name) return -1;
    char json_column[256], json_key[256];
    bool json_expression = strstr(name, "->>") != NULL;
    if (json_expression) {
        if (!uwp_dml_json_field(name, json_column, sizeof(json_column),
                               json_key, sizeof(json_key))) return -1;
        name = json_column;
    }
    const char* bare = strrchr(name, '.');
    if (bare && bare[1]) name = bare + 1;
    int column = qihse_table_find_col(table, name);
    if (json_expression && column >= 0 &&
        qihse_table_col_def(table, (size_t)column)->type != QIHSE_TS_JSONB)
        return -1;
    return column;
}

/* SQL LIKE/ILIKE match: % is any run, _ is one character.  Iterative (no
 * recursion), so the frame stays bounded for adversarial patterns. */
static bool uwp_dml_like(const char* text, const char* pattern, bool ci) {
    const char* t = text;
    const char* p = pattern;
    const char* star = NULL;
    const char* t_star = NULL;
    while (*t) {
        if (*p == '%') { star = p++; t_star = t; continue; }
        bool eq = (*p == '_');
        if (!eq) {
            eq = ci ? tolower((unsigned char)*p) == tolower((unsigned char)*t)
                    : *p == *t;
        }
        if (eq && *p) { p++; t++; continue; }
        if (star) { p = star + 1; t = ++t_star; continue; }
        return false;
    }
    while (*p == '%') p++;
    return *p == '\0';
}

/* Render a cell as text for LIKE; strings are used as-is, numbers formatted
 * into the caller's buffer.  Returns false when the cell has no text form
 * (a NULL string). */
static bool uwp_dml_cell_text(const qihse_col_value_t* cell, char* buf,
                              size_t cap, const char** out) {
    switch (cell->type) {
        case QIHSE_TS_STRING:
        case QIHSE_TS_UUID:
        case QIHSE_TS_JSONB:
            if (cell->is_null || !cell->v.str) return false;
            *out = cell->v.str;
            return true;
        case QIHSE_TS_INT32:
            (void)snprintf(buf, cap, "%d", cell->v.i32);
            *out = buf;
            return true;
        case QIHSE_TS_INT64:
            (void)snprintf(buf, cap, "%lld", (long long)cell->v.i64);
            *out = buf;
            return true;
        case QIHSE_TS_FLOAT:
            (void)snprintf(buf, cap, "%g", (double)cell->v.f32);
            *out = buf;
            return true;
        case QIHSE_TS_BOOLEAN:
            *out = cell->v.boolean ? "true" : "false";
            return true;
        case QIHSE_TS_TIMESTAMPTZ: {
            int64_t micros = cell->v.timestamptz_us;
            int64_t seconds = micros / INT64_C(1000000);
            int64_t fraction = micros % INT64_C(1000000);
            if (fraction < 0) { --seconds; fraction += INT64_C(1000000); }
            time_t epoch = (time_t)seconds;
            struct tm tm;
            if (!gmtime_r(&epoch, &tm)) return false;
            (void)snprintf(buf, cap, "%04d-%02d-%02d %02d:%02d:%02d.%06lld+00",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, (long long)fraction);
            *out = buf;
            return true;
        }
        default:
            return false;
    }
}

/* Compare exact decimal magnitudes without rounding through a floating type. */
static bool uwp_dml_numeric_compare(const char* left, const char* right, int* out) {
    if (!qihse_ts_numeric_valid(left, 0, 0) ||
        !qihse_ts_numeric_valid(right, 0, 0)) return false;
    const char* digits[2] = {left, right};
    const char* fraction[2];
    size_t integers[2], fractions[2];
    bool negative[2];
    for (size_t i = 0; i < 2; ++i) {
        const char* p = digits[i];
        negative[i] = *p == '-';
        if (*p == '-' || *p == '+') ++p;
        while (*p == '0') ++p;
        digits[i] = p;
        while (isdigit((unsigned char)*p)) ++p;
        integers[i] = (size_t)(p - digits[i]);
        fraction[i] = *p == '.' ? p + 1 : p;
        fractions[i] = strlen(fraction[i]);
        while (fractions[i] && fraction[i][fractions[i] - 1] == '0') --fractions[i];
        if (!integers[i] && !fractions[i]) negative[i] = false;
    }
    int cmp = 0;
    if (negative[0] != negative[1]) {
        *out = negative[0] ? -1 : 1;
        return true;
    }
    if (integers[0] != integers[1]) cmp = integers[0] > integers[1] ? 1 : -1;
    else if (integers[0]) cmp = memcmp(digits[0], digits[1], integers[0]);
    if (!cmp) {
        size_t count = fractions[0] > fractions[1] ? fractions[0] : fractions[1];
        for (size_t i = 0; i < count; ++i) {
            char a = i < fractions[0] ? fraction[0][i] : '0';
            char b = i < fractions[1] ? fraction[1][i] : '0';
            if (a != b) { cmp = a > b ? 1 : -1; break; }
        }
    }
    cmp = (cmp > 0) - (cmp < 0);
    *out = negative[0] ? -cmp : cmp;
    return true;
}

/* Evaluate one parsed condition against one row cell.  A value that cannot be
 * compared to the cell type matches nothing, so a mistyped filter cannot
 * silently widen a DELETE. */
static bool uwp_dml_condition_matches(const qihse_col_value_t* cell,
                                      const qihse_sql_condition_t* c) {
    if (!c->operator || !c->value || cell->is_null ||
        (c->value_parameter_index && uwp_bound_params &&
         c->value_parameter_index <= uwp_bound_count &&
         uwp_bound_params[c->value_parameter_index - 1].is_null)) return false;
    bool like = strcasecmp(c->operator, "LIKE") == 0;
    bool ilike = strcasecmp(c->operator, "ILIKE") == 0;
    if (like || ilike) {
        char buf[64];
        const char* text = NULL;
        if (!uwp_dml_cell_text(cell, buf, sizeof(buf), &text)) return false;
        return uwp_dml_like(text, c->value, ilike);
    }
    int cmp = 0;
    if (cell->type == QIHSE_TS_NUMERIC) {
        if (!uwp_dml_numeric_compare(cell->v.str, c->value, &cmp)) return false;
    } else if (cell->type == QIHSE_TS_STRING || cell->type == QIHSE_TS_UUID ||
               cell->type == QIHSE_TS_JSONB) {
        if (!cell->v.str) return false;
        cmp = strcmp(cell->v.str, c->value);
    } else if (cell->type == QIHSE_TS_BOOLEAN) {
        bool want;
        if (!strcasecmp(c->value, "true") || !strcmp(c->value, "1")) want = true;
        else if (!strcasecmp(c->value, "false") || !strcmp(c->value, "0")) want = false;
        else return false;
        cmp = (cell->v.boolean > want) - (cell->v.boolean < want);
    } else if (cell->type == QIHSE_TS_TIMESTAMPTZ) {
        int64_t want;
        if (!uwp_dml_parse_timestamp(c->value, &want)) return false;
        cmp = (cell->v.timestamptz_us > want) - (cell->v.timestamptz_us < want);
    } else {
        char* endp = NULL;
        long double want = strtold(c->value, &endp);
        if (endp == c->value || !endp || *endp != '\0') return false;
        long double have;
        switch (cell->type) {
            case QIHSE_TS_INT32: have = (long double)cell->v.i32; break;
            case QIHSE_TS_INT64: have = (long double)cell->v.i64; break;
            case QIHSE_TS_FLOAT: have = (long double)cell->v.f32; break;
            default: return false;
        }
        cmp = have < want ? -1 : (have > want ? 1 : 0);
    }
    if (strcmp(c->operator, "=") == 0) return cmp == 0;
    if (strcmp(c->operator, "<>") == 0 || strcmp(c->operator, "!=") == 0)
        return cmp != 0;
    if (strcmp(c->operator, "<") == 0) return cmp < 0;
    if (strcmp(c->operator, ">") == 0) return cmp > 0;
    if (strcmp(c->operator, "<=") == 0) return cmp <= 0;
    if (strcmp(c->operator, ">=") == 0) return cmp >= 0;
    return false;
}

/* Predicate handed to qihse_table_update / qihse_table_delete.  Every matched
 * row is counted here, which is what makes the reported row count the number
 * of rows the store actually changed: the store applies the assignments to
 * exactly the rows this predicate accepts, and pre-validation has already
 * rejected unknown columns, so a match is a change. */
typedef struct {
    const qihse_sql_condition_t* conds;
    const int*                   col_idx;   /* resolved index per condition */
    size_t                       num_conds;
    size_t                       matched;
    const qihse_user_t*          user;
    uwp_sql_labels_t             labels;
} uwp_dml_scan_t;

static int uwp_dml_pred(const qihse_col_value_t* values, size_t num_cols,
                        void* ctx) {
    uwp_dml_scan_t* scan = (uwp_dml_scan_t*)ctx;
    if (scan->user && !uwp_sql_row_allowed(scan->user, scan->labels,
                                            values, num_cols)) return 0;
    for (size_t i = 0; i < scan->num_conds; i++) {
        int col = scan->col_idx[i];
        if (col < 0 || (size_t)col >= num_cols) return 0;
        const qihse_sql_condition_t* condition = &scan->conds[i];
        if (condition->value_cast_type != QIHSE_TYPE_UNKNOWN &&
            values[col].type != QIHSE_TS_TIMESTAMPTZ) return 0;
        if (condition->column_name && strstr(condition->column_name, "->>")) {
            char column_name[256], key[256];
            char* text = NULL;
            if (values[col].is_null || values[col].type != QIHSE_TS_JSONB ||
                !uwp_dml_json_field(condition->column_name, column_name,
                    sizeof(column_name), key, sizeof(key)) ||
                !uwp_sql_json_text(values[col].v.str, key, &text)) return 0;
            qihse_col_value_t extracted = {.type=QIHSE_TS_STRING,
                .is_null=text == NULL, .v.str=text};
            bool matched = uwp_dml_condition_matches(&extracted, condition);
            free(text);
            if (!matched) return 0;
        } else if (!uwp_dml_condition_matches(&values[col], condition)) return 0;
    }
    scan->matched++;
    return 1;
}

static bool uwp_dml_uuid_valid(const char* text) {
    if (!text || strlen(text) != 36) return false;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (text[i] != '-') return false;
        } else if (!isxdigit((unsigned char)text[i])) return false;
    }
    return true;
}

static const char* uwp_json_value(const char* p, unsigned depth);
static const char* uwp_json_space(const char* p) {
    while (*p && isspace((unsigned char)*p)) ++p;
    return p;
}
static const char* uwp_json_string(const char* p) {
    if (*p++ != '\"') return NULL;
    while (*p && (unsigned char)*p >= 0x20) {
        if (*p++ == '\"') return p;
        if ((unsigned char)p[-1] == 92u) {
            if (!*p) return NULL;
            if (*p == 'u') {
                if (strnlen(p, 5) < 5) return NULL;
                for (int i = 1; i <= 4; ++i)
                    if (!isxdigit((unsigned char)p[i])) return NULL;
                p += 5;
            } else if (strchr("\\\"/bfnrt", *p)) ++p;
            else return NULL;
        }
    }
    return NULL;
}
static const char* uwp_json_value(const char* p, unsigned depth) {
    if (depth > 64) return NULL;
    p = uwp_json_space(p);
    if (*p == '\"') return uwp_json_string(p);
    if (*p == '{') {
        p = uwp_json_space(p + 1);
        if (*p == '}') return p + 1;
        for (;;) {
            p = uwp_json_string(p);
            if (!p || *(p = uwp_json_space(p)) != ':') return NULL;
            p = uwp_json_value(p + 1, depth + 1);
            if (!p) return NULL;
            p = uwp_json_space(p);
            if (*p == '}') return p + 1;
            if (*p++ != ',') return NULL;
            p = uwp_json_space(p);
        }
    }
    if (*p == '[') {
        p = uwp_json_space(p + 1);
        if (*p == ']') return p + 1;
        for (;;) {
            p = uwp_json_value(p, depth + 1);
            if (!p) return NULL;
            p = uwp_json_space(p);
            if (*p == ']') return p + 1;
            if (*p++ != ',') return NULL;
        }
    }
    const char* literal = *p == 't' ? "true" : *p == 'f' ? "false" :
                          *p == 'n' ? "null" : NULL;
    if (literal) {
        size_t n = strlen(literal);
        return strncmp(p, literal, n) == 0 ? p + n : NULL;
    }
    const char* start = p;
    if (*p == '-') ++p;
    if (*p == '0') ++p;
    else {
        if (*p < '1' || *p > '9') return NULL;
        do { ++p; } while (*p >= '0' && *p <= '9');
    }
    if (*p == '.') {
        ++p;
        if (*p < '0' || *p > '9') return NULL;
        do { ++p; } while (*p >= '0' && *p <= '9');
    }
    if (*p == 'e' || *p == 'E') {
        ++p;
        if (*p == '+' || *p == '-') ++p;
        if (*p < '0' || *p > '9') return NULL;
        do { ++p; } while (*p >= '0' && *p <= '9');
    }
    return p == start ? NULL : p;
}
static bool uwp_dml_json_valid(const char* text) {
    const char* end = uwp_json_value(text, 0);
    return end && *uwp_json_space(end) == 0;
}

/* Decode JSON string scalars for ->>; absent keys and JSON null are SQL NULL.
 * Reject invalid Unicode surrogate pairs rather than producing ambiguous keys. */
static char* uwp_sql_json_string_decode(const char* start, const char* end) {
    if (!start || !end || start >= end || *start != '"' || end[-1] != '"' ||
        (size_t)(end - start) > 16384) return NULL;
    char* out = malloc((size_t)(end - start));
    if (!out) return NULL;
    size_t n = 0;
    for (const char* p = start + 1; p < end - 1;) {
        unsigned char c = (unsigned char)*p++;
        if (c != '\\') { out[n++] = (char)c; continue; }
        if (p >= end - 1) goto invalid;
        switch (c = (unsigned char)*p++) {
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case '"': case '\\': case '/': break;
            case 'u': {
                uint32_t code = 0;
                if (end - p < 5) goto invalid;
                for (int i = 0; i < 4; ++i) {
                    int d = isdigit((unsigned char)p[i]) ? p[i] - '0' :
                        tolower((unsigned char)p[i]) - 'a' + 10;
                    if (d < 0 || d > 15) goto invalid;
                    code = (code << 4) | (uint32_t)d;
                }
                p += 4;
                if (code >= 0xd800 && code <= 0xdbff) {
                    if (end - p < 7 || p[0] != '\\' || p[1] != 'u') goto invalid;
                    p += 2;
                    uint32_t low = 0;
                    for (int i = 0; i < 4; ++i) {
                        int d = isdigit((unsigned char)p[i]) ? p[i] - '0' :
                            tolower((unsigned char)p[i]) - 'a' + 10;
                        if (d < 0 || d > 15) goto invalid;
                        low = (low << 4) | (uint32_t)d;
                    }
                    p += 4;
                    if (low < 0xdc00 || low > 0xdfff) goto invalid;
                    code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                } else if (code >= 0xdc00 && code <= 0xdfff) goto invalid;
                if (code < 0x80) out[n++] = (char)code;
                else if (code < 0x800) {
                    out[n++] = (char)(0xc0 | (code >> 6));
                    out[n++] = (char)(0x80 | (code & 63));
                } else if (code < 0x10000) {
                    out[n++] = (char)(0xe0 | (code >> 12));
                    out[n++] = (char)(0x80 | ((code >> 6) & 63));
                    out[n++] = (char)(0x80 | (code & 63));
                } else {
                    out[n++] = (char)(0xf0 | (code >> 18));
                    out[n++] = (char)(0x80 | ((code >> 12) & 63));
                    out[n++] = (char)(0x80 | ((code >> 6) & 63));
                    out[n++] = (char)(0x80 | (code & 63));
                }
                continue;
            }
            default: goto invalid;
        }
        if (!c) goto invalid;
        out[n++] = (char)c;
    }
    out[n] = 0;
    return out;
invalid:
    free(out); return NULL;
}

static bool uwp_sql_json_text(const char* json, const char* key, char** value) {
    if (!json || !key || !value || !uwp_dml_json_valid(json)) return false;
    *value = NULL;
    const char* p = uwp_json_space(json);
    if (*p++ != '{') return false;
    p = uwp_json_space(p);
    while (*p != '}') {
        const char* key_end = uwp_json_string(p);
        if (!key_end) return false;
        char* decoded_key = uwp_sql_json_string_decode(p, key_end);
        if (!decoded_key) return false;
        bool match = !strcmp(decoded_key, key);
        free(decoded_key);
        p = uwp_json_space(key_end);
        if (*p++ != ':') return false;
        p = uwp_json_space(p);
        const char* value_end = uwp_json_value(p, 0);
        if (!value_end) return false;
        if (match) {
            char* decoded = NULL;
            if (*p == '"') decoded = uwp_sql_json_string_decode(p, value_end);
            else if (value_end - p == 4 && !memcmp(p, "null", 4)) decoded = NULL;
            else if (*p != '[' && *p != '{') decoded = strndup(p, (size_t)(value_end - p));
            else return false;
            if (*p == '"' && !decoded) return false;
            free(*value);
            *value = decoded;
        }
        p = uwp_json_space(value_end);
        if (*p == ',') { p = uwp_json_space(p + 1); continue; }
        if (*p != '}') return false;
    }
    return true;
}

static bool uwp_sql_generated_expr(qihse_sql_type_t type, int stored,
                                   const char* expr) {
    static const char expected[] =
        "to_tsvector('english',coalesce(data->>'email','')||' '||"
        "coalesce(data->>'name','')||' '||coalesce(data->>'username',''))";
    if (type != QIHSE_TYPE_TSVECTOR || !stored || !expr) return false;
    const char* p = expr;
    bool quoted = false;
    for (size_t i = 0; expected[i]; ++i) {
        while (!quoted && isspace((unsigned char)*p)) ++p;
        if (!*p || tolower((unsigned char)*p) != expected[i]) return false;
        if (*p == '\'') quoted = !quoted;
        ++p;
    }
    while (isspace((unsigned char)*p)) ++p;
    return !*p && !quoted;
}

static char* uwp_sql_english_vector(const char* text) {
    char* vector = NULL;
    return qihse_sql_to_tsvector_english(text, &vector) ? vector : NULL;
}

static char* uwp_sql_generated_vector(const char* json) {
    char *email = NULL, *name = NULL, *username = NULL, *vector = NULL;
    if (!uwp_sql_json_text(json, "email", &email) ||
        !uwp_sql_json_text(json, "name", &name) ||
        !uwp_sql_json_text(json, "username", &username)) goto done;
    size_t a = email ? strlen(email) : 0;
    size_t b = name ? strlen(name) : 0;
    size_t c = username ? strlen(username) : 0;
    if (a + b + c > 4094) goto done;
    char text[4097];
    snprintf(text, sizeof(text), "%s %s %s", email ? email : "",
             name ? name : "", username ? username : "");
    vector = uwp_sql_english_vector(text);
done:
    free(email); free(name); free(username);
    return vector;
}

static bool uwp_dml_parse_timestamp(const char* text, int64_t* micros) {
    if (!text || strlen(text) < 19 || text[4] != '-' || text[7] != '-' ||
        (text[10] != 'T' && text[10] != ' ') ||
        text[13] != ':' || text[16] != ':') return false;
    for (size_t i = 0; i < 19; ++i)
        if (i != 4 && i != 7 && i != 10 && i != 13 && i != 16 &&
            (text[i] < '0' || text[i] > '9')) return false;
    int year, month, day, hour, minute, second, consumed = 0;
    if (sscanf(text, "%4d-%2d-%2d%*c%2d:%2d:%2d%n",
               &year, &month, &day, &hour, &minute, &second, &consumed) != 6 ||
        consumed <= 0 || year < 1 || month < 1 || month > 12 || day < 1 ||
        day > 31 || hour > 23 || minute > 59 || second > 59) return false;
    const char* p = text + consumed;
    int fraction = 0, digits = 0;
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9' && digits < 6) {
            fraction = fraction * 10 + (*p++ - '0');
            ++digits;
        }
        if (!digits || (*p >= '0' && *p <= '9')) return false;
        while (digits++ < 6) fraction *= 10;
    }
    int offset_minutes = 0;
    if (*p == 'Z' || *p == 'z') {
        ++p;
    } else if (*p == '+' || *p == '-') {
        int sign = *p++ == '+' ? 1 : -1;
        if (!isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]))
            return false;
        int hours = (p[0] - '0') * 10 + p[1] - '0';
        p += 2;
        int minutes = 0;
        if (*p == ':') ++p;
        if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1])) {
            minutes = (p[0] - '0') * 10 + p[1] - '0';
            p += 2;
        }
        if (hours > 15 || minutes > 59 || (hours == 15 && minutes))
            return false;
        offset_minutes = sign * (hours * 60 + minutes);
    } else if (*p) return false;
    if (*p) return false;
    struct tm tm = {.tm_year=year - 1900, .tm_mon=month - 1,
                    .tm_mday=day, .tm_hour=hour, .tm_min=minute,
                    .tm_sec=second};
    time_t epoch = timegm(&tm);
    struct tm check;
    if (!gmtime_r(&epoch, &check) || check.tm_year != year - 1900 ||
        check.tm_mon != month - 1 || check.tm_mday != day ||
        check.tm_hour != hour || check.tm_min != minute || check.tm_sec != second)
        return false;
    *micros = ((int64_t)epoch - (int64_t)offset_minutes * 60) *
              INT64_C(1000000) + fraction;
    return true;
}

/* Convert a SET right-hand side to a typed value for the target column.  Only
 * literals are accepted: the table store applies constant values, so an
 * expression (n + 1) is refused rather than stored as text. */
static bool uwp_dml_set_value(const qihse_col_def_t* def, const char* text,
                              qihse_col_value_t* out) {
    /* NULL is not a literal value in the row store. In particular it must
     * not be stored as the string "NULL" by an UPDATE. */
    if (!def || !text || !out) return false;
    memset(out, 0, sizeof(*out));
    if (strcasecmp(text, "NULL") == 0) {
        out->type = def->type;
        out->is_null = true;
        return true;
    }
    char* endp = NULL;
    errno = 0;
    switch (def->type) {
        case QIHSE_TS_INT32: {
            long v = strtol(text, &endp, 10);
            if (endp == text || *endp != '\0' || errno == ERANGE ||
                v < INT32_MIN || v > INT32_MAX)
                return false;
            out->type = QIHSE_TS_INT32;
            out->v.i32 = (int32_t)v;
            return true;
        }
        case QIHSE_TS_INT64: {
            long long v = strtoll(text, &endp, 10);
            if (endp == text || *endp != '\0' || errno == ERANGE)
                return false;
            out->type = QIHSE_TS_INT64;
            out->v.i64 = (int64_t)v;
            return true;
        }
        case QIHSE_TS_FLOAT: {
            float v = strtof(text, &endp);
            if (endp == text || *endp != '\0' || errno == ERANGE)
                return false;
            out->type = QIHSE_TS_FLOAT;
            out->v.f32 = v;
            return true;
        }
        case QIHSE_TS_STRING:
        case QIHSE_TS_NUMERIC:
        case QIHSE_TS_TSVECTOR:
            if (def->type == QIHSE_TS_NUMERIC &&
                !qihse_ts_numeric_valid(text, 0, 0)) return false;
            if (def->type == QIHSE_TS_TSVECTOR &&
                !qihse_ts_tsvector_valid(text)) return false;
            out->type = def->type;
            out->v.str = strdup(text);
            return out->v.str != NULL;
        case QIHSE_TS_UUID:
            if (!uwp_dml_uuid_valid(text)) return false;
            out->type = def->type;
            out->v.str = strdup(text);
            return out->v.str != NULL;
        case QIHSE_TS_JSONB:
            if (!uwp_dml_json_valid(text)) return false;
            out->type = def->type;
            out->v.str = strdup(text);
            return out->v.str != NULL;
        case QIHSE_TS_BOOLEAN:
            out->type = QIHSE_TS_BOOLEAN;
            if (!strcasecmp(text, "true") || !strcmp(text, "1")) out->v.boolean = true;
            else if (!strcasecmp(text, "false") || !strcmp(text, "0")) out->v.boolean = false;
            else return false;
            return true;
        case QIHSE_TS_TIMESTAMPTZ:
            out->type = QIHSE_TS_TIMESTAMPTZ;
            return uwp_dml_parse_timestamp(text, &out->v.timestamptz_us);
        default:
            return false;
    }
}

static bool uwp_sql_bound_value(const qihse_col_def_t* def,
    const qihse_schema_column_t* schema, const qihse_uwp_sql_param_t* param,
    const char* text, qihse_col_value_t* out) {
    if (!def || !schema || !param || !out) return false;
    memset(out, 0, sizeof(*out));
    out->type = def->type;
    if (param->is_null) { out->is_null = true; return true; }
    if (!text) return false;
    if (schema->type == QIHSE_TYPE_VARCHAR && schema->type_len > 0 &&
        strlen(text) > (size_t)schema->type_len) return false;
    if (schema->type == QIHSE_TYPE_NUMERIC) {
        char* normalized = uwp_sql_numeric(text, schema->type_len,
                                           schema->type_scale);
        if (!normalized) return false;
        /* Bound NUMERIC is exact: no implicit rounding of input digits. */
        const char* dot = strchr(text, '.');
        if (dot) {
            const char* extra = dot + 1 + schema->type_scale;
            if (strlen(dot + 1) > (size_t)schema->type_scale) {
                for (const char* p = extra; *p; ++p)
                    if (*p != '0') { free(normalized); return false; }
            }
        }
        out->v.str = normalized;
        return true;
    }
    /* Unlike SQL literals, bound strings never interpret the bytes NULL or
     * DEFAULT as keywords. The row store owns the copied string. */
    if (def->type == QIHSE_TS_STRING || def->type == QIHSE_TS_UUID ||
        def->type == QIHSE_TS_JSONB || def->type == QIHSE_TS_TSVECTOR) {
        if ((def->type == QIHSE_TS_UUID && !uwp_dml_uuid_valid(text)) ||
            (def->type == QIHSE_TS_JSONB && !uwp_dml_json_valid(text)) ||
            (def->type == QIHSE_TS_TSVECTOR && !qihse_ts_tsvector_valid(text)))
            return false;
        out->v.str = strdup(text);
        return out->v.str != NULL;
    }
    if (!strcasecmp(text, "NULL")) return false;
    return uwp_dml_set_value(def, text, out);
}

/* Decimal arithmetic remains decimal: never route NUMERIC through float32.
 * Normalize to the declared scale, rounding half away from zero. */
static char* uwp_sql_numeric(const char* text, int precision, int scale) {
    if (!text || precision < 1 || precision > 38 || scale < 0 || scale > precision)
        return NULL;
    const char* p = text;
    bool negative = *p == '-';
    if (*p == '-' || *p == '+') ++p;
    char digits[96] = {0};
    size_t integer = 0, fraction = 0;
    while (*p >= '0' && *p <= '9') {
        if (integer >= 48) return NULL;
        digits[integer++] = *p++;
    }
    if (!integer && *p != '.') return NULL;
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') {
            if (integer + fraction >= 90) return NULL;
            digits[integer + fraction++] = *p++;
        }
        if (!fraction && !integer) return NULL;
    }
    if (*p) return NULL;
    if (!integer) {
        memmove(digits + 1, digits, fraction);
        digits[0] = '0';
        integer = 1;
    }
    bool round = fraction > (size_t)scale && digits[integer + scale] >= '5';
    size_t len = integer + (size_t)scale;
    for (size_t i = fraction; i < (size_t)scale; ++i)
        digits[integer + i] = '0';
    if (!len) { digits[0] = '0'; len = 1; }
    if (round) {
        size_t i = len;
        while (i && digits[i - 1] == '9') digits[--i] = '0';
        if (i) ++digits[i - 1];
        else {
            if (len + 1 >= sizeof(digits)) return NULL;
            memmove(digits + 1, digits, len);
            digits[0] = '1';
            ++len; ++integer;
        }
    }
    size_t start = 0;
    while (start + 1 < integer && digits[start] == '0') ++start;
    size_t significant = integer - start;
    if (significant == 1 && digits[start] == '0') significant = 0;
    if (significant + (size_t)scale > (size_t)precision) return NULL;
    bool nonzero = false;
    for (size_t i = 0; i < len; ++i) nonzero |= digits[i] != '0';
    char* out = calloc(len + 4, 1);
    if (!out) return NULL;
    size_t n = 0;
    if (negative && nonzero) out[n++] = '-';
    if (!integer) out[n++] = '0';
    else while (start < integer) out[n++] = digits[start++];
    if (scale) {
        out[n++] = '.';
        for (int i = 0; i < scale; ++i)
            out[n++] = digits[integer + (size_t)i];
    }
    out[n] = 0;
    return out;
}

static bool uwp_dml_literal_value(const qihse_col_def_t* def, const char* text,
                                  bool quoted, qihse_col_value_t* out) {
    if (!def || !text || !out) return false;
    if (!quoted || strcasecmp(text, "NULL")) return uwp_dml_set_value(def, text, out);
    memset(out, 0, sizeof(*out));
    out->type = def->type;
    if (def->type != QIHSE_TS_STRING &&
        !(def->type == QIHSE_TS_JSONB && !strcmp(text, "null"))) return false;
    out->v.str = strdup(text);
    return out->v.str != NULL;
}

/* A migration default is evaluated at INSERT time, not at CREATE time. UUID
 * bytes come from the kernel CSPRNG; partial entropy reads are not accepted. */
static bool uwp_sql_default_value(const qihse_schema_column_t* col,
                                  qihse_col_value_t* out) {
    const char* expr = col->default_expr;
    if (!expr || !out || !out->is_null) return false;
    if (col->type == QIHSE_TYPE_UUID &&
        (!strcasecmp(expr, "gen_random_uuid()") ||
         !strcasecmp(expr, "uuid_generate_v4()"))) {
        uint8_t bytes[16];
        size_t n = 0;
        while (n < sizeof(bytes)) {
            ssize_t r = getrandom(bytes + n, sizeof(bytes) - n, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) return false;
            n += (size_t)r;
        }
        bytes[6] = (uint8_t)((bytes[6] & 0x0f) | 0x40);
        bytes[8] = (uint8_t)((bytes[8] & 0x3f) | 0x80);
        char uuid[37];
        snprintf(uuid, sizeof(uuid),
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]);
        out->v.str = strdup(uuid);
        if (!out->v.str) return false;
        out->is_null = false;
        return true;
    }
    if (col->type == QIHSE_TYPE_TIMESTAMPTZ && !strcasecmp(expr, "NOW()")) {
        struct timespec now;
        if (clock_gettime(CLOCK_REALTIME, &now) != 0) return false;
        out->v.timestamptz_us = (int64_t)now.tv_sec * INT64_C(1000000) +
                                 now.tv_nsec / 1000;
        out->is_null = false;
        return true;
    }
    if (col->type == QIHSE_TYPE_TEXT || col->type == QIHSE_TYPE_VARCHAR) {
        if (!uwp_sql_text_default(expr, &out->v.str)) return false;
        out->is_null = false;
        return true;
    }
    if (col->type == QIHSE_TYPE_JSONB && !strcmp(expr, "'{}'")) {
        out->v.str = strdup("{}");
        if (!out->v.str) return false;
        out->is_null = false;
        return true;
    }
    if (col->type == QIHSE_TYPE_INT && !strcmp(expr, "0")) {
        out->v.i32 = 0;
        out->is_null = false;
        return true;
    }
    return false;
}

typedef struct {
    int data_col;
    int vector_col;
    const int* set_cols;
    const qihse_col_value_t* set_vals;
    size_t num_set;
    char* pending;
} uwp_sql_generated_update_t;

static bool uwp_sql_generated_update_row(const qihse_col_value_t* values,
    size_t count, qihse_col_value_t* out, void* opaque) {
    uwp_sql_generated_update_t* update = opaque;
    (void)values;
    free(update->pending);
    update->pending = NULL;
    if ((size_t)update->data_col >= count ||
        (size_t)update->vector_col >= count) return false;
    for (size_t i = 0; i < update->num_set; ++i) {
        if (update->set_cols[i] < 0 || (size_t)update->set_cols[i] >= count)
            return false;
        out[update->set_cols[i]] = update->set_vals[i];
    }
    if (out[update->data_col].type != QIHSE_TS_JSONB ||
        out[update->data_col].is_null || !out[update->data_col].v.str)
        return false;
    update->pending = uwp_sql_generated_vector(out[update->data_col].v.str);
    if (!update->pending) return false;
    out[update->vector_col].type = QIHSE_TS_TSVECTOR;
    out[update->vector_col].is_null = false;
    out[update->vector_col].v.str = update->pending;
    return true;
}

static char* uwp_sql_execute_dml_on_table(qihse_uwp_context_t* ctx,
                                           const qihse_sql_ast_t* ast,
                                           qihse_user_t* user,
                                           qihse_table_t* table,
                                           qihse_table_txn_t* table_txn) {
    if (!ast || (ast->stmt_type != QIHSE_SQL_UPDATE &&
                 ast->stmt_type != QIHSE_SQL_DELETE))
        return NULL;
    const char* stmt = ast->stmt_type == QIHSE_SQL_DELETE ? "DELETE" : "UPDATE";

    if (!ast->table_name || ast->table_name[0] == '\0') {
        return uwp_dml_replyf("OK stmt_type=%s (refused: statement has no "
                              "target table; no rows changed)\n", stmt);
    }

    /* Same write-permission model as the KV / column / document targets: the
     * resource id is the FNV-1a hash of the object name, namespace 0.  The
     * operator role passes; every other role needs an explicit grant. */
    if (!user || !qihse_auth_can_access_object(
                     user, 0, (uint64_t)uwp_fnv1a(ast->table_name),
                     QIHSE_ACL_WRITE)) {
        return uwp_dml_replyf("OK stmt_type=%s (refused: no write access to "
                              "table %s; no rows changed)\n", stmt,
                              ast->table_name);
    }

    if (ast->stmt_type == QIHSE_SQL_UPDATE && ast->num_set == 0) {
        return uwp_dml_replyf("OK stmt_type=UPDATE (refused: zero SET "
                              "assignments; no rows changed)\n");
    }

    if (!table) {
        return uwp_dml_replyf("OK stmt_type=%s (table %s not found in the SQL "
                              "row store; no rows changed)\n", stmt,
                              ast->table_name);
    }

    uwp_sql_labels_t labels = uwp_sql_labels(table);
    if (!labels.valid || (labels.tenant < 0 &&
                          qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM))
        return uwp_dml_replyf("OK stmt_type=%s (refused: table has no valid "
                              "tenant labels; no rows changed)\n", stmt);

    char* reply = NULL;
    int* set_cols = NULL;
    qihse_col_value_t* set_vals = NULL;
    int* cond_cols = NULL;
    size_t num_set = ast->num_set;
    size_t num_conds = ast->num_where_conditions;
    const qihse_schema_table_t* definition = ctx && ctx->schema ?
        qihse_schema_get_table(ctx->schema, ast->table_name) : NULL;
    bool stamp_trigger = ast->stmt_type == QIHSE_SQL_UPDATE && definition &&
                         definition->num_triggers != 0;
    int generated_col = -1;
    int data_col = -1;
    bool changed_data = false;
    if (definition && ast->stmt_type == QIHSE_SQL_UPDATE) {
        for (size_t i = 0; i < definition->num_columns; ++i) {
            if (definition->columns[i].generated_stored)
                generated_col = (int)i;
            if (!strcasecmp(definition->columns[i].name, "data"))
                data_col = (int)i;
        }
    }
    if (stamp_trigger) {
        for (size_t i = 0; i < definition->num_triggers; ++i)
            if (strcasecmp(definition->triggers[i].function_name,
                           "update_updated_at_column") ||
                !qihse_schema_get_function(ctx->schema,
                    definition->triggers[i].function_name)) return NULL;
    }

    /* ---- validate the assignments before anything is mutated ---- */
    if (ast->stmt_type == QIHSE_SQL_UPDATE) {
        set_cols = (int*)calloc(num_set + (stamp_trigger ? 1 : 0), sizeof(int));
        set_vals = (qihse_col_value_t*)calloc(num_set + (stamp_trigger ? 1 : 0),
                                                sizeof(qihse_col_value_t));
        if (!set_cols || !set_vals) goto done;
        for (size_t i = 0; i < num_set; i++) {
            int col = uwp_dml_resolve_column(table, ast->set_columns[i]);
            if (col == generated_col && generated_col >= 0) goto done;
            if (col == data_col && generated_col >= 0) changed_data = true;
            if (col >= 0 && (col == labels.tenant ||
                             col == labels.classification || col == labels.sci)) {
                reply = uwp_dml_replyf("OK stmt_type=UPDATE (refused: security "
                                       "labels are immutable; no rows changed)\n");
                goto done;
            }
            if (col < 0) {
                reply = uwp_dml_replyf(
                    "OK stmt_type=UPDATE (refused: SET column %s is not in "
                    "table %s; no rows changed)\n",
                    ast->set_columns[i] ? ast->set_columns[i] : "<unnamed>",
                    ast->table_name);
                goto done;
            }
            const qihse_col_def_t* def =
                qihse_table_col_def(table, (size_t)col);
            /* A bare identifier can name a column, but a quoted string with
             * the same spelling is still a literal. */
            uint16_t bind = ast->set_parameter_indexes ?
                ast->set_parameter_indexes[i] : 0;
            bool quoted = ast->set_quoted && ast->set_quoted[i];
            if (!bind && !quoted && def && (def->type == QIHSE_TS_STRING || def->type == QIHSE_TS_UUID ||
                        def->type == QIHSE_TS_JSONB) && ast->set_values[i] &&
                uwp_dml_resolve_column(table, ast->set_values[i]) >= 0) {
                reply = uwp_dml_replyf(
                    "OK stmt_type=UPDATE (refused: SET %s = %s names a column; "
                    "column-to-column assignment is not supported by the row "
                    "store; no rows changed)\n",
                    ast->set_columns[i] ? ast->set_columns[i] : "<unnamed>",
                    ast->set_values[i]);
                goto done;
            }
            if (bind && (!uwp_bound_params || bind > uwp_bound_count)) goto done;
            bool converted;
            if (!bind && !quoted && ast->set_values[i] &&
                !strcasecmp(ast->set_values[i], "DEFAULT")) {
                if (!definition || (size_t)col >= definition->num_columns) goto done;
                set_vals[i].type = def->type;
                set_vals[i].is_null = true;
                converted = !definition->columns[col].default_expr ||
                    uwp_sql_default_value(&definition->columns[col], &set_vals[i]);
            } else converted = bind ? uwp_sql_bound_value(def,
                    &definition->columns[col], &uwp_bound_params[bind - 1],
                    ast->set_values[i], &set_vals[i]) :
                    uwp_dml_literal_value(def, ast->set_values[i], quoted, &set_vals[i]);
            if (!converted) {
                reply = uwp_dml_replyf(
                    "OK stmt_type=UPDATE (refused: SET %s = %s is not a "
                    "literal for the column type; no rows changed)\n",
                    ast->set_columns[i] ? ast->set_columns[i] : "<unnamed>",
                    ast->set_values[i] ? ast->set_values[i] : "<empty>");
                goto done;
            }
            if (set_vals[i].is_null && ctx && ctx->schema) {
                const qihse_schema_table_t* schema =
                    qihse_schema_get_table(ctx->schema, ast->table_name);
                if (!schema || (size_t)col >= schema->num_columns ||
                    schema->columns[col].not_null) {
                    reply = uwp_dml_replyf("OK stmt_type=UPDATE (refused: NULL violates NOT NULL; no rows changed)\n");
                    goto done;
                }
            }
            set_cols[i] = col;
        }
        if (stamp_trigger) {
            int updated_at = qihse_table_find_col(table, "updated_at");
            if (updated_at < 0 || (size_t)updated_at >= definition->num_columns ||
                definition->columns[updated_at].type != QIHSE_TYPE_TIMESTAMPTZ)
                goto done;
            struct timespec now;
            if (clock_gettime(CLOCK_REALTIME, &now) != 0) goto done;
            size_t slot = num_set;
            for (size_t i = 0; i < num_set; ++i)
                if (set_cols[i] == updated_at) { slot = i; break; }
            if (slot == num_set) ++num_set;
            set_cols[slot] = updated_at;
            set_vals[slot].type = QIHSE_TS_TIMESTAMPTZ;
            set_vals[slot].is_null = false;
            set_vals[slot].v.timestamptz_us =
                (int64_t)now.tv_sec * INT64_C(1000000) + now.tv_nsec / 1000;
        }
    }

    /* ---- the zero-condition guards, before any store call ---- */
    const char* where_region = NULL;
    size_t where_len = 0;
    bool has_where = uwp_dml_where_region(ast, &where_region, &where_len);
    (void)where_region;
    if (num_conds == 0) {
        if (ast->stmt_type == QIHSE_SQL_DELETE) {
            /* A zero-condition DELETE must never become a match-all: the
             * parser has already dropped a filter once (an aliased DELETE),
             * and this store has no transaction to undo a mass delete. */
            reply = uwp_dml_replyf(
                has_where
                    ? "OK stmt_type=DELETE (refused: WHERE clause present but "
                      "no conditions were parsed; no rows changed)\n"
                    : "OK stmt_type=DELETE (refused: zero WHERE conditions; an "
                      "unqualified DELETE is not executed; no rows changed)\n");
            goto done;
        }
        if (has_where) {
            reply = uwp_dml_replyf(
                "OK stmt_type=UPDATE (refused: WHERE clause present but no "
                "conditions were parsed; no rows changed)\n");
            goto done;
        }
        /* No WHERE at all: UPDATE without WHERE is a legitimate update-all. */
    } else {
        const char* reason = NULL;
        if (!uwp_dml_where_verifies(ast, &reason)) {
            reply = uwp_dml_replyf(
                "OK stmt_type=%s (refused: %s; no rows changed)\n", stmt,
                reason ? reason : "WHERE clause does not match the parsed "
                                 "conditions");
            goto done;
        }
        cond_cols = (int*)malloc(num_conds * sizeof(int));
        if (!cond_cols) goto done;
        for (size_t i = 0; i < num_conds; i++) {
            const qihse_sql_condition_t* c = &ast->where_conditions[i];
            if (c->subq_kind != 0) {
                reply = uwp_dml_replyf(
                    "OK stmt_type=%s (refused: subquery predicates are not "
                    "supported by the row store; no rows changed)\n", stmt);
                goto done;
            }
            if (!uwp_dml_operator_supported(c->operator)) {
                reply = uwp_dml_replyf(
                    "OK stmt_type=%s (refused: operator %s is not supported by "
                    "the row store; no rows changed)\n", stmt,
                    c->operator ? c->operator : "<none>");
                goto done;
            }
            int col = uwp_dml_resolve_column(table, c->column_name);
            if (col < 0) {
                reply = uwp_dml_replyf(
                    "OK stmt_type=%s (refused: WHERE column %s is not in table "
                    "%s; no rows changed)\n", stmt,
                    c->column_name ? c->column_name : "<unnamed>",
                    ast->table_name);
                goto done;
            }
            cond_cols[i] = col;
        }
    }

    /* Generated row changes require an optimistic shadow: two consecutive
     * writes on a live table would expose a stale vector between them. */
    if (changed_data && !table_txn) goto done;
    /* ---- execute: one table write lock covers the whole statement ---- */
    uwp_dml_scan_t scan;
    scan.conds = ast->where_conditions;
    scan.col_idx = cond_cols;
    scan.num_conds = num_conds;
    scan.matched = 0;
    scan.user = user;
    scan.labels = labels;
    if (ast->stmt_type == QIHSE_SQL_UPDATE) {
        if (table_txn) {
            if (changed_data) {
                if (generated_col < 0 || data_col < 0 ||
                    !uwp_sql_generated_expr(definition->columns[generated_col].type,
                        definition->columns[generated_col].generated_stored,
                        definition->columns[generated_col].generated_expr))
                    goto done;
                uwp_sql_generated_update_t generated = {
                    .data_col = data_col, .vector_col = generated_col,
                    .set_cols = set_cols, .set_vals = set_vals,
                    .num_set = num_set
                };
                int transformed = qihse_table_txn_transform(table_txn, user,
                    uwp_dml_pred, &scan, uwp_sql_generated_update_row, &generated);
                free(generated.pending);
                if (transformed < 0) goto done;
            } else if (qihse_table_txn_update(table_txn, uwp_dml_pred,
                           &scan, set_cols, set_vals, num_set) < 0) goto done;
        } else {
            int update_rc = qihse_table_update(
                table, uwp_dml_pred, &scan, set_cols, set_vals, num_set);
            if (update_rc < 0) goto done;
        }
    } else {
        if (table_txn)
            (void)qihse_table_txn_delete(table_txn, uwp_dml_pred, &scan);
        else
            (void)qihse_table_delete(table, uwp_dml_pred, &scan);
    }
    reply = uwp_dml_replyf("OK stmt_type=%s rows=%zu\n", stmt, scan.matched);

done:
    if (set_vals) {
        for (size_t i = 0; i < num_set; i++) {
            if (set_vals[i].type == QIHSE_TS_STRING || set_vals[i].type == QIHSE_TS_UUID ||
                set_vals[i].type == QIHSE_TS_JSONB) free(set_vals[i].v.str);
        }
    }
    free(set_cols);
    free(set_vals);
    free(cond_cols);
    return reply;
}

char* qihse_uwp_sql_execute_dml(const qihse_sql_ast_t* ast,
                                qihse_user_t* user) {
    qihse_table_store_t* store = qihse_uwp_sql_table_store();
    qihse_table_t* table = (store && ast && ast->table_name)
                               ? qihse_table_store_find_table(store,
                                                              ast->table_name)
                               : NULL;
    return uwp_sql_execute_dml_on_table(NULL, ast, user, table, NULL);
}

typedef struct {
    const qihse_sql_ast_t* ast;
    const int* projection;
    size_t projection_count;
    const int* condition_columns;
    uwp_text_buffer_t* response;
    size_t matched;
    size_t emitted;
    int failed;
    const qihse_user_t* user;
    uwp_sql_labels_t labels;
    int order_column;                 /* -1 for the streaming SELECT path */
    int order_ascending;
    qihse_col_value_t best_key;
    uwp_text_buffer_t best_row;       /* only one candidate, never all matches */
    bool has_best;
} uwp_sql_select_scan_t;

static bool uwp_sql_select_cell(uwp_text_buffer_t* out,
                                const qihse_col_value_t* cell) {
    if (cell->is_null) return uwp_text_appendf(out, "\\N") == 0;
    char number[96];
    const char* value = number;
    switch (cell->type) {
        case QIHSE_TS_INT32:
            (void)snprintf(number, sizeof(number), "%d", cell->v.i32);
            break;
        case QIHSE_TS_INT64:
            (void)snprintf(number, sizeof(number), "%lld",
                           (long long)cell->v.i64);
            break;
        case QIHSE_TS_FLOAT:
            (void)snprintf(number, sizeof(number), "%.9g",
                           (double)cell->v.f32);
            break;
        case QIHSE_TS_STRING:
        case QIHSE_TS_UUID:
        case QIHSE_TS_JSONB:
        case QIHSE_TS_NUMERIC:
        case QIHSE_TS_TSVECTOR:
            value = cell->v.str ? cell->v.str : "";
            break;
        case QIHSE_TS_BOOLEAN:
            value = cell->v.boolean ? "true" : "false";
            break;
        case QIHSE_TS_TIMESTAMPTZ: {
            int64_t micros = cell->v.timestamptz_us;
            int64_t seconds = micros / INT64_C(1000000);
            int64_t fraction = micros % INT64_C(1000000);
            if (fraction < 0) { --seconds; fraction += INT64_C(1000000); }
            time_t epoch = (time_t)seconds;
            struct tm tm;
            if (!gmtime_r(&epoch, &tm)) return false;
            (void)snprintf(number, sizeof(number),
                "%04d-%02d-%02d %02d:%02d:%02d.%06lld+00",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, (long long)fraction);
            break;
        }
        default:
            return false;
    }
    for (const unsigned char* p = (const unsigned char*)value; *p; ++p) {
        if (*p == '\\' || *p == '\t' || *p == '\n' || *p == '\r') {
            const char escaped[] = {
                '\\', *p == '\\' ? '\\' :
                       *p == '\t' ? 't' : *p == '\n' ? 'n' : 'r', '\0'
            };
            if (uwp_text_appendf(out, "%s", escaped) != 0) return false;
        } else if (*p < 0x20 || *p == 0x7f) {
            if (uwp_text_appendf(out, "\\x%02x", (unsigned)*p) != 0)
                return false;
        } else if (uwp_text_reserve(out, 1) != 0) {
            return false;
        } else {
            out->data[out->len++] = (char)*p;
            out->data[out->len] = '\0';
        }
    }
    return true;
}

static bool uwp_sql_select_project(uwp_sql_select_scan_t* scan,
                                   const qihse_col_value_t* values,
                                   size_t num_cols, uwp_text_buffer_t* out) {
    for (size_t i = 0; i < scan->projection_count; ++i) {
        int column = scan->projection[i];
        if (column < 0 || (size_t)column >= num_cols ||
            !uwp_sql_select_cell(out, &values[column])) return false;
        if (i + 1 < scan->projection_count &&
            uwp_text_appendf(out, "\t") != 0) return false;
    }
    return uwp_text_appendf(out, "\n") == 0;
}

/* Compare typed keys without converting large integers to floating point. */
static bool uwp_sql_select_compare(const qihse_col_value_t* a,
                                   const qihse_col_value_t* b, int* cmp) {
    if (a->type != b->type) return false;
    if (a->is_null || b->is_null) {
        *cmp = a->is_null == b->is_null ? 0 : (a->is_null ? 1 : -1);
        return true;
    }
    switch (a->type) {
        case QIHSE_TS_INT32:
            *cmp = (a->v.i32 > b->v.i32) - (a->v.i32 < b->v.i32); return true;
        case QIHSE_TS_INT64:
        case QIHSE_TS_TIMESTAMPTZ:
            *cmp = (a->v.i64 > b->v.i64) - (a->v.i64 < b->v.i64); return true;
        case QIHSE_TS_FLOAT:
            if (a->v.f32 != a->v.f32 || b->v.f32 != b->v.f32) return false;
            *cmp = (a->v.f32 > b->v.f32) - (a->v.f32 < b->v.f32); return true;
        case QIHSE_TS_BOOLEAN:
            *cmp = (a->v.boolean > b->v.boolean) - (a->v.boolean < b->v.boolean); return true;
        case QIHSE_TS_STRING:
        case QIHSE_TS_UUID:
        case QIHSE_TS_JSONB:
            if (!a->v.str || !b->v.str) return false;
            *cmp = strcmp(a->v.str, b->v.str); return true;
        default: return false;
    }
}

static bool uwp_sql_select_row(const qihse_col_value_t* values,
                               size_t num_cols, void* opaque) {
    uwp_sql_select_scan_t* scan = (uwp_sql_select_scan_t*)opaque;
    const qihse_sql_ast_t* ast = scan->ast;
    if (!uwp_sql_row_allowed(scan->user, scan->labels, values, num_cols))
        return true;
    if (scan->failed || (scan->order_column < 0 && ast->limit >= 0 &&
                         scan->emitted >= (size_t)ast->limit))
        return false;
    if (ast->num_where_conditions) {
        uwp_dml_scan_t predicate = {
            .conds = ast->where_conditions,
            .col_idx = scan->condition_columns,
            .num_conds = ast->num_where_conditions,
            .matched = 0
        };
        if (!uwp_dml_pred(values, num_cols, &predicate)) return true;
    }
    if (scan->order_column >= 0) {
        if ((size_t)scan->order_column >= num_cols) {
            scan->failed = 1;
            return false;
        }
        const qihse_col_value_t* key = &values[scan->order_column];
        int cmp = 0;
        if ((key->type == QIHSE_TS_FLOAT && key->v.f32 != key->v.f32) ||
            (scan->has_best &&
             !uwp_sql_select_compare(key, &scan->best_key, &cmp))) {
            scan->failed = 1;
            return false;
        }
        if (scan->has_best && (scan->order_ascending ? cmp >= 0 : cmp <= 0))
            return true;
        /* The candidate's key and projected row are bounded independently
         * of table cardinality, including before any text-buffer allocation. */
        size_t bytes = 0;
        for (size_t i = 0; i < scan->projection_count; ++i) {
            int col = scan->projection[i];
            if (col < 0 || (size_t)col >= num_cols) {
                scan->failed = 1;
                return false;
            }
            if (values[col].type == QIHSE_TS_STRING || values[col].type == QIHSE_TS_UUID ||
                values[col].type == QIHSE_TS_JSONB) {
                size_t n = !values[col].is_null && values[col].v.str ?
                    strnlen(values[col].v.str, 16385) : 0;
                if (n > 16384 - bytes) {
                    scan->failed = 1;
                    return false;
                }
                bytes += n;
            }
        }
        char* key_copy = NULL;
        if (key->type == QIHSE_TS_STRING || key->type == QIHSE_TS_UUID ||
            key->type == QIHSE_TS_JSONB) {
            if (!key->is_null && (!key->v.str || strnlen(key->v.str, 16385) > 16384 ||
                !(key_copy = strdup(key->v.str)))) {
                scan->failed = 1;
                return false;
            }
        } else if (key->type != QIHSE_TS_INT32 &&
                   key->type != QIHSE_TS_INT64 && key->type != QIHSE_TS_FLOAT &&
                   key->type != QIHSE_TS_BOOLEAN && key->type != QIHSE_TS_TIMESTAMPTZ) {
            scan->failed = 1;
            return false;
        }
        uwp_text_buffer_t candidate = {0};
        if (!uwp_sql_select_project(scan, values, num_cols, &candidate)) {
            free(key_copy);
            uwp_text_destroy(&candidate);
            scan->failed = 1;
            return false;
        }
        if (scan->has_best && (scan->best_key.type == QIHSE_TS_STRING ||
            scan->best_key.type == QIHSE_TS_UUID || scan->best_key.type == QIHSE_TS_JSONB ||
            scan->best_key.type == QIHSE_TS_NUMERIC || scan->best_key.type == QIHSE_TS_TSVECTOR))
            free(scan->best_key.v.str);
        uwp_text_destroy(&scan->best_row);
        scan->best_row = candidate;
        scan->best_key = *key;
        if (key_copy) scan->best_key.v.str = key_copy;
        else if (key->is_null && (key->type == QIHSE_TS_STRING ||
                 key->type == QIHSE_TS_UUID || key->type == QIHSE_TS_JSONB))
            scan->best_key.v.str = NULL;
        scan->has_best = true;
        return true;
    }
    if (scan->matched++ < (size_t)(ast->offset > 0 ? ast->offset : 0))
        return true;
    if (!uwp_sql_select_project(scan, values, num_cols, scan->response)) {
        scan->failed = 1;
        return false;
    }
    scan->emitted++;
    return ast->limit < 0 || scan->emitted < (size_t)ast->limit;
}

typedef struct {
    const qihse_sql_ast_t* ast;
    const qihse_user_t* user;
    uwp_sql_labels_t labels;
    int timestamp_col, success_col, ip_col;
    bool grouped;
    size_t total, successful, failed, unique_count;
    char** ips;
    size_t* counts;
    size_t capacity;
    bool error;
} uwp_sql_auth_aggregate_t;

static bool uwp_sql_auth_aggregate_row(const qihse_col_value_t* values,
                                      size_t num_cols, void* opaque) {
    uwp_sql_auth_aggregate_t* scan = opaque;
    if (!uwp_sql_row_allowed(scan->user, scan->labels, values, num_cols))
        return true;
    if ((size_t)scan->timestamp_col >= num_cols ||
        (size_t)scan->success_col >= num_cols ||
        (size_t)scan->ip_col >= num_cols ||
        values[scan->timestamp_col].is_null) {
        scan->error = true; return false;
    }
    const qihse_sql_condition_t* time_condition = &scan->ast->where_conditions[0];
    if (!uwp_dml_condition_matches(&values[scan->timestamp_col],
                                   time_condition)) return true;
    if (scan->grouped &&
        (values[scan->success_col].is_null ||
         values[scan->success_col].v.boolean)) return true;
    if (scan->total == SIZE_MAX) { scan->error = true; return false; }
    ++scan->total;
    if (values[scan->success_col].is_null) return true;
    if (values[scan->success_col].v.boolean) ++scan->successful;
    else ++scan->failed;
    const qihse_col_value_t* ip = &values[scan->ip_col];
    if (ip->is_null || !ip->v.str) return true;
    size_t i = 0;
    while (i < scan->unique_count && strcmp(scan->ips[i], ip->v.str)) ++i;
    if (i != scan->unique_count) {
        ++scan->counts[i];
        return true;
    }
    if (scan->unique_count == scan->capacity) {
        if (scan->capacity >= 16384) { scan->error = true; return false; }
        size_t cap = scan->capacity ? scan->capacity * 2 : 16;
        char** ips = realloc(scan->ips, cap * sizeof(*ips));
        if (!ips) { scan->error = true; return false; }
        scan->ips = ips;
        size_t* counts = realloc(scan->counts, cap * sizeof(*counts));
        if (!counts) { scan->error = true; return false; }
        scan->counts = counts;
        scan->capacity = cap;
    }
    if (strnlen(ip->v.str, 256) >= 256 ||
        !(scan->ips[i] = strdup(ip->v.str))) {
        scan->error = true; return false;
    }
    scan->counts[i] = 1;
    ++scan->unique_count;
    return true;
}

/* Bounded source-backed COUNT(CASE), DISTINCT and grouped HAVING queries.
 * Authorization is checked before either cardinalities or group keys are read. */
static int uwp_sql_select_auth_aggregate(qihse_uwp_context_t* ctx,
    const qihse_sql_ast_t* ast, qihse_txn_t** current_txn,
    qihse_user_t* user, uwp_text_buffer_t* response) {
    if (!ctx || !ctx->schema || !ast || !user ||
        ast->num_from_tables != 1 || !ast->from_tables[0].table_name ||
        strcasecmp(ast->from_tables[0].table_name, "auth_events") ||
        ast->num_joins || ast->set_op != QIHSE_SET_NONE ||
        ast->num_where_conditions < 1 || ast->num_where_conditions > 2 ||
        !ast->where_conditions[0].column_name ||
        strcasecmp(ast->where_conditions[0].column_name, "created_at") ||
        strcmp(ast->where_conditions[0].operator, ">") ||
        !ast->where_conditions[0].value ||
        !qihse_auth_can_access_object(user, 0,
            (uint64_t)uwp_fnv1a("auth_events"), QIHSE_ACL_READ)) return -1;
    bool grouped = ast->group_by != NULL;
    if (grouped) {
        if (ast->num_select_items != 2 || ast->num_where_conditions != 2 ||
            !ast->where_conditions[1].column_name ||
            strcasecmp(ast->where_conditions[1].column_name, "success") ||
            strcmp(ast->where_conditions[1].operator, "=") ||
            strcasecmp(ast->where_conditions[1].value, "FALSE") ||
            ast->group_by->num_group_columns != 1 ||
            strcasecmp(ast->group_by->group_columns[0], "ip_address") ||
            ast->select_items[0].agg_kind != QIHSE_AGG_NONE ||
            strcasecmp(ast->select_items[0].expr, "ip_address") ||
            ast->select_items[1].agg_kind != QIHSE_AGG_COUNT_STAR ||
            !ast->group_by->having_expr || ast->limit != 10 ||
            ast->num_order_items != 1 || !ast->order_items[0].column_name ||
            strcasecmp(ast->order_items[0].column_name, "attempts") ||
            ast->order_items[0].ascending) return -1;
        const char* h = ast->group_by->having_expr;
        while (isspace((unsigned char)*h)) ++h;
        if (strncasecmp(h, "COUNT(*) > 2", 12)) return -1;
        h += 12;
        while (isspace((unsigned char)*h)) ++h;
        if (*h) return -1;
    } else {
        if (ast->num_where_conditions != 1 || ast->num_select_items != 4 ||
            ast->select_items[0].agg_kind != QIHSE_AGG_COUNT_STAR ||
            ast->select_items[1].agg_kind != QIHSE_AGG_COUNT ||
            !ast->select_items[1].agg_case ||
            ast->select_items[1].agg_case->negated ||
            strcasecmp(ast->select_items[1].agg_case->column, "success") ||
            ast->select_items[2].agg_kind != QIHSE_AGG_COUNT ||
            !ast->select_items[2].agg_case ||
            !ast->select_items[2].agg_case->negated ||
            strcasecmp(ast->select_items[2].agg_case->column, "success") ||
            ast->select_items[3].agg_kind != QIHSE_AGG_COUNT ||
            !ast->select_items[3].is_distinct ||
            !ast->select_items[3].agg_arg ||
            strcasecmp(ast->select_items[3].agg_arg, "ip_address")) return -1;
        for (size_t i = 1; i <= 2; ++i)
            if (ast->select_items[i].agg_case->then_value != 1 ||
                ast->select_items[i].agg_case->has_else) return -1;
    }
    const char* reason = NULL;
    if (!uwp_dml_where_verifies(ast, &reason)) return -1;
    qihse_table_t* table = uwp_sql_row_table(ctx->schema, "auth_events");
    if (!table) return -1;
    uwp_sql_labels_t labels = uwp_sql_labels(table);
    if (!labels.valid || (labels.tenant < 0 &&
        qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM)) return -1;
    uwp_sql_auth_aggregate_t scan = {
        .ast = ast, .user = user, .labels = labels,
        .timestamp_col = qihse_table_find_col(table, "created_at"),
        .success_col = qihse_table_find_col(table, "success"),
        .ip_col = qihse_table_find_col(table, "ip_address"),
        .grouped = grouped
    };
    if (scan.timestamp_col < 0 || scan.success_col < 0 || scan.ip_col < 0 ||
        qihse_table_col_def(table, scan.timestamp_col)->type != QIHSE_TS_TIMESTAMPTZ ||
        qihse_table_col_def(table, scan.success_col)->type != QIHSE_TS_BOOLEAN ||
        qihse_table_col_def(table, scan.ip_col)->type != QIHSE_TS_STRING) return -1;
    qihse_table_txn_t* table_txn = NULL;
    if (current_txn && *current_txn) {
        table_txn = uwp_sql_txn_table(*current_txn, table, "auth_events",
                                      ctx->schema, user, false);
        if (!table_txn || qihse_txn_record_read(*current_txn, 2,
                "auth_events", strlen("auth_events"))) return -1;
    }
    if (table_txn) scan.error = !qihse_table_txn_scan_user(table_txn,
        user, uwp_sql_auth_aggregate_row, &scan);
    else scan.error = !qihse_table_scan_user(table, user,
        uwp_sql_auth_aggregate_row, &scan);
    int rc = -1;
    if (!scan.error) {
        if (!grouped) {
            if (uwp_text_appendf(response,
                "total_attempts\tsuccessful\tfailed\tunique_ips\n"
                "%zu\t%zu\t%zu\t%zu\nOK stmt_type=SELECT rows=1\n",
                scan.total, scan.successful, scan.failed,
                scan.unique_count) == 0) rc = 0;
        } else if (uwp_text_appendf(response, "ip_address\tattempts\n") == 0) {
            size_t emitted = 0;
            for (size_t k = 0; k < 10; ++k) {
                size_t best = scan.unique_count;
                for (size_t j = 0; j < scan.unique_count; ++j)
                    if (scan.counts[j] > 2 &&
                        (best == scan.unique_count ||
                         scan.counts[j] > scan.counts[best])) best = j;
                if (best == scan.unique_count) break;
                if (uwp_text_appendf(response, "%s\t%zu\n", scan.ips[best],
                                     scan.counts[best])) break;
                scan.counts[best] = 0;
                ++emitted;
            }
            if (!response->failed && uwp_text_appendf(response,
                "OK stmt_type=SELECT rows=%zu\n", emitted) == 0) rc = 0;
        }
    }
    for (size_t i = 0; i < scan.unique_count; ++i) free(scan.ips[i]);
    free(scan.ips); free(scan.counts);
    return rc;
}

/* A source-local index is rebuilt from the current authenticated generation;
 * candidate IDs are reauthorized and predicates rechecked before projection. */
static int uwp_sql_select_index(qihse_uwp_context_t* ctx,
    const qihse_sql_ast_t* ast, const qihse_table_t* table,
    const qihse_table_txn_t* txn, const qihse_user_t* user,
    uwp_sql_select_scan_t* scan) {
    if (!ctx->schema || ast->num_where_conditions != 1 ||
        strcmp(ast->where_conditions[0].operator, "=") ||
        scan->order_column >= 0) return 0;
    const qihse_schema_table_t* schema =
        qihse_schema_get_table(ctx->schema, ast->from_tables[0].table_name);
    if (!schema) return -1;
    const qihse_sql_condition_t* condition = &ast->where_conditions[0];
    int column = scan->condition_columns[0];
    bool json_expression = strstr(condition->column_name, "->>") != NULL;
    for (size_t i = 0; i < schema->num_indexes; ++i) {
        const qihse_schema_index_t* def = &schema->indexes[i];
        if (def->num_expressions != 1 || !def->expressions ||
            !def->expressions[0] ||
            (json_expression ? strcmp(def->expressions[0], condition->column_name) :
             strcasecmp(def->expressions[0], qihse_table_col_def(table, column)->name)) ||
            (def->using_method && strcasecmp(def->using_method, "btree")))
            continue;
        uint16_t bind = condition->value_parameter_index;
        if (bind && (!uwp_bound_params || bind > uwp_bound_count)) return -1;
        if ((bind && uwp_bound_params[bind - 1].is_null) ||
            (!bind && !condition->value_is_string && condition->value &&
             !strcasecmp(condition->value, "NULL"))) return 1;
        qihse_col_value_t key = {0};
        if (json_expression) {
            key.type = QIHSE_TS_STRING;
            key.v.str = condition->value ? strdup(condition->value) : NULL;
            if (!key.v.str) return -1;
        } else if (qihse_table_col_def(table, column)->type == QIHSE_TS_NUMERIC) {
            if (!qihse_ts_numeric_valid(condition->value, 0, 0)) return -1;
            key.type = QIHSE_TS_NUMERIC;
            key.v.str = strdup(condition->value);
            if (!key.v.str) return -1;
        } else if (!(bind ? uwp_sql_bound_value(qihse_table_col_def(table, column),
                        &schema->columns[column], &uwp_bound_params[bind - 1],
                        condition->value, &key) :
                    uwp_dml_literal_value(qihse_table_col_def(table, column),
                        condition->value, condition->value_is_string, &key)))
            return -1;
        if (key.is_null) return 1;
        qihse_sql_row_index_t* index = NULL;
        size_t* ids = NULL;
        size_t count = 0;
        uint64_t generation = 0;
        bool ok = qihse_sql_row_index_build(def, table, txn, user, &index) &&
            qihse_sql_row_index_equal(index, table, txn, user,
                                      &key, 1, &ids, &count) &&
            (txn ? qihse_table_txn_generation_user(txn, user, &generation) :
                   qihse_table_generation_user(table, user, &generation));
        for (size_t j = 0; ok && j < count && !scan->failed; ++j) {
            ok = txn ? qihse_table_txn_row_get_user(txn, user, generation,
                    ids[j], uwp_sql_select_row, scan) :
                qihse_table_row_get_user(table, user, generation,
                    ids[j], uwp_sql_select_row, scan);
        }
        if (key.type == QIHSE_TS_STRING || key.type == QIHSE_TS_UUID ||
            key.type == QIHSE_TS_JSONB || key.type == QIHSE_TS_NUMERIC ||
            key.type == QIHSE_TS_TSVECTOR) free(key.v.str);
        free(ids);
        qihse_sql_row_index_destroy(index);
        return ok && !scan->failed ? 1 : -1;
    }
    return 0;
}

/* Execute the deliberately narrow row-store SELECT subset. Unsupported
 * constructs fail as protocol errors rather than returning the optimizer's
 * old empty placeholder stream as if it were a valid query result. */
static int uwp_sql_execute_select(qihse_uwp_context_t* ctx,
                                  const qihse_sql_ast_t* ast,
                                  qihse_txn_t** current_txn,
                                  qihse_user_t* user,
                                  uwp_text_buffer_t* response) {
    if (ast && ast->num_from_tables == 1 && ast->from_tables &&
        ast->from_tables[0].table_name &&
        !strcasecmp(ast->from_tables[0].table_name, "auth_events") &&
        ast->num_select_items &&
        (ast->group_by || ast->select_items[0].agg_kind != QIHSE_AGG_NONE))
        return uwp_sql_select_auth_aggregate(ctx, ast, current_txn,
                                              user, response);
    if (!ctx || !ctx->schema || !ast || !user || !response ||
        ast->stmt_type != QIHSE_SQL_SELECT || ast->num_from_tables != 1 ||
        ast->num_joins != 0 || ast->set_op != QIHSE_SET_NONE ||
        ast->group_by || ast->select_distinct ||
        ast->num_select_items == 0) {
        return -1;
    }

    const char* table_name = ast->from_tables[0].table_name;
    if (!table_name || !qihse_auth_can_access_object(
                           user, 0, (uint64_t)uwp_fnv1a(table_name),
                           QIHSE_ACL_READ)) {
        return -1;
    }
    qihse_table_t* table = uwp_sql_row_table(
        (qihse_schema_registry_t*)ctx->schema, table_name);
    if (!table) return -1;
    uwp_sql_labels_t labels = uwp_sql_labels(table);
    if (!labels.valid || (labels.tenant < 0 &&
                          qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM))
        return -1;

    size_t max_projection = qihse_table_num_cols(table);
    int* projection = (int*)calloc(max_projection ? max_projection : 1,
                                   sizeof(*projection));
    int* condition_columns = ast->num_where_conditions
        ? (int*)calloc(ast->num_where_conditions, sizeof(*condition_columns))
        : NULL;
    if (!projection || (ast->num_where_conditions && !condition_columns)) {
        free(projection);
        free(condition_columns);
        return -1;
    }

    bool ok = true;
    int order_column = -1;
    if (ast->num_order_items) {
        /* The parser can silently discard ORDER tails. Accept only this fully
         * verified top-1 shape until general sorting is implemented. */
        const char* p = uwp_sql_find_keyword(ast->raw_sql, "ORDER");
        const char* name = ast->num_order_items == 1 ?
            ast->order_items[0].column_name : NULL;
        uwp_dml_token_t tok;
        if (ast->num_order_items != 1 || ast->limit != 1 || ast->offset > 0 ||
            !p || !name || !uwp_dml_next_token(&p, &tok) ||
            tok.is_string || tok.len != 2 || strncasecmp(tok.text, "BY", 2) ||
            !uwp_dml_next_token(&p, &tok) || tok.is_string ||
            !uwp_dml_token_eq(&tok, name)) ok = false;
        if (ok) {
            const char* after_name = p;
            if (uwp_dml_next_token(&p, &tok) && !tok.is_string &&
                ((tok.len == 3 && strncasecmp(tok.text, "ASC", 3) == 0) ||
                 (tok.len == 4 && strncasecmp(tok.text, "DESC", 4) == 0))) {
                bool asc = strncasecmp(tok.text, "ASC", tok.len) == 0;
                if (asc != (ast->order_items[0].ascending != 0)) ok = false;
            } else p = after_name;
            if (!uwp_dml_next_token(&p, &tok) || tok.is_string ||
                tok.len != 5 || strncasecmp(tok.text, "LIMIT", 5) ||
                !uwp_dml_next_token(&p, &tok) || tok.is_string ||
                !(uwp_dml_token_eq(&tok, "1") ||
                  uwp_dml_token_eq(&tok, "1;"))) ok = false;
            while (isspace((unsigned char)*p)) ++p;
            if (*p == ';') ++p;
            while (isspace((unsigned char)*p)) ++p;
            if (*p) ok = false;
        }
        if (ok) {
            order_column = uwp_dml_resolve_column(table, name);
            if (order_column < 0) ok = false;
        }
    } else if (uwp_sql_find_keyword(ast->raw_sql, "ORDER")) {
        ok = false;
    }
    size_t projection_count = 0;
    bool select_star = ast->num_select_items == 1 &&
                       ast->select_items[0].expr &&
                       strcmp(ast->select_items[0].expr, "*") == 0;
    if (select_star) {
        for (size_t i = 0; i < max_projection; ++i)
            projection[projection_count++] = (int)i;
    } else {
        for (size_t i = 0; i < ast->num_select_items && ok; ++i) {
            const char* expr = ast->select_items[i].expr;
            if (!expr || ast->select_items[i].agg_kind != QIHSE_AGG_NONE ||
                ast->select_items[i].scalar_subquery ||
                ast->select_items[i].window ||
                ast->select_items[i].win_kind != QIHSE_WIN_NONE) {
                ok = false;
                break;
            }
            const char* bare = strrchr(expr, '.');
            if (bare) {
                const char* qualifier = expr;
                size_t qualifier_len = (size_t)(bare - expr);
                const char* alias = ast->from_tables[0].alias;
                if (!((strlen(table_name) == qualifier_len &&
                       strncasecmp(table_name, qualifier, qualifier_len) == 0) ||
                      (alias && strlen(alias) == qualifier_len &&
                       strncasecmp(alias, qualifier, qualifier_len) == 0))) {
                    ok = false;
                    break;
                }
                expr = bare + 1;
            }
            int column = qihse_table_find_col(table, expr);
            if (column < 0 || projection_count >= max_projection) {
                ok = false;
                break;
            }
            projection[projection_count++] = column;
        }
    }

    const char* where_region = NULL;
    size_t where_len = 0;
    bool has_where = uwp_dml_where_region(ast, &where_region, &where_len);
    (void)where_region;
    (void)where_len;
    if (ast->num_where_conditions == 0 && has_where) ok = false;
    if (ast->num_where_conditions) {
        const char* reason = NULL;
        if (!uwp_dml_where_verifies(ast, &reason)) ok = false;
        for (size_t i = 0; i < ast->num_where_conditions && ok; ++i) {
            const qihse_sql_condition_t* condition = &ast->where_conditions[i];
            if (condition->subq_kind ||
                !uwp_dml_operator_supported(condition->operator)) {
                ok = false;
                break;
            }
            int column = uwp_dml_resolve_column(table,
                                                condition->column_name);
            if (column < 0) ok = false;
            else condition_columns[i] = column;
        }
    }
    if (!ok || projection_count == 0) {
        free(projection);
        free(condition_columns);
        return -1;
    }

    for (size_t i = 0; i < projection_count; ++i) {
        const char* name = NULL;
        if (select_star || !ast->select_items[i].alias ||
            ast->select_items[i].alias[0] == '\0') {
            const qihse_col_def_t* def = qihse_table_col_def(
                table, (size_t)projection[i]);
            name = def ? def->name : NULL;
        } else {
            name = ast->select_items[i].alias;
        }
        if (!name || uwp_text_appendf(response, "%s%s",
                                      i ? "\t" : "", name) != 0) {
            ok = false;
            break;
        }
    }
    if (ok && uwp_text_appendf(response, "\n") != 0) ok = false;

    qihse_table_txn_t* table_txn = NULL;
    if (ok && current_txn && *current_txn) {
        qihse_txn_t* txn = *current_txn;
        table_txn = uwp_sql_txn_table(txn, table, table_name, ctx->schema, user, false);
        if (!table_txn || qihse_txn_record_read(txn, 2, table_name,
                                                 strlen(table_name)) != 0) {
            ok = false;
        } else {
            uwp_sql_txn_resource_t* resource = txn->resource_ctx;
            for (size_t i = 0; i < resource->table_count; ++i)
                if (resource->tables[i].table_txn == table_txn)
                    resource->tables[i].read_observed = true;
        }
    }
    uwp_sql_select_scan_t scan = {
        .ast = ast,
        .projection = projection,
        .projection_count = projection_count,
        .condition_columns = condition_columns,
        .response = response,
        .user = user,
        .labels = labels,
        .order_column = order_column,
        .order_ascending = ast->num_order_items ?
            ast->order_items[0].ascending : 1
    };
    if (ok && !(ast->limit == 0)) {
        int indexed = uwp_sql_select_index(ctx, ast, table, table_txn, user, &scan);
        if (indexed < 0) ok = false;
        else if (!indexed && table_txn) ok = qihse_table_txn_scan_user(
            table_txn, user, uwp_sql_select_row, &scan);
        else if (!indexed) ok = qihse_table_scan_user(
            table, user, uwp_sql_select_row, &scan);
    }
    if (scan.failed || response->failed) ok = false;
    if (ok && order_column >= 0 && scan.has_best) {
        if (uwp_text_reserve(response, scan.best_row.len) != 0) ok = false;
        else {
            memcpy(response->data + response->len, scan.best_row.data,
                   scan.best_row.len);
            response->len += scan.best_row.len;
            response->data[response->len] = '\0';
            scan.emitted = 1;
        }
    }
    if (scan.has_best && (scan.best_key.type == QIHSE_TS_STRING ||
        scan.best_key.type == QIHSE_TS_UUID || scan.best_key.type == QIHSE_TS_JSONB ||
        scan.best_key.type == QIHSE_TS_NUMERIC || scan.best_key.type == QIHSE_TS_TSVECTOR))
        free(scan.best_key.v.str);
    uwp_text_destroy(&scan.best_row);
    if (ok && uwp_text_appendf(response, "OK stmt_type=SELECT rows=%zu\n",
                               scan.emitted) != 0)
        ok = false;

    free(projection);
    free(condition_columns);
    return ok ? 0 : -1;
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

static __attribute__((unused)) void uwp_execute_recursive_cte(qihse_uwp_context_t* ctx,
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
static __attribute__((unused)) void uwp_execute_window(qihse_uwp_context_t* ctx,
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

typedef struct {
    char* source;
    char* record_type;
    uint64_t count;
    char** keys[3];
    size_t key_counts[3];
    bool has_last;
    int64_t last;
} uwp_sql_stats_group_t;

typedef struct {
    const qihse_user_t* user;
    uwp_sql_labels_t labels;
    int source, record_type, data, created_at;
    uwp_sql_stats_group_t* groups;
    size_t count, capacity;
    bool failed;
} uwp_sql_stats_scan_t;

static void uwp_sql_stats_destroy(uwp_sql_stats_scan_t* scan) {
    for (size_t i = 0; i < scan->count; ++i) {
        uwp_sql_stats_group_t* g = &scan->groups[i];
        free(g->source); free(g->record_type);
        for (size_t k = 0; k < 3; ++k) {
            for (size_t j = 0; j < g->key_counts[k]; ++j) free(g->keys[k][j]);
            free(g->keys[k]);
        }
    }
    free(scan->groups);
}

static bool uwp_sql_stats_row(const qihse_col_value_t* values,
                              size_t num_cols, void* opaque) {
    uwp_sql_stats_scan_t* scan = opaque;
    if (!uwp_sql_row_allowed(scan->user, scan->labels, values, num_cols)) {
        scan->failed = true;
        return false;
    }
    if (scan->source < 0 || scan->record_type < 0 || scan->data < 0 ||
        scan->created_at < 0 || (size_t)scan->source >= num_cols ||
        (size_t)scan->record_type >= num_cols || (size_t)scan->data >= num_cols ||
        (size_t)scan->created_at >= num_cols ||
        values[scan->source].is_null || values[scan->record_type].is_null ||
        values[scan->data].is_null || !values[scan->source].v.str ||
        !values[scan->record_type].v.str || !values[scan->data].v.str) {
        scan->failed = true; return false;
    }
    size_t i = 0;
    for (; i < scan->count; ++i)
        if (!strcmp(scan->groups[i].source, values[scan->source].v.str) &&
            !strcmp(scan->groups[i].record_type,
                    values[scan->record_type].v.str)) break;
    if (i == scan->count) {
        if (scan->count >= 1024) { scan->failed = true; return false; }
        if (scan->count == scan->capacity) {
            size_t capacity = scan->capacity ? scan->capacity * 2 : 16;
            uwp_sql_stats_group_t* p = realloc(scan->groups,
                                                capacity * sizeof(*p));
            if (!p) { scan->failed = true; return false; }
            scan->groups = p; scan->capacity = capacity;
        }
        uwp_sql_stats_group_t* g = &scan->groups[i];
        memset(g, 0, sizeof(*g));
        g->source = strdup(values[scan->source].v.str);
        g->record_type = strdup(values[scan->record_type].v.str);
        ++scan->count;
        if (!g->source || !g->record_type) {
            scan->failed = true; return false;
        }
    }
    uwp_sql_stats_group_t* g = &scan->groups[i];
    if (g->count == UINT64_MAX) { scan->failed = true; return false; }
    ++g->count;
    const qihse_col_value_t* timestamp = &values[scan->created_at];
    if (!timestamp->is_null &&
        (!g->has_last || timestamp->v.timestamptz_us > g->last)) {
        g->last = timestamp->v.timestamptz_us;
        g->has_last = true;
    }
    static const char* keys[] = { "email", "phone", "username" };
    for (size_t k = 0; k < 3; ++k) {
        char* extracted = NULL;
        if (!uwp_sql_json_text(values[scan->data].v.str, keys[k], &extracted)) {
            scan->failed = true; return false;
        }
        if (!extracted) continue;
        size_t j = 0;
        while (j < g->key_counts[k] && strcmp(g->keys[k][j], extracted)) ++j;
        if (j != g->key_counts[k]) { free(extracted); continue; }
        if (g->key_counts[k] >= 16384) {
            free(extracted); scan->failed = true; return false;
        }
        char** grown = realloc(g->keys[k],
                        (g->key_counts[k] + 1) * sizeof(*grown));
        if (!grown) { free(extracted); scan->failed = true; return false; }
        g->keys[k] = grown;
        g->keys[k][g->key_counts[k]++] = extracted;
    }
    return true;
}

static void uwp_sql_free_stats_rows(qihse_col_value_t** rows, size_t count) {
    if (!rows) return;
    for (size_t i = 0; i < count; ++i) {
        if (!rows[i]) continue;
        free(rows[i][0].v.str);
        free(rows[i][1].v.str);
        free(rows[i]);
    }
    free(rows);
}

/* CREATE uses the same grouping callback as REFRESH, over one authenticated
 * transaction-local source snapshot. The store rechecks this generation and
 * source authorization while publishing the seeded catalog. */
static bool uwp_sql_seed_stats(qihse_uwp_context_t* ctx,
    const uwp_sql_txn_resource_t* staged,
    const qihse_sql_ast_t* query, const qihse_user_t* user,
    qihse_col_value_t*** rows, size_t* count,
    qihse_ts_source_fence_t* source_fence) {
    if (!ctx || !ctx->schema || !query || !query->from_tables ||
        !query->from_tables[0].table_name || !user || !rows || !count ||
        !source_fence || qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM)
        return false;
    const char* name = query->from_tables[0].table_name;
    const qihse_schema_table_t* definition = qihse_schema_get_table(
        staged ? staged->ddl_staged : ctx->schema, name);
    qihse_table_t* source = qihse_table_store_find_table(uwp_sql_row_store, name);
    qihse_table_store_t* private_store = NULL;
    if (!source && staged && definition) {
        /* DDL-only transactions cannot insert into newly staged tables. Use
         * their actual empty relation, not the unrelated committed catalog. */
        bool newly_staged = false;
        for (size_t i = 0; i < staged->ddl_count; ++i)
            if (!strcmp(staged->ddl_names[i], name) &&
                !staged->ddl_row_counts[i]) newly_staged = true;
        if (!newly_staged || qihse_schema_get_table(ctx->schema, name)) return false;
        qihse_col_def_t* cols = calloc(definition->num_columns, sizeof(*cols));
        if (!cols) return false;
        for (size_t c = 0; c < definition->num_columns; ++c) {
            cols[c].name = definition->columns[c].name;
            cols[c].type = uwp_sql_type_to_ts_type(definition->columns[c].type);
        }
        private_store = qihse_table_store_create();
        if (private_store) source = qihse_table_store_create_table(private_store,
            name, cols, definition->num_columns);
        free(cols);
    }
    if (!definition || !source || definition->num_columns != qihse_table_num_cols(source)) {
        qihse_table_store_destroy(private_store);
        return false;
    }
    for (size_t c = 0; c < definition->num_columns; ++c) {
        const qihse_col_def_t* col = qihse_table_col_def(source, c);
        if (!col || strcmp(col->name, definition->columns[c].name) ||
            col->type != uwp_sql_type_to_ts_type(definition->columns[c].type)) {
            qihse_table_store_destroy(private_store);
            return false;
        }
    }
    uwp_sql_labels_t labels = uwp_sql_labels(source);
    if (!labels.valid || labels.tenant >= 0) {
        qihse_table_store_destroy(private_store);
        return false;
    }
    uwp_sql_stats_scan_t scan = {
        .user = user, .labels = labels,
        .source = qihse_table_find_col(source, "source"),
        .record_type = qihse_table_find_col(source, "record_type"),
        .data = qihse_table_find_col(source, "data"),
        .created_at = qihse_table_find_col(source, "created_at")
    };
    if (scan.source < 0 || scan.record_type < 0 || scan.data < 0 ||
        scan.created_at < 0 ||
        qihse_table_col_def(source, scan.source)->type != QIHSE_TS_STRING ||
        qihse_table_col_def(source, scan.record_type)->type != QIHSE_TS_STRING ||
        qihse_table_col_def(source, scan.data)->type != QIHSE_TS_JSONB ||
        qihse_table_col_def(source, scan.created_at)->type != QIHSE_TS_TIMESTAMPTZ) {
        qihse_table_store_destroy(private_store);
        return false;
    }
    qihse_table_txn_t* snapshot = qihse_table_txn_begin_user(source, user);
    if (!snapshot) { qihse_table_store_destroy(private_store); return false; }
    bool ok = qihse_table_txn_generation_user(snapshot, user,
            &source_fence->generation) &&
        qihse_table_txn_scan_user(snapshot, user, uwp_sql_stats_row, &scan) &&
        !scan.failed;
    qihse_table_txn_rollback(snapshot);
    qihse_col_value_t** result = NULL;
    if (ok) result = calloc(scan.count ? scan.count : 1, sizeof(*result));
    if (ok && !result) ok = false;
    for (size_t i = 0; ok && i < scan.count; ++i) {
        uwp_sql_stats_group_t* g = &scan.groups[i];
        result[i] = calloc(7, sizeof(**result));
        if (!result[i] || g->count > INT64_MAX) { ok = false; break; }
        result[i][0] = (qihse_col_value_t){.type=QIHSE_TS_STRING,
                                             .v.str=strdup(g->source)};
        result[i][1] = (qihse_col_value_t){.type=QIHSE_TS_STRING,
                                             .v.str=strdup(g->record_type)};
        if (!result[i][0].v.str || !result[i][1].v.str) { ok = false; break; }
        for (size_t c = 2; c < 6; ++c)
            result[i][c] = (qihse_col_value_t){.type=QIHSE_TS_INT64,
                .v.i64=(int64_t)(c == 2 ? g->count : g->key_counts[c - 3])};
        result[i][6] = (qihse_col_value_t){.type=QIHSE_TS_TIMESTAMPTZ,
            .is_null=!g->has_last, .v.timestamptz_us=g->last};
    }
    if (ok) {
        source_fence->table = private_store ? NULL : source;
        *rows = result;
        *count = scan.count;
    } else uwp_sql_free_stats_rows(result, scan.count);
    uwp_sql_stats_destroy(&scan);
    qihse_table_store_destroy(private_store);
    return ok;
}

static int uwp_sql_stats_delete_pred(const qihse_col_value_t* values,
                                     size_t count, void* opaque) {
    (void)values; (void)count; (void)opaque;
    return 1;
}

/* Refresh reads a principal-authorized source snapshot and replaces all view
 * rows in a single optimistic commit alongside validation of that source. */
static int uwp_sql_refresh_stats(qihse_uwp_context_t* ctx,
    qihse_txn_t** current_txn, qihse_user_t* user,
    const char* view_name, size_t* rows) {
    if (!ctx || !ctx->schema || !current_txn || !*current_txn ||
        !user || !rows || !view_name) return -1;
    const qihse_schema_table_t* definition = qihse_schema_get_table(
        ctx->schema, view_name);
    if (!definition || !definition->view_query || definition->num_columns != 7)
        return -1;
    qihse_sql_ast_t* query = qihse_parse_sql_to_ast(definition->view_query);
    qihse_sql_ast_t wrapper = {.view_name=(char*)view_name,
        .raw_sql=definition->view_query, .view_query=query};
    bool valid = uwp_sql_view_query_valid(&wrapper);
    const char* parsed_source = valid ? query->from_tables[0].table_name : NULL;
    char source_name[256];
    if (!parsed_source || strnlen(parsed_source, sizeof(source_name)) >=
            sizeof(source_name)) {
        qihse_sql_ast_free(query); return -1;
    }
    strcpy(source_name, parsed_source);
    if (!qihse_auth_can_access_object(user, 0,
            (uint64_t)uwp_fnv1a(source_name), QIHSE_ACL_READ) ||
        !qihse_auth_can_access_object(user, 0,
            (uint64_t)uwp_fnv1a(view_name), QIHSE_ACL_WRITE)) {
        qihse_sql_ast_free(query); return -1;
    }
    qihse_table_t* source = uwp_sql_row_table(ctx->schema, source_name);
    qihse_table_t* view = uwp_sql_row_table(ctx->schema, view_name);
    qihse_sql_ast_free(query);
    if (!source || !view) return -1;
    uwp_sql_labels_t labels = uwp_sql_labels(source);
    if (!labels.valid || labels.tenant >= 0 ||
        qihse_user_get_tenant_id(user) != QIHSE_TENANT_SYSTEM) return -1;
    uwp_sql_stats_scan_t scan = {
        .user = user, .labels = labels,
        .source = qihse_table_find_col(source, "source"),
        .record_type = qihse_table_find_col(source, "record_type"),
        .data = qihse_table_find_col(source, "data"),
        .created_at = qihse_table_find_col(source, "created_at")
    };
    if (scan.source < 0 || scan.record_type < 0 || scan.data < 0 ||
        scan.created_at < 0 ||
        qihse_table_col_def(source, scan.data)->type != QIHSE_TS_JSONB ||
        qihse_table_col_def(source, scan.created_at)->type != QIHSE_TS_TIMESTAMPTZ)
        return -1;
    qihse_table_txn_t* source_txn = uwp_sql_txn_table(*current_txn,
        source, source_name, ctx->schema, user, false);
    if (!source_txn || qihse_txn_record_read(*current_txn, 2,
            source_name, strlen(source_name))) return -1;
    uwp_sql_txn_resource_t* resource = (*current_txn)->resource_ctx;
    for (size_t i = 0; i < resource->table_count; ++i)
        if (resource->tables[i].table_txn == source_txn)
            resource->tables[i].read_observed = true;
    if (!qihse_table_txn_scan_user(source_txn, user,
            uwp_sql_stats_row, &scan) || scan.failed) {
        uwp_sql_stats_destroy(&scan); return -1;
    }
    qihse_table_txn_t* view_txn = uwp_sql_txn_table(*current_txn,
        view, view_name, ctx->schema, user, true);
    if (!view_txn || qihse_txn_record_write(*current_txn, 2,
            view_name, strlen(view_name))) {
        uwp_sql_stats_destroy(&scan); return -1;
    }
    qihse_table_txn_delete(view_txn, uwp_sql_stats_delete_pred, NULL);
    for (size_t i = 0; i < scan.count; ++i) {
        uwp_sql_stats_group_t* g = &scan.groups[i];
        qihse_col_value_t values[7] = {
            {.type=QIHSE_TS_STRING, .v.str=g->source},
            {.type=QIHSE_TS_STRING, .v.str=g->record_type},
            {.type=QIHSE_TS_INT64, .v.i64=(int64_t)g->count},
            {.type=QIHSE_TS_INT64, .v.i64=(int64_t)g->key_counts[0]},
            {.type=QIHSE_TS_INT64, .v.i64=(int64_t)g->key_counts[1]},
            {.type=QIHSE_TS_INT64, .v.i64=(int64_t)g->key_counts[2]},
            {.type=QIHSE_TS_TIMESTAMPTZ, .is_null=!g->has_last,
             .v.timestamptz_us=g->last}
        };
        if (g->count > INT64_MAX || qihse_table_txn_insert(view_txn, values, 7) < 0) {
            uwp_sql_stats_destroy(&scan); return -1;
        }
    }
    *rows = scan.count;
    uwp_sql_stats_destroy(&scan);
    return 0;
}

static uwp_sts_result_t uwp_sql_execute(qihse_uwp_context_t* ctx,
                                        qihse_sql_ast_t* ast, const char* sql,
                                        qihse_txn_t** current_txn, qihse_user_t* user,
                                        size_t* refresh_rows) {
    int rc = 0;
    switch (ast->stmt_type) {
        case QIHSE_SQL_CREATE:
            if (!ctx->schema) return UWP_STS_ERR_NO_CTX;
            if (current_txn && *current_txn && uwp_sql_durable_ctx != ctx)
                return UWP_STS_ERR_FAILED;
            if (ast->create_if_not_exists && ast->table_name &&
                qihse_schema_get_table(ctx->schema, ast->table_name) &&
                !qihse_auth_can_access_object(user, 0,
                    (uint64_t)uwp_fnv1a(ast->table_name), QIHSE_ACL_READ))
                return UWP_STS_ERR_PERM;
            if (uwp_sql_durable_ctx == ctx) {
                int ddl_rc;
                if (ast->index_def) {
                    if (!ast->index_def->table_name ||
                        !qihse_auth_can_access_object(user, 0,
                            (uint64_t)uwp_fnv1a(ast->index_def->table_name),
                            QIHSE_ACL_READ)) return UWP_STS_ERR_PERM;
                    ddl_rc = current_txn && *current_txn ?
                        uwp_sql_txn_create_durable_index(ctx, *current_txn, ast, user) :
                        uwp_sql_create_durable_index(ctx, ast, user);
                } else ddl_rc = current_txn && *current_txn ?
                    uwp_sql_txn_create_durable_table(ctx, *current_txn, ast, user) :
                    uwp_sql_create_durable_table(ctx, ast);
                return ddl_rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
            }
            if (ast->index_def ? ast->index_def->unique :
                !uwp_sql_supported_create(ast, false)) return UWP_STS_ERR_FAILED;
            rc = ast->index_def
                     ? qihse_schema_create_index((qihse_schema_registry_t*)ctx->schema, ast)
                     : qihse_schema_create_table((qihse_schema_registry_t*)ctx->schema, ast);
            break;
        case QIHSE_SQL_CREATE_EXTENSION: {
            bool if_not_exists = false;
            if (!uwp_sql_parse_uuid_ossp_extension(sql, &if_not_exists) ||
                uwp_sql_durable_ctx != ctx) return UWP_STS_ERR_FAILED;
            int extension_rc = current_txn && *current_txn
                ? uwp_sql_txn_create_durable_extension(ctx, *current_txn, user,
                                                       if_not_exists)
                : uwp_sql_create_durable_extension(ctx, if_not_exists);
            return extension_rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
        }
        case QIHSE_SQL_DROP:
            if (uwp_sql_durable_ctx == ctx) return UWP_STS_ERR_FAILED;
            if (current_txn && *current_txn) return UWP_STS_ERR_FAILED;
            if (!ctx->schema) return UWP_STS_ERR_NO_CTX;
            rc = ast->drop_is_index
                     ? qihse_schema_drop_index((qihse_schema_registry_t*)ctx->schema,
                                               ast->drop_name)
                     : qihse_schema_drop_table((qihse_schema_registry_t*)ctx->schema,
                                               ast->drop_name);
            break;
        case QIHSE_SQL_ALTER:
            if (uwp_sql_durable_ctx == ctx) return UWP_STS_ERR_FAILED;
            if (current_txn && *current_txn) return UWP_STS_ERR_FAILED;
            if (!ctx->schema) return UWP_STS_ERR_NO_CTX;
            if (ast->alter_clause && ast->alter_clause->action == QIHSE_ALTER_ADD_COLUMN &&
                ast->alter_clause->add_column) {
                const qihse_sql_column_def_t* col = ast->alter_clause->add_column;
                if (col->not_null || col->is_primary_key || col->is_unique ||
                    col->fk || col->check_expr || col->default_expr || col->is_serial)
                    return UWP_STS_ERR_FAILED;
            }
            rc = qihse_schema_alter_table((qihse_schema_registry_t*)ctx->schema, ast);
            break;
        case QIHSE_SQL_SAVEPOINT:
        case QIHSE_SQL_RELEASE:
            /* Row-store resources do not yet expose reversible savepoint
             * snapshots.  Refuse SQL savepoints rather than acknowledge a
             * rollback boundary that cannot restore row data. */
            return UWP_STS_ERR_FAILED;
        case QIHSE_SQL_BEGIN: {
            uint8_t isolation = (uint8_t)uwp_sql_isolation(sql);
            return uwp_dispatch_txn_locked(ctx, 0x01, &isolation, 1, current_txn, user, -1,
                                    NULL, NULL);
        }
        case QIHSE_SQL_COMMIT:
            return uwp_dispatch_txn_locked(ctx, 0x02, NULL, 0, current_txn, user, -1,
                                    NULL, NULL);
        case QIHSE_SQL_ROLLBACK:
            if (ast->util && ast->util->name) {
                return uwp_dispatch_txn_locked(ctx, 0x05, (const uint8_t*)ast->util->name,
                                        strlen(ast->util->name) + 1, current_txn, user, -1,
                                        NULL, NULL);
            }
            return uwp_dispatch_txn_locked(ctx, 0x03, NULL, 0, current_txn, user, -1,
                                    NULL, NULL);
        case QIHSE_SQL_CREATE_FUNCTION:
        case QIHSE_SQL_CREATE_TRIGGER:
        case QIHSE_SQL_DROP_TRIGGER:
        case QIHSE_SQL_CREATE_MATVIEW:
            return uwp_sql_durable_catalog_change(ctx,
                current_txn ? *current_txn : NULL, ast, user, refresh_rows) == 0 ?
                UWP_STS_OK : UWP_STS_ERR_FAILED;
        case QIHSE_SQL_REFRESH:
            if (!ast->view_name || !current_txn || !*current_txn || !refresh_rows)
                return UWP_STS_ERR_FAILED;
            return uwp_sql_refresh_stats(ctx, current_txn, user,
                                         ast->view_name, refresh_rows) == 0 ?
                UWP_STS_OK : UWP_STS_ERR_FAILED;
        case QIHSE_SQL_SELECT:
            /* execution logic will be wired in caller because we need response buffer */
            break;
        case QIHSE_SQL_INSERT:
        case QIHSE_SQL_UPDATE:
        case QIHSE_SQL_DELETE: {
            const qihse_schema_table_t* target = ctx->schema && ast->table_name ?
                qihse_schema_get_table(ctx->schema, ast->table_name) : NULL;
            if (target && target->view_query) return UWP_STS_ERR_FAILED;
            break;
        }
        default:
            /* Unsupported statement kinds must fail closed, not fall through
             * to an OK response without executing their semantics. */
            return UWP_STS_ERR_FAILED;
    }
    return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
}

static uwp_sts_result_t uwp_dispatch_sql_locked(qihse_uwp_context_t* ctx,
                                                uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    if (!user || !qihse_auth_user_is_active(user)) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (!ctx || !ctx->sql_engine) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }
    /* pgwire passes a socket descriptor; in-memory UWP fixtures pass -1. */
    if ((client_fd >= 0 || uwp_sql_durable_ctx) &&
        !qihse_uwp_sql_durable_ready(ctx)) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }
    if (qihse_uwp_sql_durable_ready(ctx)) {
        const uint8_t* image = NULL;
        size_t len = 0, actual = 0;
        uint8_t* current = NULL;
        qihse_table_store_t* store = qihse_uwp_sql_table_store();
        bool valid = qihse_table_store_schema_image(store, &image, &len) &&
                     ctx->schema &&
                     qihse_schema_serialize(ctx->schema, &current, &actual) == 0 &&
                     len == actual && !memcmp(image, current, len);
        free(current);
        if (!valid) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
            return UWP_STS_ERR_NO_CTX;
        }
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

        /* Hash the SQL text to get a stmt_id (FNV-1a 32-bit). */
        uint32_t stmt_id = uwp_fnv1a(sql);
        pthread_mutex_lock(&uwp_ps_hash.mutex);
        uwp_ps_hash_ensure(&uwp_ps_hash);
        uwp_ps_node_t* node = uwp_ps_hash_find(&uwp_ps_hash, stmt_id);
        uwp_ps_slot_t* s = NULL;
        if (node) {
            /* Reuse existing slot — clear old bindings. */
            s = node->slot;
            uwp_ps_clear_bindings(s);
        } else {
            /* Allocate a new slot. */
            s = (uwp_ps_slot_t*)calloc(1, sizeof(uwp_ps_slot_t));
            if (!s) {
                pthread_mutex_unlock(&uwp_ps_hash.mutex);
                uwp_reply_cb(write_fn, write_ctx, "ERR_NO_SLOTS\n");
                return UWP_STS_ERR_FAILED;
            }
            uwp_ps_hash_insert(&uwp_ps_hash, stmt_id, s);
        }
        strncpy(s->sql, sql, UWP_PS_SQL_LEN - 1);
        s->sql[UWP_PS_SQL_LEN - 1] = '\0';
        s->valid = true;
        s->stmt_type = st;
        s->num_params = params;
        pthread_mutex_unlock(&uwp_ps_hash.mutex);

        uwp_text_buffer_t response = {0};
        (void)uwp_text_appendf(&response, "OK stmt_id=%u params=%d\n", stmt_id, params);
        uwp_write_cb(write_fn, write_ctx, response.data, response.len);
        uwp_text_destroy(&response);
        return UWP_STS_OK;
    }

    /* Legacy slot BIND has no typed/null representation. Only empty binds
     * remain supported; pgwire uses qihse_uwp_sql_execute_params. */
    if (command_opcode == 0x03) {
        if (!payload || payload_len < 4) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        uint32_t stmt_id = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                           ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        pthread_mutex_lock(&uwp_ps_hash.mutex);
        uwp_ps_node_t* node = uwp_ps_hash_find(&uwp_ps_hash, stmt_id);
        if (!node || !node->slot || !node->slot->valid) {
            pthread_mutex_unlock(&uwp_ps_hash.mutex);
            uwp_reply_cb(write_fn, write_ctx, "ERR_NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_ps_slot_t* s = node->slot;
        if (s->num_params || payload_len != 4) {
            pthread_mutex_unlock(&uwp_ps_hash.mutex);
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS; /* use typed execute_params instead */
        }
        uwp_ps_clear_bindings(s);
        pthread_mutex_unlock(&uwp_ps_hash.mutex);
        uwp_reply_cb(write_fn, write_ctx, "OK\n");
        return UWP_STS_OK;
    }

    /* --- CLOSE (0x05): release a prepared statement slot.
     * Payload: [4-byte LE stmt_id] --- */
    if (command_opcode == 0x05) {
        if (!payload || payload_len != 4) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        uint32_t stmt_id = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                           ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        pthread_mutex_lock(&uwp_ps_hash.mutex);
        uwp_ps_node_t* node = uwp_ps_hash_find(&uwp_ps_hash, stmt_id);
        if (!node || !node->slot) {
            pthread_mutex_unlock(&uwp_ps_hash.mutex);
            uwp_reply_cb(write_fn, write_ctx, "ERR_NOT_FOUND\n");
            return UWP_STS_ERR_FAILED;
        }
        uwp_ps_slot_t* s = node->slot;
        uwp_ps_clear_bindings(s);
        uwp_ps_slot_free(s);
        uwp_ps_hash_remove(&uwp_ps_hash, stmt_id);
        pthread_mutex_unlock(&uwp_ps_hash.mutex);
        uwp_reply_cb(write_fn, write_ctx, "OK\n");
        return UWP_STS_OK;
    }

    if (command_opcode != 0x02 && command_opcode != 0x04) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
        return UWP_STS_ERR_ARGS;
    }

    /* --- EXECUTE (0x02) / DESCRIBE (0x04) ---
     * EXECUTE is dual-mode: if the first 4 bytes of the payload encode a
     * valid, in-use prepared-statement slot ID, only parameter-free slots can
     * execute here. Typed parameter slots use qihse_uwp_sql_execute_params;
     * legacy untyped slots cannot safely represent NULL or type metadata.
     * Otherwise
     * the payload is treated as raw SQL text (backward compatible). */
    char* ps_sql = NULL;     /* unchanged SQL from a parameter-free slot */
    const char* sql = NULL;  /* SQL text to parse and execute */
    bool ps_active = false;

    if (command_opcode == 0x02 && payload && payload_len >= 4) {
        uint32_t stmt_id = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                           ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        pthread_mutex_lock(&uwp_ps_hash.mutex);
        uwp_ps_node_t* node = uwp_ps_hash_find(&uwp_ps_hash, stmt_id);
        if (node && node->slot && node->slot->valid) {
            ps_sql = node->slot->num_params ? NULL : strdup(node->slot->sql);
            pthread_mutex_unlock(&uwp_ps_hash.mutex);
            if (ps_sql) {
                sql = ps_sql;
                ps_active = true;
            } else {
                uwp_reply_cb(write_fn, write_ctx, "ERR_EXEC\n");
                return UWP_STS_ERR_FAILED;
            }
        } else {
            pthread_mutex_unlock(&uwp_ps_hash.mutex);
        }
    }

    if (!ps_active) {
        if (uwp_payload_string(payload, payload_len, &sql) != 0) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
    }

    qihse_sql_ast_t* ast = uwp_bound_ast ? uwp_bound_ast : qihse_parse_sql_to_ast(sql);
    if (!ast) {
        free(ps_sql);
        uwp_reply_cb(write_fn, write_ctx, "ERR_PARSE\n");
        return UWP_STS_ERR_FAILED;
    }
    /* Parsing UPSERT does not implement its uniqueness and conflict action.
     * Refuse before any row or column-store mutation, including prepared SQL. */
    if (command_opcode == 0x02 && ast->on_conflict) {
        if (ast != uwp_bound_ast) qihse_sql_ast_free(ast);
        free(ps_sql);
        uwp_reply_cb(write_fn, write_ctx, "ERR_EXEC\n");
        return UWP_STS_ERR_FAILED;
    }
    if (command_opcode == 0x02 && !uwp_sql_statement_allowed(ast, user)) {
        if (ast != uwp_bound_ast) qihse_sql_ast_free(ast);
        free(ps_sql);
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }

    uwp_sts_result_t result = UWP_STS_OK;
    size_t refresh_rows = 0;
    uwp_text_buffer_t response = {0};
    if (command_opcode == 0x04) {
        if (uwp_serialize_description(&response, ast) != 0) result = UWP_STS_ERR_FAILED;
    } else {
        /* Durable direct mutations cannot use the in-memory autocommit path. */
        if (qihse_uwp_sql_durable_ready(ctx) &&
            (ast->stmt_type == QIHSE_SQL_INSERT ||
             ast->stmt_type == QIHSE_SQL_UPDATE ||
             ast->stmt_type == QIHSE_SQL_DELETE) &&
            (!current_txn || !*current_txn))
            result = UWP_STS_ERR_FAILED;
        else result = uwp_sql_execute(ctx, ast, sql, current_txn, user,
                                      &refresh_rows);
        if (result != UWP_STS_OK && ast->stmt_type == QIHSE_SQL_REFRESH &&
            current_txn && *current_txn) {
            qihse_txn_t* failing = *current_txn;
            int rollback_rc = qihse_txn_rollback(
                (qihse_txn_manager_t*)ctx->txn_manager, failing);
            if (rollback_rc == 0 || failing->state != QIHSE_TXN_ACTIVE)
                *current_txn = NULL;
        }
        if (result == UWP_STS_OK && ast->stmt_type == QIHSE_SQL_SELECT) {
            if (uwp_sql_execute_select(ctx, ast, current_txn, user,
                                       &response) != 0)
                result = UWP_STS_ERR_FAILED;
        } else if (result == UWP_STS_OK &&
                   ast->stmt_type == QIHSE_SQL_WITH) {
            /* CTE and recursive CTE execution are not wired to an
             * authorization-aware row source. Refuse instead of reporting
             * the old empty-plan placeholder as a successful result. */
            result = UWP_STS_ERR_FAILED;
        }
        if (result == UWP_STS_OK && ast->stmt_type != QIHSE_SQL_SELECT &&
            ast->stmt_type != QIHSE_SQL_WITH) {
            if (ast->stmt_type == QIHSE_SQL_INSERT) {
                /* --- INSERT: row store is authoritative; the column-store
                 * append is the analytic copy and needs no ctx gate --- */
                if (!ctx->schema) {
                    uwp_text_appendf(&response,
                        "OK stmt_type=INSERT (no row store wired)\n");
                } else {
                    qihse_table_txn_t* table_txn = NULL;
                    if (current_txn && *current_txn) {
                        qihse_table_t* table = uwp_sql_row_table(
                            (qihse_schema_registry_t*)ctx->schema,
                            ast->table_name);
                        table_txn = uwp_sql_txn_table(*current_txn, table,
                                                      ast->table_name, ctx->schema, user, true);
                        if (!table_txn ||
                            qihse_txn_record_write(*current_txn, 2,
                                                   ast->table_name,
                                                   strlen(ast->table_name)) != 0) {
                            result = UWP_STS_ERR_FAILED;
                        }
                    }
                    int rows = result == UWP_STS_OK
                                   ? uwp_execute_insert(ctx, ast, table_txn, user)
                                   : -2;
                    if (rows == -3) result = UWP_STS_ERR_PERM;
                    if (rows == -4) result = UWP_STS_ERR_FAILED;
                    if (table_txn && rows != (int)ast->num_insert_rows) {
                        qihse_txn_t* failing = *current_txn;
                        int rollback_rc = qihse_txn_rollback(
                            (qihse_txn_manager_t*)ctx->txn_manager, failing);
                        if (rollback_rc == 0 || failing->state != QIHSE_TXN_ACTIVE)
                            *current_txn = NULL;
                        if (result != UWP_STS_ERR_PERM)
                            result = UWP_STS_ERR_FAILED;
                    }
                    if (result != UWP_STS_OK) {
                        /* The transaction was aborted above; the generic
                         * dispatcher error is emitted after AST cleanup. */
                    } else if (rows >= 0) {
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
            } else if (ast->stmt_type == QIHSE_SQL_UPDATE ||
                       ast->stmt_type == QIHSE_SQL_DELETE) {
                /* --- UPDATE / DELETE: execute against the mutable SQL row
                 * store (qihse_table_store).  The parsed SET assignments and
                 * the structured WHERE conditions are the only inputs; the
                 * raw SQL text is never re-parsed for execution.  The reply
                 * carries the number of rows actually changed, or states that
                 * the statement was refused and nothing changed. --- */
                qihse_table_store_t* store = qihse_uwp_sql_table_store();
                qihse_table_t* table = store
                    ? qihse_table_store_find_table(store, ast->table_name)
                    : NULL;
                qihse_table_txn_t* table_txn = NULL;
                if (current_txn && *current_txn) {
                    table_txn = uwp_sql_txn_table(*current_txn, table,
                                                  ast->table_name, ctx->schema, user, true);
                    if (!table_txn ||
                        qihse_txn_record_write(*current_txn, 2,
                                               ast->table_name,
                                               strlen(ast->table_name)) != 0)
                        result = UWP_STS_ERR_FAILED;
                }
                char* dml_reply = result == UWP_STS_OK
                    ? uwp_sql_execute_dml_on_table(ctx, ast, user, table, table_txn)
                    : NULL;
                if (!dml_reply) {
                    if (table_txn && current_txn && *current_txn) {
                        qihse_txn_t* failing = *current_txn;
                        int rollback_rc = qihse_txn_rollback(
                            (qihse_txn_manager_t*)ctx->txn_manager, failing);
                        if (rollback_rc == 0 || failing->state != QIHSE_TXN_ACTIVE)
                            *current_txn = NULL;
                    }
                    result = UWP_STS_ERR_FAILED;
                } else {
                    (void)uwp_text_appendf(&response, "%s", dml_reply);
                    free(dml_reply);
                }
            } else if (ast->stmt_type == QIHSE_SQL_CREATE_MATVIEW) {
                uwp_text_appendf(&response, "OK stmt_type=CREATE MATERIALIZED VIEW rows=%zu\n",
                                 refresh_rows);
            } else if (ast->stmt_type == QIHSE_SQL_REFRESH) {
                uwp_text_appendf(&response, "OK stmt_type=REFRESH rows=%zu\n",
                                 refresh_rows);
            } else {
                uwp_text_appendf(&response, "OK stmt_type=%s\n",
                                 qihse_sql_stmt_name(ast->stmt_type));
            }
        } else if (result != UWP_STS_OK && result != UWP_STS_ERR_PERM) {
            result = UWP_STS_ERR_FAILED;
        }
    }

    if (result == UWP_STS_OK) {
        uwp_write_cb(write_fn, write_ctx, response.data, response.len);
    } else if (result == UWP_STS_ERR_NO_CTX) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
    } else if (result == UWP_STS_ERR_PERM) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
    } else {
        uwp_reply_cb(write_fn, write_ctx, command_opcode == 0x02 ? "ERR_EXEC\n" : "ERR\n");
    }
    uwp_text_destroy(&response);
    free(ps_sql);
    if (ast != uwp_bound_ast) qihse_sql_ast_free(ast);
    return result;
}

uwp_sts_result_t uwp_dispatch_sql(qihse_uwp_context_t* ctx,
                                  uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user,
                                  int client_fd, qihse_uwp_write_fn write_fn,
                                  void* write_ctx) {
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    uwp_sts_result_t rc = uwp_dispatch_sql_locked(ctx, command_opcode, payload,
        payload_len, current_txn, user, client_fd, write_fn, write_ctx);
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return rc;
}

static uint32_t uwp_sql_pg_oid(qihse_sql_type_t type) {
    switch (type) {
        case QIHSE_TYPE_INT: case QIHSE_TYPE_SERIAL: return 23;
        case QIHSE_TYPE_BIGINT: case QIHSE_TYPE_BIGSERIAL: return 20;
        case QIHSE_TYPE_FLOAT: return 700;
        case QIHSE_TYPE_DOUBLE: return 701;
        case QIHSE_TYPE_TEXT: return 25;
        case QIHSE_TYPE_VARCHAR: return 1043;
        case QIHSE_TYPE_BOOL: return 16;
        case QIHSE_TYPE_UUID: return 2950;
        case QIHSE_TYPE_JSONB: return 3802;
        case QIHSE_TYPE_NUMERIC: return 1700;
        case QIHSE_TYPE_TIMESTAMPTZ: return 1184;
        case QIHSE_TYPE_TSVECTOR: return 3614;
        default: return 0;
    }
}

static const qihse_schema_column_t* uwp_sql_column_named(
    const qihse_schema_table_t* table, const char* name) {
    if (!table || !name) return NULL;
    const char* bare = strrchr(name, '.');
    if (bare) name = bare + 1;
    for (size_t i = 0; i < table->num_columns; ++i)
        if (table->columns[i].name && !strcasecmp(table->columns[i].name, name))
            return &table->columns[i];
    return NULL;
}

/* All metadata comes from the catalog, never a SELECT execution or sampled row. */
static uwp_sts_result_t uwp_sql_metadata_locked(qihse_uwp_context_t* ctx,
    const qihse_sql_ast_t* ast, qihse_user_t* user,
    const uint32_t* declared, size_t nparams, qihse_uwp_sql_metadata_t* meta) {
    if (!user || !qihse_auth_user_is_active(user) ||
        (ast && !uwp_sql_statement_allowed(ast, user))) return UWP_STS_ERR_PERM;
    if (!ctx || !ctx->sql_engine || !ctx->schema || !ast || !meta ||
        !qihse_uwp_sql_durable_ready(ctx)) return UWP_STS_ERR_NO_CTX;
    if (!qihse_sql_ast_parameters_valid(ast) ||
        qihse_sql_ast_parameter_count(ast) != nparams ||
        nparams > QIHSE_SQL_MAX_PARAMETERS || (nparams && !declared))
        return UWP_STS_ERR_ARGS;
    memset(meta, 0, sizeof(*meta));
    meta->nparams = nparams;
    if (ast->stmt_type != QIHSE_SQL_SELECT &&
        ast->stmt_type != QIHSE_SQL_INSERT &&
        ast->stmt_type != QIHSE_SQL_UPDATE &&
        ast->stmt_type != QIHSE_SQL_DELETE) {
        if (nparams) return UWP_STS_ERR_ARGS;
        switch (ast->stmt_type) {
            case QIHSE_SQL_BEGIN: case QIHSE_SQL_COMMIT: case QIHSE_SQL_ROLLBACK:
            case QIHSE_SQL_CREATE: case QIHSE_SQL_CREATE_EXTENSION:
            case QIHSE_SQL_CREATE_FUNCTION: case QIHSE_SQL_CREATE_TRIGGER:
            case QIHSE_SQL_DROP_TRIGGER: case QIHSE_SQL_CREATE_MATVIEW:
            case QIHSE_SQL_REFRESH:
                return UWP_STS_OK;
            default: return UWP_STS_ERR_FAILED;
        }
    }
    const qihse_schema_table_t* table = NULL;
    if (ast->stmt_type == QIHSE_SQL_SELECT) {
        if (ast->num_from_tables != 1 || ast->num_joins || ast->set_op ||
            !ast->from_tables || !ast->from_tables[0].table_name ||
            ast->select_distinct || !ast->num_select_items)
            return UWP_STS_ERR_FAILED;
        table = qihse_schema_get_table(ctx->schema,
                                       ast->from_tables[0].table_name);
    } else if (ast->table_name) table = qihse_schema_get_table(ctx->schema,
                                                               ast->table_name);
    if (!table || !table->columns) return UWP_STS_ERR_FAILED;
    uint32_t inferred[QIHSE_SQL_MAX_PARAMETERS] = {0};
#define UWP_INFER(index, column) do { \
    uint16_t k_ = (index); \
    uint32_t oid_ = uwp_sql_pg_oid((column)->type); \
    if (!k_ || k_ > nparams || !oid_ || \
        (inferred[k_ - 1] && inferred[k_ - 1] != oid_)) return UWP_STS_ERR_ARGS; \
    inferred[k_ - 1] = oid_; \
} while (0)
    if (ast->stmt_type == QIHSE_SQL_INSERT) {
        size_t cols = ast->num_insert_columns ? ast->num_insert_columns :
                      table->num_columns;
        if (cols > table->num_columns || !ast->insert_rows ||
            !ast->num_insert_rows || ast->insert_select_query ||
            ast->on_conflict || ast->returning)
            return UWP_STS_ERR_FAILED;
        for (size_t r = 0; r < ast->num_insert_rows; ++r) {
            if (!ast->insert_rows[r]) return UWP_STS_ERR_ARGS;
            size_t width = 0;
            while (width < cols && ast->insert_rows[r][width]) ++width;
            if (width != cols || ast->insert_rows[r][width]) return UWP_STS_ERR_ARGS;
            for (size_t c = 0; c < cols; ++c) {
                uint16_t idx = ast->insert_parameter_indexes &&
                    ast->insert_parameter_indexes[r] ?
                    ast->insert_parameter_indexes[r][c] : 0;
                if (!idx) continue;
                const qihse_schema_column_t* col = ast->num_insert_columns ?
                    uwp_sql_column_named(table, ast->insert_columns[c]) :
                    &table->columns[c];
                if (!col) return UWP_STS_ERR_ARGS;
                UWP_INFER(idx, col);
            }
        }
    } else if (ast->stmt_type == QIHSE_SQL_UPDATE) {
        for (size_t c = 0; c < ast->num_set; ++c) {
            uint16_t idx = ast->set_parameter_indexes ?
                ast->set_parameter_indexes[c] : 0;
            if (!idx) continue;
            const qihse_schema_column_t* col = uwp_sql_column_named(
                table, ast->set_columns[c]);
            if (!col) return UWP_STS_ERR_ARGS;
            UWP_INFER(idx, col);
        }
    }
    for (size_t c = 0; c < ast->num_where_conditions; ++c) {
        const qihse_sql_condition_t* cond = &ast->where_conditions[c];
        if (!cond->value_parameter_index) continue;
        const qihse_schema_column_t* col = uwp_sql_column_named(
            table, cond->column_name);
        if (!col) return UWP_STS_ERR_ARGS;
        UWP_INFER(cond->value_parameter_index, col);
    }
#undef UWP_INFER
    for (size_t i = 0; i < nparams; ++i) {
        bool text_compatible = (inferred[i] == 25 || inferred[i] == 1043) &&
            (declared[i] == 25 || declared[i] == 1043);
        /* A timestamp without time zone is assignable to timestamptz under
         * this SQL endpoint's UTC session timezone. Preserve the declared OID
         * so the pgwire client encodes its actual timestamp type. */
        bool timestamp_compatible = inferred[i] == 1184 && declared[i] == 1114;
        bool integer_compatible = (inferred[i] == 23 && declared[i] == 21) ||
            (inferred[i] == 20 && (declared[i] == 21 || declared[i] == 23));
        if (!inferred[i] || (declared[i] && declared[i] != inferred[i] &&
                             !text_compatible && !timestamp_compatible && !integer_compatible))
            return UWP_STS_ERR_ARGS;
        meta->param_oids[i] = declared[i] ? declared[i] : inferred[i];
    }
    if (ast->stmt_type == QIHSE_SQL_SELECT) {
        bool auth_aggregate = !strcasecmp(ast->from_tables[0].table_name,
            "auth_events") && (ast->group_by ||
            ast->select_items[0].agg_kind != QIHSE_AGG_NONE);
        if (auth_aggregate) {
            static const char* overall[] = {"total_attempts", "successful",
                                             "failed", "unique_ips"};
            static const char* grouped[] = {"ip_address", "attempts"};
            bool grouping = ast->group_by != NULL;
            const char* const* names = grouping ? grouped : overall;
            size_t n = grouping ? 2u : 4u;
            if (ast->num_select_items != n ||
                ast->num_where_conditions != (grouping ? 2u : 1u) ||
                !ast->where_conditions[0].column_name ||
                strcasecmp(ast->where_conditions[0].column_name, "created_at") ||
                !ast->where_conditions[0].operator ||
                strcmp(ast->where_conditions[0].operator, ">"))
                return UWP_STS_ERR_FAILED;
            for (size_t i = 0; i < n; ++i) {
                const qihse_sql_select_item_t* item = &ast->select_items[i];
                const char* name = item->alias;
                if (!name && grouping && i == 0 &&
                    item->agg_kind == QIHSE_AGG_NONE) name = item->expr;
                if (!name || strcmp(name, names[i])) return UWP_STS_ERR_FAILED;
                strcpy(meta->columns[i].name, names[i]);
                meta->columns[i].oid = grouping && i == 0 ? 1043 : 20;
            }
            meta->ncolumns = n;
            return UWP_STS_OK;
        }
        if (ast->group_by) return UWP_STS_ERR_FAILED;
        bool star = ast->num_select_items == 1 &&
            ast->select_items[0].expr &&
            strcmp(ast->select_items[0].expr, "*") == 0;
        size_t count = star ? table->num_columns : ast->num_select_items;
        if (!count || count > QIHSE_UWP_SQL_MAX_RESULT_COLUMNS)
            return UWP_STS_ERR_FAILED;
        for (size_t i = 0; i < count; ++i) {
            const qihse_sql_select_item_t* item = star ? NULL :
                &ast->select_items[i];
            if (item && (!item->expr || item->agg_kind != QIHSE_AGG_NONE ||
                         item->scalar_subquery || item->window ||
                         item->win_kind != QIHSE_WIN_NONE))
                return UWP_STS_ERR_FAILED;
            if (item) {
                const char* dot = strrchr(item->expr, '.');
                if (dot) {
                    size_t n = (size_t)(dot - item->expr);
                    const char* table_name = ast->from_tables[0].table_name;
                    const char* alias = ast->from_tables[0].alias;
                    if (!((strlen(table_name) == n &&
                           !strncasecmp(table_name, item->expr, n)) ||
                          (alias && strlen(alias) == n &&
                           !strncasecmp(alias, item->expr, n))))
                        return UWP_STS_ERR_FAILED;
                }
            }
            const qihse_schema_column_t* col = star ? &table->columns[i] :
                uwp_sql_column_named(table, item->expr);
            uint32_t oid = col ? uwp_sql_pg_oid(col->type) : 0;
            const char* name = item && item->alias ? item->alias :
                               col ? col->name : NULL;
            if (!oid || !name || strlen(name) >= sizeof(meta->columns[i].name))
                return UWP_STS_ERR_FAILED;
            strcpy(meta->columns[i].name, name);
            meta->columns[i].oid = (int32_t)oid;
        }
        meta->ncolumns = count;
    }
    return UWP_STS_OK;
}

uwp_sts_result_t qihse_uwp_sql_describe(qihse_uwp_context_t* ctx,
    const char* sql, qihse_user_t* user, const uint32_t* declared_oids,
    size_t nparams, qihse_uwp_sql_metadata_t* metadata) {
    if (!sql || !metadata || strlen(sql) >= UWP_PS_SQL_LEN)
        return UWP_STS_ERR_ARGS;
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(sql);
    if (!ast) return UWP_STS_ERR_FAILED;
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    uwp_sts_result_t result = uwp_sql_metadata_locked(ctx, ast, user,
        declared_oids, nparams, metadata);
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    qihse_sql_ast_free(ast);
    return result;
}

static uint64_t uwp_sql_be_uint(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

static char* uwp_sql_numeric_binary(const qihse_uwp_sql_param_t* param) {
    if (param->len < 8) return NULL;
    const uint8_t* data = param->data;
    unsigned count = (unsigned)uwp_sql_be_uint(data, 2);
    int weight = (int16_t)uwp_sql_be_uint(data + 2, 2);
    unsigned sign = (unsigned)uwp_sql_be_uint(data + 4, 2);
    unsigned scale = (unsigned)uwp_sql_be_uint(data + 6, 2);
    if (count > 1024 || param->len != 8u + 2u * count ||
        (sign != 0 && sign != 0x4000) || scale > 4096) return NULL;
    for (unsigned i = 0; i < count; ++i) {
        unsigned value = (unsigned)uwp_sql_be_uint(data + 8 + 2u * i, 2);
        if (value > 9999) return NULL;
        int exponent = weight - (int)i;
        if (value && exponent < -(int)((scale + 3u) / 4u)) return NULL;
        if (value && scale % 4u && exponent == -(int)((scale + 3u) / 4u)) {
            unsigned divisor = scale % 4u == 1 ? 1000 : scale % 4u == 2 ? 100 : 10;
            if (value % divisor) return NULL;
        }
    }
    if (!count) weight = 0;
    size_t integer_groups = weight > 0 ? (size_t)weight + 1u : 1u;
    size_t capacity = integer_groups * 4u + (scale ? 1u + scale : 0u) + (sign != 0);
    if (capacity > 4096) return NULL;
    char* text = malloc(capacity + 1u);
    if (!text) return NULL;
    size_t used = 0;
    if (sign) text[used++] = '-';
    for (int exponent = (int)integer_groups - 1; exponent >= 0; --exponent) {
        int index = weight - exponent;
        unsigned value = index >= 0 && (unsigned)index < count ?
            (unsigned)uwp_sql_be_uint(data + 8 + 2u * (unsigned)index, 2) : 0;
        int written = snprintf(text + used, capacity - used + 1u,
            exponent == (int)integer_groups - 1 ? "%u" : "%04u", value);
        if (written < 0 || (size_t)written > capacity - used) { free(text); return NULL; }
        used += (size_t)written;
    }
    if (scale) text[used++] = '.';
    for (unsigned offset = 0; offset < scale; offset += 4u) {
        int index = weight + 1 + (int)(offset / 4u);
        unsigned value = index >= 0 && (unsigned)index < count ?
            (unsigned)uwp_sql_be_uint(data + 8 + 2u * (unsigned)index, 2) : 0;
        char group[4] = {(char)('0' + value / 1000u),
            (char)('0' + value / 100u % 10u), (char)('0' + value / 10u % 10u),
            (char)('0' + value % 10u)};
        size_t take = scale - offset < 4u ? scale - offset : 4u;
        memcpy(text + used, group, take);
        used += take;
    }
    text[used] = '\0';
    return text;
}

/* Decode the pgwire value into an owned canonical scalar, never an SQL token.
 * The AST retains the source SQL and the parser's parameter-index metadata. */
static char* uwp_sql_param_text(const qihse_uwp_sql_param_t* p) {
    if (!p || p->format > 1 || p->len > QIHSE_UWP_SQL_MAX_BIND_BYTES ||
        (p->is_null && p->len) || (!p->is_null && !p->data)) return NULL;
    if (p->is_null) return strdup("");
    if (!p->format) {
        if (memchr(p->data, 0, p->len)) return NULL;
        char* text = malloc(p->len + 1);
        if (text) { memcpy(text, p->data, p->len); text[p->len] = 0; }
        if (text && p->oid == 16) {
            if (!strcasecmp(text, "t")) { free(text); return strdup("true"); }
            if (!strcasecmp(text, "f")) { free(text); return strdup("false"); }
        }
        return text;
    }
    char text[128];
    uint64_t bits;
    switch (p->oid) {
        case 1700:
            return uwp_sql_numeric_binary(p);
        case 25: case 1043:
            if (memchr(p->data, 0, p->len)) return NULL;
            return strndup((const char*)p->data, p->len);
        case 16:
            if (p->len != 1 || p->data[0] > 1) return NULL;
            return strdup(p->data[0] ? "true" : "false");
        case 21: case 23: case 20:
            if (p->len != (p->oid == 21 ? 2u : p->oid == 23 ? 4u : 8u)) return NULL;
            bits = uwp_sql_be_uint(p->data, p->len);
            if (p->oid == 21) snprintf(text, sizeof(text), "%d", (int16_t)bits);
            else if (p->oid == 23) snprintf(text, sizeof(text), "%d", (int32_t)bits);
            else snprintf(text, sizeof(text), "%lld", (long long)(int64_t)bits);
            return strdup(text);
        case 700: case 701: {
            if (p->len != (p->oid == 700 ? 4u : 8u)) return NULL;
            bits = uwp_sql_be_uint(p->data, p->len);
            if (p->oid == 700) {
                uint32_t v = (uint32_t)bits;
                float f;
                memcpy(&f, &v, sizeof(f));
                if (!isfinite(f)) return NULL;
                snprintf(text, sizeof(text), "%.9g", (double)f);
            } else {
                double f;
                memcpy(&f, &bits, sizeof(f));
                if (!isfinite(f) || (double)(float)f != f) return NULL;
                snprintf(text, sizeof(text), "%.9g", f);
            }
            return strdup(text);
        }
        case 2950:
            if (p->len != 16) return NULL;
            snprintf(text, sizeof(text),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                p->data[0],p->data[1],p->data[2],p->data[3],
                p->data[4],p->data[5],p->data[6],p->data[7],
                p->data[8],p->data[9],p->data[10],p->data[11],
                p->data[12],p->data[13],p->data[14],p->data[15]);
            return strdup(text);
        case 3802:
            if (p->len < 2 || p->data[0] != 1 ||
                memchr(p->data + 1, 0, p->len - 1)) return NULL;
            return strndup((const char*)p->data + 1, p->len - 1);
        case 1114: case 1184: {
            if (p->len != 8) return NULL;
            int64_t us = (int64_t)uwp_sql_be_uint(p->data, 8);
            int64_t seconds = us / INT64_C(1000000);
            int64_t fraction = us % INT64_C(1000000);
            if (fraction < 0) { --seconds; fraction += 1000000; }
            if (seconds > INT64_MAX - INT64_C(946684800) ||
                seconds < INT64_MIN + INT64_C(946684800)) return NULL;
            time_t epoch = (time_t)(seconds + INT64_C(946684800));
            struct tm tm;
            if (!gmtime_r(&epoch, &tm)) return NULL;
            snprintf(text, sizeof(text), "%04d-%02d-%02d %02d:%02d:%02d.%06lld+00",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, (long long)fraction);
            return strdup(text);
        }
        default: return NULL; /* no ambiguous binary reinterpretation */
    }
}

static bool uwp_sql_validate_bound(const qihse_schema_column_t* col,
    const qihse_uwp_sql_param_t* param, const char* text) {
    if (!col || !param || !text) return false;
    qihse_col_def_t def = {0};
    def.type = uwp_sql_type_to_ts_type(col->type);
    qihse_col_value_t value = {0};
    if (!uwp_sql_bound_value(&def, col, param, text, &value)) return false;
    if (!value.is_null && value.type == QIHSE_TS_FLOAT &&
        !isfinite(value.v.f32)) return false;
    if (value.type == QIHSE_TS_STRING || value.type == QIHSE_TS_UUID ||
        value.type == QIHSE_TS_JSONB || value.type == QIHSE_TS_NUMERIC ||
        value.type == QIHSE_TS_TSVECTOR) free(value.v.str);
    return true;
}

static bool uwp_sql_validate_params(qihse_uwp_context_t* ctx,
    const qihse_sql_ast_t* ast, const qihse_uwp_sql_param_t* params,
    char* const* values, size_t count) {
    if (!count) return true;
    const char* name = ast->stmt_type == QIHSE_SQL_SELECT ?
        ast->from_tables[0].table_name : ast->table_name;
    const qihse_schema_table_t* table = qihse_schema_get_table(ctx->schema, name);
    if (!table) return false;
    for (size_t i = 0; i < ast->num_where_conditions; ++i) {
        const qihse_sql_condition_t* cond = &ast->where_conditions[i];
        uint16_t n = cond->value_parameter_index;
        if (n) {
            const qihse_schema_column_t* column = uwp_sql_column_named(table, cond->column_name);
            if (!column || n > count) return false;
            if (column->type == QIHSE_TYPE_NUMERIC) {
                /* Comparisons do not assign into the column's precision/scale. */
                if (!params[n - 1].is_null &&
                    !qihse_ts_numeric_valid(values[n - 1], 0, 0)) return false;
            } else if (!uwp_sql_validate_bound(column, &params[n - 1], values[n - 1])) {
                return false;
            }
        }
    }
    for (size_t i = 0; i < ast->num_set; ++i) {
        uint16_t n = ast->set_parameter_indexes ? ast->set_parameter_indexes[i] : 0;
        if (n && (n > count || !uwp_sql_validate_bound(
            uwp_sql_column_named(table, ast->set_columns[i]),
            &params[n - 1], values[n - 1]))) return false;
    }
    size_t cols = ast->num_insert_columns ? ast->num_insert_columns :
                  table->num_columns;
    for (size_t r = 0; r < ast->num_insert_rows; ++r)
        for (size_t c = 0; c < cols; ++c) {
            uint16_t n = ast->insert_parameter_indexes &&
                ast->insert_parameter_indexes[r] ?
                ast->insert_parameter_indexes[r][c] : 0;
            if (n && (n > count || !uwp_sql_validate_bound(
                ast->num_insert_columns ? uwp_sql_column_named(table,
                ast->insert_columns[c]) : &table->columns[c],
                &params[n - 1], values[n - 1]))) return false;
        }
    return true;
}

static bool uwp_sql_replace_value(char** slot, const char* value) {
    if (!slot) return false;
    char* copy = strdup(value);
    if (!copy) return false;
    free(*slot);
    *slot = copy;
    return true;
}

static bool uwp_sql_bind_ast(qihse_sql_ast_t* ast, char* const* values,
                             size_t count) {
    if (!ast || !qihse_sql_ast_parameters_valid(ast) ||
        qihse_sql_ast_parameter_count(ast) != count) return false;
    for (size_t i = 0; i < ast->num_where_conditions; ++i) {
        qihse_sql_condition_t* cond = &ast->where_conditions[i];
        uint16_t n = cond->value_parameter_index;
        if (n && (n > count || !uwp_sql_replace_value(&cond->value, values[n - 1])))
            return false;
    }
    for (size_t i = 0; i < ast->num_set; ++i) {
        uint16_t n = ast->set_parameter_indexes ? ast->set_parameter_indexes[i] : 0;
        if (n && (n > count || !uwp_sql_replace_value(&ast->set_values[i], values[n - 1])))
            return false;
    }
    for (size_t r = 0; r < ast->num_insert_rows; ++r) {
        if (!ast->insert_rows || !ast->insert_rows[r]) return false;
        for (size_t c = 0; ast->insert_rows[r][c]; ++c) {
            uint16_t n = ast->insert_parameter_indexes &&
                ast->insert_parameter_indexes[r] ?
                ast->insert_parameter_indexes[r][c] : 0;
            if (n && (n > count ||
                !uwp_sql_replace_value(&ast->insert_rows[r][c], values[n - 1])))
                return false;
        }
    }
    return true;
}

uwp_sts_result_t qihse_uwp_sql_execute_params(qihse_uwp_context_t* ctx,
    const char* sql, const qihse_uwp_sql_param_t* params, size_t nparams,
    qihse_txn_t** current_txn, qihse_user_t* user,
    qihse_uwp_write_fn write_fn, void* write_ctx) {
    if (!sql || (nparams && !params) || nparams > QIHSE_SQL_MAX_PARAMETERS ||
        strlen(sql) >= UWP_PS_SQL_LEN) return UWP_STS_ERR_ARGS;
    qihse_sql_ast_t* ast = qihse_parse_sql_to_ast(sql);
    if (!ast) return UWP_STS_ERR_FAILED;
    uint32_t declared[QIHSE_SQL_MAX_PARAMETERS] = {0};
    char* values[QIHSE_SQL_MAX_PARAMETERS] = {0};
    qihse_uwp_sql_metadata_t meta;
    for (size_t i = 0; i < nparams; ++i) declared[i] = params[i].oid;
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    uwp_sts_result_t rc = uwp_sql_metadata_locked(ctx, ast, user,
        declared, nparams, &meta);
    if (rc == UWP_STS_OK) {
        for (size_t i = 0; i < nparams; ++i) {
            qihse_uwp_sql_param_t typed = params[i];
            typed.oid = meta.param_oids[i];
            values[i] = uwp_sql_param_text(&typed);
            if (!values[i]) { rc = UWP_STS_ERR_ARGS; break; }
        }
    }
    if (rc == UWP_STS_OK &&
        (!uwp_sql_validate_params(ctx, ast, params, values, nparams) ||
         !uwp_sql_bind_ast(ast, values, nparams)))
        rc = UWP_STS_ERR_ARGS;
    if (rc == UWP_STS_OK) {
        uwp_bound_ast = ast;
        uwp_bound_params = params;
        uwp_bound_count = nparams;
        rc = uwp_dispatch_sql_locked(ctx, 0x02, (const uint8_t*)sql,
            strlen(sql) + 1, current_txn, user, -1, write_fn, write_ctx);
        uwp_bound_ast = NULL;
        uwp_bound_params = NULL;
        uwp_bound_count = 0;
    }
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    if (ast) qihse_sql_ast_free(ast);
    for (size_t i = 0; i < nparams; ++i) free(values[i]);
    return rc;
}

uwp_sts_result_t qihse_uwp_sql_select_type_oids(qihse_uwp_context_t* ctx,
    const qihse_sql_ast_t* ast, qihse_user_t* user,
    const char* const* result_names, size_t count, int32_t* oids) {
    uwp_sts_result_t result = UWP_STS_ERR_FAILED;
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    if (!user || !qihse_auth_user_is_active(user)) {
        result = UWP_STS_ERR_PERM;
        goto done;
    }
    if (!ctx || !ctx->schema || !ast || !result_names || !oids ||
        ast->stmt_type != QIHSE_SQL_SELECT || ast->num_from_tables != 1 ||
        !ast->from_tables || !ast->from_tables[0].table_name ||
        ast->num_joins || ast->set_op != QIHSE_SET_NONE ||
        ast->select_distinct || !count || count > 64)
        goto done;
    const char* table_name = ast->from_tables[0].table_name;
    if (!qihse_auth_can_access_object(user, 0, (uint64_t)uwp_fnv1a(table_name),
                                      QIHSE_ACL_READ)) {
        result = UWP_STS_ERR_PERM;
        goto done;
    }
    const qihse_schema_table_t* table = qihse_schema_get_table(ctx->schema, table_name);
    qihse_table_t* row_table = uwp_sql_row_store ?
        qihse_table_store_find_table(uwp_sql_row_store, table_name) : NULL;
    if (!table || !table->columns || !table->num_columns || !row_table ||
        qihse_table_num_cols(row_table) != table->num_columns) goto done;
    for (size_t j = 0; j < table->num_columns; ++j) {
        const qihse_col_def_t* def = qihse_table_col_def(row_table, j);
        if (!def || !def->name || !table->columns[j].name ||
            strcasecmp(def->name, table->columns[j].name) != 0 ||
            def->type != uwp_sql_type_to_ts_type(table->columns[j].type))
            goto done;
    }
    bool star = ast->num_select_items == 1 && ast->select_items[0].expr &&
                strcmp(ast->select_items[0].expr, "*") == 0;
    if (count != (star ? table->num_columns : ast->num_select_items)) goto done;
    if (!strcasecmp(table_name, "auth_events") && ast->num_select_items &&
        (ast->group_by || ast->select_items[0].agg_kind != QIHSE_AGG_NONE)) {
        static const char* overall[] = {
            "total_attempts", "successful", "failed", "unique_ips"
        };
        static const char* grouped[] = { "ip_address", "attempts" };
        bool is_grouped = ast->group_by != NULL;
        const char* const* names = is_grouped ? grouped : overall;
        if (count != (is_grouped ? 2u : 4u) ||
            ast->num_select_items != count ||
            ast->num_where_conditions != (is_grouped ? 2u : 1u) ||
            !ast->where_conditions[0].column_name ||
            strcasecmp(ast->where_conditions[0].column_name, "created_at") ||
            !ast->where_conditions[0].operator ||
            strcmp(ast->where_conditions[0].operator, ">")) goto done;
        for (size_t i = 0; i < count; ++i) {
            const qihse_sql_select_item_t* item = &ast->select_items[i];
            const char* name = item->alias;
            if (!name && is_grouped && i == 0 && item->agg_kind == QIHSE_AGG_NONE)
                name = item->expr;
            if (!name || strcmp(name, names[i]) ||
                !result_names[i] || strcmp(result_names[i], names[i])) goto done;
            oids[i] = is_grouped && i == 0 ? 1043 : 20;
        }
        result = UWP_STS_OK;
        goto done;
    }
    if (ast->group_by) goto done;
    for (size_t i = 0; i < count; ++i) {
        const qihse_sql_select_item_t* item = star ? NULL : &ast->select_items[i];
        const qihse_schema_column_t* column = NULL;
        if (star) column = &table->columns[i];
        else {
            if (!item->expr || item->agg_kind != QIHSE_AGG_NONE ||
                item->scalar_subquery || item->window ||
                item->win_kind != QIHSE_WIN_NONE) goto done;
            const char* expr = item->expr;
            const char* dot = strrchr(expr, '.');
            if (dot) {
                size_t n = (size_t)(dot - expr);
                const char* alias = ast->from_tables[0].alias;
                if (!((strlen(table_name) == n &&
                       strncasecmp(expr, table_name, n) == 0) ||
                      (alias && strlen(alias) == n &&
                       strncasecmp(expr, alias, n) == 0))) goto done;
                expr = dot + 1;
            }
            for (size_t j = 0; j < table->num_columns; ++j)
                if (table->columns[j].name &&
                    strcasecmp(table->columns[j].name, expr) == 0) {
                    column = &table->columns[j];
                    break;
                }
        }
        const char* expected = item && item->alias && *item->alias ?
                               item->alias : column ? column->name : NULL;
        if (!column || !expected || !result_names[i] ||
            strcmp(expected, result_names[i]) != 0) goto done;
        switch (column->type) {
            case QIHSE_TYPE_INT: oids[i] = 23; break;
            case QIHSE_TYPE_BIGINT: oids[i] = 20; break;
            case QIHSE_TYPE_FLOAT: oids[i] = 700; break;
            case QIHSE_TYPE_DOUBLE: oids[i] = 701; break;
            case QIHSE_TYPE_TEXT: oids[i] = 25; break;
            case QIHSE_TYPE_VARCHAR: oids[i] = 1043; break;
            case QIHSE_TYPE_BOOL: oids[i] = 16; break;
            case QIHSE_TYPE_JSONB: oids[i] = 3802; break;
            case QIHSE_TYPE_UUID: oids[i] = 2950; break;
            case QIHSE_TYPE_TIMESTAMPTZ: oids[i] = 1184; break;
            case QIHSE_TYPE_NUMERIC: oids[i] = 1700; break;
            case QIHSE_TYPE_TSVECTOR: oids[i] = 3614; break;
            default: goto done;
        }
    }
    result = UWP_STS_OK;
done:
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return result;
}

static uwp_sts_result_t uwp_dispatch_txn_locked(qihse_uwp_context_t* ctx,
                                  uint8_t command_opcode,
                                  const uint8_t* payload, size_t payload_len,
                                  qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
                                  qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    if (!user || !qihse_auth_user_is_active(user)) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (!ctx || !ctx->txn_manager) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }

    if ((client_fd >= 0 || uwp_sql_durable_ctx) &&
        !qihse_uwp_sql_durable_ready(ctx)) {
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
            qihse_txn_t* finishing = *current_txn;
            if (command_opcode == 0x02 && finishing->resource_ctx) {
                uwp_sql_txn_resource_t* resource = finishing->resource_ctx;
                if (resource->magic == UWP_SQL_TXN_MAGIC) {
                    if (resource->ddl_changed &&
                        (resource->ddl_user_id != qihse_user_get_id(user) ||
                         resource->ddl_tenant_id != qihse_user_get_tenant_id(user) ||
                         qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR)) {
                        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
                        return UWP_STS_ERR_PERM;
                    }
                    for (size_t i = 0; i < resource->table_count; ++i) {
                        if (resource->tables[i].read_observed &&
                            !qihse_auth_can_access_object(user, 0,
                                (uint64_t)uwp_fnv1a(resource->tables[i].table_name),
                                QIHSE_ACL_READ)) {
                            uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
                            return UWP_STS_ERR_PERM;
                        }
                    }
                }
            }
            rc = command_opcode == 0x02
                     ? qihse_txn_commit(manager, finishing)
                     : qihse_txn_rollback(manager, finishing);
            /* Allocation failure can leave a rollbackable transaction active;
             * retain the handle in that case.  Successful completion and
             * conflict aborts clear it. */
            if (rc == 0 || finishing->state != QIHSE_TXN_ACTIVE)
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
            uwp_sql_txn_resource_t* resource = (*current_txn)->resource_ctx;
            if (resource && resource->magic == UWP_SQL_TXN_MAGIC &&
                resource->ddl_changed) {
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

uwp_sts_result_t uwp_dispatch_txn(qihse_uwp_context_t* ctx,
    uint8_t command_opcode, const uint8_t* payload, size_t payload_len,
    qihse_txn_t** current_txn, qihse_user_t* user, int client_fd,
    qihse_uwp_write_fn write_fn, void* write_ctx) {
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    uwp_sts_result_t rc = uwp_dispatch_txn_locked(ctx, command_opcode,
        payload, payload_len, current_txn, user, client_fd, write_fn, write_ctx);
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return rc;
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

static uwp_sts_result_t uwp_dispatch_schema_locked(qihse_uwp_context_t* ctx,
                                                   uint8_t command_opcode,
                                     const uint8_t* payload, size_t payload_len,
                                     qihse_user_t* user, int client_fd,
                                     qihse_uwp_write_fn write_fn, void* write_ctx) {
    (void)client_fd;
    if (!user || !qihse_auth_user_is_active(user)) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (!ctx || !ctx->schema) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_NO_CTX\n");
        return UWP_STS_ERR_NO_CTX;
    }
    if (uwp_sql_durable_ctx == ctx && command_opcode != 0x04) {
        uwp_reply_cb(write_fn, write_ctx, "ERR\n");
        return UWP_STS_ERR_FAILED;
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
    bool is_operator = qihse_user_get_role(user) == QIHSE_ROLE_OPERATOR;
    if (command_opcode != 0x04 && !is_operator) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
    if (command_opcode == 0x04 && !is_operator &&
        !qihse_auth_can_access_object(user, 0, (uint64_t)uwp_fnv1a(input),
                                      QIHSE_ACL_READ)) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_PERM\n");
        return UWP_STS_ERR_PERM;
    }
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
        if (uwp_sql_supported_create(ast, false))
            rc = qihse_schema_create_table(schema, ast);
    } else if (command_opcode == 0x03 && ast->stmt_type == QIHSE_SQL_ALTER &&
               ast->table_name && ast->alter_clause) {
        if (ast->alter_clause->action != QIHSE_ALTER_ADD_COLUMN ||
            (ast->alter_clause->add_column &&
             !ast->alter_clause->add_column->not_null &&
             !ast->alter_clause->add_column->is_primary_key &&
             !ast->alter_clause->add_column->is_unique &&
             !ast->alter_clause->add_column->fk &&
             !ast->alter_clause->add_column->check_expr &&
             !ast->alter_clause->add_column->default_expr &&
             !ast->alter_clause->add_column->is_serial))
            rc = qihse_schema_alter_table(schema, ast);
    } else if (command_opcode == 0x05 && ast->stmt_type == QIHSE_SQL_CREATE &&
               ast->index_def) {
        if (!ast->index_def->unique)
            rc = qihse_schema_create_index(schema, ast);
    }
    qihse_sql_ast_free(ast);
    uwp_reply_cb(write_fn, write_ctx, rc == 0 ? "OK\n" : "ERR\n");
    return rc == 0 ? UWP_STS_OK : UWP_STS_ERR_FAILED;
}

uwp_sts_result_t uwp_dispatch_schema(qihse_uwp_context_t* ctx,
                                     uint8_t command_opcode,
                                     const uint8_t* payload, size_t payload_len,
                                     qihse_user_t* user, int client_fd,
                                     qihse_uwp_write_fn write_fn, void* write_ctx) {
    pthread_mutex_lock(&uwp_sql_dispatch_mutex);
    uwp_sts_result_t rc = uwp_dispatch_schema_locked(ctx, command_opcode,
        payload, payload_len, user, client_fd, write_fn, write_ctx);
    pthread_mutex_unlock(&uwp_sql_dispatch_mutex);
    return rc;
}
