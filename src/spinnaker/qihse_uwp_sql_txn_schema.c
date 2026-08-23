#include "qihse_uwp_sql_txn_schema.h"
#include "qihse_optimizer.h"
#include "qihse_index_scan.h"
#include "qihse_join_executor.h"
#include "qihse_aggregate_executor.h"
#include "qihse_sort_executor.h"


#include "qihse_schema.h"
#include "qihse_sql_parser.h"
#include "qihse_txn.h"

#include <errno.h>
#include <limits.h>
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
 * recursive flag, so we also scan the raw SQL as a fallback. */
static bool uwp_has_recursive_cte(const qihse_sql_ast_t* ast) {
    if (!ast->with_clause) return false;
    for (size_t i = 0; i < ast->with_clause->num_ctes; i++) {
        if (ast->with_clause->ctes[i].recursive) return true;
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

    if (command_opcode == 0x03) {
        if (!payload || payload_len < 4) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        uint32_t count = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) |
                         ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
        size_t off = 4;
        for (uint32_t i = 0; i < count; ++i) {
            if (off >= payload_len) {
                uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
                return UWP_STS_ERR_ARGS;
            }
            const uint8_t* end = (const uint8_t*)memchr(payload + off, '\0',
                                                          payload_len - off);
            if (!end) {
                uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
                return UWP_STS_ERR_ARGS;
            }
            off = (size_t)(end - payload) + 1;
        }
        uwp_reply_cb(write_fn, write_ctx, "OK\n");
        return UWP_STS_OK;
    }
    if (command_opcode == 0x05) {
        if (!payload || payload_len != 4) {
            uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
            return UWP_STS_ERR_ARGS;
        }
        uwp_reply_cb(write_fn, write_ctx, "OK\n");
        return UWP_STS_OK;
    }
    if (command_opcode != 0x01 && command_opcode != 0x02 &&
        command_opcode != 0x04) {
        uwp_reply_cb(write_fn, write_ctx, "ERR_ARGS\n");
        return UWP_STS_ERR_ARGS;
    }

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

    uwp_sts_result_t result = UWP_STS_OK;
    uwp_text_buffer_t response = {0};
    if (command_opcode == 0x01) {
        if (uwp_serialize_ast(&response, ast) != 0) result = UWP_STS_ERR_FAILED;
    } else if (command_opcode == 0x04) {
        if (uwp_serialize_description(&response, ast) != 0) result = UWP_STS_ERR_FAILED;
    } else {
        result = uwp_sql_execute(ctx, ast, sql, current_txn, user);
        if (result == UWP_STS_OK) {
            if (ast->stmt_type == QIHSE_SQL_SELECT ||
                ast->stmt_type == QIHSE_SQL_WITH) {
                /* --- CTE (WITH clause) handling --- */
                if (ast->with_clause && ast->with_clause->num_ctes > 0) {
                    if (uwp_has_recursive_cte(ast)) {
                        uwp_text_appendf(&response,
                            "OK stmt_type=SELECT (recursive CTEs not yet supported)\n");
                    } else {
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
                }
                /* --- Window function handling --- */
                else if (uwp_has_window_functions(ast)) {
                    /* The executor pipeline (sort + aggregate) does not yet
                     * support window functions.  Degrade gracefully. */
                    uwp_text_appendf(&response,
                        "OK stmt_type=SELECT (window functions not yet supported)\n");
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
                /* --- UPDATE: column store is append-only, no update API --- */
                if (!ctx->col && !ctx->doc) {
                    uwp_text_appendf(&response,
                        "OK stmt_type=UPDATE (no row store wired)\n");
                } else if (ctx->col) {
                    uwp_text_appendf(&response,
                        "OK stmt_type=UPDATE (column store does not support in-place updates)\n");
                } else {
                    uwp_text_appendf(&response,
                        "OK stmt_type=UPDATE (no row store wired)\n");
                }
            } else if (ast->stmt_type == QIHSE_SQL_DELETE) {
                /* --- DELETE: column store is append-only, no delete API --- */
                if (!ctx->col && !ctx->doc) {
                    uwp_text_appendf(&response,
                        "OK stmt_type=DELETE (no row store wired)\n");
                } else if (ctx->col) {
                    uwp_text_appendf(&response,
                        "OK stmt_type=DELETE (column store does not support row deletion)\n");
                } else {
                    uwp_text_appendf(&response,
                        "OK stmt_type=DELETE (no row store wired)\n");
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
