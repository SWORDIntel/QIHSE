#ifndef QIHSE_TABLE_STORE_H
#define QIHSE_TABLE_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Mutable Table Store
 *
 * A simple row-oriented mutable table store that supports INSERT, UPDATE,
 * DELETE, and SELECT with WHERE filtering.  Each table has a fixed schema
 * (column names + types) and a dynamic array of rows.  Rows are arrays of
 * typed column values.  String values are deep-copied on insert and freed
 * on delete.
 *
 * Thread-safety is provided by a pthread_rwlock per table: readers acquire
 * a read lock, writers (INSERT / UPDATE / DELETE) acquire a write lock.
 * ------------------------------------------------------------------------- */

/* Column value types. */
typedef enum {
    QIHSE_TS_INT32   = 0,
    QIHSE_TS_INT64   = 1,
    QIHSE_TS_FLOAT   = 2,   /* 32-bit float */
    QIHSE_TS_STRING  = 3    /* owned, NUL-terminated */
} qihse_ts_type_t;

/* A typed column value.  For QIHSE_TS_STRING, v.str is owned by the row. */
typedef struct {
    qihse_ts_type_t type;
    union {
        int32_t  i32;
        int64_t  i64;
        float    f32;
        char*    str;       /* owned (deep-copied on insert, freed on delete) */
    } v;
} qihse_col_value_t;

/* Column definition: name + type. */
typedef struct {
    char*           name;   /* owned */
    qihse_ts_type_t type;
} qihse_col_def_t;

/* Opaque table handle. */
typedef struct qihse_table qihse_table_t;

/* Opaque table store handle. */
typedef struct qihse_table_store qihse_table_store_t;

/* Row callback for scanning.  Return false to stop the scan. */
typedef bool (*qihse_table_row_cb)(const qihse_col_value_t* values,
                                   size_t num_cols, void* ctx);

/* --- Store lifecycle --------------------------------------------------- */

/* Create a new empty table store. */
qihse_table_store_t* qihse_table_store_create(void);

/* Destroy a table store and all its tables. */
void qihse_table_store_destroy(qihse_table_store_t* store);

/* --- Table management -------------------------------------------------- */

/* Create a new table in the store with the given name and column definitions.
 * Returns a pointer to the new table, or NULL on failure (duplicate name,
 * bad args, or OOM).  The column definitions are deep-copied. */
qihse_table_t* qihse_table_store_create_table(qihse_table_store_t* store,
                                              const char* name,
                                              const qihse_col_def_t* cols,
                                              size_t num_cols);

/* Find a table by name (case-sensitive).  Returns NULL if not found. */
qihse_table_t* qihse_table_store_find_table(qihse_table_store_t* store,
                                            const char* name);

/* --- Row operations ---------------------------------------------------- */

/* Insert a row into the table.  String values are deep-copied.
 * Returns the 0-based row id (>= 0) on success, -1 on failure. */
int qihse_table_insert(qihse_table_t* table,
                       const qihse_col_value_t* values, size_t num_values);

/* Update rows matching the predicate.  For each matching row, the columns
 * listed in update_cols are set to the corresponding new_values.
 *   pred         — predicate function; returns non-zero if the row matches.
 *   pred_ctx     — opaque context passed to the predicate.
 *   update_cols  — array of column indices to update.
 *   new_values   — new values for the listed columns (strings deep-copied).
 *   num_updates  — number of entries in update_cols / new_values.
 * Returns true if at least one row was updated, false otherwise. */
bool qihse_table_update(qihse_table_t* table,
                        int (*pred)(const qihse_col_value_t* values,
                                    size_t num_cols, void* ctx),
                        void* pred_ctx,
                        const int* update_cols,
                        const qihse_col_value_t* new_values,
                        size_t num_updates);

/* Delete rows matching the predicate.  Matching rows are tombstoned and
 * the table is compacted periodically.
 *   pred     — predicate function; returns non-zero if the row matches.
 *   pred_ctx — opaque context passed to the predicate.
 * Returns true if at least one row was deleted, false otherwise. */
bool qihse_table_delete(qihse_table_t* table,
                        int (*pred)(const qihse_col_value_t* values,
                                    size_t num_cols, void* ctx),
                        void* pred_ctx);

/* --- Queries ----------------------------------------------------------- */

/* Return the number of live (non-deleted) rows in the table. */
size_t qihse_table_row_count(const qihse_table_t* table);

/* Scan all live rows in the table, calling cb for each.  The callback
 * receives a pointer to the row's values (valid only during the callback).
 * Return false from the callback to stop the scan. */
void qihse_table_scan(const qihse_table_t* table,
                      qihse_table_row_cb cb, void* ctx);

/* --- Introspection ----------------------------------------------------- */

/* Return the number of columns in the table. */
size_t qihse_table_num_cols(const qihse_table_t* table);

/* Return the column definition at index idx, or NULL if out of range. */
const qihse_col_def_t* qihse_table_col_def(const qihse_table_t* table,
                                           size_t idx);

/* Find a column index by name (case-sensitive).  Returns -1 if not found. */
int qihse_table_find_col(const qihse_table_t* table, const char* name);

/* Return the table name. */
const char* qihse_table_name(const qihse_table_t* table);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_TABLE_STORE_H */
