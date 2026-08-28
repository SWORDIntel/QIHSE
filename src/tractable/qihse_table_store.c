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

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal structures
 * ------------------------------------------------------------------------- */

struct qihse_table {
    char*               name;         /* owned */
    qihse_col_def_t*    cols;         /* array of num_defs column defs (owned) */
    size_t              num_cols;
    qihse_col_value_t** rows;         /* array of row pointers; NULL = tombstone */
    size_t              num_rows;     /* total slots (live + tombstone) */
    size_t              cap_rows;     /* allocated capacity */
    size_t              num_tomb;     /* number of tombstoned slots */
    pthread_rwlock_t    lock;
};

struct qihse_table_store {
    qihse_table_t**     tables;
    size_t              num_tables;
    size_t              cap_tables;
    pthread_mutex_t     mutex;        /* protects the table array */
};

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static void ts_free_col_value(qihse_col_value_t* v) {
    if (!v) return;
    if (v->type == QIHSE_TS_STRING) {
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
            row[i].type = values[i].type;
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
                case QIHSE_TS_STRING:
                    row[i].v.str = values[i].v.str
                        ? strdup(values[i].v.str) : NULL;
                    if (values[i].v.str && !row[i].v.str) {
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

/* -------------------------------------------------------------------------
 * Store lifecycle
 * ------------------------------------------------------------------------- */

qihse_table_store_t* qihse_table_store_create(void) {
    qihse_table_store_t* s =
        (qihse_table_store_t*)calloc(1, sizeof(qihse_table_store_t));
    if (!s) return NULL;
    pthread_mutex_init(&s->mutex, NULL);
    return s;
}

void qihse_table_store_destroy(qihse_table_store_t* store) {
    if (!store) return;
    pthread_mutex_lock(&store->mutex);
    for (size_t i = 0; i < store->num_tables; i++) {
        qihse_table_t* t = store->tables[i];
        if (!t) continue;
        for (size_t r = 0; r < t->num_rows; r++)
            ts_free_row(t->rows[r], t->num_cols);
        free(t->rows);
        for (size_t c = 0; c < t->num_cols; c++)
            free(t->cols[c].name);
        free(t->cols);
        free(t->name);
        pthread_rwlock_destroy(&t->lock);
        free(t);
    }
    free(store->tables);
    pthread_mutex_unlock(&store->mutex);
    pthread_mutex_destroy(&store->mutex);
    free(store);
}

/* -------------------------------------------------------------------------
 * Table management
 * ------------------------------------------------------------------------- */

qihse_table_t* qihse_table_store_create_table(qihse_table_store_t* store,
                                              const char* name,
                                              const qihse_col_def_t* cols,
                                              size_t num_cols) {
    if (!store || !name || !cols || num_cols == 0) return NULL;

    pthread_mutex_lock(&store->mutex);

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

    store->tables[store->num_tables++] = t;
    pthread_mutex_unlock(&store->mutex);
    return t;
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
    if (!table || !values) return -1;

    pthread_rwlock_wrlock(&table->lock);

    /* Find a free slot (reuse a tombstone if available). */
    size_t slot = table->num_rows;
    if (table->num_tomb > 0) {
        for (size_t i = 0; i < table->num_rows; i++) {
            if (table->rows[i] == NULL) {
                slot = i;
                table->num_tomb--;
                break;
            }
        }
    }

    if (slot >= table->num_rows) {
        if (!ts_ensure_cap(table, table->num_rows + 1)) {
            pthread_rwlock_unlock(&table->lock);
            return -1;
        }
        slot = table->num_rows;
        table->num_rows++;
    }

    qihse_col_value_t* row = ts_dup_row(values, num_values, table->num_cols);
    if (!row) {
        pthread_rwlock_unlock(&table->lock);
        return -1;
    }
    table->rows[slot] = row;

    pthread_rwlock_unlock(&table->lock);
    return (int)slot;
}

bool qihse_table_update(qihse_table_t* table,
                        int (*pred)(const qihse_col_value_t*, size_t, void*),
                        void* pred_ctx,
                        const int* update_cols,
                        const qihse_col_value_t* new_values,
                        size_t num_updates) {
    if (!table || !pred || !update_cols || !new_values || num_updates == 0)
        return false;

    pthread_rwlock_wrlock(&table->lock);
    bool any = false;
    for (size_t i = 0; i < table->num_rows; i++) {
        if (!table->rows[i]) continue;  /* tombstone */
        if (pred(table->rows[i], table->num_cols, pred_ctx)) {
            for (size_t u = 0; u < num_updates; u++) {
                int col = update_cols[u];
                if (col < 0 || (size_t)col >= table->num_cols) continue;
                qihse_col_value_t* cell = &table->rows[i][col];
                /* Free old string value. */
                ts_free_col_value(cell);
                cell->type = new_values[u].type;
                switch (new_values[u].type) {
                    case QIHSE_TS_INT32:
                        cell->v.i32 = new_values[u].v.i32;
                        break;
                    case QIHSE_TS_INT64:
                        cell->v.i64 = new_values[u].v.i64;
                        break;
                    case QIHSE_TS_FLOAT:
                        cell->v.f32 = new_values[u].v.f32;
                        break;
                    case QIHSE_TS_STRING:
                        cell->v.str = new_values[u].v.str
                            ? strdup(new_values[u].v.str) : NULL;
                        break;
                }
            }
            any = true;
        }
    }
    pthread_rwlock_unlock(&table->lock);
    return any;
}

bool qihse_table_delete(qihse_table_t* table,
                        int (*pred)(const qihse_col_value_t*, size_t, void*),
                        void* pred_ctx) {
    if (!table || !pred) return false;

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
