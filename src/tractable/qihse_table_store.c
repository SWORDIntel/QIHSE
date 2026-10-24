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
    if (!table || !pred || !update_cols || !new_values || num_updates == 0)
        return -1;

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

qihse_table_txn_t* qihse_table_txn_begin(qihse_table_t* table) {
    if (!table) return NULL;
    qihse_table_txn_t* txn =
        (qihse_table_txn_t*)calloc(1, sizeof(*txn));
    if (!txn) return NULL;

    pthread_rwlock_rdlock(&table->lock);
    if (table->generation == UINT64_MAX) {
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
    txn->shadow.cols = table->cols;
    txn->shadow.num_cols = table->num_cols;
    txn->shadow.rows = rows;
    txn->shadow.num_rows = table->num_rows;
    txn->shadow.cap_rows = table->num_rows;
    txn->shadow.num_tomb = table->num_tomb;
    pthread_rwlock_unlock(&table->lock);
    return txn;
}

int qihse_table_txn_insert(qihse_table_txn_t* txn,
                           const qihse_col_value_t* values,
                           size_t num_values) {
    if (!txn || !values) return -1;
    qihse_table_t* shadow = &txn->shadow;
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
    return (int)slot;
}

static bool ts_assign_value(qihse_col_value_t* cell,
                            const qihse_col_value_t* value) {
    char* string_copy = NULL;
    if (value->type == QIHSE_TS_STRING && value->v.str) {
        string_copy = strdup(value->v.str);
        if (!string_copy) return false;
    }
    ts_free_col_value(cell);
    cell->type = value->type;
    switch (value->type) {
        case QIHSE_TS_INT32: cell->v.i32 = value->v.i32; break;
        case QIHSE_TS_INT64: cell->v.i64 = value->v.i64; break;
        case QIHSE_TS_FLOAT: cell->v.f32 = value->v.f32; break;
        case QIHSE_TS_STRING: cell->v.str = string_copy; break;
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
    return 1;
}

bool qihse_table_txn_delete(qihse_table_txn_t* txn,
                            int (*pred)(const qihse_col_value_t*, size_t,
                                        void*),
                            void* pred_ctx) {
    if (!txn || !pred) return false;
    qihse_table_t* shadow = &txn->shadow;
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

bool qihse_table_txn_commit_group(qihse_table_txn_t** txns, size_t count) {
    if (!txns || count == 0 || count > SIZE_MAX / sizeof(ts_group_item_t))
        return false;
    ts_group_item_t* items = (ts_group_item_t*)calloc(count, sizeof(*items));
    if (!items) {
        ts_group_destroy_unique(txns, count);
        return false;
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
        return false;
    }

    qsort(items, count, sizeof(*items), ts_group_item_cmp);
    for (size_t i = 0; i < count; ++i)
        pthread_rwlock_wrlock(&items[i].table->lock);

    for (size_t i = 0; i < count; ++i) {
        if (items[i].table->generation != items[i].txn->base_generation) {
            for (size_t j = count; j > 0; --j)
                pthread_rwlock_unlock(&items[j - 1].table->lock);
            ts_group_destroy_unique(txns, count);
            free(items);
            return false;
        }
    }

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

    for (size_t i = 0; i < count; ++i) {
        ts_free_rows(items[i].old_rows, items[i].old_num_rows,
                     items[i].table->num_cols);
        free(items[i].txn);
    }
    free(items);
    return true;
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
