#define _GNU_SOURCE
/* qihse_index_scan.c — Phase 3.5 index scan executor operator.
 *
 * Wraps B+ tree range/prefix cursors and hash equality lookups behind a
 * uniform iterator interface that can feed other executors.
 */
#include "qihse_index_scan.h"
#include "qihse_platform.h"

#include <stdlib.h>
#include <string.h>

struct qihse_index_scan {
    qihse_index_t* idx;
    /* For BTREE: an active cursor. */
    qihse_btree_cursor_t* btree_cur;
    /* For HASH: single-shot equality result. */
    bool hash_done;
    uint64_t hash_row_id;
    /* For wrapped (HNSW/FTS): not supported for row-id scans; we return empty. */
    bool exhausted;
};

qihse_index_scan_t* qihse_index_scan_open(qihse_index_t* idx,
                                          const qihse_scan_pred_t* pred) {
    if (!idx || !pred) return NULL;
    qihse_index_scan_t* s = (qihse_index_scan_t*)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->idx = idx;
    s->exhausted = false;
    s->btree_cur = NULL;
    s->hash_done = false;

    qihse_index_type_t type = qihse_index_type(idx);

    if (type == QIHSE_INDEX_BTREE) {
        qihse_btree_t* bt = qihse_index_btree(idx);
        if (!bt) { free(s); return NULL; }
        switch (pred->kind) {
            case QIHSE_SCAN_EQ:
                s->btree_cur = qihse_btree_range_open(bt,
                                                      pred->eq_key, pred->eq_key_len,
                                                      pred->eq_key, pred->eq_key_len);
                break;
            case QIHSE_SCAN_RANGE:
                s->btree_cur = qihse_btree_range_open(bt,
                                                      pred->min_key, pred->min_len,
                                                      pred->max_key, pred->max_len);
                break;
            case QIHSE_SCAN_PREFIX:
                s->btree_cur = qihse_btree_prefix_open(bt,
                                                       pred->prefix_key,
                                                       pred->prefix_len);
                break;
            default:
                free(s);
                return NULL;
        }
        if (!s->btree_cur) { free(s); return NULL; }
    } else if (type == QIHSE_INDEX_HASH) {
        /* Hash only supports EQ. */
        if (pred->kind != QIHSE_SCAN_EQ) { free(s); return NULL; }
        qihse_hash_index_t* hi = qihse_index_hash(idx);
        if (!hi) { free(s); return NULL; }
        if (!qihse_hash_index_lookup(hi, pred->eq_key, pred->eq_key_len,
                                     &s->hash_row_id)) {
            free(s);
            return NULL;
        }
        s->hash_done = false;
    } else {
        /* HNSW/FTS: not applicable for row-id predicate scans. */
        s->exhausted = true;
    }
    return s;
}

bool qihse_index_scan_next(qihse_index_scan_t* scan,
                           uint64_t* out_buf, size_t cap,
                           size_t* out_count) {
    if (!scan || !out_buf || !out_count || cap == 0) return false;
    *out_count = 0;

    if (scan->exhausted) return false;

    qihse_index_type_t type = qihse_index_type(scan->idx);

    if (type == QIHSE_INDEX_BTREE && scan->btree_cur) {
        size_t written = 0;
        const void* key; size_t klen; uint64_t rid;
        while (written < cap) {
            if (!qihse_btree_cursor_get(scan->btree_cur, &key, &klen, &rid))
                break;
            out_buf[written++] = rid;
            if (!qihse_btree_cursor_next(scan->btree_cur))
                break;
        }
        *out_count = written;
        if (written == 0) { scan->exhausted = true; return false; }
        return true;
    }

    if (type == QIHSE_INDEX_HASH) {
        if (scan->hash_done) { scan->exhausted = true; return false; }
        out_buf[0] = scan->hash_row_id;
        *out_count = 1;
        scan->hash_done = true;
        return true;
    }

    /* Wrapped or unknown: empty. */
    scan->exhausted = true;
    return false;
}

bool qihse_index_scan_all(qihse_index_scan_t* scan,
                          uint64_t** out_buf, size_t* out_count) {
    if (!scan || !out_buf || !out_count) return false;
    *out_buf = NULL;
    *out_count = 0;

    size_t cap = 256;
    uint64_t* buf = (uint64_t*)malloc(cap * sizeof(uint64_t));
    if (!buf) return false;
    size_t total = 0;

    for (;;) {
        if (total >= cap) {
            cap *= 2;
            uint64_t* nb = (uint64_t*)realloc(buf, cap * sizeof(uint64_t));
            if (!nb) { free(buf); return false; }
            buf = nb;
        }
        size_t batch;
        if (!qihse_index_scan_next(scan, buf + total, cap - total, &batch)) {
            if (batch > 0) total += batch;
            break;
        }
        total += batch;
    }

    if (total == 0) { free(buf); return false; }
    *out_buf = buf;
    *out_count = total;
    return true;
}

void qihse_index_scan_close(qihse_index_scan_t* scan) {
    if (!scan) return;
    if (scan->btree_cur) qihse_btree_cursor_close(scan->btree_cur);
    free(scan);
}

bool qihse_index_scan_eq(qihse_index_t* idx,
                         const void* key, size_t key_len,
                         uint64_t* row_id_out) {
    if (!idx || !key) return false;
    qihse_index_type_t type = qihse_index_type(idx);
    if (type == QIHSE_INDEX_BTREE) {
        return qihse_btree_lookup(qihse_index_btree(idx), key, key_len, row_id_out);
    } else if (type == QIHSE_INDEX_HASH) {
        return qihse_hash_index_lookup(qihse_index_hash(idx), key, key_len,
                                       row_id_out);
    }
    return false;
}
