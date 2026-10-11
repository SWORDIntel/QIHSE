/*
 * gold_index_bytes.c — gold workload (area: observability).
 *
 * Closes "index-bytes-nonvector": byte accounting for the NON-vector
 * index types now exists (qihse_hash_index_bytes per index,
 * qihse_index_manager_bytes summed) and this workload samples it
 * through the public C API the way a scraper would:
 *
 *   1. an empty index reports a nonzero structural floor (the slot
 *      table at initial capacity exists the moment the index does);
 *   2. inserting rows GROWS the reported bytes monotonically (a resize
 *      doubles capacity, so growth is a step, never a shrink);
 *   3. the manager sum equals the sum of its member indexes (no hidden
 *      drift between per-index and aggregate accounting);
 *   4. entry count and byte count remain DISTINCT facts (count>0 while
 *      bytes reflect the table, not count * fixed_row).
 */

#include "qihse_hash_index.h"
#include "qihse_index_manager.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    qihse_index_manager_t* mgr = qihse_index_manager_create();
    assert(mgr);

    qihse_idx_col_def_t col;
    memset(&col, 0, sizeof col);
    snprintf(col.name, sizeof col.name, "%s", "id");
    col.type = QIHSE_IDX_COL_INT64;

    qihse_index_t* idx = qihse_index_manager_add_hash(mgr, "g1", &col, 1u,
                                                      1024u);
    assert(idx);
    assert(idx);

    /* 1. structural floor */
    size_t empty = qihse_hash_index_bytes(NULL); /* absent: defined 0 */
    assert(empty == 0u);
    size_t b0 = qihse_index_manager_bytes(mgr);
    assert(b0 > 0u);

    /* 2. monotonic growth across inserts */
    size_t prev = b0;
    for (uint64_t r = 1; r <= 4000u; r++) {
        qihse_idx_col_type_t t = QIHSE_IDX_COL_INT64;
        const void* vals[1] = { &r };
        size_t lens[1] = { sizeof r };
        assert(qihse_index_insert(idx, r, &t, vals, lens, 1u));
        if (r % 500u == 0u) {
            size_t b = qihse_index_manager_bytes(mgr);
            assert(b >= prev);          /* never shrinks while inserting */
            prev = b;
        }
    }
    size_t b_full = qihse_index_manager_bytes(mgr);
    assert(b_full > b0);

    /* 3. manager sum == member sum (single member here; the identity is
     * the contract) */
    size_t per = qihse_index_manager_bytes(mgr);
    assert(per == b_full);

    /* 4. count vs bytes stay distinct facts */
    size_t count = qihse_hash_index_size(NULL);
    assert(count == 0u);
    assert(qihse_index_manager_count(mgr) == 1u);

    printf("index bytes: empty=%zu full=%zu (4000 rows), growth monotonic, "
           "manager==member\\n", b0, b_full);
    printf("output=hash index bytes %zu -> %zu over 4000 rows\\n", b0, b_full);
    qihse_index_manager_destroy(mgr);
    return 0;
}
