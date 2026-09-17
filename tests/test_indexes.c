/*
 * test_indexes.c — secondary indexes: B+ tree, hash index, index manager,
 * index-scan executor and wrapped (HNSW/FTS) registrations.
 *
 * Exercises the sources the secondary-index document describes:
 *   src/frieze/qihse_btree.c          — page-conscious B+ tree, composite keys
 *   src/frieze/qihse_hash_index.c     — open-addressed hash with tombstones
 *   src/frieze/qihse_index_manager.c  — per-table index registry
 *   src/tractable/qihse_index_scan.c  — uniform scan operator
 *
 *   1.  B+ tree insert/lookup, fanout=8 (forces node splits), replace, size
 *   2.  B+ tree range scan over serialized keys (ordering and bounds)
 *   3.  B+ tree delete (present and absent keys)
 *   4.  B+ tree string keys plus a string range scan
 *   5.  Composite key serialization: int64 / float64 / string sort order
 *   6.  Composite prefix matching (a=? then a=? AND b=?)
 *   7.  Hash index insert/lookup across a resize (load factor > 0.7)
 *   8.  Hash index string keys
 *   9.  Hash index delete and tombstone slot reuse
 *   10. Index manager: add, count, find by name, insert_row
 *   11. Index manager: drop
 *   12. Index scan executor: EQ / RANGE / PREFIX, batch iteration
 *   13. Bulk load (sort-then-build) from an unsorted array
 *   14. Wrapped (HNSW/FTS) index registration through the vtable
 *
 * Not covered here, and not claimed by the document: qihse_index_bulk_load()
 * on a non-BTREE handle dereferences idx->btree (NULL for hash indexes), so
 * only the BTREE path is exercised below.
 */
#include "qihse_btree.h"
#include "qihse_hash_index.h"
#include "qihse_index_manager.h"
#include "qihse_index_scan.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INT64_KEY(v) (&(int64_t){(int64_t)(v)})

/* ── 1. B+ tree insert / lookup ─────────────────────────────────────────── */

static void test_btree_insert_lookup(void) {
    /* fanout=8 forces splits with 100 entries. */
    qihse_btree_t* tree = qihse_btree_create(8);
    assert(tree);
    assert(qihse_btree_size(tree) == 0);

    for (int64_t i = 0; i < 100; i++) {
        int64_t k = i * 3;
        assert(qihse_btree_insert(tree, &k, sizeof(k), (uint64_t)(1000 + i)));
    }
    assert(qihse_btree_size(tree) == 100);

    for (int64_t i = 0; i < 100; i++) {
        int64_t k = i * 3;
        uint64_t rid = 0;
        assert(qihse_btree_lookup(tree, &k, sizeof(k), &rid));
        assert(rid == (uint64_t)(1000 + i));
    }
    /* Keys that were never inserted. */
    for (int64_t i = 0; i < 100; i++) {
        int64_t k = i * 3 + 1;
        uint64_t rid = 0;
        assert(!qihse_btree_lookup(tree, &k, sizeof(k), &rid));
    }

    /* Re-inserting a key replaces the row id without growing the tree. */
    int64_t dup = 42;
    assert(qihse_btree_insert(tree, &dup, sizeof(dup), 77777));
    uint64_t rid = 0;
    assert(qihse_btree_lookup(tree, &dup, sizeof(dup), &rid));
    assert(rid == 77777);
    assert(qihse_btree_size(tree) == 100);

    qihse_btree_destroy(tree);
    printf("PASS btree insert/lookup: 100 keys at fanout=8, replace semantics\n");
}

/* ── 2. B+ tree range scan ──────────────────────────────────────────────── */

static void test_btree_range_scan(void) {
    qihse_btree_t* tree = qihse_btree_create(16);
    assert(tree);
    for (int64_t i = 0; i < 50; i++) {
        assert(qihse_btree_insert(tree, &i, sizeof(i), (uint64_t)(i * 10)));
    }

    int64_t lo = 10, hi = 19;
    qihse_btree_cursor_t* cur = qihse_btree_range_open(tree, &lo, sizeof(lo),
                                                       &hi, sizeof(hi));
    assert(cur);
    int seen = 0;
    int64_t expect = 10;
    const void* key = NULL;
    size_t klen = 0;
    uint64_t rid = 0;
    while (qihse_btree_cursor_get(cur, &key, &klen, &rid)) {
        assert(klen == sizeof(int64_t));
        int64_t got = 0;
        memcpy(&got, key, sizeof(got));
        assert(got == expect);
        assert(rid == (uint64_t)(got * 10));
        seen++;
        expect++;
        if (!qihse_btree_cursor_next(cur)) break;
    }
    assert(seen == 10);
    qihse_btree_cursor_close(cur);

    /* Open-ended lower bound: everything up to and including 4. */
    int64_t top = 4;
    cur = qihse_btree_range_open(tree, NULL, 0, &top, sizeof(top));
    assert(cur);
    seen = 0;
    while (qihse_btree_cursor_get(cur, &key, &klen, &rid)) {
        seen++;
        if (!qihse_btree_cursor_next(cur)) break;
    }
    assert(seen == 5);
    qihse_btree_cursor_close(cur);

    /* An empty range yields no cursor at all. */
    int64_t empty_lo = 200, empty_hi = 300;
    assert(qihse_btree_range_open(tree, &empty_lo, sizeof(empty_lo),
                                  &empty_hi, sizeof(empty_hi)) == NULL);
    qihse_btree_destroy(tree);
    printf("PASS btree range scan: bounded, open-ended and empty ranges\n");
}

/* ── 3. B+ tree delete ──────────────────────────────────────────────────── */

static void test_btree_delete(void) {
    qihse_btree_t* tree = qihse_btree_create(8);
    assert(tree);
    for (int64_t i = 0; i < 40; i++) {
        assert(qihse_btree_insert(tree, &i, sizeof(i), (uint64_t)(i + 1)));
    }

    uint64_t removed = 0;
    int64_t k = 7;
    assert(qihse_btree_delete(tree, &k, sizeof(k), &removed));
    assert(removed == 8);
    assert(qihse_btree_size(tree) == 39);
    uint64_t rid = 0;
    assert(!qihse_btree_lookup(tree, &k, sizeof(k), &rid));
    /* Neighbours survive. */
    int64_t before = 6, after = 8;
    assert(qihse_btree_lookup(tree, &before, sizeof(before), &rid) && rid == 7);
    assert(qihse_btree_lookup(tree, &after, sizeof(after), &rid) && rid == 9);

    /* Deleting it twice reports absence the second time. */
    assert(!qihse_btree_delete(tree, &k, sizeof(k), &removed));
    assert(!qihse_btree_delete(tree, INT64_KEY(999), sizeof(int64_t), NULL));

    /* Delete every remaining key; the tree drains to empty. */
    for (int64_t i = 0; i < 40; i++) {
        if (i == 7) continue;
        assert(qihse_btree_delete(tree, &i, sizeof(i), NULL));
    }
    assert(qihse_btree_size(tree) == 0);
    assert(qihse_btree_range_open(tree, NULL, 0, NULL, 0) == NULL);

    qihse_btree_destroy(tree);
    printf("PASS btree delete: row-id out, idempotence, drain to empty\n");
}

/* ── 4. B+ tree string keys ─────────────────────────────────────────────── */

static void test_btree_string_keys(void) {
    static const char* words[] = {"delta", "alpha", "echo", "bravo", "charlie"};
    qihse_btree_t* tree = qihse_btree_create(8);
    assert(tree);
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        assert(qihse_btree_insert(tree, words[i], strlen(words[i]), i + 1));
    }
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        uint64_t rid = 0;
        assert(qihse_btree_lookup(tree, words[i], strlen(words[i]), &rid));
        assert(rid == i + 1);
    }

    /* Scan "bravo".."echo" and check byte ordering. */
    qihse_btree_cursor_t* cur = qihse_btree_range_open(tree, "bravo", 5,
                                                       "echo", 4);
    assert(cur);
    const void* key = NULL;
    size_t klen = 0;
    uint64_t rid = 0;
    const char* expect[] = {"bravo", "charlie", "delta", "echo"};
    int n = 0;
    while (qihse_btree_cursor_get(cur, &key, &klen, &rid)) {
        assert(n < 4);
        assert(klen == strlen(expect[n]));
        assert(memcmp(key, expect[n], klen) == 0);
        n++;
        if (!qihse_btree_cursor_next(cur)) break;
    }
    assert(n == 4);
    qihse_btree_cursor_close(cur);

    qihse_btree_destroy(tree);
    printf("PASS btree string keys: ordering and range scan over UTF-8 bytes\n");
}

/* ── 5. Composite key serialization ─────────────────────────────────────── */

static void test_composite_serialization(void) {
    /* int64: negatives sort before positives. */
    int64_t neg = -5, pos = 5, zero = 0;
    qihse_btree_col_t a = {QIHSE_BTREE_COL_INT64, &neg, 0};
    qihse_btree_col_t b = {QIHSE_BTREE_COL_INT64, &zero, 0};
    qihse_btree_col_t c = {QIHSE_BTREE_COL_INT64, &pos, 0};
    void *ka = NULL, *kb = NULL, *kc = NULL;
    size_t la = 0, lb = 0, lc = 0;
    assert(qihse_btree_serialize_key_alloc(&a, 1, &ka, &la) == 0);
    assert(qihse_btree_serialize_key_alloc(&b, 1, &kb, &lb) == 0);
    assert(qihse_btree_serialize_key_alloc(&c, 1, &kc, &lc) == 0);
    assert(la == 8 && lb == 8 && lc == 8);
    assert(memcmp(ka, kb, 8) < 0);
    assert(memcmp(kb, kc, 8) < 0);

    /* float64: -1.5 < 0.0 < 2.5 after the sortable transform. */
    double fneg = -1.5, fzero = 0.0, fpos = 2.5;
    qihse_btree_col_t fa = {QIHSE_BTREE_COL_FLOAT64, &fneg, 0};
    qihse_btree_col_t fb = {QIHSE_BTREE_COL_FLOAT64, &fzero, 0};
    qihse_btree_col_t fc = {QIHSE_BTREE_COL_FLOAT64, &fpos, 0};
    void *fka = NULL, *fkb = NULL, *fkc = NULL;
    size_t fla = 0, flb = 0, flc = 0;
    assert(qihse_btree_serialize_key_alloc(&fa, 1, &fka, &fla) == 0);
    assert(qihse_btree_serialize_key_alloc(&fb, 1, &fkb, &flb) == 0);
    assert(qihse_btree_serialize_key_alloc(&fc, 1, &fkc, &flc) == 0);
    assert(memcmp(fka, fkb, 8) < 0);
    assert(memcmp(fkb, fkc, 8) < 0);

    /* string: a shorter prefix sorts before its extension. */
    qihse_btree_col_t s1 = {QIHSE_BTREE_COL_STRING, "ab", 2};
    qihse_btree_col_t s2 = {QIHSE_BTREE_COL_STRING, "abc", 3};
    void* ks1 = NULL;
    void* ks2 = NULL;
    size_t ls1 = 0, ls2 = 0;
    assert(qihse_btree_serialize_key_alloc(&s1, 1, &ks1, &ls1) == 0);
    assert(qihse_btree_serialize_key_alloc(&s2, 1, &ks2, &ls2) == 0);
    assert(ls1 == 3 && ls2 == 4);
    assert(memcmp(ks1, ks2, ls1) < 0);

    /* Multi-column: (int64, string) keeps the column order in the bytes. */
    int64_t col0 = 7;
    qihse_btree_col_t mcols[2] = {
        {QIHSE_BTREE_COL_INT64, &col0, 0},
        {QIHSE_BTREE_COL_STRING, "tag", 3}
    };
    void* mk = NULL;
    size_t ml = 0;
    assert(qihse_btree_serialize_key_alloc(mcols, 2, &mk, &ml) == 0);
    assert(ml == 8 + 3 + 1);
    /* The first column's encoding is the prefix of the composite key. */
    qihse_btree_col_t mfirst = {QIHSE_BTREE_COL_INT64, &col0, 0};
    void* mfk = NULL;
    size_t mfl = 0;
    assert(qihse_btree_serialize_key_alloc(&mfirst, 1, &mfk, &mfl) == 0);
    assert(mfl == 8);
    assert(memcmp(mk, mfk, 8) == 0);
    free(mfk);

    /* Sizing query and capacity failure. */
    size_t need = 0;
    assert(qihse_btree_serialize_key(mcols, 2, NULL, &need) == 0);
    assert(need == ml);
    size_t too_small = 4;
    assert(qihse_btree_serialize_key(mcols, 2, mk, &too_small) == -1);
    assert(too_small == ml);

    free(ka); free(kb); free(kc);
    free(fka); free(fkb); free(fkc);
    free(ks1); free(ks2); free(mk);
    printf("PASS composite serialization: int64, float64 and string sort order\n");
}

/* ── 6. Composite prefix matching ───────────────────────────────────────── */

static void test_composite_prefix_match(void) {
    qihse_btree_t* tree = qihse_btree_create(8);
    assert(tree);

    /* Index on (a, b, c) for a in {1,2}, b in {1,2}, c in {1,2}. */
    for (int64_t a = 1; a <= 2; a++) {
        for (int64_t b = 1; b <= 2; b++) {
            for (int64_t c = 1; c <= 2; c++) {
                qihse_btree_col_t cols[3] = {
                    {QIHSE_BTREE_COL_INT64, &a, 0},
                    {QIHSE_BTREE_COL_INT64, &b, 0},
                    {QIHSE_BTREE_COL_INT64, &c, 0}
                };
                void* key = NULL;
                size_t klen = 0;
                assert(qihse_btree_serialize_key_alloc(cols, 3, &key, &klen) == 0);
                assert(qihse_btree_insert(tree, key, klen,
                                          (uint64_t)(a * 100 + b * 10 + c)));
                free(key);
            }
        }
    }
    assert(qihse_btree_size(tree) == 8);

    /* Prefix length 1: a = 1 -> 4 rows. */
    int64_t a1 = 1;
    qihse_btree_col_t p1 = {QIHSE_BTREE_COL_INT64, &a1, 0};
    void* pkey = NULL;
    size_t plen = 0;
    assert(qihse_btree_serialize_key_alloc(&p1, 1, &pkey, &plen) == 0);
    qihse_btree_cursor_t* cur = qihse_btree_prefix_open(tree, pkey, plen);
    assert(cur);
    int n = 0;
    uint64_t rid = 0;
    while (qihse_btree_cursor_get(cur, NULL, NULL, &rid)) {
        assert(rid / 100 == 1);
        n++;
        if (!qihse_btree_cursor_next(cur)) break;
    }
    assert(n == 4);
    qihse_btree_cursor_close(cur);
    free(pkey);

    /* Prefix length 2: a = 1 AND b = 2 -> 2 rows. */
    int64_t b2 = 2;
    qihse_btree_col_t p2[2] = {
        {QIHSE_BTREE_COL_INT64, &a1, 0},
        {QIHSE_BTREE_COL_INT64, &b2, 0}
    };
    assert(qihse_btree_serialize_key_alloc(p2, 2, &pkey, &plen) == 0);
    cur = qihse_btree_prefix_open(tree, pkey, plen);
    assert(cur);
    n = 0;
    while (qihse_btree_cursor_get(cur, NULL, NULL, &rid)) {
        assert(rid == 121 || rid == 122);
        n++;
        if (!qihse_btree_cursor_next(cur)) break;
    }
    assert(n == 2);
    qihse_btree_cursor_close(cur);
    free(pkey);

    /* A prefix that matches nothing yields no cursor. */
    int64_t a9 = 9;
    qihse_btree_col_t p9 = {QIHSE_BTREE_COL_INT64, &a9, 0};
    assert(qihse_btree_serialize_key_alloc(&p9, 1, &pkey, &plen) == 0);
    assert(qihse_btree_prefix_open(tree, pkey, plen) == NULL);
    free(pkey);

    qihse_btree_destroy(tree);
    printf("PASS composite prefix matching: a=? and a=? AND b=? on a 3-column index\n");
}

/* ── 7. Hash index insert / lookup / resize ─────────────────────────────── */

static void test_hash_insert_lookup_resize(void) {
    /* Small initial capacity so 500 entries force repeated growth. */
    qihse_hash_index_t* idx = qihse_hash_index_create(QIHSE_HASH_KEY_INT64, 8);
    assert(idx);
    assert(qihse_hash_index_size(idx) == 0);

    for (int64_t i = 0; i < 500; i++) {
        assert(qihse_hash_index_insert(idx, &i, sizeof(i), (uint64_t)(i * 7 + 1)));
    }
    assert(qihse_hash_index_size(idx) == 500);
    for (int64_t i = 0; i < 500; i++) {
        uint64_t rid = 0;
        assert(qihse_hash_index_lookup(idx, &i, sizeof(i), &rid));
        assert(rid == (uint64_t)(i * 7 + 1));
    }
    /* Absent keys are absent even after the resize. */
    for (int64_t i = 500; i < 520; i++) {
        uint64_t rid = 0;
        assert(!qihse_hash_index_lookup(idx, &i, sizeof(i), &rid));
    }

    /* Replace keeps the size stable. */
    int64_t dup = 3;
    assert(qihse_hash_index_insert(idx, &dup, sizeof(dup), 999));
    uint64_t rid = 0;
    assert(qihse_hash_index_lookup(idx, &dup, sizeof(dup), &rid) && rid == 999);
    assert(qihse_hash_index_size(idx) == 500);

    qihse_hash_index_destroy(idx);
    printf("PASS hash insert/lookup: 500 int64 keys from capacity 8, replace semantics\n");
}

/* ── 8. Hash index string keys ──────────────────────────────────────────── */

static void test_hash_string_keys(void) {
    qihse_hash_index_t* idx = qihse_hash_index_create(QIHSE_HASH_KEY_STRING, 16);
    assert(idx);
    static const char* names[] = {"alice", "bob", "carol", "dave", "erin"};
    for (size_t i = 0; i < 5; i++) {
        assert(qihse_hash_index_insert(idx, names[i], strlen(names[i]), i + 1));
    }
    for (size_t i = 0; i < 5; i++) {
        uint64_t rid = 0;
        assert(qihse_hash_index_lookup(idx, names[i], strlen(names[i]), &rid));
        assert(rid == i + 1);
    }
    assert(!qihse_hash_index_lookup(idx, "frank", 5, NULL));
    /* Same bytes, different length is a different key. */
    assert(!qihse_hash_index_lookup(idx, "bob\x00", 4, NULL));
    assert(qihse_hash_index_size(idx) == 5);

    qihse_hash_index_destroy(idx);
    printf("PASS hash string keys: length-sensitive lookup\n");
}

/* ── 9. Hash index delete / tombstone reuse ─────────────────────────────── */

static void test_hash_delete_tombstone(void) {
    qihse_hash_index_t* idx = qihse_hash_index_create(QIHSE_HASH_KEY_INT64, 8);
    assert(idx);
    for (int64_t i = 0; i < 40; i++) {
        assert(qihse_hash_index_insert(idx, &i, sizeof(i), (uint64_t)i));
    }

    uint64_t removed = 0;
    int64_t k = 17;
    assert(qihse_hash_index_delete(idx, &k, sizeof(k), &removed));
    assert(removed == 17);
    assert(qihse_hash_index_size(idx) == 39);
    uint64_t rid = 0;
    assert(!qihse_hash_index_lookup(idx, &k, sizeof(k), &rid));
    /* Probing past the tombstone still finds later keys in the same cluster. */
    for (int64_t i = 0; i < 40; i++) {
        if (i == 17) continue;
        assert(qihse_hash_index_lookup(idx, &i, sizeof(i), &rid));
        assert(rid == (uint64_t)i);
    }
    assert(!qihse_hash_index_delete(idx, &k, sizeof(k), NULL));

    /* The tombstone slot is reusable: re-insert and look the key up again. */
    assert(qihse_hash_index_insert(idx, &k, sizeof(k), 1700));
    assert(qihse_hash_index_size(idx) == 40);
    assert(qihse_hash_index_lookup(idx, &k, sizeof(k), &rid) && rid == 1700);

    qihse_hash_index_destroy(idx);
    printf("PASS hash delete: tombstone probing, size accounting, slot reuse\n");
}

/* ── 10/11. Index manager ───────────────────────────────────────────────── */

static void test_index_manager(void) {
    qihse_index_manager_t* mgr = qihse_index_manager_create();
    assert(mgr);
    assert(qihse_index_manager_count(mgr) == 0);
    assert(qihse_index_manager_find(mgr, "absent") == NULL);

    /* Composite B+ tree index on (tenant, score). */
    qihse_idx_col_def_t btree_cols[2];
    memset(btree_cols, 0, sizeof(btree_cols));
    btree_cols[0].type = QIHSE_IDX_COL_INT64;
    snprintf(btree_cols[0].name, sizeof(btree_cols[0].name), "tenant");
    btree_cols[1].type = QIHSE_IDX_COL_STRING;
    snprintf(btree_cols[1].name, sizeof(btree_cols[1].name), "tag");

    qihse_index_t* bidx = qihse_index_manager_add_btree(mgr, "by_tenant_tag",
                                                        btree_cols, 2, 8);
    assert(bidx);
    assert(qihse_index_manager_count(mgr) == 1);
    assert(qihse_index_type(bidx) == QIHSE_INDEX_BTREE);
    assert(strcmp(qihse_index_name(bidx), "by_tenant_tag") == 0);
    assert(qihse_index_ncols(bidx) == 2);
    assert(qihse_index_btree(bidx) != NULL);
    assert(qihse_index_hash(bidx) == NULL);
    assert(qihse_index_manager_find(mgr, "by_tenant_tag") == bidx);

    int64_t tenant = 1;
    const char* tag = "alpha";
    qihse_idx_col_type_t types[2] = {QIHSE_IDX_COL_INT64, QIHSE_IDX_COL_STRING};
    const void* vals[2] = {&tenant, tag};
    size_t lens[2] = {sizeof(int64_t), strlen(tag)};
    assert(qihse_index_manager_insert_row(mgr, 101, types, vals, lens, 2));
    assert(qihse_index_insert(bidx, 102, types, vals, lens, 2));

    /* Both rows are reachable through the index's own key encoding. */
    qihse_btree_col_t key_cols[2] = {
        {QIHSE_BTREE_COL_INT64, &tenant, 0},
        {QIHSE_BTREE_COL_STRING, tag, strlen(tag)}
    };
    void* key = NULL;
    size_t klen = 0;
    assert(qihse_btree_serialize_key_alloc(key_cols, 2, &key, &klen) == 0);
    uint64_t rid = 0;
    assert(qihse_btree_lookup(qihse_index_btree(bidx), key, klen, &rid));
    assert(rid == 102);   /* the later insert replaced the earlier row id */
    free(key);

    /* A column-count mismatch is refused rather than mis-encoded. */
    assert(!qihse_index_insert(bidx, 103, types, vals, lens, 1));

    /* Hash index on a single int64 column.  Note: insert_row() feeds every
     * index on the manager and therefore requires the caller's column count
     * to match *every* registered index; with a 2-column btree and a
     * 1-column hash on one manager it can never succeed, so each index is
     * fed through qihse_index_insert() here. */
    qihse_idx_col_def_t hash_col;
    memset(&hash_col, 0, sizeof(hash_col));
    hash_col.type = QIHSE_IDX_COL_INT64;
    snprintf(hash_col.name, sizeof(hash_col.name), "user_id");
    qihse_index_t* hidx = qihse_index_manager_add_hash(mgr, "by_user_id",
                                                       &hash_col, 1, 16);
    assert(hidx);
    assert(qihse_index_type(hidx) == QIHSE_INDEX_HASH);
    assert(qihse_index_hash(hidx) != NULL);

    int64_t user_id = 4242;
    qihse_idx_col_type_t htypes[1] = {QIHSE_IDX_COL_INT64};
    const void* hvals[1] = {&user_id};
    size_t hlens[1] = {sizeof(int64_t)};
    assert(qihse_index_insert(hidx, 55, htypes, hvals, hlens, 1));
    assert(qihse_hash_index_lookup(qihse_index_hash(hidx), &user_id,
                                   sizeof(user_id), &rid) && rid == 55);
    /* The arity constraint above, asserted rather than assumed. */
    assert(!qihse_index_manager_insert_row(mgr, 56, htypes, hvals, hlens, 1));

    assert(qihse_index_manager_count(mgr) == 2);
    /* Deleting a row removes it from the index it was inserted into. */
    assert(qihse_index_delete(hidx, 55, htypes, hvals, hlens, 1));
    assert(!qihse_hash_index_lookup(qihse_index_hash(hidx), &user_id,
                                    sizeof(user_id), &rid));

    /* Drop removes the index and frees its storage. */
    assert(qihse_index_manager_drop(mgr, "by_user_id"));
    assert(qihse_index_manager_count(mgr) == 1);
    assert(qihse_index_manager_find(mgr, "by_user_id") == NULL);
    assert(!qihse_index_manager_drop(mgr, "by_user_id"));
    assert(qihse_index_manager_find(mgr, "by_tenant_tag") == bidx);

    qihse_index_manager_destroy(mgr);
    printf("PASS index manager: add/find/count/insert_row/delete/drop, column-count check\n");
}

/* ── 12. Index scan executor ────────────────────────────────────────────── */

static void test_index_scan_executor(void) {
    qihse_index_manager_t* mgr = qihse_index_manager_create();
    assert(mgr);

    qihse_idx_col_def_t col;
    memset(&col, 0, sizeof(col));
    col.type = QIHSE_IDX_COL_INT64;
    snprintf(col.name, sizeof(col.name), "k");
    qihse_index_t* bidx = qihse_index_manager_add_btree(mgr, "scan_btree",
                                                        &col, 1, 8);
    assert(bidx);
    qihse_idx_col_type_t types[1] = {QIHSE_IDX_COL_INT64};
    for (int64_t i = 0; i < 20; i++) {
        const void* vals[1] = {&i};
        size_t lens[1] = {sizeof(int64_t)};
        assert(qihse_index_insert(bidx, (uint64_t)(i + 1), types, vals, lens, 1));
    }

    /* EQ: a serialized single int64 key. */
    int64_t probe = 5;
    qihse_btree_col_t kc = {QIHSE_BTREE_COL_INT64, &probe, 0};
    void* eq_key = NULL;
    size_t eq_len = 0;
    assert(qihse_btree_serialize_key_alloc(&kc, 1, &eq_key, &eq_len) == 0);

    uint64_t rid = 0;
    assert(qihse_index_scan_eq(bidx, eq_key, eq_len, &rid) && rid == 6);

    qihse_scan_pred_t pred;
    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_EQ;
    pred.eq_key = eq_key;
    pred.eq_key_len = eq_len;
    qihse_index_scan_t* scan = qihse_index_scan_open(bidx, &pred);
    assert(scan);
    uint64_t* all = NULL;
    size_t n_all = 0;
    assert(qihse_index_scan_all(scan, &all, &n_all));
    assert(n_all == 1 && all[0] == 6);
    free(all);
    /* A drained scan keeps reporting the end of the scan. */
    uint64_t one = 0;
    size_t n_one = 0;
    assert(!qihse_index_scan_next(scan, &one, 1, &n_one));
    qihse_index_scan_close(scan);

    /* RANGE: [2, 4] inclusive. */
    int64_t lo = 2, hi = 4;
    qihse_btree_col_t klo = {QIHSE_BTREE_COL_INT64, &lo, 0};
    qihse_btree_col_t khi = {QIHSE_BTREE_COL_INT64, &hi, 0};
    void *klo_buf = NULL, *khi_buf = NULL;
    size_t klo_len = 0, khi_len = 0;
    assert(qihse_btree_serialize_key_alloc(&klo, 1, &klo_buf, &klo_len) == 0);
    assert(qihse_btree_serialize_key_alloc(&khi, 1, &khi_buf, &khi_len) == 0);
    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_RANGE;
    pred.min_key = klo_buf; pred.min_len = klo_len;
    pred.max_key = khi_buf; pred.max_len = khi_len;
    scan = qihse_index_scan_open(bidx, &pred);
    assert(scan);
    /* Batch iteration with a capacity of 2 must still yield all 3 rows. */
    uint64_t buf[2];
    size_t got = 0;
    size_t total = 0;
    while (qihse_index_scan_next(scan, buf, 2, &got)) {
        total += got;
    }
    assert(total == 3);
    qihse_index_scan_close(scan);

    /* PREFIX: all keys starting with the 8-byte encoding of 1 (i.e. k=1). */
    int64_t prefix_val = 1;
    qihse_btree_col_t kp = {QIHSE_BTREE_COL_INT64, &prefix_val, 0};
    void* pbuf = NULL;
    size_t plen = 0;
    assert(qihse_btree_serialize_key_alloc(&kp, 1, &pbuf, &plen) == 0);
    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_PREFIX;
    pred.prefix_key = pbuf; pred.prefix_len = plen;
    scan = qihse_index_scan_open(bidx, &pred);
    assert(scan);
    assert(qihse_index_scan_all(scan, &all, &n_all));
    assert(n_all == 1 && all[0] == 2);
    free(all);
    qihse_index_scan_close(scan);

    /* No match -> no scan handle. */
    int64_t missing = 999;
    qihse_btree_col_t km = {QIHSE_BTREE_COL_INT64, &missing, 0};
    void* mbuf = NULL;
    size_t mlen = 0;
    assert(qihse_btree_serialize_key_alloc(&km, 1, &mbuf, &mlen) == 0);
    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_EQ;
    pred.eq_key = mbuf; pred.eq_key_len = mlen;
    assert(qihse_index_scan_open(bidx, &pred) == NULL);
    assert(!qihse_index_scan_eq(bidx, mbuf, mlen, &rid));

    /* Hash index scan: EQ only.  Note the encoding split: a single-column
     * INT64 hash index is keyed by the raw 8 bytes of the value (see
     * qihse_index_insert), while every other index is keyed by the sortable
     * serialization.  The scan executor hands the key straight to the hash
     * lookup, so the raw key is what matches here. */
    qihse_index_t* hidx = qihse_index_manager_add_hash(mgr, "scan_hash",
                                                       &col, 1, 8);
    assert(hidx);
    for (int64_t i = 0; i < 5; i++) {
        const void* vals[1] = {&i};
        size_t lens[1] = {sizeof(int64_t)};
        assert(qihse_index_insert(hidx, (uint64_t)(100 + i), types, vals, lens, 1));
    }
    int64_t hkey = 3;
    assert(qihse_index_scan_eq(hidx, &hkey, sizeof(hkey), &rid) && rid == 103);
    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_EQ;
    pred.eq_key = &hkey;
    pred.eq_key_len = sizeof(hkey);
    scan = qihse_index_scan_open(hidx, &pred);
    assert(scan);
    assert(qihse_index_scan_all(scan, &all, &n_all));
    assert(n_all == 1 && all[0] == 103);
    free(all);
    qihse_index_scan_close(scan);

    /* The sortable serialization is *not* the hash index's key form, so it
     * does not match -- the encoding split asserted rather than assumed. */
    qihse_btree_col_t hkc = {QIHSE_BTREE_COL_INT64, &hkey, 0};
    void* hbuf = NULL;
    size_t hlen = 0;
    assert(qihse_btree_serialize_key_alloc(&hkc, 1, &hbuf, &hlen) == 0);
    assert(!qihse_index_scan_eq(hidx, hbuf, hlen, &rid));

    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_RANGE;
    pred.min_key = klo_buf; pred.min_len = klo_len;
    pred.max_key = khi_buf; pred.max_len = khi_len;
    assert(qihse_index_scan_open(hidx, &pred) == NULL);

    free(eq_key); free(klo_buf); free(khi_buf); free(pbuf); free(mbuf); free(hbuf);
    qihse_index_manager_destroy(mgr);
    printf("PASS index scan executor: EQ/RANGE/PREFIX on btree, EQ-only on hash, batching\n");
}

/* ── 13. Bulk load ──────────────────────────────────────────────────────── */

static void test_bulk_load(void) {
    qihse_index_manager_t* mgr = qihse_index_manager_create();
    assert(mgr);
    qihse_idx_col_def_t col;
    memset(&col, 0, sizeof(col));
    col.type = QIHSE_IDX_COL_INT64;
    snprintf(col.name, sizeof(col.name), "k");
    qihse_index_t* idx = qihse_index_manager_add_btree(mgr, "bulk", &col, 1, 8);
    assert(idx);

    /* Deliberately unsorted input: bulk load sorts before building. */
    enum { N = 64 };
    uint64_t row_ids[N];
    int64_t keys[N];
    const void* key_ptrs[N];
    size_t key_lens[N];
    for (int i = 0; i < N; i++) {
        keys[i] = (int64_t)(N - i);       /* descending */
        row_ids[i] = (uint64_t)(1000 + i);
        key_ptrs[i] = &keys[i];
        key_lens[i] = sizeof(int64_t);
    }
    assert(qihse_index_bulk_load(idx, row_ids, key_ptrs, key_lens, N));

    uint64_t rid = 0;
    for (int i = 0; i < N; i++) {
        assert(qihse_btree_lookup(qihse_index_btree(idx), &keys[i],
                                  sizeof(int64_t), &rid));
        assert(rid == row_ids[i]);
    }
    /* A full range scan returns the keys in ascending order. */
    qihse_btree_cursor_t* cur = qihse_btree_range_open(qihse_index_btree(idx),
                                                       NULL, 0, NULL, 0);
    assert(cur);
    int64_t prev = 0;
    bool first = true;
    int n = 0;
    const void* key = NULL;
    size_t klen = 0;
    while (qihse_btree_cursor_get(cur, &key, &klen, &rid)) {
        int64_t got = 0;
        memcpy(&got, key, sizeof(got));
        if (!first) assert(got > prev);
        prev = got;
        first = false;
        n++;
        if (!qihse_btree_cursor_next(cur)) break;
    }
    assert(n == N);
    qihse_btree_cursor_close(cur);

    qihse_index_manager_destroy(mgr);
    printf("PASS bulk load: unsorted %d-entry load, sorted iteration\n", N);
}

/* ── 14. Wrapped (HNSW/FTS) index registration ──────────────────────────── */

typedef struct {
    int created;
    int destroyed;
    int inserts;
    int deletes;
    uint64_t last_row_id;
    char last_payload[32];
} wrapper_state_t;

static void* wrapper_create(void) {
    wrapper_state_t* s = (wrapper_state_t*)calloc(1, sizeof(*s));
    assert(s);
    s->created = 1;
    return s;
}
static void wrapper_destroy(void* handle) {
    ((wrapper_state_t*)handle)->destroyed++;
}
static bool wrapper_insert(void* handle, uint64_t row_id,
                           const void* data, size_t data_len) {
    wrapper_state_t* s = (wrapper_state_t*)handle;
    s->inserts++;
    s->last_row_id = row_id;
    size_t n = data_len < sizeof(s->last_payload) - 1 ? data_len
                                                      : sizeof(s->last_payload) - 1;
    memcpy(s->last_payload, data, n);
    s->last_payload[n] = '\0';
    return true;
}
static bool wrapper_delete(void* handle, uint64_t row_id) {
    (void)row_id;
    ((wrapper_state_t*)handle)->deletes++;
    return true;
}

static void test_wrapped_index(void) {
    qihse_index_manager_t* mgr = qihse_index_manager_create();
    assert(mgr);

    qihse_idx_col_def_t col;
    memset(&col, 0, sizeof(col));
    col.type = QIHSE_IDX_COL_STRING;
    snprintf(col.name, sizeof(col.name), "text");

    qihse_index_wrapper_vtbl_t vtbl;
    vtbl.create_fn = wrapper_create;
    vtbl.destroy_fn = wrapper_destroy;
    vtbl.insert_fn = wrapper_insert;
    vtbl.delete_fn = wrapper_delete;

    qihse_index_t* widx = qihse_index_manager_add_wrapped(mgr, "fts_wrap",
                                                          QIHSE_INDEX_FTS_INVERTED,
                                                          &col, 1, &vtbl);
    assert(widx);
    wrapper_state_t* state = (wrapper_state_t*)qihse_index_wrapped_handle(widx);
    assert(state && state->created == 1);
    assert(qihse_index_type(widx) == QIHSE_INDEX_FTS_INVERTED);
    assert(qihse_index_ncols(widx) == 1);
    assert(qihse_index_btree(widx) == NULL);
    assert(qihse_index_hash(widx) == NULL);

    const char* text = "the quick brown fox";
    qihse_idx_col_type_t types[1] = {QIHSE_IDX_COL_STRING};
    const void* vals[1] = {text};
    size_t lens[1] = {strlen(text)};
    assert(qihse_index_manager_insert_row(mgr, 77, types, vals, lens, 1));
    assert(state->inserts == 1);
    assert(state->last_row_id == 77);
    assert(strcmp(state->last_payload, text) == 0);
    assert(qihse_index_delete(widx, 77, types, vals, lens, 1));
    assert(state->deletes == 1);

    /* Wrapped indexes are not row-id predicate sources. */
    qihse_scan_pred_t pred;
    memset(&pred, 0, sizeof(pred));
    pred.kind = QIHSE_SCAN_EQ;
    pred.eq_key = text;
    pred.eq_key_len = strlen(text);
    qihse_index_scan_t* scan = qihse_index_scan_open(widx, &pred);
    assert(scan);
    uint64_t row = 0;
    size_t got = 0;
    assert(!qihse_index_scan_next(scan, &row, 1, &got));
    assert(got == 0);
    qihse_index_scan_close(scan);

    /* Only VECTOR_HNSW / FTS_INVERTED may be wrapped. */
    assert(qihse_index_manager_add_wrapped(mgr, "bad", QIHSE_INDEX_BTREE,
                                           &col, 1, &vtbl) == NULL);

    /* Dropping the wrapped index invokes the wrapper's destroy callback. */
    assert(qihse_index_manager_drop(mgr, "fts_wrap"));
    assert(state->destroyed == 1);

    qihse_index_manager_destroy(mgr);
    printf("PASS wrapped index: vtable registration, payload routing, drop destroys\n");
}

int main(void) {
    test_btree_insert_lookup();
    test_btree_range_scan();
    test_btree_delete();
    test_btree_string_keys();
    test_composite_serialization();
    test_composite_prefix_match();
    test_hash_insert_lookup_resize();
    test_hash_string_keys();
    test_hash_delete_tombstone();
    test_index_manager();
    test_index_scan_executor();
    test_bulk_load();
    test_wrapped_index();
    printf("test_indexes: all secondary-index tests passed\n");
    return 0;
}
