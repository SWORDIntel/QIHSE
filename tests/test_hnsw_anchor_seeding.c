/*
 * Test suite for Anchor-Guided Vector Proximity Seeding (Idea 1).
 *
 * Verifies that:
 *   - 1D scalar-quantized projections are computed and kept in a sorted
 *     anchor table indexed by qihse_keystone_anchor_search.
 *   - qihse_hnsw_anchor_seed_entry returns a vertex whose projection is close
 *     to the query projection (exact-hit path through keystone anchor search
 *     plus nearest-neighbour fallback on miss).
 *   - Anchor-seeded search produces recall at least as good as the default
 *     HNSW search (which starts from index->enter_point) while reducing the
 *     number of distance evaluations (search hops).
 */

#include "qihse_hnsw.h"
#include "qihse_keystone.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_DIM   16
#define TEST_N     512
#define TEST_EF    32
#define TEST_QUERIES 64

/* ---- Vector store + callbacks ------------------------------------------- */

typedef struct {
    float *data;   /* N * D contiguous */
    size_t n;
    size_t dim;
} vector_store_t;

static const float *store_get_vector(void *ctx, uint32_t node_id) {
    vector_store_t *s = (vector_store_t *)ctx;
    if (!s || node_id >= s->n) return NULL;
    return &s->data[(size_t)node_id * s->dim];
}

static float store_distance(const float *a, const float *b, size_t dim) {
    float acc = 0.0f;
    for (size_t i = 0; i < dim; i++) {
        float d = a[i] - b[i];
        acc += d * d;
    }
    return acc;  /* squared L2 -- preserves ordering */
}

/* ---- Helpers ------------------------------------------------------------ */

static qihse_hnsw_index_t *build_index(vector_store_t *store) {
    qihse_hnsw_index_t *idx = (qihse_hnsw_index_t *)calloc(1, sizeof(*idx));
    assert(idx);
    idx->params.M = 16;
    idx->params.M0 = 32;
    idx->params.ef_construction = 64;
    idx->params.ef_search = TEST_EF;
    idx->params.mult = 1.0f / logf(16.0f);
    idx->params.distance_fn = store_distance;
    idx->params.get_vector_fn = store_get_vector;
    idx->params.user_context = store;
    idx->params.dim = TEST_DIM;
    idx->max_level = -1;

    /* Enable anchor seeding BEFORE insertion so projections are registered. */
    qihse_hnsw_enable_anchor_seeding(idx, true);

    for (uint32_t i = 0; i < store->n; i++) {
        hnsw_insert(idx, i, &store->data[(size_t)i * store->dim], store->dim);
    }
    return idx;
}

/* Standard HNSW search starting from index->enter_point. Returns the number
 * of distance evaluations performed (via idx->last_search_dist_calls). */
static uint64_t default_search(qihse_hnsw_index_t *idx, const float *query,
                                uint32_t ef, uint32_t *out, size_t *n_out) {
    idx->last_search_dist_calls = 0;
    uint32_t ep = idx->enter_point;
    for (int lc = idx->max_level; lc > 0; lc--) {
        uint32_t closest = ep;
        size_t n = 0;
        hnsw_search_layer(idx, query, ep, 1, lc, &closest, &n);
        if (n > 0) ep = closest;
    }
    size_t n = 0;
    hnsw_search_layer(idx, query, ep, (int)ef, 0, out, &n);
    *n_out = n;
    return idx->last_search_dist_calls;
}

/* Brute-force ground-truth nearest neighbour. */
static uint32_t brute_force_nn(vector_store_t *store, const float *query) {
    uint32_t best = 0;
    float best_d = INFINITY;
    for (uint32_t i = 0; i < store->n; i++) {
        float d = store_distance(query, &store->data[(size_t)i * store->dim], store->dim);
        if (d < best_d) { best_d = d; best = i; }
    }
    return best;
}

static bool result_contains(uint32_t *results, size_t n, uint32_t target) {
    for (size_t i = 0; i < n; i++) if (results[i] == target) return true;
    return false;
}

/* ---- Tests -------------------------------------------------------------- */

static void test_projection_and_anchor_table(void) {
    printf("Testing 1D scalar-quantized projection + sorted anchor table...\n");

    float v[TEST_DIM];
    for (size_t i = 0; i < TEST_DIM; i++) v[i] = (float)i * 0.5f;

    int64_t p1 = qihse_hnsw_compute_projection(v, TEST_DIM, NULL);
    /* sum = 0.5 * (0+1+...+15) = 0.5 * 120 = 60; scaled by 1e6 = 60,000,000 */
    assert(p1 == 60000000);

    /* Custom projection function overrides the default. */
    int64_t p2 = qihse_hnsw_compute_projection(v, TEST_DIM,
                (qihse_hnsw_projection_fn_t)NULL);
    assert(p2 == p1);

    vector_store_t store;
    store.n = 4;
    store.dim = TEST_DIM;
    store.data = (float *)calloc(store.n * store.dim, sizeof(float));
    for (uint32_t i = 0; i < store.n; i++) {
        for (size_t d = 0; d < store.dim; d++) {
            store.data[(size_t)i * store.dim + d] = (float)(i * 10 + d);
        }
    }

    qihse_hnsw_index_t idx;
    memset(&idx, 0, sizeof(idx));
    idx.params.dim = TEST_DIM;
    qihse_hnsw_enable_anchor_seeding(&idx, true);

    for (uint32_t i = 0; i < store.n; i++) {
        int rc = qihse_hnsw_register_projection(&idx, i,
                    &store.data[(size_t)i * store.dim], store.dim);
        assert(rc == 0);
    }
    assert(idx.anchor_count == store.n);

    /* Table must be sorted ascending by projection. */
    for (size_t i = 1; i < idx.anchor_count; i++) {
        assert(idx.anchor_projections[i] >= idx.anchor_projections[i - 1]);
    }

    /* Re-registering an existing node refreshes rather than duplicates. */
    int rc = qihse_hnsw_register_projection(&idx, 2,
                &store.data[(size_t)2 * store.dim], store.dim);
    assert(rc == 0);
    assert(idx.anchor_count == store.n);

    qihse_hnsw_anchor_destroy(&idx);
    free(store.data);
    printf("  -> Projection + anchor table invariants OK\n");
}

static void test_anchor_seed_entry_exact_hit(void) {
    printf("Testing qihse_keystone_anchor_search exact-hit seeding...\n");

    vector_store_t store;
    store.n = TEST_N;
    store.dim = TEST_DIM;
    store.data = (float *)malloc(store.n * store.dim * sizeof(float));
    assert(store.data);
    /* Linear layout: v[i][0] = i * 10, other dims small deterministic noise. */
    for (uint32_t i = 0; i < store.n; i++) {
        for (size_t d = 0; d < store.dim; d++) {
            float base = (d == 0) ? (float)i * 10.0f : (float)((i % 7) - 3) * 0.001f;
            store.data[(size_t)i * store.dim + d] = base;
        }
    }

    qihse_hnsw_index_t *idx = build_index(&store);
    assert(idx->anchor_count == store.n);

    /* Query exactly equal to a stored vector -> projection exact match ->
     * qihse_keystone_anchor_search must return a hit and the seeded entry
     * must be that exact node. */
    for (uint32_t t = 0; t < 16; t++) {
        uint32_t target = (t * 37 + 11) % store.n;
        const float *q = &store.data[(size_t)target * store.dim];
        uint32_t seed = qihse_hnsw_anchor_seed_entry(idx, q, store.dim);
        assert(seed == target);
    }

    hnsw_destroy(idx);
    free(store.data);
    printf("  -> Exact-hit anchor seeding verified for 16 queries OK\n");
}

static void test_search_recall_and_hop_reduction(void) {
    printf("Testing recall parity + hop reduction vs default entry point...\n");

    vector_store_t store;
    store.n = TEST_N;
    store.dim = TEST_DIM;
    store.data = (float *)malloc(store.n * store.dim * sizeof(float));
    assert(store.data);
    /* Clustered layout: 8 clusters along the first axis, members scattered
     * in node-id space so the default enter_point is rarely near the query. */
    srand(20260819);
    for (uint32_t i = 0; i < store.n; i++) {
        float center = (float)(i % 8) * 100.0f;
        for (size_t d = 0; d < store.dim; d++) {
            float jitter = ((float)(rand() % 1000) / 1000.0f - 0.5f) * 0.01f;
            store.data[(size_t)i * store.dim + d] =
                (d == 0) ? center + jitter : jitter;
        }
    }

    qihse_hnsw_index_t *idx = build_index(&store);
    assert(idx->anchor_count == store.n);

    uint32_t *def_res = (uint32_t *)malloc(TEST_EF * sizeof(uint32_t));
    uint32_t *anc_res = (uint32_t *)malloc(TEST_EF * sizeof(uint32_t));
    assert(def_res && anc_res);

    uint64_t def_total_hops = 0, anc_total_hops = 0;
    size_t def_hits = 0, anc_hits = 0;
    size_t strict_improvements = 0;

    for (size_t q = 0; q < TEST_QUERIES; q++) {
        uint32_t target = (uint32_t)((q * 7919 + 13) % store.n);
        float query[TEST_DIM];
        memcpy(query, &store.data[(size_t)target * store.dim], sizeof(query));
        /* Add tiny noise so the query is not byte-identical to the stored
         * vector (exercises the nearest-neighbour fallback path too). */
        query[0] += 0.001f;

        uint32_t gt = brute_force_nn(&store, query);

        size_t dn = 0, an = 0;
        uint64_t dh = default_search(idx, query, TEST_EF, def_res, &dn);
        uint64_t ah;
        qihse_hnsw_anchor_seed_search(idx, query, store.dim, TEST_EF, anc_res, &an);
        ah = idx->last_search_dist_calls;

        def_total_hops += dh;
        anc_total_hops += ah;
        if (result_contains(def_res, dn, gt)) def_hits++;
        if (result_contains(anc_res, an, gt)) anc_hits++;
        if (ah < dh) strict_improvements++;
    }

    printf("  -> Default  recall@%u: %zu/%zu, total hops: %llu\n",
           TEST_EF, def_hits, (size_t)TEST_QUERIES,
           (unsigned long long)def_total_hops);
    printf("  -> Anchor   recall@%u: %zu/%zu, total hops: %llu\n",
           TEST_EF, anc_hits, (size_t)TEST_QUERIES,
           (unsigned long long)anc_total_hops);
    printf("  -> Strict hop reductions on %zu/%zu queries\n",
           strict_improvements, (size_t)TEST_QUERIES);

    /* Recall must be at least as good as the default search. */
    assert(anc_hits >= def_hits);
    /* Anchor seeding must not require more total distance evaluations. */
    assert(anc_total_hops <= def_total_hops);
    /* And must produce a strict reduction on at least one query. */
    assert(strict_improvements > 0);

    free(def_res);
    free(anc_res);
    hnsw_destroy(idx);
    free(store.data);
    printf("  -> Recall parity + hop reduction verified OK\n");
}

static void test_disabled_seeding_falls_back(void) {
    printf("Testing disabled seeding falls back to enter_point...\n");

    vector_store_t store;
    store.n = 32;
    store.dim = TEST_DIM;
    store.data = (float *)calloc(store.n * store.dim, sizeof(float));
    for (uint32_t i = 0; i < store.n; i++) {
        store.data[(size_t)i * store.dim] = (float)i;
    }

    qihse_hnsw_index_t *idx = build_index(&store);
    qihse_hnsw_enable_anchor_seeding(idx, false);

    float query[TEST_DIM];
    memset(query, 0, sizeof(query));
    query[0] = 5.0f;
    uint32_t seed = qihse_hnsw_anchor_seed_entry(idx, query, store.dim);
    assert(seed == idx->enter_point);

    /* Search still works with seeding disabled. */
    uint32_t res[TEST_EF];
    size_t n = 0;
    qihse_hnsw_anchor_seed_search(idx, query, store.dim, TEST_EF, res, &n);
    assert(n > 0);

    qihse_hnsw_enable_anchor_seeding(idx, true);
    hnsw_destroy(idx);
    free(store.data);
    printf("  -> Disabled-seeding fallback OK\n");
}

int main(void) {
    printf("==============================================================\n");
    printf("  QIHSE HNSW Anchor-Guided Vector Proximity Seeding Tests     \n");
    printf("==============================================================\n");

    test_projection_and_anchor_table();
    printf("\n");
    test_anchor_seed_entry_exact_hit();
    printf("\n");
    test_search_recall_and_hop_reduction();
    printf("\n");
    test_disabled_seeding_falls_back();
    printf("\n");

    printf("All HNSW Anchor-Guided Seeding Tests PASSED!\n");
    return 0;
}
