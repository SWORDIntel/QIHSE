/* tests/test_graph_vector.c — graph+vector hybrid traversal coverage.
 *
 * Verifies the hybrid primitives in src/broad_oak/qihse_graph_vector.c:
 *
 *   - qihse_graph_vector_search_user: HNSW seed, then BFS expansion over
 *     graph edges with hop-decayed scores, sorted descending; NULL user
 *     fails closed (EACCES, no rows) — AGENTS.md invariant 1.
 *   - qihse_graph_vector_traverse: BFS bounded by hops, start vertex
 *     emitted first, no revisits; with a query the threshold filters by
 *     real cosine similarity and unverifiable neighbours fail closed.
 *   - qihse_graph_subgraph_embedding: mean of member vectors; vertices
 *     without embeddings are skipped, an all-missing set is an error.
 *   - qihse_graph_vector_recommend: hop-decayed candidate ranking with k
 *     cap, sorted descending.
 */
#include "qihse_graph_vector.h"
#include "qihse_auth.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#define DIMS 4

/* Vertices v0..v5 arranged as a path 0-1-2-3 plus a leaf 4 off 1 and an
 * isolated 5.  Vectors: vertex i gets the i-th basis vector scaled up, so
 * nearest-neighbour identity is deterministic. */
static uint64_t verts[6];

static void build_fixture(qihse_graph_t** g_out, qihse_vector_db_t* vdb_out) {
    *g_out = qihse_graph_create();
    assert(*g_out != NULL);
    *vdb_out = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(*vdb_out != NULL);

    for (size_t i = 0; i < 6; i++) {
        verts[i] = qihse_graph_vertex_create(*g_out, NULL, 0, NULL, NULL, 0);
        assert(verts[i] != 0);
        float v[DIMS] = {0};
        v[i % DIMS] = 1.0f + (float)i;  /* distinct per vertex */
        uint64_t ids[] = { verts[i] };
        assert(qihse_vector_db_add_vectors(*vdb_out, v, 1, DIMS, ids,
                                           NULL, NULL));
    }
    assert(qihse_graph_edge_create(*g_out, "KNOWS", verts[0], verts[1],
                                   NULL, NULL, 0) != 0);
    assert(qihse_graph_edge_create(*g_out, "KNOWS", verts[1], verts[2],
                                   NULL, NULL, 0) != 0);
    assert(qihse_graph_edge_create(*g_out, "KNOWS", verts[2], verts[3],
                                   NULL, NULL, 0) != 0);
    assert(qihse_graph_edge_create(*g_out, "KNOWS", verts[1], verts[4],
                                   NULL, NULL, 0) != 0);
    /* verts[5]: isolated — reachable only through a direct vector hit. */
}

static int contains(const uint64_t* ids, size_t n, uint64_t id) {
    for (size_t i = 0; i < n; i++) if (ids[i] == id) return 1;
    return 0;
}

int main(void) {
    qihse_auth_init();
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);

    qihse_graph_t* g = NULL;
    qihse_vector_db_t vdb = NULL;
    build_fixture(&g, &vdb);

    uint64_t ids[16];
    float scores[16];

    /* ── NULL principal fails closed ─────────────────────────────────── */
    {
        float q[DIMS] = {1.0f, 0, 0, 0};
        errno = 0;
        size_t n = qihse_graph_vector_search_user(g, vdb, NULL, q, DIMS,
                                                  1, 1, ids, scores, 16);
        assert(n == 0 && errno == EACCES);
        printf("PASS graph-vector search: NULL user fails closed (EACCES)\n");
    }

    /* ── HNSW seed + BFS expansion with hop decay ────────────────────── */
    {
        float q[DIMS] = {1.0f, 0, 0, 0};  /* nearest: verts[0] */
        memset(ids, 0, sizeof ids);
        memset(scores, 0, sizeof scores);
        size_t n = qihse_graph_vector_search_user(g, vdb, op, q, DIMS,
                                                  1, 1, ids, scores, 16);
        /* Seed + 1-hop neighbours of verts[0] = {0,1}. */
        assert(n >= 2);
        assert(ids[0] == verts[0]);           /* seed scores highest */
        assert(contains(ids, n, verts[1]));
        /* Hop-1 neighbour score is the seed score decayed by 1/(1+1). */
        size_t j = 0;
        while (j < n && ids[j] != verts[1]) j++;
        assert(j < n && scores[j] < scores[0]);
        /* Isolated vertex is NOT reached by graph expansion. */
        assert(!contains(ids, n, verts[5]));
        /* Sorted descending. */
        for (size_t i = 1; i < n; i++) assert(scores[i] <= scores[i - 1]);
        printf("PASS graph-vector search: seed expands over edges with "
               "decayed, sorted scores\n");
    }

    /* ── Vector-guided traversal honours hop bound and start vertex ──── */
    {
        memset(ids, 0, sizeof ids);
        size_t n = qihse_graph_vector_traverse(g, vdb, verts[0], NULL, 0,
                                               0.0f, 1, ids, 16);
        assert(n >= 1 && ids[0] == verts[0]);
        assert(contains(ids, n, verts[1]));
        /* 1 hop cannot reach verts[2] or the isolated verts[5]. */
        assert(!contains(ids, n, verts[2]));
        assert(!contains(ids, n, verts[5]));

        memset(ids, 0, sizeof ids);
        n = qihse_graph_vector_traverse(g, vdb, verts[0], NULL, 0,
                                        0.0f, 3, ids, 16);
        assert(contains(ids, n, verts[3]));   /* path reaches depth 3 */
        assert(!contains(ids, n, verts[5]));  /* isolated stays out */
        /* No vertex is emitted twice. */
        for (size_t i = 0; i < n; i++)
            for (size_t k2 = i + 1; k2 < n; k2++)
                assert(ids[i] != ids[k2]);

        /* With a query and a threshold the filter is real: from verts[1]
         * (neighbours 0, 2, 4), a query on the verts[0]/verts[4] axis keeps
         * those two and rejects verts[2], whose vector is orthogonal. */
        float q[DIMS] = {1.0f, 0, 0, 0};
        memset(ids, 0, sizeof ids);
        n = qihse_graph_vector_traverse(g, vdb, verts[1], q, DIMS,
                                        0.9f, 1, ids, 16);
        assert(ids[0] == verts[1]);
        assert(contains(ids, n, verts[0]));
        assert(contains(ids, n, verts[4]));
        assert(!contains(ids, n, verts[2]));
        printf("PASS vector-guided traverse: hop-bounded BFS, threshold "
               "filters by real cosine similarity\n");
    }

    /* ── Subgraph embedding: mean of member vectors ──────────────────── */
    {
        float emb[DIMS];
        assert(qihse_graph_subgraph_embedding(NULL, vdb, verts, 1, DIMS,
                                              emb) == -1);
        assert(qihse_graph_subgraph_embedding(g, vdb, NULL, 1, DIMS,
                                              emb) == -1);
        /* verts[0]=(1,0,0,0), verts[1]=(0,2,0,0) → mean (0.5, 1, 0, 0). */
        uint64_t members[2] = { verts[0], verts[1] };
        memset(emb, 0, sizeof emb);
        assert(qihse_graph_subgraph_embedding(g, vdb, members, 2, DIMS,
                                              emb) == 0);
        assert(fabsf(emb[0] - 0.5f) < 1e-5f && fabsf(emb[1] - 1.0f) < 1e-5f);
        assert(emb[2] == 0.0f && emb[3] == 0.0f);
        /* No vectors at all → failure, not a zero embedding. */
        uint64_t no_vec[1] = { 0xDEADBEEF };
        assert(qihse_graph_subgraph_embedding(g, vdb, no_vec, 1, DIMS,
                                              emb) == -1);
        printf("PASS subgraph embedding: mean of member vectors, "
               "empty set refused\n");
    }

    /* ── Hybrid recommend: hop-decayed ranking, k cap ────────────────── */
    {
        memset(ids, 0, sizeof ids);
        memset(scores, 0, sizeof scores);
        size_t n = qihse_graph_vector_recommend(g, vdb, verts[0], 4, 2,
                                                ids, scores, 16);
        assert(n >= 2);
        /* 1-hop candidates (verts[1]) outscore 2-hop (verts[2], verts[4]
         * via 1's neighbours). */
        assert(ids[0] == verts[1]);
        for (size_t i = 1; i < n; i++) assert(scores[i] <= scores[i - 1]);
        assert(!contains(ids, n, verts[0]));  /* the source is excluded */
        assert(!contains(ids, n, verts[5]));

        /* k caps the output. */
        memset(ids, 0, sizeof ids);
        n = qihse_graph_vector_recommend(g, vdb, verts[0], 1, 2,
                                         ids, scores, 16);
        assert(n == 1 && ids[0] == verts[1]);
        printf("PASS hybrid recommend: hop-decayed ranking, k-bounded\n");
    }

    qihse_graph_destroy(g);
    printf("test_graph_vector: all hybrid graph-vector tests passed\n");
    return 0;
}
