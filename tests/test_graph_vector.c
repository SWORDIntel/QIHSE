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
#include <stdlib.h>
#include "qihse_auth.h"
#include "persistence/qihse_vector_store.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

static qihse_vector_db_t build_protected_vector_db(const char* path,
                                                   const uint64_t ids[2]) {
    qihse_index_row_t rows[2];
    memset(rows, 0, sizeof rows);
    rows[0].vector_id = ids[0];
    rows[0].vector_offset = 0u;
    rows[0].commit_generation = 1u;
    rows[0].row_flags = QIHSE_ROW_F_LIVE;
    rows[0].classification = QIHSE_CLASS_UNCLASSIFIED;
    rows[0].sci_compartment = QIHSE_SCI_NONE;
    rows[1].vector_id = ids[1];
    rows[1].vector_offset = DIMS * sizeof(float);
    rows[1].commit_generation = 1u;
    rows[1].row_flags = QIHSE_ROW_F_LIVE;
    rows[1].classification = QIHSE_CLASS_SECRET;
    rows[1].sci_compartment = QIHSE_SCI_SI;
    const float vectors[2 * DIMS] = {
        1.0f, 0.0f, 0.0f, 0.0f,
        0.0f, 1.0f, 0.0f, 0.0f
    };
    qihse_vector_store_flush_t flush;
    memset(&flush, 0, sizeof flush);
    flush.vector_dims = DIMS;
    flush.commit_generation = 1u;
    flush.rows = rows;
    flush.row_count = 2u;
    flush.vectors = vectors;
    flush.vector_bytes = sizeof vectors;
    assert(qihse_vector_store_flush(path, &flush));
    qihse_vector_db_t db = qihse_vector_db_open(
        QIHSE_VECTOR_DB_INMEMORY, NULL, path, QIHSE_VDB_OPEN_FILE_BACKED);
    assert(db != NULL);
    return db;
}

int main(void) {
{
    /* Per-test audit/chain isolation (parallel aggregates). */
    char qdd[] = "build/test_graph_vector_XXXXXX";
    if (mkdtemp(qdd)) setenv("QIHSE_DATA_DIR", qdd, 1);
}
    (void)setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 0);
    qihse_auth_init();
    qihse_user_t* op = qihse_auth_get_user(0);
    assert(op != NULL);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 0) == 0 || errno == EEXIST);

    qihse_graph_t* g = NULL;
    qihse_vector_db_t vdb = NULL;
    build_fixture(&g, &vdb);

    uint64_t ids[16];
    float scores[16];

    /* ── NULL principal fails closed ─────────────────────────────────── */
    {
        errno = 0;
        float q[DIMS] = {1.0f, 0, 0, 0};
        size_t n = qihse_graph_vector_search_user(g, vdb, NULL, q, DIMS,
                                                  1, 1, ids, scores, 16);
        assert(n == 0 && errno == EACCES);
        printf("PASS graph-vector search: NULL user fails closed (EACCES)\n");
    }
    {
        errno = 0;
        assert(qihse_graph_vector_traverse_user(g, vdb, NULL, verts[0],
            NULL, 0u, 0.0f, 1u, ids, 16u) == 0u && errno == EACCES);
        errno = 0;
        assert(qihse_graph_vector_recommend_user(g, vdb, NULL, verts[0],
            2u, 1u, ids, scores, 16u) == 0u && errno == EACCES);
        float embedding[DIMS];
        errno = 0;
        assert(qihse_graph_subgraph_embedding_user(g, vdb, NULL, verts, 1u,
            DIMS, embedding) == -1 && errno == EACCES);
        errno = 0;
        assert(qihse_graph_vector_traverse_user(g, NULL, op, verts[0],
            NULL, 0u, 0.0f, 1u, ids, 16u) == 0u && errno == EINVAL);
        errno = 0;
        assert(qihse_graph_vector_traverse(g, vdb, verts[0], NULL, 0u,
            0.0f, 1u, ids, 16u) == 0u && errno == EACCES);
        errno = 0;
        assert(qihse_graph_vector_recommend(g, vdb, verts[0], 2u, 1u,
            ids, scores, 16u) == 0u && errno == EACCES);
        errno = 0;
        assert(qihse_graph_subgraph_embedding(g, vdb, verts, 1u, DIMS,
            embedding) == -1 && errno == EACCES);
        printf("PASS graph-vector APIs: NULL principals and vector DB fail closed\n");
    }
    {
        float q_bad[DIMS + 1u] = {1.0f, 0, 0, 0, 0};
        errno = 0;
        assert(qihse_graph_vector_search_user(g, vdb, op, q_bad, DIMS + 1u,
            1u, 1u, ids, scores, 16u) == 0u && errno == EINVAL);
        errno = 0;
        assert(qihse_graph_vector_traverse_user(g, vdb, op, verts[0], q_bad,
            DIMS + 1u, 0.0f, 1u, ids, 16u) == 0u && errno == EINVAL);
        float protected_output[DIMS + 1u];
        protected_output[DIMS] = 12345.0f;
        errno = 0;
        assert(qihse_graph_subgraph_embedding_user(g, vdb, op, verts, 1u,
            DIMS + 1u, protected_output) == -1 && errno == EINVAL);
        assert(protected_output[DIMS] == 12345.0f);
        printf("PASS graph-vector APIs: dimension mismatch rejected before fetch\n");
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
        size_t n = qihse_graph_vector_traverse_user(g, vdb, op, verts[0], NULL, 0,
                                                    0.0f, 1, ids, 16);
        assert(n >= 1 && ids[0] == verts[0]);
        assert(contains(ids, n, verts[1]));
        /* 1 hop cannot reach verts[2] or the isolated verts[5]. */
        assert(!contains(ids, n, verts[2]));
        assert(!contains(ids, n, verts[5]));

        memset(ids, 0, sizeof ids);
        n = qihse_graph_vector_traverse_user(g, vdb, op, verts[0], NULL, 0,
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
        n = qihse_graph_vector_traverse_user(g, vdb, op, verts[1], q, DIMS,
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
        assert(qihse_graph_subgraph_embedding_user(NULL, vdb, op, verts, 1,
                                                   DIMS, emb) == -1);
        assert(qihse_graph_subgraph_embedding_user(g, vdb, op, NULL, 1,
                                                   DIMS, emb) == -1);
        /* verts[0]=(1,0,0,0), verts[1]=(0,2,0,0) → mean (0.5, 1, 0, 0). */
        uint64_t members[2] = { verts[0], verts[1] };
        memset(emb, 0, sizeof emb);
        assert(qihse_graph_subgraph_embedding_user(g, vdb, op, members, 2,
                                                   DIMS, emb) == 0);
        assert(fabsf(emb[0] - 0.5f) < 1e-5f && fabsf(emb[1] - 1.0f) < 1e-5f);
        assert(emb[2] == 0.0f && emb[3] == 0.0f);
        /* No vectors at all → failure, not a zero embedding. */
        uint64_t no_vec[1] = { 0xDEADBEEF };
        assert(qihse_graph_subgraph_embedding_user(g, vdb, op, no_vec, 1,
                                                   DIMS, emb) == -1);
        printf("PASS subgraph embedding: mean of member vectors, "
               "empty set refused\n");
    }

    /* ── Hybrid recommend: hop-decayed ranking, k cap ────────────────── */
    {
        memset(ids, 0, sizeof ids);
        memset(scores, 0, sizeof scores);
        size_t n = qihse_graph_vector_recommend_user(g, vdb, op, verts[0],
                                                     4, 2, ids, scores, 16);
        assert(n >= 2);
        /* 1-hop candidates (verts[1]) outscore 2-hop (verts[2], verts[4]
         * via 1's neighbours). */
        assert(ids[0] == verts[1]);
        for (size_t i = 1; i < n; i++) assert(scores[i] <= scores[i - 1]);
        assert(!contains(ids, n, verts[0]));  /* the source is excluded */
        assert(!contains(ids, n, verts[5]));

        /* k caps the output. */
        memset(ids, 0, sizeof ids);
        n = qihse_graph_vector_recommend_user(g, vdb, op, verts[0], 1, 2,
                                              ids, scores, 16);
        assert(n == 1 && ids[0] == verts[1]);
        printf("PASS hybrid recommend: hop-decayed ranking, k-bounded\n");
    }

    /* A wide star exceeds both historical fixed limits (64 adjacency and
     * 256 frontier entries). All generated vertices have readable vectors. */
    {
        enum { WIDE_NEIGHBORS = 300, WIDE_VERTICES = WIDE_NEIGHBORS + 1 };
        qihse_graph_t* wide_graph = qihse_graph_create();
        qihse_vector_db_t wide_vdb = qihse_vector_db_create(
            QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
        assert(wide_graph && wide_vdb);
        uint64_t wide_ids[WIDE_VERTICES];
        float* wide_vectors = calloc((size_t)WIDE_VERTICES * DIMS,
                                     sizeof(*wide_vectors));
        assert(wide_vectors);
        wide_ids[0] = qihse_graph_vertex_create(wide_graph, NULL, 0u,
                                                NULL, NULL, 0u);
        assert(wide_ids[0] != 0u);
        wide_vectors[0] = 1.0f;
        for (size_t i = 1u; i < WIDE_VERTICES; ++i) {
            wide_ids[i] = qihse_graph_vertex_create(wide_graph, NULL, 0u,
                                                    NULL, NULL, 0u);
            assert(wide_ids[i] != 0u);
            wide_vectors[i * DIMS + 1u] = 1.0f;
            assert(qihse_graph_edge_create(wide_graph, "WIDE", wide_ids[0],
                wide_ids[i], NULL, NULL, 0u) != 0u);
        }
        assert(qihse_vector_db_add_vectors(wide_vdb, wide_vectors,
            WIDE_VERTICES, DIMS, wide_ids, NULL, NULL));
        uint64_t* wide_out = calloc(WIDE_VERTICES + 1u, sizeof(*wide_out));
        float* wide_scores = calloc(WIDE_VERTICES + 1u, sizeof(*wide_scores));
        assert(wide_out && wide_scores);
        size_t wide_count = qihse_graph_vector_traverse_user(
            wide_graph, wide_vdb, op, wide_ids[0], NULL, 0u, 0.0f, 1u,
            wide_out, WIDE_VERTICES + 1u);
        assert(wide_count == WIDE_VERTICES && contains(wide_out, wide_count,
                                                       wide_ids[WIDE_NEIGHBORS]));
        wide_count = qihse_graph_vector_recommend_user(
            wide_graph, wide_vdb, op, wide_ids[0], WIDE_VERTICES, 1u,
            wide_out, wide_scores, WIDE_VERTICES + 1u);
        assert(wide_count == WIDE_NEIGHBORS && contains(wide_out, wide_count,
                                                        wide_ids[WIDE_NEIGHBORS]));
        float query[DIMS] = {1.0f, 0, 0, 0};
        wide_count = qihse_graph_vector_search_user(
            wide_graph, wide_vdb, op, query, DIMS, 1u, 1u, wide_out,
            wide_scores, WIDE_VERTICES + 1u);
        assert(wide_count > 256u && contains(wide_out, wide_count,
                                             wide_ids[WIDE_NEIGHBORS]));
        free(wide_scores);
        free(wide_out);
        free(wide_vectors);
        qihse_vector_db_destroy(wide_vdb);
        qihse_graph_destroy(wide_graph);
        printf("PASS graph-vector traversal: all 300 high-degree neighbors retained\n");
    }

    /* The vector store's persisted row labels are authoritative. The source
     * and secret/SCI neighbor share a graph edge, but only the Operator may
     * see the protected vector-backed node. */
    {
        char path[] = "/tmp/qihse-graph-vector-protected-XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);
        close(fd);
        assert(unlink(path) == 0);
        qihse_graph_t* protected_graph = qihse_graph_create();
        assert(protected_graph);
        uint64_t protected_ids[2];
        protected_ids[0] = qihse_graph_vertex_create(protected_graph, NULL,
            0u, NULL, NULL, 0u);
        protected_ids[1] = qihse_graph_vertex_create(protected_graph, NULL,
            0u, NULL, NULL, 0u);
        assert(protected_ids[0] && protected_ids[1]);
        assert(qihse_graph_edge_create(protected_graph, "PROTECTED",
            protected_ids[0], protected_ids[1], NULL, NULL, 0u) != 0u);
        qihse_vector_db_t protected_vdb = build_protected_vector_db(
            path, protected_ids);
        qihse_user_t* low = qihse_auth_create_user(op, 74u,
            QIHSE_ROLE_ANALYST, 0u, 0u, "GraphLowPass123!", false);
        qihse_user_t* no_sci = qihse_auth_create_user(op, 75u,
            QIHSE_ROLE_ANALYST, QIHSE_CLASS_TOP_SECRET, QIHSE_SCI_NONE,
            "GraphNoSciPass123!", false);
        qihse_user_t* revoked = qihse_auth_create_user(op, 76u,
            QIHSE_ROLE_ANALYST, QIHSE_CLASS_TOP_SECRET, QIHSE_SCI_SI,
            "GraphRevokedPass123!", false);
        assert(low && no_sci && revoked);
        uint64_t protected_out[8];
        float protected_scores[8];
        float query[DIMS] = {1.0f, 0, 0, 0};
        size_t visible = qihse_graph_vector_search_user(protected_graph,
            protected_vdb, op, query, DIMS, 1u, 1u, protected_out,
            protected_scores, 8u);
        assert(visible == 2u && contains(protected_out, visible,
                                         protected_ids[1]));
        visible = qihse_graph_vector_search_user(protected_graph,
            protected_vdb, low, query, DIMS, 1u, 1u, protected_out,
            protected_scores, 8u);
        assert(visible == 1u && !contains(protected_out, visible,
                                          protected_ids[1]));
        visible = qihse_graph_vector_search_user(protected_graph,
            protected_vdb, no_sci, query, DIMS, 1u, 1u, protected_out,
            protected_scores, 8u);
        assert(visible == 1u && !contains(protected_out, visible,
                                          protected_ids[1]));
        visible = qihse_graph_vector_traverse_user(protected_graph,
            protected_vdb, low, protected_ids[0], NULL, 0u, 0.0f, 1u,
            protected_out, 8u);
        assert(visible == 1u && !contains(protected_out, visible,
                                          protected_ids[1]));
        visible = qihse_graph_vector_traverse_user(protected_graph,
            protected_vdb, no_sci, protected_ids[0], NULL, 0u, 0.0f, 1u,
            protected_out, 8u);
        assert(visible == 1u && !contains(protected_out, visible,
                                          protected_ids[1]));
        visible = qihse_graph_vector_recommend_user(protected_graph,
            protected_vdb, low, protected_ids[0], 4u, 1u,
            protected_out, protected_scores, 8u);
        assert(visible == 0u);
        visible = qihse_graph_vector_recommend_user(protected_graph,
            protected_vdb, no_sci, protected_ids[0], 4u, 1u,
            protected_out, protected_scores, 8u);
        assert(visible == 0u);
        float embedding[DIMS];
        assert(qihse_graph_subgraph_embedding_user(protected_graph,
            protected_vdb, low, protected_ids, 2u, DIMS, embedding) == 0);
        assert(fabsf(embedding[0] - 1.0f) < 1e-5f && embedding[1] == 0.0f);
        assert(qihse_graph_subgraph_embedding_user(protected_graph,
            protected_vdb, no_sci, protected_ids, 2u, DIMS, embedding) == 0);
        assert(fabsf(embedding[0] - 1.0f) < 1e-5f && embedding[1] == 0.0f);
        assert(qihse_auth_destroy_user(op, 76u));
        errno = 0;
        assert(qihse_graph_vector_search_user(protected_graph, protected_vdb,
            revoked, query, DIMS, 1u, 1u, protected_out,
            protected_scores, 8u) == 0u);
        assert(errno == EACCES);
        errno = 0;
        assert(qihse_graph_vector_traverse_user(protected_graph, protected_vdb,
            revoked, protected_ids[0], NULL, 0u, 0.0f, 1u,
            protected_out, 8u) == 0u);
        assert(errno == EACCES);
        errno = 0;
        assert(qihse_graph_vector_recommend_user(protected_graph, protected_vdb,
            revoked, protected_ids[0], 4u, 1u, protected_out,
            protected_scores, 8u) == 0u);
        assert(errno == EACCES);
        assert(qihse_graph_subgraph_embedding_user(protected_graph,
            protected_vdb, revoked, protected_ids, 2u, DIMS, embedding) == -1);
        assert(errno == EACCES);
        qihse_auth_destroy_user(op, 74u);
        qihse_auth_destroy_user(op, 75u);
        qihse_vector_db_destroy(protected_vdb);
        qihse_graph_destroy(protected_graph);
        unlink(path);
        printf("PASS graph-vector hybrid APIs: auth-scoped neighbors and revoked principal denial\n");
    }

    qihse_graph_destroy(g);
    printf("test_graph_vector: all hybrid graph-vector tests passed\n");
    return 0;
}
