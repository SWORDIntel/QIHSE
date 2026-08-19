/*
 * test_neural_fts_fusion.c
 *
 * Idea 5 — Neural Semantic Metadata Tagging & Hybrid FTS + Vector RRF Fusion.
 *
 * Verifies that:
 *   1. The 6-class neural classification metadata is attached to indexed FTS
 *      records and surfaced on search results.
 *   2. qihse_fts_search_user_filtered applies the semantic class bitmask so
 *      that only records whose neural class bit is set are returned.
 *   3. qihse_fts_get_doc_semantic_class resolves the stored neural tag.
 *   4. qihse_vector_db_search_multimodal performs hybrid FTS + Vector RRF
 *      fusion and applies the semantic class filter uniformly across both
 *      modalities (vector-sourced candidates are enriched via the FTS index).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "qihse_fts.h"
#include "qihse_fusion.h"
#include "qihse_auth.h"
#include "qihse_keystone.h"
#include "qihse_vector_db.h"

/* ---- Test corpus: one document per neural class ------------------------- */
static const char* DOC_FINANCIAL      = "bank payment swift iban wire transfer transaction funds";
static const char* DOC_CORPORATE      = "corporate merger acquisition board executive shareholder equity";
static const char* DOC_GOVERNMENT     = "government defense classified agency policy national security";
static const char* DOC_INFRASTRUCTURE = "infrastructure power grid network server router datacenter";
static const char* DOC_CONSUMER       = "consumer retail shopping product discount marketplace cart";

static const uint64_t ID_FINANCIAL      = 1001;
static const uint64_t ID_CORPORATE      = 1002;
static const uint64_t ID_GOVERNMENT     = 1003;
static const uint64_t ID_INFRASTRUCTURE = 1004;
static const uint64_t ID_CONSUMER       = 1005;

static int test_fts_neural_tagging(qihse_fts_index_t* idx, qihse_user_t* user) {
    printf("[1] FTS neural metadata tagging & filtered search...\n");

    /* semantic_class is attached at add time and resolvable later. */
    assert(qihse_fts_get_doc_semantic_class(idx, ID_FINANCIAL)      == QIHSE_KEYSTONE_CLASS_FINANCIAL);
    assert(qihse_fts_get_doc_semantic_class(idx, ID_CORPORATE)      == QIHSE_KEYSTONE_CLASS_CORPORATE);
    assert(qihse_fts_get_doc_semantic_class(idx, ID_GOVERNMENT)     == QIHSE_KEYSTONE_CLASS_GOVERNMENT);
    assert(qihse_fts_get_doc_semantic_class(idx, ID_INFRASTRUCTURE) == QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE);
    assert(qihse_fts_get_doc_semantic_class(idx, ID_CONSUMER)       == QIHSE_KEYSTONE_CLASS_CONSUMER);
    assert(qihse_fts_get_doc_semantic_class(idx, 999999)            == QIHSE_KEYSTONE_CLASS_UNKNOWN);

    qihse_fts_result_t results[16];

    /* Unfiltered search for "bank" returns the FINANCIAL doc and surfaces its
     * neural class on the result. */
    int n = qihse_fts_search_user(idx, "bank", user, results, 16);
    assert(n == 1);
    assert(results[0].doc_id == ID_FINANCIAL);
    assert(results[0].semantic_class == QIHSE_KEYSTONE_CLASS_FINANCIAL);

    /* Filter mask = FINANCIAL only: still returns the FINANCIAL doc. */
    uint8_t mask_fin = (uint8_t)(1u << QIHSE_KEYSTONE_CLASS_FINANCIAL);
    n = qihse_fts_search_user_filtered(idx, "bank", user, results, 16, mask_fin);
    assert(n == 1);
    assert(results[0].doc_id == ID_FINANCIAL);
    assert(results[0].semantic_class == QIHSE_KEYSTONE_CLASS_FINANCIAL);

    /* Filter mask = CONSUMER only: the FINANCIAL doc is excluded. */
    uint8_t mask_con = (uint8_t)(1u << QIHSE_KEYSTONE_CLASS_CONSUMER);
    n = qihse_fts_search_user_filtered(idx, "bank", user, results, 16, mask_con);
    assert(n == 0);

    /* Multi-class mask: CORPORATE | GOVERNMENT. Query "policy" matches the
     * GOVERNMENT doc and is admitted; querying "board" matches CORPORATE. */
    uint8_t mask_cg = (uint8_t)((1u << QIHSE_KEYSTONE_CLASS_CORPORATE)
                                | (1u << QIHSE_KEYSTONE_CLASS_GOVERNMENT));
    n = qihse_fts_search_user_filtered(idx, "policy", user, results, 16, mask_cg);
    assert(n == 1);
    assert(results[0].doc_id == ID_GOVERNMENT);
    assert(results[0].semantic_class == QIHSE_KEYSTONE_CLASS_GOVERNMENT);

    n = qihse_fts_search_user_filtered(idx, "board", user, results, 16, mask_cg);
    assert(n == 1);
    assert(results[0].doc_id == ID_CORPORATE);
    assert(results[0].semantic_class == QIHSE_KEYSTONE_CLASS_CORPORATE);

    /* A mask that excludes GOVERNMENT must drop the "policy" hit. */
    uint8_t mask_co_only = (uint8_t)(1u << QIHSE_KEYSTONE_CLASS_CORPORATE);
    n = qihse_fts_search_user_filtered(idx, "policy", user, results, 16, mask_co_only);
    assert(n == 0);

    printf("    -> PASS (neural tagging, filtered search, class lookup)\n");
    return 0;
}

static int test_hybrid_rrf_fusion(qihse_fts_index_t* idx, qihse_user_t* user) {
    printf("[2] Hybrid FTS + Vector RRF fusion with semantic filtering...\n");

    /* Build an in-memory vector DB with one vector per document. Vectors are
     * orthogonal except ID_CONSUMER which sits between FINANCIAL and CORPORATE
     * so rankings are deterministic. */
    qihse_vector_db_t vdb = qihse_vector_db_create(QIHSE_VECTOR_DB_INMEMORY, NULL, NULL);
    assert(vdb != NULL);

    float vectors[5 * 4] = {
        1.0f, 0.0f, 0.0f, 0.0f,   /* 1001 FINANCIAL */
        0.0f, 1.0f, 0.0f, 0.0f,   /* 1002 CORPORATE */
        0.0f, 0.0f, 1.0f, 0.0f,   /* 1003 GOVERNMENT */
        0.0f, 0.0f, 0.0f, 1.0f,   /* 1004 INFRASTRUCTURE */
        0.5f, 0.5f, 0.0f, 0.0f,   /* 1005 CONSUMER */
    };
    uint64_t ids[5] = { ID_FINANCIAL, ID_CORPORATE, ID_GOVERNMENT,
                        ID_INFRASTRUCTURE, ID_CONSUMER };
    bool ok = qihse_vector_db_add_vectors(vdb, vectors, 5, 4, ids, NULL, NULL);
    assert(ok);

    /* Query vector points at the FINANCIAL axis; FTS query "bank" also targets
     * the FINANCIAL doc, so ID_FINANCIAL receives RRF contribution from both
     * modalities and must rank first. */
    float qvec[4] = { 1.0f, 0.0f, 0.0f, 0.0f };
    qihse_multimodal_query_t mq = {0};
    mq.vector = qvec;
    mq.dim = 4;
    mq.modality = "text";
    mq.weight = 1.0f;

    /* ---- (a) No semantic filter: hybrid fusion, FINANCIAL on top -------- */
    qihse_multimodal_request_t req = {0};
    req.queries = &mq;
    req.num_queries = 1;
    req.top_k = 5;
    req.user = (struct qihse_user_s*)user;
    req.fts_index = idx;
    req.fts_query = "bank";
    req.fts_weight = 1.0f;
    req.semantic_class_mask = 0;

    size_t out_n = 0;
    qihse_fusion_result_t* fused = qihse_vector_db_search_multimodal(vdb, &req, &out_n);
    assert(fused != NULL);
    assert(out_n >= 1);
    assert(fused[0].id == ID_FINANCIAL);
    assert(fused[0].semantic_class == QIHSE_KEYSTONE_CLASS_FINANCIAL);
    /* FINANCIAL is fused from both modalities; its score must strictly exceed
     * any vector-only candidate. */
    if (out_n >= 2) {
        assert(fused[0].score > fused[1].score);
    }
    free(fused);

    /* ---- (b) Semantic filter = FINANCIAL: only FINANCIAL survives ------- */
    req.semantic_class_mask = (uint8_t)(1u << QIHSE_KEYSTONE_CLASS_FINANCIAL);
    fused = qihse_vector_db_search_multimodal(vdb, &req, &out_n);
    assert(fused != NULL);
    assert(out_n == 1);
    assert(fused[0].id == ID_FINANCIAL);
    assert(fused[0].semantic_class == QIHSE_KEYSTONE_CLASS_FINANCIAL);
    free(fused);

    /* ---- (c) Semantic filter = CONSUMER: FINANCIAL is excluded even
     *      though it is the top BM25 + vector hit. Only CONSUMER survives. - */
    req.semantic_class_mask = (uint8_t)(1u << QIHSE_KEYSTONE_CLASS_CONSUMER);
    fused = qihse_vector_db_search_multimodal(vdb, &req, &out_n);
    assert(fused != NULL);
    assert(out_n == 1);
    assert(fused[0].id == ID_CONSUMER);
    assert(fused[0].semantic_class == QIHSE_KEYSTONE_CLASS_CONSUMER);
    free(fused);

    /* ---- (d) Multi-class mask FINANCIAL|INFRASTRUCTURE: both survive,
     *      FINANCIAL ranks above INFRASTRUCTURE. -------------------------- */
    req.semantic_class_mask = (uint8_t)((1u << QIHSE_KEYSTONE_CLASS_FINANCIAL)
                                        | (1u << QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE));
    fused = qihse_vector_db_search_multimodal(vdb, &req, &out_n);
    assert(fused != NULL);
    assert(out_n == 2);
    assert(fused[0].id == ID_FINANCIAL);
    assert(fused[1].id == ID_INFRASTRUCTURE);
    free(fused);

    /* ---- (e) Vector-only path (no FTS) still applies the filter via the
     *      FTS index used as the semantic class source of truth. ---------- */
    qihse_multimodal_request_t req_vonly = {0};
    req_vonly.queries = &mq;
    req_vonly.num_queries = 1;
    req_vonly.top_k = 5;
    req_vonly.user = (struct qihse_user_s*)user;
    req_vonly.fts_index = idx;       /* semantic class lookup only, no FTS query */
    req_vonly.fts_query = NULL;
    req_vonly.fts_weight = 0.0f;
    req_vonly.semantic_class_mask = (uint8_t)(1u << QIHSE_KEYSTONE_CLASS_GOVERNMENT);

    fused = qihse_vector_db_search_multimodal(vdb, &req_vonly, &out_n);
    assert(fused != NULL);
    assert(out_n == 1);
    assert(fused[0].id == ID_GOVERNMENT);
    assert(fused[0].semantic_class == QIHSE_KEYSTONE_CLASS_GOVERNMENT);
    free(fused);

    qihse_vector_db_destroy(vdb);
    printf("    -> PASS (hybrid RRF, vector-only filter, multi-class mask)\n");
    return 0;
}

int main(void) {
    printf("=== Idea 5: Neural Semantic Metadata Tagging & Hybrid FTS + Vector RRF Fusion ===\n");

    qihse_auth_init();
    qihse_user_t* user = qihse_auth_get_user(0);
    assert(user != NULL);

    qihse_fts_index_t* idx = qihse_fts_create();
    assert(idx != NULL);

    /* Index the corpus with explicit 6-class neural tags. */
    assert(qihse_fts_add_document(idx, ID_FINANCIAL,      DOC_FINANCIAL,      strlen(DOC_FINANCIAL),      0, 0, QIHSE_KEYSTONE_CLASS_FINANCIAL));
    assert(qihse_fts_add_document(idx, ID_CORPORATE,      DOC_CORPORATE,      strlen(DOC_CORPORATE),      0, 0, QIHSE_KEYSTONE_CLASS_CORPORATE));
    assert(qihse_fts_add_document(idx, ID_GOVERNMENT,     DOC_GOVERNMENT,     strlen(DOC_GOVERNMENT),     0, 0, QIHSE_KEYSTONE_CLASS_GOVERNMENT));
    assert(qihse_fts_add_document(idx, ID_INFRASTRUCTURE, DOC_INFRASTRUCTURE, strlen(DOC_INFRASTRUCTURE), 0, 0, QIHSE_KEYSTONE_CLASS_INFRASTRUCTURE));
    assert(qihse_fts_add_document(idx, ID_CONSUMER,       DOC_CONSUMER,       strlen(DOC_CONSUMER),       0, 0, QIHSE_KEYSTONE_CLASS_CONSUMER));

    int rc = 0;
    rc |= test_fts_neural_tagging(idx, user);
    rc |= test_hybrid_rrf_fusion(idx, user);

    qihse_fts_destroy(idx);

    if (rc == 0) {
        printf("\nALL PASS\n");
        return 0;
    }
    printf("\nFAILURES DETECTED\n");
    return 1;
}
