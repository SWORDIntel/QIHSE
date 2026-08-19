#include "qihse_fusion.h"
#include "qihse_vector_db.h"
#include "qihse_fts.h"
#include "qihse_auth.h"
#include <stdlib.h>
#include <stdio.h>

/*
 * rrf_entry_t:
 * Internal structure to keep track of a document's RRF score and its resolved
 * 6-class neural classification metadata (Idea 5).
 */
typedef struct {
    uint64_t id;
    float rrf_score;
    qihse_keystone_class_t semantic_class;
} rrf_entry_t;

/* Sort entries by ID to easily sum scores for the same document */
static int compare_rrf_id(const void *a, const void *b) {
    const rrf_entry_t *ea = (const rrf_entry_t *)a;
    const rrf_entry_t *eb = (const rrf_entry_t *)b;
    if (ea->id < eb->id) return -1;
    if (ea->id > eb->id) return 1;
    return 0;
}

/* Sort entries by RRF score descending */
static int compare_rrf_score_desc(const void *a, const void *b) {
    const rrf_entry_t *ea = (const rrf_entry_t *)a;
    const rrf_entry_t *eb = (const rrf_entry_t *)b;
    if (ea->rrf_score > eb->rrf_score) return -1;
    if (ea->rrf_score < eb->rrf_score) return 1;
    return 0;
}

/* Resolve the 6-class neural classification for a candidate id. FTS-sourced
 * candidates already carry their class; vector-sourced candidates are enriched
 * via the FTS index when available, otherwise default to UNKNOWN. */
static qihse_keystone_class_t resolve_semantic_class(
    qihse_fts_index_t* fts_index,
    uint64_t id,
    qihse_keystone_class_t fallback)
{
    if (fts_index) {
        return qihse_fts_get_doc_semantic_class(fts_index, id);
    }
    return fallback;
}

/*
 * qihse_vector_db_search_multimodal:
 * Executes multiple queries and fuses their results natively using Reciprocal Rank Fusion (RRF).
 *
 * Idea 5: Optionally fuses an FTS (BM25) modality alongside the vector modalities
 * and applies 6-class neural semantic class filtering during fusion.
 */
qihse_fusion_result_t* qihse_vector_db_search_multimodal(
    qihse_vector_db_t vdb,
    const qihse_multimodal_request_t *request,
    size_t *out_num_results) {
    if (!request || request->num_queries == 0 || request->top_k <= 0 || !out_num_results) {
        if (out_num_results) *out_num_results = 0;
        return NULL;
    }

    const float k_constant = 60.0f;
    size_t top_n = (size_t)request->top_k * 2;
    if (top_n < 100) top_n = 100;

    bool has_fts = (request->fts_index != NULL && request->fts_query != NULL);
    size_t num_modalities = request->num_queries + (has_fts ? 1 : 0);

    size_t total_alloc = num_modalities * top_n;
    rrf_entry_t *all_entries = (rrf_entry_t *)calloc(total_alloc, sizeof(rrf_entry_t));
    if (!all_entries) {
        *out_num_results = 0;
        return NULL;
    }

    size_t entry_count = 0;

    /* ---- Vector modalities ---- */
    for (size_t i = 0; i < request->num_queries; ++i) {
        float weight = request->queries[i].weight > 0.0f ? request->queries[i].weight : 1.0f;

        if (vdb && request->queries[i].vector && request->queries[i].dim > 0) {
            /* Real ANN search against the vector database */
            qihse_vector_result_t* vdb_results = (qihse_vector_result_t*)calloc(top_n, sizeof(qihse_vector_result_t));
            if (!vdb_results) continue;

            qihse_vector_query_t query = {0};
            query.query_vector = request->queries[i].vector;
            query.vector_dims = request->queries[i].dim;
            query.top_k = top_n;
            query.similarity_threshold = 0.0f;
            query.include_vectors = false;
            query.include_metadata = false;
            query.user = request->user; /* RBAC: vector search requires a user */

            int found = qihse_vector_db_search(vdb, &query, vdb_results, top_n);

            for (int rank = 0; rank < found && entry_count < total_alloc; rank++) {
                float rrf_score = weight * (1.0f / (k_constant + (float)(rank + 1)));
                all_entries[entry_count].id = vdb_results[rank].id;
                all_entries[entry_count].rrf_score = rrf_score;
                all_entries[entry_count].semantic_class = resolve_semantic_class(
                    request->fts_index, vdb_results[rank].id, QIHSE_KEYSTONE_CLASS_UNKNOWN);
                entry_count++;
            }

            free(vdb_results);
        } else {
            /* Fallback: no VDB or no query vector — skip this modality */
            fprintf(stderr, "[QIHSE Fusion] Query %zu has no vector or VDB, skipping\n", i);
        }
    }

    /* ---- Hybrid FTS modality (Idea 5) ---- */
    if (has_fts) {
        float fts_weight = request->fts_weight > 0.0f ? request->fts_weight : 1.0f;
        qihse_fts_result_t* fts_results = (qihse_fts_result_t*)calloc(top_n, sizeof(qihse_fts_result_t));
        if (fts_results) {
            /* Run the FTS search with the semantic class filter applied at the
             * source so the FTS modality only contributes candidates that pass
             * the neural class filter. */
            int fts_found = qihse_fts_search_user_filtered(
                request->fts_index,
                request->fts_query,
                (qihse_user_t*)request->user,
                fts_results,
                (int)top_n,
                request->semantic_class_mask);

            for (int rank = 0; rank < fts_found && entry_count < total_alloc; rank++) {
                float rrf_score = fts_weight * (1.0f / (k_constant + (float)(rank + 1)));
                all_entries[entry_count].id = fts_results[rank].doc_id;
                all_entries[entry_count].rrf_score = rrf_score;
                all_entries[entry_count].semantic_class = fts_results[rank].semantic_class;
                entry_count++;
            }
            free(fts_results);
        }
    }

    /* Aggregate scores by ID: First sort by ID */
    qsort(all_entries, entry_count, sizeof(rrf_entry_t), compare_rrf_id);

    /* Merge duplicate IDs by summing their scores. The semantic class is taken
     * from the first occurrence; FTS-sourced entries (which carry the authoritative
     * neural tag) are preferred over UNKNOWN when both are present. */
    size_t unique_count = 0;
    if (entry_count > 0) {
        unique_count = 1;
        for (size_t i = 1; i < entry_count; ++i) {
            if (all_entries[i].id == all_entries[unique_count - 1].id) {
                all_entries[unique_count - 1].rrf_score += all_entries[i].rrf_score;
                if (all_entries[unique_count - 1].semantic_class == QIHSE_KEYSTONE_CLASS_UNKNOWN
                    && all_entries[i].semantic_class != QIHSE_KEYSTONE_CLASS_UNKNOWN) {
                    all_entries[unique_count - 1].semantic_class = all_entries[i].semantic_class;
                }
            } else {
                all_entries[unique_count] = all_entries[i];
                unique_count++;
            }
        }
    }

    /* Semantic class filtering (Idea 5): drop candidates whose neural class bit
     * is not set in the request mask. A zero mask disables filtering. */
    if (request->semantic_class_mask != 0) {
        size_t kept = 0;
        for (size_t i = 0; i < unique_count; ++i) {
            uint8_t class_bit = (uint8_t)(1u << (uint8_t)all_entries[i].semantic_class);
            if ((request->semantic_class_mask & class_bit) != 0) {
                all_entries[kept++] = all_entries[i];
            }
        }
        unique_count = kept;
    }

    /* Sort by aggregated RRF score descending */
    qsort(all_entries, unique_count, sizeof(rrf_entry_t), compare_rrf_score_desc);

    /* Keep top-K results */
    size_t final_count = (size_t)request->top_k;
    if (final_count > unique_count) {
        final_count = unique_count;
    }

    qihse_fusion_result_t *results = (qihse_fusion_result_t *)calloc(final_count, sizeof(qihse_fusion_result_t));
    if (!results) {
        free(all_entries);
        *out_num_results = 0;
        return NULL;
    }

    for (size_t i = 0; i < final_count; ++i) {
        results[i].id = all_entries[i].id;
        results[i].score = all_entries[i].rrf_score;
        results[i].semantic_class = all_entries[i].semantic_class;
    }

    free(all_entries);
    *out_num_results = final_count;
    return results;
}
