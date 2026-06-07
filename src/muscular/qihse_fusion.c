#include "qihse_fusion.h"
#include <stdlib.h>
#include <stdio.h>

/*
 * rrf_entry_t:
 * Internal structure to keep track of a document's RRF score
 */
typedef struct {
    uint64_t id;
    float rrf_score;
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

/*
 * qihse_vector_db_search_multimodal:
 * Executes multiple queries and fuses their results natively using Reciprocal Rank Fusion (RRF).
 */
qihse_search_result_t* qihse_vector_db_search_multimodal(const qihse_multimodal_request_t *request, size_t *out_num_results) {
    if (!request || request->num_queries == 0 || request->top_k <= 0 || !out_num_results) {
        if (out_num_results) *out_num_results = 0;
        return NULL;
    }

    printf("Executing native multi-modal search using RRF for %zu queries...\n", request->num_queries);

    /* RRF constant k is typically around 60 */
    const float k_constant = 60.0f;
    
    /* We simulate collecting top-N results from each modality.
       For a real implementation, this would call native ANN searches. */
    size_t mock_top_n = (size_t)request->top_k * 2;
    if (mock_top_n < 100) mock_top_n = 100;

    size_t total_alloc = request->num_queries * mock_top_n;
    rrf_entry_t *all_entries = (rrf_entry_t *)calloc(total_alloc, sizeof(rrf_entry_t));
    if (!all_entries) {
        *out_num_results = 0;
        return NULL;
    }

    size_t entry_count = 0;

    for (size_t i = 0; i < request->num_queries; ++i) {
        printf(" - Query %zu: Modality '%s', Dim %zu, Weight %.2f\n", 
               i, 
               request->queries[i].modality ? request->queries[i].modality : "unknown", 
               request->queries[i].dim, 
               request->queries[i].weight);

        float weight = request->queries[i].weight > 0.0f ? request->queries[i].weight : 1.0f;

        /* Simulate ANN results for this query */
        for (size_t rank = 1; rank <= mock_top_n; ++rank) {
            /* Generate somewhat overlapping mock document IDs across queries */
            uint64_t doc_id = 1000 + ((rank * 7 + i * 13) % (mock_top_n / 2 + 1));
            
            /* Calculate RRF score for this rank */
            float score = weight * (1.0f / (k_constant + (float)rank));
            
            all_entries[entry_count].id = doc_id;
            all_entries[entry_count].rrf_score = score;
            entry_count++;
        }
    }

    /* Aggregate scores by ID: First sort by ID */
    qsort(all_entries, entry_count, sizeof(rrf_entry_t), compare_rrf_id);

    /* Merge duplicate IDs by summing their scores */
    size_t unique_count = 0;
    if (entry_count > 0) {
        unique_count = 1;
        for (size_t i = 1; i < entry_count; ++i) {
            if (all_entries[i].id == all_entries[unique_count - 1].id) {
                all_entries[unique_count - 1].rrf_score += all_entries[i].rrf_score;
            } else {
                all_entries[unique_count] = all_entries[i];
                unique_count++;
            }
        }
    }

    /* Sort by aggregated RRF score descending */
    qsort(all_entries, unique_count, sizeof(rrf_entry_t), compare_rrf_score_desc);

    /* Keep top-K results */
    size_t final_count = (size_t)request->top_k;
    if (final_count > unique_count) {
        final_count = unique_count;
    }

    qihse_search_result_t *results = (qihse_search_result_t *)calloc(final_count, sizeof(qihse_search_result_t));
    if (!results) {
        free(all_entries);
        *out_num_results = 0;
        return NULL;
    }

    for (size_t i = 0; i < final_count; ++i) {
        results[i].id = all_entries[i].id;
        results[i].score = all_entries[i].rrf_score;
    }

    free(all_entries);
    *out_num_results = final_count;
    return results;
}
