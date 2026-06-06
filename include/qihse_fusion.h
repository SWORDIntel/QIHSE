#ifndef QIHSE_FUSION_H
#define QIHSE_FUSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * qihse_vector_query_t:
 * Represents a single vector query for a specific modality.
 */
typedef struct {
    float *vector;         /* Pointer to the query vector data */
    size_t dim;            /* Dimensionality of the vector */
    const char *modality;  /* Name or identifier of the modality (e.g., "text", "image", "audio") */
    float weight;          /* Weight assigned to this modality for fusion */
} qihse_vector_query_t;

/*
 * qihse_multimodal_request_t:
 * Takes an array of vector queries.
 * This struct represents a single multi-modal request consisting of queries
 * from different modalities (e.g., text, image, audio embeddings).
 * Native multi-modal fusion combines these queries.
 */
typedef struct {
    qihse_vector_query_t *queries; /* Array of vector queries */
    size_t num_queries;            /* Number of queries in the array */
    int top_k;                     /* Number of top results to return */
} qihse_multimodal_request_t;

/*
 * qihse_search_result_t:
 * Represents a single search result.
 */
typedef struct {
    uint64_t id;    /* ID of the document/entity */
    float score;    /* Final fused score */
} qihse_search_result_t;

/*
 * qihse_vector_db_search_multimodal:
 * Executes multiple queries from different modalities and fuses their results natively 
 * using Reciprocal Rank Fusion (RRF).
 * 
 * Reciprocal Rank Fusion (RRF) works by taking the rankings from multiple modalities,
 * and assigning a score to each item based on its rank in each list: 
 * score = sum(1 / (k + rank)). The items are then sorted by the final score.
 * By natively handling multi-modal embeddings, QIHSE avoids the overhead of returning
 * large intermediate result sets to the application layer.
 * 
 * Returns: A pointer to an array of qihse_search_result_t of size `request->top_k` (or fewer if fewer results exist),
 *          or NULL on error. The caller is responsible for freeing the returned array.
 */
qihse_search_result_t* qihse_vector_db_search_multimodal(const qihse_multimodal_request_t *request, size_t *out_num_results);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FUSION_H */
