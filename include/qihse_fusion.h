#ifndef QIHSE_FUSION_H
#define QIHSE_FUSION_H

#include <stddef.h>
#include <stdint.h>
#include "qihse_vector_db.h"
#include "qihse_keystone.h"

/* Forward declaration of the FTS index to avoid pulling the full FTS header
 * into every translation unit that includes the fusion API. The full type is
 * only required by the fusion implementation. */
struct qihse_fts_index;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * qihse_multimodal_query_t:
 * Represents a single vector query for a specific modality.
 */
typedef struct {
    float *vector;         /* Pointer to the query vector data */
    size_t dim;            /* Dimensionality of the vector */
    const char *modality;  /* Name or identifier of the modality (e.g., "text", "image", "audio") */
    float weight;          /* Weight assigned to this modality for fusion */
} qihse_multimodal_query_t;

/*
 * qihse_multimodal_request_t:
 * Takes an array of vector queries.
 * This struct represents a single multi-modal request consisting of queries
 * from different modalities (e.g., text, image, audio embeddings).
 * Native multi-modal fusion combines these queries.
 *
 * Idea 5 — Hybrid FTS + Vector RRF Fusion:
 *   fts_index, fts_query, and fts_weight optionally supply a Full-Text Search
 *   modality whose BM25-ranked results are fused with the vector modalities via
 *   Reciprocal Rank Fusion. The FTS modality is the source of the 6-class neural
 *   classification metadata attached to indexed records.
 *
 *   semantic_class_mask is a bitmask over the 6-class neural taxonomy. When
 *   non-zero, only candidates whose neural class bit is set are retained during
 *   RRF. Vector-sourced candidates are enriched with their semantic class via
 *   the FTS index (qihse_fts_get_doc_semantic_class) when an fts_index is
 *   supplied; otherwise they are treated as QIHSE_KEYSTONE_CLASS_UNKNOWN and
 *   pass the filter only if the UNKNOWN bit is set (or the mask is zero).
 */
typedef struct {
    qihse_multimodal_query_t *queries; /* Array of vector queries */
    size_t num_queries;            /* Number of queries in the array */
    int top_k;                     /* Number of top results to return */
    struct qihse_user_s* user;     /* User executing the multimodal query */

    /* Hybrid FTS modality (optional — NULL fts_index disables FTS fusion). */
    struct qihse_fts_index* fts_index; /* FTS index providing BM25 candidates */
    const char* fts_query;             /* FTS query string (NULL => no FTS) */
    float fts_weight;                  /* RRF weight for the FTS modality */

    /* Semantic class filter mask (bit i set => class i allowed; 0 => no filter). */
    uint8_t semantic_class_mask;
} qihse_multimodal_request_t;

/*
 * qihse_fusion_result_t:
 * Represents a single fused search result. semantic_class carries the 6-class
 * neural classification metadata resolved for the fused candidate so callers
 * can apply downstream routing without a second lookup.
 */
typedef struct {
    uint64_t id;    /* ID of the document/entity */
    float score;    /* Final fused score */
    qihse_keystone_class_t semantic_class; /* Neural class metadata */
} qihse_fusion_result_t;

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
 * Idea 5: When request->fts_index and request->fts_query are supplied, the BM25-ranked
 * FTS results are added as an additional ranked list to the RRF fusion. When
 * request->semantic_class_mask is non-zero, candidates are filtered by their 6-class
 * neural classification metadata before final ranking.
 *
 * Returns: A pointer to an array of qihse_fusion_result_t of size `request->top_k` (or fewer if fewer results exist),
 *          or NULL on error. The caller is responsible for freeing the returned array.
 */
qihse_fusion_result_t* qihse_vector_db_search_multimodal(
    qihse_vector_db_t vdb,
    const qihse_multimodal_request_t *request,
    size_t *out_num_results);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FUSION_H */
