#ifndef QIHSE_PQ_H
#define QIHSE_PQ_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t d;           // Original dimension (e.g. 1536)
    size_t m;           // Number of sub-vectors (e.g. 8)
    size_t k;           // Number of centroids per sub-vector (usually 256)
    size_t sub_d;       // Dimension per sub-vector (d / m)
    float* centroids;   // Flattened array of centroids: [m][k][sub_d]
} qihse_pq_model_t;

// Train a Product Quantizer using k-means
qihse_pq_model_t* qihse_pq_train(const float* data, size_t n_samples, size_t d, size_t m, size_t k, size_t iter);

// Encode a single vector into `m` byte codes
void qihse_pq_encode(const qihse_pq_model_t* model, const float* vec, uint8_t* out_code);

// Compute asymmetric distance between a query float vector and an encoded PQ code
float qihse_pq_asymmetric_distance(const qihse_pq_model_t* model, const float* query, const uint8_t* code);

void qihse_pq_free(qihse_pq_model_t* model);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_PQ_H
