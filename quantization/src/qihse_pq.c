#include "quantization/include/qihse_pq.h"
#include <stdlib.h>
#include <math.h>
#include <float.h>
#include <string.h>

static float l2_sqr(const float* a, const float* b, size_t d) {
    float sum = 0.0f;
    for (size_t i = 0; i < d; ++i) {
        float diff = a[i] - b[i];
        sum += diff * diff;
    }
    return sum;
}

qihse_pq_model_t* qihse_pq_train(const float* data, size_t n_samples, size_t d, size_t m, size_t k, size_t max_iter) {
    if (d % m != 0) return NULL; // d must be divisible by m
    size_t sub_d = d / m;
    
    qihse_pq_model_t* model = (qihse_pq_model_t*)malloc(sizeof(qihse_pq_model_t));
    model->d = d;
    model->m = m;
    model->k = k;
    model->sub_d = sub_d;
    model->centroids = (float*)calloc(m * k * sub_d, sizeof(float));
    
    // For each sub-vector space, run Lloyd's algorithm (k-means)
    for (size_t i = 0; i < m; ++i) {
        float* sub_centroids = &model->centroids[i * k * sub_d];
        
        // Random initialization: pick k random samples from data
        for (size_t j = 0; j < k; ++j) {
            size_t rand_idx = rand() % n_samples;
            memcpy(&sub_centroids[j * sub_d], &data[rand_idx * d + i * sub_d], sub_d * sizeof(float));
        }
        
        size_t* assignments = (size_t*)malloc(n_samples * sizeof(size_t));
        float* new_centroids = (float*)malloc(k * sub_d * sizeof(float));
        size_t* counts = (size_t*)malloc(k * sizeof(size_t));
        
        for (size_t iter = 0; iter < max_iter; ++iter) {
            // Assign points to nearest centroid
            for (size_t n = 0; n < n_samples; ++n) {
                const float* sub_vec = &data[n * d + i * sub_d];
                float min_dist = FLT_MAX;
                size_t best_c = 0;
                for (size_t c = 0; c < k; ++c) {
                    float dist = l2_sqr(sub_vec, &sub_centroids[c * sub_d], sub_d);
                    if (dist < min_dist) {
                        min_dist = dist;
                        best_c = c;
                    }
                }
                assignments[n] = best_c;
            }
            
            // Update centroids
            memset(new_centroids, 0, k * sub_d * sizeof(float));
            memset(counts, 0, k * sizeof(size_t));
            
            for (size_t n = 0; n < n_samples; ++n) {
                size_t c = assignments[n];
                counts[c]++;
                for (size_t j = 0; j < sub_d; ++j) {
                    new_centroids[c * sub_d + j] += data[n * d + i * sub_d + j];
                }
            }
            
            for (size_t c = 0; c < k; ++c) {
                if (counts[c] > 0) {
                    for (size_t j = 0; j < sub_d; ++j) {
                        sub_centroids[c * sub_d + j] = new_centroids[c * sub_d + j] / counts[c];
                    }
                }
            }
        }
        
        free(assignments);
        free(new_centroids);
        free(counts);
    }
    
    return model;
}

void qihse_pq_encode(const qihse_pq_model_t* model, const float* vec, uint8_t* out_code) {
    for (size_t i = 0; i < model->m; ++i) {
        const float* sub_vec = &vec[i * model->sub_d];
        const float* sub_centroids = &model->centroids[i * model->k * model->sub_d];
        
        float min_dist = FLT_MAX;
        uint8_t best_c = 0;
        
        for (size_t c = 0; c < model->k; ++c) {
            float dist = l2_sqr(sub_vec, &sub_centroids[c * model->sub_d], model->sub_d);
            if (dist < min_dist) {
                min_dist = dist;
                best_c = (uint8_t)c;
            }
        }
        out_code[i] = best_c;
    }
}

float qihse_pq_asymmetric_distance(const qihse_pq_model_t* model, const float* query, const uint8_t* code) {
    float total_dist = 0.0f;
    for (size_t i = 0; i < model->m; ++i) {
        const float* sub_query = &query[i * model->sub_d];
        const float* centroid = &model->centroids[i * model->k * model->sub_d + code[i] * model->sub_d];
        total_dist += l2_sqr(sub_query, centroid, model->sub_d);
    }
    return total_dist;
}

void qihse_pq_free(qihse_pq_model_t* model) {
    if (model) {
        free(model->centroids);
        free(model);
    }
}
