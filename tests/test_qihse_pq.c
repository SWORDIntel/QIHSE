#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "quantization/include/qihse_pq.h"

int main() {
    printf("--- QIHSE Product Quantization Test ---\n");
    srand(42); // deterministic

    size_t n_samples = 1000;
    size_t d = 128;
    size_t m = 8;
    size_t k = 256;
    size_t max_iter = 10;

    printf("Generating %zu random float32 vectors of dimension %zu...\n", n_samples, d);
    float* data = (float*)malloc(n_samples * d * sizeof(float));
    for (size_t i = 0; i < n_samples * d; ++i) {
        data[i] = ((float)rand() / (float)(RAND_MAX)) * 2.0f - 1.0f;
    }

    printf("Training PQ Model (m=%zu subspaces, k=%zu centroids)...\n", m, k);
    qihse_pq_model_t* model = qihse_pq_train(data, n_samples, d, m, k, max_iter);
    if (!model) {
        printf("Failed to train PQ model!\n");
        return 1;
    }

    printf("PQ Model trained successfully!\n");

    // Test Encoding
    uint8_t code[8]; // since m=8
    float query[128];
    for(size_t i=0; i<128; i++) {
        query[i] = data[i]; // Query is identical to the first vector
    }

    qihse_pq_encode(model, query, code);

    printf("Encoded vector 0 into %zu bytes: ", m);
    for (size_t i = 0; i < m; ++i) {
        printf("%02X ", code[i]);
    }
    printf("\n");

    float dist = qihse_pq_asymmetric_distance(model, query, code);
    printf("Asymmetric L2 Distance to itself (should be small due to quantization error): %f\n", dist);

    qihse_pq_free(model);
    free(data);
    
    printf("PQ Test Complete.\n");
    return 0;
}
