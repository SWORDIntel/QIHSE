#include "../../include/math/qihse_math_dispatch.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("--- Testing Dynamic Math Dispatch ---\n\n");
    
    // Scenario 1: Small dataset (e.g., standard vector search)
    size_t small_rows = 100;
    size_t small_dims = 128;
    float* small_out = (float*)malloc(100 * 64 * sizeof(float));
    
    printf("Scenario 1: Small query (%zu x %zu)\n", small_rows, small_dims);
    qihse_math_pca_compress(NULL, small_rows, small_dims, 64, small_out);
    
    printf("\n");
    
    // Scenario 2: Massive dataset (e.g., rebuilding index or global PCA)
    size_t large_rows = 10000;
    size_t large_dims = 1536; // Big OpenAI embedding size
    float* large_out = (float*)malloc(10000 * 128 * sizeof(float));
    
    printf("Scenario 2: Massive Re-indexing (%zu x %zu)\n", large_rows, large_dims);
    qihse_math_pca_compress(NULL, large_rows, large_dims, 128, large_out);
    
    free(small_out);
    free(large_out);
    return 0;
}
