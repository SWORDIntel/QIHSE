#include "../../include/math/qihse_math_dispatch.h"
#include <stdio.h>
#include <stdbool.h>

// --- Fortran external bindings via iso_c_binding ---
// These symbols will be exported by our .f90 files
extern void fortran_pca_compress(const float* in, int* rows, int* dims, int* target, float* out);
extern void fortran_matrix_multiply(const float* a, int* ra, int* ca, const float* b, int* rb, int* cb, float* out);

// --- Native C AVX/SIMD fallbacks ---
static void c_avx_pca_compress(const float* input, size_t rows, size_t dims, size_t target, float* out) {
    // Scaffold: In reality, this would use AVX-512 to compute small covariance matrices
    printf("[DISPATCHER] Executing PCA natively in C via AVX intrinsics (Size: %zu x %zu)\n", rows, dims);
    // Dummy compression loop...
}

static void c_avx_matrix_multiply(const float* a, size_t ra, size_t ca, const float* b, size_t rb, size_t cb, float* out) {
    printf("[DISPATCHER] Executing Matrix Multiply natively in C (Size: %zu x %zu)\n", ra, cb);
}

// --- The Dynamic Dispatcher ---

void qihse_math_pca_compress(
    const float* input_matrix, 
    size_t rows, 
    size_t dims, 
    size_t target_dims, 
    float* output_matrix
) {
    size_t total_elements = rows * dims;
    
    // Dynamic Path Selection based on data amount (ataimo)
    if (total_elements > QIHSE_FORTRAN_DISPATCH_THRESHOLD) {
        printf("[DISPATCHER] Massive dataset detected (%zu elements). Routing to FORTRAN path.\n", total_elements);
        int r = (int)rows, d = (int)dims, t = (int)target_dims;
        fortran_pca_compress(input_matrix, &r, &d, &t, output_matrix);
    } else {
        printf("[DISPATCHER] Small/Medium dataset. Routing to C/AVX path for zero-latency execution.\n");
        c_avx_pca_compress(input_matrix, rows, dims, target_dims, output_matrix);
    }
}
