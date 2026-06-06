#ifndef QIHSE_MATH_DISPATCH_H
#define QIHSE_MATH_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Threshold for switching from C/AVX to Fortran/BLAS (e.g., 1MB of float data)
#define QIHSE_FORTRAN_DISPATCH_THRESHOLD (256 * 1024) 

// Perform dynamic Principal Component Analysis
// Will dynamically select between Native C implementation and Fortran depending on rows*dims
void qihse_math_pca_compress(
    const float* input_matrix, 
    size_t rows, 
    size_t dims, 
    size_t target_dims, 
    float* output_matrix
);

// Perform dense matrix multiplication (Dot Product over a huge batch)
void qihse_math_matrix_multiply(
    const float* matA, size_t rowsA, size_t colsA,
    const float* matB, size_t rowsB, size_t colsB,
    float* result
);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_MATH_DISPATCH_H
