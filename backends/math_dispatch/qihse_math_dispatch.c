#include "../../include/math/qihse_math_dispatch.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

extern void fortran_pca_compress(const float* in, int* rows, int* dims, int* target, float* out);
extern void fortran_matrix_multiply(const float* a, int* ra, int* ca, const float* b, int* rb, int* cb, float* out);

static void c_avx_pca_compress(const float* input, size_t rows, size_t dims, size_t target, float* out) {
    if (!input || !out || rows == 0 || dims == 0 || target == 0) return;
    if (target > dims) target = dims;

    /* Step 1: Compute column means */
    double* means = (double*)calloc(dims, sizeof(double));
    if (!means) return;
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < dims; j++) {
            means[j] += (double)input[i * dims + j];
        }
    }
    for (size_t j = 0; j < dims; j++) {
        means[j] /= (double)rows;
    }

    /* Step 2: Compute covariance matrix (dims x dims) */
    double* cov = (double*)calloc(dims * dims, sizeof(double));
    if (!cov) { free(means); return; }
    for (size_t i = 0; i < rows; i++) {
        for (size_t a = 0; a < dims; a++) {
            double da = (double)input[i * dims + a] - means[a];
            for (size_t b = a; b < dims; b++) {
                double db = (double)input[i * dims + b] - means[b];
                cov[a * dims + b] += da * db;
                if (a != b) cov[b * dims + a] += da * db;
            }
        }
    }
    double inv_n = 1.0 / (double)(rows > 1 ? rows - 1 : 1);
    for (size_t i = 0; i < dims * dims; i++) cov[i] *= inv_n;

    /* Step 3: Power iteration to find top `target` eigenvectors */
    double* eigenvectors = (double*)calloc(dims * target, sizeof(double));
    double* residual_cov = (double*)malloc(dims * dims * sizeof(double));
    if (!eigenvectors || !residual_cov) {
        free(means); free(cov); free(eigenvectors); free(residual_cov);
        return;
    }
    memcpy(residual_cov, cov, dims * dims * sizeof(double));

    for (size_t k = 0; k < target; k++) {
        /* Initialize random vector */
        double* v = (double*)calloc(dims, sizeof(double));
        double* v_new = (double*)calloc(dims, sizeof(double));
        if (!v || !v_new) { free(v); free(v_new); break; }
        for (size_t i = 0; i < dims; i++) v[i] = (double)(i + 1) / (double)dims;

        /* Normalize initial vector */
        double norm = 0.0;
        for (size_t i = 0; i < dims; i++) norm += v[i] * v[i];
        norm = sqrt(norm);
        if (norm > 0) for (size_t i = 0; i < dims; i++) v[i] /= norm;

        /* Power iteration */
        for (int iter = 0; iter < 100; iter++) {
            /* v_new = residual_cov * v */
            for (size_t i = 0; i < dims; i++) {
                v_new[i] = 0.0;
                for (size_t j = 0; j < dims; j++) {
                    v_new[i] += residual_cov[i * dims + j] * v[j];
                }
            }
            /* Normalize */
            norm = 0.0;
            for (size_t i = 0; i < dims; i++) norm += v_new[i] * v_new[i];
            norm = sqrt(norm);
            if (norm < 1e-15) break;
            for (size_t i = 0; i < dims; i++) v[i] = v_new[i] / norm;
        }

        /* Store eigenvector */
        for (size_t i = 0; i < dims; i++) {
            eigenvectors[k * dims + i] = v[i];
        }

        /* Deflate: remove this component from covariance */
        /* eigenvalue = v^T * cov * v */
        double eigenvalue = 0.0;
        for (size_t i = 0; i < dims; i++) {
            for (size_t j = 0; j < dims; j++) {
                eigenvalue += v[i] * residual_cov[i * dims + j] * v[j];
            }
        }
        /* cov -= eigenvalue * v * v^T */
        for (size_t i = 0; i < dims; i++) {
            for (size_t j = 0; j < dims; j++) {
                residual_cov[i * dims + j] -= eigenvalue * v[i] * v[j];
            }
        }

        free(v);
        free(v_new);
    }

    /* Step 4: Project data onto eigenvectors */
    for (size_t i = 0; i < rows; i++) {
        for (size_t k = 0; k < target; k++) {
            double val = 0.0;
            for (size_t j = 0; j < dims; j++) {
                double centered = (double)input[i * dims + j] - means[j];
                val += centered * eigenvectors[k * dims + j];
            }
            out[i * target + k] = (float)val;
        }
    }

    free(means);
    free(cov);
    free(eigenvectors);
    free(residual_cov);
}

static void c_avx_matrix_multiply(const float* a, size_t ra, size_t ca, const float* b, size_t rb, size_t cb, float* out) {
    if (!a || !b || !out || ca != rb) return;
    (void)rb;
    for (size_t i = 0; i < ra; i++) {
        for (size_t j = 0; j < cb; j++) {
            float sum = 0.0f;
            for (size_t k = 0; k < ca; k++) {
                sum += a[i * ca + k] * b[k * cb + j];
            }
            out[i * cb + j] = sum;
        }
    }
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
