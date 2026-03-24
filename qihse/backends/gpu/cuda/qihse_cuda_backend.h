#ifndef QIHSE_CUDA_BACKEND_H
#define QIHSE_CUDA_BACKEND_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int qihse_cuda_compute_amplitudes(const float* data, const float* query, float* scores, size_t n, size_t dims);
#ifdef __cplusplus
}
#endif
#endif
