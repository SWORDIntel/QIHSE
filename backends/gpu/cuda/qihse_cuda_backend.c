#include "qihse_cuda_backend.h"
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <dlfcn.h>
#else
#include <windows.h>
#endif
#include <math.h>

/* Function pointers for dynamic loading */
typedef void* (*cuda_init_fn)(size_t, size_t);
typedef void (*cuda_cleanup_fn)(void*);
typedef int (*cuda_search_fn)(void*, const double*, size_t, size_t, const double*, size_t, size_t*, double*);
typedef int (*cuda_compute_amplitudes_fn)(const float*, const float*, float*, size_t, size_t);

static void* g_cuda_lib_handle = NULL;
static cuda_init_fn g_cuda_init = NULL;
static cuda_cleanup_fn g_cuda_cleanup = NULL;
static cuda_search_fn g_cuda_search = NULL;
static cuda_compute_amplitudes_fn g_cuda_compute_amplitudes = NULL;

int qihse_cuda_backend_available(void) {
    if (g_cuda_lib_handle) return 1;
    
#ifdef _WIN32
    g_cuda_lib_handle = LoadLibraryA("qihse_cuda.dll");
    if (!g_cuda_lib_handle) return 0;
    
    g_cuda_init = (cuda_init_fn)GetProcAddress((HMODULE)g_cuda_lib_handle, "qihse_cuda_init");
    g_cuda_cleanup = (cuda_cleanup_fn)GetProcAddress((HMODULE)g_cuda_lib_handle, "qihse_cuda_cleanup");
    g_cuda_search = (cuda_search_fn)GetProcAddress((HMODULE)g_cuda_lib_handle, "qihse_cuda_search");
    g_cuda_compute_amplitudes = (cuda_compute_amplitudes_fn)GetProcAddress((HMODULE)g_cuda_lib_handle, "qihse_cuda_compute_amplitudes");
#else
    g_cuda_lib_handle = dlopen("libqihse_cuda.so", RTLD_LAZY);
    if (!g_cuda_lib_handle) return 0;
    
    g_cuda_init = (cuda_init_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_init");
    g_cuda_cleanup = (cuda_cleanup_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_cleanup");
    g_cuda_search = (cuda_search_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_search");
    g_cuda_compute_amplitudes = (cuda_compute_amplitudes_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_compute_amplitudes");
#endif
    
    if (!g_cuda_init || !g_cuda_cleanup || !g_cuda_search) {
#ifdef _WIN32
        FreeLibrary((HMODULE)g_cuda_lib_handle);
#else
        dlclose(g_cuda_lib_handle);
#endif
        g_cuda_lib_handle = NULL;
        return 0;
    }
    
    return 1;
}

int qihse_cuda_compute_amplitudes(const float* data, const float* query, float* scores, size_t n, size_t dims) {
    if (qihse_cuda_backend_available() && g_cuda_compute_amplitudes) {
        return g_cuda_compute_amplitudes(data, query, scores, n, dims);
    }
    
    /* CPU Fallback implementation */
    if (!data || !query || !scores) return -1;
    
    for (size_t i = 0; i < n; i++) {
        float dot_product = 0.0f;
        float norm_data = 0.0f;
        float norm_query = 0.0f;
        
        for (size_t d = 0; d < dims; d++) {
            float v1 = data[i * dims + d];
            float v2 = query[d];
            dot_product += v1 * v2;
            norm_data += v1 * v1;
            norm_query += v2 * v2;
        }
        
        if (norm_data > 0.0f && norm_query > 0.0f) {
            scores[i] = dot_product / (sqrtf(norm_data) * sqrtf(norm_query));
        } else {
            scores[i] = 0.0f;
        }
    }
    
    return 0;
}
