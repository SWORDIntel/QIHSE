#include "qihse_cuda_backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* Function pointers for dynamic loading */
typedef void* (*cuda_init_fn)(size_t, size_t);
typedef void (*cuda_cleanup_fn)(void*);
typedef int (*cuda_search_fn)(void*, const double*, size_t, size_t, const double*, size_t, size_t*, double*);

static void* g_cuda_lib_handle = NULL;
static cuda_init_fn g_cuda_init = NULL;
static cuda_cleanup_fn g_cuda_cleanup = NULL;
static cuda_search_fn g_cuda_search = NULL;

int qihse_cuda_backend_available(void) {
    if (g_cuda_lib_handle) return 1;
    
    g_cuda_lib_handle = dlopen("libqihse_cuda.so", RTLD_LAZY);
    if (!g_cuda_lib_handle) return 0;
    
    g_cuda_init = (cuda_init_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_init");
    g_cuda_cleanup = (cuda_cleanup_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_cleanup");
    g_cuda_search = (cuda_search_fn)dlsym(g_cuda_lib_handle, "qihse_cuda_search");
    
    if (!g_cuda_init || !g_cuda_cleanup || !g_cuda_search) {
        dlclose(g_cuda_lib_handle);
        g_cuda_lib_handle = NULL;
        return 0;
    }
    
    return 1;
}

int qihse_cuda_compute_amplitudes(const float* data, const float* query, float* scores, size_t n, size_t dims) {
    /* Fallback if CUDA not available or not yet compiled */
    /* In a production environment, this would call the d_ probabilities calculation */
    return -1; 
}
