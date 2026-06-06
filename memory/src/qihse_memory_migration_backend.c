/*
 * QIHSE - Memory Migration Backend Helpers
 */

#include "../include/qihse_memory_migration_backend.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if QIHSE_MEMORY_MIGRATION_BACKEND_ENABLE_CUDA
#include <dlfcn.h>
#endif
#include <pthread.h>

static qihse_memory_migration_backend_registry_t g_qihse_memory_migration_backend_registry;
static bool g_qihse_memory_migration_backend_platform_backends_initialized = false;
static bool g_qihse_memory_migration_backend_platform_backends_registered = false;

#if QIHSE_MEMORY_MIGRATION_BACKEND_ENABLE_CUDA
typedef int qihse_memory_migration_backend_cuda_error_t;
typedef qihse_memory_migration_backend_cuda_error_t (
    *qihse_memory_migration_backend_cuda_memcpy_fn_t)(
    void* dst,
    const void* src,
    size_t byte_count,
    unsigned int kind
);
typedef const char* (*qihse_memory_migration_backend_cuda_error_string_fn_t)(
    qihse_memory_migration_backend_cuda_error_t error
);

typedef struct qihse_memory_migration_backend_cuda_copy_backend_s {
    void* library;
    qihse_memory_migration_backend_cuda_memcpy_fn_t memcpy_fn;
    qihse_memory_migration_backend_cuda_error_string_fn_t error_string_fn;
} qihse_memory_migration_backend_cuda_copy_backend_t;

static const char* const g_qihse_memory_migration_backend_cuda_lib_names[] = {
    "/usr/local/cuda/lib64/libcudart.so",
    "/usr/local/cuda/lib64/libcudart.so.12",
    "/usr/local/cuda/lib64/libcudart.so.11.0",
    "/usr/local/cuda/lib64/libcudart.so.11"
};

static qihse_memory_migration_backend_cuda_copy_backend_t
    g_qihse_memory_migration_backend_cuda_copy_backend = {NULL, NULL, NULL};

#define QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_HOST_TO_HOST 0u
#define QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_HOST_TO_DEVICE 1u
#define QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_DEVICE_TO_HOST 2u
#define QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_DEVICE_TO_DEVICE 3u

static bool qihse_memory_migration_backend_is_host_memory_type(
    qihse_memory_type_t memory_type
) {
    return memory_type == QIHSE_MEM_HOST ||
        memory_type == QIHSE_MEM_PINNED ||
        memory_type == QIHSE_MEM_UNIFIED ||
        memory_type == QIHSE_MEM_HMA_SUPERPOSITION ||
        memory_type == QIHSE_MEM_HMA_INTERACTION ||
        memory_type == QIHSE_MEM_HMA_ENTANGLEMENT ||
        memory_type == QIHSE_MEM_ANCHOR_TABLE ||
        memory_type == QIHSE_MEM_ANCHOR_WORKSPACE;
}

static bool qihse_memory_migration_backend_is_device_memory_type(
    qihse_memory_type_t memory_type
) {
    return memory_type == QIHSE_MEM_DEVICE;
}

static qihse_memory_migration_backend_status_t
qihse_memory_migration_backend_cuda_copy_kind(
    const qihse_memory_migration_backend_request_t* request,
    unsigned int* kind
) {
    if (kind == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    if (request == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    {
        bool source_is_host = qihse_memory_migration_backend_is_host_memory_type(
            request->source_type);
        bool target_is_host = qihse_memory_migration_backend_is_host_memory_type(
            request->target_type);
        bool source_is_device = qihse_memory_migration_backend_is_device_memory_type(
            request->source_type);
        bool target_is_device = qihse_memory_migration_backend_is_device_memory_type(
            request->target_type);

        if (source_is_host && target_is_host) {
            *kind = QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_HOST_TO_HOST;
            return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
        }

        if (source_is_host && target_is_device) {
            *kind = QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_HOST_TO_DEVICE;
            return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
        }

        if (source_is_device && target_is_host) {
            *kind = QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_DEVICE_TO_HOST;
            return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
        }

        if (source_is_device && target_is_device) {
            *kind = QIHSE_MEMORY_MIGRATION_BACKEND_CUDA_MEMCPY_DEVICE_TO_DEVICE;
            return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
        }
    }

    return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
}

static qihse_memory_migration_backend_status_t
qihse_memory_migration_backend_init_cuda_copy_backend(
    qihse_memory_migration_backend_cuda_copy_backend_t* backend
) {
    size_t library_index;
    qihse_memory_migration_backend_cuda_memcpy_fn_t memcpy_fn = NULL;
    qihse_memory_migration_backend_cuda_error_string_fn_t error_string_fn = NULL;

    if (backend == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    if (backend->memcpy_fn != NULL && backend->library != NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
    }

    for (library_index = 0u;
         library_index <
         sizeof(g_qihse_memory_migration_backend_cuda_lib_names) /
         sizeof(g_qihse_memory_migration_backend_cuda_lib_names[0u]);
         ++library_index) {
        const char* library_name =
            g_qihse_memory_migration_backend_cuda_lib_names[library_index];
        void* library = dlopen(library_name, RTLD_LAZY);

        if (library == NULL) {
            continue;
        }

        memcpy_fn = (qihse_memory_migration_backend_cuda_memcpy_fn_t)dlsym(
            library,
            "cudaMemcpy"
        );
        if (memcpy_fn == NULL) {
            dlclose(library);
            continue;
        }

        error_string_fn =
            (qihse_memory_migration_backend_cuda_error_string_fn_t)dlsym(
                library,
                "cudaGetErrorString"
            );

        backend->library = library;
        backend->memcpy_fn = memcpy_fn;
        backend->error_string_fn = error_string_fn;
        return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
    }

    return QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA;
}

static qihse_memory_migration_backend_status_t
qihse_memory_migration_backend_cuda_copy(
    const qihse_memory_migration_backend_request_t* request,
    void* user_context
) {
    qihse_memory_migration_backend_cuda_copy_backend_t* backend;
    qihse_memory_migration_backend_status_t status;
    unsigned int cuda_kind;
    qihse_memory_migration_backend_cuda_error_t cuda_status;

    status = qihse_memory_migration_backend_validate_host_memcpy(request);
    if (status != QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
        return status;
    }

    backend = (qihse_memory_migration_backend_cuda_copy_backend_t*)user_context;
    if (backend == NULL || backend->memcpy_fn == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE;
    }

    status = qihse_memory_migration_backend_cuda_copy_kind(request, &cuda_kind);
    if (status != QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
        return status;
    }

    if (request->byte_count == 0u) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
    }

    cuda_status = backend->memcpy_fn(
        request->dst,
        request->src,
        request->byte_count,
        cuda_kind
    );
    if (cuda_status != 0) {
        if (backend->error_string_fn != NULL) {
            (void)backend->error_string_fn(cuda_status);
        }
        return QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE;
    }

    return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
}

bool qihse_memory_migration_backend_register_cuda_backends(void) {
    bool registered = false;

    if (qihse_memory_migration_backend_init_cuda_copy_backend(
            &g_qihse_memory_migration_backend_cuda_copy_backend)
        != QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
        return false;
    }

    if (qihse_memory_migration_backend_register_copy_callback(
            QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA,
            qihse_memory_migration_backend_cuda_copy,
            &g_qihse_memory_migration_backend_cuda_copy_backend)) {
        registered = true;
    }

    if (qihse_memory_migration_backend_register_copy_callback(
            QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY,
            qihse_memory_migration_backend_cuda_copy,
            &g_qihse_memory_migration_backend_cuda_copy_backend)) {
        registered = true;
    }

    return registered;
}
#endif

static qihse_memory_migration_backend_copy_fn
qihse_memory_migration_backend_callback_for(
    qihse_memory_migration_backend_t backend,
    void** user_context
) {
    switch (backend) {
        case QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA:
            if (user_context != NULL) {
                *user_context = g_qihse_memory_migration_backend_registry.hardware_dma_context;
            }
            return g_qihse_memory_migration_backend_registry.hardware_dma_copy;
        case QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY:
            if (user_context != NULL) {
                *user_context = g_qihse_memory_migration_backend_registry.device_copy_context;
            }
            return g_qihse_memory_migration_backend_registry.device_copy;
        default:
            break;
    }

    if (user_context != NULL) {
        *user_context = NULL;
    }
    return NULL;
}

bool qihse_memory_migration_backend_lookup_copy_callback(
    qihse_memory_migration_backend_t backend,
    qihse_memory_migration_backend_copy_fn* callback,
    void** user_context
) {
    if (callback == NULL) {
        return false;
    }

    *callback = qihse_memory_migration_backend_callback_for(backend, user_context);
    return *callback != NULL;
}

static pthread_mutex_t g_qihse_memory_migration_backend_platform_backends_mutex = PTHREAD_MUTEX_INITIALIZER;

bool qihse_memory_migration_backend_register_platform_backends(void) {
    pthread_mutex_lock(&g_qihse_memory_migration_backend_platform_backends_mutex);
    if (g_qihse_memory_migration_backend_platform_backends_initialized) {
        bool registered = g_qihse_memory_migration_backend_platform_backends_registered;
        pthread_mutex_unlock(&g_qihse_memory_migration_backend_platform_backends_mutex);
        return registered;
    }

    bool registered = false;

#if QIHSE_MEMORY_MIGRATION_BACKEND_ENABLE_CUDA
    if (qihse_memory_migration_backend_register_cuda_backends()) {
        registered = true;
    }
#endif

    g_qihse_memory_migration_backend_platform_backends_initialized = true;
    g_qihse_memory_migration_backend_platform_backends_registered = registered;
    pthread_mutex_unlock(&g_qihse_memory_migration_backend_platform_backends_mutex);
    return registered;
}

static bool qihse_memory_migration_backend_range_overflows(
    const void* ptr,
    size_t byte_count
) {
    uintptr_t start;

    if (byte_count == 0u) {
        return false;
    }

    if (ptr == NULL) {
        return false;
    }

    start = (uintptr_t)ptr;
    return start > UINTPTR_MAX - (uintptr_t)byte_count;
}

static bool qihse_memory_migration_backend_ranges_overlap(
    const void* dst,
    const void* src,
    size_t byte_count
) {
    uintptr_t dst_start;
    uintptr_t dst_end;
    uintptr_t src_start;
    uintptr_t src_end;

    if (byte_count == 0u || dst == src) {
        return false;
    }

    dst_start = (uintptr_t)dst;
    src_start = (uintptr_t)src;
    dst_end = dst_start + (uintptr_t)byte_count;
    src_end = src_start + (uintptr_t)byte_count;

    return dst_start < src_end && src_start < dst_end;
}

static qihse_memory_migration_backend_status_t
qihse_memory_migration_backend_validate_host_memcpy(
    const qihse_memory_migration_backend_request_t* request
) {
    if (request == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    if (request->byte_count > 0u &&
        (request->dst == NULL || request->src == NULL)) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    if (qihse_memory_migration_backend_range_overflows(
            request->dst,
            request->byte_count) ||
        qihse_memory_migration_backend_range_overflows(
            request->src,
            request->byte_count)) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_RANGE_OVERFLOW;
    }

    if (qihse_memory_migration_backend_ranges_overlap(
            request->dst,
            request->src,
            request->byte_count)) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_OVERLAP_UNSUPPORTED;
    }

    return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
}

const char* qihse_memory_migration_backend_name(
    qihse_memory_migration_backend_t backend
) {
    switch (backend) {
        case QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY:
            return "host_memcpy";
        case QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA:
            return "hardware_dma";
        case QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY:
            return "device_copy";
        default:
            return "unknown";
    }
}

const char* qihse_memory_migration_backend_status_name(
    qihse_memory_migration_backend_status_t status
) {
    switch (status) {
        case QIHSE_MEMORY_MIGRATION_BACKEND_OK:
            return "ok";
        case QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT:
            return "invalid_argument";
        case QIHSE_MEMORY_MIGRATION_BACKEND_RANGE_OVERFLOW:
            return "range_overflow";
        case QIHSE_MEMORY_MIGRATION_BACKEND_OVERLAP_UNSUPPORTED:
            return "overlap_unsupported";
        case QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA:
            return "unsupported_dma";
        case QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE:
            return "unsupported_device";
        case QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_BACKEND:
            return "unsupported_backend";
        default:
            return "unknown";
    }
}

bool qihse_memory_migration_backend_is_supported(
    qihse_memory_migration_backend_t backend
) {
    void* context;

    if (backend == QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY) {
        return true;
    }

    (void)qihse_memory_migration_backend_register_platform_backends();
    context = NULL;
    return qihse_memory_migration_backend_callback_for(backend, &context) != NULL;
}

void qihse_memory_migration_backend_init_registry(
    qihse_memory_migration_backend_registry_t* registry
) {
    if (registry == NULL) {
        return;
    }

    registry->hardware_dma_copy = NULL;
    registry->hardware_dma_context = NULL;
    registry->device_copy = NULL;
    registry->device_copy_context = NULL;
}

bool qihse_memory_migration_backend_register_copy_callback(
    qihse_memory_migration_backend_t backend,
    qihse_memory_migration_backend_copy_fn callback,
    void* user_context
) {
    switch (backend) {
        case QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA:
            g_qihse_memory_migration_backend_registry.hardware_dma_copy = callback;
            g_qihse_memory_migration_backend_registry.hardware_dma_context = user_context;
            return true;
        case QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY:
            g_qihse_memory_migration_backend_registry.device_copy = callback;
            g_qihse_memory_migration_backend_registry.device_copy_context = user_context;
            return true;
        case QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY:
            return false;
        default:
            return false;
    }
}

qihse_memory_migration_backend_request_t qihse_memory_migration_backend_request(
    void* dst,
    const void* src,
    size_t byte_count,
    qihse_memory_migration_backend_t backend
) {
    qihse_memory_migration_backend_request_t request;

    request.dst = dst;
    request.src = src;
    request.byte_count = byte_count;
    request.source_type = QIHSE_MEM_HOST;
    request.target_type = QIHSE_MEM_HOST;
    request.source_device = -1;
    request.target_device = -1;
    request.backend = backend;
    request.backend_context = NULL;

    return request;
}

qihse_memory_migration_backend_status_t qihse_memory_migration_backend_plan(
    const qihse_memory_migration_backend_request_t* request,
    qihse_memory_migration_backend_plan_t* plan
) {
    qihse_memory_migration_backend_status_t status;

    if (plan == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    plan->backend = request != NULL
        ? request->backend
        : QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY;
    plan->status = QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    plan->byte_count = request != NULL ? request->byte_count : 0u;
    plan->executable = false;
    plan->preserves_bytes = false;

    if (request == NULL) {
        return plan->status;
    }

    switch (request->backend) {
        case QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY:
            status = qihse_memory_migration_backend_validate_host_memcpy(
                request
            );
            break;
        case QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA:
            status = qihse_memory_migration_backend_validate_host_memcpy(request);
            if (status == QIHSE_MEMORY_MIGRATION_BACKEND_OK &&
                !qihse_memory_migration_backend_is_supported(
                    QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA)) {
                status = QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA;
            }
            break;
        case QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY:
            status = qihse_memory_migration_backend_validate_host_memcpy(request);
            if (status == QIHSE_MEMORY_MIGRATION_BACKEND_OK &&
                !qihse_memory_migration_backend_is_supported(
                    QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY)) {
                status = QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE;
            }
            break;
        default:
            status = QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_BACKEND;
            break;
    }

    plan->status = status;
    plan->executable = status == QIHSE_MEMORY_MIGRATION_BACKEND_OK;
    plan->preserves_bytes = plan->executable;

    return status;
}

qihse_memory_migration_backend_status_t qihse_memory_migration_backend_execute_plan(
    const qihse_memory_migration_backend_request_t* request,
    const qihse_memory_migration_backend_plan_t* plan
) {
    qihse_memory_migration_backend_status_t status;

    if (request == NULL || plan == NULL) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    if (!plan->executable || plan->status != QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
        return plan->status;
    }

    if (plan->backend != request->backend ||
        plan->byte_count != request->byte_count) {
        return QIHSE_MEMORY_MIGRATION_BACKEND_INVALID_ARGUMENT;
    }

    switch (request->backend) {
        case QIHSE_MEMORY_MIGRATION_BACKEND_HOST_MEMCPY:
            status = qihse_memory_migration_backend_validate_host_memcpy(
                request
            );
            if (status != QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
                return status;
            }
            if (request->byte_count > 0u && request->dst != request->src) {
                memcpy(request->dst, request->src, request->byte_count);
            }
            return QIHSE_MEMORY_MIGRATION_BACKEND_OK;
        case QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA:
            {
                void* user_context = NULL;
                qihse_memory_migration_backend_copy_fn callback =
                    qihse_memory_migration_backend_callback_for(
                        request->backend,
                        &user_context);

                if (callback == NULL) {
                    return request->backend ==
                        QIHSE_MEMORY_MIGRATION_BACKEND_HARDWARE_DMA
                        ? QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DMA
                        : QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_BACKEND;
                }

                if (request->backend_context != NULL) {
                    user_context = request->backend_context;
                }

                return callback(request, user_context);
            }
        case QIHSE_MEMORY_MIGRATION_BACKEND_DEVICE_COPY:
            {
                void* user_context = NULL;
                qihse_memory_migration_backend_copy_fn callback =
                    qihse_memory_migration_backend_callback_for(
                        request->backend,
                        &user_context);

                if (callback == NULL) {
                    return QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_DEVICE;
                }

                if (request->backend_context != NULL) {
                    user_context = request->backend_context;
                }

                return callback(request, user_context);
            }
        default:
            return QIHSE_MEMORY_MIGRATION_BACKEND_UNSUPPORTED_BACKEND;
    }
}

qihse_memory_migration_backend_status_t qihse_memory_migration_backend_execute(
    const qihse_memory_migration_backend_request_t* request
) {
    qihse_memory_migration_backend_plan_t plan;
    qihse_memory_migration_backend_status_t status;

    status = qihse_memory_migration_backend_plan(request, &plan);
    if (status != QIHSE_MEMORY_MIGRATION_BACKEND_OK) {
        return status;
    }

    return qihse_memory_migration_backend_execute_plan(request, &plan);
}
