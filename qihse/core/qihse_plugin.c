#include "qihse_plugin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

qihse_error_t qihse_plugin_load_file(
    qihse_context_t ctx,
    const char* plugin_path,
    qihse_backend_t* backend
) {
    (void)ctx; (void)plugin_path; (void)backend;
    return QIHSE_ERROR_NOT_IMPLEMENTED;
}

qihse_error_t qihse_plugin_load_directory(
    qihse_context_t ctx,
    const char* plugin_dir
) {
    (void)ctx; (void)plugin_dir;
    return QIHSE_ERROR_NOT_IMPLEMENTED;
}

qihse_error_t qihse_plugin_unload(qihse_backend_t backend) {
    (void)backend;
    return QIHSE_ERROR_NOT_IMPLEMENTED;
}

qihse_error_t qihse_plugin_enumerate(
    qihse_context_t ctx,
    qihse_plugin_info_t* plugins,
    size_t* num_plugins
) {
    (void)ctx; (void)plugins;
    *num_plugins = 0;
    return QIHSE_OK;
}

qihse_error_t qihse_context_create(
    const char* config_path,
    qihse_context_t* ctx
) {
    if (!ctx) return QIHSE_ERROR_INVALID_ARGUMENT;
    (void)config_path;  /* Reserved for future config file parsing */
    *ctx = (qihse_context_t)malloc(sizeof(void*));
    return *ctx ? QIHSE_OK : QIHSE_ERROR_OUT_OF_MEMORY;
}

void qihse_context_destroy(qihse_context_t ctx) {
    free(ctx);
}

uint32_t qihse_get_abi_version(qihse_context_t ctx) {
    (void)ctx;
    return QIHSE_ABI_VERSION;
}

qihse_error_t qihse_buffer_create(
    qihse_context_t ctx,
    size_t size,
    qihse_data_type_t type,
    qihse_memory_flags_t flags,
    qihse_buffer_t* buffer
) {
    (void)ctx; (void)type; (void)flags;
    if (!buffer || size == 0) return QIHSE_ERROR_INVALID_ARGUMENT;
    buffer->data = malloc(size);
    buffer->size = size;
    buffer->type = type;
    buffer->flags = flags;
    buffer->internal_handle = NULL;
    return buffer->data ? QIHSE_OK : QIHSE_ERROR_OUT_OF_MEMORY;
}

void qihse_buffer_destroy(qihse_buffer_t* buffer) {
    if (!buffer) return;
    free(buffer->data);
    memset(buffer, 0, sizeof(qihse_buffer_t));
}

qihse_error_t qihse_buffer_copy(
    qihse_buffer_t* dst,
    const qihse_buffer_t* src
) {
    if (!dst || !src || !dst->data || !src->data) {
        return QIHSE_ERROR_INVALID_ARGUMENT;
    }
    if (dst->size < src->size) {
        return QIHSE_ERROR_MEMORY_INSUFFICIENT;
    }
    memcpy(dst->data, src->data, src->size);
    return QIHSE_OK;
}

const char* qihse_error_string(qihse_error_t error) {
    switch (error) {
        case QIHSE_OK: return "Success";
        case QIHSE_ERROR_INVALID_ARGUMENT: return "Invalid argument";
        case QIHSE_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case QIHSE_ERROR_TIMEOUT: return "Operation timeout";
        case QIHSE_ERROR_NOT_IMPLEMENTED: return "Not implemented";
        case QIHSE_ERROR_VERSION_MISMATCH: return "Version mismatch";
        case QIHSE_ERROR_BACKEND_UNAVAILABLE: return "Backend unavailable";
        case QIHSE_ERROR_BACKEND_BUSY: return "Backend busy";
        case QIHSE_ERROR_BACKEND_INCOMPATIBLE: return "Backend incompatible";
        case QIHSE_ERROR_OPERATION_INVALID: return "Invalid operation";
        case QIHSE_ERROR_OPERATION_UNSUPPORTED: return "Operation unsupported";
        case QIHSE_ERROR_OPERATION_FAILED: return "Operation failed";
        case QIHSE_ERROR_MEMORY_INVALID: return "Invalid memory";
        case QIHSE_ERROR_MEMORY_INSUFFICIENT: return "Insufficient memory";
        case QIHSE_ERROR_VERIFICATION_FAILED: return "Verification failed";
        case QIHSE_ERROR_INTEGRITY_CHECK_FAILED: return "Integrity check failed";
        default: return "Unknown error";
    }
}

const char* qihse_get_version_string(void) {
    return "QIHSE v1.0.0 (ABI 100)";
}

int qihse_check_abi_compatibility(uint32_t requested_version) {
    return (requested_version <= QIHSE_ABI_VERSION) ? 1 : 0;
}
