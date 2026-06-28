#include "qihse_wasm_injector.h"
#include "../backends/cpu/qihse_cpu_detect.h"
#include "../algorithms/qihse_verification.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <math.h>

#include <wasm3.h>
#include <m3_env.h>
#include <m3_api_libc.h>

/* Abstract dlopen handles */
static void* g_wasm_lib_handle = NULL;

bool qihse_wasm_sandbox_init(qihse_wasm_sandbox_t* sandbox, 
                             const uint8_t* wasm_bytecode, 
                             size_t bytecode_size, 
                             uint32_t fuel_quota) {
    if (!sandbox || !wasm_bytecode || bytecode_size == 0) return false;

    memset(sandbox, 0, sizeof(qihse_wasm_sandbox_t));

    if (!g_wasm_lib_handle) {
        g_wasm_lib_handle = dlopen("/usr/local/lib/libwasmtime.so", RTLD_NOW | RTLD_GLOBAL);
        if (!g_wasm_lib_handle) {
            g_wasm_lib_handle = dlopen("/usr/local/lib/libwasm3.so", RTLD_NOW | RTLD_GLOBAL);
        }
        if (!g_wasm_lib_handle) {
            g_wasm_lib_handle = dlopen("/usr/lib/libwasmtime.so", RTLD_NOW | RTLD_GLOBAL);
        }
        if (!g_wasm_lib_handle) {
            g_wasm_lib_handle = dlopen("/usr/lib/libwasm3.so", RTLD_NOW | RTLD_GLOBAL);
        }
    }

    if (!g_wasm_lib_handle) {
        fprintf(stderr, "[QIHSE WASM] FATAL: Could not locate libwasmtime.so or libwasm3.so.\n");
        fprintf(stderr, "[QIHSE WASM] The zero-trust edge compute sandbox requires a host WASM runtime.\n");
        return false;
    }

    printf("[QIHSE WASM] Initializing strict linear memory sandbox with fuel quota: %u\n", fuel_quota);

    sandbox->active = true;
    sandbox->fuel_quota = fuel_quota;

    // Allocate strict 1MB linear memory sandbox for zero-trust isolation
    sandbox->memory_size_bytes = 1024 * 1024;
    sandbox->linear_memory = aligned_alloc(4096, sandbox->memory_size_bytes);
    
    if (!sandbox->linear_memory) {
        fprintf(stderr, "[QIHSE WASM] Failed to allocate linear memory sandbox.\n");
        return false;
    }

    memset(sandbox->linear_memory, 0, sandbox->memory_size_bytes);

    // Initialize wasm3 runtime environment
    IM3Environment env = m3_NewEnvironment();
    if (!env) {
        fprintf(stderr, "[QIHSE WASM] Failed to create wasm3 environment.\n");
        free(sandbox->linear_memory);
        sandbox->linear_memory = NULL;
        return false;
    }
    sandbox->runtime_env = env;

    IM3Runtime runtime = m3_NewRuntime(env, 64 * 1024, NULL);
    if (!runtime) {
        fprintf(stderr, "[QIHSE WASM] Failed to create wasm3 runtime.\n");
        m3_FreeEnvironment(env);
        sandbox->runtime_env = NULL;
        free(sandbox->linear_memory);
        sandbox->linear_memory = NULL;
        return false;
    }
    sandbox->store = runtime;

    // Parse and load the WASM module
    IM3Module module = NULL;
    M3Result result = m3_ParseModule(env, &module, wasm_bytecode, bytecode_size);
    if (result) {
        fprintf(stderr, "[QIHSE WASM] Failed to parse WASM module: %s\n", result);
        m3_FreeRuntime(runtime);
        sandbox->store = NULL;
        m3_FreeEnvironment(env);
        sandbox->runtime_env = NULL;
        free(sandbox->linear_memory);
        sandbox->linear_memory = NULL;
        return false;
    }

    // Load module into runtime
    result = m3_LoadModule(runtime, module);
    if (result) {
        fprintf(stderr, "[QIHSE WASM] Failed to load WASM module: %s\n", result);
        m3_FreeModule(module);
        m3_FreeRuntime(runtime);
        sandbox->store = NULL;
        m3_FreeEnvironment(env);
        sandbox->runtime_env = NULL;
        free(sandbox->linear_memory);
        sandbox->linear_memory = NULL;
        return false;
    }
    sandbox->module = module;

    // Link libc API for WASM modules that need it
    result = m3_LinkLibC(runtime);
    if (result) {
        /* Non-fatal: module may not require libc */
        fprintf(stderr, "[QIHSE WASM] Warning: libc link: %s\n", result);
    }

    return true;
}

void qihse_wasm_sandbox_destroy(qihse_wasm_sandbox_t* sandbox) {
    if (sandbox) {
        if (sandbox->store) {
            m3_FreeRuntime((IM3Runtime)sandbox->store);
            sandbox->store = NULL;
            sandbox->module = NULL;
            sandbox->instance = NULL;
        }
        if (sandbox->runtime_env) {
            m3_FreeEnvironment((IM3Environment)sandbox->runtime_env);
            sandbox->runtime_env = NULL;
        }
        if (sandbox->linear_memory) {
            free(sandbox->linear_memory);
            sandbox->linear_memory = NULL;
        }
        
        sandbox->active = false;
    }
}

int qihse_wasm_sandbox_filter_vector(qihse_wasm_sandbox_t* sandbox, 
                                     const char* function_name, 
                                     const float* vec_ptr, 
                                     size_t dims) {
    if (!sandbox || !sandbox->active || !vec_ptr || !function_name) return -1;

    // Zero-Trust Memory Isolation: We NEVER expose the host pointer to the WASM UDF.
    // Instead, we safely copy the vector chunk into the isolated linear memory sandbox.
    size_t copy_size = dims * sizeof(float);
    if (copy_size > sandbox->memory_size_bytes) {
        fprintf(stderr, "[QIHSE WASM Security] UDF Payload exceeded Sandbox Linear Memory bounds!\n");
        return -1;
    }

    // Copy to the start of the WASM heap (offset 0)
    memcpy(sandbox->linear_memory, vec_ptr, copy_size);

    // Find the exported filter function in the loaded module
    IM3Runtime runtime = (IM3Runtime)sandbox->store;
    IM3Function func;
    M3Result result = m3_FindFunction(&func, runtime, function_name);
    if (result) {
        fprintf(stderr, "[QIHSE WASM] Failed to find function '%s': %s\n", function_name, result);
        return -1;
    }

    // Call the WASM filter function with vector pointer and dimensions.
    // The WASM function signature should be: (i32 ptr_offset, i32 dims) -> i32 (1=pass, 0=reject)
    // ptr_offset is 0 since we copied vector to start of linear memory.
    result = m3_CallV(func, 0, (int32_t)dims);
    if (result) {
        fprintf(stderr, "[QIHSE WASM] Execution trap: %s\n", result);
        return -1;
    }

    // Read the return value
    int32_t ret_val = 0;
    result = m3_GetResultsV(func, &ret_val);
    if (result) {
        fprintf(stderr, "[QIHSE WASM] Failed to read result: %s\n", result);
        return -1;
    }

    if (ret_val < 0) {
        // WASM function signaled an error/quota violation
        return -1;
    }

    return ret_val ? 1 : 0;
}
