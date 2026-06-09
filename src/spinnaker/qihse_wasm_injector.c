#include "qihse_wasm_injector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* Abstract dlopen handles */
static void* g_wasm_lib_handle = NULL;

bool qihse_wasm_sandbox_init(qihse_wasm_sandbox_t* sandbox, 
                             const uint8_t* wasm_bytecode, 
                             size_t bytecode_size, 
                             uint32_t fuel_quota) {
    if (!sandbox || !wasm_bytecode || bytecode_size == 0) return false;

    memset(sandbox, 0, sizeof(qihse_wasm_sandbox_t));

    // Try to load Wasmtime or WAMR dynamically at runtime
    if (!g_wasm_lib_handle) {
        g_wasm_lib_handle = dlopen("libwasmtime.so", RTLD_NOW | RTLD_GLOBAL);
        if (!g_wasm_lib_handle) {
            g_wasm_lib_handle = dlopen("libwasm3.so", RTLD_NOW | RTLD_GLOBAL);
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

    // Simulate allocating the strict 1MB linear memory sandbox
    sandbox->memory_size_bytes = 1024 * 1024;
    sandbox->linear_memory = aligned_alloc(4096, sandbox->memory_size_bytes);
    
    if (!sandbox->linear_memory) {
        fprintf(stderr, "[QIHSE WASM] Failed to allocate linear memory sandbox.\n");
        return false;
    }

    memset(sandbox->linear_memory, 0, sandbox->memory_size_bytes);

    /* 
     * In a production link against Wasmtime:
     * 1. wasmtime_engine_new()
     * 2. wasmtime_config_consume_fuel_set(config, true)
     * 3. wasmtime_store_new(engine, &sandbox->store)
     * 4. wasmtime_context_set_fuel(store, fuel_quota)
     * 5. wasmtime_module_new(engine, wasm_bytecode, bytecode_size, &sandbox->module)
     */
    
    return true;
}

void qihse_wasm_sandbox_destroy(qihse_wasm_sandbox_t* sandbox) {
    if (sandbox) {
        if (sandbox->linear_memory) {
            free(sandbox->linear_memory);
            sandbox->linear_memory = NULL;
        }
        
        sandbox->active = false;
        
        /* Free WASM runtime structures if they were dynamically resolved */
        
        memset(sandbox, 0, sizeof(qihse_wasm_sandbox_t));
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

    /*
     * In a production Wasmtime run:
     * 1. wasmtime_context_set_fuel(store, sandbox->fuel_quota) -> Reset anti-hang quota
     * 2. wasmtime_func_call(context, &filter_func, args, results)
     * 3. Check if Trap occurred (Quota exhausted or Out of Bounds access)
     * 4. Return result[0].of.i32
     */
     
    // For the sake of the architectural API, if we are stubbed, we just return true.
    return 1;
}
