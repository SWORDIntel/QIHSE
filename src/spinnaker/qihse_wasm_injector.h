#ifndef QIHSE_WASM_INJECTOR_H
#define QIHSE_WASM_INJECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief WebAssembly Edge Compute Sandbox Environment
 * 
 * Provides a mathematically isolated linear memory sandbox for executing 
 * polyglot User Defined Functions (UDFs) at the edge.
 */
typedef struct qihse_wasm_sandbox_s {
    bool active;
    void* runtime_env;      // Wasmtime/Wasm3 Engine
    void* store;            // Wasmtime/Wasm3 Store
    void* module;           // Pre-compiled WASM module
    void* instance;         // Active execution instance
    
    // Linear Memory boundary for the sandbox
    uint8_t* linear_memory;
    size_t memory_size_bytes;
    
    // Hard quota for execution instructions
    uint32_t fuel_quota;
} qihse_wasm_sandbox_t;

/**
 * @brief Initializes a WebAssembly sandbox for edge UDF execution.
 * 
 * Dynamically loads the WASM runtime (e.g. libwasmtime.so) and initializes
 * the engine with strict fuel (gas) limits and isolated memory bounds.
 * 
 * @param sandbox Pointer to the uninitialized sandbox structure.
 * @param wasm_bytecode Pointer to the raw compiled .wasm binary.
 * @param bytecode_size Size of the .wasm binary.
 * @param fuel_quota The maximum number of instructions allowed before panic.
 * @return true if successfully sandboxed, false if runtime is missing or corrupt.
 */
bool qihse_wasm_sandbox_init(qihse_wasm_sandbox_t* sandbox, 
                             const uint8_t* wasm_bytecode, 
                             size_t bytecode_size, 
                             uint32_t fuel_quota);

/**
 * @brief Destroys the WebAssembly sandbox and frees its linear memory.
 */
void qihse_wasm_sandbox_destroy(qihse_wasm_sandbox_t* sandbox);

/**
 * @brief Executes a UDF inside the sandbox to filter a vector stream.
 * 
 * Safely copies the vector into the WASM linear memory, triggers the execution,
 * and reads the boolean result back without ever exposing the host pointer.
 * 
 * @param sandbox The active WASM sandbox.
 * @param function_name The exported WASM function to call (e.g., "filter_vector").
 * @param vec_ptr The raw host vector to be copied into the sandbox.
 * @param dims Number of dimensions.
 * @return 1 if the WASM logic returns true, 0 if false, -1 on Sandbox violation (OOM/Hang).
 */
int qihse_wasm_sandbox_filter_vector(qihse_wasm_sandbox_t* sandbox, 
                                     const char* function_name, 
                                     const float* vec_ptr, 
                                     size_t dims);

#ifdef __cplusplus
}
#endif

#endif // QIHSE_WASM_INJECTOR_H
