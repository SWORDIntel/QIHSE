#ifndef QIHSE_LUA_INJECTOR_H
#define QIHSE_LUA_INJECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/**
 * @brief Represents an isolated, pre-allocated Lua VM Sandbox for a single QIHSE query.
 */
typedef struct {
    lua_State* L;
    bool active;
    uint32_t instruction_quota;
} qihse_lua_sandbox_t;

/**
 * @brief Initializes a fresh LuaJIT Sandbox and binds the zero-copy QIHSE FFI pointers.
 * @param sandbox The sandbox context to initialize.
 * @param max_instructions The quota limit for the `while true` anti-hang hook.
 * @return true if successful, false otherwise.
 */
bool qihse_lua_sandbox_init(qihse_lua_sandbox_t* sandbox, uint32_t max_instructions);

/**
 * @brief Destroys the Lua VM and frees all resources.
 */
void qihse_lua_sandbox_destroy(qihse_lua_sandbox_t* sandbox);

/**
 * @brief Executes a pre-compiled (or JIT-traced) Lua script to filter a specific vector.
 * @param sandbox The initialized sandbox.
 * @param script The Lua script text (or bytecode).
 * @param vec_ptr The raw memory pointer to the float array in the UMA/HMA memory space.
 * @param dims Number of dimensions in the vector.
 * @return 1 if the vector passes the Lua filter, 0 if it fails, or -1 on quota violation / error.
 */
int qihse_lua_sandbox_filter_vector(qihse_lua_sandbox_t* sandbox, const char* script, const float* vec_ptr, size_t dims);

#endif /* QIHSE_LUA_INJECTOR_H */
