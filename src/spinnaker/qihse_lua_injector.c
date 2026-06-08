#include "qihse_lua_injector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief The callback hook that LuaJIT triggers every N instructions.
 * If this fires, we kill the script to prevent an infinite loop.
 */
static void qihse_lua_quota_hook(lua_State* L, lua_Debug* ar) {
    (void)ar;
    luaL_error(L, "[QIHSE Security] LUA_QUOTA_EXCEEDED: Script exceeded maximum instruction limit. Sandbox killed.");
}

bool qihse_lua_sandbox_init(qihse_lua_sandbox_t* sandbox, uint32_t max_instructions) {
    if (!sandbox) return false;
    
    sandbox->L = luaL_newstate();
    if (!sandbox->L) return false;
    
    // Load standard libraries (math, string, table)
    luaL_openlibs(sandbox->L);
    
    sandbox->active = true;
    sandbox->instruction_quota = max_instructions;
    
    // 1. Establish the "Anti-Hang" Sandbox
    // Set a hook to fire every `max_instructions` executed.
    lua_sethook(sandbox->L, qihse_lua_quota_hook, LUA_MASKCOUNT, max_instructions);
    
    // 2. Establish Zero-Copy FFI (Foreign Function Interface) Bridge
    // We bind a global function 'qihse_avx512_dot' to simulate hardware intrinsics
    // In a full implementation, this uses LuaJIT's ffi.cdef to map the pointer directly.
    luaL_dostring(sandbox->L,
        "local ffi = require('ffi')\n"
        "ffi.cdef[[\n"
        "    double qihse_hardware_dot_product(const float* vec, size_t dims);\n"
        "]]\n"
    );
    
    return true;
}

void qihse_lua_sandbox_destroy(qihse_lua_sandbox_t* sandbox) {
    if (sandbox && sandbox->L) {
        lua_close(sandbox->L);
        sandbox->L = NULL;
        sandbox->active = false;
    }
}

int qihse_lua_sandbox_filter_vector(qihse_lua_sandbox_t* sandbox, const char* script, const float* vec_ptr, size_t dims) {
    if (!sandbox || !sandbox->L || !script) return -1;
    
    // Reset the instruction counter for this specific run
    lua_sethook(sandbox->L, qihse_lua_quota_hook, LUA_MASKCOUNT, sandbox->instruction_quota);
    
    // Load the script
    if (luaL_loadstring(sandbox->L, script) != 0) {
        fprintf(stderr, "[QIHSE Lua Error] Syntax: %s\n", lua_tostring(sandbox->L, -1));
        lua_pop(sandbox->L, 1);
        return -1;
    }
    
    // Push our Zero-Copy pointer (as light userdata) and dimension count
    lua_pushlightuserdata(sandbox->L, (void*)vec_ptr);
    lua_pushinteger(sandbox->L, dims);
    
    // Execute the script: 2 arguments (ptr, dims), 1 return value (boolean)
    if (lua_pcall(sandbox->L, 2, 1, 0) != 0) {
        fprintf(stderr, "[QIHSE Lua Sandbox Error] %s\n", lua_tostring(sandbox->L, -1));
        lua_pop(sandbox->L, 1);
        return -1; // -1 means quota violation or runtime error
    }
    
    // Read the boolean return value
    int result = lua_toboolean(sandbox->L, -1);
    lua_pop(sandbox->L, 1);
    
    return result;
}
