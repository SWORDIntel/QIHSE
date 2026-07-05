#include "qihse_lua_injector.h"
#include "../backends/cpu/qihse_cpu_detect.h"
#include "../algorithms/qihse_verification.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lauxlib.h>
#include <math.h>

#ifndef _WIN32

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
<<<<<<< Updated upstream
    /* Only load safe libraries — exclude io, os, debug, package */
    lua_pushcfunction(sandbox->L, luaopen_math);
    lua_call(sandbox->L, 0, 1);
    lua_setglobal(sandbox->L, "math");
    lua_pushcfunction(sandbox->L, luaopen_string);
    lua_call(sandbox->L, 0, 1);
    lua_setglobal(sandbox->L, "string");
    lua_pushcfunction(sandbox->L, luaopen_table);
    lua_call(sandbox->L, 0, 1);
    lua_setglobal(sandbox->L, "table");
=======
    lua_pushcfunction(sandbox->L, luaopen_math); lua_pushstring(sandbox->L, "math"); lua_call(sandbox->L, 1, 1);
    lua_pushcfunction(sandbox->L, luaopen_string); lua_pushstring(sandbox->L, "string"); lua_call(sandbox->L, 1, 1);
    lua_pushcfunction(sandbox->L, luaopen_table); lua_pushstring(sandbox->L, "table"); lua_call(sandbox->L, 1, 1);
    lua_pop(sandbox->L, 3);
>>>>>>> Stashed changes
    
    sandbox->active = true;
    sandbox->instruction_quota = max_instructions;
    
    // 1. Establish the "Anti-Hang" Sandbox
    // Set a hook to fire every `max_instructions` executed.
    lua_sethook(sandbox->L, qihse_lua_quota_hook, LUA_MASKCOUNT, max_instructions);
    
    // 2. Establish Zero-Copy FFI (Foreign Function Interface) Bridge
    // Bind QIHSE SIMD-accelerated similarity functions via LuaJIT FFI so Lua
    // filter scripts can call them directly on raw vector memory.
    qihse_cpu_info_t cpu = qihse_cpu_detect();
    const char* simd_func = "qihse_cosine_similarity_scalar";
    if (cpu.features & QIHSE_CPU_FEATURE_AVX512F)
        simd_func = "qihse_cosine_similarity_avx512";
    else if (cpu.features & QIHSE_CPU_FEATURE_AVX2)
        simd_func = "qihse_cosine_similarity_avx2";

    char ffi_script[1024];
    snprintf(ffi_script, sizeof(ffi_script),
        "local ffi = require('ffi')\n"
        "ffi.cdef[[\n"
        "    double qihse_cosine_similarity_avx512(const float* a, const float* b, size_t n);\n"
        "    double qihse_cosine_similarity_avx2(const float* a, const float* b, size_t n);\n"
        "    double qihse_cosine_similarity_scalar(const float* a, const float* b, size_t n);\n"
        "    typedef struct { float* ptr; size_t dims; } qihse_vec_ref;\n"
        "]]\n"
        "qihse_sim = ffi.C.%s\n"
        "qihse_vec_ref = ffi.typeof('qihse_vec_ref')\n",
        simd_func);

    if (luaL_dostring(sandbox->L, ffi_script) != 0) {
        fprintf(stderr, "[QIHSE Lua FFI] Failed to bind FFI: %s\n", lua_tostring(sandbox->L, -1));
        lua_pop(sandbox->L, 1);
        /* Non-fatal: scripts can still use lightuserdata fallback */
    }

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
    
    // Push our Zero-Copy pointer as a FFI ctype (qihse_vec_ref) for direct
    // memory access, plus dimension count as integer.
    // The Lua script receives: qihse_vec_ref(ptr, dims), dims
    lua_getglobal(sandbox->L, "qihse_vec_ref");
    if (lua_isfunction(sandbox->L, -1) || lua_isuserdata(sandbox->L, -1)) {
        // FFI path: construct qihse_vec_ref{ptr=vec_ptr, dims=dims}
        lua_pushlightuserdata(sandbox->L, (void*)vec_ptr);
        lua_pushinteger(sandbox->L, (lua_Integer)dims);
        lua_call(sandbox->L, 2, 1);  /* qihse_vec_ref(ptr, dims) -> cdata */
        lua_pushinteger(sandbox->L, (lua_Integer)dims);
        // Execute: 2 args (vec_ref, dims), 1 return
        if (lua_pcall(sandbox->L, 2, 1, 0) != 0) {
            fprintf(stderr, "[QIHSE Lua Sandbox Error] %s\n", lua_tostring(sandbox->L, -1));
            lua_pop(sandbox->L, 1);
            return -1;
        }
    } else {
        // Fallback path: light userdata + dims (for non-FFI environments)
        lua_pop(sandbox->L, 1);  /* pop nil qihse_vec_ref */
        lua_pushlightuserdata(sandbox->L, (void*)vec_ptr);
        lua_pushinteger(sandbox->L, (lua_Integer)dims);
        if (lua_pcall(sandbox->L, 2, 1, 0) != 0) {
            fprintf(stderr, "[QIHSE Lua Sandbox Error] %s\n", lua_tostring(sandbox->L, -1));
            lua_pop(sandbox->L, 1);
            return -1;
        }
    }

    // Read the boolean return value
    int result = lua_toboolean(sandbox->L, -1);
    lua_pop(sandbox->L, 1);
    
    return result;
}

#else

bool qihse_lua_sandbox_init(qihse_lua_sandbox_t* sandbox, uint32_t max_instructions) {
    if (sandbox) sandbox->active = false;
    return false;
}

void qihse_lua_sandbox_destroy(qihse_lua_sandbox_t* sandbox) {
    if (sandbox) sandbox->active = false;
}

int qihse_lua_sandbox_filter_vector(qihse_lua_sandbox_t* sandbox, const char* script, const float* vec_ptr, size_t dims) {
    return 1; // dummy pass
}

#endif
