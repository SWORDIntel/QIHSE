# QIHSE TRITON Lua Injector

> **Security Clearance**: Internal Operations Only
> **Subsystem**: `src/spinnaker/qihse_lua_injector.c`

The TRITON Lua Injector allows analysts and downstream edge systems to dynamically inject custom filtering algorithms directly into the QIHSE Vector Database execution path. By leveraging **LuaJIT**, the engine provides near bare-metal execution speeds without requiring recompilation of the core C engine.

## Architectural Capabilities

### 1. Zero-Copy FFI (Foreign Function Interface)
In traditional database scripting (e.g., PostgreSQL PL/pgSQL or Redis Lua), data must be serialized, copied across memory boundaries, and pushed onto the interpreter stack.

The QIHSE Lua Injector completely bypasses this. Utilizing LuaJIT's `ffi` library, the raw memory pointers to the float arrays stored in the UMA/HMA arenas are injected directly as `lightuserdata`. 
* **Impact**: Scripts operate directly on the raw memory space without a single byte of serialization overhead, enabling real-time filtering of millions of vectors.

### 2. The "Anti-Hang" Sandbox (Instruction Quota)
Dynamic scripting introduces the risk of catastrophic system hangs if an analyst deploys an infinite loop (`while true do end`).
* **Implementation**: The sandbox binds `lua_sethook` with a `LUA_MASKCOUNT` mask.
* **Mechanism**: Every VM state is initialized with a strict instruction quota (e.g., 50,000 instructions per vector evaluation). If the script exceeds this quota, the VM instantly hard-kills the execution context, generates a `LUA_QUOTA_EXCEEDED` audit log, and continues processing the next vector. 

### 3. Hardware SIMD Intrinsics Exposure
Pure Lua math is fast, but hardware-accelerated math is exponentially faster.
* **Implementation**: The Sandbox automatically binds QIHSE's native C-level functions into the global Lua namespace.
* **Capabilities**: Analysts can call `qihse_hardware_dot_product(vec_ptr, dims)` directly from their injected Lua script to offload dense matrix calculations to the AVX-512 / AVX2 silicon.

---

## Technical Specification

### The Execution Lifecycle

1. **Query Initiation**: An analyst submits a standard QIHSE query (via RESP, Postgres wire, or native bindings) and attaches a compiled LuaJIT payload.
2. **Sandbox Instantiation**: `qihse_lua_sandbox_init` spins up a pristine, isolated `lua_State`. Standard libraries (math, string) are loaded, but dangerous OS libraries (os, io) are strictly prohibited.
3. **FFI Bridge Setup**: The C-pointer bindings and SIMD hardware functions are registered into the VM's global state.
4. **Execution**: For each candidate vector, `qihse_lua_sandbox_filter_vector` pushes the memory pointer and dimensions into the VM.
5. **Evaluation**: The script executes and returns a boolean (`true` to retain the vector, `false` to drop it).

### Code Example: Analyst Filtering Script

```lua
local ffi = require("ffi")

-- Target vector to compare against (e.g., a known threat signature)
local THREAT_SIGNATURE_WEIGHT = 0.85

-- The VM automatically receives (vec_ptr, dims) as arguments
local vec_ptr, dims = ...

-- 1. Execute hardware-accelerated dot product directly from Lua
local similarity = qihse_hardware_dot_product(vec_ptr, dims)

-- 2. Custom logical filtering
if similarity > THREAT_SIGNATURE_WEIGHT then
    -- Analyst logic: If dimension 4 (e.g., specific packet length feature) is spiked
    local float_array = ffi.cast("const float*", vec_ptr)
    if float_array[4] > 2.0 then
        return true -- Keep in candidate pool
    end
end

return false -- Drop from candidate pool
```

## Security Profile

* **Isolation**: Every query thread receives its own dedicated `lua_State`. Memory leaks or crashes in one VM cannot physically corrupt another.
* **Escapes**: The `os.execute` and `io` libraries are purged from the environment prior to script evaluation.
* **Denial of Service**: Strictly prevented via the aforementioned `LUA_MASKCOUNT` hook. No query can exceed its computational time budget.
