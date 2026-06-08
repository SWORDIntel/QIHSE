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

-- Target vector to compare against (e.g., a known user preference profile)
local PREFERENCE_WEIGHT = 0.85

-- The VM automatically receives (vec_ptr, dims) as arguments
local vec_ptr, dims = ...

-- 1. Execute hardware-accelerated dot product directly from Lua
local similarity = qihse_hardware_dot_product(vec_ptr, dims)

-- 2. Custom logical filtering
if similarity > PREFERENCE_WEIGHT then
    -- Analyst logic: If dimension 4 (e.g., price sensitivity feature) is high
    local float_array = ffi.cast("const float*", vec_ptr)
    if float_array[4] > 2.0 then
        return true -- Keep in candidate pool
    end
end

return false -- Drop from candidate pool
```

## Advanced Execution Examples

The Lua environment is highly flexible. Below are three tactical examples demonstrating the power of zero-copy vector filtering.

### Example 1: E-Commerce Multi-Dimensional Filtering
Use this script to filter product recommendations where multiple distinct user preferences must simultaneously breach a threshold before the product is shown to the user.

```lua
local ffi = require("ffi")

local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

local matching_preferences = 0

-- Check specific vector dimensions representing distinct product features:
-- Index 14: Category affinity
-- Index 22: Brand loyalty score
-- Index 31: Discount sensitivity

if vec[14] > 0.92 then matching_preferences = matching_preferences + 1 end
if vec[22] > 3.50 then matching_preferences = matching_preferences + 1 end
if vec[31] > 0.88 then matching_preferences = matching_preferences + 1 end

-- Only return true if at least two critical preferences match
return matching_preferences >= 2
```

### Example 2: Financial Anomaly Masking
This script masks out (ignores) certain dimensions of the vector during the hardware dot-product to dynamically adjust the fraud detection search space without recalculating the entire index.

```lua
local ffi = require("ffi")

local vec_ptr, dims = ...
local vec = ffi.cast("float*", vec_ptr) -- Mutable cast for temporal masking

-- Store original values
local orig_10 = vec[10]
local orig_11 = vec[11]

-- Temporarily mask out dimensions 10 and 11 (e.g., ignoring seasonal transaction volume spikes)
vec[10] = 0.0
vec[11] = 0.0

-- Perform the hardware similarity check on the masked vector against a known fraud profile
local similarity = qihse_hardware_dot_product(vec, dims)

-- Restore the original memory state (Zero-copy integrity)
vec[10] = orig_10
vec[11] = orig_11

-- Keep candidates with a similarity over 95%
return similarity > 0.95
```

### Example 3: Sensor Data Jitter Analysis
If a vector encodes the temporal variance of an IoT sensor (e.g. temperature readings), developers can write mathematical logic directly into the database to identify failing hardware.

```lua
local ffi = require("ffi")
local math = require("math")

local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- Assume dimensions 0 through 9 contain the delta times between the last 10 sensor reads
local mean = 0
for i=0, 9 do
    mean = mean + vec[i]
end
mean = mean / 10

local variance = 0
for i=0, 9 do
    local diff = vec[i] - mean
    variance = variance + (diff * diff)
end
variance = variance / 10

-- A variance below 0.05 indicates highly rigid, possibly stuck sensor polling hardware
if variance < 0.05 and mean > 10.0 and mean < 60.0 then
    return true -- Flag for maintenance
end

return false
```

### Example 4: Signals Intelligence (SIGINT) - Sub-band Entropy Fingerprinting
This represents a highly specialized, power-user plugin used in intelligence operations. The script analyzes a vector containing network packet inter-arrival times to identify an adversary attempting to exfiltrate data via a covert timing side-channel.

```lua
local ffi = require("ffi")

local vec_ptr, dims = ...
local vec = ffi.cast("const float*", vec_ptr)

-- Dimensions 100-115 contain the spectral entropy coefficients of a target's TLS connection
-- Dimensions 116-120 contain the phase-shift deviations of the packet arrival times

local high_entropy_bands = 0
for i = 100, 115 do
    -- Evasive exfiltration payloads (like XChaCha20 streams hiding inside standard TLS)
    -- will generate a nearly perfect entropy coefficient (close to 1.0)
    if vec[i] > 0.995 then
        high_entropy_bands = high_entropy_bands + 1
    end
end

local phase_shift_variance = 0
for i = 116, 120 do
    phase_shift_variance = phase_shift_variance + math.abs(vec[i])
end
phase_shift_variance = phase_shift_variance / 5

-- If the target is injecting covert timing delays, the phase shift variance will spike,
-- and the underlying payload entropy will remain suspiciously perfect across multiple bands.
if high_entropy_bands > 12 and phase_shift_variance > 45.0 then
    -- Analyst logic: Cross-validate against the target's baseline hardware profile similarity
    local baseline_similarity = qihse_hardware_dot_product(vec_ptr, dims)
    if baseline_similarity > 0.88 then
        return true -- Flag for immediate tactical intercept
    end
end

return false -- Benign traffic
```

## Security Profile

* **Isolation**: Every query thread receives its own dedicated `lua_State`. Memory leaks or crashes in one VM cannot physically corrupt another.
* **Escapes**: The `os.execute` and `io` libraries are purged from the environment prior to script evaluation.
* **Denial of Service**: Strictly prevented via the aforementioned `LUA_MASKCOUNT` hook. No query can exceed its computational time budget.
