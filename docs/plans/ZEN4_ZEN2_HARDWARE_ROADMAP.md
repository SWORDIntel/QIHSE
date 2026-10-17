# QIHSE AMD Hardware Acceleration Roadmap (Zen 4 & Zen 2)

> **Status: planned.** Architecture specification and implementation roadmap for next-generation AMD hardware acceleration targeting the Secondary server (AMD Ryzen 9 7950X, Zen 4 Raphael) and the Relay server (AMD EPYC 7662, Zen 2 Rome), derived from `/proc/cpuinfo` hardware analysis.
> **Role:** Master architectural blueprint for Zen 4 and Zen 2 SIMD, cryptographic, cache, and concurrency exploitation in QIHSE.
> **Cross-reference:** Master sequencing and tracking live in [ROADMAP.md](../../ROADMAP.md) (§1 and §3 W9).

---

## 1. Executive Summary & Target Topologies

Analysis of `/proc/cpuinfo` across the cluster infrastructure (`server-cpuinfo-all-2026-10-17.md`) confirms two distinct AMD microarchitectural tiers deployed alongside existing Intel Xeon host (Ivy Bridge-EP) and remote (Broadwell-EP) nodes:

| Cluster Role | Processor Model | Microarchitecture | Family / Model / Stepping | Cores / Threads | Base / Boost Clock | L2 / L3 Cache | Key ISA Additions |
|---|---|---|---|---|---|---|---|
| **Secondary Node** (`linuxagent-ispsystem-test`) | AMD Ryzen 9 7950X | Zen 4 (Raphael) | Family 25 (0x19) / Model 97 (0x61) / Step 2 | 16C / 32T (2 CCDs) | 4.5 GHz / 5.7 GHz | 1 MB/core (16 MB) / 64 MB (32 MB/CCD) | AVX-512 (F, DQ, BW, VL, VNNI, VPOPCNTDQ, BITALG, VBMI, VBMI2, IFMA, BF16), SHA-NI, VPCLMULQDQ, VAES, GFNI, CLZERO, CLWB, RDPID, CX16 |
| **Relay Node** (`linuxagent-relay`) | AMD EPYC 7662 | Zen 2 (Rome) | Family 23 (0x17) / Model 49 (0x31) / Step 0 | 64C / 128T (8 CCDs) | 2.0 GHz / 3.3 GHz | 512 KB/core (32 MB) / 256 MB (16 MB/CCX) | Full-width 256-bit AVX2, SHA-NI, PCLMULQDQ, AES-NI, CLZERO, CLWB, RDPID, CX16, ADX, RDSEED |

### Architectural Opportunities & Microarchitectural Realities

1. **Zen 4 AVX-512 Execution Paradigm**:
   Unlike Intel Skylake-X/Ice Lake, which utilizes native 512-bit physical execution units with associated voltage increases and frequency downclocking penalties (AVX offset), AMD Zen 4 double-pumps 512-bit vector instructions through high-frequency 256-bit SIMD datapaths. This yields:
   - **Zero clock throttling**: Cores maintain full boost clocks (up to 5.7 GHz) even under continuous 512-bit vector workloads.
   - **Full AVX-512 ISA coverage**: Full support for AVX-512F, DQ, BW, CD, VL, VNNI, VPOPCNTDQ, BITALG, VBMI, VBMI2, and IFMA.
   - **Double register capacity**: 32 vector registers (`zmm0`–`zmm31`) and 8 dedicated opmask registers (`k0`–`k7`), eliminating spills and accumulator starvation.

2. **Zen 2 Mass-Core Throughput & SHA-NI**:
   Zen 2 Rome provides single-cycle 256-bit execution units (doubled from Zen 1) across 64 physical cores (128 threads) and features hardware `sha_ni`. This makes Zen 2 an optimal consensus, replication fan-out, and cryptographic verification relay.

---

## 2. Hardware Capability Matrix

The following matrix cross-references hardware instruction extensions across QIHSE cluster tiers:

| Hardware Primitive | Ivy Bridge Host (Xeon E5-2470 v2) | Broadwell Remote (Xeon E5-2690 v4) | Zen 2 Relay (EPYC 7662) | Zen 4 Secondary (Ryzen 9 7950X) | Primary QIHSE Subsystem Accelerated |
|---|:---:|:---:|:---:|:---:|---|
| **AVX 1.0 / F16C** | `[x]` | `[x]` | `[x]` | `[x]` | HNSW Layer-0 Candidate Search & Pruning |
| **AVX2 + FMA3** | `[ ]` | `[x]` | `[x]` | `[x]` | FP32 Dot Product & Trinary Tryte Codec |
| **AVX-512 Foundation / VL** | `[ ]` | `[ ]` | `[ ]` | `[x]` | 512-bit Columnar Scans & Superposition |
| **AVX-512 VPOPCNTDQ** | `[ ]` | `[ ]` | `[ ]` | `[x]` | Binary Embedding Hamming Distance (8x speedup) |
| **AVX-512 VNNI** (`vpdpbusd`) | `[ ]` | `[ ]` | `[ ]` | `[x]` | Single-Instruction INT8 Vector MAC (3x-4x speedup) |
| **SHA-NI** (`sha256rnds2`) | `[ ]` | `[ ]` | `[x]` | `[x]` | Consensus Envelope, WAL, & Block Hashing (~2 GB/s/core) |
| **VPCLMULQDQ** (256/512-bit) | `[ ]` | `[ ]` | `[ ]` | `[x]` | Vectorized CRC32 Folding (>20 GiB/s) |
| **PCLMULQDQ** (128-bit) | `[x]` | `[x]` | `[x]` | `[x]` | IEEE 802.3 CRC32 & CRC32C Carryless Multiply |
| **AMD CLZERO** | `[ ]` | `[ ]` | `[x]` | `[x]` | Zero-Bus-Fill 64-Byte Cache Line Clear for Arenas |
| **CLWB** | `[ ]` | `[ ]` | `[x]` | `[x]` | Non-Evicting Cache Line Flush for WAL Persistence |
| **RDPID** | `[ ]` | `[ ]` | `[x]` | `[x]` | 1-Cycle Userspace Core & NUMA Node Resolution |
| **CX16** (`cmpxchg16b`) | `[x]` | `[x]` | `[x]` | `[x]` | Lock-Free ABA-Safe Dual-Pointer CAS |
| **AVX-512 BITALG / VBMI** | `[ ]` | `[ ]` | `[ ]` | `[x]` | Trinary Tryte Bit-Slicing & Dynamic Permute |
| **AVX-512 IFMA** (52-bit FMA) | `[ ]` | `[ ]` | `[ ]` | `[x]` | Post-Quantum Lattice Cryptography (ML-KEM / ML-DSA) |
| **GFNI** | `[ ]` | `[ ]` | `[ ]` | `[x]` | Galois Field Parity & Cluster Erasure Coding |

---

## 3. Tier 1: Immediate Critical Acceleration

### 1. AVX-512 VPOPCNTDQ: Vectorized Hamming Distance for Binary Embeddings
- **Target Subsystem**: `src/broad_oak/qihse_vector_db.c`, `src/broad_oak/qihse_hnsw.c`, `codecs/qihse_trinary_tryte_codec.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X).
- **Instruction**: `vpopcntd` (`_mm512_popcnt_epi32`), `vpopcntq` (`_mm512_popcnt_epi64`).
- **Mechanics**:
  Evaluates population count (Hamming weight) across 16 × 32-bit (or 8 × 64-bit) integers simultaneously. For 1,024-dimensional binary embeddings (common in neural representations and quantized vector indices):
  1. Load 64 bytes (512 bits) of vector $A$ and vector $B$ via `_mm512_loadu_si512`.
  2. Compute bitwise difference: `diff = _mm512_xor_si512(va, vb)`.
  3. Execute single-cycle vector population count: `counts = _mm512_popcnt_epi32(diff)`.
  4. Accumulate counts via `acc = _mm512_add_epi32(acc, counts)`.
- **Performance Impact**:
  Evaluates 512 dimensions per instruction. A 1,024-bit vector comparison completes in 2 vector iterations (16 vector instructions total with 4-way unrolling), achieving an **8x throughput increase** over scalar POPCNT and 4x over 128-bit SSSE3 table lookups, with zero branch mispredictions.

### 2. AVX-512 VNNI: Single-Instruction INT8 Multiply-Accumulate
- **Target Subsystem**: `src/broad_oak/qihse_vector_db.c`, `backends/cpu/qihse_cpu_distance.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X).
- **Instruction**: `vpdpbusd` (`_mm512_dpbusd_epi32`, `_mm256_dpbusd_epi32`).
- **Mechanics**:
  The `vpdpbusd` instruction computes 4-element dot products of unsigned 8-bit integers from the first operand with signed 8-bit integers from the second operand, adding intermediate 32-bit signed sums directly into a destination 32-bit accumulator:
  $$\text{Dst}_i \leftarrow \text{Dst}_i + \sum_{j=0}^{3} \text{Src1}_{4i+j} \cdot \text{Src2}_{4i+j}$$
- **Performance Impact**:
  In AVX2, computing an INT8 dot product requires unpacking 8-bit integers into 16-bit lanes (`vpunpcklbw`/`vpunpckhbw`), multiplying and horizontally adding adjacent pairs with `vpmaddubsw`, and accumulating into 32-bit words with `vpmaddwd`. AVX-512 VNNI condenses this entire 5-instruction sequence into **a single instruction evaluating 64 byte MACs per cycle** (or 32 byte MACs on 256-bit VL). Delivers a measured **3x–4x throughput speedup** over AVX2 INT8 search kernels.

### 3. Hardware SHA-NI: Consensus, Checkpointing & WAL Hashes
- **Target Subsystem**: `src/spinnaker/qihse_overlay.c`, `src/spinnaker/qihse_cluster_bus.c`, `src/tractable/qihse_wal.c`, `src/federation/qihse_federation.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X) and AMD Zen 2 (EPYC 7662).
- **Instructions**: `sha256rnds2` (`_mm_sha256rnds2_epu32`), `sha256msg1` (`_mm_sha256msg1_epu32`), `sha256msg2` (`_mm_sha256msg2_epu32`).
- **Mechanics**:
  Dedicated hardware execution units implement SHA-256 compression rounds. Two SHA-256 rounds are computed in a single execution step using `sha256rnds2` (latency ~4 cycles, reciprocal throughput 1 cycle).
- **Performance Impact**:
  Software SHA-256 typically caps at ~350–450 MB/s per core. Hardware SHA-NI achieves **~2.0–2.5 GB/s per core**. In QIHSE, consensus proposals, signed bus gossip, journal hash-chain verification, and WAL block checksums become negligible background operations, completely removing cryptographic hashing from the critical transaction path.

### 4. VPCLMULQDQ: Ultra-Wide Carryless Multiplication for CRC32 Folding
- **Target Subsystem**: `src/tractable/qihse_wal.c`, `persistence/qihse_persist_format.c`, `src/spinnaker/qihse_qkp.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X).
- **Instruction**: `vpclmulqdq` (`_mm512_clmulepi64_epi128`, `_mm256_clmulepi64_epi128`).
- **Mechanics**:
  Vectorized carryless multiplication over 256-bit and 512-bit registers. While legacy SSE PCLMULQDQ processes 16 bytes per instruction, VPCLMULQDQ processes 32 or 64 bytes per instruction. A 4-way unrolled 512-bit folding loop folds 256 bytes per loop iteration over the polynomial generator.
- **Performance Impact**:
  Propels CRC32 checksum throughput from 1.836 GiB/s (Ivy Bridge) and 6.018 GiB/s (Broadwell) to **>20 GiB/s per core**, easily outstripping NVMe and 100GbE line rates.

---

## 4. Tier 2: Cache, Memory & Concurrency Primitives

### 1. AMD CLZERO: Zero-Bus-Fill 64-Byte Cache Line Clearing
- **Target Subsystem**: `src/marmalade/qihse_timeseries.c`, `src/tractable/qihse_mvcc.c`, `persistence/qihse_pqc_crypto.c`.
- **Target CPU**: AMD Zen 4 and Zen 2 (`AuthenticAMD`).
- **Instruction**: `clzero` (`_mm_clzero(void* ptr)`).
- **Mechanics**:
  Clears the entire 64-byte cache line containing the memory address in `rax` to zero. Unlike `memset(ptr, 0, 64)` or `_mm512_store_si512`, `clzero`:
  - Does NOT issue a Read-For-Ownership (RFO) bus transaction to external memory controllers.
  - Zeroes the cache line entirely within the processor cache hierarchy.
- **Use Cases**:
  - **Slab & Arena Allocation**: Zeroing recycling pages in MVCC and UMA memory managers at zero memory-bus cost.
  - **Cryptographic Memory Sanitization**: Guarantees constant-time erasure of ephemeral private keys, ML-KEM shared secrets, and HMAC keys without compiler optimization elision.

### 2. CLWB: Non-Evicting Cache Line Writeback
- **Target Subsystem**: `src/tractable/qihse_wal.c`, `persistence/qihse_persist_format.c`.
- **Target CPU**: AMD Zen 4 and Zen 2.
- **Instruction**: `clwb` (`_mm_clwb(const void* p)`).
- **Mechanics**:
  Forces the specified cache line to be written back to the persistent memory or system memory controller if modified, **without evicting the line from the processor's L1/L2/L3 caches**.
- **Impact**:
  Replaces `clflush` / `clflushopt`. When a transaction commits, writing the WAL commit record requires flushing dirty cache lines to ensure durability. `clflush` forces subsequent transaction readers to take expensive L3/DRAM read misses. `clwb` flushes data to the persistence boundary while keeping lines warm in cache, slashing p99 latency under concurrent write-and-read loads.

### 3. RDPID: 1-Cycle Userspace Core & NUMA Node Resolution
- **Target Subsystem**: `src/spinnaker/qihse_cluster_brain.c`, `src/spinnaker/qihse_resp_engine.c`, `src/frieze/qihse_hash_index.c`.
- **Target CPU**: AMD Zen 4 and Zen 2.
- **Instruction**: `rdpid` (`_rdpid_u32()`).
- **Mechanics**:
  Reads the `IA32_TSC_AUX` MSR directly into a 32-bit register in userspace in 1 clock cycle without a syscall.
- **Impact**:
  Replaces glibc `sched_getcpu()` (which issues `vsyscall`/`getcpu`) and TLS thread lookups. On 64-core Zen 2 and 16-core Zen 4 nodes, incoming network packets and lockless worker tasks resolve their physical core and NUMA domain in 1 cycle, routing requests directly to NUMA-local shard partitions with zero cross-socket interconnect traffic.

### 4. CX16 (`cmpxchg16b`): ABA-Safe 128-Bit Atomic CAS
- **Target Subsystem**: `src/tractable/qihse_wal.c`, `src/frieze/qihse_hash_index.c`.
- **Target CPU**: AMD Zen 4 and Zen 2 (as well as legacy hosts).
- **Instruction**: `cmpxchg16b`.
- **Mechanics**:
  Performs an atomic 128-bit compare-and-swap across `rdx:rax` and `rcx:rbx`.
- **Impact**:
  Enables lock-free freelists and multi-producer queues by packing a 64-bit pointer together with a 64-bit monotonic tag or version counter. Completely eliminates ABA race conditions in high-concurrency lock-free structures.

---

## 5. Tier 3: Advanced Vector & Cryptographic Math

### 1. AVX-512 BITALG & VBMI / VBMI2: Trinary Vector Unpacking & Bit Slicing
- **Target Subsystem**: `codecs/qihse_trinary_tryte_codec.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X).
- **Instructions**: `vpopcntb` (`_mm512_popcnt_epi8`), `vbitshuffle` (`_mm512_bitshuffle_epi64_mask`), `vpermb` (`_mm512_permutexvar_epi8`), `vpcompressb` (`_mm512_maskz_compress_epi8`).
- **Mechanics**:
  - Trinary trytes encode 5 trits into a single 8-bit byte ($3^5 = 243 \le 256$).
  - Decoding trytes traditionally requires either large lookup tables (risking cache pressure) or multi-step arithmetic divisions.
  - AVX-512 BITALG provides byte-level bit manipulation and population counts; VBMI provides arbitrary cross-lane byte permutations (`vpermb`) and multi-precision bit packing.
- **Impact**:
  Permutes and expands 64 packed trytes simultaneously into aligned trit arrays in 1–2 cycles with zero cache lookups.

### 2. AVX-512 IFMA: 52-Bit Integer FMA for Post-Quantum Cryptography
- **Target Subsystem**: `persistence/qihse_pqc_crypto.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X).
- **Instructions**: `vpmadd52luq` (`_mm512_madd52lo_epu64`), `vpmadd52huq` (`_mm512_madd52hi_epu64`).
- **Mechanics**:
  Multiplies 52-bit unsigned integers from two operands and accumulates either the low 52 bits or high 52 bits into 64-bit accumulators:
  $$\text{Dst} \leftarrow \text{Dst} + \lfloor (\text{Src1} \cdot \text{Src2}) / 2^{52} \rfloor \quad \text{or} \quad \text{Dst} \leftarrow \text{Dst} + ((\text{Src1} \cdot \text{Src2}) \bmod 2^{52})$$
- **Impact**:
  Accelerates polynomial arithmetic in NIST CNSA 2.0 Post-Quantum algorithms: ML-KEM (Kyber) and ML-DSA (Dilithium). The Number Theoretic Transform (NTT) and ring modular multiplications execute over 8 parallel 52-bit channels per register, yielding a **4x–5x speedup** over 64-bit scalar Montgomery multiplication.

### 3. GFNI: Galois Field Arithmetic for Cluster Erasure Coding
- **Target Subsystem**: `src/spinnaker/qihse_fabric_index.c`, `src/federation/qihse_federation.c`.
- **Target CPU**: AMD Zen 4 (Ryzen 9 7950X).
- **Instructions**: `vgf2p8mulb` (`_mm512_gf2p8mul_epi8`), `vgf2p8affineqb` (`_mm512_gf2p8affine_epi64_epi8`).
- **Mechanics**:
  Executes parallel multiplication and affine transformations in the Galois Field $GF(2^8)$ on 64 individual bytes simultaneously.
- **Impact**:
  Reed-Solomon erasure coding and distributed snapshot parity generation run at tens of gigabytes per second, allowing cross-cluster backup transfer and recovery without consuming CPU cycles needed for active database operations.

---

## 6. Dispatch Architecture & Multi-Versioning Strategy

### Dynamic Runtime Detection via `qihse_cpu_detect()`
To guarantee zero breakage on older hardware, the dispatch architecture strictly enforces:
1. **Zero static shims or aliases**: No hardcoded compiler flags that bake instructions into the main binary.
2. **Safe execution testing**: In `backends/cpu/qihse_cpu_detect.c`, all capabilities are tested through runtime instruction probe handlers using `sigsetjmp`/`siglongjmp` on `SIGILL` in conjunction with CPUID features.
3. **Atomic function resolution**: Function pointers are stored in static dispatch tables initialized via `pthread_once()` on first invocation (e.g., `qihse_distance_resolve()`).

### Compiler Function Multi-Versioning (`__attribute__((target(...)))`)
To maintain 100% build compatibility on legacy host machines (such as the Dual Intel Xeon E5-2470 v2 Ivy Bridge development host) while emitting cutting-edge Zen 4 and Zen 2 vector binaries:
- Every specialized function is compiled with GCC/Clang target attributes:
  ```c
  /* Zen 4 AVX-512 VPOPCNTDQ + VNNI + FMA path */
  __attribute__((target("avx512f,avx512bw,avx512dq,avx512vl,avx512vnni,avx512vpopcntdq,fma")))
  float qihse_vdb_int8_dot_product_zen4(const int8_t* a, const int8_t* b, size_t dims) {
      /* Uses _mm512_dpbusd_epi32 */
      ...
      _mm512_zeroupper();
      return result;
  }

  /* Zen 2 & Zen 4 SHA-NI hardware hashing path */
  __attribute__((target("sha,sse4.1")))
  void qihse_sha256_block_shani(uint32_t state[8], const uint8_t data[64]) {
      /* Uses _mm_sha256rnds2_epu32 */
      ...
  }

  /* Zen 4 VPCLMULQDQ 512-bit CRC32 folding */
  __attribute__((target("vpclmulqdq,avx512f")))
  uint32_t qihse_crc32_vpclmul512(const uint8_t* buf, size_t len) {
      ...
      _mm512_zeroupper();
      return crc;
  }
  ```
- **Result**: The entire repository builds cleanly on any x86-64 Linux host without `-march=native`, emitting multi-versioned object code with zero link-time dependencies on unavailable CPU instructions.

### Strict Register Hygiene: `_mm256_zeroupper()` and `_mm512_zeroupper()`
Transitions between 256-bit / 512-bit vector modes and legacy 128-bit SSE or scalar code cause the CPU to incur a severe microcode penalty (~70 clock cycles) and enter an internal AVX-SSE dirty state unless register hygiene is strictly maintained.
- **Rule**: Every function utilizing `__m256` must call `_mm256_zeroupper()` before returning.
- **Rule**: Every function utilizing `__m512` must call `_mm512_zeroupper()` before returning.
- **Verification**: Enforced via automated disassembly inspection in CI harnesses (`objdump` scanning for exit paths lacking `vzeroupper`).

---

## 7. Phased Implementation Roadmap

The implementation is structured across five sequential engineering phases:

### Phase 1: Feature Detection & Dispatch Foundations
- [ ] Extend `qihse_cpu_feature_t` bitmask in `backends/cpu/qihse_cpu_detect.h` for Zen 4/Zen 2 features: `AVX512_VPOPCNTDQ`, `AVX512_IFMA`, `AVX512_BITALG`, `AVX512_VBMI`, `AVX512_VBMI2`, `SHA_NI`, `VPCLMULQDQ`, `CLZERO`, `CLWB`, `RDPID`, `GFNI`.
- [ ] Implement execution-testing probes in `backends/cpu/qihse_cpu_detect.c` with `SIGILL` trap recovery.
- [ ] Add unit tests verifying feature flags on live silicon in `tests/test_cpu_detect.c`.

### Phase 2: Tier 1 Immediate Critical Acceleration
- [ ] Implement `qihse_hamming_distance_avx512_vpopcntdq()` in `backends/cpu/qihse_cpu_distance.c`.
- [ ] Implement `qihse_vdb_int8_dot_product_avx512_vnni()` in `src/broad_oak/qihse_vector_db.c`.
- [ ] Implement hardware SHA-256 compression kernel using SHA-NI in `src/spinnaker/qihse_overlay.c` and `src/tractable/qihse_wal.c`.
- [ ] Implement 512-bit/256-bit carryless folding using VPCLMULQDQ for CRC32 in `src/tractable/qihse_wal.c` and `persistence/qihse_persist_format.c`.

### Phase 3: Tier 2 Cache, Memory & Concurrency Primitives
- [ ] Implement `qihse_clzero_line()` and integrate into UMA slab arena allocation and PQC key zeroization.
- [ ] Integrate `clwb` into the WAL segment commit path with fallback to `clflushopt`/`clflush`.
- [ ] Integrate `rdpid` into core-aware worker thread scheduling and NUMA shard selection.
- [ ] Validate 128-bit `cmpxchg16b` in lockless transaction freelists.

### Phase 4: Tier 3 Advanced Vector & Cryptographic Math
- [ ] Accelerate trinary tryte encoding/decoding in `codecs/qihse_trinary_tryte_codec.c` using AVX-512 BITALG and VBMI.
- [ ] Accelerate post-quantum lattice polynomial multiplication using AVX-512 IFMA in `persistence/qihse_pqc_crypto.c`.
- [ ] Implement Reed-Solomon parity matrix computation using GFNI in `src/federation/qihse_federation.c`.

### Phase 5: Verification, Benchmarking & Cluster Rollout
- [ ] Run microbenchmarks on Secondary (`Ryzen 9 7950X`) and Relay (`EPYC 7662`) logging metrics to `docs/benchmarks.md`.
- [ ] Verify 100% test pass rate across all regression suites with zero residue.
- [ ] Verify audit continuity security gates.

---

## 8. Invariants & Acceptance Gates

1. **Local Build Invariant**:
   Building on legacy hosts (Ivy Bridge / Broadwell) must NEVER fail or produce binaries that trigger `SIGILL` on host test harnesses.
2. **Zero-Residue Invariant**:
   All tests and benchmarks executed on Secondary and Relay nodes must completely clean up temporary files, shm segments, and test keys.
3. **Audit Continuity Security Gate**:
   Cryptographic and memory acceleration must preserve identical mathematical results down to the bit level. SHA-NI output must exactly match OpenSSL and portable SHA-256; VPCLMULQDQ must exactly match IEEE 802.3 and Castagnoli CRC32 standards.
4. **Register Hygiene Invariant**:
   All SIMD functions must emit `vzeroupper` prior to exiting to eliminate AVX-to-SSE transition penalties.
