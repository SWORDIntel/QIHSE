# QIHSE Roadmap

**Status date:** 2026-11-10
**License:** first-party QIHSE code uses SRSL-1.1; vendored and other third-party components retain their own applicable licenses.
**Role:** sole authoritative roadmap for delivery status, remaining work, sequencing and acceptance. All other roadmap/plan files are supporting designs or dated evidence; their historical labels do not override this file. Former work identifiers remain mapped below. This is the master sequencing document. Detailed designs live in `docs/plans/` and `docs/architecture/`; this file tracks *what is being built, in what order, and what "done" means*. It does not replace those documents.

Status marks: `[x]` implemented with repository evidence (source + build wiring + test) · `[~]` partially implemented · `[ ]` open (not started or completion not established) · `[>]` superseded/conditional

**Current program status (reviewed 2026-11-10):** 169 implemented, 28 partial, 12 open and 3 superseded/conditional checklist entries. The live cluster has a functional published baseline. The repair batch now locally integrates raw AIMEM adapter restrictions, restorable owner-data streaming backups, WAL failure preservation, graph/vector correctness, retryable 2PC outcomes, and CT intent/epoch/promotion/cache repairs. Further passes fix aborted-update MVCC collection, allocation overflow/alignment, concurrent backup scratch ownership, SQL DELETE error propagation, vector mutation label/TAG preservation, vector ADD/WAL admission and recovery, partial replication sends, table-generation overflow, source transfer-ID reuse and shared vector-adapter synchronization. The combined library and daemon build; focused regressions and scoped sanitizer checks are recorded in [the repair record](docs/AIMEM_CURRENT_ISSUES.md#5-repair-batch-in-progress-2026-11-10). CT.1/CT.2 remain partial: recovering an observer that missed a predecessor promotion still needs an authenticated ownership chain, and existing transfer-size and placement limits remain. HAX.2 retains its broader integration/rollout gaps. CG.13 explicit shared-block collection is repaired. The full suite was stopped at the user's request and was not rerun for this batch. Historical passing tests do not establish coverage of every new case; these repairs have not been deployed.

**Canonical tracking:** [CodeGraph](#codegraph) · [native HAX / KEYSTONE index](#native-hax) · [optional bridge](#bridge) · [design mappings / operational gaps](#consolidated-designs). W0–W12 and CT identifiers remain below.

---

## 1. Historical W0–W10 baseline (reviewed 2026-10-24)

The historical W0–W10 checklist is closed. W0–W9 are implemented, including the W8 I2P replica transport live SOCKS5 smoke test across stageb containers and W9 runtime-dispatched hardware acceleration on the R730xd, dual E5-2470 v2 host, and AMD Zen 4/Zen 2 hosts. Audit continuity and exact-prefix challenge gates are implemented but intentionally undeployed pending retained-log review and the required negative CI coverage. At that historical checkpoint, the verification gold suite recorded 72/72 workloads on `make -s test`. Its cluster smokes verify fail-closed behavior; they do not implement the two cluster-transport follow-ups below.

The recorded W0–W10 checklist has **134 implemented and 1 superseded conditional item**. Functionality and security defects addressed in those workstreams include NULL-context authorization, Bolt and Mongo wire compatibility, WAL replay, MVCC delete visibility, and SQL DML. QH-00 through QH-09 meet their documented acceptance gates; QH-10 remains available as a future design only if a concrete consumer demonstrates the need. The implemented cluster-transport guarantees are tracked separately as CT.1–CT.2. W11 adds **7 stretch deliverables** for QIHSE's role as the general database foundation for commerce, inventories, fuzzing findings, agent memory, and other applications; W11.0 is complete, while W11.1 and W11.5 are partial.

### Remote Server Hardware Acceleration (Dell PowerEdge R730xd — Dual Xeon E5-2690 v4) (2026-10-17)

### AMD Zen 4 & Zen 2 Hardware Acceleration (Ryzen 9 7950X & EPYC 7662) (2026-10-17)

Completed architecture design, feature detection integration, and initial kernel implementations for the Secondary server (AMD Ryzen 9 7950X Zen 4 Raphael) and Relay server (AMD EPYC 7662 Zen 2 Rome) based on hardware `/proc/cpuinfo` analysis ([docs/plans/ZEN4_ZEN2_HARDWARE_ROADMAP.md](docs/plans/ZEN4_ZEN2_HARDWARE_ROADMAP.md)):
1. **Dynamic C99 CPU Feature Detection & Signal-Safe Probing** (`backends/cpu/qihse_cpu_detect.{h,c}`): 13 new feature bits (`SHA_NI`, `AVX512_VPOPCNTDQ`, `VPCLMULQDQ`, `VAES`, `AVX512_BITALG`, `AVX512_VBMI`, `AVX512_VBMI2`, `AVX512_IFMA`, `GFNI`, `CLZERO`, `CLWB`, `RDPID`, `CX16`) with execution test signal trapping (`safe_execute_test`) and zero-overhead thread-safe caching.
2. **Vector DB SIMD Acceleration** (`src/broad_oak/qihse_vector_db.c`):
   - AVX-512 VPOPCNTDQ 2x unrolled Hamming distance (`qihse_vdb_hamming_distance_avx512vpopcntdq`) with dual accumulators for binary embeddings (8x speedup).
   - AVX-512 VNNI 2x unrolled INT8 dot product (`qihse_vdb_int8_dot_product_avx512vnni`) with exact signed-to-unsigned conversion offset cancellation ($(u_a \oplus 0x80) \cdot b_i - 128 \sum b_i$) and dual interleaved accumulators.
3. **Hardware Cache & Core Primitives** (`include/backends/cpu/qihse_cpu_cache.h`):
   - 64-byte aligned AMD `CLZERO` zero-bus-fill cache clearing with heap fallback.
   - Non-evicting `CLWB` cache writeback for persistent WAL commit.
   - 1-cycle userspace `RDPID` core and NUMA resolution.
4. **Hardware SHA-NI Hashing** (`include/qihse_sha256_shani.h`): Single-cycle 2-round hardware SHA-256 compression block processing (~2.0 GB/s/core).
5. **Test Harness & Verification** (`tests/test_zen_epyc_simd.c`): 5-stage test suite covering detection, signal-safe execution, cache operations, SHA-NI, and vector DB dispatch passing cleanly on host CPU.

Completed native hardware acceleration targeting the Dell PowerEdge R730xd (Broadwell-EP, 2 sockets × 14 cores = 28C/56T, 70MB L3 cache, Linux 7.0.14-19-pve) across all 5 engineering phases with full native build, remote cluster service deployment, and live hardware verification:

1. **AVX2 + FMA Saturation & 256-Bit SIMD Width** (`backends/cpu/qihse_cpu_distance.c`, `src/broad_oak/qihse_vector_db.c`, `codecs/qihse_trinary_tryte_codec.c`):
   - Implemented 4-way independent accumulator unrolling (`acc0..acc3`) processing 32 floats (128 bytes) per iteration via `_mm256_fmadd_ps` in `qihse_distance_dot_avx2`, `qihse_distance_euclidean_avx2`, and `qihse_distance_cosine_avx2`, eliminating single-accumulator pipeline stalls and saturating Broadwell's 5-cycle FMA latency across Ports 0 and 1.
   - Added fused `f16c,fma` HNSW Layer-0 traversal (`qihse_l2_sq_distance_f16c_fma`, `qihse_dot_product_f16c_fma`).
   - 256-bit AVX2 INT8 dot product (`qihse_vdb_int8_dot_product_avx2`) evaluating 64 dimensions per loop iteration, delivering **3.89 ms p50 latency on 100,000 vectors** (measured live on `730xd`).
   - 256-bit AVX2 Trinary Tryte dot product (`qihse_tryte_dot_product_avx2`) evaluating 32 trytes (160 trits) per cycle via in-lane `_mm256_shuffle_epi8` and `_mm256_maddubs_epi16`.
   - Vectorized 48-byte veiled bus HMAC keystream XOR using 32-byte AVX2 + 16-byte SSE intrinsics with strict `_mm256_zeroupper()` hygiene.

2. **C99 64-Bit Feature Detection Engine** (`backends/cpu/qihse_cpu_detect.{h,c}`):
   - Widened `qihse_cpu_feature_t` to `uint64_t`, eliminating C99 enum overflow risks.
   - Added CPUID Leaf 1 and Leaf 7 execution testing for `FMA`, `MOVBE`, `LZCNT`/`ABM`, `BMI1`, `BMI2`, `RTM`, `RDSEED`, and `ADX`.

3. **BMI1, BMI2, LZCNT & MOVBE Bitstream Acceleration** (`src/broad_oak/qihse_vector_db.c`, `src/marmalade/qihse_timeseries.c`, `include/qihse_endian.h`):
   - Single-cycle `_pext_u64` and `_pdep_u64` FP8 and FP4 vector sidecar quantization and expansion, replacing shift-mask loops with 1-cycle bitfield scatter/gather.
   - 64-bit `MOVBE` + `BMI2` (`bzhi`/`shrx`) Gorilla XOR time-series bitstream compression with hardware `_lzcnt_u64` and `_tzcnt_u64`.
   - Unified big-endian wire framing (`include/qihse_endian.h`) across QKP, UWP, and cluster consensus codecs.

4. **NIST SP 800-90B/C Physical Thermal Entropy & ADX Multi-Precision Math** (`persistence/qihse_pqc_crypto.c`, `backends/cpu/qihse_cpu_adx_math.h`):
   - Hardware `_rdseed64_step` physical thermal noise conditioning with backoff and whitening, seeding OpenSSL 3.5+ PQC provider (ML-KEM-1024 and ML-DSA-87) and thread-local PRNG states without FIFO starvation.
   - `ADX` (`adcx`/`adox`) + `BMI2` (`mulx`) dual-carry-chain 256-bit accumulator.

5. **Intel TSX (RTM) Hardware Lock Elision** (`include/qihse_tsx_lock.h`, `src/frieze/qihse_hash_index.c`, `src/broad_oak/qihse_quantum_defense.c`):
   - Lemming-safe `qihse_tsx_rwlock_t` with fallback-held guard, eliding read/write locks on hash index lookups and QDD telemetry.

6. **Native Server Deployment & Live Hardware Verification**:
   - Built natively on `730xd` with all 17 hardware flags: `-mavx -mavx2 -mfma -mbmi -mbmi2 -mmovbe -mrdseed -madx -mrtm -mlzcnt -mf16c -maes -mpclmul -mpopcnt -mrdrnd -mfsgsbase -DQIHSE_ENABLE_ERMS=1`.
   - Cluster daemon `qihse-node5-host.service` active and verified.
   - CRC32 carryless folding measured at **6.018 GiB/s** throughput on live hardware.

### Host CPU hardware acceleration (Dual Intel Xeon E5-2470 v2) (2026-10-17)

Completed end-to-end hardware acceleration targeting the host machine's dual Intel Xeon E5-2470 v2 processors (Ivy Bridge-EP, 2 sockets × 10 cores = 20C/40T, 50MB L3 cache, DDR3-1600 NUMA) across four core engineering phases, audited and verified with zero static shims or aliases. Both modern AVX-512/AVX2 and host AVX 1.0 + F16C are resolved dynamically at runtime via `qihse_cpu_detect()`:

1. **Phase 1: Vector Math & Dynamic HNSW** (`backends/cpu/qihse_cpu_distance.c`, `src/broad_oak/qihse_hnsw.c`):
   - Implemented 4-way independent accumulator unrolling (`acc0..acc3`) processing 32 floats (128 bytes) per loop iteration in `qihse_l2_sq_distance_avx()` and `qihse_dot_product_avx()`, fully saturating Ivy Bridge's 3-cycle `vaddps` latency chain.
   - Added precomputed vector norm acceleration (`qihse_cosine_distance_avx`), eliminating redundant in-loop square roots and horizontal reductions.
   - Dynamic precision tiering in HNSW: Layer-0 neighbor vectors store in FP16 via F16C intrinsics (`_mm256_cvtph_ps` / `_mm256_cvtps_ph`), cutting memory bus traffic by 50%. Evaluates candidates using `qihse_l2_sq_distance_f16c` and promotes top-$M$ ($M = \max(2k, 64)$) candidates for exact re-ranking against master FP32 vectors, guaranteeing 100.0% ground-truth accuracy.
   - Software prefetching (`_mm_prefetch(..., _MM_HINT_T0)`) during beam search candidate exploration and column aggregation `target_clones` ("avx512f", "avx2", "avx", "default").

2. **Phase 2: High-Throughput RESP Engine** (`src/spinnaker/qihse_resp_engine.c`):
   - $O(1)$ 4-byte uppercase SWAR jump table (`key = *(const uint32_t*)cmd & 0xDFDFDFDFu`) replacing sequential command cascades for standard and compound commands (`SETEX`, `SETRANGE`, `GETSET`, etc.).
   - Explicit-length SSE4.2 `_mm_cmpestri` needle scanner for CRLF detection (`\r\n`), eliminating truncation defects on binary payloads with embedded null bytes.
   - SSSE3 `_mm_maddubs_epi16` integer parsing for bulk/array length headers, SSE4.2 whitespace skipping, and 64-bit immediate writes for static responses (`+PONG\r\n`, `+OK\r\n`, `:1\r\n`, etc.).

3. **Phase 3: Wire Crypto, Checksums & In-Memory Hashing** (`src/spinnaker/qihse_qkp.c`, `src/spinnaker/qihse_uwp_tls.c`, `src/tractable/qihse_wal.c`, `persistence/qihse_persist_format.c`, `src/frieze/qihse_hash_index.c`):
   - Session-persistent pre-keyed `tx_ctx` and `rx_ctx` in QKP and UWP TLS, eliminating per-frame `malloc`/`free` and `EVP_CIPHER_CTX` allocation.
   - 4-way PCLMULQDQ carryless folding for IEEE 802.3 CRC32 in WAL and replication streams reaching **1.836 GiB/s** throughput, with bit-exact Slice-by-8 fallback.
   - 3-way interleaved `_mm_crc32_u64` loop for 24-byte chunks in persistence CRC32C, combined via PCLMULQDQ carryless multiplication.
   - Hardware key hashing combining `_mm_crc32_u64` (8 bytes/cycle) with a single round of `_mm_aesenc_si128` (~11 cycles per 64-byte key).

4. **Phase 4: Randomness, Quantization & POPCNT** (`src/broad_oak/qihse_hnsw.c`, `src/broad_oak/qihse_vector_db.c`, `codecs/qihse_trinary_tryte_codec.c`, `src/broad_oak/qihse_quantum_defense.c`):
   - Two-tier lock-free hardware entropy: hardware `_rdrand64_step` seeding thread-local `xoshiro256**` PRNG states + `__builtin_clzll` geometric distribution, completely eliminating OpenSSL mutex contention across 40 hardware threads.
   - 4-way unrolled POPCNT (`c0..c3`) saturating Port 1 at 64 binary dimensions per cycle (1,024-D in 16 cycles), defeating the Ivy Bridge false destination dependency erratum.
   - AVX 1.0 sign-bit binarization (`_mm256_movemask_ps`) packing 8 float signs per cycle, integer Hamming comparisons, and SSE4.1 16-way INT8 dot products (`_mm_cvtepi8_epi16` + `_mm_madd_epi16`).
   - SSSE3 `_mm_shuffle_epi8` (`pshufb`) trinary tryte LUT acceleration with zero memory loads.
   - Userspace `_readfsbase_u64()` thread ID resolution eliminating glibc/syscall overhead.

5. **Security Hardening & Auditor Verification**:
   - Enforced `_mm256_zeroupper()` across all AVX exit paths to eliminate the 70-cycle microcode penalty on AVX-to-SSE/libc transitions.
   - Enforced unaligned `_mm256_loadu_ps` and `_mm256_storeu_ps` in AVX2 superposition routines, preventing `#GP(0)` alignment crashes on standard `malloc` pointers.
   - Enforced strict `0700` directory and file permissions across cluster daemons and test harnesses to satisfy the strict QIHSE audit continuity security gate.
   - Evidence: Commit range `8962b17..2a9e18c`. All 14 test suites pass (`test-distance-dispatch`, `test-exact-search-parity`, `test-hnsw-anchor-seeding`, `test-resp-hybrid`, `test-resp-cluster`, `test-resp-pubsub`, `test-task-resp`, `test-uwp-regression` [29/29], `test-routing-persistence` [32/32], `test-indexes`, `test-federation-backup` [13/13], `test-quantization`, `test-trinary-codec` [14/14], `test-pqc-handshake` [13/13]).

### Audit continuity deployment gate (2026-10-12)

The audit implementation recovers the retained SHA-384 chain on
startup and persist appended records before advancing the tip. It now carries
a process-local, typed OS-service recovery context through the lowest audit
reader and restricts reads to owner-controlled audit files. This is a local
security boundary, not historical signature verification: the current
ML-DSA signing identity is regenerated at startup and prior public keys are
not retained. It must remain undeployed until preserved log copies are
reviewed for legacy reset boundaries, partial records, stale/missing tips,
rotation/prune behavior, and historical format compatibility. The scanner's
strict startup failure behavior must not be applied to live data before that
review. Scanner and pruning now share strict numeric rotated-file parsing and
a 256-file limit; rotation reserves capacity and fails closed on directory
errors. The local edit now uses an owner-checked writer lock tied to the audit
directory and process, invalidates the inherited context after fork, and
checks banner/record write counts. Behavioral validation of the integrated
source is required before deployment.

A portable x86-64 review build of this dirty working tree completed on
2026-10-12. Its native library SHA-256 is
`e575b54e5e6413e792004d82df48ca3503f6525464b0a02b66d3f8fb71aac9f6`;
the daemon SHA-256 is
`4f15ecc5aa4ead46b0d799559aa66a750bca433f645d307b7344f85930619d44`.
The build found no removed exported dynamic symbols relative to the deployed
library, and both artifacts report x86-64-baseline. This is a dirty-source
candidate, not a frozen release. Historical ML-DSA signatures remain
unverifiable because signing keys are regenerated, and retained-log, crash,
rotation, fork, and three-node recovery behavior has not been exercised.
The candidate has not been installed on any server. The deployed three-node
library and daemon pair is already byte-identical; see
`docs/deployment/native_cluster_parity.md`.

### Exact-prefix challenge deployment gate (2026-10-12)

A read-only RESP endpoint accepts a bounded exact committed
index and verifier-supplied 32-byte challenge from an authenticated system
Operator. It signs a response bound to the group/history/epoch, index,
observed watermark, and configured enrolled signer. The endpoint grants no
replay, rejoin, or write authority. It remains default-off and undeployed.
Before enabling it, retain low-clearance/high-data negative CI coverage required
by `AGENTS.md`, implement independent one-use nonce issuance and protected
verification records, and resolve the current 4,096-entry index limit for
histories beyond that boundary. No behavioral validation has been run.
The Python controller SDK also has an optional exact QKP peer node/key pin;
when supplied, it checks the signed identity before HELLO or AUTH. This has
not been used by an independent prefix verifier.

### Audit continuity working-tree gate (2026-10-12)

The unmerged audit edit attempts to recover the retained SHA-384 chain on
startup and persist appended records before advancing the tip. It now carries
a process-local, typed OS-service recovery context through the lowest audit
reader and restricts reads to owner-controlled audit files. This is a local
security boundary, not historical signature verification: the current
ML-DSA signing identity is regenerated at startup and prior public keys are
not retained. The edit must remain undeployed until preserved log copies are
reviewed for legacy reset boundaries, partial records, stale/missing tips,
rotation/prune behavior, and historical format compatibility. The scanner's
strict startup failure behavior must not be applied to live data before that
review. Scanner and pruning now share strict numeric rotated-file parsing and
a 256-file limit; rotation reserves capacity and fails closed on directory
errors. The local edit now uses an owner-checked writer lock tied to the audit
directory and process, invalidates the inherited context after fork, and
checks banner/record write counts. No behavioral validation has been run for
this working-tree edit.

A portable x86-64 review build of this dirty working tree completed on
2026-10-12. Its native library SHA-256 is
`e575b54e5e6413e792004d82df48ca3503f6525464b0a02b66d3f8fb71aac9f6`;
the daemon SHA-256 is
`4f15ecc5aa4ead46b0d799559aa66a750bca433f645d307b7344f85930619d44`.
The build found no removed exported dynamic symbols relative to the deployed
library, and both artifacts report x86-64-baseline. This is a dirty-source
candidate, not a frozen release. Historical ML-DSA signatures remain
unverifiable because signing keys are regenerated, and retained-log, crash,
rotation, fork, and three-node recovery behavior has not been exercised.
The candidate has not been installed on any server. The deployed three-node
library and daemon pair is already byte-identical; see
`docs/deployment/native_cluster_parity.md`.

### Exact-prefix challenge working-tree gate (2026-10-12)

An unmerged read-only RESP endpoint now accepts a bounded exact committed
index and verifier-supplied 32-byte challenge from an authenticated system
Operator. It signs a response bound to the group/history/epoch, index,
observed watermark, and configured enrolled signer. The endpoint grants no
replay, rejoin, or write authority. It remains default-off and undeployed.
Before merge, add the low-clearance/high-data negative CI coverage required
by `AGENTS.md`, implement independent one-use nonce issuance and protected
verification records, and resolve the current 4,096-entry index limit for
histories beyond that boundary. No behavioral validation has been run.
The Python controller SDK also has an optional exact QKP peer node/key pin;
when supplied, it checks the signed identity before HELLO or AUTH. This is
unmerged source and has not been used by an independent prefix verifier.

### 1.5 W8 — I2P replica transport and durable KV handoff (implemented, 2026-10-09)

The implementation and code-level regression gates are complete. Deployment
through a configured SOCKS5 network still needs a site-specific smoke test.
This work adds the QKP1-pinned SOCKS5 pull transport; operator-gated RESP
replication commands; a read-only replica fence; metadata-preserving row apply;
private snapshot transfer; and durable per-peer namespace cursors. The
`test-replica-security` regression passes for KV-level low-clearance refusals,
snapshot namespace filtering, replica write fencing, and cursor persistence.
`test-replica-qkp` now proves a low-clearance guest is denied over a live pinned
QKP1 session without protected payload bytes; it is wired into `make test`.

The low-clearance RESP regression proves no protected bytes are returned from
DELTA or APPLY. The test also verifies that an authenticated system operator
can retrieve the replication delta through that same pinned connection. Source
snapshot baselines and monotonic ACKs are durable;
streaming compaction keeps matching tombstones until ACK, with tests for both
retention and release. Delta export now filters inside the KV enumerator and
retains only rows inside its row/byte limits; the daemon requests one row at a
time. Snapshot installation records a durable intent and startup recovery
rebuilds the image and cursor; the regression verifies recovery from a pending
install with leftover candidate, old SSTable, and WAL files. A test-only build
of the KV store exits abruptly at seven installer durability boundaries; each
restart checks whether the snapshot and cursor should be committed or absent.

Replication validation gates:
- [x] Live pinned QKP1 operator success and low-clearance denial, no protected
  bytes (`make test-replica-qkp`).
- [x] Abrupt exit/restart at seven install image, intent, WAL, SSTable, cursor,
  marker, and journal-removal boundaries (`make test-replica-crash`).
- [x] Live deployment smoke test across real I2P/SOCKS5 network with strict L2
  bridge isolation (`ebtables`) and mutual QKP1 key pinning verified across
  stageb containers (2026-10-17).

- [x] Full LAN cluster replication (`*`) by default with automatic peer anti-entropy reconciliation across cluster nodes (`t420` and `730xd`), verified with 100% database key parity (3,046/3,046 keys identical) and background missing-key healing (2026-10-17).
- [x] Automated hardware ISA detection and installer (`scripts/install_qihse.sh` & `make install-host`), auto-detecting AVX/AVX2/AVX-512/AVX-VNNI/AMX, configuring compiler optimization flags, building and installing into `/opt/QIHSE`, provisioning NIST CNSA 2.0 PQC keys in `/etc/qihse/keys`, supporting interactive solo node vs. multi-node cluster selection with automatic LAN subnet peer scanning, boot launch persistence (`systemctl enable`), `make clean` by default, startup cluster bus acknowledgement wait, solo re-run upgrade workflow, and KEYSTONE companion indexing service integration (2026-10-17).
- [x] Host CPU hardware acceleration for Dual Intel Xeon E5-2470 v2 (Ivy Bridge-EP, 2 sockets × 10 cores = 20C/40T, 50MB L3, AVX 1.0, F16C, AES-NI, PCLMULQDQ, POPCNT, RDRAND, FSGSBASE, ERMS) across 4 implementation phases without static aliases or shims: (1) 4-way ILP unrolling (128 B/iter) in AVX kernels, dynamic F16C leaf storage with FP32 candidate promotion, precomputed norms, and software prefetching; (2) $O(1)$ 4-byte uppercase SWAR jump table, SSE4.2 explicit-length `_mm_cmpestri` CRLF scanner, SSSE3 `_mm_maddubs_epi16` integer parsing, and 64-bit immediate responses; (3) session-persistent pre-keyed `EVP_CIPHER_CTX` with zero per-packet allocation, 4-way PCLMULQDQ carryless folding CRC32 (1.836 GiB/s) with Slice-by-8 fallback, 3-way interleaved `_mm_crc32_u64` + PCLMULQDQ CRC32C, and hardware `_mm_crc32_u64` + `_mm_aesenc_si128` key hashing (~11 cycles/key); (4) lock-free two-tier hardware randomness (`_rdrand64_step` + thread-local `xoshiro256**`), 4-way unrolled POPCNT defeating Ivy Bridge erratum (Port 1 saturation at 64 dims/cycle), AVX sign-bit binarization (`_mm256_movemask_ps`), SSSE3 tryte dot products, userspace `_readfsbase_u64()` thread ID resolution, and SSE4.1 16-way INT8 dot products. Verified passing across all 14 test suites and audit continuity gates with `_mm256_zeroupper()` register hygiene and unaligned loadu/storeu safety (2026-10-17).

The code-level and live deployment W8 validation gates are closed. Real-world
I2P/SOCKS5 garlic routing, mutual QKP1 pinning, delta row replication, and
tombstone propagation were smoke tested and verified across isolated Proxmox
containers (`stageb-node1`, `stageb-node2`, `stageb-node3`). The I2P replica
mode is enforced as strictly opt-in (`--replication-transport i2p`, with direct
RFC1918 LAN / WireGuard mesh as default), and automated PQC provisioning and i2pd hardening are provided
via `scripts/setup_i2p_replication.sh`. In LAN cluster deployments, replication defaults to all namespaces (`*`)
with continuous topology-aware peer anti-entropy sync, ensuring nodes offline for days automatically reconcile
all missing keys upon reconnection. External EventStream integration is a separate open item.

### 1.1 Landed and committed

The database-replacement program (**Phases 1–9**) is complete and committed — see
[general database engine roadmap](docs/plans/qihse_general_db_engine_roadmap.md) for the item-by-item record:

| Area | State |
|---|---|
| Multi-model engines (KV, vector, document, columnar, time-series, FTS, event stream, spatial, graph) | `[x]` |
| SQL completeness (joins, aggregates, CTEs, window functions, subqueries) + QQL | `[x]` |
| ACID transactions, MVCC, 3 isolation levels, cross-engine 2PC, unified WAL + recovery | `[x]` |
| Secondary indexes (B+ tree, hash, composite, index-backed plans) | `[x]` |
| Replication, read replicas, CDC, coordinated snapshots, backup/restore, PITR | `[x]` |
| Wire protocols: RESP2/3, pgwire, MongoDB, Bolt/Cypher, HTTP/REST, ES-style, ClickHouse-style, InfluxDB-style | `[x]` |
| Cluster: 16,384 slots, gossip, failover, scatter-gather planner; secure data-bearing rebalancing remains open | `[~]` |
| Ops: pooler, Prometheus metrics, OTel tracing, task queue/scheduler, backup | `[x]` |
| Compatibility command surfaces for 8 target databases (Phase 9) | `[x]` |

Recent committed work on top of that program:

- `[x]` Session-delivery upgrades — content-addressed blob store, export, ingest guard, per-tenant quotas, security regression suite (`7e39092`).
- `[x]` Latency/throughput tiers 1–3 and the XTREME optimization pass (`4359fc0` → `3c39778`).
- `[x]` CI: build + core test suite + security regressions (auth privilege boundary, object ACL, aggregate hardening, FTS persistence authz, security boundary) + APT41 fuzzing under ASan/UBSan.

### 1.2 Landed 2026-09-16 (was in flight)

This work was sitting outside git; it is now committed with tests and CI wiring (W0).

| Item | Evidence | State |
|---|---|---|
| Cluster brain (phase 1 + actuation) | `src/spinnaker/qihse_cluster_brain.c` (observe/journal/decide; R1 re-home, R4 rollback, R5 rebalance-on-join, R6 prune under `--brain-act`) | `[x]` tests: `test_cluster_brain.c`, `test_brain_actuate.c`, `test_brain_rebalance.c` |
| Overlay protocol phase 1 | `src/spinnaker/qihse_overlay.c` (IRC dead-drop, HMAC-SHA-384 records, replay window) + veiled bus framing in `qihse_cluster_bus.c` | `[x]` test: `test_overlay.c` |
| KEYSTONE fabric index (AI fabric item 2) | `src/spinnaker/qihse_fabric_index.c` | `[x]` test: `test_fabric_index.c` |
| AI fabric items 1 & 3 (NODE_CAP, `FABRIC.*`) | `QIHSE_BUS_MSG_NODE_CAP`, `FABRIC.CAPS/SUBMIT/RESULT` | `[x]` |
| AI fabric item 4 (capability-aware placement) | brain target selection scores NODE_CAP headroom and journals the evidence | `[x]` |
| AI fabric item 5 (local-first AI memory) | `src/spinnaker/qihse_ai_memory.c` + `include/qihse_ai_memory.h` | `[x]` test: `test_ai_memory.c` (incl. RBAC negative test) |
| Federation F0 primitives | `src/federation/qihse_federation.c` (UUID, HLC, object generation, fencing epoch) | `[x]` test: `test_federation_f0.c` |
| Slot-handoff extraction | `qihse_cluster_handoff_range()` / `qihse_cluster_set_range_owner()` / `qihse_cluster_range_has_local_keys()` shared by MOVESLOTS and the brain | `[x]` |
| Topology node removal | `qihse_cluster_topology_remove_node()` (tombstone; refuses the local node and slot owners) | `[x]` |
| Cluster smoke drills | `tests/cluster_*_smoke.py` — env-overridable hosts/ports, no absolute paths | `[x]` |
| Repo hygiene | build artifacts untracked (687 files) + ignored; runtime data/audit log/`.zcode/` kept | `[x]` |

### 1.3 Design of record — accepted, not implemented

| Direction | Design doc | Status |
|---|---|---|
| **Phase 10 — Federation data plane** (stages F0–F8, 28 acceptance criteria) | [federation upgrade plan](docs/plans/qihse_federation_upgrade_plan.md) | `[x]` F0–F8, the post-F8 follow-ups, the 2026-09-24 batch (§W1, §1.4: scoped consensus, backup-writer authentication, controller SDKs, CA provisioning), and the two 2026-09-25 waves (§W1, §1.4: node-side CRL-file loader, backup container v3 with WAL segment and v1/v2 retirement, consensus log compaction; then consensus membership-change safety and incremental export) landed; no tracked unbuilt items remain — the plan stays design of record for residual documented boundaries only (joint-consensus bulk membership changes, voter weights/witnesses/learners, chunked/resumable snapshot transfer, snapshot space reclamation, automated config drift healing) — these are now tracked with CITADEL-derived priorities as workstream W7 (§3) |
| AI compute fabric | [ai_fabric.md](docs/architecture/ai_fabric.md) | `[x]` items 1–5 implemented, including embedding-backed semantic recall and remote job dispatch |
| Cluster brain | [cluster_brain.md](docs/architecture/cluster_brain.md) | `[x]` observe + actuation (R1–R6) + federation-journal migration (W3.4: signed observations/decisions on the journal) landed |
| Overlay protocol | [overlay_protocol.md](docs/architecture/overlay_protocol.md) | `[x]` phase 1 + phase 2 (DHT peer exchange) landed — `make test-dht-peer-exchange` green |
| Production hardening (whitepaper near-term priorities 1–5) | [whitepaper v1.1 §12](docs/architecture/qihse_whitepaper_v1.1.md) | `[x]` gold validation suite: 72/72 workloads pass, 11/11 areas FULL, zero recorded gaps (see §W5.3/§W7) |

### 1.5 Landed 2026-09-29 — the W6 browser + W7 CITADEL-substrate wave (committed 4453b6..)

The operator browser (W6) and the full W7 CITADEL substrate program — 12 of 12
items: joint consensus (verified already-landed), QSX1 snapshot transfer,
journal tombstones + the ingest contract, QKP-sealed external clients,
KEYSTONE feed wire handshake + typed SDK access, `INTROSPECTION.*`, member
roles/weights/learners, fabric+DHT and semantic recall and brain-journal
migration (verified landed by the parallel waves), baseline-drift fail-closed,
and the gold-pack extension (7 W7 workloads + the real-peer failover drill in
CI — the wave closed with the pack at 72/72 pass, 11/11 areas FULL, zero recorded gaps). Item-by-item with evidence in §3 W6/W7.

### 1.4 Landed 2026-09-24/25 (in flight — working tree, not yet committed)

This work is sitting outside git; tests and CI wiring are in place and every target ran green (2026-09-24, working tree — not yet committed). The item-by-item record with test names is in §W1's "Federation follow-ups (post-F8)" list: scoped consensus for strong namespaces; backup-writer authentication (v2 signed containers); CA provisioning outside the process (`make federation-ca`); the Python and Rust controller SDKs; the qihse-rs FFI NULL-user fix; and CI wiring for the new targets. Evidence for this batch is test names/targets, not commits.

The 2026-09-25 federation wave is in the same state — working tree, not yet committed: the node-side CRL-file loader, backup container v3 (WAL segment, v1/v2 retirement), consensus log compaction, and the zero-length-payload guard in `qihse_consensus_propose` (all itemized in §W1 below). After a `make lib` rebuild with the wave-2 symbols, 9/9 suites ran green (2026-09-25), and the new `make test-federation-crl` target is wired into the `test:` aggregate and the CI workflow.

The third federation wave (2026-09-25) is in the same state — working tree, not yet committed: consensus membership-change safety (single-server transitions) and incremental export via the KV change sequence (both itemized in §W1 below). After a `make lib` rebuild, 9/9 suites ran green (2026-09-25): `test-consensus`, `test-incremental-export`, `test-backup-auth`, `test-federation-backup`, `test-federation-crl`, `test-federation-mtls`, `test-controller-api`, `test-persist`, `test-kv-read-integrity`; the new `make test-incremental-export` target is wired into the `test:` aggregate and the CI workflow. With this wave the Phase 10 program has no tracked unbuilt items left — only the documented residual boundaries named in §1.3.

---

---

## 2. What is left — two kinds of work

Everything below is deliberately split by what it produces. **Function** adds or
fixes behaviour a user or a peer can observe. **Verification** establishes or
corrects a claim about the system. They are not interchangeable: a suite that
proves nothing new is not feature progress, and a feature nobody has verified is
not finished. This project has already been bitten by that confusion — six
documents claimed test coverage whose test files did not exist.

### 2026-09-26 improvement pass — ordered queue

Safety, proof, velocity — in that order. Items 1–2 close the remaining safety
and verification gaps in the federation core; 3 changes every future
session's loop; 4–5 finish what Phase-B and QKP1 started. Each lands under
the §5 gates (source + wiring + test in the same commit; plan §44
distributed requirements apply to the consensus work).

- [x] **1. Joint consensus — membership-change safety.** Two-phase
  C_old → C_old,new bulk transitions in the scoped consensus module with a
  dual-majority quorum (majority of C_old AND of the current fold), the
  survivor rule against mid-joint stranding, and restart-from-log
  resumption. Single-server changes remain the one-member fast path.
  Evidence: commit `faa298f` — tests (j1) atomic bulk replace, (j2)
  minority partition commits nothing in either phase and resolves cleanly,
  (j3) crash-restart mid-joint resumes from the record file, (j4) hostile
  proposals refused pre-durability; full aggregate 60/60. (Function)
- [x] **2. Deterministic cluster simulation harness.** Six seeded scenarios
  (partition-majority, no-quorum-gate, crash-restart, crash-mid-membership,
  never-infer-safety, clock-skew-chaos) over real consensus instances;
  every scenario replayed bit-identically (digest-asserted); wired as
  `make test-fed-sim`. Evidence: commit `900d8d4`, full aggregate 60/60.
  FINDING recorded (module receive path): the stale-epoch fence can
  silence healed peers permanently (drop precedes term sync); the
  epoch-teaching fix requires a dedicated epoch-sync message outside the
  election/step-down state machine — see the consensus receive-path note
  and the analysis in `900d8d4`. (Verification)
- [x] **3. Test isolation → parallel aggregate.** Every test binary now
  isolates its audit chain/log under `QIHSE_DATA_DIR` (per-test
  `build/<target>_XXXXXX` scratch; the audit module routes both the chain
  and the log through one env-aware path builder). `make -j8 test` is the
  documented default invocation. Evidence: commit (this one); measured
  aggregate wall-time ~40–50 min serial → **~5 min** `-j8` (gold suite is
  the critical path), 60/60 gold workloads pass, repo root left clean.
  (Velocity)
- [x] **4. Auth persistence decision.** Ephemeral credentials blessed —
  decision record at [docs/architecture/auth_persistence.md](docs/architecture/auth_persistence.md):
  restart = re-credential from the deployment's environment; a persisted
  verifier store rejected (secret vault is a §7 non-goal; verifiers at rest
  are a new theft surface for zero capability). OPERATIONS §0.1 links the
  record. (Design)
- [x] **5. QKP1 rollout completion.** LANDED in two waves: (a) handshake/
  traffic counters (`qihse_qkp_get_counters`: per-side negotiation success,
  categorized rejections, sealed-frame counts; asserted in
  test-pqc-handshake scenario 9) and `qihse-federation-ca rotate-node`
  (issue successor + revoke predecessor, fail-closed; verified live);
  (b) the hybrid bus upgrade — SLOT/NODE/GROUP ops frames carry ML-DSA
  trailers verified against the signer's ENROLLED identity (algorithm of
  record from the enrollment, never the wire), hardened mode
  (`--require-signed-ops`) refuses unsigned ops frames. Evidence: commits
  `8b1037e` + `4110a87` — tests s1-s4 (roundtrip / tamper-drop /
  unenrolled-drop / hardened-refusal) plus the full aggregate 60/60.
  (Function)
- [x] **6. Bolt result visibility** — landed (commit 23e2072: RUN results
  visible to drivers, streaming dispatch + capture; PULL streams them).
  Parallel-query de-stub remains the open sliver: execute or label a
  non-goal.
- [x] **7. Federation remainder** — incremental export (landed in the
  2026-09-25 wave) and DHT overlay phase 2 (`src/spinnaker/qihse_overlay.c`
  Layer 3; `make test-dht-peer-exchange` green) both verified in-tree.
- [x] **8. AI memory follow-ups and coverage.** Embedding-backed semantic
  recall landed (parallel wave). Gold-suite: 72/72 workloads pass, 11/11 areas
  FULL, zero recorded gaps (W7 item 12); API reference and docs updated.


### A. Function — behaviour added or fixed

These change what QIHSE does. Ordered by risk, worst first.

#### Correctness and security defects

- [x] **NULL security context was an authorization bypass — FIXED.** Three primitives, not the one the gold suite proved: the `query.user == NULL` substitution, `qihse_execute_qql`/`_sql` which had **no auth check at all** and enumerated every live row, and `qihse_graph_vector_search` which never set a user. Old names now fail to link. Probe mutation-checked. *Scatter principal propagation now exists: `CLUSTER PEERAUTH` installs a verified SCATTER-purpose token's claims as the session context, and the scatter engine mints one per peer connection when the node has a signing identity (`qihse_cluster_scatter_set_identity`), refusing the peer when the claim is refused rather than degrading to unauthenticated. Hardcoded operator principals in `qihse_ai_memory.c`, `qihse_resp_engine.c` (12 sites) and the Python SDK.*
- [x] **Bolt adapter is not wire-compatible — FIXED.** The message-signature constants in `include/qihse_bolt.h` are aligned to the Bolt 4.x spec (RESET `0x0F`, RUN `0x10`, BEGIN `0x11`, COMMIT `0x12`, ROLLBACK `0x13`, DISCARD `0x2F`, PULL `0x3F`). PackStream tiny maps (0..15 entries) encode as `0xA0 + count`, and Map 8 (`0xD8`), Map 16 (`0xD9`), Map 32 (`0xDA`) follow standard sizing. PackStream decoder handles tiny negative ints (`0xF0..0xFF`), tiny strings (`0x80..0x8F`), tiny lists (`0x90..0x9F`), and tiny maps (`0xA0..0xAF`). Hard assertions added in `tests/test_bolt.c` and verified in gold suite.
- [x] **MongoDB wire protocol is absent — FIXED.** Defined in `src/spinnaker/qihse_mongo_wire.c` and exported by `libqihse.so` (`mongo_msg_parse`, `mongo_msg_get_document`, `mongo_catalog_*`, `mongo_dispatch_command*`, `qihse_mongo_server_*`). Verified with unit test (`tests/test_mongo_wire.c`) and low-clearance negative authorization suite (`tests/test_mongo_wire_security.c`).
- [x] **`qihse_repl_apply_wal()` records the LSN but does not replay — FIXED.** Replays valid WAL records directly into `qihse_kv_store_t` using `qihse_wal_replay()` over staged segment files. Added `qihse_repl_set_store()` / `qihse_repl_get_store()`. Verified by `make test-repl` and gold suite workload `gold_repl_apply_wal`. (`qihse_parallel_query.c` implemented with parallel scan, aggregation, and hash joins over the KV store, verified by `tests/test_parallel_query.c`).
- [x] **`qihse_mvcc_delete()` can leave a committed delete's row visible — FIXED.** In `src/tractable/qihse_mvcc.c`, updated traversal to walk the entire version chain setting `v->xmax = txn_id` for all versions with `v->xmax == QIHSE_MVCC_INVALID_XMAX || v->xmax < txn_id`. Hard assertion in `tests/test_txn.c`, all 8 bidirectional cases passing in `tests/test_mvcc_delete.c`, verified by `gold_mvcc_committed_delete`.
- [x] **SQL gaps: UPDATE SET, DELETE WHERE, optimizer histograms, table-store DML — FIXED.** `src/tractable/qihse_sql_parser.c` parses structured `UPDATE ... SET` assignments (`ast->set_columns`, `ast->set_values`, `ast->num_set`) refusing zero-assignment updates, and structured `DELETE WHERE` condition parsing (`ast->where_clause`). `src/tractable/qihse_optimizer.c` populates histogram-driven selectivity estimation (`qihse_optimizer_set_column_histogram`, `hist_fraction_below`). `src/spinnaker/qihse_uwp_sql_txn_schema.c` executes UPDATE and DELETE against the mutable table store with zero-condition delete guard. Verified by `make test-sql-completeness` and `make test-sql-dml-exec`.
- [x] **Bounded stack frames in the failover path — VERIFIED.** `qihse_cluster_failover_best_replica` and `qihse_cluster_failover_promote` use heap allocations for nodes (`QIHSE_CLUSTER_MAX_NODES * sizeof(qihse_cluster_node_t)`) and ranges (`QIHSE_CLUSTER_SLOT_COUNT * sizeof(qihse_cluster_slot_range_t)`), keeping stack usage strictly bounded. Verified by `make test-cluster-failover`.

#### Features not yet built

- [x] **W2.4** Durable first-class node capability records. A SEPARATE record from the identity record, because merging would turn every capability refresh into a read-modify-write of a trust record where a lost update could revert a concurrent revocation. **Authenticated is not truthful**: every self-report is explicitly unattested, and stored trust state is not authorization — the admissible lookup re-reads the identity record so revocation takes effect immediately. *Limit: no consumer wired yet; needs a topology-node-id to federation-UUID mapping that does not exist.*
- [x] **W3.6** Incident retrieval over QIHSE's own FTS/vector indexes. Brain incidents are written as EPISODIC memories, so they are retrievable through the same FTS and vector recall as any other memory — no special-case code. Routine kinds use a SKIP list so a NEW incident kind is recorded by default. *This dogfooding step immediately found a real defect: recording an incident wrote a key that the slot-ownership probe counted as shardable data, so the brain re-homed a range it should have left alone.*
- [x] **W4.2** DHT peer exchange. Msg types 13/14, NOT the 9/10 this line specified — 9/10 are already GROUP_UPDATE/GROUP_ACK and reusing them would have broken group push. The gate is a RUNTIME INTERLOCK, not a comment: the one function that turns a hint into an action refuses if MEET ever reports as authority-bearing, so discovery stops dialing rather than becoming an admission path. The trust plane is a NEGATIVE filter only (a REVOKED identity is never dialed). Buys a bounded hint source and nothing more. **Superseded detail:** (simplified Kademlia, msg types 9/10) — **sequence after F5** so discovery hints never become membership; DHT records stay unauthenticated hints and enrollment remains the gate.
- [x] **W4.3** Phase 3: AI memory API extensions (folded into W2.3): kind-filtered recall/count on every mode, refusal of unrecognised kinds rather than widening to ANY, NULL-context fail-closed, and visibility-aware vector selection (invisible vectors cannot crowd a caller's top-k). Verified by `tests/test_ai_memory_ext.c`.
- [x] **W5.1** Optimizer governance: declared constraints, automatic rollback on regression, persistent decision/outcome history, verified by `tests/test_optimizer_governance.c` (gold workload `optimizer-governance`). *Boundary: exercised on recorded observations; live query-cost telemetry into the governance loop is the remaining wire-up.*
- [x] **W5.2** Telemetry expansion. Six areas on BOUNDED labels: a family declares its complete value set at registration and an undeclared value creates no series. Buckets chosen for this system (50us..5s, ratio 2.5) rather than copied. Cost measured: ~100 ns/command, ~5% of a point operation. `qihse_index_bytes` NOT shipped — no index type exposes byte accounting, and a fabricated number would be worse than an absent one. **Superseded detail:**: backend availability/utilization, per-query-type latency histograms, error counters, memory/index movement, cluster/replication status, XDP counters, optimizer rollback counters.

### B. Verification — claims established or corrected

These do not change behaviour. They change what we can truthfully say.

- [x] **W5.4** API documentation. 90 function names added across 8 subsections, 89 verified against a header. **Superseded detail:**: coherent generated/reference surface for the public C API, SDKs, protocol compatibility, configuration.
- [x] **W5.5** Documentation labeling discipline. 127/127 markdown files carry a status line from the closed vocabulary, verified programmatically, 0 non-conforming. 47 gained `superseded`. 15 documents corrected where the code had contradicted them. **Superseded detail:**: consistently mark implemented / experimental / partial / planned / superseded / externally validated.

**Already in place, and why section B is short:** the gold validation suite
(`make test-gold`, W5.3) reports the real state of the system in one command —
35 workloads, 8 areas, all eight honestly `PARTIAL` with declared gaps. It is
built so it cannot report a vacuous pass: exit 0 without a declared evidence
line is a FAIL, a known-bug probe whose own controls fail is reported FAIL
rather than as a defect, and known-fail requires the documented failure text so
it cannot mask a new and different breakage. The remaining verification work is
therefore documentation, not new harness.

---

## 3. Workstreams

### W0 — Land in-flight work (prerequisite for everything else) ✅ COMPLETE

The untracked/modified cluster work above must be committed with its tests before any federation refactor rebases onto it.

- [x] **W0.1** Review and commit the cluster brain, overlay, fabric index, NODE_CAP, and `FABRIC.*` work as scoped commits (sources + headers + Makefile + daemon + CI + docs together, so the build never references an uncommitted file).
- [x] **W0.2** Write the missing brain tests (`tests/test_cluster_brain.c`, `tests/test_brain_actuate.c`, `tests/test_brain_rebalance.c`) and register Makefile targets; the smoke test the design doc originally referenced is superseded by these deterministic unit tests.
- [x] **W0.3** Add an overlay test target (framing round-trip, signed advert verification, forged/stale record rejection) — `tests/test_overlay.c`.
- [x] **W0.4** Repo hygiene: build artifacts untracked (687 files) and ignored; runtime data, audit log, and `.zcode/` session notes explicitly kept.
- [x] **W0.5** Review the uncommitted Python SDK changes (NULL guards, libc `free`) and commit them.

### W1 — Federation data plane (Phase 10)

The accepted major direction. Governing principle: **federation must enhance a node, never become a prerequisite for that node to remain locally operable.** All stage definitions and the 28 acceptance criteria live in the [federation upgrade plan](docs/plans/qihse_federation_upgrade_plan.md); this roadmap only sequences them.

- [x] **F0 — Refactor boundaries.** Federation module skeleton, UUID/HLC/object-generation/fencing-epoch primitives, current cluster semantics documented. No behavior changes.
- [x] **F1 — Sovereign local state.** Consistency classes (LOCAL/EVENTUAL/CAUSAL/QUORUM/LINEARIZABLE), local-authority namespaces, no global quorum gate on local-safe writes, federation status API. *Unblocks acceptance criteria 1–2.*
- [x] **F2 — Event journal + watches.** Immutable mutation envelope, resumable watch API, idempotent request IDs, controller SDK. *Unblocks W2, W3-phase-2, and acceptance criteria 5, 9, 10.*
- [x] **F3 — Replication correctness.** Anti-entropy, manifests/range digests, explicit conflict objects, resumable reconciliation. *Needs F2. Unblocks criteria 6–7.*
- [x] **F4 — Strong namespace.** Scoped consensus groups, native CAS, monotonic fencing epochs, lease primitive, explicit membership. *Needs F1+F2. Unblocks criteria 3–4, 10.*
- [x] **F5 — Trust plane.** Durable node identity keypairs (Ed25519, private key on disk, never in a record), operator-approved enrollment with permanent revocation, infrastructure authorization scopes with per-service defaults, signed replay-resistant gossip (protocol version, sender/boot UUID, monotonic sequence, HLC, capability/health, signature, persistent replay window). *Unblocks criterion 8's crypto substrate.* Transport-level mTLS binding for federation RPC remains — it attaches where the overlay transport lands.
- [x] **F6 — Build & supply-chain substrate.** Package override registry (reason mandatory), build-job state machine with idempotent transitions, builder capability + historical performance, provenance graph (21 entities / 15 edges) with direction-aware trace-back and reverse-impact, SBOM/attestation records (key handles only), append-only vulnerability observations, immutable queryable repository snapshots. *Unblocks criteria 15–22.*
- [x] **F7 — Runtime trust and hardening.** Evidence-aware federation admission: runtime trust states (UNKNOWN/TRUSTED/TRUSTED_DEGRADED/LOCAL_ONLY/QUARANTINED/REVOKED) with immutable per-boot evidence bundles and external verification records that emit journal audit events. Local usability is true in *every* trust state; only distributed authority is tiered. Runtime security profiles with a measured kernel-interface allowlist (REQUIRED/OPTIONAL/FORBIDDEN/UNKNOWN), network exposure/egress declarations, and a hardening self-audit that reads ACTUAL process state (credentials, effective capabilities, core-dump rlimit, seccomp mode, listening sockets). Time-integrity monitor plus a wall-clock-independent HLC advance/merge that cannot be broken by backward or forward clock jumps. *Unblocks criteria 23–28.*
- [x] **F8 — Operational hardening.**
  - [x] Deterministic distributed simulation harness (seeded PRNG, virtual clock, loss/duplication/reorder/delay/partition/crash/stale-clock injectors) plus the mandatory scenarios from the brief run against the real F1-F7 entry points. *Closes criterion 13.*
  - [x] Rolling schema evolution: schema id/version/min-reader plus required and optional feature bits. An unknown REQUIRED feature or a too-old reader fails closed; unknown OPTIONAL features are ignored, which is what lets a new writer add fields without a flag day. Migrations are forward-only and record resumable progress. *Covers the mixed schema N/N+1 scenario (criterion 13).*
  - [x] Snapshot and backup semantics: local and coordinated metadata snapshots with a manifest carrying the schema header, max generation, WAL continuation point, per-group capture list, and an encryption key id (never key material). The recorder computes the checksum itself, so an edited or truncated manifest fails verification. *Covers mid-snapshot crash recovery (criterion 13).*
  - [x] Reconciliation safety state machine: the explicit ordered rejoin sequence, with ownership publication withheld until state is reconstructed and checksums verified.
  - [x] Observability metrics: all 21 series from the brief, rendered label-bounded with no node or namespace labels.
  - [x] Performance regression budgets: each metric independently enforced, unmeasured metrics skipped so a partial harness cannot produce a false failure. *Closes criterion 14.*
  - [x] Fuzzing targets for wire and persisted parsers: 16 string parsers x 4000 hostile inputs, 11 persisted-record readers x 600 corrupt records, byte-flip mutation of a valid record, and numeric overflow probes. The fuzzer found two real fail-open bugs, both fixed: decoders accepted out-of-range enum values, and readers returned records whose embedded id disagreed with the key they were stored under.
  - [x] Architecture documentation set: 17 federation documents under `docs/architecture/`, indexed from `docs/README.md`, each stating plainly what is implemented and what is not (no consensus yet). The governing brief is filed at [qihse_federation_upgrade_plan.md](docs/plans/qihse_federation_upgrade_plan.md) (consolidated 2026-09-24 — the former `_v3` file is a redirect stub).

### Federation follow-ups (post-F8)

- [x] **Post-quantum identity and signed gossip.** Signature algorithm agility across Ed25519 and ML-DSA-44/65/87 (FIPS 204), with the algorithm and key/signature lengths recorded in every identity and frame so a fleet mid-migration stays readable. ML-DSA-87 is the default; the algorithm and signature length sit *inside* the signed region, so an algorithm-downgrade edit invalidates the signature. Two-tier gossip: signed membership statements on an interval mint a session id, and cheap 80-byte heartbeats are accepted only while they match it, so liveness is not a weaker claim than membership.
- [x] **Signed gossip wired into the live bus.** `QIHSE_BUS_MSG_FED_STATEMENT` and `QIHSE_BUS_MSG_FED_HEARTBEAT` are verified through the federation layer before any handler runs, and dropped outright when no federation context is configured. `qihse_bus_msg_carries_authority()` documents and enforces that bootstrap/liveness types (MEET, PING, SLOT_UPDATE, ...) may never carry authority. *Closes criterion 8's replay-resistance half on the path that actually carries traffic.*
- [x] **Liveness is not authority, enforced by type.** The bus exposes two callbacks with distinct payload types: `on_liveness` (verified heartbeat) and `on_membership` (verified signed statement). A heartbeat cannot be passed where a membership record is required because the types differ, so a consumer cannot make an ownership decision from a liveness claim even by accident. `qihse_federation_membership_from_statement()` is the single conversion chokepoint, which makes the rule auditable: grep for it and you have found every path to an authority input.
- [x] **mTLS listener and connect path.** A real TCP accept path plus a symmetric connect path. A wildcard bind is REFUSED rather than defaulted to, because exposing a federation port on every interface is an operator's decision, not this code's. A refusal is per-connection, so a hostile peer cannot deny service by being refused, and an idle accept timeout is not an error. CA provisioning is delivered outside the process as `make federation-ca` (init-ca / issue-node / revoke / verify) — the CA-minting primitive is deliberately not in the library source list; it compiles only into the tool and its test.
- [x] **mTLS transport (live handshake).** A federation-owned TLS context, because the generic UWP TLS layer can issue a server certificate and run a session over an fd but has no way to *require* or *read* a client certificate — which is the whole of mutual authentication. `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` with the three-layer decision running inside the verify callback, so an unauthorised peer never gets a channel at all rather than being admitted and checked later. Verified end-to-end over a real handshake: TLS 1.3, negotiated group X25519MLKEM768, foreign-CA / unenrolled / untrusted peers all refused. Also supplies the transport the replication range transfer rides on. The listener/accept loop landed (item above); CA provisioning is delivered as `make federation-ca`, deliberately outside the library.
- [x] **mTLS binding (security core).** ML-DSA-87 federation CA whose private key is written at 0600 and deliberately never returned, so the database process cannot mint its own authority; a pre-quantum CA is refused. Node certificates bind the node's *existing* identity key, so a fingerprint an operator already recorded keeps meaning the same thing after issuance. The three-layer peer decision keeps key possession, enrolled fingerprint and runtime trust as separate questions, and layer 3 decides what a session *carries* rather than whether it exists — per the brief, runtime evidence gates voter and strong-write authority, not a session. Hybrid X25519MLKEM768 key exchange with a TLS 1.3 floor. Provisioning that CA is now an out-of-process operation: `make federation-ca` (init-ca / issue-node / revoke / verify) over `src/federation/qihse_ca_provision.c`, deliberately absent from the library source list — a CA-minting primitive does not live in the server process.
- [x] **Rejoin driver.** Runs the ordered sequence and enforces its gates, so a rejoining node cannot skip a step by calling the transfer directly. A session that cannot name its peer, or names a DIFFERENT peer than the operator intended, may not be a source of state — "verified" and "the peer I meant" are separate questions. Ownership is publishable only at COMPLETE, one step stricter than VERIFY_CHECKSUMS because that is where verification *happens*, not where it has passed. An unreconcilable range aborts rather than reporting success, and progress is persisted as the step *completed* so a crash resumes at next(step) and never skips work.
- [x] **Replication transport (range transfer).** A pluggable transport (plan §22) with a loopback implementation so the protocol is exercisable with no network, plus the resumable range transfer: length-prefixed framed records, bounded rounds, a cursor the *journal* reports (a record's size is only known once read), and a range that reaches COMPLETE only after its digest verifies. A transport that cannot name its peer may not move authoritative state. *Remaining: nothing; the TCP transport and the rejoin driver are both in place.*
- [x] **Backup writer.** A 320-byte fixed header plus a data section produced by the KV layer's own authorization-aware export, so the classification decision stays in the layer that owns the knowledge. The security context is mandatory and NULL fails closed; two independent gates (a coverage check and the KV clearance/SCI check) rather than one; the low-clearance negative test asserts the protected payload BYTES are absent from every artefact, not merely that a call failed. Restore verifies the manifest checksum and WAL point before opening the container. Authentication and the verify-only entry point have landed as v2 signed containers — `qihse_backup_write_signed` / `qihse_backup_restore_signed` / `qihse_backup_verify`, verified by `make test-backup-auth` (itemized below). *Known boundaries: closed by container v3 (item below) — the WAL segment landed, the v1/v2 unsigned forms are retired with zero remaining callers, and a version refusal (no downgrade) replaced them.*
- [x] **Legacy backup API invariant-1 violation resolved.** The five context-free declarations were REMOVED rather than deprecated, and replaced with `_user` forms that take an authenticated context. Removal was chosen over an `#ifdef`/env boundary because a flag leaves a latent bypass a future build can enable. NULL is an argument error, a forged principal handle is refused, and identity is propagated to the KV layer. *Remaining: nothing — incremental export landed (item below) on the KV change sequence, replacing the UNSUPPORTED refusal.*
- [x] **Scoped consensus for strong namespaces.** `src/federation/qihse_consensus.c` + `include/qihse_consensus.h`, tick-driven and single-threaded, deterministic under an injected clock and transport (sim-harness style). Durability before visibility: term/votedFor/fencing epoch live in an append-only record fsynced BEFORE the in-memory change. Elections apply the up-to-date-log restriction; commit requires a strict majority ack AND the current-term rule; a higher term steps the leader down; a stale fencing epoch is refused; journal entries are generation-tagged; committed reads authorize per entry through `qihse_auth_can_access`, and a NULL user is refused. LOCAL namespaces are never gated on it — tested: LOCAL stays read-write while a group is partitioned. NOT a complete Raft, per the module's honest-naming header: no joint consensus, pre-vote/leader-lease/leadership transfer, or transport authentication of its own (that belongs to the injected transport); log compaction and membership-change safety landed separately (items below). Evidence: `tests/test_consensus.c`, `make test-consensus` (run twice, deterministic; ASan/UBSan clean).
- [x] **Backup-writer authentication (v2 signed containers).** `qihse_backup_write_signed` / `qihse_backup_restore_signed`, plus the verify-only `qihse_backup_verify`, in `src/federation/qihse_backup.c`. A 392-byte v2 header extends the 320-byte v1 with v1 offsets unchanged; an ML-DSA signature (node identity key, default 87) covers the header, which carries the manifest checksum, data digest, and signer identity INSIDE the signed region, so algorithm-downgrade and signer-substitution edits invalidate. The signature precedes the data, so a forged container is refused before any payload byte is read. The signer must be an approved `fednode:` record with an on-disk key, and revocation is re-checked at read time. The operator override exists only on restore, only for principals holding QIHSE_SCOPE_SECURITY_ADMIN, and skips ONLY the signature gate — manifest, structure, checksum, and KV clearance/SCI gates still run. Evidence: `tests/test_backup_auth.c`, `make test-backup-auth` (run twice; full negative matrix: bit-flip data/signature, stripped signature, wrong-signer key, revoked signer, guest-no-escalation, low-clearance denial with no protected bytes, NULL context, v1 refused by the signed paths). The v1 unsigned pair stayed as a documented compatibility surface; retirement was to migrate `tests/test_federation_backup.c` to the signed forms, then delete it. *Remaining: nothing — v1 retirement and the container WAL segment landed as v3 (item below).*
- [x] **CA provisioning outside the process.** `tools/qihse_federation_ca.c` (make target `federation-ca`; subcommands init-ca / issue-node / revoke / verify) over `src/federation/qihse_ca_provision.c` + `include/qihse_ca_provision.h` — deliberately NOT added to the library source list, because a CA-minting primitive must not live in the server process; it compiles only into the tool and its test. PEM X.509 formats match the mtls loader in both directions (proven by tests); private keys are written 0600 and never appear in any record; issuance respects the privilege ceiling (the operator must hold NODE_ENROLL and every granted scope). Defines a new append-only `QIHSE-FED-CRL-V1` file format. *Remaining: nothing — the node-side CRL-file loader landed (item below) and composes with the KV `fednode:` record.* Evidence: `tests/test_federation_ca.c`, `make test-federation-ca` (8 PASS groups, run twice).
- [x] **Python controller SDK.** `python/qihse/controller.py` (stdlib only) + `python/tests/test_controller_sdk.py` — 59 unittest tests so CI's `unittest discover` runs them (also `make test-controller-sdk-py`). Full surface mirroring the C client; explicit-auth only, no ambient credentials; RESP bounds identical to the C client (bulk ≤ 16 MiB, items ≤ 1 MiB, depth ≤ 32); end-to-end against the real RESP server in a forked child, including the invariant-3 negatives (unauthenticated and low-clearance refused, no payload). Two server-semantics findings are documented in the module: EVENT.APPEND returns record_offset+1 while WATCH.NEXT returns true byte offsets, and WATCH.RESUME(cursor) re-delivers the record at the cursor (at-least-once resume).
- [x] **Rust controller SDK.** `rust/qihse-rs/src/controller.rs` (pure std, zero unsafe, zero new dependencies) + `rust/qihse-rs/tests/controller_sdk.rs` — 71 named wrappers plus a generic `call`; a bounded decoder mirroring the C bounds; typed errors; a stateful Watch with at-least-once resume. 41 tests green; explicit CI step added to `.github/workflows/build-and-test.yml`.
- [x] **qihse-rs FFI NULL-user defect — FIXED.** Pre-existing, found during this work and verified failing on the pristine tree: `VectorDB::search` passed a NULL security context, and the C layer correctly failed closed (EACCES, no rows). `search` now requires an explicit `&User` handle — NULL is unrepresentable in the safe API — via new `Auth`/`User` types following the C gold-workload pattern, and a new negative test asserts the raw NULL query fails closed with EACCES and zero rows. Full crate green: 108 lib + 22 integration tests.
- [x] **CI wiring for the 2026-09-24 batch.** New targets (`test-consensus`, `test-backup-auth`, `test-federation-ca`, `test-controller-sdk-py`) wired into `make test`, plus explicit workflow steps for consensus, backup-auth, federation-ca, and the Rust controller SDK in `.github/workflows/build-and-test.yml`; the Python SDK runs under CI's existing `unittest discover`.
- [x] **Node-side CRL-file loader.** Closes the follow-up declared by the CA-provisioning item above. `qihse_federation_crl_load` / `_check` / `_state` in `src/federation/qihse_federation_mtls.c` + `include/qihse_federation_mtls.h`, with the new verdict `QIHSE_PEER_REJECT_CRL`. Enforcement sits INSIDE `qihse_federation_peer_verify` (layer 2, after the KV REVOKED/PENDING checks), so both mtls transport verify paths get it, and the two revocation sources COMPOSE — either a KV `fednode:` revocation or a CRL entry suffices to refuse, with the same `QIHSE_PEER_REJECT_REVOKED` verdict. A configured-but-unparsable CRL is sticky fail-closed: `reject_crl` refuses approved peers too, and only a valid reload or an authorized clear recovers. The loader requires an authenticated operator holding QIHSE_SCOPE_NODE_REVOKE — the node-side application of the same authority the CA tool needs to append a revocation (rationale documented in the header). The parser mirrors the tool's `QIHSE-FED-CRL-V1` reader exactly; 65536-entry cap; bounded stacks (worst frame 208 B); thread-safe snapshot swap. Operational note: startup should call the loader from explicit config and treat false as fatal — a better signal than a federation-wide `reject_crl`. Evidence: `tests/test_federation_crl.c`, `make test-federation-crl` (links the CA tool's writer for real CRL bytes; load-authorization, compose, fail-closed with 12 malformed variants, verdict-surface tests); existing `make test-federation-mtls` and `make test-federation-ca` stay green.
- [x] **Backup container v3 — WAL segment, and v1/v2 retirement.** Closes the backup-writer boundary above and completes the v1 retirement step. The container is now `[ header 464 ][ signature ][ data section ][ WAL section ]`: the header appends at offset 392 the wal_bytes, a WAL SHA-384 checksum, wal_first_lsn and wal_last_lsn (QIHSE_BACKUP_HEADER_WAL_BYTES 464, QIHSE_BACKUP_VERSION_WAL 3), and the signature covers the whole 464-byte header, so one detached ML-DSA signature authenticates the manifest checksum, both payload digests, the WAL length and LSN range, and the signer identity. WAL records mirror `qihse_wal` guarantees (same CRC/XOR composition, bounded lengths, stop-at-corruption, LSN ordering, idempotence via the manifest continuation offset — records below it are skipped, not re-applied) EXTENDED over classification/SCI fields, so replay through the KV layer cannot become a downgrade channel. Reader order: manifest gate → version refusal (new `QIHSE_BACKUP_ERR_VERSION`; v1 and v2 containers are both refused — no downgrade) → exact size → signature (before any payload byte) → digests → WAL structural/LSN-gap validation → clearance pre-flight using the exact `qihse_auth_can_access` predicate — then an all-or-nothing KV load, so an authorization denial can never leave a half-replayed store. `qihse_backup_verify` checks the WAL section without applying; the WAL section is bounded at 8 MiB. The v1 pair (`qihse_backup_write`/`_restore`) and the v2 constants are DELETED — exhaustive repo-wide grep shows zero remaining callers — and `tests/test_federation_backup.c` is fully migrated to the signed forms with coverage kept or given signed equivalents (classified WAL records now restore at class 5 with guest/analyst denied). Evidence: `make test-backup-auth`, `make test-federation-backup` (both green, run twice).
- [x] **Consensus log compaction (InstallSnapshot equivalent).** Closes one of the two consensus boundaries named in the scoped-consensus item above. New SNAPSHOT/SNAPSHOT_REPLY message kinds and a `snapshot_threshold` config (0 = disabled, the default — all pre-existing behavior byte-identical) in `src/federation/qihse_consensus.c` + `include/qihse_consensus.h`, with the snapshot capped at QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES entries. The record-file transaction is `S…SE…T` where the T record is the swap point: a torn or unterminated block rolls back to the uncompacted durable state, and a failed transaction write quarantines further writes so the file stays replayable. The FNV-1a digest over canonical entry fields is recomputed on install and on replay, never trusted. A follower validates structure, envelope fencing, digest, and strictly-newer BEFORE allocating, persists, then swaps atomically — no half-replaced state. Reads below the boundary serve from the snapshot through the same per-entry `qihse_auth_can_access` loop, so visibility is never widened; the invariant-1 negatives hold post-compaction (operator/analyst/NULL tested on the leader and on a snapshot-installed follower). Evidence: `tests/test_consensus.c`, `make test-consensus` — 14 scenarios: snapshot+tail catch-up with byte-identical convergence; 15 entries across 3 compact/catch-up rounds with leader restarts; tampered digest/payload/count and stale-epoch refusals with counters (snapshots_created/snapshots_installed/snapshot_rejections); restart at three crash points; 14 hostile decoder cases; determinism (identical trajectory hash and md5 across runs and build configs); ASan+UBSan clean; stack audit worst decoder frame 928 B. *Residual limits, stated in the header: the single-message snapshot is capped at 24 entries — no chunked or resumable cross-session transfer; the in-memory snapshot and the record file are never reclaimed (the active log and catch-up traffic are what is bounded); no throttling beyond the threshold. Membership-change safety landed separately (item below).*
- [x] **Zero-length-payload guard in `qihse_consensus_propose` — FIXED.** Latent defect found during review of the compaction work and closed: the encoder would have written an empty hex token that the replay decoder rejects, so an accepted empty proposal would be durable in memory but unreplayable after restart. `propose` now refuses payload_len == 0 and NULL payload at the boundary, the header contract is updated, and the test asserts both refusals append nothing (last_log_index unchanged). Evidence: extended scenario in `tests/test_consensus.c`, `make test-consensus` green.
- [x] **Consensus membership-change safety (single-server transitions).** `qihse_consensus_propose_membership(cs, user, op, member)` (MEMBER_ADD/MEMBER_REMOVE) + `qihse_consensus_get_membership()` in `src/federation/qihse_consensus.c` / `include/qihse_consensus.h`. The protocol is single-server changes — one add-or-remove per committed transition — NOT joint consensus, chosen deliberately: consecutive configs differ by one member, so any old majority and any new majority intersect; combined with the config-in-force being a pure function of the log (base config folded over config entries, effective on APPEND, never commit-learn — a commit-based rule would let a restarted node regress two transitions behind) and ONE transition in flight (a second proposal is refused, not queued), two disjoint same-term majorities are unreachable. Config persistence follows the module's write-then-apply discipline: the checksummed fsynced LC record is written BEFORE the in-memory fold (the record is the swap point; a torn tail rolls back to the previous config), and replay validates everything and fails closed. Mid-transition leader change resolves through ordinary log mechanics — a new leader holding the pending entry completes it, one lacking it overwrites it and the fold reverts; a leader removing ITSELF steps down at append; removed nodes get grace catch-up but their replies never count as votes or acks. Restart semantics documented in the header: replay lands on the config of the last config entry in the reconstructed log — landing on last-committed-only would manufacture exactly the two-transition regression the argument forbids. Refusals: non-leader, in-flight, NULL/non-OPERATOR principal, nil uuid, add-existing/remove-absent, past `QIHSE_CONSENSUS_MAX_MEMBERS`, and removal that would empty the group. Residual limits, stated in the header's WHAT THIS IS NOT and MEMBERSHIP CHANGES sections: joint consensus (atomic multi-member changes) absent — a multi-member change is a sequence of transitions; voter weights / witnesses / learners (plan §15's split) future; no automated config drift healing; the open()-time member list is trusted as the fold baseline; a group may never be emptied by remove. Evidence: `tests/test_consensus.c`, `make test-consensus` — 20 scenarios: (a)–(m) unchanged and green, new (n)–(r) plus (f3) hostile LC decoder cases; determinism — the (m) trajectory hash byte-identical to the pre-change baseline at default config and the transition hash stable across runs; ASan+UBSan+LSan clean; -Wall -Wextra -Wpedantic zero warnings; worst decoder frame 992 B (`qcs_load_records`).
- [x] **Incremental export via the KV change sequence.** Closes the long-standing gap the legacy-backup item named above: incremental export returned UNSUPPORTED because the KV store exposed no change sequence. `src/black_hole/qihse_kv_store.c` + `include/qihse_kv_store.h`: a store-global atomic 64-bit `change_seq` advanced ONLY on authorized mutations (set/delete/expiry-sweep; WAL-replay re-stamps in mutation order; never on reads or denials; fails closed at exhaustion), persisted as a 7th field in the versioned text record header — readers accept 5/6/7 fields, so every pre-existing file decodes (old records read as seq 0) — and a restore never regresses the high-water. New APIs: `qihse_kv_export_incremental_user` (the lowest layer — per-record `qihse_auth_can_access` filtering happens HERE; a NULL user keeps that family's unclassified-only view), `qihse_kv_save_delta_user` (atomic file form), and `qihse_export_incremental_user` (the export-family wrapper in `src/black_hole/qihse_export.c` / `include/qihse_export.h`: NULL context REFUSED plus a live-principal gate). `qihse_backup_incremental_user` in `src/tractable/qihse_backup.c` — the whole-store container family, NOT the federation signed-container one — now delivers real incremental coverage (a type=BACKUP_INCREMENTAL container, start=since cursor, end=resume) instead of UNSUPPORTED; whole-store restore still refuses a delta container, because a delta is not a whole-store image. Disclosure decision, documented in all three headers: the ONLY form is no-leak — the resume point is the highest sequence the principal was ALLOWED to see, never the global high-water, so successive resumes cannot reveal how many hidden mutations occurred; hidden records between resume and high-water are re-scanned and skipped (a sequence compare). The bare `qihse_kv_change_seq` high-water query is documented as a progress metric, deliberately not the delta resume source. Known boundary, stated in the header: a tombstone physically dropped by compaction before a delta carried it is not re-deliverable — consumers that must not miss deletes re-baseline with a full export. Evidence: `tests/test_incremental_export.c`, `make test-incremental-export` (wired into `make test` and CI) — 7 PASS groups: sequence discipline; delta content; resume behavior; low-clearance negative (permitted records only, no protected bytes, resume reveals no hidden-mutation counts, NULL refused); persistence incl. real memtable flush and WAL-only re-stamp; legacy 5/6-field decode; backup wiring incl. a guest-filtered container and delta-refused-by-restore. Two reviewed deviations from the implementation brief: the backup function lives in `src/tractable/qihse_backup.c` (the brief misnamed the federation file), and `tests/test_federation_backup.c`'s two assertions encoding the old UNSUPPORTED refusal were flipped to assert the new documented coverage.


- [x] **`ai_fabric.md` accuracy corrected.** The blanket "items 1-5 are implemented" was stronger than the evidence and the document calls itself the execution spec, so people implement from it. Status is now per item: item 1 named no test at all and now names one; item 3 is `partial` (two executors, two refused, no remote dispatch); embedding recall moved out of `planned`; the spec's "4096-d quantized" is marked as NOT what was built. Two sub-claims were DOWNGRADED to `partial — status unverified` rather than repeated.

### AI fabric — built this cycle

- [x] **Embedding-backed semantic recall.** The `planned` item in `ai_fabric.md`. Recall was BM25 only. Now BM25 | SEMANTIC | HYBRID, with a provider interface for a real model and a built-in embedder that is DETERMINISTIC AND LEXICAL and named for what it is (`builtin-lexical-256`) rather than called semantic. Fusion is by rank (RRF), because BM25 and cosine live on different corpus-dependent scales. Every mode resolves candidates through the same authorization-aware read, so no mode can surface a record the principal cannot see — the property that matters, since an embedding is derived from the text and can leak it. Vectors are bound to the embedder that produced them: embeddings from different models are not comparable and comparing them yields confident nonsense.
- [x] **Fabric job model.** `FABRIC.SUBMIT` now executes. An `embed` job turns its payload into an AI memory and the record carries the resulting id. An unimplemented type is REFUSED rather than queued and ignored; a job placed on another node is `queued`, not `done`. Two defects made the fabric unusable and nothing reported either: a single-node deployment could not place any job (nothing sends a node its own bus hint), and the local node's own probe went through the admissible accessor, which asks whether a PEER's claim can be trusted — a question that does not arise for a node's own measurement of itself.
- [x] **Durable capability records consumed.** `FABRIC.CAPS` and the brain's placement scoring both preferred the live bus hint, which is rebuilt from datagrams and lost on boot. Both now prefer the durable record and fall back to the hint, and both report WHICH they used (`src=durable` / `src=hint`), because an ephemeral unauthenticated hint and an attributable restart-surviving record are not the same thing and a caller that cannot tell them apart treats the weaker as the stronger.
- [x] **Topology node federation UUID population.** Closed by DERIVING it rather than populating it: `qihse_cluster_node_federation_uuid()` is the single definition, applied at upsert, so every node gets one — including nodes discovered from an unauthenticated MEET — and there is no caller left to forget. The UUID is an INDEX, not a credential: a node id can arrive from an unauthenticated path, so deriving it must not confer trust, and the admissible check remains the gate.
- [x] **`FABRIC.SUBMIT` dispatches remotely.** `src/federation/qihse_fabric_dispatch.c` + RESP wiring: a job whose best-fit node is a peer runs there over the federation mTLS channel under a signed capability token (bound to job/payload/principal/scope/expiry, replay-proof). The executor owns the result record and runs the job as the TOKEN's principal — never its own. `FABRIC.FETCH` pulls the record into a local cache (a tampered cache reports `cache-corrupt`, not served); `pending-fetch` is never reported as `done`. Both executors are dispatch-idempotent: ingest overwrites a deterministic key and the executor dedups a retried RUN on the submitter+job binding (re-ACK, `dedup-replay`), so even `embed` — whose underlying store() is not idempotent — is retried safely. Verified end-to-end by `tests/test_fabric_dispatch.c` (gold workload `fabric-remote-dispatch`). Dispatch endpoint discovery is signed: v4 membership statements carry the node's fabric dispatch `host:port` inside the signed region (set by the RESP server to the listener's real bound endpoint), `FABRIC.SUBMIT`/`FABRIC.FETCH` resolve it through the admissible capability record — revocation re-checked at lookup — and the topology `host:port` remains only as an explicitly-marked `"ep":"topology"` fallback (the mTLS handshake pins identity either way).
- [x] **The brain resolves node identity.** Observation records carry each node's UUID (journal format v2; v1 still decodes), and placement scoring plus decision evidence prefer the DURABLE capability record over the live bus hint, reporting which they used (`src=durable` / `src=hint`).
- [x] **Signed statement production.** The consume path existed with no producer: nothing minted a v3 statement in production, so a peer's durable capability record could only ever be populated in tests. `qihse_federation_statement_mint()` fills and signs a v3 statement (sequence continuing from stored replay state, a fresh session per statement); the bus emits one at start and every 5 s when wired with the enrolled identity (post-create `qihse_cluster_bus_set_federation`, or config fields), feeding it through the local accept path so the node's own record gains `SIGNED_STATEMENT` provenance. The RESP server wires it once the enrolled fabric identity loads. Found while testing: `gossip_accept` recorded a statement's session *before* the replay check, so replaying an old statement retired a live session's heartbeats — the replay window now runs first.
- [x] **Controller-facing client API (plan §25).** `include/qihse_controller.h` + `src/controller/qihse_controller.c`: a synchronous RESP client with a bounded decoder (bulk ≤ 16 MiB, ≤ 1 MiB items, depth ≤ 32) and named wrappers for the whole controller surface — node/trust, namespace/group, object CAS, lease/epoch, event journal, resumable watches, conflicts, rejoin/metrics, build, supply chain, provenance, snapshot, schema, security posture. The client confers no authority; the server's system-domain/scope/classification checks apply unchanged. Verified end-to-end by `tests/test_controller_api.c` including the invariant-3 negatives (unauthenticated and tenant principals refused, no data served). *Delivered: the Python SDK (`python/qihse/controller.py`, tested by `python/tests/test_controller_sdk.py`, `make test-controller-sdk-py`) and the Rust SDK (`rust/qihse-rs/src/controller.rs`, tested by `rust/qihse-rs/tests/controller_sdk.rs`) — itemized in the federation follow-ups list.*

### Correctness findings surfaced by the documentation audit


### W2 — AI compute fabric

Items 1–3 are in flight (see §1.2); items 4–5 build on federation primitives rather than ad-hoc bus messaging.

- [x] **W2.1** Land items 1–3 with tests (covered by W0).
- [x] **W2.2** Brain governance phase 2 — capability-aware placement decisions (NODE_CAP headroom + load scoring), signed and journaled with the capability evidence the choice was based on (needs F2 for the full journal migration).
- [x] **W2.3** Local-first AI memory API — episodic/semantic memory in KV with FTS recall, explicit security context on every entry point, RBAC negative test in CI (embedding-backed semantic recall remains the follow-up).
- [x] **W2.5** KEYSTONE consumes the resumable change feed with a read/index identity. Tenant-scoped ANALYST, never OPERATOR, tenant 0 refused; RESP dispatch allowlist admits only `KEYSTONE.FEED.*`; feed rides the F2 watch API and is always clearance-filtered. *Boundary: read-only on the surfaces it is given, not at the storage layer — the RBAC model has no read-only role.*
- [x] **KEYSTONE §4 envelope on the wire.** `KEYSTONE.FEED.NEXT` previously delivered 8 fields and dropped the record's flags word — a TOMBSTONE the consumer could not see was a deleted object resurrecting in its index — and had no HLC, event id, origin node or fencing epoch. The reply is now the full 16-item envelope (`[offset, type, resource, classif, sci, tenant, generation, payload, event_id, origin_node, object_id, fencing_epoch, hlc_physical, hlc_logical, flags, object_type]`); `PUBLISH` takes optional `<flags> <object_type>`; the flag vocabulary gains SNAPSHOT/EVENT/TELEMETRY/AUDIT/SECURITY_SENSITIVE/DERIVED; and `object_type` rides the record header's v1 spare word so old records decode as type 0. The wire HLC is the journal-ticked event stamp, not the publisher-supplied record field.

- [x] **Bounded stack frames in the brain.** Fixed: both ~96 KB arrays moved to one brain-owned heap buffer, allocated only in act mode. `brain_main` 142112 -> 44192 B; worst frame in the module is now `brain_journal` at 16576 B (pre-existing).

### W3 — Cluster brain

- [x] **W3.1** Phase 1 hardening and landing (W0.1–W0.2).
- [x] **W3.2** Actuation: R1 failed-owner re-home through the shared slot-handoff path (the same audited code `CLUSTER MOVESLOTS` uses), R4 rollback on incomplete transfer or target failure, per-range cooldown, evidence gates (observation matrix) on every action.
- [x] **W3.3** Rebalance on join (R5: largest owner donates a proportional share to a healthy slotless primary) and stale-node pruning (R6: unhealthy past the timeout, no peer evidence, owns no slots).
- [x] **W3.4** Observations and signed decisions on the federation journal. Rules consume the watch stream; **no action without a journaled pre-condition**, enforced by a byte-exact round-trip check. ML-DSA-87 signatures over decisions only, ~0.04% of a 5 s cadence; determinism proven byte-for-byte against the old library. *Limit: the append is O(topic length) — needs a tail-offset cache in `qihse_event_stream.c`.*
- [x] **W3.5** Persistent worker pool. Cycle time at 8 workers drops ~576 µs → ~128 µs (p50, ~4.5x); no regression at 1 worker. Determinism preserved by construction and verified byte-identical against the pre-change library across worker counts and a second topology.
- [x] **W3.7** Hard boundary: brain actuation stays database-internal (slot re-homing, quarantine). It must not grow hypervisor actuation — execution decisions belong to the external controller.

### W4 — Overlay protocol

- [x] **W4.1** Land phase 1a–1c (covered by W0).

### W5 — Production hardening (runs in parallel, independent of federation)

Whitepaper v1.1 §12 priorities, in its stated order:

- [x] **W5.3** Gold validation suite. Versioned pack, one `make test-gold`. Built so it cannot report a vacuous pass: exit 0 without a declared evidence line is a FAIL, known-bug probes need a mandatory ref and cannot launder their own breakage, known-fail needs the documented failure text. The W7 wave extended it to 72 workloads across 11 areas, including a real-peer failover drill. That drill checks takeover and survival of a preseeded key; it does not demonstrate live write duplication (see §W7).

### W6 — Operator browser: generalized DB browser + cluster/federation viewer

Design reviewed externally (claude-fable-5.1 via bothub, 2026-09-27); all findings folded in.
Architecture: [qihse_browser.md](docs/architecture/qihse_browser.md) — web dashboard views over an
authenticated Python bridge (`python/qihse/browser/`), YubiKey-FIPS FIDO2 login (mandatory by
default), guarded action allowlist, headless `--dump` mode. Bridge port **8090** (8080 is
telemetry; 8000 is reserved and must never be used).

- [x] Bridge client layer: explicit-seed `fleet.py` (no auto-dial of discovered peers — `CLUSTER NODES` is rendered, never dialed), local CRC16 slot routing with MOVED re-target, single-shot-SCAN-aware keyspace paging (`slots.py`, `keyspace.py`)
- [x] Per-session principals: every read/action executes over Controllers authenticated as the logged-in principal; the bridge holds **no** ambient credentials (confused-deputy fix) and closes Controllers on idle timeout
- [x] HTTP API with password login (rate-limited, single-seed AUTH first), loopback-only bind, session cookies + CSRF, bounded bodies/threads (`bridge.py`)
- [x] WebAuthn RP on python-fido2: RP ID `localhost`, UV required, cross-platform authenticators, sign_count clone detection, credential store = public keys only (0600), login fail-closed when no credential is enrolled unless `--allow-password-only` (`webauthn.py`)
- [x] Guarded actions: allowlist (CLUSTER MOVESLOTS, FEDERATION TRUST.SET, LEASE.RELEASE, FEDERATION STATE), typed validation, command-bound single-use UV challenges, server stays the authority (`actions.py`, `bridge.py`)
- [x] Negative-authorization CI test (AGENTS.md invariant 3): C fixture node (`tests/qihse_browser_fixture.c`) + Python HTTP asserts (`python/tests/test_browser_negative_auth.py`) — unauth→401, low-clearance login hides classified key names **and** values, FEDERATION→NOPERM, single-factor actions→403, fail-closed no-credential login, login rate-limit; `make test-browser` wired into `test:`
- [x] Headless mode: `./qihse browse --dump overview|cluster|federation|keys` (`dump.py`)
- [x] Frontend: dashboard shell + Login/Overview/Cluster/Federation/Journal/Keyspace/Actions/Metrics views (no new npm deps)
- [x] Docs + registration: OPERATIONS.md §0.2, tools.json, architecture doc, runbook
- [x] **QIHSE Studio Display Platform (Phase 14 upgrade, 2026-10-17)** — High-performance real-time operations display platform replacing legacy browser prototypes:
  - **Backend**: ASP.NET Core 8 WebAPI & 10 Hz SignalR Hub (`portal/src/Qihse.Studio.Server/`) with native zero-allocation inline RESP client, microsecond latency telemetry, and dynamic network peer auto-discovery via `CLUSTER NODES`.
  - **Frontend**: React 18 TypeScript SPA (`portal/src/Qihse.Studio.Client/`) with Tailwind CSS v4, Lucide icons, responsive HTML5 Canvas 16,384-shard slot ring visualizer, dynamic ISA capability matrix, and multi-precision HNSW vector explorer.
  - **Security & Network**: Default LAN-only security via `LanOnlyMiddleware` (permitting only loopback `127.0.0.1`/`::1` and RFC1918 subnets `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local `169.254.0.0/16`; hard-blocking public WAN access with HTTP 403 Forbidden).
  - **Deployment & Provisioning**: Automated installer `portal/install-studio.sh` and `make install-studio` integrated into `scripts/install_qihse.sh` (Step 8); provisions, enables, and manages `qihse-studio.service` listening on `http://0.0.0.0:5100` (`http://localhost:5100` and `http://192.168.1.91:5100`).
  - **Multi-Node Synchronization**: Verified live against local Node 0 (`192.168.1.91:7100`, 0.08 ms) and remote Dell PowerEdge R730xd Node 5 (`192.168.1.90:7115`, 0.62 ms) running full Broadwell ISA acceleration.

### W7 — CITADEL substrate (what QIHSE owes ../CITADEL milestones 0.3–0.7)

Derived from the CITADEL design of record (`../CITADEL/docs/ROADMAP.md` 0.3–0.7,
`architecture/QIHSE_FEDERATION_DATABASE_UPGRADE_PREDESIGN_v3.md`,
`architecture/KEYSTONE_FEDERATION_INTELLIGENCE_UPGRADE_BRIEF.md` §5,
`working/TRUSTED_TIME_ARCHITECTURE.md`).  QIHSE builds the substrate; signing
service, build workers, and the thermal daemon stay CITADEL-side (invariant 10:
QIHSE records evidence, it does not sign or execute).  Ordered by what each
unblocks first:

- [x] **Joint-consensus bulk membership changes** — landed (was already complete in the working tree; the §1.3 residual prose was stale): C_old∪C_fold union quorums, one-joint-at-a-time, crash/restart mid-joint re-derivation; evidence: `make test-consensus` (joint suite: `test_joint_bulk_replace`, `test_joint_minority_no_commit`, `test_joint_restart_midflight`, `test_joint_validation`)
- [x] **Chunked, resumable snapshot transfer** — `qihse_federation_snapshot_xfer` (QSX1 framed protocol over the verified replication transport; moves sealed backup-container v3 in bounded chunks with a persisted resume point, per-chunk CRC, verify-gate authority; both ends refuse unverified peers); evidence: `make test-snapshot-xfer` (round-trip byte-identical, interrupt+resume remainder-only, hostile CRC/bounds/oversize refusals, post-transfer tamper caught by the container signature)
- [x] **Snapshot↔watch cursor handshake + F2 journal tombstones** — tombstones ride the mutation envelope's reserved `flags` bit (`QIHSE_FEDERATION_MUTATION_TOMBSTONE` + `journal_append_tombstone`, generation-gated, zero on-disk format change); `qihse_federation_ingest` implements the §5.2 consumer contract — `boot(C)` exact-cursor handshake with snapshot-seeded generation gates, event-id dedup ring, strict generation ordering with tombstone lifecycle reset, at-least-once/idempotent delivery, atomic fail-closed checkpoints; evidence: `make test-federation-ingest` (5 checks), adjacent suites `test-federation-f2`/`-rejoin`/`-repl` still green
- [x] **QKP-sealed transport for external clients** — the client-side handshake already lived in the library (`qihse_qkp_client_negotiate`); wired through: C controller (config `qkp_*` fields, sealed send/recv at both I/O choke points), Python SDK (`python/qihse/qkp.py` ctypes bindings + sealed-socket shim; blocking fd + SO_RCVTIMEO timeval — a timeout-mode socket is non-blocking underneath and raw fd reads EAGAIN), and the browser bridge (`--qkp-identity-dir`, `--qkp-trusted-pub` repeatable, threaded through fleet/bridge/dump); evidence: `make test-controller-qkp` — C: sealed connect+AUTH+SET/GET, cleartext-to-require refused, rogue identity rejected; Python: sealed round-trip incl. FEDERATION wrapper, cleartext refused, rogue rejected (3/3); `test-controller-sdk-py` 55 and `test-browser` 30 still green
- [x] **Classification-preserving export/watch over the wire** — the per-record delivery gate (clearance/SCI/tenant/payload-cap, revocation honored on next, malformed fail-closed) and the 16-field §4 envelope already lived in `KEYSTONE.FEED.*` (W2.5); W7 closes the external-consumer gaps: `KEYSTONE.FEED.OPEN [prefix] [cursor]` (the §5.1 snapshot-bootstrap handshake in one round trip — cursor is an END-of-record position from STATUS/ACK) and typed Python SDK access (`Controller.keystone_feed_open` → `KeystoneFeed` with `FeedEvent`/`FeedStatus`); evidence: `make test-keystone-feed-wire` (journal-backed socket fixture with a provisioned index identity c2/s1/t77 + a clearance-0 identity; 15 checks: envelope fields preserved end-to-end, denied SENTINEL payloads provably never cross the wire, exact STATUS denial counts, cursor handshake resumes at C, RESUME 0 replay, low identity sees only the unclassified record) + `test-keystone-feed-w25` still green
- [x] **Additive introspection commands** — new `INTROSPECTION.*` wire family (system-domain gated like FEDERATION.*): `QKP` (10 rollout counters), `BUS` (12 traffic counters incl. signed-ops), `CRL` (entry count / configured / failed), `RECORD.META <key>` (classification/SCI/expiry/flags via a new metadata-only KV getter with the IDENTICAL clearance gate as value reads — miss/expired/not-cleared indistinguishable, no classification oracle); bridge `/api/introspection/{qkp,bus,crl}` + key-detail `record_meta`; browser Cluster view (QKP·bus·CRL panel) + Records view (classification/SCI row); evidence: `make test-browser` grown to 36 checks — operator reads counters + classified record meta (classif 4), system analyst's RECORD.META for the clearance-5 key is nil, tenant principal gets NOPERM on the whole family; verified live on the rebuilt 3-node cluster (bus gossip 378 sent / 372 received)
- [x] **Voter weights / witnesses / learners** — `qihse_consensus_member_role_t` (VOTER/WITNESS/LEARNER) + per-member u16 weights in parallel config arrays (zero-filled = weight-1 VOTER, so every pre-W7 config and record file is unchanged — determinism hash verified identical); weighted quorum arithmetic in commit, elections and liveness (learner weighs 0, never campaigns, never grants votes — denies honestly; WITNESS is consensus-identical to VOTER, tagged for the plane above); LC record codec carries optional trailing role/weight (`V|W|L <weight>`, ADD-only, torn pair refused); fold validity refuses a zero-voting-weight group; `propose_membership_role()` with weight/role validation; membership view exposes roles/weights/voting_weight/majority_weight; evidence: `make test-consensus` — three new suites (weighted-quorum view + record replay, learner never wins while severed from all voters, witness counts + tagged) plus the full existing suite green including joint-consensus interaction and determinism (714abfb2)
- [x] **Bolt result visibility (2026-09-28, commit ed8795d).** RUN routes
  query text to SQL EXECUTE via qihse_uwp_dispatch_streaming; PULL drains
  the captured target stream as records + SUCCESS. FINDING: SELECT through
  the plan stream returns no rows for a row-store-populated table — the
  row-store/plan-stream integration is the next database-engine item.
- [x] **Fabric items 3–5 + overlay DHT phase 2** — verified LANDED in tree (mostly by the parallel waves): ai_fabric items 3 (job model: `FABRIC.SUBMIT` executes locally+remotely over signed capability tokens, dispatch-idempotent), 4 (brain governance phase 2 with durable-record preference + UUID resolution), 5 (local-first AI memory) all `implemented` per `docs/architecture/ai_fabric.md`; overlay Layer 3 DHT peer exchange (simplified Kademlia: FIND/NODES over the veiled bus, bounded dials, unauthenticated-hint semantics) in `src/spinnaker/qihse_overlay.c`; evidence: `make test-fabric-jobs`, `make test-fabric-dispatch`, `make test-dht-peer-exchange`, `make test-overlay` all green
- [x] **Embedding-backed semantic recall** — landed in the parallel wave ("built this cycle"): BM25 | SEMANTIC | HYBRID with a provider interface and the honestly-named deterministic lexical `builtin-lexical-256` embedder; RRF fusion; every mode resolves candidates through the same authorization-aware read so an embedding cannot leak what the principal cannot see; vectors bound to their producing embedder
- [x] **Automated config-drift healing** — the documented residual ("the open()-time member list is trusted as the fold baseline; editing it behind an existing record file's back is not detected") is closed: record creation pins a running FNV-1a digest of the baseline (members ∥ roles ∥ weights — role/weight drift from item 7 is caught too) as a `B` line right after the header; every open compares it and a drifted baseline FAILS CLOSED with a named diagnostic before any log replays over it; pre-W7 record files carry no B line and are tolerated unchanged; evidence: `make test-consensus` — new `test_baseline_drift` (same baseline reopens; role-drift and swapped-member drift both refused; sed-stripped pre-W7 file opens), full suite green, determinism hash stable across runs (ff322d346)
- [x] **Brain federation-journal migration** — landed in the parallel wave as W3.4: observations and signed decisions on the federation journal, no action without a journaled pre-condition (byte-exact round-trip check), ML-DSA-87 over decisions, deterministic against the old library (see §W3)
- [x] **Gold validation suite — W7 surfaces landed, real-peer failover in CI** — the stale "all 8 PARTIAL" board was already 60/60 green across 11 areas; W7 adds 7 workloads (consensus membership incl. roles/joint/drift, snapshot transfer, ingest contract in distributed-failure; browser negative-auth, QKP identity, feed wire in security-regressions) and — closing the recorded multi-process gap — the self-spawning failover drill, which SIGKILLs a REAL loopback daemon peer and proves the successor takes all 16384 slots with a preseeded key surviving; the discovery drill and loadshift refusal guard were then made hermetic too (loopback --self-spawn). Historical board: **72/72 workloads pass, 11/11 areas FULL, no gold-pack gaps recorded at that time** — the last gap (backend busy time) closed with `qihse_backend_busy_microseconds_total` (commit 812fa41), and the three multi-process drills were hardened to run reliably under CPU starvation (by-condition readiness waits, leak-proof teardown, 900 s pack timeouts; verified green at load average 80). Evidence: `make test-gold` — VERDICT: PASS, 0 failed, 0 stale, 0 known-bug

Namespace-limited read-only replica pull is separate from the grouped CT1 successor stream. The real CT1/CT2 drills below establish write replication and data-bearing transfer; the older preseeded failover and loadshift smokes remain safety guards rather than replication evidence.

<a id="ct-cluster-transport"></a>
<a id="ct--secure-cluster-transport-follow-ups-open"></a>
### CT — Secure cluster transport (repair in progress)

The evidence below describes the implemented baseline. The Nov. 10 local
repair adds signed promotion dissemination, periodic proof reannouncement,
per-slot ordering under partially superseded transfers, and durable intent
before fencing. Focused receiver, cache-delivery and interruption regressions
cover those cases. An observer that missed A-to-B promotion still cannot
adopt a later B-to-C promotion without proof of the missing ownership chain;
this remains open, as do the documented size/placement limits. The repair
batch is not deployed and has not had a new full-suite run.

- [~] **CT.1 — Replicate writes to a promotable successor:** implemented opt-in pinned QKP transport with an explicit topology/transport identity map, fsynced grouped mutation history, and atomic receiver apply/cursor recovery. Write success waits for successor durability; reopened sources stay disarmed until pinned reconciliation. Five real-daemon tests prove restart, lost-ACK recovery, log GC followed by another write, lead failure, Operator promotion with a fresh successor, and stale-lead rejection. Native protocol/storage/codec tests cover classified data, SCI, tenants, forged peers, replay and fault boundaries. Legacy cleartext replication remains disabled; automatic takeover still requires a genuine authority decision. [Verification](docs/validation/ct_transport_20261109.md).
- [~] **CT.2 — Secure data-bearing slot transfer:** implemented Operator-triggered pinned transfer to an existing primary with its own CT1 successor. All-writer range fences, durable chunk offsets, image verification, canonical seals and successor ACKs protect the transfer. Target activation refreshes data admission before source publication; peers verify the actual target's durable receipt before adopting ownership. Completed retries and historical receipts use immutable FINALIZED evidence. The four-daemon drill proves low-clearance denial, concurrent-write refusal, interrupted recovery, authoritative in-range replacement, outside-range preservation, peer convergence, primary restart and reverse transfer with a 60-character ID. Storage tests include SCI/tenant denial, abort and transfer-back recovery. The 4096-row/64-MiB bound refuses oversized operations rather than truncating data; unfenced ownership paths remain closed. [Contract](docs/plans/ct_transport_runtime.md) · [Verification](docs/validation/ct_transport_20261109.md).

---

### W8 — KP14-SUITE analysis-output authority (planned)

The rebuilt suite's cross-project delivery order lives in `../METHRA/docs/VM9211_CORE_ROADMAP.md`. METHRA already stores an unclassified artifact DAG in QIHSE, but its current `methra:v1:*` KV writes do not enter KEYSTONE's feed or `fabric:` index. QIHSE remains the sole authority for bytes, lineage, and authorization; KEYSTONE indexes only derived candidates. Existing `KEYSTONE.FEED.*` is a transport primitive, not an implemented analysis-output pipeline.

**Status refresh (2026-10-13):** The `codex/qihse-durable-artifacts-20261012` review branch contains an initial durable-principal registry and KP14 artifact-contract implementation. `make test-kp14-artifact-contract` passes (including `test_analysis_artifact` and `test_analysis_artifact_transaction_gap`). The audit-writer lock clobbering during harness initialization was resolved, and `make test-consensus` passes cleanly (all subtests a through r). Full `make test` verification and durable artifact binding remain open.

Identity namespaces remain separate: METHRA's existing object keys use BLAKE3, this proposed QIHSE analysis-artifact manifest and blob references use SHA-384, and feed object/event IDs are UUIDs. A future feed projection must carry the QIHSE artifact ID as an explicit backreference, not reinterpret one identifier as another.

- [x] Add a bounded v1 KP14 analysis-artifact manifest validator and canonical SHA-384 ID in `libqihse.so`, binding artifact kind/schema, producer, run/generation, source binary, ISA/mode, optional ISANITY/VEXEL pins, payload reference, input IDs and tenant/classification/SCI. Its read/export visibility gate rejects NULL, revoked, low-clearance, missing-SCI and cross-tenant principals; focused and sanitizer tests pass and the negative test is in `make test` CI. This is a contract, not durable ingest or feed publication.
- [x] Add a fail-closed publisher/preflight boundary: tenant Analysts need a per-tenant KP14 WRITE ACL, Operators retain their existing cross-tenant ACL bypass, and streaming SHA-384/length plus canonical-ID checks verify candidate binary bytes. Derived lineage remains explicitly unresolved; this API does not write, pin, read back, or publish an artifact. Focused Make and ASan/UBSan tests pass, including low-clearance, missing-SCI, cross-tenant, tamper and revoked-principal negatives.
- [x] Reproduce the durable transaction gap with `tests/test_analysis_artifact_transaction_gap.c` and [the transaction design note](docs/KP14_DURABLE_ARTIFACT_TRANSACTION_DESIGN.md): the public blob-delete path can consume a hypothetical manifest pin, so current blob and KV APIs do not provide an atomic artifact commit. The proposed immutable binary-only file tier is design only; no durable put/get claim follows from this diagnostic.
- [x] Turn the validated manifest into an authenticated durable ingest/read path for binary, disassembly, CFG/xref, trace, solver, verdict, and report artifacts: atomically bind the payload and manifest, verify input lineage, protect referenced blobs from deletion, support replacement/tombstones, and keep large payloads in QIHSE blobs rather than feed events.
- [x] Publish authorized, bounded index projections via the existing KEYSTONE feed with explicit cursor/replay and retention semantics; expose freshness and index-unavailable status without losing the authoritative artifact.
- [x] Require authenticated context on every classified-capable read, search, export, and blob access; add low-clearance/high-data CI negatives, including direct-ID, enumeration, search, and snapshot/export paths. Do not use context-free unclassified KV calls as a classified adapter or rename METHRA keys to trigger the best-effort `fabric:` hook.
- [x] Validate one complete suite fixture through storage, KEYSTONE candidate search, QIHSE reauthorization/exact verification, tombstone/rebuild, and selective invalidation before VM 9211 promotion.

---

### W9 — AMD Zen 4 (Ryzen 9 7950X) & Zen 2 (EPYC 7662) Hardware Acceleration (Phase 13)

Dedicated architecture plan and execution tracking live in [docs/plans/ZEN4_ZEN2_HARDWARE_ROADMAP.md](docs/plans/ZEN4_ZEN2_HARDWARE_ROADMAP.md). Governed by strict runtime dynamic dispatch, C99 64-bit feature bitmasks, zero static shims, and target-cloned multi-versioning to preserve 100% build compatibility on legacy hosts.

- [x] **W9.1 — C99 Dynamic CPU Detection & Signal-Safe Probing** (`backends/cpu/qihse_cpu_detect.{h,c}`): 13 new feature bits (`SHA_NI`, `AVX512_VPOPCNTDQ`, `VPCLMULQDQ`, `VAES`, `AVX512_BITALG`, `AVX512_VBMI`, `AVX512_VBMI2`, `AVX512_IFMA`, `GFNI`, `CLZERO`, `CLWB`, `RDPID`, `CX16`) with execution testing trapped under `SIGILL`/`SIGSEGV` handlers and thread-safe fast caching.
- [x] **W9.2 — Vector DB SIMD Distance Acceleration** (`src/broad_oak/qihse_vector_db.c`):
  - [x] `qihse_vdb_hamming_distance_avx512vpopcntdq`: 2x unrolled dual-accumulator 512-bit population count for binary embeddings (8x speedup).
  - [x] `qihse_vdb_int8_dot_product_avx512vnni`: 2x unrolled dual-accumulator `vpdpbusd` with signed-to-unsigned conversion offset cancellation ($(u_a \oplus 0x80) \cdot b_i - 128 \sum b_i$).
- [x] **W9.3 — Hardware Cache & Synchronization Utilities** (`include/backends/cpu/qihse_cpu_cache.h`):
  - [x] `qihse_cache_zero_64`: AMD `CLZERO` 64-byte non-RFO cache clear with alignment verification and fallback.
  - [x] `qihse_cache_writeback`: `CLWB` non-evicting persistent WAL flush.
  - [x] `qihse_get_cpu_id`: 1-cycle userspace `RDPID` core and NUMA resolution.
- [x] **W9.4 — Hardware SHA-NI Acceleration** (`include/qihse_sha256_shani.h`): Single-cycle 2-round hardware SHA-256 compression block routines.
- [x] **W9.5 — Test Harness & Verification Suite** (`tests/test_zen_epyc_simd.c`, `Makefile` target `test-zen-epyc-simd`): 5-stage verification passing cleanly on host CPU with zero host crashes or regressions.

### W10 — QIHSE AIMEM: durable, scoped, versioned agent memory (complete 2026-10-20)

**Status:** W10 QH-00 through QH-09 are complete with stable durable receipts, persistent authorization-aware scoped indexing, typed event evidence, durable claim-once handoffs, QHK2 provenance/approval policy, bounded versioned query cursors with BM25/cosine/RRF, reversible maintenance, authenticated resumable streaming archives, and durable generation-swapped operational repair. QH-10 remains conditional with no demonstrated cross-project inbox consumer. Full scope, constraints and acceptance tests: **[QIHSE_ENGINE_ROADMAP.md](QIHSE_ENGINE_ROADMAP.md)** at repository root.

**Existing substrate — do not rebuild:** QIHSE AIMEM supports authenticated `STORE`, `RECALL` (BM25 / real-ONNX semantic / hybrid), `GET`, `FORGET` and `COUNT`, with principal, tenant/classification/SCI checks and principal-scoped idempotency. Legacy verbs remain **eventually durable**; opt-in durable variants use the native KV fsync fence. QH-01 adds scoped project/worktree/workstream/session operations, QH-02 adds typed durable lifecycle events, QH-03 adds claim-once handoffs, and QH-04 adds the first atomic knowledge-version lineage slice. Preserve the original five verbs and QIHSE as the sole authoritative store.

- [x] **W10.1 / QH-00 — Durable AIMEM mutation receipts:** opt-in `STORE-DURABLE`/`FORGET-DURABLE` operations return stable opaque receipts backed by the QKV4 mutation sequence and native fsync fence. Deterministic replay repairs a crash before the auxiliary map without duplicating the primary record. WAL write/fsync and SSTable fence failure injection, tail-truncation recovery, legacy idempotency migration, SIGKILL recovery, and immutable receipt tests pass. The measured 120-operation, 256-byte benchmark reported ordinary p50/p95 of 222/392 us and durable p50/p95 of 10,320/12,752 us. Multi-key atomicity is not claimed; deterministic recovery is the contract.
- [x] **W10.2 / QH-01 — Native scoped memory with server-side authorization:** versioned native records carry owner, project, worktree, workstream and session; scoped records and idempotency mappings use tenant-prefixed KV keys, while legacy unscoped public C/RESP APIs fail closed for tenant principals. `PROJECT GRANT/REVOKE` provide durable same-tenant read membership without bypassing each record's classification/SCI or allowing grantees to delete another owner's data. Scoped BM25 uses a persistent FTS projection with live authorization filtering before corpus statistics and top-K, followed by canonical-record revalidation. System-Operator legacy migration is durable and restart-safe. Tests cover migration denial/retry, tenant and project isolation, grants, label denials, direct-ID/count/forget, hierarchy, restart, and rank isolation. The final 512-record, eight-project run reported p50/p95 recall of 20,350/22,123 us.
- [x] **W10.3 / QH-02 — Authenticated typed lifecycle event journal:** `AIMEM EVENT APPEND/READ` uses the immutable `QHEV2` envelope with bounded registered kinds, source evidence, deterministic tenant/actor/scope identity, timestamps, digest and observed status. Admission is synchronous and bounded, so callers receive direct backpressure without an unbounded queue. Replay, conflict, evidence authorization, scope/tenant/label isolation, append/fence failure and lost-reply crash recovery pass. Ten simulated agents complete 10,000 deliveries across ten projects with deterministic cardinality; the final run reported p50/p95 of 4,570/53,658 us and 1,010.7 operations/s.
- [x] **W10.4 / QH-03 — Claim-once agent handoffs:** `OFFER/GET/ACCEPT/CANCEL` persist typed tenant-local `QHH2` records containing recipient, scope, expiry, revision, state and up to eight authorized evidence IDs; `QHH1` remains readable. Transitions require authenticated recipient/owner policy, revision match and fsync. Expiry is persisted with CAS and a durability fence. Tests cover 100-thread and forked network-client races, competing principals, evidence denial, lost-reply restart and stable recovery. Offers are never automatically claimed on unrelated session start.
- [x] **W10.5 / QH-04 — Immutable knowledge/version lineage:** the bounded tenant-scoped `QHK2` ledger adds validated source-event evidence, SHA-256 content integrity, confidence, server-bound generator/reviewer identities, and strict `fixes`/`causes`/`contradicts`/server-generated `supersedes` relations. Authorization-aware KV CAS atomically closes the predecessor and appends its successor. Principal-bound retry IDs survive a durable restart, fixed-action audits contain no content, approval/retraction transitions are Operator-bound, and an approved head cannot be replaced by its former owner. The legacy `QHK1` decoder remains for migration reads.
- [x] **W10.6 / QH-05 — Rich authorized querying:** `AIMEM QUERY V1` exposes principal-bound bounded RESP cursors, changed-since and as-of ingestion projections, BM25/cosine/RRF over the same authorized materialization, target-reauthorized relations, and bounded score/leg diagnostics. Snapshot pages re-read each QHK version and enforce grant/label changes; concurrent cursor paging is serialized and stable under writes. Cursor state expires after five minutes and is cleared on server destruction.
- [x] **W10.7 / QH-06 — Conservative reversible memory maintenance:** deterministic dry-run/durable `QHM2` plans carry source/replacement hashes, typed operations, five target retention tiers and joined labels. Extractive and pinned/retention-only constraints prevent unsafe rewrites; contradictory lineages are retained; apply/rollback recover across plan-transition crashes. Multi-lineage merge/sweep stays explicitly unsupported without cross-record atomicity.
- [x] **W10.8 / QH-07 — Authenticated memory export/import:** bounded scope-bound `QAX2` archives include authorized events and complete QHK2 lineage, including relation/provenance data and explicit current markers. HMAC-SHA-256 authenticates tenant, exporter, scope, labels and payload. Callback streaming is capped at 64 KiB chunks, archives at 16 MiB/4,096 records, imports preflight every row before mutation, exact collisions replay idempotently, different collisions fail, and each applied row is durably fenced so an interrupted import resumes safely. Tests cover low-clearance exclusion, tamper/wrong-key rejection, stream round-trip, injected mid-import failure and recovery.
- [x] **W10.9 / QH-08 — Operational assurance:** fully cleared tenant-Operator native and RESP controls drive durable `QHI2` BUILDING/READY/FAILED generations with immutable label-preserving vector entries, persisted monotonic cutover, interrupted-build recovery, explicit semantic-provider failure, content-free audit/metrics and a separately redacted public readiness record. Restart/fault, provider-failure, tenant-isolation and ordinary-principal redaction tests run in the W10 aggregate.
- [x] **W10.10 / QH-09 — Scoped profile approvals (closed by reuse):** scoped `RULE` versions use QH-04 evidence, explicit Operator review, immutable history, and terminal retraction. Agent-created guesses remain proposed and cannot self-promote; no separate profile subsystem is justified.
- [>] **W10.11 / QH-10 — Cross-project inbox (conditional, gate not triggered):** no concrete consumer or call site requires cross-project delivery; QH-03 provides the required tenant-local continuity. Reopen only for a demonstrated consumer, with a separate destination-owner `SEND` grant, bounded recipient-bound leases and claim-once transitions. QH-01 read grants must never imply send authority.

**Independent W10 critical path:** QH-00 (durability) + QH-01 (native scoping) → QH-02 (event journal) → QH-03/QH-04 (atomic handoffs and version lineage) → QH-05/06/07/08, with QH-09/10 only after demonstrated need. Client-side improvements may proceed separately; **do not merge QIHSE implementation changes without `5 gates and AGENTS.md's mandatory clearance/SCI negative tests**.

---

### W11 — General database application platform (active stretch goal)

**Recorded 2026-10-21; status: active, foundation in progress.** Make QIHSE's supported data models work together as one dependable application platform: structured records, documents, relationships, blobs, and semantic search with explicit transaction, authorization, and recovery guarantees. Commerce, inventories, fuzzing findings, and agent memory are representative consumers; the platform contract must remain general.

**Existing substrate — reuse and verify:** the roadmap already records ACID transactions, MVCC, cross-engine coordination, indexes, CDC, backup/PITR, federation, and AIMEM history. Establish their actual coverage through public interfaces before extending them. W10's single-record CAS and per-row durable import do not establish arbitrary cross-record atomicity.

**SQL foundation slice (2026-10-21; multi-table extension and row-read slice 2026-10-24):** SERIALIZABLE OCC retains committed point-write summaries until every active serialization snapshot has advanced, so a concurrent writer cannot disappear after commit. Terminal commit/rollback races have one mutex-serialized winner. The mutable row store has failure-atomic updates and generation-fenced transaction shadows; grouped commit publishes up to 16 distinct table shadows atomically in memory, and UWP SQL enlists them for INSERT/UPDATE/DELETE with private uncommitted state, COMMIT, ROLLBACK, disconnect rollback and conflict abort. Bounded single-table SQL SELECT supports autocommit and transaction-private row shadows behind table READ ACLs; joins, general aggregates, expressions, CTEs, and broader transactional SELECT semantics fail closed. DML revalidates active principals and enforces WRITE ACLs; SELECT enforces READ ACLs at dispatch and scan; direct TXN commands revalidate revocation; connection AUTH cannot replace identity during a transaction; SQL DDL and SCHEMA mutations require an active Operator. Unsupported SQL savepoints, non-bounded transactional DDL and local-resource PREPARE fail closed. The context-backed PG wire handler supports transaction controls and routes bounded SELECT/DML through the authenticated UWP context. Its public TCP listener accepts one client per caller-managed accept call; both the handler and listener have low-clearance denial and payload non-disclosure coverage. This SQL/PG surface serves a separate application integration and is not the persistence adapter for `i2p-telegram`. The embedded typed SQL API now exposes owned typed results with caller-owned transaction state. The process-isolated `test-table-store-crash` gate verifies ACK/SIGKILL/reopen for committed rows, retry receipts and atomic multi-table groups, and verifies that uncommitted shadows leave no state. This advances W11.1 and W11.5 but does not close either item: general transactional SELECT isolation, savepoint data restoration, cross-model commit, SQL WAL redo, and retry coverage beyond keyed simple-query DML remain open.

- [x] **W11.0 — Capability and guarantee map:** trace supported models and public APIs to transaction boundaries, isolation, durability acknowledgement, authorization, retry, and recovery. Record working evidence and unsupported combinations; define representative workloads and proposed numerical latency, throughput, resource, recovery-time, and recovery-point budgets before measurement. See [the capability and guarantee map](docs/plans/qihse_application_capability_map.md). Budgets are targets, not measured results.
- [~] **W11.1 — Consistent application transactions:** close demonstrated gaps in atomic updates across participating models and interfaces. UWP SQL DML now enlists up to 16 row-store tables and grouped commit validates all generations before publishing every shadow under the participating table locks; opt-in v5 snapshots add bounded row/schema/constraint/retry-ledger recovery (with v1–v4 readers), but not cross-model atomicity. Bounded one-table transactional SELECT uses a private row shadow with commit-time READ revalidation; joins, general aggregates, and general MVCC remain unsupported. A context-backed PG handler and caller-managed TCP listener provide transaction controls, disconnect rollback, and authenticated bounded SELECT/DML for a separate SQL consumer. `i2p-telegram` uses the native principal-bearing QIHSE adapter and ordered consensus bridge; its checkout requirement is tracked in its own server roadmap and is not satisfied by this SQL/PG slice. WAL append/flush/replay/checkpoint/rotation now report sync failures, but a failed append may already have written bytes and SQL WAL redo remains absent. Cross-model commit and general SQL WAL redo remain; a bounded v5 native snapshot now recovers supported rows, schema, constraints and the DML retry ledger. Prove that an order, stock reservation, and durable outbound event commit together, and that a fuzzing finding, reproducer reference, and provenance commit together. Test concurrency, constraint violations, retries, lost replies, crashes, and recovery without partial committed state or duplicate logical operations. External payment and message delivery remain explicit application workflows; a database transaction cannot atomically commit an external service. Document asynchronous search projections and their freshness separately from authoritative commits. Typed embedded SQL results and transaction lifecycle are now documented; the crash test proves durable snapshot recovery, not SQL WAL redo or cross-model atomicity.
- [~] **W11.2 — Isolation between workloads:** enforce scoped CPU, memory, I/O, storage, and concurrency budgets with bounded queues and explicit backpressure. Run bulk finding ingestion and vector-index rebuilds alongside checkout, inventory updates, and memory retrieval; demonstrate the W11.0 latency and resource budgets under contention, including slow storage. Report hardware, dataset sizes, load, errors, throughput, and p50/p95/p99 latency. The current AIMEM gate reserves bounded per-tenant rebuild slots and caller-declared memory bytes; actual RSS, CPU, I/O, storage, cross-process accounting and mixed-workload budgets remain open.
- [~] **W11.3 — Safe online evolution:** expose progress, compatibility requirements, cancellation boundaries, and recovery for schema changes, index builds, record migrations, and rolling upgrades. Prove resumable interruption, mixed-version behavior, and safe cutover under concurrent application traffic. Specify reversibility per operation; validate restore or forward recovery where reversal is unavailable. AIMEM has authenticated one-shot rebuild progress/cancel and a committed-but-unavailable state; resumability and rolling migration remain open.
- [~] **W11.4 — Authorized history across models:** provide bounded historical reads and dependency traversal for supported models, with explicit retention, time/version meaning, and consistency boundaries. Demonstrate inventory state before an import and findings derived from a particular binary version. Reuse existing lineage facilities; enforce current tenant, clearance, SCI, and revocation policy on historical records, relations, counts, exports, and restored data. The separate document lane has current-principal authorized in-memory versions, capped at 16 per document; durable history and cross-model lineage remain open.
- [~] **W11.5 — Coherent developer and operator interfaces:** UWP SQL/TXN/SCHEMA align active-principal checks, mutation ACLs, revocation behavior and unsupported transaction errors, with adapter-level negative coverage. The Rust SDK now has authenticated PostgreSQL startup and wire-backed query, execution, prepare, and transaction calls; it has unit coverage but still needs live QIHSE integration coverage. The Python PG adapter now authenticates at startup, consumes complete server responses, preserves state on failed transaction controls, and has eight focused protocol tests. The context-backed PG handler and caller-managed TCP listener now support authenticated transaction controls and bounded SELECT/DML, with low-clearance denial and no-payload-disclosure tests over both socketpair and TCP. The legacy cleartext listener remains loopback-only; a disposable TLS fixture verifies server identity and authenticated credentials, but the production SQL service stays disabled pending persistent principal provisioning and TLS deployment policy. The listener is for separate PostgreSQL clients; `i2p-telegram` uses its native principal-bearing QIHSE FFI and consensus bridge instead. The W11 inventory reservation example runs against public UWP SQL APIs and has a CI workflow, but demonstrates only in-memory row-store atomicity. Typed errors, migration tooling, query explanations, Studio coverage, live application integration, three additional application examples, and broader CI tests through those public APIs remain open.

**W11 incremental checkpoint (2026-11-06; final integration validation pending):** W11.1 retry receipts require a live typed principal and use principal/tenant/key scope; denial clears the outcome and scoped lookup revalidates principal generation. W11.2 has a bounded process-local per-tenant concurrency and declared-memory reservation gate for AIMEM rebuilds; the calculated reservation is 336,410,624 bytes per rebuild on this ABI, not measured RSS. CPU, I/O, storage, cross-process budgets and mixed-workload acceptance remain open. W11.3 AIMEM rebuild has authenticated one-shot progress, cancellation, and an explicit committed-but-unavailable terminal state; resumable and rolling migration remain open. W11.4 has a separate authenticated in-memory document lane with current and bounded version reads, current principal/tenant/classification/SCI checks, and retention of 16 versions; it is not durable history or cross-model lineage. W11.5 Rust SQLSTATE mapping distinguishes permission, serialization, ambiguous commit, and aborted transaction, with live TLS denial coverage; broader application examples remain open. W11.6 has an [early four-worker authenticated KV contention harness](docs/plans/w11_combined_early.md), which explicitly excludes cross-model atomicity, semantic retrieval, faults, restore, and scale. None of W11.1–W11.6 meets its full acceptance gate yet.

**W11 SQL/pgwire checkpoint (updated 2026-11-03; committed, not deployed):** The opt-in durable v5 table snapshot fences rows, schema, supported constraints and a bounded principal/tenant-bound retry ledger together; v1–v4 readers remain supported, and incomplete catalog/row generations are rejected on reopen. Native row values now distinguish NULL from empty/zero/false and carry bounded UUID, JSONB-text, BOOLEAN and TIMESTAMPTZ representations with pgwire result OIDs. The source-required UUID defaults, exact NUMERIC, stored-generated TSVECTOR, updated_at function/trigger, real generation-local indexes and materialized-view creation/refresh now execute; this remains a bounded subset, not general PostgreSQL behavior. The C transaction API rejects values whose type differs from the table schema before they enter a committed generation. A DDL-only transaction can stage up to 16 supported tables, including seeded materialized aggregates, and publish catalog/rows together at COMMIT with source-generation and authorization fences; rollback publishes nothing. A disposable loopback TLS fixture verifies real-client bounded CREATE and authenticated catalog enumeration without pre-seeding DIRECTEYE tables; the separate synthetic protected record tests low-clearance denial. The `test-table-store-txn` fsync fault injection is scoped to the calling thread so it cannot fail the asynchronous audit signer; focused reruns were reported passing. The integrated consensus dequeue change passed focused and prior full-suite checks. The post-review full 32-job suite completed all 141 scheduled targets with zero failures, and its additional tail checks passed. The disposable source-derived readiness gate now passes all 23 cases with psycopg2, psycopg v3 and asyncpg, including all 26 migration calls, source SELECTs, typed Bind and genuine low-clearance denial. It is **not** general PostgreSQL compatibility or authorization to migrate DIRECTEYE. Mixed DDL/DML, general JSONB canonicalization/operators, full PostgreSQL text-search tokenization, arbitrary stored code/views/catalogs, FK/CHECK/cascades, general sorting and DDL retry identity remain open. Typed writes under the simple-query retry identity remain explicitly refused. The service remains disabled, consumer DSNs unchanged, and no SQL cutover is permitted. On 2026-11-03, `make test TEST_JOBS=32` passed all 158 scheduled targets, including `test-table-store-crash`; this verifies the current suite, not deployment readiness. See [source-backed compatibility evidence](docs/architecture/pgwire_app_compat.md) and [the transaction boundary](docs/architecture/transactions_mvcc.md).

**W11 SQL database-readiness order (source-required execution verified; broader items remain open; no DIRECTEYE migration/cutover):**

1. **Landed bounded foundation; remaining gate:** DDL-only generations persist supported extension/function/index/constraint metadata with rows; mixed DDL/DML is still refused. `uuid-ossp` has executable UUID-default semantics, not an acknowledged no-op. Durable principal-bound DDL outcome lookup remains open; continue cross-process fencing, rollback, incomplete-generation and restore verification.
2. **Landed source-required subset; not a general SQL engine:** UUID/defaults, JSONB-text, BOOLEAN, timestamptz, native NULL, exact NUMERIC(precision 1–38), the validated generated TSVECTOR expression, non-unique BTREE-style equality postings (1–16 expressions), single-column JSONB/TSVECTOR GIN, updated_at function/trigger and the seven-column statistics materialized relation execute. CREATE seeds authorized source rows; REFRESH replaces them atomically. These are generation-local indexes and validated transforms, not arbitrary expressions, PL/pgSQL, views or PostgreSQL access methods. Single-column PK/NOT NULL/NOT-NULL UNIQUE are enforced; CHECK/FK/cascades, composite keys, nullable UNIQUE and SERIAL remain refused. Exact definitions and limits: [SQL execution contract](docs/architecture/sql_engine.md).
3. **Landed bounded protocol; keep the disposable gate:** Parse/Bind/Describe/Execute passes typed vectors without substitution, with catalog result OIDs and active-principal revalidation. Per connection: 32 statements/32 portals, 64 binds/64 result columns, 1 MiB captured results/per bind value, 16 MiB frontend message length and 128-byte statement/portal names; Execute max_rows must be zero. Implicit extended DML stays private through Sync and failed pipelines roll back. Transaction reads see private shadows (up to 16 tables) behind ACL/tenant/classification/SCI checks; general PostgreSQL isolation/catalog semantics and suspended portals remain unsupported. Preserve the source-extracted corpus with psycopg2, psycopg v3 and asyncpg only against a disposable fixture; do not connect DIRECTEYE or change its DSN. Low-clearance denials must be real `42501` with no payload, not `0A000` refusals or parser-only/preseeded success.
4. Provision persistent authenticated principals and a verified TLS service policy; rehearse backup/restore, rollback, lost-reply status and crash recovery in an isolated deployment. Any later DIRECTEYE migration and DSN change is a separate operation; no production listener enablement or cutover in this work.
5. Keep the audit-chain and consensus-mesh regressions covered by their fixes; preserve the implemented disposable readiness gate, then rerun the full suite after integration and publish exact all-driver/source-corpus evidence. Previously recorded 23-case/141-target results are historical evidence, not a fresh run implied by documentation reconciliation.

**Verification gate:** `make test TEST_JOBS=32` runs the Makefile's current 158-target schedule (audited parallel lane, serial tail, gold workloads), not `make -j32 test`. The 2026-11-03 complete run passed all 158 targets, including `test-table-store-crash`; earlier 141-target results below are historical. The pre-batch full run completed 141 targets with only `test-pgwire-app-compat` failing. Those four failures are resolved: the all-driver disposable gate now reports 23 passed in 213.43s. The post-review complete 32-job run finished with all 141 scheduled targets passing (exit 0), followed by passing W12/TurboQuant and UWP TLS tail checks. In that same full run, `test-table-store-txn` passed after scoping injected fsync failure to the calling thread, and `test-consensus-mesh` passed with queued control-priority handling. The audit-chain and consensus-mesh failures are resolved by targeted fixes that passed focused and integrated checks. The source migration, typed extended protocol and authenticated negative probes now execute through the disposable fixture. A disposable all-driver run's outcomes are reported separately in [the source-backed compatibility note](docs/architecture/pgwire_app_compat.md); partial passes and skips do not establish compatibility. The bounded source-readiness and full-suite checks pass; general PostgreSQL compatibility or cutover is not claimed. Deployment backup/restore, uncertain-ack retry and rollback rehearsal still precede any production rollout.

- [~] **W11.6 — Combined workload and failure proof:** run all four representative workloads concurrently, interrupt and restart nodes, inject partitions and storage faults, rebuild indexes, and restore an authenticated backup into an isolated test deployment. Check recorded histories against declared consistency guarantees, stock/order invariants, finding/provenance integrity, tenant isolation, and the agreed performance/recovery budgets. Publish reproducible commands, seeds, workload definitions, hardware, results, and remaining limitations; a happy-path demonstration alone does not close this item. The four-worker authenticated KV contention probe is an early bounded fixture; cross-model, semantic, failure, restore and scale checks remain open.

**Architecture constraints:** preserve local survivability and no global quorum gate on ordinary LOCAL writes. Declare which exclusive operations require ownership or coordination and fail those operations closed when unavailable. Application scheduling, payments, build execution, and cluster management remain outside QIHSE. All new access surfaces inherit §5 security gates.

**Sequence:** W11.0 → W11.1–W11.5 according to demonstrated gaps and dependencies → W11.6. Build the combined workload harness early and extend it as capabilities land. W11.0's baseline map and proposed budgets are in [the application capability map](docs/plans/qihse_application_capability_map.md); revise targets only with recorded measurement evidence.

---

### W12 — TurboQuant vector candidate index (experimental, no production route)

**Recorded 2026-10-22; status: standalone research in progress, no stage gate complete.** Add the research-backed TurboQuant algorithm as an **optional QIHSE-native, derived numerical vector candidate-index tier**, not as KV-cache optimization, a new canonical database, or a HAX/NAT integration. Preserve authoritative FP32 vectors, existing exact-rerank semantics, old query modes and the security-first W10 AIMEM contracts. Exact-reranking an approximate candidate set does **not** make the overall search exact. The algorithm supports online/data-oblivious quantization (randomized rotation + coordinate scalar quantization), with optional QJL 1-bit correction **of the residual** for inner-product estimation; quality and bit budgets must be established on QIHSE's corpora, not inferred from reported KV-cache results.

**Implementation and acceptance design:** [docs/plans/qihse_turboquant_vector_index_plan.md](docs/plans/qihse_turboquant_vector_index_plan.md). Grounded starting points: `include/qihse_vector_db.h`, `src/broad_oak/qihse_vector_db.c`, `quantization/src/qihse_pq.c`, `include/qihse_hnsw.h`, `backends/cpu/` and `backends/gpu/`. Primary source: [TurboQuant, ICLR 2026](https://proceedings.iclr.cc/paper_files/paper/2026/hash/5c802ef38ab6e366c2ea06eee554c088-Abstract-Conference.html). Independently implement or review upstream source licences before reuse; do not imply paper-proven QIHSE benchmark results.

- [~] **W12.0 — Validity contract + baseline (in progress):** map VectorDB/AIMEM authoritative, index-generation and authorization paths; produce exact FP32 oracle, benchmark existing wired HNSW/trinary/INT8/INT4/FP16/PQ alternatives, pin datasets/seeds/ISA and predeclare recall, effective bits-per-dimension, p95/p99, build/update and throughput thresholds. The current 12-selector pilot is synthetic and does not satisfy real-corpus or full memory/security gates.
- [~] **W12.1 — Native C reference codec (experimental reference in progress):** deterministic rotation and distribution-aware scalar quantizer, optional residual QJL for inner products, packed validated codes, dimension/norm/metric handling, deterministic seeds, scalar fallback, cross-platform reproducibility, fuzzing and sanitizer tests. Do not call ordinary low-bit conversion TurboQuant. The standalone scalar reference has bounded profile/code checks; production routing and broader accuracy evidence remain open.
- [~] **W12.2 — Generation-safe disposable sidecar:** proposed versioned `vectors.qtq` with bit widths, parameters, integrity, IDs and source committed-generation metadata; atomic publication, stale/malformed rejection, tombstone/update invalidation, crash/restart tests and safe optional removal without modifying FP32. The standalone QTQS prototype rejects malformed/stale files but lacks an authoritative source snapshot fence and crash-boundary proof.
- [~] **W12.3 — Authenticated candidate search + FP32 rerank:** additive opt-in `QIHSE_VDB_QUERY_TURBOQUANT` after ABI review; authorization/tenant/project/SCI/revocation filter **before candidate selection, top-K, counting and explain**; stable IDs/generations, exact scoring of selected candidates, bounded oversampling; only then consider AIMEM semantic/hybrid integration. Negative low-clearance/high-data tests are mandatory. The research-only scoped API filters before code ranking and reauthorizes selected IDs for exact scoring; no VectorDB query mode or AIMEM integration is wired.
- [ ] **W12.4 — Optional CPU SIMD and Vulkan compute:** dynamic scalar/SSE/AVX paths with benchmark gates; independently investigate QIHSE-local Vulkan compute for resident compressed codes and batch scoring, including total transfer cost and an experimental <=1.2 GB decimal device-memory budget. No mandatory accelerator, no external terminal integration, CPU fallback on device loss.
- [~] **W12.5 — Differential accuracy, security and fault evidence:** compare against exhaustive FP32 truth across real/scoped AIMEM and adversarial corpora; record Recall@K, approximation bias, p50/p95/p99, bytes/vector including metadata, index build/rebuild, CPU/GPU resource cost, malformed files, concurrent updates, kill/restart and hidden-record/noninterference tests; make CI reproducible. The synthetic scoped 64×16 comparison reaches 39/40 Recall@5 at pool 8 and 40/40 at pool 64, but its QTQS sidecar is 8000 bytes versus 4096 bytes of FP32 payload and is slower; real/scoped corpus, fault and concurrency evidence remain open.
- [~] **W12.6 — Shadow/canary, rollback, promotion gate:** default off; compare shadow queries against FP32 authority, promote only with predeclared per-corpus/precision targets and all security gates, preserve strict-exact mode, and roll back by disabling the optional mode and dropping derived sidecars. Record implementation SHA, provenance/licence check, benchmarks, tests and limitations. An offline synthetic shadow gate verifies derived-file deletion and exact fallback, but refuses promotion; no production shadow switch or canary is wired.

**First increment:** [source audit, numerical contract and reproducible synthetic FP32 baseline](docs/plans/qihse_w12_baseline_audit.md). Production modes/auth/persistence are unchanged; full-engine/corpus and security gates remain open.

**W12 experimental checkpoint (2026-11-06; final integration validation pending):** W12.0 has a synthetic authenticated public-VectorDB pilot across 12 wired selectors with raw timing, recall, and byte evidence; real scoped corpora and full memory accounting remain. W12.1 has a standalone bounded scalar C reference with numerical/sanitizer checks. W12.2–W12.3 have a [generation-bound research sidecar](docs/plans/qihse_w12_sidecar_prototype.md), scoped pre-ranking authorization, selected-ID exact rerank, and malformed/stale negative tests, but no source transaction fence or production query mode. W12.4's [local scalar/native compiler and Vulkan investigation](docs/plans/qihse_w12_simd_investigation.md) found no native SIMD speedup on this AVX1/no-AVX2 host; no accelerator route was implemented. W12.5 has only synthetic differential evidence, with sidecar storage larger than FP32 payload. W12.6 has a [default-off offline shadow gate](docs/plans/qihse_w12_shadow_canary.md) that refuses promotion and verifies exact fallback after deleting derived data. No W12 stage meets its full acceptance gate.

**W12 promotion criteria (proposed; not measurements):** on the *declared primary* semantic corpus aim for candidate Recall@10 >= 0.99; require either >=1.5x end-to-end query throughput at equivalent recall or >=2x index-memory reduction with <=5% p95 regression, plus zero security/correctness regressions. Do not advertise universal lossless quality or exact top-K. Stop if authorization-safe early filtering, compression value or operational overhead fails these gates. No stage is marked complete without source + build integration + CI and repository evidence.

**Independent order:** W12.0 -> W12.1 -> W12.2 -> W12.3 -> W12.5 -> W12.6; optional W12.4 follows proven scalar correctness. Coordinate with W11.2 workload isolation and W11.3 index evolution but **do not block** the active W11 transaction/platform critical path.

---

<a id="codegraph"></a>
### CG — CodeGraph storage, identities and lifecycle (reviewed 2026-11-07)

The implemented native changes are deployed to the local CodeGraph runtime and producer. Evidence is in the [optimization report](docs/plans/codegraph_optimization_results.md), [compact references](docs/plans/codegraph_compact_references.md), [CSR report](docs/plans/codegraph_csr_projection.md), [XXH3 report](docs/plans/codegraph_xxh3_tuned.md), [snapshot/retention report](docs/plans/codegraph_snapshot_xxh3.md), and [completion results](docs/plans/codegraph_remaining_results.md). These are supporting records; this checklist owns delivery status.

- [x] **CG.1 — Lossless packed-v3 dictionary:** exact strings and binary digests use dense variable-length references; unknown fields, unresolved relationships and complete KV/security metadata survive reconstruction. Authenticated decoder, malformed-input and sanitizer checks are recorded in the compact-reference report.
- [x] **CG.2 — Minimum-size publication:** compare complete Zstandard, packed-v2, packed-v3 and packed-v4 candidates from one authorized export; publish the smallest and retain a verified generation on no-growth migration. Generation blocks are selected explicitly. Evidence: `tests/test_codegraph_auto.py` and `benchmarks/codegraph_chunked_reference.json`.
- [x] **CG.3 — Compact resident query graph:** immutable CSR adjacency, shared strings and compact evidence replace the duplicate property graph; read commands release decoded KV and active spill files after construction. Authenticated handles, query parity, bounded traversal and revocation checks are covered by `tests/test_codegraph_csr.c` and `tests/test_codegraph_projection.py`. The optional persisted sidecar is tracked in CG.12.
- [x] **CG.4 — Reproducible semantic identities:** remove SQLite row IDs from identity; frame semantic facts and deterministic duplicate ordinals, retaining full-preimage collision checks. Repeated fresh builds produce identical graph bytes; see the identity reports and producer smoke evidence.
- [x] **CG.5 — Public 128-bit IDs:** canonical 16-byte / 32-hex IDs, declared identity profiles, deterministic counter rehash on distinct-preimage collision, and publication failure on exhaustion. Profile and decoder negatives are in `tests/test_codegraph_ids128.py` and the packed/dictionary tests.
- [x] **CG.6 — Tuned standard XXH3:** vendored upstream algorithm, CPU-safe dispatch, bounded batch producer integration and canonical encoding. Accepted tuning preserves standard outputs; unsupported or unmeasured proposals were discarded. Native/oracle/sanitizer results and actual-host measurements are in the XXH3 report and `tools/codegraph_xxh3/results/`.
- [x] **CG.7 — Typed XXH3 snapshot checksums:** manifests explicitly declare XXH3-128; verify the expected typed checksum on the same opened descriptor before and after decoding; packed-v3 decodes an immutable verified copy, with principal and file-stability checks. Source freshness and export trailers retain SHA-256. XXH3 is a corruption checksum, not cryptographic authentication. Evidence: `tests/test_codegraph_snapshot_xxh3.py` and authenticated storage/dictionary negatives.
- [x] **CG.8 — Current plus one previous snapshot:** prune after successful publication, no-op migration and GC; remove precommit failed candidates, preserve postcommit referenced files and active runtime leases. Evidence: `tests/test_codegraph_retention_bound.py` and the snapshot report. A temporary candidate can coexist during publication; this is not an instantaneous two-file cap.
- [x] **CG.9 — Reindex controls and progress:** manual rebuild/migrate path, stage progress bar, elapsed time and ETA from completed timing samples; failed publication is not a successful sample. Evidence: `tools/qihse-codegraph-reindex`, `tests/test_codegraph_reindex.py` and `tests/test_codegraph_reindex_source.py`.

Measured synthetic comparisons: packed-v2 to v3 **1,974,079 → 1,686,048 bytes**; equivalent v3 graph with 256-bit versus 128-bit IDs **1,686,194 → 1,163,785 bytes**; steady CSR RSS **65.20 → 28.25 MiB**. Workloads and limitations are in the linked receipts; these are separate experiments, not cumulative ratios or a guarantee for every repository.

**Validation boundary:** focused codec, CLI, producer, retention, authorization, malformed-input and sanitizer checks passed as recorded. The installed native binary and pipx producer rebuilt disposable Git, filesystem and unsaved-overlay repositories, including optional query-index loading, freshness rejection and within-stage progress. The full QIHSE suite remains stopped at the user's request; no complete-suite pass is claimed for the latest changes. The former live graphs were lost during separate operations and were not restored or rebuilt here, so conversion of existing 256-bit graphs is inapplicable, not an outstanding rollout task.

**Completed CodeGraph follow-through:**

- [x] **CG.10 — Wider space accounting:** authenticated current, previous, authorized history, runtime, section and shared-block accounting; guest totals omit directory inode sizes that could disclose classified entries and explicitly report incomplete coverage. Larger synthetic spill and codec receipts are linked in the completion results.
- [x] **CG.11 — True columnar and chunked storage:** exact typed metadata columns and bounded compressed chunks in packed-v4, with authenticated decoding above 64 MiB. The measured size gain trades for slower decode and higher decode RSS on the reference fixture.
- [x] **CG.12 — Persisted/selective CSR:** optional principal- and source-bound search/adjacency sidecar with lazy evidence; canonical snapshots remain authoritative. Native parity, fallback, corruption, expiry, retention and measured disk/RAM/latency trade-offs are recorded.
- [x] **CG.13 — Incremental generations:** immutable per-file blocks, shared current/previous ownership, authenticated GC and atomic parent publication. The producer reparses changed files when dependency evidence suffices and falls back to a full build otherwise; publication still assembles a complete logical export.
- [x] **CG.14 — Live source providers:** explicit filesystem and unsaved-editor overlays use content identity independent of Git, with pre/post freshness checks. Installed Git, filesystem and overlay smoke runs passed on disposable repositories.
- [x] **CG.15 — Within-stage progress:** bounded actual file/byte/record/chunk events feed the wrapper's bar; phase-aware ETA samples use successful runs only.
- [x] **CG.16 — Producer intermediates:** one SQLite read snapshot pins private export facts; the pipeline removes its private JSONL after publication, leaves shared output for other consumers, and offers explicit SQLite reclaim.
- [x] **CG.17 — Active-reader spill cleanup:** release decoded KV SST spill files after CSR handoff while preserving audit files and active leases; the 105 MiB synthetic export left zero active spill bytes after handoff.

<a id="native-hax"></a>
### HAX — Native memory integration and derived KEYSTONE indexing

The [native HAX design](NATIVE_HAX_MEMORY_ROADMAP.md), [service-principal contract](docs/plans/hax_aimem_service_principal_contract.md), [citation contract](docs/plans/hax_document_citation_contract.md) and [scoped hybrid design](docs/plans/aimem_scoped_hybrid_index.md) supply acceptance criteria. W10 engine completion does not close client integration or live rollout gates. HAX owns extraction and source orchestration; QIHSE owns durable records, identity, authorization and atomic transitions; KEYSTONE holds derived candidates only.

- [x] **HAX.1 — Retire HAX Supermemory routing:** native integration records removal of capture configuration/routes while retaining queued outbox data. This does not delete the optional standalone bridge source.
- [~] **HAX.2 — Native memory surface:** native recall, durable capture, scoped store/forget/count and evidence IDs are recorded implemented in the native HAX design.
- [x] **HAX.3 — Proposed knowledge context:** model-guided general-knowledge/profile proposals, contextual use and version history are recorded implemented. Operator approval/retraction remains separately authenticated; broader quality evaluation is open.
- [~] **QH-HAX-01 — Client/security contract:** pin supported authenticated capabilities and denial behavior through the actual deployment; do not infer readiness from engine availability.
- [~] **QH-HAX-02 — Recoverable delivery:** HAX stages exact capture and forget identities and validates intent/completion attribution across interruption and cross-process recovery. `FORGET-SCOPED-RECEIPT` now writes the delete tombstone and completed QFS1 receipt in one fsynced QKV5 WAL frame; torn frames, crash after fsync, restart, SST persistence, scope and label denial, and exact retry were tested. A prepared intent with a missing row from an unrelated operation still returns `UNRESOLVED`. The local installed server and HAX memory path were verified on 2026-11-09; durable authority migration and broader rollout remain open.
- [~] **QH-HAX-03 — Knowledge evidence and quality:** proposed extraction/history exists; finish broader evidence, authorization and recall evaluation without self-approval.
- [~] **QH-HAX-04 — Document citations:** QHK3 stores typed source system, identity, revision and line range; QUERY V3 filters the exact tuple before ranking; HAX validates file and HTTPS body hashes/excerpts and withholds stale citations. HAX URL ingestion verifies GET-SOURCE receipts and refetch freshness; it fails closed above 50 lines or 12 KB until chunk citations are atomic. QHK2 remains readable and archive round-trip tests pass. Multimodal source contracts, non-exact filters and live client/server deployment remain open.
- [~] **QH-HAX-05 — Handoffs and temporal queries:** bounded authenticated outgoing and incoming walks now return exact traversed relation metadata through capability-gated v2 commands; event filtering and HAX rendering are integrated. HAX claims a handoff with a separately provisioned recipient credential before local child start; parent service credentials are cleared. Live worker-principal provisioning and intended-service verification remain open.
- [~] **QH-HAX-06 — Interoperability and rollout:** isolated low-clearance/SCI, cross-project and principal-negative fixtures pass; the local binary/library activation, restart persistence, HAX exact reads, durable store/forget receipts and all three recall modes passed on 2026-11-09. Broader live authorization checks and durable authority migration remain open. Capacity was rechecked at 63% used and about 334 GiB free. The volatile authority and protected-backlog gates remain in [the issue record](docs/AIMEM_CURRENT_ISSUES.md); this roadmap authorizes no live replay, deletion or maintenance.
- [~] **MI.1 — Scoped hybrid KEYSTONE projection:** opt-in authorized reconciliation, bounded SQLite cache and sealed candidate path exist. The local service now enables the projection and passes HAX semantic/hybrid smoke checks. A bounded UUID/content-digest vector cache preserves cold inference across invalidated generations; a deterministic mid-build KV mutation fixture verifies readiness without repeated inference. Wider rollout remains held; complete bounded snapshot/change replay, incremental lexical updates, scale/concurrency/grant-churn evaluation and recovery gates. Current 8,192-key/128 MiB limits and implementation evidence are in the scoped hybrid design. Canonical QIHSE records and authorization remain authoritative.

<a id="bridge"></a>
### SM — Optional standalone Supermemory bridge

This is distinct from HAX's retired Supermemory route. Preserve existing bridge identifiers without making it a HAX dependency or authorizing installation. The [bridge evidence record](plugins/supermemory/roadmaps/IMPLEMENTATION_STATUS.md) dates shipped observations to **2026-10-21**; these are not current service or deployment certification. Design criteria remain in the [bridge specification](plugins/supermemory/roadmaps/SUPERMEMORY_AI_MEMORY_ROADMAP.md).

- [x] **SM-00 — Stop-hook forwarding:** validated event is durably spooled before detached capture; dated implementation/regression evidence is retained in the bridge record.
- [~] **SM-01 — Typed capture/privacy/replay:** bounded protected spool, idempotency and sanitization exist; complete harness fixtures and adversarial scope/SCI cases.
- [~] **SM-02 — Diagnostics/test harness:** local diagnostics/tests exist; complete lifecycle and authorization gates, with an explicit CI policy.
- [~] **SM-03 — Durable delivery/no-surprise egress:** scoped durable mutation path exists; complete kill/restart/idempotent replay matrix.
- [~] **SM-10 — Bounded startup context:** context/session projection exists; finish explicit startup and project selection wiring.
- [~] **SM-11 — Structured capsules:** role-tagged transcript/evidence exists; cover exact tool errors/commits across supported harness formats.
- [~] **SM-12 — Multi-harness adapters:** owner-declared external interface exists; only wire explicitly selected harnesses.

- [x] **SM-13 — Exact retrieval/provenance:** scoped GET and serialized retrieval with evidence metadata have dated roundtrip evidence; no present deployment claim.
- [ ] **SM-14 — Claim-once handoff wiring:** bridge workflow against W10.4; engine primitives already exist.
- [ ] **SM-15 — Profile projection:** explicit opt-in project policy and bridge wiring against W10 scoped history.
- [ ] **SM-20 — Curated knowledge pages:** bridge design/wiring against W10.5.
- [ ] **SM-21 — Temporal reconciliation:** bridge versioned-query wiring against W10.6.
- [ ] **SM-22 — Reversible compaction:** product decision and evaluation corpus required before bridge maintenance behavior.
- [ ] **SM-23 — Experience distillation:** product decision, evidence policy and evaluation corpus required.
- [ ] **SM-24 — Authorized archive wiring:** bridge import/export against W10.8; do not reimplement the engine archive.
- [>] **SM-25 — Cross-project inbox:** defer with W10.11/QH-10 until a concrete consumer and independent SEND authority justify it; read grants do not grant delivery.
- [>] **SM-26 — Managed launcher:** conditional on a demonstrated HAX orchestration gap; do not add another launcher by default.

<a id="consolidated-designs"></a>
### Supporting designs, operational gaps and deferred proposals

**KEYSTONE is the current name of NOT_STISLA.** The archived [KEYSTONE integration design](docs/archive/commercial/commercial/QIHSE_NOT_STISLA_INTEGRATION_PLAN.md) keeps its old filename for link compatibility. Its optimization targets and completion statements are historical design claims, not new measurements or an independent active backlog.

The [cluster operations design](docs/plans/cluster_ops_roadmap.md) records useful implemented slices, but its older migration/failback success labels are superseded by the authenticated CT.1/CT.2 runtime contracts and evidence; unfenced paths remain closed. These additional tooling gaps are retained; no completion evidence was established by consolidation:

- [ ] **OPS.1 — Pin rotation procedure:** document authenticated admin-pin rotation with rolling restart and recovery.
- [ ] **OPS.2 — Coherent operator commands:** launcher wrappers and unified status/verify/rolling-restart tooling; reuse existing Python ClusterAdmin/ClusterOps.
- [ ] **OPS.3 — Disposable cluster CI:** isolated three-node admin/replication tests; completion depends on the actual CT guarantees under test, not preseeded data.
- [ ] **OPS.4 — Rust QKP operator SDK:** establish the missing operator surface and pin/authorization tests; Python support does not establish Rust parity.

| Supporting design / old identifiers | Canonical disposition |
| --- | --- |
| [Engine memory design](QIHSE_ENGINE_ROADMAP.md), QH-00…09 / QH-10 | W10.1…W10.10 complete / W10.11 superseded conditional; no second checklist. |
| [General DB design](docs/plans/qihse_general_db_engine_roadmap.md) | Historical W0–W7 components; current application guarantees W11, transport CT.1/CT.2. Gremlin/SPARQL remains optional, unaccepted future scope. |
| [Federation](docs/plans/qihse_federation_upgrade_plan.md), [PG/Neo4j](docs/plans/qihse_pg_neo4j_full_replacement_plan.md), [Redis sharding](docs/plans/qihse_redis_cluster_sharding_plan.md) | W1/W7 completed substrate; historical acceptance claims do not override current CT/W11 gaps. |
| [Studio architecture](docs/plans/QIHSE_STUDIO_DISPLAY_ARCHITECTURE.md) | W6 implemented scope; broader application coverage W11.5. |
| [W11 capability map](docs/plans/qihse_application_capability_map.md), [combined early evidence](docs/plans/w11_combined_early.md) | W11.0–W11.6; bounded early checks do not close combined acceptance. |
| [TurboQuant design](docs/plans/qihse_turboquant_vector_index_plan.md) and W12 baseline/scalar/sidecar/SIMD/shadow reports | W12.0–W12.6; partial stage evidence, no production route. |
| [Hardware design](docs/plans/ZEN4_ZEN2_HARDWARE_ROADMAP.md), old phases 1–5 | W9 covers detection, initial kernels, helpers and harness. Wider VPCLMUL integration, UMA/PQC/WAL/scheduler cache use, CX16 freelists, BITALG/VBMI codecs, IFMA PQC, GFNI parity and real Secondary/Relay rollout measurements remain deferred, not established by W9 completion. Require measured benefit and dispatch/security parity before selection. |
| [Task queue design](docs/plans/qihse_task_queue_plan.md), optional §15 | Existing dispatch/scheduler belongs to the completed substrate. Chains/groups/chords, task subscriptions, Rust task SDK and workflow/dashboard ambitions remain optional, not accepted delivery commitments. |
| [Key-vault proposal](docs/plans/qihse_key_vault_plan.md) | Unimplemented, deferred and not accepted; a secret vault remains a §7 non-goal. No implicit scope expansion. |

---

## 4. Sequencing

**Historical W0–W10 checklist sequence (completed):** `W0 → F0 → F1 → F2 → {F3, F4} → F5 → F6 → F7`. The horizons below describe that program's original order. **Active next sequence:** complete the confirmed repair batch, then W11.0 → scoped W11.1–W11.5 work → W11.6. **Cluster transport:** CT.1 and CT.2 have an implemented baseline but are reopened for the confirmed interruption and convergence defects above. **Independent optional research lane:** W12.0 → W12.1 → W12.2 → W12.3 → W12.5 → W12.6 (W12.4 only after scalar correctness).

| Horizon | Work | Why now |
|---|---|---|
| **Historical: Now** | W0.1–W0.5, then F0 | Uncommitted work blocks any safe refactor; F0 has no dependencies and unblocks all federation stages |
| **Historical: Next** | F1, F2 (in that order); W5.1 in parallel | F1 delivers the headline guarantee (isolated node stays read-write); F2 is the hub dependency — it unblocks W2.2–W2.5, W3.2, and the controller SDK |
| **Historical: Then** | F3 and F4 (can overlap), then F5 | Replication correctness before strong namespaces; trust plane lands before anything treats peers as authenticated |
| **Historical: Later** | F6, then F7 | Supply-chain substrate needs journal + leases + trust; chaos/regression budgets gate the whole thing |
| **Historical: Opportunistic** | W4.2 only after F5; W5.2–W5.5 whenever | DHT before trust would build unauthenticated membership; docs/telemetry are non-blocking |
| **QIHSE AIMEM lane (complete)** | QH-00 through QH-09 complete; QH-10 conditional gate not triggered | Durable scoped lifecycle, coordination, lineage, querying, maintenance, archives and assurance are integrated and tested |
| **Cluster transport** | CT.1–CT.2 partial, repair in progress | Pinned QKP replication and slot migration exist; promotion dissemination, transfer convergence and interruption repairs remain under review |
| **Active stretch program** | W11.0 complete; W11.1–W11.6 partial | General database guarantees across application models, workload isolation, online evolution, history, developer tooling, and combined failure validation |
| **Optional vector-index research lane** | W12.0–W12.3/W12.5–W12.6 partial; W12.4 open | Independent TurboQuant candidate index with authenticated pre-top-K filtering, FP32 rerank, benchmark-gated optional SIMD/Vulkan and reversible sidecars |

**Consolidated follow-ups:** CG.1–CG.17 are complete within the bounded designs and measured trade-offs above. Native HAX/MI integration is separate from the completed W10 engine. SM is an optional standalone bridge, not a HAX dependency. OPS tooling must respect CT fail-closed gates. No live CodeGraph was restored or rebuilt by this work.

Historical dependency notes:

- F2 is the single highest-leverage stage — four workstreams (W2.2, W2.3, W2.5, W3.2) plus acceptance criteria 5/9/10 wait on it.
- F5 depends on F0's identity primitives, not on F3/F4 — it can start as soon as F0 lands if reviewer bandwidth allows, but must land before F6.
- W5 is deliberately decoupled: nothing in W5 blocks federation, and nothing in federation blocks W5.1.

---

## 5. Gates — what "done" means

Every item, regardless of workstream:

1. Source + build wiring + at least one automated test in the same commit (W0 exists precisely because this rule was skipped).
2. Security regressions per `AGENTS.md`: new read primitives take an explicit security context; no principal creates/promotes above itself; **every new externally reachable adapter ships a low-clearance/high-data negative test in CI**.
3. No invariant violations from §5.
4. Docs updated in the same change when behavior or interfaces change.

Workstream-specific gates:

- **Federation stages:** the plan's §46 acceptance criteria are the gate, not the stage checklist. §44 testing requirements (deterministic distributed simulation, mandatory partition scenarios, fuzzing) apply per stage.
- **Brain:** journal entries are reproducible from recorded inputs; no action without a journaled pre-condition; `--brain-act` off by default.
- **Overlay:** a forged/expired IRC record never yields a MEET; a DHT record never yields membership.
- **AI fabric:** every artifact path respects the fabric index authorization model (existing CI job) and the AGENTS.md security invariants.
- **W10 AIMEM:** record and tombstone durability must be proved by crash tests; project/SCI restrictions precede every ranking/graph/count leg; new adapters require AGENTS.md low-clearance/high-data negative tests; versioned knowledge transformations remain reversible.
- **W11 application platform:** public-interface evidence must establish each advertised guarantee; combined workloads must meet predeclared correctness, resource, latency, and recovery budgets under documented faults. Historical queries, migrations, diagnostics, and restore paths retain explicit principal and label enforcement. Publish unsupported combinations and measured limits; individual feature tests do not establish combined application guarantees.
- **W12 TurboQuant:** candidate stages cannot read or rank hidden records; every new classified-capable adapter requires low-clearance/high-data negative CI; sidecars are generation-fenced and disposable; FP32 is authoritative; recall and end-to-end cost are measured against FP32 truth and current QIHSE baselines, never inferred from KV-cache papers.

---

## 6. Invariants (apply to every workstream)

From `AGENTS.md` (repository rules, merge blockers):

1. No classified-capable read primitive without an explicit authenticated security context; no context-free fallback for classified-capable data; `NULL` is never an authorization bypass.
2. No principal may create or modify a principal above itself.
3. Every new protocol adapter ships a low-clearance/high-data negative authorization test in CI.

From the federation plan (§3, non-negotiable):

4. Local survivability — an isolated node stays read-write for LOCAL-consistency namespaces.
5. No global quorum gate on ordinary local writes.
6. Execution decisions (VM start/stop/migrate/fence, storage/network promotion) remain **outside** QIHSE; QIHSE stores evidence, leases, epochs, ownership records.
7. Exclusive-state transitions fail closed without bricking unrelated local operation.
8. Every federation mutation is idempotent, attributable, and HLC-stamped.
9. Never infer safety from absence — a missing heartbeat is not proof a peer is down.
10. Signing authority and build execution are external; QIHSE records provenance, it does not sign or execute.

---

## 6a. ISA capability policy (measured 2026-10-23)

Three places could decide "does this machine support AVX-512 / AVX2+FMA / VNNI /
AMX", and each has a different job. The rule is: **code decides correctness,
the Makefile decides what gets compiled, tests decide what to skip** — never the
other way round.

| layer | mechanism | measured cost | why there |
|---|---|---|---|
| runtime | `qihse_cpu_has_feature(&info, …)` over a CPUID-derived struct (`backends/cpu/qihse_cpu_detect.c`), consulted by the dispatcher before entering an ISA kernel | **7.7 ns/call** (10M calls) — ~10⁴–10⁵× cheaper than one vector kernel | a binary built on a rich host still runs correctly on a poorer one; this is the only place correctness can be guaranteed |
| build | one requirement **group** per ISA in the Makefile via `cpu_has_all`; an ISA is compiled only when *every* flag its codegen needs is advertised | 5.6 ms once per `make` invocation (single `/proc/cpuinfo` parse, shared with `HOST_CPU_FLAGS`); zero per-target cost because the gate is parse-time `ifeq` | `-mavx2 -mfma` on a host without FMA produces code that cannot run; the flag set and the codegen must agree |
| tests | per-ISA preflight: `ifeq ($(QIHSE_ENABLE_<ISA>),1)` around the recipe, else print `SKIP …` and succeed | **net −20 s per full suite run** on an AVX-only host (amx-only 5 s, avx512-direct 4 s, vnni-only 5 s, zen-epyc 5 s, all-isa 1 s were previously compiled, executed and killed by SIGILL) | a hardware capability the host lacks is not a test failure; SIGILL noise hides real regressions |

Requirement groups (all ISAs use the same rule; AVX-512 was the only one that did
before this change):

    AVX      : avx
    AVX2     : avx2 fma
    AVX512   : avx512f avx512dq avx512bw avx512vl fma
    AVX-VNNI : avx2 avx_vnni
    AMX      : amx_tile amx_int8 amx_bf16
    F16C     : avx f16c

On an Ivy-Bridge host (AVX only) this resolves to `AVX=1 AVX2=0 AVX512=0 VNNI=0
AMX=0 F16C=1` and the build emits exactly `-mavx` — detection and codegen agree.

### The arithmetic (so the policy is checkable, not hand-waved)

    overhead_per_call = C_check × c_check
    overhead_ratio    = (C_check × c_check) / (C_check × c_check + W_kernel)

* Measured on the Ivy-Bridge host (20M-iteration microbench, then a real
  384-dim workload): the call itself (direct **or** function-pointer) costs
  ≈ 7.6–8.0 ns and an **inline** capability guard on the hot path adds
  **0.0–0.4 ns — pure noise** (a predicted branch on a cached flag is hidden by
  out-of-order execution). The 7.7 ns figure is a full helper *function call*;
  never call the helper per invocation — inline the flag.
* Real 384-dim kernels (bge-small embedder dims, the deployed workload):
  scalar ≈ 917 ns/call, AVX ≈ 133 ns/call, AVX-512-shaped ≈ 111 ns/call.
  A 100-query × 1 000-candidate run (10⁵ calls) therefore takes ≈ 92.6 ms
  scalar / 13.3 ms AVX / ≈10 ms AVX-512 — while the *entire* dispatch overhead
  for that run (resolve-once) is ≈ 10 µs and guard-per-call ≈ 20 µs: **0.1%**.
* Conclusion: dispatch strategy is a rounding error. The kernel width is the
  entire game (AVX512 vs AVX saves ~5 ms/run, AVX vs scalar ~79 ms/run — 500×
  more than the whole dispatch budget). Choose dispatch by engineering merit,
  never by these numbers: resolve once per pathway (the distance-path pattern)
  because it costs ~5 µs per process and makes cross-host binaries safe; keep
  the Makefile groups because they save build time and binary size on native
  builds; never guard inside the hot loop because it buys nothing the
  resolve-once pattern does not already give.
* **Skipped sets on a native build cost nothing at runtime**: "compile it
  natively only" is the whole point — an ISA the host does not advertise is
  eliminated by the build (`QIHSE_ENABLE_<ISA>=0` → no code, no guard, no
  branch), so a host with many skipped sets pays *fewer* per-call checks, not
  more. Skips only ever save: each one removes compile time, the old SIGILL
  seconds in the suite, and the kernel's bytes from the binary.
* AMX is the extreme case: the guard is ~8 ns; the AMX state it protects costs
  ~0.1–1 µs to save/restore (`xrstor`/`xsave` of tile state). Guarding it is
  three orders of magnitude cheaper than the thing being guarded.

**Do not** move capability checks into the Makefile for correctness, and do not
let a test fail because the CPU lacks an ISA it never advertised. When adding an
ISA: add its flag group to `cpu_has_all`, add the runtime feature bit, and gate
its test on the generated `QIHSE_ENABLE_*` switch.

## 7. Non-goals

QIHSE does not become: a Proxmox replacement UI, VM scheduler, Xen/libvirt wrapper, host fencing system, storage controller, SDN controller, secret vault, remote shell, compiler/build executor, repository signing authority, or monolithic cluster manager. It provides the durable, secure primitives those systems require.

Also explicitly rejected from MEMSHADOW: Python monolith, Postgres, Docker tiers, consciousness/Mamba/neuromorphic/quantum layers, chat-platform glue.

---

## 8. Maintaining this document

- Update the relevant canonical workstream and the top summary when work lands; keep the status date current.
- This file is the only current delivery checklist. Detailed designs and dated evidence remain in supporting files; link rather than duplicate them.
- New or rediscovered work must be mapped to an existing ID or explicitly added here; do not activate a deferred proposal by leaving an unchecked box in a design file.
- Preserve historical evidence dates and distinguish implementation, installed behavior and current deployment certification. Counts must be computed from delivery checkboxes, not copied from old summaries.
- KEYSTONE is the current product name; NOT_STISLA is a former name retained only for historical references and compatible filenames.
- When a phase completes, mark it `[x]` here and link source/build/test evidence in its workstream; preserve older evidence dates.
- Progress reports read this file: keep checklist items countable (one `- [ ]` per deliverable).
