# W12 — TurboQuant derived vector index (research and implementation plan)

**Status:** planned / not implemented (2026-10-22).
**Master:** [QIHSE ROADMAP.md, W12](../../ROADMAP.md#w12--turboquant-vector-candidate-index-planned).
**Scope:** QIHSE-native vector retrieval and optional AIMEM semantic retrieval, not HAX, NAT, or model KV-cache integration.
**Primary reference:** Zandieh, Daliri, Hadian, Mirrokni, *TurboQuant: Online Vector Quantization with Near-optimal Distortion Rate*, ICLR 2026: https://proceedings.iclr.cc/paper_files/paper/2026/hash/5c802ef38ab6e366c2ea06eee554c088-Abstract-Conference.html ; https://arxiv.org/abs/2504.19874 .
**Research explainer:** Google Research (2026-03-24): https://research.google/blog/turboquant-redefining-ai-efficiency-with-extreme-compression/ .
**Licensing:** independently implement against the published algorithm, document provenance, and review third-party code/data licensing before copying or vendoring anything. A research paper does not grant a general software-code license.

## Scope and invariants

TurboQuant is an online/data-oblivious method for high-dimensional vector quantization, not a drop-in accelerator for opaque key-value records. Evaluate randomized orthogonal rotation and dimension-aware scalar quantization (MSE mode), plus the QJL 1-bit residual correction where inner-product estimation is required. Exact choice of rotation, distributions and unbiasedness assumptions must follow the primary paper; a standard INT4 converter or quantized original-vector sketch is **not** TurboQuant.

- Canonical FP32 vectors, IDs, WAL/MVCC and ACLs remain authoritative. New codes are **derived, disposable, generation-bound sidecars**.
- Approximate retrieval narrows candidates; existing exact FP32 rerank verifies only selected candidates. It **does not** guarantee the globally exact top-K when the approximate stage omits a true neighbour.
- All classified-capable read/search functions inherit explicit authenticated user context. Never filter an unauthorized global top-K after candidate selection; unauthorized records cannot influence authorized results, counts, scores, pagination, explanations or query-shape side channels.
- Existing query modes, C ABI values, disk formats, backward compatibility and default behaviour remain unchanged. New mode defaults **off**.
- CPU scalar correctness is mandatory. SIMD/GPU acceleration is optional, runtime-selected and never a build-time dependency.

## Existing QIHSE substrate to reuse

| Source | Existing responsibility | Proposed use |
| --- | --- | --- |
| `include/qihse_vector_db.h` | Query-mode enum, query structure, persistence status, exact-rerank semantics | Add an explicit optional mode after ABI review, preserving existing integer values |
| `src/broad_oak/qihse_vector_db.c` | FP32 authoritative data, HNSW/trinary/INT8/FP16/FP8/FP4/INT4/binary search/sidecar paths | Sidecar lifecycle, candidate-only retrieval, FP32 rerank |
| `quantization/src/qihse_pq.c` + `quantization/include/qihse_pq.h` | Codebook-trained PQ prototype | Baseline comparator, not a dependency |
| `quantization/src/qihse_quantization.c` | Additional quantization code | Inspect build wiring/correctness before reusing |
| `include/qihse_hnsw.h` | HNSW plus FP16 layer and anchor seeding | Benchmark against; graph quantized distance only if proven safe |
| `QIHSE_ENGINE_ROADMAP.md` (W10, QH-01/QH-05) | Authorized scoped AIMEM query, security-before-ranking | Non-regression and negative test requirements |
| `backends/cpu/`, `backends/gpu/` and `benchmarks/` | ISA dispatch, accelerator backends, benchmark framework | Measured optional speedups |

The proposed paths below are **not implemented artifacts**. Inspect actual build wiring and storage APIs before edits.

## Deliverables

### W12.0 — Baseline and contract (P0)

- Trace actual FP32/vector insert, update, tombstone, compaction, flush, candidate-selection and exact-rerank call paths; resolve the authenticated AIMEM vector-index entry point.
- Pin commit, compiler, hardware, corpus, seeds, dataset dimensions (e.g. 128/384/768/1536), dot/cosine/L2 modes and existing sidecar versions. Identify C/RESP/SDK ABI implications.
- Build exact exhaustive-FP32 oracle with deterministic tie handling and establish baseline speed, recall and effective index-byte cost for all **actually wired** alternatives: HNSW, trinary, INT8, INT4, FP16, binary and PQ (where built).
- Predeclare precision and candidate-pool configurations. Initial target on the declared primary semantic corpus: candidate Recall@10 >= 0.99; **and either** >= 1.5x measured end-to-end throughput at equivalent recall **or** >= 2x resident/index byte reduction without >5% p95 latency regression. These are *promotion targets*, not paper claims or universal expectations. Record statistical uncertainty and corpus failures.

**Gate:** reproducible baseline artifacts, numerical accuracy contract and limits agreed before optimizing.

### W12.1 — Correct native C scalar codec (P0)

**Candidate paths:** `quantization/include/qihse_turboquant.h`, `quantization/src/qihse_turboquant.c`, `tests/test_turboquant.c`.

- Implement paper-defined deterministic random orthogonal rotation, normalization, scalar quantization, packed bit codes and decoder/score; include dimension, norm, seed, quantizer-table version and bit-width metadata.
- Separate MSE-only and inner-product-corrected variants. QJL must sketch the **residual** after MSE reconstruction, with the proper random projection and normalization; statistically verify inner-product bias and variance.
- Handle zero norms, NaN/infinite values, overflows, unsupported dimensions, malformed or truncated inputs, and exact payload-length accounting.
- Avoid per-vector O(d²) transformations where a justified fast structured transform is available *and validated against the required theoretical construction*; separately measure encode cost. Do not silently substitute a different algorithm.
- Include reproducible randomization/seed derivation and fuzz/ASan/UBSan coverage; ensure scalar fallback on all supported legacy CPUs.

**Gate:** codec correctness and determinism across encode/reopen/score without changing existing mode behaviour.

### W12.2 — Durable derived sidecar (P1)

**Candidate sidecar name:** `vectors.qtq` (provisional, verify against existing formats).

- Version/magic, packed payload and offsets, dimensions, count, bit widths, rotation and QJL parameters, source committed generation, ID mapping, integrity fingerprint/checksum, metric support and encoder version.
- Rebuild from a stable FP32 snapshot. Publish via safe temporary write, validation, fsync, atomic cutover and directory sync; verify recovery after SIGKILL at every publication boundary.
- Explicit status ABSENT/BUILDING/READY/STALE/CORRUPT/FAILED; invalidate on insert/update/delete/compaction or source-generation mismatch. Preserve canonical query availability during rebuild. No partial new generation may leak into searches.
- Online append can be a later generation-aware delta overlay; a first implementation may explicitly force rebuild, but must never mix generations.
- Apply size limits and endian-safe decoding to all offsets, counts, arithmetic and output buffers.

**Gate:** old files still load, damaged/stale optional sidecars never contaminate authoritative results, restart/rebuild/rollback verified.

### W12.3 — QIHSE search + security integration (P1)

- After ABI review, add an explicit `QIHSE_VDB_QUERY_TURBOQUANT` selector without renumbering existing modes. Existing FP32 remains default.
- Apply live authenticated tenant/project/owner/clearance/SCI filtering **before quantized candidate generation, top-K/ranking statistics, explanations and output**. Partition/filter the source candidate universe first. A global top-K followed by auth filtering is a blocker.
- Quantized candidate results carry stable row IDs and committed generation. Reauthorize on materialization; rerank the selected set against canonical FP32 using the existing metric. Preserve tie, tombstone and cursor invariants.
- Keep explicit bounded candidate-pool/oversampling policy. Integrate into AIMEM semantic/hybrid retrieval **only after** native VectorDB mode passes scoped auth tests; preserve BM25/RRF and QH-05 cursor contracts.
- Add low-clearance/high-data negative regression tests (native API plus any new RESP/SDK adapter) for tenant/scope, revocation, SCI, counts, score/order, pagination, diagnostics, direct-ID and hybrid legs.

**Gate:** candidate/FP32-score parity for selected IDs, no ranking starvation or hidden-record influence, all auth negatives in CI.

### W12.4 — CPU SIMD and optional GPU (P2 / parallel lane)

- Profile rotation, packed scoring, QJL, partial top-K, memory movement. Optimize with dynamic SSE/AVX2/AVX-512 dispatch where available; retain golden scalar path and document numerical tolerances.
- Evaluate **optional QIHSE-local Vulkan compute** in `backends/gpu/` for batched, resident-index similarity scoring; no external terminal/runtime dependency. If testing the previously discussed device, cap **total device-local allocation at 1.2 GB decimal**, including buffers, scratch and headroom. Check real device budget at runtime.
- Measure transfer+launch+synchronization+compute+return, not just shader time. Dedicated PCIe and shared-memory iGPU cases require separate observations. OOM/device loss falls back to CPU without corrupting sidecars or violating auth.
- Promote GPU only on >=1.5x total-query win at equal recall and no harmful p95/p99 tail-latency/security regression; otherwise remain experimental/off.

**Gate:** genuine measured gain, device-budget compliance, legacy CPU compatibility, no mandatory GPU.

### W12.5 — Differential, adversarial, fault and performance verification (P1/P2)

- Compare exhaustive FP32 truth vs HNSW, trinary, FP16, INT8/INT4, binary, PQ and TurboQuant. Report candidate Recall@1/10/100, final Recall@K, NDCG when useful, MSE/inner-product bias, throughput, p50/p95/p99, build/update cost, RAM/VRAM/disk bytes per vector **including metadata and codebook/seed overhead**.
- Evaluate real authorized AIMEM corpora plus isotropic, anisotropic, clustered, duplicate, high-dynamic-range and sparse-sign synthetic data, concurrent ingestion, tombstone-heavy generations and mixed ACL/SCI tenants.
- Failure injection at encode/write/fsync/rename/swap, restart during query/build, malformed sidecar fuzz and sanitizers. Contrast low-clearance query with high-data records absent/present: no hidden-record effects.
- Maintain exact result and authorization invariants under W11.2 workload contention, W11.3 migration/cutover and W10 scoped AIMEM.

**Gate:** independently reproducible benchmark script and CI results; failure reports retained, no cherry-picked recall.

### W12.6 — Shadow -> canary -> promotion/rollback (P3)

- Opt-in only. First shadow against authoritative FP32 and record privacy-safe per-query validation receipts, then canary by corpus/metric/dimension/codec profile.
- Promote only after predeclared thresholds and security/crash gates pass. State whether strict-exact queries always bypass approximate candidate selection.
- Roll back by disabling mode and dropping the disposable sidecar, never mutating FP32 or losing WAL/ACL/provenance. Old binaries safely ignore or reject the optional sidecar.
- Record SHA, hardware, build flags, security CI, performance, reproduction instructions, change-log and third-party licensing/provenance review. No `[x]` based merely on a compiled source file.

**Gate:** successful live shadow/canary, tested rollback and no authorization regression.

## Dependency map and stopping rule

**Critical path:** W12.0 -> W12.1 -> W12.2 -> W12.3 -> W12.5 -> W12.6. W12.4 is optional after W12.1. Reuse W10 QH-01/QH-05. Coordinate W11.2 resource isolation and W11.3 online index evolution, but W12 does **not** block W11's database transaction program.

**Stop if:** recall cannot meet intended workloads at useful bit rates; encode/rebuild costs offset savings; true pre-top-K auth isolation is infeasible; no end-to-end resource/performance benefit. Publish a negative result rather than shipping a slower or weaker default.

**Non-claims:** no guarantee of “lossless 3.5-bit” quality for QIHSE vector search (the well-known near-quality-neutral 3.5-bit finding is for the paper's KV-cache experiments); no guarantee that FP32 rerank makes an approximate candidate set exact; no claim that any W12 code or benchmark exists yet.
