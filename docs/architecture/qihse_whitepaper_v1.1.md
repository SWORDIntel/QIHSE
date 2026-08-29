# QIHSE — Self-Optimizing Multi-Model Search and Database Runtime

## Commercial Architecture Whitepaper v1.1

**Original design date:** 2025-12-27  
**Implementation-status revision:** 2026-08-29  
**Status:** Active implementation; substantial core functionality implemented; production hardening ongoing

> This revision supersedes the implementation-status and roadmap interpretation in `qihse_whitepaper_v1.0.md`. The v1.0 document remains the original design snapshot. Where this document and v1.0 disagree about implementation status, current repository code, tests, security reports, and reproducible benchmarks take precedence.

---

## Executive Summary

QIHSE (Quantum-Inspired Hilbert Space Expansion Search) has evolved from a search-runtime concept into a broader **native-C, multi-model database and search runtime**. The implemented system now spans vector, relational, key-value, document, graph, time-series, full-text, event-stream, compatibility-protocol, hardware-acceleration, persistence, replication, and optimization components.

The central architectural bet remains unchanged:

> **Performance comes from coordinated decisions across algorithms, memory movement, precision, indexing, hardware selection, and verification—not from one exotic search primitive.**

The project should therefore be evaluated as a systems architecture rather than as a single “quantum-inspired algorithm.” Quantum-inspired components are optional techniques inside a larger runtime and must justify themselves against strong classical baselines.

### Modular adoption is a design requirement

**Applications do not need to use all of QIHSE.** The system is intentionally composable. A deployment may use a single engine, protocol surface, index, storage component, or hardware backend without enabling the rest of the runtime.

Examples:

- use the vector engine without the graph or relational layers;
- use PostgreSQL/pgwire compatibility without enabling Redis or MongoDB compatibility;
- use the native C API without Python or Rust bindings;
- use scalar or CPU SIMD paths without CUDA, NPU, AF_XDP, cluster, neuromorphic, or future quantum backends;
- use a local embedded database without the distributed runtime;
- use QIHSE indexing or search components inside another system rather than replacing that system wholesale.

Advanced orchestration, heterogeneous acceleration, UWP networking, cluster features, self-optimization, and multi-model compatibility are **opt-in capabilities, not prerequisites**.

This distinction is important commercially: QIHSE's breadth expands the addressable integration surface, but it does not require every adopter to absorb the complexity of the entire project.

---

## 1. Product and Architecture Model

### 1.1 Data plane and control plane

QIHSE separates hot-path execution from slower optimization and governance work.

**Data plane:**

- vector distance and top-K kernels;
- graph traversal and graph+vector operations;
- relational, document, key-value, full-text, time-series, and event-stream execution;
- quantization/dequantization;
- index lookup and candidate reduction;
- serialization/protocol handling;
- persistence and replication paths;
- CPU/GPU/NPU execution where enabled.

**Control plane:**

- workload characterization;
- hardware capability discovery;
- telemetry and profiling;
- backend and parameter selection;
- learning/optimization policy;
- regression detection;
- rollout safety and future rollback automation;
- operational observability.

The data plane must remain functional when optional adaptive components are disabled.

### 1.2 Stable native interfaces

The implementation is centered on a native C runtime and C-facing subsystem interfaces. Python, Rust, protocol compatibility, and higher-level integrations sit above that base rather than replacing it.

The architectural rule is:

> **Keep the hot path native, keep optional integrations replaceable, and do not require cross-language transitions for core execution.**

The original v1.0 roadmap proposed a C/C++/CUDA/Fortran/Julia mix. The current implementation has converged primarily on **C + Python + Rust**, with CUDA and other hardware-specific code where useful. Fortran and Julia are no longer treated as mandatory implementation milestones.

### 1.3 Backend model

Backends should expose capability, cost, and execution interfaces while preserving a portable baseline path.

Current or active backend classes include:

- scalar CPU;
- AVX/AVX2/AVX-512 CPU paths;
- AMX/BF16/VNNI paths where hardware permits;
- CUDA GPU;
- Intel/OpenVINO-oriented acceleration paths;
- distributed/cluster execution;
- optional AF_XDP/eBPF networking support;
- research/future accelerator interfaces.

A backend existing in the tree is not, by itself, proof that automatic heterogeneous scheduling is fully production-ready. Capability detection, execution, and orchestration maturity are tracked separately in the roadmap below.

---

## 2. Search and Algorithmic Model

### 2.1 Reference workload classes

QIHSE should continue to validate at least three broad search classes:

1. **Vector search** — ANN/top-K with exact reranking or verification where required.
2. **Graph search** — traversal, expansion, shortest-path-like and graph+vector workloads.
3. **Constraint/structured search** — boolean, relational, document, metadata, and score-fusion workloads.

The expanded database runtime adds additional validation domains such as full-text, time-series, event-stream, and compatibility-protocol workloads, but those do not remove the need for the original reference set.

### 2.2 Quantum-inspired techniques

“Quantum-inspired” means **classical algorithms influenced by quantum-computing concepts**, not execution on a quantum computer.

Candidate techniques include:

- Hilbert-space or kernel feature expansion;
- Random Fourier Features (RFF);
- amplitude-amplification-like iterative reweighting;
- variational or learned search policies;
- randomized candidate generation;
- tensor-network-inspired compression or structured computation;
- search-policy exploration using bandits or other learning systems.

Each such technique must have:

- a classical fallback;
- a measurable win region;
- a kill switch or disable condition;
- correctness and approximation limits;
- an end-to-end benchmark against a strong baseline.

Kernel-time wins that disappear after data movement, setup, or verification do not count as product-level wins.

### 2.3 Exact verification remains authoritative

Approximate structures may narrow the search space, but exact computation must remain available for correctness-sensitive workloads.

The working principle is:

> **Approximations hunt the targets. Exact math dictates the truth.**

This applies to vector reranking, candidate filtering, learned proposals, quantized search, and any future accelerator path.

---

## 3. Hardware and Memory Architecture

### 3.1 CPU execution

The repository contains runtime CPU distance dispatch with scalar, AVX, AVX2/FMA, and AVX-512 implementations for core vector metrics. Hardware-specific acceleration also includes AMX/BF16 and VNNI-oriented paths where supported.

The portable baseline remains mandatory. Hardware-specific code should be selected only after runtime feature detection.

### 3.2 Memory hierarchy

QIHSE treats memory movement as a first-class performance constraint.

Implemented and active work includes:

- UMA-oriented memory support;
- hardware/topology discovery;
- device placement policy;
- memory migration policy and scheduling;
- allocation policy;
- planner tracing;
- cache-conscious data structures and SIMD-oriented layouts.

The long-term KPI remains **bytes moved per query**, not only arithmetic throughput.

### 3.3 Heterogeneous acceleration

The runtime contains real CUDA execution and device-memory handling, plus NPU/OpenVINO-oriented integration work. The remaining problem is less “can code execute on another device?” and more “can the runtime consistently choose the right device, precision, transfer strategy, and fallback under real workloads?”

Accordingly, heterogeneous scheduling is treated as partially complete until cost-model selection, fallback behavior, and regression-tested coordination are mature across supported devices.

---

## 4. Adaptive Runtime and Self-Optimization

The original self-optimizing goal is no longer purely aspirational. The repository contains implementations and tests for several of the required mechanisms, including:

- Thompson-sampling multi-armed bandits;
- contextual bandits;
- workload fingerprinting;
- telemetry collection;
- regression detection;
- neural optimization experiments;
- counterfactual learning;
- variational optimization;
- parameter-space exploration;
- meta-learning experiments.

These components demonstrate the control-plane architecture, but a distinction must be maintained between **optimization primitives existing** and a **fully governed autonomous production optimizer**.

A production-grade adaptive decision should eventually record:

```text
workload features
    -> candidate plans
    -> selected plan
    -> confidence / selection rationale
    -> measured outcome
    -> correctness result
    -> regression decision
    -> rollback / retain decision
```

The open hardening work is primarily governance: A/B rollout, safety bounds, automated rollback, stable policy persistence, and production-scale validation.

---

## 5. Distributed and Multi-Model Runtime

QIHSE has expanded beyond the original search-only framing. Current architecture includes or is actively implementing:

- relational SQL, joins, aggregation, indexing, transactions and MVCC;
- vector indexing/search;
- graph storage and Cypher/Bolt paths;
- key-value and document models;
- full-text search;
- time-series and event-stream paths;
- WAL, persistence, replication, backup and recovery;
- connection pooling and CDC;
- PostgreSQL, Redis, MongoDB, Neo4j/Bolt, Elasticsearch-style, ClickHouse-style, InfluxDB-style and related compatibility surfaces.

These should be treated as **independently adoptable surfaces over shared native infrastructure**.

Compatibility does not imply perfect behavioral equivalence with every upstream database edge case. Each compatibility layer requires its own conformance tests and declared support boundary.

---

## 6. Observability and Dashboard

Observability is part of the runtime architecture, not a presentation-only feature.

The dashboard now treats the native `/metrics` endpoint as the source of truth and exposes:

- live connection state;
- stale/unavailable telemetry warnings;
- current QPS;
- rolling and peak QPS;
- current, average, p95 and p99 latency over the observed window;
- active vector count;
- dashboard-side telemetry success/failure rate;
- last update time and endpoint status;
- separate throughput and latency visualization.

The dashboard deliberately no longer presents hard-coded cluster nodes, storage capacities, or XDP/network values as if they were live telemetry.

Where native metrics do not yet expose cluster, storage, or network counters, the dashboard displays that limitation explicitly. Future visibility should be added by expanding the native metrics contract rather than fabricating values in the UI.

### Recommended next telemetry fields

The native metrics endpoint should eventually export at least:

```text
qihse_queries_total{type,backend}
qihse_query_latency_seconds buckets / p50 / p95 / p99
qihse_query_errors_total{type,backend}
qihse_backend_available{backend}
qihse_backend_utilization{backend}
qihse_vectors_active
qihse_index_bytes{index}
qihse_memory_bytes{tier,node}
qihse_replication_lag{peer}
qihse_cluster_node_state{node}
qihse_network_rx_bytes
qihse_network_tx_bytes
qihse_xdp_packets
qihse_xdp_drops
qihse_optimizer_decisions_total{plan}
qihse_optimizer_rollbacks_total{reason}
```

---

## 7. Security and Compliance Position

QIHSE is under active security hardening. Implemented cryptography or internal audit work must not be presented as external certification.

Current documented state includes:

- an internal UWP security review;
- remediation work for identified high-severity protocol issues;
- authentication and authorization mechanisms;
- transport encryption support where configured;
- data-at-rest cryptographic support for `.qdb` workflows where configured;
- fuzzing, sanitizer and protocol-regression test infrastructure.

Current limitations remain explicit:

- no third-party security audit claim;
- no FIPS 140-3 validation claim;
- no CNSA 2.0 certification claim;
- deployment security depends on configuration and the exact protocol surface exposed.

Security documentation under `docs/security/` is authoritative for the current implementation state.

---

## 8. Benchmark and Claim Discipline

### 8.1 Minimum evidence before performance claims

Any headline performance claim should report:

- hardware and CPU/GPU/NPU model;
- compiler and build flags;
- active ISA/backend;
- dataset and dimensions;
- index configuration;
- query count and concurrency;
- recall/accuracy target;
- p50/p95/p99 latency;
- throughput;
- memory footprint;
- build/setup time where relevant;
- energy/query when actually measured;
- baseline version and configuration.

### 8.2 Current measured reference point

The repository's QIHSE + KEYSTONE integrated benchmark report records the following host result on an Intel Xeon E5-2407-class system using the available CPU execution path:

| Operation | Throughput | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| HNSW vector search, default entry | 33,080 ops/s | 27.96 µs | 30.87 µs | 90.32 µs |
| HNSW vector search, anchor-seeded | 31,692 ops/s | 29.39 µs | 33.67 µs | 118.42 µs |
| Binary search, 1M rows | 2,016,334 lookups/s | 415 ns | 715 ns | 878 ns |
| Keystone anchor search, 1M rows | 3,510,610 lookups/s | 218 ns | 347 ns | 450 ns |
| AF_XDP ingest | 141,865 packets/s | 4.63 µs | 5.54 µs | 22.78 µs |
| Hybrid FTS + vector RRF | 1,838 queries/s | 501.58 µs | 715.75 µs | 850.03 µs |

These are useful **measured project results**, but they do not automatically validate every older v1.0 competitive or market-level claim. External-comparison claims should be independently reproduced on matched hardware/configurations before being used commercially.

### 8.3 Claims that remain gated

Do not treat the following as established merely because they appeared in v1.0:

- universal 10–50x performance improvements;
- 200K–250K QPS/server as a general product figure;
- sub-50 µs tail latency across all workloads;
- 40–60% general TCO/energy savings;
- linear scaling to 1000+ nodes;
- compliance certification;
- production SLAs;
- revenue/customer projections.

They remain hypotheses or targets until validated by appropriate evidence.

---

## 9. Implementation Roadmap — Current Status

### Status legend

- `[x]` — implemented with repository evidence; may still receive optimization/hardening.
- `[~]` — materially implemented, but incomplete against the milestone's full production intent.
- `[>]` — original milestone has been superseded by the current architecture.
- `[ ]` — still outstanding or not sufficiently validated.

The original week numbers are retained only as historical grouping. They are **not current schedule estimates**.

### 9.1 Phase 0 — Foundation

**Project setup and architecture**

- [x] Repository initialization with CI/CD pipeline
- [x] Core ABI specification and header surface
- [>] CMake/Meson multi-language build requirement — superseded by the current Make/unified-launcher build architecture
- [x] Initial documentation structure

**Memory management and testing infrastructure**

- [x] Core memory planner / UMA-oriented implementation
- [x] Unit testing infrastructure
- [x] Benchmark harnesses
- [x] Basic performance profiling and instrumentation

**Phase assessment:** foundation is substantially complete. Build-system wording should follow the implementation that exists rather than the original technology list.

### 9.2 Phase 1 — CPU SIMD Backend

**Core search kernels**

- [x] SIMD-accelerated vector search paths
- [x] L2 / cosine / dot-product distance metrics
- [x] Top-K selection/search infrastructure
- [x] Memory-efficient search/index data structures

**Intel hardware optimization**

- [x] AMX/BF16-oriented matrix operations
- [x] AVX-512 vector processing
- [x] VNNI integer/mixed-precision operations
- [~] Meteor Lake-specific end-to-end tuning and validation

**Phase assessment:** the CPU foundation is implemented. Remaining work is primarily hardware-specific benchmarking, tuning and regression validation rather than creation of the basic kernels.

### 9.3 Phase 2 — Heterogeneous Acceleration

**CUDA GPU backend**

- [x] CUDA kernel implementations for search-related operations
- [x] GPU memory management and data transfer
- [x] stream-based asynchronous execution
- [x] device/error handling

**NPU / OpenVINO integration**

- [x] NPU/OpenVINO model/inference integration foundation
- [x] inference pipeline integration
- [~] quantization and precision policy integration
- [~] cross-workload performance profiling and optimization

**Backend orchestration**

- [x] backend/device capability detection
- [~] cost-model maturity for backend selection
- [~] automatic heterogeneous dispatch across supported workload classes
- [~] generalized fallback behavior and regression coverage

**Multi-language support**

- [>] Fortran BLAS/LAPACK integration — no longer a required product milestone
- [>] Julia HPC integration — no longer a required product milestone
- [x] Python bindings/SDK work
- [x] Rust and C SDK surfaces
- [~] standardized zero-copy/interchange semantics across all relevant boundaries

**Phase assessment:** heterogeneous execution exists; fully automatic production-quality scheduling remains a hardening task.

### 9.4 Phase 3 — Self-Optimizing Runtime

**Telemetry infrastructure**

- [x] performance metrics collection
- [x] workload characterization
- [x] resource/hardware monitoring foundations
- [x] real-time profiling hooks

**Optimization algorithms**

- [x] multi-armed bandit implementation
- [~] general Bayesian optimization framework
- [x] workload fingerprinting
- [x] configuration/parameter-space exploration

**Governance and safety**

- [x] regression detection algorithms
- [ ] automatic rollback mechanism for optimizer rollouts
- [ ] production A/B rollout infrastructure
- [~] integrated safety bounds / constraints

**Integration testing**

- [x] end-to-end benchmark validation exists for multiple integrated paths
- [~] multi-backend coordination testing
- [~] optimization stability verification
- [ ] formal production-readiness assessment

**Phase assessment:** the self-optimization research/control-plane machinery is real. The main gap is safe production governance, not absence of optimization algorithms.

### 9.5 Phase 4 — Production Hardening

**Security and compliance**

- [x] internal security audit/hardening work
- [~] compliance-oriented control architecture
- [x] access-control/authentication mechanisms
- [~] secure configuration-management hardening
- [ ] third-party security audit/certification where commercially required

**Operations and monitoring**

- [~] production deployment tooling
- [~] monitoring dashboard — live telemetry visibility implemented; backend metric coverage still expanding
- [ ] complete alerting and incident-response automation
- [~] automated performance-regression gating

**Documentation and launch readiness**

- [~] API documentation — interfaces are documented across headers and subsystem docs, but a complete generated/reference API surface remains outstanding
- [x] getting-started and user-oriented documentation
- [~] performance/tuning guides
- [ ] formal launch-readiness assessment

**Phase assessment:** production hardening is the least complete original phase and should remain the primary engineering focus before broad “market-ready” claims.

---

## 10. Roadmap Summary

A strict interpretation of the original roadmap currently looks approximately like this:

| Phase | Implemented | Partial / superseded | Open |
|---|---:|---:|---:|
| Foundation | 7 | 1 | 0 |
| CPU SIMD | 7 | 1 | 0 |
| Heterogeneous acceleration | 8 | 7 | 0–2 depending on deprecated-language interpretation |
| Self-optimizing runtime | 9 | 4 | 3 |
| Production hardening | 3–4 | 6 | 3–4 |

The exact count is less important than the distribution: **core runtime and algorithmic work are substantially ahead of the old roadmap; production governance, observability coverage, deployment maturity, external validation and launch hardening remain behind it.**

---

## 11. Verification Gates

### 11.1 Backend conformance

Every backend should pass the same operation-level contracts for supported modes:

- input domain and shape;
- output ordering;
- top-K behavior;
- precision/error limits;
- failure semantics;
- fallback semantics;
- deterministic behavior where required.

### 11.2 Approximation validation

Approximate or quantized execution must be compared against a higher-precision or exact reference on sampled workloads.

Required outputs should include:

- recall/precision;
- error distribution;
- divergence rate;
- escalation/fallback rate;
- performance benefit after verification cost.

### 11.3 Adaptive-policy validation

Before an optimizer decision is trusted automatically:

1. log the candidate and chosen plans;
2. evaluate a representative baseline or shadow plan on sampled traffic;
3. detect statistically meaningful regressions;
4. refuse or roll back unsafe configurations;
5. preserve enough telemetry to reproduce the decision offline.

### 11.4 Distributed validation

Cluster testing should include:

- node loss;
- delayed nodes;
- partitions;
- stale replicas;
- replay/recovery;
- rebalancing;
- degraded-mode labeling;
- recovery to converged state.

---

## 12. Near-Term Engineering Priorities

The highest-value work is no longer “implement more named subsystems.” It is to make the existing breadth easier to validate and operate.

### Priority 1 — Finish optimizer governance

- production A/B or shadow-plan harness;
- explicit safety constraints;
- automatic rollback;
- persistent decision/outcome history;
- regression budgets by workload and backend.

### Priority 2 — Expand native telemetry

- backend availability/utilization;
- per-query-type latency histograms;
- error counters;
- memory/index movement counters;
- cluster/replication status;
- network/XDP counters;
- optimizer decision and rollback counters.

The dashboard should remain a truthful renderer of these metrics rather than maintaining independent synthetic state.

### Priority 3 — Build a gold validation suite

Maintain a versioned workload pack covering:

- vector ANN + exact rerank;
- relational/constraint queries;
- graph traversal;
- full-text + vector fusion;
- persistence/recovery;
- protocol compatibility;
- distributed failure tests;
- security regressions.

### Priority 4 — Formalize API documentation

Generate or maintain a coherent API reference for the public C surface, SDKs, protocol compatibility and configuration model. Existing headers and subsystem docs are useful but fragmented.

### Priority 5 — Separate target architecture from implemented behavior

Documentation should consistently label:

- **implemented**;
- **experimental**;
- **partial**;
- **planned**;
- **superseded**;
- **externally validated**.

This is especially important for deployment examples, compliance language, benchmark comparisons and compatibility claims.

---

## 13. Commercial Positioning

The credible near-term positioning is not “every database and every accelerator is finished.” It is:

> **QIHSE is a native systems platform that combines multiple search/data models, hardware-aware execution and adaptive optimization behind shared low-level infrastructure, while allowing adopters to use only the components they need.**

The strongest differentiators to validate are:

- reduced data movement from shared native execution;
- fast vector and structured lookup paths;
- integrated multi-model operations that avoid inter-service RPC;
- hardware-specific acceleration with portable fallbacks;
- compatibility surfaces that reduce migration cost;
- adaptive optimization that can eventually reduce manual tuning;
- modular deployment rather than an all-or-nothing platform requirement.

Commercial claims should track measured evidence, not roadmap ambition.

---

## 14. Operational Definition of “Done”

A roadmap item is considered **implemented** when the repository contains a functional implementation and enough tests or integration evidence to show it is more than an interface stub.

A subsystem is considered **production-ready** only when, in addition, it has:

- clear configuration and failure behavior;
- regression coverage;
- observability;
- recovery/fallback behavior;
- documented security assumptions;
- reproducible performance/correctness validation;
- operational documentation;
- no known blocker that invalidates the intended deployment model.

These are intentionally different bars.

QIHSE has crossed the implementation bar for a large portion of the original roadmap. It has **not yet crossed the production-readiness bar for the entire platform**, and the whitepaper should state that plainly.

---

## 15. Source-of-Truth Documentation

Use the following repository areas when evaluating current state:

- `README.md` — current project overview and scope;
- `docs/FEATURES.md` — subsystem inventory;
- `docs/COMPATIBILITY.md` — compatibility surfaces;
- `docs/architecture/` — implementation architecture;
- `docs/benchmarks/` — measured performance and methodology;
- `docs/security/` — current security posture and audit material;
- `docs/deployment/` — deployment/operations documentation;
- `tests/` and subsystem test directories — implementation evidence;
- `.github/workflows/` — current CI behavior;
- `dashboard/` — runtime observability UI.

The original `qihse_whitepaper_v1.0.md` remains useful for historical design intent, mathematical background, and early commercialization thinking, but it should not be used as the sole source for current implementation status.

---

## Document Metadata

**Version:** 1.1  
**Implementation status date:** 2026-08-29  
**Classification:** Living architecture and implementation-status whitepaper  
**Previous version:** `qihse_whitepaper_v1.0.md`  
**Status:** Core implementation substantially advanced; heterogeneous orchestration and self-optimization partially hardened; production hardening ongoing
