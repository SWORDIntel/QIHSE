<p align="center">
  <img src="docs/QIHSE.png" alt="QIHSE logo" width="720">
</p>
<div align="center">

## Quantum-Inspired Hilbert Space Expansion Search

### If you need a database—any database, for any workload, at any scale—this is your endgame. Vector, Graph, KV, Document, Time-Series, Columnar, FTS, and Event Stream—unified under one zero-copy protocol and one relentless standard of exactness.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE)
[![C](https://img.shields.io/badge/Core-C-00599C?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Python](https://img.shields.io/badge/SDK-Python_Native-3776AB?logo=python&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)]()
[![SIMD](https://img.shields.io/badge/SIMD-AVX2%20%7C%20AVX--512-00599C)]()
[![Multi-Modal](https://img.shields.io/badge/Multi--Modal-8%20Engines-darkgreen)]()
[![Security](https://img.shields.io/badge/Security-Cell--Level%20Clearance-red)]()
[![CNSA 2.0 Compliant](https://img.shields.io/badge/CNSA%202.0-Compliant-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero-success)]()

</div>

---

## The Masterpiece of Data Architecture

**QIHSE** is a native C database ecosystem and a systems engineering showcase built around a single, uncompromising rule:

> **Approximation is allowed to propose candidates. It is not allowed to silently decide truth.**

Modern applications often suffer from the "impedance mismatch" of stitching together a half-dozen specialized databases—a vector DB for AI, Redis for caching, PostgreSQL for documents, and Kafka for events. QIHSE eliminates this fragmentation. It is not a cosmetic ANN wrapper or a patchwork of microservices. It is a fully fortified, multi-modal database system combining **eight distinct storage engines** within the exact same process space.

Everything is natively orchestrated. Fast paths are visible. Memory is strictly managed. And data travels from the network interface straight to the computation layer with zero intermediate copies.

---

## 8 Engines, 1 Unified Brain

QIHSE seamlessly weaves together eight specialized compute engines to handle any workload you can throw at it:

1. **The Vector DB**: Acting as the optic nerve of the engine, it uses an exactness-first `float32` core. Accelerators like Trinary signatures (`qtri`/`qmag`), multi-precision quantization (`FP16`, `FP8`, `FP4`, `INT8`, `INT4`), and sparse indexing act as execution layers that rapidly reduce the search space before an authoritative, exact rerank. *(Note: Our low-level multi-precision pipelines have been rigorously red-teamed against `SIZE_MAX` integer overflows and array boundary corruption attacks to ensure ironclad memory resilience).*
2. **The Key-Value Store**: An O(k) Trinary Trie memory engine backed by native LSM-Trees and SSTable persistence for instantaneous, lock-free lookups.
3. **The Document Store**: A JIT-compiled JSON document engine that translates hot access patterns directly into executing bytecode.
4. **The Time-Series DB**: Lock-free ingress buffers paired with Gorilla XOR bit-packing act as a temporaӏ sink to absorb massive telemetry streams effortlessly.
5. **The Columnar Engine**: An AVX-accelerated OLAP backend utilizing strided OS page alignments for massive aggregations and Run-Length Encoding sweeps.
6. **The Graph Engine**: Multi-hop traversal routed dynamically via Anchor and HNSW algorithms.
7. **The FTS Engine**: Zero-copy lexical tokenization with native BM25 scoring for pinpoint full-text search.
8. **The Event Stream**: A raw, append-only log engine bypassing user-space entirely via Linux `mmap` and `sendfile` DMA, effectively policing the karma of system events.

### Orchestrated by the UWP

To drive these engines without trashing the CPU cache, QIHSE invented the **Unified Wire Protocol (UWP)**. UWP is a strictly binary, memory-aligned protocol that maps incoming network packets *directly* to internal C structs. It employs `pthread` detachment and `SO_RCVTIMEO` kernel enforcement to block Slowloris attacks, ensuring data traverses the network into the engines with blistering, zero-copy efficiency.

UWP routes these database families explicitly:

| Target | Engine | Current command |
| --- | --- | --- |
| `0x01` | Key-Value Store | Set |
| `0x02` | Vector DB | Upsert |
| `0x03` | Document Store | Insert JSON |
| `0x04` | Columnar Engine | Append float32 |
| `0x05` | Time-Series DB | Insert point |
| `0x06` | Graph Engine | Reserved target |
| `0x07` | Event Stream | Append event |

The QIHSE sync replication layer currently serializes KV set and vector set payloads over the internal cluster path while the remaining engines are served through UWP or their native APIs.

---

## Uncompromising Performance, Anywhere

QIHSE treats search like a low-level systems problem rather than a dashboard feature. 

The engine acts as a hierarchical memory laboratory: per-vector access tracking (`vectors.qtier`) allows hot/cold temperatures to automatically drive memory maintenance across Unified (UMA) and Heterogeneous (HMA) Memory Architectures. 

**And crucially, it degrades gracefully.** The build system natively supports AVX-512 and AVX2/FMA instructions for extreme parallel throughput. However, if your system lacks these features (like older Intel chips, ARM processors, or constrained VMs), QIHSE detects this at runtime and seamlessly falls back to highly optimized scalar math. **It works flawlessly on any system.**

> **⚠️ TEMPORARY INFRASTRUCTURE ADVISORY**
> Due to a recent "unfortunate incident" involving the primary testing laptop (we're totally blaming the NSA for this one 😉), direct access to NPU/GNA silicons and AVX-512 pipelines is currently unavailable. While these pathways are implemented, they are not currently fully tested, optimized, or fleshed out under the strict Omni-Test harness. A repair is currently planned for the laptop, so we will have these pathways fully remedied and verified soon! In the meantime, the engine correctly and automatically routes all execution to the fully validated AVX2/FMA and scalar pipelines.

---

## Explore the Ecosystem

To keep this showcase clean, all intensive code examples, API usage, and benchmark commands live in our detailed documentation suite:

- **[API Reference](docs/api/README.md)**: Comprehensive C API maps for Vector DB, UWP, KV Store, and Document components.
- **[Python Native SDK](sdks/python/README.md)**: Zero-overhead Python bindings utilizing CPython to expose the engine, proxies, and Supernatural Auth Gates directly to Python space.
- **[Persistence Model](docs/persistence/README.md)**: File formats, WAL structure, and engine durability.
- **[Performance Benchmarks](docs/benchmarks.md)**: Deep dive into the VectorReVamp stress tests, throughput stats, and multi-threaded engine durability compared to other databases.
- **[Onboarding & Building](docs/ONBOARDING.md)**: Instructions for compiling, running test suites, and executing benchmark harnesses (`make test-persist`, `make bench-micro`, etc.).
- **[Trinary Policy Rationale](docs/qmag-policy.md)**: The theory behind `qmag` candidate selection.

---

### Optional: Military-Grade Cell-Level Clearance

*Most users will never need to think about this feature—by default, QIHSE grants full access so you can build fast. If you don't need it, it stays completely out of your way.*

However, for those building intelligence, defense, or ultra-secure forensic systems, QIHSE natively supports **US / Five Eyes / SCI compartmentation** woven directly into the low-level data plane. Every single record can carry a Classification Boundary and SCI bitmask. 

This is not a gateway filter. The clearance check is the absolute **first mathematical operation** in the pipeline. Built with paranoia-level self-protections, if a user queries a key or vector they lack clearance for, the system executes an identical algorithmic path as if the data simply did not exist. There are zero timing leaks, and unauthorized users mathematically cannot deduce the existence of classified data. Even the most muscular network taps will see nothing but uniform algorithmic noise. 

**[Read the full Security Architecture deep dive here.](docs/security/README.md)**

### Immutable Audit Trail, CNSA 2.0 Integrity & Telemetry
QIHSE natively supports cryptographic logging for all security-relevant access and clearance modifications.
- **Stealth Integrity & CNSA 2.0 Lockdown:** To achieve CNSA 2.0 standard integrity checks, the engine stores an append-only, SHA-256 hash chain of the entire auth log state in a highly obfuscated camouflage file (`.DS_Store`). Every time the `qihse_auth.dat` log is modified, this stealth hash is updated. If an adversary tampers with the binary log, the engine will detect the hash mismatch immediately and violently lock down the entire execution process until a God-Mode Operator (Role 0) or Hardware-Token Analyst (Role 1) physically intervenes at the terminal to resume execution.
- **Silent Callout Webhook:** Every time non-UNCLASSIFIED data is accessed, a pure C native raw TCP socket fires a silent HTTP POST payload to `http://127.0.0.1:8080/callout`. This happens natively without spawning external `curl` or shell processes, leaving absolutely zero trace in process execution audits (like Sysmon or Auditd). If no webhook listener is configured, the callout simply drops into the void—normal users won't even notice the feature exists.
  - *Note:* You must update `qihse_audit.c` to point to your actual webhook listener URL and configure the expected data ingestion contract. The payload format sent is: `{"event":"classified_access", "user_id":<UID>, "classif":<LEVEL>, "sci":<COMPARTMENTS>}`.

---

## License and Use

QIHSE is licensed under **AGPL-3.0**. Read [LICENSE](LICENSE) before use.

Personal, research, and compliant self-hosted use is welcome under the license. Commercial, proprietary, closed-source, hosted, or derivative use requires written permission or a separate license first. Unauthorized commercial use, relicensing, removal of attribution, or repackaging outside the license is not permitted and will be pursued to the maximum extent of the law.
