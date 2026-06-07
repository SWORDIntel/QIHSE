<p align="center">
  <img src="docs/QIHSE.png" alt="QIHSE logo" width="720">
</p>
<div align="center">

## Quantum-Inspired Hilbert Space Expansion Search

### If you need a database—any database, for any workload, at any scale—this is your endgame. Vector, Graph, KV, Document, Time-Series, Columnar, FTS, and Event Stream—unified under one zero-copy protocol and one relentless standard of exactness.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE)
[![C](https://img.shields.io/badge/Core-C-00599C?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Multi-Modal](https://img.shields.io/badge/Multi--Modal-8%20Engines-darkgreen)]()
[![Security](https://img.shields.io/badge/Security-Cell--Level%20Clearance-red)]()

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

1. **The Vector DB**: An exactness-first `float32` core. Accelerators like Trinary signatures (`qtri`/`qmag`), INT8 quantization, and sparse indexing act as execution layers that rapidly reduce the search space before an authoritative, exact rerank.
2. **The Key-Value Store**: An O(k) Trinary Trie memory engine backed by native LSM-Trees and SSTable persistence for instantaneous, lock-free lookups.
3. **The Document Store**: A JIT-compiled JSON document engine that translates hot access patterns directly into executing bytecode.
4. **The Time-Series DB**: Lock-free ingress buffers paired with Gorilla XOR bit-packing to absorb massive temporal telemetry streams effortlessly.
5. **The Columnar Engine**: An AVX-accelerated OLAP backend utilizing strided OS page alignments for massive aggregations and Run-Length Encoding sweeps.
6. **The Graph Engine**: Multi-hop traversal routed dynamically via Anchor and HNSW algorithms.
7. **The FTS Engine**: Zero-copy lexical tokenization with native BM25 scoring for pinpoint full-text search.
8. **The Event Stream**: A raw, append-only log engine bypassing user-space entirely via Linux `mmap` and `sendfile` DMA.

### Orchestrated by the UWP

To drive these engines without trashing the CPU cache, QIHSE invented the **Unified Wire Protocol (UWP)**. UWP is a strictly binary, memory-aligned protocol that maps incoming network packets *directly* to internal C structs. It employs `pthread` detachment and `SO_RCVTIMEO` kernel enforcement to block Slowloris attacks, ensuring data traverses the network into the engines with blistering, zero-copy efficiency.

---

## Uncompromising Performance, Anywhere

QIHSE treats search like a low-level systems problem rather than a dashboard feature. 

The engine acts as a hierarchical memory laboratory: per-vector access tracking (`vectors.qtier`) allows hot/cold temperatures to automatically drive memory maintenance across Unified (UMA) and Heterogeneous (HMA) Memory Architectures. 

**Battle-Tested Scale:** The QIHSE candidate pruning layers (including Trinary signatures and KV LSM paths) are continually validated by autonomous generative test harnesses. The core engines reliably process continuous 100,000+ payload iterations with a 100% success rate, completely memory-stable.

**And crucially, it degrades gracefully.** The build system natively supports AVX-512 and AVX2/FMA instructions for extreme parallel throughput. However, if your system lacks these features (like older Intel chips, ARM processors, or constrained VMs), QIHSE detects this at runtime and seamlessly falls back to highly optimized scalar math. **It works flawlessly on any system.**

---

## Explore the Ecosystem

To keep this showcase clean, all intensive code examples, API usage, and benchmark commands live in our detailed documentation suite:

- **[API Reference](docs/api/README.md)**: Comprehensive C API maps for Vector DB, UWP, KV Store, and Document components.
- **[Persistence Model](docs/persistence/README.md)**: File formats, WAL structure, and engine durability.
- **[Onboarding & Building](docs/ONBOARDING.md)**: Instructions for compiling, running test suites, and executing benchmark harnesses (`make test-persist`, `make bench-micro`, etc.).
- **[Trinary Policy Rationale](docs/qmag-policy.md)**: The theory behind `qmag` candidate selection.

---

### Optional: Military-Grade Cell-Level Clearance

*Most users will never need to think about this feature—by default, QIHSE grants full access so you can build fast. If you don't need it, it stays completely out of your way.*

However, for those building intelligence, defense, or ultra-secure forensic systems, QIHSE natively supports **US / Five Eyes / SCI compartmentation** woven directly into the low-level data plane. Every single record can carry a Classification Boundary and SCI bitmask. 

This is not a gateway filter. The clearance check is the absolute **first mathematical operation** in the pipeline. If a user queries a key or vector they lack clearance for, the system executes an identical algorithmic path as if the data simply did not exist. There are zero timing leaks, and unauthorized users mathematically cannot deduce the existence of classified data. 

**[Read the full Security Architecture deep dive here.](docs/security/README.md)**

---

## License and Use

QIHSE is licensed under **AGPL-3.0**. Read [LICENSE](LICENSE) before use.

Personal, research, and compliant self-hosted use is welcome under the license. Commercial, proprietary, closed-source, hosted, or derivative use requires written permission or a separate license first. Unauthorized commercial use, relicensing, removal of attribution, or repackaging outside the license is not permitted and will be pursued to the maximum extent of the law.
