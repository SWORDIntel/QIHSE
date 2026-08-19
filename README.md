<p align="center">
  <img src="docs/QIHSE.png" alt="QIHSE logo" width="720">
</p>
<div align="center">

## Quantum-Inspired Hilbert Space Expansion Search

### If you need a database—any database, for any workload, at any scale—this is your endgame. Vector, Graph, KV, Document, Time-Series, Columnar, FTS, and Event Stream—unified under one zero-copy protocol and one relentless standard of exactness.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-black.svg)](LICENSE) ![C](https://img.shields.io/badge/Core-C-00599C?logo=c&logoColor=white) ![Python](https://img.shields.io/badge/SDK-Python-3776AB?logo=python&logoColor=white) ![Rust](https://img.shields.io/badge/SDK-Rust-DEA584?logo=rust&logoColor=white) ![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black) ![SIMD](https://img.shields.io/badge/SIMD-AVX%20%7C%20AVX2%20%7C%20AVX--512-00599C) ![eBPF / XDP](https://img.shields.io/badge/Networking-eBPF%20%2F%20XDP-00599C?logo=linux) ![Multi-Modal](https://img.shields.io/badge/Multi--Modal-8%20Engines-darkgreen) ![CNSA 2.0 Compliant](https://img.shields.io/badge/Cryptography-CNSA%202.0-brightgreen.svg) ![FIPS 140-3](https://img.shields.io/badge/Hardware-FIPS%20140--3-brightgreen.svg) ![Dependencies](https://img.shields.io/badge/Dependencies-Zero-success) ![Security Audit](https://img.shields.io/badge/Security-Audited%20%26%20Hardened-success?logo=shield)

</div>

---

## Core Doctrine

**QIHSE** is a native C database ecosystem built around a single, uncompromising rule:

> **Approximations hunt the targets. Exact math dictates the truth.**

Modern systems frequently fragment under the weight of stitching together half a dozen specialized databases—a vector DB for AI, Redis for caching, PostgreSQL for documents, ClickHouse for OLAP, and Kafka for events. QIHSE eliminates this operational friction. It is a multi-modal database engine combining **eight distinct storage engines and a transparent SQLite VFS replacement** within the exact same process space and memory hierarchy.

Data traverses from kernel-bypass network interfaces straight into SIMD computation registers with zero intermediate copies.

---

## Database Surface at a Glance

| Family | UWP Target | API Surface | Storage Core & Capabilities |
|---|---|---|---|
| **Vector DB** | `0x02` | `qihse_vector_db_*` | Exact `float32` reranking with Trinary signature (`qtri`/`qmag`) filtering, multi-precision quantization (`FP16`, `FP8`, `INT8`, `INT4`), and HNSW graph indexing. |
| **Key-Value Store** | `0x01` | `qihse_kv_*` | $O(k)$ Trinary Trie in-memory engine backed by native LSM-Trees and SSTable persistence. |
| **Document Store** | `0x03` | `qihse_document_*` | JSON document engine with JIT-compiled query path evaluation. |
| **Time-Series DB** | `0x05` | `qihse_timeseries_*` | Lock-free ingress buffers with Gorilla XOR delta-of-delta bit-packing. |
| **Columnar Engine** | `0x04` | `qihse_column_*` | AVX-accelerated OLAP backend with strided OS page alignment and RLE sweeps. |
| **Graph Engine** | `0x06` | `qihse_graph_*` | Dual Anchor and HNSW multi-hop relationship resolution. |
| **Full-Text Search** | Native | `qihse_fts_*` | Zero-copy lexical tokenization with native BM25 relevance scoring. |
| **Event Stream** | `0x07` | `qihse_event_*` | Append-only log bypassing userspace via Linux `mmap` / `sendfile` DMA with SHA-384 frame deduplication. |
| **SQLite VFS** | Native | `qihse_sqlite_vfs` | Drop-in SQLite storage replacement routing database pages through Black Hole KV and Marmalade Event Stream. |

---

## Architecture

```mermaid
flowchart TB
    %% Client & Network Ingress
    subgraph INGRESS["Network Ingress & Protocol Layer"]
        direction TB
        XDP["eBPF / AF_XDP Driver<br/>(Kernel-Bypass Raw Sockets)"]
        UWP["UWP Binary Dispatcher<br/>(Zero-Copy Target 0x01–0x07)"]
        SQL_API["SQLite VFS Interface<br/>(file:*.db?vfs=qihse)"]
        AUTH["CNSA 2.0 Security Guard<br/>(Cell-Level Auth & Constant-Time Rejection)"]
        
        XDP --> UWP
        SQL_API --> AUTH
        UWP --> AUTH
    end

    %% Unified Storage Engine Matrix
    subgraph ENGINES["Multi-Modal Engine Matrix"]
        direction TB
        
        subgraph VEC_PLANE["Vector & Semantic Search"]
            VDB["Vector DB Core<br/>(Exact float32 Reranker)"]
            QMAG["Trinary Filter<br/>(qtri / qmag Signatures)"]
            HNSW["HNSW Graph Index<br/>(Multi-Hop Traversal)"]
            QUANT["Quantization Pipeline<br/>(FP16 / FP8 / INT8 / INT4)"]
            
            HNSW --> QMAG
            QUANT --> QMAG
            QMAG --> VDB
        end

        subgraph REL_PLANE["Relational & Structured Engines"]
            KV["Black Hole KV Store<br/>(Trinary Trie + MemTable)"]
            DOC["Document Store<br/>(JIT Bytecode Evaluator)"]
            COL["Columnar Engine<br/>(AVX OLAP & RLE Sweeps)"]
            FTS["BM25 Search Index<br/>(Zero-Copy Tokenizer)"]
            GRAPH["Graph Engine<br/>(Anchor Traversal)"]
        end

        subgraph STREAM_PLANE["Stream & Telemetry Engines"]
            TS["Time-Series Engine<br/>(Gorilla XOR Bit-Packing)"]
            EVT["Marmalade Event Stream<br/>(DMA Append-Only Log)"]
        end
    end

    %% Memory & Compute Acceleration
    subgraph COMPUTE_MEM["Compute Acceleration & Memory Subsystem"]
        direction TB
        
        subgraph MEMORY["Hierarchical Memory (UMA / HMA)"]
            TIER["Access Tiering Controller<br/>(vectors.qtier Hot/Cold)"]
            NUMA["NUMA-Aware Allocator<br/>(HugePages / DMA Ring Buffers)"]
        end

        subgraph SIMD_DISPATCH["Hardware Execution Dispatch"]
            CPUID["Runtime CPUID Arbiter"]
            AVX512["AVX-512 / AMX / VNNI<br/>(512-bit Vector Units)"]
            AVX2["AVX2 / FMA<br/>(256-bit SIMD)"]
            SCALAR["Scalar & AVX1 Fallback<br/>(Bit-Exact Portability)"]
            
            CPUID --> AVX512
            CPUID --> AVX2
            CPUID --> SCALAR
        end
    end

    %% Persistence Subsystem
    subgraph PERSIST["Durable Persistence Layer"]
        direction LR
        SST["SSTable Disk Spooler<br/>(LSM Multi-Level)"]
        WAL["Marmalade QWAL<br/>(SHA-384 Torn-Tail Recovery)"]
        PQC_STORE["Encrypted Storage Container<br/>(.qdb ML-KEM Encapsulation)"]
    end

    %% Cross-Subsystem Interconnects
    AUTH --> VEC_PLANE
    AUTH --> REL_PLANE
    AUTH --> STREAM_PLANE

    VEC_PLANE <--> TIER
    REL_PLANE <--> TIER
    STREAM_PLANE <--> TIER
    TIER <--> NUMA

    VEC_PLANE --> CPUID
    COL --> CPUID

    REL_PLANE --> SST
    STREAM_PLANE --> WAL
    SQL_API --> WAL
    KV --> SST
    SST --> PQC_STORE
    WAL --> PQC_STORE
```

---

## Hardware Execution & Graceful Fallback

QIHSE treats performance as a low-level systems problem:

- **Vectorized SIMD Core**: Vector distance calculations and columnar scans vectorize across 512-bit or 256-bit registers (AVX-512, AVX2, FMA).
- **Graceful CPUID Routing**: If host hardware lacks AVX2 or AVX-512 (e.g. legacy Xeon nodes, constrained VMs, or ARM), QIHSE detects this at boot and dynamically routes execution through verified AVX1/SSE4.2 or scalar pipelines.
- **Hierarchical Memory Tiering**: Real-time access frequency tracking (`vectors.qtier`) automatically manages hot and cold pages across Unified (UMA) and Heterogeneous (HMA) memory.
- **Zero-Copy eBPF / AF_XDP**: Database ingress packets bypass standard Linux TCP/IP overhead via custom eBPF socket routing.

---

## Build & CLI Launcher

```bash
# Build the native library and full test harness
make clean && make

# Run the test suite
make test

# Launch the unified management CLI
./qihse status
./qihse build
./qihse test
./qihse db --help
```

---

## Documentation & Manuals

All technical specifications, integration manuals, API definitions, and code examples are documented in [`docs/`](docs/):

- 📖 **[System Architecture & Engine Overview](docs/architecture/system_overview.md)**: In-depth technical guide covering all 8 engines, UWP layout, and SIMD dispatch.
- 🗄️ **[SQLite VFS Implementation Plan](docs/qihse_sqlite_vfs_plan.md)**: Architectural blueprint and page-cache integration model.
- 📚 **[API Reference](docs/api/)**: Comprehensive C API manuals for all database interfaces.
- 🐍 **[Python SDK Manual](sdks/python/)**: Native CPython bindings and integration guide.
- 🦀 **[Rust SDK Manual](rust/qihse-rs/)**: FFI safe wrappers (`KVStore`, `VectorDB`, `TrinaryTrie`).
- 🔒 **[Security & Clearance Architecture](docs/security/README.md)**: Cell-level compartmentation and CNSA 2.0 PQC encryption.
- 🛡️ **[Security Audit & Hardening Report](docs/security/hardening-report.md)**: Results from static analysis, memory audit, and file I/O hardening.
- ⚡ **[Performance Benchmarks](docs/benchmarks/benchmarks.md)**: Stress tests, throughput comparisons, and latency profiles.

---

## License

QIHSE is licensed under **AGPL-3.0**. Read [LICENSE](LICENSE) before use.
