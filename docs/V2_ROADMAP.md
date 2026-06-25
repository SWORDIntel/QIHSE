# QIHSE 2.0 Roadmap

QIHSE 2.0 pushes the boundaries of performance, security, and distributed resilience. Building on CNSA 2.0 compliance, Trinary Logic memory structures, and hardware-accelerated backends, the V2 roadmap advances toward a zero-trust, edge-native, post-quantum architecture.

## 1. eBPF / XDP Kernel Bypass
**Status: In Progress (experimental)**
**Objective:** Sub-microsecond latency via NIC-level packet processing.

*   [x] **AF_XDP infrastructure:** `qihse_af_xdp_init/poll/teardown` implemented with full UMEM and ring buffer setup (`src/networking/qihse_af_xdp.c`)
*   [x] **io_uring integration:** XDP socket polled via `io_uring_prep_poll_add` in the PG wire event loop
*   [x] **eBPF kernel classifier:** `src/networking/qihse_xdp_kern.c` — classifies packets by TCP port (5432 PG / 7432 UWP) and UWP magic bytes (`QIHSE`), drops malformed packets at the driver level, redirects via XSKMAP
*   [x] **XSKMAP population:** AF_XDP socket registered in the kernel map on init so `XDP_REDIRECT` lands in userspace
*   [x] **Configurable ports:** `qihse_af_xdp_set_port()` updates kernel BPF port map from userspace at runtime
*   **Pending:** Zero-copy payload routing from AF_XDP callback into the full UWP/PG protocol handlers (currently logs fast-path events; full handler dispatch is the next step)

Build:
```bash
make xdp-kern   # compile eBPF object with clang -target bpf
make all        # userspace library includes AF_XDP support
```

## 2. WebAssembly (WASM) Sandbox Integration
**Objective:** Safely execute user-defined multi-tenant logic (UDFs) at the edge.

*   [x] **Edge Compute Extensions:** Deterministic WASM runtime integrated into the `tractable` execution engine
*   [x] **Memory Isolation:** Tenant-supplied queries cannot escape into core database memory (HMA/UMA regions)
*   [x] **Language Agnostic:** UDFs can be compiled from Rust, C++, AssemblyScript, or Go

## 3. Full Post-Quantum Cryptography (CNSA 2.0)
**Status: Complete**
**Objective:** All cryptographic primitives resistant to quantum adversaries.

*   [x] **ML-KEM-1024 key encapsulation:** Container at-rest encryption, TLS 1.3 key exchange group (`mlkem1024`)
*   [x] **ML-DSA-87 signatures:** Audit log integrity chain, container manifests, Raft WAL entry signing
*   [x] **AES-256-GCM:** Symmetric encryption for all container payloads
*   [x] **SHA-384:** Hash function throughout audit chain
*   [x] **FIPS 140-3 validated module:** `openssl-provider-fips` loaded automatically at startup via `qihse_pqc_init_providers()`
*   [x] **TLS 1.3 enforcement:** PG wire server enforces `TLS_AES_256_GCM_SHA384` cipher suite + ML-DSA-87 certificates
*   [x] **Native key generation:** `./qihse_keygen [output-dir]` (C, no shell dependency)
*   **Pending:** Full Raft RPC transport (broadcast + receive) with ML-DSA-87 verified messages — signing is wired in; the skeleton broadcast transport is the remaining work

## 4. Decentralized P2P Gossip & Resilience
**Objective:** Cluster survival in adversarial, disconnected, or dynamically shifting network topologies.

*   [x] **Epidemic Routing:** Hybrid Raft + SWIM-based P2P gossip for node discovery and health checking
*   [x] **CRDT Integration:** Conflict-free Replicated Data Types for offline-write and seamless merge on reconnection
*   [x] **Trinary Merkle DAGs:** Proprietary Trinary Logic engine used for high-efficiency state reconciliation across P2P mesh
