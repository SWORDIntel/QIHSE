# Getting Started with QIHSE

This guide covers the shortest path from a fresh checkout to a working local QIHSE build.

For the project overview, start with the [root README](../README.md). For subsystem details, use the [documentation hub](README.md).

## 1. Check the toolchain

QIHSE is a native C/C++ project targeting Linux. The build also integrates Python, OpenSSL, liburing, LuaJIT, eBPF/XDP, SQLite, and post-quantum cryptography components.

Run the built-in environment check first:

```bash
./qihse dev-setup
```

The launcher is the preferred entry point because it exposes the build, test, benchmark, database, server, and ISA-detection workflows in one place.

```bash
./qihse --help
./qihse status
./qihse isa-info
```

## 2. Build

The normal build automatically selects supported CPU instruction paths from the host CPU.

```bash
./qihse build
```

Equivalent Makefile workflow:

```bash
make clean && make
```

Useful alternatives:

```bash
./qihse build-ctypes
./qihse build-native
./qihse build-tui
```

QIHSE has scalar and older-ISA fallbacks; AVX2/AVX-512 are accelerators, not a requirement for the entire codebase. Build flags can also be overridden explicitly through the Makefile when testing a specific ISA path.

## 3. Run tests

```bash
./qihse test
```

or:

```bash
make test
```

Security-sensitive protocol code has additional regression, sanitizer, concurrency, TLS, ACL, and fuzz coverage. See [Security](security/README.md) and the [August 2026 UWP audit](security/UWP_AUDIT_2026-08.md).

## 4. Inspect the local build

```bash
./qihse status
./qihse version
./qihse check
```

The launcher can also start a test server or database-oriented CLI:

```bash
./qihse server
./qihse db --help
```

## 5. Python

The repository contains native Python bindings and compatibility SDKs under [`sdks/python/`](../sdks/python/).

The launcher can start a Python environment with QIHSE importable:

```bash
./qihse python
```

It can also run the bundled SDK demo:

```bash
./qihse demo
```

A minimal vector example looks like this:

```python
import numpy as np
import qihse

with qihse.VectorDB.create("/tmp/example-qihse", dims=128) as db:
    vectors = np.random.rand(100, 128).astype(np.float32)
    db.add_vectors(vectors, ids=list(range(100)))
    results = db.search(vectors[0], k=10)
    print(results)
```

QIHSE also exposes KV, document, time-series, full-text, graph, task-queue, and protocol-compatibility interfaces. See [Features](FEATURES.md) and [Compatibility](COMPATIBILITY.md).

## 6. Benchmarks

Run the general benchmark workflow with:

```bash
./qihse bench
```

The integrated QIHSE + KEYSTONE benchmark target is:

```bash
make bench-keystone-integrated
```

Do not treat benchmark numbers as portable constants. CPU generation, ISA selection, dataset shape, working-set size, compiler flags, and storage configuration all materially affect results. The methodology and recorded results live under [`docs/benchmarks/`](benchmarks/).

## 7. Where to go next

| Goal | Documentation |
|---|---|
| Understand the major subsystems | [Features](FEATURES.md) |
| See supported external protocols and compatibility layers | [Compatibility](COMPATIBILITY.md) |
| Understand architecture | [Architecture docs](architecture/) |
| Review SQL/query internals | [SQL engine](architecture/sql_engine.md) |
| Review transactions and MVCC | [Transactions & MVCC](architecture/transactions_mvcc.md) |
| Review graph/Cypher support | [Graph engine](architecture/graph_engine.md) |
| Review replication and backup | [Replication & backup](architecture/replication_backup.md) |
| Review operational protocols | [Operational protocols](architecture/operational_protocols.md) |
| Review security posture | [Security](security/README.md) |
| Review performance methodology | [Benchmarks](benchmarks/) |
| Read the deep technical treatment | [Technical whitepaper](architecture/qihse_whitepaper_v1.0.md) |
