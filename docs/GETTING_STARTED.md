# Getting Started with QIHSE

> **Status: implemented** — the launcher commands described here exist in
> `qihse` / `qihse_launcher.py` (`dev-setup`, `build`, `test`, `status`,
> `isa-info`, `db`, `server`, `python`, `bench`) and were verified on this
> branch (2026-09-26), and the Makefile targets they wrap are present.
> Exception: `./qihse demo` currently fails (module mismatch — see
> [OPERATIONS.md §6](OPERATIONS.md#6-known-issues-and-workarounds)); use the
> Python example below instead. For every target, daemon, flag, and env var,
> read [OPERATIONS.md](OPERATIONS.md).

This guide covers the shortest path from a fresh checkout to a working local QIHSE build.

For the project overview, start with the [root README](../README.md). For subsystem details, use the [documentation hub](README.md).

## 1. Check the toolchain

QIHSE is a native C/C++ project targeting Linux. The build also integrates Python, OpenSSL, liburing, LuaJIT, eBPF/XDP, SQLite, nlohmann-json, and post-quantum cryptography components.

The complete `make test TEST_JOBS=32` workflow builds the Redis adapter and
CodeGraph as well as the shared library. Their development dependencies include
ONNX Runtime (`onnxruntime/onnxruntime_c_api.h` and `libonnxruntime`), JSON-C and
libzstd. Tree-sitter's required Unicode headers are already vendored; its build
does not require a system ICU installation.
The Rust SDK TLS tests also require `rustc` and `cargo` on `PATH` when running
the complete suite.

SQL English full-text analysis additionally needs the **runtime** library
`libstemmer.so.0d` (Debian/Ubuntu package `libstemmer0d`) in the loader path of
every process using it, including chroot/container runtimes. It is loaded with
`dlopen`, so a successful link or `ldd libqihse.so` is not sufficient evidence.
The analyzer is bounded ASCII English/Snowball: input/output are limited to
4096 bytes and tokens to 256 bytes, not complete PostgreSQL text-search parity.
Non-ASCII/oversized input and missing library/symbols fail closed; a missing
library fails even for empty input. It does not silently switch to another analyzer.

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

The normal build automatically selects supported CPU instruction paths from
the host CPU and verifies them before compiling anything:

```bash
./qihse build
```

Equivalent Makefile workflow:

```bash
make           # runs the mandatory ISA check, then builds
make check-isa # report the resolved ISA matrix only
```

### Dependency discovery and local prefixes

LuaJIT headers and linker flags come from the `luajit` pkg-config module.
`PKG_CONFIG` selects the executable for this discovery; `LUAJIT_CFLAGS` and
`LUAJIT_LIBS` can override its results, including for a prepared dependency
prefix outside the system directories. The build uses `-lluajit-5.1` as the
linker fallback when that module is unavailable; provide `LUAJIT_CFLAGS`
explicitly if the headers also need a nonstandard include directory. The
`lib-ctypes` target is a compatibility alias for `lib`: both build the same
canonical `libqihse.so`, including its existing CPython exports. They use these
settings and the existing `PYTHON_INCLUDES` / `PYTHON_LDFLAGS` overrides.

For example, after installing dependencies into a prefix containing
`include/`, `lib/` and `lib/pkgconfig/`, export the paths before building:

```bash
qihse_dep_prefix="$(pwd)/build/deps"
qihse_dep_lib="$qihse_dep_prefix/lib"
export PKG_CONFIG_PATH="$qihse_dep_lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CPATH="$qihse_dep_prefix/include${CPATH:+:$CPATH}"
export LIBRARY_PATH="$qihse_dep_lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$qihse_dep_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_RUN_PATH="$qihse_dep_lib${LD_RUN_PATH:+:$LD_RUN_PATH}"
make test TEST_JOBS=32
```

For an extracted Debian package tree, select its `usr/` prefix and
`lib/$(gcc -print-multiarch)` library directory instead. Its pkg-config files
must describe that prefix, or be relocated with `PKG_CONFIG_SYSROOT_DIR`.
Include every nonstandard dependency library directory in the runtime paths.
`LD_RUN_PATH` supplies a run path when the linker command has no explicit
`-rpath`; this lets the newly linked shared library find its dependencies even
in test recipes that set `LD_LIBRARY_PATH=.`. It does not change an existing
binary, so relink after changing these paths.

Use these exported dependency variables rather than replacing the complete
`CFLAGS` or `LDFLAGS` values. The suite starts nested make processes and removes
their inherited make jobserver flags; ordinary Makefile assignments are then
reapplied, while the documented `?=` overrides and exported search paths remain
available. `QIHSE_DEPS_PREFIX` separately selects where the vendored liboqs and
OpenSSL provider are installed.

**Build on each machine natively.** Every per-ISA SIMD kernel (AVX2,
AVX-512, AVX-VNNI, AMX, F16C) is compile-time gated behind the resolved
build flags, so a binary contains only the instruction set of the machine it
was built on. Deploying a binary built on a newer CPU to an older node can
trap on instructions that node lacks, so build on the target machine with
the native helper:

```bash
./qihse build-native   # = ./scripts/build-native.sh --auto
```

`build-native.sh --auto` detects all extended ISAs (AVX, F16C, AVX2, AVX-512
F/DQ/BW/VL, AVX-VNNI, AMX), refuses to force an ISA the host does not
advertise, and passes the resolved set to `make` together with
`-march=native`.

The build hard-fails at parse time if an enabled ISA is not advertised by
the build host (e.g. `make QIHSE_ENABLE_AVX2=1` on an Ivy Bridge host).
Cross-builds that intentionally target a different CPU may opt out with
`QIHSE_ISA_SKIP_HOST_CHECK=1`. `./qihse isa-info` shows the
runtime-detected execution paths.

A full rebuild is no longer required after editing a header: object rules carry
`-MMD -MP` and the generated `.d` files are included by the Makefile, so a
header change rebuilds exactly the objects that included it. `make clean && make`
still works when you want a from-scratch build (for example after changing
compiler flags or switching ISA paths), but it is not needed for a header edit.

Useful alternatives:

```bash
./qihse build-ctypes
./qihse build-tui
```

QIHSE keeps scalar and older-ISA fallbacks: kernels whose ISA is disabled at
compile time fall back to scalar (distance, dot-product, codecs) or to the
next-lower clone (`target_clones`), and the runtime dispatcher still selects
among what was compiled in. AVX2/AVX-512 are accelerators, not a requirement
for the entire codebase.

## 3. Run tests

The full suite includes PostgreSQL client interoperability and browser/WebAuthn
fixtures. Install their Python dependencies into a virtual environment from the
repository root, keeping any native dependency-prefix variables from §2 exported:

```bash
python3 -m venv build/test-venv
. build/test-venv/bin/activate
python -m pip install -r python/requirements-test.txt
make test TEST_JOBS=32
```

[The test requirements](../python/requirements-test.txt) include the existing
`python/requirements.txt` plus `psycopg2-binary`, `psycopg[binary]`, `asyncpg` and
`fido2`. They complement the native build dependencies above. Keep the virtual
environment active so the suite's `python3` subprocesses use those packages.

The launcher also runs the tests from that environment:

```bash
./qihse test
```

Security-sensitive protocol code has additional regression, sanitizer, concurrency, TLS, ACL, and fuzz coverage. See [Security](security/README.md) and the [August 2026 UWP audit](security/UWP_AUDIT_2026-08.md).

Building in a shared or dirty checkout is development work, not authorization
to replace an installed library. For staged installation, exact artifact
manifests, affected-consumer inventory and rollback/health gates, follow
[Operations §1.6](OPERATIONS.md#16-staged-installation-and-upgrade-gates).

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

Connect to a running node. Hardened nodes (`pqc_require`, i.e. any node
with replication or admin pins configured) reject cleartext clients — use
the QKP admin CLI with the pinned administrator identity:

```bash
qihse-admin-cli --host 127.0.0.1 --port 7100 \
    --node-id admin-t420 \
    --trusted-pub /etc/qihse/keys/qihse_dsa_pub.pem --ping
```

Non-hardened nodes accept redis-cli password AUTH (`REDISCLI_AUTH` from
the operator environment file).

## 5. Python

The repository contains native Python bindings and compatibility SDKs under [`sdks/python/`](../sdks/python/).

The launcher can start a Python environment with QIHSE importable:

```bash
./qihse python
```

(The `QihseDB()` hint it prints is stale — that class belongs to the native
extension under `sdks/python/`; the ctypes package exports `VectorDB`,
`KVStore`, `TimeSeriesDB`, and friends.)

A minimal vector example looks like this (verified):

```python
import numpy as np
import qihse

with qihse.VectorDB.create("./build/example-qihse", dims=128) as db:
    vectors = np.random.rand(100, 128).astype(np.float32)
    db.add_vectors(vectors, ids=list(range(100)))
    db.build_graph()   # required for the default GRAPH (HNSW) query mode
    results = db.search(vectors[0], k=10)
    print(results)
```

Run it with `PYTHONPATH=python LD_LIBRARY_PATH=. python3 example.py`. Without
`build_graph()`, search the exact path instead:
`db.search(vectors[0], k=10, mode=qihse.QueryMode.FLOAT32)`.

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
| Operate: run any make target, daemon, tool, or smoke drill | [Operations Manual](OPERATIONS.md) |
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
| Read the deep technical treatment | [Technical whitepaper v1.1](architecture/qihse_whitepaper_v1.1.md) |
