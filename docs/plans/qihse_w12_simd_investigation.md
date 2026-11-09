# W12.4 CPU SIMD and Vulkan investigation

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

**Status: measurement only.** W12.4 remains optional and follows scalar correctness. This probe compiles the experimental W12.1 numerical reference directly; it does not benchmark a production candidate index, authenticated filtering, FP32 rerank, host/device transfer, or a Vulkan kernel.

## Reproduce

From a checkout containing the W12.1 codec:

```sh
python3 benchmarks/scripts/qihse_w12_simd_probe.py > build/qihse_w12_simd_probe.json
python3 -m json.tool build/qihse_w12_simd_probe.json >/dev/null
```

The script builds `benchmarks/scripts/qihse_w12_simd_probe.c` against `quantization/src/qihse_turboquant.c` and `qihse_turboquant_tables.c` in a temporary directory. It runs PRODUCT 4-bit scalar quantization with fixed rotation/projection seeds 42/43 and deterministic finite FP32 vectors at dimensions 128, 384, and 768. It reports code/matrix bytes, one cold profile setup, repeated encode and direct-code dot score mean time, one query preparation, and a score checksum. Each run is single-process and sequential; there is no CPU pinning, warmup distribution, or controlled storage/thermal isolation. Profile construction is included separately because its dense QR reference is O(d³); encode/query transforms are O(d²), while prepared scoring is O(d).

Two compiler configurations use GCC's scalar `-O2 -fno-tree-vectorize` and `-O3 -march=native` on the identical reference source. The latter permits compiler auto-vectorization and native instructions; it is **not** a hand-written SIMD implementation. Exact build flags, compiler version, source revision/dirty state, CPU features, and Vulkan device names are emitted in JSON. Values below are from one host run on 2026-11-06 and are not a performance claim for other machines.

## Observed host and costs

Host: two Intel Xeon E5-2470 v2 sockets, 40 logical CPUs, x86_64; GCC 14.2.0. The visible feature list includes SSE4.2 and AVX, but no AVX2 or FMA. The existing FP32 CPU distance dispatcher has AVX1 and scalar routes; those routes are separate from W12.1. Vulkan enumerates two NVIDIA GeForce GTX 750 devices and llvmpipe. `nvidia-smi` reports 2048 MiB per GTX 750. Merely enumerating a device does not establish usable W12 compute throughput or transfer behavior.

| Dimensions | Code bytes | Matrix bytes | Scalar profile setup ms | Scalar encode µs | Scalar query prep µs | Scalar score ns | Native encode µs | Native score ns |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 128 | 144 | 262,144 | 111.6 | 367.8 | 78.9 | 6,867 | 372.6 | 6,726 |
| 384 | 304 | 2,359,296 | 595.5 | 4,313.6 | 752.4 | 16,665 | 4,318.3 | 18,539 |
| 768 | 544 | 9,437,184 | 6,284.0 | 20,766.0 | 3,111.8 | 31,507 | 23,696.6 | 34,632 |

The score checksum matched between compiler configurations at each dimension. This single run does not show a useful compiler-native speedup at 384 or 768 dimensions. It also cannot determine whether a dedicated SSE/AVX kernel would help: the current scorer validates and unpacks each code, then performs scalar numerical work, so profiling must separate validation/unpack from arithmetic before designing a lane layout. Dense profile setup and encode cost dominate one-off operations at higher dimensions. A future candidate index could amortize profile setup and encode over many queries, but that amortization was not measured here.

## W12.4 decision

- Keep scalar W12.1 as the reference and do not add a production SIMD dispatch from this evidence. After W12.1 correctness and a W12.2 authenticated candidate route, measure repeated scoring of resident code batches with p50/p95/p99 and recall/error checks. Compare an explicit SSE/AVX kernel against the same scalar path on hosts with and without AVX2, including odd-dimensional tails and device-loss fallback.
- Treat Vulkan as unproven. The <=1.2 GB decimal budget can hold 1,000,000 *raw* 768-dimensional codes at 544,000,000 bytes, but excludes index, staging, profile, and allocator overhead. At 1536 dimensions the raw 5-bit codes plus 64-byte header are about 1.024 GB decimal, leaving little budget. These are arithmetic estimates, not allocation measurements. Measure batch upload, execution, download, device memory, and end-to-end query latency before any Vulkan route or memory-budget claim.
- No accelerator is mandatory. Device absence or loss must fall back to the scalar CPU path without changing authorization, candidate-set semantics, or exact FP32 rerank.
