# W11.6 early combined contention probe

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

This is a small, reproducible starting point for W11.6, not its acceptance test. It runs four threads against one authenticated public KV store: two concurrent stock reservations, finding-record ingestion, and scoped memory writes with exact-key retrieval. The two reservation threads use single-key compare-and-set; the finding and memory records use classification 5. A separate classification-0 guest must be unable to read either protected record type.

## Run

From the repository root:

```sh
bash benchmarks/w11_combined_early.sh 64 20261106 > build/w11_combined_early.json
python3 -m json.tool build/w11_combined_early.json >/dev/null
```

The first argument is logical operations per worker (1–100000); the second is a nonzero 64-bit input seed. The runner builds `libqihse.so` with the repository Makefile and compiles `benchmarks/w11_combined_early.c` with `-O2 -Wall -Wextra`. It creates an isolated temporary data directory under `build/`, removes it on exit, and measures only the workload, excluding build and setup. The JSON records input seed, workload size, machine architecture, online core count, physical RAM, elapsed time, successful operations, expected stock rejections, errors, throughput, and p50/p95/p99 operation latency. Latencies use `CLOCK_MONOTONIC` and the nearest-rank percentile. The seed controls memory key selection; thread scheduling and timings are intentionally not claimed to be deterministic.

The exit code is nonzero if any operation errors, the final stock cannot be accounted for, a finding is missing or altered on readback, or a low-clearance read discloses protected data. The two stock workers make `2 × ops` reservation attempts against `ops` initial units; exactly `ops` must succeed. A finding record is checked by authenticated readback for every generated ID.

## Measured smoke, 2026-11-06

One local smoke run used 16 operations per worker and seed 12345 on x86_64, 40 online cores, and 118,180,769,792 bytes physical RAM. The workload phase took 0.103 seconds. Stock CAS had 16 successful reservations and 16 expected sold-out results, with p95 102,059 µs. Finding ingestion and exact-key memory each completed 16 operations without errors. All three invariants passed. This is a smoke result on a mixed-purpose host, not a controlled latency baseline or evidence for the W11.0 numerical budgets.

## Coverage boundaries

- Inventory covers only one-key stock CAS. It does not write orders, reservations, or outbound-event intent atomically.
- Findings cover labeled record ingestion and ID readback. Binary blobs, version/provenance links, and cross-model atomicity are not exercised.
- Memory covers authenticated exact-key reads and writes. It does not exercise semantic search, embeddings, recall@10, or an index rebuild.
- No node restart, partition, storage fault, slow-storage profile, backup/restore, historical consistency check, or recovery-point measurement is included.
- The scale is a configurable smoke size. It does not meet the 1,000,000-record or 30-minute W11.0 reference workload.

The subsequent W11.6 harness should replace these simplified operations with the supported public SQL, blob, provenance, and AIMEM workflows as their guarantees land, then add a deterministic fault controller and isolated authenticated restore. Each new adapter path needs a low-clearance/high-data negative test under `AGENTS.md`.
