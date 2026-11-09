# W12.6 offline shadow and canary gate

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Status: **offline research only, promotion refused** (2026-11-06).
No production query selector, switch, canary traffic, or deployment has changed.
The probe operates on a temporary standalone QTQS sidecar and caller-owned
FP32 vectors through the scoped W12.3 research API.

## Reproduce

Build libqihse.so in this checkout, then run:

    python3 benchmarks/scripts/qihse_w12_shadow_gate_test.py
    python3 benchmarks/scripts/qihse_w12_shadow_gate.py --output benchmarks/scripts/qihse_w12_shadow_pilot.json

The Python runner compiles qihse_w12_shadow_probe.c against the standalone
scalar codec/sidecar and the local libqihse. It creates a private temporary
QIHSE_DATA_DIR and one temporary derived QTQS file. All classified-capable
sidecar reads have a live authenticated user context. The authoritative
vectors are explicit synthetic arrays in the probe, never the configured
QIHSE store. The JSON records source and library hashes, Git state, host
ISA flags, raw latency samples, fixture shape and policy outcome.
Three policy/format unit tests passed, and a separate ASan+UBSan build of the
C probe exited successfully with leak detection disabled in this environment.
Sanitizer timings are excluded from the performance table.

## Predeclared decision

The gate is default-off. It returns a decision document and never enables a
route. A promotion-eligible *review* requires all of:

1. Recall@1 at least 0.99 against exhaustive authorized FP32 results.
2. Either at least 1.5x end-to-end throughput at equivalent recall, **or**
   at least 2x derived-index byte reduction against a measured existing
   index baseline with p95 latency no worse than 1.05x exact. The byte
   branch is unavailable in this pilot because no such baseline was measured.
   FP32-plus-sidecar overhead is reported separately.
3. Derived-only rollback verified.
4. Real authorized corpus, coherent source-generation transaction fence,
   production adapter with strict-exact mode, low/high negative tests in CI
   for every adapter, crash/recovery rehearsal, and isolated repeatable
   latency evidence.

The third-party paper cannot satisfy QIHSE-specific evidence gates. All six
non-fixture evidence gates remain false in the checked-in pilot, and the
existing-index byte baseline is absent. A synthetic pass alone cannot
produce a promotion decision.

## Measured offline pilot

The fixed fixture contains three 2D FP32 vectors: two low-clearance rows in
tenant 42/project 7 and one higher-classification, foreign-SCI row. A low
analyst queries three vectors with K=1, candidate pool=2, five repetitions,
MSE 3-bit profile with seed 0x1206. The source callbacks authorize
tenant/project, classification and SCI before exact scoring. The same
exhaustive callback supplies the FP32 oracle. Results:

| Measure | Observed |
| --- | ---: |
| Recall@1 vs authorized exact | 3/3 (1.000) |
| Sidecar p50 / p95 | 0.072 / 0.128 ms |
| Exact fallback p50 / p95 | 0.042 / 0.110 ms |
| Mean-throughput ratio, sidecar / exact | 0.569 |
| Derived QTQS bytes | 479 |
| Authoritative FP32 payload bytes | 24 |
| Combined bytes | 503 |
| FP32-plus-sidecar overhead ratio | 20.96x FP32 payload |
| Existing-index baseline for byte gate | unmeasured |
| Exact queries after derived deletion | 3/3 |
| Policy decision | refuse |

These 15 samples per path are timing smoke evidence, not a tail-latency
benchmark. They include authenticated API calls, temporary file open,
profile comparison, query preparation and callbacks. Startup/build costs
are excluded. The combined storage is far larger than FP32 alone for this
tiny profile, and the sidecar path was slower. The JSON keeps every raw
timing sample; later runs may shift with host load. The thresholds and
evidence gates were fixed in the runner before this measurement.

Rollback calls unlink on **only** the derived file, checks the caller-owned
FP32 bytes remain identical, then runs all three queries through the
authenticated exact fallback. The temporary directory is removed afterward.
This is a local rollback smoke test, not a crash/restart or live cutover
rehearsal. A stable authoritative generation fence, real/scoped AIMEM
corpora, broader dimensions/seeds, p99 and failures under concurrent source
mutation remain open before any W12.6 canary or promotion.
