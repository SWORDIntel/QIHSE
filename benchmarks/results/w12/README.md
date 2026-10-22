# W12.0 synthetic FP32 pilot evidence

This is a **partial baseline**, not a TurboQuant implementation, end-to-end
VectorDB benchmark, production authorization test, or promotion result.

- [Raw measurements](fp32-synthetic-pilot.json)
- [Audit, algorithm contract, exact scope and reproduction](../../../docs/plans/qihse_w12_baseline_audit.md)
- Tested local source commit: `d2d45720b1e96515552d8e95ea3026052e648133`, clean tree.
- Published source commit: `4d8a7f46fed61d79f714f4c2f8c4e43fcdf29459`.
- Both source trees: `15ea786c76e7e838e999e31f5e2cc340993b792f`, verified equal.
  The connector assigns its own commit identity. The JSON preserves the original
  tested Git SHA and source-file hashes; publication metadata is additive only.

## Configuration and results

Measured 2026-10-22 on the cloud Linux x86-64 workspace, reported CPU
AMD EPYC 9V74, compiler `cc (Debian 14.2.0-19) 14.2.0`. Runtime dispatch selected
AVX-512; the scalar variant is compiled without auto-vectorization/fast-math.
No target-user hardware was accessed. The shared host is not CPU-pinned.

- Seed 20261022; 256 rows; K=10; 8 unique queries; 3 warm timing repetitions.
- Dimensions 128, 384, 768, 1536; isotropic, anisotropic, clustered, duplicates,
  high-dynamic-range and sparse-sign synthetic families.
- 24 fixture configurations, 144 metric/path records, 3,456 timed calls.
- Cosine, dot and L2 similarity; exhaustive pool includes all 256 rows.
- All selected-score checks meet the predeclared scaled-error tolerance 2e-5.
  Largest observed scaled error: 2.8475147756369563e-6.
- **Retained numerical near-tie failure:** scalar cosine on clustered 1536d
  gives mean Recall@10 **0.9875** against the independent FP64 oracle; one of
  eight queries is **0.9**. Runtime-dispatched FP32 gives 1.0 for this case and
  therefore differs from scalar's top-K. Every other metric/path/configuration
  gives mean oracle Recall@K 1.0 in this pilot. This is not approximate-index
  recall, and exact reranking does not erase numerical or candidate differences.
- Raw samples, result row ordinals, p50/p95/p99 and approximate mean confidence
  intervals are retained. Repeated warm samples are correlated, and the small
  pilot does not establish meaningful tail confidence or a deployment speedup.
- Reported vector/query/workspace bytes are explicit arrays, not total process
  or engine memory. Actual engine resident and sidecar disk bytes are null.

## Verification performed

- `make test-w12-fp32`: passed C/ABI checks and 11 Python tests. Python tests
  load real production distance kernels built with UBSan.
- `ASAN_OPTIONS=detect_leaks=0 make test-w12-fp32-sanitize`: passed C tests
  under ASan+UBSan, including an overflowed raw L2 distance that must not silently
  become zero similarity.
- Default leak-enabled sanitizer command: **blocked by environment**.
  LeakSanitizer reports it cannot run under ptrace. Leak checks remain unverified.
- All 24 fixture hashes and all 8 source hashes independently verified; report
  sample counts/statistics and the near-tie case independently recomputed.
- `git diff --check`: passed before source commit.
- `make -j2 lib`: **failed due missing build prerequisites**. Compilation stops
  at `include/qihse_lua_injector.h:8` because `lua.h` is unavailable. liboqs setup
  also reports `cmake: not found` and `ninja: not found`; its existing success
  echo does not make those commands successful. No full engine tests ran.
- No GitHub Actions run was inspected, retried, repaired or monitored.

No production search/auth/default/persistence code was modified. Full authorized
engine comparisons, real semantic corpus, complete memory accounting, target
hardware replication and W12.3 security/generation gates remain open. W12.0 is
still in progress; W12.1 is a documented next-stage contract, not implemented.
