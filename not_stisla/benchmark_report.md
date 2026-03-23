## NOT_STISLA Benchmark Comparison

| Metric | Binary Search | NOT_STISLA Search | NOT_STISLA Batch Parallel |
| --- | --- | --- | --- |
| Mean latency (ns/op) | 44.97 | 7.98 | 6.48 |
| Speedup vs binary | 1.0× | 5.6× | 6.9× |
| Speedup vs classical | 0.18× | 1.0× | 1.23× |
| Best run (ns/op) | 43.27 | 7.14 | 3.87 |
| Worst run (ns/op) | 49.04 | 8.70 | 13.20 |
| Dataset | Sorted `int64_t` (1 000 000 elements) | Same | Same |
| Query workload | 200 000 random in-array values | Same | Same |

Per-core classical `not_stisla_search` already delivers a big win over binary search (≈5.6×). Adding the batch + OpenMP path pushes latency further down (~6.9× speedup) because batched keys amortize anchor learning and threads share the fast search loop.
