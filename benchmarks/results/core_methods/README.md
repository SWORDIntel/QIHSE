# Scalar core method reference

[20261115_reference.jsonl](20261115_reference.jsonl) records a successful
45-case default run on 2026-11-15, using GCC 14.2.0 with the runner's `O3`
profile on Linux x86-64. The runner did not pin CPU affinity. This is an
instrumented standalone build of the actual core on small, resident synthetic
fixtures; it does not measure VectorDB or a full shared-library deployment.

The recorded revision is `0418efb802e3-dirty`: that commit is the base, not a
claim that it contains the measured additions. The exact source/header closure
is recorded in [20261115_sources.sha256](20261115_sources.sha256). Its aggregate
SHA256 equals `source_sha256` in the JSON metadata. From the repository root,
`sha256sum -c benchmarks/results/core_methods/20261115_sources.sha256` checks
the measured contents. The runner generates this manifest from the compiler's
dependency list before building, using only relative repository paths.

## Scope and results

The default uses 512 records, 32 queries, seed 42, gamma 1, D=64/128 real output
coordinates, tiles 1/16, one warmup and three measured batches per case. All 45
cases passed the independent original-type equality oracle. The oracle accepts
any equal duplicate index and checks absent queries as well as returned values.

Selected **median wall microseconds per complete batch**, at D=128 and tile 16
for the feature methods:

| Fixture | Exact scan | Phase cosine | Paired sine/cosine |
|---|---:|---:|---:|
| Present | 7.862 | 3,898.890 | 3,183.138 |
| Absent | 11.877 | 3,930.106 | 3,298.999 |
| Duplicates | 12.007 | 2,631.597 | 2,203.377 |
| Nearby doubles | 10.004 | 2,545.440 | 2,045.595 |
| Large integers | 9.995 | 12,251.199 | 6,102.045 |

Exact scan was fastest for every fixture in this run. Tiling still saved real
RFF work: row projections fell from 16,384 to 1,024 per batch at tile 16,
with one basis build per batch. At D=128, phase scratch increased from 4,200 to
19,560 bytes; paired scratch increased from 2,664 to 18,024 bytes. Exact scan
used zero owned heap scratch. Dot-product work remains proportional to nQD.
On the present fixture, moving from tile 1 to tile 16 reduced phase-cosine
median batch time from 47.231098 ms to 3.898890 ms and paired-feature time
from 32.206445 ms to 3.183138 ms. The exact baseline was 0.007862 ms.

Nearby-double queries also expose the role of verification. Of the 16 present
queries in each batch, phase cosine proposed one exact match and paired features
proposed none; fallback still returned all 16 correctly. Lower kernel variance
does not resolve values separated at floating-point precision automatically.

Counters sum the three timed repeats; scratch is the peak. Stage timings and
wall/CPU samples include kernel construction and metrics collection. Fixture
generation, oracle construction and validation are excluded. Data and queries
are reused after warmup. The ns/query field is amortized batch time, and three
samples do not establish request p99 behavior. These results support explicit
method selection and further workload testing, not an automatic default change.

## Reproduce and select cases

```sh
scripts/run-core-methods-bench.sh > core-methods.jsonl
scripts/run-core-methods-bench.sh --method paired --dimensions 128 --tile 1,16 --dataset nearby_double --repeats 9 --format csv > paired-nearby.csv
```

Every non-exact selection also runs the exact baseline. `--help` lists all
controls. `QIHSE_CORE_BENCH_SANITIZERS=1` enables a correctness-only build;
sanitizer timings are not performance evidence. A separate 25-case small sweep
passed ASan/UBSan with leak detection disabled for the ptrace environment.

The integrated focused core/math/runtime runners and installed-header checks
passed. The complete `make test TEST_JOBS=32` gate remains blocked during the
shared-library build by the missing `lua.h` dependency; this reference does not
stand in for that gate.
