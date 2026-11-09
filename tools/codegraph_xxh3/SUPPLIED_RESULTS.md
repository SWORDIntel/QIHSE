# Tuned XXH3-128: measured results

## Delivered implementation

Standard xxHash 0.8.3, unchanged algorithm and digest values, with:
separate scalar/SSE2/AVX2/AVX-512 translation units; one-time explicit backend
selection with CPU/OS checks; short-input call-site inlining; one-dispatch batch
loops; reusable aligned streaming state; canonical output encoding; and a
bounded-memory file hashing CLI. No QIHSE repository integration or hash-field
migration has been applied.

The custom EAX4 algorithm is not required or embedded. The header is vendored,
so ordinary library builds do not depend on the installed shared xxHash library.
The shared library is used only as a comparison/oracle in optional targets.

## New measurements (not copied from the previous EAX4 report)

Primary: one pinned logical CPU on an AMD EPYC 9V74 exposed through KVM;
GCC 14.2.0, `-O3`, release-specific xxHash 0.8.3. Host clock frequency, scheduling
and physical sibling contention were not controlled. These are resident-buffer,
repeated warm-cache measurements; file I/O and graph parsing/building are excluded.
All primary rows below use the **same AVX-512 one-shot backend**, not a
per-row best-of-all-methods selection. Medians from 15 shuffled/interleaved
samples per candidate, nominally 8 ms each. Nanoseconds per hash/file; lower is better.

| Workload | Installed shared XXH3 (ns) | Tuned AVX-512 (ns) | OpenSSL SHA-256 (ns) | Shared/tuned | SHA/tuned |
|---|---:|---:|---:|---:|---:|
| 32 bytes | 7.20 | 6.38 | 67.16 | 1.13x | 10.52x |
| 256 bytes | 29.11 | 18.90 | 224.60 | 1.54x | 11.89x |
| 4 KiB | 262.52 | 82.45 | 2,678.50 | 3.18x | 32.48x |
| 64 KiB | 3,758.91 | 1,134.28 | 42,606.64 | 3.31x | 37.56x |
| 1 MiB | 58,099.53 | 18,111.29 | 703,049.08 | 3.21x | 38.82x |
| Source corpus, average/file | 2,052.63 | 593.20 | 22,850.02 | 3.46x | 38.52x |

The corpus is **19 unchanged source files, 617,706 bytes**,
from the earlier supplied QIHSE CodeGraph source archive. It is not a capture of
serialized graph node/edge records or the missing historical 470-file corpus.
One full resident pass took **11.27 microseconds**
with tuned AVX-512, versus **39.00 microseconds**
for the shared library and **434.15 microseconds**
for SHA-256. At 64 KiB, tuned AVX-512 measured
**57.78 GB/s** (decimal).
These rates reflect hot resident data, not storage or sustained DRAM bandwidth.

### Short-input specialization

For 32-byte inputs, ordinary AVX-512 dispatch took
**6.38 ns/hash**, versus
**4.50 ns/hash** when the call-site length
was the literal `32`. A native batch of independent records took
**5.70 ns/record**, including output-array stores
and checksum reduction. The batch figure is amortized throughput, **not isolated
request latency**. Runtime-length inline results are separately recorded;
constant-length gains must not be assumed for arbitrary records.

All backend digest values are identical. The small-input win is compiler
specialization/inlining, not a different hash or skipping input bytes.

### Repeat run

Nine additional shuffled samples per candidate on the quick subset, using the
same final binary and source:

| Workload | Shared/tuned primary | Shared/tuned repeat | SHA/tuned primary | SHA/tuned repeat |
|---|---:|---:|---:|---:|
| 32B_aligned | 1.13x | 1.19x | 10.52x | 10.81x |
| 256B_aligned | 1.54x | 1.70x | 11.89x | 11.89x |
| 65536B_aligned | 3.31x | 3.30x | 37.56x | 35.78x |
| source_corpus_aligned | 3.46x | 3.51x | 38.52x | 38.59x |

### SHA-256 comparison boundary

SHA-256 computes a **256-bit cryptographic digest**; XXH3 returns a **128-bit
non-cryptographic fingerprint**. The speed comparison is not security equivalence.
The benchmark uses `SHA256_Init/Update/Final` with no per-hash provider lookup or
heap allocation. Full SHA-256 output is computed, although only 128 bits are
consumed by the benchmark checksum. No disable mask is applied to the primary run.
The lower-level OpenSSL API is retained only to avoid inflating the baseline with
provider setup, not as a recommendation to change an application's EVP usage.

A separate SHA-NI-disabled diagnostic took **144.49 microseconds** at
64 KiB, versus **42.61 microseconds** normally,
a **3.39x** slowdown. The disabled number
is NOT used in the speedup table. This is an acceleration-sensitive control, not
an instruction trace. Mask: `:~0x20000000:~0x0:~0x0:~0x0`.

### Trade-offs and limits

- `auto` chooses the widest supported ISA, not a measured universal winner.
  Explicit AVX2/AVX-512 selections and per-backend results are included. Intel
  systems, older physical x86 CPUs and non-x86 systems were not benchmarked.
- Streaming pays state/reset/chunk bookkeeping overhead. Prefer one-shot hashing
  for data that is already resident; use streaming to avoid loading huge files
  merely for hashing. No extra allocation is made by reset/update/digest.
- Inlining can enlarge callers; use the optional inline header selectively.
  Batched output writes have a cost, and batching is not always faster.
- The shared-library comparison includes its build/interface choices; it does
  not claim a new algorithmic improvement over upstream xxHash. The standard
  SIMD code and compiler visibility explain the tuning.
- No graph-build, graph-query, incremental-update, multi-core scaling, cold-I/O,
  peak-RSS, collision-resistance, or end-to-end application gain is claimed.
  Canonical framing remains the integrating application's responsibility.

## Validation completed on final source

| Check | Result |
|---|---|
| GCC warning-as-error build and native suite | PASS; 5,418,022 checks |
| Installed xxHash 0.8.3 system-library oracle | PASS; same suite and canonical bytes |
| Clang 17 warning-as-error build and suite | PASS; 5,418,022 checks |
| Portable/scalar-only build | PASS; 2,167,216 checks; unavailable backends rejected |
| ASan + UBSan | PASS on final source; native and CLI suites |
| LeakSanitizer | Disabled; not claimed |
| C++17 include/link/example smoke test | PASS |
| CLI files, pipes, missing files, invalid seeds and filename escaping | PASS |

The counts include return-code and per-update assertions, not that many distinct
messages. Native checks cover empty input, published-format empty/`abc` known
values, all lengths 0..2048 with offsets 0..15, large boundary lengths at offsets
0..63, seeds including 0/1/high bits/`UINT64_MAX`, many streaming chunk boundaries,
reused state and non-destructive digest, mixed/odd/empty batches, protected-page
boundaries through one system page, and concurrent independent streams sharing a
backend. The system-library oracle uses a separate compiled library but the same
upstream algorithm, not independently designed cryptanalysis.

## Reproduce

```sh
sha256sum -c SHA256SUMS
make -j2
make test test-oracle
make sanitize
make BUILD=build-portable PORTABLE=1 -j2 test
make CC=clang BUILD=build-clang -j2 test
make -j2 build/bench
python3 bench/run.py --out results/local.json --samples 15 --ms 8 --sha-control
python3 bench/run.py --out results/local-repeat.json --quick --samples 9 --ms 8
```

The optional `test-oracle`/benchmark targets require the installed xxHash and
OpenSSL development libraries. `make test` and the module do not.

`results/run.json` and `results/repeat.json` retain every timed sample, source and
binary hashes, exact compile commands, CPU/OS/compiler/OpenSSL metadata, selected
CPU/backend, corpus SHA-256 manifest, and the measurement method. The separate
negative-control data is retained in `results/run.json`. See
`results/ALL-MEASUREMENTS.md` for median/min/max/MAD and throughput for every case.
The delivered source reproduces the experiment, not the exact timings of a
shared virtualized host.
