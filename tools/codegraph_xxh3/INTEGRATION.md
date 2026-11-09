# Integration validation

The archive checksum manifest passed for every delivered file. The vendored
xxhash.h remains unmodified, with its upstream BSD-2-Clause notices and Debian
provenance retained. Adapter sources, tests and tools retain MIT notices.

The runtime's scalar and SSE2 backends execute on this Intel Xeon E5-2470 v2.
AVX2 and AVX-512 selection is rejected on this host. CPUID checks require SSE2 for
that backend, OSXSAVE/AVX plus XCR0 XMM/YMM state for AVX2, and XCR0 mask 0xe6 plus
AVX2/AVX512F/BW/DQ for AVX-512. The xgetbv instruction runs only after OSXSAVE and
AVX checks. No unsupported instruction path was forced.

Native and separately linked system-library oracle suites each passed 3,251,037
checks, including canonical FFI batch validation, boundary/unaligned input,
streaming, guard pages and concurrent independent streams. The batch adapter also
asserts exactly one backend dispatch and no output on malformed offsets or overlap.
Portable-only native/CLI checks passed (2,167,362 native assertions); only scalar
is selectable in that build. ASan/UBSan native/CLI checks passed (3,251,037 native
assertions); LeakSanitizer was disabled. These counts include repeated assertion
checks, not that many independent messages.

## Local resident-buffer comparison

Nine shuffled/interleaved samples per candidate, nominally 8 ms each, one pinned
logical CPU on this E5-2470 v2. Clock frequency and shared-host contention were not
controlled. The source corpus is the delivered 19-file/617,706-byte benchmark
corpus, not serialized graphs. File reads and graph construction are excluded.

| Input | Shared XXH3 | Tuned SSE2 | Shared / SSE2 |
| --- | ---: | ---: | ---: |
| 32 bytes | 31.88 ns | 31.44 ns | 1.01x |
| 256 bytes | 119.54 ns | 95.39 ns | 1.25x |
| 64 KiB | 17,025.76 ns | 10,650.18 ns | 1.60x |
| Source corpus, average per file | 9,559.79 ns | 6,077.04 ns | 1.57x |

The source-corpus batch path averaged 5,558.08 ns per file including output stores
and checksum reduction. Results are not universal speedups or graph-build gains.
`results/local-sse2.json` retains each sample, corpus/source/compiler/binary hashes
and host metadata. For reproduction, extract the original delivery corpus and set
`DELIVERY_CORPUS` to its directory, then run:

```sh
make -j4 build/bench
python3 bench/run.py --corpus "$DELIVERY_CORPUS" --out results/repeat-local.json \
  --quick --samples 9 --ms 8
```

## Follow-up canonical store review

The claimed stream-alignment defect is absent: upstream state is 576 bytes with
64-byte alignment; both the current wrapper and state-first layout occupy 640
bytes. The existing static assertion guarantees aligned_alloc's size multiple.
Seed-zero reset already calls upstream's unseeded fast path. Backend CPU probing
occurs during setup, outside the graph-ID hot path. No mmap CLI, extra ISA flags,
stream layout change or CPUID cache was adopted.

The original canonical byte loop compiled into extensive shifts and register
saves on GCC. The explicit endian-aware store now emits two BSWAP instructions
and two unaligned-safe memcpy stores on this little-endian host, with an explicit
byte-loop fallback for unknown endianness. In 15 shuffled/interleaved samples of
the actual checked canonical FFI batch API over 1,024 resident records, median
nanoseconds per record changed as follows:

| Record bytes | Before | Explicit endian store |
| --- | ---: | ---: |
| 32 | 57.10 | 30.92 |
| 96 | 72.54 | 49.40 |
| 192 | 115.20 | 88.60 |
| 256 | 122.16 | 105.47 |

The 19-file corpus was effectively unchanged (6,664 to 6,630 ns/file). Restrict
qualification added no meaningful benefit; look-ahead prefetch worsened short
records and was rejected. Raw per-sample measurements and compared library hashes
are in `results/canonical-store.json`. Python invocation overhead is shared across
candidates; this measures the canonical batch API, not complete graph building.
A NULL stream digest now returns an all-zero value with errno EINVAL, as documented
and tested. All valid digest outputs remain standard XXH3-128.
