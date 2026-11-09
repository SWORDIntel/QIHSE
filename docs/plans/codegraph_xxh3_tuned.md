# Tuned standard XXH3-128 for CodeGraph

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

The supplied module uses unchanged xxHash 0.8.3. Scalar, SSE2, AVX2 and AVX-512
backends are compiled separately; runtime CPUID and OS-state checks select a
supported backend once. This host is an Intel Xeon E5-2470 v2 with SSE2 but without
AVX2, AVX-512 or SHA-NI. The supplied AMD AVX-512 benchmark numbers do not describe
this host.

Graph public IDs remain 128 bits (16 bytes / 32 lowercase hexadecimal characters).
Changing the hash algorithm does not halve their size again. Canonical XXH3 output
is big-endian high64 followed by big-endian low64. A native batch adapter returns
those bytes directly to the producer; immutable contiguous input and offsets avoid
per-record foreign-function calls and buffer allocation.

The new profile is declared explicitly:

```json
{"identity":"qihse-semantic-xxh3-128-v1","id_algorithm":"xxh3-128","id_bits":128,"id_seed":0,"id_encoding":"xxh128-canonical","id_collision":"counter-xxh3-128-v1","id_collision_attempts":256}
```

Semantic node/edge framing and canonical ordering remain explicit. The producer
compares full semantic preimages on an ID match. Collision retries use the domain
`qihse-id-collision-xxh3-v1` followed by NUL, 8-byte big-endian original preimage
length, original preimage and 8-byte big-endian retry counter (1 through 255).
Exhaustion aborts publication rather than merging identities.

Source freshness, export trailers, authorization and capability tokens retain
their existing cryptographic algorithms. Snapshot checksums were subsequently
switched to XXH3 at the user's request; see
[the snapshot contract](codegraph_snapshot_xxh3.md). XXH3 does not authorize reads.
All live graphs were already lost; fresh builds adopt the new profile. No live
graph migration or dual writing is required.

## Measurements on the actual Xeon

Nine shuffled/interleaved warm samples per candidate, nominally 8 ms each:

| Input | Installed XXH3 | Tuned SSE2 | Ratio |
| --- | ---: | ---: | ---: |
| 32 bytes | 31.88 ns | 31.44 ns | 1.01x |
| 256 bytes | 119.54 ns | 95.39 ns | 1.25x |
| 64 KiB | 17,025.76 ns | 10,650.18 ns | 1.60x |
| Source corpus, average/file | 9,559.79 ns | 6,077.04 ns | 1.57x |

The batch corpus path measured 5,558.08 ns/file. These are resident-buffer hash
measurements on a shared host, excluding file I/O, graph parsing and Python
producer overhead. They are not a whole-reindex speedup. Raw samples and build
provenance are in `tools/codegraph_xxh3/results/local-sse2.json`.

The final-build Python producer benchmark measured 32,000 semantic frames over
11 shuffled CPU-time samples: SHA-256/128 hashing 126.31 ms versus native XXH3
batching 52.05 ms (2.43x). Full checked identity allocation measured 244.28 ms
versus 162.68 ms (1.50x). Calling ctypes separately per record took 223.96 ms and
was rejected as slower. These exclude Git, parsing, serialization and queries.
The receipt pins the exact final source/library hashes:
`benchmarks/codegraph_xxh3_producer_reference.json`.

## Selected follow-up improvements

Portable endian-aware word stores replaced byte-shift serialization. On the
actual canonical batch API, 15 interleaved samples measured 57.10 to 30.92 ns per
32-byte record, 72.54 to 49.40 ns at 96 bytes, and 122.16 to 105.47 ns at 256 bytes.
The source-corpus difference was noise. Unaligned stores use `memcpy`; unknown
endianness retains an explicit byte fallback. NULL stream digest is documented
as `EINVAL` with a zero result and covered by a focused test.

The alleged allocation UB was not present: compile-time assertions already
require a multiple-of-64 size; both proposed layouts measured 640 bytes. Upstream
already has the seed-zero reset path. Restrict was a tie and prefetch hurt short
records, so neither was retained. Setup-time CPUID caching and CLI mmap changes
were omitted from this CodeGraph implementation.

## Validation and reproduction

The vendored xxHash header remains unchanged. Final native, separate system-library
oracle, and ASan/UBSan suites passed 3,251,086 assertions each plus CLI checks;
portable-only tests passed earlier. LeakSanitizer was disabled. Producer tests
passed (28), including collision retries/exhaustion, stable rebuild ordering,
known canonical vectors, missing-library failure and scalar/auto equivalence.
Ten installed-candidate checks passed. Native format tests rejected 25 malformed
profile/ID cases, including embedded-NUL aliases. Source-adapter tests passed (11).

```sh
make codegraph-xxh3
make test-codegraph-xxh3
QIHSE_CODEGRAPH_XXH3_LIBRARY=./tools/codegraph_xxh3/build/libqihse_xxh3.so \
  "$PRODUCER_ROOT/.venv/bin/python" benchmarks/codegraph_xxh3_producer_compare.py \
  --producer-root "$PRODUCER_ROOT" --output ./build/producer-xxh3.json
```

`tools/codegraph_xxh3/bench/canonical_compare.py` reproduces the canonical-store
comparison given baseline and candidate shared libraries. Raw canonical samples
are in `tools/codegraph_xxh3/results/canonical-store.json`.

The installed private runtime bundle contains the reader, matched QIHSE library,
tuned XXH3 library and `qx3sum`. The preceding bundle and producer source are
retained for coordinated rollback. Deployment hashes are in
`build/codegraph_xxh3_deployment.json`. Validation stays scoped to CodeGraph;
no full QIHSE suite or live repository graph rebuild was run.

At the preceding SHA-snapshot checkpoint, the installed producer/launcher smoke passed: two complete fixture builds
produced identical exports; native import/query/stats reported the XXH3-128 profile
and retained SHA-256 source/snapshot verification. The three-node/three-edge
packed-v3 test snapshot occupied 1,084 bytes. Log:
`build/codegraph_xxh3_installed_smoke.log`.

The current deployed snapshot checksum and installed smoke are documented in [the snapshot/retention report](codegraph_snapshot_xxh3.md); fresh snapshots use typed XXH3-128 while source freshness remains SHA-256.
