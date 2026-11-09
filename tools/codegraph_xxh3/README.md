# CodeGraph standard XXH3-128 runtime

This independent MIT-licensed adapter packages unmodified xxHash 0.8.3
(BSD-2-Clause) with separately compiled scalar, SSE2, AVX2 and AVX-512 backends.
Only supported CPU/OS backends are selectable; this host selects SSE2. Upstream
hash bytes are unchanged. No stale QIHSE corpus files are used as implementation.

## Build and verify

From this directory:

```sh
make -j4 all
make test test-oracle
make BUILD=build-portable PORTABLE=1 -j4 test
make sanitize
./build/qx3sum --list
```

Ordinary builds need a C11 toolchain only. The optional system oracle and benchmark
need libxxhash and OpenSSL development libraries. SIMD flags are isolated to each
backend object; no global AVX flag is required. `auto` selects the widest supported
ISA and is not a benchmark autotuner. Unsupported explicit backends fail safely.

The public header provides one-shot, batch and reusable streaming APIs. For the
Python graph producer, checked exported `qx3_hash_canonical128` and
`qx3_batch_canonical128` adapters emit exactly 16 canonical bytes per input. Select
an immutable backend once, then reuse it. The canonical encoding is big-endian
high64 followed by big-endian low64; never persist the native result structure.
The canonical batch uses one backend dispatch and allocates no temporary arrays.
Offsets contain count+1 monotonic entries, start at zero and end at blob_size.
Output must not overlap the blob or offsets; malformed ranges fail before output.
Callers supply valid memory objects, as with upstream xxHash and memcpy.

These APIs hash already supplied bytes. Any classified QIHSE retrieval remains
behind an authenticated caller and is not implemented by this module. XXH3 is a
candidate fingerprint, not a replacement for snapshot integrity verification or
full-identity comparison when collisions matter.

## Provenance

Source delivery: `QIHSE_XXH3_Tuned_Source_2026-11-07.zip`, supplied by the user.
Every original delivery checksum passed before editing. `SHA256SUMS.delivery`
retains that full archive manifest; some delivery entries (historical corpus and
build logs) are intentionally not copied here, so it is not a checksum command
for this integrated subset. `SHA256SUMS` covers the integrated source subset.
The vendored header retains its original bytes and SHA-256:
`17973c0dc49d9854ca26caa191f0e12f7a424b68858d9a78de3860d959d85e4b`.

`SUPPLIED_RESULTS.md` records historical measurements on the supplier's EPYC
AVX-512 host, not measurements from this machine. Fresh local measurements and
validation status are in `results/local-sse2.json` and `INTEGRATION.md`.
