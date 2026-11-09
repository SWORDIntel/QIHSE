# Supplied ZIP storage review

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

The accepted portion removes unnecessary packed-v2 reconstruction copies and
uses smaller key spans while retaining QCGP0002/QCGZ0001, the automatic
smallest-format writer, the existing 64 MiB packed bound, and Zstd level 9.
The supplied level-3 recommendation increased these fixture sizes, so it is
available only as an explicit build-time measurement override.

The candidate was evaluated against a snapshot of the current native storage
files, commit `6ee93fc`, rather than the supplied archive's stub SDK. The
baseline was byte-identical to the integration owner's current storage files
and C tests at review time. That candidate was subsequently integrated; the baseline comparison remains historical evidence.

## Results

The durable receipt is `benchmarks/codegraph_zip_storage_reference.json`.
Each case uses the real authenticated QIHSE SDK and the same synthetic export
with independently hashed graph IDs. These are one-run observations on a
shared host, not a stable throughput claim.

| Nodes / edges | Backend | Baseline level 9 bytes | Candidate level 9 bytes | Candidate level 3 bytes |
|---|---|---:|---:|---:|
| 800 / 2,400 | Zstd | 187,857 | 187,857 | 199,229 |
| 800 / 2,400 | Packed | 182,355 | 182,355 | 196,829 |
| 8,000 / 24,000 | Zstd | 2,033,183 | 2,033,183 | 2,901,490 |
| 8,000 / 24,000 | Packed | 1,974,079 | 1,974,079 | 2,820,788 |

Packed native-load CPU time was 91.5 → 48.8 ms for the smaller fixture and
1,034.1 → 504.8 ms for the larger fixture. Shared-host scheduling affected
wall time. Peak RSS includes fixture construction and encoding, so the receipt
does **not** establish a decoder memory reduction. The structural reduction is
two fewer complete raw reconstruction copies and 8-byte rather than 16-byte
key spans on this 64-bit host.

## Boundaries and validation

The reconstruction `FILE` remains private to the principal-bound KV parser.
The public helper returns only a detached immutable store after final active
principal and aggregate classification/SCI checks. The storage wrapper binds
the opened input to the trusted manifest SHA at that historical checkpoint (fresh snapshots now use the [typed XXH3 contract](codegraph_snapshot_xxh3.md)), with
descriptor identity, size and nanosecond timestamp invariance. A failure
destroys the staged store. Labels and Zstd checksums alone are not
cryptographic authentication.

Tests cover NULL, low clearance, missing SCI, revoked principals, protected
retrieval after revocation, wrong trusted digest, exact unknown JSON bytes,
all record metadata, older binary-digest key tags, logical duplicate keys,
corruption, auto selection and the large Zstd fallback. The standalone codec
still verifies exact raw bytes; native detached-store comparison fingerprints
key/value plus classification, SCI, expiry, flags and change sequence because
its re-export order can differ. A separate native CLI smoke test verifies
import, status, stats, query, context, impact and missing-symbol parity.

Both focused C tests passed normally and under ASan/UBSan. The linked QIHSE
shared library was not rebuilt with sanitizers, and leak detection was
disabled; this is not a fully instrumented runtime result. The largest packed
decoder stack frame measured 352 bytes. The later full-suite run was explicitly stopped at the user's request; current validation boundaries are recorded in [ROADMAP.md](../../ROADMAP.md#codegraph).

## Reproduction

From the candidate checkout, create a source-only baseline directory and point
the benchmark at a built native QIHSE library. No configured live storage is
used.

```sh
mkdir -p build/baseline/tools
for name in qihse_codegraph_storage.c qihse_codegraph_storage.h qihse_codegraph_packed.c qihse_codegraph_packed.h; do
    git show "6ee93fc:tools/$name" > "build/baseline/tools/$name"
done
python3 benchmarks/codegraph_zip_storage_compare.py \
    --baseline-dir build/baseline --library-dir . --nodes 800 8000 \
    --repeats 1 --output build/zip-storage-benchmark.json
make test-codegraph-codec test-codegraph-packed
```

Use a larger `--repeats` count for timing decisions. Source hashes, library
hash, exact-byte checks and per-case measurements are recorded in the receipt.
No new persistent format or experimental QCGP0003 codec is activated here.
