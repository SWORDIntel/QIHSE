# CodeGraph storage review — 2026-11-06

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

Scope: lossless CodeGraph storage and lifecycle. All new measurements use isolated
synthetic graphs. Live repository graphs are being rebuilt separately.

The supplied-project follow-up adds the authenticated
[CSR projection](codegraph_csr_projection.md) and
[lower-copy packed loader](codegraph_zip_storage_review.md). These retain the
existing persistent formats and all authoritative records. The projection's
controlled comparison reduces steady RSS by a further 56.7% versus the initial
readonly-release implementation documented below. Compression level 9 remains
the default: level 3 enlarged the larger authenticated fixture by about 43%.

## Implemented

- Automatic storage selection exports once through the authenticated KV API,
  at that checkpoint encoded Zstandard and packed-v2 candidates and chose the smaller complete file. Current auto selection also includes packed-v3; see [compact references](codegraph_compact_references.md).
  Ties select Zstandard; exports beyond packed's 64 MiB limit use streaming
  Zstandard. Explicit format overrides remain available.
- Automatic migration retains an authenticated, size-accounted current generation
  when a new encoding is equal or larger. This also prevents size regressions
  caused by reserialization order. Large legacy snapshots without descriptor-bound
  byte accounting retain the existing verified conversion path.
- Successful import/migrate retains current and one rollback snapshot, including
  validated commands that reuse an unchanged generation. It removes
  abandoned owned private runtimes only when their ownership leases can be locked.
  Active leases and legacy runtimes without leases are preserved. Cleanup errors
  report `retention_warning` without misreporting a published graph as failed.
- Encoded candidates are staged inside the writer's leased runtime. A hard kill
  leaves reclaimable runtime files or a managed generation, rather than unleased
  compression temporary files beside the manifest.
- Read-only commands release their decoded KV after constructing the independent
  native graph. On glibc, one `malloc_trim(0)` per successful generation load
  returns unused allocator pages; hot queries do not call it. Import/migration
  retain the KV records needed for complete authenticated serialization.
- Node/edge identities, unresolved edges, provenance, unknown JSON fields and
  security metadata remain intact. No lossy graph pruning was introduced.

## Measurements

Three rotated backend orders per synthetic fixture, authenticated exports/loads,
exact roundtrips, record fingerprints and low-clearance denial checks:

| Fixture | Zstandard | Packed | Auto |
| --- | ---: | ---: | ---: |
| 8 nodes, 24 edges | 2,684 bytes | 2,710 bytes | 2,684 bytes |
| 800 nodes, 2,400 edges | 187,856 bytes | 182,356 bytes | 182,356 bytes |

The medium fixture saves 2.93% versus Zstandard. Median auto encode CPU was 319 ms
versus 140 ms for Zstandard; wall time was 384 ms versus 140 ms on a shared host.
Auto temporarily holds the authorized raw export plus both encoded candidates.
These figures establish behavior on the fixtures, not a universal size ratio.

A separate controlled 16,000-node/48,000-edge experiment used the same immutable
packed-v2 snapshot for two alternating daemon pairs. Releasing KV plus glibc trim
reduced median steady RSS from 317,846 KiB to 66,788 KiB (79.0%). Cold query output,
generation refresh, invalid-manifest denial, recovery and capability revocation
matched. Cold time and peak RSS were essentially unchanged. Releasing KV without
trim did not consistently reduce RSS because the allocator retained freed pages.
This does not establish the same RSS reduction on another allocator or graph.

Existing compression tuning found roughly 10% smaller output at level 19 on one
fixture, at roughly 36 times the encode CPU. Level 9/window 23 remains the default.

## Remaining limits

- **Resolved since this review:** semantic identity work removed SQLite row-ID churn. See [public identities](codegraph_public_ids128.md) and [the current XXH3 profile](codegraph_xxh3_tuned.md).
- The producer retains its SQLite source index and exported JSONL. Its current CLI
  cannot export to a separate output path. Deleting that shared output from the
  QIHSE wrapper could disrupt other consumers.
- Packed-v2 retains opaque JSON and caps decoded input at 64 MiB. A chunked format
  with shared dictionaries may improve larger graphs, but needs a new authenticated
  format, decoder and representative corpus measurements.
- Generated/vendor filters and exact edge-site deduplication already exist in the
  producer. Dropping unresolved edges or imposing node caps would lose evidence.

The reproducible driver and receipt are
[`benchmarks/codegraph_auto_compare.py`](../../benchmarks/codegraph_auto_compare.py)
and [`benchmarks/codegraph_auto_reference.json`](../../benchmarks/codegraph_auto_reference.json).
The committed harness pins Git fixture dates; its small validation produces
2,688 bytes for Zstandard/auto and 2,715 bytes for packed. The few-byte difference
from the table reflects metadata; the original sweep and validation are both
recorded rather than presented as identical inputs.

This is a measured improvement to the existing formats, not proof that no further
compression is possible.

## Validation

- Codec unit tests passed: exact selection over the same authenticated export,
  record/security metadata roundtrip, denied replacement preservation and a
  complete 65 MiB streaming fallback.
- ASan/UBSan passed for changed codec sources. The shared library was not
  instrumented and leak detection was disabled; this is not whole-engine sanitizer
  coverage.
- Isolated storage CLI tests passed for changing imports, publication failure,
  bounded snapshot retention and abandoned/active/unleased runtimes.
- Automatic CLI tests passed on 8-node/4-edge and 800-node/2,400-edge fixtures:
  query parity, explicit overrides, unchanged import reuse and migrations that
  shrink or retain the current generation. The medium fresh import used 182,349
  bytes automatically versus 187,975 bytes with explicit Zstandard. These separate
  imports have independently created KV metadata and differ from the codec fixture.
- Reindex wrapper: 16 tests passed, including forwarding `--storage-format auto`.
- An isolated no-op regression passed for unchanged import, explicit same-format
  migration and automatic migration: obsolete snapshots and abandoned runtimes
  were removed while the current manifest remained unchanged.
- The final `make test TEST_JOBS=32` completed 177 targets. CodeGraph and its memory
  target passed; three failures outside CodeGraph remain. See the complete
  [results and limitations](codegraph_optimization_results.md).
