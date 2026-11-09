# CodeGraph snapshot checksum and retention

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

New CodeGraph snapshots use tuned standard XXH3-128 checksums for accidental
corruption detection. The checksum is declared explicitly as
`snapshot_hash_algorithm: "xxh3-128"` plus a 32-character lowercase
`snapshot_hash` (seed zero, canonical big-endian high64 followed by low64).
It is not stored in a misleading `sha256` field.

This change applies to rebuildable CodeGraph index snapshots. Source freshness,
CRG JSONL trailers and input hashes retain their existing SHA-256 contracts.
QIHSE database snapshots and backups are outside this change. An XXH3 snapshot
checksum is not a cryptographic integrity guarantee.

The authenticated reader checks the expected typed checksum against the same
snapshot descriptor, rejects changed descriptors, validates classified record
labels before disclosure, and rechecks the principal. The dictionary decoder
verifies an immutable copy of the exact bytes it consumes. Unknown checksum
algorithms and ambiguous/malformed manifest fields fail closed.

For each repository, after durable publication the storage lifecycle retains only the current
snapshot and one previous snapshot. Validated unchanged commands and GC apply the
same rule. A failed manifest publication before commit removes its unreferenced
candidate. Runtime leases protect active readers; unrelated files are not treated
as graph snapshots or deleted.

All live graphs were already lost before this rollout; new builds use this
checksum contract. Validation uses disposable graphs, not live repository state.
## Focused verification

The new CLI regression passed across packed-v3, packed-v2 and Zstandard. It
checks explicit 32-hex XXH3 receipts/stats, query behavior, corruption denial,
unknown algorithms, embedded-NUL metadata and ambiguous old/new checksum fields.
Storage tests cover typed checksums, exact metadata preservation, low-clearance,
wrong-SCI, NULL-principal, wrong-checksum and wrong-algorithm denial.

The independent retention test passed in 68.3 seconds: four publications retain
exactly two managed snapshots; two forced pre-commit publication failures add no
snapshots; malformed input preserves both; unchanged import removes an orphan
and abandoned leased runtime while preserving active leases and unrelated files;
GC and storage conversion remain bounded. The previous implementation was first
shown to fail this test by leaving a third snapshot after publication failure.

During publication a candidate exists alongside current and previous. Hard-killed
writers can leave an orphan until the next validated publication or GC. Files
referenced by a committed manifest are preserved if durability reporting fails;
pruning them prematurely could damage crash recovery. The two-snapshot limit is
the post-success retention policy, not a promise about every intermediate I/O step.

Reproduce only the relevant CodeGraph checks:

```sh
make qihse-codegraph test-codegraph-codec test-codegraph-dictionary
python3 tests/test_codegraph_snapshot_xxh3.py --binary ./qihse-codegraph
python3 tests/test_codegraph_retention_bound.py --binary ./qihse-codegraph \
  --expect-checksum xxh3-128
```

No full QIHSE suite was run, as requested. Normal and ASan/UBSan storage tests
passed for all typed compact formats and bounded raw-descriptor reads; dictionary
XXH3 negative/cached-stdio sanitizer checks passed. The shared library remained
uninstrumented and leak detection was disabled.

The installed private runtime bundle is updated. The actual installed producer
and reader passed a disposable end-to-end build/export/import/query/stats check:
public IDs and snapshot checksums both report XXH3-128, the source checksum
remains SHA-256, and repeated builds produce identical exports. The test snapshot
had three nodes, three edges and 1,090 encoded bytes. Logs and deployment metadata:

- `build/codegraph_snapshot_xxh3_installed_smoke.log`
- `build/codegraph_snapshot_xxh3_deployment.json`
- `build/codegraph_snapshot_retention_tests.log`
- `build/codegraph_snapshot_xxh3_cli_tests.log`
- `build/codegraph_snapshot_xxh3_storage_tests.log`
- `build/codegraph_snapshot_xxh3_storage_sanitizer.log`
- `build/codegraph_snapshot_xxh3_dictionary_sanitizer.log`
