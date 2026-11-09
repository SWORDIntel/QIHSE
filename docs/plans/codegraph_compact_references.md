# CodeGraph compact references and reproducible identities

> **Roadmap authority:** [ROADMAP.md](../../ROADMAP.md) is the sole authority for delivery status, remaining work, sequencing and acceptance. This file retains supporting design, acceptance criteria and dated evidence; historical status labels below are not an independent current checklist. Consolidated 2026-11-07.

The native `packed-v3` format (`QCGP0003`) stores repeated IDs and strings once,
then uses dense variable-length references. It preserves the complete authenticated
KV export byte for byte, including unknown JSON fields, unresolved relationships,
classification, SCI, expiry and sequence metadata. Full tokens determine identity:
two IDs sharing their first 128 bits remain distinct. Existing opaque IDs are not
truncated or renamed during migration.

`--storage-format auto` compares complete Zstandard, packed-v2 and packed-v3
candidates from one authenticated export and publishes the smallest. Explicit
`packed-v2` remains available. Readers continue to support old formats. The
64 MiB decoded-input bound for dictionary packing remains; larger exports use the
streaming Zstandard path. Retention, no-growth migration, progress and source
freshness checks remain in force.

The decoder verifies the declared snapshot checksum against an immutable descriptor
copy, authorizes record labels before body decompression, bounds all expansions,
and checks the principal again before output. Snapshot verification is separate from compact references; fresh snapshots use the explicitly declared [XXH3 checksum contract](codegraph_snapshot_xxh3.md).

At the initial compact-reference checkpoint, the producer change removed SQLite row numbers from edge identity. Versioned,
framed semantic facts and deterministic duplicate occurrence ordinals produce
stable IDs and ordering across row renumbering. Full preimages are compared when
hashes repeat; distinct identities with equal digests abort export before replacing
the published file. Node IDs remain compatible. Existing snapshots keep their
original identities; new exporter output takes effect on reindex.

The initial compact-reference phase retained public identity widths. Fresh builds
now use the [128-bit public identity profile](codegraph_public_ids128.md), with
explicit collision resolution and 16-byte dictionary entries. EAX4 and the
separate exploratory column layout are not part of this format.

## Measured storage

One run per backend over each identical authenticated synthetic export; complete
encoded bytes, exact raw reconstruction, record fingerprints, and low-clearance
denial were checked. No live graph was read or migrated.

| Nodes / edges | Zstandard | Packed-v2 | Packed-v3 | Auto |
| --- | ---: | ---: | ---: | ---: |
| 8 / 24 | 2,688 | 2,715 | 2,688 | 2,688 |
| 800 / 2,400 | 187,857 | 182,355 | 177,806 | 177,806 |
| 8,000 / 24,000 | 2,033,183 | 1,974,079 | 1,686,048 | 1,686,048 |

The larger fixture is 14.59% smaller than packed-v2. This is not a prediction for
all repositories. Auto preserves the earlier format on ties. Timing measurements
were collected on a shared host; no general latency improvement is claimed. V3
uses bounded reconstruction buffers and an anonymous temporary stream; it does not
inherit v2's lower-copy decoder optimization.

Receipt: `benchmarks/codegraph_v3_reference.json`. Reproduce:

```sh
python3 benchmarks/codegraph_auto_compare.py --nodes 8 800 8000 --repeats 1 \
  --output ./build/codegraph-v3-reference.json
make test TEST_JOBS=32
```

Focused native dictionary, storage and packed tests passed. Dictionary ASan/UBSan
passed; the shared library was not instrumented and leak detection was disabled.
Producer export tests passed (22), including row renumbering, distinct unresolved
identities, parallel occurrences and forced hash collisions preserving publication.
The full suite was stopped at the user's request to keep validation scoped to
CodeGraph. It is not reported as passed. Focused results are retained in
`build/codegraph_v3_focused.log`; the final small CLI check is recorded in
`build/codegraph_v3_cli_smoke.log` (PASS: explicit v3 import, query, stats,
unchanged reuse, and rejection of a v3 snapshot mislabeled as v2).


Fresh snapshot checksums now use [XXH3 with current-plus-one retention](codegraph_snapshot_xxh3.md).
