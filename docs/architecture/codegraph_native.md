# Native QIHSE CodeGraph (structural code review)

**Status:** Native import, indexed queries and an optional local resident reader are implemented.
See [measured performance and limitations](codegraph_search_performance.md) for validation evidence.

This is an **optional, offline** native C extension to QIHSE. It receives
canonical structural relations from code-review-graph's multi-language
Tree-sitter index, stores complete immutable generations in QIHSE KV snapshots,
and reconstructs an authenticated immutable CSR query view for bounded impact
analysis. The private view interns strings and uses contiguous incoming/outgoing
edge indexes; it does not duplicate general property-graph indexes.

The general graph subsystem is separate. CodeGraph persists the complete original
records using QIHSE KV, including unknown metadata and unresolved relationships.
No CRG SQLite database or raw source-file bodies are copied into QIHSE.

## Native build

From the QIHSE repository:

~~~bash
make qihse-codegraph
make test-codegraph
~~~

This optional target needs libqihse.so, OpenSSL, json-c and Zstandard development files.
It does not add a new mandatory dependency to the main QIHSE library or to HAX.
On Debian: install libjson-c-dev, libssl-dev and libzstd-dev if not present.

Run with the QIHSE repo's libqihse.so on the loader path, or install that
library through the normal QIHSE procedure.

## Index pipeline

From the QIHSE checkout, use the rebuild wrapper for a progress bar and
compatibility with older CRG exporters:

~~~bash
./tools/qihse-codegraph-reindex --repo ../your-repository
~~~

With a CRG exporter that already emits the required v2 freshness fields, the
underlying pipeline can also be run in the source repository:

~~~bash
code-review-graph build
code-review-graph visualize --format qihse --repo .
qihse-codegraph import --repo . --input .code-review-graph/graph.qihse.jsonl
qihse-codegraph status --repo .
qihse-codegraph review --repo . --base HEAD~1 --depth 2
qihse-codegraph impact --repo . --file src/parser.c
qihse-codegraph query --repo . --symbol "parse_request"
qihse-codegraph context --repo . --symbol "parse_request" --max-tokens 1200
~~~

After changes, run CRG update + export + native import. HAX's graph_index
tool automates this sequence.

## Snapshot format and trust boundaries

The CRG exporter produces format qihse-codegraph-v1:

* Header: format/version, repository, HEAD revision, legacy worktree digest, and the explicit
  `git-status-diff-index-untracked-v2` freshness policy with its `worktree_v2` digest.
* Nodes: stable 128-bit public IDs under an explicit identity profile, repository-relative path, symbol/kind/line span.
* Edges: exact original source/target IDs, relation and source evidence,
  confidence/tier/resolution, and explicit traversable boolean.
* Trailer: record counts and SHA-256 of every preceding JSONL line.

The exporter uses raw GraphStore node/edge identities, not the visualization
exporter's heuristic ambiguity resolution. Missing, inferred, ambiguous and
low-confidence relationships are retained as non-traversable evidence.
An importer never promotes such records to authoritative graph edges.
This does NOT establish dynamic call coverage or absence of vulnerabilities.

Importer validations: bounded JSONL records, SHA-256, count reconciliation,
repo-relative paths, declared 32-hex public identities (64-hex for older fixtures), no duplicate keys, no
dangling trusted endpoints, and QIHSE graph construction before publish.

Native persistence stores QIHSE KV records under n:<nodeid> and e:<edgeid>,
and metadata under _meta/_end. QIHSE KV itself serializes the generation
to disk with its existing snapshot format and recovery-safe atomic file
operations. A manifest current.json is published only after the generation
is complete and fsynced. Old generations are immutable/readable after a
failed update.

State defaults to:
  $XDG_STATE_HOME/qihse/codegraph/<sha256(repository-root)>/
or ~/.local/state/qihse/codegraph/<hash>/.

The directory path derives from a hash to avoid leaking home-directory
names into audit and status outputs. Each CLI invocation creates a private,
temporary QIHSE_DATA_DIR to prevent touching the user's live QIHSE server
storage. No TCP listener is opened; the optional reader uses a local Unix socket.

## Source freshness and upgrades

The legacy `worktree` field remains SHA-256(status + NUL + binary HEAD diff), preserving the
canonical v1 export for existing consumers and byte-identical reference benchmarks. New readers
require the explicit v2 policy and validate **`worktree_v2`**, never the weaker legacy field.
Its digest additionally binds staged index entries and every nonignored untracked path, type and
content hash (a symlink binds its link target, not arbitrary external target bytes).
`.code-review-graph` is excluded to avoid self-invalidating exports. Ignored untracked files are
outside this snapshot policy. HEAD and digest are checked again before publication and after
query execution. Git index trust flags such as assume-unchanged, skip-worktree and fsmonitor-valid
produce an explicit unverifiable/stale result instead of trusting a potentially incomplete diff.

CRG also verifies stored source hashes before and after export. A stale GraphStore cannot gain
current Git metadata merely by being exported again: update/rebuild it first. Physical File records
without hashes, unavailable sources and inconsistent hashes are rejected. Native imports reject
old or unsupported freshness policies; re-run CRG update, export and import once after upgrading.
A restored old manifest remains subject to the same freshness checks; restoration is not permission
to label stale evidence fresh. For operational fallback, use the **current binary** without socket
flags or explicitly select `--fallback oneshot`; do not downgrade to the benchmark reference binary.

## Queries and performance

QIHSE's underlying graph store now maintains indexed outgoing and incoming
edge sets. Incident traversal and vertex deletion no longer scan the entire
edge table; complexity is proportional to incident degree, with filters and
bounded output. Self-loop handling and ascending edge ordering are preserved.

Without a reader socket, the CLI reconstructs a per-invocation graph from an immutable KV
generation. The optional resident reader retains that same graph between requests. Queries are
bounded to depth 1..5, 1..256 nodes, 64 changed files and an approximate context budget of
128..16000 tokens. Stale indexes (HEAD or Git worktree mismatch) **fail closed** for
query/impact/review/context and are reported by status.

For review, return impacted files, candidate tests, unverified test gaps,
relation evidence and explicit unresolved relation counts. Risk hints are
heuristic prioritisation scores, not probabilities or security guarantees.
Output may be truncated; that fact is always surfaced.

### Seed planning

The loaded generation has sorted node-ID, case-insensitive name and file indexes, plus a
vertex-to-node map. Edge endpoints use binary lookup instead of a linear node scan. Exact name,
qualified `path::name`, prefix and exact-file selection reuse the native indexes; substring
selection remains a scan. `--match auto` prefers an exact name and uses substring matching only
when no exact name exists and no qualifier was supplied. Use `--match substring` to request the
broader legacy behavior explicitly. Duplicate exact names remain distinct seeds; unrelated
substring names do not join an exact result. Output reports `seed_match`, seed count and ambiguity.

Bare impact/review means changes since HEAD. It is not an implicit whole-repository review.

### Optional resident reader

Choose a private runtime directory and resolve its paths at runtime:

~~~bash
runtime=$(mktemp -d)
qihse-codegraph serve --repo . --socket "$runtime/reader.sock" \
  --token-file "$runtime/reader.token" --idle-seconds 300
~~~

From another terminal, using the same resolved directory:

~~~bash
qihse-codegraph context --repo . --symbol GraphStore --match exact \
  --socket "$runtime/reader.sock" --token-file "$runtime/reader.token" --timings
~~~

The reader is optional; no service is automatically installed. It uses four fixed workers by
default (`serve --workers 1..4`) and a bounded pending queue of 16. Independent freshness checks
can overlap. Projection reads use immutable arrays and inherit the authenticated
principal; capability and generation synchronization remains in place. Requests
pin the immutable generation with a read lease; replacement takes an exclusive
lease and retires old memory only after readers finish. It retains one loaded generation and
refreshes it at request boundaries. Missing or invalid replacement manifests drop
access to the cached graph for that request and return an error, rather than serving an older
generation. Replacement clears the old resident view before validating the new
one; restoring a valid manifest permits it to be loaded again. Every data request checks Git freshness before
querying and rechecks the manifest, freshness and principal before releasing the response. This
detects changes across those checks; it does not lock Git or the publisher against subsequent changes.

Each graph walk inspects at most 65,536 edges, including filtered edges. Exhaustion
sets `truncated` and suppresses unverified test-gap hints. A batch contains at most
32 walks and is therefore bounded to 2,097,152 inspected edges. The established
2,048 matched-neighbor limit and response node/token limits still apply.

If a socket was requested, the default is `--fallback error`. Explicit `--fallback oneshot`
permits local reconstruction only for a missing/refused reader, not authentication, permission,
malformed-response or stale-graph failures. Without socket flags, the existing one-shot path
continues to work.

`--compact` selects the versioned `qihse.codegraph.search.v1` envelope: `status`, `generation`,
`fresh`, `strategy`, `strategy_reason`, `matches`, `relations`, `unresolved`, `truncated`, counts and
`timing_us`. It does not change query bounds. The default output retains the established native
shape. `--timings` adds measured authentication, capability authorization, snapshot verification,
KV loading, graph construction, pre/post freshness, lookup, traversal, serialization and total
elapsed milliseconds. Compact timings use microseconds. Warm requests report zero startup work;
these internal timings exclude client startup and socket queueing.

### Local protocol and security boundary

The Linux Unix-domain stream protocol accepts one newline-terminated JSON object per connection
and replies with one JSON object. Requests are bounded to 65536 bytes. Commands are `ping`,
`revoke`, `status`, `query`, `impact`, `review` and `context`; import is not a socket command.
A request carries `token` and `command`, with optional `repo`, `symbol`, `files`, `base`, `match`,
`depth`, `limit`, `max_tokens`, `compact` and `timings`. `symbols` accepts 1..32 symbols instead
of a single seed for a batched read. Batch output deduplicates nodes under one shared output
budget and preserves per-symbol results, including missing/ambiguous seeds and truncation.
`nodes` is a flat, deduplicated array, not an array of complete per-symbol reports. `symbol_results`
maps each requested symbol to retained node identities and truncation; `symbols` preserves request
order, including repeated symbols. The shared query builder returns owned JSON objects, so batching
does not serialize and reparse a full response for every symbol. Lookup and traversal are still
performed per distinct seed; overlapping output is deduplicated before the final wire serialization.
Retained nodes rank by closest hop, then stable identity, so requested roots outrank neighborhoods
under the shared node cap. Relations carry stable `from_id`/`to_id` endpoints and are emitted only
when both endpoints are retained; caller mappings are pruned consistently on eviction.
The CLI currently exposes a single `--symbol`; batch callers use the JSON protocol.

The socket and capability file are owner-only (0600), with distinct names in the same real
parent directory. Both endpoints verify same-UID `SO_PEERCRED`. Startup creates a random
256-bit capability; requests compare its 64-hex representation in constant time. An authenticated
`revoke` rotates it and invalidates the old value. The CLI refuses unsafe token ownership,
permissions and symlinks. Use a private parent directory even though the implementation permits
a shared one. A socket lock prevents a second reader from replacing an active instance.

This is an offline, same-user capability boundary, not a remote multi-tenant authentication
service. Each process creates an isolated QIHSE authentication realm and scratch data directory;
it does not reuse a server's credentials. Readers authenticate a Guest principal at clearance 0
with no SCI compartments, and propagate that principal through snapshot loading, KV reads and
iteration. Import rejects classified/SCI records rather than copying them into this public graph.
File permissions and the originating export still matter: the capability is not a substitute for
protecting the source repository or enforcing its access policy.

### Demand promotion and bounded resident memory

HAX records one logical graph/context tool access in a private per-repository sliding-window file.
The defaults promote on the third access in 60 seconds and start `serve --idle-seconds 600`.
Separate HAX processes share demand within the same owner-only runtime directory. Status/cache
validation and per-symbol cold fan-out do not count as additional accesses. Early accesses remain
functional one-shot queries; connected-reader authorization, stale and malformed responses never
silently fall back.

Managed readers use native options `--memory-limit-mib 1024`, `--pool-file PATH` and
`--pool-budget-mib 2048`. `RLIMIT_AS` is set before graph loading, so each reader has a hard
address-space ceiling. Pool admission serializes with `flock`, examines all POSIX record-lock
reservations, then acquires a disjoint byte range: one byte reserves one MiB. Its fd stays open for
the reader lifetime. Kernel locks release on idle exit or crash, eliminating a spawn-to-PID-ledger
accounting gap. Gaps can be reused and lowering the budget cannot admit around existing ranges
outside the new budget. A full, unsafe or contended pool refuses admission before loading the graph.

This conservatively bounds managed readers sharing one runtime pool, not manual readers outside
it, transient Git children or one-shot clients. Do not unlink the pool while readers are live.
Existing readers are never killed merely to lower a budget; new admissions remain cold until space
becomes available. A zero HAX budget disables new automatic starts but permits reuse. A reader that
cannot load within its cap also leaves the cold path available. Authentication and generation/source
verification are unchanged.

See HAX's `graph.reader.*` registry settings for thresholds, idle timeout, per-reader memory and
aggregate budget. Native one-shot commands do not install or implicitly create a pool.

### Performance limitation

One-shot startup still loads and reconstructs the generation. The resident path amortizes that
work, not Git freshness checks, bounded worker queueing or output construction. Git capture
uses `posix_spawnp` rather than copying the large resident process address space with `fork`.
Request framing has a five-second total receive deadline; partial bytes cannot extend it. Socket
send timeouts and bounded Git subprocess waits are not a whole-query wall-clock deadline.
Untracked-content hashing has a five-second aggregate verification budget; exhausting it returns
unverifiable/nonfresh without graph facts, never a partial digest labeled fresh. Regular files are
opened nonblocking without following symlinks and verified with `fstat` before hashing.
Client disconnects cannot terminate the server through SIGPIPE; traversal remains bounded, but
is not asynchronously interrupted when a client abandons its response. Substring queries still
scan names; traversal/output are bounded but do not establish complete coverage.
Neither path introduces a second persistent search store. See
[the measured comparison](codegraph_search_performance.md) before choosing deployment settings.

### Storage limitation

Each successful import currently retains its immutable KV generation.
Introduce bounded generational garbage collection only after a reference/
reader-lifetime protocol is established; do NOT delete a generation a
concurrent review process may have opened.

## Testing and acceptance

~~~bash
make test-graph
make test-codegraph
~~~

The CodeGraph integration fixture checks publication, loaded adjacency,
missing/ambiguous relations, staleness and corrupt-input rollback.
The same fixture also exercises auto exact/substring planning, duplicate-name ambiguity,
reader/one-shot parity, shared-budget batches, capability denial/rotation, abandoned clients,
generation replacement and corrupt-manifest refusal,
tracked/staged/untracked content staleness, Git trust flags, source/generation changes during a
query, interrupted-import rollback, and ENOSPC injection at snapshot and manifest publication.
It attempts a cross-UID peer-denial test only as root and explicitly skips it otherwise.
Classified/SCI imports are rejected without replacing the public generation or disclosing the marker
through read commands.

Prefix/qualified modes, explicit CLI fallback, unsafe-token denial and publication failure are
covered by the focused fixture. Remaining limits include adversarial publication/Git races beyond the
existing boundary checks, broad cross-language impact accuracy, and measured
token savings relative to tgrep plus targeted file reads. The focused fixture does not establish
complete-suite or production deployment acceptance; see the performance document for run evidence.

Review output is not a replacement for running tests or inspecting code.
Do not label uncertain relationships as verified.

## Compact storage and lifecycle maintenance

New imports default to `--storage-format auto`: one authenticated KV export is
encoded as `qihse-codegraph-zstd-v1`, `qihse-codegraph-packed-v2`, and
`qihse-codegraph-packed-v3`, and the
smaller complete file is selected (Zstandard wins ties). Packed encoding is skipped
above its 64 MiB decoded limit; streaming Zstandard remains available for larger
graphs. All codecs use Zstandard level 9; the optional CLI requires libzstd
development headers. The logical CRG format
remains `qihse-codegraph-v1`. Legacy KV snapshots remain readable. Reimporting
identical validated records reuses the current snapshot instead of appending a
new generation; a damaged current file is not reused.

For authenticated size accounting of the current generation:

```sh
qihse-codegraph stats --repo .
```

The response reports `encoded_bytes` (apparent snapshot size), `allocated_bytes`
(filesystem blocks assigned to that snapshot), and `decoded_bytes` (the legacy KV
byte count, or the compact container's declared decoded length after successful
authenticated loading). `coverage` is `authorized_current_generation`. It does not
sum rollback generations, historical snapshots, scratch files or filesystem
snapshots; those may contain records outside the reader's clearance. Do not use
this response as the total folder size or as a claim of bytes reclaimable by GC.
The counters come from the descriptor used for authenticated loading. A legacy
generation too large for the bounded immutable reader returns an accounting
error: its path-based fallback cannot bind size metadata to that authenticated
descriptor. Migrating it to compact storage permits accounting.

To convert the current stored graph without rebuilding CRG:

```sh
qihse-codegraph migrate --repo .
```

Migration authenticates legacy loading, writes a compact sibling, reopens it and
compares every key/value in both directions using canonical record fingerprints before switching `current.json`.
Source HEAD, freshness digests, counts and unresolved evidence are preserved. A
stale graph stays stale. The old snapshot is retained as `previous_snapshot` for
rollback. Migration and GC recognize both legacy decimal-PID filenames and
the newer six-character random suffixes. Conversion is per repository/current generation; historical snapshots
are not all rewritten. A failure before manifest publication leaves the old
snapshot current. If directory fsync fails after rename, inspect the manifest
before retrying; the potentially published file is retained.

Explicit `--storage-format packed-v3`, `--storage-format packed-v2` or `--storage-format zstd-v1` on `import` or
`migrate` forces a format. The reindex wrapper accepts these options and `auto`.
When authenticated current-generation byte accounting is available, automatic
migration keeps it if the candidate would be equal or larger, including changes
caused by reserialization order. Large legacy snapshots using the old path-based
loader lack that accounting and retain the existing verified conversion path.
Automatic selection spends additional encoding CPU and temporary space on three
candidates; use explicit Zstandard when those costs matter more than stored size.
The packed versioned frame
reconstructs the authorized live KV export exactly, including classification,
SCI, expiry, flags, sequence numbers and opaque JSON values. Before decoding,
the loader checks the manifest-declared snapshot checksum against the same open descriptor and
checks the reader's clearance against every record label; the decoded stream
then passes through QIHSE's authenticated KV loader. Migration compares full
record metadata without depending on export order. The packed codec currently
accepts at most 64 MiB of decoded KV data; larger graphs use the streaming
Zstandard path. Packed-v2 is selected only when smaller because its measured size depends
on graph shape and can exceed Zstandard on small graphs.
In the three-pair authenticated 800-node/2,400-edge synthetic comparison,
packed-v2 used 182,355 apparent bytes versus 187,857 for the current level-9
Zstandard container (2.93% less); a 16-node fixture was 33 bytes larger.
The [method](../../benchmarks/codegraph_packed_method.md) and
[receipts](../../benchmarks/codegraph_packed_literal_reference.json) include
exact record and native-query parity. They do not predict savings on a live
repository. [Zstandard tuning](../../benchmarks/codegraph_zstd_tuning_medium_20261106.json)
also found a 10.2% size reduction at level 19 on that synthetic fixture, with
roughly 36 times the level-9 encode CPU, so the default remains level 9.
On the selected fresh Angryier graph, packed-v2 was 7,798,284 bytes against
the existing 7,534,503-byte Zstandard snapshot (3.50% larger). Four
authenticated query responses matched apart from generation IDs. The graph
was migrated back to Zstandard; the newly serialized snapshot was 8,043,696
bytes.

Each successful import or migration prunes older managed snapshots and abandoned
leased runtime directories under the exclusive storage lock, after durable
manifest publication. The current and `previous_snapshot` generations remain
for rollback. A failed publication does not prune anything; an interrupted
cleanup can leave older files, and a successful publication then reports
`retention_warning`. Repeating the command or running GC can finish cleanup.
Active runtimes, unleased legacy directories, and unknown files remain untouched.

To collect orphan generations and inactive leased runtime directories:

```sh
qihse-codegraph gc --repo .
```

GC deletes historical managed snapshots except the current and
`previous_snapshot` generations. It is not an archive-preserving operation.
GC first authenticates and validates
the current graph. New readers, publishers, converters and GC coordinate through
a permanent `.storage.lock`; runtime scratch directories hold a `.lease` lock.
GC skips active scratch and old scratch without a lease. Before migration or the first GC,
stop any older CodeGraph binaries/readers: those versions do not participate in
these locks. Do not remove the lock files manually.

The compact container preserves the authorized legacy KV serialization, including
security labels. Its decoder rejects oversized, corrupt, truncated and trailing
frames. CodeGraph opens snapshots of at most 64 MiB decoded data and 150,000 records
through a bounded authenticated stream into an immutable KV handle. This avoids
expanded temporary files and runtime SST restoration for those reads. Larger
snapshots retain the disk-backed loader; only byte/record-limit errors trigger
fallback, never authorization or malformed-input errors. The memory path retains
record values in RAM, so its limits are deliberate. Exports and large-graph
fallback still use private temporary files, removed on normal completion. Legacy
abandoned runtime directories require separate reviewed cleanup because they have
no lease.

The 150,000-record limit was chosen from three alternating paired runs on the
selected Angryier graph (8,853 nodes, 114,689 edges; 54,478,835 decoded bytes).
With exact JSON equality, median one-shot status fell from 11.93 to 8.50 seconds
and query of `main` from 23.82 to 12.37 seconds. Sampled process writes fell
from 163,446,624 to 10,061 bytes, while peak RSS rose by roughly 26 MiB for
status and 50 MiB for query. These are measurements for this graph and host;
the 64 MiB decoded limit remains unchanged.

Allocated ZFS bytes, apparent file sizes and bytes reclaimed after deletion are
different measurements. Filesystem snapshots can retain deleted blocks. Measure
both `du -sh` and `du -sh --apparent-size`; do not infer physical savings from the
compression ratio alone.


## Query and property-index efficiency

Property indexing hashes the complete composite key, including its NUL-separated
label, property name and value. Stored key lengths are checked before comparison.
Previously, C-string hashing used only the label, producing collision chains for
same-kind nodes and a potential out-of-bounds comparison of unequal-length keys.

Bounded queries encode seed/visited/hop state in one byte per node rather than
allocating a second distance array and clearing the first array between phases.
Review aggregation visits the admitted, ID-sorted queue (at most the query limit)
instead of scanning every node again. Traversal ordering, truncation, evidence,
authorization and source freshness checks remain unchanged.

`tests/bench_codegraph_query_algorithm.py` compares exact JSON outputs before
reporting per-case query timings on synthetic graphs. It excludes Git/auth/storage
work, so its speedups are not end-to-end request speedups.
`tests/test_graph_property_index.c` measures same-label property insertion and
lookup while verifying every returned vertex. The optional `--bench FILE
memory|disk` mode of `tests/test_codegraph_memory` compares snapshot loading with
fresh isolated runtimes; its `write_bytes` metric is process logical writes, not
physical ZFS allocation. OS cache is not dropped. These isolated measurements must
not be treated as predictions for all live repositories.

Measured synthetic results (raw samples and conditions in
`benchmarks/codegraph_storage_optimization.json`):

| Workload | Before | After |
| --- | ---: | ---: |
| Build property indexes for 8,000 same-kind vertices | 6,825.6 ms | 36.0 ms |
| Verify all property lookups on those vertices | 4,064.6 ms | 11.8 ms |
| Sparse bounded review in a 100,000-node graph | 1.498 ms | 0.0728 ms |
| Load 50,000 stored KV records | 1,245.8 ms | 308.0 ms |
| Process logical writes during that load | 109,839,910 bytes | 0 bytes |

The loader retained about 26 MiB more RSS on that fixture; both modes peaked near
60 MiB. The property index adds one `size_t` per hash bucket for key length.
High-degree query timings varied between runs, so no improvement is claimed for
that case. These numbers isolate different operations and must not be multiplied
into a claimed combined speedup.

For local builds, ensure the test/CLI process selects the newly built library:

```sh
LD_LIBRARY_PATH="$PWD" ./qihse-codegraph status --repo .
```

An inherited `LD_LIBRARY_PATH` pointing at a separately installed older library
can otherwise override the executable's runpath and fail on the new snapshot API.


A separate varied synthetic storage fixture (50,000 nodes, 100,000 edges,
SHA-256 IDs, varied paths and evidence fields) measured 79,662,422 bytes of legacy
KV records versus 19,056,786 bytes of compact storage at level 9. This is a 76.1%
logical-size reduction. Level 3 produced 21,209,959 bytes; level 12 produced
18,426,123 bytes but required over twice level 9's compression CPU. Three
interleaved repetitions at each level round-tripped byte-for-byte. Reproduce with
`python3 tests/bench_codegraph_compression.py`. This motivates
the space-focused level-9 default; it does not predict physical ZFS savings.

To rebuild the source index and publish a fresh compact graph with a stage
progress bar, run from the QIHSE checkout:

```sh
./tools/qihse-codegraph-reindex --repo ../your-repository
```

The bar reports three completed stages: rebuild, export, and authenticated
compact import. On a terminal, an elapsed-time activity indicator runs while each
stage is working. After a successful run for the same repository, it also shows
an approximate ETA based on up to three completed stage timings, scaled by the
authenticated current-generation size (capped to avoid extreme extrapolation).
The first run shows "ETA calibrating"; a failed or interrupted run is never used.
The ETA does not measure progress within a stage and can change when the source
or workload changes. Timing history is kept separately under the XDG state directory.
The wrapper
uses the exporter's reported path, including custom CRG data directories.

The wrapper checks HEAD, staged entries and tracked/untracked source state before
the rebuild and after export. If they differ, publication stops. For older CRG
exporters, it verifies the exported checksum and source identity, adds the required
v2 freshness fields to a temporary export, and recomputes its checksum. The native
importer still performs all structural, authorization and freshness checks.
Failures leave the previous QIHSE generation available.

For conversion alone, with the same progress display:

```sh
./tools/qihse-codegraph-reindex --migrate-only --repo ../your-repository
```

This mode preserves the indexed source revision and freshness; it does not rebuild
the CRG index. An already compact graph returns `unchanged`.
For the bounded packed-v2 pilot, append `--storage-format packed-v2`. The
stage bar still reports completion only after the new generation is verified
and published; the previous generation remains available as rollback.

### Dense dictionary references

Packed-v3 stores exact full IDs and repeated strings in a shared dictionary and
encodes occurrences as dense varints. It preserves unknown metadata and the exact
export; IDs sharing 128-bit prefixes remain distinct. SHA-256 snapshot verification
and authenticated label checks remain mandatory. The 64 MiB decoded bound remains.
See [compact references](../plans/codegraph_compact_references.md) for identity,
compatibility and validation details.

### Fresh-build 128-bit public IDs

New exports declare `qihse-semantic-xxh3-128-v1`, `xxh3-128`, seed zero,
canonical xxHash byte encoding and the bounded `counter-xxh3-128-v1` collision policy. Nodes and edges use 32 lowercase hex
characters; packed-v3 stores them as 16-byte dictionary entries under an explicit
feature bit. Source/snapshot SHA-256 and capability widths retain their cryptographic
contracts. All previous live graphs were lost; fresh builds use this profile by
default. See [the format and validation](../plans/codegraph_public_ids128.md).

The producer uses bounded native XXH3 batches with one cached backend selection.
See [tuned hashing and measured results](../plans/codegraph_xxh3_tuned.md).

### Snapshot checksum and bounded retention

New CodeGraph snapshots use tuned `xxh3-128` checksums, explicitly stored as
`snapshot_hash_algorithm` and a 32-hex `snapshot_hash`. Source/trailer hashes remain
SHA-256. Per repository, durable publication retains current and one previous
snapshot; validated no-op operations and GC apply the same retention. Failed
pre-commit publication removes its unreferenced candidate. See
[implementation and tests](../plans/codegraph_snapshot_xxh3.md).
