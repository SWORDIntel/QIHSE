# Native QIHSE CodeGraph (structural code review)

**Status:** Native import, indexed queries and an optional local resident reader are implemented.
See [measured performance and limitations](codegraph_search_performance.md) for validation evidence.

This is an **optional, offline** native C extension to QIHSE. It receives
canonical structural relations from code-review-graph's multi-language
Tree-sitter index, stores complete immutable generations in QIHSE KV snapshots,
and reconstructs an indexed QIHSE property graph for bounded impact analysis.

The primary graph subsystem's vertex/edge store remains in-memory.
CodeGraph supplies the previously missing persistence layer using QIHSE KV.
No CRG SQLite database or raw source-file bodies are copied into QIHSE.

## Native build

From the QIHSE repository:

~~~bash
make qihse-codegraph
make test-codegraph
~~~

This optional target needs libqihse.so, OpenSSL and json-c development files.
It does not add a new mandatory dependency to the main QIHSE library or to HAX.
On Debian: install libjson-c-dev and libssl-dev if not present.

Run with the QIHSE repo's libqihse.so on the loader path, or install that
library through the normal QIHSE procedure.

## Index pipeline

In the source repository you intend to analyse:

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
* Nodes: stable SHA-256 IDs, repository-relative path, symbol/kind/line span.
* Edges: exact original source/target IDs, relation and source evidence,
  confidence/tier/resolution, and explicit traversable boolean.
* Trailer: record counts and SHA-256 of every preceding JSONL line.

The exporter uses raw GraphStore node/edge identities, not the visualization
exporter's heuristic ambiguity resolution. Missing, inferred, ambiguous and
low-confidence relationships are retained as non-traversable evidence.
An importer never promotes such records to authoritative graph edges.
This does NOT establish dynamic call coverage or absence of vulnerabilities.

Importer validations: bounded JSONL records, SHA-256, count reconciliation,
repo-relative paths, UUID-style 64-hex identities, no duplicate keys, no
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
can overlap, but native graph API calls remain serialized because iterator thread safety is not
promised. Requests pin the immutable generation with a read lease; replacement takes an exclusive
lease and retires old memory only after readers finish. It retains one loaded generation and
refreshes it at request boundaries. Missing or invalid replacement manifests drop
access to the cached graph for that request and return an error, rather than serving an older
generation. A failed replacement does not destroy the previously validated in-memory generation;
restoring its manifest makes it usable again. Every data request checks Git freshness before
querying and rechecks the manifest, freshness and principal before releasing the response. This
detects changes across those checks; it does not lock Git or the publisher against subsequent changes.

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
