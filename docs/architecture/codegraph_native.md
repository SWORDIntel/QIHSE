# Native QIHSE CodeGraph (structural code review)

**Status:** Feature branch; native import and review paths require local build/runtime validation.

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

* Header: format, version, HEAD revision and SHA-256 of Git porcelain status.
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
storage (especially /opt/qihse-data). No network listener is opened.

## Queries and performance

QIHSE's underlying graph store now maintains indexed outgoing and incoming
edge sets. Incident traversal and vertex deletion no longer scan the entire
edge table; complexity is proportional to incident degree, with filters and
bounded output. Self-loop handling and ascending edge ordering are preserved.

The CodeGraph CLI reconstructs a per-invocation graph from an immutable KV
generation. Queries are bounded to depth 1..5, 1..256 nodes, 64 changed files
and approximate context budget. Stale indexes (HEAD or Git worktree mismatch)
**fail closed** for impact/review/context and are reported by status.

For review, return impacted files, candidate tests, unverified test gaps,
relation evidence and explicit unresolved relation counts. Risk hints are
heuristic prioritisation scores, not probabilities or security guarantees.
Output may be truncated; that fact is always surfaced.

### Performance limitation

Loading the QIHSE snapshot per CLI invocation is linear in graph size. This
is a minimum native integration without a permanently running service.
If repeated queries prove too expensive on very large repositories, add
an optional in-memory daemon over a local Unix domain socket that retains
the indexed graph by generation. Do not introduce that complexity until
measured query latency justifies it.

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
Additional required live tests: large-repository startup latency, concurrent
import and readers, source changes during CRG export, signal interruption,
disk-full publication failure, cross-language impact accuracy and measured
token savings relative to tgrep plus targeted file reads.

Review output is not a replacement for running tests or inspecting code.
Do not label uncertain relationships as verified.
