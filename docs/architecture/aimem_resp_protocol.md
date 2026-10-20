# Authenticated AI-memory RESP protocol

`AIMEM` is the network adapter for QIHSE's native AI-memory API. It is kept
separate from Redis-compatible `MEMORY` commands so clients cannot accidentally
select a process-memory feature instead of durable, indexed memories.

Every command requires a live authenticated principal. The native AI-memory
implementation remains authoritative for tenant scope, classification, SCI,
ranking, and record visibility. A missing or revoked principal fails closed.

## Commands

```text
AIMEM STORE <kind> <text> [idempotency-key]
AIMEM STORE-DURABLE <kind> <text> [idempotency-key]
AIMEM RECALL <query> <limit> [bm25|semantic|hybrid] [kind]
AIMEM GET <uuid>
AIMEM FORGET <uuid>
AIMEM FORGET-DURABLE <uuid>
AIMEM COUNT [kind]
AIMEM STORE-SCOPED[-DURABLE] <kind> <text> <project> <worktree> <workstream> <session> [idempotency-key]
AIMEM RECALL-SCOPED <query> <limit> [bm25|semantic|hybrid] <kind> <project> <worktree> <workstream> <session>
AIMEM GET-SCOPED <uuid> <project> <worktree> <workstream> <session>
AIMEM FORGET-SCOPED[-DURABLE] <uuid> <project> <worktree> <workstream> <session>
AIMEM COUNT-SCOPED <project> <worktree> <workstream> <session> [kind]
AIMEM MIGRATE-LEGACY <uuid> <project> <worktree> <workstream> <session>
AIMEM EVENT APPEND <project> <worktree> <workstream> <session> <producer> <event-id> <event-kind> <source-ms> <summary> [source-evidence-uuid]
AIMEM EVENT READ <uuid> <project> <worktree> <workstream> <session>
AIMEM PROJECT GRANT <project> <reader-user-id>
AIMEM PROJECT REVOKE <project> <reader-user-id>
AIMEM HANDOFF OFFER <recipient-user-id> <ttl-ms> <project> <worktree> <workstream> <session> <summary>
AIMEM HANDOFF GET <uuid>
AIMEM HANDOFF ACCEPT <uuid> <expected-revision>
AIMEM HANDOFF CANCEL <uuid> <expected-revision>
AIMEM KNOWLEDGE CREATE <type> <status> <content> <project> <worktree> <workstream> <session>
AIMEM KNOWLEDGE REVISE <knowledge-id> <expected-version-id> <expected-revision> <status> <content>
AIMEM KNOWLEDGE GET <version-id> <project> <worktree> <workstream> <session>
AIMEM KNOWLEDGE LATEST <knowledge-id> <project> <worktree> <workstream> <session>
AIMEM KNOWLEDGE AS-OF <knowledge-id> <ingestion-time-ms> <project> <worktree> <workstream> <session>
```

`kind` is `1` for episodic or `2` for semantic; `0` selects either kind for
reads. Recall returns bounded nested arrays containing the UUID, creation time,
kind, classification, SCI, score, and text. Text is transported as a RESP bulk
string, so delimiters inside memory content are preserved.

Replies: `STORE` returns the new (or replayed) UUID as a bulk string; `GET`
returns the same 7-field nested array as a recall hit; `FORGET` returns a
RESP integer — `1` when the record was deleted, `0` when the id is unknown
or already gone; `COUNT` returns a RESP integer. Errors are `-ERR …`, and
authentication failures are `NOAUTH`/`NOPERM` as everywhere else.

`EVENT APPEND` accepts the registered kinds `session_start`, `session_end`,
`task_started`, `task_completed`, `observation`, `decision`, `blocker`, and
`checkpoint`. Producer and event IDs are bounded ASCII tokens; summaries are
limited to 16 KiB. QIHSE binds the authenticated actor, tenant, project scope,
classification/SCI and receive timestamp, stores a SHA-256 summary digest, and
fsyncs the KV store before returning the deterministic event UUID. Replaying
the same producer/event ID with identical immutable fields returns the same
UUID; conflicting source time, kind or summary fails. Event records use schema
`QHEV1` (or `QHEV2` when it carries evidence) and status `observed`; unsupported event kinds are rejected. `EVENT
READ` returns the normal authorized hit shape and revalidates the envelope
digest. `make test-aimem-durable-crash` kills the process after the durable
append result is produced but before the simulated client receives it;
restart/replay returns the same UUID and conflicting reuse stays denied.
An optional source-evidence UUID is accepted only when it resolves to a memory
record visible to the authenticated actor in the exact event scope; the UUID is
persisted in the immutable event envelope and participates in replay matching.
Admission is synchronous and bounded: the RESP server limits active clients and
request bytes, event summaries are capped at 16 KiB, and requests wait on the
server's bounded lock/fsync path. There is no unbounded in-memory event queue;
clients should retry a closed/failed request with the same producer/event ID.

## Claim-once handoffs (QH-03, first slice)

`AIMEM HANDOFF OFFER <recipient-user-id> <ttl-ms> <project> <worktree>
<workstream> <session> <summary> [evidence-uuid ...]` creates a tenant-local, durable `QHH2`
record and returns its UUID. QHH1 records remain readable. Up to eight evidence IDs may be attached; each must resolve to a visible memory record in the exact scope, and the IDs are returned as a nested array. The offering principal must own an in-project
record (or be an Operator), the named recipient must be active in the same
tenant, and that recipient must hold an active project-reader grant. The scope
and summary are bounded tokens/text; the server binds the owner, labels, SCI
compartment, creation time, expiry and revision.

`GET`, `ACCEPT <uuid> <expected-revision>`, and `CANCEL <uuid>
<expected-revision>` expose the state machine. Only the owner may cancel; only
the named recipient with a current reader grant may accept. A transition runs
under the server KV write lock, requires `OPEN`, the supplied revision and an
unexpired offer, then writes and fsyncs the new record before reply. Repeating
the same recipient's lost-ACK accept at the immediately preceding revision
returns `ACCEPTED`; accepted handoffs remain accepted and queryable rather
than being re-offered automatically. Other callers receive a generic conflict
or null reply, without a handoff summary. An authorized GET persists an OPEN to
EXPIRED transition with a revision increment and fsync before returning it.

The current lock and KV compare-and-set provide claim-once behavior across
processes. The regression races 100 in-process callers and forked TCP clients,
verifying that the authorized recipient receives the durable accepted result
while a competing principal is denied. The crash regression kills the server after durable
acceptance but before delivering the simulated reply; restart returns the same
`ACCEPTED` result to the recipient's retry and hides the record from a
competitor. Handoff evidence pointers are bounded and authorization-checked;
expiry is persisted with a revision increment before the state is returned.

## Curated knowledge lineage (QH-04, first slice)

Each knowledge object is one tenant-prefixed `QHK1` ledger containing a
bounded sequence of immutable logical versions. A revision compares the
expected head version and revision, closes the predecessor's half-open ingest
interval, marks it superseded, and appends the successor through one
authorization-aware KV compare-and-set. The single-record replacement avoids
an observable predecessor/successor half-state. RESP create and revise fsync
the KV store before returning the 15-field version array.

`GET` retrieves an exact historical version, `LATEST` returns only the current
version, and `AS-OF` evaluates ingestion-time intervals as `[from,to)`. These
timestamps describe when QIHSE knew a version; they do not claim when it was
true in the external world. All reads require an explicit principal and scope,
use tenant-prefixed authorized enumeration or direct lookup, and recheck
project membership. A protected record returns the same null response as a
miss. Project reader grants remain read-only. Only an Operator may create or
revise directly into `APPROVED`; other principals can create `PROPOSED`
versions.

The `QHK1` parser validates UUID lineage, consecutive revisions, predecessor
closure, status values, scopes, content encoding and an 8 MiB ledger bound.
`make test-aimem-knowledge` covers a simultaneous two-writer CAS race,
historical and as-of reads, grant/revoke, tenant/scope/NULL-context denial and
a low-clearance principal with valid project membership attempting exact and
latest reads of high-label data. `make test-aimem-resp` repeats the classified
direct-ID negative through the wire adapter.

QH-04 remains partial: source-event IDs and validation, SHA-256 content hashes,
confidence and reviewer/generator fields, typed relation edges, content-free
audit records, retry identity and crash-boundary recovery still need to land.

## Project scope (QH-01, first slice)

Scoped commands require a project identifier; worktree, workstream and session
are optional narrowing coordinates represented by empty arguments. Identifiers
are opaque, bounded ASCII tokens (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`). QIHSE
requires a complete parent chain: a workstream requires a worktree, and a
session requires both. Project queries include descendants; each supplied
coordinate narrows the result and sibling coordinates remain isolated.
Malformed child-only scopes are rejected before lookup or ranking. QIHSE
stores the authenticated actor ID and coordinates in a versioned canonical
record. Scope strings do not grant authority: KV classification/SCI checks
still run first, and a scoped record is available to its owner, a project
reader with an explicit durable grant, or an Operator query. A typo is an
empty scope, never a fallback to global memory.
Scoped canonical keys are tenant-prefixed (`t:<tenant>/aimem:`), and scoped
idempotency mappings use the same namespace. The legacy unscoped public C APIs
and RESP verbs are system-tenant-only; tenant callers must provide explicit
project scope. This prevents same-clearance principals in different tenants
from colliding through the raw KV layer, which authorizes labels but does not
automatically namespace native keys.

Legacy records remain unassigned until an active system Operator invokes
`MIGRATE-LEGACY` with the exact UUID and complete destination scope. Migration
preserves UUID, creation time, kind, content, classification and SCI; it
durably fences the destination before deleting and fencing the source. An
exact retry completes or confirms the move, while a mismatched destination
fails closed. Historical unscoped idempotency mappings are not redirected
across scopes, so replaying their old `STORE` request after migration returns a
conflict. Legacy global `RECALL`, `GET`, `COUNT` and `FORGET` do not include or
expose scoped records; a scoped query never guesses coordinates for an old
record. Scoped BM25 recall builds its ranking corpus
only from records that passed the authenticated KV enumeration, actor check,
scope match and optional kind filter. Thus out-of-scope or high-label records
cannot change scoped ranking statistics or occupy top-K slots. Direct-ID get
and forget repeat the same scope and actor checks.

Scoped BM25 and vector recall construct their ranking candidates only from the
authorized matching scope. Hybrid mode fuses those two scoped rankings. The
current implementation rebuilds a bounded in-memory candidate corpus per
request; persistent per-scope indexes are a performance follow-up.
`PROJECT GRANT` can be issued by an active principal that owns a record in the
project, and only to an active principal in the same tenant. The grant conveys
read membership only; each record's classification and SCI authorization still
apply, and a grantee cannot forget another owner's record. Grant and revoke
changes are fsynced before `OK`. The crash regression starts with a durably
written destination and retained legacy source, then proves restart/retry
finishes deletion and preserves the scoped record. Persistent per-scope indexes
and restart/load evidence for the hierarchy remain open QH-01 work.

The optional idempotency key is scoped to the authenticated principal and
returns the original UUID **only when both the memory kind and exact text
match** the original. Reusing a key with different kind/content (or a stale,
deleted or inaccessible target) returns `-ERR CONFLICT`; it never silently
replaces an earlier memory. RESP key lookup, admission and mapping are
serialized under the server KV write lock, including concurrent agent retries.
A caller never supplies the UUID: QIHSE still owns identifier generation.

## Embeddings and ranking

`RECALL`'s `semantic` and `hybrid` modes rank with the active AI-memory
embedder. The built-in embedder (`builtin-lexical-256`) is a deterministic
lexical hash — it exists so the pipeline is testable with no model present,
and its similarity reflects shared vocabulary, not meaning. A real model is
installed with `qihse_ai_memory_set_embedder()`; the standalone
`qihse-redis-server` does this at startup via `--embedder-onnx DIR` (or
`QIHSE_AIMEM_EMBEDDER_ONNX`), which loads an ONNX BERT-family model plus its
`vocab.txt`. Install failure is fatal: the server refuses to serve rather
than silently downgrading `semantic` to the lexical hash.

Vectors are stored bound to the embedder name that produced them, and
vectors from differently named embedders are never compared — comparing
embeddings from different models yields confident nonsense rather than an
error. Changing the model therefore requires re-storing (or re-ingesting)
memories to re-embed them. Every ranking mode still resolves candidates
through the same authorization-aware path; an embedding is derived from the
text and can leak it, so no mode can rank, score, or count a record the
principal cannot see.

## Durability — two distinct acknowledgement contracts (QH-00 partial)

The original `STORE` and `FORGET` commands preserve their **eventually
durable** acknowledgement semantics. A successful legacy reply says that the
KV operation was accepted, not that it survived power loss or immediate
`SIGKILL`. No caller may treat a legacy acknowledgement as an fsync receipt.

`STORE-DURABLE` and `FORGET-DURABLE` are additive, synchronous commands.
They return the same UUID bulk string and integer result shapes, respectively,
as the matching legacy commands, but only after
`qihse_kv_sync_store()` succeeds. The existing KV fence flushes the WAL
stdio buffer, `fsync`s it, commits the memtable to fsynced/renamed SSTables
when needed, and `fsync`s the storage directory. The fence occurs while
the RESP server holds its KV write lock. It covers the memory record or
tombstone, any successful vector write, and its idempotency mapping.

A failed fence responds `-ERR NOT_DURABLE`, **not** a success reply.
The command may already have modified memory; the failure is not a rollback.
Retry with an unchanged idempotency key after investigating the durability
failure, and do not advance an upstream export/outbox cursor until a durable
success. No ordinary AIMEM ACK certifies quorum/remote replication, and the
local durability guarantee assumes the underlying filesystem/storage honors
`fsync` and rename semantics.

**Pre-ACK recovery (QH-00 second slice):** for new requests with an
idempotency key, QIHSE derives a deterministic canonical UUID using the
existing SHA-384 federation UUID helper, namespaced by authenticated
tenant, principal and key. Before allocating a new memory, the native store
checks this UUID's KV entry and refuses conflicting kind/text or full UUID
mismatches. After a crash between the primary record write and the separate
idempotency-map write, a retry locates the original document, verifies its
content and repairs the missing map. Legacy random UUIDs with existing
idempotency mappings retain their original IDs; no migration rewrites them.

**Remaining QH-00 work:** this is **recoverable identity**, not atomic
multi-key commit. Durable ACK still certifies only the local KV fence, not
remote replication. Complete WAL-phase fault injection (including partial
I/O errors and fsync faults), receipt/LSN design, idempotency-map migration
behaviour, and measured P50/P95 fsync overhead remain required before
declaring QH-00 complete. A failed admission may already have left a primary
record; the caller must retry with the same key, not invent a new key.
Deterministic identity binds to the authenticated numeric tenant/principal
IDs, which must be restored consistently across process restarts.

Index rebuild is derived from authoritative KV documents; a durable ACK
does not certify semantic-index freshness if embedding/indexing fails.
QH-01 through QH-04 have partial implementations with their remaining gates
tracked in `ROADMAP.md` and `QIHSE_ENGINE_ROADMAP.md`.

## Operational properties

- Search modes share one authorization-aware candidate resolution path; hidden
  records cannot affect ranking, counts, or result cardinality.
- Limits are bounded at the protocol boundary to protect search latency and
  memory use.
- Callers can use stable source IDs and a durable export cursor outside QIHSE
  for resumable ingestion. A cursor must advance only after QIHSE acknowledges
  the corresponding store operation.
- A Supermemory mirror is optional and must be treated as an outbox/secondary
  sink. A mirror failure does not roll back a committed QIHSE memory.

The adapter must never open QIHSE storage files directly. Export and ingestion
must run through an authenticated protocol or SDK principal, with a negative
low-clearance/high-data test before automation is enabled.
