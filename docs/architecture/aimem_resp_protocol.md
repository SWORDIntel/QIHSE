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
QH-01 scoped identity and QH-02 typed event journaling remain planned.

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
