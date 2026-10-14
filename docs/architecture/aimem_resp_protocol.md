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
AIMEM RECALL <query> <limit> [bm25|semantic|hybrid] [kind]
AIMEM GET <uuid>
AIMEM FORGET <uuid>
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
returns the original UUID when a request is replayed. It is deliberately not a
caller-supplied memory UUID: QIHSE still owns identifier generation and record
layout.

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

## Volatility

The standalone server's AI-memory store is process-lifetime: a restart
empties AIMEM records and vectors (the durable path is the mesh/upstream
authoritative store, consumed through the export cursor). Callers must
re-ingest after a restart; the idempotency key makes that replay safe.

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
