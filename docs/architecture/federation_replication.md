# Federation Replication

> **Status: implemented** — manifests, sync plans, the pluggable transport, the
> loopback transport, and resumable digest-verified range transfer are verified
> by `tests/test_federation_repl.c`.
>
> **Contradiction:** the "What is not implemented" section below is stale. The
> transport that carries ranges, the bounded resumable cursor, and checksum
> verification of transferred data all exist in
> `src/federation/qihse_federation_repl.c`.

## Anti-entropy model

Gossip is useful for liveness but is not sufficient as the only replication
correctness mechanism, so reconciliation is explicit:

```
periodic peer reconciliation
    -> compare namespace/root summaries
    -> identify divergent ranges
    -> exchange generation/HLC digests
    -> transfer missing events/objects
    -> verify checksums
```

## Namespace manifests

A manifest covers a namespace with SHA-384 range digests over sorted object
IDs, so peers can identify divergent ranges without transferring the dataset.

```c
typedef struct {
    char range_start[64];
    char range_end[64];
    uint64_t object_count;
    uint8_t digest[48];
} qihse_federation_manifest_entry_t;
```

`qihse_federation_manifest_build()` produces one; `_compare()` reports the
number of divergent ranges and writes them out. Comparison is deterministic:
the same two manifests always produce the same divergence count and digests,
which is what makes a merge outcome reproducible.

## Sync plans

`qihse_federation_sync_plan()` classifies each range:

| Action | Meaning |
|---|---|
| `QIHSE_SYNC_SEND` | local has objects the peer lacks |
| `QIHSE_SYNC_FETCH` | the peer has objects local lacks |
| `QIHSE_SYNC_CONFLICT` | both have objects and they diverge |

## What is not implemented

> **Section status: partial — this list is stale.** The transport, the
> resumable cursor and checksum verification all exist in
> `src/federation/qihse_federation_repl.c`. See the contradiction note at the
> top of this document.

- The transport that carries ranges between peers.
- Rate limiting and resumable transfer (the plan is a plan, not a cursor).
- Checksum verification of transferred data, because nothing is transferred.

A node offline for days can currently be *compared* against a peer but not
*repaired* from one. That gap is the remaining work in this stage.
