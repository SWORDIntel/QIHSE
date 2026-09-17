# Consistency Classes

> **Status: implemented** — class semantics, local-safe/strong classification,
> and the writability table are verified by `tests/test_federation_f1.c`.

Every QIHSE namespace declares one of five consistency classes. Write
authorization is determined by **consistency class + namespace authority**,
never by global cluster status.

```c
typedef enum {
    QIHSE_CONSISTENCY_LOCAL = 0,
    QIHSE_CONSISTENCY_EVENTUAL,
    QIHSE_CONSISTENCY_CAUSAL,
    QIHSE_CONSISTENCY_QUORUM,
    QIHSE_CONSISTENCY_LINEARIZABLE
} qihse_consistency_class_t;
```

## LOCAL

Authoritative on one node. Always writable, including under complete network
isolation. Examples: live local CPU temperature, local VM runtime observation,
local device discovery, host-local logs.

## EVENTUAL

Multi-writer and convergent. Writable while isolated; divergence is reconciled
later. Examples: non-critical telemetry, historical annotations, inventory
enrichment, cached search metadata.

## CAUSAL

Preserves causality while allowing disconnected operation. Examples: state
transitions where event order matters, operator annotations, desired-state
edits not involving exclusive ownership.

## QUORUM

Requires configured replica acknowledgement, scoped to a **replication group**
rather than the whole federation. Examples: durable cluster configuration,
security-policy changes, node enrollment, trust-store changes.

## LINEARIZABLE

Strict serialization for small, high-value namespaces only. Examples: execution
ownership epochs, exclusive resource lease records, revocation epochs.
Bulk telemetry must never route through this path.

## Writability

`qihse_federation_namespace_writable()` decides whether a namespace is writable
on this node right now, given the namespace record, the federation state, and
the local node id.

| Class | CONNECTED | DEGRADED | ISOLATED | FENCED |
|---|---|---|---|---|
| LOCAL | yes | yes | yes | yes |
| EVENTUAL | yes | yes | yes | yes |
| CAUSAL | yes | yes | yes | yes |
| QUORUM | yes | yes | no | no |
| LINEARIZABLE | yes | no | no | no |

The isolated and fenced columns are the point: strong namespaces fail closed
while local-safe ones keep working.
