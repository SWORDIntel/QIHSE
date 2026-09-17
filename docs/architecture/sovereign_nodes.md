# Sovereign Nodes

> **Status: implemented** — the two-identity model and local survivability under
> isolation are verified by the S1/S4 scenarios in `tests/test_federation_f8.c`.

Every QIHSE node has two simultaneous identities:

```
LOCAL DATABASE      authoritative for permitted local namespaces
FEDERATION MEMBER   exchanges replicated/global state with peers
```

Cluster state is visible to clients but must never be conflated with database
usability.

## Operating modes

```
CONNECTED  DEGRADED  ISOLATED  RECOVERING  FENCED  MAINTENANCE
```

## Status object

The federation status API distinguishes node federation state from local
database usability:

```json
{
  "node_id": "uuid",
  "federation_state": "isolated",
  "local_database": "read-write",
  "strong_namespaces": "unavailable",
  "eventual_namespaces": "read-write",
  "pending_replication_events": 281,
  "last_peer_contact_hlc": "...",
  "reconciliation_required": true
}
```

`local_database` reports `read-write` in ISOLATED state for LOCAL namespaces.
That is acceptance criterion 2 in one field.

## What survives isolation

A surviving node can, with no peers reachable:

- read its durable local state;
- append local operational events;
- update state in namespaces for which it has explicit local authority;
- serve local telemetry and history;
- recover from its own WAL;
- continue as an independently valid QIHSE instance.

This is verified by the deterministic scenarios `S1` and `S4` in
`tests/test_federation_f8.c`, which isolate a node from four peers on a lossy
network and assert that local writes and event appends still succeed while a
LINEARIZABLE namespace fails closed.
