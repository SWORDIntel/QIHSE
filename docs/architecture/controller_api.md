# Controller-Facing API

> **Status: implemented** — the RESP-level `FEDERATION.*` surface is exercised
> by `tests/test_federation_f1.c` (status, namespaces, and the low-clearance
> negative test required by `AGENTS.md` invariant 3) through
> `tests/test_federation_f8_ops.c`. The native C client is
> `include/qihse_controller.h` / `src/controller/qihse_controller.c`, tested
> end-to-end by `tests/test_controller_api.c`. Rust and Python controller
> SDKs remain `planned`.

The controller talks to QIHSE through a narrow, first-class federation surface
rather than pretending to be a Redis or PostgreSQL client. Every command is
restricted to the **system tenant**; tenant principals receive `NOPERM`.

## Status and namespaces

| Command | Purpose |
|---|---|
| `FEDERATION.STATUS` | node federation state plus local database usability |
| `FEDERATION.STATE <state>` | set the node's federation state |
| `FEDERATION.NS.REGISTER / UNREGISTER / LIST / WRITABLE` | namespace authority |

## Events and watches

| Command | Purpose |
|---|---|
| `FEDERATION.EVENT.APPEND <type> <resource> [payload]` | append to the journal |
| `FEDERATION.EVENT.REPLAY [from_cursor]` | replay from a cursor |
| `FEDERATION.EVENT.LENGTH` | journal length |
| `FEDERATION.WATCH.OPEN [prefix]` | open a resumable watch |
| `FEDERATION.WATCH.NEXT <id>` | deliver the next event |
| `FEDERATION.WATCH.ACK <id> <offset>` | acknowledge delivery |
| `FEDERATION.WATCH.RESUME <id> <cursor>` | resume from a saved cursor |

Watches are at-least-once: an unacknowledged event is redelivered on resume.

## Objects, leases and epochs

| Command | Purpose |
|---|---|
| `FEDERATION.OBJECT.CAS <ns> <id> <value> [expected_generation]` | native compare-and-swap |
| `FEDERATION.OBJECT.GET <ns> <id>` | read with its generation |
| `FEDERATION.LEASE.ACQUIRE / READ / RENEW / RELEASE` | exclusive resource leases |
| `FEDERATION.EPOCH.NEXT / CURRENT` | monotonic fencing epochs |

## Conflicts and replication

| Command | Purpose |
|---|---|
| `FEDERATION.MANIFEST <namespace>` | namespace manifest with range digests |
| `FEDERATION.CONFLICT.LIST` | unresolved conflicts |
| `FEDERATION.CONFLICT.RESOLVE <id> <resolver>` | mark a conflict resolved |
| `FEDERATION.GROUP.CREATE / LIST / SHOW / ADD / REMOVE / ADVANCE` | replication groups |

## Trust and security

| Command | Purpose |
|---|---|
| `FEDERATION.NODE.LIST / SHOW / ENROLL / APPROVE / REVOKE` | node membership |
| `FEDERATION.SCOPE.LIST / CHECK / DEFAULTS` | infrastructure scopes |
| `FEDERATION.GOSSIP.STATUS <node> <boot>` | gossip replay state |
| `FEDERATION.TRUST.STATES / ADMISSION / SET` | runtime trust |
| `FEDERATION.SECURITY.IFACES / OBSERVE / AUDIT` | hardening posture |
| `FEDERATION.SECURITY.PROFILE.GET / SET` | runtime profile |
| `FEDERATION.SECURITY.NET.GET` | network exposure profile |

## Build and supply chain

| Command | Purpose |
|---|---|
| `FEDERATION.BUILD.CREATE / SHOW / TRANSITION / LIST / STATES` | build coordination |
| `FEDERATION.PKG.MODES / SET / GET` | package override registry |
| `FEDERATION.BUILDER.CAP / SHOW` | builder capability |
| `FEDERATION.PROV.NODE / SHOW / EDGE / TRACE / IMPACT` | provenance graph |
| `FEDERATION.SUPPLY.SBOM / SBOM.GET / VULN / VULN.COUNT / SNAPSHOT / SNAPSHOT.LIST` | supply-chain evidence |

## Operations

| Command | Purpose |
|---|---|
| `FEDERATION.SCHEMA.CHECK / MIGRATE / PROGRESS / STATUS` | schema evolution |
| `FEDERATION.SNAPSHOT.CREATE / SHOW / VERIFY` | snapshot manifests |
| `FEDERATION.REJOIN.STEPS / STATUS` | reconciliation sequence |
| `FEDERATION.METRICS [prefix]` | label-bounded metrics |

## Client library (native C)

`include/qihse_controller.h` wraps the whole surface above in a typed client:
one synchronous connection per `qihse_controller_t`, `AUTH` at connect, a
bounded RESP decoder (bulk ≤ 16 MiB, ≤ 1 MiB array items, depth ≤ 32), and
named wrappers mirroring this document's operation list —
`qihse_ctrl_node_*`, `qihse_ctrl_object_*`, `qihse_ctrl_lease_*`,
`qihse_ctrl_epoch_*`, `qihse_ctrl_event_*`, `qihse_ctrl_watch_*`,
`qihse_ctrl_conflict_*`, `qihse_ctrl_ns_*`, `qihse_ctrl_group_*`,
`qihse_ctrl_build_*`, `qihse_ctrl_pkg_*`, `qihse_ctrl_supply_*`,
`qihse_ctrl_prov_*`, `qihse_ctrl_snapshot_*`, `qihse_ctrl_schema_*`,
`qihse_ctrl_security_*`, `qihse_ctrl_federation_status`,
`qihse_ctrl_rejoin_status`, `qihse_ctrl_metrics`, plus a generic
`qihse_ctrl_call()` escape hatch.

The client holds no authority: every call lands under the authenticated
principal and the server's system-domain/scope/classification checks apply
unchanged. Watch ids are session-scoped — reconnect re-opens and resumes
from the last acked cursor.

`tests/test_controller_api.c` covers happy-path round-trips (CAS, lease
lifecycle, event + resumable watch, groups) and the invariant-3 negatives:
unauthenticated and tenant principals are refused with no data served.

## Not implemented

Rust and Python SDKs. The brief lists them as high priority; the RESP
surface and the native C client exist, but the Rust/Python controller SDKs
themselves are not written.
