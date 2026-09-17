# Controller-Facing API

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

## Not implemented

Rust and Python SDKs. The brief lists them as high priority; the RESP surface
they would wrap is complete, but the SDKs themselves are not written.
