# Federation Overview

QIHSE federation turns a cluster of QIHSE instances into a
**partition-aware, security-first federation data plane**. It is designed to
back a multi-host hypervisor control system without making host operation
depend on global cluster quorum.

## Governing principle

> **Federation must enhance a node, never become a prerequisite for that node
> to remain locally operable.**

This is enforced in code, not just documented. `qihse_runtime_admission_evaluate()`
returns `local_usable = true` for *every* trust state, including `REVOKED`.

## Boundaries

| Layer | Owns |
|---|---|
| Hypervisor control program | policy, scheduling, HA, fencing, execution |
| QIHSE | state, events, leases, epochs, metadata, telemetry, provenance |
| KEYSTONE | retrieval acceleration and optional intelligence |

QIHSE stores and evaluates. It does not start, stop, migrate, fence or promote
anything, and it never holds private signing keys.

## Stages

| Stage | Scope | Status |
|---|---|---|
| F0 | Identity, HLC, generation, fencing-epoch primitives | complete |
| F1 | Consistency classes, local-authority namespaces, status API | complete |
| F2 | Event journal, resumable watches, idempotency ledger | complete |
| F3 | Anti-entropy manifests, conflict objects | complete |
| F4 | Native CAS, scoped replication groups, lease primitive | complete |
| F5 | Node identity, enrollment, scopes, signed gossip | complete |
| F6 | Build coordination, provenance graph, SBOM, snapshots | complete |
| F7 | Runtime trust, hardening audit, time integrity | complete |
| F8 | Simulation, schema evolution, snapshots, rejoin, fuzzing | complete |

## Module map

| Area | Header | Source |
|---|---|---|
| Core federation | `include/qihse_federation.h` | `src/federation/qihse_federation.c` |
| Supply chain | `include/qihse_supply_chain.h` | `src/federation/qihse_supply_chain.c` |
| Runtime trust | `include/qihse_runtime_trust.h` | `src/federation/qihse_runtime_trust.c` |
| Security audit | `include/qihse_security_audit.h` | `src/federation/qihse_security_audit.c` |
| Operations | `include/qihse_operations.h` | `src/federation/qihse_operations.c` |
| Simulation | `include/qihse_federation_sim.h` | `src/federation/qihse_federation_sim.c` |
| RESP surface | `include/qihse_resp_wire.h` | `src/spinnaker/qihse_resp_engine.c` |

## What is not implemented

Stated plainly so the documentation does not overstate the code:

- **Replication transport.** Anti-entropy manifests and sync *plans* exist;
  the transport that would execute a plan does not.
- **mTLS binding.** Node identity and signed frames exist; the TLS binding for
  federation RPC attaches where the overlay transport lands.
- **Consensus.** Scoped replication groups and quorum evaluation exist. There
  is deliberately no Raft: the brief forbids the label without the full safety
  mechanics, so none is claimed.
- **Controller SDKs.** The RESP surface is complete; Rust and Python SDKs are not.
- **Backup execution.** Snapshot *manifests* are recorded and verified; the
  backup writer that produces the referenced data is not part of this work.

## Related documents

- [Consistency classes](consistency_classes.md)
- [Sovereign nodes](sovereign_nodes.md)
- [Leases and epochs](leases_epochs.md)
- [Federation security](federation_security.md)
- [Reconciliation](reconciliation.md)
- [Runtime trust](runtime_trust.md)
- [Time integrity](time_integrity.md)
