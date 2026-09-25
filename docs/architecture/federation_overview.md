# Federation Overview

> **Status: implemented** — F0–F8 are verified by `tests/test_federation_f0.c`
> through `tests/test_federation_f8.c`, plus `tests/test_federation_f8_ops.c`,
> `tests/test_federation_bus_trust.c`, `tests/test_federation_fuzz.c`,
> `tests/test_federation_mtls.c`, `tests/test_federation_repl.c`,
> `tests/test_federation_transport.c`, `tests/test_federation_rejoin.c`, and
> `tests/test_federation_backup.c`.
>
> The tracked Phase 10 remainder has since landed: scoped consensus
> (`tests/test_consensus.c`, `make test-consensus`, 20 deterministic
> scenarios), the signed backup container and its authentication negative
> tests (`tests/test_backup_auth.c`), the node-side CRL loader and the
> out-of-process CA tool (`tests/test_federation_crl.c`,
> `tests/test_federation_ca.c`, `make federation-ca`), the controller SDKs
> (`python/tests/test_controller_sdk.py`, `rust/qihse-rs/tests/controller_sdk.rs`),
> and the change-sequence delta export (`tests/test_incremental_export.c`,
> `make test-incremental-export`). What remains open is the residual
> boundaries each module states in its header — see
> [What is not implemented](#what-is-not-implemented).

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
| Scoped consensus | `include/qihse_consensus.h` | `src/federation/qihse_consensus.c` |
| Replication sync | `include/qihse_federation_repl.h` | `src/federation/qihse_federation_repl.c` |
| mTLS + node-side CRL | `include/qihse_federation_mtls.h` | `src/federation/qihse_federation_mtls.c` |
| TLS transport | `include/qihse_federation_transport.h` | `src/federation/qihse_federation_transport.c` |
| Rejoin | `include/qihse_federation_rejoin.h` | `src/federation/qihse_federation_rejoin.c` |
| Supply chain | `include/qihse_supply_chain.h` | `src/federation/qihse_supply_chain.c` |
| Runtime trust | `include/qihse_runtime_trust.h` | `src/federation/qihse_runtime_trust.c` |
| Security audit | `include/qihse_security_audit.h` | `src/federation/qihse_security_audit.c` |
| Operations | `include/qihse_operations.h` | `src/federation/qihse_operations.c` |
| Backup writer/reader | `include/qihse_backup.h` | `src/federation/qihse_backup.c` |
| Simulation | `include/qihse_federation_sim.h` | `src/federation/qihse_federation_sim.c` |
| Controller C client | `include/qihse_controller.h` | `src/controller/qihse_controller.c` |
| RESP surface | `include/qihse_resp_wire.h` | `src/spinnaker/qihse_resp_engine.c` |

## What is not implemented

> **Section status: implemented — the former gap list is closed.** The five
> entries this section used to carry (replication transport, mTLS binding,
> consensus, controller SDKs, backup execution) are all built and tested; the
> landed state is recorded above in the module map. What this section now
> carries is the honest residual inventory: the boundaries each landed module
> states in its own header. None of these is a missing feature that silently
> weakens a claim; each is a documented limit of what is built.

Stated plainly so the documentation does not overstate the code:

- **Consensus is deliberately not called Raft.** The scoped consensus module
  (`include/qihse_consensus.h`, `src/federation/qihse_consensus.c`, verified by
  `tests/test_consensus.c` via `make test-consensus`, 20 deterministic
  scenarios) implements persistent
  term/voted-for/fencing state, log matching, election restriction,
  majority+current-term commit, higher-term step-down, log compaction with
  follower snapshot install, and single-server membership changes. It is still
  not named Raft, because the full algorithm's mechanics are not all present:
  membership changes are single-server only (no joint consensus), there is no
  pre-vote, leadership transfer, or leader-lease linearizable read, client
  session dedup stays in the F2 request ledger, and peer authentication is the
  injected transport's job (mTLS/signed gossip), not this module's. Snapshots
  travel as a single message capped at 24 entries, and every member is an
  equal voter — no weights, witnesses, or learners. The header states each
  boundary where it applies.
- **CA provisioning is out-of-process by design.** The node consumes
  revocation state (`qihse_federation_crl_load/_check/_state`, composing the
  QIHSE-FED-CRL-V1 file with the KV `fednode:` record so either source
  refuses), but certificate provisioning for a real fleet is an operator
  procedure: `tools/qihse_federation_ca.c` (`make federation-ca`) is a
  standalone tool, deliberately not linked into `libqihse.so`. Verified by
  `tests/test_federation_crl.c` and `tests/test_federation_ca.c`.
- **The controller does not execute hypervisor actions, and never will.** The
  SDKs (`python/qihse/controller.py`, `rust/qihse-rs/src/controller.rs`, C
  reference `include/qihse_controller.h`) wrap the RESP command surface with
  explicit authentication; the federation boundary table above still applies.

## Related documents

- [Consistency classes](consistency_classes.md)
- [Sovereign nodes](sovereign_nodes.md)
- [Leases and epochs](leases_epochs.md)
- [Federation security](federation_security.md)
- [Reconciliation](reconciliation.md)
- [Runtime trust](runtime_trust.md)
- [Time integrity](time_integrity.md)
