# Cluster range-group repair — 2026-11-10

This is a source integration record. It is not a live deployment result.
The authoritative program checklist remains [ROADMAP.md](../../ROADMAP.md).
CT.1 and CT.2 remain partial until the complete runtime path passes.

## Integrated and verified

| Area | Evidence |
| --- | --- |
| Automatic CT2 selection | Four-daemon balance drill passed without a donor floor override or optional observation-journal signing configuration. Pending operations keep their immutable identity across source-generation changes. |
| Completed CT2 retry | Transfer-manager tests verify local completion from durable FINALIZED evidence without requiring the former target to be online. COMMITTED still requires the target's typed activation receipt. |
| Signed cluster bus | Actual production sender-to-UDP-receiver fixture verifies maximum ML-DSA-87 signatures and payloads. Sender endian selection, signature/trailer offsets and signed receive-buffer sizes were repaired. |
| Transfer size metadata | Production parser accepts 67,284,039-byte images and the signed 64-bit limit; malformed/overflow inputs remain rejected. Bounded frame and replication-log limits remain. |
| Quorum range history | Consensus mesh fixture covers follower submission, committed genesis/reserve/finalize, low-clearance denial, inherited uncommitted terminal entries, lost reply, leader loss, restart, exact retry and conflicting operations. RESERVED lookup does not disclose an uncommitted terminal decision. |
| Independent replication groups | Storage fixture has one store own A and receive B, restart both, and promote B while A remains usable. Context state uses field-wise persistent encoding and an explicit old-reader format fence. |
| Authority adapter | Focused adapter fixture and scoped ASan/UBSan run passed for principal propagation, immutable grants, typed activation binding, sparse/empty-stream promotion and persisted readiness-marker binding. This fixture uses a mesh boundary double; it does not substitute for runtime integration. |

The integrated library and legacy daemon build succeeded. Focused legacy CT
storage and codec authorization checks also passed after the group foundation.
The complete suite remains stopped at the user's request.

## Required before completion

- Wire common group configuration, independent receiver workers and the same
  quorum authority through daemon CT1 promotion and CT2 transfer.
- Recover original signed promotion ancestry after missing an intermediate
  promotion, including when that intermediate owner is unavailable.
- Transfer to a destination that already owns another group, whether or not it
  already holds the source group's replica; durably stage the incoming range
  at its own successor before cutover.
- Exercise a real three-node ring where every physical node owns one group
  and receives another, with writes, deletes, labels, restart and cutover.
- Verify discovered group-path regressions: token-to-group binding, all-key
  enumeration, cross-group MSET/DEL preflight, native node-local namespaces,
  expiry routing and compatible receiver policy.
- Keep legacy local journal replay separate from new live quorum admission.
  An empty historical lane identifier must not bypass quorum checks on a new
  peer message.
- Remove quadratic history scans without imposing another aggregate transfer
  count cap. Historical replay still requires work proportional to retained
  history unless a separate checkpoint implementation is added.

Slot distribution is not a measurement of balanced record counts, stored
bytes or CPU load. No performance improvement is claimed without a workload
measurement. Existing node-local namespaces, including AIMEM's local records
and indexes, are outside slot-range transfer. Preserving their native access
does not implement automatic sharding or balancing of the AIMEM dataset.
