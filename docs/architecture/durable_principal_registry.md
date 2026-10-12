# Durable principal registry and cluster replay

## Current behavior

`qihse_auth_init()` clears the `users` and `authz_states` arrays and creates
only system Operator (ID 0). `qihse_auth_create_user()`,
`qihse_auth_create_tenant_user()`, `qihse_auth_modify_user()`,
`qihse_auth_destroy_user()`, token updates, and object ACL updates change those
arrays only. `qihse_cluster_daemon` calls `qihse_auth_init()` before creating
the KV store or consensus mesh. Therefore an account created through these APIs
is neither durable across restart nor present on another node. A database row
that merely records account details does not change the authoritative QIHSE
authentication table.

Do not enable account creation for durable or clustered identities on the
assumption that current KV replication will reconstruct this table.

## Required committed state

Use one ordered, quorum-committed principal log for a cluster history. Every
mutation carries a unique request ID, the expected registry generation, the
authenticated actor ID and actor generation, and a canonical versioned record.
The record must include:

- User ID, tenant ID, username, role, classification, SCI bits,
  `can_create_users`, hardware-token requirement and registered credential ID.
- Password verifier version, algorithm, work factor, salt, and verifier bytes.
  Never log or replicate a plaintext password. Protect this log and its
  snapshots as secret-bearing data, including in backups.
- Object ACL entries and a monotonically increasing per-principal generation.
- Explicit tombstones for deletion and revocation. IDs must not be reused
  while an older generation could be replayed or presented.

The system Operator bootstrap is a separate local recovery mechanism. The
committed registry must not silently replace its credential with one from an
untrusted or different cluster history.

## Mutation ordering

The existing privilege checks in `create_user_internal()` and
`qihse_auth_modify_user()` apply before proposal, using the authoritative
current actor and target state. The same checks must be repeated at ordered
apply time against the committed predecessor state. This prevents an actor
whose authority was revoked between proposal and commit from creating or
promoting a principal. In particular, `can_create_users` delegates creation
only and must never grant role, clearance, SCI, tenant, or token-policy
authority above the creator. The `modify_user()` path currently allows any
Operator to alter a same-tenant target's clearance and SCI; the committed
apply path must preserve that explicit policy and never infer Operator power
from `can_create_users`.

Return success only after the operation commits and applies locally. If there
is no quorum or the node is fenced, reject the mutation rather than granting
temporary local authority. Append failure, stale expected generation, or
duplicate request ID must leave the auth table unchanged. Treat an exact
duplicate request as idempotent and a conflicting duplicate as an error.

All auth mutations need to use this path, including password rotation,
username changes, ACL grants/revocations, token enrollment and revocation,
and destruction. The present C APIs expose direct in-memory writes; leaving
even one reachable path outside the commit gate would allow diverging
authority.

## Startup, rejoin, and reads

On startup, validate the cluster history ID and a protected registry snapshot,
then replay the ordered committed suffix. Validate lengths, enum values,
verifier parameters, unique IDs/usernames, tenant boundaries, ACL bounds,
generations, checksums, and commit-prefix proof before materializing accounts.
Reconstruct `users`, `authz_states`, username map, and token-policy fast-path
flag from the same validated state. Never replay a partial record. Restore
role, clearance, SCI, tenant, token policy, password verifier, and ACL as one
atomic principal version.

Until the node has caught up to the committed authority index and holds a
valid lease/fence for this cluster history, it may not authenticate a
non-bootstrap principal or serve classified reads/writes under a cached
principal. If replay fails or a committed tombstone is missing, startup is
readiness-failed; falling back to a previous snapshot is not permitted. Rejoin
must compare the committed prefix and discard divergent uncommitted tails.
The relay/standby node uses the same log and readiness rule even when it is
not a normal write destination.

Authentication and permission checks must resolve a presented handle against
the applied principal generation; a pre-revocation pointer cannot stay valid
after a committed tombstone or change. The current `resolve_authoritative_user_locked()`
compares a pointer against a live table entry, but the durable implementation
also needs a generation and cluster-history binding for rejoin and recreation.

## Integration boundary

### Local record format staged

`core/qihse_principal_record.{h,c}` defines an inert `QPR1` canonical payload
codec for future committed principal mutations. It carries a request ID,
expected registry generation, actor identity and generation, target generation,
a full PUT principal with password verifier and ACL entries, or an explicit
DELETE tombstone. Decode rejects oversized or trailing records, unsupported
versions, malformed account fields, and noncanonical strings. This codec is
not connected to the auth APIs or cluster daemon: encoding a record is not
authorization, and decoding one is not replay proof. Until ordered
commit/replay and readiness fencing are implemented, QIHSE accounts remain
volatile. The payload includes verifier material, so any consensus log or
snapshot that stores it must be protected as a secret-bearing artifact.

The consensus mesh currently exposes proposals and committed reads, but auth
mutations do not use it and daemon initialization precedes mesh creation.
Implement a registry service after mesh startup and before listener readiness,
then inject it into the auth mutation APIs. This service owns snapshot/replay,
the commit/apply index, and the readiness fence. A local-only file snapshot is
not an acceptable substitute: it cannot preserve revocation ordering or
multi-node consistency. Nor can periodic key pulls establish an authoritative
order for create, modify, and delete.

Before merging a new wire/adapter path, add the required automated
low-clearance/high-data negative authorization test and run it in CI per
`AGENTS.md`. Also cover restart, partial-record recovery, stale snapshot,
concurrent mutation, revocation, partition/rejoin, and duplicate request IDs
before enabling persistent accounts. This document is a design gate; no live
registry or replay is enabled by it.
