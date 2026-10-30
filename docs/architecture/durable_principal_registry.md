# Durable principal registry

> **Standalone maintenance update:** see [PRINCIPAL_MIGRATION.md](../PRINCIPAL_MIGRATION.md)
> and `include/qihse_auth_maintenance.h`. The implementation below is explicit
> standalone durable authority, distinct from principal consensus.
> Standalone state is never a consensus prefix or an automatic fallback.
> Deployment activation remains blocked by the current LAN ownership/GC conflict;
> no primary has been stopped/replaced and no DIRECTEYE or production SQL changes
> are part of this work. This is a source-contract description, not build/test
> evidence or a claim of operational acceptance.

## Implemented standalone authority

The source maintenance API in `include/qihse_auth_maintenance.h` distinguishes
`DISABLED` (legacy volatile), `STANDALONE` (permanent local durable authority)
and `CONSENSUS` (not a supported principal authority). Unsupported selection
fails; standalone must never be inferred from a failed consensus startup.
Ordinary KV replication does not reconstruct the authoritative auth table.

`qihse_auth_maintenance_start()` is one-shot protected startup before ordinary
auth initialization/listeners. Provision and recover are distinct actions.
Provision refuses existing state and creates a fresh history unless an explicit
same-authority history is supplied to prepare a relocation target. Recovery binds
to an expected history, node, epoch and minimum generation; it must not silently
initialize a fresh registry on missing/invalid state.

`qihse_auth_bootstrap_provision()` creates a private bootstrap verifier file
without overwriting an existing file. Recovery uses an opaque startup capability,
not a fake root principal or `NULL` actor bypass. Live maintenance requires an
authoritative full-clearance/full-SCI system Operator satisfying its verifier
and hardware-token policy. Transfer never replaces protected UID 0.

`core/qihse_auth_durable.c` takes an exclusive local state-directory lock.
Commit writes a unique private pending file, synchronizes it, renames to
`authority.state` and synchronizes the directory before success/publication.
Auth mutators stage state through the durable gate before acknowledging changes:
account, password, ACL, token-policy and lockout updates cannot be in-memory-only successes in
durable mode. Failure fences readiness rather than reopening volatile auth.

### Session and handle invalidation

In durable mode, a successful generation-changing policy mutation installs a
new registered handle and its authoritative shadow state under the auth write
lock. This covers password/bootstrap, username, clearance/SCI, delegation,
hardware-token requirement/enrollment and object ACL changes. Every previous
target handle fails authoritative resolution, including sessions that check
only liveness rather than an optional saved generation. UID 0 is not exempt:
a root session becomes stale after changing its own security policy and must
reauthenticate. Adapters must not silently refresh an old session by UID.
Creation returns the current registered handle; a subsequent policy change
invalidates that handle too. Transient hardware-token presence and lockout
counters do not rotate policy handles. Legacy volatile mode retains its
in-place pointer semantics.

Replacement allocation and retirement-capacity checks precede durable commit;
OOM or exhausted retirement capacity publishes and commits nothing. Publication
has no remaining allocation/failure point. Ordinary mutations perform standalone
disk I/O under the existing lifecycle/auth locks, never consensus I/O. Import
uses the same retirement mechanism for all previous nonroot handles, including
unchanged accounts. Scoped borrow counts move with each retired allocation;
release of an old borrow cannot decrement a replacement principal's count.

The shared process-lifetime retirement pool is bounded to `MAX_USERS` (65,536)
allocations across policy rotation, deletion and import. Exhaustion rejects a
mutation/import before disk commit; restart/recovery resets this process-local
budget without resurrecting sessions. Retired allocations are never freed or
reused, preventing dangling raw handles and allocator-address aliasing. They
also remain immutable: even when scoped references reach zero, legacy unscoped
readers and borrowed string pointers cannot be proven quiescent. Cleansing at
that point would introduce a data race. Consequently their bounded old policy
and verifier payloads remain resident until process exit, not plaintext
passwords; process memory and dumps remain secret-bearing. Safely reclaiming
or cleansing these allocations earlier requires a broader lifetime-tracked API,
not a generation-check convention imposed on optional callers.

The archive contract uses explicit bounded portable encoding, ML-KEM-1024,
AES-256-GCM and ML-DSA-87 with explicit recipient/signer keys, SHA-384 DER
SubjectPublicKeyInfo pins, and authenticated source/target
authority/history/node/epoch/generation, purpose and archive ID bindings. It is
not a native-structure or process-memory dump. Protect verifiers, keys, bootstrap,
archives and backups as secret-bearing artifacts. Local durable envelopes alone
include encrypted mutable UID-0 state bound to the immutable provisioning anchor;
transfer images exclude root identity/verifier/policy and root-derived bootstrap
binding. Principal generations, tombstones and lockout state survive recovery;
sessions, verifier caches and
`hardware_token_present` do not. Authentication and token presence must be
established again. Import is a new local generation and must not resurrect a
tombstone or relax an existing hardware-token requirement.

Import carries a nonzero request ID and a bounded durable retry receipt in the
same authority state. An identical lost-ACK retry uses the original expected
position, binding and ciphertext; conflicting reuse fails. A later position
alone is not proof of that request's success.

This provides local crash consistency and explicit stale-generation checking,
**not entire-volume rollback protection**. Rolling back state, keys, bootstrap
and the configured generation floor together can restore old coherent authority.
No external monotonic witness is supplied. A local file lock also cannot fence
a copied authority on another machine. See the migration runbook for coherent
recovery, external fencing and cutover restrictions.

## Consensus boundary

The `QPR1` codec in `core/qihse_principal_record.{h,c}` is not an
authenticated committed prefix. Standalone durability does not supply quorum
ordering, partition/rejoin authority, or cross-node revocation fencing. Do not
advertise those guarantees or substitute local state automatically for failed
principal-consensus capability.
