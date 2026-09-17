# Leases and Epochs

QIHSE provides a generic, auditable atomic primitive. It does **not** implement
hypervisor HA policy — the controller decides when a lease may be acquired.

## Fencing epochs

Fencing epochs are monotonic and non-reusable, and are separate from ordinary
object generations. A persistent counter lives under `fedepoch:<node>`.

```
EPOCH.NEXT     advances and returns the new value
EPOCH.CURRENT  reads without advancing
```

A stale process holding epoch 81 must never be able to commit an
exclusive-resource action once epoch 82 is authoritative. This is enforced by a
**fencing high-water mark**: leases publish the epoch they claimed under
`fedleaseres:<namespace>:<resource>`, and that record *persists after release*.
A later acquire at an equal or lower epoch is refused.

## Lease operations

```
LEASE.CREATE / ACQUIRE   LEASE.RENEW   LEASE.RELEASE   LEASE.READ
```

Lease fields: owner, lease UUID, namespace/resource, expiry, epoch, request
UUID, issuer, generation.

## Semantics

| Requirement | How |
|---|---|
| strongly consistent namespace | resources live in `fedlease:` / `fedleaseres:` records |
| monotonic epoch | high-water mark never decreases |
| stale renewals rejected | renew refuses a lease that is not GRANTED |
| idempotent release | releasing a released lease succeeds |
| server-side expiry | `expires_hlc_physical` is compared against the HLC |
| audit event for all changes | trust/ownership transitions append to the F2 journal |

## Idempotency

A `fedleasereq:<request_id>` index maps a request id to the lease it produced,
so a retried acquire returns the original lease **even if the caller
regenerated the lease id**. Retries are therefore harmless, which is what the
brief requires of hypervisor orchestration.

## States

```
FREE  GRANTED  EXPIRED  RELEASED
```

Only a GRANTED lease blocks acquisition. A RELEASED or EXPIRED lease does not
block a *higher* epoch, but the high-water mark still blocks an equal or lower
one.

## Scoped replication groups

Quorum is evaluated per group, never for the whole federation:

```c
typedef struct {
    char group_id[64];
    size_t member_count;
    qihse_federation_group_member_t members[32];  /* voters and witnesses */
    uint64_t term;
    qihse_consistency_class_t consistency;
} qihse_federation_group_t;
```

An outage in one group must not stop an unrelated group. A reachable witness
breaks a tie between two voters but cannot form quorum on its own.

**No consensus algorithm is claimed.** There is deliberately no Raft here,
because the brief forbids the label without persistent term, voted-for
persistence, log index/term, leader election, majority commitment, log
matching, current-term commit rules, membership-change semantics,
snapshot/install-snapshot, and the crash and partition tests that go with them.
