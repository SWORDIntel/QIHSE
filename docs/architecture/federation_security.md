# Federation Security

> **Status: implemented** — node identity, enrollment, infrastructure scopes,
> signed gossip with a persistent replay window, and the federation mTLS
> binding are verified by `tests/test_federation_f5.c` and
> `tests/test_federation_mtls.c`.
>
> **Contradictions with the code:** this document describes a node identity as
> "a durable Ed25519 keypair" with a 32-byte `public_key`. The record type in
> `include/qihse_federation.h` is algorithm-agile: it carries `sig_alg`,
> `public_key_len`, and a 2592-byte key buffer, and the default for new
> identities is ML-DSA-87 (`QIHSE_SIG_ALG_DEFAULT`). The document's description
> matches only the legacy `qihse_federation_node_keygen()` entry point, which
> is still Ed25519-only; `qihse_federation_node_keygen_alg()` is the general
> path and the RESP enrollment command uses the ML-DSA-87 default. The closing
> "What is not implemented" section (mTLS for federation RPC) is also stale —
> the mTLS transport is implemented and tested.

## Node identity

A node identity is a durable Ed25519 keypair, never an IP address, hostname,
or topology array index — those are mutable attributes.

```c
typedef struct {
    qihse_uuid_t node_id;
    char hostname[128];        /* mutable attribute, display only */
    char boot_id[64];          /* changes per boot */
    char key_handle[160];      /* filesystem reference, NOT the key */
    uint8_t public_key[32];
    uint8_t fingerprint[48];   /* SHA-384 of the public key */
    qihse_trust_state_t trust;
    uint64_t enrollment_epoch;
    qihse_service_identity_t identity_kind;
    qihse_infra_scope_t scopes;
} qihse_federation_node_identity_t;
```

`qihse_federation_node_keygen()` writes the private key to
`<key_directory>/<node_id>.key` with 0600 permissions. The private key
**never** enters a QIHSE record: records carry only the public key, its
fingerprint, and a filesystem handle.

## Enrollment

```
generate node key
    -> operator approves enrollment
    -> node obtains scoped authority
    -> QIHSE stores enrollment event
```

`request` records a PENDING identity whose scopes are derived from its service
identity kind, so a requester cannot self-grant privilege. `approve` promotes
it to APPROVED with a monotonic enrollment epoch. `revoke` marks it REVOKED
with all scopes cleared, and revocation is permanent — a revoked node cannot
be re-approved.

## Infrastructure scopes

| Scope | Purpose |
|---|---|
| `FEDERATION_READ` / `FEDERATION_WRITE` | federation state access |
| `NODE_ENROLL` / `NODE_REVOKE` | membership administration |
| `POLICY_READ` / `POLICY_WRITE` | policy administration |
| `LEASE_READ` / `LEASE_WRITE` | lease operations |
| `SECURITY_ADMIN` | security administration |
| `AUDIT_READ` | audit trail access |
| `TELEMETRY_WRITE` | telemetry publication |

Service identities carry defaults: the hypervisor controller gets lease write,
the host agent gets read plus telemetry, and **KEYSTONE receives
`FEDERATION_READ` only** — never database-admin.

`qihse_infra_scope_check(NULL, ...)` returns denial. `NULL` is never an
authorization bypass.

## Signed gossip

Gossip is a signed membership and health plane. A frame carries protocol
version, feature and capability bitmaps, cluster UUID, sender node UUID,
boot/session UUID, a monotonic sequence, HLC and health summary, with an
Ed25519 signature over a deterministic little-endian serialization.

Acceptance requires an APPROVED sender, a valid signature, and a strictly
advancing sequence. The replay window persists under
`fedreplay:<node>:<boot>`, so a restart does not reopen it.

**A datagram is never trusted because its source IP matches a configured
peer.**

## What is not implemented

> **Section status: implemented — this section is stale.** mTLS for federation
> RPC is implemented in `src/federation/qihse_federation_transport.c` and
> verified by `tests/test_federation_mtls.c`. See the contradiction note at the
> top of this document.

mTLS for federation RPC. The identity and signing substrate is in place; the
TLS binding attaches where the overlay transport lands.
