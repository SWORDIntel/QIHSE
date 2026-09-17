# Runtime Trust and Federation Admission

A valid node certificate proves **identity**, not current **trustworthiness**.
Admission therefore evaluates runtime evidence.

## Trust states

```
UNKNOWN  TRUSTED  TRUSTED_DEGRADED  LOCAL_ONLY  QUARANTINED  REVOKED
```

## Evidence bundle

A node presents a machine-readable bundle containing, where available:

```
node identity, boot/session UUID, Citadel release/image identity,
root-image digest, QIHSE artifact digest, QIHSE SBOM digest,
QIHSE provenance-attestation digest, policy generation,
kernel and Xen image identities, Secure/Measured Boot state,
TPM attestation reference, hardening-audit generation
```

QIHSE **stores** this evidence exactly as reported. It does not fabricate it and
does not self-approve it. Bundles are immutable per boot.

## Admission decision

```c
typedef struct {
    qihse_runtime_trust_t trust_state;
    bool local_usable;      /* ALWAYS true */
    bool may_replicate;
    bool may_read_remote;
    bool may_strong_write;
    bool may_vote;
    char reason[96];
} qihse_admission_t;
```

| State | local_usable | replicate | read remote | strong write | vote |
|---|---|---|---|---|---|
| TRUSTED | yes | yes | yes | yes | yes |
| TRUSTED_DEGRADED | yes | yes | yes | no | no |
| LOCAL_ONLY | yes | no | no | no | no |
| QUARANTINED | yes | no | no | no | no |
| REVOKED | yes | no | no | no | no |
| UNKNOWN | yes | no | no | no | no |

**`local_usable` is true in every row.** That is the governing architectural
principle expressed as a table, and it is acceptance criterion 23: a node with
valid credentials but failed provenance keeps its local database while losing
distributed authority.

## Trust changes are audited

A trust-state change appends an immutable event to the F2 journal recording the
previous state, the new state and the verification result, so the transition is
reconstructable.

## Verification is external

`qihse_trust_verification_put()` records the *verifier's* decision — the
`verification_principal` field names who decided. QIHSE records and evaluates;
Citadel and the attestation components determine whether evidence satisfies
current policy.
