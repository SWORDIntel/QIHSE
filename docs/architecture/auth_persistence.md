# Auth credential persistence — decision record

**Status:** decided 2026-09-26 · **Decides:** roadmap improvement-pass item 4
**Applies to:** `core/qihse_auth.c`, every daemon and SDK entry point

## Decision

Credentials are **ephemeral process state**. QIHSE never persists password
verifiers: the operator (and any created users) exist exactly as long as the
process does, are seeded at `qihse_auth_init()` from the environment
(`QIHSE_OPERATOR_PASSWORD`, minimum 12 characters) or by an explicit
`--password`-style bootstrap, and **restart = re-credential**.

A persisted verifier store was considered and rejected. Storing verifiers on
disk would (a) make QIHSE a credential vault, which the architecture
explicitly lists as a non-goal — external systems own secrets; QIHSE stores
provenance and evidence, never authority; (b) add a theft/crack surface
(PBKDF2 verifiers at rest) for zero new capability, since every deployment
already controls the process environment; and (c) create a silent
stale-credential class of failure (env rotated, disk store not).

## Contract

| Aspect | Rule |
|---|---|
| Source of truth | the process environment (or flag bootstrap on first start) |
| Lifetime | the process lifetime; nothing survives restart |
| Multi-node clusters | the operator/orchestrator supplies the SAME `QIHSE_OPERATOR_PASSWORD` to every node (systemd `EnvironmentFile`, secret manager → env); mismatched nodes simply refuse each other's AUTH — visible, not silent |
| Rotation | runtime `USER.MODIFY` with operator credentials; the new verifier dies with the process, so rotation must also land in the deployment's env source |
| Revealed state | `qihse_auth_is_operator_password_default()` reports whether a verifier is configured; tools must fail closed while none is |
| Never allowed | writing verifiers, password material, or derived state to disk in any form |

## Why this is safe under the invariants

- Invariant 1 (no contextless classified access): unaffected — the principal
  table is identity, not authorization data, and every read still requires an
  authenticated principal.
- Invariant 2 (no principal above itself): unaffected — user creation bounds
  are enforced at the API regardless of how the operator itself was seeded.
- Fail-closed: a restarted node with no configured verifier refuses
  authentication rather than serving open (`is_operator_password_default`
  guards in the RESP/UWP engines).

## Operational consequence (the honest one)

A cluster restart is a credential-restore event. This is the same trust
position as TLS keys in a K8s Secret or a database URL in an env file — the
deployment layer already owns secret distribution. Documented in
[OPERATIONS §0.1](../OPERATIONS.md) as the single source of truth for
operators and agents.
