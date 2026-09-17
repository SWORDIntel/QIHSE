# Network Exposure and Egress Policy

> **Status: implemented** — the declared-listener and egress profile model,
> drift detection, and its use by the hardening audit are verified by
> `tests/test_federation_f7.c` and `tests/test_federation_fuzz.c`.
>
> **Contradiction with the code:** the "Profile location" section below gives
> `security/runtime-network-profile/<service>/<version>`. The key built in
> `src/federation/qihse_security_audit.c` is
> `security/runtime-network-profile:<service>:<version>` (colon-separated, per
> `QIHSE_NET_PROFILE_PREFIX`). The runtime hardening profile uses the same
> colon form, which [runtime_hardening.md](runtime_hardening.md) states
> correctly.

QIHSE network behaviour is explicit and minimal. A production node exposes only
configured interfaces.

## Declared listeners

Each listener must have a defined bind address, authentication mode,
authorization scope, protocol version, and rate and size limits:

```c
typedef struct {
    char service[65];
    char version[65];
    uint32_t ports[32];
    char bind_addresses[32][64];
    size_t listener_count;
    bool listener_requires_auth[32];
    size_t max_request_bytes[32];
    bool egress[QIHSE_EGRESS_CLASS_COUNT];
    uint64_t generation;
} qihse_net_profile_t;
```

No listener should bind to all interfaces merely for convenience unless the
deployment policy explicitly permits it.

## Egress classes

```
FEDERATION_PEERS  BACKUP_TARGET  TELEMETRY_SINK  LOCAL_CITADEL
UNRESTRICTED_INTERNET
```

The default profile enables `FEDERATION_PEERS` and `LOCAL_CITADEL` only.
`qihse_net_profile_is_egress_restricted()` returns true whenever
`UNRESTRICTED_INTERNET` is not declared.

**QIHSE itself never requires unrestricted Internet egress** (acceptance
criterion 26). Package and source fetching, CVE-database updates and build
dependency retrieval belong to dedicated update and build domains, not to the
QIHSE process.

## Drift detection

`qihse_net_profile_unexpected_listeners()` reports ports that are listening but
were never declared. The hardening self-audit treats each as a critical finding
that degrades federation trust.

## Enforcement is external

Network policy is represented in QIHSE **as data**. Enforcement belongs to
Citadel, the host network policy layer and the host firewall. QIHSE detects and
reports divergence; it does not attempt to enforce its own egress policy, which
it could not do reliably from inside the process being constrained.

## Profile location

```
security/runtime-network-profile/<service>/<version>
```
