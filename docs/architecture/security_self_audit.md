# Security Self-Audit

> **Status: implemented** — reading real process state, the finding model, and
> the recommended-trust mapping are verified by `tests/test_federation_f7.c` and
> `tests/test_federation_f8.c`.

QIHSE exposes a machine-readable security posture report for Citadel's global
audit mechanism. The audit verifies **actual runtime state**, not configuration
files.

## What is actually read

| Source | Read |
|---|---|
| `getuid` / `getgid` / `geteuid` / `getegid` | real process credentials |
| `/proc/self/status` `CapEff:` | effective capability mask from the kernel |
| `getrlimit(RLIMIT_CORE)` | real core-dump policy |
| `prctl(PR_GET_DUMPABLE)` | whether the process may be dumped at all |
| `/proc/self/status` `Seccomp:` | seccomp mode (0 disabled, 1 strict, 2 filter) |
| `/proc/self/status` `NoNewPrivs:` | no-new-privileges flag |
| `/proc/net/tcp{,6}` | listening sockets visible to this process |

A test run on a development host reports, for example:

```
uid=1000 euid=1000 caps=0x0 core_dumps=1 seccomp=0 listeners=36
```

Those are the real values, which is what makes the audit meaningful rather than
decorative.

## Report

```c
typedef struct {
    char service[65];
    char version[65];
    uint64_t runtime_profile_generation;
    bool profile_found;
    uint32_t unexpected_capability_count;
    uint32_t unexpected_listener_count;
    uint32_t unclassified_interface_count;
    uint32_t forbidden_interface_count;
    uint32_t finding_count;
    qihse_audit_finding_t findings[32];
    bool critical;
    qihse_runtime_trust_t recommended_trust;
} qihse_audit_report_t;
```

## Effect of a failure

A failed self-audit must not erase local data or terminate the database. Policy
may degrade federation trust, remove voter eligibility, block strong mutations,
quarantine the node, or alert the operator — according to severity. The
recommended trust is `TRUSTED`, `TRUSTED_DEGRADED` or `LOCAL_ONLY`, and
`local_usable` remains true in all three.

## Evidence records

Reports are stored as versioned immutable evidence:

```
security/audit/<node>/<service>/<hlc>
```

so posture over time is queryable rather than only observable in the moment.

## Runtime profile

The audit is compared against a versioned profile under
`security/runtime-profile:<service>:<version>`; see
[runtime_hardening.md](runtime_hardening.md) for the classification model and
[network_exposure.md](network_exposure.md) for the listener declarations.
