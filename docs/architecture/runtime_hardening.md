# Runtime Hardening Profile

QIHSE is a network-facing, state-authoritative component and requires its own
explicit security profile.

## Conservative production defaults

`qihse_runtime_profile_init()` produces a profile that:

- holds **no** Linux capabilities;
- **forbids** core dumps;
- **requires** a seccomp filter;
- marks **every** audited kernel interface `UNKNOWN` until it is classified
  deliberately.

An `UNKNOWN` interface fails hardening review rather than passing by default.

## Sensitive kernel interfaces

```
AF_PACKET  AF_NETLINK  AF_ALG  RAW_SOCKETS  IO_URING  USERFAULTFD
PERF_EVENT_OPEN  BPF  PROCESS_VM  PTRACE  KEYRINGS  MEMFD  MOUNT
```

Each is classified `REQUIRED`, `OPTIONAL`, `FORBIDDEN` or `UNKNOWN`. The brief
requires that unknown fail CI hardening review for production builds, which the
defaults enforce.

## Drift detection

`qihse_runtime_audit()` compares an observation against the declared profile
and reports findings:

| Finding | Severity |
|---|---|
| `UNEXPECTED_CAPABILITY` | critical |
| `CORE_DUMPS_ENABLED` | critical |
| `UNEXPECTED_UID` | critical |
| `UNEXPECTED_LISTENER` | critical |
| `FORBIDDEN_INTERFACE` | critical |
| `MISSING_CAPABILITY` | non-critical |
| `UNCLASSIFIED_INTERFACE` | non-critical |
| `SECCOMP_DISABLED` | non-critical |

Capability findings name the offending capabilities (`CAP_SYS_ADMIN`,
`CAP_NET_ADMIN`, ...) rather than reporting a bare bitmask.

## Severity maps to federation trust only

```
no findings            -> TRUSTED
non-critical findings  -> TRUSTED_DEGRADED
critical findings      -> LOCAL_ONLY
```

A critical hardening failure **degrades the node's federation authority** and
never makes the local database unavailable. The brief is explicit that a failed
self-audit must not automatically erase local data or terminate the database.

## Versioned metadata

Profiles are stored under `security/runtime-profile:<service>:<version>` with a
generation counter, so the intended capability and syscall posture is versioned
data and runtime drift can be detected against it.
