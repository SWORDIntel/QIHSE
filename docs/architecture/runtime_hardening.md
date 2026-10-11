# Runtime Hardening Profile

> **Status: implemented** — the conservative default profile, drift detection,
> and the severity-to-trust mapping are verified by
> `tests/test_federation_f7.c`.

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

## Subsystem Hardening & Defense-in-Depth

The comprehensive security audit remediation introduced critical runtime controls
across internal engines to eliminate denial-of-service, command execution, and timing channels:

1. **Lua Script Execution Sandboxing:**
   - Instruction counting hook via `lua_sethook` with a strict instruction budget (`LUA_MAX_INSTRUCTIONS = 1,000,000`) terminates infinite loops.
   - Memory allocation hook with custom allocator enforces a maximum heap quota (`LUA_MAX_MEMORY_BYTES = 16 MiB`).
   - Dangerous globals (`os.execute`, `io.*`, `package.loadlib`) are stripped or neutralized.

2. **Python Remote Code Execution Elimination:**
   - Eliminated unsafe `eval()` and `exec()` calls across all telemetry daemons, fan controllers, and cluster management agents.
   - Replaced with strict `ast.literal_eval` for primitive data or standard `json.loads` validation.

3. **Stack Frame Bounding (Invariant 5):**
   - Cluster failover, consensus decoders, and cluster bus structures exceeding thread stack safety thresholds were moved from stack allocations to bounded heap buffers.
   - Eliminates stack overflow vectors during large cluster transitions.

4. **Constant-Time PBKDF2 Dummy Verifications:**
   - On non-existent username lookup during authentication, a synthetic constant-time PBKDF2 computation over a dummy salt is executed.
   - Eliminates timing side-channels that would otherwise allow attackers to enumerate valid usernames.

5. **Fork-Safe Audit Logging:**
   - Background audit signing threads do not survive `fork()`. Registered `pthread_atfork` handlers fence the signer queue pre-fork and cleanly reinitialize signing thread state and mutexes in child worker processes, preventing deadlocks.

