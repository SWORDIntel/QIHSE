# Build Coordination

> **Status: implemented** — the job state machine, idempotent transitions,
> builder capability records, package override registry, and historical
> performance are verified by `tests/test_federation_f6.c`.

QIHSE provides durable coordination state for the Citadel Adaptive Federated
Build Fabric.

## Responsibilities

QIHSE is responsible for job state, requested build profile, source identity,
builder capability metadata, lease state, historical performance, artifact
references, verification state, and the audit trail.

QIHSE is **not** responsible for invoking compilers or executing arbitrary
commands. There is no generic command-execution primitive anywhere in this
subsystem, and a build worker cannot promote an artifact by writing database
state.

## State machine

```
QUEUED -> PLANNING -> LEASED -> BUILDING -> TESTING -> VERIFYING -> SIGNING -> PUBLISHED
```

Failure states: `FAILED`, `RETRYABLE`, `QUARANTINED`, `CANCELLED`.

`RETRYABLE` is a failure state but deliberately **not** terminal: a job whose
builder disappeared can be requeued and reassigned after the lease expires.
`FAILED`, `QUARANTINED` and `CANCELLED` are hard-terminal.

## Idempotent transitions

Every transition is keyed on a request id. A repeated request id is a no-op
that returns the current job rather than a second generation bump, so a retried
state update cannot corrupt the job.

```c
bool qihse_build_job_transition(void* store, void* user,
                                const qihse_uuid_t* build_id,
                                qihse_build_state_t next,
                                const qihse_uuid_t* request_id,
                                const char* failure_reason,
                                qihse_build_job_t* out);
```

An illegal transition (for example `QUEUED -> BUILDING`) is refused outright.

## Builder capability

Normalized worker records let Citadel select build nodes intelligently:

```
cpu_model, cores_total, cores_available, ram_total_gb, ram_available_gb,
scratch_available_gb, isa, load_1m_milli, thermal_headroom_milli,
build_queue_depth, trust_state
```

## Historical performance

Every execution is recorded with package, source revision, profile, toolchain,
builder node, allocated cores, peak RAM, build and test durations, artifact
size and outcome. `qihse_build_history_mean_duration()` answers "how long does
this package usually take", so Citadel can estimate from real measurements
instead of nominal CPU specifications.

## Package override registry

Every package carries one of six modes:

```
UPSTREAM_BINARY  UPSTREAM_SOURCE_REBUILD  CITADEL_OVERLAY
CITADEL_FORK     FORBIDDEN                ISOLATED_EXCEPTION
```

**A reason is mandatory.** `qihse_pkg_policy_set()` refuses a policy with an
empty reason, so every override preserves its provenance.
