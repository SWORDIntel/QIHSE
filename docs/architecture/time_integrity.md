# Time Integrity and Trusted Ordering

> **Status: implemented** — the wall-clock-independent HLC advance/merge and the
> anomaly model are verified by `tests/test_federation_f7.c`.

QIHSE relies on its hybrid logical clock for distributed ordering. HLC remains
the correctness mechanism; the wall clock is human and audit context.

## The rules

```
HLC/order correctness   >  wall clock
monotonic clock         >  wall clock for duration measurement
wall clock              =  human and audit context
```

QIHSE **never** assumes wall-clock accuracy for consensus safety.

## Monotonicity under a broken clock

`qihse_hlc_advance_safe()` takes the wall reading as a parameter, which is what
makes a broken clock injectable and the behaviour testable:

```c
qihse_hlc_t qihse_hlc_advance_safe(const qihse_hlc_t* prev, uint64_t wall_ms);
```

When the wall clock moves forward, its value is adopted and the logical counter
resets. When it stalls or moves **backward**, the previous physical component is
kept and the logical counter carries the ordering guarantee, so the result is
still strictly greater than its predecessor. A counter wrap borrows a
millisecond rather than repeating.

`qihse_hlc_merge_safe()` does the same on the receive path, taking the highest
logical counter among the clocks sharing the winning physical component. A
remote clock that is ahead or behind by any amount still yields a strictly
greater local clock.

## Anomaly detection

| Anomaly | Meaning |
|---|---|
| `BACKWARD_JUMP` | wall clock moved backwards beyond tolerance |
| `FORWARD_JUMP` | large forward wall-clock jump |
| `MONOTONIC_REGRESSION` | monotonic clock went backwards (platform fault) |
| `WALL_MONO_INCONSISTENT` | wall moved while monotonic stood still |
| `SYNC_LOST` | authenticated time sync lost |

Suggested event types: `time.sync_lost`, `time.sync_restored`,
`time.wall_jump`, `time.peer_skew`.

These affect trust and diagnostic state. They **never** silently rewrite
existing event timestamps.

## Policy thresholds

```c
typedef struct {
    uint64_t forward_jump_threshold_ms;   /* default 5 minutes */
    uint64_t backward_jump_threshold_ms;  /* default 1 second  */
    uint64_t peer_skew_threshold_ms;      /* default 30 seconds */
} qihse_time_policy_t;
```

## Why the monitor never adjusts the clock

The monitor reports; it does not correct. Correcting would make ordering depend
on the very clock whose integrity is in question. The HLC already provides the
ordering guarantee independently, so the wall clock can be wrong without
consequences for correctness.
