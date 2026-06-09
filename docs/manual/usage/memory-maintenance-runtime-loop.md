# Runtime maintenance loop (caller-driven)

QIHSE does not spawn hidden maintenance workers for memory migration. The caller
explicitly owns the maintenance loop.

## Initialization

```c
#include "memory/include/qihse_memory.h"
#include "memory/include/qihse_memory_migration_scheduler.h"

qihse_memory_migration_scheduler_t scheduler = {0};
qihse_memory_migration_scheduler_config_t config = {0};
qihse_memory_migration_task_t tasks[256];

qihse_memory_migration_scheduler_default_config(&config);
if (!qihse_memory_migration_scheduler_init(&scheduler, tasks, 256u, &config)) {
    /* handle init error */
}
```

## Per-iteration maintenance pattern

```c
if (!qihse_memory_maintenance_start(manager, &scheduler)) {
    /* handle start/reset error */
}

// Populate scheduler from current workload state
size_t enqueued = qihse_memory_maintenance_snapshot(
    manager,
    &scheduler,
    QIHSE_DEVICE_GPU,
    64u  // max candidates (0 means unbounded by caller)
);

// Run bounded maintenance steps (non-blocking batches)
size_t executed = qihse_memory_maintenance_step(manager, &scheduler, 16u);
```

Drain in a loop when service latency allows:

```c
while (scheduler.count > 0u) {
    size_t done = qihse_memory_maintenance_step(manager, &scheduler, 16u);
    if (done == 0u) {
        break;
    }
    executed += done;
}
```

You can run the same loop at fixed frequency (e.g., every request batch, every N
seconds, or background thread tick) using any `max_tasks` that fits your latency
budget.

## Why explicit start/snapshot/step

- `qihse_memory_maintenance_start()` resets scheduler state and prepares a new pass.
- `qihse_memory_maintenance_snapshot()` scores tracked buffers and enqueues candidates.
- `qihse_memory_maintenance_step()` executes a bounded number of migration tasks.

This gives deterministic control over maintenance pressure and can be tuned by
`max_candidates` and `max_tasks`.

## Optional diagnostics

```c
const qihse_memory_migration_task_t* top =
    qihse_memory_migration_scheduler_peek(&scheduler);
if (top) {
    qihse_memory_migration_decision_t decision = {0};
    if (qihse_memory_migration_decision_inspect(
            top->buffer,
            top->target_device,
            top->target_type,
            &decision)) {
        char line[256];
        (void)qihse_memory_migration_decision_format(line, sizeof(line), &decision);
        /* log line */
    }
}
```

If you need structured reason codes per candidate instead of summary logs, call
`qihse_memory_migration_decision_inspect()` on candidate buffers directly.

## Direct backend execution alternative

For advanced callers that manage their own queueing, `qihse_memory_migration_scheduler_run()`
is available and executes up to `max_tasks` from an initialized scheduler. In most
production paths, `qihse_memory_maintenance_step()` is the preferred façade.
