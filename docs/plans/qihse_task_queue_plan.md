# QIHSE Task Queue Engine — Celery-Equivalent Distributed Task Dispatch

> **Status**: PLANNED — Not yet implemented.
> **Scope**: Focused subset — task dispatch, result storage, retry/backoff, priority queues, periodic scheduling. Full task composition (chains/groups/chords) deferred to future phase.

---

## 1. Executive Summary

QIHSE already contains ~80% of a distributed task queue in its existing modules:

| Celery Component | QIHSE Module | Status |
|---|---|---|
| Broker (Redis/RabbitMQ) | Event Stream (`qihse_event_stream`) | Complete — durable append-only log with SHA-384 dedup |
| Result backend | KV Store (`qihse_kv_*`) | Complete — Trinary Trie + LSM-Trees + SSTable |
| Worker pool | Cluster shards + NUMA pinning | Complete — 1:1 core-pinned shard workers |
| Task routing | Dist Planner (`qihse_dist_planner`) | Complete — hardware-aware backend dispatch |
| Task execution | Lua Injector + WASM Injector | Complete — sandboxed, instruction-capped |
| Backpressure | System Guard | Complete — sliding-window saturation throttle |
| Inter-node comms | Cluster bus + scatter-gather | Complete — UDP gossip + TCP fan-out |
| Wire protocol | RESP2/RESP3 | Complete — Redis-compatible |

What is missing is the **task lifecycle layer** — the state machine, retry logic, priority dispatch, scheduling, and Python SDK that turn these primitives into a Celery-equivalent system.

This plan adds that layer in **4 phases**, reusing existing engines as the broker, result store, and worker infrastructure. No new storage engines are required.

### Design Decisions (confirmed)

| Decision | Choice | Rationale |
|---|---|---|
| Task model | Python-callable (Celery-compatible) | Drop-in migration from Celery; `@task` decorator + `.delay()` API |
| Worker model | Dedicated task worker pool | Tasks don't compete with query processing for CPU; predictable latency |
| Scheduling | Hybrid (TSDB persistence + in-memory timing wheel) | TSDB for crash-safe schedule persistence; timing wheel for sub-ms dispatch |
| Priority | Yes — 4 priority levels | Critical / High / Normal / Low with strict preemption for Critical |
| Scope | Focused: dispatch + results + retry + priority + scheduling | Full composition (chains/groups/chords) deferred |
| Wire protocol | Extend RESP with `TASK.*` commands | Any Redis client can use raw commands; Python SDK wraps them |

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     QIHSE TASK QUEUE ENGINE                          │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │
│  │  Python SDK  │    │  RESP Client │    │  Scheduler   │           │
│  │  @task       │    │  TASK.* cmds │    │  (Timing     │           │
│  │  .delay()    │    │  (redis-cli) │    │   Wheel)     │           │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘           │
│         │                   │                   │                    │
│         ▼                   ▼                   ▼                    │
│  ┌─────────────────────────────────────────────────────┐            │
│  │           TASK DISPATCHER (new module)               │            │
│  │  • Task state machine (PENDING→STARTED→SUCCESS/      │            │
│  │    FAILURE→RETRY)                                    │            │
│  │  • Priority queue (4 levels, strict preemption)      │            │
│  │  • Retry with exponential backoff + jitter           │            │
│  │  • Task ID assignment (SHA-384)                      │            │
│  └────────────────────┬────────────────────────────────┘            │
│                       │                                              │
│         ┌─────────────┼─────────────┐                               │
│         ▼             ▼             ▼                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                          │
│  │  Event   │  │   KV     │  │   TS     │                          │
│  │  Stream  │  │  Store   │  │   DB     │                          │
│  │ (broker) │  │ (results)│  │ (metrics)│                          │
│  └──────────┘  └──────────┘  └──────────┘                          │
│                                                                      │
│  ┌─────────────────────────────────────────────────────┐            │
│  │           DEDICATED TASK WORKER POOL (new)           │            │
│  │  • N worker threads (NUMA-pinned, separate from      │            │
│  │    shard query workers)                              │            │
│  │  • Python function execution via subprocess + IPC    │            │
│  │  • Lua/WASM sandbox for native tasks                 │            │
│  │  • Per-worker task timeout + cancellation            │            │
│  └────────────────────┬────────────────────────────────┘            │
│                       │                                              │
│         ┌─────────────┼─────────────┐                               │
│         ▼             ▼             ▼                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                          │
│  │ Worker 0 │  │ Worker 1 │  │ Worker N │                          │
│  │ Core 4   │  │ Core 5   │  │ Core N   │                          │
│  │ NUMA 0   │  │ NUMA 0   │  │ NUMA 1   │                          │
│  └──────────┘  └──────────┘  └──────────┘                          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Decomposition

### 3.1 New C Module: `src/spinnaker/qihse_task_queue.{c,h}`

The task dispatcher — the core state machine and priority queue.

| File | Role |
|---|---|
| `src/spinnaker/qihse_task_queue.c` | Task state machine, priority dispatch, retry logic |
| `include/qihse_task_queue.h` | Public API: submit, result, status, cancel, retry |

### 3.2 New C Module: `src/spinnaker/qihse_task_worker.{c,h}`

The dedicated worker pool — separate from shard query workers.

| File | Role |
|---|---|
| `src/spinnaker/qihse_task_worker.c` | Worker thread pool, NUMA pinning, task execution, timeout |
| `include/qihse_task_worker.h` | Public API: worker pool lifecycle, task execution dispatch |

### 3.3 New C Module: `src/marmalade/qihse_task_scheduler.{c,h}`

The periodic scheduling engine — hybrid TSDB + timing wheel.

| File | Role |
|---|---|
| `src/marmalade/qihse_task_scheduler.c` | Cron parser, timing wheel, schedule persistence to TSDB |
| `include/qihse_task_scheduler.h` | Public API: add/remove/list schedules, start/stop scheduler |

### 3.4 RESP Wire Extension: `src/spinnaker/qihse_resp_engine.c` (modified)

Add `TASK.*` command dispatch to the existing RESP engine.

### 3.5 Python SDK: `sdks/python/qihse_task.py` (new)

The Celery-compatible Python API.

| File | Role |
|---|---|
| `sdks/python/qihse_task.py` | `@task` decorator, `.delay()`, `.apply_async()`, `AsyncResult` |
| `sdks/python/qihse.c` (modified) | C bindings for `TASK.*` RESP commands |

---

## 4. Task State Machine

```
                          ┌─────────┐
              submit ───▶ │ PENDING │
                          └────┬────┘
                               │ worker picks up
                               ▼
                          ┌─────────┐
                          │ STARTED │
                          └────┬────┘
                               │
                    ┌──────────┼──────────┐
                    │          │          │
                    ▼          ▼          ▼
              ┌─────────┐ ┌─────────┐ ┌─────────┐
              │ SUCCESS │ │ FAILURE │ │RETRYING │
              └─────────┘ └────┬────┘ └────┬────┘
                               │           │
                               │     backoff│
                               │           ▼
                               │     ┌─────────┐
                               │     │ PENDING │ (re-enqueued)
                               │     └─────────┘
                               │
                          max_retries exceeded
                               │
                               ▼
                          ┌─────────┐
                          │  DEAD   │ (dead-letter queue)
                          └─────────┘

  CANCELLED can occur from PENDING or STARTED at any time.
```

### States

| State | Description | Stored in |
|---|---|---|
| `PENDING` | Task submitted, waiting in priority queue | Event Stream + in-memory priority queue |
| `STARTED` | Worker has picked up the task | KV Store (task:{id} = state) |
| `SUCCESS` | Task completed, result available | KV Store (result:{id} = payload, TTL) |
| `FAILURE` | Task failed, will retry if retries remain | KV Store (task:{id} = state + error) |
| `RETRYING` | Task scheduled for retry with backoff | Event Stream (re-enqueued after delay) |
| `DEAD` | Max retries exhausted, moved to dead-letter | KV Store (dead:{id} = task + error) |
| `CANCELLED` | Task cancelled by user | KV Store (task:{id} = state) |

---

## 5. Priority Queue Design

### 4 Priority Levels

| Level | Name | Behavior |
|---|---|---|
| 0 | CRITICAL | Strict preemption — if a CRITICAL task arrives, the lowest-priority running task is yielded (cooperative) |
| 1 | HIGH | Dispatched before any NORMAL or LOW tasks |
| 2 | NORMAL | Default priority |
| 3 | LOW | Dispatched only when no higher-priority tasks are pending |

### Implementation

Each priority level has its own lock-free MPSC ring buffer in the task dispatcher. The dispatcher always drains from the highest-priority non-empty queue first. CRITICAL preemption is cooperative — the worker checks a preemption flag at each yield point (every 1000 Lua instructions or every 10ms for Python tasks).

```
Priority Queue (per shard / per node)

  CRITICAL  ──▶ [task][task][task]   ← drain first
  HIGH      ──▶ [task][task]
  NORMAL    ──▶ [task][task][task][task][task]
  LOW       ──▶ [task]
                                    ← drain last
```

### RESP Priority

Priority is set at submission time:

```
TASK.SUBMIT <queue> <priority> <payload>
```

Where `<priority>` is `CRITICAL`, `HIGH`, `NORMAL`, or `LOW` (case-insensitive, defaults to `NORMAL`).

---

## 6. Retry & Backoff

### Configuration

Per-task retry parameters are set in the task payload header:

| Field | Default | Description |
|---|---|---|
| `max_retries` | 3 | Maximum retry attempts before DEAD state |
| `base_delay_ms` | 1000 | Initial backoff delay |
| `max_delay_ms` | 60000 | Cap on backoff delay |
| `backoff_factor` | 2.0 | Exponential multiplier |
| `jitter_pct` | 10 | ± percentage of random jitter to prevent thundering herd |

### Backoff Formula

```
delay = min(max_delay_ms, base_delay_ms * (backoff_factor ^ retry_count))
delay = delay * (1 ± random(-jitter_pct, +jitter_pct) / 100)
```

### Retry Flow

1. Task fails (exception or non-zero exit code)
2. State → `FAILURE`
3. If `retry_count < max_retries`:
   - State → `RETRYING`
   - Compute backoff delay
   - Schedule re-enqueue after delay (via timing wheel)
   - State → `PENDING` when delay expires
4. If `retry_count >= max_retries`:
   - State → `DEAD`
   - Move to dead-letter queue (KV: `dead:{id}`)
   - Preserve original payload + all error traces

---

## 7. Dedicated Task Worker Pool

### Design

The task worker pool is **separate** from the shard query workers. This ensures that:
- Task execution does not increase query latency
- Query processing does not starve tasks
- NUMA allocation is independent

### Worker Allocation

| Parameter | Default | Tunable |
|---|---|---|
| `task_worker_count` | `min(4, num_cores - shard_workers)` | Yes |
| `task_worker_numa_node` | Round-robin across NUMA nodes | Yes |
| `task_worker_stack_size` | 256KB | Yes |
| `task_timeout_ms` | 30000 (30s) | Per-task override |

### Python Task Execution

Python tasks are executed in **subprocess workers** (not in-process threads) to avoid the GIL and isolate failures:

```
┌─────────────────────────────────────────────────────┐
│  Task Worker Thread (C, NUMA-pinned)                 │
│                                                      │
│  1. Dequeue task from priority queue                 │
│  2. Deserialize payload (msgpack, not pickle)        │
│  3. Fork subprocess: python3 -c <task_runner>        │
│     └─ imports target function                       │
│     └─ calls function with args                      │
│     └─ returns msgpack result via pipe               │
│  4. Wait for subprocess with timeout                 │
│  5. If timeout: SIGKILL subprocess, mark FAILURE     │
│  6. Serialize result, store in KV (result:{id})      │
│  7. Update task state in KV                          │
│  8. Record metrics in TSDB                           │
└─────────────────────────────────────────────────────┘
```

### Lua/WASM Task Execution

Native tasks execute in-process via the existing Lua Injector sandbox:

```
┌─────────────────────────────────────────────────────┐
│  Task Worker Thread (C, NUMA-pinned)                 │
│                                                      │
│  1. Dequeue task from priority queue                 │
│  2. Extract Lua script from payload                  │
│  3. Initialize LuaJIT sandbox with instruction quota │
│  4. Execute script with zero-copy vector/DB refs     │
│  5. Check instruction quota (anti-hang)              │
│  6. Serialize result, store in KV (result:{id})      │
│  7. Update task state in KV                          │
│  8. Record metrics in TSDB                           │
└─────────────────────────────────────────────────────┘
```

### Serialization

Python tasks use **msgpack** (not pickle) for security:
- No arbitrary code execution on deserialization
- Cross-language compatible (Python, Rust, C can all pack/unpack)
- Smaller payload size than pickle
- The target function is identified by `module.function` string, not pickled bytecode

---

## 8. Scheduling (Hybrid TSDB + Timing Wheel)

### Design

```
┌──────────────────────────────────────────────────────┐
│              SCHEDULER ARCHITECTURE                   │
│                                                      │
│  ┌─────────────┐     ┌──────────────┐               │
│  │  TSDB       │     │  Timing      │               │
│  │  (persist)  │────▶│  Wheel       │────▶ TASK.SUBMIT
│  │             │     │  (in-mem)    │               │
│  │  schedule:{ │     │              │               │
│  │   id} = {   │     │  • 256-slot  │               │
│  │   cron,     │     │    wheel      │               │
│  │   task,     │     │  • 10ms tick  │               │
│  │   args,     │     │  • O(1) per   │               │
│  │   priority, │     │    tick       │               │
│  │   enabled   │     │              │               │
│  │  }          │     │              │               │
│  └─────────────┘     └──────────────┘               │
│                                                      │
│  On startup: load all enabled schedules from TSDB    │
│  On crash: schedules survive in TSDB, rebuilt on     │
│  restart                                             │
│  On schedule add/update: persist to TSDB + update    │
│  timing wheel                                        │
└──────────────────────────────────────────────────────┘
```

### Cron Syntax

Standard 5-field cron: `minute hour day-of-month month day-of-week`

```
*/15 * * * *      → every 15 minutes
0 2 * * *         → daily at 02:00
0 */6 * * *       → every 6 hours
0 0 * * 1         → weekly on Monday
```

### Timing Wheel

A hierarchical timing wheel with 256 slots per level, 10ms tick interval:

| Level | Range | Slots |
|---|---|---|
| 1 | 0–2.56s | 256 × 10ms |
| 2 | 2.56s–10.92s | 256 × level-1-range |
| 3 | 10.92s–46.6m | 256 × level-2-range |
| 4 | 46.6m–198h | 256 × level-3-range |

O(1) per tick, O(1) insert. Sufficient resolution for task scheduling (10ms granularity).

### RESP Schedule Commands

```
SCHEDULE.ADD <id> <cron> <queue> <priority> <payload>
SCHEDULE.REMOVE <id>
SCHEDULE.LIST
SCHEDULE.ENABLE <id>
SCHEDULE.DISABLE <id>
SCHEDULE.NEXT <id>          → returns next fire time as ISO 8601
```

---

## 9. RESP Wire Protocol Extension

### New Commands

All commands are dispatched through the existing RESP engine (`qihse_resp_engine.c`).

#### Task Commands

```
TASK.SUBMIT <queue> [priority] <payload>
  → +OK <task_id>          (task_id = SHA-384 of queue||payload||timestamp)

TASK.RESULT <task_id>
  → $<n>\r\n<result_bytes>  (if SUCCESS)
  → -PENDING                (if not yet completed)
  → -FAILURE <error_msg>    (if DEAD or CANCELLED)

TASK.STATUS <task_id>
  → +PENDING | +STARTED | +SUCCESS | +FAILURE | +RETRYING | +DEAD | +CANCELLED

TASK.CANCEL <task_id>
  → +OK                    (marks CANCELLED, worker checks flag at yield point)

TASK.RETRY <task_id>
  → +OK                    (manual retry, resets retry_count to 0)

TASK.DELETE <task_id>
  → +OK                    (removes from KV + Event Stream)

TASK.QUEUE <queue_name>
  → *<n>                   (array of pending task IDs in that queue)

TASK.STATS <queue_name>
  → *6                     (pending, started, success, failure, dead, avg_latency_ms)
```

#### Schedule Commands

```
SCHEDULE.ADD <schedule_id> <cron> <queue> <priority> <payload>
  → +OK

SCHEDULE.REMOVE <schedule_id>
  → +OK

SCHEDULE.LIST
  → *<n>                   (array of schedule IDs)

SCHEDULE.ENABLE <schedule_id>
  → +OK

SCHEDULE.DISABLE <schedule_id>
  → +OK

SCHEDULE.NEXT <schedule_id>
  → +<ISO8601_timestamp>   (next fire time)
```

#### Worker Commands

```
TASK.WORKERS
  → *<n>                   (array of worker status: id, current_task, state, uptime)

TASK.WORKERS.PAUSE
  → +OK                    (pause all workers, finish current tasks)

TASK.WORKERS.RESUME
  → +OK                    (resume accepting new tasks)

TASK.WORKERS.SET <count>
  → +OK                    (dynamically resize worker pool)
```

### redis-cli Usage Examples

```bash
# Submit a task
redis-cli -p 6379 TASK.SUBMIT myqueue NORMAL '{"func": "myapp.tasks.process", "args": [1, 2]}'

# Check status
redis-cli -p 6379 TASK.STATUS <task_id>

# Get result
redis-cli -p 6379 TASK.RESULT <task_id>

# Cancel
redis-cli -p 6379 TASK.CANCEL <task_id>

# Add a periodic schedule
redis-cli -p 6379 SCHEDULE.ADD nightly_cleanup "0 2 * * *" myqueue LOW '{"func": "myapp.tasks.cleanup"}'

# List schedules
redis-cli -p 6379 SCHEDULE.LIST

# Worker status
redis-cli -p 6379 TASK.WORKERS
```

---

## 10. Python SDK

### API Design (`sdks/python/qihse_task.py`)

```python
from qihse_task import task, TaskClient

# Connect to QIHSE RESP server
client = TaskClient(redis_url="redis://localhost:6379")

# Define a task (Celery-compatible decorator)
@task(queue="myqueue", priority="NORMAL", max_retries=3, timeout=30)
def process_data(x, y):
    return x + y

# Submit (async)
result = process_data.delay(1, 2)
print(result.id)           # SHA-384 task ID
print(result.status)       # PENDING → STARTED → SUCCESS

# Get result (blocking with timeout)
value = result.get(timeout=60)
print(value)               # 3

# Submit with explicit priority
result = process_data.apply_async(args=(1, 2), priority="HIGH")

# Cancel
result.cancel()

# Periodic schedule
@task(queue="cleanup", priority="LOW", cron="0 2 * * *")
def nightly_cleanup():
    ...

# Or schedule programmatically
client.schedule_add(
    schedule_id="nightly_cleanup",
    cron="0 2 * * *",
    queue="cleanup",
    priority="LOW",
    payload={"func": "myapp.tasks.cleanup"}
)
```

### Celery Migration

```python
# Before (Celery)
from celery import Celery
app = Celery('tasks', broker='redis://localhost:6379')
@app.task
def process_data(x, y):
    return x + y
result = process_data.delay(1, 2)

# After (QIHSE) — minimal change
from qihse_task import task
@task(queue="myqueue")
def process_data(x, y):
    return x + y
result = process_data.delay(1, 2)
```

### Serialization

- Python tasks are serialized as **msgpack** with the following structure:
  ```python
  {
      "func": "myapp.tasks.process_data",  # importable module.function path
      "args": [1, 2],
      "kwargs": {},
      "retry": {"max": 3, "base_delay_ms": 1000, "factor": 2.0, "jitter_pct": 10},
      "timeout_ms": 30000,
      "priority": "NORMAL"
  }
  ```
- The worker subprocess imports `myapp.tasks.process_data` and calls it with `args` / `kwargs`
- Results are msgpack-serialized and stored in KV with TTL

---

## 11. Implementation Phases

### Phase 1: Core Task Dispatch + State Machine

**Goal**: Submit a task, have a worker execute it, retrieve the result.

| Component | What |
|---|---|
| `qihse_task_queue.c/h` | Task struct, state machine, priority queue (4 MPSC ring buffers), task ID generation |
| `qihse_task_worker.c/h` | Worker thread pool, NUMA pinning, Python subprocess execution, timeout handling |
| `qihse_resp_engine.c` (mod) | `TASK.SUBMIT`, `TASK.RESULT`, `TASK.STATUS`, `TASK.QUEUE` |
| Event Stream integration | Tasks enqueued as event stream records (broker) |
| KV Store integration | Results + state stored in KV with TTL |
| TSDB integration | Task metrics (latency, throughput) recorded in time-series |
| Tests | `test_task_queue.c`, `test_task_worker.c` |

**Deliverable**: `redis-cli TASK.SUBMIT myqueue NORMAL '{"func":"test.add","args":[1,2]}'` → worker executes → `TASK.RESULT <id>` returns `3`.

### Phase 2: Retry, Backoff, Priority, Cancellation

**Goal**: Full task lifecycle with retry, priority dispatch, and cancellation.

| Component | What |
|---|---|
| `qihse_task_queue.c` (ext) | Retry state machine, exponential backoff + jitter, dead-letter queue |
| Priority preemption | CRITICAL task preemption flag, cooperative yield in Lua sandbox |
| `TASK.CANCEL`, `TASK.RETRY`, `TASK.DELETE` | RESP commands |
| `TASK.STATS` | Queue statistics |
| Tests | `test_task_retry.c`, `test_task_priority.c`, `test_task_cancel.c` |

**Deliverable**: Tasks with `max_retries=3` retry with backoff on failure. CRITICAL tasks preempt LOW tasks. `TASK.CANCEL` stops running tasks.

### Phase 3: Python SDK

**Goal**: Celery-compatible `@task` decorator and `AsyncResult` API.

| Component | What |
|---|---|
| `sdks/python/qihse_task.py` | `@task` decorator, `.delay()`, `.apply_async()`, `AsyncResult.get()`, `.cancel()` |
| `sdks/python/qihse.c` (mod) | C bindings for `TASK.*` RESP commands |
| msgpack serialization | Payload encoding/decoding |
| Subprocess task runner | `python3 -c qihse_task_runner.py <payload>` |
| Tests | `test_python_task.py` — end-to-end submit/execute/result |

**Deliverable**: `@task` decorated Python function, `.delay()` returns `AsyncResult`, `.get()` returns value. Drop-in Celery migration for basic tasks.

### Phase 4: Periodic Scheduling

**Goal**: Cron-based periodic task dispatch with crash-safe persistence.

| Component | What |
|---|---|
| `qihse_task_scheduler.c/h` | Cron parser, hierarchical timing wheel, TSDB persistence |
| `SCHEDULE.*` commands | RESP commands for schedule management |
| Scheduler thread | Background thread, 10ms tick, dispatches due tasks to priority queue |
| Crash recovery | On startup, load enabled schedules from TSDB, rebuild timing wheel |
| Tests | `test_task_scheduler.c` — schedule add, fire, remove, crash recovery |

**Deliverable**: `SCHEDULE.ADD nightly "0 2 * * *" cleanup LOW '{"func":"cleanup"}'` → task dispatched at 02:00 daily. Schedules survive process restart.

---

## 12. File Layout (New Files)

```
QIHSE/
├── include/
│   ├── qihse_task_queue.h          # Phase 1
│   ├── qihse_task_worker.h         # Phase 1
│   └── qihse_task_scheduler.h      # Phase 4
├── src/
│   ├── spinnaker/
│   │   ├── qihse_task_queue.c      # Phase 1
│   │   ├── qihse_task_worker.c     # Phase 1
│   │   ├── qihse_task_scheduler.c  # Phase 4
│   │   └── qihse_resp_engine.c     # Modified (all phases)
│   └── marmalade/
│       └── qihse_task_scheduler.c  # Phase 4 (TSDB integration)
├── tests/
│   ├── test_task_queue.c           # Phase 1
│   ├── test_task_worker.c          # Phase 1
│   ├── test_task_retry.c           # Phase 2
│   ├── test_task_priority.c        # Phase 2
│   ├── test_task_cancel.c          # Phase 2
│   └── test_task_scheduler.c       # Phase 4
├── benchmarks/
│   └── qihse_task_bench.c          # Throughput benchmark
└── sdks/python/
    ├── qihse_task.py               # Phase 3
    └── qihse.c                     # Modified (Phase 3)
```

---

## 13. Makefile Targets

```makefile
# Phase 1
task-queue: src/spinnaker/qihse_task_queue.c src/spinnaker/qihse_task_worker.c
	$(CC) $(CFLAGS) -c src/spinnaker/qihse_task_queue.c -o src/spinnaker/qihse_task_queue.o
	$(CC) $(CFLAGS) -c src/spinnaker/qihse_task_worker.c -o src/spinnaker/qihse_task_worker.o

# Phase 4
task-scheduler: src/spinnaker/qihse_task_scheduler.c
	$(CC) $(CFLAGS) -c src/spinnaker/qihse_task_scheduler.c -o src/spinnaker/qihse_task_scheduler.o

# Tests
test-task-queue: task-queue tests/test_task_queue.c
	$(CC) $(CFLAGS) tests/test_task_queue.c -o tests/test_task_queue $(LIBS)
test-task-worker: task-queue tests/test_task_worker.c
	$(CC) $(CFLAGS) tests/test_task_worker.c -o tests/test_task_worker $(LIBS)
test-task-retry: task-queue tests/test_task_retry.c
	$(CC) $(CFLAGS) tests/test_task_retry.c -o tests/test_task_retry $(LIBS)
test-task-priority: task-queue tests/test_task_priority.c
	$(CC) $(CFLAGS) tests/test_task_priority.c -o tests/test_task_priority $(LIBS)
test-task-cancel: task-queue tests/test_task_cancel.c
	$(CC) $(CFLAGS) tests/test_task_cancel.c -o tests/test_task_cancel $(LIBS)
test-task-scheduler: task-scheduler tests/test_task_scheduler.c
	$(CC) $(CFLAGS) tests/test_task_scheduler.c -o tests/test_task_scheduler $(LIBS)

# Benchmark
bench-task: task-queue benchmarks/qihse_task_bench.c
	$(CC) $(CFLAGS) benchmarks/qihse_task_bench.c -o benchmarks/qihse_task_bench $(LIBS)
```

---

## 14. Advantages Over Celery

| Feature | Celery | QIHSE Task Queue |
|---|---|---|
| **Broker** | External (Redis/RabbitMQ) | Built-in (Event Stream, in-process) |
| **Result backend** | External (Redis/DB) | Built-in (KV Store, in-process) |
| **Worker model** | OS processes (prefork) | NUMA-pinned threads + subprocess for Python |
| **Dispatch latency** | ~1ms (network hop to broker) | Sub-microsecond (in-process ring buffer) |
| **Hardware awareness** | None | NUMA pinning, SIMD, AF_XDP, HugePages |
| **Priority** | Limited (queue-based) | 4 levels with CRITICAL preemption |
| **Scheduling** | Separate process (Celery Beat) | Built-in timing wheel + TSDB persistence |
| **Backpressure** | No | System Guard sliding-window throttle |
| **Serialization** | pickle (security risk) | msgpack (safe, cross-language) |
| **Sandboxed execution** | No (arbitrary Python) | Lua/WASM sandbox with instruction quotas |
| **Cluster-native** | Requires Redis Cluster | 16,384 hash slots, shard-native dispatch |
| **Multi-model state** | KV only | KV (results) + TS (metrics) + Columnar (analytics) |
| **Wire protocol** | AMQP/Redis | RESP2/RESP3 (Redis-compatible) |
| **Crash recovery** | Broker-dependent | Event Stream durability + TSDB schedule persistence |
| **Metrics** | External (Flower/Prometheus) | Built-in TSDB + RESP `TASK.STATS` |

---

## 15. Out of Scope (Deferred to Future Phase)

| Feature | Rationale |
|---|---|
| Task chains (A→B→C) | Can be emulated with Event Stream topics; formal API deferred |
| Task groups (A+B+C parallel) | Can use scatter-gather; formal API deferred |
| Task chords (A+B+C → D) | Scatter-gather + aggregate exists; formal API deferred |
| Task events/streaming | Event Stream exists; subscription API for task events deferred |
| Web dashboard | RESP commands + external tool sufficient for now |
| Rust SDK | Python SDK first; Rust SDK follows existing pattern |
| Workflow engine (Airflow-equivalent) | Separate plan if needed |

---

## 16. Benchmark Targets

| Metric | Target | Method |
|---|---|---|
| Task dispatch latency (p50) | < 50µs | In-process priority queue dequeue |
| Task dispatch latency (p99) | < 200µs | Same |
| Task throughput (1 worker) | > 10,000 tasks/sec | Lightweight Lua tasks, no I/O |
| Task throughput (4 workers) | > 35,000 tasks/sec | Same, NUMA-pinned |
| Python task overhead | < 5ms (subprocess fork + msgpack) | `process_data(1, 2)` end-to-end |
| Retry backoff precision | ±10ms of target | Timing wheel tick resolution |
| Schedule precision | ±10ms of cron target | Timing wheel tick resolution |
| Crash recovery time | < 100ms | TSDB schedule load + timing wheel rebuild |

---

## 17. Test Plan

### Unit Tests

| Test | Tests | Description |
|---|---|---|
| `test-task-queue` | 8+ | Submit, state transitions, priority ordering, queue listing |
| `test-task-worker` | 6+ | Worker lifecycle, task execution, timeout, NUMA pinning |
| `test-task-retry` | 5+ | Retry count, backoff timing, jitter, dead-letter on exhaustion |
| `test-task-priority` | 5+ | 4-level ordering, CRITICAL preemption, starvation prevention |
| `test-task-cancel` | 4+ | Cancel pending, cancel running, cooperative yield, double-cancel |
| `test-task-scheduler` | 6+ | Cron parse, timing wheel, schedule add/remove, crash recovery |

All tests must be Valgrind-clean (0 bytes in use at exit, 0 errors), matching existing QIHSE test standards.

### Integration Test

```
make task-queue test-task-worker
LD_LIBRARY_PATH=. ./tests/test_task_worker --benchmark
```

### Python SDK Test

```bash
cd sdks/python && python3 test_task.py
```

---

## 18. Dependencies

| Dependency | Status | Purpose |
|---|---|---|
| Event Stream (`qihse_event_stream`) | Complete | Task broker |
| KV Store (`qihse_kv_*`) | Complete | Result + state storage |
| Time-Series DB (`qihse_timeseries`) | Complete | Task metrics + schedule persistence |
| System Guard (`qihse_system_guard`) | Complete | Backpressure |
| Lua Injector (`qihse_lua_injector`) | Complete | Native task execution |
| Cluster Bus (`qihse_cluster_bus`) | Complete | Inter-node task dispatch |
| Dist Planner (`qihse_dist_planner`) | Complete | Hardware-aware routing |
| RESP Engine (`qihse_resp_engine`) | Complete | Wire protocol (to be extended) |
| msgpack-c | **New dependency** | Payload serialization (C library, header-only option) |
| Python msgpack | **New dependency** | Python SDK serialization |

No other new dependencies. All core infrastructure exists.
