# QIHSE Python Native SDK

This directory contains the zero-overhead CPython bindings for QIHSE. By bypassing traditional IPC and executing directly against the C memory space, you retain the uncompromising exactness and speed of QIHSE natively within Python.

## Building the SDK

To compile the native C extensions:

```bash
cd sdks/python
python3 setup.py build_ext --inplace
```

## Quickstart

```python
import qihse

# Bootstraps the full QIHSE engine in memory, including
# Vector, KV, Document, Columnar, and Time-Series engines.
db = qihse.Database()

# Execute raw QQL queries
db.execute("SEARCH VECTOR...")

# Key-Value API
db.kv_set("agent_status", "active")
status = db.kv_get("agent_status")
```

## Proxies

You can launch native C-level wire proxies directly from Python. These run in detached background threads within the C extension and map external clients directly into the QIHSE engine via memory pointers, bypassing Python's GIL.

```python
# Spin up Redis-compatible wire protocol on port 6379
db.start_resp_proxy("0.0.0.0", 6379)

# Spin up Postgres-compatible wire protocol on port 5432
db.start_pg_proxy("0.0.0.0", 5432)
```

## Security & Supernatural Auth Gates

The SDK natively binds the Cell-Level clearance engine and God-Mode Operator protections. 

```python
# Create a user (Only User 0 'Chuck/Operator' can do this initially)
# db.auth_create_user(creator_id, target_user_id, role, clearance, sci)
db.auth_create_user(0, 100, 2, 0, 0) # User 100: Guest, Unclassified

# Check Clearance mathematically
allowed = db.auth_can_access(100, 1, 0) # False

# The Bullet Speaks: Attempting to destroy User 0
# This immediately triggers an interactive Y/N prompt on standard input at the C level.
db.auth_destroy_user(0)
```

## Celery-Equivalent Task Queue & Scheduler (`qihse_task`)

QIHSE provides a built-in, distributed task queue and periodic scheduler engine backed by native C worker threads, 4 priority levels, and 10ms timing wheel cron scheduling.

```python
from qihse_task import task, TaskClient

# Connect to QIHSE RESP server
client = TaskClient(host="127.0.0.1", port=6379)

# Define async tasks with @task decorator
@task(queue="recon", priority="HIGH", max_retries=3, timeout=30)
def analyze_target(target_id: str, depth: int = 1):
    # Heavy analysis or network reconnaissance
    return {"target": target_id, "score": 98.6}

# 1. Asynchronous dispatch (.delay / .apply_async)
handle = analyze_target.delay("TARGET-801", depth=3)
print(f"Task ID: {handle.id} | Status: {handle.status}")

# 2. Wait for result
result = handle.get(timeout=10.0)
print("Result:", result)

# 3. Custom priority and execution options
handle2 = analyze_target.apply_async(
    args=("URGENT-001",),
    kwargs={"depth": 5},
    priority="CRITICAL",
    timeout=60
)

# 4. Periodic Cron Task Scheduling (Celery Beat replacement)
client.schedule_add(
    schedule_id="daily_cleanup",
    cron_expr="0 2 * * *",
    queue_name="maintenance",
    payload={"func": "tasks.daily_vacuum"},
    priority="LOW"
)
next_run = client.schedule_next("daily_cleanup")
print("Next scheduled run:", next_run)
```

