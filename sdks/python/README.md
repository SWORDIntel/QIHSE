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

The `qihse_pg` client completes PostgreSQL startup authentication before it
returns a connection, then reads each command through `ReadyForQuery` so server
errors and transport failures reach the caller. Managed connections issue
`BEGIN` before their first statement and only update transaction state after a
successful command-complete/ready response. The current QIHSE PG wire server
does not yet implement transaction commands, so these calls fail explicitly;
use `autocommit=True` only when statement-at-a-time behavior is intended. The
current server also rejects PostgreSQL SSL negotiation and asks for a cleartext
password, so do not send credentials over an untrusted network.

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


## Cluster administration (hardened masters)

Hardened masters (`pqc_require` — any node with replication/migration/admin
pins) reject cleartext RESP, so the protocol-emulation adapters above
(`qihse_http`, `qihse_mongo`, …) cannot reach them. Use the administration
SDK instead. `ClusterAdmin` calls the in-process C QKP client (`qihse_qkp_admin_exec` in `libqihse.so` via ctypes) when available and falls back to `qihse-admin-cli` (e.g. when `sudo=True` is needed for root-only keys), plus exposes `execute()` and full cluster/admin helpers; `ClusterOps` wraps the ops scripts:

```python
from qihse_admin import ClusterAdmin, ClusterOps

ca = ClusterAdmin(admin_cli="/opt/QIHSE/bin/qihse-admin-cli",
                  node_id="admin-t420",          # matches --admin-peer-node-id
                  identity_dir="/etc/qihse/keys",
                  sudo=True)                     # identity keys are root-only

ca.ping("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem")
# Unwrapped RESP commands are passed as separate arguments (including spaces).
ca.execute("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem",
           "CONFIG", "GET", "cluster-announce-ip")
ca.cluster_nodes("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem")
ca.set("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "k", "v")
ca.moveslots("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem",
             4916, 4916, "192.168.1.91:7100")
ca.reclaim("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem")

# Key management — strings, generic keys, hashes, lists, sets, sorted sets,
# bitmaps and HyperLogLog, all over the same pinned-QKP admin identity.
ca.incr("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "counter")
ca.expire("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "counter", 600)
ca.keys("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "sabot/*")
ca.hset("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "h", "f", "v")
ca.lrange("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "l", 0, -1)
ca.zadd("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "z", {"m": 1.0})
ca.zrank("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "z", "m")
ca.zpopmax("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "z")

# The full sorted-set surface (ZRANK/ZREVRANK/ZPOPMAX/ZPOPMIN/ZCOUNT) is now
# implemented server-side (`qihse_resp_engine.c`) — previously nil/empty stubs.

ops = ClusterOps()              # wraps scripts/cluster_*.sh
ops.watchdog()
ops.rolling_restart(verify_only=True)
```

See `docs/OPERATIONS.md` for the full operational model (replication,
slot migration durability, backup/restore, rolling restart).
