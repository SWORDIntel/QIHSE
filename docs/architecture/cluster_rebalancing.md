# QIHSE Automated Zero-Downtime Cluster Rebalancing & Live Dynamic Migration

## 1. Executive Summary

QIHSE features an autonomous, zero-downtime **Cluster Slot Rebalancing and Dynamic Migration Engine** (`include/qihse_cluster_rebalance.h`). When new nodes join via `CLUSTER MEET` or hardware nodes fail over, the cluster autonomously calculates slot variances across all primary nodes and transitions hash slots with zero downtime using non-blocking `-ASK` handoffs.

---

## 2. Architecture & State Machine

```
      [Donor Node S]                                           [Receiver Node T]
             │                                                         │
             │   1. qihse_cluster_migration_begin(slot, S, T)          │
             │   ────────────────────────────────────────────►         │
             │   Slot state: MIGRATING                         │       │
             │   (Unfound local keys return -ASK T)            │       │
             │                                                 │       │
             │   2. Slot state: IMPORTING                      │       │
             │      (Receiver accepts ASKING prefix)           │       │
             │                                                 │       │
             │   3. Stream SSTables / Trinary Trie chunks      │       │
             │   ═════════════════════════════════════════════►│       │
             │                                                 │       │
             │   4. qihse_cluster_migration_commit()           │       │
             │   ────────────────────────────────────────────► │       │
             │   Slot state: STABLE (Owner = T)                │       │
             │                                                         │
             │   5. Broadcast epoch gossip via Cluster Bus UDP 16379    │
             ▼                                                         ▼
```

---

## 3. Imbalance Analysis & Planning Algorithm

The planner computes the ideal slot target per active, healthy primary node:

$$\text{Target} = \left\lfloor \frac{16384}{N_{\text{primaries}}} \right\rfloor$$

$$\text{Imbalance Variance} = \frac{1}{16384} \sum_{i=1}^{N} \left| S_i - \text{Target} \right|$$

* If $\text{Variance} < \text{threshold}$ (default $0.05$ or $5\%$), the cluster is balanced and no migrations are scheduled.
* If $\text{Variance} \ge \text{threshold}$, donor nodes ($S_i > \text{Target}$) transfer contiguous slot ranges to receiver nodes ($S_j < \text{Target}$) until variance is minimized.

---

## 4. Zero-Downtime Migration Guarantees

1. **Non-Blocking Query Continuity**:
   - Keys already present on the donor node continue to be served locally.
   - Keys migrated to the receiver or not yet found on the donor return `-ASK <slot> <target_ip>:<target_port>`, which Redis smart clients handle transparently.
2. **Atomic Ownership Handshake**:
   - Slot ownership switch occurs atomically via 64-byte aligned RCU pointer and epoch increment (`qihse_cluster_migration_commit()`).
3. **Multi-Model State Transfer**:
   - Migrates Black Hole KV state, Broad Oak Vector embeddings, and Marmalade Gorilla TSDB series chunks.

---

## 5. API Reference

```c
// Create rebalancer instance
qihse_cluster_rebalancer_t* rebalancer = qihse_cluster_rebalancer_create(
    topology, kv_store, vector_db, cluster_bus
);

// Plan rebalancing moves
qihse_cluster_rebalance_plan_t* plan = qihse_cluster_plan_rebalance(topology, 0.05);

// Execute all migrations sequentially with zero downtime
if (plan) {
    qihse_cluster_rebalance_all(rebalancer, plan);
    qihse_cluster_rebalance_plan_free(plan);
}

qihse_cluster_rebalancer_destroy(rebalancer);
```
