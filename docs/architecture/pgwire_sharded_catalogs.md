# QIHSE PostgreSQL Wire Protocol (PGWire) Sharded Partitioning & Multi-Engine Virtual Catalogs

## 1. Executive Summary

QIHSE incorporates a native **PostgreSQL Wire Protocol v3 Server** (`include/qihse_pg_wire.h`) extended with **16,384 CRC16 Hash Slot Partitioning** and **Multi-Engine Virtual System Catalogs**.

This enables standard SQL clients, BI platforms, and ORMs (`psql`, SQLAlchemy, Prisma, DBeaver, Grafana, Superset, Metabase) to connect directly over standard TCP port 5432 and execute multi-model queries across vector, time-series, columnar, and KV stores without middleware or proxies.

---

## 2. Architecture & Virtual System Catalogs

```
                    Standard SQL Clients (psql / DBeaver / Grafana / Metabase)
                                            │
                                            ▼ TCP Port 5432 / eBPF XDP Ingress
                        ┌───────────────────────────────────────┐
                        │    QIHSE PGWire Protocol v3 Engine    │
                        │  - Startup & Auth Handshake           │
                        │  - Extended Query Protocol (P/B/D/E)  │
                        │  - Virtual System Catalogs            │
                        └───────────────────┬───────────────────┘
                                            │
                        ┌───────────────────┴───────────────────┐
                        ▼                                       ▼
           ┌────────────────────────┐              ┌────────────────────────┐
           │ Virtual System Catalogs│              │ Distributed Query      │
           │  - pg_tables           │              │ Multi-Engine Planner   │
           │  - cluster_nodes       │              │  - {tag} CRC16 routing │
           │  - cluster_slots       │              │  - SIMD Vector / TSDB  │
           └────────────────────────┘              └────────────────────────┘
```

---

## 3. Supported Virtual Tables & Views

When clients introspect the database schema (via `pg_catalog.pg_tables` or `information_schema.tables`), QIHSE returns virtual system tables representing its multi-engine architecture:

| Virtual Table | Object Type | Description |
|---|---|---|
| `vectors` | Table | Broad Oak Vector Database (float32 SIMD embeddings & scores) |
| `kv_store` | Table | Black Hole Trinary Trie & SSTable Key-Value Store |
| `timeseries` | Table | Marmalade Gorilla Time-Series Metric Stream |
| `column_store` | Table | Frieze Vectorized Columnar OLAP Engine |
| `cluster_nodes` | View | Live cluster node topology (node ID, IP, port, role, health) |
| `cluster_slots` | View | 16,384 hash slot allocation ranges and primary ownership |

---

## 4. Query Execution & Sharded Routing

### 4.1 Topology & Cluster Introspection
```sql
-- Query live cluster topology directly from psql
SELECT * FROM cluster_nodes;
-- Returns:
-- node_id        | host      | port | role   | status
-- node_alpha     | 10.0.0.1  | 5432 | master | connected
-- node_beta      | 10.0.0.2  | 5432 | master | connected
```

### 4.2 Partition-Scoped & Hybrid Multi-Model Queries
```sql
-- Scoped single-shard vector similarity query (O(1) slot dispatch)
SELECT * FROM {device_4096} WHERE vector_search(embedding, top_k=5);

-- Multi-shard time-series and columnar scan
SELECT * FROM telemetry WHERE ts_range(ts, 0, 1000000) AND AVG(cpu_temp) > 80.0;
```

---

## 5. C99 API Reference

```c
// Start sharded PostgreSQL wire server
bool ok = qihse_start_pg_wire_cluster_server(
    kv_store, vector_db, tsdb, column_store, topology, 5432, "0.0.0.0"
);

// Synchronously handle client socket with multi-model engine context
qihse_pg_wire_handle_client_multi(
    client_fd, kv_store, vector_db, tsdb, column_store, topology
);
```
