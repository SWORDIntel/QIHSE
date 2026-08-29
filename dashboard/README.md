# QIHSE Runtime Dashboard

The dashboard is a lightweight React/Vite observability UI for the native QIHSE runtime.

## Data source

The UI polls the same-origin path:

```text
/metrics
```

During `npm run dev`, Vite proxies that path to:

```text
http://127.0.0.1:8080/metrics
```

For another deployment topology, set the Vite metrics URL when running the dev server or building the dashboard:

```bash
VITE_QIHSE_METRICS_URL=https://qihse.example.internal/metrics npm run dev
```

or:

```bash
VITE_QIHSE_METRICS_URL=https://qihse.example.internal/metrics npm run build
```

The current payload is expected to provide:

```json
{
  "qps": 0,
  "latency": 0,
  "active_vectors": 0
}
```

The dashboard treats the native endpoint as the source of truth. It does **not** fabricate cluster, storage, GPU/NPU, or XDP values when those counters are unavailable.

## Current visibility

The overview displays:

- telemetry connection state;
- stale/unavailable feed warnings;
- current QPS;
- rolling and peak QPS;
- current and rolling-average latency;
- observed-window p95 and p99 latency;
- active vector count;
- successful/failed dashboard polls;
- last telemetry update;
- throughput and latency time-series charts.

Cluster, storage, and network views explicitly identify metrics that are not yet exported by the native runtime.

## Run

```bash
cd dashboard
npm install
npm run dev
```

Production build:

```bash
npm run build
```

Lint:

```bash
npm run lint
```

For production, either serve the dashboard behind the same reverse proxy as QIHSE so `/metrics` is same-origin, or build with `VITE_QIHSE_METRICS_URL` set to a metrics endpoint that permits the dashboard origin.

## Native telemetry backlog

For deeper operational visibility, extend the native metrics contract before adding UI state. Useful future metrics include:

```text
qihse_queries_total{type,backend}
qihse_query_latency_seconds
qihse_query_errors_total{type,backend}
qihse_backend_available{backend}
qihse_backend_utilization{backend}
qihse_index_bytes{index}
qihse_memory_bytes{tier,node}
qihse_replication_lag{peer}
qihse_cluster_node_state{node}
qihse_network_rx_bytes
qihse_network_tx_bytes
qihse_xdp_packets
qihse_xdp_drops
qihse_optimizer_decisions_total{plan}
qihse_optimizer_rollbacks_total{reason}
```

The dashboard should remain a renderer of runtime truth rather than an independent source of operational claims.
