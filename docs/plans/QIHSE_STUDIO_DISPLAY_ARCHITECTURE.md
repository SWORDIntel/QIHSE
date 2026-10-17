# QIHSE Studio: Next-Gen Real-Time Display & Control Architecture

> **Status: planned & in-flight.** Architecture specification for the next-generation QIHSE operations, telemetry, and vector exploration studio.
> **Role:** Master architectural blueprint for the ASP.NET Core 8 SignalR backend and modern React (TypeScript/Tailwind/shadcn) SPA frontend.
> **Cross-reference:** Complements [ROADMAP.md](../../ROADMAP.md) and [docs/plans/ZEN4_ZEN2_HARDWARE_ROADMAP.md](ZEN4_ZEN2_HARDWARE_ROADMAP.md).

---

## 1. Executive Summary & Design Rationale

The legacy operator browser (`python/qihse/browser/` + `dashboard/`) suffered from architectural constraints:
1. **Polling Latency & Protocol Mismatch**: HTTP client-side polling every 2–5 seconds over Python `asyncio` or threaded HTTP created polling lag, unable to reflect microsecond retrieval dynamics or 60 Hz real-time cluster state transitions.
2. **Minimalist Raw Visualizations**: Views fell back to raw JSON dumps (`<pre>{JSON.stringify(...)}</pre>`) rather than rich, interactive graphics.
3. **Limited Hardware Topology Awareness**: Did not visually reflect QIHSE's multi-tier hardware acceleration across heterogeneous nodes (Broadwell-EP R730xd, Zen 4 Ryzen 9 7950X, Zen 2 EPYC 7662, and Ivy Bridge host).

**QIHSE Studio** replaces this model with a unified, dual-engine stack:
* **Backend (`Qihse.Studio.Server`)**: ASP.NET Core 8 Web API + SignalR streaming hub over zero-allocation `System.IO.Pipelines` talking native RESP (Redis Serialization Protocol) directly to cluster daemons over TCP.
* **Frontend (`Qihse.Studio.Client`)**: React 18 SPA (TypeScript + Vite + Tailwind CSS + Radix UI / shadcn + Canvas/ECharts) delivering sub-millisecond telemetry updates, an interactive 16,384-slot cluster ring, and a 3D/2D HNSW vector traversal playground.

---

## 2. System Architecture

```
                       ┌────────────────────────────────────────────────────────┐
                       │                   QIHSE CLUSTER FLEET                  │
                       │                                                        │
                       │  Node 0 (Host Ivy Bridge-EP @ 127.0.0.1:7197)          │
                       │  Node 5 (R730xd Broadwell-EP @ 192.168.1.90:7197)       │
                       │  Node S (Zen 4 7950X @ linuxagent-ispsystem-test)      │
                       │  Node R (Zen 2 EPYC 7662 @ linuxagent-relay)           │
                       └───────────────────▲────────────────────────────────────┘
                                           │ Native RESP Protocol (TCP)
                                           │ Zero-Alloc System.IO.Pipelines
                       ┌───────────────────▼────────────────────────────────────┐
                       │          ASP.NET CORE 8 MIDDLEWARE BACKEND             │
                       │                                                        │
                       │  • QihseRespClient: High-throughput TCP wire client    │
                       │  • ClusterTopologyWorker: Real-time slot & mesh poll   │
                       │  • TelemetryWorker: Rolling microsecond latency & QPS  │
                       │  • QihseTelemetryHub: SignalR WebSocket Streamer       │
                       │  • REST Endpoints: Vector search, command dispatch     │
                       └───────────────────▲────────────────────────────────────┘
                                           │ WebSockets (SignalR) + JSON REST
                                           │ Sub-millisecond push updates
                       ┌───────────────────▼────────────────────────────────────┐
                       │          MODERN REACT SPA (TypeScript + Vite)          │
                       │                                                        │
                       │  • Tailwind CSS + Lucide Icons + Radix UI (shadcn)     │
                       │  • Apache ECharts / Recharts streaming time-series     │
                       │  • Interactive Cluster Mesh & 16,384 Slot Ring (Canvas)│
                       │  • 3D/2D HNSW Graph Traversal & Vector Playground      │
                       │  • Live CPU ISA Specialization Dashboard               │
                       └────────────────────────────────────────────────────────┘
```

---

## 3. Core Subsystems

### A. ASP.NET Core 8 Backend Engine (`portal/src/Qihse.Studio.Server`)

1. **Zero-Allocation RESP Client (`QihseRespClient.cs`)**:
   - Manages persistent socket connections to QIHSE nodes.
   - Parses RESP arrays, bulk strings, integers, and error payloads at line rate without managed heap allocation spikes.
   - Executes cluster commands (`CLUSTER NODES`, `CLUSTER SLOTS`, `INFO`, `FABRIC.CAPS`, `INTROSPECTION.QKP`).

2. **SignalR Streaming Telemetry Hub (`Hubs/TelemetryHub.cs`)**:
   - Streams 10–30 Hz real-time telemetry frames to all connected client sessions.
   - Dispatches:
     - Instantaneous QPS and rolling averages.
     - P50, P95, and P99 latency percentiles (in microseconds).
     - Slot migration events and cluster node failover status.
     - Node-level memory pressure and hardware pipeline utilization.

3. **Background Mesh & Health Worker (`Services/ClusterMeshService.cs`)**:
   - Continuously interrogates node health and cluster partition state.
   - Maintains cached state models for instant serving to newly connected web clients.

### B. Modern React SPA (`portal/src/Qihse.Studio.Client`)

1. **View 1: Real-Time Fleet & Hardware Telemetry**:
   - **Hardware ISA Matrix**: Visual monitors for all 13+ ISA extensions (`AVX-512 VPOPCNTDQ`, `AVX-512 VNNI`, `SHA-NI`, `VPCLMULQDQ`, `CLZERO`, `CLWB`, `RDPID`, `TSX RTM`, `FMA3`, `AVX2`).
   - **Live Rolling Charts**: Streaming microsecond latency curves (P50/P95/P99) and transactional throughput.

2. **View 2: Interactive Cluster Mesh & 16,384 Shard Slot Ring**:
   - **Canvas Slot Ring**: 16,384 cluster hash slots mapped across active shard masters.
   - **Live Slot Migration Animation**: Real-time visual movement of slots during `CLUSTER MOVESLOTS` rebalancing.
   - **Inter-Node Latency Matrix**: Cross-node wire rate (e.g. 943 Mbps Broadwell link) and RTT tracking.

3. **View 3: Vector DB & HNSW Graph Explorer**:
   - **Vector Search Playground**: Interactive $k$-NN search interface allowing query vector inputs, metric selection (Cosine, L2, Dot Product), and precision tiering (FP32 vs FP16 vs INT8).
   - **HNSW Layer Traversal Visualizer**: Multi-layer graph visualization displaying beam-search navigation and Layer-0 candidate promotion.
   - **Hamming Pre-Filter Monitor**: Visual binary quantization sign-bit masks and popcount acceleration metrics.

---

## 4. Directory Layout

```text
portal/
├── Qihse.Studio.sln
├── src/
│   ├── Qihse.Studio.Server/          # ASP.NET Core 8 Web API & SignalR
│   │   ├── Program.cs
│   │   ├── Hubs/
│   │   │   └── TelemetryHub.cs       # Real-time WebSocket hub
│   │   ├── Models/
│   │   │   ├── NodeTelemetry.cs
│   │   │   ├── ClusterTopology.cs
│   │   │   └── VectorSearchModels.cs
│   │   ├── Services/
│   │   │   ├── QihseRespClient.cs    # TCP RESP protocol client
│   │   │   └── ClusterMeshService.cs # Topology & health poller
│   │   └── Controllers/
│   │       ├── TelemetryController.cs
│   │       ├── VectorController.cs
│   │       └── ClusterController.cs
│   │
│   └── Qihse.Studio.Client/          # React 18 + Vite + TS SPA
│       ├── package.json
│       ├── vite.config.ts
│       ├── tailwind.config.js
│       ├── index.html
│       └── src/
│           ├── types/                # Telemetry & Cluster types
│           ├── hooks/
│           │   └── useSignalR.ts     # Real-time streaming hook
│           ├── components/           # UI primitives & charts
│           │   ├── Header.tsx
│           │   ├── HardwareMatrix.tsx
│           │   ├── LatencyChart.tsx
│           │   └── SlotRingCanvas.tsx
│           └── views/
│               ├── TelemetryView.tsx # Hardware & latency dashboard
│               ├── ClusterMeshView.tsx # 16,384 slot ring & nodes
│               └── VectorHnswView.tsx# Vector DB & graph explorer
```

---

## 5. Development & Deployment Workflow

1. **Standalone Development**:
   - Backend: `~/.dotnet/dotnet run --project portal/src/Qihse.Studio.Server` (listens on `http://localhost:5000`)
   - Frontend: `cd portal/src/Qihse.Studio.Client && npm run dev` (Vite dev server with hot reload on `http://localhost:5173`, proxying `/api` and `/hub` to port 5000).

2. **Production Deployment & Systemd Service**:
   - `npm run build` in `Qihse.Studio.Client` bundles the SPA into `Qihse.Studio.Server/wwwroot`.
   - `portal/install-studio.sh` (or `make install-studio`) publishes the Release server to `/opt/QIHSE/studio` and provisions `/etc/systemd/system/qihse-studio.service`.
   - Service listens on `http://0.0.0.0:5100` (port 5000 is reserved by SPECTRA Panel).

3. **Default LAN-Only Security Enforcement**:
   - `LanOnlyMiddleware` intercepts all requests before the application pipeline.
   - Allowed sources: Loopback (`127.0.0.1`, `::1`) and RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, Link-Local `169.254.0.0/16`).
   - Non-private/public WAN sources: Rejected with HTTP 403 Forbidden.

4. **Multi-Node Cluster Auto-Linking**:
   - `ClusterMeshService` queries `CLUSTER NODES` at startup and periodically over RESP.
   - Automatically maps and links to Node 0 (`192.168.1.91:7100`), Node 5 (`192.168.1.90:7115`), and other cluster peers across the LAN mesh.
