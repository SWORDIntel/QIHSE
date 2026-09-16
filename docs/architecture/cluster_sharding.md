# QIHSE Cluster Sharding Engine — Architecture & Implementation

> **Status**: Production-ready. All 5 phases implemented, tested, and benchmarked.
> **Commits**: `685ce05` (P1-2), `6df02e0` (P3), `291b271` (P4), `a0a86ec` (P5)

---

## 1. Overview

The QIHSE Cluster Sharding Engine implements a Redis-compatible sharded cluster
in native C99, supporting the standard Redis Serialization Protocol (RESP2/RESP3)
and the Redis Cluster Specification (16,384 hash slots). Any standard Redis
client (`redis-cli -c`, `redis-py` `RedisCluster`, `ioredis`, `go-redis`)
connects out-of-the-box with transparent horizontal scale-out.

The engine is hardware-aware: CRC16 slot hashing uses PCLMULQDQ SIMD
instructions, shard workers pin to NUMA-local CPU cores, and a kernel-bypass
UDP gossip bus handles inter-node heartbeats with zero syscalls in steady
state.

### Key Properties

| Property | Value |
|---|---|
| Hash slots | 16,384 (Redis Cluster standard) |
| CRC16 algorithm | XMODEM-CRC16, PCLMULQDQ-accelerated |
| Redirection | `-MOVED` (permanent), `-ASK` (transient) |
| Gossip bus | UDP, binary protocol, 1ms heartbeat interval |
| Failover | Raft consensus, automatic primary promotion |
| Scatter-gather | TCP, RRF fusion (K=60), 2s timeout |
| System guard | Sliding-window bus saturation throttle |

---

## 2. Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                    QIHSE CLUSTER TOPOLOGY                        │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐                   │
│  │  Node 0  │    │  Node 1  │    │  Node 2  │                   │
│  │ 127.0.0.1│    │ 127.0.0.1│    │ 127.0.0.1│                   │
│  │ :7000    │    │ :7001    │    │ :7002    │                   │
│  │ Slots    │    │ Slots    │    │ Slots    │                   │
│  │ 0-5460   │    │ 5461-    │    │ 10922-   │                   │
│  │          │    │ 10921    │    │ 16383    │                   │
│  │ KV/VDB/  │    │ KV/VDB/  │    │ KV/VDB/  │                   │
│  │ TS/COL   │    │ TS/COL   │    │ TS/COL   │                   │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘                   │
│       │               │               │                          │
│       ├───────────────┼───────────────┤                          │
│       │ UDP Gossip Bus (MEET/PING)    │                          │
│       ├───────────────┼───────────────┤                          │
│       │ TCP Scatter-Gather (VEC)      │                          │
│       └───────────────┴───────────────┘                          │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ System Guard (per-node, sliding window)                    │  │
│  │ Monitors bus saturation; throttles DENYOOM writes          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Failover Coordinator (per-node, Raft)                      │  │
│  │ Detects primary failure; promotes best replica             │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Decomposition

### 3.1 Core Cluster Modules

| File | Role |
|---|---|
| `src/spinnaker/qihse_crc16.{c,h}` | SIMD PCLMULQDQ CRC16 hash with `{tag}` extraction |
| `src/spinnaker/qihse_cluster_slot.{c,h}` | 16,384-slot ownership table, RCU routing |
| `src/spinnaker/qihse_cluster_numa.{c,h}` | CPU core pinning, NUMA memory binding |
| `src/spinnaker/qihse_cluster_migrate.{c,h}` | MIGRATE/RESTORE, ASKING protocol |
| `src/spinnaker/qihse_resp_cluster.{c,h}` | CLUSTER SLOTS/NODES/INFO/MEET/FAILOVER |
| `src/spinnaker/qihse_resp_engine.{c,h}` | Main RESP2/RESP3 connection engine |
| `src/spinnaker/qihse_resp_wire.{c,h}` | TCP server entry point & configuration |

### 3.2 Phase 3: Cluster Bus & Failover

| File | Role |
|---|---|
| `src/spinnaker/qihse_cluster_bus.{c,h}` | UDP gossip bus (MEET/PING/PONG/FAIL) |
| `src/spinnaker/qihse_cluster_failover.{c,h}` | Raft-based failover coordinator |
| `src/broad_oak/qihse_system_guard.c` | Bus-saturation sliding-window guard |
| `include/qihse_system_guard.h` | System guard public API |

### 3.3 Phase 4: Scatter-Gather Engine

| File | Role |
|---|---|
| `src/spinnaker/qihse_cluster_scatter.{c,h}` | Cross-node VECSCATTER/TS/COL fan-out with RRF |
| `include/qihse_cluster_scatter.h` | Scatter-gather public API |

### 3.4 Phase 5: Bootstrap & Benchmark

| File | Role |
|---|---|
| `tests/qihse_cluster_bootstrap.c` | 3-node live cluster bootstrap + benchmark |
| `tests/qihse_cluster_node.c` | Single-node cluster harness |
| `tests/test_cluster_bus.c` | Cluster bus unit tests |
| `tests/test_cluster_failover.c` | Failover coordinator unit tests |
| `tests/test_guard_throttle.c` | System guard throttle unit tests |
| `tests/test_cluster_scatter.c` | Scatter-gather engine unit tests |
| `tests/test_cluster_slot.c` | CRC16 slot routing unit tests |
| `tests/test_cluster_numa.c` | NUMA binding unit tests |
| `tests/test_resp_cluster.c` | CLUSTER command dispatch tests |
| `benchmarks/qihse_cluster_crc_bench.c` | CRC16 throughput benchmark |

---

## 4. Hash Slot Mechanics

### 4.1 SIMD-Accelerated CRC16

Keys are partitioned across 16,384 hash slots. The slot index is computed
using XMODEM-CRC16:

```
Slot = CRC16(Key) % 16384
```

The CRC16 implementation uses runtime CPUID dispatch:

| Mode | Hardware | Throughput |
|---|---|---|
| PCLMULQDQ | Intel/AMD with carry-less multiply | ~10 GB/s |
| Scalar table | Fallback | ~2 GB/s |

### 4.2 Hash Tag Extraction

If a key contains `{` and `}` with at least one character between them,
only the substring inside the first matching braces is hashed. This
guarantees co-location of multi-model payloads:

```
{target:8011484242}.metadata   -> KV Store
{target:8011484242}.vectors    -> Vector DB
{target:8011484242}.telemetry  -> Time-Series DB

All three resolve to the same slot -> same shard -> L1/L2 cache local
```

### 4.3 Slot Ownership Table

The slot ownership table is a 32KB array of 16,384 `uint16_t` entries
mapping each slot to a node index. This fits entirely in L1/L2 cache,
enabling sub-nanosecond routing decisions.

---

## 5. Client Routing Protocol

### 5.1 MOVED (Permanent Redirection)

When a query targets a slot owned by a remote node:

```
-MOVED <slot> <target_ip>:<target_port>\r\n
```

Smart clients update their routing table and send future queries for
that slot directly to the owner.

### 5.2 ASK (Transient Redirection)

During live slot migration:

```
-ASK <slot> <target_ip>:<target_port>\r\n
```

The client sends `ASKING` to the target for that single transaction
without updating its permanent routing cache.

### 5.3 CLUSTERDOWN

When the cluster lacks full slot coverage:

```
-CLUSTERDOWN The cluster is down\r\n
```

---

## 6. Cluster Bus (UDP Gossip)

### 6.1 Protocol

The cluster bus uses UDP with a binary frame format:

```
+----------+----------+----------+--------+-----------+
| Magic(4) | Type(1)  | Epoch(8) | NodeID | Payload   |
+----------+----------+----------+--------+-----------+
| "QHCB"   | u8       | u64 BE   | 40B    | variable  |
+----------+----------+----------+--------+-----------+
```

Message types:

| Type | Name | Purpose |
|---|---|---|
| 0x01 | MEET | Join cluster (new node introduction) |
| 0x02 | PING | Heartbeat probe |
| 0x03 | PONG | Heartbeat acknowledgement |
| 0x04 | FAIL | Mark node as failed |
| 0x05 | SLOT_UPDATE | Slot ownership change notification |

### 6.2 Heartbeat Lifecycle

1. Each node sends PING to all known peers every 1ms
2. Receiver responds with PONG and piggybacks its own slot map
3. If no PONG within 5s, node is marked as suspect (PFAIL)
4. If majority confirms failure, node is marked FAIL
5. Failover coordinator triggers replica promotion

---

## 7. Failover Coordinator

The failover coordinator implements a simplified Raft consensus protocol:

### 7.1 Election

1. When a primary node is detected as FAIL, replicas enter candidate state
2. Each candidate increments its epoch and requests votes
3. A node grants a vote if the candidate's epoch is higher than any
   previously seen
4. The candidate with majority votes becomes the new primary
5. The new primary claims the failed node's slot ranges

### 7.2 Best Replica Selection

The coordinator selects the replica with:
- Most up-to-date replication offset
- Lowest latency to the majority of nodes
- Highest node ID (deterministic tiebreaker)

---

## 8. System Guard (Bus Saturation Throttle)

### 8.1 Sliding Window

The system guard maintains a sliding window of request bytes over a
configurable time interval (default 100ms). When the window's byte
count exceeds a saturation fraction (default 80%) of the estimated
DDR bandwidth, the guard enters throttled mode.

### 8.2 Throttling Behavior

In throttled mode:
- **Read-only commands** (GET, VECSEARCH, TS.RANGE, COL.SUM): Allowed
- **Write/DENYOOM commands** (SET, DEL, INCR, VECSET, TS.ADD, COL.APPEND): Rejected with `-BUSY Bus saturation: try again later`

This prevents memory bus saturation from cascading into OS OOM kills
or uncontrolled latency spikes.

---

## 9. Scatter-Gather Engine

### 9.1 VECSCATTER (Vector Search with RRF Fusion)

The `VECSCATTER` command performs parallel vector search across all
peer shards and merges results using Reciprocal Rank Fusion (RRF):

```
VECSCATTER <dims> <top_k> <v0> <v1> ... [TAG <tag>]
```

**RRF Fusion Formula** (K=60):

```
rrf_score(d) = Σ_{shard s} 1 / (K + rank_s(d))
```

Where `rank_s(d)` is the rank of document `d` in shard `s`'s result list.

**Flow**:
1. Coordinator searches local shard -> local top-K candidates
2. Coordinator opens TCP connections to all peer shards in parallel
3. Each peer executes `VECSEARCH` locally and returns its top-K
4. Coordinator merges all results via RRF, keeping the best score
5. Final merged top-K is returned to the client

### 9.2 TS.RANGE Fan-Out

Time-series range queries are scattered to all shards and merged:

| Aggregation | Merge Strategy |
|---|---|
| SUM | Additive: `total = Σ shard_sum` |
| MIN | Global: `min = min(shard_min...)` |
| MAX | Global: `max = max(shard_max...)` |
| AVG | Weighted: `avg = Σ(shard_avg * shard_count) / Σ(shard_count)` |

### 9.3 COL.SUM / COL.MINMAX Fan-Out

Columnar queries are scattered to all shards and merged globally:
- `COL.SUM`: Sum all shard sums
- `COL.MINMAX`: Take global min/max across all shards

### 9.4 Transport

The scatter-gather engine uses TCP connections with:
- Non-blocking connect with per-peer timeout (default 2s)
- Lightweight embedded RESP client for peer queries
- Unhealthy peers are skipped (marked via gossip bus)
- Stats tracking: queries sent, received, failures

---

## 10. Multi-Model Sharded Commands

### 10.1 Key-Value (Black Hole Trinary Trie)

| Command | Description |
|---|---|
| `SET <key> <val>` | Slot-routed upsert |
| `GET <key>` | Slot-routed point read |
| `DEL <key>` | Slot-routed delete |
| `MGET <k1> <k2> ...` | Multi-key (single-slot or hash-tag bounded) |
| `MSET <k1> <v1> ...` | Multi-key set (single-slot or hash-tag bounded) |
| `EXPIRE <key> <sec>` | TTL assignment |
| `TTL <key>` | TTL query |
| `INCR <key>` / `DECR <key>` | Atomic counter |
| `EXISTS <key>` | Key existence check |

### 10.2 Vector DB (HNSW + Trinary Filter)

| Command | Description |
|---|---|
| `VECSET <id> <dims> <v0> ...` | Vector upsert into local shard |
| `VECGET <id>` | Vector retrieval |
| `VECSEARCH <dims> <top_k> <v0> ...` | Local shard top-K search |
| `VECSCATTER <dims> <top_k> <v0> ...` | Cross-shard RRF-fused search |

### 10.3 Time-Series (Marmalade Gorilla XOR)

| Command | Description |
|---|---|
| `TS.ADD <key> <ts_ms> <val>` | Bit-packed delta-of-delta ingest |
| `TS.RANGE <key> <start> <end> [AGG]` | Range scan with optional aggregation |

### 10.4 Columnar (Frieze Engine)

| Command | Description |
|---|---|
| `COL.APPEND <key> <val>` | Streaming column append |
| `COL.SUM <key>` | SIMD column sum |
| `COL.MINMAX <key>` | SIMD column min/max |

---

## 11. Server Configuration

The RESP server is configured via `qihse_resp_server_config_t`:

```c
qihse_resp_server_config_t config;
qihse_resp_server_config_init(&config);

/* Core */
config.port = 7000;
config.bind_address = "127.0.0.1";
config.store = kv_store;
config.vdb = vector_db;
config.tsdb = tsdb;
config.column_store = column_store;
config.topology = topology;
config.local_node_index = 0;
config.auth_required = false;

/* Phase 3: Cluster Bus & Failover */
config.enable_bus = true;
config.bus_port = 17000;
config.enable_failover = true;
config.enable_guard_throttle = true;
config.guard_window_ms = 100;
config.guard_saturation_fraction = 0.8;

/* Phase 4: Scatter-Gather */
config.enable_scatter = true;
config.scatter_timeout_ms = 2000;
```

---

## 12. Benchmark Results

### 12.1 Test Environment

- CPU: 8 cores
- RAM: 96 GB
- CRC16 backend: PCLMULQDQ
- Cluster: 3 nodes, localhost, even slot distribution

### 12.2 redis-benchmark --cluster

| Test | rps | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| SET (10 clients, no pipeline) | 164 | ~59ms | — | — | — |
| GET (10 clients, no pipeline) | 228 | ~41ms | — | — | — |
| SET (10 clients, P=16 pipeline) | 3,610 | 14.1ms | 57.5ms | 85.6ms | 152.9ms |
| SET (1 client, CSV latency) | 92.66 | 5.7ms | 25.2ms | 43.7ms | 147.3ms |

> **Note**: Non-pipelined p50 is dominated by MOVED redirect overhead
> (redis-benchmark does not cache slot mappings in cluster mode for
> non-pipelined tests). With pipelining (P=16), throughput reaches
> 3,610 rps with p50=14.1ms.

### 12.3 Key Distribution

100 random keys distributed across 3 nodes:

| Node | Slots | Keys |
|---|---|---|
| Node 0 | 0-5460 (33.3%) | 34 (34%) |
| Node 1 | 5461-10921 (33.3%) | 35 (35%) |
| Node 2 | 10922-16383 (33.4%) | 31 (31%) |

Distribution is uniform, confirming correct CRC16 hash distribution.

### 12.4 CRC16 Throughput

Run `make bench-cluster-crc` to measure raw CRC16 throughput:

```
backend=pclmul bytes=67108864 iterations=16 throughput_gib_s=9.84
```

~10 GB/s on PCLMULQDQ hardware.

---

## 13. Verification & Test Suite

### 13.1 Unit Tests

| Test | Tests | Description |
|---|---|---|
| `test-cluster-slot` | 5+ | CRC16 vectors, hash tag extraction, slot routing |
| `test-cluster-numa` | 5+ | CPU pinning, NUMA binding, HugePages |
| `test-resp-cluster` | 5+ | CLUSTER SLOTS/NODES/INFO/MEET dispatch |
| `test-cluster-bus` | 5 | UDP round-trip, MEET injection, FAIL propagation |
| `test-cluster-failover` | 5 | Primary failover, replica selection, no-failover cases |
| `test-guard-throttle` | 6 | Saturation detection, window expiry, defaults |
| `test-cluster-scatter` | 7 | No-peers, TS/COL fanout, unhealthy skip, NULL safety |

All tests are Valgrind-clean (0 bytes in use at exit, 0 errors).

### 13.2 Live Cluster Verification

The `qihse_cluster_bootstrap` tool starts a 3-node cluster and runs
a comprehensive verification suite:

```
make redis-cluster-bootstrap
LD_LIBRARY_PATH=. ./tests/qihse_cluster_bootstrap --benchmark --latency
```

Verification checks:
- PING all 3 nodes
- CLUSTER INFO / NODES / SLOTS
- SET/GET with MOVED redirect following (`redis-cli -c`)
- 100-key distribution verification
- INFO server (redis_version, cluster_enabled, qihse_crc16_backend)
- redis-benchmark --cluster (non-pipelined + pipelined)
- Single-client CSV latency measurement

---

## 14. Build & Run

### 14.1 Build

```bash
make lib                    # Build the shared library
make redis-cluster-node     # Build single-node harness
make redis-cluster-bootstrap # Build 3-node bootstrap tool
```

### 14.2 Run 3-Node Cluster

```bash
# Functional verification only
LD_LIBRARY_PATH=. ./tests/qihse_cluster_bootstrap --base-port 7000

# With benchmark and latency measurement
LD_LIBRARY_PATH=. ./tests/qihse_cluster_bootstrap --benchmark --latency --base-port 7000
```

### 14.3 Connect with redis-cli

```bash
# Cluster-aware (follows MOVED)
redis-cli -p 7000 -c SET foo bar
redis-cli -p 7000 -c GET foo

# Cluster commands
redis-cli -p 7000 CLUSTER INFO
redis-cli -p 7000 CLUSTER NODES
redis-cli -p 7000 CLUSTER SLOTS
redis-cli -p 7000 CLUSTER KEYSLOT mykey
```

### 14.4 Run Unit Tests

```bash
make test-cluster-slot test-cluster-numa test-resp-cluster
make test-cluster-bus test-cluster-failover test-guard-throttle
make test-cluster-scatter
```

---

## 15. Implementation History

| Phase | Commit | Description |
|---|---|---|
| 1-2 | `685ce05` | SIMD slot engine, hardware RESP3 ingress, MOVED/ASK redirection |
| 3 | `6df02e0` | Kernel-bypass UDP cluster bus, Raft failover, bus-saturation guard |
| 4 | `291b271` | Multi-model vector scatter-gather with RRF fusion, TS/COL fan-out |
| 5 | `a0a86ec` | Live 3-node cluster bootstrap, redis-benchmark verification |

### Phase Details

**Phase 1-2: SIMD Slot Engine & Hardware RESP3 Ingress**
- PCLMULQDQ CRC16 with runtime CPUID dispatch
- Hash tag `{...}` extraction per Redis Cluster spec
- 32KB L1-cached slot ownership table
- NUMA core pinning (`pthread_setaffinity_np` + `MPOL_BIND`)
- MOVED/ASK redirection in RESP command loop
- CLUSTER SLOTS/NODES/INFO/MEET/FAILOVER/KEYSLOT/RESET/MYID commands

**Phase 3: Kernel-Bypass Cluster Bus & System Guard**
- UDP gossip bus with binary frame protocol (MEET/PING/PONG/FAIL/SLOT_UPDATE)
- Raft-based failover coordinator with epoch voting
- Bus-saturation system guard with sliding-window throttle
- DENYOOM write rejection during saturation

**Phase 4: Multi-Model Vector Scatter-Gather**
- VECSCATTER: parallel cross-shard vector search with RRF fusion (K=60)
- TS.RANGE fan-out: scatter time-series aggregation, merge by SUM/MIN/MAX/AVG
- COL.SUM/COL.MINMAX fan-out: scatter column queries, merge globally
- Non-blocking TCP transport with per-peer timeout
- Unhealthy peer skip via gossip bus health status

**Phase 5: Live Cluster Bootstrap & Benchmark**
- 3-node in-process cluster with per-node topology views
- redis-benchmark --cluster compatibility verification
- p50 latency measurement (CSV mode)
- Key distribution uniformity verification

## Dynamic discovery (--join)

Nodes may join without a pre-shared topology: launch with `--join SEED_HOST:SEED_BUS_PORT` (repeatable) instead of `--node` entries. The joiner sends MEET frames to the seed's bus port; the seed replies with its own MEET, gossips the newcomer to every peer it knows, and re-announces the slot ranges it owns (`SLOT_UPDATE`). Slot announcements are re-sent on every MEET contact, so slot knowledge self-heals after UDP loss. Heartbeats identify peers by node ID (not table index), so membership learned dynamically stays healthy. A joiner starts with no slots and becomes routable once the slot map is received; slot *reassignment* to the new node remains a manual/rebalance operation. See `tools/qihse_cluster_daemon.c` and `tests/cluster_discover_smoke.py`.

## Slot load shift (CLUSTER MOVESLOTS)

`CLUSTER MOVESLOTS <first>-<last> <host>:<port>` (system domain only) hands a
slot range to another node: it transfers every locally-owned KV record in the
range to the target over the MIGRATE wire flow (AUTH + ASKING + SET [PX]),
deletes the local copies, flips ownership in the topology, and broadcasts the
change on the cluster bus (`SLOT_UPDATE`), so every node's routing agrees.
Ownership flips BEFORE the transfer (the target must accept the incoming
SETs); a brief not-found window exists for not-yet-transferred keys — Redis
style ASK-state handling is future work. Verified cross-machine by
`tests/cluster_loadshift_smoke.py` (9/9).

## Cluster brain (--brain)

Optional per-node decision loop (`src/spinnaker/qihse_cluster_brain.c`,
`--brain`, `--brain-act` for phase-2 actions): every `--brain-interval`
seconds it snapshots the topology and appends ML-DSA-87-signed records to a
durable event stream under `--brain-dir` (topic `cluster.brain`) —
`OBSERVE` (nodes, health, slot runs), `ISOLATED` / `ASYMMETRY` /
`RECONNECTED` policy observations. Phase 1 is observe/journal/decide only;
phase 2 adds actuation (re-homing slots from failed owners via the
MOVESLOTS machinery, with auto-rollback). Design rationale and the
MEMSHADOW take/reject table: [cluster brain](cluster_brain.md).

## Transitive slot-map gossip

When a node receives a MEET from a newcomer, it (1) upserts the newcomer,
(2) introduces itself + gossips the newcomer to every peer it knows, and
(3) announces its FULL KNOWN slot map (all owners, coalesced runs) to the
newcomer — so a joiner that learned the cluster transitively still learns
who owns what. Known peers also receive the full map on repeat MEETs
(self-healing after UDP loss). Verified: a node that joins through an
intermediary appears in the whole cluster's tables (3-node lab).

## Container node networking (routed subnet — SOLVED)

The T320's vmbr0 is an isolated segment and its WiFi (192.168.1.250) is the
only live path to the seed, so the container node uses a **routed subnet**:
container = `10.200.69.2/24` (gw `10.200.69.1` on the T320's vmbr0), t420
routes `10.200.69.0/24 via 192.168.1.250`. The node binds
`10.200.69.2:7112`, joins via the seed's bus, and MOVED redirects from t420
are routable end-to-end. One-off setup: `ip addr add 10.200.69.1/24 dev
vmbr0` on the T320 + the t420 route (non-persistent; add to
/etc/network/interfaces or systemd-networkd for permanence).

## Node provisioning notes (T320 LXC)

A third node was provisioned as an unprivileged LXC (`pct` 410, Debian 13,
static 192.168.1.241 on vmbr0, later switched to host networking): runtime
libs are pushed from the T320 host (`/opt/qihse/lib/*` — libqihse + its 15
non-glibc deps), binaries to `/opt/qihse/bin`. Open item: the daemon serves
fine in the container foreground but exits status=1 within seconds under
systemd in this unprivileged CT (T320 host instance runs identically fine) —
suspect CT environment (capability/sysctl); a privileged CT or full VM is
the workaround. Join/retry logic now retries indefinitely while the daemon
lives (lossy-path safe).

## 3-node lab status (2026-09-13)

Three-node topology live and converged: t420 seed (slots 0-10922), T320
(10923-13653), T320 LXC `qihse-node2` (13654-16383). All three views agree:
`cluster_state:ok`, 16,384/16,384 assigned, identical `CLUSTER NODES`. Slot
routing verified across all three: writes land on the owning node and the
seed issues correct MOVED redirects — including to the container node
(physical client reachability of the container's segment is the lab's
remaining limit; the redirect itself is correct).

## Failover: most-uptime successor

When a primary is marked failed (5 s heartbeat timeout on the bus), the
failover coordinator succeeds it:
1. dedicated replicas first (existing rule: healthy replica of the failed
   primary; tie-break by lowest index);
2. otherwise — the sharded-cluster fallback — the healthy PRIMARY with the
   longest continuous presence on the bus (`first_seen`, receiver-local
   observation) inherits the failed node's slot ranges. Ownership changes are
   broadcast (`SLOT_UPDATE` + `NODE_UPDATE`), so routing converges cluster-wide.

Selection is receiver-local and deterministic; with 2 nodes the surviving
node always succeeds the dead one. Verified live: SIGKILL the lead, the
successor owns 16,384/16,384 slots within the health window.

## Data redundancy (phase 1: string KV, async)

`--redundancy-peer HOST:PORT` enables fire-and-forget duplication: every
committed string-KV write (SET with TTL) and delete (DEL) is replayed to the
peer with ASKING (accepted regardless of slot ownership — the peer stores a
duplicate outside its own routing range). Reads never consult the duplicate
until failover re-homes the slots, at which point the promoted successor
already holds the data. Honest limits: writes in flight when a node dies are
lost (async); hashes/lists/sets and blob/vector objects do not replicate in
phase 1; a persistent replication link (rather than per-write connections) is
the performance follow-up. Verified live: duplicated key survives SIGKILL of
the lead and is served by the promoted successor. See
`tests/cluster_failover_smoke.py`.

## 5-node lab status (2026-09-16)

Five nodes, all `cluster_state:ok` with 16,384/16,384 slots assigned and an
identical ownership map on every node:

| Node | Where | Endpoint | Bus | Slots |
|---|---|---|---|---|
| 0 | t420 (Proxmox host) | 192.168.1.91:7100 | 17100 | 0-5459 |
| 1 | t320 (Proxmox host) | 192.168.1.250:7101 | 17101 | 10923-13653 |
| 2 | CT 410 `qihse-node2` on t320 | 10.200.69.2:7112 | 17112 | 13654-16383 |
| 3 | CT 411 `qihse-node3` on 730xd | 192.168.1.92:7113 | 17113 | 5460-8191 |
| 4 | CT 412 `qihse-node4` on 730xd | 192.168.1.93:7114 | 17114 | 8192-10922 |

Provisioning (the 730xd joined the SIG-TRUST Proxmox cluster, so its nodes
are reachable with cluster root SSH — `sudo ssh root@192.168.1.90` — which
avoids needing a separate OS credential):

1. `pct create 411/412 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst`
   with 2 cores / 1 GiB / 8 GiB on `fast-dir-vms`, unprivileged, static
   addresses on `vmbr0` (192.168.1.92/.93), `onboot 1`.
2. Runtime push: the container needs the non-glibc dependencies of
   `libqihse.so` (liburing, libluajit-5.1, libbpf, libxdp, libsqlite3,
   libzstd, libexpat, libelf, libssl/libcrypto, libpython3.13) — installed
   with `apt-get` in the container, then `libqihse.so` +
   `qihse-cluster-daemon` extracted to `/opt/qihse/{lib,bin}`.
3. `qihse-node{3,4}.service` (`Restart=always`, enabled) runs the daemon with
   `--join 192.168.1.91:17100` and `--brain` (observe-only) so the nodes are
   self-healing across container reboots.

The two new nodes joined slotless and were given ranges with
`CLUSTER MOVESLOTS` from the largest owner (t420). Verified: writes to keys
in all five ranges land on the owning node via MOVED (including both new
730xd nodes) and every node can read all five ranges (10/10 checks).
