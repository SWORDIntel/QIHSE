# Protocol and Client Compatibility

> **Status: partial.** The protocol surfaces listed here exist in the tree, but
> verification is uneven. RESP, pub/sub, pgwire cluster and the UWP bridge have
> tests (`tests/test_resp_cluster.c`, `tests/test_resp_pubsub.c`,
> `tests/test_pg_wire_cluster.c`, `tests/test_resp_security_regression.c`), and
> SQLite VFS has `tests/test_sqlite_vfs.c`. MongoDB has `tests/test_mongo_wire.c`
> and `tests/test_mongo_wire_security.c`. Bolt has `tests/test_bolt.c`, which
> covers the codec, framing, handshake and message loop — it does **not** verify
> driver compatibility, and the adapter still discards `RUN` results and has no
> result cursor (see
> [architecture/bolt_protocol.md](architecture/bolt_protocol.md)). The
> ClickHouse, Elasticsearch and InfluxDB surfaces have no dedicated test beyond
> the handler-entry-point coverage in `tests/test_phase_c.c`.
>
> Two claims in an earlier revision of this document were wrong: Bolt does have
> a test, and MongoDB does have dedicated tests.

QIHSE exposes compatibility layers for several established database protocols and client ecosystems. This lets existing applications reach QIHSE without requiring every workload to adopt the native UWP interface immediately.

Compatibility is implemented inside QIHSE; it is not a statement that every edge case of every upstream database is identical. Treat this document as the supported surface, then validate application-specific behavior before migration.

## PostgreSQL / pgwire

QIHSE implements PostgreSQL wire-protocol paths and a relational SQL engine.

Supported areas include:

- simple and extended query flows
- Parse / Bind / Execute / Describe / Close / Sync
- transactions and savepoints
- DDL and DML
- GRANT / REVOKE and role-management paths
- prepared statements
- common aggregate and window functions
- COPY and utility commands

Related code and docs:

- `src/spinnaker/qihse_pg_wire.c`
- [SQL engine](architecture/sql_engine.md)
- [Transactions and MVCC](architecture/transactions_mvcc.md)

## Redis / RESP

The RESP compatibility layer covers common Redis-style data structures and commands.

### Data structures

- strings / keys
- lists
- hashes
- sets
- sorted sets
- bitmaps
- HyperLogLog

### Operational features

- expiry and persistence-related key operations
- MULTI / EXEC / DISCARD / WATCH / UNWATCH
- pub/sub with real message fan-out (`qihse_resp_pubsub.c`): `SUBSCRIBE` / `UNSUBSCRIBE` / `PSUBSCRIBE` / `PUNSUBSCRIBE` / `PUBLISH` / `PUBSUB CHANNELS|NUMSUB|NUMPAT`. Every publish is appended to a durable event stream (topic `resp.pubsub`) when `pubsub_log_directory` is configured, making messages replayable by the UWP STREAM target and CDC. Subscribed connections accept only subscription commands, `PING`, `QUIT`, and `RESET`. Channels carry a configurable `(classification, SCI)` security tag; `SUBSCRIBE` and `PUBLISH` require the caller's clearance to dominate it (`NOPERM` otherwise).
- server and introspection commands — `DBSIZE` returns a real, authorization-aware count (callers see only records they may read)
- scripting entry points

### QIHSE extensions to the RESP surface

These commands are QIHSE-specific; standard Redis clients will not send them.

- `BUNDLE.PREPARE <fingerprint> [have-hash …]` / `BUNDLE.PREPARE <tenant_id> <fingerprint> [have-hash …]` and `BUNDLE.CHUNK <hash> <offset>` — session-bundle compose and chunked blob delivery (system-domain callers compose on behalf of a tenant). See [Session-delivery subsystem](architecture/session_delivery.md).
- `METRICS.RENDER` — Prometheus-style delivery metrics; system-domain principals only (`NOPERM` for tenants).

### Tenancy-aware behavior (differs from stock Redis)

QIHSE tenant principals (`tenant_id != 0`) are deny-by-default at the engine boundary: they may access only keys under their own `t:<tenant_id>/…` namespace and the shared `commons/…` namespace; every other key — including unscoped ones — is refused with `NOPERM` before a handler runs. Writes into `t:*/tlm/…` (telemetry) must additionally match a closed record-type schema; violating records are rejected at ingest (`INGEST record rejected`), not stored. System-domain principals (including the operator) are unrestricted. See [Session-delivery subsystem](architecture/session_delivery.md).

### Pub/sub channel policy

Channels carry a configurable `(classification, SCI)` tag as before; since the session-delivery work a channel may additionally carry per-channel policy overrides, including `publish_system_only`. The fleet-wide `killswitch` channel (enabled via `enable_killswitch_channel`) is readable by every authenticated tenant but publishable only by system-domain principals; valid `burn_edge` telemetry writes fan out on it automatically.

### Standalone server and UWP bridge

- `make redis-server` builds `qihse-redis-server`, a standalone daemon (`tools/qihse_redis_server.c`) serving RESP on port 6379 with optional `--require-auth`, durable pub/sub (`--pubsub-dir`), channel security policy (`--channel-classif` / `--channel-sci`), and an optional UWP listener on the same stores (`--uwp-port`).
- `QIHSE_UWP_TARGET_RESP` (0x0F) routes UWP packets into the RESP dispatch path (`qihse_resp_server_execute`) with the UWP-authenticated `qihse_user_t`. Opcode `QIHSE_UWP_RESP_EXEC` (0x01) carries `u32 LE argc` followed by `argc × (u32 LE len + bytes)` and returns raw RESP reply bytes. There is no context-free fallback; see [RESP–UWP bridge](architecture/resp_uwp_bridge.md).

Cluster-oriented work includes Redis-compatible hash-slot routing and sharding architecture. See [Cluster sharding](architecture/cluster_sharding.md).

## MongoDB wire protocol

**Status: implemented** — BSON handling, framing, the in-memory catalog, command
dispatch and the TCP server are all in `src/spinnaker/qihse_mongo_wire.c` and
are covered by `tests/test_mongo_wire.c`; the invariant-3 negative authorization
test is `tests/test_mongo_wire_security.c`.

The MongoDB compatibility layer includes BSON handling and wire-protocol operations for:

- insert
- find
- update
- delete
- count and distinct
- collection and database management (`listCollections`, `listDatabases`, drop)
- query operators such as comparison, boolean, existence, set-membership, and regex predicates
- aggregation stages match, group, sort, limit, skip, count, project and unwind

Limits, stated rather than implied. `$lookup` (and `$facet`/`$graphLookup` and
computed expressions) are refused with `NOT_IMPLEMENTED` rather than silently
dropped. `findAndModify`, `getMore`, `createIndexes` and `listIndexes` are
refused loudly — there is no secondary-index management surface and every cursor
is returned as a single batch with id 0. `$where` is not evaluated (there is no
server-side JavaScript) and a filter using it is refused. An earlier revision of
this document listed `findAndModify` and index management as supported; they are
not.

Implementation: `src/spinnaker/qihse_mongo_wire.c`.

## Neo4j / Bolt / Cypher

**Status: partial.** The Bolt 4.x protocol path (PackStream serialization,
handshake, framing, message loop) is implemented and covered by
`tests/test_bolt.c`, and Cypher executes through the graph engine
(`tests/test_graph.c`). The adapter is **not** driver-compatible: `RUN`
dispatches the Cypher and then discards the result, and `PULL` returns a single
empty record with no result cursor, so a stock neo4j driver will not see query
results. See [Bolt protocol](architecture/bolt_protocol.md) for the exact
deviations.

Graph-facing functionality includes:

- HELLO / RUN / PULL
- BEGIN / COMMIT / ROLLBACK
- Node / Relationship / Path structures
- MATCH / CREATE / MERGE / DELETE / SET / WHERE / RETURN
- ordering and limiting
- graph indexes and constraints
- selected database-management and introspection commands
- graph algorithms and graph/vector fusion

See [Graph engine](architecture/graph_engine.md) and [Bolt protocol](architecture/bolt_protocol.md).

## Elasticsearch-style HTTP API

The HTTP compatibility surface includes Elasticsearch-style operations for:

- document indexing, retrieval, update, and deletion
- bulk operations
- match, term, range, bool, and match-all queries
- common aggregations
- mappings and index management
- count and explain
- scroll and point-in-time search
- multi-search and multi-get
- reindexing
- templates and stored scripts
- cluster/node/cat-style information endpoints

Implementation: `src/spinnaker/qihse_es_api.c`.

## ClickHouse-style HTTP API

The ClickHouse compatibility layer includes HTTP query handling and support for areas such as:

- MergeTree-family engine syntax
- materialized views
- dictionaries
- INSERT FORMAT paths
- PREWHERE
- ARRAY JOIN
- SAMPLE
- SETTINGS
- system-table style inspection
- common ClickHouse-style functions and output formats

Implementation: `src/spinnaker/qihse_clickhouse_http.c`.

## InfluxDB-style API

The InfluxDB compatibility layer provides:

- `/query`
- `/write`
- `/health`
- `/ping`
- line-protocol ingestion
- InfluxQL parsing for common query and management operations
- time predicates and time-bucket grouping

Implementation: `src/spinnaker/qihse_influx_api.c`.

## PgBouncer-style pooling and administration

QIHSE includes a connection pooler with:

- session pooling
- transaction pooling
- statement pooling
- SHOW-style administrative inspection
- PAUSE / RESUME / RELOAD and related control commands
- authentication and statistics paths

Implementation: `src/spinnaker/qihse_pooler.c`.

## HTTP / REST

A native HTTP server and route layer provides JSON-oriented APIs and acts as the transport for several compatibility surfaces.

Implementation: `src/spinnaker/qihse_http_api.c`.

## SDK compatibility layers

The repository contains compatibility-oriented SDKs under [`sdks/`](../sdks/).

| SDK | Intended compatibility | Location |
|---|---|---|
| `qihse_pg` | psycopg2-style Python access | `sdks/python/qihse_pg.py` |
| `qihse_neo4j` | neo4j-python style access | `sdks/python/qihse_neo4j.py` |
| `qihse_mongo` | pymongo-style access | `sdks/python/qihse_mongo.py` |
| `qihse_http` | HTTP/REST access | `sdks/python/qihse_http.py` |
| `qihse_clickhouse` | ClickHouse-oriented Python client | `sdks/python/qihse_clickhouse.py` |
| `qihse_elasticsearch` | Elasticsearch-oriented Python client | `sdks/python/qihse_elasticsearch.py` |
| `qihse_cdc` | CDC/pub-sub access | `sdks/python/qihse_cdc.py` |
| Rust bindings | Rust-native access | `sdks/rust/` |
| libpq-style C interface | PostgreSQL-oriented C access | `sdks/c/qihse_libpq.h` |
| MongoDB-oriented C interface | MongoDB-oriented C access | `sdks/c/qihse_mongo_c.h` |

## Migration guidance

Before replacing an existing database in a production application:

1. Identify exactly which commands, protocol behaviors, transaction semantics, and error codes the application depends on.
2. Test that subset against QIHSE rather than relying on broad compatibility labels.
3. Validate concurrency, persistence, recovery, and failure behavior under the application's actual workload.
4. Re-run performance tests using the production data shape and hardware.
5. Review the current [security documentation](security/README.md) before exposing any protocol listener to an untrusted network.

For the implementation-level protocol inventory, see [Operational protocols](architecture/operational_protocols.md).
