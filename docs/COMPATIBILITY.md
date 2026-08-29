# Protocol and Client Compatibility

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
- pub/sub
- server and introspection commands
- scripting entry points

Cluster-oriented work includes Redis-compatible hash-slot routing and sharding architecture. See [Cluster sharding](architecture/cluster_sharding.md).

## MongoDB wire protocol

The MongoDB compatibility layer includes BSON handling and wire-protocol operations for:

- insert
- find
- update
- delete
- findAndModify
- count
- collection management
- index management
- query operators such as comparison, boolean, existence, set-membership, and regex predicates
- aggregation stages including match, group, sort, limit, skip, project, unwind, and lookup

Implementation: `src/spinnaker/qihse_mongo_wire.c`.

## Neo4j / Bolt / Cypher

QIHSE exposes a Bolt 4.x-compatible protocol path with PackStream serialization and graph-native execution.

Supported graph-facing functionality includes:

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
