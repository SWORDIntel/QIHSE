# Operational & Protocol Layer

## Overview

QIHSE provides a complete operational and protocol stack beyond the core storage engines: CDC, MongoDB wire protocol, HTTP/REST API, ClickHouse HTTP, Elasticsearch API, InfluxDB API, Prometheus metrics, OpenTelemetry tracing, compaction/TTL, SQL extensions, and comprehensive database equivalency commands for 8 target databases.

## CDC — Change Data Capture (`src/spinnaker/qihse_cdc.c`)

Pub/sub event streaming for logical replication and external consumers.

```c
qihse_cdc_context_t* ctx = qihse_cdc_create();
qihse_cdc_subscribe(ctx, "my_sub", callback, user_data);
qihse_cdc_emit(ctx, CDC_OP_INSERT, "users", "user:1", NULL, 0, new_val, len);
```

- **Event types**: INSERT, UPDATE, DELETE
- **Subscriptions**: Named subscriptions with callback delivery
- **LSN tracking**: Monotonically increasing LSN per event
- **Thread-safe**: Mutex-protected subscription list

## MongoDB Wire Protocol (`src/spinnaker/qihse_mongo_wire.c`)

Drop-in MongoDB compatibility via BSON serialization and wire protocol.

- **BSON types**: int32, int64, double, string, bool, null, document, array, binary, datetime, timestamp, ObjectId, Regex, MinKey, MaxKey
- **Wire protocol**: OP_REPLY, OP_INSERT, OP_QUERY, OP_UPDATE, OP_DELETE, OP_MSG
- **Server**: TCP server with per-client threading
- **Document store**: Routes to existing `qihse_document_store`
- **CRUD operations**: insert, find, update, delete, findAndModify, count
- **Query operators**: $eq, $gt, $gte, $lt, $lte, $ne, $in, $nin, $and, $or, $not, $exists, $regex
- **Aggregation pipeline**: $match, $group, $sort, $limit, $skip, $project, $unwind, $lookup
- **Admin commands**: createCollection, drop, listCollections, createIndex, dropIndex, listIndexes
- **In-memory catalog**: Database/collection management with thread-safe access

## HTTP/REST API (`src/spinnaker/qihse_http_api.c`)

HTTP server with route registration and JSON responses.

```c
qihse_http_server_t* srv = qihse_http_server_create(8080);
qihse_http_server_add_route(srv, "/api/users", HTTP_GET, handle_get_users, ctx);
qihse_http_server_start(srv);
```

- **Methods**: GET, POST, PUT, DELETE, PATCH
- **Routing**: Exact match + prefix match for path parameters
- **Responses**: JSON, text, error helpers
- **JSON**: Escape, build_object helpers

## ClickHouse HTTP Protocol (`src/spinnaker/qihse_clickhouse_http.c`)

ClickHouse-compatible HTTP query interface with full SQL support.

- **Formats**: TabSeparated, JSON, JSONEachRow, CSV, CSVWithNames, Values, Pretty, Raw
- **Endpoints**: `GET /?query=...`, `POST /` with query body, `GET /ping`
- **DDL**: CREATE DATABASE, CREATE TABLE with MergeTree engines, CREATE MATERIALIZED VIEW, CREATE DICTIONARY, DROP TABLE, DROP DATABASE
- **DML**: INSERT INTO ... FORMAT (Values, CSV, JSON, TabSeparated, Pretty)
- **Query**: SHOW TABLES, SHOW DATABASES, SHOW COLUMNS, DESCRIBE TABLE, SELECT with FINAL, PREWHERE, SAMPLE, ARRAY JOIN, SETTINGS
- **System tables**: system.tables, system.databases, system.columns, system.settings
- **MergeTree engines**: MergeTree, ReplacingMergeTree, SummingMergeTree, AggregatingMergeTree, CollapsingMergeTree, VersionedMergeTree
- **Functions**: now(), today(), yesterday(), toStartOfMonth(), toStartOfDay(), countIf(), sumIf(), avgIf(), groupArray(), groupUniqArray()
- **Routes**: Registered on HTTP server, routes to columnar engine

## Elasticsearch API (`src/spinnaker/qihse_es_api.c`)

Elasticsearch-compatible REST endpoints with full query DSL and aggregation support.

- **Endpoints**: `_search` (POST/GET), `_doc` (POST/GET/PUT/DELETE), `_bulk` (POST), `_cluster/health` (GET), `_mget`, `_msearch`, `_count`, `_explain`, `_scroll`, `_pit`, `_reindex`, `_scripts`, `_template`, `_cat/*`, `_nodes`, `_cluster/*`
- **Query DSL**: match, term, range, bool (must/should/filter/must_not), match_all
- **Aggregations**: terms, avg, sum, max, min, cardinality
- **Index management**: create/delete index, mappings, settings
- **Catch-all dispatcher**: Routes any ES-style URL path to appropriate handler
- **Routes**: Registered on HTTP server, routes to FTS + vector engines

## InfluxDB API (`src/spinnaker/qihse_influx_api.c`)

InfluxDB-compatible HTTP API for time-series ingestion and querying.

- **Endpoints**: `/query` (GET/POST), `/write` (POST), `/health` (GET), `/ping` (GET/HEAD)
- **InfluxQL parser**: SELECT (with aggregations mean/sum/min/max/count), SHOW, CREATE DATABASE, DROP DATABASE/MEASUREMENT, INSERT
- **Line protocol**: `measurement,tag=val field=val timestamp` parsing with quoted strings, multiple tags/fields, nanosecond timestamps
- **WHERE predicates**: `time > now() - 1h`, epoch literals
- **GROUP BY**: `time(10m)` bucket aggregation
- **Response format**: InfluxDB JSON `{"results":[{"statement_id":0,"series":[...]}]}`
- **Routes**: Registered on HTTP server, routes to timeseries engine

## Prometheus Metrics (`src/spinnaker/qihse_metrics.c`)

Prometheus-compatible metrics registry.

```c
qihse_metrics_registry_t* reg = qihse_metrics_create();
qihse_metrics_register(reg, "qihse_queries_total", "Total queries", METRIC_COUNTER);
qihse_metrics_increment(reg, "qihse_queries_total", 1);
char* prom_text = qihse_metrics_export(reg);  // Prometheus text format
```

- **Types**: Counter, Gauge, Histogram, Summary
- **Export**: Prometheus text format with HELP/TYPE lines
- **Thread-safe**: Per-metric mutex

## OpenTelemetry Tracing (`src/spinnaker/qihse_tracing.c`)

Distributed tracing with span management.

```c
qihse_tracer_t* tracer = qihse_tracer_create();
qihse_span_t* span = qihse_span_start(tracer, "query_execute", NULL);
qihse_span_set_tag(span, "db.system", "qihse");
qihse_span_finish(tracer, span);
char* json = qihse_tracer_export_json(tracer);  // OpenTelemetry JSON
```

- **Spans**: trace_id, span_id, parent_span_id, operation_name, start/end time
- **Tags**: Key-value tags on spans
- **Hierarchy**: Parent/child span relationships
- **Export**: JSON format for OpenTelemetry collector

## Compaction & TTL (`src/tractable/qihse_compaction.c`)

Background maintenance for all storage engines.

- **Compaction**: KV SSTable merge, columnar segment compaction, document arena compaction, timeseries block compaction
- **TTL sweep**: Remove expired keys based on cutoff timestamp
- **Background loop**: Configurable interval, runs in dedicated thread

## SQL Extensions (`src/tractable/qihse_sql_extensions.c`)

Domain-specific SQL table functions and ClickHouse SQL extensions.

### VECTOR_SEARCH(table, query_vec, k, distance_metric)
Vector similarity search as a SQL table function. Supports euclidean, cosine, and dot product distances.

### TIME_BUCKET(bucket_width, time_column, agg_func, value_column)
Time-series aggregation with configurable bucket widths (e.g. `'5m'`, `'1h'`, `'1d'`). Supports gap filling (NULL, linear interpolation, carry-forward).

### MATCH(field, query, highlight, snippet_size)
Full-text search with BM25 scoring and optional highlight snippets.

### ClickHouse SQL Extensions
- **MergeTree engine parsing**: All 6 engine types (MergeTree, ReplacingMergeTree, SummingMergeTree, AggregatingMergeTree, CollapsingMergeTree, VersionedMergeTree) with ORDER BY, PARTITION BY, PRIMARY KEY, SAMPLE BY, TTL, SETTINGS
- **Materialized views**: CREATE MATERIALIZED VIEW ... AS SELECT ... with TO target table
- **Dictionaries**: CREATE DICTIONARY with SOURCE, LAYOUT, LIFETIME
- **ClickHouse functions**: now(), today(), yesterday(), toStartOfMonth(), toStartOfDay(), countIf(), sumIf(), avgIf(), groupArray(), groupUniqArray()
- **ARRAY JOIN**: LEFT ARRAY JOIN and ARRAY JOIN clause parsing
- **FINAL modifier**: Word-boundary-aware detection for MergeTree queries
- **PREWHERE clause**: Expression extraction for pre-filtering
- **SAMPLE clause**: Sampling with optional OFFSET
- **SETTINGS**: Comma-separated key=value pairs in queries

## Database Equivalency -- Phase 9

Comprehensive command interoperability for 8 target databases, enabling drop-in replacement.

### Redis Commands (`src/spinnaker/qihse_resp_engine.c`)
- **Lists**: LPUSH, RPUSH, LPOP, RPOP, LLEN, LRANGE, LINDEX, LSET, LREM, LTRIM, LINSERT, RPOPLPUSH
- **Hashes**: HSET, HMSET, HGET, HGETALL, HDEL, HEXISTS, HKEYS, HVALS, HLEN, HINCRBY, HMGET, HSETNX, HSTRLEN
- **Sets**: SADD, SREM, SMEMBERS, SISMEMBER, SCARD, SPOP, SMOVE, SDIFF, SINTER, SUNION, SRANDMEMBER
- **Sorted Sets**: ZADD, ZREM, ZSCORE, ZCARD, ZCOUNT, ZRANGE, ZREVRANGE, ZRANK, ZREVRANK, ZINCRBY, ZPOPMAX, ZPOPMIN, ZRANGEBYSCORE, ZREVRANGEBYSCORE
- **Keys**: KEYS, SCAN, RENAME, RENAMENX, GETSET, GETDEL, STRLEN, APPEND, GETRANGE, SETRANGE, INCRBY, DECRBY, INCRBYFLOAT, MSETNX, PERSIST, EXPIREAT, PEXPIREAT, UNLINK, COPY, RANDOMKEY, TOUCH, OBJECT
- **Server**: FLUSHDB, FLUSHALL, DBSIZE, TIME, SAVE, BGSAVE, LASTSAVE, SHUTDOWN, CONFIG, DEBUG, MEMORY, SLOWLOG, LATENCY
- **Transactions**: MULTI, EXEC, DISCARD, WATCH, UNWATCH (with command queueing)
- **Pub/Sub**: PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PSUBSCRIBE, PUNSUBSCRIBE, PUBSUB
- **Bitmaps**: SETBIT, GETBIT, BITCOUNT, BITPOS, BITOP
- **HyperLogLog**: PFADD, PFCOUNT, PFMERGE
- **Scripting**: EVAL, EVALSHA, SCRIPT

### PostgreSQL SQL Extensions (`src/tractable/qihse_sql_parser.c`)
- **Transaction Control**: BEGIN, COMMIT, ROLLBACK, SAVEPOINT, RELEASE, SET TRANSACTION
- **DCL**: GRANT, REVOKE, CREATE ROLE, DROP ROLE, ALTER ROLE
- **Utility**: TRUNCATE, COPY, DISCARD, RESET, SET, SHOW, DEALLOCATE, PREPARE, EXECUTE, REINDEX, CLUSTER
- **Aggregates**: VARIANCE, STDDEV, CORR, COVAR_SAMP, COVAR_POP, EVERY
- **Window Functions**: FIRST_VALUE, LAST_VALUE, NTH_VALUE

### PgBouncer Admin Commands (`src/spinnaker/qihse_pooler.c`)
- **SHOW**: 16 commands (POOLS, CLIENTS, SERVERS, SOCKETS, DBS, USERS, VERSION, STATS, TOTALS, LISTS, FDS, MEM, CONFIG, DNS_HOSTS, DNS_ZONES, PEERS, PEER_POOLS)
- **Control**: 10 commands (PAUSE, RESUME, DISABLE, ENABLE, RECONNECT, KILL, SUSPEND, SHUTDOWN, RELOAD, WAIT_DB)
- **Pooling modes**: Session, Transaction, Statement
- **Authentication**: trust, password, md5, scram-sha-256, cert, hba

### Neo4j Cypher Extensions (`src/tractable/qihse_cypher_parser.c`)
- **LOAD CSV**: WITH HEADERS, FROM path
- **CALL procedures**: db.labels(), db.relationshipTypes(), db.indexes()
- **Constraints**: CREATE/DROP CONSTRAINT, SHOW CONSTRAINTS
- **Indexes**: CREATE/DROP INDEX, SHOW INDEXES
- **Database management**: CREATE/DROP/ALTER DATABASE, SHOW DATABASES, START/STOP DATABASE
- **Query**: EXPLAIN, PROFILE, FOREACH, USE, PERIODIC COMMIT
- **Expressions**: List comprehensions, pattern comprehensions, CASE expressions

## Testing
14 tests in `tests/test_phase_c.c` covering all the above features.
