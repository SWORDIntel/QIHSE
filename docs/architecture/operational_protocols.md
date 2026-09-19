# Operational & Protocol Layer

> **Status: partial.** `tests/test_phase_c.c` (run via `make test-phase-c`) now
> exists and covers CDC, the metrics registry, tracing, HTTP request parsing and
> helpers, BSON, the Elasticsearch/InfluxDB/ClickHouse handler entry points, the
> compaction context and the SQL-extension parsers. One earlier claim in this
> document was wrong and is corrected in place:
>
> - **The MongoDB wire protocol is implemented.** `include/qihse_mongo_wire.h`
>   declares `mongo_msg_parse()`, `mongo_msg_get_document()`, `mongo_catalog_*()`,
>   `mongo_dispatch_command()` and `qihse_mongo_server_*()`; every one of them is
>   defined in `src/spinnaker/qihse_mongo_wire.c`, and `libqihse.so` exports
>   seventeen `mongo_*` / `qihse_mongo_*` symbols. An earlier revision of this
>   document said the wire protocol was declared but defined nowhere. It is
>   covered by `tests/test_mongo_wire.c` (framing, catalog, command dispatch and
>   server) and by `tests/test_mongo_wire_security.c` (the `AGENTS.md`
>   invariant-3 low-clearance/high-data negative test); the `mongo-wire` and
>   `protocol-compat-probe` workloads in `tests/gold/pack.v1.gold` assert the
>   same state.
> - **The Elasticsearch query DSL and aggregations, and the InfluxQL parser, are
>   not covered by any test.** `tests/test_phase_c.c` exercises the health/ping
>   handlers, route registration and the dispatcher only.
>
> Defects reproduced by that test as `NOTE` lines rather than asserted:
> `qihse_span_start()` does not inherit the parent's trace id (every span starts
> a new trace); `json_build_object()` ignores its declared format argument and
> consumes it as the first key; and `qihse_sql_parse_sample()` drops
> `SAMPLE ... OFFSET`.

## Overview

QIHSE provides a complete operational and protocol stack beyond the core storage engines: CDC, MongoDB wire protocol, HTTP/REST API, ClickHouse HTTP, Elasticsearch API, InfluxDB API, Prometheus metrics, OpenTelemetry tracing, compaction/TTL, SQL extensions, and comprehensive database equivalency commands for 8 target databases.

## CDC — Change Data Capture (`src/spinnaker/qihse_cdc.c`)

**Status: implemented.** Pub/sub event streaming for logical replication and
external consumers; covered by `tests/test_phase_c.c`.

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

**Status: implemented.** The BSON codec, the wire protocol, the catalog, the
command dispatcher and the TCP server are all in this one file, and all of them
are covered by `tests/test_mongo_wire.c` (`make test-mongo-wire`); the
invariant-3 negative authorization test is
`tests/test_mongo_wire_security.c` (`make test-mongo-wire-security`).

- **BSON codec**: int32, int64, double, string, bool, null, document, array,
  binary, datetime, timestamp, ObjectId, Regex, MinKey, MaxKey — build and
  iterate, plus `bson_to_json`, `bson_find_element`, `bson_find_path`,
  `bson_set_field`, `bson_remove_key`, `bson_copy`. Nested documents declare
  their own length and terminator, including when the last element is an int32.
- **Framing**: `mongo_msg_parse()` accepts OP_REPLY, OP_QUERY, OP_INSERT,
  OP_UPDATE, OP_DELETE, OP_MSG and the legacy OP_MSG form, and refuses a
  declared length that overruns the bytes present, an unknown opcode,
  OP_COMPRESSED, a checksummed OP_MSG, a document-sequence section and a
  document that is not NUL-terminated.
- **Query matching**: `bson_match()` and `bson_match_operator()` over a BSON
  filter document, and `bson_apply_update()`. The matcher implements
  `$eq`/`$ne`/`$gt`/`$gte`/`$lt`/`$lte`/`$in`/`$nin`/`$and`/`$or`/`$nor`/`$not`/
  `$exists`/`$type`/`$regex`/`$mod`/`$all`/`$elemMatch`/`$size`, and the
  update operators `$set`/`$unset`/`$setOnInsert`/`$inc` plus array modifiers
  (`$each`, `$position`, `$slice`, `$sort`). `$where` is **not evaluated** —
  there is no server-side JavaScript — and a filter that uses it is refused
  rather than silently matching everything.
- **Catalog and dispatch**: an in-memory catalog (`mongo_catalog_create()`,
  `mongo_catalog_create_auth()`, `mongo_catalog_bind_user()`,
  `mongo_catalog_get_db()`, `mongo_db_get_collection()`,
  `mongo_catalog_get_collection()`, `mongo_catalog_drop_collection()`), a
  user-aware dispatcher (`mongo_dispatch_command_as()`, `mongo_dispatch_command()`)
  and the commands ping, hello, insert, find, count, distinct, update, delete,
  aggregate, listCollections, listDatabases and drop. `getMore` and
  `createIndexes` are refused loudly rather than accepted and ignored.
- **Aggregation pipeline**: `$match`, `$group`, `$sort`, `$limit`, `$skip`,
  `$count`, `$project`, `$unwind`. `$lookup`, `$facet`, `$graphLookup` and
  computed expressions are refused with `NOT_IMPLEMENTED` rather than silently
  dropped.
- **Server**: `qihse_mongo_server_create()`, `_start()`, `_stop()`,
  `_destroy()` over a per-client thread, with the authenticated principal
  threaded through to the KV/document layer. A NULL principal is refused with
  code 13 and no payload.

The whole surface is restricted to the caller's clearance: the pipeline runs
over exactly the documents the principal may read, and every reply document
passes one gate — the static `mongo_reply_doc()` in
`src/spinnaker/qihse_mongo_wire.c` — which drops any document the principal may
not see and strips the stored classification/SCI metadata before the frame is
written.

## HTTP/REST API (`src/spinnaker/qihse_http_api.c`)

**Status: implemented.** HTTP server with route registration and JSON responses;
covered by `tests/test_phase_c.c` (request parsing, route registration, response
helpers). Two limits:

- `json_build_object()`'s first parameter is declared as a format string but is
  ignored: the key/value pairs are read from the varargs, so the first argument
  is consumed as the first key and
  `json_build_object("n", "42", NULL)` produces `{"42":"}`. Pass a placeholder
  first argument, as `tests/test_phase_c.c` does.
- The server socket loop itself is not covered by any test.

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

**Status: partial.** `tests/test_phase_c.c` verifies that
`qihse_clickhouse_handle_query()` answers a `GET /?query=...` request without
erroring and that the TSV formatter is callable. The format/DDL/DML/system-table
surface listed below is **not covered by any test**, and the SQL-extension
parsers it depends on have their own defects (see the SQL Extensions section).

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

**Status: partial.** `tests/test_phase_c.c` verifies the `_cluster/health`
handler, that the catch-all dispatcher answers an unknown index path without
erroring, and that `qihse_es_register_routes()` registers its routes. The query
DSL, aggregations, `_bulk`, `_msearch`, `_scroll`, `_pit`, `_reindex`, `_cat/*`
and the rest of the endpoint list below are **not covered by any test**.

- **Endpoints**: `_search` (POST/GET), `_doc` (POST/GET/PUT/DELETE), `_bulk` (POST), `_cluster/health` (GET), `_mget`, `_msearch`, `_count`, `_explain`, `_scroll`, `_pit`, `_reindex`, `_scripts`, `_template`, `_cat/*`, `_nodes`, `_cluster/*`
- **Query DSL**: match, term, range, bool (must/should/filter/must_not), match_all
- **Aggregations**: terms, avg, sum, max, min, cardinality
- **Index management**: create/delete index, mappings, settings
- **Catch-all dispatcher**: Routes any ES-style URL path to appropriate handler
- **Routes**: Registered on HTTP server, routes to FTS + vector engines

## InfluxDB API (`src/spinnaker/qihse_influx_api.c`)

**Status: partial.** `tests/test_phase_c.c` verifies the `/ping` and `/health`
handlers and that `qihse_influx_register_routes()` registers its routes (it
requires a non-NULL `qihse_tsdb_t`). The InfluxQL parser, line protocol and
`GROUP BY time()` handling below are **not covered by any test**.

- **Endpoints**: `/query` (GET/POST), `/write` (POST), `/health` (GET), `/ping` (GET/HEAD)
- **InfluxQL parser**: SELECT (with aggregations mean/sum/min/max/count), SHOW, CREATE DATABASE, DROP DATABASE/MEASUREMENT, INSERT
- **Line protocol**: `measurement,tag=val field=val timestamp` parsing with quoted strings, multiple tags/fields, nanosecond timestamps
- **WHERE predicates**: `time > now() - 1h`, epoch literals
- **GROUP BY**: `time(10m)` bucket aggregation
- **Response format**: InfluxDB JSON `{"results":[{"statement_id":0,"series":[...]}]}`
- **Routes**: Registered on HTTP server, routes to timeseries engine

## Prometheus Metrics (`src/spinnaker/qihse_metrics.c`)

**Status: implemented.** Prometheus-compatible metrics registry, covered by
`tests/test_phase_c.c` (registration, counter/gauge/histogram/summary, refusal
of unknown or duplicate metrics, and the HELP/TYPE text export).

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

**Status: partial.** Span lifecycle, tags, parent linkage, JSON export and the
enable/disable switch are covered by `tests/test_phase_c.c`, but
`qihse_span_start()` mints a fresh `trace_id` for every span instead of
inheriting the parent's, so spans of one logical trace are exported as separate
traces. The test prints this as a `NOTE` rather than asserting it.

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

**Status: partial.** `tests/test_phase_c.c` covers the context lifecycle, the
background start/stop loop and that a run/sweep with no engines attached
returns rather than failing. The per-engine compaction and TTL semantics below
are **not covered by any test**.

- **Compaction**: KV SSTable merge, columnar segment compaction, document arena compaction, timeseries block compaction
- **TTL sweep**: Remove expired keys based on cutoff timestamp
- **Background loop**: Configurable interval, runs in dedicated thread

## SQL Extensions (`src/tractable/qihse_sql_extensions.c`)

**Status: partial.** `tests/test_phase_c.c` covers VECTOR_SEARCH, TIME_BUCKET,
MATCH, the six MergeTree engine names, materialized views (including
IF NOT EXISTS), dictionaries, ARRAY JOIN, FINAL, PREWHERE, SAMPLE, SETTINGS and
the ClickHouse function detector. Two limits:

- `qihse_sql_parse_sample()` drops `SAMPLE ... OFFSET`: the keyword list it
  clamps the expression to includes `OFFSET`, so the OFFSET branch is
  unreachable and `offset_expr` is never set. Printed as a `NOTE` by the test.
- The `MATCH` highlight flag is parsed with `atoi()`, so the literal `true`
  yields 0; pass a number.

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

**Status: partial, and not covered by `tests/test_phase_c.c`.** The command
surfaces in this section are exercised (where they are exercised at all) by
other tests, named per subsection below. The previous revision of this document
claimed that `tests/test_phase_c.c` covered them; it does not.

### Redis Commands (`src/spinnaker/qihse_resp_engine.c`)

Covered by `tests/test_resp_cluster.c`, `tests/test_resp_pubsub.c` and
`tests/test_resp_security_regression.c` — not by `tests/test_phase_c.c`.
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

The transaction-control, DCL and utility statements below are recognised by the
parser (see [sql_engine.md](sql_engine.md) for what is and is not extracted into
the AST). `tests/test_sql_completeness.c` covers the statement types; the
window-function and aggregate list is not covered by any test.
- **Transaction Control**: BEGIN, COMMIT, ROLLBACK, SAVEPOINT, RELEASE, SET TRANSACTION
- **DCL**: GRANT, REVOKE, CREATE ROLE, DROP ROLE, ALTER ROLE
- **Utility**: TRUNCATE, COPY, DISCARD, RESET, SET, SHOW, DEALLOCATE, PREPARE, EXECUTE, REINDEX, CLUSTER
- **Aggregates**: VARIANCE, STDDEV, CORR, COVAR_SAMP, COVAR_POP, EVERY
- **Window Functions**: FIRST_VALUE, LAST_VALUE, NTH_VALUE

### PgBouncer Admin Commands (`src/spinnaker/qihse_pooler.c`)

`tests/test_repl.c` covers the pooler's admin-console parse and execute path
(`SHOW VERSION`, `SHOW POOLS`, `PAUSE`) plus the backend registry, pooling modes,
databases and users. The 16 SHOW commands, the 10 control commands and the
authentication methods are not individually covered.
- **SHOW**: 16 commands (POOLS, CLIENTS, SERVERS, SOCKETS, DBS, USERS, VERSION, STATS, TOTALS, LISTS, FDS, MEM, CONFIG, DNS_HOSTS, DNS_ZONES, PEERS, PEER_POOLS)
- **Control**: 10 commands (PAUSE, RESUME, DISABLE, ENABLE, RECONNECT, KILL, SUSPEND, SHUTDOWN, RELOAD, WAIT_DB)
- **Pooling modes**: Session, Transaction, Statement
- **Authentication**: trust, password, md5, scram-sha-256, cert, hba

### Neo4j Cypher Extensions (`src/tractable/qihse_cypher_parser.c`)

Covered (at the graph-engine level) by `tests/test_graph.c`; not by
`tests/test_phase_c.c`. The Bolt adapter that would carry Cypher to a driver is
separate and partial — see [bolt_protocol.md](bolt_protocol.md).
- **LOAD CSV**: WITH HEADERS, FROM path
- **CALL procedures**: db.labels(), db.relationshipTypes(), db.indexes()
- **Constraints**: CREATE/DROP CONSTRAINT, SHOW CONSTRAINTS
- **Indexes**: CREATE/DROP INDEX, SHOW INDEXES
- **Database management**: CREATE/DROP/ALTER DATABASE, SHOW DATABASES, START/STOP DATABASE
- **Query**: EXPLAIN, PROFILE, FOREACH, USE, PERIODIC COMMIT
- **Expressions**: List comprehensions, pattern comprehensions, CASE expressions

## Testing

`tests/test_phase_c.c` (run via `make test-phase-c`) covers:

1. **CDC**: subscribe/unsubscribe, duplicate-subscription refusal, event
   delivery with op/table/key/payload, monotonic LSNs, and per-subscriber
   delivery after an unsubscribe.
2. **Metrics**: registration of counter/gauge/histogram/summary, increment/set/
   observe, refusal of duplicate registration and unknown metric names, and the
   Prometheus text export.
3. **Tracing**: span start/finish, tags, parent span linkage, span count, JSON
   export, and that a disabled tracer records nothing.
4. **HTTP**: raw request parsing (method, path, query string, body,
   content-type), the JSON helpers, the response helpers, and route
   registration.
5. **MongoDB**: the BSON codec (all documented types, self-describing length,
   iteration, field lookup), query matching, and JSON export. The wire protocol,
   catalog, dispatcher and server are covered by `tests/test_mongo_wire.c`, not
   by this file.
6. **Elasticsearch / InfluxDB / ClickHouse**: the health, ping and query handler
   entry points answer, and route registration succeeds.
7. **Compaction**: context lifecycle, background start/stop idempotence, and
   that a run/sweep with no engines attached returns.
8. **SQL extensions**: VECTOR_SEARCH, TIME_BUCKET, MATCH, all six MergeTree
   engines, materialized views, dictionaries, ARRAY JOIN, FINAL, PREWHERE,
   SAMPLE, SETTINGS and the function detector.

Not covered by this file, and not claimed: the Redis/RESP surface and Cypher
(named tests above), the MongoDB aggregation pipeline and query operators
(covered by `tests/test_mongo_wire.c` instead), the Elasticsearch query DSL and
aggregations, the InfluxQL parser, the HTTP server socket loop, and per-engine
compaction semantics.
