# Operational & Protocol Layer

## Overview

QIHSE provides a complete operational and protocol stack beyond the core storage engines: CDC, MongoDB wire protocol, HTTP/REST API, ClickHouse HTTP, Elasticsearch API, Prometheus metrics, OpenTelemetry tracing, compaction/TTL, and SQL extensions.

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

- **BSON types**: int32, int64, double, string, bool, null, document, array, binary, datetime, timestamp
- **Wire protocol**: OP_REPLY, OP_INSERT, OP_QUERY, OP_UPDATE, OP_DELETE, OP_MSG
- **Server**: TCP server with per-client threading
- **Document store**: Routes to existing `qihse_document_store`

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

ClickHouse-compatible HTTP query interface.

- **Formats**: TabSeparated, JSON, JSONEachRow
- **Endpoints**: `GET /?query=...`, `POST /` with query body
- **Routes**: Registered on HTTP server, routes to columnar engine

## Elasticsearch API (`src/spinnaker/qihse_es_api.c`)

Elasticsearch-compatible REST endpoints.

- **Endpoints**: `_search` (POST/GET), `_doc` (POST/GET), `_bulk` (POST), `_cluster/health` (GET)
- **Query DSL**: JSON-based query parsing
- **Routes**: Registered on HTTP server, routes to FTS + vector engines

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

Domain-specific SQL table functions.

### VECTOR_SEARCH(table, query_vec, k, distance_metric)
Vector similarity search as a SQL table function. Supports euclidean, cosine, and dot product distances.

### TIME_BUCKET(bucket_width, time_column, agg_func, value_column)
Time-series aggregation with configurable bucket widths (e.g. `'5m'`, `'1h'`, `'1d'`). Supports gap filling (NULL, linear interpolation, carry-forward).

### MATCH(field, query, highlight, snippet_size)
Full-text search with BM25 scoring and optional highlight snippets.

## Testing
14 tests in `tests/test_phase_c.c` covering all the above features.
