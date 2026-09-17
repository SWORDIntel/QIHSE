/*
 * test_phase_c.c — operational and protocol layer.
 *
 * Exercises:
 *   src/spinnaker/qihse_cdc.c            — change-data-capture pub/sub
 *   src/spinnaker/qihse_metrics.c        — Prometheus-style metrics registry
 *   src/spinnaker/qihse_tracing.c        — OpenTelemetry-style spans
 *   src/spinnaker/qihse_http_api.c       — HTTP request parsing, routes, JSON helpers
 *   src/spinnaker/qihse_es_api.c         — Elasticsearch-compatible handlers
 *   src/spinnaker/qihse_influx_api.c     — InfluxDB-compatible handlers
 *   src/spinnaker/qihse_clickhouse_http.c— ClickHouse HTTP handler
 *   src/spinnaker/qihse_mongo_wire.c     — BSON codec and query matching
 *   src/tractable/qihse_compaction.c     — compaction context and TTL sweep
 *   src/tractable/qihse_sql_extensions.c — VECTOR_SEARCH / TIME_BUCKET / MATCH and
 *                                          the ClickHouse SQL extension parsers
 *
 *   1.  CDC: subscriptions, event delivery, LSN monotonicity, unsubscribe
 *   2.  Metrics: registration, counter/gauge/histogram, Prometheus text export
 *   3.  Tracing: span lifecycle, tags, parent/child, JSON export
 *   4.  HTTP: raw request parsing, route registration, JSON helpers, responses
 *   5.  MongoDB: BSON build/iterate round trip, field lookup, query matching
 *   6.  Elasticsearch: health and unknown-path dispatch through the handler
 *   7.  InfluxDB: ping/health handlers
 *   8.  ClickHouse: handler present and answering on a request with a query
 *   9.  Compaction: context lifecycle, background start/stop, TTL sweep
 *   10. SQL extensions: VECTOR_SEARCH, TIME_BUCKET, MATCH, MergeTree,
 *       materialized view, dictionary, ARRAY JOIN, FINAL, PREWHERE, SAMPLE,
 *       SETTINGS and the ClickHouse function detector
 *
 * NOT covered here, and NOT claimed by the document:
 *   - the Redis command surface (src/spinnaker/qihse_resp_engine.c) and
 *     RESP pub/sub are exercised by tests/test_resp_cluster.c and
 *     tests/test_resp_pubsub.c, not by this file;
 *   - the Cypher surface is exercised by tests/test_graph.c;
 *   - the MongoDB aggregation pipeline, query operators and admin commands are
 *     not covered by any test in this repository;
 *   - the Elasticsearch query DSL and aggregations, and the InfluxQL parser,
 *     are not covered beyond the health/ping paths below.
 */
#include "qihse_cdc.h"
#include "qihse_metrics.h"
#include "qihse_tracing.h"
#include "qihse_http_api.h"
#include "qihse_es_api.h"
#include "qihse_influx_api.h"
#include "qihse_timeseries.h"
#include "qihse_clickhouse_http.h"
#include "qihse_mongo_wire.h"
#include "qihse_compaction.h"
#include "qihse_sql_extensions.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── 1. CDC ─────────────────────────────────────────────────────────────── */

typedef struct {
    int calls;
    cdc_op_t last_op;
    char last_table[32];
    char last_key[32];
    char last_new[32];
    uint64_t last_lsn;
} cdc_sink_t;

static void cdc_cb(const qihse_cdc_event_t* ev, void* user_data) {
    cdc_sink_t* s = (cdc_sink_t*)user_data;
    s->calls++;
    s->last_op = ev->op;
    snprintf(s->last_table, sizeof(s->last_table), "%s", ev->table ? ev->table : "");
    snprintf(s->last_key, sizeof(s->last_key), "%s", ev->key ? ev->key : "");
    if (ev->new_value && ev->new_value_len < sizeof(s->last_new)) {
        memcpy(s->last_new, ev->new_value, ev->new_value_len);
        s->last_new[ev->new_value_len] = '\0';
    } else {
        s->last_new[0] = '\0';
    }
    s->last_lsn = ev->lsn;
}

static void test_cdc(void) {
    qihse_cdc_context_t* ctx = qihse_cdc_create();
    assert(ctx);
    assert(qihse_cdc_subscription_count(ctx) == 0);
    assert(qihse_cdc_get_lsn(ctx) == 0);

    cdc_sink_t a = {0}, b = {0};
    assert(qihse_cdc_subscribe(ctx, "sub_a", cdc_cb, &a) == 0);
    assert(qihse_cdc_subscribe(ctx, "sub_b", cdc_cb, &b) == 0);
    assert(qihse_cdc_subscription_count(ctx) == 2);
    /* Duplicate subscription names are refused. */
    assert(qihse_cdc_subscribe(ctx, "sub_a", cdc_cb, &a) == -1);

    const uint8_t oldv[] = "old";
    const uint8_t newv[] = "new-value";
    assert(qihse_cdc_emit(ctx, CDC_OP_INSERT, "users", "user:1",
                          NULL, 0, newv, sizeof(newv) - 1) == 0);
    assert(a.calls == 1 && b.calls == 1);
    assert(a.last_op == CDC_OP_INSERT);
    assert(strcmp(a.last_table, "users") == 0);
    assert(strcmp(a.last_key, "user:1") == 0);
    assert(strcmp(a.last_new, "new-value") == 0);
    uint64_t lsn1 = a.last_lsn;

    assert(qihse_cdc_emit(ctx, CDC_OP_UPDATE, "users", "user:1",
                          oldv, sizeof(oldv) - 1, newv, sizeof(newv) - 1) == 0);
    assert(a.calls == 2 && a.last_op == CDC_OP_UPDATE);
    assert(a.last_lsn > lsn1);
    assert(qihse_cdc_get_lsn(ctx) == a.last_lsn);

    assert(qihse_cdc_emit(ctx, CDC_OP_DELETE, "users", "user:2",
                          oldv, sizeof(oldv) - 1, NULL, 0) == 0);
    assert(a.calls == 3 && a.last_op == CDC_OP_DELETE);
    assert(strcmp(a.last_new, "") == 0);

    /* Unsubscribing stops delivery to that subscriber only. */
    assert(qihse_cdc_unsubscribe(ctx, "sub_a") == 0);
    assert(qihse_cdc_subscription_count(ctx) == 1);
    assert(qihse_cdc_unsubscribe(ctx, "sub_a") == -1);
    int b_calls = b.calls;
    assert(qihse_cdc_emit(ctx, CDC_OP_INSERT, "orders", "order:1",
                          NULL, 0, newv, sizeof(newv) - 1) == 0);
    assert(a.calls == 3);
    assert(b.calls == b_calls + 1);
    assert(strcmp(b.last_table, "orders") == 0);

    qihse_cdc_destroy(ctx);
    printf("PASS cdc: subscribe/unsubscribe, event delivery, monotonic LSN\n");
}

/* ── 2. Metrics ─────────────────────────────────────────────────────────── */

static void test_metrics(void) {
    qihse_metrics_registry_t* reg = qihse_metrics_create();
    assert(reg);
    assert(qihse_metrics_count(reg) == 0);

    assert(qihse_metrics_register(reg, "qihse_queries_total", "Total queries",
                                  METRIC_COUNTER) == 0);
    assert(qihse_metrics_register(reg, "qihse_connections", "Open connections",
                                  METRIC_GAUGE) == 0);
    assert(qihse_metrics_register(reg, "qihse_latency_ms", "Query latency",
                                  METRIC_HISTOGRAM) == 0);
    assert(qihse_metrics_register(reg, "qihse_rows", "Rows scanned",
                                  METRIC_SUMMARY) == 0);
    assert(qihse_metrics_count(reg) == 4);
    /* Re-registering the same name is refused. */
    assert(qihse_metrics_register(reg, "qihse_queries_total", "dup",
                                  METRIC_COUNTER) == -1);

    assert(qihse_metrics_increment(reg, "qihse_queries_total", 3) == 0);
    assert(qihse_metrics_increment(reg, "qihse_queries_total", 2) == 0);
    assert(qihse_metrics_set(reg, "qihse_connections", 7) == 0);
    assert(qihse_metrics_observe(reg, "qihse_latency_ms", 1.5) == 0);
    assert(qihse_metrics_observe(reg, "qihse_latency_ms", 2.5) == 0);
    assert(qihse_metrics_increment(reg, "qihse_rows", 10) == 0);
    /* Unknown metrics are refused, not silently created. */
    assert(qihse_metrics_increment(reg, "no_such_metric", 1) == -1);

    char* text = qihse_metrics_export(reg);
    assert(text);
    assert(strstr(text, "qihse_queries_total") != NULL);
    assert(strstr(text, "# TYPE") != NULL);
    assert(strstr(text, "# HELP") != NULL);
    assert(strstr(text, "5") != NULL);      /* 3 + 2 */
    assert(strstr(text, "qihse_connections") != NULL);
    free(text);

    qihse_metrics_destroy(reg);
    printf("PASS metrics: registration, counter/gauge/histogram/summary, Prometheus export\n");
}

/* ── 3. Tracing ─────────────────────────────────────────────────────────── */

static void test_tracing(void) {
    qihse_tracer_t* tracer = qihse_tracer_create();
    assert(tracer);
    assert(qihse_tracer_span_count(tracer) == 0);

    qihse_span_t* root = qihse_span_start(tracer, "query_execute", NULL);
    assert(root);
    assert(qihse_span_set_tag(root, "db.system", "qihse") == 0);
    assert(qihse_span_set_tag(root, "db.statement", "SELECT 1") == 0);
    assert(qihse_span_set_status(root, 0) == 0);

    /* A child span records its parent's span id. */
    const char* parent_id = root->span_id;
    assert(parent_id && strlen(parent_id) > 0);
    qihse_span_t* child = qihse_span_start(tracer, "parse", parent_id);
    assert(child);
    assert(child->parent_span_id && strcmp(child->parent_span_id, parent_id) == 0);
    assert(child->trace_id && strlen(child->trace_id) > 0);
    assert(qihse_span_finish(tracer, child) == 0);
    assert(qihse_span_finish(tracer, root) == 0);
    assert(qihse_tracer_span_count(tracer) == 2);
    assert(qihse_span_duration_ns(root) < 60000000000ULL);

    /*
     * KNOWN DEFECT (reported, not asserted): qihse_span_start() always mints a
     * fresh trace_id and never inherits the parent's, so spans of one logical
     * trace are exported as separate traces even though the parent link is
     * recorded.  Printed rather than asserted so a fix cannot break this test.
     */
    printf("NOTE tracing: child span trace_id %s the parent's trace_id "
           "(OpenTelemetry requires them to match) -- see "
           "docs/architecture/operational_protocols.md\n",
           (strcmp(child->trace_id, root->trace_id) == 0) ? "matches" : "differs from");

    char* json = qihse_tracer_export_json(tracer);
    assert(json);
    assert(strstr(json, "query_execute") != NULL);
    assert(strstr(json, "parse") != NULL);
    assert(strstr(json, "db.system") != NULL);
    free(json);

    /* A disabled tracer records nothing new. */
    qihse_tracer_set_enabled(tracer, 0);
    qihse_span_t* dropped = qihse_span_start(tracer, "should_not_record", NULL);
    if (dropped) qihse_span_finish(tracer, dropped);
    assert(qihse_tracer_span_count(tracer) == 2);

    qihse_tracer_destroy(tracer);
    printf("PASS tracing: span lifecycle, parent/child linkage, tags, JSON export, disable\n");
}

/* ── 4. HTTP ────────────────────────────────────────────────────────────── */

static http_response_t* echo_handler(const http_request_t* req, void* user_data) {
    (void)user_data;
    return http_response_json(200, req->path ? req->path : "null");
}

static void test_http_api(void) {
    /* Raw request parsing: method, path, query string, body. */
    const char* raw =
        "POST /api/users?limit=5&offset=1 HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"a\":\"bcd\"}\r\n";
    http_request_t req;
    memset(&req, 0, sizeof(req));
    assert(http_parse_request(raw, strlen(raw), &req) == 0);
    assert(req.method == HTTP_POST);
    assert(req.path && strcmp(req.path, "/api/users") == 0);
    assert(req.query_string && strcmp(req.query_string, "limit=5&offset=1") == 0);
    assert(req.body && req.body_len == 13);
    assert(strncmp(req.body, "{\"a\":\"bcd\"}", 11) == 0);
    assert(req.content_type && strcmp(req.content_type, "application/json") == 0);
    http_request_free(&req);

    /* A GET without a body. */
    const char* get = "GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n";
    memset(&req, 0, sizeof(req));
    assert(http_parse_request(get, strlen(get), &req) == 0);
    assert(req.method == HTTP_GET);
    assert(strcmp(req.path, "/ping") == 0);
    http_request_free(&req);

    /* JSON helpers. */
    char* esc = json_escape("he said \"hi\"\n");
    assert(esc);
    assert(strstr(esc, "\\\"") != NULL);
    assert(strstr(esc, "\\n") != NULL);
    free(esc);

    /* json_build_object()'s first parameter is declared as a format string but
     * is ignored: the key/value pairs are read from the varargs, so the first
     * argument is consumed as the first *key*.  The call below therefore passes
     * a placeholder first argument.  See the defect note in
     * docs/architecture/operational_protocols.md. */
    char* obj = json_build_object("(ignored)", "n", "42", "s", "x", NULL);
    assert(obj);
    assert(strstr(obj, "\"n\":\"42\"") != NULL);
    assert(strstr(obj, "\"s\":\"x\"") != NULL);
    free(obj);
    /* The natural call silently drops the first pair. */
    obj = json_build_object("n", "42", NULL);
    assert(obj);
    assert(strcmp(obj, "{\"42\":\"}") == 0 || strstr(obj, "\"n\"") == NULL);
    free(obj);
    printf("NOTE http api: json_build_object() ignores its first (format) argument and "
           "consumes it as the first key, so json_build_object(\"n\", \"42\", NULL) "
           "yields %s -- see docs/architecture/operational_protocols.md\n",
           "{\"42\":\"}");

    /* Responses. */
    http_response_t* res = http_response_json(200, "{\"ok\":true}");
    assert(res);
    assert(res->status_code == 200);
    assert(res->body && strstr(res->body, "ok") != NULL);
    http_response_free(res);

    res = http_response_text(201, "created");
    assert(res && res->status_code == 201);
    http_response_free(res);

    res = http_response_error(404, "not found");
    assert(res && res->status_code == 404);
    assert(res->body && strstr(res->body, "not found") != NULL);
    http_response_free(res);

    /* Route registration (the server is not started, so no port is bound). */
    qihse_http_server_t* srv = qihse_http_server_create(0);
    assert(srv);
    assert(qihse_http_server_add_route(srv, "/api/users", HTTP_GET,
                                       echo_handler, NULL) == 0);
    assert(qihse_http_server_add_route(srv, "/api/users", HTTP_POST,
                                       echo_handler, NULL) == 0);
    assert(srv->num_routes == 2);
    qihse_http_server_destroy(srv);

    printf("PASS http api: request parsing, JSON helpers, responses, route registration\n");
}

/* ── 5. MongoDB BSON and wire parsing ───────────────────────────────────── */

static void test_mongo_bson(void) {
    bson_t* doc = bson_create();
    assert(doc);
    assert(bson_append_string(doc, "name", "alice") == 0);
    assert(bson_append_int32(doc, "age", 41) == 0);
    assert(bson_append_int64(doc, "big", 9007199254740993LL) == 0);
    assert(bson_append_double(doc, "score", 1.5) == 0);
    assert(bson_append_bool(doc, "active", 1) == 0);
    assert(bson_append_null(doc, "nothing") == 0);
    bson_t* sub = bson_create();
    assert(sub);
    assert(bson_append_string(sub, "city", "springfield") == 0);
    assert(bson_append_document(doc, "address", sub) == 0);
    assert(bson_append_array(doc, "tags", sub) == 0);
    const uint8_t bin[3] = {1, 2, 3};
    assert(bson_append_binary(doc, "blob", bin, sizeof(bin)) == 0);
    assert(bson_append_datetime(doc, "when", 1700000000000LL) == 0);
    const uint8_t oid[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    assert(bson_append_objectid(doc, "_id", oid) == 0);

    size_t size = bson_size(doc);
    assert(size > 0);
    const uint8_t* data = bson_data(doc);
    assert(data);
    /* BSON documents carry their own length in the first four bytes. */
    uint32_t declared = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                        ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    assert(declared == size);

    /* Iterate the document and check the string and int fields. */
    size_t off = 4;
    bson_element_t elem;
    int saw_name = 0, saw_age = 0, saw_big = 0, saw_double = 0, saw_bool = 0;
    int saw_null = 0, saw_doc = 0, saw_array = 0, saw_bin = 0;
    int saw_date = 0, saw_oid = 0;
    while (bson_iter(doc, &off, &elem) == 0) {
        if (!elem.key) break;
        if (strcmp(elem.key, "name") == 0) {
            saw_name = 1;
            assert(elem.type == BSON_STRING);
            assert(strcmp(elem.v.str, "alice") == 0);
        } else if (strcmp(elem.key, "age") == 0) {
            saw_age = 1;
            assert(elem.v.i32 == 41);
        } else if (strcmp(elem.key, "big") == 0) {
            saw_big = 1;
            assert(elem.v.i64 == 9007199254740993LL);
        } else if (strcmp(elem.key, "score") == 0) {
            saw_double = 1;
            assert(elem.v.d == 1.5);
        } else if (strcmp(elem.key, "active") == 0) {
            saw_bool = 1;
            assert(elem.v.b == 1);
        } else if (strcmp(elem.key, "nothing") == 0) {
            saw_null = 1;
        } else if (strcmp(elem.key, "address") == 0) {
            saw_doc = 1;
        } else if (strcmp(elem.key, "tags") == 0) {
            saw_array = 1;
        } else if (strcmp(elem.key, "blob") == 0) {
            saw_bin = 1;
            assert(elem.v.bin.len == sizeof(bin));
        } else if (strcmp(elem.key, "when") == 0) {
            saw_date = 1;
        } else if (strcmp(elem.key, "_id") == 0) {
            saw_oid = 1;
        }
    }
    assert(saw_name && saw_age && saw_big && saw_double && saw_bool &&
           saw_null && saw_doc && saw_array && saw_bin && saw_date && saw_oid);

    bson_destroy(sub);
    bson_destroy(doc);

    /* BSON field lookup and query-operator matching (the query path the
     * document describes). */
    bson_t* qdoc = bson_create();
    assert(qdoc);
    assert(bson_append_string(qdoc, "name", "alice") == 0);
    assert(bson_append_int32(qdoc, "age", 41) == 0);

    bson_element_t found_elem;
    assert(bson_find_element(qdoc, "age", &found_elem) == 0);
    assert(found_elem.v.i32 == 41);
    assert(bson_find_element(qdoc, "absent", &found_elem) != 0);

    /* An empty filter matches everything. */
    bson_t* empty = bson_create();
    assert(empty);
    assert(bson_match(qdoc, empty) == 1);
    bson_destroy(empty);

    /* Equality filter on a string field. */
    bson_t* filter = bson_create();
    assert(filter);
    assert(bson_append_string(filter, "name", "alice") == 0);
    assert(bson_match(qdoc, filter) == 1);
    bson_t* miss = bson_create();
    assert(miss);
    assert(bson_append_string(miss, "name", "bob") == 0);
    assert(bson_match(qdoc, miss) == 0);
    bson_destroy(miss);
    bson_destroy(filter);

    char* json = bson_to_json(qdoc);
    assert(json);
    assert(strstr(json, "alice") != NULL);
    assert(strstr(json, "41") != NULL);
    free(json);
    bson_destroy(qdoc);

    /*
     * KNOWN GAP (reported, not asserted): include/qihse_mongo_wire.h declares
     * mongo_msg_parse(), mongo_msg_get_document(), mongo_catalog_*(),
     * mongo_dispatch_command() and qihse_mongo_server_*(), but none of them
     * exist in any source file and libqihse.so exports no mongo_* symbols at
     * all.  There is therefore no MongoDB wire protocol to test: only the BSON
     * codec and the query matcher above are implemented.
     */
    printf("NOTE mongo wire: the wire protocol (mongo_msg_parse / qihse_mongo_server_*) "
           "declared in include/qihse_mongo_wire.h is not implemented; only the BSON "
           "codec and query matcher exist -- see docs/architecture/operational_protocols.md\n");

    printf("PASS mongo bson: build/iterate round trip, field lookup, query matching, JSON export\n");
}

/* ── 6/7/8. ES, Influx, ClickHouse handlers ─────────────────────────────── */

static http_request_t make_request(const char* raw) {
    http_request_t req;
    memset(&req, 0, sizeof(req));
    assert(http_parse_request(raw, strlen(raw), &req) == 0);
    return req;
}

static void test_es_handler(void) {
    http_request_t req = make_request(
        "GET /_cluster/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    http_response_t* res = qihse_es_handle_health(&req, NULL);
    assert(res);
    assert(res->status_code >= 200 && res->status_code < 300);
    assert(res->body && strlen(res->body) > 0);
    http_response_free(res);
    http_request_free(&req);

    /* An ES-style path that has no data behind it must answer, not crash. */
    req = make_request("GET /some-index/_search HTTP/1.1\r\nHost: localhost\r\n\r\n");
    res = qihse_es_handle_dispatch(&req, NULL);
    assert(res);
    assert(res->status_code >= 200 && res->status_code < 500);
    http_response_free(res);
    http_request_free(&req);

    /* Route registration on a server instance. */
    qihse_http_server_t* srv = qihse_http_server_create(0);
    assert(srv);
    assert(qihse_es_register_routes(srv, NULL, NULL) == 0);
    assert(srv->num_routes > 0);
    qihse_http_server_destroy(srv);

    printf("PASS elasticsearch api: health handler, dispatch on unknown path, route registration\n");
}

static void test_influx_handler(void) {
    http_request_t req = make_request(
        "GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n");
    http_response_t* res = qihse_influx_handle_ping(&req, NULL);
    assert(res);
    assert(res->status_code >= 200 && res->status_code < 300);
    http_response_free(res);
    http_request_free(&req);

    req = make_request("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    res = qihse_influx_handle_health(&req, NULL);
    assert(res);
    assert(res->status_code >= 200 && res->status_code < 500);
    http_response_free(res);
    http_request_free(&req);

    qihse_http_server_t* srv = qihse_http_server_create(0);
    assert(srv);
    /* Route registration requires a real time-series handle. */
    qihse_tsdb_t* tsdb = qihse_tsdb_create();
    assert(tsdb);
    assert(qihse_influx_register_routes(srv, tsdb) == 0);
    assert(srv->num_routes > 0);
    qihse_http_server_destroy(srv);
    qihse_tsdb_destroy(tsdb);

    printf("PASS influx api: ping/health handlers and route registration\n");
}

static void test_clickhouse_handler(void) {
    http_request_t req = make_request(
        "GET /?query=SELECT%201 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    http_response_t* res = qihse_clickhouse_handle_query(&req, NULL);
    assert(res);
    assert(res->status_code >= 200 && res->status_code < 500);
    http_response_free(res);
    http_request_free(&req);

    char* tsv = qihse_clickhouse_format_tsv("SELECT 1", NULL);
    if (tsv) free(tsv);
    printf("PASS clickhouse http: query handler answers, TSV formatter callable\n");
}

/* ── 9. Compaction ──────────────────────────────────────────────────────── */

static void test_compaction(void) {
    qihse_compaction_ctx_t* ctx = qihse_compaction_create();
    assert(ctx);
    /* With no engines attached, a run reports zero work rather than failing. */
    qihse_compaction_result_t r = qihse_compaction_run(ctx, COMPACTION_KV);
    (void)r;
    qihse_ttl_result_t ttl = qihse_ttl_sweep(ctx, 0);
    (void)ttl;
    /* Background loop start/stop must be idempotent-safe. */
    assert(qihse_compaction_start(ctx, 1) == 0);
    assert(qihse_compaction_stop(ctx) == 0);
    assert(qihse_compaction_stop(ctx) == 0);
    qihse_compaction_destroy(ctx);
    printf("PASS compaction: context lifecycle, background start/stop, sweep callable\n");
}

/* ── 10. SQL extensions ─────────────────────────────────────────────────── */

static void test_sql_extensions(void) {
    /* VECTOR_SEARCH(table, query_vec, k, distance_metric) */
    qihse_vector_search_spec_t vs;
    memset(&vs, 0, sizeof(vs));
    int rc = qihse_sql_parse_vector_search(
        "SELECT * FROM VECTOR_SEARCH(items, '[1,2,3]', 5, 'cosine')", &vs);
    assert(rc == 0);
    assert(vs.table_name && strcmp(vs.table_name, "items") == 0);
    assert(vs.k == 5);
    assert(vs.distance_metric && strcmp(vs.distance_metric, "cosine") == 0);
    qihse_vector_search_spec_free(&vs);

    /* TIME_BUCKET(bucket_width, time_column, agg_func, value_column) */
    qihse_time_bucket_spec_t tb;
    memset(&tb, 0, sizeof(tb));
    rc = qihse_sql_parse_time_bucket(
        "SELECT TIME_BUCKET('5m', ts, avg, value) FROM metrics", &tb);
    assert(rc == 0);
    assert(tb.bucket_width_ms == 5 * 60 * 1000);
    assert(tb.time_column && strcmp(tb.time_column, "ts") == 0);
    assert(tb.agg_func && strcmp(tb.agg_func, "avg") == 0);
    assert(tb.value_column && strcmp(tb.value_column, "value") == 0);
    qihse_time_bucket_spec_free(&tb);

    /* MATCH(field, query, highlight, snippet_size): the highlight flag is
     * parsed with atoi(), so it must be numeric ("true" yields 0). */
    qihse_fts_match_spec_t fm;
    memset(&fm, 0, sizeof(fm));
    rc = qihse_sql_parse_fts_match(
        "SELECT * FROM MATCH(body, 'quick fox', 1, 64)", &fm);
    assert(rc == 0);
    assert(fm.field && strcmp(fm.field, "body") == 0);
    assert(fm.query && strstr(fm.query, "quick fox") != NULL);
    assert(fm.highlight == 1);
    assert(fm.snippet_size == 64);
    qihse_fts_match_spec_free(&fm);
    /* The two-argument form defaults to no highlight and a 100-char snippet. */
    memset(&fm, 0, sizeof(fm));
    assert(qihse_sql_parse_fts_match("MATCH(body, 'quick fox')", &fm) == 0);
    assert(fm.highlight == 0);
    assert(fm.snippet_size == 100);
    qihse_fts_match_spec_free(&fm);

    /* MergeTree engine parsing with ORDER BY / PARTITION BY / SETTINGS. */
    qihse_ch_mergetree_spec_t mt;
    memset(&mt, 0, sizeof(mt));
    rc = qihse_sql_parse_mergetree(
        "CREATE TABLE events (ts DateTime, v UInt64) ENGINE = ReplacingMergeTree "
        "PARTITION BY toYYYYMM(ts) ORDER BY (ts, v) SETTINGS index_granularity = 8192",
        &mt);
    assert(rc == 0);
    assert(mt.engine_kind == QIHSE_CH_ENGINE_REPLACING_MERGETREE);
    assert(mt.order_by_expr && strlen(mt.order_by_expr) > 0);
    assert(mt.partition_by_expr && strlen(mt.partition_by_expr) > 0);
    qihse_ch_mergetree_spec_free(&mt);
    /* All six engine names are recognised. */
    struct { const char* sql; qihse_ch_engine_kind_t want; } engines[] = {
        {"ENGINE = MergeTree ORDER BY a",            QIHSE_CH_ENGINE_MERGETREE},
        {"ENGINE = ReplacingMergeTree(v) ORDER BY a", QIHSE_CH_ENGINE_REPLACING_MERGETREE},
        {"ENGINE = SummingMergeTree ORDER BY a",      QIHSE_CH_ENGINE_SUMMING_MERGETREE},
        {"ENGINE = AggregatingMergeTree ORDER BY a",  QIHSE_CH_ENGINE_AGGREGATING_MERGETREE},
        {"ENGINE = CollapsingMergeTree ORDER BY a",   QIHSE_CH_ENGINE_COLLAPSING_MERGETREE},
        {"ENGINE = VersionedMergeTree ORDER BY a",    QIHSE_CH_ENGINE_VERSIONED_MERGETREE},
    };
    for (size_t i = 0; i < sizeof(engines) / sizeof(engines[0]); i++) {
        memset(&mt, 0, sizeof(mt));
        assert(qihse_sql_parse_mergetree(engines[i].sql, &mt) == 0);
        assert(mt.engine_kind == engines[i].want);
        assert(strcmp(qihse_ch_engine_name(mt.engine_kind),
                      qihse_ch_engine_name(engines[i].want)) == 0);
        qihse_ch_mergetree_spec_free(&mt);
    }

    /* Materialized view with a TO target. */
    qihse_ch_matview_spec_t mv;
    memset(&mv, 0, sizeof(mv));
    rc = qihse_sql_parse_materialized_view(
        "CREATE MATERIALIZED VIEW mv TO dst AS SELECT a FROM src", &mv);
    assert(rc == 0);
    assert(mv.view_name && strcmp(mv.view_name, "mv") == 0);
    assert(mv.target_table && strcmp(mv.target_table, "dst") == 0);
    qihse_ch_matview_spec_free(&mv);
    /* IF NOT EXISTS is recognised. */
    memset(&mv, 0, sizeof(mv));
    assert(qihse_sql_parse_materialized_view(
        "CREATE MATERIALIZED VIEW IF NOT EXISTS mv2 AS SELECT 1", &mv) == 0);
    assert(mv.view_name && strcmp(mv.view_name, "mv2") == 0);
    assert(mv.if_not_exists == 1);
    qihse_ch_matview_spec_free(&mv);

    /* Dictionary with SOURCE / LAYOUT / LIFETIME. */
    qihse_ch_dictionary_spec_t dict;
    memset(&dict, 0, sizeof(dict));
    rc = qihse_sql_parse_dictionary(
        "CREATE DICTIONARY d (id UInt64, name String) PRIMARY KEY id "
        "SOURCE(CLICKHOUSE(TABLE 'src')) LAYOUT(FLAT()) LIFETIME(300)", &dict);
    assert(rc == 0);
    assert(dict.dict_name && strcmp(dict.dict_name, "d") == 0);
    assert(dict.lifetime == 300);
    assert(dict.source && strstr(dict.source, "CLICKHOUSE") != NULL);
    assert(dict.layout && strstr(dict.layout, "FLAT") != NULL);
    qihse_ch_dictionary_spec_free(&dict);

    /* ARRAY JOIN. */
    qihse_ch_array_join_t aj;
    memset(&aj, 0, sizeof(aj));
    rc = qihse_sql_parse_array_join("SELECT a FROM t ARRAY JOIN arr AS a", &aj);
    assert(rc == 0);
    assert(aj.array_expr && strstr(aj.array_expr, "arr") != NULL);
    assert(aj.is_left == 0);
    qihse_ch_array_join_free(&aj);
    memset(&aj, 0, sizeof(aj));
    assert(qihse_sql_parse_array_join("SELECT a FROM t LEFT ARRAY JOIN arr AS a",
                                      &aj) == 0);
    assert(aj.is_left == 1);
    qihse_ch_array_join_free(&aj);

    /* FINAL, PREWHERE, SAMPLE, SETTINGS, functions. */
    assert(qihse_sql_has_final_modifier("SELECT * FROM t FINAL WHERE a = 1") == 1);
    assert(qihse_sql_has_final_modifier("SELECT * FROM final_table") == 0);
    char* pre = qihse_sql_extract_prewhere("SELECT * FROM t PREWHERE a > 1 WHERE b < 2");
    assert(pre);
    assert(strstr(pre, "a > 1") != NULL);
    free(pre);
    qihse_ch_sample_spec_t sample;
    memset(&sample, 0, sizeof(sample));
    assert(qihse_sql_parse_sample("SELECT * FROM t SAMPLE 0.1", &sample) == 0);
    assert(sample.sample_expr && strcmp(sample.sample_expr, "0.1") == 0);
    assert(sample.is_offset == 0);
    qihse_ch_sample_spec_free(&sample);

    /* KNOWN DEFECT (reported, not asserted): SAMPLE ... OFFSET drops the
     * OFFSET.  qihse_sql_parse_sample() clamps the expression end to the first
     * of a keyword list that itself contains "OFFSET", so the OFFSET branch
     * (`off_p < end`) can never be taken. */
    memset(&sample, 0, sizeof(sample));
    assert(qihse_sql_parse_sample("SELECT * FROM t SAMPLE 0.1 OFFSET 0.5",
                                  &sample) == 0);
    printf("NOTE sql extensions: SAMPLE 0.1 OFFSET 0.5 parsed with is_offset=%d, "
           "offset_expr=%s (the OFFSET is dropped) -- see "
           "docs/architecture/operational_protocols.md\n",
           sample.is_offset, sample.offset_expr ? sample.offset_expr : "absent");
    qihse_ch_sample_spec_free(&sample);

    qihse_ch_query_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    assert(qihse_sql_extract_settings(
        "SELECT 1 SETTINGS max_threads = 4, max_memory_usage = 1000",
        &settings) == 0);
    assert(settings.num_settings == 2);
    assert(strcmp(settings.names[0], "max_threads") == 0);
    assert(strcmp(settings.values[0], "4") == 0);
    assert(strcmp(settings.names[1], "max_memory_usage") == 0);
    assert(strcmp(settings.values[1], "1000") == 0);
    qihse_ch_query_settings_free(&settings);

    assert(qihse_ch_detect_function("now") == QIHSE_CH_FUNC_NOW);
    assert(qihse_ch_detect_function("countIf") == QIHSE_CH_FUNC_COUNTIF);
    assert(qihse_ch_detect_function("groupUniqArray") == QIHSE_CH_FUNC_GROUPUNIQARRAY);
    assert(qihse_ch_detect_function("not_a_function") == QIHSE_CH_FUNC_NONE);

    printf("PASS sql extensions: VECTOR_SEARCH/TIME_BUCKET/MATCH, six MergeTree engines, "
           "matview, dictionary, ARRAY JOIN, FINAL, PREWHERE, SAMPLE, SETTINGS, functions\n");
}

int main(void) {
    test_cdc();
    test_metrics();
    test_tracing();
    test_http_api();
    test_mongo_bson();
    test_es_handler();
    test_influx_handler();
    test_clickhouse_handler();
    test_compaction();
    test_sql_extensions();
    printf("test_phase_c: all operational/protocol tests passed "
           "(see the header for what this file does not cover)\n");
    return 0;
}
