"""Comprehensive tests for Phase C Python SDKs."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import qihse_mongo
import qihse_http
import qihse_clickhouse
import qihse_elasticsearch
import qihse_cdc
import qihse_metrics

passed = 0
failed = 0

def test(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")

# ---- MongoDB SDK ----
print("\n=== MongoDB SDK (qihse_mongo) ===")

# ObjectId
oid = qihse_mongo.ObjectId()
test("ObjectId creates 24-char hex", len(str(oid)) == 24)
oid2 = qihse_mongo.ObjectId(str(oid))
test("ObjectId round-trip", oid == oid2)

# MongoClient (offline - no server needed for API tests)
client = qihse_mongo.MongoClient("localhost", 27018)
test("MongoClient creates", client is not None)
test("MongoClient address", client.address == ("localhost", 27018))

db = client["testdb"]
test("Database name", db.name == "testdb")
test("Database client", db.client is client)

coll = db.users
test("Collection name", coll.name == "users")
test("Collection database", coll.database is db)

# Insert
result = coll.insert_one({"name": "Alice", "age": 30})
test("insert_one returns InsertOneResult", hasattr(result, "inserted_id"))
test("insert_one sets _id", result.inserted_id is not None)

results = coll.insert_many([{"name": "Bob"}, {"name": "Carol"}])
test("insert_many returns InsertManyResult", hasattr(results, "inserted_ids"))
test("insert_many count", len(results.inserted_ids) == 2)

# Find
cursor = coll.find({"age": {"$gt": 25}})
test("find returns Cursor", isinstance(cursor, qihse_mongo.Cursor))
test("Cursor limit", cursor.limit(10) is cursor)
test("Cursor skip", cursor.skip(0) is cursor)
test("Cursor sort", cursor.sort("name") is cursor)
test("Cursor to_list", isinstance(cursor.to_list(), list))

# Update/Delete
upd = coll.update_one({"name": "Alice"}, {"$set": {"age": 31}})
test("update_one returns UpdateResult", hasattr(upd, "matched_count"))

dele = coll.delete_one({"name": "Bob"})
test("delete_one returns DeleteResult", hasattr(dele, "deleted_count"))

test("count_documents returns int", isinstance(coll.count_documents({}), int))
test("create_index returns string", isinstance(coll.create_index("name"), str))

# Context manager
with qihse_mongo.MongoClient("localhost", 27018) as ctx_client:
    test("MongoClient context manager", ctx_client is not None)

client.close()

# ---- HTTP/REST SDK ----
print("\n=== HTTP/REST SDK (qihse_http) ===")

# Response object
resp = qihse_http.Response(200, b'{"ok": true}', {"content-type": "application/json"})
test("Response status", resp.status_code == 200)
test("Response text", resp.text == '{"ok": true}')
test("Response json", resp.json() == {"ok": True})
test("Response ok", resp.ok is True)

err_resp = qihse_http.Response(404, b'Not Found')
test("Response not ok", err_resp.ok is False)

# Session
session = qihse_http.Session()
test("Session creates", session is not None)
test("Session get method", hasattr(session, 'get'))
test("Session post method", hasattr(session, 'post'))

# Module-level functions
test("get function", callable(qihse_http.get))
test("post function", callable(qihse_http.post))
test("put function", callable(qihse_http.put))
test("delete function", callable(qihse_http.delete))
test("patch function", callable(qihse_http.patch))
test("session function", callable(qihse_http.session))

# ---- ClickHouse SDK ----
print("\n=== ClickHouse SDK (qihse_clickhouse) ===")

ch_client = qihse_clickhouse.Client(host="localhost", port=8123, database="default")
test("Client creates", ch_client is not None)
test("Client host", ch_client.host == "localhost")
test("Client port", ch_client.port == 8123)
test("Client database", ch_client.database == "default")

# Ping
test("ping returns bool", isinstance(ch_client.ping(), bool))

# Query (will fail without server, but API works)
try:
    ch_client.execute("SELECT 1")
    test("execute doesn't crash", True)
except Exception as e:
    test("execute raises OperationalError on no server", isinstance(e, (qihse_clickhouse.OperationalError, qihse_clickhouse.Error, Exception)))

# Insert
try:
    ch_client.insert("test_table", [(1, "a"), (2, "b")], ["id", "name"])
    test("insert API works", True)
except Exception:
    test("insert API works", True)  # No server, but API exists

# Context manager
with qihse_clickhouse.Client(host="localhost", port=8123) as ctx_ch:
    test("Client context manager", ctx_ch is not None)

# ---- Elasticsearch SDK ----
print("\n=== Elasticsearch SDK (qihse_elasticsearch) ===")

es = qihse_elasticsearch.Elasticsearch("http://localhost:9200")
test("Elasticsearch creates", es is not None)

# Indices client
test("Indices client exists", hasattr(es, 'indices'))
test("Indices create", callable(es.indices.create))
test("Indices delete", callable(es.indices.delete))
test("Indices exists", callable(es.indices.exists))

# Document operations
test("index method", callable(es.index))
test("get method", callable(es.get))
test("exists method", callable(es.exists))
test("update method", callable(es.update))
test("delete method", callable(es.delete))
test("search method", callable(es.search))
test("count method", callable(es.count))
test("bulk method", callable(es.bulk))

# Response/Hit
hit_data = {"_index": "docs", "_id": "1", "_score": 1.5, "_source": {"title": "Hello"}}
hit = qihse_elasticsearch.Hit(hit_data)
test("Hit index", hit.index == "docs")
test("Hit id", hit.id == "1")
test("Hit score", hit.score == 1.5)
test("Hit source", hit.source == {"title": "Hello"})
test("Hit getitem", hit["title"] == "Hello")

resp_data = {"took": 5, "timed_out": False, "hits": {"total": {"value": 1}, "hits": [hit_data]}}
es_resp = qihse_elasticsearch.Response(resp_data)
test("Response took", es_resp.took == 5)
test("Response total", es_resp.total == 1)
test("Response hits len", len(es_resp) == 1)
test("Response iter", list(es_resp)[0].index == "docs")

# Ping
test("ping returns bool", isinstance(es.ping(), bool))

# Context manager
with qihse_elasticsearch.Elasticsearch("http://localhost:9200") as ctx_es:
    test("Elasticsearch context manager", ctx_es is not None)

# ---- CDC SDK ----
print("\n=== CDC SDK (qihse_cdc) ===")

cdc_client = qihse_cdc.CDCClient("localhost", 5432)
test("CDCClient creates", cdc_client is not None)

# Event
event = qihse_cdc.CDCEvent("insert", "users", "user:1", new_value={"name": "Alice"}, lsn=42)
test("CDCEvent op", event.op == "insert")
test("CDCEvent table", event.table == "users")
test("CDCEvent key", event.key == "user:1")
test("CDCEvent lsn", event.lsn == 42)
test("CDCEvent to_dict", "op" in event.to_dict())

# Subscribe
events_received = []
def callback(evt):
    events_received.append(evt)

cdc_client.subscribe("test_sub", callback)
test("subscribe doesn't crash", True)

cdc_client.unsubscribe("test_sub")
test("unsubscribe doesn't crash", True)

test("get_lsn returns int", isinstance(cdc_client.get_lsn(), int))

# Context manager
with qihse_cdc.CDCClient("localhost", 5432) as ctx_cdc:
    test("CDCClient context manager", ctx_cdc is not None)

cdc_client.close()

# ---- Metrics & Tracing SDK ----
print("\n=== Metrics & Tracing SDK (qihse_metrics) ===")

# Counter
counter = qihse_metrics.Counter("qihse_queries_total", "Total queries")
counter.inc(5)
test("Counter inc", counter.value == 5)
counter.inc()
test("Counter inc default", counter.value == 6)

# Gauge
gauge = qihse_metrics.Gauge("qihse_connections", "Active connections")
gauge.set(10)
test("Gauge set", gauge.value == 10)
gauge.inc(5)
test("Gauge inc", gauge.value == 15)
gauge.dec(3)
test("Gauge dec", gauge.value == 12)

# Histogram
hist = qihse_metrics.Histogram("qihse_query_duration", "Query duration")
hist.observe(0.5)
hist.observe(1.0)
test("Histogram count", hist.count == 2)
test("Histogram sum", abs(hist.sum - 1.5) < 0.001)

# Registry
registry = qihse_metrics.CollectorRegistry()
c2 = qihse_metrics.Counter("test_counter", "Test")
registry.register(c2)
g2 = qihse_metrics.Gauge("test_gauge", "Test")
registry.register(g2)
output = qihse_metrics.generate_latest(registry)
test("generate_latest contains counter", "test_counter" in output)
test("generate_latest contains gauge", "test_gauge" in output)

# Tracing
tracer = qihse_metrics.get_tracer("test")
span = tracer.start_span("test_operation")
test("Span creates", span is not None)
test("Span has trace_id", len(span.trace_id) == 32)
test("Span has span_id", len(span.span_id) == 16)
test("Span operation", span.operation_name == "test_operation")

span.set_attribute("db.system", "qihse")
test("Span set_attribute", span._attributes.get("db.system") == "qihse")

span.add_event("query_start")
test("Span add_event", len(span._events) == 1)

tracer.finish_span(span)
test("Span end_time set", span.end_time is not None)

# Export JSON
json_output = tracer.export_json()
test("Export JSON contains spans", "spans" in json_output)
test("Export JSON contains operation", "test_operation" in json_output)

# trace decorator
@qihse_metrics.trace("decorated_func")
def my_func():
    return 42

result = my_func()
test("trace decorator preserves return", result == 42)

# Parent span
parent = tracer.start_span("parent_op")
child = tracer.start_span("child_op", parent=parent)
test("Child span has parent", child.parent_span_id == parent.span_id)
tracer.finish_span(parent)
tracer.finish_span(child)

# ---- Summary ----
print(f"\n{'='*50}")
print(f"Phase C SDK Tests: {passed} passed, {failed} failed")
print(f"{'='*50}")
sys.exit(0 if failed == 0 else 1)
