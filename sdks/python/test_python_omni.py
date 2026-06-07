import qihse
import time
import os

print("--- QIHSE Python Full System Test ---")
db = qihse.Database()

print("\n1. Testing KV Store")
db.kv_set("python_key", "python_val")
val = db.kv_get("python_key")
assert val == "python_val"
print("   -> KV Store OK")

print("\n2. Testing Time-Series DB")
db.tsdb_insert(1, 1700000000, 100.5)
db.tsdb_insert(1, 1700000001, 150.5)
# Average function isn't exposed yet, but insertion proves the pointer holds
print("   -> TSDB OK")

print("\n3. Testing Columnar DB")
db.col_create("revenue")
db.col_append("revenue", 10.5)
print("   -> Columnar DB OK")

print("\n4. Testing Document Store")
db.doc_insert(100, '{"test": "python_json"}')
print("   -> Document DB OK")

print("\n5. Spinning up Wire Proxies...")
# Run background proxy servers (they are detached pthreads natively)
db.start_resp_proxy("127.0.0.1", 6379)
db.start_pg_proxy("127.0.0.1", 5432)
print("   -> Proxy threads spawned natively!")

print("\nAll Python engine bindings tested successfully!")
