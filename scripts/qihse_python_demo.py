import sys
import time
import qihse

def run_demo():
    print("==============================================")
    print(" QIHSE Python SDK Demonstration")
    print("==============================================")
    
    # 1. Initialize the Database Environment
    print("[*] Initializing QIHSE Database Instance...")
    db = qihse.QihseDB()
    print("    -> Database initialized successfully.")
    
    # 2. Key-Value Store Testing
    print("\n[*] Testing Key-Value Store...")
    db.kv_set("target_alpha", "192.168.1.100")
    db.kv_set("target_beta", "10.0.0.55")
    
    res = db.kv_get("target_alpha")
    print(f"    -> Retrived 'target_alpha': {res}")
    
    # 3. Document Store Testing
    print("\n[*] Testing JSON Document Store...")
    db.doc_insert(1001, '{"operation": "TREADSTONE", "status": "active"}')
    db.doc_insert(1002, '{"operation": "BLACKBRIAR", "status": "terminated"}')
    print("    -> Documents inserted.")
    
    # 4. Columnar Store Testing
    print("\n[*] Testing Columnar Engine...")
    db.col_create("temperature_sensor")
    db.col_append("temperature_sensor", 98.6)
    db.col_append("temperature_sensor", 101.2)
    print("    -> Float columns appended.")
    
    # 5. Time-Series Testing
    print("\n[*] Testing Time-Series DB...")
    db.tsdb_insert(1, int(time.time()), 3.14159)
    print("    -> Time-series datapoint recorded.")
    
    # 6. Auth Testing
    print("\n[*] Testing Auth Subsystem (CNSA 2.0)...")
    # Creator 0 (God-Mode), Target 42, Role 1, Clearance 5, SCI 1
    db.auth_create_user(0, 42, 1, 5, 1)
    
    # Check access for user 42 against required Clearance 3, SCI 1
    can_access = db.auth_can_access(42, 3, 1)
    print(f"    -> User 42 access to Level 3 data: {can_access}")
    
    # 7. Wire Proxies
    print("\n[*] Starting Background Wire Proxies...")
    db.start_resp_proxy("127.0.0.1", 6380)
    db.start_pg_proxy("127.0.0.1", 5433)
    print("    -> Redis (RESP) Proxy started on port 6380")
    print("    -> PostgreSQL Proxy started on port 5433")
    
    print("\n==============================================")
    print(" All systems GO. The Python SDK is fully operational.")
    print("==============================================\n")

if __name__ == "__main__":
    run_demo()
