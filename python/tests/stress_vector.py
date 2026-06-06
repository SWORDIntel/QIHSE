import os
import sys
import time
import numpy as np
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qihse.core import VectorDB, DistanceMetric

def generate_sift1m_synthetic():
    print("Generating synthetic SIFT1M data (1,000,000 vectors, 128-dim)...")
    np.random.seed(42)
    # 1 million vectors, 128 dimensions, typically float or int8. SIFT uses 0-255 but let's use normalized float
    data = np.random.rand(10000, 128).astype(np.float32)
    
    # Generate queries (1000 vectors)
    queries = np.random.rand(1000, 128).astype(np.float32)
    
    return data, queries

def main():
    db_path = "stress_sift1m_test.db"
    
    import shutil
    # Cleanup old DB
    if os.path.exists(db_path):
        try:
            if os.path.isdir(db_path):
                shutil.rmtree(db_path)
            else:
                os.remove(db_path)
            for sidecar in ["_data", "_graph", "_metadata"]:
                sidecar_path = db_path + sidecar
                if os.path.exists(sidecar_path):
                    if os.path.isdir(sidecar_path):
                        shutil.rmtree(sidecar_path)
                    else:
                        os.remove(sidecar_path)
        except Exception:
            pass

    # 1. Generate data
    data, queries = generate_sift1m_synthetic()
    
    num_vectors = data.shape[0]
    dims = data.shape[1]
    num_queries = queries.shape[0]

    db = VectorDB.create(db_path, dims)
    
    # 2. Insert vectors in batches
    batch_size = 10000
    num_batches = num_vectors // batch_size
    
    print(f"Inserting {num_vectors} vectors in {num_batches} batches of {batch_size}...")
    start_time = time.time()
    
    for i in range(num_batches):
        start_idx = i * batch_size
        end_idx = start_idx + batch_size
        batch = data[start_idx:end_idx]
        ids = list(range(start_idx, end_idx))
        db.add_vectors(batch, ids=ids)
        if (i + 1) % 2 == 0:
            print(f"  Inserted {end_idx} vectors...")
            
    insert_time = time.time() - start_time
    print(f"Insertion complete. Time: {insert_time:.2f} s")
    
    # 3. Build graph
    print("Building graph...")
    start_time = time.time()
    db.build_graph(M=16, ef_construction=200)
    build_time = time.time() - start_time
    print(f"Graph build complete. Time: {build_time:.2f} s")
    
    db.flush()
    
    # 4. Perform multi-threaded queries
    print("Running multi-threaded queries to test GIL release & concurrency...")
    
    def run_query(q_vec):
        return db.search(q_vec, k=10)

    # Use ThreadPoolExecutor to run queries
    num_workers = min(16, os.cpu_count() or 4)
    print(f"Using {num_workers} threads for queries...")
    
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        # submit all queries
        futures = [executor.submit(run_query, q) for q in queries]
        # Wait for all to complete
        for _ in concurrent.futures.as_completed(futures):
            pass

    query_time = time.time() - start_time
    qps = num_queries / query_time
    
    print("--------------------------------------------------")
    print("Stress Test Results")
    print("--------------------------------------------------")
    print(f"Dataset Size : {num_vectors} vectors, {dims} dims")
    print(f"Total Queries: {num_queries}")
    print(f"Insert Time  : {insert_time:.2f} s")
    print(f"Build Time   : {build_time:.2f} s")
    print(f"Query Time   : {query_time:.2f} s")
    print(f"QPS          : {qps:.2f} queries/sec")
    print("--------------------------------------------------")

    db.close()
    
    # Cleanup
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            for sidecar in ["_data", "_graph", "_metadata"]:
                if os.path.exists(db_path + sidecar):
                    os.remove(db_path + sidecar)
        except Exception:
            pass

if __name__ == "__main__":
    main()
