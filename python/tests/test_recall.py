import sys
import os
import time
import ctypes
import numpy as np
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from qihse.core import VectorDB

def test_recall():
    print("Generating random dataset...")
    num_vectors = 5000
    dims = 128
    
    np.random.seed(42)
    vectors = np.random.randn(num_vectors, dims).astype(np.float32)
    
    db_path = "test_recall_db"
    if os.path.exists(db_path):
        import shutil
        shutil.rmtree(db_path, ignore_errors=True)
    
    db = VectorDB.create(db_path, dims)
    
    # Insert vectors
    print("Inserting 5000 vectors...")
    ids = list(range(num_vectors))
    db.add_vectors(vectors, ids=ids)
    
    print("Building HNSW graph (M=16, ef_construction=200)...")
    db.build_graph(M=16, ef_construction=200)
    
    num_queries = 200
    queries = np.random.randn(num_queries, dims).astype(np.float32)
    
    print("Running brute-force and HNSW queries to compute Recall@10...")
    k = 10
    total_recall = 0.0
    
    start_time = time.time()
    for idx, q in enumerate(queries):
        # Brute force (numpy) - using euclidean distance (L2 squared)
        diff = vectors - q
        distances = np.sum(diff**2, axis=1)
        ground_truth_indices = np.argsort(distances)[:k]
        
        # HNSW search
        from qihse.core import DistanceMetric
        results = db.search(q, k=k, metric=DistanceMetric.EUCLIDEAN)
        
        if not results:
            # print("Warning: HNSW returned no results!")
            continue
            
        hnsw_indices = [r.id for r in results]
        
        # Compute intersection
        intersection = set(ground_truth_indices).intersection(set(hnsw_indices))
        if idx == 0:
            print(f"Query 0:")
            print(f"  Ground truth: {ground_truth_indices}")
            print(f"  GT dists:     {distances[ground_truth_indices]}")
            print(f"  HNSW:         {hnsw_indices}")
            print(f"  HNSW dists:   {[1.0/r.score - 1.0 for r in results]}")
            print(f"  Intersection: {len(intersection)}")
            
        recall = len(intersection) / k
        total_recall += recall
        
    end_time = time.time()
    
    avg_recall = total_recall / num_queries
    avg_latency = (end_time - start_time) / num_queries * 1000  # ms
    
    print("-" * 50)
    print(f"Recall@10: {avg_recall:.4f}")
    print(f"Avg Query Latency: {avg_latency:.2f} ms")
    print("-" * 50)
    
    if avg_recall < 0.8:
        print("Warning: Recall is below 0.80. HNSW tuning or wiring check may be needed.")

if __name__ == "__main__":
    test_recall()
