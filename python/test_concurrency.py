import os
import sys
import shutil
import numpy as np
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'qihse')))
from core import VectorDB, DistanceMetric, VectorQuery

def main():
    # Remove old DB if exists
    shutil.rmtree("test_db_concurrency", ignore_errors=True)
    os.makedirs("test_db_concurrency", exist_ok=True)
    
    db = VectorDB.create("test_db_concurrency", dims=128)
    
    def writer_thread():
        for i in range(1000):
            try:
                vecs = np.random.rand(10, 128).astype(np.float32)
                db.add_vectors(vecs)
            except Exception as e:
                pass

    def reader_thread():
        for i in range(1000):
            try:
                q = np.random.rand(128).astype(np.float32)
                db.search(q, k=10)
            except Exception as e:
                pass

    threads = []
    print("Starting writer threads...")
    for _ in range(20):
        t = threading.Thread(target=writer_thread)
        t.start()
        threads.append(t)

    print("Starting reader threads...")
    for _ in range(20):
        t = threading.Thread(target=reader_thread)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("Finished successfully without segfault! (Unexpected)")

if __name__ == "__main__":
    main()
