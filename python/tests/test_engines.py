import unittest
import tempfile
import os
import shutil
import threading
import time
import subprocess
import numpy as np

from qihse.kv import KVStore
from qihse.core import VectorDB, DistanceMetric, _lib
from qihse.document import DocumentStore
from qihse.timeseries import TimeSeriesDB
from qihse.uwp import UWPServer

class TestQIHSEEngines(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_kv_store(self):
        with KVStore() as kv:
            kv.delete("key1")
            kv.delete("key2")
            # Test set/get
            self.assertTrue(kv.set("key1", "value1"))
            self.assertEqual(kv.get("key1"), "value1")
            
            # Test exists
            self.assertTrue(kv.exists("key1"))
            self.assertFalse(kv.exists("key2"))
            
            # Test delete
            self.assertTrue(kv.delete("key1"))
            self.assertFalse(kv.exists("key1"))
            self.assertIsNone(kv.get("key1"))
            
            # Test expire
            self.assertTrue(kv.set("key2", "value2"))
            self.assertTrue(kv.expire("key2", 50)) # 50ms
            time.sleep(0.1)
            self.assertFalse(kv.exists("key2"))

            # Test save/load
            save_path = os.path.join(self.temp_dir, "kv.dat")
            self.assertTrue(kv.set("save_key", "save_val"))
            self.assertTrue(kv.save(save_path))
        
        with KVStore() as kv2:
            self.assertTrue(kv2.load(save_path))
            self.assertEqual(kv2.get("save_key"), "save_val")

    def test_vector_db(self):
        db_path = os.path.join(self.temp_dir, "vectors.db")
        with VectorDB.create(db_path, dims=128) as vdb:
            # Add vectors
            vecs = np.random.rand(10, 128).astype(np.float32)
            ids = list(range(10))
            metadata = [f"meta_{i}".encode('utf-8') for i in range(10)]
            
            vdb.add_vectors(vecs, ids=ids, metadata=metadata)
            vdb.build_graph()
            vdb.flush()
            
            # Search
            query_vec = vecs[0]
            results = vdb.search(query_vec, k=5, metric=DistanceMetric.EUCLIDEAN)
            self.assertGreater(len(results), 0)
            self.assertEqual(results[0].id, 0)
            
        # Test open existing
        with VectorDB.open(db_path, read_only=True) as vdb2:
            self.assertEqual(vdb2.dims, 128)
            results = vdb2.search(vecs[1], k=5)
            self.assertGreater(len(results), 0)
            self.assertEqual(results[0].id, 1)

    def test_timeseries_db(self):
        with TimeSeriesDB() as tsdb:
            ts = int(time.time() * 1000)
            self.assertTrue(tsdb.insert(series_id=1, timestamp=ts, value=10.5))
            self.assertTrue(tsdb.insert(series_id=1, timestamp=ts+1000, value=20.5))
            
            tsdb.flush()
            
            avg = tsdb.average_range(ts - 1000, ts + 2000)
            self.assertEqual(avg, 15.5)

    def test_document_store(self):
        with KVStore() as kv:
            with DocumentStore(kv) as doc_store:
                self.assertTrue(doc_store.insert_json(1, '{"name": "test"}'))
                self.assertTrue(doc_store.insert_json(2, '{"value": 42}'))

    def test_uwp_server(self):
        # Bootstrap operator password away from default
        _lib.qihse_auth_bootstrap_operator(b"TestOperatorPass123!")

        # Generate temporary TLS certificate for testing
        cert_file = os.path.join(self.temp_dir, "test_cert.pem")
        key_file = os.path.join(self.temp_dir, "test_key.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key_file, "-out", cert_file,
             "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        def run_server():
            with KVStore() as kv:
                UWPServer.start(port=18472, bind_address="127.0.0.1", kv=kv,
                                tls_cert=cert_file, tls_key=key_file)
                
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Just give it a moment to initialize and ensure it didn't immediately crash
        time.sleep(0.5)
        self.assertTrue(server_thread.is_alive())

if __name__ == '__main__':
    unittest.main()
