import unittest
import numpy as np
import os
import shutil
import tempfile

import qihse

class TestQihseKeystoneSDK(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_hardware_profiler(self):
        hw = qihse.HardwareProfiler.get_profile()
        self.assertIsNotNone(hw.preferred_backend)
        self.assertGreater(hw.cache_line_bytes, 0)
        self.assertGreater(hw.l1_kb, 0)
        print(f"\n[SDK HW Profile] Backend: {hw.preferred_backend} | AVX={hw.avx} | AVX2={hw.avx2} | L1={hw.l1_kb}KB | L2={hw.l2_kb}KB | L3={hw.l3_mb:.1f}MB")

    def test_neural_classifier(self):
        cls, name, conf = qihse.NeuralClassifier.classify("auth_failure admin@pentagon.af.mil classified=TOPSECRET_007")
        self.assertIsInstance(cls, qihse.KeystoneClass)
        self.assertIsInstance(name, str)
        self.assertGreater(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

        cls2, name2, conf2 = qihse.NeuralClassifier.classify("billing_portal corporate_login invoices payment_id=98823")
        self.assertIsInstance(cls2, qihse.KeystoneClass)
        self.assertGreater(conf2, 0.0)

    def test_anchor_index(self):
        arr = np.array([10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000], dtype=np.int64)
        
        idx = qihse.AnchorIndex.lower_bound(arr, 50)
        self.assertEqual(idx, 2)

        idx = qihse.AnchorIndex.lower_bound(arr, 51)
        self.assertEqual(idx, 3)

        hit = qihse.AnchorIndex.search(arr, 100)
        self.assertEqual(hit, 3)

        miss = qihse.AnchorIndex.search(arr, 101)
        self.assertEqual(miss, -1)

    def test_fts_index(self):
        with qihse.FTSIndex() as fts:
            fts.add_document(1, "pentagon classified defense network asset", semantic_class=qihse.KeystoneClass.GOVERNMENT)
            fts.add_document(2, "corporate billing payment gateway transaction", semantic_class=qihse.KeystoneClass.CORPORATE)
            fts.add_document(3, "consumer free trial discount coupon code", semantic_class=qihse.KeystoneClass.CONSUMER)

            # Unfiltered query
            results = fts.search("defense network", top_k=5)
            self.assertGreaterEqual(len(results), 1)
            self.assertEqual(results[0].doc_id, 1)
            self.assertEqual(results[0].semantic_class, qihse.KeystoneClass.GOVERNMENT)

            # Filtered by semantic class mask (allow only CONSUMER)
            mask = 1 << qihse.KeystoneClass.CONSUMER
            filtered = fts.search("defense network", top_k=5, semantic_mask=mask)
            self.assertEqual(len(filtered), 0)

            # Query consumer
            res_consumer = fts.search("coupon code discount", top_k=5, semantic_mask=mask)
            self.assertGreaterEqual(len(res_consumer), 1)
            self.assertEqual(res_consumer[0].doc_id, 3)

    def test_multimodal_fusion(self):
        with qihse.FTSIndex() as fts:
            fts.add_document(1, "stealer log leak pentagon credential alert", semantic_class=qihse.KeystoneClass.GOVERNMENT)
            fts.add_document(2, "regular login corporate portal", semantic_class=qihse.KeystoneClass.CORPORATE)

            db_path = os.path.join(self.temp_dir, "fusion.db")
            with qihse.VectorDB.create(db_path, dims=4) as vdb:
                vecs = np.array([
                    [1.0, 0.0, 0.0, 0.0],
                    [0.0, 1.0, 0.0, 0.0],
                ], dtype=np.float32)
                vdb.add_vectors(vecs, ids=[1, 2])

                qvec = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32)
                fused = qihse.MultimodalFusion.search(
                    vector_db=vdb,
                    vector_queries=[{"vector": qvec, "modality": "text", "weight": 1.0}],
                    top_k=5,
                    fts_index=fts,
                    fts_query="stealer leak alert",
                    fts_weight=1.0,
                    semantic_mask=(1 << qihse.KeystoneClass.GOVERNMENT),
                )

                self.assertGreaterEqual(len(fused), 1)
                self.assertEqual(fused[0].id, 1)
                self.assertEqual(fused[0].semantic_class, qihse.KeystoneClass.GOVERNMENT)


if __name__ == "__main__":
    unittest.main()
