"""W12 synthetic harness tests. Not engine security or integration coverage."""
import array
import importlib.util
import json
import math
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "baseline", ROOT / "benchmarks/scripts/qihse_w12_fp32_baseline.py")
b = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(b)


class BaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="w12-")
        library = Path(cls.tmp.name) / "kernels.so"
        cls.build = b.compile_library(library, sanitize=True)
        cls.kernel = b.Kernel(library)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_known_scores_and_negative_results(self):
        vectors = [1, 0, 0, 1, -1, 0, 0, 0]
        prepared = self.kernel.prepare(vectors, [[1, 0]], [1]*4, 2, 4)
        for metric in b.METRICS:
            expected = b.oracle(vectors, [1, 0], [1]*4, 2, 4, metric)
            for dispatched in (False, True):
                ids, scores, _, scored = prepared.run(0, metric, dispatched)
                self.assertEqual(ids, [row for row, _ in expected])
                self.assertEqual(scored, 4)
                for score, (_, truth) in zip(scores, expected):
                    self.assertAlmostEqual(score, truth, places=6)
        self.assertEqual(prepared.run(0, "dot", False)[1][-1], -1)

    def test_ties_keep_physical_row_order(self):
        p = self.kernel.prepare([1, 1, 1, 1, 1], [[1]], [1]*5, 1, 3)
        for dispatched in (False, True):
            self.assertEqual(p.run(0, "cosine", dispatched)[0], [0, 1, 2])

    def test_selection_precedes_scoring_and_validation(self):
        base = self.kernel.prepare([1, 2], [[1]], [1, 1], 1, 2)
        hidden = self.kernel.prepare([1, 2, math.nan, math.inf, 1e30], [[1]], [1, 1, 0, 0, 0], 1, 2)
        for metric in b.METRICS:
            for dispatched in (False, True):
                expected = base.run(0, metric, dispatched)
                actual = hidden.run(0, metric, dispatched)
                self.assertEqual(actual[:2], expected[:2])
                self.assertEqual(actual[3], 2)
        self.assertEqual(b.oracle([1, 2, math.nan], [1], [1, 1, 0], 1, 2, "dot"), [(1, 2), (0, 1)])

    def test_empty_selection_and_zero_norm(self):
        p = self.kernel.prepare([0, 0, 1, 0], [[0, 0]], [1, 1], 2, 2)
        self.assertEqual(p.run(0, "cosine", False)[:2], ([0, 1], [0, 0]))
        p = self.kernel.prepare([1, 2], [[1]], [0, 0], 1, 2)
        self.assertEqual(p.run(0, "dot", True)[:2], ([], []))
        self.assertEqual(b.recall([], []), 1)

    def test_nonfinite_and_overflow(self):
        for value in (math.nan, math.inf, -math.inf):
            p = self.kernel.prepare([value], [[1]], [1], 1, 1)
            with self.assertRaises(ValueError):
                p.run(0, "dot", False)
            p = self.kernel.prepare([1], [[value]], [1], 1, 1)
            with self.assertRaises(ValueError):
                p.run(0, "dot", False)
        p = self.kernel.prepare([3e38, 3e38], [[3e38, 3e38]], [1], 2, 1)
        with self.assertRaises(ValueError):
            p.run(0, "dot", False)

    def test_raw_l2_overflow_does_not_silently_change_ranking(self):
        p = self.kernel.prepare([2e20, 0, 1e20, 0], [[0, 0]], [1, 1], 2, 1)
        for dispatched in (False, True):
            with self.assertRaises(ValueError):
                p.run(0, "l2", dispatched)
        self.assertEqual(b.oracle([2e20, 0, 1e20, 0], [0, 0], [1, 1], 2, 1, "l2")[0][0], 1)

    def test_shapes_and_metric_validation(self):
        for args in (([1], [[1]], [1], 2, 1), ([1], [[1]], [1], 1, 2),
                     ([1], [[1, 2]], [1], 1, 1)):
            with self.assertRaises(ValueError):
                self.kernel.prepare(*args)
        with self.assertRaises(ValueError):
            b.oracle([1], [1], [1], 1, 1, "unknown")

    def test_generated_fixtures_are_exactly_reproducible(self):
        for corpus in b.CORPORA:
            a = b.fixture(24, 17, 3, 123, corpus)
            c = b.fixture(24, 17, 3, 123, corpus)
            self.assertEqual(b.fixture_hash(*a), b.fixture_hash(*c))
            self.assertTrue(all(math.isfinite(v) for v in a[0]))
        a = b.fixture(24, 17, 3, 123, "isotropic")
        c = b.fixture(24, 17, 3, 124, "isotropic")
        self.assertNotEqual(b.fixture_hash(*a), b.fixture_hash(*c))
        self.assertEqual(a[0].itemsize, 4)

    def test_all_corpora_and_odd_simd_tail_dimensions(self):
        for corpus in b.CORPORA:
            vectors, queries, mask = b.fixture(19, 33, 2, 456, corpus)
            p = self.kernel.prepare(vectors, queries, mask, 33, 7)
            for metric in b.METRICS:
                for qi, query in enumerate(queries):
                    truth = b.oracle(vectors, query, mask, 33, 7, metric)
                    for dispatched in (False, True):
                        ids, scores, _, scored = p.run(qi, metric, dispatched)
                        self.assertEqual(scored, 19)
                        self.assertEqual(ids, [row for row, _ in truth])
                        for score, (_, expected) in zip(scores, truth):
                            self.assertLessEqual(abs(score-expected), 2e-5 * max(1, abs(expected)))

    def test_recall_and_statistics(self):
        self.assertEqual(b.recall([0, 0, 1], [0, 2]), .5)
        result = b.statistics_ns([10, 20, 30, 40])
        self.assertEqual(result["p50_ns"], 20)
        self.assertEqual(result["p95_ns"], 40)
        self.assertEqual(result["queries_per_second"], 4e7)
        self.assertIsNone(b.statistics_ns([1])["mean_95pct_normal_ci_ns"])

    def test_report_preserves_limits_and_raw_measurements(self):
        result = b.benchmark(self.kernel, 19, 17, 2, 5, 789, "clustered", 2)
        self.assertEqual(result["vector_payload_bytes"], 19 * 17 * 4)
        self.assertIsNone(result["engine_resident_bytes"])
        self.assertIsNone(result["sidecar_disk_bytes"])
        self.assertEqual(len(result["results"]), 6)
        for row in result["results"]:
            self.assertEqual(len(row["samples_ns"]), 4)
            self.assertEqual(row["candidate_pool"], 19)
            self.assertEqual(len(row["result_rows"]), 2)
        json.dumps(result, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
