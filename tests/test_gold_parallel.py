"""Gold-pack partition and oracle-evidence regression tests."""

import io
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

from run_gold_parallel import ROOT, GOLD_SAFE, independent, read_pack, report

PACK = Path("tests/gold/pack.v1.gold")


class GoldParallelTests(unittest.TestCase):
    def test_complete_pack_is_partitioned_without_loss(self):
        areas, workloads, gaps = read_pack((ROOT / PACK).read_text())
        self.assertEqual(len(areas), 11)
        self.assertEqual(len(workloads), 72)
        self.assertEqual(gaps, [])
        self.assertEqual(len({w[0] for w in workloads}), len(workloads))
        self.assertTrue(GOLD_SAFE.issubset({w[0] for w in workloads}))
        fast = [w for w in workloads if independent(w)]
        slow = [w for w in workloads if not independent(w)]
        self.assertGreater(len(fast), 10)
        self.assertEqual(len(fast) + len(slow), len(workloads))
        self.assertTrue(any(w[0] == "cluster-loadshift-smoke" for w in slow))

    def test_unknown_workload_is_serial(self):
        unknown = ("new-unknown", {"run": "make -s test-new-unknown"}, "")
        self.assertFalse(independent(unknown))

    def test_missing_or_duplicate_workload_is_rejected(self):
        with self.assertRaises(ValueError):
            read_pack('area a "area"\n')
        with self.assertRaises(ValueError):
            read_pack('area a "area"\nworkload a area=a run="true"\n'
                      'workload a area=a run="true"\n')

    def test_exit_zero_without_gold_pass_evidence_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.log"
            path.write_text("successful but no workload result\n")
            output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            with redirect_stdout(output):
                self.assertTrue(report(("unverified", 0, 0.01, path)))
            output.close()


if __name__ == "__main__":
    unittest.main()
