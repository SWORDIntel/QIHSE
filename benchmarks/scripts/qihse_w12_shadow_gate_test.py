#!/usr/bin/env python3
"""Policy and wire-format checks for the offline W12.6 shadow gate."""
import unittest

import qihse_w12_shadow_gate as gate


class ShadowGateTest(unittest.TestCase):
    def test_parser_and_refusal(self):
        line = "META,3,3,479,24,3\n"
        line += "SIDE_NS," + ",".join(["100"] * 15) + "\n"
        line += "EXACT_NS," + ",".join(["50"] * 15) + "\n"
        metrics = gate.parse_probe(line)
        self.assertEqual(metrics["recall_at_1"], 1.0)
        self.assertEqual(metrics["total_fp32_plus_sidecar_bytes"], 503)
        self.assertAlmostEqual(metrics["fp32_plus_sidecar_overhead_ratio"], 503 / 24)
        self.assertIsNone(metrics["existing_index_bytes"])
        self.assertEqual(metrics["sidecar_p95_ns"], 100)
        result = gate.evaluate(metrics, gate.EVIDENCE_GATES)
        self.assertEqual(result["decision"], "refuse")
        self.assertFalse(result["deployment_changed"])
        self.assertIn("neither_throughput_nor_bytes_gate_met", result["reasons"])
        self.assertIn("missing_existing_index_baseline_for_bytes_path", result["reasons"])
        self.assertIn("missing_source_generation_transaction_fence", result["reasons"])

    def test_eligibility_never_changes_deployment(self):
        metrics = {
            "rollback_exact_verified": True,
            "recall_at_1": 1.0,
            "throughput_ratio_vs_exact": 2.0,
            "existing_index_bytes": 1000,
            "index_bytes_reduction_vs_existing": 0.5,
            "p95_latency_ratio_vs_exact": 2.0,
        }
        result = gate.evaluate(metrics, {key: True for key in gate.EVIDENCE_GATES})
        self.assertEqual(result["decision"], "promote_eligible_for_human_review")
        self.assertFalse(result["deployment_changed"])
        metrics["existing_index_bytes"] = None
        metrics["index_bytes_reduction_vs_existing"] = None
        self.assertEqual(
            gate.evaluate(metrics, {key: True for key in gate.EVIDENCE_GATES})["decision"],
            "promote_eligible_for_human_review",
        )
        metrics["rollback_exact_verified"] = False
        self.assertEqual(gate.evaluate(metrics, {})["decision"], "refuse")

    def test_parser_rejects_missing_samples(self):
        with self.assertRaises(ValueError):
            gate.parse_probe("META,1,3,100,24,3\nSIDE_NS,1\nEXACT_NS,1\n")


if __name__ == "__main__":
    unittest.main()
