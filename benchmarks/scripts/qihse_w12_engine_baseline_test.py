#!/usr/bin/env python3
"""Focused format and oracle checks for the W12.0 full-engine driver."""
import array
from pathlib import Path
import struct
import tempfile
import unittest

import qihse_w12_engine_baseline as engine


class EngineBaselineTest(unittest.TestCase):
    def test_fixture_binary_is_exact_and_bounded(self):
        vectors = array.array("f", [1.0, -2.0, 3.0, 4.0])
        queries = [array.array("f", [-1.0, 2.0])]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.bin"
            engine.write_fixture(path, vectors, queries, 2, 2)
            data = path.read_bytes()
        self.assertEqual(struct.unpack("<4I", data[:16]), (0x57313230, 2, 2, 1))
        self.assertEqual(data[16:], struct.pack("<6f", 1, -2, 3, 4, -1, 2))

    def test_probe_parser_rejects_missing_rows_and_duplicate_ids(self):
        valid = ("Q,0,0,0,0,100,2,1,0.5,2,0.25\n"
                 "Q,0,1,0,0,200,2,2,0.5,1,0.25\n"
                 "Q,0,2,0,0,300,2,1,0.5,2,0.25\n"
                 "S,0,1,16,0,0\n")
        samples, rows, _, stats = engine.parse_probe(valid, 0, 1, 1, 2)
        self.assertEqual(samples[1], [200])
        self.assertEqual(rows[1][0], [2, 1])
        self.assertEqual(stats["fp32_resident_bytes"], 16)
        with self.assertRaises(ValueError):
            engine.parse_probe(valid.replace("2,0.25", "1,0.25", 1), 0, 1, 1, 2)
        with self.assertRaises(ValueError):
            engine.parse_probe(valid.splitlines()[0] + "\nS,0,1,16,0,0\n", 0, 1, 1, 2)


if __name__ == "__main__":
    unittest.main()
