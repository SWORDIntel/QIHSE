"""RESP resource-bound checks shared by CLI and MCP readers."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recall import _Reader


class ChunkedSocket:
    def __init__(self, payload, chunk=13):
        self.buffer = bytearray(payload)
        self.chunk = chunk

    def recv(self, size):
        if not self.buffer:
            return b""
        end = min(len(self.buffer), min(size, self.chunk))
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result


class RespTests(unittest.TestCase):
    def test_7_field_memory_record(self):
        raw = b"*1\r\n*7\r\n" + b"$2\r\nid\r\n:123\r\n:1\r\n:0\r\n:0\r\n" + b"$3\r\n0.5\r\n$4\r\ntext\r\n"
        rows = _Reader(ChunkedSocket(raw, chunk=1)).value()
        self.assertEqual(rows, [["id", 123, 1, 0, 0, "0.5", "text"]])

    def test_refuses_oversized_bulk(self):
        with self.assertRaises(RuntimeError):
            _Reader(ChunkedSocket(b"$999999999\r\n")).value()

    def test_refuses_oversized_array(self):
        with self.assertRaises(RuntimeError):
            _Reader(ChunkedSocket(b"*999999\r\n")).value()

    def test_refuses_unterminated_header(self):
        with self.assertRaises(RuntimeError):
            _Reader(ChunkedSocket(b"A" * 70000)).value()

    def test_rejects_bad_bulk_terminator(self):
        with self.assertRaises(RuntimeError):
            _Reader(ChunkedSocket(b"$4\r\ntext!!")).value()

    def test_qihse_error_is_raised(self):
        with self.assertRaises(RuntimeError):
            _Reader(ChunkedSocket(b"-NOPERM\r\n")).value()


if __name__ == "__main__":
    unittest.main()
