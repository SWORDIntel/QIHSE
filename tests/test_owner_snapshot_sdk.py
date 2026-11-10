#!/usr/bin/env python3
"""Focused tests for bounded QKP OWNER.SNAPSHOT file streaming."""
from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdks/python"))

from qihse_admin import QihseAdminError, QKPAdminSession  # noqa: E402


def bulk(data: bytes) -> bytes:
    return b"$" + str(len(data)).encode() + b"\r\n" + data + b"\r\n"


def manifest(length: int, seq: int) -> bytes:
    return b"*2\r\n" + bulk(str(length).encode()) + bulk(str(seq).encode())


class FakeSession:
    def __init__(self, payload: bytes, *, short_at=None, begin_reply=None,
                 end_reply=b"+OK\r\n", begin_exception=None):
        self.payload = payload
        self.short_at = short_at
        self.begin_reply = begin_reply or manifest(len(payload), 9127)
        self.end_reply = end_reply
        self.begin_exception = begin_exception
        self.commands = []
        self.closed = False
        self.snapshot_active = False

    def execute_resp(self, *args):
        self.commands.append(args)
        if args[0] == "OWNER.SNAPSHOT.BEGIN":
            self.snapshot_active = True
            if self.begin_exception:
                raise self.begin_exception
            return self.begin_reply
        if args[0] == "OWNER.SNAPSHOT.READ":
            offset, length = int(args[1]), int(args[2])
            data = self.payload[offset:offset + length]
            if self.short_at == offset and data:
                data = data[:-1]
            return bulk(data)
        if args[0] == "OWNER.SNAPSHOT.END":
            return self.end_reply
        raise AssertionError(f"unexpected command: {args[0]}")

    def close(self):
        self.closed = True
        self.snapshot_active = False


def sdk_session(fake: FakeSession) -> QKPAdminSession:
    session = object.__new__(QKPAdminSession)
    session._client = ctypes.c_void_p(1)
    session.execute_resp = fake.execute_resp
    session.close = fake.close
    return session


class OwnerSnapshotSdkTests(unittest.TestCase):
    def test_inventory_streams_binary_chunks_and_publishes_atomically(self):
        payload = b"row\x00one\r\n\xffrow-two\n"
        fake = FakeSession(payload)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inventory.raw"
            result = sdk_session(fake).owner_inventory(target, chunk_size=5)
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(result, {
                "path": str(target), "mode": "inventory", "size": len(payload),
                "source_change_seq": 9127,
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
            self.assertEqual(fake.commands[0], ("OWNER.SNAPSHOT.BEGIN",))
            self.assertEqual(fake.commands[-1], ("OWNER.SNAPSHOT.END",))
            reads = [c for c in fake.commands if c[0] == "OWNER.SNAPSHOT.READ"]
            self.assertTrue(reads)
            self.assertTrue(all(int(c[2]) <= 5 for c in reads))
            self.assertEqual(sum(int(c[2]) for c in reads), len(payload))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).glob("*.partial")), [])

    def test_backup_mode_selects_self_describing_data_container(self):
        payload = b"BACKUP_OWNER_DATA\x00container"
        fake = FakeSession(payload)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "owner.qbk"
            result = sdk_session(fake).backup_owner_data(target, chunk_size=7)
            self.assertEqual(fake.commands[0],
                             ("OWNER.SNAPSHOT.BEGIN", "BACKUP"))
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(result["mode"], "backup")

    def test_short_chunk_preserves_existing_target_and_cleans_up(self):
        fake = FakeSession(b"payload-data", short_at=0)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inventory.raw"
            target.write_bytes(b"previous-complete-file")
            with self.assertRaisesRegex(QihseAdminError, "short chunk"):
                sdk_session(fake).owner_inventory(target, chunk_size=5)
            self.assertEqual(target.read_bytes(), b"previous-complete-file")
            self.assertEqual(fake.commands[-1], ("OWNER.SNAPSHOT.END",))
            self.assertEqual(list(Path(directory).glob(".*.partial")), [])

    def test_malformed_or_denied_begin_never_creates_output(self):
        oversized_manifest = (b"*2\r\n$21\r\n" + b"9" * 21 +
                              b"\r\n$1\r\n0\r\n")
        for reply in (b"*2\r\n$5\r\n12\r\n", oversized_manifest,
                      b"-NOPERM operator required\r\n"):
            fake = FakeSession(b"HIGH_SECRET", begin_reply=reply)
            with tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "inventory.raw"
                with self.assertRaises(QihseAdminError):
                    sdk_session(fake).owner_inventory(target)
                self.assertFalse(target.exists())
                if reply.startswith(b"-"):
                    self.assertEqual(len(fake.commands), 1)
                else:
                    self.assertEqual(fake.commands[-1], ("OWNER.SNAPSHOT.END",))
                self.assertEqual(list(Path(directory).glob(".*.partial")), [])

    def test_failed_end_does_not_publish_and_closes_stale_session(self):
        fake = FakeSession(b"complete-data", end_reply=b"-ERR denied\r\n")
        session = sdk_session(fake)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "backup.qbk"
            target.write_bytes(b"previous-complete-file")
            with self.assertRaisesRegex(QihseAdminError, "END failed"):
                session.backup_owner_data(target)
            self.assertEqual(target.read_bytes(), b"previous-complete-file")
            self.assertTrue(fake.closed)
            self.assertEqual(list(Path(directory).glob(".*.partial")), [])

    def test_begin_transport_exception_closes_unknown_snapshot_session(self):
        fake = FakeSession(b"private-data", begin_exception=OSError("transport failed"))
        session = sdk_session(fake)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inventory.raw"
            with self.assertRaisesRegex(OSError, "transport failed"):
                session.owner_inventory(target)
            self.assertTrue(fake.closed)
            self.assertFalse(fake.snapshot_active)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).glob(".*.partial")), [])

    def test_oversized_decimal_headers_raise_sdk_error(self):
        payload = b"data"
        fake = FakeSession(payload)
        original = fake.execute_resp

        def oversized_chunk(*args):
            if args[0] == "OWNER.SNAPSHOT.READ":
                fake.commands.append(args)
                return b"$" + b"9" * 21 + b"\r\n"
            return original(*args)

        fake.execute_resp = oversized_chunk
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inventory.raw"
            with self.assertRaisesRegex(QihseAdminError, "malformed bulk length"):
                sdk_session(fake).owner_inventory(target)
            self.assertEqual(fake.commands[-1], ("OWNER.SNAPSHOT.END",))
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).glob(".*.partial")), [])

    def test_bad_chunk_frame_cleans_temp_and_ends_snapshot(self):
        fake = FakeSession(b"payload", short_at=None)
        original = fake.execute_resp

        def bad_chunk(*args):
            if args[0] == "OWNER.SNAPSHOT.READ":
                fake.commands.append(args)
                return b"$6\r\nshort\r\nEXTRA"
            return original(*args)

        fake.execute_resp = bad_chunk
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "inventory.raw"
            with self.assertRaisesRegex(QihseAdminError, "truncated or oversized"):
                sdk_session(fake).owner_inventory(target)
            self.assertFalse(target.exists())
            self.assertEqual(fake.commands[-1], ("OWNER.SNAPSHOT.END",))
            self.assertEqual(list(Path(directory).glob(".*.partial")), [])


if __name__ == "__main__":
    unittest.main()
