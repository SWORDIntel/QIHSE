#!/usr/bin/env python3
"""Focused wire tests for the restartable AIMEM migration client."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "qihse_aimem_migrate.py"
UUIDS = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
)


def read_resp(stream):
    marker = stream.read(1)
    if marker != b"*":
        return None
    count = int(stream.readline()[:-2])
    values = []
    for _ in range(count):
        if stream.read(1) != b"$":
            return None
        size = int(stream.readline()[:-2])
        value = stream.read(size)
        if stream.read(2) != b"\r\n":
            return None
        values.append(value.decode())
    return values


def bulk(value):
    if value is None:
        return b"$-1\r\n"
    encoded = value.encode()
    return f"${len(encoded)}\r\n".encode() + encoded + b"\r\n"


def array(values):
    result = [f"*{len(values)}\r\n".encode()]
    for value in values:
        if isinstance(value, list):
            result.append(array(value))
        else:
            result.append(bulk(str(value)))
    return b"".join(result)


class State:
    def __init__(self):
        self.legacy = set(UUIDS)
        self.scoped = {}
        self.migrations = 0
        self.commands = []
        self.lock = threading.Lock()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        authenticated = False
        role = ""
        while True:
            command = read_resp(self.rfile)
            if command is None:
                return
            with self.server.state.lock:
                self.server.state.commands.append(command[:2])
            if command[0] == "AUTH":
                if len(command) != 3 or command[2] != "test-secret":
                    self.wfile.write(b"-ERR invalid credentials\r\n")
                else:
                    authenticated = True
                    role = command[1]
                    self.wfile.write(b"+OK\r\n")
                continue
            if not authenticated:
                self.wfile.write(b"-NOAUTH Authentication required\r\n")
                continue
            if command[:3] == ["AIMEM", "LEGACY", "SCAN"]:
                if role != "operator":
                    self.wfile.write(b"-NOPERM system Operator required\r\n")
                    continue
                cursor, count = int(command[3]), int(command[4])
                records = sorted(self.server.state.legacy)
                page = records[cursor:cursor + count]
                next_cursor = cursor + len(page)
                if next_cursor >= len(records):
                    next_cursor = 0
                self.wfile.write(array([str(next_cursor), page]))
            elif command[:2] == ["AIMEM", "GET-SCOPED"]:
                key = (command[2], *command[3:7])
                self.wfile.write(bulk("discarded-payload" if key in self.server.state.scoped else None))
            elif command[:2] == ["AIMEM", "MIGRATE-LEGACY"]:
                if role != "operator":
                    self.wfile.write(b"-NOPERM system Operator required\r\n")
                    continue
                record_id = command[2]
                scope = tuple(command[3:7])
                with self.server.state.lock:
                    if record_id in self.server.state.legacy:
                        self.server.state.legacy.remove(record_id)
                        self.server.state.scoped[(record_id, *scope)] = True
                        self.server.state.migrations += 1
                        self.wfile.write(bulk(record_id))
                    elif (record_id, *scope) in self.server.state.scoped:
                        self.wfile.write(bulk(record_id))
                    else:
                        self.wfile.write(b"-ERR migration failed\r\n")
            else:
                self.wfile.write(b"-ERR unsupported\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class MigrationCliTest(unittest.TestCase):
    def setUp(self):
        self.state = State()
        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        records = [
            {"uuid": value, "project": "project-a", "worktree": "tree-a",
             "workstream": "stream-a", "session": "session-a"}
            for value in UUIDS
        ]
        self.manifest = self.directory / "manifest.json"
        self.manifest.write_text(json.dumps({"version": 1, "records": records}), encoding="utf-8")
        self.checkpoint = self.directory / "checkpoint.json"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def run_tool(self, username="operator", *extra):
        env = os.environ.copy()
        env["TEST_MIGRATION_PASSWORD"] = "test-secret"
        command = ["python3", str(TOOL), "--manifest", str(self.manifest),
                   "--checkpoint", str(self.checkpoint), "--host", "127.0.0.1",
                   "--port", str(self.server.server_address[1]), "--username", username,
                   "--password-env", "TEST_MIGRATION_PASSWORD", "--batch-size", "2", *extra]
        return subprocess.run(command, text=True, capture_output=True, env=env, check=False)

    def test_dry_run_preflights_without_mutation_or_secret_output(self):
        result = self.run_tool("operator", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.migrations, 0)
        self.assertNotIn("test-secret", result.stdout + result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(events[0], {"event": "preflight", "total": 3,
                                     "pending": 3, "already_migrated": 0})

    def test_batched_restart_is_idempotent_and_checkpoint_is_content_free(self):
        first = self.run_tool("operator", "--max-records", "2")
        self.assertEqual(first.returncode, 3, first.stderr)
        self.assertEqual(self.state.migrations, 2)
        checkpoint_text = self.checkpoint.read_text(encoding="utf-8")
        self.assertNotIn("project-a", checkpoint_text)
        for record_id in UUIDS:
            self.assertNotIn(record_id, checkpoint_text)

        second = self.run_tool("operator")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.state.migrations, 3)
        third = self.run_tool("operator")
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertEqual(self.state.migrations, 3)

    def test_low_clearance_and_no_auth_are_denied_without_mutation(self):
        low = self.run_tool("guest", "--dry-run")
        self.assertEqual(low.returncode, 2)
        self.assertIn("NOPERM", low.stderr)
        self.assertEqual(self.state.migrations, 0)

        with socket.create_connection(self.server.server_address) as client:
            client.sendall(b"*5\r\n$5\r\nAIMEM\r\n$6\r\nLEGACY\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$1\r\n2\r\n")
            self.assertEqual(client.recv(128), b"-NOAUTH Authentication required\r\n")
        self.assertEqual(self.state.migrations, 0)

    def test_duplicate_manifest_fails_before_connecting(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["records"].append(dict(document["records"][0]))
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        before = len(self.state.commands)
        result = self.run_tool("operator")
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate uuid", result.stderr)
        self.assertEqual(len(self.state.commands), before)

    def test_all_scopes_are_validated_before_connecting(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["records"][2]["project"] = "invalid/project"
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        before = len(self.state.commands)
        result = self.run_tool("operator")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid project", result.stderr)
        self.assertEqual(len(self.state.commands), before)

    def test_unmanifested_inventory_aborts_before_first_mutation(self):
        document = json.loads(self.manifest.read_text(encoding="utf-8"))
        document["records"].pop()
        self.manifest.write_text(json.dumps(document), encoding="utf-8")
        result = self.run_tool("operator")
        self.assertEqual(result.returncode, 2)
        self.assertIn("absent from manifest", result.stderr)
        self.assertEqual(self.state.migrations, 0)


if __name__ == "__main__":
    unittest.main()
