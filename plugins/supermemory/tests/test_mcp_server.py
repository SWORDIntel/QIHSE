"""AIMEM MCP bridge contract tests without a running backend."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import time
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
SPEC = importlib.util.spec_from_file_location("qihse_mcp_server_tests", BASE / "mcp_server.py")
mcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mcp)


class McpTests(unittest.TestCase):
    def test_exact_get_returns_authorized_record(self):
        sample = ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "9000", "1", "0", "0", "0", "precise error"]
        with (mock.patch.object(mcp, "_send", return_value=sample) as send,
              mock.patch.object(mcp, "get_current_repo", return_value=("qihse", None))):
            result = mcp.get_memory({"id": sample[0]})
        send.assert_called_once_with("AIMEM", "GET-SCOPED", sample[0],
                                     "qihse", "", "", "")
        hit = json.loads(result["content"][0]["text"])
        self.assertEqual(hit["id"], sample[0])
        self.assertEqual(hit["text"], "precise error")
        self.assertEqual(hit["created_ms"], 9000)

    def test_missing_or_hidden_record_has_single_response(self):
        with mock.patch.object(mcp, "_send", return_value=None):
            a = mcp.get_memory({"id": "not-found"})
            b = mcp.get_memory({"id": "hidden"})
        self.assertEqual(a, b)
        self.assertTrue(a["isError"])

    def test_invalid_id_does_not_send(self):
        with mock.patch.object(mcp, "_send") as send:
            for invalid in ("", [], "a" * 129, "null\x00inside", None):
                self.assertTrue(mcp.get_memory({"id": invalid})["isError"])
            send.assert_not_called()

    def test_all_memory_operations_use_native_scope(self):
        sample = ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "9000", "1", "0", "0", "0", "text"]
        with (mock.patch.object(mcp, "get_current_repo", return_value=("qihse", None)),
              mock.patch.object(mcp, "_send", side_effect=[[sample], "new-id", 1, 7]) as send):
            mcp.search_memory({"query": "needle", "scope": "repo"})
            mcp.add_memory({"text": "body", "scope": "repo", "idempotency_key": "idem"})
            mcp.forget_memory({"id": sample[0], "scope": "repo"})
            mcp.memory_count({"scope": "repo"})
        commands = [call.args[:2] for call in send.call_args_list]
        self.assertEqual(commands, [
            ("AIMEM", "RECALL-SCOPED"),
            ("AIMEM", "STORE-SCOPED-DURABLE"),
            ("AIMEM", "FORGET-SCOPED-DURABLE"),
            ("AIMEM", "COUNT-SCOPED"),
        ])
        for call in send.call_args_list:
            self.assertIn("qihse", call.args)

    def test_search_trusts_native_scope_instead_of_payload_labels(self):
        sample = ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "9000", "1", "0", "0", "0.5", "mentions another-repo"]
        with mock.patch.object(mcp, "_send", return_value=[sample]):
            result = mcp.search_memory({"query": "needle", "scope": "target_project"})
        body = json.loads(result["content"][0]["text"])
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["matched_scope"], "target-project")
        self.assertEqual(result["effective_scope"], "target-project")
        self.assertFalse(result["scope_switched"])

    def test_env_loader_does_not_import_server_bootstrap_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "env"
            env_file.write_text(
                "QIHSE_RESP_HOST=127.0.0.1\n"
                "QIHSE_AUTH_USER=AIMEM_SERVICE\n"
                "QIHSE_AUTH_PASSWORD=client-secret\n"
                "QIHSE_OPERATOR_PASSWORD=operator-secret\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            keys = ("QIHSE_RESP_HOST", "QIHSE_AUTH_USER", "QIHSE_AUTH_PASSWORD", "QIHSE_OPERATOR_PASSWORD")
            saved = {key: os.environ.get(key) for key in keys}
            try:
                for key in keys:
                    os.environ.pop(key, None)
                os.environ["QIHSE_AIMEM_ENV"] = str(env_file)
                mcp._load_env_file()
                self.assertEqual(os.environ["QIHSE_AUTH_USER"], "AIMEM_SERVICE")
                self.assertNotIn("QIHSE_OPERATOR_PASSWORD", os.environ)
            finally:
                os.environ.pop("QIHSE_AIMEM_ENV", None)
                for key, value in saved.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

    def test_qkp_never_downgrades_or_uses_operator(self):
        from sync import _qihse_connect
        env = {
            'QIHSE_AIMEM_TRANSPORT': 'qkp', 'QIHSE_RESP_HOST': '127.0.0.1',
            'QIHSE_RESP_PORT': '6401', 'QIHSE_AUTH_USER': 'AIMEM_SERVICE',
            'QIHSE_AUTH_PASSWORD': 'service-test-secret',
        }
        with (mock.patch.dict(os.environ, env, clear=True),
              mock.patch('socket.create_connection') as cleartext):
            with self.assertRaisesRegex(RuntimeError, 'requires an installed SDK'):
                _qihse_connect()
            cleartext.assert_not_called()
            os.environ['QIHSE_AUTH_USER'] = 'GODMODE_OP'
            with self.assertRaisesRegex(RuntimeError, 'AIMEM_SERVICE principal required'):
                _qihse_connect()
            cleartext.assert_not_called()
            os.environ['QIHSE_AUTH_USER'] = 'AIMEM_SERVICE'
            os.environ['QIHSE_RESP_HOST'] = '192.168.1.91'
            with self.assertRaisesRegex(RuntimeError, 'non-loopback'):
                _qihse_connect()
            cleartext.assert_not_called()

    def test_schema_and_handler_are_consistent(self):
        tools = {tool["name"] for tool in mcp.TOOLS}
        self.assertIn("get_memory", tools)
        self.assertEqual(tools, set(mcp.HANDLERS))
        self.assertEqual(mcp.handle({"method": "tools/list", "jsonrpc": "2.0", "id": 1})["result"]["tools"], mcp.TOOLS)

    def test_resp_transaction_is_serialized(self):
        class FakeSocket:
            def __init__(self):
                self.request = None
                self.lock = threading.Lock()
            def command(self, *parts):
                self.request = parts
                time.sleep(0.002)
                return self.request
            def close(self):
                pass
        sock = FakeSocket()
        out = []
        def worker(i):
            out.append(mcp._send("PING", str(i)))
        with (
            mock.patch.object(mcp, "_connection", return_value=sock),
        ):
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
        self.assertEqual(len(out), 15)
        self.assertEqual(len(set(out)), 15)


if __name__ == "__main__":
    unittest.main()
