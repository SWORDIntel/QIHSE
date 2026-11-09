"""Fixture tests for the authenticated native AIMEM Python mapping."""

import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from qihse.aimem import (AIMEMClient, DocumentSourceRef,
                         KnowledgeProvenance, KnowledgeRelation,
                         Scope)
from qihse.controller import (Controller, ControllerServerError, ControllerUsageError,
                              Reply, ReplyShapeError)


def bulk(value):
    return Reply("bulk", value=str(value).encode())


def array(*items):
    return Reply("array", items=list(items))


class Wire:
    username = "low-clearance-user"
    connected = True

    def __init__(self, *responses):
        self.responses = list(responses)
        self.commands = []

    def call(self, *args):
        self.commands.append(args)
        reply = self.responses.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


SCOPE = Scope("project", "tree", "stream", "session")
HIGH_MARKER = "protected payload must stay hidden"


class AIMEMSDKTests(unittest.TestCase):
    def test_requires_explicit_authenticated_controller(self):
        wire = Wire()
        wire.username = None
        with self.assertRaises(ControllerUsageError):
            AIMEMClient(wire)
        self.assertEqual(wire.commands, [])

    def test_scope_validation_prevents_broadening(self):
        for fields in (("",), ("project", "", "stream"),
                       ("project", "tree", "", "session"),
                       ("project/other",), ("p" * 64,)):
            with self.subTest(fields=fields), self.assertRaises(ControllerUsageError):
                Scope(*fields)

    def test_scoped_store_recall_get_forget_and_count_wire(self):
        hit = array(bulk("uuid"), bulk(123), bulk(1), bulk(5), bulk(2),
                    bulk("0.75"), bulk("example"))
        wire = Wire(bulk("uuid"), array(hit), hit,
                    Reply("int", value=1), Reply("int", value=1))
        client = AIMEMClient(wire)
        self.assertEqual(client.store(SCOPE, 1, "example", key="capture-1"), "uuid")
        self.assertEqual(client.recall(SCOPE, "exam", mode="bm25")[0].text, "example")
        self.assertEqual(client.get(SCOPE, "uuid").classification, 5)
        self.assertTrue(client.forget(SCOPE, "uuid"))
        self.assertEqual(client.count(SCOPE), 1)
        self.assertEqual(wire.commands, [
            ("AIMEM", "STORE-SCOPED-DURABLE", 1, "example", *SCOPE.args(), "capture-1"),
            ("AIMEM", "RECALL-SCOPED", "exam", 10, "bm25", 0, *SCOPE.args()),
            ("AIMEM", "GET-SCOPED", "uuid", *SCOPE.args()),
            ("AIMEM", "FORGET-SCOPED-DURABLE", "uuid", *SCOPE.args()),
            ("AIMEM", "COUNT-SCOPED", *SCOPE.args(), 0),
        ])

    def test_low_clearance_denial_never_discloses_payload(self):
        denied = ControllerServerError("NOPERM", "AIMEM access denied")
        wire = Wire(denied, Reply("nil"), denied)
        client = AIMEMClient(wire)
        with self.assertRaises(ControllerServerError) as raised:
            client.recall(SCOPE, HIGH_MARKER)
        self.assertEqual(raised.exception.error_class, "NOPERM")
        self.assertNotIn(HIGH_MARKER, str(raised.exception))
        self.assertIsNone(client.get(SCOPE, "high-uuid"))
        with self.assertRaises(ControllerServerError):
            client.knowledge_get(SCOPE, "high-version")
        self.assertEqual(len(wire.commands), 3)
        self.assertTrue(all(command[0] == "AIMEM" for command in wire.commands))

    def test_unsupported_remains_server_error(self):
        wire = Wire(ControllerServerError("ERR", "unknown AIMEM operation"))
        with self.assertRaises(ControllerServerError) as raised:
            AIMEMClient(wire).query_begin(SCOPE)
        self.assertEqual(raised.exception.error_class, "ERR")

    def test_source_query_and_bounded_walk_wire(self):
        knowledge = array(bulk("kid"), bulk("vid"), bulk(""), bulk(1), bulk(1),
                          bulk(1), bulk(100), bulk(101), bulk(0), bulk(4),
                          *(bulk(v) for v in SCOPE.args()), bulk("rule"))
        wire = Wire(bulk("cursor"), array(array(bulk(0), knowledge)))
        client = AIMEMClient(wire)
        self.assertEqual(client.query_begin(SCOPE, source_event_id="event-uuid"),
                         "cursor")
        self.assertEqual(client.knowledge_walk(SCOPE, "vid", max_depth=1,
                                               max_nodes=2)[0][1].content, "rule")
        self.assertEqual(wire.commands[0][:4], ("AIMEM", "QUERY", "V2", "BEGIN"))
        self.assertEqual(wire.commands[0][-1], "event-uuid")
        self.assertEqual(wire.commands[1],
                         ("AIMEM", "KNOWLEDGE", "WALK", "vid", *SCOPE.args(), 1, 2))
        with self.assertRaises(ControllerUsageError):
            client.knowledge_walk(SCOPE, "vid", max_depth=5)

    def test_typed_document_source_wire(self):
        source = DocumentSourceRef("hax-file", "src/example.c", "sha384-abc", 4, 9)
        knowledge = array(bulk("kid"), bulk("vid"), bulk(""), bulk(4), bulk(1),
                          bulk(1), bulk(100), bulk(101), bulk(0), bulk(4),
                          *(bulk(v) for v in SCOPE.args()), bulk("rule"))
        extended = array(knowledge, bulk(4), bulk(0), bulk(900000), array(), array())
        wire = Wire(extended, array(knowledge, array(*(bulk(v) for v in source.args()))),
                    bulk("cursor"))
        client = AIMEMClient(wire)
        provenance = KnowledgeProvenance(900000, "retry-1")
        self.assertEqual(client.knowledge_create_ex_source(
            SCOPE, 4, 1, "rule", provenance, source).version.version_id, "vid")
        self.assertEqual(client.knowledge_get_source(SCOPE, "vid")[1], source)
        self.assertEqual(client.query_begin(SCOPE, source_ref=source), "cursor")
        self.assertEqual(wire.commands[0][1:3], ("KNOWLEDGE", "CREATE-EX-SOURCE"))
        self.assertEqual(wire.commands[0][-5:], source.args())
        self.assertEqual(wire.commands[1],
                         ("AIMEM", "KNOWLEDGE", "GET-SOURCE", "vid", *SCOPE.args()))
        self.assertEqual(wire.commands[2][1:4], ("QUERY", "V3", "BEGIN"))
        self.assertEqual(wire.commands[2][-5:], source.args())
        with self.assertRaises(ControllerUsageError):
            DocumentSourceRef("hax-file", "src/example.c", "sha384-abc", 0, 9)

    def test_scoped_receipt_shape_and_wire(self):
        wire = Wire(array(bulk("STORE-SCOPED"), bulk("row-id"),
                          bulk("receipt-id"), bulk("local-fsync")))
        receipt = AIMEMClient(wire).store_receipt(SCOPE, 1, "capture", key="retry-1")
        self.assertEqual((receipt.operation, receipt.id, receipt.token,
                          receipt.durability),
                         ("STORE-SCOPED", "row-id", "receipt-id", "local-fsync"))
        self.assertEqual(wire.commands, [
            ("AIMEM", "STORE-SCOPED-RECEIPT", 1, "capture", *SCOPE.args(),
             "retry-1")])

    def test_scoped_receipt_denied_and_malformed_fail_closed(self):
        denied = ControllerServerError("NOPERM", "AIMEM denied")
        unsupported = ControllerServerError("ERR", "unknown AIMEM operation")
        wire = Wire(denied, unsupported,
                    array(bulk("STORE-SCOPED"), bulk("id"), bulk("token"),
                          bulk("global-quorum")))
        client = AIMEMClient(wire)
        with self.assertRaises(ControllerServerError) as raised:
            client.store_receipt(SCOPE, 1, "capture", key="retry-1")
        self.assertEqual(raised.exception.error_class, "NOPERM")
        with self.assertRaises(ControllerServerError) as raised:
            client.store_receipt(SCOPE, 1, "capture", key="retry-1")
        self.assertEqual(raised.exception.error_class, "ERR")
        with self.assertRaises(ReplyShapeError):
            client.store_receipt(SCOPE, 1, "capture", key="retry-1")

    def test_forget_receipt_wire_and_fail_closed_shape(self):
        wire = Wire(array(bulk("FORGET-SCOPED"), bulk("row-id"),
                          bulk("receipt-id"), bulk("local-fsync")),
                    array(bulk("STORE-SCOPED"), bulk("row-id"),
                          bulk("receipt-id"), bulk("local-fsync")))
        client = AIMEMClient(wire)
        receipt = client.forget_receipt(SCOPE, "row-id", key="delete-1")
        self.assertEqual((receipt.operation, receipt.id, receipt.token),
                         ("FORGET-SCOPED", "row-id", "receipt-id"))
        self.assertEqual(wire.commands[0],
                         ("AIMEM", "FORGET-SCOPED-RECEIPT", "row-id",
                          *SCOPE.args(), "delete-1"))
        with self.assertRaises(ReplyShapeError):
            client.forget_receipt(SCOPE, "row-id", key="delete-1")
        with self.assertRaises(ControllerUsageError):
            client.forget_receipt(SCOPE, "", key="delete-1")

    def test_knowledge_and_handoff_shapes(self):
        knowledge = array(bulk("kid"), bulk("vid"), bulk(""), bulk(1), bulk(1),
                          bulk(1), bulk(100), bulk(101), bulk(0), bulk(4),
                          *(bulk(v) for v in SCOPE.args()), bulk("rule"))
        handoff = array(bulk("hid"), bulk(4), bulk(5), bulk(100), bulk(200),
                        bulk(1), bulk("OPEN"), bulk(0),
                        *(bulk(v) for v in SCOPE.args()), bulk("summary"),
                        array(bulk("evidence")), bulk("accepted-handoff-stays-accepted"))
        wire = Wire(knowledge, handoff, bulk("ACCEPTED"))
        client = AIMEMClient(wire)
        self.assertEqual(client.knowledge_latest(SCOPE, "kid").content, "rule")
        self.assertEqual(client.handoff_get("hid").evidence_ids, ("evidence",))
        self.assertEqual(client.handoff_accept("hid", 1), "ACCEPTED")

    def test_extended_knowledge_wire_and_reply(self):
        knowledge = array(bulk("kid"), bulk("vid"), bulk(""), bulk(5), bulk(1),
                          bulk(1), bulk(100), bulk(101), bulk(0), bulk(4),
                          *(bulk(v) for v in SCOPE.args()), bulk("candidate"))
        relation = array(bulk(1), bulk("target-version"),
                         *(bulk(v) for v in SCOPE.args()))
        extended = array(knowledge, bulk(4), bulk(0), bulk(750_000),
                         array(bulk("event-uuid")), array(relation))
        wire = Wire(extended, extended)
        client = AIMEMClient(wire)
        provenance = KnowledgeProvenance(750_000, "retry-1", ("event-uuid",),
                                        (KnowledgeRelation(1, "target-version", SCOPE),))
        created = client.knowledge_create_ex(SCOPE, 5, 1, "candidate", provenance)
        self.assertEqual(created.source_event_ids, ("event-uuid",))
        self.assertEqual(created.relations[0].target_scope, SCOPE)
        self.assertEqual(created.confidence_ppm, 750_000)
        client.knowledge_revise_ex("kid", "vid", 1, 1, "candidate", provenance)
        suffix = (750_000, "retry-1", 1, "event-uuid", 1, 1,
                  "target-version", *SCOPE.args())
        self.assertEqual(wire.commands, [
            ("AIMEM", "KNOWLEDGE", "CREATE-EX", 5, 1, "candidate",
             *SCOPE.args(), *suffix),
            ("AIMEM", "KNOWLEDGE", "REVISE-EX", "kid", "vid", 1, 1,
             "candidate", *suffix),
        ])

    def test_extended_knowledge_invalid_and_denied(self):
        with self.assertRaises(ControllerUsageError):
            KnowledgeProvenance(1_000_001, "retry")
        with self.assertRaises(ControllerUsageError):
            KnowledgeProvenance(100, "retry", relations=(
                KnowledgeRelation(4, "target", SCOPE),))
        denied = ControllerServerError("NOPERM", "AIMEM evidence unavailable")
        unsupported = ControllerServerError("ERR", "UNSUPPORTED AIMEM capability")
        wire = Wire(denied, unsupported, array())
        client = AIMEMClient(wire)
        provenance = KnowledgeProvenance(100, "retry")
        with self.assertRaises(ControllerServerError) as raised:
            client.knowledge_create_ex(SCOPE, 5, 1, "candidate", provenance)
        self.assertEqual(raised.exception.error_class, "NOPERM")
        with self.assertRaises(ControllerServerError) as raised:
            client.knowledge_create_ex(SCOPE, 5, 1, "candidate", provenance)
        self.assertEqual(raised.exception.error_class, "ERR")
        with self.assertRaises(ReplyShapeError):
            client.knowledge_create_ex(SCOPE, 5, 1, "candidate", provenance)

    def test_query_cursor_lifecycle_and_shape(self):
        knowledge = array(bulk("kid"), bulk("vid"), bulk(""), bulk(1), bulk(1),
                          bulk(1), bulk(100), bulk(101), bulk(0), bulk(4),
                          *(bulk(v) for v in SCOPE.args()), bulk("rule"))
        query_hit = array(knowledge, bulk("1.0"), bulk("0.5"), bulk("0.25"),
                          bulk(1), bulk(1), bulk(0), array(), array(bulk("e1")))
        wire = Wire(bulk("cursor"), array(query_hit), Reply("simple", value=b"OK"))
        client = AIMEMClient(wire)
        cursor = client.query_begin(SCOPE, text="rule")
        self.assertEqual(client.query_next(cursor)[0].source_event_ids, ("e1",))
        client.query_end(cursor)
        self.assertEqual(wire.commands[0][:4], ("AIMEM", "QUERY", "V1", "BEGIN"))
        self.assertEqual(wire.commands[1], ("AIMEM", "QUERY", "V1", "NEXT", "cursor", 128))
        self.assertEqual(wire.commands[2], ("AIMEM", "QUERY", "V1", "END", "cursor"))

    def test_malformed_reply_fails_closed(self):
        wire = Wire(array(bulk("high-id"), bulk(HIGH_MARKER)))
        with self.assertRaises(ReplyShapeError):
            AIMEMClient(wire).recall(SCOPE, "query")


class AIMEMRealServerNegative(unittest.TestCase):
    """Low principal against high data over a real loopback AIMEM server.

    The child owns disposable auth and KV state; no live service or configured
    QIHSE storage path is touched. A C fixture uses the repository header so
    it cannot silently use a stale ctypes mirror of the server config.
    """

    _SERVER_SOURCE = r'''
#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_resp_wire.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2 || !qihse_auth_init() ||
        !qihse_auth_bootstrap_operator("PyAimemOperator1!")) return 2;
    qihse_user_t *op = qihse_auth_get_user(0u);
    if (!op || !qihse_auth_create_user(op, 109u, QIHSE_ROLE_GUEST,
            0u, 0u, "PyAimemGuest1!", false)) return 3;
    qihse_kv_store_t *store = qihse_kv_store_create();
    if (!store) return 4;
    qihse_resp_server_config_t config;
    qihse_resp_server_config_init(&config);
    config.store = store;
    config.auth_required = true;
    config.bind_address = "127.0.0.1";
    config.port = (uint16_t)strtoul(argv[1], NULL, 10);
    config.enable_bus = false;
    config.enable_failover = false;
    qihse_resp_server_t *server = qihse_resp_server_create(&config);
    if (!server || !qihse_resp_server_start(server)) return 5;
    puts("READY"); fflush(stdout);
    for (;;) pause();
}
'''

    @classmethod
    def setUpClass(cls):
        root = Path(os.environ.get("QIHSE_AIMEM_TEST_RUNTIME_ROOT") or
                    Path(__file__).resolve().parents[1]).resolve()
        if not (root / "libqihse.so").exists():
            raise unittest.SkipTest("build libqihse.so before AIMEM SDK E2E test")
        compiler = shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable for AIMEM SDK fixture")
        cls._tmp = tempfile.TemporaryDirectory(prefix="qihse_py_aimem_sdk_")
        source = Path(cls._tmp.name) / "server.c"
        binary = Path(cls._tmp.name) / "server"
        source.write_text(cls._SERVER_SOURCE)
        compile_result = subprocess.run(
            [compiler, "-I", str(root / "include"), str(source), "-L", str(root),
             "-lqihse", "-pthread", "-o", str(binary)],
            capture_output=True, text=True, timeout=60)
        if compile_result.returncode:
            cls._tmp.cleanup()
            raise AssertionError(compile_result.stderr)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            cls.port = reserve.getsockname()[1]
        env = os.environ.copy()
        env["QIHSE_DATA_DIR"] = cls._tmp.name
        env["LD_LIBRARY_PATH"] = str(root) + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        cls._child = subprocess.Popen([str(binary), str(cls.port)], env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if cls._child.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        cls.tearDownClass()
        raise AssertionError("disposable AIMEM RESP server failed to start")

    @classmethod
    def tearDownClass(cls):
        child = getattr(cls, "_child", None)
        if child is not None:
            child.terminate()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
            cls._child = None
        tmp = getattr(cls, "_tmp", None)
        if tmp is not None:
            tmp.cleanup()
            cls._tmp = None

    def test_high_data_denied_through_sdk(self):
        scope = Scope("hax-sdk-negative")
        marker = "HAX_SDK_HIGH_CLASSIFIED_MARKER"
        with Controller("127.0.0.1", self.port,
                        username="GODMODE_OP", password="PyAimemOperator1!") as operator:
            high = AIMEMClient(operator)
            high_id = high.store(scope, 2, marker, key="high-capture")
            forget_id = high.store(scope, 2, "forget receipt target", key="forget-target")
            forget_first = high.forget_receipt(scope, forget_id, key="forget-1")
            self.assertEqual(high.forget_receipt(scope, forget_id, key="forget-1"),
                             forget_first)
            self.assertEqual(forget_first.durability, "local-fsync")
            with self.assertRaises(ControllerServerError) as conflict:
                high.forget_receipt(Scope("other-project"), forget_id, key="forget-1")
            self.assertIn("CONFLICT", conflict.exception.message)
            first = high.store_receipt(scope, 1, "receipt capture", key="receipt-1")
            replay = high.store_receipt(scope, 1, "receipt capture", key="receipt-1")
            self.assertEqual(first, replay)
            self.assertEqual(first.durability, "local-fsync")
            with self.assertRaises(ControllerServerError) as conflict:
                high.store_receipt(scope, 1, "changed capture", key="receipt-1")
            self.assertIn("CONFLICT", conflict.exception.message)
            knowledge = high.knowledge_create(scope, 1, 1, marker)
            high_event_id = high.event_append(scope, "hax", "high-event-1",
                                              "observation", 1_000, marker)
            provenance = KnowledgeProvenance(500_000, "high-knowledge-1",
                                             (high_event_id,))
            extended = high.knowledge_create_ex(scope, 5, 1, marker, provenance)
            self.assertEqual(high.knowledge_create_ex(scope, 5, 1, marker,
                                                       provenance), extended)
            with self.assertRaises(ControllerServerError) as conflict:
                high.knowledge_create_ex(scope, 5, 1, "changed candidate",
                                         provenance)
            self.assertIn("CONFLICT", conflict.exception.message)
            self.assertEqual(extended.source_event_ids, (high_event_id,))
            self.assertEqual(high.get(scope, high_id).text, marker)
            self.assertEqual(high.knowledge_get(scope, knowledge.version_id).content,
                             marker)

        # User_109 shares the system tenant but has classification=0, SCI=0.
        # The high records are present before any low clearance probe.
        with Controller("127.0.0.1", self.port,
                        username="User_109", password="PyAimemGuest1!") as low_wire:
            low = AIMEMClient(low_wire)
            with self.assertRaises(ControllerServerError) as denied:
                low.forget_receipt(scope, high_id, key="low-forget")
            self.assertNotIn(marker, str(denied.exception))
            self.assertIsNone(low.get(scope, high_id))
            self.assertEqual(low.recall(scope, marker, mode="bm25"), [])
            self.assertEqual(low.count(scope), 0)
            self.assertIsNone(low.knowledge_get(scope, knowledge.version_id))
            self.assertIsNone(low.knowledge_get(scope, extended.version.version_id))
            low.store(scope, 1, "low-owned project note", key="low-owner-1")
            with self.assertRaises(ControllerServerError) as denied:
                low.knowledge_create_ex(scope, 5, 1, "low candidate",
                                        KnowledgeProvenance(100, "low-knowledge-1",
                                                            (high_event_id,)))
            self.assertNotIn(marker, str(denied.exception))
            with self.assertRaises(ControllerServerError) as denied:
                low.knowledge_revise_ex(extended.version.knowledge_id,
                                        extended.version.version_id,
                                        extended.version.revision, 1,
                                        "low takeover", KnowledgeProvenance(
                                            100, "low-revise-1"))
            self.assertNotIn(marker, str(denied.exception))


if __name__ == "__main__":
    unittest.main()
