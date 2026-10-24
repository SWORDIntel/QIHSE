"""Unit coverage for Python PostgreSQL startup and transaction outcomes."""
import socket
import struct
import threading
import unittest

from qihse_pg import OperationalError, ProgrammingError, connect


def frame(tag, body=b""):
    return tag + struct.pack("!I", 4 + len(body)) + body


def error_response(message="unsupported transaction command", sqlstate="42000"):
    body = (b"SERROR\x00C" + sqlstate.encode() + b"\x00M" +
            message.encode() + b"\x00\x00")
    return frame(b"E", body)


def ready(status):
    return frame(b"Z", status)


class FakePgServer:
    def __init__(self, responses, reject_auth=False):
        self.responses = list(responses)
        self.reject_auth = reject_auth
        self.queries = []
        self.password = None
        self.startup = None
        self.failure = None
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @staticmethod
    def _read_exact(sock, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise EOFError("client closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @classmethod
    def _read_startup(cls, sock):
        length = struct.unpack("!I", cls._read_exact(sock, 4))[0]
        return cls._read_exact(sock, length - 4)

    @classmethod
    def _read_message(cls, sock):
        tag = cls._read_exact(sock, 1)
        length = struct.unpack("!I", cls._read_exact(sock, 4))[0]
        return tag, cls._read_exact(sock, length - 4)

    def start(self):
        self.thread.start()
        return self

    def _serve(self):
        try:
            client, _ = self.listener.accept()
            client.settimeout(5)
            try:
                self.startup = self._read_startup(client)
                client.sendall(frame(b"R", struct.pack("!I", 3)))
                tag, password_body = self._read_message(client)
                if tag != b"p":
                    raise AssertionError("expected PasswordMessage")
                self.password = password_body.rstrip(b"\x00")
                if self.reject_auth:
                    client.sendall(error_response("password authentication failed", "28P01"))
                    return
                client.sendall(frame(b"R", struct.pack("!I", 0)) + ready(b"I"))
                for response in self.responses:
                    tag, body = self._read_message(client)
                    if tag == b"X":
                        break
                    if tag != b"Q":
                        raise AssertionError("expected simple Query, got %r" % tag)
                    query = body.rstrip(b"\x00").decode()
                    self.queries.append(query)
                    if response is None:
                        return
                    client.sendall(response)
            finally:
                client.close()
        except EOFError:
            pass
        except BaseException as exc:  # surface assertions from the worker thread
            self.failure = exc
        finally:
            self.listener.close()

    def join(self):
        self.thread.join(timeout=6)
        if self.thread.is_alive():
            raise AssertionError("fake PostgreSQL server did not stop")
        if self.failure:
            raise self.failure


def command(tag, status):
    return frame(b"C", tag.encode() + b"\x00") + ready(status)


class PgTransactionTests(unittest.TestCase):
    def test_startup_sends_password_before_authenticated_ready(self):
        server = FakePgServer([]).start()
        conn = connect(host="127.0.0.1", port=server.port, user="alice",
                       dbname="inventory", password="secret")
        self.assertIn(b"user\x00alice\x00database\x00inventory\x00", server.startup)
        self.assertEqual(server.password, b"secret")
        self.assertIsNotNone(conn._sock)
        conn.close()
        server.join()

    def test_startup_rejection_prevents_connection_creation(self):
        server = FakePgServer([], reject_auth=True).start()
        with self.assertRaises(OperationalError):
            connect(host="127.0.0.1", port=server.port, user="alice",
                    password="wrong")
        server.join()
        self.assertEqual(server.password, b"wrong")
        self.assertEqual(server.queries, [])

    def test_begin_rejection_keeps_transaction_state_false(self):
        server = FakePgServer([error_response() + ready(b"I")]).start()
        conn = connect(host="127.0.0.1", port=server.port, password="secret")
        with self.assertRaises(ProgrammingError):
            conn.begin()
        self.assertFalse(conn._in_transaction)
        conn.close()
        server.join()
        self.assertEqual(server.queries, ["BEGIN"])

    def test_commit_rejection_does_not_clear_active_state(self):
        server = FakePgServer([
            command("BEGIN", b"T"),
            error_response("commit refused") + ready(b"I"),
        ]).start()
        conn = connect(host="127.0.0.1", port=server.port, password="secret")
        conn.begin()
        self.assertTrue(conn._in_transaction)
        with self.assertRaises(ProgrammingError):
            conn.commit()
        self.assertTrue(conn._in_transaction)
        conn.close()
        server.join()
        self.assertEqual(server.queries, ["BEGIN", "COMMIT"])

    def test_successful_rollback_clears_active_state(self):
        server = FakePgServer([
            command("BEGIN", b"T"),
            command("ROLLBACK", b"I"),
        ]).start()
        conn = connect(host="127.0.0.1", port=server.port, password="secret")
        conn.begin()
        conn.rollback()
        self.assertFalse(conn._in_transaction)
        conn.close()
        server.join()
        self.assertEqual(server.queries, ["BEGIN", "ROLLBACK"])

    def test_default_cursor_starts_a_real_transaction_before_query(self):
        row_description = frame(
            b"T", struct.pack("!H", 1) + b"answer\x00" +
            struct.pack("!IhIhih", 0, 0, 23, 4, -1, 0))
        data_row = frame(b"D", struct.pack("!Hi", 1, 1) + b"1")
        server = FakePgServer([
            command("BEGIN", b"T"),
            row_description + data_row + command("SELECT 1", b"T"),
            command("COMMIT", b"I"),
        ]).start()
        conn = connect(host="127.0.0.1", port=server.port, password="secret")
        cur = conn.cursor()
        cur.execute("SELECT 1")
        self.assertEqual(cur.fetchone(), ("1",))
        self.assertEqual(cur.rowcount, 1)
        self.assertTrue(conn._in_transaction)
        conn.commit()
        self.assertFalse(conn._in_transaction)
        conn.close()
        server.join()
        self.assertEqual(server.queries, ["BEGIN", "SELECT 1", "COMMIT"])

    def test_default_cursor_does_not_run_query_if_begin_is_rejected(self):
        server = FakePgServer([error_response() + ready(b"I")]).start()
        conn = connect(host="127.0.0.1", port=server.port, password="secret")
        with self.assertRaises(ProgrammingError):
            conn.cursor().execute("SELECT 1")
        self.assertFalse(conn._in_transaction)
        conn.close()
        server.join()
        self.assertEqual(server.queries, ["BEGIN"])

    def test_transport_close_is_reported_and_socket_discarded(self):
        server = FakePgServer([None]).start()
        conn = connect(host="127.0.0.1", port=server.port, password="secret",
                       autocommit=True)
        with self.assertRaises(OperationalError):
            conn.cursor().execute("SELECT 1")
        self.assertIsNone(conn._sock)
        conn.close()
        server.join()


if __name__ == "__main__":
    unittest.main()
