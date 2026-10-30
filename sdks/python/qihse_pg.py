"""QIHSE psycopg2-compatible Python SDK.

Provides a psycopg2-compatible API that connects to QIHSE's PostgreSQL wire protocol.
"""
import ipaddress
import socket
import ssl
import struct
import datetime
from collections import namedtuple

# Protocol constants
PROTOCOL_VERSION = 3 << 16  # 3.0

# Message types
STARTUP_MESSAGE = 0
AUTH_REQUEST = 'R'
QUERY = 'Q'
PARSE = 'P'
BIND = 'B'
EXECUTE = 'E'
SYNC = 'S'
TERMINATE = 'X'
ROW_DESCRIPTION = 'T'
DATA_ROW = 'D'
COMMAND_COMPLETE = 'C'
READY_FOR_QUERY = 'Z'
ERROR_RESPONSE = 'E'
AUTH_OK = 'R'
PARAMETER_STATUS = 'S'
BACKEND_KEY_DATA = 'K'
NOTICE_RESPONSE = 'N'

# Connection status
CONNECTION_OK = 0
CONNECTION_BAD = 1

# Exec status
PGRES_EMPTY_QUERY = 0
PGRES_COMMAND_OK = 1
PGRES_TUPLES_OK = 2
PGRES_FATAL_ERROR = 4


class Error(Exception):
    """Base exception."""
    pass

class OperationalError(Error):
    """Operational error."""
    pass

class ProgrammingError(Error):
    pass

class IntegrityError(Error):
    pass

class DataError(Error):
    pass

class InternalError(Error):
    pass


class connection:
    """psycopg2-compatible connection."""
    
    def __init__(self, host="localhost", port=5432, dbname="test", user="admin", password="", autocommit=False,
                 sslmode="verify-full", sslrootcert=None, sslhostname=None,
                 sslcert=None, sslkey=None):
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.password = password
        self.autocommit = autocommit
        if sslmode not in ("verify-full", "disable"):
            raise OperationalError("sslmode must be verify-full or explicit loopback-only disable")
        if sslmode == "disable" and any(
                value is not None for value in (sslrootcert, sslhostname, sslcert, sslkey)):
            raise OperationalError("TLS options cannot be used with sslmode=disable")
        if (sslcert is None) != (sslkey is None):
            raise OperationalError("sslcert and sslkey must be supplied together")
        for name, value in (("user", user), ("dbname", dbname), ("password", password)):
            if not isinstance(value, str) or "\x00" in value:
                raise OperationalError("%s must be a string without NUL bytes" % name)
        self.sslmode = sslmode
        self.sslhostname = host if sslhostname is None else sslhostname
        self._ssl_context = None
        if sslmode == "verify-full":
            if not isinstance(self.sslhostname, str) or not self.sslhostname or "\x00" in self.sslhostname:
                raise OperationalError("TLS hostname must be a nonempty string without NUL bytes")
            try:
                self._ssl_context = ssl.create_default_context(cafile=sslrootcert)
                self._ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                if sslcert is not None:
                    self._ssl_context.load_cert_chain(sslcert, sslkey)
            except (OSError, ValueError) as exc:
                raise OperationalError("invalid PostgreSQL TLS configuration: %s" % exc) from exc
        self._closed = False
        self._sock = None
        self._in_transaction = False
        self._last_result = {"rows": [], "description": [], "command_tag": None}
        self._connect()
    
    def _connect(self):
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=10)
            if self.sslmode == "disable":
                # Check the connected peer, not a hostname that could resolve differently.
                if not ipaddress.ip_address(self._sock.getpeername()[0]).is_loopback:
                    raise OperationalError("sslmode=disable is restricted to loopback development")
            else:
                self._sock.sendall(struct.pack("!II", 8, 80877103))
                if self._read_exact(self._sock, 1) != b'S':
                    raise OperationalError("PostgreSQL server refused TLS; cleartext fallback is disabled")
                self._sock = self._ssl_context.wrap_socket(
                    self._sock, server_hostname=self.sslhostname)
            self._send_startup()
        except OSError as exc:
            self._discard_socket()
            raise OperationalError("PostgreSQL TLS/transport failed: %s" % exc) from exc
        except (ValueError, Error):
            self._discard_socket()
            raise

    def _discard_socket(self):
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _read_exact(sock, size):
        chunks = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise OperationalError("PostgreSQL server closed the connection mid-frame")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_message(self):
        if not self._sock:
            raise OperationalError("PostgreSQL connection is not open")
        try:
            tag = self._read_exact(self._sock, 1)
            length = struct.unpack("!I", self._read_exact(self._sock, 4))[0]
            if length < 4 or length > 16 * 1024 * 1024:
                raise OperationalError("invalid PostgreSQL message length")
            return tag, self._read_exact(self._sock, length - 4)
        except (OSError, socket.timeout) as exc:
            self._discard_socket()
            raise OperationalError("PostgreSQL transport failed: %s" % exc) from exc
    
    def _send_startup(self):
        if not self._sock:
            raise OperationalError("PostgreSQL connection is not open")
        # Build StartupMessage
        params = f"user\x00{self.user}\x00database\x00{self.dbname}\x00\x00"
        msg = struct.pack("!I", PROTOCOL_VERSION) + params.encode()
        length = struct.pack("!I", 4 + len(msg))
        try:
            self._sock.sendall(length + msg)
            authenticated = False
            while True:
                tag, body = self._read_message()
                if tag == b'R':
                    if len(body) != 4:
                        raise OperationalError("malformed PostgreSQL authentication response")
                    auth_method = struct.unpack("!I", body)[0]
                    if auth_method == 3:  # AuthenticationCleartextPassword
                        password = self.password.encode("utf-8") + b"\x00"
                        self._send_message(b'p', password)
                    elif auth_method == 0:  # AuthenticationOk
                        authenticated = True
                    else:
                        raise OperationalError(
                            "unsupported PostgreSQL authentication method %d" % auth_method)
                elif tag == b'E':
                    fields = self._parse_error_fields(body)
                    raise self._server_error(fields)
                elif tag == b'Z':
                    if len(body) != 1 or body[0:1] != b'I' or not authenticated:
                        raise OperationalError("PostgreSQL startup did not complete authentication")
                    return
                elif tag in (b'S', b'K', b'N'):
                    continue
                else:
                    raise OperationalError("unexpected PostgreSQL startup message %r" % tag)
        except (OSError, socket.timeout) as exc:
            self._discard_socket()
            raise OperationalError("PostgreSQL startup transport failed: %s" % exc) from exc

    def _send_message(self, tag, body):
        if not self._sock:
            raise OperationalError("PostgreSQL connection is not open")
        try:
            self._sock.sendall(tag + struct.pack("!I", 4 + len(body)) + body)
        except (OSError, socket.timeout) as exc:
            self._discard_socket()
            raise OperationalError("PostgreSQL transport failed: %s" % exc) from exc
    
    def cursor(self, cursor_factory=None):
        if self._closed:
            raise OperationalError("connection is closed")
        return cursor(self, cursor_factory)
    
    def commit(self):
        if not self.autocommit and self._in_transaction:
            self._execute_simple("COMMIT")
    
    def rollback(self):
        if not self.autocommit and self._in_transaction:
            self._execute_simple("ROLLBACK")

    def begin(self):
        if self.autocommit:
            raise ProgrammingError("cannot begin a managed transaction in autocommit mode")
        if self._in_transaction:
            raise ProgrammingError("a transaction is already active")
        self._execute_simple("BEGIN")
    
    def _execute_simple(self, query):
        if not self._sock:
            raise OperationalError("PostgreSQL connection is not open")
        msg = query.encode() + b'\x00'
        length = struct.pack("!I", 4 + len(msg))
        self._send_message(QUERY.encode(), msg)
        rows = []
        description = []
        command_tag = None
        error = None
        ready_status = None
        try:
            while True:
                tag, body = self._read_message()
                if tag == b'T':
                    description = self._parse_row_description(body)
                elif tag == b'D':
                    rows.append(self._parse_data_row(body))
                elif tag == b'C':
                    command_tag = self._cstring(body)
                elif tag == b'E':
                    error = self._parse_error_fields(body)
                elif tag == b'Z':
                    if len(body) != 1 or body[0:1] not in (b'I', b'T', b'E'):
                        raise OperationalError("malformed ReadyForQuery response")
                    ready_status = body[0:1]
                    break
                elif tag in (b'N', b'A', b'S', b'K', b'I'):
                    continue
                else:
                    raise OperationalError("unexpected PostgreSQL query response %r" % tag)
        except OperationalError:
            self._discard_socket()
            raise
        except (OSError, socket.timeout) as exc:
            self._discard_socket()
            raise OperationalError("PostgreSQL transport failed: %s" % exc) from exc

        if ready_status is None:
            self._discard_socket()
            raise OperationalError("PostgreSQL query ended without ReadyForQuery")
        if error is not None:
            raise self._server_error(error)

        verb = query.lstrip().split(None, 1)[0].rstrip(";").upper() if query.strip() else ""
        tag_verb = (command_tag or "").split(None, 1)[0].upper()
        if verb in ("BEGIN", "START") and tag_verb == "BEGIN" and ready_status == b'T':
            self._in_transaction = True
        elif verb in ("COMMIT", "ROLLBACK", "END") and ready_status == b'I' and tag_verb in ("COMMIT", "ROLLBACK"):
            self._in_transaction = False

        self._last_result = {
            "rows": rows,
            "description": description,
            "command_tag": command_tag,
        }
        return self._last_result

    @staticmethod
    def _cstring(body, offset=0):
        end = body.find(b"\x00", offset)
        if end < 0:
            raise OperationalError("malformed PostgreSQL C string")
        return body[offset:end].decode("utf-8", "replace")

    @classmethod
    def _parse_error_fields(cls, body):
        fields = {}
        offset = 0
        while offset < len(body) and body[offset] != 0:
            code = chr(body[offset])
            offset += 1
            end = body.find(b"\x00", offset)
            if end < 0:
                raise OperationalError("malformed PostgreSQL ErrorResponse")
            fields[code] = body[offset:end].decode("utf-8", "replace")
            offset = end + 1
        return fields

    @staticmethod
    def _server_error(fields):
        message = fields.get('M', "PostgreSQL server rejected the request")
        code = fields.get('C', "")
        error_type = ProgrammingError if code.startswith("42") else OperationalError
        return error_type("%s%s" % ((code + ": ") if code else "", message))

    @classmethod
    def _parse_row_description(cls, body):
        if len(body) < 2:
            raise OperationalError("malformed PostgreSQL RowDescription")
        count = struct.unpack_from("!H", body, 0)[0]
        offset = 2
        result = []
        for _ in range(count):
            end = body.find(b"\x00", offset)
            if end < 0:
                raise OperationalError("malformed PostgreSQL RowDescription field name")
            name = cls._cstring(body, offset)
            offset = end + 1
            if offset + 18 > len(body):
                raise OperationalError("truncated PostgreSQL RowDescription field")
            table_oid, column_no, type_oid, type_size, type_modifier, fmt = struct.unpack_from(
                "!IhIhih", body, offset)
            offset += 18
            result.append((name, type_oid, None, type_size, None, None, None))
        if offset != len(body):
            raise OperationalError("trailing bytes in PostgreSQL RowDescription")
        return result

    @staticmethod
    def _parse_data_row(body):
        if len(body) < 2:
            raise OperationalError("malformed PostgreSQL DataRow")
        count = struct.unpack_from("!H", body, 0)[0]
        offset = 2
        row = []
        for _ in range(count):
            if offset + 4 > len(body):
                raise OperationalError("truncated PostgreSQL DataRow length")
            size = struct.unpack_from("!i", body, offset)[0]
            offset += 4
            if size == -1:
                row.append(None)
            elif size < -1 or offset + size > len(body):
                raise OperationalError("invalid PostgreSQL DataRow value length")
            else:
                row.append(body[offset:offset + size].decode("utf-8", "replace"))
                offset += size
        if offset != len(body):
            raise OperationalError("trailing bytes in PostgreSQL DataRow")
        return tuple(row)
    
    def close(self):
        if self._sock:
            try:
                self._send_message(TERMINATE.encode(), b'')
            except (OperationalError, OSError):
                pass
        self._discard_socket()
        self._closed = True
    
    @property
    def closed(self):
        return 2 if self._closed else 0
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                self.rollback()
            else:
                self.commit()
        finally:
            self.close()
        return False


class cursor:
    """psycopg2-compatible cursor."""
    
    def __init__(self, conn, cursor_factory=None):
        self.connection = conn
        self.cursor_factory = cursor_factory
        self._results = []
        self._description = []
        self._rowcount = -1
        self._closed = False
        self.arraysize = 100
    
    def execute(self, query, params=None):
        if self._closed:
            raise OperationalError("cursor is closed")
        if params:
            # Parameter substitution
            if isinstance(params, (list, tuple)):
                idx = 0
                for p in params:
                    placeholder = "%s"
                    pos = query.find(placeholder)
                    if pos >= 0:
                        if isinstance(p, str):
                            val = "'" + p.replace("'", "''") + "'"
                        elif isinstance(p, (datetime.datetime, datetime.date)):
                            val = "'" + str(p) + "'"
                        elif p is None:
                            val = "NULL"
                        else:
                            val = str(p)
                        query = query[:pos] + val + query[pos+2:]
                        idx += 1
        if self.connection._sock:
            command = query.lstrip().split(None, 1)[0].rstrip(";").upper() if query.strip() else ""
            if (not self.connection.autocommit and
                    not self.connection._in_transaction and
                    command not in ("BEGIN", "START", "COMMIT", "ROLLBACK", "END")):
                self.connection.begin()
            self.connection._execute_simple(query)
            result = self.connection._last_result
            self._results = list(result["rows"])
            self._description = list(result["description"])
            tag = result["command_tag"] or ""
            try:
                self._rowcount = int(tag.rsplit(" ", 1)[1])
            except (ValueError, IndexError):
                self._rowcount = -1
        else:
            raise OperationalError("PostgreSQL connection is not open")
        return self
    
    def executemany(self, query, param_list):
        for params in param_list:
            self.execute(query, params)
    
    def fetchone(self):
        if self._results:
            row = self._results.pop(0)
            if self.cursor_factory == RealDictCursor:
                return dict(zip([d[0] for d in self._description], row))
            elif self.cursor_factory == NamedTupleCursor:
                Row = namedtuple('Row', [d[0] for d in self._description])
                return Row(*row)
            return row
        return None
    
    def fetchall(self):
        results = []
        while True:
            row = self.fetchone()
            if row is None:
                break
            results.append(row)
        return results
    
    def fetchmany(self, size=None):
        if size is None:
            size = self.arraysize
        results = []
        for _ in range(size):
            row = self.fetchone()
            if row is None:
                break
            results.append(row)
        return results
    
    def _fetch_results(self):
        return list(self.connection._last_result["rows"])
    
    @property
    def description(self):
        return self._description
    
    @property
    def rowcount(self):
        return self._rowcount
    
    def close(self):
        self._closed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
    
    def __iter__(self):
        return self
    
    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row
    
    def copy_from(self, file, table, sep='\t', null='\\N'):
        """Basic COPY FROM implementation."""
        for line in file:
            line = line.strip()
            if line:
                values = line.split(sep)
                placeholders = ', '.join(['%s'] * len(values))
                self.execute(f"INSERT INTO {table} VALUES ({placeholders})", values)
    
    def copy_to(self, file, table, sep='\t', null='\\N'):
        """Basic COPY TO implementation."""
        self.execute(f"SELECT * FROM {table}")
        for row in self.fetchall():
            file.write(sep.join(str(v) if v is not None else null for v in row))
            file.write('\n')


class RealDictCursor:
    """Cursor factory that returns rows as dicts."""
    pass

class NamedTupleCursor:
    """Cursor factory that returns rows as named tuples."""
    pass


def connect(host="localhost", port=5432, dbname="test", user="admin", password="", **kwargs):
    """Create a psycopg2-compatible connection."""
    return connection(host=host, port=port, dbname=dbname, user=user, password=password, **kwargs)
