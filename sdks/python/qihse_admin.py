"""QIHSE cluster administration SDK.

Hardened masters (pqc_require — any node with replication/migration/admin
pins) reject cleartext RESP, so the protocol-emulation adapters in this
package (qihse_http, qihse_mongo, ...) cannot reach them. This module is the
operator surface: it uses the in-process C QKP client (`qihse_qkp_admin_exec`
from `libqihse.so` via ctypes) when available and readable, falling back to
`qihse-admin-cli` (for example when `sudo=True` is requested for root-only
identity keys).

Typical use:

    from qihse_admin import ClusterAdmin

    ca = ClusterAdmin(node_id="admin-t420",
                      identity_dir="keys")

    ca.ping("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem")
    ca.cluster_nodes("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem")
    ca.set("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "k", "v")
    ca.moveslots("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem",
                 4916, 4916, "192.168.1.91:7100")
    ca.reclaim("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem")
"""

import ctypes
import hashlib
import json
import os
import subprocess
import tempfile
from typing import List, Optional


class QihseAdminError(Exception):
    """Raised when an admin operation fails."""
    def __init__(self, message: str, exit_code: Optional[int] = None,
                 stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


_OWNER_SNAPSHOT_MAX_READ = 512 * 1024
_OWNER_SNAPSHOT_MAX_ERROR = 512


def _owner_snapshot_bulk(reply: bytes) -> bytes:
    """Decode one complete RESP2 bulk reply without interpreting its payload."""
    if not isinstance(reply, bytes) or not reply.startswith(b"$"):
        raise QihseAdminError("owner snapshot returned a non-bulk reply")
    line_end = reply.find(b"\r\n", 1)
    if line_end < 0:
        raise QihseAdminError("owner snapshot returned a malformed bulk header")
    length_text = reply[1:line_end]
    if (not length_text or len(length_text) > 20 or
            any(c < 48 or c > 57 for c in length_text)):
        raise QihseAdminError("owner snapshot returned a malformed bulk length")
    length = int(length_text)
    payload_start = line_end + 2
    payload_end = payload_start + length
    if payload_end + 2 != len(reply) or reply[payload_end:payload_end + 2] != b"\r\n":
        raise QihseAdminError("owner snapshot returned a truncated or oversized bulk reply")
    return reply[payload_start:payload_end]


def _owner_snapshot_manifest(reply: bytes) -> tuple[int, int]:
    """Decode the fixed `[byte_length, source_change_seq]` RESP2 manifest."""
    if (isinstance(reply, bytes) and 4 <= len(reply) <= _OWNER_SNAPSHOT_MAX_ERROR
            and reply.startswith(b"-") and reply.endswith(b"\r\n")):
        # execute_resp preserves RESP error frames. Report a complete bounded
        # error line using the same exception/exit code as execute(), without
        # attaching malformed frames or arbitrary non-error payloads.
        try:
            message = reply[1:-2].decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            if message and all(c.isprintable() for c in message):
                raise QihseAdminError(message, exit_code=5)
    if not isinstance(reply, bytes) or not reply.startswith(b"*2\r\n"):
        # Do not attach an arbitrary reply to the exception: it might contain
        # server data if a future protocol regression returns the wrong frame.
        raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
    body = reply[4:]
    fields = []
    for _ in range(2):
        if not body.startswith(b"$"):
            raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
        line_end = body.find(b"\r\n", 1)
        if line_end < 0:
            raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
        size_text = body[1:line_end]
        if (not size_text or len(size_text) > 20 or
                any(c < 48 or c > 57 for c in size_text)):
            raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
        size = int(size_text)
        start = line_end + 2
        end = start + size
        if end + 2 > len(body) or body[end:end + 2] != b"\r\n":
            raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
        fields.append(body[start:end])
        body = body[end + 2:]
    if body:
        raise QihseAdminError("owner snapshot BEGIN returned an oversized manifest")
    numbers = []
    for field in fields:
        if (not field or len(field) > 20 or
                any(c < 48 or c > 57 for c in field)):
            raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
        value = int(field)
        if value > (1 << 64) - 1:
            raise QihseAdminError("owner snapshot BEGIN returned an invalid manifest")
        numbers.append(value)
    return numbers[0], numbers[1]


def _load_native_qkp_lib(lib_path: Optional[str] = None) -> Optional[ctypes.CDLL]:
    candidates = []
    if lib_path:
        candidates.append(lib_path)
    env_lib = os.environ.get("QIHSE_LIB_PATH")
    if env_lib:
        candidates.append(env_lib)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    candidates.extend([
        os.path.join(repo_root, "libqihse.so"),
        "libqihse.so",
    ])
    for path in candidates:
        try:
            lib = ctypes.CDLL(path)
            exec_fn = lib.qihse_qkp_admin_exec
            free_fn = lib.qihse_qkp_admin_free
            exec_fn.argtypes = [
                ctypes.c_char_p,
                ctypes.c_uint16,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_char_p),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_char_p,
                ctypes.c_size_t,
            ]
            exec_fn.restype = ctypes.c_int
            free_fn.argtypes = [ctypes.c_void_p]
            free_fn.restype = None
            # Remember where this build came from: the subprocess fallback must
            # load the same library, not whatever an inherited LD_LIBRARY_PATH
            # or ldconfig resolves first.
            lib._qihse_lib_path = os.path.abspath(path)
            return lib
        except OSError:
            continue
        except AttributeError:
            continue
    return None


class ClusterAdmin:
    """Administers hardened QIHSE masters via the pinned QKP admin identity."""

    def __init__(self, admin_cli: str = "qihse-admin-cli",
                 node_id: str = "admin-t420",
                 identity_dir: Optional[str] = None,
                 sudo: bool = False,
                 lib_path: Optional[str] = None,
                 prefer_native: bool = True):
        self.admin_cli = admin_cli
        self.node_id = node_id
        self.identity_dir = identity_dir or os.environ.get(
            "QIHSE_IDENTITY_DIR",
            "keys" if os.path.exists("keys/qihse_dsa_key.pem") else "/etc/qihse/keys"
        )
        self.sudo = sudo
        self.prefer_native = prefer_native
        self._lib = _load_native_qkp_lib(lib_path) if prefer_native else None

    @property
    def is_native(self) -> bool:
        """True when backed by in-process libqihse QKP symbols."""
        return self._lib is not None and not self.sudo

    def _pub_path(self, trusted_pub: str) -> str:
        # trusted_pub may be a bare filename (resolved against identity_dir)
        # or an absolute path.
        if trusted_pub.startswith("/"):
            return trusted_pub
        return f"{self.identity_dir}/{trusted_pub}"

    def execute(self, host: str, port: int, trusted_pub: str,
                *command: str) -> str:
        """Run any RESP command supported by the QKP admin identity.

        Arguments are transmitted as independent RESP bulk strings. This is
        the parity escape hatch for commands without a dedicated convenience
        method; it does not bypass server-side authorization.
        """
        if not command or any(not isinstance(arg, str) for arg in command):
            raise ValueError("command must contain one or more string arguments")
        return self._run(host, port, trusted_pub, command[0], *command[1:])

    def session(self, host: str, port: int, trusted_pub: str, *,
                user: Optional[str] = None, password: Optional[str] = None,
                timeout_ms: int = 30000):
        """Open one pinned QKP session; optional AUTH selects a user principal.

        Requires the current native library and readable identity keys. No sudo,
        subprocess or legacy transport fallback can silently drop session state.
        """
        if not self.is_native:
            raise QihseAdminError("persistent sessions require the native QKP library")
        return QKPAdminSession(self._lib, host, port, self.node_id,
                               self.identity_dir, self._pub_path(trusted_pub),
                               user=user, password=password, timeout_ms=timeout_ms)

    def execute_typed(self, host: str, port: int, trusted_pub: str, *command,
                      user: Optional[str] = None, password: Optional[str] = None,
                      timeout_ms: int = 30000):
        """Return bytes/int/None/nested lists; raise on actual RESP errors.

        Unlike legacy execute(), accepts binary arguments and preserves empty
        strings, newlines, nulls and nested arrays. All server commands, including
        AIMEM and capability discovery, use this same authenticated path.
        """
        with self.session(host, port, trusted_pub, user=user, password=password,
                          timeout_ms=timeout_ms) as session:
            return session.execute(*command)

    def _run_native(self, host: str, port: int, trusted_pub: str,
                    command: str, *args: str) -> str:
        full_args = (command,) + args
        if any("\x00" in arg for arg in full_args):
            raise ValueError("legacy text API cannot encode NUL; use execute_typed")
        c_argv = (ctypes.c_char_p * len(full_args))(
            *(a.encode("utf-8") for a in full_args)
        )
        out_ptr = ctypes.c_void_p()
        err_buf = ctypes.create_string_buffer(512)
        rc = self._lib.qihse_qkp_admin_exec(
            host.encode("utf-8"),
            ctypes.c_uint16(port),
            self.node_id.encode("utf-8"),
            self.identity_dir.encode("utf-8"),
            self._pub_path(trusted_pub).encode("utf-8"),
            ctypes.c_size_t(len(full_args)),
            c_argv,
            ctypes.byref(out_ptr),
            err_buf,
            ctypes.c_size_t(len(err_buf)),
        )
        try:
            if rc != 0:
                err_text = err_buf.value.decode("utf-8", errors="replace")
                raise QihseAdminError(
                    f"{command} failed (exit {rc}): {err_text}",
                    exit_code=rc,
                    stderr=err_text,
                )
            if not out_ptr.value:
                return ""
            raw = ctypes.cast(out_ptr, ctypes.c_char_p).value or b""
            return raw.decode("utf-8", errors="replace").rstrip("\n")
        finally:
            if out_ptr.value:
                self._lib.qihse_qkp_admin_free(out_ptr)

    def _child_env(self) -> Optional[dict]:
        """Environment for the CLI fallback: pin the in-tree library build.

        The fallback must not silently load a different libqihse.so (an older
        system install without the QKP admin symbols) just because
        LD_LIBRARY_PATH or the loader cache resolves it first.
        """
        lib_dir = None
        if self._lib is not None:
            lib_path = getattr(self._lib, "_qihse_lib_path", None)
            if lib_path:
                lib_dir = os.path.dirname(lib_path)
        if lib_dir is None:
            # No in-process library: derive the build tree from the CLI path so
            # a bin/qihse-admin-cli still resolves <root>/libqihse.so.
            cli_dir = os.path.dirname(os.path.abspath(self.admin_cli))
            # Prefer the build root over a bin/ that may hold a stale library
            # copy, matching the CLI's own rpath order.
            for candidate in (os.path.dirname(cli_dir), cli_dir):
                if os.path.exists(os.path.join(candidate, "libqihse.so")):
                    lib_dir = candidate
                    break
        if lib_dir is None or not os.path.isdir(lib_dir):
            return None
        env = os.environ.copy()
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{existing}" if existing else lib_dir
        return env

    def _run(self, host: str, port: int, trusted_pub: str,
             command: str, *args: str) -> str:
        if self._lib is not None and not self.sudo:
            return self._run_native(host, port, trusted_pub, command, *args)
        cmd = [self.admin_cli, "--host", host, "--port", str(port),
               "--node-id", self.node_id,
               "--identity-dir", self.identity_dir,
               "--trusted-pub", self._pub_path(trusted_pub)]
        # The CLI's --arg form encodes each RESP argument as a distinct bulk
        # string; never interpolate user data into its whitespace command parser.
        for argument in (command,) + args:
            cmd.extend(("--arg", argument))
        if self.sudo:
            cmd = ["sudo"] + cmd
        # Legacy calls use the pinned identity, just like the native path;
        # ambient CLI AUTH defaults must not silently select another principal.
        env = (self._child_env() or os.environ).copy()
        env.pop("QIHSE_AUTH_USER", None)
        env.pop("QIHSE_AUTH_PASSWORD", None)
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise QihseAdminError(
                f"{command} failed (exit {proc.returncode})",
                exit_code=proc.returncode, stderr=proc.stderr)
        return proc.stdout.rstrip("\n")

    # ---- RESP/data commands ----
    def ping(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "PING")

    def get(self, host: str, port: int, trusted_pub: str, key: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "GET", key)
        return None if out == "(nil)" else out

    def set(self, host: str, port: int, trusted_pub: str, key: str,
            value: str, px: Optional[int] = None) -> str:
        if px is not None:
            return self._run(host, port, trusted_pub, "SET", key, value, "PX", str(px))
        return self._run(host, port, trusted_pub, "SET", key, value)

    def delete(self, host: str, port: int, trusted_pub: str, *keys: str) -> int:
        if not keys:
            raise ValueError("delete requires at least one key")
        return int(self._run(host, port, trusted_pub, "DEL", *keys))

    def exists(self, host: str, port: int, trusted_pub: str, *keys: str) -> int:
        if not keys:
            raise ValueError("exists requires at least one key")
        return int(self._run(host, port, trusted_pub, "EXISTS", *keys))

    def ttl_ms(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "PTTL", key))

    def info(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "INFO")

    def role(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "ROLE")

    def dbsize(self, host: str, port: int, trusted_pub: str) -> int:
        return int(self._run(host, port, trusted_pub, "DBSIZE"))

    # ---- key management (strings) ----
    def append(self, host: str, port: int, trusted_pub: str,
               key: str, value: str) -> int:
        return int(self._run(host, port, trusted_pub, "APPEND", key, value))

    def strlen(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "STRLEN", key))

    def getrange(self, host: str, port: int, trusted_pub: str,
                 key: str, start: int, end: int) -> str:
        return self._run(host, port, trusted_pub, "GETRANGE", key,
                         str(start), str(end))

    def setrange(self, host: str, port: int, trusted_pub: str,
                 key: str, offset: int, value: str) -> int:
        return int(self._run(host, port, trusted_pub, "SETRANGE", key,
                             str(offset), value))

    def getset(self, host: str, port: int, trusted_pub: str,
               key: str, value: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "GETSET", key, value)
        return None if out == "(nil)" else out

    def getdel(self, host: str, port: int, trusted_pub: str,
               key: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "GETDEL", key)
        return None if out == "(nil)" else out

    def setex(self, host: str, port: int, trusted_pub: str, key: str,
              seconds: int, value: str) -> str:
        return self._run(host, port, trusted_pub, "SETEX", key,
                         str(seconds), value)

    def psetex(self, host: str, port: int, trusted_pub: str, key: str,
               milliseconds: int, value: str) -> str:
        return self._run(host, port, trusted_pub, "PSETEX", key,
                         str(milliseconds), value)

    def incr(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "INCR", key))

    def decr(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "DECR", key))

    def incrby(self, host: str, port: int, trusted_pub: str, key: str,
               amount: int) -> int:
        return int(self._run(host, port, trusted_pub, "INCRBY", key, str(amount)))

    def decrby(self, host: str, port: int, trusted_pub: str, key: str,
               amount: int) -> int:
        return int(self._run(host, port, trusted_pub, "DECRBY", key, str(amount)))

    def incrbyfloat(self, host: str, port: int, trusted_pub: str, key: str,
                    amount: float) -> float:
        return float(self._run(host, port, trusted_pub, "INCRBYFLOAT", key,
                               repr(amount)))

    def mget(self, host: str, port: int, trusted_pub: str,
             *keys: str) -> List[Optional[str]]:
        if not keys:
            raise ValueError("mget requires at least one key")
        out = self._run(host, port, trusted_pub, "MGET", *keys)
        return [None if v == "(nil)" else v
                for v in (out.split("\n") if out else [])]

    def mset(self, host: str, port: int, trusted_pub: str,
             mapping: dict) -> str:
        if not mapping:
            raise ValueError("mset requires at least one key/value pair")
        args = []
        for k, v in mapping.items():
            args.extend([k, v])
        return self._run(host, port, trusted_pub, "MSET", *args)

    def msetnx(self, host: str, port: int, trusted_pub: str,
               mapping: dict) -> int:
        if not mapping:
            raise ValueError("msetnx requires at least one key/value pair")
        args = []
        for k, v in mapping.items():
            args.extend([k, v])
        return int(self._run(host, port, trusted_pub, "MSETNX", *args))

    # ---- key management (generic/keyspace) ----
    def type(self, host: str, port: int, trusted_pub: str, key: str) -> str:
        return self._run(host, port, trusted_pub, "TYPE", key)

    def ttl(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "TTL", key))

    def expire(self, host: str, port: int, trusted_pub: str, key: str,
               seconds: int) -> int:
        return int(self._run(host, port, trusted_pub, "EXPIRE", key, str(seconds)))

    def pexpire(self, host: str, port: int, trusted_pub: str, key: str,
                milliseconds: int) -> int:
        return int(self._run(host, port, trusted_pub, "PEXPIRE", key,
                             str(milliseconds)))

    def expireat(self, host: str, port: int, trusted_pub: str, key: str,
                 unix_seconds: int) -> int:
        return int(self._run(host, port, trusted_pub, "EXPIREAT", key,
                             str(unix_seconds)))

    def pexpireat(self, host: str, port: int, trusted_pub: str, key: str,
                  unix_ms: int) -> int:
        return int(self._run(host, port, trusted_pub, "PEXPIREAT", key,
                             str(unix_ms)))

    def persist(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "PERSIST", key))

    def rename(self, host: str, port: int, trusted_pub: str, key: str,
               new_key: str) -> str:
        return self._run(host, port, trusted_pub, "RENAME", key, new_key)

    def renamenx(self, host: str, port: int, trusted_pub: str, key: str,
                 new_key: str) -> int:
        return int(self._run(host, port, trusted_pub, "RENAMENX", key, new_key))

    def copy(self, host: str, port: int, trusted_pub: str, src: str,
             dst: str, replace: bool = False) -> int:
        args = ["COPY", src, dst]
        if replace:
            args.append("REPLACE")
        return int(self._run(host, port, trusted_pub, *args))

    def touch(self, host: str, port: int, trusted_pub: str, *keys: str) -> int:
        if not keys:
            raise ValueError("touch requires at least one key")
        return int(self._run(host, port, trusted_pub, "TOUCH", *keys))

    def unlink(self, host: str, port: int, trusted_pub: str, *keys: str) -> int:
        if not keys:
            raise ValueError("unlink requires at least one key")
        return int(self._run(host, port, trusted_pub, "UNLINK", *keys))

    def keys(self, host: str, port: int, trusted_pub: str,
             pattern: str = "*") -> List[str]:
        out = self._run(host, port, trusted_pub, "KEYS", pattern)
        return [k for k in out.split("\n") if k] if out else []

    def scan(self, host: str, port: int, trusted_pub: str,
             cursor: int = 0, match: Optional[str] = None,
             count: Optional[int] = None) -> str:
        args = ["SCAN", str(cursor)]
        if match is not None:
            args.extend(["MATCH", match])
        if count is not None:
            args.extend(["COUNT", str(count)])
        return self._run(host, port, trusted_pub, *args)

    def randomkey(self, host: str, port: int, trusted_pub: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "RANDOMKEY")
        return None if out == "(nil)" else out

    def object(self, host: str, port: int, trusted_pub: str,
               subcommand: str, key: str) -> str:
        return self._run(host, port, trusted_pub, "OBJECT", subcommand, key)

    # ---- key management (hashes) ----
    def hset(self, host: str, port: int, trusted_pub: str, key: str,
             field: str, value: str) -> int:
        return int(self._run(host, port, trusted_pub, "HSET", key, field, value))

    def hget(self, host: str, port: int, trusted_pub: str, key: str,
             field: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "HGET", key, field)
        return None if out == "(nil)" else out

    def hmset(self, host: str, port: int, trusted_pub: str, key: str,
              mapping: dict) -> str:
        args = [key]
        for f, v in mapping.items():
            args.extend([f, v])
        return self._run(host, port, trusted_pub, "HMSET", *args)

    def hmget(self, host: str, port: int, trusted_pub: str, key: str,
              *fields: str) -> List[Optional[str]]:
        out = self._run(host, port, trusted_pub, "HMGET", key, *fields)
        return [None if v == "(nil)" else v
                for v in (out.split("\n") if out else [])]

    def hgetall(self, host: str, port: int, trusted_pub: str,
                key: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "HGETALL", key)
        return [v for v in out.split("\n") if v] if out else []

    def hdel(self, host: str, port: int, trusted_pub: str, key: str,
             *fields: str) -> int:
        if not fields:
            raise ValueError("hdel requires at least one field")
        return int(self._run(host, port, trusted_pub, "HDEL", key, *fields))

    def hexists(self, host: str, port: int, trusted_pub: str, key: str,
                field: str) -> int:
        return int(self._run(host, port, trusted_pub, "HEXISTS", key, field))

    def hkeys(self, host: str, port: int, trusted_pub: str,
              key: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "HKEYS", key)
        return [v for v in out.split("\n") if v] if out else []

    def hvals(self, host: str, port: int, trusted_pub: str,
              key: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "HVALS", key)
        return [v for v in out.split("\n") if v] if out else []

    def hlen(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "HLEN", key))

    def hincrby(self, host: str, port: int, trusted_pub: str, key: str,
                field: str, amount: int) -> int:
        return int(self._run(host, port, trusted_pub, "HINCRBY", key, field,
                             str(amount)))

    def hsetnx(self, host: str, port: int, trusted_pub: str, key: str,
               field: str, value: str) -> int:
        return int(self._run(host, port, trusted_pub, "HSETNX", key, field, value))

    def hstrlen(self, host: str, port: int, trusted_pub: str, key: str,
                field: str) -> int:
        return int(self._run(host, port, trusted_pub, "HSTRLEN", key, field))

    # ---- key management (lists) ----
    def lpush(self, host: str, port: int, trusted_pub: str, key: str,
              *values: str) -> int:
        return int(self._run(host, port, trusted_pub, "LPUSH", key, *values))

    def rpush(self, host: str, port: int, trusted_pub: str, key: str,
              *values: str) -> int:
        return int(self._run(host, port, trusted_pub, "RPUSH", key, *values))

    def lpop(self, host: str, port: int, trusted_pub: str, key: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "LPOP", key)
        return None if out == "(nil)" else out

    def rpop(self, host: str, port: int, trusted_pub: str, key: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "RPOP", key)
        return None if out == "(nil)" else out

    def llen(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "LLEN", key))

    def lrange(self, host: str, port: int, trusted_pub: str, key: str,
               start: int, stop: int) -> List[str]:
        out = self._run(host, port, trusted_pub, "LRANGE", key,
                        str(start), str(stop))
        return [v for v in out.split("\n") if v] if out else []

    def lindex(self, host: str, port: int, trusted_pub: str, key: str,
               index: int) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "LINDEX", key, str(index))
        return None if out == "(nil)" else out

    def lset(self, host: str, port: int, trusted_pub: str, key: str,
             index: int, value: str) -> str:
        return self._run(host, port, trusted_pub, "LSET", key, str(index), value)

    def lrem(self, host: str, port: int, trusted_pub: str, key: str,
             count: int, value: str) -> int:
        return int(self._run(host, port, trusted_pub, "LREM", key,
                             str(count), value))

    def ltrim(self, host: str, port: int, trusted_pub: str, key: str,
              start: int, stop: int) -> str:
        return self._run(host, port, trusted_pub, "LTRIM", key,
                         str(start), str(stop))

    def linsert(self, host: str, port: int, trusted_pub: str, key: str,
                where: str, pivot: str, value: str) -> int:
        return int(self._run(host, port, trusted_pub, "LINSERT", key,
                             where, pivot, value))

    def rpoplpush(self, host: str, port: int, trusted_pub: str,
                  src: str, dst: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "RPOPLPUSH", src, dst)
        return None if out == "(nil)" else out

    # ---- key management (sets) ----
    def sadd(self, host: str, port: int, trusted_pub: str, key: str,
             *members: str) -> int:
        return int(self._run(host, port, trusted_pub, "SADD", key, *members))

    def srem(self, host: str, port: int, trusted_pub: str, key: str,
             *members: str) -> int:
        return int(self._run(host, port, trusted_pub, "SREM", key, *members))

    def smembers(self, host: str, port: int, trusted_pub: str,
                 key: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "SMEMBERS", key)
        return [v for v in out.split("\n") if v] if out else []

    def sismember(self, host: str, port: int, trusted_pub: str, key: str,
                  member: str) -> int:
        return int(self._run(host, port, trusted_pub, "SISMEMBER", key, member))

    def scard(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "SCARD", key))

    def spop(self, host: str, port: int, trusted_pub: str, key: str,
             count: Optional[int] = None) -> str:
        if count is None:
            return self._run(host, port, trusted_pub, "SPOP", key)
        return self._run(host, port, trusted_pub, "SPOP", key, str(count))

    def smove(self, host: str, port: int, trusted_pub: str,
              src: str, dst: str, member: str) -> int:
        return int(self._run(host, port, trusted_pub, "SMOVE", src, dst, member))

    def sdiff(self, host: str, port: int, trusted_pub: str,
              *keys: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "SDIFF", *keys)
        return [v for v in out.split("\n") if v] if out else []

    def sinter(self, host: str, port: int, trusted_pub: str,
               *keys: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "SINTER", *keys)
        return [v for v in out.split("\n") if v] if out else []

    def sunion(self, host: str, port: int, trusted_pub: str,
               *keys: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "SUNION", *keys)
        return [v for v in out.split("\n") if v] if out else []

    def srandmember(self, host: str, port: int, trusted_pub: str, key: str,
                    count: Optional[int] = None) -> str:
        if count is None:
            return self._run(host, port, trusted_pub, "SRANDMEMBER", key)
        return self._run(host, port, trusted_pub, "SRANDMEMBER", key, str(count))

    # ---- key management (sorted sets) ----
    def zadd(self, host: str, port: int, trusted_pub: str, key: str,
             mapping: dict) -> int:
        args = [key]
        for member, score in mapping.items():
            args.extend([str(score), member])
        return int(self._run(host, port, trusted_pub, "ZADD", *args))

    def zrem(self, host: str, port: int, trusted_pub: str, key: str,
             *members: str) -> int:
        return int(self._run(host, port, trusted_pub, "ZREM", key, *members))

    def zscore(self, host: str, port: int, trusted_pub: str, key: str,
               member: str) -> Optional[str]:
        out = self._run(host, port, trusted_pub, "ZSCORE", key, member)
        return None if out == "(nil)" else out

    def zcard(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "ZCARD", key))

    def zcount(self, host: str, port: int, trusted_pub: str, key: str,
               min_score: str, max_score: str) -> int:
        return int(self._run(host, port, trusted_pub, "ZCOUNT", key,
                             min_score, max_score))

    def zincrby(self, host: str, port: int, trusted_pub: str, key: str,
                amount: float, member: str) -> str:
        return self._run(host, port, trusted_pub, "ZINCRBY", key,
                         repr(amount), member)

    def zrange(self, host: str, port: int, trusted_pub: str, key: str,
               start: int, stop: int, withscores: bool = False) -> List[str]:
        args = ["ZRANGE", key, str(start), str(stop)]
        if withscores:
            args.append("WITHSCORES")
        out = self._run(host, port, trusted_pub, *args)
        return [v for v in out.split("\n") if v] if (out and not withscores) else out

    def zrevrange(self, host: str, port: int, trusted_pub: str, key: str,
                  start: int, stop: int, withscores: bool = False) -> List[str]:
        args = ["ZREVRANGE", key, str(start), str(stop)]
        if withscores:
            args.append("WITHSCORES")
        out = self._run(host, port, trusted_pub, *args)
        return [v for v in out.split("\n") if v] if (out and not withscores) else out

    def zrank(self, host: str, port: int, trusted_pub: str, key: str,
              member: str) -> Optional[int]:
        out = self._run(host, port, trusted_pub, "ZRANK", key, member)
        return None if out == "(nil)" else int(out)

    def zrevrank(self, host: str, port: int, trusted_pub: str, key: str,
                 member: str) -> Optional[int]:
        out = self._run(host, port, trusted_pub, "ZREVRANK", key, member)
        return None if out == "(nil)" else int(out)

    def zpopmax(self, host: str, port: int, trusted_pub: str, key: str,
                count: Optional[int] = None) -> str:
        if count is None:
            return self._run(host, port, trusted_pub, "ZPOPMAX", key)
        return self._run(host, port, trusted_pub, "ZPOPMAX", key, str(count))

    def zpopmin(self, host: str, port: int, trusted_pub: str, key: str,
                count: Optional[int] = None) -> str:
        if count is None:
            return self._run(host, port, trusted_pub, "ZPOPMIN", key)
        return self._run(host, port, trusted_pub, "ZPOPMIN", key, str(count))

    def zrangebyscore(self, host: str, port: int, trusted_pub: str, key: str,
                      min_score: str, max_score: str,
                      withscores: bool = False) -> str:
        args = ["ZRANGEBYSCORE", key, min_score, max_score]
        if withscores:
            args.append("WITHSCORES")
        return self._run(host, port, trusted_pub, *args)

    def zrevrangebyscore(self, host: str, port: int, trusted_pub: str, key: str,
                         max_score: str, min_score: str,
                         withscores: bool = False) -> str:
        args = ["ZREVRANGEBYSCORE", key, max_score, min_score]
        if withscores:
            args.append("WITHSCORES")
        return self._run(host, port, trusted_pub, *args)

    # ---- key management (bitmaps + hyperloglog) ----
    def setbit(self, host: str, port: int, trusted_pub: str, key: str,
               offset: int, value: int) -> int:
        return int(self._run(host, port, trusted_pub, "SETBIT", key,
                             str(offset), str(value)))

    def getbit(self, host: str, port: int, trusted_pub: str, key: str,
               offset: int) -> int:
        return int(self._run(host, port, trusted_pub, "GETBIT", key, str(offset)))

    def bitcount(self, host: str, port: int, trusted_pub: str, key: str,
                 start: Optional[int] = None, end: Optional[int] = None) -> int:
        args = ["BITCOUNT", key]
        if start is not None and end is not None:
            args.extend([str(start), str(end)])
        return int(self._run(host, port, trusted_pub, *args))

    def bitpos(self, host: str, port: int, trusted_pub: str, key: str,
               bit: int, start: Optional[int] = None,
               end: Optional[int] = None) -> int:
        args = ["BITPOS", key, str(bit)]
        if start is not None:
            args.append(str(start))
        if end is not None:
            args.append(str(end))
        return int(self._run(host, port, trusted_pub, *args))

    def bitop(self, host: str, port: int, trusted_pub: str, operation: str,
              destkey: str, *keys: str) -> int:
        if not keys:
            raise ValueError("bitop requires at least one source key")
        return int(self._run(host, port, trusted_pub, "BITOP", operation,
                             destkey, *keys))

    def pfadd(self, host: str, port: int, trusted_pub: str, key: str,
              *elements: str) -> int:
        return int(self._run(host, port, trusted_pub, "PFADD", key, *elements))

    def pfcount(self, host: str, port: int, trusted_pub: str, *keys: str) -> int:
        if not keys:
            raise ValueError("pfcount requires at least one key")
        return int(self._run(host, port, trusted_pub, "PFCOUNT", *keys))

    def pfmerge(self, host: str, port: int, trusted_pub: str, destkey: str,
                *sourcekeys: str) -> str:
        if not sourcekeys:
            raise ValueError("pfmerge requires at least one source key")
        return self._run(host, port, trusted_pub, "PFMERGE", destkey, *sourcekeys)

    # ---- cluster commands ----
    def cluster_nodes(self, host: str, port: int, trusted_pub: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "CLUSTER", "NODES")
        return out.split("\n") if out else []

    def cluster_info(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "CLUSTER", "INFO")

    def cluster_slots(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "CLUSTER", "SLOTS")

    def cluster_myid(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "CLUSTER", "MYID")

    def cluster_meet(self, host: str, port: int, trusted_pub: str,
                     peer_ip: str, peer_port: int,
                     peer_bus_port: Optional[int] = None) -> str:
        args = ["CLUSTER", "MEET", peer_ip, str(peer_port)]
        if peer_bus_port is not None:
            args.append(str(peer_bus_port))
        return self._run(host, port, trusted_pub, *args)

    def key_slot(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "CLUSTER", "KEYSLOT", key))

    def moveslots(self, host: str, port: int, trusted_pub: str,
                  first: int, last: int, target: str) -> str:
        """Move slot range [first,last] from `host` to `target` (host:port).

        Returns the daemon's acknowledgement line (e.g.
        'N keys moved; slots S-S now owned by host:port')."""
        return self._run(host, port, trusted_pub, "CLUSTER", "MOVESLOTS",
                         f"{first}-{last}", target)

    def reclaim(self, host: str, port: int, trusted_pub: str,
                limit: int = 4096) -> int:
        """Reclaim up to `limit` stale foreign-slot keys on `host`."""
        return int(self._run(host, port, trusted_pub, "CLUSTER", "RECLAIM",
                             str(limit)))

    def repl_status(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "REPL.STATUS")

    def consensus_status(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "QIHSE.CONSENSUS.STATUS")

    def metrics_render(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "METRICS.RENDER")


class ClusterOps:
    """Wraps the cluster operations scripts."""

    def __init__(self, repo_root: Optional[str] = None):
        import os
        self.repo_root = repo_root or os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))

    def _script(self, name: str) -> str:
        return f"{self.repo_root}/scripts/{name}"

    def _run_script(self, name: str, *args: str) -> str:
        proc = subprocess.run([self._script(name)] + list(args),
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise QihseAdminError(f"{name} failed (exit {proc.returncode})",
                                  exit_code=proc.returncode, stderr=proc.stderr)
        return proc.stdout

    def rolling_restart(self, verify_only: bool = False,
                        nodes: Optional[List[str]] = None) -> str:
        args = ["--verify-only"] if verify_only else []
        for n in (nodes or []):
            args.extend(["--node", n])
        return self._run_script("cluster_rolling_restart.sh", *args)

    def replicas(self, action: str = "status") -> str:
        if action in ("deploy", ""):
            return self._run_script("cluster_replica_deploy.sh")
        if action in ("status", "remove"):
            return self._run_script("cluster_replica_deploy.sh", f"--{action}")
        raise ValueError(f"unsupported replica action: {action}")

    def watchdog(self) -> str:
        return self._run_script("cluster_watchdog.sh")


class QKPAdminSession:
    """Synchronous, single-caller QKP session. Use as a context manager.

    No automatic replay, reconnect or MOVED/ASK following. AUTH is never replaced
    with an operator identity when rejected. Raw replies are available for adapters
    that need RESP framing rather than the typed execute() result.
    """

    def __init__(self, lib, host, port, node_id, identity_dir, trusted_pub, *,
                 user=None, password=None, timeout_ms=30000):
        self._lib = lib
        self._client = ctypes.c_void_p()
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be in 1..65535")
        if not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 2147483647:
            raise ValueError("timeout_ms must be in 1..2147483647")
        if (user is None) != (password is None):
            raise ValueError("user and password must be supplied together")
        config = (host, node_id, identity_dir, trusted_pub)
        if any(not isinstance(s, str) or not s or "\u0000" in s for s in config):
            raise ValueError("connection arguments must be nonempty NUL-free strings")
        try:
            open_fn = lib.qihse_qkp_admin_open
            command_fn = lib.qihse_qkp_admin_command
            close_fn = lib.qihse_qkp_admin_close
            format_fn = lib.qihse_qkp_admin_format
        except AttributeError as exc:
            raise QihseAdminError("native library lacks persistent admin API; rebuild libqihse") from exc
        open_fn.argtypes = [ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p,
                            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint,
                            ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_size_t]
        open_fn.restype = ctypes.c_int
        command_fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_size_t),
                               ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
                               ctypes.c_char_p, ctypes.c_size_t]
        command_fn.restype = ctypes.c_int
        close_fn.argtypes = [ctypes.c_void_p]
        close_fn.restype = None
        format_fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_bool,
                              ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t),
                              ctypes.POINTER(ctypes.c_bool)]
        format_fn.restype = ctypes.c_int
        error = ctypes.create_string_buffer(512)
        rc = open_fn(host.encode(), port, node_id.encode(), identity_dir.encode(),
                     trusted_pub.encode(), timeout_ms, ctypes.byref(self._client), error, len(error))
        if rc:
            raise QihseAdminError(error.value.decode("utf-8", "replace"), exit_code=rc)
        if user is not None:
            try:
                if self.execute_resp("AUTH", user, password) != b"+OK\r\n":
                    raise QihseAdminError("AUTH rejected", exit_code=5)
            except BaseException:
                self.close()
                raise

    def close(self):
        if self._client.value:
            self._lib.qihse_qkp_admin_close(self._client)
            self._client = ctypes.c_void_p()

    def __enter__(self):
        if not self._client.value:
            raise QihseAdminError("session is closed")
        return self

    def __exit__(self, *_):
        self.close()

    def execute_resp(self, *command):
        """Return exact RESP bytes, including error replies; str args use UTF-8."""
        if not self._client.value:
            raise QihseAdminError("session is closed")
        if not command or any(not isinstance(a, (str, bytes)) for a in command):
            raise ValueError("command requires str or bytes arguments")
        args = tuple(a.encode("utf-8") if isinstance(a, str) else a for a in command)
        argv = (ctypes.c_char_p * len(args))(*args)
        lengths = (ctypes.c_size_t * len(args))(*(len(a) for a in args))
        reply = ctypes.c_void_p()
        size = ctypes.c_size_t()
        error = ctypes.create_string_buffer(512)
        rc = self._lib.qihse_qkp_admin_command(self._client, len(args), argv, lengths,
                                              ctypes.byref(reply), ctypes.byref(size), error, len(error))
        try:
            if rc:
                if rc == 5:
                    self.close()
                raise QihseAdminError(error.value.decode("utf-8", "replace"), exit_code=rc)
            return ctypes.string_at(reply, size.value)
        finally:
            self._lib.qihse_qkp_admin_free(reply)

    def _stream_owner_snapshot(self, output_path, *, mode, chunk_size):
        """Stream one immutable OWNER.SNAPSHOT to a mode-0600 file atomically.

        ``inventory`` is the default live-data inventory and is not a restore
        backup. ``backup`` requests the self-describing BACKUP_OWNER_DATA
        container; restoring that container is a separate operation against a
        fresh CT-disabled store. The session must already be authenticated as
        an authorized system Operator and remains pinned for the whole stream.

        The method retains at most one bounded RESP chunk in memory. On any
        failure it removes the temporary file and attempts SNAPSHOT.END; the
        destination is replaced only after the announced byte count, fsync,
        and END all succeed. Returns size, source change sequence, and SHA-256
        metadata without retaining or logging the payload.
        """
        if not self._client.value:
            raise QihseAdminError("session is closed")
        if mode not in ("inventory", "backup"):
            raise ValueError("mode must be 'inventory' or 'backup'")
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or not 1 <= chunk_size <= _OWNER_SNAPSHOT_MAX_READ:
            raise ValueError("chunk_size must be in 1..524288")
        path_value = os.fspath(output_path)
        if not isinstance(path_value, str):
            raise TypeError("output_path must be a string or PathLike[str]")
        path = os.path.abspath(path_value)
        if not os.path.basename(path):
            raise ValueError("output_path must name a file")
        parent = os.path.dirname(path)
        mode_arg = ("BACKUP",) if mode == "backup" else ()

        fd = None
        temporary = None
        begun = False
        try:
            try:
                begin_reply = self.execute_resp("OWNER.SNAPSHOT.BEGIN", *mode_arg)
            except BaseException:
                # The server may have created its session-pinned snapshot
                # before transport/protocol failure obscured the reply. Drop
                # this connection so server-side session cleanup releases it.
                self.close()
                raise
            # The server may have created the snapshot even if its response is
            # malformed or truncated, so try END for every returned BEGIN.
            begun = not begin_reply.startswith(b"-")
            byte_length, source_change_seq = _owner_snapshot_manifest(begin_reply)

            # Create the private staging file next to the destination so
            # os.replace is atomic on the target filesystem.
            fd, temporary = tempfile.mkstemp(
                prefix="." + os.path.basename(path) + ".",
                suffix=".partial", dir=parent)
            digest = hashlib.sha256()
            offset = 0
            with os.fdopen(fd, "wb", closefd=True) as stream:
                fd = None
                while offset < byte_length:
                    wanted = min(chunk_size, byte_length - offset)
                    chunk_reply = self.execute_resp(
                        "OWNER.SNAPSHOT.READ", str(offset), str(wanted))
                    chunk = _owner_snapshot_bulk(chunk_reply)
                    if len(chunk) != wanted:
                        raise QihseAdminError("owner snapshot returned a short chunk")
                    stream.write(chunk)
                    digest.update(chunk)
                    offset += len(chunk)
                stream.flush()
                os.fsync(stream.fileno())

            end_reply = self.execute_resp("OWNER.SNAPSHOT.END")
            if end_reply != b"+OK\r\n":
                raise QihseAdminError("owner snapshot END failed")
            begun = False
            os.replace(temporary, path)
            temporary = None
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            return {
                "path": path,
                "mode": mode,
                "size": byte_length,
                "source_change_seq": source_change_seq,
                "sha256": digest.hexdigest(),
            }
        finally:
            if fd is not None:
                os.close(fd)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
            if begun:
                try:
                    end_reply = self.execute_resp("OWNER.SNAPSHOT.END")
                    if end_reply != b"+OK\r\n":
                        self.close()
                except BaseException:
                    # Preserve the original stream/write failure. The server
                    # drops its handle when this authenticated session closes.
                    # A failed END leaves no safe way to reuse this connection.
                    self.close()

    def owner_inventory(self, output_path, *, chunk_size=_OWNER_SNAPSHOT_MAX_READ):
        """Write a live owner data inventory (not a restore backup) to a file."""
        return self._stream_owner_snapshot(
            output_path, mode="inventory", chunk_size=chunk_size)

    def backup_owner_data(self, output_path, *, chunk_size=_OWNER_SNAPSHOT_MAX_READ):
        """Write an online BACKUP_OWNER_DATA container to a private file.

        Requires server support for ``OWNER.SNAPSHOT.BEGIN BACKUP``. Restore
        only through the existing backup restore tooling into a fresh,
        CT-disabled store; this does not resume CT journals or cursors.
        """
        return self._stream_owner_snapshot(
            output_path, mode="backup", chunk_size=chunk_size)

    def execute(self, *command):
        """Return bytes/int/None/list, raising on errors even inside arrays."""
        reply = self.execute_resp(*command)
        output = ctypes.c_void_p()
        size = ctypes.c_size_t()
        error = ctypes.c_bool()
        rc = self._lib.qihse_qkp_admin_format(reply, len(reply), True,
                                             ctypes.byref(output), ctypes.byref(size), ctypes.byref(error))
        try:
            if rc:
                raise QihseAdminError("invalid RESP reply or formatting failure", exit_code=rc)
            value = json.loads(ctypes.string_at(output, size.value))
        finally:
            self._lib.qihse_qkp_admin_free(output)

        def convert(item):
            if isinstance(item, dict):
                raise QihseAdminError(item["error"], exit_code=5)
            if isinstance(item, list):
                return [convert(child) for child in item]
            if isinstance(item, str):
                return item.encode("latin-1")
            return item

        return convert(value)
