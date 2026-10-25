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
import os
import subprocess
from typing import List, Optional


class QihseAdminError(Exception):
    """Raised when an admin operation fails."""
    def __init__(self, message: str, exit_code: Optional[int] = None,
                 stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


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

    def _run_native(self, host: str, port: int, trusted_pub: str,
                    command: str, *args: str) -> str:
        full_args = (command,) + args
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
        proc = subprocess.run(cmd, capture_output=True, text=True)
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
