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
            "QIHSE_IDENTITY_DIR", "keys")
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
