"""QIHSE cluster administration SDK.

Hardened masters (pqc_require — any node with replication/migration/admin
pins) reject cleartext RESP, so the protocol-emulation adapters in this
package (qihse_http, qihse_mongo, ...) cannot reach them. This module is the
operator surface: it wraps the QKP admin CLI (`qihse-admin-cli`) and the ops
scripts so you can administer the cluster from Python.

Typical use:

    from qihse_admin import ClusterAdmin

    ca = ClusterAdmin(admin_cli="/opt/QIHSE/bin/qihse-admin-cli",
                      node_id="admin-t420",
                      identity_dir="/etc/qihse/keys")

    ca.ping("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem")
    ca.cluster_nodes("192.168.1.91", 7100, "qihse_dsa_pub_t420.pem")
    ca.set("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem", "k", "v")
    ca.moveslots("192.168.1.90", 7115, "qihse_dsa_pub_730xd.pem",
                 4916, 4916, "192.168.1.91:7100")
"""

import subprocess
from typing import List, Optional


class QihseAdminError(Exception):
    """Raised when an admin operation fails."""
    def __init__(self, message: str, exit_code: Optional[int] = None,
                 stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class ClusterAdmin:
    """Administers hardened QIHSE masters via the pinned QKP admin identity."""

    def __init__(self, admin_cli: str = "qihse-admin-cli",
                 node_id: str = "admin-t420",
                 identity_dir: str = "/etc/qihse/keys",
                 sudo: bool = False):
        self.admin_cli = admin_cli
        self.node_id = node_id
        self.identity_dir = identity_dir
        self.sudo = sudo

    def _pub_path(self, trusted_pub: str) -> str:
        # trusted_pub may be a bare filename (resolved against identity_dir)
        # or an absolute path.
        if trusted_pub.startswith("/"):
            return trusted_pub
        return f"{self.identity_dir}/{trusted_pub}"

    def _run(self, host: str, port: int, trusted_pub: str,
             command: str, *args: str) -> str:
        cmd = [self.admin_cli, "--host", host, "--port", str(port),
               "--node-id", self.node_id,
               "--identity-dir", self.identity_dir,
               "--trusted-pub", self._pub_path(trusted_pub),
               "--command", " ".join([command] + list(args))]
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
            value: str) -> str:
        return self._run(host, port, trusted_pub, "SET", key, value)

    def delete(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "DEL", key))

    # ---- cluster commands ----
    def cluster_nodes(self, host: str, port: int, trusted_pub: str) -> List[str]:
        out = self._run(host, port, trusted_pub, "CLUSTER", "NODES")
        return out.split("\n") if out else []

    def key_slot(self, host: str, port: int, trusted_pub: str, key: str) -> int:
        return int(self._run(host, port, trusted_pub, "CLUSTER", "KEYSLOT", key))

    def moveslots(self, host: str, port: int, trusted_pub: str,
                  first: int, last: int, target: str) -> str:
        """Move slot range [first,last] from `host` to `target` (host:port).

        Returns the daemon's acknowledgement line (e.g.
        'N keys moved; slots S-S now owned by host:port')."""
        return self._run(host, port, trusted_pub, "CLUSTER", "MOVESLOTS",
                         f"{first}-{last}", target)

    def repl_status(self, host: str, port: int, trusted_pub: str) -> str:
        return self._run(host, port, trusted_pub, "REPL.STATUS")


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

    def rolling_restart(self, verify_only: bool = False) -> str:
        args = ["--verify-only"] if verify_only else []
        return self._run_script("cluster_rolling_restart.sh", *args)

    def replicas(self, action: str = "status") -> str:
        return self._run_script("cluster_replica_deploy.sh", f"--{action}")

    def watchdog(self) -> str:
        return self._run_script("cluster_watchdog.sh")
