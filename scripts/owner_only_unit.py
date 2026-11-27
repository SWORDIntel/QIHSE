#!/usr/bin/env python3
"""Render/check the three-host owner-only systemd override from the live unit.

Keep unrelated authentication and application flags from the effective unit;
replace only CT/replica membership, owner slot map, and data directory. Neither
service credentials nor protected KV files are read by this installer.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tempfile

OWNERS = {
    "a": ("qihse-node0.service", 0, "192.168.1.91", 7100, 17100,
          "recovery-20261109/a-owner-only-20261127", "0-5039"),
    "c": ("qihse-node1.service", 4, "192.168.1.250", 7101, 17101,
          "recovery-20261109/c-owner-only-20261127", "5461-10921"),
    "b": ("qihse-node5-host.service", 2, "192.168.1.90", 7115, 17115,
          "b-owner-only-20261127", "10922-16383"),
}
ONE = {
    "--index", "--bind", "--port", "--bus-port", "--dir", "--pqc-identity-dir",
    "--pqc-node-id", "--admin-peer-node-id", "--admin-peer-dsa-pub",
    "--machine-principal-id", "--machine-principal-tenant",
    "--replication-principal-id", "--replication-principal-clearance",
    "--replication-principal-sci", "--pqc-trusted-pub",
}
REMOVE_ONE = {
    "--ct-role", "--ct-peer", "--ct-generation", "--ct-log-limit",
    "--ct-ack-timeout-ms", "--ct-auto-successor", "--ct1-recovery-frozen-root",
    "--replication-peer-node-id", "--replication-peer-dsa-pub", "--replica-of",
    "--slot-range", "--slot-range-of", "--node",
}
TWO = {"--topology-qkp-map", "--migration-peer", "--replication-allowed-peer"}
ZERO = {"--pqc-require", "--consensus-authority-proposals", "--require-signed-ops"}
DROPIN = "zzzzzzzzzzzzzz-owneronly-20261127.conf"
OTHER_UNITS = {
    "a": ("qihse-ct-successor-b.service", "qihse-replica-kp14.service", "qihse-replica-keystone.service"),
    "c": ("qihse-ct-successor-a.service", "qihse-replica-sabot.service", "qihse-replica-tool.service"),
    "b": ("qihse-ct-successor-c.service", "qihse-replica-audit.service", "qihse-replica-chain.service"),
}


def parse_effective(text):
    match = re.search(r"argv\[\]=(.*?) ; ignore_errors=", text)
    if not match:
        raise ValueError("systemd did not provide an effective ExecStart argv")
    return shlex.split(match.group(1))


def render(label, args, data_root):
    unit, self_index, self_host, port, bus_port, suffix, self_slots = OWNERS[label]
    data_dir = data_root / suffix
    if not data_dir.is_dir() or (data_dir / "ct-state.bin").exists():
        raise ValueError("expected existing CT-disabled owner store: " + str(data_dir))
    daemon = next((arg for arg in args[:3] if arg.endswith("/bin/qihse-cluster-daemon")), None)
    if daemon is None or Path(daemon).parents[1].name != "QIHSE":
        raise ValueError("effective unit must use the canonical QIHSE runtime")
    env_executable = shutil.which("env")
    if env_executable and args[0] == env_executable:
        if args[:3] != [env_executable, "LD_LIBRARY_PATH=" + str(Path(daemon).parents[1] / "lib"), daemon]:
            raise ValueError("unexpected daemon environment wrapper")
    elif args[0] != daemon:
        raise ValueError("unexpected daemon prefix")
    expected = ["--index", str(self_index), "--bind", self_host, "--port", str(port),
                "--bus-port", str(bus_port)]
    for flag, value in zip(expected[::2], expected[1::2]):
        if args.count(flag) != 1 or args[args.index(flag) + 1] != value:
            raise ValueError("owner endpoint differs from the three-host manifest: " + flag)

    output = []
    i = 0
    while i < len(args):
        flag = args[i]
        if not flag.startswith("--"):
            if i >= 3 or flag not in (env_executable, daemon, "LD_LIBRARY_PATH=" + str(Path(daemon).parents[1] / "lib")):
                raise ValueError("unreviewed positional daemon argument")
            output.append(flag)
            i += 1
        elif flag in ONE | REMOVE_ONE:
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                raise ValueError("invalid value for " + flag)
            if flag == "--dir":
                output.extend((flag, str(data_dir)))
            elif flag in ONE:
                output.extend(args[i:i + 2])
            i += 2
        elif flag in TWO:
            if i + 2 >= len(args) or args[i + 1].startswith("--") or args[i + 2].startswith("--"):
                raise ValueError("invalid peer mapping for " + flag)
            identity = args[i + 2] if flag == "--topology-qkp-map" else args[i + 1]
            if identity.startswith("recovery-"):
                pass
            elif identity in {owner[2] for owner in OWNERS.values()}:
                output.extend(args[i:i + 3])
            else:
                raise ValueError("unrecognized owner peer identity for " + flag)
            i += 3
        elif flag in ZERO:
            output.append(flag)
            i += 1
        else:
            raise ValueError("unreviewed daemon flag: " + flag)

    for peer in ("a", "b", "c"):
        _, index, host, peer_port, peer_bus, _, slots = OWNERS[peer]
        output.extend(("--node", f"{index}:{host}:{peer_port}:{peer_bus}"))
        if peer != label:
            output.extend(("--slot-range-of", f"{index}:{slots}"))
    output.extend(("--node", f"7:{OWNERS['a'][2]}:{OWNERS['a'][3]}:{OWNERS['a'][4]}",
                   "--slot-range-of", "7:5041-5460"))
    output.extend(("--node", f"6:{OWNERS['b'][2]}:{OWNERS['b'][3]}:{OWNERS['b'][4]}",
                   "--slot-range-of", "6:5040-5040", "--slot-range", self_slots))
    if any(arg.startswith("--ct-") or arg == "--replica-of" for arg in output):
        raise ValueError("CT/replica arguments remained in owner-only unit")
    return "[Service]\nExecStart=\nExecStart=" + " ".join(shlex.quote(arg) for arg in output) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label", choices=OWNERS)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="compare to the installed override")
    action.add_argument("--install", action="store_true", help="atomically update the override; never restart")
    data_root = os.environ.get("QIHSE_OWNER_DATA_ROOT")
    if data_root is None:
        data_root = Path(__file__).resolve().parent.parent.parent / "qihse-data"
    parser.add_argument("--data-root", type=Path, default=Path(data_root))
    args = parser.parse_args(argv)
    unit = OWNERS[args.label][0]
    def state(property_name, name):
        return subprocess.check_output(["systemctl", "show", "-P", property_name, name], text=True).strip()
    for other in OTHER_UNITS[args.label]:
        if (state("ActiveState", other), state("UnitFileState", other)) != ("inactive", "disabled"):
            raise ValueError("CT/namespace service is not inactive and disabled: " + other)
    if args.check and (state("ActiveState", unit), state("UnitFileState", unit)) != ("active", "enabled"):
        raise ValueError("owner unit must be active and enabled: " + unit)
    effective = subprocess.check_output(["systemctl", "show", "-P", "ExecStart", unit], text=True)
    rendered = render(args.label, parse_effective(effective), args.data_root)
    fragment = subprocess.check_output(["systemctl", "show", "-P", "FragmentPath", unit], text=True).strip()
    if not fragment or not Path(fragment).is_file():
        raise ValueError("systemd unit fragment unavailable")
    dropin = Path(fragment).parent / (unit + ".d") / DROPIN
    if args.check:
        if not dropin.is_file() or dropin.read_text() != rendered:
            raise ValueError("installed owner-only override differs from the manifest: " + str(dropin))
        print(unit, "owner-only override matches the Git manifest")
        return 0
    dropin.parent.mkdir(mode=0o755, exist_ok=True)
    if dropin.is_file() and dropin.read_text() == rendered:
        print(unit, "already matches; no restart or write")
        return 0
    if dropin.exists():
        raise ValueError("refusing to replace a divergent override without review: " + str(dropin))
    fd, temp = tempfile.mkstemp(prefix=".owner-only-", dir=dropin.parent)
    try:
        with os.fdopen(fd, "w") as file:
            os.fchmod(file.fileno(), 0o600)
            file.write(rendered)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp, dropin)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(unit, "owner-only override installed; restart only in a coordinated rollout")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("owner-only unit: " + str(exc), file=sys.stderr)
        sys.exit(1)
