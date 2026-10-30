#!/bin/sh
# Install as "$QIHSE_PREFIX/libexec/refresh-machine-token.sh" (0755).
# Python is already required by the fan agent; never send mint output to logs.
exec python3 - <<'PY'
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(name + " is required")
    return value


def number(name):
    value = required(name)
    if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 4294967295:
        raise ValueError(name + " must be a positive decimal uint32")
    return value


def interrupted(signum, frame):
    raise RuntimeError("refresh interrupted")


for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(signum, interrupted)
os.umask(0o077)
temporary = None
try:
    user = number("QIHSE_MACHINE_USER_ID")
    tenant = number("QIHSE_MACHINE_TENANT")
    prefix = Path(required("QIHSE_PREFIX"))
    identity = Path(required("QIHSE_MACHINE_IDENTITY"))
    output = Path(required("QIHSE_MACHINE_TOKEN"))
    if not all(path.is_absolute() for path in (prefix, identity, output)):
        raise ValueError("prefix, identity and token paths must be absolute at deployment")
    # Do not allow a typo to replace the signing key, including a hardlink.
    if output.resolve() == identity.resolve() or (
            output.exists() and identity.exists() and os.path.samefile(output, identity)):
        raise ValueError("identity and token must be different files")
    if output.is_symlink() or (output.exists() and not stat.S_ISREG(output.stat().st_mode)):
        raise ValueError("token destination must be a regular file, not a symlink")
    # Parent must be provisioned by the installer, never a shared writable dir.
    parent = output.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise ValueError("token directory must be owned by the refresh user and not group/world writable")
    fd, temporary = tempfile.mkstemp(prefix=".machine-token-", dir=output.parent)
    with os.fdopen(fd, "w+b") as stream:
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = str(prefix / "lib")
        result = subprocess.run(
            [str(prefix / "bin/qihse-machine-token"), "--identity", str(identity),
             "--user-id", user, "--tenant", tenant, "--ttl-seconds", "86400"],
            stdout=stream, stderr=subprocess.DEVNULL, env=env, timeout=60, check=False)
        if result.returncode:
            raise RuntimeError("mint failed")
        stream.seek(0)
        token = stream.read(65537)
        if not re.fullmatch(rb"(?:[0-9a-f]{2})+\n", token) or len(token) > 65536:
            raise RuntimeError("invalid mint output")
        os.fchmod(stream.fileno(), 0o600)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output)
    temporary = None
except ValueError as error:
    print("machine-token refresh: " + str(error), file=sys.stderr)
    sys.exit(2)
except (OSError, RuntimeError, subprocess.SubprocessError):
    # Do not expose subprocess diagnostics, paths containing secrets, or tokens.
    print("machine-token refresh failed; existing credential retained", file=sys.stderr)
    sys.exit(1)
finally:
    if temporary is not None:
        os.unlink(temporary)
PY
