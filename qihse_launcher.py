#!/usr/bin/env python3
"""
QIHSE Launcher — Unified entry point for the QIHSE vector engine.

Dispatches subcommands to the appropriate Makefile targets, scripts, or
direct library calls.  Mirrors the FRAMEWERX ``fw`` launcher pattern.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT / "scripts"
LIBQIHSE = ROOT / "libqihse.so"


# ── Helpers ──────────────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: str | None = None, env: dict | None = None) -> int:
    """Run a command, streaming output to the terminal. Returns exit code."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    full_env.setdefault("LD_LIBRARY_PATH", str(ROOT))
    return subprocess.call(cmd, cwd=cwd or str(ROOT), env=full_env)


def _run_make(target: str, *extra: str) -> int:
    return _run(["make", "-j", str(os.cpu_count() or 4), target, *extra])


def _lib_info() -> dict:
    info: dict = {"path": str(LIBQIHSE), "exists": LIBQIHSE.exists()}
    if not LIBQIHSE.exists():
        return info
    info["size_kb"] = LIBQIHSE.stat().st_size // 1024
    try:
        import ctypes
        lib = ctypes.CDLL(str(LIBQIHSE))
        if hasattr(lib, "qihse_version"):
            lib.qihse_version.restype = ctypes.c_char_p
            info["version"] = lib.qihse_version().decode("utf-8", "replace")
        if hasattr(lib, "qihse_build_info"):
            lib.qihse_build_info.restype = ctypes.c_char_p
            info["build_info"] = lib.qihse_build_info().decode("utf-8", "replace")
        if hasattr(lib, "qihse_available"):
            lib.qihse_available.restype = ctypes.c_bool
            info["available"] = lib.qihse_available()
    except Exception as exc:
        info["load_error"] = str(exc)
    return info


# ── Command handlers ─────────────────────────────────────────────────────

def cmd_build(args: list[str]) -> int:
    """Build libqihse.so via make (auto-detects SIMD features)."""
    print("[qihse] Building libqihse.so ...")
    return _run_make("lib")


def cmd_build_ctypes(args: list[str]) -> int:
    """Build ctypes-only variant (no Python C extension linking)."""
    print("[qihse] Building libqihse.so (ctypes-only) ...")
    return _run_make("lib-ctypes")


def cmd_build_native(args: list[str]) -> int:
    """Build via build-native.sh with full SIMD auto-detection."""
    print("[qihse] Building via build-native.sh ...")
    script = SCRIPTS / "build-native.sh"
    if not script.exists():
        print(f"[qihse] ERROR: {script} not found", file=sys.stderr)
        return 1
    os.chmod(script, 0o755)
    return _run([str(script)] + args)


def cmd_build_tui(args: list[str]) -> int:
    """Launch interactive build configuration TUI."""
    print("[qihse] Launching build TUI ...")
    return _run([sys.executable, str(SCRIPTS / "build-tui.py")] + args)


def cmd_test(args: list[str]) -> int:
    """Run the full test suite."""
    print("[qihse] Running test suite ...")
    return _run_make("test")


def cmd_bench(args: list[str]) -> int:
    """Run the benchmark suite (validate-reference-workflow)."""
    if args:
        return _run_make(*args)
    print("[qihse] Running benchmark suite ...")
    return _run_make("benchmark")


def cmd_db(args: list[str]) -> int:
    """QIHSE vector DB CLI — delegates to scripts/qihse-db."""
    script = SCRIPTS / "qihse-db"
    if not script.exists():
        print(f"[qihse] ERROR: {script} not found", file=sys.stderr)
        return 1
    return _run([sys.executable, str(script)] + args)


def cmd_server(args: list[str]) -> int:
    """Build and run the QIHSE test server."""
    print("[qihse] Building and running test server ...")
    return _run_make("server")


def cmd_keygen(args: list[str]) -> int:
    """Build and run the PQC key generator."""
    print("[qihse] Building qihse_keygen ...")
    rc = _run_make("keygen")
    if rc != 0:
        return rc
    keygen = ROOT / "qihse_keygen"
    if keygen.exists():
        return _run([str(keygen)] + args)
    print("[qihse] qihse_keygen binary not found after build", file=sys.stderr)
    return 1


def cmd_demo(args: list[str]) -> int:
    """Run the Python SDK demo."""
    print("[qihse] Running Python SDK demo ...")
    env = {"LD_LIBRARY_PATH": str(ROOT)}
    full_env = os.environ.copy()
    full_env.update(env)
    full_env["PYTHONPATH"] = str(ROOT / "python") + os.pathsep + full_env.get("PYTHONPATH", "")
    return subprocess.call(
        [sys.executable, str(SCRIPTS / "qihse_python_demo.py")] + args,
        cwd=str(ROOT), env=full_env,
    )


def cmd_python(args: list[str]) -> int:
    """Start a Python REPL with qihse importable."""
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(ROOT) + os.pathsep + env.get("LD_LIBRARY_PATH", "")
    env["PYTHONPATH"] = str(ROOT / "python") + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable]
    if args:
        cmd.extend(args)
    else:
        cmd.append("-i")
        cmd.append("-c")
        cmd.append(
            "import qihse; print(f'QIHSE {getattr(qihse,\"__version__\",\"?\")} loaded'); "
            "print('Available: VectorDB, QihseDB, DistanceMetric'); "
            "print('Try: db = qihse.QihseDB(); db.kv_set(\"k\",\"v\"); db.kv_get(\"k\")')"
        )
    return subprocess.call(cmd, cwd=str(ROOT), env=env)


def cmd_bootstrap(args: list[str]) -> int:
    """Initialize workspace directories."""
    print("[qihse] Bootstrapping workspace ...")
    script = SCRIPTS / "bootstrap-workspace.sh"
    if not script.exists():
        print(f"[qihse] ERROR: {script} not found", file=sys.stderr)
        return 1
    os.chmod(script, 0o755)
    return _run(["sh", str(script)] + args)


def cmd_clean(args: list[str]) -> int:
    """Remove build artifacts."""
    print("[qihse] Cleaning build artifacts ...")
    return _run_make("clean")


def cmd_pristine(args: list[str]) -> int:
    """Deep clean — build artifacts, data, and results."""
    print("[qihse] Pristine clean (build + data + results) ...")
    rc = _run_make("clean")
    if rc != 0:
        return rc
    for d in ("data", "results", "build"):
        p = ROOT / d
        if p.exists():
            print(f"  rm -rf {p}")
            shutil.rmtree(p)
    print("[qihse] Pristine clean done.")
    return 0


def cmd_isa_info(args: list[str]) -> int:
    """Show CPU ISA detection and build flags."""
    return _run_make("isa-info")


def cmd_check(args: list[str]) -> int:
    """Run upstream workflow checks."""
    print("[qihse] Running workflow checks ...")
    return _run_make("check")


def cmd_dev_setup(args: list[str]) -> int:
    """Check required toolchain."""
    print("[qihse] Checking toolchain ...")
    return _run_make("dev-setup")


def cmd_version(args: list[str]) -> int:
    """Show library version and build info."""
    info = _lib_info()
    if not info.get("exists"):
        print("QIHSE library not built. Run: ./qihse build")
        return 1
    print(f"QIHSE {info.get('version', 'unknown')}")
    print(f"  path:       {info['path']}")
    print(f"  size:       {info.get('size_kb', '?')} KB")
    print(f"  build_info: {info.get('build_info', 'n/a')}")
    print(f"  available:  {info.get('available', '?')}")
    if "load_error" in info:
        print(f"  load_error: {info['load_error']}")
    return 0


def cmd_status(args: list[str]) -> int:
    """Show build status, library info, and availability."""
    info = _lib_info()
    print("╔══════════════════════════════════════════════════╗")
    print("║          QIHSE Vector Engine — Status            ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  Root:       {ROOT}")
    print(f"  Library:    {info['path']}")
    print(f"  Built:      {'✓' if info['exists'] else '✗ (not built)'}")
    if info.get("exists"):
        print(f"  Version:    {info.get('version', '?')}")
        print(f"  Size:       {info.get('size_kb', '?')} KB")
        print(f"  Available:  {info.get('available', '?')}")
        if "load_error" in info:
            print(f"  Load Error: {info['load_error']}")
    print()

    # Check toolchain
    tools = {}
    for tool in ("gcc", "make", "python3", "git"):
        tools[tool] = shutil.which(tool) is not None
    print("  Toolchain:")
    for tool, ok in tools.items():
        print(f"    {tool:12s} {'✓' if ok else '✗'}")
    print()

    # Check Python bindings
    py_bindings = ROOT / "python" / "qihse"
    print(f"  Python SDK: {'✓' if py_bindings.is_dir() else '✗'}")

    # Check scripts
    scripts = list(SCRIPTS.glob("*.py")) + list(SCRIPTS.glob("*.sh"))
    print(f"  Scripts:    {len(scripts)} files in scripts/")
    print()
    if not info.get("exists"):
        print("  → Run './qihse build' to build the native library.")
    return 0


# ── Dispatch ─────────────────────────────────────────────────────────────

COMMANDS = {
    "build":         cmd_build,
    "build-ctypes":  cmd_build_ctypes,
    "build-native":  cmd_build_native,
    "build-tui":     cmd_build_tui,
    "test":          cmd_test,
    "bench":         cmd_bench,
    "db":            cmd_db,
    "server":        cmd_server,
    "keygen":        cmd_keygen,
    "demo":          cmd_demo,
    "python":        cmd_python,
    "bootstrap":     cmd_bootstrap,
    "clean":         cmd_clean,
    "pristine":      cmd_pristine,
    "isa-info":      cmd_isa_info,
    "check":         cmd_check,
    "dev-setup":     cmd_dev_setup,
    "version":       cmd_version,
    "status":        cmd_status,
}


def _help() -> None:
    print(
        "QIHSE Launcher — Unified entry point for the QIHSE vector engine\n"
        "\n"
        "Usage: ./qihse [command] [args...]\n"
        "\n"
        "Commands:\n"
        "  build          Build libqihse.so (auto-detect SIMD)\n"
        "  build-ctypes   Build ctypes-only variant (no Python extension)\n"
        "  build-native   Build via build-native.sh (full SIMD auto-detect)\n"
        "  build-tui      Interactive build configuration TUI\n"
        "  test           Run full test suite\n"
        "  bench          Run benchmark suite (or pass a specific bench-* target)\n"
        "  db             QIHSE vector DB CLI (e.g. ./qihse db create --dims 128 --path /tmp/db)\n"
        "  server         Build and run the test server\n"
        "  keygen         Build and run PQC key generator\n"
        "  demo           Run Python SDK demo\n"
        "  python         Start Python REPL with qihse importable\n"
        "  bootstrap      Initialize workspace directories\n"
        "  clean          Remove build artifacts\n"
        "  pristine       Deep clean (build + data + results)\n"
        "  isa-info       Show CPU ISA detection and build flags\n"
        "  check          Run upstream workflow checks\n"
        "  dev-setup      Check required toolchain\n"
        "  version        Show library version and build info\n"
        "  status         Show build status and availability (default)\n"
    )


def main() -> int:
    args = sys.argv[1:]
    if not args:
        args = ["status"]

    cmd = args[0]
    rest = args[1:]

    if cmd in ("-h", "--help", "help"):
        _help()
        return 0

    handler = COMMANDS.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        _help()
        return 1

    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
