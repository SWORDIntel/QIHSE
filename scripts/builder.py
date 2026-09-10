#!/usr/bin/env python3
"""
QIHSE Builder — architecture-aware build orchestrator with dep provisioning.

Auto-detects CPU ISA, offers target override (cross-compile), pulls down
all vendored deps (tree-sitter, liboqs, oqs-provider), then compiles.

Theme: SWORD cyber-dark (#08080a bg, #e50000 accent, Share Tech Mono spirit).
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── SWORD cyber-dark ANSI palette ──────────────────────────────────────
BG     = "\033[48;5;233m"   # #08080a near-black
RST    = "\033[0m"
RED    = "\033[38;5;196m"   # #e50000 SWORD red
CYAN   = "\033[36m"          # T420 label
ORANGE = "\033[38;5;208m"   # T320 label
BOLD   = "\033[1m"
DIM    = "\033[2m"
WHITE  = "\033[97m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"


def c(text: str, *colors: str) -> str:
    return f"{''.join(colors)}{text}{RST}"


def banner(title: str) -> None:
    bar = "─" * 57
    print(f"{BG}{c('┌' + bar + '┐', RED)}{RST}")
    print(f"{BG}{c('│ ' + title.center(55) + ' │', RED, BOLD)}{RST}")
    print(f"{BG}{c('└' + bar + '┘', RED)}{RST}")


def info(msg: str) -> None:
    print(f"  {c('●', CYAN)} {msg}")


def ok(msg: str) -> None:
    print(f"  {c('✓', GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"  {c('⚠', YELLOW)} {msg}")


def fail(msg: str) -> None:
    print(f"  {c('✗', RED)} {msg}")


def run(cmd: list[str] | str, cwd: Path | None = None, check: bool = True,
        env: dict | None = None, shell: bool = False) -> int:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    if shell:
        assert isinstance(cmd, str)
        return subprocess.run(cmd, cwd=cwd, env=full_env, shell=True).returncode
    assert isinstance(cmd, list)
    rc = subprocess.run(cmd, cwd=cwd, env=full_env).returncode
    if check and rc != 0:
        fail(f"Command failed (exit {rc}): {' '.join(cmd)}")
        sys.exit(rc)
    return rc


# ── Architecture detection ─────────────────────────────────────────────

def detect_cpu() -> dict:
    """Detect CPU architecture and SIMD features via /proc/cpuinfo + cpuid."""
    flags: list[str] = []
    arch = "x86_64"
    model = "unknown"

    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("flags") and not flags:
                    flags = line.split(":", 1)[1].split()
                if line.startswith("model name") and model == "unknown":
                    model = line.split(":", 1)[1].strip()
    except FileNotFoundError:
        pass

    # Fallback: use uname
    if not flags:
        arch = os.uname().machine
        try:
            out = subprocess.check_output(["lscpu"], text=True)
            for line in out.splitlines():
                if line.startswith("Flags:"):
                    flags = line.split(":", 1)[1].split()
                if line.startswith("Model name:"):
                    model = line.split(":", 1)[1].strip()
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass

    feat = {
        "arch": arch,
        "model": model,
        "sse42": "sse4_2" in flags,
        "avx": "avx" in flags,
        "avx2": "avx2" in flags,
        "avx512f": "avx512f" in flags,
        "avx512dq": "avx512dq" in flags,
        "avx512bw": "avx512bw" in flags,
        "avx512vl": "avx512vl" in flags,
        "aesni": "aes" in flags,
        "fma": "fma" in flags,
        "amx": "amx_tile" in flags,
        "vnni": "avx512_vnni" in flags,
        "f16c": "f16c" in flags,
    }
    feat["avx512"] = all(feat[k] for k in ("avx512f", "avx512dq", "avx512bw", "avx512vl"))
    return feat


def arch_label(feat: dict) -> str:
    if feat["avx512"]:
        return "AVX-512"
    if feat["avx2"]:
        return "AVX2"
    if feat["avx"]:
        return "AVX1"
    if feat["sse42"]:
        return "SSE4.2"
    return "scalar"


def default_march(feat: dict) -> str:
    """Pick a safe -march for the detected CPU."""
    return "native"


# ── Target menu (cross-compile override) ───────────────────────────────

TARGETS = {
    "1": ("native",  "Auto-detect (march=native)", None),
    "2": ("sandy",   "Sandy Bridge (-march=sandybridge)", "sandybridge"),
    "3": ("haswell", "Haswell AVX2 (-march=haswell)", "haswell"),
    "4": ("skylake", "Skylake AVX-512 (-march=skylake-avx512)", "skylake-avx512"),
    "5": ("generic", "Generic x86-64 (-march=x86-64-v2)", "x86-64-v2"),
    "6": ("scalar",  "Scalar only (no SIMD)", "x86-64"),
}

BUILD_TARGETS = {
    "1": ("all",     "Full build (lib + server + keygen)"),
    "2": ("lib",     "Library only (libqihse.so)"),
    "3": ("keygen",  "Key generator only"),
    "4": ("server",  "Server only"),
    "5": ("build",   "Build variant (lib + ctypes + keygen)"),
}


def menu(title: str, options: dict, default: str) -> str:
    print(f"\n  {c(title, RED, BOLD)}")
    for key in sorted(options):
        desc = options[key][1]
        marker = f" {c('→', CYAN)} " if key == default else "   "
        print(f"  {marker}{c(f'[{key}]', DIM)} {desc}")
    choice = input(f"\n  {c('Select', WHITE)} [{default}]: ").strip() or default
    if choice not in options:
        fail(f"Invalid choice: {choice}")
        sys.exit(1)
    return choice


# ── Dependency provisioning ────────────────────────────────────────────

DEPS = [
    ("liboqs",       "vendor/liboqs",        "Post-quantum crypto (ML-KEM/ML-DSA)"),
    ("oqs-provider", "vendor/oqs-provider",  "OpenSSL OQS provider (FIPS PQC)"),
    ("tree-sitter",  "vendor/tree-sitter",   "SQL parser grammar (tree-sitter)"),
]

APT_DEPS = [
    ("gcc", "gcc"),
    ("g++", "g++"),
    ("cmake", "cmake"),
    ("ninja-build", "ninja-build"),
    ("libssl-dev", "libssl-dev"),
    ("libsqlite3-dev", "libsqlite3-dev"),
    ("libluajit-5.1-dev", "libluajit-5.1-dev"),
    ("libbpf-dev", "libbpf-dev"),
    ("libxdp-dev", "libxdp-dev"),
    ("liburing-dev", "liburing-dev"),
    ("libpython3-dev", "libpython3-dev"),
    ("python3-dev", "python3-dev"),
]


def check_apt_deps() -> list[str]:
    """Return list of missing apt packages."""
    missing = []
    for pkg, _ in APT_DEPS:
        r = subprocess.run(["dpkg", "-s", pkg], capture_output=True)
        if r.returncode != 0:
            missing.append(pkg)
    return missing


def install_apt_deps(missing: list[str]) -> None:
    if not missing:
        ok("All system dependencies present")
        return
    warn(f"Missing system packages: {', '.join(missing)}")
    if input(f"  {c('Install via apt?', WHITE)} [Y/n] ").strip().lower() not in ("n", "no"):
        run(["sudo", "apt-get", "install", "-y"] + missing)


def ensure_submodule(name: str, path: str, desc: str) -> None:
    full = ROOT / path
    info(f"Checking {c(name, CYAN)} — {desc}")
    if not (full / "CMakeLists.txt").exists() and not (full / "Makefile").exists() and not (full / "lib").exists():
        warn(f"{name} not present, initializing submodule...")
        run(["git", "submodule", "update", "--init", "--recursive", path], cwd=ROOT)
    ok(f"{name} ready")


def ensure_tree_sitter() -> None:
    ts = ROOT / "vendor" / "tree-sitter"
    info(f"Checking {c('tree-sitter', CYAN)} — SQL parser grammar")
    if not (ts / "lib" / "src" / "lib.c").exists():
        warn("tree-sitter lib not present, cloning...")
        run(["git", "submodule", "update", "--init", "--recursive", "vendor/tree-sitter"], cwd=ROOT)
    ok("tree-sitter ready")


def provision_deps() -> None:
    """Pull down all vendored deps before building."""
    banner("DEPENDENCY PROVISIONING")
    missing = check_apt_deps()
    install_apt_deps(missing)
    for name, path, desc in DEPS:
        if name == "tree-sitter":
            ensure_tree_sitter()
        else:
            ensure_submodule(name, path, desc)


# ── Build ──────────────────────────────────────────────────────────────

def build(march: str | None, target: str, clean: bool, jobs: int) -> None:
    banner("COMPILING")
    make_args = ["make", f"-j{jobs}"]

    if clean:
        info("Cleaning previous build...")
        run(["make", "clean"], cwd=ROOT, check=False)

    # SIMD flags
    avx2 = "1" if march and march not in ("x86-64", "x86-64-v2", "sandybridge") else "0"
    avx512 = "1" if march in ("skylake-avx512",) else "0"

    cflags = f"-march={march}" if march else "-march=native"
    cflags += " -DNDEBUG -O3"

    make_args += [
        f"QIHSE_ENABLE_AVX2={avx2}",
        f"QIHSE_ENABLE_AVX512={avx512}",
        f"QIHSE_CFLAGS_EXTRA={cflags}",
        target,
    ]

    info(f"Target: {c(target, CYAN)}  march={c(march or 'native', CYAN)}  jobs={c(str(jobs), CYAN)}")
    info(f"Command: {' '.join(make_args)}")
    print()
    rc = run(make_args, cwd=ROOT, check=False)
    print()
    if rc == 0:
        ok(f"Build successful — {target}")
    else:
        fail(f"Build failed (exit {rc})")
        sys.exit(rc)


def install_opt() -> None:
    """Install built artifacts to /opt/qihse."""
    banner("INSTALL → /opt/qihse")
    dest = Path("/opt/qihse")
    if not dest.exists():
        warn("/opt/qihse does not exist, creating (needs sudo)...")
        run(["sudo", "mkdir", "-p", str(dest / "bin"), str(dest / "lib"), str(dest / "include" / "qihse")])
        run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(dest)])

    lib = ROOT / "libqihse.so"
    keygen = ROOT / "qihse_keygen"
    server = ROOT / "tests" / "qihse_server"

    if lib.exists():
        shutil.copy2(lib, dest / "lib" / "libqihse.so")
        ok(f"libqihse.so → {dest}/lib/")
    if keygen.exists():
        shutil.copy2(keygen, dest / "bin" / "qihse_keygen")
        ok(f"qihse_keygen → {dest}/bin/")
    if server.exists():
        shutil.copy2(server, dest / "bin" / "qihse_server")
        ok(f"qihse_server → {dest}/bin/")

    # Headers
    inc_src = ROOT / "include"
    inc_dst = dest / "include" / "qihse"
    inc_dst.mkdir(parents=True, exist_ok=True)
    for h in inc_src.glob("*.h"):
        shutil.copy2(h, inc_dst / h.name)
    if (ROOT / "qihse.h").exists():
        shutil.copy2(ROOT / "qihse.h", inc_dst / "qihse.h")
    ok(f"headers → {dest}/include/qihse/ ({len(list(inc_dst.glob('*.h')))} files)")

    # Symlink
    link = dest / "libqihse.so"
    if not link.exists() or link.is_symlink():
        try:
            link.unlink(missing_ok=True)
        except OSError:
            pass
        link.symlink_to("lib/libqihse.so")
        ok(f"symlink → {dest}/libqihse.so")

    print(f"\n  {c('Keys preserved:', DIM)} {len(list((dest / 'keys').glob('*')))} files  "
          f"{c('Data preserved:', DIM)} {len(list((dest / 'data').glob('*')))} files")


# ── Main ───────────────────────────────────────────────────────────────

def main() -> None:
    banner("QIHSE BUILDER")
    feat = detect_cpu()

    print(f"\n  {c('Architecture', RED, BOLD)}")
    info(f"CPU:    {c(feat['model'], WHITE)}")
    info(f"Arch:   {c(feat['arch'], CYAN)}  ISA: {c(arch_label(feat), CYAN)}")
    feats = [k.upper() for k in ("sse42", "avx", "avx2", "avx512", "aesni", "fma", "amx", "vnni", "f16c") if feat[k]]
    info(f"Flags:  {c(' '.join(feats), DIM)}")

    # Provision deps
    provision_deps()

    # Target menu
    arch_choice = menu("Build target (architecture)", TARGETS, "1")
    _, arch_desc, march_override = TARGETS[arch_choice]

    build_choice = menu("Build target (make goal)", BUILD_TARGETS, "1")
    _, build_desc = BUILD_TARGETS[build_choice]

    clean = input(f"\n  {c('Clean before build?', WHITE)} [y/N] ").strip().lower() in ("y", "yes")
    jobs = os.cpu_count() or 4

    march = march_override  # None means native
    print(f"\n  {c('─' * 50, DIM)}")
    info(f"Architecture: {c(arch_desc, CYAN)}")
    info(f"Build goal:   {c(build_desc, CYAN)}")
    info(f"Clean:        {c('yes' if clean else 'no', CYAN)}  Jobs: {c(str(jobs), CYAN)}")

    build(march, BUILD_TARGETS[build_choice][0], clean, jobs)

    # Offer install
    if input(f"\n  {c('Install to /opt/qihse?', WHITE)} [Y/n] ").strip().lower() not in ("n", "no"):
        install_opt()

    print(f"\n  {c('Done.', GREEN, BOLD)}  {c('QIHSE build complete.', DIM)}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {c('Aborted.', RED)}")
        sys.exit(130)
