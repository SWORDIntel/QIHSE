#!/usr/bin/env python3
"""
QIHSE Builder — architecture-aware build orchestrator with dep provisioning.

Auto-detects CPU ISA, offers target override (cross-compile), pulls down
all vendored deps (tree-sitter, liboqs, oqs-provider), then compiles.

Theme: SWORD cyber-dark (#08080a bg, #e50000 accent, Share Tech Mono spirit).
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def visible_len(s: str) -> int:
    """Length of string excluding ANSI escape codes, counting wide chars as 2."""
    clean = _ANSI_RE.sub("", s)
    w = 0
    for ch in clean:
        ea = unicodedata.east_asian_width(ch)
        w += 2 if ea in ("W", "F") else 1
    return w


def pad_right(s: str, width: int) -> str:
    """Pad string on the right so its visible width equals width."""
    vl = visible_len(s)
    return s + " " * max(0, width - vl)

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
GRAY   = "\033[38;5;240m"

WIDTH = 80


def c(text: str, *colors: str) -> str:
    return f"{''.join(colors)}{text}{RST}"


def banner(title: str) -> None:
    inner = WIDTH - 2
    top    = f"╭{'─' * inner}╮"
    bottom = f"╰{'─' * inner}╯"
    vl = visible_len(title)
    pad = max(0, inner - 2 - vl)
    left = pad // 2
    right = pad - left
    print(f"\n  {c(top, RED)}")
    print(f"  {c('│', RED)} {' ' * left}{c(title, RED, BOLD)}{' ' * right} {c('│', RED)}")
    print(f"  {c(bottom, RED)}")


def section(title: str) -> None:
    print(f"\n  {c('◆', RED)} {c(title, RED, BOLD)}")
    print(f"  {c('─' * (WIDTH - 2), GRAY)}")


def warning_box(lines: list[str]) -> None:
    inner = WIDTH - 4
    top    = f"╭{'─' * inner}╮"
    bottom = f"╰{'─' * inner}╯"
    print(f"\n  {c(top, YELLOW, BOLD)}")
    for line in lines:
        print(f"  {c('│', YELLOW, BOLD)} {pad_right(line, inner - 2)} {c('│', YELLOW, BOLD)}")
    print(f"  {c(bottom, YELLOW, BOLD)}")


def info(msg: str) -> None:
    print(f"  {c('●', CYAN)} {msg}")


def ok(msg: str) -> None:
    print(f"  {c('✓', GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"  {c('⚠', YELLOW)} {msg}")


def fail(msg: str) -> None:
    print(f"  {c('✗', RED)} {msg}")


def countdown_prompt(prompt: str, seconds: int = 5) -> bool:
    """Show a countdown prompt that defaults to yes after N seconds."""
    import select
    import termios
    import tty

    old = None
    try:
        old = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
    except (termios.error, AttributeError):
        print(f"  {c('◆', RED)} {prompt} [{c('Y', GREEN)}/n] {c('(auto-yes)', DIM)}")
        return True

    result = True
    try:
        for i in range(seconds, 0, -1):
            sys.stdout.write(f"\r  {c('◆', RED)} {prompt} [{c('Y', GREEN)}/n] {c(f'auto-yes in {i}s', YELLOW)}  ")
            sys.stdout.flush()
            r, _, _ = select.select([sys.stdin], [], [], 1.0)
            if r:
                ch = sys.stdin.read(1)
                if ch.lower() == "n":
                    result = False
                    break
                elif ch.lower() == "y" or ch in ("\n", "\r"):
                    result = True
                    break
        else:
            result = True
    finally:
        if old:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
    label = c("✓ yes", GREEN) if result else c("✗ no", RED)
    sys.stdout.write(f"\r  {c('◆', RED)} {prompt} [{c('Y', GREEN)}/n] {label}{' ' * 20}\r\n")
    return result


# Progress bar state
_progress_stop = threading.Event()
_progress_thread = None


def start_progress(msg: str = "Building") -> None:
    """Start an animated progress bar on a background thread."""
    global _progress_stop, _progress_thread
    _progress_stop.clear()
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _spin():
        i = 0
        while not _progress_stop.is_set():
            bar_len = 20
            filled = (i // 2) % (bar_len + 1)
            bar = c("█", RED) * filled + c("░", GRAY) * (bar_len - filled)
            sys.stdout.write(f"\r  {c(frames[i % len(frames)], RED)} {msg}  {bar} ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1

    _progress_thread = threading.Thread(target=_spin, daemon=True)
    _progress_thread.start()


def stop_progress(success: bool = True) -> None:
    """Stop the progress bar and show final state."""
    global _progress_stop, _progress_thread
    _progress_stop.set()
    if _progress_thread:
        _progress_thread.join(timeout=0.5)
        _progress_thread = None
    bar_len = 20
    bar = c("█", GREEN if success else RED) * bar_len
    label = c("done", GREEN) if success else c("failed", RED)
    sys.stdout.write(f"\r  {c('●', GREEN if success else RED)} {label}  {bar}{' ' * 10}\r\n")
    sys.stdout.flush()


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
        # SSE / AVX baseline
        "sse42": "sse4_2" in flags,
        "avx": "avx" in flags,
        "avx2": "avx2" in flags,
        "fma": "fma" in flags,
        "f16c": "f16c" in flags,
        "aesni": "aes" in flags,
        # AVX-VNNI (separate from AVX-512 VNNI)
        "avx_vnni": "avx_vnni" in flags,
        "avx_vnni_int8": "avx_vnni_int8" in flags,
        "avx_vnni_int16": "avx_vnni_int16" in flags,
        # AVX-512 foundation + subsets
        "avx512f": "avx512f" in flags,
        "avx512dq": "avx512dq" in flags,
        "avx512bw": "avx512bw" in flags,
        "avx512vl": "avx512vl" in flags,
        "avx512cd": "avx512cd" in flags,
        "avx512_ifma": "avx512ifma" in flags,
        "avx512_vbmi": "avx512vbmi" in flags,
        "avx512_vbmi2": "avx512vbmi2" in flags,
        "avx512_vpopcntdq": "avx512vpopcntdq" in flags,
        "avx512_vnni": "avx512_vnni" in flags,
        "avx512_bf16": "avx512_bf16" in flags,
        "avx512_fp16": "avx512fp16" in flags,
        "avx512_vp2intersect": "avx512_vp2intersect" in flags,
        # AMX
        "amx_tile": "amx_tile" in flags,
        "amx_int8": "amx_int8" in flags,
        "amx_bf16": "amx_bf16" in flags,
        "amx_fp16": "amx_fp16" in flags,
        # Other modern
        "avx_ne_convert": "avx_ne_convert" in flags,
        "avx_ifma": "avxifma" in flags,
    }
    feat["avx512"] = all(feat[k] for k in ("avx512f", "avx512dq", "avx512bw", "avx512vl"))
    feat["amx"] = feat["amx_tile"] and (feat["amx_int8"] or feat["amx_bf16"])
    feat["vnni"] = feat["avx512_vnni"] or feat["avx_vnni"]
    return feat


def arch_label(feat: dict) -> str:
    """Human-readable ISA label showing the highest supported level."""
    parts = []
    if feat["avx512"]:
        parts.append("AVX-512")
        if feat["avx512_bf16"]:
            parts.append("BF16")
        if feat["avx512_fp16"]:
            parts.append("FP16")
        if feat["avx512_vnni"]:
            parts.append("VNNI")
        if feat["avx512_vbmi"]:
            parts.append("VBMI")
        if feat["avx512_ifma"]:
            parts.append("IFMA")
    if feat["amx"]:
        parts.append("AMX")
        if feat["amx_fp16"]:
            parts.append("AMX-FP16")
    if feat["avx_vnni"] and not feat["avx512"]:
        parts.append("AVX-VNNI")
    if not parts:
        if feat["avx2"]:
            parts.append("AVX2")
        elif feat["avx"]:
            parts.append("AVX1")
        elif feat["sse42"]:
            parts.append("SSE4.2")
        else:
            parts.append("scalar")
    if feat["fma"] and "AVX2" in parts:
        parts.append("FMA")
    return "+".join(parts)


def default_march(feat: dict) -> str:
    """Pick a safe -march for the detected CPU."""
    return "native"


# ── Target menu (cross-compile override) ───────────────────────────────

TARGETS = {
    "1": ("native",  "Auto-detect (march=native)", None),
    "2": ("sandy",   "Sandy Bridge (-march=sandybridge)", "sandybridge"),
    "3": ("haswell", "Haswell AVX2+FMA (-march=haswell)", "haswell"),
    "4": ("alder",   "Alder Lake AVX-VNNI (-march=alderlake)", "alderlake"),
    "5": ("avx512",  "AVX-512 family → submenu", "SUBMENU"),
    "6": ("generic_v2", "Generic x86-64-v2 (-march=x86-64-v2)", "x86-64-v2"),
    "7": ("generic_v3", "Generic x86-64-v3 (-march=x86-64-v3)", "x86-64-v3"),
    "8": ("generic_v4", "Generic x86-64-v4 (-march=x86-64-v4)", "x86-64-v4"),
    "9": ("scalar",  "Scalar only (-march=x86-64)", "x86-64"),
}

AVX512_TARGETS = {
    "1": ("skylake",   "Skylake-SP — F+DQ+BW+VL+CD (-march=skylake-avx512)", "skylake-avx512"),
    "2": ("icelake",   "Ice Lake — +IFMA+VBMI+VPOPCNTDQ+VNNI (-march=icelake-server)", "icelake-server"),
    "3": ("cooperlake", "Cooper Lake — +BF16 (-march=cooperlake)", "cooperlake"),
    "4": ("sapphirerapids", "Sapphire Rapids — +BF16+AMX-INT8/BF16 (-march=sapphirerapids)", "sapphirerapids"),
    "5": ("emeraldrapids", "Emerald Rapids — +AMX (-march=emeraldrapids)", "emeraldrapids"),
    "6": ("graniterapids", "Granite Rapids — +AMX-FP16+AVX-VNNIINT8 (-march=graniterapids)", "graniterapids"),
    "7": ("back",      "← Back to main menu", None),
}

BUILD_TARGETS = {
    "1": ("all",     "Full build (lib + server + keygen)"),
    "2": ("lib",     "Library only (libqihse.so)"),
    "3": ("keygen",  "Key generator only"),
    "4": ("server",  "Server only"),
    "5": ("build",   "Build variant (lib + ctypes + keygen)"),
}


def menu(title: str, options: dict, default: str) -> str:
    section(title)
    for key in sorted(options):
        desc = options[key][1]
        marker = f" {c('▸', CYAN)} " if key == default else "   "
        print(f"  {marker}{c(f'[{key}]', BOLD)} {desc}")
    choice = input(f"\n  {c('◆', RED)} {c('Select', WHITE)} [{default}]: ").strip() or default
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

    start_progress(f"Building {target}")
    proc = subprocess.Popen(make_args, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = []
    for line in proc.stdout:
        output.append(line)
    proc.wait()
    stop_progress(success=proc.returncode == 0)

    # Print build output
    if output:
        print(f"  {c('─' * (WIDTH - 2), GRAY)}")
        for line in output:
            print(f"  {line}", end="" if line.endswith("\n") else "\n")
        print(f"  {c('─' * (WIDTH - 2), GRAY)}")

    if proc.returncode == 0:
        ok(f"Build successful — {target}")
    else:
        fail(f"Build failed (exit {proc.returncode})")
        sys.exit(proc.returncode)


def install_opt(dest: Path) -> None:
    """Install built artifacts to dest."""
    banner(f"INSTALL → {dest}")
    if not dest.exists():
        warn(f"{dest} does not exist, creating...")
        dest.mkdir(parents=True, exist_ok=True)
    for sub in ("bin", "lib", Path("include") / "qihse"):
        (dest / sub).mkdir(parents=True, exist_ok=True)

    lib = ROOT / "libqihse.so"
    keygen = ROOT / "qihse_keygen"
    server = ROOT / "tests" / "qihse_server"

    def safe_copy(src: Path, dst: Path) -> bool:
        try:
            if src.resolve() == dst.resolve():
                return False
            shutil.copy2(src, dst)
            return True
        except (shutil.SameFileError, OSError):
            return False

    if lib.exists():
        safe_copy(lib, dest / "lib" / "libqihse.so")
        ok(f"libqihse.so → {dest}/lib/")
    if keygen.exists():
        safe_copy(keygen, dest / "bin" / "qihse_keygen")
        ok(f"qihse_keygen → {dest}/bin/")
    if server.exists():
        safe_copy(server, dest / "bin" / "qihse_server")
        ok(f"qihse_server → {dest}/bin/")

    # Headers
    inc_src = ROOT / "include"
    inc_dst = dest / "include" / "qihse"
    inc_dst.mkdir(parents=True, exist_ok=True)
    for h in inc_src.glob("*.h"):
        safe_copy(h, inc_dst / h.name)
    if (ROOT / "qihse.h").exists():
        safe_copy(ROOT / "qihse.h", inc_dst / "qihse.h")
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


def detect_shell_configs() -> list[Path]:
    """Find all shell config files that exist."""
    home = Path.home()
    candidates = [
        home / ".bashrc",
        home / ".zshrc",
        home / ".config" / "fish" / "config.fish",
        home / ".profile",
        home / ".bash_profile",
    ]
    return [c for c in candidates if c.exists()]


def setup_integration(alias_name: str, dest: Path, project: str) -> None:
    """Set up env var alias, PATH, LD_LIBRARY_PATH, PKG_CONFIG_PATH, and
    offer to persist across all auto-detected shell configs."""
    section("INTEGRATION")

    shell_rcs = detect_shell_configs()
    if shell_rcs:
        info(f"Detected shell configs: {c(', '.join(str(r.relative_to(Path.home())) for r in shell_rcs), CYAN)}")
    else:
        warn("No shell configs detected")

    # Build the export block
    exports = []
    exports.append(f"export {alias_name}={dest}")
    exports.append(f"export PATH=\"{dest}/bin:$PATH\"")
    exports.append(f"export LD_LIBRARY_PATH=\"{dest}/lib:$LD_LIBRARY_PATH\"")
    exports.append(f"export PKG_CONFIG_PATH=\"{dest}/lib/pkgconfig:$PKG_CONFIG_PATH\"")
    exports.append(f"export CMAKE_PREFIX_PATH=\"{dest}:$CMAKE_PREFIX_PATH\"")

    info(f"{c(alias_name, CYAN)} = {c(str(dest), WHITE)}")
    print()
    for e in exports:
        print(f"  {c(e, DIM)}")
    print()

    # Offer to persist with 5s countdown (default yes)
    if not shell_rcs:
        return
    if not countdown_prompt("Persist in shell configs?", seconds=5):
        return

    block = f"\n# {alias_name} — set by {project} builder\n" + "\n".join(exports) + "\n"
    for rc in shell_rcs:
        existing = rc.read_text()
        if f"export {alias_name}=" not in existing:
            rc.open("a").write(block)
            ok(f"Added to {c(str(rc.relative_to(Path.home())), CYAN)}")
        else:
            ok(f"Already in {c(str(rc.relative_to(Path.home())), CYAN)}")

    # Offer ld.so.conf.d for system-wide lib resolution
    if input(f"\n  {c('◆', RED)} {c('Add to ld.so.conf.d (system-wide)?', WHITE)} [y/N] ").strip().lower() in ("y", "yes"):
        conf = Path("/etc/ld.so.conf.d") / f"{project.lower()}.conf"
        try:
            conf.parent.mkdir(parents=True, exist_ok=True)
            conf.write_text(f"{dest}/lib\n")
            run(["ldconfig"], check=False)
            ok(f"Written {conf} and ran ldconfig")
        except PermissionError:
            warn("Needs root, trying with sudo...")
            run(["sudo", "tee", str(conf)], check=False, shell=False)
            run(["sudo", "ldconfig"], check=False)
            ok(f"Written {conf} via sudo")

    # Source hint
    rcs_str = "  ".join(f"source ~/{rc.relative_to(Path.home())}" for rc in shell_rcs)
    warn(f"Run: {c(rcs_str, CYAN)}  or start a new shell")


# ── Main ───────────────────────────────────────────────────────────────

def main() -> None:
    banner("Q I H S E")
    feat = detect_cpu()

    section("ARCHITECTURE DETECTION")
    info(f"CPU:    {c(feat['model'], WHITE)}")
    info(f"Arch:   {c(feat['arch'], CYAN)}  ISA: {c(arch_label(feat), CYAN)}")
    # Show all detected ISA features
    feat_names = []
    for k, label in [
        ("sse42", "SSE42"), ("avx", "AVX"), ("avx2", "AVX2"), ("fma", "FMA"),
        ("f16c", "F16C"), ("aesni", "AESNI"),
        ("avx_vnni", "AVX-VNNI"), ("avx_vnni_int8", "AVX-VNNI-INT8"),
        ("avx512", "AVX512"), ("avx512_bf16", "BF16"), ("avx512_fp16", "FP16"),
        ("avx512_vnni", "VNNI"), ("avx512_vbmi", "VBMI"), ("avx512_ifma", "IFMA"),
        ("amx", "AMX"), ("amx_int8", "AMX-INT8"), ("amx_bf16", "AMX-BF16"),
        ("amx_fp16", "AMX-FP16"), ("avx_ne_convert", "NE-CONVERT"),
    ]:
        if feat.get(k):
            feat_names.append(label)
    info(f"Flags:  {c(' '.join(feat_names), DIM)}")

    # Provision deps
    provision_deps()

    # Target menu with AVX-512 submenu
    while True:
        arch_choice = menu("Build target (architecture)", TARGETS, "1")
        _, arch_desc, march_override = TARGETS[arch_choice]
        if march_override == "SUBMENU":
            sub_choice = menu("AVX-512 family", AVX512_TARGETS, "1")
            _, sub_desc, sub_march = AVX512_TARGETS[sub_choice]
            if sub_march is None:
                continue  # Back to main menu
            arch_desc = sub_desc
            march_override = sub_march
        break

    # Cross-compile warning
    if arch_choice != "1":
        warning_box([
            c("⚠  CROSS-COMPILATION WARNING", YELLOW, BOLD),
            "",
            f"  You selected: {arch_desc}",
            f"  Your CPU ISA:  {arch_label(feat)}",
            "",
            "  Building for a different architecture than this",
            "  CPU means the binaries may NOT run on this PC.",
            "  Use this only when deploying to another machine.",
            "",
            "  If unsure, select [1] Auto-detect (march=native).",
        ])
        if input(f"  {c('◆', RED)} {c('Proceed anyway?', WHITE)} [y/N] ").strip().lower() not in ("y", "yes"):
            warn("Aborted — no changes made.")
            sys.exit(0)

    build_choice = menu("Build target (make goal)", BUILD_TARGETS, "1")
    _, build_desc = BUILD_TARGETS[build_choice]

    # Output path
    section("OUTPUT PATH")
    default_out = str(ROOT)
    out_input = input(f"  {c('◆', RED)} {c('Output path', WHITE)} [{c(default_out, DIM)}]: ").strip()
    out_path = Path(out_input).expanduser().resolve() if out_input else Path(default_out)

    # Alias
    default_alias = "QIHSE_DB"
    alias_input = input(f"  {c('◆', RED)} {c('Alias name', WHITE)} [{c(default_alias, DIM)}]: ").strip()
    alias_name = alias_input.upper() if alias_input else default_alias

    clean = input(f"\n  {c('◆', RED)} {c('Clean before build?', WHITE)} [y/N] ").strip().lower() in ("y", "yes")
    jobs = os.cpu_count() or 4

    march = march_override  # None means native

    # Summary box
    section("BUILD SUMMARY")
    info(f"Architecture:  {c(arch_desc, CYAN)}")
    info(f"Build goal:    {c(build_desc, CYAN)}")
    info(f"Clean:         {c('yes' if clean else 'no', CYAN)}   Jobs: {c(str(jobs), CYAN)}")
    info(f"Output path:   {c(str(out_path), CYAN)}")
    info(f"Alias:         {c(alias_name, CYAN)} → {c(str(out_path), DIM)}")

    build(march, BUILD_TARGETS[build_choice][0], clean, jobs)

    # Install to output path
    if input(f"\n  {c('◆', RED)} {c(f'Install to {out_path}?', WHITE)} [Y/n] ").strip().lower() not in ("n", "no"):
        install_opt(out_path)
        setup_integration(alias_name, out_path, "QIHSE")

    done_line = c("Done.", GREEN, BOLD) + "  " + c("QIHSE build complete.", DIM)
    inner_w = WIDTH - 4
    print(f"\n  {c('╭' + '─' * (WIDTH - 2) + '╮', GREEN)}")
    print(f"  {c('│', GREEN)} {pad_right(done_line, inner_w)} {c('│', GREEN)}")
    print(f"  {c('╰' + '─' * (WIDTH - 2) + '╯', GREEN)}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {c('Aborted.', RED)}")
        sys.exit(130)
