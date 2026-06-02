#!/usr/bin/env python3
"""
QIHSE Build TUI - Interactive build configuration and execution.

Usage: ./build-tui.py
"""

import curses
import os
import subprocess
import sys

BUILD_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# Configuration state
# ---------------------------------------------------------------------------
class BuildConfig:
    def __init__(self):
        self.build_type = "release"      # release, debug, profile
        self.avx2 = False
        self.avx512 = False
        self.sanitizer = None            # None, address, thread, undefined
        self.clean = False
        self.target = "lib"              # lib, test, benchmark, all
        self.jobs = os.cpu_count() or 4

    def to_make_args(self):
        args = ["make", "-C", BUILD_DIR, "-j", str(self.jobs)]
        if self.clean:
            args.append("clean")

        # Build type flags
        extra = []
        if self.build_type == "debug":
            extra.append("-O0 -g3 -DDEBUG")
        elif self.build_type == "profile":
            extra.append("-O2 -g -pg")
        elif self.build_type == "release":
            extra.append("-O3 -DNDEBUG")

        # SIMD
        if self.avx512:
            args.append("QIHSE_ENABLE_AVX512=1")
            args.append("QIHSE_ENABLE_AVX2=1")
        elif self.avx2:
            args.append("QIHSE_ENABLE_AVX2=1")
            args.append("QIHSE_ENABLE_AVX512=0")
        else:
            args.append("QIHSE_ENABLE_AVX2=0")
            args.append("QIHSE_ENABLE_AVX512=0")

        # Sanitizer
        if self.sanitizer == "address":
            extra.append("-fsanitize=address -fno-omit-frame-pointer")
        elif self.sanitizer == "thread":
            extra.append("-fsanitize=thread")
        elif self.sanitizer == "undefined":
            extra.append("-fsanitize=undefined")

        if extra:
            args.append(f"QIHSE_CFLAGS_EXTRA={' '.join(extra)}")

        # Target
        target_map = {
            "lib": "lib",
            "test": "test",
            "benchmark": "bench-micro",
            "all": "all",
        }
        args.append(target_map.get(self.target, "lib"))
        return args

    def summary(self):
        parts = [
            f"Build: {self.build_type}",
            f"SIMD: {'AVX512' if self.avx512 else ('AVX2' if self.avx2 else 'scalar')}",
        ]
        if self.sanitizer:
            parts.append(f"Sanitizer: {self.sanitizer}")
        if self.clean:
            parts.append("clean first")
        parts.append(f"Target: {self.target}")
        return "  |  ".join(parts)


# ---------------------------------------------------------------------------
# TUI helpers
# ---------------------------------------------------------------------------
def center_text(stdscr, y, text, attr=0):
    w = stdscr.getmaxyx()[1]
    x = max(0, (w - len(text)) // 2)
    stdscr.addstr(y, x, text, attr)


def draw_box(stdscr, y1, x1, y2, x2):
    for y in range(y1, y2 + 1):
        for x in range(x1, x2 + 1):
            if y == y1 or y == y2:
                stdscr.addch(y, x, curses.ACS_HLINE)
            elif x == x1 or x == x2:
                stdscr.addch(y, x, curses.ACS_VLINE)
    stdscr.addch(y1, x1, curses.ACS_ULCORNER)
    stdscr.addch(y1, x2, curses.ACS_URCORNER)
    stdscr.addch(y2, x1, curses.ACS_LLCORNER)
    stdscr.addch(y2, x2, curses.ACS_LRCORNER)


# ---------------------------------------------------------------------------
# Main TUI
# ---------------------------------------------------------------------------
def run_build(stdscr, config):
    """Run the actual build and show output."""
    curses.use_default_colors()
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    center_text(stdscr, 2, "QIHSE Build", curses.A_BOLD | curses.A_UNDERLINE)
    center_text(stdscr, 4, config.summary())
    stdscr.addstr(6, 4, "Running: " + " ".join(config.to_make_args()), curses.A_DIM)
    stdscr.addstr(8, 4, "-" * (w - 8))
    stdscr.refresh()

    args = config.to_make_args()
    line_y = 10
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=BUILD_DIR,
        )
        for line in proc.stdout:
            if line_y < h - 3:
                trimmed = line.rstrip()[:w - 8]
                stdscr.addstr(line_y, 4, trimmed)
                line_y += 1
            stdscr.refresh()
        proc.wait()

        stdscr.addstr(h - 2, 4, "-" * (w - 8))
        if proc.returncode == 0:
            stdscr.addstr(h - 1, 4, "BUILD SUCCESS", curses.color_pair(2) | curses.A_BOLD)
        else:
            stdscr.addstr(h - 1, 4, f"BUILD FAILED (exit {proc.returncode})", curses.color_pair(1) | curses.A_BOLD)
    except Exception as e:
        stdscr.addstr(h - 1, 4, f"ERROR: {e}", curses.color_pair(1))

    stdscr.addstr(h - 1, w - 20, "Press any key...", curses.A_DIM)
    stdscr.refresh()
    stdscr.getch()


def main_tui(stdscr):
    curses.curs_set(0)
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)

    config = BuildConfig()

    # Auto-detect CPU features
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()
        flags = cpuinfo.split("flags\t:", 1)[1].split("\n", 1)[0] if "flags\t:" in cpuinfo else ""
        config.avx2 = "avx2" in flags
        config.avx512 = all(f in flags for f in ("avx512f", "avx512dq", "avx512bw", "avx512vl"))
    except Exception:
        pass

    options = [
        ("build_type", "Build Type", ["release", "debug", "profile"]),
        ("avx2", "Enable AVX2", [False, True]),
        ("avx512", "Enable AVX512", [False, True]),
        ("sanitizer", "Sanitizer", [None, "address", "thread", "undefined"]),
        ("clean", "Clean First", [False, True]),
        ("target", "Target", ["lib", "test", "benchmark", "all"]),
    ]
    labels = {
        "build_type": {k: k for k in ["release", "debug", "profile"]},
        "avx2": {False: "no", True: "yes"},
        "avx512": {False: "no", True: "yes"},
        "sanitizer": {None: "none", "address": "address", "thread": "thread", "undefined": "undefined"},
        "clean": {False: "no", True: "yes"},
        "target": {k: k for k in ["lib", "test", "benchmark", "all"]},
    }
    current = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # Title
        center_text(stdscr, 1, "  QIHSE Build TUI  ", curses.A_BOLD | curses.A_REVERSE)
        center_text(stdscr, 3, "Arrow keys to navigate, Enter to build, q to quit")

        # Options box
        box_h = len(options) + 4
        box_w = min(60, w - 8)
        box_x = (w - box_w) // 2
        box_y = 5
        draw_box(stdscr, box_y, box_x, box_y + box_h, box_x + box_w)

        for i, (key, title, _) in enumerate(options):
            y = box_y + 2 + i
            val = getattr(config, key)
            label = labels[key].get(val, str(val))
            prefix = "> " if i == current else "  "
            attr = curses.A_BOLD | curses.color_pair(4) if i == current else 0
            stdscr.addstr(y, box_x + 3, f"{prefix}{title:<20} {label}", attr)

        # Summary
        stdscr.addstr(box_y + box_h + 2, box_x, f"Summary: {config.summary()}", curses.A_DIM)

        # Footer
        stdscr.addstr(h - 2, 4, "Shortcuts: r=release d=debug p=profile  a=AVX2  5=AVX512  s=sanitizer  c=clean  t=target")
        stdscr.refresh()

        key = stdscr.getch()

        if key in (ord('q'), ord('Q')):
            return 0
        elif key in (curses.KEY_UP, ord('k')):
            current = (current - 1) % len(options)
        elif key in (curses.KEY_DOWN, ord('j')):
            current = (current + 1) % len(options)
        elif key in (curses.KEY_LEFT, ord('h')):
            opt_key, _, opt_vals = options[current]
            idx = opt_vals.index(getattr(config, opt_key))
            setattr(config, opt_key, opt_vals[(idx - 1) % len(opt_vals)])
        elif key in (curses.KEY_RIGHT, ord('l'), ord(' ')):
            opt_key, _, opt_vals = options[current]
            idx = opt_vals.index(getattr(config, opt_key))
            setattr(config, opt_key, opt_vals[(idx + 1) % len(opt_vals)])
        elif key == ord('\n'):
            run_build(stdscr, config)
        # Quick shortcuts
        elif key == ord('r'):
            config.build_type = "release"
        elif key == ord('d'):
            config.build_type = "debug"
        elif key == ord('p'):
            config.build_type = "profile"
        elif key == ord('a'):
            config.avx2 = not config.avx2
        elif key == ord('5'):
            config.avx512 = not config.avx512
        elif key == ord('s'):
            _, _, vals = options[3]
            idx = vals.index(config.sanitizer)
            config.sanitizer = vals[(idx + 1) % len(vals)]
        elif key == ord('c'):
            config.clean = not config.clean
        elif key == ord('t'):
            _, _, vals = options[5]
            idx = vals.index(config.target)
            config.target = vals[(idx + 1) % len(vals)]

    return 0


def main():
    # Ensure terminal is large enough
    try:
        return curses.wrapper(main_tui)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
