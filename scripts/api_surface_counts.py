#!/usr/bin/env python3
"""Count the public C API surface per header and keep the docs table honest.

Counts `qihse_*` function declarations in each header listed by the
API-surface table in docs/API_REFERENCE.md, distinguishes exported symbols
(defined in libqihse.so) from `static inline` wrappers, and either rewrites the
table or fails when it has drifted.

    scripts/api_surface_counts.py            # print the table
    scripts/api_surface_counts.py --write    # rewrite it in the docs
    scripts/api_surface_counts.py --check    # exit 1 when the docs are stale

Limitations, stated so the numbers are not over-trusted: macro-generated
declarations are invisible (the preprocessor is not run), and only names
beginning `qihse_` are counted.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "API_REFERENCE.md"
LIB = ROOT / "libqihse.so"
PREFIX = "qihse_"

TABLE_HEADER = "| Header | Declared | Exported |"
TABLE_RULE = "|---|---|---|"


def strip_comments_and_strings(text: str) -> str:
    out = []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "/*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
        elif two == "//":
            end = text.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
        elif text[i] == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            out.append(' "" ')
        elif text[i] == "'":
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "'":
                    i += 1
                    break
                i += 1
            out.append(" '' ")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def declarations(text: str) -> tuple[list[str], list[str]]:
    """(external prototypes, static inline definitions) at file scope."""
    text = strip_comments_and_strings(text)
    # `extern "C" {` (after string stripping: extern "" {) is a linkage guard,
    # not a scope the declarations live inside; treat it as transparent.
    text = re.sub(r'extern\s*""\s*\{', " ", text)
    # Drop preprocessor lines but keep them as buffer breaks.
    lines = []
    for line in text.splitlines():
        lines.append("\x00" if line.lstrip().startswith("#") else line)
    text = "\n".join(lines)

    extern: list[str] = []
    inline: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch == "\x00":
            if depth == 0:
                buf.clear()
            continue
        if ch == "{":
            if depth == 0 and "static inline" in "".join(buf) and _is_function("".join(buf)):
                inline.append(_name("".join(buf)))
                buf.clear()
                depth = 1
                continue
            depth += 1
            continue
        if ch == "}":
            depth = max(0, depth - 1)
            if depth == 0:
                buf.clear()
            continue
        if depth > 0:
            continue
        if ch == ";":
            chunk = "".join(buf).strip()
            buf.clear()
            if chunk and "typedef" not in chunk and _is_function(chunk):
                extern.append(_name(chunk))
            continue
        buf.append(ch)
    return extern, inline


def _is_function(chunk: str) -> bool:
    flat = " ".join(chunk.split())
    return bool(re.search(r"\b\w+\s*\([^()]*\)\s*$", flat))


def _name(chunk: str) -> str:
    flat = " ".join(chunk.split())
    match = re.search(r"\b(\w+)\s*\([^()]*\)\s*$", flat)
    return match.group(1) if match else ""


def exported_symbols() -> set[str]:
    if not LIB.is_file():
        return set()
    try:
        out = subprocess.run(["nm", "-D", "--defined-only", str(LIB)],
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return set()
    return {line.split()[-1] for line in out.splitlines() if line.split()}


def header_rows(headers: list[str], exported: set[str]) -> list[tuple[str, int, str]]:
    rows = []
    for header in headers:
        path = ROOT / header
        if not path.is_file():
            raise SystemExit(f"missing header: {header}")
        extern, inline = declarations(path.read_text(encoding="utf-8"))
        extern = [f for f in extern if f.startswith(PREFIX)]
        inline = [f for f in inline if f.startswith(PREFIX)]
        total = len(extern) + len(inline)
        if inline:
            resolved = sum(1 for f in extern if f in exported) if exported else len(extern)
            exported_text = f"{resolved} ({len(inline)} `static inline`)"
        else:
            resolved = sum(1 for f in extern if f in exported) if exported else len(extern)
            exported_text = str(resolved)
        rows.append((header, total, exported_text))
    return rows


def doc_headers(text: str) -> list[str]:
    start = text.index(TABLE_HEADER)
    end = text.index("\n\n", start)
    block = text[start:end]
    return re.findall(r"\|\s*`(include/[^`]+)`\s*\|", block)


def render(rows: list[tuple[str, int, str]]) -> str:
    lines = [TABLE_HEADER, TABLE_RULE]
    for header, total, exported_text in rows:
        lines.append(f"| `{header}` | {total} | {exported_text} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="rewrite the table")
    parser.add_argument("--check", action="store_true", help="fail when stale")
    args = parser.parse_args()

    text = DOC.read_text(encoding="utf-8")
    headers = doc_headers(text)
    if not headers:
        raise SystemExit("no API surface table found in the docs")
    exported = exported_symbols()
    rows = header_rows(headers, exported)
    rendered = render(rows)

    start = text.index(TABLE_HEADER)
    end = text.index("\n\n", start)
    current = text[start:end]

    declared = sum(total for _, total, _ in rows)
    print(rendered)
    print(f"\ntotal declared: {declared}")
    if exported:
        print(f"library symbols available: {len(exported)}")

    if args.write:
        DOC.write_text(text[:start] + rendered + text[end:], encoding="utf-8")
        print(f"\nrewrote {DOC.relative_to(ROOT)}")
        return 0
    if args.check and current.strip() != rendered.strip():
        print("\nSTALE: docs/API_REFERENCE.md table does not match the headers",
              file=sys.stderr)
        return 1
    if args.check:
        print("\nOK: table matches the headers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
