#!/usr/bin/env python3
"""Gate per-function ISA kernels behind QIHSE_ENABLE_* / compiler macros.

GCC __attribute__((target(...))) functions ignore global flags, so without
compile-time guards every build ships every ISA variant (a "fat binary").
This script wraps each kernel in a compile-time guard so a native build
contains only the target machine's ISA:

  #if defined(QIHSE_ENABLE_AVX2) || defined(__AVX2__)
  __attribute__((target("avx2,fma"))) float fn(...) { ... }
  #endif

- static kernels: the same guard is applied to dispatch call sites of the
  form `if (cond) { return FN(...); }` so nothing references a kernel that
  was compiled out. Any static kernel whose call site cannot be found is
  reported so it can be reviewed manually.
- external kernels: a scalar #else fallback is emitted so library symbols
  always exist (fallback name = _scalar-suffixed counterpart).
- __attribute__((target_clones(...))) lists are rebuilt from the enabled ISAs.

Only ISA groups that vary between QIHSE nodes are gated (AVX2, AVX-512,
AVX-VNNI, AMX, F16C, BMI1/2); baseline groups (AVX, SSE*, SSSE3, POPCNT,
PCLMUL) are left alone.

Usage: python3 scripts/gate_isa_kernels.py [--apply] [FILE...]
  dry run prints diffs; --apply writes files in place.
"""

import re
import sys
import difflib

# feature token(s) -> (QIHSE_ENABLE_* macro, compiler macro). Varying ISAs only.
# NOTE: bmi/bmi2 are intentionally NOT gated — they are 1-2 instruction inline
# helpers whose call sites are large multi-statement blocks guarded by
# s_cpu_has_bmi2/qihse_has_bmi1() at runtime; gating them would require
# wrapping whole code blocks for a negligible size win.
ISA_GUARDS = [
    (("avx512bf16", "avx512f"), ("QIHSE_ENABLE_AMX", "__AVX512BF16__")),
    (("avx512vnni",), ("QIHSE_ENABLE_AVX512", "__AVX512F__")),
    (("avx512vpopcntdq",), ("QIHSE_ENABLE_AVX512", "__AVX512F__")),
    (("avx512f",), ("QIHSE_ENABLE_AVX512", "__AVX512F__")),
    (("avx2",), ("QIHSE_ENABLE_AVX2", "__AVX2__")),
    (("avxvnni",), ("QIHSE_ENABLE_AVX_VNNI", "__AVXVNNI__")),
    (("avx", "f16c"), ("QIHSE_ENABLE_F16C", "__F16C__")),
    (("f16c",), ("QIHSE_ENABLE_F16C", "__F16C__")),
]

# Handled elsewhere: manual gating, Makefile gating, detection probes,
# or already guarded with #if defined(__AVX2__)/__x86_64__ where that is enough.
SKIP_FILES = {
    "backends/cpu/qihse_cpu_detect.c",     # runtime detection probes
    "backends/cpu/qihse_cpu_distance.c",   # gated manually
    "backends/cpu/qihse_cpu_amx.c",        # whole file Makefile-gated on AMX
    "src/spinnaker/qihse_cluster_bus.c",   # already #if defined(__AVX2__)
    "tests/bench_simd.c",                  # test tool, already #ifdef __AVX512BF16__
}

# target_clones list entries -> QIHSE_ENABLE_* macro (ordered best->worst).
CLONE_ISA = [("avx512f", "QIHSE_ENABLE_AVX512"),
             ("avx2", "QIHSE_ENABLE_AVX2"),
             ("avx", "QIHSE_ENABLE_AVX")]


def guard_cond(enable, comp):
    conds = [c for c in (f"defined({enable})" if enable else None,
                         f"defined({comp})" if comp else None) if c]
    return " || ".join(conds)


def find_guard(features):
    # Most-specific-first: a guard matches when ALL of its tokens are present
    # (e.g. "avx512vnni,avx512vl,avx512f,avx512bw" -> AVX512 via avx512vnni).
    tset = set(features)
    for toks, (enable, comp) in ISA_GUARDS:
        if all(t in tset for t in toks):
            return enable, comp
    return None, None


def match_brace(text, start):
    """Index just past the '}' closing the '{' at index start."""
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == '"':
            j = text.find('"', i + 1)
            i = n if j == -1 else j + 1
            continue
        if c == "'":
            j = text.find("'", i + 1)
            i = n if j == -1 else j + 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced braces")


def param_names(sig, fn_name):
    """Extract parameter variable names from a function signature."""
    paren = sig.find("(", sig.find(fn_name))
    if paren == -1:
        return None
    close = sig.find(")", paren)
    if close == -1:
        return None
    params = sig[paren + 1:close].strip()
    if params in ("", "void"):
        return []
    names = []
    for pm in params.split(","):
        mm = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\[[^\]]*\])?\s*$', pm.strip())
        if not mm:
            return None
        names.append(mm.group(1))
    return names


def transform_file(path):
    with open(path) as f:
        text = f.read()

    pat = re.compile(
        r'__attribute__\(\(\s*target(_clones)?\s*\(\s*'
        r'"([^"]+)"((?:\s*,\s*"[^"]+")*)\s*\)\s*\)\)')
    out = []
    i = 0
    n = len(text)
    changes = 0
    static_gated = []  # (fn_name, guard)

    while True:
        m = pat.search(text, i)
        if not m:
            out.append(text[i:])
            break
        # a 'static' qualifier may sit just before the attribute; fold it into
        # the gated region so the guard covers the whole declaration
        pre_static = re.search(r'(static\s*)$', text[max(0, m.start() - 40):m.start()])
        func_start = m.start() - len(pre_static.group(1)) if pre_static else m.start()
        out.append(text[i:func_start])
        is_clones = m.group(1) == "_clones"
        # target("a,b") style: group(2) = "a,b". target_clones("a","b") style:
        # group(2) = "a", group(3) = ",\"b\",\"c\"".
        raw = m.group(2) + m.group(3)
        features = [t.strip().strip('"') for t in re.split(r'[,]', raw) if t.strip()]

        brace = text.find("{", m.end())
        if brace == -1:
            out.append(text[m.start():])
            i = n
            break
        body_end = match_brace(text, brace)
        sig = text[m.end():brace]
        fn_match = re.search(
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;{}]*$', sig, re.S)
        fn_name = fn_match.group(1) if fn_match else None
        func_text = text[func_start:body_end]

        if is_clones:
            # Nested #if/#else chain: each level keeps its ISA's clones plus
            # everything below it; the deepest level is the plain default.
            clones = [(tok, macro) for tok, macro in CLONE_ISA if tok in features]
            keep_default = "default" in features
            block = []
            for idx in range(len(clones)):
                tail = [c[0] for c in clones[idx:]] + (["default"] if keep_default else [])
                attr = '__attribute__((target_clones(' + ", ".join(f'"{t}"' for t in tail) + ')))'
                cond = f"defined({clones[idx][1]})"
                block.append(f"#if {cond}")
                block.append(attr)
                block.append("#else")
            if keep_default:
                block.append('__attribute__((target_clones("default")))')
            else:
                block.append("/* no ISA variants enabled */")
            block.append("\n".join("#endif" for _ in range(len(clones))))
            out.append("\n".join(block) + "\n" + text[m.end():body_end])
            changes += 1
            i = body_end
            continue

        enable, comp = find_guard(features)
        if enable is None and comp is None:
            out.append(func_text)  # baseline or unknown — leave untouched
            i = body_end
            continue

        cond = guard_cond(enable, comp)
        guard = f"#if {cond}"
        # 'static' may appear before or after the attribute
        pre = text[max(0, m.start() - 80):m.start()]
        is_static = bool(re.search(r'\bstatic\b', pre + " " + sig))

        if is_static and fn_name:
            out.append(f"{guard}\n{func_text}\n#endif")
            static_gated.append((fn_name, guard))
            changes += 1
            i = body_end
            continue

        # external: emit scalar fallback so the symbol always exists
        fallback = None
        if fn_name:
            names = param_names(sig, fn_name)
            if names is not None:
                base = re.sub(
                    r'_(?:avx512(?:vnni|vpopcntdq|bf16)?|avx2|avxvnni|f16c(?:_fma)?|bmi2?)$',
                    "_scalar", fn_name)
                fallback = (f"#else\n{sig.rstrip()}\n{{\n    return {base}"
                            f"({', '.join(names)});\n}}\n#endif")
        if fallback:
            out.append(f"{guard}\n{func_text}\n{fallback}")
        else:
            print(f"WARN {path}: no fallback generated for {fn_name}",
                  file=sys.stderr)
            out.append(f"{guard}\n{func_text}\n#endif")
        changes += 1
        i = body_end

    new_text = "".join(out)

    # Post-pass: gate dispatch call sites of gated static kernels.
    for fn_name, guard in static_gated:
        single = re.compile(
            r'(?m)^([ \t]*if\s*\([^)]*\)\s*return\s+'
            + re.escape(fn_name) + r'\([^;]*\);\s*)$')
        multi = re.compile(
            r'(?m)^([ \t]*if\s*\([^)]*\)\s*\{\s*\n'
            r'\s*return\s+' + re.escape(fn_name) + r'\([^;]*\);\s*\n'
            r'\s*\}\s*)$')
        new2, cnt1 = single.subn(
            lambda m: f"{guard}\n{m.group(1)}\n#endif", new_text)
        new2, cnt2 = multi.subn(
            lambda m: f"{guard}\n{m.group(1)}\n#endif", new2)
        if cnt1 + cnt2 == 0:
            print(f"WARN {path}: no call site found for static {fn_name}",
                  file=sys.stderr)
        new_text = new2

    if new_text == text:
        return text, 0
    return new_text, changes


def main():
    apply_ = "--apply" in sys.argv
    files = [a for a in sys.argv[1:] if a != "--apply" and a.endswith((".c", ".h"))]
    if not files:
        import subprocess
        files = subprocess.run(
            ["git", "ls-files", "*.c", "*.h"],
            capture_output=True, text=True).stdout.split()
    for path in files:
        if path in SKIP_FILES or "/vendor/" in path:
            continue
        try:
            new_text, changes = transform_file(path)
        except ValueError as e:
            print(f"SKIP {path}: {e}", file=sys.stderr)
            continue
        if not changes:
            continue
        with open(path) as f:
            old = f.read()
        if old == new_text:
            continue
        diff = difflib.unified_diff(old.splitlines(True), new_text.splitlines(True),
                                    fromfile=f"a/{path}", tofile=f"b/{path}")
        if apply_:
            with open(path, "w") as f:
                f.write(new_text)
            print(f"APPLIED {path} ({changes} kernel(s))")
        else:
            print(f"=== {path} ({changes} kernel(s)) ===")
            print("".join(diff))


if __name__ == "__main__":
    main()
