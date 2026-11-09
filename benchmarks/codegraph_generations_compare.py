#!/usr/bin/env python3
"""Compare immutable CodeGraph file blocks with equivalent whole Zstd snapshots.

Synthetic semantic 128-bit IDs have hash-like entropy. This measures standalone
codec operations, not whole parsing/import/publication. Every generation is
independently decoded and compared byte for byte. Raw export creation/staging,
engine KV import, and native publication verification are outside these timings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def fixture(path: Path, files: int, nodes: int, seq: int, changed: int | None) -> None:
    rows: list[tuple[str, dict]] = [
        (
            "_meta",
            {
                "format": "qihse-codegraph-v1",
                "identity": "synthetic-128",
                "freshness_revision": seq,
            },
        )
    ]
    for file in range(files):
        source = f"src/module{file:04d}.c"
        ids = [digest(f"node:{source}:{i}") for i in range(nodes)]
        for i, node in enumerate(ids):
            rows.append(
                (
                    "n:" + node,
                    {
                        "t": "node",
                        "id": node,
                        "file": source,
                        "name": f"function_{file:04d}_{i:04d}",
                        "kind": "Function",
                        "line_start": i * 10 + 1,
                        "line_end": i * 10 + 8,
                        "is_test": False,
                        "unknown": "changed" if changed == file else "preserve exactly",
                    },
                )
            )
            for relation in range(3):
                edge = digest(f"edge:{source}:{i}:{relation}")
                rows.append(
                    (
                        "e:" + edge,
                        {
                            "t": "edge",
                            "id": edge,
                            "file": source,
                            "source": node,
                            "target": ids[(i + relation + 1) % nodes],
                            "relation": "CALLS",
                            "line": i * 10 + relation + 2,
                            "confidence": 0.95000,
                            "traversable": True,
                            "resolution": "resolved",
                            "tier": "semantic",
                            "unknown": "changed"
                            if changed == file
                            else "preserve exactly",
                        },
                    )
                )
    rows.append(
        (
            "_end",
            {"nodes": files * nodes, "edges": files * nodes * 3, "unresolved_edges": 0},
        )
    )
    with path.open("wb") as out:
        for index, (key, record) in enumerate(rows):
            value = json.dumps(
                record, separators=(",", ":"), ensure_ascii=True
            ).encode()
            out.write(
                f"{len(key)} {len(value)} 0 0 0 0 {seq + index}\n".encode()
                + key.encode()
                + value
                + b"\n"
            )
    path.chmod(0o600)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--driver", type=Path, required=True)
    ap.add_argument("--files", type=int, default=100)
    ap.add_argument("--nodes-per-file", type=int, default=80)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if not 1 <= args.files <= 1000 or not 1 <= args.nodes_per_file <= 1000:
        ap.error("fixture scale out of bounds")
    if args.files * args.nodes_per_file * 4 + 2 > 2_000_000:
        ap.error("fixture exceeds bounded codec record limit")
    driver = args.driver.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix="codegraph-generations-benchmark-") as temp:
        root = Path(temp)
        blocks = root / "blocks"

        def run(mode: str, source: Path, output: Path) -> dict:
            state = root / f"auth-{len(list(root.glob('auth-*')))}"
            state.mkdir(mode=0o700)
            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = str(Path(__file__).resolve().parent.parent) + (
                os.pathsep + env["LD_LIBRARY_PATH"]
                if env.get("LD_LIBRARY_PATH")
                else ""
            )
            process = subprocess.run(
                [str(driver), mode, str(source), str(output), str(blocks), str(state)],
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            return json.loads(process.stdout.splitlines()[-1])

        parents = []
        for revision, changed in enumerate([None, None, args.files // 2]):
            raw = root / f"graph-{revision}.raw"
            fixture(
                raw, args.files, args.nodes_per_file, revision * 100000 + 1, changed
            )
            full = root / f"full-{revision}.kv"
            zstd = run("zstd", raw, full)
            dictionary_file = root / f"dictionary-{revision}.kv"
            dictionary = run("packed-v3", raw, dictionary_file)
            dictionary_raw = root / f"dictionary-{revision}.raw"
            dictionary_decode = run("decode-v3", dictionary_file, dictionary_raw)
            assert dictionary_raw.read_bytes() == raw.read_bytes()
            parent = root / f"parent-{revision}.kv"
            generation = run("encode", raw, parent)
            parents.append(parent)
            decoded = root / f"decoded-{revision}.raw"
            decode = run("decode", parent, decoded)
            assert decoded.read_bytes() == raw.read_bytes()
            previous = parents[max(0, len(parents) - 2) :]
            for old in parents[:-2]:
                old.unlink(missing_ok=True)
            gc = run("gc", parent, previous[0]) if len(previous) == 2 else None
            actual_blocks = sum(p.stat().st_size for p in blocks.glob("*.qgb"))
            row = {
                "revision": revision,
                "changed_file": changed,
                "raw_bytes": raw.stat().st_size,
                "zstd": zstd,
                "packed_v3": dictionary,
                "packed_v3_decode": dictionary_decode,
                "generations": generation,
                "decode": decode,
                "verified_exact": True,
                "generation_current_previous_bytes": actual_blocks
                + sum(p.stat().st_size for p in previous),
                "generation_snapshot_bytes_written": generation["parent_bytes"]
                + generation["new_block_bytes"],
                "zstd_snapshot_bytes_written": full.stat().st_size,
                "gc": gc,
                "generation_physical_block_bytes": sum(
                    p.stat().st_blocks * 512 for p in blocks.glob("*.qgb")
                ),
                "generation_current_previous_allocated_bytes": sum(
                    p.stat().st_blocks * 512 for p in blocks.glob("*.qgb")
                )
                + sum(p.stat().st_blocks * 512 for p in previous),
                "zstd_current_previous_bytes": sum(
                    (root / f"full-{i}.kv").stat().st_size
                    for i in range(max(0, revision - 1), revision + 1)
                ),
                "packed_v3_current_previous_bytes": sum(
                    (root / f"dictionary-{i}.kv").stat().st_size
                    for i in range(max(0, revision - 1), revision + 1)
                ),
            }
            results.append(row)
        report = {
            "methodology": __doc__,
            "platform": platform.platform(),
            "files": args.files,
            "nodes": args.files * args.nodes_per_file,
            "edges": 3 * args.files * args.nodes_per_file,
            "codec_sources": {
                p: hashlib.sha256(
                    (Path(__file__).resolve().parent.parent / p).read_bytes()
                ).hexdigest()
                for p in [
                    "tools/qihse_codegraph_generation.c",
                    "tools/qihse_codegraph_checksum.c",
                    "tools/qihse_codegraph_dictionary.c",
                ]
            },
            "results": results,
            "measurement_limits": [
                "One sample per revision on the execution host; not a general performance guarantee.",
                "Peak RSS covers the standalone authenticated codec process, including auth/library initialization, not the Python fixture producer.",
                "Snapshot bytes written exclude raw export staging and canonical native publication/verification.",
                "GC/accounting validate-only mode writes no reconstructed export.",
                "Current+previous block union is validated and garbage-collected before retained size accounting.",
            ],
        }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "results": [
                    {
                        "revision": r["revision"],
                        "zstd_bytes": r["zstd"]["output_bytes"],
                        "packed_v3_bytes": r["packed_v3"]["output_bytes"],
                        "generation_current_bytes": r["generations"]["parent_bytes"]
                        + r["generations"]["block_bytes"],
                        "generation_snapshot_bytes_written": r[
                            "generation_snapshot_bytes_written"
                        ],
                        "seconds": r["generations"]["seconds"],
                    }
                    for r in results
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
