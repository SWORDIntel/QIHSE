#!/usr/bin/env python3
"""Build a deterministic text-vector sample workload from a PDF."""

from __future__ import annotations

import argparse
import hashlib
import math
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")


def extract_pdf_text(pdf_path: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="qihse_pdf_text_") as temp_dir:
        output_path = Path(temp_dir) / "text.txt"
        try:
            subprocess.run(
                ["pdftotext", "-layout", str(pdf_path), str(output_path)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("pdftotext is required for PDF sample extraction") from exc
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"pdftotext failed: {exc.stderr.strip()}") from exc
        return output_path.read_text(encoding="utf-8", errors="replace")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def chunk_tokens(tokens: list[str], chunk_size: int) -> list[list[str]]:
    return [tokens[index:index + chunk_size] for index in range(0, len(tokens), chunk_size)]


def token_bucket(token: str, dims: int) -> tuple[int, float]:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    value = int.from_bytes(digest, "little")
    bucket = value % dims
    sign = 1.0 if ((value >> 63) & 1) == 0 else -1.0
    return bucket, sign


def embed_chunk(tokens: list[str], dims: int) -> list[float]:
    vector = [0.0] * dims
    for token in tokens:
        bucket, sign = token_bucket(token, dims)
        vector[bucket] += sign

    norm = math.sqrt(sum(value * value for value in vector))
    if norm > 0.0:
        vector = [value / norm for value in vector]
    return vector


def dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def write_f32_matrix(path: Path, rows: list[list[float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for row in rows:
            handle.write(struct.pack(f"<{len(row)}f", *row))


def write_u32_matrix(path: Path, rows: list[list[int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        for row in rows:
            handle.write(struct.pack(f"<{len(row)}I", *row))


def build_vectors(chunks: list[list[str]], dims: int, rows: int, queries: int) -> tuple[list[list[float]], list[list[float]]]:
    if not chunks:
        raise RuntimeError("PDF text did not produce any token chunks")

    base_vectors: list[list[float]] = []
    query_vectors: list[list[float]] = []
    for index in range(rows):
        base_vectors.append(embed_chunk(chunks[index % len(chunks)], dims))

    query_offset = max(1, len(chunks) // 3)
    for index in range(queries):
        chunk = chunks[(query_offset + index) % len(chunks)]
        query_vectors.append(embed_chunk(chunk, dims))

    return base_vectors, query_vectors


def build_ground_truth(base_vectors: list[list[float]], query_vectors: list[list[float]], top_k: int) -> list[list[int]]:
    truth: list[list[int]] = []
    for query in query_vectors:
        ranked = sorted(
            ((dot(query, base), index) for index, base in enumerate(base_vectors)),
            key=lambda item: (-item[0], item[1]),
        )
        truth.append([index for _, index in ranked[:top_k]])
    return truth


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pdf", required=True, help="source PDF path")
    parser.add_argument("--out", default="data/vxug_pdf_sample", help="output directory")
    parser.add_argument("--dims", type=int, default=256)
    parser.add_argument("--rows", type=int, default=256)
    parser.add_argument("--queries", type=int, default=16)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--chunk-tokens", type=int, default=96)
    args = parser.parse_args(argv)

    pdf_path = Path(args.pdf).resolve()
    if not pdf_path.exists():
        print(f"PDF not found: {pdf_path}", file=sys.stderr)
        return 1
    if args.dims <= 0 or args.rows <= 0 or args.queries <= 0 or args.top_k <= 0:
        print("dims, rows, queries, and top-k must be positive", file=sys.stderr)
        return 1
    if args.top_k > args.rows:
        print("top-k must be <= rows", file=sys.stderr)
        return 1

    try:
        text = extract_pdf_text(pdf_path)
        chunks = chunk_tokens(tokenize(text), args.chunk_tokens)
        base_vectors, query_vectors = build_vectors(chunks, args.dims, args.rows, args.queries)
        ground_truth = build_ground_truth(base_vectors, query_vectors, args.top_k)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    write_f32_matrix(out_dir / "base.f32", base_vectors)
    write_f32_matrix(out_dir / "query.f32", query_vectors)
    write_u32_matrix(out_dir / "ground_truth.u32", ground_truth)

    print(
        "wrote vxug-pdf-sample "
        f"rows={args.rows} queries={args.queries} dims={args.dims} top_k={args.top_k} "
        f"out={out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
