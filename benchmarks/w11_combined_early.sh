#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
mkdir -p build
run_dir="$(mktemp -d "build/w11_combined_early.XXXXXX")"
trap 'rm -rf "$run_dir"' EXIT
mkdir -m 700 "$run_dir/data"

make -s libqihse.so >&2
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Iinclude -Icore -I. \
    -o "$run_dir/w11_combined_early" benchmarks/w11_combined_early.c \
    -L. -lqihse -Wl,-rpath,"$repo_root" -lpthread

QIHSE_DATA_DIR="$run_dir/data" LD_LIBRARY_PATH=".:${LD_LIBRARY_PATH:-}" \
    "$run_dir/w11_combined_early" "${1:-64}" "${2:-20261106}"
