#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
mkdir -p build
run_dir="$(mktemp -d "build/w11_inventory.XXXXXX")"
trap 'rm -rf "$run_dir"' EXIT
mkdir -m 700 "$run_dir/data"

library_dir="${QIHSE_PREBUILT_LIB_DIR:-$repo_root}"
if [[ -z "${QIHSE_PREBUILT_LIB_DIR:-}" ]]; then
    make -s lib
fi
"${CC:-cc}" -std=c11 -Wall -Wextra \
    -Iinclude -Icore -I. \
    -o "$run_dir/inventory_reservation" \
    examples/w11_inventory/inventory_reservation.c \
    -L"$library_dir" -lqihse -Wl,-rpath,"$library_dir" -lpthread

QIHSE_DATA_DIR="$run_dir/data" \
LD_LIBRARY_PATH="$library_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$run_dir/inventory_reservation"
