#!/usr/bin/env bash
set -euo pipefail
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/qihse-rff-maps.XXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT
cd -- "$project_root"
compiler=${CC:-gcc}
flags=(-std=c99 -D_GNU_SOURCE -O2 -g -Wall -Wextra -Werror
       -ffunction-sections -fdata-sections -I. -Iinclude -Icore -Ialgorithms -Ibackends/cpu)
if [[ ${QIHSE_RFF_SANITIZERS:-0} == 1 ]]; then
    flags+=(-O1 -fsanitize=address,undefined,float-cast-overflow -fno-omit-frame-pointer -fno-sanitize-recover=all)
fi
"$compiler" "${flags[@]}" tests/test_rff_maps.c src/bombe/qihse_math.c \
    -Wl,--gc-sections -lm -pthread -o "$build_dir/test_rff_maps"
"$build_dir/test_rff_maps"
