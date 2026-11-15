#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$repo_dir"
bench_build=${QIHSE_CORE_BENCH_BUILD_DIR:-build/core-methods-bench}
mkdir -p -- "$bench_build"
flags=(-std=c99 -D_GNU_SOURCE -O3 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -I. -Iinclude -Icore -Ialgorithms)
profile=O3
if [[ ${QIHSE_CORE_BENCH_SANITIZERS:-0} == 1 ]]; then
    flags+=(-O1 -g -fsanitize=address,undefined,float-cast-overflow -fno-omit-frame-pointer)
    profile=O1-ASan-UBSan-validation-only
fi
revision=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)
if ! git diff --quiet --ignore-submodules -- 2>/dev/null; then
    revision+=-dirty
fi
sources=(benchmarks/qihse_core_methods_bench.c core/qihse.c core/qihse_helpers.c
    src/bombe/qihse_math.c src/broad_oak/qihse_search.c
    algorithms/qihse_amplification.c algorithms/qihse_superposition.c)
# Hash the compiler's actual repository source/header closure, with relative
# paths, so a HEAD-dirty result still identifies the code that was measured.
"${CC:-gcc}" "${flags[@]}" -MM "${sources[@]}" > "$bench_build/dependencies.mk"
mapfile -t source_files < <(sed 's/\\$//' "$bench_build/dependencies.mk" |
    awk '{for (i=1; i<=NF; i++) if ($i !~ /:$/) print $i}' | LC_ALL=C sort -u)
sha256sum -- "${source_files[@]}" > "$bench_build/source-files.sha256"
source_hash=$(sha256sum -- "$bench_build/source-files.sha256")
source_hash=${source_hash%% *}
"${CC:-gcc}" "${flags[@]}" \
    "-DQIHSE_BENCH_REVISION=\"$revision\"" \
    "-DQIHSE_BENCH_SOURCE_SHA256=\"$source_hash\"" \
    "-DQIHSE_BENCH_BUILD_PROFILE=\"$profile\"" \
    "${sources[@]}" -Wl,--gc-sections -lm -pthread \
    -o "$bench_build/qihse_core_methods_bench"
"$bench_build/qihse_core_methods_bench" "$@"
