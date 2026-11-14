#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$repo_dir"
test_build=${QIHSE_CORE_TEST_BUILD_DIR:-build/core-search-regressions}
mkdir -p -- "$test_build"
flags=(-std=c99 -D_GNU_SOURCE -O2 -g -Wall -Wextra -ffunction-sections -fdata-sections -I. -Iinclude -Icore -Ialgorithms)
if [[ ${QIHSE_CORE_SANITIZERS:-0} == 1 ]]; then
    flags+=(-O1 -fsanitize=address,undefined,float-cast-overflow -fno-omit-frame-pointer)
fi
"${CC:-gcc}" "${flags[@]}" tests/test_core_search_regressions.c \
    core/qihse.c core/qihse_helpers.c src/bombe/qihse_math.c \
    src/broad_oak/qihse_search.c algorithms/qihse_amplification.c \
    algorithms/qihse_superposition.c -Wl,--gc-sections -lm -pthread \
    -o "$test_build/test_core_search_regressions"
"$test_build/test_core_search_regressions"
