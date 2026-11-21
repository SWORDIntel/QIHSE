#!/usr/bin/env bash
set -euo pipefail
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/qihse-math-tests.XXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT
cd -- "$project_root"
compiler=${CC:-gcc}
common=(-std=c99 -D_GNU_SOURCE -O2 -g -Wall -Wextra -ffunction-sections -fdata-sections
        -I. -Iinclude -Icore -Ialgorithms -Ibackends/cpu)
if [[ ${QIHSE_MATH_SANITIZERS:-0} == 1 ]]; then
    common+=(-fsanitize=address,undefined -fno-omit-frame-pointer)
fi
sources=(tests/test_runtime_math_regressions.c src/bombe/qihse_math.c src/bombe/qihse_hetero.c)
"$compiler" "${common[@]}" "${sources[@]}" -Wl,--gc-sections -lm -pthread -o "$build_dir/scalar"
"$build_dir/scalar"
if rg -q '(^| )avx2( |$)' /proc/cpuinfo && rg -q '(^| )fma( |$)' /proc/cpuinfo; then
    "$compiler" "${common[@]}" -DTEST_AVX2 -mavx2 -mfma "${sources[@]}" backends/cpu/qihse_cpu_avx2.c \
        -Wl,--gc-sections -lm -pthread -o "$build_dir/avx2"
    "$build_dir/avx2"
else
    printf '%s\n' 'SKIP AVX2/FMA math regression: host does not advertise required ISA.'
fi
if rg -q '(^| )avx512f( |$)' /proc/cpuinfo && rg -q '(^| )fma( |$)' /proc/cpuinfo; then
    "$compiler" "${common[@]}" -DTEST_AVX512 -mavx512f -mfma "${sources[@]}" backends/cpu/qihse_cpu_avx512.c \
        -Wl,--gc-sections -lm -pthread -o "$build_dir/avx512"
    "$build_dir/avx512"
else
    printf '%s\n' 'SKIP AVX512/FMA math regression: host does not advertise required ISA.'
fi
