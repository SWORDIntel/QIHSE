#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
mkdir -p build/core-math-regressions
compiler=${CC:-cc}
flags='-O2'
if [ "${QIHSE_SANITIZE:-0}" = 1 ]; then
    flags='-O1 -g -fsanitize=address,undefined,float-cast-overflow -fno-omit-frame-pointer -fno-sanitize-recover=all'
fi
run_lane() {
    lane=$1
    shift
    # Intentional word splitting applies only to these fixed, locally selected flags.
    "$compiler" -std=c99 -D_GNU_SOURCE -Wall -Wextra $flags "$@" \
        -ffunction-sections -fdata-sections -I. -Iinclude -Icore -Ialgorithms -Ibackends/cpu \
        tests/test_core_math_regressions.c src/bombe/qihse_math.c src/qihse_exports.c \
        algorithms/qihse_superposition.c algorithms/qihse_amplification.c \
        algorithms/qihse_dimensions.c algorithms/qihse_verification.c \
        -Wl,--gc-sections -lm -lcrypto -pthread -o "build/core-math-regressions/test_$lane"
    printf '%s\n' "Core math lane: $lane"
    "./build/core-math-regressions/test_$lane"
}
run_lane scalar
if rg -q '(^| )avx2( |$)' /proc/cpuinfo && rg -q '(^| )fma( |$)' /proc/cpuinfo; then
    run_lane avx2 -mavx2 -mfma
else
    printf '%s\n' 'SKIP AVX2/FMA core math: host does not advertise required ISA.'
fi
if rg -q '(^| )avx512f( |$)' /proc/cpuinfo && rg -q '(^| )avx512dq( |$)' /proc/cpuinfo && rg -q '(^| )fma( |$)' /proc/cpuinfo; then
    run_lane avx512 -mavx512f -mavx512dq -mavx2 -mfma
else
    printf '%s\n' 'SKIP AVX512F/DQ/FMA core math: host does not advertise required ISA.'
fi
