# W12.0 uses production CPU kernels, with no full-engine or GPU dependency.
W12_CC ?= cc
W12_FLAGS = -std=c99 -D_GNU_SOURCE -O2 -fno-fast-math -ffp-contract=off -fno-tree-vectorize -Iinclude -Ibackends/cpu -pthread
W12_SOURCES = benchmarks/src/qihse_w12_fp32.c backends/cpu/qihse_cpu_distance.c backends/cpu/qihse_cpu_detect.c
W12_HEADERS = benchmarks/include/qihse_w12_fp32.h backends/cpu/qihse_cpu_distance.h backends/cpu/qihse_cpu_detect.h include/qihse_vector_db.h
W12_ARGS ?=

.PHONY: test-w12-fp32 test-w12-fp32-sanitize bench-w12-fp32

# Include the lightweight contract checks in the normal repository test suite.
test: test-w12-fp32

test-w12-fp32: build/w12/test_w12_fp32
	./build/w12/test_w12_fp32
	CC="$(W12_CC)" python3 tests/test_w12_fp32_baseline.py

build/w12/test_w12_fp32: tests/test_w12_fp32_baseline.c $(W12_SOURCES) $(W12_HEADERS)
	mkdir -p build/w12
	$(W12_CC) $(W12_FLAGS) $< $(W12_SOURCES) -lm -o $@

test-w12-fp32-sanitize:
	mkdir -p build/w12
	$(W12_CC) $(W12_FLAGS) -g -fsanitize=address,undefined -fno-sanitize-recover=all \
		tests/test_w12_fp32_baseline.c $(W12_SOURCES) -lm -o build/w12/test_w12_fp32_sanitize
	ASAN_OPTIONS="$${ASAN_OPTIONS:-detect_leaks=1}" ./build/w12/test_w12_fp32_sanitize

bench-w12-fp32:
	CC="$(W12_CC)" python3 benchmarks/scripts/qihse_w12_fp32_baseline.py $(W12_ARGS)
