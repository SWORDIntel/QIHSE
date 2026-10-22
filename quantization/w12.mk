# W12.1 standalone numerical reference only. No libqihse or engine-mode wiring.
TQ_CC ?= cc
TQ_FLAGS = -std=c99 -O2 -Wall -Wextra -Werror -pedantic -fno-fast-math -ffp-contract=off -fno-tree-vectorize -I. -Iquantization/include
TQ_SOURCES = quantization/src/qihse_turboquant.c quantization/src/qihse_turboquant_tables.c
TQ_HEADERS = quantization/include/qihse_turboquant.h quantization/include/qihse_turboquant_tables.h quantization/src/qihse_turboquant_rng.h

.PHONY: test-w12-turboquant test-w12-turboquant-sanitize
test: test-w12-turboquant

test-w12-turboquant: build/w12/test_turboquant build/w12/test_turboquant_tables
	./build/w12/test_turboquant_tables
	./build/w12/test_turboquant

build/w12/test_turboquant: tests/test_turboquant.c $(TQ_SOURCES) $(TQ_HEADERS)
	mkdir -p build/w12
	$(TQ_CC) $(TQ_FLAGS) $< $(TQ_SOURCES) -lm -o $@

build/w12/test_turboquant_tables: tests/test_turboquant_tables.c quantization/src/qihse_turboquant_tables.c quantization/include/qihse_turboquant_tables.h
	mkdir -p build/w12
	$(TQ_CC) $(TQ_FLAGS) $< quantization/src/qihse_turboquant_tables.c -lm -o $@

test-w12-turboquant-sanitize:
	mkdir -p build/w12
	$(TQ_CC) $(TQ_FLAGS) -g -fsanitize=address,undefined -fno-sanitize-recover=all \
		tests/test_turboquant_tables.c quantization/src/qihse_turboquant_tables.c -lm -o build/w12/test_turboquant_tables_sanitize
	$(TQ_CC) $(TQ_FLAGS) -g -fsanitize=address,undefined -fno-sanitize-recover=all \
		tests/test_turboquant.c $(TQ_SOURCES) -lm -o build/w12/test_turboquant_sanitize
	ASAN_OPTIONS="$${ASAN_OPTIONS:-detect_leaks=1}" ./build/w12/test_turboquant_tables_sanitize
	ASAN_OPTIONS="$${ASAN_OPTIONS:-detect_leaks=1}" ./build/w12/test_turboquant_sanitize

# Optional GNU-compatible linker fault-injection check; not a portable ABI API.
.PHONY: test-w12-turboquant-alloc
test-w12-turboquant-alloc:
	mkdir -p build/w12
	$(TQ_CC) $(TQ_FLAGS) -g -fsanitize=address,undefined -fno-sanitize-recover=all \
		tests/test_turboquant_alloc.c $(TQ_SOURCES) -lm \
		-Wl,--wrap=malloc,--wrap=calloc,--wrap=free -o build/w12/test_turboquant_alloc
	ASAN_OPTIONS="$${ASAN_OPTIONS:-detect_leaks=1}" ./build/w12/test_turboquant_alloc

# Intentionally expensive dense-QR boundary checks, excluded from default tests.
.PHONY: test-w12-turboquant-large
test-w12-turboquant-large: build/w12/test_turboquant_large
	./build/w12/test_turboquant_large

build/w12/test_turboquant_large: tests/test_turboquant_large.c $(TQ_SOURCES) $(TQ_HEADERS)
	mkdir -p build/w12
	$(TQ_CC) $(TQ_FLAGS) $< $(TQ_SOURCES) -lm -o $@
