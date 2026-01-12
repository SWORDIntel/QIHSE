# QIHSE Breakthroughalgo Makefile
# Phase 0.5: Quantum-Inspired Core Algorithms

CC=gcc

# Two build configurations:
# 1. CFLAGS_AVX2 - Works on most modern Intel/AMD CPUs (AVX2)
# 2. CFLAGS_FULL - Requires AVX-512, AMX, VNNI capable CPU (Sapphire Rapids, etc.)

CFLAGS_BASE=-std=c99 -Wall -Wextra -I. -I./core -I./algorithms -I./backends/cpu -I./backends/npu -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include -I../not_stisla/include -fPIC -lm -pthread -O3

# AVX2-only build (works on Core Ultra 7, etc.)
CFLAGS_AVX2=$(CFLAGS_BASE) -mavx2 -mfma

# Full AVX-512/VNNI build for A00 engineering board (no AMX - may not be stable on early samples)
CFLAGS_FULL=$(CFLAGS_BASE) -mavx2 -mfma -mavx512f -mavx512dq -mavx512bw -mavx512vl -mavx512vnni

# Experimental: Full with AMX (uncomment if AMX is confirmed working)
# CFLAGS_AMX=$(CFLAGS_FULL) -mamx-tile -mamx-int8 -mamx-bf16

# Default to AVX2 (safe for most systems)
CFLAGS=$(CFLAGS_AVX2)

LDFLAGS=-ldl -lm

# MONOLITHIC CORE: Use qihse_core.c (complete impl) + qihse_hetero.c (compute pool)
# DO NOT include split files that duplicate these (core/qihse.c, core/qihse_helpers.c, algorithm files)
ABI_SOURCES=core/qihse_plugin.c qihse_core.c qihse_hetero.c
ABI_HEADERS=core/qihse_abi.h core/qihse_plugin.h core/qihse_searchop.h qihse.h qihse_hetero.h

# Algorithm files - EXCLUDED (already in qihse_core.c)
# Only include qihse_dimensions.c which has unique functions not in qihse_core.c
ALGO_SOURCES=algorithms/qihse_dimensions.c algorithms/qihse_verification.c

# CPU Backend files (Phase 1) - Full AVX-512, AMX, VNNI support
CPU_SOURCES=backends/cpu/qihse_cpu_detect.c backends/cpu/qihse_cpu_avx2.c backends/cpu/qihse_cpu_avx512.c
CPU_HEADERS=backends/cpu/qihse_cpu_detect.h backends/cpu/qihse_cpu_avx2.h backends/cpu/qihse_cpu_avx512.h

# Orchestration files (Phase 1.5 + Distributed) - exclude qihse_hetero.c (using root version)
ORCH_SOURCES=orchestration/src/qihse_partition.c orchestration/src/qihse_orchestrator.c orchestration/src/qihse_distributed.c
ORCH_HEADERS=orchestration/include/qihse_hetero.h orchestration/include/qihse_partition.h orchestration/include/qihse_orchestrator.h orchestration/include/qihse_distributed.h

# Memory files (Phase 2)
MEM_SOURCES=memory/src/qihse_memory.c memory/src/qihse_hma.c memory/src/qihse_uma.c
MEM_HEADERS=memory/include/qihse_memory.h memory/include/qihse_hma.h memory/include/qihse_uma.h

# NPU backend files (Phase 2.5 + PIM)
NPU_SOURCES=backends/npu/qihse_npu_openvino.c
NPU_HEADERS=backends/npu/qihse_npu_openvino.h

# Quantization files (Phase 2.6)
QUANT_SOURCES=quantization/src/qihse_quantization.c
QUANT_HEADERS=quantization/include/qihse_quantization.h

ALGO_HEADERS=algorithms/qihse_rff.h algorithms/qihse_superposition.h algorithms/qihse_amplification.h algorithms/qihse_dimensions.h algorithms/qihse_verification.h

# All source and header files
ALL_SOURCES=$(ABI_SOURCES) $(ALGO_SOURCES) $(CPU_SOURCES) $(ORCH_SOURCES) $(MEM_SOURCES) $(NPU_SOURCES) $(QUANT_SOURCES)
ALL_HEADERS=$(ABI_HEADERS) $(ALGO_HEADERS) $(CPU_HEADERS) $(ORCH_HEADERS) $(MEM_HEADERS) $(NPU_HEADERS) $(QUANT_HEADERS)

# Test files
TEST_SOURCES=tests/test_abi.c tests/test_algorithms.c tests/test_quantization.c tests/test_verification.c
TEST_OBJECTS=$(TEST_SOURCES:.c=.o)

# Targets
.PHONY: all clean test test_abi test_algorithms compile_core compile_algorithms check

all: compile_core compile_algorithms test

# Compile core ABI sources
compile_core: $(ABI_SOURCES) $(ABI_HEADERS)
	@echo "Compiling core ABI sources..."
	$(CC) $(CFLAGS) -c $(ABI_SOURCES)
	@echo "Core ABI compilation successful"

# Compile algorithm sources
compile_algorithms: $(ALGO_SOURCES) $(ALGO_HEADERS)
	@echo "Compiling algorithm sources..."
	$(CC) $(CFLAGS) -c $(ALGO_SOURCES)
	@echo "Algorithm compilation successful"

# Build and run ABI tests
test_abi: tests/test_abi.c $(ALL_SOURCES) $(ALL_HEADERS)
	@echo "Building ABI tests..."
	$(CC) $(CFLAGS) -o test_abi tests/test_abi.c $(ALL_SOURCES) $(LDFLAGS)
	@echo "Running ABI tests..."
	./test_abi
	@echo "ABI tests completed successfully"

# Build and run algorithm tests
test_algorithms: tests/test_algorithms.c $(ALL_SOURCES) $(ALL_HEADERS)
	@echo "Building algorithm tests..."
	$(CC) $(CFLAGS) -o test_algorithms tests/test_algorithms.c $(ALL_SOURCES) $(LDFLAGS)
	@echo "Running algorithm tests..."
	./test_algorithms
	@echo "Algorithm tests completed successfully"

# Build and run quantization tests
test_quantization: tests/test_quantization.c $(ALL_SOURCES) $(ALL_HEADERS)
	@echo "Building quantization tests..."
	$(CC) $(CFLAGS) -o test_quantization tests/test_quantization.c $(ALL_SOURCES) $(LDFLAGS)
	@echo "Running quantization tests..."
	./test_quantization
	@echo "Quantization tests completed successfully"

# Build and run verification tests
test_verification: tests/test_verification.c $(ALL_SOURCES) $(ALL_HEADERS)
	@echo "Building verification tests..."
	$(CC) $(CFLAGS) -o test_verification tests/test_verification.c $(ALL_SOURCES) $(LDFLAGS)
	@echo "Running verification tests..."
	./test_verification
	@echo "Verification tests completed successfully"

# PIM operations tests (Phase 4.6)
test_pim: benchmarks/tests/test_pim.c $(ALL_SOURCES) $(ALL_HEADERS)
	@echo "Building PIM tests..."
	$(CC) $(CFLAGS) -Ibenchmarks/include -o test_pim benchmarks/tests/test_pim.c $(ALL_SOURCES) $(LDFLAGS) -lm
	@echo "Running PIM tests..."
	./test_pim
	@echo "PIM tests completed successfully"

# Distributed coherence tests (Phase 4.7)
test_distributed: orchestration/tests/test_distributed.c $(ALL_SOURCES) $(ALL_HEADERS)
	@echo "Building distributed tests..."
	$(CC) $(CFLAGS) -Iorchestration/include -o test_distributed orchestration/tests/test_distributed.c $(ALL_SOURCES) $(LDFLAGS) -lm -lpthread
	@echo "Running distributed tests..."
	./test_distributed
	@echo "Distributed tests completed successfully"

# ML engine sources
ML_INCLUDE = ml/include
ML_SRC = ml/src
ML_TESTS = ml/tests

ML_OBJS = $(ML_SRC)/qihse_ml.o
TEST_ML_OBJS = $(ML_TESTS)/test_ml.o

$(ML_SRC)/qihse_ml.o: $(ML_SRC)/qihse_ml.c $(ML_INCLUDE)/qihse_ml.h
	$(CC) $(CFLAGS) -I$(ML_INCLUDE) -c $< -o $@

$(ML_TESTS)/test_ml.o: $(ML_TESTS)/test_ml.c $(ML_INCLUDE)/qihse_ml.h
	$(CC) $(CFLAGS) -I$(ML_INCLUDE) -c $< -o $@

test_ml: $(TEST_ML_OBJS) $(ML_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ -lm

# Build and run all tests
test: test_abi test_algorithms test_quantization test_verification test_ml test_pim test_distributed

# Benchmark target - MINIMAL build with only required files
# qihse_core.c and qihse_hetero.c are monolithic and contain all needed functions
BENCHMARK_SOURCES=qihse_benchmark_suite.c
BENCHMARK_CORE=qihse_core.c qihse_hetero.c core/qihse_plugin.c
BENCHMARK_CPU=backends/cpu/qihse_cpu_detect.c backends/cpu/qihse_cpu_avx2.c backends/cpu/qihse_cpu_avx512.c
# NOT_STISLA dependency (required by qihse_core.c)
NOT_STISLA_SRC=../not_stisla/src/not_stisla.c

# Default benchmark (AVX2 - runs on most systems)
benchmark: $(BENCHMARK_CORE) $(BENCHMARK_CPU) $(NOT_STISLA_SRC) $(BENCHMARK_SOURCES)
	@echo "Building QIHSE benchmark suite (AVX2)..."
	$(CC) $(CFLAGS_AVX2) -DQIHSE_MINIMAL_BUILD -o qihse_benchmark $(BENCHMARK_SOURCES) $(BENCHMARK_CORE) $(BENCHMARK_CPU) $(NOT_STISLA_SRC) $(LDFLAGS)
	@echo "Benchmark build successful (AVX2)"
	@echo "Run with: ./qihse_benchmark"

# Full benchmark for A00 engineering board (AVX-512, AMX, VNNI)
benchmark-a00: $(BENCHMARK_CORE) $(BENCHMARK_CPU) $(NOT_STISLA_SRC) $(BENCHMARK_SOURCES)
	@echo "Building QIHSE benchmark suite for A00 board (AVX-512/AMX/VNNI)..."
	$(CC) $(CFLAGS_FULL) -DQIHSE_MINIMAL_BUILD -DQIHSE_FORCE_FULL_FEATURES -o qihse_benchmark_a00 $(BENCHMARK_SOURCES) $(BENCHMARK_CORE) $(BENCHMARK_CPU) $(NOT_STISLA_SRC) $(LDFLAGS)
	@echo "Benchmark build successful (AVX-512/AMX/VNNI)"
	@echo "Run on A00 board with: ./qihse_benchmark_a00"

# Quick benchmark run
benchmark_run: benchmark
	@echo "Running QIHSE benchmark suite..."
	./qihse_benchmark

# Clean build artifacts
clean:
	rm -f *.o core/*.o algorithms/*.o backends/cpu/*.o backends/npu/*.o orchestration/src/*.o orchestration/include/*.o memory/src/*.o memory/include/*.o quantization/src/*.o quantization/include/*.o ml/src/*.o ml/tests/*.o tests/*.o test_abi test_algorithms test_quantization test_verification test_ml qihse_benchmark
	@echo "Clean completed"

# Quick compilation check
check: $(ALL_SOURCES) $(ALL_HEADERS) $(TEST_SOURCES)
	@echo "Checking compilation..."
	$(CC) $(CFLAGS) -fsyntax-only $(ALL_SOURCES) $(TEST_SOURCES)
	@echo "Compilation check passed"

