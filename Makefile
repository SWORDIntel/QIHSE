# QIHSE Breakthroughalgo Makefile
# Phase 0.5: Quantum-Inspired Core Algorithms

CC=gcc

CFLAGS_BASE=-std=c99 -Wall -Wextra -I. -I./core -I./algorithms -I./backends/cpu -I./backends/npu -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include -I../not_stisla/include -fPIC -lm -pthread -D_GNU_SOURCE -O3

# AVX2-only build (safe for Haswell)
CFLAGS=$(CFLAGS_BASE) -mavx2 -mfma

LDFLAGS=-ldl -lm -lpthread

# Use the most complete set of sources WITHOUT duplicates
# We use qihse_exports.c to fill in any missing gaps for the Python layer
SRCS=core/qihse.c qihse_search.c qihse_math.c qihse_instr.c qihse_hetero.c qihse_vector_db.c qihse_exports.c \
     core/qihse_helpers.c core/qihse_plugin.c \
     algorithms/qihse_dimensions.c algorithms/qihse_verification.c algorithms/qihse_amplification.c \
     backends/cpu/qihse_cpu_detect.c backends/cpu/qihse_cpu_avx2.c backends/cpu/qihse_cpu_avx512.c \
     backends/npu/qihse_npu_openvino.c \
     backends/gpu/cuda/qihse_cuda_backend.c \
     memory/src/qihse_memory.c memory/src/qihse_hma.c memory/src/qihse_uma.c \
     ../not_stisla/src/not_stisla.c

# Note: core/qihse_plugin.c and algorithms/qihse_superposition.c etc are EXCLUDED 
# because their functionality is already partially in qihse_math.c / qihse_search.c 
# or provided by qihse_exports.c stubs.

.PHONY: all clean lib

all: lib

lib: $(SRCS)
	@echo "Building libqihse.so..."
	$(CC) -shared -fPIC $(CFLAGS) -o libqihse.so $(SRCS) $(LDFLAGS)
	@echo "Shared library build successful"

clean:
	rm -f *.o libqihse.so qihse_benchmark qihse_benchmark_a00
	@echo "Clean completed"
