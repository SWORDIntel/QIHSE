# QIHSE Breakthroughalgo Makefile
# Phase 0.5: Quantum-Inspired Core Algorithms

CC=gcc

CFLAGS_BASE=-std=c99 -Wall -Wextra -I. -I./core -I./algorithms -I./backends/cpu -I./backends/npu -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include -fPIC -lm -pthread -D_GNU_SOURCE -O3

# CPU-specific SIMD backend selection.
# R320/E5-2450 v2 exposes AVX but not AVX2/FMA, so these must be off there.
# Enable on newer hosts with:
#   make QIHSE_ENABLE_AVX2=1 QIHSE_ENABLE_AVX512=0
QIHSE_ENABLE_AVX2?=0
QIHSE_ENABLE_AVX512?=0

CFLAGS=$(CFLAGS_BASE)

LDFLAGS=-ldl -lm -lpthread

# Use the most complete set of sources WITHOUT duplicates
# We use qihse_exports.c to fill in any missing gaps for the Python layer
SRCS_BASE=core/qihse.c qihse_search.c qihse_math.c qihse_instr.c qihse_hetero.c qihse_vector_db.c qihse_exports.c \
     persistence/qihse_file_posix.c persistence/qihse_persist_format.c persistence/qihse_vector_store.c \
     algorithms/qihse_anchor_search.c \
     core/qihse_helpers.c core/qihse_plugin.c \
     algorithms/qihse_dimensions.c algorithms/qihse_verification.c algorithms/qihse_amplification.c \
     backends/cpu/qihse_cpu_detect.c \
     backends/npu/qihse_npu_openvino.c \
     backends/gpu/cuda/qihse_cuda_backend.c \
     memory/src/qihse_memory.c memory/src/qihse_hma.c memory/src/qihse_uma.c

SRCS=$(SRCS_BASE)

ifeq ($(QIHSE_ENABLE_AVX2),1)
CFLAGS += -mavx2 -mfma
SRCS += backends/cpu/qihse_cpu_avx2.c
endif

ifeq ($(QIHSE_ENABLE_AVX512),1)
CFLAGS += -mavx512f -mavx512dq -mfma
SRCS += backends/cpu/qihse_cpu_avx512.c
endif

# Note: core/qihse_plugin.c and algorithms/qihse_superposition.c etc are EXCLUDED 
# because their functionality is already partially in qihse_math.c / qihse_search.c 
# or provided by qihse_exports.c stubs.

.PHONY: all clean lib test-persist

all: lib

lib: $(SRCS)
	@echo "Building libqihse.so..."
	$(CC) -shared -fPIC $(CFLAGS) -o libqihse.so $(SRCS) $(LDFLAGS)
	@echo "Shared library build successful"

test-persist: lib
	$(CC) $(CFLAGS) -o tests/qihse_vector_db_persistence_test \
	    tests/qihse_vector_db_persistence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_vector_db_persistence_test

clean:
	rm -f *.o libqihse.so qihse_benchmark qihse_benchmark_a00 tests/qihse_vector_db_persistence_test
	@echo "Clean completed"
