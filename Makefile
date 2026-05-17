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
VXUG_PDF?=../exploits/vxunderground/VXUG-Papers/Hells Gate/HellsGate.pdf
REFERENCE_WORKLOAD?=vxug-pdf-sample

SIFT1M_BASE_DATA=data/sift1m/sift_base.fvecs
SIFT1M_QUERY_DATA=data/sift1m/sift_query.fvecs
SIFT1M_GROUND_TRUTH=data/sift1m/sift_groundtruth.ivecs
SIFT1M_FALLBACK_WORKLOAD=sift1m-fallback
SIFT1M_FALLBACK_DIR=data/sift1m/fallback
SIFT1M_FALLBACK_ROWS=2048
SIFT1M_FALLBACK_QUERIES=128
SIFT1M_FALLBACK_DIMENSIONS=128
SIFT1M_FALLBACK_TOP_K=10

# Use the most complete set of sources WITHOUT duplicates
# We use qihse_exports.c to fill in any missing gaps for the Python layer
SRCS_BASE=core/qihse.c qihse_search.c qihse_math.c qihse_instr.c qihse_hetero.c qihse_vector_db.c qihse_exports.c \
     persistence/qihse_file_posix.c persistence/qihse_persist_format.c persistence/qihse_vector_store.c \
     algorithms/qihse_anchor_search.c \
     codecs/qihse_trinary_tryte_codec.c \
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

.PHONY: all clean lib test-persist test-trinary-codec bench-trinary-codec bench-trinary-db-candidate bench-trinary-search-path bench-trinary-search-sweep bench-trinary-weighted-sweep bench-trinary-magnitude-sweep bench-reference-workloads bench-reference-runner-smoke sample-vxug-pdf-workload bench-vxug-pdf-workload bench-reference-workload bench-reference-result-summary bench-sift1m-workload bench-sift1m-fallback-data validate-reference-workflow check-upstream-workflow check

.NOTPARALLEL: validate-reference-workflow

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

test-trinary-codec:
	$(CC) $(CFLAGS) -o tests/qihse_trinary_codec_test \
	    tests/qihse_trinary_codec_test.c \
	    codecs/qihse_trinary_tryte_codec.c \
	    $(LDFLAGS)
	./tests/qihse_trinary_codec_test

bench-trinary-codec:
	$(CC) $(CFLAGS) -o /tmp/qihse_trinary_candidate_bench \
	    benchmarks/qihse_trinary_candidate_bench.c \
	    codecs/qihse_trinary_tryte_codec.c \
	    $(LDFLAGS)
	/tmp/qihse_trinary_candidate_bench

bench-trinary-db-candidate: lib
	$(CC) $(CFLAGS) -o /tmp/qihse_trinary_db_candidate_bench \
	    benchmarks/qihse_trinary_db_candidate_bench.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. /tmp/qihse_trinary_db_candidate_bench

bench-trinary-search-path: lib
	$(CC) $(CFLAGS) -o /tmp/qihse_trinary_search_path_bench \
	    benchmarks/qihse_trinary_db_candidate_bench.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_DATASET=banded LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_DATASET=weighted LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_DATASET=magnitude_skew LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_DATASET=near_tie LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench

bench-trinary-search-sweep: lib
	$(CC) $(CFLAGS) -o /tmp/qihse_trinary_search_path_bench \
	    benchmarks/qihse_trinary_db_candidate_bench.c \
	    -L. -lqihse $(LDFLAGS)
	QIHSE_BENCH_SWEEP=1 LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_DATASET=banded LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_DATASET=weighted LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_DATASET=magnitude_skew LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_DATASET=near_tie LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench

bench-trinary-weighted-sweep: lib
	$(CC) $(CFLAGS) -o /tmp/qihse_trinary_search_path_bench \
	    benchmarks/qihse_trinary_db_candidate_bench.c \
	    -L. -lqihse $(LDFLAGS)
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=weighted LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=weighted QIHSE_BENCH_DATASET=banded LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=weighted QIHSE_BENCH_DATASET=weighted LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=weighted QIHSE_BENCH_DATASET=magnitude_skew LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=weighted QIHSE_BENCH_DATASET=near_tie LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench

bench-trinary-magnitude-sweep: lib
	$(CC) $(CFLAGS) -o /tmp/qihse_trinary_search_path_bench \
	    benchmarks/qihse_trinary_db_candidate_bench.c \
	    -L. -lqihse $(LDFLAGS)
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=magnitude LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=magnitude QIHSE_BENCH_DATASET=banded LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=magnitude QIHSE_BENCH_DATASET=weighted LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=magnitude QIHSE_BENCH_DATASET=magnitude_skew LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench
	QIHSE_BENCH_SWEEP=1 QIHSE_BENCH_TRINARY_SCORE=magnitude QIHSE_BENCH_DATASET=near_tie LD_LIBRARY_PATH=. /tmp/qihse_trinary_search_path_bench

bench-reference-workloads:
	python3 benchmarks/scripts/qihse_reference_workloads.py --root . --plan

bench-reference-runner-smoke: lib
	python3 benchmarks/scripts/qihse_reference_runner_smoke.py --root .

sample-vxug-pdf-workload:
	python3 benchmarks/scripts/qihse_pdf_text_sample.py --pdf "$(VXUG_PDF)" --out data/vxug_pdf_sample
	python3 benchmarks/scripts/qihse_reference_workloads.py --root . --manifest benchmarks/reference_workloads.json --workload vxug-pdf-sample --inspect-files

bench-vxug-pdf-workload: lib
	python3 benchmarks/scripts/qihse_reference_workloads.py --root . --manifest benchmarks/reference_workloads.json --workload vxug-pdf-sample --inspect-files
	python3 benchmarks/scripts/qihse_vxug_reference_bench.py --root . --output-json results/vxug_pdf_sample/latest.json
	python3 benchmarks/scripts/qihse_reference_result_summary.py --root . --workload vxug-pdf-sample --result results/vxug_pdf_sample/latest.json

bench-reference-workload: lib
	python3 benchmarks/scripts/qihse_reference_workloads.py --root . --manifest benchmarks/reference_workloads.json --workload $(REFERENCE_WORKLOAD) --inspect-files
	python3 benchmarks/scripts/qihse_vxug_reference_bench.py --root . --workload $(REFERENCE_WORKLOAD) --output-json results/$(REFERENCE_WORKLOAD)/latest.json
	python3 benchmarks/scripts/qihse_reference_result_summary.py --root . --workload $(REFERENCE_WORKLOAD) --result results/$(REFERENCE_WORKLOAD)/latest.json

bench-sift1m-fallback-data:
	python3 benchmarks/scripts/qihse_generate_sift1m_fixture.py \
	    --out-dir $(SIFT1M_FALLBACK_DIR) \
	    --rows $(SIFT1M_FALLBACK_ROWS) \
	    --queries $(SIFT1M_FALLBACK_QUERIES) \
	    --dimensions $(SIFT1M_FALLBACK_DIMENSIONS) \
	    --top-k $(SIFT1M_FALLBACK_TOP_K) \
	    --force

bench-reference-result-summary:
	python3 benchmarks/scripts/qihse_reference_result_summary.py --root . --workload $(REFERENCE_WORKLOAD) --result results/$(REFERENCE_WORKLOAD)/latest.json

bench-sift1m-workload: lib
	@if [ -f "$(SIFT1M_BASE_DATA)" ] && [ -f "$(SIFT1M_QUERY_DATA)" ] && [ -f "$(SIFT1M_GROUND_TRUTH)" ]; then \
	  echo "Using full SIFT1M dataset from data/sift1m/"; \
	  $(MAKE) bench-reference-workload REFERENCE_WORKLOAD=sift1m; \
	else \
	  echo "SIFT1M files missing; generating lightweight deterministic fallback workload"; \
	  $(MAKE) bench-sift1m-fallback-data; \
	  $(MAKE) bench-reference-workload REFERENCE_WORKLOAD=$(SIFT1M_FALLBACK_WORKLOAD); \
	fi

validate-reference-workflow: bench-reference-workloads bench-reference-runner-smoke bench-vxug-pdf-workload bench-sift1m-workload test-persist

check: check-upstream-workflow

check-upstream-workflow:
	python3 scripts/qihse_workflow_check.py --root .

clean:
	rm -f *.o libqihse.so qihse_benchmark qihse_benchmark_a00 \
	    tests/qihse_vector_db_persistence_test tests/qihse_trinary_codec_test
	@echo "Clean completed"
