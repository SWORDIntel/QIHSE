# QIHSE Breakthroughalgo Makefile
# Phase 0.5: Quantum-Inspired Core Algorithms

CC=gcc

INCLUDES = -I. -I./include -I./core -I./algorithms -I./backends/cpu -I./backends/npu -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include -I./msnet -I./vendor/tree-sitter/lib/include
CFLAGS_BASE=-std=c99 -Wall -Wextra -fopenmp-simd $(INCLUDES) -fPIC -lm -pthread -D_GNU_SOURCE -O3
QIHSE_CFLAGS_EXTRA?=

# CPU-specific SIMD backend selection.
# R320/E5-2450 v2 exposes AVX but not AVX2/FMA, so these must be off there.
# Enable on newer hosts with:
#   make QIHSE_ENABLE_AVX2=1 QIHSE_ENABLE_AVX512=0
QIHSE_ENABLE_AVX2?=0
QIHSE_ENABLE_AVX512?=0

CFLAGS=$(CFLAGS_BASE) $(QIHSE_CFLAGS_EXTRA)

LDFLAGS = -L. -lqihse -ldl -lm -lpthread -luring
TARGET_LDFLAGS = -ldl -lm -lpthread -luring
VXUG_PDF_REPO?=$(CURDIR)/VXUG-Papers
VXUG_PDF?=
REFERENCE_WORKLOAD?=vxug-pdf-sample
LIB_TARGET=libqihse.so

SIFT1M_BASE_DATA=data/sift1m/sift_base.fvecs
SIFT1M_QUERY_DATA=data/sift1m/sift_query.fvecs
SIFT1M_GROUND_TRUTH=data/sift1m/sift_groundtruth.ivecs
SIFT1M_FALLBACK_WORKLOAD=sift1m-fallback
SIFT1M_FALLBACK_DIR=data/sift1m/fallback
SIFT1M_FALLBACK_ROWS=2048
SIFT1M_FALLBACK_QUERIES=128
SIFT1M_FALLBACK_DIMENSIONS=128
SIFT1M_FALLBACK_TOP_K=10
SIFT1M_CALIBRATION_SCOPE?=auto
QIHSE_TRINARY_SWEEP_ITERS?=10000
QIHSE_TRINARY_SWEEP_SEED?=
QIHSE_TRINARY_SWEEP_OUTPUT_DIR?=results/sweep10000
QIHSE_TRINARY_SWEEP_BENCH_ITERS?=1

# Use the most complete set of sources WITHOUT duplicates
# We use qihse_exports.c to fill in any missing gaps for the Python layer
SRCS_BASE = core/qihse.c core/qihse_auth.c \
            src/broad_oak/qihse_search.c src/broad_oak/qihse_hnsw.c \
            src/bombe/qihse_math.c src/bombe/qihse_instr.c src/bombe/qihse_hetero.c \
            src/broad_oak/qihse_vector_db.c src/broad_oak/qihse_system_guard.c src/qihse_exports.c src/broad_oak/qihse_recursive_search.c \
            src/marmalade/qihse_temporal.c src/bombe/qihse_fusion.c src/spinnaker/qihse_subscription.c src/spinnaker/qihse_cluster.c \
            src/black_hole/qihse_kv_store.c src/spinnaker/qihse_resp_wire.c src/spinnaker/qihse_uwp.c \
            algorithms/qihse_trinary_trie.c src/black_hole/qihse_arena.c src/frieze/qihse_fts_index.c src/frieze/qihse_document_store.c src/frieze/qihse_spatial_index.c \
            src/frieze/qihse_column_store.c src/marmalade/qihse_timeseries.c src/marmalade/qihse_event_stream.c \
            src/tractable/qihse_bytecode.c src/tractable/qihse_bytecode_compiler.c \
            src/spinnaker/qihse_pg_wire.c src/tractable/qihse_qql_parser.c qql-grammar/src/parser.c \
            vendor/tree-sitter/lib/src/lib.c src/tractable/qihse_sql_parser.c \
     persistence/qihse_file_posix.c persistence/qihse_persist_format.c persistence/qihse_vector_store.c \
     algorithms/qihse_anchor_search.c algorithms/qihse_version.c \
     codecs/qihse_trinary_tryte_codec.c \
     core/qihse_helpers.c core/qihse_plugin.c \
     algorithms/qihse_dimensions.c algorithms/qihse_verification.c algorithms/qihse_amplification.c \
     backends/cpu/qihse_cpu_detect.c \
     backends/cpu/qihse_cpu_distance.c \
     backends/npu/qihse_npu_openvino.c \
     backends/gpu/cuda/qihse_cuda_backend.c \
     memory/src/qihse_memory.c memory/src/qihse_hma.c memory/src/qihse_uma.c \
     memory/src/qihse_memory_topology_probe.c memory/src/qihse_memory_planner_trace.c memory/src/qihse_memory_allocation_policy.c \
     memory/src/qihse_memory_coherence.c memory/src/qihse_memory_migration_policy.c \
     memory/src/qihse_memory_device_placement.c memory/src/qihse_memory_migration_backend.c memory/src/qihse_memory_migration_scheduler.c \
     $(wildcard msnet/*.c)

SRCS=$(SRCS_BASE)

ifeq ($(QIHSE_ENABLE_AVX2),1)
CFLAGS += -mavx2 -mfma -DQIHSE_ENABLE_AVX2=1
SRCS += backends/cpu/qihse_cpu_avx2.c backends/cpu/qihse_cpu_distance_avx2.c
endif

ifeq ($(QIHSE_ENABLE_AVX512),1)
CFLAGS += -mavx512f -mavx512dq -mfma
SRCS += backends/cpu/qihse_cpu_avx512.c
endif

# Note: core/qihse_plugin.c and algorithms/qihse_superposition.c etc are EXCLUDED 
# because their functionality is already partially in qihse_math.c / qihse_search.c 
# or provided by qihse_exports.c stubs.

.PHONY: all build build-native clean pristine workspace workspace-clean lib persistence persistence-check test benchmark install dev-setup docs test-persist test-trinary-codec test-memory-planner test-memory-topology-probe test-memory-planner-trace test-memory-allocation-policy test-memory-coherence test-memory-migration-policy test-memory-migration test-memory-device-placement test-memory-migration-backend test-memory-migration-scheduler bench-trinary-codec bench-trinary-db-candidate bench-micro bench-trinary-search-path bench-trinary-search-sweep bench-trinary-random-sweep bench-trinary-weighted-sweep bench-trinary-magnitude-sweep bench-reference-workloads bench-reference-runner-smoke sample-vxug-pdf-workload bench-vxug-pdf-workload bench-reference-workload bench-reference-result-summary bench-sift1m-workload bench-sift1m-fallback-data calibrate-sift1m-workload validate-reference-workflow check-upstream-workflow check-upstream-workflow-strict check upstream-pr-loop test-all-isa test-vnni-bench test-vnni-only test-avx2-only test-avx512-direct test-amx-only test-direct-execution test-simple-exec
.NOTPARALLEL: validate-reference-workflow

all: lib server
build: lib server

build-native:
	./scripts/build-native.sh

server: lib
	$(CC) $(CFLAGS) -o tests/qihse_server tests/qihse_server.c -L. -lqihse $(LDFLAGS)

lib: $(LIB_TARGET)

$(LIB_TARGET): $(SRCS)
	@echo "Building libqihse.so..."
	$(CC) -shared -fPIC $(CFLAGS) -o $(LIB_TARGET) $(SRCS) $(LDFLAGS)
	@echo "Shared library build successful"

persistence: test-persist
persistence-check: test-persist

test-persist: lib
	$(CC) $(CFLAGS) -o tests/qihse_vector_db_persistence_test \
	    tests/qihse_vector_db_persistence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_vector_db_persistence_test

test: test-omni test-e2e test-e2e-memory-planner test-persist test-bytecode test-document-store test-column-store test-fts-engine test-timeseries test-trinary-codec test-memory-planner test-memory-topology-probe test-memory-planner-trace test-memory-allocation-policy test-memory-coherence test-memory-migration-policy test-memory-migration test-memory-device-placement test-memory-migration-backend test-memory-migration-scheduler

test-bytecode: lib
	$(CC) $(CFLAGS) -o tests/test_bytecode tests/test_bytecode.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_bytecode

test-document-store: lib
	$(CC) $(CFLAGS) -o tests/test_document_store tests/test_document_store.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_document_store

test-column-store: lib
	$(CC) $(CFLAGS) -o tests/test_column_store tests/test_column_store.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_column_store

test-fts-engine: lib
	$(CC) $(CFLAGS) -o tests/test_fts_engine tests/test_fts_engine.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_fts_engine

test-e2e: lib
	$(CC) $(CFLAGS) -o tests/test_qihse_e2e tests/test_qihse_e2e.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_qihse_e2e

test-omni: lib
	$(CC) $(CFLAGS) -o tests/test_qihse_omni tests/test_qihse_omni.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_qihse_omni

test-apt41:
	$(CC) $(CFLAGS) -fsanitize=address,undefined -g -fno-omit-frame-pointer -o tests/apt41_fuzzer tests/apt41_fuzzer.c -L. -lqihse $(LDFLAGS)
	ASAN_OPTIONS=detect_leaks=1 LD_LIBRARY_PATH=. ./tests/apt41_fuzzer

test-timeseries: lib
	$(CC) $(CFLAGS) -o tests/test_timeseries tests/test_timeseries.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_timeseries

test-trinary-codec:
	$(CC) $(CFLAGS) -o tests/qihse_trinary_codec_test \
	    tests/qihse_trinary_codec_test.c \
	    codecs/qihse_trinary_tryte_codec.c \
	    $(LDFLAGS)
	./tests/qihse_trinary_codec_test

test-memory-planner: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_planner_test \
	    tests/qihse_memory_planner_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_planner_test

test-e2e-memory-planner: lib
	$(CC) $(CFLAGS) -o tests/test_memory_planner \
	    tests/test_memory_planner.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_memory_planner

test-memory-topology-probe: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_topology_probe_test \
	    tests/qihse_memory_topology_probe_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_topology_probe_test

test-memory-planner-trace: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_planner_trace_test \
	    tests/qihse_memory_planner_trace_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_planner_trace_test

test-memory-allocation-policy: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_allocation_policy_test \
	    tests/qihse_memory_allocation_policy_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_allocation_policy_test

test-memory-coherence: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_coherence_test \
	    tests/qihse_memory_coherence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_coherence_test

test-memory-migration-policy: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_migration_policy_test \
	    tests/qihse_memory_migration_policy_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_migration_policy_test

test-memory-migration: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_migration_test \
	    tests/qihse_memory_migration_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_migration_test

test-memory-device-placement: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_device_placement_test \
	    tests/qihse_memory_device_placement_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_device_placement_test

test-memory-migration-backend: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_migration_backend_test \
	    tests/qihse_memory_migration_backend_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_migration_backend_test

test-memory-migration-scheduler: lib
	$(CC) $(CFLAGS) -o tests/qihse_memory_migration_scheduler_test \
	    tests/qihse_memory_migration_scheduler_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_memory_migration_scheduler_test

test-all-isa:
	$(CC) $(CFLAGS) -o tests/test_all_isa tests/test_all_isa.c $(LDFLAGS)
	./tests/test_all_isa

test-vnni-bench:
	$(CC) $(CFLAGS) -o tests/test_vnni_bench tests/test_vnni_bench.c \
		-L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_vnni_bench

test-vnni-only:
	$(CC) $(CFLAGS) -mavx2 -mfma -o tests/test_vnni_only tests/test_vnni_only.c $(LDFLAGS)
	./tests/test_vnni_only

test-avx2-only:
	$(CC) $(CFLAGS) -mavx2 -mfma -o tests/test_avx2_only tests/test_avx2_only.c $(LDFLAGS)
	./tests/test_avx2_only

test-avx512-direct:
	$(CC) $(CFLAGS) -mavx512f -mavx512dq -mavx512bw -mavx512vl -mfma -o tests/test_avx512_direct tests/test_avx512_direct.c $(LDFLAGS)
	./tests/test_avx512_direct

test-amx-only:
	$(CC) $(CFLAGS) -mamx-tile -mamx-int8 -mamx-bf16 -o tests/test_amx_only tests/test_amx_only.c $(LDFLAGS)
	./tests/test_amx_only

test-direct-execution:
	$(CC) $(CFLAGS) -mavx2 -mavx512f -mavx512dq -mavx512bw -mavx512vl -mfma -mamx-tile -mamx-int8 -mamx-bf16 -o tests/test_direct_execution tests/test_direct_execution.c $(LDFLAGS)
	./tests/test_direct_execution

test-simple-exec:
	$(CC) $(CFLAGS) -mavx2 -mavx512f -mavx512dq -mavx512bw -mavx512vl -mfma -mamx-tile -mamx-int8 -mamx-bf16 -o tests/test_simple_exec tests/test_simple_exec.c $(LDFLAGS)
	./tests/test_simple_exec

bench-micro: lib
	$(CC) $(CFLAGS) -o benchmarks/qihse_micro_bench \
		benchmarks/qihse_micro_bench.c \
		-L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./benchmarks/qihse_micro_bench

bench-memory-hierarchy: lib
	$(CC) $(CFLAGS) -o benchmarks/qihse_memory_hierarchy_bench \
		benchmarks/qihse_memory_hierarchy_bench.c \
		-L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./benchmarks/qihse_memory_hierarchy_bench

benchmark: validate-reference-workflow

dev-setup:
	@echo "Checking required toolchain..."
	@command -v gcc >/dev/null || { echo "Missing gcc"; exit 1; }
	@command -v make >/dev/null || { echo "Missing make"; exit 1; }
	@command -v python3 >/dev/null || { echo "Missing python3"; exit 1; }
	@echo "Optional: install rust/oneAPI/CUDA/OpenVINO manually based on workload targets."
	@echo "Use sudo for optional OS package install (intel-oneapi-basekit, libopenvino-dev, cuda)."

docs:
	@echo "No generated docs build target exists yet; docs are maintained in markdown under docs/."
	@echo "Use 'find docs -name \"*.md\" | wc -l' to inspect documentation files."

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

bench-trinary-random-sweep: lib
	./scripts/run-trinary-random-sweep.sh \
	  --iterations $(QIHSE_TRINARY_SWEEP_ITERS) \
	  --iters-per-pass $(QIHSE_TRINARY_SWEEP_BENCH_ITERS) \
	  --output-dir $(QIHSE_TRINARY_SWEEP_OUTPUT_DIR) \
	  $(if $(QIHSE_TRINARY_SWEEP_SEED),--seed $(QIHSE_TRINARY_SWEEP_SEED),)

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
	@PDF_PATH="$(VXUG_PDF)"; \
	if [ -z "$${PDF_PATH}" ] || [ ! -f "$${PDF_PATH}" ]; then \
		if [ ! -d "$(VXUG_PDF_REPO)" ]; then \
		  echo "Cloning VXUG papers repository to $(VXUG_PDF_REPO)..."; \
		  git clone --depth 1 https://github.com/vxunderground/VXUG-Papers "$(VXUG_PDF_REPO)"; \
		fi; \
		if [ -z "$${PDF_PATH}" ]; then \
		  if [ -f "$(VXUG_PDF_REPO)/Hells Gate/HellsGate.pdf" ]; then \
		    PDF_PATH="$(VXUG_PDF_REPO)/Hells Gate/HellsGate.pdf"; \
		  fi; \
		fi; \
		if [ -z "$${PDF_PATH}" ]; then \
			PDF_PATH=$$(find "$(VXUG_PDF_REPO)" -type f -iname "HellsGate.pdf" | head -n 1); \
		fi; \
		if [ -z "$${PDF_PATH}" ]; then \
			echo "No HellsGate.pdf found under $(VXUG_PDF_REPO)"; \
			exit 1; \
		fi; \
		fi; \
	python3 benchmarks/scripts/qihse_pdf_text_sample.py --pdf "$${PDF_PATH}" --out data/vxug_pdf_sample
	python3 benchmarks/scripts/qihse_reference_workloads.py --root . --manifest benchmarks/reference_workloads.json --workload vxug-pdf-sample --inspect-files

bench-vxug-pdf-workload: lib sample-vxug-pdf-workload
	@if [ ! -f data/vxug_pdf_sample/base.f32 ] || [ ! -f data/vxug_pdf_sample/query.f32 ] || [ ! -f data/vxug_pdf_sample/ground_truth.u32 ]; then \
		echo "bench-vxug-pdf-workload failed: vxug artifacts missing in data/vxug_pdf_sample"; \
		exit 1; \
	fi
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

calibrate-sift1m-workload: lib
	@if [ "$(SIFT1M_CALIBRATION_SCOPE)" = "full" ]; then \
	  if [ ! -f "$(SIFT1M_BASE_DATA)" ] || [ ! -f "$(SIFT1M_QUERY_DATA)" ] || [ ! -f "$(SIFT1M_GROUND_TRUTH)" ]; then \
	    echo "Full SIFT1M scope requested but required files are missing"; \
	    exit 1; \
	  fi; \
	  workload=sift1m; \
	elif [ "$(SIFT1M_CALIBRATION_SCOPE)" = "fallback" ]; then \
	  $(MAKE) bench-sift1m-fallback-data; \
	  workload=$(SIFT1M_FALLBACK_WORKLOAD); \
	else \
	  if [ -f "$(SIFT1M_BASE_DATA)" ] && [ -f "$(SIFT1M_QUERY_DATA)" ] && [ -f "$(SIFT1M_GROUND_TRUTH)" ]; then \
	    workload=sift1m; \
	  else \
	    echo "Full SIFT1M not available; using fallback workload automatically"; \
	    $(MAKE) bench-sift1m-fallback-data; \
	    workload=$(SIFT1M_FALLBACK_WORKLOAD); \
	  fi; \
	fi; \
	echo "SIFT1M calibration workload=$${workload}"; \
	$(MAKE) bench-reference-workload REFERENCE_WORKLOAD=$${workload}; \
	$(MAKE) bench-reference-result-summary REFERENCE_WORKLOAD=$${workload}; \
	python3 benchmarks/scripts/qihse_sift1m_calibration.py \
	  --root . \
	  --workload $${workload} \
	  --result results/$${workload}/latest.json

validate-reference-workflow: bench-reference-workloads bench-reference-runner-smoke bench-vxug-pdf-workload bench-sift1m-workload test-persist

upstream-pr-loop:
	python3 scripts/qihse_upstream_pr_loop.py --source-root . $(if $(UPSTREAM_ROOT),--upstream-root $(UPSTREAM_ROOT))

check: check-upstream-workflow

check-upstream-workflow:
	python3 scripts/qihse_workflow_check.py --root .

check-upstream-workflow-strict:
	python3 scripts/qihse_workflow_check.py --root . --strict-upstream

clean:
	rm -f *.o libqihse.so qihse_benchmark qihse_benchmark_a00 \
	    tests/qihse_vector_db_persistence_test tests/qihse_trinary_codec_test \
	    tests/test_all_isa tests/test_vnni_bench tests/test_vnni_only \
	    tests/test_avx2_only tests/test_avx512_direct tests/test_amx_only \
	    tests/test_direct_execution tests/test_simple_exec tests/test_timeseries
	@echo "Clean completed"

workspace:
	@sh scripts/bootstrap-workspace.sh
	@echo "Workspace directories are ready."

workspace-clean:
	@sh scripts/bootstrap-workspace.sh --clean
	@echo "Workspace directories removed."

pristine: clean workspace-clean
	@echo "Build artifacts and workspace artifacts removed."

install: all
	@install -d $(DESTDIR)/usr/local/lib $(DESTDIR)/usr/local/include/qihse
	@install -m 644 libqihse.so $(DESTDIR)/usr/local/lib/libqihse.so
	@install -m 644 qihse.h $(DESTDIR)/usr/local/include/qihse/qihse.h
	@echo "Installed libqihse.so and qihse.h into $(DESTDIR)/usr/local"
