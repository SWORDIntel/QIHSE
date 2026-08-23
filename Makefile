# QIHSE Breakthroughalgo Makefile
# Phase 0.5: Quantum-Inspired Core Algorithms

CC=gcc
CXX=g++

PYTHON_INCLUDES ?= $(shell python3-config --includes 2>/dev/null || pkg-config --cflags python3 2>/dev/null || echo "-I/usr/include/python3.13")
PYTHON_LDFLAGS  ?= $(shell python3-config --ldflags --embed 2>/dev/null || python3-config --ldflags 2>/dev/null || pkg-config --libs python3 2>/dev/null || echo "-lpython3.13")

INCLUDES = -I. -I./include -I./include/network_intelligence -I./core -I./algorithms -I./backends/cpu -I./backends/npu -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include -I./sync -I./vendor/tree-sitter/lib/include -I/usr/include/luajit-2.1 -I/usr/local/include -I./vendor/liboqs/include -I./src/network_intelligence
CFLAGS_BASE=-std=c99 -Wall -Wextra -fopenmp-simd $(INCLUDES) -fPIC -lm -pthread -D_GNU_SOURCE -O3 $(PYTHON_INCLUDES)
CXXFLAGS_BASE=-std=c++20 -Wall -Wextra -fopenmp-simd $(INCLUDES) -fPIC -lm -pthread -D_GNU_SOURCE -O3
QIHSE_CFLAGS_EXTRA?=

# ---------------------------------------------------------------------------
# CPU ISA feature flags
# ---------------------------------------------------------------------------
# Each flag defaults to auto-detect from the build host's advertised CPU flags.
# Override on the command line or environment, e.g.:
#   make QIHSE_ENABLE_AVX2=1 QIHSE_ENABLE_AVX512=0 QIHSE_ENABLE_AMX=0
#
# Cross-builds may override each flag explicitly on the make command line.
#
# R320/E5-2450 v2: AVX only – AVX2, FMA, AVX-512, VNNI, AMX all absent.
# Sapphire Rapids+: all features available.

# ---- host feature helpers --------------------------------------------------
HOST_CPU_FLAGS ?= $(shell awk -F: '/^flags/{sub(/^ /, "", $$2); print $$2; exit}' /proc/cpuinfo 2>/dev/null)
cpu_has = $(if $(filter $(1),$(HOST_CPU_FLAGS)),1,0)

# ---- per-ISA defaults (auto-detect unless already set in env/CLI) ----------
QIHSE_ENABLE_AVX2     ?= $(call cpu_has,avx2)
QIHSE_ENABLE_AVX512   ?= $(if $(and $(filter avx512f,$(HOST_CPU_FLAGS)),$(filter avx512dq,$(HOST_CPU_FLAGS)),$(filter avx512bw,$(HOST_CPU_FLAGS)),$(filter avx512vl,$(HOST_CPU_FLAGS))),1,0)
QIHSE_ENABLE_AVX_VNNI ?= $(call cpu_has,avx_vnni)
QIHSE_ENABLE_AMX      ?= $(if $(and $(filter amx_tile,$(HOST_CPU_FLAGS)),$(filter amx_int8,$(HOST_CPU_FLAGS)),$(filter amx_bf16,$(HOST_CPU_FLAGS))),1,0)

# ---------------------------------------------------------------------------
# Security & Audit Configuration
# ---------------------------------------------------------------------------
# Webhook URL for classified-access callouts (empty = disabled).
# Set at build time: make QIHSE_AUDIT_WEBHOOK_URL="https://your.server:443/endpoint"
QIHSE_AUDIT_WEBHOOK_URL?=

CFLAGS=$(CFLAGS_BASE) $(QIHSE_CFLAGS_EXTRA)
ifdef QIHSE_AUDIT_WEBHOOK_URL
CFLAGS += -DQIHSE_AUDIT_WEBHOOK_URL=\"$(QIHSE_AUDIT_WEBHOOK_URL)\"
endif

LDFLAGS = -L. -lqihse -ldl -lm -lpthread -luring $(PYTHON_LDFLAGS) -lluajit-5.1 -lssl -lcrypto -lbpf -lxdp -lsqlite3 
TARGET_LDFLAGS = -ldl -lm -lpthread -luring $(PYTHON_LDFLAGS) -lluajit-5.1 -lssl -lcrypto -lbpf -lxdp -lsqlite3 
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
SRCS_BASE = core/qihse.c sdks/python/qihse.c core/qihse_auth.c core/qihse_audit.c \
            src/broad_oak/qihse_search.c src/broad_oak/qihse_hnsw.c \
            src/bombe/qihse_math.c src/bombe/qihse_instr.c src/bombe/qihse_hetero.c \
            src/broad_oak/qihse_vector_db.c src/broad_oak/qihse_system_guard.c src/qihse_exports.c src/broad_oak/qihse_recursive_search.c \
            src/marmalade/qihse_temporal.c src/bombe/qihse_fusion.c src/spinnaker/qihse_subscription.c src/spinnaker/qihse_cluster.c src/spinnaker/qihse_raft.c src/spinnaker/qihse_lua_injector.c src/spinnaker/qihse_http_telemetry.c \
            src/spinnaker/qihse_crc16.c src/spinnaker/qihse_cluster_slot.c src/spinnaker/qihse_cluster_numa.c src/spinnaker/qihse_cluster_migrate.c src/spinnaker/qihse_resp_cluster.c src/spinnaker/qihse_resp_engine.c src/spinnaker/qihse_cluster_bus.c src/spinnaker/qihse_cluster_failover.c src/spinnaker/qihse_cluster_scatter.c src/spinnaker/qihse_cluster_rebalance.c \
            src/spinnaker/qihse_task_queue.c src/spinnaker/qihse_task_worker.c src/spinnaker/qihse_task_scheduler.c \
            src/black_hole/qihse_kv_store.c src/black_hole/qihse_keystone.c src/spinnaker/qihse_resp_wire.c src/spinnaker/qihse_uwp.c src/spinnaker/qihse_uwp_graph_index.c src/spinnaker/qihse_uwp_repl_pool.c src/spinnaker/qihse_uwp_sql_txn_schema.c \
            algorithms/qihse_trinary_trie.c src/black_hole/qihse_arena.c src/frieze/qihse_fts_index.c src/frieze/qihse_document_store.c src/frieze/qihse_spatial_index.c \
            src/frieze/qihse_column_store.c src/frieze/qihse_btree.c src/frieze/qihse_hash_index.c src/frieze/qihse_index_manager.c src/marmalade/qihse_timeseries.c src/marmalade/qihse_event_stream.c src/network_intelligence/qihse_routing_persistence.c \
            src/network_intelligence/bgp_route_probe.cpp src/network_intelligence/bgp_update_decoder.cpp src/network_intelligence/rpki_rtr_probe.cpp src/network_intelligence/rdap_probe.cpp src/network_intelligence/ptr_probe.cpp src/network_intelligence/route_helper.cpp \
            src/tractable/qihse_bytecode.c src/tractable/qihse_bytecode_compiler.c src/tractable/qihse_index_scan.c src/tractable/qihse_txn.c src/tractable/qihse_mvcc.c src/tractable/qihse_wal.c src/tractable/qihse_recovery.c src/broad_oak/qihse_graph_store.c src/broad_oak/qihse_graph_ingest.c src/tractable/qihse_cypher_parser.c src/tractable/qihse_cypher_executor.c src/broad_oak/qihse_graph_algo.c src/broad_oak/qihse_graph_vector.c \
            src/spinnaker/qihse_pg_wire.c src/spinnaker/qihse_bolt.c src/spinnaker/qihse_protocol_translate.c src/spinnaker/qihse_pooler.c src/spinnaker/qihse_repl.c src/spinnaker/qihse_read_replica.c src/tractable/qihse_backup.c src/tractable/qihse_parallel_query.c src/spinnaker/qihse_cdc.c src/spinnaker/qihse_mongo_wire.c src/spinnaker/qihse_http_api.c src/spinnaker/qihse_metrics.c src/spinnaker/qihse_tracing.c src/spinnaker/qihse_clickhouse_http.c src/spinnaker/qihse_es_api.c src/spinnaker/qihse_influx_api.c src/tractable/qihse_compaction.c src/tractable/qihse_sql_extensions.c src/tractable/qihse_qql_parser.c qql-grammar/src/parser.c \
            vendor/tree-sitter/lib/src/lib.c src/tractable/qihse_sql_parser.c src/tractable/qihse_dist_planner.c src/tractable/qihse_join_executor.c src/tractable/qihse_aggregate_executor.c src/tractable/qihse_sort_executor.c src/tractable/qihse_schema.c src/tractable/qihse_optimizer.c \
     persistence/qihse_file_posix.c persistence/qihse_persist_format.c persistence/qihse_vector_store.c persistence/qihse_container.c persistence/qihse_pqc_crypto.c \
     algorithms/qihse_anchor_search.c algorithms/qihse_version.c \
     codecs/qihse_trinary_tryte_codec.c \
     quantization/src/qihse_quantization.c quantization/src/qihse_pq.c \
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
     src/networking/qihse_af_xdp.c src/broad_oak/qihse_quantum_defense.c src/broad_oak/qihse_mmdb.c \
     $(wildcard sync/*.c)

# SQLite VFS sources
SRCS_VFS = persistence/qihse_sqlite_vfs.c \
           persistence/qihse_vfs_page_cache.c \
           persistence/qihse_vfs_wal.c

SRCS_BASE += $(SRCS_VFS)

SRCS=$(SRCS_BASE)

ifeq ($(LIB_TARGET),qihse.dll)
  SRCS := $(filter-out sdks/python/%, $(SRCS))
  SRCS := $(filter-out vendor/tree-sitter/%, $(SRCS))
  SRCS := $(filter-out src/networking/%, $(SRCS))
  SRCS := $(filter-out backends/npu/%, $(SRCS))
  SRCS := $(filter-out backends/gpu/%, $(SRCS))
  SRCS := $(filter-out src/marmalade/%, $(SRCS))
  SRCS := $(filter-out src/frieze/%, $(SRCS))
  SRCS := $(filter-out src/tractable/%, $(SRCS))
  SRCS := $(filter-out qql-grammar/src/parser.c, $(SRCS))
  
  SRCS := $(filter-out core/qihse_audit.c, $(SRCS))
  SRCS := $(filter-out src/bombe/qihse_hetero.c, $(SRCS))
  SRCS := $(filter-out src/broad_oak/qihse_quantum_defense.c, $(SRCS))
  SRCS := $(filter-out src/broad_oak/qihse_mmdb.c, $(SRCS))
  SRCS += src/windows_stubs.c
  
  LDFLAGS = -L. -lm -lpthread -lws2_32
endif


ifeq ($(QIHSE_ENABLE_AVX2),1)
CFLAGS += -mavx2 -mfma -DQIHSE_ENABLE_AVX2=1
SRCS += backends/cpu/qihse_cpu_avx2.c
endif

ifeq ($(QIHSE_ENABLE_AVX512),1)
CFLAGS += -mavx512f -mavx512dq -mavx512bw -mavx512vl -mfma -DQIHSE_ENABLE_AVX512=1
SRCS += backends/cpu/qihse_cpu_avx512.c
endif

# AVX-VNNI: integer dot-product via 256-bit VEX-encoded vpdpbusd (Alder Lake+, Zen4+).
# Distinct from AVX-512 VNNI. Requires AVX2 to be enabled as well.
ifeq ($(QIHSE_ENABLE_AVX_VNNI),1)
ifeq ($(QIHSE_ENABLE_AVX2),1)
CFLAGS += -mavxvnni -DQIHSE_ENABLE_AVX_VNNI=1
else
$(warning QIHSE_ENABLE_AVX_VNNI=1 requires QIHSE_ENABLE_AVX2=1 -- AVX-VNNI disabled)
endif
endif

# AMX: 2D tile matrix multiply (Sapphire Rapids+). Needs kernel tile-permission prctl.
ifeq ($(QIHSE_ENABLE_AMX),1)
CFLAGS += -mamx-tile -mamx-int8 -mamx-bf16 -DQIHSE_ENABLE_AMX=1
endif

# Note: core/qihse_plugin.c and algorithms/qihse_superposition.c etc are EXCLUDED 
# because their functionality is already partially in qihse_math.c / qihse_search.c 
# or provided by qihse_exports.c stubs.

.PHONY: all build build-native clean pristine workspace workspace-clean lib lib-ctypes liboqs oqs-provider persistence persistence-check test benchmark install dev-setup docs redis-cluster-node bench-cluster-crc test-object-acl test-cluster-slot test-cluster-numa test-resp-cluster test-persist test-edge-persistence test-routing-persistence test-kv-read-integrity test-trinary-codec test-memory-planner test-memory-topology-probe test-memory-planner-trace test-memory-allocation-policy test-memory-coherence test-memory-migration-policy test-memory-migration test-memory-device-placement test-memory-migration-backend test-memory-migration-scheduler bench-trinary-codec bench-trinary-db-candidate bench-micro bench-trinary-search-path bench-trinary-search-sweep bench-trinary-random-sweep bench-trinary-weighted-sweep bench-trinary-magnitude-sweep bench-reference-workloads bench-reference-runner-smoke sample-vxug-pdf-workload bench-vxug-pdf-workload bench-reference-workload bench-reference-result-summary bench-sift1m-workload bench-sift1m-fallback-data calibrate-sift1m-workload validate-reference-workflow check-upstream-workflow check-upstream-workflow-strict check upstream-pr-loop test-all-isa test-vnni-bench test-vnni-only test-avx2-only test-avx512-direct test-amx-only test-direct-execution test-simple-exec test-hnsw-anchor-seeding test-column-tsdb-anchor test-neural-fts-fusion test-af-xdp-keystone-ingest test-dist-planner-hardware bench-keystone-integrated
.NOTPARALLEL: validate-reference-workflow

all: liboqs oqs-provider lib server keygen
build: liboqs oqs-provider lib server lib-ctypes keygen

build-native:
	./scripts/build-native.sh

server: lib
	$(CC) $(CFLAGS) -o tests/qihse_server tests/qihse_server.c -L. -lqihse $(LDFLAGS)

redis-cluster-node: lib
	$(CC) $(CFLAGS) -o tests/qihse_cluster_node tests/qihse_cluster_node.c -L. -lqihse $(LDFLAGS)

redis-cluster-bootstrap: lib
	$(CC) $(CFLAGS) -o tests/qihse_cluster_bootstrap tests/qihse_cluster_bootstrap.c -L. -lqihse $(LDFLAGS)

keygen: persistence/qihse_pqc_crypto.c persistence/qihse_pqc_crypto.h tools/qihse_keygen.c
	@echo "Building qihse_keygen..."
	$(CC) -std=c99 -Wall -Wextra -O2 -fPIC \
	    -I. -I./persistence -I./include \
	    -o qihse_keygen \
	    tools/qihse_keygen.c \
	    persistence/qihse_pqc_crypto.c \
	    -lssl -lcrypto -lpthread
	@echo "qihse_keygen build successful"
	@echo "  Usage: ./qihse_keygen [output-dir]"

xdp-kern: src/networking/qihse_xdp_kern.c
	@echo "Building eBPF XDP kernel object..."
	clang -O2 -target bpf \
	    -I/usr/include \
	    -I/usr/include/x86_64-linux-gnu \
	    -D__TARGET_ARCH_x86 \
	    -c src/networking/qihse_xdp_kern.c \
	    -o src/networking/qihse_xdp.o
	@echo "qihse_xdp.o build successful"

lib: $(LIB_TARGET)

# ---------------------------------------------------------------------------
# liboqs — post-quantum cryptography library (submodule)
# ---------------------------------------------------------------------------
liboqs:
	@if [ -f vendor/liboqs/CMakeLists.txt ]; then \
		echo "Building liboqs..."; \
		cd vendor/liboqs && mkdir -p build && cd build && \
		cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_USE_OPENSSL=OFF .. 2>&1 && \
		ninja 2>&1; (ninja install 2>&1 || true); \
		echo "liboqs build successful"; \
	elif [ -f /usr/local/include/oqs/oqs.h ] || [ -f /usr/include/oqs/oqs.h ]; then \
		echo "liboqs already installed on system."; \
	else \
		echo "liboqs submodule not present; skipping local build"; \
	fi

# ---------------------------------------------------------------------------
# oqs-provider — OpenSSL 3.x provider bridging liboqs PQC algorithms
# ---------------------------------------------------------------------------
oqs-provider: liboqs
	@if [ -f vendor/oqs-provider/CMakeLists.txt ] && ([ -f /usr/local/lib/cmake/liboqs/liboqsConfig.cmake ] || [ -f /usr/lib/cmake/liboqs/liboqsConfig.cmake ]); then \
		echo "Building oqs-provider..."; \
		cd vendor/oqs-provider && mkdir -p build && cd build && \
		cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
			-DOPENSSL_ROOT_DIR=/usr \
			-DOPENSSL_INCLUDE_DIR=/usr/include \
			-DOPENSSL_CRYPTO_LIBRARY=/usr/lib/x86_64-linux-gnu/libcrypto.so \
			-DOPENSSL_SSL_LIBRARY=/usr/lib/x86_64-linux-gnu/libssl.so \
			-Dliboqs_DIR=/usr/local/lib/cmake/liboqs .. 2>&1 && \
		ninja 2>&1 && (ninja install 2>&1 || true); \
		echo "oqs-provider build successful"; \
	else \
		echo "oqs-provider prerequisites not met; skipping"; \
	fi

CSRCS = $(filter %.c, $(SRCS))
CXXSRCS = $(filter %.cpp, $(SRCS))
COBJS = $(CSRCS:.c=.o)
CXXOBJS = $(CXXSRCS:.cpp=.o)
OBJS = $(COBJS) $(CXXOBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS_BASE) -c $< -o $@

$(LIB_TARGET): $(OBJS)
	@echo "Building $(LIB_TARGET)..."
	$(CXX) -shared -fPIC -o $(LIB_TARGET) $(OBJS) $(filter-out -lqihse,$(LDFLAGS)) -lsqlite3
	@echo "$(LIB_TARGET) build successful"

lib-ctypes: $(filter-out sdks/python/qihse.o,$(OBJS))
	@echo "Building libqihse.so..."
	$(CXX) -shared -fPIC -o libqihse.so $(subst .c,.o,$(subst .cpp,.o,$(SRCS))) \
	    -L. -ldl -lm -lpthread -luring -lpython3.13 -lluajit-5.1 -lssl -lcrypto -lbpf -lxdp -lsqlite3 $$(pkg-config --libs sqlite3)
	@echo "libqihse.so build successful"

persistence: test-persist
persistence-check: test-persist

test-graph: lib
	$(CC) $(CFLAGS) -o tests/test_graph tests/test_graph.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_graph

test-object-acl: lib
	$(CC) $(CFLAGS) -o tests/test_object_acl tests/test_object_acl.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_object_acl

test-persist: lib
	$(CC) $(CFLAGS) -o tests/qihse_vector_db_persistence_test \
	    tests/qihse_vector_db_persistence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_vector_db_persistence_test

test-edge-persistence: lib
	$(CC) $(CFLAGS) -o tests/qihse_edge_persistence_test \
	    tests/qihse_edge_persistence_test.c \
	    -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/qihse_edge_persistence_test

test: test-object-acl test-graph test-cluster-slot test-cluster-numa test-resp-cluster test-cluster-bus test-cluster-failover test-guard-throttle test-cluster-scatter test-task test-omni test-e2e test-e2e-memory-planner test-persist test-bytecode test-document-store test-column-store test-fts-engine test-neural-fts-fusion test-timeseries test-event-stream test-routing-persistence test-trinary-codec test-memory-planner test-memory-topology-probe test-memory-planner-trace test-memory-allocation-policy test-memory-coherence test-memory-migration-policy test-memory-migration test-memory-device-placement test-memory-migration-backend test-memory-migration-scheduler test-quantization test-kv-read-integrity test-hnsw-anchor-seeding test-column-tsdb-anchor test-af-xdp-keystone-ingest test-dist-planner-hardware

test-cluster-slot: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_slot tests/test_cluster_slot.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_slot

test-cluster-numa: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_numa tests/test_cluster_numa.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_numa

test-resp-cluster: lib
	$(CC) $(CFLAGS) -o tests/test_resp_cluster tests/test_resp_cluster.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_resp_cluster

test-cluster-bus: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_bus tests/test_cluster_bus.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_bus

test-cluster-failover: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_failover tests/test_cluster_failover.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_failover

test-af-xdp-resp: lib
	$(CC) $(CFLAGS) -o tests/test_af_xdp_resp tests/test_af_xdp_resp.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_af_xdp_resp

test-af-xdp-keystone-ingest: lib
	$(CC) $(CFLAGS) -o tests/test_af_xdp_keystone_ingest tests/test_af_xdp_keystone_ingest.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_af_xdp_keystone_ingest

test-guard-throttle: lib
	$(CC) $(CFLAGS) -o tests/test_guard_throttle tests/test_guard_throttle.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_guard_throttle

test-cluster-scatter: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_scatter tests/test_cluster_scatter.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_scatter

test-dist-planner: lib
	$(CC) $(CFLAGS) -o tests/test_dist_planner tests/test_dist_planner.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_dist_planner

test-dist-planner-hardware: lib
	$(CC) $(CFLAGS) -o tests/test_dist_planner_hardware tests/test_dist_planner_hardware.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_dist_planner_hardware

test-task-queue: lib
	$(CC) $(CFLAGS) -o tests/test_task_queue tests/test_task_queue.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_task_queue

test-task-worker: lib
	$(CC) $(CFLAGS) -o tests/test_task_worker tests/test_task_worker.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_task_worker

test-task-scheduler: lib
	$(CC) $(CFLAGS) -o tests/test_task_scheduler tests/test_task_scheduler.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_task_scheduler

test-task-resp: lib
	$(CC) $(CFLAGS) -o tests/test_task_resp tests/test_task_resp.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_task_resp

test-task: test-task-queue test-task-worker test-task-scheduler test-task-resp

test-cluster-rebalance: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_rebalance tests/test_cluster_rebalance.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_rebalance

test-pg-wire-cluster: lib
	$(CC) $(CFLAGS) -o tests/test_pg_wire_cluster tests/test_pg_wire_cluster.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_pg_wire_cluster

test-keystone-qihse: lib
	$(CC) $(CFLAGS) -o tests/test_keystone_qihse_integration tests/test_keystone_qihse_integration.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_keystone_qihse_integration

test-hnsw-anchor-seeding: lib
	$(CC) $(CFLAGS) -o tests/test_hnsw_anchor_seeding tests/test_hnsw_anchor_seeding.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_hnsw_anchor_seeding

test-kv-read-integrity: lib
	$(CC) $(CFLAGS) -o tests/test_kv_read_integrity tests/test_kv_read_integrity.c -L. -lqihse $(LDFLAGS)
	rm -f qihse_integrity.chain*
	@status=0; LD_LIBRARY_PATH=. ./tests/test_kv_read_integrity || status=$$?; \
		rm -f tests/test_kv_read_integrity; exit $$status

test-bytecode: lib
	$(CC) $(CFLAGS) -o tests/test_bytecode tests/test_bytecode.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_bytecode

test-qql-parser: lib
	$(CC) $(CFLAGS) -o tests/test_qql_parser tests/test_qql_parser.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_qql_parser

test-document-store: lib
	$(CC) $(CFLAGS) -o tests/test_document_store tests/test_document_store.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_document_store

test-column-store: lib
	$(CC) $(CFLAGS) -o tests/test_column_store tests/test_column_store.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_column_store

test-fts-engine: lib
	$(CC) $(CFLAGS) -o tests/test_fts_engine tests/test_fts_engine.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_fts_engine

test-neural-fts-fusion: lib
	$(CC) $(CFLAGS) -o tests/test_neural_fts_fusion tests/test_neural_fts_fusion.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_neural_fts_fusion

test-e2e: lib
	$(CC) $(CFLAGS) -o tests/test_qihse_e2e tests/test_qihse_e2e.c -L. -lqihse $(LDFLAGS)
	rm -f qihse_integrity.chain*
	LD_LIBRARY_PATH=. ./tests/test_qihse_e2e

test-omni: lib
	$(CC) $(CFLAGS) -o tests/test_qihse_omni tests/test_qihse_omni.c -L. -lqihse $(LDFLAGS)
	rm -f qihse_integrity.chain*
	LD_LIBRARY_PATH=. ./tests/test_qihse_omni

test-apt41:
	$(CC) $(CFLAGS) -fsanitize=address,undefined -g -fno-omit-frame-pointer -o tests/apt41_fuzzer tests/apt41_fuzzer.c -L. -lqihse $(LDFLAGS)
	ASAN_OPTIONS=detect_leaks=1 LD_LIBRARY_PATH=. ./tests/apt41_fuzzer

test-apt41-qql: lib
	$(CC) $(CFLAGS) -fsanitize=address,undefined -g -fno-omit-frame-pointer -o tests/apt41_qql_fuzzer tests/apt41_qql_fuzzer.c -L. -lqihse $(LDFLAGS)
	ASAN_OPTIONS=detect_leaks=1 LD_LIBRARY_PATH=. ./tests/apt41_qql_fuzzer

test-pq: lib
	$(CC) $(CFLAGS) -o tests/test_qihse_pq tests/test_qihse_pq.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_qihse_pq

test-quantization: lib
	$(CC) $(CFLAGS) -o tests/test_quantization tests/test_quantization.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_quantization

test-timeseries: lib
	$(CC) $(CFLAGS) -o tests/test_timeseries tests/test_timeseries.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_timeseries

test-column-tsdb-anchor: lib
	$(CC) $(CFLAGS) -o tests/test_column_tsdb_anchor tests/test_column_tsdb_anchor.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_column_tsdb_anchor

test-event-stream: lib
	$(CC) $(CFLAGS) -o tests/test_event_stream tests/qihse_event_stream_test.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_event_stream

test-routing-persistence: lib
	$(CC) $(CFLAGS) -o tests/test_routing_persistence tests/qihse_routing_persistence_test.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_routing_persistence

test-pqc: lib
	$(CC) $(CFLAGS) -o tests/test_pqc_e2e tests/test_pqc_e2e.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. QIHSE_ENABLE_PQC=1 ./tests/test_pqc_e2e

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
	$(CC) $(CFLAGS) -mavx2 -mfma -mavxvnni -o tests/test_vnni_only tests/test_vnni_only.c $(LDFLAGS)
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

bench-cluster-crc: lib
	$(CC) $(CFLAGS) -o benchmarks/qihse_cluster_crc_bench benchmarks/qihse_cluster_crc_bench.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./benchmarks/qihse_cluster_crc_bench

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

bench-hotpath: lib qihse_vfs.so
	$(CC) $(CFLAGS) -o benchmarks/qihse_system_hotpath_bench \
		benchmarks/qihse_system_hotpath_bench.c ./qihse_vfs.so \
		-L. -lqihse $(LDFLAGS) -Wl,-rpath,'$$ORIGIN/..'
	LD_LIBRARY_PATH=. ./benchmarks/qihse_system_hotpath_bench

bench-keystone-integrated: lib
	$(CC) $(CFLAGS) -o benchmarks/qihse_keystone_integrated_bench \
		benchmarks/qihse_keystone_integrated_bench.c \
		-L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./benchmarks/qihse_keystone_integrated_bench

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

isa-info:
	@echo "=== QIHSE ISA build-time detection ==="
	@echo "  QIHSE_ENABLE_AVX2     = $(QIHSE_ENABLE_AVX2)"
	@echo "  QIHSE_ENABLE_AVX512   = $(QIHSE_ENABLE_AVX512)"
	@echo "  QIHSE_ENABLE_AVX_VNNI = $(QIHSE_ENABLE_AVX_VNNI)"
	@echo "  QIHSE_ENABLE_AMX      = $(QIHSE_ENABLE_AMX)"
	@echo "  CC                    = $(CC)"
	@echo "  CFLAGS (ISA portion)  = $(filter -mavx% -mfma -mamx% -mfpmath%,$(CFLAGS))"

clean:
	rm -f $(OBJS) *.o libqihse.so qihse.dll qihse_benchmark qihse_benchmark_a00 \
	    qihse_keygen \
	    tests/qihse_vector_db_persistence_test tests/qihse_trinary_codec_test \
	    tests/test_all_isa tests/test_vnni_bench tests/test_vnni_only \
	    tests/test_avx2_only tests/test_avx512_direct tests/test_amx_only \
	    tests/test_direct_execution tests/test_simple_exec tests/test_timeseries \
	    tests/test_column_tsdb_anchor tests/test_object_acl
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

# Optional page-level encryption for SQLite VFS
ifeq ($(QIHSE_VFS_ENCRYPT),1)
CFLAGS += -DQIHSE_VFS_ENCRYPT=1
endif

# Standalone loadable extension target
qihse_vfs.so: $(SRCS_VFS) persistence/qihse_file_posix.c libqihse.so
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(SRCS_VFS) persistence/qihse_file_posix.c \
	    $$(pkg-config --cflags --libs sqlite3) -L. -lqihse -lssl -lcrypto -Wl,-rpath,'$$ORIGIN'

# Integration test target
test-sqlite-vfs: qihse_vfs.so tests/test_sqlite_vfs.c
	$(CC) $(CFLAGS) -o $@ tests/test_sqlite_vfs.c ./qihse_vfs.so \
	    -L. -lqihse $$(pkg-config --cflags --libs sqlite3) -Wl,-rpath,'$$ORIGIN'
