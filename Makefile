# QIHSE Breakthroughalgo Makefile
# Phase 0.5: Quantum-Inspired Core Algorithms

CC=gcc
CXX=g++

PYTHON_INCLUDES ?= $(shell python3-config --includes 2>/dev/null || pkg-config --cflags python3 2>/dev/null || echo "-I/usr/include/python3.13")
PYTHON_LDFLAGS  ?= $(shell python3-config --ldflags --embed 2>/dev/null || python3-config --ldflags 2>/dev/null || pkg-config --libs python3 2>/dev/null || echo "-lpython3.13")

INCLUDES = -I. -I./include -I./include/network_intelligence -I./core -I./algorithms -I./backends/cpu -I./backends/npu -I./orchestration/include -I./memory/include -I./quantization/include -I./ml/include -I./sync -I./vendor/tree-sitter/lib/include -I/usr/include/luajit-2.1 -I/usr/local/include -I./vendor/liboqs/include -I./src/network_intelligence -I./persistence
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
SRCS_BASE = core/qihse.c sdks/python/qihse.c core/qihse_auth.c core/qihse_audit.c core/qihse_rate_limit.c core/qihse_quota.c \
            src/broad_oak/qihse_search.c src/broad_oak/qihse_hnsw.c \
            src/bombe/qihse_math.c src/bombe/qihse_instr.c src/bombe/qihse_hetero.c \
            src/broad_oak/qihse_vector_db.c src/broad_oak/qihse_system_guard.c src/qihse_exports.c src/broad_oak/qihse_recursive_search.c \
            src/marmalade/qihse_temporal.c src/bombe/qihse_fusion.c src/spinnaker/qihse_subscription.c src/spinnaker/qihse_cluster.c src/spinnaker/qihse_lua_injector.c src/spinnaker/qihse_http_telemetry.c \
            src/spinnaker/qihse_crc16.c src/spinnaker/qihse_cluster_slot.c src/spinnaker/qihse_cluster_numa.c src/spinnaker/qihse_cluster_migrate.c src/spinnaker/qihse_resp_cluster.c src/spinnaker/qihse_resp_engine.c src/spinnaker/qihse_resp_pubsub.c src/spinnaker/qihse_cluster_bus.c src/spinnaker/qihse_cluster_failover.c src/spinnaker/qihse_cluster_scatter.c src/spinnaker/qihse_cluster_rebalance.c \
            src/spinnaker/qihse_task_queue.c src/spinnaker/qihse_task_worker.c src/spinnaker/qihse_task_scheduler.c src/spinnaker/qihse_ingest_guard.c src/spinnaker/qihse_bundle.c src/spinnaker/qihse_fabric_index.c src/federation/qihse_fabric_dispatch.c \
            src/black_hole/qihse_kv_store.c src/black_hole/qihse_blob.c src/black_hole/qihse_export.c src/black_hole/qihse_keystone.c src/spinnaker/qihse_resp_wire.c src/spinnaker/qihse_uwp.c src/spinnaker/qihse_uwp_graph_index.c src/spinnaker/qihse_uwp_repl_pool.c src/spinnaker/qihse_uwp_sql_txn_schema.c src/spinnaker/qihse_uwp_tls.c src/spinnaker/qihse_uwp_metrics.c \
            algorithms/qihse_trinary_trie.c src/black_hole/qihse_arena.c src/frieze/qihse_fts_index.c src/frieze/qihse_document_store.c src/frieze/qihse_spatial_index.c \
            src/frieze/qihse_column_store.c src/frieze/qihse_btree.c src/frieze/qihse_hash_index.c src/frieze/qihse_index_manager.c src/marmalade/qihse_timeseries.c src/marmalade/qihse_event_stream.c src/network_intelligence/qihse_routing_persistence.c \
            src/network_intelligence/bgp_route_probe.cpp src/network_intelligence/bgp_update_decoder.cpp src/network_intelligence/rpki_rtr_probe.cpp src/network_intelligence/rdap_probe.cpp src/network_intelligence/ptr_probe.cpp src/network_intelligence/route_helper.cpp \
            src/tractable/qihse_bytecode.c src/tractable/qihse_bytecode_compiler.c src/tractable/qihse_index_scan.c src/tractable/qihse_txn.c src/tractable/qihse_mvcc.c src/tractable/qihse_wal.c src/tractable/qihse_recovery.c src/broad_oak/qihse_graph_store.c src/broad_oak/qihse_graph_ingest.c src/tractable/qihse_cypher_parser.c src/tractable/qihse_cypher_executor.c src/broad_oak/qihse_graph_algo.c src/broad_oak/qihse_graph_vector.c \
            src/spinnaker/qihse_pg_wire.c src/spinnaker/qihse_bolt.c src/spinnaker/qihse_protocol_translate.c src/spinnaker/qihse_pooler.c src/spinnaker/qihse_repl.c src/spinnaker/qihse_read_replica.c src/tractable/qihse_backup.c src/tractable/qihse_parallel_query.c src/spinnaker/qihse_cdc.c src/spinnaker/qihse_cluster_brain.c src/spinnaker/qihse_overlay.c src/spinnaker/qihse_ai_memory.c src/controller/qihse_controller.c src/federation/qihse_federation.c src/federation/qihse_supply_chain.c src/federation/qihse_runtime_trust.c src/federation/qihse_security_audit.c src/federation/qihse_federation_sim.c src/federation/qihse_backup.c src/federation/qihse_operations.c src/federation/qihse_federation_mtls.c src/federation/qihse_federation_repl.c src/federation/qihse_federation_transport.c src/federation/qihse_federation_rejoin.c src/federation/qihse_consensus.c src/spinnaker/qihse_mongo_wire.c src/spinnaker/qihse_http_api.c src/spinnaker/qihse_metrics.c src/spinnaker/qihse_tracing.c src/spinnaker/qihse_clickhouse_http.c src/spinnaker/qihse_es_api.c src/spinnaker/qihse_influx_api.c src/tractable/qihse_compaction.c src/tractable/qihse_sql_extensions.c src/tractable/qihse_qql_parser.c qql-grammar/src/parser.c \
            vendor/tree-sitter/lib/src/lib.c src/tractable/qihse_sql_parser.c src/tractable/qihse_dist_planner.c src/tractable/qihse_join_executor.c src/tractable/qihse_aggregate_executor.c src/tractable/qihse_sort_executor.c src/tractable/qihse_window_executor.c src/tractable/qihse_table_store.c src/tractable/qihse_schema.c src/tractable/qihse_optimizer.c src/tractable/qihse_optimizer_governance.c \
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

.PHONY: all build build-native clean pristine workspace workspace-clean lib lib-ctypes liboqs oqs-provider persistence persistence-check test benchmark install dev-setup docs redis-server redis-cluster-node cluster-daemon stress-session-delivery bench-cluster-crc test-object-acl test-cluster-slot test-cluster-numa test-resp-cluster test-resp-pubsub test-persist test-edge-persistence test-routing-persistence test-kv-read-integrity test-trinary-codec test-memory-planner test-memory-topology-probe test-memory-planner-trace test-memory-allocation-policy test-memory-coherence test-memory-migration-policy test-memory-migration test-memory-device-placement test-memory-migration-backend test-memory-migration-scheduler bench-trinary-codec bench-trinary-db-candidate bench-micro bench-trinary-search-path bench-trinary-search-sweep bench-trinary-random-sweep bench-trinary-weighted-sweep bench-trinary-magnitude-sweep bench-reference-workloads bench-reference-runner-smoke sample-vxug-pdf-workload bench-vxug-pdf-workload bench-reference-workload bench-reference-result-summary bench-sift1m-workload bench-sift1m-fallback-data calibrate-sift1m-workload validate-reference-workflow check-upstream-workflow check-upstream-workflow-strict check upstream-pr-loop test-all-isa test-vnni-bench test-vnni-only test-avx2-only test-avx512-direct test-amx-only test-direct-execution test-simple-exec test-hnsw-anchor-seeding test-column-tsdb-anchor test-neural-fts-fusion test-af-xdp-keystone-ingest test-dist-planner-hardware bench-keystone-integrated test-uwp-regression test-uwp-metrics fuzz-uwp
.NOTPARALLEL: validate-reference-workflow

all: liboqs oqs-provider lib server keygen federation-ca
build: liboqs oqs-provider lib server lib-ctypes keygen

build-native:
	./scripts/build-native.sh

server: lib
	$(CC) $(CFLAGS) -o tests/qihse_server tests/qihse_server.c -L. -lqihse $(LDFLAGS)

redis-cluster-node: lib
	$(CC) $(CFLAGS) -o tests/qihse_cluster_node tests/qihse_cluster_node.c -L. -lqihse $(LDFLAGS)

redis-server: lib
	$(CC) $(CFLAGS) -o qihse-redis-server tools/qihse_redis_server.c -L. -lqihse $(LDFLAGS)
	@echo "qihse-redis-server build successful"

# Session-delivery stress: N tenants, 1-5 MB up/down each, for a time budget.
# Tune via env: QIHSE_STRESS_TENANTS QIHSE_STRESS_SECONDS QIHSE_STRESS_MIN_MB QIHSE_STRESS_MAX_MB QIHSE_STRESS_CYCLE_MS
stress-session-delivery: lib
	$(CC) $(CFLAGS) -o tests/stress_session_delivery tests/stress_session_delivery.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/stress_session_delivery

cluster-daemon: lib
	$(CC) $(CFLAGS) -o qihse-cluster-daemon tools/qihse_cluster_daemon.c -L. -lqihse $(LDFLAGS)
	@echo "qihse-cluster-daemon build successful"

redis-cluster-bootstrap: lib
	$(CC) $(CFLAGS) -o tests/qihse_cluster_bootstrap tests/qihse_cluster_bootstrap.c -L. -lqihse $(LDFLAGS)

keygen: persistence/qihse_pqc_crypto.c persistence/qihse_pqc_crypto.h tools/qihse_keygen.c
	@echo "Building qihse_keygen..."
	$(CC) -std=c99 -Wall -Wextra -O2 -fPIC \
	    -DQIHSE_KEY_DIR='""' \
	    -I. -I./persistence -I./include \
	    -o qihse_keygen \
	    tools/qihse_keygen.c \
	    persistence/qihse_pqc_crypto.c \
	    -lssl -lcrypto -lpthread
	@echo "qihse_keygen build successful"
	@echo "  Usage: ./qihse_keygen [output-dir]  (default: /opt/qihse/keys)"

# Out-of-process federation CA provisioning.  Deliberately NOT part of
# SRCS_BASE/libqihse.so: a CA-minting primitive must not live inside the
# server process; it is compiled only into this tool and its test.
federation-ca: lib
	$(CC) $(CFLAGS) -o qihse-federation-ca tools/qihse_federation_ca.c \
	    src/federation/qihse_ca_provision.c -L. -lqihse $(LDFLAGS)
	@echo "qihse-federation-ca build successful"
	@echo "  Usage: ./qihse-federation-ca <init-ca|issue-node|revoke|verify> ..."

xdp-kern: src/networking/qihse_xdp_kern.c
	@echo "Building eBPF XDP kernel object..."
	clang -O2 -target bpf \
	    -I/usr/include \
	    -I/usr/include/x86_64-linux-gnu \
	    -D__TARGET_ARCH_x86 \
	    -c src/networking/qihse_xdp_kern.c \
	    -o src/networking/qihse_xdp.o
	@echo "qihse_xdp.o build successful"

lib: liboqs oqs-provider $(LIB_TARGET)

# ---------------------------------------------------------------------------
# liboqs — post-quantum cryptography library (submodule)
# ---------------------------------------------------------------------------
liboqs:
	@if [ ! -f vendor/liboqs/CMakeLists.txt ]; then \
		echo "Initializing liboqs submodule..."; \
		git submodule update --init --recursive vendor/liboqs; \
	fi
	@if [ -f vendor/liboqs/CMakeLists.txt ] && [ ! -f vendor/liboqs/build/lib/liboqs.so ] && [ ! -f /usr/local/lib/liboqs.so ]; then \
		echo "Building liboqs..."; \
		cd vendor/liboqs && mkdir -p build && cd build && \
		cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON .. 2>&1 && \
		ninja 2>&1; (ninja install 2>&1 || true); \
		echo "liboqs build successful"; \
	elif [ -f /usr/local/lib/liboqs.so ] || [ -f vendor/liboqs/build/lib/liboqs.so ]; then \
		echo "liboqs ready."; \
	fi

# ---------------------------------------------------------------------------
# oqs-provider — OpenSSL 3.x provider bridging liboqs PQC algorithms
# ---------------------------------------------------------------------------
oqs-provider: liboqs
	@if [ ! -f vendor/oqs-provider/CMakeLists.txt ]; then \
		echo "Initializing oqs-provider submodule..."; \
		git submodule update --init --recursive vendor/oqs-provider; \
	fi
	@if [ -f vendor/oqs-provider/CMakeLists.txt ] && [ ! -f vendor/oqs-provider/build/lib/oqsprovider.so ] && [ ! -f /usr/local/lib/ossl-modules/oqsprovider.so ]; then \
		echo "Building oqs-provider..."; \
		cd vendor/oqs-provider && mkdir -p build && cd build && \
		cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
			-DOPENSSL_ROOT_DIR=/usr \
			-DOPENSSL_INCLUDE_DIR=/usr/include \
			-DOPENSSL_CRYPTO_LIBRARY=/usr/lib/x86_64-linux-gnu/libcrypto.so \
			-DOPENSSL_SSL_LIBRARY=/usr/lib/x86_64-linux-gnu/libssl.so \
			-Dliboqs_DIR=$(if $(wildcard /usr/local/lib/cmake/liboqs/liboqsConfig.cmake),/usr/local/lib/cmake/liboqs,$(CURDIR)/vendor/liboqs/build) .. 2>&1 && \
		ninja 2>&1; (ninja install 2>&1 || true); \
		echo "oqs-provider build successful"; \
	elif [ -f vendor/oqs-provider/build/lib/oqsprovider.so ] || [ -f /usr/local/lib/ossl-modules/oqsprovider.so ]; then \
		echo "oqs-provider ready."; \
	fi

CSRCS = $(filter %.c, $(SRCS))
CXXSRCS = $(filter %.cpp, $(SRCS))
COBJS = $(CSRCS:.c=.o)
CXXOBJS = $(CXXSRCS:.cpp=.o)
OBJS = $(COBJS) $(CXXOBJS)

# Header dependency tracking. Without this a change to a struct in a header
# leaves every .o that included it compiled against the OLD layout while the
# rest of the tree is rebuilt against the new one, and the link succeeds: the
# mismatch shows up as memory corruption far from the edit. That is exactly
# what happened when qihse_cluster_node_t gained fields — the brain test
# failed until `make clean`, and nothing in the build said why.
#
# -MMD -MP emits a .d per object listing the headers it actually included,
# and -include pulls them in so make knows to rebuild. The generated .d files
# are build artifacts and are gitignored with the rest of the objects.
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS_BASE) -MMD -MP -c $< -o $@

-include $(OBJS:.o=.d)

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

test-graph-vector: lib
	$(CC) $(CFLAGS) -o tests/test_graph_vector tests/test_graph_vector.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_graph_vector

test-resp-hybrid: lib
	$(CC) $(CFLAGS) -o tests/test_resp_hybrid tests/test_resp_hybrid.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_resp_hybrid

test-http-adapters: lib
	$(CC) $(CFLAGS) -o tests/test_http_adapters tests/test_http_adapters.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_http_adapters

test-object-acl: lib
	$(CC) $(CFLAGS) -o tests/test_object_acl tests/test_object_acl.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_object_acl

test-auth-privilege-boundary: lib
	$(CC) $(CFLAGS) -o tests/test_auth_privilege_boundary tests/test_auth_privilege_boundary.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_auth_privilege_boundary

test-aggregate-hardened: lib
	$(CC) $(CFLAGS) -o tests/test_aggregate_hardened tests/test_aggregate_hardened.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_aggregate_hardened

test-fabric-index: lib
	$(CC) $(CFLAGS) -o tests/test_fabric_index tests/test_fabric_index.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_fabric_index

test-cluster-brain: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_brain tests/test_cluster_brain.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_brain

test-brain-incidents: lib
	$(CC) $(CFLAGS) -o tests/test_brain_incidents tests/test_brain_incidents.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_brain_incidents

test-brain-actuate: lib
	$(CC) $(CFLAGS) -o tests/test_brain_actuate tests/test_brain_actuate.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_brain_actuate

test-brain-rebalance: lib
	$(CC) $(CFLAGS) -o tests/test_brain_rebalance tests/test_brain_rebalance.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_brain_rebalance

test-brain-fed-journal: lib
	$(CC) $(CFLAGS) -o tests/test_brain_fed_journal tests/test_brain_fed_journal.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_brain_fed_journal

test-federation-f0: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f0 tests/test_federation_f0.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f0

test-federation-f1: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f1 tests/test_federation_f1.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f1

test-federation-f2: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f2 tests/test_federation_f2.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f2

test-federation-f3: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f3 tests/test_federation_f3.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f3

test-federation-f4: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f4 tests/test_federation_f4.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f4

test-lease-liveness: lib
	$(CC) $(CFLAGS) -o tests/test_lease_liveness tests/test_lease_liveness.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_lease_liveness

test-federation-f5: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f5 tests/test_federation_f5.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f5

test-federation-f6: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f6 tests/test_federation_f6.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f6

test-federation-f7: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f7 tests/test_federation_f7.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f7

test-federation-f8: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f8 tests/test_federation_f8.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f8

test-federation-f8-ops: lib
	$(CC) $(CFLAGS) -o tests/test_federation_f8_ops tests/test_federation_f8_ops.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_f8_ops

test-federation-fuzz: lib
	$(CC) $(CFLAGS) -o tests/test_federation_fuzz tests/test_federation_fuzz.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_fuzz

test-federation-bus-trust: lib
	$(CC) $(CFLAGS) -o tests/test_federation_bus_trust tests/test_federation_bus_trust.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_bus_trust

# W2.4: NODE_CAP payloads as durable federation/node/<uuid> records.
test-node-cap-records: lib
	$(CC) $(CFLAGS) -o tests/test_node_cap_records tests/test_node_cap_records.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_node_cap_records

# §25 controller-facing API: typed RESP client (qihse_controller).
test-controller-api: lib
	$(CC) $(CFLAGS) -o tests/test_controller_api tests/test_controller_api.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_controller_api

test-federation-mtls: lib
	$(CC) $(CFLAGS) -o tests/test_federation_mtls tests/test_federation_mtls.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_mtls

test-federation-repl: lib
	$(CC) $(CFLAGS) -o tests/test_federation_repl tests/test_federation_repl.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_repl

test-federation-transport: lib
	$(CC) $(CFLAGS) -o tests/test_federation_transport tests/test_federation_transport.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_transport

test-federation-ca: lib
	$(CC) $(CFLAGS) -o tests/test_federation_ca tests/test_federation_ca.c \
	    src/federation/qihse_ca_provision.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_ca

test-federation-crl: lib
	$(CC) $(CFLAGS) -o tests/test_federation_crl tests/test_federation_crl.c \
	    src/federation/qihse_ca_provision.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_crl

test-backup-auth: lib
	$(CC) $(CFLAGS) -I./core -o tests/test_backup_auth tests/test_backup_auth.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_backup_auth

test-controller-sdk-py: lib
	PYTHONPATH=python LD_LIBRARY_PATH=. python3 -m unittest discover -s python/tests -p test_controller_sdk.py

test-consensus: lib
	$(CC) $(CFLAGS) -o tests/test_consensus tests/test_consensus.c src/federation/qihse_consensus.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_consensus

test-incremental-export: lib
	$(CC) $(CFLAGS) -o tests/test_incremental_export tests/test_incremental_export.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_incremental_export

test-federation-rejoin: lib
	$(CC) $(CFLAGS) -o tests/test_federation_rejoin tests/test_federation_rejoin.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_rejoin

test-federation-backup: lib
	$(CC) $(CFLAGS) -o tests/test_federation_backup tests/test_federation_backup.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_federation_backup

test-keystone-feed-w25: lib
	$(CC) $(CFLAGS) -o tests/test_keystone_feed_w25 tests/test_keystone_feed_w25.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_keystone_feed_w25

test-ai-memory: lib
	$(CC) $(CFLAGS) -o tests/test_ai_memory tests/test_ai_memory.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_ai_memory

test-ai-memory-embed: lib
	$(CC) $(CFLAGS) -o tests/test_ai_memory_embed tests/test_ai_memory_embed.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_ai_memory_embed

test-ai-memory-ext: lib
	$(CC) $(CFLAGS) -o tests/test_ai_memory_ext tests/test_ai_memory_ext.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_ai_memory_ext

test-fabric-jobs: lib
	$(CC) $(CFLAGS) -o tests/test_fabric_jobs tests/test_fabric_jobs.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_fabric_jobs

test-fabric-dispatch: lib
	$(CC) $(CFLAGS) -o tests/test_fabric_dispatch tests/test_fabric_dispatch.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_fabric_dispatch

test-group-push: lib
	$(CC) $(CFLAGS) -o tests/test_group_push tests/test_group_push.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_group_push

test-overlay: lib
	$(CC) $(CFLAGS) -o tests/test_overlay tests/test_overlay.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_overlay

test-dht-peer-exchange: lib
	$(CC) $(CFLAGS) -o tests/test_dht_peer_exchange tests/test_dht_peer_exchange.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_dht_peer_exchange

test-operator-mode: lib
	$(CC) $(CFLAGS) -o tests/test_operator_mode tests/test_operator_mode.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_operator_mode

test-uwp-regression: tests/test_uwp_regression
	LD_LIBRARY_PATH=. ./tests/test_uwp_regression

tests/test_uwp_regression: tests/test_uwp_regression.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/test_uwp_regression.c -L. -lqihse -lpthread -lm -o tests/test_uwp_regression

test-uwp-metrics: tests/test_uwp_metrics
	LD_LIBRARY_PATH=. ./tests/test_uwp_metrics

tests/test_uwp_metrics: tests/test_uwp_metrics.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/test_uwp_metrics.c -L. -lqihse -lpthread -lm -o tests/test_uwp_metrics

test-uwp-tls: tests/test_uwp_tls_integration
	LD_LIBRARY_PATH=. ./tests/test_uwp_tls_integration

tests/test_uwp_tls_integration: tests/test_uwp_tls_integration.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/test_uwp_tls_integration.c -L. -lqihse -lssl -lcrypto -lpthread -lm -o tests/test_uwp_tls_integration

test-uwp-concurrency: tests/test_uwp_concurrency
	LD_LIBRARY_PATH=. ./tests/test_uwp_concurrency

tests/test_uwp_concurrency: tests/test_uwp_concurrency.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/test_uwp_concurrency.c -L. -lqihse -lpthread -lm -o tests/test_uwp_concurrency

test-uwp-real-engines: tests/test_uwp_real_engines
	LD_LIBRARY_PATH=. ./tests/test_uwp_real_engines

tests/test_uwp_real_engines: tests/test_uwp_real_engines.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/test_uwp_real_engines.c -L. -lqihse -lpthread -lm -o tests/test_uwp_real_engines

fuzz-uwp: tests/fuzz_uwp
	@echo "Build with: clang -fsanitize=fuzzer -DFUZZER_STANDALONE_MAIN=0 -I. -I./include tests/fuzz_uwp.c -L. -lqihse -lpthread -lm -o tests/fuzz_uwp"
	@echo "Run with: ./tests/fuzz_uwp -max_total_time=60"

tests/fuzz_uwp: tests/fuzz_uwp.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/fuzz_uwp.c -L. -lqihse -lpthread -lm -o tests/fuzz_uwp

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

test: test-auth-privilege-boundary test-object-acl test-aggregate-hardened test-uwp-regression test-graph test-graph-vector test-cluster-slot test-cluster-numa test-resp-cluster test-resp-pubsub test-cluster-bus test-cluster-failover test-guard-throttle test-cluster-scatter test-cluster-brain test-brain-incidents test-brain-actuate test-brain-rebalance test-brain-fed-journal test-overlay test-dht-peer-exchange test-federation-f0 test-federation-f1 test-federation-f2 test-federation-f3 test-federation-f4 test-lease-liveness test-federation-f5 test-federation-f6 test-federation-f7 test-federation-f8 test-federation-f8-ops test-federation-fuzz test-federation-bus-trust test-node-cap-records test-federation-mtls test-federation-repl test-federation-transport test-federation-rejoin test-federation-ca test-federation-crl test-federation-backup test-backup-auth test-consensus test-incremental-export test-controller-sdk-py test-keystone-feed-w25 test-ai-memory test-ai-memory-embed test-ai-memory-ext test-fabric-jobs test-fabric-dispatch test-task test-omni test-e2e test-e2e-memory-planner test-persist test-bytecode test-document-store test-column-store test-fts-engine test-neural-fts-fusion test-resp-hybrid test-http-adapters test-timeseries test-event-stream test-routing-persistence test-trinary-codec test-memory-planner test-memory-topology-probe test-memory-planner-trace test-memory-allocation-policy test-memory-coherence test-memory-migration-policy test-memory-migration test-memory-device-placement test-memory-migration-backend test-memory-migration-scheduler test-quantization test-kv-read-integrity test-hnsw-anchor-seeding test-column-tsdb-anchor test-af-xdp-keystone-ingest test-dist-planner-hardware test-txn test-mvcc-delete test-indexes test-sql-completeness test-optimizer-governance test-sql-dml-exec test-bolt test-mongo-wire test-mongo-wire-security test-repl test-phase-c test-metrics-w52 test-parallel-query test-gold

# --- W5.3 gold validation suite -------------------------------------------
# One entry point for the versioned workload pack under tests/gold/.  The pack
# is data: adding a workload is a pack edit, not a Makefile edit.  The pack
# names the binaries the Makefile must build (bin=) and runs everything else
# through the targets that already exist.  GOLD_PACK pins the pack version;
# GOLD_STRICT=1 makes known defects and recorded coverage gaps fatal (the
# runner then exits 2).
GOLD_PACK ?= tests/gold/pack.v1.gold
GOLD_WORKLOAD_BINS := $(shell sed -n '/^[[:space:]]*#/d; s/.*[[:space:]]bin=\([^[:space:]]*\/[^[:space:]]*\).*/\1/p' $(GOLD_PACK) 2>/dev/null)

test-gold: lib tests/gold/gold_runner $(GOLD_WORKLOAD_BINS)
	LD_LIBRARY_PATH=. ./tests/gold/gold_runner $(GOLD_PACK)

tests/gold/gold_runner: tests/gold/gold_runner.c libqihse.so
	$(CC) $(CFLAGS) -o tests/gold/gold_runner tests/gold/gold_runner.c -L. -lqihse $(LDFLAGS)

tests/gold/workloads/%: tests/gold/workloads/%.c libqihse.so
	$(CC) $(CFLAGS) -o $@ $< -L. -lqihse $(LDFLAGS)

# --- Architecture-document reconciliation tests ---------------------------
# Each of these is named by the corresponding document under docs/architecture/.

test-txn: lib
	$(CC) $(CFLAGS) -o tests/test_txn tests/test_txn.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_txn

# MVCC delete semantics in both directions: a committed DELETE hides the row
# whatever aborted writers preceded it, and it hides nothing a reader of an
# older snapshot, or of a version the deleter could not see, is entitled to.
test-mvcc-delete: lib
	$(CC) $(CFLAGS) -o tests/test_mvcc_delete tests/test_mvcc_delete.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_mvcc_delete

test-indexes: lib
	$(CC) $(CFLAGS) -o tests/test_indexes tests/test_indexes.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_indexes

test-sql-completeness: lib
	$(CC) $(CFLAGS) -o tests/test_sql_completeness tests/test_sql_completeness.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_sql_completeness

# W5.1 optimizer governance: shadow A/B evaluation of a candidate plan with
# the safety constraints named in code (regression bound, minimum sample size,
# result equivalence, journal required, anti-oscillation, proven improvement),
# automatic rollback inside the observation path, and every switch/rollback
# persisted to an event-stream journal.  The case that matters is the rollback:
# it asserts the violation is DETECTED and the incumbent plan is RESTORED
# without an operator, and then reads the SWITCH and ROLLBACK records back out
# of the journal with the evidence they rested on.
test-optimizer-governance: lib
	$(CC) $(CFLAGS) -o tests/test_optimizer_governance tests/test_optimizer_governance.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_optimizer_governance

# UPDATE/DELETE execution against the mutable table store, including the
# zero-condition DELETE guard (a DELETE whose WHERE parsed to nothing must
# refuse, never match-all).
test-sql-dml-exec: lib
	$(CC) $(CFLAGS) -o tests/test_sql_dml_exec tests/test_sql_dml_exec.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_sql_dml_exec

test-bolt: lib
	$(CC) $(CFLAGS) -o tests/test_bolt tests/test_bolt.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_bolt

# MongoDB wire adapter: BSON framing (spec-conformant nested documents,
# declared lengths validated against the bytes present), the catalog, command
# dispatch and the TCP server (OP_MSG + legacy OP_QUERY/OP_REPLY).
test-mongo-wire: lib
	$(CC) $(CFLAGS) -o tests/test_mongo_wire tests/test_mongo_wire.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_mongo_wire

# AGENTS.md invariant 3: the negative authorization test for the MongoDB wire
# adapter.  A low-clearance principal (classification 91, no SCI) must be
# denied every access form — query, direct-ID, enumeration, aggregate, update,
# delete, drop, handle materialisation, NULL context, forged labels, and the
# same over a real socket — with no protected payload byte in any reply.
test-mongo-wire-security: lib
	$(CC) $(CFLAGS) -o tests/test_mongo_wire_security tests/test_mongo_wire_security.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_mongo_wire_security

test-repl: lib
	$(CC) $(CFLAGS) -o tests/test_repl tests/test_repl.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_repl

test-phase-c: lib
	$(CC) $(CFLAGS) -o tests/test_phase_c tests/test_phase_c.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_phase_c

# W5.2 telemetry expansion: label-bounded families (query type, engine
# backend), per-query-type latency histograms, error counters, cluster/
# replication status, memory/index gauges and XDP counters — all rendered by
# the existing METRICS.RENDER.  Asserts the counters MOVE on the event, and
# that an undeclared label value creates no series.
test-metrics-w52: lib
	$(CC) $(CFLAGS) -o tests/test_metrics_w52_telemetry tests/test_metrics_w52_telemetry.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_metrics_w52_telemetry

# Parallel query: the scan really partitions the KV keyspace, the aggregate
# really aggregates, the hash join really joins, a join that cannot have
# matched anything is refused instead of reporting 0 rows, a refused
# pthread_create fails the operation, and a context with no user bound sees
# unclassified rows only.
test-parallel-query: lib
	$(CC) $(CFLAGS) -o tests/test_parallel_query tests/test_parallel_query.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_parallel_query

test-cluster-slot: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_slot tests/test_cluster_slot.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_slot

test-cluster-numa: lib
	$(CC) $(CFLAGS) -o tests/test_cluster_numa tests/test_cluster_numa.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_cluster_numa

test-resp-cluster: lib
	$(CC) $(CFLAGS) -o tests/test_resp_cluster tests/test_resp_cluster.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_resp_cluster

test-resp-pubsub: lib
	$(CC) $(CFLAGS) -o tests/test_resp_pubsub tests/test_resp_pubsub.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_resp_pubsub

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

test-fts-persistence-auth: lib
	$(CC) $(CFLAGS) -o tests/test_fts_persistence_auth tests/test_fts_persistence_auth.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_fts_persistence_auth

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

.PHONY: test-distance-dispatch test-exact-search-parity
test: test-distance-dispatch test-exact-search-parity

test-distance-dispatch:
	$(CC) $(CFLAGS) -o tests/test_distance_dispatch \
	    tests/test_distance_dispatch.c backends/cpu/qihse_cpu_distance.c \
	    backends/cpu/qihse_cpu_detect.c -lm -pthread
	./tests/test_distance_dispatch

test-exact-search-parity: lib
	$(CC) $(CFLAGS) -o tests/test_exact_search_parity \
	    tests/test_exact_search_parity.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_exact_search_parity

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
	    qihse_keygen qihse-federation-ca tests/test_federation_ca tests/test_federation_crl tests/test_backup_auth tests/test_consensus tests/test_incremental_export \
	    tests/qihse_vector_db_persistence_test tests/qihse_trinary_codec_test \
	    tests/test_all_isa tests/test_vnni_bench tests/test_vnni_only \
	    tests/test_avx2_only tests/test_avx512_direct tests/test_amx_only \
	    tests/test_direct_execution tests/test_simple_exec tests/test_timeseries \
	    tests/test_column_tsdb_anchor tests/test_object_acl \
	    tests/test_auth_privilege_boundary tests/test_aggregate_hardened \
	    tests/test_uwp_regression tests/fuzz_uwp
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
