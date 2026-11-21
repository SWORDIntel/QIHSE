ROOT := ../..
CC ?= cc
CFLAGS ?= -O2 -g
.PHONY: test
# Standalone structural codec checks; intentionally not a production approval target.
test:
	@tmp=$$(mktemp -d); trap 'rm -f "$$tmp/protocol"; rmdir "$$tmp"' EXIT; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -DQIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL \
	    -I$(ROOT)/include $(ROOT)/tests/test_ct1_authority_protocol.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_protocol.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    -L$(ROOT) -lqihse -lcrypto -o "$$tmp/protocol" && LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH "$$tmp/protocol"

.PHONY: test-quote
# Pure verified-evidence signer and verifier fixture; disposable ML-DSA-87 keys only.
test-quote:
	@tmp=$$(mktemp -d); trap 'rm -f "$$tmp/quote"; rmdir "$$tmp"' EXIT; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -I$(ROOT)/include -I$(ROOT)/persistence -I$(ROOT)/backends/cpu \
	    $(ROOT)/tests/test_ct1_node_quote.c \
	    $(ROOT)/src/black_hole/qihse_ct1_node_quote.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    $(ROOT)/persistence/qihse_pqc_crypto.c \
	    $(ROOT)/backends/cpu/qihse_cpu_detect.c \
	    -L$(ROOT) -lqihse -lcrypto -lm -pthread -o "$$tmp/quote" && LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH "$$tmp/quote"

.PHONY: test-host-state
# Isolated local-only ledger fixture: explicit provisioning, fail-closed runtime reopen;
# legacy is untrusted; strict mode uses a separate root-owned checkpoint.
# Root coverage: sudo -n make test-ct1-authority-store at repository root.
# All state and binaries live in disposable directories, never production paths.
test-host-state:
	@tmp=$$(mktemp -d); trap 'rm -f "$$tmp/host-state"; rmdir "$$tmp"' EXIT; \
	chmod 0711 "$$tmp"; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -DQIHSE_CT1_TEST_CRASH_CUT \
	    -I$(ROOT)/include $(ROOT)/tests/test_ct1_authority_store.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_store.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    -L$(ROOT) -lqihse -lcrypto -o "$$tmp/host-state" && (cd "$$tmp" && LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH ./host-state)

.PHONY: test-service test-ci
# Issue/consume stay disabled; verify disposable signed records independently.
# Root coverage: sudo -n make -C tests/ct1_authority test-service.
test-service:
	@tmp=$$(mktemp -d); trap 'rm -f "$$tmp/service" "$$tmp/service-dev" "$$tmp/authority" "$$tmp/qihse_audit.log" "$$tmp/qihse_audit.writer.lock" "$$tmp/qihse_integrity.chain"; rmdir "$$tmp"' EXIT; \
	set -e; chmod 0711 "$$tmp"; \
	for mode in service service-dev; do \
	    defs=; \
	    if [ "$$mode" = service-dev ]; then \
	        defs='-DQIHSE_CT1_INSECURE_DEV_AUTHORITY_PROTOCOL -DQIHSE_CT1_INSECURE_DEV_WITNESS -DQIHSE_CT1_INSECURE_DEV_ARCHIVE'; \
	    fi; \
	    $(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	        -DQIHSE_CT1_TEST_CRASH_CUT $$defs \
	        -I$(ROOT)/include $(ROOT)/tests/test_ct1_authority_service.c \
	        $(ROOT)/src/black_hole/qihse_ct1_authority_service.c \
	        $(ROOT)/src/black_hole/qihse_ct1_authority_store.c \
	        $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	        $(ROOT)/src/black_hole/qihse_ct1_node_quote.c \
	        $(ROOT)/persistence/qihse_pqc_crypto.c \
	        $(ROOT)/backends/cpu/qihse_cpu_detect.c \
	        -I$(ROOT)/persistence -I$(ROOT)/backends/cpu \
	        -L$(ROOT) -lqihse -lcrypto -lm -pthread -o "$$tmp/$$mode"; \
	    (cd "$$tmp" && LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH ./"$$mode"); \
	done; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -Wall -Wextra -Werror \
	    -I$(ROOT)/include $(ROOT)/tools/qihse_ct1_authority.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_service.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_store.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    $(ROOT)/src/black_hole/qihse_ct1_node_quote.c \
	    $(ROOT)/persistence/qihse_pqc_crypto.c \
	    $(ROOT)/backends/cpu/qihse_cpu_detect.c \
	    -I$(ROOT)/persistence -I$(ROOT)/backends/cpu \
	    -L$(ROOT) -lqihse -lcrypto -lm -pthread -o "$$tmp/authority"; \
	LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH "$$tmp/authority" --help; \
	rc=0; LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH "$$tmp/authority" --status || rc=$$?; test "$$rc" -eq 2

# Root host with separate preprovisioned strict ledger/checkpoint, public socket
# and disposable distinct-UID Operator/B client keys. No production listener or grant.
# Invoke explicitly as root; it is not part of the broad test lane.
# Frozen roster verifier needs non-writable ancestors, so use the checkout's parent
# rather than a system temporary directory with world-writable ancestors.
.PHONY: test-host-admission
test-host-admission:
	@test "$$(id -u)" -eq 0 || { echo 'test-host-admission requires root' >&2; exit 1; }
	@tmp=$$(mktemp -d -p "$$(dirname "$$(realpath "$(ROOT)")")"); trap 'rm -f "$$tmp/host-admission" "$$tmp/audit-data/qihse_audit.log" "$$tmp/audit-data/qihse_audit.writer.lock" "$$tmp/audit-data/qihse_integrity.chain"; rmdir "$$tmp/audit-data" "$$tmp"' EXIT; \
	chmod 0700 "$$tmp"; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -DQIHSE_CT1_TEST_CRASH_CUT \
	    -I$(ROOT) -I$(ROOT)/include -I$(ROOT)/persistence \
	    $(ROOT)/tests/test_ct1_host_admission.c \
	    $(ROOT)/tests/test_ct1_receiver_writer.c \
	    $(ROOT)/src/black_hole/qihse_ct1_host_admission.c \
	    $(ROOT)/src/black_hole/qihse_ct1_receiver_writer.c \
	    $(ROOT)/src/black_hole/qihse_ct1_archive.c \
	    $(ROOT)/src/black_hole/qihse_ct1_disposition.c \
	    $(ROOT)/src/black_hole/qihse_ct_codec.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_store.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_service.c \
	    $(ROOT)/src/black_hole/qihse_ct1_node_quote.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    $(ROOT)/src/spinnaker/qihse_qkp.c \
	    -L$(ROOT) -lqihse -lcrypto -lpthread -o "$$tmp/host-admission" && \
	(cd "$$tmp" && LD_LIBRARY_PATH=$(abspath $(ROOT)) ./host-admission "$$tmp")

# Focused CI lane only; never issues a grant or contacts production nodes.
test-ci: test test-quote test-host-state test-service test-disposition

.PHONY: test-disposition
# Explicit, in-memory custody codec check; no approval, WAL or production apply.
test-disposition:
	@tmp=$$(mktemp -d); trap 'rm -f "$$tmp/disposition"; rmdir "$$tmp"' EXIT; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -I$(ROOT)/include $(ROOT)/tests/test_ct1_disposition.c \
	    $(ROOT)/src/black_hole/qihse_ct1_disposition.c \
	    $(ROOT)/src/black_hole/qihse_ct_codec.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    -L$(ROOT) -lqihse -lcrypto -o "$$tmp/disposition" && LD_LIBRARY_PATH=$(abspath $(ROOT)):$$LD_LIBRARY_PATH "$$tmp/disposition"

# Independent native receiver-store evidence, not a host approval or B writer.
.PHONY: test-native-receiver
test-native-receiver:
	@test "$$(id -u)" -eq 0 || { echo 'test-native-receiver requires root' >&2; exit 1; }
	@tmp=$$(mktemp -d -p "$$(dirname "$$(realpath "$(ROOT)")")"); trap 'rm -f "$$tmp/native-receiver"; rmdir "$$tmp"' EXIT; \
	chmod 0700 "$$tmp"; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -I$(ROOT)/include -I$(ROOT)/core -I$(ROOT)/tests \
	    $(ROOT)/tests/test_ct1_receiver_fixture.c \
	    $(ROOT)/tests/ct1_authority/native_historical_reemit.c \
	    -L$(ROOT) -lqihse -lcrypto -lpthread -o "$$tmp/native-receiver" && \
	(cd "$$tmp" && LD_LIBRARY_PATH=$(abspath $(ROOT)) ./native-receiver "$$tmp")

# Diagnostic integration gate: native target and source must satisfy the
# canonical roster/frame contract before any host B or quotes are asserted.
.PHONY: test-host-native-evidence
test-host-native-evidence:
	@test "$$(id -u)" -eq 0 || { echo 'test-host-native-evidence requires root' >&2; exit 1; }
	@tmp=$$(mktemp -d -p "$$(dirname "$$(realpath "$(ROOT)")")"); trap 'rm -rf -- "$$tmp"' EXIT; \
	chmod 0700 "$$tmp"; \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -I$(ROOT)/include -I$(ROOT)/core -I$(ROOT)/tests \
	    $(ROOT)/tests/test_ct1_receiver_fixture.c \
	    $(ROOT)/tests/ct1_authority/native_historical_reemit.c \
	    -L$(ROOT) -lqihse -lcrypto -lpthread -o "$$tmp/native-receiver" && \
	(cd "$$tmp" && LD_LIBRARY_PATH=$(abspath $(ROOT)) ./native-receiver export "$$tmp") && \
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror \
	    -DQIHSE_CT1_TEST_CRASH_CUT \
	    -I$(ROOT) -I$(ROOT)/include -I$(ROOT)/persistence \
	    $(ROOT)/tests/test_ct1_host_admission.c \
	    $(ROOT)/tests/test_ct1_receiver_writer.c \
	    $(ROOT)/src/black_hole/qihse_ct1_host_admission.c \
	    $(ROOT)/src/black_hole/qihse_ct1_receiver_writer.c \
	    $(ROOT)/src/black_hole/qihse_ct1_archive.c \
	    $(ROOT)/src/black_hole/qihse_ct1_disposition.c \
	    $(ROOT)/src/black_hole/qihse_ct_codec.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_store.c \
	    $(ROOT)/src/black_hole/qihse_ct1_authority_service.c \
	    $(ROOT)/src/black_hole/qihse_ct1_node_quote.c \
	    $(ROOT)/src/black_hole/qihse_ct1_recovery_manifest.c \
	    $(ROOT)/src/spinnaker/qihse_qkp.c \
	    -L$(ROOT) -lqihse -lcrypto -lpthread -o "$$tmp/host-admission" && \
	(cd "$$tmp" && LD_LIBRARY_PATH=$(abspath $(ROOT)) ./host-admission native-evidence "$$tmp")
