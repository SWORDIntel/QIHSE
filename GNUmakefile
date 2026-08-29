# QIHSE GNU Make security overlay
#
# GNU make prefers GNUmakefile over Makefile.  Keep the main build definition in
# Makefile, then replace the standalone UWP/TLS translation units with one
# wrapper translation unit.  The wrapper includes the existing implementations
# so the router and protocol logic remain single-source, while allowing the
# public qihse_start_uwp_server() entry point to enforce certificate TLS by
# default.

include Makefile

SRCS := $(filter-out src/spinnaker/qihse_uwp.c src/spinnaker/qihse_uwp_tls.c,$(SRCS))
SRCS += src/spinnaker/qihse_uwp_secure.c

# The wrapper includes these implementation files directly, so make must
# rebuild it when either source changes.
src/spinnaker/qihse_uwp_secure.o: src/spinnaker/qihse_uwp_secure.c \
                                  src/spinnaker/qihse_uwp.c \
                                  src/spinnaker/qihse_uwp_tls.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: test-uwp-secure-default

test-uwp-secure-default: tests/test_uwp_secure_default
	LD_LIBRARY_PATH=. ./tests/test_uwp_secure_default

tests/test_uwp_secure_default: tests/test_uwp_secure_default.c libqihse.so
	$(CC) $(CFLAGS) -I. -I./include tests/test_uwp_secure_default.c \
		-L. -lqihse -lssl -lcrypto -lpthread -lm -o $@

# Extend the normal regression suite with both the existing real TLS 1.3
# handshake test and the new fail-closed default-policy test.
test: test-uwp-tls test-uwp-secure-default
