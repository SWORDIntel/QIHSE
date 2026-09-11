# Security regression targets layered on top of the root Makefile.
# Usage: make -f Makefile -f tests/security-regression.mk test-security-regressions

.PHONY: test-kv-security-regression test-keystone-qihse-security test-vector-skip-integrity test-resp-security-regression test-security-regressions

test-kv-security-regression: lib
	$(CC) $(CFLAGS) -o tests/test_kv_security_regression tests/test_kv_security_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_kv_security_regression

test-keystone-qihse-security: lib
	$(CC) $(CFLAGS) -o tests/test_keystone_qihse_integration tests/test_keystone_qihse_integration.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_keystone_qihse_integration

test-vector-skip-integrity: lib
	$(CC) $(CFLAGS) -Ipersistence -o tests/test_vector_skip_integrity tests/test_vector_skip_integrity.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_vector_skip_integrity

test-resp-security-regression: lib
	$(CC) $(CFLAGS) -o tests/test_resp_security_regression tests/test_resp_security_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_resp_security_regression

test-security-regressions: test-kv-security-regression test-keystone-qihse-security test-vector-skip-integrity test-resp-security-regression
