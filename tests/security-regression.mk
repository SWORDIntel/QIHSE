# Security regression targets layered on top of the root Makefile.
# Usage: make -f Makefile -f tests/security-regression.mk test-kv-security-regression

.PHONY: test-kv-security-regression

test-kv-security-regression: lib
	$(CC) $(CFLAGS) -o tests/test_kv_security_regression tests/test_kv_security_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_kv_security_regression
