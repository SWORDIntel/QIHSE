# Security regression targets layered on top of the root Makefile.
# Usage: make -f Makefile -f tests/security-regression.mk test-security-regressions

.PHONY: test-kv-security-regression test-keystone-qihse-security test-vector-skip-integrity test-resp-security-regression test-tenant-security-regression test-tenant-privilege-ladder test-blob-security-regression test-ingest-guard-regression test-bundle-security-regression test-killswitch-regression test-vector-tenant-isolation test-retention-regression test-export-regression test-metrics-regression test-sci-compartment-regression test-blob-persistence-regression test-security-regressions

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

test-tenant-security-regression: lib
	$(CC) $(CFLAGS) -o tests/test_tenant_security_regression tests/test_tenant_security_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_tenant_security_regression

test-tenant-privilege-ladder: lib
	$(CC) $(CFLAGS) -o tests/test_tenant_privilege_ladder tests/test_tenant_privilege_ladder.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_tenant_privilege_ladder

test-blob-security-regression: lib
	$(CC) $(CFLAGS) -o tests/test_blob_security_regression tests/test_blob_security_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_blob_security_regression

test-ingest-guard-regression: lib
	$(CC) $(CFLAGS) -o tests/test_ingest_guard_regression tests/test_ingest_guard_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_ingest_guard_regression

test-bundle-security-regression: lib
	$(CC) $(CFLAGS) -o tests/test_bundle_security_regression tests/test_bundle_security_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_bundle_security_regression

test-killswitch-regression: lib
	$(CC) $(CFLAGS) -o tests/test_killswitch_regression tests/test_killswitch_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_killswitch_regression

test-vector-tenant-isolation: lib
	$(CC) $(CFLAGS) -o tests/test_vector_tenant_isolation tests/test_vector_tenant_isolation.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_vector_tenant_isolation

test-retention-regression: lib
	$(CC) $(CFLAGS) -o tests/test_retention_regression tests/test_retention_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_retention_regression

test-export-regression: lib
	$(CC) $(CFLAGS) -o tests/test_export_regression tests/test_export_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_export_regression

test-metrics-regression: lib
	$(CC) $(CFLAGS) -o tests/test_metrics_regression tests/test_metrics_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_metrics_regression

test-sci-compartment-regression: lib
	$(CC) $(CFLAGS) -o tests/test_sci_compartment_regression tests/test_sci_compartment_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_sci_compartment_regression

test-blob-persistence-regression: lib
	$(CC) $(CFLAGS) -o tests/test_blob_persistence_regression tests/test_blob_persistence_regression.c -L. -lqihse $(LDFLAGS)
	LD_LIBRARY_PATH=. ./tests/test_blob_persistence_regression

test-security-regressions: test-kv-security-regression test-keystone-qihse-security test-vector-skip-integrity test-resp-security-regression test-tenant-security-regression test-tenant-privilege-ladder test-blob-security-regression test-ingest-guard-regression test-bundle-security-regression test-killswitch-regression test-vector-tenant-isolation test-retention-regression test-export-regression test-metrics-regression test-sci-compartment-regression test-blob-persistence-regression
