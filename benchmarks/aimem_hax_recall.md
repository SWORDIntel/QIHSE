# HAX AIMEM recall fixture

`make test-hax-recall-fixture` builds a private, disposable 64-record corpus and
checks three BM25 queries. It asserts the expected top record UUID, verifies
every returned UUID and text against the authorized fixture, and excludes a
high-label/SCI row, another tenant's row, and a sibling worktree row. A direct
read of the high row must return no payload. In the standard build, semantic
and hybrid scoped recall must return `ENOTSUP`.

The opt-in comparison uses the same corpus and queries for all modes. Build a
QIHSE library with the matching KEYSTONE candidate projection enabled, then
provide a real ONNX embedder and KEYSTONE library:

```sh
QIHSE_AIMEM_EMBEDDER_ONNX_TEST_DIR=./model \
QIHSE_AIMEM_KEYSTONE_TEST_LIBRARY=./libkeystone.so \
make bench-hax-recall QIHSE_ENABLE_AIMEM_KEYSTONE=1 \
  QIHSE_AIMEM_KEYSTONE_INCLUDE=../KEYSTONE/include
```

The executable waits for projection readiness, warms each mode with three
queries, then measures 40 calls per mode with `CLOCK_MONOTONIC`. It reports
sorted-sample p50 (index 19), p95 (index 37), top-1 target UUID accuracy, and
the number of returned hits whose UUID and text match the fixture. The
provider, CPU, build flags, and model artifact must accompany any published
latency or quality numbers. This benchmark does not configure the production
recall default.

If the semantic provider or projection is unavailable, the benchmark exits
with status 77 and prints no comparative latency claim. The ordinary test
still checks BM25 in the standard build.

AIMEM recall hits currently carry an AIMEM record UUID and text, not a stable
document source/revision/chunk ID. The fixture verifies record UUID integrity;
it cannot claim document citation correctness until that contract exists.
