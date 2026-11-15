# Core algorithm validation follow-up

Date: 2026-11-15.

**Final status:** the complete `make test TEST_JOBS=32` rerun executed all 254
targets: **253 passed; `test-codegraph` failed**. The command exited with status
2 after 1,689.779 seconds, with all 254 target logs retained. The four ordinary
failures from the first complete run passed in this final run. CodeGraph's
named Unix reader remains blocked by an independently reproduced
socket-creation denial in this execution environment, so the required full
gate has not passed completely.

This follow-up starts from the selectable-method implementation at
`00035059f706`, after the core corrections in `0418efb802e3`. Dependency-discovery
repairs and the INT8 pre-admission access check were working-tree changes during
these checks. [ROADMAP.md](../../ROADMAP.md) remains the delivery-status authority.

## Completed evidence

| Scope | Check | Result |
|---|---|---|
| Core lookup and numerical helpers | Focused core search, methodology, math, runtime and RFF-map regressions, including their bounded sanitizer runs | Passed. These checks compile the relevant implementations directly. |
| Installed public API | `test-public-api-install`, including the staged core-header checks and linked C/C++ consumers | Passed against the built library. The core headers also pass standalone and combined C11/C++11 compilation using only the staged include root. |
| Scalar method benchmark | Preserved 45-case synthetic default run with an independent original-type oracle | All 45 cases passed; measurements and source identity remain in the original reference. |
| Shared-library loading | `ldd -r libqihse.so` after configuring the relocated Python/dependency runtime paths | Dependencies resolved; no undefined-symbol errors. |
| Canonical ctypes compatibility target | `make lib-ctypes`, export checks, native extension import and a four-argument ctypes fidelity call after the full gate | Passed with the library hash unchanged. Both CPython initializers and extended search APIs remained exported; `QihseDB` imported; identical raw vectors returned status 0 and fidelity 1.0. |
| Vector candidate integration | `make test-vector-candidate-rerank`, linked against the built `libqihse.so` and real cryptographic providers | Passed full-pool reranking, three metrics, owned payloads, metadata filtering and the INT8/binary clearance boundary. |
| Controller Python SDK | Repaired fixture using a C helper compiled against the canonical server configuration | All 61 tests passed with no skips or warnings, including four native end-to-end cases. |
| Browser fixtures | Focused retries and final-suite execution after installing the declared `fido2` test dependency | Both targets passed: 41 unit checks and 36 integration checks. |
| PostgreSQL application compatibility | `test-pgwire-app-compat` in the final suite | 12 self-contained cases passed; 15 external-corpus cases skipped because `DIRECTEYE_SOURCE` was unavailable. |
| Gold workloads | Gold runner within the final complete suite | Reported 74 workloads across 11 areas with zero failures. |

The linked candidate test generates its own container keys, completes the
ML-KEM-1024 and ML-DSA-87 round-trip checks, and constructs actual operator and
low-clearance principals. With a candidate pool of one, a hidden approximate
winner cannot displace the authorized row in either selector. This closes the
earlier gap between the isolated selector harness and provider-backed execution.

The INT8 pre-admission check fixes a distinct omission: before the check, a
hidden row could fill the bounded approximate pool and later be rejected,
leaving no result even though an authorized row existed. Both selectors now
filter clearance/SCI before admission and retain their rerank-time checks.
Their approximate geometry is unchanged; this does not recover authorized rows
excluded for unrelated approximate-ranking reasons.

Controller end-to-end coverage now includes the operator round trip, watch
reconnection/resume, low-clearance guest denial without payload disclosure, and
unauthenticated denial without payload disclosure. This supersedes the earlier
skipped end-to-end class caused by a stale manually mirrored configuration
layout. The fixture now compiles against the current C header.

## Build preparation and the complete gate

The original missing `lua.h` failure was resolved by supplying LuaJIT development
and runtime dependencies. LuaJIT include/link settings now support pkg-config
and explicit overrides rather than a fixed system include directory. A later
tree-sitter Unicode-header failure was an include-path defect: the required
headers were already vendored, and the target-specific source include path was
corrected. No external ICU package was required for that repair.

`lib-ctypes` is a compatibility alias for `lib`. Both targets produce the same
canonical shared library, preserving its CPython exports and avoiding separate
recipes that can overwrite the same artifact. The integration results here
refer to that canonical library; an earlier isolated filtered-link prototype
was superseded and is not evidence for the final artifact.

Dependency-prefix and runtime-loader setup is documented in
[Getting started](../GETTING_STARTED.md#dependency-discovery-and-local-prefixes).
The Python test packages are listed separately in
[`python/requirements-test.txt`](../../python/requirements-test.txt), including
PostgreSQL clients and `fido2`; existing runtime requirements are unchanged.
The shared library, server and administrative executable built successfully.
Building those artifacts and precompiling test binaries are preparation steps;
they are not substitutes for executing the complete suite:

```sh
make test TEST_JOBS=32
```

The first complete run failed `test-cluster-bus-bind`,
`test-controller-sdk-py`, `test-browser-unit`, `test-browser` and
`test-codegraph`. The bus-bind failure occurred before test execution because
its launcher could not find `libqihse.so`; the repaired runtime path passes the
IPv4 bind-policy test. The controller failure came from a fixture event
shadowing `Thread._stop`; the fixture and its native end-to-end setup are now
validated. The two browser targets lacked `fido2` and pass after installing it.

| Complete attempt | Targets executed | Passed | Failed |
|---|---:|---:|---:|
| First complete run | 254 | 249 | 5 |
| Final run after repairs | 254 | 253 | 1: `test-codegraph` |

The final runner reported `Suite: 254 targets, 1 failed: test-codegraph`.
Bus-bind, controller and both browser targets passed within that complete
rerun, as did all six core regression targets. The final Gold result was
`GOLD: 11 areas, 74 workloads, 0 failed`. These results establish the repaired
targets' integration status while preserving the failed status of the earlier
attempt and the remaining CodeGraph limitation.

## Remaining Unix-socket capability limitation

Independent Python and C probes fail at
`socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)` with `EPERM`, before a bind
or any CodeGraph operation. `socketpair` succeeds. The named Unix-reader
integration therefore cannot start in this environment; that capability
limitation is separate from the repository defects corrected above.

The reader-startup diagnostic now reports an early child's exit status and
captured output accurately. Its early-exit detection already existed; the
30-second deadline for a still-running child remains. The test continues to
report the socket-creation failure.

The aggregate CodeGraph recipe stops at the denied reader. The 18 downstream
commands were therefore executed separately: 16 passed and two failed at the
same named-reader startup boundary:

- `tests/test_codegraph_query_index.py` reported that the reader did not become
  ready, with `CodeGraph reader socket unavailable` in the child output.
- `tests/test_codegraph_runtime_spills.py` completed its import, then failed at
  reader setup with the same socket-unavailable result. That is not a completed
  runtime-spill validation.

The successful supplemental commands include storage, accounting and accounting
formats. The final command was
`python3 -m unittest discover -s tests -p test_codegraph_incremental.py`, which
passed all 15 tests. These 18 command outcomes are separate from the 254-target
suite, and do not change the aggregate CodeGraph target's failed status.

## Optional external-application coverage

`test-pgwire-app-compat` passed its 12 self-contained core, client and numeric
cases. It skipped 15 cases whose optional sibling-application corpus was not
available through `DIRECTEYE_SOURCE`, including the referenced
`services/postgres_service.py` and `migration/01_setup_postgresql.py` sources.
Those skips do not establish application compatibility for that absent corpus.
The target also reported one third-party pytest deprecation warning. The
controller fixture's zero-skip result above applies to its 61 tests; it is not
a claim that the complete repository suite had no skips or warnings.

## Preserve the original benchmark evidence

The [scalar reference](../../benchmarks/results/core_methods/README.md) retains
its original JSONL measurements and 19-file source/header manifest. Its recorded
`0418efb802e3-dirty` identity describes the pre-commit measurement state; the
aggregate source hash identifies the measured contents. This integration pass
does not rewrite that metadata, replace its timing samples, or imply that the
standalone benchmark was run through the newly built shared library.
