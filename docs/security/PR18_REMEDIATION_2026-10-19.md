# PR 18 follow-up remediation — 2026-10-19

Base of this follow-up: `356a13bb8c3acad64b1f1fadf53a8b62298c3504`.

This is an incremental remediation, not a complete security certification.
The owner explicitly requested publication to main before full CI completed.
That publication is not a release-validation claim; the complete required CI
and deployment checks must still pass.
The operator-password configuration is deliberately unchanged in this follow-up.

## Implemented boundaries

- The IPv4 cluster bus explicitly maps `localhost` to `127.0.0.1` and rejects
  invalid/unsupported bind inputs instead of substituting a wildcard address.
  RESP passes its normalized bind value to both bus construction paths and
  fails startup if the requested bus cannot start. Failure callbacks are wired
  in place; the failover coordinator no longer retains a freed bus after
  unnecessary destroy/recreation. IPv6 bus addresses remain
  unsupported and now fail closed rather than exposing IPv4 wildcard service.
- Native HTTP uses an absolute monotonic I/O deadline, tracks accepted sockets
  for shutdown cancellation, and drains workers before freeing shared state.
  Application handlers must still terminate; network cancellation is not safe
  arbitrary-thread preemption. Concurrent start/stop is serialized.
- Container HMAC operations return status; errors propagate through readers,
  encoders and writes rather than becoming a synthetic all-zero digest.
- Linux open-file-description locks replace process-associated locks so closing
  an independent reader cannot release the writer's lock. Platforms without
  this primitive fail writer opens rather than silently weakening exclusion.
- Partial section reads authenticate in a bounded-memory streaming pass and
  stage requested output until verification succeeds. Memory is bounded by the
  requested slice plus 64 KiB. The v1 format has no chunk MACs, so authenticated
  slice reads still cost O(section length) I/O; callers should account for this.
- Fleet redirects are iterative and bounded, and ASK uses ASKING on the same
  authenticated connection. Network operations share monotonic deadlines across
  connection, TLS, authentication, reads, retry, redirects and seed fallback.
  Endpoint addresses must be IPv4/IPv6 literals; the TLS server name remains
  independently configured and verified. This avoids unbounded OS DNS lookup.
- The ingest fixture owns/frees its thread argument and joins before teardown.
  The DHT fixture now emits and reads canonical network-order bus headers rather
  than rejecting replies through host-endian interpretation.

## Regression evidence

New targets: `test-http-lifecycle`, `test-cluster-bus-bind`, and
`test-container-lifecycle`. They are included in native and sanitizer CI.
The DHT and ingest fixtures also run independently before the broad native suite.
Python fleet security tests cover redirect cycles, ASK behavior, deadline sharing,
bounded read progress, literal endpoints, cleanup and authentication boundaries.

Local focused HTTP/bind/container lifecycle and Python regressions pass. The full
local engine build was not completed: Lua development headers and build tools
were unavailable and dependency installation was blocked by the execution
environment. Local LeakSanitizer cannot run under its tracing environment;
ASan/UBSan-only checks are not substitutes for the required CI leak checks.
Use the actual GitHub workflow results for complete build/validation status.

## Explicitly unresolved format boundary

Container v1 authenticates neither the full section metadata table nor the WAL
as a complete authenticated structure. Bounds checking and key admission do not
repair that format-level gap. This follow-up does not silently upgrade existing
files or assert that trusted data can be recovered from an already-tampered v1
container. A versioned authenticated format and an explicit migration policy
for trusted legacy input remain a separate compatibility decision.

## Deployment still requires evidence

Source changes do not rotate existing deployed credentials, authenticate a local
reverse proxy, or prove production recovery and rollout safety. Existing rotation,
ownership, rollout/rollback, real-topology and full negative-authorization gates
remain mandatory. No merge or production deployment is performed by this patch.

## Follow-up CI evidence

Run `39204517500` on `c9ca6c74676569e5cc0a68df9e76d1ea10014ff7`
passed both builds, Studio/dashboard, the new native and sanitized lifecycle
checks, and the corrected DHT/ingest fixtures. It then exposed later failures:

- Four leaked bundle-fixture thread arguments (64 bytes). The same ownership
  pattern also existed in killswitch, vector-tenant, retention and metrics
  fixtures. These tests now free transferred arguments and join all handlers
  before destroying shared state, without changing authorization assertions.
- The remote fabric-dispatch test expected indexed completion even though the
  optional KEYSTONE backend was absent. Its observed outcome must be checked
  against the real index-availability condition and durable result, not relabeled
  as fully indexed success or fixed by increasing a timeout.

These later failures were previously hidden by earlier aborts. New workflow
results, rather than this document, establish whether the full suite is green.
