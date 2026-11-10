# Local AIMEM deployment — 2026-11-09

The user-authorized local deployment is active through the user unit
`qihse-aimem.service`. The release is `20261109T032508Z-native-hax-retrycache`, selected by
`$HOME/.local/lib/qihse-aimem/current`. Its `build-manifest.json` records exact
binary/library, source-file hashes, base commit and the dirty-tree boundary.
The running executable and both mapped libraries were checked against it.

## Configuration and verification

The release enables `QIHSE_ENABLE_AIMEM_KEYSTONE=1` with the matching
`QIHSE_AIMEM_KEYSTONE_INCLUDE=../KEYSTONE/include`. Its launcher loads the
adjacent `libkeystone.so` and enables the private cache under
`$HOME/.cache/qihse-aimem/projection` (overridable through
`QIHSE_AIMEM_PROJECTION_DIR`). Operator and AIMEM service credentials, numeric
identity/tenant, QKP pins, ONNX model and canonical KV directory are retained.
The authority remains volatile legacy mode; durable authority migration was
not activated.

An isolated server was tested before activation. The live pre-upgrade durable
canary survived restart. The actual HAX Python QKP client passed durable store,
exact read, wrong-project denial, BM25/semantic/hybrid recall and local-fsync
forget after the final release restart. Disposable memory records were removed.

A cold-generation retry cache fixes loss of completed inference when a KV
marker changes during construction. It is bounded to 8,192 UUID/content-digest
entries, cleared on model/security-context change, successful publication or
shutdown, and never substitutes for authorized canonical reads or publication
marker checks. The focused fixture forced a KV mutation on the third inference,
reached readiness after retry and asserted one inference per authorized row.
Ranking, grant revocation, restore, tombstones and model mismatch checks passed.

The required standard-build `make test TEST_JOBS=32` run completed all 188
targets: 187 passed, including the full CodeGraph aggregate and gold pack.
`test-parallel-runner` failed because it exposes the unimplemented CT1 pinned
write replication and CT2 fenced slot transfer gaps; tests were not weakened.
The separate projection-enabled focused fixture and real HAX live checks also
passed against the exact installed release.

## Changed source and records

- `src/spinnaker/qihse_ai_memory.c`: bounded computed-vector retry cache,
  authorization/model cleanup and phase-only failure diagnostics.
- `tests/test_aimem_keystone_projection.c`: deterministic mid-build mutation
  and inference reuse regression.
- `tests/test_auth_privilege_boundary.c`: default Operator full-permission
  regression assertions.
- `ROADMAP.md` and `docs/AIMEM_CURRENT_ISSUES.md`: local deployment evidence,
  current limitations and wider rollout blockers.

## Wider rollout

Historical Nov. 9 rollout checkpoint (superseded for cluster health by the
[Nov. 10 recovery record](../plans/cluster_recovery_20261109.md)): at that
time no remote services had been restarted; authenticated views disagreed,
T320 reported FAIL, and maintenance gates were OPEN. The recovery record
documents the later native deployment and converged slot map. This local HAX
deployment note does not verify whether remote KEYSTONE semantic projection
is enabled and ready.
